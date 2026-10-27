//! The "ask Claude" pane: a transcript of one Claude Code session (questions, the read-only
//! commands Claude ran, streamed answers) with an input line for follow-ups.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::theme::Theme;
use super::widgets::{self, chip, wrap};
use crate::claude::{Ask, Event, Proposed};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    You,
    Claude,
    Tool,
    ToolErr,
    Info,
    Err,
}

/// A command sentry runs on the user's behalf from inside the chat (not Claude).
#[derive(Debug, Clone, PartialEq)]
pub enum Job {
    /// A proposed command; `output` collects what it prints.
    Proposal {
        cmd: String,
        output: String,
        changes: bool,
    },
    /// `sentry job audit` after a change; the command and its result wait for it.
    Audit {
        cmd: String,
        code: i32,
        output: String,
    },
}

/// Where the failed workflow step a fix chat is about stands (kept up to date by the app).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Failed,
    Running,
    /// Its dry run passed: `t` runs it for real.
    DryOk,
    Done,
}

pub struct Chat {
    pub ask: Ask,
    pub session: Option<String>,
    pub entries: Vec<(Kind, String)>,
    /// Stream id and pid of the running turn.
    pub live: Option<(u64, u32)>,
    pub started: Option<Instant>,
    pub input: String,
    /// Lines scrolled up from the bottom (0 follows what's new).
    pub scroll: usize,
    /// Lines that arrived while scrolled up (kept out of view's way), and the line count at
    /// the last draw: draw has only `&self`.
    grown: std::cell::Cell<usize>,
    drawn: std::cell::Cell<usize>,
    pub cost: f64,
    got_done: bool,
    /// Commands from Claude's latest answer, runnable with `r` + 1–9.
    pub proposals: Vec<Proposed>,
    /// `r` pressed: the next digit picks a proposal.
    pub picking: bool,
    /// Stream id, pid and kind of the command sentry is running for the chat.
    pub job: Option<(u64, u32, Job)>,
    /// A finished command's report, ready to send to Claude with `s`.
    pub offer: Option<String>,
    /// Set for a chat about a failed workflow step.
    pub step: Option<StepState>,
}

impl Chat {
    pub fn new(ask: Ask) -> Self {
        Self {
            session: None,
            entries: Vec::new(),
            live: None,
            started: None,
            input: String::new(),
            scroll: 0,
            grown: Default::default(),
            drawn: Default::default(),
            cost: 0.0,
            got_done: false,
            proposals: Vec::new(),
            picking: false,
            job: None,
            offer: None,
            step: ask.step().map(|_| StepState::Failed),
            ask,
        }
    }

    pub fn busy(&self) -> bool {
        self.live.is_some() || self.job.is_some() || self.step == Some(StepState::Running)
    }

    /// `t` is offered: the step can be retried (or run for real after its dry run).
    pub fn can_retry(&self) -> bool {
        matches!(self.step, Some(StepState::Failed | StepState::DryOk))
    }

    /// Re-read the proposals from the newest answer (after a turn ends).
    fn refresh_proposals(&mut self) {
        let last = self
            .entries
            .iter()
            .rev()
            .take_while(|(k, _)| *k != Kind::You)
            .filter(|(k, _)| *k == Kind::Claude)
            .map(|(_, t)| t.as_str())
            .collect::<Vec<_>>();
        let text: String = last.into_iter().rev().collect::<Vec<_>>().join("\n");
        let p = crate::claude::parse_commands(&text, &self.ask.known);
        if !p.is_empty() || self.proposals.is_empty() {
            self.proposals = p;
        }
    }

    /// Output from the command sentry runs for the chat.
    pub fn on_job_line(&mut self, text: String) {
        let out = match self.job.as_mut() {
            Some((_, _, Job::Proposal { output, .. })) => output,
            // The audit's own progress isn't interesting here.
            _ => return,
        };
        if out.len() < 16_000 {
            out.push_str(&text);
            out.push('\n');
        }
        self.push(Kind::Tool, format!("  {text}"));
    }

    /// The report sent back to Claude after a command (and the audit after it).
    pub fn set_offer(&mut self, cmd: &str, code: i32, output: &str, after: Option<&str>) {
        let tail: Vec<&str> = output.lines().rev().take(60).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        let mut text = format!(
            "I ran this through sentry:\n$ {cmd}\nexit code {code}\noutput (last {} lines):\n{}",
            tail.len(),
            if tail.is_empty() {
                "(none)".to_string()
            } else {
                tail.join("\n")
            }
        );
        if let Some(a) = after {
            text.push_str(&format!("\n\n{a}"));
        }
        text.push_str("\n\nDid it work? What, if anything, should I do next?");
        self.offer = Some(text);
    }

    fn offset(&self) -> usize {
        self.scroll + self.grown.get()
    }

    /// Scroll up (+) or down (-) by `n` lines; down to 0 follows what's new again.
    pub fn scroll_by(&mut self, n: isize) {
        let at = self.offset() as isize + n;
        self.scroll = at.max(0) as usize;
        self.grown.set(0);
        // Not past the top: draw clamps too, but keys shouldn't pile up beyond it.
        self.scroll = self.scroll.min(self.drawn.get());
    }

    pub fn scroll_top(&mut self) {
        self.scroll = self.drawn.get();
        self.grown.set(0);
    }

    pub fn scroll_bottom(&mut self) {
        self.scroll = 0;
        self.grown.set(0);
    }

    pub fn push(&mut self, kind: Kind, text: impl Into<String>) {
        self.entries.push((kind, text.into()));
        // Scrolled up: the view stays put (draw keeps it on the same lines); at the bottom it
        // follows what's new.
    }

    pub fn begin_turn(&mut self, question: &str, id: u64, pid: u32) {
        self.push(Kind::You, question);
        self.live = Some((id, pid));
        self.started = Some(Instant::now());
        self.got_done = false;
    }

    pub fn on_event(&mut self, e: Event) {
        match e {
            Event::Init { session_id } => self.session = Some(session_id),
            Event::Text(t) => match self.entries.last_mut() {
                Some((Kind::Claude, s)) => s.push_str(&t),
                _ => self.push(Kind::Claude, t),
            },
            Event::ToolUse { name, input } => {
                let shown = if name == "Bash" {
                    format!("$ {input}")
                } else {
                    format!("{name} {input}")
                };
                self.push(Kind::Tool, shown);
            }
            Event::ToolResult { summary, is_error } => {
                let kind = if is_error { Kind::ToolErr } else { Kind::Tool };
                self.push(kind, format!("  → {summary}"));
            }
            Event::Done {
                is_error,
                result,
                cost,
            } => {
                self.got_done = true;
                self.cost += cost.unwrap_or(0.0);
                if is_error {
                    self.push(Kind::Err, result);
                } else if !self
                    .entries
                    .iter()
                    .rev()
                    .take_while(|(k, _)| *k != Kind::You)
                    .any(|(k, _)| *k == Kind::Claude)
                {
                    // No streamed text (e.g. partial messages off): show the final result.
                    self.push(Kind::Claude, result);
                }
            }
        }
    }

    /// Non-JSON output (stderr) from claude.
    pub fn on_raw(&mut self, line: String) {
        if !line.trim().is_empty() {
            self.push(Kind::Err, line);
        }
    }

    pub fn on_exit(&mut self, code: i32) {
        self.live = None;
        if code != 0 && !self.got_done {
            self.push(Kind::Err, format!("claude exited with {code}"));
        }
        self.refresh_proposals();
    }

    pub fn running(&self) -> bool {
        self.live.is_some()
    }
}

pub fn draw(f: &mut Frame, area: Rect, t: &Theme, c: &Chat) {
    let rect = widgets::centered(
        area,
        area.width.saturating_sub(6).max(60),
        area.height.saturating_sub(2),
    );
    let color = if c.running() { t.cyan } else { t.mag };
    let inner = widgets::overlay(f, rect, t, &format!("Claude · {}", c.ask.subject), color);
    let [log, rule, input, keyline] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    let w = log.width as usize;
    let mut lines: Vec<Line> = Vec::new();
    for (kind, text) in &c.entries {
        let (label, style) = match kind {
            Kind::You => ("you    ", t.s(t.cyan)),
            Kind::Claude => ("claude ", t.fg()),
            Kind::Tool => ("       ", t.dim()),
            Kind::ToolErr => ("       ", t.s(t.yellow)),
            Kind::Info => ("       ", t.dim()),
            Kind::Err => ("error  ", t.s(t.red)),
        };
        let mut first = true;
        let mut code = false;
        for para in text.split('\n') {
            // Light markdown: code fences become plain indented commands, **bold** loses its stars.
            if *kind == Kind::Claude && para.trim_start().starts_with("```") {
                code = !code;
                continue;
            }
            let (body, st) = if code {
                (format!("  {para}"), t.s(t.cyan))
            } else if *kind == Kind::Claude {
                (para.replace("**", ""), style)
            } else {
                (para.to_string(), style)
            };
            let wrapped = wrap(&body, w.saturating_sub(7).max(10));
            let wrapped = if wrapped.is_empty() {
                vec![String::new()]
            } else if code {
                // Keep code on one line (truncated) so it can be copied as-is.
                vec![widgets::trunc(&body, w.saturating_sub(7).max(10))]
            } else {
                wrapped
            };
            for l in wrapped {
                let lab = if first { label } else { "       " };
                first = false;
                lines.push(Line::from(vec![
                    Span::styled(lab.to_string(), t.s(t.mag)),
                    Span::styled(l, st),
                ]));
            }
        }
        if matches!(kind, Kind::Claude | Kind::Err) {
            lines.push(Line::raw(""));
        }
    }
    if !c.proposals.is_empty() && !c.running() {
        lines.push(Line::styled(
            "       Proposed commands (sentry runs them, after you confirm; Claude can't):",
            t.s(t.yellow),
        ));
        for (i, p) in c.proposals.iter().take(9).enumerate() {
            let first = p.cmd.lines().next().unwrap_or("");
            let more = if p.cmd.lines().count() > 1 {
                " …"
            } else {
                ""
            };
            let color = if crate::claude::risky(&p.cmd).is_some() {
                t.red
            } else {
                t.cyan
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("     {} ", i + 1),
                    ratatui::style::Style::new().fg(t.ink).bg(t.yellow),
                ),
                Span::styled(
                    widgets::trunc(&format!(" {first}{more}"), w.saturating_sub(8).max(10)),
                    t.s(color),
                ),
            ]));
            let mut note = p.why.clone();
            if p.known {
                note.push_str(" (sentry's known fix)");
            }
            for l in wrap(&note, w.saturating_sub(9).max(10)) {
                lines.push(Line::styled(format!("         {l}"), t.dim()));
            }
        }
        lines.push(Line::raw(""));
    }
    if c.step == Some(StepState::Running) {
        lines.push(Line::styled(
            "       … the step is running (its output is in the workflow log behind this)",
            t.dim(),
        ));
    } else if let Some((_, _, job)) = &c.job {
        let what = match job {
            Job::Proposal { .. } => "       … running (C-c stops it)",
            Job::Audit { .. } => "       … auditing again",
        };
        lines.push(Line::styled(what, t.dim()));
    } else if c.offer.is_some() {
        lines.push(Line::styled(
            "       Press s to send this output to Claude (shown first), or ask your own follow-up.",
            t.s(t.yellow),
        ));
    }
    if c.running() {
        let s = c.started.map_or(0, |s| s.elapsed().as_secs());
        lines.push(Line::styled(
            format!("       … thinking ({}:{:02})", s / 60, s % 60),
            t.dim(),
        ));
    }
    let h = log.height as usize;
    // Scrolled up while lines arrive: move by as many, so the view holds still. Never past
    // the top.
    let total = lines.len();
    if c.scroll > 0 && c.drawn.get() > 0 {
        c.grown
            .set(c.grown.get() + total.saturating_sub(c.drawn.get()));
    }
    c.drawn.set(total);
    let scroll = c.offset().min(total.saturating_sub(h));
    let end = total.saturating_sub(scroll);
    let start = end.saturating_sub(h);
    f.render_widget(Paragraph::new(lines[start..end].to_vec()), log);
    f.render_widget(
        Paragraph::new("─".repeat(rule.width as usize)).style(t.s(t.rule)),
        rule,
    );
    let prompt = if c.running() {
        Line::styled("  (answering… C-c stops it)", t.dim())
    } else if c.picking {
        Line::styled(
            format!("  run which? 1–{} (Esc cancels)", c.proposals.len().min(9)),
            t.s(t.yellow),
        )
    } else {
        Line::from(vec![
            Span::styled("› ", t.s(t.cyan)),
            Span::styled(c.input.clone(), t.fg()),
            Span::styled("▏", t.s(t.cyan)),
        ])
    };
    f.render_widget(Paragraph::new(prompt), input);
    let mut spans = Vec::new();
    for (k, d) in keys(c) {
        spans.extend(chip(t, k, d, t.dim));
        spans.push(Span::raw("  "));
    }
    if c.cost > 0.0 {
        spans.push(Span::styled(format!("session ${:.3}", c.cost), t.dim()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), keyline);
}

/// The key line: letters act only while the input line is empty (otherwise they're typed).
pub fn keys(c: &Chat) -> Vec<(&'static str, &'static str)> {
    let mut k = vec![("Enter", "follow-up")];
    let idle = c.input.is_empty() && !c.busy();
    if idle && !c.proposals.is_empty() {
        k.push(("r", "run a proposed command"));
    }
    if idle && c.offer.is_some() {
        k.push(("s", "send output"));
    }
    if idle && c.can_retry() {
        k.push((
            "t",
            if c.step == Some(StepState::DryOk) {
                "run the step"
            } else {
                "retry the step"
            },
        ));
    }
    if idle && c.session.is_some() {
        k.push(("C", "continue in Claude Code"));
    }
    k.push(("Esc", "close"));
    if c.busy() {
        k.push(("C-c", "stop"));
    }
    k.push(("↑↓ PgUp/Dn", "scroll"));
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_from_events() {
        let mut c = Chat::new(Ask::new("x", "ctx", "q"));
        c.begin_turn("q", 1, 42);
        for e in crate::collectors::fixture("claude/stream.jsonl")
            .lines()
            .flat_map(crate::claude::parse_line)
        {
            c.on_event(e);
        }
        c.on_exit(0);
        let kinds: Vec<Kind> = c.entries.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            kinds,
            vec![
                Kind::You,
                Kind::Tool,
                Kind::Tool,
                Kind::Tool,
                Kind::ToolErr,
                Kind::Claude
            ]
        );
        assert_eq!(c.entries[5].1, "Port 27500 is owned by root.");
        assert_eq!(
            c.session.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert!(!c.running());
        assert!((c.cost - 0.0312).abs() < 1e-9);
        assert!(c.proposals.is_empty());
        assert!(!keys(&c).iter().any(|(k, _)| *k == "r"));
        assert!(keys(&c).iter().any(|(k, _)| *k == "C"));
    }

    #[test]
    fn proposals_after_answer() {
        let f = crate::audit::Finding {
            id: "unit-failed:system:systemd-remount-fs.service".into(),
            message: "systemd-remount-fs.service failed".into(),
            ..Default::default()
        };
        let mut c = Chat::new(Ask::fix(&f));
        c.begin_turn("q", 1, 42);
        c.on_event(Event::Text(
            "**What's going on** read-only root.\n**Commands**\n```bash\n# why: harmless on composefs\nsudo systemctl reset-failed systemd-remount-fs.service\n```\n".into(),
        ));
        c.on_exit(0);
        assert_eq!(c.proposals.len(), 1);
        assert!(c.proposals[0].known);
        assert!(keys(&c).iter().any(|(k, _)| *k == "r"));
        let backend = ratatui::backend::TestBackend::new(100, 30);
        let mut term = ratatui::Terminal::new(backend).unwrap();
        let t = Theme::truecolor();
        term.draw(|fr| draw(fr, fr.area(), &t, &c)).unwrap();
        let screen: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|x| x.symbol())
            .collect();
        assert!(screen.contains("Proposed commands"));
        assert!(screen.contains("sudo systemctl reset-failed systemd-remount-fs.service"));
        assert!(screen.contains("sentry's known fix"));
        c.set_offer("x", 0, "ok", Some("The finding is gone."));
        assert!(c.offer.as_deref().unwrap().contains("exit code 0"));
    }

    #[test]
    fn scrolled_up_the_view_holds_while_lines_arrive() {
        let t = crate::tui::theme::Theme::truecolor();
        let mut c = Chat::new(crate::claude::Ask::new("s", "c", "q"));
        for i in 0..80 {
            c.push(Kind::Claude, format!("line {i}"));
        }
        let draw = |c: &Chat| {
            let mut term =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(60, 20)).unwrap();
            term.draw(|f| draw(f, f.area(), &t, c)).unwrap();
            let b = term.backend().buffer().clone();
            (0..20)
                .map(|y| (0..60).map(|x| b[(x, y)].symbol()).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        };
        draw(&c);
        c.scroll_by(30);
        let before = draw(&c);
        assert!(!before.contains("line 79"), "scrolled up");
        for i in 80..90 {
            c.push(Kind::Claude, format!("line {i}"));
        }
        assert_eq!(draw(&c), before, "new lines don't move a scrolled-up view");
        c.scroll_by(10_000);
        assert!(draw(&c).contains("line 0"), "not past the top");
        c.scroll_bottom();
        assert!(draw(&c).contains("line 89"), "End follows again");
    }
}

//! The "ask Claude" pane: a transcript of one Claude Code session (questions, the read-only
//! commands Claude ran, streamed answers) with an input line for follow-ups. A chat only
//! explains: anything that changes the system is an apply session (`a` hands it over).

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::theme::Theme;
use super::widgets::{self, chip, wrap};
use crate::claude::{Ask, Event};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    You,
    Claude,
    Tool,
    ToolErr,
    Info,
    Err,
    /// A good outcome (green).
    Good,
    /// Where an apply session's plan goes (the text is its index); drawn by the session.
    Plan,
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
    /// What `a` applies (an apply ask for what the chat is about), if anything.
    pub apply_with: Option<Ask>,
    /// Esc while Claude answers: out of sight, still running (`A` brings it back).
    pub hidden: bool,
    /// The last tool Claude called (name, input): a refusal right after names what it wanted.
    last_tool: Option<(String, String)>,
    /// Files Claude was refused this turn, for `g` (not yet granted).
    pub requests: Vec<crate::claude::Grant>,
    /// What the user granted in this conversation (every later turn gets it).
    pub grants: Vec<crate::claude::Grant>,
    /// Files Claude may write: path, its hash when last seen, its backup.
    pub watched: Vec<(String, u64, std::path::PathBuf)>,
    /// Not sent yet: the brief is shown, and Enter sends it (with what's typed, if anything).
    pub pending: bool,
    /// What Claude may do with what's sent (shown under the brief).
    pub privacy: String,
}

/// A file's contents, hashed (0: it doesn't exist).
fn file_hash(path: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    std::fs::read(path).map_or(0, |b| {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        b.hash(&mut h);
        h.finish()
    })
}

fn line_count(p: &std::path::Path) -> usize {
    std::fs::read_to_string(p).map_or(0, |t| t.lines().count())
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
            hidden: false,
            apply_with: None,
            ask,
            last_tool: None,
            requests: Vec::new(),
            grants: Vec::new(),
            watched: Vec::new(),
            pending: false,
            privacy: crate::claude::allowlist_summary(),
        }
    }

    /// The box `g` opens: what Claude asked for, what's granted, what isn't and why.
    pub fn grant_lines(&self, t: &Theme) -> Vec<Line<'static>> {
        let mut l = vec![Line::styled(
            "Claude asked to use these files, for the rest of this conversation:",
            t.fg(),
        )];
        for g in &self.requests {
            match crate::claude::grantable(g) {
                Ok(()) => l.push(Line::styled(
                    format!(
                        "  {} {}{}",
                        g.word(),
                        g.path,
                        match g.access {
                            crate::claude::Access::Write => "  (backed up first)",
                            crate::claude::Access::Run => {
                                "  (that exact command; sentry doesn't know it: read it first)"
                            }
                            crate::claude::Access::Read => "",
                        }
                    ),
                    t.fg(),
                )),
                Err(why) => l.push(Line::styled(
                    format!("  {} {}  · not granted: {why}", g.word(), g.path),
                    t.s(t.red),
                )),
            }
        }
        l.push(Line::raw(""));
        l.push(Line::styled(
            "What Claude reads or runs is sent to Anthropic. Commands that change things stay yours.",
            t.dim(),
        ));
        l
    }

    /// `y` on that box: the grantable requests become grants (a write's file is backed up
    /// by the caller, `watch`); the text of the next turn, telling Claude.
    pub fn grant(&mut self) -> Option<String> {
        let ok: Vec<crate::claude::Grant> = std::mem::take(&mut self.requests)
            .into_iter()
            .filter(|g| crate::claude::grantable(g).is_ok())
            .collect();
        if ok.is_empty() {
            return None;
        }
        let what: Vec<String> = ok
            .iter()
            .map(|g| format!("{} {}", g.word(), g.path))
            .collect();
        for g in ok {
            // A write covers a read of the same file.
            self.grants
                .retain(|x| !(x.path == g.path && x.access == crate::claude::Access::Read));
            if !self.grants.contains(&g) {
                self.grants.push(g);
            }
        }
        Some(format!(
            "I've granted you: {} (for this conversation). Carry on where you stopped.",
            what.join("; ")
        ))
    }

    /// Watch a file Claude may now write (its backup made by the caller).
    pub fn watch(&mut self, path: &str, backup: std::path::PathBuf) {
        if !self.watched.iter().any(|(p, ..)| p == path) {
            self.watched
                .push((path.to_string(), file_hash(path), backup));
        }
    }

    /// Files Claude changed since they were last looked at: (path, backup, lines before (in
    /// the backup), lines now). Each change is reported once.
    pub fn changed(&mut self) -> Vec<(String, std::path::PathBuf, usize, usize)> {
        let mut out = Vec::new();
        for (path, hash, backup) in &mut self.watched {
            let now = file_hash(path);
            if now != *hash {
                *hash = now;
                out.push((
                    path.clone(),
                    backup.clone(),
                    line_count(backup),
                    line_count(std::path::Path::new(path.as_str())),
                ));
            }
        }
        out
    }

    pub fn busy(&self) -> bool {
        self.live.is_some()
    }

    /// `a` is offered: there's something to apply, and nothing running.
    pub fn can_apply(&self) -> bool {
        self.apply_with.is_some() && self.input.is_empty() && !self.busy()
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
        self.begin_quiet(id, pid);
    }

    /// A turn sentry sent by itself (its own line is already in the transcript).
    pub fn begin_quiet(&mut self, id: u64, pid: u32) {
        self.pending = false;
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
                self.last_tool = Some((name.clone(), input.clone()));
                let shown = if name == "Bash" {
                    format!("$ {input}")
                } else {
                    format!("{name} {input}")
                };
                self.push(Kind::Tool, shown);
            }
            Event::ToolResult { summary, is_error } => {
                // Refused a file: sentry can ask the user to grant it (`g`).
                if is_error
                    && summary.contains("requested permissions")
                    && let Some(g) = self
                        .last_tool
                        .as_ref()
                        .and_then(|(n, i)| crate::claude::requested(n, i, &summary))
                    && !self.grants.contains(&g)
                    && !self.requests.contains(&g)
                {
                    self.requests.push(g);
                }
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
        if !self.requests.is_empty() {
            let what: Vec<String> = self
                .requests
                .iter()
                .map(|g| format!("{} {}", g.word(), g.path))
                .collect();
            self.push(
                Kind::Info,
                format!("Claude asked to {} · g grants it", what.join(", ")),
            );
        }
    }

    pub fn running(&self) -> bool {
        self.live.is_some()
    }

    /// Esc: hide it while Claude (or a command for it) is still running; otherwise it's done
    /// with (true: close it).
    pub fn esc(&mut self) -> bool {
        if self.running() {
            self.hidden = true;
            false
        } else {
            true
        }
    }

    /// The `A` chip while the chat is hidden.
    pub fn hidden_word(&self) -> &'static str {
        if self.running() {
            "Claude answering…"
        } else {
            "Claude answered"
        }
    }
}

pub fn draw(f: &mut Frame, area: Rect, t: &Theme, c: &Chat) {
    // Nothing of the screen behind shows at the edges.
    f.render_widget(ratatui::widgets::Clear, area);
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
    let mut lines = entry_lines(c, t, w, false, &|_| Vec::new());
    if c.pending {
        lines.extend(brief_lines(c, t, w, false));
    }
    if c.running() {
        let s = c.started.map_or(0, |s| s.elapsed().as_secs());
        lines.push(Line::styled(
            format!("       … thinking ({}:{:02})", s / 60, s % 60),
            t.dim(),
        ));
    }
    show_scrolled(f, log, c, lines);
    f.render_widget(
        Paragraph::new("─".repeat(rule.width as usize)).style(t.s(t.rule)),
        rule,
    );
    let prompt = if c.running() {
        Line::styled("  (answering… C-c stops it)", t.dim())
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

/// The transcript as lines, `w` wide. `fold`: Claude's read-only commands fold to one line
/// per run of them; `plan`: the lines a `Kind::Plan` entry stands for.
pub fn entry_lines(
    c: &Chat,
    t: &Theme,
    w: usize,
    fold: bool,
    plan: &dyn Fn(usize) -> Vec<Line<'static>>,
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut i = 0;
    while i < c.entries.len() {
        let (kind, text) = &c.entries[i];
        if *kind == Kind::Plan {
            lines.extend(plan(text.parse().unwrap_or(0)));
            i += 1;
            continue;
        }
        if fold && matches!(kind, Kind::Tool | Kind::ToolErr) {
            let n = c.entries[i..]
                .iter()
                .take_while(|(k, _)| matches!(k, Kind::Tool | Kind::ToolErr))
                .count();
            let cmds = c.entries[i..i + n]
                .iter()
                .filter(|(_, t)| !t.starts_with("  → "))
                .count();
            lines.push(Line::styled(
                format!(
                    "       looked around: {cmds} read-only command{}",
                    if cmds == 1 { "" } else { "s" }
                ),
                t.dim(),
            ));
            i += n;
            continue;
        }
        let (label, style) = match kind {
            Kind::You => ("you    ", t.s(t.cyan)),
            Kind::Claude => ("claude ", t.fg()),
            Kind::Tool => ("       ", t.dim()),
            Kind::ToolErr => ("       ", t.s(t.yellow)),
            Kind::Info => ("       ", t.dim()),
            Kind::Err => ("error  ", t.s(t.red)),
            Kind::Good => ("       ", t.s(t.green)),
            Kind::Plan => ("       ", t.dim()),
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
        i += 1;
    }
    lines
}

/// What's sent first: the brief (folded to its first lines unless `open`), and what Claude
/// may do with it.
pub fn brief_lines(c: &Chat, t: &Theme, w: usize, open: bool) -> Vec<Line<'static>> {
    let all: Vec<&str> = c.ask.context.lines().collect();
    let shown = if open { all.len() } else { all.len().min(4) };
    let mut l = vec![Line::styled(
        format!(
            "       Sent to Claude through your Claude Code login (Anthropic){}:",
            if all.len() > shown {
                format!(" · {} lines · Tab shows all", all.len())
            } else {
                String::new()
            }
        ),
        t.s(t.yellow),
    )];
    for x in &all[..shown] {
        for y in wrap(x, w.saturating_sub(9).max(10)) {
            l.push(Line::styled(format!("         {y}"), t.dim()));
        }
    }
    if all.len() > shown {
        l.push(Line::styled("         …", t.dim()));
    }
    for y in wrap(&c.privacy, w.saturating_sub(7).max(10)) {
        l.push(Line::styled(format!("       {y}"), t.dim()));
    }
    l.push(Line::raw(""));
    l
}

/// Draw `lines` into `log`, at the chat's scroll position. Scrolled up while lines arrive:
/// move by as many, so the view holds still. Never past the top.
pub fn show_scrolled(f: &mut Frame, log: Rect, c: &Chat, lines: Vec<Line<'static>>) {
    let h = log.height as usize;
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
}

/// The key line: letters act only while the input line is empty (otherwise they're typed).
pub fn keys(c: &Chat) -> Vec<(&'static str, &'static str)> {
    if c.pending {
        return vec![("Enter", "send"), ("Esc", "cancel")];
    }
    let mut k = vec![("Enter", "follow-up")];
    let idle = c.input.is_empty() && !c.busy();
    if c.can_apply() {
        k.push(("a", "apply it"));
    }
    if idle && !c.requests.is_empty() {
        k.push(("g", "grant files"));
    }
    if idle && c.session.is_some() {
        k.push(("C", "continue in Claude Code"));
    }
    k.push((
        "Esc",
        if c.running() {
            "hide (it carries on)"
        } else {
            "close"
        },
    ));
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
                Kind::Claude,
                Kind::Info
            ]
        );
        assert_eq!(c.entries[5].1, "Port 27500 is owned by root.");
        // The refused `sudo ss`: asked for, but never grantable.
        assert_eq!(c.requests[0].path, "sudo ss -tlnp");
        assert!(crate::claude::grantable(&c.requests[0]).is_err());
        assert_eq!(
            c.session.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert!(!c.running());
        assert!((c.cost - 0.0312).abs() < 1e-9);
        assert!(!keys(&c).iter().any(|(k, _)| *k == "r" || *k == "a"));
        assert!(keys(&c).iter().any(|(k, _)| *k == "C"));
    }

    #[test]
    fn a_chat_explains_and_hands_applying_over() {
        let f = crate::finding::Finding {
            id: "unit-failed:system:systemd-remount-fs.service".into(),
            message: "systemd-remount-fs.service failed".into(),
            ..Default::default()
        };
        let mut c = Chat::new(crate::claude::Ask::new("s", "ctx", "What is this?"));
        c.begin_turn("q", 1, 42);
        c.on_event(Event::Text(
            "It fails on composefs.\n```bash\nsudo systemctl reset-failed x\n```\n".into(),
        ));
        c.on_exit(0);
        // Commands in an answer are just text: nothing to run.
        assert!(!keys(&c).iter().any(|(k, _)| *k == "r" || *k == "s"));
        assert!(!c.can_apply());
        // What the chat is about can be applied: `a` hands it to a session.
        c.apply_with = Some(crate::claude::Ask::for_finding(&f, &[]));
        assert!(keys(&c).iter().any(|(k, w)| *k == "a" && *w == "apply it"));
        c.input.push('x');
        assert!(!c.can_apply(), "typing: the letter is text");
    }

    #[test]
    fn a_refused_file_can_be_granted_and_edits_are_noticed() {
        use crate::claude::{Access, Ask, Event, Grant};
        let file = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
        let mut c = Chat::new(Ask::new("s", "ctx", "q"));
        c.begin_turn("q", 1, 1);
        c.on_event(Event::ToolUse {
            name: "Read".into(),
            input: file.clone(),
        });
        c.on_event(Event::ToolResult {
            summary: format!(
                "denied: Claude requested permissions to read from {file}, but you haven't granted it yet."
            ),
            is_error: true,
        });
        c.on_exit(0);
        assert_eq!(c.requests.len(), 1);
        assert!(keys(&c).iter().any(|(k, _)| *k == "g"));
        assert!(c.entries.iter().any(|(_, t)| t.ends_with("g grants it")));
        let text = c.grant().expect("granted");
        assert!(
            text.starts_with("I've granted you: read ") && text.contains(&file),
            "{text}"
        );
        assert_eq!(c.grants.len(), 1);
        assert!(c.requests.is_empty() && !keys(&c).iter().any(|(k, _)| *k == "g"));
        // A write: its file is watched; a change is reported once.
        let tmp = std::env::temp_dir().join(format!("sentry-chat-edit-{}.md", std::process::id()));
        std::fs::write(&tmp, "a\n").unwrap();
        let path = tmp.display().to_string();
        c.watch(&path, tmp.clone());
        c.grants.push(Grant {
            access: Access::Write,
            path: path.clone(),
        });
        assert!(c.changed().is_empty());
        std::fs::write(&tmp, "a\nb\n").unwrap();
        let ch = c.changed();
        assert_eq!(ch.len(), 1);
        assert_eq!((ch[0].0.as_str(), ch[0].3), (path.as_str(), 2));
        assert!(c.changed().is_empty(), "reported once");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn the_apply_question_asks_for_one_plan() {
        use crate::claude::{Apply, Ask};
        let wf = Apply {
            key: "updates".into(),
            workflow: Some("quick-update".into()),
            ..Default::default()
        };
        let p = Ask::apply("updates", "ctx", wf).prompt();
        assert!(
            p.contains("```sentry-apply") && p.contains("never its commands"),
            "{p}"
        );
        assert!(p.contains("root's configuration under /etc"), "{p}");
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

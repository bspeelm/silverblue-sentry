//! The "ask Claude" pane: a transcript of one Claude Code session (questions, the read-only
//! commands Claude ran, streamed answers) with an input line for follow-ups.

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
}

pub struct Chat {
    pub ask: Ask,
    pub session: Option<String>,
    pub entries: Vec<(Kind, String)>,
    /// Stream id and pid of the running turn.
    pub live: Option<(u64, u32)>,
    pub started: Option<Instant>,
    pub input: String,
    pub scroll: usize,
    pub cost: f64,
    got_done: bool,
}

impl Chat {
    pub fn new(ask: Ask) -> Self {
        Self {
            ask,
            session: None,
            entries: Vec::new(),
            live: None,
            started: None,
            input: String::new(),
            scroll: 0,
            cost: 0.0,
            got_done: false,
        }
    }

    pub fn push(&mut self, kind: Kind, text: impl Into<String>) {
        self.entries.push((kind, text.into()));
        self.scroll = 0;
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
    let [log, rule, input, keys] = Layout::vertical([
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
    if c.running() {
        let s = c.started.map_or(0, |s| s.elapsed().as_secs());
        lines.push(Line::styled(
            format!("       … thinking ({}:{:02})", s / 60, s % 60),
            t.dim(),
        ));
    }
    let h = log.height as usize;
    let end = lines.len().saturating_sub(c.scroll);
    let start = end.saturating_sub(h);
    f.render_widget(Paragraph::new(lines[start..end].to_vec()), log);
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
    for (k, d) in [
        ("Enter", "ask a follow-up"),
        ("Esc", "close"),
        ("C-c", "stop"),
        ("PgUp/PgDn", "scroll"),
    ] {
        spans.extend(chip(t, k, d, t.dim));
        spans.push(Span::raw("  "));
    }
    if c.cost > 0.0 {
        spans.push(Span::styled(format!("session ${:.3}", c.cost), t.dim()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), keys);
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
    }
}

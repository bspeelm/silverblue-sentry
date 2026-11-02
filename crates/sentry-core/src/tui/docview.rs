//! Records shown as documents, in both programs: the maintenance log (its ledger as a list,
//! an entry as a document), Claude's plans and reviews (and their writer, which runs in the
//! background), and the Markdown they're all written in.

use ratatui::Frame;
use ratatui::crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use std::time::Instant;

use ratatui::widgets::{Clear, Paragraph, Wrap};

use crate::claude::Event;
use crate::maint::log::LogEntry;
use crate::maint::plan::{PlanDoc, PlanStatus};
use crate::tui::theme::Theme;

/// Enough Markdown for a plan: headings, bullets, code blocks, **bold**.
pub fn markdown(t: &Theme, text: &str) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let mut code = false;
    for raw in text.lines() {
        let l = raw.trim_end();
        if l.trim_start().starts_with("```") {
            code = !code;
            continue;
        }
        if code {
            out.push(Line::from(vec![
                Span::styled("   │ ", t.s(t.border)),
                Span::styled(l.to_string(), t.s(t.cyan)),
            ]));
            continue;
        }
        let plain = l.replace("**", "");
        if let Some(h) = plain.strip_prefix("# ") {
            out.push(Line::styled(
                format!(" {h}"),
                Style::new().fg(t.fg).add_modifier(Modifier::BOLD),
            ));
        } else if let Some(h) = plain
            .strip_prefix("## ")
            .or_else(|| plain.strip_prefix("### "))
        {
            out.push(Line::raw(""));
            out.push(Line::styled(
                format!(" {h}"),
                Style::new().fg(t.mag).add_modifier(Modifier::BOLD),
            ));
        } else {
            out.push(Line::styled(format!(" {plain}"), t.fg()));
        }
    }
    out
}

/// The Log view: the maintenance ledger as a list, or one entry as a document.
pub struct LogView {
    pub entries: Vec<LogEntry>,
    pub cur: usize,
    /// An entry open, scrolled this far from the top.
    pub open: Option<usize>,
    /// The item selected when it was opened (its entries are marked).
    pub item: Option<String>,
}

impl LogView {
    /// Start on the item's newest entry when there is one.
    pub fn new(entries: Vec<LogEntry>, item: Option<String>) -> Self {
        let cur = item
            .as_ref()
            .and_then(|i| entries.iter().position(|e| e.head.item.as_ref() == Some(i)))
            .unwrap_or(0);
        Self {
            entries,
            cur,
            open: None,
            item,
        }
    }

    /// j/k pick a run, Enter opens it, Esc goes back a level. False: close the view.
    pub fn key(&mut self, code: KeyCode) -> bool {
        let n = self.entries.len();
        match (&mut self.open, code) {
            (Some(_), KeyCode::Esc | KeyCode::Char('q') | KeyCode::Backspace) => self.open = None,
            (Some(s), KeyCode::Down | KeyCode::Char('j')) => *s += 1,
            (Some(s), KeyCode::Up | KeyCode::Char('k')) => *s = s.saturating_sub(1),
            (Some(s), KeyCode::PageDown | KeyCode::Char(' ')) => *s += 20,
            (Some(s), KeyCode::PageUp) => *s = s.saturating_sub(20),
            (Some(s), KeyCode::Home | KeyCode::Char('g')) => *s = 0,
            (Some(s), KeyCode::End | KeyCode::Char('G')) => *s = usize::MAX / 2,
            (Some(_), _) => {}
            (None, KeyCode::Esc | KeyCode::Char('q')) => return false,
            (None, KeyCode::Down | KeyCode::Char('j')) => {
                self.cur = (self.cur + 1).min(n.saturating_sub(1))
            }
            (None, KeyCode::Up | KeyCode::Char('k')) => self.cur = self.cur.saturating_sub(1),
            (None, KeyCode::Home | KeyCode::Char('g')) => self.cur = 0,
            (None, KeyCode::End | KeyCode::Char('G')) => self.cur = n.saturating_sub(1),
            (None, KeyCode::Enter) if n > 0 => self.open = Some(0),
            _ => {}
        }
        true
    }
}

pub fn draw_log(f: &mut Frame, area: Rect, t: &Theme, lv: &LogView, dir: &str) {
    use ratatui::widgets::{Cell, Row};
    f.render_widget(Clear, area);
    let [head, rule, body] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);
    let title = Span::styled(
        " Maintenance log ",
        Style::new()
            .fg(t.ink)
            .bg(t.cyan)
            .add_modifier(Modifier::BOLD),
    );
    let rule_line = || Paragraph::new("─".repeat(rule.width as usize)).style(t.s(t.border));
    if let (Some(scroll), Some(e)) = (lv.open, lv.entries.get(lv.cur)) {
        let h = &e.head;
        let mut l1 = vec![title, Span::styled(format!("  {}", e.file_name()), t.fg())];
        if !h.tags.is_empty() {
            l1.push(Span::styled(format!("  · {}", h.tags.join(" ")), t.dim()));
        }
        let l2 = Line::styled(
            format!(
                " {}{}",
                h.ended
                    .or(h.started)
                    .map_or(String::new(), |t| t.strftime("%Y-%m-%d %H:%M").to_string()),
                h.duration_s.map_or(String::new(), |d| format!(
                    " · took {}m{:02}s",
                    d / 60,
                    d % 60
                ))
            ),
            t.dim(),
        );
        f.render_widget(Paragraph::new(vec![Line::from(l1), l2]), head);
        f.render_widget(rule_line(), rule);
        let lines = markdown(t, &e.body);
        let top = scroll.min(lines.len().saturating_sub(body.height as usize));
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .scroll((top as u16, 0)),
            body,
        );
        return;
    }
    f.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                title,
                Span::styled(format!("  {} run(s)", lv.entries.len()), t.fg()),
            ]),
            Line::styled(format!(" {dir}/LOG.md"), t.dim()),
        ]),
        head,
    );
    f.render_widget(rule_line(), rule);
    if lv.entries.is_empty() {
        f.render_widget(
            Paragraph::new(Line::styled(
                "  Nothing logged yet: every workflow run is written here when it ends.",
                t.dim(),
            )),
            body,
        );
        return;
    }
    let rows: Vec<Row> = lv
        .entries
        .iter()
        .map(|e| {
            let h = &e.head;
            let mine = lv.item.is_some() && h.item == lv.item;
            let change = match (&h.from, &h.to) {
                (Some(a), Some(b)) => format!("{a} → {b}"),
                _ if h.kind == "retire" => "retired".into(),
                _ => String::new(),
            };
            let rc = match h.result.as_str() {
                "done" if h.failed.is_empty() && h.by_hand.is_empty() => t.green,
                "done" => t.yellow,
                _ => t.red,
            };
            Row::new(vec![
                Cell::from(if mine { "●" } else { " " }).style(t.s(t.mag)),
                Cell::from(
                    h.ended
                        .or(h.started)
                        .map_or("?".into(), |t| t.strftime("%Y-%m-%d %H:%M").to_string()),
                )
                .style(t.dim()),
                Cell::from(h.item.clone().unwrap_or_else(|| "-".into())).style(t.fg()),
                Cell::from(change).style(t.fg()),
                Cell::from(h.workflow.clone()).style(t.dim()),
                Cell::from(h.result.clone()).style(t.s(rc)),
                Cell::from(h.summary.clone()).style(t.fg()),
            ])
        })
        .collect();
    crate::tui::widgets::table(
        f,
        body,
        t,
        crate::tui::widgets::TableSpec {
            header: vec![
                "", "When", "Item", "Change", "Workflow", "Result", "Summary",
            ],
            widths: vec![
                Constraint::Length(1),
                Constraint::Length(16),
                Constraint::Length(14),
                Constraint::Length(26),
                Constraint::Length(16),
                Constraint::Length(9),
                Constraint::Fill(1),
            ],
            rows,
            selected: Some(lv.cur),
        },
    );
}

/// Claude writing (or revising) one plan in the background.
pub struct Writer {
    pub item: String,
    pub doc: PlanDoc,
    /// Writing a maintenance review instead of a plan.
    pub review: Option<crate::maint::review::ReviewDoc>,
    /// Stream id and pid of the running turn.
    pub live: Option<(u64, u32)>,
    pub started: Instant,
    pub web: usize,
    pub files: usize,
    pub server: usize,
    /// Where its commands run, for the progress line ("server", "machine").
    pub place: &'static str,
    /// What it's doing now, in a few words.
    pub doing: String,
    /// The turn's final answer (the plan), or why there's none.
    pub answer: Option<String>,
    pub err: Option<String>,
    pub session: Option<String>,
}

impl Writer {
    pub fn new(item: &str, doc: PlanDoc) -> Self {
        let session = doc.head.session.clone();
        Self {
            item: item.to_string(),
            doc,
            review: None,
            live: None,
            started: Instant::now(),
            web: 0,
            files: 0,
            server: 0,
            place: "server",
            doing: "starting".into(),
            answer: None,
            err: None,
            session,
        }
    }

    /// A maintenance review, written the same way as a plan.
    pub fn review(doc: crate::maint::review::ReviewDoc) -> Self {
        let session = doc.head.session.clone();
        let mut w = Self::new(REVIEW, PlanDoc::default());
        w.session = session;
        w.review = Some(doc);
        w
    }

    pub fn running(&self) -> bool {
        self.live.is_some()
    }

    pub fn on_event(&mut self, e: Event) {
        match e {
            Event::Init { session_id } => self.session = Some(session_id),
            Event::Text(_) => self.doing = "writing".into(),
            Event::ToolUse { name, input } => {
                self.doing = match name.as_str() {
                    "WebFetch" | "WebSearch" => {
                        self.web += 1;
                        "reading release notes".into()
                    }
                    "Read" => {
                        self.files += 1;
                        "reading your notes".into()
                    }
                    _ => {
                        self.server += 1;
                        let cmd = input
                            .split(" -- ")
                            .nth(1)
                            .unwrap_or(&input)
                            .chars()
                            .take(40)
                            .collect::<String>();
                        format!("checking the {}: {cmd}", self.place)
                    }
                }
            }
            Event::ToolResult { .. } => {}
            Event::Done {
                is_error, result, ..
            } => {
                if is_error {
                    self.err = Some(result);
                } else {
                    self.answer = Some(result);
                }
            }
        }
    }

    pub fn progress(&self) -> String {
        let s = self.started.elapsed().as_secs();
        format!(
            "{} · {} web page(s) · {} note file(s) · {} {} read(s) · {}:{:02}",
            self.doing,
            self.web,
            self.files,
            self.server,
            self.place,
            s / 60,
            s % 60
        )
    }
}

/// The writer's item name while it writes a review.
pub const REVIEW: &str = "(review)";

/// The Plan view: the item's plan as a document, or Claude's progress while it writes.
pub fn draw(
    f: &mut Frame,
    area: Rect,
    t: &Theme,
    doc: Option<&PlanDoc>,
    writer: Option<&Writer>,
    scroll: usize,
    path: &str,
) {
    f.render_widget(Clear, area);
    let [head, rule, body] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);
    let d = writer.map(|w| &w.doc).or(doc);
    let Some(d) = d else {
        f.render_widget(Paragraph::new(Line::styled("no plan", t.dim())), body);
        return;
    };
    let h = &d.head;
    let (status, color) = match (writer.is_some_and(|w| w.running()), h.status) {
        (true, _) => ("Claude is writing it", t.cyan),
        (_, PlanStatus::Ready) => ("ready to apply", t.green),
        (_, PlanStatus::Wait) => ("Claude advises waiting", t.yellow),
        (_, PlanStatus::Failed) => ("writing it failed", t.red),
        (_, s) => (s.word(), t.dim),
    };
    let target = h.to.clone().unwrap_or_else(|| {
        if h.vars.contains_key("unit") {
            "retire".into()
        } else {
            "?".into()
        }
    });
    let mut l1 = vec![
        Span::styled(
            " Plan ",
            Style::new()
                .fg(t.ink)
                .bg(t.mag)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "  {}  {} → {}",
                h.item,
                h.from.as_deref().unwrap_or("?"),
                target
            ),
            t.fg(),
        ),
        Span::styled(format!("  · {}", h.workflow), t.dim()),
        Span::styled(format!("  · {status}"), t.s(color)),
    ];
    if let Some(u) = h.updated.or(h.created) {
        l1.push(Span::styled(
            format!("  · {}", u.strftime("%Y-%m-%d %H:%M")),
            t.dim(),
        ));
    }
    let l2 = match writer.filter(|w| w.running()) {
        Some(w) => Line::styled(format!(" {}", w.progress()), t.s(t.cyan)),
        None => Line::styled(
            format!(
                " {}{}",
                path,
                h.note
                    .as_deref()
                    .map_or(String::new(), |n| format!("  · note: {n}"))
            ),
            t.dim(),
        ),
    };
    f.render_widget(Paragraph::new(vec![Line::from(l1), l2]), head);
    f.render_widget(
        Paragraph::new("─".repeat(rule.width as usize)).style(t.s(t.border)),
        rule,
    );
    let lines = if d.body.trim().is_empty() {
        vec![Line::styled(
            if writer.is_some_and(|w| w.running()) {
                "  The plan appears here when Claude has gathered what it needs and written it."
            } else {
                "  (empty)"
            },
            t.dim(),
        )]
    } else {
        markdown(t, &d.body)
    };
    // Scroll is lines from the top; clamp so the last page stays full.
    let max = lines.len().saturating_sub(body.height as usize);
    let top = scroll.min(max);
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((top as u16, 0)),
        body,
    );
}

/// The Review view: the latest maintenance review, or Claude's progress while it writes.
pub fn draw_review(
    f: &mut Frame,
    area: Rect,
    t: &Theme,
    doc: Option<&crate::maint::review::ReviewDoc>,
    writer: Option<&Writer>,
    scroll: usize,
) {
    f.render_widget(Clear, area);
    let [head, rule, body] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);
    let writing = writer.is_some_and(|w| w.running());
    let mut l1 = vec![Span::styled(
        " Maintenance review ",
        Style::new()
            .fg(t.ink)
            .bg(t.mag)
            .add_modifier(Modifier::BOLD),
    )];
    if let Some(d) = doc {
        l1.push(Span::styled(
            format!(
                "  {}",
                d.head
                    .updated
                    .or(d.head.created)
                    .map_or(String::new(), |u| u.strftime("%Y-%m-%d %H:%M").to_string())
            ),
            t.fg(),
        ));
    }
    let open = doc.map_or(0, |d| d.open().len());
    let l2 = match writer.filter(|w| w.running()) {
        Some(w) => Line::styled(format!(" {}", w.progress()), t.s(t.cyan)),
        None if open > 0 => Line::styled(
            format!(
                " {open} suggested task{} · a adds one to Maintenance · x skips one · R writes a new review",
                if open == 1 { "" } else { "s" }
            ),
            t.s(t.yellow),
        ),
        None => Line::styled(
            " what to maintain next, and why · R writes a new one",
            t.dim(),
        ),
    };
    f.render_widget(Paragraph::new(vec![Line::from(l1), l2]), head);
    f.render_widget(
        Paragraph::new("─".repeat(rule.width as usize)).style(t.s(t.border)),
        rule,
    );
    let lines = match doc {
        Some(d) if !writing => {
            let mut l = suggestions(t, d);
            l.extend(markdown(t, &d.body));
            l
        }
        Some(d) => {
            let mut l = vec![
                Line::styled(
                    "  Claude is writing a new review; the last one is below.",
                    t.s(t.cyan),
                ),
                Line::raw(""),
            ];
            l.extend(markdown(t, &d.body));
            l
        }
        None if writing => vec![Line::styled(
            "  The review appears here when Claude has gathered what it needs and written it.",
            t.dim(),
        )],
        None => vec![Line::styled("  No review yet: R writes one.", t.dim())],
    };
    let top = scroll.min(lines.len().saturating_sub(body.height as usize));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((top as u16, 0)),
        body,
    );
}

/// A review's suggested tasks, above its text.
fn suggestions(t: &Theme, d: &crate::maint::review::ReviewDoc) -> Vec<Line<'static>> {
    use crate::maint::tasks::SugState;
    if d.head.suggest.is_empty() {
        return Vec::new();
    }
    let mut l = vec![Line::styled(
        "Suggested tasks",
        t.s(t.mag).add_modifier(Modifier::BOLD),
    )];
    for s in &d.head.suggest {
        let (mark, style) = match s.state {
            SugState::Open => ("open   ", t.s(t.yellow)),
            SugState::Added => ("added  ", t.s(t.green)),
            SugState::Skipped => ("skipped", t.dim()),
        };
        l.push(Line::from(vec![
            Span::styled(format!("  {mark}  "), style),
            Span::styled(format!("{:<8}", s.task.level.word()), t.dim()),
            Span::styled(s.task.title.clone(), t.fg()),
            Span::styled(format!("  · {} · {}", s.task.when(), s.task.act), t.dim()),
        ]));
    }
    l.push(Line::raw(""));
    l
}

/// What the confirm box shows before a suggested task is added: the task and its TOML.
pub fn task_lines(t: &Theme, task: &crate::maint::tasks::Task, file: &str) -> Vec<Line<'static>> {
    let mut l = vec![
        Line::styled(task.title.clone(), t.fg().add_modifier(Modifier::BOLD)),
        Line::styled(task.why.clone(), t.fg()),
        Line::raw(""),
        Line::styled(format!("Added to {file}:"), t.dim()),
    ];
    l.extend(
        task.to_toml()
            .lines()
            .map(|x| Line::styled(format!("  {x}"), t.s(t.cyan))),
    );
    l.push(Line::raw(""));
    l.push(Line::styled(
        format!(
            "It shows on Maintenance while it's due ({}). Nothing runs now.",
            task.when()
        ),
        t.dim(),
    ));
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_counts_what_claude_reads() {
        let mut w = Writer::new("web", PlanDoc::default());
        w.on_event(Event::ToolUse {
            name: "WebFetch".into(),
            input: "{}".into(),
        });
        w.on_event(Event::ToolUse {
            name: "Bash".into(),
            input: "sentry-server exec myserver -- docker ps".into(),
        });
        assert!(
            w.progress()
                .starts_with("checking the server: docker ps · 1 web page(s)")
        );
        w.on_event(Event::Done {
            is_error: false,
            result: "TARGET: 1.5.2\n# Plan".into(),
            cost: None,
        });
        assert_eq!(w.answer.as_deref(), Some("TARGET: 1.5.2\n# Plan"));
    }
}

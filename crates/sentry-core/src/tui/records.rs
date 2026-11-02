//! Records (`v`, `R`, `:log`, both programs): everything kept about the maintenance, in one
//! place. Tasks (every one that applies, due or not), the log, the plans (open and done),
//! Claude's reviews, and what's put off or marked expected (Later), each a section; `[`/`]`
//! switch. What a key does that changes something is the app's: this returns an `Fx`.

use std::path::PathBuf;

use jiff::Timestamp;
use jiff::civil::Date;
use ratatui::Frame;
use ratatui::crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Clear, Paragraph, Row, Wrap};

use super::docview::{LogView, draw_log, markdown};
use super::theme::Theme;
use super::widgets::{TableSpec, table};
use crate::maint::log::LogEntry;
use crate::maint::plan::{PlanDoc, PlanStatus};
use crate::maint::review::ReviewDoc;
use crate::maint::tasks::{self, Task};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Tasks,
    Log,
    Plans,
    Reviews,
    Later,
}

impl Section {
    pub const ALL: [Section; 5] = [
        Section::Tasks,
        Section::Log,
        Section::Plans,
        Section::Reviews,
        Section::Later,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Section::Tasks => "Tasks",
            Section::Log => "Log",
            Section::Plans => "Plans",
            Section::Reviews => "Reviews",
            Section::Later => "Later",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }
}

/// Something taken off Maintenance, and how to bring it back.
#[derive(Debug, Clone, PartialEq)]
pub enum LaterKind {
    /// `z`: until this date (`later.toml`).
    Snoozed(Date),
    /// A finding marked expected (the baseline).
    Expected,
    /// A listener marked expected (sentry's baseline).
    Listener,
    /// Something discovery found, ignored (sentry-server's `items.toml`).
    Ignored,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LaterRow {
    pub kind: LaterKind,
    /// The snooze key, finding id, listener or discovery key.
    pub key: String,
    /// Where it's written, for the row.
    pub file: &'static str,
}

/// What Records shows, read by the app when it opens.
pub struct Data {
    /// Where the records live (the header says so).
    pub dir: String,
    /// Every task that applies (`tasks::effective`).
    pub tasks: Vec<Task>,
    pub log: Vec<LogEntry>,
    /// The open plans, then those done (`plans/done/`).
    pub plans: Vec<(PathBuf, PlanDoc)>,
    /// Newest first.
    pub reviews: Vec<(PathBuf, ReviewDoc)>,
    pub later: Vec<LaterRow>,
    pub audited: Option<Timestamp>,
    pub now: Timestamp,
}

/// What a key asks the app to do.
#[derive(Debug, Clone, PartialEq)]
pub enum Fx {
    Close,
    TaskDo(String),
    TaskEvery(String),
    TaskRemove(String),
    TaskDone(String),
    /// Add a note to this entry.
    Note(Box<LogEntry>),
    /// An open plan, in its own view (apply, revise, drop there), by item.
    OpenPlan(String),
    OpenReview(PathBuf),
    NewReview,
    Undo(LaterRow),
}

pub struct Records {
    pub section: Section,
    pub data: Data,
    /// The Log section (a list, or one entry open).
    pub log: LogView,
    cur: [usize; 5],
    /// A done plan open as a document, scrolled this far.
    doc: Option<usize>,
}

impl Records {
    /// `item`: the log marks that item's entries and starts on its newest.
    pub fn new(mut data: Data, section: Section, item: Option<String>) -> Self {
        let log = LogView::new(std::mem::take(&mut data.log), item);
        let mut cur = [0; 5];
        // The log starts on the item's newest entry.
        cur[Section::Log.index()] = log.cur;
        Self {
            section,
            data,
            log,
            cur,
            doc: None,
        }
    }

    fn len(&self) -> usize {
        match self.section {
            Section::Tasks => self.data.tasks.len(),
            Section::Log => self.log.entries.len(),
            Section::Plans => self.data.plans.len(),
            Section::Reviews => self.data.reviews.len(),
            Section::Later => self.data.later.len(),
        }
    }

    fn sel(&self) -> usize {
        self.cur[self.section.index()].min(self.len().saturating_sub(1))
    }

    pub fn task(&self) -> Option<&Task> {
        (self.section == Section::Tasks)
            .then(|| self.data.tasks.get(self.sel()))
            .flatten()
    }

    fn switch(&mut self, by: isize) {
        let n = Section::ALL.len() as isize;
        let i = (self.section.index() as isize + by).rem_euclid(n);
        self.section = Section::ALL[i as usize];
        self.doc = None;
    }

    /// A key. `None`: handled here (moved, switched, opened).
    pub fn key(&mut self, code: KeyCode) -> Option<Fx> {
        // An open document (a log entry, a done plan) scrolls; Esc closes it.
        if self.section == Section::Log && self.log.open.is_some() {
            self.log.key(code);
            return None;
        }
        if let Some(s) = self.doc.as_mut() {
            match code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Backspace => self.doc = None,
                KeyCode::Down | KeyCode::Char('j') => *s += 1,
                KeyCode::Up | KeyCode::Char('k') => *s = s.saturating_sub(1),
                KeyCode::PageDown | KeyCode::Char(' ') => *s += 20,
                KeyCode::PageUp => *s = s.saturating_sub(20),
                _ => {}
            }
            return None;
        }
        let n = self.len();
        let i = self.section.index();
        match code {
            KeyCode::Esc | KeyCode::Char('q') => return Some(Fx::Close),
            KeyCode::Char(']') | KeyCode::Right | KeyCode::Tab => self.switch(1),
            KeyCode::Char('[') | KeyCode::Left | KeyCode::BackTab => self.switch(-1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.cur[i] = (self.sel() + 1).min(n.saturating_sub(1))
            }
            KeyCode::Up | KeyCode::Char('k') => self.cur[i] = self.sel().saturating_sub(1),
            KeyCode::Home | KeyCode::Char('g') => self.cur[i] = 0,
            KeyCode::End | KeyCode::Char('G') => self.cur[i] = n.saturating_sub(1),
            _ => return self.act(code),
        }
        if self.section == Section::Log {
            self.log.cur = self.cur[i].min(self.log.entries.len().saturating_sub(1));
        }
        None
    }

    fn act(&mut self, code: KeyCode) -> Option<Fx> {
        let i = self.sel();
        match (self.section, code) {
            (Section::Tasks, c) => {
                let id = self.data.tasks.get(i)?.id.clone();
                match c {
                    KeyCode::Enter => Some(Fx::TaskDo(id)),
                    KeyCode::Char('e') => Some(Fx::TaskEvery(id)),
                    KeyCode::Char('x') => Some(Fx::TaskRemove(id)),
                    KeyCode::Char('d') => Some(Fx::TaskDone(id)),
                    _ => None,
                }
            }
            (Section::Log, KeyCode::Enter) => {
                self.log.cur = i;
                self.log.key(KeyCode::Enter);
                None
            }
            (Section::Log, KeyCode::Char('n')) => {
                Some(Fx::Note(Box::new(self.log.entries.get(i)?.clone())))
            }
            (Section::Plans, KeyCode::Enter) => {
                let (p, d) = self.data.plans.get(i)?;
                if is_done(p) {
                    self.doc = Some(0);
                    None
                } else {
                    Some(Fx::OpenPlan(d.head.item.clone()))
                }
            }
            (Section::Reviews, KeyCode::Enter) => {
                Some(Fx::OpenReview(self.data.reviews.get(i)?.0.clone()))
            }
            (Section::Reviews, KeyCode::Char('R')) => Some(Fx::NewReview),
            (Section::Later, KeyCode::Char('u')) => Some(Fx::Undo(self.data.later.get(i)?.clone())),
            _ => None,
        }
    }

    /// The keys of the section on screen.
    pub fn hints(&self) -> Vec<(&'static str, &'static str)> {
        if (self.section == Section::Log && self.log.open.is_some()) || self.doc.is_some() {
            return vec![("j/k", "scroll"), ("Esc", "back")];
        }
        let mut h = vec![("[ ]", "section"), ("j/k", "select")];
        h.extend(match self.section {
            Section::Tasks => vec![
                ("Enter", "do it now"),
                ("d", "done"),
                ("e", "every"),
                ("x", "remove / off"),
            ],
            Section::Log => vec![("Enter", "open"), ("n", "add a note")],
            Section::Plans => vec![("Enter", "open")],
            Section::Reviews => vec![("Enter", "open"), ("R", "new review")],
            Section::Later => vec![("u", "bring it back")],
        });
        h.push(("Esc", "close"));
        h
    }
}

fn is_done(p: &std::path::Path) -> bool {
    p.parent()
        .and_then(|d| d.file_name())
        .is_some_and(|n| n == "done")
}

fn day(t: Option<Timestamp>) -> String {
    t.map_or("-".into(), |t| t.strftime("%Y-%m-%d").to_string())
}

pub fn draw(f: &mut Frame, area: Rect, t: &Theme, r: &Records) {
    f.render_widget(Clear, area);
    let [head, rule, body] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);
    let mut tabs = vec![Span::styled(
        " Records ",
        Style::new()
            .fg(t.ink)
            .bg(t.cyan)
            .add_modifier(Modifier::BOLD),
    )];
    for s in Section::ALL {
        let n = match s {
            Section::Tasks => r.data.tasks.len(),
            Section::Log => r.log.entries.len(),
            Section::Plans => r.data.plans.len(),
            Section::Reviews => r.data.reviews.len(),
            Section::Later => r.data.later.len(),
        };
        let label = format!("  {} {n}", s.title());
        tabs.push(if s == r.section {
            Span::styled(label, t.s(t.cyan).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(label, t.dim())
        });
    }
    f.render_widget(
        Paragraph::new(vec![
            Line::from(tabs),
            Line::styled(format!(" {} · [ ] switch", r.data.dir), t.dim()),
        ]),
        head,
    );
    f.render_widget(
        Paragraph::new("─".repeat(rule.width as usize)).style(t.s(t.border)),
        rule,
    );
    let sel = Some(r.sel());
    let empty = |f: &mut Frame, what: &str| {
        f.render_widget(
            Paragraph::new(Line::styled(format!("  {what}"), t.dim())),
            body,
        )
    };
    match r.section {
        Section::Log => draw_log(f, body, t, &r.log, &format!("{}/log", r.data.dir)),
        Section::Tasks if r.data.tasks.is_empty() => empty(f, "No tasks."),
        Section::Tasks => {
            let rows = r
                .data
                .tasks
                .iter()
                .map(|x| {
                    let last = tasks::last_done(x, &r.log.entries, r.data.audited);
                    let due = tasks::due(x, &r.log.entries, r.data.audited, r.data.now);
                    let next = match (x.off, due, x.every, last) {
                        (true, ..) => "off".to_string(),
                        (_, true, ..) => "due".into(),
                        (_, _, Some(e), Some(l)) => day(l.checked_add(e.0).ok()),
                        (_, _, None, Some(_)) => "done".into(),
                        _ => "-".into(),
                    };
                    let nc = match next.as_str() {
                        "due" => t.yellow,
                        "off" => t.dim,
                        _ => t.fg,
                    };
                    Row::new(vec![
                        Cell::from(x.title.clone()).style(t.fg()),
                        Cell::from(x.act.clone()).style(t.dim()),
                        Cell::from(x.when()).style(t.dim()),
                        Cell::from(day(last)).style(t.dim()),
                        Cell::from(next).style(t.s(nc)),
                        Cell::from(x.source.word()).style(t.dim()),
                    ])
                })
                .collect();
            table(
                f,
                body,
                t,
                TableSpec {
                    header: vec!["Task", "Does", "When", "Last done", "Next", "From"],
                    widths: vec![
                        Constraint::Fill(3),
                        Constraint::Fill(2),
                        Constraint::Length(10),
                        Constraint::Length(10),
                        Constraint::Length(10),
                        Constraint::Length(10),
                    ],
                    rows,
                    selected: sel,
                },
            );
        }
        Section::Plans if r.data.plans.is_empty() => {
            empty(f, "No plans yet: p on Maintenance has Claude write one.")
        }
        Section::Plans => {
            if let (Some(scroll), Some((p, d))) = (r.doc, r.data.plans.get(r.sel())) {
                let mut lines = vec![
                    Line::styled(
                        format!(
                            " {} · {} · {}",
                            d.head.item,
                            d.head.status.word(),
                            p.display()
                        ),
                        t.dim(),
                    ),
                    Line::raw(""),
                ];
                lines.extend(markdown(t, &d.body));
                let top = scroll.min(lines.len().saturating_sub(body.height as usize));
                f.render_widget(
                    Paragraph::new(lines)
                        .wrap(Wrap { trim: false })
                        .scroll((top as u16, 0)),
                    body,
                );
                return;
            }
            let rows = r
                .data
                .plans
                .iter()
                .map(|(p, d)| {
                    let h = &d.head;
                    let c = match h.status {
                        PlanStatus::Ready => t.green,
                        PlanStatus::Writing | PlanStatus::Wait => t.yellow,
                        PlanStatus::Failed => t.red,
                        _ => t.dim,
                    };
                    Row::new(vec![
                        Cell::from(h.item.clone()).style(t.fg()),
                        Cell::from(h.status.word()).style(t.s(c)),
                        Cell::from(h.to.clone().unwrap_or_else(|| "-".into())).style(t.fg()),
                        Cell::from(day(h.updated.or(h.created))).style(t.dim()),
                        Cell::from(if is_done(p) { "done/" } else { "open" }).style(t.dim()),
                        Cell::from(h.note.clone().unwrap_or_default()).style(t.dim()),
                    ])
                })
                .collect();
            table(
                f,
                body,
                t,
                TableSpec {
                    header: vec!["Plan", "Status", "To", "Updated", "", "Note"],
                    widths: vec![
                        Constraint::Fill(2),
                        Constraint::Length(9),
                        Constraint::Length(14),
                        Constraint::Length(10),
                        Constraint::Length(5),
                        Constraint::Fill(3),
                    ],
                    rows,
                    selected: sel,
                },
            );
        }
        Section::Reviews if r.data.reviews.is_empty() => {
            empty(f, "No reviews yet: R has Claude review it all.")
        }
        Section::Reviews => {
            let rows = r
                .data
                .reviews
                .iter()
                .map(|(p, d)| {
                    let open = d.open().len();
                    Row::new(vec![
                        Cell::from(day(d.head.updated.or(d.head.created))).style(t.fg()),
                        Cell::from(d.head.status.word()).style(t.dim()),
                        Cell::from(if open == 0 {
                            String::new()
                        } else {
                            format!("{open} suggested task(s)")
                        })
                        .style(t.s(t.yellow)),
                        Cell::from(
                            p.file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default(),
                        )
                        .style(t.dim()),
                    ])
                })
                .collect();
            table(
                f,
                body,
                t,
                TableSpec {
                    header: vec!["When", "Status", "Open", "File"],
                    widths: vec![
                        Constraint::Length(10),
                        Constraint::Length(9),
                        Constraint::Length(20),
                        Constraint::Fill(1),
                    ],
                    rows,
                    selected: sel,
                },
            );
        }
        Section::Later if r.data.later.is_empty() => {
            empty(f, "Nothing put off or marked expected.")
        }
        Section::Later => {
            let rows = r
                .data
                .later
                .iter()
                .map(|x| {
                    let (what, when) = match &x.kind {
                        LaterKind::Snoozed(d) => ("put off", format!("until {d}")),
                        LaterKind::Expected => ("expected", String::new()),
                        LaterKind::Listener => ("expected listener", String::new()),
                        LaterKind::Ignored => ("ignored", String::new()),
                    };
                    Row::new(vec![
                        Cell::from(what).style(t.fg()),
                        Cell::from(x.key.clone()).style(t.fg()),
                        Cell::from(when).style(t.dim()),
                        Cell::from(x.file).style(t.dim()),
                    ])
                })
                .collect();
            table(
                f,
                body,
                t,
                TableSpec {
                    header: vec!["", "What", "When", "File"],
                    widths: vec![
                        Constraint::Length(18),
                        Constraint::Fill(3),
                        Constraint::Length(17),
                        Constraint::Fill(1),
                    ],
                    rows,
                    selected: sel,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> Data {
        Data {
            dir: "~/.config/sentry".into(),
            tasks: ["job-audit", "job-update-check"]
                .map(|id| Task {
                    id: id.into(),
                    title: id.into(),
                    why: String::new(),
                    level: crate::maint::Level::Routine,
                    every: Some(crate::config::Dur::secs(7 * 86400)),
                    act: "audit".into(),
                    item: None,
                    steps: String::new(),
                    added: None,
                    off: false,
                    source: tasks::Source::Default,
                    review: None,
                    after: None,
                })
                .to_vec(),
            log: vec![LogEntry::event(
                "",
                "job",
                "audit",
                true,
                "fine",
                &[],
                "2026-11-01T00:00:00Z".parse().unwrap(),
            )],
            plans: Vec::new(),
            reviews: Vec::new(),
            later: vec![LaterRow {
                kind: LaterKind::Snoozed(jiff::civil::date(2026, 12, 1)),
                key: "updates".into(),
                file: "later.toml",
            }],
            audited: None,
            now: "2026-11-02T00:00:00Z".parse().unwrap(),
        }
    }

    #[test]
    fn sections_switch_and_keys_say_what_to_do() {
        let mut r = Records::new(data(), Section::Tasks, None);
        assert_eq!(r.key(KeyCode::Enter), Some(Fx::TaskDo("job-audit".into())));
        assert_eq!(
            r.key(KeyCode::Char('x')),
            Some(Fx::TaskRemove("job-audit".into()))
        );
        // [ wraps to Later; u brings the row back.
        assert_eq!(r.key(KeyCode::Char('[')), None);
        assert_eq!(r.section, Section::Later);
        assert!(matches!(r.key(KeyCode::Char('u')), Some(Fx::Undo(row)) if row.key == "updates"));
        // ] twice: Log; Enter opens the entry, Esc closes it, Esc again closes Records.
        r.key(KeyCode::Char(']'));
        r.key(KeyCode::Char(']'));
        assert_eq!(r.section, Section::Log);
        assert_eq!(r.key(KeyCode::Enter), None);
        assert!(r.log.open.is_some());
        assert_eq!(r.key(KeyCode::Esc), None);
        assert!(matches!(r.key(KeyCode::Char('n')), Some(Fx::Note(_))));
        assert_eq!(r.key(KeyCode::Esc), Some(Fx::Close));
    }
}

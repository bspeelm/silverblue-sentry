//! Maintenance: what on the network needs attention (the shared list, `maintlist`): the
//! audit's findings, the audit itself when it's due, and the tasks due from `tasks.toml`.
//! Beside it, what the last audit looked at; `F` opens its report. Nothing here changes the
//! router: a finding is looked at, marked expected or put off; a task is done by hand.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use super::{Hints, View, report};
use crate::audit::Report;
use crate::collect::services::State as SvcState;
use crate::tui::data::Kind;
use crate::tui::target::{Effect, Modal, Own};
use sentry_core::finding::{Finding, Sev};
use sentry_core::fmt;
use sentry_core::maint::Level;
use sentry_core::maint::rec::{self, Target};
use sentry_core::maint::tasks::{Do, Task};
use sentry_core::tui::keys::Action as Key;
use sentry_core::tui::maintlist::{self, Dismiss, Verbs};
use sentry_core::tui::reportview::ReportView;
use sentry_core::tui::widgets::{inner, panel};

/// What Enter does on a row.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// An audit finding (its id): its place in the report.
    Finding(String),
    /// Audit the network now.
    Audit,
    /// A task (its id): what Enter does is the task's own.
    Task(String),
}

/// Keys (for `z`): `finding:<id>`, `audit`, `task:<id>`.
pub type Rec = rec::Rec<Action>;

impl rec::Act for Action {
    fn target(&self) -> Target {
        match self {
            Action::Audit => Target::Audit,
            _ => Target::None,
        }
    }
    fn task(id: String) -> Self {
        Action::Task(id)
    }
}

/// An audit older than this is due again (as a server's is).
pub const AUDIT_EVERY_DAYS: i64 = 7;

/// The latest audit report, when there is one.
pub fn latest<'a>(v: &View<'a>) -> Option<&'a Report> {
    v.s.report.value.as_ref()?.as_deref()
}

pub fn finding<'a>(v: &View<'a>, id: &str) -> Option<&'a Finding> {
    latest(v)?.findings.iter().find(|f| f.id == id)
}

/// When it was last audited, and whether that's long enough ago to do it again (or never).
pub fn audit_age(v: &View) -> (Option<jiff::Timestamp>, bool) {
    let at = latest(v).and_then(|r| r.snapshot.taken_at);
    let due = at.is_none_or(|t| v.secs_since(t) / 86_400 >= AUDIT_EVERY_DAYS);
    (at, due)
}

/// Every task that applies: `tasks.toml`'s (a network's config implies none yet).
pub fn all_tasks(v: &View) -> Vec<Task> {
    sentry_core::maint::tasks::effective(&v.sh.tasks, Vec::new())
}

/// Every recommendation there is, whatever is shown.
pub fn every_rec(v: &View) -> Vec<Rec> {
    let mut out: Vec<Rec> = Vec::new();
    let findings = latest(v).map_or(&[][..], |r| &r.findings[..]);
    for f in findings.iter().filter(|f| !f.expected) {
        out.push(Rec {
            level: match f.severity {
                Sev::High => Level::Now,
                Sev::Medium => Level::Soon,
                Sev::Low => Level::Tidy,
            },
            key: format!("finding:{}", f.id),
            title: f.message.clone(),
            why: if f.why.is_empty() {
                f.what.clone()
            } else {
                f.why.clone()
            },
            action: Action::Finding(f.id.clone()),
            item: None,
            can_wait: false,
        });
    }
    let (audited, due) = audit_age(v);
    if due && v.s.report.value.is_some() {
        out.push(Rec {
            level: Level::Routine,
            key: "audit".into(),
            title: "Audit the network".into(),
            why: match audited {
                Some(t) => format!("The last audit was {} days ago.", v.secs_since(t) / 86_400),
                None => "No audit yet: the firewall, what listens, ssh and the web interface, who is on the network.".into(),
            },
            action: Action::Audit,
            item: None,
            can_wait: false,
        });
    }
    out.sort_by(|a, b| a.level.cmp(&b.level).then(a.title.cmp(&b.title)));
    let tasks = all_tasks(v);
    rec::finish(
        out,
        &rec::Tail {
            tasks: &tasks,
            log: &v.sh.log,
            audited,
            now: v.now,
            snooze: &v.sh.later,
            today: v.now.to_zoned(jiff::tz::TimeZone::UTC).date(),
        },
    )
}

/// What to look at next: what's due or urgent (everything with `o`), filtered.
pub fn recs(v: &View) -> Vec<Rec> {
    let mut r = rec::needed(every_rec(v), v.everything).0;
    r.retain(|x| v.matches(&[&x.title, &x.why, x.level.word()]));
    r
}

/// How many recommendations wait, not shown (`o` shows them).
pub fn waiting(v: &View) -> usize {
    rec::needed(every_rec(v), v.everything).1
}

/// A view over the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sub {
    /// The audit report (`F`).
    Report,
}

#[derive(Default)]
pub struct Maint {
    pub cur: sentry_core::tui::Cursor,
    /// The row selected (its key and title), kept when the list changes.
    pub sel: Option<String>,
    pub view: Option<Sub>,
    pub report: ReportView,
}

pub fn pick(v: &View) -> Option<Rec> {
    recs(v).get(v.cur).cloned()
}

pub fn row_key(v: &View) -> Option<String> {
    pick(v).map(|r| format!("{}:{}", r.key, r.title))
}

fn task_of(v: &View, id: &str) -> Option<Task> {
    all_tasks(v).into_iter().find(|t| t.id == id)
}

/// The keys the selected row takes (the key bar shows only these).
pub fn verbs(v: &View) -> Verbs {
    let only = |enter: &'static str| Verbs {
        enter,
        ..Default::default()
    };
    match pick(v).map(|r| r.action) {
        None => Verbs::default(),
        Some(Action::Finding(_)) => Verbs {
            dismiss: Some(Dismiss::Expected),
            like: true,
            ..only("in the report")
        },
        Some(Action::Audit) => only("audit"),
        Some(Action::Task(id)) => {
            let what = task_of(v, &id).map(|t| t.action());
            Verbs {
                done: true,
                every: true,
                manual: what == Some(Do::ByHand),
                dismiss: Some(Dismiss::Remove),
                ..only(match what {
                    Some(Do::ByHand) => "its steps",
                    Some(Do::Audit) => "audit",
                    _ => "do it",
                })
            }
        }
    }
}

/// The key bar: the row's keys (no Claude for a network yet, so no `A`), then the screen's.
pub fn hints(v: &View) -> Hints {
    // (An empty list has no row to name keys for.)
    let mut h: Hints = match pick(v) {
        Some(_) => maintlist::hints(&verbs(v), 0)
            .into_iter()
            .filter(|(k, _)| *k != "A")
            .collect(),
        None => Vec::new(),
    };
    if v.everything || waiting(v) > 0 {
        h.push(("o", maintlist::everything_word(v.everything)));
    }
    h.extend([("r", "audit"), ("F", "report"), ("v", "records")]);
    h
}

/// `?`: every row key a network's rows take.
pub fn help() -> Hints {
    let not_here = ["p / P", "t", "x", "Space / a", "A"];
    maintlist::GRAMMAR
        .iter()
        .copied()
        .filter(|(k, _)| !not_here.contains(k))
        .chain([
            ("x", "expected (a finding) · remove (a task); asks first"),
            ("b", "a finding: expected (as x, without the box)"),
            ("r / c", "audit the network now (it only reads)"),
            ("F", "the audit report"),
            ("v", "records: tasks, the log, what's put off or expected"),
        ])
        .collect()
}

/// The count on the strip: what's to check or review now.
pub fn badge(v: &View) -> Option<(String, Color)> {
    v.s.report.value.as_ref()?;
    let r = recs(v);
    let now = r.iter().filter(|x| x.level == Level::Now).count();
    let soon = r.iter().filter(|x| x.level == Level::Soon).count();
    match (now, soon) {
        (0, 0) => None,
        (0, n) => Some((format!(" {n}"), v.t.yellow)),
        (n, m) => Some((format!(" {}", n + m), v.t.red)),
    }
}

/// Enter on a task: the audit, or (by hand) its steps.
pub fn task_enter(v: &View, id: &str) -> Vec<Effect> {
    let Some(task) = task_of(v, id) else {
        return Vec::new();
    };
    match task.action() {
        Do::Audit => report::audit_now(),
        Do::ByHand => task_manual(v, id),
        Do::Run(wf) => vec![Effect::Toast(format!(
            "there are no workflows for a network yet ({wf}): d marks it done"
        ))],
        Do::Plan(it) => vec![Effect::Toast(format!(
            "nothing is tracked on a network yet ({it}): d marks it done"
        ))],
        Do::Job(j) => vec![Effect::Toast(format!(
            "{j} is a job of this machine's, not the network's: d marks it done"
        ))],
    }
}

/// `m` on a task done by hand: its steps, to do it yourself, then mark it done.
pub fn task_manual(v: &View, id: &str) -> Vec<Effect> {
    let t = v.t;
    let Some(task) = task_of(v, id).filter(|t| t.action() == Do::ByHand) else {
        return Vec::new();
    };
    let mut lines = vec![Line::styled(task.why.clone(), t.fg()), Line::raw("")];
    if task.steps.trim().is_empty() {
        lines.push(Line::styled("(no steps given)", t.dim()));
    } else {
        lines.extend(sentry_core::tui::docview::markdown(t, &task.steps));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "Do it yourself, then mark it done: it's logged, and leaves the list.",
        t.dim(),
    ));
    vec![Effect::Confirm(Modal {
        title: task.title.clone(),
        color: t.cyan,
        lines,
        yes: Some(("mark done".into(), vec![Effect::TaskDone(id.to_string())])),
    })]
}

fn key(c: char, v: &View) -> Vec<Effect> {
    let Some(r) = pick(v) else {
        return Vec::new();
    };
    let t = v.t;
    match (c, &r.action) {
        ('\n', Action::Finding(id)) => vec![Effect::own(Own::OpenReport(Some(id.clone())))],
        ('\n', Action::Audit) => report::audit_now(),
        ('\n', Action::Task(id)) => task_enter(v, id),
        ('x', Action::Finding(id)) => vec![Effect::Confirm(Modal {
            title: "Mark it expected".into(),
            color: t.yellow,
            lines: vec![
                Line::styled(r.title.clone(), t.fg()),
                Line::styled(
                    "The audit stops listing it (the network's baseline.toml). Records › Later takes it back.",
                    t.dim(),
                ),
            ],
            yes: Some((
                "yes".into(),
                vec![Effect::own(Own::Expected(id.clone(), true))],
            )),
        })],
        ('b', Action::Finding(id)) => vec![Effect::own(Own::Expected(id.clone(), true))],
        ('B', Action::Finding(id)) => {
            finding(v, id).map_or(Vec::new(), |f| report::pattern_effects(v, f))
        }
        ('d', Action::Task(id)) => vec![Effect::TaskDone(id.clone())],
        ('m', Action::Task(id)) => task_manual(v, id),
        ('e', Action::Task(id)) => vec![Effect::TaskEvery(id.clone())],
        ('x', Action::Task(id)) => vec![Effect::Confirm(Modal {
            title: "Remove this task".into(),
            color: t.yellow,
            lines: vec![
                Line::styled(r.title.clone(), t.fg()),
                Line::styled(
                    "It comes off tasks.toml and leaves Maintenance. The log keeps what was done.",
                    t.dim(),
                ),
            ],
            yes: Some(("remove".into(), vec![Effect::TaskRemove(id.clone())])),
        })],
        ('x', _) => vec![Effect::Toast(maintlist::NOTHING_TO_DISMISS.into())],
        ('z', _) => vec![Effect::Choose(maintlist::later_choice(
            t,
            &r.title,
            v.now.to_zoned(jiff::tz::TimeZone::UTC).date(),
            |_, until| vec![Effect::Snooze(r.key.clone(), until)],
        ))],
        _ => Vec::new(),
    }
}

impl Maint {
    pub fn count(&self, v: &View) -> usize {
        recs(v).len()
    }

    pub fn handle(&mut self, a: Key, v: &View) -> Vec<Effect> {
        if self.view.is_some() {
            if a == Key::Esc {
                self.view = None;
                return Vec::new();
            }
            return report::handle(&mut self.report, a, v);
        }
        match a {
            Key::Refresh | Key::Check => report::audit_now(),
            Key::Enter => key('\n', v),
            Key::Char(c @ ('x' | 'b' | 'B' | 'z' | 'd' | 'm' | 'e')) => key(c, v),
            // Nothing a network's rows do is carried out by sentry yet: no series.
            Key::Char(' ' | 'a') => vec![Effect::Toast(maintlist::NOT_IN_A_SERIES.into())],
            Key::Char('F') => self.open_report(v, None),
            Key::Char('o') => vec![Effect::Everything],
            Key::Char('v') => vec![Effect::LogOpen(None)],
            _ => Vec::new(),
        }
    }

    /// `F`, `:audit`, Enter on a finding: the audit report over the list, on that finding
    /// when one is named; its reports are read from disk.
    pub fn open_report(&mut self, v: &View, id: Option<&str>) -> Vec<Effect> {
        self.view = Some(Sub::Report);
        self.report = ReportView::default();
        if let Some(i) = id.and_then(|id| report::position(v, id)) {
            self.report.cur.sel = i;
        }
        vec![Own::fetch(Kind::Report)]
    }

    /// The list changed under the cursor: put it back on the row it was on.
    pub fn keep(&mut self, v: &View) {
        if let Some(key) = &self.sel
            && let Some(i) = recs(v)
                .iter()
                .position(|r| &format!("{}:{}", r.key, r.title) == key)
        {
            self.cur.sel = i;
        }
        let n = recs(v).len();
        self.cur.clamp(n);
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        if self.view.is_some() {
            let [head, body] =
                Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(" Maintenance › Audit report ", t.s(t.cyan)),
                    Span::styled(" Esc back", t.dim()),
                ])),
                head,
            );
            return report::draw(&mut self.report, f, body, v);
        }
        let recs = recs(v);
        let (rec_a, audit_a, detail_a) = maintlist::split(area, recs.len());
        let read = v.s.report.value.is_some();
        let (audited, _) = audit_age(v);
        let note = if !read {
            String::new()
        } else {
            format!(
                "{} · {}",
                rec::note(recs.len(), 0, waiting(v)),
                match audited {
                    Some(at) => format!("audited {}", fmt::ago(v.secs_since(at))),
                    None => "no audit yet".into(),
                }
            )
        };
        let empty = if !read {
            match &v.s.report.err {
                Some(e) => format!("audit: {e}"),
                None => "reading…".to_string(),
            }
        } else if v.filter.is_some() {
            maintlist::NO_MATCH.to_string()
        } else {
            match waiting(v) {
                0 => "✓ nothing needs attention right now · r audits again".to_string(),
                n => maintlist::empty(n),
            }
        };
        let none = maintlist::Ticks::new();
        self.cur.page = maintlist::draw(
            f,
            rec_a,
            t,
            &recs,
            maintlist::List {
                note,
                selected: (v.cur < recs.len()).then_some(v.cur),
                empty: (empty.as_str(), t.dim()),
                ticks: &none,
            },
        );

        let b = panel(t, "Last audit", audited.map_or(String::new(), fmt::date));
        let r = inner(&b, audit_a);
        f.render_widget(b, audit_a);
        f.render_widget(Paragraph::new(audit_lines(v)), r);

        let b = panel(t, "Details", "");
        let r = inner(&b, detail_a);
        f.render_widget(b, detail_a);
        let lines = match recs.get(v.cur) {
            None => vec![Line::styled(
                if read { "nothing selected" } else { "" },
                t.dim(),
            )],
            Some(x) => {
                let mut l = maintlist::detail_head(t, x, r.width as usize);
                match &x.action {
                    Action::Finding(id) => {
                        l.push(Line::styled(
                            "Enter: its place in the audit report · b or x: expected · z: later",
                            t.s(t.cyan),
                        ));
                        if let Some(fd) = finding(v, id) {
                            l.push(Line::raw(""));
                            l.extend(report::finding_lines(t, fd, r.width as usize));
                        }
                    }
                    Action::Audit => l.push(Line::styled(
                        "Enter: audit the network now (it only reads)",
                        t.s(t.cyan),
                    )),
                    Action::Task(id) => {
                        if let Some(task) = task_of(v, id) {
                            l.push(Line::styled(
                                match task.action() {
                                    Do::ByHand => {
                                        "By hand: Enter (or m) shows its steps; d marks it done."
                                            .to_string()
                                    }
                                    Do::Audit => {
                                        "Enter audits now; it's done with the audit.".to_string()
                                    }
                                    _ => "d marks it done.".to_string(),
                                },
                                t.s(t.cyan),
                            ));
                            l.push(Line::styled(
                                format!("{} · from {}", task.when(), task.source.word()),
                                t.dim(),
                            ));
                            if !task.steps.trim().is_empty() {
                                l.push(Line::raw(""));
                                l.extend(sentry_core::tui::docview::markdown(t, &task.steps));
                            }
                        }
                    }
                }
                l
            }
        };
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), r);
    }
}

/// What the last audit looked at, a line for each part.
fn audit_lines(v: &View) -> Vec<Line<'static>> {
    let t = v.t;
    let Some(rep) = latest(v) else {
        return vec![Line::styled(
            if v.s.report.value.is_some() {
                "No audit yet: r runs one. It only reads, and takes a second."
            } else {
                ""
            },
            t.dim(),
        )];
    };
    let s = &rep.snapshot;
    let open = |prefix: &str| {
        rep.findings
            .iter()
            .filter(|f| !f.expected && f.id.starts_with(prefix))
            .count()
    };
    let row = |what: &str, said: String, findings: usize| {
        let (dot, c) = match findings {
            0 => ("✓", t.green),
            _ => ("●", t.yellow),
        };
        Line::from(vec![
            Span::styled(format!("{dot} "), t.s(c)),
            Span::styled(format!("{what:<14}"), t.dim()),
            Span::styled(said, t.fg()),
        ])
    };
    let mut l = Vec::new();
    if let Some(u) = &s.uci {
        l.push(row(
            "firewall",
            format!(
                "{} zones · {} forwards",
                u.zones().len(),
                u.forwards().iter().filter(|f| f.enabled).count()
            ),
            open("net:zone:") + open("net:forward:"),
        ));
        l.push(row(
            "access",
            format!(
                "ssh {} · web interface {}",
                if open("net:ssh:") > 0 {
                    "takes passwords"
                } else {
                    "keys only"
                },
                if open("net:luci:") > 0 {
                    "over HTTP too"
                } else {
                    "HTTPS"
                }
            ),
            open("net:ssh:") + open("net:luci:") + open("net:cert:"),
        ));
        l.push(row(
            "config",
            match u.staged_audited().len() {
                0 => "nothing staged".to_string(),
                n => format!("{n} change(s) staged"),
            },
            open("net:config:"),
        ));
    }
    if let Some(ls) = &s.listeners {
        l.push(row(
            "listeners",
            format!("{} sockets", ls.len()),
            open("net:listener:"),
        ));
    }
    if let Some(c) = &s.clients {
        let unknown = open("net:client:");
        l.push(row(
            "clients",
            match unknown {
                0 => format!("{} seen", c.len()),
                n => format!("{} seen · {n} unknown", c.len()),
            },
            unknown,
        ));
    }
    if let Some(sv) = &s.services {
        let watched = sv.watched(&v.cfg.expect.services);
        let up = watched
            .iter()
            .filter(|n| matches!(sv.state(n), SvcState::Running | SvcState::NotADaemon))
            .count();
        l.push(row(
            "services",
            format!("{up} of {} running", watched.len()),
            open("net:service:"),
        ));
    }
    for (sec, e) in &s.errors {
        l.push(Line::styled(format!("– {sec}: {e}"), t.dim()));
    }
    l
}

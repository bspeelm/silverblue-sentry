//! Maintenance: what on the network needs attention (the shared list, `maintlist`): the
//! audit's findings, the audit itself when it's due, what the firmware, the packages and
//! the config backups ask for (`maint::recommend`), and the tasks due (`tasks.toml` over
//! the config's cadences). Under it the Items: firmware, packages, backup, one cursor with
//! the list; then what the last audit looked at. `F` opens the audit's report. The one thing started from here that does
//! something is a workflow (`config-backup`, which only reads the router); everything else
//! is looked at, marked expected or put off, and a by-hand task is done by hand.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Wrap};

use super::{Hints, View, report};
use crate::audit::Report;
use crate::collect::services::State as SvcState;
use crate::config::ItemKind;
use crate::maint::eval::{self, EolState, Firmware};
use crate::maint::recommend::{self, BACKUP_WF, ItemRow, Tone};
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
use sentry_core::tui::widgets::{self, TableSpec, inner, panel};

/// What Enter does on a row.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// An audit finding (its id): its place in the report.
    Finding(String),
    /// Audit the network now.
    Audit,
    /// A task (its id): what Enter does is the task's own.
    Task(String),
    /// Start this workflow.
    Run(String),
    /// Something of this item that sentry can't carry out yet: Enter says how it stands.
    About(ItemKind),
}

/// The audit's finding that the config isn't backed up: Enter on it makes a backup.
pub const UNSAVED: &str = "net:config:unsaved";

/// Keys (for `z`): `finding:<id>`, `audit`, `task:<id>`, `net:maint:<what>`.
pub type Rec = rec::Rec<Action>;

impl rec::Act for Action {
    fn target(&self) -> Target {
        match self {
            Action::Audit => Target::Audit,
            Action::Run(wf) => Target::Workflow(wf.clone()),
            // A backup task that's due is the same row.
            Action::Finding(id) if id == UNSAVED => Target::Workflow(BACKUP_WF.into()),
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

/// Every task that applies: `tasks.toml`'s over the config's cadences.
pub fn all_tasks(v: &View) -> Vec<Task> {
    sentry_core::maint::tasks::effective(
        &v.sh.tasks,
        crate::maint::cadence_tasks(v.cfg, &v.sh.workflows),
    )
}

/// The firmware against upstream, once the board was read (by a screen, or the last audit).
pub fn firmware(v: &View) -> Option<Firmware> {
    let version =
        v.s.ifaces
            .value
            .as_ref()
            .or_else(|| latest(v)?.snapshot.ifaces.as_ref())
            .map(|i| i.board.version.as_str())?;
    let up = v.s.upstream.value.as_ref().and_then(|c| c.as_ref());
    Some(eval::firmware(
        version,
        up.map(|c| &c.data),
        v.now.to_zoned(jiff::tz::TimeZone::UTC).date(),
    ))
}

/// The config isn't backed up, as last read (none: not read yet).
fn unsaved_now(v: &View) -> Option<bool> {
    v.s.backup.value.as_ref().map(|b| b.unsaved())
}

/// What the rules are asked with.
fn with_state<R>(v: &View, f: impl FnOnce(&recommend::State) -> R) -> R {
    let fw = firmware(v);
    // The audit's finding says the config isn't backed up, and nothing read since says
    // otherwise: it is the row (marked expected, it is nobody's).
    let listed = finding(v, UNSAVED).is_some() && unsaved_now(v) != Some(false);
    f(&recommend::State {
        firmware: fw.as_ref(),
        updates: v.s.updates.value.as_ref(),
        backup: v.s.backup.value.as_ref(),
        backup_age: v.cfg.thresholds.backup_age.0.as_secs() as i64,
        now: v.now,
        unsaved_listed: listed,
    })
}

/// The Items panel's rows.
pub fn items(v: &View) -> Vec<ItemRow> {
    with_state(v, |s| recommend::items(v.cfg, s))
}

/// Every recommendation there is, whatever is shown.
pub fn every_rec(v: &View) -> Vec<Rec> {
    let mut out: Vec<Rec> = Vec::new();
    let findings = latest(v).map_or(&[][..], |r| &r.findings[..]);
    // A backup made since the audit: its finding is over before the next audit says so.
    let stale = |f: &&Finding| f.id == UNSAVED && unsaved_now(v) == Some(false);
    for f in findings
        .iter()
        .filter(|f| !f.expected)
        .filter(|f| !stale(f))
    {
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
    for r in with_state(v, recommend::rules) {
        out.push(Rec {
            level: r.level,
            key: r.key.to_string(),
            title: r.title,
            why: r.why,
            action: match r.action {
                recommend::Do::Run(wf) => Action::Run(wf),
                recommend::Do::Say(_) => Action::About(r.item),
            },
            item: None,
            can_wait: r.can_wait,
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
    /// The rows ticked for a series (Space), by key.
    pub ticks: maintlist::Ticks,
    /// Whether the list showed everything when the selection was last noted (`o` changes
    /// the list under the cursor).
    pub everything: bool,
}

/// The selected row: a recommendation (they come first) or an item.
pub enum Sel {
    Rec(Rec),
    Item(ItemRow),
}

pub fn sel(v: &View) -> Option<Sel> {
    let r = recs(v);
    if let Some(x) = r.get(v.cur) {
        return Some(Sel::Rec(x.clone()));
    }
    items(v).into_iter().nth(v.cur - r.len()).map(Sel::Item)
}

/// The recommendation selected (none: nothing, or an item).
pub fn pick(v: &View) -> Option<Rec> {
    recs(v).get(v.cur).cloned()
}

fn rec_key(r: &Rec) -> String {
    format!("{}:{}", r.key, r.title)
}

/// What the row at the cursor is, to find it again after the list changes.
pub fn row_key(v: &View) -> Option<String> {
    match sel(v)? {
        Sel::Rec(r) => Some(rec_key(&r)),
        Sel::Item(i) => Some(format!("item:{}", i.id)),
    }
}

/// How a series takes care of a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeriesKind {
    Workflow(String),
    Audit,
    /// A session with Claude (a finding, a task done by hand).
    Session,
}

/// What a series does for this row (None: Enter does it by itself, it can't be ticked).
pub fn series_kind(v: &View, x: &Rec) -> Option<SeriesKind> {
    let has = |wf: &str| v.sh.workflows.iter().any(|w| w == wf);
    let run = |wf: &str| has(wf).then(|| SeriesKind::Workflow(wf.to_string()));
    match &x.action {
        Action::Run(wf) => run(wf),
        Action::Finding(id) if id == UNSAVED => run(BACKUP_WF),
        Action::Audit => Some(SeriesKind::Audit),
        Action::Task(id) => match task_of(v, id)?.action() {
            Do::Run(wf) => run(&wf),
            Do::Audit => Some(SeriesKind::Audit),
            Do::ByHand => Some(SeriesKind::Session),
            _ => None,
        },
        Action::Finding(_) => Some(SeriesKind::Session),
        Action::About(_) => None,
    }
}

/// How many of the rows there are ticked.
pub fn ticked(v: &View, ticks: &maintlist::Ticks) -> usize {
    if ticks.is_empty() {
        return 0;
    }
    every_rec(v)
        .iter()
        .filter(|r| ticks.contains(&r.key))
        .count()
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
    let series = pick(v).is_some_and(|r| series_kind(v, &r).is_some());
    let row = match sel(v) {
        None => return Verbs::default(),
        Some(Sel::Item(i)) => {
            return only(match i.kind {
                ItemKind::Backup => "back up",
                _ => "about",
            });
        }
        Some(Sel::Rec(r)) => r.action,
    };
    let vb = match row {
        Action::Run(_) => only("run"),
        Action::About(_) => only("about"),
        Action::Finding(id) if id == UNSAVED => Verbs {
            dismiss: Some(Dismiss::Expected),
            ..only("back up")
        },
        Action::Finding(_) => Verbs {
            dismiss: Some(Dismiss::Expected),
            like: true,
            ..only("in the report")
        },
        Action::Audit => only("audit"),
        Action::Task(id) => {
            let what = task_of(v, &id).map(|t| t.action());
            Verbs {
                done: true,
                every: true,
                manual: what == Some(Do::ByHand),
                dismiss: Some(Dismiss::Remove),
                ..only(match what {
                    Some(Do::ByHand) => "its steps",
                    Some(Do::Audit) => "audit",
                    Some(Do::Run(_)) => "run",
                    _ => "do it",
                })
            }
        }
    };
    Verbs { series, ..vb }
}

/// The key bar: the row's keys (no Claude for a network yet, so no `A`), then the screen's.
/// `ticked`: how many rows are ticked for a series.
pub fn hints(v: &View, ticked: usize) -> Hints {
    // (An empty list has no row to name keys for.)
    let mut h: Hints = match sel(v) {
        Some(Sel::Rec(_)) => maintlist::hints(&verbs(v), ticked)
            .into_iter()
            .filter(|(k, _)| *k != "A")
            .collect(),
        // An item is looked at or acted on; it isn't put off.
        Some(Sel::Item(_)) => maintlist::hints(&verbs(v), ticked)
            .into_iter()
            .filter(|(k, _)| !matches!(*k, "A" | "z"))
            .collect(),
        None => Vec::new(),
    };
    if v.everything || waiting(v) > 0 {
        h.push(("o", maintlist::everything_word(v.everything)));
    }
    h.extend([
        ("r", "refresh"),
        ("c", "audit"),
        ("F", "report"),
        ("v", "records"),
    ]);
    h
}

/// `?`: every row key a network's rows take.
pub fn help() -> Hints {
    let not_here = ["p / P", "t", "x", "A"];
    maintlist::GRAMMAR
        .iter()
        .copied()
        .filter(|(k, _)| !not_here.contains(k))
        .chain([
            ("x", "expected (a finding) · remove (a task); asks first"),
            ("b", "a finding: expected (as x, without the box)"),
            (
                "r",
                "refresh: fetch the package index again (apk update, tmpfs only), look upstream, audit",
            ),
            ("c", "audit the network now (it only reads)"),
            ("F", "the audit report"),
            ("w", "the workflows (0)"),
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
        Do::Run(wf) if v.sh.workflows.contains(&wf) => vec![Effect::StartWorkflow(wf)],
        Do::Run(wf) => vec![Effect::Toast(format!(
            "this network has no workflow {wf}: d marks it done"
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

/// Enter on anything that makes a backup: the workflow, or what it can't start without.
fn backup_enter(v: &View) -> Vec<Effect> {
    if v.cfg.backup.recipients.is_empty() {
        return vec![Effect::Confirm(Modal {
            title: "No backup recipient".into(),
            color: v.t.yellow,
            lines: vec![
                Line::styled(
                    "A backup is encrypted to the public keys under backup.recipients in \
                     network_config.yaml, and there are none.",
                    v.t.fg(),
                ),
                Line::raw(""),
                Line::styled(
                    "`sentry-network backup key <file>` makes a key and prints the line to add. \
                     Keep that file safe: sentry never has the secret key.",
                    v.t.dim(),
                ),
            ],
            yes: None,
        })];
    }
    vec![Effect::StartWorkflow(BACKUP_WF.into())]
}

/// The workflows Enter starts on the packages and the firmware.
pub const PACKAGES_WF: &str = "package-update";
pub const FIRMWARE_WF: &str = "firmware-upgrade";

/// Enter on an item (or a row about one): the backup is made, the packages' workflow
/// starts (it asks which ones), and the firmware's says how it stands and that its
/// workflow is still a draft, until the user makes it not one.
fn item_enter(v: &View, kind: ItemKind) -> Vec<Effect> {
    let has = |wf: &str| v.sh.workflows.iter().any(|w| w == wf);
    let draft = |wf: &str| {
        v.sh.wf_entries
            .iter()
            .find(|e| e.name == wf)
            .is_some_and(|e| e.wf.as_ref().is_ok_and(|w| w.draft))
    };
    let (title, wf) = match kind {
        ItemKind::Backup => return backup_enter(v),
        ItemKind::Packages if has(PACKAGES_WF) => {
            return vec![Effect::StartWorkflow(PACKAGES_WF.into())];
        }
        ItemKind::Firmware if has(FIRMWARE_WF) && !draft(FIRMWARE_WF) => {
            return vec![Effect::StartWorkflow(FIRMWARE_WF.into())];
        }
        ItemKind::Packages => ("Packages", PACKAGES_WF),
        ItemKind::Firmware => ("Firmware", FIRMWARE_WF),
    };
    let mut lines = item_lines(v, kind);
    lines.push(Line::raw(""));
    let said = if has(wf) {
        vec![
            format!("{wf} is a draft: it has never been run end to end on a router."),
            "Read its steps (0), then delete `draft = true` from its file to use it.".to_string(),
            "Until then nothing here flashes firmware.".to_string(),
        ]
    } else {
        vec![format!("this network has no workflow {wf}")]
    };
    lines.extend(said.into_iter().map(|l| Line::styled(l, v.t.s(v.t.yellow))));
    vec![Effect::Confirm(Modal {
        title: title.into(),
        color: v.t.cyan,
        lines,
        yes: None,
    })]
}

fn key(c: char, v: &View) -> Vec<Effect> {
    let r = match sel(v) {
        Some(Sel::Rec(r)) => r,
        Some(Sel::Item(i)) => {
            return match c {
                '\n' => item_enter(v, i.kind),
                'x' | 'z' => vec![Effect::Toast(
                    "an item stays: its rows above are what's put off (z) or marked expected"
                        .into(),
                )],
                _ => Vec::new(),
            };
        }
        None => return Vec::new(),
    };
    let t = v.t;
    match (c, &r.action) {
        ('\n', Action::Finding(id)) if id == UNSAVED => backup_enter(v),
        ('\n', Action::Run(wf)) if wf == BACKUP_WF => backup_enter(v),
        ('\n', Action::Run(wf)) => vec![Effect::StartWorkflow(wf.clone())],
        ('\n', Action::About(kind)) => item_enter(v, *kind),
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
        recs(v).len() + items(v).len()
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
            // Refresh: the one place the package index is fetched again (`apk update`
            // writes the router's tmpfs cache), with upstream, the backups and the audit.
            Key::Refresh => vec![
                Own::fetch(Kind::Refresh),
                Own::fetch(Kind::Lookup),
                Own::fetch(Kind::Backup),
                Own::fetch(Kind::Audit),
                Effect::Toast(
                    "refreshing: the package index, upstream, the backups and the audit…".into(),
                ),
            ],
            Key::Check => report::audit_now(),
            // Ticks: Space the row, a every row that can be, Esc none.
            Key::Char(' ') => match pick(v) {
                Some(r) if series_kind(v, &r).is_some() => {
                    maintlist::tick(&mut self.ticks, &r.key);
                    Vec::new()
                }
                _ => vec![Effect::Toast(maintlist::NOT_IN_A_SERIES.into())],
            },
            Key::Char('a') => {
                let can = recs(v)
                    .iter()
                    .filter(|r| series_kind(v, r).is_some())
                    .map(|r| r.key.clone())
                    .collect();
                maintlist::tick_all(&mut self.ticks, can);
                Vec::new()
            }
            Key::Esc => {
                self.ticks.clear();
                Vec::new()
            }
            // With rows ticked, Enter does those, one after another.
            Key::Enter => {
                let rows: Vec<(String, String)> = every_rec(v)
                    .into_iter()
                    .filter(|r| self.ticks.contains(&r.key))
                    .map(|r| (r.key, r.title))
                    .collect();
                if rows.is_empty() {
                    self.ticks.clear();
                    key('\n', v)
                } else {
                    vec![Effect::SeriesStart(rows)]
                }
            }
            Key::Char(c @ ('x' | 'b' | 'B' | 'z' | 'd' | 'm' | 'e')) => key(c, v),
            Key::Char('w') => vec![Effect::Goto(sentry_core::tui::ScreenId::Upgrade)],
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
        let recs = recs(v);
        if let Some(key) = &self.sel {
            let at = match key.strip_prefix("item:") {
                Some(id) => items(v)
                    .iter()
                    .position(|i| i.id == id)
                    .map(|i| recs.len() + i),
                None => recs.iter().position(|r| &rec_key(r) == key),
            };
            if let Some(i) = at {
                self.cur.sel = i;
            }
        }
        let n = self.count(v);
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
                rec::note(recs.len(), ticked(v, &self.ticks), waiting(v)),
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
                0 => "✓ nothing needs attention right now · c audits again".to_string(),
                n => maintlist::empty(n),
            }
        };
        self.cur.page = maintlist::draw(
            f,
            rec_a,
            t,
            &recs,
            maintlist::List {
                note,
                selected: (v.cur < recs.len()).then_some(v.cur),
                empty: (empty.as_str(), t.dim()),
                ticks: &self.ticks,
            },
        );
        // The items, and under them (where there's room) what the last audit looked at.
        let n_items = items(v).len() as u16;
        let [items_a, last_a] =
            Layout::vertical([Constraint::Length(n_items + 3), Constraint::Fill(1)]).areas(audit_a);
        draw_items(f, items_a, v, v.cur.checked_sub(recs.len()));
        if last_a.height >= 4 {
            let b = panel(t, "Last audit", audited.map_or(String::new(), fmt::date));
            let r = inner(&b, last_a);
            f.render_widget(b, last_a);
            f.render_widget(Paragraph::new(audit_lines(v)), r);
        }

        let b = panel(t, "Details", "");
        let r = inner(&b, detail_a);
        f.render_widget(b, detail_a);
        let lines = match sel(v) {
            None => vec![Line::styled(
                if read { "nothing selected" } else { "" },
                t.dim(),
            )],
            Some(Sel::Item(i)) => {
                let mut l = vec![
                    Line::styled(i.id.clone(), t.s(t.cyan)),
                    Line::styled(
                        match i.kind {
                            ItemKind::Backup => "Enter: make a backup now (config-backup)",
                            _ => "Enter: how it stands",
                        },
                        t.s(t.cyan),
                    ),
                    Line::raw(""),
                ];
                l.extend(item_lines(v, i.kind));
                l
            }
            Some(Sel::Rec(x)) => {
                let x = &x;
                let mut l = maintlist::detail_head(t, x, r.width as usize);
                match &x.action {
                    Action::Run(wf) => {
                        l.push(Line::styled(
                            format!("Enter: run {wf} (it only reads the router) · z: later"),
                            t.s(t.cyan),
                        ));
                        l.push(Line::raw(""));
                        l.extend(item_lines(v, ItemKind::Backup));
                    }
                    Action::About(kind) => {
                        l.push(Line::styled("Enter: how it stands · z: later", t.s(t.cyan)));
                        l.push(Line::raw(""));
                        l.extend(item_lines(v, *kind));
                    }
                    Action::Finding(id) if id == UNSAVED => {
                        l.push(Line::styled(
                            "Enter: back it up now (config-backup) · b or x: expected · z: later",
                            t.s(t.cyan),
                        ));
                        if let Some(fd) = finding(v, id) {
                            l.push(Line::raw(""));
                            l.extend(report::finding_lines(t, fd, r.width as usize));
                        }
                    }
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
                                    Do::Run(wf) if v.sh.workflows.contains(&wf) => {
                                        format!("Enter runs {wf}; it's done when that ends well.")
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

/// The Items panel: firmware, packages, backup, each with how it stands.
fn draw_items(f: &mut Frame, area: Rect, v: &View, selected: Option<usize>) {
    let t = v.t;
    let rows = items(v);
    let up = match v.s.upstream.value.as_ref() {
        None => String::new(),
        Some(None) => " · upstream not looked up yet (r)".to_string(),
        Some(Some(c)) => format!(" · upstream {}", fmt::ago(v.secs_since(c.fetched_at))),
    };
    let b = panel(t, "Items", format!("{}{up}", rows.len()));
    let r = inner(&b, area);
    f.render_widget(b, area);
    let color = |tone: Tone| match tone {
        Tone::Ok => t.green,
        Tone::Note => t.cyan,
        Tone::Warn => t.yellow,
        Tone::Dim => t.dim,
    };
    let table: Vec<Row> = rows
        .iter()
        .map(|i| {
            Row::new(vec![
                Cell::from(i.id.clone()).style(t.fg()),
                Cell::from(i.state.clone()).style(t.s(color(i.tone))),
                Cell::from(i.detail.clone()).style(t.dim()),
            ])
        })
        .collect();
    widgets::table(
        f,
        r,
        t,
        TableSpec {
            header: vec!["Item", "State", ""],
            widths: vec![
                Constraint::Length(10),
                Constraint::Length(22),
                Constraint::Fill(1),
            ],
            rows: table,
            selected,
        },
    );
}

/// What Details (and Enter's box) say about an item.
fn item_lines(v: &View, kind: ItemKind) -> Vec<Line<'static>> {
    let t = v.t;
    let row = |what: &str, said: String| {
        Line::from(vec![
            Span::styled(format!("{what:<13}"), t.dim()),
            Span::styled(said, t.fg()),
        ])
    };
    let dim = |s: String| Line::styled(s, t.dim());
    let mut l = Vec::new();
    match kind {
        ItemKind::Firmware => {
            let Some(f) = firmware(v) else {
                return vec![dim("the router's release wasn't read yet".into())];
            };
            l.push(row("installed", format!("OpenWrt {}", f.installed)));
            if let Some(latest) = &f.latest {
                l.push(row(
                    "latest",
                    format!(
                        "{latest}{}",
                        match (f.newer, f.security) {
                            (false, _) => " (this one)",
                            (true, Some(true)) => " · its notes list security fixes",
                            (true, Some(false)) => " · no security fix in its notes",
                            (true, None) => " · its notes couldn't be read",
                        }
                    ),
                ));
            }
            l.push(row(
                "end of life",
                match (f.eol_state, f.eol) {
                    (EolState::Unknown, _) => "not known".into(),
                    (EolState::Supported, None) => {
                        format!("none announced for {}", f.series.as_deref().unwrap_or("it"))
                    }
                    (EolState::Past(n), d) => format!(
                        "{} · {n} days ago",
                        d.map_or(String::new(), |d| d.to_string())
                    ),
                    (EolState::Soon(n), d) => format!(
                        "{} · in {n} days",
                        d.map_or(String::new(), |d| d.to_string())
                    ),
                    (EolState::Supported, Some(d)) => d.to_string(),
                },
            ));
            if let Some(n) = &f.note {
                l.push(dim(n.clone()));
            }
            l.push(dim(
                "Looked up from this machine (endoflife.date, GitHub): nothing runs on the router for it."
                    .into(),
            ));
        }
        ItemKind::Packages => {
            let Some(u) = v.s.updates.value.as_ref() else {
                return vec![dim(match &v.s.updates.err {
                    Some(e) => format!("packages: {e}"),
                    None => "the package listing wasn't read yet".into(),
                })];
            };
            l.push(row("index", u.index_said()));
            if let Some(c) = u.refresh_failed {
                l.push(Line::styled(
                    format!("the last refresh failed (apk update exited {c})"),
                    t.s(t.yellow),
                ));
            }
            l.push(row("upgradable", u.packages.len().to_string()));
            for p in u.packages.iter().take(12) {
                l.push(dim(format!("  {}  {} → {}", p.name, p.from, p.to)));
            }
            if u.packages.len() > 12 {
                l.push(dim(format!("  … {} more", u.packages.len() - 12)));
            }
            l.push(dim(
                "The index is only as new as the last r here (apk update: the router's tmpfs)."
                    .into(),
            ));
        }
        ItemKind::Backup => {
            let Some(b) = v.s.backup.value.as_ref() else {
                return vec![dim(match &v.s.backup.err {
                    Some(e) => format!("backups: {e}"),
                    None => "the backups weren't compared yet".into(),
                })];
            };
            match &b.newest {
                None => l.push(row("newest", "none yet".into())),
                Some(k) => l.push(row(
                    "newest",
                    format!(
                        "{} · OpenWrt {} · {}",
                        fmt::ago(v.secs_since(k.at)),
                        k.release,
                        fmt::bytes(k.size)
                    ),
                )),
            }
            l.push(row(
                "kept",
                format!("{} (backup.keep {})", b.count, v.cfg.backup.keep),
            ));
            l.push(row(
                "encrypted to",
                match v.cfg.backup.recipients.len() {
                    0 => "nobody: set backup.recipients".into(),
                    n => format!("{n} recipient(s)"),
                },
            ));
            match &b.changed {
                Some(c) if c.any() => {
                    l.push(Line::styled(
                        format!("{} file(s) changed since:", c.files.len()),
                        t.s(t.yellow),
                    ));
                    let what = if c.options.is_empty() {
                        &c.files
                    } else {
                        &c.options
                    };
                    l.extend(
                        crate::backup::capped(what, 10)
                            .into_iter()
                            .map(|o| dim(format!("  {o}"))),
                    );
                }
                Some(_) => l.push(Line::styled("nothing changed since", t.s(t.green))),
                None => {}
            }
            l.push(dim(format!(
                "in {}",
                widgets::short_home(&crate::backup::backups_dir(&crate::remote::scope(v.name)))
            )));
        }
    }
    l
}

//! Maintenance (`6`): what to do on this machine next, ranked (`maint::local`): the audit's
//! findings, updates and a staged reboot, tasks due (the jobs' cadences among them), a failed
//! job, space to reclaim, a workflow left in progress, plans ready to apply. Beside it the
//! deployments and the selected recommendation's details. The audit report opens as a view
//! here (`F`); Esc comes back. Cleanup has its own screen (`7`, or `C` here).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use super::{Cursor, Hints, View, audit, updates};
use crate::audit::Finding;
use crate::maint::Level;
use crate::maint::local::{self, Action as Do, Inputs, Rec, RunInfo};
use crate::maint::tasks::{Do as TaskDo, Task};
use crate::tui::app::{Effect, Modal, RunSpec};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::maintlist::{self, Dismiss, Verbs};
use crate::tui::widgets::{inner, panel};

/// A view opened inside Maintenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sub {
    /// The audit report: findings, the diff against the previous one, `[`/`]` to browse.
    Report,
}

impl Sub {
    fn title(self) -> &'static str {
        match self {
            Sub::Report => "Audit report",
        }
    }
}

#[derive(Default)]
pub struct Maint {
    pub cur: Cursor,
    /// The selected recommendation's key: the cursor follows it when the list changes.
    sel: Option<String>,
    /// The rows' keys in order, as last seen with the selected one among them: where the
    /// cursor waits while that row is away (the updates' row during their run).
    order: Vec<String>,
    /// Select the first recommendation whose key starts with this (from the dashboard).
    pub find: Option<String>,
    pub view: Option<Sub>,
    pub audit: audit::Audit,
    /// The rows ticked for a series (Space), by key.
    pub ticks: maintlist::Ticks,
}

/// How a series takes care of a row (None: Enter does it by itself, it can't be ticked).
pub enum How {
    /// An apply session with Claude.
    Session(Box<crate::claude::Ask>),
    /// A run of this workflow (with its plan, when one is ready).
    Workflow(String),
    Audit,
}

/// What a series does for this row.
pub fn how(v: &View, r: &Rec) -> Option<How> {
    let claude = crate::claude::available();
    match &r.action {
        Do::Fix(id) if claude => {
            finding(v, id).map(|f| How::Session(Box::new(crate::audit::fix::ask(f))))
        }
        Do::Audit => Some(How::Audit),
        Do::Run(wf) | Do::OpenPlan(wf) => Some(How::Workflow(wf.clone())),
        // The security audit is the window's own flow, not a row of a series.
        Do::Task(id) if id == sentry_core::secaudit::TASK_ID => None,
        Do::Task(id) => match task(v, id)?.action() {
            TaskDo::Run(wf) => Some(How::Workflow(wf)),
            TaskDo::Audit => Some(How::Audit),
            TaskDo::ByHand | TaskDo::Plan(_) if claude => {
                apply_ask(v, r).map(|a| How::Session(Box::new(a)))
            }
            _ => None,
        },
        // A reboot ends the TUI; cleanup has its own screen and ticks; the rest is one key.
        _ => None,
    }
}

/// The audit, as a run in the pane (a series' row).
pub fn audit_run() -> Effect {
    audit::audit_run()
}

/// The row a series is at, by its key, as it is now (None: it left the list).
pub fn series_how(v: &View, key: &str) -> Option<How> {
    recs_all(v)
        .iter()
        .find(|r| r.key == key)
        .and_then(|r| how(v, r))
}

pub fn on_enter(v: &View) -> Vec<Effect> {
    let mut e = vec![
        Effect::Fetch(Fetch::Reports),
        Effect::Fetch(Fetch::Log),
        Effect::Fetch(Fetch::Ostree),
        Effect::Fetch(Fetch::Disks),
    ];
    if v.d.flatpak.get().is_none() {
        // Installed versions, for "old → new" in the updates' details.
        e.push(Effect::Fetch(Fetch::Flatpak));
    }
    e
}

pub fn hints(v: &View, m: &Maint) -> Hints {
    if let Some(s) = m.view {
        let mut h = match s {
            Sub::Report => audit::hints(v),
        };
        h.insert(0, ("Esc", "back"));
        return h;
    }
    let mut h = maintlist::hints(
        &m.selected(v).map(|r| verbs(v, &r)).unwrap_or_default(),
        m.ticked(v),
    );
    // The screen's own few; F, C, w and the rest are in `?`.
    // o only when something waits (or is shown because of it).
    if v.everything || waiting(v) > 0 {
        h.push(("o", maintlist::everything_word(v.everything)));
    }
    h.extend([("c", "check"), ("v", "records"), ("R", "review")]);
    h
}

/// The keys a row takes besides Enter.
pub fn verbs(v: &View, r: &Rec) -> Verbs {
    let enter = match &r.action {
        Do::Fix(_) => "fix",
        Do::Audit => "audit",
        Do::CheckUpdates => "check",
        Do::Run(wf) if wf == local::UPDATE_WORKFLOW => "install",
        Do::Run(_) => "start",
        Do::Reboot => "reboot",
        Do::Cleanup => "clean up",
        Do::OpenRun => "open run",
        Do::OpenPlan(_) => "apply the plan",
        Do::Security(id) if v.sh.sec.iter().any(|i| &i.id == id && i.question.is_some()) => {
            "answer"
        }
        Do::Security(_) => "fix",
        Do::Task(id) if id == sentry_core::secaudit::TASK_ID => "audit",
        Do::Task(id) => match task(v, id).map(|t| t.action()) {
            Some(TaskDo::Run(_)) => "start",
            Some(TaskDo::Audit) => "audit",
            Some(TaskDo::Job(j)) if j.starts_with("cleanup") => "clean up",
            Some(TaskDo::Job(_)) => "run",
            _ if crate::claude::available() => "with Claude",
            _ => "steps",
        },
    };
    let base = Verbs {
        enter,
        series: how(v, r).is_some(),
        ..Default::default()
    };
    match &r.action {
        Do::Fix(_) => Verbs {
            dismiss: Some(Dismiss::Expected),
            like: true,
            ..base
        },
        Do::Run(wf) | Do::OpenPlan(wf) => Verbs {
            plan: true,
            planned: v.sh.plans.contains_key(wf),
            ..base
        },
        Do::Task(id) => Verbs {
            done: true,
            every: true,
            manual: task(v, id)
                .is_some_and(|t| matches!(t.action(), TaskDo::ByHand | TaskDo::Plan(_))),
            dismiss: Some(Dismiss::Remove),
            ..base
        },
        _ => base,
    }
}

/// A workflow for Claude: what it does and its steps, in order.
fn workflow_text(wf: &str) -> String {
    match crate::workflows::find(wf).map(|e| e.wf) {
        Some(Ok(w)) => {
            let steps: Vec<String> = w
                .steps
                .iter()
                .enumerate()
                .map(|(i, s)| format!("  {}. {} ({})", i + 1, s.title, s.id))
                .collect();
            format!(
                "sentry's workflow `{wf}`: {}\nIts steps:\n{}",
                w.description,
                steps.join("\n")
            )
        }
        _ => format!("sentry's workflow `{wf}` (its file couldn't be read)."),
    }
}

/// Where the ledger and the notes are: a session starts its research from them.
fn records(v: &View) -> String {
    crate::tui::plans::records(v.cfg)
}

/// `A` → "help me apply it": what Claude is told about the row, and what the chat can do.
/// None: the row is only asked about (a finding has its own fix flow; a reboot or a cleanup
/// is applied by its own screen).
pub fn apply_ask(v: &View, r: &Rec) -> Option<crate::claude::Ask> {
    use crate::claude::{Apply, Ask};
    let head = format!(
        "A maintenance recommendation on my Silverblue machine: [{}] {}\nWhy: {}",
        r.level.word(),
        r.title,
        r.why
    );
    let with_wf = |wf: &str, extra: String| {
        let ctx = format!("{head}\n\n{extra}{}\n\n{}", workflow_text(wf), records(v));
        Ask::apply(
            r.title.clone(),
            ctx,
            Apply {
                key: r.key.clone(),
                workflow: Some(wf.to_string()),
                // Its plan is kept under the workflow, and closed when its run ends well.
                plan: Some(wf.to_string()),
                ..Default::default()
            },
        )
    };
    match &r.action {
        Do::Run(wf) | Do::OpenPlan(wf) if wf == local::UPDATE_WORKFLOW => Some(with_wf(
            wf,
            updates::ask(v).map_or(String::new(), |a| format!("{}\n\n", a.context)),
        )),
        Do::Run(wf) | Do::OpenPlan(wf) => Some(with_wf(wf, String::new())),
        Do::Task(id) => {
            let t = task(v, id)?;
            let wf = match t.action() {
                TaskDo::Run(wf) => Some(wf),
                TaskDo::ByHand | TaskDo::Plan(_) => None,
                TaskDo::Audit | TaskDo::Job(_) => return None,
            };
            let mut ctx = format!(
                "{head}\n\nA task ({}): {}\n{}",
                t.when(),
                t.title,
                if t.steps.trim().is_empty() {
                    "(no steps written)".to_string()
                } else {
                    format!("Its steps:\n{}", t.steps.trim())
                }
            );
            if let Some(wf) = &wf {
                ctx.push_str(&format!("\n\n{}", workflow_text(wf)));
            }
            Some(Ask::apply(
                t.title.clone(),
                ctx,
                Apply {
                    key: r.key.clone(),
                    workflow: wf,
                    task: Some(t.id.clone()),
                    ..Default::default()
                },
            ))
        }
        _ => None,
    }
}

/// The session for a workflow's plan (Enter on its ready plan, `P`, `A` in the Plan view):
/// with a plan saved it opens on that plan; without, Claude researches first.
pub fn plan_apply_ask(v: &View, wf: &str) -> Option<crate::claude::Ask> {
    Some(crate::claude::Ask::apply(
        format!("the plan for {wf}"),
        format!(
            "Running sentry's workflow {wf} on my Silverblue machine.\n\n{}\n\n{}\n\n{}",
            context(v),
            workflow_text(wf),
            records(v)
        ),
        crate::claude::Apply {
            key: format!("plan:{wf}"),
            workflow: Some(wf.to_string()),
            plan: Some(wf.to_string()),
            ..Default::default()
        },
    ))
}

/// The recommendations shown: what's due or urgent (everything with `o`), of those the ones
/// the `/` filter keeps.
pub fn recs(v: &View) -> Vec<Rec> {
    crate::maint::rec::needed(recs_all(v), v.everything)
        .0
        .into_iter()
        .filter(|r| v.matches(&[&r.title, &r.why, r.level.word()]))
        .collect()
}

/// How many recommendations wait, not shown (`o` shows them).
pub fn waiting(v: &View) -> usize {
    crate::maint::rec::needed(recs_all(v), v.everything).1
}

/// The recommendations, from what's loaded.
pub fn recs_all(v: &View) -> Vec<Rec> {
    crate::maint::rec::with_audit(
        own_recs(v),
        &v.sh.sec,
        &v.sh.later,
        jiff::Zoned::now().date(),
        audit_same,
        Do::Security,
    )
}

/// Which row here is already about the subject of one of the security audit's items: the
/// updates waiting, the staged reboot, a listener open to everyone, the firewall.
fn audit_same(i: &sentry_core::secaudit::Item, recs: &[Rec]) -> Option<usize> {
    let what = i.id.split(':').nth(1).unwrap_or("");
    let key = |f: &dyn Fn(&str) -> bool| recs.iter().position(|r| f(&r.key));
    match what {
        "os" => key(&|k| k == "updates"),
        "reboot" => key(&|k| k == "reboot"),
        "listen-wide" => key(&|k| k.starts_with("finding:listener:")),
        "firewall" => key(&|k| k.starts_with("finding:firewall")),
        _ => None,
    }
}

fn own_recs(v: &View) -> Vec<Rec> {
    let run = v.wf.map(|s| {
        let i = s.next.idx();
        RunInfo {
            workflow: &s.wf.name,
            done: s.done(),
            step: i.map(|i| (i + 1, s.wf.steps.len(), s.wf.steps[i].title.as_str())),
            failed: i.is_some_and(|i| {
                s.run.state.steps[i].status == crate::workflows::state::StepStatus::Failed
            }),
        }
    });
    let reclaim = v.d.cleanup.get().map(|plans| {
        plans
            .iter()
            .flat_map(|p| p.runnable())
            .filter_map(|i| i.bytes)
            .sum()
    });
    let disk_tight =
        v.d.disks
            .get()
            .is_some_and(|ds| ds.iter().any(|m| !m.removable && m.pct() >= 90.0));
    local::recommend(&Inputs {
        now: jiff::Timestamp::now(),
        cfg: v.cfg,
        report: v.d.reports.get().and_then(|r| r.last()).map(|s| &s.report),
        baseline: &v.d.baseline,
        ostree: v.d.ostree.get(),
        flatpak_updates: v.d.fp_waiting(&v.sh.log).map(|c| c.data.len()),
        toolbox_updates: v
            .d
            .tbx_waiting(&v.sh.log)
            .map(|c| crate::collectors::toolbox::total(&c.data)),
        reclaim,
        disk_tight,
        run,
        plans: &v.sh.plans,
        snoozes: &v.sh.later,
        tasks: &all_tasks(v),
        log: &v.sh.log,
    })
}

/// Every task that applies: `tasks.toml`'s and the jobs' cadences.
pub fn all_tasks(v: &View) -> Vec<Task> {
    crate::maint::tasks::effective(&v.sh.tasks, derived_tasks(v.cfg, v.sh))
}

/// The tasks nothing wrote down: the jobs' cadences, and the security audit (the whole
/// system's, kept here: this machine is where sentry runs).
pub fn derived_tasks(cfg: &crate::config::Config, sh: &sentry_app::shared::Shared) -> Vec<Task> {
    let mut t = crate::jobs::state::tasks(cfg);
    t.push(sentry_core::secaudit::task(sh.sec_last, &sh.log));
    t
}

/// The task behind a `Task` recommendation.
fn task(v: &View, id: &str) -> Option<Task> {
    all_tasks(v).into_iter().find(|t| t.id == id)
}

/// The finding behind a `Fix` recommendation, from the newest report.
fn finding<'a>(v: &View<'a>, id: &str) -> Option<&'a Finding> {
    v.d.reports
        .get()?
        .last()?
        .report
        .findings
        .iter()
        .find(|f| f.id == id)
}

/// The tab's badge: how many want doing now or soon, colored by the most urgent.
pub fn badge(v: &View) -> Option<(usize, Level)> {
    let r = recs(v);
    let urgent: Vec<&Rec> = r.iter().filter(|r| r.level <= Level::Soon).collect();
    Some((urgent.len(), urgent.first()?.level))
}

pub use crate::tui::maintlist::level_color;

/// Check everything: audit, OS/Flatpak/toolbox updates, and what cleanup could free.
pub fn check_all() -> Vec<Effect> {
    vec![
        Effect::Fetch(Fetch::OstreeCheck),
        Effect::Fetch(Fetch::FlatpakUpdates),
        Effect::Fetch(Fetch::ToolboxUpdates),
        Effect::Fetch(Fetch::Cleanup),
        audit::audit_run(),
    ]
}

impl Maint {
    /// Keep the cursor on the selected recommendation (or the one asked for by `find`).
    /// While its row is away (a run's own row stands for the row that started it, a task is
    /// done) the cursor waits on the nearest row that was after it, else before it, and
    /// goes back when the row does; a key on the list takes the row under the cursor
    /// instead (`handle`).
    fn sync(&mut self, recs: &[Rec]) {
        let at = |k: &String| recs.iter().position(|r| &r.key == k);
        if let Some(p) = self.find.take() {
            if let Some(i) = recs.iter().position(|r| r.key.starts_with(&p)) {
                self.cur.sel = i;
            }
            self.sel = None;
        } else if let Some(k) = &self.sel {
            match at(k) {
                Some(i) => self.cur.sel = i,
                None => {
                    let was = self.order.iter().position(|o| o == k);
                    let near = was.and_then(|p| {
                        let (before, after) = self.order.split_at(p);
                        after
                            .iter()
                            .find_map(at)
                            .or(before.iter().rev().find_map(at))
                    });
                    self.cur.sel = near.unwrap_or(self.cur.sel);
                    self.cur.clamp(recs.len());
                    return;
                }
            }
        }
        let i = self.cur.clamp(recs.len());
        self.sel = recs.get(i).map(|r| r.key.clone());
        self.order = recs.iter().map(|r| r.key.clone()).collect();
    }

    /// The row under the cursor is the one meant from now on (a key was pressed on it).
    fn take(&mut self, recs: &[Rec]) {
        self.sel = recs.get(self.cur.sel).map(|r| r.key.clone());
        self.order = recs.iter().map(|r| r.key.clone()).collect();
    }

    pub fn selected(&self, v: &View) -> Option<Rec> {
        let r = recs(v);
        let i = self
            .sel
            .as_ref()
            .and_then(|k| r.iter().position(|x| &x.key == k))
            .unwrap_or(self.cur.sel);
        r.get(i.min(r.len().saturating_sub(1))).cloned()
    }

    /// How many of the rows there are ticked.
    pub fn ticked(&self, v: &View) -> usize {
        if self.ticks.is_empty() {
            return 0;
        }
        recs_all(v)
            .iter()
            .filter(|r| self.ticks.contains(&r.key))
            .count()
    }

    pub fn open(&mut self, s: Sub) {
        self.view = Some(s);
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        if let Some(s) = self.view {
            if a == Action::Esc {
                self.view = None;
                return Vec::new();
            }
            return match s {
                Sub::Report => self.audit.handle(a, v),
            };
        }
        let recs = recs(v);
        self.sync(&recs);
        let moved = self.cur.nav(a, recs.len());
        self.take(&recs);
        if moved {
            return Vec::new();
        }
        let t = v.t;
        match a {
            Action::Check => {
                let mut e = check_all();
                e.push(Effect::Toast(
                    "auditing, checking OS, Flatpak and toolbox updates, measuring cleanup…".into(),
                ));
                return e;
            }
            Action::Refresh => {
                return [Fetch::Reports, Fetch::Log, Fetch::Ostree, Fetch::Disks]
                    .into_iter()
                    .map(Effect::Fetch)
                    .collect();
            }
            // Reports and jobs are read when Maintenance opens (r reads them again).
            Action::Char('F') => {
                self.view = Some(Sub::Report);
                return Vec::new();
            }
            Action::Char('C') => return vec![Effect::Goto(crate::tui::ScreenId::Clean)],
            Action::Char('w') => return vec![Effect::Goto(crate::tui::ScreenId::Upgrade)],
            Action::Char('v') => return vec![Effect::LogOpen],
            Action::Char('R') => return vec![Effect::ReviewOpen],
            Action::Char('o') => return vec![Effect::Everything],
            // Ticks: Space the row, a every row that can be, Esc none.
            Action::Char('a') => {
                let can = recs
                    .iter()
                    .filter(|r| how(v, r).is_some())
                    .map(|r| r.key.clone())
                    .collect();
                maintlist::tick_all(&mut self.ticks, can);
                return Vec::new();
            }
            Action::Esc => {
                self.ticks.clear();
                return Vec::new();
            }
            // With rows ticked, Enter does those, one after another.
            Action::Enter => {
                let rows: Vec<(String, String)> = recs_all(v)
                    .into_iter()
                    .filter(|r| self.ticks.contains(&r.key))
                    .map(|r| (r.key, r.title))
                    .collect();
                if !rows.is_empty() {
                    return vec![Effect::SeriesStart(rows)];
                }
                self.ticks.clear();
            }
            _ => {}
        }
        let Some(r) = recs.get(self.cur.sel) else {
            return Vec::new();
        };
        match a {
            Action::Char(' ') if how(v, r).is_some() => {
                maintlist::tick(&mut self.ticks, &r.key);
                Vec::new()
            }
            Action::Char(' ') => vec![Effect::Toast(maintlist::NOT_IN_A_SERIES.into())],
            Action::Enter => self.act(v, r),
            // A workflow's saved plan, to read; `P`: its session, from the research.
            Action::Char('p' | 'P') => match &r.action {
                Do::Run(wf) | Do::OpenPlan(wf) if a == Action::Char('p') => {
                    vec![Effect::PlanOpen(wf.clone())]
                }
                Do::Run(wf) | Do::OpenPlan(wf) => vec![Effect::PlanAgain(wf.clone())],
                _ => vec![Effect::Toast(
                    "plans are kept for workflows: p on updates, or on Upgrade (0)".into(),
                )],
            },
            Action::Char('m') => match &r.action {
                Do::Task(id) => manual_effects(v, id),
                _ => Vec::new(),
            },
            Action::Char('d') => match &r.action {
                Do::Task(id) => vec![Effect::TaskDone(id.clone())],
                _ => Vec::new(),
            },
            Action::Char('e') => match &r.action {
                Do::Task(id) => {
                    let now = task(v, id)
                        .and_then(|t| t.every)
                        .map_or(String::new(), |d| d.to_string());
                    vec![Effect::Prompt(
                        crate::tui::app::Prompt::TaskEvery(id.clone()),
                        now,
                    )]
                }
                _ => Vec::new(),
            },
            Action::Char('x') => match &r.action {
                Do::Task(id) => vec![Effect::Confirm(Modal {
                    title: "Remove this task".into(),
                    color: t.yellow,
                    lines: vec![
                        Line::styled(r.title.clone(), t.fg()),
                        Line::styled(
                            "It comes off tasks.toml and leaves Maintenance. The log keeps what \
                             was done.",
                            t.dim(),
                        ),
                    ],
                    yes: Some(("remove".into(), vec![Effect::TaskRemove(id.clone())])),
                })],
                Do::Fix(id) => finding(v, id).map_or(Vec::new(), |f| {
                    vec![Effect::Confirm(Modal {
                        title: "Mark it expected".into(),
                        color: t.yellow,
                        lines: vec![
                            Line::styled(r.title.clone(), t.fg()),
                            Line::styled(
                                "The audit stops listing it (baseline.toml; b in the report \
                                 (F) takes it back).",
                                t.dim(),
                            ),
                        ],
                        yes: Some((
                            "yes".into(),
                            vec![
                                audit::expected_toggle(v, f),
                                Effect::Toast("marked expected (baseline.toml)".into()),
                            ],
                        )),
                    })]
                }),
                _ => vec![Effect::Toast(maintlist::NOTHING_TO_DISMISS.into())],
            },
            Action::Char('B') => match &r.action {
                Do::Fix(id) => finding(v, id).map_or(Vec::new(), |f| audit::pattern_effects(v, f)),
                _ => Vec::new(),
            },
            Action::Char('z') => vec![Effect::Choose(maintlist::later_choice(
                t,
                &r.title,
                jiff::Zoned::now().date(),
                |d, _| vec![Effect::Snooze(r.key.clone(), d)],
            ))],
            _ => Vec::new(),
        }
    }

    /// Enter: what the recommendation says to do.
    fn act(&mut self, v: &View, r: &Rec) -> Vec<Effect> {
        let t = v.t;
        match &r.action {
            Do::Fix(id) => match finding(v, id) {
                Some(f) if crate::claude::available() => {
                    vec![Effect::AskConsent(crate::audit::fix::ask(f))]
                }
                Some(f) => audit::fix_effects(v, f),
                None => vec![Effect::Toast(
                    "that finding isn't in the newest report".into(),
                )],
            },
            Do::Audit => vec![audit::audit_run()],
            Do::CheckUpdates => vec![
                Effect::Fetch(Fetch::OstreeCheck),
                Effect::Fetch(Fetch::FlatpakUpdates),
                Effect::Fetch(Fetch::ToolboxUpdates),
                Effect::Toast("checking OS, Flatpak and toolbox updates…".into()),
            ],
            Do::Run(wf) => vec![Effect::StartWorkflow(wf.clone())],
            Do::Reboot => {
                let cmd = crate::workflows::cli::reboot_cmd();
                vec![Effect::Confirm(Modal {
                    title: "Reboot".into(),
                    color: t.red,
                    lines: vec![
                        Line::styled(r.why.clone(), t.fg()),
                        Line::styled(format!("$ {}", cmd.display()), t.dim()),
                        Line::styled("Save your work first: everything closes.", t.dim()),
                    ],
                    yes: Some((
                        "reboot".into(),
                        vec![
                            // Logged first: after the reboot there's no one to write it.
                            Effect::LogEvent(Box::new(crate::maint::log::LogEntry::event(
                                crate::maint::LOCAL,
                                "reboot",
                                "reboot",
                                true,
                                &r.why,
                                &[],
                                jiff::Timestamp::now(),
                            ))),
                            Effect::Run(RunSpec {
                                title: "reboot".into(),
                                cmd,
                                queue: Vec::new(),
                                then: Vec::new(),
                                ok_toast: "rebooting…".into(),
                                log: None,
                            }),
                        ],
                    )),
                })]
            }
            // A cleanup job that failed: Cleanup, with that job's items selected.
            Do::Cleanup => match r
                .key
                .strip_prefix("job:")
                .and_then(crate::jobs::JobId::from_name)
            {
                Some(j) => vec![Effect::CleanupFocus(j)],
                None => vec![Effect::Goto(crate::tui::ScreenId::Clean)],
            },
            Do::OpenRun => vec![Effect::Goto(crate::tui::ScreenId::Upgrade)],
            // A plan ready for it: its session opens on that plan, to approve.
            Do::OpenPlan(wf) => vec![Effect::PlanApply(wf.clone())],
            Do::Security(id) => vec![Effect::SecItem(id.clone())],
            Do::Task(id) => task_effects(v, id),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        if let Some(s) = self.view {
            let [head, body] =
                Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(format!(" Maintenance › {} ", s.title()), t.s(t.cyan)),
                    Span::styled(" Esc back", t.dim()),
                ])),
                head,
            );
            match s {
                Sub::Report => self.audit.render(f, body, v),
            }
            return;
        }
        let recs = recs(v);
        self.sync(&recs);
        let (top, bottom, right) = maintlist::split(area, recs.len());
        self.draw_recs(f, top, v, &recs);
        updates::draw_deployments(f, bottom, v);
        draw_details(f, right, v, recs.get(self.cur.sel));
    }

    fn draw_recs(&mut self, f: &mut Frame, area: Rect, v: &View, recs: &[Rec]) {
        let t = v.t;
        let audited =
            v.d.reports
                .get()
                .and_then(|r| r.last())
                .map(|s| {
                    format!(
                        "audited {}",
                        crate::fmt::ago(
                            jiff::Timestamp::now().as_second() - s.report.taken_at.as_second()
                        )
                    )
                })
                .unwrap_or_else(|| "no audit yet".into());
        let waiting = waiting(v);
        let empty = if v.filter.is_some() {
            maintlist::NO_MATCH.to_string()
        } else if v.d.loading(Fetch::Reports) || v.d.loading(Fetch::Log) {
            "reading…".to_string()
        } else {
            maintlist::empty(waiting)
        };
        self.cur.page = maintlist::draw(
            f,
            area,
            t,
            recs,
            maintlist::List {
                note: format!(
                    "{} · {audited}",
                    crate::maint::rec::note(recs.len(), self.ticked(v), waiting)
                ),
                selected: Some(self.cur.sel),
                empty: (&empty, t.dim()),
                ticks: &self.ticks,
            },
        );
    }

    /// `A` → "help me apply it", for the selected row (None in a view, or when it's only asked
    /// about).
    pub fn apply_ask(&self, v: &View) -> Option<crate::claude::Ask> {
        if self.view.is_some() {
            return None;
        }
        apply_ask(v, &self.selected(v)?)
    }

    pub fn ask(&self, v: &View) -> Result<crate::claude::Ask, String> {
        if let Some(s) = self.view {
            return match s {
                Sub::Report => self.audit.ask(v),
            };
        }
        let r = self.selected(v);
        match r.as_ref().map(|r| &r.action) {
            Some(Do::Fix(id)) => {
                let f = finding(v, id).ok_or("that finding isn't in the newest report")?;
                Ok(crate::audit::fix::ask(f))
            }
            Some(Do::Run(wf)) if wf == local::UPDATE_WORKFLOW => updates::ask(v),
            Some(Do::Reboot) => updates::ask(v),
            _ => {
                let lines: Vec<String> = recs(v)
                    .iter()
                    .map(|r| format!("- [{}] {}: {}", r.level.word(), r.title, r.why))
                    .collect();
                Ok(crate::claude::Ask::new(
                    "maintenance",
                    format!(
                        "What sentry recommends maintaining on my Silverblue machine, ranked:\n{}",
                        lines.join("\n")
                    ),
                    "What should I do first, and is anything here safe to put off?",
                ))
            }
        }
    }
}

fn draw_details(f: &mut Frame, area: Rect, v: &View, r: Option<&Rec>) {
    let t = v.t;
    let b = panel(t, "Details", "");
    let inner_r = inner(&b, area);
    f.render_widget(b, area);
    let Some(r) = r else {
        f.render_widget(
            Paragraph::new(Line::styled("nothing selected", t.dim())),
            inner_r,
        );
        return;
    };
    let w = inner_r.width as usize;
    let mut l = maintlist::detail_head(t, r, w);
    l.push(Line::styled(action_words(&r.action), t.s(t.cyan)));
    match &r.action {
        Do::Fix(id) => {
            if let Some(fd) = finding(v, id) {
                l.push(Line::raw(""));
                l.extend(audit::finding_lines(t, fd, w, "Enter"));
            }
        }
        Do::Run(wf) if wf == local::UPDATE_WORKFLOW => {
            l.push(Line::raw(""));
            l.extend(updates::updates_lines(v));
        }
        Do::Task(id) => {
            if let Some(task) = task(v, id) {
                l.push(Line::raw(""));
                l.push(Line::styled(task_words(&task), t.fg()));
                l.push(Line::styled(
                    format!(
                        "{} · {}",
                        task.when(),
                        match &task.review {
                            Some(r) => format!("from the review {r}"),
                            None => format!("from {}", task.source.word()),
                        }
                    ),
                    t.dim(),
                ));
                if !task.steps.trim().is_empty() {
                    l.push(Line::raw(""));
                    l.extend(crate::tui::docview::markdown(t, &task.steps));
                }
            }
        }
        Do::Cleanup => {
            l.push(Line::raw(""));
            match v.d.cleanup.get() {
                Some(plans) => {
                    for i in plans.iter().flat_map(|p| p.runnable()) {
                        l.push(Line::styled(
                            format!(
                                "{:>10}  {}",
                                i.bytes.map_or("?".into(), crate::fmt::bytes),
                                i.label
                            ),
                            t.dim(),
                        ));
                    }
                }
                None => l.push(Line::styled("not measured yet: c measures it", t.dim())),
            }
        }
        _ => {}
    }
    f.render_widget(Paragraph::new(l).wrap(Wrap { trim: false }), inner_r);
}

fn action_words(a: &Do) -> String {
    match a {
        Do::Fix(_) => if crate::claude::available() {
            "Enter: Claude looks into it and says what to run"
        } else {
            "Enter: sentry's fixes for it"
        }
        .into(),
        Do::Audit => "Enter: audit now (read-only, about a second)".into(),
        Do::CheckUpdates => "Enter: check OS, Flatpak and toolbox updates".into(),
        Do::Run(wf) if wf == local::UPDATE_WORKFLOW => {
            "Enter: install these updates (it asks before each step)".into()
        }
        Do::Run(wf) => format!("Enter: start {wf} (it asks before each step)"),
        Do::Reboot => "Enter: reboot (asks first)".into(),
        Do::Cleanup => "Enter: open Cleanup (7): pick what goes, see it, confirm".into(),
        Do::OpenRun => "Enter: open the run on Upgrade (0)".into(),
        Do::OpenPlan(_) => {
            "Enter: the plan, to approve (it starts its workflow) · p reads it".into()
        }
        Do::Security(_) => "From the security audit (S shows it). Enter: a session with Claude that fixes it, or your answer where only you know".into(),
        Do::Task(_) => "A task: Enter does it".into(),
    }
}

/// What Enter does on a task, in words.
fn task_words(task: &Task) -> String {
    if task.id == sentry_core::secaudit::TASK_ID {
        return "Enter runs the security audit across every target (reads only, a minute or two); it's done when the audit has run.".into();
    }
    match task.action() {
        TaskDo::Run(wf) => format!("Enter starts {wf}; it's done when the run ends well."),
        TaskDo::Audit => "Enter audits now; it's done with the audit.".into(),
        TaskDo::Job(j) if j.starts_with("cleanup") => {
            "Enter opens Cleanup; it's done when a cleanup runs.".into()
        }
        TaskDo::Job(j) => format!("Enter runs {j}; it's done when it has run."),
        TaskDo::ByHand | TaskDo::Plan(_) => {
            "By hand: Enter works it out with Claude (it plans, sentry applies).".into()
        }
    }
}

/// Enter on a task: what its `do` says (by hand: with Claude, who plans it; `m`: the steps).
pub fn task_effects(v: &View, id: &str) -> Vec<Effect> {
    let Some(task) = task(v, id) else {
        return Vec::new();
    };
    if id == sentry_core::secaudit::TASK_ID {
        return vec![Effect::SecRun];
    }
    match task.action() {
        TaskDo::Run(wf) => vec![Effect::StartWorkflow(wf)],
        TaskDo::Audit => vec![audit::audit_run()],
        TaskDo::Job(j) => job_effects(&j),
        // By hand (a plan of an item is sentry-server's): with Claude, who plans it and
        // sentry applies it; without Claude Code, the steps (`m` shows them anyway).
        TaskDo::ByHand | TaskDo::Plan(_) => {
            let apply = recs(v)
                .into_iter()
                .find(|r| r.key == task.key())
                .and_then(|r| apply_ask(v, &r))
                .filter(|_| crate::claude::available());
            match apply {
                Some(a) => vec![Effect::AskConsent(a)],
                None => manual_effects(v, id),
            }
        }
    }
}

/// `m` on a task done by hand: its steps, to do it yourself, then mark it done.
pub fn manual_effects(v: &View, id: &str) -> Vec<Effect> {
    let t = v.t;
    let Some(task) = task(v, id) else {
        return Vec::new();
    };
    match task.action() {
        TaskDo::ByHand | TaskDo::Plan(_) => {
            let mut lines = vec![Line::styled(task.why.clone(), t.fg()), Line::raw("")];
            if task.steps.trim().is_empty() {
                lines.push(Line::styled("(no steps given: see the review)", t.dim()));
            } else {
                lines.extend(crate::tui::docview::markdown(t, &task.steps));
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
        _ => Vec::new(),
    }
}

/// Enter on one of the jobs: the check runs here, a cleanup opens its screen.
pub fn job_effects(job: &str) -> Vec<Effect> {
    match job {
        "audit" => vec![audit::audit_run()],
        "update-check" => {
            let mut e = check_all();
            e.retain(|x| matches!(x, Effect::Fetch(f) if *f != Fetch::Cleanup));
            e.push(Effect::Toast(
                "checking OS, Flatpak and toolbox updates…".into(),
            ));
            e
        }
        j if j.starts_with("cleanup") => vec![Effect::Goto(crate::tui::ScreenId::Clean)],
        "update-apply" => vec![Effect::Toast(format!(
            "updates go through {}: Enter on the updates row, or Upgrade (0)",
            local::UPDATE_WORKFLOW
        ))],
        j => vec![Effect::Toast(format!("no job {j}"))],
    }
}

/// The machine's state for a plan or a review: deployments and what's waiting.
pub fn context(v: &View) -> String {
    updates::ask(v).map_or_else(|e| format!("(updates: {e})"), |a| a.context)
}

/// The recommendations, one line each, for a review.
pub fn recs_text(v: &View) -> String {
    let r: Vec<String> = recs_all(v)
        .iter()
        .map(|r| format!("- [{}] {}: {}", r.level.word(), r.title, r.why))
        .collect();
    if r.is_empty() {
        "(nothing)".into()
    } else {
        r.join("\n")
    }
}

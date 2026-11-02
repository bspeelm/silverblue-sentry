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
use crate::tui::app::{Choice, Effect, Modal, RunSpec};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::maintlist::{self, Dismiss, Verbs};
use crate::tui::widgets::{inner, panel, wrap};

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
    /// Select the first recommendation whose key starts with this (from the dashboard).
    pub find: Option<String>,
    pub view: Option<Sub>,
    pub audit: audit::Audit,
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
    let mut h = maintlist::hints(&m.selected(v).map(|r| verbs(v, &r)).unwrap_or_default());
    // Narrow: the bar drops these from the end.
    h.extend([
        ("c", "check all"),
        ("R", "review"),
        ("v", "records"),
        ("F", "report"),
        ("C", "cleanup"),
        ("w", "workflows"),
    ]);
    h
}

/// The keys a row takes besides Enter.
pub fn verbs(v: &View, r: &Rec) -> Verbs {
    match &r.action {
        Do::Fix(_) => Verbs {
            dismiss: Some(Dismiss::Expected),
            like: true,
            ..Default::default()
        },
        Do::Run(wf) | Do::OpenPlan(wf) => Verbs {
            plan: true,
            planned: v.d.plans.contains_key(wf),
            ..Default::default()
        },
        Do::Task(_) => Verbs {
            done: true,
            every: true,
            dismiss: Some(Dismiss::Remove),
            ..Default::default()
        },
        _ => Verbs::default(),
    }
}

/// The recommendations, from what's loaded.
pub fn recs(v: &View) -> Vec<Rec> {
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
        flatpak_updates: v.d.fp_updates.get().map(|c| c.data.len()),
        toolbox_updates: v
            .d
            .tbx_updates
            .get()
            .map(|c| crate::collectors::toolbox::total(&c.data)),
        reclaim,
        disk_tight,
        run,
        plans: &v.d.plans,
        snoozes: &v.d.snoozes,
        tasks: &all_tasks(v),
        log: &v.d.maint_log,
    })
    .into_iter()
    .filter(|r| v.matches(&[&r.title, &r.why, r.level.word()]))
    .collect()
}

/// Every task that applies: `tasks.toml`'s and the jobs' cadences.
pub fn all_tasks(v: &View) -> Vec<Task> {
    crate::maint::tasks::effective(&v.d.tasks, crate::jobs::state::tasks(v.cfg))
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
    fn sync(&mut self, recs: &[Rec]) {
        if let Some(p) = self.find.take() {
            if let Some(i) = recs.iter().position(|r| r.key.starts_with(&p)) {
                self.cur.sel = i;
            }
        } else if let Some(i) = self
            .sel
            .as_ref()
            .and_then(|k| recs.iter().position(|r| &r.key == k))
        {
            self.cur.sel = i;
        }
        let i = self.cur.clamp(recs.len());
        self.sel = recs.get(i).map(|r| r.key.clone());
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
        if self.cur.nav(a, recs.len()) {
            self.sel = recs.get(self.cur.sel).map(|r| r.key.clone());
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
            _ => {}
        }
        let Some(r) = recs.get(self.cur.sel) else {
            return Vec::new();
        };
        match a {
            Action::Enter => self.act(v, r),
            Action::Char('p' | 'P') => match &r.action {
                Do::Run(wf) | Do::OpenPlan(wf) => {
                    vec![Effect::PlanAsk(wf.clone(), a == Action::Char('P'))]
                }
                _ => vec![Effect::Toast(
                    "plans are for workflows: p on updates, or on Upgrade (0)".into(),
                )],
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
                _ => vec![Effect::Toast(
                    "only findings can be marked expected: z puts this off".into(),
                )],
            },
            Action::Char('B') => match &r.action {
                Do::Fix(id) => finding(v, id).map_or(Vec::new(), |f| audit::pattern_effects(v, f)),
                _ => Vec::new(),
            },
            Action::Char('z') => {
                let days = [7, 30, 90];
                let mut lines: Vec<Line<'static>> = days
                    .iter()
                    .enumerate()
                    .map(|(i, d)| Line::styled(format!("{}  in {d} days", i + 1), t.fg()))
                    .collect();
                lines.push(Line::raw(""));
                lines.push(Line::styled(
                    format!("{}: it leaves the list until then (maint.toml).", r.title),
                    t.dim(),
                ));
                vec![Effect::Choose(Choice {
                    title: "Look again later · pick one (1–3, n cancels)".into(),
                    lines,
                    options: days
                        .into_iter()
                        .map(|d| {
                            (
                                format!("in {d} days"),
                                vec![Effect::Snooze(r.key.clone(), d)],
                            )
                        })
                        .collect(),
                })]
            }
            _ => Vec::new(),
        }
    }

    /// Enter: what the recommendation says to do.
    fn act(&mut self, v: &View, r: &Rec) -> Vec<Effect> {
        let t = v.t;
        match &r.action {
            Do::Fix(id) => match finding(v, id) {
                Some(f) if crate::claude::available() => {
                    vec![Effect::AskConsent(crate::claude::Ask::fix(f))]
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
            Do::OpenPlan(wf) => vec![Effect::PlanOpen(wf.clone())],
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
        let [left, right] =
            Layout::horizontal([Constraint::Ratio(55, 100), Constraint::Ratio(45, 100)])
                .spacing(1)
                .areas(area);
        let want = recs.len().max(1) as u16 + 4;
        let [top, bottom] = Layout::vertical([
            Constraint::Length(want.min(left.height / 2).max(6)),
            Constraint::Fill(1),
        ])
        .areas(left);
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
        let empty = if v.filter.is_some() {
            "nothing matches the filter"
        } else if v.d.loading(Fetch::Reports) || v.d.loading(Fetch::Log) {
            "reading…"
        } else {
            "✓ nothing to maintain right now · c checks everything again"
        };
        self.cur.page = maintlist::draw(
            f,
            area,
            t,
            format!("{} · {audited}", recs.len()),
            recs,
            Some(self.cur.sel),
            (empty, t.dim()),
        );
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
                Ok(crate::claude::Ask::fix(f))
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
    let mut l = vec![Line::from(vec![
        Span::styled(
            format!("{}  ", r.level.word()),
            t.s(level_color(t, r.level)),
        ),
        Span::styled(r.title.clone(), t.fg()),
    ])];
    l.push(Line::raw(""));
    for x in wrap(&r.why, w) {
        l.push(Line::styled(x, t.fg()));
    }
    l.push(Line::raw(""));
    l.push(Line::styled(action_words(&r.action), t.s(t.cyan)));
    if let Do::Run(wf) = &r.action {
        l.push(Line::styled(
            format!("Same as {wf} on the Upgrade screen (0), where you can watch it."),
            t.dim(),
        ));
    }
    l.push(Line::styled("z: look again later", t.dim()));
    match &r.action {
        Do::Fix(id) => {
            if let Some(fd) = finding(v, id) {
                l.push(Line::raw(""));
                l.extend(audit::finding_lines(t, fd, w, "Enter"));
                l.push(Line::styled("x: expected (baseline.toml)", t.dim()));
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
                l.push(Line::raw(""));
                l.push(Line::styled(
                    "d: done (logs it) · x: remove it (tasks.toml)",
                    t.dim(),
                ));
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
        Do::OpenPlan(_) => "Enter: open the plan (Enter there starts its workflow)".into(),
        Do::Task(_) => "A task: Enter does it".into(),
    }
}

/// What Enter does on a task, in words.
fn task_words(task: &Task) -> String {
    match task.action() {
        TaskDo::Run(wf) => format!("Enter starts {wf}; it's done when the run ends well."),
        TaskDo::Audit => "Enter audits now; it's done with the audit.".into(),
        TaskDo::Job(j) if j.starts_with("cleanup") => {
            "Enter opens Cleanup; it's done when a cleanup runs.".into()
        }
        TaskDo::Job(j) => format!("Enter runs {j}; it's done when it has run."),
        TaskDo::ByHand | TaskDo::Plan(_) => {
            "By hand: Enter shows the steps, then marks it done.".into()
        }
    }
}

/// Enter on a task: what its `do` says (by hand: its steps, then mark it done).
pub fn task_effects(v: &View, id: &str) -> Vec<Effect> {
    let t = v.t;
    let Some(task) = task(v, id) else {
        return Vec::new();
    };
    match task.action() {
        TaskDo::Run(wf) => vec![Effect::StartWorkflow(wf)],
        TaskDo::Audit => vec![audit::audit_run()],
        TaskDo::Job(j) => job_effects(&j),
        // By hand (a plan of an item is sentry-server's): Claude's steps, then done.
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
    let r: Vec<String> = recs(v)
        .iter()
        .map(|r| format!("- [{}] {}: {}", r.level.word(), r.title, r.why))
        .collect();
    if r.is_empty() {
        "(nothing)".into()
    } else {
        r.join("\n")
    }
}

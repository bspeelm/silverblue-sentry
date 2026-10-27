//! Maintenance (`6`): what to do on this machine next, ranked (`maint::local`): the audit's
//! findings, updates and a staged reboot, jobs due by their cadence, space to reclaim, a
//! workflow left in progress, plans ready to apply. Beside it the deployments and the
//! selected recommendation's details. The audit report, the jobs and the cleanup checklist
//! open as views here (`F`, `J`, `C`); Esc comes back.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Wrap};

use super::{Cursor, Hints, View, audit, cleanup, jobs, updates};
use crate::audit::Finding;
use crate::maint::Level;
use crate::maint::local::{self, Action as Do, Inputs, Rec, RunInfo};
use crate::tui::app::{Choice, Effect, Modal, RunSpec};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::theme::Theme;
use crate::tui::widgets::{TableSpec, inner, panel, placeholder, table, wrap};

/// A view opened inside Maintenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sub {
    /// The audit report: findings, the diff against the previous one, `[`/`]` to browse.
    Report,
    Jobs,
    Cleanup,
}

impl Sub {
    fn title(self) -> &'static str {
        match self {
            Sub::Report => "Audit report",
            Sub::Jobs => "Jobs",
            Sub::Cleanup => "Cleanup",
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
    pub jobs: jobs::Jobs,
    pub clean: cleanup::Cleanup,
}

pub fn on_enter(v: &View, view: Option<Sub>) -> Vec<Effect> {
    let mut e = vec![
        Effect::Fetch(Fetch::Reports),
        Effect::Fetch(Fetch::Jobs),
        Effect::Fetch(Fetch::Ostree),
        Effect::Fetch(Fetch::Disks),
    ];
    if v.d.flatpak.get().is_none() {
        // Installed versions, for "old → new" in the updates' details.
        e.push(Effect::Fetch(Fetch::Flatpak));
    }
    if view == Some(Sub::Cleanup) {
        e.extend(cleanup::on_enter(v));
    }
    e
}

pub fn hints(v: &View, m: &Maint) -> Hints {
    if let Some(s) = m.view {
        let mut h = match s {
            Sub::Report => audit::hints(v),
            Sub::Jobs => jobs::hints(),
            Sub::Cleanup => cleanup::hints(),
        };
        h.insert(0, ("Esc", "back"));
        return h;
    }
    let mut h = vec![("j/k", "select"), ("Enter", "do it")];
    if let Some(r) = m.selected(v) {
        if matches!(r.action, Do::Fix(_)) {
            h.push(("x", "expected"));
        }
        if matches!(r.action, Do::Run(_) | Do::OpenPlan(_)) {
            h.push(("p", "plan"));
        }
        h.push(("z", "later"));
    }
    h.extend([
        ("c", "check all"),
        ("F", "report"),
        ("J", "jobs"),
        ("C", "cleanup"),
        ("R", "review"),
        ("v", "log"),
    ]);
    h
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
        jobs: v.d.job_runs.get(),
        reclaim,
        disk_tight,
        run,
        plans: &v.d.plans,
        snoozes: &v.d.snoozes,
    })
    .into_iter()
    .filter(|r| v.matches(&[&r.title, &r.why, r.level.word()]))
    .collect()
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

pub fn level_color(t: &Theme, l: Level) -> ratatui::style::Color {
    match l {
        Level::Now => t.red,
        Level::Soon => t.yellow,
        Level::Routine => t.cyan,
        Level::Tidy => t.dim,
    }
}

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
                Sub::Jobs => self.jobs.handle(a, v),
                Sub::Cleanup => self.clean.handle(a, v),
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
                return [Fetch::Reports, Fetch::Jobs, Fetch::Ostree, Fetch::Disks]
                    .into_iter()
                    .map(Effect::Fetch)
                    .collect();
            }
            // Reports and jobs are read when Maintenance opens (r reads them again).
            Action::Char('F') => {
                self.view = Some(Sub::Report);
                return Vec::new();
            }
            Action::Char('J') => {
                self.view = Some(Sub::Jobs);
                return Vec::new();
            }
            Action::Char('C') => {
                self.view = Some(Sub::Cleanup);
                return cleanup::on_enter(v);
            }
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
            Action::Char('x') => match &r.action {
                Do::Fix(id) => finding(v, id).map_or(Vec::new(), |f| {
                    vec![
                        audit::expected_toggle(v, f),
                        Effect::Toast("marked expected (baseline.toml)".into()),
                    ]
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
                        vec![Effect::Run(RunSpec {
                            title: "reboot".into(),
                            cmd,
                            queue: Vec::new(),
                            then: Vec::new(),
                            ok_toast: "rebooting…".into(),
                        })],
                    )),
                })]
            }
            Do::Cleanup => {
                self.view = Some(Sub::Cleanup);
                cleanup::on_enter(v)
            }
            Do::Jobs(j) => {
                self.view = Some(Sub::Jobs);
                self.jobs.cur.sel = crate::jobs::JobId::ALL
                    .iter()
                    .position(|x| x == j)
                    .unwrap_or(0);
                vec![Effect::Fetch(Fetch::Jobs)]
            }
            Do::OpenRun => vec![Effect::Goto(crate::tui::ScreenId::Upgrade)],
            Do::OpenPlan(wf) => vec![Effect::PlanOpen(wf.clone())],
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
                Sub::Jobs => self.jobs.render(f, body, v),
                Sub::Cleanup => self.clean.render(f, body, v),
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
        let b = panel(t, "Recommended", format!("{} · {audited}", recs.len()));
        let r = inner(&b, area);
        f.render_widget(b, area);
        self.cur.page = r.height as usize;
        if recs.is_empty() {
            let msg = if v.filter.is_some() {
                "nothing matches the filter"
            } else if v.d.loading(Fetch::Reports) || v.d.loading(Fetch::Jobs) {
                "reading…"
            } else {
                "✓ nothing to maintain right now · c checks everything again"
            };
            placeholder(f, r, t, &[(msg, t.dim())]);
            return;
        }
        let rows: Vec<Row> = recs
            .iter()
            .map(|x| {
                Row::new(vec![
                    Cell::from(x.level.word()).style(t.s(level_color(t, x.level))),
                    Cell::from(x.title.clone()).style(t.fg()),
                    Cell::from(x.why.clone()).style(t.dim()),
                ])
            })
            .collect();
        table(
            f,
            r,
            t,
            TableSpec {
                header: vec!["", "What", "Why"],
                widths: vec![
                    Constraint::Length(8),
                    Constraint::Fill(3),
                    Constraint::Fill(4),
                ],
                rows,
                selected: Some(self.cur.sel),
            },
        );
    }

    pub fn ask(&self, v: &View) -> Result<crate::claude::Ask, String> {
        if let Some(s) = self.view {
            return match s {
                Sub::Report => self.audit.ask(v),
                Sub::Jobs => self.jobs.ask(v),
                Sub::Cleanup => self.clean.ask(v),
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
            Some(Do::Cleanup) => self.clean.ask(v),
            Some(Do::Jobs(_)) => self.jobs.ask(v),
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
        Do::Run(wf) => format!(
            "Enter: start {wf}, the workflow on Upgrade (0): the same run as starting it there, \
             which shows there (each step asks first)"
        ),
        Do::Reboot => "Enter: reboot (asks first)".into(),
        Do::Cleanup => "Enter: the cleanup checklist (pick, preview, confirm)".into(),
        Do::Jobs(j) => format!("Enter: the job {} (its plan, then run)", j.name()),
        Do::OpenRun => "Enter: open the run on Upgrade (0)".into(),
        Do::OpenPlan(_) => "Enter: open the plan (Enter there starts its workflow)".into(),
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

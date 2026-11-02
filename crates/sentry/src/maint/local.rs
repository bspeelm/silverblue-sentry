//! What to maintain on this machine next, and why: the audit's open findings, updates
//! waiting and a deployment waiting for a reboot, jobs whose last run failed, space to
//! reclaim, a workflow left in progress, plans ready to apply, and the tasks that are due
//! (the jobs' cadences among them). Pure.

use std::collections::BTreeMap;

use jiff::Timestamp;

use super::Level;
use super::later::Snoozes;
use super::log::LogEntry;
use super::plan::{PlanDoc, PlanStatus};
use super::rec::Target;
use super::tasks::Task;
use crate::audit::{Report, Sev};
use crate::baseline::Baseline;
use crate::collectors::ostree::{Ostree, UpgradePlan, upgrade_plan};
use crate::config::Config;

/// The workflow that applies updates: Flatpaks, toolboxes, the OS, and the kmod ritual.
pub const UPDATE_WORKFLOW: &str = "quick-update";
/// A deployment staged this long ago makes the reboot "now".
const REBOOT_NOW_DAYS: i64 = 14;
/// Less than this to reclaim isn't worth a line (unless a disk is tight).
const RECLAIM_MIN: u64 = 1 << 30;

/// What Enter does on a recommendation.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// An audit finding: fix it (Claude, or sentry's own fixes).
    Fix(String),
    /// Run the audit.
    Audit,
    /// Check for OS, Flatpak and toolbox updates.
    CheckUpdates,
    /// Start a workflow (updates: `quick-update`).
    Run(String),
    /// Reboot into the staged deployment.
    Reboot,
    /// Open the Cleanup view.
    Cleanup,
    /// Open the workflow run (Upgrade).
    OpenRun,
    /// Open a plan (ready to apply).
    OpenPlan(String),
    /// A task from a review (its id): what Enter does is the task's own `do`.
    Task(String),
}

/// Keys: `finding:<id>`, `updates`, `reboot`, `job:<name>`, `cleanup`, `run`,
/// `plan:<workflow>`, `task:<id>`.
pub type Rec = super::rec::Rec<Action>;

impl super::rec::Act for Action {
    fn target(&self) -> Target {
        match self {
            Action::Run(wf) => Target::Workflow(wf.clone()),
            Action::Audit => Target::Audit,
            Action::CheckUpdates => Target::Job("update-check".into()),
            Action::Cleanup => Target::Job("cleanup".into()),
            _ => Target::None,
        }
    }
    fn task(id: String) -> Self {
        Action::Task(id)
    }
}

/// The workflow run on screen, if any.
pub struct RunInfo<'a> {
    pub workflow: &'a str,
    pub done: bool,
    /// The step it's at, and whether it failed.
    pub step: Option<(usize, usize, &'a str)>,
    pub failed: bool,
}

pub struct Inputs<'a> {
    pub now: Timestamp,
    pub cfg: &'a Config,
    /// The newest audit report, and when it was taken.
    pub report: Option<&'a Report>,
    pub baseline: &'a Baseline,
    pub ostree: Option<&'a Ostree>,
    pub flatpak_updates: Option<usize>,
    pub toolbox_updates: Option<usize>,
    /// Bytes the cleanup dry runs found (None: not measured).
    pub reclaim: Option<u64>,
    /// A disk past 90%.
    pub disk_tight: bool,
    pub run: Option<RunInfo<'a>>,
    pub plans: &'a BTreeMap<String, PlanDoc>,
    pub snoozes: &'a Snoozes,
    /// Tasks taken from reviews (`tasks.toml`), and the log that says which are done.
    pub tasks: &'a [Task],
    pub log: &'a [LogEntry],
}

pub fn recommend(i: &Inputs) -> Vec<Rec> {
    let mut out = Vec::new();
    // A run left in progress comes first: nothing else should start until it's done.
    if let Some(r) = i.run.as_ref().filter(|r| !r.done) {
        let at = r.step.map_or(String::new(), |(n, of, title)| {
            format!(" at step {n}/{of}: {title}")
        });
        out.push(Rec {
            level: Level::Now,
            key: "run".into(),
            title: format!(
                "{} {}",
                r.workflow,
                if r.failed { "stopped" } else { "in progress" }
            ),
            why: format!(
                "The run is{at}{}. Finish it (or abandon it) before starting other changes.",
                if r.failed { ", which failed" } else { "" }
            ),
            action: Action::OpenRun,
            item: None,
        });
    }
    for (wf, p) in i.plans {
        if matches!(p.head.status, PlanStatus::Ready) {
            out.push(Rec {
                level: Level::Soon,
                key: format!("plan:{wf}"),
                title: format!("Plan ready: {wf}"),
                why: p.head.note.clone().unwrap_or_else(|| {
                    "Claude's plan is written: Enter opens it, Enter there starts the workflow."
                        .into()
                }),
                action: Action::OpenPlan(wf.clone()),
                item: None,
            });
        }
    }
    findings(i, &mut out);
    updates(i, &mut out);
    jobs(i, &mut out);
    super::rec::finish(
        out,
        &super::rec::Tail {
            tasks: i.tasks,
            log: i.log,
            audited: i.report.map(|r| r.taken_at),
            now: i.now,
            snooze: i.snoozes,
            today: i.now.to_zoned(jiff::tz::TimeZone::system()).date(),
        },
    )
}

fn findings(i: &Inputs, out: &mut Vec<Rec>) {
    let Some(r) = i.report else { return };
    for f in r.open(i.baseline) {
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
            action: Action::Fix(f.id.clone()),
            item: None,
        });
    }
}

fn updates(i: &Inputs, out: &mut Vec<Rec>) {
    let days = |ts: i64| (i.now.as_second() - ts).max(0) / 86400;
    if let Some(o) = i.ostree {
        // Staged and waiting: the update is done but not running yet.
        if let Some(s) = o.deployments.iter().find(|d| d.staged && !d.booted) {
            let d = days(s.timestamp);
            out.push(Rec {
                level: if d >= REBOOT_NOW_DAYS {
                    Level::Now
                } else {
                    Level::Soon
                },
                key: "reboot".into(),
                title: format!("Reboot into {}", s.version),
                why: format!(
                    "{} is staged{}: it takes effect on the next boot.",
                    s.version,
                    if d > 0 {
                        format!(" (built {d} days ago)")
                    } else {
                        String::new()
                    }
                ),
                action: Action::Reboot,
                item: None,
            });
        }
    }
    // The update workflow is already running: its own row says so (Enter opens it).
    if i.run
        .as_ref()
        .is_some_and(|r| !r.done && r.workflow == UPDATE_WORKFLOW)
    {
        return;
    }
    let os = i.ostree.and_then(|o| o.update.as_ref());
    let fp = i.flatpak_updates.unwrap_or(0);
    let tb = i.toolbox_updates.unwrap_or(0);
    if os.is_none() && fp + tb == 0 {
        return;
    }
    let mut parts = Vec::new();
    if let Some(u) = os {
        parts.push(format!("OS {}", u.version.as_deref().unwrap_or("update")));
    }
    if fp > 0 {
        parts.push(format!("{fp} Flatpak"));
    }
    if tb > 0 {
        parts.push(format!("{tb} in toolboxes"));
    }
    let ritual = i
        .ostree
        .is_some_and(|o| matches!(upgrade_plan(o), UpgradePlan::Ritual(_)));
    let security = os.is_some_and(|u| u.advisories > 0);
    out.push(Rec {
        level: if security || ritual || os.is_some() {
            Level::Soon
        } else {
            Level::Routine
        },
        key: "updates".into(),
        title: format!("Updates waiting: {}", parts.join(" · ")),
        why: if ritual {
            "The kernel changes: quick-update runs the NVIDIA kmod procedure (two reboots).".into()
        } else if security {
            format!(
                "{} security advisories. quick-update does Flatpaks, toolboxes, then the OS.",
                os.map_or(0, |u| u.advisories)
            )
        } else {
            "quick-update does Flatpaks, toolboxes, then stages the OS update.".into()
        },
        action: Action::Run(UPDATE_WORKFLOW.into()),
        item: None,
    });
}

fn jobs(i: &Inputs, out: &mut Vec<Rec>) {
    // A job whose last run failed (the log has it). Due jobs are tasks.
    for (name, r) in crate::jobs::state::last_runs(i.log) {
        let action = match name {
            "audit" => Action::Audit,
            "update-check" => Action::CheckUpdates,
            "update-apply" => Action::Run(UPDATE_WORKFLOW.into()),
            _ => Action::Cleanup,
        };
        if !r.ok {
            out.push(Rec {
                level: Level::Soon,
                key: format!("job:{name}"),
                title: format!("{name} failed"),
                why: format!("Last run: {}", r.summary),
                action,
                item: None,
            });
        }
    }
    let big = i.reclaim.is_some_and(|b| b >= RECLAIM_MIN);
    if big || (i.disk_tight && i.reclaim.is_some_and(|b| b > 0)) {
        let space = i
            .reclaim
            .filter(|b| *b > 0)
            .map(|b| format!("{} to reclaim", crate::fmt::bytes(b)));
        out.push(Rec {
            level: if i.disk_tight {
                Level::Now
            } else {
                Level::Tidy
            },
            key: "cleanup".into(),
            title: match &space {
                Some(s) => format!("Clean up: {s}"),
                None => "Clean up".into(),
            },
            why: [
                i.disk_tight.then(|| "A disk is past 90%.".to_string()),
                Some("Cleanup (7) shows what goes before anything does.".to_string()),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" "),
            action: Action::Cleanup,
            item: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Finding;

    fn finding(id: &str, sev: Sev) -> Finding {
        Finding {
            id: id.into(),
            severity: sev,
            category: "services".into(),
            message: format!("{id} message"),
            why: format!("{id} why"),
            ..Default::default()
        }
    }

    fn base<'a>(
        cfg: &'a Config,
        b: &'a Baseline,
        s: &'a Snoozes,
        p: &'a BTreeMap<String, PlanDoc>,
    ) -> Inputs<'a> {
        Inputs {
            now: "2026-10-27T12:00:00Z".parse().unwrap(),
            cfg,
            report: None,
            baseline: b,
            ostree: None,
            flatpak_updates: None,
            toolbox_updates: None,
            reclaim: None,
            disk_tight: false,
            run: None,
            plans: p,
            snoozes: s,
            tasks: &[],
            log: &[],
        }
    }

    #[test]
    fn tasks_due_are_recommended_and_snooze_like_the_rest() {
        let (cfg, b, p) = (Config::default(), Baseline::default(), BTreeMap::new());
        let task = Task {
            id: "ups".into(),
            title: "Check the UPS battery".into(),
            why: "It's three years old.".into(),
            level: Level::Soon,
            every: Some(crate::config::Dur::secs(90 * 86400)),
            act: "by-hand".into(),
            item: None,
            steps: String::new(),
            added: None,
            review: None,
            off: false,
            source: Default::default(),
        };
        let tasks = [task];
        let s = Snoozes::new();
        let mut i = base(&cfg, &b, &s, &p);
        i.tasks = &tasks;
        let r = recommend(&i);
        let t = r.iter().find(|r| r.key == "task:ups").expect("the task");
        assert_eq!(t.action, Action::Task("ups".into()));
        assert_eq!(t.level, Level::Soon);
        assert!(t.why.contains("every 90d; not done yet"));
        let mut s = Snoozes::new();
        s.insert("task:ups".into(), "2026-11-30".parse().unwrap());
        let mut i = base(&cfg, &b, &s, &p);
        i.tasks = &tasks;
        assert!(recommend(&i).iter().all(|r| r.key != "task:ups"));
    }

    #[test]
    fn findings_rank_by_severity_and_expected_ones_stay_out() {
        let (cfg, s, p) = (Config::default(), Snoozes::new(), BTreeMap::new());
        let b = Baseline {
            findings: vec!["ok".into()],
            ..Default::default()
        };
        let mut r = crate::audit::test_report(Default::default());
        r.findings = vec![
            finding("low", Sev::Low),
            finding("high", Sev::High),
            finding("mid", Sev::Medium),
        ];
        r.findings.push(finding("ok", Sev::High));
        let mut i = base(&cfg, &b, &s, &p);
        i.report = Some(&r);
        let recs = recommend(&i);
        let keys: Vec<&str> = recs.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, ["finding:high", "finding:mid", "finding:low"]);
        assert_eq!(recs[0].action, Action::Fix("high".into()));
        assert_eq!(recs[0].why, "high why");
    }

    #[test]
    fn updates_staged_reboot_and_the_ritual() {
        let (cfg, b, s, p) = (
            Config::default(),
            Baseline::default(),
            Snoozes::new(),
            BTreeMap::new(),
        );
        let o = crate::collectors::ostree::parse(&crate::collectors::fixture("ostree/status.json"))
            .unwrap();
        let mut i = base(&cfg, &b, &s, &p);
        i.ostree = Some(&o);
        i.flatpak_updates = Some(3);
        let recs = recommend(&i);
        let u = recs.iter().find(|r| r.key == "updates").expect("updates");
        assert_eq!(u.level, Level::Soon);
        assert!(u.title.contains("3 Flatpak"), "{}", u.title);
        assert!(
            u.why.contains("kmod"),
            "the fixture's kernel changes: {}",
            u.why
        );
        assert_eq!(u.action, Action::Run("quick-update".into()));
        // Only Flatpaks: routine.
        i.ostree = None;
        let recs = recommend(&i);
        assert_eq!(recs[0].level, Level::Routine);
        // A staged deployment, two weeks on: reboot now.
        let mut staged = o.clone();
        staged.update = None;
        staged.deployments[0].booted = false;
        staged.deployments[0].staged = true;
        staged.deployments[0].timestamp = i.now.as_second() - 15 * 86400;
        i.ostree = Some(&staged);
        i.flatpak_updates = None;
        // quick-update running: the run's row stands for the updates.
        i.ostree = Some(&o);
        i.run = Some(RunInfo {
            workflow: UPDATE_WORKFLOW,
            done: false,
            step: Some((2, 9, "Update Flatpaks")),
            failed: false,
        });
        let keys: Vec<String> = recommend(&i).into_iter().map(|r| r.key).collect();
        assert!(keys.contains(&"run".to_string()) && !keys.contains(&"updates".to_string()));
        i.run = None;
        i.ostree = Some(&staged);
        let recs = recommend(&i);
        assert_eq!(recs[0].key, "reboot");
        assert_eq!(recs[0].level, Level::Now);
    }

    #[test]
    fn failed_jobs_due_tasks_and_cleanup() {
        let (cfg, b, s, p) = (
            Config::default(),
            Baseline::default(),
            Snoozes::new(),
            BTreeMap::new(),
        );
        let now: Timestamp = "2026-10-27T12:00:00Z".parse().unwrap();
        let yesterday = now - jiff::SignedDuration::from_hours(24);
        // Everything ran yesterday, except the audit (never) and podman (failed).
        let log: Vec<LogEntry> = crate::jobs::JobId::ALL
            .into_iter()
            .filter(|j| j.name() != "audit")
            .map(|j| {
                let ok = j.name() != "cleanup-podman";
                LogEntry::event("", "job", j.name(), ok, "podman: not found", &[], yesterday)
            })
            .collect();
        let tasks = crate::jobs::state::tasks(&cfg);
        let mut i = base(&cfg, &b, &s, &p);
        i.log = &log;
        i.tasks = &tasks;
        i.reclaim = Some(3 << 30);
        let recs = recommend(&i);
        let keys: Vec<&str> = recs.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(
            keys,
            ["job:cleanup-podman", "task:job-audit", "cleanup"],
            "{recs:#?}"
        );
        assert_eq!(recs[1].action, Action::Task("job-audit".into()));
        assert_eq!(recs[2].level, Level::Tidy);
        assert!(recs[2].title.contains("3.0 GiB"), "{}", recs[2].title);
        i.disk_tight = true;
        assert_eq!(recommend(&i)[0].key, "cleanup", "a full disk makes it now");
    }

    #[test]
    fn a_run_in_progress_comes_first_and_snoozed_ones_wait() {
        let (cfg, b, p) = (Config::default(), Baseline::default(), BTreeMap::new());
        let mut s = Snoozes::new();
        s.insert("finding:high".into(), "2026-11-03".parse().unwrap());
        let mut r = crate::audit::test_report(Default::default());
        r.findings = vec![finding("high", Sev::High), finding("other", Sev::High)];
        let mut i = base(&cfg, &b, &s, &p);
        i.report = Some(&r);
        i.run = Some(RunInfo {
            workflow: "quick-update",
            done: false,
            step: Some((3, 9, "Update Flatpaks")),
            failed: true,
        });
        let recs = recommend(&i);
        let keys: Vec<&str> = recs.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, ["run", "finding:other"]);
        assert!(recs[0].title.contains("stopped") && recs[0].why.contains("step 3/9"));
    }
}

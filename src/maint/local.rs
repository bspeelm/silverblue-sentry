//! What to maintain on this machine next, and why: the audit's open findings, updates
//! waiting and a deployment waiting for a reboot, jobs that are due or failed (cadence is the
//! reminder), space to reclaim, a workflow left in progress, and plans ready to apply. Pure.

use std::collections::BTreeMap;

use jiff::Timestamp;

use super::Level;
use super::plan::{PlanDoc, PlanStatus};
use super::snooze::Snoozes;
use crate::audit::{Report, Sev};
use crate::baseline::Baseline;
use crate::collectors::ostree::{Ostree, UpgradePlan, upgrade_plan};
use crate::config::Config;
use crate::jobs::JobId;
use crate::jobs::state::{Records, due};

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
    /// Open the Jobs view on this job.
    Jobs(JobId),
    /// Open the workflow run (Upgrade).
    OpenRun,
    /// Open a plan (ready to apply).
    OpenPlan(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rec {
    pub level: Level,
    /// For `z` and for keeping the selection: `finding:<id>`, `updates`, `reboot`,
    /// `job:<name>`, `cleanup`, `run`, `plan:<workflow>`.
    pub key: String,
    pub title: String,
    pub why: String,
    pub action: Action,
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
    pub jobs: Option<&'a Records>,
    /// Bytes the cleanup dry runs found (None: not measured).
    pub reclaim: Option<u64>,
    /// A disk past 90%.
    pub disk_tight: bool,
    pub run: Option<RunInfo<'a>>,
    pub plans: &'a BTreeMap<String, PlanDoc>,
    pub snoozes: &'a Snoozes,
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
            });
        }
    }
    findings(i, &mut out);
    updates(i, &mut out);
    jobs(i, &mut out);
    out.retain(|r| !snoozed(i, &r.key));
    out.sort_by_key(|r| r.level);
    out
}

fn snoozed(i: &Inputs, key: &str) -> bool {
    let today = i.now.to_zoned(jiff::tz::TimeZone::system()).date();
    i.snoozes.get(key).is_some_and(|d| *d > today)
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
            });
        }
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
    });
}

fn jobs(i: &Inputs, out: &mut Vec<Rec>) {
    let Some(rec) = i.jobs else { return };
    let has_updates = out.iter().any(|r| r.key == "updates");
    let mut cleanup_due = Vec::new();
    for j in JobId::ALL {
        let every = rec.every(j, i.cfg);
        let last = rec.runs.get(j.name());
        if let Some(l) = last.filter(|l| !l.ok) {
            out.push(Rec {
                level: Level::Soon,
                key: format!("job:{}", j.name()),
                title: format!("{} failed", j.name()),
                why: format!("Last run: {}", l.summary),
                action: Action::Jobs(j),
            });
            continue;
        }
        if !due(j, every, &rec.runs, i.now).is_due() {
            continue;
        }
        let ago = last.map_or("never run".to_string(), |l| {
            format!(
                "last run {} days ago, due every {}",
                (i.now.as_second() - l.at.as_second()) / 86400,
                every.label()
            )
        });
        let (title, action) = match j {
            JobId::Audit => ("Audit this machine", Action::Audit),
            JobId::UpdateCheck => ("Check for updates", Action::CheckUpdates),
            // Applying is what the updates recommendation does already.
            JobId::UpdateApply if has_updates => continue,
            JobId::UpdateApply => ("Apply updates", Action::Run(UPDATE_WORKFLOW.into())),
            _ => {
                cleanup_due.push(j.name());
                continue;
            }
        };
        out.push(Rec {
            level: Level::Routine,
            key: format!("job:{}", j.name()),
            title: title.into(),
            why: format!("{} ({ago}).", j.name()),
            action,
        });
    }
    let big = i.reclaim.is_some_and(|b| b >= RECLAIM_MIN);
    if big || !cleanup_due.is_empty() || (i.disk_tight && i.reclaim.is_some_and(|b| b > 0)) {
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
                (!cleanup_due.is_empty()).then(|| format!("Due: {}.", cleanup_due.join(", "))),
                space
                    .is_none()
                    .then(|| "c measures what can go.".to_string()),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" "),
            action: Action::Cleanup,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Finding;
    use crate::jobs::state::Run;

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
            jobs: None,
            reclaim: None,
            disk_tight: false,
            run: None,
            plans: p,
            snoozes: s,
        }
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
        let recs = recommend(&i);
        assert_eq!(recs[0].key, "reboot");
        assert_eq!(recs[0].level, Level::Now);
    }

    #[test]
    fn jobs_due_failed_and_cleanup() {
        let (cfg, b, s, p) = (
            Config::default(),
            Baseline::default(),
            Snoozes::new(),
            BTreeMap::new(),
        );
        let now: Timestamp = "2026-10-27T12:00:00Z".parse().unwrap();
        let mut rec = Records::default();
        // Everything ran yesterday, except the audit (never) and podman (failed).
        for j in JobId::ALL {
            rec.runs.insert(
                j.name().into(),
                Run {
                    at: now - jiff::SignedDuration::from_hours(24),
                    ok: j != JobId::CleanupPodman,
                    summary: "podman: not found".into(),
                },
            );
        }
        rec.runs.remove("audit");
        let mut i = base(&cfg, &b, &s, &p);
        i.jobs = Some(&rec);
        i.reclaim = Some(3 << 30);
        let recs = recommend(&i);
        let keys: Vec<&str> = recs.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(
            keys,
            ["job:cleanup-podman", "job:audit", "cleanup"],
            "{recs:#?}"
        );
        assert_eq!(recs[1].action, Action::Audit);
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

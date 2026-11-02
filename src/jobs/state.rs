//! What the jobs did, and when they're due. A run goes in the maintenance log (`kind = "job"`);
//! each job's cadence (`[jobs]` in config.toml, else its default) is a recurring task
//! (`tasks.toml` can replace it, `e` on its row writes that). Cadence is a reminder, never a
//! trigger. The old `jobs.json` and `cadence.toml` are read once and moved aside (`migrate`).

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::JobId;
use crate::config::{Config, Dur};
use crate::maint::Level;
use crate::maint::tasks::{Source, Task};
use crate::paths;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Run {
    pub at: Timestamp,
    pub ok: bool,
    pub summary: String,
}

pub type Runs = BTreeMap<String, Run>;

fn runs_path() -> std::path::PathBuf {
    paths::data_dir().join("jobs.json")
}

fn cadence_path() -> std::path::PathBuf {
    paths::config_dir().join("cadence.toml")
}

fn load() -> Runs {
    std::fs::read_to_string(runs_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// A job ran: it goes in the maintenance log (`kind = "job"`), which is what says a job task
/// is done. The checks (audit, update-check) change nothing, so only their latest run is kept.
pub fn record(job: JobId, ok: bool, summary: &str) -> anyhow::Result<()> {
    record_at(job, ok, summary, Timestamp::now(), &[])
}

fn record_at(
    job: JobId,
    ok: bool,
    summary: &str,
    at: Timestamp,
    extra: &[String],
) -> anyhow::Result<()> {
    use crate::maint::{LOCAL, log};
    if matches!(job, JobId::Audit | JobId::UpdateCheck) {
        log::remove_where(LOCAL, |e| {
            e.head.kind == "job" && e.head.workflow == job.name()
        })?;
    }
    log::write(&log::LogEntry::event(
        LOCAL,
        "job",
        job.name(),
        ok,
        summary,
        &std::iter::once(format!("job:{}", job.name()))
            .chain(extra.iter().cloned())
            .collect::<Vec<_>>(),
        at,
    ))?;
    Ok(())
}

/// The latest run of each job, from the log.
pub fn last_runs(log: &[crate::maint::log::LogEntry]) -> BTreeMap<&'static str, Run> {
    let mut out = BTreeMap::new();
    // Newest first: the first one seen is the latest.
    for e in log.iter().filter(|e| e.head.kind == "job") {
        let Some(j) = JobId::from_name(&e.head.workflow) else {
            continue;
        };
        out.entry(j.name()).or_insert_with(|| Run {
            at: e.head.ended.or(e.head.started).unwrap_or_default(),
            ok: e.head.result == "done",
            summary: e.head.summary.clone(),
        });
    }
    out
}

fn overrides() -> BTreeMap<String, String> {
    std::fs::read_to_string(cadence_path())
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

/// This machine's jobs as recurring tasks (`job-audit`, `job-update-check`, `job-cleanup`).
/// update-apply has none: updates go through `quick-update`.
pub fn tasks(cfg: &Config) -> Vec<Task> {
    tasks_with(cfg, &BTreeMap::new())
}

/// With cadence overrides (the old `cadence.toml`) on top of the config.
fn tasks_with(cfg: &Config, ov: &BTreeMap<String, String>) -> Vec<Task> {
    // A job's cadence and where it came from; None: no cadence at all.
    let every = |j: JobId| -> Option<(Option<Dur>, Source)> {
        let (s, src) = if let Some(s) = ov.get(j.name()) {
            (s.clone(), Source::File)
        } else if let Some(s) = cfg
            .jobs
            .get(j.name())
            .and_then(|c| c.suggested_every.clone())
        {
            (s, Source::Config)
        } else {
            (j.default_every()?.to_string(), Source::Default)
        };
        match s.trim() {
            "off" => Some((None, src)),
            d => d.parse().ok().map(|d| (Some(d), src)),
        }
    };
    let task = |id: &str, act: &str, title: &str, why: &str, e: (Option<Dur>, Source)| Task {
        id: id.into(),
        title: title.into(),
        why: why.into(),
        level: Level::Routine,
        every: e.0,
        act: act.into(),
        item: None,
        steps: String::new(),
        added: None,
        off: e.0.is_none(),
        source: e.1,
        review: None,
    };
    let mut out = Vec::new();
    if let Some(e) = every(JobId::Audit) {
        out.push(task(
            "job-audit",
            "audit",
            "Audit this machine",
            "Read-only: what changed since the last audit, and what to look at.",
            e,
        ));
    }
    if let Some(e) = every(JobId::UpdateCheck) {
        out.push(task(
            "job-update-check",
            "job update-check",
            "Check for updates",
            "The OS, Flatpaks and toolboxes: what's waiting (nothing is installed).",
            e,
        ));
    }
    // The cleanups are one task: the soonest cadence of those that have one.
    let cleanups: Vec<(Option<Dur>, Source)> =
        JobId::CLEANUP.into_iter().filter_map(every).collect();
    if !cleanups.is_empty() {
        let soonest = cleanups.iter().filter_map(|c| c.0).min_by_key(|d| d.0);
        let src = cleanups
            .iter()
            .map(|c| c.1)
            .find(|s| *s != Source::Default)
            .unwrap_or(Source::Default);
        out.push(task(
            "job-cleanup",
            "job cleanup",
            "Clean up",
            "Old deployments, unused Flatpak runtimes, podman leftovers, caches: see what can go.",
            (soonest, src),
        ));
    }
    out
}

/// Move the old records into the new ones, once: `jobs.json`'s last runs become log entries,
/// `cadence.toml`'s overrides become tasks in `tasks.toml`. Each file is then renamed
/// `*.migrated` (never deleted).
pub fn migrate(cfg: &Config) {
    let old_runs = runs_path();
    if old_runs.exists() {
        for (name, r) in load() {
            if let Some(j) = JobId::from_name(&name) {
                let _ = record_at(j, r.ok, &r.summary, r.at, &["migrated".into()]);
            }
        }
        let _ = std::fs::rename(&old_runs, old_runs.with_extension("json.migrated"));
    }
    let old_cadence = cadence_path();
    if old_cadence.exists() {
        let ov = overrides();
        let plain = tasks_with(cfg, &BTreeMap::new());
        for t in tasks_with(cfg, &ov) {
            let same = plain
                .iter()
                .any(|p| p.id == t.id && p.every == t.every && p.off == t.off);
            if !same {
                let _ = crate::maint::tasks::add(
                    crate::maint::LOCAL,
                    Task {
                        source: Source::File,
                        ..t
                    },
                );
            }
        }
        let _ = std::fs::rename(&old_cadence, old_cadence.with_extension("toml.migrated"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_cadences_are_tasks() {
        let (mut cfg, _) = Config::parse("[jobs]\naudit.suggested_every = \"7d\"\n").unwrap();
        cfg.jobs.remove("update-check");
        let t = tasks(&cfg);
        let ids: Vec<&str> = t.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, ["job-audit", "job-update-check", "job-cleanup"]);
        assert_eq!(t[0].every, Some(Dur::secs(7 * 86400)));
        assert_eq!(t[0].source, Source::Config);
        assert_eq!(t[1].source, Source::Default);
        // An override turns one off; the cleanups take the soonest cadence they have.
        let ov: BTreeMap<String, String> = [
            ("audit".to_string(), "off".to_string()),
            ("cleanup-ostree".to_string(), "14d".to_string()),
        ]
        .into();
        let t = tasks_with(&cfg, &ov);
        assert!(t[0].off);
        assert_eq!(t[2].every, Some(Dur::secs(14 * 86400)));
    }

    #[test]
    fn job_runs_go_in_the_log_and_checks_keep_only_their_latest() {
        use crate::maint::{LOCAL, log};
        let at = |d: i64| Timestamp::from_second(d * 86400).unwrap();
        record_at(JobId::Audit, true, "first", at(1), &[]).unwrap();
        record_at(JobId::Audit, true, "second", at(2), &[]).unwrap();
        record_at(JobId::CleanupOstree, true, "freed 1 GB", at(3), &[]).unwrap();
        record_at(JobId::CleanupOstree, false, "it failed", at(4), &[]).unwrap();
        let entries = log::list(LOCAL);
        let audits = entries
            .iter()
            .filter(|e| e.head.kind == "job" && e.head.workflow == "audit")
            .count();
        assert_eq!(audits, 1);
        let last = last_runs(&entries);
        assert_eq!(last["audit"].summary, "second");
        assert!(!last["cleanup-ostree"].ok, "the latest run counts");
    }

    #[test]
    fn the_old_files_move_into_the_log_and_tasks_once() {
        use crate::maint::{LOCAL, log, tasks};
        std::fs::create_dir_all(paths::data_dir()).unwrap();
        std::fs::create_dir_all(paths::config_dir()).unwrap();
        std::fs::write(
            runs_path(),
            r#"{"cleanup-flatpak": {"at": "2026-09-01T00:00:00Z", "ok": true, "summary": "freed 2 GB"}}"#,
        )
        .unwrap();
        std::fs::write(cadence_path(), "audit = \"off\"\n").unwrap();
        migrate(&Config::default());
        assert!(!runs_path().exists() && runs_path().with_extension("json.migrated").exists());
        assert!(!cadence_path().exists());
        let e = log::list(LOCAL)
            .into_iter()
            .find(|e| e.head.workflow == "cleanup-flatpak")
            .expect("in the log");
        assert!(
            e.head.tags.contains(&"migrated".to_string()),
            "{:?}",
            e.head.tags
        );
        let t = tasks::load(LOCAL);
        assert!(t.iter().any(|t| t.id == "job-audit" && t.off), "{t:?}");
        // Again: nothing left to move.
        migrate(&Config::default());
        assert_eq!(
            log::list(LOCAL)
                .iter()
                .filter(|e| e.head.workflow == "cleanup-flatpak")
                .count(),
            1
        );
    }
}

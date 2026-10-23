//! Last-run records (`~/.local/share/sentry/jobs.json`, written by the job process) and cadence:
//! config `[jobs]` overridden by `~/.config/sentry/cadence.toml` (machine-written by the TUI `e`).
//! Cadence is a reminder, never a trigger.
#![allow(dead_code)] // cadence is wired into the Jobs screen in milestone 4

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::JobId;
use crate::config::{Config, Dur};
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

pub fn load() -> Runs {
    std::fs::read_to_string(runs_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn record(job: JobId, ok: bool, summary: &str) -> anyhow::Result<()> {
    let mut r = load();
    r.insert(
        job.name().into(),
        Run {
            at: Timestamp::now(),
            ok,
            summary: summary.lines().next().unwrap_or("").chars().take(200).collect(),
        },
    );
    paths::write_atomic(&runs_path(), &serde_json::to_vec_pretty(&r)?)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Every {
    /// No cadence applies (update-apply).
    Never,
    Off,
    Interval(Dur),
}

impl Every {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim() {
            "off" => Ok(Every::Off),
            "—" | "-" | "" => Ok(Every::Never),
            d => d.parse().map(Every::Interval),
        }
    }

    pub fn label(self) -> String {
        match self {
            Every::Never => "—".into(),
            Every::Off => "off".into(),
            Every::Interval(d) => d.to_string(),
        }
    }
}

fn overrides() -> BTreeMap<String, String> {
    std::fs::read_to_string(cadence_path())
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

/// Effective cadence: cadence.toml > config `[jobs]` > spec default.
pub fn every(job: JobId, cfg: &Config) -> Every {
    every_with(job, cfg, &overrides())
}

pub fn every_with(job: JobId, cfg: &Config, ov: &BTreeMap<String, String>) -> Every {
    let s = ov
        .get(job.name())
        .cloned()
        .or_else(|| cfg.jobs.get(job.name()).and_then(|j| j.suggested_every.clone()))
        .or_else(|| job.default_every().map(str::to_string));
    match s {
        None => Every::Never,
        Some(s) => Every::parse(&s).unwrap_or(Every::Never),
    }
}

/// Persist a cadence override from the TUI.
pub fn set_every(job: JobId, e: Every) -> anyhow::Result<()> {
    let mut ov = overrides();
    ov.insert(job.name().into(), e.label());
    let body = format!(
        "# Written by sentry (Jobs screen, `e`). Overrides [jobs] in config.toml. Safe to edit.\n{}",
        toml::to_string(&ov)?
    );
    paths::write_atomic(&cadence_path(), body.as_bytes())?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub enum Due {
    /// No cadence or disabled.
    NotTracked,
    Never,
    /// Seconds until due (negative = overdue).
    In(i64),
}

pub fn due(job: JobId, e: Every, runs: &Runs, now: Timestamp) -> Due {
    let Every::Interval(d) = e else {
        return Due::NotTracked;
    };
    match runs.get(job.name()) {
        None => Due::Never,
        Some(r) => Due::In(r.at.as_second() + d.0.as_secs() as i64 - now.as_second()),
    }
}

impl Due {
    pub fn is_due(&self) -> bool {
        match self {
            Due::Never => true,
            Due::In(s) => *s <= 0,
            Due::NotTracked => false,
        }
    }
}

/// Names of jobs that are due now (dashboard, `sentry status`).
pub fn due_jobs(cfg: &Config, runs: &Runs, now: Timestamp) -> Vec<JobId> {
    let ov = overrides();
    JobId::ALL
        .into_iter()
        .filter(|j| due(*j, every_with(*j, cfg, &ov), runs, now).is_due())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cadence_precedence_and_due() {
        let (mut cfg, _) = Config::parse("[jobs]\naudit.suggested_every = \"7d\"\n").unwrap();
        let mut ov = BTreeMap::new();
        assert_eq!(every_with(JobId::Audit, &cfg, &ov), Every::Interval(Dur::secs(7 * 86400)));
        ov.insert("audit".into(), "off".into());
        assert_eq!(every_with(JobId::Audit, &cfg, &ov), Every::Off);
        assert_eq!(every_with(JobId::UpdateApply, &cfg, &ov), Every::Never);
        assert_eq!(every_with(JobId::CleanupCache, &cfg, &ov), Every::Off);
        cfg.jobs.clear();
        let e = every_with(JobId::CleanupOstree, &cfg, &ov);
        let now = Timestamp::from_second(100 * 86400).unwrap();
        let mut runs = Runs::new();
        assert_eq!(due(JobId::CleanupOstree, e, &runs, now), Due::Never);
        runs.insert(
            "cleanup-ostree".into(),
            Run {
                at: Timestamp::from_second(60 * 86400).unwrap(),
                ok: true,
                summary: String::new(),
            },
        );
        assert_eq!(
            due(JobId::CleanupOstree, e, &runs, now),
            Due::In(-10 * 86400)
        );
        assert!(due(JobId::CleanupOstree, e, &runs, now).is_due());
    }
}

//! `sentry status`: one line from state files only. Never runs collectors.

use crate::{
    audit, baseline::Baseline, cache, collectors::flatpak::FpUpdate, config::Config, fmt, jobs,
    resume,
};

pub fn line(short: bool) -> String {
    let now = jiff::Timestamp::now();
    let (cfg, _) = Config::load();
    let wf = resume::in_progress().map(|r| r.summary());
    let due = jobs::state::due_jobs(&cfg, &jobs::state::load(), now);
    let high = audit::store::latest().map(|r| r.counts(&Baseline::effective(&cfg)).high);
    if short {
        // Empty when there's nothing to say, so a shell prompt stays clean.
        let mut parts = Vec::new();
        if let Some(w) = &wf {
            parts.push(format!("⟳ {w}"));
        }
        if !due.is_empty() {
            parts.push(format!("{} job(s) due", due.len()));
        }
        if let Some(h) = high.filter(|h| *h > 0) {
            parts.push(format!("{h} high finding(s)"));
        }
        return parts.join(" · ");
    }
    let fp = cache::load::<Vec<FpUpdate>>(cache::FLATPAK_UPDATES).map(|c| c.data.len());
    let checked =
        cache::load::<serde_json::Value>(cache::OSTREE_CHECK).map(|c| fmt::ago(c.age_secs(now)));
    let names: Vec<&str> = due.iter().map(|j| j.name()).collect();
    format!(
        "workflow: {} · jobs due: {} · high findings: {} · flatpak updates: {} · last update check: {}",
        wf.unwrap_or_else(|| "none".into()),
        if names.is_empty() {
            "none".into()
        } else {
            names.join(", ")
        },
        high.map_or("no audit yet".into(), |h| h.to_string()),
        fp.map_or("unknown".into(), |n| n.to_string()),
        checked.unwrap_or_else(|| "never".into()),
    )
}

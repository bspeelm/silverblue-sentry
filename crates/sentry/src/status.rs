//! `sentry status`: one line from state files only. Never runs collectors.

use crate::{
    audit, baseline::Baseline, cache, collectors::flatpak::FpUpdate, config::Config, fmt, jobs,
    resume,
};

pub fn line(short: bool) -> String {
    let now = jiff::Timestamp::now();
    let (cfg, _) = Config::load();
    let wf = resume::in_progress().map(|r| r.summary());
    jobs::state::migrate(&cfg);
    let latest = audit::store::latest();
    let tasks = crate::maint::tasks::effective(
        &crate::maint::tasks::load(crate::maint::LOCAL),
        jobs::state::tasks(&cfg),
    );
    let log = crate::maint::log::list(crate::maint::LOCAL);
    let due: Vec<&str> =
        crate::maint::tasks::recs(&tasks, &log, latest.as_ref().map(|r| r.taken_at), now)
            .into_iter()
            .filter_map(|r| tasks.iter().find(|t| t.id == r.id))
            .map(|t| t.title.as_str())
            .collect();
    let high = latest.map(|r| r.counts(&Baseline::effective(&cfg)).high);
    if short {
        // Empty when there's nothing to say, so a shell prompt stays clean.
        let mut parts = Vec::new();
        if let Some(w) = &wf {
            parts.push(format!("⟳ {w}"));
        }
        if !due.is_empty() {
            parts.push(format!("{} task(s) due", due.len()));
        }
        if let Some(h) = high.filter(|h| *h > 0) {
            parts.push(format!("{h} audit finding(s) to check"));
        }
        return parts.join(" · ");
    }
    let fp = cache::load::<Vec<FpUpdate>>(cache::FLATPAK_UPDATES).map(|c| c.data.len());
    let checked =
        cache::load::<serde_json::Value>(cache::OSTREE_CHECK).map(|c| fmt::ago(c.age_secs(now)));
    let names = &due;
    format!(
        "workflow: {} · tasks due: {} · audit findings to check: {} · flatpak updates: {} · last update check: {}",
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

#[cfg(test)]
mod tests {
    #[test]
    fn due_tasks_are_counted() {
        // The scratch dirs have never seen an update check: that task is due.
        let short = super::line(true);
        assert!(short.contains("task(s) due"), "{short}");
        let long = super::line(false);
        assert!(
            long.contains("tasks due: ") && long.contains("Check for updates"),
            "{long}"
        );
    }
}

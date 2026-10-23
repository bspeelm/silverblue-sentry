//! `sentry status`: one line from state files only. Never runs collectors.

use crate::{cache, collectors::flatpak::FpUpdate, fmt, resume};

pub fn line(short: bool) -> String {
    let wf = resume::in_progress().map(|r| r.summary());
    let fp = cache::load::<Vec<FpUpdate>>(cache::FLATPAK_UPDATES).map(|c| c.data.len());
    let checked = cache::load::<serde_json::Value>(cache::OSTREE_CHECK)
        .map(|c| fmt::ago(c.age_secs(jiff::Timestamp::now())));
    if short {
        return match wf {
            Some(w) => format!("⟳ {w}"),
            None => String::new(),
        };
    }
    format!(
        "workflow: {} · flatpak updates: {} · last update check: {} · jobs: n/a until milestone 4",
        wf.unwrap_or_else(|| "none".into()),
        fp.map_or("unknown".into(), |n| n.to_string()),
        checked.unwrap_or_else(|| "never".into()),
    )
}

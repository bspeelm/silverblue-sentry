//! Recommendations put off with `z`: key → the day to show it again. This machine's are in
//! `~/.config/sentry/maint.toml` (sentry-server keeps its own in `servers/<name>.maint.toml`).

use std::collections::BTreeMap;
use std::path::PathBuf;

use jiff::civil::Date;
use serde::{Deserialize, Serialize};

use crate::paths;

pub type Snoozes = BTreeMap<String, Date>;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct File {
    snooze: Snoozes,
}

fn path() -> PathBuf {
    paths::config_dir().join("maint.toml")
}

pub fn load() -> Snoozes {
    std::fs::read_to_string(path())
        .ok()
        .and_then(|t| toml::from_str::<File>(&t).ok())
        .map(|f| f.snooze)
        .unwrap_or_default()
}

/// Put `key` off until `until` (past dates are dropped while at it).
pub fn set(key: &str, until: Date, today: Date) -> anyhow::Result<()> {
    let mut snooze = load();
    snooze.retain(|_, d| *d > today);
    snooze.insert(key.to_string(), until);
    let text = format!(
        "# Recommendations put off with z on Maintenance (sentry). Edit freely.\n{}",
        toml::to_string(&File { snooze })?
    );
    let p = path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    paths::write_atomic(&p, text.as_bytes())?;
    Ok(())
}

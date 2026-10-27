//! Deliberate maintenance: what's pinned or held on purpose (`maintenance:` in
//! server_config.yaml), what's newer upstream, and when to look again. Nothing here changes
//! the server: changes go through a workflow, one item at a time.

pub mod eval;
pub mod local;
pub mod upstream;
pub mod version;

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::paths;

/// What sentry-server writes itself, next to the config (never in it): review dates moved
/// with `z`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub snooze: BTreeMap<String, jiff::civil::Date>,
}

fn state_path(server: &str) -> PathBuf {
    paths::config_dir()
        .join("servers")
        .join(format!("{server}.maint.toml"))
}

pub fn load_state(server: &str) -> State {
    std::fs::read_to_string(state_path(server))
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

/// Move an item's review date (`z`).
pub fn snooze(server: &str, id: &str, until: jiff::civil::Date) -> anyhow::Result<()> {
    let mut st = load_state(server);
    st.snooze.insert(id.to_string(), until);
    let text = format!(
        "# Review dates moved in sentry-server (z on the Maintenance tab). Edit freely.\n{}",
        toml::to_string(&st)?
    );
    paths::write_atomic(&state_path(server), text.as_bytes())?;
    Ok(())
}

/// One change made through a workflow started from an item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub at: jiff::Timestamp,
    pub item: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub workflow: String,
    /// `done`, `abandoned`, `failed`.
    pub result: String,
}

fn log_path(server: &str) -> PathBuf {
    paths::data_dir()
        .join("servers")
        .join(server)
        .join("maintenance.jsonl")
}

pub fn log_change(server: &str, c: &Change) -> anyhow::Result<()> {
    use std::io::Write;
    let p = log_path(server);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)?;
    writeln!(f, "{}", serde_json::to_string(c)?)?;
    Ok(())
}

/// An item's changes, newest first.
pub fn history(server: &str, item: &str) -> Vec<Change> {
    let mut v: Vec<Change> = std::fs::read_to_string(log_path(server))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Change>(l).ok())
        .filter(|c| c.item == item)
        .collect();
    v.reverse();
    v
}

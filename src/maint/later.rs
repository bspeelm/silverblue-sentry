//! What's put off with `z`: key → the day it shows again, in `later.toml` beside the other
//! records (this machine: `~/.config/sentry/later.toml`; a server:
//! `servers/<name>/later.toml`). On a server an item's key is also its review date. The old
//! files (`maint.toml`, `servers/<name>.maint.toml`) are read once and moved aside.

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

fn path(server: &str) -> PathBuf {
    super::root(server).join("later.toml")
}

/// Where they were before.
fn old_path(server: &str) -> PathBuf {
    if server.is_empty() {
        paths::config_dir().join("maint.toml")
    } else {
        paths::config_dir()
            .join("servers")
            .join(format!("{server}.maint.toml"))
    }
}

fn read(p: &std::path::Path) -> Snoozes {
    std::fs::read_to_string(p)
        .ok()
        .and_then(|t| toml::from_str::<File>(&t).ok())
        .map(|f| f.snooze)
        .unwrap_or_default()
}

pub fn load(server: &str) -> Snoozes {
    migrate(server);
    read(&path(server))
}

fn save(server: &str, snooze: &Snoozes) -> anyhow::Result<()> {
    let text = format!(
        "# Put off with z on Maintenance until a date (on a server, an item's is its review\n\
         # date). Records › Later lists them; u brings one back. Edit freely.\n{}",
        toml::to_string(&File {
            snooze: snooze.clone(),
        })?
    );
    let p = path(server);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    paths::write_atomic(&p, text.as_bytes())?;
    Ok(())
}

/// Put `key` off until `until` (dates that have passed are dropped while at it).
pub fn set(server: &str, key: &str, until: Date, today: Date) -> anyhow::Result<()> {
    let mut s = load(server);
    s.retain(|_, d| *d > today);
    s.insert(key.to_string(), until);
    save(server, &s)
}

/// Bring it back now.
pub fn remove(server: &str, key: &str) -> anyhow::Result<()> {
    let mut s = load(server);
    s.remove(key);
    save(server, &s)
}

/// The old file's dates move here, once. A server's old file is moved aside only when it
/// has no plans left in it (those become plan files first).
fn migrate(server: &str) {
    let old = old_path(server);
    if path(server).exists() || !old.exists() {
        return;
    }
    let snooze = read(&old);
    if save(server, &snooze).is_err() {
        return;
    }
    let plans_left = std::fs::read_to_string(&old)
        .ok()
        .and_then(|t| t.parse::<toml::Table>().ok())
        .and_then(|t| {
            t.get("plans")
                .and_then(|p| p.as_table())
                .map(|p| !p.is_empty())
        })
        .unwrap_or(false);
    if !plans_left {
        let _ = std::fs::rename(&old, old.with_extension("toml.migrated"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_off_brought_back_and_moved_from_the_old_file() {
        let d = |s: &str| s.parse::<Date>().unwrap();
        // A server's old file, plans already gone: its dates move, the file goes aside.
        let old = old_path("later-test");
        std::fs::create_dir_all(old.parent().unwrap()).unwrap();
        std::fs::write(&old, "[snooze]\nweb = \"2027-01-01\"\n").unwrap();
        assert_eq!(load("later-test")["web"], d("2027-01-01"));
        assert!(!old.exists());
        set("later-test", "updates", d("2026-12-01"), d("2026-11-02")).unwrap();
        remove("later-test", "web").unwrap();
        let s = load("later-test");
        assert_eq!(s.len(), 1);
        assert_eq!(s["updates"], d("2026-12-01"));
    }
}

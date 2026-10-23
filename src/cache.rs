//! On-disk cache of slow/network collector results (`~/.cache/sentry/<key>.json`).
//! Nothing here refreshes on its own; callers decide when to `store`.

use jiff::Timestamp;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::paths;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cached<T> {
    pub fetched_at: Timestamp,
    pub data: T,
}

impl<T> Cached<T> {
    pub fn age_secs(&self, now: Timestamp) -> i64 {
        (now.as_second() - self.fetched_at.as_second()).max(0)
    }
}

fn path(key: &str) -> std::path::PathBuf {
    paths::cache_dir().join(format!("{key}.json"))
}

pub fn load<T: DeserializeOwned>(key: &str) -> Option<Cached<T>> {
    let text = std::fs::read_to_string(path(key)).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn store<T: Serialize>(key: &str, data: &T) -> anyhow::Result<Timestamp> {
    let now = Timestamp::now();
    let c = Cached {
        fetched_at: now,
        data,
    };
    paths::write_atomic(&path(key), &serde_json::to_vec(&c)?)?;
    Ok(now)
}

pub const OSTREE_CHECK: &str = "ostree-check";
pub const FLATPAK_UPDATES: &str = "flatpak-updates";
pub const DISK_BREAKDOWN: &str = "disk-breakdown";

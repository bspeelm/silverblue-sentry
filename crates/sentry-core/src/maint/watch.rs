//! What sentry stopped watching: `watch.toml` beside a target's records. A target's config
//! lists what must be there (a server's timers and services, a network's forwards); the
//! user writes that file and sentry never rewrites it. When one of those things is retired
//! on purpose, the expectation itself is what's out of date, and this file is where sentry
//! says so: an entry here is applied over the config wherever it is read (the collectors'
//! expectations, the audit), so the thing is no longer looked for.
//!
//! This is not `baseline.toml`: marking a finding expected hides that one finding and
//! leaves the thing watched; an entry here removes the expectation. Records › Later lists
//! them, and `u` there watches the thing again.

use std::path::PathBuf;

use jiff::civil::Date;
use serde::{Deserialize, Serialize};

/// One thing no longer watched.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Unwatched {
    /// What kind of thing, in the target's own words (`timer`, `service`, `forward`).
    pub kind: String,
    /// Its name as the config has it.
    pub name: String,
    pub since: Date,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub why: String,
}

impl Unwatched {
    /// `timer:backup.timer`: what a plan's `unwatch` step and Records name it by.
    pub fn key(&self) -> String {
        key(&self.kind, &self.name)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Watch {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unwatched: Vec<Unwatched>,
}

pub fn key(kind: &str, name: &str) -> String {
    format!("{kind}:{name}")
}

/// A key's kind and name (`timer:backup.timer`; the name may hold colons).
pub fn split(key: &str) -> Option<(&str, &str)> {
    let (kind, name) = key.split_once(':')?;
    (!kind.is_empty() && !name.trim().is_empty()).then_some((kind, name))
}

impl Watch {
    pub fn has(&self, kind: &str, name: &str) -> bool {
        self.unwatched
            .iter()
            .any(|u| u.kind == kind && u.name == name)
    }

    /// Every name of this kind.
    pub fn names<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a str> {
        self.unwatched
            .iter()
            .filter(move |u| u.kind == kind)
            .map(|u| u.name.as_str())
    }

    /// Stop watching it. False: it already wasn't.
    pub fn add(&mut self, kind: &str, name: &str, since: Date, why: &str) -> bool {
        if self.has(kind, name) {
            return false;
        }
        self.unwatched.push(Unwatched {
            kind: kind.to_string(),
            name: name.to_string(),
            since,
            why: why.trim().to_string(),
        });
        true
    }

    /// Watch it again. False: it wasn't in the file.
    pub fn remove(&mut self, key: &str) -> bool {
        let n = self.unwatched.len();
        self.unwatched.retain(|u| u.key() != key);
        self.unwatched.len() != n
    }
}

pub fn path(scope: &str) -> PathBuf {
    super::root(scope).join("watch.toml")
}

pub fn load(scope: &str) -> Watch {
    std::fs::read_to_string(path(scope))
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save(scope: &str, w: &Watch) -> anyhow::Result<()> {
    let p = path(scope);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let text = format!(
        "# What sentry no longer watches here, though the config still lists it: things\n\
         # retired on purpose. Applied over the config, which is never rewritten. Records\n\
         # (v) › Later lists these; u there watches one again. Edit freely.\n\n{}",
        toml::to_string(w)?
    );
    crate::paths::write_atomic(&p, text.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_added_once_and_taken_back_by_its_key() {
        let d: Date = "2026-11-21".parse().unwrap();
        let mut w = Watch::default();
        assert!(w.add("timer", "backup.timer", d, " retired; the new job runs "));
        assert!(!w.add("timer", "backup.timer", d, "again"));
        assert!(w.has("timer", "backup.timer") && !w.has("service", "backup.timer"));
        assert_eq!(w.unwatched[0].key(), "timer:backup.timer");
        assert_eq!(w.unwatched[0].why, "retired; the new job runs");
        assert_eq!(w.names("timer").collect::<Vec<_>>(), ["backup.timer"]);
        // The file reads back as written.
        let text = toml::to_string(&w).unwrap();
        assert_eq!(toml::from_str::<Watch>(&text).unwrap(), w);
        assert!(!w.remove("timer:other.timer"));
        assert!(w.remove("timer:backup.timer"));
        assert_eq!(w, Watch::default());
    }

    /// On disk (a scratch scope of this test's own): written with its header, read back
    /// the same, and an empty or missing file is nothing unwatched.
    #[test]
    fn the_file_reads_back_as_written() {
        let scope = "watch-file-test";
        let _ = std::fs::remove_file(path(scope));
        assert_eq!(load(scope), Watch::default());
        let mut w = Watch::default();
        w.add(
            "timer",
            "report.timer",
            "2026-11-21".parse().unwrap(),
            "retired; v2 runs",
        );
        save(scope, &w).unwrap();
        let text = std::fs::read_to_string(path(scope)).unwrap();
        assert!(
            text.starts_with("# What sentry no longer watches here"),
            "{text}"
        );
        assert!(
            text.contains("[[unwatched]]")
                && text.contains("kind = \"timer\"")
                && text.contains("name = \"report.timer\"")
                && text.contains("since = \"2026-11-21\"")
                && text.contains("why = \"retired; v2 runs\""),
            "{text}"
        );
        assert_eq!(load(scope), w);
        assert!(path(scope).ends_with("servers/watch-file-test/watch.toml"));
        let _ = std::fs::remove_file(path(scope));
    }

    #[test]
    fn a_key_is_a_kind_and_a_name() {
        assert_eq!(split("timer:backup.timer"), Some(("timer", "backup.timer")));
        assert_eq!(split("disk:/srv/data"), Some(("disk", "/srv/data")));
        assert_eq!(
            split("smart:/dev/disk/by-id/a:b"),
            Some(("smart", "/dev/disk/by-id/a:b"))
        );
        assert_eq!(split("timer:"), None);
        assert_eq!(split("backup.timer"), None);
    }
}

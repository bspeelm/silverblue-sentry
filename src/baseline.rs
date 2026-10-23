//! Effective baseline = config `[baseline]` (user-authored) ∪ `~/.config/sentry/baseline.toml`
//! (machine-written from the TUI). See spec-addendum A6.

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::paths;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BaselineFile {
    pub listeners: Vec<String>,
    pub findings: Vec<String>,
}

fn path() -> std::path::PathBuf {
    paths::config_dir().join("baseline.toml")
}

impl BaselineFile {
    pub fn load() -> Self {
        std::fs::read_to_string(path())
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn save(&self) -> anyhow::Result<()> {
        let body = format!(
            "# Written by sentry when you mark things as expected. Safe to edit.\n{}",
            toml::to_string_pretty(self)?
        );
        paths::write_atomic(&path(), body.as_bytes())?;
        Ok(())
    }

    /// Append a listener key; returns false if it was already present.
    pub fn add_listener(key: &str) -> anyhow::Result<bool> {
        let mut b = Self::load();
        if b.listeners.iter().any(|l| l == key) {
            return Ok(false);
        }
        b.listeners.push(key.to_string());
        b.save()?;
        Ok(true)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Baseline {
    pub listeners: Vec<String>,
}

impl Baseline {
    pub fn effective(cfg: &Config) -> Self {
        let mut listeners = cfg.baseline.listeners.clone();
        for l in BaselineFile::load().listeners {
            if !listeners.contains(&l) {
                listeners.push(l);
            }
        }
        Self { listeners }
    }

    /// `key` is `addr:port/process`. Root-owned sockets have no visible process (`/?`); those
    /// match on the `addr:port` part alone so `127.0.0.1:631/cupsd` still covers cupsd.
    pub fn has_listener(&self, key: &str) -> bool {
        let addr_only = key.strip_suffix("/?");
        self.listeners.iter().any(|p| {
            glob(p, key)
                || addr_only
                    .is_some_and(|a| glob(p.rsplit_once('/').map_or(p.as_str(), |(pa, _)| pa), a))
        })
    }
}

/// `*` matches any run of characters (including none). Everything else is literal.
pub fn glob(pattern: &str, s: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == s;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !s.starts_with(first)
        || !s[first.len()..].ends_with(last)
        || s.len() < first.len() + last.len()
    {
        return false;
    }
    let mut rest = &s[first.len()..s.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{Baseline, glob};

    #[test]
    fn unknown_process_matches_addr() {
        let b = Baseline {
            listeners: vec!["127.0.0.1:631/cupsd".into()],
        };
        assert!(b.has_listener("127.0.0.1:631/?"));
        assert!(b.has_listener("127.0.0.1:631/cupsd"));
        assert!(!b.has_listener("127.0.0.1:631/evil"));
    }

    #[test]
    fn globbing() {
        assert!(glob("127.0.0.1:631/cupsd", "127.0.0.1:631/cupsd"));
        assert!(glob(
            "127.0.0.1:*/rust-analyzer",
            "127.0.0.1:44917/rust-analyzer"
        ));
        assert!(!glob(
            "127.0.0.1:*/rust-analyzer",
            "0.0.0.0:44917/rust-analyzer"
        ));
        assert!(glob("*:22000/syncthing", "[::]:22000/syncthing"));
        assert!(glob("a*b*c", "aXXbYYc"));
        assert!(!glob("a*b*c", "aXXc"));
        assert!(!glob("ab*ba", "aba"));
    }
}

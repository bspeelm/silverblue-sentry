//! Effective baseline = config `[baseline]` (user-authored) ∪ `~/.config/sentry/baseline.toml`
//! (machine-written from the TUI). See spec-addendum A6. A server's file is
//! `servers/<name>/baseline.toml`, beside its other records ([`crate::maint::root`]).

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::paths;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BaselineFile {
    pub listeners: Vec<String>,
    pub findings: Vec<String>,
}

/// Where it's kept: this machine's (`""`) in the config dir, a server's under its records.
pub fn path(server: &str) -> std::path::PathBuf {
    crate::maint::root(server).join("baseline.toml")
}

/// Where a server's file was before.
fn old_path(server: &str) -> Option<std::path::PathBuf> {
    crate::maint::beside(server, ".baseline.toml")
}

impl BaselineFile {
    /// A server's file used to be `servers/<name>.baseline.toml` (findings only): it's moved
    /// in the first time, so what was marked expected stays so.
    pub fn load(server: &str) -> Self {
        if let Some(old) = old_path(server)
            && !path(server).exists()
            && old.exists()
        {
            if let Some(d) = path(server).parent() {
                let _ = std::fs::create_dir_all(d);
            }
            let _ = std::fs::rename(&old, path(server));
        }
        std::fs::read_to_string(path(server))
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, server: &str) -> anyhow::Result<()> {
        let body = format!(
            "# Written by sentry when you mark things as expected. Safe to edit.\n{}",
            toml::to_string_pretty(self)?
        );
        let p = path(server);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        paths::write_atomic(&p, body.as_bytes())?;
        Ok(())
    }

    /// Append a finding id; returns false if it was already present.
    pub fn add_finding(server: &str, id: &str) -> anyhow::Result<bool> {
        let mut b = Self::load(server);
        if b.findings.iter().any(|f| f == id) {
            return Ok(false);
        }
        b.findings.push(id.to_string());
        b.save(server)?;
        Ok(true)
    }

    /// Drop every listener entry that covers one of `keys` (exact or glob); how many went.
    pub fn drop_listeners(&mut self, keys: &[String]) -> usize {
        let before = self.listeners.len();
        self.listeners
            .retain(|p| !keys.iter().any(|k| listener_entry_matches(p, k)));
        before - self.listeners.len()
    }

    fn drop_finding(&mut self, id: &str) -> usize {
        let before = self.findings.len();
        self.findings.retain(|p| !glob(p, id));
        before - self.findings.len()
    }

    /// Remove every listener entry that covers one of `keys` (exact or glob). Returns how many.
    pub fn remove_listeners(server: &str, keys: &[String]) -> anyhow::Result<usize> {
        let mut b = Self::load(server);
        let n = b.drop_listeners(keys);
        if n > 0 {
            b.save(server)?;
        }
        Ok(n)
    }

    /// Remove every finding entry that covers `id` (exact or glob). Returns how many.
    pub fn remove_finding(server: &str, id: &str) -> anyhow::Result<usize> {
        let mut b = Self::load(server);
        let n = b.drop_finding(id);
        if n > 0 {
            b.save(server)?;
        }
        Ok(n)
    }

    /// Append a listener key; returns false if it was already present.
    pub fn add_listener(server: &str, key: &str) -> anyhow::Result<bool> {
        let mut b = Self::load(server);
        if b.listeners.iter().any(|l| l == key) {
            return Ok(false);
        }
        b.listeners.push(key.to_string());
        b.save(server)?;
        Ok(true)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Baseline {
    pub listeners: Vec<String>,
    /// Finding ids (globs allowed), see `audit::findings`.
    pub findings: Vec<String>,
}

impl Baseline {
    pub fn effective(cfg: &Config) -> Self {
        let file = BaselineFile::load(crate::maint::LOCAL);
        let union = |a: &[String], b: Vec<String>| {
            let mut v = a.to_vec();
            for x in b {
                if !v.contains(&x) {
                    v.push(x);
                }
            }
            v
        };
        Self {
            listeners: union(&cfg.baseline.listeners, file.listeners),
            findings: union(&cfg.baseline.findings, file.findings),
        }
    }

    /// `key` is `addr:port/process`. Root-owned sockets have no visible process (`/?`); those
    /// match on the `addr:port` part alone so `127.0.0.1:631/cupsd` still covers cupsd.
    pub fn has_listener(&self, key: &str) -> bool {
        self.listeners
            .iter()
            .any(|p| listener_entry_matches(p, key))
    }
}

/// Whether baseline entry `p` covers listener `key`. Root-owned sockets have no visible
/// process (`/?`), so those match on the `addr:port` part alone.
pub fn listener_entry_matches(p: &str, key: &str) -> bool {
    glob(p, key)
        || key
            .strip_suffix("/?")
            .is_some_and(|a| glob(p.rsplit_once('/').map_or(p, |(pa, _)| pa), a))
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
    use super::{Baseline, BaselineFile, glob};

    #[test]
    fn unmarking_removes_what_covers_it() {
        let mut f = BaselineFile {
            listeners: vec![
                "0.0.0.0:27500/?".into(),
                "*:5353/avahi-daemon".into(),
                "127.0.0.1:631/cupsd".into(),
            ],
            findings: vec!["repo:_copr_x.repo".into(), "unit-failed:system:*".into()],
        };
        assert_eq!(f.drop_listeners(&["0.0.0.0:27500/?".into()]), 1);
        // A root-owned socket (`/?`) is covered by an entry naming its process.
        assert_eq!(f.drop_listeners(&["[::]:5353/?".into()]), 1);
        assert_eq!(f.listeners, vec!["127.0.0.1:631/cupsd"]);
        assert_eq!(
            f.drop_finding("unit-failed:system:foo.service"),
            1,
            "glob entries count"
        );
        assert_eq!(f.drop_finding("repo:other.repo"), 0);
        assert_eq!(f.findings, vec!["repo:_copr_x.repo"]);
    }

    #[test]
    fn server_file_lives_under_its_root_and_migrates() {
        use crate::paths::config_dir;
        let name = "baseline-migrate-test";
        let old = super::old_path(name).unwrap();
        std::fs::create_dir_all(old.parent().unwrap()).unwrap();
        std::fs::write(&old, "findings = [\"srv:docker-sock:*\"]\n").unwrap();
        let b = BaselineFile::load(name);
        assert_eq!(b.findings, ["srv:docker-sock:*"]);
        assert!(b.listeners.is_empty());
        assert!(!old.exists(), "moved, not copied");
        assert!(
            config_dir()
                .join("servers")
                .join(name)
                .join("baseline.toml")
                .exists()
        );
        // Listeners are kept in the same file from now on.
        assert!(BaselineFile::add_listener(name, "*:443/*").unwrap());
        let b = BaselineFile::load(name);
        assert_eq!((b.listeners.len(), b.findings.len()), (1, 1));
    }

    #[test]
    fn this_machine_s_file_stays_put_and_a_server_s_is_under_its_records() {
        use crate::paths::config_dir;
        assert_eq!(super::path(""), config_dir().join("baseline.toml"));
        assert_eq!(
            super::path("myserver"),
            config_dir().join("servers/myserver/baseline.toml")
        );
        // Each has its own entries.
        assert!(BaselineFile::add_listener("base-test", "*:443/*").unwrap());
        assert!(!BaselineFile::add_listener("base-test", "*:443/*").unwrap());
        assert!(BaselineFile::add_finding("base-test", "srv:listener:tcp:443").unwrap());
        let f = BaselineFile::load("base-test");
        assert_eq!(f.listeners, ["*:443/*"]);
        assert_eq!(f.findings, ["srv:listener:tcp:443"]);
        assert!(BaselineFile::load("other-test").listeners.is_empty());
        assert_eq!(
            BaselineFile::remove_listeners("base-test", &["0.0.0.0:443/nginx".into()]).unwrap(),
            1
        );
        assert_eq!(
            BaselineFile::remove_finding("base-test", "srv:listener:tcp:443").unwrap(),
            1
        );
        assert!(BaselineFile::load("base-test").listeners.is_empty());
    }

    #[test]
    fn unknown_process_matches_addr() {
        let b = Baseline {
            listeners: vec!["127.0.0.1:631/cupsd".into()],
            findings: vec![],
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

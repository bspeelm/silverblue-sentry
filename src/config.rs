//! `~/.config/sentry/config.toml` (spec §12). Sentry never writes this file.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::paths;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub ui: Ui,
    pub cache: CacheCfg,
    pub audit: Audit,
    pub flatpak: FlatpakCfg,
    pub jobs: BTreeMap<String, JobCfg>,
    pub cleanup: Cleanup,
    pub recorder: Recorder,
    pub baseline: BaselineCfg,
    pub keys: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Ui {
    pub dashboard_hz: f32,
    pub processes_hz: f32,
    /// Terminal used to enter containers; falls back to $TERMINAL, xdg-terminal-exec, ghostty, ptyxis.
    pub terminal: Option<String>,
}

impl Default for Ui {
    fn default() -> Self {
        Self {
            dashboard_hz: 1.0,
            processes_hz: 2.0,
            terminal: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CacheCfg {
    pub update_check_max_age: Dur,
}

impl Default for CacheCfg {
    fn default() -> Self {
        Self {
            update_check_max_age: Dur::hours(24),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Audit {
    pub retention_months: u32,
    pub stale_container_days: u32,
    pub cache_warn_mb: u64,
}

impl Default for Audit {
    fn default() -> Self {
        Self {
            retention_months: 12,
            stale_container_days: 30,
            cache_warn_mb: 2048,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FlatpakCfg {
    pub flag_filesystems: Vec<String>,
    pub flag_talk_names: Vec<String>,
    /// Remotes not listed here count as unverified origins.
    pub trusted_origins: Vec<String>,
}

impl Default for FlatpakCfg {
    fn default() -> Self {
        Self {
            flag_filesystems: vec!["host".into(), "home".into(), "host-os".into()],
            flag_talk_names: vec!["org.freedesktop.Flatpak".into()],
            trusted_origins: vec!["flathub".into(), "fedora".into()],
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct JobCfg {
    /// `"30d"` or `"off"`; interpreted by the jobs module.
    pub suggested_every: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Cleanup {
    pub cache: CleanupCache,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CleanupCache {
    pub delete_dirs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Recorder {
    pub interval: Dur,
    pub retention_hours: u32,
    pub max_mb: u32,
    pub alerts: Vec<String>,
}

impl Default for Recorder {
    fn default() -> Self {
        Self {
            interval: Dur::secs(10),
            retention_hours: 72,
            max_mb: 50,
            alerts: vec![
                "cpu>90%:5m".into(),
                "disk_free<5%".into(),
                "new_listener".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BaselineCfg {
    pub listeners: Vec<String>,
    /// Audit finding ids to treat as expected (globs allowed).
    pub findings: Vec<String>,
}

impl Default for BaselineCfg {
    fn default() -> Self {
        Self {
            listeners: vec!["127.0.0.1:631/cupsd".into()],
            findings: Vec::new(),
        }
    }
}

/// Duration written as `10s`, `5m`, `24h`, `30d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dur(pub Duration);

impl Dur {
    pub const fn secs(s: u64) -> Self {
        Self(Duration::from_secs(s))
    }
    pub const fn hours(h: u64) -> Self {
        Self(Duration::from_secs(h * 3600))
    }
}

impl FromStr for Dur {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let split = s
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("missing unit in {s:?}"))?;
        let (n, unit) = s.split_at(split);
        let n: u64 = n.parse().map_err(|_| format!("bad number in {s:?}"))?;
        let mul = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86400,
            _ => return Err(format!("unknown unit {unit:?} in {s:?} (use s, m, h, d)")),
        };
        Ok(Self(Duration::from_secs(n * mul)))
    }
}

impl fmt::Display for Dur {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.as_secs();
        match s {
            _ if s > 0 && s.is_multiple_of(86400) => write!(f, "{}d", s / 86400),
            _ if s > 0 && s.is_multiple_of(3600) => write!(f, "{}h", s / 3600),
            _ if s > 0 && s.is_multiple_of(60) => write!(f, "{}m", s / 60),
            _ => write!(f, "{s}s"),
        }
    }
}

impl<'de> Deserialize<'de> for Dur {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for Dur {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl Config {
    /// Parse config text; unknown keys are returned as warnings rather than errors.
    pub fn parse(text: &str) -> anyhow::Result<(Self, Vec<String>)> {
        let mut unknown = Vec::new();
        let de = toml::de::Deserializer::parse(text)?;
        let cfg: Config = serde_ignored::deserialize(de, |path| unknown.push(path.to_string()))?;
        let warnings = unknown
            .into_iter()
            .map(|p| format!("config: unknown key `{p}` ignored"))
            .collect();
        Ok((cfg, warnings))
    }

    /// Load from disk. A missing file means defaults; a broken file means defaults plus a warning.
    pub fn load() -> (Self, Vec<String>) {
        let path = paths::config_dir().join("config.toml");
        match std::fs::read_to_string(&path) {
            Ok(text) => match Self::parse(&text) {
                Ok(r) => r,
                Err(e) => (
                    Self::default(),
                    vec![format!(
                        "config: {} — using defaults",
                        first_line(&e.to_string())
                    )],
                ),
            },
            Err(_) => (Self::default(), Vec::new()),
        }
    }
}

fn first_line(s: &str) -> &str {
    s.lines().find(|l| !l.trim().is_empty()).unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_EXAMPLE: &str = r#"
[ui]
dashboard_hz = 1
processes_hz = 2

[cache]
update_check_max_age = "24h"

[audit]
retention_months = 12
stale_container_days = 30
cache_warn_mb = 2048

[flatpak]
flag_filesystems = ["host", "home", "host-os"]
flag_talk_names = ["org.freedesktop.Flatpak"]

[jobs]
audit.suggested_every = "30d"
update-check.suggested_every = "7d"
cleanup-flatpak.suggested_every = "30d"
cleanup-podman.suggested_every = "30d"
cleanup-ostree.suggested_every = "30d"

[cleanup.cache]
delete_dirs = []

[recorder]
interval = "10s"
retention_hours = 72
max_mb = 50
alerts = ["cpu>90%:5m", "disk_free<5%", "new_listener"]

[baseline]
listeners = ["127.0.0.1:631/cupsd"]
"#;

    #[test]
    fn spec_example_parses_without_warnings() {
        let (c, w) = Config::parse(SPEC_EXAMPLE).unwrap();
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(
            c.jobs["update-check"].suggested_every.as_deref(),
            Some("7d")
        );
        assert_eq!(c.cache.update_check_max_age, Dur::hours(24));
        assert_eq!(c.recorder.interval.to_string(), "10s");
    }

    #[test]
    fn empty_is_defaults() {
        let (c, w) = Config::parse("").unwrap();
        assert!(w.is_empty());
        assert_eq!(c.ui.processes_hz, 2.0);
        assert_eq!(c.baseline.listeners, vec!["127.0.0.1:631/cupsd"]);
    }

    #[test]
    fn unknown_keys_warn() {
        let (_, w) = Config::parse("[ui]\nbogus = 1\n[nope]\nx = 2\n").unwrap();
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w.iter().any(|w| w.contains("ui.bogus")), "{w:?}");
    }

    #[test]
    fn keys_table() {
        let (c, _) = Config::parse("[keys]\nquit = \"Q\"\n\"screen.history\" = \"H\"\n").unwrap();
        assert_eq!(c.keys["quit"], "Q");
        assert_eq!(c.keys["screen.history"], "H");
    }

    #[test]
    fn durations() {
        assert_eq!("30d".parse::<Dur>().unwrap(), Dur::secs(30 * 86400));
        assert_eq!("90s".parse::<Dur>().unwrap().to_string(), "90s");
        assert!("10".parse::<Dur>().is_err());
        assert!("10w".parse::<Dur>().is_err());
    }
}

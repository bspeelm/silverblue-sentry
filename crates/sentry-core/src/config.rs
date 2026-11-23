//! `~/.config/sentry/config.toml` (spec §12): this machine and the window. Written only
//! through `cfg` (`sentry config`, the Config tab), which keeps the file before beside it.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cfg::{Field, Kind};

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
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
    pub retention: Retention,
    pub maintenance: Maintenance,
    pub review: Review,
    pub targets: Targets,
}

/// Which targets the window opens (`[targets]`): this machine is `local`, a server
/// `srv:<name>`. Left out: all of them, this machine first.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct Targets {
    /// The targets shown, in the strip's order.
    pub show: Option<Vec<String>>,
}

impl Targets {
    /// `all` (every target there is, as ids: `local`, `srv:<name>`) as `show` orders and
    /// limits it, and the entries of `show` that name nothing.
    pub fn pick(&self, all: &[String]) -> (Vec<String>, Vec<String>) {
        let Some(show) = &self.show else {
            return (all.to_vec(), Vec::new());
        };
        let (mut picked, mut unknown) = (Vec::new(), Vec::new());
        for s in show {
            if !all.contains(s) {
                unknown.push(s.clone());
            } else if !picked.contains(s) {
                picked.push(s.clone());
            }
        }
        (picked, unknown)
    }
}

/// The reviews sentry starts by itself (both programs). Each is one Claude turn in the
/// background; nothing changes until you apply what it proposes.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct Review {
    /// At each start of the TUI: which tasks are due again because something changed.
    pub at_start: bool,
    /// When a workflow run ends well: which tasks it did.
    pub after_run: bool,
}

impl Default for Review {
    fn default() -> Self {
        Self {
            at_start: true,
            after_run: true,
        }
    }
}

/// How long maintenance records are kept (both programs). Pruned when the TUI starts and
/// after each write; the newest few always stay.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct Retention {
    /// Log entries older than this go (`LOG.md` follows), except the newest `log_keep`.
    pub log_months: u32,
    pub log_keep: usize,
    /// Workflow run directories (state and step logs) kept per workflow; a run in progress
    /// always stays.
    pub runs_per_workflow: usize,
    /// Applied or dropped plans (`plans/done/`).
    pub done_months: u32,
    /// Claude's reviews kept.
    pub reviews: usize,
    /// Audit reports kept at most (besides `audit.retention_months`).
    pub reports: usize,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            log_months: 12,
            log_keep: 20,
            runs_per_workflow: 10,
            done_months: 12,
            reviews: 10,
            reports: 100,
        }
    }
}

/// Maintenance on this machine.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct Maintenance {
    /// Your own notes (Markdown files) Claude reads when it plans or reviews: upgrade
    /// runbooks, what broke last time. Read only, never sent anywhere but to Claude.
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct Audit {
    pub retention_months: u32,
    pub stale_container_days: u32,
    pub cache_warn_mb: u64,
    /// The security audit's check from outside: a command of yours, run on this machine,
    /// given `{address}` (your uplink's public address) and `{ports}` (comma separated),
    /// that prints the ports it found open, one per line. None: nothing is checked from
    /// outside (the README has examples: a host elsewhere over ssh, a VPN's namespace).
    pub outside: Option<String>,
}

impl Default for Audit {
    fn default() -> Self {
        Self {
            retention_months: 12,
            stale_container_days: 30,
            cache_warn_mb: 2048,
            outside: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct JobCfg {
    /// `"30d"` or `"off"`; interpreted by the jobs module.
    pub suggested_every: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct Cleanup {
    pub cache: CleanupCache,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct CleanupCache {
    pub delete_dirs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

/// Builds a [`Field`] row.
const fn f(
    path: &'static str,
    label: &'static str,
    kind: Kind,
    essential: bool,
    help: &'static str,
) -> Field {
    Field {
        path,
        label,
        help,
        kind,
        essential,
    }
}

/// Every setting of config.toml (`sentry config explain`; the forms).
pub const FIELDS: &[Field] = &[
    f(
        "ui",
        "Window",
        Kind::Section,
        false,
        "How often the live screens sample, and the terminal containers are entered in.",
    ),
    f(
        "ui.dashboard_hz",
        "Dashboard rate",
        Kind::Number,
        false,
        "Samples a second on the Dashboard (1).",
    ),
    f(
        "ui.processes_hz",
        "Processes rate",
        Kind::Number,
        false,
        "Samples a second on Processes (2).",
    ),
    f(
        "ui.terminal",
        "Terminal",
        Kind::Text,
        true,
        "Terminal used to enter containers (`ghostty -e`); falls back to $TERMINAL, xdg-terminal-exec, ghostty, ptyxis.",
    ),
    f(
        "cache",
        "Cache",
        Kind::Section,
        false,
        "How long slow checks are kept.",
    ),
    f(
        "cache.update_check_max_age",
        "Update check age",
        Kind::Duration,
        false,
        "How old the cached update check may get before it is shown as old (24h); it is never refreshed by itself.",
    ),
    f(
        "audit",
        "Audit",
        Kind::Section,
        false,
        "This machine's audit.",
    ),
    f(
        "audit.retention_months",
        "Reports kept (months)",
        Kind::Number,
        false,
        "Audit reports older than this go (12).",
    ),
    f(
        "audit.stale_container_days",
        "Stale container (days)",
        Kind::Number,
        false,
        "A stopped container older than this is a finding (30).",
    ),
    f(
        "audit.cache_warn_mb",
        "Cache warning (MB)",
        Kind::Number,
        false,
        "A cache larger than this is a finding (2048).",
    ),
    f(
        "audit.outside",
        "Check from outside",
        Kind::Text,
        false,
        "The security audit's check from outside: a command of yours, run on this machine, given `{address}` (your uplink's public address) and `{ports}` (comma separated), that prints the ports it found open, one per line. None: nothing is checked from outside.",
    ),
    f(
        "flatpak",
        "Flatpak",
        Kind::Section,
        false,
        "What the audit flags in Flatpak apps' permissions.",
    ),
    f(
        "flatpak.flag_filesystems",
        "Flagged filesystems",
        Kind::List,
        false,
        "Filesystem permissions that are flagged (host, home, host-os).",
    ),
    f(
        "flatpak.flag_talk_names",
        "Flagged bus names",
        Kind::List,
        false,
        "D-Bus names an app may talk to that are flagged.",
    ),
    f(
        "flatpak.trusted_origins",
        "Trusted remotes",
        Kind::List,
        false,
        "Remotes not listed here count as unverified origins (flathub, fedora).",
    ),
    f(
        "jobs",
        "Jobs",
        Kind::Map,
        false,
        "Per job (audit, update-check, cleanup-*): how often it is suggested.",
    ),
    f(
        "jobs.*.suggested_every",
        "Suggested every",
        Kind::Text,
        false,
        "`30d`, or `off`: the job is recommended when it last ran longer ago than this.",
    ),
    f(
        "cleanup",
        "Cleanup",
        Kind::Section,
        false,
        "What Cleanup may delete.",
    ),
    f(
        "cleanup.cache",
        "Cache cleanup",
        Kind::Section,
        false,
        "Caches in ~/.cache Cleanup may delete.",
    ),
    f(
        "cleanup.cache.delete_dirs",
        "Cache dirs to delete",
        Kind::List,
        false,
        "Opt-in: directories under ~/.cache Cleanup may delete (pip, yarn).",
    ),
    f(
        "recorder",
        "Recorder",
        Kind::Section,
        false,
        "`sentry record` and History.",
    ),
    f(
        "recorder.interval",
        "Interval",
        Kind::Duration,
        false,
        "Time between two samples (10s).",
    ),
    f(
        "recorder.retention_hours",
        "Kept (hours)",
        Kind::Number,
        false,
        "How much history the ring holds (72).",
    ),
    f(
        "recorder.max_mb",
        "Size (MB)",
        Kind::Number,
        false,
        "The ring's size at most (50).",
    ),
    f(
        "recorder.alerts",
        "Alerts",
        Kind::List,
        false,
        "Desktop notifications while recording: `cpu>90%:5m`, `disk_free<5%`, `new_listener`.",
    ),
    f(
        "baseline",
        "Expected",
        Kind::Section,
        false,
        "What the audit takes as expected, besides what you mark in the window.",
    ),
    f(
        "baseline.listeners",
        "Expected listeners",
        Kind::List,
        false,
        "Listening sockets, `addr:port/process` (127.0.0.1:631/cupsd).",
    ),
    f(
        "baseline.findings",
        "Expected findings",
        Kind::List,
        false,
        "Audit finding ids to treat as expected (globs allowed).",
    ),
    f(
        "keys",
        "Keys",
        Kind::Map,
        true,
        "Rebinds: `quit = \"Q\"`, `\"screen.history\" = \"F9\"`, `\"target.next\" = \"C-n\"`.",
    ),
    f(
        "retention",
        "Retention",
        Kind::Section,
        true,
        "How long maintenance records are kept (every target). Pruned when the window starts and after each write; the newest few always stay.",
    ),
    f(
        "retention.log_months",
        "Log (months)",
        Kind::Number,
        true,
        "Log entries older than this go (LOG.md follows), except the newest `log_keep` (12).",
    ),
    f(
        "retention.log_keep",
        "Log entries always kept",
        Kind::Number,
        true,
        "The newest log entries kept whatever their age (20).",
    ),
    f(
        "retention.runs_per_workflow",
        "Runs per workflow",
        Kind::Number,
        true,
        "Workflow run directories (state and step logs) kept per workflow; a run in progress always stays (10).",
    ),
    f(
        "retention.done_months",
        "Done plans (months)",
        Kind::Number,
        true,
        "Applied or dropped plans (plans/done/) older than this go (12).",
    ),
    f(
        "retention.reviews",
        "Reviews kept",
        Kind::Number,
        true,
        "Claude's reviews kept (10).",
    ),
    f(
        "retention.reports",
        "Reports kept",
        Kind::Number,
        true,
        "Audit reports kept at most, besides audit.retention_months (100).",
    ),
    f(
        "maintenance",
        "Maintenance",
        Kind::Section,
        true,
        "Maintenance on this machine.",
    ),
    f(
        "maintenance.notes",
        "Notes",
        Kind::List,
        true,
        "Your own notes (Markdown files) Claude reads when it plans or reviews: upgrade runbooks, what broke last time. Read only, never sent anywhere but to Claude.",
    ),
    f(
        "review",
        "Reviews at start and after a run",
        Kind::Section,
        true,
        "The reviews sentry starts by itself (every target). Each is one Claude turn in the background; nothing changes until you apply what it proposes.",
    ),
    f(
        "review.at_start",
        "Review at start",
        Kind::Bool,
        true,
        "At each start of the window: which tasks are due again because something changed (on).",
    ),
    f(
        "review.after_run",
        "Review after a run",
        Kind::Bool,
        true,
        "When a workflow run ends well: which tasks it did (on).",
    ),
    f(
        "targets",
        "Targets",
        Kind::Section,
        true,
        "Which targets the window opens.",
    ),
    f(
        "targets.show",
        "Shown, in order",
        Kind::List,
        true,
        "The targets shown, in the strip's order: `local`, `srv:<name>`, `net:<name>`. Left out: all of them, this machine first.",
    ),
];

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
        let path = crate::cfg::FileId::App.path();
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

impl crate::cfg::ConfigFile for Config {
    const FILE: crate::cfg::FileId = crate::cfg::FileId::App;
    const FIELDS: &'static [crate::cfg::Field] = FIELDS;
    fn parse(text: &str) -> Result<(Self, Vec<String>), String> {
        Config::parse(text).map_err(|e| first_line(&e.to_string()).to_string())
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

[retention]
log_months = 12
log_keep = 20
runs_per_workflow = 10
done_months = 12
reviews = 10
reports = 100

[maintenance]
notes = []
"#;

    #[test]
    fn targets_are_all_unless_show_orders_or_hides_them() {
        let all: Vec<String> = ["local", "srv:a", "srv:b"].map(String::from).to_vec();
        let (cfg, w) = Config::parse("").unwrap();
        assert!(w.is_empty());
        assert_eq!(cfg.targets.pick(&all), (all.clone(), vec![]));
        let (cfg, _) =
            Config::parse("[targets]\nshow = [\"srv:b\", \"local\", \"srv:x\"]").unwrap();
        assert_eq!(
            cfg.targets.pick(&all),
            (
                vec!["srv:b".to_string(), "local".to_string()],
                vec!["srv:x".to_string()]
            )
        );
    }

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

    /// What the spec's example parses to, fixed before sentry could write the file.
    #[test]
    fn the_spec_example_parses_to_what_it_always_did() {
        let (c, _) = Config::parse(SPEC_EXAMPLE).unwrap();
        insta::assert_snapshot!(serde_json::to_string_pretty(&c).unwrap());
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

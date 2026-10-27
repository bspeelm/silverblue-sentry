//! `~/.config/sentry/server_config.yaml`: the servers `sentry-server` knows and what "healthy"
//! means for each. The user writes it; sentry-server never rewrites it, so comments survive.
//! Whatever sentry-server records itself (findings marked expected) goes in
//! `servers/<name>.baseline.toml` next to it.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::Dur;
use crate::paths;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerFile {
    pub servers: BTreeMap<String, Server>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Server {
    /// What `ssh` connects to (an alias from `~/.ssh/config`, or `user@host`). Default: the
    /// server's name.
    pub ssh: Option<String>,
    /// Read-only commands run as `sudo -n …`, as argv prefixes (`docker ps` allows
    /// `docker ps -a`, not `docker rm`). Nothing else ever gets sudo while monitoring.
    pub sudo: Vec<String>,
    pub disks: Vec<DiskRule>,
    /// Devices for SMART health, read with `smartctl -n standby` so sleeping disks stay asleep.
    pub smart: Vec<String>,
    /// Units that must be active.
    pub services: Vec<String>,
    /// Timers whose last run must be recent and successful.
    pub timers: Vec<TimerRule>,
    pub compose: Vec<Compose>,
    pub containers: Containers,
    /// Expected listening sockets, `addr:port/process` with `*` globs (`*:443/*`).
    pub listeners: Vec<String>,
    /// Finding ids that are expected here (globs allowed).
    pub findings: Vec<String>,
    pub thresholds: Thresholds,
    /// Your own maintenance commands, offered behind a confirm box.
    pub actions: Vec<CustomAction>,
    /// What's pinned or held deliberately, and when to look at it again (the Maintenance tab).
    pub maintenance: Maintenance,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Maintenance {
    /// Local files Claude may read when planning or reviewing (runbooks, notes).
    pub notes: Vec<String>,
    pub items: Vec<MaintItem>,
    /// How often a routine workflow should run (`apt-maintenance: 30d`): recommended when
    /// the maintenance log says it last ran longer ago than that.
    pub cadence: BTreeMap<String, Dur>,
}

/// One thing kept at a deliberate version: an image, held packages, or an app on the host.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct MaintItem {
    pub id: String,
    /// A container image: its pin from the compose file, what runs from `docker inspect`.
    pub image: Option<ImageRef>,
    /// Debian packages: installed (and held) vs the candidate apt offers.
    pub apt: Vec<String>,
    /// An app on the host: a command printing its version, run as the login user.
    pub version_cmd: Option<String>,
    /// Its systemd unit, for a host app (what `retire` stops).
    pub unit: Option<String>,
    /// Where newer versions come from: `github:owner/repo`, `docker:repo` (Docker Hub),
    /// `ghcr:owner/image`. Packages use apt's candidate.
    pub source: Option<String>,
    /// Which upstream tags count, as a glob (`*-alpine`); default: plain version numbers.
    pub tag: Option<String>,
    /// How risky a change to it is (`tier:` and green/amber/red are still read).
    #[serde(alias = "tier")]
    pub risk: Risk,
    /// Why it's held where it is.
    pub hold: Option<String>,
    /// What limits the choice of version.
    pub constraint: Option<String>,
    /// Look at it again by then (YYYY-MM-DD).
    pub review_by: Option<jiff::civil::Date>,
    /// End of life from endoflife.date: `product` or `product/cycle`.
    pub eol: Option<String>,
    /// The workflow that applies a change to it (`p` on the Maintenance tab).
    pub workflow: Option<String>,
    /// Planned to be removed.
    pub retire: Option<Retire>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ImageRef {
    /// A compose service (its pin is read from the compose file).
    pub service: Option<String>,
    /// The compose project it belongs to (default: the first under compose:).
    pub compose: Option<String>,
    /// A container not run by compose.
    pub container: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Retire {
    pub replaced_by: Option<String>,
    pub workflow: Option<String>,
}

/// How risky a change to it is: low (routine), medium (have a rollback ready), high (can
/// break things or can't be undone: back up first, in a window). Shown, and told to Claude.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    #[serde(alias = "green")]
    Low,
    #[default]
    #[serde(alias = "amber")]
    Medium,
    #[serde(alias = "red")]
    High,
}

impl Risk {
    pub fn as_str(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DiskRule {
    pub mount: String,
    /// Percent used.
    #[serde(default = "warn_pct")]
    pub warn: u8,
    #[serde(default = "crit_pct")]
    pub crit: u8,
}

fn warn_pct() -> u8 {
    85
}
fn crit_pct() -> u8 {
    95
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TimerRule {
    pub unit: String,
    /// The last successful run must be newer than this.
    pub max_age: Dur,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Compose {
    pub name: String,
    /// The compose file on the server.
    pub file: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Containers {
    /// Container names (globs) that may be stopped.
    pub ignore: Vec<String>,
    /// A container started more recently than this counts as restarted.
    pub restart_window: Dur,
}

impl Default for Containers {
    fn default() -> Self {
        Self {
            ignore: Vec::new(),
            restart_window: Dur::hours(24),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Thresholds {
    /// Memory used, percent.
    pub mem: f32,
    /// 1-minute load per core.
    pub load_per_core: f32,
    /// °C.
    pub cpu_temp: f32,
    pub gpu_temp: f32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            mem: 90.0,
            load_per_core: 2.0,
            cpu_temp: 85.0,
            gpu_temp: 83.0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct CustomAction {
    pub id: String,
    pub title: String,
    /// Shell command run on the server.
    pub run: String,
    /// Run it with sudo.
    #[serde(default)]
    pub sudo: bool,
    /// Destructive or hard to undo: shown in red.
    #[serde(default)]
    pub risky: bool,
    #[serde(default)]
    pub undo: Option<String>,
}

/// Words that make a `sudo:` entry more than a read: such entries are refused.
const WRITE_WORDS: &[&str] = &[
    "rm", "rmi", "restart", "start", "stop", "kill", "prune", "upgrade", "install", "remove",
    "purge", "reboot", "poweroff", "tee", "sh", "bash", "-c", "exec", "run", "pull", "up", "down",
    "update", "edit", "set", "enable", "disable", "mask", "reload",
];

impl Server {
    /// The ssh destination.
    pub fn ssh_target<'a>(&'a self, name: &'a str) -> &'a str {
        self.ssh.as_deref().unwrap_or(name)
    }

    /// Whether `argv` may run as `sudo -n` (it starts with an allowed entry's words).
    pub fn sudo_allows(&self, argv: &[&str]) -> bool {
        self.sudo.iter().any(|entry| {
            let words: Vec<&str> = entry.split_whitespace().collect();
            !words.is_empty() && argv.len() >= words.len() && argv[..words.len()] == words[..]
        })
    }

    pub fn timer_age(&self, unit: &str) -> Option<Duration> {
        self.timers
            .iter()
            .find(|t| t.unit == unit)
            .map(|t| t.max_age.0)
    }
}

pub fn path() -> PathBuf {
    paths::config_dir().join("server_config.yaml")
}

/// Parse the file's text; unknown keys come back as warnings.
pub fn parse(text: &str) -> Result<(ServerFile, Vec<String>), String> {
    let mut unknown = Vec::new();
    let file: ServerFile = serde_saphyr::with_deserializer_from_str(text, |de| {
        serde_ignored::deserialize(de, |p| unknown.push(p.to_string()))
    })
    .map_err(|e| e.to_string())?;
    let warnings = unknown
        .into_iter()
        .map(|p| format!("server_config.yaml: unknown key `{p}` ignored"))
        .collect();
    Ok((file, warnings))
}

pub fn load() -> Result<(ServerFile, Vec<String>), String> {
    let p = path();
    let text = std::fs::read_to_string(&p).map_err(|_| {
        format!(
            "no {}: run `sentry-server init <ssh-host>` to draft one",
            p.display()
        )
    })?;
    parse(&text).map_err(|e| format!("{}: {e}", p.display()))
}

/// Pick a server: by name, or the only one configured.
pub fn pick<'a>(file: &'a ServerFile, name: Option<&str>) -> Result<(&'a str, &'a Server), String> {
    match name {
        Some(n) => file
            .servers
            .get_key_value(n)
            .map(|(k, v)| (k.as_str(), v))
            .ok_or_else(|| {
                format!(
                    "no server `{n}` in server_config.yaml (configured: {})",
                    names(file)
                )
            }),
        None => match file.servers.len() {
            1 => {
                let (k, v) = file.servers.iter().next().expect("one");
                Ok((k.as_str(), v))
            }
            0 => Err("server_config.yaml has no servers".into()),
            _ => Err(format!(
                "several servers configured, name one: {}",
                names(file)
            )),
        },
    }
}

fn names(file: &ServerFile) -> String {
    file.servers.keys().cloned().collect::<Vec<_>>().join(", ")
}

/// The ssh destination as `&'static str` for [`crate::exec::Site::Ssh`]; leaked once per name.
pub fn host(target: &str) -> &'static str {
    static HOSTS: OnceLock<Mutex<HashMap<String, &'static str>>> = OnceLock::new();
    let mut m = HOSTS.get_or_init(Default::default).lock().expect("hosts");
    m.entry(target.to_string())
        .or_insert_with(|| Box::leak(target.to_string().into_boxed_str()))
}

/// Problems found without contacting the server.
pub fn lint(name: &str, s: &Server) -> Vec<String> {
    let mut p = Vec::new();
    for entry in &s.sudo {
        let words: Vec<&str> = entry.split_whitespace().collect();
        if words.is_empty() {
            p.push(format!("{name}: empty sudo entry"));
        } else if let Some(w) = words.iter().find(|w| WRITE_WORDS.contains(w)) {
            p.push(format!(
                "{name}: sudo entry `{entry}` contains `{w}`: sudo is only for read-only commands \
                 (maintenance goes in actions:)"
            ));
        }
    }
    for d in &s.disks {
        if !d.mount.starts_with('/') {
            p.push(format!(
                "{name}: disk mount `{}` isn't an absolute path",
                d.mount
            ));
        }
        if d.warn >= d.crit || d.crit > 100 {
            p.push(format!(
                "{name}: disk {}: warn {} must be below crit {} (≤ 100)",
                d.mount, d.warn, d.crit
            ));
        }
    }
    for t in &s.timers {
        if !t.unit.ends_with(".timer") {
            p.push(format!("{name}: timer `{}` should end in .timer", t.unit));
        }
    }
    for c in &s.compose {
        if !c.file.starts_with('/') {
            p.push(format!(
                "{name}: compose {}: file must be an absolute path",
                c.name
            ));
        }
    }
    for d in &s.smart {
        if !d.starts_with("/dev/") {
            p.push(format!("{name}: smart device `{d}` should be a /dev path"));
        }
    }
    let mut ids = std::collections::HashSet::new();
    for a in &s.actions {
        if !ids.insert(&a.id) {
            p.push(format!("{name}: action id `{}` used twice", a.id));
        }
        if a.run.trim().is_empty() {
            p.push(format!("{name}: action `{}` has no run command", a.id));
        }
    }
    let mut ids = std::collections::HashSet::new();
    for it in &s.maintenance.items {
        let at = format!("{name}: maintenance item `{}`", it.id);
        if it.id.is_empty() {
            p.push(format!("{name}: a maintenance item has no id"));
        } else if !ids.insert(&it.id) {
            p.push(format!("{at} used twice"));
        }
        let kinds = usize::from(it.image.is_some())
            + usize::from(!it.apt.is_empty())
            + usize::from(it.version_cmd.is_some());
        if kinds != 1 && it.retire.is_none() && it.eol.is_none() {
            p.push(format!(
                "{at}: give exactly one of image:, apt: or version_cmd:"
            ));
        }
        if let Some(img) = &it.image {
            if img.service.is_some() == img.container.is_some() {
                p.push(format!(
                    "{at}: image: needs service: or container:, not both"
                ));
            }
            if let Some(c) = &img.compose
                && !s.compose.iter().any(|x| &x.name == c)
            {
                p.push(format!("{at}: compose project `{c}` isn't under compose:"));
            }
            if img.service.is_some() && img.compose.is_none() && s.compose.is_empty() {
                p.push(format!("{at}: a compose service, but no compose: projects"));
            }
        }
        if let Some(src) = &it.source
            && !["github:", "docker:", "ghcr:"]
                .iter()
                .any(|pre| src.strip_prefix(pre).is_some_and(|r| !r.is_empty()))
        {
            p.push(format!(
                "{at}: source `{src}` should be github:owner/repo, docker:repo or ghcr:owner/image"
            ));
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../assets/server_config.example.yaml");

    #[test]
    fn example_parses_and_lints_clean() {
        let (f, warnings) = parse(EXAMPLE).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        let (name, s) = pick(&f, None).unwrap();
        assert_eq!(name, "myserver");
        assert_eq!(s.ssh_target(name), "admin@myserver.example");
        assert!(lint(name, s).is_empty(), "{:?}", lint(name, s));
        assert_eq!(s.disks[0].warn, 85);
        assert_eq!(
            s.timer_age("backup.timer"),
            Some(Duration::from_secs(26 * 3600))
        );
        assert_eq!(s.containers.restart_window, Dur::hours(24));
    }

    #[test]
    fn unknown_keys_warn_and_errors_say_where() {
        let (_, w) = parse("servers:\n  a:\n    sudoo: [x]\n").unwrap();
        assert_eq!(
            w,
            ["server_config.yaml: unknown key `servers.a.sudoo` ignored"]
        );
        let e = parse("servers:\n  a:\n    timers:\n      - {unit: x.timer, max_age: 3 days}\n")
            .unwrap_err();
        assert!(e.contains("unknown unit") && e.contains("line 4"), "{e}");
    }

    #[test]
    fn sudo_is_a_read_only_argv_prefix() {
        let s = Server {
            sudo: vec!["docker ps".into(), "smartctl".into()],
            ..Default::default()
        };
        assert!(s.sudo_allows(&["docker", "ps", "-a"]));
        assert!(s.sudo_allows(&["smartctl", "-n", "standby", "-H", "/dev/sda"]));
        assert!(!s.sudo_allows(&["docker", "rm", "web"]));
        assert!(!s.sudo_allows(&["docker"]));
        let bad = Server {
            sudo: vec![
                "docker compose up".into(),
                "sh -c".into(),
                "journalctl".into(),
            ],
            ..Default::default()
        };
        let p = lint("x", &bad);
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p[0].contains("`up`") && p[1].contains("`sh`"));
    }

    #[test]
    fn pick_by_name_or_the_only_one() {
        let (f, _) = parse("servers:\n  a: {}\n  b: {}\n").unwrap();
        assert!(pick(&f, None).unwrap_err().contains("a, b"));
        assert_eq!(pick(&f, Some("b")).unwrap().0, "b");
        assert!(pick(&f, Some("c")).is_err());
        assert_eq!(host("a"), host("a"));
    }

    #[test]
    fn risk_reads_the_old_tier_names_too() {
        let (f, w) = parse(
            "servers:\n  s:\n    maintenance:\n      items:\n        - {id: a, version_cmd: x, tier: red}\n        - {id: b, version_cmd: x, risk: low}\n        - {id: c, version_cmd: x}\n",
        )
        .unwrap();
        assert!(w.is_empty(), "{w:?}");
        let r: Vec<Risk> = f.servers["s"]
            .maintenance
            .items
            .iter()
            .map(|i| i.risk)
            .collect();
        assert_eq!(r, [Risk::High, Risk::Low, Risk::Medium]);
    }
}

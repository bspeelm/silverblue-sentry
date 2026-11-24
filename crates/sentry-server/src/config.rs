//! `~/.config/sentry/server_config.yaml`: the servers `sentry-server` knows and what "healthy"
//! means for each. What you said: written only through core's `cfg` (`sentry-server init
//! --write`, `sentry config`), which keeps the file before beside it; a hand-edited file's
//! comments are not kept on the next save. Whatever sentry-server records itself (findings
//! marked expected) goes in `servers/<name>/baseline.toml` beside it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use sentry_core::cfg::{ConfigFile, Field, FileId, Kind};
use sentry_core::config::Dur;

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerFile {
    pub servers: BTreeMap<String, Server>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
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
    /// What's pinned or held deliberately, and when to look at it again (Maintenance).
    pub maintenance: Maintenance,
    /// SusCheck's incidents folder on this server, read for the SusCheck screen. Off
    /// without a `dir`.
    pub suscheck: Suscheck,
}

/// Where SusCheck (a home service that checks screenshots of suspicious mail and pages)
/// keeps its incidents on this server, and who reads them. Only ever read, as an
/// unprivileged login, and never by sentry's agent.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct Suscheck {
    /// The incidents folder (absolute). Not set: off, no screen, no findings.
    pub dir: Option<String>,
    /// A login of its own for reading the folder (an ssh alias or `user@host`), in the
    /// folder's group; the server's ordinary login then isn't, and can't read it.
    pub ssh: Option<String>,
    /// How many of the latest checks are read (the end of the index).
    pub recent: u32,
}

/// `suscheck.recent` when the file doesn't say.
pub const SUSCHECK_RECENT: u32 = 200;
/// The most `suscheck.recent` may be (one read, kept in memory).
pub const SUSCHECK_RECENT_MAX: u32 = 2000;

impl Default for Suscheck {
    fn default() -> Self {
        Self {
            dir: None,
            ssh: None,
            recent: SUSCHECK_RECENT,
        }
    }
}

impl Suscheck {
    /// The folder, when the block is there: SusCheck is on for this server.
    pub fn on(&self) -> Option<&str> {
        self.dir.as_deref().filter(|d| !d.trim().is_empty())
    }
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
    /// End of life from endoflife.date: write the `product` (`docker-engine`, `nvidia`,
    /// `debian`); the release series is told from what runs (the item's version, or the
    /// server's own OS release for an item with nothing else). `product/cycle` is still read:
    /// that cycle is the fallback when the series can't be told.
    pub eol: Option<String>,
    /// The workflow that applies a change to it (`p` on Maintenance).
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

impl Server {
    /// A disk's `warn` when the file doesn't say.
    pub fn default_warn() -> u8 {
        warn_pct()
    }
    /// A disk's `crit` when the file doesn't say.
    pub fn default_crit() -> u8 {
        crit_pct()
    }
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

const fn f(
    path: &'static str,
    label: &'static str,
    kind: Kind,
    common: bool,
    help: &'static str,
) -> Field {
    Field {
        path,
        label,
        help,
        kind,
        common,
    }
}

const RISKS: &[&str] = &["low", "medium", "high"];

/// Every setting of server_config.yaml (`sentry config explain`; the forms).
pub const FIELDS: &[Field] = &[
    f(
        "servers",
        "Servers",
        Kind::Map,
        true,
        "Each entry is one server sentry watches over ssh, by its name.",
    ),
    f(
        "servers.*.ssh",
        "ssh",
        Kind::Text,
        true,
        "What `ssh` connects to (an alias from ~/.ssh/config, or user@host). Default: the server's name. Key-based login is required.",
    ),
    f(
        "servers.*.sudo",
        "sudo allowlist",
        Kind::List,
        true,
        "Read-only commands run as `sudo -n …`, as argv prefixes (`docker ps` allows `docker ps -a`, not `docker rm`). Nothing else ever gets sudo while monitoring; write commands are refused here.",
    ),
    f(
        "servers.*.disks",
        "Disks",
        Kind::Records,
        true,
        "Filesystems to watch, percent used.",
    ),
    f(
        "servers.*.disks[].mount",
        "Mount",
        Kind::Text,
        true,
        "The mount point (an absolute path).",
    ),
    f(
        "servers.*.disks[].warn",
        "Warn at",
        Kind::Number,
        true,
        "Percent used from which it is a warning (85).",
    ),
    f(
        "servers.*.disks[].crit",
        "Critical at",
        Kind::Number,
        true,
        "Percent used from which it is critical (95).",
    ),
    f(
        "servers.*.smart",
        "SMART",
        Kind::List,
        true,
        "Devices for SMART health (/dev/sda), read with `smartctl -n standby` so sleeping disks stay asleep.",
    ),
    f(
        "servers.*.services",
        "Services",
        Kind::List,
        true,
        "Units that must be active.",
    ),
    f(
        "servers.*.timers",
        "Timers",
        Kind::Records,
        true,
        "Timers whose last run must be recent and successful.",
    ),
    f(
        "servers.*.timers[].unit",
        "Unit",
        Kind::Text,
        true,
        "The timer (`backup.timer`).",
    ),
    f(
        "servers.*.timers[].max_age",
        "Max age",
        Kind::Duration,
        true,
        "The last successful run must be newer than this.",
    ),
    f(
        "servers.*.compose",
        "Compose projects",
        Kind::Records,
        true,
        "Docker compose projects: status, health, pull/up from Containers.",
    ),
    f(
        "servers.*.compose[].name",
        "Name",
        Kind::Text,
        true,
        "The project's name.",
    ),
    f(
        "servers.*.compose[].file",
        "File",
        Kind::Text,
        true,
        "The compose file on the server (an absolute path).",
    ),
    f(
        "servers.*.containers",
        "Containers",
        Kind::Section,
        false,
        "How containers are judged.",
    ),
    f(
        "servers.*.containers.ignore",
        "May be stopped",
        Kind::List,
        false,
        "Container names (globs) that may be stopped.",
    ),
    f(
        "servers.*.containers.restart_window",
        "Restart window",
        Kind::Duration,
        false,
        "A container started more recently than this counts as restarted (24h).",
    ),
    f(
        "servers.*.listeners",
        "Listeners",
        Kind::List,
        true,
        "Expected listening sockets, `addr:port/process` with `*` globs (`*:443/*`). Anything else listening is a finding.",
    ),
    f(
        "servers.*.findings",
        "Expected findings",
        Kind::List,
        false,
        "Finding ids that are expected here (globs allowed).",
    ),
    f(
        "servers.*.thresholds",
        "Thresholds",
        Kind::Section,
        false,
        "When the Dashboard and the audit call something high.",
    ),
    f(
        "servers.*.thresholds.mem",
        "Memory",
        Kind::Number,
        false,
        "Memory used, in percent, from which it counts as high (90).",
    ),
    f(
        "servers.*.thresholds.load_per_core",
        "Load per core",
        Kind::Number,
        false,
        "The 1-minute load divided by the number of cores, from which it counts as high (2.0).",
    ),
    f(
        "servers.*.thresholds.cpu_temp",
        "CPU temperature",
        Kind::Number,
        false,
        "The CPU temperature in °C from which it counts as high (85).",
    ),
    f(
        "servers.*.thresholds.gpu_temp",
        "GPU temperature",
        Kind::Number,
        false,
        "The GPU temperature in °C from which it counts as high (83).",
    ),
    f(
        "servers.*.actions",
        "Actions",
        Kind::Records,
        false,
        "Your own maintenance commands, offered behind a confirm box.",
    ),
    f(
        "servers.*.actions[].id",
        "Id",
        Kind::Text,
        false,
        "A short name for it, unique on this server.",
    ),
    f(
        "servers.*.actions[].title",
        "Title",
        Kind::Text,
        false,
        "What it is called in the window.",
    ),
    f(
        "servers.*.actions[].run",
        "Command",
        Kind::Text,
        false,
        "Shell command run on the server.",
    ),
    f(
        "servers.*.actions[].sudo",
        "With sudo",
        Kind::Bool,
        false,
        "Run it with sudo.",
    ),
    f(
        "servers.*.actions[].risky",
        "Risky",
        Kind::Bool,
        false,
        "Destructive or hard to undo: shown in red.",
    ),
    f(
        "servers.*.actions[].undo",
        "Undo",
        Kind::Text,
        false,
        "How to undo it, in words: said in its confirm box. Empty: nothing is said.",
    ),
    f(
        "servers.*.maintenance",
        "Maintenance",
        Kind::Section,
        true,
        "What's pinned or held deliberately, and when to look at it again (Maintenance).",
    ),
    f(
        "servers.*.maintenance.notes",
        "Notes",
        Kind::List,
        true,
        "Local files Claude may read when planning or reviewing (runbooks, notes).",
    ),
    f(
        "servers.*.maintenance.items",
        "Items",
        Kind::Records,
        true,
        "Things kept at a deliberate version: an image, held packages, or an app on the host.",
    ),
    f(
        "servers.*.maintenance.items[].id",
        "Id",
        Kind::Text,
        true,
        "A short name for it, unique on this server.",
    ),
    f(
        "servers.*.maintenance.items[].image",
        "Image",
        Kind::Section,
        false,
        "A container image: its pin from the compose file, what runs from `docker inspect`.",
    ),
    f(
        "servers.*.maintenance.items[].image.service",
        "Compose service",
        Kind::Text,
        false,
        "A compose service (its pin is read from the compose file).",
    ),
    f(
        "servers.*.maintenance.items[].image.compose",
        "Compose project",
        Kind::Text,
        false,
        "The compose project it belongs to (default: the first under compose:).",
    ),
    f(
        "servers.*.maintenance.items[].image.container",
        "Container",
        Kind::Text,
        false,
        "A container not run by compose.",
    ),
    f(
        "servers.*.maintenance.items[].apt",
        "Packages",
        Kind::List,
        false,
        "Debian packages: installed (and held) vs the candidate apt offers.",
    ),
    f(
        "servers.*.maintenance.items[].version_cmd",
        "Version command",
        Kind::Text,
        false,
        "An app on the host: a command printing its version, run as the login user.",
    ),
    f(
        "servers.*.maintenance.items[].unit",
        "Unit",
        Kind::Text,
        false,
        "Its systemd unit, for a host app (what `retire` stops).",
    ),
    f(
        "servers.*.maintenance.items[].source",
        "Source",
        Kind::Text,
        true,
        "Where newer versions come from: `github:owner/repo`, `docker:repo` (Docker Hub), `ghcr:owner/image`. Packages use apt's candidate.",
    ),
    f(
        "servers.*.maintenance.items[].tag",
        "Tags",
        Kind::Text,
        false,
        "Which upstream tags count, as a glob (`*-alpine`); default: plain version numbers.",
    ),
    f(
        "servers.*.maintenance.items[].risk",
        "Risk",
        Kind::Choice(RISKS),
        true,
        "How risky a change to it is: low (routine), medium (have a rollback ready), high (back up first, in a window). `tier:` and green/amber/red are still read.",
    ),
    f(
        "servers.*.maintenance.items[].hold",
        "Why held",
        Kind::Text,
        false,
        "Why it's held where it is, in a sentence: shown on Maintenance and told to Claude.",
    ),
    f(
        "servers.*.maintenance.items[].constraint",
        "Constraint",
        Kind::Text,
        false,
        "What limits the choice of version (`needs the 550 driver series`): told to Claude when it plans.",
    ),
    f(
        "servers.*.maintenance.items[].review_by",
        "Review by",
        Kind::Date,
        false,
        "Look at it again by this date (YYYY-MM-DD); Maintenance flags it once the date has passed. Empty: no date.",
    ),
    f(
        "servers.*.maintenance.items[].eol",
        "End of life",
        Kind::Text,
        false,
        "The endoflife.date product (`docker-engine`, `debian`); the series is told from what runs. `product/cycle` is still read.",
    ),
    f(
        "servers.*.maintenance.items[].workflow",
        "Workflow",
        Kind::Text,
        true,
        "The workflow that applies a change to it.",
    ),
    f(
        "servers.*.maintenance.items[].retire",
        "Retire",
        Kind::Section,
        false,
        "Planned to be removed.",
    ),
    f(
        "servers.*.maintenance.items[].retire.replaced_by",
        "Replaced by",
        Kind::Text,
        false,
        "What takes its place, in words (another item, a product).",
    ),
    f(
        "servers.*.maintenance.items[].retire.workflow",
        "Retire workflow",
        Kind::Text,
        false,
        "The workflow that retires it, one of this server's.",
    ),
    f(
        "servers.*.maintenance.cadence",
        "How often",
        Kind::Map,
        true,
        "How often a routine workflow should run (`apt-maintenance: 30d`): recommended when the maintenance log says it last ran longer ago than that.",
    ),
    f(
        "servers.*.suscheck",
        "SusCheck",
        Kind::Section,
        false,
        "SusCheck's incidents on this server (a home service that checks screenshots of suspicious mail and pages), for the SusCheck screen. Read only, never by sentry's agent. Off without a folder.",
    ),
    f(
        "servers.*.suscheck.dir",
        "Incidents folder",
        Kind::Text,
        false,
        "The incidents folder on the server (an absolute path; SusCheck writes it in /etc/suscheck/incidents.path). Empty: off.",
    ),
    f(
        "servers.*.suscheck.ssh",
        "Login that reads it",
        Kind::Text,
        false,
        "A login of its own for reading the folder (an ssh alias or user@host), in the folder's group while the server's ordinary login is not: then nothing sentry's agent runs there can read a check. Empty: the server's own login reads it.",
    ),
    f(
        "servers.*.suscheck.recent",
        "Checks read",
        Kind::Number,
        false,
        "How many of the latest checks are read each time (200; at most 2000).",
    ),
];

impl Server {
    /// The ssh destination.
    pub fn ssh_target<'a>(&'a self, name: &'a str) -> &'a str {
        self.ssh.as_deref().unwrap_or(name)
    }

    /// Whether `argv` may run as `sudo -n` (it starts with an allowed entry's words).
    pub fn sudo_allows(&self, argv: &[&str]) -> bool {
        sentry_app::remote::allows(&self.sudo, argv)
    }

    pub fn timer_age(&self, unit: &str) -> Option<Duration> {
        self.timers
            .iter()
            .find(|t| t.unit == unit)
            .map(|t| t.max_age.0)
    }
}

pub fn path() -> PathBuf {
    FileId::Servers.path()
}

impl ConfigFile for ServerFile {
    const FILE: FileId = FileId::Servers;
    const FIELDS: &'static [Field] = FIELDS;
    fn parse(text: &str) -> Result<(Self, Vec<String>), String> {
        parse(text)
    }
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

pub use sentry_app::remote::host;

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
    let sus = &s.suscheck;
    match sus.on() {
        Some(d) => {
            if !d.starts_with('/') || d.chars().any(char::is_control) {
                p.push(format!(
                    "{name}: suscheck.dir `{}` isn't an absolute path",
                    d.escape_debug()
                ));
            } else if d.trim_end_matches('/').is_empty() {
                p.push(format!("{name}: suscheck.dir can't be `/`"));
            }
            if sus.recent == 0 || sus.recent > SUSCHECK_RECENT_MAX {
                p.push(format!(
                    "{name}: suscheck.recent is {}: 1 to {SUSCHECK_RECENT_MAX}",
                    sus.recent
                ));
            }
            if sus.ssh.as_deref().is_some_and(|h| {
                h.trim().is_empty() || h.starts_with('-') || h.contains(char::is_whitespace)
            }) {
                p.push(format!(
                    "{name}: suscheck.ssh should be an ssh alias or user@host"
                ));
            }
        }
        None if sus.ssh.is_some() => p.push(format!(
            "{name}: suscheck.ssh is set without suscheck.dir (the incidents folder)"
        )),
        None => {}
    }
    p
}

/// What is worth saying about a server's entry that isn't wrong: advice, never a problem.
/// `sentry-server lint` and `sentry config check` print these without failing, and the
/// Config area's check shows them as notes.
pub fn notes(name: &str, s: &Server) -> Vec<String> {
    let mut n = Vec::new();
    if s.suscheck.on().is_some() && s.suscheck.ssh.is_none() {
        n.push(format!(
            "{name}: suscheck has no login of its own (suscheck.ssh): the folder is read as \
             this server's ordinary login, the same one sentry's sessions run commands as, so \
             a session could read a household's checks. Give the folder a login of its own: a \
             second user in the folder's group, with the ordinary login left out of it"
        ));
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../assets/server_config.example.yaml");

    /// Every field at something other than its default, with names and values a YAML file has
    /// to quote.
    pub(crate) fn full() -> ServerFile {
        let item = MaintItem {
            id: "web".into(),
            image: Some(ImageRef {
                service: Some("web".into()),
                compose: Some("stack".into()),
                container: Some("yes".into()),
            }),
            apt: vec!["engine-pkg".into(), "1.10".into()],
            version_cmd: Some("/opt/app/bin/app --version: \"x\"".into()),
            unit: Some("app.service".into()),
            source: Some("github:example/web".into()),
            tag: Some("*-alpine".into()),
            risk: Risk::High,
            hold: Some("1.5 migrates the database one way; wait for 1.5.2 # not a comment".into()),
            constraint: Some(":needs the old api".into()),
            review_by: Some(jiff::civil::date(2027, 1, 15)),
            eol: Some("docker-engine".into()),
            workflow: Some("compose-bump".into()),
            retire: Some(Retire {
                replaced_by: Some("app.service".into()),
                workflow: Some("retire-service".into()),
            }),
        };
        let server = Server {
            ssh: Some("admin@myserver.example".into()),
            suscheck: Suscheck {
                dir: Some("/srv/suscheck/incidents".into()),
                ssh: Some("suscheck-reader@myserver.example".into()),
                recent: 50,
            },
            sudo: vec!["docker ps".into(), "no".into()],
            disks: vec![
                DiskRule {
                    mount: "/".into(),
                    warn: 70,
                    crit: 80,
                },
                DiskRule {
                    mount: "/srv/data".into(),
                    warn: 85,
                    crit: 95,
                },
            ],
            smart: vec!["/dev/sda".into()],
            services: vec!["app.service".into(), "null".into()],
            timers: vec![TimerRule {
                unit: "backup.timer".into(),
                max_age: Dur::hours(26),
            }],
            compose: vec![Compose {
                name: "stack".into(),
                file: "/home/admin/stack/compose.yaml".into(),
            }],
            containers: Containers {
                ignore: vec!["*-old".into()],
                restart_window: Dur::secs(600),
            },
            listeners: vec!["*:443/*".into(), "127.0.0.1:*/*".into(), "[::1]:*/*".into()],
            findings: vec!["srv:timer:*".into()],
            thresholds: Thresholds {
                mem: 80.5,
                load_per_core: 1.0,
                cpu_temp: 70.0,
                gpu_temp: 75.0,
            },
            actions: vec![CustomAction {
                id: "app-reload".into(),
                title: "Reload: the app's configuration".into(),
                run: "systemctl reload app.service && echo '{done}'".into(),
                sudo: true,
                risky: true,
                undo: Some("none needed".into()),
            }],
            maintenance: Maintenance {
                notes: vec!["~/notes/myserver runbook.md".into()],
                items: vec![
                    item,
                    MaintItem {
                        id: "bare".into(),
                        ..Default::default()
                    },
                ],
                cadence: [("apt-maintenance".to_string(), Dur::secs(30 * 86400))].into(),
            },
        };
        ServerFile {
            servers: [
                ("my.server-1".to_string(), server),
                ("empty".to_string(), Server::default()),
                (
                    "on".to_string(),
                    Server {
                        sudo: vec![],
                        maintenance: Maintenance {
                            items: vec![],
                            cadence: Default::default(),
                            notes: vec!["*".into()],
                        },
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        }
    }

    fn round_trip(f: &ServerFile) -> String {
        let text = sentry_core::cfg::render(f).unwrap_or_else(|e| panic!("{e}"));
        let (back, w) = parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        assert!(w.is_empty(), "{w:?}\n{text}");
        assert_eq!(&back, f, "{text}");
        text
    }

    #[test]
    fn what_sentry_writes_reads_back_as_what_it_was() {
        round_trip(&ServerFile::default());
        let (example, _) = parse(EXAMPLE).unwrap();
        let text = round_trip(&example);
        // As clean as before.
        let (back, _) = parse(&text).unwrap();
        for (n, s) in &back.servers {
            assert!(lint(n, s).is_empty(), "{:?}", lint(n, s));
        }
        insta::assert_snapshot!("example_rendered", text);
        let text = round_trip(&full());
        insta::assert_snapshot!("full_rendered", text);
    }

    #[test]
    fn every_setting_has_its_field() {
        let tree = sentry_core::cfg::Value::of(&full()).unwrap();
        assert_eq!(
            sentry_core::cfg::fields::uncovered(FIELDS, &tree),
            Vec::<String>::new()
        );
        assert_eq!(
            sentry_core::cfg::fields::unused(FIELDS, &tree),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn every_diff_applies() {
        let (example, _) = parse(EXAMPLE).unwrap();
        for (a, b) in [
            (ServerFile::default(), full()),
            (full(), example.clone()),
            (example, ServerFile::default()),
        ] {
            let mut x = a.clone();
            for c in sentry_core::cfg::diff(&a, &b).unwrap() {
                sentry_core::cfg::apply(&mut x, &c).unwrap_or_else(|e| panic!("{e}"));
            }
            assert_eq!(x, b);
        }
    }

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

    /// What the sample parses to, fixed before sentry could write the file: rendering it must
    /// never change what a file a user wrote by hand means.
    #[test]
    fn the_example_parses_to_what_it_always_did() {
        let (f, _) = parse(EXAMPLE).unwrap();
        insta::assert_snapshot!(serde_json::to_string_pretty(&f).unwrap());
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
    fn suscheck_is_off_without_a_folder_and_linted_when_on() {
        let (f, w) = parse("servers:\n  a: {}\n").unwrap();
        assert!(w.is_empty());
        let a = &f.servers["a"];
        assert_eq!((a.suscheck.on(), a.suscheck.recent), (None, 200));
        assert!(lint("a", a).is_empty() && notes("a", a).is_empty());
        let on = |text: &str| {
            let (f, w) = parse(&format!("servers:\n  a:\n    suscheck: {text}\n")).unwrap();
            assert!(w.is_empty(), "{w:?}");
            f.servers["a"].clone()
        };
        // On, with a login of its own: nothing to say.
        let s = on("{dir: /srv/suscheck/incidents, ssh: reader@myserver.example, recent: 50}");
        assert_eq!(s.suscheck.on(), Some("/srv/suscheck/incidents"));
        assert!(lint("a", &s).is_empty() && notes("a", &s).is_empty());
        // The same login as the sessions': a note, never a problem.
        let s = on("{dir: /srv/suscheck/incidents}");
        assert!(lint("a", &s).is_empty(), "{:?}", lint("a", &s));
        let n = notes("a", &s);
        assert_eq!(n.len(), 1);
        assert!(
            n[0].contains("the same one sentry's sessions run commands as")
                && n[0].contains("Give the folder a login of its own"),
            "{n:?}"
        );
        for (bad, why) in [
            ("{dir: srv/incidents}", "isn't an absolute path"),
            ("{dir: \"/srv/a\\nb\"}", "isn't an absolute path"),
            ("{dir: /}", "can't be `/`"),
            ("{dir: /srv/x, recent: 0}", "1 to 2000"),
            ("{dir: /srv/x, recent: 5000}", "1 to 2000"),
            ("{dir: /srv/x, ssh: \"-oProxyCommand=x\"}", "ssh alias"),
            ("{ssh: reader}", "without suscheck.dir"),
        ] {
            let p = lint("a", &on(bad));
            assert!(p.len() == 1 && p[0].contains(why), "{bad}: {p:?}");
        }
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

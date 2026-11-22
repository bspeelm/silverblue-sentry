//! The security audit across every target as one system (`sentry audit security`).
//!
//! Each target says what it knows as [`TargetFacts`] (optional sections: `None` is "couldn't
//! tell", never a guess). [`evaluate`] is the pure rules over all of them at once, grouped by
//! what an attacker would try, and gives [`Item`]s in plain language. The [`Report`] is the
//! app's own record, not a target's: `~/.config/sentry/system/security/<stamp>.toml`.
//!
//! Honesty: a rule fires only on evidence; what's missing is `CouldNotCheck` and says what it
//! would take; what only the user knows is an `Ask` with a remembered answer; there is no
//! score. Nothing here scans or probes: it reads configuration and state.
//!
//! Privacy: the fields the rules only match on (addresses) are never serialized and never
//! put into an item; evidence strings are written by the owning target, already scrubbed.

mod rules;
pub mod sshd;

use std::collections::BTreeMap;
use std::path::PathBuf;

use jiff::Timestamp;
use jiff::civil::Date;
use serde::{Deserialize, Serialize};

use crate::claude;
use crate::maint::Level;
use crate::maint::log::LogEntry;
use crate::maint::tasks::{Again, Source, Task};
use crate::paths;

pub use rules::{EDGE_FIX, evaluate};

// ---- what a target says

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Local,
    Server,
    Network,
}

/// Whether software is still looked after by whoever makes it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Eol {
    #[default]
    Unknown,
    Supported,
    /// Ends in this many days.
    Soon(i64),
    /// Ended this many days ago.
    Past(i64),
}

/// What one target knows. Every section is optional: `None` is "it couldn't tell".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TargetFacts {
    /// `local`, `srv:<name>`, `net:<name>`.
    pub id: String,
    pub kind: Kind,
    /// How the user calls it.
    pub name: String,
    /// It couldn't be reached at all: why.
    pub unreachable: Option<String>,
    /// (section, why it's missing)
    pub errors: Vec<(String, String)>,
    /// A server whose sudo asks for a password, with nothing read as root yet: what
    /// needs root there waits for its inventory (`I` on the server target).
    pub needs_inventory: bool,
    /// Its own addresses. Match only: never serialized, never in an item.
    #[serde(skip)]
    pub addrs: Vec<String>,
    pub os: Option<Os>,
    pub listeners: Option<Vec<Listen>>,
    pub ssh: Option<Ssh>,
    /// sudo runs anything without asking for a password.
    pub sudo_nopasswd: Option<bool>,
    pub containers: Option<Vec<Ctr>>,
    /// What maintenance tracks there: apps, images, packages.
    pub software: Option<Vec<Software>>,
    pub watch: Option<Watch>,
    pub backup: Option<Backup>,
    pub firewall: Option<HostFw>,
    pub keys: Option<Keys>,
    pub router: Option<Router>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Os {
    /// `Debian GNU/Linux 12 (bookworm)`, `Fedora Silverblue 44.2026…`.
    pub name: String,
    /// Updates waiting (none: not known).
    pub updates: Option<u32>,
    /// Of those, security fixes.
    pub security: Option<u32>,
    /// A restart is needed for an update already installed.
    pub reboot_pending: bool,
    /// Days since it was last updated.
    pub updated_days: Option<i64>,
    /// Security updates install by themselves.
    pub auto_updates: Option<bool>,
    pub eol: Eol,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Listen {
    pub proto: String,
    pub port: u16,
    /// Beyond the machine itself (not loopback only).
    pub wide: bool,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ssh {
    /// The ssh server runs.
    pub on: Option<bool>,
    /// Password logins are allowed.
    pub password: Option<bool>,
    /// `PermitRootLogin` as it stands (`yes`, `prohibit-password`, `no`).
    pub root: Option<String>,
    /// Where the settings were read (`sshd -T`, or its config files).
    pub source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ctr {
    pub name: String,
    pub image: String,
    pub privileged: bool,
    pub host_network: bool,
    pub docker_sock: bool,
    /// Host ports it publishes on every address.
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Software {
    pub id: String,
    pub running: Option<String>,
    pub latest: Option<String>,
    pub behind: bool,
    /// A newer release speaks of security fixes.
    pub security: bool,
    pub eol: Eol,
    /// The container it runs as, when it is one.
    pub container: Option<String>,
}

/// What watches for attacks and blocks them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Watch {
    /// CrowdSec's agent runs here (none: it isn't installed).
    pub crowdsec: Option<bool>,
    /// The kinds of bouncer registered with it and still pulling (none: not read).
    pub bouncers: Option<Vec<String>>,
    /// fail2ban jails that are on.
    pub jails: Option<usize>,
    /// On a router: its firewall enforces CrowdSec's bans.
    pub enforces: Option<bool>,
    /// On a router: the bouncer's package is there and isn't switched on.
    pub installed_off: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Backup {
    /// What looks like a backup there (a timer, a tool, a container), by name.
    pub signals: Vec<String>,
    /// How many backups sentry itself keeps (a router's config).
    pub count: Option<usize>,
    pub newest_days: Option<i64>,
    pub encrypted: Option<bool>,
    /// Changes made since the newest backup.
    pub unsaved: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostFw {
    pub active: bool,
    pub zone: Option<String>,
}

/// Private key files in `~/.ssh`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Keys {
    pub total: usize,
    /// Readable by other users of the machine.
    pub loose: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Router {
    pub wan_up: Option<bool>,
    /// The uplink's public IPv4 address, for the outside check. Match only.
    #[serde(skip)]
    pub wan_addr: Option<String>,
    pub firmware: Option<Firmware>,
    pub packages: Option<Packages>,
    pub forwards: Option<Vec<Forward>>,
    /// The firewall accepts whatever the internet sends to the router itself.
    pub wan_input_accept: Option<bool>,
    /// The router's own services the internet can reach.
    pub wan_listeners: Option<Vec<WanListen>>,
    /// Rules that let the internet reach devices directly (IPv6 has no NAT in the way):
    /// `tcp 8443 to lan`.
    pub v6_inbound: Option<Vec<String>>,
    pub ssh_password: Option<bool>,
    /// The admin page answers on plain HTTP without sending the browser to HTTPS.
    pub admin_http: Option<bool>,
    pub wifi: Option<Vec<Wifi>>,
    pub zones: Option<Vec<Zone>>,
    /// Live flows between zones the firewall keeps apart, when the audit looked.
    pub crossings: Option<Vec<Crossing>>,
    pub devices: Option<Devices>,
    pub dns_filter: Option<DnsFilter>,
    /// The log is kept somewhere that survives a reboot.
    pub log_kept: Option<bool>,
    pub outside: Option<Outside>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Firmware {
    pub version: String,
    pub latest: Option<String>,
    pub newer: bool,
    /// A newer release speaks of security fixes (none: its notes couldn't be read).
    pub security: Option<bool>,
    pub eol: Eol,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Packages {
    pub behind: usize,
    /// How old the router's package list is (none: it has none since it booted).
    pub index_days: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Forward {
    pub proto: String,
    /// The port, or `from-to`, the internet sees.
    pub port: String,
    /// The port it arrives on inside.
    pub to_port: String,
    /// The inside address it goes to. Match only.
    #[serde(skip)]
    pub dest: String,
    /// The zone that address is in, when known.
    pub zone: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WanListen {
    pub proto: String,
    pub port: u16,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Wifi {
    /// `Wi-Fi 1` (never the network's name).
    pub label: String,
    /// `none`, `wep`, `psk`, `psk2`, `sae`, `sae-mixed`, …
    pub encryption: String,
    pub wps: bool,
    /// Its clients are kept from the main network.
    pub guest: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Zone {
    pub name: String,
    /// It faces the internet.
    pub wan: bool,
    /// What the firewall does with traffic from it to the router: `ACCEPT`, `REJECT`, `DROP`.
    pub input: String,
    /// The zones its devices may open connections into.
    pub reaches: Vec<String>,
    /// Devices seen there (none: not counted).
    pub devices: Option<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Crossing {
    pub from: String,
    pub to: String,
    pub flows: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Devices {
    pub total: usize,
    /// Holding a lease, with no name in the config.
    pub unknown: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsFilter {
    pub on: bool,
    pub age_days: Option<i64>,
}

/// What the user's own outside check said (`[audit] outside`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Outside {
    pub asked: Vec<u16>,
    pub open: Vec<u16>,
    /// It couldn't be run: why.
    pub error: Option<String>,
}

impl TargetFacts {
    pub fn new(id: &str, kind: Kind, name: &str) -> Self {
        Self {
            id: id.into(),
            kind,
            name: name.into(),
            ..Default::default()
        }
    }

    /// A target that didn't answer: everything about it is "couldn't check".
    pub fn unreachable(id: &str, kind: Kind, name: &str, why: &str) -> Self {
        Self {
            unreachable: Some(why.into()),
            ..Self::new(id, kind, name)
        }
    }
}

/// What looks like a backup by its name: a unit, a timer, a container, an app.
const BACKUP_WORDS: &[&str] = &[
    "backup",
    "restic",
    "borg",
    "rsnapshot",
    "duplicity",
    "duplicati",
    "dejadup",
    "deja-dup",
    "kopia",
    "rclone",
    "snapper",
    "timeshift",
    "sanoid",
    "syncoid",
    "vorta",
];

pub fn backup_signal(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    // (dpkg's own `dpkg-db-backup` keeps a copy of the package list, not of anyone's data.)
    !n.starts_with("dpkg-") && BACKUP_WORDS.iter().any(|w| n.contains(w))
}

/// An address only the machine itself can reach (as `ss` and docker write them).
pub fn loopback(addr: &str) -> bool {
    let a = addr.trim_matches(|c| c == '[' || c == ']');
    let a = a.split('%').next().unwrap_or(a);
    a.starts_with("127.") || a == "::1" || a == "localhost"
}

// ---- what the audit says

/// What an attacker would try, in the order the report goes through them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Group {
    GettingIn,
    KnownHoles,
    Logins,
    MovingAround,
    Recovering,
}

impl Group {
    pub const ALL: [Group; 5] = [
        Group::GettingIn,
        Group::KnownHoles,
        Group::Logins,
        Group::MovingAround,
        Group::Recovering,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Group::GettingIn => "Getting in from the internet",
            Group::KnownHoles => "Known holes",
            Group::Logins => "Logins",
            Group::MovingAround => "Moving around once inside",
            Group::Recovering => "Noticing and recovering",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    DoFirst,
    Worth,
    Fine,
    CouldNotCheck,
    Ask,
}

impl State {
    /// How open it is, for comparing two reports: higher is worse.
    pub fn weight(self) -> u8 {
        match self {
            State::DoFirst => 3,
            State::Worth => 2,
            State::Ask | State::CouldNotCheck => 1,
            State::Fine => 0,
        }
    }
}

/// The order inside "Do these first" (`Item.rank`, lower first). Explicit and small:
/// what the internet can reach without a login or with known holes comes before weak
/// logins on what it can reach, then software nobody fixes any more, then a network where
/// one broken device reaches all the others, then what would make recovering hard.
pub mod rank {
    pub const EXPOSED: u8 = 0;
    pub const WEAK_LOGIN: u8 = 1;
    pub const OUTDATED: u8 = 2;
    pub const FLAT: u8 = 3;
    pub const RECOVERY: u8 = 4;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    /// Stable across reports: `sec:door:net:home:tcp:443`.
    pub id: String,
    pub group: Group,
    pub state: State,
    /// See [`rank`].
    #[serde(default)]
    pub rank: u8,
    /// One plain sentence.
    pub title: String,
    /// What could happen.
    #[serde(default)]
    pub why: String,
    /// What it takes.
    #[serde(default)]
    pub fix: String,
    /// The targets it's about (`local`, `srv:<name>`, `net:<name>`).
    #[serde(default)]
    pub targets: Vec<String>,
    /// Short, already scrubbed.
    #[serde(default)]
    pub evidence: Vec<String>,
    /// What a session that fixes it is told.
    #[serde(default)]
    pub brief: String,
    /// An `Ask`: the key its answer is remembered under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub question: Option<String>,
}

impl Item {
    /// The existing apply `Ask` for a session on this item: the caller opens it on the
    /// first of `targets` (or across them). `remote` when that isn't this machine.
    pub fn ask(&self) -> claude::Ask {
        let mut context = format!("Security audit · {}\n{}\n", self.group.title(), self.title);
        if !self.why.is_empty() {
            context.push_str(&format!("Why it matters: {}\n", self.why));
        }
        if !self.targets.is_empty() {
            context.push_str(&format!("About: {}\n", self.targets.join(", ")));
        }
        if !self.evidence.is_empty() {
            context.push_str("What the audit saw:\n");
            for e in &self.evidence {
                context.push_str(&format!("- {e}\n"));
            }
        }
        claude::Ask {
            subject: format!("Security · {}", self.title),
            context,
            question: self.brief.clone(),
            target: Some(claude::Target::Apply(claude::Apply {
                key: self.id.clone(),
                remote: self.targets.first().is_some_and(|t| t != LOCAL),
                ..Default::default()
            })),
        }
    }
}

/// This machine's target id.
pub const LOCAL: &str = "local";

// ---- what only the user knows

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Answer {
    /// `yes` or `no`.
    pub answer: String,
    pub at: Date,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// `system/security/answers.toml`: what the user said, and when.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Answers {
    #[serde(default)]
    pub answers: BTreeMap<String, Answer>,
}

impl Answers {
    pub fn path() -> PathBuf {
        dir().join("answers.toml")
    }

    pub fn load() -> Self {
        std::fs::read_to_string(Self::path())
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        paths::write_atomic(&Self::path(), toml::to_string(self)?.as_bytes())?;
        Ok(())
    }

    /// `Some(true)` yes, `Some(false)` no, `None` never answered.
    pub fn get(&self, key: &str) -> Option<bool> {
        self.answers.get(key).map(|a| a.answer == "yes")
    }

    /// Remember an answer given today, on disk.
    pub fn remember(key: &str, yes: bool) -> anyhow::Result<()> {
        let mut a = Self::load();
        a.set(key, yes, jiff::Zoned::now().date());
        a.save()
    }

    pub fn set(&mut self, key: &str, yes: bool, today: Date) {
        self.answers.insert(
            key.to_string(),
            Answer {
                answer: if yes { "yes" } else { "no" }.into(),
                at: today,
                note: String::new(),
            },
        );
    }
}

// ---- the report

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Seen {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub reached: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Missing {
    pub target: String,
    pub section: String,
    pub why: String,
}

/// Against the report before: ids.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Diff {
    /// There was no report before.
    pub first: bool,
    /// Open now, not listed before (or fine then).
    pub new: Vec<String>,
    /// Open before, fine or gone now.
    pub fixed: Vec<String>,
    /// More pressing than it was.
    pub worse: Vec<String>,
    /// Less pressing than it was, but still open.
    pub better: Vec<String>,
    pub same: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub version: u32,
    pub at: Timestamp,
    #[serde(default)]
    pub targets: Vec<Seen>,
    /// The exposure was checked from outside (`[audit] outside`), not only read from config.
    #[serde(default)]
    pub observed: bool,
    #[serde(default)]
    pub items: Vec<Item>,
    /// What the targets couldn't read.
    #[serde(default)]
    pub errors: Vec<Missing>,
    #[serde(default)]
    pub diff: Diff,
}

fn open(s: State) -> bool {
    matches!(s, State::DoFirst | State::Worth)
}

/// What changed between two reports' items, by id.
pub fn diff(prev: &[Item], now: &[Item]) -> Diff {
    let before: BTreeMap<&str, State> = prev.iter().map(|i| (i.id.as_str(), i.state)).collect();
    let mut d = Diff::default();
    for i in now {
        match before.get(i.id.as_str()) {
            None if i.state != State::Fine => d.new.push(i.id.clone()),
            None => d.same += 1,
            Some(&was) if open(was) && i.state == State::Fine => d.fixed.push(i.id.clone()),
            Some(&was) if was == State::Fine && i.state != State::Fine => d.new.push(i.id.clone()),
            Some(&was) if i.state.weight() > was.weight() => d.worse.push(i.id.clone()),
            Some(&was) if i.state.weight() < was.weight() => d.better.push(i.id.clone()),
            Some(_) => d.same += 1,
        }
    }
    for p in prev {
        if open(p.state) && !now.iter().any(|i| i.id == p.id) {
            d.fixed.push(p.id.clone());
        }
    }
    d
}

impl Report {
    /// Evaluate, and compare with the report before.
    pub fn build(
        facts: &[TargetFacts],
        answers: &Answers,
        prev: Option<&Report>,
        at: Timestamp,
    ) -> Self {
        let today = at.to_zoned(jiff::tz::TimeZone::UTC).date();
        let items = evaluate(facts, answers, today);
        let diff = match prev {
            Some(p) => diff(&p.items, &items),
            None => Diff {
                first: true,
                ..Default::default()
            },
        };
        Report {
            version: 1,
            at,
            targets: facts
                .iter()
                .map(|f| Seen {
                    id: f.id.clone(),
                    name: f.name.clone(),
                    kind: f.kind,
                    reached: f.unreachable.is_none(),
                })
                .collect(),
            observed: facts.iter().any(|f| {
                f.router
                    .as_ref()
                    .and_then(|r| r.outside.as_ref())
                    .is_some_and(|o| o.error.is_none())
            }),
            items,
            errors: facts
                .iter()
                .flat_map(|f| {
                    f.unreachable
                        .iter()
                        .map(|w| ("reach".to_string(), w.clone()))
                        .chain(f.errors.iter().cloned())
                        .map(|(section, why)| Missing {
                            target: f.id.clone(),
                            section,
                            why,
                        })
                })
                .collect(),
            diff,
        }
    }

    /// The whole of one audit: evaluate with the remembered answers, compare with the
    /// report before, save.
    pub fn finish(facts: &[TargetFacts]) -> anyhow::Result<(Self, PathBuf)> {
        let prev = latest();
        let r = Self::build(facts, &Answers::load(), prev.as_ref(), Timestamp::now());
        let path = save(&r)?;
        Ok((r, path))
    }

    /// One line for a log entry or a toast.
    pub fn summary(&self) -> String {
        format!(
            "{} to do first, {} worth doing, {} fine, {} couldn't be checked or need an answer",
            self.of(State::DoFirst).len(),
            self.of(State::Worth).len(),
            self.of(State::Fine).len(),
            self.of(State::Ask).len() + self.of(State::CouldNotCheck).len()
        )
    }

    pub fn of(&self, s: State) -> Vec<&Item> {
        self.items.iter().filter(|i| i.state == s).collect()
    }

    /// Nothing at all could be read from any target.
    pub fn empty(&self) -> bool {
        self.targets.iter().all(|t| !t.reached)
    }
}

// ---- where reports live

/// The app's own scope, not a target's.
pub fn dir() -> PathBuf {
    paths::config_dir().join("system").join("security")
}

/// Reports kept.
pub const KEEP: usize = 24;

fn stamp(at: Timestamp) -> String {
    at.strftime("%Y%m%dT%H%M%SZ").to_string()
}

fn reports_in(d: &std::path::Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "toml")
                && p.file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.len() == 16 && s.starts_with("20") && s.ends_with('Z'))
        })
        .collect();
    v.sort();
    v.reverse();
    v
}

pub fn save_in(d: &std::path::Path, r: &Report) -> anyhow::Result<PathBuf> {
    let path = d.join(format!("{}.toml", stamp(r.at)));
    paths::write_atomic(&path, toml::to_string(r)?.as_bytes())?;
    for old in reports_in(d).into_iter().skip(KEEP) {
        let _ = std::fs::remove_file(old.with_extension("review.md"));
        let _ = std::fs::remove_file(old);
    }
    Ok(path)
}

/// Claude's review of a report, kept beside it (`<stamp>.review.md`).
pub fn save_review(r: &Report, text: &str) -> anyhow::Result<()> {
    let path = dir().join(format!("{}.review.md", stamp(r.at)));
    paths::write_atomic(&path, text.as_bytes())?;
    Ok(())
}

pub fn review_of(r: &Report) -> Option<String> {
    std::fs::read_to_string(dir().join(format!("{}.review.md", stamp(r.at))))
        .ok()
        .filter(|t| !t.trim().is_empty())
}

pub fn save(r: &Report) -> anyhow::Result<PathBuf> {
    save_in(&dir(), r)
}

pub fn latest_in(d: &std::path::Path) -> Option<Report> {
    reports_in(d)
        .into_iter()
        .find_map(|p| toml::from_str(&std::fs::read_to_string(p).ok()?).ok())
}

/// The newest report (by listing the directory).
pub fn latest() -> Option<Report> {
    latest_in(&dir())
}

// ---- in words

/// What a tool like this can and cannot do: the report's first lines.
pub const LIMITS: [&str; 3] = [
    "This audit reads the configuration and state of the devices sentry manages. It doesn't \
     attack anything and doesn't look inside your traffic.",
    "It can't see inside devices sentry doesn't manage (phones, TVs, cameras): only that \
     they are there.",
    "It can't stop someone being tricked into giving a password away or installing something. \
     It makes that cost less: fewer doors, fewer old holes, less to reach from one device.",
];

fn section(out: &mut String, title: &str, items: &[&Item], rep: &Report, detail: bool) {
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("\n{title} ({})\n", items.len()));
    for g in Group::ALL {
        let of: Vec<&&Item> = items.iter().filter(|i| i.group == g).collect();
        if of.is_empty() {
            continue;
        }
        out.push_str(&format!("\n  {}\n", g.title()));
        if g == Group::GettingIn && !rep.observed {
            out.push_str("  (inferred from configuration, not observed from outside)\n");
        }
        for i in of {
            let mark = if rep.diff.new.contains(&i.id) {
                " [new]"
            } else if rep.diff.worse.contains(&i.id) {
                " [worse]"
            } else {
                ""
            };
            out.push_str(&format!("  - {}{mark}\n", i.title));
            if detail {
                if !i.why.is_empty() {
                    out.push_str(&format!("      Why: {}\n", i.why));
                }
                if !i.fix.is_empty() {
                    out.push_str(&format!("      What it takes: {}\n", i.fix));
                }
                for e in &i.evidence {
                    out.push_str(&format!("      · {e}\n"));
                }
            }
            if let Some(q) = &i.question {
                out.push_str(&format!(
                    "      Answer: sentry audit security answers {q} yes|no\n"
                ));
            }
        }
    }
}

/// The report as plain text.
pub fn render(r: &Report) -> String {
    let mut out = String::from("Security audit");
    out.push_str(&format!(" · {}\n", r.at.strftime("%Y-%m-%d %H:%M UTC")));
    for l in LIMITS {
        out.push_str(&format!("{l}\n"));
    }
    let names: Vec<String> = r
        .targets
        .iter()
        .map(|t| {
            if t.reached {
                t.name.clone()
            } else {
                format!("{} (not reached)", t.name)
            }
        })
        .collect();
    out.push_str(&format!("\nLooked at: {}\n", names.join(", ")));

    let first = {
        let mut v = r.of(State::DoFirst);
        v.sort_by_key(|i| i.rank);
        v
    };
    if first.is_empty() {
        out.push_str("\nDo these first (0)\n  Nothing the audit can see needs doing first.\n");
    } else {
        // Ranked, not grouped: the order is the point.
        out.push_str(&format!("\nDo these first ({})\n", first.len()));
        if !r.observed && first.iter().any(|i| i.group == Group::GettingIn) {
            out.push_str(
                "  (what the internet can reach is inferred from configuration, not observed \
                 from outside)\n",
            );
        }
        for (n, i) in first.iter().enumerate() {
            let mark = if r.diff.new.contains(&i.id) {
                " [new]"
            } else if r.diff.worse.contains(&i.id) {
                " [worse]"
            } else {
                ""
            };
            out.push_str(&format!("  {}. {}{mark}\n", n + 1, i.title));
            out.push_str(&format!("      Why: {}\n", i.why));
            out.push_str(&format!("      What it takes: {}\n", i.fix));
            for e in &i.evidence {
                out.push_str(&format!("      · {e}\n"));
            }
        }
    }
    section(&mut out, "Worth doing", &r.of(State::Worth), r, true);
    section(&mut out, "Fine", &r.of(State::Fine), r, false);
    let mut rest = r.of(State::Ask);
    rest.extend(r.of(State::CouldNotCheck));
    section(
        &mut out,
        "Couldn't check / need your answer",
        &rest,
        r,
        true,
    );
    if !r.errors.is_empty() {
        out.push_str("\nNot read\n");
        for e in &r.errors {
            let name = r
                .targets
                .iter()
                .find(|t| t.id == e.target)
                .map_or(e.target.as_str(), |t| t.name.as_str());
            out.push_str(&format!("  - {name} · {}: {}\n", e.section, e.why));
        }
    }
    if !r.diff.first {
        out.push_str(&format!(
            "\nSince the last audit: {} new, {} fixed, {} worse, {} better, {} the same.\n",
            r.diff.new.len(),
            r.diff.fixed.len(),
            r.diff.worse.len(),
            r.diff.better.len(),
            r.diff.same
        ));
        for id in &r.diff.fixed {
            out.push_str(&format!("  fixed: {id}\n"));
        }
    }
    out
}

/// What Claude's review of the evidence is asked (layer 2). Only what the items hold:
/// titles, states and evidence, which the targets scrubbed before it got here. The answer
/// is prose; it changes no tasks, so it ends in no `sentry-changes` block.
pub fn review_brief(r: &Report) -> String {
    let mut out = String::from(
        "This is the evidence of a security audit sentry ran across the user's own devices \
         (a workstation, servers, a home router), as one system. The user is not a security \
         expert and wants to be well guarded against attacks, including AI-assisted ones \
         that find and try every door quickly.\n\n\
         Your job:\n\
         - Order what matters most HERE, in plain words: for each, one sentence on what \
         could happen and what it takes to fix. A handful first, the rest after.\n\
         - Look up security advisories for the exact software versions listed (the web), and \
         say which apply. Name the advisory.\n\
         - Never invent a finding the evidence below doesn't hold. If you suspect something \
         the evidence can't show, say it under what couldn't be checked, with what would \
         show it.\n\
         - Say what couldn't be checked and what the user was asked.\n\
         - No score, no grades. Don't ask the user to run or paste anything.\n\
         - Addresses, device names and network names were left out on purpose: don't ask \
         for them.\n\n\
         Sections:\n\
         ## Do these first\n## Worth doing\n## Fine as it is\n## Couldn't check\n\n",
    );
    out.push_str(&format!(
        "Evidence ({}; exposure {}):\n",
        r.at.strftime("%Y-%m-%d"),
        if r.observed {
            "checked from outside"
        } else {
            "inferred from configuration, not observed from outside"
        }
    ));
    for g in Group::ALL {
        out.push_str(&format!("\n### {}\n", g.title()));
        for i in r.items.iter().filter(|i| i.group == g) {
            let state = match i.state {
                State::DoFirst => "do first",
                State::Worth => "worth doing",
                State::Fine => "fine",
                State::CouldNotCheck => "couldn't check",
                State::Ask => "asked of the user, not answered",
            };
            out.push_str(&format!("- [{state}] {} ({})\n", i.title, i.id));
            for e in &i.evidence {
                out.push_str(&format!("  - {e}\n"));
            }
        }
    }
    if !r.errors.is_empty() {
        out.push_str("\n### Not read\n");
        for e in &r.errors {
            out.push_str(&format!("- {} · {}: {}\n", e.target, e.section, e.why));
        }
    }
    out
}

// ---- the outside check

/// Management ports checked besides the forwarded ones: a short fixed list.
pub const MGMT_PORTS: [u16; 7] = [22, 23, 80, 443, 7547, 8080, 8443];

/// The user's own outside check: `template` with `{address}` and `{ports}` (comma
/// separated) filled in, run on this machine; it prints the open ports, one per line.
/// Only an address literal and numbers are ever put into the line.
pub fn outside_line(template: &str, address: &str, ports: &[u16]) -> Result<String, String> {
    let ip: std::net::IpAddr = address
        .parse()
        .map_err(|_| "the uplink's address isn't an address".to_string())?;
    if !template.contains("{address}") {
        return Err("[audit] outside has no {address}".into());
    }
    let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
    Ok(template
        .replace("{address}", &ip.to_string())
        .replace("{ports}", &ports.join(",")))
}

/// The open ports the command printed: numbers that were asked for, nothing else.
pub fn outside_parse(text: &str, asked: &[u16]) -> Vec<u16> {
    let mut open: Vec<u16> = text
        .lines()
        .filter_map(|l| {
            let w = l.split_whitespace().next()?;
            w.split('/').next()?.parse::<u16>().ok()
        })
        .filter(|p| asked.contains(p))
        .collect();
    open.sort_unstable();
    open.dedup();
    open
}

/// Run the outside check for one router's facts (its uplink's address, its forwarded TCP
/// ports and [`MGMT_PORTS`]). Nothing but the user's own command is run.
pub fn outside(template: &str, router: &Router) -> Outside {
    let mut asked: Vec<u16> = MGMT_PORTS.to_vec();
    for f in router.forwards.iter().flatten() {
        if f.proto != "udp"
            && let Ok(p) = f.port.parse::<u16>()
        {
            asked.push(p);
        }
    }
    asked.sort_unstable();
    asked.dedup();
    let fail = |why: String| Outside {
        asked: asked.clone(),
        open: Vec::new(),
        error: Some(why),
    };
    let Some(addr) = &router.wan_addr else {
        return fail("the uplink has no public IPv4 address to check".into());
    };
    let line = match outside_line(template, addr, &asked) {
        Ok(l) => l,
        Err(e) => return fail(e),
    };
    let cmd = crate::exec::Cmd::host("sh")
        .args(["-c", &line])
        .timeout(Some(std::time::Duration::from_secs(120)));
    match cmd.output() {
        Ok(text) => Outside {
            open: outside_parse(&text, &asked),
            asked,
            error: None,
        },
        Err(e) => fail(format!("the outside check failed: {e}")),
    }
}

// ---- the task

pub const TASK_ID: &str = "security-audit";

/// "Run the security audit", every 30 days: a derived task for this machine's slot (the
/// audit is the whole system's, and this machine is where sentry runs). Due again before
/// its time when a firmware or OS upgrade was logged after the last report: `logs` are the
/// targets' maintenance logs.
pub fn task(last: Option<Timestamp>, logs: &[LogEntry]) -> Task {
    let again = upgraded_since(last, logs).map(|(at, what)| Again {
        at,
        why: format!("{what} since the last security audit"),
    });
    Task {
        id: TASK_ID.into(),
        title: "Run the security audit".into(),
        why: "What the internet can reach, old software and weak logins change as things are \
              installed and updated."
            .into(),
        level: Level::Routine,
        every: "30d".parse().ok(),
        act: "by-hand".into(),
        item: None,
        steps: "Run `sentry audit security` and read \"Do these first\".".into(),
        added: None,
        off: false,
        source: Source::Default,
        review: None,
        after: None,
        again,
    }
}

/// An upgrade of firmware or of an operating system that ended well after `last`.
fn upgraded_since(last: Option<Timestamp>, logs: &[LogEntry]) -> Option<(Timestamp, String)> {
    let last = last?;
    logs.iter()
        .filter(|e| e.head.result == "done")
        .filter(|e| {
            let w = e.head.workflow.as_str();
            e.head.kind == "release"
                || [
                    "firmware",
                    "release",
                    "rebase",
                    "dist-upgrade",
                    "os-upgrade",
                ]
                .iter()
                .any(|k| w.contains(k))
        })
        .filter_map(|e| Some((e.head.ended.or(e.head.started)?, e)))
        .filter(|(at, _)| *at > last)
        .max_by_key(|(at, _)| *at)
        .map(|(at, e)| (at, format!("{} ran", e.head.workflow)))
}

/// The log entry that marks the task done (the CLI writes it on this machine's log).
pub fn done_entry(summary: &str) -> LogEntry {
    LogEntry::task("", TASK_ID, "Run the security audit", Some(summary))
}

#[cfg(test)]
mod tests;

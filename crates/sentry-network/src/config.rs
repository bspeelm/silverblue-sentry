//! `~/.config/sentry/network_config.yaml`: the networks sentry knows, each through its router,
//! and what is expected on each. What you said: written only through core's `cfg`
//! (`sentry-network init` adds a network, `sentry config`), which keeps the file before beside
//! it; a hand-edited file's comments are not kept on the next save. What sentry records
//! itself (what's marked expected, which clients were seen, names given in the window) goes
//! under `networks/<name>/` beside it.
//!
//! The whole shape is read from the start, so the file doesn't change as the Clients, Network
//! and Maintenance screens arrive: `expect`, `devices`, `backup`, `maintenance`, `notes` and
//! `claude` are parsed and linted here and used by those.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use sentry_core::cfg::{ConfigFile, Field, FileId, Kind};
use sentry_core::config::Dur;

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct NetworkFile {
    pub networks: BTreeMap<String, Network>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Network {
    pub router: RouterCfg,
    /// What the firewall and the listeners should look like (the audit compares).
    pub expect: Expect,
    /// The devices you know: everything else that takes a lease is new.
    pub devices: Vec<Device>,
    pub thresholds: Thresholds,
    pub backup: Backup,
    pub maintenance: Maintenance,
    /// Local files Claude may read when planning or reviewing (runbooks, notes).
    pub notes: Vec<String>,
    pub claude: ClaudeCfg,
    pub guard: GuardCfg,
}

/// The guard around a change to the configs the network is reached through.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct GuardCfg {
    /// Seconds the router waits for the change to be confirmed before it takes it back
    /// by itself.
    pub window: u64,
}

impl Default for GuardCfg {
    fn default() -> Self {
        Self { window: 300 }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct RouterCfg {
    /// What `ssh` connects to (an alias from `~/.ssh/config`, or `root@host`); the login is
    /// root. Default: the network's name.
    pub ssh: Option<String>,
    pub kind: RouterKind,
}

/// The router's system. Only OpenWrt is known.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RouterKind {
    #[default]
    Openwrt,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Expect {
    /// Each firewall zone and the interfaces in it, as `uci show firewall` names them.
    pub zones: BTreeMap<String, Vec<String>>,
    /// The port forwards that should exist (and no others).
    pub forwards: Vec<Forward>,
    /// What may listen on the router, `proto:port@zone` (`tcp:22@lan`).
    pub listeners: Vec<String>,
    /// Services that must be running, besides dnsmasq, dropbear and uhttpd (watched
    /// wherever they are installed): names as `ubus call service list` has them.
    pub services: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Forward {
    pub name: String,
    /// `tcp`, `udp` or `any`.
    #[serde(default = "tcp")]
    pub proto: String,
    /// The port on the WAN side, or a range (`8000-8010`).
    pub port: Ports,
    /// The address it goes to.
    pub to: String,
}

fn tcp() -> String {
    "tcp".into()
}

/// One port, or a range of them (`from` ≤ `to`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    pub from: u16,
    pub to: u16,
}

impl std::fmt::Display for Ports {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.from == self.to {
            write!(f, "{}", self.from)
        } else {
            write!(f, "{}-{}", self.from, self.to)
        }
    }
}

impl std::str::FromStr for Ports {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("bad port {s:?} (a number, or a range like 8000-8010)");
        let (a, b) = s.trim().split_once('-').unwrap_or((s.trim(), s.trim()));
        let from: u16 = a.trim().parse().map_err(|_| bad())?;
        let to: u16 = b.trim().parse().map_err(|_| bad())?;
        if from == 0 || to < from {
            return Err(bad());
        }
        Ok(Self { from, to })
    }
}

impl<'de> Deserialize<'de> for Ports {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Ports;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a port number or a range like 8000-8010")
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Ports, E> {
                v.to_string().parse().map_err(E::custom)
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Ports, E> {
                v.to_string().parse().map_err(E::custom)
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Ports, E> {
                v.parse().map_err(E::custom)
            }
        }
        d.deserialize_any(V)
    }
}

impl Serialize for Ports {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.from == self.to {
            s.serialize_u16(self.from)
        } else {
            s.collect_str(self)
        }
    }
}

/// A device you know, by its MAC or (for one that randomises its MAC) the hostname it gives.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Device {
    pub name: Option<String>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    /// Nothing sentry or Claude does may touch it (told to Claude by name).
    pub leave_alone: bool,
    /// It uses a private (randomised) MAC: known by `hostname` instead.
    pub private_mac: bool,
}

impl Device {
    /// What to call it: its name, else its hostname, else its MAC.
    pub fn label(&self) -> &str {
        self.name
            .as_deref()
            .or(self.hostname.as_deref())
            .or(self.mac.as_deref())
            .unwrap_or("?")
    }
}

/// A MAC as sentry compares them: six lowercase hex pairs with colons. None: not a MAC.
pub fn mac(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase().replace('-', ":");
    let parts: Vec<&str> = s.split(':').collect();
    (parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit())))
    .then_some(s)
}

/// A locally administered MAC (the second-lowest bit of its first byte): what a phone's
/// "private address" is, and never a vendor's.
pub fn local_mac(mac: &str) -> bool {
    u8::from_str_radix(mac.get(..2).unwrap_or(""), 16).is_ok_and(|b| b & 0x02 != 0)
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Thresholds {
    /// The 1-minute load that counts as high.
    pub load: f32,
    /// Memory in use, percent.
    pub mem_pct: f32,
    /// The web interface's certificate: days left that count as soon.
    pub cert_days: u32,
    /// A config backup older than this is due.
    pub backup_age: Dur,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            load: 2.0,
            mem_pct: 85.0,
            cert_days: 21,
            backup_age: Dur::secs(30 * 86400),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Backup {
    /// Who can decrypt a backup: age recipients (`age1…`), or files holding one a line.
    /// sentry never has the secret key.
    pub recipients: Vec<String>,
    /// How many of the newest backups are kept.
    pub keep: u32,
}

impl Default for Backup {
    fn default() -> Self {
        Self {
            recipients: Vec::new(),
            keep: 12,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Maintenance {
    pub items: Vec<Item>,
    /// How often a routine workflow should run.
    pub cadence: Vec<Cadence>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Item {
    pub id: String,
    pub kind: ItemKind,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    Firmware,
    Packages,
    Backup,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Cadence {
    pub workflow: String,
    pub every: Dur,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ClaudeCfg {
    /// Claude may see the WAN address (off: it is scrubbed from what's sent).
    pub share_wan_address: bool,
}

impl Network {
    /// The ssh destination.
    pub fn ssh_target<'a>(&'a self, name: &'a str) -> &'a str {
        self.router.ssh.as_deref().unwrap_or(name)
    }
}

pub fn path() -> PathBuf {
    FileId::Networks.path()
}

impl ConfigFile for NetworkFile {
    const FILE: FileId = FileId::Networks;
    const FIELDS: &'static [Field] = FIELDS;
    fn parse(text: &str) -> Result<(Self, Vec<String>), String> {
        parse(text)
    }
}

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

/// Every setting of network_config.yaml (`sentry config explain`; the forms).
pub const FIELDS: &[Field] = &[
    f(
        "networks",
        "Networks",
        Kind::Map,
        true,
        "Each entry is one network, seen through its router over ssh, by its name (one word: it names a directory and `net:<name>`).",
    ),
    f(
        "networks.*.router",
        "Router",
        Kind::Section,
        true,
        "The router the network is seen through.",
    ),
    f(
        "networks.*.router.ssh",
        "Router ssh",
        Kind::Text,
        true,
        "What `ssh` connects to (an alias from ~/.ssh/config, or root@host); the login is root, with a key. Default: the network's name.",
    ),
    f(
        "networks.*.router.kind",
        "Router kind",
        Kind::Choice(&["openwrt"]),
        false,
        "The router's system. Only OpenWrt is known.",
    ),
    f(
        "networks.*.expect",
        "Expected",
        Kind::Section,
        true,
        "What the firewall and the listeners should look like (the audit compares).",
    ),
    f(
        "networks.*.expect.zones",
        "Zones",
        Kind::Map,
        true,
        "Each firewall zone and the interfaces in it, as `uci show firewall` names them.",
    ),
    f(
        "networks.*.expect.zones.*",
        "Zone's interfaces",
        Kind::List,
        true,
        "The interfaces in that zone.",
    ),
    f(
        "networks.*.expect.forwards",
        "Port forwards",
        Kind::Records,
        true,
        "The port forwards that should exist (and no others).",
    ),
    f(
        "networks.*.expect.forwards[].name",
        "Name",
        Kind::Text,
        true,
        "The forward's name, as the firewall has it.",
    ),
    f(
        "networks.*.expect.forwards[].proto",
        "Protocol",
        Kind::Choice(&["tcp", "udp", "any"]),
        true,
        "`tcp`, `udp` or `any` (tcp).",
    ),
    f(
        "networks.*.expect.forwards[].port",
        "Port",
        Kind::Text,
        true,
        "The port on the WAN side, or a range (`8000-8010`).",
    ),
    f(
        "networks.*.expect.forwards[].to",
        "To",
        Kind::Text,
        true,
        "The inside address it goes to (192.0.2.20).",
    ),
    f(
        "networks.*.expect.listeners",
        "Listeners",
        Kind::List,
        false,
        "What may listen on the router, `proto:port@zone` (`tcp:22@lan`).",
    ),
    f(
        "networks.*.expect.services",
        "Services",
        Kind::List,
        false,
        "Services that must be running, besides dnsmasq, dropbear and uhttpd (watched wherever they are installed): names as `ubus call service list` has them.",
    ),
    f(
        "networks.*.devices",
        "Devices",
        Kind::Records,
        true,
        "The devices you know: everything else that takes a lease is new.",
    ),
    f(
        "networks.*.devices[].name",
        "Name",
        Kind::Text,
        true,
        "What to call it: shown wherever the device is, instead of its MAC.",
    ),
    f(
        "networks.*.devices[].mac",
        "MAC",
        Kind::Text,
        true,
        "Its MAC address (02:00:5e:00:53:01).",
    ),
    f(
        "networks.*.devices[].hostname",
        "Hostname",
        Kind::Text,
        true,
        "The hostname it gives: how a device with a private MAC is known.",
    ),
    f(
        "networks.*.devices[].leave_alone",
        "Leave alone",
        Kind::Bool,
        true,
        "Nothing sentry or Claude does may touch it (told to Claude by name).",
    ),
    f(
        "networks.*.devices[].private_mac",
        "Private MAC",
        Kind::Bool,
        true,
        "It uses a private (randomised) MAC: known by `hostname` instead.",
    ),
    f(
        "networks.*.thresholds",
        "Thresholds",
        Kind::Section,
        false,
        "When the Dashboard and the audit call something high, soon or old.",
    ),
    f(
        "networks.*.thresholds.load",
        "Load",
        Kind::Number,
        false,
        "The 1-minute load that counts as high (2.0).",
    ),
    f(
        "networks.*.thresholds.mem_pct",
        "Memory",
        Kind::Number,
        false,
        "Memory in use, percent (85).",
    ),
    f(
        "networks.*.thresholds.cert_days",
        "Certificate days",
        Kind::Number,
        false,
        "The web interface's certificate: days left that count as soon (21).",
    ),
    f(
        "networks.*.thresholds.backup_age",
        "Backup age",
        Kind::Duration,
        false,
        "A config backup older than this is due (30d).",
    ),
    f(
        "networks.*.backup",
        "Backups",
        Kind::Section,
        true,
        "Encrypted config backups (`sentry-network backup`, the config-backup workflow).",
    ),
    f(
        "networks.*.backup.recipients",
        "Backup recipients",
        Kind::List,
        true,
        "Who can decrypt a backup: age recipients (`age1…`), or files holding one a line. sentry never has the secret key; `sentry-network backup key <file>` makes one. Until one is set, no backup is made.",
    ),
    f(
        "networks.*.backup.keep",
        "Backups kept",
        Kind::Number,
        true,
        "How many of the newest backups are kept, plus each month's first for a year (12).",
    ),
    f(
        "networks.*.maintenance",
        "Maintenance",
        Kind::Section,
        false,
        "What is kept up to date, and how often a routine workflow runs.",
    ),
    f(
        "networks.*.maintenance.items",
        "Items",
        Kind::Records,
        false,
        "The router's firmware, its packages, its config backup.",
    ),
    f(
        "networks.*.maintenance.items[].id",
        "Id",
        Kind::Text,
        false,
        "A short name for it, unique on this network.",
    ),
    f(
        "networks.*.maintenance.items[].kind",
        "Kind",
        Kind::Choice(&["firmware", "packages", "backup"]),
        false,
        "What it is: `firmware` (the router's release), `packages` (what apk would upgrade) or `backup` (its config backup).",
    ),
    f(
        "networks.*.maintenance.cadence",
        "How often",
        Kind::Records,
        true,
        "How often a routine workflow should run.",
    ),
    f(
        "networks.*.maintenance.cadence[].workflow",
        "Workflow",
        Kind::Text,
        true,
        "The workflow (`config-backup`, `package-update`).",
    ),
    f(
        "networks.*.maintenance.cadence[].every",
        "Every",
        Kind::Duration,
        true,
        "Recommended when it last ran longer ago than this.",
    ),
    f(
        "networks.*.notes",
        "Notes",
        Kind::List,
        true,
        "Local files Claude may read when planning or reviewing (runbooks, notes).",
    ),
    f(
        "networks.*.claude",
        "Claude",
        Kind::Section,
        true,
        "What Claude may see.",
    ),
    f(
        "networks.*.claude.share_wan_address",
        "Share the WAN address",
        Kind::Bool,
        true,
        "Claude may see the WAN address (off: it is scrubbed from what's sent).",
    ),
    f(
        "networks.*.guard",
        "Guard",
        Kind::Section,
        false,
        "The guard around a change to the configs the network is reached through.",
    ),
    f(
        "networks.*.guard.window",
        "Guard window",
        Kind::Number,
        false,
        "Seconds the router waits for the change to be confirmed before it takes it back by itself (300; 5–3600).",
    ),
];

/// Parse the file's text; unknown keys come back as warnings.
pub fn parse(text: &str) -> Result<(NetworkFile, Vec<String>), String> {
    let mut unknown = Vec::new();
    let file: NetworkFile = serde_saphyr::with_deserializer_from_str(text, |de| {
        serde_ignored::deserialize(de, |p| unknown.push(p.to_string()))
    })
    .map_err(|e| e.to_string())?;
    let warnings = unknown
        .into_iter()
        .map(|p| format!("network_config.yaml: unknown key `{p}` ignored"))
        .collect();
    Ok((file, warnings))
}

pub fn load() -> Result<(NetworkFile, Vec<String>), String> {
    let p = path();
    let text = std::fs::read_to_string(&p).map_err(|_| {
        format!(
            "no {}: run `sentry-network init <ssh-host>` to draft one",
            p.display()
        )
    })?;
    parse(&text).map_err(|e| format!("{}: {e}", p.display()))
}

/// Pick a network: by name, or the only one configured.
pub fn pick<'a>(
    file: &'a NetworkFile,
    name: Option<&str>,
) -> Result<(&'a str, &'a Network), String> {
    let names = || file.networks.keys().cloned().collect::<Vec<_>>().join(", ");
    match name {
        Some(n) => file
            .networks
            .get_key_value(n)
            .map(|(k, v)| (k.as_str(), v))
            .ok_or_else(|| {
                format!(
                    "no network `{n}` in network_config.yaml (configured: {})",
                    names()
                )
            }),
        None => match file.networks.len() {
            1 => {
                let (k, v) = file.networks.iter().next().expect("one");
                Ok((k.as_str(), v))
            }
            0 => Err("network_config.yaml has no networks".into()),
            _ => Err(format!(
                "several networks configured, name one: {}",
                names()
            )),
        },
    }
}

/// `proto:port@zone` as (proto, ports, zone).
pub fn listener(entry: &str) -> Result<(&str, Ports, &str), String> {
    let bad = || format!("`{entry}` should be proto:port@zone (tcp:22@lan)");
    let (what, zone) = entry.split_once('@').ok_or_else(bad)?;
    let (proto, port) = what.split_once(':').ok_or_else(bad)?;
    if !matches!(proto, "tcp" | "udp") || zone.is_empty() {
        return Err(bad());
    }
    Ok((proto, port.parse().map_err(|_| bad())?, zone))
}

/// Problems found without contacting the router.
pub fn lint(name: &str, n: &Network) -> Vec<String> {
    let mut p = Vec::new();
    if name.is_empty() || name.contains(|c: char| c.is_whitespace() || c == '/' || c == ':') {
        p.push(format!(
            "`{name}`: a network's name is one word (it names a directory and `net:{name}`)"
        ));
    }
    if !(5..=3600).contains(&n.guard.window) {
        p.push(format!(
            "{name}: guard: window: {} s (between 5 and 3600: long enough for the reloads, \
             short enough to wait out)",
            n.guard.window
        ));
    }
    if n.router.ssh.as_deref().is_some_and(|s| s.trim().is_empty()) {
        p.push(format!("{name}: router: ssh: is empty"));
    }
    for (zone, ifs) in &n.expect.zones {
        if ifs.is_empty() {
            p.push(format!("{name}: zone `{zone}` names no interface"));
        }
    }
    let mut names = std::collections::HashSet::new();
    for f in &n.expect.forwards {
        let at = format!("{name}: forward `{}`", f.name);
        if f.name.is_empty() {
            p.push(format!("{name}: a forward has no name"));
        } else if !names.insert(f.name.as_str()) {
            p.push(format!("{at} is there twice"));
        }
        if !matches!(f.proto.as_str(), "tcp" | "udp" | "any") {
            p.push(format!(
                "{at}: proto `{}` should be tcp, udp or any",
                f.proto
            ));
        }
        if f.to.parse::<std::net::IpAddr>().is_err() {
            p.push(format!("{at}: to `{}` isn't an address", f.to));
        }
    }
    for l in &n.expect.listeners {
        match listener(l) {
            Ok((_, _, zone))
                if !n.expect.zones.is_empty() && !n.expect.zones.contains_key(zone) =>
            {
                p.push(format!(
                    "{name}: listener `{l}`: zone `{zone}` isn't under zones:"
                ))
            }
            Ok(_) => {}
            Err(e) => p.push(format!("{name}: listener {e}")),
        }
    }
    let (mut names, mut macs) = (
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );
    for d in &n.devices {
        let at = format!("{name}: device `{}`", d.label());
        if d.name.as_deref().is_some_and(|x| !names.insert(x)) {
            p.push(format!("{at} is there twice"));
        }
        match d.mac.as_deref().map(|m| (m, mac(m))) {
            Some((m, None)) => p.push(format!("{at}: `{m}` isn't a MAC address")),
            Some((m, Some(norm))) => {
                if !macs.insert(norm) {
                    p.push(format!("{at}: MAC {m} is another device's too"));
                }
                if d.private_mac {
                    p.push(format!(
                        "{at}: private_mac means its MAC changes: give hostname:, not mac:"
                    ));
                }
            }
            None if d.hostname.as_deref().is_none_or(str::is_empty) => {
                p.push(format!("{at}: give mac: or hostname:"));
            }
            None => {}
        }
    }
    let t = &n.thresholds;
    if t.load.is_nan() || t.load <= 0.0 {
        p.push(format!("{name}: thresholds: load must be above 0"));
    }
    if t.mem_pct.is_nan() || t.mem_pct <= 0.0 || t.mem_pct > 100.0 {
        p.push(format!("{name}: thresholds: mem_pct is a percentage"));
    }
    if t.backup_age.0.is_zero() {
        p.push(format!("{name}: thresholds: backup_age must be above 0"));
    }
    for r in &n.backup.recipients {
        if let Err(e) = crate::backup::recipient(r) {
            p.push(format!("{name}: backup: {e}"));
        }
    }
    if n.backup.keep == 0 {
        p.push(format!("{name}: backup: keep must be at least 1"));
    }
    let mut ids = std::collections::HashSet::new();
    for it in &n.maintenance.items {
        if it.id.is_empty() {
            p.push(format!("{name}: a maintenance item has no id"));
        } else if !ids.insert(it.id.as_str()) {
            p.push(format!(
                "{name}: maintenance item `{}` is there twice",
                it.id
            ));
        }
    }
    let mut wfs = std::collections::HashSet::new();
    for c in &n.maintenance.cadence {
        if c.workflow.is_empty() {
            p.push(format!("{name}: a cadence names no workflow"));
        } else if !wfs.insert(c.workflow.as_str()) {
            p.push(format!(
                "{name}: cadence for `{}` is there twice",
                c.workflow
            ));
        }
        if c.every.0.is_zero() {
            p.push(format!(
                "{name}: cadence for `{}`: every must be above 0",
                c.workflow
            ));
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../assets/network_config.example.yaml");

    /// Every field at something other than its default, with names and values a YAML file has
    /// to quote.
    pub(crate) fn full() -> NetworkFile {
        let n = Network {
            router: RouterCfg {
                ssh: Some("root@192.0.2.1".into()),
                kind: RouterKind::Openwrt,
            },
            expect: Expect {
                zones: [
                    ("lan".to_string(), vec!["lan".to_string()]),
                    (
                        "wan".to_string(),
                        vec!["wan".to_string(), "wan6".to_string()],
                    ),
                    ("yes".to_string(), vec![]),
                ]
                .into(),
                forwards: vec![
                    Forward {
                        name: "web".into(),
                        proto: "udp".into(),
                        port: Ports { from: 443, to: 443 },
                        to: "192.0.2.10".into(),
                    },
                    Forward {
                        name: "game it's".into(),
                        proto: "tcp".into(),
                        port: Ports {
                            from: 8000,
                            to: 8010,
                        },
                        to: "2001:db8::10".into(),
                    },
                ],
                listeners: vec!["tcp:22@lan".into()],
                services: vec!["odhcpd".into()],
            },
            devices: vec![
                Device {
                    name: Some("1.10".into()),
                    mac: Some("02:00:5e:00:53:01".into()),
                    hostname: Some("nas".into()),
                    leave_alone: true,
                    private_mac: true,
                },
                Device {
                    hostname: Some("*phone".into()),
                    ..Default::default()
                },
            ],
            thresholds: Thresholds {
                load: 3.5,
                mem_pct: 70.0,
                cert_days: 7,
                backup_age: Dur::secs(7 * 86400),
            },
            backup: Backup {
                recipients: vec![
                    "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq".into(),
                ],
                keep: 3,
            },
            maintenance: Maintenance {
                items: vec![
                    Item {
                        id: "firmware".into(),
                        kind: ItemKind::Firmware,
                    },
                    Item {
                        id: "pkgs".into(),
                        kind: ItemKind::Packages,
                    },
                    Item {
                        id: "backup".into(),
                        kind: ItemKind::Backup,
                    },
                ],
                cadence: vec![Cadence {
                    workflow: "config-backup".into(),
                    every: Dur::secs(30 * 86400),
                }],
            },
            notes: vec!["~/notes/network.md".into()],
            claude: ClaudeCfg {
                share_wan_address: true,
            },
            guard: GuardCfg { window: 60 },
        };
        NetworkFile {
            networks: [
                ("home".to_string(), n),
                ("lab-2".to_string(), Network::default()),
                (
                    "no".to_string(),
                    Network {
                        expect: Expect {
                            zones: [("lan".to_string(), vec![])].into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        }
    }

    fn round_trip(f: &NetworkFile) -> String {
        let text = sentry_core::cfg::render(f).unwrap_or_else(|e| panic!("{e}"));
        let (back, w) = parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        assert!(w.is_empty(), "{w:?}\n{text}");
        assert_eq!(&back, f, "{text}");
        text
    }

    #[test]
    fn what_sentry_writes_reads_back_as_what_it_was() {
        round_trip(&NetworkFile::default());
        let (example, _) = parse(EXAMPLE).unwrap();
        let text = round_trip(&example);
        let (back, _) = parse(&text).unwrap();
        for (n, net) in &back.networks {
            assert!(lint(n, net).is_empty(), "{:?}", lint(n, net));
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
            (NetworkFile::default(), full()),
            (full(), example.clone()),
            (example, NetworkFile::default()),
        ] {
            let mut x = a.clone();
            for c in sentry_core::cfg::diff(&a, &b).unwrap() {
                sentry_core::cfg::apply(&mut x, &c).unwrap_or_else(|e| panic!("{e}"));
            }
            assert_eq!(x, b);
        }
    }

    #[test]
    fn example_parses_whole_and_lints_clean() {
        let (f, warnings) = parse(EXAMPLE).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        let (name, n) = pick(&f, None).unwrap();
        assert_eq!(name, "home");
        assert_eq!(n.ssh_target(name), "myrouter");
        assert_eq!(n.router.kind, RouterKind::Openwrt);
        assert!(lint(name, n).is_empty(), "{:?}", lint(name, n));
        // Every part of the shape is there, for the screens that will read it.
        assert_eq!(n.expect.zones["wan"], ["wan", "wan6"]);
        let web = &n.expect.forwards[0];
        assert_eq!(
            (web.name.as_str(), web.proto.as_str(), web.port.to_string()),
            ("web", "tcp", "443".to_string())
        );
        assert_eq!(web.to, "192.0.2.10");
        assert_eq!(
            n.expect.forwards[1].port,
            Ports {
                from: 8000,
                to: 8010
            }
        );
        assert_eq!(
            listener(&n.expect.listeners[0]).unwrap(),
            ("tcp", Ports { from: 22, to: 22 }, "lan")
        );
        assert_eq!(n.devices.len(), 3);
        assert_eq!(n.devices[0].mac.as_deref(), Some("02:00:5e:00:53:01"));
        assert!(n.devices[1].leave_alone && n.devices[2].private_mac);
        assert_eq!(n.devices[2].label(), "phone");
        assert_eq!(
            (
                n.thresholds.load,
                n.thresholds.mem_pct,
                n.thresholds.cert_days
            ),
            (2.0, 85.0, 21)
        );
        assert_eq!(n.thresholds.backup_age, Dur::secs(30 * 86400));
        assert_eq!((n.backup.recipients.len(), n.backup.keep), (0, 12));
        let kinds: Vec<ItemKind> = n.maintenance.items.iter().map(|i| i.kind).collect();
        assert_eq!(
            kinds,
            [ItemKind::Firmware, ItemKind::Packages, ItemKind::Backup]
        );
        assert_eq!(n.maintenance.cadence[0].workflow, "config-backup");
        assert_eq!(n.maintenance.cadence[1].every, Dur::secs(60 * 86400));
        assert_eq!(n.notes, ["~/notes/network.md"]);
        assert!(!n.claude.share_wan_address);
    }

    /// What the sample parses to, fixed before sentry could write the file: rendering it must
    /// never change what a file a user wrote by hand means.
    #[test]
    fn the_example_parses_to_what_it_always_did() {
        let (f, _) = parse(EXAMPLE).unwrap();
        insta::assert_snapshot!(serde_json::to_string_pretty(&f).unwrap());
    }

    #[test]
    fn an_empty_network_has_the_defaults() {
        let (f, w) = parse("networks:\n  home: {}\n").unwrap();
        assert!(w.is_empty());
        let n = &f.networks["home"];
        assert_eq!(n, &Network::default());
        assert_eq!(n.ssh_target("home"), "home");
        assert_eq!(n.backup.keep, 12);
        assert!(lint("home", n).is_empty());
    }

    #[test]
    fn unknown_keys_warn_and_errors_say_where() {
        let (_, w) = parse("networks:\n  a:\n    routr: {ssh: x}\n").unwrap();
        assert_eq!(
            w,
            ["network_config.yaml: unknown key `networks.a.routr` ignored"]
        );
        let e = parse("networks:\n  a:\n    thresholds: {backup_age: 3 weeks}\n").unwrap_err();
        assert!(e.contains("unknown unit"), "{e}");
        let e = parse("networks:\n  a:\n    router: {kind: pfsense}\n").unwrap_err();
        assert!(e.contains("pfsense") || e.contains("openwrt"), "{e}");
        let e = parse(
            "networks:\n  a:\n    expect:\n      forwards: [{name: x, port: 0, to: 192.0.2.1}]\n",
        )
        .unwrap_err();
        assert!(e.contains("bad port"), "{e}");
    }

    #[test]
    fn lint_says_what_can_be_seen_offline() {
        let text = r#"
networks:
  home:
    expect:
      zones: { lan: [lan], wan: [] }
      forwards:
        - { name: web, proto: sctp, port: 443, to: nas.lan }
        - { name: web, port: 80, to: 192.0.2.10 }
      listeners: [ "tcp:22@lan", "tcp:22", "udp:53@guest" ]
    devices:
      - { name: nas, mac: "02:00:5E:00:53:01" }
      - { name: nas, mac: "02-00-5e-00-53-01" }
      - { name: tv, mac: "not-a-mac" }
      - { name: phone, mac: "02:00:5e:00:53:07", private_mac: true }
      - { name: nothing }
      - { hostname: printer }
    thresholds: { load: 0, mem_pct: 140 }
    backup: { recipients: [ "age1short", "what" ], keep: 0 }
    maintenance:
      items: [ { id: firmware, kind: firmware }, { id: firmware, kind: packages } ]
      cadence: [ { workflow: config-backup, every: 0d }, { workflow: config-backup, every: 30d } ]
"#;
        let (f, w) = parse(text).unwrap();
        assert!(w.is_empty(), "{w:?}");
        let p = lint("home", &f.networks["home"]);
        let has = |s: &str| p.iter().any(|x| x.contains(s));
        for want in [
            "zone `wan` names no interface",
            "forward `web`: proto `sctp`",
            "to `nas.lan` isn't an address",
            "forward `web` is there twice",
            "listener `tcp:22` should be proto:port@zone",
            "zone `guest` isn't under zones:",
            "device `nas` is there twice",
            "MAC 02-00-5e-00-53-01 is another device's too",
            "`not-a-mac` isn't a MAC address",
            "private_mac means its MAC changes",
            "device `nothing`: give mac: or hostname:",
            "load must be above 0",
            "mem_pct is a percentage",
            "isn't a whole age recipient",
            "`what` isn't an age recipient",
            "keep must be at least 1",
            "maintenance item `firmware` is there twice",
            "cadence for `config-backup` is there twice",
            "every must be above 0",
        ] {
            assert!(has(want), "missing {want:?} in {p:#?}");
        }
        assert_eq!(p.len(), 19, "{p:#?}");
        assert!(lint("my net", &Network::default())[0].contains("one word"));
    }

    #[test]
    fn macs_are_compared_in_one_form() {
        assert_eq!(
            mac("02-00-5E-00-53-0A").as_deref(),
            Some("02:00:5e:00:53:0a")
        );
        assert_eq!(mac("02:00:5e:00:53"), None);
        assert_eq!(mac("02:00:5e:00:53:zz"), None);
        // The documentation range used here is locally administered; a vendor's isn't.
        assert!(local_mac("02:00:5e:00:53:01"));
        assert!(!local_mac("00:00:5e:00:53:01"));
        assert!(local_mac("da:a1:19:00:00:01"));
    }

    #[test]
    fn pick_by_name_or_the_only_one() {
        let (f, _) = parse("networks:\n  a: {}\n  b: {}\n").unwrap();
        assert!(pick(&f, None).unwrap_err().contains("a, b"));
        assert_eq!(pick(&f, Some("b")).unwrap().0, "b");
        assert!(pick(&f, Some("c")).unwrap_err().contains("no network `c`"));
        let (f, _) = parse("networks: {}\n").unwrap();
        assert!(pick(&f, None).unwrap_err().contains("no networks"));
    }
}

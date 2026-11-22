//! What on the network needs you, in plain sentences ([`attention`]), and how the network
//! is covered ([`posture`]). Pure: both are made from what was read ([`State`]), the marks
//! the picture already has, and the findings the audit's own rule derives from the same
//! reads, so a row here and a row on Maintenance are one thing with one id.
//!
//! A row says what was seen, why it matters, and what Enter does about it ([`Act`]). A row
//! that is an audit finding carries the finding's id: marking it expected or putting it
//! off here is the baseline and the later list Maintenance uses.

use std::net::IpAddr;

use sentry_core::baseline::glob;
use sentry_core::finding::{Finding, Sev};

use super::blocks::{self, Blocks};
use super::{End, Mark, Nets, Picture, Read};
use crate::clients::{Client, Link};
use crate::collect::crowdsec::Bouncer;

/// How much a row asks of you.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rank {
    /// Something is wrong now.
    Now,
    /// Worth a look and a decision.
    Look,
    /// Good to know; nothing is wrong.
    Note,
}

impl Rank {
    pub fn word(self) -> &'static str {
        match self {
            Rank::Now => "act now",
            Rank::Look => "look",
            Rank::Note => "note",
        }
    }
}

/// Where a row stands in the list, and why: the order a non-expert would agree with once
/// it is said out loud. The list goes by how much a row asks first ([`Rank`]: an `act
/// now` is never under a `look`), then, among rows that ask as much, by its class in the
/// order below, then as it was found. No scores.
///
/// | | class | what is in it |
/// |-|-|-|
/// | 1 | `Live` | happening now and shouldn't be: a live connection across sides kept apart, a connection from the internet with no listed door, refused logins or repeated wrong Wi-Fi passwords, a login from a device with no name, a device on a port ordinary devices rarely use, a device that joined within the last day and has no name |
/// | 2 | `Hole` | a known hole with a fix: firmware, packages or an app with security fixes waiting or unsupported, a door or a firewall rule that lets the internet in unlisted |
/// | 3 | `Login` | weak logins, admin pages without encryption, a door's certificate that lapsed or anyone could make (what the outside reaches is `act now` and so comes first, then what only the inside reaches) |
/// | 4 | `Guard` | protection that is installed and not working: CrowdSec's blocker off, a blocklist that is stale or doesn't run, a service that should run |
/// | 5 | `Structure` | how the network is laid out: everything on one network |
/// | 6 | `Recovery` | what you'd need afterwards: no backup, a log lost on restart |
/// | 7 | `Housekeeping` | naming long-standing devices, answering sentry's questions, and everything that is only a note |
///
/// Two rules keep the levels honest ([`arrange`]): whatever is only a `note` is
/// housekeeping wherever it came from, and housekeeping is never more than a `note`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    Live,
    Hole,
    Login,
    Guard,
    Structure,
    Recovery,
    Housekeeping,
}

impl Class {
    /// The class of a row of the page's own, by its key (first prefix that fits).
    pub fn of(key: &str) -> Class {
        const TABLE: &[(&str, Class)] = &[
            ("finding:net:flow:", Class::Live),
            ("sec:inbound", Class::Live),
            ("finding:net:ssh:failed", Class::Live),
            ("sec:ssh:unknown", Class::Live),
            ("sec:wifi:psk", Class::Live),
            ("sec:odd:", Class::Live),
            ("finding:net:forward:", Class::Hole),
            ("finding:net:zone:", Class::Hole),
            ("finding:net:listener:", Class::Hole),
            ("finding:net:ssh:password", Class::Login),
            ("finding:net:luci:http", Class::Login),
            ("finding:net:cert:", Class::Login),
            ("finding:net:crowdsec:", Class::Guard),
            ("finding:net:service:", Class::Guard),
            ("sec:blocklist", Class::Guard),
            ("sec:filter:", Class::Guard),
            // (A device that joined within the day is `Live`: its builder says so.)
            ("finding:net:client:", Class::Housekeeping),
        ];
        TABLE
            .iter()
            .find(|(p, _)| key.starts_with(p))
            .map_or(Class::Housekeeping, |(_, c)| *c)
    }

    /// The class of one of the security audit's items: by what it is about (the second
    /// part of its id, `sec:<what>:…`), else by the audit's own section.
    pub fn of_audit(id: &str, group: sentry_core::secaudit::Group) -> Class {
        use sentry_core::secaudit::Group as G;
        match id.split(':').nth(1).unwrap_or("") {
            "crossing" => Class::Live,
            "firmware" | "packages" | "os" | "os-life" | "apps-behind" | "app" | "reboot"
            | "wan-input" | "wan-mgmt" | "door" | "outside" | "ctr" | "ctrs" | "listen-wide"
            | "firewall" => Class::Hole,
            // (A certificate that lapsed or that anyone could make: posing as the server.)
            "ssh-password" | "admin-http" | "ssh-root" | "sudo" | "keys" | "wifi" | "wps"
            | "cert" => Class::Login,
            "watch" | "dns-filter" | "auto-updates" => Class::Guard,
            "flat" | "apart" => Class::Structure,
            "backup" | "logs" | "restore" => Class::Recovery,
            "unknown-devices" => Class::Housekeeping,
            _ => match group {
                G::GettingIn | G::KnownHoles => Class::Hole,
                G::Logins => Class::Login,
                G::MovingAround => Class::Structure,
                G::Recovering => Class::Recovery,
            },
        }
    }
}

/// How a device is on the network, as far as a sentence needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Wired,
    Wifi,
    /// On a routed port of its own (the server's side).
    Routed,
    Other,
}

/// What several rows of one kind are, as one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Long-standing devices nobody has named.
    Devices,
    /// The audit's questions about doors from the internet.
    Doors,
    /// The audit's other questions.
    Asks,
    /// Devices on ports ordinary devices rarely use.
    Odd,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Devices, Kind::Doors, Kind::Asks, Kind::Odd];

    /// The group's row key.
    pub fn key(self) -> &'static str {
        match self {
            Kind::Devices => "group:devices",
            Kind::Doors => "group:doors",
            Kind::Asks => "group:asks",
            Kind::Odd => "group:odd",
        }
    }

    /// The kind a row is one of (None: it is always a row of its own).
    pub fn of(r: &Row) -> Option<Kind> {
        match &r.act {
            Act::Audit { id, asks: true } if id.starts_with("sec:door:") => Some(Kind::Doors),
            Act::Audit { asks: true, .. } => Some(Kind::Asks),
            Act::Device(_)
                if r.key.starts_with("finding:net:client:") && r.class == Class::Housekeeping =>
            {
                Some(Kind::Devices)
            }
            _ if r.key.starts_with("sec:odd:") => Some(Kind::Odd),
            _ => None,
        }
    }

    /// The list's heading when it is open.
    pub fn heading(self, n: usize) -> String {
        match self {
            Kind::Devices => format!("{} with no name yet", plural(n, "device", "devices")),
            Kind::Doors => format!("{} from the internet", plural(n, "door", "doors")),
            Kind::Asks => format!("{} only you can answer", plural(n, "question", "questions")),
            Kind::Odd => format!("{} on unusual ports", plural(n, "device", "devices")),
        }
    }
}

/// From how many rows of one kind they are listed as one.
pub const GROUP_AT: usize = 3;

/// A device first seen less than this long ago is news; older ones are housekeeping.
pub const NEW_FOR: i64 = 86_400;

/// The panel that holds a row's evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    Ingress,
    /// Egress, on this device's row when it has one (its key there).
    Egress(Option<String>),
    Zones,
    Dns,
    Wifi,
    None,
}

/// A device a row is about, as far as an action needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevRef {
    pub mac: String,
    /// The salted tag that names it in a run's values and the log.
    pub tag: String,
    pub label: String,
    pub zone: String,
    /// The access point it is on, on Wi-Fi.
    pub wifi: Option<String>,
    pub named: bool,
    pub via: Via,
}

/// What Enter does on a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Act {
    /// Decide about a device: name it, block it, pause it, send it off the Wi-Fi.
    Device(DevRef),
    /// A pause that ended: unblock.
    Unblock {
        tag: String,
    },
    /// A port forward: close it, remove it, or say it is meant.
    Forward {
        section: String,
        name: String,
    },
    SshKeys,
    AdminHttps,
    /// The blocklist: fetch it again; its own schedule on.
    Blocklist {
        stale: bool,
        scheduled: Option<bool>,
    },
    /// Wrong passphrases: a new Wi-Fi password is the fix.
    WifiKey,
    /// An audit finding with no fixed remedy: a session with Claude plans the fix.
    Finding(String),
    /// Nothing to do but look: Enter shows the numbers.
    Evidence,
    /// Its fix spans the server and the router: one session across both.
    Server {
        brief: String,
    },
    /// One of the security audit's items (its id): a session that fixes it; `asks`: what
    /// only you know, answered with a pick.
    Audit {
        id: String,
        asks: bool,
    },
    /// The audit says it and the item does it (firmware, packages, the backup): Enter is
    /// that item's own Enter on Maintenance (the draft's box, then the workflow).
    Maint(crate::config::ItemKind),
    /// Several rows of one kind as one: Enter lists them, each still its own decision.
    Group {
        kind: Kind,
        rows: Vec<Row>,
    },
    /// The family filter differs between the router and this machine's note of it:
    /// `on_router`, a filter sentry has no note of (keep it or take it off); else one noted
    /// here that the router doesn't have whole (put it back or forget it).
    FilterDrift {
        tag: String,
        on_router: bool,
    },
    /// The filter is on the router but has stopped working (forced lookups in front of it,
    /// or nobody's forced): the filter again on the same devices puts it right.
    FilterRepair,
}

impl Act {
    /// What the key bar calls Enter.
    pub fn enter(&self) -> &'static str {
        match self {
            Act::Device(_) => "decide",
            Act::Unblock { .. } => "unblock",
            Act::Forward { .. } => "close it",
            Act::SshKeys => "keys only",
            Act::AdminHttps => "use HTTPS",
            Act::Blocklist { stale: true, .. } => "refresh",
            Act::Blocklist { .. } => "keep updated",
            Act::WifiKey => "new password",
            Act::Finding(_) => "fix",
            Act::Evidence => "the numbers",
            Act::Server { .. } => "finish it",
            Act::Audit { asks: true, .. } => "answer",
            Act::Audit { .. } => "fix",
            Act::Maint(_) => "do it",
            Act::Group { .. } => "list them",
            Act::FilterDrift { .. } => "decide",
            Act::FilterRepair => "put it right",
        }
    }

    /// What Enter does, in plain words: the row's second line. `claude`: Claude Code is
    /// there (without it a session's row shows what was seen instead).
    pub fn step(&self, claude: bool) -> &'static str {
        match self {
            Act::Device(_) => "Enter: name it if it's yours, or block or pause it",
            Act::Unblock { .. } => "Enter: lift the block",
            Act::Forward { .. } => "Enter: close it, remove it, or say it's meant to be open",
            Act::SshKeys => "Enter: logins by key only (sentry checks its key works first)",
            Act::AdminHttps => "Enter: make the admin page use encryption (HTTPS)",
            Act::Blocklist { stale: true, .. } => "Enter: fetch the list again",
            Act::Blocklist { .. } => "Enter: make the list update by itself",
            Act::WifiKey => "Enter: set a new Wi-Fi password",
            Act::Finding(_) if claude => "Enter: fix it with Claude (it shows a plan, you approve)",
            Act::Server { .. } if claude => {
                "Enter: fix it with Claude (one plan for both, you approve)"
            }
            Act::Finding(_) | Act::Server { .. } | Act::Evidence => {
                "Enter: see the numbers behind it (nothing to change)"
            }
            Act::Audit { asks: true, .. } => "Enter: answer yes, no, or don't know",
            Act::Audit { .. } if claude => {
                "Enter: fix it with Claude (it shows a plan, you approve)"
            }
            Act::Audit { .. } => "Enter: read it in the security audit's report",
            Act::Maint(k) => maint_step(*k),
            Act::Group {
                kind: Kind::Devices,
                ..
            } => "Enter: go through them (name, block or pause each)",
            Act::Group {
                kind: Kind::Doors | Kind::Asks,
                ..
            } => "Enter: answer them one after another",
            Act::Group { .. } => "Enter: look at each",
            Act::FilterDrift {
                on_router: true, ..
            } => "Enter: keep it, or take it off the router",
            Act::FilterDrift { .. } => "Enter: put it back on the router, or forget it",
            Act::FilterRepair => "Enter: put the filter right (its plan first)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Stable: `finding:<id>` (Maintenance's key for the same finding) or `sec:<what>`.
    pub key: String,
    /// What marking it expected writes to the baseline: the finding's id, or the key.
    pub id: String,
    pub rank: Rank,
    pub title: String,
    /// Why it matters, one line.
    pub why: String,
    /// What was seen, for the detail.
    pub seen: Vec<String>,
    pub act: Act,
    pub subject: Subject,
    /// Nothing asks for it now: listed with `o`.
    pub can_wait: bool,
    /// Where it stands in the list.
    pub class: Class,
    /// What Enter does, where the row knows better than its [`Act`] (None: `Act::step`).
    pub next: Option<String>,
}

impl Row {
    /// The row's second line: what Enter does, in plain words.
    pub fn step(&self, claude: bool) -> String {
        match (&self.next, &self.act) {
            // A fix named for Claude: without Claude Code, what Enter does instead.
            (Some(_), Act::Finding(_) | Act::Server { .. } | Act::Audit { asks: false, .. })
                if !claude =>
            {
                self.act.step(claude).to_string()
            }
            (Some(n), _) => n.clone(),
            (None, a) => a.step(claude).to_string(),
        }
    }

    /// The rows it stands for (a group), else none.
    pub fn members(&self) -> &[Row] {
        match &self.act {
            Act::Group { rows, .. } => rows,
            _ => &[],
        }
    }

    /// Whether it is, or holds, a row whose key starts with `prefix`.
    pub fn about(&self, prefix: &str) -> bool {
        self.key.starts_with(prefix) || self.members().iter().any(|m| m.key.starts_with(prefix))
    }
}

/// What the server's own guard (CrowdSec) reports about the doors this router forwards to
/// it: said by the server target (`SystemLine::facts`), carried by the app, read here by
/// name. None without a server that has one (or before it was read).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerGuard {
    /// The server, as the window names it.
    pub server: String,
    /// Attackers it blocked in the last day (None: it runs, the count wasn't read).
    pub banned_today: Option<usize>,
    /// What they were banned for, most first.
    pub scenarios: Vec<String>,
    /// The router enforces those bans (a bouncer here fed by it). None: unknown.
    pub enforced_here: Option<bool>,
}

impl ServerGuard {
    /// "myserver blocked 7 attacker(s) today (mostly ssh brute force)", or that it runs
    /// when the count wasn't read.
    pub fn says(&self) -> String {
        match self.banned_today {
            Some(n) => format!(
                "{} blocked {n} attacker(s) today{}",
                self.server,
                match self.scenarios.first() {
                    Some(x) => format!(" (mostly {x})"),
                    None => String::new(),
                }
            ),
            None => format!(
                "CrowdSec runs on {} (how many attackers it blocked today wasn't read)",
                self.server
            ),
        }
    }
}

/// Everything the list and the posture are made from.
#[derive(Clone, Copy)]
pub struct State<'a> {
    pub network: &'a str,
    pub read: Read<'a>,
    pub picture: &'a Picture,
    /// What `audit::derive` says of the same reads (each with its `expected`).
    pub findings: &'a [Finding],
    /// The baseline's `findings` globs: a row that isn't a finding is dismissed by its key.
    pub expected: &'a [String],
    pub blocks: &'a Blocks,
    pub bouncer: Option<&'a Bouncer>,
    pub server_guard: Option<&'a ServerGuard>,
    /// Now, epoch seconds (this machine's clock: only for a pause's end).
    pub now: i64,
}

/// A zone in a sentence.
pub fn side(zone: &str) -> String {
    match zone {
        "lan" => "your home side (lan)".into(),
        "dmz" => "the server's side (dmz)".into(),
        "guest" => "the guest network".into(),
        "iot" => "the smart-devices network (iot)".into(),
        z => format!("the {z} network"),
    }
}

/// A length of time in a sentence: `40 seconds`, `20 minutes`, `2 h 40 min`, `3 days`.
pub fn lasting(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60);
    match (d, h, m) {
        (0, 0, 0) => format!("{secs} seconds"),
        (0, 0, 1) => "a minute".into(),
        (0, 0, m) => format!("{m} minutes"),
        (0, 1, 0) => "an hour".into(),
        (0, h, 0) => format!("{h} hours"),
        (0, h, m) => format!("{h} h {m} min"),
        (1, _, _) => "a day".into(),
        (d, _, _) => format!("{d} days"),
    }
}

fn times(n: usize) -> String {
    match n {
        1 => "once".into(),
        2 => "twice".into(),
        n => format!("{n} times"),
    }
}

fn cap(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

impl<'a> State<'a> {
    fn dismissed(&self, id: &str) -> bool {
        self.expected.iter().any(|g| glob(g, id))
    }

    fn open(&self, id: &str) -> Option<&'a Finding> {
        self.findings.iter().find(|f| f.id == id && !f.expected)
    }

    fn in_window(&self) -> String {
        match self.picture.log.as_ref().and_then(|l| l.window_s) {
            Some(w) => format!("in the last {}", lasting(w)),
            None => "in the router's log".into(),
        }
    }

    fn nets(&self) -> Option<Nets> {
        self.read.ifaces.map(|i| Nets::new(i, self.read.uci))
    }

    /// The device a client is, for an action (None: no MAC, or no tag can be made).
    pub fn dev(&self, c: &Client, nets: Option<&Nets>) -> Option<DevRef> {
        dev_of(self.network, c, nets)
    }
}

/// The device a client is, for an action (None: no MAC, or no tag can be made).
pub fn dev_of(network: &str, c: &Client, nets: Option<&Nets>) -> Option<DevRef> {
    let mac = c.mac.clone()?;
    let zone = c
        .addrs
        .iter()
        .filter_map(|a| a.parse::<IpAddr>().ok())
        .find_map(|a| match nets?.end(a) {
            End::Zone(z) => Some(z),
            _ => None,
        })
        .or_else(|| match &c.link {
            Link::Dmz { net, .. } => Some(net.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "lan".into());
    Some(DevRef {
        tag: blocks::tag(network, &mac)?,
        mac,
        label: c.label().to_string(),
        zone,
        wifi: match &c.link {
            Link::Wifi { ifname, .. } => Some(ifname.clone()),
            _ => None,
        },
        named: c.name.is_some(),
        via: match &c.link {
            Link::Wired { .. } => Via::Wired,
            Link::Wifi { .. } => Via::Wifi,
            Link::Dmz { .. } => Via::Routed,
            Link::Unknown => Via::Other,
        },
    })
}

fn sev_rank(s: Sev) -> Rank {
    match s {
        Sev::High => Rank::Now,
        Sev::Medium => Rank::Look,
        Sev::Low => Rank::Note,
    }
}

/// The findings that are about security but have no sentence of their own here: said in
/// the audit's words, fixed in a session. (What only differs from what the config
/// expects, a zone's members, a forward that is gone, is Maintenance's.)
const OTHER: &[&str] = &["net:service:", "net:cert:"];

/// The finding and the row for CrowdSec's blocker at the edge: one id, here and on
/// Maintenance.
pub const EDGE: &str = "net:crowdsec:bouncer";

/// The router has CrowdSec's firewall part and it isn't switched on: one sentence, wherever
/// the page says it (the posture, the row, the finding).
pub fn edge_off(server: bool) -> String {
    format!(
        "CrowdSec is installed on the router but switched off: {} aren't turned away there",
        if server {
            "attackers the server banned"
        } else {
            "known attackers"
        }
    )
}
/// These only when they are high: the outside reaches something.
const OTHER_HIGH: &[&str] = &["net:zone:", "net:listener:"];

/// What needs you, in the list's order ([`Class`]), several of one kind as one row
/// ([`arrange`]). Rows marked expected aren't here; rows put off are the caller's to drop
/// (it has the later list).
pub fn attention(s: &State) -> Vec<Row> {
    arrange(raw(s), None)
}

/// A zone in a row's first line, where there is no room for its config name.
fn side_short(zone: &str) -> String {
    match zone {
        "lan" => "your home side".into(),
        "dmz" => "the server's side".into(),
        z => side(z),
    }
}

/// Every row by itself, as found: what [`arrange`] orders and groups.
pub fn raw(s: &State) -> Vec<Row> {
    let p = s.picture;
    let nets = s.nets();
    let shut = s.read.uci.map(blocks::found).unwrap_or_default();
    let blocked = |tag: &str| shut.iter().any(|b| b.tag == tag);
    let mut out: Vec<Row> = Vec::new();
    let finding_row = |f: &Finding, title: String, why: String, act: Act, subject: Subject| Row {
        key: format!("finding:{}", f.id),
        id: f.id.clone(),
        rank: sev_rank(f.severity),
        title,
        why,
        seen: f.evidence.lines().map(str::to_string).collect(),
        subject,
        can_wait: f.severity == Sev::Low,
        class: Class::of(&format!("finding:{}", f.id)),
        next: matches!(act, Act::Finding(_))
            .then(|| fix_step(&f.fix))
            .flatten(),
        act,
    };
    let own = |key: &str, rank: Rank, title: String, why: &str, act: Act, subject: Subject| Row {
        key: key.to_string(),
        id: key.to_string(),
        rank,
        title,
        why: why.to_string(),
        seen: Vec::new(),
        act,
        subject,
        can_wait: false,
        class: Class::of(key),
        next: None,
    };

    // The family filter where the router and this machine's note of it differ.
    if let Some(u) = s.read.uci {
        let on = super::family::found(u);
        // It has stopped working: something forces lookups in front of it again, or nothing
        // forces them at all.
        let forced: Vec<String> = s
            .read
            .counters
            .map(|c| {
                let mut z: Vec<String> = on.iter().map(|f| f.zone.clone()).collect();
                z.sort();
                z.dedup();
                z.iter()
                    .flat_map(|z| super::family::hijacked(c, z))
                    .collect()
            })
            .unwrap_or_default();
        if !on.is_empty() && !forced.is_empty() {
            out.push(own(
                "sec:filter:forced",
                Rank::Now,
                "The family filter has stopped working: the router's own forced lookups are \
                 back in front of it"
                    .into(),
                "Its rules are still on the router, but the DNS proxy's forcing of lookups is \
                 first again (after an update of the package, or a change in its settings), \
                 so the filtered devices' lookups go to the router like everyone's. Enter \
                 puts the filter back in front (its plan first).",
                Act::FilterRepair,
                Subject::None,
            ));
        } else if !on.is_empty()
            && !super::family::dns_found(u).is_empty()
            && super::family::canaries(u)
                .iter()
                .any(|n| !super::family::refused_by_config(u, n))
        {
            out.push(own(
                "sec:filter:canaries",
                Rank::Now,
                "A browser's own encrypted lookups are no longer switched off on this network"
                    .into(),
                "The router stopped refusing the names that tell Firefox to keep its own \
                 encrypted lookups (DNS over HTTPS) off and switch iCloud Private Relay off, \
                 so those can switch on by themselves and skip both the router's blocklist \
                 and the family filter. Enter puts sentry's entries for them back (its plan \
                 first).",
                Act::FilterRepair,
                Subject::None,
            ));
        } else if !on.is_empty() && unforced(u) {
            out.push(own(
                "sec:filter:unforced",
                Rank::Now,
                "Lookups aren't forced through the router for anyone".into(),
                "sentry took the forcing of lookups over for the family filter, and its rules \
                 for that are gone from the router while the DNS proxy's own forcing is off: \
                 any device can ask another service and skip the router's blocklist and the \
                 family filter. Enter puts sentry's rules back (its plan first).",
                Act::FilterRepair,
                Subject::None,
            ));
        }
        let label = |tag: &str, mac: &str| filtered_label(s.blocks, s.read.clients, tag, mac);
        for f in &on {
            if !s.blocks.filter.contains_key(&f.tag) {
                out.push(own(
                    &format!("sec:filter:unknown:{}", f.tag),
                    Rank::Look,
                    format!(
                        "A family filter is on {} that sentry has no note of",
                        label(&f.tag, &f.mac)
                    ),
                    "sentry's rule for it is on the router, but this machine doesn't remember \
                     making it (made from another computer, or the note was lost). Keep it, \
                     or take it off.",
                    Act::FilterDrift {
                        tag: f.tag.clone(),
                        on_router: true,
                    },
                    Subject::None,
                ));
            } else if !f.whole() {
                out.push(own(
                    &format!("sec:filter:gone:{}", f.tag),
                    Rank::Look,
                    format!(
                        "The family filter on {} is only partly on the router",
                        label(&f.tag, &f.mac)
                    ),
                    "Part of sentry's rules for it was removed on the router, so its lookups \
                     may not be filtered. Put it back, or forget it.",
                    Act::FilterDrift {
                        tag: f.tag.clone(),
                        on_router: false,
                    },
                    Subject::None,
                ));
            }
        }
        for tag in s.blocks.filter.keys() {
            if !on.iter().any(|f| &f.tag == tag) {
                out.push(own(
                    &format!("sec:filter:gone:{tag}"),
                    Rank::Look,
                    format!(
                        "The family filter on {} isn't on the router any more",
                        label(tag, "a device")
                    ),
                    "This machine remembers filtering it, but the router has no rule of \
                     sentry's for it now (removed there, or the router was reset): its lookups \
                     aren't filtered. Put it back, or forget it.",
                    Act::FilterDrift {
                        tag: tag.clone(),
                        on_router: false,
                    },
                    Subject::None,
                ));
            }
        }
    }

    // A pause that ended: the rule is still there until Enter takes it away.
    for b in &shut {
        if s.blocks.ended(&b.tag, s.now) {
            let label = s
                .blocks
                .device
                .get(&b.tag)
                .map_or(b.mac.as_str(), |d| d.label.as_str());
            out.push(own(
                &format!("sec:pause:{}", b.tag),
                Rank::Note,
                format!("The pause on {label} has ended: it is still blocked"),
                "The router has no timer of sentry's, so the block stays until you lift it.",
                Act::Unblock { tag: b.tag.clone() },
                Subject::None,
            ));
        }
    }

    // Live flows between sides the firewall keeps apart.
    for x in p.crossings() {
        let id = format!("net:flow:{}-{}", x.from, x.to);
        if s.dismissed(&id) || s.findings.iter().any(|f| f.id == id && f.expected) {
            continue;
        }
        let mut r = own(
            &format!("finding:{id}"),
            Rank::Now,
            format!(
                "A device on {} is reaching {} right now",
                side_short(&x.from),
                side_short(&x.to)
            ),
            "The firewall is set to keep those two sides apart, so a break-in on one can't \
             reach the other. A live connection across means a rule lets it through, or \
             something is wired where it shouldn't be.",
            Act::Finding(id.clone()),
            Subject::Zones,
        );
        r.id = id.clone();
        r.seen = vec![format!("{} live connection(s) across, right now", x.flows)];
        if let Some(f) = s.open(&id) {
            r.seen.extend(f.evidence.lines().map(str::to_string));
        }
        out.push(r);
    }

    // A door from the internet that isn't listed.
    for f in s.findings.iter().filter(|f| !f.expected) {
        let Some(rest) = f.id.strip_prefix("net:forward:") else {
            continue;
        };
        if rest.starts_with("missing:") {
            continue;
        }
        let Some((proto, port)) = rest.split_once(':') else {
            continue;
        };
        let fw = s
            .read
            .uci
            .map(|u| u.forwards())
            .unwrap_or_default()
            .into_iter()
            .find(|r| r.enabled && r.protos.iter().any(|x| x == proto) && r.port == port);
        let (title, act) = match fw {
            Some(r) => (
                format!(
                    "An unlisted door from the internet is open: {} ({proto} port {port})",
                    r.name
                ),
                Act::Forward {
                    section: r.section,
                    name: r.name,
                },
            ),
            None => (cap(&f.message), Act::Finding(f.id.clone())),
        };
        out.push(finding_row(
            f,
            title,
            "A port forward lets anyone on the internet reach that device on that port. If \
             you set it up, say it is expected; if not, close it."
                .into(),
            act,
            Subject::Ingress,
        ));
    }

    // Password logins over ssh.
    if let Some(f) = s.open("net:ssh:password") {
        out.push(finding_row(
            f,
            "The router's remote login (ssh) still accepts a password".into(),
            "A password can be guessed, a key can't. sentry logs in with a key, so passwords \
             can be turned off without locking it (or you, with your key) out."
                .into(),
            Act::SshKeys,
            Subject::Ingress,
        ));
    }
    // Refused logins.
    if let Some(f) = s.open("net:ssh:failed") {
        let tries = p
            .marks
            .iter()
            .find_map(|m| match m {
                Mark::SshFailed { tries } => Some(*tries),
                _ => None,
            })
            .unwrap_or(1);
        let passwords = s
            .read
            .uci
            .is_some_and(|u| u.dropbear().iter().any(|d| d.password_auth));
        out.push(finding_row(
            f,
            format!(
                "The router refused a login {} {}",
                times(tries),
                s.in_window()
            ),
            if passwords {
                "A refused login is the lock holding. Several mean someone is guessing \
                 passwords: turning password logins off ends the guessing."
                    .into()
            } else {
                "A refused login is the lock holding, and passwords are already off: there \
                 is nothing to guess. Worth knowing which device it was."
                    .into()
            },
            if passwords {
                Act::SshKeys
            } else {
                Act::Evidence
            },
            Subject::Ingress,
        ));
    }

    // The admin page without encryption.
    if let Some(f) = s.open("net:luci:http") {
        out.push(finding_row(
            f,
            "The router's admin page can be opened without encryption".into(),
            "Whoever is on the network could read the admin password as it is typed (the \
             page answers on plain HTTP). Sending it on to HTTPS closes that."
                .into(),
            Act::AdminHttps,
            Subject::None,
        ));
    }

    // Devices nobody has named. One that joined within the day is news; the rest are
    // housekeeping.
    let watched = s
        .read
        .clients
        .unwrap_or(&[])
        .iter()
        .filter_map(|c| c.first_seen)
        .min()
        .is_some_and(|t| s.now - t >= NEW_FOR);
    for c in s.read.clients.unwrap_or(&[]).iter().filter(|c| c.unknown()) {
        let Some(mac) = &c.mac else { continue };
        let id = crate::audit::client_id(s.network, mac);
        let Some(dev) = s.dev(c, nets.as_ref()) else {
            continue;
        };
        if s.dismissed(&id) || blocked(&dev.tag) {
            continue;
        }
        // News only where sentry has watched long enough to tell new from old.
        let joined = c
            .first_seen
            .filter(|t| watched && s.now >= *t && s.now - *t < NEW_FOR)
            .map(|t| (s.now - t) as u64);
        // (What it calls itself, or its MAC: two such rows are two devices.)
        let it = c.label();
        let title = match (joined, &c.link) {
            (Some(n), Link::Wifi { .. }) => format!(
                "A device nobody has named joined the Wi-Fi {} ago: {it}",
                lasting(n)
            ),
            (Some(n), Link::Wired { port }) => format!(
                "A device nobody has named was plugged into {port} {} ago: {it}",
                lasting(n)
            ),
            (Some(n), _) => format!(
                "A device nobody has named appeared on the network {} ago: {it}",
                lasting(n)
            ),
            (None, Link::Wifi { .. }) => format!("A device on the Wi-Fi has no name yet: {it}"),
            (None, Link::Wired { port }) => {
                format!("A device plugged into {port} has no name yet: {it}")
            }
            (None, Link::Dmz { net, .. }) => {
                format!("A device on {} has no name yet: {it}", side_short(net))
            }
            (None, Link::Unknown) => format!("A device on the network has no name yet: {it}"),
        };
        let mut seen = vec![match &c.hostname {
            Some(h) => format!("It calls itself {h} · {mac}"),
            None => format!("It gives no name · {mac}"),
        }];
        if !c.addrs.is_empty() {
            seen.push(format!("address {}", c.addrs.join(", ")));
        }
        if let Some(t) = c.first_seen.filter(|t| s.now > *t) {
            seen.push(format!("first seen {} ago", lasting((s.now - t) as u64)));
        }
        out.push(Row {
            key: format!("finding:{id}"),
            id,
            rank: if joined.is_some() {
                Rank::Look
            } else {
                Rank::Note
            },
            title,
            why: if joined.is_some() {
                "It wasn't here yesterday. Whatever is on your network can talk to your other \
                 devices: if it is yours, name it; if you don't know it, block it or pause it \
                 and see what stops working."
                    .into()
            } else {
                "It has been here a while, so it is probably yours. Giving it a name means a \
                 new device stands out the day it appears; if you don't know it, block it or \
                 pause it and see what stops working."
                    .into()
            },
            seen,
            act: Act::Device(dev),
            subject: Subject::Egress(Some(c.key.clone())),
            can_wait: false,
            class: if joined.is_some() {
                Class::Live
            } else {
                Class::Housekeeping
            },
            next: None,
        });
    }

    // A device using a port ordinary devices rarely use.
    for d in &p.devices {
        let Some(far) = d.odd().next() else { continue };
        let client = s
            .read
            .clients
            .unwrap_or(&[])
            .iter()
            .find(|c| c.key == d.key);
        let dev = client.and_then(|c| s.dev(c, nets.as_ref()));
        let key = format!(
            "sec:odd:{}",
            dev.as_ref().map_or(d.key.as_str(), |x| x.tag.as_str())
        );
        if s.dismissed(&key) {
            continue;
        }
        let ports: Vec<String> = d.odd().map(|f| f.port.to_string()).collect();
        let mut r = own(
            &key,
            Rank::Look,
            format!(
                "{} is using a port ordinary devices rarely use (port {})",
                d.label,
                ports.join(", ")
            ),
            "Rare for a healthy device and common for one that was taken over or is badly \
             set up. A reason to look, not a verdict.",
            match dev {
                Some(x) => Act::Device(x),
                None => Act::Evidence,
            },
            Subject::Egress(Some(d.key.clone())),
        );
        r.seen = d
            .odd()
            .map(|f| {
                format!(
                    "{}/{}: {} · {} live connection(s)",
                    f.proto,
                    f.port,
                    f.odd.unwrap_or(""),
                    f.flows
                )
            })
            .collect();
        let _ = far;
        out.push(r);
    }

    // From the marks: what has no finding of its own.
    for m in &p.marks {
        let row = match m {
            Mark::Inbound { flows } => Some(own(
                "sec:inbound",
                Rank::Look,
                format!(
                    "{} from the internet {} inside without a listed door",
                    plural(*flows, "connection", "connections"),
                    if *flows == 1 { "reaches" } else { "reach" }
                ),
                "No door (port forward) is set up for them. Usually IPv6, where every device has a public address: the firewall should \
                 still refuse what nobody inside asked for.",
                Act::Evidence,
                Subject::Ingress,
            )),
            Mark::SshUnknown { logins } => Some(own(
                "sec:ssh:unknown",
                Rank::Look,
                format!(
                    "An unnamed device logged in to the router {} {}",
                    times(*logins),
                    s.in_window()
                ),
                "A login that worked, from an address sentry can't put a name to. If that \
                 was you on another device, name that device and this goes away.",
                Act::Evidence,
                Subject::Ingress,
            )),
            Mark::WifiAuthFailed { tries } => Some(own(
                "sec:wifi:psk",
                if *tries >= 5 { Rank::Look } else { Rank::Note },
                format!(
                    "Someone tried a wrong Wi-Fi password {} {}",
                    times(*tries),
                    s.in_window()
                ),
                "Often a device of yours with an old password. Many tries from something you \
                 don't own is someone guessing: a long password is the defence, and a new \
                 one the fix if you think it got out.",
                Act::WifiKey,
                Subject::Wifi,
            )),
            Mark::DotTried { per_min } => {
                let mut r = own(
                    "sec:dot",
                    Rank::Note,
                    "A device tries to look up names behind the router's back (all refused)"
                        .to_string(),
                    "Encrypted name lookups to an outside service (DNS over TLS) would skip \
                     your filtering of bad sites. The router refuses them; phones try by \
                     habit (Android's Private DNS).",
                    Act::Evidence,
                    Subject::Dns,
                );
                r.seen = vec![format!("{per_min:.1} tries a minute, all refused")];
                r.can_wait = true;
                Some(r)
            }
            Mark::NoMfp { stations } => {
                let mut r = own(
                    "sec:wifi:mfp",
                    Rank::Note,
                    format!(
                        "{} could be knocked off the Wi-Fi by a stranger nearby",
                        plural(*stations, "Wi-Fi device", "Wi-Fi devices"),
                    ),
                    "The Wi-Fi offers a protection against forged \"disconnect\" messages \
                     (management frame protection) and not every device took it: usually \
                     older ones. A nuisance, not a break-in. Nothing to fix on the router.",
                    Act::Evidence,
                    Subject::Wifi,
                );
                r.can_wait = true;
                Some(r)
            }
            Mark::Offload => {
                let mut r = own(
                    "sec:offload",
                    Rank::Note,
                    "The router's fast path is on: the traffic numbers here undercount".into(),
                    "Flow offloading hands connections past the part that counts them. It \
                     is a speed setting, not a risk: the byte counts and some connection \
                     counts on this screen are lower than the truth.",
                    Act::Evidence,
                    Subject::Egress(None),
                );
                r.can_wait = true;
                Some(r)
            }
            // Said above (from the finding, the devices), or below (the blocklist).
            Mark::Crossing { .. }
            | Mark::SshFailed { .. }
            | Mark::OddPorts { .. }
            | Mark::ListOld { .. } => None,
        };
        if let Some(r) = row.filter(|r| !s.dismissed(&r.key)) {
            out.push(r);
        }
    }

    // The list of bad sites.
    if let Some(b) = s.read.dns.and_then(|d| d.blocklist.as_ref())
        && !s.dismissed("sec:blocklist")
    {
        let days = s.read.dns.and_then(|d| d.list_age_days());
        let old = days.is_some_and(|d| d >= super::LIST_OLD_DAYS);
        let by_itself = match b.auto_update {
            Some(false) => " and doesn't update by itself",
            _ => "",
        };
        let said = if !b.running {
            Some((
                Rank::Look,
                "The filter for bad sites isn't running".to_string(),
                true,
            ))
        } else if b.errors > 0 {
            Some((
                Rank::Look,
                format!(
                    "The filter for bad sites reports {} error(s) building its list",
                    b.errors
                ),
                true,
            ))
        } else if old {
            Some((
                Rank::Look,
                format!(
                    "The list of bad sites is {} days old{by_itself}",
                    days.unwrap_or(0)
                ),
                true,
            ))
        } else if b.auto_update == Some(false) {
            Some((
                Rank::Note,
                "The list of bad sites doesn't update by itself".to_string(),
                false,
            ))
        } else {
            None
        };
        if let Some((rank, title, stale)) = said {
            let mut r = own(
                "sec:blocklist",
                rank,
                title,
                "New scam and malware sites appear every day; a list that isn't fetched \
                 again stops knowing them.",
                Act::Blocklist {
                    stale,
                    scheduled: b.auto_update,
                },
                Subject::Dns,
            );
            r.can_wait = rank == Rank::Note;
            if let Some(n) = b.entries {
                r.seen.push(format!("{n} names listed"));
            }
            out.push(r);
        }
    }

    // The audit's other security findings, in its own words.
    for f in s.findings.iter().filter(|f| !f.expected) {
        let high = f.severity == Sev::High && OTHER_HIGH.iter().any(|p| f.id.starts_with(p));
        if high || OTHER.iter().any(|p| f.id.starts_with(p)) {
            let why = if f.why.is_empty() { &f.what } else { &f.why };
            let title = if f.id.starts_with("net:zone:") {
                format!(
                    "The firewall lets the internet in where it should refuse ({})",
                    f.message
                )
            } else {
                cap(&f.message)
            };
            out.push(finding_row(
                f,
                title,
                why.clone(),
                Act::Finding(f.id.clone()),
                if f.id.starts_with("net:zone:") {
                    Subject::Zones
                } else {
                    Subject::None
                },
            ));
        }
    }

    // CrowdSec at the edge: ONE row, whatever says it (the router's own finding, the
    // server's guard), and its Enter is the session across both that finishes it.
    let edge_key = format!("finding:{EDGE}");
    let edge_expected = s.findings.iter().any(|f| f.id == EDGE && f.expected);
    if !edge_expected && !s.dismissed(EDGE) {
        let guard = s.server_guard;
        let unenforced = guard.filter(|g| g.enforced_here == Some(false));
        let off = s.bouncer.is_some_and(|b| !b.on());
        let seen = |extra: Vec<String>| {
            let mut v = extra;
            if let Some(g) = guard {
                v.push(g.says());
            }
            v
        };
        let row = if off {
            Some(Row {
                key: edge_key.clone(),
                id: EDGE.into(),
                rank: Rank::Look,
                title: edge_off(guard.is_some()),
                why: "The server refuses the attackers CrowdSec catches by itself; the router \
                      could refuse them at the door, for every device behind it. The package \
                      is there: it needs the server's address and a key, and switching on."
                    .into(),
                seen: seen(vec!["the bouncer: installed, switched off".into()]),
                act: Act::Server {
                    brief: sentry_core::secaudit::EDGE_FIX.into(),
                },
                subject: Subject::Ingress,
                can_wait: false,
                class: Class::Guard,
                next: None,
            })
        } else if let Some(f) = s.open(EDGE) {
            let mut r = finding_row(
                f,
                cap(&f.message),
                if f.why.is_empty() {
                    f.what.clone()
                } else {
                    f.why.clone()
                },
                Act::Server {
                    brief: format!(
                        "On the router: {}. {} Find the cause on the router or on the server \
                         whose CrowdSec it asks, and fix it where it is.",
                        f.message, f.what
                    ),
                },
                Subject::Ingress,
            );
            r.seen = seen(r.seen);
            Some(r)
        } else {
            unenforced
                .filter(|_| s.bouncer.is_none())
                .and_then(|g| g.banned_today.filter(|n| *n > 0).map(|n| (g, n)))
                .map(|(g, n)| Row {
                    key: edge_key.clone(),
                    id: EDGE.into(),
                    rank: Rank::Look,
                    title: format!(
                        "{} blocked {n} attacker(s) today, but the router still lets them knock",
                        g.server
                    ),
                    why: "The server refuses them itself; the router could refuse them at \
                          the door, for every device behind it."
                        .into(),
                    seen: seen(Vec::new()),
                    act: Act::Server {
                        brief: format!(
                            "{} banned {} address(es) today ({}). The router doesn't enforce \
                             those bans. Plan what it takes on both to have the router's \
                             firewall enforce them: CrowdSec's firewall bouncer on the router, \
                             fed by the server's CrowdSec. {}",
                            g.server,
                            n,
                            g.scenarios.join(", "),
                            sentry_core::secaudit::EDGE_FIX
                        ),
                    },
                    subject: Subject::Ingress,
                    can_wait: false,
                    class: Class::Guard,
                    next: None,
                })
        };
        out.extend(row);
    }
    out
}

/// The page's own row that is already about an audit item's subject, by its key (a
/// prefix), for the items that are this network's.
fn audit_subject(i: &sentry_core::secaudit::Item) -> Option<String> {
    let what = i.id.split(':').nth(1).unwrap_or("");
    Some(
        match what {
            "ssh-password" => "finding:net:ssh:password",
            "admin-http" => "finding:net:luci:http",
            "unknown-devices" => "finding:net:client:",
            "crossing" => "finding:net:flow:",
            "dns-filter" => "sec:blocklist",
            "wan-input" => "finding:net:zone:",
            "watch" => "finding:net:crowdsec:",
            // A door the page lists as one you haven't listed: `sec:door:<net>:<proto>:<port>`.
            "door" => {
                let mut end = i.id.rsplit(':');
                let (port, proto) = (end.next()?, end.next()?);
                return Some(format!("finding:net:forward:{proto}:{port}"));
            }
            _ => return None,
        }
        .to_string(),
    )
}

/// What Enter does on the audit's items whose fix is always of one kind, in plain words
/// (a certificate renewed or replaced, a release upgraded, a log kept longer). Others are
/// named from their fix's own words (`fix_step`).
fn audit_step(what: &str) -> Option<&'static str> {
    Some(match what {
        "cert" => "Enter: renew or replace it with Claude (you approve the plan)",
        "os-life" => "Enter: plan the upgrade with Claude (you approve the plan)",
        "logs" => "Enter: keep the log longer, with Claude (you approve the plan)",
        _ => return None,
    })
}

/// What Enter does on a row Maintenance carries out, in the row's own words.
fn maint_step(kind: crate::config::ItemKind) -> &'static str {
    use crate::config::ItemKind as K;
    match kind {
        K::Firmware => "Enter: upgrade the router's software (it shows the plan first)",
        K::Packages => "Enter: update the router's packages (it shows the plan first)",
        K::Backup => "Enter: make a backup of the router's settings",
    }
}

/// The security audit's items this page lists (the window's `Shared::sec`; the command line's latest report), joined with its own rows by
/// subject: where the page already has the row (it has the action), that row takes the
/// audit's why and its urgency and the item gets none; where the page's row was marked
/// expected, the item stays away too; the rest become rows of their own. What Maintenance
/// does (firmware, packages, the backup) is a row whose Enter goes there.
pub fn audit_rows(items: &[sentry_core::secaudit::Item], me: &str, s: &State, rows: &mut Vec<Row>) {
    use sentry_core::secaudit::State as St;
    for i in items {
        let own = i.targets.len() <= 1 || i.targets.iter().any(|t| t == me);
        let what = i.id.split(':').nth(1).unwrap_or("");
        let rank = match i.state {
            St::DoFirst => Rank::Now,
            St::Ask => Rank::Note,
            _ => Rank::Look,
        };
        if let Some(prefix) = audit_subject(i).filter(|_| own || what == "watch") {
            let prefix = prefix.as_str();
            if let Some(r) = rows.iter_mut().find(|r| r.key.starts_with(prefix)) {
                r.rank = r.rank.min(rank);
                r.can_wait = false;
                if !i.why.is_empty() && !r.why.contains(&i.why) {
                    r.why = format!("{} {}", i.why, r.why);
                }
                continue;
            }
            // The page read it and has no row: expected, or no longer so.
            let id = prefix.trim_start_matches("finding:");
            let expected = s
                .findings
                .iter()
                .any(|f| f.id.starts_with(id) && f.expected)
                || s.expected
                    .iter()
                    .any(|g| sentry_core::baseline::glob(g, id.trim_end_matches(':')));
            let read = match what {
                "unknown-devices" => s.read.clients.is_some(),
                "dns-filter" => s.read.dns.is_some(),
                _ => false,
            };
            // (A door you listed is still the audit's to judge: what answers behind it.)
            if (expected || read) && what != "door" {
                continue;
            }
        }
        let key = sentry_app::secaudit::row_key(&i.id);
        if s.expected
            .iter()
            .any(|g| sentry_core::baseline::glob(g, &key))
        {
            continue;
        }
        use crate::config::ItemKind as K;
        let maint = match what {
            "firmware" => Some(K::Firmware),
            "packages" => Some(K::Packages),
            "backup" => Some(K::Backup),
            _ => None,
        }
        .filter(|_| own);
        rows.push(Row {
            id: key.clone(),
            key,
            rank,
            title: i.title.clone(),
            why: match (i.state, i.fix.is_empty()) {
                (St::Ask, _) => {
                    "The security audit can't read this: only you know. Enter answers it."
                        .to_string()
                }
                (_, true) => i.why.clone(),
                (_, false) => format!("{} What it takes: {}", i.why, i.fix),
            },
            seen: i.evidence.clone(),
            act: match maint {
                Some(k) => Act::Maint(k),
                None => Act::Audit {
                    id: i.id.clone(),
                    asks: i.state == St::Ask,
                },
            },
            subject: match what {
                // What a door's own panel shows: the forward, its counts.
                "cert" | "door" => Subject::Ingress,
                _ => Subject::None,
            },
            can_wait: false,
            class: Class::of_audit(&i.id, i.group),
            next: match maint {
                Some(k) => Some(maint_step(k).to_string()),
                None if i.state != St::Ask => audit_step(what)
                    .map(str::to_string)
                    .or_else(|| fix_step(&i.fix)),
                None => None,
            },
        });
    }
}

/// A row's second line for a fix Claude carries out, named from the fix's own words
/// ("Enter: with Claude, remove the redirect"): the whole fix where it fits the line, else
/// its first clause; None where it doesn't name a change (a question, "run the audit
/// again") or doesn't fit, and the row says the general words.
pub fn fix_step(fix: &str) -> Option<String> {
    const MAX: usize = 63;
    let f = fix.trim().trim_end_matches('.');
    let f = match f.find("otherwise ") {
        Some(i) => &f[i + "otherwise ".len()..],
        None if f.starts_with("If you meant it") => return None,
        None => f,
    };
    if f.is_empty()
        || [
            "Run the audit",
            "See ",
            "Look at",
            "Check ",
            "Press ",
            "Answer ",
        ]
        .iter()
        .any(|p| f.starts_with(p))
    {
        return None;
    }
    let lower = |s: &str| {
        let mut c = s.chars();
        match (c.next(), s.chars().nth(1)) {
            (Some(a), Some(b)) if !b.is_uppercase() => {
                a.to_lowercase().collect::<String>() + c.as_str()
            }
            _ => s.to_string(),
        }
    };
    let mut candidates = vec![f];
    for sep in [". ", "; ", " (", ", or ", ": ", ", "] {
        if let Some(i) = f.find(sep) {
            candidates.push(&f[..i]);
        }
    }
    candidates
        .into_iter()
        // (Two words, "Fix it", say nothing the general words don't.)
        .filter(|c| c.split_whitespace().count() >= 3)
        .map(|c| format!("Enter: with Claude, {}", lower(c.trim())))
        .find(|s| s.chars().count() <= MAX)
}

/// The list as it is shown: each row in its class, the levels kept honest, several rows of
/// one kind as one, and the whole in order.
///
/// Whatever is only a `note` is housekeeping, and housekeeping is never more than a
/// `note`. From [`GROUP_AT`] rows of one [`Kind`] they become one row whose Enter lists
/// them; fewer stay rows of their own. `open` (a group's key) is the list being gone
/// through: it stays one row down to its last member, so the list doesn't fall apart
/// under the cursor as its count drops. Ties keep the order the rows were found in.
pub fn arrange(mut rows: Vec<Row>, open: Option<&str>) -> Vec<Row> {
    for r in &mut rows {
        if matches!(r.act, Act::Audit { asks: true, .. }) || r.rank == Rank::Note {
            r.class = Class::Housekeeping;
        }
        if r.class == Class::Housekeeping {
            r.rank = Rank::Note;
        }
    }
    for kind in Kind::ALL {
        let n = rows.iter().filter(|r| Kind::of(r) == Some(kind)).count();
        if n < GROUP_AT && !(n > 0 && open == Some(kind.key())) {
            continue;
        }
        let (members, rest): (Vec<Row>, Vec<Row>) =
            rows.into_iter().partition(|r| Kind::of(r) == Some(kind));
        rows = rest;
        rows.push(group(kind, members));
    }
    // (Among notes, what nothing asks for now comes last.)
    rows.sort_by_key(|r| (r.rank, r.class, r.can_wait));
    rows
}

/// "4 plugged in, 1 on Wi-Fi": how a group's devices are on the network.
fn by_link(rows: &[Row]) -> String {
    let n = |via: Via| {
        rows.iter()
            .filter(|r| matches!(&r.act, Act::Device(d) if d.via == via))
            .count()
    };
    [
        (n(Via::Wired), "plugged in"),
        (n(Via::Wifi), "on Wi-Fi"),
        (n(Via::Routed), "on the server's side"),
        (n(Via::Other), "elsewhere"),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, how)| format!("{n} {how}"))
    .collect::<Vec<_>>()
    .join(", ")
}

/// Rows of one kind as one row.
fn group(kind: Kind, rows: Vec<Row>) -> Row {
    let n = rows.len();
    let (title, why) = match kind {
        Kind::Devices => (
            format!(
                "{} {} no name yet: {}",
                plural(n, "device", "devices"),
                if n == 1 { "has" } else { "have" },
                by_link(&rows)
            ),
            "They have been here a while, so most are probably yours. Once each has a name, a \
             new device stands out the day it appears. One you don't know can be blocked or \
             paused to see what stops working.",
        ),
        Kind::Doors => (
            format!(
                "{} from the internet: tell sentry whether each asks for a login",
                plural(n, "door", "doors")
            ),
            "sentry sees that a door is open, not what answers behind it. A door that asks \
             for a login is a far smaller risk than one that lets anyone in: only you know \
             which these are.",
        ),
        Kind::Asks => (
            format!("{} only you can answer", plural(n, "question", "questions")),
            "The security audit can't read these from any device. Your answers decide what \
             it lists.",
        ),
        Kind::Odd => (
            format!(
                "{} {} using ports ordinary devices rarely use",
                plural(n, "device", "devices"),
                if n == 1 { "is" } else { "are" }
            ),
            "Rare for a healthy device and common for one that was taken over or is badly \
             set up. A reason to look, not a verdict.",
        ),
    };
    Row {
        key: kind.key().into(),
        id: kind.key().into(),
        rank: rows.iter().map(|r| r.rank).min().unwrap_or(Rank::Note),
        title,
        why: why.into(),
        seen: rows
            .iter()
            .map(|r| match &r.act {
                Act::Device(d) => d.label.clone(),
                _ => r.title.clone(),
            })
            .collect(),
        subject: Subject::None,
        can_wait: rows.iter().all(|r| r.can_wait),
        class: rows
            .iter()
            .map(|r| r.class)
            .min()
            .unwrap_or(Class::Housekeeping),
        next: None,
        act: Act::Group { kind, rows },
    }
}

/// A sentence in one line of `w`: whole where it fits; else up to the last clause that
/// does (a colon, a comma, a bracket), so it ends on a thought and not mid-word; else cut.
pub fn one_line(s: &str, w: usize) -> String {
    if s.chars().count() <= w {
        return s.to_string();
    }
    let head: String = s.chars().take(w.saturating_sub(1)).collect();
    let cut = [": ", ", ", " ("]
        .iter()
        .filter_map(|sep| head.rfind(sep))
        .max()
        .filter(|at| head[..*at].chars().count() * 2 >= w);
    match cut {
        Some(at) => format!("{}…", &head[..at]),
        None => format!("{}…", head.trim_end()),
    }
}

/// A row's two lines: its sentence and under it what Enter does, when the sentence fits
/// one line; else the sentence over both (the step gives way: the detail and the key bar
/// still say it), ending on a clause where even two lines are too few. The flag: the
/// second line is the step.
pub fn two_lines(title: &str, step: &str, w: usize) -> (String, String, bool) {
    let w = w.max(8);
    if title.chars().count() <= w {
        return (
            title.to_string(),
            sentry_core::tui::widgets::trunc(step, w),
            true,
        );
    }
    let mut l = sentry_core::tui::widgets::wrap(title, w).into_iter();
    let first = l.next().unwrap_or_default();
    let rest = l.collect::<Vec<_>>().join(" ");
    (first, one_line(&rest, w), false)
}

/// How many rows are the ones to start with: the first three that ask something of you
/// (a `note` never does).
pub fn start_here<'a>(rows: impl IntoIterator<Item = &'a Row>) -> usize {
    rows.into_iter()
        .take(3)
        .take_while(|r| r.rank != Rank::Note)
        .count()
}

/// The cover with every weak or missing part that has a row pointing at it ("see 2
/// above") instead of saying it twice. `rows`: the list as numbered on the page.
pub fn pointed(posture: &[Line], rows: &[&Row]) -> Vec<Line> {
    posture
        .iter()
        .map(|l| {
            let at: Vec<String> = match l.state {
                Cover::Weak | Cover::Off => rows
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| l.rows().iter().any(|p| r.about(p)))
                    .map(|(i, _)| (i + 1).to_string())
                    .collect(),
                _ => Vec::new(),
            };
            let see = match at.as_slice() {
                [] => return l.clone(),
                [one] => one.clone(),
                [most @ .., last] => format!("{} and {last}", most.join(", ")),
            };
            // (What a server's guard counted is said nowhere else: it stays.)
            let lead = match (l.what, l.text.rsplit_once("; ")) {
                ("server", Some((said, _))) => said,
                _ => l.label(),
            };
            Line {
                text: format!("{lead}: see {see} above"),
                ..l.clone()
            }
        })
        .collect()
}

/// How a line of the posture stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cover {
    Ok,
    Weak,
    Off,
    Unknown,
}

impl Cover {
    pub fn word(self) -> &'static str {
        match self {
            Cover::Ok => "ok",
            Cover::Weak => "weak",
            Cover::Off => "off",
            Cover::Unknown => "?",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// `reach`, `who`, `apart`, `filter`, `wifi`, `admin`, `edge`, `server`.
    pub what: &'static str,
    pub state: Cover,
    pub text: String,
}

impl Line {
    /// What the line is about, in a few words.
    pub fn label(&self) -> &'static str {
        match self.what {
            "reach" => "What the internet can reach",
            "who" => "Who is on the network",
            "apart" => "What is kept apart from what",
            "filter" => "Filtering of bad sites",
            "wifi" => "The Wi-Fi",
            "admin" => "Logging in to the router",
            "edge" => "Blocking attackers at the router",
            "server" => "The server's blocklist at the router",
            "family" => "The family filter",
            _ => "The security audit",
        }
    }

    /// The rows that say what is weak about it (key prefixes).
    pub fn rows(&self) -> &'static [&'static str] {
        match self.what {
            "reach" => &[
                "finding:net:forward:",
                "finding:net:zone:",
                "audit:sec:wan-input",
            ],
            "who" => &["finding:net:client:"],
            "apart" => &["finding:net:flow:", "audit:sec:flat", "audit:sec:crossing"],
            "filter" => &["sec:blocklist"],
            "wifi" => &["audit:sec:wifi", "audit:sec:wps"],
            "admin" => &["finding:net:ssh:password", "finding:net:luci:http"],
            "edge" | "server" => &["finding:net:crowdsec:"],
            "family" => &["sec:filter:"],
            _ => &[],
        }
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    match n {
        1 => format!("1 {one}"),
        n => format!("{n} {many}"),
    }
}

/// What a filtered device is called: as noted when it was ticked, else as the network
/// knows it now (by its MAC), else its MAC.
pub fn filtered_label(b: &Blocks, clients: Option<&[Client]>, tag: &str, mac: &str) -> String {
    b.device
        .get(tag)
        .map(|d| d.label.clone())
        .filter(|l| !l.is_empty())
        .or_else(|| {
            clients?
                .iter()
                .find(|c| {
                    c.mac
                        .as_deref()
                        .is_some_and(|m| m.eq_ignore_ascii_case(mac))
                })
                .map(|c| c.label().to_string())
        })
        .unwrap_or_else(|| mac.to_string())
}

/// sentry took the forcing of lookups over and its rules for it are gone, while the DNS
/// proxy's own is off: nobody's lookups are forced through the router.
fn unforced(u: &crate::collect::uci::Uci) -> bool {
    super::family::proxy_forces(u).is_some_and(|(_, on)| !on)
        && super::family::dns_found(u).is_empty()
}

/// The family filter's line of the cover: "Family filter: on 2 devices (a, b)".
fn say_family(
    s: &State,
    u: &crate::collect::uci::Uci,
    say: &mut dyn FnMut(&'static str, Cover, String),
) {
    let on = super::family::found(u);
    let svc = super::family::service();
    let names: Vec<String> = on
        .iter()
        .map(|f| filtered_label(s.blocks, s.read.clients, &f.tag, &f.mac))
        .collect();
    // What would stop it working in the home zone (the one a filter is usually for).
    let blocked = s
        .read
        .counters
        .map(|c| super::family::hijacked(c, "lan"))
        .unwrap_or_default();
    let drift = on
        .iter()
        .any(|f| !f.whole() || !s.blocks.filter.contains_key(&f.tag))
        || s.blocks
            .filter
            .keys()
            .any(|t| !on.iter().any(|f| &f.tag == t));
    let who = match names.len() {
        0 => "on no device".to_string(),
        n => {
            let shown: Vec<&str> = names.iter().take(3).map(String::as_str).collect();
            let more = if n > 3 {
                format!(" and {} more", n - 3)
            } else {
                String::new()
            };
            format!(
                "{} ({}{more})",
                plural(n, "device", "devices"),
                shown.join(", ")
            )
        }
    };
    let proxy_only = blocked.iter().all(|b| b == super::family::PROXY);
    let unforced = !names.is_empty() && unforced(u);
    let (state, text) = match (names.len(), blocked.is_empty()) {
        _ if unforced => (
            Cover::Off,
            format!(
                "Family filter: {who}, but lookups aren't forced through the router for anyone"
            ),
        ),
        (0, false) if proxy_only => (
            Cover::Ok,
            format!(
                "Family filter ({}): on no device · its first use takes over the router's \
                 forcing of lookups, the same for everyone else",
                svc.name
            ),
        ),
        (0, false) => (
            Cover::Ok,
            format!(
                "Family filter: on no device; it can't work on this router yet ({} sends \
                 every lookup to the router first)",
                blocked.join(", ")
            ),
        ),
        (_, false) => (
            Cover::Off,
            format!(
                "Family filter: {who}, but the router's forced lookups ({}) are in front of \
                 them again, so they aren't filtered",
                blocked.join(", ")
            ),
        ),
        (0, true) => (
            Cover::Ok,
            format!(
                "Family filter ({}): on no device · Enter under Filtered by you chooses",
                svc.name
            ),
        ),
        _ => (
            if drift { Cover::Weak } else { Cover::Ok },
            format!("Family filter ({}): on {who}", svc.name),
        ),
    };
    say("family", state, text);
}

/// How the network is covered: a sentence each, in a fixed order. A part that wasn't read
/// says so (`Unknown`); a part the router doesn't have is left out where its absence says
/// nothing (a bouncer), and said where it does (no filter).
pub fn posture(s: &State) -> Vec<Line> {
    let p = s.picture;
    let mut out = Vec::new();
    let mut say =
        |what: &'static str, state: Cover, text: String| out.push(Line { what, state, text });
    let open = |prefix: &str| {
        s.findings
            .iter()
            .any(|f| f.id.starts_with(prefix) && !f.expected)
    };
    let any = |id: &str| s.findings.iter().any(|f| f.id == id);
    let clients = s.read.clients;

    // What the internet can reach.
    match s.read.uci {
        None => say(
            "reach",
            Cover::Unknown,
            "What the internet can reach: not read yet".into(),
        ),
        Some(u) => {
            let doors: Vec<_> = u.forwards().into_iter().filter(|r| r.enabled).collect();
            let mut to: Vec<String> = Vec::new();
            for r in &doors {
                let who = clients
                    .unwrap_or(&[])
                    .iter()
                    .find(|c| c.addrs.iter().any(|a| a == &r.dest_ip))
                    .and_then(|c| c.name.clone())
                    .unwrap_or_else(|| r.dest_ip.clone());
                if !to.contains(&who) {
                    to.push(who);
                }
            }
            let wan_open = s
                .findings
                .iter()
                .any(|f| f.id.starts_with("net:zone:") && f.severity == Sev::High && !f.expected);
            let unlisted = s
                .findings
                .iter()
                .filter(|f| {
                    f.id.starts_with("net:forward:")
                        && !f.id.starts_with("net:forward:missing:")
                        && !f.expected
                })
                .count();
            let text = match (doors.len(), to.as_slice()) {
                (0, _) => {
                    "No door is open from the internet: nothing inside can be reached from outside"
                        .to_string()
                }
                (1, [one]) => format!("1 door is open from the internet, to {one}"),
                (n, [one]) => format!("{n} doors are open from the internet, all to {one}"),
                (n, many) => format!(
                    "{n} doors are open from the internet, to {} devices: {}",
                    many.len(),
                    many.join(", ")
                ),
            };
            if wan_open {
                say(
                    "reach",
                    Cover::Off,
                    format!("{text}; and the firewall lets the internet in beyond them"),
                );
            } else if unlisted > 0 {
                say(
                    "reach",
                    Cover::Weak,
                    format!("{text}; {unlisted} of them you haven't listed"),
                );
            } else {
                say("reach", Cover::Ok, text);
            }
        }
    }

    // Who is on the network.
    match clients {
        None => say(
            "who",
            Cover::Unknown,
            "Who is on the network: not read yet".into(),
        ),
        Some(c) => {
            let unknown = c.iter().filter(|c| c.unknown()).count();
            let private = c
                .iter()
                .filter(|c| c.name.is_none() && !c.unknown() && c.mac.is_some())
                .count();
            let total = plural(c.len(), "device", "devices");
            let vouched = match private {
                0 => String::new(),
                n => format!(" ({n} with a private address, vouched for by the Wi-Fi password)"),
            };
            match unknown {
                0 if private == 0 => say(
                    "who",
                    Cover::Ok,
                    format!("{total} on the network, all named"),
                ),
                0 => say(
                    "who",
                    Cover::Ok,
                    format!("{total} on the network, none unaccounted for{vouched}"),
                ),
                n => say(
                    "who",
                    Cover::Weak,
                    format!("{total} on the network, {n} not named{vouched}"),
                ),
            }
        }
    }

    // The sides kept apart.
    match &p.matrix {
        None => say(
            "apart",
            Cover::Unknown,
            "What is kept apart from what: not read yet".into(),
        ),
        Some(m) => {
            let apart = p.apart();
            let crossed = p.crossings();
            let inside = m.iter().filter(|x| !x.outside).count();
            let flows_read = s.read.flows.is_some();
            if let Some(x) = crossed.first() {
                say(
                    "apart",
                    Cover::Off,
                    format!(
                        "{} is meant to be kept from {}, but {} cross right now",
                        cap(&side(&x.from)),
                        side(&x.to),
                        plural(x.flows, "connection", "connections")
                    ),
                );
            } else if let Some(x) = apart.iter().find(|x| x.to == "lan").or(apart.first()) {
                say(
                    "apart",
                    Cover::Ok,
                    format!(
                        "{} can't reach {}: the rules say so{}",
                        cap(&side(&x.from)),
                        side(&x.to),
                        if flows_read {
                            ", and nothing crosses right now"
                        } else {
                            " (live connections not read yet)"
                        }
                    ),
                );
            } else if inside == 0 {
                say(
                    "apart",
                    Cover::Unknown,
                    "There is one network inside: nothing is kept apart from anything".into(),
                );
            } else {
                say(
                    "apart",
                    Cover::Weak,
                    "Every network inside can reach every other: nothing is kept apart".into(),
                );
            }
        }
    }

    // Filtering of bad sites.
    match s.read.dns {
        None => say(
            "filter",
            Cover::Unknown,
            "Filtering of bad sites: not read yet".into(),
        ),
        Some(d) => match &d.blocklist {
            None => say(
                "filter",
                Cover::Off,
                "No filtering of bad sites: the router has no blocklist".into(),
            ),
            Some(b) if !b.running => say(
                "filter",
                Cover::Off,
                "Filtering of bad sites is installed but not running".into(),
            ),
            Some(b) => {
                let days = d.list_age_days();
                let mut said = vec!["Bad sites are filtered".to_string()];
                if let Some(n) = b.entries {
                    said.push(format!("{n} listed"));
                }
                match days {
                    Some(0) => said.push("the list is from today".into()),
                    Some(1) => said.push("the list is a day old".into()),
                    Some(n) => said.push(format!("the list is {n} days old")),
                    None => {}
                }
                match b.auto_update {
                    Some(true) => said.push("it updates by itself".into()),
                    Some(false) => said.push("it doesn't update by itself".into()),
                    None => {}
                }
                let bypass = p.forced_dns == Some(false);
                if bypass {
                    said.push("a device can skip it by asking another service".into());
                }
                let weak =
                    b.errors > 0 || days.is_some_and(|d| d >= super::LIST_OLD_DAYS) || bypass;
                say(
                    "filter",
                    if weak { Cover::Weak } else { Cover::Ok },
                    said.join(", "),
                );
            }
        },
    }

    // The family filter: on which devices, and whether it can work here.
    if let Some(u) = s.read.uci {
        say_family(s, u, &mut say);
    }

    // Wi-Fi.
    if s.read.uci.is_some() {
        let aps = &p.aps;
        let open_ap = aps.iter().filter(|a| a.encryption == "none").count();
        let old = aps
            .iter()
            .filter(|a| a.encryption.starts_with("wep") || a.encryption == "psk")
            .count();
        let wps = aps.iter().any(|a| a.wps);
        let n = plural(aps.len(), "Wi-Fi network", "Wi-Fi networks");
        if aps.is_empty() {
            say("wifi", Cover::Ok, "No Wi-Fi is switched on".into());
        } else if open_ap > 0 {
            say(
                "wifi",
                Cover::Off,
                format!("{n}, {open_ap} open: anyone nearby can join without a password"),
            );
        } else if old > 0 {
            say(
                "wifi",
                Cover::Weak,
                format!("{n}, {old} on protection that is broken today (WEP or the first WPA)"),
            );
        } else if wps {
            say(
                "wifi",
                Cover::Weak,
                format!("{n}, password-protected, but joining by button (WPS) is on"),
            );
        } else {
            say(
                "wifi",
                Cover::Ok,
                format!("{n}, password-protected (WPA2/WPA3), no joining by button"),
            );
        }
    }

    // Admin access.
    if let Some(u) = s.read.uci {
        let ssh_pw = any("net:ssh:password");
        let http = any("net:luci:http");
        let has_ssh = !u.dropbear().is_empty();
        let text = match (ssh_pw, http) {
            (false, false) if has_ssh => {
                "Logging in to the router takes a key, and its admin page is encrypted"
            }
            (false, false) => "The router's admin page is encrypted",
            (true, false) => {
                "The router's admin page is encrypted, but its remote login (ssh) still takes a password"
            }
            (false, true) => {
                "Remote login (ssh) takes a key, but the admin page can be opened without encryption"
            }
            (true, true) => {
                "Remote login (ssh) takes a password, and the admin page can be opened without encryption"
            }
        };
        say(
            "admin",
            if ssh_pw || http {
                Cover::Weak
            } else {
                Cover::Ok
            },
            text.into(),
        );
    }

    // Attackers blocked at the edge: only where the router has a bouncer.
    if let Some(b) = s.bouncer {
        let down = open("net:crowdsec:");
        match (b.enabled, b.age_s, b.blocked()) {
            (e, _, _) if e != Some(true) => {
                say("edge", Cover::Off, edge_off(s.server_guard.is_some()))
            }
            (_, None, _) => say(
                "edge",
                Cover::Off,
                "CrowdSec's blocker on the router isn't running".into(),
            ),
            (_, Some(_), Some(n)) if n > 0 => say(
                "edge",
                Cover::Ok,
                format!("{n} known attackers are refused at the router (CrowdSec)"),
            ),
            _ => say(
                "edge",
                if down { Cover::Weak } else { Cover::Ok },
                "CrowdSec's blocker runs on the router, with nobody on its list yet".into(),
            ),
        }
    }

    // What the server's own guard reports (the seam: drawn when something provides it).
    if let Some(g) = s.server_guard {
        match g.enforced_here {
            Some(true) => say(
                "server",
                Cover::Ok,
                format!("{}; the router refuses them too", g.says()),
            ),
            _ => say(
                "server",
                Cover::Weak,
                format!("{}; the router doesn't enforce its bans", g.says()),
            ),
        }
    }
    out
}

#[cfg(test)]
mod wording {
    use super::*;

    #[test]
    fn a_fix_with_claude_is_named_in_its_own_words() {
        for (fix, said) in [
            (
                "Set redirect_https to 1 in /etc/config/uhttpd (or drop listen_http).",
                // (Too long for the line: the general words.)
                None,
            ),
            (
                "Close the firewall rule or bind it inside.",
                Some("Enter: with Claude, close the firewall rule or bind it inside"),
            ),
            (
                "If you meant it, add it to expect.forwards in network_config.yaml (or press b); otherwise remove the redirect.",
                Some("Enter: with Claude, remove the redirect"),
            ),
            (
                "Update it now (its row on the server's Maintenance screen), or close the door.",
                Some("Enter: with Claude, update it now"),
            ),
            ("Run the audit again when the router answers.", None),
            ("If you meant it, press b.", None),
            ("Fix it.", None),
            ("", None),
        ] {
            assert_eq!(fix_step(fix).as_deref(), said, "{fix}");
        }
        // Always within the line.
        let long = "Turn the thing that listens on every address of the router off, then check that nothing else needs it any more";
        assert!(fix_step(long).is_none_or(|s| s.chars().count() <= 63));
    }

    #[test]
    fn a_long_sentence_takes_the_step_line_and_ends_on_a_thought() {
        let (a, b, step) = two_lines("A short one", "Enter: do it", 40);
        assert_eq!(
            (a.as_str(), b.as_str(), step),
            ("A short one", "Enter: do it", true)
        );
        let (a, b, step) = two_lines(
            "Udp port 1900 on the router is open to the internet (the kernel)",
            "Enter: fix it",
            40,
        );
        assert!(!step);
        assert_eq!(
            format!("{a} {b}"),
            "Udp port 1900 on the router is open to the internet (the kernel)"
        );
        // Too long for two lines: the second ends on a clause, marked.
        let (_, b, _) = two_lines(
            "An unlisted door from the internet is open: game, which a device inside serves on udp port 8000 to 8010, nobody listed",
            "Enter",
            40,
        );
        assert!(b.ends_with('…') && b.chars().count() <= 40, "{b}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::clients::Station;
    use crate::collect::dnsstate::DnsState;
    use crate::collect::flows::Flows;
    use crate::collect::ifaces::Ifaces;
    use crate::collect::seclog::SecLog;
    use crate::collect::uci::Uci;
    use crate::collect::{dnsstate, fixture, flows, seclog};
    use crate::config::Network;
    use crate::redact::Salt;
    use crate::security::blocks::{Dev, Note, Reach};
    use crate::security::gather::{More, findings};
    use crate::security::tests::{line, the_clients, the_flows, the_ifaces};
    use sentry_core::baseline::BaselineFile;

    /// Everything read, to change one thing at a time.
    struct World {
        cfg: Network,
        ifaces: Option<Ifaces>,
        uci: Option<Uci>,
        clients: Option<Vec<Client>>,
        stations: Vec<Station>,
        flows: Option<Flows>,
        log: Option<SecLog>,
        dns: Option<DnsState>,
        expected: Vec<String>,
        blocks: Blocks,
        bouncer: Option<Bouncer>,
        guard: Option<ServerGuard>,
        now: i64,
    }

    fn uci_with(change: &[(&str, &str)], more: &str) -> Uci {
        let mut text = fixture("network/uci.txt");
        for (from, to) in change {
            assert!(text.contains(from), "the fixture has {from}");
            text = text.replace(from, to);
        }
        // (More firewall lines go in the firewall's part.)
        let text = text.replacen("@@dropbear", &format!("{more}@@dropbear"), 1);
        crate::collect::uci::parse(&text, &Salt::fixed([7; 16]))
    }

    impl World {
        fn fixture() -> Self {
            let cfg = crate::audit::tests::cfg();
            let raw = crate::collect::clients::parse(&fixture("network/clients.txt")).unwrap();
            World {
                ifaces: Some(the_ifaces()),
                uci: Some(uci_with(&[], "")),
                clients: Some(the_clients()),
                stations: raw.stations,
                flows: Some(the_flows()),
                log: Some(seclog::parse(&fixture("network/logread.txt"))),
                dns: Some(dnsstate::parse(&fixture("network/dnsstate.txt")).unwrap()),
                expected: Vec::new(),
                blocks: Blocks::default(),
                bouncer: None,
                guard: None,
                now: 1_793_016_000,
                cfg,
            }
        }

        /// Without `names`, as the clients were first read.
        fn forget(mut self, names: &[&str]) -> Self {
            for c in self.clients.iter_mut().flatten() {
                if c.name.as_deref().is_some_and(|n| names.contains(&n)) {
                    c.name = None;
                    c.known = false;
                }
            }
            self
        }

        fn with<R>(&self, f: impl FnOnce(&State) -> R) -> R {
            let read = Read {
                ifaces: self.ifaces.as_ref(),
                uci: self.uci.as_ref(),
                clients: self.clients.as_deref(),
                stations: Some(&self.stations),
                flows: self.flows.as_ref(),
                log: self.log.as_ref(),
                dns: self.dns.as_ref(),
                ..Default::default()
            };
            let picture = Picture::of(&read);
            let base = BaselineFile {
                findings: self.expected.clone(),
                ..Default::default()
            };
            let found = findings(
                "home",
                &self.cfg,
                &base,
                &read,
                More::default(),
                jiff::Timestamp::from_second(self.now).unwrap(),
            );
            f(&State {
                network: "home",
                read,
                picture: &picture,
                findings: &found,
                expected: &self.expected,
                blocks: &self.blocks,
                bouncer: self.bouncer.as_ref(),
                server_guard: self.guard.as_ref(),
                now: self.now,
            })
        }

        fn rows(&self) -> Vec<Row> {
            self.with(attention)
        }

        fn row(&self, key: &str) -> Row {
            let rows = self.rows();
            rows.iter()
                .find(|r| r.key == key || r.key.starts_with(key))
                .unwrap_or_else(|| {
                    panic!(
                        "no row {key} among {:?}",
                        rows.iter().map(|r| &r.key).collect::<Vec<_>>()
                    )
                })
                .clone()
        }

        fn has(&self, key: &str) -> bool {
            self.rows().iter().any(|r| r.key.starts_with(key))
        }

        fn cover(&self, what: &str) -> Option<(Cover, String)> {
            self.with(posture)
                .into_iter()
                .find(|l| l.what == what)
                .map(|l| (l.state, l.text))
        }
    }

    #[test]
    fn the_fixtures_rows_in_plain_sentences() {
        let w = World::fixture();
        let said: Vec<(Rank, bool, String, &str)> = w
            .rows()
            .into_iter()
            .map(|r| (r.rank, r.can_wait, r.title, r.act.enter()))
            .collect();
        let want = [
            (
                Rank::Look,
                false,
                "The router refused a login 3 times in the last 2 h 50 min",
                "the numbers",
            ),
            (
                Rank::Look,
                false,
                "192.0.2.77 is using a port ordinary devices rarely use (port 23)",
                "the numbers",
            ),
            (
                Rank::Look,
                false,
                "An unnamed device logged in to the router once in the last 2 h 50 min",
                "the numbers",
            ),
            (
                Rank::Note,
                false,
                "Someone tried a wrong Wi-Fi password twice in the last 2 h 50 min",
                "new password",
            ),
            (
                Rank::Note,
                true,
                "1 Wi-Fi device could be knocked off the Wi-Fi by a stranger nearby",
                "the numbers",
            ),
            (
                Rank::Note,
                true,
                "The list of bad sites doesn't update by itself",
                "keep updated",
            ),
        ];
        assert_eq!(said.len(), want.len(), "{said:#?}");
        for (got, want) in said.iter().zip(want) {
            assert_eq!((got.0, got.1, got.2.as_str(), got.3), want, "{said:#?}");
        }
        // A row that is an audit finding has Maintenance's key and the finding's id.
        let r = w.row("finding:net:ssh:failed");
        assert_eq!(r.id, "net:ssh:failed");
        assert_eq!(r.subject, Subject::Ingress);
        // No sentence leaves a term unexplained.
        for r in w.rows() {
            for jargon in ["DNAT", "conntrack", "MFP", "PSK", "DoT", "nft"] {
                assert!(!r.title.contains(jargon), "{jargon} in {}", r.title);
            }
            assert!(!r.why.is_empty(), "{}", r.key);
        }
    }

    #[test]
    fn each_kind_of_row_and_what_enter_does() {
        // Password logins: the row, and the refused logins' remedy becomes the same.
        let mut w = World::fixture();
        w.uci = Some(uci_with(
            &[(
                "dropbear.main.PasswordAuth='off'",
                "dropbear.main.PasswordAuth='on'",
            )],
            "",
        ));
        let r = w.row("finding:net:ssh:password");
        assert_eq!(
            (r.title.as_str(), &r.act, r.rank),
            (
                "The router's remote login (ssh) still accepts a password",
                &Act::SshKeys,
                Rank::Look
            )
        );
        assert_eq!(w.row("finding:net:ssh:failed").act, Act::SshKeys);

        // The admin page on plain HTTP.
        let mut w = World::fixture();
        w.uci = Some(uci_with(
            &[(
                "uhttpd.main.redirect_https='1'",
                "uhttpd.main.redirect_https='0'",
            )],
            "",
        ));
        let r = w.row("finding:net:luci:http");
        assert_eq!(r.act, Act::AdminHttps);
        assert!(
            r.title.ends_with("without encryption") && r.why.contains("plain HTTP"),
            "{}",
            r.title
        );

        // A live connection from the server's side into the home side.
        let mut w = World::fixture();
        let mut text = fixture("network/conntrack.txt");
        text.push_str(&line(
            "tcp",
            "203.0.113.93",
            "192.0.2.10",
            445,
            "192.0.2.10",
        ));
        w.flows = Some(flows::parse(&format!("@acct 1\n{text}")));
        let r = w.row("finding:net:flow:dmz-lan");
        assert_eq!(
            r.title,
            "A device on the server's side is reaching your home side right now"
        );
        assert_eq!(
            (r.rank, &r.act),
            (Rank::Now, &Act::Finding("net:flow:dmz-lan".into()))
        );
        assert_eq!(r.id, "net:flow:dmz-lan");
        assert_eq!(w.rows()[0].key, r.key, "act now comes first");
        assert!(
            r.seen[0].contains("1 live connection(s) across"),
            "{:?}",
            r.seen
        );
        // Marked expected (here or on Maintenance): gone.
        w.expected = vec!["net:flow:*".into()];
        assert!(!w.has("finding:net:flow"));

        // A device nobody has named: wired, with what it calls itself; Enter decides.
        let w = World::fixture().forget(&["desk"]);
        let r = w.row("finding:net:client:");
        assert!(
            r.title.starts_with("A device plugged into lan")
                && r.title.contains("has no name yet: ")
                && r.rank == Rank::Note
                && !r.can_wait,
            "{}",
            r.title
        );
        let Act::Device(dev) = &r.act else {
            panic!("{:?}", r.act)
        };
        assert_eq!(
            (dev.mac.as_str(), dev.zone.as_str(), dev.named),
            ("00:00:5e:00:53:11", "lan", false)
        );
        assert_eq!(r.key, format!("finding:net:client:{}", dev.tag));
        assert!(blocks::is_tag(&dev.tag) && !r.key.contains("53:11"));
        assert_eq!(r.subject, Subject::Egress(Some("00:00:5e:00:53:11".into())));
        // Blocked: it is under "Blocked by you", not a row; expected: gone too.
        let mut blocked = World::fixture().forget(&["desk"]);
        blocked.uci = Some(uci_with(
            &[],
            &format!(
                "firewall.sentry_block_{t}=rule\nfirewall.sentry_block_{t}.name='sentry-block-{t}'\n\
                 firewall.sentry_block_{t}.src='lan'\nfirewall.sentry_block_{t}.src_mac='00:00:5e:00:53:11'\n\
                 firewall.sentry_block_{t}.dest='wan'\nfirewall.sentry_block_{t}.target='REJECT'\n",
                t = dev.tag
            ),
        ));
        assert!(!blocked.has("finding:net:client:"));
        // … until its pause has ended: then a row offers to lift it.
        blocked.blocks.device.insert(
            dev.tag.clone(),
            Dev {
                mac: dev.mac.clone(),
                label: "tablet".into(),
                zone: "lan".into(),
                wifi: None,
            },
        );
        blocked.blocks.block.insert(
            dev.tag.clone(),
            Note {
                since: blocked.now - 7200,
                until: Some(blocked.now - 3600),
                reach: Reach::Internet,
                why: "paused for an hour".into(),
            },
        );
        let p = blocked.row("sec:pause:");
        assert_eq!(
            p.title,
            "The pause on tablet has ended: it is still blocked"
        );
        assert_eq!(
            p.act,
            Act::Unblock {
                tag: dev.tag.clone()
            }
        );
        blocked.blocks.block.get_mut(&dev.tag).unwrap().until = Some(blocked.now + 60);
        assert!(!blocked.has("sec:pause:"));
        let mut known = World::fixture().forget(&["desk"]);
        known.expected = vec![r.id.clone()];
        assert!(!known.has("finding:net:client:"));

        // A door nobody listed: the forward itself, to close.
        let mut w = World::fixture();
        w.cfg.expect.forwards.clear();
        let r = w.row("finding:net:forward:tcp:443");
        assert!(
            r.title == "An unlisted door from the internet is open: web (tcp port 443)",
            "{}",
            r.title
        );
        assert_eq!(
            (r.rank, &r.act),
            (
                Rank::Now,
                &Act::Forward {
                    section: "web_https".into(),
                    name: "web".into()
                }
            )
        );

        // The blocklist: old, and not updating; not running at all.
        let mut w = World::fixture();
        w.dns.as_mut().unwrap().now += 40 * 86_400;
        let r = w.row("sec:blocklist");
        assert_eq!(
            r.title,
            "The list of bad sites is 54 days old and doesn't update by itself"
        );
        assert_eq!(
            (r.rank, r.can_wait, &r.act),
            (
                Rank::Look,
                false,
                &Act::Blocklist {
                    stale: true,
                    scheduled: Some(false)
                }
            )
        );
        w.dns.as_mut().unwrap().blocklist.as_mut().unwrap().running = false;
        assert_eq!(
            w.row("sec:blocklist").title,
            "The filter for bad sites isn't running"
        );
        w.expected = vec!["sec:blocklist".into()];
        assert!(!w.has("sec:blocklist"));

        // Many wrong Wi-Fi passwords are worth a look; a few are a note.
        let mut w = World::fixture();
        let mut log = fixture("network/logread.txt");
        for _ in 0..10 {
            log.push_str(
                "Mon Oct 26 10:50:00 2026 daemon.notice hostapd: phy0-ap0: AP-STA-POSSIBLE-PSK-MISMATCH 02:00:5e:00:53:55\n",
            );
        }
        w.log = Some(seclog::parse(&log));
        let r = w.row("sec:wifi:psk");
        assert_eq!(
            (r.rank, r.act.clone(), r.subject.clone()),
            (Rank::Look, Act::WifiKey, Subject::Wifi)
        );
        assert!(
            r.title
                .starts_with("Someone tried a wrong Wi-Fi password 12 times in the last"),
            "{}",
            r.title
        );

        // Offloading: a note about the numbers, nothing to do.
        let mut w = World::fixture();
        w.flows.as_mut().unwrap().flows[0].offloaded = true;
        let r = w.row("sec:offload");
        assert_eq!(
            (r.rank, r.can_wait, &r.act),
            (Rank::Note, true, &Act::Evidence)
        );

        // What the server's guard saw: only when a server says it. ONE row for CrowdSec at
        // the edge, under the finding's own id (Maintenance's), whatever says it.
        const EDGE_ROW: &str = "finding:net:crowdsec:bouncer";
        let mut w = World::fixture();
        assert!(!w.has(EDGE_ROW) && w.cover("server").is_none());
        w.guard = Some(ServerGuard {
            server: "myserver".into(),
            banned_today: Some(7),
            scenarios: vec!["ssh brute force".into()],
            enforced_here: Some(false),
        });
        let r = w.row(EDGE_ROW);
        assert_eq!(
            r.title,
            "myserver blocked 7 attacker(s) today, but the router still lets them knock"
        );
        assert!(matches!(&r.act, Act::Server { brief } if brief.contains("ssh brute force")));
        assert_eq!(
            w.cover("server"),
            Some((
                Cover::Weak,
                "myserver blocked 7 attacker(s) today (mostly ssh brute force); the router doesn't enforce its bans".into()
            ))
        );
        w.guard.as_mut().unwrap().enforced_here = Some(true);
        assert!(!w.has(EDGE_ROW));
        assert_eq!(w.cover("server").unwrap().0, Cover::Ok);

        // The bouncer installed on the router and not switched on: the posture, the row
        // and the finding say one thing, there is one row, and its Enter is the session
        // across the server and the router that finishes it.
        const OFF: &str = "CrowdSec is installed on the router but switched off: attackers the server banned aren't turned away there";
        let mut w = World::fixture();
        w.bouncer = Some(Bouncer {
            enabled: Some(false),
            blocked4: None,
            blocked6: None,
            age_s: None,
        });
        w.guard = Some(ServerGuard {
            server: "myserver".into(),
            banned_today: Some(7),
            scenarios: vec!["ssh brute force".into()],
            enforced_here: Some(false),
        });
        let rows = w.with(attention);
        let edge: Vec<&Row> = rows
            .iter()
            .filter(|r| r.key.contains("crowdsec") || r.key.contains("server"))
            .collect();
        assert_eq!(edge.len(), 1, "{edge:#?}");
        let r = edge[0];
        assert_eq!((r.key.as_str(), r.id.as_str()), (EDGE_ROW, EDGE));
        assert_eq!(
            (r.title.as_str(), r.rank, r.can_wait),
            (OFF, Rank::Look, false)
        );
        assert!(
            matches!(&r.act, Act::Server { brief } if brief.contains("captured as a secret")
                && brief.contains("guarded change")),
            "{:?}",
            r.act
        );
        assert!(r.seen.iter().any(|s| s.starts_with("myserver blocked 7")));
        assert_eq!(w.cover("edge"), Some((Cover::Off, OFF.into())));
        // The server's CrowdSec runs but its count wasn't read: still the server's
        // blocklist, and the line says what is known.
        w.guard.as_mut().unwrap().banned_today = None;
        assert_eq!(w.row(EDGE_ROW).title, OFF);
        assert_eq!(
            w.cover("server"),
            Some((
                Cover::Weak,
                "CrowdSec runs on myserver (how many attackers it blocked today wasn't read); the router doesn't enforce its bans".into()
            ))
        );
        // Without a server that says anything, the same sentence without one.
        w.guard = None;
        assert_eq!(
            w.row(EDGE_ROW).title,
            "CrowdSec is installed on the router but switched off: known attackers aren't turned away there"
        );
        // Marked expected (here or on Maintenance): gone from both.
        w.expected = vec![EDGE.into()];
        assert!(!w.has(EDGE_ROW));
    }

    #[test]
    fn how_the_network_is_covered() {
        let w = World::fixture();
        let said: Vec<(&str, Cover, String)> = w
            .with(posture)
            .into_iter()
            .map(|l| (l.what, l.state, l.text))
            .collect();
        let want = [
            (
                "reach",
                "2 doors are open from the internet, to 2 devices: web, phone",
            ),
            (
                "who",
                "10 devices on the network, none unaccounted for (1 with a private address, vouched for by the Wi-Fi password)",
            ),
            (
                "apart",
                "The server's side (dmz) can't reach your home side (lan): the rules say so, and nothing crosses right now",
            ),
            (
                "filter",
                "Bad sites are filtered, 104200 listed, the list is 14 days old, it doesn't update by itself",
            ),
            (
                "family",
                "Family filter (CleanBrowsing Family): on no device · Enter under Filtered by you chooses",
            ),
            (
                "wifi",
                "2 Wi-Fi networks, password-protected (WPA2/WPA3), no joining by button",
            ),
            (
                "admin",
                "Logging in to the router takes a key, and its admin page is encrypted",
            ),
        ];
        assert_eq!(said.len(), want.len(), "{said:#?}");
        for (got, (what, text)) in said.iter().zip(want) {
            assert_eq!((got.0, got.1, got.2.as_str()), (what, Cover::Ok, text));
        }

        // Nothing read: every line says so, none claims anything; what the router
        // doesn't have (a bouncer) has no line.
        let mut none = World::fixture();
        (none.uci, none.clients, none.flows, none.dns) = (None, None, None, None);
        let lines = none.with(posture);
        assert_eq!(
            lines.iter().map(|l| (l.what, l.state)).collect::<Vec<_>>(),
            [
                ("reach", Cover::Unknown),
                ("who", Cover::Unknown),
                ("apart", Cover::Unknown),
                ("filter", Cover::Unknown)
            ]
        );

        // A door nobody listed; a device nobody named.
        let mut w = World::fixture().forget(&["desk", "dock"]);
        w.cfg.expect.forwards.clear();
        assert_eq!(
            w.cover("reach").unwrap(),
            (
                Cover::Weak,
                "2 doors are open from the internet, to 2 devices: web, phone; 2 of them you haven't listed".into()
            )
        );
        let (state, text) = w.cover("who").unwrap();
        assert_eq!(state, Cover::Weak);
        assert!(
            text.contains("10 devices on the network, 2 not named"),
            "{text}"
        );

        // The sides: crossed now is off.
        let mut w = World::fixture();
        let mut text = fixture("network/conntrack.txt");
        text.push_str(&line(
            "tcp",
            "203.0.113.93",
            "192.0.2.10",
            445,
            "192.0.2.10",
        ));
        w.flows = Some(flows::parse(&format!("@acct 1\n{text}")));
        assert_eq!(
            w.cover("apart").unwrap(),
            (
                Cover::Off,
                "The server's side (dmz) is meant to be kept from your home side (lan), but 1 connection cross right now".into()
            )
        );
        w.flows = None;
        assert!(
            w.cover("apart")
                .unwrap()
                .1
                .ends_with("(live connections not read yet)")
        );

        // Filtering: none installed, not running, old.
        let mut w = World::fixture();
        w.dns.as_mut().unwrap().blocklist = None;
        assert_eq!(w.cover("filter").unwrap().0, Cover::Off);
        let mut w = World::fixture();
        w.dns.as_mut().unwrap().now += 40 * 86_400;
        assert_eq!(w.cover("filter").unwrap().0, Cover::Weak);
        w.dns.as_mut().unwrap().blocklist.as_mut().unwrap().running = false;
        assert_eq!(
            w.cover("filter").unwrap(),
            (
                Cover::Off,
                "Filtering of bad sites is installed but not running".into()
            )
        );

        // Wi-Fi: an open network is off; joining by button is weak.
        let mut w = World::fixture();
        w.uci = Some(uci_with(
            &[(
                "wireless.default_radio1.encryption='sae'",
                "wireless.default_radio1.encryption='none'",
            )],
            "",
        ));
        let (state, text) = w.cover("wifi").unwrap();
        assert_eq!(state, Cover::Off);
        assert!(
            text.contains("1 open: anyone nearby can join without a password"),
            "{text}"
        );
        let mut w = World::fixture();
        w.uci = Some(uci_with(
            &[(
                "wireless.default_radio1.encryption='sae'",
                "wireless.default_radio1.encryption='sae'\nwireless.default_radio1.wps_pushbutton='1'",
            )],
            "",
        ));
        assert_eq!(w.cover("wifi").unwrap().0, Cover::Weak);

        // Admin access: each weak part is said.
        let mut w = World::fixture();
        w.uci = Some(uci_with(
            &[(
                "dropbear.main.PasswordAuth='off'",
                "dropbear.main.PasswordAuth='on'",
            )],
            "",
        ));
        assert_eq!(
            w.cover("admin").unwrap(),
            (
                Cover::Weak,
                "The router's admin page is encrypted, but its remote login (ssh) still takes a password".into()
            )
        );
        // … and a weak line is also a row above.
        assert!(w.has("finding:net:ssh:password"));

        // A bouncer on the router: a line; none: no line.
        let mut w = World::fixture();
        assert!(w.cover("edge").is_none());
        w.bouncer = Some(Bouncer {
            enabled: Some(true),
            blocked4: Some(1200),
            blocked6: Some(34),
            age_s: Some(86_400),
        });
        assert_eq!(
            w.cover("edge").unwrap(),
            (
                Cover::Ok,
                "1234 known attackers are refused at the router (CrowdSec)".into()
            )
        );
        w.bouncer.as_mut().unwrap().age_s = None;
        assert_eq!(w.cover("edge").unwrap().0, Cover::Off);
    }

    /// `sentry-network security`: the same list and cover, as text.
    #[test]
    fn the_list_and_the_cover_as_text() {
        let w = World::fixture();
        let said = crate::security::gather::Said {
            rows: w.rows(),
            posture: w.with(posture),
            filtered: vec![
                ("kid's tablet".into(), Some(0)),
                ("02:00:5e:00:53:44".into(), None),
            ],
            audited: Some("2026-10-26T09:00:00Z".parse().unwrap()),
        };
        let text = crate::cli::security_text("home", &said, &[]).join("\n");
        for want in [
            "home · security\n\nStart here\n   1. look     The router refused a login 3 times",
            "               A refused login is the lock holding",
            "\nThen\n   4. note     Someone tried a wrong Wi-Fi password twice",
            "               Security (4) · Enter: set a new Wi-Fi password",
            "\nHow you're covered\n  ok    2 doors are open from the internet",
            "  ok    Logging in to the router takes a key, and its admin page is encrypted",
            "What a tool like this can't see: what is inside the traffic",
            "\nFiltered by you (family filter, CleanBrowsing Family)\n  kid's tablet, since ",
            "  02:00:5e:00:53:44 (this machine has no note of when)",
            "The security audit's own rows are from its latest report (2026-10-26 09:00 UTC).",
        ] {
            assert!(text.contains(want), "{want}:\n{text}");
        }
        // Nothing but what can wait: it says so, and still lists the cover.
        let calm = crate::security::gather::Said {
            rows: said.rows.into_iter().filter(|r| r.can_wait).collect(),
            posture: said.posture,
            filtered: Vec::new(),
            audited: None,
        };
        let text = crate::cli::security_text("home", &calm, &[("log".into(), "no logread".into())])
            .join("\n");
        assert!(
            text.contains("Nothing needs you.\n   1. note ")
                && text.contains("How you're covered")
                && text.contains("(not read: log: no logread)"),
            "{text}"
        );
    }

    /// A row as a table needs it: its key says what it is.
    fn a(key: &str, rank: Rank, act: Act) -> Row {
        Row {
            key: key.into(),
            id: key.into(),
            rank,
            title: key.into(),
            why: String::new(),
            seen: Vec::new(),
            act,
            subject: Subject::None,
            can_wait: false,
            class: match key.strip_prefix("audit:") {
                Some(id) => Class::of_audit(id, sentry_core::secaudit::Group::GettingIn),
                None => Class::of(key),
            },
            next: None,
        }
    }

    fn asks(id: &str) -> Row {
        a(
            &format!("audit:{id}"),
            Rank::Note,
            Act::Audit {
                id: id.into(),
                asks: true,
            },
        )
    }

    fn keys(rows: &[Row]) -> Vec<&str> {
        rows.iter().map(|r| r.key.as_str()).collect()
    }

    /// The order, one row per class: by level first, then the seven classes, and rows
    /// that tie stay as they were found.
    #[test]
    fn the_order_is_by_level_then_by_class() {
        use Class::*;
        // Each kind of row is in the class the table says.
        for (key, want) in [
            ("finding:net:flow:dmz-lan", Live),
            ("sec:inbound", Live),
            ("finding:net:ssh:failed", Live),
            ("sec:ssh:unknown", Live),
            ("sec:wifi:psk", Live),
            ("sec:odd:ab12", Live),
            ("finding:net:forward:tcp:443", Hole),
            ("finding:net:zone:wan", Hole),
            ("finding:net:listener:udp:1900", Hole),
            ("finding:net:ssh:password", Login),
            ("finding:net:luci:http", Login),
            ("finding:net:cert:expiry", Login),
            ("finding:net:crowdsec:bouncer", Guard),
            ("finding:net:service:dnsmasq", Guard),
            ("sec:blocklist", Guard),
            ("finding:net:client:ab12", Housekeeping),
            ("sec:pause:ab12", Housekeeping),
            ("sec:offload", Housekeeping),
        ] {
            assert_eq!(Class::of(key), want, "{key}");
        }
        let g = sentry_core::secaudit::Group::Recovering;
        for (id, want) in [
            ("sec:crossing:net:home:dmz:lan", Live),
            ("sec:firmware:net:home", Hole),
            ("sec:packages:net:home", Hole),
            ("sec:app:srv:myserver:stack", Hole),
            ("sec:door:net:home:tcp:443", Hole),
            ("sec:os-life:srv:myserver", Hole),
            ("sec:ssh-password:srv:myserver", Login),
            ("sec:cert:net:home:tcp:443", Login),
            ("sec:admin-http:net:home", Login),
            ("sec:watch", Guard),
            ("sec:dns-filter:net:home", Guard),
            ("sec:flat:net:home", Structure),
            ("sec:backup:net:home", Recovery),
            ("sec:logs:net:home", Recovery),
            ("sec:unknown-devices:net:home", Housekeeping),
            ("sec:something-new:net:home", Recovery),
        ] {
            assert_eq!(Class::of_audit(id, g), want, "{id}");
        }

        // One row per class at one level, handed over backwards: out in the table's order.
        let look = |key: &str| a(key, Rank::Look, Act::Evidence);
        let one_each = [
            "sec:inbound",
            "audit:sec:firmware:net:home",
            "finding:net:ssh:password",
            "sec:blocklist",
            "audit:sec:flat:net:home",
            "audit:sec:backup:net:home",
            "finding:net:client:ab12",
        ];
        let rows = arrange(one_each.iter().rev().map(|k| look(k)).collect(), None);
        assert_eq!(keys(&rows), one_each);
        assert_eq!(
            rows.iter().map(|r| r.class).collect::<Vec<_>>(),
            [Live, Hole, Login, Guard, Structure, Recovery, Housekeeping]
        );
        // Housekeeping is never more than a note; the rest keep their level.
        assert_eq!(rows[6].rank, Rank::Note);
        assert!(rows[..6].iter().all(|r| r.rank == Rank::Look));

        // An act-now is never under a look, whatever their classes: a login the outside
        // reaches comes before something live that is only worth a look.
        let rows = arrange(
            vec![
                look("sec:inbound"),
                a("finding:net:ssh:password", Rank::Now, Act::SshKeys),
                a(
                    "audit:sec:firmware:net:home",
                    Rank::Now,
                    Act::Maint(crate::config::ItemKind::Firmware),
                ),
                a("finding:net:flow:dmz-lan", Rank::Now, Act::Evidence),
            ],
            None,
        );
        assert_eq!(
            keys(&rows),
            [
                "finding:net:flow:dmz-lan",
                "audit:sec:firmware:net:home",
                "finding:net:ssh:password",
                "sec:inbound"
            ]
        );
        // Ties keep the order they were found in.
        let rows = arrange(
            vec![
                look("finding:net:forward:udp:8000"),
                look("sec:odd:b"),
                look("finding:net:forward:tcp:443"),
                look("sec:odd:a"),
            ],
            None,
        );
        assert_eq!(
            keys(&rows),
            [
                "sec:odd:b",
                "sec:odd:a",
                "finding:net:forward:udp:8000",
                "finding:net:forward:tcp:443"
            ]
        );
        // What is only a note is housekeeping wherever it came from, and a question is a
        // note: both under everything that asks something.
        let rows = arrange(
            vec![
                asks("sec:restore:net:home"),
                a("sec:wifi:psk", Rank::Note, Act::WifiKey),
                look("audit:sec:backup:net:home"),
            ],
            None,
        );
        assert_eq!(
            rows.iter().map(|r| (r.class, r.rank)).collect::<Vec<_>>(),
            [
                (Recovery, Rank::Look),
                (Housekeeping, Rank::Note),
                (Housekeeping, Rank::Note)
            ]
        );
        // The first three that ask something are where to start; a note never is.
        assert_eq!(start_here(&rows), 1);
        assert_eq!(start_here(&arrange(one_each.map(look).into(), None)), 3);
        assert_eq!(start_here(&[asks("sec:restore:net:home")]), 0);
        assert_eq!(start_here(&[]), 0);
    }

    impl World {
        /// With `n` devices nobody has named, first seen a month ago (every other one on
        /// the Wi-Fi), and nothing else unnamed.
        fn unnamed(n: usize) -> Self {
            let mut w = World::fixture();
            let now = w.now;
            let list = w.clients.as_mut().unwrap();
            let base = list
                .iter()
                .find(|c| c.name.as_deref() == Some("desk"))
                .unwrap()
                .clone();
            for c in list.iter_mut() {
                c.first_seen = Some(now - 40 * 86_400);
            }
            for i in 0..n {
                let mac = format!("00:00:5e:00:54:{i:02x}");
                list.push(Client {
                    key: mac.clone(),
                    mac: Some(mac),
                    name: None,
                    known: false,
                    hostname: Some(format!("thing-{i}")),
                    addrs: vec![format!("192.0.2.{}", 200 + i)],
                    link: if i % 2 == 1 {
                        Link::Wifi {
                            ifname: "phy0-ap0".into(),
                            signal: None,
                        }
                    } else {
                        Link::Wired {
                            port: "lan3".into(),
                        }
                    },
                    first_seen: Some(now - 30 * 86_400),
                    connected_s: None,
                    ..base.clone()
                });
            }
            w
        }

        fn devices(&self) -> Vec<Row> {
            self.rows()
                .into_iter()
                .filter(|r| r.about("finding:net:client:"))
                .collect()
        }
    }

    #[test]
    fn unnamed_devices_are_one_row_from_three_and_a_new_one_stands_alone() {
        // None, one, two: rows of their own (or none), each a note that is still listed.
        for n in [0, 1, 2] {
            let rows = World::unnamed(n).devices();
            assert_eq!(rows.len(), n, "{n}");
            assert!(
                rows.iter().all(|r| matches!(r.act, Act::Device(_))
                    && r.rank == Rank::Note
                    && !r.can_wait
                    && r.title.contains("has no name yet: thing-")),
                "{rows:#?}"
            );
        }
        // Three: one row, which says how many and how they are on the network.
        let rows = World::unnamed(3).devices();
        assert_eq!(rows.len(), 1, "{rows:#?}");
        let g = &rows[0];
        assert_eq!(
            (g.key.as_str(), g.title.as_str(), g.rank, g.can_wait),
            (
                "group:devices",
                "3 devices have no name yet: 2 plugged in, 1 on Wi-Fi",
                Rank::Note,
                false
            )
        );
        assert_eq!(g.members().len(), 3);
        assert_eq!(g.seen, ["thing-0", "thing-1", "thing-2"]);
        assert_eq!(
            g.step(true),
            "Enter: go through them (name, block or pause each)"
        );
        // Seven, as on a network nobody has described yet.
        let w = World::unnamed(7);
        let rows = w.devices();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].title,
            "7 devices have no name yet: 4 plugged in, 3 on Wi-Fi"
        );
        // One of them joined twenty minutes ago: that is news, a row of its own above
        // everything that is housekeeping; the other six stay one row.
        let mut w = World::unnamed(7);
        let now = w.now;
        w.clients.as_mut().unwrap().last_mut().unwrap().first_seen = Some(now - 1200);
        let rows = w.rows();
        let new = rows
            .iter()
            .position(|r| r.title.contains("thing-6"))
            .unwrap();
        let rest = rows.iter().position(|r| r.key == "group:devices").unwrap();
        assert_eq!(
            (rows[new].title.as_str(), rows[new].rank, rows[new].class),
            (
                "A device nobody has named was plugged into lan3 20 minutes ago: thing-6",
                Rank::Look,
                Class::Live
            )
        );
        assert!(new < rest, "{:?}", keys(&rows));
        assert_eq!(rows[rest].members().len(), 6);
        assert!(rows[new + 1..rest].iter().all(|r| r.rank <= Rank::Note));
        // On the Wi-Fi it says so.
        w.clients.as_mut().unwrap().last_mut().unwrap().link = Link::Wifi {
            ifname: "phy0-ap0".into(),
            signal: None,
        };
        assert!(w.rows().iter().any(
            |r| r.title == "A device nobody has named joined the Wi-Fi 20 minutes ago: thing-6"
        ));
        // sentry itself started watching today: nothing can be called new yet.
        for c in w.clients.as_mut().unwrap() {
            c.first_seen = Some(now - 1200);
        }
        let rows = w.devices();
        assert_eq!(rows.len(), 1, "{:?}", keys(&rows));
        assert!(rows[0].members().len() >= 7);

        // A list being gone through stays one row down to its last device, then is gone.
        let open = |n: usize| World::unnamed(n).with(|s| arrange(raw(s), Some("group:devices")));
        for n in [2, 1] {
            let rows = open(n);
            let g = rows.iter().find(|r| r.key == "group:devices").unwrap();
            assert_eq!(g.members().len(), n);
        }
        assert_eq!(
            open(1)
                .iter()
                .find(|r| r.key == "group:devices")
                .unwrap()
                .title,
            "1 device has no name yet: 1 plugged in"
        );
        assert!(open(0).iter().all(|r| r.key != "group:devices"));
    }

    #[test]
    fn questions_and_odd_ports_are_one_row_from_three() {
        let door = |port: u16| asks(&format!("sec:door:net:home:tcp:{port}"));
        // Two doors to answer for: two rows.
        let rows = arrange(vec![door(80), door(443)], None);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.members().is_empty()));
        // Three: one row; another kind of question stays its own.
        let rows = arrange(
            vec![
                door(80),
                asks("sec:restore:net:home"),
                door(443),
                door(8443),
            ],
            None,
        );
        assert_eq!(keys(&rows), ["audit:sec:restore:net:home", "group:doors"]);
        let g = &rows[1];
        assert_eq!(
            g.title,
            "3 doors from the internet: tell sentry whether each asks for a login"
        );
        assert_eq!(
            (g.rank, g.class, g.can_wait, g.members().len()),
            (Rank::Note, Class::Housekeeping, false, 3)
        );
        assert_eq!(g.step(false), "Enter: answer them one after another");
        assert!(g.about("audit:sec:door:net:home:tcp:443"));
        // Three devices on odd ports: one row, worth a look as each of them is.
        let odd = |t: &str| a(&format!("sec:odd:{t}"), Rank::Look, Act::Evidence);
        let rows = arrange(vec![odd("a"), odd("b"), odd("c")], None);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].title.as_str(), rows[0].rank, rows[0].class),
            (
                "3 devices are using ports ordinary devices rarely use",
                Rank::Look,
                Class::Live
            )
        );
        assert_eq!(arrange(vec![odd("a"), odd("b")], None).len(), 2);
    }

    #[test]
    fn a_weak_part_of_the_cover_points_at_its_row() {
        let line = |what: &'static str, state: Cover, text: &str| Line {
            what,
            state,
            text: text.into(),
        };
        let cover = [
            line(
                "reach",
                Cover::Ok,
                "1 door is open from the internet, to web",
            ),
            line("who", Cover::Weak, "9 devices on the network, 3 not named"),
            line(
                "admin",
                Cover::Weak,
                "Remote login (ssh) takes a password, and …",
            ),
            line(
                "filter",
                Cover::Off,
                "Filtering of bad sites is installed but not running",
            ),
            line(
                "wifi",
                Cover::Weak,
                "2 Wi-Fi networks, 1 on protection that is broken",
            ),
        ];
        let rows = arrange(
            vec![
                a("finding:net:ssh:password", Rank::Look, Act::SshKeys),
                a("finding:net:luci:http", Rank::Look, Act::AdminHttps),
                a("sec:blocklist", Rank::Look, Act::Evidence),
                a("finding:net:client:a", Rank::Note, Act::Device(dev("a"))),
                a("finding:net:client:b", Rank::Note, Act::Device(dev("b"))),
                a("finding:net:client:c", Rank::Note, Act::Device(dev("c"))),
            ],
            None,
        );
        let listed: Vec<&Row> = rows.iter().collect();
        let said: Vec<String> = pointed(&cover, &listed)
            .into_iter()
            .map(|l| l.text)
            .collect();
        assert_eq!(
            said,
            [
                // Fine: said as it is.
                "1 door is open from the internet, to web",
                // The three devices are one row, the fourth.
                "Who is on the network: see 4 above",
                "Logging in to the router: see 1 and 2 above",
                "Filtering of bad sites: see 3 above",
                // Weak, and no row says why: the line still does.
                "2 Wi-Fi networks, 1 on protection that is broken",
            ]
        );
    }

    fn dev(tag: &str) -> DevRef {
        DevRef {
            mac: format!("00:00:5e:00:53:{tag}"),
            tag: tag.into(),
            label: tag.into(),
            zone: "lan".into(),
            wifi: None,
            named: false,
            via: Via::Wired,
        }
    }

    /// The second line of every row: it starts with the key, says a thing to do, and
    /// fits a narrow list's line.
    #[test]
    fn every_row_says_what_enter_does_in_one_short_line() {
        let acts = [
            Act::Device(dev("a")),
            Act::Unblock { tag: "a".into() },
            Act::Forward {
                section: "s".into(),
                name: "web".into(),
            },
            Act::SshKeys,
            Act::AdminHttps,
            Act::Blocklist {
                stale: true,
                scheduled: Some(false),
            },
            Act::Blocklist {
                stale: false,
                scheduled: Some(false),
            },
            Act::WifiKey,
            Act::Finding("net:x".into()),
            Act::Evidence,
            Act::Server {
                brief: String::new(),
            },
            Act::Audit {
                id: "sec:x".into(),
                asks: true,
            },
            Act::Audit {
                id: "sec:x".into(),
                asks: false,
            },
            Act::Maint(crate::config::ItemKind::Firmware),
            Act::Group {
                kind: Kind::Devices,
                rows: Vec::new(),
            },
            Act::Group {
                kind: Kind::Doors,
                rows: Vec::new(),
            },
            Act::Group {
                kind: Kind::Odd,
                rows: Vec::new(),
            },
        ];
        for act in &acts {
            for claude in [true, false] {
                let step = act.step(claude);
                assert!(step.starts_with("Enter: "), "{step}");
                assert!(step.chars().count() <= 63, "{} chars: {step}", step.len());
                for jargon in ["ssh", "HTTP ", "bouncer", "uci", "DNAT"] {
                    assert!(!step.contains(jargon), "{jargon} in {step}");
                }
            }
        }
        // Without Claude Code a session's row says what Enter still does.
        assert_eq!(
            Act::Finding("net:x".into()).step(false),
            "Enter: see the numbers behind it (nothing to change)"
        );
        // A row that knows better says so itself.
        let mut r = a(
            "audit:sec:firmware:net:home",
            Rank::Now,
            Act::Maint(crate::config::ItemKind::Firmware),
        );
        assert_eq!(
            r.step(true),
            "Enter: upgrade the router's software (it shows the plan first)"
        );
        r.next = Some("Enter: something it knows better".into());
        assert_eq!(r.step(true), "Enter: something it knows better");
    }

    #[test]
    fn a_long_sentence_ends_on_a_clause_in_the_list() {
        let s =
            "Every device at home shares one network, so one compromised gadget can reach the rest";
        assert_eq!(one_line(s, 100), s);
        assert_eq!(one_line(s, 69), "Every device at home shares one network…");
        assert_eq!(
            one_line(
                "5 devices have no name yet: 3 plugged in, 1 on Wi-Fi, 1 elsewhere",
                50
            ),
            "5 devices have no name yet: 3 plugged in…"
        );
        // No clause to end on (or only a stub of one): cut where the line ends.
        assert_eq!(one_line("abcdefghij klmnopqrst", 12), "abcdefghij…");
        assert_eq!(
            one_line("So, this goes on and on and on", 20),
            "So, this goes on an…"
        );
        assert!(one_line(s, 69).chars().count() <= 69);
    }

    #[test]
    fn words_for_sentences() {
        assert_eq!(
            [40, 60, 1200, 3600, 9600, 7200, 86_400, 3 * 86_400].map(lasting),
            [
                "40 seconds",
                "a minute",
                "20 minutes",
                "an hour",
                "2 h 40 min",
                "2 hours",
                "a day",
                "3 days"
            ]
        );
        assert_eq!([1, 2, 12].map(times), ["once", "twice", "12 times"]);
        assert_eq!(side("dmz"), "the server's side (dmz)");
        assert_eq!(side("kids"), "the kids network");
        assert_eq!(
            [Rank::Now, Rank::Look, Rank::Note].map(Rank::word),
            ["act now", "look", "note"]
        );
        assert!(Rank::Now < Rank::Look && Rank::Look < Rank::Note);
    }

    /// The audit's certificate, end-of-support and log items say in plain words what
    /// Enter does, are in their class, and a door's certificate shows the door's panel.
    #[test]
    fn the_audits_certificate_release_and_log_rows_say_what_enter_does() {
        use sentry_core::secaudit::{Group, Item, State as St};
        let item = |id: &str, group, fix: &str| Item {
            id: id.into(),
            group,
            state: St::Worth,
            rank: 0,
            title: format!("about {id}"),
            why: "Why.".into(),
            fix: fix.into(),
            targets: vec!["net:home".into()],
            evidence: vec![],
            brief: String::new(),
            question: None,
        };
        let items = [
            item(
                "sec:cert:net:home:tcp:443",
                Group::GettingIn,
                "Use a certificate from a public authority (Let's Encrypt is free and renews \
                 by itself).",
            ),
            item(
                "sec:os-life:net:home",
                Group::KnownHoles,
                "Upgrade to a supported release (with a backup first); a session with Claude \
                 can plan it.",
            ),
            item(
                "sec:logs:net:home",
                Group::Recovering,
                "Keep more of it (journald's size and age limits); a session with Claude can.",
            ),
        ];
        let w = World::fixture();
        let rows = w.with(|s| {
            let mut rows = Vec::new();
            audit_rows(&items, "net:home", s, &mut rows);
            rows
        });
        let of = |id: &str| {
            rows.iter()
                .find(|r| r.id == sentry_app::secaudit::row_key(id))
                .unwrap_or_else(|| panic!("no row for {id}: {rows:#?}"))
        };
        for (id, step, class, subject) in [
            (
                "sec:cert:net:home:tcp:443",
                "Enter: renew or replace it with Claude (you approve the plan)",
                Class::Login,
                Subject::Ingress,
            ),
            (
                "sec:os-life:net:home",
                "Enter: plan the upgrade with Claude (you approve the plan)",
                Class::Hole,
                Subject::None,
            ),
            (
                "sec:logs:net:home",
                "Enter: keep the log longer, with Claude (you approve the plan)",
                Class::Recovery,
                Subject::None,
            ),
        ] {
            let r = of(id);
            assert_eq!(r.step(true), step, "{id}");
            assert!(step.chars().count() <= 63, "{step}");
            assert_eq!(r.class, class, "{id}");
            assert_eq!(r.subject, subject, "{id}");
            // Without Claude Code: what Enter still does.
            assert_eq!(
                r.step(false),
                "Enter: read it in the security audit's report"
            );
        }
    }
}

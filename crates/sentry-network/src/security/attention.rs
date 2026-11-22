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
    /// The audit says it, Maintenance does it (firmware, packages, the backup).
    Maint,
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
            Act::Maint => "Maintenance",
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
            tag: blocks::tag(self.network, &mac)?,
            mac,
            label: c.label().to_string(),
            zone,
            wifi: match &c.link {
                Link::Wifi { ifname, .. } => Some(ifname.clone()),
                _ => None,
            },
            named: c.name.is_some(),
        })
    }
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

/// The router has the blocker and it isn't switched on: one sentence, wherever it is said
/// (the posture, the row, the finding, the audit).
pub fn edge_off(server: bool) -> String {
    format!(
        "CrowdSec's blocker is installed on the router but not switched on: {} isn't \
         enforced at the edge yet",
        if server {
            "the server's blocklist"
        } else {
            "what CrowdSec would block"
        }
    )
}
/// These only when they are high: the outside reaches something.
const OTHER_HIGH: &[&str] = &["net:zone:", "net:listener:"];

/// What needs you, most urgent first. Rows marked expected aren't here; rows put off are
/// the caller's to drop (it has the later list).
pub fn attention(s: &State) -> Vec<Row> {
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
        act,
        subject,
        can_wait: f.severity == Sev::Low,
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
    };

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
                Rank::Look,
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
                "Something on {} is talking to a device on {}: that should never happen",
                side(&x.from),
                side(&x.to)
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
                    "A door from the internet is open that you haven't listed: {}, {proto} port {port} to {}",
                    r.name, r.dest_ip
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
            "The router lets people log in over ssh with a password".into(),
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
                "Someone tried to log in to the router {} and was refused, {}",
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
            "The router's admin page can be opened without encryption (plain HTTP)".into(),
            "Whoever is on the network could read the admin password as it is typed. Sending \
             the page on to HTTPS closes that."
                .into(),
            Act::AdminHttps,
            Subject::None,
        ));
    }

    // Devices nobody has named.
    for c in s.read.clients.unwrap_or(&[]).iter().filter(|c| c.unknown()) {
        let Some(mac) = &c.mac else { continue };
        let id = crate::audit::client_id(s.network, mac);
        let Some(dev) = s.dev(c, nets.as_ref()) else {
            continue;
        };
        if s.dismissed(&id) || blocked(&dev.tag) {
            continue;
        }
        let since = match (c.connected_s, c.first_seen) {
            (Some(n), _) => Some(n),
            (None, Some(t)) if s.now > t => Some((s.now - t) as u64),
            _ => None,
        };
        let ago = since.map_or(String::new(), |n| format!(" {} ago", lasting(n)));
        // (What it calls itself, or its MAC: two such rows are two devices.)
        let it = c.label();
        let title = match &c.link {
            Link::Wifi { .. } => {
                format!("A device nobody has named joined the Wi-Fi{ago}: {it}")
            }
            Link::Wired { port } => {
                format!("A device nobody has named is plugged into {port}: {it}")
            }
            Link::Dmz { net, .. } => {
                format!("A device nobody has named is on {}: {it}", side(net))
            }
            Link::Unknown => {
                format!("A device nobody has named holds an address on the network: {it}")
            }
        };
        let mut seen = vec![match &c.hostname {
            Some(h) => format!("It calls itself {h} · {mac}"),
            None => format!("It gives no name · {mac}"),
        }];
        if !c.addrs.is_empty() {
            seen.push(format!("address {}", c.addrs.join(", ")));
        }
        out.push(Row {
            key: format!("finding:{id}"),
            id,
            rank: Rank::Look,
            title,
            why: "Whatever is on your network can talk to your other devices. If it is yours, \
                  name it; if you don't know it, block it or pause it and see what stops \
                  working."
                .into(),
            seen,
            act: Act::Device(dev),
            subject: Subject::Egress(Some(c.key.clone())),
            can_wait: false,
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
                "{} is talking to the internet in a way ordinary devices rarely do (port {})",
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
                    "{flows} connection(s) from the internet reach devices inside directly, \
                     with no door (port forward) set up for them"
                ),
                "Usually IPv6, where every device has a public address: the firewall should \
                 still refuse what nobody inside asked for.",
                Act::Evidence,
                Subject::Ingress,
            )),
            Mark::SshUnknown { logins } => Some(own(
                "sec:ssh:unknown",
                Rank::Look,
                format!(
                    "Someone logged in to the router {} from a device nobody has named, {}",
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
                    format!(
                        "A device is trying to look names up behind the router's back \
                         ({per_min:.1} tries a minute, all refused)"
                    ),
                    "Encrypted name lookups to an outside service (DNS over TLS) would skip \
                     your filtering of bad sites. The router refuses them; phones try by \
                     habit (Android's Private DNS).",
                    Act::Evidence,
                    Subject::Dns,
                );
                r.can_wait = true;
                Some(r)
            }
            Mark::NoMfp { stations } => {
                let mut r = own(
                    "sec:wifi:mfp",
                    Rank::Note,
                    format!(
                        "{} on the Wi-Fi {} use the protection against being knocked off \
                         by a stranger",
                        plural(*stations, "device", "devices"),
                        if *stations == 1 { "doesn't" } else { "don't" }
                    ),
                    "The Wi-Fi offers it (management frame protection) and not every device \
                     took it: usually older ones. Nothing to fix on the router.",
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
                    "The list of bad sites the router blocks is {} days old{by_itself}",
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
                })
        };
        out.extend(row);
    }

    out.sort_by_key(|r| r.rank);
    out
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

fn plural(n: usize, one: &str, many: &str) -> String {
    match n {
        1 => format!("1 {one}"),
        n => format!("{n} {many}"),
    }
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
            (true, false) => "The router's admin page is encrypted, but ssh still takes a password",
            (false, true) => {
                "Logging in over ssh takes a key, but the admin page can be opened without encryption"
            }
            (true, true) => {
                "ssh takes a password, and the admin page can be opened without encryption"
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
                "Someone tried to log in to the router 3 times and was refused, in the last 2 h 50 min",
                "the numbers",
            ),
            (
                Rank::Look,
                false,
                "192.0.2.77 is talking to the internet in a way ordinary devices rarely do (port 23)",
                "the numbers",
            ),
            (
                Rank::Look,
                false,
                "Someone logged in to the router once from a device nobody has named, in the last 2 h 50 min",
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
                "1 device on the Wi-Fi doesn't use the protection against being knocked off by a stranger",
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
                "The router lets people log in over ssh with a password",
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
            r.title.contains("without encryption (plain HTTP)"),
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
            "Something on the server's side (dmz) is talking to a device on your home side (lan): that should never happen"
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
            r.title
                .starts_with("A device nobody has named is plugged into lan"),
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
            r.title.starts_with("A door from the internet is open that you haven't listed: web, tcp port 443 to 203.0.113.93"),
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
            "The list of bad sites the router blocks is 54 days old and doesn't update by itself"
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
        const OFF: &str = "CrowdSec's blocker is installed on the router but not switched on: the server's blocklist isn't enforced at the edge yet";
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
            "CrowdSec's blocker is installed on the router but not switched on: what CrowdSec would block isn't enforced at the edge yet"
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
                "The router's admin page is encrypted, but ssh still takes a password".into()
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
        };
        let text = crate::cli::security_text("home", &said, &[]).join("\n");
        for want in [
            "home · security\n\nNeeds attention\n  look     Someone tried to log in to the router 3 times",
            "           A refused login is the lock holding",
            "           Enter on Security (4): new password",
            "\nHow you're covered\n  ok    2 doors are open from the internet",
            "  ok    Logging in to the router takes a key, and its admin page is encrypted",
            "What a tool like this can't see: what is inside the traffic",
        ] {
            assert!(text.contains(want), "{want}:\n{text}");
        }
        // Nothing but what can wait: it says so, and still lists the cover.
        let calm = crate::security::gather::Said {
            rows: said.rows.into_iter().filter(|r| r.can_wait).collect(),
            posture: said.posture,
        };
        let text = crate::cli::security_text("home", &calm, &[("log".into(), "no logread".into())])
            .join("\n");
        assert!(
            text.contains("Nothing needs you.\n  note ")
                && text.contains("How you're covered")
                && text.contains("(not read: log: no logread)"),
            "{text}"
        );
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
}

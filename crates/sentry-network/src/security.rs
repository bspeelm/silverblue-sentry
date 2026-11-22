//! What flows through the router, made from what it counts and tracks (pure; the reads are
//! `collect::{counters, flows, seclog, dnsstate}` and the clients'): each live flow put
//! between two sides ([`classify`]), the inside end joined with the client that has that
//! address ([`devices`]), the firewall's zone pairs as configured beside what is observed
//! now ([`matrix`]), rates from two reads of the counters on the router's own clock
//! ([`CounterRates`]), what the log window says ([`log_sum`]), and a few marks worth a look
//! ([`Picture::marks`]).
//!
//! What these numbers are not (the screen says the same):
//! - A rule's counter counts packets that open a flow (new connections, rejected packets),
//!   never traffic. A counter that went back, or a firewall loaded since, restarts the
//!   baseline: no rate for that interval.
//! - Every zone allowed out shares one counter (`accept_to_<wan>`): it isn't split here.
//! - Traffic rejected between two inside zones has no counter on a default fw4, so that
//!   separation is shown from live flows: none should exist, and blocked tries aren't seen.
//! - A flow's bytes are those of a flow still in the table: "now", never a total.
//! - dnsmasq doesn't count blocked names: they are inside "answered locally".
//! - Log numbers cover the log's window only, and DNS over HTTPS to other resolvers looks
//!   like any HTTPS.
//!
//! Marks are hints for the screen. Only two things here are findings (`audit::derive`): a
//! live flow between zones the firewall doesn't join, and failed ssh logins.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use crate::clients::Client;
use crate::collect::clients::Station;
use crate::collect::counters::{Counted, Counters, Role};
use crate::collect::dnsstate::DnsState;
use crate::collect::flows::{Flow, Flows};
use crate::collect::ifaces::Ifaces;
use crate::collect::seclog::{Event, Failed, SecLog};
use crate::collect::uci::{Redirect, Uci};

/// A blocklist older than this gets a mark.
pub const LIST_OLD_DAYS: i64 = 30;

/// Destination ports worth a mark when a device on a home network opens them to the
/// outside: each is rare for ordinary devices and common for compromised or misconfigured
/// ones. A mark is a reason to look, not a verdict.
pub const ODD_PORTS: &[(&str, u16, &str)] = &[
    (
        "tcp",
        23,
        "telnet: unencrypted logins; what IoT malware scans for",
    ),
    (
        "tcp",
        2323,
        "telnet on its alternate port: IoT malware scanning",
    ),
    (
        "tcp",
        25,
        "mail sent straight to a mail server: spam bots do; mail apps use 465/587",
    ),
    (
        "tcp",
        445,
        "Windows file sharing to the internet: worms spread this way",
    ),
    ("tcp", 139, "NetBIOS to the internet: as port 445"),
    (
        "tcp",
        3389,
        "remote desktop to the internet: often brute-forced or tunnelled",
    ),
    (
        "tcp",
        5900,
        "VNC to the internet: remote control, usually unencrypted",
    ),
    (
        "tcp",
        6667,
        "IRC: rare for people now, a classic botnet control channel",
    ),
];

fn odd(proto: &str, port: u16) -> Option<&'static str> {
    ODD_PORTS
        .iter()
        .find(|(p, n, _)| *p == proto && *n == port)
        .map(|(_, _, why)| *why)
}

fn parse_net(s: &str) -> Option<(IpAddr, u8)> {
    let (a, m) = s.split_once('/')?;
    Some((a.parse().ok()?, m.parse().ok()?))
}

fn within(a: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (a, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let m = u32::MAX
                .checked_shl(32 - prefix.min(32) as u32)
                .unwrap_or(0);
            u32::from(a) & m == u32::from(n) & m
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let m = u128::MAX
                .checked_shl(128 - prefix.min(128) as u32)
                .unwrap_or(0);
            u128::from(a) & m == u128::from(n) & m
        }
        _ => false,
    }
}

/// One side of a flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// One of the router's own addresses.
    Router,
    /// An address on an inside network, by its firewall zone.
    Zone(String),
    /// Anything else: the internet (the uplink's own network included).
    Outside,
    /// Link-local, multicast, broadcast: chatter on one link, nobody's traffic.
    Local,
}

/// The router's networks: which addresses are its own, and which zone an address is in.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Nets {
    router: Vec<IpAddr>,
    /// (network, prefix length, zone)
    inside: Vec<(IpAddr, u8, String)>,
    /// The zones that hold an uplink.
    pub wan: Vec<String>,
    /// Every zone, the firewall's order.
    pub zones: Vec<String>,
}

impl Nets {
    pub fn new(i: &Ifaces, uci: Option<&Uci>) -> Self {
        let zones = uci.map(Uci::zones).unwrap_or_default();
        let zone_of = |iface: &str| {
            zones
                .iter()
                .find(|z| z.networks.iter().any(|n| n == iface))
                .map_or(iface.to_string(), |z| z.name.clone())
        };
        let uplinks: Vec<&str> = [i.wan(), i.wan6()]
            .into_iter()
            .flatten()
            .map(|w| w.name.as_str())
            .collect();
        let mut out = Nets {
            zones: zones.iter().map(|z| z.name.clone()).collect(),
            ..Default::default()
        };
        for x in &i.interfaces {
            let zone = zone_of(&x.name);
            let up = uplinks.contains(&x.name.as_str());
            if up && !out.wan.contains(&zone) {
                out.wan.push(zone.clone());
            }
            for (a, m) in x.ipv4.iter().chain(&x.ipv6).filter_map(|s| parse_net(s)) {
                out.router.push(a);
                if !up && !a.is_loopback() {
                    out.inside.push((a, m, zone.clone()));
                }
            }
            out.router
                .extend(x.local6.iter().filter_map(|a| a.parse::<IpAddr>().ok()));
            if !up {
                for (a, m) in x.assigned6.iter().filter_map(|s| parse_net(s)) {
                    out.inside.push((a, m, zone.clone()));
                }
            }
        }
        if out.wan.is_empty() && out.zones.iter().any(|z| z == "wan") {
            out.wan.push("wan".into());
        }
        for z in out.inside.iter().map(|n| n.2.clone()).collect::<Vec<_>>() {
            if !out.zones.contains(&z) {
                out.zones.push(z);
            }
        }
        out
    }

    pub fn end(&self, a: IpAddr) -> End {
        if a.is_loopback() || self.router.contains(&a) {
            return End::Router;
        }
        let local = match a {
            IpAddr::V4(v) => {
                v.is_multicast() || v.is_broadcast() || v.is_link_local() || v.is_unspecified()
            }
            IpAddr::V6(v) => {
                v.is_multicast() || v.is_unspecified() || (v.segments()[0] & 0xffc0) == 0xfe80
            }
        };
        if local {
            return End::Local;
        }
        match self.inside.iter().find(|(n, m, _)| within(a, *n, *m)) {
            // A network's own broadcast address is the link's.
            Some((IpAddr::V4(n), m, _))
                if *m < 31 && {
                    let host = u32::MAX.checked_shr(*m as u32).unwrap_or(0);
                    matches!(a, IpAddr::V4(v) if u32::from(v) == u32::from(*n) | host)
                } =>
            {
                End::Local
            }
            Some((_, _, z)) => End::Zone(z.clone()),
            None => End::Outside,
        }
    }

    /// The uplink's zone, as rows name it.
    pub fn wan_zone(&self) -> &str {
        self.wan.first().map_or("wan", String::as_str)
    }
}

/// What a live flow is, by where it starts and where it really goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Class {
    /// From an inside zone out to the internet.
    Egress { zone: String },
    /// From outside through a port forward to a host in `zone`.
    Forwarded { zone: String },
    /// From outside straight to an inside address (routed IPv6: no forward involved).
    Inbound { zone: String },
    /// From one inside zone to another; `reflected`: by way of a port forward on the
    /// uplink's address.
    Between {
        from: String,
        to: String,
        reflected: bool,
    },
    /// From an inside zone to the router itself. `forced`: addressed elsewhere and
    /// redirected to the router (forced DNS).
    ToRouter { zone: String, forced: bool },
    /// The router's own, out to the internet.
    RouterOut,
    /// From outside to the router itself, answered (something the firewall lets in).
    RouterIn,
    /// The router's own, to an inside host.
    RouterToZone { zone: String },
    /// On-link chatter, and anything that is neither side's.
    Local,
}

pub fn classify(f: &Flow, n: &Nets) -> Class {
    let (s, d) = (n.end(f.src), n.end(f.dst));
    let t = f.dnat.map(|(a, _)| n.end(a));
    match (s, d, t) {
        (End::Local, _, _) | (_, End::Local, _) => Class::Local,
        (End::Zone(zone), d, Some(End::Router)) if d != End::Router => {
            Class::ToRouter { zone, forced: true }
        }
        (End::Zone(from), End::Router, Some(End::Zone(to))) => Class::Between {
            from,
            to,
            reflected: true,
        },
        (End::Zone(zone), End::Router, _) => Class::ToRouter {
            zone,
            forced: false,
        },
        (End::Zone(from), End::Zone(to), _) => Class::Between {
            from,
            to,
            reflected: false,
        },
        (End::Zone(zone), End::Outside, _) => Class::Egress { zone },
        (End::Outside, _, Some(End::Zone(zone))) => Class::Forwarded { zone },
        (End::Outside, End::Zone(zone), _) => Class::Inbound { zone },
        (End::Outside, End::Router, _) => Class::RouterIn,
        (End::Router, End::Outside, _) => Class::RouterOut,
        (End::Router, End::Zone(zone), _) => Class::RouterToZone { zone },
        _ => Class::Local,
    }
}

fn in_ports(spec: &str, port: u16) -> bool {
    spec.split(',').any(|p| match p.split_once('-') {
        Some((a, b)) => matches!((a.trim().parse::<u16>(), b.trim().parse::<u16>()),
            (Ok(a), Ok(b)) if (a..=b).contains(&port)),
        None => p.trim().parse() == Ok(port),
    })
}

/// The port forward a forwarded flow came through.
pub fn forward_of<'a>(f: &Flow, forwards: &'a [Redirect]) -> Option<&'a Redirect> {
    let (to, _) = f.dnat?;
    forwards.iter().find(|r| {
        r.enabled
            && r.protos.contains(&f.proto)
            && in_ports(&r.port, f.dport)
            && r.dest_ip.parse() == Ok(to)
    })
}

/// How the firewall stands between two zones, as configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allowed {
    /// A `forwarding` joins them.
    Yes,
    /// No forwarding; these rules accept some of it.
    Rules(Vec<String>),
    /// Nothing lets it through: rejected.
    No,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pair {
    pub from: String,
    pub to: String,
    pub allowed: Allowed,
    /// Live flows that way now (not counting those through a port forward).
    pub flows: usize,
    /// Those through a port forward (what the forwards are for).
    pub forwarded: usize,
    /// One side is the uplink's zone (the other pairs are between inside zones).
    pub outside: bool,
}

impl Pair {
    /// Live flows where the firewall has nothing that lets them through.
    pub fn breach(&self) -> bool {
        self.allowed == Allowed::No && self.flows > 0
    }
}

/// Every ordered pair of zones: what the firewall says of it, and the live flows now.
pub fn matrix(uci: &Uci, n: &Nets, classes: &[Class]) -> Vec<Pair> {
    let fw = uci.config("firewall");
    let joined = |a: &str, b: &str| {
        fw.iter().any(|s| {
            s.kind == "forwarding"
                && s.one("src") == Some(a)
                && s.one("dest") == Some(b)
                && s.flag("enabled", true)
        })
    };
    let rules = |a: &str, b: &str| -> Vec<String> {
        fw.iter()
            .filter(|s| {
                s.kind == "rule"
                    && s.flag("enabled", true)
                    && s.one("target")
                        .is_some_and(|t| t.eq_ignore_ascii_case("ACCEPT"))
                    && matches!(s.one("src"), Some(x) if x == a || x == "*")
                    && matches!(s.one("dest"), Some(x) if x == b || x == "*")
            })
            .map(|s| s.one("name").unwrap_or(&s.name).to_string())
            .collect()
    };
    let wan = n.wan_zone();
    let mut out = Vec::new();
    for a in &n.zones {
        for b in n.zones.iter().filter(|b| *b != a) {
            let allowed = if joined(a, b) {
                Allowed::Yes
            } else {
                match rules(a, b) {
                    r if r.is_empty() => Allowed::No,
                    r => Allowed::Rules(r),
                }
            };
            let count = |f: &dyn Fn(&Class) -> bool| classes.iter().filter(|c| f(c)).count();
            let (flows, forwarded) = if n.wan.contains(b) {
                (
                    count(&|c| matches!(c, Class::Egress { zone } if zone == a)),
                    0,
                )
            } else if n.wan.contains(a) {
                (
                    count(&|c| matches!(c, Class::Inbound { zone } if zone == b)),
                    count(&|c| matches!(c, Class::Forwarded { zone } if zone == b)),
                )
            } else {
                (
                    count(
                        &|c| matches!(c, Class::Between { from, to, reflected: false } if from == a && to == b),
                    ),
                    count(
                        &|c| matches!(c, Class::Between { from, to, reflected: true } if from == a && to == b),
                    ),
                )
            };
            // Only one uplink zone is a row's far side.
            if (n.wan.contains(a) && a != wan) || (n.wan.contains(b) && b != wan) {
                continue;
            }
            out.push(Pair {
                from: a.clone(),
                to: b.clone(),
                allowed,
                flows,
                forwarded,
                outside: n.wan.contains(a) || n.wan.contains(b),
            });
        }
    }
    out
}

/// Where a device's flows go: one destination port, how many flows, and the far ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Far {
    pub proto: String,
    pub port: u16,
    pub flows: usize,
    pub addrs: Vec<IpAddr>,
    /// Why this port is marked ([`ODD_PORTS`]), for flows to the outside.
    pub odd: Option<&'static str>,
}

/// A device with live flows of its own making (out to the internet or into another zone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The client's key (its MAC), or the address when no client has it.
    pub key: String,
    /// As Clients shows it: its name, hostname or MAC; else the address.
    pub label: String,
    /// The client's name from `devices`, when it has one.
    pub named: bool,
    pub private: bool,
    pub zone: String,
    pub flows: usize,
    /// Distinct far ends.
    pub dests: usize,
    /// Bytes its live flows have carried so far, out and back (None: no accounting).
    pub up: Option<u64>,
    pub down: Option<u64>,
    /// By destination port, most flows first.
    pub far: Vec<Far>,
}

impl Device {
    /// `443 ×4, 993`: the busiest ports, as many as fit `n`.
    pub fn top_ports(&self, n: usize) -> String {
        let mut out: Vec<String> = Vec::new();
        for f in self.far.iter().take(n) {
            let p = if f.proto == "tcp" || f.proto == "udp" {
                format!("{}{}", if f.proto == "udp" { "u" } else { "" }, f.port)
            } else {
                f.proto.clone()
            };
            out.push(if f.flows > 1 {
                format!("{p}×{}", f.flows)
            } else {
                p
            });
        }
        if self.far.len() > n {
            out.push("…".into());
        }
        out.join(" ")
    }

    pub fn odd(&self) -> impl Iterator<Item = &Far> {
        self.far.iter().filter(|f| f.odd.is_some())
    }
}

/// One row for each inside address that opened a live flow out or across zones, joined
/// with the client that has the address. Most flows first.
pub fn devices(flows: &[Flow], classes: &[Class], clients: &[Client]) -> Vec<Device> {
    let by_addr: HashMap<IpAddr, &Client> = clients
        .iter()
        .flat_map(|c| {
            c.addrs
                .iter()
                .filter_map(move |a| Some((a.parse().ok()?, c)))
        })
        .collect();
    let mut rows: BTreeMap<String, Device> = BTreeMap::new();
    let mut seen: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for (f, c) in flows.iter().zip(classes) {
        let (zone, outside) = match c {
            Class::Egress { zone } => (zone, true),
            Class::Between { from, .. } => (from, false),
            _ => continue,
        };
        let client = by_addr.get(&f.src);
        let key = client.map_or(f.src.to_string(), |c| c.key.clone());
        let d = rows.entry(key.clone()).or_insert_with(|| Device {
            key: key.clone(),
            label: client.map_or(f.src.to_string(), |c| c.label().to_string()),
            named: client.is_some_and(|c| c.name.is_some()),
            private: client.is_some_and(|c| c.private),
            zone: zone.clone(),
            flows: 0,
            dests: 0,
            up: None,
            down: None,
            far: Vec::new(),
        });
        d.flows += 1;
        let ends = seen.entry(key).or_default();
        if !ends.contains(&f.dst) {
            ends.push(f.dst);
            d.dests = ends.len();
        }
        if let Some(b) = f.bytes {
            d.up = Some(d.up.unwrap_or(0) + b);
        }
        if let Some(b) = f.reply_bytes {
            d.down = Some(d.down.unwrap_or(0) + b);
        }
        let far = match d
            .far
            .iter_mut()
            .find(|x| x.proto == f.proto && x.port == f.dport)
        {
            Some(x) => x,
            None => {
                d.far.push(Far {
                    proto: f.proto.clone(),
                    port: f.dport,
                    flows: 0,
                    addrs: Vec::new(),
                    odd: outside.then(|| odd(&f.proto, f.dport)).flatten(),
                });
                d.far.last_mut().expect("just pushed")
            }
        };
        far.flows += 1;
        if !far.addrs.contains(&f.dst) {
            far.addrs.push(f.dst);
        }
    }
    let mut out: Vec<Device> = rows.into_values().collect();
    for d in &mut out {
        d.far
            .sort_by(|a, b| b.flows.cmp(&a.flows).then(a.port.cmp(&b.port)));
    }
    out.sort_by(|a, b| b.flows.cmp(&a.flows).then(a.label.cmp(&b.label)));
    out
}

/// Packets per second for each counted rule, between two reads.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Rated {
    /// By [`Counted::key`]. A rule with no rate isn't here (drawn `–`).
    pub rules: HashMap<String, f64>,
    /// dnsmasq's queries per second: (forwarded, answered locally).
    pub dns: Option<(f64, f64)>,
    /// The counters started over since the read before (a reload, a reboot).
    pub reset: bool,
}

/// Rates from one read of the counters to the next, on the router's clock. No rate on the
/// first read, when the clock didn't advance, across a reboot or a firewall reload (a newer
/// state file, or any counter gone back: the whole table was made again), or for a rule
/// that wasn't there before.
#[derive(Debug, Default)]
pub struct CounterRates {
    prev: Option<Counters>,
}

impl CounterRates {
    pub fn feed(&mut self, c: &Counters) -> Rated {
        let mut out = Rated::default();
        if let Some(p) = &self.prev
            && c.uptime > p.uptime
        {
            let dt = c.uptime - p.uptime;
            // (Rules that share a key are one number.)
            let by_key = |c: &Counters| {
                let mut m: HashMap<String, u64> = HashMap::new();
                for r in c.rules.iter().flatten() {
                    *m.entry(r.key()).or_default() += r.packets;
                }
                m
            };
            let (before, now) = (by_key(p), by_key(c));
            let back = now
                .iter()
                .any(|(k, n)| before.get(k).is_some_and(|b| n < b));
            out.reset = back || c.reset_at != p.reset_at;
            if !out.reset {
                for (k, n) in now {
                    if let Some(b) = before.get(&k) {
                        out.rules.insert(k, (n - b) as f64 / dt);
                    }
                }
            }
            // dnsmasq restarts by itself too: its counters have their own baseline.
            if let (Some(a), Some(b)) = (&p.dns, &c.dns)
                && b.forwarded >= a.forwarded
                && b.local >= a.local
            {
                out.dns = Some((
                    (b.forwarded - a.forwarded) as f64 / dt,
                    (b.local - a.local) as f64 / dt,
                ));
            }
        } else if self.prev.as_ref().is_some_and(|p| c.uptime < p.uptime) {
            out.reset = true;
        }
        self.prev = Some(c.clone());
        out
    }
}

/// What the log window says, as counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogSum {
    pub window_s: Option<u64>,
    /// Logins from this machine (sentry's own connections): counted, nothing else.
    pub ssh_own: usize,
    /// Logins from an address a named device has.
    pub ssh_known: usize,
    /// Logins from anywhere else, by address.
    pub ssh_unknown: Vec<(Option<IpAddr>, usize)>,
    /// Refused logins (a bad password, no such user, too many tries), by address. Those
    /// from this machine's address are listed too.
    pub ssh_failed: Vec<(Option<IpAddr>, usize)>,
    /// Connections that left without logging in.
    pub ssh_left: usize,
    pub wifi_connects: usize,
    pub wifi_disconnects: usize,
    pub wifi_auth_failed: usize,
}

impl LogSum {
    pub fn failed(&self) -> usize {
        self.ssh_failed.iter().map(|(_, n)| n).sum()
    }
    pub fn unknown(&self) -> usize {
        self.ssh_unknown.iter().map(|(_, n)| n).sum()
    }
    /// Refused logins from an address that isn't this machine's.
    pub fn failed_elsewhere(&self, me: Option<IpAddr>) -> Vec<(Option<IpAddr>, usize)> {
        self.ssh_failed
            .iter()
            .filter(|(a, _)| a.is_none() || *a != me)
            .copied()
            .collect()
    }
}

pub fn log_sum(log: &SecLog, clients: &[Client]) -> LogSum {
    let named = |a: IpAddr| {
        clients
            .iter()
            .any(|c| c.name.is_some() && c.addrs.iter().any(|x| x.parse() == Ok(a)))
    };
    let mut s = LogSum {
        window_s: log.window_s(),
        ..Default::default()
    };
    fn bump(v: &mut Vec<(Option<IpAddr>, usize)>, a: Option<IpAddr>) {
        match v.iter_mut().find(|(x, _)| *x == a) {
            Some(x) => x.1 += 1,
            None => v.push((a, 1)),
        }
    }
    for (_, e) in &log.events {
        match e {
            Event::SshLogin { from, .. } if from.is_some() && *from == log.me => s.ssh_own += 1,
            Event::SshLogin { from: Some(a), .. } if named(*a) => s.ssh_known += 1,
            Event::SshLogin { from, .. } => bump(&mut s.ssh_unknown, *from),
            Event::SshFailed {
                why: Failed::LeftBeforeAuth,
                ..
            } => s.ssh_left += 1,
            Event::SshFailed { from, .. } => bump(&mut s.ssh_failed, *from),
            Event::WifiConnected { .. } => s.wifi_connects += 1,
            Event::WifiDisconnected { .. } => s.wifi_disconnects += 1,
            Event::WifiAuthFailed { .. } => s.wifi_auth_failed += 1,
        }
    }
    s
}

/// Management frame protection, as an access point is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mfp {
    Off,
    Optional,
    Required,
}

impl Mfp {
    pub fn word(self) -> &'static str {
        match self {
            Mfp::Off => "off",
            Mfp::Optional => "optional",
            Mfp::Required => "required",
        }
    }
}

/// An access point as configured, with who is on it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ap {
    /// The radio (`radio0`).
    pub device: String,
    pub encryption: String,
    pub mfp: Mfp,
    pub wps: bool,
    /// Stations on it now (None: the stations weren't read).
    pub stations: Option<usize>,
    /// Of those, the ones without management frame protection (said so; unknown isn't
    /// counted).
    pub without_mfp: usize,
}

/// `ieee80211w` as set, else what OpenWrt gives the encryption: WPA3 alone requires it,
/// a mixed mode offers it, WPA2 and open leave it off.
fn mfp_of(encryption: &str, set: Option<&str>) -> Mfp {
    match set {
        Some("2") => Mfp::Required,
        Some("1") => Mfp::Optional,
        Some("0") => Mfp::Off,
        _ if encryption.contains("mixed") && encryption.contains("sae") => Mfp::Optional,
        _ if encryption.starts_with("sae") || encryption.starts_with("owe") => Mfp::Required,
        _ => Mfp::Off,
    }
}

/// The access points that are switched on, each with its stations (`phyN-apK` is the
/// K-th of `radioN`, unless the config names the interface).
pub fn aps(uci: &Uci, stations: Option<&[Station]>) -> Vec<Ap> {
    let ifaces: Vec<_> = uci
        .config("wireless")
        .iter()
        .filter(|s| s.kind == "wifi-iface")
        .filter(|s| !s.flag("disabled", false) && s.one("mode").is_none_or(|m| m == "ap"))
        .collect();
    let mut nth: HashMap<&str, usize> = HashMap::new();
    ifaces
        .iter()
        .map(|s| {
            let device = s.one("device").unwrap_or("").to_string();
            let k = nth.entry(s.one("device").unwrap_or("")).or_insert(0);
            let ifname = s
                .one("ifname")
                .map(str::to_string)
                .unwrap_or_else(|| format!("phy{}-ap{k}", device.trim_start_matches("radio")));
            *k += 1;
            let enc = s.one("encryption").unwrap_or("none").to_string();
            let on: Option<Vec<&Station>> =
                stations.map(|st| st.iter().filter(|x| x.ifname == ifname).collect());
            Ap {
                mfp: mfp_of(&enc, s.one("ieee80211w")),
                wps: s.flag("wps_pushbutton", false) || s.flag("wps_label", false),
                encryption: enc,
                device,
                without_mfp: on.iter().flatten().filter(|x| x.mfp == Some(false)).count(),
                stations: on.map(|v| v.len()),
            }
        })
        .collect()
}

/// A counter with its rate between the last two reads.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Count {
    pub total: u64,
    /// Per second (None: no rate yet, or the counters started over).
    pub rate: Option<f64>,
}

/// A port forward, with what its rule counted and who is connected through it now.
#[derive(Debug, Clone, PartialEq)]
pub struct ForwardRow {
    pub name: String,
    pub proto: String,
    pub port: String,
    pub to: String,
    /// New connections (None: the rule has no counter, or the counters weren't read).
    pub new: Option<Count>,
    /// Live flows through it now (None: the flows weren't read).
    pub live: Option<usize>,
}

/// Something worth a look. Hints, not findings.
#[derive(Debug, Clone, PartialEq)]
pub enum Mark {
    /// Live flows between zones the firewall doesn't join.
    Crossing {
        from: String,
        to: String,
        flows: usize,
    },
    /// Flows from outside straight to inside addresses, with no forward for them.
    Inbound {
        flows: usize,
    },
    /// A device with flows to ports on [`ODD_PORTS`].
    OddPorts {
        device: String,
        ports: Vec<String>,
    },
    /// DNS over TLS is being tried past the forced DNS, now.
    DotTried {
        per_min: f64,
    },
    SshFailed {
        tries: usize,
    },
    /// Logins from addresses no named device has.
    SshUnknown {
        logins: usize,
    },
    WifiAuthFailed {
        tries: usize,
    },
    /// Stations without management frame protection on an access point that offers it.
    NoMfp {
        stations: usize,
    },
    ListOld {
        days: i64,
    },
    /// Flow offloading is on: per-flow bytes and counts undercount.
    Offload,
}

impl Mark {
    /// One line for the screen.
    pub fn text(&self) -> String {
        match self {
            Mark::Crossing { from, to, flows } => format!(
                "{flows} live flow(s) from {from} into {to}, which the firewall doesn't join"
            ),
            Mark::Inbound { flows } => {
                format!(
                    "{flows} flow(s) from outside straight to inside addresses, with no forward"
                )
            }
            Mark::OddPorts { device, ports } => {
                format!("{device} has flows out to {}", ports.join(", "))
            }
            Mark::DotTried { per_min } => {
                format!("DNS over TLS is being tried past the router ({per_min:.1}/min, rejected)")
            }
            Mark::SshFailed { tries } => format!("{tries} refused ssh login(s) in the log window"),
            Mark::SshUnknown { logins } => {
                format!("{logins} ssh login(s) from an address no named device has")
            }
            Mark::WifiAuthFailed { tries } => {
                format!("{tries} wrong Wi-Fi passphrase(s) in the log window")
            }
            Mark::NoMfp { stations } => {
                format!("{stations} station(s) without management frame protection")
            }
            Mark::ListOld { days } => format!("the blocklist is {days} days old"),
            Mark::Offload => "flow offloading is on: per-flow bytes and counts undercount".into(),
        }
    }

    /// The ones that say the separation or a login failed: drawn red.
    pub fn grave(&self) -> bool {
        matches!(self, Mark::Crossing { .. } | Mark::SshFailed { .. })
    }
}

/// What was read, as far as it was.
#[derive(Clone, Copy, Default)]
pub struct Read<'a> {
    pub ifaces: Option<&'a Ifaces>,
    pub uci: Option<&'a Uci>,
    pub clients: Option<&'a [Client]>,
    pub stations: Option<&'a [Station]>,
    pub counters: Option<&'a Counters>,
    pub rated: Option<&'a Rated>,
    pub flows: Option<&'a Flows>,
    pub log: Option<&'a SecLog>,
    pub dns: Option<&'a DnsState>,
}

/// Everything the Security screen, the Dashboard's row and a brief for Claude are made of.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Picture {
    /// Each flow's class, in the flows' order (empty: flows or interfaces not read).
    pub classes: Vec<Class>,
    /// Unsolicited packets from outside, rejected.
    pub wan_rejects: Option<Count>,
    pub forwards: Vec<ForwardRow>,
    /// New connections accepted towards the uplink: every zone allowed out, and the
    /// router, in one counter.
    pub out_new: Option<Count>,
    pub devices: Vec<Device>,
    /// None: the firewall's config wasn't read.
    pub matrix: Option<Vec<Pair>>,
    /// DNS over TLS tries rejected (every protocol's rule together).
    pub dot: Option<Count>,
    /// The firewall redirects DNS to the router (None: unknown).
    pub forced_dns: Option<bool>,
    /// dnsmasq's upstream servers, as configured.
    pub upstreams: Vec<String>,
    pub aps: Vec<Ap>,
    pub log: Option<LogSum>,
    pub offload: bool,
    pub marks: Vec<Mark>,
}

impl Picture {
    pub fn of(r: &Read) -> Self {
        let mut p = Picture::default();
        let nets = r.ifaces.map(|i| Nets::new(i, r.uci));
        let forwards = r.uci.map(Uci::forwards).unwrap_or_default();
        if let (Some(n), Some(f)) = (&nets, r.flows) {
            p.classes = f.flows.iter().map(|x| classify(x, n)).collect();
            p.devices = devices(&f.flows, &p.classes, r.clients.unwrap_or(&[]));
        }
        if let (Some(n), Some(u)) = (&nets, r.uci) {
            p.matrix = Some(matrix(u, n, &p.classes));
        }
        let rate = |c: &Counted| Count {
            total: c.packets,
            rate: r.rated.and_then(|x| x.rules.get(&c.key()).copied()),
        };
        // Several rules of one role (a rule for each protocol) are one number.
        let sum = |rules: &[Counted], f: &dyn Fn(&Role) -> bool| -> Option<Count> {
            let hit: Vec<Count> = rules.iter().filter(|c| f(&c.role)).map(rate).collect();
            (!hit.is_empty()).then(|| Count {
                total: hit.iter().map(|c| c.total).sum(),
                rate: hit
                    .iter()
                    .map(|c| c.rate)
                    .try_fold(0.0, |a, x| x.map(|x| a + x)),
            })
        };
        let rules = r.counters.and_then(|c| c.rules.as_deref());
        let wan = nets.as_ref().map(|n| n.wan.clone()).unwrap_or_default();
        let is_wan = |z: &String| wan.contains(z) || (wan.is_empty() && z == "wan");
        if let Some(rules) = rules {
            p.wan_rejects = sum(
                rules,
                &|x| matches!(x, Role::RejectFrom { zone } if is_wan(zone)),
            );
            p.out_new = sum(
                rules,
                &|x| matches!(x, Role::AcceptTo { zone } if is_wan(zone)),
            );
            p.dot = sum(rules, &|x| matches!(x, Role::DotReject { .. }));
        }
        // Forced DNS: what the proxy says of itself, else whether the firewall has the
        // redirect.
        p.forced_dns = r
            .dns
            .and_then(|d| d.proxy.as_ref())
            .map(|x| x.force_dns)
            .or_else(|| {
                rules.map(|rs| {
                    rs.iter()
                        .any(|c| matches!(c.role, Role::DnsRedirect { .. }))
                })
            });
        // The forwards: the config's, each protocol a row, joined with its rule's counter
        // and the flows through it; without the config, the counted rules alone.
        let live = |name_port: &dyn Fn(&Flow) -> bool| {
            r.flows.filter(|_| nets.is_some()).map(|f| {
                f.flows
                    .iter()
                    .zip(&p.classes)
                    .filter(|(x, c)| matches!(c, Class::Forwarded { .. }) && name_port(x))
                    .count()
            })
        };
        if r.uci.is_some() {
            for fw in forwards.iter().filter(|f| f.enabled) {
                for proto in &fw.protos {
                    let counted = rules.and_then(|rs| {
                        rs.iter().find(|c| {
                            c.name == fw.name
                                && matches!(&c.role, Role::Dnat { proto: p, .. } if p == proto)
                        })
                    });
                    p.forwards.push(ForwardRow {
                        name: fw.name.clone(),
                        proto: proto.clone(),
                        port: fw.port.clone(),
                        to: format!(
                            "{}:{}",
                            fw.dest_ip,
                            fw.dest_port.as_deref().unwrap_or(&fw.port)
                        ),
                        new: counted.map(rate),
                        live: live(&|x| {
                            x.proto == *proto
                                && forward_of(x, &forwards).is_some_and(|f| f.name == fw.name)
                        }),
                    });
                }
            }
        } else if let Some(rules) = rules {
            for c in rules {
                if let Role::Dnat {
                    proto, port, to, ..
                } = &c.role
                {
                    p.forwards.push(ForwardRow {
                        name: c.name.clone(),
                        proto: proto.clone(),
                        port: port.clone(),
                        to: to.clone(),
                        new: Some(rate(c)),
                        live: None,
                    });
                }
            }
        }
        if let Some(u) = r.uci {
            p.upstreams = u
                .config("dhcp")
                .iter()
                .filter(|s| s.kind == "dnsmasq")
                .flat_map(|s| s.list("server"))
                // A `/name/…` entry routes one domain; the upstreams are the plain ones.
                .filter(|s| !s.starts_with('/'))
                .collect();
            p.aps = aps(u, r.stations);
            p.offload = u
                .config("firewall")
                .iter()
                .filter(|s| s.kind == "defaults")
                .any(|s| s.flag("flow_offloading", false) || s.flag("flow_offloading_hw", false));
        }
        p.offload |= r.flows.is_some_and(|f| f.flows.iter().any(|x| x.offloaded));
        p.log = r.log.map(|l| log_sum(l, r.clients.unwrap_or(&[])));
        p.marks = p.marked(r);
        p
    }

    fn marked(&self, r: &Read) -> Vec<Mark> {
        let mut m = Vec::new();
        // (From outside straight in is the `Inbound` mark below.)
        for pair in self
            .matrix
            .iter()
            .flatten()
            .filter(|x| x.breach() && !x.outside)
        {
            m.push(Mark::Crossing {
                from: pair.from.clone(),
                to: pair.to.clone(),
                flows: pair.flows,
            });
        }
        if let Some(log) = &self.log {
            let me = r.log.and_then(|l| l.me);
            let tries: usize = log.failed_elsewhere(me).iter().map(|(_, n)| n).sum();
            if tries > 0 {
                m.push(Mark::SshFailed { tries });
            }
        }
        let inbound = self
            .classes
            .iter()
            .filter(|c| matches!(c, Class::Inbound { .. }))
            .count();
        if inbound > 0 {
            m.push(Mark::Inbound { flows: inbound });
        }
        for d in &self.devices {
            let ports: Vec<String> = d.odd().map(|f| format!("{}/{}", f.proto, f.port)).collect();
            if !ports.is_empty() {
                m.push(Mark::OddPorts {
                    device: d.label.clone(),
                    ports,
                });
            }
        }
        if let Some(rate) = self.dot.and_then(|d| d.rate).filter(|r| *r > 0.0) {
            m.push(Mark::DotTried {
                per_min: rate * 60.0,
            });
        }
        if let Some(log) = &self.log {
            if log.unknown() > 0 {
                m.push(Mark::SshUnknown {
                    logins: log.unknown(),
                });
            }
            if log.wifi_auth_failed > 0 {
                m.push(Mark::WifiAuthFailed {
                    tries: log.wifi_auth_failed,
                });
            }
        }
        let no_mfp: usize = self
            .aps
            .iter()
            .filter(|a| a.mfp != Mfp::Off)
            .map(|a| a.without_mfp)
            .sum();
        if no_mfp > 0 {
            m.push(Mark::NoMfp { stations: no_mfp });
        }
        if let Some(days) = r
            .dns
            .and_then(DnsState::list_age_days)
            .filter(|d| *d >= LIST_OLD_DAYS)
        {
            m.push(Mark::ListOld { days });
        }
        if self.offload {
            m.push(Mark::Offload);
        }
        m
    }

    /// Flows of a class.
    pub fn count(&self, f: impl Fn(&Class) -> bool) -> usize {
        self.classes.iter().filter(|c| f(c)).count()
    }

    /// The inside pairs the firewall keeps apart (what "segmentation" is about).
    pub fn apart(&self) -> Vec<&Pair> {
        self.matrix
            .iter()
            .flatten()
            .filter(|x| x.allowed == Allowed::No && !x.outside)
            .collect()
    }

    /// The pairs with live flows the firewall has nothing for, between inside zones.
    pub fn crossings(&self) -> Vec<&Pair> {
        self.marks
            .iter()
            .filter_map(|m| match m {
                Mark::Crossing { from, to, .. } => self
                    .matrix
                    .iter()
                    .flatten()
                    .find(|p| &p.from == from && &p.to == to),
                _ => None,
            })
            .collect()
    }
}

/// Live flows from one inside zone into another that the firewall doesn't join.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Crossing {
    pub from: String,
    pub to: String,
    pub flows: usize,
    /// A few of them: `203.0.113.93 → 192.0.2.10 tcp/445` (both ends are inside).
    pub which: Vec<String>,
}

/// Refused ssh logins in the log's window, from addresses that aren't this machine's.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Refused {
    pub tries: usize,
    /// The inside addresses they came from; those from outside are only counted.
    pub inside: Vec<String>,
    pub outside: usize,
    pub window_s: Option<u64>,
}

/// What an audit keeps of all this: only what its two findings are made of. No far end of
/// any flow is in it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Seen {
    /// None: the flows (or the firewall, or the interfaces) weren't read.
    pub crossings: Option<Vec<Crossing>>,
    /// None: the log wasn't read.
    pub refused: Option<Refused>,
}

impl Seen {
    pub fn of(r: &Read) -> Self {
        let p = Picture::of(r);
        let nets = r.ifaces.map(|i| Nets::new(i, r.uci));
        let crossings = match (r.flows, &p.matrix) {
            (Some(f), Some(_)) => Some(
                p.crossings()
                    .into_iter()
                    .map(|x| Crossing {
                        from: x.from.clone(),
                        to: x.to.clone(),
                        flows: x.flows,
                        which: f
                            .flows
                            .iter()
                            .zip(&p.classes)
                            .filter(|(_, c)| {
                                matches!(c, Class::Between { from, to, reflected: false }
                                    if *from == x.from && *to == x.to)
                            })
                            .take(5)
                            .map(|(f, _)| format!("{} → {} {}/{}", f.src, f.dst, f.proto, f.dport))
                            .collect(),
                    })
                    .collect(),
            ),
            _ => None,
        };
        let refused = r.log.zip(p.log.as_ref()).map(|(log, sum)| {
            let from = sum.failed_elsewhere(log.me);
            let is_inside = |a: &IpAddr| {
                nets.as_ref()
                    .is_some_and(|n| matches!(n.end(*a), End::Zone(_)))
            };
            Refused {
                tries: from.iter().map(|(_, n)| n).sum(),
                inside: from
                    .iter()
                    .filter_map(|(a, _)| a.filter(is_inside).map(|a| a.to_string()))
                    .collect(),
                outside: from
                    .iter()
                    .filter(|(a, _)| !a.as_ref().is_some_and(is_inside))
                    .count(),
                window_s: sum.window_s,
            }
        });
        Seen { crossings, refused }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::collect::{clients, counters, dnsstate, fixture, flows, ifaces, seclog, uci};
    use crate::redact::Salt;

    pub(crate) fn the_ifaces() -> Ifaces {
        ifaces::parse(&fixture("network/ifaces.txt")).unwrap()
    }
    pub(crate) fn the_uci() -> Uci {
        uci::parse(&fixture("network/uci.txt"), &Salt::fixed([7; 16]))
    }
    pub(crate) fn the_flows() -> Flows {
        flows::parse(&format!("@acct 1\n{}", fixture("network/conntrack.txt")))
    }
    pub(crate) fn the_counters() -> Counters {
        counters::parse(&fixture("network/counters.txt")).unwrap()
    }
    pub(crate) fn the_clients() -> Vec<Client> {
        let raw = clients::parse(&fixture("network/clients.txt")).unwrap();
        let cfg = crate::audit::tests::cfg();
        let i = the_ifaces();
        let mut seen = Default::default();
        crate::clients::read(
            &raw,
            &crate::clients::Topo::of(&i),
            &cfg.devices,
            &mut seen,
            1793016000,
        )
        .0
    }
    /// A line of the table: `proto src:sport > dst:dport`, answered from `reply`.
    pub(crate) fn line(proto: &str, src: &str, dst: &str, dport: u16, reply: &str) -> String {
        format!(
            "ipv4     2 {proto}      6 100 ESTABLISHED src={src} dst={dst} sport=40000 dport={dport} \
             packets=4 bytes=400 src={reply} dst={src} sport={dport} dport=40000 packets=3 \
             bytes=300 [ASSURED] mark=0 zone=0 use=2\n"
        )
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_address_is_the_routers_a_zones_or_outside() {
        let n = Nets::new(&the_ifaces(), Some(&the_uci()));
        assert_eq!(n.wan, ["wan"]);
        assert_eq!(n.zones, ["lan", "wan", "dmz"]);
        let zone = |z: &str| End::Zone(z.into());
        for (a, want) in [
            ("192.0.2.1", End::Router),
            ("203.0.113.1", End::Router),
            ("198.51.100.23", End::Router),
            ("2001:db8:1200::1", End::Router),
            ("127.0.0.1", End::Router),
            ("::1", End::Router),
            ("192.0.2.10", zone("lan")),
            ("203.0.113.93", zone("dmz")),
            ("2001:db8:1200::c40", zone("lan")),
            // The uplink's own network is the outside, like everything beyond it.
            ("198.51.100.1", End::Outside),
            ("198.18.0.80", End::Outside),
            ("2001:db8:ffff::1", End::Outside),
            // A delegated prefix's unassigned part is nobody's zone.
            ("2001:db8:1200:80::5", End::Outside),
            ("192.0.2.255", End::Local),
            ("255.255.255.255", End::Local),
            ("224.0.0.251", End::Local),
            ("169.254.3.4", End::Local),
            ("fe80::200:5eff:fe00:5310", End::Local),
            ("ff02::1:2", End::Local),
        ] {
            assert_eq!(n.end(ip(a)), want, "{a}");
        }
        // Before the firewall is read a network is its own zone, and wan is the uplink.
        let bare = Nets::new(&the_ifaces(), None);
        assert_eq!(bare.end(ip("203.0.113.93")), zone("dmz"));
        assert_eq!(bare.wan, ["wan", "wan6"]);
        assert_eq!(bare.wan_zone(), "wan");
    }

    #[test]
    fn every_flow_is_put_between_two_sides() {
        let n = Nets::new(&the_ifaces(), Some(&the_uci()));
        let f = the_flows();
        let classes: Vec<Class> = f.flows.iter().map(|x| classify(x, &n)).collect();
        assert_eq!(classes.len(), f.lines, "none is left out");
        let count = |c: &Class| classes.iter().filter(|x| *x == c).count();
        let z = |s: &str| s.to_string();
        // lan out: nas 3 + desk 1 + the unnamed phone 1 + the unknown address 2 + IPv6 2.
        assert_eq!(count(&Class::Egress { zone: z("lan") }), 9);
        assert_eq!(count(&Class::Egress { zone: z("dmz") }), 1);
        // In through the forward to the DMZ server.
        assert_eq!(count(&Class::Forwarded { zone: z("dmz") }), 2);
        // To the router itself: ssh from the desk, DNS from the phone, DNS from the DMZ;
        // and DNS addressed elsewhere that the router answered.
        assert_eq!(
            count(&Class::ToRouter {
                zone: z("lan"),
                forced: false
            }),
            2
        );
        assert_eq!(
            count(&Class::ToRouter {
                zone: z("lan"),
                forced: true
            }),
            1
        );
        assert_eq!(
            count(&Class::ToRouter {
                zone: z("dmz"),
                forced: false
            }),
            1
        );
        assert_eq!(
            count(&Class::Between {
                from: z("lan"),
                to: z("dmz"),
                reflected: false
            }),
            1
        );
        assert_eq!(count(&Class::RouterOut), 1);
        assert_eq!(count(&Class::RouterIn), 1);
        assert_eq!(count(&Class::Local), 1);
        // Each one by itself: the zone pairs a table can't have by accident.
        let one = |text: &str| classify(&flows::parse(text).flows[0], &n);
        for (text, want) in [
            (
                line("tcp", "203.0.113.93", "192.0.2.10", 445, "192.0.2.10"),
                Class::Between {
                    from: z("dmz"),
                    to: z("lan"),
                    reflected: false,
                },
            ),
            // From the LAN to the uplink's address and through the forward: reflected.
            (
                line("tcp", "192.0.2.10", "198.51.100.23", 443, "203.0.113.93"),
                Class::Between {
                    from: z("lan"),
                    to: z("dmz"),
                    reflected: true,
                },
            ),
            (
                line("tcp", "192.0.2.1", "192.0.2.10", 80, "192.0.2.10"),
                Class::RouterToZone { zone: z("lan") },
            ),
        ] {
            assert_eq!(one(&text), want, "{text}");
        }
        // IPv6 from outside straight to an inside address: nothing forwarded it.
        let six = "ipv6     10 tcp      6 100 ESTABLISHED src=2001:0db8:ffff:0000:0000:0000:0000:0009 \
            dst=2001:0db8:1200:0000:0000:0000:0000:0114 sport=5 dport=22 packets=1 bytes=1 \
            src=2001:0db8:1200:0000:0000:0000:0000:0114 dst=2001:0db8:ffff:0000:0000:0000:0000:0009 \
            sport=22 dport=5 packets=1 bytes=1 [ASSURED] mark=0 zone=0 use=2\n";
        assert_eq!(one(six), Class::Inbound { zone: z("lan") });
    }

    #[test]
    fn a_forwarded_flow_names_its_forward() {
        let fw = the_uci().forwards();
        let f = the_flows();
        let through: Vec<&str> = f
            .flows
            .iter()
            .filter_map(|x| forward_of(x, &fw))
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(through, ["web", "web"]);
        // A range, by protocol and target.
        let game = flows::parse(&line(
            "udp",
            "198.18.1.1",
            "198.51.100.23",
            8004,
            "192.0.2.20",
        ));
        assert_eq!(forward_of(&game.flows[0], &fw).unwrap().name, "game");
        let other = flows::parse(&line(
            "tcp",
            "198.18.1.1",
            "198.51.100.23",
            8004,
            "192.0.2.20",
        ));
        assert!(
            forward_of(&other.flows[0], &fw).is_none(),
            "not its protocol"
        );
        // A forward that is switched off forwards nothing.
        let cam = flows::parse(&line(
            "tcp",
            "198.18.1.1",
            "198.51.100.23",
            8554,
            "192.0.2.50",
        ));
        assert!(forward_of(&cam.flows[0], &fw).is_none());
        assert!(in_ports("8000-8010", 8010) && !in_ports("8000-8010", 8011));
        assert!(in_ports("80,443", 443) && !in_ports("", 1));
    }

    fn pic(flows: &Flows) -> Picture {
        let (i, u, c) = (the_ifaces(), the_uci(), the_clients());
        Picture::of(&Read {
            ifaces: Some(&i),
            uci: Some(&u),
            clients: Some(&c),
            flows: Some(flows),
            ..Default::default()
        })
    }

    #[test]
    fn the_zone_pairs_as_configured_and_as_observed() {
        let p = pic(&the_flows());
        let m = p.matrix.as_ref().unwrap();
        let said: Vec<String> = m
            .iter()
            .map(|x| {
                format!(
                    "{}>{} {} {}+{}",
                    x.from,
                    x.to,
                    match &x.allowed {
                        Allowed::Yes => "yes".to_string(),
                        Allowed::No => "no".to_string(),
                        Allowed::Rules(r) => r.join("+"),
                    },
                    x.flows,
                    x.forwarded
                )
            })
            .collect();
        assert_eq!(
            said,
            [
                "lan>wan yes 9+0",
                "lan>dmz yes 1+0",
                "wan>lan Allow-ICMPv6-Forward 0+0",
                "wan>dmz Allow-ICMPv6-Forward 0+2",
                "dmz>lan no 0+0",
                "dmz>wan yes 1+0",
            ]
        );
        // What the firewall joins is simply allowed: nothing is marked for it.
        assert!(p.crossings().is_empty());
        // Without that forwarding the same flow is one the firewall should have rejected.
        let (i, c) = (the_ifaces(), the_clients());
        let apart = uci::parse(
            &fixture("network/uci.txt").replace(
                "firewall.@forwarding[2].dest='dmz'",
                "firewall.@forwarding[2].dest='nowhere'",
            ),
            &Salt::fixed([7; 16]),
        );
        let f = the_flows();
        let no = Picture::of(&Read {
            ifaces: Some(&i),
            uci: Some(&apart),
            clients: Some(&c),
            flows: Some(&f),
            ..Default::default()
        });
        assert_eq!(no.matrix.as_ref().unwrap()[1].allowed, Allowed::No);
        assert_eq!(
            no.marks.iter().filter(|m| m.grave()).collect::<Vec<_>>(),
            [&Mark::Crossing {
                from: "lan".into(),
                to: "dmz".into(),
                flows: 1
            }]
        );
        // The DMZ reaching into the LAN: the red row.
        let mut f = the_flows();
        f.flows.extend(
            flows::parse(&line(
                "tcp",
                "203.0.113.93",
                "192.0.2.10",
                445,
                "192.0.2.10",
            ))
            .flows,
        );
        let p = pic(&f);
        let bad: Vec<(&str, &str, usize)> = p
            .crossings()
            .iter()
            .map(|x| (x.from.as_str(), x.to.as_str(), x.flows))
            .collect();
        assert_eq!(bad, [("dmz", "lan", 1)]);
        // A reflected flow came through a forward: counted as that, never a crossing.
        let mut f = Flows::default();
        f.flows.extend(
            flows::parse(&line(
                "tcp",
                "192.0.2.10",
                "198.51.100.23",
                443,
                "203.0.113.93",
            ))
            .flows,
        );
        let p = pic(&f);
        assert!(p.crossings().is_empty());
        let lan_dmz = &p.matrix.as_ref().unwrap()[1];
        assert_eq!((lan_dmz.flows, lan_dmz.forwarded), (0, 1));
    }

    #[test]
    fn devices_are_joined_by_address_and_ranked_by_flows() {
        let p = pic(&the_flows());
        let rows: Vec<(&str, &str, usize, usize, String)> = p
            .devices
            .iter()
            .map(|d| {
                (
                    d.label.as_str(),
                    d.zone.as_str(),
                    d.flows,
                    d.dests,
                    d.top_ports(3),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                // The NAS: three flows over IPv4 and one over IPv6, one client.
                ("nas", "lan", 4, 3, "443×3 993".to_string()),
                // No client has this address: it is its own row, by address.
                ("192.0.2.77", "lan", 2, 2, "23×2".to_string()),
                // The desk: QUIC out, and ssh into the DMZ.
                ("desk", "lan", 2, 2, "22 u443".to_string()),
                ("02:00:5e:00:53:21", "lan", 1, 1, "5223".to_string()),
                // (By its IPv6 lease's hostname, which the config names.)
                ("phone", "lan", 1, 1, "u443".to_string()),
                ("web", "dmz", 1, 1, "443".to_string()),
            ]
        );
        let nas = &p.devices[0];
        assert!(nas.named && !nas.private);
        // Bytes of its live flows, so far: 14200+5200+3100+7200 out.
        assert_eq!((nas.up, nas.down), (Some(29700), Some(420900)));
        assert!(p.devices[4].private, "a phone's private address");
        // What is sent to the router itself (DNS, ssh) isn't a device's row.
        assert!(p.devices.iter().all(|d| d.far.iter().all(|f| f.port != 53)));
        // Telnet to the outside is marked, with why; ssh into the DMZ isn't an odd port.
        let odd = &p.devices[1];
        assert_eq!(odd.odd().count(), 1);
        assert!(odd.far[0].odd.unwrap().starts_with("telnet"));
        assert_eq!(odd.far[0].addrs.len(), 2);
        assert!(p.marks.contains(&Mark::OddPorts {
            device: "192.0.2.77".into(),
            ports: vec!["tcp/23".into()]
        }));
        assert_eq!(p.devices[2].odd().count(), 0);
        // Without accounting the bytes are unknown, not nothing.
        let mut f = the_flows();
        for x in &mut f.flows {
            (x.bytes, x.reply_bytes) = (None, None);
        }
        assert_eq!(pic(&f).devices[0].up, None);
    }

    #[test]
    fn rates_between_two_reads_and_what_restarts_them() {
        let first = the_counters();
        let later = |secs: f64, f: &dyn Fn(&mut Counted)| {
            let mut c = first.clone();
            c.uptime += secs;
            c.now += secs as i64;
            for r in c.rules.as_mut().unwrap() {
                f(r);
            }
            if let Some(d) = c.dns.as_mut() {
                d.forwarded += 30;
                d.local += 20;
            }
            c
        };
        let bump = |r: &mut Counted| match &r.role {
            Role::RejectFrom { zone } if zone == "wan" => r.packets += 5,
            Role::Dnat { proto, .. } if proto == "tcp" => r.packets += 2,
            Role::DotReject { proto, .. } if proto == "tcp" => r.packets += 1,
            _ => {}
        };
        let key = |c: &Counters, f: &dyn Fn(&Role) -> bool| {
            c.rules
                .as_ref()
                .unwrap()
                .iter()
                .find(|r| f(&r.role))
                .unwrap()
                .key()
        };
        let wan = key(
            &first,
            &|r| matches!(r, Role::RejectFrom { zone } if zone == "wan"),
        );
        let mut rates = CounterRates::default();
        // The first read: nothing to compare with.
        let r = rates.feed(&first);
        assert!(r.rules.is_empty() && r.dns.is_none() && !r.reset);
        // Ten seconds on by the router's clock: 5 rejects = 0.5/s; a rule that stood
        // still is a rate of nothing, not an unknown one.
        let second = later(10.0, &bump);
        let r = rates.feed(&second);
        assert_eq!(r.rules[&wan], 0.5);
        assert_eq!(r.rules.len(), 19);
        assert_eq!(r.rules.values().filter(|v| **v == 0.0).count(), 16);
        // (Each protocol's rule of one uci rule is its own: none hides another's count.)
        assert_eq!(r.dns, Some((3.0, 2.0)));
        // The clock didn't advance (the same read twice): no rates, nothing reset.
        let r = rates.feed(&second);
        assert!(r.rules.is_empty() && !r.reset);
        // A counter went back: the table was made again. No rate for this interval, and
        // the next one counts from here.
        let mut third = later(20.0, &|r| r.packets /= 2);
        let r = rates.feed(&third);
        assert!(r.reset && r.rules.is_empty());
        assert_eq!(r.dns, Some((0.0, 0.0)), "dnsmasq wasn't restarted");
        third.uptime += 10.0;
        for x in third.rules.as_mut().unwrap() {
            bump(x);
        }
        assert_eq!(rates.feed(&third).rules[&wan], 0.5);
        // The firewall was loaded again and the counters happen to be no smaller.
        let mut fourth = third.clone();
        fourth.uptime += 10.0;
        fourth.reset_at = Some(fourth.now);
        assert!(rates.feed(&fourth).reset);
        // A reboot: the clock went back.
        let mut boot = first.clone();
        boot.uptime = 30.0;
        let r = rates.feed(&boot);
        assert!(r.reset && r.rules.is_empty() && r.dns.is_none());
        // dnsmasq restarted: its own rates only.
        let mut dns = boot.clone();
        dns.uptime += 10.0;
        dns.dns = Some(Default::default());
        let r = rates.feed(&dns);
        assert!(!r.reset && r.dns.is_none() && r.rules.len() == 19);
        // A rule that is new has no rate; the others do.
        let mut more = dns.clone();
        more.uptime += 10.0;
        more.rules.as_mut().unwrap().push(Counted {
            chain: "dstnat_wan".into(),
            name: "new".into(),
            on: String::new(),
            packets: 3,
            bytes: 0,
            role: Role::Other,
        });
        let r = rates.feed(&more);
        assert_eq!(r.rules.len(), 19);
        // No table at all: no rates, and no claim of a reset.
        let mut none = more.clone();
        none.uptime += 10.0;
        none.rules = None;
        let r = rates.feed(&none);
        assert!(r.rules.is_empty() && !r.reset);
    }

    #[test]
    fn the_log_window_as_counts_without_this_machines_own_logins() {
        let log = seclog::parse(&fixture("network/logread.txt"));
        let s = log_sum(&log, &the_clients());
        assert_eq!(s.window_s, Some(10200));
        // Two of the four logins are sentry's own; one is the NAS (named); one comes from
        // an address no named device has.
        assert_eq!((s.ssh_own, s.ssh_known), (2, 1));
        assert_eq!(s.ssh_unknown, [(Some(ip("2001:db8:1200::c40")), 1)]);
        assert_eq!(s.ssh_failed, [(Some(ip("192.0.2.77")), 3)]);
        assert_eq!((s.failed(), s.ssh_left), (3, 1));
        assert_eq!(
            (s.wifi_connects, s.wifi_disconnects, s.wifi_auth_failed),
            (2, 1, 2)
        );
        // A refused login from this machine's own address still shows; it just isn't
        // "from elsewhere".
        let mut mine = log.clone();
        mine.me = Some(ip("192.0.2.77"));
        let s = log_sum(&mine, &[]);
        assert_eq!(s.failed(), 3);
        assert!(s.failed_elsewhere(mine.me).is_empty());
        // Nobody is named: every login not from here is from an unknown address.
        assert_eq!((s.ssh_own, s.ssh_known, s.unknown()), (0, 0, 4));
        // The router didn't say where this connection came from: nothing is "own".
        let mut anon = log.clone();
        anon.me = None;
        assert_eq!(log_sum(&anon, &[]).ssh_own, 0);
    }

    #[test]
    fn access_points_and_their_stations() {
        let raw = clients::parse(&fixture("network/clients.txt")).unwrap();
        let a = aps(&the_uci(), Some(&raw.stations));
        // The guest network is switched off: not listed.
        assert_eq!(a.len(), 2);
        assert_eq!(
            (
                a[0].device.as_str(),
                a[0].encryption.as_str(),
                a[0].mfp,
                a[0].wps
            ),
            ("radio0", "sae-mixed", Mfp::Optional, false)
        );
        // Two stations on the first; one says it has no protection, the other doesn't say.
        assert_eq!((a[0].stations, a[0].without_mfp), (Some(2), 1));
        assert_eq!(
            (a[1].mfp, a[1].stations, a[1].without_mfp),
            (Mfp::Required, Some(1), 0)
        );
        assert_eq!(aps(&the_uci(), None)[0].stations, None);
        for (enc, set, want) in [
            ("psk2", None, Mfp::Off),
            ("psk2", Some("1"), Mfp::Optional),
            ("sae", Some("0"), Mfp::Off),
            ("owe", None, Mfp::Required),
            ("none", None, Mfp::Off),
            ("sae-mixed", Some("2"), Mfp::Required),
        ] {
            assert_eq!(mfp_of(enc, set), want, "{enc} {set:?}");
        }
    }

    #[test]
    fn each_mark_and_when_there_is_none() {
        let (i, u, c) = (the_ifaces(), the_uci(), the_clients());
        let raw = clients::parse(&fixture("network/clients.txt")).unwrap();
        let (f, log) = (the_flows(), seclog::parse(&fixture("network/logread.txt")));
        let dns = dnsstate::parse(&fixture("network/dnsstate.txt")).unwrap();
        let counters = the_counters();
        let mut rates = CounterRates::default();
        rates.feed(&counters);
        let mut next = counters.clone();
        next.uptime += 64.0;
        for r in next.rules.as_mut().unwrap() {
            if matches!(&r.role, Role::DotReject { proto, .. } if proto == "tcp") {
                r.packets += 32;
            }
        }
        let rated = rates.feed(&next);
        let read = Read {
            ifaces: Some(&i),
            uci: Some(&u),
            clients: Some(&c),
            stations: Some(&raw.stations),
            counters: Some(&next),
            rated: Some(&rated),
            flows: Some(&f),
            log: Some(&log),
            dns: Some(&dns),
        };
        let p = Picture::of(&read);
        assert_eq!(
            p.marks,
            [
                Mark::SshFailed { tries: 3 },
                Mark::OddPorts {
                    device: "192.0.2.77".into(),
                    ports: vec!["tcp/23".into()]
                },
                Mark::DotTried { per_min: 30.0 },
                Mark::SshUnknown { logins: 1 },
                Mark::WifiAuthFailed { tries: 2 },
                Mark::NoMfp { stations: 1 },
            ]
        );
        assert!(p.marks.iter().all(|m| !m.text().is_empty()));
        // The numbers beside them.
        assert_eq!(p.wan_rejects.unwrap().total, 31200);
        assert_eq!(p.wan_rejects.unwrap().rate, Some(0.0));
        assert_eq!(
            p.dot,
            Some(Count {
                total: 1672,
                rate: Some(0.5)
            })
        );
        assert_eq!(p.out_new.unwrap().total, 902114);
        assert_eq!(p.forced_dns, Some(true));
        let fw: Vec<(&str, &str, Option<u64>, Option<usize>)> = p
            .forwards
            .iter()
            .map(|x| {
                (
                    x.name.as_str(),
                    x.proto.as_str(),
                    x.new.map(|n| n.total),
                    x.live,
                )
            })
            .collect();
        assert_eq!(
            fw,
            [
                ("web", "tcp", Some(5210), Some(2)),
                ("game", "udp", Some(77), Some(0))
            ]
        );
        // A list a month old; offloading switched on; a flow from outside straight in.
        let mut old = dns.clone();
        old.blocklist.as_mut().unwrap().built_at = Some(old.now - 31 * 86_400);
        let off = uci::parse(
            &fixture("network/uci.txt").replace(
                "firewall.@defaults[0].syn_flood='1'",
                "firewall.@defaults[0].syn_flood='1'\nfirewall.@defaults[0].flow_offloading='1'",
            ),
            &Salt::fixed([7; 16]),
        );
        let p = Picture::of(&Read {
            uci: Some(&off),
            dns: Some(&old),
            ..read
        });
        assert!(p.marks.contains(&Mark::ListOld { days: 31 }) && p.marks.contains(&Mark::Offload));
        // A quiet router: the forwarding in place, nobody refused, nothing odd.
        let quiet_uci = uci::parse(
            &fixture("network/uci.txt").replace(
                "wireless.default_radio0.encryption='sae-mixed'",
                "wireless.default_radio0.encryption='sae-mixed'\n\
                 wireless.default_radio0.ieee80211w='0'",
            ),
            &Salt::fixed([7; 16]),
        );
        let mut quiet_flows = the_flows();
        quiet_flows.flows.retain(|x| x.dport != 23);
        let mut quiet_log = log.clone();
        quiet_log.events.retain(|(_, e)| {
            matches!(e, Event::SshLogin { from, .. } if *from == log.me)
                || matches!(e, Event::WifiConnected { .. })
        });
        let first = Rated::default();
        let p = Picture::of(&Read {
            uci: Some(&quiet_uci),
            flows: Some(&quiet_flows),
            log: Some(&quiet_log),
            rated: Some(&first),
            ..read
        });
        assert_eq!(p.marks, []);
        // Nothing read: nothing claimed.
        let p = Picture::of(&Read::default());
        assert_eq!(p, Picture::default());
        assert!(p.matrix.is_none() && p.forced_dns.is_none() && p.wan_rejects.is_none());
        // The counters alone (the firewall's config not read yet): the forwards by their
        // rules, live flows unknown.
        let p = Picture::of(&Read {
            counters: Some(&counters),
            ..Default::default()
        });
        assert_eq!(p.forwards.len(), 2);
        assert_eq!(
            (p.forwards[0].live, p.forwards[1].port.as_str()),
            (None, "8000-8010")
        );
        assert_eq!(p.wan_rejects.unwrap().rate, None);
    }
}

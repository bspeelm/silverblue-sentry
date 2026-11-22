//! Findings for a network: what in a [`Snapshot`] of its router needs attention, given what
//! the config says is expected. Pure ([`derive`]), so every rule is tested on synthetic
//! snapshots. Reports go to `~/.local/share/sentry/networks/<name>/reports/`; what's marked
//! expected goes to `~/.config/sentry/networks/<name>/baseline.toml` (the Network screen's
//! expected listeners and the Clients screen's expected devices too).

use std::net::IpAddr;
use std::path::PathBuf;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::clients::{self, Client, Link, Seen, Topo};
use crate::collect::cert::Cert;
use crate::collect::ifaces::Ifaces;
use crate::collect::services::{Services, State as SvcState};
use crate::collect::uci::{Opening, Uci, Zone};
use crate::collect::{self, CollectError};
use crate::config::{self, Network};
use crate::remote::Router;
use sentry_app::remote::audit as store;
pub use sentry_app::remote::audit::{reports_dir, set_expected_in};
use sentry_core::baseline::{BaselineFile, glob};
use sentry_core::collectors::net::{ListenStatus, Listener};
use sentry_core::finding::{Finding, Sev};

/// The finding namespace of everything a network's audit says.
pub const NS: &str = "net";

pub type Report = store::Report<Snapshot>;
pub type Shown = store::Shown<Snapshot>;

/// Everything sentry knows about a network's router at one moment. Secrets in `uci` are
/// already tags ([`crate::redact`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    pub network: String,
    pub taken_at: Option<Timestamp>,
    pub ifaces: Option<Ifaces>,
    pub uci: Option<Uci>,
    pub listeners: Option<Vec<Listener>>,
    pub clients: Option<Vec<Client>>,
    /// The web interface's certificate (none: it has none, or it wasn't read).
    pub cert: Option<Cert>,
    pub services: Option<Services>,
    /// CrowdSec's firewall bouncer, where the router has it (counts, never an address).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crowdsec: Option<collect::crowdsec::Bouncer>,
    /// The config backups against the router's files as they are now (none: not compared).
    pub backup: Option<crate::backup::Status>,
    /// What the live flows and the log's window said, as far as a finding is made of it
    /// (flows across zones the firewall keeps apart, refused logins). Counts and inside
    /// addresses only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<crate::security::Seen>,
    /// (section, why it's missing)
    pub errors: Vec<(String, String)>,
}

pub fn listener_id(l: &Listener) -> String {
    store::listener_id(NS, l)
}

/// An unknown device's finding: named by a tag of its MAC (keyed with the network's salt,
/// like a secret's), never by the MAC. An id goes where Claude reads without the
/// scrubbing in between (the maintenance log, a task's row), and a MAC is one of the
/// things that never leaves this machine whole.
pub fn client_id(network: &str, mac: &str) -> String {
    match client_salt(network) {
        Some(salt) => format!(
            "{NS}:client:{}",
            salt.tag(&mac.to_ascii_lowercase())
                .trim_start_matches("redacted:")
        ),
        // No salt, no name for it: every unknown device shares one finding.
        None => format!("{NS}:client:unnamed"),
    }
}

/// (Tests and their snapshots: one salt, so an id is the same in every run.)
#[cfg(any(test, feature = "testing"))]
fn client_salt(_network: &str) -> Option<crate::redact::Salt> {
    Some(crate::redact::Salt::fixed([7; 16]))
}

#[cfg(not(any(test, feature = "testing")))]
fn client_salt(network: &str) -> Option<crate::redact::Salt> {
    use std::sync::Mutex;
    static SALTS: Mutex<Vec<(String, crate::redact::Salt)>> = Mutex::new(Vec::new());
    let mut salts = SALTS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, s)) = salts.iter().find(|(n, _)| n == network) {
        return Some(s.clone());
    }
    let s = crate::redact::Salt::load(&crate::remote::scope(network)).ok()?;
    salts.push((network.to_string(), s.clone()));
    Some(s)
}

/// The report at `idx` (None: the newest) with the one before, read from disk.
pub fn shown(scope: &str, idx: Option<usize>) -> Shown {
    store::shown(scope, idx)
}

pub fn latest(scope: &str) -> Option<Report> {
    store::latest(scope)
}

pub fn pattern_for(id: &str) -> Option<(String, String)> {
    store::pattern_for(NS, id)
}

/// Where a listening socket can be reached from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Side {
    /// The router itself only.
    Local,
    /// Every address: wherever the firewall lets it be reached.
    Any,
    /// An address of an interface in this firewall zone.
    Zone(String),
    /// An address no interface is known to have.
    Unknown,
}

/// The firewall and the interfaces, as far as they were read: which zone an address is in,
/// and what the outside can reach.
pub struct Exposure<'a> {
    ifaces: Option<&'a Ifaces>,
    pub zones: Vec<Zone>,
    openings: Vec<Opening>,
    /// The zones that hold an uplink.
    pub wan: Vec<String>,
}

fn ip(s: &str) -> Option<IpAddr> {
    s.trim_start_matches('[')
        .trim_end_matches(']')
        .split('/')
        .next()?
        .parse()
        .ok()
}

/// The link-local address a MAC makes (EUI-64).
fn link_local(mac: &str) -> Option<IpAddr> {
    let b: Vec<u8> = config::mac(mac)?
        .split(':')
        .filter_map(|x| u8::from_str_radix(x, 16).ok())
        .collect();
    let [a, b1, c, d, e, f] = b[..] else {
        return None;
    };
    format!(
        "fe80::{:x}:{:x}:{:x}:{:x}",
        u16::from_be_bytes([a ^ 2, b1]),
        u16::from_be_bytes([c, 0xff]),
        u16::from_be_bytes([0xfe, d]),
        u16::from_be_bytes([e, f])
    )
    .parse()
    .ok()
}

impl<'a> Exposure<'a> {
    pub fn of(s: &'a Snapshot) -> Self {
        Self::new(s.ifaces.as_ref(), s.uci.as_ref())
    }

    pub fn new(ifaces: Option<&'a Ifaces>, uci: Option<&Uci>) -> Self {
        let zones = uci.map(Uci::zones).unwrap_or_default();
        let uplinks: Vec<&str> = ifaces
            .map(|i| {
                [i.wan(), i.wan6()]
                    .into_iter()
                    .flatten()
                    .map(|w| w.name.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let mut wan: Vec<String> = zones
            .iter()
            .filter(|z| z.networks.iter().any(|n| uplinks.contains(&n.as_str())))
            .map(|z| z.name.clone())
            .collect();
        // Nothing read says which is the uplink: the zone called wan is.
        if wan.is_empty() && zones.iter().any(|z| z.name == "wan") {
            wan.push("wan".into());
        }
        Self {
            ifaces,
            zones,
            openings: uci.map(Uci::openings).unwrap_or_default(),
            wan,
        }
    }

    fn zone_of_net(&self, net: &str) -> Option<&str> {
        self.zones
            .iter()
            .find(|z| z.networks.iter().any(|n| n == net))
            .map(|z| z.name.as_str())
    }

    pub fn side(&self, l: &Listener) -> Side {
        let Some(addr) = ip(&l.addr) else {
            return if l.addr == "*" {
                Side::Any
            } else {
                Side::Unknown
            };
        };
        if addr.is_loopback() {
            return Side::Local;
        }
        if addr.is_unspecified() {
            return Side::Any;
        }
        let Some(i) = self.ifaces else {
            return Side::Unknown;
        };
        let net = i
            .interfaces
            .iter()
            .find(|x| {
                x.ipv4
                    .iter()
                    .chain(&x.ipv6)
                    .chain(&x.local6)
                    .any(|a| ip(a) == Some(addr))
            })
            .and_then(|x| self.zone_of_net(&x.name));
        if let Some(z) = net {
            return Side::Zone(z.to_string());
        }
        // A link-local address is its device's; a bridge and the ports beside it can share
        // one MAC, and then the address alone doesn't say which zone it's in.
        let mut zones: Vec<&str> = i
            .devices
            .iter()
            .filter(|d| link_local(&d.mac) == Some(addr))
            .filter_map(|d| self.zone_of_net(i.net_of(&d.name)?))
            .collect();
        zones.sort();
        zones.dedup();
        match zones[..] {
            [z] => Side::Zone(z.to_string()),
            _ => Side::Unknown,
        }
    }

    /// Whether the firewall lets `proto` to `port` on the router in from outside.
    pub fn wan_open(&self, proto: &str, port: &str) -> bool {
        let Ok(port) = port.parse::<u16>() else {
            return false;
        };
        self.zones
            .iter()
            .filter(|z| self.wan.contains(&z.name))
            .any(|z| z.input == "ACCEPT")
            || self
                .openings
                .iter()
                .any(|o| self.wan.contains(&o.src) && o.covers(proto, port))
    }

    /// The outside can reach it: bound to an uplink's address, or to every address with the
    /// firewall letting its port in.
    pub fn outside(&self, l: &Listener) -> bool {
        match self.side(l) {
            Side::Zone(z) => self.wan.contains(&z),
            Side::Any => self.wan_open(&l.proto, &l.port),
            Side::Local | Side::Unknown => false,
        }
    }

    /// The baseline keys of the listeners `expect.listeners` covers: `proto:port@zone`
    /// covers a listener on an address of that zone, and one on every address unless the
    /// outside can reach it too (that takes naming the uplink's zone).
    pub fn expected_keys(&self, listeners: &[Listener], cfg: &Network) -> Vec<String> {
        let entries: Vec<(&str, config::Ports, &str)> = cfg
            .expect
            .listeners
            .iter()
            .filter_map(|e| config::listener(e).ok())
            .collect();
        listeners
            .iter()
            .filter(|l| {
                let Ok(port) = l.port.parse::<u16>() else {
                    return false;
                };
                let side = self.side(l);
                entries.iter().any(|(proto, ports, zone)| {
                    *proto == l.proto
                        && ports.from <= port
                        && port <= ports.to
                        && match &side {
                            Side::Zone(z) => z == zone,
                            Side::Any if self.wan_open(&l.proto, &l.port) => {
                                self.wan.iter().any(|w| w == zone)
                            }
                            Side::Any | Side::Unknown => true,
                            Side::Local => false,
                        }
                })
            })
            .map(Listener::key)
            .collect()
    }

    /// How a listening socket stands, for the audit and the Network screen alike: the
    /// shared rule, with what `expect.listeners` covers; a UDP socket on a port the kernel
    /// handed out (an NTP client's) is a client's, not a service.
    pub fn status(&self, l: &Listener, expected: &[String], base: &BaselineFile) -> ListenStatus {
        match store::listener_status(l, expected, base) {
            ListenStatus::New
                if l.proto == "udp" && l.port.parse::<u16>().is_ok_and(|p| p >= 32768) =>
            {
                ListenStatus::Ephemeral
            }
            s => s,
        }
    }
}

fn f(id: String, sev: Sev, category: &str, message: String) -> Finding {
    Finding {
        id,
        severity: sev,
        category: category.into(),
        message,
        ..Default::default()
    }
}

trait Explain {
    fn explain(self, what: &str, why: &str, fix: &str) -> Self;
    fn evidence(self, e: String) -> Self;
}

impl Explain for Finding {
    fn explain(mut self, what: &str, why: &str, fix: &str) -> Self {
        self.what = what.into();
        self.why = why.into();
        self.fix = fix.into();
        self
    }
    fn evidence(mut self, e: String) -> Self {
        self.evidence = e;
        self
    }
}

/// How a client's link reads in a sentence.
fn on(link: &Link) -> String {
    match link {
        Link::Wired { port } => format!("on wired port {port}"),
        Link::Wifi { ifname, .. } => format!("on Wi-Fi ({ifname})"),
        Link::Dmz { port, net } if net.is_empty() => format!("on port {port}"),
        Link::Dmz { port, net } => format!("on {net} ({port})"),
        Link::Unknown => "holding a lease".into(),
    }
}

/// Every finding for this snapshot. `base` is what was marked expected (findings, listeners).
/// Nothing is compared with the report before (`_prev`): what changed since the last config
/// backup is in the snapshot itself (`backup`, read against the backup's own manifest).
pub fn derive(
    s: &Snapshot,
    cfg: &Network,
    _prev: Option<&Snapshot>,
    base: &BaselineFile,
) -> Vec<Finding> {
    let now = s.taken_at.unwrap_or_else(Timestamp::now);
    let ex = Exposure::of(s);
    let mut out: Vec<Finding> = Vec::new();

    if let Some(i) = &s.ifaces {
        if let Some(w) = i.wan().filter(|w| !w.up) {
            out.push(
                f(
                    format!("{NS}:wan:down"),
                    Sev::High,
                    "uplink",
                    format!("the uplink ({}) is down", w.name),
                )
                .explain(
                    "The interface that leads to the internet isn't up.",
                    "Nothing on the network reaches the internet until it is.",
                    "Check the cable and the modem; the Dashboard shows the port's link.",
                )
                .evidence(format!("{} on {} · {}", w.proto, w.device, w.name)),
            );
        }
        let t = &cfg.thresholds;
        let info = &i.info;
        if info.mem_total > 0 {
            let used = 100.0 * (info.mem_total.saturating_sub(info.mem_available)) as f32
                / info.mem_total as f32;
            if used >= t.mem_pct {
                out.push(f(
                    format!("{NS}:mem-high"),
                    Sev::Medium,
                    "load",
                    format!("memory {used:.0}% used"),
                ));
            }
        }
        if info.load[1] >= t.load {
            out.push(f(
                format!("{NS}:load-high"),
                Sev::Medium,
                "load",
                format!("load {:.1} (5 min)", info.load[1]),
            ));
        }
    }

    if let Some(u) = &s.uci {
        // Zones: who is in them, and what the uplink's zone lets through.
        let mut zone_said: Vec<(String, Sev, Vec<String>)> = Vec::new();
        let mut say =
            |zone: &str, sev: Sev, what: String| match zone_said.iter_mut().find(|z| z.0 == zone) {
                Some(z) => {
                    z.1 = z.1.max(sev);
                    z.2.push(what);
                }
                None => zone_said.push((zone.to_string(), sev, vec![what])),
            };
        if !cfg.expect.zones.is_empty() {
            for (name, nets) in &cfg.expect.zones {
                match ex.zones.iter().find(|z| &z.name == name) {
                    None => say(name, Sev::Medium, "isn't in the firewall any more".into()),
                    Some(z) => {
                        let sorted = |v: &[String]| {
                            let mut v = v.to_vec();
                            v.sort();
                            v
                        };
                        if sorted(&z.networks) != sorted(nets) {
                            say(
                                name,
                                Sev::Medium,
                                format!(
                                    "holds {} (expected {})",
                                    z.networks.join(", "),
                                    nets.join(", ")
                                ),
                            );
                        }
                    }
                }
            }
            for z in ex
                .zones
                .iter()
                .filter(|z| !cfg.expect.zones.contains_key(&z.name))
            {
                say(
                    &z.name,
                    Sev::Medium,
                    format!("isn't in expect.zones (it holds {})", z.networks.join(", ")),
                );
            }
        }
        for z in ex.zones.iter().filter(|z| ex.wan.contains(&z.name)) {
            if z.input == "ACCEPT" {
                say(
                    &z.name,
                    Sev::High,
                    "accepts everything from outside for the router itself (input ACCEPT)".into(),
                );
            }
            if z.forward == "ACCEPT" {
                say(
                    &z.name,
                    Sev::High,
                    "forwards everything from outside (forward ACCEPT)".into(),
                );
            }
        }
        for (zone, sev, what) in zone_said {
            out.push(
                f(format!("{NS}:zone:{zone}"), sev, "firewall", format!("zone {zone} {}", what.join("; ")))
                    .explain(
                        "A firewall zone isn't as network_config.yaml expects it.",
                        if sev == Sev::High {
                            "The uplink's zone should reject or drop what nobody asked for: this lets the internet in."
                        } else {
                            "Which interfaces share a zone decides what can talk to what."
                        },
                        "If you meant it, change expect.zones (or press b); otherwise put the zone back.",
                    ),
            );
        }

        // Port forwards: each one found is expected, and each one expected is found.
        let found = u.forwards();
        let covers = |e: &config::Forward, proto: &str| e.proto == proto || e.proto == "any";
        for r in found.iter().filter(|r| r.enabled) {
            for proto in &r.protos {
                let port_as =
                    |e: &&config::Forward| covers(e, proto) && e.port.to_string() == r.port;
                if cfg
                    .expect
                    .forwards
                    .iter()
                    .filter(port_as)
                    .any(|e| e.to == r.dest_ip)
                {
                    continue;
                }
                let message = match cfg.expect.forwards.iter().find(port_as) {
                    Some(e) => format!(
                        "{proto} port {} is forwarded to {} (expected {}, as {})",
                        r.port, r.dest_ip, e.to, e.name
                    ),
                    None => format!(
                        "{proto} port {} is forwarded to {} ({})",
                        r.port, r.dest_ip, r.name
                    ),
                };
                out.push(
                    f(format!("{NS}:forward:{proto}:{}", r.port), Sev::High, "firewall", message)
                        .explain(
                            "The firewall sends this port from outside to a device inside, and expect.forwards doesn't have it.",
                            "Anyone on the internet can reach that device on this port.",
                            "If you meant it, add it to expect.forwards in network_config.yaml (or press b); otherwise remove the redirect.",
                        )
                        .evidence(format!(
                            "firewall.{} · {} → {}:{}",
                            r.section,
                            r.src,
                            r.dest_ip,
                            r.dest_port.as_deref().unwrap_or(&r.port)
                        )),
                );
            }
        }
        for e in &cfg.expect.forwards {
            let same_port = |r: &&crate::collect::uci::Redirect| {
                r.port == e.port.to_string() && r.protos.iter().any(|p| covers(e, p))
            };
            if found.iter().filter(|r| r.enabled).any(|r| same_port(&r)) {
                continue;
            }
            let disabled = found.iter().find(same_port);
            out.push(
                f(
                    format!("{NS}:forward:missing:{}", e.name),
                    Sev::Medium,
                    "firewall",
                    format!(
                        "the forward {} ({} {} → {}) {}",
                        e.name,
                        e.proto,
                        e.port,
                        e.to,
                        if disabled.is_some() {
                            "is switched off"
                        } else {
                            "isn't there"
                        }
                    ),
                )
                .explain(
                    "A port forward network_config.yaml expects isn't in effect.",
                    "Whatever it serves can't be reached from outside.",
                    "Put it back, or take it out of expect.forwards.",
                ),
            );
        }

        // ssh: password logins.
        let lax: Vec<_> = u
            .dropbear()
            .into_iter()
            .filter(|d| d.password_auth || d.root_password_auth)
            .collect();
        if let Some(first) = lax.first() {
            let outside = lax.iter().any(|d| {
                ex.wan_open("tcp", &d.port)
                    && d.interface.as_deref().is_none_or(|i| {
                        ex.zone_of_net(i)
                            .is_some_and(|z| ex.wan.iter().any(|w| w == z))
                    })
            });
            out.push(
                f(
                    format!("{NS}:ssh:password"),
                    if outside { Sev::High } else { Sev::Medium },
                    "access",
                    "ssh accepts passwords".to_string(),
                )
                .explain(
                    "The router's ssh server lets a password log in (as root, too).",
                    "A password can be guessed or phished; a key can't. sentry itself logs in with a key.",
                    "Once your key works, set PasswordAuth and RootPasswordAuth to off in /etc/config/dropbear.",
                )
                .evidence(format!(
                    "dropbear.{}: PasswordAuth {} · RootPasswordAuth {} · port {}",
                    first.section,
                    if first.password_auth { "on" } else { "off" },
                    if first.root_password_auth { "on" } else { "off" },
                    first.port
                )),
            );
        }

        // The web interface over plain HTTP.
        if let Some(h) = u
            .uhttpd()
            .filter(|h| !h.listen_http.is_empty() && !h.redirect_https)
        {
            out.push(
                f(format!("{NS}:luci:http"), Sev::Medium, "access", "the web interface answers over plain HTTP".into())
                    .explain(
                        "uhttpd listens for HTTP and doesn't send browsers on to HTTPS.",
                        "Logging in that way sends the router's password across the network in the clear.",
                        "Set redirect_https to 1 in /etc/config/uhttpd (or drop listen_http).",
                    )
                    .evidence(format!("listen_http {} · redirect_https 0", h.listen_http.join(" "))),
            );
        }

        // Changes staged with `uci set` and never committed.
        let staged = u.staged_audited();
        if !staged.is_empty() {
            let more = staged.len().saturating_sub(8);
            let mut lines: Vec<String> = staged.iter().take(8).map(|l| l.to_string()).collect();
            if more > 0 {
                lines.push(format!("… {more} more"));
            }
            out.push(
                f(
                    format!("{NS}:config:staged"),
                    Sev::Medium,
                    "config",
                    format!("{} config change(s) staged but not committed", staged.len()),
                )
                .explain(
                    "Something was changed with `uci set` (or in the web interface, not yet saved) and never committed.",
                    "It isn't in effect and isn't on flash: the next commit by anything applies it, and a reboot loses it.",
                    "Look at `uci changes`; then `uci commit`, or `uci revert <config>`.",
                )
                .evidence(lines.join("\n")),
            );
        }
    }

    // The config against its newest backup (or there is none).
    if let Some(b) = &s.backup {
        let fix = if b.recipients {
            "Enter here runs config-backup (or `sentry-network backup`)."
        } else {
            "Set backup.recipients in network_config.yaml (`sentry-network backup key <file>` makes a key), then run config-backup."
        };
        let id = format!("{NS}:config:unsaved");
        match (&b.newest, b.changed.as_ref().filter(|c| c.any())) {
            (None, _) => out.push(
                f(
                    id,
                    // Nobody set backups up: said, but nothing presses.
                    if b.recipients { Sev::Medium } else { Sev::Low },
                    "config",
                    "there is no backup of the router's config".into(),
                )
                .explain(
                    "sentry has never backed this router's configuration up.",
                    "A reset, a failed upgrade or a dead router takes the firewall, the Wi-Fi and every lease with it.",
                    fix,
                ),
            ),
            (Some(k), Some(c)) => {
                let what = if c.options.is_empty() { &c.files } else { &c.options };
                out.push(
                    f(
                        id,
                        Sev::Medium,
                        "config",
                        format!(
                            "the config changed since the last backup ({} file(s))",
                            c.files.len()
                        ),
                    )
                    .explain(
                        "What's on the router isn't what the newest backup holds.",
                        "Restoring that backup would lose these changes.",
                        fix,
                    )
                    .evidence(format!(
                        "since {}\n{}",
                        k.at.strftime("%Y-%m-%d %H:%M UTC"),
                        crate::backup::capped(what, 8).join("\n")
                    )),
                );
            }
            _ => {}
        }
    }

    if let Some(ls) = &s.listeners {
        let expected = ex.expected_keys(ls, cfg);
        let mut seen: Vec<String> = Vec::new();
        for l in ls {
            if ex.status(l, &expected, base) != ListenStatus::New {
                continue;
            }
            let id = listener_id(l);
            if seen.contains(&id) {
                continue;
            }
            seen.push(id.clone());
            let group: Vec<&Listener> = ls
                .iter()
                .filter(|x| {
                    listener_id(x) == id && ex.status(x, &expected, base) == ListenStatus::New
                })
                .collect();
            let outside = group.iter().any(|x| ex.outside(x));
            let owner = l.process.clone().unwrap_or_else(|| "the kernel".into());
            let finding = if outside {
                f(id, Sev::High, "listeners", format!("{} port {} on the router is open to the internet ({owner})", l.proto, l.port))
                    .explain(
                        "Something on the router listens where the outside can reach it: on the uplink's address, or on every address with the firewall letting the port in.",
                        "Anyone on the internet can talk to it.",
                        "If you meant it, name it in expect.listeners with the uplink's zone (or press b); otherwise close the firewall rule or bind it inside.",
                    )
            } else {
                f(id, Sev::Low, "listeners", format!("{} port {} listens on the router ({owner})", l.proto, l.port))
                    .explain(
                        "Something on the router listens on this port, and expect.listeners doesn't have it. Only the inside can reach it.",
                        "A router's own services (DNS, DHCP, ssh, the web interface) are usual; anything else is worth knowing about.",
                        "If you meant it, press b (or add it to expect.listeners in network_config.yaml).",
                    )
            };
            let mut finding =
                finding.evidence(group.iter().map(|x| x.key()).collect::<Vec<_>>().join("\n"));
            finding.listeners = group.iter().map(|x| x.key()).collect();
            out.push(finding);
        }
    }

    if let Some(c) = &s.cert {
        let days = c.days_left(now);
        let finding = if days < 0 {
            Some(f(
                format!("{NS}:cert:expiry"),
                Sev::Medium,
                "access",
                format!("the web interface's certificate ended {} days ago", -days),
            ))
        } else if days <= cfg.thresholds.cert_days as i64 {
            Some(f(
                format!("{NS}:cert:expiry"),
                Sev::Low,
                "access",
                format!("the web interface's certificate ends in {days} days"),
            ))
        } else {
            None
        };
        if let Some(x) = finding {
            out.push(
                x.explain(
                    "The certificate uhttpd serves the web interface with is at its end.",
                    "Browsers refuse it (more loudly than a self-signed one), and saved exceptions stop working.",
                    "Delete it and restart uhttpd to have a new one made, or install your own.",
                )
                .evidence(format!("valid until {}", c.not_after.strftime("%Y-%m-%d"))),
            );
        }
    }

    for c in s.clients.iter().flatten().filter(|c| c.flagged) {
        let Some(mac) = &c.mac else { continue };
        let named = c
            .hostname
            .as_deref()
            .map_or(String::new(), |h| format!(" ({h})"));
        out.push(
            f(client_id(&s.network, mac), Sev::Medium, "clients", format!("unknown device {mac}{named} {}", on(&c.link)))
                .explain(
                    if c.private {
                        "A device with a randomised MAC is on a wired or routed port, where no passphrase vouches for it."
                    } else {
                        "A device holds an address on your network and devices: in network_config.yaml doesn't name it."
                    },
                    "It may be something of yours that was never named, or something that shouldn't be there.",
                    "If it's yours, name it under devices: (Enter on Clients shows the line) or press b; if not, find the port or change the Wi-Fi passphrase.",
                )
                .evidence(c.addrs.join(" ")),
        );
    }

    if let Some(sv) = &s.services {
        for name in sv.watched(&cfg.expect.services) {
            let said = match sv.state(name) {
                SvcState::Down => "isn't running",
                SvcState::Missing => "isn't a service the router has",
                SvcState::Running | SvcState::NotADaemon => continue,
            };
            out.push(
                f(
                    format!("{NS}:service:{name}"),
                    Sev::High,
                    "services",
                    format!("{name} {said}"),
                )
                .explain(
                    "A service the network depends on has no running instance.",
                    "Whatever it provides is down: names, addresses, logins or the web interface.",
                    "Look at `logread -e <name>`, then /etc/init.d/<name> restart.",
                ),
            );
        }
    }

    if let Some(sec) = &s.security {
        for c in sec.crossings.iter().flatten() {
            out.push(
                f(
                    format!("{NS}:flow:{}-{}", c.from, c.to),
                    Sev::High,
                    "firewall",
                    format!(
                        "live traffic from {} into {}, which the firewall keeps apart ({} flow(s))",
                        c.from, c.to, c.flows
                    ),
                )
                .explain(
                    "The router is tracking a connection from one zone into another, and \
                     nothing in the firewall's config (no forwarding, no rule, no port \
                     forward) lets that through.",
                    "The separation between the two zones isn't holding: a firewall changed \
                     by hand, a rule added outside the config, or a config not yet reloaded.",
                    "Look at `nft list chain inet fw4 forward` and the zone's forward chain, \
                     then `fw4 reload`; if the traffic is meant, add the forwarding or a rule \
                     for it (or press b).",
                )
                .evidence(c.which.join(" · ")),
            );
        }
        if let Some(r) = sec.refused.as_ref().filter(|r| r.tries > 0) {
            let window = match r.window_s {
                Some(w) => format!(
                    "the last {}",
                    match (w / 3600, (w % 3600) / 60) {
                        (0, m) => format!("{m}m"),
                        (h, 0) => format!("{h}h"),
                        (h, m) => format!("{h}h {m}m"),
                    }
                ),
                None => "the log".to_string(),
            };
            let mut from = r.inside.clone();
            if r.outside > 0 {
                from.push(format!("{} address(es) outside", r.outside));
            }
            out.push(
                f(
                    format!("{NS}:ssh:failed"),
                    Sev::Medium,
                    "access",
                    format!("{} refused ssh login(s) in {window}", r.tries),
                )
                .explain(
                    "The router's log has logins that were refused (a wrong password, a user \
                     that doesn't exist), from an address that isn't this machine's.",
                    "Someone or something is trying to log in to the router. The log is short: \
                     this covers only its window.",
                    "Find the device at that address (Clients); if it's yours and mistyped, \
                     press b. Keep password logins off (dropbear PasswordAuth), and ssh \
                     closed to the outside.",
                )
                .evidence(from.join(" · ")),
            );
        }
    }

    if let Some(b) = &s.crowdsec {
        let running = s
            .services
            .as_ref()
            .map(|sv| sv.state(collect::crowdsec::SERVICE) == SvcState::Running);
        out.extend(crowdsec(b, running));
    }

    for x in &mut out {
        x.expected = base.findings.iter().any(|g| glob(g, &x.id));
    }
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
    out
}

/// A bouncer that has run this long with nothing in its sets isn't being fed.
pub const CROWDSEC_EMPTY_S: u64 = 86_400;

/// How CrowdSec's firewall bouncer stands, where the router has it: switched on and not
/// running (high, as any service that is down), installed and never switched on, or running
/// for a day with nothing to block (both low). `running`: None when the services weren't read.
fn crowdsec(b: &collect::crowdsec::Bouncer, running: Option<bool>) -> Option<Finding> {
    let id = format!("{NS}:crowdsec:bouncer");
    let name = collect::crowdsec::SERVICE;
    if b.on() && running == Some(false) {
        return Some(
            f(
                id,
                Sev::High,
                "services",
                "CrowdSec's firewall bouncer is switched on and isn't running".into(),
            )
            .explain(
                "crowdsec-firewall-bouncer has no running instance.",
                "Its tables are removed when it stops: nothing CrowdSec decided is blocked \
                 at the router.",
                &format!("Look at `logread -e {name}`, then /etc/init.d/{name} restart."),
            ),
        );
    }
    if !b.on() && running != Some(true) {
        return Some(
            f(
                id,
                Sev::Low,
                "services",
                "CrowdSec's blocker is installed on the router but not switched on".into(),
            )
            .explain(
                "The package is on the router; `option enabled` in /etc/config/crowdsec isn't 1.",
                "Nothing CrowdSec would block is enforced at the edge yet: it needs an \
                 agent's address and key, and switching on.",
                "Set it up (api_url, api_key, enabled), or remove the package if it isn't wanted.",
            ),
        );
    }
    if running == Some(true)
        && b.blocked() == Some(0)
        && b.age_s.is_some_and(|a| a >= CROWDSEC_EMPTY_S)
    {
        return Some(
            f(
                id,
                Sev::Low,
                "services",
                "CrowdSec's firewall bouncer has run for over a day with nothing to block".into(),
            )
            .explain(
                "Its nft sets are empty.",
                "An agent with the community blocklist hands out thousands of addresses: an \
                 empty set usually means the bouncer can't reach the agent or its key is refused.",
                &format!(
                    "Look at `logread -e {name}` and /var/log/crowdsec-firewall-bouncer.log; \
                          on the agent, `cscli bouncers list` says when it last asked."
                ),
            ),
        );
    }
    None
}

/// Read everything the audit looks at. A part that fails is left out and its error
/// recorded; only ssh itself failing fails the whole.
pub fn snapshot(r: &Router) -> Result<Snapshot, CollectError> {
    let now = Timestamp::now();
    let mut errors: Vec<(String, String)> = Vec::new();
    fn part<T>(
        sec: &str,
        res: Result<T, CollectError>,
        errors: &mut Vec<(String, String)>,
    ) -> Result<Option<T>, CollectError> {
        match res {
            Ok(v) => Ok(Some(v)),
            Err(e @ CollectError::Unreachable(_)) => Err(e),
            Err(e) => {
                errors.push((sec.to_string(), e.to_string()));
                Ok(None)
            }
        }
    }
    let ifaces = part("interfaces", collect::ifaces::collect(r), &mut errors)?;
    let uci = part("config", collect::uci::collect(r), &mut errors)?;
    let listeners = part("listeners", collect::listeners::collect(r), &mut errors)?;
    let raw = part("clients", collect::clients::collect(r), &mut errors)?;
    let cert = part("certificate", collect::cert::collect(r), &mut errors)?.flatten();
    let (services, crowdsec) =
        match part("services", collect::services::collect_with(r), &mut errors)? {
            Some((sv, cs)) => (Some(sv), cs),
            None => (None, None),
        };
    // How the backups stand (a backup's sidecars are plain: nothing is decrypted).
    let backup = part(
        "backup",
        crate::backup::status(r, uci.as_ref()),
        &mut errors,
    )?;
    let clients = raw.map(|raw| {
        let topo = ifaces.as_ref().map(Topo::of).unwrap_or_default();
        let mut seen = Seen::load(&r.scope);
        let (list, _) = clients::read(&raw, &topo, &r.cfg.devices, &mut seen, now.as_second());
        let _ = seen.save(&r.scope);
        list
    });
    // The live flows and the log's window, for the two findings made of them. A router
    // that has neither (no connection table, no `logread`) simply has no such part.
    fn there<T>(
        sec: &str,
        res: Result<T, CollectError>,
        errors: &mut Vec<(String, String)>,
    ) -> Result<Option<T>, CollectError> {
        match res {
            Err(CollectError::Unavailable(_)) => Ok(None),
            res => part(sec, res, errors),
        }
    }
    let flows = there("flows", collect::flows::collect(r), &mut errors)?;
    let log = there("log", collect::seclog::collect(r), &mut errors)?;
    let security = (flows.is_some() || log.is_some()).then(|| {
        crate::security::Seen::of(&crate::security::Read {
            ifaces: ifaces.as_ref(),
            uci: uci.as_ref(),
            clients: clients.as_deref(),
            flows: flows.as_ref(),
            log: log.as_ref(),
            ..Default::default()
        })
    });
    Ok(Snapshot {
        network: r.name.clone(),
        taken_at: Some(now),
        ifaces,
        uci,
        listeners,
        clients,
        cert,
        services,
        crowdsec,
        backup,
        security,
        errors,
    })
}

/// Snapshot, derive, store (keeping the newest 200 reports).
pub fn run(r: &Router) -> Result<(Report, PathBuf), CollectError> {
    let snap = snapshot(r)?;
    let prev = latest(&r.scope);
    let base = BaselineFile::load(&r.scope);
    let findings = derive(&snap, &r.cfg, prev.as_ref().map(|p| &p.snapshot), &base);
    let report = Report {
        snapshot: snap,
        findings,
    };
    let path = store::store(&r.scope, &report)?;
    Ok((report, path))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::collect::{cert, fixture, ifaces, listeners, services, uci};
    use crate::redact::Salt;

    pub(crate) const NOW: &str = "2026-10-26T12:00:00Z";

    /// A network set up as its config says: every zone, forward, listener and device named.
    pub(crate) fn cfg() -> Network {
        let (f, w) = config::parse(
            r#"
networks:
  home:
    expect:
      zones: { lan: [lan], wan: [wan, wan6], dmz: [dmz] }
      forwards:
        - { name: web, proto: tcp, port: 443, to: 203.0.113.93 }
        - { name: game, proto: udp, port: 8000-8010, to: 192.0.2.20 }
      listeners: [ "tcp:22@lan", "tcp:80@lan", "tcp:443@lan", "tcp:53@lan", "udp:53@lan",
                   "udp:67@lan", "udp:547@lan", "tcp:53@dmz", "udp:53@dmz" ]
    devices:
      - { name: nas, mac: "00:00:5e:00:53:10" }
      - { name: desk, mac: "00:00:5e:00:53:11" }
      - { name: panel, mac: "00:00:5e:00:53:12", leave_alone: true }
      - { name: printer, mac: "00:00:5e:00:53:13" }
      - { name: dock, mac: "02:00:5e:00:53:22" }
      - { name: web, mac: "00:00:5e:00:53:30" }
      - { name: cam, mac: "00:00:5e:00:53:14" }
      - { name: phone, hostname: my-phone, private_mac: true }
"#,
        )
        .unwrap();
        assert!(w.is_empty(), "{w:?}");
        f.networks["home"].clone()
    }

    /// The fixtures as one snapshot, read twice (so a lease has been held two reads
    /// running). The socket on the uplink's address is left out: `snap_wan` has it.
    pub(crate) fn snap(cfg: &Network) -> Snapshot {
        let mut s = snap_wan(cfg);
        if let Some(ls) = s.listeners.as_mut() {
            ls.retain(|l| l.port != "1900");
        }
        s
    }

    pub(crate) fn snap_wan(cfg: &Network) -> Snapshot {
        let i = ifaces::parse(&fixture("network/ifaces.txt")).unwrap();
        let raw = crate::collect::clients::parse(&fixture("network/clients.txt")).unwrap();
        let mut seen = Seen::default();
        let topo = Topo::of(&i);
        let at: Timestamp = NOW.parse().unwrap();
        clients::read(&raw, &topo, &cfg.devices, &mut seen, at.as_second() - 10);
        let (list, _) = clients::read(&raw, &topo, &cfg.devices, &mut seen, at.as_second());
        Snapshot {
            network: "home".into(),
            taken_at: Some(at),
            ifaces: Some(i),
            uci: Some(uci::parse(
                &fixture("network/uci.txt"),
                &Salt::fixed([7; 16]),
            )),
            listeners: Some(listeners::parse(&fixture("network/netstat.txt"))),
            clients: Some(list),
            cert: cert::parse(&fixture("network/cert.hex")).unwrap(),
            services: Some(services::parse(&fixture("network/services.json")).unwrap()),
            crowdsec: None,
            backup: None,
            security: None,
            errors: Vec::new(),
        }
    }

    fn none() -> BaselineFile {
        BaselineFile::default()
    }

    fn ids(f: &[Finding]) -> Vec<(&str, Sev)> {
        f.iter().map(|x| (x.id.as_str(), x.severity)).collect()
    }

    fn find<'a>(f: &'a [Finding], id: &str) -> &'a Finding {
        f.iter()
            .find(|x| x.id == id)
            .unwrap_or_else(|| panic!("no {id} in {:?}", ids(f)))
    }

    /// The fixture's config with one option set (or a line added).
    fn with_uci(s: &mut Snapshot, edit: impl Fn(String) -> String) {
        s.uci = Some(uci::parse(
            &edit(fixture("network/uci.txt")),
            &Salt::fixed([7; 16]),
        ));
    }

    #[test]
    fn a_router_as_its_config_expects_has_no_findings() {
        let c = cfg();
        let f = derive(&snap(&c), &c, None, &none());
        assert!(f.is_empty(), "{:#?}", ids(&f));
    }

    #[test]
    fn where_a_listener_can_be_reached_from() {
        let c = cfg();
        let s = snap_wan(&c);
        let ex = Exposure::of(&s);
        assert_eq!(ex.wan, ["wan"]);
        let ls = s.listeners.as_ref().unwrap();
        let side = |proto: &str, local: &str| {
            ex.side(
                ls.iter()
                    .find(|l| l.proto == proto && l.local() == local)
                    .unwrap(),
            )
        };
        assert_eq!(side("tcp", "0.0.0.0:22"), Side::Any);
        assert_eq!(side("tcp", "[::]:443"), Side::Any);
        assert_eq!(side("tcp", "127.0.0.1:53"), Side::Local);
        assert_eq!(side("udp", "[::1]:53"), Side::Local);
        assert_eq!(side("udp", "192.0.2.1:53"), Side::Zone("lan".into()));
        assert_eq!(side("udp", "203.0.113.1:53"), Side::Zone("dmz".into()));
        // The router's own address in the prefix assigned to the LAN.
        assert_eq!(
            side("tcp", "[2001:db8:1200::1]:53"),
            Side::Zone("lan".into())
        );
        assert_eq!(side("udp", "198.51.100.23:1900"), Side::Zone("wan".into()));
        // A link-local address the bridge and the routed port share: it doesn't say.
        assert_eq!(side("udp", "[fe80::5eff:fe00:53a0]:53"), Side::Unknown);
        assert_eq!(
            link_local("02:00:5e:00:53:a1"),
            "fe80::5eff:fe00:53a1".parse().ok()
        );
        // What the firewall lets in from outside: DHCP's answers, nothing else.
        assert!(ex.wan_open("udp", "68") && !ex.wan_open("tcp", "22") && !ex.wan_open("udp", "53"));
        // The statuses the Network screen shows.
        let keys = ex.expected_keys(ls, &c);
        let status = |proto: &str, local: &str| {
            ex.status(
                ls.iter()
                    .find(|l| l.proto == proto && l.local() == local)
                    .unwrap(),
                &keys,
                &none(),
            )
        };
        assert_eq!(status("tcp", "0.0.0.0:22"), ListenStatus::Baseline);
        assert_eq!(status("tcp", "127.0.0.1:5053"), ListenStatus::Local);
        assert_eq!(status("udp", "0.0.0.0:51234"), ListenStatus::Ephemeral);
        assert_eq!(status("udp", "[::]:546"), ListenStatus::Ephemeral);
        assert_eq!(status("udp", "198.51.100.23:1900"), ListenStatus::New);
    }

    #[test]
    fn listeners_nobody_expects_and_the_ones_the_outside_can_reach() {
        let mut c = cfg();
        // On the uplink's own address: open to the internet.
        let f = derive(&snap_wan(&c), &c, None, &none());
        assert_eq!(ids(&f), [("net:listener:udp:1900", Sev::High)]);
        assert_eq!(
            find(&f, "net:listener:udp:1900").listeners,
            ["198.51.100.23:1900/?"]
        );
        // Nothing named: every service the inside can reach is listed once, low.
        c.expect.listeners.clear();
        let f = derive(&snap(&c), &c, None, &none());
        assert_eq!(
            ids(&f),
            [
                ("net:listener:tcp:22", Sev::Low),
                ("net:listener:tcp:443", Sev::Low),
                ("net:listener:tcp:53", Sev::Low),
                ("net:listener:tcp:80", Sev::Low),
                ("net:listener:udp:53", Sev::Low),
                ("net:listener:udp:547", Sev::Low),
                ("net:listener:udp:67", Sev::Low),
            ]
        );
        let dns = find(&f, "net:listener:udp:53");
        assert_eq!(dns.listeners.len(), 4, "{:?}", dns.listeners);
        assert!(dns.message.contains("dnsmasq"));
        // The firewall opens ssh to the outside: the same socket is now the internet's,
        // and naming it for the lan doesn't cover that.
        let mut c = cfg();
        let mut s = snap(&c);
        with_uci(&mut s, |t| {
            t.replace(
                "@@dropbear",
                "firewall.ssh=rule\nfirewall.ssh.src='wan'\nfirewall.ssh.proto='tcp'\nfirewall.ssh.dest_port='22'\nfirewall.ssh.target='ACCEPT'\n@@dropbear",
            )
        });
        let f = derive(&s, &c, None, &none());
        assert_eq!(ids(&f), [("net:listener:tcp:22", Sev::High)]);
        c.expect.listeners.push("tcp:22@wan".into());
        assert!(derive(&s, &c, None, &none()).is_empty());
        // Marked expected in the baseline file, by its keys: gone, as on the Network screen.
        let c = cfg();
        let base = BaselineFile {
            listeners: vec!["198.51.100.23:1900/?".into()],
            ..Default::default()
        };
        assert!(derive(&snap_wan(&c), &c, None, &base).is_empty());
    }

    #[test]
    fn forwards_found_and_forwards_expected() {
        let mut c = cfg();
        let s = snap(&c);
        // Not named: each protocol and port is a finding; a disabled redirect is none.
        c.expect.forwards.clear();
        let f = derive(&s, &c, None, &none());
        assert_eq!(
            ids(&f),
            [
                ("net:forward:tcp:443", Sev::High),
                ("net:forward:udp:8000-8010", Sev::High)
            ]
        );
        assert!(
            find(&f, "net:forward:tcp:443")
                .message
                .contains("203.0.113.93 (web)")
        );
        assert!(
            find(&f, "net:forward:tcp:443")
                .evidence
                .starts_with("firewall.web_https · wan → 203.0.113.93:443")
        );
        // Expected to go somewhere else: said as that, once.
        let mut c = cfg();
        c.expect.forwards[0].to = "203.0.113.94".into();
        let f = derive(&s, &c, None, &none());
        assert_eq!(ids(&f), [("net:forward:tcp:443", Sev::High)]);
        assert!(
            f[0].message.contains("expected 203.0.113.94, as web"),
            "{}",
            f[0].message
        );
        // Expected and absent, or switched off.
        let mut c = cfg();
        c.expect.forwards.push(config::Forward {
            name: "cam".into(),
            proto: "tcp".into(),
            port: "8554".parse().unwrap(),
            to: "192.0.2.50".into(),
        });
        c.expect.forwards.push(config::Forward {
            name: "vpn".into(),
            proto: "any".into(),
            port: "51820".parse().unwrap(),
            to: "192.0.2.10".into(),
        });
        let f = derive(&s, &c, None, &none());
        assert_eq!(
            ids(&f),
            [
                ("net:forward:missing:cam", Sev::Medium),
                ("net:forward:missing:vpn", Sev::Medium)
            ]
        );
        assert!(
            find(&f, "net:forward:missing:cam")
                .message
                .ends_with("is switched off")
        );
        assert!(
            find(&f, "net:forward:missing:vpn")
                .message
                .ends_with("isn't there")
        );
        // `any` covers whichever protocol the redirect has.
        let mut c = cfg();
        c.expect.forwards[1].proto = "any".into();
        assert!(derive(&s, &c, None, &none()).is_empty());
    }

    #[test]
    fn zones_as_expected_and_an_uplink_that_lets_the_outside_in() {
        let mut c = cfg();
        let s = snap(&c);
        c.expect
            .zones
            .insert("lan".into(), vec!["lan".into(), "guest".into()]);
        c.expect.zones.remove("dmz");
        c.expect.zones.insert("iot".into(), vec!["iot".into()]);
        let f = derive(&s, &c, None, &none());
        assert_eq!(
            ids(&f),
            [
                ("net:zone:dmz", Sev::Medium),
                ("net:zone:iot", Sev::Medium),
                ("net:zone:lan", Sev::Medium)
            ]
        );
        assert_eq!(
            find(&f, "net:zone:lan").message,
            "zone lan holds lan (expected lan, guest)"
        );
        assert!(
            find(&f, "net:zone:dmz")
                .message
                .contains("isn't in expect.zones")
        );
        assert!(
            find(&f, "net:zone:iot")
                .message
                .contains("isn't in the firewall any more")
        );
        // The uplink's zone accepting input: high, whatever the config expects; and what
        // listens on every address is then the internet's too.
        let c = cfg();
        let mut s = snap(&c);
        with_uci(&mut s, |t| {
            t.replace(
                "firewall.@zone[1].input='REJECT'",
                "firewall.@zone[1].input='ACCEPT'",
            )
        });
        let f = derive(&s, &c, None, &none());
        assert_eq!(find(&f, "net:zone:wan").severity, Sev::High);
        assert!(find(&f, "net:zone:wan").message.contains("input ACCEPT"));
        assert_eq!(find(&f, "net:listener:tcp:22").severity, Sev::High);
        // No zones named: membership isn't judged, the uplink's policy still is.
        let mut c = cfg();
        c.expect.zones.clear();
        assert!(
            !ids(&derive(&snap(&c), &c, None, &none()))
                .iter()
                .any(|(id, _)| id.starts_with("net:zone"))
        );
        assert!(ids(&derive(&s, &c, None, &none())).contains(&("net:zone:wan", Sev::High)));
    }

    #[test]
    fn password_ssh_plain_http_and_staged_changes() {
        let c = cfg();
        let mut s = snap(&c);
        with_uci(&mut s, |t| {
            t.replace(
                "dropbear.main.RootPasswordAuth='off'",
                "dropbear.main.RootPasswordAuth='on'",
            )
            .replace(
                "uhttpd.main.redirect_https='1'",
                "uhttpd.main.redirect_https='0'",
            )
            .replace(
                "@@changes",
                "@@changes\nfirewall.cfg10.name='new'\nwireless.default_radio0.key='hunter2'",
            )
        });
        let f = derive(&s, &c, None, &none());
        assert_eq!(
            ids(&f),
            [
                ("net:config:staged", Sev::Medium),
                ("net:luci:http", Sev::Medium),
                ("net:ssh:password", Sev::Medium)
            ]
        );
        assert_eq!(
            find(&f, "net:ssh:password").evidence,
            "dropbear.main: PasswordAuth off · RootPasswordAuth on · port 22"
        );
        let staged = find(&f, "net:config:staged");
        assert!(
            staged.message.starts_with("2 config change(s)"),
            "{}",
            staged.message
        );
        // Other packages' lines aren't counted, and a staged secret is a tag here too.
        assert!(staged.evidence.contains("firewall.cfg10.name='new'"));
        assert!(!staged.evidence.contains("hunter2") && !staged.evidence.contains("adblock"));
        assert!(
            staged
                .evidence
                .contains("wireless.default_radio0.key='redacted:")
        );
        // Password ssh the outside can reach is high.
        with_uci(&mut s, |t| {
            t.replace("dropbear.main.PasswordAuth='off'", "dropbear.main.PasswordAuth='on'")
                .replace("dropbear.main.Interface='lan'\n", "")
                .replace(
                    "@@dropbear",
                    "firewall.ssh=rule\nfirewall.ssh.src='wan'\nfirewall.ssh.proto='tcp'\nfirewall.ssh.dest_port='22'\nfirewall.ssh.target='ACCEPT'\n@@dropbear",
                )
        });
        assert_eq!(
            find(&derive(&s, &c, None, &none()), "net:ssh:password").severity,
            Sev::High
        );
    }

    #[test]
    fn the_certificate_near_its_end_and_past_it() {
        let c = cfg();
        let mut s = snap(&c);
        // 21 days before it ends: within thresholds.cert_days.
        s.taken_at = Some("2027-03-12T00:00:00Z".parse().unwrap());
        let f = derive(&s, &c, None, &none());
        assert_eq!(ids(&f), [("net:cert:expiry", Sev::Low)]);
        assert_eq!(
            f[0].message,
            "the web interface's certificate ends in 21 days"
        );
        assert_eq!(f[0].evidence, "valid until 2027-04-02");
        s.taken_at = Some("2027-03-10T00:00:00Z".parse().unwrap());
        assert!(derive(&s, &c, None, &none()).is_empty());
        s.taken_at = Some("2027-04-12T00:00:01Z".parse().unwrap());
        let f = derive(&s, &c, None, &none());
        assert_eq!(ids(&f), [("net:cert:expiry", Sev::Medium)]);
        assert_eq!(
            f[0].message,
            "the web interface's certificate ended 11 days ago"
        );
        // No certificate: nothing to say.
        s.cert = None;
        assert!(derive(&s, &c, None, &none()).is_empty());
    }

    #[test]
    fn unknown_clients_a_down_uplink_services_and_load() {
        let mut c = cfg();
        c.devices
            .retain(|d| !matches!(d.name.as_deref(), Some("desk" | "dock" | "web")));
        let f = derive(&snap(&c), &c, None, &none());
        // Named by a tag of the MAC, the same every time, and never by the MAC.
        let net = snap(&c).network;
        let id_of = |mac: &str| client_id(&net, mac);
        assert!(
            id_of("00:00:5e:00:53:11").len() == "net:client:".len() + 8
                && id_of("00:00:5e:00:53:11") == id_of("00:00:5E:00:53:11")
                && id_of("00:00:5e:00:53:11") != id_of("00:00:5e:00:53:30")
        );
        assert!(f.iter().all(|x| !x.id.contains("5e:00")), "{:?}", ids(&f));
        assert_eq!(
            ids(&f),
            [
                (id_of("00:00:5e:00:53:11").as_str(), Sev::Medium),
                (id_of("02:00:5e:00:53:22").as_str(), Sev::Medium),
                (id_of("00:00:5e:00:53:30").as_str(), Sev::Medium)
            ]
        );
        assert_eq!(
            f[0].message,
            "unknown device 00:00:5e:00:53:11 on wired port lan2"
        );
        assert_eq!(
            f[2].message,
            "unknown device 00:00:5e:00:53:30 (web) on dmz (lan4)"
        );
        assert!(f[1].what.contains("randomised MAC"));
        // The private MACs on Wi-Fi never are, named or not.
        assert!(
            !f.iter()
                .any(|x| x.id.ends_with(":20") || x.id.ends_with(":21"))
        );

        let c = cfg();
        let mut s = snap(&c);
        let i = s.ifaces.as_mut().unwrap();
        i.interfaces
            .iter_mut()
            .filter(|x| x.name == "wan")
            .for_each(|x| x.up = false);
        i.info.load = [0.4, 2.5, 1.0];
        i.info.mem_available = i.info.mem_total / 10;
        let sv = s.services.as_mut().unwrap();
        sv.0.get_mut("dnsmasq").unwrap().running = 0;
        let mut c2 = c.clone();
        c2.expect.services = vec!["odhcpd".into(), "wireguard".into(), "firewall".into()];
        let f = derive(&s, &c2, None, &none());
        assert_eq!(
            ids(&f),
            [
                ("net:service:dnsmasq", Sev::High),
                ("net:service:wireguard", Sev::High),
                ("net:wan:down", Sev::High),
                ("net:load-high", Sev::Medium),
                ("net:mem-high", Sev::Medium)
            ]
        );
        assert_eq!(
            find(&f, "net:service:wireguard").message,
            "wireguard isn't a service the router has"
        );
        assert_eq!(find(&f, "net:mem-high").message, "memory 90% used");
    }

    #[test]
    fn a_config_that_isnt_backed_up_is_a_finding() {
        use crate::backup::{Changed, Kept, Status};
        let c = cfg();
        let unsaved = |b: Status| {
            let mut s = snap(&c);
            s.backup = Some(b);
            derive(&s, &c, None, &none())
                .into_iter()
                .find(|f| f.id == "net:config:unsaved")
        };
        let kept = Kept {
            stamp: "20261020T090000Z".into(),
            at: "2026-10-20T09:00:00Z".parse().unwrap(),
            release: "25.12.3".into(),
            size: 30_000,
            path: "x".into(),
        };
        let with = |changed: Option<Changed>| Status {
            recipients: true,
            count: 1,
            newest: Some(kept.clone()),
            changed,
        };
        // Not compared (the backups weren't read): nothing is said.
        assert!(
            !ids(&derive(&snap(&c), &c, None, &none()))
                .iter()
                .any(|(id, _)| *id == "net:config:unsaved")
        );
        // A backup of the router as it is: nothing.
        assert!(unsaved(with(Some(Changed::default()))).is_none());
        // One without a manifest can't be compared: nothing is claimed.
        assert!(unsaved(with(None)).is_none());
        // Changed since: the options named (capped), a secret's value never among them.
        let options: Vec<String> = (0..11)
            .map(|i| format!("firewall.@rule[{i}].enabled: 1 → 0"))
            .chain(["wireless.default_radio0.key changed".to_string()])
            .collect();
        let f = unsaved(with(Some(Changed {
            files: vec!["/etc/config/firewall".into(), "/etc/config/wireless".into()],
            options,
        })))
        .unwrap();
        assert_eq!(f.severity, Sev::Medium);
        assert_eq!(
            f.message,
            "the config changed since the last backup (2 file(s))"
        );
        let ev: Vec<&str> = f.evidence.lines().collect();
        assert_eq!(ev[0], "since 2026-10-20 09:00 UTC");
        assert_eq!(ev[1], "firewall.@rule[0].enabled: 1 → 0");
        assert_eq!(ev.len(), 10);
        assert_eq!(ev[9], "… 4 more");
        assert!(f.fix.contains("config-backup"), "{}", f.fix);
        // Files outside the configs read: the files are named instead.
        let f = unsaved(with(Some(Changed {
            files: vec!["/etc/shadow".into()],
            options: Vec::new(),
        })))
        .unwrap();
        assert!(f.evidence.ends_with("/etc/shadow"), "{}", f.evidence);
        // No backup at all: its own words; low until someone can be encrypted to.
        let none_yet = |recipients| Status {
            recipients,
            ..Default::default()
        };
        let f = unsaved(none_yet(true)).unwrap();
        assert_eq!(f.message, "there is no backup of the router's config");
        assert_eq!(f.severity, Sev::Medium);
        let f = unsaved(none_yet(false)).unwrap();
        assert_eq!(f.severity, Sev::Low);
        assert!(f.fix.contains("backup.recipients"), "{}", f.fix);
        // Marked expected like any finding.
        let base = BaselineFile {
            findings: vec!["net:config:unsaved".into()],
            ..Default::default()
        };
        let mut s = snap(&c);
        s.backup = Some(none_yet(true));
        assert!(find(&derive(&s, &c, None, &base), "net:config:unsaved").expected);
    }

    #[test]
    fn what_wasnt_read_isnt_judged_and_expected_findings_are_marked() {
        let c = cfg();
        let empty = Snapshot {
            taken_at: Some(NOW.parse().unwrap()),
            ..Default::default()
        };
        assert!(derive(&empty, &c, None, &none()).is_empty());
        let mut c = cfg();
        c.expect.forwards.clear();
        let base = BaselineFile {
            findings: vec!["net:forward:tcp:*".into()],
            ..Default::default()
        };
        let f = derive(&snap(&c), &c, None, &base);
        assert!(find(&f, "net:forward:tcp:443").expected);
        assert!(!find(&f, "net:forward:udp:8000-8010").expected);
        assert_eq!(
            pattern_for("net:client:00:00:5e:00:53:11"),
            Some((
                "net:client:*".to_string(),
                "every client finding".to_string()
            ))
        );
        assert_eq!(pattern_for("net:load-high"), None);
    }

    /// The two findings made of what flows: a live flow between zones the firewall keeps
    /// apart, and refused ssh logins from somewhere that isn't this machine.
    #[test]
    fn a_flow_across_zones_and_refused_logins_are_findings() {
        use crate::collect::{flows, seclog};
        use crate::security::{Read, Seen};
        let cfg = cfg();
        let seen = |s: &Snapshot, f: &flows::Flows, log: &seclog::SecLog| {
            Seen::of(&Read {
                ifaces: s.ifaces.as_ref(),
                uci: s.uci.as_ref(),
                clients: s.clients.as_deref(),
                flows: Some(f),
                log: Some(log),
                ..Default::default()
            })
        };
        let the_flows = flows::parse(&fixture("network/conntrack.txt"));
        let the_log = seclog::parse(&fixture("network/logread.txt"));
        // A quiet log: only this machine's own logins.
        let mut quiet = the_log.clone();
        quiet.events.retain(
            |(_, e)| matches!(e, seclog::Event::SshLogin { from, .. } if *from == the_log.me),
        );
        // The fixtures' router with its flows and a quiet log: still nothing to find.
        let mut s = snap(&cfg);
        s.security = Some(seen(&s, &the_flows, &quiet));
        assert_eq!(
            s.security.as_ref().unwrap().crossings.as_deref(),
            Some(&[][..])
        );
        let f = derive(&s, &cfg, None, &none());
        assert!(f.is_empty(), "{:#?}", ids(&f));
        // The DMZ's server with a connection into the LAN.
        let mut crossed = the_flows.clone();
        crossed.flows.extend(
            flows::parse(&crate::security::tests::line(
                "tcp",
                "203.0.113.93",
                "192.0.2.10",
                445,
                "192.0.2.10",
            ))
            .flows,
        );
        s.security = Some(seen(&s, &crossed, &quiet));
        let f = derive(&s, &cfg, None, &BaselineFile::default());
        assert_eq!(ids(&f), [("net:flow:dmz-lan", Sev::High)]);
        assert_eq!(
            f[0].message,
            "live traffic from dmz into lan, which the firewall keeps apart (1 flow(s))"
        );
        assert_eq!(f[0].evidence, "203.0.113.93 → 192.0.2.10 tcp/445");
        // Refused logins from a device: medium, with where from (an inside address) and
        // the window they were counted in.
        s.security = Some(seen(&s, &the_flows, &the_log));
        let f = derive(&s, &cfg, None, &BaselineFile::default());
        assert_eq!(ids(&f), [("net:ssh:failed", Sev::Medium)]);
        assert_eq!(f[0].message, "3 refused ssh login(s) in the last 2h 50m");
        assert_eq!(f[0].evidence, "192.0.2.77");
        // From outside: counted, the address kept out of the report.
        let mut far = the_log.clone();
        for (_, e) in &mut far.events {
            if let seclog::Event::SshFailed { from, .. } = e {
                *from = Some("198.18.9.9".parse().unwrap());
            }
        }
        s.security = Some(seen(&s, &the_flows, &far));
        let f = derive(&s, &cfg, None, &BaselineFile::default());
        assert_eq!(f[0].evidence, "1 address(es) outside");
        assert!(
            !serde_json::to_string(&s).unwrap().contains("198.18."),
            "no far end is kept in a report"
        );
        // This machine's own mistyped password isn't someone else trying.
        let mut mine = the_log.clone();
        mine.me = Some("192.0.2.77".parse().unwrap());
        s.security = Some(seen(&s, &the_flows, &mine));
        assert!(derive(&s, &cfg, None, &BaselineFile::default()).is_empty());
        // Both marked expected (`b`), like any finding.
        s.security = Some(seen(&s, &crossed, &the_log));
        let base = BaselineFile {
            findings: vec!["net:flow:dmz-lan".into(), "net:ssh:failed".into()],
            ..Default::default()
        };
        let f = derive(&s, &cfg, None, &base);
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|x| x.expected));
        // Neither was read: nothing is judged, and an old report without the part reads.
        s.security = Some(Seen::default());
        assert!(derive(&s, &cfg, None, &BaselineFile::default()).is_empty());
        let old: Snapshot = serde_json::from_str("{\"network\": \"home\"}").unwrap();
        assert!(old.security.is_none());
    }

    #[test]
    fn crowdsec_bouncer_down_off_or_unfed_and_nothing_where_it_isnt() {
        use crate::collect::crowdsec::{Bouncer, SERVICE};
        use crate::collect::services::Service;
        let cfg = cfg();
        let of = |s: &Snapshot| -> Vec<(String, Sev, String)> {
            derive(s, &cfg, None, &none())
                .into_iter()
                .filter(|f| f.id.contains("crowdsec"))
                .map(|f| (f.id, f.severity, f.message))
                .collect()
        };
        // A router without it: nothing, and the report doesn't mention it.
        let mut s = snap(&cfg);
        assert!(of(&s).is_empty());
        assert!(!serde_json::to_string(&s).unwrap().contains("crowdsec"));
        let svc = |s: &mut Snapshot, running: u32| {
            s.services.as_mut().unwrap().0.insert(
                SERVICE.into(),
                Service {
                    instances: running,
                    running,
                },
            );
        };
        let fed = Bouncer {
            enabled: Some(true),
            blocked4: Some(1204),
            blocked6: Some(37),
            age_s: Some(3 * 86_400),
        };
        // Running and fed: nothing.
        s.crowdsec = Some(fed);
        svc(&mut s, 1);
        assert!(of(&s).is_empty());
        // Switched on and no instance: high, as any service down.
        svc(&mut s, 0);
        s.crowdsec = Some(Bouncer {
            blocked4: None,
            blocked6: None,
            age_s: None,
            ..fed
        });
        let f = of(&s);
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].0.as_str(), f[0].1),
            ("net:crowdsec:bouncer", Sev::High)
        );
        assert!(f[0].2.contains("isn't running"), "{}", f[0].2);
        // procd doesn't know it at all (never started): the same.
        s.services.as_mut().unwrap().0.remove(SERVICE);
        assert_eq!(of(&s)[0].1, Sev::High);
        // As the package ships: installed, `enabled '0'`. Low.
        s.crowdsec = Some(Bouncer {
            enabled: Some(false),
            ..Default::default()
        });
        let f = of(&s);
        assert_eq!((f.len(), f[0].1), (1, Sev::Low));
        assert!(f[0].2.contains("not switched on"));
        // Running with empty sets: low after a day, nothing before (it has just started),
        // nothing when its age isn't known or the tables couldn't be read.
        let empty = Bouncer {
            blocked4: Some(0),
            blocked6: Some(0),
            ..fed
        };
        svc(&mut s, 1);
        s.crowdsec = Some(empty);
        let f = of(&s);
        assert_eq!((f.len(), f[0].1), (1, Sev::Low));
        assert!(f[0].2.contains("nothing to block"));
        for b in [
            Bouncer {
                age_s: Some(CROWDSEC_EMPTY_S - 1),
                ..empty
            },
            Bouncer {
                age_s: None,
                ..empty
            },
            Bouncer {
                blocked4: None,
                blocked6: None,
                ..empty
            },
            Bouncer {
                blocked6: None,
                blocked4: Some(5),
                ..empty
            },
        ] {
            s.crowdsec = Some(b);
            assert!(of(&s).is_empty(), "{b:?}");
        }
        // The services weren't read: nothing is said about whether it runs.
        s.crowdsec = Some(fed);
        s.services = None;
        assert!(of(&s).is_empty());
        // Marked expected (a bouncer left off on purpose) stays expected.
        s.crowdsec = Some(Bouncer::default());
        let base = BaselineFile {
            findings: vec!["net:crowdsec:bouncer".into()],
            ..Default::default()
        };
        let f = derive(&s, &cfg, None, &base);
        assert!(
            f.iter()
                .find(|f| f.id == "net:crowdsec:bouncer")
                .unwrap()
                .expected
        );
    }
}

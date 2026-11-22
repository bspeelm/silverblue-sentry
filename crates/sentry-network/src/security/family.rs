//! The family filter: the devices you tick have their name lookups answered by a family
//! DNS service (CleanBrowsing Family) instead of the router's own resolver, so adult and
//! other unwanted sites don't resolve on them. Every other device is left as it is.
//!
//! **On the router it is firewall config, never DHCP or DNS config.** (Handing a device
//! another DNS server through DHCP would be the textbook way, but a blocklist package keeps
//! its own lines staged in `dhcp` on real routers, and the guard refuses a guarded change
//! while foreign lines are staged; and a device that ignores DHCP's answer would slip out.)
//! Per device, three sections of the firewall config, sentry's by name as blocks are
//! (`blocks.rs`): section and name must both be sentry's and say the same tag.
//!
//! - `sentry_filter_<tag>` / `sentry-filter-<tag>`: a `redirect` (DNAT) from the device's
//!   zone, matched by its MAC, of DNS (port 53, UDP and TCP) over IPv4 to the service's
//!   address. fw4 renders it into `dstnat_<zone>` as `ether saddr <mac> … dnat ip to
//!   <service>:53`. It catches lookups whatever server the device addressed: the router
//!   (what DHCP told it) or any other on port 53.
//! - `sentry_filter_<tag>_v6in` / `sentry-filter-<tag>-v6in` and `…_v6out` / `…-v6out`:
//!   two `rule`s that refuse DNS over IPv6 from the device, to the router (no `dest`: fw4's
//!   input chain) and onward (`dest='*'`: the forward chain). fw4 can DNAT IPv6, but a
//!   device that sends its IPv6 lookups from a private (ULA) address to the router's ULA
//!   address would, redirected to a public resolver, get no answer back (no NAT for IPv6
//!   on a default OpenWrt): its lookups would hang until they time out. Refused, they fail
//!   at once and the device asks again over IPv4, which is redirected.
//!
//! **Which rule wins (read from fw4's own source on a real router, 25.12):** in
//! `fw4.uc`'s `load()`, the redirects that packages hand to procd (`ubus_rules`) are
//! parsed *before* the config's own (`map(filter(this.state.ubus_rules, r => r.type ==
//! "redirect"), …)` and then `this.cursor.foreach("firewall", "redirect", …)`), and each
//! becomes a rule in `dstnat_<zone>` in that order. A NAT statement (`redirect`, `dnat`)
//! ends the chain for the packet. So a package that forces every DNS query to the router
//! (https-dns-proxy's `force_dns`, which hands fw4 `redirect to :53` for its source
//! interfaces, by default `lan`) always comes first, and no section of the firewall config
//! can be put ahead of it: the device's lookups would be sent to the router before sentry's
//! redirect is ever looked at. Where that program is the DNS proxy, the plan **takes its
//! forcing over** in the same change (below: "taking over"); for any other ([`hijacked`])
//! the filter refuses with a plain explanation instead of making a change that does
//! nothing. A redirect of the
//! same kind that is a section of the config (someone's own "intercept DNS" rule) can be
//! put behind sentry's: the plan reorders sentry's sections ahead of the first one
//! ([`delta`]). Another nft table with its own NAT chain on DNS is a priority sentry can't
//! reason about from the config: refused too ([`foreign_tables`]).
//!
//! What the router can't prove, and the plan says: that a given device's lookups are now
//! redirected (sentry can't test from the device itself), and that fw4 turned the sections
//! into the rules described (the disposable router can't load a firewall).
//!
//! What it doesn't stop, said once in the plan: a VPN, mobile data, a browser's own
//! encrypted lookups (DNS over HTTPS), a device that changes its MAC. A filtered device's
//! lookups skip the router's own blocklist; the family service blocks malware sites too.

use std::collections::BTreeSet;

use crate::collect::counters::{Counters, Role};
use crate::collect::uci::{Section, Uci};

/// A family DNS service. One table, so another can be added later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    /// The word a run and the notes name it by.
    pub id: &'static str,
    pub name: &'static str,
    /// Plain DNS over IPv4: the first is the one DNS is redirected to.
    pub v4: [&'static str; 2],
    pub v6: [&'static str; 2],
    /// A name the service documents as blocked (its own functional test).
    pub blocked_test: &'static str,
    /// A name any resolver answers.
    pub ordinary: &'static str,
    /// Where the addresses and the test are documented.
    pub source: &'static str,
}

/// CleanBrowsing's Family filter. Addresses from <https://cleanbrowsing.org/filters/>
/// (fetched 2026-11-22: 185.228.168.168, 185.228.169.168; 2a0d:2a00:1::, 2a0d:2a00:2::);
/// the test from <https://cleanbrowsing.org/learn/verify-dns-configuration> ("pornhub.com"
/// on the Family filter: NXDOMAIN or a block page's address). Checked from a real router
/// the same day: both v4 addresses and the first v6 one answered NXDOMAIN for the test
/// name and an address for openwrt.org.
pub const CLEANBROWSING_FAMILY: Service = Service {
    id: "cleanbrowsing-family",
    name: "CleanBrowsing Family",
    v4: ["185.228.168.168", "185.228.169.168"],
    v6: ["2a0d:2a00:1::", "2a0d:2a00:2::"],
    blocked_test: "pornhub.com",
    ordinary: "openwrt.org",
    source: "https://cleanbrowsing.org/filters/",
};

pub const SERVICES: &[Service] = &[CLEANBROWSING_FAMILY];

/// The service the filter uses.
pub fn service() -> &'static Service {
    &SERVICES[0]
}

pub fn by_id(id: &str) -> Option<&'static Service> {
    SERVICES.iter().find(|s| s.id == id)
}

/// A section's name starts with this.
pub const SECTION: &str = "sentry_filter_";
/// Its `name` starts with this.
pub const PREFIX: &str = "sentry-filter-";

/// The three parts of a device's filter: (section suffix, name suffix, kind).
const PARTS: [(&str, &str, &str); 3] = [
    ("", "", "redirect"),
    ("_v6in", "-v6in", "rule"),
    ("_v6out", "-v6out", "rule"),
];

fn word(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// A device to filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    pub tag: String,
    pub mac: String,
    pub zone: String,
}

/// The uci lines that filter one device. Err: something that can't go into a rule.
pub fn device_lines(w: &Want, wan: &str, svc: &Service) -> Result<Vec<String>, String> {
    if !super::blocks::is_tag(&w.tag) {
        return Err("no tag for this device (the network's salt couldn't be read)".into());
    }
    let mac = crate::config::mac(&w.mac).ok_or("that isn't a MAC address")?;
    if !word(&w.zone) || !word(wan) {
        return Err(format!(
            "a zone's name isn't a plain word ({}, {wan})",
            w.zone
        ));
    }
    let t = &w.tag;
    let z = &w.zone;
    let mut l = Vec::new();
    let sec = format!("{SECTION}{t}");
    for (k, v) in [
        ("", "redirect".to_string()),
        (".name", format!("'{PREFIX}{t}'")),
        (".src", format!("'{z}'")),
        (".src_mac", format!("'{mac}'")),
        (".src_dport", "'53'".into()),
        (".proto", "'tcp udp'".into()),
        (".family", "'ipv4'".into()),
        (".dest", format!("'{wan}'")),
        (".dest_ip", format!("'{}'", svc.v4[0])),
        (".dest_port", "'53'".into()),
        (".target", "'DNAT'".into()),
        (".reflection", "'0'".into()),
    ] {
        l.push(format!("uci set firewall.{sec}{k}={v}"));
    }
    for (s, n, dest) in [("_v6in", "-v6in", None), ("_v6out", "-v6out", Some("*"))] {
        let sec = format!("{SECTION}{t}{s}");
        l.push(format!("uci set firewall.{sec}=rule"));
        l.push(format!("uci set firewall.{sec}.name='{PREFIX}{t}{n}'"));
        l.push(format!("uci set firewall.{sec}.src='{z}'"));
        l.push(format!("uci set firewall.{sec}.src_mac='{mac}'"));
        if let Some(d) = dest {
            l.push(format!("uci set firewall.{sec}.dest='{d}'"));
        }
        l.push(format!("uci set firewall.{sec}.family='ipv6'"));
        l.push(format!("uci set firewall.{sec}.proto='tcp udp'"));
        l.push(format!("uci set firewall.{sec}.dest_port='53'"));
        l.push(format!("uci set firewall.{sec}.target='REJECT'"));
    }
    Ok(l)
}

/// Which of sentry's parts a section is: (tag, part index). Its kind, section and name must
/// all be sentry's and say the same tag.
fn ours(s: &Section) -> Option<(String, usize)> {
    let rest = s.name.strip_prefix(SECTION)?;
    PARTS
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, (ss, ns, kind))| {
            let tag = rest.strip_suffix(ss).filter(|_| !ss.is_empty() || i == 0)?;
            let want = format!("{PREFIX}{tag}{ns}");
            (super::blocks::is_tag(tag) && s.kind == *kind && s.one("name") == Some(want.as_str()))
                .then(|| (tag.to_string(), i))
        })
}

/// Whether a firewall section is one of sentry's filter sections.
pub fn is_ours(s: &Section) -> bool {
    ours(s).is_some()
}

/// A device's filter as the router's firewall config has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub tag: String,
    pub mac: String,
    pub zone: String,
    /// The address its DNS goes to (None: the redirect part is missing).
    pub resolver: Option<String>,
    pub sections: Vec<String>,
}

impl Found {
    /// All three parts are there.
    pub fn whole(&self) -> bool {
        self.sections.len() == PARTS.len() && self.resolver.is_some()
    }
}

/// Sentry's filters on the router, by tag, in the config's order.
pub fn found(uci: &Uci) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    for s in uci.config("firewall") {
        let Some((tag, part)) = ours(s) else {
            continue;
        };
        let f = match out.iter_mut().position(|f| f.tag == tag) {
            Some(i) => &mut out[i],
            None => {
                out.push(Found {
                    tag: tag.clone(),
                    mac: String::new(),
                    zone: String::new(),
                    resolver: None,
                    sections: Vec::new(),
                });
                out.last_mut().unwrap()
            }
        };
        f.sections.push(s.name.clone());
        if f.mac.is_empty() {
            f.mac = s.one("src_mac").unwrap_or_default().to_ascii_lowercase();
        }
        if f.zone.is_empty() {
            f.zone = s.one("src").unwrap_or_default().to_string();
        }
        if part == 0 {
            f.resolver = s.one("dest_ip").map(str::to_string);
        }
    }
    out
}

/// What already sends a zone's DNS somewhere before any section of the firewall config
/// could: the packages that hand fw4 a DNS redirect of their own (`ubus:<package>[…]`),
/// for this zone. Empty: nothing comes ahead of sentry's redirect.
pub fn hijacked(c: &Counters, zone: &str) -> Vec<String> {
    let chain = format!("dstnat_{zone}");
    let mut who: Vec<String> = c
        .rules
        .iter()
        .flatten()
        .filter(|r| r.chain == chain)
        .filter(|r| {
            matches!(r.role, Role::DnsRedirect { .. })
                || matches!(&r.role, Role::Dnat { port, .. } if port == "53")
        })
        .filter_map(|r| r.name.strip_prefix("ubus:"))
        .map(|n| n.split(['[', ' ']).next().unwrap_or(n).to_string())
        .collect();
    who.dedup();
    who
}

/// Other nft tables than fw4's with a NAT chain on the prerouting hook that touches port 53
/// (`nft list ruleset`): their priority against fw4's isn't something the config decides.
pub fn foreign_tables(ruleset: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut table = String::new();
    let mut nat = false;
    for line in ruleset.lines() {
        let l = line.trim();
        if let Some(t) = l.strip_prefix("table ") {
            table = t.trim_end_matches(" {").trim().to_string();
            nat = false;
        } else if l.starts_with("chain ") {
            nat = false;
        } else if l.starts_with("type nat hook prerouting") {
            nat = true;
        } else if nat
            && table != "inet fw4"
            && l.contains("dport 53")
            && (l.contains("redirect") || l.contains("dnat"))
            && !out.contains(&table)
        {
            out.push(table.clone());
        }
    }
    out
}

/// The DNS proxy package whose forced lookups sentry knows how to take over.
pub const PROXY: &str = "https-dns-proxy";

/// What is wrong with filtering a device in this zone, said plainly (None: nothing, or
/// only what the takeover handles: the DNS proxy's own forcing, [`takeover_needed`]).
pub fn refused(zone: &str, hijack: &[String], tables: &[String]) -> Option<String> {
    let others: Vec<&String> = hijack.iter().filter(|h| *h != PROXY).collect();
    if !others.is_empty() {
        return Some(format!(
            "the router already sends every name lookup from {} to itself ({}), and the \
             firewall puts that program's rule before any rule sentry can add: a filter set \
             up now would do nothing there, and sentry doesn't know how to take that \
             program's place",
            super::attention::side(zone),
            others
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !tables.is_empty() {
        return Some(format!(
            "another firewall table ({}) redirects name lookups itself, and which of it and \
             the router's own firewall comes first isn't something sentry can tell from the \
             settings: sentry won't work against it",
            tables.join(", ")
        ));
    }
    None
}

/// The change from what the router has to what is asked for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delta {
    pub lines: Vec<String>,
    /// Tags filtered from now on.
    pub add: Vec<String>,
    /// Tags no longer filtered.
    pub remove: Vec<String>,
    /// Tags whose filter is there and stays.
    pub keep: Vec<String>,
    /// Tags whose sections are made again (a part missing, another MAC, zone or service).
    pub redo: Vec<String>,
}

impl Delta {
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

/// A redirect of someone else's that sends DNS from this zone somewhere: sentry's must come
/// before it.
fn dns_redirect(s: &Section, zone: &str) -> bool {
    s.kind == "redirect"
        && !is_ours(s)
        && s.flag("enabled", true)
        && s.one("src") == Some(zone)
        && s.one("target")
            .is_none_or(|t| t.eq_ignore_ascii_case("DNAT"))
        && s.one("src_dport")
            .is_none_or(|p| p.split(['-', ':']).next() == Some("53") || p == "53")
}

/// The lines that make the router's filters exactly `want` (by tag): deletes first, then
/// the new sections, then what puts them ahead of someone's own DNS redirect.
pub fn delta(uci: &Uci, want: &[Want], wan: &str, svc: &Service) -> Result<Delta, String> {
    delta_without(uci, want, wan, svc, &BTreeSet::new())
}

/// The same, with these other sections deleted first by the same change (the lines that
/// delete them are the caller's, put in front).
pub fn delta_without(
    uci: &Uci,
    want: &[Want],
    wan: &str,
    svc: &Service,
    gone: &BTreeSet<String>,
) -> Result<Delta, String> {
    let have = found(uci);
    let mut d = Delta::default();
    let wanted: BTreeSet<&str> = want.iter().map(|w| w.tag.as_str()).collect();
    let mut deleted: BTreeSet<String> = gone.clone();
    let mut del = |f: &Found, lines: &mut Vec<String>| {
        for s in &f.sections {
            lines.push(format!("uci delete firewall.{s}"));
            deleted.insert(s.clone());
        }
    };
    let mut adds: Vec<&Want> = Vec::new();
    for f in &have {
        if !wanted.contains(f.tag.as_str()) {
            del(f, &mut d.lines);
            d.remove.push(f.tag.clone());
        }
    }
    for w in want {
        match have.iter().find(|f| f.tag == w.tag) {
            Some(f)
                if f.whole()
                    && Some(f.mac.as_str()) == crate::config::mac(&w.mac).as_deref()
                    && f.zone == w.zone
                    && f.resolver.as_deref() == Some(svc.v4[0]) =>
            {
                d.keep.push(w.tag.clone());
            }
            Some(f) => {
                del(f, &mut d.lines);
                d.redo.push(w.tag.clone());
                adds.push(w);
            }
            None => {
                d.add.push(w.tag.clone());
                adds.push(w);
            }
        }
    }
    for w in &adds {
        d.lines.extend(device_lines(w, wan, svc)?);
    }
    // Someone's own DNS redirect from the zone: sentry's go ahead of it. The index is
    // counted as the config stands after the deletes above (added sections go last).
    let firewall: Vec<&Section> = uci
        .config("firewall")
        .iter()
        .filter(|s| !deleted.contains(&s.name))
        .collect();
    for w in &adds {
        if let Some(at) = firewall.iter().position(|s| dns_redirect(s, &w.zone)) {
            d.lines
                .push(format!("uci reorder firewall.{SECTION}{}={at}", w.tag));
        }
    }
    Ok(d)
}

/// The addresses an answer from busybox's `nslookup` gives for the name (the server's own
/// `Address:` line, which ends in `:53`, is left out).
pub fn answered(text: &str) -> Vec<String> {
    let mut named = false;
    let mut out = Vec::new();
    for l in text.lines() {
        let l = l.trim();
        if l.starts_with("Name:") {
            named = true;
        } else if named && let Some(a) = l.strip_prefix("Address:") {
            let a = a.trim();
            if a.parse::<std::net::IpAddr>().is_ok() {
                out.push(a.to_string());
            }
        }
    }
    out
}

/// Whether the answer says the name is blocked: no such name (NXDOMAIN), or only the
/// "nowhere" address.
pub fn blocked(text: &str) -> bool {
    let a = answered(text);
    text.contains("NXDOMAIN") || (!a.is_empty() && a.iter().all(|x| x == "0.0.0.0" || x == "::"))
}

// ---- taking over the DNS proxy's forced lookups
//
// What https-dns-proxy's `force_dns` does (read on a real router, OpenWrt 25.12,
// `/etc/init.d/https-dns-proxy` of `2026.05.06-r1`, and its procd service data):
// - `start_instance` hands procd, as the FIRST instance's `data.firewall`, for each
//   interface of `force_dns_src_interface` (default `lan`) and each port of
//   `force_dns_port` (default `53 853`, plus every dnsmasq instance's own port): a
//   `redirect` (DNAT, `tcp udp`, `src_dport 53`, `dest_port <port>`, `family any`,
//   `reflection 0`) when something on the router listens on that port, else a `rule`
//   (`dest '*'`, `tcp udp`, `dest_port <port>`, REJECT). On the real router: the redirect of
//   53 to the router and the reject of 853 (DNS over TLS), lan only. fw4 puts these
//   `ubus_rules` before the config's own.
// - With it on, the dnsmasq instances get `server=/use-application-dns.net/` and the two
//   iCloud Private Relay names (no answer for them: Firefox then keeps its own encrypted
//   lookups off, iCloud Private Relay is off), unless `canary_domains_*` say no. They are
//   added on start (`dnsmasq_doh_server add`) and removed only on stop (`... remove`).
//   `restart` is `reload` in that script, so a reload with `force_dns` off stops
//   handing the firewall rules over and leaves those dnsmasq lines where they are
//   (inferred from the script, not watched).
// - Nothing else in the script reads `force_dns` (`notrack_dns`, the DoH upstreams and
//   dnsmasq's `server`/`noresolv` lines are independent of it).
// - Any reload of it commits whatever is staged in `dhcp` (`uci_changes dhcp` →
//   `uci_commit dhcp`) and then restarts dnsmasq: it does that on every reload, sentry's
//   or the interface triggers'. (On the real router the staged `dhcp` lines are
//   adblock-fast's `serversfile`, equal to what is saved.)
//
// The takeover, one change with the filter's own rules: `force_dns '0'` in the package's
// config, and sections of sentry's in the firewall config that are what the package's
// rules were (`sentry_dns_<n>` / `sentry-dns-<n>`, from its procd data, read when the plan
// is made), appended after the per-device filters, so those come first in `dstnat_<zone>`.
// The guard snapshots and restores both configs and reloads the package before the
// firewall: until fw4's reload (one nft transaction) the old rules are still loaded, so no
// device's lookups are unforced in between.

/// A section of the DNS takeover's starts with this.
pub const DNS_SECTION: &str = "sentry_dns_";
/// Its `name`.
pub const DNS_PREFIX: &str = "sentry-dns-";

/// One rule the DNS proxy hands the firewall (`data.firewall` in its procd service data).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Forced {
    /// `redirect` or `rule`.
    pub kind: String,
    pub target: String,
    pub src: String,
    pub dest: Option<String>,
    pub proto: String,
    pub src_dport: Option<String>,
    pub dest_port: Option<String>,
    pub family: Option<String>,
}

/// `ubus call service list '{"name":"https-dns-proxy"}'` → its instances' firewall rules.
pub fn parse_forced(json: &str) -> Result<Vec<Forced>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let Some(inst) = v[PROXY]["instances"].as_object() else {
        return Ok(out);
    };
    let s = |x: &serde_json::Value, k: &str| match &x[k] {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    for i in inst.values() {
        for r in i["data"]["firewall"].as_array().into_iter().flatten() {
            out.push(Forced {
                kind: s(r, "type").unwrap_or_default(),
                target: s(r, "target").unwrap_or_default(),
                src: s(r, "src").unwrap_or_default(),
                dest: s(r, "dest"),
                proto: s(r, "proto").unwrap_or_default(),
                src_dport: s(r, "src_dport"),
                dest_port: s(r, "dest_port"),
                family: s(r, "family"),
            });
        }
    }
    Ok(out)
}

/// The DNS proxy's own setting, as its config has it (None: the package isn't there).
/// Its default is on.
pub fn proxy_forces(uci: &Uci) -> Option<(String, bool)> {
    let c = uci.config(PROXY);
    let s = c
        .iter()
        .find(|s| s.kind == "main")
        .or_else(|| c.iter().find(|s| s.name == "config"))?;
    Some((s.name.clone(), s.flag("force_dns", true)))
}

/// sentry's takeover sections on the router, in the config's order: (section, kind, src).
pub fn dns_found(uci: &Uci) -> Vec<(String, String, String)> {
    uci.config("firewall")
        .iter()
        .filter_map(|s| {
            let n = s.name.strip_prefix(DNS_SECTION)?;
            let ok = !n.is_empty()
                && n.bytes().all(|b| b.is_ascii_digit())
                && s.one("name") == Some(format!("{DNS_PREFIX}{n}").as_str())
                && (s.kind == "redirect" || s.kind == "rule");
            ok.then(|| {
                (
                    s.name.clone(),
                    s.kind.clone(),
                    s.one("src").unwrap_or_default().to_string(),
                )
            })
        })
        .collect()
}

/// A word uci and fw4 take as written (a zone, a port list, a protocol list).
fn plain(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" _-*:".contains(&b))
}

/// The lines that take the forcing over: the package's setting off, and its rules as
/// sentry's sections. Err: a rule sentry can't reproduce exactly.
pub fn takeover_lines(proxy_section: &str, forced: &[Forced]) -> Result<Vec<String>, String> {
    if forced.is_empty() {
        return Err("the DNS proxy says it forces lookups but hands the firewall no rule".into());
    }
    if !plain(proxy_section) {
        return Err(format!("`{proxy_section}` isn't a section uci names"));
    }
    let mut l = vec![format!("uci set {PROXY}.{proxy_section}.force_dns='0'")];
    for (i, f) in forced.iter().enumerate() {
        let sec = format!("firewall.{DNS_SECTION}{i}");
        let kind = match f.kind.as_str() {
            "redirect" if f.target.eq_ignore_ascii_case("DNAT") => "redirect",
            "rule" if f.target.eq_ignore_ascii_case("REJECT") => "rule",
            k => {
                return Err(format!(
                    "the DNS proxy hands the firewall a `{k}` sentry doesn't know"
                ));
            }
        };
        let mut opts: Vec<(&str, String)> = vec![
            ("name", format!("{DNS_PREFIX}{i}")),
            ("src", f.src.clone()),
            ("proto", f.proto.clone()),
            ("target", f.target.to_ascii_uppercase()),
        ];
        for (k, v) in [
            ("dest", &f.dest),
            ("src_dport", &f.src_dport),
            ("dest_port", &f.dest_port),
            ("family", &f.family),
        ] {
            if let Some(v) = v {
                opts.push((k, v.clone()));
            }
        }
        if kind == "redirect" {
            opts.push(("reflection", "0".into()));
        }
        if let Some((k, v)) = opts.iter().find(|(_, v)| !plain(v)) {
            return Err(format!(
                "the DNS proxy's `{k}` (`{v}`) isn't something sentry copies"
            ));
        }
        l.push(format!("uci set {sec}={kind}"));
        for (k, v) in opts {
            l.push(format!("uci set {sec}.{k}='{v}'"));
        }
    }
    Ok(l)
}

/// What the DNS proxy would hand the firewall with `force_dns` on, from its own settings,
/// the way its init script makes it (for each `force_dns_src_interface`, each port of
/// `force_dns_port`: a redirect where something listens on it, a refusal where nothing
/// does). Used only where sentry's sections are gone and the proxy's forcing is off, so its
/// procd data has nothing to copy: taken as 53 listening and the rest not (inferred: the
/// router's own resolver is on 53, nothing on 853).
pub fn default_forced(uci: &Uci) -> Vec<Forced> {
    let c = uci.config(PROXY);
    let main = c.iter().find(|s| s.kind == "main");
    let get = |k: &str, d: &str| {
        main.and_then(|s| s.one(k))
            .filter(|v| !v.is_empty())
            .unwrap_or(d)
            .to_string()
    };
    let mut out = Vec::new();
    for iface in get("force_dns_src_interface", "lan")
        .split([' ', ','])
        .filter(|x| !x.is_empty())
    {
        for p in get("force_dns_port", "53 853")
            .split([' ', ','])
            .filter(|x| !x.is_empty())
        {
            out.push(match p {
                "53" => Forced {
                    kind: "redirect".into(),
                    target: "DNAT".into(),
                    src: iface.into(),
                    dest: None,
                    proto: "tcp udp".into(),
                    src_dport: Some("53".into()),
                    dest_port: Some("53".into()),
                    family: Some("any".into()),
                },
                p => Forced {
                    kind: "rule".into(),
                    target: "REJECT".into(),
                    src: iface.into(),
                    dest: Some("*".into()),
                    proto: "tcp udp".into(),
                    src_dport: None,
                    dest_port: Some(p.into()),
                    family: None,
                },
            });
        }
    }
    out
}

/// The lines that hand the forcing back: sentry's sections gone, the package's setting on.
pub fn handback_lines(uci: &Uci) -> Vec<String> {
    let mut l: Vec<String> = dns_found(uci)
        .into_iter()
        .map(|(s, _, _)| format!("uci delete firewall.{s}"))
        .collect();
    if let Some((sec, false)) = proxy_forces(uci) {
        l.push(format!("uci set {PROXY}.{sec}.force_dns='1'"));
    }
    l
}

/// The precedence, read back from the firewall as loaded (`nft list chain inet fw4
/// dstnat_<zone>` then `forward_<zone>`, cut at `@@forward`): no DNS redirect of the
/// proxy's left, every device's filter before the catch-all, the catch-all there, and the
/// rejects that were the proxy's present. Ok: what was seen.
pub fn precedence(zone: &str, text: &str, rejects: usize) -> Result<String, String> {
    let (nat, fwd) = text.split_once("@@forward").unwrap_or((text, ""));
    let rule_of = |l: &str, p: &str| l.contains(&format!("\"!fw4: {p}"));
    let lines: Vec<&str> = nat.lines().collect();
    if lines
        .iter()
        .any(|l| rule_of(l, "ubus:") && l.contains("dport 53"))
    {
        return Err(format!(
            "another program's DNS redirect is still first in {zone}'s rules"
        ));
    }
    let catch = lines
        .iter()
        .position(|l| rule_of(l, DNS_PREFIX) && l.contains("redirect"));
    let last_filter = lines
        .iter()
        .rposition(|l| rule_of(l, PREFIX) && !l.contains("-v6"));
    let Some(catch) = catch else {
        return Err(format!(
            "sentry's catch-all redirect of lookups isn't among {zone}'s rules"
        ));
    };
    if last_filter.is_some_and(|f| f > catch) {
        return Err(format!(
            "a device's filter comes after the catch-all in {zone}'s rules"
        ));
    }
    let seen = fwd.lines().filter(|l| rule_of(l, DNS_PREFIX)).count();
    if seen < rejects {
        return Err(format!(
            "{zone}'s refusal of encrypted lookups (port 853) isn't loaded"
        ));
    }
    Ok(format!(
        "in {zone}'s rules every filtered device comes before the catch-all, and the forced \
         lookups' other rules are loaded"
    ))
}

/// Tests on a router that can't load a firewall: the two chains as fw4 would load them
/// from this config and these procd-supplied rules (fw4.uc's order: the procd rules
/// first, then the config's, each in order), in `nft list chain`'s words as far as
/// [`precedence`] reads them. It shows the order the config makes, never what nft did.
#[cfg(test)]
pub fn simulated(uci: &Uci, zone: &str, forced: &[Forced]) -> String {
    let mut nat = Vec::new();
    let mut fwd = Vec::new();
    for (i, f) in forced.iter().enumerate().filter(|(_, f)| f.src == zone) {
        let c = format!("comment \"!fw4: ubus:{PROXY}[instance1] {} {i}\"", f.kind);
        match f.kind.as_str() {
            "redirect" => nat.push(format!("udp dport 53 counter redirect to :53 {c}")),
            _ => fwd.push(format!(
                "tcp dport {} counter jump handle_reject {c}",
                f.dest_port.as_deref().unwrap_or("")
            )),
        }
    }
    for s in uci.config("firewall") {
        if s.one("src") != Some(zone) || !s.flag("enabled", true) {
            continue;
        }
        let name = s.one("name").unwrap_or(&s.name);
        let port = s.one("src_dport").or(s.one("dest_port")).unwrap_or("");
        match s.kind.as_str() {
            "redirect" => nat.push(format!(
                "udp dport {port} counter {} comment \"!fw4: {name}\"",
                match s.one("dest_ip") {
                    Some(ip) => format!("dnat ip to {ip}:53"),
                    None => "redirect to :53".into(),
                }
            )),
            "rule" if s.one("dest").is_some() => fwd.push(format!(
                "tcp dport {port} counter jump handle_reject comment \"!fw4: {name}\""
            )),
            _ => {}
        }
    }
    format!(
        "table inet fw4 {{\n\tchain dstnat_{zone} {{\n{}\n\t}}\n}}\n@@forward\ntable inet fw4 {{\n\tchain forward_{zone} {{\n{}\n\t}}\n}}\n",
        nat.join("\n"),
        fwd.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::Salt;

    fn uci_of(firewall: &str) -> Uci {
        crate::collect::uci::parse(&format!("@@firewall\n{firewall}"), &Salt::fixed([7; 16]))
    }

    fn want(tag: &str, n: u8) -> Want {
        Want {
            tag: tag.into(),
            mac: format!("02:00:5E:00:53:{n:02X}"),
            zone: "lan".into(),
        }
    }

    /// The config as the router would have it after the lines (a uci show of them).
    fn applied(lines: &[String]) -> String {
        lines
            .iter()
            .filter_map(|l| l.strip_prefix("uci set "))
            .map(|l| format!("{l}\n"))
            .collect()
    }

    #[test]
    fn one_device_is_a_redirect_and_two_ipv6_rejects() {
        let l = device_lines(&want("ab12cd34", 0x21), "wan", service()).unwrap();
        let text = l.join("\n");
        insta::assert_snapshot!("family_device_lines", text);
        assert!(text.contains("dest_ip='185.228.168.168'"));
        assert!(
            text.contains("src_mac='02:00:5e:00:53:21'"),
            "a MAC as uci writes it"
        );
        // The input rule has no dest; the forward one has `*`.
        assert!(!text.contains("_v6in.dest='"));
        assert!(text.contains("_v6out.dest='*'"));
        // The guard takes every line as written.
        let c = crate::guard::Change::parse("firewall", &l.join("; "), "firewall", false);
        assert!(c.is_ok(), "{c:?}");
        for (tag, mac, zone) in [
            ("nope", "02:00:5e:00:53:21", "lan"),
            ("ab12cd34", "nope", "lan"),
            ("ab12cd34", "02:00:5e:00:53:21", "l'an"),
        ] {
            let w = Want {
                tag: tag.into(),
                mac: mac.into(),
                zone: zone.into(),
            };
            assert!(device_lines(&w, "wan", service()).is_err(), "{w:?}");
        }
    }

    #[test]
    fn the_change_is_a_delta_against_the_router() {
        let svc = service();
        // Nothing there, nothing wanted: no change.
        let empty = uci_of("firewall.@defaults[0]=defaults\n");
        assert!(delta(&empty, &[], "wan", svc).unwrap().is_empty());
        // Nothing there, three wanted: three devices' sections, nothing deleted.
        let three = [
            want("0000000a", 1),
            want("0000000b", 2),
            want("0000000c", 3),
        ];
        let d = delta(&empty, &three, "wan", svc).unwrap();
        assert_eq!(d.add.len(), 3);
        assert_eq!(d.lines.len(), 3 * 29);
        assert!(
            !d.lines
                .iter()
                .any(|l| l.contains("delete") || l.contains("reorder"))
        );
        // One there: asking for the same one changes nothing; for 0 removes exactly its
        // sections; for it and another adds only the other.
        let one = uci_of(&applied(&device_lines(&three[0], "wan", svc).unwrap()));
        assert_eq!(found(&one).len(), 1);
        assert!(found(&one)[0].whole());
        let same = delta(&one, &three[..1], "wan", svc).unwrap();
        assert!(same.is_empty() && same.keep == ["0000000a"]);
        let none = delta(&one, &[], "wan", svc).unwrap();
        assert_eq!(
            none.lines,
            [
                "uci delete firewall.sentry_filter_0000000a",
                "uci delete firewall.sentry_filter_0000000a_v6in",
                "uci delete firewall.sentry_filter_0000000a_v6out",
            ]
        );
        assert_eq!(none.remove, ["0000000a"]);
        let more = delta(&one, &three[..2], "wan", svc).unwrap();
        assert_eq!(
            (more.add.as_slice(), more.keep.as_slice()),
            (&["0000000b".to_string()][..], &["0000000a".to_string()][..])
        );
        assert!(more.lines.iter().all(|l| l.contains("0000000b")));
        // A part gone (someone deleted a rule): made again whole.
        let broken = uci_of(
            &applied(&device_lines(&three[0], "wan", svc).unwrap())
                .lines()
                .filter(|l| !l.contains("_v6out"))
                .map(|l| format!("{l}\n"))
                .collect::<String>(),
        );
        let d = delta(&broken, &three[..1], "wan", svc).unwrap();
        assert_eq!(d.redo, ["0000000a"]);
        assert!(d.lines[0].starts_with("uci delete firewall.sentry_filter_0000000a"));
        assert!(d.lines.last().unwrap().contains("_v6out.target"));
    }

    #[test]
    fn only_sentrys_own_sections_are_found_and_touched() {
        let svc = service();
        let mine = applied(&device_lines(&want("0000000a", 1), "wan", svc).unwrap());
        let u = uci_of(&format!(
            "{mine}\
             firewall.sentry_filter_kids=redirect\n\
             firewall.sentry_filter_kids.name='sentry-filter-kids'\n\
             firewall.sentry_filter_0000000b=redirect\n\
             firewall.sentry_filter_0000000b.name='my own dns rule'\n\
             firewall.mine=redirect\n\
             firewall.mine.name='sentry-filter-0000000c'\n\
             firewall.sentry_filter_0000000d=rule\n\
             firewall.sentry_filter_0000000d.name='sentry-filter-0000000d'\n"
        ));
        let f = found(&u);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].tag, "0000000a");
        assert_eq!(f[0].resolver.as_deref(), Some("185.228.168.168"));
        // Taking everything off touches the three sections of sentry's and nothing else.
        let d = delta(&u, &[], "wan", svc).unwrap();
        assert_eq!(d.lines.len(), 3);
        assert!(d.lines.iter().all(|l| l.contains("sentry_filter_0000000a")));
        // None of sentry's is ever a port forward.
        assert!(
            u.forwards().iter().all(|r| !r.name.starts_with(PREFIX)),
            "{:?}",
            u.forwards()
        );
    }

    #[test]
    fn sentrys_redirect_goes_ahead_of_someones_own_dns_redirect() {
        let u = uci_of(
            "firewall.@defaults[0]=defaults\n\
             firewall.@zone[0]=zone\n\
             firewall.@zone[0].name='lan'\n\
             firewall.web=redirect\n\
             firewall.web.src='wan'\n\
             firewall.web.src_dport='443'\n\
             firewall.web.dest_ip='192.0.2.10'\n\
             firewall.dns=redirect\n\
             firewall.dns.name='Intercept-DNS'\n\
             firewall.dns.src='lan'\n\
             firewall.dns.src_dport='53'\n\
             firewall.dns.target='DNAT'\n",
        );
        let d = delta(&u, &[want("0000000a", 1)], "wan", service()).unwrap();
        assert_eq!(
            d.lines.last().unwrap(),
            "uci reorder firewall.sentry_filter_0000000a=3"
        );
        // Someone's redirect in another zone isn't in the way.
        let mut w = want("0000000a", 1);
        w.zone = "guest".into();
        let d = delta(&u, &[w], "wan", service()).unwrap();
        assert!(!d.lines.iter().any(|l| l.contains("reorder")));
    }

    #[test]
    fn a_package_that_forces_dns_comes_first_and_the_filter_refuses() {
        let c = crate::collect::counters::parse(&crate::collect::fixture("network/counters.txt"))
            .unwrap();
        assert_eq!(hijacked(&c, "lan"), ["https-dns-proxy"]);
        assert!(hijacked(&c, "guest").is_empty());
        // The DNS proxy's forcing is taken over, not refused; anyone else's is.
        assert!(refused("lan", &hijacked(&c, "lan"), &[]).is_none());
        let why = refused("lan", &["other-dns".to_string()], &[]).unwrap();
        assert!(
            why.contains("would do nothing") && why.contains("other-dns"),
            "{why}"
        );
        assert!(refused("guest", &[], &[]).is_none());
        let rs = "table inet fw4 {\n\tchain dstnat {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tudp dport 53 redirect to :53\n\t}\n}\n\
                  table inet https_dns_proxy_notrack {\n\tchain raw_output {\n\t\ttype filter hook output priority raw; policy accept;\n\t\tudp dport 53 notrack\n\t}\n}\n\
                  table ip other {\n\tchain pre {\n\t\ttype nat hook prerouting priority -110; policy accept;\n\t\tudp dport 53 dnat to 192.0.2.53\n\t}\n}\n";
        assert_eq!(foreign_tables(rs), ["ip other"]);
        assert!(refused("lan", &[], &foreign_tables(rs)).is_some());
    }

    #[test]
    fn the_takeover_is_what_the_proxy_handed_the_firewall() {
        let f = parse_forced(&crate::collect::fixture(
            "network/service-https-dns-proxy.json",
        ))
        .unwrap();
        assert_eq!(f.len(), 2, "{f:?}");
        assert_eq!(
            (f[0].kind.as_str(), f[0].dest_port.as_deref()),
            ("redirect", Some("53"))
        );
        assert_eq!(
            (f[1].kind.as_str(), f[1].dest.as_deref()),
            ("rule", Some("*"))
        );
        let l = takeover_lines("config", &f).unwrap();
        insta::assert_snapshot!("family_takeover_lines", l.join("\n"));
        let c = crate::guard::Change::parse_action(
            "firewall,https-dns-proxy",
            &l.join("; "),
            "https-dns-proxy,firewall",
            false,
        );
        assert!(c.is_ok(), "{c:?}");
        // As the router would have it after: sentry's sections found, and handed back.
        let mut text = String::from("@@firewall\n");
        for x in l.iter().filter_map(|x| x.strip_prefix("uci set firewall.")) {
            text.push_str(&format!("firewall.{x}\n"));
        }
        text.push_str(
            "firewall.sentry_dns_kids=redirect\nfirewall.sentry_dns_kids.name='sentry-dns-kids'\n",
        );
        text.push_str("@@https-dns-proxy\nhttps-dns-proxy.config=main\nhttps-dns-proxy.config.force_dns='0'\n");
        let u = uci_of_all(&text);
        assert_eq!(dns_found(&u).len(), 2, "a look-alike isn't sentry's");
        assert_eq!(proxy_forces(&u), Some(("config".into(), false)));
        assert_eq!(
            handback_lines(&u),
            [
                "uci delete firewall.sentry_dns_0",
                "uci delete firewall.sentry_dns_1",
                "uci set https-dns-proxy.config.force_dns='1'"
            ]
        );
        // What can't be copied exactly isn't.
        let mut odd = f.clone();
        odd[0].src = "lan; reboot".into();
        assert!(takeover_lines("config", &odd).is_err());
        assert!(takeover_lines("config", &[]).is_err());
    }

    #[test]
    fn precedence_is_read_back_from_the_chains() {
        let nat = |rules: &[&str]| {
            format!(
                "table inet fw4 {{\n\tchain dstnat_lan {{\n{}\n\t}}\n}}\n@@forward\n\t\ttcp dport 853 counter jump handle_reject comment \"!fw4: sentry-dns-1\"\n",
                rules.join("\n")
            )
        };
        let filt = "\t\tmeta nfproto ipv4 udp dport 53 ether saddr 02:00:5e:00:53:31 counter dnat ip to 185.228.168.168:53 comment \"!fw4: sentry-filter-0000000a\"";
        let catch = "\t\tudp dport 53 counter redirect to :53 comment \"!fw4: sentry-dns-0\"";
        let theirs = "\t\tudp dport 53 counter redirect to :53 comment \"!fw4: ubus:https-dns-proxy[instance1] redirect 0\"";
        assert!(precedence("lan", &nat(&[filt, catch]), 1).is_ok());
        assert!(
            precedence("lan", &nat(&[catch, filt]), 1)
                .unwrap_err()
                .contains("after the catch-all")
        );
        assert!(
            precedence("lan", &nat(&[theirs, filt, catch]), 1)
                .unwrap_err()
                .contains("still first")
        );
        assert!(
            precedence("lan", &nat(&[filt]), 1)
                .unwrap_err()
                .contains("catch-all")
        );
        assert!(
            precedence("lan", &nat(&[filt, catch]), 2)
                .unwrap_err()
                .contains("853")
        );
    }

    fn uci_of_all(text: &str) -> Uci {
        crate::collect::uci::parse(text, &Salt::fixed([7; 16]))
    }

    #[test]
    fn what_nslookup_says() {
        let ok = "Server:\t\t185.228.168.168\nAddress:\t185.228.168.168:53\n\n\
                  Non-authoritative answer:\nName:\topenwrt.org\nAddress: 198.51.100.7\n\n\
                  Non-authoritative answer:\nName:\topenwrt.org\nAddress: 2001:db8::7\n";
        assert_eq!(answered(ok), ["198.51.100.7", "2001:db8::7"]);
        assert!(!blocked(ok));
        let no = "Server:\t\t185.228.168.168\nAddress:\t185.228.168.168:53\n\n\
                  ** server can't find pornhub.com: NXDOMAIN\n\n\
                  ** server can't find pornhub.com: NXDOMAIN\n";
        assert!(answered(no).is_empty() && blocked(no));
        assert!(blocked("Name:\tx\nAddress: 0.0.0.0\n"));
        assert!(!blocked(
            ";; connection timed out; no servers could be reached\n"
        ));
    }
}

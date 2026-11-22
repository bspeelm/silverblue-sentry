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
//! redirect is ever looked at. On such a zone the filter **refuses** ([`hijacked`]), with
//! a plain explanation, instead of making a change that does nothing. A redirect of the
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

/// What is wrong with filtering a device in this zone, said plainly (None: nothing).
pub fn refused(zone: &str, hijack: &[String], tables: &[String]) -> Option<String> {
    if !hijack.is_empty() {
        return Some(format!(
            "the router already sends every name lookup from {} to itself ({}'s \"force \
             DNS\"), and the firewall puts that program's rule before any rule sentry can \
             add: a filter set up now would do nothing there. Switching that program's \
             \"force DNS\" off is a change sentry doesn't make by itself yet",
            super::attention::side(zone),
            hijack.join(", ")
        ));
    }
    if !tables.is_empty() {
        return Some(format!(
            "another firewall table ({}) redirects name lookups itself, and which of it and \
             the router's own firewall comes first isn't something sentry can tell from the \
             settings",
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
    let have = found(uci);
    let mut d = Delta::default();
    let wanted: BTreeSet<&str> = want.iter().map(|w| w.tag.as_str()).collect();
    let mut deleted: BTreeSet<String> = BTreeSet::new();
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
        let why = refused("lan", &hijacked(&c, "lan"), &[]).unwrap();
        assert!(
            why.contains("would do nothing") && why.contains("https-dns-proxy"),
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

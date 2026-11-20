//! `sentry-network init <ssh-host>`: read what the router reports (read-only: `ubus`, `uci
//! show firewall`, the DHCP leases) and draft `network_config.yaml` from it: its ports as a
//! note, the firewall's zones and port forwards as what's expected, and every device holding
//! a lease as a device still to be named. The draft is pure ([`draft`]); nothing is written on
//! the router.

use std::collections::BTreeMap;

use crate::collect::ifaces::{self, Ifaces};
use crate::collect::{CollectError, sections};
use crate::config;
use crate::rates;
use crate::remote::Router;

/// One `uci` section: its name (`@zone[0]`, `web_https`), its type and its options.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Section {
    pub name: String,
    pub kind: String,
    pub opts: BTreeMap<String, Vec<String>>,
}

impl Section {
    fn one(&self, k: &str) -> Option<&str> {
        self.opts.get(k)?.first().map(String::as_str)
    }
    fn list(&self, k: &str) -> Vec<String> {
        // A list written as one option holds its words.
        self.opts.get(k).map_or(Vec::new(), |v| {
            v.iter()
                .flat_map(|x| x.split_whitespace().map(str::to_string))
                .collect()
        })
    }
}

/// The quoted values after `=`: `'wan' 'wan6'` (a list) or `'it'\''s'` (one, with a quote).
fn values(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                quoted = !quoted;
                any = true;
            }
            '\\' if !quoted => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// `uci show <config>`: `pkg.section=type`, then `pkg.section.option='value'`.
pub fn uci(text: &str) -> Vec<Section> {
    let mut out: Vec<Section> = Vec::new();
    for line in text.lines() {
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let mut parts = key.splitn(3, '.');
        let (Some(_pkg), Some(section)) = (parts.next(), parts.next()) else {
            continue;
        };
        match parts.next() {
            None => out.push(Section {
                name: section.to_string(),
                kind: values(val).into_iter().next().unwrap_or_default(),
                opts: BTreeMap::new(),
            }),
            Some(opt) => {
                if let Some(s) = out.iter_mut().rev().find(|s| s.name == section) {
                    s.opts.insert(opt.to_string(), values(val));
                }
            }
        }
    }
    out
}

/// A dnsmasq lease: `<expiry> <mac> <address> <hostname or *> <client id or *>`.
#[derive(Debug, Clone, PartialEq)]
pub struct Lease {
    pub mac: String,
    pub addr: String,
    pub hostname: Option<String>,
}

pub fn leases(text: &str) -> Vec<Lease> {
    text.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            Some(Lease {
                mac: config::mac(w.get(1)?)?,
                addr: w.get(2)?.to_string(),
                hostname: w.get(3).filter(|h| **h != "*").map(|h| h.to_string()),
            })
        })
        .collect()
}

/// What the router reported.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub ifaces: Ifaces,
    pub firewall: Vec<Section>,
    pub leases: Vec<Lease>,
}

const SCRIPT_MORE: &str = "; echo @@firewall; uci show firewall; \
     echo @@leases; cat /tmp/dhcp.leases 2>/dev/null; true";

pub fn discover(r: &Router) -> Result<Facts, CollectError> {
    let script = format!("{}{SCRIPT_MORE}", ifaces::SCRIPT);
    let text = super::collect::output_needing(r, "ubus", &script)?;
    parse(&text).map_err(CollectError::Parse)
}

pub fn parse(text: &str) -> Result<Facts, String> {
    let mut f = Facts {
        ifaces: ifaces::parse(text)?,
        ..Default::default()
    };
    for (name, body) in sections(text) {
        match name {
            "firewall" => f.firewall = uci(body),
            "leases" => f.leases = leases(body),
            _ => {}
        }
    }
    Ok(f)
}

/// A YAML scalar: bare when it's plainly safe, else double-quoted.
fn y(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-/".contains(c))
        && !s.starts_with('-')
        && s.parse::<f64>().is_err()
        && !matches!(
            s.to_ascii_lowercase().as_str(),
            "true" | "false" | "yes" | "no" | "on" | "off" | "null" | "~"
        );
    if plain {
        s.to_string()
    } else {
        serde_json::Value::String(s.to_string()).to_string()
    }
}

/// The firewall's port forwards as `expect.forwards` entries; what can't be one, as notes.
fn forwards(fw: &[Section]) -> (Vec<String>, Vec<String>) {
    let (mut out, mut notes) = (Vec::new(), Vec::new());
    for s in fw.iter().filter(|s| s.kind == "redirect") {
        let name = s.one("name").unwrap_or(&s.name);
        if s.one("target").is_some_and(|t| t != "DNAT") || s.one("enabled") == Some("0") {
            continue;
        }
        let proto = match s.list("proto").as_slice() {
            [p] if p == "tcp" || p == "udp" => p.clone(),
            [] => "any".to_string(),
            l if l.iter().all(|p| p == "tcp" || p == "udp") => "any".to_string(),
            [p] if p == "tcpudp" || p == "all" || p == "any" => "any".to_string(),
            other => {
                notes.push(format!("forward {name}: proto {}", other.join(" ")));
                continue;
            }
        };
        let port = s
            .one("src_dport")
            .map(|p| p.replace(':', "-"))
            .and_then(|p| p.parse::<config::Ports>().ok());
        match (port, s.one("dest_ip")) {
            (Some(port), Some(to)) => {
                let port = match port.to_string() {
                    p if port.from == port.to => p,
                    p => format!("\"{p}\""),
                };
                out.push(format!(
                    "{{ name: {}, proto: {proto}, port: {port}, to: {} }}",
                    y(name),
                    y(to)
                ));
            }
            _ => notes.push(format!("forward {name}: no port or no address to go to")),
        }
    }
    (out, notes)
}

/// The draft of the whole file, for a router that isn't configured yet.
pub fn draft(name: &str, ssh: &str, f: &Facts, today: &str) -> String {
    let i = &f.ifaces;
    let b = &i.board;
    let mut o = String::new();
    let mut line = |s: String| {
        o.push_str(&s);
        o.push('\n');
    };
    line(format!(
        "# sentry-network configuration, drafted by `sentry-network init` on {today} from what the"
    ));
    line(
        "# router reports. Check it, name your devices, then run `sentry-network lint`. sentry never"
            .into(),
    );
    line(
        "# rewrites this file. Every key: assets/network_config.example.yaml in sentry's source."
            .into(),
    );
    line(String::new());
    line("networks:".into());
    line(format!("  {}:", y(name)));
    line(format!(
        "    # {} · {} {} · {}",
        b.model, b.distribution, b.version, b.target
    ));
    line(format!("    router: {{ ssh: {}, kind: openwrt }}", y(ssh)));
    line(String::new());
    let ports: Vec<String> = i
        .rows()
        .iter()
        .map(|d| {
            let net = i
                .net_of(&d.name)
                .map_or(String::new(), |n| format!(" ({n})"));
            let link = match (d.carrier, d.speed) {
                (false, _) => " no link".to_string(),
                (true, Some(m)) => format!(" {}", rates::speed(m)),
                (true, None) => String::new(),
            };
            format!("{}{net}{link}", d.name)
        })
        .collect();
    if !ports.is_empty() {
        line("    # Its ports and radios now:".into());
        for chunk in ports.chunks(4) {
            line(format!("    #   {}", chunk.join(" · ")));
        }
        line(String::new());
    }
    line("    # What the firewall looks like now, taken as what's expected.".into());
    line("    expect:".into());
    let zones: Vec<(String, Vec<String>)> = f
        .firewall
        .iter()
        .filter(|s| s.kind == "zone")
        .filter_map(|s| {
            let mut ifs = s.list("network");
            ifs.extend(s.list("device"));
            Some((s.one("name")?.to_string(), ifs)).filter(|(_, ifs)| !ifs.is_empty())
        })
        .collect();
    if zones.is_empty() {
        line("      zones: {}".into());
    } else {
        line("      # Each zone and the interfaces in it.".into());
        line("      zones:".into());
        for (zone, ifs) in &zones {
            let ifs: Vec<String> = ifs.iter().map(|x| y(x)).collect();
            line(format!("        {}: [{}]", y(zone), ifs.join(", ")));
        }
    }
    let (fwd, notes) = forwards(&f.firewall);
    if fwd.is_empty() {
        line("      forwards: []".into());
    } else {
        line("      forwards:".into());
        for x in &fwd {
            line(format!("        - {x}"));
        }
    }
    for n in &notes {
        line(format!("      # not taken: {n}"));
    }
    line("      # What may listen on the router itself, proto:port@zone (tcp:22@lan).".into());
    line("      listeners: []".into());
    line(String::new());
    // Known by MAC; one with a private (randomised) MAC by the hostname it gives.
    let mut entries: Vec<String> = Vec::new();
    let mut nameless = 0;
    let mut seen = std::collections::HashSet::new();
    for l in &f.leases {
        let private = config::local_mac(&l.mac);
        match (&l.hostname, private) {
            (Some(h), true) => {
                if seen.insert(h.clone()) {
                    entries.push(format!(
                        "- {{ hostname: {}, private_mac: true }}   # {}",
                        y(h),
                        l.addr
                    ));
                }
            }
            (None, true) => nameless += 1,
            (h, false) => {
                if seen.insert(l.mac.clone()) {
                    let host = h
                        .as_ref()
                        .map_or(String::new(), |h| format!(", hostname: {}", y(h)));
                    entries.push(format!("- {{ mac: \"{}\"{host} }}   # {}", l.mac, l.addr));
                }
            }
        }
    }
    line(
        "    # Every device holding a lease now. Give the ones you know a `name:` and delete the"
            .into(),
    );
    line(
        "    # rest. `private_mac`: its MAC is locally administered, as a phone's private address"
            .into(),
    );
    line(
        "    # is, so it's known by its hostname (give `mac:` instead if its MAC never changes)."
            .into(),
    );
    if entries.is_empty() {
        line("    devices: []".into());
    } else {
        line("    devices:".into());
        for e in &entries {
            line(format!("      {e}"));
        }
    }
    if nameless > 0 {
        line(format!(
            "    # (not listed: {nameless} with a private MAC and no hostname)"
        ));
    }
    line(String::new());
    line("    thresholds: { load: 2.0, mem_pct: 85, cert_days: 21, backup_age: 30d }".into());
    line(String::new());
    line(
        "    # Config backups are encrypted with `age` on this machine. Put a public recipient"
            .into(),
    );
    line(
        "    # here (an age1… key, an ssh public key, or a file holding one) to have them.".into(),
    );
    line("    backup: { recipients: [], keep: 12 }".into());
    line(String::new());
    line("    maintenance:".into());
    line("      items:".into());
    line("        - { id: firmware, kind: firmware }".into());
    line("        - { id: packages, kind: packages }".into());
    line("        - { id: backup,   kind: backup }".into());
    line("      cadence: []".into());
    line(String::new());
    line("    notes: []".into());
    line("    claude: { share_wan_address: false }".into());
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIREWALL: &str = "\
firewall.@defaults[0]=defaults
firewall.@defaults[0].input='REJECT'
firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].network='lan'
firewall.@zone[0].input='ACCEPT'
firewall.@zone[1]=zone
firewall.@zone[1].name='wan'
firewall.@zone[1].network='wan' 'wan6'
firewall.@zone[1].masq='1'
firewall.@forwarding[0]=forwarding
firewall.@forwarding[0].src='lan'
firewall.@forwarding[0].dest='wan'
firewall.web_https=redirect
firewall.web_https.name='web-https'
firewall.web_https.target='DNAT'
firewall.web_https.src='wan'
firewall.web_https.proto='tcp'
firewall.web_https.src_dport='443'
firewall.web_https.dest_ip='203.0.113.10'
firewall.web_https.dest_port='443'
firewall.@redirect[0]=redirect
firewall.@redirect[0].name='game it'\\''s'
firewall.@redirect[0].proto='tcp' 'udp'
firewall.@redirect[0].src_dport='8000-8010'
firewall.@redirect[0].dest_ip='192.0.2.20'
firewall.@redirect[1]=redirect
firewall.@redirect[1].name='off'
firewall.@redirect[1].enabled='0'
firewall.@redirect[1].src_dport='22'
firewall.@redirect[1].dest_ip='192.0.2.5'
firewall.@redirect[2]=redirect
firewall.@redirect[2].name='half'
firewall.@redirect[2].proto='tcp'
firewall.@zone[2]=zone
firewall.@zone[2].name='dmz'
firewall.@zone[2].network='dmz'
";

    const LEASES: &str = "\
1793003600 00:00:5e:00:53:10 192.0.2.10 nas 01:00:00:5e:00:53:10
1793003700 00:00:5e:00:53:11 192.0.2.11 * *
1793003800 02:00:5e:00:53:20 192.0.2.20 my-phone 01:02:00:5e:00:53:20
1793003900 02:00:5e:00:53:21 192.0.2.21 my-phone *
1793004000 02:00:5e:00:53:22 192.0.2.22 * *
not a lease
";

    fn facts() -> Facts {
        let text = format!(
            "{}@@firewall\n{FIREWALL}@@leases\n{LEASES}",
            crate::collect::fixture("network/ifaces.txt")
        );
        parse(&text).unwrap()
    }

    #[test]
    fn uci_sections_options_and_lists() {
        let fw = uci(FIREWALL);
        let kinds: Vec<&str> = fw.iter().map(|s| s.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "defaults",
                "zone",
                "zone",
                "forwarding",
                "redirect",
                "redirect",
                "redirect",
                "redirect",
                "zone"
            ]
        );
        assert_eq!(fw[2].one("name"), Some("wan"));
        assert_eq!(fw[2].list("network"), ["wan", "wan6"]);
        assert_eq!(fw[4].name, "web_https");
        // A quote inside a value, as uci writes it.
        assert_eq!(fw[5].one("name"), Some("game it's"));
        assert_eq!(values("'a b' 'c'"), ["a b", "c"]);
        assert_eq!(values("''"), [""]);
    }

    #[test]
    fn leases_by_mac_with_the_hostname_given() {
        let l = leases(LEASES);
        assert_eq!(l.len(), 5);
        assert_eq!(l[0].hostname.as_deref(), Some("nas"));
        assert_eq!(l[1].hostname, None);
        assert_eq!(
            (l[2].mac.as_str(), l[2].addr.as_str()),
            ("02:00:5e:00:53:20", "192.0.2.20")
        );
    }

    #[test]
    fn the_draft_is_a_config_that_parses_and_lints_clean() {
        let f = facts();
        let text = draft("home", "myrouter", &f, "2026-11-20");
        let (file, warnings) = config::parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        assert!(warnings.is_empty(), "{warnings:?}");
        let n = &file.networks["home"];
        assert!(
            config::lint("home", n).is_empty(),
            "{:?}",
            config::lint("home", n)
        );
        assert_eq!(n.ssh_target("home"), "myrouter");
        // Zones and forwards as the firewall has them.
        assert_eq!(n.expect.zones["wan"], ["wan", "wan6"]);
        assert_eq!(n.expect.zones.len(), 3);
        let fw: Vec<(String, String, String, String)> = n
            .expect
            .forwards
            .iter()
            .map(|x| {
                (
                    x.name.clone(),
                    x.proto.clone(),
                    x.port.to_string(),
                    x.to.clone(),
                )
            })
            .collect();
        assert_eq!(
            fw,
            [
                (
                    "web-https".into(),
                    "tcp".into(),
                    "443".into(),
                    "203.0.113.10".into()
                ),
                (
                    "game it's".into(),
                    "any".into(),
                    "8000-8010".into(),
                    "192.0.2.20".into()
                ),
            ]
        );
        assert!(
            text.contains("# not taken: forward half: no port or no address"),
            "{text}"
        );
        assert!(
            !text.contains("name: off"),
            "a disabled forward isn't expected"
        );
        // The leases, unnamed: by MAC, or by hostname when the MAC is a private one.
        assert!(n.devices.iter().all(|d| d.name.is_none()));
        let by_mac: Vec<&str> = n.devices.iter().filter_map(|d| d.mac.as_deref()).collect();
        assert_eq!(by_mac, ["00:00:5e:00:53:10", "00:00:5e:00:53:11"]);
        let private: Vec<&str> = n
            .devices
            .iter()
            .filter(|d| d.private_mac)
            .filter_map(|d| d.hostname.as_deref())
            .collect();
        assert_eq!(private, ["my-phone"], "once, though it holds two leases");
        assert!(text.contains("(not listed: 1 with a private MAC and no hostname)"));
        // The ports are a note: the file has no key for them.
        assert!(
            text.contains(
                "#   eth1 (wan) 1G · lan1 (lan) 1G · lan2 (lan) 100M · lan3 (lan) no link"
            )
        );
        assert!(text.contains("# Example Router AX · OpenWrt 25.12.3 · mediatek/filogic"));
        assert_eq!(n.maintenance.items.len(), 3);
    }

    #[test]
    fn a_router_with_nothing_set_up_still_drafts_a_valid_file() {
        let f = parse("@@board\n{\"model\": \"X\"}\n@@firewall\n@@leases\n").unwrap();
        let text = draft("lab net", "root@192.0.2.1", &f, "2026-11-20");
        let (file, _) = config::parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        let n = &file.networks["lab net"];
        assert_eq!(n.ssh_target("x"), "root@192.0.2.1");
        assert!(n.expect.zones.is_empty() && n.devices.is_empty());
        assert_eq!(y("on"), "\"on\"");
        assert_eq!(y("443"), "\"443\"");
        assert_eq!(y("web-1"), "web-1");
    }
}

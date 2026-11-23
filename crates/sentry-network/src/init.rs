//! `sentry-network init <ssh-host>`: read what the router reports (read-only: `ubus`, `uci
//! show firewall`, the DHCP leases) and draft a network's entry for `network_config.yaml`
//! from it: the firewall's zones and port forwards as what's expected, and every device
//! holding a lease as a device still to be named; its board and ports as notes. The draft is
//! pure and typed ([`draft`]: the entry and its notes); `cfg` writes it. Nothing is written
//! on the router.

use crate::collect::clients::{Lease, leases};
use crate::collect::ifaces::{self, Ifaces};
use crate::collect::uci::{Section, show as uci};
use crate::collect::{CollectError, sections};
use crate::config;
use crate::rates;
use crate::remote::Router;
use sentry_core::cfg::{Draft, Note, Saved, Seg, path_string};

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

/// The path of one of the entry's settings: `networks.<name>.<field>`.
fn at(name: &str, field: &str) -> String {
    format!(
        "{}.{field}",
        path_string(&[Seg::Key("networks".into()), Seg::Key(name.into())])
    )
}

/// The firewall's port forwards as `expect.forwards` entries; what can't be one, as notes.
fn forwards(fw: &[Section]) -> (Vec<config::Forward>, Vec<String>) {
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
            (Some(port), Some(to)) => out.push(config::Forward {
                name: name.to_string(),
                proto,
                port,
                to: to.to_string(),
            }),
            _ => notes.push(format!("forward {name}: no port or no address to go to")),
        }
    }
    (out, notes)
}

/// The entry for a router that isn't configured yet, and notes on what it was drafted from
/// (what the drafted text's comments used to say), each at the setting it is about.
pub fn draft(name: &str, ssh: &str, f: &Facts) -> Draft<config::Network> {
    let i = &f.ifaces;
    let b = &i.board;
    let mut n = config::Network::default();
    let mut notes = vec![Note::on(
        &at(name, "router"),
        format!(
            "{} · {} {} · {}",
            b.model, b.distribution, b.version, b.target
        ),
    )];
    n.router.ssh = Some(ssh.to_string());
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
        notes.push(Note::on(
            &at(name, "router"),
            format!("its ports and radios now: {}", ports.join(" · ")),
        ));
    }
    notes.push(Note::on(
        &at(name, "expect"),
        "what the firewall looks like now, taken as what's expected.",
    ));
    n.expect.zones = f
        .firewall
        .iter()
        .filter(|s| s.kind == "zone")
        .filter_map(|s| {
            let mut ifs = s.list("network");
            ifs.extend(s.list("device"));
            Some((s.one("name")?.to_string(), ifs)).filter(|(_, ifs)| !ifs.is_empty())
        })
        .collect();
    let (fwd, not_taken) = forwards(&f.firewall);
    n.expect.forwards = fwd;
    for x in not_taken {
        notes.push(Note::on(
            &at(name, "expect.forwards"),
            format!("not taken: {x}"),
        ));
    }
    // Known by MAC; one with a private (randomised) MAC by the hostname it gives.
    let mut nameless = 0;
    let mut seen = std::collections::HashSet::new();
    for l in &f.leases {
        let private = config::local_mac(&l.mac);
        let device = match (&l.hostname, private) {
            (Some(h), true) if seen.insert(h.clone()) => config::Device {
                hostname: Some(h.clone()),
                private_mac: true,
                ..Default::default()
            },
            (None, true) => {
                nameless += 1;
                continue;
            }
            (h, false) if seen.insert(l.mac.clone()) => config::Device {
                mac: Some(l.mac.clone()),
                hostname: h.clone(),
                ..Default::default()
            },
            _ => continue,
        };
        notes.push(Note::on(
            &format!("{}[{}]", at(name, "devices"), n.devices.len()),
            format!("holds {} now", l.addr),
        ));
        n.devices.push(device);
    }
    notes.push(Note::on(
        &at(name, "devices"),
        "every device holding a lease now. Give the ones you know a `name:` and delete the \
         rest. `private_mac`: its MAC is locally administered, as a phone's private address \
         is, so it's known by its hostname (give `mac:` instead if its MAC never changes).",
    ));
    if nameless > 0 {
        notes.push(Note::on(
            &at(name, "devices"),
            format!("not listed: {nameless} with a private MAC and no hostname"),
        ));
    }
    notes.push(Note::on(
        &at(name, "backup.recipients"),
        "config backups are encrypted on this machine. Put a public recipient here (an age1… \
         key; `sentry-network backup key <file>` makes one) to have them.",
    ));
    n.maintenance.items = [
        ("firmware", config::ItemKind::Firmware),
        ("packages", config::ItemKind::Packages),
        ("backup", config::ItemKind::Backup),
    ]
    .into_iter()
    .map(|(id, kind)| config::Item {
        id: id.into(),
        kind,
    })
    .collect();
    Draft { entry: n, notes }
}

/// Add `entry` as `name` to the file at `path` (made when it isn't there), through `cfg`: the
/// whole file is written again from what it says, a copy of it before kept. A name the file
/// has, or a file that doesn't parse, writes nothing.
pub fn write(path: &std::path::Path, name: &str, entry: &config::Network) -> Result<Saved, String> {
    sentry_core::cfg::update::<config::NetworkFile>(path, |f| {
        if f.networks.contains_key(name) {
            return Err(format!(
                "{} already has `{name}`: not touching it (--name adds it under another name).",
                path.display()
            ));
        }
        f.networks.insert(name.to_string(), entry.clone());
        Ok(())
    })
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

    /// What the text draft (before the typed one) wrote for the same facts, word for word.
    const OLD_HOME: &str = r#"# sentry-network configuration, drafted by `sentry-network init` on 2026-11-20 from what the
# router reports. Check it, name your devices, then run `sentry-network lint`. sentry never
# rewrites this file. Every key: assets/network_config.example.yaml in sentry's source.

networks:
  home:
    # Example Router AX · OpenWrt 25.12.3 · mediatek/filogic
    router: { ssh: myrouter, kind: openwrt }

    # Its ports and radios now:
    #   eth1 (wan) 1G · lan1 (lan) 1G · lan2 (lan) 100M · lan3 (lan) no link
    #   lan4 (dmz) 1G · phy0-ap0 (lan) · phy1-ap0 (lan)

    # What the firewall looks like now, taken as what's expected.
    expect:
      # Each zone and the interfaces in it.
      zones:
        lan: [lan]
        wan: [wan, wan6]
        dmz: [dmz]
      forwards:
        - { name: web-https, proto: tcp, port: 443, to: 203.0.113.10 }
        - { name: "game it's", proto: any, port: "8000-8010", to: 192.0.2.20 }
      # not taken: forward half: no port or no address to go to
      # What may listen on the router itself, proto:port@zone (tcp:22@lan).
      listeners: []

    # Every device holding a lease now. Give the ones you know a `name:` and delete the
    # rest. `private_mac`: its MAC is locally administered, as a phone's private address
    # is, so it's known by its hostname (give `mac:` instead if its MAC never changes).
    devices:
      - { mac: "00:00:5e:00:53:10", hostname: nas }   # 192.0.2.10
      - { mac: "00:00:5e:00:53:11" }   # 192.0.2.11
      - { hostname: my-phone, private_mac: true }   # 192.0.2.20
    # (not listed: 1 with a private MAC and no hostname)

    thresholds: { load: 2.0, mem_pct: 85, cert_days: 21, backup_age: 30d }

    # Config backups are encrypted on this machine. Put a public recipient here
    # (an age1… key; `sentry-network backup key <file>` makes one) to have them.
    backup: { recipients: [], keep: 12 }

    maintenance:
      items:
        - { id: firmware, kind: firmware }
        - { id: packages, kind: packages }
        - { id: backup,   kind: backup }
      cadence: []

    notes: []
    claude: { share_wan_address: false }
"#;

    const OLD_LAB: &str = r#"# sentry-network configuration, drafted by `sentry-network init` on 2026-11-20 from what the
# router reports. Check it, name your devices, then run `sentry-network lint`. sentry never
# rewrites this file. Every key: assets/network_config.example.yaml in sentry's source.

networks:
  "lab net":
    router: { ssh: "root@192.0.2.1", kind: openwrt }

    # What the firewall looks like now, taken as what's expected.
    expect:
      zones: {}
      forwards: []
      # What may listen on the router itself, proto:port@zone (tcp:22@lan).
      listeners: []

    # Every device holding a lease now. Give the ones you know a `name:` and delete the
    # rest. `private_mac`: its MAC is locally administered, as a phone's private address
    # is, so it's known by its hostname (give `mac:` instead if its MAC never changes).
    devices: []

    thresholds: { load: 2.0, mem_pct: 85, cert_days: 21, backup_age: 30d }

    # Config backups are encrypted on this machine. Put a public recipient here
    # (an age1… key; `sentry-network backup key <file>` makes one) to have them.
    backup: { recipients: [], keep: 12 }

    maintenance:
      items:
        - { id: firmware, kind: firmware }
        - { id: packages, kind: packages }
        - { id: backup,   kind: backup }
      cadence: []

    notes: []
    claude: { share_wan_address: false }
"#;

    fn written(name: &str, d: &Draft<config::Network>) -> String {
        let file = config::NetworkFile {
            networks: [(name.to_string(), d.entry.clone())].into(),
        };
        sentry_core::cfg::render(&file).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn the_draft_is_a_config_that_parses_and_lints_clean() {
        let f = facts();
        let d = draft("home", "myrouter", &f);
        let text = written("home", &d);
        let (file, warnings) = config::parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        assert!(warnings.is_empty(), "{warnings:?}");
        let n = &file.networks["home"];
        assert_eq!(n, &d.entry);
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
        let notes = d.note_lines();
        let has = |s: &str| notes.iter().any(|n| n.contains(s));
        assert!(
            has("networks.home.expect.forwards: not taken: forward half: no port or no address"),
            "{notes:#?}"
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
        assert!(has(
            "networks.home.devices: not listed: 1 with a private MAC and no hostname"
        ));
        assert!(
            has("networks.home.devices[2]: holds 192.0.2.20 now"),
            "{notes:#?}"
        );
        // The ports and the board are notes: the file has no key for them.
        assert!(has(
            "networks.home.router: its ports and radios now: eth1 (wan) 1G · lan1 (lan) 1G · lan2 (lan) 100M · lan3 (lan) no link"
        ));
        assert!(has(
            "networks.home.router: Example Router AX · OpenWrt 25.12.3 · mediatek/filogic"
        ));
        assert_eq!(n.maintenance.items.len(), 3);
        insta::assert_snapshot!(format!("{text}\n{}", notes.join("\n")));
    }

    /// The typed draft proposes exactly what the text draft did: the same zones, forwards,
    /// devices and items.
    #[test]
    fn the_typed_draft_is_what_the_text_draft_was() {
        let d = draft("home", "myrouter", &facts());
        let (old, _) = config::parse(OLD_HOME).unwrap();
        assert_eq!(old.networks["home"], d.entry);
        let f = parse("@@board\n{\"model\": \"X\"}\n@@firewall\n@@leases\n").unwrap();
        let d = draft("lab net", "root@192.0.2.1", &f);
        let (old, _) = config::parse(OLD_LAB).unwrap();
        assert_eq!(old.networks["lab net"], d.entry);
    }

    #[test]
    fn a_router_with_nothing_set_up_still_drafts_a_valid_file() {
        let f = parse("@@board\n{\"model\": \"X\"}\n@@firewall\n@@leases\n").unwrap();
        let d = draft("lab net", "root@192.0.2.1", &f);
        let text = written("lab net", &d);
        let (file, _) = config::parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        let n = &file.networks["lab net"];
        assert_eq!(n.ssh_target("x"), "root@192.0.2.1");
        assert!(n.expect.zones.is_empty() && n.devices.is_empty());
        // Names a YAML file has to quote come back as they were.
        let mut odd = d.entry.clone();
        odd.expect.forwards.push(config::Forward {
            name: "on".into(),
            proto: "tcp".into(),
            port: "443".parse().unwrap(),
            to: "192.0.2.5".into(),
        });
        odd.devices.push(config::Device {
            hostname: Some("443".into()),
            private_mac: true,
            ..Default::default()
        });
        let file = config::NetworkFile {
            networks: [("lab net".to_string(), odd.clone())].into(),
        };
        let text = sentry_core::cfg::render(&file).unwrap();
        assert_eq!(config::parse(&text).unwrap().0.networks["lab net"], odd);
    }

    /// A second network is added to a file that has one (the old init could only write a
    /// whole new file); a name that's there is refused.
    #[test]
    fn a_network_is_added_beside_the_ones_there() {
        let dir = sentry_core::paths::config_dir().join("init-write");
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("network_config.yaml");
        let d = draft("home", "myrouter", &facts());
        assert_eq!(write(&p, "home", &d.entry).unwrap().backup, None);
        let before = std::fs::read_to_string(&p).unwrap();
        assert!(
            write(&p, "home", &d.entry)
                .unwrap_err()
                .contains("already has `home`")
        );
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before);
        let saved = write(&p, "lab", &d.entry).unwrap();
        assert!(
            saved.backup.is_some() && !saved.handwritten,
            "sentry wrote it"
        );
        let (f, w) = config::parse(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert!(w.is_empty());
        assert_eq!(f.networks.keys().collect::<Vec<_>>(), ["home", "lab"]);
        for (n, net) in &f.networks {
            assert!(
                config::lint(n, net).is_empty(),
                "{:?}",
                config::lint(n, net)
            );
        }
    }
}

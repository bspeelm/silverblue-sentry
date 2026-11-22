//! What a network says to the security audit (`sentry audit security`, core `secaudit`):
//! the audit's own snapshot plus the packages, the firmware's standing and the DNS filter,
//! turned into facts. Nothing of the router's that is private goes into words here: no
//! address, MAC, hostname or network name. The addresses the audit only matches on (where
//! a forward goes, the uplink's) are fields core never serializes.

use std::net::IpAddr;

use jiff::Timestamp;
use sentry_core::secaudit::{
    Backup, Crossing, Devices, DnsFilter, Eol, Firmware, Forward, Kind, Packages, Router as Facts,
    TargetFacts, WanListen, Watch, Wifi, Zone,
};

use crate::audit::{Exposure, Snapshot};
use crate::collect::dnsstate::DnsState;
use crate::collect::uci::Uci;
use crate::collect::updates::Updates;
use crate::maint::eval::{self, EolState};
use crate::remote::Router;
use crate::security::{End, Nets};

/// The target's id in the audit.
pub fn id(name: &str) -> String {
    format!("net:{name}")
}

/// What was read besides the audit's snapshot.
#[derive(Default)]
pub struct Extra<'a> {
    pub updates: Option<&'a Updates>,
    pub firmware: Option<eval::Firmware>,
    /// None: not read. `Some(None)`-like absence is a `DnsState` without a blocklist.
    pub dns: Option<&'a DnsState>,
}

fn eol(s: EolState) -> Eol {
    match s {
        EolState::Unknown => Eol::Unknown,
        EolState::Supported => Eol::Supported,
        EolState::Soon(d) => Eol::Soon(d),
        EolState::Past(d) => Eol::Past(d),
    }
}

fn public4(a: &str) -> Option<String> {
    let ip = a.split('/').next()?.parse::<std::net::Ipv4Addr>().ok()?;
    // (Carrier-grade NAT, 100.64/10, isn't reachable from outside either.)
    let cgnat = ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64;
    (!ip.is_private() && !ip.is_loopback() && !ip.is_link_local() && !cgnat).then(|| ip.to_string())
}

/// The rules that let the uplink's side open connections to devices inside: `ACCEPT`,
/// from an uplink zone, with a destination zone. Not ICMP (IPv6 needs it), and not what
/// every OpenWrt ships for IPsec passthrough.
fn inbound(uci: &Uci, wan: &[String]) -> Vec<String> {
    uci.config("firewall")
        .iter()
        .filter(|s| s.kind == "rule" && s.flag("enabled", true))
        .filter(|s| {
            s.one("target")
                .is_some_and(|t| t.eq_ignore_ascii_case("ACCEPT"))
        })
        .filter(|s| s.one("src").is_some_and(|z| wan.iter().any(|w| w == z)))
        .filter_map(|s| {
            let dest = s.one("dest")?;
            let protos = s.list("proto");
            let ports = s.list("dest_port");
            let icmp = !protos.is_empty() && protos.iter().all(|p| p.starts_with("icmp"));
            let ipsec = protos.iter().all(|p| p == "esp") && !protos.is_empty()
                || (protos.iter().all(|p| p == "udp") && ports.iter().all(|p| p == "500"))
                    && !ports.is_empty();
            if icmp || ipsec {
                return None;
            }
            let proto = if protos.is_empty() {
                "tcp and udp".to_string()
            } else {
                protos.join(" and ")
            };
            let port = if ports.is_empty() {
                "any port".to_string()
            } else {
                format!("port {}", ports.join(" "))
            };
            Some(format!("{proto} {port} to the {dest} network"))
        })
        .collect()
}

/// Pure: the facts of one snapshot.
pub fn facts(name: &str, s: &Snapshot, x: &Extra, now: Timestamp) -> TargetFacts {
    let mut t = TargetFacts::new(&id(name), Kind::Network, name);
    t.errors = s.errors.clone();
    let ex = Exposure::of(s);
    let nets = s.ifaces.as_ref().map(|i| Nets::new(i, s.uci.as_ref()));
    let mut r = Facts::default();

    if let Some(i) = &s.ifaces {
        let wan = i.wan();
        r.wan_up = wan.map(|w| w.up);
        r.wan_addr = wan.and_then(|w| w.ipv4.iter().find_map(|a| public4(a)));
    }
    r.firmware = x.firmware.as_ref().map(|f| Firmware {
        version: f.installed.clone(),
        latest: f.latest.clone(),
        newer: f.newer,
        security: f.security,
        eol: eol(f.eol_state),
    });
    r.packages = x.updates.map(|u| Packages {
        behind: u.packages.len(),
        index_days: u.index_age().map(|s| s.max(0) / 86_400),
    });

    if let Some(u) = &s.uci {
        let zones = u.zones();
        r.forwards = Some(
            u.forwards()
                .into_iter()
                .filter(|f| f.enabled && (ex.wan.is_empty() || ex.wan.contains(&f.src)))
                .flat_map(|f| {
                    let zone = f.dest_ip.parse::<IpAddr>().ok().and_then(|a| {
                        match nets.as_ref()?.end(a) {
                            End::Zone(z) => Some(z),
                            _ => None,
                        }
                    });
                    let protos = if f.protos.is_empty() {
                        vec!["tcp".to_string(), "udp".to_string()]
                    } else {
                        f.protos.clone()
                    };
                    protos
                        .into_iter()
                        .flat_map(|p| match p.as_str() {
                            "tcpudp" | "all" => vec!["tcp".to_string(), "udp".to_string()],
                            _ => vec![p],
                        })
                        .map(move |proto| Forward {
                            proto,
                            port: f.port.clone(),
                            to_port: f.dest_port.clone().unwrap_or_else(|| f.port.clone()),
                            dest: f.dest_ip.clone(),
                            zone: zone.clone(),
                            probe: None,
                        })
                        .collect::<Vec<_>>()
                })
                .collect(),
        );
        if !ex.wan.is_empty() {
            r.wan_input_accept = Some(
                zones
                    .iter()
                    .any(|z| ex.wan.contains(&z.name) && z.input == "ACCEPT"),
            );
            r.v6_inbound = Some(inbound(u, &ex.wan));
        }
        let ssh = u.dropbear();
        if !ssh.is_empty() {
            r.ssh_password = Some(ssh.iter().any(|d| d.password_auth));
        }
        r.admin_http = u
            .uhttpd()
            .map(|h| !h.listen_http.is_empty() && !h.redirect_https);
        let wireless = u.config("wireless");
        r.wifi = Some(
            u.wifi()
                .into_iter()
                .filter(|w| !w.disabled)
                .enumerate()
                .map(|(n, w)| {
                    let sec = wireless.iter().find(|s| s.name == w.section);
                    let flag = |k: &str| sec.is_some_and(|s| s.flag(k, false));
                    let net = sec.and_then(|s| s.one("network")).unwrap_or("");
                    Wifi {
                        label: format!("Wi-Fi {}", n + 1),
                        encryption: w.encryption.clone(),
                        wps: flag("wps_pushbutton"),
                        guest: flag("isolate") || net.contains("guest"),
                    }
                })
                .collect(),
        );
        let joins: Vec<(String, String)> = u
            .config("firewall")
            .iter()
            .filter(|s| s.kind == "forwarding" && s.flag("enabled", true))
            .filter_map(|s| Some((s.one("src")?.to_string(), s.one("dest")?.to_string())))
            .collect();
        if !ex.wan.is_empty() {
            r.zones = Some(
                zones
                    .iter()
                    .map(|z| Zone {
                        name: z.name.clone(),
                        wan: ex.wan.contains(&z.name),
                        input: z.input.clone(),
                        reaches: joins
                            .iter()
                            .filter(|(src, _)| src == &z.name)
                            .map(|(_, d)| d.clone())
                            .collect(),
                        devices: None,
                        named: None,
                        wifi: None,
                        wired: None,
                    })
                    .collect(),
            );
        }
        r.log_kept = u
            .config("system")
            .iter()
            .find(|s| s.kind == "system")
            .map(|s| {
                ["log_file", "log_ip"]
                    .iter()
                    .any(|k| s.one(k).is_some_and(|v| !v.is_empty()))
            });
    }
    if let (Some(ls), true) = (&s.listeners, s.ifaces.is_some() && s.uci.is_some()) {
        let mut seen = std::collections::BTreeSet::new();
        r.wan_listeners = Some(
            ls.iter()
                .filter(|l| ex.outside(l))
                // The uplink's own DHCP clients: the provider has to reach those.
                .filter(|l| !(l.proto == "udp" && ["68", "546"].contains(&l.port.as_str())))
                .filter_map(|l| {
                    let port = l.port.parse::<u16>().ok()?;
                    seen.insert((l.proto.clone(), port)).then(|| WanListen {
                        proto: l.proto.clone(),
                        port,
                        process: l.process.clone(),
                    })
                })
                .collect(),
        );
    }
    r.crossings = s
        .security
        .as_ref()
        .and_then(|x| x.crossings.as_ref())
        .map(|v| {
            v.iter()
                .map(|c| Crossing {
                    from: c.from.clone(),
                    to: c.to.clone(),
                    flows: c.flows,
                })
                .collect()
        });
    // How many devices each side holds (which of them are gadgets isn't guessed).
    if let (Some(clients), Some(ifaces), Some(zones)) = (&s.clients, &s.ifaces, r.zones.as_mut()) {
        use crate::clients::Link;
        use crate::security::{End, Nets};
        let nets = Nets::new(ifaces, s.uci.as_ref());
        // (all, named, on Wi-Fi, on a cable) per zone.
        let mut count: std::collections::BTreeMap<String, [usize; 4]> = Default::default();
        for c in clients {
            let zone = c
                .addrs
                .iter()
                .filter_map(|a| a.parse::<std::net::IpAddr>().ok())
                .find_map(|a| match nets.end(a) {
                    End::Zone(z) => Some(z),
                    _ => None,
                })
                .or_else(|| match &c.link {
                    Link::Dmz { net, .. } => Some(net.clone()),
                    _ => None,
                });
            if let Some(z) = zone {
                let n = count.entry(z).or_default();
                n[0] += 1;
                n[1] += usize::from(c.known);
                n[2] += usize::from(matches!(c.link, Link::Wifi { .. }));
                n[3] += usize::from(matches!(c.link, Link::Wired { .. } | Link::Dmz { .. }));
            }
        }
        for z in zones.iter_mut().filter(|z| !z.wan) {
            let [all, named, wifi, wired] = count.get(&z.name).copied().unwrap_or_default();
            z.devices = Some(all);
            z.named = Some(named);
            z.wifi = Some(wifi);
            z.wired = Some(wired);
        }
    }
    r.devices = s.clients.as_ref().map(|c| Devices {
        total: c.len(),
        unknown: c.iter().filter(|c| c.unknown() && !c.leave_alone).count(),
    });
    r.dns_filter = x.dns.and_then(|d| {
        let b = d.blocklist.as_ref()?;
        Some(DnsFilter {
            on: b.enabled && b.running,
            age_days: d.list_age_days(),
        })
    });

    t.backup = s.backup.as_ref().map(|b| Backup {
        signals: Vec::new(),
        count: Some(b.count),
        newest_days: b
            .newest
            .as_ref()
            .map(|k| (now.as_second() - k.at.as_second()).max(0) / 86_400),
        encrypted: (b.count > 0).then_some(true),
        unsaved: Some(b.unsaved()),
    });
    // The services were read: a router without the bouncer is known not to enforce.
    t.watch = s.services.as_ref().map(|_| Watch {
        enforces: Some(s.crowdsec.as_ref().is_some_and(|b| b.on())),
        installed_off: s.crowdsec.as_ref().is_some_and(|b| !b.on()),
        ..Default::default()
    });
    t.router = Some(r);
    t
}

/// Read the router and say what it knows. Never fails: a router that doesn't answer is a
/// target that couldn't be checked.
pub fn collect(r: &Router) -> TargetFacts {
    let snap = match crate::audit::snapshot(r) {
        Ok(s) => s,
        Err(e) => {
            return TargetFacts::unreachable(&id(&r.name), Kind::Network, &r.name, &e.to_string());
        }
    };
    let now = snap.taken_at.unwrap_or_else(Timestamp::now);
    let mut errors = Vec::new();
    let updates = crate::collect::updates::collect(r)
        .map_err(|e| errors.push(("packages".to_string(), e.to_string())))
        .ok();
    let dns = crate::collect::dnsstate::collect(r)
        .map_err(|e| errors.push(("dns filter".to_string(), e.to_string())))
        .ok();
    let firmware = snap.ifaces.as_ref().map(|i| {
        let installed = i.board.version.as_str();
        let up = eval::series(installed).map(|s| crate::maint::upstream::get(&r.name, &s));
        let today = now.to_zoned(jiff::tz::TimeZone::UTC).date();
        eval::firmware(installed, up.as_ref().map(|c| &c.data), today)
    });
    let mut t = facts(
        &r.name,
        &snap,
        &Extra {
            updates: updates.as_ref(),
            firmware,
            dns: dns.as_ref(),
        },
        now,
    );
    t.errors.extend(errors);
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tests::{NOW, cfg, snap};
    use sentry_core::secaudit::{Answers, State, evaluate};

    fn now() -> Timestamp {
        NOW.parse().unwrap()
    }

    #[test]
    fn a_snapshot_becomes_facts_without_private_values() {
        let s = snap(&cfg());
        let fw = eval::firmware(
            "25.12.3",
            None,
            now().to_zoned(jiff::tz::TimeZone::UTC).date(),
        );
        let t = facts(
            "home",
            &s,
            &Extra {
                firmware: Some(fw),
                ..Default::default()
            },
            now(),
        );
        assert_eq!((t.id.as_str(), t.kind), ("net:home", Kind::Network));
        let r = t.router.as_ref().unwrap();
        let fwds = r.forwards.as_ref().unwrap();
        assert!(!fwds.is_empty());
        // Where a forward goes is kept for matching and never written.
        assert!(fwds.iter().all(|f| !f.dest.is_empty()));
        let json = serde_json::to_string(&t).unwrap();
        for f in fwds {
            assert!(!json.contains(&f.dest), "{json}");
        }
        for w in s.uci.as_ref().unwrap().wifi() {
            assert!(!json.contains(&w.ssid), "an SSID in the facts");
        }
        for c in s.clients.iter().flatten() {
            for v in c.mac.iter().chain(&c.hostname).chain(&c.addrs) {
                assert!(!json.contains(v.as_str()), "{v} in the facts");
            }
        }
        assert_eq!(r.wan_input_accept, Some(false));
        assert!(r.zones.as_ref().unwrap().iter().any(|z| z.wan));
        assert!(
            r.wifi
                .as_ref()
                .unwrap()
                .iter()
                .all(|w| w.label.starts_with("Wi-Fi "))
        );
        // And the rules read them: a door to a device sentry doesn't manage here.
        let items = evaluate(&[t], &Answers::default(), jiff::civil::date(2026, 10, 26));
        assert!(
            items
                .iter()
                .any(|i| i.id.starts_with("sec:door:net:home:") && i.state == State::CouldNotCheck),
            "{items:#?}"
        );
    }

    #[test]
    fn inbound_rules_leave_out_icmp_and_the_stock_ipsec_ones() {
        let text = "@@firewall\nfirewall.r1=rule\nfirewall.r1.name='Allow-ICMPv6-Forward'\n\
                    firewall.r1.src='wan'\nfirewall.r1.dest='*'\nfirewall.r1.proto='icmp'\n\
                    firewall.r1.target='ACCEPT'\n\
                    firewall.r2=rule\nfirewall.r2.src='wan'\nfirewall.r2.dest='lan'\n\
                    firewall.r2.proto='esp'\nfirewall.r2.target='ACCEPT'\n\
                    firewall.r3=rule\nfirewall.r3.src='wan'\nfirewall.r3.dest='lan'\n\
                    firewall.r3.proto='udp'\nfirewall.r3.dest_port='500'\n\
                    firewall.r3.target='ACCEPT'\n\
                    firewall.r4=rule\nfirewall.r4.src='wan'\nfirewall.r4.dest='dmz'\n\
                    firewall.r4.proto='tcp'\nfirewall.r4.dest_port='8443'\n\
                    firewall.r4.target='ACCEPT'\n\
                    firewall.r5=rule\nfirewall.r5.src='lan'\nfirewall.r5.dest='dmz'\n\
                    firewall.r5.target='ACCEPT'\n\
                    firewall.r6=rule\nfirewall.r6.src='wan'\nfirewall.r6.proto='tcp'\n\
                    firewall.r6.dest_port='22'\nfirewall.r6.target='ACCEPT'\n";
        let u = crate::collect::uci::parse(text, &crate::redact::Salt::fixed([7; 16]));
        assert_eq!(
            inbound(&u, &["wan".to_string()]),
            ["tcp port 8443 to the dmz network"]
        );
    }

    #[test]
    fn only_a_public_uplink_address_is_checked_from_outside() {
        assert_eq!(public4("203.0.113.7/24").as_deref(), Some("203.0.113.7"));
        assert_eq!(public4("192.168.1.2/24"), None);
        assert_eq!(public4("100.64.3.2/10"), None);
        assert_eq!(public4("2001:db8::1/64"), None);
    }
}

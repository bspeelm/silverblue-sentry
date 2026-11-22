//! Who is on the network, as the router sees it, in one exec: the DHCP leases (dnsmasq's,
//! IPv4, by MAC; odhcpd's, IPv6, by DUID), the neighbour table, each bridge's forwarding
//! table with its port numbering (`ip neigh` never names the wired port; there is no
//! `bridge` command), and the stations each access point has (`hostapd`'s list for signal
//! and rates, `iw`'s for how long they've been connected). Raw here; [`crate::clients`]
//! makes one list of it. Read every 10 s while Clients is in view.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{CollectError, output_needing, sections};
use crate::config;
use sentry_app::remote::Remote;

pub const SCRIPT: &str = "echo @@leases; cat /tmp/dhcp.leases 2>/dev/null; \
     echo @@leases6; cat /tmp/odhcpd.leases 2>/dev/null; \
     echo @@neigh; ip neigh; \
     echo @@ports; for p in /sys/class/net/*/brif/*; do [ -e \"$p/port_no\" ] || continue; \
     read n <\"$p/port_no\"; b=${p%/brif/*}; echo \"${b##*/} ${p##*/} $n\"; done; \
     echo @@fdb; for b in /sys/class/net/*/bridge; do [ -e \"$b\" ] || continue; b=${b%/bridge}; \
     echo \"@bridge ${b##*/}\"; brctl showmacs \"${b##*/}\" 2>/dev/null; done; \
     for h in $(ubus list 'hostapd.*' 2>/dev/null); do echo \"@@$h\"; ubus call $h get_clients; \
     echo \"@@iw.${h#hostapd.}\"; iw dev \"${h#hostapd.}\" station dump 2>/dev/null; done; true";

/// A dnsmasq lease: `<expiry> <mac> <address> <hostname or *> <client id or *>`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lease {
    /// When it ends (epoch seconds; 0: never).
    pub expires: i64,
    pub mac: String,
    pub addr: String,
    pub hostname: Option<String>,
}

/// An odhcpd lease: IPv6, known by its DUID. Only a DUID made from a link-layer address
/// alone carries the MAC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lease6 {
    pub ifname: String,
    pub duid: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub expires: i64,
    /// Without the prefix length.
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Neigh {
    pub addr: String,
    pub dev: String,
    pub mac: Option<String>,
    /// `REACHABLE`, `STALE`, `DELAY`, `FAILED`…
    pub state: String,
}

/// A MAC a bridge learnt, and the port it's behind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fdb {
    pub bridge: String,
    pub port: String,
    pub mac: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Station {
    pub ifname: String,
    pub mac: String,
    /// dBm.
    pub signal: i32,
    /// bit/s, as the access point sees them.
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub freq: u32,
    pub connected_s: Option<u64>,
    /// Management frame protection in use (None: the access point didn't say).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfp: Option<bool>,
    /// It joined by WPS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wps: Option<bool>,
    /// The handshake is complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Raw {
    pub leases: Vec<Lease>,
    pub leases6: Vec<Lease6>,
    pub neigh: Vec<Neigh>,
    pub fdb: Vec<Fdb>,
    pub stations: Vec<Station>,
}

pub fn leases(text: &str) -> Vec<Lease> {
    text.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            Some(Lease {
                expires: w.first()?.parse().ok()?,
                mac: config::mac(w.get(1)?)?,
                addr: w.get(2)?.to_string(),
                hostname: w.get(3).filter(|h| **h != "*").map(|h| h.to_string()),
            })
        })
        .collect()
}

/// The MAC in a DUID-LL for Ethernet (`0003 0001` + six bytes). A DUID-LLT's or a UUID's
/// isn't the address the device uses now.
fn duid_mac(duid: &str) -> Option<String> {
    let hex = duid.strip_prefix("00030001").filter(|h| h.len() == 12)?;
    let pairs: Vec<&str> = (0..6).map(|i| &hex[2 * i..2 * i + 2]).collect();
    config::mac(&pairs.join(":"))
}

/// `# <ifname> <duid> <iaid> <hostname or -> <expiry> <id> <length> <address/len>…`.
pub fn leases6(text: &str) -> Vec<Lease6> {
    text.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.strip_prefix('#')?.split_whitespace().collect();
            let duid = w.get(1)?.to_ascii_lowercase();
            Some(Lease6 {
                ifname: w.first()?.to_string(),
                mac: duid_mac(&duid),
                duid,
                hostname: w.get(3).filter(|h| **h != "-").map(|h| h.to_string()),
                expires: w.get(4)?.parse().ok()?,
                addrs: w
                    .get(7..)?
                    .iter()
                    .map(|a| a.split('/').next().unwrap_or(a).to_string())
                    .collect(),
            })
        })
        .collect()
}

/// `<addr> dev <if> [lladdr <mac>] [router] … <STATE>`.
pub fn neigh(text: &str) -> Vec<Neigh> {
    text.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            let after = |k: &str| w.iter().position(|x| *x == k).and_then(|i| w.get(i + 1));
            Some(Neigh {
                addr: w.first()?.to_string(),
                dev: after("dev")?.to_string(),
                mac: after("lladdr").and_then(|m| config::mac(m)),
                state: w.last()?.to_string(),
            })
        })
        .collect()
}

/// `brctl showmacs` of each bridge (after its `@bridge <name>` line), with the ports named
/// through `ports` (`<bridge> <port> <number>` lines, the number in hex as sysfs has it).
/// The bridge's own addresses (`is local?` yes) aren't anyone's.
pub fn fdb(ports: &str, text: &str) -> Vec<Fdb> {
    let mut names: BTreeMap<(String, u32), String> = BTreeMap::new();
    for l in ports.lines() {
        let w: Vec<&str> = l.split_whitespace().collect();
        if let [bridge, port, no] = w[..]
            && let Ok(n) = u32::from_str_radix(no.trim_start_matches("0x"), 16)
        {
            names.insert((bridge.to_string(), n), port.to_string());
        }
    }
    let mut bridge = String::new();
    let mut out: Vec<Fdb> = Vec::new();
    for l in text.lines() {
        if let Some(b) = l.strip_prefix("@bridge ") {
            bridge = b.trim().to_string();
            continue;
        }
        let w: Vec<&str> = l.split_whitespace().collect();
        let (Some(no), Some(mac), Some(local)) = (
            w.first().and_then(|n| n.parse::<u32>().ok()),
            w.get(1).and_then(|m| config::mac(m)),
            w.get(2),
        ) else {
            continue;
        };
        if *local != "no" {
            continue;
        }
        let Some(port) = names.get(&(bridge.clone(), no)) else {
            continue;
        };
        let e = Fdb {
            bridge: bridge.clone(),
            port: port.clone(),
            mac,
        };
        if !out.contains(&e) {
            out.push(e);
        }
    }
    out
}

/// One access point's `get_clients`.
pub fn stations(ifname: &str, json: &str) -> Result<Vec<Station>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let freq = v["freq"].as_u64().unwrap_or(0) as u32;
    Ok(v["clients"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(mac, c)| {
            Some(Station {
                ifname: ifname.to_string(),
                mac: config::mac(mac)?,
                signal: c["signal"].as_i64().unwrap_or(0) as i32,
                rx_rate: c["rate"]["rx"].as_u64().unwrap_or(0),
                tx_rate: c["rate"]["tx"].as_u64().unwrap_or(0),
                freq,
                connected_s: None,
                mfp: c["mfp"].as_bool(),
                wps: c["wps"].as_bool(),
                authorized: c["authorized"].as_bool(),
            })
        })
        .collect())
}

/// `iw dev <if> station dump`: how long each station has been connected, by MAC.
pub fn connected(text: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let mut cur: Option<String> = None;
    for l in text.lines() {
        if let Some(rest) = l.strip_prefix("Station ") {
            cur = rest.split_whitespace().next().and_then(config::mac);
        } else if let Some((k, v)) = l.trim().split_once(':')
            && k == "connected time"
            && let Some(mac) = &cur
            && let Some(Ok(s)) = v.split_whitespace().next().map(str::parse)
        {
            out.insert(mac.clone(), s);
        }
    }
    out
}

pub fn parse(text: &str) -> Result<Raw, String> {
    let mut raw = Raw::default();
    let secs = sections(text);
    let body = |name: &str| secs.iter().find(|(n, _)| *n == name).map_or("", |(_, b)| b);
    raw.leases = leases(body("leases"));
    raw.leases6 = leases6(body("leases6"));
    raw.neigh = neigh(body("neigh"));
    raw.fdb = fdb(body("ports"), body("fdb"));
    for (name, b) in &secs {
        if let Some(ifname) = name.strip_prefix("hostapd.") {
            let mut st = stations(ifname, b).map_err(|e| format!("{name}: {e}"))?;
            let times = connected(body(&format!("iw.{ifname}")));
            for s in &mut st {
                s.connected_s = times.get(&s.mac).copied();
            }
            raw.stations.extend(st);
        }
    }
    Ok(raw)
}

pub fn collect(r: &Remote) -> Result<Raw, CollectError> {
    parse(&output_needing(r, "ip", SCRIPT)?).map_err(CollectError::Parse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    pub(crate) fn raw() -> Raw {
        parse(&fixture("network/clients.txt")).unwrap()
    }

    #[test]
    fn leases_by_mac_with_when_they_end() {
        let r = raw();
        assert_eq!(r.leases.len(), 8);
        let nas = &r.leases[0];
        assert_eq!(
            (
                nas.mac.as_str(),
                nas.addr.as_str(),
                nas.hostname.as_deref(),
                nas.expires
            ),
            (
                "00:00:5e:00:53:10",
                "192.0.2.10",
                Some("nas"),
                1_793_037_600
            )
        );
        assert_eq!(r.leases[1].hostname, None);
        assert!(leases("not a lease\n1 zz 192.0.2.1 * *\n").is_empty());
    }

    #[test]
    fn ipv6_leases_are_by_duid_and_only_some_carry_a_mac() {
        let l = raw().leases6;
        assert_eq!(l.len(), 4);
        // DUID-LL: the MAC is in it.
        assert_eq!(l[0].mac.as_deref(), Some("00:00:5e:00:53:10"));
        assert_eq!(l[0].addrs, ["2001:db8:1200::114", "fd00:db8:1::114"]);
        assert_eq!(l[0].hostname.as_deref(), Some("nas"));
        assert_eq!(l[1].mac.as_deref(), Some("02:00:5e:00:53:21"));
        // A UUID, and a DUID-LLT (whose address is from another time): no MAC to go by.
        assert_eq!(
            (l[2].mac.as_deref(), l[2].hostname.as_deref()),
            (None, None)
        );
        assert_eq!(
            (l[3].mac.as_deref(), l[3].hostname.as_deref()),
            (None, Some("my-phone"))
        );
        assert_eq!(l[3].ifname, "br-lan");
    }

    #[test]
    fn neighbours_with_or_without_an_address_of_their_own() {
        let n = raw().neigh;
        assert_eq!(n.len(), 13);
        assert_eq!(
            (
                n[0].addr.as_str(),
                n[0].dev.as_str(),
                n[0].mac.as_deref(),
                n[0].state.as_str()
            ),
            (
                "192.0.2.10",
                "br-lan",
                Some("00:00:5e:00:53:10"),
                "REACHABLE"
            )
        );
        assert_eq!((n[2].mac.as_deref(), n[2].state.as_str()), (None, "FAILED"));
        let dmz = n.iter().find(|x| x.dev == "lan4").unwrap();
        assert_eq!(dmz.mac.as_deref(), Some("00:00:5e:00:53:30"));
    }

    #[test]
    fn a_mac_is_behind_the_port_its_bridge_learnt_it_on() {
        let f = raw().fdb;
        let port = |mac: &str| f.iter().find(|x| x.mac == mac).map(|x| x.port.as_str());
        assert_eq!(port("00:00:5e:00:53:10"), Some("lan1"));
        assert_eq!(port("00:00:5e:00:53:11"), Some("lan2"));
        assert_eq!(port("02:00:5e:00:53:22"), Some("lan2"));
        assert_eq!(port("02:00:5e:00:53:20"), Some("phy1-ap0"));
        // The bridge's own addresses aren't clients.
        assert_eq!(port("02:00:5e:00:53:a0"), None);
        assert_eq!(f.len(), 7);
        assert!(f.iter().all(|x| x.bridge == "br-lan"));
        // Port numbers are hex in sysfs, decimal in brctl.
        let f = fdb(
            "br0 lan9 0xa\n",
            "@bridge br0\n 10\t00:00:5e:00:53:01\tno\t 1.00\n",
        );
        assert_eq!(f[0].port, "lan9");
        // A port number nothing names: left out rather than guessed.
        assert!(fdb("", "@bridge br0\n 1\t00:00:5e:00:53:01\tno\t 1.00\n").is_empty());
    }

    #[test]
    fn stations_on_each_radio_with_signal_rates_and_time() {
        let s = raw().stations;
        assert_eq!(s.len(), 3);
        let phone = s.iter().find(|x| x.mac == "02:00:5e:00:53:20").unwrap();
        assert_eq!(
            (phone.ifname.as_str(), phone.signal, phone.freq),
            ("phy1-ap0", -46, 5200)
        );
        assert_eq!((phone.rx_rate, phone.tx_rate), (864_800_000, 1_200_900_000));
        assert_eq!(phone.connected_s, Some(39_149));
        let on24: Vec<&str> = s
            .iter()
            .filter(|x| x.ifname == "phy0-ap0")
            .map(|x| x.mac.as_str())
            .collect();
        assert_eq!(on24.len(), 2);
        assert!(on24.contains(&"00:00:5e:00:53:12"));
        // Without iw, the time isn't known; the rest is.
        let no_iw = parse("@@hostapd.phy0-ap0\n{\"freq\": 2412, \"clients\": {\"00:00:5e:00:53:12\": {\"signal\": -70}}}\n").unwrap();
        assert_eq!(no_iw.stations[0].connected_s, None);
        assert!(parse("@@hostapd.phy0-ap0\nnot json\n").is_err());
        // A router with no Wi-Fi and no leases yet: nothing, not an error.
        assert_eq!(
            parse("@@leases\n@@leases6\n@@neigh\n@@ports\n@@fdb\n").unwrap(),
            Raw::default()
        );
    }
}

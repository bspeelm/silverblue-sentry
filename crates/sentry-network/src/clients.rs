//! One list of who is on the network, from what the router reports ([`collect::clients`]):
//! each device once, by its MAC, with what it's called, how it's connected (which wired
//! port, which radio and how well, or a routed port of its own such as a DMZ), its addresses
//! and its lease. Pure ([`merge`]); what was seen before is `seen.toml` beside the network's
//! records ([`Seen`]).
//!
//! Randomised addresses: a locally administered MAC on Wi-Fi is a phone's private address,
//! and it holds the passphrase, so it never raises a finding; it's listed with `~`, under the
//! hostname of a `private_mac` device when it gives one (a label, not an identity). A MAC
//! with a vendor's prefix that isn't in `devices`, or any MAC that isn't on a wired or
//! routed port, is unknown, and raises `net:client:<mac>` once it has held a lease in two
//! reads running.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::collect::clients::{Fdb, Lease, Lease6, Neigh, Raw, Station};
use crate::collect::ifaces::{DevKind, Ifaces};
use crate::config::{self, Device};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Link {
    /// Behind a wired port of the switch.
    Wired { port: String },
    /// On an access point; the signal while it's associated.
    Wifi { ifname: String, signal: Option<i32> },
    /// On a routed port of its own (not in the bridge): `net` is the interface's name
    /// (`dmz`).
    Dmz { port: String, net: String },
    /// Holding a lease, not seen on any port now.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Associated, or answering its neighbours' questions now.
    Online,
    /// Known to the switch or the neighbour table, not heard from just now.
    Idle,
    /// Only its lease is left.
    Away,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Client {
    /// Its MAC; `duid:<…>` for one known only by an IPv6 lease.
    pub key: String,
    pub mac: Option<String>,
    /// What `devices` calls it (by its MAC, or for a private MAC by its hostname).
    pub name: Option<String>,
    pub hostname: Option<String>,
    pub link: Link,
    /// IPv4 first.
    pub addrs: Vec<String>,
    /// When its lease ends (epoch seconds); none: it holds no lease.
    pub lease_end: Option<i64>,
    pub state: State,
    /// A locally administered (randomised) MAC.
    pub private: bool,
    /// `devices` names this MAC.
    pub known: bool,
    pub leave_alone: bool,
    /// bit/s to and from it, on Wi-Fi.
    pub rates: Option<(u64, u64)>,
    pub connected_s: Option<u64>,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    /// It raises `net:client:<mac>`: unknown, and holding a lease two reads running.
    pub flagged: bool,
}

impl Client {
    /// What the list calls it: its name, else its hostname, else its MAC.
    pub fn label(&self) -> &str {
        self.name
            .as_deref()
            .or(self.hostname.as_deref())
            .unwrap_or(&self.key)
    }

    /// Nothing vouches for it: no name for its MAC, and it isn't a private address on
    /// Wi-Fi (which the passphrase vouches for).
    pub fn unknown(&self) -> bool {
        self.mac.is_some()
            && !self.known
            && (!self.private || matches!(self.link, Link::Wired { .. } | Link::Dmz { .. }))
    }

    /// The first three bytes of a vendor's MAC (a private one has no vendor).
    pub fn vendor_prefix(&self) -> Option<&str> {
        self.mac.as_deref().filter(|_| !self.private)?.get(..8)
    }
}

/// What of the router's layout the list needs: which devices are bridges, which lead
/// outside, which radios there are, and what each routed device's interface is called.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Topo {
    pub bridges: Vec<String>,
    pub uplinks: Vec<String>,
    pub radios: Vec<String>,
    pub nets: BTreeMap<String, String>,
}

impl Topo {
    pub fn of(i: &Ifaces) -> Self {
        let mut uplinks: Vec<String> = Vec::new();
        for w in [i.wan(), i.wan6()].into_iter().flatten() {
            for d in [&w.device, &w.l3_device] {
                if !d.is_empty() && !uplinks.contains(d) {
                    uplinks.push(d.clone());
                }
            }
        }
        let of_kind = |k: DevKind| {
            i.devices
                .iter()
                .filter(|d| d.kind == k)
                .map(|d| d.name.clone())
                .collect::<Vec<_>>()
        };
        Self {
            bridges: of_kind(DevKind::Bridge),
            uplinks,
            radios: of_kind(DevKind::Wireless),
            nets: i
                .devices
                .iter()
                .filter_map(|d| Some((d.name.clone(), i.net_of(&d.name)?.to_string())))
                .collect(),
        }
    }
}

/// What was seen before, by MAC.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Seen {
    pub clients: BTreeMap<String, SeenOne>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SeenOne {
    pub first: i64,
    pub last: i64,
    /// Reads running in which it held a lease (counted to two: that's all that's asked).
    pub leases: u8,
}

/// One that hasn't shown up for this long is forgotten.
const FORGET_S: i64 = 180 * 86400;

impl Seen {
    pub fn path(scope: &str) -> PathBuf {
        sentry_core::maint::root(scope).join("seen.toml")
    }

    pub fn load(scope: &str) -> Self {
        std::fs::read_to_string(Self::path(scope))
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, scope: &str) -> anyhow::Result<()> {
        let p = Self::path(scope);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        let body = format!(
            "# Written by sentry: when each device on the network was first and last seen.\n{}",
            toml::to_string_pretty(self)?
        );
        sentry_core::paths::write_atomic(&p, body.as_bytes())?;
        Ok(())
    }

    /// Take a read in: who is there, and who holds a lease. True: something other than a
    /// "last seen" changed (worth writing down at once).
    pub fn note(&mut self, clients: &[Client], now: i64) -> bool {
        let mut changed = false;
        for c in clients {
            let Some(mac) = &c.mac else { continue };
            if c.state == State::Away && c.lease_end.is_none() {
                continue;
            }
            let e = self.clients.entry(mac.clone()).or_insert_with(|| {
                changed = true;
                SeenOne {
                    first: now,
                    ..Default::default()
                }
            });
            e.last = now;
        }
        for (mac, e) in &mut self.clients {
            let leased = clients
                .iter()
                .any(|c| c.mac.as_deref() == Some(mac) && c.lease_end.is_some());
            let next = if leased { (e.leases + 1).min(2) } else { 0 };
            changed |= next != e.leases;
            e.leases = next;
        }
        let before = self.clients.len();
        self.clients.retain(|_, e| now - e.last < FORGET_S);
        changed | (self.clients.len() != before)
    }
}

fn answering(n: &Neigh) -> bool {
    matches!(n.state.as_str(), "REACHABLE" | "DELAY" | "PROBE")
}

/// What `devices` says about a MAC, or (a label only) about a private MAC's hostname.
fn named<'a>(
    devices: &'a [Device],
    mac: &str,
    hostname: Option<&str>,
) -> (Option<&'a Device>, bool) {
    if let Some(d) = devices
        .iter()
        .find(|d| d.mac.as_deref().and_then(config::mac).as_deref() == Some(mac))
    {
        // Listed but not named (as `init` drafts it): still to be vouched for.
        return (Some(d), d.name.is_some());
    }
    let by_host = hostname.filter(|_| config::local_mac(mac)).and_then(|h| {
        devices.iter().find(|d| {
            d.private_mac
                && d.hostname
                    .as_deref()
                    .is_some_and(|x| x.eq_ignore_ascii_case(h))
        })
    });
    (by_host, false)
}

/// One list from everything read. Keyed by lower-cased MAC; an IPv6 lease that names no MAC
/// joins the device that gave the same hostname, else it's listed by itself.
pub fn merge(
    leases: (&[Lease], &[Lease6]),
    stations: &[Station],
    neigh: &[Neigh],
    ports: (&[Fdb], &Topo),
    devices: &[Device],
    seen: &Seen,
) -> Vec<Client> {
    let (leases, leases6) = leases;
    let (fdb, topo) = ports;
    let bridge =
        |dev: &str| topo.bridges.iter().any(|b| b == dev) || fdb.iter().any(|f| f.bridge == dev);
    // A neighbour counts when it's on the bridge or on a routed port inside: the ISP's
    // gateway on the uplink isn't a client, and without the layout nothing else is certain.
    let inside = |n: &&Neigh| {
        n.mac.is_some()
            && !topo.uplinks.contains(&n.dev)
            && (bridge(&n.dev) || topo.nets.contains_key(&n.dev))
    };
    let mut macs: Vec<String> = Vec::new();
    let mut add = |m: &str| {
        if !macs.iter().any(|x| x == m) {
            macs.push(m.to_string());
        }
    };
    leases.iter().for_each(|l| add(&l.mac));
    stations.iter().for_each(|s| add(&s.mac));
    fdb.iter().for_each(|f| add(&f.mac));
    // A neighbour that isn't answering is a memory of one (the table keeps them long after
    // the device left): it adds its addresses to a device that's there, never a device.
    neigh
        .iter()
        .filter(inside)
        .filter(|n| answering(n))
        .for_each(|n| add(n.mac.as_deref().unwrap_or_default()));
    leases6
        .iter()
        .filter_map(|l| l.mac.as_deref())
        .for_each(&mut add);

    let mut out: Vec<Client> = macs
        .iter()
        .map(|mac| {
            let lease = leases
                .iter()
                .filter(|l| &l.mac == mac)
                .max_by_key(|l| l.expires);
            let lease6: Vec<&Lease6> = leases6
                .iter()
                .filter(|l| l.mac.as_ref() == Some(mac))
                .collect();
            let station = stations.iter().find(|s| &s.mac == mac);
            let learnt = fdb.iter().find(|f| &f.mac == mac);
            let near: Vec<&Neigh> = neigh
                .iter()
                .filter(inside)
                .filter(|n| n.mac.as_ref() == Some(mac))
                .collect();
            let hostname = lease
                .and_then(|l| l.hostname.clone())
                .or_else(|| lease6.iter().find_map(|l| l.hostname.clone()));
            let routed = near.iter().find(|n| !bridge(&n.dev));
            let link = match (station, learnt, routed) {
                (Some(s), _, _) => Link::Wifi {
                    ifname: s.ifname.clone(),
                    signal: Some(s.signal),
                },
                (None, Some(f), _) if topo.radios.contains(&f.port) => Link::Wifi {
                    ifname: f.port.clone(),
                    signal: None,
                },
                (None, Some(f), _) => Link::Wired {
                    port: f.port.clone(),
                },
                (None, None, Some(n)) => Link::Dmz {
                    port: n.dev.clone(),
                    net: topo.nets.get(&n.dev).cloned().unwrap_or_default(),
                },
                (None, None, None) => Link::Unknown,
            };
            let mut addrs: Vec<String> = Vec::new();
            let mut addr = |a: &str| {
                // Link-local addresses say nothing a MAC doesn't.
                if !a.starts_with("fe80:") && !addrs.iter().any(|x| x == a) {
                    addrs.push(a.to_string());
                }
            };
            lease.iter().for_each(|l| addr(&l.addr));
            near.iter()
                .filter(|n| !n.addr.contains(':'))
                .for_each(|n| addr(&n.addr));
            lease6.iter().flat_map(|l| &l.addrs).for_each(|a| addr(a));
            near.iter()
                .filter(|n| n.addr.contains(':'))
                .for_each(|n| addr(&n.addr));
            let answering = near.iter().any(|n| answering(n));
            let state = if station.is_some() || answering {
                State::Online
            } else if learnt.is_some() || !near.is_empty() {
                State::Idle
            } else {
                State::Away
            };
            let (dev, known) = named(devices, mac, hostname.as_deref());
            let was = seen.clients.get(mac);
            let mut c = Client {
                key: mac.clone(),
                mac: Some(mac.clone()),
                name: dev.and_then(|d| d.name.clone()),
                hostname,
                link,
                addrs,
                lease_end: lease
                    .map(|l| l.expires)
                    .or_else(|| lease6.iter().map(|l| l.expires).max()),
                state,
                private: config::local_mac(mac),
                known,
                leave_alone: dev.is_some_and(|d| d.leave_alone),
                rates: station.map(|s| (s.rx_rate, s.tx_rate)),
                connected_s: station.and_then(|s| s.connected_s),
                first_seen: was.map(|s| s.first),
                last_seen: was.map(|s| s.last),
                flagged: false,
            };
            c.flagged = c.unknown() && was.is_some_and(|s| s.leases >= 2) && c.lease_end.is_some();
            c
        })
        .collect();

    // IPv6 leases by a DUID that names no MAC: the device that gave the same hostname takes
    // their addresses; else they're an entry of their own.
    for l in leases6.iter().filter(|l| l.mac.is_none()) {
        let same = l.hostname.as_deref().and_then(|h| {
            out.iter_mut().find(|c| {
                c.hostname
                    .as_deref()
                    .is_some_and(|x| x.eq_ignore_ascii_case(h))
            })
        });
        match same {
            Some(c) => {
                for a in &l.addrs {
                    if !c.addrs.contains(a) {
                        c.addrs.push(a.clone());
                    }
                }
            }
            None => out.push(Client {
                key: format!("duid:{}", l.duid),
                mac: None,
                name: None,
                hostname: l.hostname.clone(),
                link: Link::Unknown,
                addrs: l.addrs.clone(),
                lease_end: Some(l.expires),
                state: State::Away,
                private: false,
                known: false,
                leave_alone: false,
                rates: None,
                connected_s: None,
                first_seen: None,
                last_seen: None,
                flagged: false,
            }),
        }
    }
    out
}

/// A read taken in: the list, with `seen` brought up to date by it (true: `seen` changed in
/// a way worth saving now).
pub fn read(
    raw: &Raw,
    topo: &Topo,
    devices: &[Device],
    seen: &mut Seen,
    now: i64,
) -> (Vec<Client>, bool) {
    let go = |seen: &Seen| {
        merge(
            (&raw.leases, &raw.leases6),
            &raw.stations,
            &raw.neigh,
            (&raw.fdb, topo),
            devices,
            seen,
        )
    };
    let changed = seen.note(&go(seen), now);
    (go(seen), changed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::collect::{fixture, ifaces};

    pub(crate) const NOW: i64 = 1_793_016_000;

    pub(crate) fn topo() -> Topo {
        Topo::of(&ifaces::parse(&fixture("network/ifaces.txt")).unwrap())
    }

    pub(crate) fn devices() -> Vec<Device> {
        let dev = |name: &str, mac: Option<&str>, hostname: Option<&str>| Device {
            name: Some(name.into()),
            mac: mac.map(String::from),
            hostname: hostname.map(String::from),
            private_mac: mac.is_none(),
            ..Default::default()
        };
        vec![
            dev("nas", Some("00:00:5E:00:53:10"), None),
            Device {
                leave_alone: true,
                ..dev("panel", Some("00:00:5e:00:53:12"), None)
            },
            dev("phone", None, Some("My-Phone")),
            dev("web", Some("00:00:5e:00:53:30"), None),
        ]
    }

    pub(crate) fn raw() -> Raw {
        crate::collect::clients::parse(&fixture("network/clients.txt")).unwrap()
    }

    /// The fixture's network after `reads` reads of it.
    pub(crate) fn clients(reads: usize, devices: &[Device]) -> (Vec<Client>, Seen) {
        let mut seen = Seen::default();
        let mut out = Vec::new();
        for i in 0..reads {
            out = read(&raw(), &topo(), devices, &mut seen, NOW + 10 * i as i64).0;
        }
        (out, seen)
    }

    fn one<'a>(c: &'a [Client], key: &str) -> &'a Client {
        c.iter()
            .find(|x| x.key == key)
            .unwrap_or_else(|| panic!("no {key}"))
    }

    #[test]
    fn the_layout_comes_from_the_interfaces() {
        let t = topo();
        assert_eq!(t.bridges, ["br-lan"]);
        assert_eq!(t.uplinks, ["eth1"]);
        assert_eq!(t.radios, ["phy0-ap0", "phy1-ap0"]);
        assert_eq!(t.nets.get("lan4").map(String::as_str), Some("dmz"));
        assert_eq!(t.nets.get("lan1").map(String::as_str), Some("lan"));
    }

    #[test]
    fn each_device_once_with_its_name_link_and_standing() {
        let (c, _) = clients(2, &devices());
        // What each row is, and whether it raises a finding.
        let table: Vec<(&str, &str, Link, State, bool, bool, bool)> = c
            .iter()
            .map(|x| {
                (
                    x.key.as_str(),
                    x.label(),
                    x.link.clone(),
                    x.state,
                    x.private,
                    x.known,
                    x.flagged,
                )
            })
            .collect();
        let wired = |p: &str| Link::Wired { port: p.into() };
        let wifi = |i: &str, s: i32| Link::Wifi {
            ifname: i.into(),
            signal: Some(s),
        };
        let want = vec![
            // Known by its MAC, on a wired port.
            (
                "00:00:5e:00:53:10",
                "nas",
                wired("lan1"),
                State::Online,
                false,
                true,
                false,
            ),
            // A vendor's MAC nobody named: unknown.
            (
                "00:00:5e:00:53:11",
                "00:00:5e:00:53:11",
                wired("lan2"),
                State::Idle,
                false,
                false,
                true,
            ),
            // A private MAC on Wi-Fi under the hostname a private_mac device gives: a label.
            (
                "02:00:5e:00:53:20",
                "phone",
                wifi("phy1-ap0", -46),
                State::Online,
                true,
                false,
                false,
            ),
            // A private MAC on Wi-Fi with no name at all: fine too.
            (
                "02:00:5e:00:53:21",
                "02:00:5e:00:53:21",
                wifi("phy0-ap0", -63),
                State::Online,
                true,
                false,
                false,
            ),
            // A private MAC on a wired port: nothing vouches for it.
            (
                "02:00:5e:00:53:22",
                "02:00:5e:00:53:22",
                wired("lan2"),
                State::Idle,
                true,
                false,
                true,
            ),
            (
                "00:00:5e:00:53:12",
                "panel",
                wifi("phy0-ap0", -81),
                State::Online,
                false,
                true,
                false,
            ),
            // On the routed port: named, so known.
            (
                "00:00:5e:00:53:30",
                "web",
                Link::Dmz {
                    port: "lan4".into(),
                    net: "dmz".into(),
                },
                State::Online,
                false,
                true,
                false,
            ),
            // Only its lease is left.
            (
                "00:00:5e:00:53:13",
                "old-printer",
                Link::Unknown,
                State::Away,
                false,
                false,
                true,
            ),
            // No lease: seen by the switch, never flagged.
            (
                "00:00:5e:00:53:14",
                "00:00:5e:00:53:14",
                wired("lan2"),
                State::Idle,
                false,
                false,
                false,
            ),
            // An IPv6 lease no MAC or hostname ties to anything.
            (
                "duid:0004a1b2c3d4e5f60718293a4b5c6d7e8f90",
                "duid:0004a1b2c3d4e5f60718293a4b5c6d7e8f90",
                Link::Unknown,
                State::Away,
                false,
                false,
                false,
            ),
        ];
        assert_eq!(table.len(), want.len(), "{table:#?}");
        for (got, want) in table.iter().zip(&want) {
            assert_eq!(got, want);
        }
        assert!(one(&c, "00:00:5e:00:53:12").leave_alone);
        // The uplink's gateway, neighbours without an address and one the table only
        // remembers aren't clients.
        assert!(
            !c.iter()
                .any(|x| x.key.ends_with(":fe") || x.key.ends_with(":77"))
        );
    }

    #[test]
    fn addresses_join_by_mac_then_by_hostname() {
        let (c, _) = clients(1, &devices());
        // By the MAC in the DUID; a link-local address adds nothing.
        assert_eq!(
            one(&c, "00:00:5e:00:53:10").addrs,
            ["192.0.2.10", "2001:db8:1200::114", "fd00:db8:1::114"]
        );
        // The phone's IPv6 lease names no MAC: its hostname ties it.
        assert_eq!(
            one(&c, "02:00:5e:00:53:20").addrs,
            ["192.0.2.20", "2001:db8:1200::cc8"]
        );
        assert_eq!(
            one(&c, "02:00:5e:00:53:21").addrs,
            ["192.0.2.21", "2001:db8:1200::601"]
        );
        let v6 = c.iter().find(|x| x.mac.is_none()).unwrap();
        assert_eq!(v6.addrs, ["2001:db8:1200::c40", "fd00:db8:1::c40"]);
        assert_eq!(v6.lease_end, Some(1_793_040_000));
        assert!(!v6.unknown());
        let phone = one(&c, "02:00:5e:00:53:20");
        assert_eq!(phone.lease_end, Some(1_793_052_000));
        assert_eq!(phone.rates, Some((864_800_000, 1_200_900_000)));
        assert_eq!(phone.connected_s, Some(39_149));
        assert_eq!(phone.vendor_prefix(), None);
        assert_eq!(
            one(&c, "00:00:5e:00:53:11").vendor_prefix(),
            Some("00:00:5e")
        );
    }

    #[test]
    fn unknown_raises_only_after_two_reads_with_a_lease() {
        let flagged = |c: &[Client]| -> Vec<String> {
            c.iter()
                .filter(|x| x.flagged)
                .map(|x| x.key.clone())
                .collect()
        };
        let (first, seen) = clients(1, &devices());
        assert!(flagged(&first).is_empty(), "one read isn't two");
        assert_eq!(
            seen.clients["00:00:5e:00:53:11"],
            SeenOne {
                first: NOW,
                last: NOW,
                leases: 1
            }
        );
        let (second, seen) = clients(2, &devices());
        assert_eq!(
            flagged(&second),
            [
                "00:00:5e:00:53:11",
                "02:00:5e:00:53:22",
                "00:00:5e:00:53:13"
            ]
        );
        assert_eq!(one(&second, "00:00:5e:00:53:11").first_seen, Some(NOW));
        assert_eq!(one(&second, "00:00:5e:00:53:11").last_seen, Some(NOW + 10));
        // The count stops at two, and only a lease counts.
        let (_, third) = clients(3, &devices());
        assert_eq!(third.clients["00:00:5e:00:53:11"].leases, 2);
        assert_eq!(seen.clients["00:00:5e:00:53:14"].leases, 0);
        // The lease gone for one read: it starts over.
        let mut seen = seen;
        let mut raw = raw();
        raw.leases.retain(|l| l.mac != "00:00:5e:00:53:11");
        let (c, changed) = read(&raw, &topo(), &devices(), &mut seen, NOW + 20);
        assert!(changed && !one(&c, "00:00:5e:00:53:11").flagged);
        assert_eq!(seen.clients["00:00:5e:00:53:11"].leases, 0);
        // Listed by MAC without a name, as `init` drafts the file: not vouched for yet.
        let listed = [Device {
            mac: Some("00:00:5e:00:53:11".into()),
            hostname: Some("desk".into()),
            ..Default::default()
        }];
        let (c, _) = clients(2, &listed);
        let desk = one(&c, "00:00:5e:00:53:11");
        assert!(desk.flagged && !desk.known && desk.name.is_none());
        // Named by MAC: never. Named nowhere: everything unknown, the private ones on
        // Wi-Fi still aside.
        let (bare, _) = clients(2, &[]);
        assert_eq!(
            flagged(&bare),
            [
                "00:00:5e:00:53:10",
                "00:00:5e:00:53:11",
                "02:00:5e:00:53:22",
                "00:00:5e:00:53:12",
                "00:00:5e:00:53:30",
                "00:00:5e:00:53:13"
            ]
        );
    }

    #[test]
    fn a_hostname_is_a_label_never_an_identity() {
        // The phone's hostname on a vendor's MAC, and on a private MAC behind a wired port.
        let mut raw = raw();
        for l in &mut raw.leases {
            if matches!(l.mac.as_str(), "00:00:5e:00:53:11" | "02:00:5e:00:53:22") {
                l.hostname = Some("my-phone".into());
            }
        }
        let mut seen = Seen::default();
        read(&raw, &topo(), &devices(), &mut seen, NOW);
        let (c, _) = read(&raw, &topo(), &devices(), &mut seen, NOW + 10);
        let universal = one(&c, "00:00:5e:00:53:11");
        assert_eq!((universal.label(), universal.flagged), ("my-phone", true));
        assert_eq!(universal.name, None, "private_mac names only a private MAC");
        let wired = one(&c, "02:00:5e:00:53:22");
        assert_eq!(
            (wired.label(), wired.known, wired.flagged),
            ("phone", false, true)
        );
    }

    #[test]
    fn without_the_layout_only_the_bridge_is_trusted() {
        let r = raw();
        let c = merge(
            (&r.leases, &r.leases6),
            &r.stations,
            &r.neigh,
            (&r.fdb, &Topo::default()),
            &[],
            &Seen::default(),
        );
        // The routed port's client keeps its lease but no link; the gateway stays out.
        assert_eq!(one(&c, "00:00:5e:00:53:30").link, Link::Unknown);
        assert!(!c.iter().any(|x| x.key.ends_with(":fe")));
        assert_eq!(
            one(&c, "00:00:5e:00:53:10").link,
            Link::Wired {
                port: "lan1".into()
            }
        );
    }

    #[test]
    fn seen_is_kept_beside_the_records_and_forgets_in_time() {
        let scope = "net:seen-test";
        let (_, mut seen) = clients(2, &devices());
        assert!(Seen::path(scope).ends_with("networks/seen-test/seen.toml"));
        seen.save(scope).unwrap();
        assert_eq!(Seen::load(scope), seen);
        let _ = std::fs::remove_file(Seen::path(scope));
        assert_eq!(Seen::load(scope), Seen::default());
        // Nothing new and no lease count moving: not worth a write.
        assert!(!seen.note(&clients(2, &devices()).0, NOW + 20));
        assert!(seen.note(&[], NOW + FORGET_S + 30));
        assert!(seen.clients.is_empty());
    }
}

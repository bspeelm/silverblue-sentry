//! What the router is and how its interfaces stand: `ubus call system board`, `system info`,
//! `network.interface dump` and `network.device status` in one exec, cut at `@@` marks. Read
//! every 30 s while the Dashboard is in view (none of it moves fast).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{CollectError, output_needing, sections};
use sentry_app::remote::Remote;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Board {
    pub model: String,
    pub board_name: String,
    pub hostname: String,
    pub kernel: String,
    /// `OpenWrt`.
    pub distribution: String,
    /// `25.12.3`.
    pub version: String,
    pub revision: String,
    /// `mediatek/filogic`.
    pub target: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Info {
    pub uptime_s: u64,
    pub load: [f32; 3],
    pub mem_total: u64,
    pub mem_available: u64,
    /// The overlay (flash you can write to), in KiB.
    pub root_total_kib: u64,
    pub root_used_kib: u64,
    pub tmp_total_kib: u64,
    pub tmp_used_kib: u64,
}

impl Info {
    /// The overlay's share used.
    pub fn root_pct(&self) -> Option<f32> {
        (self.root_total_kib > 0)
            .then(|| 100.0 * self.root_used_kib as f32 / self.root_total_kib as f32)
    }
}

/// A logical interface (`wan`, `lan`), as netifd has it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub device: String,
    pub l3_device: String,
    pub proto: String,
    pub up: bool,
    /// Seconds since it came up.
    pub uptime_s: u64,
    /// `address/mask`.
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    /// Prefixes delegated to it (`2001:db8::/56`).
    pub prefixes: Vec<String>,
    pub gateway: Option<String>,
    pub gateway6: Option<String>,
    pub dns: Vec<String>,
    /// The DHCP lease's length, where there is one (the router is told no expiry).
    pub lease_time_s: Option<u64>,
}

/// How long a DHCP lease still runs. The router only says how long the lease is and how long
/// the interface has been up; a renewal (at half the lease) doesn't restart that clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseLeft {
    /// Not renewed yet: lease time less the interface's uptime.
    Exact(u64),
    /// Renewed since: somewhere between half the lease and all of it.
    Between(u64, u64),
}

impl Interface {
    pub fn lease_left(&self) -> Option<LeaseLeft> {
        let lease = self.lease_time_s.filter(|l| *l > 0 && self.up)?;
        Some(if self.uptime_s < lease / 2 {
            LeaseLeft::Exact(lease - self.uptime_s)
        } else {
            LeaseLeft::Between(lease / 2, lease)
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DevKind {
    /// A port with its own MAC (the WAN port, or the one the switch hangs off).
    Ethernet,
    /// A port of the built-in switch.
    Dsa,
    Bridge,
    /// A Wi-Fi access point's interface.
    Wireless,
    Loopback,
    #[default]
    Other,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    pub kind: DevKind,
    pub up: bool,
    pub carrier: bool,
    /// Mbit/s, from `"1000F"`.
    pub speed: Option<u32>,
    /// Full duplex (`F`); None where there's no speed.
    pub full_duplex: Option<bool>,
    pub mac: String,
    /// A bridge's ports.
    pub members: Vec<String>,
    /// A switch port's way to the CPU.
    pub conduit: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Ifaces {
    pub board: Board,
    pub info: Info,
    pub interfaces: Vec<Interface>,
    pub devices: Vec<Device>,
}

impl Ifaces {
    /// The interface the default route leaves by (else the one called `wan`).
    pub fn wan(&self) -> Option<&Interface> {
        self.interfaces
            .iter()
            .find(|i| i.gateway.is_some())
            .or_else(|| self.interfaces.iter().find(|i| i.name == "wan"))
    }

    /// The IPv6 uplink: the one with a default route or a delegated prefix (else `wan6`).
    pub fn wan6(&self) -> Option<&Interface> {
        self.interfaces
            .iter()
            .find(|i| i.gateway6.is_some() || (i.proto == "dhcpv6" && !i.prefixes.is_empty()))
            .or_else(|| self.interfaces.iter().find(|i| i.name == "wan6"))
    }

    pub fn device(&self, name: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.name == name)
    }

    /// The logical interface a device belongs to: its own, or its bridge's.
    pub fn net_of(&self, dev: &str) -> Option<&str> {
        let own = |d: &str| {
            self.interfaces
                .iter()
                .find(|i| i.device == d && i.name != "loopback")
                .map(|i| i.name.as_str())
        };
        own(dev).or_else(|| {
            self.devices
                .iter()
                .filter(|b| b.kind == DevKind::Bridge && b.members.iter().any(|m| m == dev))
                .find_map(|b| own(&b.name))
        })
    }

    /// The devices the Dashboard has a row for, in its order: the uplink's first, then the
    /// wired ports by name, then the radios. Not the loopback, bridges, or the port the
    /// switch hangs off (its ports are the rows).
    pub fn rows(&self) -> Vec<&Device> {
        let wan = self.wan().map(|w| w.device.as_str());
        let conduit = |d: &Device| {
            self.devices
                .iter()
                .any(|x| x.conduit.as_deref() == Some(&d.name))
        };
        let mut rows: Vec<&Device> = self
            .devices
            .iter()
            .filter(|d| match d.kind {
                DevKind::Ethernet => !conduit(d),
                DevKind::Dsa | DevKind::Wireless => true,
                DevKind::Bridge | DevKind::Loopback | DevKind::Other => false,
            })
            .collect();
        rows.sort_by_key(|d| {
            (
                match d.kind {
                    _ if Some(d.name.as_str()) == wan => 0,
                    DevKind::Wireless => 2,
                    _ => 1,
                },
                d.name.clone(),
            )
        });
        rows
    }
}

pub const SCRIPT: &str = "echo @@board; ubus call system board; \
     echo @@info; ubus call system info; \
     echo @@interfaces; ubus call network.interface dump; \
     echo @@devices; ubus call network.device status";

pub fn collect(r: &Remote) -> Result<Ifaces, CollectError> {
    parse(&output_needing(r, "ubus", SCRIPT)?).map_err(CollectError::Parse)
}

/// Only `system info` (what the recorder reads once a minute: how full the overlay is).
pub fn info(r: &Remote) -> Result<Info, CollectError> {
    parse(&output_needing(
        r,
        "ubus",
        "echo @@info; ubus call system info",
    )?)
    .map(|i| i.info)
    .map_err(CollectError::Parse)
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or_default().to_string()
}

fn n(v: &Value, k: &str) -> u64 {
    v[k].as_u64().unwrap_or(0)
}

/// `[{address, mask}]` as `address/mask`.
fn addrs(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| {
            Some(format!(
                "{}/{}",
                a["address"].as_str()?,
                a["mask"].as_u64()?
            ))
        })
        .collect()
}

/// `"1000F"` → (1000, full).
fn speed(v: &Value) -> (Option<u32>, Option<bool>) {
    let Some(text) = v.as_str() else {
        return (None, None);
    };
    let digits = text.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    match digits.parse::<i64>() {
        Ok(m) if m > 0 => (
            Some(m as u32),
            match &text[digits.len()..] {
                "F" => Some(true),
                "H" => Some(false),
                _ => None,
            },
        ),
        _ => (None, None),
    }
}

fn interface(v: &Value) -> Interface {
    let default = |target: &str| {
        v["route"].as_array().into_iter().flatten().find_map(|r| {
            (r["target"].as_str() == Some(target) && r["mask"].as_u64() == Some(0))
                .then(|| r["nexthop"].as_str().map(str::to_string))
                .flatten()
        })
    };
    Interface {
        name: s(v, "interface"),
        device: s(v, "device"),
        l3_device: s(v, "l3_device"),
        proto: s(v, "proto"),
        up: v["up"].as_bool().unwrap_or(false),
        uptime_s: n(v, "uptime"),
        ipv4: addrs(&v["ipv4-address"]),
        ipv6: addrs(&v["ipv6-address"]),
        prefixes: addrs(&v["ipv6-prefix"]),
        gateway: default("0.0.0.0"),
        gateway6: default("::"),
        dns: v["dns-server"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str().map(str::to_string))
            .collect(),
        lease_time_s: v["data"]["leasetime"].as_u64(),
    }
}

fn device(name: &str, v: &Value) -> Device {
    let devtype = v["devtype"].as_str().unwrap_or("");
    let kind = match devtype {
        _ if name == "lo" => DevKind::Loopback,
        "bridge" => DevKind::Bridge,
        "dsa" => DevKind::Dsa,
        "ethernet" => DevKind::Ethernet,
        "wlan" => DevKind::Wireless,
        // A Wi-Fi interface is hostapd's, not netifd's: `external`, and no device type.
        "" if v["external"].as_bool() == Some(true) => DevKind::Wireless,
        _ if v["type"].as_str() == Some("bridge") => DevKind::Bridge,
        _ => DevKind::Other,
    };
    let carrier = v["carrier"].as_bool().unwrap_or(false);
    let (speed, full_duplex) = match carrier {
        true => speed(&v["speed"]),
        false => (None, None),
    };
    Device {
        name: name.to_string(),
        kind,
        up: v["up"].as_bool().unwrap_or(false),
        carrier,
        speed,
        full_duplex,
        mac: s(v, "macaddr"),
        members: v["bridge-members"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| m.as_str().map(str::to_string))
            .collect(),
        conduit: v["conduit"].as_str().map(str::to_string),
        rx_bytes: n(&v["statistics"], "rx_bytes"),
        tx_bytes: n(&v["statistics"], "tx_bytes"),
    }
}

pub fn parse(text: &str) -> Result<Ifaces, String> {
    let mut out = Ifaces::default();
    let mut seen = 0;
    for (name, body) in sections(text) {
        // (Other marks in the same output are someone else's, and may not be JSON.)
        if body.trim().is_empty() || !["board", "info", "interfaces", "devices"].contains(&name) {
            continue;
        }
        let v: Value = serde_json::from_str(body).map_err(|e| format!("{name}: {e}"))?;
        seen += 1;
        match name {
            "board" => {
                let r = &v["release"];
                out.board = Board {
                    model: s(&v, "model"),
                    board_name: s(&v, "board_name"),
                    hostname: s(&v, "hostname"),
                    kernel: s(&v, "kernel"),
                    distribution: s(r, "distribution"),
                    version: s(r, "version"),
                    revision: s(r, "revision"),
                    target: s(r, "target"),
                };
            }
            "info" => {
                let load: Vec<f32> = v["load"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|x| x.as_u64().unwrap_or(0) as f32 / 65536.0)
                    .collect();
                out.info = Info {
                    uptime_s: n(&v, "uptime"),
                    load: [
                        load.first().copied().unwrap_or(0.0),
                        load.get(1).copied().unwrap_or(0.0),
                        load.get(2).copied().unwrap_or(0.0),
                    ],
                    mem_total: n(&v["memory"], "total"),
                    mem_available: n(&v["memory"], "available"),
                    root_total_kib: n(&v["root"], "total"),
                    root_used_kib: n(&v["root"], "used"),
                    tmp_total_kib: n(&v["tmp"], "total"),
                    tmp_used_kib: n(&v["tmp"], "used"),
                };
            }
            "interfaces" => {
                out.interfaces = v["interface"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(interface)
                    .collect();
            }
            "devices" => {
                out.devices = v
                    .as_object()
                    .into_iter()
                    .flatten()
                    .map(|(k, d)| device(k, d))
                    .collect();
                out.devices.sort_by(|a, b| a.name.cmp(&b.name));
            }
            _ => {}
        }
    }
    if seen == 0 {
        return Err("ubus answered nothing".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx() -> Ifaces {
        parse(&super::super::fixture("network/ifaces.txt")).unwrap()
    }

    #[test]
    fn parses_board_info_interfaces_and_devices() {
        let i = fx();
        assert_eq!(i.board.model, "Example Router AX");
        assert_eq!(
            (i.board.distribution.as_str(), i.board.version.as_str()),
            ("OpenWrt", "25.12.3")
        );
        assert_eq!(i.board.target, "mediatek/filogic");
        assert_eq!(i.board.kernel, "6.12.80");
        assert_eq!(i.info.uptime_s, 1_363_000);
        // ubus gives load × 65536.
        assert!((i.info.load[0] - 0.42).abs() < 0.001, "{:?}", i.info.load);
        assert!((i.info.root_pct().unwrap() - 6.0).abs() < 0.01);
        assert_eq!(i.interfaces.len(), 5);
        let wan = i.wan().unwrap();
        assert_eq!((wan.name.as_str(), wan.device.as_str()), ("wan", "eth1"));
        assert_eq!(wan.ipv4, ["198.51.100.23/24"]);
        assert_eq!(wan.gateway.as_deref(), Some("198.51.100.1"));
        assert_eq!(wan.dns, ["198.51.100.53", "198.51.100.54"]);
        assert_eq!(wan.lease_time_s, Some(7200));
        let wan6 = i.wan6().unwrap();
        assert_eq!(wan6.name, "wan6");
        assert_eq!(wan6.prefixes, ["2001:db8:1200::/56"]);
        assert_eq!(wan6.gateway6.as_deref(), Some("fe80::1"));
        assert_eq!(i.devices.len(), 10);
    }

    #[test]
    fn devices_know_their_kind_speed_and_network() {
        let i = fx();
        let d = |n: &str| i.device(n).unwrap();
        assert_eq!(d("eth1").kind, DevKind::Ethernet);
        assert_eq!(
            (d("eth1").speed, d("eth1").full_duplex),
            (Some(1000), Some(true))
        );
        assert_eq!(d("eth0").speed, Some(2500));
        assert_eq!(d("lan2").kind, DevKind::Dsa);
        assert_eq!(d("lan2").speed, Some(100));
        assert_eq!(d("lan2").conduit.as_deref(), Some("eth0"));
        // No link: no speed, whatever the router prints for it.
        assert_eq!((d("lan3").carrier, d("lan3").speed), (false, None));
        assert_eq!(d("br-lan").kind, DevKind::Bridge);
        assert_eq!(d("lo").kind, DevKind::Loopback);
        // Wi-Fi has no speed to read.
        assert_eq!(
            (d("phy0-ap0").kind, d("phy0-ap0").speed),
            (DevKind::Wireless, None)
        );
        assert_eq!(d("phy1-ap0").tx_bytes, 590_000_000_000);
        assert_eq!(i.net_of("eth1"), Some("wan"));
        assert_eq!(i.net_of("lan1"), Some("lan"));
        assert_eq!(i.net_of("phy0-ap0"), Some("lan"));
        assert_eq!(i.net_of("lan4"), Some("dmz"));
        assert_eq!(i.net_of("eth0"), None);
        // The uplink, the switch's ports, the radios; not the port the switch hangs off.
        let rows: Vec<&str> = i.rows().iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            rows,
            [
                "eth1", "lan1", "lan2", "lan3", "lan4", "phy0-ap0", "phy1-ap0"
            ]
        );
    }

    #[test]
    fn speeds_as_ubus_writes_them() {
        use serde_json::json;
        assert_eq!(speed(&json!("1000F")), (Some(1000), Some(true)));
        assert_eq!(speed(&json!("100H")), (Some(100), Some(false)));
        assert_eq!(speed(&json!("2500F")), (Some(2500), Some(true)));
        assert_eq!(speed(&json!("-1F")), (None, None));
        assert_eq!(speed(&json!(null)), (None, None));
    }

    #[test]
    fn lease_left_is_only_exact_until_the_first_renewal() {
        let i = fx();
        // Up for 40 minutes of a two-hour lease: 1h 20m left.
        assert_eq!(i.wan().unwrap().lease_left(), Some(LeaseLeft::Exact(4800)));
        let mut wan = i.wan().unwrap().clone();
        // Up for weeks: renewed many times since; the router doesn't say when last.
        wan.uptime_s = 1_400_000;
        assert_eq!(wan.lease_left(), Some(LeaseLeft::Between(3600, 7200)));
        wan.up = false;
        assert_eq!(wan.lease_left(), None);
        // A static interface has no lease.
        assert_eq!(i.interfaces[0].lease_left(), None);
    }

    #[test]
    fn an_interface_that_is_down_and_an_empty_answer() {
        let text = "@@interfaces\n{\"interface\": [{\"interface\": \"wan\", \"up\": false, \
                    \"proto\": \"dhcp\", \"device\": \"eth1\", \"ipv4-address\": [], \
                    \"route\": [], \"data\": {}}]}\n";
        let i = parse(text).unwrap();
        let wan = i.wan().unwrap();
        assert!(!wan.up && wan.ipv4.is_empty() && wan.gateway.is_none());
        assert_eq!(wan.uptime_s, 0);
        assert!(i.rows().is_empty());
        assert_eq!(parse("").unwrap_err(), "ubus answered nothing");
        assert!(
            parse("@@board\n{ not json\n")
                .unwrap_err()
                .starts_with("board:")
        );
        assert!(SCRIPT.matches("ubus call").count() == 4);
    }
}

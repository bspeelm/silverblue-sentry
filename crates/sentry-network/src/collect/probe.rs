//! The 1 Hz sample: the shared `/proc` probe (`sentry_app::remote::probe`) and, in the same
//! exec, each interface's link and speed from `/sys/class/net`. The byte counters are the
//! ones `/proc/net/dev` already gave; the SoC's temperature comes along when there is a thermal
//! zone. `read` instead of `cat` for the small files: no forks.

use serde::{Deserialize, Serialize};

use super::{CollectError, sections};
use sentry_app::remote::{Remote, probe};

/// One interface as the kernel has it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Port {
    pub name: String,
    /// Link: None where the kernel won't say (the interface is down).
    pub carrier: Option<bool>,
    /// Mbit/s. None without a link, and where there's no such thing (lo, Wi-Fi).
    pub speed: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Probe {
    #[serde(flatten)]
    pub host: probe::Probe,
    /// The router's clock: seconds since it booted, to the hundredth (what rates divide by).
    pub uptime: f64,
    /// Every interface, by name.
    pub ports: Vec<Port>,
    /// The SoC's temperature, °C (None: no thermal zone to read).
    pub temp_c: Option<f32>,
}

/// The files with several lines, read by one `awk` that marks each with its name (one fork
/// for the four; `cat` each where there's no awk); the one-line files and `/sys` with the
/// shell's own `read` (none). On the router this is 4 ms where a `cat` per file was 11.
pub fn script() -> String {
    const MANY: &str = "/proc/stat /proc/meminfo /proc/net/dev /proc/net/route";
    format!(
        "if command -v awk >/dev/null; then \
         awk 'FNR==1{{print \"@@\" substr(FILENAME,7)}}1' {MANY}; \
         else for f in {MANY}; do echo \"@@${{f#/proc/}}\"; cat $f; done; fi; \
         for f in loadavg uptime sys/kernel/random/boot_id; do \
         IFS= read -r l </proc/$f; echo \"@@$f\"; echo \"$l\"; done; \
         echo @@ifs; cd /sys/class/net && for n in *; do \
         read c <$n/carrier 2>/dev/null || c=-; read s <$n/speed 2>/dev/null || s=-; \
         echo \"$n $c $s\"; done; \
         echo @@temp; read t </sys/class/thermal/thermal_zone0/temp 2>/dev/null && echo $t; \
         true"
    )
}

pub fn collect(r: &Remote) -> Result<Probe, CollectError> {
    parse(&r.output(&r.sh(&script()))?).map_err(CollectError::Parse)
}

pub fn parse(text: &str) -> Result<Probe, String> {
    let host = probe::parse(text)?;
    let mut uptime = host.uptime_s as f64;
    let mut counters: Vec<(&str, u64, u64)> = Vec::new();
    let mut ifs = None;
    let mut temp_c = None;
    for (name, body) in sections(text) {
        match name {
            "uptime" => {
                if let Some(u) = body.split_whitespace().next().and_then(|x| x.parse().ok()) {
                    uptime = u;
                }
            }
            "net/dev" => {
                for l in body.lines() {
                    let Some((name, rest)) = l.split_once(':') else {
                        continue;
                    };
                    let v: Vec<u64> = rest
                        .split_whitespace()
                        .filter_map(|x| x.parse().ok())
                        .collect();
                    if let (Some(rx), Some(tx)) = (v.first(), v.get(8)) {
                        counters.push((name.trim(), *rx, *tx));
                    }
                }
            }
            "ifs" => ifs = Some(body),
            // Millidegrees.
            "temp" => temp_c = body.trim().parse::<f32>().ok().map(|m| m / 1000.0),
            _ => {}
        }
    }
    let bytes = |n: &str| {
        counters
            .iter()
            .find(|c| c.0 == n)
            .map_or((0, 0), |c| (c.1, c.2))
    };
    let mut ports: Vec<Port> = match ifs {
        Some(body) => body
            .lines()
            .filter_map(|l| {
                let mut w = l.split_whitespace();
                let name = w.next()?;
                let carrier = match w.next() {
                    Some("1") => Some(true),
                    Some("0") => Some(false),
                    _ => None,
                };
                // `-1` without a link; nothing or `-` where reading it is an error.
                let speed = w
                    .next()
                    .and_then(|s| s.parse::<i64>().ok())
                    .filter(|s| *s > 0)
                    .map(|s| s as u32);
                let (rx_bytes, tx_bytes) = bytes(name);
                Some(Port {
                    name: name.to_string(),
                    carrier,
                    speed: speed.filter(|_| carrier != Some(false)),
                    rx_bytes,
                    tx_bytes,
                })
            })
            .collect(),
        // No /sys there: the counters alone.
        None => counters
            .iter()
            .map(|(n, rx, tx)| Port {
                name: n.to_string(),
                carrier: None,
                speed: None,
                rx_bytes: *rx,
                tx_bytes: *tx,
            })
            .collect(),
    };
    ports.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Probe {
        host,
        uptime,
        ports,
        temp_c,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_bundle_with_every_port() {
        let p = parse(&super::super::fixture("network/probe.txt")).unwrap();
        assert_eq!(p.host.cores, 4);
        assert_eq!(p.host.load, [0.42, 0.31, 0.18]);
        assert_eq!((p.host.uptime_s, p.uptime), (1_363_000, 1_363_000.25));
        assert_eq!(p.host.iface.as_deref(), Some("eth1"));
        assert_eq!(p.host.boot_id, "3f8a1c52-7d04-4e9b-a6c1-52d0b7e4f913");
        assert!((p.host.mem_used_pct() - 20.9).abs() < 0.1);
        let names: Vec<&str> = p.ports.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "br-lan", "eth0", "eth1", "lan1", "lan2", "lan3", "lan4", "lo", "phy0-ap0",
                "phy1-ap0"
            ]
        );
        let port = |n: &str| p.ports.iter().find(|x| x.name == n).unwrap();
        assert_eq!(
            port("eth1"),
            &Port {
                name: "eth1".into(),
                carrier: Some(true),
                speed: Some(1000),
                rx_bytes: 755_100_000_000,
                tx_bytes: 101_000_000_000,
            }
        );
        assert_eq!(port("lan2").speed, Some(100));
        // No link: the kernel says -1, which is no speed.
        assert_eq!(
            (port("lan3").carrier, port("lan3").speed),
            (Some(false), None)
        );
        // Speed can't be read on lo (nothing printed) nor on Wi-Fi (`-`): absent, no error.
        assert_eq!((port("lo").carrier, port("lo").speed), (Some(true), None));
        assert_eq!(port("phy1-ap0").speed, None);
        assert_eq!(port("phy1-ap0").tx_bytes, 590_000_000_000);
        assert_eq!(p.temp_c, Some(51.5));
    }

    #[test]
    fn without_sys_the_counters_still_name_the_ports() {
        let text = super::super::fixture("network/probe.txt");
        let cut = &text[..text.find("@@ifs").unwrap()];
        let p = parse(cut).unwrap();
        assert_eq!(p.ports.len(), 10);
        assert!(p.ports.iter().all(|x| x.carrier.is_none()));
        // No thermal zone: nothing after the mark.
        assert_eq!(p.temp_c, None);
        assert_eq!(parse(&format!("{cut}@@temp\n")).unwrap().temp_c, None);
        // An interface that's down: carrier can't be read either.
        let p = parse(&format!("{cut}@@ifs\nlan9 - -\n")).unwrap();
        assert_eq!(p.ports[0].carrier, None);
        assert_eq!(p.ports[0].rx_bytes, 0);
        assert!(parse("@@ifs\nlo 1 -\n").is_err(), "no cpu line");
    }

    #[test]
    fn one_exec_reads_proc_and_sys_with_one_fork() {
        let s = script();
        assert!(
            s.contains("awk 'FNR==1{print \"@@\" substr(FILENAME,7)}1' /proc/stat /proc/meminfo")
        );
        assert!(s.contains("echo @@ifs; cd /sys/class/net && for n in *;"));
        assert!(s.ends_with(
            "read t </sys/class/thermal/thermal_zone0/temp 2>/dev/null && echo $t; true"
        ));
        assert!(!s.contains("$("), "no subshells: they fork");
        assert_eq!(
            s.matches("cat ").count(),
            1,
            "cat only where there's no awk"
        );
    }

    /// The script, run here by a local `sh` (this machine has /proc and /sys too): what it
    /// prints parses, by the awk path and by the one without.
    #[test]
    fn the_script_runs_and_parses_with_and_without_awk() {
        use sentry_core::exec::Cmd;
        let with = Cmd::local("sh").args(["-c", &script()]).output().unwrap();
        let p = parse(&with).unwrap();
        assert!(p.host.cores >= 1 && p.uptime > 0.0 && !p.host.boot_id.is_empty());
        assert!(p.host.mem_total_kib > 0);
        assert!(p.ports.iter().any(|x| x.name == "lo"), "{:?}", p.ports);
        let marks: Vec<&str> = sections(&with).into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            marks,
            [
                "stat",
                "meminfo",
                "net/dev",
                "net/route",
                "loadavg",
                "uptime",
                "sys/kernel/random/boot_id",
                "ifs",
                "temp"
            ]
        );
        // No awk: the same marks, by `cat`.
        let without = script().replace("command -v awk", "command -v no-such-awk");
        let out = Cmd::local("sh").args(["-c", &without]).output().unwrap();
        let q = parse(&out).unwrap();
        assert_eq!(
            sections(&out)
                .into_iter()
                .map(|(n, _)| n)
                .collect::<Vec<_>>(),
            marks
        );
        assert_eq!((q.host.cores, q.ports.len()), (p.host.cores, p.ports.len()));
        // No thermal zone: still a success, with no temperature.
        let cold = script().replace("thermal_zone0", "thermal_zone-none");
        let out = Cmd::local("sh").args(["-c", &cold]).output().unwrap();
        assert_eq!(parse(&out).unwrap().temp_c, None);
    }
}

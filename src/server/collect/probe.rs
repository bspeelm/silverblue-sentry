//! The 1 Hz sample: several `/proc` files in one round trip, separated by `@@name` lines.

use serde::{Deserialize, Serialize};

use super::super::remote::{Remote, SrvError};
use crate::collectors::system::meminfo_kib;

const FILES: &[&str] = &[
    "stat",
    "loadavg",
    "uptime",
    "meminfo",
    "net/dev",
    "net/route",
    "sys/kernel/random/boot_id",
];

/// Total and idle jiffies from the aggregate `cpu` line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct CpuTimes {
    pub total: u64,
    pub idle: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Probe {
    pub cpu: CpuTimes,
    pub cores: usize,
    pub load: [f32; 3],
    pub uptime_s: u64,
    pub mem_total_kib: u64,
    pub mem_avail_kib: u64,
    pub swap_total_kib: u64,
    pub swap_free_kib: u64,
    /// Interface of the default route, with its byte counters.
    pub iface: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub boot_id: String,
}

impl Probe {
    pub fn mem_used_pct(&self) -> f32 {
        if self.mem_total_kib == 0 {
            return 0.0;
        }
        100.0 * (self.mem_total_kib - self.mem_avail_kib.min(self.mem_total_kib)) as f32
            / self.mem_total_kib as f32
    }
}

pub fn script() -> String {
    FILES
        .iter()
        .map(|f| format!("echo @@{f}; cat /proc/{f}"))
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn collect(r: &Remote) -> Result<Probe, SrvError> {
    parse(&r.output(&r.sh(&script()))?).map_err(SrvError::Parse)
}

fn sections(text: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("@@") {
        rest = &rest[i + 2..];
        let (name, body) = rest.split_once('\n').unwrap_or((rest, ""));
        let end = body.find("\n@@").map_or(body.len(), |e| e + 1);
        out.push((name.trim(), &body[..end]));
        rest = &body[end..];
    }
    out
}

pub fn parse(text: &str) -> Result<Probe, String> {
    let mut p = Probe::default();
    let mut route = "";
    let mut netdev = "";
    for (name, body) in sections(text) {
        match name {
            "stat" => {
                for l in body.lines() {
                    if let Some(rest) = l.strip_prefix("cpu ") {
                        let v: Vec<u64> = rest
                            .split_whitespace()
                            .filter_map(|x| x.parse().ok())
                            .collect();
                        // user nice system idle iowait irq softirq steal (guest is in user)
                        let total: u64 = v.iter().take(8).sum();
                        let idle = v.get(3).copied().unwrap_or(0) + v.get(4).copied().unwrap_or(0);
                        p.cpu = CpuTimes { total, idle };
                    } else if l.starts_with("cpu") {
                        p.cores += 1;
                    }
                }
            }
            "loadavg" => {
                let v: Vec<f32> = body
                    .split_whitespace()
                    .take(3)
                    .filter_map(|x| x.parse().ok())
                    .collect();
                if v.len() == 3 {
                    p.load = [v[0], v[1], v[2]];
                }
            }
            "uptime" => {
                p.uptime_s = body
                    .split_whitespace()
                    .next()
                    .and_then(|x| x.parse::<f64>().ok())
                    .unwrap_or(0.0) as u64;
            }
            "meminfo" => {
                p.mem_total_kib = meminfo_kib(body, "MemTotal");
                p.mem_avail_kib = meminfo_kib(body, "MemAvailable");
                p.swap_total_kib = meminfo_kib(body, "SwapTotal");
                p.swap_free_kib = meminfo_kib(body, "SwapFree");
            }
            "net/dev" => netdev = body,
            "net/route" => route = body,
            "sys/kernel/random/boot_id" => p.boot_id = body.trim().to_string(),
            _ => {}
        }
    }
    if p.cpu.total == 0 {
        return Err("no cpu line in /proc/stat".into());
    }
    p.iface = crate::collectors::system::parse_default_iface(route);
    if let Some(ifc) = &p.iface {
        for l in netdev.lines() {
            if let Some((name, rest)) = l.split_once(':')
                && name.trim() == ifc
            {
                let v: Vec<u64> = rest
                    .split_whitespace()
                    .filter_map(|x| x.parse().ok())
                    .collect();
                p.rx_bytes = v.first().copied().unwrap_or(0);
                p.tx_bytes = v.get(8).copied().unwrap_or(0);
            }
        }
    }
    Ok(p)
}

/// CPU % between consecutive samples.
#[derive(Debug, Default)]
pub struct CpuDelta {
    prev: Option<CpuTimes>,
}

impl CpuDelta {
    pub fn pct(&mut self, now: CpuTimes) -> Option<f32> {
        let prev = self.prev.replace(now)?;
        let total = now.total.checked_sub(prev.total)?;
        let idle = now.idle.checked_sub(prev.idle)?;
        (total > 0).then(|| 100.0 * (total - idle.min(total)) as f32 / total as f32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_bundle() {
        let p = parse(&super::super::fixture("probe.txt")).unwrap();
        assert_eq!(p.cores, 4);
        assert_eq!(
            p.cpu,
            CpuTimes {
                total: 1_150_000,
                idle: 1_002_000
            }
        );
        assert_eq!(p.load, [0.31, 0.27, 0.22]);
        assert_eq!(p.uptime_s, 1_209_731);
        assert_eq!(p.iface.as_deref(), Some("eth0"));
        assert_eq!((p.rx_bytes, p.tx_bytes), (12_345_678_901, 9_876_543_210));
        assert_eq!(p.boot_id, "5d1c7a3e-0f6b-4b8e-9b51-2f0c1e7d9a44");
        assert!(
            (p.mem_used_pct() - 36.3).abs() < 0.1,
            "{}",
            p.mem_used_pct()
        );
    }

    #[test]
    fn cpu_percent_from_two_samples() {
        let mut d = CpuDelta::default();
        assert_eq!(
            d.pct(CpuTimes {
                total: 1000,
                idle: 900
            }),
            None
        );
        assert_eq!(
            d.pct(CpuTimes {
                total: 1100,
                idle: 975
            }),
            Some(25.0)
        );
        // A counter going backwards (reboot) gives nothing rather than nonsense.
        assert_eq!(d.pct(CpuTimes { total: 10, idle: 5 }), None);
    }
}

//! CPU, memory, swap, load, uptime, temperatures and NIC throughput (sysinfo + /proc).
//! One long-lived `Sampler` lives in the TUI; refreshes are selective to stay cheap.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sysinfo::{Components, CpuRefreshKind, MemoryRefreshKind, Networks, RefreshKind, System};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemSnap {
    pub cpu_model: String,
    pub threads: usize,
    pub cores: Option<usize>,
    pub cpu_total: f32,
    pub per_core: Vec<f32>,
    pub load: [f64; 3],
    pub uptime_s: u64,
    pub mem: Mem,
    pub swap: Swap,
    pub temps: Temps,
    pub net: NetIo,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Mem {
    pub total: u64,
    pub used: u64,
    pub avail: u64,
    pub cache: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Swap {
    pub total: u64,
    pub used: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Temps {
    pub cpu: Option<f32>,
    pub nvme: Vec<f32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetIo {
    pub iface: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

pub struct Sampler {
    sys: System,
    comps: Components,
    nets: Networks,
    last_net: Option<Instant>,
    last_comps: Option<Instant>,
    iface: String,
    temps: Temps,
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

impl Sampler {
    pub fn new() -> Self {
        let sys = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                .with_memory(MemoryRefreshKind::everything()),
        );
        Self {
            sys,
            comps: Components::new(),
            nets: Networks::new_with_refreshed_list(),
            last_net: Some(Instant::now()),
            last_comps: None,
            iface: default_iface().unwrap_or_default(),
            temps: Temps::default(),
        }
    }

    /// For one-shot CLI use: CPU usage needs two samples.
    pub fn sample_settled(&mut self) -> SystemSnap {
        self.sample();
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(Duration::from_millis(250)));
        self.last_comps = None;
        self.sample()
    }

    pub fn sample(&mut self) -> SystemSnap {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();

        let now = Instant::now();
        let elapsed = self
            .last_net
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(1.0)
            .max(0.001);
        self.nets.refresh(true);
        self.last_net = Some(now);
        let (rx, tx) = self
            .nets
            .list()
            .get(&self.iface)
            .map(|d| {
                (
                    d.received() as f64 / elapsed,
                    d.transmitted() as f64 / elapsed,
                )
            })
            .unwrap_or_default();

        // Temperatures change slowly and hwmon reads aren't free.
        if self
            .last_comps
            .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(5))
        {
            if self.comps.list().is_empty() {
                self.comps.refresh(true);
            } else {
                self.comps.refresh(false);
            }
            self.temps = temps(&self.comps);
            self.last_comps = Some(now);
        }

        let la = System::load_average();
        let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let swaps = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
        let cpus = self.sys.cpus();
        SystemSnap {
            cpu_model: cpus
                .first()
                .map(|c| short_cpu_model(c.brand()))
                .unwrap_or_default(),
            threads: cpus.len(),
            cores: System::physical_core_count(),
            cpu_total: self.sys.global_cpu_usage(),
            per_core: cpus.iter().map(|c| c.cpu_usage()).collect(),
            load: [la.one, la.five, la.fifteen],
            uptime_s: System::uptime(),
            mem: Mem {
                total: self.sys.total_memory(),
                used: self.sys.used_memory(),
                avail: self.sys.available_memory(),
                cache: meminfo_kib(&meminfo, "Cached:") * 1024,
            },
            swap: Swap {
                total: self.sys.total_swap(),
                used: self.sys.used_swap(),
                kind: swap_kind(&swaps),
            },
            temps: self.temps.clone(),
            net: NetIo {
                iface: self.iface.clone(),
                rx_bps: rx,
                tx_bps: tx,
            },
        }
    }
}

fn temps(comps: &Components) -> Temps {
    let mut t = Temps::default();
    for c in comps.list() {
        let label = c.label();
        let Some(v) = c.temperature().filter(|v| v.is_finite() && *v > 0.0) else {
            continue;
        };
        if label.contains("Package id 0") || label.contains("Tctl") || label.contains("Tdie") {
            t.cpu = Some(v);
        } else if label.starts_with("nvme") && label.contains("Composite") {
            t.nvme.push(v);
        }
    }
    t
}

/// `Intel(R) Core(TM) i9-14900K` → `i9-14900K`; `AMD Ryzen 7 7700X 8-Core Processor` → `Ryzen 7 7700X`.
pub fn short_cpu_model(brand: &str) -> String {
    let mut s = brand
        .replace("(R)", "")
        .replace("(TM)", "")
        .replace("Intel Core", "")
        .replace("AMD ", "");
    if let Some(i) = s.find(" Processor") {
        s.truncate(i);
    }
    let s = s.trim();
    let s = match s.rsplit_once(' ') {
        Some((head, tail)) if tail.ends_with("-Core") => head,
        _ => s,
    };
    s.trim().trim_start_matches("Intel").trim().to_string()
}

pub fn meminfo_kib(meminfo: &str, key: &str) -> u64 {
    meminfo
        .lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

pub fn swap_kind(proc_swaps: &str) -> String {
    let devs: Vec<&str> = proc_swaps
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    match devs.as_slice() {
        [] => "none".into(),
        d if d.iter().all(|d| d.starts_with("/dev/zram")) => "zram".into(),
        _ => "file".into(),
    }
}

/// Interface of the default IPv4 route, from /proc/net/route.
pub fn default_iface() -> Option<String> {
    parse_default_iface(&std::fs::read_to_string("/proc/net/route").ok()?)
}

pub fn parse_default_iface(route: &str) -> Option<String> {
    route.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 2 && f[1] == "00000000").then(|| f[0].to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_model_shortening() {
        assert_eq!(short_cpu_model("Intel(R) Core(TM) i9-14900K"), "i9-14900K");
        assert_eq!(
            short_cpu_model("AMD Ryzen 7 7700X 8-Core Processor"),
            "Ryzen 7 7700X"
        );
    }

    #[test]
    fn proc_parsers() {
        assert_eq!(
            meminfo_kib("MemTotal: 10 kB\nCached:   6400 kB\n", "Cached:"),
            6400
        );
        assert_eq!(
            swap_kind("Filename Type\n/dev/zram0 partition 8388604 0 100\n"),
            "zram"
        );
        assert_eq!(swap_kind("Filename Type\n"), "none");
        let route = "Iface\tDestination\tGateway\nwlp0s20f3\t0000A8C0\t00000000\nenp6s0\t00000000\t0101A8C0\n";
        assert_eq!(parse_default_iface(route).as_deref(), Some("enp6s0"));
    }
}

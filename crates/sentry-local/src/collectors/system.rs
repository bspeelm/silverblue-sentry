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

pub use super::procfs::{default_iface, meminfo_kib, parse_default_iface, swap_kind};

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
}

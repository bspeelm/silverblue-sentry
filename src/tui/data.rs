//! Everything the screens render from. Mutated only on the main thread; background fetches
//! arrive as `Event::Data` and are applied here.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::Instant;

use jiff::Timestamp;

use super::Event;
use crate::cache::{self, Cached};
use crate::collectors::breakdown::{self, Breakdown};
use crate::collectors::disk::{self, Mount};
use crate::collectors::flatpak::{self, FpUpdate, Flatpak};
use crate::collectors::gpu::{self, Gpu};
use crate::collectors::net::{self, Counts, Net};
use crate::collectors::ostree::{self, Ostree};
use crate::collectors::podman::{self, Podman};
use crate::collectors::processes::{ProcSampler, Proc};
use crate::collectors::system::{Sampler, SystemSnap};
use crate::collectors::units::{self, Units};
use crate::collectors::{CollectError, Ctx};
use crate::config::Config;
use crate::exec::Cmd;

/// Background work the UI can request. At most one of each kind is in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fetch {
    Gpu,
    Disks,
    Breakdown,
    Net,
    Ostree,
    /// `rpm-ostree upgrade --preview`, then re-read status.
    OstreeCheck,
    Flatpak,
    FlatpakUpdates,
    Podman,
    Units,
}

pub enum Payload {
    Gpu(Option<Gpu>),
    Disks(Vec<Mount>),
    Breakdown(Cached<Breakdown>),
    Net(Net),
    Ostree(Ostree),
    OstreeChecked(Ostree, Timestamp),
    Flatpak(Flatpak),
    FlatpakUpdates(Cached<Vec<FpUpdate>>),
    Podman(Podman),
    Units(Units),
}

#[derive(Debug, Clone)]
pub enum FetchErr {
    Unavailable(String),
    Failed(String),
}

impl FetchErr {
    pub fn text(&self) -> String {
        match self {
            FetchErr::Unavailable(b) => format!("— {b} not found"),
            FetchErr::Failed(e) => format!("✗ {}", e.lines().next().unwrap_or(e)),
        }
    }
}

impl From<CollectError> for FetchErr {
    fn from(e: CollectError) -> Self {
        match e {
            CollectError::Unavailable(b) => FetchErr::Unavailable(b),
            e => FetchErr::Failed(e.to_string()),
        }
    }
}

/// A value fetched in the background, plus when and whether it failed.
#[derive(Debug)]
pub struct Slot<T> {
    pub value: Option<T>,
    pub at: Option<Instant>,
    pub err: Option<FetchErr>,
}

impl<T> Default for Slot<T> {
    fn default() -> Self {
        Self { value: None, at: None, err: None }
    }
}

impl<T> Slot<T> {
    pub fn set(&mut self, r: Result<T, FetchErr>) {
        self.at = Some(Instant::now());
        match r {
            Ok(v) => {
                self.value = Some(v);
                self.err = None;
            }
            Err(e) => self.err = Some(e),
        }
    }

    pub fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Status text for an empty slot: loading or error.
    pub fn status(&self, loading: bool) -> String {
        match (&self.err, loading) {
            (Some(e), _) => e.text(),
            (None, true) => "loading…".into(),
            (None, false) => "—".into(),
        }
    }
}

pub const HIST: usize = 240;

#[derive(Default)]
pub struct Ring(pub VecDeque<f64>);

impl Ring {
    pub fn push(&mut self, v: f64) {
        if self.0.len() == HIST {
            self.0.pop_front();
        }
        self.0.push_back(v);
    }

    pub fn vec(&self) -> Vec<f64> {
        self.0.iter().copied().collect()
    }

}

pub struct DataStore {
    pub sampler: Option<Sampler>,
    pub sys: Option<SystemSnap>,
    pub cpu_hist: Ring,
    pub rx_hist: Ring,
    pub tx_hist: Ring,
    pub counts: Option<Counts>,

    pub proc_sampler: Option<ProcSampler>,
    pub procs: Vec<Proc>,

    pub gpu: Slot<Option<Gpu>>,
    pub disks: Slot<Vec<Mount>>,
    pub breakdown: Slot<Cached<Breakdown>>,
    pub net: Slot<Net>,
    pub ostree: Slot<Ostree>,
    pub ostree_checked: Option<Timestamp>,
    pub flatpak: Slot<Flatpak>,
    pub fp_updates: Slot<Cached<Vec<FpUpdate>>>,
    pub podman: Slot<Podman>,
    pub units: Slot<Units>,

    pub inflight: HashSet<Fetch>,
    pub os_version: String,
    pub kernel: String,
}

impl DataStore {
    pub fn new() -> Self {
        let mut d = Self::blank(os_version(), ostree::booted_kernel());
        d.ostree_checked = cache::load::<serde_json::Value>(cache::OSTREE_CHECK).map(|c| c.fetched_at);
        // Cached results are shown immediately with their age; never refreshed automatically.
        if let Some(c) = cache::load(cache::FLATPAK_UPDATES) {
            d.fp_updates.set(Ok(c));
        }
        if let Some(c) = cache::load(cache::DISK_BREAKDOWN) {
            d.breakdown.set(Ok(c));
        }
        d
    }

    /// No disk access: used by `new` and by render tests.
    pub fn blank(os_version: String, kernel: String) -> Self {
        Self {
            sampler: None,
            sys: None,
            cpu_hist: Ring::default(),
            rx_hist: Ring::default(),
            tx_hist: Ring::default(),
            counts: None,
            proc_sampler: None,
            procs: Vec::new(),
            gpu: Slot::default(),
            disks: Slot::default(),
            breakdown: Slot::default(),
            net: Slot::default(),
            ostree: Slot::default(),
            ostree_checked: None,
            flatpak: Slot::default(),
            fp_updates: Slot::default(),
            podman: Slot::default(),
            units: Slot::default(),
            inflight: HashSet::new(),
            os_version,
            kernel,
        }
    }

    pub fn loading(&self, f: Fetch) -> bool {
        self.inflight.contains(&f)
    }

    /// Sample CPU/mem/net (main thread; cheap).
    pub fn sample_system(&mut self) {
        let s = self.sampler.get_or_insert_with(Sampler::new).sample();
        self.cpu_hist.push(s.cpu_total as f64);
        self.rx_hist.push(s.net.rx_bps);
        self.tx_hist.push(s.net.tx_bps);
        self.sys = Some(s);
    }

    pub fn sample_counts(&mut self) {
        self.counts = Some(net::proc_counts());
    }

    pub fn sample_procs(&mut self) {
        self.procs = self.proc_sampler.get_or_insert_with(ProcSampler::new).sample();
    }

    pub fn apply(&mut self, f: Fetch, r: Result<Payload, FetchErr>) {
        self.inflight.remove(&f);
        macro_rules! put {
            ($slot:ident, $pat:path) => {
                self.$slot.set(r.map(|p| match p {
                    $pat(v) => v,
                    _ => unreachable!("payload kind matches fetch"),
                }))
            };
        }
        match f {
            Fetch::Gpu => put!(gpu, Payload::Gpu),
            Fetch::Disks => put!(disks, Payload::Disks),
            Fetch::Breakdown => put!(breakdown, Payload::Breakdown),
            Fetch::Net => put!(net, Payload::Net),
            Fetch::Ostree => put!(ostree, Payload::Ostree),
            Fetch::OstreeCheck => match r {
                Ok(Payload::OstreeChecked(o, ts)) => {
                    self.ostree_checked = Some(ts);
                    self.ostree.set(Ok(o));
                }
                Err(e) => self.ostree.err = Some(e),
                Ok(_) => unreachable!(),
            },
            Fetch::Flatpak => put!(flatpak, Payload::Flatpak),
            Fetch::FlatpakUpdates => put!(fp_updates, Payload::FlatpakUpdates),
            Fetch::Podman => put!(podman, Payload::Podman),
            Fetch::Units => put!(units, Payload::Units),
        }
    }

    /// Start a background fetch unless one of the same kind is already running.
    pub fn fetch(&mut self, f: Fetch, cfg: &Arc<Config>, tx: &Sender<Event>) {
        if !self.inflight.insert(f) {
            return;
        }
        let cfg = Arc::clone(cfg);
        let tx = tx.clone();
        std::thread::spawn(move || {
            let ctx = Ctx::new((*cfg).clone());
            let r = run_fetch(f, &ctx);
            let _ = tx.send(Event::Data(f, r));
        });
    }
}

fn run_fetch(f: Fetch, ctx: &Ctx) -> Result<Payload, FetchErr> {
    let stored = |key: &str, r: anyhow::Result<Timestamp>| -> Result<Timestamp, FetchErr> {
        r.map_err(|e| FetchErr::Failed(format!("cache {key}: {e}")))
    };
    Ok(match f {
        Fetch::Gpu => Payload::Gpu(gpu::collect()?),
        Fetch::Disks => Payload::Disks(disk::collect()?),
        Fetch::Breakdown => {
            let b = breakdown::collect(ctx);
            let at = stored(cache::DISK_BREAKDOWN, cache::store(cache::DISK_BREAKDOWN, &b))?;
            Payload::Breakdown(Cached { fetched_at: at, data: b })
        }
        Fetch::Net => Payload::Net(net::collect(ctx)?),
        Fetch::Ostree => Payload::Ostree(ostree::collect()?),
        Fetch::OstreeCheck => {
            let out = Cmd::host("rpm-ostree")
                .args(["upgrade", "--preview"])
                .timeout(Some(std::time::Duration::from_secs(600)))
                .run()
                .map_err(CollectError::from)?;
            // Exit 77 means "no updates" for --check; --preview returns 0 either way.
            if out.code != 0 && out.code != 77 {
                return Err(FetchErr::Failed(format!("rpm-ostree upgrade --preview: {}", out.stderr.trim())));
            }
            let at = stored(cache::OSTREE_CHECK, cache::store(cache::OSTREE_CHECK, &serde_json::json!({})))?;
            Payload::OstreeChecked(ostree::collect()?, at)
        }
        Fetch::Flatpak => Payload::Flatpak(flatpak::collect(ctx)?),
        Fetch::FlatpakUpdates => {
            let u = flatpak::collect_updates()?;
            let at = stored(cache::FLATPAK_UPDATES, cache::store(cache::FLATPAK_UPDATES, &u))?;
            Payload::FlatpakUpdates(Cached { fetched_at: at, data: u })
        }
        Fetch::Podman => Payload::Podman(podman::collect(ctx)?),
        Fetch::Units => Payload::Units(units::collect(ctx)?),
    })
}

/// `44.20261002.0` from host os-release `VERSION="44.20261002.0 (Silverblue)"`.
fn os_version() -> String {
    let text = std::fs::read_to_string(crate::paths::host("/etc/os-release")).unwrap_or_default();
    parse_os_version(&text)
}

pub fn parse_os_version(text: &str) -> String {
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k))
            .map(|v| v.trim_matches('"').to_string())
    };
    get("VERSION=")
        .map(|v| v.split(' ').next().unwrap_or(&v).to_string())
        .or_else(|| get("VERSION_ID="))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #[test]
    fn os_release() {
        assert_eq!(
            super::parse_os_version("NAME=\"Fedora Linux\"\nVERSION=\"44.20261002.0 (Silverblue)\"\nVERSION_ID=44\n"),
            "44.20261002.0"
        );
    }
}

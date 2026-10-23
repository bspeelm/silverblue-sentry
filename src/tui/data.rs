//! Everything the screens render from. Mutated only on the main thread; background fetches
//! arrive as `Event::Data` and are applied here.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::Instant;

use jiff::Timestamp;

use super::Event;
use super::screens::history::HistData;
use super::screens::upgrade::WfInfo;
use crate::audit::store::Stored;
use crate::baseline::Baseline;
use crate::cache::{self, Cached};
use crate::collectors::breakdown::{self, Breakdown};
use crate::collectors::disk::{self, Mount};
use crate::collectors::flatpak::{self, Flatpak, FpUpdate};
use crate::collectors::gpu::{self, Gpu};
use crate::collectors::net::{self, Counts, Net};
use crate::collectors::ostree::{self, Ostree};
use crate::collectors::podman::{self, Podman};
use crate::collectors::processes::{Proc, ProcSampler};
use crate::collectors::system::{Sampler, SystemSnap};
use crate::collectors::units::{self, Units};
use crate::collectors::{CollectError, Ctx};
use crate::config::Config;
use crate::jobs::JobId;
use crate::jobs::plan::Plan;
use crate::jobs::state::Runs;

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
    /// Stored audit reports (`reports/*.json`).
    Reports,
    /// `jobs.json` last-run records.
    Jobs,
    /// Plans of the four cleanup jobs (Cleanup screen).
    Cleanup,
    /// One job's plan, for its confirm modal.
    Plan(JobId),
    /// Workflow files, lint results and last runs (Upgrade screen).
    Workflows,
    /// Recorder ring file + status (History screen).
    History,
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
    Reports(Vec<Stored>),
    Jobs(Runs),
    Cleanup(Vec<Plan>),
    Plan(Plan),
    Workflows(Vec<WfInfo>),
    History(Box<HistData>),
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
        Self {
            value: None,
            at: None,
            err: None,
        }
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
    pub reports: Slot<Vec<Stored>>,
    pub job_runs: Slot<Runs>,
    pub cleanup: Slot<Vec<Plan>>,
    /// The most recent single-job plan (consumed by the app to open a modal).
    pub plan: Option<Plan>,
    pub workflows: Slot<Vec<WfInfo>>,
    pub history: Slot<Box<HistData>>,
    /// The recorder process, checked with the dashboard's slow refresh.
    pub recorder: Option<crate::recorder::Live>,
    /// Effective baseline; reloaded after the TUI writes baseline.toml.
    pub baseline: Baseline,

    pub inflight: HashSet<Fetch>,
    pub os_version: String,
    pub kernel: String,
}

impl DataStore {
    pub fn new() -> Self {
        let mut d = Self::blank(crate::paths::os_version(), ostree::booted_kernel());
        d.baseline = Baseline::effective(&Config::load().0);
        d.ostree_checked =
            cache::load::<serde_json::Value>(cache::OSTREE_CHECK).map(|c| c.fetched_at);
        // Cached results are shown immediately with their age; never refreshed automatically.
        if let Some(c) = cache::load(cache::FLATPAK_UPDATES) {
            d.fp_updates.set(Ok(c));
        }
        if let Some(c) = cache::load(cache::DISK_BREAKDOWN) {
            d.breakdown.set(Ok(c));
        }
        d.recorder = crate::recorder::live();
        d.prefill_from_recording();
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
            reports: Slot::default(),
            job_runs: Slot::default(),
            cleanup: Slot::default(),
            plan: None,
            workflows: Slot::default(),
            history: Slot::default(),
            recorder: None,
            baseline: Baseline::default(),
            inflight: HashSet::new(),
            os_version,
            kernel,
        }
    }

    /// Spec §10: the dashboard graphs extend back over the recording (one point per sample).
    fn prefill_from_recording(&mut self) {
        let Some((_, recs)) = crate::recorder::ring::read_metrics(&crate::recorder::ring::path())
        else {
            return;
        };
        let now = Timestamp::now().as_second();
        // Only a recent recording: an old one would splice a stale past onto the live graph.
        if recs.last().is_none_or(|r| now - r.ts > 300) {
            return;
        }
        for r in &recs[recs.len().saturating_sub(HIST)..] {
            self.cpu_hist.push(r.cpu as f64);
            self.rx_hist.push(r.rx as f64);
            self.tx_hist.push(r.tx as f64);
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
        self.procs = self
            .proc_sampler
            .get_or_insert_with(ProcSampler::new)
            .sample();
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
            Fetch::Reports => put!(reports, Payload::Reports),
            Fetch::Jobs => put!(job_runs, Payload::Jobs),
            Fetch::Cleanup => put!(cleanup, Payload::Cleanup),
            Fetch::Workflows => put!(workflows, Payload::Workflows),
            Fetch::History => put!(history, Payload::History),
            Fetch::Plan(_) => {
                self.plan = match r {
                    Ok(Payload::Plan(p)) => Some(p),
                    _ => None,
                }
            }
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
            let _ = tx.send(Event::Data(f, Box::new(r)));
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
            let at = stored(
                cache::DISK_BREAKDOWN,
                cache::store(cache::DISK_BREAKDOWN, &b),
            )?;
            Payload::Breakdown(Cached {
                fetched_at: at,
                data: b,
            })
        }
        Fetch::Net => Payload::Net(net::collect(ctx)?),
        Fetch::Ostree => Payload::Ostree(ostree::collect()?),
        Fetch::OstreeCheck => {
            let o = crate::jobs::check_ostree()?;
            let at = cache::load::<serde_json::Value>(cache::OSTREE_CHECK)
                .map_or_else(Timestamp::now, |c| c.fetched_at);
            // `c` is the update-check job, so its cadence resets.
            let n = o
                .update
                .as_ref()
                .map_or(0, |u| u.upgraded.len() + u.added.len());
            let _ = crate::jobs::state::record(
                crate::jobs::JobId::UpdateCheck,
                true,
                &format!("{n} ostree (from the TUI)"),
            );
            Payload::OstreeChecked(o, at)
        }
        Fetch::Flatpak => Payload::Flatpak(flatpak::collect(ctx)?),
        Fetch::FlatpakUpdates => Payload::FlatpakUpdates(crate::jobs::check_flatpak()?),
        Fetch::Podman => Payload::Podman(podman::collect(ctx)?),
        Fetch::Units => Payload::Units(units::collect(ctx)?),
        Fetch::Reports => Payload::Reports(crate::audit::store::list()),
        Fetch::Jobs => Payload::Jobs(crate::jobs::state::load()),
        Fetch::Cleanup => Payload::Cleanup(
            JobId::CLEANUP
                .iter()
                .map(|j| crate::jobs::plan::plan(*j, ctx))
                .collect(),
        ),
        Fetch::Plan(j) => Payload::Plan(crate::jobs::plan::plan(j, ctx)),
        Fetch::Workflows => Payload::Workflows(super::screens::upgrade::load_infos()),
        Fetch::History => Payload::History(Box::new(super::screens::history::load())),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn os_release() {
        assert_eq!(
            crate::paths::parse_os_version(
                "NAME=\"Fedora Linux\"\nVERSION=\"44.20261002.0 (Silverblue)\"\nVERSION_ID=44\n"
            ),
            "44.20261002.0"
        );
    }
}

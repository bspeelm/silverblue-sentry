//! What the server TUI knows, and fetching it: every fetch runs on its own thread and reports
//! back as an [`Ev::Data`]; a kind already in flight isn't started twice.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::mpsc::Sender;
use std::time::Instant;

use super::Ev;
use crate::audit::{self, Report};
use crate::collect::{self, JournalUnit, apt, docker, health, probe, units};
use crate::maint;
use crate::remote::{Remote, SrvError, SudoMode};
use sentry_core::collectors::{disk, gpu, net};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// OS and kernel, once.
    Host,
    /// How sudo behaves for this login, once.
    Sudo,
    Probe,
    /// The probe plus every process (the Processes screen's sample).
    Procs,
    Gpu,
    Temp,
    Disks,
    Units,
    Docker,
    Stats,
    Apt,
    Smart,
    Jails,
    Listeners,
    /// What listens and what's connected, without sudo (the Network screen's sample).
    Sockets,
    Journal,
    /// The newest stored report (local disk, instant).
    Report,
    /// The stored report at this index, oldest first (the report view's `[` `]`).
    ReportAt(u16),
    /// A new audit: snapshot over ssh, findings, stored.
    Audit,
    /// Maintenance items: the server's side now, upstream from the cache.
    Maint,
    /// Look upstream versions up again (from this machine, network).
    Upstream,
    /// The server's metrics ring, read from this machine's disk (no ssh).
    History,
}

pub enum Payload {
    Host(String, String),
    Sudo(SudoMode),
    Probe(probe::Probe),
    Procs(Box<collect::procs::Raw>),
    Gpu(Option<gpu::Gpu>),
    Temp(Option<health::CpuTemp>),
    Disks(Vec<disk::Mount>),
    Units(units::Units),
    Docker(docker::Docker),
    Stats(Vec<docker::Stat>),
    Apt(apt::Apt),
    Smart(Vec<Result<health::Smart, SrvError>>),
    Jails(Vec<health::Jail>),
    Listeners(Vec<net::Listener>),
    Sockets(collect::sockets::Sockets),
    Journal(Vec<JournalUnit>),
    Report(Option<Box<Report>>),
    /// A report with the one before it, and where it is among those kept.
    Reports(Box<audit::Shown>),
    Maint(
        Vec<maint::eval::Status>,
        BTreeMap<String, maint::local::Local>,
        maint::discover::Found,
    ),
    Upstream(jiff::Timestamp),
    History(Box<sentry_core::tui::histview::HistData>),
}

/// A value with when it arrived and the last error fetching it.
pub struct Slot<T> {
    pub value: Option<T>,
    pub at: Option<Instant>,
    pub err: Option<SrvError>,
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
    pub fn set(&mut self, r: Result<T, SrvError>) {
        match r {
            Ok(v) => {
                self.value = Some(v);
                self.at = Some(Instant::now());
                self.err = None;
            }
            Err(e) => self.err = Some(e),
        }
    }
}

/// What one probe added: CPU % and bytes per second since the one before (none on the
/// first, or across a reboot).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sampled {
    pub cpu: Option<f32>,
    pub rx: Option<f64>,
    pub tx: Option<f64>,
}

const HIST: usize = 240;

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
    pub fn last(&self) -> Option<f64> {
        self.0.back().copied()
    }
}

#[derive(Default)]
pub struct Store {
    pub host: Slot<(String, String)>,
    pub sudo: Slot<SudoMode>,
    pub probe: Slot<probe::Probe>,
    pub cpu_delta: probe::CpuDelta,
    pub cpu: Ring,
    pub mem: Ring,
    /// Bytes per second.
    pub rx: Ring,
    pub tx: Ring,
    last_net: Option<(u64, u64, Instant)>,
    /// The sample that just arrived, until the recorder takes it.
    pub sampled: Option<Sampled>,
    /// What was recorded for this server (the History screen).
    pub history: Slot<sentry_core::tui::histview::HistData>,
    /// The boot id seen first; a different one means the server rebooted.
    pub boot_id: Option<String>,
    /// The processes, with their share of a core since the sample before.
    pub procs: Slot<Vec<sentry_core::collectors::procs::Proc>>,
    proc_rates: collect::procs::Rates,
    /// The uid sentry-server logs in as.
    pub login_uid: Option<u32>,
    /// Each process's start time and parent, from the last sample (what a kill checks).
    pub proc_ticks: std::collections::HashMap<u32, collect::procs::Tick>,
    /// The shell that took the last sample: its ancestors are our ssh session.
    pub proc_self: Option<u32>,
    pub gpu: Slot<Option<gpu::Gpu>>,
    pub temp: Slot<Option<health::CpuTemp>>,
    pub disks: Slot<Vec<disk::Mount>>,
    pub units: Slot<units::Units>,
    pub docker: Slot<docker::Docker>,
    pub stats: Slot<Vec<docker::Stat>>,
    pub apt: Slot<apt::Apt>,
    pub smart: Slot<Vec<Result<health::Smart, SrvError>>>,
    pub jails: Slot<Vec<health::Jail>>,
    /// Listeners with the process names only root sees (sudo, or the inventory read).
    pub listeners: Slot<Vec<net::Listener>>,
    pub sockets: Slot<collect::sockets::Sockets>,
    /// What's marked expected (`servers/<name>/baseline.toml`): read at start and after
    /// each change, never while drawing.
    pub baseline: sentry_core::baseline::BaselineFile,
    pub journal: Slot<Vec<JournalUnit>>,
    pub report: Slot<Option<Box<Report>>>,
    /// What the audit report view shows (`F` on Maintenance): a report and the one before.
    pub shown: Option<audit::Shown>,
    pub maint: Slot<Vec<maint::eval::Status>>,
    /// The server's side of each item (the pinned image's repository, for planning).
    pub maint_local: Option<BTreeMap<String, maint::local::Local>>,
    /// When upstream was last looked up.
    pub upstream_at: Option<jiff::Timestamp>,
    /// What's put off with `z`, and items' review dates (`servers/<name>/later.toml`).
    pub later: sentry_core::maint::later::Snoozes,
    /// Open plans, by item (`servers/<name>/plans/<item>.md`).
    pub plans: BTreeMap<String, maint::plan::PlanDoc>,
    /// What discovery found: untracked things, tracked ones gone.
    pub maint_found: maint::discover::Found,
    /// The maintenance log, newest first (for cadences).
    pub log: Vec<maint::log::LogEntry>,
    /// The server's workflow names.
    pub workflows: Vec<String>,
    /// The latest maintenance review.
    pub review: Option<maint::review::ReviewDoc>,
    /// Tasks taken from reviews (`servers/<name>/tasks.toml`).
    pub tasks: Vec<sentry_core::maint::tasks::Task>,
    pub inflight: HashSet<Kind>,
    /// The last time ssh itself failed, and why.
    pub unreachable: Option<(Instant, String)>,
}

impl Store {
    pub fn fetch(&mut self, k: Kind, r: &Remote, tx: &Sender<Ev>) {
        if !self.inflight.insert(k) {
            return;
        }
        let r = r.clone();
        let tx = tx.clone();
        std::thread::spawn(move || {
            let res = run(k, &r);
            let _ = tx.send(Ev::Data(k, Box::new(res)));
        });
    }

    pub fn apply(&mut self, k: Kind, res: Result<Payload, SrvError>) {
        self.inflight.remove(&k);
        let res = match res {
            Err(e @ SrvError::Unreachable(_)) => {
                self.unreachable = Some((Instant::now(), e.to_string()));
                // Keep the old values: they're what was last known.
                return;
            }
            Ok(p) => {
                self.unreachable = None;
                p
            }
            Err(e) => {
                self.set_err(k, e);
                return;
            }
        };
        match res {
            Payload::Host(os, k) => self.host.set(Ok((os, k))),
            Payload::Sudo(m) => self.sudo.set(Ok(m)),
            Payload::Probe(p) => self.on_probe(p),
            // The probe is in the same sample: the Dashboard's series keep going.
            Payload::Procs(raw) => {
                self.login_uid = raw.login_uid.or(self.login_uid);
                self.proc_self = raw.self_pid;
                let procs = self.proc_rates.procs(&raw);
                self.procs.set(Ok(procs));
                self.proc_ticks = raw.ticks;
                self.on_probe(raw.probe);
            }
            Payload::Gpu(v) => self.gpu.set(Ok(v)),
            Payload::Temp(v) => self.temp.set(Ok(v)),
            Payload::Disks(v) => self.disks.set(Ok(v)),
            Payload::Units(v) => self.units.set(Ok(v)),
            Payload::Docker(v) => self.docker.set(Ok(v)),
            Payload::Stats(v) => self.stats.set(Ok(v)),
            Payload::Apt(v) => self.apt.set(Ok(v)),
            Payload::Smart(v) => self.smart.set(Ok(v)),
            Payload::Jails(v) => self.jails.set(Ok(v)),
            Payload::Listeners(v) => self.listeners.set(Ok(v)),
            Payload::Sockets(v) => self.sockets.set(Ok(v)),
            Payload::Journal(v) => self.journal.set(Ok(v)),
            Payload::Report(v) => {
                self.report.set(Ok(v));
                self.shown = None;
            }
            Payload::Reports(s) => {
                if s.latest() {
                    self.report.set(Ok(s.cur.clone()));
                }
                self.shown = Some(*s);
            }
            Payload::Maint(st, local, found) => {
                self.maint.set(Ok(st));
                self.maint_local = Some(local);
                self.maint_found = found;
            }
            Payload::Upstream(at) => self.upstream_at = Some(at),
            Payload::History(h) => self.history.set(Ok(*h)),
        }
    }

    fn set_err(&mut self, k: Kind, e: SrvError) {
        match k {
            Kind::Host => self.host.err = Some(e),
            Kind::Sudo => self.sudo.err = Some(e),
            Kind::Probe => self.probe.err = Some(e),
            Kind::Procs => self.procs.err = Some(e),
            Kind::Gpu => self.gpu.err = Some(e),
            Kind::Temp => self.temp.err = Some(e),
            Kind::Disks => self.disks.err = Some(e),
            Kind::Units => self.units.err = Some(e),
            Kind::Docker => self.docker.err = Some(e),
            Kind::Stats => self.stats.err = Some(e),
            Kind::Apt => self.apt.err = Some(e),
            Kind::Smart => self.smart.err = Some(e),
            Kind::Jails => self.jails.err = Some(e),
            Kind::Listeners => self.listeners.err = Some(e),
            Kind::Sockets => self.sockets.err = Some(e),
            Kind::Journal => self.journal.err = Some(e),
            Kind::Report | Kind::ReportAt(_) | Kind::Audit => self.report.err = Some(e),
            Kind::Maint | Kind::Upstream => self.maint.err = Some(e),
            Kind::History => self.history.err = Some(e),
        }
    }

    fn on_probe(&mut self, p: probe::Probe) {
        let mut sampled = Sampled {
            cpu: self.cpu_delta.pct(p.cpu),
            rx: None,
            tx: None,
        };
        if let Some(c) = sampled.cpu {
            self.cpu.push(c as f64);
        }
        self.mem.push(p.mem_used_pct() as f64);
        let now = Instant::now();
        if let Some((rx, tx, at)) = self.last_net {
            let dt = now.duration_since(at).as_secs_f64();
            if dt > 0.0 && p.rx_bytes >= rx && p.tx_bytes >= tx {
                sampled.rx = Some((p.rx_bytes - rx) as f64 / dt);
                sampled.tx = Some((p.tx_bytes - tx) as f64 / dt);
                self.rx.push((p.rx_bytes - rx) as f64 / dt);
                self.tx.push((p.tx_bytes - tx) as f64 / dt);
            }
        }
        self.sampled = Some(sampled);
        self.last_net = Some((p.rx_bytes, p.tx_bytes, now));
        if self.boot_id.is_none() {
            self.boot_id = Some(p.boot_id.clone());
        }
        self.probe.set(Ok(p));
    }

    /// Forget the boot id seen so far (after a reboot we asked for).
    pub fn reset_boot(&mut self) {
        self.boot_id = self.probe.value.as_ref().map(|p| p.boot_id.clone());
    }

    /// The server came back with a different boot id than when sentry-server started.
    pub fn rebooted(&self) -> bool {
        match (&self.boot_id, &self.probe.value) {
            (Some(first), Some(p)) => *first != p.boot_id,
            _ => false,
        }
    }
}

fn run(k: Kind, r: &Remote) -> Result<Payload, SrvError> {
    Ok(match k {
        Kind::Host => {
            let (os, k) = collect::host(r)?;
            Payload::Host(os, k)
        }
        Kind::Sudo => Payload::Sudo(r.sudo_mode()?),
        Kind::Probe => Payload::Probe(probe::collect(r)?),
        Kind::Procs => Payload::Procs(Box::new(collect::procs::collect(r)?)),
        Kind::Gpu => Payload::Gpu(collect::gpu(r)?),
        Kind::Temp => Payload::Temp(health::cpu_temp(r)?),
        Kind::Disks => Payload::Disks(collect::disks(r)?),
        Kind::Units => Payload::Units(units::collect(r)?),
        Kind::Docker => Payload::Docker(docker::collect(r)?),
        Kind::Stats => Payload::Stats(docker::stats(r)?),
        Kind::Apt => Payload::Apt(apt::collect(r)?),
        Kind::Smart => Payload::Smart(r.cfg.smart.iter().map(|d| health::smart(r, d)).collect()),
        Kind::Jails => Payload::Jails(health::fail2ban(r)?),
        Kind::Listeners => Payload::Listeners(collect::listeners(r)?),
        Kind::Sockets => Payload::Sockets(collect::sockets::collect(r)?),
        Kind::Journal => Payload::Journal(collect::journal(r)?),
        Kind::Report => Payload::Reports(Box::new(audit::shown(&r.name, None))),
        Kind::ReportAt(i) => Payload::Reports(Box::new(audit::shown(&r.name, Some(i as usize)))),
        Kind::Audit => {
            audit::run(r)?;
            Payload::Reports(Box::new(audit::shown(&r.name, None)))
        }
        Kind::Maint => {
            let (st, local, found) = collect::maint_read(r);
            Payload::Maint(st, local, found)
        }
        Kind::Upstream => {
            maint::upstream::refresh(&r.name, &r.cfg);
            Payload::Upstream(jiff::Timestamp::now())
        }
        Kind::History => Payload::History(Box::new(sentry_core::tui::histview::load(&r.name))),
    })
}

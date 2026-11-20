//! What the network target knows, and fetching it: every fetch runs on its own thread and
//! reports back as a [`Data`] through the target's `Mail`; a kind already in flight isn't
//! started twice.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use crate::audit::{self, Report, Shown};
use crate::clients::{self, Client, Seen, Topo};
use crate::collect::cert::Cert;
use crate::collect::clients::Raw;
use crate::collect::services::Services;
use crate::collect::uci::Uci;
use crate::collect::updates::Updates;
use crate::collect::{self, CollectError, ifaces, probe};
use crate::maint::upstream::{self, Upstream};
use crate::rates::{Rate, Rates};
use crate::remote::Router;
use sentry_app::remote::probe::CpuDelta;
use sentry_app::target::Mail;
use sentry_core::cache::Cached;
use sentry_core::collectors::net::Listener;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The 1 Hz sample: `/proc`, and every port's link, speed and counters.
    Probe,
    /// Board, release, interfaces and devices from `ubus`.
    Ifaces,
    /// The router's metrics ring, read from this machine's disk (no ssh).
    History,
    /// Leases, neighbours, each bridge's ports and the stations on each radio.
    Clients,
    /// What listens on the router.
    Listeners,
    /// The configuration, secrets tagged, and what's staged.
    Uci,
    /// The web interface's certificate.
    Cert,
    /// Which services run.
    Services,
    /// Audit now: every read above, a report stored. Then as `Report`.
    Audit,
    /// The newest report and the one before, from this machine's disk (no ssh).
    Report,
    /// The report at this place among those kept.
    ReportAt(u16),
    /// Which packages could be upgraded, from the index the router has (it only reads).
    Updates,
    /// The same after `apk update`: only ever on the user's `r`.
    Refresh,
    /// What was last looked up upstream, from this machine's cache (no network).
    Upstream,
    /// Look upstream up (from this machine; within a day the cache answers): on `r`.
    Lookup,
    /// The config backups against the router's files now.
    Backup,
}

/// What a fetch thread sends back: the kind, and what it read or why it couldn't.
pub struct Data(pub Kind, pub Box<Result<Payload, CollectError>>);

pub enum Payload {
    Probe(probe::Probe),
    Ifaces(Box<ifaces::Ifaces>),
    History(Box<sentry_core::tui::histview::HistData>),
    Clients(Box<Raw>),
    Listeners(Vec<Listener>),
    Uci(Box<Uci>),
    Cert(Option<Cert>),
    Services(Services),
    Reports(Box<Shown>),
    Updates(Updates),
    Upstream(Option<Box<Cached<Upstream>>>),
    Backup(Box<crate::backup::Status>),
}

/// A value with when it arrived and the last error fetching it.
pub struct Slot<T> {
    pub value: Option<T>,
    pub at: Option<Instant>,
    pub err: Option<CollectError>,
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
    pub fn set(&mut self, v: T) {
        self.value = Some(v);
        self.at = Some(Instant::now());
        self.err = None;
    }
}

/// What one probe added, for the recorder: CPU % and the uplink's bytes per second since the
/// one before (none on the first, or across a reboot).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sampled {
    pub cpu: Option<f32>,
    pub rx: Option<f64>,
    pub tx: Option<f64>,
    pub temp: Option<f32>,
}

/// Samples kept for a graph or a row's sparkline (four minutes at 1 Hz).
pub const HIST: usize = 240;

#[derive(Default, Clone)]
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
    pub probe: Slot<probe::Probe>,
    pub ifaces: Slot<ifaces::Ifaces>,
    pub history: Slot<sentry_core::tui::histview::HistData>,
    /// What the router last said about its clients, and the one list made of it (made
    /// again when the interfaces or the config's devices are read).
    pub raw_clients: Slot<Raw>,
    pub clients: Option<Vec<Client>>,
    /// When each device was first and last seen (`seen.toml`; not read or written offline).
    pub seen: Seen,
    seen_saved: Option<Instant>,
    pub listeners: Slot<Vec<Listener>>,
    pub uci: Slot<Uci>,
    pub cert: Slot<Option<Cert>>,
    pub services: Slot<Services>,
    /// The latest audit (`Some(None)`: read, and there's none yet).
    pub report: Slot<Option<Box<Report>>>,
    /// What the audit report view shows (`F` on Maintenance): a report and the one before.
    pub shown: Option<Shown>,
    /// The packages that could be upgraded, and how old the index is.
    pub updates: Slot<Updates>,
    /// What upstream has released (`Some(None)`: read, never looked up).
    pub upstream: Slot<Option<Cached<Upstream>>>,
    /// The config backups against the router now.
    pub backup: Slot<crate::backup::Status>,
    /// `seen.toml` was written by an audit since it was read here.
    seen_stale: bool,
    /// The clients were read and the list isn't made of that read yet (it waits for the
    /// interfaces).
    pub raw_pending: bool,
    cpu_delta: CpuDelta,
    pub cpu: Ring,
    pub mem: Ring,
    rates: Rates,
    /// Each port's rate between the last two samples; a port with none isn't here.
    pub rate: HashMap<String, Rate>,
    /// Each port's rate over time (in + out, bits per second), for its sparkline.
    pub traffic: HashMap<String, Ring>,
    /// The sample that just arrived, until the recorder takes it.
    pub sampled: Option<Sampled>,
    /// The boot id seen first; a different one means the router rebooted.
    pub boot_id: Option<String>,
    pub inflight: HashSet<Kind>,
    /// The last time ssh itself failed, and why.
    pub unreachable: Option<(Instant, String)>,
}

impl Store {
    pub fn fetch(&mut self, k: Kind, r: &Router, mail: &Mail) {
        if !self.inflight.insert(k) {
            return;
        }
        let r = r.clone();
        let mail = mail.clone();
        std::thread::spawn(move || {
            let res = run(k, &r);
            mail.send(Data(k, Box::new(res)));
        });
    }

    pub fn apply(&mut self, k: Kind, res: Result<Payload, CollectError>) {
        self.inflight.remove(&k);
        match res {
            Err(e @ CollectError::Unreachable(_)) => {
                // Keep the old values: they're what was last known.
                self.unreachable = Some((Instant::now(), e.to_string()));
            }
            Err(e) => match k {
                Kind::Probe => self.probe.err = Some(e),
                Kind::Ifaces => self.ifaces.err = Some(e),
                Kind::History => self.history.err = Some(e),
                Kind::Clients => self.raw_clients.err = Some(e),
                Kind::Listeners => self.listeners.err = Some(e),
                Kind::Uci => self.uci.err = Some(e),
                Kind::Cert => self.cert.err = Some(e),
                Kind::Services => self.services.err = Some(e),
                Kind::Audit | Kind::Report | Kind::ReportAt(_) => self.report.err = Some(e),
                Kind::Updates | Kind::Refresh => self.updates.err = Some(e),
                Kind::Upstream | Kind::Lookup => self.upstream.err = Some(e),
                Kind::Backup => self.backup.err = Some(e),
            },
            Ok(p) => {
                if !matches!(
                    k,
                    Kind::History
                        | Kind::Report
                        | Kind::ReportAt(_)
                        | Kind::Upstream
                        | Kind::Lookup
                ) {
                    self.unreachable = None;
                }
                match p {
                    Payload::Probe(p) => self.on_probe(p),
                    Payload::Ifaces(i) => self.ifaces.set(*i),
                    Payload::History(h) => self.history.set(*h),
                    Payload::Clients(raw) => self.raw_clients.set(*raw),
                    Payload::Listeners(l) => self.listeners.set(l),
                    Payload::Uci(u) => self.uci.set(*u),
                    Payload::Cert(c) => self.cert.set(c),
                    Payload::Services(sv) => self.services.set(sv),
                    Payload::Reports(shown) => self.on_reports(*shown, k),
                    Payload::Updates(u) => self.updates.set(u),
                    Payload::Upstream(u) => self.upstream.set(u.map(|u| *u)),
                    Payload::Backup(b) => self.backup.set(*b),
                }
            }
        }
    }

    fn on_probe(&mut self, p: probe::Probe) {
        let cpu = self.cpu_delta.pct(p.host.cpu);
        if let Some(c) = cpu {
            self.cpu.push(c as f64);
        }
        self.mem.push(p.host.mem_used_pct() as f64);
        self.rate = self.rates.feed(&p);
        for (name, r) in &self.rate {
            self.traffic
                .entry(name.clone())
                .or_default()
                .push(r.total());
        }
        // A port that's gone takes its history with it.
        self.traffic
            .retain(|name, _| p.ports.iter().any(|x| &x.name == name));
        let wan = p.host.iface.as_ref().and_then(|i| self.rate.get(i));
        self.sampled = Some(Sampled {
            cpu,
            rx: wan.map(|r| r.rx / 8.0),
            tx: wan.map(|r| r.tx / 8.0),
            temp: p.temp_c,
        });
        if self.boot_id.is_none() {
            self.boot_id = Some(p.host.boot_id.clone());
        }
        self.probe.set(p);
    }

    /// Reports read from disk: the newest is the latest audit, and what it read stands in
    /// for what no screen has read yet (so the Dashboard and Network have something to show
    /// before their own reads arrive).
    fn on_reports(&mut self, shown: Shown, k: Kind) {
        if shown.latest() {
            if let Some(r) = shown.cur.as_deref() {
                let snap = &r.snapshot;
                if self.clients.is_none() {
                    self.clients = snap.clients.clone();
                }
                if self.cert.value.is_none() {
                    self.cert.value = Some(snap.cert);
                }
                if self.services.value.is_none() || k == Kind::Audit {
                    self.services.value = snap.services.clone().or(self.services.value.take());
                }
                if k == Kind::Audit {
                    // The audit just read all of it: the screens show what it saw.
                    if let Some(u) = &snap.uci {
                        self.uci.set(u.clone());
                    }
                    if let Some(l) = &snap.listeners {
                        self.listeners.set(l.clone());
                    }
                    if let Some(c) = &snap.clients {
                        self.clients = Some(c.clone());
                    }
                    self.cert.set(snap.cert);
                    if let Some(b) = &snap.backup {
                        self.backup.set(b.clone());
                    }
                    self.seen_stale = true;
                }
            }
            self.report.set(shown.cur.clone());
        }
        self.shown = Some(shown);
    }

    /// Make the one list of clients from the last read, with the layout the interfaces
    /// give. `save`: where `seen.toml` is written when it changed (none: offline).
    pub fn merge_clients(
        &mut self,
        devices: &[crate::config::Device],
        now: i64,
        save: Option<&str>,
    ) {
        let (Some(raw), Some(i)) = (&self.raw_clients.value, &self.ifaces.value) else {
            return;
        };
        // Each read is taken in once: what was seen counts reads.
        if !std::mem::take(&mut self.raw_pending) {
            return;
        }
        if let Some(scope) = save
            && std::mem::take(&mut self.seen_stale)
        {
            // An audit wrote it meanwhile.
            self.seen = Seen::load(scope);
        }
        let (list, changed) = clients::read(raw, &Topo::of(i), devices, &mut self.seen, now);
        self.clients = Some(list);
        // What changed is written at once; "last seen" alone, every few minutes.
        let due = self
            .seen_saved
            .is_none_or(|t| t.elapsed() > std::time::Duration::from_secs(300));
        if let Some(scope) = save
            && (changed || due)
        {
            let _ = self.seen.save(scope);
            self.seen_saved = Some(Instant::now());
        }
    }

    /// The router came back with a different boot id than when it was first read.
    pub fn rebooted(&self) -> bool {
        match (&self.boot_id, &self.probe.value) {
            (Some(first), Some(p)) => *first != p.host.boot_id,
            _ => false,
        }
    }
}

fn run(k: Kind, r: &Router) -> Result<Payload, CollectError> {
    Ok(match k {
        Kind::Probe => Payload::Probe(probe::collect(r)?),
        Kind::Ifaces => Payload::Ifaces(Box::new(ifaces::collect(r)?)),
        Kind::History => Payload::History(Box::new(sentry_core::tui::histview::load(&r.scope))),
        Kind::Clients => Payload::Clients(Box::new(collect::clients::collect(r)?)),
        Kind::Listeners => Payload::Listeners(collect::listeners::collect(r)?),
        Kind::Uci => Payload::Uci(Box::new(collect::uci::collect(r)?)),
        Kind::Cert => Payload::Cert(collect::cert::collect(r)?),
        Kind::Services => Payload::Services(collect::services::collect(r)?),
        Kind::Report => Payload::Reports(Box::new(audit::shown(&r.scope, None))),
        Kind::ReportAt(i) => Payload::Reports(Box::new(audit::shown(&r.scope, Some(i as usize)))),
        Kind::Audit => {
            audit::run(r)?;
            Payload::Reports(Box::new(audit::shown(&r.scope, None)))
        }
        Kind::Updates => Payload::Updates(collect::updates::collect(r)?),
        Kind::Refresh => Payload::Updates(collect::updates::refresh(r)?),
        Kind::Upstream => Payload::Upstream(upstream::load(&r.name).map(Box::new)),
        Kind::Lookup => {
            // The series the router runs decides what's looked up.
            let version = ifaces::collect(r)?.board.version;
            match crate::maint::eval::series(&version) {
                Some(s) => Payload::Upstream(Some(Box::new(upstream::get(&r.name, &s)))),
                None => Payload::Upstream(upstream::load(&r.name).map(Box::new)),
            }
        }
        Kind::Backup => {
            let uci = collect::uci::collect(r).ok();
            Payload::Backup(Box::new(crate::backup::status(r, uci.as_ref())?))
        }
    })
}

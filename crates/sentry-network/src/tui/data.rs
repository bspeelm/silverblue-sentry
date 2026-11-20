//! What the network target knows, and fetching it: every fetch runs on its own thread and
//! reports back as a [`Data`] through the target's `Mail`; a kind already in flight isn't
//! started twice.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use crate::collect::{CollectError, ifaces, probe};
use crate::rates::{Rate, Rates};
use crate::remote::Router;
use sentry_app::remote::probe::CpuDelta;
use sentry_app::target::Mail;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The 1 Hz sample: `/proc`, and every port's link, speed and counters.
    Probe,
    /// Board, release, interfaces and devices from `ubus`.
    Ifaces,
    /// The router's metrics ring, read from this machine's disk (no ssh).
    History,
}

/// What a fetch thread sends back: the kind, and what it read or why it couldn't.
pub struct Data(pub Kind, pub Box<Result<Payload, CollectError>>);

pub enum Payload {
    Probe(probe::Probe),
    Ifaces(Box<ifaces::Ifaces>),
    History(Box<sentry_core::tui::histview::HistData>),
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
            },
            Ok(p) => {
                if k != Kind::History {
                    self.unreachable = None;
                }
                match p {
                    Payload::Probe(p) => self.on_probe(p),
                    Payload::Ifaces(i) => self.ifaces.set(*i),
                    Payload::History(h) => self.history.set(*h),
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
    })
}

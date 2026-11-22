//! Everything the attention list is made from, read in one go (`sentry-network security`),
//! and the one rule that turns reads into the audit's findings for it: the window calls
//! [`findings`] with what its store holds, the command line with what [`gather`] read.

use jiff::Timestamp;
use sentry_core::baseline::BaselineFile;
use sentry_core::collectors::net::Listener;
use sentry_core::finding::Finding;

use super::blocks::Blocks;
use super::{Picture, Read, Seen, State};
use crate::audit::{self, Snapshot};
use crate::clients::{self, Client, Topo};
use crate::collect::clients::Station;
use crate::collect::counters::Counters;
use crate::collect::crowdsec::Bouncer;
use crate::collect::dnsstate::DnsState;
use crate::collect::flows::Flows;
use crate::collect::ifaces::Ifaces;
use crate::collect::seclog::SecLog;
use crate::collect::services::Services;
use crate::collect::uci::Uci;
use crate::collect::{self, CollectError};
use crate::config::Network;
use crate::remote::Router;

/// What the audit's rule is given besides the security reads.
#[derive(Clone, Copy, Default)]
pub struct More<'a> {
    pub services: Option<&'a Services>,
    pub crowdsec: Option<&'a Bouncer>,
    pub listeners: Option<&'a [Listener]>,
}

/// What the audit would say of these reads, each finding with its `expected`.
pub fn findings(
    network: &str,
    cfg: &Network,
    base: &BaselineFile,
    read: &Read,
    more: More,
    now: Timestamp,
) -> Vec<Finding> {
    let snap = Snapshot {
        network: network.to_string(),
        taken_at: Some(now),
        ifaces: read.ifaces.cloned(),
        uci: read.uci.cloned(),
        listeners: more.listeners.map(<[Listener]>::to_vec),
        services: more.services.cloned(),
        crowdsec: more.crowdsec.cloned(),
        security: (read.flows.is_some() || read.log.is_some()).then(|| Seen::of(read)),
        ..Default::default()
    };
    audit::derive(&snap, cfg, None, base)
}

/// One read of everything. A part the router doesn't have is absent, never an error.
#[derive(Default)]
pub struct Gathered {
    pub ifaces: Option<Ifaces>,
    pub uci: Option<Uci>,
    pub clients: Option<Vec<Client>>,
    pub stations: Option<Vec<Station>>,
    pub counters: Option<Counters>,
    pub flows: Option<Flows>,
    pub log: Option<SecLog>,
    pub dns: Option<DnsState>,
    pub services: Option<Services>,
    pub crowdsec: Option<Bouncer>,
    pub listeners: Option<Vec<Listener>>,
    /// (what, why it's missing)
    pub errors: Vec<(String, String)>,
}

impl Gathered {
    pub fn read(&self) -> Read<'_> {
        Read {
            ifaces: self.ifaces.as_ref(),
            uci: self.uci.as_ref(),
            clients: self.clients.as_deref(),
            stations: self.stations.as_deref(),
            counters: self.counters.as_ref(),
            // One read of the counters: no rate (a rising count needs two).
            rated: None,
            flows: self.flows.as_ref(),
            log: self.log.as_ref(),
            dns: self.dns.as_ref(),
        }
    }
}

/// Reads only. Err: the router couldn't be reached.
pub fn gather(r: &Router) -> Result<Gathered, CollectError> {
    let mut g = Gathered::default();
    fn part<T>(
        what: &str,
        res: Result<T, CollectError>,
        errors: &mut Vec<(String, String)>,
    ) -> Result<Option<T>, CollectError> {
        match res {
            Ok(v) => Ok(Some(v)),
            Err(e @ CollectError::Unreachable(_)) => Err(e),
            Err(CollectError::Unavailable(_)) => Ok(None),
            Err(e) => {
                errors.push((what.to_string(), e.to_string()));
                Ok(None)
            }
        }
    }
    let e = &mut g.errors;
    g.ifaces = part("interfaces", collect::ifaces::collect(r), e)?;
    g.uci = part("config", collect::uci::collect(r), e)?;
    if let Some(raw) = part("clients", collect::clients::collect(r), e)? {
        let topo = g.ifaces.as_ref().map(Topo::of).unwrap_or_default();
        // (What was seen before says who is new; nothing is written here.)
        let mut seen = clients::Seen::load(&r.scope);
        let now = Timestamp::now().as_second();
        g.clients = Some(clients::read(&raw, &topo, &r.cfg.devices, &mut seen, now).0);
        g.stations = Some(raw.stations);
    }
    g.counters = part("counters", collect::counters::collect(r), e)?;
    g.flows = part("flows", collect::flows::collect(r), e)?;
    g.log = part("log", collect::seclog::collect(r), e)?;
    g.dns = part("dns", collect::dnsstate::collect(r), e)?;
    g.listeners = part("listeners", collect::listeners::collect(r), e)?;
    if let Some((sv, cs)) = part("services", collect::services::collect_with(r), e)? {
        g.services = Some(sv);
        g.crowdsec = cs;
    }
    Ok(g)
}

/// The list and the posture of what was gathered.
pub struct Said {
    pub rows: Vec<super::Row>,
    pub posture: Vec<super::Line>,
}

/// What `sentry-network security [name]` prints: the rows not put off or marked expected
/// (what can wait included), and the posture.
pub fn said(r: &Router, g: &Gathered) -> Said {
    let read = g.read();
    let picture = Picture::of(&read);
    let base = BaselineFile::load(&r.scope);
    let now = Timestamp::now();
    let found = findings(
        &r.name,
        &r.cfg,
        &base,
        &read,
        More {
            services: g.services.as_ref(),
            crowdsec: g.crowdsec.as_ref(),
            listeners: g.listeners.as_deref(),
        },
        now,
    );
    let blocks = Blocks::load(&r.scope);
    let state = State {
        network: &r.name,
        read,
        picture: &picture,
        findings: &found,
        expected: &base.findings,
        blocks: &blocks,
        bouncer: g.crowdsec.as_ref(),
        server_guard: None,
        now: now.as_second(),
    };
    let later = sentry_core::maint::later::load(&r.scope);
    let today = now.to_zoned(jiff::tz::TimeZone::system()).date();
    let mut rows = super::attention(&state);
    rows.retain(|x| later.get(&x.key).is_none_or(|d| *d <= today));
    Said {
        rows,
        posture: super::posture(&state),
    }
}

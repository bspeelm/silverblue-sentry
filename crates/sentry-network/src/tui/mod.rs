//! A network in sentry's TUI: its router's Dashboard, Clients, Network, Maintenance and
//! History, everything fetched over ssh
//! while you watch (the window itself is opened by the `sentry` binary, with the network as
//! one of its targets). The app (the frame, sessions, records, the workflow run) is
//! `sentry_app`'s; what's here is the network as its target ([`target::NetworkTarget`]).

pub mod ask;
mod data;
mod screens;
mod target;
#[cfg(test)]
mod tests;

use crate::remote::Router;
use sentry_core::tui::{ScreenId, ScreenSet};

pub use sentry_app::{App, Event};
pub use target::NetworkTarget;

/// The network target's screens, with sentry's numbers and names: `1` Dashboard, `2`
/// Clients, `3` Network, `6` Maintenance, `0` Upgrade (its workflows, and the run) and `H`
/// History (in the strip once something was recorded).
pub const SCREENS: ScreenSet = ScreenSet {
    ids: &[
        ScreenId::Dash,
        ScreenId::Clients,
        ScreenId::Net,
        ScreenId::Maint,
        ScreenId::Upgrade,
        ScreenId::Hist,
    ],
    aliases: &[
        ("overview", ScreenId::Dash),
        ("router", ScreenId::Dash),
        ("devices", ScreenId::Clients),
        ("firewall", ScreenId::Net),
    ],
};

/// A network's id as a target (`[targets]` calls it the same: `net:<name>`).
pub fn id_of(name: &str) -> String {
    NetworkTarget::id_of(name)
}

/// The network as a target of the app: what `App::new` or `App::add` builds it with.
pub fn target(
    router: Router,
) -> impl FnOnce(sentry_app::target::Mail) -> Box<dyn sentry_app::Target> {
    |mail| Box::new(NetworkTarget::new(router, mail))
}

/// Test support for the window's own tests (several targets side by side).
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::data::{Data, Kind, Payload};
    use crate::collect::{ifaces, probe};

    /// What a probe of the network's router would have sent: `text` is the exec's output.
    pub fn probe_ev(network: &str, text: &str) -> super::Event {
        let p = probe::parse(text).map_err(crate::collect::CollectError::Parse);
        super::Event::Data(
            super::id_of(network),
            Box::new(Data(Kind::Probe, Box::new(p.map(Payload::Probe)))),
        )
    }

    /// The same for the interfaces read.
    pub fn ifaces_ev(network: &str, text: &str) -> super::Event {
        let i = ifaces::parse(text).map_err(crate::collect::CollectError::Parse);
        super::Event::Data(
            super::id_of(network),
            Box::new(Data(
                Kind::Ifaces,
                Box::new(i.map(|i| Payload::Ifaces(Box::new(i)))),
            )),
        )
    }

    /// The fetches the network in slot `i` has asked for so far, in order (asked for: with
    /// the window offline none is started, but each is still counted).
    pub fn asked(a: &super::App, i: usize) -> Vec<&'static str> {
        let t: &super::NetworkTarget = a.slots[i]
            .target
            .as_any()
            .downcast_ref()
            .expect("a network target");
        t.asked
            .iter()
            .map(|k| match k {
                Kind::Probe => "probe",
                Kind::Ifaces => "ifaces",
                Kind::History => "history",
                Kind::Clients => "clients",
                Kind::Listeners => "listeners",
                Kind::Uci => "uci",
                Kind::Cert => "cert",
                Kind::Services => "services",
                Kind::Audit => "audit",
                Kind::Report | Kind::ReportAt(_) => "report",
                Kind::Updates => "updates",
                Kind::Refresh => "refresh",
                Kind::Upstream => "upstream",
                Kind::Lookup => "lookup",
                Kind::Backup => "backup",
            })
            .collect()
    }
}

//! A network in sentry's TUI: its router's Dashboard, Clients, Network, Security,
//! Maintenance and History, everything fetched over ssh
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
/// Clients, `3` Network, `4` Security (what flows through the router: read-only), `6`
/// Maintenance, `0` Upgrade (its workflows, and the run) and `H`
/// History (in the strip once something was recorded).
pub const SCREENS: ScreenSet = ScreenSet {
    ids: &[
        ScreenId::Dash,
        ScreenId::Clients,
        ScreenId::Net,
        ScreenId::Security,
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

    /// The same for the configuration (secrets tagged with a fixed salt).
    pub fn uci_ev(network: &str, text: &str) -> super::Event {
        let u = crate::collect::uci::parse(text, &crate::redact::Salt::fixed([7; 16]));
        super::Event::Data(
            super::id_of(network),
            Box::new(Data(Kind::Uci, Box::new(Ok(Payload::Uci(Box::new(u)))))),
        )
    }

    /// The same for the clients read.
    pub fn clients_ev(network: &str, text: &str) -> super::Event {
        let raw = crate::collect::clients::parse(text).map_err(crate::collect::CollectError::Parse);
        super::Event::Data(
            super::id_of(network),
            Box::new(Data(
                Kind::Clients,
                Box::new(raw.map(|r| Payload::Clients(Box::new(r)))),
            )),
        )
    }

    /// What reading the router's CrowdSec bouncer would have sent: installed, switched on
    /// (and running) or not.
    pub fn bouncer_ev(network: &str, on: bool) -> super::Event {
        let b = crate::collect::crowdsec::Bouncer {
            enabled: Some(on),
            blocked4: on.then_some(0),
            blocked6: None,
            age_s: on.then_some(60),
        };
        super::Event::Data(
            super::id_of(network),
            Box::new(Data(
                Kind::Crowdsec,
                Box::new(Ok(Payload::Crowdsec(Some(b)))),
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
                Kind::Crowdsec => "crowdsec",
                Kind::Audit => "audit",
                Kind::Report | Kind::ReportAt(_) => "report",
                Kind::Updates => "updates",
                Kind::Refresh => "refresh",
                Kind::Upstream => "upstream",
                Kind::Lookup => "lookup",
                Kind::Backup => "backup",
                Kind::Counters => "counters",
                Kind::Flows => "flows",
                Kind::SecLog => "seclog",
                Kind::DnsState => "dnsstate",
            })
            .collect()
    }

    /// A network for the rows matrix (`sentry_app::resolve`): its config expects a
    /// service that isn't running, and the audit says so.
    pub struct Rig;

    const SERVICE: &str = "adblock";
    const FINDING: &str = "net:service:adblock";

    fn rig_cfg(watched: bool) -> crate::config::Network {
        let mut n = crate::config::Network::default();
        if watched {
            n.expect.services = vec![SERVICE.into()];
        }
        n
    }

    fn report(name: &str, still: bool) -> crate::audit::Shown {
        let mut findings = Vec::new();
        if still {
            findings.push(sentry_core::finding::Finding {
                id: FINDING.into(),
                severity: sentry_core::finding::Sev::High,
                category: "services".into(),
                message: format!("{SERVICE} isn't running"),
                evidence: "no instance in `ubus call service list`".into(),
                ..Default::default()
            });
        }
        crate::audit::Shown {
            names: vec!["2026-10-26-110000".into()],
            idx: 0,
            cur: Some(Box::new(crate::audit::Report {
                snapshot: crate::audit::Snapshot {
                    network: name.into(),
                    taken_at: Some("2026-10-26T11:00:00Z".parse().unwrap()),
                    ..Default::default()
                },
                findings,
            })),
            prev: None,
        }
    }

    fn reports_ev(a: &super::App, k: Kind, still: bool) -> super::Event {
        let id = a.slot().target.ident().id.clone();
        let name = id.trim_start_matches("net:").to_string();
        super::Event::Data(
            id,
            Box::new(Data(
                k,
                Box::new(Ok(Payload::Reports(Box::new(report(&name, still))))),
            )),
        )
    }

    impl sentry_app::resolve::Rig for Rig {
        fn kind(&self) -> &'static str {
            "network"
        }

        fn app(&self, name: &str) -> super::App {
            let (tx, _rx) = std::sync::mpsc::channel();
            let mut a = super::App::new(
                tx,
                &super::id_of(name),
                super::target(crate::remote::Router::new(name, &rig_cfg(true))),
            );
            a.win.offline = true;
            a.win.theme = sentry_core::tui::theme::Theme::truecolor();
            a.win.now_override = Some("2026-10-26T12:00:00Z".parse().unwrap());
            // What must be hidden from Claude is known before it is asked anything.
            let fx = |f: &str| {
                let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/network")
                    .join(f);
                std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
            };
            for ev in [
                ifaces_ev(name, &fx("ifaces.txt")),
                uci_ev(name, &fx("uci.txt")),
                clients_ev(name, &fx("clients.txt")),
                reports_ev(&a, Kind::Report, true),
            ] {
                a.on_event(ev, std::time::Instant::now());
            }
            a
        }

        fn finding(&self) -> (String, String) {
            (FINDING.into(), format!("finding:{FINDING}"))
        }

        fn watched(&self) -> Option<String> {
            Some(format!("service:{SERVICE}"))
        }

        fn audited(&self, a: &mut super::App, still: bool) {
            // (What isn't watched isn't reported, whatever the test asks for.)
            let watched = a
                .slot()
                .target
                .as_any()
                .downcast_ref::<super::target::NetworkTarget>()
                .is_some_and(|t| t.router.cfg.expect.services.iter().any(|s| s == SERVICE));
            let ev = reports_ev(a, Kind::Audit, still && watched);
            a.on_event(ev, std::time::Instant::now());
        }

        fn reread(&self, a: &mut super::App) {
            let ev = reports_ev(a, Kind::Report, true);
            a.on_event(ev, std::time::Instant::now());
        }

        fn workflow(&self, a: &mut super::App, name: &str) -> Box<dyn std::any::Any> {
            use sentry_app::resolve::WF;
            let scope = crate::remote::scope(name);
            let _ = std::fs::remove_dir_all(sentry_app::remote::workflow::root(&scope));
            let text = format!(
                "name = \"{WF}\"\ndescription = \"test\"\n[[steps]]\nid = \"one\"\n\
                 title = \"one\"\nrun = \"true\"\ngate = \"auto\"\n"
            );
            let path = sentry_core::paths::config_dir().join(format!("net-{name}-{WF}.toml"));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &text).unwrap();
            a.set_wf_entries(vec![sentry_core::workflows::Entry {
                name: WF.to_string(),
                path,
                wf: sentry_core::workflows::parse(&text),
                issues: Vec::new(),
            }]);
            Box::new(())
        }

        fn scope(&self, name: &str) -> String {
            crate::remote::scope(name)
        }

        fn config_on_disk(&self, name: &str, watched: bool) {
            let expect = if watched {
                format!("    expect:\n      services: [{SERVICE}]\n")
            } else {
                String::new()
            };
            let p = crate::config::path();
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(
                p,
                format!(
                    "networks:\n  {name}:\n    router:\n      ssh: root@{name}.example\n{expect}"
                ),
            )
            .unwrap();
        }
    }
}

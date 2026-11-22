//! A server in sentry's TUI: sentry's screens, everything fetched over ssh while you watch
//! (the window itself is opened by the `sentry` binary, with the server as one of its targets). The app itself (the frame, sessions, series, reviews, records, the workflow run) is
//! `sentry_app`'s; what's here is the server as its target ([`target::ServerTarget`]).
//! Built on the same runtime as the local TUI ([`sentry_core::tui::run_ui`]).

mod actions;
mod ask;
mod data;
mod planview;
mod screens;
mod target;
#[cfg(test)]
mod tests;

use std::sync::mpsc::Sender;

use crate::remote::Remote;
use sentry_core::tui::{ScreenId, ScreenSet};

pub use sentry_app::{App, Event};
pub use target::ServerTarget;

/// This program's screens, with sentry's numbers and names: `1` Dashboard, `2` Processes,
/// `3` Network, `4` Containers, `5` Services (where sentry has Flatpaks), `6` Maintenance,
/// `0` the workflow run, `H` History (in the strip once something was recorded).
pub const SCREENS: ScreenSet = ScreenSet {
    ids: &[
        ScreenId::Dash,
        ScreenId::Proc,
        ScreenId::Net,
        ScreenId::Cont,
        ScreenId::Svc,
        ScreenId::Maint,
        ScreenId::Upgrade,
        ScreenId::Hist,
    ],
    aliases: &[
        ("overview", ScreenId::Dash),
        ("workflows", ScreenId::Upgrade),
        ("run", ScreenId::Upgrade),
    ],
};

/// A server's id as a target (`[targets]` calls it the same: `srv:<name>`).
pub fn id_of(name: &str) -> String {
    ServerTarget::id_of(name)
}

/// The server as a target of the app: what `App::new` or `App::add` builds it with.
pub fn target(
    remote: Remote,
) -> impl FnOnce(sentry_app::target::Mail) -> Box<dyn sentry_app::Target> {
    |mail| Box::new(ServerTarget::new(remote, mail))
}

/// The app with this server as its one target.
pub fn app(remote: Remote, tx: Sender<Event>) -> App {
    App::new(tx, &id_of(&remote.name), target(remote))
}

/// Test support for the window's own tests (several targets side by side).
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::data::{Data, Kind, Payload};
    use crate::remote::SudoMode;

    /// What reading how sudo works on the server would have sent (`asks`: it wants a
    /// password).
    pub fn sudo_ev(server: &str, asks: bool) -> super::Event {
        let mode = if asks {
            SudoMode::Password
        } else {
            SudoMode::NoPasswd
        };
        super::Event::Data(
            super::id_of(server),
            Box::new(Data(Kind::Sudo, Box::new(Ok(Payload::Sudo(mode))))),
        )
    }

    /// What reading the server's CrowdSec would have sent: its agent running, this many
    /// alerts in the last day (all of one scenario), no bouncer.
    pub fn crowdsec_ev(server: &str, alerts: u32, scenario: &str) -> super::Event {
        use crate::collect::crowdsec::{Agent, Alerts, Crowdsec};
        let c = Crowdsec {
            agent: Agent::Running,
            version: None,
            now: 1_793_000_000,
            decisions: None,
            alerts: Some(Alerts {
                count: alerts,
                capped: false,
                top: vec![(scenario.to_string(), alerts)],
            }),
            hub: None,
            bouncers: Some(Vec::new()),
            unread: Vec::new(),
        };
        super::Event::Data(
            super::id_of(server),
            Box::new(Data(
                Kind::Crowdsec,
                Box::new(Ok(Payload::Crowdsec(Some(Box::new(c))))),
            )),
        )
    }

    /// A server for the rows matrix (`sentry_app::resolve`): its config watches a timer
    /// that hasn't run, and the audit says so.
    pub struct Rig;

    const TIMER: &str = "report.timer";
    const FINDING: &str = "srv:timer-stale:report.timer";

    fn rig_cfg(watched: bool) -> crate::config::Server {
        crate::config::Server {
            timers: if watched {
                vec![crate::config::TimerRule {
                    unit: TIMER.into(),
                    max_age: sentry_core::config::Dur::hours(26),
                }]
            } else {
                Vec::new()
            },
            ..Default::default()
        }
    }

    fn report(name: &str, still: bool) -> crate::audit::Shown {
        let mut findings = Vec::new();
        if still {
            findings.push(sentry_core::finding::Finding {
                id: FINDING.into(),
                severity: sentry_core::finding::Sev::High,
                category: "timers".into(),
                message: format!("{TIMER}: last ran 12 days ago (max 1d 2h)"),
                evidence: "LastTriggerUSec=2026-10-14T03:00:00Z NextElapse=-".into(),
                ..Default::default()
            });
        }
        crate::audit::Shown {
            names: vec!["2026-10-26-110000".into()],
            idx: 0,
            cur: Some(Box::new(crate::audit::Report {
                snapshot: crate::collect::Snapshot {
                    server: name.into(),
                    taken_at: Some("2026-10-26T11:00:00Z".parse().unwrap()),
                    ..Default::default()
                },
                findings,
            })),
            prev: None,
        }
    }

    fn rig_app(name: &str, cfg: &crate::config::Server) -> super::App {
        let (tx, _rx) = std::sync::mpsc::channel();
        let mut a = super::app(crate::remote::Remote::new(name, cfg), tx);
        a.win.offline = true;
        a.win.theme = sentry_core::tui::theme::Theme::truecolor();
        a.win.now_override = Some("2026-10-26T12:00:00Z".parse().unwrap());
        a.on_event(sudo_ev(name, false), std::time::Instant::now());
        let ev = super::Event::Data(
            super::id_of(name),
            Box::new(Data(
                Kind::Report,
                Box::new(Ok(Payload::Reports(Box::new(report(name, true))))),
            )),
        );
        a.on_event(ev, std::time::Instant::now());
        a
    }

    impl sentry_app::resolve::Rig for Rig {
        fn kind(&self) -> &'static str {
            "server"
        }

        fn app(&self, name: &str) -> super::App {
            rig_app(name, &rig_cfg(true))
        }

        fn finding(&self) -> (String, String) {
            (FINDING.into(), format!("finding:{FINDING}"))
        }

        fn watched(&self) -> Option<String> {
            Some(format!("timer:{TIMER}"))
        }

        fn audited(&self, a: &mut super::App, still: bool) {
            let name = a.slot().target.ident().scope.clone();
            let id = a.slot().target.ident().id.clone();
            // (What isn't watched isn't reported, whatever the test asks for.)
            let watched = a
                .slot()
                .target
                .as_any()
                .downcast_ref::<super::target::ServerTarget>()
                .is_some_and(|t| t.remote.cfg.timers.iter().any(|t| t.unit == TIMER));
            let ev = super::Event::Data(
                id,
                Box::new(Data(
                    Kind::Audit,
                    Box::new(Ok(Payload::Reports(Box::new(report(
                        &name,
                        still && watched,
                    ))))),
                )),
            );
            a.on_event(ev, std::time::Instant::now());
        }

        fn reread(&self, a: &mut super::App) {
            let name = a.slot().target.ident().scope.clone();
            let ev = super::Event::Data(
                a.slot().target.ident().id.clone(),
                Box::new(Data(
                    Kind::Report,
                    Box::new(Ok(Payload::Reports(Box::new(report(&name, true))))),
                )),
            );
            a.on_event(ev, std::time::Instant::now());
        }

        fn workflow(&self, a: &mut super::App, name: &str) -> Box<dyn std::any::Any> {
            use sentry_app::resolve::WF;
            let _ = std::fs::remove_dir_all(crate::workflow::root(name));
            let text = format!(
                "name = \"{WF}\"\ndescription = \"test\"\n[[steps]]\nid = \"one\"\n\
                 title = \"one\"\nrun = \"true\"\ngate = \"auto\"\n"
            );
            let path = sentry_core::paths::config_dir().join(format!("{name}-{WF}.toml"));
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

        fn not_here(&self, _way: sentry_app::resolve::Way) -> Option<&'static str> {
            None
        }

        fn scope(&self, name: &str) -> String {
            name.to_string()
        }

        fn config_on_disk(&self, name: &str, watched: bool) {
            let timers = if watched {
                format!("    timers:\n      - unit: {TIMER}\n        max_age: 26h\n")
            } else {
                String::new()
            };
            let p = crate::config::path();
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(
                p,
                format!("servers:\n  {name}:\n    ssh: admin@{name}.example\n{timers}"),
            )
            .unwrap();
        }

        /// What only a server has: `t` tracks what discovery found, `x` ignores it, and an
        /// item of sentry-server's own is untracked. Each writes items.toml and reads the
        /// config again, so the process must be the test's own.
        fn own(
            &self,
            way: sentry_app::resolve::Way,
            name: &str,
        ) -> Option<sentry_app::resolve::Outcome> {
            use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
            use sentry_app::resolve::{Way, listed, select};
            if !matches!(way, Way::Track | Way::Untrack | Way::Ignore) {
                return None;
            }
            let _ = std::fs::remove_file(crate::maint::tracked::path(name));
            self.config_on_disk(name, true);
            let item = crate::config::MaintItem {
                id: "cache".into(),
                ..Default::default()
            };
            if way == Way::Untrack {
                crate::maint::tracked::track(name, item.clone()).unwrap();
            }
            let mut a = rig_app(name, &rig_cfg(true));
            let now = std::time::Instant::now();
            let found = crate::maint::discover::Found {
                candidates: vec![crate::maint::discover::Candidate {
                    key: "image:cache".into(),
                    what: "compose service cache".into(),
                    item,
                }],
                gone: vec![crate::maint::discover::Gone {
                    id: "cache".into(),
                    why: "its container is gone".into(),
                }],
            };
            let found = match way {
                Way::Untrack => crate::maint::discover::Found {
                    candidates: Vec::new(),
                    ..found
                },
                _ => crate::maint::discover::Found {
                    gone: Vec::new(),
                    ..found
                },
            };
            let ev = super::Event::Data(
                a.slot().target.ident().id.clone(),
                Box::new(Data(
                    Kind::Maint,
                    Box::new(Ok(Payload::Maint(Vec::new(), Default::default(), found))),
                )),
            );
            a.on_event(ev, now);
            let row = match way {
                Way::Untrack => "gone:cache",
                _ => "image:cache",
            };
            let before = listed(&mut a, row);
            select(&mut a, row);
            let mut key = |c| {
                a.on_event(
                    super::Event::Key(KeyEvent::new(c, KeyModifiers::NONE)),
                    std::time::Instant::now(),
                )
            };
            match way {
                Way::Track => key(KeyCode::Char('t')),
                _ => {
                    key(KeyCode::Char('x'));
                    key(KeyCode::Enter);
                }
            }
            let after = listed(&mut a, row);
            let _ = std::fs::remove_file(crate::maint::tracked::path(name));
            Some(Ok((before, after)))
        }
    }
}

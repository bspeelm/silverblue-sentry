//! sentry's TUI: this machine as a target of the app (`sentry_app`), its screens and their
//! data. The terminal, event loop and widgets are `sentry_core::tui` (re-exported here).
//!
//! The window itself is opened by the `sentry` binary, with this machine as one of its targets.
//!
//! One main thread owns all state. An input thread forwards key events; background fetches and
//! streamed commands send `Event`s over the same channel. There is no ticker thread: the loop
//! sleeps until the active screen's next refresh is due, so idle screens cost ~nothing.

mod app;
mod data;
mod plans;
mod screens;
mod target;
mod wf;

pub use sentry_core::tui::*;

/// sentry's screens, in strip order.
pub const SCREENS: ScreenSet = ScreenSet {
    ids: &[
        ScreenId::Dash,
        ScreenId::Proc,
        ScreenId::Net,
        ScreenId::Cont,
        ScreenId::Flat,
        ScreenId::Maint,
        ScreenId::Clean,
        ScreenId::Upgrade,
        ScreenId::Hist,
    ],
    aliases: &[],
};

pub use data::{Fetch, FetchErr, Payload};
pub use sentry_app::Event;

/// This machine's id as a target (`[targets]` calls it `local`).
pub const ID: &str = target::LocalTarget::ID;

/// This machine as a target of the app: what `App::new` or `App::add` builds it with.
pub fn target(
    cfg: crate::config::Config,
) -> impl FnOnce(sentry_app::target::Mail) -> Box<dyn sentry_app::Target> {
    |mail| Box::new(target::LocalTarget::new(cfg, mail))
}

/// The app with this machine as its one target.
pub fn app(tx: std::sync::mpsc::Sender<Event>) -> sentry_app::App {
    let (cfg, warnings) = crate::config::Config::load();
    let mut app = sentry_app::App::new(tx, ID, target(cfg));
    // What's wrong in config.toml, said once the TUI is up (ahead of a `[keys]` warning).
    if let Some(w) = warnings.into_iter().next() {
        app.warn_at_start(w);
    }
    app
}

/// Test support for the window's own tests (several targets side by side).
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    /// This machine with nothing read from it, under a fixed release and kernel.
    pub fn target(
        cfg: crate::config::Config,
    ) -> impl FnOnce(sentry_app::target::Mail) -> Box<dyn sentry_app::Target> {
        |mail| {
            Box::new(super::target::LocalTarget::with(
                cfg,
                super::data::DataStore::blank("44.1".into(), "7.2.8-200.fc44.x86_64".into()),
                mail,
            ))
        }
    }

    /// This machine's runs are kept in one place: whoever starts one for real in a test
    /// takes its turn (the guard), and begins with no run left there.
    pub fn runs_turn() -> std::sync::MutexGuard<'static, ()> {
        static RUNS: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let turn = RUNS.lock().unwrap_or_else(|e| e.into_inner());
        let _ = std::fs::remove_dir_all(crate::workflows::state::root());
        turn
    }

    /// This machine for the rows matrix (`sentry_app::resolve`): the audit found a unit
    /// that failed.
    pub struct Rig;

    const FINDING: &str = "unit-failed:rowsmatrix:thing.service";

    fn reports(still: bool) -> Vec<crate::audit::store::Stored> {
        let mut findings = Vec::new();
        if still {
            findings.push(crate::finding::Finding {
                id: FINDING.into(),
                severity: crate::finding::Sev::High,
                category: "units".into(),
                message: "thing.service failed".into(),
                evidence: "Result=exit-code".into(),
                ..Default::default()
            });
        }
        vec![crate::audit::store::Stored {
            path: std::path::PathBuf::from("2026-10-26-110000.json"),
            report: crate::audit::Report {
                version: crate::audit::VERSION,
                taken_at: "2026-10-26T11:00:00Z".parse().unwrap(),
                tag: None,
                host: Default::default(),
                sections: Default::default(),
                errors: Vec::new(),
                findings,
            },
        }]
    }

    fn local(a: &mut sentry_app::App) -> &mut super::target::LocalTarget {
        a.slot_mut()
            .target
            .as_any_mut()
            .downcast_mut()
            .expect("this machine")
    }

    impl sentry_app::resolve::Rig for Rig {
        fn kind(&self) -> &'static str {
            "this machine"
        }

        fn app(&self, _name: &str) -> sentry_app::App {
            let (tx, _rx) = std::sync::mpsc::channel();
            let mut data =
                super::data::DataStore::blank("44.1".into(), "7.2.8-200.fc44.x86_64".into());
            data.reports.set(Ok(reports(true)));
            let mut a = sentry_app::App::new(tx, super::ID, |mail| {
                Box::new(super::target::LocalTarget::with(
                    Default::default(),
                    data,
                    mail,
                ))
            });
            a.win.offline = true;
            a.win.theme = sentry_core::tui::theme::Theme::truecolor();
            a.slot_mut().screen = sentry_core::tui::ScreenId::Maint;
            a
        }

        fn finding(&self) -> (String, String) {
            (FINDING.into(), format!("finding:{FINDING}"))
        }

        /// This machine's config lists nothing that must be there.
        fn watched(&self) -> Option<String> {
            None
        }

        fn audited(&self, a: &mut sentry_app::App, still: bool) {
            let id = local(a)
                .audited_for_test(FINDING, still)
                .expect("the audit was started");
            a.on_event(
                super::Event::Stream(
                    super::ID.to_string(),
                    id,
                    sentry_core::exec::StreamMsg::Exit {
                        code: 0,
                        elapsed: std::time::Duration::ZERO,
                    },
                ),
                std::time::Instant::now(),
            );
        }

        fn reread(&self, a: &mut sentry_app::App) {
            use super::data::{Data, Fetch, Payload};
            a.on_event(
                super::Event::Data(
                    super::ID.to_string(),
                    Box::new(Data(
                        Fetch::Reports,
                        Box::new(Ok(Payload::Reports(reports(true)))),
                    )),
                ),
                std::time::Instant::now(),
            );
        }

        fn workflow(&self, _a: &mut sentry_app::App, _name: &str) -> Box<dyn std::any::Any> {
            use sentry_app::resolve::WF;
            let turn = runs_turn();
            let dir = crate::workflows::dir();
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join(format!("{WF}.toml")),
                format!(
                    "name = \"{WF}\"\ndescription = \"test\"\n[[steps]]\nid = \"one\"\n\
                     title = \"one\"\nrun = \"true\"\ngate = \"auto\"\n"
                ),
            )
            .unwrap();
            Box::new(turn)
        }

        fn not_here(&self, way: sentry_app::resolve::Way) -> Option<&'static str> {
            use sentry_app::resolve::Way;
            match way {
                Way::DiskConfig => Some("this machine's config lists nothing to watch"),
                _ => None,
            }
        }

        fn scope(&self, _name: &str) -> String {
            crate::maint::LOCAL.to_string()
        }
    }
}

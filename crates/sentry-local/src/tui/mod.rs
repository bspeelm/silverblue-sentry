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
}

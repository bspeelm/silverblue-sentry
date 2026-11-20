//! sentry's TUI: this machine as a target of the app (`sentry_app`), its screens and their
//! data. The terminal, event loop and widgets are `sentry_core::tui` (re-exported here).
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

/// The app with this machine as its one target.
pub fn app(tx: std::sync::mpsc::Sender<Event>) -> sentry_app::App {
    let (cfg, warnings) = crate::config::Config::load();
    let mut app = sentry_app::App::new(tx, target::LocalTarget::ID, |mail| {
        Box::new(target::LocalTarget::new(cfg, mail))
    });
    // What's wrong in config.toml, said once the TUI is up (ahead of a `[keys]` warning).
    if let Some(w) = warnings.into_iter().next() {
        app.warn_at_start(w);
    }
    app
}

pub fn run() -> anyhow::Result<()> {
    run_ui(app)
}

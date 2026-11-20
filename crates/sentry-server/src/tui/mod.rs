//! The sentry-server TUI: one server, sentry's screens, everything fetched over ssh while you
//! watch. The app itself (the frame, sessions, series, reviews, records, the workflow run) is
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

/// The app with this server as its one target.
pub fn app(remote: Remote, tx: Sender<Event>) -> App {
    let id = ServerTarget::id_of(&remote.name);
    App::new(tx, &id, |mail| Box::new(ServerTarget::new(remote, mail)))
}

pub fn run(remote: Remote) -> anyhow::Result<()> {
    sentry_core::tui::run_ui(|tx| app(remote, tx))
}

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
}

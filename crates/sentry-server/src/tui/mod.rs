//! The sentry-server TUI: one server, sentry's screens, everything fetched over ssh while you
//! watch.
//! Built on the same runtime as the local TUI ([`sentry_core::tui::run_ui`]).

mod actions;
mod app;
mod ask;
mod data;
mod planview;
mod screens;
#[cfg(test)]
mod tests;

use ratatui::crossterm::event::KeyEvent;

use crate::remote::{Remote, SrvError};
use sentry_core::exec::StreamMsg;
use sentry_core::tui::{Input, ScreenId, ScreenSet};

pub use app::App;

pub enum Ev {
    Key(KeyEvent),
    Paste(String),
    Resize,
    Signal,
    Data(data::Kind, Box<Result<data::Payload, SrvError>>),
    Run(u64, StreamMsg),
    /// Output fetched for the pane (logs).
    Text(u64, Result<String, String>),
}

impl From<Input> for Ev {
    fn from(i: Input) -> Self {
        match i {
            Input::Key(k) => Ev::Key(k),
            Input::Paste(t) => Ev::Paste(t),
            Input::Resize => Ev::Resize,
            Input::Signal => Ev::Signal,
        }
    }
}

/// This program's screens, with sentry's numbers and names: `1` Dashboard, `4` Containers,
/// `5` Services (where sentry has Flatpaks), `6` Maintenance, `0` the workflow run.
pub const SCREENS: ScreenSet = ScreenSet {
    ids: &[
        ScreenId::Dash,
        ScreenId::Cont,
        ScreenId::Svc,
        ScreenId::Maint,
        ScreenId::Upgrade,
    ],
    aliases: &[
        ("overview", ScreenId::Dash),
        ("workflows", ScreenId::Upgrade),
        ("run", ScreenId::Upgrade),
    ],
};

pub fn run(remote: Remote) -> anyhow::Result<()> {
    sentry_core::tui::run_ui(|tx| App::new(remote, tx))
}

//! sentry's TUI: the app, its screens and their data. The terminal, event loop and widgets are
//! `sentry_core::tui` (re-exported here).
//!
//! One main thread owns all state. An input thread forwards key events; background fetches and
//! streamed commands send `Event`s over the same channel. There is no ticker thread: the loop
//! sleeps until the active screen's next refresh is due, so idle screens cost ~nothing.

mod app;
mod data;
mod plans;
mod screens;
mod wf;

pub use sentry_core::tui::*;

use ratatui::crossterm::event::KeyEvent;

use crate::exec::StreamMsg;
pub use data::{Fetch, FetchErr, Payload};

impl From<Input> for Event {
    fn from(i: Input) -> Self {
        match i {
            Input::Key(k) => Event::Key(k),
            Input::Resize => Event::Resize,
            Input::Signal => Event::Signal,
        }
    }
}

pub enum Event {
    Key(KeyEvent),
    Resize,
    Data(Fetch, Box<Result<Payload, FetchErr>>),
    Run(u64, StreamMsg),
    Signal,
}

pub fn run() -> anyhow::Result<()> {
    run_ui(app::App::new)
}

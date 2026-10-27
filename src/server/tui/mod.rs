//! The sentry-server TUI: one server, seven tabs, everything fetched over ssh while you watch.
//! Built on the same runtime as the local TUI ([`crate::tui::run_ui`]).

mod actions;
mod app;
mod ask;
mod data;
mod maint;
mod planview;
mod tabs;
#[cfg(test)]
mod tests;
mod wftab;

use ratatui::crossterm::event::KeyEvent;

use crate::exec::StreamMsg;
use crate::server::remote::{Remote, SrvError};
use crate::tui::Input;

pub use app::App;

pub enum Ev {
    Key(KeyEvent),
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
            Input::Resize => Ev::Resize,
            Input::Signal => Ev::Signal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Services,
    Containers,
    Audit,
    Maint,
}

impl Tab {
    pub const ALL: [Tab; 5] = [
        Tab::Overview,
        Tab::Services,
        Tab::Containers,
        Tab::Audit,
        Tab::Maint,
    ];

    pub fn key(self) -> char {
        match self {
            Tab::Overview => '1',
            Tab::Services => '2',
            Tab::Containers => '3',
            Tab::Audit => '5',
            Tab::Maint => '6',
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Services => "Services",
            Tab::Containers => "Containers",
            Tab::Audit => "Audit",
            Tab::Maint => "Maintenance",
        }
    }

    fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

pub fn run(remote: Remote) -> anyhow::Result<()> {
    crate::tui::run_ui(|tx| App::new(remote, tx))
}

//! The Agent screen's own state: whether the configured command is there, what it says it
//! is, and what one test turn came to. Looked up on a worker when the screen is entered, on
//! `r`, and when the command is changed (never on a timer); the answers come back as
//! [`Msg`]s through the window's events (`Event::Config`), which is also how a test gives
//! them.

use ratatui::text::{Line, Span};
use sentry_core::claude::{Found, Tested};
use sentry_core::tui::theme::Theme;
use sentry_core::tui::widgets;

/// What a worker found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Found(Found),
    /// (The command that was asked, what the turn came to.)
    Tested(String, Tested),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Agent {
    /// The command these answers are about (`[agent] command` as it is to be).
    pub command: String,
    pub found: Option<Found>,
    pub finding: bool,
    pub test: Option<Tested>,
    pub testing: bool,
}

/// What the screen says of the agents there aren't.
pub const NOT_YET: &str =
    "Other agents, API connections and locally deployed models are not supported yet.";

impl Agent {
    /// The answers held are about this command.
    pub(crate) fn is_for(&self, cmd: &str) -> bool {
        self.command == cmd && (self.found.is_some() || self.finding)
    }

    /// `cmd` is being asked about: what was known of another is gone.
    pub(crate) fn asked(&mut self, cmd: &str) {
        *self = Self {
            command: cmd.to_string(),
            ..Default::default()
        };
    }

    pub(crate) fn on_msg(&mut self, m: Msg) {
        match m {
            Msg::Found(f) if f.command == self.command => {
                self.found = Some(f);
                self.finding = false;
            }
            Msg::Tested(cmd, r) if cmd == self.command => {
                self.test = Some(r);
                self.testing = false;
            }
            // About a command that was changed since: nobody's.
            _ => {}
        }
    }

    /// The status, as the screen's right-hand panel says it.
    pub fn lines(&self, t: &Theme, offline: bool, width: usize) -> Vec<Line<'static>> {
        let row = |name: &str, text: String, style| {
            Line::from(vec![
                Span::styled(format!("{name:<9} "), t.dim()),
                Span::styled(text, style),
            ])
        };
        let mut out = vec![Line::styled("Status", t.s(t.mag))];
        out.push(row(
            "command",
            if self.command.is_empty() {
                "(none)".into()
            } else {
                self.command.clone()
            },
            t.fg(),
        ));
        out.push(match &self.found {
            _ if self.finding => row("found", "looking…".into(), t.dim()),
            Some(f) => match &f.path {
                Some(p) => row(
                    "found",
                    format!("✓ {}", widgets::short_home(p)),
                    t.s(t.green),
                ),
                None if f.command.contains('/') => {
                    row("found", "✗ no such file".into(), t.s(t.red))
                }
                None => row("found", "✗ not on PATH".into(), t.s(t.red)),
            },
            None if offline => row("found", "not looked up".into(), t.dim()),
            None => row("found", "r looks it up".into(), t.dim()),
        });
        if let Some(f) = self.found.as_ref().filter(|f| f.path.is_some()) {
            out.push(match &f.version {
                Some(v) => row("version", v.clone(), t.fg()),
                None => row("version", "it didn't say (--version)".into(), t.dim()),
            });
        }
        let mut test = match &self.test {
            _ if self.testing => vec![row("test", "asking for one word…".into(), t.dim())],
            Some(Tested::Answers(a)) => vec![row(
                "test",
                format!("✓ answers ({})", widgets::trunc(a, 40)),
                t.s(t.green),
            )],
            Some(Tested::NotLoggedIn) => vec![
                row("test", "✗ not logged in".into(), t.s(t.red)),
                row(
                    "",
                    format!("run `{}` once in a terminal, then t again", self.command),
                    t.fg(),
                ),
            ],
            Some(Tested::Failed(why)) => {
                let mut l = vec![row("test", "✗ it didn't answer".into(), t.s(t.red))];
                l.extend(
                    widgets::wrap(why, width.saturating_sub(10).max(20))
                        .into_iter()
                        .map(|x| row("", x, t.fg())),
                );
                l
            }
            None => vec![row(
                "test",
                "t tests it: one turn, no tools".into(),
                t.dim(),
            )],
        };
        out.append(&mut test);
        out.push(Line::raw(""));
        out.extend(
            widgets::wrap(NOT_YET, width.max(20))
                .into_iter()
                .map(|l| Line::styled(l, t.dim())),
        );
        out
    }
}

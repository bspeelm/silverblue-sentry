//! A workflow run as the app sees it: what a slot holds while one is in progress, whatever
//! kind of host runs its steps. The host's own session implements [`WfRun`]
//! ([`crate::remote::workflow::Session`] for one reached over ssh); how a step becomes a
//! command, and what sudo needs for it, stays with the target (`Host::run_go`).

use std::any::Any;
use std::time::{Duration, Instant};

use sentry_core::exec::Cmd;
use sentry_core::workflows::Workflow;
use sentry_core::workflows::runner::Next;
use sentry_core::workflows::state::Run;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    Info,
    Cmd,
    Out,
    Ok,
    Err,
}

/// How a step's command is run.
#[derive(Clone, Debug)]
pub enum How {
    /// As it is.
    Plain(Cmd),
    /// A command line for the host's shell that uses sudo: the app runs it with the target's
    /// password (asked once, in the key bar, when sudo wants one), never with the terminal
    /// handed over.
    Root(String),
}

/// What the app runs for the session.
pub enum Exec {
    /// Stream into the log. `dry`: a dry run of the step, before the real one; `timeout`:
    /// stopped when it takes longer.
    Stream {
        how: How,
        idx: usize,
        dry: bool,
        timeout: Option<Duration>,
    },
    /// An interactive shell for the step, with the terminal handed over.
    Shell { idx: usize },
    /// The host reboots; what follows is the target's (`Host::reboot`).
    Reboot { how: How },
}

/// The step that's running.
#[derive(Clone, Copy)]
pub struct Live {
    pub id: u64,
    pub idx: usize,
    pub pid: Option<u32>,
    pub started: Instant,
    /// It's the step's dry run.
    pub dry: bool,
    /// When it's stopped for taking too long.
    pub deadline: Option<Instant>,
}

pub trait WfRun: Any {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn wf(&self) -> &Workflow;
    /// Where the run is kept, and its state.
    fn run(&self) -> &Run;
    fn next(&self) -> &Next;
    fn live(&self) -> Option<&Live>;
    /// The running step is this one from now on; the one before is handed back.
    fn set_live(&mut self, live: Option<Live>) -> Option<Live>;
    /// Auto steps may run (the user opened the run or started it).
    fn armed(&self) -> bool;
    fn arm(&mut self);
    fn done(&self) -> bool;
    fn title(&self, idx: usize) -> String;
    fn state_word(&self) -> &'static str;
    fn push(&mut self, text: String, kind: LogKind);
    fn on_line(&mut self, text: &str, stderr: bool);
    fn on_exit(&mut self, idx: usize, code: i32);
    /// The step's command couldn't be started.
    fn spawn_failed(&mut self, idx: usize, _dry: bool, err: &str) {
        self.push(format!("✗ {err}"), LogKind::Err);
        self.on_exit(idx, 127);
    }
    /// The shell of a shell step exited.
    fn after_shell(&mut self, _idx: usize) {}
    fn skip(&mut self, force: bool) -> Result<(), String>;
    fn retry(&mut self) -> Result<(), String>;
    fn mark_done(&mut self) -> Result<(), String>;
    fn abandon(&mut self);
    /// The host is back with a new boot id.
    fn after_reboot(&mut self);
    /// The current step's log: (title, text).
    fn step_log(&self) -> Option<(String, String)>;
}

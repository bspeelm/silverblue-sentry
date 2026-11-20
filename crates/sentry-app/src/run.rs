//! A workflow run as the app sees it: what a slot holds while one is in progress, whatever
//! kind of host runs its steps. The host's own session implements [`WfRun`]
//! ([`crate::remote::workflow::Session`] for one reached over ssh); how a step becomes a
//! command, and what sudo needs for it, stays with the target (`Host::run_go`).

use std::any::Any;
use std::time::Instant;

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

/// What the app runs for the session.
pub enum Exec {
    /// Stream into the log.
    Stream { cmd: Cmd, idx: usize },
    /// Hand over the terminal (sudo that asks for a password). The output is also written to
    /// `capture` on the host, read back into the step's log afterwards (`tty_output`).
    Tty {
        cmd: Cmd,
        idx: usize,
        capture: String,
    },
    /// The host reboots; what follows is the target's (`Host::reboot`). `tty`: sudo asks for
    /// a password, so the terminal is handed over for it.
    Reboot { cmd: Cmd, tty: bool },
}

/// The step that's running.
pub struct Live {
    pub id: u64,
    pub idx: usize,
    pub pid: Option<u32>,
    pub started: Instant,
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
    fn on_line(&mut self, text: &str);
    fn on_exit(&mut self, idx: usize, code: i32);
    /// A step that had the terminal ended; `read`: its captured output is read back first.
    fn tty_ended(&mut self, idx: usize, capture: &str, code: i32, read: bool);
    fn skip(&mut self, force: bool) -> Result<(), String>;
    fn retry(&mut self) -> Result<(), String>;
    fn mark_done(&mut self) -> Result<(), String>;
    fn abandon(&mut self);
    /// The host is back with a new boot id.
    fn after_reboot(&mut self);
    /// The current step's log: (title, text).
    fn step_log(&self) -> Option<(String, String)>;
}

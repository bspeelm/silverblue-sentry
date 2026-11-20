//! What a host is to the app. One app holds different kinds (`Box<dyn Target>`): a target owns
//! its fetch threads, the kinds and payloads of what it reads, its data store and its screens,
//! all privately. The app asks it to start what is due, hands it what arrived, and calls it
//! where a flow needs to know something only this kind of host can say.
//!
//! The split: [`Target`] is identity, data and screens; [`Upkeep`] what its maintenance lists
//! hold; [`Asks`] what Claude is told and allowed; [`Host`] how a command line and a workflow
//! run reach it. Everything written once for every target lives in [`crate::slot`].

use std::any::Any;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::text::Line;

use crate::app::Event;
use crate::effect::{Effect, Own, ReadsFor};
use crate::run::{Exec, WfRun};
use crate::shared::Shared;
use sentry_core::claude::{Ask, Grant, Profile};
use sentry_core::exec::{Cmd, ExecError, StreamMsg};
use sentry_core::maint::changes::{Change, Known};
use sentry_core::maint::plan::PlanDoc;
use sentry_core::maint::tasks::Task;
use sentry_core::tui::docview::Writer;
use sentry_core::tui::keys::Action;
use sentry_core::tui::records::LaterRow;
use sentry_core::tui::theme::Theme;
use sentry_core::tui::{ScreenId, ScreenSet};
use sentry_core::workflows::Entry;

/// Which target: `""` this machine, `srv:<name>` a server, `net:<name>` a network.
pub type TargetId = String;

pub type Hints = Vec<(&'static str, &'static str)>;

/// A target's names and the words the frame says about it. Fixed for as long as it's open.
pub struct Ident {
    pub id: TargetId,
    /// What it's called on screen.
    pub title: String,
    /// The key of its records and data (`maint::root`, the ring's directory).
    pub scope: String,
    /// What it is in a sentence: "the server", "this machine".
    pub place: &'static str,
    /// The program's chip in the top bar, and what Claude is told runs its workflows.
    pub app: &'static str,
    pub screens: &'static ScreenSet,
    /// Where its workflow runs are kept.
    pub runs: PathBuf,
    /// The quit box's question.
    pub quit: String,
    /// `?`: the keys that work on every screen, the `:` commands, the last line.
    pub help_globals: &'static [(&'static str, &'static str)],
    pub commands: &'static str,
    pub help_footer: String,
    /// What Claude may do with what's sent, shown with a chat's brief and a session's.
    pub privacy: String,
    pub session_privacy: String,
}

/// How events reach a target's slot: its fetches, its streams and the logs it reads all come
/// back tagged with its id, whatever is in view.
#[derive(Clone)]
pub struct Mail {
    tx: Sender<Event>,
    id: TargetId,
    seq: Arc<AtomicU64>,
}

impl Mail {
    pub fn new(tx: Sender<Event>, id: &str, seq: Arc<AtomicU64>) -> Self {
        Self {
            tx,
            id: id.to_string(),
            seq,
        }
    }

    pub fn id(&self) -> &TargetId {
        &self.id
    }

    /// A new stream id, unique in the window.
    pub fn next(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Something a fetch thread read: the target gets it back in `Target::on_data`.
    pub fn send(&self, data: impl Any + Send) {
        let _ = self.tx.send(Event::Data(self.id.clone(), Box::new(data)));
    }

    /// Start `cmd`; its lines and exit arrive as stream `id`. Returns the pid.
    pub fn stream(&self, id: u64, cmd: &Cmd) -> Result<u32, ExecError> {
        let (tx, tid) = (self.tx.clone(), self.id.clone());
        cmd.stream(move |m| {
            let _ = tx.send(Event::Stream(tid.clone(), id, m));
        })
    }

    /// Run `cmd` to its end on a thread; its output arrives as text `id`.
    pub fn text(&self, id: u64, cmd: Cmd) {
        let (tx, tid) = (self.tx.clone(), self.id.clone());
        std::thread::spawn(move || {
            let res = cmd.output().map_err(|e| e.to_string());
            let _ = tx.send(Event::Text(tid, id, res));
        });
    }
}

/// What a target may look at of its slot and the window while it answers.
#[derive(Clone, Copy)]
pub struct Cx<'a> {
    pub theme: &'a Theme,
    /// The clock (fixed in snapshot tests).
    pub now: jiff::Timestamp,
    /// The screen in view.
    pub screen: ScreenId,
    /// Its `/` filter, as typed (may be empty, may be on a screen that has none).
    pub filter: Option<&'a str>,
    /// Maintenance lists what can wait too (`o`).
    pub everything: bool,
    /// What Claude is writing in the background (a plan, a review), or last wrote.
    pub writer: Option<&'a Writer>,
    /// The workflow run in progress (or just ended).
    pub run: Option<&'a dyn WfRun>,
    /// When the last maintenance run or change ended.
    pub last_change: Option<jiff::Timestamp>,
    /// Tests: nothing is fetched, written or sent.
    pub offline: bool,
}

/// Why a target should read something again.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Why {
    /// Its maintenance lists (a snooze, a log entry, a task changed).
    Lists,
    /// An apply session's step ran.
    Step,
    /// A workflow run ended: what a run can change is read again.
    Run,
    /// A run that ended well is in the log: the host is not as it was last read.
    Changed,
    /// A fix was applied: audit what it was about again.
    Reaudit,
    /// Audit now (a series' row, `:audit now`).
    Audit,
    /// The user edited a file of its own.
    Edited,
}

/// Why a target's cursors and selections may need putting right.
#[derive(Clone, Debug, PartialEq)]
pub enum Settle {
    /// A key was handled.
    Key,
    /// The lists changed.
    Lists,
    /// The filter of the screen in view changed.
    Filter,
    /// A series ended: these rows stay ticked.
    Ticks(Vec<String>),
    /// The workflow at this place in the list is the one meant.
    Workflow(usize),
}

/// A screen in the strip.
pub struct TabInfo {
    pub id: ScreenId,
    pub badge: Option<(String, Color)>,
    /// It takes a `/` filter.
    pub filterable: bool,
}

/// Which of Claude's roles a profile is for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProfileFor {
    Chat,
    Session,
    Plan,
    Review,
}

/// What the row a series is at needs.
pub enum SeriesStep {
    Session(Ask),
    Plan(String, PlanDoc),
    Workflow(String),
    Audit,
}

/// A review's changes that only this kind of target has (tracked items…), settled together
/// with the tasks: applied in memory, saved with the rest, then taken in.
pub trait Changes {
    /// None: not one of this target's.
    fn apply(&mut self, c: &Change) -> Option<Result<String, String>>;
    fn save(&mut self) -> Result<(), String>;
    /// What changed on the target's side, for it to take in; nothing when nothing did.
    fn done(self: Box<Self>) -> Vec<Effect>;
}

pub trait Target: Upkeep + Asks + Host {
    fn ident(&self) -> &Ident;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;

    // ---- data: its own threads, kinds and store
    /// The TUI is up: what's read once, and what was left from last time.
    fn start(&mut self, sh: &mut Shared, cx: &Cx) -> Vec<Effect>;
    /// `cx.screen` came into view (from `from`): what it shows is fetched right away.
    fn enter(&mut self, from: ScreenId, now: Instant, sh: &Shared, cx: &Cx) -> Vec<Effect>;
    /// Start what the screen in view polls and is due.
    fn due(&mut self, now: Instant, cx: &Cx);
    /// When `due` next has something to do.
    fn next_due(&self) -> Option<Instant>;
    /// Something one of its threads sent (`Mail::send`).
    fn on_data(&mut self, data: Box<dyn Any + Send>, sh: &mut Shared, cx: &Cx) -> Vec<Effect>;
    /// A stream of its own (`Mail::stream`). None: not one of its.
    fn on_stream(&mut self, _id: u64, _m: &StreamMsg, _cx: &Cx) -> Option<Vec<Effect>> {
        None
    }
    fn refresh(&mut self, why: Why, cx: &Cx) -> Vec<Effect>;
    /// One of its own effects came back.
    fn on_own(&mut self, fx: &Own, sh: &mut Shared, cx: &Cx) -> Vec<Effect>;
    /// A command of its own that had the terminal ended.
    fn after_suspend(
        &mut self,
        own: &Own,
        status: Result<ExitStatus, ExecError>,
        sh: &mut Shared,
        cx: &Cx,
    ) -> Vec<Effect>;

    // ---- screens
    fn handle(&mut self, a: Action, sh: &Shared, cx: &Cx) -> Vec<Effect>;
    fn render(&mut self, f: &mut Frame, area: Rect, sh: &Shared, cx: &Cx);
    /// The keys of the screen in view; `help`: every one, for `?`.
    fn hints(&self, help: bool, sh: &Shared, cx: &Cx) -> Hints;
    /// The strip.
    fn tabs(&self, sh: &Shared, cx: &Cx) -> Vec<TabInfo>;
    fn settle(&mut self, why: Settle, sh: &Shared, cx: &Cx);
    /// The top bar: facts about the host, and the state of the connection.
    fn top(&self, cx: &Cx) -> (Vec<String>, (String, Color));
    /// A `:` command only this target has.
    fn colon(
        &mut self,
        _cmd: &str,
        _arg: Option<&str>,
        _sh: &Shared,
        _cx: &Cx,
    ) -> Option<Vec<Effect>> {
        None
    }
}

/// What its maintenance lists hold.
pub trait Upkeep {
    /// The tasks its config implies (cadences); `tasks.toml` goes over them.
    fn derived_tasks(&self, sh: &Shared) -> Vec<Task>;
    /// Everything on Maintenance a review's changes may name.
    fn with_known(&self, sh: &Shared, cx: &Cx, f: &mut dyn FnMut(&Known));
    fn changes(&self, sh: &Shared, cx: &Cx) -> Box<dyn Changes>;
    /// What the row with this key needs now (None: it left the list).
    fn series_step(&self, key: &str, sh: &Shared, cx: &Cx) -> Option<SeriesStep>;
    /// Enter on a task.
    fn task_enter(&self, id: &str, sh: &Shared, cx: &Cx) -> Vec<Effect>;
    /// A maintenance item's (kind, risk), for the log.
    fn item_kind(&self, item: &str) -> Option<(String, String)>;
    /// What Records lists besides the shared records: rows of its own under Later, and when
    /// it was last audited.
    fn records(&self, sh: &Shared, cx: &Cx) -> (Vec<LaterRow>, Option<jiff::Timestamp>);
    /// Take back one of those rows, or something marked expected.
    fn undo(&mut self, row: &LaterRow, sh: &mut Shared, cx: &Cx) -> Result<Vec<Effect>, String>;
    /// A run or a series is over and nothing more is asked about it: anything to offer?
    fn settled(&mut self, _cx: &Cx) -> Vec<Effect> {
        Vec::new()
    }
}

/// What Claude is asked, told and allowed.
pub trait Asks {
    /// About the screen in view (its selected row, the run), or why there's nothing.
    fn ask(&self, sh: &Shared, cx: &Cx) -> Result<Ask, String>;
    /// Applying the selected Maintenance row.
    fn apply_ask(&self, sh: &Shared, cx: &Cx) -> Option<Ask>;
    /// Carrying out an item's plan (`key`: the session's).
    fn plan_ask(&self, item: &str, key: String, sh: &Shared, cx: &Cx) -> Option<Ask>;
    /// Before Claude plans an item: what the box says, and the request.
    fn plan_brief(
        &self,
        item: &str,
        doc: &PlanDoc,
        sh: &Shared,
        cx: &Cx,
    ) -> Result<(Vec<Line<'static>>, String), String>;
    /// What a review reads and does, shown before one is started.
    fn review_brief(&self, cx: &Cx) -> Vec<Line<'static>>;
    /// What a review is sent; `auto`: one the app starts by itself, and what it's about.
    fn review_request(&self, auto: Option<&str>, changes: &str, sh: &Shared, cx: &Cx) -> String;
    /// What Claude is sent to revise an item's plan.
    fn plan_revise(&self, what: &str) -> String;
    /// Claude's profile for one of its roles; `grants`: what the user allowed in this
    /// conversation (a chat's, a session's).
    fn profile(&self, f: ProfileFor, grants: &[Grant]) -> Profile;
    /// The answer says Claude waits for reads only the user can allow.
    fn waits_for_reads(&self, _answer: &str) -> bool {
        false
    }
    /// After a turn: what Claude asked to read that needs the user. `waiting`: its answer
    /// waits for them.
    fn offer_reads(&mut self, _to: ReadsFor, _waiting: bool, _cx: &Cx) -> Vec<Effect> {
        Vec::new()
    }
}

/// How a command line and a workflow run reach the host.
pub trait Host {
    /// The line as a command on the host (its shell over ssh, this machine's bash).
    fn command(&self, line: &str) -> Cmd;
    /// The workflows there are, and where they come from.
    fn workflows(&self) -> (Vec<Entry>, PathBuf);
    fn begin_run(
        &self,
        entry: &Entry,
        vars: BTreeMap<String, String>,
    ) -> Result<Box<dyn WfRun>, String>;
    /// A run left in progress.
    fn resume_run(&self) -> Option<Box<dyn WfRun>>;
    /// The run's next step (`auto`: only if it runs without asking): what to execute. What
    /// the step needs of the host (sudo) is checked here.
    fn run_go(&mut self, run: &mut dyn WfRun, auto: bool, cx: &Cx) -> Result<Option<Exec>, String>;
    /// A streamed step ended.
    fn step_ended(&mut self, _run: &dyn WfRun, _cx: &Cx) {}
    /// A workflow's reboot step: what rebooting this host means is the target's.
    fn reboot(&mut self, cmd: Cmd, tty: bool, old_boot: String, cx: &Cx) -> Vec<Effect>;
}

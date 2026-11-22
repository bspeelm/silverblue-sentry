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
use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::text::Line;

use crate::app::Event;
use crate::effect::{Effect, ItemChange, Own, Prompt, ReadsFor};
use crate::run::{Exec, WfRun};
use crate::shared::Shared;
use sentry_core::claude::{Ask, Grant, Profile};
use sentry_core::exec::{Cmd, ExecError, StreamMsg};
use sentry_core::maint::changes::{Change, Known};
use sentry_core::maint::log::ItemInfo;
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
    /// Its kind's `:` command, which gives it the window: `local`, `server` (with a name
    /// when there are several: `:server my`).
    pub word: &'static str,
    /// The program's chip in the top bar, and what Claude is told runs its workflows.
    pub app: &'static str,
    pub screens: &'static ScreenSet,
    /// Where its workflow runs are kept.
    pub runs: PathBuf,
    /// Where its workflows come from, as shown until they're read.
    pub wf_dir: String,
    /// Where this program's flows go their own way.
    pub ways: Ways,
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

/// Where one program's flows differ from another's: its words, and the rules it keeps. The
/// default is the app's own way (a host over ssh); a target says only what it does otherwise.
#[derive(Clone, Copy)]
pub struct Ways {
    /// Said when Claude Code isn't there.
    pub no_claude: &'static str,
    /// The run's next auto step is looked for on every tick and after every workflow key
    /// (what it waits for is read in the background: how sudo works there). Off: when the
    /// run is armed, a step ends, or the terminal comes back. Either way a run goes on
    /// whatever screen, and whichever target, is in view.
    pub auto_polled: bool,
    /// Rebooting this host ends the TUI: a workflow's reboot step waits while another
    /// target is at work, and goes by itself when that settles.
    pub reboot_ends_tui: bool,
    /// A run left in progress is shown at start.
    pub resume_opens_run: bool,
    /// The workflows are read at start (off: when something first needs them).
    pub workflows_at_start: bool,
    /// The key of the run's screen leaves Records, a plan or a review open.
    pub docs_keep_run_key: bool,
    /// With both open, the review is over the plan (off: the plan over the review, and
    /// Records over both).
    pub review_over_plan: bool,
    /// The words of a prompt, where they aren't the app's: what it asks, and what Enter does.
    pub label: fn(&Prompt) -> Option<(String, &'static str)>,
    /// What is being typed into a prompt, as the input line shows it, where that isn't
    /// what was typed (a router's new passphrase among a run's values: dots).
    pub typed: fn(&Prompt, &str) -> Option<String>,
    /// Esc on a workflow's values says this.
    pub not_started: Option<&'static str>,
    /// A run's note was saved.
    pub noted: &'static str,
    /// A task marked done asks for its note in words of its own, and no review follows it.
    pub task_note: bool,
    /// Tasks done in a session are logged under their titles (off: their ids).
    pub log_task_title: bool,
    /// A session marked done by hand closes its plan as done by hand.
    pub plans_by_hand: bool,
    /// A session's log entry names its item (`item:<id>`).
    pub log_item_tag: bool,
    /// A plan closed by its session is said, and its view closes.
    pub plan_done_says: bool,
    /// A plan that isn't there isn't opened: this is said (with what it's for).
    pub no_plan: Option<fn(&str) -> String>,
    /// The Plan view's keys, when a plan is there.
    pub plan_hints: &'static [(&'static str, &'static str)],
    /// C-c in the Plan view.
    pub plan_stopped: &'static str,
    /// A series doesn't start while Claude writes a review that was asked for.
    pub series_waits_writer: bool,
    /// A series' next row closes a plan left open.
    pub series_closes_plan: bool,
    /// The audit runs in the pane: a series closes it when it goes on.
    pub audit_in_pane: bool,
    /// What a review may change is asked for as a server's (`changes::request_section`).
    pub server_changes: bool,
    /// Whether a task is due after a run counts the last audit.
    pub due_counts_audit: bool,
    /// What a plan or a review says it's about ("server", "machine").
    pub writer_place: &'static str,
    /// The first question's line in a chat's transcript.
    pub first_shown: fn(&Ask) -> String,
    /// Offline (tests), a chat's turn still counts as running.
    pub offline_turns_live: bool,
    /// The session's workflow needs the user: what follows the workflow's name.
    pub needs_you: &'static str,
    /// Leaving ends the pane's command and the run's step.
    pub exit_kills_run: bool,
    /// Leaving ends the session's turn and step.
    pub exit_kills_session: bool,
    /// Opening the session's run looks for another run in progress first, and goes to the
    /// run's screen only when it runs.
    pub run_checks: bool,
    /// The log in memory follows every entry written, a run's note too (and tests, which
    /// write nothing, still see their runs in it).
    pub log_kept: bool,
    /// The pane: lines kept, whether it says how long the command took, what a command that
    /// couldn't start shows (before the error) and its exit code, what C-c says (none: a
    /// line in the pane), what a key says while it runs, and whether scrolling stops at
    /// the top.
    pub pane_lines: usize,
    pub pane_took: bool,
    pub pane_failed: (&'static str, i32),
    pub pane_kill: Option<&'static str>,
    pub pane_busy: &'static str,
    pub pane_clamp: bool,
}

impl Default for Ways {
    fn default() -> Self {
        Self {
            no_claude: "Claude Code isn't installed (or not on PATH)",
            auto_polled: true,
            reboot_ends_tui: false,
            resume_opens_run: true,
            workflows_at_start: true,
            docs_keep_run_key: true,
            review_over_plan: true,
            label: |_| None,
            typed: |_, _| None,
            not_started: Some("not started"),
            noted: "noted in the maintenance log",
            task_note: false,
            log_task_title: false,
            plans_by_hand: true,
            log_item_tag: true,
            plan_done_says: true,
            no_plan: None,
            plan_hints: &[
                ("Enter", "apply"),
                ("A", "claude"),
                ("P", "start over"),
                ("x", "drop"),
                ("j/k PgUp/Dn", "scroll"),
                ("Esc", "back"),
            ],
            plan_stopped: "stopped: the plan keeps what it had",
            series_waits_writer: true,
            series_closes_plan: true,
            audit_in_pane: false,
            server_changes: true,
            due_counts_audit: false,
            writer_place: "server",
            first_shown: |a| a.question.lines().next().unwrap_or("").to_string(),
            offline_turns_live: false,
            needs_you: " needs you · the plan carries on after its run (A)",
            exit_kills_run: true,
            exit_kills_session: false,
            run_checks: true,
            log_kept: false,
            pane_lines: 5000,
            pane_took: false,
            pane_failed: ("✗ ", -1),
            pane_kill: None,
            pane_busy: "running · C-c stops it",
            pane_clamp: true,
        }
    }
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
    /// The moment of the event being handled (what scheduling counts from).
    pub at: Instant,
    /// One of the slot's boxes is open.
    pub modal: bool,
    /// The pane is open (true: its command still runs).
    pub pane: Option<bool>,
    /// Claude is answering in the chat.
    pub chat_running: bool,
    /// The finding the apply session is fixing.
    pub finding: Option<&'a str>,
    /// The target's sudo password is held: what needs root runs without asking.
    pub root: bool,
    /// Auto mode is on for the target.
    pub auto: bool,
    /// The target has the window: its screen is the one in view, and what that screen polls
    /// may be fetched. Out of view a target fetches only what its own work waits for.
    pub focused: bool,
    /// What the target is called (the top bar's name for it).
    pub target: &'a str,
    /// Every target the window has, as last surveyed (empty with one): what each says of
    /// itself, its `SystemLine::facts` among it. How one target shows what another knows
    /// without depending on it: the app carries, the target reads by name.
    pub system: &'a [crate::system::Sys],
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
    /// A run's entry was written to the log.
    Logged,
    /// What's marked expected changed (a listener taken back in Records).
    Baseline,
    /// The security audit is about to read every target: what this one reads as root,
    /// and can read now (its password is held), is read again first.
    Facts,
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
    /// It was emptied.
    FilterCleared,
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
    Review,
    /// A session started on another target: how it reaches this one (its gateway and
    /// reads, its denials). What it changes here are plan steps, run by this target.
    Peer,
}

/// What the row a series is at needs.
pub enum SeriesStep {
    Session(Box<Ask>),
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
    /// Start what the screen in view polls and is due. True: draw again.
    fn due(&mut self, now: Instant, cx: &Cx) -> bool;
    /// When `due` next has something to do.
    fn next_due(&self, now: Instant, cx: &Cx) -> Option<Instant>;
    /// Something one of its threads sent (`Mail::send`).
    fn on_data(&mut self, data: Box<dyn Any + Send>, sh: &mut Shared, cx: &Cx) -> Vec<Effect>;
    /// A stream of its own (`Mail::stream`). None: not one of its.
    fn on_stream(&mut self, _id: u64, _m: &StreamMsg, _cx: &Cx) -> Option<Vec<Effect>> {
        None
    }
    fn refresh(&mut self, why: Why, cx: &Cx) -> Vec<Effect>;
    /// One of its own effects came back.
    fn on_own(&mut self, fx: &Own, sh: &mut Shared, cx: &Cx) -> Vec<Effect>;
    /// A prompt of its own was answered (None: dismissed).
    fn on_prompt(
        &mut self,
        _own: &Own,
        _answer: Option<&str>,
        _sh: &mut Shared,
        _cx: &Cx,
    ) -> Vec<Effect> {
        Vec::new()
    }
    /// A pane's command that named an end of its own (`RunSpec::end`) exited: its code and
    /// its last lines.
    fn pane_ended(
        &mut self,
        _end: &Own,
        _code: i32,
        _tail: &[String],
        _sh: &mut Shared,
        _cx: &Cx,
    ) -> Vec<Effect> {
        Vec::new()
    }
    /// Something read as root for it (`Effect::RootRead`) came back: its output, or why not.
    fn root_read(
        &mut self,
        _own: &Own,
        _out: Result<String, String>,
        _sh: &mut Shared,
        _cx: &Cx,
    ) -> Vec<Effect> {
        Vec::new()
    }
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
    /// A `:` command only this target has (`line`: all of it, as typed).
    fn colon(
        &mut self,
        _line: &str,
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
    /// A run ended: the key of the plan it carried out (closed when it ended well).
    fn run_plan(&mut self, _run: &dyn WfRun, change: Option<&ItemChange>) -> Option<String> {
        change.map(|c| c.item.clone())
    }
    /// What the run changed, for the log (`plan`: the plan it closed).
    fn run_info(
        &self,
        _run: &dyn WfRun,
        change: Option<&ItemChange>,
        plan: Option<PathBuf>,
    ) -> Option<ItemInfo> {
        let c = change?;
        let (kind, risk) = self
            .item_kind(&c.item)
            .unwrap_or_else(|| ("system".into(), "medium".into()));
        Some(ItemInfo {
            item: c.item.clone(),
            kind,
            risk,
            from: c.from.clone(),
            to: c.to.clone(),
            plan,
        })
    }
}

/// What Claude is asked, told and allowed.
pub trait Asks {
    /// Claude can be asked about this target, and it has work auto mode could carry. A
    /// kind of target that has neither yet says no: the key bar and `?` then offer
    /// neither, and `A` says `Ways::no_claude`.
    fn offered(&self) -> bool {
        true
    }
    /// Auto mode has work to carry on this target, so its key is named where work is
    /// started and followed. As `offered`, unless a target has workflows and no Claude yet.
    fn auto_offered(&self) -> bool {
        self.offered()
    }
    /// About the screen in view (its selected row, the run), or why there's nothing.
    fn ask(&self, sh: &Shared, cx: &Cx) -> Result<Ask, String>;
    /// Applying the selected Maintenance row.
    fn apply_ask(&self, sh: &Shared, cx: &Cx) -> Option<Ask>;
    /// Carrying out an item's plan (`key`: the session's).
    fn plan_ask(&self, item: &str, key: String, sh: &Shared, cx: &Cx) -> Option<Ask>;
    /// The header of a plan kept for the first time under `key` (an item's, a workflow's):
    /// what it's for, its workflow and values. None: the app's plain one.
    fn plan_head(
        &self,
        _key: &str,
        _sh: &Shared,
        _cx: &Cx,
    ) -> Option<sentry_core::maint::plan::Head> {
        None
    }
    /// A session's plan is about to be kept: anything of the target's to put in its header
    /// (the version it moves to, into the workflow's values).
    fn plan_kept(&self, _doc: &mut PlanDoc, _answer: &str) {}
    /// Words about to be written down for this target (a log entry's, a run's note), as
    /// they may be kept: a router's takes out a secret one of its runs was given. None: as
    /// they are.
    fn kept(&self, _text: &str) -> Option<String> {
        None
    }
    /// What a review reads and does, shown before one is started.
    fn review_brief(&self, cx: &Cx) -> Vec<Line<'static>>;
    /// What a review is sent; `auto`: one the app starts by itself, and what it's about.
    fn review_request(&self, auto: Option<&str>, changes: &str, sh: &Shared, cx: &Cx) -> String;
    /// Claude's profile for one of its roles; `grants`: what the user allowed in this
    /// conversation (a chat's, a session's).
    fn profile(&self, f: ProfileFor, grants: &[Grant]) -> Profile;
    /// A key in the Plan view that this target takes itself (None: the app's own keys).
    fn plan_key(
        &mut self,
        _item: &str,
        _key: KeyEvent,
        _writing: bool,
        _sh: &Shared,
        _cx: &Cx,
    ) -> Option<Vec<Effect>> {
        None
    }
    /// `C` in an idle chat: carry the conversation on somewhere else (its Claude session).
    fn chat_continue(&mut self, _session: &str) -> Option<Vec<Effect>> {
        None
    }
    /// The session that fixes one of the security audit's items, started here: the
    /// audit's own brief, as this kind of target opens a session.
    fn sec_ask(&self, item: &sentry_core::secaudit::Item, _sh: &Shared, _cx: &Cx) -> Ask {
        let mut ask = item.ask();
        if let Some(sentry_core::claude::Target::Apply(a)) = ask.target.as_mut() {
            a.remote = self.peer().remote;
        }
        ask
    }
    /// The rules this target keeps for any session's steps and requests, whichever
    /// target the session started on.
    fn peer(&self) -> sentry_core::apply::session::Peer;
    /// What it is, for a session's "the system" section, and how other hosts may know
    /// it (matched by the app, never shown).
    fn describe(&self, sh: &Shared, cx: &Cx) -> crate::system::SystemLine;
    /// Secret values a session holds (captured on any target, or asked for), told to
    /// every target a session touches: a target that sweeps what it writes down by
    /// itself (a router's run log and state) takes them in.
    fn given(&mut self, _secrets: &[String]) {}
    /// What a command sentry ran for Claude printed, as Claude may see it (a router's
    /// output with what is private scrubbed). None: as it is.
    fn hides(&self, _text: &str) -> Option<String> {
        None
    }
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
    /// Whether sudo there asks for a password right now (looked up again each time: it can
    /// change while this is open). Err: there's no sudo to use, and why.
    fn sudo_asks(&mut self, cx: &Cx) -> Result<bool, String>;
    /// The workflows there are, and where they come from.
    fn workflows(&self) -> (Vec<Entry>, PathBuf);
    /// The workflow as it is now, when the list read earlier isn't to be trusted for it.
    fn find_workflow(&self, _name: &str) -> Option<Entry> {
        None
    }
    fn begin_run(
        &mut self,
        entry: &Entry,
        vars: BTreeMap<String, String>,
        sh: &Shared,
    ) -> Result<Box<dyn WfRun>, String>;
    /// Starting a workflow by name (`:wf`, a recommendation, a series' row), when that's
    /// the target's own flow. None: the app's start box.
    fn wf_start(&mut self, _name: &str, _sh: &Shared, _cx: &Cx) -> Option<Vec<Effect>> {
        None
    }
    /// An apply session's plan starts a workflow with these values, the target's own way.
    /// None: the app's (a refusal fails the step, the plan's values come first).
    fn session_starts(
        &mut self,
        _wf: &str,
        _vars: &BTreeMap<String, String>,
        _sh: &Shared,
        _cx: &Cx,
    ) -> Option<Vec<Effect>> {
        None
    }
    /// A workflow command of its own (`WfCmd::Own`), on the run.
    fn run_cmd(
        &mut self,
        _run: &mut dyn WfRun,
        _own: &Own,
        _sh: &Shared,
        _cx: &Cx,
    ) -> Result<Vec<Effect>, String> {
        Ok(Vec::new())
    }
    /// A run left in progress.
    fn resume_run(&self) -> Option<Box<dyn WfRun>>;
    /// The run's next step (`auto`: only if it runs without asking): what to execute. What
    /// the step needs of the host (sudo) is checked here.
    fn run_go(&mut self, run: &mut dyn WfRun, auto: bool, cx: &Cx) -> Result<Option<Exec>, String>;
    /// A streamed step ended.
    fn step_ended(&mut self, _run: &dyn WfRun, _cx: &Cx) {}
    /// A workflow's reboot step: what rebooting this host means is the target's.
    fn reboot(&mut self, cmd: Cmd, old_boot: String, cx: &Cx) -> Vec<Effect>;
}

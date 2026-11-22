//! What a key press, a box or a target asks the app to do, and what the one input line in the
//! key bar can be asking for.

use std::any::Any;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;

use ratatui::crossterm::event::KeyEvent;
use ratatui::text::Line;

use crate::run::LogKind;
use sentry_core::claude::Ask;
use sentry_core::exec::Cmd;
use sentry_core::maint::log::LogEntry;
use sentry_core::tui::ScreenId;
use sentry_core::tui::input::PromptLine;
use sentry_core::tui::modal;

/// Something only one kind of target has (an inventory read, tracking an item, one of its
/// fetches): the app hands it back to the target that made it (`Target::on_own`).
#[derive(Clone)]
pub struct Own(pub Rc<dyn Any>);

impl std::fmt::Debug for Own {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Own(..)")
    }
}

/// What a key press asks the app to do.
#[derive(Clone, Debug)]
pub enum Effect {
    /// The target's own: back to it.
    Own(Own),
    Toast(String),
    Info(String, Vec<Line<'static>>),
    Goto(ScreenId),
    Quit,
    Confirm(Modal),
    /// A box whose no (n, Esc) does something too.
    ConfirmOr(Modal, Vec<Effect>),
    /// Stream a command's output into the pane (after a confirm).
    Run(RunSpec),
    /// Hand the terminal to a command (an editor, a shell, a pager): never for sudo.
    Suspend(Suspend),
    /// Read something as root, quietly: the line (with sudo in it) is run with the target's
    /// password when sudo wants one (asked first if it isn't held), and its output goes to
    /// the target (`Target::root_read`).
    RootRead(RootRead),
    /// Forget the sudo password held for this target (`C-f`).
    Forget,
    /// Read-only output, fetched once, shown in the scrollable pane.
    Logs(String, Cmd),
    /// Pick one of several (digits 1-9).
    Choose(Choice),
    /// Workflow actions.
    Wf(WfCmd),
    /// Open the plan saved for an item, to read (`p`).
    PlanOpen(String),
    /// The session for an item: opened on its saved plan when one is ready (straight at
    /// the plan, to approve), else from the start (it researches, then shows its plan).
    PlanApply(String),
    /// Start over (`P`): the saved plan is set aside (plans/done/) and the session begins
    /// from its research.
    PlanAgain(String),
    /// Open the maintenance log, marking this item's entries.
    LogOpen(Option<String>),
    /// The latest maintenance review (or the box to write one).
    ReviewOpen,
    /// Maintenance: list what can wait too, or only what's needed (`o`).
    Everything,
    /// Maintenance: do the ticked rows (key, title) one after another.
    SeriesStart(Vec<(String, String)>),
    /// Start a workflow (its start box first).
    StartWorkflow(String),
    /// The workflows are read again (`r` on screen 0).
    ReloadWorkflows,
    /// Open a file in $EDITOR (a workflow, the target's config); what it holds is read again
    /// after.
    Edit(PathBuf),
    /// The current step's log, in the pane.
    StepLog,
    /// Look at a maintenance row again later (`z`).
    Snooze(String, jiff::civil::Date),
    /// Drop an item's plan (`x`, after a confirm).
    PlanDrop(String),
    /// A plan without a workflow, carried out by hand: close it and log the change.
    PlanDoneByHand(String),
    /// Open a conversation with Claude showing what it would send (a choice's option);
    /// nothing is sent before Enter. Applying something opens an apply session.
    AskConsent(Box<Ask>),
    /// Grant the files Claude asked for, then tell it (the next turn).
    ChatGrant,
    /// Apply the selected Maintenance row with Claude (an apply session).
    ApplyAsk,
    /// Just ask (the first), with what applying it would be (`a` in the chat).
    AskWith(Box<Ask>, Box<Ask>),
    /// Take a task off `tasks.toml`.
    TaskRemove(String),
    /// A task done by hand: logged (tagged `task:<id>`), then the note box.
    TaskDone(String),
    /// Ask how often a task recurs (`e`): written to this target's tasks.toml.
    TaskEvery(String),
    /// A key, as if pressed.
    Key(KeyEvent),
    /// The help box (`?`).
    Help,
    /// Ask for a line in the key bar (with what's there to start with).
    Prompt(Prompt, String),
    /// Into the maintenance log now.
    LogEvent(Box<LogEntry>),
    /// Close the Plan view.
    PlanClose,
    /// The security audit (the window's, across every target): its report, or, with none
    /// yet, run it (`S`, `:audit security`).
    SecShow,
    /// Run it now (its task's Enter).
    SecRun,
    /// Enter on one of its rows (the item's id): a session that fixes it, or the pick for
    /// what only the user knows.
    SecItem(String),
    /// The answer to one of its questions (None: not known; the item's id then).
    SecAnswer(String, Option<bool>),
    /// A target that never had the window starts now (its id): this one's screen shows
    /// what it knows.
    Wake(String),
    /// From a target: a line of its own in the open chat.
    ChatNote(String),
    /// From a target: what the apply session fixed was audited again (true: it's gone).
    Reaudited(bool),
    /// From a target: its audit ended (a series may be waiting for it).
    AuditEnded(bool),
    /// From a target: what a review at start is told about has been read.
    Loaded,
    /// From a target: the host is back after a reboot (what to say).
    Rebooted(String),
    /// From a target: a line for the pane, if one is open.
    PaneLine(String),
    /// From a target: a line for the workflow run's log.
    RunNote(String, LogKind),
    /// From a target: another turn for whatever Claude is writing in the background.
    WriterFollow(String),
    /// From a target: a turn in the open chat (said if it was closed meanwhile).
    ChatTurn(String),
}

impl Effect {
    /// A target's own effect, wrapped for the trip through the app.
    pub fn own(x: impl Any) -> Self {
        Effect::Own(Own(Rc::new(x)))
    }
}

/// Where the answer to read requests goes back to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReadsFor {
    Chat,
    /// What Claude writes in the background (a review).
    Plan,
}

/// A workflow's `[vars]` being asked for, one at a time, before it starts.
#[derive(Clone, Debug)]
pub struct VarInput {
    pub workflow: String,
    /// (name, prompt, default), in the order asked.
    pub asks: Vec<(String, String, Option<String>)>,
    pub values: BTreeMap<String, String>,
    /// Why the last answer wasn't taken.
    pub note: Option<String>,
}

impl VarInput {
    pub fn current(&self) -> Option<&(String, String, Option<String>)> {
        self.asks.get(self.values.len())
    }
}

/// What the one input line in the key bar asks for.
#[derive(Clone, Debug)]
pub enum Prompt {
    /// A workflow's values, before it starts.
    WfVar(VarInput),
    /// A note for the entry a run, a plan or a task just wrote (optional).
    LogNote(Box<LogEntry>),
    /// A note added to an entry from Records.
    LogAddNote(Box<LogEntry>),
    /// A task's cadence (its id): `30d`, `off`.
    TaskEvery(String),
    /// A task just logged as done (its entry, its title): a note for the entry (optional).
    TaskNote(Box<LogEntry>, String),
    /// One of a target's own: it gets the answer (`Target::on_prompt`).
    Own(OwnPrompt),
}

/// A prompt only one kind of target asks.
#[derive(Clone, Debug)]
pub struct OwnPrompt {
    pub label: String,
    pub enter: &'static str,
    /// The workflow whose values it asks for, if that's what it is.
    pub workflow: Option<String>,
    /// A workflow's value, and it and every one still to come has a default: auto mode
    /// takes them without asking.
    pub defaults: bool,
    pub own: Own,
}

impl PromptLine for Prompt {
    fn label(&self) -> String {
        match self {
            Prompt::WfVar(v) => match v.current() {
                Some((name, prompt, _)) => format!(
                    "{} {}/{} · {prompt} ({name}): ",
                    v.workflow,
                    v.values.len() + 1,
                    v.asks.len()
                ),
                None => format!("{}: ", v.workflow),
            },
            Prompt::LogNote(e) | Prompt::LogAddNote(e) => format!(
                "{} {} · for the maintenance log, what to know next time (optional): ",
                e.head.item.as_deref().unwrap_or(&e.head.workflow),
                e.head.result
            ),
            Prompt::TaskEvery(id) => format!("{id} · every (e.g. 30d, 90d, off): "),
            Prompt::TaskNote(_, title) => {
                format!("{title}: done, logged · how it went, for the log (optional): ")
            }
            Prompt::Own(o) => o.label.clone(),
        }
    }

    fn enter_word(&self) -> &'static str {
        match self {
            Prompt::WfVar(_) => "next",
            Prompt::Own(o) => o.enter,
            _ => "save",
        }
    }

    fn note(&self) -> Option<&str> {
        match self {
            Prompt::WfVar(v) => v.note.as_deref(),
            _ => None,
        }
    }
}

/// The maintenance item a workflow run changes: logged with the run when it ends.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ItemChange {
    pub item: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Clone, Debug)]
pub enum WfCmd {
    /// Start it; its vars are asked for first, unless given.
    Begin(String),
    /// Start it from a maintenance item: its vars default to the item's values, and the run
    /// is logged as a change to the item when it ends.
    BeginPrefilled(String, BTreeMap<String, String>, Option<ItemChange>),
    BeginWith(String, BTreeMap<String, String>),
    /// The run's screen is open: auto steps may run, and the next one does.
    Arm,
    /// One of a target's own, on the run (`Host::run_cmd`).
    Own(Own),
    Go,
    Skip(bool),
    Done,
    Retry,
    Abandon,
    Close,
}

/// A numbered choice between actions.
pub type Choice = modal::Choice<Effect>;

pub type Modal = modal::Modal<Effect>;

#[derive(Clone, Debug)]
pub struct RunSpec {
    pub title: String,
    pub cmd: Cmd,
    /// What follows its exit (a target's re-reads, its wait for a reboot).
    pub then: Vec<Effect>,
    /// It reboots the host: logged as one.
    pub reboot: bool,
    /// Run after `cmd`, in order, while each one succeeds.
    pub queue: Vec<Cmd>,
    /// When the last one exits, the target hears how (`Target::pane_ended`).
    pub end: Option<Own>,
    /// It needs root: this command line (with sudo in it) is run in place of `cmd`, with the
    /// target's password when sudo wants one (asked first, once, if it isn't held).
    pub root: Option<String>,
}

/// Something read as root for the target.
#[derive(Clone, Debug)]
pub struct RootRead {
    /// What the password is for, if it has to be asked: "to read what needs root".
    pub what: String,
    pub line: String,
    /// Whose it is: it gets the output.
    pub own: Own,
    /// What follows when the password isn't given (Esc).
    pub skipped: Vec<Effect>,
}

/// A command that gets the terminal.
#[derive(Clone, Debug)]
pub struct Suspend {
    pub cmd: Cmd,
    /// Printed above it.
    pub banner: String,
    /// Done as the terminal is handed over (what the command changes is read again).
    pub then: Vec<Effect>,
    /// Whose it is: the target hears how it ended (`Target::after_suspend`). None: the app
    /// says "done" or the exit code.
    pub own: Option<Own>,
}

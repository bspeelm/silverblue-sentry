//! One target and everything that belongs to it: its records, the screen in view, the
//! workflow run, the apply session, the series, the chat, what Claude writes in the
//! background, Records, its boxes. The flows here are written once for every kind of target:
//! they run on the slot with the window (`Win`) beside it, and ask the target only for what
//! this kind of host alone can say.
//!
//! `core` is events, keys, the input line and the terminal handed over (an editor, a
//! shell); `root` the sudo password and everything that runs with it; `effects` what an
//! effect does; `session` the apply session and the chat; `wf` the workflow run; `series`
//! the ticked rows; `review` the writer, reviews and tasks; `records` Records and plans;
//! `draw` the frame.

pub mod auto;
mod core;
mod draw;
mod effects;
mod records;
mod review;
mod root;
mod series;
mod session;
mod wf;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::crossterm::event::KeyEvent;
use ratatui::text::Line;

use crate::app::{Win, kill};
use crate::effect::{
    Choice, Effect, ItemChange, Modal, Own, Prompt, ReadsFor, RunSpec, Suspend, VarInput, WfCmd,
};
use crate::run::{Exec, Live, LogKind, WfRun};
use crate::shared::Shared;
use crate::target::{Mail, ProfileFor, SeriesStep, Settle, Target, Why};
use sentry_core::claude::{self, Ask};
use sentry_core::exec::{ExecError, StreamMsg};
use sentry_core::maint::plan::{PlanDoc, PlanStatus};
use sentry_core::maint::tasks::Task;
use sentry_core::tui::ScreenId;
use sentry_core::tui::chat::{self as chatmod, Chat};
use sentry_core::tui::docview::Writer;
use sentry_core::tui::frame::{self, Layer};
use sentry_core::tui::input::{Input, Typed};
use sentry_core::tui::keys::Action;
use sentry_core::tui::modal;
use sentry_core::tui::theme::Theme;
use sentry_core::tui::widgets;
use sentry_core::workflows::runner::Next;

/// What the target may look at while it answers (see [`crate::target::Cx`]). A macro, so the
/// borrows stay on the fields it reads; `norun` leaves the run out (it's being changed).
macro_rules! cx {
    ($s:expr, $w:expr) => {
        cx!($s, $w, $s.run.as_deref())
    };
    ($s:expr, $w:expr, norun) => {
        cx!($s, $w, None)
    };
    ($s:expr, $w:expr, $run:expr) => {
        crate::target::Cx {
            theme: &$w.theme,
            now: $w.now(),
            screen: $s.screen,
            filter: $s.filters.get(&$s.screen).map(String::as_str),
            everything: $s.everything,
            writer: $s.writer.as_ref(),
            run: $run,
            last_change: $s.last_change_at,
            offline: $w.offline,
            at: $w.at,
            modal: $s.modal.is_some(),
            pane: $s.pane.as_ref().map(|p| p.done.is_none()),
            chat_running: $s.chat.as_ref().is_some_and(|c| c.running()),
            root: $s.secret_ok,
            auto: $s.auto,
            focused: $w.focused,
            target: &$s.title,
            finding: $s.apply.as_ref().and_then(|a| a.chat.ask.finding()),
        }
    };
}
pub(crate) use cx;

/// Streamed output of an action, or a log being read.
pub(crate) struct Pane {
    id: u64,
    title: String,
    pub(crate) cmd: String,
    pub(crate) lines: VecDeque<String>,
    pid: Option<u32>,
    /// Exit code once finished (`None` = running).
    pub(crate) done: Option<i32>,
    /// How long it took.
    took: Option<Duration>,
    started: Instant,
    scroll: usize,
    /// What follows its exit.
    then: Vec<Effect>,
    /// Commands still to run after this one, while each succeeds.
    queue: VecDeque<sentry_core::exec::Cmd>,
    /// The target hears how the last one ended.
    end: Option<Own>,
}

impl Pane {
    /// A pane with nothing running in it yet.
    fn new(id: u64, title: String, cmd: String) -> Self {
        Self {
            id,
            title,
            cmd,
            lines: VecDeque::new(),
            pid: None,
            done: None,
            took: None,
            started: Instant::now(),
            scroll: 0,
            then: Vec::new(),
            queue: VecDeque::new(),
            end: None,
        }
    }
}

pub struct Slot {
    pub target: Box<dyn Target>,
    /// Its records.
    pub shared: Shared,
    pub(crate) mail: Mail,
    /// From the target's `Ident`, which never changes: the key of its records, what it's
    /// called, and the program's name.
    scope: String,
    title: String,
    app: &'static str,
    /// The screen in view.
    pub screen: ScreenId,
    /// Each screen's `/` filter.
    filters: HashMap<ScreenId, String>,
    /// Maintenance lists what can wait too (`o`).
    everything: bool,
    pub(crate) modal: Option<Modal>,
    /// What answering no (n, Esc) to a box does, for the box with that title (usually none).
    modal_no: Option<(String, Vec<Effect>)>,
    choice: Option<Choice>,
    pub(crate) pane: Option<Pane>,
    /// A command waiting for the terminal.
    suspend: Option<Suspend>,
    /// Whose the command that has the terminal is (the target hears how it ended).
    suspend_own: Option<Own>,
    /// It's an editor: what the file holds is read again afterwards.
    suspend_edit: bool,
    /// A shell step's shell has the terminal.
    suspend_shell: Option<usize>,
    /// Where this program's flows go their own way (the target's, fixed).
    pub(crate) ways: crate::target::Ways,
    /// The ticked rows being done one after another.
    series: Option<sentry_core::maint::series::Series>,
    /// The maintenance change the running workflow makes (logged when it ends).
    wf_change: Option<ItemChange>,
    /// The run already written to the maintenance log.
    wf_logged: Option<PathBuf>,
    /// The run that just ended well, until its tasks review is started.
    review_run: Option<sentry_core::maint::log::LogEntry>,
    /// The review at start is still to begin (it waits for the first data).
    start_check: bool,
    /// `[review]` in config.toml: the reviews started without being asked.
    pub auto_review: sentry_core::config::Review,
    /// When the last maintenance run ended.
    pub(crate) last_change_at: Option<jiff::Timestamp>,
    /// Tests: the last entry written with a note.
    pub last_log: Option<sentry_core::maint::log::LogEntry>,
    /// Claude writing a review, in the background.
    pub(crate) writer: Option<Writer>,
    /// The Plan view: the item shown, and lines scrolled from the top.
    plan_view: Option<(String, usize)>,
    /// The Review window (`R` on Maintenance).
    pub(crate) review_view: Option<sentry_core::tui::reviewview::ReviewView>,
    /// Records (`v`, `:log`): tasks, log, plans, reviews, what's put off.
    pub rec_view: Option<sentry_core::tui::records::Records>,
    /// The workflow run in progress on this target.
    pub run: Option<Box<dyn WfRun>>,
    pub(crate) chat: Option<Chat>,
    /// Applying something with Claude: the one session, start to finish.
    pub(crate) apply: Option<sentry_core::apply::session::Session>,
    /// sudo's check for the session running (stream id; true: the password's check).
    pub(crate) apply_aux: Option<(u64, bool)>,
    /// The target's sudo password, once sudo accepted it: held while the window is open,
    /// for everything on this target that needs root (`slot/root.rs`). Wiped when dropped.
    pub(crate) secret: sentry_core::apply::sudo::Secret,
    pub(crate) secret_ok: bool,
    /// The password being asked for in the key bar.
    pub(crate) unlock: Option<root::Unlock>,
    /// What's being read as root for the target (by the id its output comes back under).
    reads: HashMap<u64, crate::effect::Own>,
    /// Tests (nothing is sent): what the last turn of a session would have sent Claude.
    pub last_prompt: Option<String>,
    /// Auto mode (`slot/auto.rs`): routine questions on this target are answered without a
    /// key. Off at start, never saved.
    pub auto: bool,
    /// `auto_step` is at work (what it starts comes back to it: once round more, `again`).
    auto_busy: bool,
    auto_again: bool,
    /// The run's step auto has dealt with as it stands (the run, the step, its dry run,
    /// when it last started): left to the user, or tried and not started.
    auto_held: Option<(PathBuf, usize, bool, Option<jiff::Timestamp>)>,
    /// The run about to begin got its values from auto (noted in its state once it exists).
    auto_took_values: bool,
    /// This slot's keymap and input line while another slot's flow runs or is in view; in
    /// their place while this one's does, whatever the window had (`Slot::park`).
    pub(crate) keys: sentry_core::tui::keys::Keymap,
    pub(crate) line: Input<Prompt>,
    /// Not started yet: it never had the window (`App::start` only picked up its run).
    asleep: bool,
    /// What it waits for out of view, once said (`App::flag`).
    pub(crate) flagged: Option<&'static str>,
    /// The run's reboot, asked for while another target was at work: how, the boot id it
    /// had, and who it waits for. It goes when they settle (`reboot_when_settled`).
    reboot_held: Option<(crate::run::How, String, String)>,
}

/// What a slot is doing, for its entry in the target strip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Needs {
    Nothing,
    /// A run, a session, a series or Claude is at work.
    Working,
    /// It waits for the user: what for.
    You(&'static str),
}

impl Slot {
    pub fn new(target: Box<dyn Target>, mail: Mail) -> Self {
        let id = target.ident();
        let (scope, title, app) = (id.scope.clone(), id.title.clone(), id.app);
        let ways = id.ways;
        let shared = Shared {
            wf_dir: id.wf_dir.clone(),
            ..Shared::default()
        };
        Self {
            target,
            shared,
            mail,
            scope,
            title,
            app,
            screen: ScreenId::Dash,
            filters: HashMap::new(),
            everything: false,
            modal: None,
            modal_no: None,
            choice: None,
            pane: None,
            suspend: None,
            suspend_own: None,
            suspend_edit: false,
            suspend_shell: None,
            ways,
            series: None,
            wf_change: None,
            wf_logged: None,
            review_run: None,
            start_check: false,
            auto_review: sentry_core::config::Review::default(),
            last_change_at: None,
            last_log: None,
            writer: None,
            plan_view: None,
            review_view: None,
            rec_view: None,
            run: None,
            chat: None,
            apply: None,
            apply_aux: None,
            secret: Default::default(),
            secret_ok: false,
            unlock: None,
            reads: HashMap::new(),
            last_prompt: None,
            auto: false,
            auto_busy: false,
            auto_again: false,
            auto_held: None,
            auto_took_values: false,
            keys: Default::default(),
            line: Input::None,
            asleep: false,
            flagged: None,
            reboot_held: None,
        }
    }

    /// What the target is called.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Swap this slot's keymap and input line with the window's: the window's are the slot's
    /// own while its flow runs or it is in view, and are kept here meanwhile.
    pub(crate) fn park(&mut self, w: &mut Win) {
        std::mem::swap(&mut self.keys, &mut w.keys);
        std::mem::swap(&mut self.line, &mut w.input);
    }

    /// The slot is in view (again): the first time it starts; after that its screen is
    /// fetched as on entering it.
    pub(crate) fn shown(&mut self, w: &mut Win, now: Instant) {
        if std::mem::take(&mut self.asleep) {
            self.start(w, now);
        } else {
            self.enter(w, self.screen, now);
        }
    }

    /// At start, for a target not in view: nothing of it is read or fetched until it is,
    /// except a run left in progress, which is picked up (it waits to be opened, as ever).
    pub(crate) fn pickup(&mut self, w: &mut Win) {
        self.asleep = true;
        if !w.offline {
            self.run = self.target.resume_run();
        }
    }

    /// Whether a character typed now is text (a message, a prompt's line, the password).
    pub(crate) fn takes_text(&self, w: &Win) -> bool {
        matches!(
            frame::layer(&self.open(w)),
            Layer::Unlock | Layer::Apply | Layer::Chat | Layer::Input
        )
    }

    /// Where the slot stands, for the strip: waiting for the user (what for), at work, or
    /// neither. `line`: its input line, wherever that is now.
    pub fn needs(&self, line: &Input<Prompt>) -> Needs {
        use sentry_core::tui::stepview::State;
        if self.unlock.as_ref().is_some_and(|u| u.checking.is_none()) {
            return Needs::You("the sudo password");
        }
        if self.modal.as_ref().is_some_and(|m| m.yes.is_some()) || self.choice.is_some() {
            return Needs::You("a question to answer");
        }
        if self.suspend.is_some() {
            return Needs::You("a command for the terminal");
        }
        match line {
            Input::Prompt(Prompt::WfVar(_), _) => return Needs::You("a workflow's values"),
            Input::Prompt(Prompt::Own(o), _) if o.workflow.is_some() => {
                return Needs::You("a workflow's values");
            }
            Input::Prompt(Prompt::LogNote(_), _) => {
                return Needs::You("a note for the log (the run ended)");
            }
            Input::Prompt(..) => return Needs::You("a line to type"),
            _ => {}
        }
        // The run first: a session that waits for its workflow stands where the run does.
        let mut working = false;
        // (A reboot that waits for the other targets was already asked for.)
        if let Some(r) = self
            .run
            .as_ref()
            .filter(|r| !r.done() && self.reboot_held.is_none())
        {
            if r.live().is_some() {
                working = true;
            } else {
                match *r.next() {
                    Next::Run(_) if r.armed() => working = true,
                    Next::Run(_) => return Needs::You("a run to carry on"),
                    Next::Confirm(_) => return Needs::You("a step to confirm"),
                    Next::Reboot {
                        requested: true, ..
                    } => working = true,
                    Next::Reboot { .. } => return Needs::You("a reboot to start"),
                    Next::Shell(_) => return Needs::You("a shell step"),
                    Next::Manual { failed: false, .. } => {
                        return Needs::You("a step to do by hand");
                    }
                    Next::Manual { .. } | Next::Stopped(_) => return Needs::You("a failed step"),
                    Next::Done => {}
                }
            }
        }
        if let Some(s) = self.apply.as_ref() {
            match sentry_core::tui::applyview::state(s) {
                State::You(_) if working && s.waiting_workflow().is_some() => {}
                State::You(_) => {
                    return Needs::You(match s.enter_word() {
                        Some("apply the plan") => "a plan to approve",
                        Some("allow it") => "a request to allow",
                        Some("start") => "a session to start",
                        Some("go on with the next") => "the next row to go on to",
                        Some("open the workflow") => "a workflow to start",
                        _ => "a session to look at",
                    });
                }
                State::Running | State::Working(_) => working = true,
                State::Done | State::Failed | State::Stopped | State::Idle => {}
            }
        }
        working = working
            || self.series.is_some()
            || self.writer.as_ref().is_some_and(|w| w.running())
            || self.chat.as_ref().is_some_and(|c| c.running())
            || self.pane.as_ref().is_some_and(|p| p.done.is_none())
            || self.unlock.is_some()
            || self.reboot_held.is_some()
            || !self.reads.is_empty();
        if working {
            Needs::Working
        } else {
            Needs::Nothing
        }
    }

    /// What quitting now would cut short here, a line each.
    pub(crate) fn going(&self) -> Vec<String> {
        let mut v = Vec::new();
        if let Some(r) = self.run.as_ref().filter(|r| !r.done()) {
            v.push(format!(
                "{} is in progress: its state is saved, and it carries on next time",
                r.wf().name
            ));
        }
        if let Some(sr) = &self.series {
            v.push(format!("{}: what's left stays to do", sr.line()));
        }
        if let Some(s) = self.apply.as_ref().filter(|s| s.busy()) {
            v.push(format!(
                "{}: stopped where it is",
                sentry_core::tui::applyview::banner(s)
            ));
        }
        if self.chat.as_ref().is_some_and(|c| c.running())
            || self.writer.as_ref().is_some_and(|w| w.running())
        {
            v.push("Claude is answering: stopped".into());
        }
        if let Some(p) = self.pane.as_ref().filter(|p| p.done.is_none()) {
            v.push(format!("{} is running", p.title));
        }
        v
    }

    /// sudo's check for the session is running (tests).
    #[cfg(any(test, feature = "testing"))]
    pub fn apply_aux_for_test(&self) -> bool {
        self.apply_aux.is_some()
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn asleep_for_test(&self) -> bool {
        self.asleep
    }

    /// This target's reboot waits for the other targets' work to settle.
    pub(crate) fn reboot_waits(&self) -> bool {
        self.reboot_held.is_some()
    }

    /// The id the next stream would get (tests: the last one started is this minus one).
    #[cfg(any(test, feature = "testing"))]
    pub fn mail_next_for_test(&self) -> u64 {
        self.mail.next()
    }

    /// Have the target read something again; what it says to that is done.
    pub(crate) fn refresh(&mut self, w: &mut Win, why: Why) {
        let e = self.target.refresh(why, &cx!(self, w));
        self.apply(w, e, w.at);
    }

    /// The lists changed, a key was handled: the target's cursors and selections follow.
    pub(crate) fn settle(&mut self, w: &mut Win, why: Settle) {
        self.target.settle(why, &self.shared, &cx!(self, w));
    }

    /// A run or a series is over: what the target offers then (reading the host again…).
    pub(crate) fn settled(&mut self, w: &mut Win) {
        let e = self.target.settled(&cx!(self, w));
        self.apply(w, e, w.at);
    }

    /// Every task that applies: `tasks.toml` over what the target's config implies.
    pub(crate) fn all_tasks(&self) -> Vec<Task> {
        sentry_core::maint::tasks::effective(
            &self.shared.tasks,
            self.target.derived_tasks(&self.shared),
        )
    }

    /// Don't leave a streamed command running on the host, nor the password in memory.
    pub(crate) fn shutdown(&mut self) {
        self.forget();
        self.unlock = None;
        if self.ways.exit_kills_run {
            if let Some(pid) = self.pane.as_ref().and_then(|p| p.pid) {
                let _ = kill(pid);
            }
            if let Some(pid) = self.run.as_ref().and_then(|s| s.live()).and_then(|l| l.pid) {
                let _ = kill(pid);
            }
        }
        if let Some((_, pid)) = self.chat.as_ref().and_then(|c| c.live) {
            let _ = kill(pid);
        }
        if self.ways.exit_kills_session
            && let Some(s) = self.apply.as_ref()
        {
            for pid in [s.chat.live.map(|l| l.1), s.job.map(|j| j.1)]
                .into_iter()
                .flatten()
            {
                let _ = kill(pid);
            }
        }
    }

    /// Which of Records, the plan and the review is in front, when more than one is open.
    pub(crate) fn doc_front(&self) -> Option<Doc> {
        let order = if self.ways.review_over_plan {
            [Doc::Review, Doc::Records, Doc::Plan]
        } else {
            [Doc::Records, Doc::Plan, Doc::Review]
        };
        order.into_iter().find(|d| match d {
            Doc::Review => self.review_view.is_some(),
            Doc::Records => self.rec_view.is_some(),
            Doc::Plan => self.plan_view.is_some(),
        })
    }
}

/// What can be open over the screen.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Doc {
    Records,
    Plan,
    Review,
}

/// `A` where Claude can help apply something: apply it with Claude, or just ask.
fn claude_choice(t: &Theme, app: &str, apply: Ask, ask: Ask) -> Choice {
    frame::claude_choice(
        t,
        app,
        vec![Effect::AskConsent(Box::new(apply.clone()))],
        vec![Effect::AskWith(Box::new(ask), Box::new(apply))],
    )
}

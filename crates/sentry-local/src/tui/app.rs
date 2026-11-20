//! What this machine's screens ask for: their effects, prompts and workflow keys. The app
//! itself (the frame, sessions, series, reviews, records, the workflow run) is `sentry_app`'s,
//! shared with every other target; this machine is its target ([`super::target`]), which
//! hands on what the app does for every host and carries out the rest.

use std::collections::BTreeMap;

use ratatui::text::Line;

use super::ScreenId;
use super::data::Fetch;
use super::theme::Theme;
use crate::exec::Cmd;

/// Something a screen wants done. Screens never touch threads or the terminal themselves.
#[derive(Clone)]
pub enum Effect {
    Fetch(Fetch),
    Toast(String),
    Confirm(Modal),
    Run(RunSpec),
    /// The same, for a command line that uses sudo: it runs in place of the spec's command,
    /// with the password when sudo wants one (asked once, in the key bar).
    RunRoot(RunSpec, String),
    /// Start a GUI program / new terminal window, detached.
    Detach(Cmd, String),
    /// Run in this terminal with the TUI suspended.
    Suspend(Cmd),
    Kill(u32, String),
    /// Append to `baseline.toml` (listener key or finding id/pattern).
    Baseline(BaselineEdit),
    /// Run in this terminal with the TUI suspended, then apply the effects (e.g. re-audit).
    Interactive(Cmd, Vec<Effect>),
    /// Pick one of several actions with 1–9.
    Choose(Choice),
    /// Remove from `baseline.toml` whatever covers this (the `b` toggle).
    Unbaseline(BaselineEdit),
    /// Ask for a line of input in the key bar (initial text).
    Prompt(Prompt, String),
    Wf(WfCmd),
    /// Open a conversation with Claude showing what it would send (nothing sent until Enter),
    /// e.g. `f` on an audit finding; applying something opens an apply session.
    AskConsent(crate::claude::Ask),
    /// Back from continuing the chat in Claude Code.
    ChatBack,
    /// Switch to another tab.
    Goto(ScreenId),
    /// Open Upgrade and start this workflow (its own confirm/var prompts follow).
    StartWorkflow(String),
    /// The maintenance log (`v`, `:log`).
    LogOpen,
    /// Maintenance: list what can wait too, or only what's needed (`o`).
    Everything,
    /// Maintenance: do the ticked rows (key, title) one after another.
    SeriesStart(Vec<(String, String)>),
    /// Maintenance with the first recommendation whose key starts with this selected.
    MaintFind(String),
    /// Put a recommendation off for this many days (`z`).
    Snooze(String, i64),
    /// A saved plan (`plans/<workflow>.md`), in the Plan view.
    PlanOpen(String),
    /// The session for a workflow's plan: on the saved plan when one is ready (to approve).
    PlanApply(String),
    /// Start over (`P`): the saved plan is set aside, the session begins from its research.
    PlanAgain(String),
    /// `R`: the latest review, or what writing one means.
    ReviewOpen,
    TaskRemove(String),
    /// A task done by hand: logged now, then a note for it is asked.
    TaskDone(String),
    /// Into the maintenance log now (a reboot, before it happens).
    LogEvent(Box<crate::maint::log::LogEntry>),
    /// Open Cleanup with only this job's items selected.
    CleanupFocus(crate::jobs::JobId),
}

/// What this machine asks for in the key bar itself (the app asks for the rest).
#[derive(Clone, Debug, PartialEq)]
pub enum Prompt {
    /// A task's cadence (its id): `30d`, `off`.
    TaskEvery(String),
    /// One workflow var; `rest` are the vars still to ask, `vars` the values so far.
    WfVar {
        workflow: String,
        key: String,
        prompt: String,
        rest: Vec<(String, String, String)>,
        vars: BTreeMap<String, String>,
    },
}

impl Prompt {
    pub fn label(&self) -> String {
        match self {
            Prompt::TaskEvery(id) => format!("{id} · every (e.g. 30d, 90d, off): "),
            Prompt::WfVar { prompt, .. } => format!("{prompt}: "),
        }
    }
}

/// A numbered choice between actions (fix options).
pub type Choice = super::modal::Choice<Effect>;

/// Workflow actions from the Upgrade screen, executed against the app's run.
#[derive(Clone, Debug)]
pub enum WfCmd {
    /// The Upgrade screen is open: auto steps may run.
    Arm,
    Begin(String, BTreeMap<String, String>),
    Go,
    Skip,
    /// Skip a step that isn't optional (after a confirm).
    SkipAnyway,
    Retry,
    Done,
    SkipDry,
    Abandon,
    Rollback,
    OpenLog,
    Edit(std::path::PathBuf),
    Close,
    /// Log scroll: positive = up (older), `i32::MIN` = back to the end.
    Scroll(i32),
}

#[derive(Clone, Debug, PartialEq)]
pub enum BaselineEdit {
    Listener(String),
    /// Every address of a grouped listener finding.
    Listeners(Vec<String>),
    Finding(String),
}

impl BaselineEdit {
    pub fn value(&self) -> String {
        match self {
            BaselineEdit::Listener(k) => format!("listeners += {k:?}"),
            BaselineEdit::Listeners(v) => format!("listeners += {} addresses", v.len()),
            BaselineEdit::Finding(k) => format!("findings += {k:?}"),
        }
    }
}

#[derive(Clone)]
pub struct RunSpec {
    pub title: String,
    pub cmd: Cmd,
    /// Run after `cmd`, in order, while each one succeeds.
    pub queue: Vec<Cmd>,
    /// Collectors to refresh once the command exits.
    pub then: Vec<Fetch>,
    pub ok_toast: String,
    /// When it ends, a maintenance log entry: (kind, tags). Its result is the exit code.
    pub log: Option<(String, Vec<String>)>,
}

pub type Modal = super::modal::Modal<Effect>;

pub fn info_modal(t: &Theme, title: &str, lines: Vec<Line<'static>>) -> Modal {
    Modal {
        title: title.into(),
        color: t.cyan,
        lines,
        yes: None,
    }
}

/// The app with this machine in it, as the tests drive it: nothing is fetched for a
/// conversation, written or sent. What the tests ask of it beyond `sentry_app::App`'s own
/// test support is here.
#[cfg(test)]
pub struct App(pub sentry_app::App);

#[cfg(test)]
impl std::ops::Deref for App {
    type Target = sentry_app::App;
    fn deref(&self) -> &sentry_app::App {
        &self.0
    }
}

#[cfg(test)]
impl std::ops::DerefMut for App {
    fn deref_mut(&mut self) -> &mut sentry_app::App {
        &mut self.0
    }
}

#[cfg(test)]
impl App {
    /// The app as `sentry` runs it (live tests).
    pub fn new(tx: std::sync::mpsc::Sender<super::Event>) -> Self {
        Self(super::app(tx))
    }

    /// Construct without config/terminal side effects (snapshot tests).
    pub fn for_test(
        cfg: crate::config::Config,
        data: super::data::DataStore,
        screen: ScreenId,
    ) -> Self {
        let (tx, _rx) = std::sync::mpsc::channel();
        Self::for_test_on(tx, cfg, data, screen)
    }

    /// The same, with the events it sends going to `tx` (a test that runs commands).
    pub fn for_test_on(
        tx: std::sync::mpsc::Sender<super::Event>,
        cfg: crate::config::Config,
        mut data: super::data::DataStore,
        screen: ScreenId,
    ) -> Self {
        use super::target::LocalTarget;
        let mut records = sentry_app::shared::Shared::default();
        data.records_into(&mut records);
        let (keys, review) = (cfg.keys.clone(), cfg.review.clone());
        let mut a = sentry_app::App::new(tx, LocalTarget::ID, |mail| {
            Box::new(LocalTarget::with(cfg, data, mail))
        });
        a.set_keys_for_test(&keys);
        a.win.theme = Theme::truecolor();
        a.win.offline = true;
        let s = a.slot_mut();
        s.screen = screen;
        s.auto_review = review;
        s.shared.later = records.later;
        s.shared.plans = records.plans;
        s.shared.tasks = records.tasks;
        s.shared.log = records.log;
        // The seeded workflows, by name (nothing is read from disk).
        s.shared.workflows = crate::workflows::SEEDS
            .iter()
            .map(|(n, _)| n.to_string())
            .collect();
        Self(a)
    }

    fn local(&self) -> &super::target::LocalTarget {
        self.slot()
            .target
            .as_any()
            .downcast_ref()
            .expect("this machine")
    }

    pub fn set_chat(&mut self, c: super::chat::Chat) {
        self.open_chat(c);
    }

    pub fn apply_for_test(&mut self, e: Vec<Effect>) {
        let e = super::target::lifted(e);
        self.0.apply(e, std::time::Instant::now());
    }

    /// The session's run has ended; it's logged as the event loop would.
    pub fn run_logged_for_test(&mut self) {
        self.0.run_logged_for_test();
    }

    /// A task in tasks.toml (nothing is written).
    pub fn add_task_for_test(&mut self, t: crate::maint::tasks::Task) {
        self.slot_mut().shared.tasks.push(t);
    }

    /// The review sentry started by itself and is still writing: why, and its run.
    pub fn auto_review_for_test(&self) -> Option<(String, Option<String>)> {
        let w = self.writer_for_test().filter(|w| w.quiet && w.running())?;
        let h = &w.review.as_ref()?.head;
        Some((h.origin.clone(), h.run.clone()))
    }

    /// The review at start begins (nothing is sent).
    pub fn start_check_for_test(&mut self) {
        self.0.review_auto_for_test();
    }

    /// Claude answered whatever is being written.
    pub fn writer_answered_for_test(&mut self, answer: &str) {
        self.writer_answered(answer);
    }

    /// The tasks due now.
    pub fn tasks_due_for_test(&self) -> Vec<String> {
        let s = self.slot();
        crate::maint::tasks::recs(
            &self.local().all_tasks(&s.shared),
            &s.shared.log,
            None,
            jiff::Timestamp::now(),
        )
        .into_iter()
        .map(|r| r.id)
        .collect()
    }

    /// The apply session's running step ended, or the audit after its plan (nothing ran).
    pub fn apply_step_exit_for_test(&mut self, code: i32) {
        match self.local().reaudit {
            Some(id) => {
                let ev = super::Event::Stream(
                    LocalTarget::ID.to_string(),
                    id,
                    crate::exec::StreamMsg::Exit {
                        code,
                        elapsed: std::time::Duration::ZERO,
                    },
                );
                self.0.on_event(ev, std::time::Instant::now());
            }
            None => self.0.apply_exit_for_test(code),
        }
    }

    /// The maintenance log as loaded.
    pub fn log_for_test(&self) -> &[crate::maint::log::LogEntry] {
        &self.slot().shared.log
    }

    /// Claude wrote this plan for `wf` (nothing is sent or saved).
    pub fn plan_written_for_test(
        &mut self,
        wf: &str,
        vars: BTreeMap<String, String>,
        answer: &str,
    ) {
        let doc = crate::maint::plan::PlanDoc {
            head: crate::maint::plan::Head {
                item: wf.into(),
                workflow: wf.into(),
                vars,
                ..Default::default()
            },
            body: String::new(),
        };
        // A plan on disk from before plans were a session's (its document, no plan block).
        let mut doc = doc;
        doc.take_answer(answer);
        self.0.slot_mut().shared.plans.insert(wf.to_string(), doc);
    }

    /// Claude wrote this review (nothing is sent or saved).
    pub fn review_written_for_test(&mut self, answer: &str) {
        let mut doc = crate::maint::review::ReviewDoc::new(crate::maint::LOCAL);
        doc.head.created = "2026-10-27T12:00:00Z".parse().ok();
        self.0
            .start_writer_for_test(super::docview::Writer::review(doc));
        self.writer_answered(answer);
    }

    pub fn set_wf(&mut self, s: super::wf::Session) {
        self.slot_mut().run = Some(Box::new(s));
    }
}

#[cfg(test)]
use super::target::LocalTarget;

/// Render the whole UI into plain text (snapshot tests).
#[cfg(test)]
pub fn render_to_string(app: &mut App, w: u16, h: u16) -> String {
    sentry_app::app::render_to_string(&mut app.0, w, h)
}

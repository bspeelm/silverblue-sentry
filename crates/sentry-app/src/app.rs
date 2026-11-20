//! The window: what exists once however many targets are open. The slots (one per target),
//! which of them has the keys, the input line, the help and quit boxes, the toast, the keymap,
//! and the events coming in, each carrying the id of the target it belongs to.

use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::crossterm::event::KeyEvent;

use crate::effect::{Effect, Modal, Prompt};
use crate::slot::Slot;
use crate::target::{Mail, Target, TargetId};
use sentry_core::exec::{Cmd, ExecError, StreamMsg};
use sentry_core::tui::ScreenId;
use sentry_core::tui::frame;
use sentry_core::tui::input::Input;
use sentry_core::tui::keys::Keymap;
use sentry_core::tui::theme::Theme;

pub enum Event {
    Key(KeyEvent),
    Paste(String),
    Resize,
    Signal,
    /// Something a target's thread read (`Mail::send`): only that target knows what.
    Data(TargetId, Box<dyn std::any::Any + Send>),
    /// A line or the exit of a streamed command (`Mail::stream`).
    Stream(TargetId, u64, StreamMsg),
    /// Output fetched for the pane (logs).
    Text(TargetId, u64, Result<String, String>),
}

impl From<sentry_core::tui::Input> for Event {
    fn from(i: sentry_core::tui::Input) -> Self {
        use sentry_core::tui::Input as I;
        match i {
            I::Key(k) => Event::Key(k),
            I::Paste(t) => Event::Paste(t),
            I::Resize => Event::Resize,
            I::Signal => Event::Signal,
        }
    }
}

/// What belongs to the window, handed to a slot's flows beside the slot itself.
pub struct Win {
    pub theme: Theme,
    pub keys: Keymap,
    pub toast: Option<frame::Toast>,
    /// The line being typed in the key bar: a `/` filter, a `:` command, or a prompt.
    pub input: Input<Prompt>,
    /// A box of the window's own: help, quit.
    pub modal: Option<Modal>,
    pub quit: bool,
    pub dirty: bool,
    /// The moment of the event being handled: the one clock the flows schedule by.
    pub at: Instant,
    /// Fixed clock for snapshot tests.
    pub now_override: Option<jiff::Timestamp>,
    /// Tests: never start a fetch, write a record or send anything.
    pub offline: bool,
    /// Something wrong in `[keys]`, said once the TUI is up.
    pub(crate) keys_warning: Option<String>,
}

impl Win {
    pub fn toast(&mut self, s: &str) {
        self.toast = Some(frame::Toast::new(s));
        self.dirty = true;
    }

    pub fn now(&self) -> jiff::Timestamp {
        self.now_override.unwrap_or_else(jiff::Timestamp::now)
    }
}

pub struct App {
    pub slots: Vec<Slot>,
    /// The slot that has the keys and is drawn.
    pub focus: usize,
    pub win: Win,
}

impl App {
    /// The window with one target in it. `make` builds the target around the `Mail` its
    /// threads answer through.
    pub fn new(tx: Sender<Event>, id: &str, make: impl FnOnce(Mail) -> Box<dyn Target>) -> Self {
        let mail = Mail::new(tx, id, Arc::new(AtomicU64::new(0)));
        let target = make(mail.clone());
        // The same `[keys]` for every program (another program's screens in it are skipped).
        let (keys, warnings) = Keymap::new(
            target.ident().screens,
            &sentry_core::config::Config::load().0.keys,
        );
        Self {
            slots: vec![Slot::new(target, mail)],
            focus: 0,
            win: Win {
                theme: Theme::detect(),
                keys,
                toast: None,
                input: Input::None,
                modal: None,
                quit: false,
                dirty: true,
                at: Instant::now(),
                now_override: None,
                offline: false,
                keys_warning: warnings.into_iter().next(),
            },
        }
    }

    /// The slot in view.
    pub fn slot(&self) -> &Slot {
        &self.slots[self.focus]
    }

    pub fn slot_mut(&mut self) -> &mut Slot {
        &mut self.slots[self.focus]
    }

    /// The slot in view and the window, to run one of its flows.
    pub fn parts(&mut self) -> (&mut Slot, &mut Win) {
        (&mut self.slots[self.focus], &mut self.win)
    }

    fn of(&mut self, id: &TargetId) -> Option<(&mut Slot, &mut Win)> {
        let s = self.slots.iter_mut().find(|s| s.mail.id() == id)?;
        Some((s, &mut self.win))
    }

    /// Something to say once the TUI is up, ahead of a `[keys]` warning.
    pub fn warn_at_start(&mut self, s: String) {
        self.win.keys_warning = Some(s);
    }

    pub fn start(&mut self, now: Instant) {
        self.win.at = now;
        for s in &mut self.slots {
            s.start(&mut self.win, now);
        }
        if let Some(w) = self.win.keys_warning.take() {
            self.win.toast(&w);
        }
    }

    pub fn enter(&mut self, id: ScreenId, now: Instant) {
        self.win.at = now;
        let (s, w) = self.parts();
        s.enter(w, id, now);
    }

    pub fn apply(&mut self, effects: Vec<Effect>, now: Instant) {
        self.win.at = now;
        let (s, w) = self.parts();
        s.apply(w, effects, now);
    }

    pub fn tick(&mut self, now: Instant) {
        self.win.at = now;
        let (s, w) = self.parts();
        s.tick(w, now);
    }

    pub fn next_due(&self, now: Instant) -> Instant {
        let mut due = now + Duration::from_secs(60);
        if let Some(t) = self.slot().next_due(&self.win, now) {
            due = due.min(t);
        }
        if let Some(t) = &self.win.toast {
            due = due.min(t.until());
        }
        due.max(now)
    }

    pub fn on_event(&mut self, ev: Event, now: Instant) {
        self.win.at = now;
        match ev {
            Event::Key(k) => {
                let (s, w) = self.parts();
                s.on_key(w, k, now);
            }
            Event::Paste(text) => {
                let (s, w) = self.parts();
                s.on_paste(w, &text);
            }
            Event::Resize => self.win.dirty = true,
            Event::Signal => self.win.quit = true,
            // Whatever is in view, it lands in its own slot.
            Event::Data(id, data) => {
                if let Some((s, w)) = self.of(&id) {
                    s.on_data(w, data);
                }
            }
            Event::Stream(id, sid, m) => {
                if let Some((s, w)) = self.of(&id) {
                    s.on_run(w, sid, m);
                }
            }
            Event::Text(id, tid, res) => {
                if let Some((s, w)) = self.of(&id) {
                    s.on_text(w, tid, res);
                }
            }
        }
    }

    pub fn draw(&mut self, f: &mut Frame) {
        let (s, w) = self.parts();
        s.draw(w, f);
    }

    pub fn take_suspend(&mut self) -> Option<(Cmd, String)> {
        self.win.at = Instant::now();
        let (s, w) = self.parts();
        s.take_suspend(w)
    }

    pub fn after_suspend(&mut self, status: Result<ExitStatus, ExecError>) {
        self.win.at = Instant::now();
        let (s, w) = self.parts();
        s.after_suspend(w, status);
    }
}

impl sentry_core::tui::Ui for App {
    type Ev = Event;
    fn start(&mut self, now: Instant) {
        App::start(self, now);
    }
    fn dirty(&self) -> bool {
        self.win.dirty
    }
    fn draw(&mut self, f: &mut Frame) {
        App::draw(self, f);
        self.win.dirty = false;
    }
    fn take_suspend(&mut self) -> Option<(Cmd, String)> {
        App::take_suspend(self)
    }
    fn after_suspend(&mut self, status: Result<ExitStatus, ExecError>) {
        App::after_suspend(self, status);
    }
    fn quitting(&self) -> bool {
        self.win.quit
    }
    fn shutdown(&mut self) {
        for s in &mut self.slots {
            s.shutdown();
        }
    }
    fn next_due(&self, now: Instant) -> Instant {
        App::next_due(self, now)
    }
    fn on_event(&mut self, ev: Event, now: Instant) {
        App::on_event(self, ev, now);
    }
    fn tick(&mut self, now: Instant) {
        App::tick(self, now);
    }
}

pub(crate) fn kill(pid: u32) -> std::io::Result<()> {
    let pid = rustix::process::Pid::from_raw(pid as i32)
        .ok_or_else(|| std::io::Error::other("bad pid"))?;
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).map_err(std::io::Error::from)
}

/// Test support: what the targets' own tests drive the flows with. Nothing is sent or run.
#[cfg(any(test, feature = "testing"))]
impl App {
    pub fn set_wf_entries(&mut self, e: Vec<sentry_core::workflows::Entry>) {
        let (s, w) = self.parts();
        s.shared.workflows = e.iter().map(|x| x.name.clone()).collect();
        s.shared.wf_list = e
            .iter()
            .cloned()
            .map(|entry| sentry_core::tui::wflist::WfInfo { entry, last: None })
            .collect();
        s.shared.wf_entries = e;
        s.settle(w, crate::target::Settle::Lists);
    }
    /// What the review window on its brief would send, or the brief of a conversation just
    /// opened.
    pub fn consent_text_any(&self) -> Option<String> {
        let s = self.slot();
        if s.review_view.as_ref().is_some_and(|v| v.brief) {
            return Some(s.review_prompt(&self.win));
        }
        self.consent_text()
    }
    /// What the conversation just opened would send (nothing sent yet).
    pub fn consent_text(&self) -> Option<String> {
        let s = self.slot();
        if let Some(s) = s
            .apply
            .as_ref()
            .filter(|s| s.phase == sentry_core::apply::session::Phase::Brief)
        {
            return Some(s.chat.ask.prompt());
        }
        s.chat
            .as_ref()
            .filter(|c| c.pending)
            .map(|c| c.ask.prompt())
    }
    /// The apply session.
    pub fn apply_session(&mut self) -> Option<&mut sentry_core::apply::session::Session> {
        self.slot_mut().apply.as_mut()
    }
    /// Claude's answer to the apply session's turn (nothing was sent).
    pub fn apply_answer_for_test(&mut self, text: &str) {
        let id = self
            .slot()
            .apply
            .as_ref()
            .and_then(|s| s.chat.live.map(|l| l.0))
            .expect("no turn running");
        let line = serde_json::json!({
            "type": "stream_event",
            "event": {"type": "content_block_delta", "delta": {"type": "text_delta", "text": text}}
        })
        .to_string();
        let tid = self.slot().mail.id().clone();
        self.on_event(
            Event::Stream(
                tid.clone(),
                id,
                StreamMsg::Line {
                    stderr: false,
                    text: line,
                },
            ),
            Instant::now(),
        );
        self.on_event(
            Event::Stream(
                tid,
                id,
                StreamMsg::Exit {
                    code: 0,
                    elapsed: std::time::Duration::ZERO,
                },
            ),
            Instant::now(),
        );
    }
    /// The apply session's running step (or sudo's check) ended (nothing ran).
    pub fn apply_exit_for_test(&mut self, code: i32) {
        let s = self.slot();
        let id = s
            .apply
            .as_ref()
            .and_then(|s| s.job.map(|j| j.0))
            .or(s.apply_aux.map(|a| a.0))
            .expect("nothing running");
        let tid = s.mail.id().clone();
        self.on_event(
            Event::Stream(
                tid,
                id,
                StreamMsg::Exit {
                    code,
                    elapsed: std::time::Duration::ZERO,
                },
            ),
            Instant::now(),
        );
    }
    /// The sudo password is being asked for in the key bar: (what for, characters typed,
    /// times refused).
    pub fn unlock_for_test(&self) -> Option<(String, usize, u8)> {
        let u = self.slot().unlock.as_ref()?;
        Some((u.what.clone(), u.typed.len(), u.tries))
    }
    /// sudo's check of the password typed in the key bar ended (nothing ran).
    pub fn unlock_exit_for_test(&mut self, code: i32) {
        let s = self.slot();
        let id = s
            .unlock
            .as_ref()
            .and_then(|u| u.checking)
            .expect("no password being checked");
        let tid = s.mail.id().clone();
        self.on_event(
            Event::Stream(
                tid,
                id,
                StreamMsg::Exit {
                    code,
                    elapsed: std::time::Duration::ZERO,
                },
            ),
            Instant::now(),
        );
    }
    /// The pane is closed, whatever it was running (nothing was).
    pub fn close_pane_for_test(&mut self) {
        self.slot_mut().pane = None;
    }
    /// Whether the target's sudo password is held.
    pub fn holds_password_for_test(&self) -> bool {
        self.slot().secret_ok
    }
    /// A command line as the app would run it as root now: its argv, shell-quoted (what
    /// goes on its stdin isn't part of it).
    pub fn root_cmd_for_test(&self, line: &str) -> String {
        self.slot().root_cmd(line, true).quoted_argv()
    }
    /// What's being read as root came back (nothing ran): the oldest read gets `out`.
    pub fn root_read_for_test(&mut self, out: Result<String, String>) {
        let s = self.slot();
        let id = *s.reads_for_test().first().expect("nothing being read");
        let tid = s.mail.id().clone();
        self.on_event(Event::Text(tid, id, out), Instant::now());
    }
    /// How many reads as root are under way.
    pub fn root_reads_for_test(&self) -> usize {
        self.slot().reads_for_test().len()
    }
    /// The review writer answered.
    pub fn writer_answered(&mut self, answer: &str) {
        let (s, w) = self.parts();
        if let Some(wr) = s.writer.as_mut() {
            wr.live = None;
            wr.answer = Some(answer.to_string());
        }
        s.writer_turn_ended(w);
    }
    /// Whether Claude is still writing a review.
    pub fn writing(&self) -> bool {
        self.slot().writer.as_ref().is_some_and(|w| w.running())
    }
    /// Open a conversation without asking Claude anything.
    pub fn open_chat(&mut self, c: sentry_core::tui::chat::Chat) {
        self.slot_mut().chat = Some(c);
    }
    /// The conversation, if one is open.
    pub fn chat_for_test(&self) -> Option<&sentry_core::tui::chat::Chat> {
        self.slot().chat.as_ref()
    }
    pub fn chat_mut(&mut self) -> Option<&mut sentry_core::tui::chat::Chat> {
        self.slot_mut().chat.as_mut()
    }
    /// `[keys]` as config.toml would give it; what's wrong in it.
    pub fn set_keys_for_test(
        &mut self,
        overrides: &std::collections::BTreeMap<String, String>,
    ) -> Vec<String> {
        let (keys, warnings) = Keymap::new(self.slot().target.ident().screens, overrides);
        self.win.keys = keys;
        warnings
    }
    /// The command the run pane shows.
    pub fn pane_cmd_for_test(&self) -> Option<String> {
        self.slot().pane.as_ref().map(|p| p.cmd.clone())
    }
    /// A task lands in `tasks.toml` (as an apply session's follow-up does).
    pub fn add_task_for_test(&mut self, task: sentry_core::maint::tasks::Task) {
        let (s, w) = self.parts();
        s.task_add(w, task);
    }
    /// The review as it stands.
    pub fn review_for_test(&self) -> Option<&sentry_core::maint::review::ReviewDoc> {
        self.slot().shared.review.as_ref()
    }
    /// The box in front, if it's one to confirm: what yes does.
    pub fn box_yes_for_test(&self) -> Option<&[Effect]> {
        Some(&self.slot().modal.as_ref()?.yes.as_ref()?.1)
    }
    /// The run that ended is logged, as the event loop would.
    pub fn run_logged_for_test(&mut self) {
        let (s, w) = self.parts();
        s.wf_log_change(w);
    }
    /// A workflow run ended with this log entry: the session waiting for it hears.
    pub fn run_ended_for_test(&mut self, e: &sentry_core::maint::log::LogEntry) {
        let (s, w) = self.parts();
        s.apply_run_ended(w, e);
    }
    /// What Claude is writing in the background, or last wrote.
    pub fn writer_for_test(&self) -> Option<&sentry_core::tui::docview::Writer> {
        self.slot().writer.as_ref()
    }
    /// The review the app starts by itself begins (nothing is sent).
    pub fn review_auto_for_test(&mut self) {
        let (s, w) = self.parts();
        s.review_auto(w, None);
    }
    /// Claude starts writing this (nothing is sent).
    pub fn start_writer_for_test(&mut self, wr: sentry_core::tui::docview::Writer) {
        let (s, w) = self.parts();
        s.start_writer(w, wr, String::new(), None);
    }
    /// The pane's lines and, once its command ended, its exit code.
    pub fn pane_for_test(&self) -> Option<(Vec<String>, Option<i32>)> {
        let p = self.slot().pane.as_ref()?;
        Some((p.lines.iter().cloned().collect(), p.done))
    }
    /// When the target last changed (a run, a task done).
    pub fn set_last_change_for_test(&mut self, at: jiff::Timestamp) {
        self.slot_mut().last_change_at = Some(at);
    }
}

/// Stop a process (tests).
#[cfg(any(test, feature = "testing"))]
pub fn kill_for_test(pid: u32) {
    let _ = kill(pid);
}

/// Render the whole UI into plain text (snapshot tests).
#[cfg(any(test, feature = "testing"))]
pub fn render_to_string(app: &mut App, w: u16, h: u16) -> String {
    frame::render_to_string(w, h, |f| app.draw(f))
}

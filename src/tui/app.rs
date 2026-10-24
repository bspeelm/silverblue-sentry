//! App state, key routing, effects, scheduling and chrome (top bar, tabs, key bar, overlays).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use super::data::{DataStore, Fetch};
use super::keys::{Action, Keymap};
use super::screens::{Screens, View};
use super::theme::Theme;
use super::wf::{Exec, Session};
use super::widgets::{self, chip};
use super::{Event, ScreenId};
use crate::config::Config;
use crate::exec::{Cmd, ExecError, StreamMsg};
use crate::fmt;

/// Something a screen wants done. Screens never touch threads or the terminal themselves.
#[derive(Clone)]
pub enum Effect {
    Fetch(Fetch),
    Toast(String),
    Confirm(Modal),
    Run(RunSpec),
    /// Start a GUI program / new terminal window, detached.
    Detach(Cmd, String),
    /// Run in this terminal with the TUI suspended.
    Suspend(Cmd),
    Kill(u32, String),
    /// Append to `baseline.toml` (listener key or finding id/pattern).
    Baseline(BaselineEdit),
    /// Remove from `baseline.toml` whatever covers this (the `b` toggle).
    Unbaseline(BaselineEdit),
    /// Ask for a line of input in the key bar (initial text).
    Prompt(Prompt, String),
    Wf(WfCmd),
    /// Send a turn to Claude: the first question, or a follow-up in the open chat.
    AskSend(AskTurn),
    /// Switch to another tab.
    Goto(ScreenId),
    /// Open Upgrade and start this workflow (its own confirm/var prompts follow).
    StartWorkflow(String),
    /// Open Cleanup with only this job's items selected.
    CleanupFocus(crate::jobs::JobId),
    Quit,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Prompt {
    Cadence(crate::jobs::JobId),
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
    fn label(&self) -> String {
        match self {
            Prompt::Cadence(j) => format!("cadence for {} (e.g. 30d, 7d, off): ", j.name()),
            Prompt::WfVar { prompt, .. } => format!("{prompt}: "),
        }
    }
}

#[derive(Clone, Debug)]
pub enum AskTurn {
    First(crate::claude::Ask),
    Follow(String),
}

/// Workflow actions from the Upgrade screen, executed against the app's session.
#[derive(Clone, Debug)]
pub enum WfCmd {
    /// The Upgrade screen is open: auto steps may run.
    Arm,
    Begin(String, BTreeMap<String, String>),
    Go,
    Skip,
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

/// Which session step a suspended terminal command belongs to.
enum SuspendFor {
    Step(usize),
    Shell(usize),
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
}

#[derive(Clone)]
pub struct Modal {
    pub title: String,
    pub color: Color,
    pub lines: Vec<Line<'static>>,
    /// Confirm label and what it does; `None` = informational (Enter/Esc close).
    pub yes: Option<(String, Vec<Effect>)>,
}

struct RunPane {
    id: u64,
    title: String,
    cmd: String,
    lines: VecDeque<(String, bool)>,
    started: Instant,
    done: Option<(i32, Duration)>,
    pid: Option<u32>,
    then: Vec<Fetch>,
    ok_toast: String,
    scroll: usize,
    queue: VecDeque<Cmd>,
}

const RUN_LINES: usize = 2000;

enum Input {
    None,
    Filter(String),
    Command(String),
    Prompt(Prompt, String),
}

struct Sched {
    sys: Instant,
    counts: Instant,
    gpu: Instant,
    slow: Instant,
    procs: Instant,
    net: Instant,
}

pub struct App {
    pub screen: ScreenId,
    pub quit: bool,
    pub dirty: bool,
    cfg: Arc<Config>,
    theme: Theme,
    keys: Keymap,
    data: DataStore,
    screens: Screens,
    modal: Option<Modal>,
    run: Option<RunPane>,
    run_seq: u64,
    toast: Option<(String, Instant)>,
    input: Input,
    filters: HashMap<ScreenId, String>,
    sched: Sched,
    tx: Sender<Event>,
    suspend: Option<Cmd>,
    last_minute: i64,
    wf: Option<Session>,
    suspend_for: Option<SuspendFor>,
    chat: Option<super::chat::Chat>,
}

const TOAST_FOR: Duration = Duration::from_millis(2600);

impl App {
    pub fn new(tx: Sender<Event>) -> Self {
        let (cfg, mut warnings) = Config::load();
        let (keys, kw) = Keymap::new(&cfg.keys);
        warnings.extend(kw);
        let now = Instant::now();
        let mut app = Self {
            screen: ScreenId::Dash,
            quit: false,
            dirty: true,
            cfg: Arc::new(cfg),
            theme: Theme::detect(),
            keys,
            data: DataStore::new(),
            screens: Screens::default(),
            modal: None,
            run: None,
            run_seq: 0,
            toast: None,
            input: Input::None,
            filters: HashMap::new(),
            sched: Sched {
                sys: now,
                counts: now,
                gpu: now,
                slow: now,
                procs: now,
                net: now,
            },
            tx,
            suspend: None,
            last_minute: 0,
            wf: Session::resume(),
            suspend_for: None,
            chat: None,
        };
        if let Some(w) = warnings.first() {
            app.toast(w.clone());
        }
        app
    }

    #[cfg(test)]
    pub fn set_chat(&mut self, c: super::chat::Chat) {
        self.chat = Some(c);
    }

    #[cfg(test)]
    pub fn set_wf(&mut self, s: Session) {
        self.wf = Some(s);
    }

    /// Construct without config/terminal side effects (snapshot tests).
    #[cfg(test)]
    pub fn for_test(cfg: Config, data: DataStore, screen: ScreenId) -> Self {
        let (tx, _rx) = std::sync::mpsc::channel();
        let (keys, _) = Keymap::new(&cfg.keys);
        let now = Instant::now();
        Self {
            screen,
            quit: false,
            dirty: true,
            cfg: Arc::new(cfg),
            theme: Theme::truecolor(),
            keys,
            data,
            screens: Screens::default(),
            modal: None,
            run: None,
            run_seq: 0,
            toast: None,
            input: Input::None,
            filters: HashMap::new(),
            sched: Sched {
                sys: now,
                counts: now,
                gpu: now,
                slow: now,
                procs: now,
                net: now,
            },
            tx,
            suspend: None,
            last_minute: 0,
            wf: None,
            suspend_for: None,
            chat: None,
        }
    }

    pub fn start(&mut self, now: Instant) {
        // State files only (cheap): the dashboard Status panel and tab badges need them.
        self.data.fetch(Fetch::Reports, &self.cfg, &self.tx);
        self.data.fetch(Fetch::Jobs, &self.cfg, &self.tx);
        self.enter(self.screen, now);
    }

    fn view(&self) -> View<'_> {
        View {
            d: &self.data,
            cfg: &self.cfg,
            t: &self.theme,
            filter: self
                .filters
                .get(&self.screen)
                .map(String::as_str)
                .filter(|s| !s.is_empty()),
            wf: self.wf.as_ref(),
        }
    }

    fn toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
        self.dirty = true;
    }

    // ---------------------------------------------------------------- scheduling

    fn enter(&mut self, id: ScreenId, now: Instant) {
        self.screen = id;
        self.dirty = true;
        match id {
            ScreenId::Dash => {
                // Second CPU sample shortly after the first so the bars aren't empty for 1 s.
                self.sched.sys = now;
                self.sched.counts = now;
                self.sched.gpu = now;
                self.sched.slow = now;
            }
            ScreenId::Proc => self.sched.procs = now,
            ScreenId::Net => self.sched.net = now,
            _ => {}
        }
        let effects = self.screens.on_enter(id, &self.view());
        self.apply(effects, now);
    }

    fn hz(v: f32) -> Duration {
        Duration::from_secs_f32(1.0 / v.clamp(0.1, 10.0))
    }

    /// When the loop should wake up next if no event arrives.
    pub fn next_due(&self, now: Instant) -> Instant {
        let mut due =
            now + Duration::from_secs(60 - (jiff::Timestamp::now().as_second() % 60) as u64);
        let mut at = |t: Instant| due = due.min(t);
        match self.screen {
            ScreenId::Dash => {
                at(self.sched.sys);
                at(self.sched.counts);
                at(self.sched.gpu);
                at(self.sched.slow);
            }
            ScreenId::Proc => at(self.sched.procs),
            ScreenId::Net => at(self.sched.net),
            _ => {}
        }
        if let Some((_, t)) = &self.toast {
            at(*t + TOAST_FOR);
        }
        if self.run.as_ref().is_some_and(|r| r.done.is_none()) {
            at(now + Duration::from_secs(1));
        }
        if self.wf.as_ref().is_some_and(|s| s.live.is_some())
            || self.chat.as_ref().is_some_and(|c| c.running())
        {
            at(now + Duration::from_millis(250));
        }
        due.max(now)
    }

    pub fn tick(&mut self, now: Instant) {
        let first_sample = self.data.sys.is_none();
        match self.screen {
            ScreenId::Dash => {
                if now >= self.sched.sys {
                    self.data.sample_system();
                    self.sched.sys = now
                        + if first_sample {
                            Duration::from_millis(300)
                        } else {
                            Self::hz(self.cfg.ui.dashboard_hz)
                        };
                    self.dirty = true;
                }
                if now >= self.sched.counts {
                    self.data.sample_counts();
                    self.sched.counts = now + Duration::from_secs(5);
                }
                if now >= self.sched.gpu {
                    self.data.fetch(Fetch::Gpu, &self.cfg, &self.tx);
                    self.sched.gpu = now + Duration::from_secs(5);
                }
                if now >= self.sched.slow {
                    for f in [Fetch::Disks, Fetch::Units, Fetch::Ostree] {
                        self.data.fetch(f, &self.cfg, &self.tx);
                    }
                    self.data.recorder = crate::recorder::live();
                    self.sched.slow = now + Duration::from_secs(60);
                }
            }
            ScreenId::Proc if now >= self.sched.procs => {
                let first = self.data.procs.is_empty();
                self.data.sample_procs();
                self.sched.procs = now
                    + if first {
                        Duration::from_millis(300)
                    } else {
                        Self::hz(self.cfg.ui.processes_hz)
                    };
                self.dirty = true;
            }
            ScreenId::Net if now >= self.sched.net => {
                self.data.fetch(Fetch::Net, &self.cfg, &self.tx);
                self.sched.net = now + Duration::from_secs(3);
            }
            _ => {}
        }
        if self
            .toast
            .as_ref()
            .is_some_and(|(_, t)| now >= *t + TOAST_FOR)
        {
            self.toast = None;
            self.dirty = true;
        }
        let minute = jiff::Timestamp::now().as_second() / 60;
        if minute != self.last_minute {
            self.last_minute = minute;
            self.dirty = true;
        }
        if self.run.as_ref().is_some_and(|r| r.done.is_none()) {
            self.dirty = true;
        }
        if self.chat.as_ref().is_some_and(|c| c.running()) {
            self.dirty = true;
        }
        if let Some(s) = self.wf.as_mut()
            && let Some(l) = s.live.as_mut()
        {
            self.dirty = true;
            if l.deadline.is_some_and(|d| now >= d) {
                l.deadline = None;
                if let Some(pid) = l.pid {
                    let _ = kill(pid);
                }
                s.push("✗ timeout: sent SIGTERM", super::wf::LogKind::Err);
            }
        }
    }

    // ---------------------------------------------------------------- events

    pub fn on_event(&mut self, ev: Event, now: Instant) {
        match ev {
            Event::Key(k) => self.on_key(k, now),
            Event::Resize => self.dirty = true,
            Event::Data(f, r) => {
                let r = *r;
                if let Err(e) = &r
                    && matches!(
                        f,
                        Fetch::OstreeCheck
                            | Fetch::FlatpakUpdates
                            | Fetch::ToolboxUpdates
                            | Fetch::Breakdown
                            | Fetch::Reports
                            | Fetch::Plan(_)
                            | Fetch::Cleanup
                    )
                {
                    self.toast(e.text());
                }
                self.data.apply(f, r);
                if let Fetch::Plan(job) = f
                    && let Some(p) = self.data.plan.take()
                    && self.modal.is_none()
                    && self.run.is_none()
                {
                    self.modal = Some(super::screens::jobs::plan_modal(&self.theme, job, &p));
                }
                self.dirty = true;
            }
            Event::Run(id, msg) => self.on_run_msg(id, msg),
            Event::Signal => self.quit = true,
        }
    }

    fn on_run_msg(&mut self, id: u64, msg: StreamMsg) {
        if let Some(c) = self.chat.as_mut()
            && c.live.is_some_and(|(cid, _)| cid == id)
        {
            match msg {
                StreamMsg::Line {
                    stderr: false,
                    text,
                } => {
                    for e in crate::claude::parse_line(&text) {
                        c.on_event(e);
                    }
                }
                StreamMsg::Line { stderr: true, text } => c.on_raw(text),
                StreamMsg::Exit { code, .. } => c.on_exit(code),
            }
            self.dirty = true;
            return;
        }
        if let Some(s) = self.wf.as_mut()
            && let Some(live) = s.live.as_ref().filter(|l| l.id == id)
        {
            let (idx, dry) = (live.idx, live.dry);
            match msg {
                StreamMsg::Line { stderr, text } => s.on_line(text, stderr),
                StreamMsg::Exit { code, .. } => {
                    s.on_exit(idx, dry, code, None);
                    self.wf_auto();
                    self.after_wf_change();
                }
            }
            self.dirty = true;
            return;
        }
        let Some(run) = self.run.as_mut().filter(|r| r.id == id) else {
            return;
        };
        match msg {
            StreamMsg::Line { stderr, text } => {
                if run.lines.len() == RUN_LINES {
                    run.lines.pop_front();
                }
                run.lines.push_back((text, stderr));
            }
            StreamMsg::Exit { code, elapsed } => {
                if code == 0
                    && let Some(next) = run.queue.pop_front()
                {
                    run.lines.push_back((String::new(), false));
                    run.lines
                        .push_back((format!("$ {}", next.display()), false));
                    let tx = self.tx.clone();
                    match next.stream(move |m| {
                        let _ = tx.send(Event::Run(id, m));
                    }) {
                        Ok(pid) => {
                            run.pid = Some(pid);
                            run.cmd = next.display();
                            self.dirty = true;
                            return;
                        }
                        Err(e) => {
                            run.lines.push_back((e.to_string(), true));
                            run.done = Some((127, elapsed));
                        }
                    }
                } else {
                    run.done = Some((code, elapsed));
                }
                let code = run.done.map_or(code, |d| d.0);
                run.pid = None;
                let then = std::mem::take(&mut run.then);
                let msg = if code == 0 {
                    run.ok_toast.clone()
                } else {
                    format!("{} failed (exit {code})", run.title)
                };
                for f in then {
                    self.data.fetch(f, &self.cfg, &self.tx);
                }
                self.toast(msg);
            }
        }
        self.dirty = true;
    }

    fn on_key(&mut self, k: KeyEvent, now: Instant) {
        self.dirty = true;
        if self.run.is_some() {
            self.run_key(k);
            return;
        }
        if let Some(m) = self.modal.take() {
            match k.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    if let Some((_, effects)) = m.yes {
                        self.apply(effects, now);
                    }
                }
                KeyCode::Char('n') | KeyCode::Esc | KeyCode::Char('q') => {}
                _ => self.modal = Some(m),
            }
            return;
        }
        if self.chat.is_some() {
            self.chat_key(k, now);
            return;
        }
        if !matches!(self.input, Input::None) {
            self.input_key(k, now);
            return;
        }
        let Some(action) = self.keys.resolve(&k) else {
            return;
        };
        match action {
            Action::Screen(id) => self.enter(id, now),
            Action::NextScreen | Action::PrevScreen => {
                let tabs = self.visible_tabs();
                let i = tabs.iter().position(|s| *s == self.screen).unwrap_or(0);
                let n = tabs.len();
                let j = if action == Action::NextScreen {
                    (i + 1) % n
                } else {
                    (i + n - 1) % n
                };
                self.enter(tabs[j], now);
            }
            Action::Help => self.show_help(),
            Action::Ask => self.ask(),
            Action::Interrupt
                if self.screen == ScreenId::Upgrade
                    && self.wf.as_ref().is_some_and(|s| s.live.is_some()) =>
            {
                if let Some(pid) = self.wf.as_ref().and_then(|s| s.live.as_ref()?.pid) {
                    let _ = kill(pid);
                    self.toast("sent SIGTERM to the step");
                }
            }
            Action::Quit | Action::Interrupt => self.modal = Some(quit_modal(&self.theme)),
            Action::Filter => {
                self.input =
                    Input::Filter(self.filters.get(&self.screen).cloned().unwrap_or_default());
            }
            Action::Command => self.input = Input::Command(String::new()),
            Action::Esc
                if self
                    .filters
                    .get(&self.screen)
                    .is_some_and(|f| !f.is_empty()) =>
            {
                self.filters.remove(&self.screen);
            }
            a => {
                let v = View {
                    d: &self.data,
                    cfg: &self.cfg,
                    t: &self.theme,
                    filter: self
                        .filters
                        .get(&self.screen)
                        .map(String::as_str)
                        .filter(|s| !s.is_empty()),
                    wf: self.wf.as_ref(),
                };
                let effects = self.screens.handle(self.screen, a, &v);
                self.apply(effects, now);
            }
        }
    }

    fn input_key(&mut self, k: KeyEvent, now: Instant) {
        let buf = match &mut self.input {
            Input::Filter(s) | Input::Command(s) | Input::Prompt(_, s) => s,
            Input::None => return,
        };
        match k.code {
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Backspace => {
                if buf.pop().is_none() {
                    self.input = Input::None;
                }
            }
            KeyCode::Esc => {
                if matches!(self.input, Input::Filter(_)) {
                    self.filters.remove(&self.screen);
                }
                self.input = Input::None;
                return;
            }
            KeyCode::Enter => {
                let input = std::mem::replace(&mut self.input, Input::None);
                match input {
                    Input::Command(c) => self.command(c.trim(), now),
                    Input::Prompt(p, text) => self.submit(p, text.trim(), now),
                    _ => {}
                }
                return;
            }
            _ => {}
        }
        if let Input::Filter(s) = &self.input {
            self.filters.insert(self.screen, s.clone());
            self.screens.reset_cursor(self.screen);
        }
    }

    /// `A`: build the selected thing's question and show exactly what would be sent.
    fn ask(&mut self) {
        if !crate::claude::available() {
            self.toast("Claude Code not found (expected ~/.local/bin/claude)");
            return;
        }
        let v = View {
            d: &self.data,
            cfg: &self.cfg,
            t: &self.theme,
            filter: self
                .filters
                .get(&self.screen)
                .map(String::as_str)
                .filter(|s| !s.is_empty()),
            wf: self.wf.as_ref(),
        };
        match self.screens.ask(self.screen, &v) {
            Err(why) => self.toast(why),
            Ok(ask) => {
                self.modal = Some(consent_modal(
                    &self.theme,
                    &ask.prompt(),
                    AskTurn::First(ask),
                ))
            }
        }
    }

    fn chat_key(&mut self, k: KeyEvent, now: Instant) {
        use ratatui::crossterm::event::KeyModifiers;
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let Some(c) = self.chat.as_mut() else { return };
        match k.code {
            KeyCode::Char('c') if ctrl => {
                if let Some((_, pid)) = c.live {
                    let _ = kill(pid);
                    c.push(super::chat::Kind::Info, "stopped");
                }
            }
            KeyCode::Char('k') if ctrl => c.scroll += 1,
            KeyCode::Char('j') if ctrl => c.scroll = c.scroll.saturating_sub(1),
            KeyCode::PageUp => c.scroll += 10,
            KeyCode::PageDown => c.scroll = c.scroll.saturating_sub(10),
            KeyCode::Esc => {
                if let Some((_, pid)) = c.live {
                    let _ = kill(pid);
                }
                self.chat = None;
            }
            KeyCode::Enter if !c.running() && !c.input.trim().is_empty() => {
                let text = std::mem::take(&mut c.input);
                self.modal = Some(consent_modal(
                    &self.theme,
                    &text,
                    AskTurn::Follow(text.clone()),
                ));
            }
            KeyCode::Backspace => {
                c.input.pop();
            }
            KeyCode::Char(ch) if !ctrl && !c.running() => c.input.push(ch),
            _ => {}
        }
        let _ = now;
    }

    fn ask_turn(&mut self, turn: AskTurn) {
        let (prompt, shown, resume) = match turn {
            AskTurn::First(ask) => {
                let p = ask.prompt();
                let q = ask.question.clone();
                self.chat = Some(super::chat::Chat::new(ask));
                (p, q, None)
            }
            AskTurn::Follow(text) => {
                let session = self.chat.as_ref().and_then(|c| c.session.clone());
                (text.clone(), text, session)
            }
        };
        let cmd = crate::claude::turn_cmd(&prompt, resume.as_deref());
        self.run_seq += 1;
        let id = self.run_seq;
        let tx = self.tx.clone();
        let r = cmd.stream(move |m| {
            let _ = tx.send(Event::Run(id, m));
        });
        let Some(c) = self.chat.as_mut() else { return };
        match r {
            Ok(pid) => c.begin_turn(&shown, id, pid),
            Err(e) => c.push(
                super::chat::Kind::Err,
                format!("couldn't start claude: {e}"),
            ),
        }
    }

    /// Kill anything still talking to Claude (sentry is exiting).
    pub fn shutdown(&mut self) {
        if let Some((_, pid)) = self.chat.as_ref().and_then(|c| c.live) {
            let _ = kill(pid);
        }
    }

    fn show_help(&mut self) {
        let hints = self.screens.hints(self.screen, &self.view());
        self.modal = Some(help_modal(&self.theme, self.screen.name(), &hints));
    }

    /// `:workflow [name]`: open Upgrade and start `name` the same way Enter does there.
    fn workflow_command(&mut self, name: Option<&str>, now: Instant) {
        self.enter(ScreenId::Upgrade, now);
        let Some(name) = name else { return };
        if self.wf.as_ref().is_some_and(|s| !s.done()) {
            self.toast("a workflow is already in progress");
            return;
        }
        // The list loads in the background on entry; this needs it now (a few small files).
        let infos = super::screens::upgrade::load_infos();
        let Some(i) = infos.iter().position(|w| w.entry.name == name) else {
            self.toast(format!("no workflow {name} in ~/.config/sentry/workflows"));
            return;
        };
        self.data.workflows.set(Ok(infos));
        self.screens.select_workflow(i);
        let v = View {
            d: &self.data,
            cfg: &self.cfg,
            t: &self.theme,
            filter: None,
            wf: self.wf.as_ref(),
        };
        let effects = self.screens.handle(ScreenId::Upgrade, Action::Enter, &v);
        self.apply(effects, now);
    }

    fn submit(&mut self, p: Prompt, text: &str, now: Instant) {
        match p {
            Prompt::WfVar {
                workflow,
                key,
                mut rest,
                mut vars,
                ..
            } => {
                if text.is_empty() {
                    self.toast(format!("{key} can't be empty"));
                    return;
                }
                vars.insert(key, text.to_string());
                if rest.is_empty() {
                    self.wf_cmd(WfCmd::Begin(workflow, vars), now);
                } else {
                    let (key, prompt, default) = rest.remove(0);
                    self.input = Input::Prompt(
                        Prompt::WfVar {
                            workflow,
                            key,
                            prompt,
                            rest,
                            vars,
                        },
                        default,
                    );
                }
            }
            Prompt::Cadence(job) => {
                use crate::jobs::state::{Every, set_every};
                match Every::parse(text) {
                    Ok(e) => match set_every(job, e) {
                        Ok(()) => {
                            self.toast(format!(
                                "{} every {} (cadence.toml)",
                                job.name(),
                                e.label()
                            ));
                            self.data.fetch(Fetch::Jobs, &self.cfg, &self.tx);
                        }
                        Err(e) => self.toast(format!("cadence.toml: {e}")),
                    },
                    Err(e) => self.toast(e),
                }
            }
        }
    }

    fn command(&mut self, c: &str, now: Instant) {
        let mut parts = c.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("q" | "q!" | "quit" | "qa"), _) => self.quit = true,
            (Some("refresh" | "r"), _) => self.on_key(KeyEvent::from(KeyCode::Char('r')), now),
            (Some("help" | "h"), _) => self.show_help(),
            (Some("job"), Some(name)) => match crate::jobs::JobId::from_name(name) {
                Some(j) => {
                    self.enter(ScreenId::Jobs, now);
                    self.data.fetch(Fetch::Plan(j), &self.cfg, &self.tx);
                }
                None => self.toast(format!("unknown job {name}")),
            },
            (Some("job"), None) => self.enter(ScreenId::Jobs, now),
            (Some("workflow" | "wf"), name) => self.workflow_command(name, now),
            (Some(name), None) => match ScreenId::from_name(name) {
                Some(id) => self.enter(id, now),
                None => self.toast(format!("unknown command :{c}")),
            },
            _ if c.is_empty() => {}
            _ => self.toast(format!("unknown command :{c}")),
        }
    }

    fn run_key(&mut self, k: KeyEvent) {
        let Some(run) = self.run.as_mut() else { return };
        let ctrl_c = k.code == KeyCode::Char('c')
            && k.modifiers
                .contains(ratatui::crossterm::event::KeyModifiers::CONTROL);
        match (k.code, run.done) {
            (KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q'), Some(_)) => self.run = None,
            (_, None) if ctrl_c => {
                if let Some(pid) = run.pid {
                    let _ = kill(pid);
                    self.toast("sent SIGTERM");
                }
            }
            (KeyCode::Esc, None) => self.toast("still running — Ctrl-C terminates"),
            (KeyCode::Char('k') | KeyCode::Up, _) => run.scroll = run.scroll.saturating_add(1),
            (KeyCode::Char('j') | KeyCode::Down, _) => run.scroll = run.scroll.saturating_sub(1),
            (KeyCode::Char('G') | KeyCode::End, _) => run.scroll = 0,
            _ => {}
        }
    }

    // ---------------------------------------------------------------- effects

    fn apply(&mut self, effects: Vec<Effect>, now: Instant) {
        for e in effects {
            match e {
                Effect::Fetch(f) => self.data.fetch(f, &self.cfg, &self.tx),
                Effect::Toast(s) => self.toast(s),
                Effect::Confirm(m) => self.modal = Some(m),
                Effect::Run(spec) => self.start_run(spec),
                Effect::Detach(cmd, msg) => match cmd.detach() {
                    Ok(()) => self.toast(msg),
                    Err(e) => self.toast(format!("{}: {e}", cmd.bin())),
                },
                Effect::Suspend(cmd) => self.suspend = Some(cmd),
                Effect::Kill(pid, msg) => match kill(pid) {
                    Ok(()) => {
                        self.toast(msg);
                        self.sched.procs = now;
                    }
                    Err(e) => self.toast(format!("kill {pid}: {e}")),
                },
                Effect::Baseline(edit) => {
                    use crate::baseline::BaselineFile;
                    let (r, label) = match &edit {
                        BaselineEdit::Listener(k) => (BaselineFile::add_listener(k), k.clone()),
                        BaselineEdit::Listeners(v) => (
                            v.iter().try_fold(false, |any, k| {
                                BaselineFile::add_listener(k).map(|added| any | added)
                            }),
                            format!("{} address(es)", v.len()),
                        ),
                        BaselineEdit::Finding(k) => (BaselineFile::add_finding(k), k.clone()),
                    };
                    match r {
                        Ok(true) => {
                            self.toast(format!("{label} marked expected (baseline.toml)"));
                            self.data.baseline = crate::baseline::Baseline::effective(&self.cfg);
                            if !matches!(edit, BaselineEdit::Finding(_)) {
                                self.data.fetch(Fetch::Net, &self.cfg, &self.tx);
                            }
                        }
                        Ok(false) => self.toast(format!("{label} is already in the baseline")),
                        Err(e) => self.toast(format!("baseline.toml: {e}")),
                    }
                }
                Effect::Unbaseline(edit) => {
                    use crate::baseline::BaselineFile;
                    let (r, label) = match &edit {
                        BaselineEdit::Listener(k) => (
                            BaselineFile::remove_listeners(std::slice::from_ref(k)),
                            k.clone(),
                        ),
                        BaselineEdit::Listeners(v) => (
                            BaselineFile::remove_listeners(v),
                            format!("{} address(es)", v.len()),
                        ),
                        BaselineEdit::Finding(k) => (BaselineFile::remove_finding(k), k.clone()),
                    };
                    self.data.baseline = crate::baseline::Baseline::effective(&self.cfg);
                    let still = match &edit {
                        BaselineEdit::Listener(k) => self.data.baseline.has_listener(k),
                        BaselineEdit::Listeners(v) => {
                            v.iter().any(|k| self.data.baseline.has_listener(k))
                        }
                        BaselineEdit::Finding(k) => self
                            .data
                            .baseline
                            .findings
                            .iter()
                            .any(|p| crate::baseline::glob(p, k)),
                    };
                    match r {
                        Err(e) => self.toast(format!("baseline.toml: {e}")),
                        Ok(_) if still => self.toast(format!(
                            "{label}: still expected by an entry in config.toml [baseline] (edit it there)"
                        )),
                        Ok(0) => self.toast(format!("{label} wasn't marked expected")),
                        Ok(n) => self.toast(format!(
                            "{label} no longer expected ({n} baseline.toml entr{} removed)",
                            if n == 1 { "y" } else { "ies" }
                        )),
                    }
                    if !matches!(edit, BaselineEdit::Finding(_)) {
                        self.data.fetch(Fetch::Net, &self.cfg, &self.tx);
                    }
                }
                Effect::Prompt(p, init) => self.input = Input::Prompt(p, init),
                Effect::Wf(c) => self.wf_cmd(c, now),
                Effect::AskSend(turn) => self.ask_turn(turn),
                Effect::Goto(id) => self.enter(id, now),
                Effect::StartWorkflow(name) => self.workflow_command(Some(&name), now),
                Effect::CleanupFocus(job) => {
                    self.screens.focus_cleanup(job);
                    self.enter(ScreenId::Clean, now);
                }
                Effect::Quit => self.quit = true,
            }
        }
        self.dirty = true;
    }

    fn start_run(&mut self, spec: RunSpec) {
        self.run_seq += 1;
        let id = self.run_seq;
        let tx = self.tx.clone();
        let mut pane = RunPane {
            id,
            title: spec.title,
            cmd: spec.cmd.display(),
            lines: VecDeque::new(),
            started: Instant::now(),
            done: None,
            pid: None,
            then: spec.then,
            ok_toast: spec.ok_toast,
            scroll: 0,
            queue: spec.queue.into(),
        };
        match spec.cmd.stream(move |m| {
            let _ = tx.send(Event::Run(id, m));
        }) {
            Ok(pid) => pane.pid = Some(pid),
            Err(e) => {
                pane.lines.push_back((e.to_string(), true));
                pane.done = Some((127, Duration::ZERO));
            }
        }
        self.run = Some(pane);
    }

    fn wf_cmd(&mut self, c: WfCmd, now: Instant) {
        let _ = now;
        let r: Result<Option<Exec>, String> = match c {
            WfCmd::Arm => {
                if let Some(s) = self.wf.as_mut() {
                    s.armed = true;
                }
                Ok(self.wf.as_mut().and_then(Session::auto))
            }
            WfCmd::Begin(name, vars) => {
                let Some(entry) = crate::workflows::find(&name) else {
                    self.toast(format!("no workflow {name}"));
                    return;
                };
                match Session::begin(&entry, vars) {
                    Ok(s) => {
                        self.wf = Some(s);
                        // Entering the screen arms the session and runs the first auto step.
                        self.enter(ScreenId::Upgrade, now);
                        Ok(None)
                    }
                    Err(e) => Err(format!("{e:#}")),
                }
            }
            WfCmd::Close => {
                if self.wf.as_ref().is_some_and(Session::done) {
                    self.wf = None;
                    self.data.fetch(Fetch::Workflows, &self.cfg, &self.tx);
                }
                Ok(None)
            }
            WfCmd::Edit(path) => {
                let editor = std::env::var("VISUAL")
                    .or_else(|_| std::env::var("EDITOR"))
                    .unwrap_or_else(|_| "nano".into());
                let mut parts = editor.split_whitespace();
                let bin = parts.next().unwrap_or("nano").to_string();
                let cmd = Cmd::local(&bin)
                    .args(parts.map(str::to_string))
                    .arg(path.as_os_str())
                    .timeout(None);
                self.suspend = Some(cmd);
                self.data.fetch(Fetch::Workflows, &self.cfg, &self.tx);
                Ok(None)
            }
            c => {
                let Some(s) = self.wf.as_mut() else {
                    return;
                };
                match c {
                    WfCmd::Go => s.go(),
                    WfCmd::Skip => s.skip().map(|_| None),
                    WfCmd::Retry => {
                        if s.error.is_some() {
                            s.refresh();
                            Ok(None)
                        } else {
                            s.retry().map(|_| None)
                        }
                    }
                    WfCmd::Done => s.mark_done().map(|_| None),
                    WfCmd::SkipDry => s.skip_dry().map(|_| None),
                    WfCmd::Abandon => {
                        s.abandon();
                        Ok(None)
                    }
                    WfCmd::Scroll(d) => {
                        s.scroll = if d == i32::MIN {
                            0
                        } else {
                            (s.scroll as i64 + d as i64).clamp(0, s.log.len() as i64) as usize
                        };
                        Ok(None)
                    }
                    WfCmd::OpenLog => {
                        let id = s
                            .next
                            .idx()
                            .or_else(|| s.wf.steps.len().checked_sub(1))
                            .map(|i| s.wf.steps[i].id.clone());
                        let path = id.map(|id| s.run.log_path(&id));
                        match path.filter(|p| p.exists()) {
                            Some(p) => {
                                self.suspend = Some(
                                    Cmd::local("less")
                                        .args(["-R", "+G"])
                                        .arg(p.as_os_str())
                                        .timeout(None),
                                );
                                Ok(None)
                            }
                            None => Err("no log for this step yet".into()),
                        }
                    }
                    WfCmd::Rollback => {
                        let cmds = s.rollback_cmds();
                        s.abandon();
                        let mut it = cmds.into_iter().map(|(_, c)| c);
                        if let Some(first) = it.next() {
                            self.start_run(RunSpec {
                                title: "rollback steps".into(),
                                cmd: first,
                                queue: it.collect(),
                                then: vec![Fetch::Ostree, Fetch::Workflows],
                                ok_toast: "rollback steps done · workflow abandoned".into(),
                            });
                        }
                        Ok(None)
                    }
                    WfCmd::Arm | WfCmd::Begin(..) | WfCmd::Close | WfCmd::Edit(_) => Ok(None),
                }
            }
        };
        match r {
            Ok(Some(e)) => self.wf_exec(e),
            Ok(None) => {}
            Err(e) => self.toast(e),
        }
        self.after_wf_change();
        self.dirty = true;
    }

    /// Run the next auto step if the session wants one.
    fn wf_auto(&mut self) {
        if let Some(e) = self.wf.as_mut().and_then(Session::auto) {
            self.wf_exec(e);
        }
    }

    /// Keep tabs, dashboard and the workflow list in step with the session.
    fn after_wf_change(&mut self) {
        if self.wf.as_ref().is_some_and(Session::done) {
            self.data.fetch(Fetch::Workflows, &self.cfg, &self.tx);
        }
    }

    fn wf_exec(&mut self, e: Exec) {
        match e {
            Exec::Stream {
                cmd,
                idx,
                dry,
                timeout,
            } => {
                self.run_seq += 1;
                let id = self.run_seq;
                let tx = self.tx.clone();
                let r = cmd.stream(move |m| {
                    let _ = tx.send(Event::Run(id, m));
                });
                let Some(s) = self.wf.as_mut() else { return };
                match r {
                    Ok(pid) => {
                        s.live = Some(super::wf::Live {
                            id,
                            idx,
                            dry,
                            started: Instant::now(),
                            deadline: timeout.map(|t| Instant::now() + t),
                            pid: Some(pid),
                        })
                    }
                    Err(e) => s.on_exit(idx, dry, 127, Some(e.to_string())),
                }
            }
            Exec::Tty { cmd, idx } => {
                self.suspend = Some(cmd);
                self.suspend_for = Some(SuspendFor::Step(idx));
            }
            Exec::Shell { idx } => {
                let sh = std::env::var("SHELL").unwrap_or_else(|_| "bash".into());
                self.suspend = Some(Cmd::local(&sh).timeout(None));
                self.suspend_for = Some(SuspendFor::Shell(idx));
            }
            Exec::Reboot => {
                let r = crate::workflows::cli::reboot_cmd().run();
                let msg = match r {
                    Ok(o) => format!("{}{}", o.stdout.trim(), o.stderr.trim()),
                    Err(e) => e.to_string(),
                };
                if let Some(s) = self.wf.as_mut() {
                    s.push(msg.clone(), super::wf::LogKind::Info);
                    s.refresh();
                }
                if !msg.is_empty() {
                    self.toast(msg);
                }
            }
        }
    }

    pub fn take_suspend(&mut self) -> Option<Cmd> {
        self.suspend.take()
    }

    pub fn after_suspend(&mut self, status: Result<ExitStatus, ExecError>) {
        if let Some(sf) = self.suspend_for.take()
            && let Some(s) = self.wf.as_mut()
        {
            match sf {
                SuspendFor::Step(idx) => {
                    let (code, note) = match &status {
                        Ok(st) => (st.code().unwrap_or(-1), None),
                        Err(e) => (127, Some(e.to_string())),
                    };
                    s.on_exit(idx, false, code, note);
                }
                SuspendFor::Shell(idx) => s.after_shell(idx),
            }
            self.wf_auto();
            self.after_wf_change();
            self.dirty = true;
            return;
        }
        match status {
            Ok(s) if s.success() => self.toast("back in sentry"),
            Ok(s) => self.toast(format!("exited with {}", s.code().unwrap_or(-1))),
            Err(e) => self.toast(e.to_string()),
        }
        self.dirty = true;
    }

    fn visible_tabs(&self) -> Vec<ScreenId> {
        // History only appears once the recorder has produced data (spec §11); `H` still opens it.
        let has_rec = crate::recorder::ring::path().exists();
        ScreenId::ALL
            .into_iter()
            .filter(|s| *s != ScreenId::Hist || has_rec || self.screen == ScreenId::Hist)
            .collect()
    }

    // ---------------------------------------------------------------- drawing

    pub fn draw(&mut self, f: &mut Frame) {
        let area = f.area();
        let t = self.theme;
        if area.width < 80 || area.height < 24 {
            widgets::placeholder(
                f,
                area,
                &t,
                &[(
                    &format!(
                        "terminal too small ({}×{}, need 80×24)",
                        area.width, area.height
                    ),
                    t.dim(),
                )],
            );
            return;
        }
        let banner = (self.wf.is_some() && self.screen != ScreenId::Upgrade) as u16;
        let [top, tabs, rule, ban, body, keyrule, keybar] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(banner),
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);
        self.draw_top(f, top);
        self.draw_tabs(f, tabs);
        f.render_widget(
            Paragraph::new("─".repeat(rule.width as usize)).style(t.s(t.border)),
            rule,
        );
        if let Some(sess) = self
            .wf
            .as_ref()
            .filter(|_| self.screen != ScreenId::Upgrade)
        {
            let n = sess.wf.steps.len();
            let hint = "press 0 to continue";
            let fixed = format!(
                " ↻ workflow {} · step 99/{n}  · {}   ",
                sess.wf.name,
                sess.state_word()
            );
            let room = (ban.width as usize).saturating_sub(fixed.chars().count() + hint.len());
            let step = sess.next.idx().map_or(String::new(), |i| {
                format!(
                    "step {}/{n} {}",
                    i + 1,
                    widgets::trunc(&sess.title(i), room)
                )
            });
            let line = Line::from(vec![
                Span::styled(
                    format!(
                        " ↻ workflow {} · {step} · {}   ",
                        sess.wf.name,
                        sess.state_word()
                    ),
                    t.s(t.yellow),
                ),
                Span::styled(hint, t.dim()),
            ]);
            f.render_widget(
                Paragraph::new(line).style(Style::new().bg(t.banner_bg)),
                ban,
            );
        }
        let body = Rect {
            y: body.y + 1,
            height: body.height.saturating_sub(1),
            ..body
        };
        let v = View {
            d: &self.data,
            cfg: &self.cfg,
            t: &self.theme,
            filter: self
                .filters
                .get(&self.screen)
                .map(String::as_str)
                .filter(|s| !s.is_empty()),
            wf: self.wf.as_ref(),
        };
        self.screens.render(self.screen, f, body, &v);
        f.render_widget(
            Paragraph::new("─".repeat(keyrule.width as usize)).style(t.s(t.border)),
            keyrule,
        );
        self.draw_keybar(f, keybar);
        if let Some(c) = &self.chat {
            widgets::dim_backdrop(f.buffer_mut(), body);
            super::chat::draw(f, body, &t, c);
        }
        if let Some(m) = &self.modal {
            widgets::dim_backdrop(f.buffer_mut(), body);
            draw_modal(f, body, &t, m);
        }
        if let Some(r) = &self.run {
            widgets::dim_backdrop(f.buffer_mut(), body);
            draw_run(f, body, &t, r);
        }
    }

    fn draw_top(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        let up = self
            .data
            .sys
            .as_ref()
            .map(|s| s.uptime_s)
            .unwrap_or_else(sysinfo::System::uptime);
        let mut left = vec![
            Span::styled(
                " sentry ",
                Style::new()
                    .fg(t.ink)
                    .bg(t.cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("  silverblue {}", self.data.os_version), t.fg()),
            Span::styled(format!("  kernel {}", self.data.kernel), t.dim()),
            Span::styled(format!("  up {}", fmt::uptime(up)), t.dim()),
        ];
        let (live, color) = match self.screen {
            ScreenId::Dash => (format!("● live {} Hz", self.cfg.ui.dashboard_hz), t.green),
            ScreenId::Proc => (format!("● live {} Hz", self.cfg.ui.processes_hz), t.green),
            ScreenId::Net => ("● live 3 s".to_string(), t.green),
            _ => ("○ idle".to_string(), t.dim),
        };
        let clock = jiff::Zoned::now().strftime("%a %d %b %H:%M").to_string();
        let right = Line::from(vec![
            Span::styled(live, t.s(color)),
            Span::styled(format!("   {clock} "), t.dim()),
        ]);
        let rw = right.width() as u16;
        // Narrow terminals: drop kernel, then uptime, rather than overlap the clock.
        for drop in [2, 2] {
            if Line::from(left.clone()).width() as u16 + rw + 1 > area.width && left.len() > drop {
                left.remove(drop);
            }
        }
        f.render_widget(Paragraph::new(Line::from(left)), area);
        f.render_widget(
            Paragraph::new(right),
            Rect {
                x: area.right().saturating_sub(rw),
                width: rw,
                ..area
            },
        );
    }

    fn badge(&self, id: ScreenId) -> Option<(String, Color)> {
        let t = &self.theme;
        match id {
            ScreenId::Upd => {
                let os = self.data.ostree.get().and_then(|o| o.update.as_ref());
                let fp = self.data.fp_updates.get().map_or(0, |c| c.data.len());
                match os {
                    Some(u) if u.kernel_changed => Some((" !".into(), t.yellow)),
                    Some(_) => Some((" ↑".into(), t.yellow)),
                    None if fp > 0 => Some((format!(" {fp}"), t.yellow)),
                    None => None,
                }
            }
            ScreenId::Cont => {
                let n = crate::collectors::toolbox::total(&self.data.tbx_updates.get()?.data);
                (n > 0).then(|| (format!(" {n}"), t.yellow))
            }
            ScreenId::Net => {
                let n = self.data.net.get().map_or(0, |n| {
                    n.listeners
                        .iter()
                        .filter(|l| l.status == crate::collectors::net::ListenStatus::New)
                        .count()
                });
                (n > 0).then(|| (format!(" {n}"), t.red))
            }
            ScreenId::Audit => {
                let r = self.data.reports.get()?.last()?;
                let c = r.report.counts(&self.data.baseline);
                (c.high > 0).then(|| (format!(" !{}", c.high), t.red))
            }
            ScreenId::Jobs => {
                let runs = self.data.job_runs.get()?;
                let n = runs.due_jobs(&self.cfg, jiff::Timestamp::now()).len();
                (n > 0).then(|| (format!(" {n}"), t.yellow))
            }
            ScreenId::Upgrade => self
                .wf
                .as_ref()
                .filter(|s| !s.done())
                .map(|_| (" ●".into(), t.yellow)),
            _ => None,
        }
    }

    fn draw_tabs(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        let tabs = self.visible_tabs();
        let full: usize = tabs.iter().map(|s| s.name().len() + 4).sum();
        let short: usize = tabs.iter().map(|s| s.short().len() + 4).sum();
        let w = area.width as usize;
        let mut spans = Vec::new();
        for id in tabs {
            let active = id == self.screen;
            let name = if full + 6 <= w || active {
                id.name()
            } else if short + 6 <= w {
                id.short()
            } else {
                ""
            };
            let (fg, kc, bg) = if active {
                (t.ink, t.ink, t.fg)
            } else {
                (t.fg, t.dim, Color::Reset)
            };
            let bg_style = if active {
                Style::new().bg(bg)
            } else {
                Style::new()
            };
            spans.push(Span::styled(format!(" {}", id.key()), bg_style.fg(kc)));
            if !name.is_empty() {
                spans.push(Span::styled(format!(" {name}"), bg_style.fg(fg)));
            }
            if let Some((b, c)) = self.badge(id) {
                spans.push(Span::styled(b, bg_style.fg(if active { t.ink } else { c })));
            }
            if let Some(flt) = self.filters.get(&id).filter(|s| !s.is_empty()) {
                spans.push(Span::styled(
                    format!(" /{flt}"),
                    bg_style.fg(if active { t.ink } else { t.cyan }),
                ));
            }
            spans.push(Span::styled(" ", bg_style));
            spans.push(Span::raw(" "));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn draw_keybar(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        let mut spans = Vec::new();
        match &self.input {
            Input::Filter(s) => {
                spans.push(Span::styled(format!("/{s}"), t.fg()));
                spans.push(Span::styled("▏", t.s(t.cyan)));
                spans.push(Span::styled("   Enter keep · Esc clear", t.dim()));
            }
            Input::Command(s) => {
                spans.push(Span::styled(format!(":{s}"), t.fg()));
                spans.push(Span::styled("▏", t.s(t.cyan)));
            }
            Input::Prompt(p, s) => {
                spans.push(Span::styled(p.label(), t.dim()));
                spans.push(Span::styled(s.clone(), t.fg()));
                spans.push(Span::styled("▏", t.s(t.cyan)));
                spans.push(Span::styled("   Enter save · Esc cancel", t.dim()));
            }
            Input::None => {
                let hints: Vec<(&str, &str)> = if self.run.is_some() {
                    if self.run.as_ref().is_some_and(|r| r.done.is_some()) {
                        vec![("Esc", "close"), ("j/k", "scroll")]
                    } else {
                        vec![("C-c", "terminate"), ("j/k", "scroll")]
                    }
                } else if self.modal.as_ref().is_some_and(|m| m.yes.is_some()) {
                    vec![("y", "confirm"), ("n", "cancel")]
                } else {
                    let v = self.view();
                    let mut h = self.screens.hints(self.screen, &v);
                    // `A` is global but invisible unless it's in the bar on every tab.
                    if crate::claude::available() {
                        h.push(("A", "ask Claude"));
                    }
                    h.extend([("?", "help"), ("q", "quit")]);
                    h
                };
                // Too wide: drop the screen's own hints from the end, never the global
                // ones (A, ?, q) that end the list. Chips are ` k ` + ` d` + two spaces.
                let mut hints = hints;
                let room = (area.width as usize).saturating_sub(
                    self.toast
                        .as_ref()
                        .map_or(0, |(m, _)| m.chars().count() + 2),
                );
                let width = |h: &[(&str, &str)]| -> usize {
                    h.iter()
                        .map(|(k, d)| k.chars().count() + d.chars().count() + 5)
                        .sum()
                };
                let globals = hints
                    .iter()
                    .rev()
                    .take_while(|(k, _)| matches!(*k, "A" | "?" | "q"))
                    .count();
                while width(&hints) > room && hints.len() > globals {
                    hints.remove(hints.len() - globals - 1);
                }
                for (k, d) in hints {
                    spans.extend(chip(t, k, d, t.dim));
                    spans.push(Span::raw("  "));
                }
            }
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
        if let Some((msg, _)) = &self.toast {
            let w = (msg.chars().count() as u16 + 1).min(area.width / 2);
            let r = Rect {
                x: area.right() - w,
                width: w,
                ..area
            };
            f.render_widget(
                Paragraph::new(Span::styled(widgets::trunc(msg, w as usize - 1), t.fg())),
                r,
            );
        }
    }
}

fn kill(pid: u32) -> std::io::Result<()> {
    let pid = rustix::process::Pid::from_raw(pid as i32)
        .ok_or_else(|| std::io::Error::other("bad pid"))?;
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).map_err(std::io::Error::from)
}

fn draw_modal(f: &mut Frame, area: Rect, t: &Theme, m: &Modal) {
    let w = 84u16.min(area.width);
    // Inner text width = box − borders − padding; count wrapped rows so nothing is clipped.
    let text_w = w.saturating_sub(4).max(1) as usize;
    let rows: usize = m
        .lines
        .iter()
        .map(|l| l.width().max(1).div_ceil(text_w))
        .sum();
    let rect = widgets::centered(area, w, rows as u16 + 5);
    let inner = widgets::overlay(f, rect, t, &m.title, m.color);
    let [body, _, keys] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    let body = Rect {
        y: body.y + 1,
        height: body.height.saturating_sub(1),
        ..body
    };
    f.render_widget(
        Paragraph::new(m.lines.clone()).wrap(Wrap { trim: false }),
        body,
    );
    let mut spans = Vec::new();
    match &m.yes {
        Some((label, _)) => {
            spans.extend(chip(t, "y", label, m.color));
            spans.push(Span::raw("   "));
            spans.extend(chip(t, "n", "cancel", t.dim));
        }
        None => spans.extend(chip(t, "Enter", "close", m.color)),
    }
    f.render_widget(Paragraph::new(Line::from(spans)), keys);
}

fn draw_run(f: &mut Frame, area: Rect, t: &Theme, r: &RunPane) {
    let rect = widgets::centered(
        area,
        area.width.saturating_sub(8).max(60),
        area.height.saturating_sub(2),
    );
    let (color, status) = match r.done {
        None => {
            let s = r.started.elapsed().as_secs();
            (t.cyan, format!("⠿ running · {}:{:02}", s / 60, s % 60))
        }
        Some((0, d)) => (t.green, format!("✓ done · {:.1}s", d.as_secs_f32())),
        Some((c, d)) => (t.red, format!("✗ exit {c} · {:.1}s", d.as_secs_f32())),
    };
    let inner = widgets::overlay(f, rect, t, &r.title, color);
    let [cmd, log, foot] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    f.render_widget(
        Paragraph::new(Span::styled(format!("$ {}", r.cmd), t.dim())),
        cmd,
    );
    let h = log.height as usize;
    let end = r.lines.len().saturating_sub(r.scroll);
    let start = end.saturating_sub(h);
    let lines: Vec<Line> = r
        .lines
        .iter()
        .skip(start)
        .take(end - start)
        .map(|(s, _)| {
            let st = if s.contains("error") || s.contains("Error") {
                t.s(t.red)
            } else {
                t.fg()
            };
            Line::styled(widgets::trunc(s, log.width as usize), st)
        })
        .collect();
    f.render_widget(Paragraph::new(lines), log);
    f.render_widget(Paragraph::new(Span::styled(status, t.s(color))), foot);
}

fn help_modal(t: &Theme, screen: &str, hints: &[(&str, &str)]) -> Modal {
    let l = |s: &str| Line::styled(s.to_string(), t.fg());
    let mut lines = vec![
        l("1–9 0 H   switch screen        Tab/S-Tab, h/l  next/prev screen"),
        l("j/k ↑↓    move selection       gg/G  top/bottom   C-d/C-u  page"),
        l("/         filter (Esc clears)  n/N   next/prev    C-h/C-l  pane focus"),
        l("r         refresh current      c     check now    C-j/C-k  scroll log/diff"),
        l("Enter     select / act         Esc   cancel       ?  help    q  quit"),
        l("A         ask Claude about the selected thing (you see what's sent first)"),
        l(":q  :<screen>  :job <name>  :workflow <name>  :refresh"),
        Line::raw(""),
        Line::styled(format!("{screen}:"), t.s(t.cyan)),
    ];
    let mut row = String::new();
    for (k, d) in hints {
        let cell = format!("{k:<7} {d:<22}");
        if row.chars().count() + cell.chars().count() > 76 {
            lines.push(l(row.trim_end()));
            row.clear();
        }
        row.push_str(&cell);
    }
    if !row.is_empty() {
        lines.push(l(row.trim_end()));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "Destructive actions: preview → confirm → streamed output.",
        t.dim(),
    ));
    lines.push(Line::styled(
        "Nothing runs in the background after sentry exits.",
        t.dim(),
    ));
    Modal {
        title: "Keys".into(),
        color: t.cyan,
        lines,
        yes: None,
    }
}

/// What is about to leave the machine, verbatim, before every Claude turn.
fn consent_modal(t: &Theme, text: &str, turn: AskTurn) -> Modal {
    let mut lines = vec![
        Line::styled(
            "Sent to Claude through your Claude Code login (Anthropic):",
            t.fg(),
        ),
        Line::raw(""),
    ];
    let shown: Vec<&str> = text.lines().collect();
    for l in shown.iter().take(24) {
        lines.push(Line::styled(format!("  {l}"), t.dim()));
    }
    if shown.len() > 24 {
        lines.push(Line::styled(
            format!("  … {} more lines", shown.len() - 24),
            t.dim(),
        ));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        crate::claude::allowlist_summary(),
        t.s(t.yellow),
    ));
    Modal {
        title: "Ask Claude".into(),
        color: t.mag,
        lines,
        yes: Some(("send".into(), vec![Effect::AskSend(turn)])),
    }
}

fn quit_modal(t: &Theme) -> Modal {
    Modal {
        title: "Quit".into(),
        color: t.dim,
        lines: vec![Line::styled(
            "Quit sentry? Nothing keeps running after exit.",
            t.fg(),
        )],
        yes: Some(("quit".into(), vec![Effect::Quit])),
    }
}

pub fn info_modal(t: &Theme, title: &str, lines: Vec<Line<'static>>) -> Modal {
    Modal {
        title: title.into(),
        color: t.cyan,
        lines,
        yes: None,
    }
}

/// Render the whole UI into plain text (snapshot tests).
#[cfg(test)]
pub fn render_to_string(app: &mut App, w: u16, h: u16) -> String {
    let backend = ratatui::backend::TestBackend::new(w, h);
    let mut term = ratatui::Terminal::new(backend).unwrap();
    term.draw(|f| app.draw(f)).unwrap();
    let buf = term.backend().buffer().clone();
    let mut out = String::new();
    for y in 0..h {
        let mut line = String::new();
        for x in 0..w {
            line.push_str(buf[(x, y)].symbol());
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::data::DataStore;

    fn sh(script: &str) -> Cmd {
        Cmd::local("sh").args(["-c", script]).timeout(None)
    }

    /// Run `spec` to completion, pumping stream events through the app.
    fn run(spec: RunSpec) -> (Vec<String>, Option<(i32, Duration)>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut a = App::for_test(
            Config::default(),
            DataStore::blank(String::new(), String::new()),
            ScreenId::Dash,
        );
        a.tx = tx;
        a.apply(vec![Effect::Run(spec)], Instant::now());
        while a.run.as_ref().is_some_and(|r| r.done.is_none()) {
            let ev = rx.recv_timeout(Duration::from_secs(5)).expect("event");
            a.on_event(ev, Instant::now());
        }
        let r = a.run.take().unwrap();
        (r.lines.into_iter().map(|(l, _)| l).collect(), r.done)
    }

    #[test]
    fn queue_runs_in_order_and_stops_on_failure() {
        let spec = |first: &str| RunSpec {
            title: "t".into(),
            cmd: sh(first),
            queue: vec![sh("echo two"), sh("echo three")],
            then: vec![],
            ok_toast: "ok".into(),
        };
        let (lines, done) = run(spec("echo one"));
        let text = lines.join("|");
        assert!(text.starts_with("one|"), "{text}");
        assert!(
            text.contains("$ echo two|two") && text.ends_with("three"),
            "{text}"
        );
        assert_eq!(done.map(|d| d.0), Some(0));
        let (lines, done) = run(spec("echo bad; exit 3"));
        assert_eq!(lines, vec!["bad"]);
        assert_eq!(done.map(|d| d.0), Some(3));
    }
}

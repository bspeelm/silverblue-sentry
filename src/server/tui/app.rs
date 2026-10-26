//! State, keys, refresh schedule and the frame around the tabs.

use std::collections::VecDeque;
use std::process::ExitStatus;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::data::{Kind, Store};
use super::tabs::{self, View};
use super::{Ev, Tab};
use crate::claude::{self, Ask, Proposed};
use crate::exec::{Cmd, ExecError, StreamMsg};
use crate::server::remote::Remote;
use crate::server::workflow::{self, Exec, Session};
use crate::tui::chat::{self as chatmod, Chat, Job};
use crate::tui::keys::{Action, Keymap};
use crate::tui::modal;
use crate::tui::theme::Theme;
use crate::tui::widgets::{self, chip};
use crate::workflows::Entry;
use crate::workflows::runner::Next;

/// What a key press asks the app to do.
#[derive(Clone, Debug)]
pub enum Effect {
    Fetch(Kind),
    Toast(String),
    Info(String, Vec<Line<'static>>),
    Goto(Tab),
    Expected(String, bool),
    Quit,
    Confirm(Modal),
    /// Stream a command's output into the pane (after a confirm).
    Run(RunSpec),
    /// Hand the terminal to a command (sudo password prompts), then refresh.
    Suspend(Cmd, String, Vec<Kind>),
    /// Read-only output, fetched once, shown in the scrollable pane.
    Logs(String, Cmd),
    /// Pick one of several (digits 1-9).
    Choose(String, Vec<Choice>),
    /// Workflow actions.
    Wf(WfCmd),
    /// Send a turn to Claude (after the consent box).
    AskSend(AskTurn),
    /// Run one of Claude's proposals on the server (after its confirm box).
    ChatRun(Proposed),
}

#[derive(Clone, Debug)]
pub enum AskTurn {
    First(Ask),
    Follow(String),
}

#[derive(Clone, Debug)]
pub enum WfCmd {
    Begin(String),
    Go,
    Skip(bool),
    Done,
    Retry,
    Abandon,
    Close,
}

/// One entry of a chooser: its label and what picking it does.
pub type Choice = (String, Vec<Effect>);

#[derive(Clone, Debug)]
pub struct RunSpec {
    pub title: String,
    pub cmd: Cmd,
    /// What to re-read when it exits.
    pub then: Vec<Kind>,
    /// It reboots the server: wait for it to come back.
    pub reboot: bool,
}

/// Streamed output of an action, or a log being read.
struct Pane {
    id: u64,
    title: String,
    cmd: String,
    lines: VecDeque<String>,
    pid: Option<u32>,
    /// Exit code once finished (`None` = running).
    done: Option<i32>,
    started: Instant,
    scroll: usize,
    then: Vec<Kind>,
    reboot: bool,
}

const PANE_LINES: usize = 5000;

pub type Modal = modal::Modal<Effect>;

#[derive(Default)]
struct Sched {
    probe: Option<Instant>,
    fast: Option<Instant>,
    slow: Option<Instant>,
}

const PROBE: Duration = Duration::from_secs(1);
const FAST: Duration = Duration::from_secs(5);
const SLOW: Duration = Duration::from_secs(60);
/// Updates and the apt simulation are slow-moving; re-read on entering the tab at most hourly.
const APT_MAX_AGE: Duration = Duration::from_secs(3600);

pub struct App {
    pub remote: Remote,
    tx: Sender<Ev>,
    pub theme: Theme,
    keys: Keymap,
    pub store: Store,
    pub tab: Tab,
    cursors: [usize; 6],
    modal: Option<Modal>,
    toast: Option<(String, Instant)>,
    sched: Sched,
    pane: Option<Pane>,
    chooser: Option<(String, Vec<Choice>)>,
    suspend: Option<(Cmd, String, Vec<Kind>)>,
    run_seq: u64,
    /// Rebooting: since when, and the boot id it had.
    reboot_wait: Option<(Instant, String)>,
    /// The workflow run in progress on this server.
    pub wf: Option<Session>,
    wf_entries: Vec<Entry>,
    /// A step running with the terminal handed over.
    suspend_step: Option<usize>,
    /// The stream id of a workflow's reboot command.
    wf_reboot_id: Option<u64>,
    chat: Option<Chat>,
    /// The `:` command line being typed.
    cmdline: Option<String>,
    pub quit: bool,
    pub dirty: bool,
    /// Fixed clock for snapshot tests.
    pub now_override: Option<jiff::Timestamp>,
    /// Tests: never start a fetch.
    pub offline: bool,
}

impl App {
    pub fn new(remote: Remote, tx: Sender<Ev>) -> Self {
        let (keys, _) = Keymap::new(&Default::default());
        Self {
            remote,
            tx,
            theme: Theme::detect(),
            keys,
            store: Store::default(),
            tab: Tab::Overview,
            cursors: [0; 6],
            modal: None,
            toast: None,
            sched: Sched::default(),
            pane: None,
            chooser: None,
            suspend: None,
            run_seq: 0,
            reboot_wait: None,
            wf: None,
            wf_entries: Vec::new(),
            suspend_step: None,
            wf_reboot_id: None,
            chat: None,
            cmdline: None,
            quit: false,
            dirty: true,
            now_override: None,
            offline: false,
        }
    }

    pub fn start(&mut self, now: Instant) {
        self.fetch(Kind::Host);
        self.fetch(Kind::Sudo);
        if !self.offline {
            self.wf = Session::resume(&self.remote);
        }
        self.enter(self.tab, now);
    }

    fn fetch(&mut self, k: Kind) {
        if self.offline {
            return;
        }
        let (r, tx) = (self.remote.clone(), self.tx.clone());
        self.store.fetch(k, &r, &tx);
    }

    /// Switch tabs; what the tab shows is fetched right away.
    pub fn enter(&mut self, tab: Tab, now: Instant) {
        self.tab = tab;
        self.sched = Sched::default();
        match tab {
            Tab::Overview => {
                // Status rows need a little of everything.
                for k in [Kind::Units, Kind::Docker, Kind::Report] {
                    self.fetch(k);
                }
                self.fetch_apt_if_stale();
            }
            Tab::Services => {
                self.fetch(Kind::Units);
                self.fetch(Kind::Journal);
            }
            Tab::Containers => self.fetch(Kind::Docker),
            Tab::Updates => self.fetch_apt_if_stale(),
            Tab::Audit => self.fetch(Kind::Report),
            Tab::Workflows => {
                if !self.offline {
                    self.wf_entries = workflow::list();
                }
                if let Some(s) = self.wf.as_mut() {
                    s.armed = true;
                }
            }
        }
        self.tick(now);
        self.dirty = true;
    }

    fn fetch_apt_if_stale(&mut self) {
        if self.store.apt.at.is_none_or(|t| t.elapsed() > APT_MAX_AGE) {
            self.fetch(Kind::Apt);
        }
    }

    pub fn tick(&mut self, now: Instant) {
        if self.toast.as_ref().is_some_and(|(_, t)| now >= *t) {
            self.toast = None;
            self.dirty = true;
        }
        if self.reboot_wait.is_some() && self.sched.probe.is_none_or(|t| now >= t) {
            // Every 2 s on any tab until the boot id changes.
            self.fetch(Kind::Probe);
            self.sched.probe = Some(now + Duration::from_secs(2));
        }
        if self.tab == Tab::Workflows {
            self.wf_auto();
        }
        if self.tab != Tab::Overview {
            return;
        }
        if self.sched.probe.is_none_or(|t| now >= t) {
            self.fetch(Kind::Probe);
            self.sched.probe = Some(now + PROBE);
        }
        if self.sched.fast.is_none_or(|t| now >= t) {
            self.fetch(Kind::Gpu);
            self.fetch(Kind::Temp);
            self.sched.fast = Some(now + FAST);
        }
        if self.sched.slow.is_none_or(|t| now >= t) {
            if self.sched.slow.is_some() {
                self.fetch(Kind::Units);
                self.fetch(Kind::Docker);
            }
            self.fetch(Kind::Disks);
            if !self.remote.cfg.smart.is_empty() {
                self.fetch(Kind::Smart);
            }
            self.sched.slow = Some(now + SLOW);
        }
    }

    pub fn next_due(&self, now: Instant) -> Instant {
        let mut due = now + Duration::from_secs(60);
        if self.tab == Tab::Overview || self.reboot_wait.is_some() {
            for t in [self.sched.probe, self.sched.fast, self.sched.slow]
                .into_iter()
                .flatten()
            {
                due = due.min(t);
            }
        }
        if let Some((_, t)) = &self.toast {
            due = due.min(*t);
        }
        due.max(now)
    }

    pub fn on_event(&mut self, ev: Ev, now: Instant) {
        match ev {
            Ev::Key(k) => self.on_key(k, now),
            Ev::Resize => self.dirty = true,
            Ev::Signal => self.quit = true,
            Ev::Data(k, res) => {
                if k == Kind::Audit && res.is_ok() {
                    self.toast("audit done · report saved");
                }
                if k == Kind::Audit
                    && let Err(e) = res.as_ref()
                {
                    self.toast(&format!("audit failed: {e}"));
                }
                self.store.apply(k, *res);
                if k == Kind::Probe {
                    self.check_back();
                }
                let n = self.rows();
                let c = &mut self.cursors[self.tab.index()];
                *c = (*c).min(n.saturating_sub(1));
                self.dirty = true;
            }
            Ev::Run(id, m) => self.on_run(id, m),
            Ev::Text(id, res) => {
                if let Some(p) = self.pane.as_mut().filter(|p| p.id == id) {
                    match res {
                        Ok(text) => p.lines.extend(text.lines().map(str::to_string)),
                        Err(e) => p.lines.push_back(format!("✗ {e}")),
                    }
                    p.done = Some(0);
                    // Logs open at their end, like `less +G`.
                    p.scroll = 0;
                }
                self.dirty = true;
            }
        }
    }

    fn on_run(&mut self, id: u64, m: StreamMsg) {
        if let Some(c) = self.chat.as_mut()
            && c.live.is_some_and(|(cid, _)| cid == id)
        {
            match m {
                StreamMsg::Line {
                    stderr: false,
                    text,
                } => {
                    for e in claude::parse_line(&text) {
                        c.on_event(e);
                    }
                }
                StreamMsg::Line { stderr: true, text } => c.on_raw(text),
                StreamMsg::Exit { code, .. } => c.on_exit(code),
            }
            self.dirty = true;
            return;
        }
        if let Some(c) = self.chat.as_mut()
            && c.job.as_ref().is_some_and(|(jid, _, _)| *jid == id)
        {
            match m {
                StreamMsg::Line { text, .. } => c.on_job_line(text),
                StreamMsg::Exit { code, .. } => {
                    if let Some((_, _, Job::Proposal { cmd, output, .. })) = c.job.take() {
                        c.push(chatmod::Kind::Info, format!("exit {code}"));
                        c.set_offer(&cmd, code, &output, None);
                        c.push(chatmod::Kind::Info, "s sends the output to Claude");
                    }
                    for k in [Kind::Units, Kind::Docker] {
                        self.fetch(k);
                    }
                }
            }
            self.dirty = true;
            return;
        }
        if let Some(s) = self.wf.as_mut()
            && let Some(l) = s.live.as_ref().filter(|l| l.id == id)
        {
            let idx = l.idx;
            match m {
                StreamMsg::Line { text, .. } => s.on_line(&text),
                StreamMsg::Exit { code, .. } => {
                    s.on_exit(idx, code);
                    self.wf_auto();
                }
            }
            self.dirty = true;
            return;
        }
        if self.wf_reboot_id == Some(id) {
            // The reboot command's own output and its exit (255 as ssh drops) are expected.
            if let (StreamMsg::Exit { .. }, Some(s)) = (&m, self.wf.as_mut()) {
                s.push(
                    "… waiting for the server to come back",
                    workflow::LogKind::Info,
                );
            }
            self.dirty = true;
            return;
        }
        let Some(p) = self.pane.as_mut().filter(|p| p.id == id) else {
            return;
        };
        match m {
            StreamMsg::Line { text, .. } => {
                if p.lines.len() == PANE_LINES {
                    p.lines.pop_front();
                }
                p.lines.push_back(text);
            }
            StreamMsg::Exit { code, .. } => {
                p.done = Some(code);
                p.pid = None;
                let (then, reboot) = (p.then.clone(), p.reboot);
                if reboot {
                    // ssh drops (255) as the server goes down: that's the reboot happening.
                    let boot = self
                        .store
                        .probe
                        .value
                        .as_ref()
                        .map(|p| p.boot_id.clone())
                        .unwrap_or_default();
                    self.reboot_wait = Some((Instant::now(), boot));
                    if let Some(p) = self.pane.as_mut() {
                        p.lines
                            .push_back("… waiting for the server to come back".into());
                    }
                } else {
                    for k in then {
                        self.fetch(k);
                    }
                }
            }
        }
        self.dirty = true;
    }

    /// While rebooting: a probe with a new boot id means it's back.
    fn check_back(&mut self) {
        let Some((since, old)) = &self.reboot_wait else {
            return;
        };
        let Some(p) = &self.store.probe.value else {
            return;
        };
        if p.boot_id != *old && !old.is_empty() {
            let secs = since.elapsed().as_secs();
            self.reboot_wait = None;
            self.store.reset_boot();
            for k in [Kind::Host, Kind::Apt, Kind::Units, Kind::Docker] {
                self.fetch(k);
            }
            if let Some(s) = self.wf.as_mut() {
                s.after_reboot();
            }
            self.wf_auto();
            let msg = format!("✓ {} is back after {secs} s", self.remote.name);
            if let Some(pane) = self.pane.as_mut() {
                pane.lines.push_back(msg.clone());
            }
            self.toast(&msg);
        }
    }

    fn toast(&mut self, s: &str) {
        self.toast = Some((s.to_string(), Instant::now() + Duration::from_secs(4)));
        self.dirty = true;
    }

    fn view(&self) -> View<'_> {
        View {
            t: &self.theme,
            s: &self.store,
            cfg: &self.remote.cfg,
            name: &self.remote.name,
            cur: self.cursors[self.tab.index()],
            now: self.now_override.unwrap_or_else(jiff::Timestamp::now),
        }
    }

    fn rows(&self) -> usize {
        match self.tab {
            Tab::Workflows if self.wf.is_none() => self.wf_entries.len(),
            Tab::Workflows => 0,
            t => tabs::rows(t, &self.view()),
        }
    }

    fn on_key(&mut self, k: KeyEvent, now: Instant) {
        self.dirty = true;
        if self.cmdline.is_some() {
            self.cmdline_key(k, now);
            return;
        }
        // The chat takes raw keys (Backspace, any character) before the keymap, which knows
        // neither; boxes opened from the chat still come first.
        if self.chat.is_some()
            && self.pane.is_none()
            && self.chooser.is_none()
            && self.modal.is_none()
        {
            self.chat_key(k);
            return;
        }
        let Some(a) = self.keys.resolve(&k) else {
            return;
        };
        if let Some(p) = self.pane.as_mut() {
            let running = p.done.is_none();
            let len = p.lines.len();
            match a {
                Action::Interrupt if running => {
                    if let Some(pid) = p.pid {
                        let _ = kill(pid);
                        p.lines.push_back("■ stopping…".into());
                    }
                }
                Action::Esc | Action::Quit | Action::Enter if !running => self.pane = None,
                Action::Down => p.scroll = p.scroll.saturating_sub(1),
                Action::Up => p.scroll = (p.scroll + 1).min(len),
                Action::PageDown => p.scroll = p.scroll.saturating_sub(20),
                Action::PageUp => p.scroll = (p.scroll + 20).min(len),
                Action::Bottom => p.scroll = 0,
                Action::Top => p.scroll = len,
                _ if running => self.toast("running · C-c stops it"),
                _ => {}
            }
            return;
        }
        if let Some((title, choices)) = self.chooser.take() {
            // Digits are tab keys in the keymap; here they pick.
            let digit = match a {
                Action::Char(c) => c.to_digit(10),
                Action::Screen(id) => id.key().to_digit(10),
                _ => None,
            };
            if let Some(d) = digit
                && let Some((_, e)) = choices.get((d as usize).wrapping_sub(1))
            {
                let e = e.clone();
                self.apply(e, now);
                return;
            }
            if !matches!(a, Action::Esc | Action::Quit | Action::NextMatch) {
                self.chooser = Some((title, choices));
            }
            return;
        }
        if let Some(m) = self.modal.take() {
            match a {
                Action::Char('y') | Action::Enter if m.yes.is_some() => {
                    let effects = m.yes.map(|(_, e)| e).unwrap_or_default();
                    self.apply(effects, now);
                }
                // `n` is bound to "next match" globally.
                Action::Char('n') | Action::NextMatch | Action::Esc | Action::Quit => {}
                Action::Enter if m.yes.is_none() => {}
                _ => self.modal = Some(m),
            }
            return;
        }
        if self.tab == Tab::Workflows && self.wf_key(a, now) {
            return;
        }
        let n = self.rows();
        let cur = &mut self.cursors[self.tab.index()];
        match a {
            // As in sentry: q and Ctrl-C ask first, `:q` quits.
            Action::Quit | Action::Interrupt => {
                self.modal = Some(Modal {
                    title: "Quit".into(),
                    color: self.theme.dim,
                    lines: vec![Line::styled(
                        format!(
                            "Quit sentry-server? Nothing keeps running on {} after exit.",
                            self.remote.name
                        ),
                        self.theme.fg(),
                    )],
                    yes: Some(("quit".into(), vec![Effect::Quit])),
                })
            }
            Action::Command => self.cmdline = Some(String::new()),
            Action::Screen(id) => {
                if let Some(t) = Tab::ALL.into_iter().find(|t| t.key() == id.key()) {
                    self.enter(t, now);
                }
            }
            Action::NextScreen => {
                let i = (self.tab.index() + 1) % Tab::ALL.len();
                self.enter(Tab::ALL[i], now);
            }
            Action::PrevScreen => {
                let i = (self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
                self.enter(Tab::ALL[i], now);
            }
            Action::Down => *cur = (*cur + 1).min(n.saturating_sub(1)),
            Action::Up => *cur = cur.saturating_sub(1),
            Action::Top => *cur = 0,
            Action::Bottom => *cur = n.saturating_sub(1),
            Action::PageDown => *cur = (*cur + 10).min(n.saturating_sub(1)),
            Action::PageUp => *cur = cur.saturating_sub(10),
            Action::Help => {
                let lines = tabs::hints(self.tab, &self.view())
                    .into_iter()
                    .chain(super::actions::hints(self.tab))
                    .chain([
                        ("A", "ask Claude"),
                        ("1-5 0", "tabs (or Tab, h/l)"),
                        ("j/k", "move"),
                        (":", ":q quit · :r refresh · :<tab> · :wf <name>"),
                        ("q", "quit (asks)"),
                    ])
                    .map(|(k, d)| Line::styled(format!("{k:<8} {d}"), self.theme.fg()))
                    .collect();
                self.modal = Some(Modal {
                    title: format!("{} · keys", self.tab.name()),
                    color: self.theme.cyan,
                    lines,
                    yes: None,
                });
            }
            Action::Refresh => {
                let e = tabs::refresh(self.tab);
                self.apply(e, now);
            }
            Action::Check => {
                let e = tabs::check(self.tab);
                self.apply(e, now);
            }
            Action::Enter => {
                let e = tabs::enter(self.tab, &self.view());
                self.apply(e, now);
            }
            Action::Ask => {
                if !claude::available() {
                    self.toast("Claude Code isn't installed (or not on PATH)");
                } else {
                    let v = self.view();
                    match super::ask::ask_for(self.tab, &v, &self.remote, self.wf.as_ref()) {
                        Some(ask) => {
                            let text = ask.prompt();
                            self.modal = Some(self.consent(&text, AskTurn::First(ask)));
                        }
                        None => self.toast("nothing selected to ask about here"),
                    }
                }
            }
            Action::Char('a') => {
                let e = super::actions::custom(&self.view(), &self.remote);
                self.apply(e, now);
            }
            Action::Char('B') if self.tab == Tab::Overview => {
                let e = super::actions::reboot(&self.view(), &self.remote);
                self.apply(e, now);
            }
            Action::Char(c) => {
                let e = tabs::key(self.tab, c, &self.view(), &self.remote);
                self.apply(e, now);
            }
            _ => {}
        }
    }

    fn apply(&mut self, effects: Vec<Effect>, now: Instant) {
        for e in effects {
            match e {
                Effect::Fetch(k) => {
                    if k == Kind::Audit {
                        self.toast("auditing… (a few seconds)");
                    }
                    self.fetch(k);
                }
                Effect::Toast(s) => self.toast(&s),
                Effect::Quit => self.quit = true,
                Effect::Info(title, lines) => {
                    self.modal = Some(Modal {
                        title,
                        color: self.theme.cyan,
                        lines,
                        yes: None,
                    })
                }
                Effect::Goto(t) => self.enter(t, now),
                Effect::Wf(c) => self.wf_cmd(c),
                Effect::AskSend(turn) => self.ask_turn(turn),
                Effect::ChatRun(p) => self.chat_run(p),
                Effect::Confirm(m) => self.modal = Some(m),
                Effect::Choose(title, choices) => self.chooser = Some((title, choices)),
                Effect::Suspend(cmd, banner, then) => self.suspend = Some((cmd, banner, then)),
                Effect::Run(spec) => self.start_run(spec),
                Effect::Logs(title, cmd) => {
                    self.run_seq += 1;
                    let id = self.run_seq;
                    self.pane = Some(Pane {
                        id,
                        title,
                        cmd: cmd.display(),
                        lines: VecDeque::new(),
                        pid: None,
                        done: None,
                        started: Instant::now(),
                        scroll: 0,
                        then: Vec::new(),
                        reboot: false,
                    });
                    if !self.offline {
                        let tx = self.tx.clone();
                        std::thread::spawn(move || {
                            let res = cmd.output().map_err(|e| e.to_string());
                            let _ = tx.send(Ev::Text(id, res));
                        });
                    }
                }
                Effect::Expected(id, on) => {
                    match crate::server::audit::set_expected(&self.remote.name, &id, on) {
                        Ok(_) => {
                            if let Some(Some(r)) = self.store.report.value.as_mut() {
                                for f in r.findings.iter_mut().filter(|f| f.id == id) {
                                    f.expected = on;
                                }
                            }
                            self.toast(if on {
                                "marked expected"
                            } else {
                                "no longer expected"
                            });
                        }
                        Err(e) => self.toast(&format!("couldn't save: {e}")),
                    }
                }
            }
        }
        self.dirty = true;
    }

    /// Keys on the Workflows tab; true when handled.
    fn wf_key(&mut self, a: Action, _now: Instant) -> bool {
        let t = self.theme;
        let Some(s) = self.wf.as_ref() else {
            if let Action::Enter = a
                && let Some(e) = self.wf_entries.get(self.cursors[Tab::Workflows.index()])
            {
                let steps: Vec<String> = match &e.wf {
                    Ok(w) => w.steps.iter().map(|s| s.id.clone()).collect(),
                    Err(_) => Vec::new(),
                };
                let mut lines = vec![
                    Line::styled(
                        e.wf.as_ref()
                            .map(|w| w.description.clone())
                            .unwrap_or_default(),
                        t.fg(),
                    ),
                    Line::styled(steps.join(" → "), t.dim()),
                    Line::styled(
                        "Auto steps run right away; every other step waits for Enter.",
                        t.dim(),
                    ),
                ];
                if let Some(why) = e.blocked() {
                    lines.push(Line::styled(why, t.s(t.yellow)));
                }
                self.modal = Some(Modal {
                    title: format!("Start {} on {}", e.name, self.remote.name),
                    color: t.yellow,
                    lines,
                    yes: Some((
                        "start".into(),
                        vec![Effect::Wf(WfCmd::Begin(e.name.clone()))],
                    )),
                });
                return true;
            }
            return false;
        };
        let failed = matches!(s.next, Next::Stopped(_) | Next::Manual { failed: true, .. });
        let idx = s.next.idx();
        let title = idx.map(|i| s.title(i)).unwrap_or_default();
        let ask = |title: &str, line: String, label: &str, cmd: WfCmd, color| Modal {
            title: title.into(),
            color,
            lines: vec![Line::styled(line, t.fg())],
            yes: Some((label.into(), vec![Effect::Wf(cmd)])),
        };
        match a {
            Action::Enter if s.done() => self.wf_cmd(WfCmd::Close),
            Action::Enter => match s.next {
                Next::Reboot {
                    requested: false, ..
                } => {
                    self.modal = Some(Modal {
                        title: "Reboot the server".into(),
                        color: t.red,
                        lines: vec![
                            Line::styled(title, t.fg()),
                            Line::styled(
                                format!("$ sudo systemctl reboot   on {}", self.remote.name),
                                t.fg(),
                            ),
                            Line::styled(
                                "Everything on it stops until it's back; sentry-server waits here.",
                                t.s(t.yellow),
                            ),
                        ],
                        yes: Some(("reboot".into(), vec![Effect::Wf(WfCmd::Go)])),
                    })
                }
                _ => self.wf_cmd(WfCmd::Go),
            },
            Action::Char('s') => {
                let optional = idx.is_some_and(|i| s.wf.steps[i].optional);
                if optional {
                    self.wf_cmd(WfCmd::Skip(false));
                } else if idx.is_some() {
                    self.modal = Some(ask(
                        "Skip step",
                        format!("{title}: it isn't optional, later steps may expect it."),
                        "skip it",
                        WfCmd::Skip(true),
                        t.yellow,
                    ));
                }
            }
            Action::Char('d') if idx.is_some() => {
                self.modal = Some(ask(
                    "Done by hand",
                    format!("{title}: mark it done only if you've made sure of it yourself."),
                    "mark done",
                    WfCmd::Done,
                    t.yellow,
                ))
            }
            Action::Refresh if failed => self.wf_cmd(WfCmd::Retry),
            Action::Char('a') => {
                self.modal = Some(ask(
                    "Abandon workflow",
                    format!("Abandon {}? The server is left as it is now.", s.wf.name),
                    "abandon",
                    WfCmd::Abandon,
                    t.red,
                ))
            }
            Action::Char('L') => {
                if let Some((title, text)) = s.step_log() {
                    self.run_seq += 1;
                    self.pane = Some(Pane {
                        id: self.run_seq,
                        title,
                        cmd: String::new(),
                        lines: text.lines().map(str::to_string).collect(),
                        pid: None,
                        done: Some(0),
                        started: Instant::now(),
                        scroll: 0,
                        then: Vec::new(),
                        reboot: false,
                    });
                } else {
                    self.toast("no log for this step yet");
                }
            }
            _ => return false,
        }
        true
    }

    fn wf_cmd(&mut self, c: WfCmd) {
        let sudo = self.store.sudo.value;
        let r: Result<Option<Exec>, String> = match c {
            WfCmd::Begin(name) => match self.wf_entries.iter().find(|e| e.name == name) {
                Some(e) => match Session::begin(e, &self.remote) {
                    Ok(s) => {
                        self.wf = Some(s);
                        Ok(None)
                    }
                    Err(e) => Err(e.to_string()),
                },
                None => Err(format!("no workflow {name}")),
            },
            WfCmd::Close => {
                self.wf = None;
                if !self.offline {
                    self.wf_entries = workflow::list();
                }
                Ok(None)
            }
            c => match self.wf.as_mut() {
                None => Ok(None),
                Some(s) => match c {
                    WfCmd::Go => s.go(sudo),
                    WfCmd::Skip(force) => s.skip(force).map(|_| None),
                    WfCmd::Done => s.mark_done().map(|_| None),
                    WfCmd::Retry => s.retry().map(|_| None),
                    WfCmd::Abandon => {
                        s.abandon();
                        Ok(None)
                    }
                    WfCmd::Begin(_) | WfCmd::Close => Ok(None),
                },
            },
        };
        match r {
            Ok(Some(e)) => self.wf_exec(e),
            Ok(None) => {}
            Err(e) => self.toast(&e),
        }
        self.wf_auto();
        self.dirty = true;
    }

    /// Run the next auto step when the Workflows tab is open.
    fn wf_auto(&mut self) {
        if self.tab != Tab::Workflows {
            return;
        }
        let sudo = self.store.sudo.value;
        if let Some(e) = self.wf.as_mut().and_then(|s| s.auto(sudo)) {
            self.wf_exec(e);
        }
    }

    fn wf_exec(&mut self, e: Exec) {
        self.run_seq += 1;
        let id = self.run_seq;
        match e {
            Exec::Stream { cmd, idx } => {
                let mut pid = None;
                if !self.offline {
                    let tx = self.tx.clone();
                    match cmd.stream(move |m| {
                        let _ = tx.send(Ev::Run(id, m));
                    }) {
                        Ok(p) => pid = Some(p),
                        Err(err) => {
                            if let Some(s) = self.wf.as_mut() {
                                s.push(format!("✗ {err}"), workflow::LogKind::Err);
                                s.on_exit(idx, 127);
                            }
                            return;
                        }
                    }
                }
                if let Some(s) = self.wf.as_mut() {
                    s.live = Some(workflow::Live {
                        id,
                        idx,
                        pid,
                        started: Instant::now(),
                    });
                }
            }
            Exec::Tty { cmd, idx } => {
                self.suspend_step = Some(idx);
                let banner = format!("sentry-server · workflow step on {}", self.remote.name);
                self.suspend = Some((cmd, banner, Vec::new()));
            }
            Exec::Reboot { cmd } => {
                let old = self
                    .wf
                    .as_ref()
                    .and_then(|s| {
                        s.next
                            .idx()
                            .and_then(|i| s.run.state.steps[i].boot_id.clone())
                    })
                    .unwrap_or_default();
                self.wf_reboot_id = Some(id);
                self.reboot_wait = Some((Instant::now(), old));
                if !self.offline {
                    let tx = self.tx.clone();
                    let _ = cmd.stream(move |m| {
                        let _ = tx.send(Ev::Run(id, m));
                    });
                }
            }
        }
    }

    fn cmdline_key(&mut self, k: KeyEvent, now: Instant) {
        use ratatui::crossterm::event::KeyCode;
        let Some(buf) = self.cmdline.as_mut() else {
            return;
        };
        match k.code {
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Backspace => {
                if buf.pop().is_none() {
                    self.cmdline = None;
                }
            }
            KeyCode::Esc => self.cmdline = None,
            KeyCode::Enter => {
                let c = self.cmdline.take().unwrap_or_default();
                self.command(c.trim(), now);
            }
            _ => {}
        }
        self.dirty = true;
    }

    /// `:` commands, as in sentry.
    fn command(&mut self, c: &str, now: Instant) {
        let mut parts = c.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("q" | "q!" | "quit" | "qa"), _) => self.quit = true,
            (Some("refresh" | "r"), _) => {
                let e = tabs::refresh(self.tab);
                self.apply(e, now);
            }
            (Some("help" | "h"), _) => {
                let k = ratatui::crossterm::event::KeyEvent::from(
                    ratatui::crossterm::event::KeyCode::Char('?'),
                );
                self.on_key(k, now);
            }
            (Some("audit"), Some("now")) => self.apply(vec![Effect::Fetch(Kind::Audit)], now),
            (Some("workflow" | "wf"), name) => {
                self.enter(Tab::Workflows, now);
                if let Some(n) = name {
                    if self.wf.is_some() {
                        self.toast("a workflow is already in progress");
                    } else if let Some(i) = self.wf_entries.iter().position(|e| e.name == n) {
                        self.cursors[Tab::Workflows.index()] = i;
                        let enter = ratatui::crossterm::event::KeyEvent::from(
                            ratatui::crossterm::event::KeyCode::Enter,
                        );
                        self.on_key(enter, now);
                    } else {
                        self.toast(&format!("no workflow {n}"));
                    }
                }
            }
            (Some(name), None) => {
                let name = name.to_ascii_lowercase();
                match Tab::ALL.into_iter().find(|t| {
                    let n = t.name().to_ascii_lowercase();
                    n == name || (name.len() >= 3 && n.starts_with(&name))
                }) {
                    Some(t) => self.enter(t, now),
                    None => self.toast(&format!("unknown command :{c}")),
                }
            }
            _ if c.is_empty() => {}
            _ => self.toast(&format!("unknown command :{c}")),
        }
    }

    fn consent(&self, text: &str, turn: AskTurn) -> Modal {
        let t = self.theme;
        let mut lines = vec![
            Line::styled(
                "Sent to Claude through your Claude Code login (Anthropic):",
                t.fg(),
            ),
            Line::raw(""),
        ];
        let shown: Vec<&str> = text.lines().collect();
        for l in shown.iter().take(22) {
            lines.push(Line::styled(format!("  {l}"), t.dim()));
        }
        if shown.len() > 22 {
            lines.push(Line::styled(
                format!("  … {} more lines", shown.len() - 22),
                t.dim(),
            ));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!(
                "Claude may run read-only commands on {} through `sentry-server exec` (nothing \
                 that changes it); it can't use ssh. Whatever it proposes, you run here after a \
                 confirm box.",
                self.remote.name
            ),
            t.s(t.yellow),
        ));
        Modal {
            title: "Ask Claude".into(),
            color: t.mag,
            lines,
            yes: Some(("send".into(), vec![Effect::AskSend(turn)])),
        }
    }

    fn ask_turn(&mut self, turn: AskTurn) {
        let (prompt, shown, resume) = match turn {
            AskTurn::First(ask) => {
                let p = ask.prompt();
                let q = ask.question.lines().next().unwrap_or("").to_string();
                self.chat = Some(Chat::new(ask));
                (p, q, None)
            }
            AskTurn::Follow(text) => {
                let session = self.chat.as_ref().and_then(|c| c.session.clone());
                (text.clone(), text, session)
            }
        };
        let (os, kernel) = self.store.host.value.clone().unwrap_or_default();
        let profile = super::ask::profile(&self.remote, &os, &kernel);
        let cmd = claude::turn_cmd_with(&prompt, resume.as_deref(), &profile);
        self.run_seq += 1;
        let id = self.run_seq;
        if self.offline {
            if let Some(c) = self.chat.as_mut() {
                c.push(chatmod::Kind::You, shown);
            }
            return;
        }
        let tx = self.tx.clone();
        let r = cmd.stream(move |m| {
            let _ = tx.send(Ev::Run(id, m));
        });
        let Some(c) = self.chat.as_mut() else { return };
        match r {
            Ok(pid) => c.begin_turn(&shown, id, pid),
            Err(e) => c.push(chatmod::Kind::Err, format!("couldn't start claude: {e}")),
        }
    }

    fn chat_key(&mut self, k: KeyEvent) {
        use ratatui::crossterm::event::{KeyCode, KeyModifiers};
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let t = self.theme;
        let server = self.remote.name.clone();
        let Some(c) = self.chat.as_mut() else { return };
        if c.picking {
            c.picking = false;
            if let KeyCode::Char(d @ '1'..='9') = k.code
                && let Some(p) = c.proposals.get(d as usize - '1' as usize).cloned()
            {
                self.modal = Some(proposal_modal(&t, &server, p));
            }
            return;
        }
        let idle = c.input.is_empty() && !c.busy();
        match k.code {
            KeyCode::Char('c') if ctrl => {
                if let Some((_, pid)) = c.live {
                    let _ = kill(pid);
                    c.push(chatmod::Kind::Info, "stopped");
                }
                if let Some((_, pid, _)) = &c.job {
                    let _ = kill(*pid);
                }
            }
            KeyCode::Char('r') if idle && !c.proposals.is_empty() => {
                if c.proposals.len() == 1 {
                    let p = c.proposals[0].clone();
                    self.modal = Some(proposal_modal(&t, &server, p));
                } else {
                    c.picking = true;
                }
            }
            KeyCode::Char('s') if idle && c.offer.is_some() => {
                let text = c.offer.take().unwrap_or_default();
                self.modal = Some(self.consent(&text, AskTurn::Follow(text.clone())));
            }
            KeyCode::Char('k') if ctrl => c.scroll += 1,
            KeyCode::Char('j') if ctrl => c.scroll = c.scroll.saturating_sub(1),
            KeyCode::PageUp => c.scroll += 10,
            KeyCode::PageDown => c.scroll = c.scroll.saturating_sub(10),
            KeyCode::Esc => {
                if let Some((_, pid)) = c.live {
                    let _ = kill(pid);
                }
                if let Some((_, pid, _)) = &c.job {
                    let _ = kill(*pid);
                }
                self.chat = None;
            }
            KeyCode::Enter if !c.running() && !c.input.trim().is_empty() => {
                let text = std::mem::take(&mut c.input);
                self.modal = Some(self.consent(&text, AskTurn::Follow(text.clone())));
            }
            KeyCode::Backspace => {
                c.input.pop();
            }
            KeyCode::Char(ch) if !ctrl && !c.busy() => c.input.push(ch),
            _ => {}
        }
        self.dirty = true;
    }

    /// A proposal, confirmed: run it on the server, its output into the chat.
    fn chat_run(&mut self, p: Proposed) {
        if self.wf.as_ref().is_some_and(|s| s.live.is_some()) {
            self.toast("a workflow step is running: wait for it to finish");
            return;
        }
        let password = p.cmd.contains("sudo")
            && self.store.sudo.value == Some(crate::server::remote::SudoMode::Password);
        let cmd = self.remote.sh(&p.cmd).timeout(None);
        if password {
            if let Some(c) = self.chat.as_mut() {
                c.push(
                    chatmod::Kind::Tool,
                    format!("$ {}  (terminal handed over for sudo)", p.cmd),
                );
            }
            self.suspend = Some((
                cmd,
                format!("sentry-server · {} on {}", p.cmd, self.remote.name),
                vec![Kind::Units, Kind::Docker],
            ));
            return;
        }
        self.run_seq += 1;
        let id = self.run_seq;
        let r = if self.offline {
            Ok(0)
        } else {
            let tx = self.tx.clone();
            cmd.stream(move |m| {
                let _ = tx.send(Ev::Run(id, m));
            })
        };
        let Some(c) = self.chat.as_mut() else { return };
        c.push(chatmod::Kind::Tool, format!("$ {}", p.cmd));
        match r {
            Ok(pid) => {
                c.job = Some((
                    id,
                    pid,
                    Job::Proposal {
                        cmd: p.cmd,
                        output: String::new(),
                        changes: true,
                    },
                ))
            }
            Err(e) => c.push(chatmod::Kind::Err, format!("couldn't start it: {e}")),
        }
    }

    fn start_run(&mut self, spec: RunSpec) {
        self.run_seq += 1;
        let id = self.run_seq;
        let mut pane = Pane {
            id,
            title: spec.title,
            cmd: spec.cmd.display(),
            lines: VecDeque::new(),
            pid: None,
            done: None,
            started: Instant::now(),
            scroll: 0,
            then: spec.then,
            reboot: spec.reboot,
        };
        if !self.offline {
            let tx = self.tx.clone();
            match spec.cmd.stream(move |m| {
                let _ = tx.send(Ev::Run(id, m));
            }) {
                Ok(pid) => pane.pid = Some(pid),
                Err(e) => {
                    pane.lines.push_back(format!("✗ {e}"));
                    pane.done = Some(-1);
                }
            }
        }
        self.pane = Some(pane);
    }

    pub fn take_suspend(&mut self) -> Option<(Cmd, String)> {
        let (cmd, banner, then) = self.suspend.take()?;
        // Re-read afterwards whatever the command changed.
        for k in then {
            self.fetch(k);
        }
        Some((cmd, banner))
    }

    pub fn after_suspend(&mut self, status: Result<ExitStatus, ExecError>) {
        if let Some(idx) = self.suspend_step.take()
            && let Some(s) = self.wf.as_mut()
        {
            let code = match &status {
                Ok(st) => st.code().unwrap_or(-1),
                Err(_) => -1,
            };
            s.on_exit(idx, code);
            self.wf_auto();
            return;
        }
        match status {
            Ok(s) if s.success() => self.toast("done"),
            Ok(s) => self.toast(&format!("exited {}", s.code().unwrap_or(-1))),
            Err(e) => self.toast(&e.to_string()),
        }
    }

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
        let [top, tabs_row, rule, body, keyrule, keybar] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);
        self.draw_top(f, top);
        self.draw_tabs(f, tabs_row);
        for r in [rule, keyrule] {
            f.render_widget(
                Paragraph::new("─".repeat(r.width as usize)).style(t.s(t.border)),
                r,
            );
        }
        let body = Rect {
            y: body.y + 1,
            height: body.height.saturating_sub(1),
            ..body
        };
        let body = match self.wf.as_ref().filter(|s| !s.done()) {
            Some(s) if self.tab != Tab::Workflows => {
                let [ban, rest] =
                    Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(body);
                let step = s
                    .next
                    .idx()
                    .map(|i| format!("step {}/{} {}", i + 1, s.wf.steps.len(), s.title(i)))
                    .unwrap_or_default();
                f.render_widget(
                    Paragraph::new(Line::from(vec![
                        Span::styled(
                            format!(" ↻ {} · {step} · {}   ", s.wf.name, s.state_word()),
                            t.s(t.yellow),
                        ),
                        Span::styled("press 0 to continue", t.dim()),
                    ]))
                    .style(Style::new().bg(t.banner_bg)),
                    ban,
                );
                rest
            }
            _ => body,
        };
        match (self.tab, &self.wf) {
            (Tab::Workflows, Some(s)) => super::wftab::draw_session(f, body, &t, s),
            (Tab::Workflows, None) => super::wftab::draw_list(
                f,
                body,
                &t,
                &self.wf_entries,
                self.cursors[Tab::Workflows.index()],
            ),
            _ => tabs::draw(f, body, self.tab, &self.view()),
        }
        self.draw_keybar(f, keybar);
        if let Some(c) = &self.chat {
            chatmod::draw(f, body, &t, c);
        }
        if let Some(p) = &self.pane {
            draw_pane(f, body, &t, p);
        }
        if let Some((title, choices)) = &self.chooser {
            let lines = choices
                .iter()
                .enumerate()
                .map(|(i, (label, _))| Line::styled(format!("{}  {label}", i + 1), t.fg()))
                .collect();
            let m: Modal = Modal {
                title: title.clone(),
                color: t.cyan,
                lines,
                yes: None,
            };
            modal::draw(f, area, &t, &m);
        }
        if let Some(m) = &self.modal {
            modal::draw(f, area, &t, m);
        }
    }

    fn draw_top(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        let s = &self.store;
        let mut spans = vec![
            Span::styled(
                " sentry-server ",
                Style::new()
                    .fg(t.ink)
                    .bg(t.cyan)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            ),
            Span::styled(format!("  {}", self.remote.name), t.fg()),
        ];
        if let Some((os, kernel)) = &s.host.value {
            spans.push(Span::styled(format!("  {os}  {kernel}"), t.dim()));
        }
        if let Some(p) = &s.probe.value {
            spans.push(Span::styled(
                format!("  up {}", crate::fmt::uptime(p.uptime_s)),
                t.dim(),
            ));
        }
        let state = match &s.unreachable {
            Some(_) => Span::styled("○ unreachable · retrying", t.s(t.red)),
            None if s.rebooted() => Span::styled("● rebooted", t.s(t.mag)),
            None if s.probe.value.is_some() || s.host.value.is_some() => {
                Span::styled("● connected", t.s(t.green))
            }
            None => Span::styled("○ connecting…", t.dim()),
        };
        let left: usize = spans.iter().map(|s| s.width()).sum();
        let pad = (area.width as usize).saturating_sub(left + state.width() + 1);
        spans.push(Span::raw(" ".repeat(pad)));
        spans.push(state);
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn draw_tabs(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        let mut spans = Vec::new();
        for tab in Tab::ALL {
            let active = tab == self.tab;
            let style = if active {
                Style::new().bg(t.fg)
            } else {
                Style::new()
            };
            let (fg, kc) = if active {
                (t.ink, t.ink)
            } else {
                (t.fg, t.dim)
            };
            spans.push(Span::styled(format!(" {}", tab.key()), style.fg(kc)));
            spans.push(Span::styled(format!(" {}", tab.name()), style.fg(fg)));
            if let Some((b, c)) = tabs::badge(tab, &self.view()) {
                spans.push(Span::styled(b, style.fg(if active { t.ink } else { c })));
            }
            spans.push(Span::styled(" ", style));
            spans.push(Span::raw(" "));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn draw_keybar(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        if let Some(buf) = &self.cmdline {
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(format!(":{buf}"), t.fg()),
                    Span::styled("▏", t.s(t.cyan)),
                ])),
                area,
            );
            return;
        }
        if let Some((msg, _)) = &self.toast {
            f.render_widget(
                Paragraph::new(Span::styled(format!(" {msg}"), t.s(t.cyan))),
                area,
            );
            return;
        }
        let hints: Vec<(&str, &str)> = if let Some(p) = &self.pane {
            if p.done.is_some() {
                vec![("Esc", "close"), ("j/k", "scroll"), ("G", "end")]
            } else {
                vec![("C-c", "stop it"), ("j/k", "scroll")]
            }
        } else if let Some(c) = self.chat.as_ref().filter(|_| self.modal.is_none()) {
            chatmod::keys(c)
        } else if self.chooser.is_some() {
            vec![("1-9", "choose"), ("Esc", "cancel")]
        } else if self.modal.as_ref().is_some_and(|m| m.yes.is_some()) {
            vec![("y", "confirm"), ("n", "cancel")]
        } else {
            let mut h = tabs::hints(self.tab, &self.view());
            if self.tab == Tab::Workflows {
                h = match &self.wf {
                    None => vec![("j/k", "select"), ("Enter", "start")],
                    Some(s) if s.done() => vec![("Enter", "close")],
                    Some(_) => vec![
                        ("Enter", "run"),
                        ("s", "skip"),
                        ("a", "abandon"),
                        ("L", "log"),
                    ],
                };
            }
            h.extend(super::actions::hints(self.tab));
            if claude::available() {
                h.push(("A", "ask Claude"));
            }
            h.extend([("?", "help"), ("q", "quit")]);
            h
        };
        // Too wide: drop the tab's own hints from the end, never the global ones (A, ?, q)
        // that end the list. Chips are ` k ` + ` d` + two spaces, as in sentry.
        let mut hints = hints;
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
        while width(&hints) > area.width as usize && hints.len() > globals {
            hints.remove(hints.len() - globals - 1);
        }
        let mut spans = Vec::new();
        for (k, d) in hints {
            spans.extend(chip(t, k, d, t.dim));
            spans.push(Span::raw("  "));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }
}

impl crate::tui::Ui for App {
    type Ev = Ev;
    fn start(&mut self, now: Instant) {
        App::start(self, now);
    }
    fn dirty(&self) -> bool {
        self.dirty
    }
    fn draw(&mut self, f: &mut Frame) {
        App::draw(self, f);
        self.dirty = false;
    }
    fn take_suspend(&mut self) -> Option<(Cmd, String)> {
        App::take_suspend(self)
    }
    fn after_suspend(&mut self, status: Result<ExitStatus, ExecError>) {
        App::after_suspend(self, status);
    }
    fn quitting(&self) -> bool {
        self.quit
    }
    fn shutdown(&mut self) {
        // Don't leave a streamed command running on the server.
        if let Some(pid) = self.pane.as_ref().and_then(|p| p.pid) {
            let _ = kill(pid);
        }
        if let Some(pid) = self
            .wf
            .as_ref()
            .and_then(|s| s.live.as_ref())
            .and_then(|l| l.pid)
        {
            let _ = kill(pid);
        }
        if let Some((_, pid)) = self.chat.as_ref().and_then(|c| c.live) {
            let _ = kill(pid);
        }
    }
    fn next_due(&self, now: Instant) -> Instant {
        App::next_due(self, now)
    }
    fn on_event(&mut self, ev: Ev, now: Instant) {
        App::on_event(self, ev, now);
    }
    fn tick(&mut self, now: Instant) {
        App::tick(self, now);
    }
}

fn kill(pid: u32) -> std::io::Result<()> {
    let pid = rustix::process::Pid::from_raw(pid as i32)
        .ok_or_else(|| std::io::Error::other("bad pid"))?;
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).map_err(std::io::Error::from)
}

#[cfg(test)]
impl App {
    pub fn set_wf_entries(&mut self, e: Vec<Entry>) {
        self.wf_entries = e;
    }
    pub fn chat_mut(&mut self) -> Option<&mut Chat> {
        self.chat.as_mut()
    }
}

#[cfg(test)]
pub fn kill_for_test(pid: u32) {
    let _ = kill(pid);
}

fn proposal_modal(t: &Theme, server: &str, p: Proposed) -> Modal {
    let mut lines = vec![
        Line::styled(format!("why: {}", p.why), t.fg()),
        Line::raw(""),
        Line::styled(format!("$ {}", p.cmd), t.fg()),
        Line::styled(
            format!("on {server}, as your login (sudo where the command says so)"),
            t.dim(),
        ),
        Line::styled(
            "The output goes to the chat; s sends it back to Claude.",
            t.dim(),
        ),
    ];
    if let Some(r) = claude::risky(&p.cmd) {
        lines.push(Line::styled(format!("Careful: {r}."), t.s(t.red)));
    }
    Modal {
        title: "Run Claude's proposal".into(),
        color: if claude::risky(&p.cmd).is_some() {
            t.red
        } else {
            t.yellow
        },
        lines,
        yes: Some(("run".into(), vec![Effect::ChatRun(p)])),
    }
}

fn draw_pane(f: &mut Frame, area: Rect, t: &Theme, p: &Pane) {
    let (state, color) = match p.done {
        None => (
            format!("running {} s", p.started.elapsed().as_secs()),
            t.yellow,
        ),
        Some(0) => ("done".to_string(), t.green),
        Some(c) => (format!("exit {c}"), t.red),
    };
    let inner = widgets::overlay(f, area, t, &format!("{} · {state}", p.title), color);
    let [cmd, body] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(inner);
    f.render_widget(
        Paragraph::new(Span::styled(
            widgets::trunc(&format!("$ {}", p.cmd), cmd.width as usize),
            t.dim(),
        )),
        cmd,
    );
    let h = body.height as usize;
    let end = p.lines.len().saturating_sub(p.scroll);
    let start = end.saturating_sub(h);
    let lines: Vec<Line> = p
        .lines
        .iter()
        .skip(start)
        .take(end - start)
        .map(|l| Line::styled(widgets::trunc(l, body.width as usize), t.fg()))
        .collect();
    f.render_widget(Paragraph::new(lines), body);
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

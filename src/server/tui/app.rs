//! State, keys, refresh schedule and the frame around the tabs.

use std::collections::{BTreeMap, VecDeque};
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
use super::planview;
use super::tabs::{self, View};
use super::{Ev, Tab};
use crate::claude::{self, Ask, Proposed};
use crate::exec::{Cmd, ExecError, StreamMsg};
use crate::server::maint::plan::{PlanDoc, PlanStatus};
use crate::server::remote::{Remote, SudoMode};
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
    /// Hand the terminal to a command (sudo password prompts), then refresh. `true`: it's a
    /// reboot, so wait for the server to come back afterwards.
    Suspend(Cmd, String, Vec<Kind>, bool),
    /// Read-only output, fetched once, shown in the scrollable pane.
    Logs(String, Cmd),
    /// Pick one of several (digits 1-9).
    Choose(String, Vec<Choice>),
    /// Workflow actions.
    Wf(WfCmd),
    /// Read what needs root, with the terminal handed over for the password (after a confirm).
    Inventory,
    /// Run the reads Claude asked for with sudo (after a confirm), and send it the output.
    SudoReads(Vec<Vec<String>>, ReadsFor),
    /// The user skipped the reads a plan waits for: Claude writes it without them.
    ReadsSkipped,
    /// Open an item's plan in the Plan view.
    PlanOpen(String),
    /// Open the maintenance log, marking this item's entries.
    LogOpen(Option<String>),
    /// Claude writes the plan (after the confirm box): item, the new plan, the request.
    PlanWrite(String, PlanDoc, String),
    /// Look at a maintenance item again later (`z`).
    Snooze(String, jiff::civil::Date),
    /// Ask for an optional note, then save the plan (`p`).
    PlanNote(String, PlanDoc),
    /// Drop an item's plan (`x`, after a confirm).
    PlanDrop(String),
    /// Open server_config.yaml in $EDITOR, then reload it.
    EditConfig,
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

/// Where the answer to read requests goes back to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReadsFor {
    Chat,
    Plan,
}

/// A workflow's `[vars]` being asked for, one at a time, before it starts.
struct VarInput {
    workflow: String,
    /// (name, prompt, default), in the order asked.
    asks: Vec<(String, String, Option<String>)>,
    values: BTreeMap<String, String>,
    buf: String,
    /// Why the last answer wasn't taken.
    note: Option<String>,
}

impl VarInput {
    fn current(&self) -> Option<&(String, String, Option<String>)> {
        self.asks.get(self.values.len())
    }
}

#[derive(Clone, Debug)]
pub enum WfCmd {
    /// Start it; its vars are asked for first, unless given.
    Begin(String),
    /// Start it from a maintenance item: its vars default to the item's values, and the run
    /// is logged as a change to the item when it ends.
    BeginPrefilled(
        String,
        BTreeMap<String, String>,
        Option<crate::server::maint::Change>,
    ),
    BeginWith(String, BTreeMap<String, String>),
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
    cursors: [usize; 7],
    modal: Option<Modal>,
    /// What answering no (n, Esc) to a box does, for the box with that title (usually none).
    modal_no: Option<(String, Vec<Effect>)>,
    toast: Option<(String, Instant)>,
    sched: Sched,
    pane: Option<Pane>,
    chooser: Option<(String, Vec<Choice>)>,
    suspend: Option<(Cmd, String, Vec<Kind>)>,
    /// The suspended command reboots the server.
    suspend_reboot: bool,
    /// The suspended command is the inventory read (`I`).
    suspend_inventory: bool,
    /// When the last inventory was read.
    inventory_at: Option<jiff::Timestamp>,
    /// The maintenance change the running workflow makes (logged when it ends).
    wf_change: Option<crate::server::maint::Change>,
    /// The run already written to the maintenance log.
    wf_logged: Option<std::path::PathBuf>,
    /// When the last maintenance run ended (a read with sudo before it is out of date).
    last_change_at: Option<jiff::Timestamp>,
    /// After the log note: offer to read the server again (the run changed what was read).
    offer_reread: bool,
    /// The log entry waiting for its note, and the note typed so far.
    log_note: Option<(crate::server::maint::log::LogEntry, String)>,
    /// Tests: the last entry written with a note.
    pub last_log: Option<crate::server::maint::log::LogEntry>,
    /// The suspended command edits the config (reload it afterwards).
    suspend_edit: bool,
    /// The open chat is an assessment (its follow-ups keep the web and notes access).
    chat_assess: bool,
    /// The item it assesses (its answer is saved when a turn ends).
    assess_item: Option<String>,
    /// A plan waiting for its note: (item, plan, the note typed so far).
    plan_note: Option<(String, PlanDoc, String)>,
    /// Claude writing a plan, in the background.
    writer: Option<planview::Writer>,
    /// The Plan view: the item shown, and lines scrolled from the top.
    plan_view: Option<(String, usize)>,
    /// What to change in the plan (`r` in the Plan view), being typed.
    revise_input: Option<String>,
    /// The Log view (`v` on Maintenance, `:log`).
    pub log_view: Option<planview::LogView>,
    /// The suspended command runs Claude's read requests.
    suspend_reads: Option<(Vec<Vec<String>>, ReadsFor)>,
    run_seq: u64,
    /// Rebooting: since when, and the boot id it had.
    reboot_wait: Option<(Instant, String)>,
    /// The workflow run in progress on this server.
    pub wf: Option<Session>,
    wf_entries: Vec<Entry>,
    /// Where they come from (shown on the tab).
    wf_dir: String,
    /// A step running with the terminal handed over, and where its output is captured.
    suspend_step: Option<(usize, String)>,
    /// The stream id of a workflow's reboot command.
    wf_reboot_id: Option<u64>,
    /// A workflow reboot with the terminal handed over: the boot id it had.
    reboot_old: Option<String>,
    chat: Option<Chat>,
    /// The `:` command line being typed.
    cmdline: Option<String>,
    /// A workflow's vars being asked for.
    var_input: Option<VarInput>,
    /// Each tab's `/` filter, and whether it's being typed.
    filters: [String; 7],
    filtering: bool,
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
            remote: remote.with_inventory(),
            tx,
            theme: Theme::detect(),
            keys,
            store: Store::default(),
            tab: Tab::Overview,
            cursors: [0; 7],
            modal: None,
            modal_no: None,
            toast: None,
            sched: Sched::default(),
            pane: None,
            chooser: None,
            suspend: None,
            suspend_reboot: false,
            suspend_inventory: false,
            inventory_at: None,
            wf_change: None,
            wf_logged: None,
            last_change_at: None,
            offer_reread: false,
            log_note: None,
            last_log: None,
            suspend_edit: false,
            chat_assess: false,
            assess_item: None,
            plan_note: None,
            writer: None,
            plan_view: None,
            revise_input: None,
            log_view: None,
            suspend_reads: None,
            run_seq: 0,
            reboot_wait: None,
            wf: None,
            wf_entries: Vec::new(),
            wf_dir: "~/.config/sentry/server-workflows/".into(),
            suspend_step: None,
            wf_reboot_id: None,
            reboot_old: None,
            chat: None,
            cmdline: None,
            var_input: None,
            filters: Default::default(),
            filtering: false,
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
            self.inventory_at =
                crate::server::inventory::load(&self.remote.name).map(|c| c.fetched_at);
            self.store.upstream_at =
                crate::server::maint::upstream::load(&self.remote.name).map(|c| c.fetched_at);
            self.store.maint_state = crate::server::maint::load_state(&self.remote.name);
            crate::server::maint::plan::migrate(&self.remote.name);
            self.store.plans = crate::server::maint::plan::list(&self.remote.name);
            self.last_change_at = crate::server::maint::log::list(&self.remote.name)
                .first()
                .and_then(|e| e.head.ended.or(e.head.started));
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
            Tab::Maint => {
                self.fetch(Kind::Maint);
                self.fetch(Kind::Docker);
                // Upstream changes slowly: looked up again at most daily without `c`.
                let stale = self
                    .store
                    .upstream_at
                    .is_none_or(|at| jiff::Timestamp::now().as_second() - at.as_second() > 86400);
                if stale && !self.cfg_items_empty() {
                    self.fetch(Kind::Upstream);
                }
            }
            Tab::Workflows => {
                if !self.offline {
                    self.load_wf_entries();
                }
                if let Some(s) = self.wf.as_mut() {
                    s.armed = true;
                }
            }
        }
        self.tick(now);
        self.dirty = true;
    }

    fn cfg_items_empty(&self) -> bool {
        self.remote.cfg.maintenance.items.is_empty()
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
                if k == Kind::Upstream && res.is_ok() {
                    self.toast("newer versions looked up");
                    self.fetch(Kind::Maint);
                }
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
        if let Some(w) = self.writer.as_mut()
            && w.live.is_some_and(|(wid, _)| wid == id)
        {
            match m {
                StreamMsg::Line {
                    stderr: false,
                    text,
                } => {
                    for e in claude::parse_line(&text) {
                        w.on_event(e);
                    }
                }
                StreamMsg::Line { .. } => {}
                StreamMsg::Exit { code, .. } => {
                    w.live = None;
                    if w.answer.is_none() && w.err.is_none() && code != 0 {
                        w.err = Some(format!("claude exited with {code}"));
                    }
                    self.writer_turn_ended();
                }
            }
            self.dirty = true;
            return;
        }
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
                StreamMsg::Exit { code, .. } => {
                    c.on_exit(code);
                    self.save_assessment();
                    self.offer_reads(ReadsFor::Chat);
                }
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
                    if s.sudo_refused() {
                        // sudo changed under us: r now retries with the terminal.
                        self.fresh_sudo();
                    }
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
            filter: Some(self.filters[self.tab.index()].as_str())
                .filter(|f| !f.is_empty() && tabs::filterable(self.tab)),
            inventory: self
                .inventory_at
                .filter(|_| self.store.sudo.value == Some(SudoMode::Password)),
            inventory_stale: self
                .inventory_at
                .zip(self.last_change_at)
                .is_some_and(|(read, changed)| read < changed),
            upstream: self.store.upstream_at,
            planning: self
                .writer
                .as_ref()
                .filter(|w| w.running())
                .map(|w| w.item.clone()),
            plans: &self.store.plans,
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
        if self.filtering {
            self.filter_key(k);
            return;
        }
        if self.var_input.is_some() {
            self.var_key(k);
            return;
        }
        if self.plan_note.is_some() {
            self.plan_note_key(k);
            return;
        }
        if self.revise_input.is_some() {
            self.revise_key(k);
            return;
        }
        if self.log_note.is_some() && self.modal.is_none() {
            self.log_note_key(k);
            return;
        }
        if self.log_view.is_some() && self.modal.is_none() {
            self.log_view_key(k);
            return;
        }
        if self.plan_view.is_some()
            && self.modal.is_none()
            && self.chooser.is_none()
            && self.pane.is_none()
        {
            self.plan_view_key(k, now);
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
                    self.modal_no = None;
                    let effects = m.yes.map(|(_, e)| e).unwrap_or_default();
                    self.apply(effects, now);
                }
                // `n` is bound to "next match" globally.
                Action::Char('n') | Action::NextMatch | Action::Esc | Action::Quit => {
                    if let Some((title, effects)) = self.modal_no.take()
                        && title == m.title
                    {
                        self.apply(effects, now);
                    }
                }
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
            Action::Filter if tabs::filterable(self.tab) => self.filtering = true,
            Action::Filter => self.toast("nothing to filter on this tab"),
            Action::Esc if !self.filters[self.tab.index()].is_empty() => {
                self.filters[self.tab.index()].clear();
            }
            // Rows are already filtered, so n/N just walk them with wrap-around.
            Action::NextMatch if n > 0 => *cur = (*cur + 1) % n,
            Action::PrevMatch if n > 0 => *cur = (*cur + n - 1) % n,
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
                        ("I", "read what needs root, once, with your sudo password"),
                        ("1-5 0", "tabs (or Tab, h/l)"),
                        ("j/k", "move"),
                        ("/", "filter (Esc clears) · n/N next/prev"),
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
                    let entry = self.wf_entries.get(self.cursors[Tab::Workflows.index()]);
                    match super::ask::ask_for(self.tab, &v, &self.remote, self.wf.as_ref(), entry) {
                        Some(ask) => {
                            let text = ask.prompt();
                            self.modal = Some(self.consent(&text, AskTurn::First(ask)));
                        }
                        None => {
                            let why = super::ask::nothing_here(self.tab, &v);
                            self.toast(why);
                        }
                    }
                }
            }
            Action::Char('I') => {
                let m = self.fresh_sudo();
                self.inventory_box(m);
            }
            Action::Char('a') => {
                self.fresh_sudo();
                let e = super::actions::custom(&self.view(), &self.remote);
                self.apply(e, now);
            }
            Action::Char('B') if self.tab == Tab::Overview => {
                self.fresh_sudo();
                let e = super::actions::reboot(&self.view(), &self.remote);
                self.apply(e, now);
            }
            Action::Char(c) => {
                if super::actions::uses_root(self.tab, c) {
                    self.fresh_sudo();
                }
                let e = tabs::key(self.tab, c, &self.view(), &self.remote);
                self.apply(e, now);
            }
            _ => {}
        }
    }

    pub fn apply(&mut self, effects: Vec<Effect>, now: Instant) {
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
                Effect::PlanNote(id, plan) => {
                    self.plan_note = Some((id, plan, String::new()));
                }
                Effect::PlanDrop(id) => {
                    if let Some(doc) = self.store.plans.remove(&id)
                        && !self.offline
                    {
                        let _ = crate::server::maint::plan::close(&doc, PlanStatus::Dropped);
                    }
                    self.plan_view = None;
                    self.toast(&format!("{id}: plan dropped (kept in plans/done/)"));
                }
                Effect::PlanOpen(id) => self.plan_view = Some((id, 0)),
                Effect::LogOpen(item) => self.open_log(item),
                Effect::ReadsSkipped => self.writer_follow(planview::reads_skipped()),
                Effect::PlanWrite(id, doc, prompt) => self.write_plan(id, doc, prompt, None),
                Effect::Snooze(id, until) => {
                    match crate::server::maint::snooze(&self.remote.name, &id, until) {
                        Ok(()) => {
                            self.toast(&format!("{id}: look again {until}"));
                            self.fetch(Kind::Maint);
                        }
                        Err(e) => self.toast(&format!("couldn't save it: {e}")),
                    }
                }
                Effect::EditConfig => {
                    let editor = std::env::var("VISUAL")
                        .or_else(|_| std::env::var("EDITOR"))
                        .unwrap_or_else(|_| "vi".into());
                    let path = crate::server::config::path();
                    let mut words = editor.split_whitespace();
                    let cmd = Cmd::local(words.next().unwrap_or("vi"))
                        .args(words)
                        .arg(path.display().to_string())
                        .timeout(None);
                    self.suspend = Some((cmd, String::new(), Vec::new()));
                    self.suspend_edit = true;
                }
                Effect::SudoReads(reads, to) => {
                    let script = crate::server::inventory::reads_script(&reads);
                    let cmd = self
                        .remote
                        .sh(&crate::server::inventory::sudo_wrapper(
                            &script,
                            ".cache/sentry-server/claude-reads.out",
                            &format!(
                                "Reading for Claude on {} (nothing is changed)…",
                                self.remote.name
                            ),
                        ))
                        .timeout(None);
                    let banner = format!(
                        "sentry-server · reading {} with sudo for Claude",
                        self.remote.name
                    );
                    self.suspend = Some((cmd, banner, Vec::new()));
                    self.suspend_reads = Some((reads, to));
                }
                Effect::Inventory => {
                    let cmd = self
                        .remote
                        .sh(&crate::server::inventory::wrapper(&self.remote))
                        .timeout(None);
                    let banner = format!("sentry-server · reading {} with sudo", self.remote.name);
                    self.suspend = Some((cmd, banner, Vec::new()));
                    self.suspend_inventory = true;
                }
                Effect::Suspend(cmd, banner, then, reboot) => {
                    self.suspend = Some((cmd, banner, then));
                    self.suspend_reboot = reboot;
                }
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

    fn load_wf_entries(&mut self) {
        self.wf_entries = workflow::list_for(&self.remote.name);
        let d = workflow::dir_for(&self.remote.name);
        let home = std::env::var("HOME").unwrap_or_default();
        let shown = d.display().to_string();
        self.wf_dir = match shown.strip_prefix(&home) {
            Some(rest) if !home.is_empty() => format!("~{rest}/"),
            _ => format!("{shown}/"),
        };
    }

    /// After `e`: read server_config.yaml again; on an error, keep what was loaded.
    fn reload_config(&mut self) {
        let loaded = crate::server::config::load().and_then(|(f, w)| {
            let s = f.servers.get(&self.remote.name).cloned().ok_or_else(|| {
                format!("{} is no longer in server_config.yaml", self.remote.name)
            })?;
            Ok((s, w))
        });
        match loaded {
            Ok((s, warnings)) => {
                let problems = crate::server::config::lint(&self.remote.name, &s);
                self.remote = Remote::new(&self.remote.name, &s).with_inventory();
                self.fetch(Kind::Maint);
                match warnings.iter().chain(&problems).next() {
                    Some(p) => self.toast(&format!("reloaded · {p}")),
                    None => self.toast("server_config.yaml reloaded"),
                }
            }
            Err(e) => self.toast(&format!("not reloaded: {e}")),
        }
    }

    /// When the workflow started from a maintenance item has ended: log the change.
    fn wf_log_change(&mut self) {
        let Some(s) = self.wf.as_ref().filter(|s| s.done()) else {
            return;
        };
        if self.wf_logged.as_ref() == Some(&s.run.dir) {
            return;
        }
        self.wf_logged = Some(s.run.dir.clone());
        use crate::server::maint::{log, plan};
        use crate::workflows::state::RunStatus;
        let done = s.run.state.status == RunStatus::Done;
        let change = self.wf_change.take();
        // A plan carried out is done with (it moves to plans/done/); an abandoned run leaves it.
        let mut plan_path = None;
        if let Some(c) = &change
            && done
            && let Some(doc) = self.store.plans.remove(&c.item)
        {
            plan_path = if self.offline {
                Some(plan::path(&self.remote.name, &c.item))
            } else {
                plan::close(&doc, PlanStatus::Done).ok()
            };
        }
        let info = change.as_ref().map(|c| {
            let it = self
                .remote
                .cfg
                .maintenance
                .items
                .iter()
                .find(|i| i.id == c.item);
            log::ItemInfo {
                item: c.item.clone(),
                kind: it.map_or("system", item_kind).to_string(),
                risk: it.map_or("medium", |i| i.risk.as_str()).to_string(),
                from: c.from.clone(),
                to: c.to.clone(),
                plan: plan_path,
            }
        });
        let entry = log::LogEntry::from_run(
            &self.remote.name,
            &s.wf,
            &s.run.state,
            &s.run.dir,
            info.as_ref(),
            None,
        );
        if !self.offline {
            if let Err(e) = log::write(&entry) {
                self.toast(&format!("couldn't write the maintenance log: {e}"));
            }
            self.fetch(Kind::Maint);
        }
        if done {
            self.last_change_at = Some(jiff::Timestamp::now());
            // What was read with sudo is from before this run: offer to read it again.
            self.offer_reread =
                self.store.sudo.value == Some(SudoMode::Password) && self.inventory_at.is_some();
        }
        // What to know next time: asked now, while it's fresh.
        self.log_note = Some((entry, String::new()));
    }

    /// After a run that changed the server: what Maintenance and Containers show was read
    /// with sudo before it; offer to read it again.
    fn reread_box(&mut self) {
        if !std::mem::take(&mut self.offer_reread) {
            return;
        }
        let t = self.theme;
        let when = self.inventory_at.map_or("earlier".into(), |a| {
            a.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%H:%M")
                .to_string()
        });
        self.modal = Some(Modal {
            title: "Read the server again".into(),
            color: t.cyan,
            lines: vec![
                Line::styled(
                    format!(
                        "Maintenance and Containers show what was read with sudo at {when}, \
                         before this change, so they still show the old versions."
                    ),
                    t.fg(),
                ),
                Line::raw(""),
                Line::styled(
                    "Read it again now? One sudo, read-only (the terminal is handed over for \
                     the password). Or later: I.",
                    t.dim(),
                ),
            ],
            yes: Some(("read".into(), vec![Effect::Inventory])),
        });
    }

    /// The note for the maintenance log: Enter saves it (empty is fine), Esc leaves none.
    fn log_note_key(&mut self, k: KeyEvent) {
        use ratatui::crossterm::event::KeyCode;
        let Some((_, buf)) = self.log_note.as_mut() else {
            return;
        };
        self.dirty = true;
        match k.code {
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Esc => {
                self.log_note = None;
                self.reread_box();
            }
            KeyCode::Enter => {
                let Some((entry, note)) = self.log_note.take() else {
                    return;
                };
                self.reread_box();
                let note = note.trim();
                if note.is_empty() {
                    return;
                }
                let Some(s) = self.wf.as_ref() else { return };
                // Rebuilt with the note (it replaces the entry written when the run ended).
                let info =
                    entry
                        .head
                        .item
                        .as_ref()
                        .map(|item| crate::server::maint::log::ItemInfo {
                            item: item.clone(),
                            kind: entry.head.kind.clone(),
                            risk: entry.head.risk.clone().unwrap_or_default(),
                            from: entry.head.from.clone(),
                            to: entry.head.to.clone(),
                            plan: entry.head.plan.clone().map(Into::into),
                        });
                let with_note = crate::server::maint::log::LogEntry::from_run(
                    &self.remote.name,
                    &s.wf,
                    &s.run.state,
                    &s.run.dir,
                    info.as_ref(),
                    Some(note),
                );
                if !self.offline
                    && let Err(e) = crate::server::maint::log::write(&with_note)
                {
                    return self.toast(&format!("couldn't write the note: {e}"));
                }
                self.last_log = Some(with_note);
                self.toast("noted in the maintenance log");
            }
            _ => {}
        }
    }

    /// `I`: what it reads and why, then the terminal for the password.
    fn inventory_box(&mut self, mode: Option<SudoMode>) {
        let t = self.theme;
        match mode {
            Some(SudoMode::NoPasswd) => {
                return self.toast("sudo doesn't ask for a password here: it's all read live");
            }
            Some(SudoMode::Absent) => return self.toast("this login has no sudo on the server"),
            _ => {}
        }
        let script = crate::server::inventory::script(&self.remote);
        if script.is_empty() {
            return self.toast("nothing to read: no sudo: entries in server_config.yaml");
        }
        let mut lines = vec![
            Line::styled(
                format!(
                    "sudo on {} asks for a password, so these can't be read in the background:",
                    self.remote.name
                ),
                t.fg(),
            ),
            Line::raw(""),
        ];
        let mut seen = Vec::new();
        for l in script.lines().filter(|l| l.ends_with(" 2>/dev/null")) {
            let cmd = l.trim_end_matches(" 2>/dev/null").trim();
            if !seen.contains(&cmd) {
                seen.push(cmd);
                lines.push(Line::styled(format!("  {cmd}"), t.dim()));
            }
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "All read-only, in one sudo: the terminal is handed over for your password. Containers,              SMART, the journal and the audit then use this read (its age is shown) until you read again.",
            t.s(t.yellow),
        ));
        self.modal = Some(Modal {
            title: "Read with sudo".into(),
            color: t.yellow,
            lines,
            yes: Some(("read".into(), vec![Effect::Inventory])),
        });
    }

    fn after_inventory(&mut self, status: Result<ExitStatus, ExecError>) {
        match status {
            Ok(st) if st.success() => {}
            Ok(st) => {
                let _ = self.remote.output(
                    &self
                        .remote
                        .sh("rm -f \"$HOME/.cache/sentry-server/inventory.out\""),
                );
                return self.toast(&format!(
                    "the read didn't finish (exit {}): nothing changed",
                    st.code().unwrap_or(-1)
                ));
            }
            Err(e) => return self.toast(&e.to_string()),
        }
        let inv = match crate::server::inventory::read_back(&self.remote) {
            Ok(i) => i,
            Err(e) => return self.toast(&format!("couldn't read it back: {e}")),
        };
        let n = inv.outputs.len();
        match crate::server::inventory::save(&self.remote.name, &inv) {
            Ok(at) => self.inventory_at = Some(at),
            Err(e) => return self.toast(&format!("couldn't save it: {e}")),
        }
        for k in [
            Kind::Docker,
            Kind::Smart,
            Kind::Jails,
            Kind::Journal,
            Kind::Listeners,
            Kind::Maint,
        ] {
            self.fetch(k);
        }
        self.toast(&format!(
            "read {n} command(s) with sudo · c on Audit audits with them"
        ));
    }

    /// How sudo behaves right now, checked again (the server's sudoers can change while this
    /// is open); tests use what the store has.
    fn fresh_sudo(&mut self) -> Option<SudoMode> {
        if !self.offline {
            let m = self.remote.sudo_mode();
            self.store.sudo.set(m);
        }
        self.store.sudo.value
    }

    /// The sudo mode for the workflow's next step: checked again only when it uses sudo.
    fn wf_sudo(&mut self) -> Option<SudoMode> {
        if self.wf.as_ref().is_some_and(|s| s.next_uses_sudo()) {
            self.fresh_sudo()
        } else {
            self.store.sudo.value
        }
    }

    /// Stop the workflow's running step (abandoning, closing or quitting).
    fn wf_stop_live(&mut self) {
        if let Some(pid) = self
            .wf
            .as_mut()
            .and_then(|s| s.live.take())
            .and_then(|l| l.pid)
        {
            let _ = kill(pid);
        }
    }

    fn wf_cmd(&mut self, c: WfCmd) {
        let sudo = match c {
            WfCmd::Go => self.wf_sudo(),
            _ => self.store.sudo.value,
        };
        if matches!(c, WfCmd::Abandon | WfCmd::Close) {
            self.wf_stop_live();
        }
        let r: Result<Option<Exec>, String> = match c {
            WfCmd::Begin(name) => {
                let asks: Vec<(String, String, Option<String>)> = self
                    .wf_entries
                    .iter()
                    .find(|e| e.name == name)
                    .and_then(|e| e.wf.as_ref().ok())
                    .map(|w| {
                        w.vars
                            .iter()
                            .map(|(k, v)| (k.clone(), v.prompt.clone(), v.default.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                if asks.is_empty() {
                    return self.wf_cmd(WfCmd::BeginWith(name, BTreeMap::new()));
                }
                let buf = asks[0].2.clone().unwrap_or_default();
                self.var_input = Some(VarInput {
                    workflow: name,
                    asks,
                    values: BTreeMap::new(),
                    buf,
                    note: None,
                });
                self.dirty = true;
                return;
            }
            WfCmd::BeginPrefilled(name, given, change) => {
                if self.wf.as_ref().is_some_and(|s| !s.done()) {
                    self.toast("a workflow is already in progress");
                    return;
                }
                self.enter(Tab::Workflows, Instant::now());
                let Some(e) = self.wf_entries.iter().find(|e| e.name == name) else {
                    self.toast(&format!(
                        "no workflow {name} in {}",
                        self.wf_dir.trim_end_matches('/')
                    ));
                    return;
                };
                self.wf_change = change;
                let asks: Vec<(String, String, Option<String>)> =
                    e.wf.as_ref()
                        .map(|w| {
                            w.vars
                                .iter()
                                .map(|(k, v)| (k.clone(), v.prompt.clone(), v.default.clone()))
                                .collect()
                        })
                        .unwrap_or_default();
                let asks = super::maint::merge_defaults(asks, &given);
                if asks.is_empty() {
                    return self.wf_cmd(WfCmd::BeginWith(name, BTreeMap::new()));
                }
                let buf = asks[0].2.clone().unwrap_or_default();
                self.var_input = Some(VarInput {
                    workflow: name,
                    asks,
                    values: BTreeMap::new(),
                    buf,
                    note: None,
                });
                self.dirty = true;
                return;
            }
            WfCmd::BeginWith(name, vars) => match self.wf_entries.iter().find(|e| e.name == name) {
                Some(e) => match Session::begin(e, &self.remote, vars) {
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
                    self.load_wf_entries();
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
                    WfCmd::Begin(_)
                    | WfCmd::BeginWith(..)
                    | WfCmd::BeginPrefilled(..)
                    | WfCmd::Close => Ok(None),
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
        self.wf_log_change();
        if self.tab != Tab::Workflows {
            return;
        }
        if !self
            .wf
            .as_ref()
            .is_some_and(|s| s.armed && s.live.is_none() && matches!(s.next, Next::Run(_)))
        {
            return;
        }
        let sudo = self.wf_sudo();
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
            Exec::Tty { cmd, idx, capture } => {
                self.suspend_step = Some((idx, capture));
                let banner = format!("sentry-server · workflow step on {}", self.remote.name);
                self.suspend = Some((cmd, banner, Vec::new()));
            }
            Exec::Reboot { cmd, tty } => {
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
                if tty {
                    // sudo asks for the password; the wait starts once the terminal is back.
                    self.suspend = Some((
                        cmd,
                        format!("sentry-server · rebooting {}", self.remote.name),
                        Vec::new(),
                    ));
                    self.suspend_reboot = true;
                    self.reboot_old = Some(old);
                    return;
                }
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

    /// Typing a workflow var: Enter takes it (an empty answer takes the default), Esc cancels
    /// the start.
    fn var_key(&mut self, k: KeyEvent) {
        use ratatui::crossterm::event::KeyCode;
        let Some(v) = self.var_input.as_mut() else {
            return;
        };
        self.dirty = true;
        match k.code {
            KeyCode::Char(c) => v.buf.push(c),
            KeyCode::Backspace => {
                v.buf.pop();
            }
            KeyCode::Esc => {
                self.var_input = None;
                self.toast("not started");
            }
            KeyCode::Enter => {
                let Some((name, _, default)) = v.current().cloned() else {
                    return;
                };
                let val = match v.buf.trim() {
                    "" => default.unwrap_or_default(),
                    s => s.to_string(),
                };
                if val.is_empty() {
                    v.note = Some(format!("{name} needs a value"));
                    return;
                }
                v.note = None;
                v.values.insert(name, val);
                v.buf = v
                    .current()
                    .and_then(|(_, _, d)| d.clone())
                    .unwrap_or_default();
                if v.current().is_none() {
                    let v = self.var_input.take().expect("var input");
                    self.wf_cmd(WfCmd::BeginWith(v.workflow, v.values));
                }
            }
            _ => {}
        }
    }

    /// `p`, after the note: what Claude is asked, in a confirm box; yes starts the writer.
    fn ask_for_plan(&mut self, id: String, doc: PlanDoc) {
        if self.wf_entries.is_empty() && !self.offline {
            self.load_wf_entries();
        }
        let steps = self
            .wf_entries
            .iter()
            .find(|e| e.name == doc.head.workflow)
            .and_then(|e| e.wf.as_ref().ok())
            .map(|w| {
                w.steps
                    .iter()
                    .enumerate()
                    .map(|(i, st)| {
                        format!(
                            "{}. {} [{}]{}",
                            i + 1,
                            st.title,
                            st.tag(),
                            st.run.as_deref().map_or(String::new(), |c| format!(
                                "\n   $ {}",
                                c.replace('\n', "\n     ")
                            ))
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_else(|| format!("(workflow {} not found)", doc.head.workflow));
        let v = self.view();
        let Some((s, it)) =
            v.s.maint
                .value
                .as_ref()
                .and_then(|st| st.iter().find(|s| s.id == id))
                .zip(v.cfg.maintenance.items.iter().find(|i| i.id == id))
        else {
            return self.toast("that item is gone");
        };
        let goal = match (&doc.head.to, it.retire.is_some()) {
            (_, true) => format!("retiring {id}"),
            (Some(t), _) => format!(
                "moving {id} from {} to {t}",
                s.pinned.as_deref().unwrap_or("?")
            ),
            (None, _) => format!(
                "moving {id} from {} to the version you recommend",
                s.pinned.as_deref().unwrap_or("?")
            ),
        };
        let prompt = planview::request(
            &super::maint::context(&v, &self.remote, s, it),
            &doc.head.workflow,
            &steps,
            &goal,
            doc.head.note.as_deref(),
        );
        let t = self.theme;
        let notes = &self.remote.cfg.maintenance.notes;
        let lines = vec![
            Line::styled(format!("Claude writes the plan for {goal}."), t.fg()),
            Line::raw(""),
            Line::styled(
                format!(
                    "It reads the release notes on the web, your notes ({}), and {} read-only \
                     through the gateway; reads that need root are asked for first. Its answer \
                     is saved as {}.",
                    if notes.is_empty() {
                        "none".to_string()
                    } else {
                        notes.join(", ")
                    },
                    self.remote.name,
                    crate::server::maint::plan::path(&self.remote.name, &id).display()
                ),
                t.dim(),
            ),
            Line::raw(""),
            Line::styled(
                "Sent to Claude through your Claude Code login (Anthropic). Nothing on the \
                 server changes.",
                t.s(t.yellow),
            ),
        ];
        self.modal = Some(Modal {
            title: format!("Plan {id} with Claude"),
            color: t.mag,
            lines,
            yes: Some(("write it".into(), vec![Effect::PlanWrite(id, doc, prompt)])),
        });
    }

    /// Start (or continue) Claude writing a plan in the background; the Plan view shows it.
    fn write_plan(&mut self, id: String, doc: PlanDoc, prompt: String, resume: Option<String>) {
        if self.writer.as_ref().is_some_and(|w| w.running()) {
            return self.toast("Claude is already writing a plan: wait for it, or C-c in its view");
        }
        let mut w = planview::Writer::new(&id, doc);
        self.plan_view = Some((id.clone(), 0));
        let (os, kernel) = self.store.host.value.clone().unwrap_or_default();
        let profile = planview::profile(&self.remote, &os, &kernel, self.store.sudo.value);
        let cmd = claude::turn_cmd_with(&prompt, resume.as_deref(), &profile);
        self.run_seq += 1;
        let rid = self.run_seq;
        if self.offline {
            w.live = Some((rid, 0));
            self.writer = Some(w);
            return;
        }
        let tx = self.tx.clone();
        match cmd.stream(move |m| {
            let _ = tx.send(Ev::Run(rid, m));
        }) {
            Ok(pid) => {
                w.live = Some((rid, pid));
                self.writer = Some(w);
            }
            Err(e) => self.toast(&format!("couldn't start claude: {e}")),
        }
    }

    /// Another turn for the plan being written (in its Claude session).
    fn writer_follow(&mut self, prompt: String) {
        match self.writer.as_ref() {
            Some(w) if !w.running() => {
                let (id, doc, session) = (w.item.clone(), w.doc.clone(), w.session.clone());
                self.write_plan(id, doc, prompt, session);
            }
            _ => self.toast("the plan isn't being written any more"),
        }
    }

    /// The writer's turn ended: save its answer as the plan, then any reads it asked for.
    fn writer_turn_ended(&mut self) {
        let Some(w) = self.writer.as_mut() else {
            return;
        };
        let mut doc = w.doc.clone();
        doc.head.session = w.session.clone().or(doc.head.session);
        // Waiting for reads that need root: no plan yet; ask for them.
        if w.answer.as_deref().is_some_and(planview::waits_for_reads) {
            w.doc.head.session = w.session.clone().or(w.doc.head.session.clone());
            w.doing = "waiting for reads that need root".into();
            if !self.offline {
                let reads = crate::server::gateway::take_reads(&self.remote.name);
                if reads.is_empty() {
                    // Nothing queued after all: have it write the plan.
                    return self.writer_follow(planview::reads_skipped());
                }
                self.reads_box(reads, ReadsFor::Plan);
            }
            return;
        }
        let msg = match (&w.answer, &w.err) {
            (Some(a), _) if !a.trim().is_empty() => {
                doc.take_answer(a);
                match doc.head.status {
                    PlanStatus::Wait => format!("plan for {}: Claude advises waiting", w.item),
                    _ => format!(
                        "plan for {} saved: → {} · Enter applies it",
                        w.item,
                        doc.head.to.as_deref().unwrap_or("retire")
                    ),
                }
            }
            (_, err) => {
                // A revision that failed keeps the plan it had.
                if doc.body.trim().is_empty() {
                    doc.head.status = PlanStatus::Failed;
                    doc.body = format!(
                        "Claude didn't write the plan: {}",
                        err.clone().unwrap_or_else(|| "no answer".into())
                    );
                }
                format!(
                    "no plan for {}: {}",
                    w.item,
                    err.clone()
                        .unwrap_or_else(|| "Claude gave no answer".into())
                )
            }
        };
        w.doc = doc.clone();
        let item = w.item.clone();
        if !self.offline
            && let Err(e) = crate::server::maint::plan::save(&doc)
        {
            return self.toast(&format!("couldn't save the plan: {e}"));
        }
        self.store.plans.insert(item, doc);
        self.toast(&msg);
        self.offer_reads(ReadsFor::Plan);
    }

    /// An assessment's turn ended: keep what Claude said, for `L` and the item's details.
    fn save_assessment(&mut self) {
        let (Some(id), Some(c)) = (self.assess_item.clone(), self.chat.as_ref()) else {
            return;
        };
        let text = c
            .entries
            .iter()
            .filter(|(k, _)| *k == chatmod::Kind::Claude)
            .map(|(_, t)| t.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");
        if text.trim().is_empty() {
            return;
        }
        if !self.offline {
            let _ = crate::server::maint::save_assessment(&self.remote.name, &id, &text);
        }
        self.store.maint_state.assessments.insert(
            id,
            crate::server::maint::Assessment {
                at: Some(jiff::Timestamp::now()),
                text,
            },
        );
    }

    fn open_log(&mut self, item: Option<String>) {
        let entries = if self.offline {
            Vec::new()
        } else {
            crate::server::maint::log::list(&self.remote.name)
        };
        // Start on the item's newest entry when there is one.
        let cur = item
            .as_ref()
            .and_then(|i| entries.iter().position(|e| e.head.item.as_ref() == Some(i)))
            .unwrap_or(0);
        self.log_view = Some(planview::LogView {
            entries,
            cur,
            open: None,
            item,
        });
    }

    /// Keys in the Log view: j/k pick a run, Enter opens it, Esc goes back a level.
    fn log_view_key(&mut self, k: KeyEvent) {
        use ratatui::crossterm::event::KeyCode;
        let Some(lv) = self.log_view.as_mut() else {
            return;
        };
        self.dirty = true;
        let n = lv.entries.len();
        match (&mut lv.open, k.code) {
            (Some(_), KeyCode::Esc | KeyCode::Char('q') | KeyCode::Backspace) => lv.open = None,
            (Some(s), KeyCode::Down | KeyCode::Char('j')) => *s += 1,
            (Some(s), KeyCode::Up | KeyCode::Char('k')) => *s = s.saturating_sub(1),
            (Some(s), KeyCode::PageDown | KeyCode::Char(' ')) => *s += 20,
            (Some(s), KeyCode::PageUp) => *s = s.saturating_sub(20),
            (Some(s), KeyCode::Home | KeyCode::Char('g')) => *s = 0,
            (Some(s), KeyCode::End | KeyCode::Char('G')) => *s = usize::MAX / 2,
            (Some(_), _) => {}
            (None, KeyCode::Esc | KeyCode::Char('q')) => self.log_view = None,
            (None, KeyCode::Down | KeyCode::Char('j')) => {
                lv.cur = (lv.cur + 1).min(n.saturating_sub(1))
            }
            (None, KeyCode::Up | KeyCode::Char('k')) => lv.cur = lv.cur.saturating_sub(1),
            (None, KeyCode::Home | KeyCode::Char('g')) => lv.cur = 0,
            (None, KeyCode::End | KeyCode::Char('G')) => lv.cur = n.saturating_sub(1),
            (None, KeyCode::Enter) if n > 0 => lv.open = Some(0),
            _ => {}
        }
    }

    /// Keys in the Plan view: scroll, apply (Enter), revise (r), drop (x), back (Esc).
    fn plan_view_key(&mut self, k: KeyEvent, now: Instant) {
        use ratatui::crossterm::event::{KeyCode, KeyModifiers};
        let Some((id, scroll)) = self.plan_view.clone() else {
            return;
        };
        self.dirty = true;
        let set = |me: &mut Self, s: usize| me.plan_view = Some((id.clone(), s));
        let writing = self
            .writer
            .as_ref()
            .is_some_and(|w| w.item == id && w.running());
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => self.plan_view = None,
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(pid) = self
                    .writer
                    .as_ref()
                    .filter(|w| w.item == id)
                    .and_then(|w| w.live.map(|(_, p)| p))
                {
                    let _ = kill(pid);
                    self.toast("stopped: the plan keeps what it had");
                }
            }
            KeyCode::Down | KeyCode::Char('j') => set(self, scroll + 1),
            KeyCode::Up | KeyCode::Char('k') => set(self, scroll.saturating_sub(1)),
            KeyCode::PageDown | KeyCode::Char(' ') => set(self, scroll + 20),
            KeyCode::PageUp => set(self, scroll.saturating_sub(20)),
            KeyCode::Home | KeyCode::Char('g') => set(self, 0),
            KeyCode::End | KeyCode::Char('G') => set(self, usize::MAX / 2),
            _ if writing => {
                self.toast("Claude is writing it · C-c stops · Esc goes back (it carries on)")
            }
            KeyCode::Enter => self.apply_plan(&id, now),
            KeyCode::Char('r') => match self.store.plans.get(&id) {
                Some(d) if d.head.session.is_some() => self.revise_input = Some(String::new()),
                Some(_) => {
                    self.toast("this plan has no Claude session to continue: p writes a new one")
                }
                None => {}
            },
            KeyCode::Char('x') if self.store.plans.contains_key(&id) => {
                let t = self.theme;
                self.modal = Some(Modal {
                    title: "Drop the plan".into(),
                    color: t.yellow,
                    lines: vec![Line::styled(
                        format!(
                            "Drop the plan for {id}? It moves to plans/done/; nothing on the server changes."
                        ),
                        t.fg(),
                    )],
                    yes: Some(("drop".into(), vec![Effect::PlanDrop(id.clone())])),
                });
            }
            _ => {}
        }
    }

    /// Enter in the Plan view: the item's workflow, with the plan's values filled in.
    fn apply_plan(&mut self, id: &str, now: Instant) {
        let Some(d) = self.store.plans.get(id).cloned() else {
            return;
        };
        match d.head.status {
            PlanStatus::Ready => {}
            PlanStatus::Wait => {
                return self.toast("Claude advises waiting: r revises it, or p plans again");
            }
            s => return self.toast(&format!("this plan is {}: p plans again", s.word())),
        }
        self.plan_view = None;
        let effects = vec![Effect::Wf(WfCmd::BeginPrefilled(
            d.head.workflow.clone(),
            d.head.vars.clone(),
            Some(crate::server::maint::Change {
                at: jiff::Timestamp::now(),
                item: id.to_string(),
                from: d.head.from.clone(),
                to: d.head.to.clone(),
                workflow: d.head.workflow.clone(),
                result: String::new(),
            }),
        ))];
        self.apply(effects, now);
    }

    /// `r` in the Plan view: what to change, then Claude rewrites the plan in its session.
    fn revise_key(&mut self, k: KeyEvent) {
        use ratatui::crossterm::event::KeyCode;
        let Some(buf) = self.revise_input.as_mut() else {
            return;
        };
        self.dirty = true;
        match k.code {
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Esc => self.revise_input = None,
            KeyCode::Enter => {
                let what = self.revise_input.take().unwrap_or_default();
                let Some((id, _)) = self.plan_view.clone() else {
                    return;
                };
                let Some(doc) = self.store.plans.get(&id).cloned() else {
                    return;
                };
                if what.trim().is_empty() {
                    return;
                }
                let session = doc.head.session.clone();
                self.write_plan(id, doc, planview::revise(what.trim()), session);
            }
            _ => {}
        }
    }

    /// The plan's note: Enter saves the plan (an empty note is fine), Esc doesn't save it.
    fn plan_note_key(&mut self, k: KeyEvent) {
        use ratatui::crossterm::event::KeyCode;
        let Some((_, _, buf)) = self.plan_note.as_mut() else {
            return;
        };
        self.dirty = true;
        match k.code {
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Esc => {
                self.plan_note = None;
                self.toast("not planned");
            }
            KeyCode::Enter => {
                let Some((id, mut plan, note)) = self.plan_note.take() else {
                    return;
                };
                let note = note.trim();
                plan.head.note = (!note.is_empty()).then(|| note.to_string());
                if !claude::available() {
                    return self.toast("plans are written by Claude Code, which isn't installed");
                }
                self.ask_for_plan(id, plan);
            }
            _ => {}
        }
    }

    /// Typing a `/` filter: rows narrow as you type; Enter keeps it, Esc clears it.
    fn filter_key(&mut self, k: KeyEvent) {
        use ratatui::crossterm::event::KeyCode;
        let i = self.tab.index();
        match k.code {
            KeyCode::Char(c) => self.filters[i].push(c),
            KeyCode::Backspace => {
                if self.filters[i].pop().is_none() {
                    self.filtering = false;
                }
            }
            KeyCode::Esc => {
                self.filters[i].clear();
                self.filtering = false;
            }
            KeyCode::Enter => self.filtering = false,
            _ => {}
        }
        self.cursors[i] = 0;
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
            (Some("log"), _) => self.open_log(None),
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
        if self.tab == Tab::Maint {
            let notes = &self.remote.cfg.maintenance.notes;
            lines.push(Line::styled(
                format!(
                    "For an assessment Claude may also read the web (release notes) and these \
                     local files: {}",
                    if notes.is_empty() {
                        "none".to_string()
                    } else {
                        notes.join(", ")
                    }
                ),
                t.s(t.yellow),
            ));
        }
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
        match turn {
            AskTurn::First(ask) => {
                self.chat_assess = self.tab == Tab::Maint;
                self.assess_item = if self.chat_assess {
                    super::maint::selected(&self.view()).map(|(s, _)| s.id.clone())
                } else {
                    None
                };
                let p = ask.prompt();
                let q = ask.question.lines().next().unwrap_or("").to_string();
                self.chat = Some(Chat::new(ask));
                self.start_turn(ReadsFor::Chat, &p, q, None);
            }
            AskTurn::Follow(text) => {
                let session = self.chat.as_ref().and_then(|c| c.session.clone());
                self.start_turn(ReadsFor::Chat, &text, text.clone(), session);
            }
        }
    }

    /// Send one turn to Claude, into the open chat or the background plan.
    fn start_turn(&mut self, to: ReadsFor, prompt: &str, shown: String, resume: Option<String>) {
        let assess = self.chat_assess;
        let (os, kernel) = self.store.host.value.clone().unwrap_or_default();
        let profile = if assess {
            super::ask::assess_profile(&self.remote, &os, &kernel, self.store.sudo.value)
        } else {
            super::ask::profile(&self.remote, &os, &kernel, self.store.sudo.value)
        };
        let cmd = claude::turn_cmd_with(prompt, resume.as_deref(), &profile);
        self.run_seq += 1;
        let id = self.run_seq;
        let _ = to;
        let Some(c) = self.chat.as_mut() else { return };
        if self.offline {
            c.push(chatmod::Kind::You, shown);
            return;
        }
        let tx = self.tx.clone();
        match cmd.stream(move |m| {
            let _ = tx.send(Ev::Run(id, m));
        }) {
            Ok(pid) => c.begin_turn(&shown, id, pid),
            Err(e) => c.push(chatmod::Kind::Err, format!("couldn't start claude: {e}")),
        }
    }

    /// After a turn: if Claude asked to read things that need root, show them and ask.
    fn offer_reads(&mut self, to: ReadsFor) {
        if self.offline {
            return;
        }
        let reads = crate::server::gateway::take_reads(&self.remote.name);
        if !reads.is_empty() {
            self.reads_box(reads, to);
        }
    }

    fn reads_box(&mut self, reads: Vec<Vec<String>>, to: ReadsFor) {
        let t = self.theme;
        let mut lines = vec![
            Line::styled(
                format!(
                    "Claude asks to read these on {}, which need root (sudo asks for your password):",
                    self.remote.name
                ),
                t.fg(),
            ),
            Line::raw(""),
        ];
        for argv in &reads {
            lines.push(Line::styled(
                format!(
                    "  $ sudo {}",
                    argv.iter()
                        .map(|a| crate::exec::sh_quote(a))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
                t.fg(),
            ));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "All on the read-only list. One sudo, the terminal handed over for the password; the \
             output goes back to Claude, which then continues.",
            t.s(t.yellow),
        ));
        let skip = match to {
            // The plan waits for an answer either way.
            ReadsFor::Plan => vec![Effect::ReadsSkipped],
            ReadsFor::Chat => Vec::new(),
        };
        self.modal = Some(Modal {
            title: "Claude asks to read with sudo".into(),
            color: t.yellow,
            lines,
            yes: Some(("read".into(), vec![Effect::SudoReads(reads, to)])),
        });
        self.modal_no = Some(("Claude asks to read with sudo".into(), skip));
    }

    /// The reads ran: send their output back to Claude.
    fn after_reads(
        &mut self,
        reads: Vec<Vec<String>>,
        to: ReadsFor,
        status: Result<ExitStatus, ExecError>,
    ) {
        const CAPTURE: &str = ".cache/sentry-server/claude-reads.out";
        if let Err(e) = status {
            return self.toast(&e.to_string());
        }
        let inv = match crate::server::inventory::read_capture(&self.remote, CAPTURE) {
            Ok(i) => i,
            Err(e) => return self.toast(&format!("couldn't read it back: {e}")),
        };
        if inv.outputs.is_empty() {
            return self.toast("nothing was read (wrong password?)");
        }
        let mut text = String::from(
            "Here is the output of the commands you asked to read with sudo (I ran them):\n",
        );
        for argv in &reads {
            let line = argv
                .iter()
                .map(|a| crate::exec::sh_quote(a))
                .collect::<Vec<_>>()
                .join(" ");
            let Some(c) = inv.outputs.get(&line) else {
                continue;
            };
            let out: Vec<&str> = c.out.lines().collect();
            let shown = if out.len() > 300 {
                format!(
                    "{}\n… ({} more lines cut)",
                    out[out.len() - 300..].join("\n"),
                    out.len() - 300
                )
            } else {
                out.join("\n")
            };
            text.push_str(&format!("\n$ sudo {line}   (exit {})\n{shown}\n", c.code));
        }
        text.push_str("\nContinue from here.");
        match to {
            ReadsFor::Plan => self.writer_follow(planview::reads_back(&text)),
            _ if self.chat.is_some() => self.ask_turn(AskTurn::Follow(text)),
            _ => self.toast("the conversation is closed: the output wasn't sent"),
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
            KeyCode::Char('k') if ctrl => c.scroll_by(1),
            KeyCode::Char('j') if ctrl => c.scroll_by(-1),
            KeyCode::Up => c.scroll_by(1),
            KeyCode::Down => c.scroll_by(-1),
            KeyCode::PageUp => c.scroll_by(10),
            KeyCode::PageDown => c.scroll_by(-10),
            KeyCode::Home => c.scroll_top(),
            KeyCode::End => c.scroll_bottom(),
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
        if let Some((idx, capture)) = self.suspend_step.take()
            && let Some(s) = self.wf.as_mut()
        {
            let code = match &status {
                Ok(st) => st.code().unwrap_or(-1),
                Err(_) => -1,
            };
            if !self.offline {
                s.tty_output(idx, &capture);
            }
            s.on_exit(idx, code);
            self.wf_auto();
            return;
        }
        if std::mem::take(&mut self.suspend_edit) {
            self.reload_config();
            return;
        }
        if let Some((reads, to)) = self.suspend_reads.take() {
            self.after_reads(reads, to, status);
            return;
        }
        if std::mem::take(&mut self.suspend_inventory) {
            self.after_inventory(status);
            return;
        }
        if std::mem::take(&mut self.suspend_reboot) {
            // ssh drops (255) as the server goes down; a quick non-zero exit is sudo refusing.
            let old = self.reboot_old.take().unwrap_or_else(|| {
                self.store
                    .probe
                    .value
                    .as_ref()
                    .map(|p| p.boot_id.clone())
                    .unwrap_or_default()
            });
            match &status {
                Ok(st) if st.code() != Some(255) && !st.success() => {
                    self.toast(&format!(
                        "reboot didn't start (exit {})",
                        st.code().unwrap_or(-1)
                    ));
                    if let Some(s) = self.wf.as_mut() {
                        s.push("✗ the reboot didn't start", workflow::LogKind::Err);
                    }
                }
                Err(e) => self.toast(&e.to_string()),
                Ok(_) => {
                    self.reboot_wait = Some((Instant::now(), old));
                    if let Some(s) = self.wf.as_mut() {
                        s.push(
                            "… waiting for the server to come back",
                            workflow::LogKind::Info,
                        );
                    }
                    self.toast(&format!("waiting for {} to come back…", self.remote.name));
                }
            }
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
                &self.wf_dir,
                &self.wf_entries,
                self.cursors[Tab::Workflows.index()],
            ),
            _ => tabs::draw(f, body, self.tab, &self.view()),
        }
        if let Some(lv) = &self.log_view {
            let d = crate::server::maint::log::dir(&self.remote.name)
                .display()
                .to_string();
            let home = std::env::var("HOME").unwrap_or_default();
            let d = match d.strip_prefix(&home) {
                Some(r) if !home.is_empty() => format!("~{r}"),
                _ => d,
            };
            super::planview::draw_log(f, body, &t, lv, &d);
        } else if let Some((id, scroll)) = &self.plan_view {
            let path = crate::server::maint::plan::path(&self.remote.name, id)
                .display()
                .to_string();
            let home = std::env::var("HOME").unwrap_or_default();
            let path = match path.strip_prefix(&home) {
                Some(r) if !home.is_empty() => format!("~{r}"),
                _ => path,
            };
            super::planview::draw(
                f,
                body,
                &t,
                self.store.plans.get(id),
                self.writer.as_ref().filter(|w| &w.item == id),
                *scroll,
                &path,
            );
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
            let flt = &self.filters[tab.index()];
            if !flt.is_empty() && tabs::filterable(tab) {
                spans.push(Span::styled(
                    format!(" /{flt}"),
                    style.fg(if active { t.ink } else { t.cyan }),
                ));
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
        if let Some((e, buf)) = &self.log_note {
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(
                        format!(
                            "{} {} · for the maintenance log, what to know next time (optional): ",
                            e.head.item.as_deref().unwrap_or(&e.head.workflow),
                            e.head.result
                        ),
                        t.dim(),
                    ),
                    Span::styled(buf.clone(), t.fg()),
                    Span::styled("▏", t.s(t.cyan)),
                    Span::styled("   Enter save · Esc none", t.dim()),
                ])),
                area,
            );
            return;
        }
        if let Some(buf) = &self.revise_input {
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("revise the plan: ", t.dim()),
                    Span::styled(buf.clone(), t.fg()),
                    Span::styled("▏", t.s(t.cyan)),
                    Span::styled("   Enter send · Esc cancel", t.dim()),
                ])),
                area,
            );
            return;
        }
        if let Some((id, plan, buf)) = &self.plan_note {
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(
                        format!(
                            "plan {id} → {} · a note (optional): ",
                            plan.head.to.as_deref().unwrap_or("retire")
                        ),
                        t.dim(),
                    ),
                    Span::styled(buf.clone(), t.fg()),
                    Span::styled("▏", t.s(t.cyan)),
                    Span::styled("   Enter save · Esc cancel", t.dim()),
                ])),
                area,
            );
            return;
        }
        if let Some(v) = &self.var_input
            && let Some((name, prompt, _)) = v.current()
        {
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(
                        format!(
                            "{} {}/{} · {prompt} ({name}): ",
                            v.workflow,
                            v.values.len() + 1,
                            v.asks.len()
                        ),
                        t.dim(),
                    ),
                    Span::styled(v.buf.clone(), t.fg()),
                    Span::styled("▏", t.s(t.cyan)),
                    match &v.note {
                        Some(n) => Span::styled(format!("   {n}"), t.s(t.red)),
                        None => Span::styled("   Enter next · Esc cancel", t.dim()),
                    },
                ])),
                area,
            );
            return;
        }
        if self.filtering {
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(format!("/{}", self.filters[self.tab.index()]), t.fg()),
                    Span::styled("▏", t.s(t.cyan)),
                    Span::styled("   Enter keep · Esc clear", t.dim()),
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
        } else if let Some(lv) = self.log_view.as_ref().filter(|_| self.modal.is_none()) {
            if lv.open.is_some() {
                vec![("j/k PgUp/Dn", "scroll"), ("Esc", "back to the list")]
            } else {
                vec![("j/k", "select"), ("Enter", "open"), ("Esc", "back")]
            }
        } else if let Some((id, _)) = self
            .plan_view
            .as_ref()
            .filter(|_| self.modal.is_none() && self.chooser.is_none())
        {
            if self
                .writer
                .as_ref()
                .is_some_and(|w| &w.item == id && w.running())
            {
                vec![
                    ("j/k", "scroll"),
                    ("C-c", "stop"),
                    ("Esc", "back (it carries on)"),
                ]
            } else {
                vec![
                    ("Enter", "apply"),
                    ("r", "revise"),
                    ("x", "drop"),
                    ("j/k PgUp/Dn", "scroll"),
                    ("Esc", "back"),
                ]
            }
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
            // sudo asks for a password: say where the root-only data comes from.
            if self.store.sudo.value == Some(SudoMode::Password) {
                h.push(("I", "read with sudo"));
            }
            // The Maintenance tab names its own `A` (assess).
            if claude::available() && self.tab != Tab::Maint {
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

/// What a maintenance item is, for the log.
fn item_kind(it: &crate::server::config::MaintItem) -> &'static str {
    if it.retire.is_some() {
        "retire"
    } else if it.image.is_some() {
        "image"
    } else if !it.apt.is_empty() {
        "packages"
    } else if it.version_cmd.is_some() {
        "app"
    } else {
        "release"
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
    /// Tests: the question waiting in the consent box.
    pub fn consent_text(&self) -> Option<String> {
        let m = self.modal.as_ref()?;
        match m.yes.as_ref()?.1.first()? {
            Effect::AskSend(AskTurn::First(ask)) => Some(ask.prompt()),
            _ => None,
        }
    }
    /// Tests: Claude's turn ended (there's no claude process offline).
    pub fn turn_ended(&mut self) {
        self.save_assessment();
    }
    /// Tests: the plan writer answered.
    pub fn writer_answered(&mut self, answer: &str) {
        if let Some(w) = self.writer.as_mut() {
            w.live = None;
            w.answer = Some(answer.to_string());
        }
        self.writer_turn_ended();
    }
    /// Tests: when the server was read with sudo, and when it last changed.
    pub fn set_inventory_times(&mut self, read: jiff::Timestamp, changed: jiff::Timestamp) {
        self.inventory_at = Some(read);
        self.last_change_at = Some(changed);
    }
    /// Tests: whether Claude is still writing a plan.
    pub fn writing(&self) -> bool {
        self.writer.as_ref().is_some_and(|w| w.running())
    }
    /// Tests: open a conversation without asking Claude anything.
    pub fn open_chat(&mut self, c: Chat) {
        self.chat = Some(c);
    }
    /// Tests: a chat turn ended (online: reads Claude asked for are offered).
    pub fn turn_ended_online_for_reads(&mut self) {
        self.offer_reads(ReadsFor::Chat);
    }
    /// Tests: the reads waiting for a yes, if that box is open.
    pub fn take_reads_box(&mut self) -> Option<Vec<Vec<String>>> {
        let m = self.modal.take()?;
        match m.yes.as_ref()?.1.first()? {
            Effect::SudoReads(r, _) => {
                let r = r.clone();
                self.modal = Some(m);
                Some(r)
            }
            _ => None,
        }
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

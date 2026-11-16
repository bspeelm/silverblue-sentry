//! State, keys, refresh schedule and the frame around the screens.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::process::ExitStatus;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::crossterm::event::KeyEvent;
use ratatui::text::Line;

use super::data::{Kind, Store};
use super::planview;
use super::screens::{Screens, View};
use super::{Ev, SCREENS};
use crate::maint::plan::{PlanDoc, PlanStatus};
use crate::remote::{Remote, SudoMode};
use crate::workflow::{self, Exec, Session};
use sentry_core::claude::{self, Ask};
use sentry_core::exec::{Cmd, ExecError, StreamMsg};
use sentry_core::tui::ScreenId;
use sentry_core::tui::chat::{self as chatmod, Chat};
use sentry_core::tui::frame::{self, Layer};
use sentry_core::tui::input::{Input, PromptLine, Typed};
use sentry_core::tui::keys::{Action, Keymap};
use sentry_core::tui::modal;
use sentry_core::tui::theme::Theme;
use sentry_core::tui::widgets;
use sentry_core::workflows::Entry;
use sentry_core::workflows::runner::Next;

/// What a key press asks the app to do.
#[derive(Clone, Debug)]
pub enum Effect {
    Fetch(Kind),
    Toast(String),
    Info(String, Vec<Line<'static>>),
    Goto(ScreenId),
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
    Choose(Choice),
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
    /// Carry out an item's ready plan (an apply session seeded with it).
    PlanApply(String),
    /// Open the maintenance log, marking this item's entries.
    LogOpen(Option<String>),
    /// The latest maintenance review (or the box to write one).
    ReviewOpen,
    /// Track what discovery found (written to servers/<name>/items.toml).
    Track(crate::config::MaintItem),
    /// Don't suggest it again: (discovery key, its id).
    Ignore(String, String),
    /// Stop tracking an item (one of sentry-server's own; a YAML one is edited there).
    Untrack(String),
    /// Start a workflow (its start box first).
    StartWorkflow(String),
    /// Ask Claude how to fix an audit finding (the consent box first).
    FixFinding(String),
    /// The workflows are read again (`r` on screen 0).
    ReloadWorkflows,
    /// Open a workflow's file in $EDITOR (read again after).
    EditWorkflow(std::path::PathBuf),
    /// The current step's log, in the pane.
    StepLog,
    /// Select the first Maintenance recommendation whose key starts with this.
    MaintFind(String),
    /// Select an item's row on Maintenance.
    MaintJump(String),
    /// Claude writes the plan (after the confirm box): item, the new plan, the request.
    PlanWrite(String, PlanDoc, String),
    /// Look at a maintenance item again later (`z`).
    Snooze(String, jiff::civil::Date),
    /// Ask for an optional note, then save the plan (`p`).
    PlanNote(String, PlanDoc),
    /// Drop an item's plan (`x`, after a confirm).
    PlanDrop(String),
    /// A plan without a workflow, carried out by hand: close it and log the change.
    PlanDoneByHand(String),
    /// Open server_config.yaml in $EDITOR, then reload it.
    EditConfig,
    /// Open a conversation with Claude showing what it would send (a choice's option);
    /// nothing is sent before Enter. Applying something opens an apply session.
    AskConsent(Box<sentry_core::claude::Ask>),
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
    /// Open this server's tasks.toml in $EDITOR (read again after).
    EditTasks,
}

/// Where the answer to read requests goes back to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReadsFor {
    Chat,
    Plan,
}

/// A workflow's `[vars]` being asked for, one at a time, before it starts.
#[derive(Clone, Debug)]
pub struct VarInput {
    workflow: String,
    /// (name, prompt, default), in the order asked.
    asks: Vec<(String, String, Option<String>)>,
    values: BTreeMap<String, String>,
    /// Why the last answer wasn't taken.
    note: Option<String>,
}

/// What the one input line in the key bar asks for.
#[derive(Clone, Debug)]
pub enum Prompt {
    /// A workflow's values, before it starts.
    WfVar(VarInput),
    /// A note for the entry a run, a plan or a task just wrote (optional).
    LogNote(Box<crate::maint::log::LogEntry>),
    /// A note added to an entry from Records.
    LogAddNote(Box<crate::maint::log::LogEntry>),
    /// A note for Claude before it plans an item (optional).
    PlanNote(String, Box<PlanDoc>),
    /// What to change in an item's plan.
    PlanRevise(String),
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
            Prompt::PlanNote(id, plan) => format!(
                "plan {id} → {} · a note (optional): ",
                plan.head.to.as_deref().unwrap_or("retire")
            ),
            Prompt::PlanRevise(_) => "revise the plan: ".into(),
        }
    }

    fn enter_word(&self) -> &'static str {
        match self {
            Prompt::WfVar(_) => "next",
            Prompt::PlanRevise(_) => "send",
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
        Option<crate::maint::Change>,
    ),
    BeginWith(String, BTreeMap<String, String>),
    Go,
    Skip(bool),
    Done,
    Retry,
    Abandon,
    Close,
}

/// A numbered choice between actions.
pub type Choice = modal::Choice<Effect>;

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

pub struct App {
    pub remote: Remote,
    tx: Sender<Ev>,
    pub theme: Theme,
    keys: Keymap,
    pub store: Store,
    /// The screen in view.
    pub screen: ScreenId,
    screens: Screens,
    modal: Option<Modal>,
    /// What answering no (n, Esc) to a box does, for the box with that title (usually none).
    modal_no: Option<(String, Vec<Effect>)>,
    toast: Option<frame::Toast>,
    /// When each fetch of the screen in view is next due.
    due: HashMap<Kind, Instant>,
    /// While waiting for a reboot: when the boot id is read next.
    reboot_probe: Option<Instant>,
    /// Something wrong in `[keys]`, said once the TUI is up.
    keys_warning: Option<String>,
    pane: Option<Pane>,
    choice: Option<Choice>,
    suspend: Option<(Cmd, String, Vec<Kind>)>,
    /// The suspended command reboots the server.
    suspend_reboot: bool,
    /// The suspended command is the inventory read (`I`).
    suspend_inventory: bool,
    /// When the last inventory was read.
    inventory_at: Option<jiff::Timestamp>,
    /// The maintenance change the running workflow makes (logged when it ends).
    wf_change: Option<crate::maint::Change>,
    /// The run already written to the maintenance log.
    wf_logged: Option<std::path::PathBuf>,
    /// When the last maintenance run ended (a read with sudo before it is out of date).
    last_change_at: Option<jiff::Timestamp>,
    /// After the log note: offer to read the server again (the run changed what was read).
    offer_reread: bool,
    /// Tests: the last entry written with a note.
    pub last_log: Option<crate::maint::log::LogEntry>,
    /// The suspended command edits the config (reload it afterwards).
    suspend_edit: bool,
    /// Claude writing a plan, in the background.
    writer: Option<planview::Writer>,
    /// The Plan view: the item shown, and lines scrolled from the top.
    plan_view: Option<(String, usize)>,
    /// The Review window (`R` on Maintenance).
    review_view: Option<sentry_core::tui::reviewview::ReviewView>,
    /// The Log view (`v` on Maintenance, `:log`).
    /// Records (`v`, `R`, `:log`): tasks, log, plans, reviews, what's put off.
    pub rec_view: Option<sentry_core::tui::records::Records>,
    /// The suspended command runs Claude's read requests.
    suspend_reads: Option<(Vec<Vec<String>>, ReadsFor)>,
    run_seq: u64,
    /// Rebooting: since when, and the boot id it had.
    reboot_wait: Option<(Instant, String)>,
    /// The workflow run in progress on this server.
    pub wf: Option<Session>,
    wf_entries: Vec<Entry>,
    /// The same, each with its last run (screen 0's list).
    wf_list: Vec<sentry_core::tui::wflist::WfInfo>,
    /// Where they come from (shown with the run).
    wf_dir: String,
    /// A step running with the terminal handed over, and where its output is captured.
    suspend_step: Option<(usize, String)>,
    /// The stream id of a workflow's reboot command.
    wf_reboot_id: Option<u64>,
    /// A workflow reboot with the terminal handed over: the boot id it had.
    reboot_old: Option<String>,
    chat: Option<Chat>,
    /// Applying something with Claude: the one session, start to finish.
    apply: Option<sentry_core::apply::session::Session>,
    /// sudo's check for the session running (stream id; true: the password's check).
    apply_aux: Option<(u64, bool)>,
    /// The line being typed in the key bar: a `/` filter, a `:` command, or a prompt.
    input: Input<Prompt>,
    /// Each screen's `/` filter.
    filters: HashMap<ScreenId, String>,
    pub quit: bool,
    pub dirty: bool,
    /// Fixed clock for snapshot tests.
    pub now_override: Option<jiff::Timestamp>,
    /// Tests: never start a fetch.
    pub offline: bool,
}

impl App {
    pub fn new(remote: Remote, tx: Sender<Ev>) -> Self {
        // The same `[keys]` as sentry's (the other program's screens in it are skipped).
        let (keys, warnings) = Keymap::new(&SCREENS, &sentry_core::config::Config::load().0.keys);
        Self {
            remote: remote.with_inventory(),
            tx,
            theme: Theme::detect(),
            keys,
            store: Store::default(),
            screen: ScreenId::Dash,
            screens: Screens::default(),
            modal: None,
            modal_no: None,
            toast: None,
            due: HashMap::new(),
            reboot_probe: None,
            keys_warning: warnings.into_iter().next(),
            pane: None,
            choice: None,
            suspend: None,
            suspend_reboot: false,
            suspend_inventory: false,
            inventory_at: None,
            wf_change: None,
            wf_logged: None,
            last_change_at: None,
            offer_reread: false,
            last_log: None,
            suspend_edit: false,
            writer: None,
            plan_view: None,
            rec_view: None,
            review_view: None,
            suspend_reads: None,
            run_seq: 0,
            reboot_wait: None,
            wf: None,
            wf_entries: Vec::new(),
            wf_list: Vec::new(),
            wf_dir: "~/.config/sentry/server-workflows/".into(),
            suspend_step: None,
            wf_reboot_id: None,
            reboot_old: None,
            chat: None,
            apply: None,
            apply_aux: None,
            input: Input::None,
            filters: Default::default(),
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
            let keep = sentry_core::config::Config::load().0.retention;
            sentry_core::maint::retention::purge(
                &self.remote.name,
                &crate::workflow::root(&self.remote.name),
                &keep,
                jiff::Timestamp::now(),
            );
            sentry_core::maint::retention::cap_reports(
                &crate::audit::reports_dir(&self.remote.name),
                keep.reports,
            );
            self.wf = Session::resume(&self.remote);
            // A run left in progress: show it (its auto steps wait until it's open).
            if self.wf.is_some() {
                self.screen = ScreenId::Upgrade;
            }
            self.inventory_at = crate::inventory::load(&self.remote.name).map(|c| c.fetched_at);
            self.store.upstream_at =
                crate::maint::upstream::load(&self.remote.name).map(|c| c.fetched_at);
            // Before the old plans move: their file also held the review dates.
            self.store.later = sentry_core::maint::later::load(&self.remote.name);
            crate::maint::migrate_plans(&self.remote.name);
            self.store.plans = crate::maint::plan::list(&self.remote.name);
            self.store.review = crate::maint::review::latest(&self.remote.name);
            self.store.tasks = sentry_core::maint::tasks::load(&self.remote.name);
            self.store.log = crate::maint::log::list(&self.remote.name);
            self.last_change_at = self
                .store
                .log
                .first()
                .and_then(|e| e.head.ended.or(e.head.started));
            self.load_wf_entries();
        }
        self.enter(self.screen, now);
        if let Some(w) = self.keys_warning.take() {
            self.toast(&w);
        }
    }

    fn fetch(&mut self, k: Kind) {
        if self.offline {
            return;
        }
        let (r, tx) = (self.remote.clone(), self.tx.clone());
        self.store.fetch(k, &r, &tx);
    }

    /// Switch screens; what the screen shows is fetched right away, and from then on only
    /// what it polls.
    pub fn enter(&mut self, id: ScreenId, now: Instant) {
        self.screen = id;
        if id == ScreenId::Upgrade {
            if self.wf_entries.is_empty() && !self.offline {
                self.load_wf_entries();
            }
            // Its auto steps may run now that it's in view.
            if let Some(s) = self.wf.as_mut() {
                s.armed = true;
            }
        }
        self.due.clear();
        for p in Screens::polls(id, &self.remote.cfg) {
            self.fetch(p.kind);
            if let Some(every) = p.every {
                self.due.insert(p.kind, now + every);
            }
        }
        let e = self.with_screens(|s, v, _| s.on_enter(id, v));
        self.apply(e, now);
        self.tick(now);
        self.dirty = true;
    }

    /// The screens with the view they act on (the view borrows the rest of the app).
    fn with_screens<R>(&mut self, f: impl FnOnce(&mut Screens, &View, &Remote) -> R) -> R {
        let mut s = std::mem::take(&mut self.screens);
        let cur = s.cur(self.screen);
        let r = f(&mut s, &self.view_at(cur), &self.remote);
        self.screens = s;
        r
    }

    pub fn tick(&mut self, now: Instant) {
        if self.chat.as_ref().is_some_and(|c| c.running() && !c.hidden)
            || self
                .apply
                .as_ref()
                .is_some_and(|s| s.busy() && !s.chat.hidden)
        {
            self.dirty = true;
        }
        if self.toast.as_ref().is_some_and(|t| t.over(now)) {
            self.toast = None;
            self.dirty = true;
        }
        if self.reboot_wait.is_some() && self.reboot_probe.is_none_or(|t| now >= t) {
            // Every 2 s on any screen until the boot id changes.
            self.fetch(Kind::Probe);
            self.reboot_probe = Some(now + Duration::from_secs(2));
        }
        if self.screen == ScreenId::Upgrade {
            self.wf_auto();
        }
        // Only what the screen in view polls.
        for p in Screens::polls(self.screen, &self.remote.cfg) {
            if let Some(every) = p.every
                && self.due.get(&p.kind).is_none_or(|t| now >= *t)
            {
                self.fetch(p.kind);
                self.due.insert(p.kind, now + every);
            }
        }
    }

    pub fn next_due(&self, now: Instant) -> Instant {
        let mut due = now + Duration::from_secs(60);
        for t in self.due.values() {
            due = due.min(*t);
        }
        if let Some(t) = self.reboot_probe.filter(|_| self.reboot_wait.is_some()) {
            due = due.min(t);
        }
        if let Some(t) = &self.toast {
            due = due.min(t.until());
        }
        // A chat or an apply session working in view: its clocks tick.
        if self.chat.as_ref().is_some_and(|c| c.running() && !c.hidden)
            || self
                .apply
                .as_ref()
                .is_some_and(|s| s.busy() && !s.chat.hidden)
        {
            due = due.min(now + Duration::from_secs(1));
        }
        due.max(now)
    }

    pub fn on_event(&mut self, ev: Ev, now: Instant) {
        match ev {
            Ev::Key(k) => self.on_key(k, now),
            Ev::Paste(text) => self.on_paste(&text),
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
                self.keep_maint_selection();
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
        if self.apply_stream(id, &m) {
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
                    if c.hidden {
                        self.toast("Claude answered · A opens the chat");
                    }
                    self.chat_edits();
                    self.offer_reads(ReadsFor::Chat);
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
                    let Some(s) = self.wf.as_mut() else { return };
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
        self.toast = Some(frame::Toast::new(s));
        self.dirty = true;
    }

    fn view(&self) -> View<'_> {
        self.view_at(self.screens.cur(self.screen))
    }

    /// The view with `cur` as the row selected on the screen in view.
    fn view_at(&self, cur: usize) -> View<'_> {
        View {
            t: &self.theme,
            s: &self.store,
            cfg: &self.remote.cfg,
            name: &self.remote.name,
            cur,
            now: self.now_override.unwrap_or_else(jiff::Timestamp::now),
            filter: self
                .filters
                .get(&self.screen)
                .map(String::as_str)
                .filter(|f| !f.is_empty() && Screens::filterable(self.screen)),
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
            wf: self.wf.as_ref(),
            wf_list: &self.wf_list,
        }
    }

    /// What's in front now, for [`frame::layer`]: who gets a key or a paste, and whose keys
    /// the key bar names.
    fn open(&self) -> frame::Open {
        frame::Open {
            run: self.pane.is_some(),
            choice: self.choice.is_some(),
            modal: self.modal.is_some(),
            apply: self.apply.as_ref().is_some_and(|s| !s.chat.hidden),
            chat: self.chat.as_ref().is_some_and(|c| !c.hidden),
            input: self.input.is_open(),
            docs: self.rec_view.is_some() || self.plan_view.is_some() || self.review_view.is_some(),
        }
    }

    /// A paste goes to the input that has the focus, whole; with none, it does nothing (its
    /// letters must never act as keys).
    fn on_paste(&mut self, text: &str) {
        self.dirty = true;
        match frame::layer(&self.open()) {
            Layer::Apply => {
                if let Some(s) = self.apply.as_mut() {
                    s.paste(text);
                }
            }
            Layer::Chat => {
                if let Some(c) = self.chat.as_mut().filter(|c| !c.running()) {
                    c.paste(text);
                }
            }
            Layer::Input => self.input.paste(text),
            Layer::Run | Layer::Choice | Layer::Modal | Layer::Docs | Layer::Screen => {}
        }
    }

    /// The workflow whose values are being asked for.
    fn asking_vars(&self) -> Option<&str> {
        match &self.input {
            Input::Prompt(Prompt::WfVar(v), _) => Some(&v.workflow),
            _ => None,
        }
    }

    fn on_key(&mut self, k: KeyEvent, now: Instant) {
        self.dirty = true;
        self.on_key_inner(k, now);
        if self.screen == ScreenId::Maint {
            self.screens.maint.sel = super::screens::maint::row_key(&self.view());
        }
    }

    /// The lists changed: Maintenance stays on the row it was on, and the cursor in view
    /// stays inside its list.
    fn keep_maint_selection(&mut self) {
        let id = self.screen;
        self.with_screens(|s, v, _| s.clamp(id, v));
    }

    fn on_key_inner(&mut self, k: KeyEvent, now: Instant) {
        use modal::{Answer, Pick};
        match frame::layer(&self.open()) {
            Layer::Run => return self.pane_key(k),
            Layer::Choice => {
                let n = self.choice.as_ref().map_or(0, |c| c.options.len());
                match modal::pick(&k, n) {
                    Pick::Option(i) => {
                        if let Some(c) = self.choice.take() {
                            self.apply(c.options[i].1.clone(), now);
                        }
                    }
                    Pick::Close => self.choice = None,
                    Pick::Stay => {}
                }
                return;
            }
            Layer::Modal => {
                let has_yes = self.modal.as_ref().is_some_and(|m| m.yes.is_some());
                match modal::answer(&k, has_yes) {
                    Answer::Yes => {
                        self.modal_no = None;
                        if let Some((_, effects)) = self.modal.take().and_then(|m| m.yes) {
                            self.apply(effects, now);
                        }
                    }
                    Answer::No => {
                        let title = self.modal.take().map(|m| m.title);
                        if let Some((t, effects)) = self.modal_no.take()
                            && Some(t) == title
                        {
                            self.apply(effects, now);
                        }
                    }
                    Answer::Stay => {}
                }
                return;
            }
            // The apply session and the chat take raw keys (Backspace, any character).
            Layer::Apply => {
                let fx = self.apply.as_mut().map(|s| s.key(k)).unwrap_or_default();
                return self.apply_fx(fx);
            }
            Layer::Chat => return self.chat_key(k),
            Layer::Input => return self.input_key(k, now),
            Layer::Docs => {
                // Over Records, a plan or a review: a screen key goes there, `:` still works.
                match self.keys.resolve(&k) {
                    Some(Action::Screen(id)) if id != ScreenId::Upgrade => {
                        self.rec_view = None;
                        self.review_view = None;
                        self.plan_view = None;
                        return self.enter(id, now);
                    }
                    Some(Action::Command) => {
                        self.input = Input::Command(String::new());
                        return;
                    }
                    _ => {}
                }
                if self.rec_view.is_some() {
                    self.records_key(k, now);
                } else if self.review_view.is_some() {
                    self.review_view_key(k);
                } else {
                    self.plan_view_key(k, now);
                }
                return;
            }
            Layer::Screen => {}
        }
        let Some(a) = self.keys.resolve(&k) else {
            return;
        };
        match a {
            // C-c on a running step stops the step, as in sentry.
            Action::Interrupt
                if self.screen == ScreenId::Upgrade
                    && self
                        .wf
                        .as_ref()
                        .is_some_and(|s| s.live.as_ref().is_some_and(|l| l.pid.is_some())) =>
            {
                // Its exit ends the step as failed; the run stays.
                if let Some(pid) = self.wf.as_ref().and_then(|s| s.live.as_ref()?.pid) {
                    let _ = kill(pid);
                }
                self.toast("sent SIGTERM to the step");
            }
            // As in sentry: q and Ctrl-C ask first, `:q` quits.
            Action::Quit | Action::Interrupt => {
                self.modal = Some(frame::quit_modal(
                    &self.theme,
                    format!(
                        "Quit sentry-server? Nothing keeps running on {} after exit.",
                        self.remote.name
                    ),
                    Effect::Quit,
                ))
            }
            Action::Command => self.input = Input::Command(String::new()),
            Action::Filter if Screens::filterable(self.screen) => {
                self.input =
                    Input::Filter(self.filters.get(&self.screen).cloned().unwrap_or_default());
            }
            Action::Filter => self.toast("nothing to filter on this screen"),
            Action::Esc
                if self
                    .filters
                    .get(&self.screen)
                    .is_some_and(|f| !f.is_empty()) =>
            {
                self.filters.remove(&self.screen);
                self.keep_maint_selection();
            }
            Action::Screen(id) => self.enter(id, now),
            Action::NextScreen | Action::PrevScreen => {
                let ids = SCREENS.ids;
                let i = ids.iter().position(|s| *s == self.screen).unwrap_or(0);
                let step = if a == Action::NextScreen {
                    1
                } else {
                    ids.len() - 1
                };
                self.enter(ids[(i + step) % ids.len()], now);
            }
            Action::Help => self.show_help(),
            Action::Ask => {
                if let Some(sess) = self.apply.as_mut().filter(|s| s.chat.hidden) {
                    sess.chat.hidden = false;
                } else if let Some(c) = self.chat.as_mut().filter(|c| c.hidden) {
                    c.hidden = false;
                } else if !claude::available() {
                    self.toast("Claude Code isn't installed (or not on PATH)");
                } else {
                    if self.screen == ScreenId::Maint && self.wf_entries.is_empty() {
                        self.load_wf_entries();
                    }
                    let v = self.view();
                    let on_run = self.screen == ScreenId::Upgrade;
                    let ask = match self.wf.as_ref().filter(|_| on_run) {
                        Some(s) => Some(super::ask::ask_run(&v, &self.remote, s)),
                        None => self.screens.ask(self.screen, &v, &self.remote).ok(),
                    };
                    let apply = (self.screen == ScreenId::Maint)
                        .then(|| {
                            super::ask::apply_ask(&v, &self.remote, &|wf| self.workflow_text(wf))
                        })
                        .flatten();
                    match (ask, apply) {
                        (Some(ask), Some(apply)) => {
                            self.choice = Some(claude_choice(&self.theme, apply, ask));
                        }
                        (None, Some(apply)) => self.open_ask(apply),
                        (Some(ask), None) => self.open_ask(ask),
                        (None, None) => {
                            let why = super::ask::nothing_here(self.screen, &v);
                            self.toast(why);
                        }
                    }
                }
            }
            Action::Char('I') => {
                let m = self.fresh_sudo();
                self.inventory_box(m);
            }
            // The rest is the screen's: moving, Enter, r, c and its own letters.
            a => {
                if let Action::Char(c) = a
                    && Screens::uses_root(self.screen, c)
                {
                    self.fresh_sudo();
                }
                let id = self.screen;
                let e = self.with_screens(|s, v, r| s.handle(id, a, v, r));
                self.apply(e, now);
            }
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
                Effect::ChatGrant => self.chat_grant(),
                Effect::ApplyAsk => {
                    if self.wf_entries.is_empty() {
                        self.load_wf_entries();
                    }
                    let v = self.view();
                    let apply =
                        super::ask::apply_ask(&v, &self.remote, &|wf| self.workflow_text(wf));
                    match apply {
                        Some(ask) => self.open_ask(ask),
                        None => self.toast("nothing for Claude to apply here"),
                    }
                }
                Effect::AskConsent(ask) => self.open_ask(*ask),
                Effect::AskWith(ask, apply) => {
                    self.open_ask(*ask);
                    if let Some(c) = self.chat.as_mut() {
                        c.apply_with = Some(*apply);
                    }
                }
                Effect::Confirm(m) => self.modal = Some(m),
                Effect::Choose(c) => self.choice = Some(c),
                Effect::PlanNote(id, plan) => {
                    self.input = Input::Prompt(Prompt::PlanNote(id, Box::new(plan)), String::new());
                }
                Effect::PlanDrop(id) => {
                    if let Some(doc) = self.store.plans.remove(&id)
                        && !self.offline
                    {
                        let _ = crate::maint::plan::close(&doc, PlanStatus::Dropped);
                    }
                    self.plan_view = None;
                    self.toast(&format!("{id}: plan dropped (kept in plans/done/)"));
                }
                Effect::PlanOpen(id) => self.plan_view = Some((id, 0)),
                Effect::PlanApply(id) => self.apply_plan(&id, now),
                Effect::PlanDoneByHand(id) => self.plan_done_by_hand(&id),
                Effect::LogOpen(item) => {
                    self.open_records(sentry_core::tui::records::Section::Log, item)
                }
                Effect::ReviewOpen => self.review_open(),
                Effect::TaskRemove(id) => {
                    let all = super::screens::maint::all_tasks(&self.view());
                    let Some(t) = all.into_iter().find(|t| t.id == id) else {
                        return;
                    };
                    if self.offline {
                        self.store.tasks.retain(|x| x.id != id);
                        return;
                    }
                    match sentry_core::maint::tasks::remove_or_off(
                        &self.remote.name,
                        &t,
                        &self.store.tasks,
                    ) {
                        Ok(off) => self.toast(&if off {
                            format!("{} is off (tasks.toml)", t.title)
                        } else {
                            format!("{} is off the list (tasks.toml)", t.title)
                        }),
                        Err(e) => return self.toast(&format!("couldn't change it: {e}")),
                    }
                    self.store.tasks = sentry_core::maint::tasks::load(&self.remote.name);
                }
                Effect::TaskDone(id) => self.task_done(&id),
                Effect::Track(item) => {
                    let id = item.id.clone();
                    match crate::maint::tracked::track(&self.remote.name, item) {
                        Ok(()) => {
                            self.reload_config();
                            self.toast(&format!(
                                "tracking {id} (servers/{}/items.toml)",
                                self.remote.name
                            ));
                        }
                        Err(e) => self.toast(&format!("couldn't track it: {e}")),
                    }
                }
                Effect::Ignore(key, id) => {
                    match crate::maint::tracked::ignore(&self.remote.name, &key) {
                        Ok(()) => {
                            self.store.maint_found.candidates.retain(|c| c.key != key);
                            self.toast(&format!("{id} won't be suggested again"));
                        }
                        Err(e) => self.toast(&format!("couldn't save it: {e}")),
                    }
                }
                Effect::Untrack(id) => {
                    match crate::maint::tracked::untrack(&self.remote.name, &id) {
                        Ok(true) => {
                            self.reload_config();
                            self.toast(&format!("{id}: no longer tracked"));
                        }
                        Ok(false) => self.toast(&format!(
                            "{id} is in server_config.yaml: remove it there (e opens it)"
                        )),
                        Err(e) => self.toast(&format!("couldn't save it: {e}")),
                    }
                }
                Effect::StartWorkflow(name) => self.wf_start(&name, now),
                Effect::ReloadWorkflows => {
                    if !self.offline {
                        self.load_wf_entries();
                    }
                    self.toast("workflows read again");
                }
                Effect::StepLog => match self.wf.as_ref().and_then(|s| s.step_log()) {
                    Some((title, text)) => {
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
                    }
                    None => self.toast("no log for this step yet"),
                },
                Effect::MaintFind(prefix) => {
                    let v = self.view();
                    if let Some(i) = super::screens::maint::recs(&v)
                        .iter()
                        .position(|r| r.key.starts_with(&prefix))
                    {
                        let key = super::screens::maint::row_key_at(&v, i);
                        self.screens.maint.select(i, key);
                    }
                }
                Effect::FixFinding(id) => {
                    if !claude::available() {
                        self.toast("Claude Code isn't installed (or not on PATH)");
                    } else {
                        let v = self.view();
                        if let Some(f) = super::screens::maint::finding(&v, &id) {
                            let ask = super::ask::ask_finding(&v, &self.remote, f);
                            self.open_ask(ask);
                        }
                    }
                }
                Effect::MaintJump(id) => {
                    if let Some(i) = super::screens::maint::row_of(&self.view(), &id) {
                        self.screens.maint.select(i, Some(format!("item:{id}")));
                    }
                }
                Effect::ReadsSkipped => {
                    let review = self.writer.as_ref().is_some_and(|w| w.review.is_some());
                    self.writer_follow(planview::reads_skipped(review))
                }
                Effect::PlanWrite(id, doc, prompt) => {
                    if !self.offline {
                        let _ = sentry_core::maint::plan::retire(&self.remote.name, &id);
                    }
                    self.write_plan(id, doc, prompt, None)
                }
                Effect::Snooze(id, until) => {
                    let today = jiff::Zoned::now().date();
                    match sentry_core::maint::later::set(&self.remote.name, &id, until, today) {
                        Ok(()) => {
                            self.toast(&format!("{id}: look again {until} (Records › Later)"));
                            // The recommendations filter on the loaded dates: read them again.
                            self.store.later = sentry_core::maint::later::load(&self.remote.name);
                            self.fetch(Kind::Maint);
                        }
                        Err(e) => self.toast(&format!("couldn't save it: {e}")),
                    }
                }
                Effect::EditConfig | Effect::EditTasks | Effect::EditWorkflow(_) => {
                    let editor = std::env::var("VISUAL")
                        .or_else(|_| std::env::var("EDITOR"))
                        .unwrap_or_else(|_| "vi".into());
                    let path = match e {
                        Effect::EditTasks => sentry_core::maint::tasks::path(&self.remote.name),
                        Effect::EditWorkflow(p) => p,
                        _ => crate::config::path(),
                    };
                    let mut words = editor.split_whitespace();
                    let cmd = Cmd::local(words.next().unwrap_or("vi"))
                        .args(words)
                        .arg(path.display().to_string())
                        .timeout(None);
                    self.suspend = Some((cmd, String::new(), Vec::new()));
                    self.suspend_edit = true;
                }
                Effect::SudoReads(reads, to) => {
                    let script = crate::inventory::reads_script(&reads);
                    let cmd = self
                        .remote
                        .sh(&crate::inventory::sudo_wrapper(
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
                        .sh(&crate::inventory::wrapper(&self.remote))
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
                    match crate::audit::set_expected(&self.remote.name, &id, on) {
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

    /// The workflows there are (a server's own, else the seeded ones), with their last runs.
    fn load_wf_entries(&mut self) {
        self.wf_entries = workflow::list_for(&self.remote.name);
        self.wf_list = sentry_core::tui::wflist::load_infos(
            self.wf_entries.clone(),
            &workflow::root(&self.remote.name),
        );
        self.store.workflows = self.wf_entries.iter().map(|e| e.name.clone()).collect();
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
        let loaded = crate::config::load().and_then(|(f, w)| {
            let s = f.servers.get(&self.remote.name).cloned().ok_or_else(|| {
                format!("{} is no longer in server_config.yaml", self.remote.name)
            })?;
            Ok((s, w))
        });
        match loaded {
            Ok((s, warnings)) => {
                let problems = crate::config::lint(&self.remote.name, &s);
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

    /// A workflow for Claude: what it does and its steps, in order.
    fn workflow_text(&self, wf: &str) -> String {
        match self.wf_entries.iter().find(|e| e.name == wf).map(|e| &e.wf) {
            Some(Ok(w)) => {
                let steps: Vec<String> = w
                    .steps
                    .iter()
                    .enumerate()
                    .map(|(i, s)| format!("  {}. {} ({})", i + 1, s.title, s.id))
                    .collect();
                format!(
                    "sentry-server's workflow `{wf}`: {}\nIts steps:\n{}",
                    w.description,
                    steps.join("\n")
                )
            }
            _ => format!("sentry-server's workflow `{wf}`."),
        }
    }

    /// A stream that belongs to the apply session (Claude's turn, a step, sudo's check).
    fn apply_stream(&mut self, id: u64, m: &StreamMsg) -> bool {
        use sentry_core::apply::session::Phase;
        let Some(sess) = self.apply.as_mut() else {
            return false;
        };
        if sess.chat.live.is_some_and(|(cid, _)| cid == id) {
            match m {
                StreamMsg::Line {
                    stderr: false,
                    text,
                } => {
                    for e in claude::parse_line(text) {
                        sess.chat.on_event(e);
                    }
                }
                StreamMsg::Line { stderr: true, text } => sess.chat.on_raw(text.clone()),
                StreamMsg::Exit { code, .. } => {
                    let names = self.wf_infos();
                    let Some(sess) = self.apply.as_mut() else {
                        return true;
                    };
                    let fx = sess.turn_ended(*code, &names);
                    if sess.chat.hidden && !sess.busy() {
                        self.toast("Claude answered · A opens it");
                    }
                    self.apply_fx(fx);
                }
            }
            return true;
        }
        if sess.job.is_some_and(|(jid, _)| jid == id) {
            match m {
                StreamMsg::Line { text, .. } => sess.step_line(text.clone()),
                StreamMsg::Exit { code, .. } => {
                    let fx = sess.step_ended(*code);
                    self.apply_fx(fx);
                    for k in [Kind::Units, Kind::Docker] {
                        self.fetch(k);
                    }
                }
            }
            return true;
        }
        if let Some((_, password)) = self.apply_aux.filter(|(aid, _)| *aid == id) {
            if let StreamMsg::Exit { code, .. } = m {
                self.apply_aux = None;
                let fx = match (password, sess.phase) {
                    (true, Phase::Password { .. }) => sess.password_checked(*code == 0),
                    (false, Phase::SudoCheck) => sess.sudo_checked(*code != 0),
                    _ => Vec::new(),
                };
                self.apply_fx(fx);
            }
            return true;
        }
        false
    }

    /// Carry out what the apply session asks for: commands on the server, edits of local
    /// files (the session does those), Claude's turns with the gateway.
    fn apply_fx(&mut self, fx: Vec<sentry_core::apply::session::Fx>) {
        use sentry_core::apply::session::Fx;
        for f in fx {
            match f {
                Fx::Turn { prompt, shown } => {
                    let Some(sess) = self.apply.as_ref() else {
                        return;
                    };
                    let resume = sess.chat.session.clone();
                    let grants = sess.chat.grants.clone();
                    let r = self.spawn_turn(&prompt, resume.as_deref(), &grants);
                    let Some(sess) = self.apply.as_mut() else {
                        return;
                    };
                    match (r, shown) {
                        (Ok((id, pid)), Some(q)) => sess.chat.begin_turn(&q, id, pid),
                        (Ok((id, pid)), None) => sess.chat.begin_quiet(id, pid),
                        (Err(e), _) => {
                            sess.chat
                                .push(chatmod::Kind::Err, format!("couldn't start claude: {e}"));
                            let names = self.wf_infos();
                            if let Some(sess) = self.apply.as_mut() {
                                let fx = sess.turn_ended(-1, &names);
                                self.apply_fx(fx);
                            }
                        }
                    }
                }
                Fx::Kill(pid) => {
                    let _ = kill(pid);
                }
                Fx::Command { cmd, sudo } => {
                    let Some(sess) = self.apply.as_ref() else {
                        return;
                    };
                    let c = if sudo && sess.secret_ok {
                        self.remote
                            .sh(&sentry_core::apply::sudo::wrap(&cmd))
                            .input(sess.secret.stdin())
                    } else {
                        self.remote.sh(&cmd)
                    }
                    .timeout(None);
                    self.run_seq += 1;
                    let id = self.run_seq;
                    let r = if self.offline {
                        Ok(0)
                    } else {
                        let tx = self.tx.clone();
                        c.stream(move |m| {
                            let _ = tx.send(Ev::Run(id, m));
                        })
                        .map_err(|e| e.to_string())
                    };
                    let Some(sess) = self.apply.as_mut() else {
                        return;
                    };
                    match r {
                        Ok(pid) => sess.step_started(id, pid),
                        Err(e) => {
                            sess.step_line(format!("couldn't start it: {e}"));
                            let fx = sess.step_ended(-1);
                            self.apply_fx(fx);
                        }
                    }
                }
                // Findings on a server are verified by Claude's own read-only check.
                Fx::Reaudit => {}
                Fx::RetryStep => {
                    self.wf_cmd(WfCmd::Retry);
                    self.enter(ScreenId::Upgrade, Instant::now());
                }
                Fx::MarkDone => {
                    let a = self
                        .apply
                        .as_ref()
                        .and_then(|s| s.chat.ask.applying().cloned())
                        .unwrap_or_default();
                    match (a.task, a.plan) {
                        (Some(id), _) => {
                            let e = sentry_core::maint::log::LogEntry::task(
                                &self.remote.name,
                                &id,
                                &id,
                                None,
                            );
                            self.log_event(e);
                        }
                        (None, Some(item)) => {
                            self.apply(vec![Effect::PlanDoneByHand(item)], Instant::now())
                        }
                        _ => {}
                    }
                }
                Fx::CheckSudo | Fx::CheckPassword => {
                    let password = f == Fx::CheckPassword;
                    let Some(sess) = self.apply.as_ref() else {
                        return;
                    };
                    let c = if password {
                        self.remote
                            .sh(sentry_core::apply::sudo::check_script())
                            .input(sess.secret.stdin())
                    } else {
                        self.remote.sh("sudo -n true")
                    }
                    .timeout(None);
                    self.run_seq += 1;
                    let id = self.run_seq;
                    self.apply_aux = Some((id, password));
                    if !self.offline {
                        let tx = self.tx.clone();
                        if let Err(e) = c.stream(move |m| {
                            let _ = tx.send(Ev::Run(id, m));
                        }) {
                            self.apply_aux = None;
                            self.toast(&format!("couldn't run sudo: {e}"));
                        }
                    }
                }
                Fx::StartWorkflow(wf, vars) => {
                    // It can't start (a draft, another run open): the step fails with why, and
                    // Claude hears it, rather than the plan waiting for a run that never comes.
                    if let Some(why) = self.wf_refusal(&wf) {
                        if let Some(sess) = self.apply.as_mut() {
                            sess.chat.hidden = false;
                            let fx = sess.workflow_ended(&wf, false, format!("not started: {why}"));
                            self.apply_fx(fx);
                        }
                        continue;
                    }
                    // The item it changes goes in the log with the run (and its plan, if any,
                    // is closed when the run ends well).
                    let change = self
                        .apply
                        .as_ref()
                        .and_then(|s| s.chat.ask.applying())
                        .and_then(|a| a.item.clone())
                        .map(|item| {
                            let plan = self.store.plans.get(&item);
                            crate::maint::Change {
                                at: jiff::Timestamp::now(),
                                from: plan.and_then(|p| p.head.from.clone()),
                                to: plan.and_then(|p| p.head.to.clone()),
                                item,
                                workflow: wf.clone(),
                                result: String::new(),
                            }
                        });
                    // The plan's values are the base; the step's own come on top.
                    let mut given: BTreeMap<String, String> = change
                        .as_ref()
                        .and_then(|c| self.store.plans.get(&c.item))
                        .filter(|p| p.head.workflow == wf)
                        .map(|p| p.head.vars.clone())
                        .unwrap_or_default();
                    given.extend(vars);
                    self.apply(
                        vec![Effect::Wf(WfCmd::BeginPrefilled(wf.clone(), given, change))],
                        Instant::now(),
                    );
                    let going = self.wf.as_ref().is_some_and(|s| s.live.is_some());
                    if !going || self.asking_vars().is_some() {
                        if let Some(sess) = self.apply.as_mut() {
                            sess.chat.hidden = true;
                        }
                        self.toast(&format!(
                            "{wf} needs you · the plan carries on after its run (A)"
                        ));
                    }
                }
                Fx::PlanDone(item) => {
                    // Already closed when its workflow's run ended: nothing left to do.
                    if let Some(doc) = self.store.plans.remove(&item) {
                        if !self.offline {
                            let _ = crate::maint::plan::close(&doc, PlanStatus::Done);
                        }
                        self.plan_view = None;
                        self.toast(&format!("the plan for {item} is done (plans/done/)"));
                    }
                }
                Fx::OpenRun(wf, vars) => {
                    // Its values being asked: they're in front already.
                    let asking = self.asking_vars() == Some(wf.as_str());
                    let running = self
                        .wf
                        .as_ref()
                        .is_some_and(|s| s.wf.name == wf && !s.done());
                    let other = self
                        .wf
                        .as_ref()
                        .filter(|s| s.wf.name != wf && !s.done())
                        .map(|s| s.wf.name.clone());
                    if let Some(other) = other {
                        if let Some(sess) = self.apply.as_mut() {
                            sess.chat.hidden = true;
                        }
                        self.enter(ScreenId::Upgrade, Instant::now());
                        self.toast(&format!(
                            "{other} is in progress: finish it, then A · Enter starts {wf}"
                        ));
                        continue;
                    }
                    if !asking && !running {
                        // It never started (its values dismissed, refused): start it again.
                        self.apply_fx(vec![Fx::StartWorkflow(wf, vars)]);
                        continue;
                    }
                    if let Some(sess) = self.apply.as_mut() {
                        sess.chat.hidden = true;
                    }
                    if running {
                        self.enter(ScreenId::Upgrade, Instant::now());
                    }
                    self.toast("the plan carries on when the run ends · A shows it");
                }
                Fx::Log { ok, body, tags } => {
                    let mut tags = tags;
                    if let Some(i) = self
                        .apply
                        .as_ref()
                        .and_then(|s| s.chat.ask.applying())
                        .and_then(|a| a.item.clone())
                    {
                        tags.push(format!("item:{i}"));
                    }
                    let e = sentry_core::maint::log::LogEntry::event(
                        &self.remote.name,
                        "apply",
                        "apply",
                        ok,
                        &body,
                        &tags,
                        jiff::Timestamp::now(),
                    );
                    self.log_event(e);
                }
                Fx::TaskDone(id) => {
                    let e =
                        sentry_core::maint::log::LogEntry::task(&self.remote.name, &id, &id, None);
                    self.log_event(e);
                }
                Fx::AddTask(t) => self.task_add(*t),
                Fx::Hide => {
                    if let Some(sess) = self.apply.as_mut() {
                        sess.chat.hidden = true;
                    }
                    self.toast("it carries on · A brings it back");
                }
                Fx::Close => self.apply = None,
            }
        }
    }

    /// Why the workflow `name` won't start now, if it won't.
    fn wf_refusal(&mut self, name: &str) -> Option<String> {
        if let Some(s) = self.wf.as_ref().filter(|s| !s.done()) {
            return Some(format!(
                "{} is in progress: finish or abandon it first",
                s.wf.name
            ));
        }
        if self.wf_entries.is_empty() && !self.offline {
            self.load_wf_entries();
        }
        let Some(e) = self.wf_entries.iter().find(|e| e.name == name) else {
            return Some(format!(
                "no workflow {name} in {}",
                self.wf_dir.trim_end_matches('/')
            ));
        };
        if let Some(why) = e.blocked() {
            return Some(format!("{}: {why}", e.path.display()));
        }
        if self.offline {
            return None;
        }
        sentry_core::workflows::state::in_progress_in(&crate::workflow::root(&self.remote.name))
            .map(|cur| {
                format!(
                    "{} is already in progress: finish or abandon it first",
                    cur.state.workflow
                )
            })
    }

    /// How the workflow the apply session waits for is doing, for its step.
    fn wf_glimpse(&self) -> Vec<String> {
        let Some(name) = self.apply.as_ref().and_then(|s| s.waiting_workflow()) else {
            return Vec::new();
        };
        let Some(s) = self.wf.as_ref().filter(|s| s.wf.name == name) else {
            return vec![format!("{name}: waiting to start · Enter opens it")];
        };
        let n = s.wf.steps.len();
        if let Some(l) = &s.live {
            return vec![format!(
                "{name} · step {}/{n}: {}",
                l.idx + 1,
                s.wf.steps[l.idx].title
            )];
        }
        match s.next.idx() {
            Some(i) => vec![format!(
                "{name} · step {}/{n}: {} · it needs you: Enter opens it",
                i + 1,
                s.wf.steps[i].title
            )],
            None => vec![format!("{name} · finishing")],
        }
    }

    /// A workflow run ended: the apply session waiting for it carries on (and shows again).
    fn apply_run_ended(&mut self, e: &crate::maint::log::LogEntry) {
        let Some(sess) = self.apply.as_mut() else {
            return;
        };
        let h = &e.head;
        let note = format!("{} {}: {}", h.workflow, h.result, h.summary);
        let fx = sess.workflow_ended(&h.workflow, h.result == "done", note);
        if !fx.is_empty() || sess.phase != sentry_core::apply::session::Phase::Applying {
            sess.chat.hidden = false;
        }
        self.apply_fx(fx);
    }

    /// When the workflow started from a maintenance item has ended: log the change.
    fn wf_log_change(&mut self) {
        let Some(s) = self.wf.as_ref().filter(|s| s.done()) else {
            return;
        };
        if self.wf_logged.as_ref() == Some(&s.run.dir) {
            return;
        }
        // What the run changed shows at once: the updates waiting, the kernel, the services
        // and containers, and each item's standing (a retirement done) are read again.
        for k in [
            Kind::Host,
            Kind::Apt,
            Kind::Units,
            Kind::Docker,
            Kind::Maint,
        ] {
            let (r, tx) = (self.remote.clone(), self.tx.clone());
            if !self.offline {
                self.store.fetch(k, &r, &tx);
            }
        }
        let Some(s) = self.wf.as_ref() else { return };
        self.wf_logged = Some(s.run.dir.clone());
        use crate::maint::{log, plan};
        use sentry_core::workflows::state::RunStatus;
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
        let mut entry = log::LogEntry::from_run(
            &self.remote.name,
            &s.wf,
            &s.run.state,
            &s.run.dir,
            info.as_ref(),
            None,
        );
        sentry_core::maint::tasks::tag_run(
            &mut entry,
            &super::screens::maint::all_tasks(&self.view()),
        );
        self.apply_run_ended(&entry);
        if !self.offline {
            if let Err(e) = log::write(&entry) {
                self.toast(&format!("couldn't write the maintenance log: {e}"));
            }
            self.store.log = log::list(&self.remote.name);
            self.fetch(Kind::Maint);
        }
        if done {
            self.last_change_at = Some(jiff::Timestamp::now());
            // What was read with sudo is from before this run: offer to read it again.
            self.offer_reread =
                self.store.sudo.value == Some(SudoMode::Password) && self.inventory_at.is_some();
        }
        // What to know next time: asked now, while it's fresh.
        self.input = Input::Prompt(Prompt::LogNote(Box::new(entry)), String::new());
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

    /// The note for the maintenance log, typed: saved with the entry (empty is fine). `add`:
    /// it's added to an entry from Records, not the one a run or task just wrote.
    fn log_note_submit(&mut self, entry: crate::maint::log::LogEntry, note: &str, add: bool) {
        let note = note.trim();
        // From Records: appended, dated, to the entry as it is.
        if add {
            if note.is_empty() {
                return;
            }
            let mut with_note = entry.clone();
            with_note.add_note(note);
            if !self.offline
                && let Err(e) = crate::maint::log::write_replacing(&entry, &with_note)
            {
                return self.toast(&format!("couldn't write the note: {e}"));
            }
            self.last_log = Some(with_note);
            self.store.log = if self.offline {
                self.store.log.clone()
            } else {
                sentry_core::maint::log::list(&self.remote.name)
            };
            self.toast("noted in the maintenance log");
            return self.open_records(sentry_core::tui::records::Section::Log, None);
        }
        self.reread_box();
        if note.is_empty() {
            return;
        }
        // Done by hand (no run): the same entry, with the note.
        if entry.head.run.is_none() {
            let h = &entry.head;
            let task = h.tags.iter().find_map(|t| t.strip_prefix("task:"));
            let with_note = match task {
                Some(id) => sentry_core::maint::log::LogEntry::task(
                    &h.server,
                    id,
                    &self
                        .store
                        .tasks
                        .iter()
                        .find(|t| t.id == id)
                        .map_or(id.to_string(), |t| t.title.clone()),
                    Some(note),
                ),
                None => crate::maint::log::LogEntry::by_hand(
                    &h.server,
                    h.item.as_deref().unwrap_or("?"),
                    &h.kind,
                    h.from.clone(),
                    h.to.clone(),
                    h.plan.as_deref().map(std::path::Path::new),
                    Some(note),
                ),
            };
            if !self.offline
                && let Err(e) = crate::maint::log::write_replacing(&entry, &with_note)
            {
                return self.toast(&format!("couldn't write the note: {e}"));
            }
            self.last_log = Some(with_note);
            return self.toast("noted in the maintenance log");
        }
        let Some(s) = self.wf.as_ref() else { return };
        // Rebuilt with the note (it replaces the entry written when the run ended).
        let info = entry
            .head
            .item
            .as_ref()
            .map(|item| crate::maint::log::ItemInfo {
                item: item.clone(),
                kind: entry.head.kind.clone(),
                risk: entry.head.risk.clone().unwrap_or_default(),
                from: entry.head.from.clone(),
                to: entry.head.to.clone(),
                plan: entry.head.plan.clone().map(Into::into),
            });
        let mut with_note = crate::maint::log::LogEntry::from_run(
            &self.remote.name,
            &s.wf,
            &s.run.state,
            &s.run.dir,
            info.as_ref(),
            Some(note),
        );
        sentry_core::maint::tasks::tag_run(
            &mut with_note,
            &super::screens::maint::all_tasks(&self.view()),
        );
        if !self.offline
            && let Err(e) = crate::maint::log::write(&with_note)
        {
            return self.toast(&format!("couldn't write the note: {e}"));
        }
        self.last_log = Some(with_note);
        self.toast("noted in the maintenance log");
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
        let script = crate::inventory::script(&self.remote);
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
        let inv = match crate::inventory::read_back(&self.remote) {
            Ok(i) => i,
            Err(e) => return self.toast(&format!("couldn't read it back: {e}")),
        };
        let n = inv.outputs.len();
        match crate::inventory::save(&self.remote.name, &inv) {
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
            "read {n} command(s) with sudo · c on Maintenance audits with them"
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
                self.input = Input::Prompt(
                    Prompt::WfVar(VarInput {
                        workflow: name,
                        asks,
                        values: BTreeMap::new(),
                        note: None,
                    }),
                    buf,
                );
                self.dirty = true;
                return;
            }
            WfCmd::BeginPrefilled(name, given, change) => {
                if self.wf.as_ref().is_some_and(|s| !s.done()) {
                    self.toast("a workflow is already in progress");
                    return;
                }
                if self.wf_entries.is_empty() && !self.offline {
                    self.load_wf_entries();
                }
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
                let asks = super::screens::maint::merge_defaults(asks, &given);
                if asks.is_empty() {
                    return self.wf_cmd(WfCmd::BeginWith(name, BTreeMap::new()));
                }
                let buf = asks[0].2.clone().unwrap_or_default();
                self.input = Input::Prompt(
                    Prompt::WfVar(VarInput {
                        workflow: name,
                        asks,
                        values: BTreeMap::new(),
                        note: None,
                    }),
                    buf,
                );
                self.dirty = true;
                return;
            }
            WfCmd::BeginWith(name, vars) => match self.wf_entries.iter().find(|e| e.name == name) {
                Some(e) => match Session::begin(e, &self.remote, vars) {
                    Ok(s) => {
                        self.wf = Some(s);
                        // Its screen: the run is followed there, and its auto steps start.
                        self.enter(ScreenId::Upgrade, Instant::now());
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

    /// Run the next auto step while the run is in view (screen 0).
    fn wf_auto(&mut self) {
        self.wf_log_change();
        if self.screen != ScreenId::Upgrade {
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

    /// A key for the line being typed in the key bar.
    fn input_key(&mut self, k: KeyEvent, now: Instant) {
        match self.input.key(&k) {
            Typed::Filter(f) => {
                self.filters.insert(self.screen, f);
                self.screens.reset_cursor(self.screen);
            }
            Typed::FilterCleared => {
                self.filters.remove(&self.screen);
                self.screens.reset_cursor(self.screen);
            }
            Typed::Command(c) => self.command(c.trim(), now),
            Typed::Submit(p, text) => self.submit(p, text.trim()),
            Typed::Cancelled(Some(p)) => self.cancelled(p),
            Typed::Editing | Typed::FilterKept | Typed::Cancelled(None) => {}
        }
    }

    /// Enter on a prompt: what was asked for is done with the answer.
    fn submit(&mut self, p: Prompt, text: &str) {
        match p {
            // A workflow's values, one at a time: an empty answer takes the default; with
            // none, it's asked again.
            Prompt::WfVar(mut v) => {
                let Some((name, _, default)) = v.current().cloned() else {
                    return;
                };
                let val = match text {
                    "" => default.unwrap_or_default(),
                    s => s.to_string(),
                };
                if val.is_empty() {
                    v.note = Some(format!("{name} needs a value"));
                    self.input = Input::Prompt(Prompt::WfVar(v), String::new());
                    return;
                }
                v.note = None;
                v.values.insert(name, val);
                match v.current().map(|(_, _, d)| d.clone().unwrap_or_default()) {
                    Some(next) => self.input = Input::Prompt(Prompt::WfVar(v), next),
                    None => self.wf_cmd(WfCmd::BeginWith(v.workflow, v.values)),
                }
            }
            Prompt::LogNote(e) => self.log_note_submit(*e, text, false),
            Prompt::LogAddNote(e) => self.log_note_submit(*e, text, true),
            // The plan's note: an empty one is fine.
            Prompt::PlanNote(id, mut plan) => {
                plan.head.note = (!text.is_empty()).then(|| text.to_string());
                if !claude::available() {
                    return self.toast("plans are written by Claude Code, which isn't installed");
                }
                self.ask_for_plan(id, *plan);
            }
            Prompt::PlanRevise(id) => {
                let Some(doc) = self.store.plans.get(&id).cloned() else {
                    return;
                };
                if text.is_empty() {
                    return;
                }
                let session = doc.head.session.clone();
                self.write_plan(id, doc, planview::revise(text), session);
            }
        }
    }

    /// Esc on a prompt.
    fn cancelled(&mut self, p: Prompt) {
        match p {
            Prompt::WfVar(_) => self.toast("not started"),
            Prompt::PlanNote(..) => self.toast("not planned"),
            // No note: what the run changed may still want reading again.
            Prompt::LogNote(_) => self.reread_box(),
            Prompt::LogAddNote(_) | Prompt::PlanRevise(_) => {}
        }
    }

    /// A key for the pane (a command's streamed output, or a log being read).
    fn pane_key(&mut self, k: KeyEvent) {
        use frame::RunKey;
        let Some(p) = self.pane.as_mut() else { return };
        let len = p.lines.len();
        match frame::run_key(&k, p.done.is_none()) {
            RunKey::Close => self.pane = None,
            RunKey::Kill => {
                if let Some(pid) = p.pid {
                    let _ = kill(pid);
                    p.lines.push_back("■ stopping…".into());
                }
            }
            RunKey::Busy => self.toast("running · C-c stops it"),
            RunKey::Scroll(n) => p.scroll = p.scroll.saturating_add_signed(n as isize).min(len),
            RunKey::End => p.scroll = 0,
            RunKey::Top => p.scroll = len,
            RunKey::None => {}
        }
    }

    /// `?`: the screen's keys, laid out as in sentry.
    fn show_help(&mut self) {
        let mut keys = self.screens.hints(self.screen, &self.view());
        // Maintenance: every row key, not only the selected row's.
        if self.screen == ScreenId::Maint {
            let row = ["Enter", "p", "P", "t", "d", "e", "m", "x", "B", "z", "A"];
            keys = sentry_core::tui::maintlist::GRAMMAR
                .iter()
                .copied()
                .chain(keys.into_iter().filter(|(k, _)| !row.contains(k)))
                // Not on the key bar, to keep it to what the row takes.
                .chain([
                    ("w", "the workflows (0)"),
                    ("e", "edit server_config.yaml (a task: its file)"),
                ])
                .collect();
        }
        keys.extend(super::actions::hints(self.screen));
        let footer = format!(
            "Nothing keeps running on {} after sentry-server exits.",
            self.remote.name
        );
        self.modal = Some(frame::help_modal(
            &self.theme,
            &frame::Help {
                screen: self.screen.name(),
                hints: &keys,
                globals: &[("I", "read what needs root, once, with your sudo password")],
                app: "sentry-server",
                commands: ":q  :<screen>  :workflow <name>  :audit now  :log  :refresh",
                footer: &[
                    "Destructive actions: preview → confirm → streamed output.",
                    &footer,
                ],
            },
        ));
    }

    /// `p`, after the note: what Claude is asked, in a confirm box; yes starts the writer.
    fn ask_for_plan(&mut self, id: String, doc: PlanDoc) {
        if self.wf_entries.is_empty() && !self.offline {
            self.load_wf_entries();
        }
        let steps = self
            .wf_entries
            .iter()
            .find(|e| !doc.head.workflow.is_empty() && e.name == doc.head.workflow)
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
            &super::screens::maint::context(&v, &self.remote, s, it),
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
                    crate::maint::plan::path(&self.remote.name, &id).display()
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
        self.start_writer(planview::Writer::new(&id, doc), prompt, resume);
    }

    /// The start box for a workflow: what it does, then `start`.
    /// Enter on a workflow (screen 0, `:wf <name>`): its values are asked when it takes any,
    /// otherwise the box that says what starting it does.
    fn wf_start(&mut self, name: &str, now: Instant) {
        if self.screen != ScreenId::Upgrade {
            self.enter(ScreenId::Upgrade, now);
        }
        if self.wf.as_ref().is_some_and(|s| !s.done()) {
            return self.toast("a workflow is in progress: finish or abandon it first");
        }
        if self.wf_entries.is_empty() && !self.offline {
            self.load_wf_entries();
        }
        let t = self.theme;
        let Some(i) = self.wf_entries.iter().position(|e| e.name == name) else {
            return self.toast(&format!("no workflow {name}"));
        };
        self.screens.upgrade.cur.sel = i;
        let e = &self.wf_entries[i];
        if let Some(why) = e.blocked() {
            self.modal = Some(Modal {
                title: format!("{} can't start", e.name),
                color: t.cyan,
                lines: vec![
                    Line::styled(why, t.s(t.yellow)),
                    Line::styled(
                        format!("Edit with e: {}", widgets::short_home(&e.path)),
                        t.dim(),
                    ),
                ],
                yes: None,
            });
            return;
        }
        if e.wf.as_ref().is_ok_and(|w| !w.vars.is_empty()) {
            return self.wf_cmd(WfCmd::Begin(name.to_string()));
        }
        self.start_box(name);
    }

    fn start_box(&mut self, name: &str) {
        let t = self.theme;
        let Some(e) = self.wf_entries.iter().find(|e| e.name == name) else {
            return self.toast(&format!("no workflow {name}"));
        };
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
    }

    fn writing_review(&self) -> bool {
        self.writer
            .as_ref()
            .is_some_and(|w| w.review.is_some() && w.running())
    }

    /// Claude writes (a plan or a review) in the background; its view opens.
    fn start_writer(&mut self, mut w: planview::Writer, prompt: String, resume: Option<String>) {
        if self.writer.as_ref().is_some_and(|w| w.running()) {
            return self.toast("Claude is already writing: wait for it, or C-c in its view");
        }
        let (os, kernel) = self.store.host.value.clone().unwrap_or_default();
        let profile = if w.review.is_some() {
            self.review_view
                .get_or_insert_with(sentry_core::tui::reviewview::ReviewView::show)
                .brief = false;
            planview::review_profile(&self.remote, &os, &kernel, self.store.sudo.value)
        } else {
            self.plan_view = Some((w.item.clone(), 0));
            planview::profile(&self.remote, &os, &kernel, self.store.sudo.value)
        };
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
                let session = w.session.clone();
                let next = match &w.review {
                    Some(r) => planview::Writer::review(r.clone()),
                    None => planview::Writer::new(&w.item, w.doc.clone()),
                };
                self.start_writer(next, prompt, session);
            }
            _ => self.toast("it isn't being written any more"),
        }
    }

    /// `R` on Maintenance: the review window. A review with changes still to apply shows
    /// them; otherwise the brief, and Enter starts a new one.
    fn review_open(&mut self) {
        use sentry_core::tui::reviewview::ReviewView;
        self.rec_view = None;
        self.plan_view = None;
        self.review_view = Some(if self.writing_review() {
            ReviewView::show()
        } else {
            ReviewView::open(self.store.review.as_ref())
        });
    }

    /// What a review reads and does, shown before one is started.
    fn review_brief(&self) -> Vec<Line<'static>> {
        let t = self.theme;
        if !claude::available() {
            return vec![Line::styled(
                "  Reviews are written by Claude Code, which isn't installed.",
                t.s(t.yellow),
            )];
        }
        let name = &self.remote.name;
        let notes = &self.remote.cfg.maintenance.notes;
        vec![
            Line::raw(""),
            Line::styled(
                format!(
                    "  Claude reviews the maintenance of {name}: every tracked item, what isn't tracked,"
                ),
                t.fg(),
            ),
            Line::styled(
                "  tasks and what's put off, updates and reboots waiting, the maintenance log and upstream's",
                t.fg(),
            ),
            Line::styled(
                "  release notes, then writes what to do now, soon and routinely, and why.",
                t.fg(),
            ),
            Line::raw(""),
            Line::styled(
                "  It ends with how the list should change: tasks to add, remove or change, items to track",
                t.fg(),
            ),
            Line::styled(
                "  or stop tracking, and what can wait. You see those as one list, ticked; Enter applies them",
                t.fg(),
            ),
            Line::styled("  together.", t.fg()),
            Line::raw(""),
            Line::styled(
                format!(
                    "  It reads the web, your notes ({}), and {name} read-only through the gateway; reads",
                    if notes.is_empty() {
                        "none".to_string()
                    } else {
                        notes.join(", ")
                    }
                ),
                t.dim(),
            ),
            Line::styled(
                format!(
                    "  that need root are asked for first. Saved in {}.",
                    sentry_core::tui::widgets::short_home(&crate::maint::review::dir(name))
                ),
                t.dim(),
            ),
            Line::styled(
                "  Sent to Claude through your Claude Code login (Anthropic). Nothing on the server changes.",
                t.s(t.yellow),
            ),
            Line::raw(""),
            Line::styled("  Enter starts the review.", t.s(t.cyan)),
        ]
    }

    /// The view with no `/` filter: a review is about everything on the list.
    fn view_all(&self) -> View<'_> {
        View {
            filter: None,
            ..self.view()
        }
    }

    /// Everything on Maintenance a review's changes may name, and `f` with it.
    fn with_known<R>(&self, f: impl FnOnce(&sentry_core::maint::changes::Known) -> R) -> R {
        let v = self.view_all();
        let tasks = super::screens::maint::all_tasks(&v);
        let rows: Vec<(String, String)> = super::screens::maint::recs(&v)
            .into_iter()
            .map(|r| (r.key, r.title))
            .collect();
        let own: Vec<String> = crate::maint::tracked::load(&self.remote.name)
            .items
            .into_iter()
            .map(|i| i.id)
            .collect();
        let items: Vec<(String, String)> = self
            .remote
            .cfg
            .maintenance
            .items
            .iter()
            .map(|i| {
                (
                    i.id.clone(),
                    format!(
                        "{} risk; defined in {}",
                        i.risk.as_str(),
                        if own.contains(&i.id) {
                            "items.toml"
                        } else {
                            "server_config.yaml"
                        }
                    ),
                )
            })
            .collect();
        let found: Vec<(String, String)> = self
            .store
            .maint_found
            .candidates
            .iter()
            .map(|c| (c.key.clone(), c.what.clone()))
            .collect();
        f(&sentry_core::maint::changes::Known {
            workflows: &self.store.workflows,
            tasks: &tasks,
            rows: &rows,
            later: Some(&self.store.later),
            items: &items,
            found: &found,
        })
    }

    /// What a review is sent.
    fn review_prompt(&self) -> String {
        let changes = self.with_known(|k| sentry_core::maint::changes::request_section(k, true));
        planview::review_request(
            &super::screens::maint::review_context(&self.view_all(), &self.remote),
            &changes,
        )
    }

    /// Enter on the brief: Claude writes the review.
    fn review_start(&mut self) {
        if !claude::available() {
            return self.toast("reviews are written by Claude Code, which isn't installed");
        }
        let prompt = self.review_prompt();
        let doc = crate::maint::review::ReviewDoc::new(&self.remote.name);
        self.start_writer(planview::Writer::review(doc), prompt, None);
    }

    /// Enter on a review's changes: those ticked are applied together, the rest skipped,
    /// and the log says what was done.
    fn review_apply(&mut self) {
        use crate::maint::tracked;
        use sentry_core::maint::{changes, later, log, tasks as tk};
        let Some(mut rd) = self.store.review.clone() else {
            return;
        };
        let name = self.remote.name.clone();
        let derived = crate::maint::cadence_tasks(&self.remote.cfg, &self.store.workflows);
        let mut tasks = self.store.tasks.clone();
        let mut snoozes = self.store.later.clone();
        let mut items = tracked::load(&name);
        let before = items.clone();
        // The ids server_config.yaml defines: never rewritten, changed through items.toml.
        let yaml: Vec<String> = match crate::config::load() {
            Ok((f, _)) if !self.offline => f.servers.get(&name).map_or(Vec::new(), |s| {
                s.maintenance.items.iter().map(|i| i.id.clone()).collect()
            }),
            _ => self
                .item_ids()
                .into_iter()
                .filter(|id| !items.items.iter().any(|i| &i.id == id))
                .collect(),
        };
        let found = self.store.maint_found.candidates.clone();
        let now = jiff::Timestamp::now();
        let (done, skipped, failed) = changes::settle(&mut rd.head.changes, |c| {
            changes::apply(c, &mut tasks, &mut snoozes, &derived, now)
                .or_else(|| tracked::apply(&mut items, c, &yaml, &found))
                .unwrap_or_else(|| Err("not something sentry-server can change".into()))
        });
        if !self.offline {
            let saved = tk::save(&name, &tasks)
                .and_then(|_| later::replace(&name, &snoozes))
                .and_then(|_| {
                    if items == before {
                        Ok(())
                    } else {
                        tracked::save(&name, &items)
                    }
                })
                .and_then(|_| crate::maint::review::save(&rd).map(|_| ()));
            if let Err(e) = saved {
                return self.toast(&format!("couldn't apply the changes: {e}"));
            }
        }
        self.store.tasks = tasks;
        self.store.later = snoozes;
        if done + failed > 0 {
            let entry = log::LogEntry::event(
                &name,
                "review",
                "review",
                failed == 0,
                &changes::summary(&rd.head.changes),
                &[format!("review:{}", rd.file_name())],
                now,
            );
            if self.offline {
                self.store.log.insert(0, entry);
            } else if let Err(e) = log::write(&entry) {
                self.toast(&format!("couldn't write the maintenance log: {e}"));
            } else {
                self.store.log = log::list(&name);
            }
        }
        self.store.review = Some(rd);
        if items != before {
            // What was tracked or ignored isn't "found" any more.
            self.store.maint_found.candidates.retain(|c| {
                !items.ignore.contains(&c.key) && !items.items.iter().any(|i| i.id == c.item.id)
            });
            if self.offline {
                self.remote.cfg = tracked::merged(&self.remote.cfg, &items).into();
                if let Some(st) = self.store.maint.value.as_mut() {
                    st.retain(|s| !items.untracked.contains(&s.id));
                }
            } else {
                self.reload_config();
            }
        } else if !self.offline {
            self.fetch(Kind::Maint);
        }
        self.keep_maint_selection();
        self.toast(&format!(
            "review: {}",
            sentry_core::tui::reviewview::outcome(done, skipped, failed)
        ));
    }

    /// Keys in the Review window: its own, and what they ask for.
    fn review_view_key(&mut self, k: KeyEvent) {
        use sentry_core::tui::reviewview::Fx;
        self.dirty = true;
        let writing = self.writing_review();
        let Some(v) = self.review_view.as_mut() else {
            return;
        };
        match v.key(k, self.store.review.as_mut(), writing) {
            Fx::None => {}
            Fx::Close => self.review_view = None,
            Fx::Start => self.review_start(),
            Fx::Apply => self.review_apply(),
            Fx::Stop => {
                if let Some(pid) = self
                    .writer
                    .as_ref()
                    .filter(|w| w.review.is_some())
                    .and_then(|w| w.live.map(|(_, p)| p))
                {
                    let _ = kill(pid);
                    self.toast("stopped");
                }
            }
        }
    }

    fn item_ids(&self) -> Vec<String> {
        self.remote
            .cfg
            .maintenance
            .items
            .iter()
            .map(|i| i.id.clone())
            .collect()
    }

    /// A task from an apply session's follow-up: into `tasks.toml`.
    fn task_add(&mut self, task: sentry_core::maint::tasks::Task) {
        let mut task = task;
        task.added = Some(jiff::Timestamp::now());
        if !self.offline
            && let Err(e) = sentry_core::maint::tasks::add(&self.remote.name, task.clone())
        {
            return self.toast(&format!("couldn't add it: {e}"));
        }
        let (id, title) = (task.id.clone(), task.title.clone());
        self.store.tasks.retain(|t| t.id != id);
        self.store.tasks.push(task);
        self.toast(&format!("added to Maintenance (6): {title}"));
    }

    /// A task done by hand: logged now (tagged `task:<id>`, which takes it off the list),
    /// then the note box, as for a plan done by hand.
    fn task_done(&mut self, id: &str) {
        let title = super::screens::maint::all_tasks(&self.view())
            .into_iter()
            .find(|t| t.id == id)
            .map_or(id.to_string(), |t| t.title);
        let entry = sentry_core::maint::log::LogEntry::task(&self.remote.name, id, &title, None);
        if !self.offline {
            if let Err(e) = sentry_core::maint::log::write(&entry) {
                return self.toast(&format!("couldn't write the maintenance log: {e}"));
            }
            self.store.log = sentry_core::maint::log::list(&self.remote.name);
        } else {
            self.store.log.insert(0, entry.clone());
        }
        self.last_change_at = Some(jiff::Timestamp::now());
        self.input = Input::Prompt(Prompt::LogNote(Box::new(entry)), String::new());
    }

    /// The writer's turn ended: save its answer as the plan, then any reads it asked for.
    fn writer_turn_ended(&mut self) {
        if let Some(mut rd) = self.writer.as_ref().and_then(|w| w.review.clone()) {
            let (answer, err, session) = self
                .writer
                .as_ref()
                .map(|w| (w.answer.clone(), w.err.clone(), w.session.clone()))
                .unwrap_or_default();
            rd.head.session = session.or(rd.head.session);
            // Waiting for reads that need root: no review yet; ask for them.
            if answer.as_deref().is_some_and(planview::waits_for_reads) {
                if let Some(w) = self.writer.as_mut() {
                    w.review = Some(rd);
                    w.doing = "waiting for reads that need root".into();
                }
                if !self.offline {
                    let reads = crate::gateway::take_reads(&self.remote.name);
                    if reads.is_empty() {
                        return self.writer_follow(planview::reads_skipped(true));
                    }
                    self.reads_box(reads, ReadsFor::Plan);
                }
                return;
            }
            let msg = match (&answer, &err) {
                (Some(a), _) if !a.trim().is_empty() => {
                    let today = jiff::Zoned::now().date();
                    self.with_known(|k| rd.take_answer(a, k, today));
                    match rd.open().len() {
                        0 => "the review is saved: no changes to the list".to_string(),
                        n => format!("the review is saved: {n} changes to apply (Enter)"),
                    }
                }
                (_, err) => format!(
                    "no review: {}",
                    err.clone()
                        .unwrap_or_else(|| "Claude gave no answer".into())
                ),
            };
            if let Some(w) = self.writer.as_mut() {
                w.review = Some(rd.clone());
            }
            if rd.head.status == PlanStatus::Ready {
                if !self.offline
                    && let Err(e) = crate::maint::review::save(&rd)
                {
                    return self.toast(&format!("couldn't save the review: {e}"));
                }
                self.store.review = Some(rd);
                if let Some(v) = self.review_view.as_mut() {
                    *v = sentry_core::tui::reviewview::ReviewView::show();
                }
            }
            self.toast(&msg);
            return self.offer_reads(ReadsFor::Plan);
        }
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
                let reads = crate::gateway::take_reads(&self.remote.name);
                if reads.is_empty() {
                    // Nothing queued after all: have it write the plan.
                    return self.writer_follow(planview::reads_skipped(false));
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
            && let Err(e) = crate::maint::plan::save(&doc)
        {
            return self.toast(&format!("couldn't save the plan: {e}"));
        }
        self.store.plans.insert(item, doc);
        self.toast(&msg);
        self.offer_reads(ReadsFor::Plan);
    }

    /// What Records shows, read now.
    fn records_data(&self) -> sentry_core::tui::records::Data {
        use sentry_core::maint::{log, plan, review};
        use sentry_core::tui::records::{LaterKind, LaterRow};
        let name = &self.remote.name;
        let v = self.view();
        let today = jiff::Zoned::now().date();
        let mut later: Vec<LaterRow> = self
            .store
            .later
            .iter()
            .filter(|(_, d)| **d > today)
            .map(|(k, d)| LaterRow {
                kind: LaterKind::Snoozed(*d),
                key: k.clone(),
                file: "later.toml",
            })
            .collect();
        if !self.offline {
            later.extend(
                crate::audit::load_baseline(name)
                    .findings
                    .into_iter()
                    .map(|k| LaterRow {
                        kind: LaterKind::Expected,
                        key: k,
                        file: "baseline.toml",
                    }),
            );
            let tracked = crate::maint::tracked::load(name);
            later.extend(
                tracked
                    .ignore
                    .into_iter()
                    .chain(tracked.untracked.iter().map(|id| format!("item:{id}")))
                    .map(|k| LaterRow {
                        kind: LaterKind::Ignored,
                        key: k,
                        file: "items.toml",
                    }),
            );
        }
        let home = std::env::var("HOME").unwrap_or_default();
        let dir = sentry_core::maint::root(name).display().to_string();
        sentry_core::tui::records::Data {
            dir: match dir.strip_prefix(&home) {
                Some(r) if !home.is_empty() && !self.offline => format!("~{r}"),
                _ if self.offline => format!("~/.config/sentry/servers/{name}"),
                _ => dir,
            },
            tasks: super::screens::maint::all_tasks(&v),
            log: if self.offline {
                self.store.log.clone()
            } else {
                log::list(name)
            },
            plans: if self.offline {
                Vec::new()
            } else {
                plan::all(name)
            },
            reviews: if self.offline {
                // Tests: the one in memory.
                self.store
                    .review
                    .iter()
                    .map(|d| (review::dir(name).join(d.file_name()), d.clone()))
                    .collect()
            } else {
                review::list(name)
            },
            later,
            audited: v
                .s
                .report
                .value
                .as_ref()
                .and_then(|r| r.as_deref())
                .and_then(|r| r.snapshot.taken_at),
            now: jiff::Timestamp::now(),
        }
    }

    fn open_records(&mut self, s: sentry_core::tui::records::Section, item: Option<String>) {
        self.plan_view = None;
        self.review_view = None;
        self.rec_view = Some(sentry_core::tui::records::Records::new(
            self.records_data(),
            s,
            item,
        ));
    }

    fn records_key(&mut self, k: KeyEvent, now: Instant) {
        use sentry_core::tui::records::{Fx, LaterKind};
        self.dirty = true;
        let Some(r) = self.rec_view.as_mut() else {
            return;
        };
        let Some(fx) = r.key(k.code) else {
            return;
        };
        let t = self.theme;
        let task = r.task().cloned();
        match fx {
            Fx::Close => self.rec_view = None,
            Fx::TaskDo(id) => {
                self.rec_view = None;
                let e = super::screens::maint::task_enter(&self.view(), &id);
                self.apply(e, now);
            }
            // Where it's written: the config (a cadence) or tasks.toml.
            Fx::TaskEvery(_) => {
                self.rec_view = None;
                let e = match task.map(|t| t.source) {
                    Some(sentry_core::maint::tasks::Source::Config) => Effect::EditConfig,
                    _ => Effect::EditTasks,
                };
                self.apply(vec![e], now);
            }
            Fx::TaskRemove(id) => {
                self.rec_view = None;
                self.modal = Some(Modal {
                    title: "Remove this task".into(),
                    color: t.yellow,
                    lines: vec![
                        Line::styled(task.map_or(id.clone(), |t| t.title), t.fg()),
                        Line::styled(
                            "It comes off tasks.toml (a built-in one is turned off there). \
                             The log keeps what was done.",
                            t.dim(),
                        ),
                    ],
                    yes: Some(("remove".into(), vec![Effect::TaskRemove(id)])),
                });
            }
            Fx::TaskDone(id) => {
                self.rec_view = None;
                self.task_done(&id);
            }
            Fx::Note(e) => {
                self.rec_view = None;
                self.input = Input::Prompt(Prompt::LogAddNote(e), String::new());
            }
            Fx::OpenPlan(item) => {
                self.rec_view = None;
                self.plan_view = Some((item, 0));
            }
            Fx::OpenReview(p) => match sentry_core::maint::review::read(&p).or_else(|| {
                self.store
                    .review
                    .clone()
                    .filter(|d| p.ends_with(d.file_name()))
            }) {
                Some(d) => {
                    self.store.review = Some(d);
                    self.rec_view = None;
                    self.review_view = Some(sentry_core::tui::reviewview::ReviewView::show());
                }
                None => self.toast("couldn't read that review"),
            },
            Fx::NewReview => {
                self.rec_view = None;
                self.review_view = Some(sentry_core::tui::reviewview::ReviewView {
                    brief: true,
                    ..Default::default()
                });
            }
            Fx::Undo(row) => {
                let name = self.remote.name.clone();
                match row.kind {
                    LaterKind::Snoozed(_) => {
                        if !self.offline
                            && let Err(e) = sentry_core::maint::later::remove(&name, &row.key)
                        {
                            return self.toast(&format!("later.toml: {e}"));
                        }
                        self.store.later.remove(&row.key);
                        self.fetch(Kind::Maint);
                    }
                    LaterKind::Expected => {
                        self.apply(vec![Effect::Expected(row.key.clone(), false)], now)
                    }
                    // A YAML item a review untracked: tracked again.
                    LaterKind::Ignored if row.key.starts_with("item:") => {
                        let id = row.key.trim_start_matches("item:");
                        if let Err(e) = crate::maint::tracked::retrack(&name, id) {
                            return self.toast(&format!("items.toml: {e}"));
                        }
                        self.reload_config();
                    }
                    LaterKind::Ignored => {
                        if let Err(e) = crate::maint::tracked::unignore(&name, &row.key) {
                            return self.toast(&format!("items.toml: {e}"));
                        }
                        self.fetch(Kind::Maint);
                    }
                    LaterKind::Listener => {}
                }
                self.toast(&format!("{}: back on Maintenance", row.key));
                let item = None;
                self.open_records(sentry_core::tui::records::Section::Later, item);
            }
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
            // Claude alongside: apply this plan, or ask about it.
            KeyCode::Char('A') if !writing => {
                if !claude::available() {
                    return self.toast("Claude Code isn't installed (or not on PATH)");
                }
                if self.wf_entries.is_empty() {
                    self.load_wf_entries();
                }
                let v = self.view();
                let apply =
                    super::ask::apply_item(&v, &self.remote, &id, format!("plan:{id}"), &|wf| {
                        self.workflow_text(wf)
                    });
                match apply {
                    Some(apply) => {
                        let ask = sentry_core::claude::Ask::new(
                            format!("{} · the plan for {id}", self.remote.name),
                            apply.context.clone(),
                            "Is this plan still right for the server as it is now? What would you \
                             check or change first?",
                        );
                        self.choice = Some(claude_choice(&self.theme, apply, ask));
                    }
                    None => self.toast(&format!("{id} isn't tracked any more")),
                }
            }
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
            _ if writing => self.toast("Claude is writing it · C-c stops · Esc goes back"),
            KeyCode::Enter => self.apply_plan(&id, now),
            KeyCode::Char('r') => match self.store.plans.get(&id) {
                Some(d) if d.head.session.is_some() => {
                    self.input = Input::Prompt(Prompt::PlanRevise(id.clone()), String::new())
                }
                Some(_) => self.toast("no Claude session for this plan: p writes a new one"),
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

    /// A plan carried out by hand: it moves to plans/done/, and the change is logged (the
    /// note box follows, as after a run).
    fn plan_done_by_hand(&mut self, id: &str) {
        use crate::maint::{log, plan};
        let Some(doc) = self.store.plans.remove(id) else {
            return;
        };
        self.plan_view = None;
        let path = if self.offline {
            Some(plan::path(&self.remote.name, id))
        } else {
            plan::close(&doc, PlanStatus::Done).ok()
        };
        let entry = log::LogEntry::by_hand(
            &self.remote.name,
            id,
            self.remote
                .cfg
                .maintenance
                .items
                .iter()
                .find(|i| i.id == id)
                .map_or("system", item_kind),
            doc.head.from.clone(),
            doc.head.to.clone(),
            path.as_deref(),
            None,
        );
        if !self.offline {
            if let Err(e) = log::write(&entry) {
                self.toast(&format!("couldn't write the maintenance log: {e}"));
            }
            self.store.log = log::list(&self.remote.name);
            self.fetch(Kind::Maint);
        }
        self.last_change_at = Some(jiff::Timestamp::now());
        self.input = Input::Prompt(Prompt::LogNote(Box::new(entry)), String::new());
    }

    /// Enter in the Plan view: the item's workflow, with the plan's values filled in.
    /// Enter on a ready plan (in the Plan view, or its recommendation): carried out in an
    /// apply session seeded with the plan (its checks, its workflow with the plan's values).
    fn apply_plan(&mut self, id: &str, _now: Instant) {
        let Some(d) = self.store.plans.get(id) else {
            return;
        };
        match d.head.status {
            PlanStatus::Ready => {}
            PlanStatus::Wait => {
                return self.toast("Claude advises waiting: r revises it, or p plans again");
            }
            s => return self.toast(&format!("this plan is {}: p plans again", s.word())),
        }
        if self.wf_entries.is_empty() && !self.offline {
            self.load_wf_entries();
        }
        let v = self.view();
        let ask = super::ask::apply_item(&v, &self.remote, id, id.to_string(), &|wf| {
            self.workflow_text(wf)
        });
        match ask {
            Some(ask) => {
                self.plan_view = None;
                self.open_ask(ask);
            }
            None => self.toast(&format!("{id} isn't tracked any more")),
        }
    }

    /// The workflows sentry-server knows, with their values, for checking a plan's steps.
    fn wf_infos(&self) -> Vec<sentry_core::apply::plan::WfInfo> {
        use sentry_core::apply::plan::WfInfo;
        if self.wf_entries.is_empty() {
            self.store
                .workflows
                .iter()
                .map(|n| WfInfo::from(n.as_str()))
                .collect()
        } else {
            self.wf_entries.iter().map(WfInfo::of).collect()
        }
    }

    /// `:` commands, as in sentry.
    fn command(&mut self, c: &str, now: Instant) {
        let mut parts = c.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("q" | "q!" | "quit" | "qa"), _) => self.quit = true,
            (Some("refresh" | "r"), _) => {
                let id = self.screen;
                let e = self.with_screens(|s, v, r| s.handle(id, Action::Refresh, v, r));
                self.apply(e, now);
            }
            (Some("help" | "h"), _) => {
                let k = ratatui::crossterm::event::KeyEvent::from(
                    ratatui::crossterm::event::KeyCode::Char('?'),
                );
                self.on_key(k, now);
            }
            (Some("audit"), Some("now")) => self.apply(vec![Effect::Fetch(Kind::Audit)], now),
            (Some("log"), _) => self.open_records(sentry_core::tui::records::Section::Log, None),
            (Some("records" | "rec" | "tasks"), _) => {
                self.open_records(sentry_core::tui::records::Section::Tasks, None)
            }
            (Some("plans"), _) => {
                self.open_records(sentry_core::tui::records::Section::Plans, None)
            }
            (Some("reviews"), _) => {
                self.open_records(sentry_core::tui::records::Section::Reviews, None)
            }
            (Some("later"), _) => {
                self.open_records(sentry_core::tui::records::Section::Later, None)
            }
            // As in sentry: screen 0, and Enter on the workflow named.
            (Some("workflow" | "wf"), name) => match name {
                Some(n) => self.wf_start(n, now),
                None => self.enter(ScreenId::Upgrade, now),
            },
            // A screen, by sentry's names (and the ones the tabs had).
            (Some(name), None) => match SCREENS.from_name(name) {
                Some(id) => self.enter(id, now),
                None => self.toast(&format!("unknown command :{c}")),
            },
            _ if c.is_empty() => {}
            _ => self.toast(&format!("unknown command :{c}")),
        }
    }

    /// What Claude may do with what's sent, on this server (shown with the brief).
    fn privacy(&self) -> String {
        format!(
            "Claude may run read-only commands on {} through `sentry-server exec` (nothing \
             that changes it); it can't use ssh.",
            self.remote.name
        )
    }

    /// Open the conversation, nothing sent yet: an apply session, or a chat, showing the
    /// brief; Enter sends it.
    fn open_ask(&mut self, ask: Ask) {
        if !claude::available() {
            self.toast("Claude Code isn't installed (or not on PATH)");
            return;
        }
        if ask.applying().is_some() {
            if let Some(pid) = self.apply.as_ref().and_then(|s| s.chat.live.map(|l| l.1)) {
                let _ = kill(pid);
            }
            let mut sess = sentry_core::apply::session::Session::new(ask);
            sess.chat.privacy = self.privacy();
            self.apply = Some(sess);
            return;
        }
        if let Some((_, pid)) = self.chat.as_ref().and_then(|c| c.live) {
            let _ = kill(pid);
        }
        let mut c = Chat::new(ask);
        c.pending = true;
        c.privacy = self.privacy();
        self.chat = Some(c);
    }

    /// A follow-up in the open chat, as typed (or what sentry offered to send).
    fn ask_turn(&mut self, text: String) {
        let session = self.chat.as_ref().and_then(|c| c.session.clone());
        self.start_turn(ReadsFor::Chat, &text, text.clone(), session);
    }

    /// Start a Claude turn with the gateway, the notes files and `grants`. Offline (tests):
    /// nothing starts; the id is real, the pid 0.
    fn spawn_turn(
        &mut self,
        prompt: &str,
        resume: Option<&str>,
        grants: &[sentry_core::claude::Grant],
    ) -> Result<(u64, u32), String> {
        let (os, kernel) = self.store.host.value.clone().unwrap_or_default();
        // An apply session may read release notes (as plans do): it may have to decide.
        let profile = super::ask::with_web(
            super::ask::profile(&self.remote, &os, &kernel, self.store.sudo.value)
                .with_notes(&self.remote.cfg.maintenance.notes)
                .with_log(&sentry_core::maint::log::dir(&self.remote.name))
                .with_grants(grants),
        );
        self.run_seq += 1;
        let id = self.run_seq;
        if self.offline {
            return Ok((id, 0));
        }
        let cmd = claude::turn_cmd_with(prompt, resume, &profile);
        let tx = self.tx.clone();
        cmd.stream(move |m| {
            let _ = tx.send(Ev::Run(id, m));
        })
        .map(|pid| (id, pid))
        .map_err(|e| e.to_string())
    }

    /// Send one turn to Claude, into the open chat or the background plan.
    fn start_turn(&mut self, to: ReadsFor, prompt: &str, shown: String, resume: Option<String>) {
        let (os, kernel) = self.store.host.value.clone().unwrap_or_default();
        // The gateway, plus the notes files, plus what the user granted in this conversation.
        let grants = self
            .chat
            .as_ref()
            .map(|c| c.grants.clone())
            .unwrap_or_default();
        let profile = super::ask::profile(&self.remote, &os, &kernel, self.store.sudo.value)
            .with_notes(&self.remote.cfg.maintenance.notes)
            .with_log(&sentry_core::maint::log::dir(&self.remote.name))
            .with_grants(&grants);
        let cmd = claude::turn_cmd_with(prompt, resume.as_deref(), &profile);
        self.run_seq += 1;
        let id = self.run_seq;
        let _ = to;
        let Some(c) = self.chat.as_mut() else { return };
        c.pending = false;
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
        let reads = crate::gateway::take_reads(&self.remote.name);
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
                        .map(|a| sentry_core::exec::sh_quote(a))
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
        let inv = match crate::inventory::read_capture(&self.remote, CAPTURE) {
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
                .map(|a| sentry_core::exec::sh_quote(a))
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
            ReadsFor::Plan => {
                let review = self.writer.as_ref().is_some_and(|w| w.review.is_some());
                self.writer_follow(planview::reads_back(&text, review))
            }
            _ if self.chat.is_some() => self.ask_turn(text),
            _ => self.toast("the conversation is closed: the output wasn't sent"),
        }
    }

    fn chat_key(&mut self, k: KeyEvent) {
        use ratatui::crossterm::event::{KeyCode, KeyModifiers};
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let t = self.theme;
        let Some(c) = self.chat.as_mut() else { return };
        if c.pending {
            match k.code {
                KeyCode::Esc => self.chat = None,
                KeyCode::Enter => {
                    let note = std::mem::take(&mut c.input);
                    let mut prompt = c.ask.prompt();
                    let shown = match note.trim() {
                        "" => c.ask.question.lines().next().unwrap_or("").to_string(),
                        n => {
                            prompt.push_str(&format!("\n\nFrom me: {n}"));
                            n.to_string()
                        }
                    };
                    self.start_turn(ReadsFor::Chat, &prompt, shown, None);
                }
                KeyCode::Backspace => {
                    c.input.pop();
                }
                KeyCode::Char(ch) if !ctrl => c.input.push(ch),
                _ => {}
            }
            self.dirty = true;
            return;
        }
        let idle = c.input.is_empty() && !c.busy();
        match k.code {
            KeyCode::Char('c') if ctrl => {
                if let Some((_, pid)) = c.live {
                    let _ = kill(pid);
                    c.push(chatmod::Kind::Info, "stopped");
                }
            }
            // Apply what the chat is about: a session takes the conversation over.
            KeyCode::Char('a') if c.can_apply() => {
                if let Some(c) = self.chat.take()
                    && let Some(apply) = c.apply_with.clone()
                {
                    let mut sess = sentry_core::apply::session::Session::from_chat(c, apply);
                    sess.chat.privacy = self.privacy();
                    self.apply = Some(sess);
                }
            }
            // What Claude was refused: Enter allows it, for this conversation.
            KeyCode::Enter if c.can_allow() => self.chat_grant(),
            // The same, shown first.
            KeyCode::Char('g') if idle && !c.requests.is_empty() => {
                let lines = c.grant_lines(&t);
                self.modal = Some(Modal {
                    title: "Grant files to Claude".into(),
                    color: t.yellow,
                    lines,
                    yes: Some(("grant".into(), vec![Effect::ChatGrant])),
                });
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
                if c.esc() {
                    self.chat = None;
                } else {
                    self.toast("Claude carries on · A brings the chat back");
                }
            }
            // What you typed is what's sent: no box.
            KeyCode::Enter if !c.running() && !c.input.trim().is_empty() => {
                let text = std::mem::take(&mut c.input);
                self.ask_turn(text);
            }
            KeyCode::Backspace => {
                c.input.pop();
            }
            KeyCode::Char(ch) if !ctrl && !c.busy() => c.input.push(ch),
            _ => {}
        }
        self.dirty = true;
    }

    /// `y` on the grant box: back up what Claude may write, grant it, and tell Claude.
    fn chat_grant(&mut self) {
        use sentry_core::claude::{Access, backup, grantable};
        let offline = self.offline;
        let Some(c) = self.chat.as_mut() else { return };
        for g in c.requests.clone() {
            if g.access == Access::Write && grantable(&g).is_ok() {
                let b = if offline {
                    Ok(std::path::PathBuf::from("(offline: no backup)"))
                } else {
                    backup(&g.path)
                };
                match b {
                    Ok(b) => {
                        c.push(
                            chatmod::Kind::Info,
                            format!("backed up {} → {}", g.path, b.display()),
                        );
                        c.watch(&g.path, b);
                    }
                    Err(e) => {
                        // No backup, no write.
                        c.requests.retain(|r| r != &g);
                        c.push(
                            chatmod::Kind::Err,
                            format!("couldn't back up {}: {e} (not granted)", g.path),
                        );
                    }
                }
            }
        }
        if let Some(text) = c.grant() {
            self.ask_turn(text);
        }
    }

    /// After Claude's turn: files it changed (granted, watched) go in the chat and the log.
    fn chat_edits(&mut self) {
        let Some(c) = self.chat.as_mut() else { return };
        let key = c.ask.applying().map(|a| a.key.clone());
        let changed = c.changed();
        for (path, b, before, after) in &changed {
            c.push(
                chatmod::Kind::Info,
                format!(
                    "✎ edited {path} ({before} → {after} lines) · backup {}",
                    b.display()
                ),
            );
        }
        for (path, b, before, after) in changed {
            let tags: Vec<String> = std::iter::once(format!("file:{path}"))
                .chain(key.as_ref().map(|k| format!("apply:{k}")))
                .collect();
            let e = sentry_core::maint::log::LogEntry::event(
                &self.remote.name,
                "edit",
                "edit",
                true,
                &format!(
                    "Claude edited {path} ({before} → {after} lines). Backup: {}",
                    b.display()
                ),
                &tags,
                jiff::Timestamp::now(),
            );
            self.log_event(e);
        }
    }

    /// Something done outside a workflow (a reboot, a fix): into the maintenance log.
    fn log_event(&mut self, e: sentry_core::maint::log::LogEntry) {
        if !self.offline {
            if let Err(err) = sentry_core::maint::log::write(&e) {
                return self.toast(&format!("couldn't write the maintenance log: {err}"));
            }
            self.store.log = sentry_core::maint::log::list(&self.remote.name);
        } else {
            self.store.log.insert(0, e);
        }
        self.last_change_at = Some(jiff::Timestamp::now());
    }

    fn start_run(&mut self, spec: RunSpec) {
        if spec.reboot {
            let e = sentry_core::maint::log::LogEntry::event(
                &self.remote.name,
                "reboot",
                "reboot",
                true,
                &spec.title,
                &[],
                jiff::Timestamp::now(),
            );
            self.log_event(e);
        }
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
            self.load_wf_entries();
            self.store.tasks = sentry_core::maint::tasks::load(&self.remote.name);
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
        let t = self.theme;
        // A run in progress, on every screen but its own.
        let banner = self
            .wf
            .as_ref()
            .filter(|_| self.screen != ScreenId::Upgrade);
        let Some(areas) = frame::layout(f, &t, banner.is_some()) else {
            return;
        };
        let body = areas.body;
        frame::draw_top(f, areas.top, &t, &self.top());
        self.draw_tabs(f, areas.tabs);
        if let Some(s) = banner {
            let n = s.wf.steps.len();
            frame::draw_banner(
                f,
                areas.banner,
                &t,
                &frame::Banner {
                    workflow: &s.wf.name,
                    step: s.next.idx().map(|i| (i + 1, n, s.title(i).to_string())),
                    state: s.state_word(),
                },
            );
        }
        let id = self.screen;
        self.with_screens(|s, v, _| s.render(id, f, body, v));
        if let Some(rv) = &self.review_view {
            let w = self.writer.as_ref().filter(|w| w.review.is_some());
            let path = self.store.review.as_ref().map_or(String::new(), |d| {
                sentry_core::tui::widgets::short_home(
                    &crate::maint::review::dir(&self.remote.name).join(d.file_name()),
                )
            });
            sentry_core::tui::reviewview::draw(
                f,
                body,
                &t,
                rv,
                &sentry_core::tui::reviewview::Shown {
                    doc: self.store.review.as_ref(),
                    writer: w,
                    brief: &self.review_brief(),
                    path: &path,
                },
            );
        } else if let Some(r) = &self.rec_view {
            sentry_core::tui::records::draw(f, body, &t, r);
        } else if let Some((id, scroll)) = &self.plan_view {
            let path = crate::maint::plan::path(&self.remote.name, id)
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
        self.draw_keybar(f, areas.keybar);
        // Whatever is in front sits in the body, over the screen dimmed.
        if let Some(c) = self.chat.as_ref().filter(|c| !c.hidden) {
            widgets::dim_backdrop(f.buffer_mut(), body);
            chatmod::draw(f, body, &t, c);
        }
        if let Some(sess) = self.apply.as_ref().filter(|s| !s.chat.hidden) {
            widgets::dim_backdrop(f.buffer_mut(), body);
            let wf = self.wf_glimpse();
            sentry_core::tui::applyview::draw(f, body, &t, sess, &wf);
        }
        if let Some(m) = &self.modal {
            widgets::dim_backdrop(f.buffer_mut(), body);
            modal::draw(f, body, &t, m);
        }
        if let Some(c) = &self.choice {
            widgets::dim_backdrop(f.buffer_mut(), body);
            modal::draw_choice(f, body, &t, c);
        }
        if let Some(p) = &self.pane {
            widgets::dim_backdrop(f.buffer_mut(), body);
            frame::draw_run(
                f,
                body,
                &t,
                &frame::RunView {
                    title: &p.title,
                    cmd: &p.cmd,
                    len: p.lines.len(),
                    scroll: p.scroll,
                    started: p.started,
                    done: p.done.map(|code| (code, None)),
                },
                p.lines.iter().map(String::as_str),
            );
        }
    }

    /// The top bar: the server, what it runs and how long it's been up; the connection.
    fn top(&self) -> frame::Top<'static> {
        let t = &self.theme;
        let s = &self.store;
        let mut facts = Vec::new();
        if let Some((os, kernel)) = &s.host.value {
            facts.push(os.clone());
            facts.push(format!("kernel {kernel}"));
        }
        if let Some(p) = &s.probe.value {
            facts.push(format!("up {}", sentry_core::fmt::uptime(p.uptime_s)));
        }
        let state = match &s.unreachable {
            Some(_) => ("○ unreachable · retrying".to_string(), t.red),
            None if s.rebooted() => ("● rebooted".to_string(), t.mag),
            None if s.probe.value.is_some() || s.host.value.is_some() => {
                ("● connected".to_string(), t.green)
            }
            None => ("○ connecting…".to_string(), t.dim),
        };
        let now = self
            .now_override
            .unwrap_or_else(jiff::Timestamp::now)
            .to_zoned(jiff::tz::TimeZone::system());
        frame::Top {
            app: "sentry-server",
            subject: self.remote.name.clone(),
            facts,
            state,
            clock: frame::clock(&now),
        }
    }

    /// The strip: sentry's, with this program's screens.
    fn draw_tabs(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let v = self.view();
        let tabs: Vec<sentry_core::tui::frame::Tab> = SCREENS
            .ids
            .iter()
            .copied()
            .map(|id| sentry_core::tui::frame::Tab {
                id,
                badge: match id {
                    ScreenId::Upgrade => self
                        .wf
                        .as_ref()
                        .filter(|s| !s.done())
                        .map(|_| (" ●".to_string(), self.theme.yellow)),
                    _ => self.screens.badge(id, &v),
                },
                filter: self
                    .filters
                    .get(&id)
                    .filter(|_| Screens::filterable(id))
                    .cloned(),
            })
            .collect();
        sentry_core::tui::frame::draw_tabs(f, area, &self.theme, &tabs, self.screen);
    }

    /// The key bar: what's being typed, or the keys of whatever is in front.
    fn draw_keybar(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let toast = self.toast.as_ref().map(|t| t.msg());
        let layer = frame::layer(&self.open());
        // A box or a conversation over the line: its keys, not the line's.
        if layer == Layer::Input
            && let Some(bar) = self.input.bar()
        {
            return frame::draw_keybar(f, area, &self.theme, &bar, toast);
        }
        let hints: frame::Hints = match layer {
            Layer::Run => frame::run_hints(self.pane.as_ref().is_some_and(|p| p.done.is_some())),
            Layer::Choice => frame::CHOICE_HINTS.to_vec(),
            Layer::Modal if self.modal.as_ref().is_some_and(|m| m.yes.is_some()) => {
                frame::CONFIRM_HINTS.to_vec()
            }
            // Their windows have their own key line.
            Layer::Apply | Layer::Chat => Vec::new(),
            // Records, a plan or a review (an info box over one leaves its keys named).
            _ if self.open().docs => self.doc_hints(),
            _ => {
                let mut h = self.screens.hints(self.screen, &self.view());
                h.extend(super::actions::hints(self.screen));
                // sudo asks for a password: say where the root-only data comes from.
                if self.store.sudo.value == Some(SudoMode::Password) {
                    h.push(("I", "read with sudo"));
                }
                // A hidden conversation waiting takes `A` over.
                let hidden = self
                    .apply
                    .as_ref()
                    .filter(|s| s.chat.hidden)
                    .map(|s| {
                        if s.busy() {
                            "applying…"
                        } else {
                            "the apply session"
                        }
                    })
                    .or_else(|| {
                        self.chat
                            .as_ref()
                            .filter(|c| c.hidden)
                            .map(|c| c.hidden_word())
                    });
                frame::with_globals(h, hidden, claude::available())
            }
        };
        frame::draw_keybar(f, area, &self.theme, &frame::KeyBar::Hints(hints), toast);
    }

    /// The keys of Records, a plan or a review, whichever is over the screen.
    fn doc_hints(&self) -> frame::Hints<'_> {
        if let Some(rv) = &self.review_view {
            rv.hints(self.store.review.as_ref(), self.writing_review())
        } else if let Some(r) = &self.rec_view {
            r.hints()
        } else if let Some((id, _)) = &self.plan_view {
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
                    ("A", "claude"),
                    ("r", "revise"),
                    ("x", "drop"),
                    ("j/k PgUp/Dn", "scroll"),
                    ("Esc", "back"),
                ]
            }
        } else {
            Vec::new()
        }
    }
}

impl sentry_core::tui::Ui for App {
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
fn item_kind(it: &crate::config::MaintItem) -> &'static str {
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
        self.store.workflows = e.iter().map(|x| x.name.clone()).collect();
        self.wf_list = e
            .iter()
            .cloned()
            .map(|entry| sentry_core::tui::wflist::WfInfo { entry, last: None })
            .collect();
        self.wf_entries = e;
        self.keep_maint_selection();
    }
    /// Tests: the request waiting in a box (a plan's), what the review window on its brief
    /// would send, or the brief of a conversation just opened.
    pub fn consent_text_any(&self) -> Option<String> {
        match self.modal.as_ref().and_then(|m| m.yes.as_ref()?.1.first()) {
            Some(Effect::PlanWrite(_, _, p)) => Some(p.clone()),
            _ if self.review_view.as_ref().is_some_and(|v| v.brief) => Some(self.review_prompt()),
            _ => self.consent_text(),
        }
    }
    /// Tests: what the conversation just opened would send (nothing sent yet).
    pub fn consent_text(&self) -> Option<String> {
        if let Some(s) = self
            .apply
            .as_ref()
            .filter(|s| s.phase == sentry_core::apply::session::Phase::Brief)
        {
            return Some(s.chat.ask.prompt());
        }
        self.chat
            .as_ref()
            .filter(|c| c.pending)
            .map(|c| c.ask.prompt())
    }
    /// Tests: the apply session.
    pub fn apply_session(&mut self) -> Option<&mut sentry_core::apply::session::Session> {
        self.apply.as_mut()
    }
    /// Tests: Claude's answer to the apply session's turn (nothing was sent).
    pub fn apply_answer_for_test(&mut self, text: &str) {
        let id = self
            .apply
            .as_ref()
            .and_then(|s| s.chat.live.map(|l| l.0))
            .expect("no turn running");
        let line = serde_json::json!({
            "type": "stream_event",
            "event": {"type": "content_block_delta", "delta": {"type": "text_delta", "text": text}}
        })
        .to_string();
        self.on_event(
            Ev::Run(
                id,
                StreamMsg::Line {
                    stderr: false,
                    text: line,
                },
            ),
            Instant::now(),
        );
        self.on_event(
            Ev::Run(
                id,
                StreamMsg::Exit {
                    code: 0,
                    elapsed: std::time::Duration::ZERO,
                },
            ),
            Instant::now(),
        );
    }
    /// Tests: the apply session's running step (or sudo's check) ended (nothing ran).
    pub fn apply_exit_for_test(&mut self, code: i32) {
        let id = self
            .apply
            .as_ref()
            .and_then(|s| s.job.map(|j| j.0))
            .or(self.apply_aux.map(|a| a.0))
            .expect("nothing running");
        self.on_event(
            Ev::Run(
                id,
                StreamMsg::Exit {
                    code,
                    elapsed: std::time::Duration::ZERO,
                },
            ),
            Instant::now(),
        );
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
    /// Tests: the conversation, if one is open.
    pub fn chat_for_test(&self) -> Option<&Chat> {
        self.chat.as_ref()
    }
    /// Tests: `[keys]` as config.toml would give it; what's wrong in it.
    pub fn set_keys_for_test(
        &mut self,
        overrides: &std::collections::BTreeMap<String, String>,
    ) -> Vec<String> {
        let (keys, warnings) = Keymap::new(&SCREENS, overrides);
        self.keys = keys;
        warnings
    }
    /// Tests: what the screen in view fetches again by itself.
    pub fn polled_for_test(&self) -> Vec<Kind> {
        self.due.keys().copied().collect()
    }
    /// Tests: a task lands in `tasks.toml` (as an apply session's follow-up does).
    pub fn add_task_for_test(&mut self, task: sentry_core::maint::tasks::Task) {
        self.task_add(task);
    }
    /// Tests: what a review left in the tracked items' file, were it written.
    pub fn review_for_test(&self) -> Option<&sentry_core::maint::review::ReviewDoc> {
        self.store.review.as_ref()
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

/// Render the whole UI into plain text (snapshot tests).
#[cfg(test)]
pub fn render_to_string(app: &mut App, w: u16, h: u16) -> String {
    frame::render_to_string(w, h, |f| app.draw(f))
}

/// `A` where Claude can help apply something: apply it with Claude, or just ask.
fn claude_choice(t: &Theme, apply: Ask, ask: Ask) -> Choice {
    frame::claude_choice(
        t,
        "sentry-server",
        vec![Effect::AskConsent(Box::new(apply.clone()))],
        vec![Effect::AskWith(Box::new(ask), Box::new(apply))],
    )
}

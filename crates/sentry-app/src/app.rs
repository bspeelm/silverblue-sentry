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
use crate::slot::{Needs, Slot};
use crate::target::{Mail, Target, TargetId};
use sentry_core::exec::{Cmd, ExecError, StreamMsg};
use sentry_core::tui::ScreenId;
use sentry_core::tui::frame;
use sentry_core::tui::input::Input;
use sentry_core::tui::keys::{Action, Keymap};
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
    /// Something a worker of the Config area's found (`cfgarea::agent::Msg`).
    Config(Box<dyn std::any::Any + Send>),
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

/// What belongs to the window, handed to a slot's flows beside the slot itself. While a
/// slot's flow runs, the keymap and the input line here are that slot's own (`Slot::park`),
/// whichever target has the window.
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
    /// Live tests: a session's turns aren't sent to Claude (the test gives its answers);
    /// everything else runs for real.
    pub scripted_turns: bool,
    /// Something wrong in `[keys]`, said once the TUI is up.
    pub(crate) keys_warning: Option<String>,
    /// The slot whose flow runs has the window: its screen is the one in view.
    pub focused: bool,
    /// The slot whose flow runs isn't the one in view: its toasts say whose they are.
    pub(crate) speaker: Option<String>,
    /// The target strip (every target shown, then the Config tab), and which entry is in
    /// view.
    pub(crate) strip: Vec<frame::TargetTab>,
    pub(crate) strip_focus: usize,
    /// How many targets the window has.
    pub(crate) n_targets: usize,
    /// `config.toml` as it is now: read when the window opens and again when it is saved
    /// (or edited) in the Config area. What a slot starts with, instead of the file.
    pub cfg: sentry_core::config::Config,
    /// The other targets that are at work now, by name (this machine's reboot waits for
    /// them).
    pub(crate) others_working: Vec<String>,
    /// A `:` command no slot knew: the window's, if it names a target.
    pub(crate) target_cmd: Option<String>,
    /// The quit box was just opened: with several targets it lists what each has going.
    pub(crate) quit_asked: bool,
    /// Every target the window has, as a session needs to know them (`App::survey`):
    /// what each is, the rules it keeps, how a session elsewhere reaches it.
    pub system: Vec<crate::system::Sys>,
    /// What one slot's flow hands the app for another slot (a session's step `on`
    /// another target, and what comes back): delivered when the flow returns.
    pub(crate) outbox: std::collections::VecDeque<(TargetId, crate::system::Parcel)>,
    /// The security audit: one for every target (`crate::secaudit`).
    pub sec: crate::secaudit::Sec,
    /// What is wrong in the config files, found offline when the window started (every
    /// file's lint, unknown keys, files that don't parse): what the Config area shows.
    pub config_problems: Vec<crate::cfgarea::Problem>,
}

impl Win {
    pub fn toast(&mut self, s: &str) {
        self.toast = Some(frame::Toast::new(match &self.speaker {
            Some(who) => format!("{who} · {s}"),
            None => s.to_string(),
        }));
        self.dirty = true;
    }

    pub fn now(&self) -> jiff::Timestamp {
        self.now_override.unwrap_or_else(jiff::Timestamp::now)
    }

    /// More than one target is open.
    pub fn several(&self) -> bool {
        self.n_targets > 1
    }
}

/// What builds a target around the `Mail` its threads answer through.
pub type Make = Box<dyn FnOnce(Mail) -> Box<dyn Target>>;

/// Builds the target with this id (`local`, `srv:<name>`, `net:<name>`, as `[targets] show`
/// spells them) from the config files in this directory as they are now. None: the files
/// have no such target. The binary's: it alone knows every kind of target.
pub type Maker = Box<dyn Fn(&str, &std::path::Path) -> Option<Make>>;

pub struct App {
    pub slots: Vec<Slot>,
    /// The slot that has the keys and is drawn.
    pub focus: usize,
    pub win: Win,
    tx: Sender<Event>,
    /// Stream ids, unique in the window.
    seq: Arc<AtomicU64>,
    /// The secrets the window's sessions hold: one sweep for what every slot writes.
    sweep: crate::system::Sweep,
    /// When the targets were last surveyed.
    surveyed: Option<Instant>,
    /// `[keys]`: each target's keymap is the defaults for its screens with these on top.
    key_overrides: std::collections::BTreeMap<String, String>,
    /// The slot whose command has the terminal.
    handed: Option<usize>,
    /// The Config area: part of the window, not a target. It has the keys and the frame
    /// while `in_config`.
    pub config: crate::cfgarea::ConfigArea,
    /// The Config tab has the window. `focus` is then the slot that had it before (its
    /// keymap and input line stay in `win`): no slot is in view, all of them run on.
    pub in_config: bool,
    /// The Config area's editor has the terminal.
    config_handed: bool,
    /// How a target the files gained is built (`App::set_maker`).
    maker: Option<Maker>,
}

impl App {
    /// The window with one target in it. `make` builds the target around the `Mail` its
    /// threads answer through. More targets: [`App::add`].
    pub fn new(tx: Sender<Event>, id: &str, make: impl FnOnce(Mail) -> Box<dyn Target>) -> Self {
        let cfg = sentry_core::config::Config::load().0;
        sentry_core::claude::set_command(&cfg.agent.command);
        let mut app = Self {
            slots: Vec::new(),
            focus: 0,
            win: Win {
                theme: Theme::detect(),
                keys: Keymap::default(),
                toast: None,
                input: Input::None,
                modal: None,
                quit: false,
                dirty: true,
                at: Instant::now(),
                now_override: None,
                offline: false,
                scripted_turns: false,
                keys_warning: None,
                focused: true,
                speaker: None,
                strip: Vec::new(),
                strip_focus: 0,
                n_targets: 0,
                cfg: cfg.clone(),
                others_working: Vec::new(),
                target_cmd: None,
                quit_asked: false,
                system: Vec::new(),
                outbox: Default::default(),
                sec: Default::default(),
                config_problems: Vec::new(),
            },
            config: crate::cfgarea::ConfigArea::new(tx.clone()),
            in_config: false,
            config_handed: false,
            maker: None,
            tx,
            seq: Arc::new(AtomicU64::new(0)),
            sweep: Default::default(),
            surveyed: None,
            // The same `[keys]` for every target (another target's screens in it are skipped).
            key_overrides: cfg.keys,
            handed: None,
        };
        app.add(id, make);
        app
    }

    /// One more target in the window, after the ones there: its place in the strip. It
    /// costs nothing until it first has the window (`App::focus`).
    pub fn add(&mut self, id: &str, make: impl FnOnce(Mail) -> Box<dyn Target>) -> usize {
        let mail = Mail::new(self.tx.clone(), id, self.seq.clone());
        let target = make(mail.clone());
        let (keys, warnings) = Keymap::new(target.ident().screens, &self.key_overrides);
        let mut slot = Slot::new(target, mail);
        slot.sweep = self.sweep.clone();
        self.surveyed = None;
        if self.slots.is_empty() {
            self.win.keys = keys;
            self.win.keys_warning = warnings.into_iter().next();
        } else {
            slot.keys = keys;
        }
        self.slots.push(slot);
        self.win.n_targets = self.slots.len();
        self.slots.len() - 1
    }

    /// How a target that a save adds to the config files is built (the binary registers
    /// what its own start uses).
    pub fn set_maker(&mut self, maker: Maker) {
        self.maker = Some(maker);
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
        self.win.focused = true;
        (&mut self.slots[self.focus], &mut self.win)
    }

    /// Where the target with this id is in the strip.
    pub fn place(&self, id: &str) -> Option<usize> {
        self.slots.iter().position(|s| s.mail.id() == id)
    }

    /// What slot `i` waits for or is doing, wherever its input line is now.
    pub fn needs(&self, i: usize) -> Needs {
        let s = &self.slots[i];
        s.needs(if i == self.focus {
            &self.win.input
        } else {
            &s.line
        })
    }

    /// Run one of slot `i`'s flows: with the window as that slot sees it (its own keymap and
    /// input line; its toasts named when it isn't the one in view), and afterwards, for a
    /// slot out of view, its strip entry flagged if it now waits for the user.
    pub fn with<R>(&mut self, i: usize, f: impl FnOnce(&mut Slot, &mut Win) -> R) -> R {
        // With several targets, a session may be about to open: what it is told of the
        // others is kept fresh (cheap, and at most every few seconds).
        if self.slots.len() > 1
            && self
                .surveyed
                .is_none_or(|at| self.win.at.duration_since(at) >= SURVEY_EVERY)
        {
            self.survey();
        }
        let r = self.with_one(i, f);
        self.deliver();
        // A slot looked at its files: a security report written since is taken in.
        if std::mem::take(&mut self.win.sec.look) {
            self.sec_look();
        }
        // sentry changed a target, and nothing is at work now: the security audit looks
        // again.
        self.sec_after_change();
        self.deliver();
        if self.win.sec.pending.is_some() {
            self.sec_go();
        }
        r
    }

    /// What a flow handed over for other slots, and whatever those hand on.
    fn deliver(&mut self) {
        let mut rounds = 0;
        while let Some((to, p)) = self.win.outbox.pop_front() {
            rounds += 1;
            if rounds > 10_000 {
                self.win.outbox.clear();
                break;
            }
            if let Some(j) = self.place(&to) {
                self.with_one(j, |s, w| s.parcel(w, p));
            }
        }
    }

    /// How a worker thread answers a slot.
    pub(crate) fn sender(&self) -> Sender<Event> {
        self.tx.clone()
    }

    /// Ask every target what it is and how a session elsewhere reaches it (`Win::system`).
    pub fn survey(&mut self) {
        self.surveyed = Some(self.win.at);
        let mut all = Vec::with_capacity(self.slots.len());
        for i in 0..self.slots.len() {
            all.push(self.with_one(i, |s, w| s.surveyed(w)));
        }
        self.win.system = all;
        // The security audit's task is due again after an upgrade on any target.
        let upgraded: Vec<_> = (0..self.slots.len())
            .map(|i| self.slots[i].upgraded(&self.win))
            .collect();
        if upgraded != self.win.sec.upgraded {
            self.win.sec.upgraded = upgraded;
            self.win.sec.rev += 1;
        }
    }

    pub(crate) fn with_one<R>(&mut self, i: usize, f: impl FnOnce(&mut Slot, &mut Win) -> R) -> R {
        let focus = self.focus;
        if self.slots.len() > 1 {
            self.win.others_working = (0..self.slots.len())
                .filter(|j| *j != i && !self.slots[*j].reboot_waits())
                .filter(|j| self.needs(*j) == Needs::Working)
                .map(|j| self.slots[j].title().to_string())
                .collect();
        }
        // Out of view: another slot has the window, or the Config area does.
        let out = i != focus || self.in_config;
        if i != focus {
            self.slots[focus].park(&mut self.win);
            self.slots[i].park(&mut self.win);
        }
        if out {
            self.win.speaker = Some(self.slots[i].title().to_string());
        }
        self.win.focused = !out;
        self.slots[i].sec_sync(&self.win);
        let r = f(&mut self.slots[i], &mut self.win);
        self.win.focused = true;
        if out {
            self.win.speaker = None;
        }
        if i != focus {
            self.slots[i].park(&mut self.win);
            self.slots[focus].park(&mut self.win);
        }
        if out {
            self.flag(i);
        }
        r
    }

    /// A slot out of view came to something only the user can answer: said once, with the
    /// target's name (its strip entry says so for as long as it waits).
    fn flag(&mut self, i: usize) {
        match self.needs(i) {
            Needs::You(what) if self.slots[i].flagged != Some(what) => {
                self.slots[i].flagged = Some(what);
                let say = format!("{} · needs you: {what}", self.slots[i].title());
                self.win.toast(&say);
            }
            Needs::You(_) => {}
            _ => self.slots[i].flagged = None,
        }
    }

    /// Give slot `to` the window. The first time, the target starts (its records are read,
    /// its first fetches go out, its review at start may follow); after that its screen
    /// comes back into view and is fetched again.
    pub fn focus(&mut self, to: usize, now: Instant) {
        // (Coming back from the Config area, the slot that had the window may be the one.)
        let from_config = std::mem::take(&mut self.in_config);
        if to >= self.slots.len() || (to == self.focus && !from_config) {
            self.in_config = from_config;
            return;
        }
        self.win.at = now;
        let old = self.focus;
        if to != old {
            // What the one left waits for has been seen: it isn't announced again.
            if !from_config {
                self.slots[old].flagged = match self.needs(old) {
                    Needs::You(what) => Some(what),
                    _ => None,
                };
            }
            self.slots[old].park(&mut self.win);
            self.slots[to].park(&mut self.win);
            self.focus = to;
        }
        self.slots[to].flagged = None;
        // What was said about it out of view is on screen now.
        let said = format!("{} · ", self.slots[to].title());
        if self
            .win
            .toast
            .as_ref()
            .is_some_and(|t| t.msg().starts_with(&said))
        {
            self.win.toast = None;
        }
        // Help was about the other target's screen.
        self.win.modal = None;
        self.win.dirty = true;
        self.with(to, |s, w| s.shown(w, now));
    }

    /// Give the Config area the window: no slot is in view (each runs on, as a slot out of
    /// view does), and the area looks at its files.
    pub fn focus_config(&mut self, now: Instant) {
        if self.in_config {
            return;
        }
        self.win.at = now;
        let old = self.focus;
        self.slots[old].flagged = match self.needs(old) {
            Needs::You(what) => Some(what),
            _ => None,
        };
        self.in_config = true;
        self.win.modal = None;
        self.win.dirty = true;
        self.config.targets = self.in_window();
        let fx = self.config.shown(&mut self.win);
        self.config_fx(fx, now);
    }

    /// Before the TUI is up: the window opens on the Config tab (`sentry config`).
    pub fn config_at_start(&mut self) {
        self.in_config = true;
    }

    /// Before the TUI is up, on a first run (no config file is there): the window opens on
    /// the Config tab's setup flow.
    pub fn setup_at_start(&mut self) {
        self.in_config = true;
        self.config.guide_at_start();
    }

    /// The slots in the strip, in its order (one `[targets] show` hides isn't).
    fn visible(&self) -> Vec<usize> {
        (0..self.slots.len())
            .filter(|i| !self.slots[*i].hidden)
            .collect()
    }

    /// The targets the window has, as the Config area names them.
    fn in_window(&self) -> Vec<crate::cfgarea::InWindow> {
        (0..self.slots.len())
            .map(|i| crate::cfgarea::InWindow {
                id: show_id(self.slots[i].mail.id()).to_string(),
                title: self.slots[i].title().to_string(),
                hidden: self.slots[i].hidden,
                working: self.needs(i) == Needs::Working,
                going: match self.slots[i].at_work() {
                    true => {
                        let mut g = self.slots[i].going();
                        if g.is_empty() {
                            g.push("something of its own is still running there".to_string());
                        }
                        g
                    }
                    false => Vec::new(),
                },
            })
            .collect()
    }

    /// What the Config area asked for when its key or event was done.
    fn config_fx(&mut self, fx: Option<crate::cfgarea::Fx>, now: Instant) {
        match fx {
            Some(crate::cfgarea::Fx::Command(line)) => self.target_cmd(&line, now),
            Some(crate::cfgarea::Fx::Changed(files)) => self.config_changed(&files),
            None => {}
        }
        // The setup is done: the first system it added (else this machine) has the window.
        if let Some(id) = self.config.leave_to.take() {
            let to = self
                .place(target_id(&id))
                .filter(|i| !self.slots[*i].hidden)
                .or_else(|| self.visible().first().copied());
            if let Some(to) = to {
                self.focus(to, now);
            }
        }
        self.quit_asked();
    }

    /// The quit box was just opened: with several targets it lists what each has going,
    /// and whatever is staged in the Config area is said (quitting drops it).
    fn quit_asked(&mut self) {
        if !std::mem::take(&mut self.win.quit_asked) {
            return;
        }
        if self.slots.len() > 1 {
            self.quit_box();
        }
        let t = self.win.theme;
        if let (Some(note), Some(m)) = (self.config.quit_note(), self.win.modal.as_mut()) {
            m.lines.push(ratatui::text::Line::raw(""));
            m.lines
                .push(ratatui::text::Line::styled(note, t.s(t.yellow)));
        }
    }

    /// Config files are not what they were (saved in the Config area, or edited): what
    /// follows at once. `config.toml`: every setting the window and its slots took from it
    /// at start. A server's or a network's own file: its slot sees it when it next looks at
    /// its files (`Slot::look`, on focus).
    fn config_changed(&mut self, files: &[sentry_core::cfg::FileId]) {
        if files.contains(&sentry_core::cfg::FileId::App) {
            // (What the file says: a change staged and not saved is nobody's yet.)
            if let Some(cfg) = self.config.app_on_disk() {
                self.configure(cfg);
            }
        }
        self.sync_targets(files);
        self.config.targets = self.in_window();
    }

    /// The targets follow the config files at once, by id: one the files gained gets a slot
    /// (asleep until it first has the window, as at start), one they lost is closed (unless
    /// it is at work: the save box refuses that before writing, so this is a file edited
    /// outside), and one whose file changed looks at it again (`Why::Edited`).
    fn sync_targets(&mut self, files: &[sentry_core::cfg::FileId]) {
        let (added, gone) = self.config.targets_changed();
        let dir = self.config.dir();
        let mut fresh: Vec<TargetId> = Vec::new();
        for id in &added {
            if self.place(target_id(id)).is_some() {
                continue;
            }
            let Some(make) = self.maker.as_ref().and_then(|m| m(id, &dir)) else {
                continue;
            };
            let i = self.add(target_id(id), make);
            self.with_one(i, |s, w| s.pickup(w));
            fresh.push(target_id(id).to_string());
        }
        for id in &gone {
            let Some(i) = self.place(target_id(id)) else {
                continue;
            };
            if self.slots[i].at_work() {
                let say = format!(
                    "{} is no longer in its file, but it is at work: its tab stays until \
                     the next start",
                    self.slots[i].title()
                );
                self.win.toast(&say);
            } else {
                self.close(i);
            }
        }
        if !added.is_empty() || !gone.is_empty() {
            // A new one takes the place it would have at the next start (this machine, the
            // servers, the networks, as the files have them); `[targets] show` then orders
            // and hides as it says.
            if !fresh.is_empty() {
                let order = self.config.targets_on_disk();
                self.reorder(|id| order.iter().position(|t| t == show_id(id)));
            }
            let targets = self.win.cfg.targets.clone();
            self.retarget(&targets);
        }
        // An entry that changed: its target reads its own file again.
        for i in 0..self.slots.len() {
            let id = self.slots[i].mail.id().clone();
            if fresh.contains(&id) || !files.contains(&crate::cfgarea::ConfigArea::file_of(&id)) {
                continue;
            }
            // One that never had the window holds its entry as it was when the window
            // opened, and reads nothing until it starts: it is built again from the file.
            if !id.is_empty()
                && self.slots[i].is_asleep()
                && !self.slots[i].at_work()
                && let Some(make) = self.maker.as_ref().and_then(|m| m(show_id(&id), &dir))
            {
                self.rebuild(i, make);
                continue;
            }
            self.with(i, |s, w| s.look(w));
        }
    }

    /// Slot `i`, which never had the window, built again around its entry as the files say
    /// it now: in its place, hidden or not as it was, asleep as it was.
    fn rebuild(&mut self, i: usize, make: Make) {
        let id = self.slots[i].mail.id().clone();
        let hidden = self.slots[i].hidden;
        self.add(&id, make);
        let Some(mut new) = self.slots.pop() else {
            return;
        };
        new.hidden = hidden;
        let mut old = std::mem::replace(&mut self.slots[i], new);
        old.shutdown();
        self.win.n_targets = self.slots.len();
        self.with_one(i, |s, w| s.pickup(w));
    }

    /// The slots sorted by `place` (None: after the others, as they were). By id: the slot
    /// in view and the one whose command has the terminal stay the ones they were.
    fn reorder(&mut self, place: impl Fn(&str) -> Option<usize>) {
        let focus_id = self.slots[self.focus].mail.id().clone();
        let handed_id = self.handed.map(|i| self.slots[i].mail.id().clone());
        let mut order: Vec<usize> = (0..self.slots.len()).collect();
        order.sort_by_key(|i| (place(self.slots[*i].mail.id()).unwrap_or(usize::MAX), *i));
        if order.iter().enumerate().any(|(to, from)| to != *from) {
            let mut old: Vec<Option<Slot>> = std::mem::take(&mut self.slots)
                .into_iter()
                .map(Some)
                .collect();
            self.slots = order.iter().filter_map(|i| old[*i].take()).collect();
        }
        self.focus = self.place(&focus_id).unwrap_or(0);
        self.handed = handed_id.and_then(|id| self.place(&id));
    }

    /// Close slot `i`: its target leaves the window. Everything that names a slot goes by
    /// id, so the slot in view and the one whose command has the terminal stay the ones
    /// they were; what was addressed to the closed one is dropped. The last slot is never
    /// closed (the window always has a target).
    fn close(&mut self, i: usize) {
        if self.slots.len() <= 1 || i >= self.slots.len() {
            return;
        }
        let id = self.slots[i].mail.id().clone();
        let now = self.win.at;
        // The slot in view goes: another gets the window first (its keymap and input line).
        let moved = i == self.focus;
        if moved {
            let to = self
                .visible()
                .into_iter()
                .find(|j| *j != i)
                .or_else(|| (0..self.slots.len()).find(|j| *j != i))
                .unwrap_or(0);
            self.slots[i].park(&mut self.win);
            self.slots[to].park(&mut self.win);
            self.focus = to;
            self.win.modal = None;
        }
        let focus_id = self.slots[self.focus].mail.id().clone();
        let handed_id = self
            .handed
            .filter(|h| *h != i)
            .map(|h| self.slots[h].mail.id().clone());
        let mut slot = self.slots.remove(i);
        slot.shutdown();
        self.focus = self.place(&focus_id).unwrap_or(0);
        self.handed = handed_id.and_then(|h| self.place(&h));
        self.win.n_targets = self.slots.len();
        // What was on its way to it, and what the security audit kept for it.
        self.win.outbox.retain(|(to, _)| *to != id);
        let sec = &mut self.win.sec;
        sec.asked.retain(|a| a.slot != id);
        sec.again.retain(|a| a.slot != id);
        if sec.pending.as_ref().is_some_and(|(_, who)| *who == id) {
            sec.pending = None;
        }
        let name = crate::secaudit::name(&id).to_string();
        sec.changes.retain(|c| c.target != name);
        sec.rev += 1;
        // What is kept by place is asked again.
        self.surveyed = None;
        self.survey();
        if moved && !self.in_config {
            let to = self.focus;
            self.with(to, |s, w| s.shown(w, now));
        }
        self.win.dirty = true;
    }

    /// `config.toml` is `cfg` from now: `[keys]` (every slot's keymap), `[review]`,
    /// `[retention]`, `[maintenance] notes`, `[ui] terminal` (the target's own copy),
    /// `[agent] command`, `[targets] show`.
    pub fn configure(&mut self, cfg: sentry_core::config::Config) {
        self.key_overrides = cfg.keys.clone();
        for i in 0..self.slots.len() {
            let (keys, _) = Keymap::new(self.slots[i].target.ident().screens, &self.key_overrides);
            // (The keymap of the slot that has, or last had, the window is the window's.)
            if i == self.focus {
                self.win.keys = keys;
            } else {
                self.slots[i].keys = keys;
            }
            self.slots[i].configured(&self.win, &cfg);
        }
        sentry_core::claude::set_command(&cfg.agent.command);
        self.retarget(&cfg.targets);
        self.win.cfg = cfg;
        self.win.dirty = true;
    }

    /// The strip as `[targets] show` says it now, for the targets the window has: their
    /// order, and which are hidden. By id, never by place: the slot in view (and the one
    /// whose command has the terminal) stay the ones they were. A hidden slot is not
    /// closed: it runs on out of view and comes back when it is shown again. (Targets
    /// added to or taken out of the files: the next part.)
    pub fn retarget(&mut self, targets: &sentry_core::config::Targets) {
        let ids: Vec<String> = self
            .slots
            .iter()
            .map(|s| show_id(s.mail.id()).to_string())
            .collect();
        let (mut shown, _) = targets.pick(&ids);
        if shown.is_empty() {
            shown = ids.clone();
        }
        let place = |id: &str| shown.iter().position(|s| s == id);
        let focus_id = self.slots[self.focus].mail.id().clone();
        let handed_id = self.handed.map(|i| self.slots[i].mail.id().clone());
        // Shown ones in `show`'s order, then the hidden ones as they were.
        let mut order: Vec<usize> = (0..self.slots.len()).collect();
        order.sort_by_key(|i| (place(&ids[*i]).unwrap_or(usize::MAX), *i));
        if order.iter().enumerate().any(|(to, from)| to != *from) {
            let mut old: Vec<Option<Slot>> = std::mem::take(&mut self.slots)
                .into_iter()
                .map(Some)
                .collect();
            self.slots = order.iter().filter_map(|i| old[*i].take()).collect();
        }
        for s in &mut self.slots {
            s.hidden = place(show_id(s.mail.id())).is_none();
        }
        self.focus = self.place(&focus_id).unwrap_or(0);
        self.handed = handed_id.and_then(|id| self.place(&id));
        // The slot in view was hidden: the first one shown has the window (or stands behind
        // the Config area) instead.
        if self.slots[self.focus].hidden
            && let Some(to) = self.visible().first().copied()
        {
            let old = self.focus;
            self.slots[old].park(&mut self.win);
            self.slots[to].park(&mut self.win);
            self.focus = to;
            if !self.in_config {
                let now = self.win.at;
                self.with(to, |s, w| s.shown(w, now));
            }
        }
        // What is kept by place is asked again.
        self.surveyed = None;
        if self.slots.len() > 1 {
            self.survey();
        }
        self.win.dirty = true;
    }

    /// Before the TUI is up: the target that has the window when it opens.
    pub fn focus_at_start(&mut self, to: usize) {
        if to < self.slots.len() && to != self.focus {
            self.slots[self.focus].park(&mut self.win);
            self.slots[to].park(&mut self.win);
            self.focus = to;
        }
    }

    /// One of the window's target keys.
    fn target_key(&mut self, a: Action, now: Instant) {
        // The strip: the targets shown, then the Config tab.
        let shown = self.visible();
        let n = shown.len();
        let here = match self.in_config {
            true => n,
            false => shown.iter().position(|i| *i == self.focus).unwrap_or(0),
        };
        let to = match a {
            Action::Target(i) => i as usize,
            Action::NextTarget => (here + 1) % (n + 1),
            Action::PrevTarget => (here + n) % (n + 1),
            _ => return,
        };
        match shown.get(to) {
            Some(i) => self.focus(*i, now),
            None if to == n => self.focus_config(now),
            None => {}
        }
    }

    /// `:local`, `:server <name>`…: the target of that kind whose name starts so (the first
    /// of its kind without a name).
    fn target_cmd(&mut self, line: &str, now: Instant) {
        let mut parts = line.split_whitespace();
        let (word, arg) = (parts.next().unwrap_or(""), parts.next());
        if (word, arg) == (CONFIG_WORD, None) {
            return self.focus_config(now);
        }
        let hit = self.slots.iter().position(|s| {
            let id = s.target.ident();
            let name = id.id.split_once(':').map_or("", |(_, n)| n);
            !s.hidden
                && id.word == word
                && arg.is_none_or(|a| !name.is_empty() && name.starts_with(a))
        });
        match hit {
            Some(i) => self.focus(i, now),
            None => self.win.toast(&format!("unknown command :{line}")),
        }
    }

    /// The quit box, with several targets open: what each still has going is listed.
    fn quit_box(&mut self) {
        let t = self.win.theme;
        let going: Vec<(String, Vec<String>)> = self
            .slots
            .iter()
            .map(|s| (s.title().to_string(), s.going()))
            .filter(|(_, g)| !g.is_empty())
            .collect();
        let Some(m) = self.win.modal.as_mut() else {
            return;
        };
        m.lines = vec![ratatui::text::Line::styled(
            "Quit sentry? Nothing keeps running after exit.",
            t.fg(),
        )];
        for (title, lines) in going {
            m.lines.push(ratatui::text::Line::raw(""));
            m.lines
                .push(ratatui::text::Line::styled(title, t.s(t.cyan)));
            m.lines.extend(
                lines
                    .into_iter()
                    .map(|l| ratatui::text::Line::styled(format!("  {l}"), t.dim())),
            );
        }
    }

    /// Something to say once the TUI is up, ahead of a `[keys]` warning.
    pub fn warn_at_start(&mut self, s: String) {
        self.win.keys_warning = Some(s);
    }

    /// The TUI is up: the target in view starts. The others wait for their first turn in
    /// view, except that a run left in progress is picked up for each now.
    pub fn start(&mut self, now: Instant) {
        self.win.at = now;
        self.sec_load();
        // The config files as the Config area reads them: what is wrong in them is the
        // window's to show (its tab says so).
        self.config.targets = self.in_window();
        self.config.load(&mut self.win);
        if self.in_config {
            match self.config.guide {
                Some(_) => self.config.guide_show(&mut self.win),
                None => self.config.enter(&mut self.win, self.config.screen),
            }
        }
        for i in 0..self.slots.len() {
            self.with(i, |s, w| {
                if w.focused {
                    s.start(w, now)
                } else {
                    s.pickup(w);
                    // (What its log says changed since the security audit's report.)
                    s.note_logged_changes(w);
                }
            });
        }
        if let Some(w) = self.win.keys_warning.take() {
            self.win.toast(&w);
        }
    }

    pub fn enter(&mut self, id: ScreenId, now: Instant) {
        self.win.at = now;
        self.with(self.focus, |s, w| s.enter(w, id, now));
    }

    /// The strip: every target shown, then the Config tab (always there, always last, its
    /// key the next by place). `*` on it: changes staged and not saved; `!`: problems in the
    /// files.
    fn strip(&self) -> (Vec<frame::TargetTab>, usize) {
        let shown = self.visible();
        let mut tabs: Vec<frame::TargetTab> = shown
            .iter()
            .enumerate()
            .map(|(at, i)| frame::TargetTab {
                key: self.win.keys.key_of(Action::Target(at as u8)),
                name: self.slots[*i].title().to_string(),
                mark: match self.needs(*i) {
                    Needs::Nothing => frame::Mark::None,
                    Needs::Working => frame::Mark::Working,
                    Needs::You(_) => frame::Mark::You,
                },
                auto: self.slots[*i].auto,
                accent: None,
            })
            .collect();
        tabs.push(frame::TargetTab {
            key: self.win.keys.key_of(Action::Target(shown.len() as u8)),
            name: match self.config.pending.is_empty() {
                true => CONFIG_WORD.to_string(),
                false => format!("{CONFIG_WORD}*"),
            },
            mark: match self.config.problems.is_empty() {
                true => frame::Mark::None,
                false => frame::Mark::You,
            },
            auto: false,
            accent: Some(crate::cfgarea::accent(&self.win.theme)),
        });
        let focus = match self.in_config {
            true => shown.len(),
            false => shown.iter().position(|i| *i == self.focus).unwrap_or(0),
        };
        (tabs, focus)
    }

    pub fn apply(&mut self, effects: Vec<Effect>, now: Instant) {
        self.win.at = now;
        self.with(self.focus, |s, w| s.apply(w, effects, now));
    }

    /// Every slot's own time: its run, its session and what they wait for go on whatever is
    /// in view; only the slot in view polls for its screen.
    pub fn tick(&mut self, now: Instant) {
        self.win.at = now;
        if self.win.toast.as_ref().is_some_and(|t| t.over(now)) {
            self.win.toast = None;
            self.win.dirty = true;
        }
        for i in 0..self.slots.len() {
            self.with(i, |s, w| s.tick(w, now));
        }
    }

    pub fn next_due(&self, now: Instant) -> Instant {
        let mut due = now + Duration::from_secs(60);
        for (i, s) in self.slots.iter().enumerate() {
            if let Some(t) = s.next_due(&self.win, now, i == self.focus && !self.in_config) {
                due = due.min(t);
            }
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
                // The window's own keys: F-keys wherever the keys are; a character only
                // where it wouldn't be typed (a message, a prompt, the password).
                if let Some((a, text)) = self.win.keys.target(&k) {
                    let typing = match self.in_config {
                        true => self.config.takes_text(),
                        false => self.slots[self.focus].takes_text(&self.win),
                    };
                    if !(text && typing) {
                        return self.target_key(a, now);
                    }
                }
                if self.in_config {
                    self.config.targets = self.in_window();
                    let fx = self.config.on_key(&mut self.win, k);
                    return self.config_fx(fx, now);
                }
                self.with(self.focus, |s, w| s.on_key(w, k, now));
                if let Some(line) = self.win.target_cmd.take() {
                    self.target_cmd(&line, now);
                }
                self.quit_asked();
            }
            Event::Paste(text) if self.in_config => self.config.on_paste(&mut self.win, &text),
            Event::Paste(text) => self.with(self.focus, |s, w| s.on_paste(w, &text)),
            Event::Config(data) => {
                self.config.targets = self.in_window();
                self.config.on_data(&mut self.win, data)
            }
            Event::Resize => self.win.dirty = true,
            Event::Signal => self.win.quit = true,
            // Whatever is in view, it lands in its own slot.
            Event::Data(id, data) => {
                if let Some(i) = self.place(&id) {
                    self.with(i, |s, w| s.on_data(w, data));
                }
            }
            Event::Stream(id, sid, m) => {
                if let Some(i) = self.place(&id) {
                    self.with(i, |s, w| s.on_run(w, sid, m));
                }
            }
            Event::Text(id, tid, res) => {
                if let Some(i) = self.place(&id) {
                    self.with(i, |s, w| s.on_text(w, tid, res));
                }
            }
        }
    }

    pub fn draw(&mut self, f: &mut Frame) {
        let (strip, focus) = self.strip();
        self.win.strip = strip;
        self.win.strip_focus = focus;
        if self.in_config {
            self.config.targets = self.in_window();
            return self.config.draw(&mut self.win, f);
        }
        self.with(self.focus, |s, w| s.draw(w, f));
    }

    /// A command waiting for the terminal: the slot in view's only (one out of view waits
    /// until it's looked at; its strip entry says it needs you).
    pub fn take_suspend(&mut self) -> Option<(Cmd, String)> {
        self.win.at = Instant::now();
        // The Config area's editor; a slot's command waits until its slot is looked at.
        if self.in_config {
            let r = self.config.take_suspend();
            self.config_handed = r.is_some();
            return r;
        }
        let r = self.with(self.focus, |s, w| s.take_suspend(w));
        if r.is_some() {
            self.handed = Some(self.focus);
        }
        r
    }

    /// The terminal is back. (What the other slots' threads sent meanwhile is queued, and
    /// handled next.)
    pub fn after_suspend(&mut self, status: Result<ExitStatus, ExecError>) {
        self.win.at = Instant::now();
        if std::mem::take(&mut self.config_handed) {
            self.config.targets = self.in_window();
            let fx = self.config.after_editor(&mut self.win);
            return self.config_fx(fx, self.win.at);
        }
        let i = self.handed.take().unwrap_or(self.focus);
        self.with(i, |s, w| s.after_suspend(w, status));
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
        self.config.shutdown();
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

/// The Config tab's name in the strip, and its `:` command.
pub const CONFIG_WORD: &str = "config";

/// A target's id as `[targets] show` spells it: this machine's (the empty one) is `local`.
fn show_id(id: &str) -> &str {
    if id.is_empty() { "local" } else { id }
}

/// The other way: a target's own id for what `[targets] show` calls it.
fn target_id(show: &str) -> &str {
    if show == "local" { "" } else { show }
}

/// How often the targets are surveyed while several are open.
const SURVEY_EVERY: Duration = Duration::from_secs(5);

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
    /// The same for the slot at `i`, in view or not.
    pub fn set_wf_entries_at(&mut self, i: usize, e: Vec<sentry_core::workflows::Entry>) {
        self.with(i, |s, w| {
            s.shared.workflows = e.iter().map(|x| x.name.clone()).collect();
            s.shared.wf_list = e
                .iter()
                .cloned()
                .map(|entry| sentry_core::tui::wflist::WfInfo { entry, last: None })
                .collect();
            s.shared.wf_entries = e;
            s.settle(w, crate::target::Settle::Lists);
        });
    }
    /// Effects for the slot at `i`, as if one of its own events brought them.
    pub fn apply_at(&mut self, i: usize, effects: Vec<Effect>) {
        let now = Instant::now();
        self.with(i, |s, w| s.apply(w, effects, now));
    }
    /// The running step of the run in slot `i` ends (nothing ran).
    pub fn run_step_exit_at(&mut self, i: usize, code: i32) {
        let s = &self.slots[i];
        let id = s
            .run
            .as_ref()
            .and_then(|r| r.live())
            .map(|l| l.id)
            .expect("no step running");
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
    /// sudo's check of the password typed for the slot at `i` ended (nothing ran).
    pub fn unlock_exit_at(&mut self, i: usize, code: i32) {
        let s = &self.slots[i];
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
    /// The step a session elsewhere runs on the target at `i` printed a line (nothing ran).
    pub fn guest_line_at(&mut self, i: usize, text: &str) {
        let s = &self.slots[i];
        let id = s
            .guest
            .as_ref()
            .map(|g| g.id)
            .expect("no guest step running");
        let tid = s.mail.id().clone();
        self.on_event(
            Event::Stream(
                tid,
                id,
                StreamMsg::Line {
                    stderr: false,
                    text: text.to_string(),
                },
            ),
            Instant::now(),
        );
    }
    /// That step (or the check of a password typed for this target elsewhere) ended.
    pub fn guest_exit_at(&mut self, i: usize, code: i32) {
        let s = &self.slots[i];
        let id = s
            .guest
            .as_ref()
            .map(|g| g.id)
            .or(s.guest_aux.as_ref().map(|a| a.0))
            .expect("nothing running here for a session elsewhere");
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
    /// What a session elsewhere has running or waiting on the target at `i`.
    pub fn guest_at(&self, i: usize) -> (bool, bool) {
        (
            self.slots[i].guest.is_some(),
            self.slots[i].guest_wait.is_some(),
        )
    }
    /// The profile a session of the slot at `i` would send its turn with.
    pub fn session_profile_at(&mut self, i: usize) -> sentry_core::claude::Profile {
        self.survey();
        self.slots[i].session_profile(&self.win, &[])
    }
    /// Whether the slot at `i` holds its sudo password.
    pub fn holds_password_at(&self, i: usize) -> bool {
        self.slots[i].secret_ok
    }
    /// The apply session of the slot at `i`.
    pub fn apply_session_at(&self, i: usize) -> Option<&sentry_core::apply::session::Session> {
        self.slots[i].apply.as_ref()
    }
    /// The sudo password being asked for in slot `i`: (what for, characters typed).
    pub fn unlock_at(&self, i: usize) -> Option<(String, usize)> {
        let u = self.slots[i].unlock.as_ref()?;
        Some((u.what.clone(), u.typed.len()))
    }
    /// The Config area's editor came back (nothing ran: the test changed the file itself).
    pub fn config_edited_for_test(&mut self) {
        self.config_handed = false;
        self.config.targets = self.in_window();
        let fx = self.config.after_editor(&mut self.win);
        self.config_fx(fx, Instant::now());
    }
    /// The toast on screen.
    pub fn toast_for_test(&self) -> Option<&str> {
        self.win.toast.as_ref().map(|t| t.msg())
    }
    /// Whether the slot at `i` has started (it had the window at least once).
    pub fn started_at(&self, i: usize) -> bool {
        !self.slots[i].asleep_for_test()
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
        self.apply_answer_at(self.focus, text);
    }
    /// The same, for the session of the slot at `i`.
    pub fn apply_answer_at(&mut self, i: usize, text: &str) {
        let id = self.slots[i]
            .apply
            .as_ref()
            .and_then(|s| s.chat.live.map(|l| l.0))
            .expect("no turn running");
        let line = serde_json::json!({
            "type": "stream_event",
            "event": {"type": "content_block_delta", "delta": {"type": "text_delta", "text": text}}
        })
        .to_string();
        let tid = self.slots[i].mail.id().clone();
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
        self.apply_exit_at(self.focus, code);
    }
    /// The same, for the session of the slot at `i`.
    pub fn apply_exit_at(&mut self, i: usize, code: i32) {
        let s = &self.slots[i];
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
    /// The workflow run's running step ends (nothing ran).
    pub fn run_step_exit_for_test(&mut self, code: i32) {
        let s = self.slot();
        let id = s
            .run
            .as_ref()
            .and_then(|r| r.live())
            .map(|l| l.id)
            .expect("no step running");
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
    /// The keys of every row Maintenance lists (what can wait too).
    pub fn rows_for_test(&mut self) -> Vec<String> {
        let (s, w) = self.parts();
        s.rows_for_test(w)
    }
    /// The key of the Maintenance row the cursor is on.
    pub fn row_at_for_test(&mut self) -> Option<String> {
        let (s, w) = self.parts();
        s.row_at_for_test(w)
    }
    /// Maintenance lists what can wait too (`o`).
    pub fn everything_for_test(&self) -> bool {
        self.slot().everything_for_test()
    }
    /// Records › Later's row with this key, taken back. False: there is none.
    pub fn undo_for_test(&mut self, key: &str) -> bool {
        let (s, w) = self.parts();
        s.undo_for_test(w, key)
    }
    /// What the app does on `r`, on entering a screen and on getting the window back:
    /// what changed on disk is read (an offline app's own `look` reads nothing).
    pub fn look_for_test(&mut self) -> bool {
        let (s, w) = self.parts();
        s.look_now(w)
    }
    /// A plan kept under `key`, on disk too.
    pub fn plan_keep_for_test(&mut self, key: &str, body: &str) {
        let (s, w) = self.parts();
        s.plan_keep_for_test(w, key, body);
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
    /// When sentry last changed the target (a run or a session's steps that ended well).
    pub fn set_last_change_for_test(&mut self, at: jiff::Timestamp) {
        self.slot_mut().last_change_at = Some(at);
    }
    /// When sentry last changed the target in view (`Slot::host_changed`).
    pub fn last_change_for_test(&self) -> Option<jiff::Timestamp> {
        self.slot().last_change_at
    }
    /// The same, for the slot at `i`.
    pub fn last_change_at(&self, i: usize) -> Option<jiff::Timestamp> {
        self.slots[i].last_change_at
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

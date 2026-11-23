//! The window's Config area: the three config files side by side, what is wrong in them,
//! what is staged, and the screens that show and change them. It is part of the window, not a
//! target: `App` holds one [`ConfigArea`] beside its slots and gives it the keys, the pastes
//! and the frame while its tab has the window (`App::in_config`); every slot keeps running
//! out of view meanwhile.
//!
//! Each kind of config describes itself ([`kind::Kind`], registered by the binary), so the
//! area needs no target crate. A change made in a form is staged ([`Pending`], a
//! `cfg::Change` by path); nothing is written before the save box's Enter ([`save`]); a file
//! that changed on disk underneath is read again and what is staged made on it, or shown as
//! a conflict ([`ConfigArea::look`]).

pub mod agent;
mod draw;
mod keys;
pub mod kind;
mod save;

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

use sentry_core::cfg::{self, By, Change, FileId, Seg, Value, parse_path};
use sentry_core::claude;
use sentry_core::config::Config;
use sentry_core::exec::Cmd;
use sentry_core::tui::form::{self, Form};
use sentry_core::tui::lineedit::LineEdit;

use crate::app::{Event, Win};
pub use draw::accent;
pub use kind::{DocAny, Entry, Item, Kind, Section};

/// One thing wrong in a config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub file: FileId,
    /// The server or network it is about (None: the file as a whole, or config.toml).
    pub entry: Option<String>,
    pub text: String,
}

impl Problem {
    /// A problem of `file`: its text without the file's or the entry's name in front (they are
    /// fields here), the entry told from that name or from a key's path in the text.
    pub fn of(file: FileId, entry: Option<&str>, text: &str) -> Self {
        let mut text = text;
        for prefix in [file.name(), "config"] {
            if let Some(rest) = text.strip_prefix(prefix).and_then(|r| r.strip_prefix(": ")) {
                text = rest;
            }
        }
        if let Some(rest) = entry
            .and_then(|e| text.strip_prefix(e))
            .and_then(|r| r.strip_prefix(": "))
        {
            text = rest;
        }
        let entry = entry.map(str::to_string).or_else(|| entry_in(file, text));
        Self {
            file,
            entry,
            text: text.to_string(),
        }
    }

    /// `server_config.yaml · myserver: timer `x` should end in .timer`.
    pub fn line(&self) -> String {
        match &self.entry {
            Some(e) => format!("{} · {e}: {}", self.file.name(), self.text),
            None => format!("{}: {}", self.file.name(), self.text),
        }
    }
}

/// The entry a key's path in backticks names (`servers.a.sudoo` → `a`).
fn entry_in(file: FileId, text: &str) -> Option<String> {
    let top = match file {
        FileId::Servers => "servers",
        FileId::Networks => "networks",
        FileId::App => return None,
    };
    let path = text.split('`').nth(1)?;
    match parse_path(path).ok()?.as_slice() {
        [Seg::Key(t), Seg::Key(e), ..] if t == top => Some(e.clone()),
        _ => None,
    }
}

/// What the window says once it is up: the first problem, how many there are, and where to
/// see them all. None: nothing is wrong.
pub fn toast(problems: &[Problem]) -> Option<String> {
    let first = problems.first()?.line();
    Some(match problems.len() {
        1 => format!("{first} (the Config tab shows it)"),
        n => format!("{n} config problems, the Config tab lists them · {first}"),
    })
}

/// A problem is about the setting at `path` (a form draws it under that field): its text
/// names the path in backticks, or starts `[section] leaf` (`[targets] show: …`), or, for a
/// whole table (`keys`), `[keys]`.
impl Problem {
    pub fn about(&self, path: &str) -> bool {
        if FileId::of_path(path) != self.file {
            return false;
        }
        if self.text.contains(&format!("`{path}`")) {
            return true;
        }
        let Ok(segs) = parse_path(path) else {
            return false;
        };
        match segs.as_slice() {
            [Seg::Key(s)] => self.text.starts_with(&format!("[{s}]")),
            [Seg::Key(s), Seg::Key(leaf)] => self.text.starts_with(&format!("[{s}] {leaf}")),
            _ => false,
        }
    }
}

/// `[targets] show` against the targets there are (`all`, as it spells them): each entry
/// that names none, and a list that names none at all.
pub fn targets_problems(show: Option<&[String]>, all: &[String]) -> Vec<Problem> {
    let Some(show) = show else {
        return Vec::new();
    };
    let mut out: Vec<Problem> = show
        .iter()
        .filter(|s| !all.contains(s))
        .map(|u| {
            Problem::of(
                FileId::App,
                None,
                &format!("[targets] show: no target `{u}`"),
            )
        })
        .collect();
    if !show.iter().any(|s| all.contains(s)) {
        out.push(Problem::of(
            FileId::App,
            None,
            "[targets] show names no target: showing all",
        ));
    }
    out
}

/// The area's screens (its own: no target has them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Overview,
    Agent,
    Machine,
    Servers,
    Networks,
    Window,
}

impl Screen {
    pub const ALL: [Screen; 6] = [
        Screen::Overview,
        Screen::Agent,
        Screen::Machine,
        Screen::Servers,
        Screen::Networks,
        Screen::Window,
    ];

    pub fn key(self) -> char {
        (b'1' + Screen::ALL.iter().position(|s| *s == self).unwrap_or(0) as u8) as char
    }

    pub fn name(self) -> &'static str {
        match self {
            Screen::Overview => "Overview",
            Screen::Agent => "Agent",
            Screen::Machine => "This machine",
            Screen::Servers => "Servers",
            Screen::Networks => "Networks",
            Screen::Window => "Window",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Screen::Overview => "Over",
            Screen::Agent => "Agent",
            Screen::Machine => "Here",
            Screen::Servers => "Srv",
            Screen::Networks => "Net",
            Screen::Window => "Win",
        }
    }

    pub fn by_key(c: char) -> Option<Screen> {
        Screen::ALL.into_iter().find(|s| s.key() == c)
    }

    /// By its name, the start of it (two letters or more), or its short name.
    pub fn by_name(word: &str) -> Option<Screen> {
        let w = word.to_ascii_lowercase();
        Screen::ALL.into_iter().find(|s| {
            let name = s.name().to_ascii_lowercase();
            name == w
                || s.short().to_ascii_lowercase() == w
                || (w.len() >= 2 && (name.starts_with(&w) || name.replace("this ", "") == w))
        })
    }

    /// The file a screen's settings are in.
    fn file(self) -> Option<FileId> {
        match self {
            Screen::Overview => None,
            Screen::Agent | Screen::Machine | Screen::Window => Some(FileId::App),
            Screen::Servers => Some(FileId::Servers),
            Screen::Networks => Some(FileId::Networks),
        }
    }
}

/// `config.toml`'s entries, by name (its `Kind` gives them these names and the area's
/// screens show them).
pub const AGENT: &str = "agent";
pub const MACHINE: &str = "this machine";
pub const WINDOW: &str = "window";

/// One file as the area holds it.
pub struct File {
    pub id: FileId,
    /// None: it doesn't parse (`err` says why).
    pub doc: Option<Box<dyn DocAny>>,
    pub err: Option<String>,
    /// What its parse said (unknown keys): gone with the next save.
    pub warnings: Vec<String>,
    /// As it was when a file that doesn't parse was read.
    stamp: Option<cfg::Stamp>,
}

/// A change staged in the area: nothing is written until the save box's Enter.
#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    pub change: Change,
    /// It can't be made on the file as it is now (why): unticked until it can.
    pub conflict: Option<String>,
}

/// A target the window has, as the area names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InWindow {
    /// As `[targets] show` spells it: `local`, `srv:<name>`, `net:<name>`.
    pub id: String,
    pub title: String,
    pub hidden: bool,
    /// It is at work now (a run, a session, a step for another target).
    pub working: bool,
}

/// What the area asks of the app when a key or an event is done.
#[derive(Debug, Clone, PartialEq)]
pub enum Fx {
    /// A `:` command that isn't the area's: the window's, if it names a target.
    Command(String),
    /// These files are not what they were (saved here, or edited outside): what follows
    /// them is the app's to do.
    Changed(Vec<FileId>),
}

/// The save box: what Enter will write, said first.
pub struct SaveBox {
    pub lines: Vec<String>,
    scroll: usize,
}

/// The Config area: the three files side by side, what is staged, and its screens.
pub struct ConfigArea {
    kinds: Vec<Box<dyn Kind>>,
    files: Vec<File>,
    pub pending: Vec<Pending>,
    /// Everything wrong in the files as they are to be (`Win.config_problems` is a copy).
    pub problems: Vec<Problem>,
    pub screen: Screen,
    /// Overview's cursor: over the systems, the add row, then the pending changes.
    cur: usize,
    /// Servers' and Networks' cursors.
    list: [usize; 2],
    /// The entry under the cursor is shown with all its essential settings.
    open: bool,
    /// The form of the screen in view (Agent, This machine, Window).
    form: Option<Form>,
    pub save: Option<SaveBox>,
    /// The `:` line.
    cmd: Option<LineEdit>,
    pub agent: agent::Agent,
    /// A file waiting for the editor.
    edit: Option<PathBuf>,
    /// Where the files are (None: the config dir). Tests point it at their own.
    dir: Option<PathBuf>,
    loaded: bool,
    tx: Sender<Event>,
    /// The targets the window has (the app says, before each key and draw).
    pub(crate) targets: Vec<InWindow>,
}

impl ConfigArea {
    pub(crate) fn new(tx: Sender<Event>) -> Self {
        Self {
            kinds: Vec::new(),
            files: Vec::new(),
            pending: Vec::new(),
            problems: Vec::new(),
            screen: Screen::Overview,
            cur: 0,
            list: [0; 2],
            open: false,
            form: None,
            save: None,
            cmd: None,
            agent: Default::default(),
            edit: None,
            dir: None,
            loaded: false,
            tx,
            targets: Vec::new(),
        }
    }

    /// One more kind of config (the binary registers each beside the target makers).
    pub fn register(&mut self, kind: Box<dyn Kind>) {
        self.kinds.push(kind);
        self.loaded = false;
    }

    /// Read the files from this directory instead of the config dir, now.
    pub fn set_dir(&mut self, w: &mut Win, dir: &Path) {
        self.dir = Some(dir.to_path_buf());
        self.pending.clear();
        self.load(w);
    }

    fn path(&self, id: FileId) -> PathBuf {
        match &self.dir {
            Some(d) => d.join(id.name()),
            None => id.path(),
        }
    }

    fn read(&self, k: &dyn Kind) -> File {
        let path = self.path(k.id());
        match k.load(&path) {
            Ok((doc, warnings)) => File {
                id: k.id(),
                doc: Some(doc),
                err: None,
                warnings,
                stamp: None,
            },
            Err(e) => File {
                id: k.id(),
                doc: None,
                // (The path is the screen's to say; the reason is what's wanted.)
                err: Some(
                    e.strip_prefix(&format!("{}: ", path.display()))
                        .unwrap_or(&e)
                        .to_string(),
                ),
                warnings: Vec::new(),
                stamp: cfg::Stamp::of(&path),
            },
        }
    }

    /// Read every file (again): at start, and whenever all of it is wanted fresh. What is
    /// staged is made again on what was read (`restage`).
    pub fn load(&mut self, w: &mut Win) {
        self.files = self.kinds.iter().map(|k| self.read(k.as_ref())).collect();
        self.loaded = true;
        self.restage();
        self.lint(w);
        self.form = self.build_form();
    }

    fn at(&self, id: FileId) -> Option<usize> {
        self.kinds.iter().position(|k| k.id() == id)
    }

    fn kind(&self, id: FileId) -> Option<&dyn Kind> {
        self.at(id).map(|i| self.kinds[i].as_ref())
    }

    pub fn doc(&self, id: FileId) -> Option<&dyn DocAny> {
        self.files.get(self.at(id)?)?.doc.as_deref()
    }

    fn doc_mut(&mut self, id: FileId) -> Option<&mut Box<dyn DocAny>> {
        let i = self.at(id)?;
        self.files.get_mut(i)?.doc.as_mut()
    }

    fn file(&self, id: FileId) -> Option<&File> {
        self.files.get(self.at(id)?)
    }

    /// `config.toml` as it is to be (the area's own reading of it).
    pub fn app(&self) -> Option<&Config> {
        kind::typed::<Config>(self.doc(FileId::App)?)
    }

    /// `config.toml` as the file says it (nothing staged in it): what the window goes by.
    pub fn app_on_disk(&self) -> Option<Config> {
        kind::typed_on_disk::<Config>(self.doc(FileId::App)?)
    }

    /// Changes staged and ticked.
    pub fn unsaved(&self) -> usize {
        self.pending.iter().filter(|p| p.change.on).count()
    }

    /// Every entry of every file, in the order the Overview lists them.
    pub fn entries(&self) -> Vec<(FileId, Entry)> {
        let mut out = Vec::new();
        for (k, f) in self.kinds.iter().zip(&self.files) {
            let Some(d) = f.doc.as_deref() else {
                continue;
            };
            out.extend(k.entries(d).into_iter().map(|e| (k.id(), e)));
        }
        out
    }

    /// The systems: this machine, each server, each network.
    pub fn systems(&self) -> Vec<(FileId, Entry)> {
        self.entries()
            .into_iter()
            .filter(|(_, e)| e.target.is_some())
            .collect()
    }

    /// Every target there is, as `[targets] show` spells them.
    fn all_targets(&self) -> Vec<String> {
        self.systems()
            .into_iter()
            .filter_map(|(_, e)| e.target)
            .collect()
    }

    /// Everything wrong in the files as they are to be, found again: each kind's own lint,
    /// a file that doesn't parse, `[targets] show` against the targets there are.
    pub fn lint(&mut self, w: &mut Win) {
        let mut out = Vec::new();
        for (k, f) in self.kinds.iter().zip(&self.files) {
            match (&f.doc, &f.err) {
                (Some(d), _) => out.extend(k.problems(d.as_ref(), &f.warnings)),
                (None, Some(e)) => out.push(Problem::of(f.id, None, e)),
                (None, None) => {}
            }
        }
        if let Some(cfg) = self.app() {
            out.extend(targets_problems(
                cfg.targets.show.as_deref(),
                &self.all_targets(),
            ));
        }
        self.problems = out;
        w.config_problems = self.problems.clone();
        w.dirty = true;
    }

    /// What is to be, made again from what was read: every ticked change in the order it
    /// was staged. One that can't be made any more is a conflict, unticked, with why.
    fn restage(&mut self) {
        for f in &mut self.files {
            if let Some(d) = f.doc.as_mut() {
                d.reset();
            }
        }
        let mut pending = std::mem::take(&mut self.pending);
        for p in &mut pending {
            if !p.change.on {
                continue;
            }
            let made = match self.doc_mut(p.change.file) {
                Some(d) => d.apply(&p.change),
                None => Err(format!("{} doesn't parse", p.change.file.name())),
            };
            match made {
                Ok(()) => p.conflict = None,
                Err(why) => {
                    p.conflict = Some(why);
                    p.change.on = false;
                }
            }
        }
        self.pending = pending;
    }

    /// Stage one setting: `to` is what it is to be (None: taken away). A setting staged
    /// before is that change with a new end; back at what the file says, it is no change.
    /// Refused (the type wouldn't read it): nothing is staged.
    pub fn stage(&mut self, path: &str, to: Option<Value>, by: By) -> Result<(), String> {
        let file = FileId::of_path(path);
        let before = self.pending.clone();
        match self.pending.iter().position(|p| p.change.path == path) {
            Some(i) => {
                let p = &mut self.pending[i];
                p.change.to = to;
                p.change.on = true;
                p.change.by = by;
                p.conflict = None;
                if p.change.from == p.change.to {
                    self.pending.remove(i);
                }
                self.restage();
            }
            None => {
                let d = self
                    .doc_mut(file)
                    .ok_or_else(|| format!("{} doesn't parse: e opens it", file.name()))?;
                let c = kind::set(d.as_mut(), path, to, by)?;
                if c.from != c.to {
                    self.pending.push(Pending {
                        change: c,
                        conflict: None,
                    });
                }
                return Ok(());
            }
        }
        // The one just changed must have gone in: else it is as it was.
        match self
            .pending
            .iter()
            .find(|p| p.change.path == path)
            .and_then(|p| p.conflict.clone())
        {
            Some(why) => {
                self.pending = before;
                self.restage();
                Err(why)
            }
            None => Ok(()),
        }
    }

    /// Take a staged change back.
    pub fn undo(&mut self, i: usize) {
        if i < self.pending.len() {
            self.pending.remove(i);
            self.restage();
        }
    }

    /// Tick or untick a staged change. Why it can't be ticked, when it can't.
    pub fn tick(&mut self, i: usize) -> Option<String> {
        let p = self.pending.get_mut(i)?;
        p.change.on = !p.change.on;
        self.restage();
        self.pending.get(i).and_then(|p| p.conflict.clone())
    }

    /// Look at the files: whatever changed on disk since it was read is read again, and
    /// what is staged for it made again on the newer file (`cfg::Doc::rebase`); one that
    /// can't be is a conflict. The files that changed.
    pub fn look(&mut self, w: &mut Win) -> Vec<FileId> {
        if !self.loaded {
            self.load(w);
            return Vec::new();
        }
        let mut changed = Vec::new();
        for i in 0..self.files.len() {
            let id = self.files[i].id;
            let stale = match &self.files[i].doc {
                Some(d) => d.changed_on_disk(),
                None => cfg::Stamp::of(&self.path(id)) != self.files[i].stamp,
            };
            if !stale {
                continue;
            }
            changed.push(id);
            let ticked: Vec<Change> = self
                .pending
                .iter()
                .filter(|p| p.change.file == id && p.change.on)
                .map(|p| p.change.clone())
                .collect();
            let rebased = match self.files[i].doc.as_mut() {
                Some(d) => d.rebase(&ticked).ok(),
                None => None,
            };
            match rebased {
                Some((_, conflicts)) => {
                    for (c, why) in conflicts {
                        if let Some(p) = self.pending.iter_mut().find(|p| p.change == c) {
                            p.conflict = Some(why);
                            p.change.on = false;
                        }
                    }
                    // (Its warnings are the newer file's.)
                    let fresh = self.read(self.kinds[i].as_ref());
                    self.files[i].warnings = fresh.warnings;
                }
                // It didn't parse before, or doesn't now: read from scratch.
                None => self.files[i] = self.read(self.kinds[i].as_ref()),
            }
        }
        if !changed.is_empty() {
            self.restage();
            self.lint(w);
            self.form = self.build_form().map(|f| match &self.form {
                Some(old) => f.at(old),
                None => f,
            });
        }
        changed
    }

    /// The area has the window: its files are looked at, its screen is entered.
    pub(crate) fn shown(&mut self, w: &mut Win) -> Option<Fx> {
        let changed = self.look(w);
        self.enter(w, self.screen);
        (!changed.is_empty()).then_some(Fx::Changed(changed))
    }

    /// Switch screens: its form is made, and what it looks up once is looked up.
    pub fn enter(&mut self, w: &mut Win, s: Screen) {
        self.screen = s;
        self.open = false;
        self.form = self.build_form();
        if s == Screen::Agent {
            self.agent_find(w, false);
        }
        w.dirty = true;
    }

    /// The setting the selected field of the form in view is.
    fn field_path(&self) -> Option<String> {
        self.form.as_ref()?.field().map(|f| f.key.clone())
    }

    /// The form of the screen in view, from the file as it is to be.
    fn build_form(&self) -> Option<Form> {
        let entry = match self.screen {
            Screen::Agent => AGENT,
            Screen::Machine => MACHINE,
            Screen::Window => WINDOW,
            _ => return None,
        };
        let kind = self.kind(FileId::App)?;
        let doc = self.doc(FileId::App)?;
        let fields = self.form_fields(kind, doc, &kind.sections(doc, entry));
        Some(Form::new(self.screen.name(), fields))
    }

    /// The form's fields for these sections: each item by its table entry and its value.
    fn form_fields(
        &self,
        kind: &dyn Kind,
        doc: &dyn DocAny,
        sections: &[Section],
    ) -> Vec<form::Field> {
        let (tree, defaults) = (doc.tree(), doc.defaults());
        let mut out = Vec::new();
        for s in sections {
            let mut head = Some(s.title.clone());
            for item in &s.items {
                let Ok(segs) = parse_path(&item.path) else {
                    continue;
                };
                let Some(spec) = cfg::fields::find(kind.fields(), &item.path) else {
                    continue;
                };
                let Some(value) = kind::to_form(spec.kind, tree.at(&segs)) else {
                    continue;
                };
                let mut f = form::Field::new(&item.path, spec.label, value)
                    .help(spec.help)
                    .empty(&item.empty);
                f.head = head.take().unwrap_or_default();
                f.changed = self.pending.iter().any(|p| p.change.path == item.path);
                f.problem = self
                    .problems
                    .iter()
                    .find(|p| p.about(&item.path))
                    .map(|p| p.text.clone());
                if spec.kind == cfg::Kind::Number {
                    f.range = Some((0, i64::MAX));
                }
                // No number in these files is negative; the type says the rest.
                if item.path == "targets.show" {
                    let all = self.all_targets();
                    f.help = format!("{} There are: {}.", f.help, all.join(", "));
                    f.seed = all;
                }
                if f.empty.is_empty()
                    && let Some(Value::Str(d)) = defaults.at(&segs)
                    && !d.is_empty()
                {
                    f.empty = d.clone();
                }
                out.push(f);
            }
        }
        out
    }

    /// A form's change: staged, or refused in place with why.
    fn form_set(&mut self, w: &mut Win, path: &str, v: &form::Value) {
        let nullable = self
            .doc(FileId::of_path(path))
            .zip(parse_path(path).ok())
            .is_some_and(|(d, segs)| matches!(d.defaults().at(&segs), Some(Value::Null) | None));
        let staged = self.stage(path, Some(kind::from_form(v, nullable)), By::You);
        self.lint(w);
        let fresh = self.build_form();
        self.form = match (fresh, self.form.take()) {
            (Some(f), Some(old)) => Some(f.at(&old)),
            (f, _) => f,
        };
        if let (Err(why), Some(f)) = (staged, self.form.as_mut()) {
            f.refuse(path, &why);
        }
        if path == "agent.command" {
            self.agent_find(w, false);
        }
    }

    /// The file `e` opens: the screen's, or on the Overview the selected system's.
    fn file_to_edit(&self) -> FileId {
        self.screen.file().unwrap_or_else(|| {
            let systems = self.systems();
            match systems.get(self.cur) {
                Some((id, _)) => *id,
                None => match self.pending.get(self.cur.saturating_sub(systems.len() + 1)) {
                    Some(p) if self.cur > systems.len() => p.change.file,
                    _ => FileId::App,
                },
            }
        })
    }

    /// A text is being typed: a character is never a key of the window's.
    pub fn takes_text(&self) -> bool {
        self.cmd.is_some() || self.form.as_ref().is_some_and(|f| f.editing())
    }

    /// The editor is wanted (the app hands the terminal over).
    pub(crate) fn take_suspend(&mut self) -> Option<(Cmd, String)> {
        let path = self.edit.take()?;
        let editor = std::env::var("VISUAL")
            .or_else(|_| std::env::var("EDITOR"))
            .unwrap_or_else(|_| "vi".into());
        let mut words = editor.split_whitespace();
        let cmd = Cmd::local(words.next().unwrap_or("vi"))
            .args(words)
            .arg(path.display().to_string())
            .timeout(None);
        Some((cmd, String::new()))
    }

    /// The editor is done: the file is read again, linted, and what is staged made on it.
    pub(crate) fn after_editor(&mut self, w: &mut Win) -> Option<Fx> {
        let changed = self.look(w);
        if changed.is_empty() {
            w.toast("nothing changed");
            return None;
        }
        let conflicts = self.pending.iter().filter(|p| p.conflict.is_some()).count();
        let names: Vec<&str> = changed.iter().map(|f| f.name()).collect();
        w.toast(&match (self.problems.len(), conflicts) {
            (0, 0) => format!("{} read again: nothing wrong", names.join(", ")),
            (n, 0) => format!("{} read again: {}", names.join(", "), count(n, "problem")),
            (_, c) => format!(
                "{} read again: {} staged here no longer fit",
                names.join(", "),
                count(c, "change")
            ),
        });
        Some(Fx::Changed(changed))
    }

    /// Something a worker of the area's sent.
    pub(crate) fn on_data(&mut self, w: &mut Win, data: Box<dyn std::any::Any + Send>) {
        if let Ok(m) = data.downcast::<agent::Msg>() {
            self.agent.on_msg(*m);
            w.dirty = true;
        }
    }

    /// Look the agent's command up (on entering its screen, on `r`, when the command is
    /// changed): on a worker, never offline. `again`: even when it was looked up before.
    fn agent_find(&mut self, w: &mut Win, again: bool) {
        let cmd = self.app().map_or_else(
            || claude::DEFAULT_COMMAND.to_string(),
            |c| c.agent.command.clone(),
        );
        if !again && self.agent.is_for(&cmd) {
            return;
        }
        self.agent.asked(&cmd);
        if w.offline || cmd.trim().is_empty() {
            return;
        }
        self.agent.finding = true;
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let found = claude::find(&cmd);
            let _ = tx.send(Event::Config(Box::new(agent::Msg::Found(found))));
        });
    }

    /// `t`: one turn, no tools, on a worker.
    fn agent_test(&mut self, w: &mut Win) {
        let cmd = self.agent.command.clone();
        if self.agent.testing {
            return w.toast("still asking");
        }
        if cmd.trim().is_empty() {
            return w.toast("no command to test");
        }
        if self.agent.found.as_ref().is_some_and(|f| f.path.is_none()) {
            return w.toast(&format!("`{cmd}` isn't there: nothing to test"));
        }
        self.agent.test = None;
        self.agent.testing = true;
        if w.offline {
            return;
        }
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let r = claude::test(&cmd);
            let _ = tx.send(Event::Config(Box::new(agent::Msg::Tested(cmd, r))));
        });
    }
}

fn count(n: usize, what: &str) -> String {
    match n {
        1 => format!("1 {what}"),
        n => format!("{n} {what}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_problem_knows_its_file_and_entry() {
        let p = Problem::of(
            FileId::Servers,
            None,
            "server_config.yaml: unknown key `servers.my-box.sudoo` ignored",
        );
        assert_eq!(p.entry.as_deref(), Some("my-box"));
        assert_eq!(p.text, "unknown key `servers.my-box.sudoo` ignored");
        let p = Problem::of(
            FileId::Servers,
            Some("a"),
            "a: timer `x` should end in .timer",
        );
        assert_eq!(
            p.line(),
            "server_config.yaml · a: timer `x` should end in .timer"
        );
        let p = Problem::of(FileId::App, None, "config: unknown key `ui.bogus` ignored");
        assert_eq!(p.line(), "config.toml: unknown key `ui.bogus` ignored");
        assert_eq!(toast(&[]), None);
        assert_eq!(
            toast(std::slice::from_ref(&p)).unwrap(),
            "config.toml: unknown key `ui.bogus` ignored (the Config tab shows it)"
        );
        assert!(
            toast(&[p.clone(), p])
                .unwrap()
                .starts_with("2 config problems")
        );
    }
}

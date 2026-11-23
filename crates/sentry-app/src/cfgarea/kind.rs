//! What the Config area knows of a config file without knowing its type: each kind of
//! config (`config.toml`, the servers' file, the networks') describes itself through
//! [`Kind`], which the binary registers beside the target makers, as targets do through
//! `Target`. The file as read and as it is to be is a [`DocAny`]: core's `cfg::Doc<T>` with
//! its type erased, so the area holds the three side by side.

use std::any::Any;
use std::io;
use std::path::{Path, PathBuf};

use sentry_core::cfg::{self, By, Change, ConfigFile, Doc, Field, FileId, Seg, Value, parse_path};
use sentry_core::tui::form;

use super::{Problem, Screen};

/// One config file, typed underneath: what was read, what is to be written.
pub trait DocAny {
    fn file(&self) -> FileId;
    fn path(&self) -> &Path;
    /// The file was there when it was read (else: the defaults, nothing on disk).
    fn there(&self) -> bool;
    fn changed_on_disk(&self) -> bool;
    /// The file as read isn't what sentry would write for what it says.
    fn handwritten(&self) -> bool;
    /// The value as it is to be, as a tree.
    fn tree(&self) -> Value;
    /// The value as read.
    fn base(&self) -> Value;
    /// The value when nothing is set.
    fn defaults(&self) -> Value;
    /// Make one change on what is to be (the type refuses what it wouldn't read).
    fn apply(&mut self, c: &Change) -> Result<(), String>;
    /// What is to be is what was read again.
    fn reset(&mut self);
    /// Read the file again and make `changes` on it: `cfg::Doc::rebase`.
    fn rebase(&mut self, changes: &[Change]) -> Result<cfg::Rebased, String>;
    /// Write it (`cfg::Doc::save`): the backup's path, when the file was there.
    fn save(&mut self) -> io::Result<Option<PathBuf>>;
    /// The same file with nothing staged in it: what is on disk.
    fn on_disk(&self) -> Box<dyn DocAny>;
    /// The file's type reads this tree: the tree as the type writes it back (a proposal's
    /// value is one the type holds, or why not).
    fn reads(&self, tree: &Value) -> Result<Value, String>;
    fn as_any(&self) -> &dyn Any;
}

impl<T: ConfigFile + 'static> DocAny for Doc<T> {
    fn file(&self) -> FileId {
        T::FILE
    }
    fn path(&self) -> &Path {
        &self.path
    }
    fn there(&self) -> bool {
        self.stamp.is_some()
    }
    fn changed_on_disk(&self) -> bool {
        Doc::changed_on_disk(self)
    }
    fn handwritten(&self) -> bool {
        Doc::handwritten(self)
    }
    fn tree(&self) -> Value {
        Value::of(&self.now).unwrap_or(Value::Null)
    }
    fn base(&self) -> Value {
        Doc::base(self)
            .ok()
            .and_then(|b| Value::of(&b).ok())
            .unwrap_or(Value::Null)
    }
    fn defaults(&self) -> Value {
        Value::of(&T::default()).unwrap_or(Value::Null)
    }
    fn apply(&mut self, c: &Change) -> Result<(), String> {
        cfg::apply(&mut self.now, c)
    }
    fn reset(&mut self) {
        if let Ok(b) = Doc::base(self) {
            self.now = b;
        }
    }
    fn rebase(&mut self, changes: &[Change]) -> Result<cfg::Rebased, String> {
        Doc::rebase(self, changes)
    }
    fn save(&mut self) -> io::Result<Option<PathBuf>> {
        Doc::save(self)
    }
    fn on_disk(&self) -> Box<dyn DocAny> {
        let mut d = self.clone();
        if let Ok(b) = Doc::base(self) {
            d.now = b;
        }
        Box::new(d)
    }
    fn reads(&self, tree: &Value) -> Result<Value, String> {
        Value::of(&tree.to::<T>()?)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// What a kind's `load` gives: the document and the parse's warnings (unknown keys).
pub type Loaded = Result<(Box<dyn DocAny>, Vec<String>), String>;

/// `Kind::load` for a file of type `T`.
pub fn load<T: ConfigFile + 'static>(path: &Path) -> Loaded {
    let (doc, warnings) = Doc::<T>::load_from(path)?;
    Ok((Box::new(doc), warnings))
}

/// The typed value a document holds, for the one who knows its type.
pub fn typed<T: ConfigFile + 'static>(d: &dyn DocAny) -> Option<&T> {
    d.as_any().downcast_ref::<Doc<T>>().map(|d| &d.now)
}

/// The typed value the file held when it was read (what is on disk, nothing staged).
pub fn typed_on_disk<T: ConfigFile + 'static>(d: &dyn DocAny) -> Option<T> {
    d.as_any().downcast_ref::<Doc<T>>()?.base().ok()
}

/// One thing a file configures: a server, a network; for `config.toml`, one of its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    /// What it is in a word: `server`, `network`, `this machine`.
    pub kind: &'static str,
    /// One line about it.
    pub summary: String,
    /// The target it is in the window, as `[targets] show` spells it (`srv:<name>`).
    pub target: Option<String>,
    /// The area's screen that has it.
    pub screen: Screen,
    /// What ssh connects to for it (a server, a network's router).
    pub ssh: Option<String>,
}

/// One setting in a form: where it is, and what the form says about it beyond its table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Item {
    /// The setting's path in its file (`review.at_start`, `servers.myserver.ssh`).
    pub path: String,
    /// What an empty value means, shown in its place.
    pub empty: String,
    /// A number's bounds, both included (None: zero or more).
    pub range: Option<(i64, i64)>,
}

impl Item {
    pub fn at(path: &str) -> Self {
        Self {
            path: path.to_string(),
            empty: String::new(),
            range: None,
        }
    }

    pub fn empty(mut self, what: &str) -> Self {
        self.empty = what.to_string();
        self
    }

    pub fn range(mut self, min: i64, max: i64) -> Self {
        self.range = Some((min, max));
        self
    }
}

/// A titled group of settings in an entry's form. The common ones are open, first; the
/// rest are `fold`ed: a header row with `about` (a line saying what the group is for) that
/// opens on Enter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub title: String,
    pub items: Vec<Item>,
    pub about: String,
    pub fold: bool,
}

impl Section {
    /// A group shown open.
    pub fn new(title: &str, items: Vec<Item>) -> Self {
        Self {
            title: title.to_string(),
            items,
            about: String::new(),
            fold: false,
        }
    }

    /// A group that starts folded, with a line about it.
    pub fn folded(title: &str, about: &str, items: Vec<Item>) -> Self {
        Self {
            title: title.to_string(),
            items,
            about: about.to_string(),
            fold: true,
        }
    }
}

/// One setting of a record, as its row's form has it.
#[derive(Debug, Clone, Copy)]
pub struct RecField {
    pub spec: &'static Field,
    /// Its path within the record: `unit`, `image.service`.
    pub rel: &'static str,
    /// The record within the record it is in (an item's `image`), shown as a small group
    /// of its own.
    pub group: Option<&'static Field>,
}

/// The settings of the records in the list `spec` (`servers.*.timers`), in the order its
/// row's form shows them: the common ones, the rest, then each nested record's.
pub fn record_fields(fields: &'static [Field], spec: &Field) -> Vec<RecField> {
    let prefix = format!("{}[].", spec.path);
    let inside = |f: &&'static Field| f.path.strip_prefix(&prefix).is_some();
    let rel = |f: &'static Field| &f.path[prefix.len()..];
    let direct = |f: &&'static Field| {
        inside(f) && f.kind != cfg::Kind::Section && !rel(f).contains(['.', '['])
    };
    let mut out: Vec<RecField> = fields
        .iter()
        .filter(direct)
        .filter(|f| f.common)
        .chain(fields.iter().filter(direct).filter(|f| !f.common))
        .map(|f| RecField {
            spec: f,
            rel: rel(f),
            group: None,
        })
        .collect();
    for g in fields
        .iter()
        .filter(|f| inside(f) && f.kind == cfg::Kind::Section && !rel(f).contains(['.', '[']))
    {
        let under = format!("{}.", g.path);
        out.extend(
            fields
                .iter()
                .filter(|f| {
                    f.kind != cfg::Kind::Section
                        && f.path
                            .strip_prefix(&under)
                            .is_some_and(|r| !r.contains(['.', '[']))
                })
                .map(|f| RecField {
                    spec: f,
                    rel: rel(f),
                    group: Some(g),
                }),
        );
    }
    out
}

/// Where every setting of a kind's table is in its forms, checked: each one that holds a
/// value must be in exactly one place. A place is an item of a section of one of `entries`
/// (for a file of systems: one system stands for all), a field of the row form of a list of
/// records that is such an item, a named list of words under a map that is one, or one of
/// `elsewhere` (what the Upkeep group holds, and a file's map of systems). What is in no
/// place, or in two: a line each.
pub fn misplaced(
    kind: &dyn Kind,
    d: &dyn DocAny,
    entries: &[&str],
    elsewhere: &[&str],
) -> Vec<String> {
    let fields = kind.fields();
    let mut homes: Vec<(&str, String)> = elsewhere
        .iter()
        .map(|p| (*p, "elsewhere".to_string()))
        .collect();
    for entry in entries {
        for s in kind.sections(d, entry) {
            for item in &s.items {
                let Some(f) = cfg::fields::find(fields, &item.path) else {
                    homes.push(("?", format!("{}: not in the table", item.path)));
                    continue;
                };
                let at = format!("{entry} · {}", s.title);
                homes.push((f.path, at.clone()));
                match f.kind {
                    cfg::Kind::Records => {
                        for r in record_fields(fields, f) {
                            homes.push((r.spec.path, format!("{at} · a row")));
                        }
                    }
                    cfg::Kind::Map => {
                        let under = format!("{}.*", f.path);
                        if let Some(x) = fields.iter().find(|x| x.path == under) {
                            homes.push((x.path, format!("{at} · an entry")));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let mut out: Vec<String> = homes
        .iter()
        .filter(|(p, _)| *p == "?")
        .map(|(_, why)| why.clone())
        .collect();
    for f in fields.iter().filter(|f| f.kind != cfg::Kind::Section) {
        let at: Vec<&str> = homes
            .iter()
            .filter(|(p, _)| *p == f.path)
            .map(|(_, at)| at.as_str())
            .collect();
        match at.len() {
            1 => {}
            0 => out.push(format!("{} is in no form", f.path)),
            _ => out.push(format!("{} is in {}", f.path, at.join(" and in "))),
        }
    }
    out
}

/// A kind of config: one file, described to the area.
pub trait Kind {
    fn id(&self) -> FileId;
    /// Read the file at `path` (not there: the defaults; doesn't parse: why).
    fn load(&self, path: &Path) -> Loaded;
    /// Its settings' table (`cfg::ConfigFile::FIELDS`).
    fn fields(&self) -> &'static [Field];
    /// What it configures, in the order shown.
    fn entries(&self, d: &dyn DocAny) -> Vec<Entry>;
    /// An entry's form: every setting of it, grouped. The groups of the settings the table
    /// marks `common` come first and are open; the rest follow, folded.
    fn sections(&self, d: &dyn DocAny, entry: &str) -> Vec<Section>;
    /// One of this file's entries when nothing is set in it (a server, a network), as a
    /// tree: what a setting's default is. None: the file isn't a map of entries (its own
    /// defaults say it).
    fn entry_default(&self) -> Option<Value> {
        None
    }
    /// The settings of a record of the list at `list` that have a default, each with it (a
    /// disk's `warn`, an item's unset `hold`): the ones a row's form marks as the default
    /// and that may be left out.
    fn record_default(&self, _list: &str) -> Option<Value> {
        None
    }
    /// Which entry a setting belongs to (the pending list and the save box say it).
    fn entry_of(&self, path: &str) -> String {
        match parse_path(path).ok().as_deref() {
            Some([_, Seg::Key(e), ..]) => e.clone(),
            _ => self.id().word().to_string(),
        }
    }
    /// Everything wrong with the document as it is to be, seen without a host; `warnings`
    /// are what its parse said (unknown keys).
    fn problems(&self, d: &dyn DocAny, warnings: &[String]) -> Vec<Problem>;
    /// A setting's help, for forms and (later) the agent.
    fn explain(&self, path: &str) -> Option<&'static str> {
        cfg::fields::find(self.fields(), path).map(|f| f.help)
    }
    /// A new record for the list at `list` (`servers.myserver.timers`), as `n` adds it.
    fn blank(&self, _list: &str) -> Option<Value> {
        None
    }
    /// What the setting at `path` is one of, when that is only known here (a tracked
    /// item's workflow: that server's workflows). `disk`: files may be read.
    fn choices(&self, _d: &dyn DocAny, _path: &str, _disk: bool) -> Option<Vec<String>> {
        None
    }
    /// Something a field can do besides being typed (`K` on it): a network's backup
    /// recipients make a key.
    fn action(&self, _path: &str) -> Option<FieldAction> {
        None
    }
    /// Do it with what was typed: the element to add to the field's list, or why not.
    fn act(&self, _path: &str, _arg: &str) -> Result<String, String> {
        Err("nothing to do here".into())
    }
    /// The connection checks of one entry (`c`): what runs them, on a worker thread. Reads
    /// only. None: this kind has no host to check.
    fn check(&self, _d: &dyn DocAny, _entry: &str) -> Option<Checker> {
        None
    }
    /// Look at the host behind `ssh` (on a worker thread, reads only) and draft its entry
    /// under `name`. Which kind a host is, is the binary's to tell: it asks the right one.
    fn probe(&self, ssh: &str, _name: &str) -> Probe {
        Probe::Failed(Refused {
            ssh: ssh.to_string(),
            why: "this kind of config has no hosts".into(),
            todo: String::new(),
        })
    }
    /// An entry's workflows and how often each is due. `disk`: its folders may be read
    /// (else: the seeded set as shipped).
    fn upkeep(&self, _d: &dyn DocAny, _entry: &str, _disk: bool) -> Upkeep {
        Upkeep::default()
    }
    /// The file's tree (as staged, as on disk, or a draft's entry in a file of its own) as
    /// the Config tab's wizard may see it: what is private in this kind of file hidden by
    /// its own rules, then whatever still looks private masked.
    fn for_agent(&self, tree: &Value) -> AgentView {
        AgentView {
            tree: masked(tree),
            ..Default::default()
        }
    }
    /// A draft's note as the wizard may see it (None: not at all).
    fn agent_note(&self, note: &cfg::Note) -> Option<String> {
        Some(cfg::hide::mask(&note.text))
    }
    /// A problem's text as the wizard may see it.
    fn agent_problem(&self, text: &str) -> String {
        cfg::hide::mask(text)
    }
    /// The change that makes `workflow` due every `every` for this entry (None: not on a
    /// cadence; `off` where the kind has it): the setting to stage and its whole value.
    fn cadence(
        &self,
        _d: &dyn DocAny,
        _entry: &str,
        _workflow: &str,
        _every: Option<&str>,
    ) -> Option<(String, Option<Value>)> {
        None
    }
}

/// What the Config tab's wizard may see of a file: an agent is never shown a config file
/// as it is.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AgentView {
    /// The file's tree with everything private in it hidden or taken out. It still reads
    /// as the file's type, so it can be printed as the file would be.
    pub tree: Value,
    /// What was taken out and how much of it there is: (entry, a line).
    pub notes: Vec<(String, String)>,
    /// Entries that are only counted, not shown, and why (a network that has no salt
    /// yet): a command that prints the file leaves them out and says so.
    pub held: Vec<(String, String)>,
}

/// Every text in a tree through [`cfg::hide::mask`]: the net under each kind's own rules.
pub fn masked(v: &Value) -> Value {
    match v {
        Value::Str(s) => Value::Str(cfg::hide::mask(s)),
        Value::List(l) => Value::List(l.iter().map(masked).collect()),
        Value::Map(m) => Value::Map(m.iter().map(|(k, v)| (k.clone(), masked(v))).collect()),
        v => v.clone(),
    }
}

/// How a check line reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Ok,
    Note,
    Bad,
}

/// One line of a connection check: `✓ reachable · 41 ms`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckLine {
    pub mark: Mark,
    pub text: String,
}

impl CheckLine {
    pub fn ok(text: impl Into<String>) -> Self {
        Self {
            mark: Mark::Ok,
            text: text.into(),
        }
    }
    pub fn note(text: impl Into<String>) -> Self {
        Self {
            mark: Mark::Note,
            text: text.into(),
        }
    }
    pub fn bad(text: impl Into<String>) -> Self {
        Self {
            mark: Mark::Bad,
            text: text.into(),
        }
    }

    /// As a terminal prints it.
    pub fn line(&self) -> String {
        let mark = match self.mark {
            Mark::Ok => "✓",
            Mark::Note => "·",
            Mark::Bad => "✗",
        };
        format!("{mark} {}", self.text)
    }
}

/// What runs an entry's connection checks (on a worker thread).
pub type Checker = Box<dyn FnOnce() -> Vec<CheckLine> + Send>;

/// Something a field's key does: what it is called and what it asks for first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldAction {
    /// The key bar's word for it (`make a key`).
    pub label: &'static str,
    /// What the line typed is (`Where the secret key is written`).
    pub prompt: String,
    /// What the line starts as.
    pub start: String,
    /// What is said when it is done.
    pub done: &'static str,
}

/// What looking at a host came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Probe {
    Drafted(Drafted),
    Failed(Refused),
}

/// An entry drafted from what a host said.
#[derive(Debug, Clone, PartialEq)]
pub struct Drafted {
    pub file: FileId,
    /// `server`, `network`.
    pub kind: &'static str,
    /// The name it was drafted under (the area picks another when it is taken).
    pub name: String,
    pub ssh: String,
    /// The entry, as its file holds one.
    pub entry: Value,
    /// What the draft says about itself; a note's path is within the entry (`timers`).
    pub notes: Vec<cfg::Note>,
    /// What the host is, in a few words (its system).
    pub what: String,
}

/// A host that couldn't be looked at: why, and what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub ssh: String,
    pub why: String,
    pub todo: String,
}

/// One workflow (or routine job) of a system, and how often it is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfRow {
    pub name: String,
    /// What it is for, in a line.
    pub title: String,
    /// `workflow`, `job`.
    pub what: &'static str,
    /// It is the system's own copy (not the shared set's).
    pub own: bool,
    pub draft: bool,
    /// What its lint says.
    pub problems: Vec<String>,
    /// How often it is due as the file says: `30d`, `off`, or nothing (not on a cadence).
    pub every: String,
    /// What applies when the file says nothing (a job's own default).
    pub default: String,
    /// What the setup flow proposes for a system just added (None: nothing).
    pub suggest: Option<&'static str>,
    /// Its file, where it has one.
    pub path: Option<PathBuf>,
}

/// A system's upkeep: its workflows, and where they come from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Upkeep {
    pub rows: Vec<WfRow>,
    /// The folder of the set its kind of device shares.
    pub shared: PathBuf,
    /// The folder of its own set, which replaces the shared one when it holds any (None:
    /// this kind has no set per system).
    pub own: Option<PathBuf>,
    /// It follows its own set now.
    pub has_own: bool,
}

/// What a draft's notes say of `path` within its entry.
pub fn note_on<'a>(notes: &'a [cfg::Note], path: &str) -> Option<&'a str> {
    notes
        .iter()
        .find(|n| n.path.as_deref() == Some(path))
        .map(|n| n.text.as_str())
}

/// A draft's notes with their paths within the entry (`servers.<name>.timers` → `timers`).
pub fn notes_within(notes: Vec<cfg::Note>, entry_path: &str) -> Vec<cfg::Note> {
    notes
        .into_iter()
        .map(|mut n| {
            n.path = n.path.map(|p| {
                p.strip_prefix(entry_path)
                    .and_then(|r| r.strip_prefix('.'))
                    .unwrap_or(&p)
                    .to_string()
            });
            n
        })
        .collect()
}

/// Set the setting at `path` to `to` (None: take it away) on what is to be: the change that
/// did it, with what was there as its `from`. Refused by the type: nothing changed.
pub fn set(d: &mut dyn DocAny, path: &str, to: Option<Value>, by: By) -> Result<Change, String> {
    let segs = parse_path(path)?;
    let c = Change {
        file: d.file(),
        path: path.to_string(),
        from: d.tree().at(&segs).cloned(),
        to,
        by,
        on: true,
    };
    d.apply(&c)?;
    Ok(c)
}

/// A config value as a form shows it, by the kind its table gives it. None: not something a
/// form holds (a section, a map of records).
pub fn to_form(kind: cfg::Kind, v: Option<&Value>) -> Option<form::Value> {
    let text = |v: &Value| match v {
        Value::Str(s) => s.clone(),
        Value::Null => String::new(),
        v => v.to_string(),
    };
    Some(match (kind, v) {
        (cfg::Kind::Text, v) => form::Value::Text(v.map(text).unwrap_or_default()),
        (cfg::Kind::Bool, Some(Value::Bool(b))) => form::Value::Bool(*b),
        (cfg::Kind::Number, Some(Value::Int(n))) => form::Value::Int(*n),
        (cfg::Kind::Number, Some(Value::Float(x))) => form::Value::Float(*x),
        (cfg::Kind::Duration, Some(Value::Str(s))) => form::Value::Dur(s.parse().ok()?),
        // A date, or none yet: an empty one.
        (cfg::Kind::Date, v) => form::Value::Date(v.map(text).unwrap_or_default()),
        (cfg::Kind::Choice(words), Some(Value::Str(s))) => form::Value::Pick(
            words.iter().map(|w| w.to_string()).collect(),
            words.iter().position(|w| w == s)?,
        ),
        (cfg::Kind::List, v) => form::Value::List(match v {
            Some(Value::List(l)) => l.iter().map(text).collect(),
            _ => Vec::new(),
        }),
        (cfg::Kind::Map, v) => form::Value::Pairs(match v {
            // Named lists of words (a zone's interfaces): `name = a b`.
            Some(Value::Map(m)) if !m.is_empty() && m.iter().all(|(_, v)| words(v).is_some()) => m
                .iter()
                .map(|(k, v)| (k.clone(), words(v).unwrap_or_default()))
                .collect(),
            Some(Value::Map(m)) => {
                if m.iter().any(|(_, v)| !matches!(v, Value::Str(_))) {
                    return None;
                }
                m.iter().map(|(k, v)| (k.clone(), text(v))).collect()
            }
            _ => Vec::new(),
        }),
        (cfg::Kind::Records, v) => {
            let rows: Vec<&Vec<(String, Value)>> = match v {
                Some(Value::List(l)) => l
                    .iter()
                    .filter_map(|r| match r {
                        Value::Map(m) => Some(m),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let cols: Vec<String> = rows
                .first()
                .map(|m| m.iter().map(|(k, _)| k.clone()).collect())
                .unwrap_or_default();
            form::Value::Rows(
                cols,
                rows.iter()
                    .map(|m| m.iter().map(|(_, v)| text(v)).collect())
                    .collect(),
            )
        }
        _ => return None,
    })
}

/// A list of words on one line (`lan guest`); None: not a list of words.
fn words(v: &Value) -> Option<String> {
    match v {
        Value::List(l) => l
            .iter()
            .map(|x| match x {
                Value::Str(s) => Some(s.clone()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .map(|w| w.join(" ")),
        _ => None,
    }
}

/// Named entries as named lists of words: what `name = a b` means where the setting is
/// one (a zone's interfaces).
pub fn lists_of(v: Value) -> Value {
    match v {
        Value::Map(m) => Value::Map(
            m.into_iter()
                .map(|(k, v)| {
                    let v = match v {
                        Value::Str(s) => Value::List(
                            s.split([' ', ','])
                                .filter(|w| !w.is_empty())
                                .map(|w| Value::Str(w.to_string()))
                                .collect(),
                        ),
                        v => v,
                    };
                    (k, v)
                })
                .collect(),
        ),
        v => v,
    }
}

/// A form's value as the file holds it. `nullable`: the setting may be left unset, which is
/// what an empty text or list means.
pub fn from_form(v: &form::Value, nullable: bool) -> Value {
    match v {
        form::Value::Text(s) if s.is_empty() && nullable => Value::Null,
        form::Value::Text(s) => Value::Str(s.clone()),
        form::Value::Bool(b) => Value::Bool(*b),
        form::Value::Pick(words, at) => Value::Str(words.get(*at).cloned().unwrap_or_default()),
        form::Value::Int(n) => Value::Int(*n),
        form::Value::Float(x) => Value::Float(*x),
        form::Value::Dur(d) => Value::Str(d.to_string()),
        form::Value::List(l) if l.is_empty() && nullable => Value::Null,
        form::Value::List(l) => Value::List(l.iter().cloned().map(Value::Str).collect()),
        form::Value::Pairs(p) => Value::Map(
            p.iter()
                .map(|(k, v)| (k.clone(), Value::Str(v.clone())))
                .collect(),
        ),
        form::Value::Date(s) if s.is_empty() => Value::Null,
        form::Value::Date(s) => Value::Str(s.clone()),
        form::Value::Rows(..) | form::Value::Fold(..) => Value::Null,
    }
}

/// A default as a form's side panel says it: a word or a few; nothing for what has none
/// worth saying (not set, an empty list, a group).
pub fn default_shown(v: &Value) -> String {
    match v {
        Value::Bool(true) => "yes".into(),
        Value::Bool(false) => "no".into(),
        Value::Null | Value::Map(_) => String::new(),
        Value::List(l) if l.is_empty() => String::new(),
        Value::Str(s) if s.is_empty() => String::new(),
        // (A whole number reads as one: 90, not 90.0.)
        Value::Float(x) => x.to_string(),
        v => plain(Some(v)),
    }
}

/// A value in a few words, as people write it (no quotes round a word).
pub fn plain(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "(not set)".into(),
        Some(Value::Str(s)) if s.is_empty() => "(empty)".into(),
        Some(Value::Str(s)) => s.clone(),
        Some(Value::List(l)) if l.is_empty() => "(none)".into(),
        Some(Value::List(l)) => l
            .iter()
            .map(|v| plain(Some(v)))
            .collect::<Vec<_>>()
            .join(", "),
        Some(Value::Map(m)) if m.is_empty() => "(none)".into(),
        Some(Value::Map(m)) => m
            .iter()
            .map(|(k, v)| format!("{k} = {}", plain(Some(v))))
            .collect::<Vec<_>>()
            .join(", "),
        Some(v) => v.to_string(),
    }
}

/// What a change does, in a few words: `claude → /opt/claude`, `+ notes.md`, `− srv:other`,
/// `quit = Q`, `order`.
pub fn what_changed(from: Option<&Value>, to: Option<&Value>) -> String {
    let list = |v: Option<&Value>| match v {
        Some(Value::List(l)) => Some(l.clone()),
        None | Some(Value::Null) => Some(Vec::new()),
        _ => None,
    };
    let map = |v: Option<&Value>| match v {
        Some(Value::Map(m)) => Some(m.clone()),
        None | Some(Value::Null) => Some(Vec::new()),
        _ => None,
    };
    let is_list = |v: Option<&Value>| matches!(v, Some(Value::List(_)));
    let is_map = |v: Option<&Value>| matches!(v, Some(Value::Map(_)));
    if (is_list(from) || is_list(to))
        && let (Some(a), Some(b)) = (list(from), list(to))
    {
        let mut parts: Vec<String> = b
            .iter()
            .filter(|x| !a.contains(x))
            .map(|x| format!("+ {}", plain(Some(x))))
            .collect();
        parts.extend(
            a.iter()
                .filter(|x| !b.contains(x))
                .map(|x| format!("− {}", plain(Some(x)))),
        );
        if parts.is_empty() {
            return format!("order: {}", plain(to));
        }
        // What was unset names everything it shows from now on.
        if matches!(from, None | Some(Value::Null)) {
            return format!("only {}", plain(to));
        }
        return parts.join(", ");
    }
    if (is_map(from) || is_map(to))
        && let (Some(a), Some(b)) = (map(from), map(to))
    {
        let get =
            |m: &[(String, Value)], k: &str| m.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone());
        let mut parts: Vec<String> = b
            .iter()
            .filter(|(k, v)| get(&a, k).as_ref() != Some(v))
            .map(|(k, v)| format!("{k} = {}", plain(Some(v))))
            .collect();
        parts.extend(
            a.iter()
                .filter(|(k, _)| get(&b, k).is_none())
                .map(|(k, _)| format!("− {k}")),
        );
        return parts.join(", ");
    }
    match (from, to) {
        (Some(Value::Bool(_)), Some(Value::Bool(b))) => if *b { "on" } else { "off" }.to_string(),
        _ => format!("{} → {}", plain(from), plain(to)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(json: &str) -> Value {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_change_is_said_in_a_few_words() {
        let w = |a: &str, b: &str| what_changed(Some(&v(a)), Some(&v(b)));
        assert_eq!(w("\"claude\"", "\"/opt/claude\""), "claude → /opt/claude");
        assert_eq!(w("null", "\"ghostty -e\""), "(not set) → ghostty -e");
        assert_eq!(w("true", "false"), "off");
        assert_eq!(w("12", "6"), "12 → 6");
        assert_eq!(w("[\"a\", \"b\"]", "[\"b\", \"c\"]"), "+ c, − a");
        assert_eq!(w("[\"a\", \"b\"]", "[\"b\", \"a\"]"), "order: b, a");
        assert_eq!(w("null", "[\"local\"]"), "only local");
        assert_eq!(w("[\"local\"]", "null"), "− local");
        assert_eq!(
            w(
                "{\"quit\": \"Q\", \"help\": \"F1\"}",
                "{\"quit\": \"X\", \"up\": \"w\"}"
            ),
            "quit = X, up = w, − help"
        );
    }

    #[test]
    fn a_value_goes_to_a_form_and_comes_back_as_the_file_holds_it() {
        use sentry_core::config::Dur;
        let round = |k: cfg::Kind, json: &str, nullable: bool| {
            let f = to_form(k, Some(&v(json))).unwrap();
            assert_eq!(from_form(&f, nullable), v(json), "{f:?}");
            f
        };
        round(cfg::Kind::Text, "\"claude\"", false);
        // What may be unset is unset when it is empty; what may not stays an empty text.
        assert_eq!(
            round(cfg::Kind::Text, "null", true),
            form::Value::Text("".into())
        );
        assert_eq!(from_form(&form::Value::Text("".into()), false), v("\"\""));
        round(cfg::Kind::Bool, "true", false);
        round(cfg::Kind::Number, "12", false);
        round(cfg::Kind::Number, "1.5", false);
        // A date; none is an empty one, and empty is unset again.
        assert_eq!(
            round(cfg::Kind::Date, "\"2027-03-31\"", true),
            form::Value::Date("2027-03-31".into())
        );
        assert_eq!(
            round(cfg::Kind::Date, "null", true),
            form::Value::Date("".into())
        );
        assert_eq!(
            to_form(cfg::Kind::Date, None),
            Some(form::Value::Date("".into()))
        );
        // A map of durations is named entries; the type says what isn't a duration.
        round(
            cfg::Kind::Map,
            "{\"apt-maintenance\": \"30d\", \"compose-update\": \"14d\"}",
            false,
        );
        assert_eq!(default_shown(&v("90.0")), "90");
        assert_eq!(default_shown(&v("2.5")), "2.5");
        assert_eq!(default_shown(&v("true")), "yes");
        assert_eq!(default_shown(&v("[\"host\", \"home\"]")), "host, home");
        assert_eq!(default_shown(&v("null")), "");
        assert_eq!(default_shown(&v("[]")), "");
        assert_eq!(
            round(cfg::Kind::Duration, "\"36h\"", false),
            form::Value::Dur(Dur::hours(36))
        );
        round(
            cfg::Kind::Choice(&["claude-code"]),
            "\"claude-code\"",
            false,
        );
        round(cfg::Kind::List, "[\"local\", \"srv:myserver\"]", true);
        assert_eq!(
            round(cfg::Kind::List, "null", true),
            form::Value::List(vec![])
        );
        round(cfg::Kind::Map, "{\"quit\": \"Q\"}", false);
        // Records are rows to look at; a section and a map of records are not a field.
        let rows = to_form(
            cfg::Kind::Records,
            Some(&v("[{\"unit\": \"backup.timer\", \"max_age\": \"26h\"}]")),
        );
        assert_eq!(
            rows,
            Some(form::Value::Rows(
                vec!["unit".into(), "max_age".into()],
                vec![vec!["backup.timer".into(), "26h".into()]]
            ))
        );
        assert_eq!(to_form(cfg::Kind::Section, Some(&v("{}"))), None);
        assert_eq!(
            to_form(cfg::Kind::Map, Some(&v("{\"a\": {\"b\": 1}}"))),
            None
        );
        assert_eq!(to_form(cfg::Kind::Choice(&["a"]), Some(&v("\"z\""))), None);
    }
}

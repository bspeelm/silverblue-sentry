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
}

/// One setting in a form: where it is, and what the form says about it beyond its table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Item {
    /// The setting's path in its file (`review.at_start`, `servers.myserver.ssh`).
    pub path: String,
    /// What an empty value means, shown in its place.
    pub empty: String,
}

impl Item {
    pub fn at(path: &str) -> Self {
        Self {
            path: path.to_string(),
            empty: String::new(),
        }
    }

    pub fn empty(mut self, what: &str) -> Self {
        self.empty = what.to_string();
        self
    }
}

/// A titled group of settings in an entry's form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub title: String,
    pub items: Vec<Item>,
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
    /// An entry's form: the settings the table marks `essential`, grouped.
    fn sections(&self, d: &dyn DocAny, entry: &str) -> Vec<Section>;
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
    // For the next part (servers' and networks' forms, discovery, upkeep), each with a
    // default so the kinds there are keep compiling:
    //   fn probe(&self, ssh: &str) -> Probe            (on a worker: `init::discover`)
    //   fn check(&self, d: &dyn DocAny, entry: &str) -> Vec<CheckLine>
    //   fn upkeep(&self, d: &dyn DocAny, entry: &str) -> Vec<WfRow>
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

/// The essential settings directly in the entry at `prefix` (`servers.myserver`), as items:
/// what a kind without sections of its own shows.
pub fn essentials(fields: &[Field], pattern: &str, prefix: &str) -> Vec<Item> {
    fields
        .iter()
        .filter(|f| f.essential && f.kind != cfg::Kind::Section)
        .filter_map(|f| {
            let rest = f.path.strip_prefix(pattern)?.strip_prefix('.')?;
            (!rest.contains(['[', '*'])).then(|| Item::at(&format!("{prefix}.{rest}")))
        })
        .collect()
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
        (cfg::Kind::Choice(words), Some(Value::Str(s))) => form::Value::Pick(
            words.iter().map(|w| w.to_string()).collect(),
            words.iter().position(|w| w == s)?,
        ),
        (cfg::Kind::List, v) => form::Value::List(match v {
            Some(Value::List(l)) => l.iter().map(text).collect(),
            _ => Vec::new(),
        }),
        (cfg::Kind::Map, v) => form::Value::Pairs(match v {
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
        form::Value::Rows(..) => Value::Null,
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

//! What the Config tab's wizard proposes: one ```` ```sentry-config ```` TOML block at the
//! end of an answer, `[[set]]`, `[[add]]` and `[[remove]]` tables, each naming a setting by
//! its path. [`take`] reads the block and checks every table against the field tables and
//! the files as they are staged now; what doesn't hold is dropped with its reason, and
//! nothing here stages or writes anything: the window stages what comes back, ticked, for
//! the user to save or not.
//!
//! ```toml
//! [[set]]                      # a setting, or one field of a record in a list
//! path = "servers.myserver.timers[0].max_age"
//! value = "26h"
//! why = "the backup runs daily; 24h leaves no slack"
//!
//! [[add]]                      # one more element of a list
//! path = "servers.myserver.services"
//! value = "app.service"
//! why = "…"
//!
//! [[add]]                      # one more named entry (`key`)
//! path = "keys"
//! key = "quit"
//! value = "Q"
//!
//! [[remove]]                   # an element of a list, a named entry, or an optional setting
//! path = "servers.myserver.listeners[2]"
//! value = "*:8080/*"           # optional: only if that is what is there
//! ```
//! `file = "app" | "servers" | "networks"` may be given; the path says it anyway.
//!
//! What can never be proposed, whatever the answer says: a whole server or network (adding
//! one goes through discovery, removing one is the user's `x`), and the settings in
//! [`NEVER`]: the program sentry starts as its agent, every other command or host sentry
//! would run or connect to, and what decides who may read what.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::fields::{self, Field, Kind};
use super::value::{Seg, Value, parse_path, path_string};
use super::{FileId, change};

pub const FENCE: &str = "```sentry-config";

/// What a proposal does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Set,
    Add,
    Remove,
}

impl Op {
    pub fn word(self) -> &'static str {
        match self {
            Op::Set => "set",
            Op::Add => "add",
            Op::Remove => "remove",
        }
    }
}

/// A proposal that holds up: the setting to stage and what it is to be.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposed {
    pub file: FileId,
    /// The setting as the window stages one: a scalar at its own path, a list or named
    /// entries whole at theirs (so a change inside a list is that list's change).
    pub path: String,
    /// The setting's whole value once this is made (and every proposal before it in the
    /// same block).
    pub to: Value,
    pub op: Op,
    /// The path as the answer wrote it.
    pub at: String,
    /// What it does, in a few words: `backup.timer · max_age 24h → 26h`, `+ app.service`.
    pub said: String,
    pub why: String,
}

/// A proposal left out, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    /// `set servers.myserver.timers[0].max_age`.
    pub what: String,
    pub why: String,
}

/// One file as it is staged now.
pub struct File<'a> {
    pub id: FileId,
    pub fields: &'static [Field],
    pub tree: Value,
    /// The file's type reads this tree: the tree as the type writes it back.
    pub reads: &'a dyn Fn(&Value) -> Result<Value, String>,
}

/// What proposals are checked against.
pub struct Known<'a> {
    /// The files that parse (a proposal for one that doesn't is dropped).
    pub files: Vec<File<'a>>,
    /// The settings the user changed by hand in this window: never proposed over.
    pub yours: Vec<String>,
}

/// The settings no proposal may touch, each with why. Patterns as the field tables write
/// them; what is under one is covered too.
pub const NEVER: &[(&str, &str)] = &[
    (
        "agent",
        "which program sentry starts as its agent is yours alone to say",
    ),
    (
        "audit.outside",
        "a command sentry runs on this machine is yours alone to write",
    ),
    (
        "ui.terminal",
        "a program sentry starts on this machine is yours alone to name",
    ),
    (
        "maintenance.notes",
        "which files an agent may read is yours alone to say",
    ),
    (
        "servers.*.ssh",
        "which host sentry connects to is yours alone to say",
    ),
    (
        "servers.*.sudo",
        "what runs as root on a server is yours alone to say",
    ),
    (
        "servers.*.actions",
        "a command sentry runs on a server is yours alone to write",
    ),
    (
        "servers.*.maintenance.items[].version_cmd",
        "a command sentry runs on a server is yours alone to write",
    ),
    (
        "servers.*.maintenance.notes",
        "which files an agent may read is yours alone to say",
    ),
    (
        "networks.*.router.ssh",
        "which host sentry connects to is yours alone to say",
    ),
    (
        "networks.*.backup.recipients",
        "who can decrypt a backup is yours alone to say",
    ),
    (
        "networks.*.notes",
        "which files an agent may read is yours alone to say",
    ),
    (
        "networks.*.claude",
        "what an agent may see of the network is yours alone to say",
    ),
];

/// Why nothing may be proposed at `path`, if it is one of [`NEVER`].
pub fn never(path: &[Seg]) -> Option<&'static str> {
    NEVER
        .iter()
        .find(|(pat, _)| fields::under(pat, path))
        .map(|(_, why)| *why)
}

/// One table of the block.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    path: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    why: String,
}

/// A value in a few words, as people write it.
fn plain(v: &Value) -> String {
    match v {
        Value::Null => "(not set)".into(),
        Value::Bool(true) => "on".into(),
        Value::Bool(false) => "off".into(),
        Value::Str(s) if s.is_empty() => "(empty)".into(),
        Value::Str(s) => s.clone(),
        // A record by what names it: its first word.
        Value::Map(m) => match m.iter().find_map(|(_, v)| match v {
            Value::Str(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }) {
            Some(name) => name,
            None => v.to_string(),
        },
        Value::List(l) => l.iter().map(plain).collect::<Vec<_>>().join(", "),
        v => v.to_string(),
    }
}

fn first_line(e: &str) -> String {
    e.lines().next().unwrap_or_default().trim().to_string()
}

/// Where the setting a path is in ends: the first list, list of records or named entries
/// on the way (staged whole), else the path itself. None: no such setting.
fn setting(file: FileId, fields: &[Field], segs: &[Seg]) -> Option<usize> {
    let start = if file == FileId::App { 1 } else { 3 };
    for n in start..=segs.len() {
        match fields.iter().find(|f| f.is(&segs[..n])) {
            Some(f) if matches!(f.kind, Kind::List | Kind::Records | Kind::Map) => return Some(n),
            Some(f) if n == segs.len() && f.kind != Kind::Section => return Some(n),
            _ => {}
        }
    }
    None
}

/// Every path the change from `a` to `b` (both at `at`) sets something at.
fn touched(at: &[Seg], a: &Value, b: &Value) -> Vec<Vec<Seg>> {
    let mut raw = Vec::new();
    change::diff_trees(&mut at.to_vec(), a, b, &mut raw);
    let mut out = Vec::new();
    for (path, _, to) in raw {
        let Ok(segs) = parse_path(&path) else {
            continue;
        };
        // What is put there, leaf by leaf (a record added brings its fields).
        if let Some(v) = &to {
            for leaf in v.leaves() {
                if v.at(&leaf).is_some_and(|x| *x != Value::Null) {
                    out.push(segs.iter().cloned().chain(leaf).collect());
                }
            }
        }
        out.push(segs);
    }
    out
}

struct Work<'a> {
    file: &'a File<'a>,
    tree: Value,
}

/// One table against what there is: the proposal, or why not. `w.tree` is as it is after
/// every proposal taken so far, and is changed only when this one holds.
fn one(op: Op, raw: &Raw, k: &Known, works: &mut [Work]) -> Result<Proposed, String> {
    let segs = parse_path(&raw.path).map_err(|e| format!("not a setting's path: {e}"))?;
    let file = FileId::of_path(&raw.path);
    if let Some(f) = &raw.file
        && FileId::from_word(f) != Some(file)
    {
        return Err(format!(
            "`{}` is a setting of {}, not of `{f}`",
            raw.path,
            file.name()
        ));
    }
    // A whole server or network is never the wizard's to add or take away.
    if file != FileId::App && (segs.len() < 2 || (segs.len() == 2 && op != Op::Set)) {
        return Err(match op {
            Op::Remove => "removing a system is yours: x on it in the Overview".to_string(),
            _ => "adding a system goes through discovery: `+ add a system` in the Overview"
                .to_string(),
        });
    }
    if file != FileId::App && segs.len() == 2 {
        return Err("a whole system can't be set: name one of its settings".to_string());
    }
    if let Some(why) = never(&segs) {
        return Err(why.to_string());
    }
    let Some(w) = works.iter_mut().find(|w| w.file.id == file) else {
        return Err(format!("{} doesn't parse: e opens it", file.name()));
    };
    if file != FileId::App && w.tree.at(&segs[..2]).is_none() {
        return Err(format!(
            "there is no {} `{}`",
            if file == FileId::Servers {
                "server"
            } else {
                "network"
            },
            match &segs[1] {
                Seg::Key(k) => k.as_str(),
                Seg::Index(_) => "?",
            }
        ));
    }
    let n = setting(file, w.file.fields, &segs)
        .ok_or("no such setting (`sentry config explain` lists them)")?;
    let (at, within) = segs.split_at(n);
    let at_path = path_string(at);
    // (A system still being drafted is one change of the user's, and what is proposed in
    // it is laid over the draft: only a setting they changed itself is theirs alone.)
    if k.yours
        .iter()
        .any(|y| parse_path(y).is_ok_and(|y| y.starts_with(at)))
    {
        return Err("you changed this yourself".to_string());
    }
    let before = w.tree.at(at).cloned().unwrap_or(Value::Null);
    let there = w.tree.at(&segs).cloned();
    let mut tree = w.tree.clone();
    // Where a list or named entries would be and nothing is yet: an empty one.
    let field = w.file.fields.iter().find(|f| f.is(&segs));
    let empty = |f: Option<&Field>| match f.map(|f| f.kind) {
        Some(Kind::List | Kind::Records) => Some(Value::List(Vec::new())),
        Some(Kind::Map) => Some(Value::Map(Vec::new())),
        _ => None,
    };
    let said = match op {
        Op::Set => {
            let value = raw.value.clone().ok_or("a set needs a `value`")?;
            if raw.key.is_some() {
                return Err("`key` is for an add to named entries".to_string());
            }
            let Some(now) = there else {
                return Err(format!("{} isn't there: add it, or set what is", raw.path));
            };
            tree.set(&segs, Some(value.clone()))?;
            // Inside a list of records: which record, and which field of it.
            let lead = match within {
                [Seg::Index(i), rest @ ..] if !rest.is_empty() => {
                    let record = before.at(&[Seg::Index(*i)]).map(plain).unwrap_or_default();
                    format!("{record} · {} ", path_string(rest))
                }
                [first, ..] => format!("{} ", path_string(std::slice::from_ref(first))),
                [] => String::new(),
            };
            format!("{lead}{} → {}", plain(&now), plain(&value))
        }
        Op::Add => {
            let value = raw.value.clone().ok_or("an add needs a `value`")?;
            let now = match there {
                Some(Value::Null) | None => empty(field)
                    .ok_or_else(|| format!("{} isn't a list or named entries", raw.path))?,
                Some(v) => v,
            };
            match (now, &raw.key) {
                (Value::List(mut l), None) => {
                    if l.contains(&value) {
                        return Err("it is there already".to_string());
                    }
                    l.push(value.clone());
                    tree.set(&segs, Some(Value::List(l)))?;
                    format!("+ {}", plain(&value))
                }
                (Value::List(_), Some(_)) => {
                    return Err("`key` is for named entries; this is a list".to_string());
                }
                (Value::Map(mut m), Some(key)) if field.is_some_and(|f| f.kind == Kind::Map) => {
                    if m.iter().any(|(x, _)| x == key) {
                        return Err(format!("`{key}` is there already: set it"));
                    }
                    m.push((key.clone(), value.clone()));
                    tree.set(&segs, Some(Value::Map(m)))?;
                    format!("+ {key} = {}", plain(&value))
                }
                (Value::Map(_), None) if field.is_some_and(|f| f.kind == Kind::Map) => {
                    return Err("an add to named entries needs a `key`".to_string());
                }
                _ => return Err(format!("{} isn't a list or named entries", raw.path)),
            }
        }
        Op::Remove => {
            let Some(now) = there else {
                return Err(format!("{} isn't there", raw.path));
            };
            if let Some(expected) = &raw.value
                && *expected != now
            {
                return Err(format!(
                    "{} is {} now, not {}",
                    raw.path,
                    plain(&now),
                    plain(expected)
                ));
            }
            // An element of a list or a named entry goes; a setting of its own is unset
            // (which its type allows or doesn't).
            let element = matches!(segs.last(), Some(Seg::Index(_)))
                || segs.split_last().is_some_and(|(_, up)| {
                    w.file
                        .fields
                        .iter()
                        .any(|f| f.kind == Kind::Map && f.is(up))
                });
            match element {
                true => tree.set(&segs, None)?,
                false if now == Value::Null => return Err("it isn't set".to_string()),
                false => tree.set(&segs, Some(Value::Null))?,
            }
            format!("− {}", plain(&now))
        }
    };
    // The type decides whether that is a value it holds; what it reads it as is what is
    // staged.
    let read = (w.file.reads)(&tree).map_err(|e| {
        let e = first_line(&e);
        // (Where in the type's own text it stopped reading means nothing here.)
        match e.rsplit_once(" at line ") {
            Some((what, _)) => what.to_string(),
            None => e,
        }
    })?;
    let to = read.at(at).cloned().unwrap_or(Value::Null);
    if to == before {
        return Err("it is that already".to_string());
    }
    // Whatever the path named, nothing a proposal sets may be one of the never-settings
    // (a record added to a list brings its fields with it).
    if let Some(why) = touched(at, &before, &to).iter().find_map(|p| never(p)) {
        return Err(why.to_string());
    }
    w.tree = read;
    Ok(Proposed {
        file,
        path: at_path,
        to,
        op,
        at: raw.path.clone(),
        said,
        why: raw.why.trim().to_string(),
    })
}

/// An answer → the answer without its block, the proposals that hold up against what
/// there is (in the block's order: sets, adds, removes), and what was left out and why. A
/// block that isn't TOML is said once and proposes nothing. No block: nothing.
pub fn take(answer: &str, k: &Known) -> (String, Vec<Proposed>, Vec<Dropped>) {
    let Some((body, block)) = crate::maint::fenced_block(answer, FENCE) else {
        return (answer.to_string(), Vec::new(), Vec::new());
    };
    let tables: BTreeMap<String, toml::Value> = match toml::from_str(&block) {
        Ok(t) => t,
        Err(e) => {
            return (
                body,
                Vec::new(),
                vec![Dropped {
                    what: "the whole block".to_string(),
                    why: format!("the proposal didn't parse: {}", first_line(&e.to_string())),
                }],
            );
        }
    };
    let mut works: Vec<Work> = k
        .files
        .iter()
        .map(|f| Work {
            file: f,
            tree: f.tree.clone(),
        })
        .collect();
    let (mut out, mut dropped) = (Vec::new(), Vec::new());
    for name in tables.keys() {
        if !["set", "add", "remove"].contains(&name.as_str()) {
            dropped.push(Dropped {
                what: format!("[[{name}]]"),
                why: "a proposal is a [[set]], an [[add]] or a [[remove]]".to_string(),
            });
        }
    }
    for (name, op) in [("set", Op::Set), ("add", Op::Add), ("remove", Op::Remove)] {
        let list = match tables.get(name) {
            Some(toml::Value::Array(a)) => a.clone(),
            Some(_) => {
                dropped.push(Dropped {
                    what: format!("[[{name}]]"),
                    why: format!("write each as a table: [[{name}]]"),
                });
                continue;
            }
            None => continue,
        };
        for v in list {
            let path = v
                .get("path")
                .and_then(|p| p.as_str())
                .unwrap_or("(no path)")
                .to_string();
            let what = format!("{name} {path}");
            let made = v
                .try_into::<Raw>()
                .map_err(|e| first_line(&e.to_string()))
                .and_then(|raw| one(op, &raw, k, &mut works));
            match made {
                Ok(p) => out.push(p),
                Err(why) => dropped.push(Dropped { what, why }),
            }
        }
    }
    (body, out, dropped)
}

/// What the wizard is told about proposing (part of its system text).
pub const HOW: &str = "To propose changes, end your answer with ONE fenced block whose info \
string is `sentry-config`, in TOML, a table per change:\n\
```sentry-config\n\
[[set]]\n\
path = \"servers.myserver.timers[0].max_age\"\n\
value = \"26h\"\n\
why = \"one line: why\"\n\
\n\
[[add]]\n\
path = \"servers.myserver.services\"\n\
value = \"app.service\"\n\
why = \"…\"\n\
\n\
[[remove]]\n\
path = \"servers.myserver.listeners[2]\"\n\
why = \"…\"\n\
```\n\
`path` is a setting's path as `sentry config explain` lists them, with the system's name \
and a list element's index in it. `set` changes a setting that is there (or one field of a \
record in a list); `add` appends `value` to a list, or with `key = \"name\"` adds a named \
entry; `remove` takes a list element or a named entry away, or unsets an optional setting \
(give `value` to remove it only if that is what is there). Values are TOML: a duration is a \
string (\"26h\"), a list of records' element is an inline table. You cannot add or remove a \
whole server or network, and you cannot propose the agent's own command, any command or \
host sentry runs or connects to, a notes file, a backup recipient or what an agent may see: \
those are refused. Every proposal is checked; the user sees which held and which were \
dropped and why, and nothing is saved unless they save it.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn reads(v: &Value) -> Result<Value, String> {
        Value::of(&v.to::<Config>()?)
    }

    fn known(cfg: &Config, yours: &[&str]) -> Known<'static> {
        Known {
            files: vec![File {
                id: FileId::App,
                fields: <Config as crate::cfg::ConfigFile>::FIELDS,
                tree: Value::of(cfg).unwrap(),
                reads: &reads,
            }],
            yours: yours.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn block(body: &str) -> String {
        format!("Here is what I'd do.\n\n```sentry-config\n{body}\n```\n")
    }

    fn drops(d: &[Dropped]) -> Vec<String> {
        d.iter().map(|d| format!("{}: {}", d.what, d.why)).collect()
    }

    #[test]
    fn proposals_that_hold_come_back_as_settings_to_stage() {
        let mut cfg = Config::default();
        cfg.baseline.findings = vec!["a".into(), "b".into()];
        let k = known(&cfg, &[]);
        let (body, got, dropped) = take(
            &block(
                "[[set]]\npath = \"review.at_start\"\nvalue = false\nwhy = \"you asked\"\n\
                 [[set]]\npath = \"recorder.interval\"\nvalue = \"30s\"\n\
                 [[add]]\npath = \"baseline.findings\"\nvalue = \"c\"\nwhy = \"expected here\"\n\
                 [[add]]\npath = \"keys\"\nkey = \"quit\"\nvalue = \"Q\"\n\
                 [[add]]\npath = \"targets.show\"\nvalue = \"local\"\n\
                 [[remove]]\npath = \"baseline.findings[0]\"\nvalue = \"a\"\n",
            ),
            &k,
        );
        assert_eq!(body, "Here is what I'd do.");
        assert_eq!(drops(&dropped), Vec::<String>::new());
        let lines: Vec<String> = got
            .iter()
            .map(|p| format!("{} {} = {} · {}", p.op.word(), p.path, p.to, p.said))
            .collect();
        assert_eq!(
            lines,
            [
                "set review.at_start = false · on → off",
                "set recorder.interval = \"30s\" · 10s → 30s",
                "add baseline.findings = [\"a\", \"b\", \"c\"] · + c",
                "add keys = {quit: \"Q\"} · + quit = Q",
                "add targets.show = [\"local\"] · + local",
                // (After the add before it: the list is staged whole, once.)
                "remove baseline.findings = [\"b\", \"c\"] · − a",
            ]
        );
        assert_eq!(got[0].why, "you asked");
        assert_eq!(got[2].at, "baseline.findings");
        assert_eq!(got[5].at, "baseline.findings[0]");
    }

    #[test]
    fn what_does_not_hold_is_dropped_with_its_reason() {
        let mut cfg = Config::default();
        cfg.baseline.findings = vec!["a".into()];
        let k = known(&cfg, &["review.after_run", "keys"]);
        let (_, got, dropped) = take(
            &block(
                "[[set]]\npath = \"ui.nope\"\nvalue = 1\n\
                 [[set]]\npath = \"recorder.interval\"\nvalue = \"soon\"\n\
                 [[set]]\npath = \"review\"\nvalue = { at_start = true }\n\
                 [[set]]\npath = \"review.after_run\"\nvalue = false\n\
                 [[set]]\npath = \"review.at_start\"\nvalue = true\n\
                 [[set]]\npath = \"review.at_start\"\n\
                 [[set]]\npath = \"baseline.findings[4]\"\nvalue = \"z\"\n\
                 [[set]]\npath = \"retention.reviews\"\nvalue = 3\nbecause = \"x\"\n\
                 [[set]]\npath = \"servers.myserver.ssh\"\nvalue = \"x\"\n\
                 [[set]]\npath = \"review.at_start\"\nfile = \"servers\"\nvalue = true\n\
                 [[add]]\npath = \"keys\"\nkey = \"quit\"\nvalue = \"Q\"\n\
                 [[add]]\npath = \"baseline.findings\"\nvalue = \"a\"\n\
                 [[add]]\npath = \"review.at_start\"\nvalue = \"a\"\n\
                 [[remove]]\npath = \"baseline.findings[0]\"\nvalue = \"b\"\n\
                 [[remove]]\npath = \"baseline.findings[3]\"\n\
                 [[remove]]\npath = \"ui.terminal\"\n\
                 [[rename]]\npath = \"x\"\n",
            ),
            &k,
        );
        assert_eq!(got, []);
        assert_eq!(
            drops(&dropped),
            [
                "[[rename]]: a proposal is a [[set]], an [[add]] or a [[remove]]",
                "set ui.nope: no such setting (`sentry config explain` lists them)",
                "set recorder.interval: bad number in \"soon\"",
                "set review: no such setting (`sentry config explain` lists them)",
                "set review.after_run: you changed this yourself",
                "set review.at_start: it is that already",
                "set review.at_start: a set needs a `value`",
                "set baseline.findings[4]: baseline.findings[4] isn't there: add it, or set \
                 what is",
                "set retention.reviews: unknown field `because`, expected one of `path`, \
                 `file`, `key`, `value`, `why`",
                "set servers.myserver.ssh: which host sentry connects to is yours alone to say",
                "set review.at_start: `review.at_start` is a setting of config.toml, not of \
                 `servers`",
                "add keys: you changed this yourself",
                "add baseline.findings: it is there already",
                "add review.at_start: review.at_start isn't a list or named entries",
                "remove baseline.findings[0]: baseline.findings[0] is a now, not b",
                "remove baseline.findings[3]: baseline.findings[3] isn't there",
                "remove ui.terminal: a program sentry starts on this machine is yours alone \
                 to name",
            ]
        );
    }

    /// The program sentry starts as its agent can't be proposed, by any road.
    #[test]
    fn the_agents_own_command_can_never_be_proposed() {
        let k = known(&Config::default(), &[]);
        let (_, got, dropped) = take(
            &block(
                "[[set]]\npath = \"agent.command\"\nvalue = \"/tmp/other\"\n\
                 [[set]]\npath = \"agent.kind\"\nvalue = \"claude-code\"\n\
                 [[set]]\npath = \"agent\"\nvalue = { command = \"/tmp/other\" }\n\
                 [[remove]]\npath = \"agent.command\"\n\
                 [[add]]\npath = \"agent\"\nkey = \"command\"\nvalue = \"x\"\n\
                 [[set]]\npath = \"audit.outside\"\nvalue = \"curl example.org\"\n",
            ),
            &k,
        );
        assert_eq!(got, []);
        assert_eq!(dropped.len(), 6, "{dropped:?}");
        assert!(
            dropped
                .iter()
                .filter(|d| d.what != "set audit.outside")
                .all(|d| d.why.contains("its agent is yours alone")),
            "{dropped:?}"
        );
        assert!(never(&parse_path("agent.command").unwrap()).is_some());
        assert!(
            never(&parse_path("servers.a.maintenance.items[2].version_cmd").unwrap()).is_some()
        );
        assert!(never(&parse_path("servers.a.sudo[0]").unwrap()).is_some());
        assert!(never(&parse_path("servers.a.services[0]").unwrap()).is_none());
    }

    #[test]
    fn a_block_that_is_not_toml_is_said_once_and_proposes_nothing() {
        let k = known(&Config::default(), &[]);
        let (body, got, dropped) = take(&block("[[set\npath = "), &k);
        assert_eq!(body, "Here is what I'd do.");
        assert_eq!(got, []);
        assert_eq!(dropped.len(), 1);
        assert!(
            dropped[0].why.starts_with("the proposal didn't parse: "),
            "{dropped:?}"
        );
        // No block: the answer as it is.
        let (body, got, dropped) = take("Nothing to change.", &k);
        assert_eq!(
            (body.as_str(), got.len(), dropped.len()),
            ("Nothing to change.", 0, 0)
        );
        // A table that isn't one, a file that doesn't parse here.
        let (_, got, dropped) = take(
            &block("set = 3\n[[add]]\npath = \"networks.home.expect.services\"\nvalue = \"x\"\n"),
            &k,
        );
        assert_eq!(got, []);
        assert_eq!(
            drops(&dropped),
            [
                "[[set]]: write each as a table: [[set]]",
                "add networks.home.expect.services: network_config.yaml doesn't parse: e \
                 opens it",
            ]
        );
    }
}

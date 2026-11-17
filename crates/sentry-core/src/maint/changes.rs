//! What a review proposes to change on the Maintenance list: tasks to add, remove or change,
//! rows to put off or bring back and, on a server, items to track, stop tracking, ignore or
//! change. Claude ends its review with them in a ```` ```sentry-changes ```` TOML block; the
//! review window lists them ticked and Enter applies those left ticked, together. Nothing
//! here touches a machine: only `tasks.toml`, `later.toml` and a server's `items.toml`.

use std::collections::BTreeMap;

use jiff::Timestamp;
use jiff::civil::Date;
use serde::{Deserialize, Serialize};

use super::Level;
use super::later::Snoozes;
use super::tasks::{Source, Task};
use crate::config::Dur;

/// What to set on a server's item (all optional).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ItemSet {
    /// `low`, `medium` or `high`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl ItemSet {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// "risk high · held: …".
    pub fn words(&self) -> String {
        let mut w = Vec::new();
        if let Some(r) = &self.risk {
            w.push(format!("risk {r}"));
        }
        if let Some(h) = &self.hold {
            w.push(format!("held: {h}"));
        }
        if let Some(c) = &self.constraint {
            w.push(format!("constraint: {c}"));
        }
        if let Some(s) = &self.source {
            w.push(format!("source {s}"));
        }
        w.join(" · ")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Kind {
    AddTask {
        task: Box<Task>,
    },
    RemoveTask {
        id: String,
    },
    /// `every`: `off` or a cadence (`30d`).
    SetTask {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        every: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        level: Option<Level>,
    },
    /// The task is done: the log shows it (a run that just ended did what it asks).
    DoneTask {
        id: String,
    },
    /// The task is due again now, whatever its cadence says: something changed.
    AgainTask {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        level: Option<Level>,
    },
    Later {
        key: String,
        until: Date,
    },
    Back {
        key: String,
    },
    /// A server: track what discovery found (its key).
    Track {
        key: String,
        #[serde(default)]
        set: ItemSet,
    },
    Untrack {
        id: String,
    },
    Ignore {
        key: String,
    },
    SetItem {
        id: String,
        #[serde(default)]
        set: ItemSet,
    },
}

/// What you did with a change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    #[default]
    Open,
    Applied,
    Skipped,
    Failed,
}

/// The headings the window lists them under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    Done,
    Remove,
    Add,
    Change,
    PutOff,
}

impl Group {
    pub fn word(self) -> &'static str {
        match self {
            Group::Done => "Done",
            Group::Remove => "Remove",
            Group::Add => "Add",
            Group::Change => "Change",
            Group::PutOff => "Put off",
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    #[serde(default)]
    pub why: String,
    #[serde(default)]
    pub state: State,
    /// What it does, in a few words ("every 30d → 14d").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// After applying: what was written, or why it couldn't be.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// Ticked in the window.
    #[serde(skip, default = "yes")]
    pub on: bool,
    #[serde(flatten)]
    pub kind: Kind,
}

impl Change {
    /// The task a `[[done]]` marks done.
    pub fn done_task(&self) -> Option<&str> {
        match &self.kind {
            Kind::DoneTask { id } => Some(id),
            _ => None,
        }
    }

    fn new(kind: Kind, why: &str, label: String) -> Self {
        Self {
            why: why.trim().to_string(),
            state: State::Open,
            label,
            note: String::new(),
            on: true,
            kind,
        }
    }

    pub fn group(&self) -> Group {
        match self.kind {
            Kind::DoneTask { .. } => Group::Done,
            Kind::RemoveTask { .. } | Kind::Untrack { .. } | Kind::Ignore { .. } => Group::Remove,
            Kind::AddTask { .. } | Kind::Track { .. } => Group::Add,
            Kind::SetTask { .. } | Kind::AgainTask { .. } | Kind::SetItem { .. } => Group::Change,
            Kind::Later { .. } | Kind::Back { .. } => Group::PutOff,
        }
    }

    /// The kind of thing, in the window's second column.
    pub fn word(&self) -> &'static str {
        match self.kind {
            Kind::AddTask { .. } | Kind::RemoveTask { .. } | Kind::SetTask { .. } => "task",
            Kind::DoneTask { .. } => "done",
            Kind::AgainTask { .. } => "again",
            Kind::Untrack { .. } | Kind::SetItem { .. } => "item",
            Kind::Track { .. } => "track",
            Kind::Ignore { .. } => "ignore",
            Kind::Later { .. } => "later",
            Kind::Back { .. } => "back",
        }
    }

    /// What it's about: a task or item id, or a row's key.
    pub fn name(&self) -> &str {
        match &self.kind {
            Kind::AddTask { task } => &task.id,
            Kind::RemoveTask { id }
            | Kind::DoneTask { id }
            | Kind::AgainTask { id, .. }
            | Kind::SetTask { id, .. }
            | Kind::Untrack { id }
            | Kind::SetItem { id, .. } => id,
            Kind::Later { key, .. }
            | Kind::Back { key }
            | Kind::Track { key, .. }
            | Kind::Ignore { key } => key,
        }
    }
}

/// What a change may name: built by each program from everything on its Maintenance list
/// (unfiltered).
#[derive(Default)]
pub struct Known<'a> {
    pub workflows: &'a [String],
    /// Every task that applies (`tasks::effective`), turned off or not.
    pub tasks: &'a [Task],
    /// Every row on the list: (key, title).
    pub rows: &'a [(String, String)],
    pub later: Option<&'a Snoozes>,
    /// A server: the items tracked (id, how it stands).
    pub items: &'a [(String, String)],
    /// A server: what discovery found and nothing tracks (key, what).
    pub found: &'a [(String, String)],
    /// The maintenance log and the time, to say when each task was last done and which are
    /// due (`now` None: not said).
    pub log: &'a [super::log::LogEntry],
    pub audited: Option<Timestamp>,
    pub now: Option<Timestamp>,
}

impl Known<'_> {
    fn item_ids(&self) -> Vec<String> {
        self.items.iter().map(|(i, _)| i.clone()).collect()
    }

    /// "; last done 2026-11-01; due now".
    fn standing(&self, t: &Task) -> String {
        let Some(now) = self.now else {
            return String::new();
        };
        let last = super::tasks::last_done(t, self.log, self.audited)
            .map_or("never done".to_string(), |l| {
                format!("last done {}", l.strftime("%Y-%m-%d"))
            });
        let due = if super::tasks::due(t, self.log, self.audited, now) {
            "due now"
        } else {
            "not due"
        };
        format!("; {last}; {due}")
    }

    fn put_off(&self, key: &str) -> Option<Date> {
        self.later.and_then(|l| l.get(key).copied())
    }
}

const FENCE: &str = "```sentry-changes";

/// One table of the block, whatever its kind.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Raw {
    task: Option<String>,
    item: Option<String>,
    id: Option<String>,
    key: Option<String>,
    why: String,
    every: Option<String>,
    level: Option<Level>,
    until: Option<Date>,
    risk: Option<String>,
    hold: Option<String>,
    constraint: Option<String>,
    source: Option<String>,
}

impl Raw {
    fn name(&self) -> Option<String> {
        [&self.task, &self.item, &self.id, &self.key]
            .into_iter()
            .flatten()
            .map(|s| s.trim().to_string())
            .find(|s| !s.is_empty())
    }

    fn set(&self) -> Result<ItemSet, String> {
        let risk = match self.risk.as_deref().map(|r| r.trim().to_lowercase()) {
            Some(r) if ["low", "medium", "high"].contains(&r.as_str()) => Some(r),
            Some(r) => return Err(format!("risk {r:?} isn't low, medium or high")),
            None => None,
        };
        Ok(ItemSet {
            risk,
            hold: self.hold.clone(),
            constraint: self.constraint.clone(),
            source: self.source.clone(),
        })
    }
}

/// Claude's answer → the review without its changes block, the changes that hold up against
/// what there is, and what was left out and why.
pub fn take(answer: &str, k: &Known, today: Date) -> (String, Vec<Change>, Vec<String>) {
    let Some((body, block)) = super::fenced_block(answer, FENCE) else {
        return (answer.to_string(), Vec::new(), Vec::new());
    };
    let tables: BTreeMap<String, Vec<toml::Value>> = match toml::from_str(&block) {
        Ok(t) => t,
        Err(e) => {
            let why = e.to_string();
            let why = why.lines().next().unwrap_or_default();
            return (
                body,
                Vec::new(),
                vec![format!("the changes block isn't TOML: {why}")],
            );
        }
    };
    let mut out: Vec<Change> = Vec::new();
    let mut dropped = Vec::new();
    // In the order the window shows them.
    for table in [
        "done", "remove", "untrack", "ignore", "add", "track", "again", "change", "item", "later",
        "back",
    ] {
        for v in tables.get(table).into_iter().flatten() {
            match one(table, v.clone(), k, today) {
                Ok(c)
                    if out
                        .iter()
                        .any(|o| o.name() == c.name() && o.word() == c.word()) =>
                {
                    dropped.push(format!("{table} {}: listed twice", c.name()));
                }
                Ok(c) => out.push(c),
                Err(why) => dropped.push(why),
            }
        }
    }
    for t in tables.keys() {
        if ![
            "done", "remove", "untrack", "ignore", "add", "track", "again", "change", "item",
            "later", "back",
        ]
        .contains(&t.as_str())
        {
            dropped.push(format!("[[{t}]]: not a kind of change"));
        }
    }
    out.sort_by_key(|c| c.group());
    (body, out, dropped)
}

/// The start of a parse error: what's wrong, without the list of what was expected.
fn first(msg: &str) -> &str {
    let l = msg.lines().next().unwrap_or_default();
    l.split(", expected").next().unwrap_or(l)
}

fn one(table: &str, v: toml::Value, k: &Known, today: Date) -> Result<Change, String> {
    if table == "add" {
        return add(v, k);
    }
    let r: Raw = v
        .try_into()
        .map_err(|e: toml::de::Error| format!("a [[{table}]] entry: {}", first(e.message())))?;
    let name = r
        .name()
        .ok_or_else(|| format!("a [[{table}]] entry names nothing"))?;
    let bad = |why: &str| format!("{table} {name}: {why}");
    let task = |id: &str| k.tasks.iter().find(|t| t.id == id);
    let title = |key: &str| {
        k.rows
            .iter()
            .find(|(x, _)| x == key)
            .map(|(_, t)| t.clone())
            .or_else(|| {
                k.items
                    .iter()
                    .find(|(i, _)| i == key)
                    .map(|(i, _)| format!("item {i}"))
            })
    };
    let (kind, label) = match table {
        "remove" => {
            let t = task(&name)
                .filter(|t| !t.off)
                .ok_or_else(|| bad("no such task"))?;
            (Kind::RemoveTask { id: name.clone() }, t.title.clone())
        }
        "done" => {
            let t = task(&name)
                .filter(|t| !t.off)
                .ok_or_else(|| bad("no such task"))?;
            (Kind::DoneTask { id: name.clone() }, t.title.clone())
        }
        "again" => {
            let t = task(&name)
                .filter(|t| !t.off)
                .ok_or_else(|| bad("no such task"))?;
            if r.why.trim().is_empty() {
                return Err(bad("no `why`: what changed?"));
            }
            let level = r.level.filter(|l| *l != t.level);
            (
                Kind::AgainTask {
                    id: name.clone(),
                    level,
                },
                match level {
                    Some(l) => format!("due again · {} → {}", t.level.word(), l.word()),
                    None => "due again".into(),
                },
            )
        }
        "change" => {
            let t = task(&name).ok_or_else(|| bad("no such task"))?;
            let every = match r.every.as_deref().map(str::trim) {
                None => None,
                Some("off") if t.off => None,
                Some("off") => Some("off".to_string()),
                Some(e) => {
                    let d: Dur = e.parse().map_err(|why: String| bad(&why))?;
                    (t.off || t.every != Some(d)).then(|| d.to_string())
                }
            };
            let level = r.level.filter(|l| *l != t.level);
            let mut words = Vec::new();
            if let Some(e) = &every {
                let was = match (t.off, t.every) {
                    (true, _) => "off".to_string(),
                    (_, Some(d)) => format!("every {d}"),
                    (_, None) => "once".to_string(),
                };
                let to = if e == "off" {
                    "off".to_string()
                } else {
                    format!("every {e}")
                };
                words.push(format!("{was} → {to}"));
            }
            if let Some(l) = level {
                words.push(format!("{} → {}", t.level.word(), l.word()));
            }
            if words.is_empty() {
                return Err(bad("nothing would change"));
            }
            (
                Kind::SetTask {
                    id: name.clone(),
                    every,
                    level,
                },
                words.join(" · "),
            )
        }
        "later" => {
            let what = title(&name).ok_or_else(|| bad("not on the list"))?;
            let until = r.until.ok_or_else(|| bad("no `until` date"))?;
            if until <= today {
                return Err(bad("its date has passed"));
            }
            (
                Kind::Later {
                    key: name.clone(),
                    until,
                },
                format!("until {until} · {what}"),
            )
        }
        "back" => {
            let d = k.put_off(&name).ok_or_else(|| bad("isn't put off"))?;
            (
                Kind::Back { key: name.clone() },
                format!("was put off until {d}"),
            )
        }
        "track" | "ignore" => {
            let what = k
                .found
                .iter()
                .find(|(x, _)| x == &name)
                .map(|(_, w)| w.clone())
                .ok_or_else(|| bad("discovery found no such thing"))?;
            if table == "ignore" {
                (Kind::Ignore { key: name.clone() }, what)
            } else {
                let set = r.set().map_err(|e| bad(&e))?;
                let label = match set.words() {
                    w if w.is_empty() => what,
                    w => format!("{what} · {w}"),
                };
                (
                    Kind::Track {
                        key: name.clone(),
                        set,
                    },
                    label,
                )
            }
        }
        "untrack" | "item" => {
            if !k.items.iter().any(|(i, _)| i == &name) {
                return Err(bad("not a tracked item"));
            }
            if table == "untrack" {
                (Kind::Untrack { id: name.clone() }, "stop tracking".into())
            } else {
                let set = r.set().map_err(|e| bad(&e))?;
                if set.is_empty() {
                    return Err(bad("nothing would change"));
                }
                let label = set.words();
                (
                    Kind::SetItem {
                        id: name.clone(),
                        set,
                    },
                    label,
                )
            }
        }
        _ => return Err(format!("[[{table}]]: not a kind of change")),
    };
    Ok(Change::new(kind, &r.why, label))
}

fn add(v: toml::Value, k: &Known) -> Result<Change, String> {
    let mut t: Task = v
        .try_into()
        .map_err(|e: toml::de::Error| format!("an [[add]] entry: {}", first(e.message())))?;
    t.id = super::tasks::slug(&t.id);
    if t.id.is_empty() || t.title.trim().is_empty() {
        return Err("an [[add]] entry has no id or title".into());
    }
    if k.tasks.iter().any(|x| x.id == t.id) {
        return Err(format!("add {}: already a task", t.id));
    }
    t.off = false;
    t.added = None;
    t.source = Source::File;
    super::tasks::validate(&mut t, k.workflows, &k.item_ids());
    let label = format!("{} · {}", t.title, t.when());
    let why = t.why.clone();
    Ok(Change::new(
        Kind::AddTask { task: Box::new(t) },
        &why,
        label,
    ))
}

/// The end of a review request: everything on the list a change may name, and the block to
/// answer with.
pub fn request_section(k: &Known, server: bool) -> String {
    let list = |rows: Vec<String>| {
        if rows.is_empty() {
            "(none)".to_string()
        } else {
            rows.join("\n")
        }
    };
    let tasks = list(
        k.tasks
            .iter()
            .map(|t| {
                format!(
                    "- {}: {} ({}; {}; {}{}{})",
                    t.id,
                    t.title,
                    if t.off { "off".into() } else { t.when() },
                    t.act,
                    t.source.word(),
                    t.item
                        .as_ref()
                        .map_or(String::new(), |i| format!("; item {i}")),
                    if t.off { String::new() } else { k.standing(t) }
                )
            })
            .collect(),
    );
    let rows = list(
        k.rows
            .iter()
            .map(|(key, title)| format!("- {key}: {title}"))
            .collect(),
    );
    let later = list(
        k.later
            .into_iter()
            .flatten()
            .map(|(key, d)| format!("- {key}: until {d}"))
            .collect(),
    );
    let mut dos = vec!["`audit`".to_string(), "`by-hand`".to_string()];
    dos.extend(k.workflows.iter().map(|w| format!("`run {w}`")));
    dos.extend(k.items.iter().map(|(i, _)| format!("`plan {i}`")));
    let mut s = format!(
        "What is on sentry's Maintenance list now.\n\
         Tasks (id: title (when; do; where it's defined)):\n{tasks}\n\
         Rows shown (key: title):\n{rows}\n\
         Put off (key: until):\n{later}\n"
    );
    if server {
        s.push_str(&format!(
            "Tracked items (id: standing):\n{}\nFound on the server, tracked by nothing \
             (discovery key: what):\n{}\n",
            list(
                k.items
                    .iter()
                    .map(|(i, st)| format!("- {i}: {st}"))
                    .collect()
            ),
            list(k.found.iter().map(|(x, w)| format!("- {x}: {w}")).collect()),
        ));
    }
    s.push_str(
        "\nLast, after the Watch section and with no heading of its own, say how that list should \
         change so it matches your review: what no longer belongs on it, what is missing, what \
         should change and what can wait. One fenced block whose info string is `sentry-changes`, \
         TOML, one table per change, each with a `why` of one sentence. The user sees them as one \
         list and applies them together, so propose only changes you'd make yourself, name only \
         ids and keys listed above, and leave out what is fine as it is (an empty block is a good \
         answer):\n\
         ```sentry-changes\n\
         [[remove]]            # a task that is stale, duplicated or no longer applies\n\
         task = \"<task id>\"\nwhy = \"…\"\n\n\
         [[add]]               # a task that is missing\n\
         id = \"short-slug\"\ntitle = \"What to do, in a few words\"\n\
         why = \"One or two sentences: why, and why now\"\n\
         level = \"soon\"        # now, soon, routine or tidy\n\
         do = \"by-hand\"\n\
         # every = \"90d\" only for work that recurs; leave it out for once\n\
         # item = \"<item id>\" when it's about one\n\
         steps = \"\"\"\nFor by-hand tasks: the exact steps and commands, in Markdown.\n\"\"\"\n\n\
         [[done]]              # a task the log shows was done (a run did what it asks)\n\
         task = \"<task id>\"\nwhy = \"…\"\n\n\
         [[again]]             # a task due again now, before its time, because something changed\n\
         task = \"<task id>\"\nwhy = \"What changed, in one sentence\"\n# level = \"soon\" to raise it\n\n\
         [[change]]            # a task's cadence (`every = \"off\"` turns it off) or level\n\
         task = \"<task id>\"\nevery = \"30d\"\nwhy = \"…\"\n\n\
         [[later]]             # a row (or item) that can wait until a date\n\
         key = \"<row key>\"\nuntil = 2027-01-15\nwhy = \"…\"\n\n\
         [[back]]              # something put off that matters now\n\
         key = \"<key that is put off>\"\nwhy = \"…\"\n",
    );
    if server {
        s.push_str(
            "\n[[track]]             # start tracking what was found (optional: risk, hold, source, constraint)\n\
             key = \"<discovery key>\"\nrisk = \"medium\"\nwhy = \"…\"\n\n\
             [[untrack]]           # stop tracking an item\n\
             item = \"<item id>\"\nwhy = \"…\"\n\n\
             [[ignore]]            # never suggest what was found again\n\
             key = \"<discovery key>\"\nwhy = \"…\"\n\n\
             [[item]]              # an item's risk (low, medium, high), hold reason, constraint or source\n\
             id = \"<item id>\"\nrisk = \"high\"\nwhy = \"…\"\n",
        );
    }
    s.push_str(&format!("```\n`do` is one of: {}.", dos.join(", ")));
    s
}

/// Apply one of the kinds both programs share to what's in memory: `tasks` is `tasks.toml`'s,
/// `derived` the tasks defined elsewhere. None: not a shared kind (a server's own).
pub fn apply(
    c: &Change,
    tasks: &mut Vec<Task>,
    later: &mut Snoozes,
    derived: &[Task],
    now: Timestamp,
) -> Option<Result<String, String>> {
    // The task as it stands: the file's, else the derived one.
    let find = |tasks: &[Task], id: &str| {
        tasks
            .iter()
            .chain(derived)
            .find(|t| t.id == id)
            .cloned()
            .ok_or_else(|| format!("no task {id} any more"))
    };
    let put = |tasks: &mut Vec<Task>, t: Task| {
        tasks.retain(|x| x.id != t.id);
        tasks.push(Task {
            source: Source::File,
            ..t
        });
    };
    Some(match &c.kind {
        Kind::AddTask { task } => {
            put(
                tasks,
                Task {
                    added: Some(now),
                    ..(**task).clone()
                },
            );
            Ok("added to tasks.toml".into())
        }
        Kind::RemoveTask { id } => {
            if derived.iter().any(|t| &t.id == id) {
                match find(tasks, id) {
                    Ok(t) => {
                        put(tasks, Task { off: true, ..t });
                        Ok("turned off in tasks.toml".into())
                    }
                    Err(e) => Err(e),
                }
            } else if tasks.iter().any(|t| &t.id == id) {
                tasks.retain(|t| &t.id != id);
                Ok("removed from tasks.toml".into())
            } else {
                Err(format!("no task {id} any more"))
            }
        }
        Kind::SetTask { id, every, level } => match find(tasks, id) {
            Ok(mut t) => {
                let mut bad = None;
                match every.as_deref() {
                    Some("off") => t.off = true,
                    Some(e) => match e.parse::<Dur>() {
                        Ok(d) => {
                            t.every = Some(d);
                            t.off = false;
                        }
                        Err(why) => bad = Some(why),
                    },
                    None => {}
                }
                if let Some(l) = level {
                    t.level = *l;
                }
                match bad {
                    Some(why) => Err(why),
                    None => {
                        put(tasks, t);
                        Ok("written to tasks.toml".into())
                    }
                }
            }
            Err(e) => Err(e),
        },
        // The log is what says a task is done: the program writes its entry.
        Kind::DoneTask { id } => find(tasks, id).map(|_| "marked done in the log".into()),
        Kind::AgainTask { id, level } => match find(tasks, id) {
            Ok(mut t) => {
                t.again = Some(super::tasks::Again {
                    at: now,
                    why: c.why.clone(),
                });
                if let Some(l) = level {
                    t.level = *l;
                }
                put(tasks, t);
                Ok("due again (tasks.toml)".into())
            }
            Err(e) => Err(e),
        },
        Kind::Later { key, until } => {
            later.insert(key.clone(), *until);
            Ok(format!("put off until {until} (later.toml)"))
        }
        Kind::Back { key } => {
            later.remove(key);
            Ok("back on the list (later.toml)".into())
        }
        Kind::Track { .. } | Kind::Untrack { .. } | Kind::Ignore { .. } | Kind::SetItem { .. } => {
            return None;
        }
    })
}

/// Carry out every open change with `one` (ticked ones; the rest are skipped) and say what
/// happened: (applied, skipped, failed).
pub fn settle(
    changes: &mut [Change],
    mut one: impl FnMut(&Change) -> Result<String, String>,
) -> (usize, usize, usize) {
    let (mut done, mut skipped, mut failed) = (0, 0, 0);
    for c in changes.iter_mut().filter(|c| c.state == State::Open) {
        if !c.on {
            c.state = State::Skipped;
            skipped += 1;
            continue;
        }
        match one(c) {
            Ok(note) => {
                c.state = State::Applied;
                c.note = note;
                done += 1;
            }
            Err(why) => {
                c.state = State::Failed;
                c.note = why;
                failed += 1;
            }
        }
    }
    (done, skipped, failed)
}

/// The log entry's text for a review that was applied: a headline, then one line per change.
pub fn summary(changes: &[Change]) -> String {
    let n = |g: Group| {
        changes
            .iter()
            .filter(|c| c.state == State::Applied && c.group() == g)
            .count()
    };
    let mut head = Vec::new();
    for (g, word) in [
        (Group::Done, "done"),
        (Group::Add, "added"),
        (Group::Remove, "removed"),
        (Group::Change, "changed"),
        (Group::PutOff, "put off or brought back"),
    ] {
        if n(g) > 0 {
            head.push(format!("{} {word}", n(g)));
        }
    }
    let mut s = format!(
        "Review applied: {}",
        if head.is_empty() {
            "nothing".to_string()
        } else {
            head.join(", ")
        }
    );
    for c in changes {
        let mark = match c.state {
            State::Applied => "applied",
            State::Skipped => "skipped",
            State::Failed => "failed",
            State::Open => continue,
        };
        s.push_str(&format!(
            "\n- {mark}: {} {} {} ({}){}",
            c.group().word().to_lowercase(),
            c.word(),
            c.name(),
            c.label,
            if c.state == State::Failed {
                format!(": {}", c.note)
            } else {
                String::new()
            }
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Date {
        s.parse().unwrap()
    }

    fn task(id: &str, every: Option<&str>, act: &str) -> Task {
        Task {
            id: id.into(),
            title: format!("T {id}"),
            why: String::new(),
            level: Level::Routine,
            every: every.map(|e| e.parse().unwrap()),
            act: act.into(),
            item: None,
            steps: String::new(),
            added: None,
            off: false,
            source: Source::File,
            review: None,
            after: None,
            again: None,
        }
    }

    struct World {
        workflows: Vec<String>,
        tasks: Vec<Task>,
        rows: Vec<(String, String)>,
        later: Snoozes,
        items: Vec<(String, String)>,
        found: Vec<(String, String)>,
    }

    impl World {
        fn new() -> Self {
            let mut cadence = task("audit", Some("30d"), "audit");
            cadence.source = Source::Default;
            Self {
                workflows: vec!["quick-update".into()],
                tasks: vec![task("ups", Some("90d"), "by-hand"), cadence],
                rows: vec![
                    ("updates".into(), "Install updates".into()),
                    ("task:ups".into(), "T ups".into()),
                ],
                later: [("cleanup".to_string(), d("2027-02-01"))].into(),
                items: vec![
                    ("web".into(), "medium risk".into()),
                    ("legacy".into(), "low risk".into()),
                ],
                found: vec![("image:cache".into(), "image cache".into())],
            }
        }

        fn known(&self) -> Known<'_> {
            Known {
                workflows: &self.workflows,
                tasks: &self.tasks,
                rows: &self.rows,
                later: Some(&self.later),
                items: &self.items,
                found: &self.found,
                ..Default::default()
            }
        }
    }

    const ANSWER: &str = "# Maintenance review\n\n## Now\n- web\n\n```sentry-changes\n\
        [[add]]\nid = \"Restore Test\"\ntitle = \"Test a restore\"\nwhy = \"none since July\"\n\
        level = \"soon\"\nevery = \"90d\"\ndo = \"by-hand\"\n\
        steps = \"\"\"\n```bash\nrestic check\n```\n\"\"\"\n\n\
        [[add]]\nid = \"ghost\"\ntitle = \"Run ghost\"\nlevel = \"soon\"\ndo = \"run ghost\"\n\n\
        [[remove]]\ntask = \"ups\"\nwhy = \"the UPS is gone\"\n\n\
        [[change]]\ntask = \"audit\"\nevery = \"14d\"\nlevel = \"soon\"\nwhy = \"new findings\"\n\n\
        [[later]]\nkey = \"updates\"\nuntil = 2027-01-15\nwhy = \"nothing urgent\"\n\n\
        [[back]]\nkey = \"cleanup\"\nwhy = \"the disk is filling\"\n\n\
        [[track]]\nkey = \"image:cache\"\nrisk = \"High\"\nwhy = \"unpinned\"\n\n\
        [[untrack]]\nitem = \"legacy\"\nwhy = \"retired\"\n\n\
        [[item]]\nid = \"web\"\nrisk = \"high\"\nhold = \"2.0 migrates the database\"\nwhy = \"can't be undone\"\n\
        ```\n\n## After";

    #[test]
    fn the_changes_are_taken_out_of_the_answer() {
        let w = World::new();
        let (body, changes, dropped) = take(ANSWER, &w.known(), d("2026-11-16"));
        assert_eq!(body, "# Maintenance review\n\n## Now\n- web\n\n\n## After");
        assert_eq!(dropped, Vec::<String>::new());
        let shown: Vec<String> = changes
            .iter()
            .map(|c| format!("{} {} {}", c.group().word(), c.word(), c.name()))
            .collect();
        assert_eq!(
            shown,
            [
                "Remove task ups",
                "Remove item legacy",
                "Add task restore-test",
                "Add task ghost",
                "Add track image:cache",
                "Change task audit",
                "Change item web",
                "Put off later updates",
                "Put off back cleanup",
            ]
        );
        assert!(changes.iter().all(|c| c.on && c.state == State::Open));
        assert_eq!(changes[0].label, "T ups");
        assert_eq!(changes[0].why, "the UPS is gone");
        // A fence inside `steps` doesn't end the block; an unknown workflow is done by hand.
        let Kind::AddTask { task } = &changes[2].kind else {
            panic!()
        };
        assert!(task.steps.contains("```bash\nrestic check\n```"));
        assert_eq!(changes[2].label, "Test a restore · every 90d");
        let Kind::AddTask { task } = &changes[3].kind else {
            panic!()
        };
        assert_eq!(task.act, "by-hand");
        assert!(task.why.contains("workflow ghost not found"));
        assert_eq!(
            changes[4].label, "image cache · risk high",
            "risk is lowercased"
        );
        assert_eq!(changes[5].label, "every 30d → every 14d · routine → soon");
        assert_eq!(
            changes[6].label,
            "risk high · held: 2.0 migrates the database"
        );
        assert_eq!(changes[7].label, "until 2027-01-15 · Install updates");
        assert_eq!(changes[8].label, "was put off until 2027-02-01");
        // No block: nothing taken, nothing dropped.
        let (b, c, dr) = take("# Review\n", &w.known(), d("2026-11-16"));
        assert_eq!((b.as_str(), c.len(), dr.len()), ("# Review\n", 0, 0));
    }

    #[test]
    fn what_cannot_be_applied_is_dropped_with_a_reason() {
        let w = World::new();
        let answer = "# R\n```sentry-changes\n\
            [[remove]]\ntask = \"nope\"\n\n\
            [[remove]]\ntask = \"ups\"\n\n[[remove]]\ntask = \"ups\"\n\n\
            [[add]]\nid = \"ups\"\ntitle = \"Again\"\nlevel = \"soon\"\ndo = \"by-hand\"\n\n\
            [[add]]\nid = \"bad\"\ntitle = \"Bad level\"\nlevel = \"whenever\"\ndo = \"audit\"\n\n\
            [[change]]\ntask = \"audit\"\nevery = \"30d\"\n\n\
            [[change]]\ntask = \"audit\"\nevery = \"soonish\"\n\n\
            [[later]]\nkey = \"ghost\"\nuntil = 2027-01-01\n\n\
            [[later]]\nkey = \"updates\"\nuntil = 2026-11-16\n\n\
            [[later]]\nkey = \"web\"\nuntil = 2027-03-01\n\n\
            [[back]]\nkey = \"updates\"\n\n\
            [[track]]\nkey = \"image:nope\"\n\n\
            [[track]]\nkey = \"image:cache\"\nrisk = \"scary\"\n\n\
            [[untrack]]\nitem = \"nope\"\n\n\
            [[item]]\nid = \"web\"\n\n\
            [[item]]\nid = \"web\"\ncolour = \"red\"\n\n\
            [[retire]]\nitem = \"web\"\n```";
        let (_, changes, dropped) = take(answer, &w.known(), d("2026-11-16"));
        let kept: Vec<String> = changes
            .iter()
            .map(|c| format!("{} {}", c.word(), c.name()))
            .collect();
        // An item's key is its review date, so it can be put off.
        assert_eq!(kept, ["task ups", "later web"]);
        assert_eq!(changes[1].label, "until 2027-03-01 · item web");
        let has = |s: &str| dropped.iter().any(|x| x.contains(s));
        for why in [
            "remove nope: no such task",
            "remove ups: listed twice",
            "add ups: already a task",
            "an [[add]] entry:",
            "change audit: nothing would change",
            "change audit: bad number",
            "later ghost: not on the list",
            "later updates: its date has passed",
            "back updates: isn't put off",
            "track image:nope: discovery found no such thing",
            "track image:cache: risk \"scary\" isn't low, medium or high",
            "untrack nope: not a tracked item",
            "item web: nothing would change",
            "a [[item]] entry: unknown field `colour`",
            "[[retire]]: not a kind of change",
        ] {
            assert!(has(why), "{why} not in {dropped:#?}");
        }
        assert_eq!(dropped.len(), 15);
        // A block that isn't TOML: nothing, and it says so.
        let (_, c, dr) = take("```sentry-changes\n[[add\n```", &w.known(), d("2026-11-16"));
        assert!(c.is_empty() && dr[0].starts_with("the changes block isn't TOML"));
    }

    #[test]
    fn a_review_marks_tasks_done_or_due_again() {
        use crate::maint::log::LogEntry;
        let w = World::new();
        let answer = "# Maintenance review\n\n```sentry-changes\n\
            [[again]]\ntask = \"audit\"\nlevel = \"soon\"\nwhy = \"A new kernel was booted.\"\n\n\
            [[done]]\ntask = \"ups\"\nwhy = \"The run replaced the battery.\"\n\n\
            [[again]]\ntask = \"ups\"\n\n\
            [[done]]\ntask = \"nope\"\nwhy = \"x\"\n```\n";
        let (_, mut changes, dropped) = take(answer, &w.known(), d("2026-11-16"));
        let got: Vec<_> = changes.iter().map(|c| (c.name(), c.word())).collect();
        assert_eq!(got, [("ups", "done"), ("audit", "again")]);
        assert_eq!(changes[1].label, "due again · routine → soon");
        assert_eq!(
            dropped,
            [
                "done nope: no such task",
                "again ups: no `why`: what changed?"
            ]
        );
        let mut file = vec![w.tasks[0].clone()];
        let derived = vec![w.tasks[1].clone()];
        let mut later = w.later.clone();
        let now: Timestamp = "2026-11-16T12:00:00Z".parse().unwrap();
        let hours = jiff::SignedDuration::from_hours;
        let out = settle(&mut changes, |c| {
            apply(c, &mut file, &mut later, &derived, now).unwrap()
        });
        assert_eq!(out, (2, 0, 0));
        // Done is the log's to say: the program writes the entry.
        assert_eq!(changes[0].done_task(), Some("ups"));
        assert_eq!(changes[0].note, "marked done in the log");
        // Audited yesterday, every 30d: not due, but it is again since the review.
        let audit = file.iter().find(|t| t.id == "audit").unwrap();
        assert_eq!(audit.level, Level::Soon);
        let ran = |at| LogEntry::event("", "job", "audit", true, "", &[], at);
        let log = [ran(now - hours(24))];
        assert!(!crate::maint::tasks::due(&derived[0], &log, None, now));
        assert!(crate::maint::tasks::due(audit, &log, None, now));
        let recs = crate::maint::tasks::recs(std::slice::from_ref(audit), &log, None, now);
        assert_eq!(
            recs[0].why,
            "A new kernel was booted. (due again; last done 2026-11-15)"
        );
        // Until it's next done.
        let log = [ran(now + hours(1)), ran(now - hours(24))];
        assert!(!crate::maint::tasks::due(audit, &log, None, now + hours(2)));
        assert!(summary(&changes).starts_with("Review applied: 1 done, 1 changed\n"));
        // It survives the file.
        let text = audit.to_toml();
        assert!(
            text.contains("[task.again]") && text.contains("A new kernel"),
            "{text}"
        );

        // The request says how each task stands, when it's told the time.
        let mut k = w.known();
        k.log = &log;
        k.now = Some(now + hours(2));
        let req = request_section(&k, false);
        assert!(
            req.contains("- ups: T ups (every 90d; by-hand; tasks.toml; never done; due now)"),
            "{req}"
        );
        assert!(req.contains("last done 2026-11-16; not due)"), "{req}");
        assert!(req.contains("[[done]]") && req.contains("[[again]]"));
    }

    #[test]
    fn applying_writes_tasks_and_later() {
        let w = World::new();
        let (_, mut changes, _) = take(ANSWER, &w.known(), d("2026-11-16"));
        // tasks.toml has `ups`; `audit` is built in.
        let mut file = vec![w.tasks[0].clone()];
        let derived = vec![w.tasks[1].clone()];
        let mut later = w.later.clone();
        let now: Timestamp = "2026-11-16T12:00:00Z".parse().unwrap();
        // Leave the new `ghost` task unticked.
        changes[3].on = false;
        let mut own = Vec::new();
        let (done, skipped, failed) = settle(&mut changes, |c| {
            apply(c, &mut file, &mut later, &derived, now).unwrap_or_else(|| {
                own.push(c.name().to_string());
                Ok("the server's".into())
            })
        });
        assert_eq!((done, skipped, failed), (8, 1, 0));
        assert_eq!(own, ["legacy", "image:cache", "web"]);
        let ids: Vec<&str> = file.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, ["restore-test", "audit"]);
        assert_eq!(file[0].added, Some(now));
        // The built-in cadence is written to the file with what changed.
        assert_eq!(file[1].every, Some("14d".parse().unwrap()));
        assert_eq!((file[1].level, file[1].source), (Level::Soon, Source::File));
        assert_eq!(later.len(), 1);
        assert_eq!(later["updates"], d("2027-01-15"));
        assert_eq!(changes[0].note, "removed from tasks.toml");
        assert_eq!(changes[3].state, State::Skipped);
        let s = summary(&changes);
        assert!(s.starts_with(
            "Review applied: 2 added, 2 removed, 2 changed, 2 put off or brought back\n"
        ));
        assert!(s.contains("- applied: remove task ups (T ups)"));
        assert!(s.contains("- skipped: add task ghost"));
        // A second Enter does nothing.
        assert_eq!(settle(&mut changes, |_| Err("again".into())), (0, 0, 0));

        // Removing a built-in task turns it off; turning one off by `every`.
        let mut file = Vec::new();
        let off = Change::new(Kind::RemoveTask { id: "audit".into() }, "", String::new());
        let note = apply(&off, &mut file, &mut later, &derived, now).unwrap();
        assert_eq!(note.unwrap(), "turned off in tasks.toml");
        assert!(file[0].off && file[0].id == "audit");
        let gone = Change::new(Kind::RemoveTask { id: "nope".into() }, "", String::new());
        assert!(
            apply(&gone, &mut file, &mut later, &derived, now)
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn the_request_lists_everything_and_its_example_parses() {
        let w = World::new();
        let s = request_section(&w.known(), true);
        for has in [
            "- ups: T ups (every 90d; by-hand; tasks.toml)",
            "- audit: T audit (every 30d; audit; built in)",
            "- updates: Install updates",
            "- cleanup: until 2027-02-01",
            "- web: medium risk",
            "- image:cache: image cache",
            "`run quick-update`",
            "`plan web`",
            "[[untrack]]",
        ] {
            assert!(s.contains(has), "{has}");
        }
        let local = request_section(
            &Known {
                items: &[],
                found: &[],
                ..w.known()
            },
            false,
        );
        assert!(!local.contains("[[untrack]]") && !local.contains("Tracked items"));
        // The example block is valid: its placeholders name nothing, so all of it is dropped
        // but the task to add.
        let (_, changes, dropped) = take(&s, &w.known(), d("2026-11-16"));
        assert_eq!(changes.len(), 1, "{dropped:#?}");
        assert_eq!(changes[0].name(), "short-slug");
        assert!(!dropped.iter().any(|x| x.contains("isn't TOML")));
    }

    #[test]
    fn a_change_round_trips_through_the_review_s_header() {
        #[derive(Serialize, Deserialize)]
        struct Head {
            changes: Vec<Change>,
        }
        let w = World::new();
        let (_, mut changes, _) = take(ANSWER, &w.known(), d("2026-11-16"));
        changes[0].state = State::Applied;
        changes[0].note = "removed from tasks.toml".into();
        let text = toml::to_string(&Head {
            changes: changes.clone(),
        })
        .unwrap();
        assert_eq!(toml::from_str::<Head>(&text).unwrap().changes, changes);
    }
}

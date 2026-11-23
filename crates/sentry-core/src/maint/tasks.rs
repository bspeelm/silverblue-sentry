//! Tasks you took from a review: one-time ("plan web to 1.5.2", "check the UPS battery") or
//! recurring (`every = "90d"`). A review proposes them among its changes
//! ([`super::changes`]); applied, they land in `tasks.toml` under [`super::root`]. Maintenance shows those that are due. Whether a task is
//! done comes from the log (the workflow it runs ended well, or `d` logged it by hand), never
//! from this file. Edit it freely.
//!
//! Recurring work the programs know about is a task too, without being written anywhere: this
//! machine's jobs (`[jobs]` in config.toml, else their defaults) and a server's
//! `maintenance.cadence`. A task in `tasks.toml` with the same id takes its place (`e` writes
//! one; `off = true` turns it off).

use std::path::PathBuf;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::Level;
use super::log::LogEntry;
use crate::config::Dur;
use crate::paths;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub why: String,
    pub level: Level,
    /// Recurring: due again this long after it was last done. None: once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub every: Option<Dur>,
    /// `run <workflow>`, `plan <item>` (sentry-server), `audit`, `job <name>` (this machine's
    /// jobs; `job cleanup` is any cleanup), or `by-hand`.
    #[serde(rename = "do")]
    pub act: String,
    /// The server item it's about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// What to do, for a task done by hand (Markdown).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub steps: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<Timestamp>,
    /// Turned off: it's never due (a built-in one you don't want).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub off: bool,
    /// Where it comes from (not written: a task in the file is `File`).
    #[serde(skip)]
    pub source: Source,
    /// The review it came from (file name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<String>,
    /// Not due before then: the next good run of this workflow after it was added (a
    /// follow-up check), or a wait from when it was added (`7d`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    /// Due again whatever its cadence says, since something changed: a review found so.
    /// It holds until the task is next done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub again: Option<Again>,
}

/// Why a task is due before its time, and since when.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Again {
    pub at: Timestamp,
    #[serde(default)]
    pub why: String,
}

/// Where a task comes from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Source {
    /// `tasks.toml`.
    #[default]
    File,
    /// The config (`[jobs]`, `maintenance.cadence`).
    Config,
    /// Built in (a job's default cadence).
    Default,
}

impl Source {
    pub fn word(self) -> &'static str {
        match self {
            Source::File => "tasks.toml",
            Source::Config => "config",
            Source::Default => "built in",
        }
    }
}

/// What Enter does on a task.
#[derive(Debug, Clone, PartialEq)]
pub enum Do {
    Run(String),
    Plan(String),
    Audit,
    /// One of this machine's jobs (`cleanup`: any cleanup job, on the Cleanup screen).
    Job(String),
    ByHand,
}

impl Do {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        match s.split_once(char::is_whitespace) {
            Some(("run", wf)) if !wf.trim().is_empty() => Some(Do::Run(wf.trim().to_string())),
            Some(("plan", it)) if !it.trim().is_empty() => Some(Do::Plan(it.trim().to_string())),
            Some(("job", "audit")) => Some(Do::Audit),
            Some(("job", j)) if !j.trim().is_empty() => Some(Do::Job(j.trim().to_string())),
            None if s == "audit" => Some(Do::Audit),
            None if s == "by-hand" => Some(Do::ByHand),
            _ => None,
        }
    }
}

impl Task {
    pub fn action(&self) -> Do {
        Do::parse(&self.act).unwrap_or(Do::ByHand)
    }

    pub fn key(&self) -> String {
        format!("task:{}", self.id)
    }

    /// "once" or "every 90d" (and what it waits for).
    pub fn when(&self) -> String {
        let w = self
            .every
            .map_or("once".to_string(), |d| format!("every {d}"));
        match &self.after {
            Some(a) if a.parse::<Dur>().is_ok() => format!("{w}, {a} after it was added"),
            Some(wf) => format!("{w}, after the next {wf} run"),
            None => w,
        }
    }

    /// The task as it's written to `tasks.toml` (what the confirm box shows).
    pub fn to_toml(&self) -> String {
        #[derive(Serialize)]
        struct One<'a> {
            task: [&'a Task; 1],
        }
        toml::to_string(&One { task: [self] }).unwrap_or_default()
    }
}

/// `run`/`plan` must name a workflow or item there is; anything else is done by hand.
pub(crate) fn validate(t: &mut Task, workflows: &[String], items: &[String]) {
    let missing = match Do::parse(&t.act) {
        Some(Do::Run(wf)) if !workflows.contains(&wf) => Some(format!("workflow {wf}")),
        Some(Do::Plan(it)) if !items.contains(&it) => Some(format!("item {it}")),
        None => Some(format!("action {:?}", t.act)),
        _ => None,
    };
    if let Some(m) = missing {
        t.act = "by-hand".into();
        t.why = format!("{} ({m} not found: do it by hand)", t.why.trim())
            .trim()
            .to_string();
    }
}

pub(crate) fn slug(s: &str) -> String {
    let s: String = s
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    s.split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
        .chars()
        .take(40)
        .collect()
}

/// When it was last done: a log entry tagged with it, the workflow it runs ending well, the
/// item's change ending well, or (audit) the last audit.
pub fn last_done(t: &Task, log: &[LogEntry], audited: Option<Timestamp>) -> Option<Timestamp> {
    let tag = t.key();
    let act = t.action();
    let from_log = log
        .iter()
        .filter(|e| {
            let h = &e.head;
            let ok = h.result == "done";
            h.tags.contains(&tag)
                || match &act {
                    Do::Run(wf) => ok && &h.workflow == wf && item_fits(t, h),
                    Do::Plan(it) => ok && h.item.as_ref() == Some(it),
                    Do::Job(j) => ok && h.kind == "job" && job_matches(j, &h.workflow),
                    Do::Audit => ok && h.kind == "job" && h.workflow == "audit",
                    Do::ByHand => false,
                }
        })
        .filter_map(|e| e.head.ended.or(e.head.started))
        .max();
    let audit = matches!(act, Do::Audit).then_some(audited).flatten();
    from_log.max(audit)
}

/// A workflow run that ended well: tag it with the tasks it does (`task:<id>`), so the log
/// says why they left the list. Every such task, due or not, so the tags are the same when
/// the entry is written again with its note.
pub fn tag_run(entry: &mut LogEntry, tasks: &[Task]) {
    let h = &entry.head;
    if h.result != "done" {
        return;
    }
    let tags: Vec<String> = tasks
        .iter()
        .filter(|t| match t.action() {
            Do::Run(wf) => wf == h.workflow && item_fits(t, h),
            Do::Plan(it) => h.item.as_ref() == Some(&it),
            _ => false,
        })
        .map(Task::key)
        .filter(|k| !h.tags.contains(k))
        .collect();
    entry.head.tags.extend(tags);
}

/// A run of the task's workflow does the task: its `item` narrows it only when the run says
/// which item it changed. A run with no item is the workflow as a whole (the network's
/// firmware upgrade, or a task's own Enter, which starts the workflow without an item), so a
/// task written with an item is done by it too; a run for another item is not.
fn item_fits(t: &Task, h: &super::log::LogHead) -> bool {
    match (&t.item, &h.item) {
        (Some(want), Some(ran)) => want == ran,
        _ => true,
    }
}

/// A job task's name against a job that ran (`cleanup`: any cleanup job).
fn job_matches(task: &str, ran: &str) -> bool {
    task == ran || (task == "cleanup" && ran.starts_with("cleanup-"))
}

/// Whether it belongs on Maintenance now.
pub fn due(t: &Task, log: &[LogEntry], audited: Option<Timestamp>, now: Timestamp) -> bool {
    if t.off || !waited(t, log, now) {
        return false;
    }
    let last = last_done(t, log, audited);
    if again(t, last).is_some() {
        return true;
    }
    match t.every {
        None => match (last, t.added) {
            (None, _) => true,
            (Some(l), Some(a)) => l < a,
            (Some(_), None) => false,
        },
        Some(every) => last
            .or(counted_from(t, log))
            .is_none_or(|l| now.as_second() - l.as_second() >= every.0.as_secs() as i64),
    }
}

/// A recurring task that was never done. One from tasks.toml is due: someone (you, a review)
/// put it there to be done. A derived one (a cadence, a job's) was never asked for, so its
/// interval counts from when the log here began; with no log at all it's due too.
pub fn counted_from(t: &Task, log: &[LogEntry]) -> Option<Timestamp> {
    if t.source == Source::File {
        return None;
    }
    log.iter()
        .filter_map(|e| e.head.started.or(e.head.ended))
        .min()
}

/// Why it's due again before its time, while it hasn't been done since.
pub fn again(t: &Task, last: Option<Timestamp>) -> Option<&Again> {
    t.again.as_ref().filter(|a| last.is_none_or(|l| l < a.at))
}

/// What a task waits for (`after`) has happened: the workflow ran well since it was added,
/// or the wait is over. A task with no `added` time doesn't wait.
pub fn waited(t: &Task, log: &[LogEntry], now: Timestamp) -> bool {
    waited_in(t, log, now, &|scope| crate::maint::log::list(scope))
}

/// `after = "task:<target id>/<task id>"`: the scope of that target's records (`""` this
/// machine, a server's name, `net:<name>`) and the task's id.
pub fn after_task(after: &str) -> Option<(String, &str)> {
    let (target, id) = after.strip_prefix("task:")?.rsplit_once('/')?;
    let scope = match target {
        "" | "local" => "",
        t if t.starts_with("net:") && t.len() > 4 => t,
        t => t.strip_prefix("srv:").filter(|n| !n.is_empty())?,
    };
    (!id.is_empty()).then(|| (scope.to_string(), id))
}

/// `waited`, with another target's log read through `other` (by its scope): a task that
/// is `after = "task:<target id>/<task id>"` isn't due until that task is logged done
/// (an entry tagged `task:<id>`) under that target's scope, whenever that was.
pub fn waited_in(
    t: &Task,
    log: &[LogEntry],
    now: Timestamp,
    other: &dyn Fn(&str) -> Vec<LogEntry>,
) -> bool {
    if let Some((scope, id)) = t.after.as_deref().and_then(after_task) {
        let tag = format!("task:{id}");
        return other(&scope).iter().any(|e| e.head.tags.contains(&tag));
    }
    let (Some(after), Some(added)) = (&t.after, t.added) else {
        return true;
    };
    if let Ok(d) = after.parse::<Dur>() {
        return now.as_second() - added.as_second() >= d.0.as_secs() as i64;
    }
    log.iter().any(|e| {
        let h = &e.head;
        &h.workflow == after
            && h.result == "done"
            && h.ended.or(h.started).is_some_and(|at| at > added)
    })
}

/// A one-time task that's done, and when (retention drops it a while after).
pub fn finished(t: &Task, log: &[LogEntry], audited: Option<Timestamp>) -> Option<Timestamp> {
    if t.every.is_some() {
        return None;
    }
    let last = last_done(t, log, audited)?;
    t.added.is_none_or(|a| last >= a).then_some(last)
}

/// The tasks to keep: a one-time task done before `cutoff` goes (its log entry is about to,
/// and without it the task would look undone).
pub fn keep(tasks: &[Task], log: &[LogEntry], cutoff: Timestamp) -> Vec<Task> {
    tasks
        .iter()
        .filter(|t| finished(t, log, None).is_none_or(|d| d >= cutoff))
        .cloned()
        .collect()
}

/// The tasks due, as Maintenance shows them.
pub struct TaskRec {
    pub level: Level,
    pub key: String,
    pub title: String,
    pub why: String,
    pub id: String,
    pub item: Option<String>,
}

pub fn recs(
    tasks: &[Task],
    log: &[LogEntry],
    audited: Option<Timestamp>,
    now: Timestamp,
) -> Vec<TaskRec> {
    tasks
        .iter()
        .filter(|t| due(t, log, audited, now))
        .map(|t| {
            let last = last_done(t, log, audited);
            // Twice as long as it should be: it has waited long enough.
            let late = t
                .every
                .zip(last)
                .is_some_and(|(e, l)| now.as_second() - l.as_second() >= 2 * e.0.as_secs() as i64);
            let why = match (t.every, last) {
                _ if again(t, last).is_some_and(|a| !a.why.trim().is_empty()) => {
                    let a = again(t, last).expect("checked");
                    match last {
                        Some(l) => format!(
                            "{} (due again; last done {})",
                            a.why.trim(),
                            l.strftime("%Y-%m-%d")
                        ),
                        None => a.why.trim().to_string(),
                    }
                }
                // (How often it recurs is with its title.)
                (Some(_), Some(l)) => {
                    format!("{} (last done {})", t.why.trim(), l.strftime("%Y-%m-%d"))
                }
                (Some(_), None) => match counted_from(t, log) {
                    Some(f) => format!(
                        "{} (not done yet, tracked since {})",
                        t.why.trim(),
                        f.strftime("%Y-%m-%d")
                    ),
                    None => format!("{} (not done yet)", t.why.trim()),
                },
                (None, _) => t.why.trim().to_string(),
            };
            TaskRec {
                level: if late && again(t, last).is_none() {
                    t.level.min(Level::Soon)
                } else {
                    t.level
                },
                key: t.key(),
                // A task that recurs says so beside its name; one without is once. The
                // level says only how soon.
                title: match t.every {
                    Some(d) => format!("{} · every {d}", t.title),
                    None => t.title.clone(),
                },
                why: why.trim().to_string(),
                id: t.id.clone(),
                item: t.item.clone(),
            }
        })
        .collect()
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct File {
    task: Vec<Task>,
}

/// The tasks that apply: `tasks.toml`'s, and the derived ones it doesn't replace.
pub fn effective(file: &[Task], derived: Vec<Task>) -> Vec<Task> {
    let mut v: Vec<Task> = derived
        .into_iter()
        .filter(|d| !file.iter().any(|f| f.id == d.id))
        .collect();
    v.extend(file.iter().cloned());
    v
}

/// `x` on a task: one from the file goes; a derived one is turned off (written with
/// `off = true`, so it stays off).
pub fn remove_or_off(server: &str, t: &Task, file: &[Task]) -> anyhow::Result<bool> {
    let derived = t.source != Source::File || file.iter().all(|f| f.id != t.id);
    if derived {
        add(
            server,
            Task {
                off: true,
                source: Source::File,
                ..t.clone()
            },
        )?;
    } else {
        remove(server, &t.id)?;
    }
    Ok(derived)
}

/// `e` on a task: written to `tasks.toml` with its new cadence (`None`: off).
pub fn set_every(server: &str, t: &Task, every: Option<Dur>) -> anyhow::Result<()> {
    add(
        server,
        Task {
            every: every.or(t.every),
            off: every.is_none(),
            source: Source::File,
            ..t.clone()
        },
    )
}

/// What was typed for a cadence: `off` (None) or a duration (`30d`).
pub fn parse_every(text: &str) -> Result<Option<Dur>, String> {
    match text.trim() {
        "off" => Ok(None),
        d => d.parse::<Dur>().map(Some),
    }
}

pub fn path(server: &str) -> PathBuf {
    super::root(server).join("tasks.toml")
}

pub fn load(server: &str) -> Vec<Task> {
    std::fs::read_to_string(path(server))
        .ok()
        .and_then(|t| toml::from_str::<File>(&t).ok())
        .map(|f| f.task)
        .unwrap_or_default()
}

pub fn save(server: &str, tasks: &[Task]) -> anyhow::Result<()> {
    let p = path(server);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let text = format!(
        "# Maintenance tasks: taken from a review (R on Maintenance), and built-in cadences\n\
         # changed with e (or off = true). Done is read from the maintenance log;\n\
         # do = run <workflow> | plan <item> | audit | job <name> | by-hand.\n\
         # level = now | soon | routine | tidy: how soon it matters, nothing else (routine is\n\
         # normal priority, and is shown as \"normal\"; that spelling is read too).\n\
         # every = \"30d\": it recurs. Without it the task is done once. Edit freely.\n\n{}",
        toml::to_string(&File {
            task: tasks.to_vec()
        })?
    );
    paths::write_atomic(&p, text.as_bytes())?;
    Ok(())
}

/// Add (or replace, same id) a task.
pub fn add(server: &str, task: Task) -> anyhow::Result<()> {
    let mut v = load(server);
    v.retain(|t| t.id != task.id);
    v.push(task);
    save(server, &v)
}

pub fn remove(server: &str, id: &str) -> anyhow::Result<()> {
    let mut v = load(server);
    v.retain(|t| t.id != id);
    save(server, &v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maint::log::LogHead;

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn a_task_round_trips_through_the_file_format() {
        let mut t = task(
            "run quick-update",
            Some(Dur::secs(90 * 86400)),
            "2026-10-20T00:00:00Z",
        );
        t.steps = "```bash\nls\n```".into();
        let text = toml::to_string(&File {
            task: vec![t.clone()],
        })
        .unwrap();
        assert_eq!(toml::from_str::<File>(&text).unwrap().task, vec![t.clone()]);
        assert!(t.to_toml().starts_with("[[task]]"));
        // `run`/`plan` of something that isn't there is done by hand, and says why.
        validate(&mut t, &[], &[]);
        assert_eq!(t.action(), Do::ByHand);
        assert!(t.why.contains("workflow quick-update not found"));
        assert_eq!(slug(" Plan  Web! "), "plan-web");
    }

    fn entry(
        workflow: &str,
        item: Option<&str>,
        result: &str,
        ended: &str,
        tags: &[&str],
    ) -> LogEntry {
        LogEntry {
            head: LogHead {
                workflow: workflow.into(),
                item: item.map(String::from),
                result: result.into(),
                ended: Some(ts(ended)),
                tags: tags.iter().map(|t| t.to_string()).collect(),
                ..Default::default()
            },
            body: String::new(),
        }
    }

    fn task(act: &str, every: Option<Dur>, added: &str) -> Task {
        Task {
            id: "t".into(),
            title: "T".into(),
            why: "because".into(),
            level: Level::Soon,
            every,
            act: act.into(),
            item: None,
            steps: String::new(),
            added: Some(ts(added)),
            review: None,
            after: None,
            again: None,
            off: false,
            source: Default::default(),
        }
    }

    #[test]
    fn an_override_in_tasks_toml_replaces_a_config_cadence() {
        // A cadence from the config (a server's `maintenance.cadence`, a job's).
        let mut cadence = task(
            "run apt-maintenance",
            Some(Dur::secs(30 * 86400)),
            "2026-10-20T00:00:00Z",
        );
        cadence.id = "cadence-apt-maintenance".into();
        cadence.source = Source::Config;
        assert_eq!(parse_every(" 45d "), Ok(Some(Dur::secs(45 * 86400))));
        assert_eq!(parse_every("off"), Ok(None));
        assert!(parse_every("soon").is_err());
        let server = "every-test";
        set_every(server, &cadence, parse_every("45d").unwrap()).unwrap();
        let all = effective(&load(server), vec![cadence.clone()]);
        assert_eq!(all.len(), 1, "the file's takes the config's place");
        assert_eq!(all[0].every, Some(Dur::secs(45 * 86400)));
        assert!(!all[0].off);
        // Off: still one task, never due; its cadence is kept for turning it on again.
        set_every(server, &all[0], None).unwrap();
        let all = effective(&load(server), vec![cadence]);
        assert!(all[0].off && all[0].every == Some(Dur::secs(45 * 86400)));
        assert!(!due(&all[0], &[], None, ts("2027-10-20T00:00:00Z")));
    }

    #[test]
    fn a_follow_up_waits_for_its_workflow_or_its_time() {
        let mut t = task("by-hand", None, "2026-10-20T00:00:00Z");
        t.after = Some("quick-update".into());
        let now = ts("2026-10-27T12:00:00Z");
        assert!(!due(&t, &[], None, now), "the run hasn't happened");
        let before = entry("quick-update", None, "done", "2026-10-19T00:00:00Z", &[]);
        let failed = entry("quick-update", None, "failed", "2026-10-21T00:00:00Z", &[]);
        assert!(!due(&t, &[before, failed.clone()], None, now));
        let ran = entry("quick-update", None, "done", "2026-10-22T00:00:00Z", &[]);
        assert!(due(&t, &[failed, ran], None, now));
        assert_eq!(t.when(), "once, after the next quick-update run");
        t.after = Some("7d".into());
        assert!(due(&t, &[], None, now));
        assert!(!due(&t, &[], None, ts("2026-10-25T00:00:00Z")));
        assert_eq!(t.when(), "once, 7d after it was added");
    }

    #[test]
    fn once_is_due_until_its_action_ends_well_after_it_was_added() {
        let now = ts("2026-10-27T12:00:00Z");
        let t = task("run quick-update", None, "2026-10-20T00:00:00Z");
        assert!(due(&t, &[], None, now));
        // Before it was added, or abandoned: still due.
        let old = entry("quick-update", None, "done", "2026-10-01T00:00:00Z", &[]);
        let gave_up = entry(
            "quick-update",
            None,
            "abandoned",
            "2026-10-25T00:00:00Z",
            &[],
        );
        assert!(due(&t, &[old.clone(), gave_up], None, now));
        let ok = entry("quick-update", None, "done", "2026-10-26T00:00:00Z", &[]);
        assert!(!due(&t, &[old, ok.clone()], None, now));
        assert_eq!(finished(&t, &[ok], None), Some(ts("2026-10-26T00:00:00Z")));
        // By hand: only its own log entry counts.
        let h = task("by-hand", None, "2026-10-20T00:00:00Z");
        let other = entry("by-hand", Some("x"), "done", "2026-10-26T00:00:00Z", &[]);
        assert!(due(&h, &[other], None, now));
        let mine = entry(
            "by-hand",
            Some("t"),
            "done",
            "2026-10-26T00:00:00Z",
            &["task:t"],
        );
        assert!(!due(&h, &[mine], None, now));
        // Audit: the last audit.
        let a = task("audit", None, "2026-10-20T00:00:00Z");
        assert!(due(&a, &[], Some(ts("2026-10-19T00:00:00Z")), now));
        assert!(!due(&a, &[], Some(ts("2026-10-21T00:00:00Z")), now));
        // Plan an item: that item's change ending well.
        let p = task("plan web", None, "2026-10-20T00:00:00Z");
        let web = entry(
            "compose-bump",
            Some("web"),
            "done",
            "2026-10-22T00:00:00Z",
            &[],
        );
        assert!(!due(&p, &[web], None, now));
    }

    #[test]
    fn every_is_due_again_after_its_interval() {
        let now = ts("2026-10-27T12:00:00Z");
        let t = task(
            "by-hand",
            Some(Dur::secs(30 * 86400)),
            "2026-01-01T00:00:00Z",
        );
        assert!(due(&t, &[], None, now));
        let recent = entry(
            "by-hand",
            Some("t"),
            "done",
            "2026-10-10T00:00:00Z",
            &["task:t"],
        );
        assert!(!due(&t, std::slice::from_ref(&recent), None, now));
        let old = entry(
            "by-hand",
            Some("t"),
            "done",
            "2026-09-01T00:00:00Z",
            &["task:t"],
        );
        assert!(due(&t, &[old], None, now));
        assert_eq!(finished(&t, std::slice::from_ref(&recent), None), None);
        let r = recs(&[t], &[recent], None, now);
        assert!(r.is_empty());
    }

    #[test]
    fn done_one_time_tasks_go_before_their_log_entry() {
        let once = task("run quick-update", None, "2026-01-01T00:00:00Z");
        let mut every = task("by-hand", Some(Dur::secs(86400)), "2026-01-01T00:00:00Z");
        every.id = "e".into();
        let ran = entry("quick-update", None, "done", "2026-02-01T00:00:00Z", &[]);
        let log = [ran];
        let tasks = [once, every];
        let ids = |v: Vec<Task>| v.into_iter().map(|t| t.id).collect::<Vec<_>>();
        assert_eq!(ids(keep(&tasks, &log, ts("2026-03-01T00:00:00Z"))), ["e"]);
        assert_eq!(
            ids(keep(&tasks, &log, ts("2026-01-15T00:00:00Z"))),
            ["t", "e"]
        );
    }

    fn job_task(id: &str, act: &str, every: Option<u64>) -> Task {
        Task {
            id: id.into(),
            title: id.into(),
            why: String::new(),
            level: Level::Routine,
            every: every.map(|d| Dur::secs(d * 86400)),
            act: act.into(),
            item: None,
            steps: String::new(),
            added: None,
            off: false,
            source: Source::Default,
            review: None,
            after: None,
            again: None,
        }
    }

    fn job_run(name: &str, ok: bool, at: &str) -> LogEntry {
        LogEntry::event("", "job", name, ok, "", &[], ts(at))
    }

    #[test]
    fn job_tasks_are_done_by_their_jobs_and_overdue_twice_is_soon() {
        assert_eq!(
            Do::parse("job update-check"),
            Some(Do::Job("update-check".into()))
        );
        assert_eq!(Do::parse("job audit"), Some(Do::Audit));
        let now = ts("2026-11-02T00:00:00Z");
        let clean = job_task("job-cleanup", "job cleanup", Some(30));
        // Any cleanup job counts; a failed one doesn't.
        let log = vec![
            job_run("cleanup-podman", false, "2026-10-30T00:00:00Z"),
            job_run("cleanup-ostree", true, "2026-10-20T00:00:00Z"),
        ];
        assert_eq!(
            last_done(&clean, &log, None),
            Some(ts("2026-10-20T00:00:00Z"))
        );
        assert!(!due(&clean, &log, None, now));
        // Never done: due. Done 70 days ago with a 30-day cadence: due, and soon.
        assert!(due(&clean, &[], None, now));
        // Never done, but nobody asked for it (a job's own cadence): its 30 days count from
        // when the log here began. One you put in tasks.toml is due at once.
        let began = |at| vec![job_run("update-check", true, at)];
        assert!(!due(&clean, &began("2026-10-23T00:00:00Z"), None, now));
        let long = began("2026-09-20T00:00:00Z");
        assert!(due(&clean, &long, None, now));
        let r = recs(std::slice::from_ref(&clean), &long, None, now);
        assert!(
            r[0].why
                .ends_with("(not done yet, tracked since 2026-09-20)"),
            "{}",
            r[0].why
        );
        // That it recurs is said with its name; a task without `every` is once, and says
        // nothing. The level is only how soon.
        assert!(r[0].title.ends_with(" · every 30d"), "{}", r[0].title);
        let once = Task {
            every: None,
            source: Source::File,
            ..clean.clone()
        };
        let o = recs(std::slice::from_ref(&once), &[], None, now);
        assert_eq!(o[0].title, once.title);
        assert_eq!(r[0].level, clean.level, "never done isn't late");
        let mine = Task {
            source: Source::File,
            ..clean.clone()
        };
        assert!(due(&mine, &began("2026-10-23T00:00:00Z"), None, now));
        let old = vec![job_run("cleanup-ostree", true, "2026-08-24T00:00:00Z")];
        let r = recs(std::slice::from_ref(&clean), &old, None, now);
        assert_eq!(r[0].level, Level::Soon);
        // Turned off: never due.
        let off = Task { off: true, ..clean };
        assert!(!due(&off, &[], None, now));
    }

    #[test]
    fn the_file_replaces_a_derived_task_and_x_turns_a_derived_one_off() {
        let derived = vec![
            job_task("job-audit", "audit", Some(30)),
            job_task("job-cleanup", "job cleanup", Some(30)),
        ];
        let mut mine = job_task("job-audit", "audit", Some(7));
        mine.source = Source::File;
        let all = effective(std::slice::from_ref(&mine), derived);
        assert_eq!(all.len(), 2);
        let audit = all.iter().find(|t| t.id == "job-audit").unwrap();
        assert_eq!(audit.every, Some(Dur::secs(7 * 86400)));
        // x on a derived one writes it with off = true.
        let server = "x-turns-off";
        let off = remove_or_off(server, &all[0], &[]).unwrap();
        assert!(off);
        let back = load(server);
        assert!(back[0].off && back[0].id == "job-cleanup", "{back:?}");
        // x on one from the file removes it.
        assert!(!remove_or_off(server, &back[0], &back).unwrap());
        assert!(load(server).is_empty());
    }

    #[test]
    fn a_run_is_tagged_with_the_tasks_it_does() {
        let tasks = vec![
            job_task("weekly", "run quick-update", Some(7)),
            job_task("other", "run something-else", None),
        ];
        let mut e = LogEntry::parse(
            "+++\nworkflow = \"quick-update\"\nresult = \"done\"\ntags = [\"result:done\"]\n+++\n",
        )
        .unwrap();
        tag_run(&mut e, &tasks);
        tag_run(&mut e, &tasks);
        assert_eq!(e.head.tags, ["result:done", "task:weekly"]);
        let mut failed =
            LogEntry::parse("+++\nworkflow = \"quick-update\"\nresult = \"failed\"\n+++\n")
                .unwrap();
        tag_run(&mut failed, &tasks);
        assert!(failed.head.tags.is_empty());
    }

    #[test]
    fn a_run_of_the_whole_workflow_does_a_task_written_for_an_item() {
        // A review's task: `run firmware-upgrade`, item `firmware`. The run is logged as the
        // workflow as a whole (`kind = "system"`, no item).
        let mut fw = task("run firmware-upgrade", None, "2026-11-01T00:00:00Z");
        fw.id = "fw".into();
        fw.item = Some("firmware".into());
        let mut web = task("run compose-update", None, "2026-11-01T00:00:00Z");
        web.id = "web".into();
        web.item = Some("web".into());
        let tasks = vec![fw.clone(), web.clone()];
        let whole = entry(
            "firmware-upgrade",
            None,
            "done",
            "2026-11-20T10:00:00Z",
            &[],
        );
        assert_eq!(
            last_done(&fw, std::slice::from_ref(&whole), None),
            Some(ts("2026-11-20T10:00:00Z"))
        );
        assert!(!due(
            &fw,
            std::slice::from_ref(&whole),
            None,
            ts("2026-11-21T00:00:00Z")
        ));
        let mut tagged = whole.clone();
        tag_run(&mut tagged, &tasks);
        assert_eq!(tagged.head.tags, ["task:fw"]);
        // A run that said which item it changed does only that item's task.
        let other = entry(
            "compose-update",
            Some("db"),
            "done",
            "2026-11-20T10:00:00Z",
            &[],
        );
        assert_eq!(last_done(&web, std::slice::from_ref(&other), None), None);
        let mut tagged = other.clone();
        tag_run(&mut tagged, &tasks);
        assert!(tagged.head.tags.is_empty());
        let same = entry(
            "compose-update",
            Some("web"),
            "done",
            "2026-11-20T10:00:00Z",
            &[],
        );
        assert!(last_done(&web, std::slice::from_ref(&same), None).is_some());
        // Neither a failed run nor another workflow does it.
        let failed = entry(
            "firmware-upgrade",
            None,
            "failed",
            "2026-11-20T10:00:00Z",
            &[],
        );
        assert_eq!(last_done(&fw, &[failed], None), None);
        let pkgs = entry("package-update", None, "done", "2026-11-20T10:00:00Z", &[]);
        assert_eq!(last_done(&fw, &[pkgs], None), None);
    }

    #[test]
    fn a_task_can_wait_for_a_task_of_another_target() {
        assert_eq!(
            after_task("task:srv:myserver/open-api"),
            Some(("myserver".into(), "open-api"))
        );
        assert_eq!(
            after_task("task:net:home/bouncer"),
            Some(("net:home".into(), "bouncer"))
        );
        assert_eq!(after_task("task:local/x"), Some((String::new(), "x")));
        assert_eq!(after_task("task:/x"), Some((String::new(), "x")));
        for bad in [
            "task:srv:/x",
            "task:myserver/x",
            "task:srv:myserver/",
            "quick-update",
            "7d",
            "task:x",
        ] {
            assert_eq!(after_task(bad), None, "{bad}");
        }
        let now = ts("2026-11-21T12:00:00Z");
        let mut t: Task = toml::from_str("id = \"bouncer\"\ntitle = \"Install the bouncer\"\nlevel = \"routine\"\ndo = \"by-hand\"").unwrap();
        t.after = Some("task:srv:myserver/open-api".into());
        let done = |id: &str| {
            let mut e = LogEntry::task("myserver", id, id, None);
            e.head.tags = vec![format!("task:{id}")];
            e
        };
        for (scope_has, want) in [
            // Nothing logged there yet: it waits.
            (vec![], false),
            // Another task done there: still waits.
            (vec![done("other")], false),
            // That task logged done under that target's scope: due.
            (vec![done("other"), done("open-api")], true),
        ] {
            let other = |scope: &str| {
                assert_eq!(scope, "myserver");
                scope_has.clone()
            };
            assert_eq!(waited_in(&t, &[], now, &other), want);
        }
        // This target's own log doesn't count for it.
        assert!(!waited_in(&t, &[done("open-api")], now, &|_| Vec::new()));
    }
}

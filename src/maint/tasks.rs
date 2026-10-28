//! Tasks you took from a review: one-time ("plan web to 1.5.2", "check the UPS battery") or
//! recurring (`every = "90d"`). Claude suggests them at the end of a review in a
//! ```` ```sentry-tasks ```` TOML block; you accept each one in the review view and it lands in
//! `tasks.toml` under [`super::root`]. Maintenance shows those that are due. Whether a task is
//! done comes from the log (the workflow it runs ended well, or `d` logged it by hand), never
//! from this file. Edit it freely.

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
    /// `run <workflow>`, `plan <item>` (sentry-server), `audit`, or `by-hand`.
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
    /// The review it came from (file name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<String>,
}

/// What Enter does on a task.
#[derive(Debug, Clone, PartialEq)]
pub enum Do {
    Run(String),
    Plan(String),
    Audit,
    ByHand,
}

impl Do {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        match s.split_once(char::is_whitespace) {
            Some(("run", wf)) if !wf.trim().is_empty() => Some(Do::Run(wf.trim().to_string())),
            Some(("plan", it)) if !it.trim().is_empty() => Some(Do::Plan(it.trim().to_string())),
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

    /// "once" or "every 90d".
    pub fn when(&self) -> String {
        self.every
            .map_or("once".to_string(), |d| format!("every {d}"))
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

/// A review's suggestion and what you did with it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SugState {
    #[default]
    Open,
    Added,
    Skipped,
}

impl SugState {
    pub fn word(self) -> &'static str {
        match self {
            SugState::Open => "open",
            SugState::Added => "added",
            SugState::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Suggestion {
    #[serde(default)]
    pub state: SugState,
    pub task: Task,
}

/// What a suggestion may point at: the workflows there are, and (sentry-server) the items.
pub struct Known<'a> {
    pub workflows: &'a [String],
    pub items: &'a [String],
}

const FENCE: &str = "```sentry-tasks";

/// Claude's review answer → the review without its tasks block, and the tasks in it. Entries
/// that don't parse are dropped; a `run`/`plan` of something unknown becomes by hand.
pub fn take_suggestions(answer: &str, known: &Known) -> (String, Vec<Task>) {
    let lines: Vec<&str> = answer.lines().collect();
    let Some(start) = lines.iter().position(|l| l.trim_start().starts_with(FENCE)) else {
        return (answer.to_string(), Vec::new());
    };
    // The closing fence is the first one outside a TOML multi-line string: `steps` may hold
    // Markdown with fences of its own.
    let mut quoted = false;
    let end = lines[start + 1..]
        .iter()
        .position(|l| {
            let closes = !quoted && l.trim() == "```";
            if l.matches("\"\"\"").count() % 2 == 1 {
                quoted = !quoted;
            }
            closes
        })
        .map_or(lines.len(), |n| start + 1 + n);
    let block = lines[start + 1..end].join("\n");
    let rest: Vec<&str> = lines[..start]
        .iter()
        .chain(lines.get(end + 1..).unwrap_or_default())
        .copied()
        .collect();
    let body = rest.join("\n").trim().to_string();
    (body, parse_block(&block, known))
}

fn parse_block(block: &str, known: &Known) -> Vec<Task> {
    #[derive(Deserialize)]
    struct Block {
        #[serde(default)]
        task: Vec<toml::Value>,
    }
    let Ok(b) = toml::from_str::<Block>(block) else {
        return Vec::new();
    };
    let mut out: Vec<Task> = Vec::new();
    for v in b.task {
        let Ok(mut t) = v.try_into::<Task>() else {
            continue;
        };
        t.id = slug(&t.id);
        if t.id.is_empty() || t.title.trim().is_empty() || out.iter().any(|o| o.id == t.id) {
            continue;
        }
        validate(&mut t, known);
        out.push(t);
    }
    out
}

/// `run`/`plan` must name a workflow or item there is; anything else is done by hand.
fn validate(t: &mut Task, known: &Known) {
    let missing = match Do::parse(&t.act) {
        Some(Do::Run(wf)) if !known.workflows.contains(&wf) => Some(format!("workflow {wf}")),
        Some(Do::Plan(it)) if !known.items.contains(&it) => Some(format!("item {it}")),
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

fn slug(s: &str) -> String {
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

/// The end of a review request: how to suggest tasks, and the tasks already taken.
pub fn request_section(workflows: &[String], items: &[String], current: &[Task]) -> String {
    let mut dos = vec!["`audit`".to_string(), "`by-hand`".to_string()];
    dos.extend(workflows.iter().map(|w| format!("`run {w}`")));
    dos.extend(items.iter().map(|i| format!("`plan {i}`")));
    let taken = if current.is_empty() {
        "(none yet)".to_string()
    } else {
        current
            .iter()
            .map(|t| format!("- {}: {} ({}; {})", t.id, t.title, t.when(), t.act))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "Last, after the Watch section and with no heading of its own, suggest the tasks the user \
         should add to sentry's Maintenance list: things from Now, Soon and Routine that the \
         recommendations above don't already cover, as one fenced block whose info string is \
         `sentry-tasks`, TOML, one `[[task]]` table each:\n\
         ```sentry-tasks\n[[task]]\nid = \"short-slug\"\ntitle = \"What to do, in a few words\"\n\
         why = \"One or two sentences: why, and why now\"\nlevel = \"now\" # now, soon, routine or tidy\n\
         do = \"by-hand\"\n# every = \"90d\" only for work that recurs; leave it out for once\n\
         # item = \"<item id>\" when it's about one\n\
         steps = \"\"\"\nFor by-hand tasks: the exact steps and commands, in Markdown.\n\"\"\"\n```\n\
         `do` is one of: {}. The user accepts each task or not; suggest none if nothing is missing.\n\
         Tasks already taken (don't suggest them again):\n{taken}",
        dos.join(", ")
    )
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
                    Do::Run(wf) => {
                        ok && &h.workflow == wf
                            && t.item.as_ref().is_none_or(|i| h.item.as_ref() == Some(i))
                    }
                    Do::Plan(it) => ok && h.item.as_ref() == Some(it),
                    Do::Audit | Do::ByHand => false,
                }
        })
        .filter_map(|e| e.head.ended.or(e.head.started))
        .max();
    let audit = matches!(act, Do::Audit).then_some(audited).flatten();
    from_log.max(audit)
}

/// Whether it belongs on Maintenance now.
pub fn due(t: &Task, log: &[LogEntry], audited: Option<Timestamp>, now: Timestamp) -> bool {
    let last = last_done(t, log, audited);
    match t.every {
        None => match (last, t.added) {
            (None, _) => true,
            (Some(l), Some(a)) => l < a,
            (Some(_), None) => false,
        },
        Some(every) => {
            last.is_none_or(|l| now.as_second() - l.as_second() >= every.0.as_secs() as i64)
        }
    }
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
            let why = match (t.every, last) {
                (Some(d), Some(l)) => format!(
                    "{} (every {d}; last done {})",
                    t.why.trim(),
                    l.strftime("%Y-%m-%d")
                ),
                (Some(d), None) => format!("{} (every {d}; not done yet)", t.why.trim()),
                (None, _) => t.why.trim().to_string(),
            };
            TaskRec {
                level: t.level,
                key: t.key(),
                title: t.title.clone(),
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
        "# Maintenance tasks you took from a review (a on the review view). Done is read from\n\
         # the maintenance log; do = run <workflow> | plan <item> | audit | by-hand. Edit freely.\n\n{}",
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

    fn known() -> (Vec<String>, Vec<String>) {
        (vec!["quick-update".into()], vec!["web".into()])
    }

    const ANSWER: &str = "# Maintenance review\n\n## Now\n- web\n\n```sentry-tasks\n\
        [[task]]\nid = \"Plan Web\"\ntitle = \"Plan web to 1.5.2\"\nwhy = \"security fix\"\n\
        level = \"now\"\ndo = \"plan web\"\nitem = \"web\"\n\n\
        [[task]]\nid = \"ups\"\ntitle = \"Check the UPS battery\"\nlevel = \"routine\"\n\
        every = \"90d\"\ndo = \"by-hand\"\nsteps = \"Run the self-test.\"\n\n\
        [[task]]\nid = \"ghost\"\ntitle = \"Run ghost\"\nlevel = \"soon\"\ndo = \"run ghost\"\n\n\
        [[task]]\nid = \"ups\"\ntitle = \"again\"\nlevel = \"soon\"\ndo = \"audit\"\n\n\
        [[task]]\nid = \"bad\"\ntitle = \"bad level\"\nlevel = \"whenever\"\ndo = \"audit\"\n\
        ```\n";

    #[test]
    fn the_block_leaves_the_body_and_bad_entries_go() {
        let (wf, it) = known();
        let k = Known {
            workflows: &wf,
            items: &it,
        };
        let (body, tasks) = take_suggestions(ANSWER, &k);
        assert_eq!(body, "# Maintenance review\n\n## Now\n- web");
        let ids: Vec<&str> = tasks.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, ["plan-web", "ups", "ghost"]);
        assert_eq!(tasks[0].action(), Do::Plan("web".into()));
        assert_eq!(tasks[1].every, Some(Dur::secs(90 * 86400)));
        // An unknown workflow: done by hand, and it says why.
        assert_eq!(tasks[2].action(), Do::ByHand);
        assert!(tasks[2].why.contains("workflow ghost not found"));
        // Fences inside `steps` don't end the block.
        let fenced = "# Review\n\n```sentry-tasks\n[[task]]\nid = \"fw\"\ntitle = \"Firmware\"\n\
            level = \"routine\"\ndo = \"by-hand\"\nsteps = \"\"\"\n```bash\nfwupdmgr get-updates\n```\n\
            Then reboot.\n\"\"\"\n\n[[task]]\nid = \"two\"\ntitle = \"Two\"\nlevel = \"tidy\"\n\
            do = \"by-hand\"\nsteps = \"\"\"\n```\nls\n```\n\"\"\"\n```\n\n## After";
        let (body, tasks) = take_suggestions(fenced, &k);
        assert_eq!(body, "# Review\n\n\n## After");
        assert_eq!(tasks.len(), 2);
        assert!(tasks[0].steps.contains("```bash\nfwupdmgr get-updates\n```"));
        // No block: nothing taken.
        let (b, t) = take_suggestions("# Review\n", &k);
        assert_eq!((b.as_str(), t.len()), ("# Review\n", 0));
    }

    #[test]
    fn a_task_round_trips_through_the_file_format() {
        let (wf, it) = known();
        let k = Known {
            workflows: &wf,
            items: &it,
        };
        let (_, tasks) = take_suggestions(ANSWER, &k);
        let text = toml::to_string(&File {
            task: tasks.clone(),
        })
        .unwrap();
        assert_eq!(toml::from_str::<File>(&text).unwrap().task, tasks);
        assert!(tasks[1].to_toml().starts_with("[[task]]"));
    }

    #[test]
    fn the_request_lists_what_do_may_name_and_the_tasks_taken() {
        let (wf, it) = known();
        let s = request_section(&wf, &it, &[task("audit", None, "2026-10-20T00:00:00Z")]);
        assert!(s.contains("`run quick-update`") && s.contains("`plan web`"));
        assert!(s.contains("- t: T (once; audit)"));
        // The example in it parses as a block.
        let k = Known {
            workflows: &wf,
            items: &it,
        };
        let (_, tasks) = take_suggestions(&s, &k);
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, "short-slug");
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
        }
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
}

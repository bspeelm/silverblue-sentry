//! A recommendation, as both programs' Maintenance lists show it, and the tail both rule
//! engines share: the tasks due join the list (a task and a rule about the same thing become
//! one row), what was put off with `z` leaves it, and the rest is ranked by level. Pure.

use std::collections::BTreeMap;

use jiff::Timestamp;
use jiff::civil::Date;

use super::Level;
use super::log::LogEntry;
use super::tasks::{Do, Task};

/// One row: `A` is the program's own action (what Enter does).
#[derive(Debug, Clone, PartialEq)]
pub struct Rec<A> {
    pub level: Level,
    /// Stable: for `z`, for keeping the selection, and for jumping to it.
    pub key: String,
    pub title: String,
    pub why: String,
    pub action: A,
    /// The maintenance item it's about (sentry-server; None on this machine).
    pub item: Option<String>,
    /// Nothing asks for it yet (a newer version, updates no one is waiting on, something to
    /// tidy): listed only with everything (`o`).
    pub can_wait: bool,
}

/// What a row acts on: a task and a rule acting on the same thing are one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Workflow(String),
    Item(String),
    Audit,
    /// One of this machine's jobs (`cleanup`: the Cleanup screen).
    Job(String),
    None,
}

pub trait Act: Clone {
    fn target(&self) -> Target;
    /// The row for a task (its id).
    fn task(id: String) -> Self;
}

/// What a task does, as a target.
pub fn task_target(t: &Task) -> Target {
    match t.action() {
        Do::Run(wf) => Target::Workflow(wf),
        Do::Plan(it) => Target::Item(it),
        Do::Audit => Target::Audit,
        Do::Job(j) if j.starts_with("cleanup") => Target::Job("cleanup".into()),
        Do::Job(j) => Target::Job(j),
        Do::ByHand => Target::None,
    }
}

/// What both engines do last.
pub struct Tail<'a> {
    pub tasks: &'a [Task],
    pub log: &'a [LogEntry],
    pub audited: Option<Timestamp>,
    pub now: Timestamp,
    /// Put off with `z`: key → the day it shows again.
    pub snooze: &'a BTreeMap<String, Date>,
    pub today: Date,
}

/// Add the tasks due (a rule about the same target folds into the task's row, which keeps the
/// more urgent level), drop what's put off, and rank by level. The engine's own order holds
/// within a level; tasks come after the rules of their level.
pub fn finish<A: Act>(mut rules: Vec<Rec<A>>, t: &Tail) -> Vec<Rec<A>> {
    for d in super::tasks::recs(t.tasks, t.log, t.audited, t.now) {
        let target = t
            .tasks
            .iter()
            .find(|x| x.id == d.id)
            .map_or(Target::None, task_target);
        let mut row = Rec {
            level: d.level,
            key: d.key,
            title: d.title,
            why: d.why,
            action: A::task(d.id),
            item: d.item,
            can_wait: false,
        };
        if target != Target::None {
            let (same, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut rules)
                .into_iter()
                .partition(|r| r.action.target() == target);
            rules = rest;
            for r in same {
                row.level = row.level.min(r.level);
                row.why = format!("{} · also: {}", row.why, r.title);
            }
        }
        rules.push(row);
    }
    rules.retain(|r| t.snooze.get(&r.key).is_none_or(|d| *d <= t.today));
    rules.sort_by_key(|r| r.level);
    rules
}

/// What the list shows: everything, or only what's due or urgent. With it, how many wait.
pub fn needed<A>(recs: Vec<Rec<A>>, everything: bool) -> (Vec<Rec<A>>, usize) {
    let waiting = recs.iter().filter(|r| r.can_wait).count();
    if everything {
        return (recs, 0);
    }
    (recs.into_iter().filter(|r| !r.can_wait).collect(), waiting)
}

/// The Recommended panel's note: how many rows, how many ticked, how many wait.
pub fn note(shown: usize, ticked: usize, waiting: usize) -> String {
    let mut s = shown.to_string();
    if ticked > 0 {
        s.push_str(&format!(" · {ticked} ticked"));
    }
    if waiting > 0 {
        s.push_str(&format!(" · {waiting} can wait (o)"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    enum A {
        Run(String),
        Other,
        Task(String),
    }

    impl Act for A {
        fn target(&self) -> Target {
            match self {
                A::Run(wf) => Target::Workflow(wf.clone()),
                _ => Target::None,
            }
        }
        fn task(id: String) -> Self {
            A::Task(id)
        }
    }

    fn rec(level: Level, key: &str, action: A) -> Rec<A> {
        Rec {
            level,
            key: key.into(),
            title: key.into(),
            why: String::new(),
            action,
            item: None,
            can_wait: false,
        }
    }

    fn task(id: &str, act: &str, level: Level) -> Task {
        Task {
            id: id.into(),
            title: id.into(),
            why: "why".into(),
            level,
            every: None,
            act: act.into(),
            item: None,
            steps: String::new(),
            added: None,
            review: None,
            after: None,
            again: None,
            off: false,
            source: Default::default(),
        }
    }

    fn tail<'a>(tasks: &'a [Task], snooze: &'a BTreeMap<String, Date>) -> Tail<'a> {
        Tail {
            tasks,
            log: &[],
            audited: None,
            now: "2026-11-02T12:00:00Z".parse().unwrap(),
            snooze,
            today: jiff::civil::date(2026, 11, 2),
        }
    }

    #[test]
    fn a_task_and_a_rule_about_the_same_workflow_are_one_row() {
        let rules = vec![
            rec(Level::Now, "updates", A::Run("quick-update".into())),
            rec(Level::Soon, "other", A::Other),
        ];
        let tasks = [task("weekly", "run quick-update", Level::Routine)];
        let none = BTreeMap::new();
        let out = finish(rules, &tail(&tasks, &none));
        assert_eq!(out.len(), 2, "{out:#?}");
        // The task's row, as urgent as the rule it took in.
        assert_eq!(out[0].action, A::Task("weekly".into()));
        assert_eq!(out[0].level, Level::Now);
        assert!(out[0].why.ends_with("also: updates"), "{}", out[0].why);
        assert_eq!(out[1].key, "other");
    }

    #[test]
    fn put_off_rows_wait_and_the_rest_rank_by_level_keeping_order() {
        let rules = vec![
            rec(Level::Tidy, "t", A::Other),
            rec(Level::Soon, "b", A::Other),
            rec(Level::Soon, "a", A::Other),
            rec(Level::Now, "later", A::Other),
        ];
        let tasks = [task("by-hand", "by-hand", Level::Soon)];
        let mut snooze = BTreeMap::new();
        snooze.insert("later".to_string(), jiff::civil::date(2026, 11, 9));
        // A date that has come: it's back.
        snooze.insert("t".to_string(), jiff::civil::date(2026, 11, 2));
        let out = finish(rules, &tail(&tasks, &snooze));
        let keys: Vec<&str> = out.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, ["b", "a", "task:by-hand", "t"]);
    }

    #[test]
    fn what_can_wait_is_hidden_until_a_due_task_takes_it_in() {
        let waits = |key: &str, a: A| Rec {
            can_wait: true,
            ..rec(Level::Routine, key, a)
        };
        let rules = || {
            vec![
                waits("updates", A::Run("quick-update".into())),
                waits("newer", A::Other),
                rec(Level::Soon, "finding", A::Other),
            ]
        };
        let none = BTreeMap::new();
        // Nothing due: only the finding; two wait, and `o` shows them.
        let (out, waiting) = needed(finish(rules(), &tail(&[], &none)), false);
        assert_eq!((out.len(), waiting), (1, 2));
        assert_eq!(out[0].key, "finding");
        let (all, waiting) = needed(finish(rules(), &tail(&[], &none)), true);
        assert_eq!((all.len(), waiting), (3, 0));
        // A due task about the same workflow takes the updates in: its row doesn't wait.
        let tasks = [task("weekly", "run quick-update", Level::Routine)];
        let (out, waiting) = needed(finish(rules(), &tail(&tasks, &none)), false);
        let keys: Vec<&str> = out.iter().map(|r| r.key.as_str()).collect();
        assert_eq!((keys, waiting), (vec!["finding", "task:weekly"], 1));
        assert_eq!(note(2, 0, 1), "2 · 1 can wait (o)");
        assert_eq!(note(2, 2, 0), "2 · 2 ticked");
    }
}

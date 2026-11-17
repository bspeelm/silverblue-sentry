//! Maintenance reviews: Claude looks over everything tracked, what discovery found, the
//! ledger and upstream, and writes what to maintain next and why. Saved as
//! `reviews/<YYYY-MM-DD-HHMM>.md` under [`super::root`] (a `+++` TOML header, then Markdown).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::changes::{Change, Kind, Known, State};
use super::plan::PlanStatus;
use super::tasks::Task;
use crate::paths;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReviewHead {
    /// The server reviewed (empty: this machine).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server: String,
    pub status: PlanStatus,
    pub created: Option<jiff::Timestamp>,
    pub updated: Option<jiff::Timestamp>,
    pub session: Option<String>,
    /// What Claude proposed to change on the list (its `sentry-changes` block), and what
    /// became of each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<Change>,
    /// Proposals that couldn't be used, and why.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dropped: Vec<String>,
    /// Reviews written before changes: the tasks they suggested (read, never written).
    #[serde(skip_serializing)]
    suggest: Vec<Suggested>,
}

/// An older review's suggested task.
#[derive(Debug, Clone, PartialEq, Deserialize)]
struct Suggested {
    #[serde(default)]
    state: String,
    task: Task,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReviewDoc {
    pub head: ReviewHead,
    pub body: String,
}

const FENCE: &str = "+++";

impl ReviewDoc {
    pub fn new(server: &str) -> Self {
        Self {
            head: ReviewHead {
                server: server.to_string(),
                created: Some(jiff::Timestamp::now()),
                ..Default::default()
            },
            body: String::new(),
        }
    }

    pub fn to_md(&self) -> String {
        format!(
            "{FENCE}\n{}{FENCE}\n\n{}\n",
            toml::to_string(&self.head).unwrap_or_default(),
            self.body.trim_end()
        )
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let rest = text
            .strip_prefix(FENCE)
            .ok_or("no +++ header")?
            .trim_start_matches(['\r', '\n']);
        let end = rest
            .find(&format!("\n{FENCE}"))
            .ok_or("unterminated header")?;
        let mut head: ReviewHead = toml::from_str(&rest[..end]).map_err(|e| e.to_string())?;
        // An older review's suggestions are tasks to add.
        for s in std::mem::take(&mut head.suggest) {
            head.changes.push(Change {
                why: s.task.why.clone(),
                state: match s.state.as_str() {
                    "added" => State::Applied,
                    "skipped" => State::Skipped,
                    _ => State::Open,
                },
                label: format!("{} · {}", s.task.title, s.task.when()),
                note: String::new(),
                on: true,
                kind: Kind::AddTask {
                    task: Box::new(s.task),
                },
            });
        }
        Ok(Self {
            head,
            body: rest[end + 1 + FENCE.len()..].trim().to_string(),
        })
    }

    /// Claude's answer: the review, from its title on (before it: Claude saying what it reads);
    /// its changes block becomes the changes.
    pub fn take_answer(&mut self, answer: &str, known: &Known, today: jiff::civil::Date) {
        let (answer, mut changes, dropped) = super::changes::take(answer, known, today);
        let review = self.file_name();
        for c in &mut changes {
            if let Kind::AddTask { task } = &mut c.kind {
                task.review = Some(review.clone());
            }
        }
        self.head.changes = changes;
        self.head.dropped = dropped;
        let lines: Vec<&str> = answer.lines().collect();
        let start = lines
            .iter()
            .position(|l| l.trim_start().starts_with('#'))
            .unwrap_or(0);
        self.body = lines[start..].join("\n").trim().to_string();
        self.head.status = PlanStatus::Ready;
        self.head.updated = Some(jiff::Timestamp::now());
    }

    /// The changes not yet applied or skipped.
    pub fn open(&self) -> Vec<&Change> {
        self.head
            .changes
            .iter()
            .filter(|c| c.state == State::Open)
            .collect()
    }

    pub fn file_name(&self) -> String {
        let when = self
            .head
            .created
            .map(|t| t.strftime("%Y-%m-%d-%H%M").to_string())
            .unwrap_or_else(|| "undated".into());
        format!("{when}.md")
    }
}

pub fn dir(server: &str) -> PathBuf {
    super::root(server).join("reviews")
}

pub fn save(doc: &ReviewDoc) -> anyhow::Result<PathBuf> {
    let d = dir(&doc.head.server);
    std::fs::create_dir_all(&d)?;
    let p = d.join(doc.file_name());
    paths::write_atomic(&p, doc.to_md().as_bytes())?;
    Ok(p)
}

/// Every review written, newest first, with its file.
pub fn list(server: &str) -> Vec<(PathBuf, ReviewDoc)> {
    let mut v: Vec<(PathBuf, ReviewDoc)> = std::fs::read_dir(dir(server))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .filter_map(|p| {
            let d = ReviewDoc::parse(&std::fs::read_to_string(&p).ok()?).ok()?;
            Some((p, d))
        })
        .filter(|(_, d)| d.head.status == PlanStatus::Ready)
        .collect();
    v.sort_by_key(|(_, d)| std::cmp::Reverse(d.head.created));
    v
}

/// One review, from its file.
pub fn read(p: &std::path::Path) -> Option<ReviewDoc> {
    ReviewDoc::parse(&std::fs::read_to_string(p).ok()?).ok()
}

/// The newest review that was written.
pub fn latest(server: &str) -> Option<ReviewDoc> {
    let mut v: Vec<ReviewDoc> = std::fs::read_dir(dir(server))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .filter_map(|p| ReviewDoc::parse(&std::fs::read_to_string(p).ok()?).ok())
        .filter(|d| d.head.status == PlanStatus::Ready)
        .collect();
    v.sort_by_key(|d| d.head.created);
    v.pop()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_becomes_the_review_and_round_trips() {
        let mut d = ReviewDoc::new("myserver");
        let items = [("web".to_string(), "medium risk".to_string())];
        let known = Known {
            items: &items,
            ..Default::default()
        };
        d.take_answer(
            "Reading the ledger first.\n# Maintenance review · myserver\n\n## Now\n- web: plan 1.5.2\n\n\
             ```sentry-changes\n[[add]]\nid = \"web\"\ntitle = \"Plan web\"\nlevel = \"now\"\n\
             do = \"plan web\"\n\n[[untrack]]\nitem = \"nope\"\n```",
            &known,
            "2026-11-16".parse().unwrap(),
        );
        assert!(d.body.starts_with("# Maintenance review"));
        assert!(!d.body.contains("sentry-changes"));
        assert_eq!(d.head.status, PlanStatus::Ready);
        assert_eq!(d.open().len(), 1);
        assert_eq!(d.head.dropped, ["untrack nope: not a tracked item"]);
        let Kind::AddTask { task } = &d.head.changes[0].kind else {
            panic!()
        };
        assert_eq!(task.review.as_deref(), Some(d.file_name().as_str()));
        assert_eq!(ReviewDoc::parse(&d.to_md()).unwrap(), d);
        d.head.changes[0].state = State::Applied;
        assert!(d.open().is_empty());
        assert_eq!(ReviewDoc::parse(&d.to_md()).unwrap(), d);
    }

    #[test]
    fn an_old_review_s_suggestions_still_load() {
        let old = "+++\nserver = \"myserver\"\nstatus = \"ready\"\n\n[[suggest]]\nstate = \"open\"\n\n\
            [suggest.task]\nid = \"ups\"\ntitle = \"Check the UPS\"\nwhy = \"it's old\"\nlevel = \"routine\"\n\
            every = \"90d\"\ndo = \"by-hand\"\n\n[[suggest]]\nstate = \"added\"\n\n[suggest.task]\n\
            id = \"web\"\ntitle = \"Plan web\"\nlevel = \"now\"\ndo = \"by-hand\"\n+++\n\n# Review\n";
        let d = ReviewDoc::parse(old).unwrap();
        assert_eq!(d.head.changes.len(), 2);
        assert_eq!(d.open().len(), 1);
        assert_eq!(d.open()[0].label, "Check the UPS · every 90d");
        assert_eq!(d.head.changes[1].state, State::Applied);
        // Written back, they're changes.
        let again = ReviewDoc::parse(&d.to_md()).unwrap();
        assert_eq!(again, d);
        assert!(!d.to_md().contains("[[suggest]]"));
    }
}

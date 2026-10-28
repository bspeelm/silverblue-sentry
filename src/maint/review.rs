//! Maintenance reviews: Claude looks over everything tracked, what discovery found, the
//! ledger and upstream, and writes what to maintain next and why. Saved as
//! `reviews/<YYYY-MM-DD-HHMM>.md` under [`super::root`] (a `+++` TOML header, then Markdown).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::plan::PlanStatus;
use super::tasks::{Known, SugState, Suggestion};
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
    /// The tasks Claude suggested (its `sentry-tasks` block), and what you did with each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub suggest: Vec<Suggestion>,
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
        Ok(Self {
            head: toml::from_str(&rest[..end]).map_err(|e| e.to_string())?,
            body: rest[end + 1 + FENCE.len()..].trim().to_string(),
        })
    }

    /// Claude's answer: the review, from its title on (before it: Claude saying what it reads);
    /// its tasks block becomes the suggestions.
    pub fn take_answer(&mut self, answer: &str, known: &Known) {
        let (answer, tasks) = super::tasks::take_suggestions(answer, known);
        let review = self.file_name();
        self.head.suggest = tasks
            .into_iter()
            .map(|mut task| {
                task.review = Some(review.clone());
                Suggestion {
                    state: SugState::Open,
                    task,
                }
            })
            .collect();
        let lines: Vec<&str> = answer.lines().collect();
        let start = lines
            .iter()
            .position(|l| l.trim_start().starts_with('#'))
            .unwrap_or(0);
        self.body = lines[start..].join("\n").trim().to_string();
        self.head.status = PlanStatus::Ready;
        self.head.updated = Some(jiff::Timestamp::now());
    }

    /// The suggestions not yet added or skipped.
    pub fn open(&self) -> Vec<&Suggestion> {
        self.head
            .suggest
            .iter()
            .filter(|s| s.state == SugState::Open)
            .collect()
    }

    /// Mark a suggestion added or skipped.
    pub fn mark(&mut self, id: &str, state: SugState) {
        for s in &mut self.head.suggest {
            if s.task.id == id {
                s.state = state;
            }
        }
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
        let known = Known {
            workflows: &[],
            items: &["web".to_string()],
        };
        d.take_answer(
            "Reading the ledger first.\n# Maintenance review · myserver\n\n## Now\n- web: plan 1.5.2\n\n\
             ```sentry-tasks\n[[task]]\nid = \"web\"\ntitle = \"Plan web\"\nlevel = \"now\"\n\
             do = \"plan web\"\n```",
            &known,
        );
        assert!(d.body.starts_with("# Maintenance review"));
        assert!(!d.body.contains("sentry-tasks"));
        assert_eq!(d.head.status, PlanStatus::Ready);
        assert_eq!(d.open().len(), 1);
        assert_eq!(
            d.head.suggest[0].task.review.as_deref(),
            Some(d.file_name().as_str())
        );
        assert_eq!(ReviewDoc::parse(&d.to_md()).unwrap(), d);
        d.mark("web", SugState::Added);
        assert!(d.open().is_empty());
        assert_eq!(ReviewDoc::parse(&d.to_md()).unwrap(), d);
    }
}

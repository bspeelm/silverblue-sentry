//! Maintenance reviews: Claude looks over everything tracked, what discovery found, the
//! ledger and upstream, and writes what to maintain next and why. Saved as
//! `reviews/<YYYY-MM-DD-HHMM>.md` under [`super::root`] (a `+++` TOML header, then Markdown).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::plan::PlanStatus;
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

    /// Claude's answer: the review, from its title on (before it: Claude saying what it reads).
    pub fn take_answer(&mut self, answer: &str) {
        let lines: Vec<&str> = answer.lines().collect();
        let start = lines
            .iter()
            .position(|l| l.trim_start().starts_with('#'))
            .unwrap_or(0);
        self.body = lines[start..].join("\n").trim().to_string();
        self.head.status = PlanStatus::Ready;
        self.head.updated = Some(jiff::Timestamp::now());
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
        d.take_answer("Reading the ledger first.\n# Maintenance review · myserver\n\n## Now\n- web: plan 1.5.2");
        assert!(d.body.starts_with("# Maintenance review"));
        assert_eq!(d.head.status, PlanStatus::Ready);
        assert_eq!(ReviewDoc::parse(&d.to_md()).unwrap(), d);
    }
}

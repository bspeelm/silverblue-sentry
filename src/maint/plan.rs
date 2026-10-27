//! Execution plans as Markdown files: `plans/<item>.md` under [`super::root`], a
//! TOML header (`+++`) that says how to apply it (target, workflow and its vars, status),
//! then the plan Claude wrote. Applied plans move to `plans/done/`. Local only, never in git.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanStatus {
    /// Claude is writing it.
    #[default]
    Writing,
    /// Written: it can be applied.
    Ready,
    /// Claude advises not to move it now.
    Wait,
    /// Writing it failed (the body says why).
    Failed,
    /// Applied: its workflow ran to the end.
    Done,
    /// Dropped without applying it.
    Dropped,
}

impl PlanStatus {
    pub fn word(self) -> &'static str {
        match self {
            PlanStatus::Writing => "writing",
            PlanStatus::Ready => "ready",
            PlanStatus::Wait => "wait",
            PlanStatus::Failed => "failed",
            PlanStatus::Done => "done",
            PlanStatus::Dropped => "dropped",
        }
    }
}

/// The header: everything needed to apply the plan later.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Head {
    pub item: String,
    /// The server it's for (empty: this machine).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server: String,
    pub status: PlanStatus,
    /// What it was when planned, and what it moves to (none: retiring it, or not decided).
    pub from: Option<String>,
    pub to: Option<String>,
    pub workflow: String,
    /// The workflow's vars, filled in from the item and the target.
    pub vars: BTreeMap<String, String>,
    /// The pinned image's repository (the image var follows the target).
    pub repo: Option<String>,
    pub note: Option<String>,
    pub created: Option<jiff::Timestamp>,
    pub updated: Option<jiff::Timestamp>,
    /// Claude's session, so a revision continues where the plan was written.
    pub session: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PlanDoc {
    pub head: Head,
    /// The plan itself, Markdown.
    pub body: String,
}

const FENCE: &str = "+++";

impl PlanDoc {
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
        let head: Head = toml::from_str(&rest[..end]).map_err(|e| e.to_string())?;
        let body = rest[end + 1 + FENCE.len()..].trim().to_string();
        Ok(Self { head, body })
    }

    /// Take Claude's answer: its `TARGET:` line sets the target (or "wait"); the rest is the
    /// body. The image var follows the target, written the way the pin is.
    pub fn take_answer(&mut self, answer: &str) {
        let target = target(answer);
        let body: Vec<&str> = answer.lines().filter(|l| !is_target_line(l)).collect();
        // Anything before the plan's title is Claude talking, not the plan.
        let start = body
            .iter()
            .position(|l| l.trim_start().starts_with('#'))
            .unwrap_or(0);
        self.body = body[start..].join("\n").trim().to_string();
        self.head.updated = Some(jiff::Timestamp::now());
        match target {
            Some(None) => self.head.status = PlanStatus::Wait,
            Some(Some(t)) => {
                self.head.status = PlanStatus::Ready;
                if self.head.vars.contains_key("service") {
                    let tag =
                        crate::server::maint::version::like_pin(&t, self.head.from.as_deref());
                    if let Some(repo) = &self.head.repo {
                        self.head
                            .vars
                            .insert("image".into(), format!("{repo}:{tag}"));
                    }
                    self.head.to = Some(tag);
                }
            }
            // No TARGET line: keep what was chosen; the plan is still a plan.
            None => self.head.status = PlanStatus::Ready,
        }
    }
}

/// The version Claude chose: its `TARGET:` line (`Some(None)` for `wait`; None without one).
pub fn target(text: &str) -> Option<Option<String>> {
    let line = text.lines().find(|l| is_target_line(l))?;
    let t = line
        .split_once(':')
        .map_or("", |(_, v)| v)
        .trim()
        .trim_matches(|c: char| c == '*' || c == '`' || c.is_whitespace());
    Some((!t.eq_ignore_ascii_case("wait") && !t.is_empty()).then(|| t.to_string()))
}

fn is_target_line(l: &str) -> bool {
    l.trim()
        .trim_matches(|c| c == '*' || c == '`' || c == '#')
        .trim()
        .to_ascii_uppercase()
        .starts_with("TARGET:")
}

pub fn dir(server: &str) -> PathBuf {
    super::root(server).join("plans")
}

pub fn path(server: &str, item: &str) -> PathBuf {
    dir(server).join(format!("{item}.md"))
}

pub fn save(doc: &PlanDoc) -> anyhow::Result<PathBuf> {
    let p = path(&doc.head.server, &doc.head.item);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    paths::write_atomic(&p, doc.to_md().as_bytes())?;
    Ok(p)
}

/// The open plans, by item (files that don't parse are skipped).
pub fn list(server: &str) -> BTreeMap<String, PlanDoc> {
    read_dir_md(&dir(server))
}

fn read_dir_md(d: &Path) -> BTreeMap<String, PlanDoc> {
    std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .filter_map(|p| PlanDoc::parse(&std::fs::read_to_string(&p).ok()?).ok())
        .map(|d| (d.head.item.clone(), d))
        .collect()
}

/// Done with it (applied or dropped): it moves to `plans/done/<item>-<when>.md`.
pub fn close(doc: &PlanDoc, status: PlanStatus) -> anyhow::Result<PathBuf> {
    let mut doc = doc.clone();
    doc.head.status = status;
    doc.head.updated = Some(jiff::Timestamp::now());
    let stamp = jiff::Zoned::now().strftime("%Y%m%d-%H%M%S").to_string();
    let d = dir(&doc.head.server).join("done");
    std::fs::create_dir_all(&d)?;
    let to = d.join(format!("{}-{stamp}.md", doc.head.item));
    paths::write_atomic(&to, doc.to_md().as_bytes())?;
    let _ = std::fs::remove_file(path(&doc.head.server, &doc.head.item));
    Ok(to)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> PlanDoc {
        PlanDoc {
            head: Head {
                item: "web".into(),
                server: "myserver".into(),
                from: Some("1.4.2".into()),
                workflow: "compose-bump".into(),
                vars: [("service".to_string(), "web".to_string())].into(),
                repo: Some("example/web".into()),
                note: Some("after Saturday's backup".into()),
                ..Default::default()
            },
            body: String::new(),
        }
    }

    #[test]
    fn claudes_answer_becomes_the_plan() {
        let mut d = doc();
        d.take_answer(
            "Here's the plan.\n\n**TARGET: v1.5.2**\n\n# Plan: web 1.4.2 → 1.5.2\n\n## Before\n```sh\nsudo true\n```\n",
        );
        assert_eq!(d.head.status, PlanStatus::Ready);
        assert_eq!(d.head.to.as_deref(), Some("1.5.2"), "written like the pin");
        assert_eq!(d.head.vars["image"], "example/web:1.5.2");
        assert!(d.body.starts_with("# Plan: web"), "{}", d.body);
        assert!(!d.body.contains("TARGET") && !d.body.contains("Here's the plan"));
        let mut w = doc();
        w.take_answer("TARGET: wait\n# Plan: web\nNot until 1.5.3.");
        assert_eq!(w.head.status, PlanStatus::Wait);
    }

    #[test]
    fn the_file_round_trips() {
        let mut d = doc();
        d.take_answer("TARGET: 1.5.2\n# Plan\n\n+++ not a header +++\n\n## Verify\n- it's up");
        let back = PlanDoc::parse(&d.to_md()).unwrap();
        assert_eq!(back, d);
        assert!(d.to_md().starts_with("+++\nitem = \"web\""));
    }
}

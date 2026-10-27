//! Deliberate maintenance: what's pinned or held on purpose (`maintenance:` in
//! server_config.yaml), what's newer upstream, and when to look again. Nothing here changes
//! the server: changes go through a workflow, one item at a time.

pub mod discover;
pub mod eval;
pub mod local;
pub mod log;
pub mod plan;
pub mod recommend;
pub mod review;
pub mod tracked;
pub mod upstream;
pub mod version;

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::paths;

/// What sentry-server writes itself, next to the config (never in it): review dates moved
/// with `z`, saved plans (`p`) and the last assessment of each item (`A`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub snooze: BTreeMap<String, jiff::civil::Date>,
    pub plans: BTreeMap<String, Plan>,
    pub assessments: BTreeMap<String, Assessment>,
}

/// A change decided on but not made yet: kept until it's run to the end or dropped.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Plan {
    /// What it was when planned.
    pub from: Option<String>,
    /// The version to move to (none: retiring it).
    pub to: Option<String>,
    pub workflow: String,
    /// The workflow's vars, filled in from the item.
    pub vars: BTreeMap<String, String>,
    pub note: Option<String>,
    pub created: Option<jiff::Timestamp>,
    /// The pinned image's repository (for the image var when Claude picks the version).
    pub repo: Option<String>,
    /// Claude's execution plan: assessment, before, change, verify, roll back, when.
    pub text: String,
    /// Claude advised not to move it now.
    pub wait: bool,
    /// Claude's conversation, to resume when it's opened again (`o`).
    pub session: Option<String>,
}

/// Claude's last assessment of an item.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Assessment {
    pub at: Option<jiff::Timestamp>,
    pub text: String,
}

fn state_path(server: &str) -> PathBuf {
    paths::config_dir()
        .join("servers")
        .join(format!("{server}.maint.toml"))
}

pub fn load_state(server: &str) -> State {
    std::fs::read_to_string(state_path(server))
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

/// Change the state file (read, change, write back).
fn update(server: &str, f: impl FnOnce(&mut State)) -> anyhow::Result<()> {
    let mut st = load_state(server);
    f(&mut st);
    let text = format!(
        "# Written by sentry-server's Maintenance tab: review dates (z), plans (p), assessments (A).\n\
         # Edit freely.\n{}",
        toml::to_string(&st)?
    );
    paths::write_atomic(&state_path(server), text.as_bytes())?;
    Ok(())
}

/// Move an item's review date (`z`).
pub fn snooze(server: &str, id: &str, until: jiff::civil::Date) -> anyhow::Result<()> {
    update(server, |st| {
        st.snooze.insert(id.to_string(), until);
    })
}

/// Save (or replace) an item's plan.
pub fn save_plan(server: &str, id: &str, plan: Plan) -> anyhow::Result<()> {
    update(server, |st| {
        st.plans.insert(id.to_string(), plan);
    })
}

pub fn drop_plan(server: &str, id: &str) -> anyhow::Result<()> {
    update(server, |st| {
        st.plans.remove(id);
    })
}

/// After the old plans became files.
fn clear_old_plans(server: &str) -> anyhow::Result<()> {
    update(server, |st| st.plans.clear())
}

pub fn save_assessment(server: &str, id: &str, text: &str) -> anyhow::Result<()> {
    update(server, |st| {
        st.assessments.insert(
            id.to_string(),
            Assessment {
                at: Some(jiff::Timestamp::now()),
                text: text.to_string(),
            },
        );
    })
}

/// One change made through a workflow started from an item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub at: jiff::Timestamp,
    pub item: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub workflow: String,
    /// `done`, `abandoned`, `failed`.
    pub result: String,
}

/// An item's changes, newest first (from the maintenance log).
pub fn history(server: &str, item: &str) -> Vec<Change> {
    log::for_item(server, item)
        .into_iter()
        .map(|e| Change {
            at: e.head.ended.or(e.head.started).unwrap_or_default(),
            item: item.to_string(),
            from: e.head.from,
            to: e.head.to,
            workflow: e.head.workflow,
            result: e.head.result,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_with_plans_and_long_assessments() {
        let mut st = State::default();
        st.snooze
            .insert("web".into(), jiff::civil::date(2027, 1, 1));
        st.plans.insert(
            "web".into(),
            Plan {
                from: Some("1.4.2".into()),
                to: Some("v1.5.2".into()),
                workflow: "compose-bump".into(),
                vars: [("service".to_string(), "web".to_string())].into(),
                note: Some("after the backup on Saturday".into()),
                created: Some("2026-10-27T10:00:00Z".parse().unwrap()),
                repo: Some("example/web".into()),
                text: "TARGET: v1.5.2\n**Before**: \"back up\"".into(),
                wait: false,
                session: None,
            },
        );
        st.assessments.insert(
            "web".into(),
            Assessment {
                at: None,
                text: "**What changed**\n- a \"quoted\" line\n\n**Recommendation**: wait".into(),
            },
        );
        let back: State = toml::from_str(&toml::to_string(&st).unwrap()).unwrap();
        assert_eq!(back, st);
    }
}

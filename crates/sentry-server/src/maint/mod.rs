//! Deliberate maintenance: what's pinned or held on purpose (`maintenance:` in
//! server_config.yaml), what's newer upstream, and when to look again. Nothing here changes
//! the server: changes go through a workflow, one item at a time.

pub mod discover;
pub mod eval;
pub mod local;
pub use sentry_core::maint::{log, plan, review, version};
pub mod recommend;
pub mod tracked;
pub mod upstream;

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use sentry_core::maint::tasks::Task;
use sentry_core::paths;

/// The old state file next to the config: plans from before plans were files (migrated,
/// then cleared). Review dates moved with `z` are in `later.toml` now (`maint::later`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub plans: BTreeMap<String, Plan>,
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
        "# Written by sentry-server (old plans, before plans were files).\n\
         # Edit freely.\n{}",
        toml::to_string(&st)?
    );
    paths::write_atomic(&state_path(server), text.as_bytes())?;
    Ok(())
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

/// `maintenance.cadence` as recurring tasks (`cadence-<workflow>`), for the workflows this
/// server has. `tasks.toml` can replace one with the same id.
pub fn cadence_tasks(cfg: &crate::config::Server, workflows: &[String]) -> Vec<Task> {
    cfg.maintenance
        .cadence
        .iter()
        .filter(|(wf, _)| workflows.contains(wf))
        .map(|(wf, every)| Task {
            id: format!("cadence-{wf}"),
            title: format!("Run {wf}"),
            why: "Routine (maintenance.cadence in server_config.yaml).".into(),
            level: sentry_core::maint::Level::Routine,
            every: Some(*every),
            act: format!("run {wf}"),
            item: None,
            steps: String::new(),
            added: None,
            off: false,
            source: sentry_core::maint::tasks::Source::Config,
            review: None,
            after: None,
        })
        .collect()
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

/// An item's changes, newest first (from the maintenance log, newest first).
pub fn history(log: &[log::LogEntry], item: &str) -> Vec<Change> {
    log.iter()
        .filter(|e| e.head.item.as_deref() == Some(item))
        .cloned()
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

/// Plans kept in the old state file (before plans were files) become files.
pub fn migrate_plans(server: &str) {
    let st = load_state(server);
    if st.plans.is_empty() {
        return;
    }
    for (item, p) in &st.plans {
        if plan::path(server, item).exists() {
            continue;
        }
        let mut doc = plan::PlanDoc {
            head: plan::Head {
                item: item.clone(),
                server: server.to_string(),
                from: p.from.clone(),
                to: p.to.clone(),
                workflow: p.workflow.clone(),
                vars: p.vars.clone(),
                repo: p.repo.clone(),
                note: p.note.clone(),
                created: p.created,
                session: p.session.clone(),
                ..Default::default()
            },
            body: String::new(),
        };
        let (to, vars) = (doc.head.to.clone(), doc.head.vars.clone());
        doc.take_answer(&p.text);
        // The old plan's own target and vars stand.
        doc.head.to = to;
        doc.head.vars = vars;
        if p.wait {
            doc.head.status = plan::PlanStatus::Wait;
        }
        let _ = plan::save(&doc);
    }
    let _ = clear_old_plans(server);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_with_old_plans() {
        let mut st = State::default();
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
        let back: State = toml::from_str(&toml::to_string(&st).unwrap()).unwrap();
        assert_eq!(back, st);
    }
}

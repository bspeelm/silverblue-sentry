//! Run directories (spec §9.3): `~/.local/share/sentry/workflows/<name>/run-<ts>/` holding
//! `state.json`, a frozen copy of the workflow (`workflow.toml`) and `steps/<id>.log`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::paths;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    InProgress,
    Done,
    Abandoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    /// Command running, or (reboot) reboot requested and not yet observed.
    Running,
    Ok,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StepState {
    pub id: String,
    pub status: StepStatus,
    #[serde(default)]
    pub code: Option<i32>,
    #[serde(default)]
    pub started: Option<Timestamp>,
    #[serde(default)]
    pub ended: Option<Timestamp>,
    /// Boot id when the step last changed (reboot detection, spec §9.3).
    #[serde(default)]
    pub boot_id: Option<String>,
    /// The rpm-ostree dry-run sibling has succeeded.
    #[serde(default)]
    pub dry_ok: bool,
    /// Why it was skipped (`when !kernel_changed`, `skipped by user`).
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunState {
    pub workflow: String,
    pub status: RunStatus,
    pub started: Timestamp,
    #[serde(default)]
    pub ended: Option<Timestamp>,
    /// User vars plus built-ins frozen so far.
    pub vars: BTreeMap<String, String>,
    /// `when` conditions, frozen at first evaluation.
    pub conds: BTreeMap<String, bool>,
    pub steps: Vec<StepState>,
}

impl RunState {
    pub fn new(workflow: &str, ids: &[String], vars: BTreeMap<String, String>) -> Self {
        Self {
            workflow: workflow.into(),
            status: RunStatus::InProgress,
            started: Timestamp::now(),
            ended: None,
            vars,
            conds: BTreeMap::new(),
            steps: ids
                .iter()
                .map(|id| StepState {
                    id: id.clone(),
                    status: StepStatus::Pending,
                    code: None,
                    started: None,
                    ended: None,
                    boot_id: None,
                    dry_ok: false,
                    note: None,
                })
                .collect(),
        }
    }

    pub fn done_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| matches!(s.status, StepStatus::Ok | StepStatus::Skipped))
            .count()
    }
}

pub fn root() -> PathBuf {
    paths::data_dir().join("workflows")
}

#[derive(Debug, Clone)]
pub struct Run {
    pub dir: PathBuf,
    pub state: RunState,
}

impl Run {
    pub fn create(name: &str, toml_text: &str, state: RunState) -> anyhow::Result<Self> {
        let stamp = state
            .started
            .to_zoned(jiff::tz::TimeZone::system())
            .strftime("%Y%m%d-%H%M%S")
            .to_string();
        let base = root().join(name);
        let mut dir = base.join(format!("run-{stamp}"));
        let mut n = 2;
        while dir.exists() {
            dir = base.join(format!("run-{stamp}-{n}"));
            n += 1;
        }
        std::fs::create_dir_all(dir.join("steps"))?;
        paths::write_atomic(&dir.join("workflow.toml"), toml_text.as_bytes())?;
        let r = Self { dir, state };
        r.save()?;
        Ok(r)
    }

    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(dir.join("state.json"))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            state: serde_json::from_str(&text)?,
        })
    }

    pub fn save(&self) -> anyhow::Result<()> {
        paths::write_atomic(
            &self.dir.join("state.json"),
            &serde_json::to_vec_pretty(&self.state)?,
        )?;
        Ok(())
    }

    pub fn log_path(&self, id: &str) -> PathBuf {
        self.dir.join("steps").join(format!("{id}.log"))
    }

    pub fn append_log(&self, id: &str, line: &str) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_path(id))
        {
            let _ = writeln!(f, "{line}");
        }
    }

    /// The frozen workflow copy taken at start.
    pub fn workflow_text(&self) -> anyhow::Result<String> {
        Ok(std::fs::read_to_string(self.dir.join("workflow.toml"))?)
    }
}

/// All runs of a workflow, oldest first.
pub fn runs_of(name: &str) -> Vec<Run> {
    let mut v: Vec<Run> = std::fs::read_dir(root().join(name))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("run-"))
        .filter_map(|e| Run::load(&e.path()).ok())
        .collect();
    v.sort_by_key(|r| r.state.started);
    v
}

/// The (single) run still in progress, across all workflows.
pub fn in_progress() -> Option<Run> {
    std::fs::read_dir(root())
        .ok()?
        .flatten()
        .flat_map(|wf| runs_of(&wf.file_name().to_string_lossy()))
        .filter(|r| r.state.status == RunStatus::InProgress)
        .max_by_key(|r| r.state.started)
}

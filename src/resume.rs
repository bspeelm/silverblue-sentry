//! Startup resume hook (spec §9.3). Workflows arrive in milestone 5; until then this only
//! looks for run directories so the UI and `sentry status` have a stable seam to call.

use crate::paths;

pub struct InProgress {
    pub workflow: String,
    pub run_dir: std::path::PathBuf,
}

impl InProgress {
    pub fn summary(&self) -> String {
        format!("{} ({})", self.workflow, self.run_dir.display())
    }
}

/// Find a workflow run whose state.json says it's still in progress.
pub fn in_progress() -> Option<InProgress> {
    let root = paths::data_dir().join("workflows");
    for wf in std::fs::read_dir(root).ok()?.flatten() {
        for run in std::fs::read_dir(wf.path()).ok()?.flatten() {
            let state = std::fs::read_to_string(run.path().join("state.json")).ok()?;
            let v: serde_json::Value = serde_json::from_str(&state).ok()?;
            if v["status"].as_str() == Some("in_progress") {
                return Some(InProgress {
                    workflow: wf.file_name().to_string_lossy().into(),
                    run_dir: run.path(),
                });
            }
        }
    }
    None
}

/// Called once at TUI startup. No-op until milestone 5 beyond discovery.
pub fn check() -> Option<InProgress> {
    in_progress()
}

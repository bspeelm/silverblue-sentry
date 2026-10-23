//! Startup resume hook (spec §9.3): the in-progress workflow run, if any.

pub struct InProgress {
    pub workflow: String,
    pub run_dir: std::path::PathBuf,
}

impl InProgress {
    pub fn summary(&self) -> String {
        format!("{} ({})", self.workflow, self.run_dir.display())
    }
}

/// The workflow run whose state.json says it's still in progress.
pub fn in_progress() -> Option<InProgress> {
    crate::workflows::state::in_progress().map(|r| InProgress {
        workflow: r.state.workflow,
        run_dir: r.dir,
    })
}

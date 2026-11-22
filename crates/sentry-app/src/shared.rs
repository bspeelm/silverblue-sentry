//! A target's records, the same for every kind of host: what `maint::root(scope)` holds, read
//! at start and after each change, never while drawing. The flows in [`crate::slot`] write
//! them; a target reads them for its lists.

use std::collections::BTreeMap;

use sentry_core::baseline::BaselineFile;
use sentry_core::maint::later::Snoozes;
use sentry_core::maint::log::LogEntry;
use sentry_core::maint::plan::PlanDoc;
use sentry_core::maint::review::ReviewDoc;
use sentry_core::maint::tasks::Task;
use sentry_core::tui::wflist::WfInfo;
use sentry_core::workflows::Entry;

#[derive(Default)]
pub struct Shared {
    /// What's marked expected (`baseline.toml`).
    pub baseline: BaselineFile,
    /// What's put off with `z`, and items' review dates (`later.toml`).
    pub later: Snoozes,
    /// Open plans, by item (`plans/<item>.md`).
    pub plans: BTreeMap<String, PlanDoc>,
    /// The maintenance log, newest first (for cadences).
    pub log: Vec<LogEntry>,
    /// The latest maintenance review.
    pub review: Option<ReviewDoc>,
    /// Tasks taken from reviews (`tasks.toml`).
    pub tasks: Vec<Task>,
    /// The target's workflow names.
    pub workflows: Vec<String>,
    /// The workflows there are (a host's own, else the seeded ones).
    pub wf_entries: Vec<Entry>,
    /// The same, each with its last run (screen 0's list).
    pub wf_list: Vec<WfInfo>,
    /// Where they come from (shown with the run).
    pub wf_dir: String,
    /// When the security audit last ran (the window's; its task is this machine's).
    pub sec_last: Option<jiff::Timestamp>,
    /// The security audit's items this target lists (`secaudit::mine`): to do first, worth
    /// doing, asked. The app's copy of what is the window's, kept as the report changes.
    pub sec: Vec<sentry_core::secaudit::Item>,
}

impl Shared {
    /// A workflow for Claude: what it does and its steps, in order.
    pub fn workflow_text(&self, app: &str, wf: &str) -> String {
        match self.wf_entries.iter().find(|e| e.name == wf).map(|e| &e.wf) {
            Some(Ok(w)) => {
                let steps: Vec<String> = w
                    .steps
                    .iter()
                    .enumerate()
                    .map(|(i, s)| format!("  {}. {} ({})", i + 1, s.title, s.id))
                    .collect();
                format!(
                    "{app}'s workflow `{wf}`: {}\nIts steps:\n{}",
                    w.description,
                    steps.join("\n")
                )
            }
            _ => format!("{app}'s workflow `{wf}`."),
        }
    }
}

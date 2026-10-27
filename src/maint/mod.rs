//! Maintenance records both programs keep: the log and its ledger, Claude's plans and
//! reviews, and how long they're kept. This machine's live under `~/.config/sentry/`, a
//! server's under `~/.config/sentry/servers/<name>/`. Local only, never in git.

pub mod local;
pub mod log;
pub mod plan;
pub mod retention;
pub mod review;
pub mod snooze;

use std::path::PathBuf;

use crate::paths;

/// The `server` that means this machine.
pub const LOCAL: &str = "";

/// Where a server's records live (`LOCAL`: this machine's).
pub fn root(server: &str) -> PathBuf {
    if server.is_empty() {
        paths::config_dir()
    } else {
        paths::config_dir().join("servers").join(server)
    }
}

/// How records name it.
pub fn label(server: &str) -> &str {
    if server.is_empty() {
        "this machine"
    } else {
        server
    }
}

/// A path with its symlinks resolved, even when its end doesn't exist yet (nothing is created).
pub fn real_path(p: &std::path::Path) -> String {
    let mut base = p.to_path_buf();
    let mut rest = Vec::new();
    while !base.exists() {
        match (base.file_name().map(|n| n.to_owned()), base.parent()) {
            (Some(n), Some(parent)) => {
                rest.push(n);
                base = parent.to_path_buf();
            }
            _ => break,
        }
    }
    let mut real = std::fs::canonicalize(&base).unwrap_or(base);
    for n in rest.into_iter().rev() {
        real.push(n);
    }
    real.display().to_string()
}

/// Notes paths as Claude Code sees them: `~` expanded and symlinks resolved (its permission
/// checks use the real path).
pub fn resolve_notes(notes: &[String]) -> Vec<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    notes
        .iter()
        .map(|n| {
            let p = match n.strip_prefix("~/") {
                Some(rest) => format!("{home}/{rest}"),
                None => n.clone(),
            };
            std::fs::canonicalize(&p)
                .map(|c| c.display().to_string())
                .unwrap_or(p)
        })
        .collect()
}

/// Notes files as Claude Code `Read(…)` permissions (`~/…` as is, `/abs` as `//abs`).
pub fn read_rules(notes: &[String]) -> Vec<String> {
    notes
        .iter()
        .map(|n| match n.strip_prefix('/') {
            Some(abs) => format!("Read(//{abs})"),
            None => format!("Read({n})"),
        })
        .collect()
}

/// How soon a recommendation should be acted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Now,
    Soon,
    Routine,
    Tidy,
}

impl Level {
    pub fn word(self) -> &'static str {
        match self {
            Level::Now => "now",
            Level::Soon => "soon",
            Level::Routine => "routine",
            Level::Tidy => "tidy",
        }
    }
}

//! Maintenance records both programs keep: the log and its ledger, Claude's plans and
//! reviews, the tasks you took from reviews, and how long they're kept. This machine's live under `~/.config/sentry/`, a
//! server's under `~/.config/sentry/servers/<name>/`. Local only, never in git.

pub mod later;
pub mod log;
pub mod plan;
pub mod rec;
pub mod retention;
pub mod review;
pub mod tasks;
pub mod version;

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

/// A fenced block whose opening line starts with `fence` (```` ```sentry-tasks ````) taken out
/// of an answer: (the answer without it, the block's text). The closing fence is the first
/// one outside a TOML multi-line string, since a string may hold Markdown with fences of its
/// own.
pub fn fenced_block(answer: &str, fence: &str) -> Option<(String, String)> {
    let lines: Vec<&str> = answer.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.trim_start().starts_with(fence))?;
    let mut quoted = false;
    let end = lines[start + 1..]
        .iter()
        .position(|l| {
            let closes = !quoted && l.trim() == "```";
            if l.matches("\"\"\"").count() % 2 == 1 {
                quoted = !quoted;
            }
            closes
        })
        .map_or(lines.len(), |n| start + 1 + n);
    let block = lines[start + 1..end].join("\n");
    let rest: Vec<&str> = lines[..start]
        .iter()
        .chain(lines.get(end + 1..).unwrap_or_default())
        .copied()
        .collect();
    Some((rest.join("\n").trim().to_string(), block))
}

/// How soon a recommendation should be acted on.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
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

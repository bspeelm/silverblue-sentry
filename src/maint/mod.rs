//! Maintenance records both programs keep: the log and its ledger, Claude's plans and
//! reviews, and how long they're kept. This machine's live under `~/.config/sentry/`, a
//! server's under `~/.config/sentry/servers/<name>/`. Local only, never in git.

pub mod log;
pub mod plan;
pub mod retention;
pub mod review;

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

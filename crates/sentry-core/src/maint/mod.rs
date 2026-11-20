//! Maintenance records both programs keep: the log and its ledger, Claude's plans and
//! reviews, the tasks you took from reviews, and how long they're kept. This machine's live under `~/.config/sentry/`, a
//! server's under `~/.config/sentry/servers/<name>/`, a network's (scope `net:<name>`) under
//! `~/.config/sentry/networks/<name>/`. Local only, never in git.

pub mod changes;
pub mod later;
pub mod log;
pub mod plan;
pub mod rec;
pub mod retention;
pub mod review;
pub mod series;
pub mod tasks;
pub mod version;

use std::path::PathBuf;

use crate::paths;

/// The `server` that means this machine.
pub const LOCAL: &str = "";

/// What starts a network's scope (`net:<name>`); a plain name is a server's.
pub const NET: &str = "net:";

/// A scope's directory under the config or the data dir: `servers/<name>`, or
/// `networks/<name>` for `net:<name>`. None for this machine, whose files lie at the top.
fn dir_of(scope: &str) -> Option<PathBuf> {
    match scope.strip_prefix(NET) {
        _ if scope.is_empty() => None,
        Some(name) => Some(PathBuf::from("networks").join(name)),
        None => Some(PathBuf::from("servers").join(scope)),
    }
}

fn under(base: PathBuf, scope: &str) -> PathBuf {
    match dir_of(scope) {
        Some(d) => base.join(d),
        None => base,
    }
}

/// Where a server's or a network's records live (`LOCAL`: this machine's).
pub fn root(server: &str) -> PathBuf {
    under(paths::config_dir(), server)
}

/// Where its data lives (reports, workflow runs, metrics).
pub fn data_root(server: &str) -> PathBuf {
    under(paths::data_dir(), server)
}

/// A file from before a server had a directory of its own: `servers/<name><suffix>`, beside
/// where that directory is now. None for this machine.
pub fn beside(server: &str, suffix: &str) -> Option<PathBuf> {
    let root = root(server);
    let name = dir_of(server)?.file_name()?.to_string_lossy().to_string();
    Some(root.with_file_name(format!("{name}{suffix}")))
}

/// How records name it.
pub fn label(server: &str) -> &str {
    if server.is_empty() {
        "this machine"
    } else {
        server.strip_prefix(NET).unwrap_or(server)
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

/// A fenced block whose opening line starts with `fence` (```` ```sentry-changes ````) taken out
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::{config_dir, data_dir};

    #[test]
    fn a_scope_has_one_directory_for_its_records_and_its_data() {
        // This machine: the top of each.
        assert_eq!(root(LOCAL), config_dir());
        assert_eq!(data_root(LOCAL), data_dir());
        assert_eq!(beside(LOCAL, ".maint.toml"), None);
        // A plain name is a server, where it always was.
        assert_eq!(root("myserver"), config_dir().join("servers/myserver"));
        assert_eq!(data_root("myserver"), data_dir().join("servers/myserver"));
        assert_eq!(
            beside("my.server", ".baseline.toml"),
            Some(config_dir().join("servers/my.server.baseline.toml"))
        );
        // `net:<name>` is a network.
        assert_eq!(root("net:home"), config_dir().join("networks/home"));
        assert_eq!(data_root("net:home"), data_dir().join("networks/home"));
        assert_eq!(
            crate::recorder::ring::path("net:home"),
            data_dir().join("networks/home/metrics/ring.bin")
        );
        assert_eq!(
            crate::baseline::path("net:home"),
            config_dir().join("networks/home/baseline.toml")
        );
        // A server and a network of one name don't share anything.
        assert_ne!(root("home"), root("net:home"));
    }

    #[test]
    fn a_label_is_the_name_without_its_kind() {
        assert_eq!(label(LOCAL), "this machine");
        assert_eq!(label("myserver"), "myserver");
        assert_eq!(label("net:home"), "home");
    }
}

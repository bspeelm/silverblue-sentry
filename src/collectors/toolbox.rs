//! Package updates inside toolbox/distrobox containers (`dnf check-update` via `podman exec`).
//! Network-bound and slow, so it runs only on request and is cached by the caller. Stopped
//! containers are started for the check and stopped again afterwards.

use std::collections::{BTreeMap, HashMap};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::podman::{self, Kind};
use super::{CResult, Ctx};
use crate::exec::Cmd;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PkgUpdate {
    /// `name.arch`
    pub name: String,
    pub old: Option<String>,
    pub new: String,
    pub repo: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoxUpdates {
    pub checked_at: Timestamp,
    pub updates: Vec<PkgUpdate>,
    /// `Some("not dnf")` for containers without dnf; other text for failures.
    pub error: Option<String>,
}

pub type ToolboxUpdates = BTreeMap<String, BoxUpdates>;

const SCRIPT: &str = "command -v dnf >/dev/null || exit 127; \
    dnf -q check-update 2>/dev/null; echo \"__RC=$?\"; \
    rpm -qa --qf '%{NAME}.%{ARCH} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n'";

/// `2:9.2-1` stays; `0:3.8-1` → `3.8-1` (dnf omits a zero epoch).
fn drop_zero_epoch(v: &str) -> &str {
    v.strip_prefix("0:").unwrap_or(v)
}

/// The output of `SCRIPT`: check-update rows, `__RC=<code>`, then installed versions.
/// Returns the updates and dnf's exit code (100 = updates, 0 = none).
pub fn parse_exec(text: &str) -> (Vec<PkgUpdate>, Option<i32>) {
    let (check, installed) = match text.split_once("__RC=") {
        Some((c, rest)) => (c, rest),
        None => (text, ""),
    };
    let mut lines = installed.lines();
    let rc = lines.next().and_then(|l| l.trim().parse().ok());
    let have: HashMap<&str, &str> = lines
        .filter_map(|l| l.split_once(' '))
        .map(|(n, v)| (n, drop_zero_epoch(v.trim())))
        .collect();
    let mut out = Vec::new();
    for l in check.lines() {
        // dnf lists obsoletes after a header, each followed by the package it replaces.
        if l.trim_start().starts_with("Obsoleting") {
            break;
        }
        let f: Vec<&str> = l.split_whitespace().collect();
        let [name, new, repo] = f.as_slice() else {
            continue;
        };
        if !name.contains('.') || repo.starts_with('@') {
            continue;
        }
        out.push(PkgUpdate {
            name: name.to_string(),
            old: have.get(name).map(|s| s.to_string()),
            new: drop_zero_epoch(new).to_string(),
            repo: repo.to_string(),
        });
    }
    (out, rc)
}

/// Check one container. `running`: leave its state alone; otherwise start and stop it,
/// remembering its real exit time (`exited_at`) so it doesn't stop looking stale.
pub fn check_one(name: &str, running: bool, exited_at: Option<i64>) -> BoxUpdates {
    let now = Timestamp::now;
    if !running && let Err(e) = Cmd::host("podman").args(["start", name]).run() {
        return BoxUpdates {
            checked_at: now(),
            updates: Vec::new(),
            error: Some(format!("podman start: {e}")),
        };
    }
    let r = Cmd::host("podman")
        .args(["exec", name, "sh", "-c", SCRIPT])
        .timeout(Some(std::time::Duration::from_secs(180)))
        .run();
    if !running {
        let _ = Cmd::host("podman").args(["stop", "-t", "5", name]).run();
        if let Some(t) = exited_at {
            podman::remember_own_stop(name, t);
        }
    }
    let (updates, error) = match r {
        Err(e) => (Vec::new(), Some(e.to_string())),
        Ok(o) if o.code == 127 => (Vec::new(), Some("not dnf".into())),
        Ok(o) => match parse_exec(&o.stdout) {
            (u, Some(0 | 100)) => (u, None),
            (_, rc) => (
                Vec::new(),
                Some(format!(
                    "dnf check-update exit {}",
                    rc.map_or("?".into(), |c| c.to_string())
                )),
            ),
        },
    };
    BoxUpdates {
        checked_at: now(),
        updates,
        error,
    }
}

/// Every toolbox and distrobox container (plain podman containers update by image pull).
pub fn collect(ctx: &Ctx) -> CResult<ToolboxUpdates> {
    let p = podman::collect(ctx)?;
    Ok(p.containers
        .iter()
        .filter(|c| c.kind != Kind::Podman)
        .map(|c| (c.name.clone(), check_one(&c.name, c.running(), c.exited_at)))
        .collect())
}

/// Command that upgrades one container as root (no sudo, so no terminal needed), restoring a
/// stopped container's state afterwards.
pub fn upgrade_cmd(name: &str, running: bool) -> Cmd {
    if running {
        return Cmd::host("podman")
            .args(["exec", "--user", "root", name, "dnf", "-y", "upgrade"])
            .timeout(None);
    }
    let q = crate::workflows::runner::quote(name);
    Cmd::host("sh")
        .args([
            "-c",
            &format!(
                "podman start {q} >/dev/null && podman exec --user root {q} dnf -y upgrade; rc=$?; podman stop -t 5 {q} >/dev/null; exit $rc"
            ),
        ])
        .timeout(None)
}

/// Total pending across containers (tab badge, dashboard).
pub fn total(u: &ToolboxUpdates) -> usize {
    u.values().map(|b| b.updates.len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_fixture() {
        let (u, rc) = parse_exec(&super::super::fixture("toolbox/exec-output.txt"));
        assert_eq!(rc, Some(100));
        let names: Vec<&str> = u.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["systemd-shared.x86_64", "tmux.x86_64", "vim-minimal.x86_64"]
        );
        assert_eq!(
            u[0].old.as_deref(),
            Some("259.8-1.fc44"),
            "zero epoch dropped"
        );
        assert_eq!(u[2].old.as_deref(), Some("2:9.2.1100-1.fc44"));
        assert_eq!(u[2].new, "2:9.2.1202-1.fc44");
        assert_eq!(u[1].repo, "updates");
        let (none, rc) = parse_exec("__RC=0\nbash.x86_64 0:5.3-1.fc44\n");
        assert!(none.is_empty());
        assert_eq!(rc, Some(0));
    }
}

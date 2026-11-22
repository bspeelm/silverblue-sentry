//! A remote host's audit reports and what's marked expected: the storage and the rules that
//! don't depend on what kind of host it is. What a snapshot holds and how findings are
//! derived from it is each target's own. Reports go to
//! `~/.local/share/sentry/servers/<name>/reports/` (a network's under `networks/`); findings
//! marked expected go to the scope's `baseline.toml` (the Network screen's expected
//! listeners too).

use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use sentry_core::baseline::{BaselineFile, listener_entry_matches};
use sentry_core::collectors::net::{ListenStatus, Listener};
use sentry_core::finding::Finding;
use sentry_core::paths;

/// How many reports are kept.
pub const KEPT: usize = 200;

/// One audit: what was read (`S`, the target's snapshot) and what it found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report<S> {
    pub snapshot: S,
    pub findings: Vec<Finding>,
}

impl<S> Report<S> {
    pub fn open(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| !f.expected)
    }
}

/// The finding a listener open to the network gets (one per protocol and port), in the
/// target's namespace (`srv`).
pub fn listener_id(ns: &str, l: &Listener) -> String {
    format!("{ns}:listener:{}:{}", l.proto, l.port)
}

/// How a listening socket stands, for the audit and the Network screen alike: loopback is
/// local, DHCP's client sockets are clients, what the config's `listeners` or the baseline
/// file covers is expected, and the rest is new.
pub fn listener_status(l: &Listener, listeners: &[String], base: &BaselineFile) -> ListenStatus {
    if l.addr.starts_with("127.") || l.addr == "[::1]" || l.addr == "::1" {
        return ListenStatus::Local;
    }
    if l.proto == "udp" && (l.port == "68" || l.port == "546") {
        return ListenStatus::Ephemeral;
    }
    if listeners
        .iter()
        .chain(&base.listeners)
        .any(|p| listener_entry_matches(p, &l.key()))
    {
        return ListenStatus::Baseline;
    }
    ListenStatus::New
}

pub fn reports_dir(scope: &str) -> PathBuf {
    sentry_core::maint::data_root(scope).join("reports")
}

/// Set `expected` on findings as things stand now: what the config's patterns or the
/// baseline file cover is expected, the rest isn't. A stored report says what was expected
/// when it was written; whoever shows one marks it again with this first.
pub fn mark_expected(findings: &mut [Finding], config: &[String], base: &BaselineFile) {
    for f in findings {
        f.expected = config
            .iter()
            .chain(&base.findings)
            .any(|g| sentry_core::baseline::glob(g, &f.id));
    }
}

/// Mark a finding expected (or not) in a baseline; whether anything changed.
pub fn set_expected_in(b: &mut BaselineFile, id: &str, expected: bool) -> bool {
    if expected {
        !b.findings.iter().any(|x| x == id) && {
            b.findings.push(id.to_string());
            true
        }
    } else {
        let n = b.findings.len();
        b.findings.retain(|x| x != id);
        b.findings.len() != n
    }
}

/// Mark a finding expected (or not) in the scope's baseline file; returns whether anything
/// changed.
pub fn set_expected(scope: &str, id: &str, expected: bool) -> anyhow::Result<bool> {
    let mut b = BaselineFile::load(scope);
    let changed = set_expected_in(&mut b, id, expected);
    if changed {
        b.save(scope)?;
    }
    Ok(changed)
}

/// Every stored report's name (its file's, without `.json`), oldest first.
pub fn names(scope: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(reports_dir(scope))
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter_map(|p| Some(p.file_stem()?.to_string_lossy().to_string()))
        .collect();
    v.sort();
    v
}

/// One stored report, by name.
pub fn load<S: DeserializeOwned>(scope: &str, name: &str) -> Option<Report<S>> {
    let text = std::fs::read_to_string(reports_dir(scope).join(format!("{name}.json"))).ok()?;
    serde_json::from_str(&text).ok()
}

/// A report as the report view shows it: with the one before it, and where it is among
/// those kept.
#[derive(Debug, Clone)]
pub struct Shown<S> {
    pub names: Vec<String>,
    pub idx: usize,
    pub cur: Option<Box<Report<S>>>,
    pub prev: Option<Box<Report<S>>>,
}

impl<S> Default for Shown<S> {
    fn default() -> Self {
        Self {
            names: Vec::new(),
            idx: 0,
            cur: None,
            prev: None,
        }
    }
}

impl<S> Shown<S> {
    pub fn latest(&self) -> bool {
        self.idx + 1 >= self.names.len()
    }
}

/// The report at `idx` (None: the newest), read from disk.
pub fn shown<S: DeserializeOwned>(scope: &str, idx: Option<usize>) -> Shown<S> {
    let names = names(scope);
    let Some(last) = names.len().checked_sub(1) else {
        return Shown::default();
    };
    let idx = idx.unwrap_or(last).min(last);
    let at = |i: usize| load(scope, &names[i]).map(Box::new);
    Shown {
        cur: at(idx),
        prev: idx.checked_sub(1).and_then(at),
        idx,
        names,
    }
}

/// `B`: the pattern for every finding like this one (`<ns>:<kind>:*`), and what that is in
/// words. None for a finding that is the only one of its kind, or of another namespace.
pub fn pattern_for(ns: &str, id: &str) -> Option<(String, String)> {
    let rest = id.strip_prefix(ns)?.strip_prefix(':')?;
    let (kind, what) = rest.split_once(':')?;
    if what.is_empty() {
        return None;
    }
    Some((format!("{ns}:{kind}:*"), format!("every {kind} finding")))
}

/// The newest stored report.
pub fn latest<S: DeserializeOwned>(scope: &str) -> Option<Report<S>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(reports_dir(scope))
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let text = std::fs::read_to_string(files.last()?).ok()?;
    serde_json::from_str(&text).ok()
}

/// Store a report under now's stamp, keeping the newest [`KEPT`]. Where it went.
pub fn store<S: Serialize>(scope: &str, report: &Report<S>) -> Result<PathBuf, super::Error> {
    use super::Error;
    let dir = reports_dir(scope);
    std::fs::create_dir_all(&dir).map_err(|e| Error::Failed(e.to_string()))?;
    let stamp = jiff::Zoned::now().strftime("%Y-%m-%d-%H%M%S").to_string();
    let path = dir.join(format!("{stamp}.json"));
    let json = serde_json::to_vec_pretty(report).map_err(|e| Error::Parse(e.to_string()))?;
    paths::write_atomic(&path, &json).map_err(|e| Error::Failed(e.to_string()))?;
    if let Ok(rd) = std::fs::read_dir(&dir) {
        let mut all: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
        all.sort();
        let excess = all.len().saturating_sub(KEPT);
        for p in all.into_iter().take(excess) {
            let _ = std::fs::remove_file(p);
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::baseline::glob;

    #[test]
    fn a_pattern_covers_everything_of_a_kind_in_its_namespace() {
        let (p, what) = pattern_for("net", "net:client:aa-bb:new").unwrap();
        assert_eq!(
            (p.as_str(), what.as_str()),
            ("net:client:*", "every client finding")
        );
        assert!(glob(&p, "net:client:cc-dd:new"));
        assert_eq!(pattern_for("net", "net:reboot-required"), None);
        assert_eq!(pattern_for("net", "srv:container:db:exited"), None);
        assert_eq!(pattern_for("srv", "srvx:container:db"), None);
    }

    #[test]
    fn a_report_is_stored_and_read_back_under_its_scope() {
        let scope = "net:report-store-test";
        let rep = |id: &str| Report {
            snapshot: vec![1u8, 2],
            findings: vec![Finding {
                id: id.into(),
                ..Default::default()
            }],
        };
        assert!(latest::<Vec<u8>>(scope).is_none());
        assert!(shown::<Vec<u8>>(scope, None).cur.is_none());
        let path = store(scope, &rep("net:a:1")).unwrap();
        assert!(path.starts_with(
            sentry_core::paths::data_dir().join("networks/report-store-test/reports")
        ));
        let back: Report<Vec<u8>> = latest(scope).unwrap();
        assert_eq!((back.open().count(), back.snapshot), (1, vec![1, 2]));
        let s: Shown<Vec<u8>> = shown(scope, None);
        assert!(s.latest() && s.cur.is_some() && s.prev.is_none());
        assert_eq!(names(scope).len(), 1);
        let _ = std::fs::remove_dir_all(reports_dir(scope));
    }

    #[test]
    fn expected_findings_are_marked_once() {
        let mut b = BaselineFile::default();
        assert!(set_expected_in(&mut b, "net:a:1", true));
        assert!(!set_expected_in(&mut b, "net:a:1", true));
        assert!(set_expected_in(&mut b, "net:a:1", false));
        assert!(!set_expected_in(&mut b, "net:a:1", false));
    }
}

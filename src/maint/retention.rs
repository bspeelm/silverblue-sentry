//! Keeping the records from ballooning: old log entries, workflow run directories, closed
//! plans and reviews are deleted, the newest few always kept. Runs when a TUI starts and
//! after a record is written; nothing runs in the background.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use jiff::Timestamp;

use crate::config::Retention;
use crate::workflows::state::{RunStatus, runs_in};

#[derive(Debug, Default, PartialEq)]
pub struct Purged {
    pub log: usize,
    pub runs: usize,
    pub plans: usize,
    pub reviews: usize,
}

impl Purged {
    pub fn total(&self) -> usize {
        self.log + self.runs + self.plans + self.reviews
    }
}

fn months_ago(now: Timestamp, months: u32) -> i64 {
    now.as_second() - months as i64 * 30 * 86400
}

/// Prune a server's records (`LOCAL`: this machine's); `runs` is where its workflow runs live.
pub fn purge(server: &str, runs: &Path, k: &Retention, now: Timestamp) -> Purged {
    let mut p = Purged {
        log: purge_log(&super::log::dir(server), server, k, now),
        runs: purge_runs(runs, k.runs_per_workflow),
        ..Default::default()
    };
    p.plans = remove_older(
        &super::plan::dir(server).join("done"),
        months_ago(now, k.done_months),
    );
    p.reviews = keep_newest(&md_files(&super::review::dir(server)), k.reviews);
    p
}

fn purge_log(d: &Path, server: &str, k: &Retention, now: Timestamp) -> usize {
    let cutoff = months_ago(now, k.log_months);
    let mut n = 0;
    for e in super::log::list_in(d).iter().skip(k.log_keep) {
        let when = e.head.ended.or(e.head.started).map(|t| t.as_second());
        if when.is_some_and(|w| w < cutoff) && std::fs::remove_file(d.join(e.file_name())).is_ok() {
            n += 1;
        }
    }
    if n > 0 {
        let _ = super::log::write_index_in(d, server);
    }
    n
}

/// Each workflow's runs past the newest `keep` (never one in progress).
fn purge_runs(root: &Path, keep: usize) -> usize {
    let mut n = 0;
    for wf in std::fs::read_dir(root).into_iter().flatten().flatten() {
        let runs = runs_in(root, &wf.file_name().to_string_lossy());
        let old = runs.len().saturating_sub(keep);
        for r in runs.iter().take(old) {
            if r.state.status != RunStatus::InProgress && std::fs::remove_dir_all(&r.dir).is_ok() {
                n += 1;
            }
        }
    }
    n
}

fn md_files(d: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect()
}

fn modified(p: &Path) -> SystemTime {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// Files in `d` last changed before `cutoff` (unix seconds).
fn remove_older(d: &Path, cutoff: i64) -> usize {
    md_files(d)
        .into_iter()
        .filter(|p| {
            modified(p)
                .duration_since(SystemTime::UNIX_EPOCH)
                .is_ok_and(|t| (t.as_secs() as i64) < cutoff)
        })
        .filter(|p| std::fs::remove_file(p).is_ok())
        .count()
}

/// All but the newest `keep` (by name: they're dated), oldest removed first.
fn keep_newest(files: &[PathBuf], keep: usize) -> usize {
    let mut v = files.to_vec();
    v.sort();
    let old = v.len().saturating_sub(keep);
    v.iter()
        .take(old)
        .filter(|p| std::fs::remove_file(p).is_ok())
        .count()
}

/// Stored reports past the newest `keep`, oldest first by modification time; a report's
/// `.md` twin goes with it.
pub fn cap_reports(d: &Path, keep: usize) -> usize {
    let mut v: Vec<PathBuf> = std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    v.sort_by_key(|p| modified(p));
    let old = v.len().saturating_sub(keep);
    v.iter()
        .take(old)
        .filter(|p| {
            let _ = std::fs::remove_file(p.with_extension("md"));
            std::fs::remove_file(p).is_ok()
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflows::state::{Run, RunState};

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sentry-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn runs_keep_the_newest_and_the_one_in_progress() {
        let tmp = scratch("retain-runs");
        let t0: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        for i in 0..5 {
            let mut st = RunState::new("w", &["a".into()], Default::default());
            st.started = t0 + jiff::SignedDuration::from_hours(i);
            st.status = if i == 0 {
                RunStatus::InProgress
            } else {
                RunStatus::Done
            };
            Run::create_in(tmp.as_path(), "w", "", st).unwrap();
        }
        assert_eq!(purge_runs(tmp.as_path(), 2), 2, "the oldest done runs go");
        let left = runs_in(tmp.as_path(), "w");
        assert_eq!(left.len(), 3);
        assert_eq!(left[0].state.status, RunStatus::InProgress, "never purged");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn old_log_entries_go_and_the_ledger_follows() {
        use super::super::log::{LogEntry, LogHead, list_in};
        let d = scratch("retain-log");
        let now: Timestamp = "2026-10-27T00:00:00Z".parse().unwrap();
        for (i, when) in [
            "2024-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
            "2026-10-01T00:00:00Z",
        ]
        .iter()
        .enumerate()
        {
            let e = LogEntry {
                head: LogHead {
                    workflow: format!("w{i}"),
                    result: "done".into(),
                    ended: Some(when.parse().unwrap()),
                    ..Default::default()
                },
                body: String::new(),
            };
            std::fs::write(d.join(e.file_name()), e.to_md()).unwrap();
        }
        let k = Retention {
            log_keep: 1,
            ..Default::default()
        };
        assert_eq!(
            purge_log(&d, "", &k, now),
            2,
            "older than 12 months, past the newest 1"
        );
        assert_eq!(list_in(&d).len(), 1);
        let ledger = std::fs::read_to_string(d.join("LOG.md")).unwrap();
        assert!(
            ledger.contains("this machine") && ledger.contains("w2"),
            "{ledger}"
        );
        assert!(!ledger.contains("w0"));
        let k = Retention {
            log_keep: 0,
            ..Default::default()
        };
        assert_eq!(purge_log(&d, "", &k, now), 0, "a recent entry stays");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn newest_files_stay() {
        let tmp = scratch("retain-files");
        for n in [
            "2026-01-01-0000.md",
            "2026-02-01-0000.md",
            "2026-03-01-0000.md",
        ] {
            std::fs::write(tmp.as_path().join(n), "x").unwrap();
        }
        assert_eq!(keep_newest(&md_files(tmp.as_path()), 2), 1);
        assert!(!tmp.as_path().join("2026-01-01-0000.md").exists());
        assert!(tmp.as_path().join("2026-03-01-0000.md").exists());
        for i in 0..3 {
            std::fs::write(tmp.as_path().join(format!("r{i}.json")), "{}").unwrap();
            std::fs::write(tmp.as_path().join(format!("r{i}.md")), "").unwrap();
        }
        assert_eq!(cap_reports(tmp.as_path(), 3), 0);
        assert_eq!(remove_older(tmp.as_path(), 0), 0, "nothing older than 1970");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

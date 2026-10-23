//! `~/.local/share/sentry/reports/YYYY-MM-DD[-tag][-N].json` plus a rendered `.md` alongside.

use std::path::{Path, PathBuf};

use jiff::Timestamp;

use super::diff::{self, Kind};
use super::{Report, Sev};
use crate::paths;

#[derive(Debug, Clone)]
pub struct Stored {
    pub path: PathBuf,
    pub report: Report,
}

impl Stored {
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

pub fn dir() -> PathBuf {
    paths::data_dir().join("reports")
}

/// Every readable report, oldest first.
pub fn list() -> Vec<Stored> {
    list_in(&dir())
}

pub fn list_in(d: &Path) -> Vec<Stored> {
    let mut v: Vec<Stored> = std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter_map(|path| {
            let text = std::fs::read_to_string(&path).ok()?;
            let report = serde_json::from_str(&text).ok()?;
            Some(Stored { path, report })
        })
        .collect();
    v.sort_by_key(|s| s.report.taken_at);
    v
}

/// The newest report by mtime, parsing only that one file.
pub fn latest() -> Option<Report> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir())
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    v.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
    let text = std::fs::read_to_string(v.last()?).ok()?;
    serde_json::from_str(&text).ok()
}

/// Latest report carrying `tag`.
pub fn find_tag<'a>(all: &'a [Stored], tag: &str) -> Option<&'a Stored> {
    all.iter()
        .rev()
        .find(|s| s.report.tag.as_deref() == Some(tag))
}

fn stem(r: &Report) -> String {
    let date = r
        .taken_at
        .to_zoned(jiff::tz::TimeZone::system())
        .strftime("%Y-%m-%d")
        .to_string();
    match &r.tag {
        Some(t) => format!("{date}-{}", sanitize(t)),
        None => date,
    }
}

fn sanitize(tag: &str) -> String {
    tag.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Write the JSON and the Markdown rendering; never overwrites an earlier report.
pub fn save(r: &Report, prev: Option<&Stored>) -> anyhow::Result<PathBuf> {
    save_in(&dir(), r, prev)
}

pub fn save_in(d: &Path, r: &Report, prev: Option<&Stored>) -> anyhow::Result<PathBuf> {
    let base = stem(r);
    let mut n = 1;
    let path = loop {
        let name = if n == 1 {
            format!("{base}.json")
        } else {
            format!("{base}-{n}.json")
        };
        let p = d.join(name);
        if !p.exists() {
            break p;
        }
        n += 1;
    };
    paths::write_atomic(&path, &serde_json::to_vec_pretty(r)?)?;
    paths::write_atomic(&path.with_extension("md"), markdown(r, prev).as_bytes())?;
    Ok(path)
}

/// Delete reports older than `months` (30-day months). Returns how many were removed.
pub fn prune(months: u32, now: Timestamp) -> usize {
    let cutoff = now.as_second() - months as i64 * 30 * 86400;
    let mut n = 0;
    for s in list() {
        if s.report.taken_at.as_second() < cutoff {
            let _ = std::fs::remove_file(s.path.with_extension("md"));
            if std::fs::remove_file(&s.path).is_ok() {
                n += 1;
            }
        }
    }
    n
}

pub fn markdown(r: &Report, prev: Option<&Stored>) -> String {
    let mut s = format!(
        "# sentry audit · {}{}\n\nsilverblue {} · kernel {} · driver {}\n\n## Findings\n\n",
        r.taken_at
            .to_zoned(jiff::tz::TimeZone::system())
            .strftime("%Y-%m-%d %H:%M"),
        r.tag.as_ref().map_or(String::new(), |t| format!(" · {t}")),
        r.host.os_version,
        r.host.kernel,
        r.host.driver.as_deref().unwrap_or("—"),
    );
    if r.findings.is_empty() {
        s.push_str("None.\n");
    } else {
        s.push_str("| severity | category | finding |\n|---|---|---|\n");
        for f in &r.findings {
            let sev = if f.expected {
                format!("~~{}~~ (expected)", f.severity.as_str())
            } else if f.severity == Sev::High {
                format!("**{}**", f.severity.as_str())
            } else {
                f.severity.as_str().to_string()
            };
            s.push_str(&format!(
                "| {sev} | {} | {} |\n",
                f.category,
                f.message.replace('|', "\\|")
            ));
        }
    }
    if !r.errors.is_empty() {
        s.push_str("\n## Not collected\n\n");
        for e in &r.errors {
            s.push_str(&format!("- {e}\n"));
        }
    }
    match prev {
        Some(p) => {
            let d = diff::diff(&p.report, r);
            s.push_str(&format!(
                "\n## Diff vs {}\n\n{}\n\n```diff\n",
                p.name(),
                diff::summary(&d)
            ));
            for l in &d {
                match l.kind {
                    Kind::Section => s.push_str(&format!("# {}\n", l.text)),
                    _ => s.push_str(&format!("{}\n", l.text)),
                }
            }
            s.push_str("```\n");
        }
        None => s.push_str("\n## Diff\n\nFirst report: nothing to compare against.\n"),
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Finding, Sections, test_report};

    #[test]
    fn save_never_overwrites_and_lists_in_order() {
        let d = std::env::temp_dir().join(format!("sentry-reports-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let mut a = test_report(Sections::default());
        a.taken_at = Timestamp::from_second(1_760_000_000).unwrap();
        a.tag = Some("pre rebase/45".into());
        a.findings.push(Finding {
            id: "x".into(),
            severity: Sev::High,
            category: "shell".into(),
            message: "a | b".into(),
            evidence: String::new(),
            expected: false,
        });
        let p1 = save_in(&d, &a, None).unwrap();
        let p2 = save_in(&d, &a, None).unwrap();
        assert_ne!(p1, p2);
        assert!(
            p1.to_string_lossy().ends_with("-pre-rebase-45.json"),
            "{p1:?}"
        );
        assert!(p2.to_string_lossy().ends_with("-pre-rebase-45-2.json"));
        let md = std::fs::read_to_string(p1.with_extension("md")).unwrap();
        assert!(md.contains("| **high** | shell | a \\| b |"), "{md}");
        let all = list_in(&d);
        assert_eq!(all.len(), 2);
        assert!(find_tag(&all, "pre rebase/45").is_some());
        std::fs::remove_dir_all(&d).unwrap();
    }
}

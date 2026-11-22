//! What's newer upstream, looked up from this machine (never from the host) with `curl`:
//! GitHub releases and endoflife.date, and which of a source's releases count as newer.
//! What else a kind of host follows (container registries), and its cache, are its own.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use sentry_core::exec::Cmd;
use sentry_core::maint::version;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Release {
    pub version: String,
    /// YYYY-MM-DD when known.
    pub date: Option<String>,
    /// Its notes mention a security fix (GHSA-, CVE-, "security").
    pub security: bool,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Eol {
    pub cycle: String,
    /// None: no end date announced.
    pub eol: Option<jiff::civil::Date>,
    pub latest: Option<String>,
}

/// `GET` a URL from this machine.
pub fn curl(url: &str, headers: &[&str]) -> Result<String, String> {
    let mut c = Cmd::local("curl").args(["-fsSL", "--max-time", "20"]);
    for h in headers {
        c = c.args(["-H", h]);
    }
    c.arg(url)
        .timeout(Some(std::time::Duration::from_secs(25)))
        .output()
        .map_err(|e| format!("{url}: {e}"))
}

fn mentions_security(notes: &str) -> bool {
    let l = notes.to_ascii_lowercase();
    l.contains("ghsa-") || l.contains("cve-") || l.contains("security")
}

/// `GET /repos/{o}/{r}/releases`: published, non-draft releases.
pub fn parse_github(json: &str) -> Result<Vec<Release>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let list = v.as_array().ok_or("not a list of releases")?;
    Ok(list
        .iter()
        .filter(|r| !r["draft"].as_bool().unwrap_or(false))
        .filter(|r| !r["prerelease"].as_bool().unwrap_or(false))
        .filter_map(|r| {
            let tag = r["tag_name"].as_str()?;
            Some(Release {
                version: tag.to_string(),
                date: r["published_at"]
                    .as_str()
                    .map(|d| d.chars().take(10).collect()),
                security: mentions_security(r["body"].as_str().unwrap_or("")),
                url: r["html_url"].as_str().map(str::to_string),
            })
        })
        .collect())
}

/// A GitHub repository's (`owner/repo`) published releases.
pub fn fetch_github(repo: &str) -> Result<Vec<Release>, String> {
    let json = curl(
        &format!("https://api.github.com/repos/{repo}/releases?per_page=50"),
        &["Accept: application/vnd.github+json"],
    )?;
    parse_github(&json)
}

/// endoflife.date `GET /api/{product}.json`: the cycle asked for, or the newest one.
pub fn parse_eol(json: &str, cycle: Option<&str>) -> Result<Eol, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let list = v.as_array().ok_or("not a list of cycles")?;
    let c = match cycle {
        Some(want) => list
            .iter()
            .find(|c| {
                c["cycle"].as_str() == Some(want)
                    || c["cycle"].as_u64().map(|n| n.to_string()).as_deref() == Some(want)
            })
            .ok_or_else(|| format!("no cycle {want}"))?,
        None => list.first().ok_or("no cycles")?,
    };
    let cycle = c["cycle"]
        .as_str()
        .map(str::to_string)
        .or_else(|| c["cycle"].as_u64().map(|n| n.to_string()))
        .unwrap_or_default();
    Ok(Eol {
        cycle,
        // `false` (no end announced), `true` (ended, no date) or a date.
        eol: c["eol"]
            .as_str()
            .and_then(|d| d.parse().ok())
            .or_else(|| (c["eol"].as_bool() == Some(true)).then(|| jiff::civil::date(1970, 1, 1))),
        latest: c["latest"].as_str().map(str::to_string),
    })
}

/// A tag's shape: digit runs become `#`, a leading `v` is dropped (`v3.2.4-alpine` →
/// `#.#.#-alpine`), so variants (`-builder-alpine`, `-slim`) don't count as newer versions.
pub fn shape(tag: &str) -> String {
    let t = tag.strip_prefix('v').unwrap_or(tag);
    let mut out = String::new();
    for c in t.chars() {
        if c.is_ascii_digit() {
            if !out.ends_with('#') {
                out.push('#');
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Releases that count for an item, newest first: tags matching its glob if it has one, else
/// tags shaped like the pinned one (`like`), else plain version numbers.
pub fn comparable(
    releases: &[Release],
    tag_glob: Option<&str>,
    like: Option<&str>,
) -> Vec<Release> {
    let want = like.map(shape);
    let mut v: Vec<Release> = releases
        .iter()
        .filter(|r| match (tag_glob, &want) {
            (Some(g), _) => sentry_core::baseline::glob(g, &r.version),
            (None, Some(w)) => shape(&r.version) == *w,
            // Plain version numbers: dotted, no variant suffix (not a commit hash).
            (None, None) => {
                version::is_release(&r.version)
                    && !r.version.contains('-')
                    && r.version.contains('.')
            }
        })
        .filter(|r| version::is_release(&r.version))
        .cloned()
        .collect();
    v.sort_by(|a, b| version::cmp(&b.version, &a.version));
    v.dedup_by(|a, b| a.version == b.version);
    v
}

/// endoflife.date: a product, or one cycle of it (`debian/13`).
pub fn fetch_eol(key: &str) -> Result<Eol, String> {
    let (product, cycle) = match key.split_once('/') {
        Some((p, c)) => (p, Some(c)),
        None => (key, None),
    };
    let json = curl(&format!("https://endoflife.date/api/{product}.json"), &[])?;
    parse_eol(&json, cycle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_releases() {
        let json = r#"[
          {"tag_name":"v2.0.0-rc1","prerelease":true,"draft":false,"body":"","published_at":"2026-10-01T00:00:00Z"},
          {"tag_name":"v1.5.2","prerelease":false,"draft":false,"body":"Fixes GHSA-abcd-1234-wxyz","published_at":"2026-09-30T10:00:00Z","html_url":"https://example.invalid/r/1.5.2"},
          {"tag_name":"v1.5.1","prerelease":false,"draft":false,"body":"Bug fixes","published_at":"2026-09-01T10:00:00Z"},
          {"tag_name":"v1.6.0-draft","prerelease":false,"draft":true,"body":""}
        ]"#;
        let r = parse_github(json).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].version, "v1.5.2");
        assert!(r[0].security && !r[1].security);
        assert_eq!(r[0].date.as_deref(), Some("2026-09-30"));
    }

    #[test]
    fn releases_that_count() {
        let r: Vec<Release> = ["latest", "3.2.5-alpine", "3.2.5", "3.2.10-alpine", "v0.7.5"]
            .iter()
            .map(|v| Release {
                version: v.to_string(),
                ..Default::default()
            })
            .collect();
        let names = |v: Vec<Release>| v.into_iter().map(|r| r.version).collect::<Vec<_>>();
        assert_eq!(
            names(comparable(&r, Some("*-alpine"), None)),
            ["3.2.10-alpine", "3.2.5-alpine"]
        );
        assert_eq!(names(comparable(&r, None, None)), ["3.2.5", "v0.7.5"]);
        assert_eq!(
            names(comparable(&r, None, Some("3.2.4-alpine"))),
            ["3.2.10-alpine", "3.2.5-alpine"]
        );
        assert_eq!(shape("v2.1.5"), shape("2.1.7"));
    }

    #[test]
    fn end_of_life_cycles() {
        let json = r#"[{"cycle":"13","eol":"2030-06-30","latest":"13.2"},
                       {"cycle":"12","eol":"2028-06-10","latest":"12.12"},
                       {"cycle":"3","eol":false,"latest":"3.1"},
                       {"cycle":"2","eol":true}]"#;
        let e = parse_eol(json, Some("12")).unwrap();
        assert_eq!(e.eol, Some(jiff::civil::date(2028, 6, 10)));
        assert_eq!(parse_eol(json, None).unwrap().cycle, "13");
        assert_eq!(parse_eol(json, Some("3")).unwrap().eol, None);
        assert!(parse_eol(json, Some("2")).unwrap().eol.is_some());
        assert!(parse_eol(json, Some("9")).is_err());
    }
}

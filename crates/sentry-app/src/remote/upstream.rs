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

/// One entry of endoflife.date's list: `cycle` and `latest` are strings, or numbers for
/// some products.
fn eol_entry(c: &Value) -> Eol {
    let text = |v: &Value| {
        v.as_str()
            .map(str::to_string)
            .or_else(|| v.as_number().map(|n| n.to_string()))
    };
    Eol {
        cycle: text(&c["cycle"]).unwrap_or_default(),
        // `false` (no end announced), `true` (ended, no date) or a date.
        eol: c["eol"]
            .as_str()
            .and_then(|d| d.parse().ok())
            .or_else(|| (c["eol"].as_bool() == Some(true)).then(|| jiff::civil::date(1970, 1, 1))),
        latest: text(&c["latest"]),
    }
}

/// endoflife.date `GET /api/{product}.json`: every cycle of a product, in the file's order
/// (newest first).
pub fn parse_cycles(json: &str) -> Result<Vec<Eol>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let list = v.as_array().ok_or("not a list of cycles")?;
    Ok(list.iter().map(eol_entry).collect())
}

/// endoflife.date `GET /api/{product}.json`: the cycle asked for, or the newest one.
pub fn parse_eol(json: &str, cycle: Option<&str>) -> Result<Eol, String> {
    let list = parse_cycles(json)?;
    match cycle {
        Some(want) => list
            .into_iter()
            .find(|c| c.cycle == want)
            .ok_or_else(|| format!("no cycle {want}")),
        None => list.into_iter().next().ok_or_else(|| "no cycles".into()),
    }
}

/// A version as a package or a tag writes it, down to its numbers: no epoch (`5:`), no
/// leading `v`, nothing from the first `-`, `~` or `+` (`5:29.1.0-1~deb13` → `29.1.0`,
/// `3.2.4-alpine` → `3.2.4`).
pub fn bare_version(v: &str) -> &str {
    let v = v.trim();
    let v = match v.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.chars().all(|c| c.is_ascii_digit()) => {
            rest
        }
        _ => v,
    };
    let v = match v.strip_prefix(['v', 'V']) {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => v,
    };
    v.split(['-', '~', '+']).next().unwrap_or(v)
}

/// The release series (of `cycles`, one product's) the version that runs belongs to. Pure;
/// never the newest by default, never a guess:
/// 1. a cycle named only by numbers that the version starts with, up to a dot (`29` for
///    `29.10.0`, `26.1` for `26.1.5`; `2` is not `29.1`): the longest;
/// 2. else the cycle whose `latest` starts with the same number (`620.70.06` → `r620-linux`,
///    whose latest is `620.70.06`, never `r620-windows`, whose latest is `621.14`); of
///    several, the one whose latest is the version itself, else the only one whose latest
///    has as many parts;
/// 3. else none.
pub fn cycle_for<'a>(cycles: &'a [Eol], running: &str) -> Option<&'a Eol> {
    let v = bare_version(running);
    if !v.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let numeric = |s: &str| {
        !s.is_empty()
            && s.split('.')
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    };
    let by_name = cycles
        .iter()
        .filter(|c| numeric(&c.cycle))
        .filter(|c| {
            v.strip_prefix(c.cycle.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
        })
        .max_by_key(|c| c.cycle.len());
    if by_name.is_some() {
        return by_name;
    }
    let lead = |s: &str| s.split('.').next().unwrap_or("").to_string();
    let head = lead(v);
    if !head.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    fn latest(c: &Eol) -> Option<&str> {
        c.latest.as_deref().map(bare_version)
    }
    let same: Vec<&Eol> = cycles
        .iter()
        .filter(|c| latest(c).is_some_and(|l| lead(l) == head))
        .collect();
    if let [one] = same[..] {
        return Some(one);
    }
    if let Some(e) = same.iter().find(|c| latest(c) == Some(v)) {
        return Some(e);
    }
    let parts = |s: &str| s.split('.').count();
    let alike: Vec<&Eol> = same
        .into_iter()
        .filter(|c| latest(c).is_some_and(|l| parts(l) == parts(v)))
        .collect();
    match alike[..] {
        [one] => Some(one),
        _ => None,
    }
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

/// endoflife.date: every cycle of a product (`debian`), newest first.
pub fn fetch_cycles(product: &str) -> Result<Vec<Eol>, String> {
    parse_cycles(&curl(
        &format!("https://endoflife.date/api/{product}.json"),
        &[],
    )?)
}

/// endoflife.date: a product's newest cycle, or one cycle of it (`debian/13`).
pub fn fetch_eol(key: &str) -> Result<Eol, String> {
    let (product, cycle) = match key.split_once('/') {
        Some((p, c)) => (p, Some(c)),
        None => (key, None),
    };
    let json = curl(&format!("https://endoflife.date/api/{product}.json"), &[])?;
    parse_eol(&json, cycle)
}

/// [`fetch_eol`] of one cycle, kept a day in the cache (`eol-<product>-<cycle>`): the
/// security audit asks it for an operating system's release every time it runs.
pub fn eol_cached(product: &str, cycle: &str) -> Result<Eol, String> {
    let key = format!("eol-{product}-{cycle}");
    if let Some(c) = sentry_core::cache::load::<Eol>(&key)
        && c.age_secs(jiff::Timestamp::now()) < 86_400
    {
        return Ok(c.data);
    }
    let e = fetch_eol(&format!("{product}/{cycle}"))?;
    let _ = sentry_core::cache::store(&key, &e);
    Ok(e)
}

/// What the security audit says of an operating system's release (`/etc/os-release`):
/// looked up on endoflife.date (a day's cache), or why it couldn't be.
pub fn os_life(os_release: &str) -> sentry_core::secaudit::Life {
    use sentry_core::secaudit::{Life, release_of};
    match release_of(os_release) {
        None => Life {
            release: String::new(),
            ends: None,
            error: Some("sentry doesn't know where to look up this system's support".into()),
        },
        Some((product, cycle, release)) => match eol_cached(&product, &cycle) {
            // (`true` without a date reads as 1970: long past.)
            Ok(e) => Life {
                release,
                ends: e.eol,
                error: None,
            },
            Err(e) => Life {
                release,
                ends: None,
                error: Some(format!("endoflife.date couldn't be asked: {e}")),
            },
        },
    }
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

    fn cycles(list: &[(&str, &str, &str)]) -> Vec<Eol> {
        let json: Vec<String> = list
            .iter()
            .map(|(c, eol, latest)| format!(r#"{{"cycle":"{c}","eol":{eol},"latest":"{latest}"}}"#))
            .collect();
        parse_cycles(&format!("[{}]", json.join(","))).unwrap()
    }

    #[test]
    fn a_running_version_names_its_series() {
        let nvidia = cycles(&[
            ("r620-linux", r#""2029-11-04""#, "620.70.06"),
            ("r620-windows", r#""2029-11-04""#, "621.14"),
            ("r595-linux", "false", "595.112.07"),
            ("r595-windows", "false", "597.30"),
            ("r580-linux", "false", "580.196.07"),
            ("r550-linux", r#""2025-04-17""#, "550.144.03"),
            ("r550-windows", r#""2025-04-17""#, "553.74"),
        ]);
        let docker = cycles(&[
            ("29", "false", "29.10.0"),
            ("28", "false", "28.5.2"),
            ("26.1", "false", "26.1.5"),
            ("26.0", "false", "26.0.2"),
            ("25.0", "false", "25.0.5"),
        ]);
        let debian = cycles(&[
            ("13", r#""2030-06-30""#, "13.7"),
            ("12", r#""2028-06-10""#, "12.15"),
        ]);
        let few = cycles(&[("2", "false", "2.9"), ("1", "true", "1.4")]);
        let table: &[(&[Eol], &str, Option<&str>)] = &[
            (&nvidia, "620.70.06-1", Some("r620-linux")),
            (&nvidia, "620.70.06", Some("r620-linux")),
            (&nvidia, "620.61.01", Some("r620-linux")),
            (&nvidia, "550.144.03-1", Some("r550-linux")),
            (&nvidia, "595.100.01", Some("r595-linux")),
            (&nvidia, "580.82.09-1", Some("r580-linux")),
            // A Windows latest never stands for a Linux version.
            (&nvidia, "621.14", Some("r620-windows")),
            (&nvidia, "470.256.02", None),
            (&docker, "5:29.10.0-1~debian.13~trixie", Some("29")),
            (&docker, "29.1.3", Some("29")),
            (&docker, "v28.0.1", Some("28")),
            (&docker, "26.1.4", Some("26.1")),
            (&docker, "26.0.0", Some("26.0")),
            // No cycle 26.2; 26.1 and 26.0 both lead with 26: can't tell.
            (&docker, "26.2.0", None),
            (&docker, "24.0.9", None),
            (&debian, "13.7", Some("13")),
            (&debian, "13", Some("13")),
            (&debian, "12.15", Some("12")),
            (&debian, "11.11", None),
            // `2` isn't a prefix of `29.1`.
            (&few, "29.1", None),
            (&few, "2.1", Some("2")),
            (&nvidia, "latest", None),
            (&docker, "", None),
        ];
        for (list, running, want) in table {
            assert_eq!(
                cycle_for(list, running).map(|e| e.cycle.as_str()),
                *want,
                "{running}"
            );
        }
        // No Windows cycle is ever chosen for a Linux driver.
        for v in [
            "620.70.06",
            "595.112.07",
            "580.196.07",
            "550.144.03",
            "550.54.14",
        ] {
            assert!(
                cycle_for(&nvidia, v).is_some_and(|e| e.cycle.ends_with("-linux")),
                "{v}"
            );
        }
        assert_eq!(bare_version("620.70.06-1"), "620.70.06");
        assert_eq!(bare_version("v0.7.4"), "0.7.4");
        assert_eq!(bare_version("3.2.4-alpine"), "3.2.4");
        assert_eq!(bare_version("5:29.10.0-1~debian.13~trixie"), "29.10.0");
        assert_eq!(nvidia[5].eol, Some(jiff::civil::date(2025, 4, 17)));
        assert_eq!(few[1].eol, Some(jiff::civil::date(1970, 1, 1)));
        assert_eq!(
            parse_cycles(r#"[{"cycle":3.9,"eol":false},{"cycle":8,"eol":false}]"#)
                .unwrap()
                .iter()
                .map(|e| e.cycle.as_str())
                .collect::<Vec<_>>(),
            ["3.9", "8"]
        );
    }
}

//! What's newer upstream, looked up from this machine (never from the server) with `curl`:
//! GitHub releases, Docker Hub and GHCR tags, endoflife.date. Cached per server for a day;
//! fetched only when asked (`c` on the Maintenance tab, `sentry-server maint --refresh`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::version;
use crate::cache;
use crate::exec::Cmd;

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

/// One source's answer.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Upstream {
    /// Newest first.
    pub releases: Vec<Release>,
    pub err: Option<String>,
}

/// Everything looked up for a server: by source (`github:o/r`) and by eol key (`debian/13`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Lookups {
    pub sources: BTreeMap<String, Upstream>,
    pub eol: BTreeMap<String, Result<Eol, String>>,
}

fn curl(url: &str, headers: &[&str]) -> Result<String, String> {
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

/// Docker Hub `GET /v2/repositories/{ns}/{repo}/tags`.
pub fn parse_hub(json: &str) -> Result<Vec<Release>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let list = v["results"]
        .as_array()
        .ok_or("no results in the tag list")?;
    Ok(list
        .iter()
        .filter_map(|t| {
            Some(Release {
                version: t["name"].as_str()?.to_string(),
                date: t["last_updated"]
                    .as_str()
                    .map(|d| d.chars().take(10).collect()),
                ..Default::default()
            })
        })
        .collect())
}

/// A registry's `GET /v2/{name}/tags/list` (GHCR): names only.
pub fn parse_registry(json: &str) -> Result<Vec<Release>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let list = v["tags"].as_array().ok_or("no tags in the list")?;
    Ok(list
        .iter()
        .filter_map(|t| t.as_str())
        .map(|t| Release {
            version: t.to_string(),
            ..Default::default()
        })
        .collect())
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
            (Some(g), _) => crate::baseline::glob(g, &r.version),
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

/// Docker Hub, newest first, up to 5 pages; `name` narrows it server-side (tags containing it).
fn hub_tags(repo: &str, name: Option<&str>) -> Result<Vec<Release>, String> {
    let mut url = format!(
        "https://hub.docker.com/v2/repositories/{repo}/tags?page_size=100&ordering=last_updated{}",
        name.map_or(String::new(), |n| format!("&name={n}"))
    );
    let mut out = Vec::new();
    for _ in 0..5 {
        let json = curl(&url, &[])?;
        out.extend(parse_hub(&json)?);
        let v: Value = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        match v["next"].as_str() {
            Some(n) if !n.is_empty() => url = n.to_string(),
            _ => break,
        }
    }
    Ok(out)
}

fn fetch_source(src: &str, tag_glob: Option<&str>) -> Result<Vec<Release>, String> {
    if let Some(repo) = src.strip_prefix("github:") {
        let json = curl(
            &format!("https://api.github.com/repos/{repo}/releases?per_page=50"),
            &["Accept: application/vnd.github+json"],
        )?;
        parse_github(&json)
    } else if let Some(repo) = src.strip_prefix("docker:") {
        let repo = if repo.contains('/') {
            repo.to_string()
        } else {
            format!("library/{repo}")
        };
        // A glob's literal start (`v*` → `v`) filters on Docker Hub's side.
        let prefix = tag_glob
            .map(|g| g.split('*').next().unwrap_or(""))
            .filter(|p| {
                !p.is_empty()
                    && p.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            });
        hub_tags(&repo, prefix)
    } else if let Some(name) = src.strip_prefix("ghcr:") {
        let tok = curl(
            &format!("https://ghcr.io/token?scope=repository:{name}:pull"),
            &[],
        )?;
        let tok: Value = serde_json::from_str(&tok).map_err(|e| e.to_string())?;
        let tok = tok["token"].as_str().ok_or("ghcr gave no token")?;
        let json = curl(
            &format!("https://ghcr.io/v2/{name}/tags/list?n=1000"),
            &[&format!("Authorization: Bearer {tok}")],
        )?;
        parse_registry(&json)
    } else {
        Err(format!("unknown source {src}"))
    }
}

fn fetch_eol(key: &str) -> Result<Eol, String> {
    let (product, cycle) = match key.split_once('/') {
        Some((p, c)) => (p, Some(c)),
        None => (key, None),
    };
    let json = curl(&format!("https://endoflife.date/api/{product}.json"), &[])?;
    parse_eol(&json, cycle)
}

fn cache_key(server: &str) -> String {
    format!("server-{server}-upstream")
}

pub fn load(server: &str) -> Option<cache::Cached<Lookups>> {
    cache::load(&cache_key(server))
}

/// Look everything up again (in parallel) and cache it.
pub fn refresh(server: &str, cfg: &crate::server::config::Server) -> Lookups {
    let items = &cfg.maintenance.items;
    let mut sources: Vec<(&str, Option<&str>)> = items
        .iter()
        .filter_map(|i| Some((i.source.as_deref()?, i.tag.as_deref())))
        .collect();
    sources.sort();
    sources.dedup_by(|a, b| a.0 == b.0);
    let mut eols: Vec<&str> = items.iter().filter_map(|i| i.eol.as_deref()).collect();
    eols.sort();
    eols.dedup();
    let mut out = Lookups::default();
    std::thread::scope(|sc| {
        let hs: Vec<_> = sources
            .iter()
            .map(|(s, g)| (*s, sc.spawn(move || fetch_source(s, *g))))
            .collect();
        let he: Vec<_> = eols
            .iter()
            .map(|k| (*k, sc.spawn(move || fetch_eol(k))))
            .collect();
        for (s, h) in hs {
            let up = match h.join().unwrap_or_else(|_| Err("lookup panicked".into())) {
                Ok(releases) => Upstream {
                    releases,
                    err: None,
                },
                Err(e) => Upstream {
                    releases: Vec::new(),
                    err: Some(e),
                },
            };
            out.sources.insert(s.to_string(), up);
        }
        for (k, h) in he {
            let r = h.join().unwrap_or_else(|_| Err("lookup panicked".into()));
            out.eol.insert(k.to_string(), r);
        }
    });
    let _ = cache::store(&cache_key(server), &out);
    out
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
    fn registry_tags_and_comparable_ones() {
        let hub = r#"{"results":[{"name":"latest"},{"name":"3.2.5-alpine","last_updated":"2026-10-20T00:00:00Z"},
            {"name":"3.2.5"},{"name":"3.2.10-alpine"},{"name":"3.3.0-beta.1-alpine"},{"name":"3.2.4-alpine"}]}"#;
        let r = parse_hub(hub).unwrap();
        let alpine: Vec<String> = comparable(&r, Some("*-alpine"), None)
            .into_iter()
            .map(|r| r.version)
            .collect();
        assert_eq!(alpine, ["3.2.10-alpine", "3.2.5-alpine", "3.2.4-alpine"]);
        let plain: Vec<String> = comparable(&r, None, None)
            .into_iter()
            .map(|r| r.version)
            .collect();
        assert_eq!(plain, ["3.2.5"]);
        // Shaped like the pin: a `-builder-alpine` variant isn't a newer version of it.
        let mut r2 = r.clone();
        r2.push(Release {
            version: "3.2.11-builder-alpine".into(),
            ..Default::default()
        });
        let like: Vec<String> = comparable(&r2, None, Some("3.2.4-alpine"))
            .into_iter()
            .map(|r| r.version)
            .collect();
        assert_eq!(like, ["3.2.10-alpine", "3.2.5-alpine", "3.2.4-alpine"]);
        assert_eq!(shape("v2.1.5"), shape("2.1.7"));
        let ghcr =
            parse_registry(r#"{"name":"org/app","tags":["v0.7.4","v0.7.5","main","sha-abc"]}"#)
                .unwrap();
        let v: Vec<String> = comparable(&ghcr, None, None)
            .into_iter()
            .map(|r| r.version)
            .collect();
        assert_eq!(v, ["v0.7.5", "v0.7.4"]);
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

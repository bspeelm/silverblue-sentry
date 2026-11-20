//! What's newer upstream, looked up from this machine (never from the server) with `curl`:
//! GitHub releases, Docker Hub and GHCR tags, endoflife.date. Cached per server for a day;
//! fetched only when asked (`c` on Maintenance, `sentry-server maint --refresh`). GitHub's and
//! endoflife.date's side, and which releases count, are `sentry_app::remote::upstream`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use sentry_app::remote::upstream::{
    Eol, Release, comparable, curl, fetch_eol, fetch_github, parse_eol, parse_github, shape,
};
use sentry_core::cache;

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
        fetch_github(repo)
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

fn cache_key(server: &str) -> String {
    format!("server-{server}-upstream")
}

pub fn load(server: &str) -> Option<cache::Cached<Lookups>> {
    cache::load(&cache_key(server))
}

/// Look everything up again (in parallel) and cache it.
pub fn refresh(server: &str, cfg: &crate::config::Server) -> Lookups {
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
}

//! Containers, images and volumes via `podman ... --format json`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{CResult, Ctx};
use crate::exec::Cmd;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Toolbox,
    Distrobox,
    Podman,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Toolbox => "toolbox",
            Kind::Distrobox => "distrobox",
            Kind::Podman => "podman",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ctr {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub state: String,
    pub status: String,
    pub image: String,
    pub created: i64,
    pub exited_at: Option<i64>,
    pub home_mount: bool,
    pub stale: bool,
    /// Seconds since exit (stopped) or since creation (running).
    pub age_s: i64,
}

impl Ctr {
    pub fn running(&self) -> bool {
        self.state == "running"
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Totals {
    pub count: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Podman {
    pub containers: Vec<Ctr>,
    pub images: Totals,
    pub dangling: Totals,
    pub volumes: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawCtr {
    id: String,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    image: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    created: i64,
    #[serde(default)]
    exited_at: i64,
    #[serde(default)]
    labels: Option<HashMap<String, String>>,
    #[serde(default)]
    mounts: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawImage {
    #[serde(default)]
    size: u64,
}

pub fn collect(ctx: &Ctx) -> CResult<Podman> {
    let ps = Cmd::host("podman")
        .args(["ps", "-a", "--format", "json"])
        .output()?;
    let images = Cmd::host("podman")
        .args(["image", "ls", "--format", "json"])
        .output()?;
    let dangling = Cmd::host("podman")
        .args([
            "image",
            "ls",
            "--filter",
            "dangling=true",
            "--format",
            "json",
        ])
        .output()?;
    let volumes = Cmd::host("podman")
        .args(["volume", "ls", "--format", "json"])
        .output()?;
    let home = ctx.home.to_string_lossy();
    let mut containers = parse_ps(
        &ps,
        &home,
        ctx.now.as_second(),
        ctx.cfg.audit.stale_container_days,
    )?;
    apply_own_stops(
        &mut containers,
        &load_own_stops(),
        ctx.now.as_second(),
        ctx.cfg.audit.stale_container_days,
    );
    Ok(Podman {
        containers,
        images: parse_images(&images)?,
        dangling: parse_images(&dangling)?,
        volumes: parse_len(&volumes)?,
    })
}

/// When sentry starts a stopped toolbox just to look inside it (update checks), podman's exit
/// time moves to "now" and the container would stop looking stale. We remember the exit time
/// podman reports after *our* stop, and the original one, and report the original while the
/// container hasn't been used since.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OwnStop {
    pub ours: i64,
    pub original: i64,
}

fn own_stops_path() -> std::path::PathBuf {
    crate::paths::data_dir().join("container-stops.json")
}

pub fn load_own_stops() -> std::collections::BTreeMap<String, OwnStop> {
    std::fs::read_to_string(own_stops_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Record that sentry stopped `name` (whose real last exit was `original`).
pub fn remember_own_stop(name: &str, original: i64) {
    let Ok(ours) = Cmd::host("podman")
        .args(["inspect", "--format", "{{.State.FinishedAt.Unix}}", name])
        .output()
    else {
        return;
    };
    let Ok(ours) = ours.trim().parse::<i64>() else {
        return;
    };
    let mut m = load_own_stops();
    // An earlier record means the original exit is older still: keep it.
    let original = m.get(name).map_or(original, |o| o.original.min(original));
    m.insert(name.to_string(), OwnStop { ours, original });
    if let Ok(b) = serde_json::to_vec_pretty(&m) {
        let _ = crate::paths::write_atomic(&own_stops_path(), &b);
    }
}

pub fn apply_own_stops(
    ctrs: &mut [Ctr],
    stops: &std::collections::BTreeMap<String, OwnStop>,
    now: i64,
    stale_days: u32,
) {
    for c in ctrs.iter_mut() {
        let Some(o) = stops.get(&c.name) else {
            continue;
        };
        // Only while podman's exit time is still the one our stop produced.
        if c.running() || c.exited_at.is_none_or(|t| (t - o.ours).abs() > 5) {
            continue;
        }
        c.exited_at = Some(o.original);
        c.age_s = now - o.original;
        c.stale = now - o.original > stale_days as i64 * 86400;
    }
}

fn json_or_empty(s: &str) -> &str {
    if s.trim().is_empty() { "[]" } else { s }
}

pub fn parse_ps(json: &str, home: &str, now: i64, stale_days: u32) -> anyhow::Result<Vec<Ctr>> {
    let raw: Vec<RawCtr> = serde_json::from_str(json_or_empty(json))?;
    let mut out: Vec<Ctr> = raw
        .into_iter()
        .map(|r| {
            let labels = r.labels.unwrap_or_default();
            let kind = if labels
                .get("com.github.containers.toolbox")
                .is_some_and(|v| v == "true")
            {
                Kind::Toolbox
            } else if labels.get("manager").is_some_and(|v| v == "distrobox") {
                Kind::Distrobox
            } else {
                Kind::Podman
            };
            let home_mount = r.mounts.unwrap_or_default().iter().any(|m| {
                m == home || home.starts_with(&format!("{}/", m.trim_end_matches('/'))) && m != "/"
            });
            let running = r.state == "running";
            let exited_at = (r.exited_at > 0 && !running).then_some(r.exited_at);
            let age_s = now - exited_at.unwrap_or(r.created);
            Ctr {
                stale: !running
                    && r.state != "created"
                    && exited_at.is_some_and(|t| now - t > stale_days as i64 * 86400),
                name: r
                    .names
                    .first()
                    .cloned()
                    .unwrap_or_else(|| r.id.chars().take(12).collect()),
                id: r.id,
                kind,
                state: r.state,
                status: r.status,
                image: r.image,
                created: r.created,
                exited_at,
                home_mount,
                age_s,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        (!a.running(), a.kind as u8, &a.name).cmp(&(!b.running(), b.kind as u8, &b.name))
    });
    Ok(out)
}

pub fn parse_images(json: &str) -> anyhow::Result<Totals> {
    let raw: Vec<RawImage> = serde_json::from_str(json_or_empty(json))?;
    Ok(Totals {
        count: raw.len(),
        bytes: raw.iter().map(|i| i.size).sum(),
    })
}

pub fn parse_len(json: &str) -> anyhow::Result<usize> {
    Ok(serde_json::from_str::<Vec<serde_json::Value>>(json_or_empty(json))?.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_stops_keep_real_exit_time() {
        let now = 100 * 86400;
        let mut c = parse_ps(
            &crate::collectors::fixture("podman/ps.json"),
            "/var/home/user",
            now,
            30,
        )
        .unwrap();
        let i = c
            .iter()
            .position(|x| !x.running() && x.exited_at.is_some())
            .unwrap();
        let name = c[i].name.clone();
        let ours = c[i].exited_at.unwrap();
        let mut m = std::collections::BTreeMap::new();
        m.insert(
            name.clone(),
            OwnStop {
                ours,
                original: now - 64 * 86400,
            },
        );
        apply_own_stops(&mut c, &m, now, 30);
        assert_eq!(c[i].age_s, 64 * 86400);
        assert!(c[i].stale);
        // Used since (exit time moved again): the record no longer applies.
        let mut c2 = parse_ps(
            &crate::collectors::fixture("podman/ps.json"),
            "/var/home/user",
            now,
            30,
        )
        .unwrap();
        m.insert(
            name,
            OwnStop {
                ours: ours - 1000,
                original: 0,
            },
        );
        apply_own_stops(&mut c2, &m, now, 30);
        assert_eq!(c2[i].exited_at, Some(ours));
    }
    use crate::collectors::fixture;

    #[test]
    fn ps_fixture() {
        let now = 1_792_800_000;
        let c = parse_ps(&fixture("podman/ps.json"), "/var/home/user", now, 30).unwrap();
        let aip = c.iter().find(|c| c.name == "aip").unwrap();
        assert_eq!(aip.kind, Kind::Toolbox);
        assert!(aip.home_mount);
        let api = c.iter().find(|c| c.name == "webapp-api").unwrap();
        assert_eq!(api.kind, Kind::Podman);
        assert!(!api.home_mount);
        assert!(c[0].running(), "running first");
    }

    #[test]
    fn stale_and_distrobox() {
        let now = 100 * 86400;
        let j = r#"[{"Id":"abc","Names":["arch"],"State":"exited","Created":1,"ExitedAt":86400,
                     "Labels":{"manager":"distrobox"},"Mounts":["/var/home/u"]},
                    {"Id":"def","Names":["pg"],"State":"exited","Created":1,"ExitedAt":8000000,"Labels":null,"Mounts":null}]"#;
        let c = parse_ps(j, "/var/home/u", now, 30).unwrap();
        let arch = c.iter().find(|c| c.name == "arch").unwrap();
        assert!(arch.stale && arch.home_mount && arch.kind == Kind::Distrobox);
        assert!(!c.iter().find(|c| c.name == "pg").unwrap().stale);
    }

    #[test]
    fn image_totals() {
        let t = parse_images(&fixture("podman/images.json")).unwrap();
        assert!(t.count > 0 && t.bytes > 0);
        assert_eq!(parse_images("").unwrap().count, 0);
        assert!(parse_len(&fixture("podman/volumes.json")).unwrap() > 0);
    }
}

//! Keeping the maintenance list in step with the server: what's there but not tracked
//! (compose services, other containers, held packages, the kernel, GPU driver and container
//! engine, the OS release), and what's tracked but gone.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::version;
use crate::server::collect::docker::Docker;
use crate::server::config::{ImageRef, MaintItem, Risk, Server};
use crate::server::remote::{Remote, SrvError};

/// Packages worth tracking when installed: what a change to would ripple through the server.
/// Patterns as dpkg-query takes them.
const INFRA: &[(&str, &str, Risk)] = &[
    ("linux-image-amd64", "kernel", Risk::High),
    ("linux-image-arm64", "kernel", Risk::High),
    ("linux-image-generic", "kernel", Risk::High),
    ("nvidia-driver", "nvidia-driver", Risk::High),
    ("nvidia-driver-[0-9]*", "nvidia-driver", Risk::High),
    ("nvidia-container-toolkit", "nvidia-toolkit", Risk::Medium),
    ("docker-ce", "docker-engine", Risk::High),
    ("docker.io", "docker-engine", Risk::High),
    ("containerd.io", "containerd", Risk::High),
    ("podman", "podman", Risk::High),
];

/// Something on the server that isn't tracked, with the item that would track it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Candidate {
    /// Stable, for `ignore` (`image:web`, `held:a b`, `eol:debian/13`).
    pub key: String,
    /// In a few words, for the list.
    pub what: String,
    pub item: MaintItem,
}

/// A tracked item that isn't on the server any more.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Gone {
    pub id: String,
    pub why: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Found {
    pub candidates: Vec<Candidate>,
    pub gone: Vec<Gone>,
}

/// What the one ssh read says.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostFacts {
    pub held: Vec<String>,
    /// Installed packages asked about: name → version.
    pub installed: BTreeMap<String, String>,
    /// `/etc/os-release`: ID and VERSION_ID.
    pub os: Option<(String, String)>,
    /// Units asked about: unit → LoadState.
    pub units: BTreeMap<String, String>,
}

fn script(units: &[&str], pkgs: &[String]) -> String {
    let q = |s: &str| crate::exec::sh_quote(s);
    let pats: Vec<String> = INFRA
        .iter()
        .map(|(p, ..)| q(p))
        .chain(pkgs.iter().map(|p| q(p)))
        .collect();
    let units: Vec<String> = units.iter().map(|u| q(u)).collect();
    format!(
        "echo @@held; apt-mark showhold 2>/dev/null\n\
         echo @@pkgs; dpkg-query -W -f '${{db:Status-Abbrev}} ${{Package}} ${{Version}}\\n' {} 2>/dev/null\n\
         echo @@os; (. /etc/os-release && echo \"$ID $VERSION_ID\")\n\
         echo @@units; {}",
        pats.join(" "),
        if units.is_empty() {
            "true".to_string()
        } else {
            format!(
                "for u in {}; do echo \"$u $(systemctl show -p LoadState --value \"$u\")\"; done",
                units.join(" ")
            )
        }
    )
}

pub fn parse_facts(out: &str) -> HostFacts {
    let mut f = HostFacts::default();
    let mut sec = "";
    for l in out.lines() {
        if let Some(s) = l.strip_prefix("@@") {
            sec = match s.trim() {
                "held" => "held",
                "pkgs" => "pkgs",
                "os" => "os",
                "units" => "units",
                _ => "",
            };
            continue;
        }
        let l = l.trim();
        if l.is_empty() {
            continue;
        }
        match sec {
            "held" => f.held.push(l.to_string()),
            "pkgs" => {
                let w: Vec<&str> = l.split_whitespace().collect();
                if let [status, name, ver] = w[..]
                    && status.starts_with("ii")
                {
                    f.installed.insert(name.to_string(), ver.to_string());
                }
            }
            "os" => {
                if let Some((id, v)) = l.split_once(' ') {
                    f.os = Some((id.to_string(), v.trim_matches('"').to_string()));
                }
            }
            "units" => {
                if let Some((u, st)) = l.split_once(' ') {
                    f.units.insert(u.to_string(), st.to_string());
                }
            }
            _ => {}
        }
    }
    f
}

pub fn read_facts(r: &Remote, cfg: &Server) -> Result<HostFacts, SrvError> {
    let units: Vec<&str> = cfg
        .maintenance
        .items
        .iter()
        .filter_map(|i| i.unit.as_deref())
        .collect();
    let pkgs: Vec<String> = cfg
        .maintenance
        .items
        .iter()
        .flat_map(|i| i.apt.iter().cloned())
        .collect();
    Ok(parse_facts(&r.output(&r.sh(&script(&units, &pkgs)))?))
}

/// Source for an image by where it's hosted: `ghcr.io/o/a` → `ghcr:o/a`; anything else
/// without a registry → Docker Hub.
fn image_source(repo: &str) -> Option<String> {
    if let Some(rest) = repo.strip_prefix("ghcr.io/") {
        return Some(format!("ghcr:{rest}"));
    }
    let first = repo.split('/').next().unwrap_or("");
    // A registry host (has a dot or a port) other than ghcr: no lookup we know.
    if repo.contains('/') && (first.contains('.') || first.contains(':')) {
        return None;
    }
    Some(format!("docker:{repo}"))
}

fn repo_of(image: &str) -> String {
    match version::image_tag(image) {
        Some(t) => image.trim_end_matches(t).trim_end_matches(':').to_string(),
        None => image.to_string(),
    }
}

/// Compose services with an image: (project, service, image).
pub fn compose_services(project: &str, text: &str) -> Vec<(String, String, String)> {
    let Ok(v) = serde_saphyr::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    v["services"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(svc, def)| {
                    Some((
                        project.to_string(),
                        svc.clone(),
                        def["image"].as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Compare the list with the server. `compose`: each project's file text when it could be
/// read; `docker`: the containers when they could be read; `workflows`: the server's
/// workflow names (a tracked image gets compose-bump when there is one).
pub fn find(
    cfg: &Server,
    compose: &BTreeMap<String, Option<String>>,
    docker: Option<&Docker>,
    facts: Option<&HostFacts>,
    ignore: &[String],
    workflows: &[String],
) -> Found {
    let items = &cfg.maintenance.items;
    let mut out = Found::default();
    let mut add = |c: Candidate| {
        if !ignore.contains(&c.key) && !out.candidates.iter().any(|x| x.key == c.key) {
            out.candidates.push(c);
        }
    };
    let bump = workflows
        .iter()
        .any(|w| w == "compose-bump")
        .then(|| "compose-bump".to_string());
    // Compose services.
    let mut services: BTreeSet<String> = BTreeSet::new();
    let mut readable = false;
    for (project, text) in compose {
        let Some(text) = text else { continue };
        readable = true;
        for (proj, svc, image) in compose_services(project, text) {
            services.insert(svc.clone());
            let tracked = items.iter().any(|i| {
                i.image
                    .as_ref()
                    .is_some_and(|r| r.service.as_deref() == Some(svc.as_str()))
            });
            if !tracked {
                let repo = repo_of(&image);
                add(Candidate {
                    key: format!("image:{svc}"),
                    what: format!("compose service {svc} ({image})"),
                    item: MaintItem {
                        id: svc.clone(),
                        image: Some(ImageRef {
                            service: Some(svc),
                            compose: (cfg.compose.len() > 1).then_some(proj),
                            container: None,
                        }),
                        source: image_source(&repo),
                        workflow: bump.clone(),
                        ..Default::default()
                    },
                });
            }
        }
    }
    // Containers not run by compose.
    if let Some(d) = docker {
        for c in d.containers.iter().filter(|c| c.compose.is_none()) {
            let tracked = items.iter().any(|i| {
                i.image
                    .as_ref()
                    .is_some_and(|r| r.container.as_deref() == Some(c.name.as_str()))
            });
            if !tracked && !c.finished() {
                let repo = repo_of(&c.image);
                add(Candidate {
                    key: format!("container:{}", c.name),
                    what: format!("container {} ({}), not run by compose", c.name, c.image),
                    item: MaintItem {
                        id: c.name.clone(),
                        image: Some(ImageRef {
                            container: Some(c.name.clone()),
                            ..Default::default()
                        }),
                        source: image_source(&repo),
                        ..Default::default()
                    },
                });
            }
        }
    }
    let covered = |p: &str| items.iter().any(|i| i.apt.iter().any(|a| a == p));
    if let Some(f) = facts {
        // Held packages nothing tracks: one item for the set (they're held together).
        let loose: Vec<String> = f.held.iter().filter(|p| !covered(p)).cloned().collect();
        if !loose.is_empty() {
            add(Candidate {
                key: format!("held:{}", loose.join(" ")),
                what: format!("held packages: {}", loose.join(" ")),
                item: MaintItem {
                    id: format!("held-{}", loose[0]),
                    apt: loose.clone(),
                    risk: Risk::High,
                    hold: Some("held with apt-mark hold".into()),
                    ..Default::default()
                },
            });
        }
        // Infrastructure packages.
        for (name, ver) in &f.installed {
            if covered(name) || f.held.contains(name) {
                continue;
            }
            let Some((_, id, risk)) = INFRA.iter().find(|(p, ..)| {
                p.strip_suffix("[0-9]*")
                    .map_or(*p == name, |pre| name.starts_with(pre))
            }) else {
                continue;
            };
            if items.iter().any(|i| i.id == *id) {
                continue;
            }
            add(Candidate {
                key: format!("apt:{name}"),
                what: format!("package {name} {ver}"),
                item: MaintItem {
                    id: id.to_string(),
                    apt: vec![name.clone()],
                    risk: *risk,
                    ..Default::default()
                },
            });
        }
        // The OS release's end of life.
        if let Some((id, v)) = &f.os {
            let cycle = if id == "debian" {
                v.split('.').next().unwrap_or(v).to_string()
            } else {
                v.clone()
            };
            let key = format!("{id}/{cycle}");
            if !items.iter().any(|i| i.eol.as_deref() == Some(key.as_str())) {
                add(Candidate {
                    key: format!("eol:{key}"),
                    what: format!("{id} {v}: its end of life"),
                    item: MaintItem {
                        id: id.clone(),
                        eol: Some(key),
                        risk: Risk::High,
                        ..Default::default()
                    },
                });
            }
        }
    }
    // Tracked but gone.
    for it in items {
        let why = if let Some(img) = &it.image {
            match (&img.service, &img.container) {
                (Some(s), _) if readable && !services.contains(s) => {
                    Some(format!("no service {s} in the compose file any more"))
                }
                (None, Some(c))
                    if docker.is_some_and(|d| !d.containers.iter().any(|x| &x.name == c)) =>
                {
                    Some(format!("no container {c} any more"))
                }
                _ => None,
            }
        } else if let (Some(f), Some(p)) = (facts, it.apt.first()) {
            (!f.installed.contains_key(p)).then(|| format!("{p} isn't installed any more"))
        } else {
            None
        };
        let why = why.or_else(|| {
            let u = it.unit.as_deref()?;
            let st = facts?.units.get(u)?;
            (st == "not-found").then(|| format!("{u} doesn't exist any more"))
        });
        if let Some(why) = why {
            out.gone.push(Gone {
                id: it.id.clone(),
                why,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::collect::docker::Container;

    fn cfg() -> Server {
        let mut s = Server::default();
        s.compose.push(crate::server::config::Compose {
            name: "stack".into(),
            file: "/srv/stack/compose.yaml".into(),
        });
        s.maintenance.items = vec![
            MaintItem {
                id: "web".into(),
                image: Some(ImageRef {
                    service: Some("web".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            MaintItem {
                id: "old".into(),
                image: Some(ImageRef {
                    service: Some("old".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            MaintItem {
                id: "engine".into(),
                apt: vec!["engine-pkg".into()],
                ..Default::default()
            },
            MaintItem {
                id: "legacy".into(),
                unit: Some("legacy.service".into()),
                ..Default::default()
            },
        ];
        s
    }

    #[test]
    fn host_facts_parse() {
        let f = parse_facts(
            "@@held\nengine-pkg\nengine-cli\n@@pkgs\nii  linux-image-amd64 6.1.1\nun  podman <none>\nii  engine-pkg 24.3\n@@os\ndebian 12\n@@units\nlegacy.service not-found\n",
        );
        assert_eq!(f.held, ["engine-pkg", "engine-cli"]);
        assert_eq!(f.installed.len(), 2, "only installed ones");
        assert_eq!(f.os, Some(("debian".into(), "12".into())));
        assert_eq!(f.units["legacy.service"], "not-found");
        assert!(
            script(&["legacy.service"], &["engine-pkg".into()]).contains("'nvidia-driver-[0-9]*'")
        );
    }

    #[test]
    fn what_isnt_tracked_and_what_is_gone() {
        let mut compose = BTreeMap::new();
        compose.insert(
            "stack".to_string(),
            Some("services:\n  web:\n    image: example/web:1.2\n  db:\n    image: postgres:16.4\n  ui:\n    image: ghcr.io/org/ui:v0.7\n".to_string()),
        );
        let docker = Docker {
            containers: vec![Container {
                name: "runner".into(),
                image: "example/runner:v3".into(),
                status: "running".into(),
                ..Default::default()
            }],
            projects: Vec::new(),
        };
        let facts = parse_facts(
            "@@held\nengine-pkg\nengine-cli\n@@pkgs\nii linux-image-amd64 6.1.1\nii engine-pkg 24.3\n@@os\ndebian 12.7\n@@units\nlegacy.service not-found\n",
        );
        let f = find(
            &cfg(),
            &compose,
            Some(&docker),
            Some(&facts),
            &["image:ui".to_string()],
            &["compose-bump".to_string()],
        );
        let keys: Vec<&str> = f.candidates.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "image:db",
                "container:runner",
                "held:engine-cli",
                "apt:linux-image-amd64",
                "eol:debian/12"
            ],
            "ui is ignored; engine-pkg is tracked"
        );
        let db = &f.candidates[0].item;
        assert_eq!(db.source.as_deref(), Some("docker:postgres"));
        assert_eq!(db.workflow.as_deref(), Some("compose-bump"));
        assert_eq!(f.candidates[3].item.id, "kernel");
        let gone: Vec<(&str, &str)> = f
            .gone
            .iter()
            .map(|g| (g.id.as_str(), g.why.as_str()))
            .collect();
        assert_eq!(
            gone,
            [
                ("old", "no service old in the compose file any more"),
                ("legacy", "legacy.service doesn't exist any more")
            ]
        );
        assert_eq!(image_source("ghcr.io/org/ui"), Some("ghcr:org/ui".into()));
        assert_eq!(image_source("registry.example:5000/x/y"), None);
    }
}

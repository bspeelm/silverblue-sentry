//! What the server has for each maintenance item: the pinned version (compose file, installed
//! package), what actually runs (`docker inspect`), apt's candidate and holds. Read over ssh;
//! the compose file and docker may come from the inventory when sudo asks for a password.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::version;
use crate::server::collect::docker;
use crate::server::config::{MaintItem, Server};
use crate::server::remote::{Remote, SrvError};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Local {
    /// What the config pins (compose tag) or what's installed (package, app).
    pub pinned: Option<String>,
    /// What runs (a container's image tag), when that can differ from the pin.
    pub running: Option<String>,
    /// apt's candidate, for packages.
    pub candidate: Option<String>,
    /// The image's repository as pinned (`example/web`), so a new tag can go with it.
    pub repo: Option<String>,
    /// All its packages are on `apt-mark hold`.
    pub held: bool,
    /// Why something couldn't be read.
    pub note: Option<String>,
}

/// The image a compose service pins, from the compose file's text.
pub fn compose_image(text: &str, service: &str) -> Option<String> {
    let v: serde_json::Value = serde_saphyr::from_str(text).ok()?;
    v["services"][service]["image"].as_str().map(str::to_string)
}

/// Installed versions, held packages, apt's candidates.
type AptState = (
    BTreeMap<String, String>,
    Vec<String>,
    BTreeMap<String, String>,
);

/// `dpkg-query -W -f '${Package} ${Version}\n'`, `apt-mark showhold`, `apt-cache policy`, in
/// one ssh call separated by marker lines.
fn apt_state(r: &Remote, pkgs: &[&str]) -> Result<AptState, SrvError> {
    let list = pkgs
        .iter()
        .map(|p| crate::exec::sh_quote(p))
        .collect::<Vec<_>>()
        .join(" ");
    let out = r.output(&r.sh(&format!(
        "dpkg-query -W -f '${{Package}} ${{Version}}\\n' {list} 2>/dev/null; echo @@hold; \
         apt-mark showhold; echo @@policy; apt-cache policy {list}"
    )))?;
    Ok(parse_apt_state(&out))
}

pub fn parse_apt_state(out: &str) -> AptState {
    let (installed, rest) = out.split_once("@@hold\n").unwrap_or((out, ""));
    let (held, policy) = rest.split_once("@@policy\n").unwrap_or((rest, ""));
    let installed = installed
        .lines()
        .filter_map(|l| l.split_once(' '))
        .filter(|(_, v)| !v.is_empty())
        .map(|(p, v)| (p.to_string(), v.to_string()))
        .collect();
    let held = held.lines().map(|l| l.trim().to_string()).collect();
    let mut candidates = BTreeMap::new();
    let mut cur: Option<String> = None;
    for l in policy.lines() {
        if !l.starts_with(' ') && l.ends_with(':') {
            cur = Some(l.trim_end_matches(':').to_string());
        } else if let (Some(p), Some(c)) = (&cur, l.trim().strip_prefix("Candidate:")) {
            let c = c.trim();
            if c != "(none)" {
                candidates.insert(p.clone(), c.to_string());
            }
        }
    }
    (installed, held, candidates)
}

/// The compose file's text: read directly when the login can, else from the inventory.
fn compose_text(r: &Remote, file: &str) -> Result<String, String> {
    let c = r.cmd("cat").arg(file);
    match r.output(&c) {
        Ok(t) => Ok(t),
        Err(e) => {
            if r.inventory
                && let Some(cap) = crate::server::inventory::lookup(&r.name, &c.quoted_argv())
                && cap.code == 0
            {
                return Ok(cap.out);
            }
            Err(match e {
                SrvError::Failed(m) if m.contains("Permission denied") => {
                    format!("{file} is readable only with sudo: I (in the TUI) reads it once")
                }
                e => format!("{file}: {e}"),
            })
        }
    }
}

/// Read every item's state.
pub fn read(r: &Remote, cfg: &Server) -> BTreeMap<String, Local> {
    let items = &cfg.maintenance.items;
    let mut out: BTreeMap<String, Local> = BTreeMap::new();
    let wants_docker = items.iter().any(|i| i.image.is_some());
    let docker = wants_docker.then(|| docker::collect(r));
    let mut composes: BTreeMap<String, Result<String, String>> = BTreeMap::new();
    let pkgs: Vec<&str> = items
        .iter()
        .flat_map(|i| i.apt.iter().map(String::as_str))
        .collect();
    let apt = (!pkgs.is_empty()).then(|| apt_state(r, &pkgs));
    for it in items {
        let mut l = Local::default();
        if let Some(img) = &it.image {
            if let Some(svc) = &img.service {
                let proj = img
                    .compose
                    .as_ref()
                    .and_then(|n| cfg.compose.iter().find(|c| &c.name == n))
                    .or_else(|| cfg.compose.first());
                match proj {
                    Some(p) => {
                        let text = composes
                            .entry(p.file.clone())
                            .or_insert_with(|| compose_text(r, &p.file));
                        match text {
                            Ok(t) => match compose_image(t, svc) {
                                Some(image) => {
                                    l.pinned = version::image_tag(&image).map(str::to_string);
                                    l.repo = Some(match &l.pinned {
                                        Some(t) => image
                                            .trim_end_matches(t.as_str())
                                            .trim_end_matches(':')
                                            .to_string(),
                                        None => image.clone(),
                                    });
                                }
                                None => l.note = Some(format!("no image for {svc} in {}", p.file)),
                            },
                            Err(e) => l.note = Some(e.clone()),
                        }
                    }
                    None => l.note = Some("no compose: project".into()),
                }
            }
            match &docker {
                Some(Ok(d)) => {
                    let c = d
                        .containers
                        .iter()
                        .find(|c| match (&img.service, &img.container) {
                            (Some(s), _) => c.service.as_deref() == Some(s.as_str()),
                            (None, Some(n)) => &c.name == n,
                            _ => false,
                        });
                    l.running = c.and_then(|c| version::image_tag(&c.image).map(str::to_string));
                    if img.container.is_some() {
                        // Not run by compose: what runs is its pin.
                        l.pinned = l.running.clone();
                    }
                }
                Some(Err(e)) => {
                    l.note.get_or_insert_with(|| format!("docker: {e}"));
                }
                None => {}
            }
        } else if !it.apt.is_empty() {
            match &apt {
                Some(Ok((installed, held, cand))) => {
                    // The first package stands for the set (they move together).
                    let first = &it.apt[0];
                    l.pinned = installed.get(first).cloned();
                    l.running = l.pinned.clone();
                    l.candidate = cand.get(first).cloned();
                    l.held = it.apt.iter().all(|p| held.contains(p));
                    if l.pinned.is_none() {
                        l.note = Some(format!("{first} isn't installed"));
                    }
                }
                Some(Err(e)) => l.note = Some(e.to_string()),
                None => {}
            }
        } else if let Some(cmd) = &it.version_cmd {
            match r.output(&r.sh(cmd)) {
                Ok(o) => {
                    l.pinned = version::find(&o);
                    l.running = l.pinned.clone();
                    if l.pinned.is_none() {
                        l.note = Some(format!("no version in `{cmd}`'s output"));
                    }
                }
                Err(e) => l.note = Some(e.to_string()),
            }
        }
        out.insert(it.id.clone(), l);
    }
    out
}

/// The vars a workflow gets for an item (`p` on the Maintenance tab): a compose service and its
/// new image, or the unit being retired.
pub fn vars_for(it: &MaintItem, l: &Local, target: Option<&str>) -> BTreeMap<String, String> {
    let mut v = BTreeMap::new();
    if let Some(svc) = it.image.as_ref().and_then(|i| i.service.as_ref()) {
        v.insert("service".into(), svc.clone());
        // The repository as pinned; else the source's, when it names an image.
        let repo = l.repo.clone().or_else(|| {
            let (kind, repo) = it.source.as_deref()?.split_once(':')?;
            match kind {
                "ghcr" => Some(format!("ghcr.io/{repo}")),
                "docker" => Some(repo.to_string()),
                _ => None,
            }
        });
        if let (Some(repo), Some(t)) = (repo, target) {
            v.insert("image".into(), format!("{repo}:{t}"));
        }
    }
    if let Some(ret) = &it.retire {
        if let Some(u) = &it.unit {
            v.insert("unit".into(), u.clone());
        }
        if let Some(r) = &ret.replaced_by {
            v.insert("replaced_by".into(), r.clone());
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_pins() {
        let text = "name: stack\nservices:\n  web:\n    image: example/web:1.2.3   # pin\n  db:\n    image: postgres:16.4-alpine\n";
        assert_eq!(
            compose_image(text, "web").as_deref(),
            Some("example/web:1.2.3")
        );
        assert_eq!(
            compose_image(text, "db").as_deref(),
            Some("postgres:16.4-alpine")
        );
        assert_eq!(compose_image(text, "nope"), None);
    }

    #[test]
    fn apt_state_parses() {
        let out = "engine-pkg 5:24.3.1-1~deb12\nengine-cli 5:24.3.1-1~deb12\n@@hold\nengine-cli\nengine-pkg\n@@policy\n\
engine-pkg:\n  Installed: 5:24.3.1-1~deb12\n  Candidate: 5:24.4.0-1~deb12\n  Version table:\n\
engine-cli:\n  Installed: 5:24.3.1-1~deb12\n  Candidate: 5:24.4.0-1~deb12\n";
        let (inst, held, cand) = parse_apt_state(out);
        assert_eq!(inst["engine-pkg"], "5:24.3.1-1~deb12");
        assert_eq!(held, ["engine-cli", "engine-pkg"]);
        assert_eq!(cand["engine-cli"], "5:24.4.0-1~deb12");
    }
}

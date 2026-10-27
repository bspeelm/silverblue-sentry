//! Items sentry-server tracks for you: `servers/<name>/items.toml`, written when you track
//! something discovery found (`t` on Maintenance), and what you chose to ignore. Merged with
//! `maintenance.items` from server_config.yaml, which wins on the same id; sentry-server
//! never rewrites the YAML. Edit this file freely.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::paths;
use crate::server::config::{MaintItem, Server};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Tracked {
    /// Discovered things you don't want tracked or suggested again (discovery keys).
    pub ignore: Vec<String>,
    pub items: Vec<MaintItem>,
}

pub fn path(server: &str) -> PathBuf {
    paths::config_dir()
        .join("servers")
        .join(server)
        .join("items.toml")
}

pub fn load(server: &str) -> Tracked {
    std::fs::read_to_string(path(server))
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

fn save(server: &str, t: &Tracked) -> anyhow::Result<()> {
    let p = path(server);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let text = file_text(t)?;
    paths::write_atomic(&p, text.as_bytes())?;
    Ok(())
}

fn file_text(t: &Tracked) -> anyhow::Result<String> {
    Ok(format!(
        "# Maintenance items sentry-server tracks for you (t on the Maintenance tab), and what\n\
         # you chose to ignore (x). Items in server_config.yaml win on the same id. Edit freely.\n\n{}",
        toml::to_string(t)?
    ))
}

pub fn track(server: &str, item: MaintItem) -> anyhow::Result<()> {
    let mut t = load(server);
    t.items.retain(|i| i.id != item.id);
    t.items.push(item);
    save(server, &t)
}

pub fn ignore(server: &str, key: &str) -> anyhow::Result<()> {
    let mut t = load(server);
    if !t.ignore.iter().any(|k| k == key) {
        t.ignore.push(key.to_string());
    }
    save(server, &t)
}

/// Stop tracking one of sentry-server's own items (one from the YAML stays: edit it there).
pub fn untrack(server: &str, id: &str) -> anyhow::Result<bool> {
    let mut t = load(server);
    let before = t.items.len();
    t.items.retain(|i| i.id != id);
    let gone = t.items.len() != before;
    if gone {
        save(server, &t)?;
    }
    Ok(gone)
}

/// The server's config with the tracked items added (the YAML's win on the same id).
pub fn merged(cfg: &Server, t: &Tracked) -> Server {
    let mut s = cfg.clone();
    for it in &t.items {
        if !s.maintenance.items.iter().any(|i| i.id == it.id) {
            s.maintenance.items.push(it.clone());
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_yaml_wins_and_tracked_items_are_added() {
        let mut cfg = Server::default();
        cfg.maintenance.items.push(MaintItem {
            id: "web".into(),
            version_cmd: Some("web --version".into()),
            ..Default::default()
        });
        let t = Tracked {
            ignore: vec!["image:db".into()],
            items: vec![
                MaintItem {
                    id: "web".into(),
                    apt: vec!["other".into()],
                    ..Default::default()
                },
                MaintItem {
                    id: "cache".into(),
                    apt: vec!["cache-pkg".into()],
                    ..Default::default()
                },
            ],
        };
        let m = merged(&cfg, &t);
        let ids: Vec<&str> = m.maintenance.items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["web", "cache"]);
        assert!(
            m.maintenance.items[0].version_cmd.is_some(),
            "the YAML's web"
        );
        let back: Tracked = toml::from_str(&toml::to_string(&t).unwrap()).unwrap();
        assert_eq!(back, t);
        // What save writes parses back, header and all.
        assert_eq!(
            toml::from_str::<Tracked>(&file_text(&t).unwrap()).unwrap(),
            t
        );
    }
}

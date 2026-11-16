//! Items sentry-server tracks for you: `servers/<name>/items.toml`, written when you track
//! something discovery found (`t` on Maintenance), and what you chose to ignore. Merged with
//! `maintenance.items` from server_config.yaml, which wins on the same id; sentry-server
//! never rewrites the YAML. What a review changes about a YAML item is kept here instead and
//! applied over it: `untracked` (ids not tracked after all) and `[set.<id>]` (its risk, hold,
//! constraint or source). Edit this file freely.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::discover::Candidate;
use crate::config::{MaintItem, Risk, Server};
use sentry_core::maint::changes::{Change, ItemSet, Kind};
use sentry_core::paths;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Tracked {
    /// Discovered things you don't want tracked or suggested again (discovery keys).
    pub ignore: Vec<String>,
    /// Items from server_config.yaml that aren't tracked after all (their ids).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub untracked: Vec<String>,
    /// Changes to items from server_config.yaml, by id, applied over it.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<String, ItemSet>,
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

pub fn save(server: &str, t: &Tracked) -> anyhow::Result<()> {
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
        "# Maintenance items sentry-server tracks for you (t on Maintenance), and what\n\
         # you chose to ignore (x). Items in server_config.yaml win on the same id, except for\n\
         # what a review changed about them: `untracked` ids and `[set.<id>]`. Edit freely.\n\n{}",
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

/// Suggest it again (Records › Later, `u`).
pub fn unignore(server: &str, key: &str) -> anyhow::Result<()> {
    let mut t = load(server);
    t.ignore.retain(|k| k != key);
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

/// Track a YAML item again (Records › Later, `u`).
pub fn retrack(server: &str, id: &str) -> anyhow::Result<()> {
    let mut t = load(server);
    t.untracked.retain(|i| i != id);
    save(server, &t)
}

/// What a change sets, on an item.
fn set_on(it: &mut MaintItem, set: &ItemSet) {
    if let Some(r) = &set.risk {
        it.risk = match r.as_str() {
            "low" => Risk::Low,
            "high" => Risk::High,
            _ => Risk::Medium,
        };
    }
    for (to, from) in [
        (&mut it.hold, &set.hold),
        (&mut it.constraint, &set.constraint),
        (&mut it.source, &set.source),
    ] {
        if from.is_some() {
            *to = from.clone();
        }
    }
}

/// One of a review's changes to the items, on what's in memory. `yaml` is the ids
/// server_config.yaml defines (never rewritten: their changes go to `untracked` and `set`).
/// None: not about items.
pub fn apply(
    t: &mut Tracked,
    c: &Change,
    yaml: &[String],
    found: &[Candidate],
) -> Option<Result<String, String>> {
    Some(match &c.kind {
        Kind::Track { key, set } => match found.iter().find(|x| &x.key == key) {
            Some(cand) => {
                let mut it = cand.item.clone();
                set_on(&mut it, set);
                t.items.retain(|i| i.id != it.id);
                t.untracked.retain(|i| i != &it.id);
                let id = it.id.clone();
                t.items.push(it);
                Ok(format!("tracking {id} (items.toml)"))
            }
            None => Err(format!("{key} isn't there any more")),
        },
        Kind::Ignore { key } => {
            if !t.ignore.contains(key) {
                t.ignore.push(key.clone());
            }
            Ok("won't be suggested again (items.toml)".into())
        }
        Kind::Untrack { id } => {
            let own = t.items.iter().any(|i| &i.id == id);
            t.items.retain(|i| &i.id != id);
            t.set.remove(id);
            if yaml.contains(id) {
                if !t.untracked.contains(id) {
                    t.untracked.push(id.clone());
                }
                Ok("not tracked any more (untracked in items.toml; server_config.yaml still defines it)".into())
            } else if own {
                Ok("not tracked any more (items.toml)".into())
            } else {
                Err(format!("no item {id} any more"))
            }
        }
        Kind::SetItem { id, set } => {
            if yaml.contains(id) {
                let s = t.set.entry(id.clone()).or_default();
                for (to, from) in [
                    (&mut s.risk, &set.risk),
                    (&mut s.hold, &set.hold),
                    (&mut s.constraint, &set.constraint),
                    (&mut s.source, &set.source),
                ] {
                    if from.is_some() {
                        *to = from.clone();
                    }
                }
                Ok(format!(
                    "written to items.toml ([set.{id}], over server_config.yaml)"
                ))
            } else if let Some(it) = t.items.iter_mut().find(|i| &i.id == id) {
                set_on(it, set);
                Ok("written to items.toml".into())
            } else {
                Err(format!("no item {id} any more"))
            }
        }
        _ => return None,
    })
}

/// The server's config with the tracked items added (the YAML's win on the same id), and
/// what was changed about the YAML's own: those untracked left out, `set` applied.
pub fn merged(cfg: &Server, t: &Tracked) -> Server {
    let mut s = cfg.clone();
    s.maintenance.items.retain(|i| !t.untracked.contains(&i.id));
    for it in &mut s.maintenance.items {
        if let Some(set) = t.set.get(&it.id) {
            set_on(it, set);
        }
    }
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
            untracked: Vec::new(),
            set: BTreeMap::new(),
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

    #[test]
    fn a_review_s_item_changes_apply_over_the_yaml() {
        let mut cfg = Server::default();
        for id in ["web", "legacy"] {
            cfg.maintenance.items.push(MaintItem {
                id: id.into(),
                ..Default::default()
            });
        }
        let yaml = vec!["web".to_string(), "legacy".to_string()];
        let found = vec![Candidate {
            key: "image:cache".into(),
            what: "image cache".into(),
            item: MaintItem {
                id: "cache".into(),
                ..Default::default()
            },
        }];
        let ch = |kind: Kind| Change {
            why: String::new(),
            state: Default::default(),
            label: String::new(),
            note: String::new(),
            on: true,
            kind,
        };
        let high = ItemSet {
            risk: Some("high".into()),
            hold: Some("2.0 migrates the database".into()),
            ..Default::default()
        };
        let mut t = Tracked::default();
        for (c, says) in [
            (
                ch(Kind::Track {
                    key: "image:cache".into(),
                    set: high.clone(),
                }),
                "tracking cache",
            ),
            (
                ch(Kind::Ignore {
                    key: "apt:podman".into(),
                }),
                "won't be suggested",
            ),
            (
                ch(Kind::Untrack {
                    id: "legacy".into(),
                }),
                "untracked in items.toml",
            ),
            (
                ch(Kind::SetItem {
                    id: "web".into(),
                    set: high.clone(),
                }),
                "[set.web]",
            ),
            (
                ch(Kind::SetItem {
                    id: "cache".into(),
                    set: ItemSet {
                        risk: Some("low".into()),
                        ..Default::default()
                    },
                }),
                "written to items.toml",
            ),
        ] {
            let note = apply(&mut t, &c, &yaml, &found).unwrap().unwrap();
            assert!(note.contains(says), "{note}");
        }
        // Not about items; gone since.
        assert!(apply(&mut t, &ch(Kind::Back { key: "x".into() }), &yaml, &found).is_none());
        assert!(
            apply(
                &mut t,
                &ch(Kind::Untrack { id: "nope".into() }),
                &yaml,
                &found
            )
            .unwrap()
            .is_err()
        );
        let m = merged(&cfg, &t);
        let ids: Vec<&str> = m.maintenance.items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["web", "cache"], "legacy is untracked");
        assert_eq!(m.maintenance.items[0].risk, Risk::High);
        assert_eq!(
            m.maintenance.items[0].hold.as_deref(),
            Some("2.0 migrates the database")
        );
        assert_eq!(m.maintenance.items[1].risk, Risk::Low, "set after tracking");
        assert_eq!(t.ignore, ["apt:podman"]);
        // The file round-trips with what was changed, and untracking one of its own drops it.
        assert_eq!(
            toml::from_str::<Tracked>(&file_text(&t).unwrap()).unwrap(),
            t
        );
        let note = apply(
            &mut t,
            &ch(Kind::Untrack { id: "cache".into() }),
            &yaml,
            &found,
        );
        assert_eq!(note.unwrap().unwrap(), "not tracked any more (items.toml)");
        assert!(t.items.is_empty());
    }
}

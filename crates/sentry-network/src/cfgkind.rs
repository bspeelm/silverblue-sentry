//! `network_config.yaml` as the window's Config area knows it (`sentry_app::cfgarea::Kind`):
//! each network an entry with a line about it, its essential settings, and what its lint
//! says. (Its forms, discovery and adding or removing a network come with the next part.)

use std::path::Path;

use sentry_app::cfgarea::kind::{self, DocAny, Entry, Kind, Loaded, Section};
use sentry_app::cfgarea::{Problem, Screen};
use sentry_core::cfg::{ConfigFile, Field, FileId, Seg, path_string};

use crate::config::{self, NetworkFile};

pub struct NetworksKind;

/// What is wrong in the networks' file: what its parse said, then each network's lint.
pub fn problems(file: &NetworkFile, warnings: &[String]) -> Vec<Problem> {
    let mut out: Vec<Problem> = warnings
        .iter()
        .map(|w| Problem::of(FileId::Networks, None, w))
        .collect();
    for (n, net) in &file.networks {
        out.extend(
            config::lint(n, net)
                .iter()
                .map(|p| Problem::of(FileId::Networks, Some(n), p)),
        );
    }
    out
}

fn counted(n: usize, what: &str) -> Option<String> {
    match n {
        0 => None,
        1 => Some(format!("1 {what}")),
        n => Some(format!("{n} {what}s")),
    }
}

impl Kind for NetworksKind {
    fn id(&self) -> FileId {
        FileId::Networks
    }

    fn load(&self, path: &Path) -> Loaded {
        kind::load::<NetworkFile>(path)
    }

    fn fields(&self) -> &'static [Field] {
        NetworkFile::FIELDS
    }

    fn entries(&self, d: &dyn DocAny) -> Vec<Entry> {
        let Some(file) = kind::typed::<NetworkFile>(d) else {
            return Vec::new();
        };
        file.networks
            .iter()
            .map(|(name, n)| {
                // (Never a device's name, address or MAC here: counts only.)
                let mut parts = vec![format!(
                    "router over ssh {}",
                    n.router.ssh.as_deref().unwrap_or(name)
                )];
                parts.extend(
                    [
                        counted(n.expect.zones.len(), "zone"),
                        counted(n.expect.forwards.len(), "forward"),
                        counted(n.devices.len(), "device"),
                    ]
                    .into_iter()
                    .flatten(),
                );
                parts.push(match n.backup.recipients.len() {
                    0 => "no backup recipient".to_string(),
                    _ => "backups encrypted".to_string(),
                });
                Entry {
                    name: name.clone(),
                    kind: "network",
                    summary: parts.join(" · "),
                    target: Some(crate::tui::id_of(name)),
                    screen: Screen::Networks,
                }
            })
            .collect()
    }

    fn sections(&self, _d: &dyn DocAny, entry: &str) -> Vec<Section> {
        let at = path_string(&[Seg::Key("networks".into()), Seg::Key(entry.to_string())]);
        vec![Section {
            title: "What sentry watches here".to_string(),
            items: kind::essentials(NetworkFile::FIELDS, "networks.*", &at),
        }]
    }

    fn problems(&self, d: &dyn DocAny, warnings: &[String]) -> Vec<Problem> {
        match kind::typed::<NetworkFile>(d) {
            Some(file) => problems(file, warnings),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_network_is_an_entry_that_names_no_device() {
        let dir = std::env::temp_dir().join(format!("sentry-netkind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("network_config.yaml");
        std::fs::write(
            &path,
            "networks:\n  home:\n    router: {ssh: myrouter}\n    devices:\n      - {name: nas, mac: \"02:00:5E:00:53:01\"}\n    backup: {keep: 0}\n",
        )
        .unwrap();
        let k = NetworksKind;
        let (doc, warnings) = k.load(&path).unwrap();
        let e = k.entries(doc.as_ref());
        assert_eq!(e.len(), 1);
        assert_eq!(
            (
                e[0].name.as_str(),
                e[0].summary.as_str(),
                e[0].target.as_deref()
            ),
            (
                "home",
                "router over ssh myrouter · 1 device · no backup recipient",
                Some("net:home")
            )
        );
        let items: Vec<String> = k
            .sections(doc.as_ref(), "home")
            .into_iter()
            .flat_map(|s| s.items)
            .map(|i| i.path)
            .collect();
        assert!(
            items.contains(&"networks.home.router.ssh".to_string()),
            "{items:?}"
        );
        for p in &items {
            let f = sentry_core::cfg::fields::find(k.fields(), p).unwrap_or_else(|| panic!("{p}"));
            assert!(f.essential, "{p}");
        }
        assert_eq!(
            k.problems(doc.as_ref(), &warnings)
                .iter()
                .map(Problem::line)
                .collect::<Vec<_>>(),
            ["network_config.yaml · home: backup: keep must be at least 1"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

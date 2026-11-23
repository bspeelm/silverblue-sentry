//! `server_config.yaml` as the window's Config area knows it (`sentry_app::cfgarea::Kind`):
//! each server an entry with a line about it, its essential settings, and what its lint
//! says. (Its forms, discovery and adding or removing a server come with the next part.)

use std::path::Path;

use sentry_app::cfgarea::kind::{self, DocAny, Entry, Kind, Loaded, Section};
use sentry_app::cfgarea::{Problem, Screen};
use sentry_core::cfg::{ConfigFile, Field, FileId, Seg, path_string};

use crate::config::{self, ServerFile};

pub struct ServersKind;

/// What is wrong in the servers' file: what its parse said, then each server's lint.
pub fn problems(file: &ServerFile, warnings: &[String]) -> Vec<Problem> {
    let mut out: Vec<Problem> = warnings
        .iter()
        .map(|w| Problem::of(FileId::Servers, None, w))
        .collect();
    for (n, s) in &file.servers {
        out.extend(
            config::lint(n, s)
                .iter()
                .map(|p| Problem::of(FileId::Servers, Some(n), p)),
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

impl Kind for ServersKind {
    fn id(&self) -> FileId {
        FileId::Servers
    }

    fn load(&self, path: &Path) -> Loaded {
        kind::load::<ServerFile>(path)
    }

    fn fields(&self) -> &'static [Field] {
        ServerFile::FIELDS
    }

    fn entries(&self, d: &dyn DocAny) -> Vec<Entry> {
        let Some(file) = kind::typed::<ServerFile>(d) else {
            return Vec::new();
        };
        file.servers
            .iter()
            .map(|(name, s)| {
                let mut parts = vec![format!("ssh {}", s.ssh.as_deref().unwrap_or(name))];
                parts.extend(
                    [
                        counted(s.services.len(), "service"),
                        counted(s.timers.len(), "timer"),
                        counted(s.disks.len(), "disk"),
                        counted(s.compose.len(), "compose project"),
                        counted(s.maintenance.items.len(), "tracked item"),
                    ]
                    .into_iter()
                    .flatten(),
                );
                Entry {
                    name: name.clone(),
                    kind: "server",
                    summary: parts.join(" · "),
                    target: Some(crate::tui::id_of(name)),
                    screen: Screen::Servers,
                }
            })
            .collect()
    }

    fn sections(&self, _d: &dyn DocAny, entry: &str) -> Vec<Section> {
        let at = path_string(&[Seg::Key("servers".into()), Seg::Key(entry.to_string())]);
        vec![Section {
            title: "What sentry watches here".to_string(),
            items: kind::essentials(ServerFile::FIELDS, "servers.*", &at),
        }]
    }

    fn problems(&self, d: &dyn DocAny, warnings: &[String]) -> Vec<Problem> {
        match kind::typed::<ServerFile>(d) {
            Some(file) => problems(file, warnings),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_server_is_an_entry_with_its_essential_settings() {
        let dir = std::env::temp_dir().join(format!("sentry-srvkind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server_config.yaml");
        std::fs::write(
            &path,
            "servers:\n  myserver:\n    ssh: admin@192.0.2.10\n    services: [app.service]\n    timers: [{unit: x, max_age: 1d}]\n  my.other: {}\n",
        )
        .unwrap();
        let k = ServersKind;
        let (doc, warnings) = k.load(&path).unwrap();
        let entries = k.entries(doc.as_ref());
        assert_eq!(
            entries
                .iter()
                .map(|e| (e.name.as_str(), e.summary.as_str(), e.target.as_deref()))
                .collect::<Vec<_>>(),
            [
                ("my.other", "ssh my.other", Some("srv:my.other")),
                (
                    "myserver",
                    "ssh admin@192.0.2.10 · 1 service · 1 timer",
                    Some("srv:myserver")
                ),
            ]
        );
        // Its settings to read: only what the table marks essential, at this server's paths.
        let items: Vec<String> = k
            .sections(doc.as_ref(), "my.other")
            .into_iter()
            .flat_map(|s| s.items)
            .map(|i| i.path)
            .collect();
        assert!(
            items.contains(&"servers.\"my.other\".ssh".to_string()),
            "{items:?}"
        );
        for p in &items {
            let f = sentry_core::cfg::fields::find(k.fields(), p).unwrap_or_else(|| panic!("{p}"));
            assert!(f.essential, "{p}");
        }
        assert_eq!(k.entry_of("servers.myserver.timers[0].unit"), "myserver");
        let p = k.problems(doc.as_ref(), &warnings);
        assert_eq!(
            p.iter().map(Problem::line).collect::<Vec<_>>(),
            ["server_config.yaml · myserver: timer `x` should end in .timer"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

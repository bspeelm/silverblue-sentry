//! `config.toml` as the window's Config area knows it (`sentry_app::cfgarea::Kind`): its
//! three parts (the agent, this machine, the window), the settings each part's form has,
//! and everything wrong in it that can be seen without a host.

use std::path::Path;

use sentry_app::cfgarea::kind::{self, DocAny, Entry, Item, Kind, Loaded, Section};
use sentry_app::cfgarea::{AGENT, MACHINE, Problem, Screen, WINDOW};
use sentry_core::cfg::{ConfigFile, Field, FileId};
use sentry_core::config::Config;
use sentry_core::tui::keys::Keymap;

pub struct AppKind;

/// What is wrong in `config.toml`: what its parse said (unknown keys), `[keys]` (an action
/// or a key that isn't one), `[agent] command`. (`[targets] show` is checked against the
/// targets there are by whoever knows them.)
pub fn problems(cfg: &Config, warnings: &[String]) -> Vec<Problem> {
    let mut out: Vec<Problem> = warnings
        .iter()
        .map(|w| Problem::of(FileId::App, None, w))
        .collect();
    let (_, keys) = Keymap::new(&crate::tui::SCREENS, &cfg.keys);
    out.extend(keys.iter().map(|w| Problem::of(FileId::App, None, w)));
    let cmd = cfg.agent.command.trim();
    if cmd.is_empty() {
        out.push(Problem::of(
            FileId::App,
            None,
            "[agent] command is empty: the name of the program, or its path (claude)",
        ));
    } else if cmd.contains(char::is_whitespace) {
        out.push(Problem::of(
            FileId::App,
            None,
            "[agent] command is one program (a name on PATH or a path), without arguments",
        ));
    }
    out
}

impl Kind for AppKind {
    fn id(&self) -> FileId {
        FileId::App
    }

    fn load(&self, path: &Path) -> Loaded {
        kind::load::<Config>(path)
    }

    fn fields(&self) -> &'static [Field] {
        Config::FIELDS
    }

    fn entries(&self, d: &dyn DocAny) -> Vec<Entry> {
        let cfg = kind::typed::<Config>(d);
        let on = |b: bool| if b { "on" } else { "off" };
        vec![
            Entry {
                name: MACHINE.into(),
                kind: "this machine",
                summary: cfg.map_or_else(String::new, |c| {
                    format!(
                        "reviews at start {}, after a run {} · {}",
                        on(c.review.at_start),
                        on(c.review.after_run),
                        match c.maintenance.notes.len() {
                            0 => "no notes files".to_string(),
                            1 => "1 notes file".to_string(),
                            n => format!("{n} notes files"),
                        }
                    )
                }),
                target: Some("local".into()),
                screen: Screen::Machine,
            },
            Entry {
                name: AGENT.into(),
                kind: "agent",
                summary: cfg.map_or_else(String::new, |c| {
                    format!("{} · {}", c.agent.kind.name(), c.agent.command)
                }),
                target: None,
                screen: Screen::Agent,
            },
            Entry {
                name: WINDOW.into(),
                kind: "window",
                summary: cfg.map_or_else(String::new, |c| {
                    format!(
                        "{} · {}",
                        match &c.targets.show {
                            Some(s) => format!("shows {}", s.join(", ")),
                            None => "shows every target".to_string(),
                        },
                        match c.keys.len() {
                            0 => "the default keys".to_string(),
                            1 => "1 key rebound".to_string(),
                            n => format!("{n} keys rebound"),
                        }
                    )
                }),
                target: None,
                screen: Screen::Window,
            },
        ]
    }

    fn sections(&self, _d: &dyn DocAny, entry: &str) -> Vec<Section> {
        let section = |title: &str, items: Vec<Item>| Section {
            title: title.to_string(),
            items,
        };
        match entry {
            AGENT => vec![section(
                "The agent sentry asks",
                vec![Item::at("agent.kind"), Item::at("agent.command")],
            )],
            MACHINE => vec![
                section(
                    "Reviews sentry starts by itself",
                    vec![Item::at("review.at_start"), Item::at("review.after_run")],
                ),
                section(
                    "Notes Claude may read",
                    vec![Item::at("maintenance.notes").empty("none")],
                ),
                section(
                    "Containers",
                    vec![
                        Item::at("ui.terminal")
                            .empty("$TERMINAL, xdg-terminal-exec, ghostty, ptyxis"),
                    ],
                ),
            ],
            WINDOW => vec![
                section(
                    "Targets in the strip",
                    vec![Item::at("targets.show").empty("all of them, this machine first")],
                ),
                section("Keys", vec![Item::at("keys").empty("the defaults")]),
                section(
                    "How long records are kept (every target)",
                    vec![
                        Item::at("retention.log_months"),
                        Item::at("retention.log_keep"),
                        Item::at("retention.runs_per_workflow"),
                        Item::at("retention.done_months"),
                        Item::at("retention.reviews"),
                        Item::at("retention.reports"),
                    ],
                ),
            ],
            _ => Vec::new(),
        }
    }

    fn entry_of(&self, path: &str) -> String {
        match path.split(['.', '[']).next() {
            Some("agent") => AGENT,
            Some("review" | "maintenance" | "ui") => MACHINE,
            _ => WINDOW,
        }
        .to_string()
    }

    fn problems(&self, d: &dyn DocAny, warnings: &[String]) -> Vec<Problem> {
        match kind::typed::<Config>(d) {
            Some(cfg) => problems(cfg, warnings),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_form_setting_is_an_essential_one_of_the_table() {
        let k = AppKind;
        let (doc, _) = k.load(Path::new("/nonexistent/config.toml")).unwrap();
        let mut seen = Vec::new();
        for e in k.entries(doc.as_ref()) {
            let sections = k.sections(doc.as_ref(), &e.name);
            assert!(!sections.is_empty(), "{}", e.name);
            for item in sections.iter().flat_map(|s| &s.items) {
                let f = sentry_core::cfg::fields::find(k.fields(), &item.path)
                    .unwrap_or_else(|| panic!("{}", item.path));
                assert!(f.essential, "{}", item.path);
                assert_eq!(k.entry_of(&item.path), e.name, "{}", item.path);
                seen.push(f.path);
            }
        }
        // And every essential setting that holds a value is in a form.
        for f in Config::FIELDS
            .iter()
            .filter(|f| f.essential && f.kind != sentry_core::cfg::Kind::Section)
        {
            assert!(seen.contains(&f.path), "{} is in no form", f.path);
        }
    }

    #[test]
    fn the_agents_command_is_one_program() {
        let lines = |text: &str| -> Vec<String> {
            let (c, w) = Config::parse(text).unwrap();
            problems(&c, &w).iter().map(Problem::line).collect()
        };
        assert!(lines("").is_empty());
        assert!(lines("[agent]\ncommand = \"/opt/bin/claude\"\n").is_empty());
        assert_eq!(
            lines("[agent]\ncommand = \"\"\n"),
            [
                "config.toml: [agent] command is empty: the name of the program, or its path (claude)"
            ]
        );
        assert_eq!(
            lines("[agent]\ncommand = \"claude --fast\"\n[keys]\nnope = \"x\"\n"),
            [
                "config.toml: [keys]: unknown action `nope`",
                "config.toml: [agent] command is one program (a name on PATH or a path), without arguments",
            ]
        );
        // A kind that isn't one is the file's own error.
        assert!(Config::parse("[agent]\nkind = \"other\"\n").is_err());
    }
}

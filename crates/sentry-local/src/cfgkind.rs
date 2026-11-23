//! `config.toml` as the window's Config area knows it (`sentry_app::cfgarea::Kind`): its
//! three parts (the agent, this machine, the window), the settings each part's form has
//! (every one of the file's: the common ones in open groups, the rest in groups that start
//! folded), and everything wrong in it that can be seen without a host.

use std::path::Path;

use sentry_app::cfgarea::kind::{self, DocAny, Entry, Item, Kind, Loaded, Section, Upkeep, WfRow};
use sentry_app::cfgarea::{AGENT, MACHINE, Problem, Screen, WINDOW};
use sentry_core::cfg::{ConfigFile, Field, FileId, Value};
use sentry_core::config::Config;
use sentry_core::tui::keys::Keymap;

use crate::jobs::JobId;
use crate::workflows as local;
use crate::workflows;

pub struct AppKind;

/// `config.toml` as the Config tab's wizard may see it: the notes files and the agent's
/// command by their names only, the command that looks from outside not at all (it is the
/// user's own, with whatever it names); then the mask over every text.
pub fn for_agent(cfg: &Config) -> Config {
    use sentry_core::cfg::hide;
    let mut c = cfg.clone();
    for n in &mut c.maintenance.notes {
        *n = hide::file_name(n);
    }
    if c.audit.outside.is_some() {
        c.audit.outside = Some(hide::HIDDEN.to_string());
    }
    if c.agent.command.contains('/') {
        c.agent.command = hide::file_name(&c.agent.command);
    }
    if let Some(t) = c.ui.terminal.as_mut().filter(|t| t.contains('/')) {
        *t = hide::file_name(t);
    }
    c
}

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
                ssh: None,
            },
            Entry {
                name: AGENT.into(),
                kind: "agent",
                summary: cfg.map_or_else(String::new, |c| {
                    format!("{} · {}", c.agent.kind.name(), c.agent.command)
                }),
                target: None,
                screen: Screen::Agent,
                ssh: None,
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
                ssh: None,
            },
        ]
    }

    fn sections(&self, _d: &dyn DocAny, entry: &str) -> Vec<Section> {
        let section = Section::new;
        let folded = |title: &str, about: &str, paths: &[&str]| {
            Section::folded(title, about, paths.iter().map(|p| Item::at(p)).collect())
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
                // Everything else config.toml says about this machine. (`[jobs]` is the
                // Upkeep group's; what the whole window goes by is on Window.)
                Section::folded(
                    "Refresh rates",
                    "How often this machine's live screens sample.",
                    vec![
                        Item::at("ui.dashboard_hz").range(0, 10),
                        Item::at("ui.processes_hz").range(0, 10),
                    ],
                ),
                folded(
                    "Update checks",
                    "How long a cached update check counts as fresh.",
                    &["cache.update_check_max_age"],
                ),
                folded(
                    "Audit",
                    "What the audit flags, how long reports stay.",
                    &[
                        "audit.stale_container_days",
                        "audit.cache_warn_mb",
                        "audit.retention_months",
                        "audit.outside",
                    ],
                ),
                folded(
                    "Flatpak rules",
                    "Permissions and remotes the audit flags.",
                    &[
                        "flatpak.flag_filesystems",
                        "flatpak.flag_talk_names",
                        "flatpak.trusted_origins",
                    ],
                ),
                folded(
                    "Recorder",
                    "`sentry record` and History: how often, how much.",
                    &[
                        "recorder.interval",
                        "recorder.retention_hours",
                        "recorder.max_mb",
                        "recorder.alerts",
                    ],
                ),
                folded(
                    "Cleanup",
                    "The cache directories Cleanup may delete.",
                    &["cleanup.cache.delete_dirs"],
                ),
                folded(
                    "Expected",
                    "Listeners and findings taken as expected.",
                    &["baseline.listeners", "baseline.findings"],
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
            Some("targets" | "keys" | "retention") => WINDOW,
            _ => MACHINE,
        }
        .to_string()
    }

    fn problems(&self, d: &dyn DocAny, warnings: &[String]) -> Vec<Problem> {
        match kind::typed::<Config>(d) {
            Some(cfg) => problems(cfg, warnings),
            None => Vec::new(),
        }
    }

    /// This machine's upkeep: its workflows (they run when there is something for them to
    /// do: no cadence), then its jobs, each due as `[jobs]` says or by its own default.
    /// There is one set of workflows here, nobody else's to share.
    fn for_agent(&self, tree: &Value) -> kind::AgentView {
        match tree.to::<Config>().and_then(|c| Value::of(&for_agent(&c))) {
            Ok(t) => kind::AgentView {
                tree: kind::masked(&t),
                ..Default::default()
            },
            Err(_) => kind::AgentView::default(),
        }
    }

    fn upkeep(&self, d: &dyn DocAny, entry: &str, disk: bool) -> Upkeep {
        if entry != MACHINE {
            return Upkeep::default();
        }
        let cfg = kind::typed::<Config>(d);
        let entries: Vec<workflows::Entry> = match disk {
            true => local::list(),
            false => local::SEEDS
                .iter()
                .map(|(n, text)| {
                    let wf = workflows::parse(text);
                    workflows::Entry {
                        name: n.to_string(),
                        path: local::dir().join(format!("{n}.toml")),
                        issues: wf.as_ref().map(local::lint).unwrap_or_default(),
                        wf,
                    }
                })
                .collect(),
        };
        let mut rows: Vec<WfRow> = entries
            .into_iter()
            .map(|e| WfRow {
                title: e
                    .wf
                    .as_ref()
                    .map(|w| w.description.clone())
                    .unwrap_or_default(),
                what: "workflow",
                own: false,
                draft: e.wf.as_ref().is_ok_and(|w| w.draft),
                problems: match &e.wf {
                    Err(why) => vec![format!("it doesn't parse: {why}")],
                    Ok(_) => e.errors().map(|i| i.msg.clone()).collect(),
                },
                every: String::new(),
                default: String::new(),
                suggest: None,
                path: Some(e.path.clone()),
                name: e.name,
            })
            .collect();
        // (update-apply has no cadence: updates go through quick-update.)
        rows.extend(
            JobId::ALL
                .into_iter()
                .filter(|j| j.default_every().is_some())
                .map(|j| WfRow {
                    name: j.name().to_string(),
                    title: format!("{}.", j.description()),
                    what: "job",
                    own: false,
                    draft: false,
                    problems: Vec::new(),
                    every: cfg
                        .and_then(|c| c.jobs.get(j.name())?.suggested_every.clone())
                        .unwrap_or_default(),
                    default: j.default_every().unwrap_or_default().to_string(),
                    suggest: None,
                    path: None,
                }),
        );
        Upkeep {
            rows,
            shared: local::dir(),
            own: None,
            has_own: false,
        }
    }

    /// A job's cadence is `[jobs] <name>.suggested_every`: the whole table is staged (a
    /// job the file doesn't name has no entry to set a field in). Nothing typed: the job's
    /// own default again. A workflow of this machine's has no cadence.
    fn cadence(
        &self,
        d: &dyn DocAny,
        entry: &str,
        workflow: &str,
        every: Option<&str>,
    ) -> Option<(String, Option<Value>)> {
        if entry != MACHINE {
            return None;
        }
        JobId::from_name(workflow)?.default_every()?;
        let mut jobs = kind::typed::<Config>(d)?.jobs.clone();
        match every {
            Some(e) => {
                jobs.entry(workflow.to_string())
                    .or_default()
                    .suggested_every = Some(e.to_string())
            }
            None => {
                jobs.remove(workflow);
            }
        }
        Some(("jobs".to_string(), Value::of(&jobs).ok()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_setting_of_config_toml_has_one_home_in_a_form() {
        let k = AppKind;
        let (doc, _) = k.load(Path::new("/nonexistent/config.toml")).unwrap();
        // `[jobs]` is what the Upkeep group of This machine sets.
        assert_eq!(
            kind::misplaced(
                &k,
                doc.as_ref(),
                &[AGENT, MACHINE, WINDOW],
                &["jobs", "jobs.*.suggested_every"]
            ),
            Vec::<String>::new()
        );
        for e in k.entries(doc.as_ref()) {
            let sections = k.sections(doc.as_ref(), &e.name);
            assert!(!sections.is_empty(), "{}", e.name);
            // The common settings are in the open groups, which come first; the rest fold.
            let first_fold = sections.iter().position(|s| s.fold);
            for (i, s) in sections.iter().enumerate() {
                assert_eq!(s.fold, first_fold.is_some_and(|f| i >= f), "{}", s.title);
                assert_eq!(s.fold, !s.about.is_empty(), "{}", s.title);
                for item in &s.items {
                    let f = sentry_core::cfg::fields::find(k.fields(), &item.path).unwrap();
                    assert_eq!(f.common, !s.fold, "{}", item.path);
                    assert_eq!(k.entry_of(&item.path), e.name, "{}", item.path);
                }
            }
        }
        // Window-wide things stay on Window; what is this machine's is on This machine.
        assert_eq!(k.entry_of("jobs"), MACHINE);
        assert_eq!(k.entry_of("retention.reviews"), WINDOW);
        assert_eq!(k.entry_of("recorder.alerts"), MACHINE);
    }

    #[test]
    fn this_machines_upkeep_is_its_workflows_and_its_jobs() {
        let k = AppKind;
        let dir = std::env::temp_dir().join(format!("sentry-appkind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "[jobs]\nupdate-check.suggested_every = \"3d\"\n").unwrap();
        let (doc, _) = k.load(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let up = k.upkeep(doc.as_ref(), MACHINE, false);
        let rows: Vec<(&str, &str, &str, &str)> = up
            .rows
            .iter()
            .map(|r| {
                (
                    r.name.as_str(),
                    r.what,
                    r.every.as_str(),
                    r.default.as_str(),
                )
            })
            .collect();
        assert!(
            rows.contains(&("quick-update", "workflow", "", "")),
            "{rows:?}"
        );
        assert!(rows.contains(&("audit", "job", "", "30d")), "{rows:?}");
        assert!(
            rows.contains(&("update-check", "job", "3d", "7d")),
            "{rows:?}"
        );
        assert!(
            rows.contains(&("cleanup-cache", "job", "", "off")),
            "{rows:?}"
        );
        assert!(!rows.iter().any(|r| r.0 == "update-apply"), "{rows:?}");
        // No set per system here.
        assert_eq!((up.own.clone(), up.has_own), (None, false));
        assert!(k.upkeep(doc.as_ref(), AGENT, false).rows.is_empty());
        // A job's cadence is staged in `[jobs]`; a workflow has none to set.
        let (path, to) = k
            .cadence(doc.as_ref(), MACHINE, "audit", Some("14d"))
            .unwrap();
        assert_eq!(path, "jobs");
        assert_eq!(
            to.unwrap().to_string(),
            "{audit: {suggested_every: \"14d\"}, update-check: {suggested_every: \"3d\"}}"
        );
        let (_, to) = k
            .cadence(doc.as_ref(), MACHINE, "update-check", None)
            .unwrap();
        assert_eq!(to.unwrap().to_string(), "{}");
        assert_eq!(
            k.cadence(doc.as_ref(), MACHINE, "quick-update", Some("7d")),
            None
        );
        assert_eq!(
            k.cadence(doc.as_ref(), MACHINE, "update-apply", Some("7d")),
            None
        );
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

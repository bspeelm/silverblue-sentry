//! `server_config.yaml` as the window's Config area knows it (`sentry_app::cfgarea::Kind`):
//! each server an entry with a line about it, its essential settings in sections, what its
//! lint says, its connection checks (`sentry-server check` prints the same lines), how a
//! host is looked at and drafted (`init`'s discovery), and its upkeep: the workflows it has
//! and how often each is due.

use std::path::Path;
use std::time::Instant;

use sentry_app::cfgarea::discover::refusal;
use sentry_app::cfgarea::kind::{
    self, CheckLine, Checker, DocAny, Drafted, Entry, Item, Kind, Loaded, Probe, Section, Upkeep,
    WfRow,
};
use sentry_app::cfgarea::{Problem, Screen};
use sentry_core::cfg::{ConfigFile, Field, FileId, Seg, Value, parse_path, path_string};
use sentry_core::workflows;

use crate::config::{self, Compose, DiskRule, MaintItem, Server, ServerFile, TimerRule};
use crate::remote::{Remote, SrvError, SudoMode};

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

/// The tools `check` looks for: the first four are what every screen needs.
const TOOLS: [&str; 10] = [
    "systemctl",
    "journalctl",
    "findmnt",
    "ss",
    "apt-get",
    "docker",
    "smartctl",
    "sensors",
    "nvidia-smi",
    "fail2ban-client",
];

/// A server's connection checks: is it reachable (and how fast), what sudo does, which tools
/// are there, and whether sudoers allows each `sudo:` entry where sudo needs no password.
/// Reads only. The second value: it couldn't be reached at all.
pub fn check(r: &Remote, s: &Server) -> (Vec<CheckLine>, bool) {
    let mut out = Vec::new();
    let t = Instant::now();
    match r.output(&r.sh(". /etc/os-release; echo \"$PRETTY_NAME · $(uname -r)\"")) {
        Ok(o) => out.push(CheckLine::ok(format!(
            "{} ({}): {} · {} ms",
            r.name,
            r.host,
            o.trim(),
            t.elapsed().as_millis()
        ))),
        Err(e) => {
            let why = match &e {
                SrvError::Unreachable(m) => refusal(r.host, m).why,
                e => e.to_string(),
            };
            out.push(CheckLine::bad(format!("{} ({}): {why}", r.name, r.host)));
            return (out, true);
        }
    }
    let t = Instant::now();
    if r.cmd("true").output().is_ok() {
        out.push(CheckLine::ok(format!(
            "next command over the shared connection: {} ms",
            t.elapsed().as_millis()
        )));
    }
    let mode = r.sudo_mode();
    out.push(match &mode {
        Ok(SudoMode::NoPasswd) => CheckLine::ok("sudo -n: no password needed"),
        Ok(SudoMode::Password) => CheckLine::note(
            "sudo asks for a password: monitoring runs without root; what needs root asks for \
             it once, in the window",
        ),
        Ok(SudoMode::Absent) => CheckLine::note("no sudo for this user"),
        Ok(SudoMode::Root) => CheckLine::ok("root login: nothing needs sudo"),
        Err(e) => CheckLine::bad(format!("sudo: {e}")),
    });
    let script = TOOLS
        .iter()
        .map(|t| format!("command -v {t} >/dev/null && echo {t}"))
        .collect::<Vec<_>>()
        .join("; ");
    if let Ok(o) = r.output(&r.sh(&format!("{}{script}; true", crate::init::SBIN))) {
        let found: Vec<&str> = o.lines().collect();
        let missing: Vec<&str> = TOOLS
            .iter()
            .copied()
            .filter(|t| !found.contains(t))
            .collect();
        out.push(CheckLine::ok(format!("tools: {}", found.join(" "))));
        if !missing.is_empty() {
            out.push(CheckLine::note(format!(
                "not installed (their panels stay empty): {}",
                missing.join(" ")
            )));
        }
    }
    if mode == Ok(SudoMode::NoPasswd) {
        for entry in &s.sudo {
            // `sudo -l <cmd>` asks sudoers whether it may run, without running it.
            let words: Vec<&str> = entry.split_whitespace().collect();
            let ok = r
                .cmd("sudo")
                .args(["-n", "-l"])
                .args(words.iter().copied())
                .run()
                .is_ok_and(|o| o.code == 0);
            out.push(match ok {
                true => CheckLine::ok(format!("sudo: {entry}")),
                false => CheckLine::bad(format!(
                    "sudo: {entry} (sudoers doesn't allow it, or it isn't installed)"
                )),
            });
        }
    }
    (out, false)
}

/// What the setup proposes for a server just added, per seeded workflow.
fn suggested(workflow: &str) -> Option<&'static str> {
    match workflow {
        "apt-maintenance" => Some("30d"),
        _ => None,
    }
}

/// A server's workflows with their lint: from its folders, or (`disk` off: a test's
/// window) the seeded set as shipped.
fn workflows_of(name: &str, disk: bool) -> (Vec<workflows::Entry>, bool) {
    if disk {
        let own = crate::workflow::dir_for(name) != crate::workflow::dir();
        return (crate::workflow::list_for(name), own);
    }
    let seeded = crate::workflow::SEEDS
        .iter()
        .map(|(n, text)| {
            let wf = workflows::parse(text);
            workflows::Entry {
                name: n.to_string(),
                path: crate::workflow::dir().join(format!("{n}.toml")),
                issues: wf
                    .as_ref()
                    .map(|w| workflows::lint_with(w, &crate::workflow::RULES))
                    .unwrap_or_default(),
                wf,
            }
        })
        .collect();
    (seeded, false)
}

fn server<'a>(d: &'a dyn DocAny, entry: &str) -> Option<&'a Server> {
    kind::typed::<ServerFile>(d)?.servers.get(entry)
}

fn at(entry: &str, rest: &str) -> String {
    format!(
        "{}.{rest}",
        path_string(&[Seg::Key("servers".into()), Seg::Key(entry.to_string())])
    )
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
                    ssh: Some(s.ssh_target(name).to_string()),
                }
            })
            .collect()
    }

    fn sections(&self, _d: &dyn DocAny, entry: &str) -> Vec<Section> {
        let section = |title: &str, items: &[(&str, &str)]| Section {
            title: title.to_string(),
            items: items
                .iter()
                .map(|(rest, empty)| Item::at(&at(entry, rest)).empty(empty))
                .collect(),
        };
        vec![
            section(
                "Who it is",
                &[
                    ("ssh", "its name"),
                    ("sudo", "nothing: monitoring runs without root"),
                ],
            ),
            section(
                "What must be running",
                &[("services", "none"), ("timers", "none")],
            ),
            section("Disks", &[("disks", "none"), ("smart", "none")]),
            section(
                "Containers and what listens",
                &[
                    ("compose", "none"),
                    ("listeners", "none: everything listening is a finding"),
                ],
            ),
            section(
                "Kept at a deliberate version",
                &[("maintenance.items", "none")],
            ),
            section("Notes Claude may read", &[("maintenance.notes", "none")]),
        ]
    }

    fn problems(&self, d: &dyn DocAny, warnings: &[String]) -> Vec<Problem> {
        match kind::typed::<ServerFile>(d) {
            Some(file) => problems(file, warnings),
            None => Vec::new(),
        }
    }

    fn blank(&self, list: &str) -> Option<Value> {
        let segs = parse_path(list).ok()?;
        let v = match segs.last()? {
            Seg::Key(k) if k == "timers" => Value::of(&TimerRule {
                unit: String::new(),
                max_age: sentry_core::config::Dur::hours(26),
            }),
            Seg::Key(k) if k == "disks" => Value::of(&DiskRule {
                mount: "/".into(),
                warn: Server::default_warn(),
                crit: Server::default_crit(),
            }),
            Seg::Key(k) if k == "compose" => Value::of(&Compose {
                name: String::new(),
                file: String::new(),
            }),
            Seg::Key(k) if k == "items" => Value::of(&MaintItem::default()),
            _ => return None,
        };
        v.ok()
    }

    /// A tracked item's workflow is one of that server's workflows.
    fn choices(&self, _d: &dyn DocAny, path: &str, disk: bool) -> Option<Vec<String>> {
        let segs = parse_path(path).ok()?;
        match segs.as_slice() {
            [
                Seg::Key(_),
                Seg::Key(name),
                Seg::Key(m),
                Seg::Key(i),
                Seg::Index(_),
                Seg::Key(leaf),
            ] if m == "maintenance" && i == "items" && leaf == "workflow" => Some(
                workflows_of(name, disk)
                    .0
                    .into_iter()
                    .map(|e| e.name)
                    .collect(),
            ),
            _ => None,
        }
    }

    fn check(&self, d: &dyn DocAny, entry: &str) -> Option<Checker> {
        let s = server(d, entry)?.clone();
        let name = entry.to_string();
        Some(Box::new(move || {
            let (mut lines, _) = check(&Remote::new(&name, &s), &s);
            lines.extend(
                config::lint(&name, &s)
                    .into_iter()
                    .map(|p| CheckLine::bad(Problem::of(FileId::Servers, Some(&name), &p).text)),
            );
            lines
        }))
    }

    fn probe(&self, ssh: &str, name: &str) -> Probe {
        let s = Server {
            ssh: Some(ssh.to_string()),
            ..Default::default()
        };
        let r = Remote::new(name, &s);
        let facts = match crate::init::discover(&r) {
            Ok(f) => f,
            Err(e) => return Probe::Failed(refusal(ssh, &e.to_string())),
        };
        let draft = crate::init::draft(name, ssh, &facts);
        let entry_path = path_string(&[Seg::Key("servers".into()), Seg::Key(name.to_string())]);
        match Value::of(&draft.entry) {
            Ok(entry) => Probe::Drafted(Drafted {
                file: FileId::Servers,
                kind: "server",
                name: name.to_string(),
                ssh: ssh.to_string(),
                entry,
                notes: kind::notes_within(draft.notes, &entry_path),
                what: facts.os,
            }),
            Err(e) => Probe::Failed(refusal(ssh, &e)),
        }
    }

    fn upkeep(&self, d: &dyn DocAny, entry: &str, disk: bool) -> Upkeep {
        let cadence = server(d, entry)
            .map(|s| s.maintenance.cadence.clone())
            .unwrap_or_default();
        let (entries, own) = workflows_of(entry, disk);
        Upkeep {
            rows: entries
                .into_iter()
                .map(|e| WfRow {
                    title: e
                        .wf
                        .as_ref()
                        .map(|w| w.description.clone())
                        .unwrap_or_default(),
                    what: "workflow",
                    own,
                    draft: e.wf.as_ref().is_ok_and(|w| w.draft),
                    problems: match &e.wf {
                        Err(why) => vec![format!("it doesn't parse: {why}")],
                        Ok(_) => e.errors().map(|i| i.msg.clone()).collect(),
                    },
                    every: cadence
                        .get(&e.name)
                        .map(|d| d.to_string())
                        .unwrap_or_default(),
                    default: String::new(),
                    suggest: suggested(&e.name),
                    path: Some(e.path.clone()),
                    name: e.name,
                })
                .collect(),
            shared: crate::workflow::dir(),
            own: Some(crate::workflow::server_dir(entry)),
            has_own: own,
        }
    }

    /// A server's cadence is one map in its entry: staged whole. (`off` is no cadence
    /// here: a workflow that isn't in the map isn't recommended on a clock.)
    fn cadence(
        &self,
        d: &dyn DocAny,
        entry: &str,
        workflow: &str,
        every: Option<&str>,
    ) -> Option<(String, Option<Value>)> {
        let mut map: Vec<(String, Value)> = server(d, entry)?
            .maintenance
            .cadence
            .iter()
            .filter(|(k, _)| *k != workflow)
            .map(|(k, v)| (k.clone(), Value::Str(v.to_string())))
            .collect();
        if let Some(e) = every.filter(|e| *e != "off") {
            map.push((workflow.to_string(), Value::Str(e.to_string())));
            map.sort_by(|a, b| a.0.cmp(&b.0));
        }
        Some((at(entry, "maintenance.cadence"), Some(Value::Map(map))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(text: &str, tag: &str) -> (Box<dyn DocAny>, Vec<String>) {
        let dir = std::env::temp_dir().join(format!("sentry-srvkind-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server_config.yaml");
        std::fs::write(&path, text).unwrap();
        let r = ServersKind.load(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        r
    }

    #[test]
    fn each_server_is_an_entry_with_its_essential_settings() {
        let k = ServersKind;
        let (doc, warnings) = loaded(
            "servers:\n  myserver:\n    ssh: admin@192.0.2.10\n    services: [app.service]\n    timers: [{unit: x, max_age: 1d}]\n  my.other: {}\n",
            "entries",
        );
        let entries = k.entries(doc.as_ref());
        assert_eq!(
            entries
                .iter()
                .map(|e| (
                    e.name.as_str(),
                    e.summary.as_str(),
                    e.target.as_deref(),
                    e.ssh.as_deref()
                ))
                .collect::<Vec<_>>(),
            [
                (
                    "my.other",
                    "ssh my.other",
                    Some("srv:my.other"),
                    Some("my.other")
                ),
                (
                    "myserver",
                    "ssh admin@192.0.2.10 · 1 service · 1 timer",
                    Some("srv:myserver"),
                    Some("admin@192.0.2.10")
                ),
            ]
        );
        // Its form: only what the table marks essential, at this server's paths.
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
        // And every essential setting of a server that isn't a record's own field is in its
        // form, or is its cadence (the Upkeep section's).
        for f in ServerFile::FIELDS.iter().filter(|f| {
            f.essential
                && f.kind != sentry_core::cfg::Kind::Section
                && f.path.starts_with("servers.*.")
                && !f.path.contains("[]")
        }) {
            let path = f.path.replace("servers.*", "servers.\"my.other\"");
            assert!(
                items.contains(&path) || f.path == "servers.*.maintenance.cadence",
                "{} is in no form",
                f.path
            );
        }
        assert_eq!(k.entry_of("servers.myserver.timers[0].unit"), "myserver");
        let p = k.problems(doc.as_ref(), &warnings);
        assert_eq!(
            p.iter().map(Problem::line).collect::<Vec<_>>(),
            ["server_config.yaml · myserver: timer `x` should end in .timer"]
        );
    }

    #[test]
    fn a_new_record_is_one_its_type_reads() {
        let k = ServersKind;
        for (list, key) in [
            ("servers.a.timers", "unit"),
            ("servers.a.disks", "mount"),
            ("servers.a.compose", "name"),
            ("servers.a.maintenance.items", "id"),
        ] {
            let v = k.blank(list).unwrap_or_else(|| panic!("{list}"));
            assert!(v.get(key).is_some(), "{list}: {v}");
        }
        assert_eq!(k.blank("servers.a.services"), None);
        // A file with one of each added reads back.
        let s = Server {
            timers: vec![k.blank("servers.a.timers").unwrap().to().unwrap()],
            disks: vec![k.blank("servers.a.disks").unwrap().to().unwrap()],
            ..Default::default()
        };
        assert_eq!((s.disks[0].warn, s.disks[0].crit), (85, 95));
    }

    #[test]
    fn upkeep_lists_the_workflows_and_stages_the_cadence_in_the_servers_own_map() {
        let k = ServersKind;
        let (doc, _) = loaded(
            "servers:\n  myserver:\n    maintenance:\n      cadence: {compose-update: 14d}\n",
            "upkeep",
        );
        let up = k.upkeep(doc.as_ref(), "myserver", false);
        assert_eq!(
            up.rows
                .iter()
                .map(|r| (r.name.as_str(), r.every.as_str(), r.suggest, r.own))
                .collect::<Vec<_>>(),
            [
                ("apt-maintenance", "", Some("30d"), false),
                ("compose-update", "14d", None, false),
            ]
        );
        assert!(up.rows.iter().all(|r| r.problems.is_empty() && !r.draft));
        assert!(up.shared.ends_with("server-workflows"));
        assert!(
            up.own
                .as_ref()
                .unwrap()
                .ends_with("servers/myserver/workflows")
        );
        // Setting one keeps the others; `off` and nothing take it out of the map.
        let (path, to) = k
            .cadence(doc.as_ref(), "myserver", "apt-maintenance", Some("30d"))
            .unwrap();
        assert_eq!(path, "servers.myserver.maintenance.cadence");
        assert_eq!(
            to.unwrap().to_string(),
            "{apt-maintenance: \"30d\", compose-update: \"14d\"}"
        );
        for none in [None, Some("off")] {
            let (_, to) = k
                .cadence(doc.as_ref(), "myserver", "compose-update", none)
                .unwrap();
            assert_eq!(to.unwrap().to_string(), "{}");
        }
        // A tracked item's workflow is one of the server's.
        assert_eq!(
            k.choices(
                doc.as_ref(),
                "servers.myserver.maintenance.items[0].workflow",
                false
            ),
            Some(vec!["apt-maintenance".to_string(), "compose-update".into()])
        );
        assert_eq!(k.choices(doc.as_ref(), "servers.myserver.ssh", false), None);
    }
}

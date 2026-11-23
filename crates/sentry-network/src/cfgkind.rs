//! `network_config.yaml` as the window's Config area knows it (`sentry_app::cfgarea::Kind`):
//! each network an entry with a line about it, its essential settings in sections, what its
//! lint says, its router's connection checks (`sentry-network check` starts with the same
//! lines), how a router is looked at and drafted (`init`'s discovery), a key for its
//! backups, and its upkeep: the workflows it has and how often each is due.

use std::path::Path;
use std::time::Instant;

use sentry_app::cfgarea::discover::refusal;
use sentry_app::cfgarea::kind::{
    self, CheckLine, Checker, DocAny, Drafted, Entry, FieldAction, Item, Kind, Loaded, Probe,
    Section, Upkeep, WfRow,
};
use sentry_app::cfgarea::{Problem, Screen};
use sentry_core::cfg::{ConfigFile, Field, FileId, Seg, Value, parse_path, path_string};
use sentry_core::workflows;

use crate::collect::ifaces::{self, Ifaces};
use crate::config::{self, Cadence, Device, Forward, Network, NetworkFile, RouterCfg};
use crate::remote::Router;

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

/// The commands the network target uses, now or soon: which are there is worth knowing
/// before anything depends on them.
pub const TOOLS: &[&str] = &[
    "ubus",
    "uci",
    "ip",
    "netstat",
    "nft",
    "iw",
    "logread",
    "apk",
    "sysupgrade",
    "hexdump",
    "brctl",
];

/// What a router's connection checks said: the lines, whether it couldn't be reached at
/// all, and what it reported of itself (`sentry-network check` goes on from it).
pub struct Checked {
    pub lines: Vec<CheckLine>,
    pub unreachable: bool,
    pub ifaces: Option<Ifaces>,
}

/// A router's connection checks: is it reachable as root (and how fast), which tools are
/// there, its release and board. Reads only.
pub fn check(r: &Router) -> Checked {
    let mut lines = Vec::new();
    let t = Instant::now();
    let uid = match r.output(&r.sh("id -u")) {
        Ok(u) => u.trim().to_string(),
        Err(e) => {
            let why = match &e {
                sentry_app::remote::Error::Unreachable(m) => refusal(r.host, m).why,
                e => e.to_string(),
            };
            lines.push(CheckLine::bad(format!("not reachable: {why}")));
            return Checked {
                lines,
                unreachable: true,
                ifaces: None,
            };
        }
    };
    let first = t.elapsed().as_millis();
    let t = Instant::now();
    let _ = r.output(&r.sh("true"));
    let again = t.elapsed().as_millis();
    lines.push(match uid.as_str() {
        "0" => CheckLine::ok(format!(
            "reachable as root ({first} ms, then {again} ms on the shared connection)"
        )),
        uid => CheckLine::bad(format!(
            "the login is uid {uid}, not root: a router's login is root (there is no sudo)"
        )),
    });
    let tools = format!(
        "for b in {}; do command -v $b >/dev/null && echo \"+$b\" || echo \"-$b\"; done",
        TOOLS.join(" ")
    );
    if let Ok(out) = r.output(&r.sh(&tools)) {
        let (have, miss): (Vec<&str>, Vec<&str>) = out.lines().partition(|l| l.starts_with('+'));
        let strip = |v: Vec<&str>| v.iter().map(|l| &l[1..]).collect::<Vec<_>>().join(" ");
        lines.push(match miss.is_empty() {
            true => CheckLine::ok(format!("tools: {}", strip(have))),
            false => CheckLine::note(format!("tools: {} (missing: {})", strip(have), strip(miss))),
        });
    }
    let t = Instant::now();
    let ifs = ifaces::collect(r);
    let took = t.elapsed().as_millis();
    let ifaces = match ifs {
        Ok(i) => {
            let b = &i.board;
            lines.push(CheckLine::ok(format!(
                "{} {} ({}) · {} · {} · kernel {} ({took} ms)",
                b.distribution, b.version, b.revision, b.model, b.target, b.kernel
            )));
            Some(i)
        }
        Err(e) => {
            lines.push(CheckLine::bad(format!("interfaces: {e}")));
            None
        }
    };
    Checked {
        lines,
        unreachable: false,
        ifaces,
    }
}

/// What the setup proposes for a network just added, per seeded workflow.
fn suggested(workflow: &str) -> Option<&'static str> {
    match workflow {
        "config-backup" | "package-update" => Some("30d"),
        _ => None,
    }
}

/// A network's workflows with their lint: from its folders, or (`disk` off: a test's
/// window) the seeded set as shipped.
fn workflows_of(name: &str, disk: bool) -> (Vec<workflows::Entry>, bool) {
    if disk {
        let scope = crate::remote::scope(name);
        let own = crate::workflow::dir_for(&scope) != crate::workflow::dir();
        return (crate::workflow::list_for(&scope), own);
    }
    let mut seeded = crate::workflow::seeded_all();
    seeded.sort_by(|a, b| a.name.cmp(&b.name));
    (seeded, false)
}

fn network<'a>(d: &'a dyn DocAny, entry: &str) -> Option<&'a Network> {
    kind::typed::<NetworkFile>(d)?.networks.get(entry)
}

fn at(entry: &str, rest: &str) -> String {
    format!(
        "{}.{rest}",
        path_string(&[Seg::Key("networks".into()), Seg::Key(entry.to_string())])
    )
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
                    ssh: Some(n.ssh_target(name).to_string()),
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
            section("Who it is", &[("router.ssh", "its name")]),
            section(
                "What its firewall should look like",
                &[
                    ("expect.zones", "none: nothing is compared"),
                    ("expect.forwards", "none: every forward is a finding"),
                ],
            ),
            section("The devices you know", &[("devices", "none")]),
            section(
                "Config backups",
                &[
                    ("backup.recipients", "none: no backup is made"),
                    ("backup.keep", ""),
                ],
            ),
            section(
                "Claude",
                &[("notes", "none"), ("claude.share_wan_address", "")],
            ),
        ]
    }

    fn problems(&self, d: &dyn DocAny, warnings: &[String]) -> Vec<Problem> {
        match kind::typed::<NetworkFile>(d) {
            Some(file) => problems(file, warnings),
            None => Vec::new(),
        }
    }

    fn blank(&self, list: &str) -> Option<Value> {
        let segs = parse_path(list).ok()?;
        let v = match segs.last()? {
            Seg::Key(k) if k == "forwards" => Value::of(&Forward {
                name: String::new(),
                proto: "tcp".into(),
                port: "80".parse().ok()?,
                to: String::new(),
            }),
            Seg::Key(k) if k == "devices" => Value::of(&Device::default()),
            Seg::Key(k) if k == "cadence" => Value::of(&Cadence {
                workflow: String::new(),
                every: sentry_core::config::Dur::secs(30 * 86400),
            }),
            _ => return None,
        };
        v.ok()
    }

    /// A network's backup recipients can make their key.
    fn action(&self, path: &str) -> Option<FieldAction> {
        let segs = parse_path(path).ok()?;
        match segs.as_slice() {
            [Seg::Key(_), Seg::Key(name), Seg::Key(b), Seg::Key(r)]
                if b == "backup" && r == "recipients" =>
            {
                Some(FieldAction {
                    label: "make a key",
                    prompt: "Where the secret key is written: a new file (0600), never over \
                             one that is there. sentry keeps only the public half, as a \
                             recipient; the secret one is in that file and nowhere else. Keep \
                             a copy somewhere that isn't this machine: without it no backup \
                             can be read."
                        .to_string(),
                    start: format!("~/sentry-{name}-backup.key"),
                    done: "the secret key is in that file (0600): keep a copy elsewhere · its \
                           public half is staged as a recipient",
                })
            }
            _ => None,
        }
    }

    /// `sentry-network backup key <file>`: the file is the secret half, what comes back
    /// the public one.
    fn act(&self, path: &str, arg: &str) -> Result<String, String> {
        if self.action(path).is_none() {
            return Err("nothing to do here".into());
        }
        crate::backup::make_key(Path::new(arg)).map_err(|e| e.to_string())
    }

    fn check(&self, d: &dyn DocAny, entry: &str) -> Option<Checker> {
        let n = network(d, entry)?.clone();
        let name = entry.to_string();
        Some(Box::new(move || {
            let mut lines = check(&Router::new(&name, &n)).lines;
            lines.extend(
                config::lint(&name, &n)
                    .into_iter()
                    .map(|p| CheckLine::note(Problem::of(FileId::Networks, Some(&name), &p).text)),
            );
            lines
        }))
    }

    fn probe(&self, ssh: &str, name: &str) -> Probe {
        let n = Network {
            router: RouterCfg {
                ssh: Some(ssh.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let r = Router::new(name, &n);
        let facts = match crate::init::discover(&r) {
            Ok(f) => f,
            Err(e) => return Probe::Failed(refusal(ssh, &e.to_string())),
        };
        let draft = crate::init::draft(name, ssh, &facts);
        let entry_path = path_string(&[Seg::Key("networks".into()), Seg::Key(name.to_string())]);
        let b = &facts.ifaces.board;
        match Value::of(&draft.entry) {
            Ok(entry) => Probe::Drafted(Drafted {
                file: FileId::Networks,
                kind: "network",
                name: name.to_string(),
                ssh: ssh.to_string(),
                entry,
                notes: kind::notes_within(draft.notes, &entry_path),
                what: format!("{} {} · {}", b.distribution, b.version, b.model),
            }),
            Err(e) => Probe::Failed(refusal(ssh, &e)),
        }
    }

    fn upkeep(&self, d: &dyn DocAny, entry: &str, disk: bool) -> Upkeep {
        let cadence: Vec<Cadence> = network(d, entry)
            .map(|n| n.maintenance.cadence.clone())
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
                        .iter()
                        .find(|c| c.workflow == e.name)
                        .map(|c| c.every.to_string())
                        .unwrap_or_default(),
                    default: String::new(),
                    suggest: suggested(&e.name),
                    path: Some(e.path.clone()),
                    name: e.name,
                })
                .collect(),
            shared: crate::workflow::dir(),
            own: Some(sentry_app::remote::workflow::own_dir(
                &crate::remote::scope(entry),
            )),
            has_own: own,
        }
    }

    /// A network's cadence is one list in its entry: staged whole. (`off` is no cadence
    /// here: a workflow that isn't in the list isn't recommended on a clock.)
    fn cadence(
        &self,
        d: &dyn DocAny,
        entry: &str,
        workflow: &str,
        every: Option<&str>,
    ) -> Option<(String, Option<Value>)> {
        let mut list: Vec<Cadence> = network(d, entry)?
            .maintenance
            .cadence
            .iter()
            .filter(|c| c.workflow != workflow)
            .cloned()
            .collect();
        if let Some(e) = every.filter(|e| *e != "off") {
            list.push(Cadence {
                workflow: workflow.to_string(),
                every: e.parse().ok()?,
            });
        }
        Some((at(entry, "maintenance.cadence"), Value::of(&list).ok()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(text: &str, tag: &str) -> (Box<dyn DocAny>, Vec<String>) {
        let dir = std::env::temp_dir().join(format!("sentry-netkind-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("network_config.yaml");
        std::fs::write(&path, text).unwrap();
        let r = NetworksKind.load(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        r
    }

    #[test]
    fn each_network_is_an_entry_that_names_no_device() {
        let k = NetworksKind;
        let (doc, warnings) = loaded(
            "networks:\n  home:\n    router: {ssh: myrouter}\n    devices:\n      - {name: nas, mac: \"02:00:5E:00:53:01\"}\n    backup: {keep: 0}\n",
            "entries",
        );
        let e = k.entries(doc.as_ref());
        assert_eq!(e.len(), 1);
        assert_eq!(
            (
                e[0].name.as_str(),
                e[0].summary.as_str(),
                e[0].target.as_deref(),
                e[0].ssh.as_deref()
            ),
            (
                "home",
                "router over ssh myrouter · 1 device · no backup recipient",
                Some("net:home"),
                Some("myrouter")
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
        // And every essential setting of a network that isn't a record's own field (or a
        // zone's own list) is in its form, or is its cadence (the Upkeep section's).
        for f in NetworkFile::FIELDS.iter().filter(|f| {
            f.essential
                && f.kind != sentry_core::cfg::Kind::Section
                && f.path.starts_with("networks.*.")
                && !f.path.contains("[]")
                && !f.path.ends_with(".*")
        }) {
            let path = f.path.replace("networks.*", "networks.home");
            assert!(
                items.contains(&path) || f.path == "networks.*.maintenance.cadence",
                "{} is in no form",
                f.path
            );
        }
        assert_eq!(
            k.problems(doc.as_ref(), &warnings)
                .iter()
                .map(Problem::line)
                .collect::<Vec<_>>(),
            ["network_config.yaml · home: backup: keep must be at least 1"]
        );
    }

    #[test]
    fn a_new_record_is_one_its_type_reads_and_recipients_make_a_key() {
        let k = NetworksKind;
        let f: Forward = k
            .blank("networks.home.expect.forwards")
            .unwrap()
            .to()
            .unwrap();
        assert_eq!(
            (f.proto.as_str(), f.port.to_string().as_str()),
            ("tcp", "80")
        );
        let d: Device = k.blank("networks.home.devices").unwrap().to().unwrap();
        assert_eq!(d, Device::default());
        assert_eq!(k.blank("networks.home.notes"), None);
        // The key is offered on the recipients and nowhere else; what it asks for names
        // the network, and it never writes over a file that is there.
        let a = k.action("networks.home.backup.recipients").unwrap();
        assert_eq!(a.label, "make a key");
        assert_eq!(a.start, "~/sentry-home-backup.key");
        assert_eq!(k.action("networks.home.backup.keep"), None);
        assert!(k.act("networks.home.notes", "/nonexistent/x").is_err());
        let dir = std::env::temp_dir().join(format!("sentry-netkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = dir.join("backup.key");
        let public = k
            .act("networks.home.backup.recipients", &file.to_string_lossy())
            .unwrap();
        assert!(public.starts_with("age1"), "{public}");
        assert_eq!(crate::backup::recipient(&public).map(|_| ()), Ok(()));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // The secret half is in the file; what came back isn't it.
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("AGE-SECRET-KEY-") && !public.contains("SECRET"));
        let again = k.act("networks.home.backup.recipients", &file.to_string_lossy());
        assert!(again.unwrap_err().contains("already there"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upkeep_lists_the_workflows_and_stages_the_cadence_in_the_networks_own_list() {
        let k = NetworksKind;
        let (doc, _) = loaded(
            "networks:\n  home:\n    maintenance:\n      cadence: [{workflow: config-backup, every: 7d}]\n",
            "upkeep",
        );
        let up = k.upkeep(doc.as_ref(), "home", false);
        let rows: Vec<(&str, &str, Option<&str>)> = up
            .rows
            .iter()
            .map(|r| (r.name.as_str(), r.every.as_str(), r.suggest))
            .collect();
        assert!(
            rows.contains(&("config-backup", "7d", Some("30d"))),
            "{rows:?}"
        );
        assert!(
            rows.contains(&("package-update", "", Some("30d"))),
            "{rows:?}"
        );
        assert!(rows.contains(&("firmware-upgrade", "", None)), "{rows:?}");
        assert!(up.shared.ends_with("network-workflows"));
        assert!(
            up.own
                .as_ref()
                .unwrap()
                .ends_with("networks/home/workflows")
        );
        let (path, to) = k
            .cadence(doc.as_ref(), "home", "package-update", Some("30d"))
            .unwrap();
        assert_eq!(path, "networks.home.maintenance.cadence");
        assert_eq!(
            to.unwrap().to_string(),
            "[{workflow: \"config-backup\", every: \"7d\"}, {workflow: \"package-update\", every: \"30d\"}]"
        );
        let (_, to) = k
            .cadence(doc.as_ref(), "home", "config-backup", None)
            .unwrap();
        assert_eq!(to.unwrap().to_string(), "[]");
    }
}

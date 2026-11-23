//! The three config files together: read and checked offline (what the window does at start,
//! `Win.config_problems`), and `sentry config check|show|explain` on the command line.

use std::process::ExitCode;

use sentry_app::cfgarea::Problem;
use sentry_core::cfg::{self, ConfigFile, Field, FileId};
use sentry_core::config::Config;
use sentry_network::config::{self as networks, NetworkFile};
use sentry_server::config::{self as servers, ServerFile};

/// The three files as read, and everything wrong in them that can be seen without a host.
pub struct Files {
    pub app: Config,
    /// None: no file, or one that doesn't parse (`servers_err` says which).
    pub servers: Option<ServerFile>,
    pub servers_err: Option<String>,
    pub networks: Option<NetworkFile>,
    pub networks_err: Option<String>,
    /// The files that aren't there (not a problem: nothing configured).
    pub missing: Vec<FileId>,
    pub problems: Vec<Problem>,
}

/// Read the three files and lint them, offline: unknown keys, a file that doesn't parse, each
/// server's and network's `lint`, `[keys]`, `[targets] show`. Reads no host.
pub fn read() -> Files {
    assemble(
        (Config::load(), FileId::App.path().exists()),
        (servers::load(), servers::path().exists()),
        (networks::load(), networks::path().exists()),
    )
}

type Loaded<T> = (Result<(T, Vec<String>), String>, bool);

/// [`read`] from what was read (each file's load, and whether it is there).
fn assemble(
    ((app, warnings), app_there): ((Config, Vec<String>), bool),
    (servers_load, servers_there): Loaded<ServerFile>,
    (networks_load, networks_there): Loaded<NetworkFile>,
) -> Files {
    let mut missing = Vec::new();
    let mut problems = Vec::new();
    if !app_there {
        missing.push(FileId::App);
    }
    problems.extend(warnings.iter().map(|w| Problem::of(FileId::App, None, w)));
    let (_, keys) = sentry_core::tui::keys::Keymap::new(&sentry_local::tui::SCREENS, &app.keys);
    problems.extend(keys.iter().map(|w| Problem::of(FileId::App, None, w)));

    let (servers_file, servers_err) = match servers_load {
        Ok((f, w)) => {
            problems.extend(w.iter().map(|w| Problem::of(FileId::Servers, None, w)));
            for (n, s) in &f.servers {
                problems.extend(
                    servers::lint(n, s)
                        .iter()
                        .map(|p| Problem::of(FileId::Servers, Some(n), p)),
                );
            }
            (Some(f), None)
        }
        Err(e) => {
            if servers_there {
                problems.push(Problem::of(FileId::Servers, None, &e));
            } else {
                missing.push(FileId::Servers);
            }
            (None, Some(e))
        }
    };
    let (networks_file, networks_err) = match networks_load {
        Ok((f, w)) => {
            problems.extend(w.iter().map(|w| Problem::of(FileId::Networks, None, w)));
            for (n, net) in &f.networks {
                problems.extend(
                    networks::lint(n, net)
                        .iter()
                        .map(|p| Problem::of(FileId::Networks, Some(n), p)),
                );
            }
            (Some(f), None)
        }
        Err(e) => {
            if networks_there {
                problems.push(Problem::of(FileId::Networks, None, &e));
            } else {
                missing.push(FileId::Networks);
            }
            (None, Some(e))
        }
    };
    // `[targets] show` against the targets there are.
    if let Ok(plan) = crate::tui::plan_all(
        &app,
        servers_file.as_ref(),
        networks_file.as_ref(),
        crate::tui::Open::Local,
    ) {
        problems.extend(
            plan.warnings
                .iter()
                .map(|w| Problem::of(FileId::App, None, w)),
        );
    }
    Files {
        app,
        servers: servers_file,
        servers_err,
        networks: networks_file,
        networks_err,
        missing,
        problems,
    }
}

const USAGE: &str = "\
sentry config: the three config files (config.toml, server_config.yaml, network_config.yaml)
  sentry config check                       what's wrong in them, without contacting any host
  sentry config show [app|servers|networks] each file as sentry would write it
  sentry config explain [<path>]            what a setting is (servers.<name>.timers), or the list";

/// `sentry config [check|show|explain …]`.
pub fn main(args: &[String]) -> ExitCode {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["check"] => check(),
        ["show"] => show(None),
        ["show", which] => show(Some(which)),
        ["explain"] => explain(None),
        ["explain", path] => explain(Some(path)),
        [] => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn what(file: FileId) -> &'static str {
    match file {
        FileId::App => "every setting at its default",
        FileId::Servers => "no servers",
        FileId::Networks => "no networks",
    }
}

/// `✓`/`✗` per file, as `sentry-server lint` says them; 1 when anything is wrong.
fn check() -> ExitCode {
    let f = read();
    for file in cfg::FILES {
        if f.missing.contains(&file) {
            println!("· {} isn't there ({})", file.name(), what(file));
            continue;
        }
        let mine: Vec<&Problem> = f.problems.iter().filter(|p| p.file == file).collect();
        if mine.is_empty() {
            let entries: Vec<&String> = match file {
                FileId::App => vec![],
                FileId::Servers => f.servers.iter().flat_map(|s| s.servers.keys()).collect(),
                FileId::Networks => f.networks.iter().flat_map(|n| n.networks.keys()).collect(),
            };
            match entries.is_empty() {
                true => println!("✓ {}", file.name()),
                false => println!(
                    "✓ {}: {}",
                    file.name(),
                    entries
                        .iter()
                        .map(|e| e.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        }
        mine.iter().for_each(|p| println!("✗ {}", p.line()));
    }
    if f.problems.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Each file (or the one named) as `cfg::render` writes it from what it says: what a save
/// would make of it. A network's MACs and hostnames are its salt's tags when it has one.
fn show(which: Option<&str>) -> ExitCode {
    let files: Vec<FileId> = match which {
        None => cfg::FILES.to_vec(),
        Some(w) => match FileId::from_word(w) {
            Some(f) => vec![f],
            None => {
                eprintln!("sentry config show: `{w}` is app, servers or networks");
                return ExitCode::from(2);
            }
        },
    };
    let f = read();
    let mut bad = false;
    for (i, file) in files.iter().enumerate() {
        if files.len() > 1 {
            if i > 0 {
                println!();
            }
            println!("# ── {} ──", file.path().display());
        }
        if f.missing.contains(file) {
            println!("# (isn't there: {})", what(*file));
            continue;
        }
        let text = match file {
            FileId::App => cfg::render(&f.app),
            FileId::Servers => match (&f.servers, &f.servers_err) {
                (Some(s), _) => cfg::render(s),
                (None, e) => Err(e.clone().unwrap_or_default()),
            },
            FileId::Networks => match (&f.networks, &f.networks_err) {
                (Some(n), _) => cfg::render(&shown_networks(n)),
                (None, e) => Err(e.clone().unwrap_or_default()),
            },
        };
        match text {
            Ok(t) => print!("{t}"),
            Err(e) => {
                eprintln!("{}: {e}", file.name());
                bad = true;
            }
        }
    }
    if bad {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// The networks as a person may see them printed: devices by their salt's tags where the
/// network has a salt (made by its first audit or read), as they are where it hasn't.
fn shown_networks(f: &NetworkFile) -> NetworkFile {
    let mut f = f.clone();
    for (name, n) in &mut f.networks {
        if let Some(salt) =
            sentry_network::redact::Salt::existing(&sentry_network::remote::scope(name))
        {
            sentry_network::redact::tag_identities(n, &salt);
        }
    }
    f
}

/// Every setting there is, the three files' tables together.
fn all_fields() -> impl Iterator<Item = &'static Field> {
    Config::FIELDS
        .iter()
        .chain(ServerFile::FIELDS)
        .chain(NetworkFile::FIELDS)
}

fn explain(path: Option<&str>) -> ExitCode {
    let Some(path) = path else {
        for f in all_fields() {
            println!("{:<52} {}: {}", f.path, f.label, first_sentence(f.help));
        }
        return ExitCode::SUCCESS;
    };
    match explained(path) {
        Some(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        None => {
            eprintln!(
                "sentry config explain: no setting at `{path}` (`sentry config explain` lists them)"
            );
            ExitCode::FAILURE
        }
    }
}

/// What `sentry config explain <path>` prints: the setting, its kind, its help, whether the
/// window's forms have it, and the settings in it.
pub fn explained(path: &str) -> Option<String> {
    let fields = match FileId::of_path(path) {
        FileId::App => Config::FIELDS,
        FileId::Servers => ServerFile::FIELDS,
        FileId::Networks => NetworkFile::FIELDS,
    };
    let f = cfg::fields::find(fields, path)?;
    let kind = match f.kind {
        cfg::Kind::Choice(words) => format!("one of {}", words.join(", ")),
        k => k.word().to_string(),
    };
    let mut out = format!(
        "{} ({} · {}): {}\n{}\n",
        f.path,
        FileId::of_path(path).name(),
        kind,
        f.label,
        f.help
    );
    if !f.essential {
        out.push_str("Not in the window's forms: `e` there opens the file in $EDITOR.\n");
    }
    let inner: Vec<&Field> = fields
        .iter()
        .filter(|g| {
            g.path
                .strip_prefix(f.path)
                .and_then(|r| r.strip_prefix("[].").or_else(|| r.strip_prefix('.')))
                .is_some_and(|r| !r.contains('.'))
        })
        .collect();
    if !inner.is_empty() {
        out.push_str("In it:\n");
        for g in inner {
            out.push_str(&format!("  {:<48} {}\n", g.path, g.label));
        }
    }
    Some(out)
}

fn first_sentence(help: &str) -> &str {
    help.find(". ").map_or(help, |i| &help[..=i])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything wrong in all three files is found at once, offline, each with its file and
    /// entry: what the window keeps in `Win.config_problems` and says the first of.
    #[test]
    fn every_problem_of_every_file_is_found_at_start() {
        let app = Config::parse(
            "[ui]\nbogus = 1\n[keys]\nnope = \"x\"\n[targets]\nshow = [\"srv:gone\", \"local\"]\n",
        )
        .unwrap();
        let srv = servers::parse(
            "servers:\n  a:\n    sudoo: [x]\n    timers: [{unit: x, max_age: 1d}]\n    smart: [sda]\n  b: {}\n",
        );
        let nets = networks::parse("networks:\n  home:\n    backup: {keep: 0}\n");
        let f = assemble(((app.0, app.1), true), (srv, true), (nets, true));
        let lines: Vec<String> = f.problems.iter().map(Problem::line).collect();
        assert_eq!(
            lines,
            [
                "config.toml: unknown key `ui.bogus` ignored",
                "config.toml: [keys]: unknown action `nope`",
                "server_config.yaml · a: unknown key `servers.a.sudoo` ignored",
                "server_config.yaml · a: timer `x` should end in .timer",
                "server_config.yaml · a: smart device `sda` should be a /dev path",
                "network_config.yaml · home: backup: keep must be at least 1",
                "config.toml: [targets] show: no target `srv:gone`",
            ]
        );
        assert!(f.missing.is_empty());
        let toast = sentry_app::cfgarea::toast(&f.problems).unwrap();
        assert!(toast.starts_with("7 config problems, `sentry config check` lists them"));
        // A file that doesn't parse is a problem; one that isn't there isn't.
        let f = assemble(
            ((Config::default(), vec![]), false),
            (servers::parse("servers: [\n"), true),
            (Err("no file".into()), false),
        );
        assert_eq!(f.missing, [FileId::App, FileId::Networks]);
        assert_eq!(f.problems.len(), 1);
        assert_eq!(f.problems[0].file, FileId::Servers);
        assert!(f.servers.is_none() && f.servers_err.is_some());
    }

    #[test]
    fn explain_finds_a_setting_by_any_of_its_paths() {
        let t = explained("servers.myserver.timers").unwrap();
        assert!(
            t.starts_with("servers.*.timers (server_config.yaml · list of records): Timers\n"),
            "{t}"
        );
        assert!(t.contains("servers.*.timers[].max_age"), "{t}");
        let t = explained("ui.dashboard_hz").unwrap();
        assert!(t.contains("config.toml · number"), "{t}");
        assert!(t.contains("Not in the window's forms"), "{t}");
        let t = explained("networks.home.backup.recipients").unwrap();
        assert!(t.contains("age recipients"), "{t}");
        assert!(explained("servers.\"my.server\".timers[3].unit").is_some());
        assert!(explained("keys.\"screen.history\"").is_some());
        assert!(explained("networks.home.nope").is_none());
        // Every setting of the three files is explained, each in its own file.
        for f in all_fields() {
            let t = explained(f.path).unwrap_or_else(|| panic!("{}", f.path));
            assert!(t.starts_with(f.path), "{t}");
        }
    }

    #[test]
    fn shown_networks_tag_identities_only_with_a_salt() {
        let (f, _) = networks::parse(
            "networks:\n  showtest:\n    devices:\n      - { name: nas, mac: \"02:00:5E:00:53:01\", hostname: nas-box }\n",
        )
        .unwrap();
        // No salt for it yet: as it is.
        let plain = shown_networks(&f);
        assert_eq!(plain, f);
        // With one: tags, the names kept.
        let p = sentry_network::redact::path(&sentry_network::remote::scope("showtest"));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "07".repeat(16)).unwrap();
        let shown = shown_networks(&f);
        let d = &shown.networks["showtest"].devices[0];
        assert_eq!(d.name.as_deref(), Some("nas"));
        assert!(sentry_network::redact::is_tag(d.mac.as_deref().unwrap()));
        assert!(sentry_network::redact::is_tag(
            d.hostname.as_deref().unwrap()
        ));
        let text = cfg::render(&shown).unwrap();
        assert!(
            !text.contains("02:00:5") && !text.contains("nas-box"),
            "{text}"
        );
    }
}

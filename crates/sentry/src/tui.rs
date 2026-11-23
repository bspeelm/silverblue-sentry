//! The one window: this machine, every server in `server_config.yaml` and every network in
//! `network_config.yaml`, each a target of the app (`sentry_app::App`), as `[targets]` in
//! config.toml orders and limits them. `sentry` opens it on this machine, `sentry-server
//! [name]` on that server, `sentry-network [name]` on that network. A target costs nothing
//! until it first has the window.

use std::path::Path;

use sentry_app::cfgarea::Kind as _;
use sentry_app::cfgarea::kind::Probe;
use sentry_core::cfg::FileId;
use sentry_core::config::Config;
use sentry_network::config as networks;
use sentry_network::remote::Router;
use sentry_server::config as servers;
use sentry_server::remote::Remote;

/// Which target has the window when it opens: this machine (`sentry`), a server
/// (`sentry-server [name]`) or a network (`sentry-network [name]`), by name if one was given.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Open<'a> {
    Local,
    Server(Option<&'a str>),
    Network(Option<&'a str>),
    /// `sentry config`: the same window as `sentry`, opened on its Config tab.
    Config,
}

/// `[targets]`' name for this machine (its id as a target is the empty one).
const LOCAL: &str = "local";

/// What the window opens: the targets' names as `[targets]` spells them (`local`,
/// `srv:<name>`, `net:<name>`), in the strip's order, which of them has the window first, and
/// what to say once it's up.
pub(crate) struct Plan {
    targets: Vec<String>,
    focus: usize,
    /// What `[targets] show` names that isn't there (the Config area and `sentry config
    /// check` say the same of the files: `cfgarea::targets_problems`).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) warnings: Vec<String>,
}

/// `server`: `sentry-server [name]` was called (the name, if given). The servers come from
/// `file`; with `sentry` a file that isn't there just means there are none.
#[cfg(test)]
fn plan(
    cfg: &Config,
    file: Option<&servers::ServerFile>,
    server: Option<Option<&str>>,
) -> Result<Plan, String> {
    let open = match server {
        None => Open::Local,
        Some(name) => Open::Server(name),
    };
    plan_all(cfg, file, None, open)
}

/// The same with the networks: this machine first, then the servers, then the networks.
pub(crate) fn plan_all(
    cfg: &Config,
    file: Option<&servers::ServerFile>,
    nets: Option<&networks::NetworkFile>,
    open: Open,
) -> Result<Plan, String> {
    let mut all = vec![LOCAL.to_string()];
    if let Some(f) = file {
        all.extend(f.servers.keys().map(|n| sentry_server::tui::id_of(n)));
    }
    if let Some(f) = nets {
        all.extend(f.networks.keys().map(|n| sentry_network::tui::id_of(n)));
    }
    let (mut targets, unknown) = cfg.targets.pick(&all);
    let mut warnings: Vec<String> = unknown
        .iter()
        .map(|u| format!("config: [targets] show: no target `{u}`"))
        .collect();
    if targets.is_empty() {
        warnings.push("config: [targets] show names no target: showing all".into());
        targets = all;
    }
    let want = match open {
        Open::Local | Open::Config => LOCAL.to_string(),
        Open::Server(name) => {
            let file = file.ok_or("server_config.yaml has no servers")?;
            sentry_server::tui::id_of(servers::pick(file, name)?.0)
        }
        Open::Network(name) => {
            let nets = nets.ok_or("network_config.yaml has no networks")?;
            sentry_network::tui::id_of(networks::pick(nets, name)?.0)
        }
    };
    let focus = match targets.iter().position(|t| *t == want) {
        Some(i) => i,
        // The server or network asked for is opened even when `[targets]` leaves it out.
        None if matches!(open, Open::Server(_) | Open::Network(_)) => {
            targets.push(want);
            targets.len() - 1
        }
        None => 0,
    };
    Ok(Plan {
        targets,
        focus,
        warnings,
    })
}

/// The kinds of config the window's Config area has: one per file, each described by the
/// crate that owns its type.
pub fn kinds() -> Vec<Box<dyn sentry_app::cfgarea::Kind>> {
    vec![
        Box::new(sentry_local::cfgkind::AppKind),
        Box::new(sentry_server::cfgkind::ServersKind),
        Box::new(sentry_network::cfgkind::NetworksKind),
    ]
}

/// What tells an OpenWrt router from anything else, in one read: `ubus` is there, or its
/// os-release says so.
const IDENTIFY: &str = "command -v ubus >/dev/null 2>&1 && echo ubus; \
     . /etc/os-release 2>/dev/null; echo \"id=$ID\"; true";

/// Look at the host behind `ssh` and draft its entry: the one function that decides what
/// a host is. It logs in with your key (`BatchMode`: nothing is ever asked), reads, and
/// changes nothing. An OpenWrt router is drafted as a network, anything else as a server; a
/// host that can't be looked at comes back with why and what to do. Honours
/// `SENTRY_SSH_CONFIG`, as every ssh sentry runs does. (The window calls it on a worker for
/// each host ticked and confirmed; it takes nothing from the window, so a command line can
/// call it too.)
pub fn probe(ssh: &str) -> Probe {
    let host = sentry_app::remote::host(ssh);
    let said = match sentry_core::exec::Cmd::ssh(host, "sh")
        .args(["-c", IDENTIFY])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return Probe::Failed(sentry_app::cfgarea::discover::refusal(ssh, &e.to_string()));
        }
    };
    let name = sentry_app::cfgarea::discover::name_from(ssh);
    match said.lines().any(|l| l == "ubus" || l == "id=openwrt") {
        true => sentry_network::cfgkind::NetworksKind.probe(ssh, "home"),
        false => sentry_server::cfgkind::ServersKind.probe(ssh, &name),
    }
}

/// What builds one target of the window around the `Mail` its threads answer through.
type Make = sentry_app::app::Make;

/// The target `id` (`local`, `srv:<name>`, `net:<name>`) from the configs as given. None:
/// they have no such target.
fn make_with(
    id: &str,
    cfg: &Config,
    file: Option<&servers::ServerFile>,
    nets: Option<&networks::NetworkFile>,
) -> Option<Make> {
    Some(match id.split_once(':') {
        Some(("srv", name)) => {
            let s = file?.servers.get(name)?;
            Box::new(sentry_server::tui::target(Remote::new(name, s)))
        }
        Some(("net", name)) => {
            let n = nets?.networks.get(name)?;
            Box::new(sentry_network::tui::target(Router::new(name, n)))
        }
        _ => Box::new(sentry_local::tui::target(cfg.clone())),
    })
}

/// The target `id` from the config files in `dir` as they are now: what the window calls
/// when a save adds a system (`App::set_maker`).
pub fn make(id: &str, dir: &Path) -> Option<Make> {
    let text = |f: FileId| std::fs::read_to_string(dir.join(f.name())).ok();
    let cfg = text(FileId::App)
        .and_then(|t| Config::parse(&t).ok())
        .map_or_else(Config::default, |(c, _)| c);
    let file = text(FileId::Servers).and_then(|t| servers::parse(&t).ok());
    let nets = text(FileId::Networks).and_then(|t| networks::parse(&t).ok());
    make_with(
        id,
        &cfg,
        file.as_ref().map(|(f, _)| f),
        nets.as_ref().map(|(f, _)| f),
    )
}

/// The window about to open: the config files as read, which targets it has and which has
/// it first, and whether this is a first run.
pub(crate) struct Opening {
    open: Open<'static>,
    /// None of the three config files is there: the window opens on the setup flow.
    pub(crate) first: bool,
    plan: Plan,
    cfg: Config,
    file: Option<servers::ServerFile>,
    nets: Option<networks::NetworkFile>,
    problems: Vec<sentry_app::cfgarea::Problem>,
}

/// Read the config files and plan the window `open` asks for. Err: what to say instead
/// (`sentry-server` with other files there but none of its own, a name nobody has).
pub(crate) fn opening(open: Open) -> Result<Opening, String> {
    // Every file read and checked offline: what's wrong is the window's to show
    // (`Win.config_problems`), and its first is said once the window is up.
    let files = crate::cfgcmd::read();
    // A first run (no config file at all): whichever name it was called by, the window
    // opens on the Config area's setup flow.
    let first = files.first_run();
    let open = if first { Open::Config } else { open };
    let crate::cfgcmd::Files {
        app: cfg,
        servers: file,
        servers_err,
        networks: nets,
        networks_err,
        problems,
        ..
    } = files;
    // `sentry-server` needs its file, `sentry-network` its own; for `sentry` a file that
    // isn't there just means there are none.
    match (open, &servers_err, &networks_err) {
        (Open::Server(_), Some(e), _) | (Open::Network(_), _, Some(e)) => return Err(e.clone()),
        _ => {}
    }
    let plan = plan_all(&cfg, file.as_ref(), nets.as_ref(), open)?;
    Ok(Opening {
        // (Which target has the window is in the plan: only the kind of opening is kept.)
        open: match open {
            Open::Local => Open::Local,
            Open::Config => Open::Config,
            Open::Server(_) => Open::Server(None),
            Open::Network(_) => Open::Network(None),
        },
        first,
        plan,
        cfg,
        file,
        nets,
        problems,
    })
}

impl Opening {
    /// The window: its targets, its Config area, and what a save there needs to be
    /// followed at once.
    pub(crate) fn app(&self, tx: std::sync::mpsc::Sender<sentry_app::Event>) -> sentry_app::App {
        let mut app: Option<sentry_app::App> = None;
        for t in &self.plan.targets {
            let Some(make) = make_with(t, &self.cfg, self.file.as_ref(), self.nets.as_ref()) else {
                continue;
            };
            let id = if t == LOCAL {
                sentry_local::tui::ID
            } else {
                t.as_str()
            };
            match app.as_mut() {
                Some(a) => {
                    a.add(id, make);
                }
                None => app = Some(sentry_app::App::new(tx.clone(), id, make)),
            }
        }
        let mut app = app.expect("a target");
        app.focus_at_start(self.plan.focus);
        // The Config area: each kind of config describes itself, as the targets do.
        for k in kinds() {
            app.config.register(k);
        }
        // What a save in the Config area needs to follow at once: how a host is looked at
        // and drafted, and how a target the files gained is built.
        app.config.set_prober(std::sync::Arc::new(probe));
        app.set_maker(Box::new(make));
        if self.first {
            app.setup_at_start();
        } else if self.open == Open::Config {
            app.config_at_start();
        }
        // The security audit is the window's: every target's facts, read side by side.
        app.win.sec.collect = Some(std::sync::Arc::new(crate::secaudit::collect));
        // What's wrong in the config files, said once the TUI is up (ahead of a `[keys]`
        // warning, which is among them): the first, how many, and where to see them all.
        if let Some(w) = sentry_app::cfgarea::toast(&self.problems) {
            app.warn_at_start(w);
        }
        app.win.config_problems = self.problems.clone();
        app
    }
}

/// `sentry`, `sentry-server [name]` or `sentry-network [name]`: the TUI. Returns the exit code.
pub fn run(open: Open) -> u8 {
    let prog = match open {
        Open::Local | Open::Config => "sentry",
        Open::Server(_) => "sentry-server",
        Open::Network(_) => "sentry-network",
    };
    let opening = match opening(open) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    if opening.plan.targets.iter().any(|t| t == LOCAL) {
        crate::init_logging();
    }
    match sentry_core::tui::run_ui(|tx| opening.app(tx)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{prog}: {e:#}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(names: &[&str]) -> servers::ServerFile {
        servers::ServerFile {
            servers: names
                .iter()
                .map(|n| (n.to_string(), Default::default()))
                .collect(),
        }
    }

    fn cfg(show: Option<&[&str]>) -> Config {
        let mut c = Config::default();
        c.targets.show = show.map(|s| s.iter().map(|x| x.to_string()).collect());
        c
    }

    fn nets(names: &[&str]) -> networks::NetworkFile {
        networks::NetworkFile {
            networks: names
                .iter()
                .map(|n| (n.to_string(), Default::default()))
                .collect(),
        }
    }

    #[test]
    fn every_network_is_a_target_after_the_servers() {
        let (f, n) = (file(&["myserver"]), nets(&["home", "lab"]));
        let p = plan_all(&cfg(None), Some(&f), Some(&n), Open::Local).unwrap();
        assert_eq!(p.targets, ["local", "srv:myserver", "net:home", "net:lab"]);
        assert_eq!(p.focus, 0);
        // `sentry-network lab` opens on it; with several, a name is needed.
        let p = plan_all(&cfg(None), Some(&f), Some(&n), Open::Network(Some("lab"))).unwrap();
        assert_eq!(p.focus, 3);
        let e = plan_all(&cfg(None), Some(&f), Some(&n), Open::Network(None))
            .err()
            .unwrap();
        assert!(e.contains("several networks configured"), "{e}");
        let e = plan_all(&cfg(None), None, Some(&n), Open::Network(Some("nope")))
            .err()
            .unwrap();
        assert!(e.contains("no network `nope`"), "{e}");
        // The only one needs no name; no file at all is `sentry-network`'s own error.
        let one = nets(&["home"]);
        let p = plan_all(&cfg(None), None, Some(&one), Open::Network(None)).unwrap();
        assert_eq!(
            (p.targets, p.focus),
            (vec!["local".into(), "net:home".to_string()], 1)
        );
        assert!(plan_all(&cfg(None), None, None, Open::Network(None)).is_err());
        // The server's command is as it was with networks about.
        let p = plan_all(&cfg(None), Some(&f), Some(&n), Open::Server(None)).unwrap();
        assert_eq!(p.focus, 1);
    }

    #[test]
    fn targets_show_takes_networks_by_their_ids() {
        let (f, n) = (file(&["myserver"]), nets(&["home", "lab"]));
        let c = cfg(Some(&["net:home", "local", "net:gone"]));
        let p = plan_all(&c, Some(&f), Some(&n), Open::Local).unwrap();
        assert_eq!(p.targets, ["net:home", "local"]);
        assert_eq!(p.focus, 1);
        assert_eq!(p.warnings, ["config: [targets] show: no target `net:gone`"]);
        // One left out is opened all the same when it's asked for by name.
        let p = plan_all(&c, Some(&f), Some(&n), Open::Network(Some("lab"))).unwrap();
        assert_eq!(p.targets, ["net:home", "local", "net:lab"]);
        assert_eq!(p.focus, 2);
        // A network and a server of one name are two targets.
        let (f, n) = (file(&["home"]), nets(&["home"]));
        let p = plan_all(&cfg(Some(&["net:home"])), Some(&f), Some(&n), Open::Local).unwrap();
        assert_eq!(p.targets, ["net:home"]);
    }

    #[test]
    fn sentry_alone_is_this_machine() {
        let p = plan(&cfg(None), None, None).unwrap();
        assert_eq!((p.targets, p.focus), (vec!["local".to_string()], 0));
        assert!(p.warnings.is_empty());
        // `sentry-server` with no file: its own error.
        assert!(plan(&cfg(None), None, Some(None)).is_err());
    }

    #[test]
    fn every_server_is_a_target_and_each_command_opens_on_its_own() {
        let f = file(&["myserver", "other"]);
        let p = plan(&cfg(None), Some(&f), None).unwrap();
        assert_eq!(p.targets, ["local", "srv:myserver", "srv:other"]);
        assert_eq!(p.focus, 0);
        let p = plan(&cfg(None), Some(&f), Some(Some("other"))).unwrap();
        assert_eq!(p.focus, 2);
        // Several, none named: as `sentry-server` always said.
        let e = plan(&cfg(None), Some(&f), Some(None)).err().unwrap();
        assert!(e.contains("several servers configured"), "{e}");
        let e = plan(&cfg(None), Some(&f), Some(Some("nope")))
            .err()
            .unwrap();
        assert!(e.contains("no server `nope`"), "{e}");
        // The only one needs no name.
        let p = plan(&cfg(None), Some(&file(&["myserver"])), Some(None)).unwrap();
        assert_eq!((p.targets.len(), p.focus), (2, 1));
    }

    #[test]
    fn targets_show_orders_hides_and_warns() {
        let f = file(&["myserver", "other"]);
        let c = cfg(Some(&["srv:other", "local", "srv:gone"]));
        let p = plan(&c, Some(&f), None).unwrap();
        assert_eq!(p.targets, ["srv:other", "local"]);
        assert_eq!(p.focus, 1);
        assert_eq!(p.warnings, ["config: [targets] show: no target `srv:gone`"]);
        // A server asked for by name is opened though it's left out; alone when only it is shown.
        let p = plan(&c, Some(&f), Some(Some("myserver"))).unwrap();
        assert_eq!((p.targets.len(), p.focus), (3, 2));
        let only = cfg(Some(&["srv:myserver"]));
        let p = plan(&only, Some(&f), Some(Some("myserver"))).unwrap();
        assert_eq!((p.targets, p.focus), (vec!["srv:myserver".to_string()], 0));
        // This machine hidden: `sentry` opens on the first shown.
        let p = plan(&only, Some(&f), None).unwrap();
        assert_eq!(p.focus, 0);
        // Nothing valid: everything.
        let p = plan(&cfg(Some(&[])), Some(&f), None).unwrap();
        assert_eq!(p.targets.len(), 3);
        assert_eq!(p.warnings.len(), 1);
    }
}

//! The one window: this machine, every server in `server_config.yaml` and every network in
//! `network_config.yaml`, each a target of the app (`sentry_app::App`), as `[targets]` in
//! config.toml orders and limits them. `sentry` opens it on this machine, `sentry-server
//! [name]` on that server, `sentry-network [name]` on that network. A target costs nothing
//! until it first has the window.

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
}

/// `[targets]`' name for this machine (its id as a target is the empty one).
const LOCAL: &str = "local";

/// What the window opens: the targets' names as `[targets]` spells them (`local`,
/// `srv:<name>`, `net:<name>`), in the strip's order, which of them has the window first, and
/// what to say once it's up.
struct Plan {
    targets: Vec<String>,
    focus: usize,
    warnings: Vec<String>,
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
fn plan_all(
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
        Open::Local => LOCAL.to_string(),
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
        None if open != Open::Local => {
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

/// `sentry`, `sentry-server [name]` or `sentry-network [name]`: the TUI. Returns the exit code.
pub fn run(open: Open) -> u8 {
    let prog = match open {
        Open::Local => "sentry",
        Open::Server(_) => "sentry-server",
        Open::Network(_) => "sentry-network",
    };
    let (cfg, mut warnings) = Config::load();
    let file = match servers::load() {
        Ok((f, w)) => {
            w.iter().for_each(|w| eprintln!("{w}"));
            Some(f)
        }
        // `sentry-server` needs the file; without one there are just no servers.
        Err(e) if matches!(open, Open::Server(_)) => {
            eprintln!("{e}");
            return 1;
        }
        Err(e) => {
            if servers::path().exists() {
                warnings.push(e);
            }
            None
        }
    };
    let nets = match networks::load() {
        Ok((f, w)) => {
            w.iter().for_each(|w| eprintln!("{w}"));
            Some(f)
        }
        // `sentry-network` needs the file; without one there are just no networks.
        Err(e) if matches!(open, Open::Network(_)) => {
            eprintln!("{e}");
            return 1;
        }
        Err(e) => {
            if networks::path().exists() {
                warnings.push(e);
            }
            None
        }
    };
    let plan = match plan_all(&cfg, file.as_ref(), nets.as_ref(), open) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    if plan.targets.iter().any(|t| t == LOCAL) {
        crate::init_logging();
    }
    warnings.extend(plan.warnings.iter().cloned());
    let r = sentry_core::tui::run_ui(|tx| {
        let mut app: Option<sentry_app::App> = None;
        for t in &plan.targets {
            // What builds the target around the `Mail` its threads answer through.
            type Make = Box<dyn FnOnce(sentry_app::target::Mail) -> Box<dyn sentry_app::Target>>;
            let (id, make): (&str, Make) = match t.split_once(':') {
                Some(("srv", name)) => {
                    let Some(s) = file.as_ref().and_then(|f| f.servers.get(name)) else {
                        continue;
                    };
                    (
                        t,
                        Box::new(sentry_server::tui::target(Remote::new(name, s))),
                    )
                }
                Some(("net", name)) => {
                    let Some(n) = nets.as_ref().and_then(|f| f.networks.get(name)) else {
                        continue;
                    };
                    (
                        t,
                        Box::new(sentry_network::tui::target(Router::new(name, n))),
                    )
                }
                _ => (
                    sentry_local::tui::ID,
                    Box::new(sentry_local::tui::target(cfg.clone())),
                ),
            };
            match app.as_mut() {
                Some(a) => {
                    a.add(id, make);
                }
                None => app = Some(sentry_app::App::new(tx.clone(), id, make)),
            }
        }
        let mut app = app.expect("a target");
        app.focus_at_start(plan.focus);
        // The security audit is the window's: every target's facts, read side by side.
        app.win.sec.collect = Some(std::sync::Arc::new(crate::secaudit::collect));
        // What's wrong in a config file, said once the TUI is up (ahead of a `[keys]` warning).
        if let Some(w) = warnings.into_iter().next() {
            app.warn_at_start(w);
        }
        app
    });
    match r {
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

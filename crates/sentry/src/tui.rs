//! The one window: this machine and every server in `server_config.yaml`, each a target of
//! the app (`sentry_app::App`), as `[targets]` in config.toml orders and limits them. `sentry`
//! opens it on this machine, `sentry-server [name]` on that server. A target costs nothing
//! until it first has the window.

use sentry_core::config::Config;
use sentry_server::config as servers;
use sentry_server::remote::Remote;

/// `[targets]`' name for this machine (its id as a target is the empty one).
const LOCAL: &str = "local";

/// What the window opens: the targets' names as `[targets]` spells them (`local`,
/// `srv:<name>`), in the strip's order, which of them has the window first, and what to say
/// once it's up.
struct Plan {
    targets: Vec<String>,
    focus: usize,
    warnings: Vec<String>,
}

/// `server`: `sentry-server [name]` was called (the name, if given). The servers come from
/// `file`; with `sentry` a file that isn't there just means there are none.
fn plan(
    cfg: &Config,
    file: Option<&servers::ServerFile>,
    server: Option<Option<&str>>,
) -> Result<Plan, String> {
    let mut all = vec![LOCAL.to_string()];
    if let Some(f) = file {
        all.extend(f.servers.keys().map(|n| sentry_server::tui::id_of(n)));
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
    let want = match server {
        None => LOCAL.to_string(),
        Some(name) => {
            let file = file.ok_or("server_config.yaml has no servers")?;
            sentry_server::tui::id_of(servers::pick(file, name)?.0)
        }
    };
    let focus = match targets.iter().position(|t| *t == want) {
        Some(i) => i,
        // The server asked for by name is opened even when `[targets]` leaves it out.
        None if server.is_some() => {
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

/// `sentry` (`server`: None) or `sentry-server [name]`: the TUI. Returns the exit code.
pub fn run(server: Option<Option<&str>>) -> u8 {
    let prog = if server.is_some() {
        "sentry-server"
    } else {
        "sentry"
    };
    let (cfg, mut warnings) = Config::load();
    let file = match servers::load() {
        Ok((f, w)) => {
            w.iter().for_each(|w| eprintln!("{w}"));
            Some(f)
        }
        // `sentry-server` needs the file; `sentry` without one is this machine alone.
        Err(e) if server.is_some() => {
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
    let plan = match plan(&cfg, file.as_ref(), server) {
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
            match t.strip_prefix("srv:") {
                None => {
                    let make = sentry_local::tui::target(cfg.clone());
                    match app.as_mut() {
                        Some(a) => {
                            a.add(sentry_local::tui::ID, make);
                        }
                        None => {
                            app = Some(sentry_app::App::new(
                                tx.clone(),
                                sentry_local::tui::ID,
                                make,
                            ))
                        }
                    }
                }
                Some(name) => {
                    let Some(s) = file.as_ref().and_then(|f| f.servers.get(name)) else {
                        continue;
                    };
                    let make = sentry_server::tui::target(Remote::new(name, s));
                    match app.as_mut() {
                        Some(a) => {
                            a.add(t, make);
                        }
                        None => app = Some(sentry_app::App::new(tx.clone(), t, make)),
                    }
                }
            }
        }
        let mut app = app.expect("a target");
        app.focus_at_start(plan.focus);
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

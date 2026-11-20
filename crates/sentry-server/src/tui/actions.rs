//! Maintenance: every action is a confirm box showing the exact command, then streamed output
//! (with the server's password when sudo wants one: asked once, in the key bar). Nothing runs
//! without Enter on that box.

use ratatui::text::Line;

use super::data::Kind;
use super::screens::View;
use super::target::{Effect, Modal, Own, RunSpec};
use crate::config::CustomAction;
use crate::remote::{Remote, SudoMode};
use sentry_core::exec::{Cmd, sh_quote};
use sentry_core::tui::ScreenId;

/// A root command: the plain command for the pane, and (unless the login is root) the line
/// the app runs for it through sudo, with the server's password when sudo wants one.
fn root(
    r: &Remote,
    mode: Option<SudoMode>,
    argv: &[&str],
) -> Result<(Cmd, Option<String>), String> {
    match mode {
        Some(SudoMode::NoPasswd | SudoMode::Password) => Ok((
            r.cmd("sudo").arg("-n").args(argv).timeout(None),
            Some(format!("sudo {}", cmd_line(argv))),
        )),
        Some(SudoMode::Absent) => Err("this login has no sudo on the server".into()),
        // A server's login goes through sudo; a root login would run it as it is.
        Some(SudoMode::Root) => r
            .privileged(argv)
            .map(|c| (c.timeout(None), None))
            .map_err(|e| e.to_string()),
        None => Err("still checking how sudo works on the server".into()),
    }
}

pub struct Spec<'a> {
    pub title: String,
    pub what: String,
    pub argv: Vec<String>,
    pub confirm: &'a str,
    pub then: Vec<Kind>,
    pub risky: bool,
    pub undo: Option<String>,
    pub warn: Option<String>,
    pub reboot: bool,
}

/// The confirm box for a root action.
pub fn confirm(v: &View, r: &Remote, s: Spec) -> Vec<Effect> {
    let t = v.t;
    let argv: Vec<&str> = s.argv.iter().map(String::as_str).collect();
    let (cmd, line) = match root(r, v.s.sudo.value, &argv) {
        Ok(x) => x,
        Err(e) => return vec![Effect::Toast(e)],
    };
    let mut lines = vec![
        Line::styled(s.what.clone(), t.fg()),
        Line::raw(""),
        Line::styled(format!("$ sudo {}", cmd_line(&argv)), t.fg()),
        Line::styled(format!("on {} ({})", r.name, r.host), t.dim()),
    ];
    if let Some(u) = &s.undo {
        lines.push(Line::styled(format!("undo: {u}"), t.dim()));
    }
    if let Some(w) = &s.warn {
        lines.push(Line::styled(w.clone(), t.s(t.yellow)));
    }
    if s.risky {
        lines.push(Line::styled("This is hard to undo.", t.s(t.red)));
    }
    let run = Own::run(RunSpec {
        title: s.title.clone(),
        cmd,
        then: s.then.clone(),
        reboot: s.reboot,
        root: line,
    });
    vec![Effect::Confirm(Modal {
        title: s.title,
        color: if s.risky { t.red } else { t.yellow },
        lines,
        yes: Some((s.confirm.to_string(), vec![run])),
    })]
}

fn cmd_line(argv: &[&str]) -> String {
    argv.iter()
        .map(|a| sh_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

fn spec(
    title: &str,
    what: String,
    argv: &[&str],
    confirm: &'static str,
    then: &[Kind],
) -> Spec<'static> {
    Spec {
        title: title.into(),
        what,
        argv: argv.iter().map(|s| s.to_string()).collect(),
        confirm,
        then: then.to_vec(),
        risky: false,
        undo: None,
        warn: None,
        reboot: false,
    }
}

/// Read-only output in the scrollable pane (logs).
fn logs(r: &Remote, title: String, argv: &[&str]) -> Vec<Effect> {
    match r.privileged(argv) {
        Ok(c) => vec![Effect::Logs(
            title,
            c.timeout(Some(std::time::Duration::from_secs(30))),
        )],
        Err(e) => vec![Effect::Toast(e.to_string())],
    }
}

// ---------- per screen ----------

pub fn services(v: &View, r: &Remote, c: char, unit: &str, failed: bool) -> Vec<Effect> {
    let timer = unit.ends_with(".timer");
    match c {
        'R' if timer => {
            let svc =
                v.s.units
                    .value
                    .as_ref()
                    .and_then(|u| u.get(unit))
                    .and_then(|u| u.triggers.clone())
                    .unwrap_or_else(|| unit.replace(".timer", ".service"));
            confirm(
                v,
                r,
                spec(
                    "Run now",
                    format!("Start {svc} now instead of waiting for {unit}."),
                    &["systemctl", "start", &svc],
                    "run it",
                    &[Kind::Units],
                ),
            )
        }
        'R' => {
            let mut s = spec(
                "Restart",
                format!("Restart {unit}."),
                &["systemctl", "restart", unit],
                "restart",
                &[Kind::Units],
            );
            if unit.starts_with("ssh") {
                s.risky = true;
                s.warn = Some(
                    "This is the ssh server sentry-server talks through; if it doesn't come back, \
                     you'll need the console."
                        .into(),
                );
            }
            confirm(v, r, s)
        }
        'x' if failed => confirm(
            v,
            r,
            Spec {
                undo: Some("it shows as failed again if it fails again".into()),
                ..spec(
                    "Clear failed state",
                    format!("Tell systemd to forget that {unit} failed."),
                    &["systemctl", "reset-failed", unit],
                    "clear it",
                    &[Kind::Units],
                )
            },
        ),
        'x' => vec![Effect::Toast(format!("{unit} hasn't failed"))],
        'L' => {
            let target = if timer {
                unit.replace(".timer", ".service")
            } else {
                unit.to_string()
            };
            logs(
                r,
                format!("journal · {target}"),
                &["journalctl", "-u", &target, "-n", "300", "--no-pager"],
            )
        }
        _ => Vec::new(),
    }
}

pub fn containers(v: &View, r: &Remote, c: char, name: &str, project: Option<&str>) -> Vec<Effect> {
    let compose_file = |p: &str| -> Option<String> {
        v.cfg
            .compose
            .iter()
            .find(|c| c.name == p)
            .map(|c| c.file.clone())
            .or_else(|| {
                v.s.docker.value.as_ref().and_then(|d| {
                    d.projects
                        .iter()
                        .find(|x| x.name == p)
                        .map(|x| x.files.split(',').next().unwrap_or("").to_string())
                })
            })
    };
    match c {
        'R' => confirm(
            v,
            r,
            spec(
                "Restart container",
                format!("Restart the container {name}."),
                &["docker", "restart", name],
                "restart",
                &[Kind::Docker],
            ),
        ),
        'L' => logs(
            r,
            format!("docker logs · {name}"),
            &["docker", "logs", "--tail", "300", "--timestamps", name],
        ),
        'p' | 'u' => {
            let Some(p) = project else {
                return vec![Effect::Toast(format!(
                    "{name} isn't part of a compose project"
                ))];
            };
            let Some(file) = compose_file(p) else {
                return vec![Effect::Toast(format!(
                    "no compose file known for {p}: add it to compose: in server_config.yaml"
                ))];
            };
            if c == 'p' {
                confirm(
                    v,
                    r,
                    spec(
                        "Pull images",
                        format!(
                            "Download newer images for every service in {p}. Nothing restarts yet: u does that."
                        ),
                        &["docker", "compose", "-f", &file, "pull"],
                        "pull",
                        &[Kind::Docker],
                    ),
                )
            } else {
                confirm(
                    v,
                    r,
                    Spec {
                        warn: Some("Containers whose image or settings changed are recreated (a short outage for each).".into()),
                        ..spec(
                            "Bring the project up",
                            format!("Start {p}'s containers, recreating the ones that changed."),
                            &["docker", "compose", "-f", &file, "up", "-d"],
                            "up -d",
                            &[Kind::Docker],
                        )
                    },
                )
            }
        }
        _ => Vec::new(),
    }
}

pub fn reboot(v: &View, r: &Remote) -> Vec<Effect> {
    let why =
        v.s.apt
            .value
            .as_ref()
            .map_or(String::new(), |a| match &a.newest_kernel {
                Some(n) if a.kernel_pending() => format!(" It comes back on kernel {n}."),
                _ => String::new(),
            });
    confirm(
        v,
        r,
        Spec {
            risky: true,
            reboot: true,
            warn: Some("Every service and container on it stops until it's back. sentry-server waits and tells you when it is.".into()),
            ..spec(
                "Reboot the server",
                format!("Reboot {}.{why}", r.name),
                &["systemctl", "reboot"],
                "reboot",
                &[],
            )
        },
    )
}

/// `a`: your own actions from server_config.yaml.
pub fn custom(v: &View, r: &Remote) -> Vec<Effect> {
    if v.cfg.actions.is_empty() {
        return vec![Effect::Toast(
            "no actions: add some under actions: in server_config.yaml".into(),
        )];
    }
    let choices = v
        .cfg
        .actions
        .iter()
        .map(|a| (a.title.clone(), custom_one(v, r, a)))
        .collect();
    vec![Effect::Choose(super::target::Choice::numbered(
        v.t, "Actions", choices,
    ))]
}

fn custom_one(v: &View, r: &Remote, a: &CustomAction) -> Vec<Effect> {
    let t = v.t;
    if a.sudo {
        return confirm(
            v,
            r,
            Spec {
                risky: a.risky,
                undo: a.undo.clone(),
                ..spec(
                    &a.title,
                    format!("Your action `{}`.", a.id),
                    &["sh", "-c", &a.run],
                    "run",
                    &[Kind::Units, Kind::Docker],
                )
            },
        );
    }
    let cmd = r.sh(&a.run).timeout(None);
    let mut lines = vec![
        Line::styled(format!("Your action `{}`.", a.id), t.fg()),
        Line::raw(""),
        Line::styled(format!("$ {}", a.run), t.fg()),
        Line::styled(format!("on {} ({})", r.name, r.host), t.dim()),
    ];
    if let Some(u) = &a.undo {
        lines.push(Line::styled(format!("undo: {u}"), t.dim()));
    }
    if a.risky {
        lines.push(Line::styled("This is hard to undo.", t.s(t.red)));
    }
    vec![Effect::Confirm(Modal {
        title: a.title.clone(),
        color: if a.risky { t.red } else { t.yellow },
        lines,
        yes: Some((
            "run".into(),
            vec![Own::run(RunSpec {
                title: a.title.clone(),
                cmd,
                then: vec![Kind::Units, Kind::Docker],
                reboot: false,
                root: None,
            })],
        )),
    })]
}

/// Keys each screen adds for maintenance.
pub fn hints(tab: ScreenId) -> Vec<(&'static str, &'static str)> {
    match tab {
        ScreenId::Dash => vec![("a", "actions"), ("B", "reboot")],
        ScreenId::Svc => vec![("R", "restart/run"), ("x", "reset failed"), ("L", "log")],
        ScreenId::Cont => vec![
            ("R", "restart"),
            ("L", "log"),
            ("p", "pull"),
            ("u", "up -d"),
        ],
        _ => Vec::new(),
    }
}

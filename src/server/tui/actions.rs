//! Maintenance: every action is a confirm box showing the exact command, then streamed output
//! (or, when sudo wants a password, the terminal handed over). Nothing runs without `y`.

use ratatui::text::Line;

use super::Tab;
use super::app::{Effect, Modal, RunSpec};
use super::data::Kind;
use super::tabs::View;
use crate::exec::{Cmd, sh_quote};
use crate::server::config::CustomAction;
use crate::server::remote::{Remote, SudoMode};

/// A root command, built for how sudo behaves here: streamed when no password is needed,
/// interactive when it asks for one.
fn root(r: &Remote, mode: Option<SudoMode>, argv: &[&str]) -> Result<(Cmd, bool), String> {
    match mode {
        Some(SudoMode::NoPasswd) => Ok((r.cmd("sudo").arg("-n").args(argv).timeout(None), false)),
        Some(SudoMode::Password) => Ok((r.cmd("sudo").args(argv).timeout(None), true)),
        Some(SudoMode::Absent) => Err("this login has no sudo on the server".into()),
        None => Err("still checking how sudo works on the server".into()),
    }
}

/// Keys whose action may run something as root (so sudo is checked again first).
pub fn uses_root(tab: Tab, c: char) -> bool {
    matches!(
        (tab, c),
        (Tab::Services, 'R' | 'x')
            | (Tab::Containers, 'R' | 'p' | 'u')
            | (Tab::Updates, 'C' | 'U' | 'B')
    )
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
    let (cmd, interactive) = match root(r, v.s.sudo.value, &argv) {
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
    if interactive {
        lines.push(Line::styled(
            "sudo asks for your password: the terminal is handed over while it runs.",
            t.dim(),
        ));
    }
    if let Some(w) = &s.warn {
        lines.push(Line::styled(w.clone(), t.s(t.yellow)));
    }
    if s.risky {
        lines.push(Line::styled("This is hard to undo.", t.s(t.red)));
    }
    let run = if interactive {
        Effect::Suspend(
            cmd,
            format!("sentry-server · {} on {}", s.title, r.name),
            s.then.clone(),
            s.reboot,
        )
    } else {
        Effect::Run(RunSpec {
            title: s.title.clone(),
            cmd,
            then: s.then.clone(),
            reboot: s.reboot,
        })
    };
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

// ---------- per tab ----------

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

pub fn updates(v: &View, r: &Remote, c: char) -> Vec<Effect> {
    match c {
        'C' => confirm(
            v,
            r,
            spec(
                "Refresh package lists",
                "Download the current package lists (apt-get update), then simulate the upgrade again.".into(),
                &["apt-get", "update"],
                "refresh",
                &[Kind::Apt],
            ),
        ),
        'U' => {
            let Some(a) = &v.s.apt.value else {
                return vec![Effect::Toast("no update list yet".into())];
            };
            if a.upgrades.is_empty() {
                return vec![Effect::Toast("nothing to upgrade".into())];
            }
            let names: Vec<&str> = a.upgrades.iter().map(|p| p.name.as_str()).collect();
            let mut s = spec(
                "Upgrade packages",
                format!("Install {} update(s): {}.", names.len(), names.join(" ")),
                &["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "dist-upgrade"],
                "upgrade",
                &[Kind::Apt, Kind::Units, Kind::Docker],
            );
            let mut warns = Vec::new();
            if !a.removals.is_empty() {
                warns.push(format!("It also removes: {}.", a.removals.join(" ")));
            }
            if a.upgrades.iter().any(|p| p.name.starts_with("docker") || p.name.starts_with("containerd")) {
                warns.push("Docker itself is upgraded: containers restart.".into());
            }
            if !warns.is_empty() {
                s.warn = Some(warns.join(" "));
            }
            confirm(v, r, s)
        }
        'B' => reboot(v, r),
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
    vec![Effect::Choose("Actions".into(), choices)]
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
            vec![Effect::Run(RunSpec {
                title: a.title.clone(),
                cmd,
                then: vec![Kind::Units, Kind::Docker],
                reboot: false,
            })],
        )),
    })]
}

/// Keys each tab adds for maintenance.
pub fn hints(tab: Tab) -> Vec<(&'static str, &'static str)> {
    match tab {
        Tab::Overview => vec![("a", "actions"), ("B", "reboot")],
        Tab::Services => vec![("R", "restart/run"), ("x", "reset failed"), ("L", "log")],
        Tab::Containers => vec![
            ("R", "restart"),
            ("L", "log"),
            ("p", "pull"),
            ("u", "up -d"),
        ],
        Tab::Updates => vec![("C", "refresh lists"), ("U", "upgrade"), ("B", "reboot")],
        Tab::Audit | Tab::Workflows => Vec::new(),
    }
}

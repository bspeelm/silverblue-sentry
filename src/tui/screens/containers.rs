//! Containers: toolbox / distrobox / podman with stale and $HOME-mount flags.
//! `Enter` opens a shell in a new terminal window, `s` stops, `d` removes (confirmed).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row};

use super::{Cursor, Hints, View};
use crate::collectors::podman::{Ctr, Kind};
use crate::exec::Cmd;
use crate::fmt;
use crate::tui::app::{Effect, Modal, RunSpec};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::widgets::{TableSpec, table};

#[derive(Default)]
pub struct Containers {
    pub cur: Cursor,
}

pub fn on_enter(_v: &View) -> Vec<Effect> {
    vec![Effect::Fetch(Fetch::Podman)]
}

pub fn hints() -> Hints {
    vec![
        ("j/k", "select"),
        ("Enter", "enter"),
        ("s", "stop"),
        ("d", "remove"),
        ("r", "refresh"),
    ]
}

/// Shell command that enters the container.
pub fn enter_argv(c: &Ctr) -> Option<Vec<String>> {
    Some(match c.kind {
        Kind::Toolbox => vec!["toolbox".into(), "enter".into(), c.name.clone()],
        Kind::Distrobox => vec!["distrobox".into(), "enter".into(), c.name.clone()],
        Kind::Podman if c.running() => vec![
            "podman".into(),
            "exec".into(),
            "-it".into(),
            c.name.clone(),
            "sh".into(),
        ],
        Kind::Podman => return None,
    })
}

/// A new terminal window running `argv`, or `None` if no terminal emulator is found.
pub fn terminal_cmd(configured: Option<&str>, argv: &[String]) -> Option<Cmd> {
    let with = |prefix: &[&str]| -> Option<Cmd> {
        let c = Cmd::host(prefix[0]);
        c.available().then(|| {
            c.args(prefix[1..].iter().copied())
                .args(argv.iter().map(String::as_str))
        })
    };
    if let Some(t) = configured {
        let parts: Vec<&str> = t.split_whitespace().collect();
        if !parts.is_empty()
            && let Some(c) = with(&parts)
        {
            return Some(c);
        }
    }
    if let Ok(t) = std::env::var("TERMINAL")
        && !t.is_empty()
        && let Some(c) = with(&[&t, "-e"])
    {
        return Some(c);
    }
    [
        &["xdg-terminal-exec"][..],
        &["ghostty", "-e"],
        &["ptyxis", "--"],
        &["gnome-terminal", "--"],
        &["kgx", "--"],
    ]
    .into_iter()
    .find_map(with)
}

impl Containers {
    fn rows<'a>(&self, v: &View<'a>) -> Vec<&'a Ctr> {
        v.d.podman.get().map_or(Vec::new(), |p| {
            p.containers
                .iter()
                .filter(|c| v.matches(&[&c.name, &c.image, c.kind.as_str(), &c.state]))
                .collect()
        })
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        let rows = self.rows(v);
        if self.cur.nav(a, rows.len()) {
            return Vec::new();
        }
        if a == Action::Refresh {
            return vec![Effect::Fetch(Fetch::Podman)];
        }
        let Some(c) = rows.get(self.cur.clamp(rows.len())) else {
            return Vec::new();
        };
        let t = v.t;
        let then = vec![Fetch::Podman];
        match a {
            Action::Enter => {
                let Some(argv) = enter_argv(c) else {
                    return vec![Effect::Toast(format!("{} is not running", c.name))];
                };
                match terminal_cmd(v.cfg.ui.terminal.as_deref(), &argv) {
                    Some(cmd) => vec![Effect::Detach(
                        cmd,
                        format!("opening {} in a new terminal", c.name),
                    )],
                    // No terminal emulator: use this one; sentry resumes when the shell exits.
                    None => vec![Effect::Suspend(
                        Cmd::host(&argv[0])
                            .args(argv[1..].iter().map(String::as_str))
                            .timeout(None),
                    )],
                }
            }
            Action::Char('s') if !c.running() => {
                vec![Effect::Toast(format!("{} is already stopped", c.name))]
            }
            Action::Char('s') => {
                let cmd = Cmd::host("podman").args(["stop", &c.name]).timeout(None);
                vec![Effect::Confirm(Modal {
                    title: "Stop container".into(),
                    color: t.yellow,
                    lines: vec![
                        Line::styled(format!("Stop {} ({})?", c.name, c.kind.as_str()), t.fg()),
                        Line::styled(format!("$ {}", cmd.display()), t.dim()),
                    ],
                    yes: Some((
                        "stop".into(),
                        vec![Effect::Run(RunSpec {
                            title: format!("podman stop {}", c.name),
                            cmd,
                            then,
                            ok_toast: format!("{} stopped", c.name),
                        })],
                    )),
                })]
            }
            Action::Char('d') if c.running() => vec![Effect::Toast(format!(
                "{} is running — stop it first (s)",
                c.name
            ))],
            Action::Char('d') => {
                let cmd = Cmd::host("podman").args(["rm", &c.name]).timeout(None);
                let mut lines = vec![
                    Line::styled(
                        format!("Remove {} ({}, {})?", c.name, c.kind.as_str(), c.image),
                        t.fg(),
                    ),
                    Line::styled(format!("$ {}", cmd.display()), t.dim()),
                ];
                if c.kind != Kind::Podman {
                    lines.push(Line::styled(
                        "Packages installed inside it are lost; $HOME is shared and untouched.",
                        t.dim(),
                    ));
                }
                vec![Effect::Confirm(Modal {
                    title: "Remove container".into(),
                    color: t.red,
                    lines,
                    yes: Some((
                        "remove".into(),
                        vec![Effect::Run(RunSpec {
                            title: format!("podman rm {}", c.name),
                            cmd,
                            then,
                            ok_toast: format!("{} removed", c.name),
                        })],
                    )),
                })]
            }
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let [list, _, foot] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);
        let Some(p) = v.d.podman.get() else {
            f.render_widget(
                Paragraph::new(v.d.podman.status(v.d.loading(Fetch::Podman))).style(t.dim()),
                list,
            );
            return;
        };
        let rows = self.rows(v);
        self.cur.page = list.height as usize;
        let sel = self.cur.clamp(rows.len());
        let body: Vec<Row> = rows
            .iter()
            .map(|c| {
                let age = format!(
                    "{}{}",
                    fmt::age(c.age_s),
                    if c.stale { " stale" } else { "" }
                );
                let home = if c.home_mount { "yes" } else { "no" };
                let home_c = match (c.home_mount, c.stale) {
                    (true, true) => t.red,
                    (true, false) => t.yellow,
                    _ => t.dim,
                };
                Row::new(vec![
                    Cell::from(c.name.clone()),
                    Cell::from(c.kind.as_str()).style(t.dim()),
                    Cell::from(c.state.clone()).style(t.s(if c.running() {
                        t.green
                    } else {
                        t.dim
                    })),
                    Cell::from(age).style(t.s(if c.stale { t.yellow } else { t.dim })),
                    Cell::from(home).style(t.s(home_c)),
                    Cell::from(c.image.clone()).style(t.dim()),
                ])
            })
            .collect();
        table(
            f,
            list,
            t,
            TableSpec {
                header: vec!["NAME", "KIND", "STATUS", "AGE", "$HOME", "IMAGE"],
                widths: vec![
                    Constraint::Length(24),
                    Constraint::Length(10),
                    Constraint::Length(9),
                    Constraint::Length(10),
                    Constraint::Length(6),
                    Constraint::Fill(1),
                ],
                rows: body,
                selected: (!rows.is_empty()).then_some(sel),
            },
        );
        let summary = Line::from(vec![Span::styled(
            format!(
                "images {} · {} · {} dangling ({})   volumes {}   stale = stopped > {}d",
                p.images.count,
                fmt::bytes(p.images.bytes),
                p.dangling.count,
                fmt::bytes(p.dangling.bytes),
                p.volumes,
                v.cfg.audit.stale_container_days
            ),
            t.dim(),
        )]);
        f.render_widget(Paragraph::new(summary), foot);
    }
}

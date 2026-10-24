//! Containers: toolbox / distrobox / podman with stale and $HOME-mount flags, plus pending
//! package updates inside toolboxes. `Enter` opens a shell in a new terminal window, `s` stops,
//! `d` removes, `c` checks toolbox updates, `u`/`U` upgrade one/all (all confirmed).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row};

use super::{Cursor, Hints, View};
use crate::collectors::podman::{Ctr, Kind};
use crate::collectors::toolbox::{self, BoxUpdates};
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
        ("c", "check updates"),
        ("u/U", "upgrade one/all"),
        ("s", "stop"),
        ("d", "remove"),
    ]
}

fn box_updates<'a>(v: &View<'a>, name: &str) -> Option<&'a BoxUpdates> {
    v.d.tbx_updates.get()?.data.get(name)
}

/// Run spec that upgrades `targets` in order and re-checks afterwards.
fn upgrade_run(targets: &[&Ctr], title: String) -> Option<Effect> {
    let mut cmds = targets
        .iter()
        .map(|c| toolbox::upgrade_cmd(&c.name, c.running()));
    let first = cmds.next()?;
    Some(Effect::Run(RunSpec {
        title,
        cmd: first,
        queue: cmds.collect(),
        then: vec![Fetch::Podman, Fetch::ToolboxUpdates],
        ok_toast: "toolbox upgrade done · re-checking".into(),
    }))
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
        let t = v.t;
        if a == Action::Check {
            let n = rows.iter().filter(|c| c.kind != Kind::Podman).count();
            return vec![
                Effect::Fetch(Fetch::ToolboxUpdates),
                Effect::Toast(format!(
                    "checking {n} toolbox(es) · stopped ones are started, then stopped again"
                )),
            ];
        }
        if a == Action::Char('U') {
            let pending: Vec<&Ctr> = rows
                .iter()
                .copied()
                .filter(|c| box_updates(v, &c.name).is_some_and(|b| !b.updates.is_empty()))
                .collect();
            if pending.is_empty() {
                return vec![Effect::Toast(
                    "no toolbox has pending updates (c checks)".into(),
                )];
            }
            let mut lines: Vec<Line> = pending
                .iter()
                .map(|c| {
                    let n = box_updates(v, &c.name).map_or(0, |b| b.updates.len());
                    Line::styled(format!("• {:<24} {n} package(s)", c.name), t.fg())
                })
                .collect();
            lines.push(Line::styled(
                "$ podman exec --user root <name> dnf -y upgrade   (stopped ones: start, upgrade, stop)",
                t.dim(),
            ));
            let Some(run) = upgrade_run(&pending, "upgrade toolboxes".into()) else {
                return Vec::new();
            };
            return vec![Effect::Confirm(Modal {
                title: "Upgrade all toolboxes".into(),
                color: t.yellow,
                lines,
                yes: Some((format!("upgrade {}", pending.len()), vec![run])),
            })];
        }
        let Some(c) = rows.get(self.cur.clamp(rows.len())) else {
            return Vec::new();
        };
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
            Action::Char('u') if c.kind == Kind::Podman => vec![Effect::Toast(format!(
                "{} is a plain podman container: update it by pulling a new image",
                c.name
            ))],
            Action::Char('u') => match box_updates(v, &c.name) {
                None => vec![Effect::Toast(format!(
                    "{} not checked yet · press c",
                    c.name
                ))],
                Some(b) if b.error.is_some() => vec![Effect::Toast(format!(
                    "{}: {}",
                    c.name,
                    b.error.as_deref().unwrap_or("")
                ))],
                Some(b) if b.updates.is_empty() => {
                    vec![Effect::Toast(format!("{} is up to date", c.name))]
                }
                Some(b) => {
                    let cmd = toolbox::upgrade_cmd(&c.name, c.running());
                    let mut lines = vec![
                        Line::styled(
                            format!("Upgrade {} package(s) in {}?", b.updates.len(), c.name),
                            t.fg(),
                        ),
                        Line::styled(format!("$ {}", cmd.display()), t.dim()),
                    ];
                    if !c.running() {
                        lines.push(Line::styled(
                            "It's stopped: started for the upgrade, stopped again after.",
                            t.dim(),
                        ));
                    }
                    let Some(run) = upgrade_run(&[c], format!("dnf upgrade · {}", c.name)) else {
                        return Vec::new();
                    };
                    vec![Effect::Confirm(Modal {
                        title: "Upgrade toolbox".into(),
                        color: t.yellow,
                        lines,
                        yes: Some(("upgrade".into(), vec![run])),
                    })]
                }
            },
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
                            queue: Vec::new(),
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
                            queue: Vec::new(),
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
        // The table gets what it needs; the selected toolbox's updates fill the rest.
        let n_rows = self.rows(v).len() as u16;
        let table_h = (n_rows + 2).clamp(4, area.height / 2);
        let [list, _, pane, _, foot] = Layout::vertical([
            Constraint::Length(table_h),
            Constraint::Length(1),
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
                let (upd, uc) = match (c.kind, box_updates(v, &c.name)) {
                    (Kind::Podman, _) => ("image".to_string(), t.dim),
                    (_, None) => ("—".into(), t.dim),
                    (_, Some(b)) if b.error.as_deref() == Some("not dnf") => ("n/a".into(), t.dim),
                    (_, Some(b)) if b.error.is_some() => ("✗".into(), t.red),
                    (_, Some(b)) if b.updates.is_empty() => ("0".into(), t.dim),
                    (_, Some(b)) => (format!("{} ↑", b.updates.len()), t.yellow),
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
                    Cell::from(upd).style(t.s(uc)),
                    Cell::from(c.image.clone()).style(t.dim()),
                ])
            })
            .collect();
        table(
            f,
            list,
            t,
            TableSpec {
                header: vec!["NAME", "KIND", "STATUS", "AGE", "$HOME", "UPDATES", "IMAGE"],
                widths: vec![
                    Constraint::Length(24),
                    Constraint::Length(10),
                    Constraint::Length(9),
                    Constraint::Length(10),
                    Constraint::Length(6),
                    Constraint::Length(8),
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
        if let Some(c) = rows.get(sel) {
            self.render_updates(f, pane, v, c);
        }
    }

    fn render_updates(&self, f: &mut Frame, area: Rect, v: &View, c: &Ctr) {
        let t = v.t;
        let checking = v.d.loading(Fetch::ToolboxUpdates);
        let cached = v.d.tbx_updates.get();
        let b = cached.and_then(|x| x.data.get(&c.name));
        let detail = match (b, checking) {
            (_, true) => "checking…".to_string(),
            (Some(b), false) => {
                let age = (jiff::Timestamp::now().as_second() - b.checked_at.as_second()).max(0);
                format!("{} pending · checked {}", b.updates.len(), fmt::ago(age))
            }
            (None, false) => "never checked · press c".into(),
        };
        let block = crate::tui::widgets::panel(t, "Updates", format!("{} · {detail}", c.name));
        let r = crate::tui::widgets::inner(&block, area);
        f.render_widget(block, area);
        let msg = |s: &str| Paragraph::new(Span::styled(s.to_string(), t.dim()));
        if c.kind == Kind::Podman {
            f.render_widget(
                msg("Plain podman containers update by pulling a newer image; nothing to check inside."),
                r,
            );
            return;
        }
        let Some(b) = b else {
            f.render_widget(
                msg("Press c to run dnf check-update in every toolbox (stopped ones are started, then stopped)."),
                r,
            );
            return;
        };
        if let Some(e) = &b.error {
            f.render_widget(msg(&format!("✗ {e}")), r);
            return;
        }
        if b.updates.is_empty() {
            f.render_widget(msg("Up to date."), r);
            return;
        }
        let w = r.width as usize;
        let body: Vec<Row> = b
            .updates
            .iter()
            .map(|u| {
                Row::new(vec![
                    Cell::from(u.name.clone()),
                    Cell::from(format!("{} → {}", u.old.as_deref().unwrap_or("?"), u.new)),
                    Cell::from(u.repo.clone()).style(t.dim()),
                ])
            })
            .collect();
        table(
            f,
            r,
            t,
            TableSpec {
                header: vec!["PACKAGE", "VERSION", "REPO"],
                widths: vec![
                    Constraint::Length((w / 3).min(40) as u16),
                    Constraint::Fill(1),
                    Constraint::Length(14),
                ],
                rows: body,
                selected: None,
            },
        );
    }
}

impl Containers {
    pub fn ask(&self, v: &View) -> Result<crate::claude::Ask, String> {
        let rows = self.rows(v);
        let c = rows
            .get(self.cur.sel.min(rows.len().saturating_sub(1)))
            .ok_or("no container selected")?;
        let upd = match box_updates(v, &c.name) {
            Some(b) if b.error.is_none() => {
                let names: Vec<&str> = b.updates.iter().take(20).map(|u| u.name.as_str()).collect();
                format!(
                    "{} pending dnf updates: {}",
                    b.updates.len(),
                    names.join(" ")
                )
            }
            Some(b) => format!("update check failed: {}", b.error.as_deref().unwrap_or("")),
            None => "updates not checked".into(),
        };
        Ok(crate::claude::Ask::new(
            format!("container {}", c.name),
            format!(
                "A podman container on my machine:\nname {}\nkind {} (toolbox/distrobox containers share my home folder)\nimage {}\nstate {} ({})\nage {}{}\nmounts $HOME: {}\n{upd}",
                c.name,
                c.kind.as_str(),
                c.image,
                c.state,
                c.status,
                fmt::age(c.age_s),
                if c.stale { ", stale" } else { "" },
                if c.home_mount { "yes" } else { "no" }
            ),
            "What is this container for, is it safe to keep or remove, and does it need updating?",
        ))
    }
}

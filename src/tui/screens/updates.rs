//! Updates: rpm-ostree deployments + pending update (from rpm-ostree's cached-update), cached
//! Flatpak updates. `u` upgrades (kmod ritual stage 1 when the kernel changes), `f` flatpak
//! update, `R` rollback — each behind a confirm modal, then streamed.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row};

use super::{Hints, View};
use crate::collectors::ostree::{Ostree, UpgradePlan, upgrade_plan};
use crate::exec::Cmd;
use crate::fmt;
use crate::tui::app::{Effect, Modal, RunSpec};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::theme::Theme;
use crate::tui::widgets::{TableSpec, inner, panel, table, trunc};

#[derive(Default)]
pub struct Updates;

pub fn on_enter(v: &View) -> Vec<Effect> {
    let mut e = vec![Effect::Fetch(Fetch::Ostree)];
    if v.d.flatpak.get().is_none() {
        // Installed versions, for "old → new" in the Flatpak pane.
        e.push(Effect::Fetch(Fetch::Flatpak));
    }
    e
}

pub fn hints(_v: &View) -> Hints {
    vec![
        ("c", "check now"),
        ("u", "upgrade"),
        ("f", "flatpak update"),
        ("R", "rollback"),
        ("r", "refresh"),
    ]
}

fn upgrade_effects(t: &Theme, o: &Ostree) -> Vec<Effect> {
    let u = o.update.as_ref();
    let summary = u.map_or(String::new(), |u| {
        format!(
            "{} → {} · {} packages",
            o.booted().map_or("?", |b| &b.version),
            u.version.as_deref().unwrap_or("?"),
            u.upgraded.len() + u.added.len()
        )
    });
    let then = vec![Fetch::Ostree];
    match upgrade_plan(o) {
        UpgradePlan::NoUpdate => vec![Effect::Toast(
            "no pending rpm-ostree update — press c to check".into(),
        )],
        UpgradePlan::Routine => {
            let cmd = Cmd::host("rpm-ostree").arg("upgrade").timeout(None);
            vec![Effect::Confirm(Modal {
                title: "rpm-ostree upgrade".into(),
                color: t.yellow,
                lines: vec![
                    Line::styled(summary, t.fg()),
                    Line::styled(format!("$ {}", cmd.display()), t.dim()),
                    Line::styled(
                        "Stages a new deployment; the running system is untouched until reboot.",
                        t.dim(),
                    ),
                ],
                yes: Some((
                    "stage upgrade".into(),
                    vec![Effect::Run(RunSpec {
                        queue: Vec::new(),
                        title: "rpm-ostree upgrade".into(),
                        cmd,
                        then,
                        ok_toast: "staged · reboot required".into(),
                    })],
                )),
            })]
        }
        UpgradePlan::Ritual(kmod) => {
            let cmd = Cmd::host("rpm-ostree")
                .args(["upgrade", "--uninstall", &kmod])
                .timeout(None);
            let new_k = u
                .and_then(|u| u.new_kernel.clone())
                .unwrap_or_else(|| "?".into());
            vec![Effect::Confirm(Modal {
                title: "rpm-ostree upgrade · kernel changes".into(),
                color: t.yellow,
                lines: vec![
                    Line::styled(summary, t.fg()),
                    Line::styled(format!("kernel {} → {new_k}", o.booted_kernel), t.yellow),
                    Line::styled(
                        "Kmod ritual step 1: stage the upgrade and drop the old kmod.",
                        t.fg(),
                    ),
                    Line::styled(format!("$ {}", cmd.display()), t.dim()),
                    Line::styled(
                        "Then reboot, build/layer the new kmod, reboot again (quick-update workflow, milestone 5).",
                        t.dim(),
                    ),
                    Line::styled(
                        "An openssl-devel depsolve wall means mirror lag: wait, or use the master mirror.",
                        t.dim(),
                    ),
                ],
                yes: Some((
                    "stage upgrade".into(),
                    vec![Effect::Run(RunSpec {
                        queue: Vec::new(),
                        title: "rpm-ostree upgrade (kmod ritual step 1)".into(),
                        cmd,
                        then,
                        ok_toast: "staged without old kmod · reboot, then build the new kmod"
                            .into(),
                    })],
                )),
            })]
        }
        UpgradePlan::Ambiguous(kmods) => {
            let mut lines = vec![
                Line::styled(
                    "STOP: the kernel changes but there is not exactly one layered kmod-nvidia.",
                    t.red,
                ),
                Line::styled(
                    "Read LocalPackages in `rpm-ostree status` and uninstall the exact string by hand.",
                    t.fg(),
                ),
            ];
            lines.extend(
                kmods
                    .into_iter()
                    .map(|k| Line::styled(format!("  {k}"), t.dim())),
            );
            vec![Effect::Confirm(crate::tui::app::info_modal(
                t,
                "rpm-ostree upgrade · blocked",
                lines,
            ))]
        }
    }
}

fn flatpak_effects(v: &View) -> Vec<Effect> {
    let t = v.t;
    let n = v.d.fp_updates.get().map(|c| c.data.len());
    // A sandbox started before the update keeps a stale runtime bind-mount.
    let running = Cmd::host("flatpak")
        .args(["ps", "--columns=application"])
        .timeout(Some(std::time::Duration::from_secs(3)))
        .output()
        .unwrap_or_default();
    let running: Vec<&str> = running
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let cmd = Cmd::host("flatpak")
        .args(["update", "-y", "--noninteractive"])
        .timeout(None);
    let mut lines = vec![
        Line::styled(format!("$ {}", cmd.display()), t.fg()),
        Line::styled(
            n.map_or("pending updates unknown (press c to check)".into(), |n| {
                format!("{n} pending (from last check)")
            }),
            t.dim(),
        ),
    ];
    if !running.is_empty() {
        lines.push(Line::styled(
            format!(
                "Running sandboxes: {} — quit them first (Steam especially).",
                running.join(", ")
            ),
            t.yellow,
        ));
    }
    vec![Effect::Confirm(Modal {
        title: "flatpak update".into(),
        color: t.yellow,
        lines,
        yes: Some((
            "update".into(),
            vec![Effect::Run(RunSpec {
                queue: Vec::new(),
                title: "flatpak update".into(),
                cmd,
                then: vec![Fetch::Flatpak, Fetch::FlatpakUpdates],
                ok_toast: "flatpak: updated".into(),
            })],
        )),
    })]
}

fn rollback_effects(t: &Theme, o: &Ostree) -> Vec<Effect> {
    let target = o.deployments.iter().find(|d| !d.booted && !d.staged);
    let cmd = Cmd::host("rpm-ostree").arg("rollback").timeout(None);
    vec![Effect::Confirm(Modal {
        title: "rpm-ostree rollback".into(),
        color: t.red,
        lines: vec![
            Line::styled(
                format!(
                    "Make {} the default boot target?",
                    target.map_or("the previous deployment", |d| d.version.as_str())
                ),
                t.fg(),
            ),
            Line::styled(format!("$ {}", cmd.display()), t.dim()),
            Line::styled(
                "Takes effect on next reboot. /home and configs are untouched.",
                t.dim(),
            ),
        ],
        yes: Some((
            "roll back".into(),
            vec![Effect::Run(RunSpec {
                queue: Vec::new(),
                title: "rpm-ostree rollback".into(),
                cmd,
                then: vec![Fetch::Ostree],
                ok_toast: "rollback staged · reboot to apply".into(),
            })],
        )),
    })]
}

impl Updates {
    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        match a {
            Action::Check => vec![
                Effect::Fetch(Fetch::OstreeCheck),
                Effect::Fetch(Fetch::FlatpakUpdates),
                Effect::Toast("checking rpm-ostree and flatpak updates…".into()),
            ],
            Action::Refresh => vec![Effect::Fetch(Fetch::Ostree), Effect::Fetch(Fetch::Flatpak)],
            Action::Char('u') => match v.d.ostree.get() {
                Some(o) => upgrade_effects(v.t, o),
                None => vec![Effect::Toast("rpm-ostree status not loaded yet".into())],
            },
            Action::Char('f') => flatpak_effects(v),
            Action::Char('R') => match v.d.ostree.get() {
                Some(o) => rollback_effects(v.t, o),
                None => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let [left, right] = Layout::horizontal([Constraint::Ratio(1, 2); 2])
            .spacing(2)
            .areas(area);
        draw_ostree(f, left, v);
        draw_flatpak(f, right, v);
    }
}

fn draw_ostree(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let block = panel(t, "rpm-ostree", "deployments");
    let r = inner(&block, area);
    f.render_widget(block, area);
    let Some(o) = v.d.ostree.get() else {
        f.render_widget(
            Paragraph::new(v.d.ostree.status(v.d.loading(Fetch::Ostree))).style(t.dim()),
            r,
        );
        return;
    };
    let w = r.width as usize;
    let mut lines: Vec<Line> = Vec::new();
    // Booted/staged first, then the rest; keep room for the update section.
    let max_deploys = if o.update.is_some() { 3 } else { 4 };
    for d in o.deployments.iter().take(max_deploys) {
        let (mark, c, label) = if d.staged {
            ("◆", t.yellow, "staged")
        } else if d.booted {
            ("●", t.green, "booted")
        } else {
            (" ", t.dim, "")
        };
        let mut head = vec![
            Span::styled(format!("{mark} "), t.s(c)),
            Span::styled(d.origin.clone(), t.fg()),
            Span::styled(format!("  {label}"), t.dim()),
        ];
        if d.pinned {
            head.push(Span::styled("  pinned", t.s(t.cyan)));
        }
        lines.push(Line::from(head));
        let date = jiff::Timestamp::from_second(d.timestamp)
            .map(|ts| ts.strftime("%Y-%m-%d").to_string())
            .unwrap_or_default();
        let sig = match d.sig_valid {
            Some(true) => "",
            Some(false) => " · BAD SIGNATURE",
            None => "",
        };
        lines.push(Line::styled(
            format!("  version {} · {date}{sig}", d.version),
            t.dim(),
        ));
        let layered = trunc(&d.layered.join(" "), w.saturating_sub(12));
        lines.push(Line::from(vec![
            Span::styled("  layered  ", t.dim()),
            Span::styled(layered, t.fg()),
        ]));
        if !d.local.is_empty() {
            let local = trunc(&d.local.join(" "), w.saturating_sub(12));
            lines.push(Line::from(vec![
                Span::styled("  local    ", t.dim()),
                Span::styled(local, t.fg()),
            ]));
        }
        lines.push(Line::default());
    }
    lines.push(Line::styled("─".repeat(w), t.s(t.rule)));
    let checked =
        v.d.ostree_checked
            .map(|ts| fmt::ago(jiff::Timestamp::now().as_second() - ts.as_second()));
    let checking = v.d.loading(Fetch::OstreeCheck);
    let age = if checking {
        "checking…".to_string()
    } else {
        checked.map_or("not checked yet".into(), |a| format!("checked {a}"))
    };
    match &o.update {
        None => {
            lines.push(Line::from(vec![
                Span::styled("no pending update known  ", t.fg()),
                Span::styled(age, t.dim()),
            ]));
        }
        Some(u) => {
            let n = u.upgraded.len() + u.added.len();
            lines.push(Line::from(vec![
                Span::styled(format!("{n} package updates"), t.s(t.yellow)),
                Span::styled(
                    format!(" → {}", u.version.as_deref().unwrap_or("?")),
                    t.fg(),
                ),
                Span::styled(format!("  {} advisories  {age}", u.advisories), t.dim()),
            ]));
            let room = (r.height as usize).saturating_sub(lines.len() + 2);
            // Kernel first, then the rest alphabetically.
            let mut pkgs: Vec<_> = u.upgraded.iter().collect();
            pkgs.sort_by_key(|p| (!p.name.starts_with("kernel"), p.name.clone()));
            for p in pkgs.iter().take(room.saturating_sub(1)) {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<28}", trunc(&p.name, 28)), t.dim()),
                    Span::styled(format!("{} → ", trunc(&p.old, 22)), t.dim()),
                    Span::styled(trunc(&p.new, 24), t.fg()),
                ]));
            }
            if pkgs.len() > room.saturating_sub(1) {
                lines.push(Line::styled(
                    format!("  … {} more", pkgs.len() - room.saturating_sub(1)),
                    t.dim(),
                ));
            }
            if u.kernel_changed {
                lines.push(Line::styled(
                    format!(
                        "! kernel → {} · nvidia kmod ritual (u stages step 1)",
                        u.new_kernel.as_deref().unwrap_or("?")
                    ),
                    t.s(t.yellow),
                ));
            }
        }
    }
    f.render_widget(Paragraph::new(lines), r);
}

fn draw_flatpak(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let block = panel(t, "Flatpak", "remote-ls --updates");
    let r = inner(&block, area);
    f.render_widget(block, area);
    let [list, foot] = Layout::vertical([Constraint::Fill(1), Constraint::Length(2)]).areas(r);
    let checking = v.d.loading(Fetch::FlatpakUpdates);
    match v.d.fp_updates.get() {
        None => {
            let msg = if checking {
                "checking…".to_string()
            } else {
                v.d.fp_updates
                    .err
                    .as_ref()
                    .map_or("never checked · press c".into(), |e| e.text())
            };
            f.render_widget(Paragraph::new(msg).style(t.dim()), list);
        }
        Some(c) => {
            let installed = v.d.flatpak.get();
            let rows: Vec<Row> = c
                .data
                .iter()
                .map(|u| {
                    let old = installed
                        .and_then(|fp| fp.apps.iter().find(|a| a.id == u.id))
                        .map(|a| a.version.clone());
                    let ver = match (old, u.version.is_empty()) {
                        (Some(o), false) if o != u.version => format!("{o} → {}", u.version),
                        // OCI remotes (fedora) rebuild under the same version: the digest changed.
                        (Some(o), false) if o == u.version => format!("{o} (rebuild)"),
                        (_, false) => u.version.clone(),
                        (_, true) => "runtime".into(),
                    };
                    Row::new(vec![
                        Cell::from(u.id.clone()),
                        Cell::from(u.origin.clone()).style(t.dim()),
                        Cell::from(ver),
                    ])
                })
                .collect();
            table(
                f,
                list,
                t,
                TableSpec {
                    header: vec!["APP", "ORIGIN", "VERSION"],
                    widths: vec![
                        Constraint::Fill(3),
                        Constraint::Length(9),
                        Constraint::Fill(2),
                    ],
                    rows,
                    selected: None,
                },
            );
            let age = if checking {
                "checking…".into()
            } else {
                format!("checked {}", fmt::ago(c.age_secs(jiff::Timestamp::now())))
            };
            let stale = c.age_secs(jiff::Timestamp::now()) as u64
                > v.cfg.cache.update_check_max_age.0.as_secs();
            f.render_widget(
                Paragraph::new(vec![
                    Line::default(),
                    Line::from(vec![
                        Span::styled(format!("{} updates · ", c.data.len()), t.dim()),
                        Span::styled(age, t.s(if stale { t.yellow } else { t.dim })),
                    ]),
                ]),
                foot,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::ostree::parse;

    fn status(kmods: &[&str], kernel: bool) -> Ostree {
        let pkg = if kernel { "kernel-core" } else { "mesa-libGL" };
        let j = format!(
            r#"{{"deployments":[{{"booted":true,"version":"44.1","requested-local-packages":{}}}],
            "cached-update":{{"version":"44.2","rpm-diff":{{"upgraded":[[0,"{pkg}",["1-1","x"],["1-2","x"]]]}}}}}}"#,
            serde_json::to_string(kmods).unwrap()
        );
        parse(&j).unwrap()
    }

    #[test]
    fn plans() {
        let k = "kmod-nvidia-7.2.8-200.fc44.x86_64-3:615.71.09-3.fc44.x86_64";
        assert_eq!(upgrade_plan(&status(&[k], false)), UpgradePlan::Routine);
        assert_eq!(
            upgrade_plan(&status(&[k], true)),
            UpgradePlan::Ritual(k.into())
        );
        assert_eq!(upgrade_plan(&status(&[], true)), UpgradePlan::Routine);
        assert!(
            matches!(upgrade_plan(&status(&[k, "kmod-nvidia-x"], true)), UpgradePlan::Ambiguous(v) if v.len() == 2)
        );
        let mut none = status(&[k], true);
        none.update = None;
        assert_eq!(upgrade_plan(&none), UpgradePlan::NoUpdate);
    }

    #[test]
    fn real_fixture_is_ritual() {
        let o = parse(&crate::collectors::fixture("ostree/status.json")).unwrap();
        assert!(
            matches!(upgrade_plan(&o), UpgradePlan::Ritual(k) if k.starts_with("kmod-nvidia-7.2.8"))
        );
    }
}

//! Updates and deployments, for Maintenance: the deployments panel (booted, staged, pinned,
//! rollback, and the pending update from rpm-ostree's cached-update), what's waiting for the
//! updates recommendation, rollback behind its confirm, and `A` on pending updates.
//! Updates are applied by the `quick-update` workflow, not from here.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::View;
use crate::collectors::ostree::Ostree;
use crate::exec::Cmd;
use crate::fmt;
use crate::tui::app::{Effect, Modal, RunSpec};
use crate::tui::data::Fetch;
use crate::tui::theme::Theme;
use crate::tui::widgets::{inner, panel, trunc};

pub fn rollback_effects(t: &Theme, o: &Ostree) -> Vec<Effect> {
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

pub fn draw_deployments(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let block = panel(t, "Deployments", "rpm-ostree");
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
                        "! kernel → {} · nvidia kmod ritual (quick-update runs it)",
                        u.new_kernel.as_deref().unwrap_or("?")
                    ),
                    t.s(t.yellow),
                ));
            }
        }
    }
    f.render_widget(Paragraph::new(lines), r);
}

/// What's waiting, for the updates recommendation's details: the OS update, Flatpaks
/// (old → new) and toolbox packages, and when they were checked.
pub fn updates_lines(v: &View) -> Vec<Line<'static>> {
    let t = v.t;
    let now = jiff::Timestamp::now();
    let mut l = Vec::new();
    match v.d.ostree.get().and_then(|o| o.update.as_ref()) {
        Some(u) => {
            l.push(Line::styled(
                format!(
                    "OS → {}: {} upgraded, {} added, {} removed, {} advisories",
                    u.version.as_deref().unwrap_or("?"),
                    u.upgraded.len(),
                    u.added.len(),
                    u.removed.len(),
                    u.advisories
                ),
                t.s(t.yellow),
            ));
            if u.kernel_changed {
                l.push(Line::styled(
                    format!(
                        "  kernel → {}: the NVIDIA kmod ritual",
                        u.new_kernel.as_deref().unwrap_or("?")
                    ),
                    t.s(t.yellow),
                ));
            }
        }
        None => l.push(Line::styled("OS: no update known", t.dim())),
    }
    if let Some(c) = v.d.fp_updates.get() {
        l.push(Line::styled(
            format!(
                "Flatpak: {} (checked {})",
                c.data.len(),
                fmt::ago(c.age_secs(now))
            ),
            t.fg(),
        ));
        let installed = v.d.flatpak.get();
        for u in c.data.iter().take(12) {
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
            l.push(Line::styled(format!("  {}  {ver}", u.id), t.dim()));
        }
        if c.data.len() > 12 {
            l.push(Line::styled(
                format!("  … {} more", c.data.len() - 12),
                t.dim(),
            ));
        }
    }
    if let Some(c) = v.d.tbx_updates.get() {
        for (name, b) in &c.data {
            if !b.updates.is_empty() {
                l.push(Line::styled(
                    format!("Toolbox {name}: {} package(s)", b.updates.len()),
                    t.fg(),
                ));
            }
        }
    }
    let checked = v.d.ostree_checked.map_or("never".into(), |ts| {
        fmt::ago(now.as_second() - ts.as_second())
    });
    l.push(Line::styled(
        format!("Last check {checked} · c checks again"),
        t.dim(),
    ));
    l
}

/// `A` on the updates recommendation: what's pending, for a risk read before applying.
pub fn ask(v: &View) -> Result<crate::claude::Ask, String> {
    let o = v.d.ostree.get().ok_or("rpm-ostree status not loaded yet")?;
    let mut lines = vec![format!(
        "booted {} (kernel {})",
        o.booted().map_or("?", |b| b.version.as_str()),
        o.booted_kernel
    )];
    if let Some(b) = o.booted() {
        lines.push(format!("layered: {}", b.layered.join(" ")));
        lines.push(format!("local packages: {}", b.local.join(" ")));
    }
    match &o.update {
        None => lines.push("no rpm-ostree update known (press c to check)".into()),
        Some(u) => {
            lines.push(format!(
                "pending rpm-ostree update {}: {} upgraded, {} added, {} removed, {} advisories{}",
                u.version.as_deref().unwrap_or("?"),
                u.upgraded.len(),
                u.added.len(),
                u.removed.len(),
                u.advisories,
                if u.kernel_changed {
                    " · KERNEL CHANGES"
                } else {
                    ""
                }
            ));
            for p in u.upgraded.iter().take(60) {
                lines.push(format!("  {} {} → {}", p.name, p.old, p.new));
            }
            if u.upgraded.len() > 60 {
                lines.push(format!("  … {} more", u.upgraded.len() - 60));
            }
        }
    }
    if let Some(c) = v.d.fp_updates.get() {
        lines.push(format!("{} Flatpak updates:", c.data.len()));
        for u in c.data.iter().take(30) {
            lines.push(format!("  {} {} ({})", u.id, u.version, u.origin));
        }
    }
    Ok(crate::claude::Ask::new(
        "pending updates",
        format!(
            "Pending updates on my Silverblue machine. On a kernel change, sentry's quick-update workflow runs the NVIDIA kmod procedure (drop the old local kmod, reboot, build and layer the new one, reboot).\n{}",
            lines.join("\n")
        ),
        "What's in this update, is anything risky for my NVIDIA/kmod setup, and should I use the routine path or quick-update?",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::ostree::parse;
    use crate::collectors::ostree::{UpgradePlan, upgrade_plan};

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

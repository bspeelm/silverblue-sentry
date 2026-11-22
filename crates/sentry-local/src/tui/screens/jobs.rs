//! Running one job from the TUI (`:job <name>`): it's planned in the background, the plan shows
//! in a confirm modal, then `sentry job <name> --yes` streams. Due jobs are tasks on Maintenance.

use ratatui::text::Line;

use super::sentry_cmd;
use crate::fmt;
use crate::jobs::JobId;
use crate::jobs::plan::{Act, Plan};
use crate::tui::app::{Effect, Modal, RunSpec};
use crate::tui::data::Fetch;
use crate::tui::theme::Theme;

/// Collectors to refresh after a job finishes.
pub fn then_for(job: JobId) -> Vec<Fetch> {
    let mut v = vec![Fetch::Log];
    v.extend(match job {
        JobId::Audit => vec![Fetch::Reports],
        JobId::UpdateCheck | JobId::UpdateApply => {
            vec![Fetch::Ostree, Fetch::FlatpakUpdates, Fetch::Flatpak]
        }
        JobId::CleanupFlatpak => vec![Fetch::Flatpak, Fetch::Cleanup],
        JobId::CleanupPodman => vec![Fetch::Podman, Fetch::Cleanup],
        JobId::CleanupOstree | JobId::CleanupCache => vec![Fetch::Cleanup],
    });
    v
}

/// Confirm modal for a planned job (opened by the app when `Fetch::Plan` returns).
pub fn plan_modal(t: &Theme, job: JobId, p: &Plan) -> Modal {
    let mut lines = vec![
        Line::styled(format!("sentry job {}", job.name()), t.fg()),
        Line::styled(job.description(), t.dim()),
        Line::raw(""),
    ];
    let mut runnable = 0;
    for i in &p.items {
        let on = matches!(i.act, Act::Run(_) | Act::Builtin) && i.default_on;
        runnable += on as usize;
        let size = i
            .bytes
            .map_or(String::new(), |b| format!("  ≈ {}", fmt::bytes(b)));
        let (mark, c) = match (&i.act, on) {
            (Act::ListOnly | Act::Nothing, _) => ("·", t.dim),
            (_, false) => ("○", t.dim),
            (_, true) => ("•", t.fg),
        };
        lines.push(Line::styled(format!("{mark} {}{size}", i.label), t.s(c)));
        for pl in i.preview.iter().take(4) {
            lines.push(Line::styled(format!("    {pl}"), t.dim()));
        }
        if !on && i.runnable() {
            lines.push(Line::styled(
                "    opt-in: select it in Cleanup (7)",
                t.dim(),
            ));
        }
    }
    for n in &p.notes {
        lines.push(Line::styled(format!("! {n}"), t.s(t.yellow)));
    }
    if runnable == 0 {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Nothing to run.", t.fg()));
        return crate::tui::app::info_modal(t, &format!("Job · {}", job.name()), lines);
    }
    Modal {
        title: "Run job".into(),
        color: t.yellow,
        lines,
        yes: Some((
            "run now".into(),
            vec![Effect::Run(RunSpec {
                title: format!("sentry job {}", job.name()),
                cmd: sentry_cmd(&["job", job.name(), "--yes"]),
                queue: Vec::new(),
                then: then_for(job),
                ok_toast: format!("{} finished", job.name()),
                log: None,
            })],
        )),
    }
}

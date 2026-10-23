//! Screens whose milestones haven't landed yet. Tabs and keys exist so layout is final.

use ratatui::Frame;
use ratatui::layout::Rect;

use super::{Hints, View};
use crate::tui::ScreenId;
use crate::tui::app::Effect;
use crate::tui::keys::Action;
use crate::tui::widgets::placeholder;

fn info(id: ScreenId) -> (u8, &'static str) {
    match id {
        ScreenId::Audit => (3, "Security audit snapshots, findings by severity, month-over-month diff, baseline."),
        ScreenId::Jobs => (4, "Maintenance jobs with cadence reminders. Nothing runs until you press Enter."),
        ScreenId::Clean => (4, "Reclaimable space from dry-runs: ostree, Flatpak, podman, ~/.cache."),
        ScreenId::Upgrade => (5, "Resumable upgrade workflows (quick-update, release-rebase) with the NVIDIA kmod ritual."),
        ScreenId::Hist => (6, "Recorder history."),
        _ => (0, ""),
    }
}

pub fn render(id: ScreenId, f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    if id == ScreenId::Hist {
        placeholder(
            f,
            area,
            t,
            &[
                ("No recorder data.", t.dim()),
                ("", t.dim()),
                ("Run `sentry record --interval 10s` in a spare terminal. It exits on Ctrl-C.", t.dim()),
                ("(the recorder arrives in milestone 6)", t.dim()),
            ],
        );
        return;
    }
    let (m, what) = info(id);
    let head = format!("{} arrives in milestone {m}", id.name());
    placeholder(f, area, t, &[(&head, t.fg()), ("", t.dim()), (what, t.dim())]);
}

pub fn handle(id: ScreenId, a: Action) -> Vec<Effect> {
    match a {
        Action::Enter | Action::Char(_) | Action::Refresh | Action::Check => {
            vec![Effect::Toast(format!("{} arrives in milestone {}", id.name(), info(id).0))]
        }
        _ => Vec::new(),
    }
}

pub fn hints(_id: ScreenId) -> Hints {
    vec![("1-0", "screens")]
}

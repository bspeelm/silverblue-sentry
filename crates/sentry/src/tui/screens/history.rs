//! History (`H`): the recorder's ring file as per-metric graphs over a 6h/24h/72h window.
//! `[`/`]` change the window, `←`/`→` scrub. Shown as a tab only once recorder data exists.
//! The graphs are `tui::histview` (sentry-server's History draws through it too).

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};

use super::{Hints, View};
use crate::tui::app::Effect;
use crate::tui::data::Fetch;
use crate::tui::histview::{self, HistState};
use crate::tui::keys::Action;

pub use crate::tui::histview::HistData;

/// This machine's ring, read in the background.
pub fn load() -> HistData {
    histview::load(crate::maint::LOCAL)
}

#[derive(Default)]
pub struct History {
    s: HistState,
}

pub fn on_enter(_v: &View) -> Vec<Effect> {
    vec![Effect::Fetch(Fetch::History)]
}

pub fn hints() -> Hints {
    histview::hints()
}

impl History {
    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        if !self.s.key(a, v.d.history.get().map(|h| &**h)) && a == Action::Refresh {
            return vec![Effect::Fetch(Fetch::History)];
        }
        Vec::new()
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let h = v.d.history.get().map(|h| &**h);
        let mut foot = Vec::new();
        if let Some(h) = h {
            foot.push(Line::from(vec![
                Span::styled(
                    format!("alerts  {}   ", v.cfg.recorder.alerts.join(" · ")),
                    t.dim(),
                ),
                histview::recorder_span(
                    t,
                    h.live.as_ref(),
                    "○ recorder off · `sentry record` to resume",
                ),
            ]));
            foot.extend(histview::alert_lines(t, h));
        }
        histview::draw(
            f,
            area,
            t,
            h,
            &self.s,
            v.d.loading(Fetch::History),
            &[
                "",
                "Run `sentry record --interval 10s` in a spare terminal. It exits on Ctrl-C.",
            ],
            foot,
        );
    }
}

impl History {
    pub fn ask(&self, v: &View) -> Result<crate::claude::Ask, String> {
        let h = v.d.history.get();
        let (label, mut lines) = h
            .and_then(|h| histview::ask_lines(h, &self.s))
            .ok_or("no recorder data (run `sentry record`)")?;
        for (ts, msg) in h.iter().flat_map(|h| &h.alerts) {
            lines.push(format!("alert {ts}: {msg}"));
        }
        Ok(crate::claude::Ask::new(
            format!("history · last {label}"),
            format!(
                "Metrics recorded by `sentry record` on my machine:\n{}",
                lines.join("\n")
            ),
            "Anything unusual in this period?",
        ))
    }
}

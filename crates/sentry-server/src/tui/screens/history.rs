//! History (`H`): what was recorded for the server, as sentry's per-metric graphs over a
//! 6h/24h/72h window. The ring is on this machine and is written only while sentry-server
//! samples the server (the Dashboard or Processes open, or `sentry-server record`), so
//! times nobody sampled are gaps. In the strip once there's a ring, as in sentry.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;

use super::{Hints, View};
use crate::remote::Remote;
use crate::tui::data::Kind;
use crate::tui::target::{Effect, Own};
use sentry_core::claude::Ask;
use sentry_core::tui::histview::{self, HistState};
use sentry_core::tui::keys::Action;

#[derive(Default)]
pub struct History {
    s: HistState,
}

pub fn hints() -> Hints {
    histview::hints()
}

impl History {
    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        if !self.s.key(a, v.s.history.value.as_ref()) && a == Action::Refresh {
            return vec![Own::fetch(Kind::History)];
        }
        Vec::new()
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let h = v.s.history.value.as_ref();
        let off = format!(
            "○ recorded while the Dashboard or Processes is open · sentry-server record {} to keep going",
            v.name
        );
        let foot = h.map_or(Vec::new(), |h| {
            vec![Line::from(histview::recorder_span(
                v.t,
                h.live.as_ref(),
                &off,
            ))]
        });
        let how = format!(
            "Open the Dashboard for a few seconds, or run `sentry-server record {}` in a spare \
             terminal. It exits on Ctrl-C.",
            v.name
        );
        histview::draw(
            f,
            area,
            v.t,
            h,
            &self.s,
            v.s.inflight.contains(&Kind::History),
            &["", &how],
            foot,
        );
    }

    /// What Claude is asked about the window shown.
    pub fn ask(&self, v: &View, r: &Remote) -> Result<Ask, String> {
        let (label, lines) = v
            .s
            .history
            .value
            .as_ref()
            .and_then(|h| histview::ask_lines(h, &self.s))
            .ok_or_else(|| {
                format!(
                    "no recorder data (open the Dashboard a while, or `sentry-server record {}`)",
                    r.name
                )
            })?;
        Ok(Ask::new(
            format!("{} · history · last {label}", r.name),
            format!(
                "{}Metrics sentry-server recorded for this server (only while it was open or \
                 recording; gaps are times nobody sampled):\n{}",
                crate::tui::ask::header(v, r),
                lines.join("\n")
            ),
            "Anything unusual in this period?",
        ))
    }
}

//! History (`H`): what was recorded for the router, as sentry's per-metric graphs over a
//! 6h/24h/72h window (core `tui::histview`, as for this machine and a server). The ring is on
//! this machine and is written only while sentry samples the router (its Dashboard open, or
//! `sentry-network record`), so times nobody sampled are gaps. In the strip once there's a
//! ring.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;

use super::{Hints, View};
use crate::tui::data::Kind;
use crate::tui::target::{Effect, Own};
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
            "○ recorded while the Dashboard is open · sentry-network record {} to keep going",
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
            "Open the Dashboard for a few seconds, or run `sentry-network record {}` in a spare \
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
}

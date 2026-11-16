//! Processes: the server's, top by CPU or memory, sampled every two seconds while shown.
//! Drawn and sorted like sentry's.

use std::time::Duration;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use super::{Hints, View};
use crate::remote::{Remote, SrvError};
use crate::tui::app::Effect;
use crate::tui::data::Kind;
use sentry_core::claude::Ask;
use sentry_core::collectors::procs::{Proc, SortBy, sort};
use sentry_core::tui::Cursor;
use sentry_core::tui::keys::Action;
use sentry_core::tui::proctable;

/// How often it's sampled: one exec each time, so slower than sentry's own 2 Hz.
pub const EVERY: Duration = Duration::from_secs(2);
/// The second sample comes sooner: CPU shares need two.
pub const SECOND: Duration = Duration::from_secs(1);

#[derive(Default)]
pub struct Processes {
    pub cur: Cursor,
    sort: SortBy,
}

pub fn hints() -> Hints {
    let mut h: Hints = proctable::hints()
        .into_iter()
        .filter(|(k, _)| *k != "x")
        .collect();
    h.push(("r", "refresh"));
    h
}

/// Those the `/` filter keeps (command, user, pid), as sampled.
fn filtered<'a>(v: &View<'a>) -> impl Iterator<Item = &'a Proc> {
    let keep: Vec<bool> =
        v.s.procs
            .value
            .iter()
            .flatten()
            .map(|p| v.matches(&[&p.cmd, &p.user, &p.pid.to_string()]))
            .collect();
    v.s.procs
        .value
        .iter()
        .flatten()
        .zip(keep)
        .filter_map(|(p, k)| k.then_some(p))
}

/// How many rows the screen has.
pub fn count(v: &View) -> usize {
    filtered(v).count()
}

impl Processes {
    /// The rows in the order shown.
    pub fn rows(&self, v: &View) -> Vec<Proc> {
        let mut p: Vec<Proc> = filtered(v).cloned().collect();
        sort(&mut p, self.sort);
        p
    }

    pub fn selected(&self, v: &View) -> Option<Proc> {
        let r = self.rows(v);
        let i = v.cur.min(r.len().checked_sub(1)?);
        r.into_iter().nth(i)
    }

    pub fn handle(&mut self, a: Action, _v: &View) -> Vec<Effect> {
        match a {
            Action::Char('C' | 'P') => self.sort = SortBy::Cpu,
            Action::Char('M') => self.sort = SortBy::Mem,
            Action::Refresh => return vec![Effect::Fetch(Kind::Procs)],
            _ => {}
        }
        Vec::new()
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        if v.s.procs.value.is_none() {
            let (text, style) = match &v.s.procs.err {
                Some(SrvError::NotFound(_)) => (format!("ps not found on {}", v.name), v.t.dim()),
                Some(e) => (format!("processes: {e}"), v.t.s(v.t.red)),
                None => ("reading processes…".to_string(), v.t.dim()),
            };
            f.render_widget(
                Paragraph::new(Line::styled(format!(" {text}"), style)),
                area,
            );
            return;
        }
        let rows = self.rows(v);
        self.cur.page = area.height as usize;
        let sel = v.cur.min(rows.len().saturating_sub(1));
        proctable::draw(f, area, v.t, &rows, Some(sel), self.sort);
    }

    /// What Claude is asked about the selected process.
    pub fn ask(&self, v: &View, r: &Remote) -> Result<Ask, String> {
        let p = self.selected(v).ok_or(if v.s.procs.value.is_none() {
            "the processes are still loading"
        } else {
            "no process selected"
        })?;
        let (title, context) = proctable::ask_text("the server", &p);
        Ok(Ask::new(
            format!("{} · {title}", r.name),
            format!("{}{context}", crate::tui::ask::header(v, r)),
            proctable::QUESTION,
        ))
    }
}

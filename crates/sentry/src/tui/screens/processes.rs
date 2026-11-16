//! Processes: top by CPU or memory, 2 Hz while visible. `x` sends SIGTERM after confirm.

use ratatui::Frame;
use ratatui::layout::Rect;

use super::{Cursor, Hints, View};
use crate::collectors::processes::{Proc, SortBy, sort};
use crate::tui::app::{Effect, Modal};
use crate::tui::keys::Action;
use crate::tui::proctable;

#[derive(Default)]
pub struct Processes {
    pub cur: Cursor,
    sort: SortBy,
}

pub fn hints() -> Hints {
    proctable::hints()
}

impl Processes {
    fn rows(&self, v: &View) -> Vec<Proc> {
        let mut p: Vec<Proc> =
            v.d.procs
                .iter()
                .filter(|p| v.matches(&[&p.cmd, &p.user, &p.pid.to_string()]))
                .cloned()
                .collect();
        sort(&mut p, self.sort);
        p
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        let rows = self.rows(v);
        if self.cur.nav(a, rows.len()) {
            return Vec::new();
        }
        match a {
            Action::Char('C') | Action::Char('P') => self.sort = SortBy::Cpu,
            Action::Char('M') => self.sort = SortBy::Mem,
            Action::Char('x') => {
                let Some(p) = rows.get(self.cur.clamp(rows.len())) else {
                    return Vec::new();
                };
                let me = rustix::process::getuid().as_raw();
                if p.uid.is_some_and(|u| u != me) {
                    return vec![Effect::Toast(format!(
                        "{} is owned by {} — requires root",
                        p.pid, p.user
                    ))];
                }
                let t = v.t;
                return vec![Effect::Confirm(Modal {
                    title: "Kill process".into(),
                    color: t.red,
                    lines: proctable::kill_lines(t, p),
                    yes: Some((
                        "send SIGTERM".into(),
                        vec![Effect::Kill(p.pid, format!("sent SIGTERM to {}", p.pid))],
                    )),
                })];
            }
            _ => {}
        }
        Vec::new()
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let rows = self.rows(v);
        self.cur.page = area.height as usize;
        let sel = self.cur.clamp(rows.len());
        proctable::draw(f, area, v.t, &rows, Some(sel), self.sort);
    }
}

impl Processes {
    pub fn ask(&self, v: &View) -> Result<crate::claude::Ask, String> {
        let rows = self.rows(v);
        let p = rows
            .get(self.cur.sel.min(rows.len().saturating_sub(1)))
            .ok_or("no process selected")?;
        let (title, context) = proctable::ask_text("my Silverblue machine", p);
        Ok(crate::claude::Ask::new(title, context, proctable::QUESTION))
    }
}

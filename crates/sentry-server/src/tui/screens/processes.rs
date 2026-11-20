//! Processes: the server's, top by CPU or memory, sampled every two seconds while shown.
//! Drawn and sorted like sentry's. `x` sends SIGTERM after a confirm box, as there; another
//! user's process goes through sudo, like the server's other actions.

use std::time::Duration;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use super::{Hints, View};
use crate::collect::procs::{kill_script, lineage};
use crate::remote::{Remote, SrvError, SudoMode};
use crate::tui::data::Kind;
use crate::tui::target::{Effect, Modal, Own, RunSpec};
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
    let mut h = proctable::hints();
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

    pub fn handle(&mut self, a: Action, v: &View, r: &Remote) -> Vec<Effect> {
        match a {
            Action::Char('C' | 'P') => self.sort = SortBy::Cpu,
            Action::Char('M') => self.sort = SortBy::Mem,
            Action::Refresh => return vec![Own::fetch(Kind::Procs)],
            Action::Char('x') => return self.kill(v, r),
            _ => {}
        }
        Vec::new()
    }

    /// The selected process belongs to someone else: ending it takes sudo.
    pub fn needs_root(&self, v: &View) -> bool {
        self.selected(v)
            .is_some_and(|p| p.uid.is_some() && p.uid != v.s.login_uid)
    }

    /// `x`: the box that asks before SIGTERM, showing the command. Our own process: plain
    /// `kill`. Another user's: `sudo kill`, with the server's password when sudo wants one
    /// (asked once, in the key bar). Either way nothing is signalled unless the pid is still
    /// the process listed.
    fn kill(&self, v: &View, r: &Remote) -> Vec<Effect> {
        let t = v.t;
        let Some(p) = self.selected(v) else {
            return Vec::new();
        };
        if p.pid == 1 {
            return vec![Effect::Toast(
                "pid 1 is the server's init: not ended from here".into(),
            )];
        }
        let Some(tick) = v.s.proc_ticks.get(&p.pid) else {
            return vec![Effect::Toast(format!("process {} is gone", p.pid))];
        };
        // (how it's written in the box and run, whether it goes through sudo).
        let (how, root) = if !self.needs_root(v) {
            ("kill", false)
        } else {
            match v.s.sudo.value {
                Some(SudoMode::NoPasswd | SudoMode::Password) => ("sudo kill", true),
                Some(SudoMode::Root) => ("kill", false),
                Some(SudoMode::Absent) => {
                    return vec![Effect::Toast(format!(
                        "{} is owned by {}, and this login has no sudo on the server",
                        p.pid, p.user
                    ))];
                }
                None => {
                    return vec![Effect::Toast(
                        "still checking how sudo works on the server".into(),
                    )];
                }
            }
        };
        let shown = how;
        let mut lines = proctable::kill_lines(t, &p);
        lines.extend([
            Line::raw(""),
            Line::styled(format!("$ {shown} -TERM {}", p.pid), t.fg()),
            Line::styled(format!("on {} ({})", r.name, r.host), t.dim()),
        ]);
        // An ancestor of the shell that sampled: the ssh session itself, or the ssh server.
        let ours =
            v.s.proc_self
                .is_some_and(|me| lineage(&v.s.proc_ticks, me).contains(&p.pid));
        if ours {
            lines.push(Line::styled(
                "This is the connection sentry-server talks through: ending it cuts                  sentry-server off from the server.",
                t.s(t.yellow),
            ));
            lines.push(Line::styled("This is hard to undo.", t.s(t.red)));
        }
        let line = kill_script(p.pid, tick.start, how);
        let run = Own::run(RunSpec {
            title: "Kill process".into(),
            cmd: r.sh(&line).timeout(None),
            then: vec![Kind::Procs],
            reboot: false,
            root: root.then_some(line),
        });
        vec![Effect::Confirm(Modal {
            title: "Kill process".into(),
            color: t.red,
            lines,
            yes: Some(("send SIGTERM".into(), vec![run])),
        })]
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

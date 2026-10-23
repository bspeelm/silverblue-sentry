//! Processes: top by CPU or memory, 2 Hz while visible. `x` sends SIGTERM after confirm.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Cell, Row};

use super::{Cursor, Hints, View};
use crate::collectors::processes::{Proc, SortBy, sort};
use crate::fmt;
use crate::tui::app::{Effect, Modal};
use crate::tui::keys::Action;
use crate::tui::widgets::{TableSpec, table};

#[derive(Default)]
pub struct Processes {
    pub cur: Cursor,
    sort: SortBy,
}

pub fn hints() -> Hints {
    vec![("j/k", "select"), ("C/M", "sort cpu/mem"), ("x", "kill"), ("/", "filter")]
}

impl Processes {
    fn rows(&self, v: &View) -> Vec<Proc> {
        let mut p: Vec<Proc> = v
            .d
            .procs
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
                let Some(p) = rows.get(self.cur.clamp(rows.len())) else { return Vec::new() };
                let me = rustix::process::getuid().as_raw();
                if p.uid.is_some_and(|u| u != me) {
                    return vec![Effect::Toast(format!("{} is owned by {} — requires root", p.pid, p.user))];
                }
                let t = v.t;
                return vec![Effect::Confirm(Modal {
                    title: "Kill process".into(),
                    color: t.red,
                    lines: vec![
                        Line::styled(format!("Send SIGTERM to {} {}?", p.pid, crate::tui::widgets::trunc(&p.cmd, 60)), t.fg()),
                        Line::styled(format!("owner {} · cpu {:.1}% · mem {:.1}%", p.user, p.cpu, p.mem_pct), t.dim()),
                    ],
                    yes: Some(("send SIGTERM".into(), vec![Effect::Kill(p.pid, format!("sent SIGTERM to {}", p.pid))])),
                })];
            }
            _ => {}
        }
        Vec::new()
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let rows = self.rows(v);
        self.cur.page = area.height as usize;
        let sel = self.cur.clamp(rows.len());
        let mark = |s: SortBy| if self.sort == s { " ▼" } else { "" };
        let cpu_h = format!("CPU%{}", mark(SortBy::Cpu));
        let mem_h = format!("MEM%{}", mark(SortBy::Mem));
        let body: Vec<Row> = rows
            .iter()
            .map(|p| {
                let cpu_c = if p.cpu > 15.0 { t.red } else if p.cpu > 5.0 { t.yellow } else { t.fg };
                Row::new(vec![
                    Cell::from(p.pid.to_string()).style(t.dim()),
                    Cell::from(p.user.clone()),
                    Cell::from(format!("{:.1}", p.cpu)).style(t.s(cpu_c)),
                    Cell::from(format!("{:.1}", p.mem_pct)),
                    Cell::from(fmt::hms(p.run_time_s)).style(t.dim()),
                    Cell::from(p.cmd.clone()),
                ])
            })
            .collect();
        table(
            f,
            area,
            t,
            TableSpec {
                header: vec!["PID", "USER", &cpu_h, &mem_h, "TIME", "COMMAND"],
                widths: vec![
                    Constraint::Length(9),
                    Constraint::Length(14),
                    Constraint::Length(9),
                    Constraint::Length(9),
                    Constraint::Length(11),
                    Constraint::Fill(1),
                ],
                rows: body,
                selected: (!rows.is_empty()).then_some(sel),
            },
        );
    }
}

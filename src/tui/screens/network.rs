//! Network: listeners (with baseline status) and established connections. `e` marks the
//! selected listener as expected (written to baseline.toml).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::widgets::{Cell, Paragraph, Row};

use super::{Cursor, Hints, View};
use crate::collectors::net::{ListenStatus, Listener};
use crate::tui::app::{BaselineEdit, Effect};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::widgets::{TableSpec, inner, panel, table};

#[derive(Default)]
pub struct Network {
    pub cur: Cursor,
}

pub fn hints() -> Hints {
    vec![
        ("j/k", "select"),
        ("e", "mark expected"),
        ("/", "filter"),
        ("r", "refresh"),
    ]
}

impl Network {
    fn rows<'a>(&self, v: &View<'a>) -> Vec<&'a Listener> {
        v.d.net.get().map_or(Vec::new(), |n| {
            n.listeners
                .iter()
                .filter(|l| v.matches(&[&l.local(), l.process.as_deref().unwrap_or(""), &l.proto]))
                .collect()
        })
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        let rows = self.rows(v);
        if self.cur.nav(a, rows.len()) {
            return Vec::new();
        }
        match a {
            Action::Refresh => vec![Effect::Fetch(Fetch::Net)],
            Action::Char('e') => match rows.get(self.cur.clamp(rows.len())) {
                Some(l) if l.status == ListenStatus::Baseline => {
                    vec![Effect::Toast(format!(
                        "{} is already in the baseline",
                        l.key()
                    ))]
                }
                Some(l) => vec![Effect::Baseline(BaselineEdit::Listener(l.key()))],
                None => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let [left, right] =
            Layout::horizontal([Constraint::Ratio(55, 100), Constraint::Ratio(45, 100)])
                .spacing(2)
                .areas(area);
        let rows = self.rows(v);
        let sel = self.cur.clamp(rows.len());
        let new = rows
            .iter()
            .filter(|l| l.status == ListenStatus::New)
            .count();
        let block = panel(
            t,
            "Listening",
            format!("ss -tulpn · {} · {new} new", rows.len()),
        );
        let r = inner(&block, left);
        f.render_widget(block, left);
        self.cur.page = r.height as usize;
        if v.d.net.get().is_none() {
            f.render_widget(
                Paragraph::new(v.d.net.status(v.d.loading(Fetch::Net))).style(t.dim()),
                r,
            );
        } else {
            let body: Vec<Row> = rows
                .iter()
                .map(|l| {
                    let (txt, c) = match l.status {
                        ListenStatus::New => ("NEW", t.red),
                        ListenStatus::Baseline => ("baseline", t.dim),
                        ListenStatus::Local => ("local", t.green),
                        ListenStatus::Ephemeral => ("client", t.dim),
                    };
                    let proc = match (&l.process, l.pid) {
                        (Some(p), Some(pid)) => format!("{p} ({pid})"),
                        (Some(p), None) => p.clone(),
                        _ => "?".into(),
                    };
                    Row::new(vec![
                        Cell::from(l.proto.clone()).style(t.dim()),
                        Cell::from(l.local()),
                        Cell::from(proc),
                        Cell::from(txt).style(t.s(c)),
                    ])
                })
                .collect();
            table(
                f,
                r,
                t,
                TableSpec {
                    header: vec!["PROTO", "LOCAL", "PROCESS", "STATUS"],
                    widths: vec![
                        Constraint::Length(5),
                        Constraint::Fill(3),
                        Constraint::Fill(2),
                        Constraint::Length(8),
                    ],
                    rows: body,
                    selected: (!rows.is_empty()).then_some(sel),
                },
            );
        }

        let est =
            v.d.net
                .get()
                .map_or(Vec::new(), |n| n.established.iter().collect::<Vec<_>>());
        let block = panel(t, "Established", est.len().to_string());
        let r = inner(&block, right);
        f.render_widget(block, right);
        let body: Vec<Row> = est
            .iter()
            .map(|c| {
                Row::new(vec![
                    Cell::from(c.peer.clone()),
                    Cell::from(c.process.clone().unwrap_or_else(|| "?".into())).style(t.dim()),
                ])
            })
            .collect();
        table(
            f,
            r,
            t,
            TableSpec {
                header: vec!["PEER", "PROCESS"],
                widths: vec![Constraint::Fill(1), Constraint::Length(18)],
                rows: body,
                selected: None,
            },
        );
    }
}

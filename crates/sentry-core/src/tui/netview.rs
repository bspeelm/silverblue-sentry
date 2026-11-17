//! The Network screen's two panels, in both programs: what's listening (with its status
//! against the baseline) and the established connections.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::widgets::{Cell, Paragraph, Row};

use super::theme::Theme;
use super::widgets::{TableSpec, inner, panel, table};
use crate::collectors::net::{Conn, ListenStatus, Listener};

/// A listener and what its PROCESS column says (each program words an unknown owner its own
/// way).
pub struct ListenRow<'a> {
    pub l: &'a Listener,
    pub process: String,
}

pub struct NetView<'a> {
    /// The listeners shown (filtered); None: nothing read yet, and `waiting` says why.
    pub listen: Option<Vec<ListenRow<'a>>>,
    pub waiting: String,
    /// Where they come from, for the panel's title (`ss -tulpn`).
    pub source: &'a str,
    /// Added to the title when there's something to say about the read (empty: nothing).
    pub note: String,
    pub established: &'a [Conn],
    /// The listener selected.
    pub sel: usize,
}

pub fn hints() -> Vec<(&'static str, &'static str)> {
    vec![
        ("j/k", "select"),
        ("b", "expected on/off"),
        ("/", "filter"),
        ("r", "refresh"),
    ]
}

/// How a listener's owner reads when `ss` named it: `name (pid)`, or the name alone.
pub fn owner(l: &Listener) -> Option<String> {
    match (&l.process, l.pid) {
        (Some(p), Some(pid)) => Some(format!("{p} ({pid})")),
        (Some(p), None) => Some(p.clone()),
        _ => None,
    }
}

/// Both panels. Returns the listener table's height, for paging.
pub fn draw(f: &mut Frame, area: Rect, t: &Theme, n: &NetView) -> usize {
    let [left, right] =
        Layout::horizontal([Constraint::Ratio(55, 100), Constraint::Ratio(45, 100)])
            .spacing(2)
            .areas(area);
    let rows = n.listen.as_deref().unwrap_or_default();
    let new = rows
        .iter()
        .filter(|r| r.l.status == ListenStatus::New)
        .count();
    let block = panel(
        t,
        "Listening",
        format!(
            "{} · {} · {new} new{}",
            n.source,
            rows.len(),
            if n.note.is_empty() {
                String::new()
            } else {
                format!(" · {}", n.note)
            }
        ),
    );
    let r = inner(&block, left);
    f.render_widget(block, left);
    if n.listen.is_none() {
        f.render_widget(Paragraph::new(n.waiting.clone()).style(t.dim()), r);
    } else {
        let body: Vec<Row> = rows
            .iter()
            .map(|row| {
                let l = row.l;
                let (txt, c) = match l.status {
                    ListenStatus::New => ("NEW", t.red),
                    ListenStatus::Baseline => ("baseline", t.dim),
                    ListenStatus::Local => ("local", t.green),
                    ListenStatus::Ephemeral => ("client", t.dim),
                };
                Row::new(vec![
                    Cell::from(l.proto.clone()).style(t.dim()),
                    Cell::from(l.local()),
                    Cell::from(row.process.clone()),
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
                selected: (!rows.is_empty()).then_some(n.sel),
            },
        );
    }

    let block = panel(t, "Established", n.established.len().to_string());
    let er = inner(&block, right);
    f.render_widget(block, right);
    let body: Vec<Row> = n
        .established
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
        er,
        t,
        TableSpec {
            header: vec!["PEER", "PROCESS"],
            widths: vec![Constraint::Fill(1), Constraint::Length(18)],
            rows: body,
            selected: None,
        },
    );
    r.height as usize
}

//! The Recommended list both programs' Maintenance shows: one table, one set of keys. Which
//! keys a row takes depends on the row (`Verbs`); the key bar shows only those, and `?` shows
//! them all (`GRAMMAR`).

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Cell, Row};

use super::theme::Theme;
use super::widgets::{TableSpec, inner, panel, placeholder, table};
use crate::maint::Level;
use crate::maint::rec::Rec;

/// What `x` does on a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dismiss {
    /// A finding: the audit stops listing it.
    Expected,
    /// Something discovery found: it stops suggesting it.
    Ignore,
    /// A tracked item that's gone: it comes off the list.
    Untrack,
    /// A task: it comes off tasks.toml.
    Remove,
    /// An item's plan: it moves to plans/done/.
    DropPlan,
}

impl Dismiss {
    pub fn word(self) -> &'static str {
        match self {
            Dismiss::Expected => "expected",
            Dismiss::Ignore => "ignore",
            Dismiss::Untrack => "untrack",
            Dismiss::Remove => "remove",
            Dismiss::DropPlan => "drop plan",
        }
    }
}

/// The keys the selected row takes, besides Enter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Verbs {
    /// `p` plans it.
    pub plan: bool,
    /// It has a plan (or one is being written): `p` opens it, `P` plans again.
    pub planned: bool,
    /// `t` tracks it (discovery).
    pub track: bool,
    /// `d` marks it done by hand (a task).
    pub done: bool,
    pub dismiss: Option<Dismiss>,
    /// `B`: everything like this finding is expected too.
    pub like: bool,
}

/// The row's keys for the key bar, in the same order on both programs.
pub fn hints(v: &Verbs) -> Vec<(&'static str, &'static str)> {
    let mut h = vec![("j/k", "select"), ("Enter", "do it")];
    if v.planned {
        h.extend([("p", "open plan"), ("P", "plan again")]);
    } else if v.plan {
        h.push(("p", "plan"));
    }
    if v.track {
        h.push(("t", "track"));
    }
    if v.done {
        h.push(("d", "done"));
    }
    if let Some(d) = v.dismiss {
        h.push(("x", d.word()));
    }
    if v.like {
        h.push(("B", "all like it"));
    }
    h.push(("z", "later"));
    h
}

/// Every row key, for `?`.
pub const GRAMMAR: &[(&str, &str)] = &[
    ("Enter", "do what the row says"),
    ("p / P", "plan it (Claude writes the plan) / plan again"),
    ("t", "track it (something discovery found)"),
    ("d", "done by hand (a task): logged, with your note"),
    (
        "x",
        "expected (a finding) · ignore · untrack · remove (a task) · drop the plan; asks first",
    ),
    ("B", "a finding: everything like it is expected"),
    ("z", "look again later: 7, 30 or 90 days"),
];

pub fn level_color(t: &Theme, l: Level) -> Color {
    match l {
        Level::Now => t.red,
        Level::Soon => t.yellow,
        Level::Routine => t.cyan,
        Level::Tidy => t.dim,
    }
}

/// The Recommended panel. `empty` is shown (centred) when there are no rows; returns the rows'
/// height (a page, for the cursor).
pub fn draw<A>(
    f: &mut Frame,
    area: Rect,
    t: &Theme,
    note: String,
    recs: &[Rec<A>],
    selected: Option<usize>,
    empty: (&str, Style),
) -> usize {
    let b = panel(t, "Recommended", note);
    let r = inner(&b, area);
    f.render_widget(b, area);
    if recs.is_empty() {
        placeholder(f, r, t, &[empty]);
        return r.height as usize;
    }
    let rows: Vec<Row> = recs
        .iter()
        .map(|x| {
            Row::new(vec![
                Cell::from(x.level.word()).style(t.s(level_color(t, x.level))),
                Cell::from(x.title.clone()).style(t.fg()),
                Cell::from(x.why.clone()).style(t.dim()),
            ])
        })
        .collect();
    table(
        f,
        r,
        t,
        TableSpec {
            header: vec!["", "What", "Why"],
            widths: vec![
                Constraint::Length(8),
                Constraint::Fill(3),
                Constraint::Fill(4),
            ],
            rows,
            selected,
        },
    );
    r.height as usize
}

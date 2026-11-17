//! The Recommended list both programs' Maintenance shows: one table, one set of keys. Which
//! keys a row takes depends on the row (`Verbs`); the key bar shows only those, and `?` shows
//! them all (`GRAMMAR`).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row};

use super::modal::Choice;
use super::theme::Theme;
use super::widgets::{TableSpec, inner, panel, placeholder, table, wrap};
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

/// The keys the selected row takes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Verbs {
    /// What Enter does, in a word or two ("install", "fix", "open plan"); empty: "do it".
    pub enter: &'static str,
    /// `p` plans it.
    pub plan: bool,
    /// It has a plan (or one is being written): `p` opens it, `P` plans again.
    pub planned: bool,
    /// `t` tracks it (discovery).
    pub track: bool,
    /// `d` marks it done by hand (a task).
    pub done: bool,
    /// `e` sets how often it recurs (a task).
    pub every: bool,
    /// `m` shows the steps to do it yourself (a task done by hand).
    pub manual: bool,
    pub dismiss: Option<Dismiss>,
    /// `B`: everything like this finding is expected too.
    pub like: bool,
    /// Space ticks it: it can be done in a series with the other ticked rows.
    pub series: bool,
}

/// The row's keys for the key bar, in the same order on both programs. The screen adds its
/// few own keys after these; everything else is in `?`.
pub fn hints(v: &Verbs, ticked: usize) -> Vec<(&'static str, &'static str)> {
    let enter = if v.enter.is_empty() { "do it" } else { v.enter };
    // With rows ticked, Enter does those, one after another.
    let mut h = vec![("Enter", if ticked > 0 { "do the ticked" } else { enter })];
    if v.series {
        h.push(("Space", "tick"));
    }
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
    if v.every {
        h.push(("e", "every"));
    }
    if v.manual {
        h.push(("m", "steps"));
    }
    if let Some(d) = v.dismiss {
        h.push(("x", d.word()));
    }
    if v.like {
        h.push(("B", "all like it"));
    }
    h.push(("z", "later"));
    h.push(("A", "claude"));
    h
}

/// Every row key, for `?`.
pub const GRAMMAR: &[(&str, &str)] = &[
    ("Enter", "do what the row says (the key bar names it)"),
    ("p / P", "plan it (Claude writes the plan) / plan again"),
    ("t", "track it (something discovery found)"),
    (
        "d",
        "done by hand (a task): logged, then a note if you like",
    ),
    (
        "e",
        "how often a task recurs (30d, off); written to tasks.toml",
    ),
    ("m", "a task's steps, to do it yourself (then mark it done)"),
    (
        "x",
        "expected (a finding) · ignore · untrack · remove (a task) · drop the plan; asks first",
    ),
    ("B", "a finding: everything like it is expected"),
    (
        "Space / a",
        "tick the row / every row that can be: Enter then does the ticked ones in a series",
    ),
    ("z", "look again later: 7, 30 or 90 days"),
    (
        "o",
        "everything: what can wait too (newer versions, updates nothing asks for, things to tidy)",
    ),
    (
        "A",
        "Claude: help me apply it (it plans, you approve, sentry applies) or just ask",
    ),
];

/// The Recommended panel when there's nothing in it.
pub const EMPTY: &str = "✓ nothing to maintain right now · c checks everything again";
/// The Recommended panel with nothing needed, when `waiting` rows can wait.
pub fn empty(waiting: usize) -> String {
    match waiting {
        0 => EMPTY.to_string(),
        n => format!("✓ nothing to maintain right now · o shows {n} that can wait"),
    }
}

/// What `o` does now, for the key bar.
pub fn everything_word(everything: bool) -> &'static str {
    if everything {
        "needed only"
    } else {
        "everything"
    }
}
/// … and when the `/` filter leaves nothing.
pub const NO_MATCH: &str = "nothing matches the filter";
/// Space on a row a series can't do.
pub const NOT_IN_A_SERIES: &str = "Enter does this one by itself: it can't go in a series";

/// The rows ticked for a series, by key.
pub type Ticks = std::collections::BTreeSet<String>;

/// Space: tick the row, or untick it.
pub fn tick(ticks: &mut Ticks, key: &str) {
    if !ticks.remove(key) {
        ticks.insert(key.to_string());
    }
}

/// `a`: tick every row that can be; when they all are, untick them.
pub fn tick_all(ticks: &mut Ticks, can: Vec<String>) {
    if !can.is_empty() && can.iter().all(|k| ticks.contains(k)) {
        ticks.clear();
    } else {
        ticks.extend(can);
    }
}

/// `x` on a row that has nothing to dismiss.
pub const NOTHING_TO_DISMISS: &str = "only findings can be marked expected: z puts this off";

/// The screen's three panels, the same in both programs: Recommended over a second panel
/// on the left (55%), Details on the right. Recommended is as tall as its rows, between six
/// lines and half the height.
pub fn split(area: Rect, n_recs: usize) -> (Rect, Rect, Rect) {
    let [left, right] =
        Layout::horizontal([Constraint::Ratio(55, 100), Constraint::Ratio(45, 100)])
            .spacing(1)
            .areas(area);
    let want = n_recs.max(1) as u16 + 4;
    let [top, bottom] = Layout::vertical([
        Constraint::Length(want.min(left.height / 2).max(6)),
        Constraint::Fill(1),
    ])
    .areas(left);
    (top, bottom, right)
}

/// How Details opens on a recommendation: its level and title, then why, wrapped to `width`.
pub fn detail_head<A>(t: &Theme, r: &Rec<A>, width: usize) -> Vec<Line<'static>> {
    let mut l = vec![Line::from(vec![
        Span::styled(
            format!("{}  ", r.level.word()),
            t.s(level_color(t, r.level)),
        ),
        Span::styled(r.title.clone(), t.fg()),
    ])];
    l.push(Line::raw(""));
    for x in wrap(&r.why, width) {
        l.push(Line::styled(x, t.fg()));
    }
    l.push(Line::raw(""));
    l
}

/// `z`: look again in 7, 30 or 90 days. `mk` makes the effects for (days, the day it shows
/// again).
pub fn later_choice<E>(
    t: &Theme,
    what: &str,
    today: jiff::civil::Date,
    mk: impl Fn(i64, jiff::civil::Date) -> Vec<E>,
) -> Choice<E> {
    let days = [7i64, 30, 90];
    let until = |d: i64| {
        today
            .checked_add(jiff::Span::new().days(d))
            .unwrap_or(today)
    };
    let mut lines: Vec<Line<'static>> = days
        .iter()
        .enumerate()
        .map(|(i, d)| Line::styled(format!("{}  in {d} days ({})", i + 1, until(*d)), t.fg()))
        .collect();
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!("{what}: it leaves the list until then. Records › Later takes it back."),
        t.dim(),
    ));
    Choice {
        title: "Look again later · pick one (1–3, n cancels)".into(),
        lines,
        options: days
            .into_iter()
            .map(|d| (format!("in {d} days"), mk(d, until(d))))
            .collect(),
    }
}

pub fn level_color(t: &Theme, l: Level) -> Color {
    match l {
        Level::Now => t.red,
        Level::Soon => t.yellow,
        Level::Routine => t.cyan,
        Level::Tidy => t.dim,
    }
}

/// What the Recommended panel shows besides its rows.
pub struct List<'a> {
    /// After the title: how many, when it was audited.
    pub note: String,
    pub selected: Option<usize>,
    /// Shown (centred) when there are no rows.
    pub empty: (&'a str, Style),
    /// The rows ticked for a series.
    pub ticks: &'a Ticks,
}

/// The Recommended panel. `empty` is shown (centred) when there are no rows; returns the rows'
/// height (a page, for the cursor).
pub fn draw<A>(f: &mut Frame, area: Rect, t: &Theme, recs: &[Rec<A>], l: List) -> usize {
    let List {
        note,
        selected,
        empty,
        ticks,
    } = l;
    let b = panel(t, "Recommended", note);
    let r = inner(&b, area);
    f.render_widget(b, area);
    if recs.is_empty() {
        placeholder(f, r, t, &[empty]);
        return r.height as usize;
    }
    // The tick column is there only while something is ticked.
    let ticked = recs.iter().any(|x| ticks.contains(&x.key));
    let rows: Vec<Row> = recs
        .iter()
        .map(|x| {
            let mut cells = vec![
                Cell::from(x.level.word()).style(t.s(level_color(t, x.level))),
                Cell::from(x.title.clone()).style(t.fg()),
                Cell::from(x.why.clone()).style(t.dim()),
            ];
            if ticked {
                let mark = if ticks.contains(&x.key) { "✓" } else { "" };
                cells.insert(0, Cell::from(mark).style(t.s(t.green)));
            }
            Row::new(cells)
        })
        .collect();
    let mut header = vec!["", "What", "Why"];
    let mut widths = vec![
        Constraint::Length(8),
        Constraint::Fill(3),
        Constraint::Fill(4),
    ];
    if ticked {
        header.insert(0, "");
        widths.insert(0, Constraint::Length(1));
    }
    table(
        f,
        r,
        t,
        TableSpec {
            header,
            widths,
            rows,
            selected,
        },
    );
    r.height as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_is_seven_thirty_or_ninety_days() {
        let c = later_choice(
            &Theme::truecolor(),
            "Updates waiting",
            "2026-11-16".parse().unwrap(),
            |d, until| vec![(d, until.to_string())],
        );
        let days: Vec<i64> = c.options.iter().map(|(_, e)| e[0].0).collect();
        assert_eq!(days, [7, 30, 90]);
        assert_eq!(c.options[0].1[0].1, "2026-11-23");
        let text: Vec<String> = c.lines.iter().map(|l| l.to_string()).collect();
        assert_eq!(text[2], "3  in 90 days (2027-02-14)");
        assert!(text[4].starts_with("Updates waiting: it leaves the list"));
    }

    #[test]
    fn the_panels_split_the_same_way_whatever_is_in_them() {
        let area = Rect::new(0, 0, 158, 34);
        let (top, bottom, right) = split(area, 2);
        assert_eq!((top.height, bottom.height), (6, 28));
        assert_eq!(top.width + 1 + right.width, 158);
        // Many recommendations: half the height at most.
        assert_eq!(split(area, 40).0.height, 17);
    }

    #[test]
    fn ticks_toggle_and_a_takes_every_row_that_can_be() {
        let mut ticks = Ticks::new();
        tick(&mut ticks, "a");
        tick(&mut ticks, "b");
        tick(&mut ticks, "a");
        assert_eq!(ticks.iter().collect::<Vec<_>>(), ["b"]);
        let can = || vec!["a".to_string(), "b".to_string()];
        tick_all(&mut ticks, can());
        assert_eq!(ticks.len(), 2);
        // They all are: a unticks them.
        tick_all(&mut ticks, can());
        assert!(ticks.is_empty());
        tick_all(&mut ticks, Vec::new());
        assert!(ticks.is_empty());
        // The key bar: Space on a row that can be ticked; with ticks, Enter does those.
        let v = Verbs {
            enter: "fix",
            series: true,
            ..Default::default()
        };
        assert_eq!(hints(&v, 0)[..2], [("Enter", "fix"), ("Space", "tick")]);
        assert_eq!(hints(&v, 2)[0], ("Enter", "do the ticked"));
        assert!(!hints(&Verbs::default(), 0).contains(&("Space", "tick")));
    }
}

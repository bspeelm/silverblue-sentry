//! The Clients table (a network's `2`): who is on the network, how each is connected, its
//! address and its lease. Drawn like the Processes and Network tables; the program that has
//! clients makes the rows. Nothing here acts on a client's device: the keys select, sort,
//! filter, mark expected and show details.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row as TableRow};

use super::theme::Theme;
use super::widgets::{TableSpec, table, trunc};

/// How a client is connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    /// A wired port, by name.
    Wired(String),
    /// A radio's interface, and the signal in dBm while associated.
    Wifi(String, Option<i32>),
    /// A port or network of its own (`dmz`), as it should read.
    Other(String),
    /// Not on any port now.
    None,
}

/// What the status column says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Named, or vouched for by the Wi-Fi passphrase.
    Fine,
    /// Nobody named it.
    Unknown,
    /// Unknown, and marked expected.
    Expected,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// Its name, else its hostname, else its MAC.
    pub name: String,
    /// A randomised (locally administered) MAC: marked `~`.
    pub private: bool,
    pub link: Link,
    pub addr: String,
    /// Seconds its lease still runs (none: no lease; negative: it ran out).
    pub lease_left: Option<i64>,
    /// Seconds since it was last seen (none: never noted; 0 while it's there).
    pub seen_ago: Option<i64>,
    /// There now (the rest is dimmed).
    pub online: bool,
    pub standing: Standing,
    /// Nothing may touch it.
    pub leave_alone: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Sort {
    #[default]
    Name,
    Link,
    Signal,
    Lease,
}

impl Sort {
    pub fn next(self) -> Self {
        match self {
            Sort::Name => Sort::Link,
            Sort::Link => Sort::Signal,
            Sort::Signal => Sort::Lease,
            Sort::Lease => Sort::Name,
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            Sort::Name => "name",
            Sort::Link => "link",
            Sort::Signal => "signal",
            Sort::Lease => "lease",
        }
    }
}

/// Order the rows: unknown ones first whatever the sort (they're what to look at), then by
/// the column asked for, the name breaking ties.
pub fn sort<T>(rows: &mut [T], by: Sort, row: impl Fn(&T) -> &Row) {
    let link = |r: &Row| match &r.link {
        Link::Wired(p) => (0, p.clone()),
        Link::Wifi(i, _) => (1, i.clone()),
        Link::Other(o) => (2, o.clone()),
        Link::None => (3, String::new()),
    };
    // Strongest first; no signal last.
    let signal = |r: &Row| match &r.link {
        Link::Wifi(_, Some(s)) => -(*s as i64),
        _ => i64::MAX,
    };
    rows.sort_by(|a, b| {
        let (a, b) = (row(a), row(b));
        let first = (a.standing != Standing::Unknown).cmp(&(b.standing != Standing::Unknown));
        let name = || a.name.to_lowercase().cmp(&b.name.to_lowercase());
        first
            .then_with(|| match by {
                Sort::Name => std::cmp::Ordering::Equal,
                Sort::Link => link(a).cmp(&link(b)),
                Sort::Signal => signal(a).cmp(&signal(b)),
                // Ending soonest first; no lease last.
                Sort::Lease => a
                    .lease_left
                    .unwrap_or(i64::MAX)
                    .cmp(&b.lease_left.unwrap_or(i64::MAX)),
            })
            .then_with(name)
    });
}

pub fn hints() -> Vec<(&'static str, &'static str)> {
    vec![
        ("j/k", "select"),
        ("Enter", "details"),
        ("s", "sort"),
        ("b", "expected on/off"),
        ("/", "filter"),
        ("r", "read again"),
    ]
}

/// A signal as four bars: `▂▄▆█` at −55 dBm or better, one bar under −80.
pub fn bars(dbm: i32) -> &'static str {
    match dbm {
        d if d >= -55 => "▂▄▆█",
        d if d >= -67 => "▂▄▆ ",
        d if d >= -80 => "▂▄  ",
        _ => "▂   ",
    }
}

/// A length of time in a narrow column: `45s`, `12m`, `5h`, `3d`.
pub fn short(secs: i64) -> String {
    match secs.max(0) {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 2 * 86400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86400),
    }
}

fn link_cell<'a>(t: &Theme, l: &Link, online: bool) -> Cell<'a> {
    let st = if online { t.fg() } else { t.dim() };
    match l {
        Link::Wired(p) => Cell::from(p.clone()).style(st),
        Link::Other(o) => Cell::from(o.clone()).style(st),
        Link::None => Cell::from("–").style(t.dim()),
        Link::Wifi(i, None) => Cell::from(i.clone()).style(t.dim()),
        Link::Wifi(i, Some(s)) => {
            let c = match *s {
                d if d >= -67 => t.green,
                d if d >= -80 => t.yellow,
                _ => t.red,
            };
            Cell::from(Line::from(vec![
                Span::styled(format!("{} ", trunc(i, 9)), st),
                Span::styled(bars(*s), t.s(c)),
                Span::styled(format!(" {s}"), t.dim()),
            ]))
        }
    }
}

/// The table: `rows` already filtered and sorted by `by` (its column gets the `▼`). Narrow
/// terminals lose the lease and last-seen columns before anything else.
pub fn draw(f: &mut Frame, area: Rect, t: &Theme, rows: &[Row], sel: Option<usize>, by: Sort) {
    let mark = |s: Sort| if by == s { " ▼" } else { "" };
    let heads = [
        format!("NAME{}", mark(Sort::Name)),
        if by == Sort::Signal {
            "LINK · SIGNAL ▼".to_string()
        } else {
            format!("LINK{}", mark(Sort::Link))
        },
        "ADDRESS".to_string(),
        format!("LEASE{}", mark(Sort::Lease)),
        "SEEN".to_string(),
        String::new(),
    ];
    let cols: &[usize] = match area.width {
        w if w >= 96 => &[0, 1, 2, 3, 4, 5],
        w if w >= 76 => &[0, 1, 2, 3, 5],
        _ => &[0, 1, 2, 5],
    };
    let widths = [
        Constraint::Fill(3),
        Constraint::Length(21),
        Constraint::Fill(2),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(8),
    ];
    let body: Vec<TableRow> = rows
        .iter()
        .map(|r| {
            let st = if r.online { t.fg() } else { t.dim() };
            let name = Line::from(vec![
                Span::styled(if r.private { "~" } else { " " }, t.dim()),
                Span::styled(r.name.clone(), st),
                Span::styled(if r.leave_alone { "  (leave alone)" } else { "" }, t.dim()),
            ]);
            let lease = match r.lease_left {
                None => "–".to_string(),
                Some(s) if s <= 0 => "ended".to_string(),
                Some(s) => short(s),
            };
            let seen = match (r.online, r.seen_ago) {
                (true, _) => "now".to_string(),
                (false, Some(s)) => short(s),
                (false, None) => "–".to_string(),
            };
            let (word, c) = match r.standing {
                Standing::Fine => ("", t.dim),
                Standing::Unknown => ("NEW", t.red),
                Standing::Expected => ("expected", t.dim),
            };
            let cells = [
                Cell::from(name),
                link_cell(t, &r.link, r.online),
                Cell::from(r.addr.clone()).style(st),
                Cell::from(lease).style(t.dim()),
                Cell::from(seen).style(t.dim()),
                Cell::from(word).style(t.s(c)),
            ];
            TableRow::new(cols.iter().map(|i| cells[*i].clone()).collect::<Vec<_>>())
        })
        .collect();
    table(
        f,
        area,
        t,
        TableSpec {
            header: cols.iter().map(|i| heads[*i].as_str()).collect(),
            widths: cols.iter().map(|i| widths[*i]).collect(),
            rows: body,
            selected: sel.filter(|_| !rows.is_empty()),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn row(name: &str, link: Link, standing: Standing) -> Row {
        Row {
            name: name.into(),
            private: false,
            link,
            addr: "192.0.2.10".into(),
            lease_left: Some(7200),
            seen_ago: Some(0),
            online: true,
            standing,
            leave_alone: false,
        }
    }

    fn text(rows: &[Row], w: u16, by: Sort) -> Vec<String> {
        let t = Theme::truecolor();
        let mut term = Terminal::new(TestBackend::new(w, 6)).unwrap();
        term.draw(|f| draw(f, f.area(), &t, rows, Some(0), by))
            .unwrap();
        let buf = term.backend().buffer().clone();
        (0..6)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect()
    }

    #[test]
    fn unknown_first_then_the_column_asked_for() {
        let mut rows = vec![
            row("nas", Link::Wired("lan2".into()), Standing::Fine),
            row(
                "Phone",
                Link::Wifi("phy1-ap0".into(), Some(-46)),
                Standing::Fine,
            ),
            Row {
                lease_left: Some(60),
                ..row(
                    "tv",
                    Link::Wifi("phy0-ap0".into(), Some(-71)),
                    Standing::Fine,
                )
            },
            row("zz-new", Link::Wired("lan1".into()), Standing::Unknown),
            Row {
                lease_left: None,
                ..row("away", Link::None, Standing::Expected)
            },
        ];
        let names = |rows: &[Row]| rows.iter().map(|r| r.name.clone()).collect::<Vec<_>>();
        sort(&mut rows, Sort::Name, |r| r);
        assert_eq!(names(&rows), ["zz-new", "away", "nas", "Phone", "tv"]);
        sort(&mut rows, Sort::Link, |r| r);
        assert_eq!(names(&rows), ["zz-new", "nas", "tv", "Phone", "away"]);
        sort(&mut rows, Sort::Signal, |r| r);
        assert_eq!(names(&rows), ["zz-new", "Phone", "tv", "away", "nas"]);
        sort(&mut rows, Sort::Lease, |r| r);
        assert_eq!(names(&rows), ["zz-new", "tv", "nas", "Phone", "away"]);
        assert_eq!(Sort::Lease.next(), Sort::Name);
        assert_eq!(Sort::default().next().word(), "link");
    }

    #[test]
    fn signal_as_bars_and_times_kept_short() {
        assert_eq!(bars(-40), "▂▄▆█");
        assert_eq!(bars(-60), "▂▄▆ ");
        assert_eq!(bars(-75), "▂▄  ");
        assert_eq!(bars(-90), "▂   ");
        let said: Vec<String> = [45, 720, 18_000, 100_000, 260_000, -5]
            .into_iter()
            .map(short)
            .collect();
        assert_eq!(said, ["45s", "12m", "5h", "27h", "3d", "0s"]);
    }

    #[test]
    fn the_table_marks_private_unknown_and_narrows_by_dropping_columns() {
        let rows = [
            Row {
                private: true,
                ..row(
                    "phone",
                    Link::Wifi("phy1-ap0".into(), Some(-46)),
                    Standing::Fine,
                )
            },
            Row {
                online: false,
                seen_ago: Some(7200),
                lease_left: Some(-3),
                leave_alone: true,
                ..row("panel", Link::None, Standing::Unknown)
            },
        ];
        let wide = text(&rows, 110, Sort::Signal);
        assert!(
            wide[0].contains("LINK · SIGNAL ▼") && wide[0].contains("SEEN"),
            "{}",
            wide[0]
        );
        assert!(
            wide[1].contains("~phone") && wide[1].contains("phy1-ap0 ▂▄▆█ -46"),
            "{}",
            wide[1]
        );
        assert!(wide[1].contains("2h") && wide[1].contains("now"));
        assert!(
            wide[2].contains("panel  (leave alone)") && wide[2].contains("NEW"),
            "{}",
            wide[2]
        );
        assert!(wide[2].contains("ended") && wide[2].contains(" 2h"));
        let narrow = text(&rows, 70, Sort::Name);
        assert!(
            narrow[0].contains("NAME ▼") && !narrow[0].contains("LEASE"),
            "{}",
            narrow[0]
        );
        assert!(narrow[2].contains("NEW") && narrow[1].contains("192.0.2.10"));
        let mid = text(&rows, 80, Sort::Lease);
        assert!(
            mid[0].contains("LEASE ▼") && !mid[0].contains("SEEN"),
            "{}",
            mid[0]
        );
    }
}

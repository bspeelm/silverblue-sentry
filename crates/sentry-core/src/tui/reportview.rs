//! The audit report view (`F` on Maintenance), in both programs: a report's findings with the
//! selected one explained, beside what changed since the report before. Each program makes
//! the [`Page`] from its own reports; moving around, the two panes and the drawing are here.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row as TableRow};

use super::Cursor;
use super::keys::Action;
use super::theme::Theme;
use super::widgets::{TableSpec, inner, panel, placeholder, table, trunc, wrap};
use crate::finding::{Finding, Sev};

/// How a line of the changes pane is coloured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Section,
    Add,
    Remove,
    Change,
    Same,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Focus {
    #[default]
    Findings,
    Changes,
}

/// The view's own state: which report, which finding, which pane.
#[derive(Default)]
pub struct ReportView {
    pub cur: Cursor,
    /// Index into the reports; `None` follows the latest.
    pub report: Option<usize>,
    focus: Focus,
    scroll: usize,
    page: usize,
}

/// A finding in the list.
pub struct Row<'a> {
    pub finding: &'a Finding,
    /// Expected now (the baseline decides, so marking one shows at once).
    pub expected: bool,
}

/// One report, as the view shows it.
pub struct Page<'a> {
    /// The report's name, and where it is among them (`(2, 5)`) when there are several.
    pub name: String,
    pub pos: Option<(usize, usize)>,
    /// The two lines above the list: what this is, and the keys.
    pub header: &'a str,
    pub keys: &'a str,
    pub rows: Vec<Row<'a>>,
    /// Shown instead of the list when `rows` is empty.
    pub empty: &'a str,
    /// Findings to check, to review, and for information.
    pub counts: (usize, usize, usize),
    pub not_collected: Vec<String>,
    /// The selected finding explained, wrapped to a width.
    pub detail: &'a dyn Fn(&Finding, usize) -> Vec<Line<'static>>,
    /// The right pane: its name ("Diff"), its title, its lines.
    pub changes_name: &'a str,
    pub changes_title: String,
    pub changes: Vec<(Mark, String)>,
}

impl ReportView {
    /// The report shown, of `n`.
    pub fn idx(&self, n: usize) -> Option<usize> {
        if n == 0 {
            return None;
        }
        Some(self.report.unwrap_or(n - 1).min(n - 1))
    }

    /// The finding selected, of `n` rows.
    pub fn selected(&mut self, n: usize) -> usize {
        self.cur.clamp(n)
    }

    /// The view's own keys: the pane in focus (C-h/C-l), the changes pane's scroll, `[` `]`
    /// between reports, moving in the list. True: the key was the view's.
    pub fn key(&mut self, a: Action, n_reports: usize, n_rows: usize) -> bool {
        match a {
            Action::FocusLeft => self.focus = Focus::Findings,
            Action::FocusRight => self.focus = Focus::Changes,
            Action::LogDown => self.scroll += 1,
            Action::LogUp => self.scroll = self.scroll.saturating_sub(1),
            Action::Char('[') if n_reports > 0 => {
                let i = self.idx(n_reports).unwrap_or(0);
                self.report = Some(i.saturating_sub(1));
                self.cur.sel = 0;
                self.scroll = 0;
            }
            Action::Char(']') if n_reports > 0 => {
                let i = self.idx(n_reports).unwrap_or(0);
                self.report = if i + 1 >= n_reports - 1 {
                    None
                } else {
                    Some(i + 1)
                };
                self.cur.sel = 0;
                self.scroll = 0;
            }
            // In the changes pane every other key is its scrolling, or nothing.
            _ if self.focus == Focus::Changes => {
                let page = self.page.max(2);
                match a {
                    Action::Down => self.scroll += 1,
                    Action::Up => self.scroll = self.scroll.saturating_sub(1),
                    Action::PageDown => self.scroll += page / 2,
                    Action::PageUp => self.scroll = self.scroll.saturating_sub(page / 2),
                    Action::Top => self.scroll = 0,
                    Action::Bottom => self.scroll = usize::MAX / 2,
                    _ => {}
                }
            }
            _ => return self.cur.nav(a, n_rows),
        }
        true
    }

    pub fn draw(&mut self, f: &mut Frame, area: Rect, t: &Theme, p: &Page) {
        // Narrow terminals show one pane at a time; C-h/C-l switch.
        let (left, right) = if area.width < 110 {
            match self.focus {
                Focus::Findings => (area, Rect { width: 0, ..area }),
                Focus::Changes => (Rect { width: 0, ..area }, area),
            }
        } else {
            let [l, r] =
                Layout::horizontal([Constraint::Ratio(52, 100), Constraint::Ratio(48, 100)])
                    .spacing(2)
                    .areas(area);
            (l, r)
        };

        // ---- findings + evidence
        let pos = p.pos.map_or(String::new(), |(i, n)| format!(" ({i}/{n})"));
        let block = panel(t, "Findings", format!("{}{pos}", p.name));
        let r = inner(&block, left);
        f.render_widget(block, left);
        let sel = self.selected(p.rows.len());
        // Detail box for the selected finding: what / why / to do, then the raw evidence.
        let detail: Vec<Line> = p
            .rows
            .get(sel)
            .map_or(Vec::new(), |row| (p.detail)(row.finding, r.width as usize));
        let detail_rows = detail.len();
        let ev_h = (detail_rows as u16 + 1).clamp(4, (r.height / 2).max(4));
        let [head, list, summary, evidence] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(ev_h),
        ])
        .areas(r);
        f.render_widget(
            Paragraph::new(vec![
                Line::styled(p.header.to_string(), t.fg()),
                Line::styled(trunc(p.keys, head.width as usize), t.dim()),
            ]),
            head,
        );
        self.cur.page = list.height as usize;
        if p.rows.is_empty() {
            f.render_widget(Paragraph::new(p.empty.to_string()).style(t.dim()), list);
        } else {
            let body: Vec<TableRow> = p
                .rows
                .iter()
                .map(|row| {
                    let fd = row.finding;
                    // check = look at this now, review = worth a look, info = probably your choice
                    let (sev, sc) = match (row.expected, fd.severity) {
                        (true, _) => ("ok", t.dim),
                        (_, Sev::High) => ("check", t.red),
                        (_, Sev::Medium) => ("review", t.yellow),
                        (_, Sev::Low) => ("info", t.dim),
                    };
                    let msg = if row.expected {
                        format!("{}  (expected)", fd.message)
                    } else {
                        fd.message.clone()
                    };
                    TableRow::new(vec![
                        Cell::from(sev).style(t.s(sc)),
                        Cell::from(fd.category.clone()).style(t.dim()),
                        Cell::from(msg).style(if row.expected { t.dim() } else { t.fg() }),
                    ])
                })
                .collect();
            table(
                f,
                list,
                t,
                TableSpec {
                    header: vec!["", "AREA", "FINDING"],
                    widths: vec![
                        Constraint::Length(6),
                        Constraint::Length(9),
                        Constraint::Fill(1),
                    ],
                    rows: body,
                    selected: (self.focus == Focus::Findings).then_some(sel),
                },
            );
        }
        let (high, medium, low) = p.counts;
        let mut sum = vec![
            Span::styled(
                format!("{high} to check"),
                t.s(if high > 0 { t.red } else { t.dim }),
            ),
            Span::styled(" · ", t.dim()),
            Span::styled(
                format!("{medium} to review"),
                t.s(if medium > 0 { t.yellow } else { t.dim }),
            ),
            Span::styled(format!(" · {low} info"), t.dim()),
        ];
        if !p.not_collected.is_empty() {
            sum.push(Span::styled(
                format!("   not collected: {}", p.not_collected.join(", ")),
                t.s(t.yellow),
            ));
        }
        f.render_widget(Paragraph::new(Line::from(sum)), summary);
        let mut ev = vec![Line::styled(
            "─".repeat(evidence.width as usize),
            t.s(t.rule),
        )];
        ev.extend(detail);
        f.render_widget(Paragraph::new(ev), evidence);

        // ---- what changed
        let block = panel(t, p.changes_name, p.changes_title.clone());
        let r = inner(&block, right);
        f.render_widget(block, right);
        let h = r.height as usize;
        self.page = h;
        let max = p.changes.len().saturating_sub(h);
        self.scroll = self.scroll.min(max);
        let shown: Vec<Line> = p
            .changes
            .iter()
            .skip(self.scroll)
            .take(h)
            .map(|(mark, text)| {
                let c = match mark {
                    Mark::Section => t.cyan,
                    Mark::Add => t.green,
                    Mark::Remove => t.red,
                    Mark::Change => t.yellow,
                    Mark::Same => t.dim,
                };
                Line::styled(trunc(text, r.width as usize), t.s(c))
            })
            .collect();
        f.render_widget(Paragraph::new(shown), r);
        if self.focus == Focus::Changes && max > 0 {
            let pct = self.scroll * 100 / max;
            let s = format!(" {pct}% ");
            f.render_widget(
                Paragraph::new(Span::styled(s.clone(), t.dim())),
                Rect {
                    x: right.right().saturating_sub(s.len() as u16 + 2),
                    y: right.bottom().saturating_sub(1),
                    width: s.len() as u16,
                    height: 1,
                },
            );
        }
    }
}

/// What / Why / To do for a finding, wrapped to `width` in a labelled gutter, then how to
/// fix it (`fix`, when there's a way) and its evidence.
pub fn finding_lines(
    t: &Theme,
    fd: &Finding,
    width: usize,
    fix: Option<&str>,
) -> Vec<Line<'static>> {
    let tw = width.saturating_sub(7).max(10);
    let mut d = Vec::new();
    // Label in a 7-column gutter; wrapped text stays aligned under the first line.
    let mut sec = |label: &str, text: &str| {
        for (k, l) in wrap(text, tw).into_iter().enumerate() {
            d.push(Line::from(vec![
                Span::styled(
                    format!("{:<7}", if k == 0 { label } else { "" }),
                    t.s(t.cyan),
                ),
                Span::styled(l, t.fg()),
            ]));
        }
    };
    // Reports from before what/why/fix existed: message + evidence only.
    sec(
        "What",
        if fd.what.is_empty() {
            &fd.message
        } else {
            &fd.what
        },
    );
    sec("Why", &fd.why);
    sec("To do", &fd.fix);
    if let Some(fix) = fix {
        sec("Fix", fix);
    }
    for l in fd.evidence.lines().take(8) {
        d.push(Line::styled(format!("       {l}"), t.dim()));
    }
    d
}

/// No report yet: how to get one, and where they're kept.
pub fn draw_placeholder(
    f: &mut Frame,
    area: Rect,
    t: &Theme,
    loading: bool,
    how: &str,
    kept: &str,
) {
    placeholder(
        f,
        area,
        t,
        &[
            (
                if loading {
                    "loading reports…"
                } else {
                    "No audit yet."
                },
                t.fg(),
            ),
            ("", t.dim()),
            (how, t.dim()),
            (kept, t.dim()),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_view_s_keys_move_between_reports_panes_and_findings() {
        let mut v = ReportView::default();
        assert_eq!(v.idx(0), None);
        assert_eq!(v.idx(3), Some(2), "the latest");
        assert!(v.key(Action::Char('['), 3, 5));
        assert_eq!(v.idx(3), Some(1));
        assert!(v.key(Action::Char(']'), 3, 5));
        assert_eq!(v.report, None, "back on the latest, and following it");
        // In the list: moving is the view's, the rest is the program's.
        assert!(v.key(Action::Down, 3, 5));
        assert_eq!(v.cur.sel, 1);
        assert!(!v.key(Action::Enter, 3, 5));
        // In the changes pane everything is its scrolling.
        assert!(v.key(Action::FocusRight, 3, 5));
        assert!(v.key(Action::Down, 3, 5) && v.key(Action::Enter, 3, 5));
        assert_eq!((v.cur.sel, v.scroll), (1, 1));
        assert!(v.key(Action::FocusLeft, 3, 5));
        assert!(!v.key(Action::Enter, 3, 5));
    }

    #[test]
    fn a_finding_is_explained_in_a_gutter() {
        let fd = Finding {
            message: "port 8080 open".into(),
            why: "Reachable from outside.".into(),
            evidence: "tcp 0.0.0.0:8080\nmore".into(),
            ..Default::default()
        };
        let l: Vec<String> = finding_lines(&Theme::truecolor(), &fd, 60, Some("press Enter"))
            .iter()
            .map(|l| l.to_string())
            .collect();
        assert_eq!(
            l,
            [
                "What   port 8080 open",
                "Why    Reachable from outside.",
                "Fix    press Enter",
                "       tcp 0.0.0.0:8080",
                "       more"
            ]
        );
    }
}

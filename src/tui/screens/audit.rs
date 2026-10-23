//! Audit: findings of the selected report with an evidence box, and the structural diff against
//! the report before it. `Enter` audits now (read-only), `b`/`B` baseline, `[`/`]` browse.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Wrap};

use super::{Cursor, Hints, View};
use crate::audit::diff::{self, Kind};
use crate::audit::findings::is_expected;
use crate::audit::store::Stored;
use crate::audit::{Finding, Sev};
use crate::exec::Cmd;
use crate::tui::app::{BaselineEdit, Effect, Modal, RunSpec};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::widgets::{TableSpec, inner, panel, placeholder, table, trunc};

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Focus {
    #[default]
    Findings,
    Diff,
}

#[derive(Default)]
pub struct Audit {
    pub cur: Cursor,
    /// Index into the report list; `None` follows the latest.
    report: Option<usize>,
    focus: Focus,
    diff_scroll: usize,
    diff_h: usize,
}

pub fn on_enter(_v: &View) -> Vec<Effect> {
    vec![Effect::Fetch(Fetch::Reports)]
}

pub fn hints(v: &View) -> Hints {
    if v.d.reports.get().is_none_or(|r| r.is_empty()) {
        return vec![("Enter", "run audit")];
    }
    vec![
        ("j/k", "select"),
        ("b", "accept as baseline"),
        ("B", "baseline pattern"),
        ("Enter", "run audit"),
        ("[ ]", "browse reports"),
        ("C-h/l", "focus"),
    ]
}

/// `sentry job audit`, streamed. Same binary, so headless and TUI runs are identical.
pub fn audit_run() -> Effect {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "sentry".into());
    Effect::Run(RunSpec {
        title: "sentry job audit".into(),
        cmd: Cmd::local(&exe).args(["job", "audit"]).timeout(None),
        then: vec![Fetch::Reports],
        ok_toast: "audit complete".into(),
    })
}

/// Broader baseline pattern for `B`: same process on any address, same app any permission, …
pub fn pattern_for(f: &Finding) -> Option<(BaselineEdit, String)> {
    let id = f.id.as_str();
    if let Some(key) = id.strip_prefix("listener:") {
        let (_, proc) = key.rsplit_once('/')?;
        if proc == "?" {
            return None;
        }
        let p = format!("*/{proc}");
        return Some((
            BaselineEdit::Listener(p.clone()),
            format!("any address/port for process {proc}"),
        ));
    }
    let (kind, rest) = id.split_once(':')?;
    let (p, what) = match kind {
        "flatpak-perm" => {
            let app = rest.split(':').next()?;
            (format!("flatpak-perm:{app}:*"), format!("every flagged permission of {app}"))
        }
        "repo" => {
            let stem = rest.split(['-', '.']).next()?;
            (format!("repo:{stem}*"), format!("every repo file starting with {stem}"))
        }
        "unit-failed" => {
            let scope = rest.split(':').next()?;
            (format!("unit-failed:{scope}:*"), format!("every failed {scope} unit"))
        }
        "flatpak-gl-stale" => ("flatpak-gl-stale:*".into(), "every stale GL extension".into()),
        _ => return None,
    };
    Some((BaselineEdit::Finding(p), what))
}

impl Audit {
    fn reports<'a>(&self, v: &View<'a>) -> &'a [Stored] {
        v.d.reports.get().map_or(&[], |r| r.as_slice())
    }

    fn idx(&self, n: usize) -> Option<usize> {
        if n == 0 {
            return None;
        }
        Some(self.report.unwrap_or(n - 1).min(n - 1))
    }

    fn rows<'a>(&self, v: &View<'a>) -> Vec<&'a Finding> {
        let all = self.reports(v);
        let Some(i) = self.idx(all.len()) else {
            return Vec::new();
        };
        let b = &v.d.baseline;
        let mut rows: Vec<&Finding> = all[i]
            .report
            .findings
            .iter()
            .filter(|f| v.matches(&[&f.message, &f.category, f.severity.as_str()]))
            .collect();
        // The current baseline decides what's expected (b takes effect immediately).
        rows.sort_by_key(|f| (is_expected(f, b), std::cmp::Reverse(f.severity)));
        rows
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        let n = self.reports(v).len();
        match a {
            Action::FocusLeft => self.focus = Focus::Findings,
            Action::FocusRight => self.focus = Focus::Diff,
            Action::LogDown => self.diff_scroll += 1,
            Action::LogUp => self.diff_scroll = self.diff_scroll.saturating_sub(1),
            Action::Char('[') if n > 0 => {
                let i = self.idx(n).unwrap_or(0);
                self.report = Some(i.saturating_sub(1));
                self.cur.sel = 0;
                self.diff_scroll = 0;
            }
            Action::Char(']') if n > 0 => {
                let i = self.idx(n).unwrap_or(0);
                self.report = if i + 1 >= n - 1 { None } else { Some(i + 1) };
                self.cur.sel = 0;
                self.diff_scroll = 0;
            }
            Action::Enter => return vec![audit_run()],
            Action::Refresh => return vec![Effect::Fetch(Fetch::Reports)],
            _ if self.focus == Focus::Diff => {
                let page = self.diff_h.max(2);
                match a {
                    Action::Down => self.diff_scroll += 1,
                    Action::Up => self.diff_scroll = self.diff_scroll.saturating_sub(1),
                    Action::PageDown => self.diff_scroll += page / 2,
                    Action::PageUp => self.diff_scroll = self.diff_scroll.saturating_sub(page / 2),
                    Action::Top => self.diff_scroll = 0,
                    Action::Bottom => self.diff_scroll = usize::MAX / 2,
                    _ => {}
                }
            }
            _ => {
                let rows = self.rows(v);
                if self.cur.nav(a, rows.len()) {
                    return Vec::new();
                }
                let Some(f) = rows.get(self.cur.clamp(rows.len())) else {
                    return Vec::new();
                };
                match a {
                    Action::Char('b') if is_expected(f, &v.d.baseline) => {
                        return vec![Effect::Toast("already in the baseline".into())];
                    }
                    Action::Char('b') => {
                        let edit = match f.id.strip_prefix("listener:") {
                            Some(k) => BaselineEdit::Listener(k.to_string()),
                            None => BaselineEdit::Finding(f.id.clone()),
                        };
                        return vec![Effect::Baseline(edit)];
                    }
                    Action::Char('B') => {
                        let Some((edit, what)) = pattern_for(f) else {
                            return vec![Effect::Toast(
                                "no broader pattern for this finding — use b".into(),
                            )];
                        };
                        let t = v.t;
                        return vec![Effect::Confirm(Modal {
                            title: "Baseline pattern".into(),
                            color: t.yellow,
                            lines: vec![
                                Line::styled(format!("Treat {what} as expected?"), t.fg()),
                                Line::styled(
                                    format!("baseline.toml ← {}", edit.value()),
                                    t.dim(),
                                ),
                                Line::styled(
                                    "Future audits suppress matching findings. Edit the file to undo.",
                                    t.dim(),
                                ),
                            ],
                            yes: Some(("add pattern".into(), vec![Effect::Baseline(edit)])),
                        })];
                    }
                    _ => {}
                }
            }
        }
        Vec::new()
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let all = self.reports(v);
        let Some(i) = self.idx(all.len()) else {
            let loading = v.d.loading(Fetch::Reports);
            placeholder(
                f,
                area,
                t,
                &[
                    (if loading { "loading reports…" } else { "No audit yet." }, t.fg()),
                    ("", t.dim()),
                    (
                        "Press Enter to run one. It's read-only and takes about a second.",
                        t.dim(),
                    ),
                    (
                        "Reports are kept in ~/.local/share/sentry/reports/ (json + md).",
                        t.dim(),
                    ),
                ],
            );
            return;
        };
        let cur = &all[i];
        let prev = i.checked_sub(1).map(|j| &all[j]);
        let [left, right] =
            Layout::horizontal([Constraint::Ratio(52, 100), Constraint::Ratio(48, 100)])
                .spacing(2)
                .areas(area);

        // ---- findings + evidence
        let b = &v.d.baseline;
        let c = cur.report.counts(b);
        let pos = if all.len() > 1 {
            format!(" ({}/{})", i + 1, all.len())
        } else {
            String::new()
        };
        let block = panel(t, "Findings", format!("{}{pos}", cur.name()));
        let r = inner(&block, left);
        f.render_widget(block, left);
        let rows = self.rows(v);
        let sel = self.cur.clamp(rows.len());
        let ev_lines: Vec<&str> = rows
            .get(sel)
            .map_or(Vec::new(), |f| f.evidence.lines().collect());
        let ev_h = (ev_lines.len() as u16 + 2).clamp(4, 9).min(r.height / 2);
        let [list, summary, evidence] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(ev_h),
        ])
        .areas(r);
        self.cur.page = list.height as usize;
        if rows.is_empty() {
            f.render_widget(
                Paragraph::new(if cur.report.findings.is_empty() {
                    "No findings."
                } else {
                    "No findings match the filter."
                })
                .style(t.dim()),
                list,
            );
        } else {
            let body: Vec<Row> = rows
                .iter()
                .map(|fd| {
                    let exp = is_expected(fd, b);
                    let (sev, sc) = match (exp, fd.severity) {
                        (true, _) => ("—", t.dim),
                        (_, Sev::High) => ("high", t.red),
                        (_, Sev::Medium) => ("medium", t.yellow),
                        (_, Sev::Low) => ("low", t.dim),
                    };
                    let msg = if exp {
                        format!("{}  (expected)", fd.message)
                    } else {
                        fd.message.clone()
                    };
                    Row::new(vec![
                        Cell::from(sev).style(t.s(sc)),
                        Cell::from(fd.category.clone()).style(t.dim()),
                        Cell::from(msg).style(if exp { t.dim() } else { t.fg() }),
                    ])
                })
                .collect();
            table(
                f,
                list,
                t,
                TableSpec {
                    header: vec!["SEV", "CATEGORY", "FINDING"],
                    widths: vec![
                        Constraint::Length(7),
                        Constraint::Length(10),
                        Constraint::Fill(1),
                    ],
                    rows: body,
                    selected: (self.focus == Focus::Findings).then_some(sel),
                },
            );
        }
        let mut sum = vec![
            Span::styled(format!("{} high", c.high), t.s(if c.high > 0 { t.red } else { t.dim })),
            Span::styled(" · ", t.dim()),
            Span::styled(
                format!("{} medium", c.medium),
                t.s(if c.medium > 0 { t.yellow } else { t.dim }),
            ),
            Span::styled(format!(" · {} low", c.low), t.dim()),
        ];
        if !cur.report.errors.is_empty() {
            sum.push(Span::styled(
                format!("   not collected: {}", cur.report.errors.join(", ")),
                t.s(t.yellow),
            ));
        }
        f.render_widget(Paragraph::new(Line::from(sum)), summary);
        let mut ev = vec![
            Line::styled("─".repeat(evidence.width as usize), t.s(t.rule)),
            Line::styled("evidence", t.dim()),
        ];
        ev.extend(ev_lines.iter().map(|l| Line::styled(l.to_string(), t.fg())));
        f.render_widget(Paragraph::new(ev).wrap(Wrap { trim: false }), evidence);

        // ---- diff pane
        let title = match prev {
            Some(p) => format!("{} → {}", strip_json(&p.name()), strip_json(&cur.name())),
            None => "first report".into(),
        };
        let block = panel(t, "Diff", title);
        let r = inner(&block, right);
        f.render_widget(block, right);
        let lines: Vec<diff::Line> = match prev {
            Some(p) => diff::diff(&p.report, &cur.report),
            None => vec![diff::Line {
                kind: Kind::Same,
                text: "Nothing to compare against yet. The next audit diffs against this one."
                    .into(),
            }],
        };
        let h = r.height as usize;
        self.diff_h = h;
        let max = lines.len().saturating_sub(h);
        self.diff_scroll = self.diff_scroll.min(max);
        let shown: Vec<Line> = lines
            .iter()
            .skip(self.diff_scroll)
            .take(h)
            .map(|l| {
                let c = match l.kind {
                    Kind::Section => t.cyan,
                    Kind::Add => t.green,
                    Kind::Remove => t.red,
                    Kind::Change => t.yellow,
                    Kind::Same => t.dim,
                };
                Line::styled(trunc(&l.text, r.width as usize), t.s(c))
            })
            .collect();
        f.render_widget(Paragraph::new(shown), r);
        if self.focus == Focus::Diff && max > 0 {
            let pct = self.diff_scroll * 100 / max;
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

fn strip_json(s: &str) -> &str {
    s.strip_suffix(".json").unwrap_or(s)
}

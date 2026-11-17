//! The workflow list of screen `0` while nothing runs, in both programs: each workflow with
//! its steps, lint and last run on the left; the selected one's last result and its start
//! card on the right. Also the card itself, which a running step uses too.

use std::path::Path;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use super::theme::Theme;
use super::widgets::{inner, panel, short_home, wrap};
use crate::workflows::Entry;
use crate::workflows::state::RunStatus;

/// A workflow file plus its most recent run.
#[derive(Debug, Clone)]
pub struct WfInfo {
    pub entry: Entry,
    /// How it ended, when it started, and the steps done of how many.
    pub last: Option<(RunStatus, jiff::Timestamp, usize, usize)>,
}

/// Each workflow with its last run, read from the runs kept under `root`.
pub fn load_infos(entries: Vec<Entry>, root: &Path) -> Vec<WfInfo> {
    entries
        .into_iter()
        .map(|entry| {
            let last = crate::workflows::state::runs_in(root, &entry.name)
                .last()
                .map(|r| {
                    (
                        r.state.status,
                        r.state.started,
                        r.state.done_count(),
                        r.state.steps.len(),
                    )
                });
            WfInfo { entry, last }
        })
        .collect()
}

/// What a program adds about one workflow.
#[derive(Default)]
pub struct Notes {
    /// Something for it to do now (sentry: the updates waiting), under its last run.
    pub waiting: Option<String>,
    /// More lines under "Last result", when it's the one selected.
    pub right: Vec<Line<'static>>,
}

/// The screen's two columns: the list (or the steps), and the rest.
pub fn split(area: Rect) -> (Rect, Rect) {
    let [left, right] = Layout::horizontal([
        Constraint::Length(60.min(area.width / 2)),
        Constraint::Fill(1),
    ])
    .spacing(2)
    .areas(area);
    (left, right)
}

/// A run's time, as the list writes it.
pub fn when(ts: jiff::Timestamp) -> String {
    ts.to_zoned(jiff::tz::TimeZone::system())
        .strftime("%Y-%m-%d %H:%M")
        .to_string()
}

/// The list and the selected workflow's card. `empty`: what the list says with nothing in it.
pub fn draw_idle(
    f: &mut Frame,
    (left, right): (Rect, Rect),
    t: &Theme,
    infos: &[WfInfo],
    sel: usize,
    empty: &str,
    notes: &dyn Fn(&WfInfo, usize) -> Notes,
) {
    let dir = infos
        .first()
        .and_then(|i| i.entry.path.parent().map(short_home))
        .unwrap_or_default();
    let block = panel(t, "Workflows", dir);
    let r = inner(&block, left);
    f.render_widget(block, left);
    let mut y = r.y;
    for (i, info) in infos.iter().enumerate() {
        let e = &info.entry;
        let steps = e.wf.as_ref().map_or(0, |w| w.steps.len());
        let desc =
            e.wf.as_ref()
                .map_or(String::new(), |w| w.description.clone());
        let mut head = vec![
            Span::styled(e.name.clone(), t.fg()),
            Span::styled(format!("  {steps} steps"), t.dim()),
        ];
        if e.wf.as_ref().is_ok_and(|w| w.draft) {
            head.push(Span::styled("  draft", t.s(t.yellow)));
        }
        if e.errors().next().is_some() || e.wf.is_err() {
            head.push(Span::styled("  lint ✗", t.s(t.red)));
        }
        let (last, lc) = match info.last {
            Some((RunStatus::Done, ts, d, n)) => {
                (format!("✓ {} · {d}/{n} · completed", when(ts)), t.green)
            }
            Some((RunStatus::Abandoned, ts, d, n)) => {
                (format!("■ {} · {d}/{n} · abandoned", when(ts)), t.dim)
            }
            Some((RunStatus::InProgress, ts, d, n)) => {
                (format!("● {} · {d}/{n} · in progress", when(ts)), t.yellow)
            }
            None => ("never run".into(), t.dim),
        };
        // Something to do since the last run: that run being done doesn't mean nothing's left.
        let waiting = notes(info, r.width as usize).waiting;
        let lc = if waiting.is_some() && lc == t.green {
            t.dim
        } else {
            lc
        };
        let mut lines = vec![Line::from(head)];
        lines.extend(
            wrap(&desc, r.width as usize)
                .into_iter()
                .map(|l| Line::styled(l, t.dim())),
        );
        if waiting.is_some() && info.last.is_some() {
            lines.push(Line::styled(format!("last time: {last}"), t.s(lc)));
        } else {
            lines.push(Line::styled(last, t.s(lc)));
        }
        if let Some(w) = waiting {
            lines.push(Line::styled(w, t.s(t.yellow)));
        }
        let h = lines.len() as u16;
        let rect = Rect {
            y,
            height: h.min(r.bottom().saturating_sub(y)),
            ..r
        };
        let style = if i == sel {
            Style::new().bg(t.sel_bg)
        } else {
            Style::new()
        };
        f.render_widget(Paragraph::new(lines).style(style), rect);
        y += h + 1;
        if y >= r.bottom() {
            break;
        }
    }
    if infos.is_empty() {
        f.render_widget(Paragraph::new(empty.to_string()).style(t.dim()), r);
    }

    // Right: last result + card for the selected workflow.
    let block = panel(t, "Last result", "");
    let r = inner(&block, right);
    f.render_widget(block, right);
    let Some(info) = infos.get(sel) else { return };
    let chain = info
        .entry
        .wf
        .as_ref()
        .map(|w| {
            w.steps
                .iter()
                .filter(|s| !s.rollback)
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>()
                .join(" → ")
        })
        .unwrap_or_default();
    let file = info
        .entry
        .path
        .file_name()
        .map_or(String::new(), |n| n.to_string_lossy().into_owned());
    let blocked = info.entry.blocked();
    let mut body = vec![Line::styled(chain, t.fg())];
    if let Some(why) = &blocked {
        body.push(Line::styled(why.clone(), t.s(t.yellow)));
    }
    let cw = r.width.saturating_sub(4).max(1) as usize;
    let rows: usize = body.iter().map(|l| l.width().max(1).div_ceil(cw)).sum();
    let card_h = (rows as u16 + 4).min(r.height.saturating_sub(4));
    let [log, card] = Layout::vertical([Constraint::Fill(1), Constraint::Length(card_h)]).areas(r);
    let mut lines = vec![
        Line::styled("No workflow in progress.", t.dim()),
        Line::raw(""),
    ];
    match info.last {
        Some((st, ts, d, n)) => {
            lines.push(Line::styled(
                format!("last run  {}  {}", info.entry.name, when(ts)),
                t.fg(),
            ));
            lines.push(Line::styled(
                format!("          {d}/{n} steps · {st:?}").to_lowercase(),
                t.dim(),
            ));
        }
        None => lines.push(Line::styled(
            format!("{} has never run.", info.entry.name),
            t.dim(),
        )),
    }
    lines.extend(notes(info, r.width as usize).right);
    f.render_widget(Paragraph::new(lines), log);
    let lint = match blocked {
        None => Span::styled("lint ✓", t.s(t.green)),
        Some(_) => Span::styled("can't start", t.s(t.yellow)),
    };
    gate_card(
        f,
        card,
        t.dim,
        Line::styled(file, t.dim()),
        body,
        Line::from(vec![
            Span::styled("[Enter] start   [e] edit   ", t.dim()),
            lint,
        ]),
    );
}

/// A bordered card: a head line, its body, and the keys at the bottom.
pub fn gate_card(f: &mut Frame, area: Rect, color: Color, head: Line, body: Vec<Line>, sub: Line) {
    if area.height < 3 {
        return;
    }
    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(color));
    let r = block.inner(area);
    let r = Rect {
        x: r.x + 1,
        width: r.width.saturating_sub(2),
        ..r
    };
    f.render_widget(block, area);
    let mut lines = vec![head];
    lines.extend(body);
    let sub = key_rows(&sub, r.width.max(1) as usize);
    let [b, s] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(sub.len() as u16)]).areas(r);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), b);
    f.render_widget(Paragraph::new(sub), s);
}

/// The card's key line, broken between keys (`[r] retry   [d] …`) so none is cut off.
pub fn key_rows(sub: &Line, width: usize) -> Vec<Line<'static>> {
    let style = sub
        .spans
        .first()
        .map_or(sub.style, |s| sub.style.patch(s.style));
    let text: String = sub.spans.iter().map(|s| s.content.as_ref()).collect();
    let mut rows: Vec<String> = Vec::new();
    for part in text.split("   ").filter(|p| !p.is_empty()) {
        match rows.last_mut() {
            Some(row) if row.chars().count() + 3 + part.chars().count() <= width => {
                row.push_str("   ");
                row.push_str(part);
            }
            _ => rows.push(part.to_string()),
        }
    }
    if rows.is_empty() {
        rows.push(String::new());
    }
    rows.into_iter().map(|r| Line::styled(r, style)).collect()
}

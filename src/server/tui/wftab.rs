//! The Workflows tab: the list when nothing runs; steps, log and the current step's card while
//! a run is in progress.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Wrap};

use crate::server::workflow::{LogKind, Session};
use crate::tui::theme::Theme;
use crate::tui::widgets::{self, TableSpec, inner, panel, trunc};
use crate::workflows::Entry;
use crate::workflows::runner::{Next, preview};
use crate::workflows::state::StepStatus;

pub fn draw_list(f: &mut Frame, area: Rect, t: &Theme, dir: &str, entries: &[Entry], cur: usize) {
    let b = panel(t, "Workflows", dir);
    let r = inner(&b, area);
    f.render_widget(b, area);
    let rows: Vec<Row> = entries
        .iter()
        .map(|e| {
            let (state, c) = match e.blocked() {
                None => ("ready".to_string(), t.green),
                Some(why) => (why, t.yellow),
            };
            let (steps, desc) = match &e.wf {
                Ok(w) => (w.steps.len().to_string(), w.description.clone()),
                Err(_) => ("-".into(), String::new()),
            };
            Row::new(vec![
                Cell::from(e.name.clone()).style(t.fg()),
                Cell::from(steps).style(t.dim()),
                Cell::from(state).style(t.s(c)),
                Cell::from(desc).style(t.dim()),
            ])
        })
        .collect();
    widgets::table(
        f,
        r,
        t,
        TableSpec {
            header: vec!["Workflow", "Steps", "State", "What it does"],
            widths: vec![
                Constraint::Length(20),
                Constraint::Length(6),
                Constraint::Length(24),
                Constraint::Fill(1),
            ],
            rows,
            selected: Some(cur),
        },
    );
}

pub fn draw_session(f: &mut Frame, area: Rect, t: &Theme, s: &Session) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(38), Constraint::Percentage(62)]).areas(area);
    let n = s.wf.steps.len();
    let b = panel(
        t,
        &s.wf.name,
        format!("{} · {}", s.state_word(), s.run.state.done_count()),
    );
    let r = inner(&b, left);
    f.render_widget(b, left);
    let cur = s.next.idx();
    let lines: Vec<Line> =
        s.wf.steps
            .iter()
            .enumerate()
            .map(|(i, step)| {
                let st = &s.run.state.steps[i];
                let (icon, c) = match st.status {
                    StepStatus::Ok => ("✓", t.green),
                    StepStatus::Skipped => ("–", t.dim),
                    StepStatus::Failed => ("✗", t.red),
                    StepStatus::Running => ("▶", t.yellow),
                    StepStatus::Pending if Some(i) == cur => ("▶", t.yellow),
                    StepStatus::Pending => ("○", t.dim),
                };
                let style = if Some(i) == cur {
                    ratatui::style::Style::new().bg(t.sel_bg)
                } else {
                    ratatui::style::Style::new()
                };
                Line::from(vec![
                    Span::styled(format!("{icon} {:>2} ", i + 1), t.s(c)),
                    Span::styled(
                        trunc(&s.title(i), r.width.saturating_sub(14) as usize),
                        if st.status == StepStatus::Skipped {
                            t.dim()
                        } else {
                            t.fg()
                        },
                    ),
                    Span::styled(format!("  {}", step.tag()), t.dim()),
                ])
                .style(style)
            })
            .collect();
    f.render_widget(Paragraph::new(lines), r);

    let card = card(t, s);
    let card_h = (card.len() as u16 + 2).min(right.height / 2);
    let [log_a, card_a] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(card_h)]).areas(right);
    let b = panel(
        t,
        "Log",
        cur.map_or(String::new(), |i| {
            format!("step {}/{n} · steps/{}.log", i + 1, s.wf.steps[i].id)
        }),
    );
    let r = inner(&b, log_a);
    f.render_widget(b, log_a);
    let h = r.height as usize;
    let shown: Vec<Line> = s
        .log
        .iter()
        .skip(s.log.len().saturating_sub(h))
        .map(|(l, k)| {
            let c = match k {
                LogKind::Info => t.cyan,
                LogKind::Cmd => t.dim,
                LogKind::Out => t.fg,
                LogKind::Ok => t.green,
                LogKind::Err => t.red,
            };
            Line::styled(trunc(l, r.width as usize), t.s(c))
        })
        .collect();
    f.render_widget(Paragraph::new(shown), r);
    let color = match s.next {
        Next::Stopped(_) | Next::Manual { failed: true, .. } => t.red,
        Next::Reboot { .. } => t.mag,
        Next::Done => t.green,
        _ => t.yellow,
    };
    let block = ratatui::widgets::Block::new()
        .borders(ratatui::widgets::Borders::ALL)
        .border_style(t.s(color));
    let r = block.inner(card_a);
    f.render_widget(block, card_a);
    f.render_widget(Paragraph::new(card).wrap(Wrap { trim: false }), r);
}

fn card(t: &Theme, s: &Session) -> Vec<Line<'static>> {
    let Some(i) = s.next.idx() else {
        return vec![
            Line::styled(
                format!("✓ {} {}", s.wf.name, if s.done() { "finished" } else { "" }),
                t.s(t.green),
            ),
            Line::styled("[Enter] close", t.dim()),
        ];
    };
    let step = &s.wf.steps[i];
    let title = s.title(i);
    let cmd = step
        .run
        .as_deref()
        .map(|r| format!("$ {}", preview(&s.run.state, r)));
    let manual = step
        .manual
        .as_deref()
        .map(|m| preview(&s.run.state, m))
        .unwrap_or_default();
    let mut out = Vec::new();
    match s.next {
        Next::Run(_) | Next::Confirm(_) => {
            out.push(Line::styled(
                format!("▶ {title} · {}", step.tag()),
                t.s(t.yellow),
            ));
            out.extend(cmd.map(|c| Line::styled(c, t.fg())));
            out.push(Line::styled(
                format!(
                    "[Enter] run{}   [L] log   [a] abandon",
                    if step.optional {
                        "   [s] skip"
                    } else {
                        "   [s] skip (asks)"
                    }
                ),
                t.dim(),
            ));
        }
        Next::Reboot { requested, .. } => {
            out.push(Line::styled(format!("↻ {title}"), t.s(t.mag)));
            out.push(Line::styled(
                if requested {
                    "Waiting for the server to come back (its boot id changes)…"
                } else {
                    "sudo systemctl reboot on the server; sentry-server waits for it here."
                },
                t.fg(),
            ));
            out.push(Line::styled(
                if requested {
                    "[d] it's back, mark done   [a] abandon"
                } else {
                    "[Enter] reboot now   [s] skip (asks)   [a] abandon"
                },
                t.dim(),
            ));
        }
        Next::Manual { failed: false, .. } => {
            out.push(Line::styled(format!("✋ {title} · manual"), t.s(t.yellow)));
            out.extend(manual.lines().map(|l| Line::styled(l.to_string(), t.fg())));
            out.push(Line::styled("[Enter] done   [a] abandon", t.dim()));
        }
        Next::Manual { failed: true, .. } | Next::Stopped(_) => {
            let code = s.run.state.steps[i]
                .code
                .map_or("?".into(), |c| c.to_string());
            out.push(Line::styled(
                format!("✗ {title} · failed (exit {code})"),
                t.s(t.red),
            ));
            if let Some(note) = &s.run.state.steps[i].note {
                out.push(Line::styled(note.clone(), t.dim()));
            }
            out.extend(manual.lines().map(|l| Line::styled(l.to_string(), t.fg())));
            out.push(Line::styled(
                "[r] retry   [d] done by hand   [s] skip   [L] log   [a] abandon",
                t.dim(),
            ));
        }
        Next::Shell(_) | Next::Done => {}
    }
    if let Some(e) = &s.error {
        out.push(Line::styled(e.clone(), t.s(t.red)));
    }
    out
}

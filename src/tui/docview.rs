//! Records shown as documents, in both programs: the maintenance log (its ledger as a list,
//! an entry as a document) and the Markdown that plans, reviews and entries are written in.

use ratatui::Frame;
use ratatui::crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Wrap};

use crate::maint::log::LogEntry;
use crate::tui::theme::Theme;

/// Enough Markdown for a plan: headings, bullets, code blocks, **bold**.
pub fn markdown(t: &Theme, text: &str) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let mut code = false;
    for raw in text.lines() {
        let l = raw.trim_end();
        if l.trim_start().starts_with("```") {
            code = !code;
            continue;
        }
        if code {
            out.push(Line::from(vec![
                Span::styled("   │ ", t.s(t.border)),
                Span::styled(l.to_string(), t.s(t.cyan)),
            ]));
            continue;
        }
        let plain = l.replace("**", "");
        if let Some(h) = plain.strip_prefix("# ") {
            out.push(Line::styled(
                format!(" {h}"),
                Style::new().fg(t.fg).add_modifier(Modifier::BOLD),
            ));
        } else if let Some(h) = plain
            .strip_prefix("## ")
            .or_else(|| plain.strip_prefix("### "))
        {
            out.push(Line::raw(""));
            out.push(Line::styled(
                format!(" {h}"),
                Style::new().fg(t.mag).add_modifier(Modifier::BOLD),
            ));
        } else {
            out.push(Line::styled(format!(" {plain}"), t.fg()));
        }
    }
    out
}

/// The Log view: the maintenance ledger as a list, or one entry as a document.
pub struct LogView {
    pub entries: Vec<LogEntry>,
    pub cur: usize,
    /// An entry open, scrolled this far from the top.
    pub open: Option<usize>,
    /// The item selected when it was opened (its entries are marked).
    pub item: Option<String>,
}

impl LogView {
    /// Start on the item's newest entry when there is one.
    pub fn new(entries: Vec<LogEntry>, item: Option<String>) -> Self {
        let cur = item
            .as_ref()
            .and_then(|i| entries.iter().position(|e| e.head.item.as_ref() == Some(i)))
            .unwrap_or(0);
        Self {
            entries,
            cur,
            open: None,
            item,
        }
    }

    /// j/k pick a run, Enter opens it, Esc goes back a level. False: close the view.
    pub fn key(&mut self, code: KeyCode) -> bool {
        let n = self.entries.len();
        match (&mut self.open, code) {
            (Some(_), KeyCode::Esc | KeyCode::Char('q') | KeyCode::Backspace) => self.open = None,
            (Some(s), KeyCode::Down | KeyCode::Char('j')) => *s += 1,
            (Some(s), KeyCode::Up | KeyCode::Char('k')) => *s = s.saturating_sub(1),
            (Some(s), KeyCode::PageDown | KeyCode::Char(' ')) => *s += 20,
            (Some(s), KeyCode::PageUp) => *s = s.saturating_sub(20),
            (Some(s), KeyCode::Home | KeyCode::Char('g')) => *s = 0,
            (Some(s), KeyCode::End | KeyCode::Char('G')) => *s = usize::MAX / 2,
            (Some(_), _) => {}
            (None, KeyCode::Esc | KeyCode::Char('q')) => return false,
            (None, KeyCode::Down | KeyCode::Char('j')) => {
                self.cur = (self.cur + 1).min(n.saturating_sub(1))
            }
            (None, KeyCode::Up | KeyCode::Char('k')) => self.cur = self.cur.saturating_sub(1),
            (None, KeyCode::Home | KeyCode::Char('g')) => self.cur = 0,
            (None, KeyCode::End | KeyCode::Char('G')) => self.cur = n.saturating_sub(1),
            (None, KeyCode::Enter) if n > 0 => self.open = Some(0),
            _ => {}
        }
        true
    }
}

pub fn draw_log(f: &mut Frame, area: Rect, t: &Theme, lv: &LogView, dir: &str) {
    use ratatui::widgets::{Cell, Row};
    f.render_widget(Clear, area);
    let [head, rule, body] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);
    let title = Span::styled(
        " Maintenance log ",
        Style::new()
            .fg(t.ink)
            .bg(t.cyan)
            .add_modifier(Modifier::BOLD),
    );
    let rule_line = || Paragraph::new("─".repeat(rule.width as usize)).style(t.s(t.border));
    if let (Some(scroll), Some(e)) = (lv.open, lv.entries.get(lv.cur)) {
        let h = &e.head;
        let mut l1 = vec![title, Span::styled(format!("  {}", e.file_name()), t.fg())];
        if !h.tags.is_empty() {
            l1.push(Span::styled(format!("  · {}", h.tags.join(" ")), t.dim()));
        }
        let l2 = Line::styled(
            format!(
                " {}{}",
                h.ended
                    .or(h.started)
                    .map_or(String::new(), |t| t.strftime("%Y-%m-%d %H:%M").to_string()),
                h.duration_s.map_or(String::new(), |d| format!(
                    " · took {}m{:02}s",
                    d / 60,
                    d % 60
                ))
            ),
            t.dim(),
        );
        f.render_widget(Paragraph::new(vec![Line::from(l1), l2]), head);
        f.render_widget(rule_line(), rule);
        let lines = markdown(t, &e.body);
        let top = scroll.min(lines.len().saturating_sub(body.height as usize));
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .scroll((top as u16, 0)),
            body,
        );
        return;
    }
    f.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                title,
                Span::styled(format!("  {} run(s)", lv.entries.len()), t.fg()),
            ]),
            Line::styled(format!(" {dir}/LOG.md"), t.dim()),
        ]),
        head,
    );
    f.render_widget(rule_line(), rule);
    if lv.entries.is_empty() {
        f.render_widget(
            Paragraph::new(Line::styled(
                "  Nothing logged yet: every workflow run is written here when it ends.",
                t.dim(),
            )),
            body,
        );
        return;
    }
    let rows: Vec<Row> = lv
        .entries
        .iter()
        .map(|e| {
            let h = &e.head;
            let mine = lv.item.is_some() && h.item == lv.item;
            let change = match (&h.from, &h.to) {
                (Some(a), Some(b)) => format!("{a} → {b}"),
                _ if h.kind == "retire" => "retired".into(),
                _ => String::new(),
            };
            let rc = match h.result.as_str() {
                "done" if h.failed.is_empty() && h.by_hand.is_empty() => t.green,
                "done" => t.yellow,
                _ => t.red,
            };
            Row::new(vec![
                Cell::from(if mine { "●" } else { " " }).style(t.s(t.mag)),
                Cell::from(
                    h.ended
                        .or(h.started)
                        .map_or("?".into(), |t| t.strftime("%Y-%m-%d %H:%M").to_string()),
                )
                .style(t.dim()),
                Cell::from(h.item.clone().unwrap_or_else(|| "-".into())).style(t.fg()),
                Cell::from(change).style(t.fg()),
                Cell::from(h.workflow.clone()).style(t.dim()),
                Cell::from(h.result.clone()).style(t.s(rc)),
                Cell::from(h.summary.clone()).style(t.fg()),
            ])
        })
        .collect();
    crate::tui::widgets::table(
        f,
        body,
        t,
        crate::tui::widgets::TableSpec {
            header: vec![
                "", "When", "Item", "Change", "Workflow", "Result", "Summary",
            ],
            widths: vec![
                Constraint::Length(1),
                Constraint::Length(16),
                Constraint::Length(14),
                Constraint::Length(26),
                Constraint::Length(16),
                Constraint::Length(9),
                Constraint::Fill(1),
            ],
            rows,
            selected: Some(lv.cur),
        },
    );
}

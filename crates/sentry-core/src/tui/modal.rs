//! A centred confirm/info box, shared by both TUIs. `E` is what confirming does (each app's
//! own effect type).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use super::theme::Theme;
use super::widgets::{self, chip};

#[derive(Clone, Debug)]
pub struct Modal<E> {
    pub title: String,
    pub color: Color,
    pub lines: Vec<Line<'static>>,
    /// Confirm label and what it does; `None` = informational (Enter/Esc close).
    pub yes: Option<(String, Vec<E>)>,
}

pub fn draw<E>(f: &mut Frame, area: Rect, t: &Theme, m: &Modal<E>) {
    let w = 84u16.min(area.width);
    // Inner text width = box − borders − padding; count wrapped rows so nothing is clipped.
    let text_w = w.saturating_sub(4).max(1) as usize;
    let rows: usize = m
        .lines
        .iter()
        .map(|l| l.width().max(1).div_ceil(text_w))
        .sum();
    let rect = widgets::centered(area, w, rows as u16 + 5);
    let inner = widgets::overlay(f, rect, t, &m.title, m.color);
    let [body, _, keys] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    let body = Rect {
        y: body.y + 1,
        height: body.height.saturating_sub(1),
        ..body
    };
    f.render_widget(
        Paragraph::new(m.lines.clone()).wrap(Wrap { trim: false }),
        body,
    );
    let mut spans = Vec::new();
    match &m.yes {
        Some((label, _)) => {
            spans.extend(chip(t, "y", label, m.color));
            spans.push(Span::raw("   "));
            spans.extend(chip(t, "n", "cancel", t.dim));
        }
        None => spans.extend(chip(t, "Enter", "close", m.color)),
    }
    f.render_widget(Paragraph::new(Line::from(spans)), keys);
}

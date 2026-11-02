//! Drawing helpers that reproduce the mockup's primitives: titled panels, block bars,
//! eighth-block graphs, key chips, tables with a selection row, centered modals.

use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table, TableState,
};

use super::theme::Theme;

/// Bordered panel with a mockup-style title: name in fg, detail in dim.
pub fn panel<'a>(t: &Theme, name: &'a str, detail: impl Into<String>) -> Block<'a> {
    let detail = detail.into();
    let mut spans = vec![Span::styled(format!(" {name} "), t.fg())];
    if !detail.is_empty() {
        spans.pop();
        spans.push(Span::styled(format!(" {name}"), t.fg()));
        spans.push(Span::styled(format!(" · {detail} "), t.dim()));
    }
    Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(t.s(t.border))
        .title(Line::from(spans))
}

/// Inner area of a panel with one column of horizontal padding.
pub fn inner(block: &Block, area: Rect) -> Rect {
    let r = block.inner(area);
    Rect {
        x: r.x + 1,
        width: r.width.saturating_sub(2),
        ..r
    }
}

/// `████░░░░` spans for a percentage over `width` cells.
pub fn bar(t: &Theme, pct: f64, width: u16, color: Color) -> Vec<Span<'static>> {
    let w = width as usize;
    let n = ((pct.clamp(0.0, 100.0) / 100.0) * w as f64).round() as usize;
    vec![
        Span::styled("█".repeat(n.min(w)), t.s(color)),
        Span::styled("░".repeat(w - n.min(w)), t.s(t.track)),
    ]
}

const EIGHTHS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Port of the mockup's `graph(arr, max, rows)`: an N-row eighth-block plot of the last
/// `area.width` samples, right-aligned so the newest sample is at the right edge.
pub fn graph(buf: &mut Buffer, area: Rect, data: &[f64], max: f64, color: Color) {
    if area.width == 0 || area.height == 0 || max <= 0.0 {
        return;
    }
    let rows = area.height as i64;
    let w = area.width as usize;
    let start = data.len().saturating_sub(w);
    let slice = &data[start..];
    let x0 = area.x + (w - slice.len()) as u16;
    for (i, v) in slice.iter().enumerate() {
        let level = ((v / max).clamp(0.0, 1.0) * (rows * 8) as f64).round() as i64;
        for r in 0..rows {
            // r = 0 is the bottom row.
            let lv = level - r * 8;
            let ch = if lv <= 0 {
                continue;
            } else if lv >= 8 {
                '█'
            } else {
                EIGHTHS[(lv - 1) as usize]
            };
            let y = area.y + (rows - 1 - r) as u16;
            buf[(x0 + i as u16, y)].set_char(ch).set_fg(color);
        }
    }
}

/// `[k] desc` chip pair for the key bar and modals.
pub fn chip(t: &Theme, key: &str, desc: &str, bg: Color) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!(" {key} "), t.chip(bg)),
        Span::styled(format!(" {desc}"), t.s(t.hint)),
    ]
}

/// Truncate to `w` display cells with an ellipsis.
pub fn trunc(s: &str, w: usize) -> String {
    if s.chars().count() <= w {
        s.to_string()
    } else if w == 0 {
        String::new()
    } else {
        let mut o: String = s.chars().take(w - 1).collect();
        o.push('…');
        o
    }
}

/// A table with a dim header, mockup selection background and scroll-to-selection.
pub struct TableSpec<'a> {
    pub header: Vec<&'a str>,
    pub widths: Vec<Constraint>,
    pub rows: Vec<Row<'a>>,
    pub selected: Option<usize>,
}

pub fn table(f: &mut Frame, area: Rect, t: &Theme, spec: TableSpec) {
    let header = Row::new(
        spec.header
            .into_iter()
            .map(|h| Cell::from(h).style(t.dim())),
    )
    .style(
        Style::new()
            .add_modifier(Modifier::UNDERLINED)
            .underline_color(t.rule),
    );
    let table = Table::new(spec.rows, spec.widths)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::new().bg(t.sel_bg));
    let mut st = TableState::default().with_selected(spec.selected);
    f.render_stateful_widget(table, area, &mut st);
}

/// Centered rect of at most `w`×`h` inside `area`.
pub fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

/// Dim everything already drawn in `area` (modal backdrop).
pub fn dim_backdrop(buf: &mut Buffer, area: Rect) {
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let c = &mut buf[(x, y)];
            c.modifier.insert(Modifier::DIM);
        }
    }
}

/// Bordered overlay box; returns its inner (padded) area.
pub fn overlay(f: &mut Frame, rect: Rect, t: &Theme, title: &str, color: Color) -> Rect {
    f.render_widget(Clear, rect);
    let b = Block::new()
        .borders(Borders::ALL)
        .border_style(t.s(color))
        .title(Span::styled(format!(" {title} "), t.s(color)));
    let inner = inner(&b, rect);
    f.render_widget(b, rect);
    inner
}

/// Centered dim message for empty states and placeholders.
pub fn placeholder(f: &mut Frame, area: Rect, t: &Theme, lines: &[(&str, Style)]) {
    let h = lines.len() as u16;
    let r = Rect {
        y: area.y + area.height.saturating_sub(h) / 2,
        height: h.min(area.height),
        ..area
    };
    let text: Vec<Line> = lines
        .iter()
        .map(|(s, st)| Line::styled(s.to_string(), *st).centered())
        .collect();
    let _ = t;
    f.render_widget(Paragraph::new(text), r);
}

/// Greedy word wrap for descriptions.
pub fn wrap(s: &str, w: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in s.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > w {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

/// A path with the home directory written `~`.
pub fn short_home(p: &std::path::Path) -> String {
    let h = crate::paths::home();
    match p.strip_prefix(&h) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => p.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_matches_mockup_levels() {
        let area = Rect::new(0, 0, 3, 2);
        let mut buf = Buffer::empty(area);
        graph(&mut buf, area, &[0.0, 50.0, 100.0], 100.0, Color::Cyan);
        let row = |y| {
            (0..3)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect::<String>()
        };
        assert_eq!(row(1), " ██");
        assert_eq!(row(0), "  █");
    }

    #[test]
    fn truncation() {
        assert_eq!(trunc("abcdef", 4), "abc…");
        assert_eq!(trunc("abc", 4), "abc");
    }
}

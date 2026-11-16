//! A centred confirm/info box, shared by both TUIs. `E` is what confirming does (each app's
//! own effect type).

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
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
            spans.extend(chip(t, "Enter", label, m.color));
            spans.push(Span::raw("   "));
            spans.extend(chip(t, "Esc", "cancel", t.dim));
        }
        None => spans.extend(chip(t, "Enter", "close", m.color)),
    }
    f.render_widget(Paragraph::new(Line::from(spans)), keys);
}

/// What a key says to a box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Yes,
    /// Close it (cancel, or an info box read).
    No,
    Stay,
}

/// Enter or `y` confirm; Esc, `n` or `q` cancel. A box with nothing to confirm closes on any
/// of them.
pub fn answer(k: &KeyEvent, has_yes: bool) -> Answer {
    match k.code {
        KeyCode::Char('y') | KeyCode::Enter if has_yes => Answer::Yes,
        KeyCode::Char('y' | 'n' | 'q') | KeyCode::Enter | KeyCode::Esc => Answer::No,
        _ => Answer::Stay,
    }
}

/// A numbered choice between actions.
#[derive(Clone, Debug)]
pub struct Choice<E> {
    pub title: String,
    pub lines: Vec<Line<'static>>,
    pub options: Vec<(String, Vec<E>)>,
}

impl<E> Choice<E> {
    /// One line per option, numbered: `1  label`.
    pub fn numbered(t: &Theme, title: &str, options: Vec<(String, Vec<E>)>) -> Self {
        let n = options.len().min(9);
        Self {
            title: format!("{title} · pick one (1–{n}, n cancels)"),
            lines: options
                .iter()
                .take(9)
                .enumerate()
                .map(|(i, (label, _))| Line::styled(format!("{}  {label}", i + 1), t.fg()))
                .collect(),
            options,
        }
    }
}

pub fn draw_choice<E>(f: &mut Frame, area: Rect, t: &Theme, c: &Choice<E>) {
    let m: Modal<E> = Modal {
        title: c.title.clone(),
        color: t.yellow,
        lines: c.lines.clone(),
        yes: None,
    };
    draw(f, area, t, &m);
}

/// What a key says to a choice of `n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    Option(usize),
    Close,
    Stay,
}

/// 1–9 pick; Esc, `n`, `q` or Enter close.
pub fn pick(k: &KeyEvent, n: usize) -> Pick {
    match k.code {
        KeyCode::Char(d @ '1'..='9') => match d as usize - '1' as usize {
            i if i < n => Pick::Option(i),
            _ => Pick::Stay,
        },
        KeyCode::Char('n' | 'q') | KeyCode::Esc | KeyCode::Enter => Pick::Close,
        _ => Pick::Stay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyModifiers;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    #[test]
    fn enter_and_y_confirm_esc_n_q_cancel() {
        for c in [KeyCode::Enter, KeyCode::Char('y')] {
            assert_eq!(answer(&key(c), true), Answer::Yes);
            // Nothing to confirm: it closes.
            assert_eq!(answer(&key(c), false), Answer::No);
        }
        for c in [KeyCode::Esc, KeyCode::Char('n'), KeyCode::Char('q')] {
            assert_eq!(answer(&key(c), true), Answer::No);
        }
        assert_eq!(answer(&key(KeyCode::Char('x')), true), Answer::Stay);
        // A choice: its digits, and the same ways out.
        assert_eq!(pick(&key(KeyCode::Char('2')), 2), Pick::Option(1));
        assert_eq!(pick(&key(KeyCode::Char('3')), 2), Pick::Stay);
        assert_eq!(pick(&key(KeyCode::Esc), 2), Pick::Close);
        assert_eq!(pick(&key(KeyCode::Char('n')), 2), Pick::Close);
        assert_eq!(pick(&key(KeyCode::Char('j')), 2), Pick::Stay);
        let c: Choice<()> = Choice::numbered(
            &Theme::truecolor(),
            "Later",
            vec![("in 7 days".into(), vec![]), ("in 30 days".into(), vec![])],
        );
        assert_eq!(c.title, "Later · pick one (1–2, n cancels)");
        assert_eq!(c.lines[1].to_string(), "2  in 30 days");
    }
}

//! A tick-list: rows you tick (`[x]`), under headings, one cursor. Target-agnostic, like the
//! form: the Config area uses it for the hosts it may look at, for what discovery proposes
//! to watch, and for the routine upkeep it would schedule. The list holds what is shown;
//! every key comes back as an [`Fx`] for its owner.
//!
//! Keys: `j`/`k` move (headings are stepped over); Space ticks; `a` ticks every row in view,
//! or unticks them when all are; `/` filters by text (Enter keeps the filter, Esc drops it);
//! Enter and Esc are the owner's ([`Fx::Enter`], [`Fx::Leave`]).

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use super::frame::Hints;
use super::lineedit::{Edited, LineEdit};
use super::theme::Theme;
use super::widgets;

/// What a row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// It can be ticked.
    Tick,
    /// A heading over the rows after it.
    Head,
    /// A line to read: the cursor rests on it, Space does nothing.
    Info,
}

/// How a row's state is coloured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Plain,
    Good,
    Busy,
    Bad,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// What it is to its owner.
    pub key: String,
    pub text: String,
    /// A few words after the text, dim.
    pub note: String,
    /// What the detail panel says of it.
    pub detail: String,
    pub ticked: bool,
    pub kind: Kind,
    /// Where it stands (`reading…`, `drafted as a server`), after the note.
    pub state: Option<(String, Tone)>,
}

impl Row {
    pub fn tick(key: &str, text: &str, ticked: bool) -> Self {
        Self {
            key: key.to_string(),
            text: text.to_string(),
            note: String::new(),
            detail: String::new(),
            ticked,
            kind: Kind::Tick,
            state: None,
        }
    }

    pub fn head(text: &str) -> Self {
        Self {
            kind: Kind::Head,
            ..Self::tick("", text, false)
        }
    }

    pub fn info(key: &str, text: &str) -> Self {
        Self {
            kind: Kind::Info,
            ..Self::tick(key, text, false)
        }
    }

    pub fn note(mut self, note: &str) -> Self {
        self.note = note.to_string();
        self
    }

    pub fn detail(mut self, detail: &str) -> Self {
        self.detail = detail.to_string();
        self
    }

    pub fn state(mut self, text: &str, tone: Tone) -> Self {
        self.state = Some((text.to_string(), tone));
        self
    }
}

/// What a key came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fx {
    None,
    /// These rows' ticks changed (the list already shows it).
    Toggled(Vec<String>),
    /// Enter: the owner goes on with what is ticked.
    Enter,
    /// Esc with no filter: the list is left.
    Leave,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickList {
    pub title: String,
    pub rows: Vec<Row>,
    /// The row the cursor is on (an index into `rows`).
    pub cur: usize,
    /// The filter being typed.
    typing: Option<LineEdit>,
    /// The filter in force.
    query: String,
}

impl TickList {
    pub fn new(title: &str, rows: Vec<Row>) -> Self {
        let mut l = Self {
            title: title.to_string(),
            rows,
            cur: 0,
            typing: None,
            query: String::new(),
        };
        l.settle();
        l
    }

    /// Newer rows in the same list: the cursor stays on its row (by key), else where it was.
    pub fn set_rows(&mut self, rows: Vec<Row>) {
        let key = self
            .selected()
            .map(|r| r.key.clone())
            .filter(|k| !k.is_empty());
        self.rows = rows;
        if let Some(i) = key.and_then(|k| self.rows.iter().position(|r| r.key == k)) {
            self.cur = i;
        }
        self.settle();
    }

    /// The rows in view (the filter's), as indices into `rows`. A heading is in view when a
    /// row under it is.
    fn shown(&self) -> Vec<usize> {
        let q = self.query.to_lowercase();
        if q.is_empty() {
            return (0..self.rows.len()).collect();
        }
        let hit = |r: &Row| {
            r.kind != Kind::Head
                && (r.text.to_lowercase().contains(&q) || r.note.to_lowercase().contains(&q))
        };
        let mut out = Vec::new();
        let mut head: Option<usize> = None;
        for (i, r) in self.rows.iter().enumerate() {
            if r.kind == Kind::Head {
                head = Some(i);
            } else if hit(r) {
                out.extend(head.take());
                out.push(i);
            }
        }
        out
    }

    /// The cursor on a row that is in view and isn't a heading.
    fn settle(&mut self) {
        let rows: Vec<usize> = self
            .shown()
            .into_iter()
            .filter(|i| self.rows[*i].kind != Kind::Head)
            .collect();
        if rows.contains(&self.cur) {
            return;
        }
        self.cur = rows
            .iter()
            .copied()
            .find(|i| *i >= self.cur)
            .or(rows.last().copied())
            .unwrap_or(0);
    }

    fn step(&mut self, down: bool) {
        let rows: Vec<usize> = self
            .shown()
            .into_iter()
            .filter(|i| self.rows[*i].kind != Kind::Head)
            .collect();
        let Some(at) = rows.iter().position(|i| *i == self.cur) else {
            return self.settle();
        };
        let to = match down {
            true => (at + 1).min(rows.len() - 1),
            false => at.saturating_sub(1),
        };
        self.cur = rows[to];
    }

    pub fn selected(&self) -> Option<&Row> {
        self.rows.get(self.cur).filter(|r| r.kind != Kind::Head)
    }

    /// The rows that are ticked.
    pub fn ticked(&self) -> Vec<&Row> {
        self.rows
            .iter()
            .filter(|r| r.kind == Kind::Tick && r.ticked)
            .collect()
    }

    /// The filter is being typed: every character is text.
    pub fn typing(&self) -> bool {
        self.typing.is_some()
    }

    pub fn paste(&mut self, text: &str) {
        if let Some(l) = self.typing.as_mut() {
            l.paste(text);
            self.query = l.text();
            self.settle();
        }
    }

    pub fn key(&mut self, k: &KeyEvent) -> Fx {
        if let Some(mut line) = self.typing.take() {
            match line.key(k) {
                Edited::Submit => {}
                Edited::Cancel => self.query.clear(),
                _ => {
                    self.query = line.text();
                    self.typing = Some(line);
                }
            }
            self.settle();
            return Fx::None;
        }
        if k.modifiers.contains(KeyModifiers::CONTROL) {
            return Fx::None;
        }
        match k.code {
            KeyCode::Down | KeyCode::Char('j') => self.step(true),
            KeyCode::Up | KeyCode::Char('k') => self.step(false),
            KeyCode::Home => {
                self.cur = 0;
                self.settle();
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.cur = self.rows.len().saturating_sub(1);
                self.settle();
            }
            KeyCode::Char(' ') => {
                if let Some(r) = self.rows.get_mut(self.cur).filter(|r| r.kind == Kind::Tick) {
                    r.ticked = !r.ticked;
                    return Fx::Toggled(vec![r.key.clone()]);
                }
            }
            KeyCode::Char('a') => {
                let rows: Vec<usize> = self
                    .shown()
                    .into_iter()
                    .filter(|i| self.rows[*i].kind == Kind::Tick)
                    .collect();
                let to = !rows.iter().all(|i| self.rows[*i].ticked);
                let mut keys = Vec::new();
                for i in rows {
                    if self.rows[i].ticked != to {
                        self.rows[i].ticked = to;
                        keys.push(self.rows[i].key.clone());
                    }
                }
                if !keys.is_empty() {
                    return Fx::Toggled(keys);
                }
            }
            KeyCode::Char('/') => self.typing = Some(LineEdit::new(&self.query)),
            KeyCode::Enter => return Fx::Enter,
            KeyCode::Esc if !self.query.is_empty() => {
                self.query.clear();
                self.settle();
            }
            KeyCode::Esc => return Fx::Leave,
            _ => {}
        }
        Fx::None
    }

    /// The keys that act now (Enter and Esc are the owner's to name).
    pub fn hints(&self) -> Hints<'static> {
        if self.typing.is_some() {
            return vec![("Enter", "keep the filter"), ("Esc", "drop it")];
        }
        let mut h = Vec::new();
        if self.rows.iter().any(|r| r.kind == Kind::Tick) {
            h.extend([("Space", "tick"), ("a", "all")]);
        }
        h.push(("/", "filter"));
        h
    }

    fn lines(&self, t: &Theme, width: usize) -> (Vec<Line<'static>>, usize) {
        let sel = Style::new().bg(t.sel_bg);
        let tone = |tone: Tone| -> Color {
            match tone {
                Tone::Plain => t.dim,
                Tone::Good => t.green,
                Tone::Busy => t.yellow,
                Tone::Bad => t.red,
            }
        };
        let mut out = Vec::new();
        let mut cursor = 0;
        for i in self.shown() {
            let r = &self.rows[i];
            let line = match r.kind {
                Kind::Head => {
                    if !out.is_empty() {
                        out.push(Line::raw(""));
                    }
                    let mut spans = vec![Span::styled(format!(" {}", r.text), t.s(t.mag))];
                    if !r.note.is_empty() {
                        spans.push(Span::styled(
                            format!(
                                "  {}",
                                widgets::trunc(
                                    &r.note,
                                    width.saturating_sub(r.text.chars().count() + 4)
                                )
                            ),
                            t.dim(),
                        ));
                    }
                    Line::from(spans)
                }
                Kind::Tick | Kind::Info => {
                    let mark = match (r.kind, r.ticked) {
                        (Kind::Info, _) => "    ",
                        (_, true) => "[x] ",
                        (_, false) => "[ ] ",
                    };
                    // The text first, whole where it fits; then where it stands, then the
                    // note, each in what room is left.
                    let room = width.saturating_sub(6);
                    let text = widgets::trunc(&r.text, room);
                    let mut left = room.saturating_sub(text.chars().count());
                    let state = r.state.as_ref().filter(|_| left > 6).map(|(s, tone)| {
                        let s = widgets::trunc(s, left - 2);
                        left -= s.chars().count() + 2;
                        (s, *tone)
                    });
                    let mut spans = vec![
                        Span::styled(
                            format!(" {mark}"),
                            if r.ticked { t.s(t.green) } else { t.dim() },
                        ),
                        Span::styled(
                            text,
                            if r.kind == Kind::Info {
                                t.dim()
                            } else {
                                t.fg()
                            },
                        ),
                    ];
                    if !r.note.is_empty() && left > 5 {
                        spans.push(Span::styled(
                            format!("  {}", widgets::trunc(&r.note, left - 2)),
                            t.dim(),
                        ));
                    }
                    if let Some((s, tn)) = state {
                        spans.push(Span::styled(format!("  {s}"), t.s(tone(tn))));
                    }
                    let l = Line::from(spans);
                    if i == self.cur {
                        cursor = out.len();
                        l.style(sel)
                    } else {
                        l
                    }
                }
            };
            out.push(line);
        }
        (out, cursor)
    }

    /// The rows in `area`, scrolled so the cursor's is in it; the filter under them while
    /// there is one.
    pub fn draw(&self, f: &mut Frame, area: Rect, t: &Theme) {
        let filter = self.typing.is_some() || !self.query.is_empty();
        let [rows, bar] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(u16::from(filter))])
                .areas(area);
        let (lines, cursor) = self.lines(t, rows.width as usize);
        if lines.is_empty() {
            widgets::placeholder(
                f,
                rows,
                t,
                &[(
                    if self.query.is_empty() {
                        "nothing here"
                    } else {
                        "nothing matches the filter"
                    },
                    t.dim(),
                )],
            );
        } else {
            let h = rows.height as usize;
            let off = cursor
                .saturating_sub(h / 2)
                .min(lines.len().saturating_sub(h));
            f.render_widget(
                Paragraph::new(lines.into_iter().skip(off).take(h).collect::<Vec<_>>()),
                rows,
            );
        }
        if filter {
            let mut spans = vec![Span::styled(" /", t.s(t.mag))];
            match &self.typing {
                Some(l) => spans.extend(l.spans(t)),
                None => spans.push(Span::styled(self.query.clone(), t.fg())),
            }
            f.render_widget(Paragraph::new(Line::from(spans)), bar);
        }
    }
}

/// A tick-list in two panels: the rows, and the selected one in words with `extra` under it
/// (the owner's lines: what Enter does, what a row's state means). Side by side where there
/// is room (100 columns), else the words under the rows.
pub fn draw_panels(f: &mut Frame, area: Rect, t: &Theme, list: &TickList, extra: &[Line<'static>]) {
    let (left, right) = if area.width >= 100 {
        let [l, r] =
            Layout::horizontal([Constraint::Percentage(55), Constraint::Fill(1)]).areas(area);
        (l, r)
    } else {
        let below = (area.height * 2 / 5).clamp(6, 14);
        let [l, r] = Layout::vertical([Constraint::Fill(1), Constraint::Length(below)]).areas(area);
        (l, r)
    };
    let ticks = list.rows.iter().filter(|r| r.kind == Kind::Tick).count();
    let block = widgets::panel(
        t,
        &list.title,
        match ticks {
            0 => String::new(),
            n => format!("{} of {n} ticked", list.ticked().len()),
        },
    );
    let inner = widgets::inner(&block, left);
    f.render_widget(block, left);
    list.draw(f, inner, t);
    let sel = list.selected();
    let block = widgets::panel(t, sel.map_or("", |r| r.text.as_str()), "");
    let inner = widgets::inner(&block, right);
    f.render_widget(block, right);
    let mut lines: Vec<Line<'static>> = Vec::new();
    if let Some(r) = sel {
        for part in r.detail.split('\n').filter(|p| !p.is_empty()) {
            lines.extend(
                widgets::wrap(part, (inner.width as usize).max(10))
                    .into_iter()
                    .map(|l| Line::styled(l, t.fg())),
            );
        }
    }
    if !extra.is_empty() {
        if !lines.is_empty() {
            lines.push(Line::raw(""));
        }
        lines.extend(extra.iter().cloned());
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::frame::render_to_string;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn list() -> TickList {
        TickList::new(
            "Hosts",
            vec![
                Row::head("From ~/.ssh/config"),
                Row::tick("myserver", "myserver", false).detail("An ssh host of yours."),
                Row::tick("other", "other", false).note("user@192.0.2.7"),
                Row::head("On this network").note("the default gateway"),
                Row::tick("192.0.2.1", "192.0.2.1", false)
                    .note("likely your router")
                    .state("reading…", Tone::Busy),
                Row::info("name", "n adds one by name"),
            ],
        )
    }

    fn ticked(l: &TickList) -> Vec<&str> {
        l.ticked().iter().map(|r| r.key.as_str()).collect()
    }

    #[test]
    fn rows_are_ticked_one_by_one_or_all_and_headings_are_stepped_over() {
        let mut l = list();
        // The cursor starts on the first row that isn't a heading.
        assert_eq!(l.selected().unwrap().key, "myserver");
        assert_eq!(
            l.key(&key(KeyCode::Char(' '))),
            Fx::Toggled(vec!["myserver".into()])
        );
        l.key(&key(KeyCode::Char('j')));
        l.key(&key(KeyCode::Char('j')));
        assert_eq!(l.selected().unwrap().key, "192.0.2.1");
        l.key(&key(KeyCode::Char('j')));
        // A line to read: the cursor rests on it, Space does nothing.
        assert_eq!(l.selected().unwrap().key, "name");
        assert_eq!(l.key(&key(KeyCode::Char(' '))), Fx::None);
        l.key(&key(KeyCode::Char('j')));
        assert_eq!(l.selected().unwrap().key, "name");
        // `a`: every row that can be ticked; again: none.
        assert_eq!(
            l.key(&key(KeyCode::Char('a'))),
            Fx::Toggled(vec!["other".into(), "192.0.2.1".into()])
        );
        assert_eq!(ticked(&l), ["myserver", "other", "192.0.2.1"]);
        l.key(&key(KeyCode::Char('a')));
        assert!(ticked(&l).is_empty());
        assert_eq!(l.key(&key(KeyCode::Enter)), Fx::Enter);
        assert_eq!(l.key(&key(KeyCode::Esc)), Fx::Leave);
    }

    #[test]
    fn a_filter_narrows_the_rows_and_a_acts_on_what_is_in_view() {
        let mut l = list();
        l.key(&key(KeyCode::Char('/')));
        assert!(l.typing());
        for c in "192".chars() {
            l.key(&key(KeyCode::Char(c)));
        }
        l.key(&key(KeyCode::Enter));
        assert!(!l.typing());
        // Its text or its note: the rows, each under its heading.
        let s = render_to_string(60, 10, |f| l.draw(f, f.area(), &Theme::truecolor()));
        assert!(s.contains("other") && s.contains("192.0.2.1"), "{s}");
        assert!(!s.contains("myserver") && s.contains("/192"), "{s}");
        l.key(&key(KeyCode::Char('a')));
        assert_eq!(ticked(&l), ["other", "192.0.2.1"]);
        // Esc drops the filter first, then leaves.
        assert_eq!(l.key(&key(KeyCode::Esc)), Fx::None);
        assert_eq!(l.key(&key(KeyCode::Esc)), Fx::Leave);
    }

    #[test]
    fn newer_rows_keep_the_cursor_on_its_row() {
        let mut l = list();
        l.key(&key(KeyCode::Char('j')));
        assert_eq!(l.selected().unwrap().key, "other");
        let mut rows = list().rows;
        rows.insert(1, Row::tick("first", "first", true));
        l.set_rows(rows);
        assert_eq!(l.selected().unwrap().key, "other");
        assert_eq!(ticked(&l), ["first"]);
    }

    #[test]
    fn it_draws_ticks_notes_states_and_the_selected_rows_words() {
        let mut l = list();
        l.key(&key(KeyCode::Char(' ')));
        let t = Theme::truecolor();
        let s = render_to_string(110, 12, |f| {
            draw_panels(
                f,
                f.area(),
                &t,
                &l,
                &[Line::raw("Enter reads what is ticked")],
            )
        });
        insta::assert_snapshot!("ticklist_panels_110", s);
    }
}

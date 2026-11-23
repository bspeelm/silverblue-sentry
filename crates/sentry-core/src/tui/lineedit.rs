//! One line being edited, with a cursor: what a form's field (and the Config area's `:` line)
//! is typed in. Insert where the cursor is, Left/Right, Home/End, Backspace/Delete, a paste
//! in one piece. (The key bar's `Input` stays as it is: append only.)

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::text::Span;

use super::theme::Theme;

/// What a key did to the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edited {
    /// The text changed.
    Changed,
    /// Only the cursor moved.
    Moved,
    /// Enter.
    Submit,
    /// Esc.
    Cancel,
    /// Not a key of the line's.
    Ignored,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineEdit {
    text: Vec<char>,
    /// Before which character the cursor is (`text.len()`: at the end).
    cur: usize,
}

impl LineEdit {
    /// A line holding `text`, the cursor at its end.
    pub fn new(text: &str) -> Self {
        let text: Vec<char> = text.chars().collect();
        Self {
            cur: text.len(),
            text,
        }
    }

    pub fn text(&self) -> String {
        self.text.iter().collect()
    }

    pub fn cursor(&self) -> usize {
        self.cur
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// A paste goes in whole where the cursor is, on one line.
    pub fn paste(&mut self, text: &str) {
        let clean = text.replace(['\r', '\n'], " ");
        for c in clean.trim_end().chars().filter(|c| !c.is_control()) {
            self.text.insert(self.cur, c);
            self.cur += 1;
        }
    }

    /// Where the word before the cursor starts.
    fn word_start(&self) -> usize {
        let mut i = self.cur;
        while i > 0 && self.text[i - 1].is_whitespace() {
            i -= 1;
        }
        while i > 0 && !self.text[i - 1].is_whitespace() {
            i -= 1;
        }
        i
    }

    pub fn key(&mut self, k: &KeyEvent) -> Edited {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Enter => Edited::Submit,
            KeyCode::Esc => Edited::Cancel,
            KeyCode::Left | KeyCode::Char('b') if k.code == KeyCode::Left || ctrl => {
                self.cur = self.cur.saturating_sub(1);
                Edited::Moved
            }
            KeyCode::Right | KeyCode::Char('f') if k.code == KeyCode::Right || ctrl => {
                self.cur = (self.cur + 1).min(self.text.len());
                Edited::Moved
            }
            KeyCode::Home => {
                self.cur = 0;
                Edited::Moved
            }
            KeyCode::Char('a') if ctrl => {
                self.cur = 0;
                Edited::Moved
            }
            KeyCode::End => {
                self.cur = self.text.len();
                Edited::Moved
            }
            KeyCode::Char('e') if ctrl => {
                self.cur = self.text.len();
                Edited::Moved
            }
            KeyCode::Backspace if self.cur > 0 => {
                self.cur -= 1;
                self.text.remove(self.cur);
                Edited::Changed
            }
            KeyCode::Delete if self.cur < self.text.len() => {
                self.text.remove(self.cur);
                Edited::Changed
            }
            KeyCode::Backspace | KeyCode::Delete => Edited::Moved,
            // The line up to the cursor goes.
            KeyCode::Char('u') if ctrl => {
                self.text.drain(..self.cur);
                self.cur = 0;
                Edited::Changed
            }
            // The word before the cursor goes.
            KeyCode::Char('w') if ctrl => {
                let from = self.word_start();
                self.text.drain(from..self.cur);
                self.cur = from;
                Edited::Changed
            }
            KeyCode::Char(c) if !ctrl => {
                self.text.insert(self.cur, c);
                self.cur += 1;
                Edited::Changed
            }
            _ => Edited::Ignored,
        }
    }

    /// The line as drawn: the text with the cursor's bar where it is.
    pub fn spans(&self, t: &Theme) -> Vec<Span<'static>> {
        let before: String = self.text[..self.cur].iter().collect();
        let after: String = self.text[self.cur..].iter().collect();
        vec![
            Span::styled(before, t.fg()),
            Span::styled("▏", t.s(t.cyan)),
            Span::styled(after, t.fg()),
        ]
    }

    /// The same as plain text (`clau▏de`).
    pub fn shown(&self) -> String {
        let before: String = self.text[..self.cur].iter().collect();
        let after: String = self.text[self.cur..].iter().collect();
        format!("{before}▏{after}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn typed(l: &mut LineEdit, s: &str) {
        for c in s.chars() {
            assert_eq!(l.key(&key(KeyCode::Char(c))), Edited::Changed);
        }
    }

    #[test]
    fn text_goes_in_where_the_cursor_is() {
        let mut l = LineEdit::new("clade");
        assert_eq!((l.text().as_str(), l.cursor()), ("clade", 5));
        for _ in 0..2 {
            assert_eq!(l.key(&key(KeyCode::Left)), Edited::Moved);
        }
        typed(&mut l, "u");
        assert_eq!(l.shown(), "clau▏de");
        // Home and End, and the ends hold.
        l.key(&key(KeyCode::Home));
        assert_eq!(l.key(&key(KeyCode::Left)), Edited::Moved);
        assert_eq!(l.cursor(), 0);
        typed(&mut l, "/opt/");
        assert_eq!(l.text(), "/opt/claude");
        l.key(&key(KeyCode::End));
        l.key(&key(KeyCode::Right));
        assert_eq!(l.cursor(), 11);
        typed(&mut l, "2");
        assert_eq!(l.shown(), "/opt/claude2▏");
    }

    #[test]
    fn backspace_and_delete_take_the_character_at_the_cursor() {
        let mut l = LineEdit::new("abcd");
        l.key(&key(KeyCode::Left));
        assert_eq!(l.key(&key(KeyCode::Backspace)), Edited::Changed);
        assert_eq!(l.shown(), "ab▏d");
        assert_eq!(l.key(&key(KeyCode::Delete)), Edited::Changed);
        assert_eq!(l.shown(), "ab▏");
        // Nothing there: nothing changes.
        assert_eq!(l.key(&key(KeyCode::Delete)), Edited::Moved);
        l.key(&key(KeyCode::Home));
        assert_eq!(l.key(&key(KeyCode::Backspace)), Edited::Moved);
        assert_eq!(l.text(), "ab");
    }

    #[test]
    fn a_paste_is_one_piece_on_one_line() {
        let mut l = LineEdit::new("ab");
        l.key(&key(KeyCode::Left));
        l.paste("x\ny\r\n");
        assert_eq!(l.shown(), "ax y▏b");
        // Letters in it never act as keys: Enter and Esc are the only ways out.
        assert_eq!(l.key(&key(KeyCode::Enter)), Edited::Submit);
        assert_eq!(l.key(&key(KeyCode::Esc)), Edited::Cancel);
        assert_eq!(l.key(&key(KeyCode::F(3))), Edited::Ignored);
        assert_eq!(l.text(), "ax yb");
    }

    #[test]
    fn the_readline_keys_work() {
        let mut l = LineEdit::new("one two  three");
        assert_eq!(l.key(&ctrl('w')), Edited::Changed);
        assert_eq!(l.shown(), "one two  ▏");
        l.key(&ctrl('w'));
        assert_eq!(l.shown(), "one ▏");
        l.key(&ctrl('a'));
        assert_eq!(l.cursor(), 0);
        l.key(&ctrl('f'));
        l.key(&ctrl('e'));
        l.key(&ctrl('b'));
        assert_eq!(l.shown(), "one▏ ");
        assert_eq!(l.key(&ctrl('u')), Edited::Changed);
        assert_eq!(l.shown(), "▏ ");
        // Wide characters count as one.
        let mut l = LineEdit::new("é→");
        l.key(&key(KeyCode::Left));
        typed(&mut l, "x");
        assert_eq!(l.text(), "éx→");
    }
}

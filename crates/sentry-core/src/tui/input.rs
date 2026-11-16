//! The one line of input in the key bar, in both programs: a `/` filter, a `:` command, or a
//! prompt for one value (`P`, each program's own).

use ratatui::crossterm::event::{KeyCode, KeyEvent};

use super::frame::KeyBar;

/// A prompt for one line: how it's labelled, and what Enter is called.
pub trait PromptLine {
    fn label(&self) -> String;
    fn enter_word(&self) -> &'static str {
        "save"
    }
    /// What was wrong with the last answer, shown in place of the hint.
    fn note(&self) -> Option<&str> {
        None
    }
}

pub enum Input<P> {
    None,
    Filter(String),
    Command(String),
    Prompt(P, String),
}

/// What a key did to the line.
#[derive(Debug, PartialEq)]
pub enum Typed<P> {
    /// Still being typed (or nothing was open).
    Editing,
    /// The filter as it is now.
    Filter(String),
    /// Esc on a filter: it's gone.
    FilterCleared,
    /// Enter (or Backspace on nothing): the filter stays as it is.
    FilterKept,
    /// Enter on a command.
    Command(String),
    /// Enter on a prompt: its answer.
    Submit(P, String),
    /// Esc: a prompt's is handed back.
    Cancelled(Option<P>),
}

impl<P: PromptLine> Input<P> {
    pub fn is_open(&self) -> bool {
        !matches!(self, Input::None)
    }

    /// A paste goes in whole, on one line.
    pub fn paste(&mut self, text: &str) {
        if let Input::Filter(s) | Input::Command(s) | Input::Prompt(_, s) = self {
            s.push_str(text.replace(['\r', '\n'], " ").trim_end());
        }
    }

    pub fn key(&mut self, k: &KeyEvent) -> Typed<P> {
        let buf = match self {
            Input::Filter(s) | Input::Command(s) | Input::Prompt(_, s) => s,
            Input::None => return Typed::Editing,
        };
        match k.code {
            KeyCode::Char(c) => buf.push(c),
            // Backspace on nothing closes a filter or a command. Not a prompt: that would
            // drop what it was asked for (a chain of a workflow's values); Esc cancels it.
            KeyCode::Backspace => {
                if buf.pop().is_none() && !matches!(self, Input::Prompt(..)) {
                    let was_filter = matches!(self, Input::Filter(_));
                    *self = Input::None;
                    return if was_filter {
                        Typed::FilterKept
                    } else {
                        Typed::Cancelled(None)
                    };
                }
            }
            KeyCode::Esc => {
                return match std::mem::replace(self, Input::None) {
                    Input::Filter(_) => Typed::FilterCleared,
                    Input::Prompt(p, _) => Typed::Cancelled(Some(p)),
                    _ => Typed::Cancelled(None),
                };
            }
            KeyCode::Enter => {
                return match std::mem::replace(self, Input::None) {
                    Input::Command(c) => Typed::Command(c),
                    Input::Prompt(p, text) => Typed::Submit(p, text),
                    _ => Typed::FilterKept,
                };
            }
            _ => {}
        }
        match self {
            Input::Filter(s) => Typed::Filter(s.clone()),
            _ => Typed::Editing,
        }
    }

    /// The line as the key bar draws it. None: nothing is being typed.
    pub fn bar(&self) -> Option<KeyBar<'_>> {
        Some(match self {
            Input::None => return None,
            Input::Filter(s) => KeyBar::Filter(s),
            Input::Command(s) => KeyBar::Command(s),
            Input::Prompt(p, s) => KeyBar::Prompt {
                label: p.label(),
                text: s,
                enter: p.enter_word(),
                note: p.note().map(str::to_string),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyModifiers;

    #[derive(Debug, PartialEq)]
    struct Ask(&'static str);
    impl PromptLine for Ask {
        fn label(&self) -> String {
            format!("{}: ", self.0)
        }
    }

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    #[test]
    fn backspace_closes_a_command_not_a_prompt() {
        let mut i: Input<Ask> = Input::Command("q".into());
        assert_eq!(i.key(&key(KeyCode::Backspace)), Typed::Editing);
        assert!(i.is_open());
        assert_eq!(i.key(&key(KeyCode::Backspace)), Typed::Cancelled(None));
        assert!(!i.is_open());
        // A filter closes too, and stays as it was.
        let mut i: Input<Ask> = Input::Filter(String::new());
        assert_eq!(i.key(&key(KeyCode::Char('a'))), Typed::Filter("a".into()));
        assert_eq!(i.key(&key(KeyCode::Backspace)), Typed::Filter("".into()));
        assert_eq!(i.key(&key(KeyCode::Backspace)), Typed::FilterKept);
        assert!(!i.is_open());
        // A prompt doesn't: one Backspace too many loses nothing.
        let mut i = Input::Prompt(Ask("tag"), "v".into());
        i.key(&key(KeyCode::Backspace));
        assert_eq!(i.key(&key(KeyCode::Backspace)), Typed::Editing);
        assert!(i.is_open());
        i.paste("1.5\n");
        assert_eq!(
            i.key(&key(KeyCode::Enter)),
            Typed::Submit(Ask("tag"), "1.5".into())
        );
    }

    #[test]
    fn esc_hands_the_prompt_back() {
        let mut i = Input::Prompt(Ask("tag"), "v1".into());
        assert_eq!(
            i.key(&key(KeyCode::Esc)),
            Typed::Cancelled(Some(Ask("tag")))
        );
        assert!(!i.is_open());
        let mut i: Input<Ask> = Input::Filter("web".into());
        assert_eq!(i.key(&key(KeyCode::Esc)), Typed::FilterCleared);
        let mut i: Input<Ask> = Input::Filter("web".into());
        assert_eq!(i.key(&key(KeyCode::Enter)), Typed::FilterKept);
        let mut i: Input<Ask> = Input::Command("wf".into());
        assert_eq!(i.key(&key(KeyCode::Enter)), Typed::Command("wf".into()));
        // Nothing open: nothing happens.
        let mut i: Input<Ask> = Input::None;
        assert_eq!(i.key(&key(KeyCode::Char('x'))), Typed::Editing);
        assert!(i.bar().is_none());
    }
}

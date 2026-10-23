//! Key → Action mapping. Vim navigation by default (spec §11), overridable via `[keys]`.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::ScreenId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Screen(ScreenId),
    NextScreen,
    PrevScreen,
    Up,
    Down,
    Top,
    Bottom,
    PageDown,
    PageUp,
    Left,
    Right,
    Enter,
    Esc,
    Filter,
    NextMatch,
    PrevMatch,
    Command,
    Help,
    Quit,
    Refresh,
    Check,
    FocusLeft,
    FocusRight,
    LogDown,
    LogUp,
    Interrupt,
    /// Unbound key, passed to the active screen.
    Char(char),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    pub code: KeyCode,
    pub ctrl: bool,
}

impl Key {
    fn from_event(e: &KeyEvent) -> Self {
        let code = match e.code {
            // Normalise Shift-Tab spellings.
            KeyCode::Tab if e.modifiers.contains(KeyModifiers::SHIFT) => KeyCode::BackTab,
            c => c,
        };
        Self { code, ctrl: e.modifiers.contains(KeyModifiers::CONTROL) }
    }
}

/// `q`, `H`, `C-j`, `S-Tab`, `Tab`, `Enter`, `Esc`, `Space`, `PgDn`, `Up`, `F5`.
pub fn parse_key(spec: &str) -> Option<Key> {
    let (ctrl, rest) = match spec.strip_prefix("C-") {
        Some(r) => (true, r),
        None => (false, spec),
    };
    let code = match rest {
        "S-Tab" | "BackTab" => KeyCode::BackTab,
        "Tab" => KeyCode::Tab,
        "Enter" => KeyCode::Enter,
        "Esc" => KeyCode::Esc,
        "Space" => KeyCode::Char(' '),
        "PgDn" | "PageDown" => KeyCode::PageDown,
        "PgUp" | "PageUp" => KeyCode::PageUp,
        "Up" => KeyCode::Up,
        "Down" => KeyCode::Down,
        "Left" => KeyCode::Left,
        "Right" => KeyCode::Right,
        "Home" => KeyCode::Home,
        "End" => KeyCode::End,
        f if f.starts_with('F') && f.len() > 1 => KeyCode::F(f[1..].parse().ok()?),
        c if c.chars().count() == 1 => KeyCode::Char(c.chars().next()?),
        _ => return None,
    };
    Some(Key { code, ctrl })
}

/// Action names usable in `[keys]`.
fn action_by_name(name: &str) -> Option<Action> {
    use Action::*;
    Some(match name {
        "next_screen" => NextScreen,
        "prev_screen" => PrevScreen,
        "up" => Up,
        "down" => Down,
        "bottom" => Bottom,
        "page_down" => PageDown,
        "page_up" => PageUp,
        "filter" => Filter,
        "next_match" => NextMatch,
        "prev_match" => PrevMatch,
        "command" => Command,
        "help" => Help,
        "quit" => Quit,
        "refresh" => Refresh,
        "check" => Check,
        "focus_left" => FocusLeft,
        "focus_right" => FocusRight,
        "log_down" => LogDown,
        "log_up" => LogUp,
        n => Screen(ScreenId::ALL.iter().copied().find(|s| format!("screen.{}", s.slug()) == n)?),
    })
}

pub struct Keymap {
    map: HashMap<Key, Action>,
    pending_g: Option<Instant>,
}

impl Keymap {
    pub fn new(overrides: &BTreeMap<String, String>) -> (Self, Vec<String>) {
        use Action::*;
        let mut map = HashMap::new();
        let ch = |c| Key { code: KeyCode::Char(c), ctrl: false };
        let ctl = |c| Key { code: KeyCode::Char(c), ctrl: true };
        let code = |c| Key { code: c, ctrl: false };
        for s in ScreenId::ALL {
            map.insert(ch(s.key()), Screen(s));
        }
        for (k, a) in [
            (code(KeyCode::Tab), NextScreen),
            (code(KeyCode::BackTab), PrevScreen),
            (ch('l'), NextScreen),
            (ch('h'), PrevScreen),
            (ch('j'), Down),
            (ch('k'), Up),
            (code(KeyCode::Down), Down),
            (code(KeyCode::Up), Up),
            (code(KeyCode::Left), Left),
            (code(KeyCode::Right), Right),
            (ch('G'), Bottom),
            (code(KeyCode::End), Bottom),
            (code(KeyCode::Home), Top),
            (ctl('d'), PageDown),
            (ctl('u'), PageUp),
            (code(KeyCode::PageDown), PageDown),
            (code(KeyCode::PageUp), PageUp),
            (code(KeyCode::Enter), Enter),
            (code(KeyCode::Esc), Esc),
            (ch('/'), Filter),
            (ch('n'), NextMatch),
            (ch('N'), PrevMatch),
            (ch(':'), Command),
            (ch('?'), Help),
            (ch('q'), Quit),
            (ch('r'), Refresh),
            (ch('c'), Check),
            (ctl('h'), FocusLeft),
            (ctl('l'), FocusRight),
            (ctl('j'), LogDown),
            (ctl('k'), LogUp),
            (ctl('c'), Interrupt),
        ] {
            map.insert(k, a);
        }
        let mut warnings = Vec::new();
        for (name, spec) in overrides {
            match (action_by_name(name), parse_key(spec)) {
                (Some(a), Some(k)) => {
                    map.retain(|_, v| *v != a);
                    map.insert(k, a);
                }
                (None, _) => warnings.push(format!("[keys]: unknown action `{name}`")),
                (_, None) => warnings.push(format!("[keys]: can't parse key `{spec}` for `{name}`")),
            }
        }
        (Self { map, pending_g: None }, warnings)
    }

    /// Resolve a key event. `gg` (two `g` within 1 s) is Top.
    pub fn resolve(&mut self, e: &KeyEvent) -> Option<Action> {
        let k = Key::from_event(e);
        if k == (Key { code: KeyCode::Char('g'), ctrl: false }) && !self.map.contains_key(&k) {
            if self.pending_g.take().is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
                return Some(Action::Top);
            }
            self.pending_g = Some(Instant::now());
            return None;
        }
        self.pending_g = None;
        if let Some(a) = self.map.get(&k) {
            return Some(*a);
        }
        match k.code {
            KeyCode::Char(c) if !k.ctrl => Some(Action::Char(c)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(c: KeyCode, m: KeyModifiers) -> KeyEvent {
        KeyEvent::new(c, m)
    }

    #[test]
    fn gg_chord_and_screens() {
        let (mut km, w) = Keymap::new(&BTreeMap::new());
        assert!(w.is_empty());
        let g = ev(KeyCode::Char('g'), KeyModifiers::NONE);
        assert_eq!(km.resolve(&g), None);
        assert_eq!(km.resolve(&g), Some(Action::Top));
        assert_eq!(km.resolve(&ev(KeyCode::Char('H'), KeyModifiers::SHIFT)), Some(Action::Screen(ScreenId::Hist)));
        assert_eq!(km.resolve(&ev(KeyCode::Char('0'), KeyModifiers::NONE)), Some(Action::Screen(ScreenId::Upgrade)));
        assert_eq!(km.resolve(&ev(KeyCode::Char('j'), KeyModifiers::CONTROL)), Some(Action::LogDown));
        assert_eq!(km.resolve(&ev(KeyCode::Tab, KeyModifiers::SHIFT)), Some(Action::PrevScreen));
        assert_eq!(km.resolve(&ev(KeyCode::Char('x'), KeyModifiers::NONE)), Some(Action::Char('x')));
    }

    #[test]
    fn overrides() {
        let mut o = BTreeMap::new();
        o.insert("quit".to_string(), "Q".to_string());
        o.insert("screen.history".to_string(), "F9".to_string());
        o.insert("bogus".to_string(), "x".to_string());
        let (mut km, w) = Keymap::new(&o);
        assert_eq!(w.len(), 1);
        assert_eq!(km.resolve(&ev(KeyCode::Char('Q'), KeyModifiers::SHIFT)), Some(Action::Quit));
        assert_eq!(km.resolve(&ev(KeyCode::Char('q'), KeyModifiers::NONE)), Some(Action::Char('q')));
        assert_eq!(km.resolve(&ev(KeyCode::F(9), KeyModifiers::NONE)), Some(Action::Screen(ScreenId::Hist)));
    }

    #[test]
    fn key_specs() {
        assert_eq!(parse_key("C-j"), Some(Key { code: KeyCode::Char('j'), ctrl: true }));
        assert_eq!(parse_key("S-Tab"), Some(Key { code: KeyCode::BackTab, ctrl: false }));
        assert_eq!(parse_key("nope"), None);
    }
}

//! Key → Action mapping. Vim navigation by default (spec §11), overridable via `[keys]`.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{ScreenId, ScreenSet};

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
    /// Ask Claude about the selected thing.
    Ask,
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
        Self {
            code,
            ctrl: e.modifiers.contains(KeyModifiers::CONTROL),
        }
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

/// What a `[keys]` name is.
enum Named {
    Action(Action),
    /// A screen only the other program has (both read the same config.toml).
    NotHere,
    Unknown,
}

/// Action names usable in `[keys]`.
fn action_by_name(name: &str, set: &ScreenSet) -> Named {
    use Action::*;
    Named::Action(match name {
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
        "ask" => Ask,
        n => {
            let is = |s: &ScreenId| format!("screen.{}", s.slug()) == n;
            match set.ids.iter().copied().find(|s| is(s)) {
                Some(s) => Screen(s),
                None if ScreenId::ALL.iter().any(is) => return Named::NotHere,
                None => return Named::Unknown,
            }
        }
    })
}

pub struct Keymap {
    map: HashMap<Key, Action>,
    pending_g: Option<Instant>,
}

impl Keymap {
    /// The default keys with `overrides` (`[keys]`) on top, and what's wrong in those. Only
    /// `set`'s screens get their keys.
    pub fn new(set: &ScreenSet, overrides: &BTreeMap<String, String>) -> (Self, Vec<String>) {
        use Action::*;
        let mut map = HashMap::new();
        let ch = |c| Key {
            code: KeyCode::Char(c),
            ctrl: false,
        };
        let ctl = |c| Key {
            code: KeyCode::Char(c),
            ctrl: true,
        };
        let code = |c| Key {
            code: c,
            ctrl: false,
        };
        for s in set.ids {
            map.insert(ch(s.key()), Screen(*s));
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
            (ch('A'), Ask),
        ] {
            map.insert(k, a);
        }
        let mut warnings = Vec::new();
        for (name, spec) in overrides {
            match (action_by_name(name, set), parse_key(spec)) {
                (Named::NotHere, _) => {}
                (Named::Action(a), Some(k)) => {
                    map.retain(|_, v| *v != a);
                    map.insert(k, a);
                }
                (Named::Unknown, _) => warnings.push(format!("[keys]: unknown action `{name}`")),
                (_, None) => {
                    warnings.push(format!("[keys]: can't parse key `{spec}` for `{name}`"))
                }
            }
        }
        (
            Self {
                map,
                pending_g: None,
            },
            warnings,
        )
    }

    /// Resolve a key event. `gg` (two `g` within 1 s) is Top.
    pub fn resolve(&mut self, e: &KeyEvent) -> Option<Action> {
        let k = Key::from_event(e);
        if k == (Key {
            code: KeyCode::Char('g'),
            ctrl: false,
        }) && !self.map.contains_key(&k)
        {
            if self
                .pending_g
                .take()
                .is_some_and(|t| t.elapsed() < Duration::from_secs(1))
            {
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

    /// sentry's screens.
    const LOCAL: ScreenSet = ScreenSet {
        ids: &[
            ScreenId::Dash,
            ScreenId::Proc,
            ScreenId::Net,
            ScreenId::Cont,
            ScreenId::Flat,
            ScreenId::Maint,
            ScreenId::Clean,
            ScreenId::Upgrade,
            ScreenId::Hist,
        ],
        aliases: &[],
    };

    #[test]
    fn a_set_binds_only_its_screens() {
        let server = ScreenSet {
            ids: &[ScreenId::Dash, ScreenId::Svc, ScreenId::Maint],
            aliases: &[],
        };
        let (mut km, _) = Keymap::new(&server, &BTreeMap::new());
        let press = |km: &mut Keymap, c| km.resolve(&ev(KeyCode::Char(c), KeyModifiers::NONE));
        assert_eq!(press(&mut km, '5'), Some(Action::Screen(ScreenId::Svc)));
        assert_eq!(press(&mut km, '6'), Some(Action::Screen(ScreenId::Maint)));
        // No screen there: an ordinary key.
        assert_eq!(press(&mut km, '2'), Some(Action::Char('2')));
        assert_eq!(press(&mut km, '7'), Some(Action::Char('7')));
        let (mut km, _) = Keymap::new(&LOCAL, &BTreeMap::new());
        assert_eq!(press(&mut km, '5'), Some(Action::Screen(ScreenId::Flat)));
    }

    #[test]
    fn the_other_programs_screen_is_skipped_quietly() {
        let server = ScreenSet {
            ids: &[ScreenId::Dash, ScreenId::Svc],
            aliases: &[],
        };
        let mut o = BTreeMap::new();
        o.insert("screen.flatpaks".to_string(), "F5".to_string());
        o.insert("screen.services".to_string(), "F6".to_string());
        o.insert("screen.nowhere".to_string(), "F7".to_string());
        let (mut km, w) = Keymap::new(&server, &o);
        assert_eq!(w, ["[keys]: unknown action `screen.nowhere`"]);
        assert_eq!(km.resolve(&ev(KeyCode::F(5), KeyModifiers::NONE)), None);
        assert_eq!(
            km.resolve(&ev(KeyCode::F(6), KeyModifiers::NONE)),
            Some(Action::Screen(ScreenId::Svc))
        );
    }

    #[test]
    fn gg_chord_and_screens() {
        let (mut km, w) = Keymap::new(&LOCAL, &BTreeMap::new());
        assert!(w.is_empty());
        let g = ev(KeyCode::Char('g'), KeyModifiers::NONE);
        assert_eq!(km.resolve(&g), None);
        assert_eq!(km.resolve(&g), Some(Action::Top));
        assert_eq!(
            km.resolve(&ev(KeyCode::Char('H'), KeyModifiers::SHIFT)),
            Some(Action::Screen(ScreenId::Hist))
        );
        assert_eq!(
            km.resolve(&ev(KeyCode::Char('0'), KeyModifiers::NONE)),
            Some(Action::Screen(ScreenId::Upgrade))
        );
        assert_eq!(
            km.resolve(&ev(KeyCode::Char('j'), KeyModifiers::CONTROL)),
            Some(Action::LogDown)
        );
        assert_eq!(
            km.resolve(&ev(KeyCode::Tab, KeyModifiers::SHIFT)),
            Some(Action::PrevScreen)
        );
        assert_eq!(
            km.resolve(&ev(KeyCode::Char('x'), KeyModifiers::NONE)),
            Some(Action::Char('x'))
        );
    }

    #[test]
    fn overrides() {
        let mut o = BTreeMap::new();
        o.insert("quit".to_string(), "Q".to_string());
        o.insert("screen.history".to_string(), "F9".to_string());
        o.insert("bogus".to_string(), "x".to_string());
        let (mut km, w) = Keymap::new(&LOCAL, &o);
        assert_eq!(w.len(), 1);
        assert_eq!(
            km.resolve(&ev(KeyCode::Char('Q'), KeyModifiers::SHIFT)),
            Some(Action::Quit)
        );
        assert_eq!(
            km.resolve(&ev(KeyCode::Char('q'), KeyModifiers::NONE)),
            Some(Action::Char('q'))
        );
        assert_eq!(
            km.resolve(&ev(KeyCode::F(9), KeyModifiers::NONE)),
            Some(Action::Screen(ScreenId::Hist))
        );
    }

    #[test]
    fn key_specs() {
        assert_eq!(
            parse_key("C-j"),
            Some(Key {
                code: KeyCode::Char('j'),
                ctrl: true
            })
        );
        assert_eq!(
            parse_key("S-Tab"),
            Some(Key {
                code: KeyCode::BackTab,
                ctrl: false
            })
        );
        assert_eq!(parse_key("nope"), None);
    }
}

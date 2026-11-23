//! The Config area's keys: what is in front gets them (the window's box, the save box, the
//! `:` line, a form with something open), then the keys that work on every screen of the
//! area, then the screen's own.

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::text::Line;
use sentry_core::cfg::FileId;
use sentry_core::tui::form;
use sentry_core::tui::frame::{self, Hints};
use sentry_core::tui::keys::Action;
use sentry_core::tui::lineedit::{Edited, LineEdit};
use sentry_core::tui::modal::{self, Answer};

use super::{ConfigArea, Fx, Screen, count};
use crate::app::Win;
use crate::effect::{Effect, Modal};

/// What the quit box says.
pub(crate) const QUIT: &str = "Quit sentry? Nothing keeps running after exit.";

impl ConfigArea {
    pub(crate) fn on_paste(&mut self, w: &mut Win, text: &str) {
        if let Some(line) = self.cmd.as_mut() {
            line.paste(text);
        } else if let Some(f) = self.form.as_mut() {
            f.paste(text);
        }
        w.dirty = true;
    }

    pub(crate) fn on_key(&mut self, w: &mut Win, k: KeyEvent) -> Option<Fx> {
        w.dirty = true;
        // The window's own box (help, quit).
        if let Some(m) = &w.modal {
            match modal::answer(&k, m.yes.is_some()) {
                Answer::Yes => {
                    let yes = w.modal.take().and_then(|m| m.yes);
                    if yes.is_some_and(|(_, fx)| fx.iter().any(|e| matches!(e, Effect::Quit))) {
                        w.quit = true;
                    }
                }
                Answer::No => w.modal = None,
                Answer::Stay => {}
            }
            return None;
        }
        if self.save.is_some() {
            return match k.code {
                KeyCode::Enter | KeyCode::Char('y') => self.do_save(w),
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.save = None;
                    None
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.save_scroll(true);
                    None
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.save_scroll(false);
                    None
                }
                _ => None,
            };
        }
        if let Some(line) = self.cmd.as_mut() {
            let empty = line.is_empty();
            match line.key(&k) {
                Edited::Submit => {
                    let text = self.cmd.take().map(|l| l.text()).unwrap_or_default();
                    return self.command(w, text.trim());
                }
                Edited::Cancel => self.cmd = None,
                // Backspace on nothing closes it.
                _ if empty && k.code == KeyCode::Backspace => self.cmd = None,
                _ => {}
            }
            return None;
        }
        if self.form.as_ref().is_some_and(|f| f.captures()) {
            return self.form_key(w, &k);
        }
        let a = w.keys.resolve(&k);
        match a {
            Some(Action::Quit | Action::Interrupt) => self.quit_box(w),
            Some(Action::Help) => self.help(w),
            Some(Action::Command) => self.cmd = Some(LineEdit::default()),
            Some(Action::Screen(id)) if Screen::by_key(id.key()).is_some() => {
                if let Some(s) = Screen::by_key(id.key()) {
                    self.enter(w, s);
                }
            }
            Some(Action::Char(c)) if Screen::by_key(c).is_some() => {
                if let Some(s) = Screen::by_key(c) {
                    self.enter(w, s);
                }
            }
            Some(Action::NextScreen | Action::PrevScreen) => {
                let i = Screen::ALL
                    .iter()
                    .position(|s| *s == self.screen)
                    .unwrap_or(0);
                let n = Screen::ALL.len();
                let step = if a == Some(Action::NextScreen) {
                    1
                } else {
                    n - 1
                };
                self.enter(w, Screen::ALL[(i + step) % n]);
            }
            Some(Action::Refresh) => {
                let changed = self.look(w);
                if self.screen == Screen::Agent {
                    self.agent_find(w, true);
                }
                w.toast(match changed.is_empty() {
                    true => "read again: the files are as they were",
                    false => "read again: a file had changed",
                });
                return (!changed.is_empty()).then_some(Fx::Changed(changed));
            }
            Some(Action::Check) => {
                let changed = self.look(w);
                self.lint(w);
                w.toast(&match self.problems.len() {
                    0 => "checked: nothing wrong in the files".to_string(),
                    n => format!("checked: {} in the files", count(n, "problem")),
                });
                return (!changed.is_empty()).then_some(Fx::Changed(changed));
            }
            Some(Action::Char('s')) => return self.open_save(w),
            Some(Action::Char('e')) => {
                let file = self.file_to_edit();
                self.edit = Some(self.path(file));
            }
            Some(Action::Char('u')) => self.undo_here(w),
            Some(Action::Char('t')) if self.screen == Screen::Agent => self.agent_test(w),
            _ => match self.screen {
                Screen::Overview => self.overview_key(w, a),
                Screen::Servers | Screen::Networks => self.list_key(w, a),
                // A form's moving and Enter are whatever `[keys]` binds them to.
                _ => {
                    let k = match a {
                        Some(Action::Down) => KeyEvent::from(KeyCode::Down),
                        Some(Action::Up) => KeyEvent::from(KeyCode::Up),
                        Some(Action::Top) => KeyEvent::from(KeyCode::Home),
                        Some(Action::Bottom) => KeyEvent::from(KeyCode::End),
                        Some(Action::Enter) => KeyEvent::from(KeyCode::Enter),
                        Some(Action::Esc) => KeyEvent::from(KeyCode::Esc),
                        _ => k,
                    };
                    return self.form_key(w, &k);
                }
            },
        }
        None
    }

    /// A key for the form of the screen in view.
    fn form_key(&mut self, w: &mut Win, k: &KeyEvent) -> Option<Fx> {
        let Some(f) = self.form.as_mut() else {
            // (The file doesn't parse: there is no form. Esc goes back.)
            if k.code == KeyCode::Esc {
                self.enter(w, Screen::Overview);
            }
            return None;
        };
        match f.key(k) {
            form::Fx::None | form::Fx::Open(..) => {}
            form::Fx::Leave => self.enter(w, Screen::Overview),
            form::Fx::Set(path, v) => self.form_set(w, &path, &v),
        }
        None
    }

    /// The rows the Overview's cursor goes over: the systems, the add row, what is staged.
    pub(crate) fn overview_rows(&self) -> usize {
        self.systems().len() + 1 + self.pending.len()
    }

    /// Which staged change the Overview's cursor is on.
    pub(crate) fn pending_at(&self) -> Option<usize> {
        self.cur
            .checked_sub(self.systems().len() + 1)
            .filter(|i| *i < self.pending.len())
    }

    fn overview_key(&mut self, w: &mut Win, a: Option<Action>) {
        let n = self.overview_rows();
        let systems = self.systems();
        self.cur = self.cur.min(n.saturating_sub(1));
        match a {
            Some(Action::Down) => self.cur = (self.cur + 1).min(n.saturating_sub(1)),
            Some(Action::Up) => self.cur = self.cur.saturating_sub(1),
            Some(Action::Top) => self.cur = 0,
            Some(Action::Bottom) => self.cur = n.saturating_sub(1),
            Some(Action::Char(' ')) => match self.pending_at() {
                Some(i) => {
                    if let Some(why) = self.tick(i) {
                        w.toast(&format!("it no longer fits the file: {why}"));
                    }
                    self.lint(w);
                }
                None => w.toast("Space ticks a staged change"),
            },
            Some(Action::Enter) => match systems.get(self.cur) {
                Some((_, e)) => {
                    let (screen, name) = (e.screen, e.name.clone());
                    self.enter(w, screen);
                    // A server or a network: its own row there.
                    if let Some(l) = self.list_of(screen) {
                        let at = self
                            .entries_of(screen)
                            .iter()
                            .position(|x| x.name == name)
                            .unwrap_or(0);
                        self.list[l] = at;
                    }
                }
                None if self.cur == systems.len() => w.toast(ADD_LATER),
                None => {
                    // A staged change: the screen its setting is on.
                    if let Some(p) = self.pending_at().map(|i| self.pending[i].change.clone()) {
                        let screen = self
                            .kind(p.file)
                            .and_then(|k| {
                                let entry = k.entry_of(&p.path);
                                let d = self.doc(p.file)?;
                                k.entries(d).into_iter().find(|e| e.name == entry)
                            })
                            .map_or(Screen::Window, |e| e.screen);
                        self.enter(w, screen);
                        if let Some(f) = self.form.as_mut()
                            && let Some(i) = f.fields.iter().position(|x| x.key == p.path)
                        {
                            f.cur = i;
                        }
                    }
                }
            },
            _ => {}
        }
    }

    /// Which of the two list cursors a screen has.
    pub(crate) fn list_of(&self, s: Screen) -> Option<usize> {
        match s {
            Screen::Servers => Some(0),
            Screen::Networks => Some(1),
            _ => None,
        }
    }

    /// The entries a list screen shows.
    pub(crate) fn entries_of(&self, s: Screen) -> Vec<super::Entry> {
        self.entries()
            .into_iter()
            .filter(|(_, e)| e.screen == s)
            .map(|(_, e)| e)
            .collect()
    }

    fn list_key(&mut self, w: &mut Win, a: Option<Action>) {
        let Some(l) = self.list_of(self.screen) else {
            return;
        };
        let n = self.entries_of(self.screen).len();
        let last = n.saturating_sub(1);
        self.list[l] = self.list[l].min(last);
        match a {
            Some(Action::Down) => self.list[l] = (self.list[l] + 1).min(last),
            Some(Action::Up) => self.list[l] = self.list[l].saturating_sub(1),
            Some(Action::Top) => self.list[l] = 0,
            Some(Action::Bottom) => self.list[l] = last,
            Some(Action::Enter) if n > 0 => self.open = !self.open,
            Some(Action::Enter) => w.toast(ADD_LATER),
            Some(Action::Esc) if self.open => self.open = false,
            Some(Action::Esc) => self.enter(w, Screen::Overview),
            _ => {}
        }
    }

    /// `u`: the staged change under the cursor (the Overview's row, a form's field) is
    /// taken back.
    fn undo_here(&mut self, w: &mut Win) {
        let i = match self.screen {
            Screen::Overview => self.pending_at(),
            _ => self
                .field_path()
                .and_then(|p| self.pending.iter().position(|x| x.change.path == p)),
        };
        match i {
            Some(i) => {
                let (entry, label) = self.named(&self.pending[i]);
                self.undo(i);
                self.lint(w);
                let old = self.form.take();
                self.form = self.build_form().map(|f| match &old {
                    Some(o) => f.at(o),
                    None => f,
                });
                self.cur = self.cur.min(self.overview_rows().saturating_sub(1));
                w.toast(&format!("{entry} · {label}: as the file says again"));
            }
            None => w.toast("nothing staged here to take back"),
        }
    }

    /// The area's `:` commands; one that isn't its own is the window's.
    fn command(&mut self, w: &mut Win, c: &str) -> Option<Fx> {
        let mut parts = c.split_whitespace();
        let (name, arg) = (parts.next(), parts.next());
        match (name, arg) {
            (None, _) | (Some("config"), None) => {}
            (Some("q" | "q!" | "quit" | "qa"), _) => w.quit = true,
            (Some("help" | "h"), _) => self.help(w),
            (Some("save" | "w"), _) => return self.open_save(w),
            (Some("check"), _) => {
                self.look(w);
                self.lint(w);
                w.toast(&format!(
                    "checked: {}",
                    count(self.problems.len(), "problem")
                ));
            }
            // (The window's target words come first: `:server` is a target, not Servers.)
            (Some("local" | "server" | "net"), _) => return Some(Fx::Command(c.to_string())),
            (Some(n), None) if Screen::by_name(n).is_some() => {
                if let Some(s) = Screen::by_name(n) {
                    self.enter(w, s);
                }
            }
            _ => return Some(Fx::Command(c.to_string())),
        }
        None
    }

    fn quit_box(&mut self, w: &mut Win) {
        // (What is staged and would be dropped is the app's to add: `App::quit_note`.)
        let m: Modal = frame::quit_modal(&w.theme, QUIT.to_string(), Effect::Quit);
        w.modal = Some(m);
        w.quit_asked = true;
    }

    /// What the quit box says of the area: what is staged here would be dropped.
    pub(crate) fn quit_note(&self) -> Option<String> {
        let n = self.pending.len();
        (n > 0).then(|| {
            format!(
                "{} staged in Config {} not saved: quitting drops {}.",
                count(n, "change"),
                if n == 1 { "is" } else { "are" },
                if n == 1 { "it" } else { "them" },
            )
        })
    }

    /// `?`: the area's own keys.
    fn help(&mut self, w: &mut Win) {
        let t = w.theme;
        let l = |s: &str| Line::styled(s.to_string(), t.fg());
        let dir = match &self.dir {
            Some(d) => d.clone(),
            None => sentry_core::paths::config_dir(),
        };
        let lines = vec![
            l("1–6       its screens          Tab/S-Tab, h/l  next/prev screen"),
            l("j/k ↑↓    move                 Enter  open · edit · toggle"),
            l("Space     tick a staged change, toggle a yes/no"),
            l("u         take the staged change here back"),
            l("s         the save box: what will be written, then Enter writes it"),
            l("e         the file in $EDITOR   r  read the files again   c  check them"),
            l("t         (Agent) test the agent: one turn, no tools"),
            l(":overview :agent :machine :servers :networks :window  :save  :check  :q"),
            Line::raw(""),
            Line::styled("In a list:".to_string(), t.s(t.mag)),
            l("Enter     edit the element     n  add   x  remove   J/K  move it   Esc  back"),
            Line::raw(""),
            Line::styled("The window:".to_string(), t.s(t.mag)),
            l("F1…  { }  another target, or back here (:config)     ?  help    q  quit"),
            Line::raw(""),
            Line::styled(
                format!(
                    "Nothing is written before the save box. The files: {}",
                    sentry_core::tui::widgets::short_home(&dir)
                ),
                t.dim(),
            ),
            Line::styled(
                "Each save keeps the file before beside it (.bak-<time>, the newest 5).",
                t.dim(),
            ),
        ];
        w.modal = Some(Modal {
            title: "Keys · sentry config".into(),
            color: t.mag,
            lines,
            yes: None,
        });
    }

    /// The key bar's hints for what is in front.
    pub(crate) fn hints(&self) -> Hints<'static> {
        if self.save.is_some() {
            return vec![("Enter", "save"), ("Esc", "back"), ("j/k", "scroll")];
        }
        if let Some(f) = self.form.as_ref().filter(|f| f.captures()) {
            return f.hints();
        }
        let mut h: Hints<'static> = match self.screen {
            Screen::Overview => vec![("Enter", "open"), ("Space", "tick")],
            Screen::Servers | Screen::Networks => {
                vec![("Enter", if self.open { "less" } else { "its settings" })]
            }
            _ => match &self.form {
                Some(f) => {
                    let mut h = f.hints();
                    h.retain(|(k, _)| *k != "j/k");
                    h
                }
                None => vec![("Esc", "back")],
            },
        };
        if self.screen == Screen::Agent {
            h.push(("t", "test it"));
        }
        h.extend([
            ("s", "save…"),
            ("c", "check"),
            ("e", "editor"),
            ("u", "undo"),
            ("?", "help"),
            ("q", "quit"),
        ]);
        h
    }

    /// Which screen an `App` problem belongs to (its badge).
    pub(crate) fn screen_of(&self, p: &super::Problem) -> Screen {
        match p.file {
            FileId::Servers => Screen::Servers,
            FileId::Networks => Screen::Networks,
            FileId::App => {
                let on = |words: &[&str]| {
                    words.iter().any(|s| {
                        p.text.starts_with(&format!("[{s}]")) || p.text.contains(&format!("`{s}."))
                    })
                };
                if on(&["agent"]) {
                    Screen::Agent
                } else if on(&["review", "maintenance", "ui"]) {
                    Screen::Machine
                } else {
                    Screen::Window
                }
            }
        }
    }
}

/// What the add row says until the next part.
pub(crate) const ADD_LATER: &str = "adding a system here comes with the next part: for now `sentry-server init <ssh-host>` or `sentry-network init <ssh-host>`";

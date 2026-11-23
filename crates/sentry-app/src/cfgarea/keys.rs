//! The Config area's keys: what is in front gets them (the window's box, a box of the area's
//! own, the save box, the `:` line, a record's form, a form with something open), then the
//! keys that work everywhere in the area, then the setup flow's or the page's in front, then
//! the screen's own.

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::text::Line;
use sentry_core::cfg::{By, FileId, Value, parse_path};
use sentry_core::tui::form;
use sentry_core::tui::frame::{self, Hints};
use sentry_core::tui::keys::Action;
use sentry_core::tui::lineedit::{Edited, LineEdit};
use sentry_core::tui::modal::{self, Answer};

use super::discover::AddFx;
use super::{ConfigArea, Fx, Page, Prompt, Screen, Then, Yes, count};
use crate::app::Win;
use crate::effect::{Effect, Modal};

/// What the quit box says.
pub(crate) const QUIT: &str = "Quit sentry? Nothing keeps running after exit.";

impl ConfigArea {
    pub(crate) fn on_paste(&mut self, w: &mut Win, text: &str) {
        if w.modal.is_some() {
            // (A box of the window's is in front: nothing is typed anywhere.)
        } else if let Some(c) = self.chat.as_mut().filter(|c| !c.hidden) {
            if !c.busy() {
                c.paste(text);
            }
        } else if let Some(p) = self.prompt.as_mut() {
            p.line.paste(text);
        } else if let Some(line) = self.cmd.as_mut() {
            line.paste(text);
        } else if let Some(r) = self.row.as_mut() {
            r.form.paste(text);
        } else {
            match self.page {
                Page::Add => {
                    if let Some(a) = self.add.as_mut() {
                        a.list.paste(text);
                    }
                }
                Page::Review => {
                    if let Some(r) = self.review.as_mut() {
                        r.list.paste(text);
                        r.form.paste(text);
                    }
                }
                Page::Routine => {
                    if let Some(l) = self.routine.as_mut() {
                        l.paste(text);
                    }
                }
                Page::Shown => {
                    if let Some(l) = self.shown.as_mut() {
                        l.paste(text);
                    }
                }
                Page::None => {
                    if let Some(f) = self.form.as_mut() {
                        f.paste(text);
                    }
                }
            }
        }
        w.dirty = true;
    }

    /// A key for the area. What is in front has it: the window's own box (help, quit),
    /// then the wizard's chat while it is in view, then a box of the area's (one that
    /// asks, a line typed, the save box), the `:` line, a field being edited; only then
    /// the keys that work everywhere (the wizard's `A` among them), the setup flow's, the
    /// page's and the screen's. So the chat is never opened over a box or a field being
    /// edited (there `A` isn't the wizard's key), and while it is in view nothing behind
    /// it gets a key.
    pub(crate) fn on_key(&mut self, w: &mut Win, k: KeyEvent) -> Option<Fx> {
        let fx = self.key(w, k);
        self.sync_hosts();
        fx
    }

    fn key(&mut self, w: &mut Win, k: KeyEvent) -> Option<Fx> {
        w.dirty = true;
        self.disk = !w.offline;
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
        if self.wizard_visible() {
            self.wizard_key(w, &k);
            return None;
        }
        if self.ask.is_some() {
            return self.ask_key(w, &k);
        }
        if self.prompt.is_some() {
            return self.prompt_key(w, &k);
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
        // A record's form is in front of its system's.
        if self.row.as_ref().is_some_and(|r| r.form.captures()) {
            return self.row_key(w, &k);
        }
        if self.page == Page::None
            && self.row.is_none()
            && self.form.as_ref().is_some_and(|f| f.captures())
        {
            return self.form_key(w, &k);
        }
        let a = w.keys.resolve(&k);
        // What works everywhere in the area, unless a line is being typed.
        if !self.takes_text() {
            match a {
                Some(Action::Quit | Action::Interrupt) => {
                    self.quit_box(w);
                    return None;
                }
                Some(Action::Help) => {
                    self.help(w);
                    return None;
                }
                Some(Action::Command) => {
                    self.cmd = Some(LineEdit::default());
                    return None;
                }
                // The wizard: wherever the area's keys are, the setup flow included.
                Some(Action::Ask) => {
                    self.wizard_open(w);
                    return None;
                }
                _ => {}
            }
        }
        // The setup flow's keys, then its step's.
        if self.guide.is_some() {
            if let Some(fx) = self.guide_key(w, &k) {
                return fx;
            }
        } else if self.page != Page::None {
            return self.page_key(w, &k);
        }
        if self.row.is_some() {
            return self.row_key(w, &k);
        }
        match a {
            // In the setup, the steps are walked in order: its rail is the way round.
            Some(
                Action::Screen(_)
                | Action::NextScreen
                | Action::PrevScreen
                | Action::Char('1'..='6'),
            ) if self.guide.is_some() => {
                w.toast("the setup walks the screens in order · Esc leaves it");
            }
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
                // On a system that has a host: its connection is checked too.
                let host = self
                    .system_here()
                    .filter(|(file, e)| self.check_system(w, *file, &e.name));
                w.toast(&match (self.problems.len(), host) {
                    (0, None) => "checked: nothing wrong in the files".to_string(),
                    (n, None) => format!("checked: {} in the files", count(n, "problem")),
                    (0, Some((_, e))) => {
                        format!("checking {}: its connection, sudo, tools", e.name)
                    }
                    (n, Some((_, e))) => format!(
                        "{} in the files · checking {}'s connection",
                        count(n, "problem"),
                        e.name
                    ),
                });
                return (!changed.is_empty()).then_some(Fx::Changed(changed));
            }
            Some(Action::Char('s')) => return self.open_save(w),
            Some(Action::Char('e')) => {
                // A workflow under Upkeep: its file; else the config file.
                match self.upkeep_here().and_then(|(_, _, row, _)| row.path) {
                    Some(p) => self.edit = Some(p),
                    None => {
                        let file = self.file_to_edit();
                        self.edit = Some(self.path(file));
                    }
                }
            }
            Some(Action::Char('o')) if self.form.is_some() && self.upkeep_here().is_some() => {
                self.own_copy(w)
            }
            Some(Action::Char('K')) if self.form.is_some() => self.field_action(w),
            // Which targets show: ticked in a list (their order is the field's own list).
            Some(Action::Char(' ')) if self.field_path().as_deref() == Some("targets.show") => {
                self.open_shown()
            }
            Some(Action::Char('u')) => self.undo_here(w),
            Some(Action::Char('t')) if self.screen == Screen::Agent => self.agent_test(w),
            _ => match self.screen {
                Screen::Overview => self.overview_key(w, a),
                Screen::Servers | Screen::Networks if !self.open => self.list_key(w, a),
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

    /// A key in a box of the area's own.
    fn ask_key(&mut self, w: &mut Win, k: &KeyEvent) -> Option<Fx> {
        match k.code {
            KeyCode::Enter | KeyCode::Char('y') => match self.ask.take().map(|a| a.yes) {
                Some(Yes::Probe(hosts)) => self.start_probes(w, &hosts),
                Some(Yes::OwnCopy { shared, own, open }) => {
                    self.do_own_copy(w, &shared, &own, open)
                }
                Some(Yes::LeaveGuide) => return self.guide_leave(w),
                None => {}
            },
            KeyCode::Esc | KeyCode::Char('n' | 'q') => self.ask = None,
            _ => {}
        }
        None
    }

    /// A key while a line is typed in a box.
    fn prompt_key(&mut self, w: &mut Win, k: &KeyEvent) -> Option<Fx> {
        let p = self.prompt.as_mut()?;
        match p.line.key(k) {
            Edited::Cancel => self.prompt = None,
            Edited::Submit => {
                let p = self.prompt.take()?;
                let text = p.line.text();
                match p.then {
                    Then::AddHost => self.add_by_name(w, &text),
                    Then::Act { path, done } => self.act_done(w, &path, text.trim(), done),
                }
            }
            _ => {}
        }
        None
    }

    /// `K` on a field that can do something (a network's backup recipients: make a key):
    /// what it needs is asked first.
    fn field_action(&mut self, w: &mut Win) {
        let Some(path) = self.field_path() else {
            return;
        };
        let Some(a) = self
            .kind(FileId::of_path(&path))
            .and_then(|k| k.action(&path))
        else {
            return w.toast("nothing more to do on this field");
        };
        self.prompt = Some(Prompt {
            title: a.label.to_string(),
            label: "file".into(),
            help: a.prompt,
            line: LineEdit::new(&a.start),
            then: Then::Act { path, done: a.done },
        });
    }

    /// The field's action ran: what it made joins the field's list, staged.
    fn act_done(&mut self, w: &mut Win, path: &str, arg: &str, done: &'static str) {
        if arg.is_empty() {
            return;
        }
        // (A path as it is typed: `~` is home.)
        let arg = super::discover::expand(arg);
        let arg = arg.to_string_lossy();
        let arg = arg.as_ref();
        let made = match (&self.act, w.offline) {
            (Some(act), _) => act(path, arg),
            (None, true) => Err("offline: nothing is written".to_string()),
            (None, false) => match self.kind(FileId::of_path(path)) {
                Some(k) => k.act(path, arg),
                None => Err("nothing to do here".to_string()),
            },
        };
        let elem = match made {
            Ok(e) => e,
            Err(why) => return w.toast(&format!("not done: {why}")),
        };
        let mut list = match parse_path(path)
            .ok()
            .zip(self.doc(FileId::of_path(path)))
            .and_then(|(segs, d)| d.tree().at(&segs).cloned())
        {
            Some(Value::List(l)) => l,
            _ => Vec::new(),
        };
        list.push(Value::Str(elem));
        match self.stage(path, Some(Value::List(list)), By::You) {
            Ok(()) => w.toast(done),
            Err(why) => w.toast(&format!("made, but not staged: {why}")),
        }
        self.refresh_forms(w);
    }

    /// A key on a page of the add flow, outside the setup.
    fn page_key(&mut self, w: &mut Win, k: &KeyEvent) -> Option<Fx> {
        match self.page {
            Page::Add => match self.add_key(w, k) {
                AddFx::Done => {
                    for d in &mut self.drafts {
                        d.reviewed = false;
                    }
                    if !self.open_review(w) {
                        self.page = Page::None;
                        w.toast("no system was drafted: nothing staged");
                    }
                }
                AddFx::Leave => self.page = Page::None,
                AddFx::Stay => {}
            },
            Page::Review => match self.review_key(w, k) {
                AddFx::Done => {
                    self.page = Page::None;
                    self.enter(w, Screen::Overview);
                    w.toast(&format!(
                        "{} staged to be added · s saves, and they get their tabs",
                        match self.drafts.len() {
                            1 => "1 system".to_string(),
                            n => format!("{n} systems"),
                        }
                    ));
                }
                AddFx::Leave => self.page = Page::None,
                AddFx::Stay => {}
            },
            Page::Shown => {
                use sentry_core::tui::ticklist;
                match self.shown.as_mut().map(|l| l.key(k)) {
                    Some(ticklist::Fx::Enter) => self.shown_accept(w),
                    Some(ticklist::Fx::Leave) | None => {
                        self.page = Page::None;
                        self.shown = None;
                    }
                    _ => {}
                }
            }
            Page::Routine | Page::None => self.page = Page::None,
        }
        None
    }

    /// A key for a record's form.
    fn row_key(&mut self, w: &mut Win, k: &KeyEvent) -> Option<Fx> {
        let r = self.row.as_mut()?;
        match r.form.key(k) {
            form::Fx::Leave => self.row = None,
            form::Fx::Set(path, v) => self.form_set(w, &path, &v),
            _ => {}
        }
        None
    }

    /// A key for the form of the screen in view.
    pub(crate) fn form_key(&mut self, w: &mut Win, k: &KeyEvent) -> Option<Fx> {
        let list = self.list_of(self.screen).is_some();
        let Some(f) = self.form.as_mut() else {
            // (The file doesn't parse: there is no form. Esc goes back.)
            if k.code == KeyCode::Esc {
                self.enter(w, Screen::Overview);
            }
            return None;
        };
        let file = self.screen.file().unwrap_or(FileId::App);
        match f.key(k) {
            form::Fx::None => {}
            form::Fx::Open(key, at) => self.open_row(file, &key, at),
            form::Fx::Add(key) => self.add_row(w, file, &key),
            form::Fx::Remove(key, at) => self.remove_row(w, file, &key, at),
            // A system's form closes to its list; a screen's own to the Overview.
            form::Fx::Leave if list => {
                self.open = false;
                self.form = None;
            }
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

    /// A system's own screen with its form open (a server's, a network's), or this
    /// machine's.
    pub(crate) fn open_entry(&mut self, w: &mut Win, screen: Screen, name: &str) {
        self.enter(w, screen);
        if let Some(l) = self.list_of(screen) {
            let at = self
                .entries_of(screen)
                .iter()
                .position(|x| x.name == name)
                .unwrap_or(0);
            self.list[l] = at;
            self.open = true;
            self.form = self.build_form();
        }
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
            Some(Action::Char('x')) => match systems.get(self.cur) {
                Some((file, e)) => self.remove_system(w, *file, &e.name),
                None => w.toast("x takes a system out · u takes a staged change back"),
            },
            Some(Action::Enter) => match systems.get(self.cur) {
                Some((_, e)) => {
                    let (screen, name) = (e.screen, e.name.clone());
                    self.open_entry(w, screen, &name);
                }
                None if self.cur == systems.len() => self.open_add(w),
                None => {
                    // A staged change: the screen its setting is on.
                    if let Some(p) = self.pending_at().map(|i| self.pending[i].change.clone()) {
                        let entry = self.kind(p.file).and_then(|k| {
                            let entry = k.entry_of(&p.path);
                            let d = self.doc(p.file)?;
                            k.entries(d).into_iter().find(|e| e.name == entry)
                        });
                        match entry {
                            Some(e) => self.open_entry(w, e.screen, &e.name),
                            None => self.enter(w, Screen::Window),
                        }
                        if let Some(f) = self.form.as_mut() {
                            f.go(&p.path);
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
        let entries = self.entries_of(self.screen);
        let n = entries.len();
        let last = n.saturating_sub(1);
        self.list[l] = self.list[l].min(last);
        match a {
            Some(Action::Down) => self.list[l] = (self.list[l] + 1).min(last),
            Some(Action::Up) => self.list[l] = self.list[l].saturating_sub(1),
            Some(Action::Top) => self.list[l] = 0,
            Some(Action::Bottom) => self.list[l] = last,
            Some(Action::Enter) if n > 0 => {
                self.open = true;
                self.form = self.build_form();
            }
            // None yet: the way to add one.
            Some(Action::Enter | Action::NextMatch | Action::Char('n')) => self.open_add(w),
            Some(Action::Char('x')) => {
                if let (Some(file), Some(e)) = (self.screen.file(), entries.get(self.list[l])) {
                    self.remove_system(w, file, &e.name);
                }
            }
            Some(Action::Esc) => self.enter(w, Screen::Overview),
            _ => {}
        }
    }

    /// `u`: the staged change under the cursor (the Overview's row, a form's field) is
    /// taken back.
    fn undo_here(&mut self, w: &mut Win) {
        let i = match self.screen {
            Screen::Overview => self.pending_at().or_else(|| {
                // On a system: what is staged for the system as a whole (added, removed).
                let (file, e) = self.system_here()?;
                let path = super::systems::entry_path(file, &e.name)?;
                self.pending.iter().position(|p| p.change.path == path)
            }),
            _ => self.field_path().and_then(|p| {
                let path = match self.upkeep_here() {
                    // (A workflow's cadence is staged in its system's own setting.)
                    Some((file, entry, row, _)) => self
                        .kind_doc(file)
                        .and_then(|(k, d)| k.cadence(d, &entry, &row.name, None))
                        .map(|(path, _)| path)?,
                    None => p,
                };
                self.pending.iter().position(|x| x.change.path == path)
            }),
        };
        match i {
            Some(i) => {
                let (entry, label) = self.named(&self.pending[i]);
                self.undo(i);
                self.live_drafts();
                self.refresh_forms(w);
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
            (Some("setup"), _) => self.start_guide(w),
            (Some("add"), _) if self.guide.is_none() => {
                self.enter(w, Screen::Overview);
                self.open_add(w);
            }
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
            (Some(n), None) if Screen::by_name(n).is_some() && self.guide.is_some() => {
                w.toast("the setup walks the screens in order · Esc leaves it");
            }
            (Some(n), None) if Screen::by_name(n).is_some() => {
                if let Some(s) = Screen::by_name(n) {
                    self.page = Page::None;
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
        let dir = self.dir();
        let lines = vec![
            l("1–6       its screens          Tab/S-Tab, h/l  next/prev screen"),
            l("j/k ↑↓    move                 Enter  open · edit · toggle"),
            l("Space     tick a staged change, toggle a yes/no, open or close a group"),
            l("u         take the staged change here back"),
            l("s         the save box: what will be written, then Enter writes it"),
            l("e         the file in $EDITOR   r  read the files again"),
            l("c         check the files; on a system, its connection too (reads only)"),
            l("x         (a system) stage its removal: its records stay on disk"),
            l("t         (Agent) test the agent: one turn, no tools"),
            l("A         the wizard: ask the agent about the setup. It explains and proposes;"),
            l("          what it proposes lands in Pending, ticked, (Claude): you save, or not"),
            l(":overview :agent :machine :servers :networks :window  :save  :check  :q"),
            l(":add      look for systems to add          :setup  the setup, step by step"),
            Line::raw(""),
            Line::styled("In a list:".to_string(), t.s(t.mag)),
            l("Enter     edit the element     n  add   x  remove   J/K  move it   Esc  back"),
            l("          (a record's row opens as a form of its own)"),
            Line::raw(""),
            Line::styled("Under Upkeep:".to_string(), t.s(t.mag)),
            l("Enter     how often it is due (7d, 30d, off)     e  its steps in $EDITOR"),
            l("o         give this system its own copy of the workflows (asks first)"),
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
        if let Some(c) = self.chat.as_ref().filter(|c| !c.hidden) {
            return sentry_core::tui::chat::keys(c);
        }
        let h = self.hints_behind();
        // The wizard is offered wherever its key works: not in a box, not while a field
        // is edited, and not without an agent.
        let boxed = self.ask.is_some() || self.prompt.is_some() || self.save.is_some();
        if boxed || self.takes_text() {
            return h;
        }
        let word = match &self.chat {
            Some(c) => c.hidden_word(),
            None if sentry_core::claude::available() => "wizard",
            None => return h,
        };
        // After what the screen itself does, before what is always there.
        let always = ["s", "c", "e", "u", "?", "q"];
        let at = h
            .iter()
            .position(|(k, _)| always.contains(k) && *k != "s")
            .unwrap_or(h.len());
        let mut out = h;
        out.insert(at, ("A", word));
        out
    }

    /// The hints as the key bar has room for them: where they don't all fit, the wizard's
    /// is the first to go (every other one is a key of what is in view; `?` still says it).
    pub(crate) fn hints_in(&self, room: usize) -> Hints<'static> {
        let mut h = self.hints();
        let width: usize = h
            .iter()
            .map(|(k, d)| k.chars().count() + d.chars().count() + 5)
            .sum();
        if width > room && !self.wizard_visible() {
            h.retain(|(k, d)| !(*k == "A" && *d == "wizard"));
        }
        h
    }

    /// The hints of what is in front, the wizard aside.
    fn hints_behind(&self) -> Hints<'static> {
        if let Some(a) = &self.ask {
            return vec![("Enter", a.enter), ("Esc", "back")];
        }
        if self.prompt.is_some() {
            return vec![("Enter", "do it"), ("Esc", "leave it")];
        }
        if let Some(b) = &self.save {
            return match b.refused {
                true => vec![("Esc", "back")],
                false => vec![("Enter", "save"), ("Esc", "back"), ("j/k", "scroll")],
            };
        }
        if let Some(r) = &self.row {
            let mut h = r.form.hints();
            if !r.form.captures() {
                h.retain(|(k, _)| *k != "Esc");
                h.push(("Esc", "back to the list"));
            }
            return h;
        }
        if self.page == Page::None
            && let Some(f) = self.form.as_ref().filter(|f| f.captures())
        {
            return f.hints();
        }
        let guide = self.step_hints();
        let mut h: Hints<'static> = match self.page {
            Page::Add => {
                let mut h = self
                    .add
                    .as_ref()
                    .map(|a| a.list.hints())
                    .unwrap_or_default();
                h.push(("n", "by name"));
                if guide.is_empty() {
                    h.extend([("Enter", "look · go on"), ("Esc", "back")]);
                }
                h
            }
            Page::Review => {
                let mut h = match &self.review {
                    Some(r) if r.naming => vec![("Space", "edit")],
                    Some(r) => r.list.hints(),
                    None => Vec::new(),
                };
                if guide.is_empty() {
                    h.extend([("Enter", "go on"), ("Esc", "back")]);
                }
                h
            }
            Page::Routine => self.routine.as_ref().map(|l| l.hints()).unwrap_or_default(),
            Page::Shown => {
                let mut h = self.shown.as_ref().map(|l| l.hints()).unwrap_or_default();
                h.extend([("Enter", "stage it"), ("Esc", "back")]);
                h
            }
            Page::None => match self.screen {
                Screen::Overview => {
                    vec![("Enter", "open"), ("Space", "tick"), ("x", "remove")]
                }
                Screen::Servers | Screen::Networks if !self.open => {
                    vec![("Enter", "its settings"), ("x", "remove")]
                }
                _ => match &self.form {
                    Some(f) => {
                        let mut h = f.hints();
                        h.retain(|(k, _)| *k != "j/k");
                        if !guide.is_empty() {
                            h.retain(|(k, _)| *k != "Enter" && *k != "Esc");
                            h.push(("Space", "edit · toggle"));
                        }
                        if self.field_path().as_deref() == Some("targets.show") {
                            h.push(("Space", "which show"));
                        }
                        if self
                            .upkeep_here()
                            .is_some_and(|(_, _, row, _)| row.path.is_some())
                        {
                            h.push(("o", "its own copy"));
                        }
                        if self
                            .field_path()
                            .and_then(|p| self.kind(FileId::of_path(&p))?.action(&p))
                            .is_some()
                        {
                            h.push(("K", "make a key"));
                        }
                        h
                    }
                    None => vec![("Esc", "back")],
                },
            },
        };
        if self.screen == Screen::Agent && self.page == Page::None {
            h.push(("t", "test it"));
        }
        if !guide.is_empty() {
            let mut all = guide;
            all.extend(h);
            all.extend([("?", "help"), ("q", "quit")]);
            return all;
        }
        if self.page != Page::None {
            h.extend([("?", "help"), ("q", "quit")]);
            return h;
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
                } else if on(&[
                    "review",
                    "maintenance",
                    "ui",
                    "cache",
                    "audit",
                    "flatpak",
                    "jobs",
                    "cleanup",
                    "recorder",
                    "baseline",
                ]) {
                    Screen::Machine
                } else {
                    Screen::Window
                }
            }
        }
    }
}

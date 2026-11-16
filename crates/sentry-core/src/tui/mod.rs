//! The TUI kit both apps are built on: terminal lifecycle, event loop, input thread, and the
//! shared widgets, chat, documents, Maintenance list and Records.
//!
//! One main thread owns all state. An input thread forwards key events; background fetches and
//! streamed commands send `Event`s over the same channel. There is no ticker thread: the loop
//! sleeps until the active screen's next refresh is due, so idle screens cost ~nothing.

pub mod applyview;
pub mod chat;
pub mod docview;
pub mod frame;
pub mod input;
pub mod keys;
pub mod maintlist;
pub mod modal;
pub mod records;
pub mod reviewview;
pub mod theme;
pub mod widgets;
// The screens both programs show the same way.
pub mod histview;
pub mod netview;
pub mod proctable;

use std::io;
use std::process::ExitStatus;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event as CEvent, KeyEvent, KeyEventKind};
use ratatui::crossterm::{cursor, execute, terminal};
use ratatui::{DefaultTerminal, Frame};

use crate::exec::{Cmd, ExecError};

/// What the terminal itself produces, for any TUI built on [`run_ui`].
pub enum Input {
    Key(KeyEvent),
    /// Text pasted into the terminal, whole (bracketed paste).
    Paste(String),
    Resize,
    Signal,
}

/// An app [`run_ui`] can drive: it owns all state on the main thread and is told about
/// events; the loop sleeps until `next_due`, so nothing runs while nothing is due.
pub trait Ui {
    type Ev: From<Input> + Send + 'static;
    fn start(&mut self, now: Instant);
    /// Something changed since the last draw.
    fn dirty(&self) -> bool;
    fn draw(&mut self, f: &mut Frame);
    /// A command that needs the real terminal (sudo prompts, less, $EDITOR), with a banner.
    fn take_suspend(&mut self) -> Option<(Cmd, String)>;
    fn after_suspend(&mut self, status: Result<ExitStatus, ExecError>);
    fn quitting(&self) -> bool;
    fn shutdown(&mut self);
    fn next_due(&self, now: Instant) -> Instant;
    fn on_event(&mut self, ev: Self::Ev, now: Instant);
    fn tick(&mut self, now: Instant);
}

/// Every screen either program has. Each declares its own in a [`ScreenSet`]: the keys and
/// names are the same wherever two screens are the same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScreenId {
    Dash,
    Proc,
    Net,
    Cont,
    /// This machine's Flatpaks (`5` in sentry).
    Flat,
    /// A server's services and timers (`5` in sentry-server).
    Svc,
    Maint,
    Clean,
    Upgrade,
    Hist,
}

impl ScreenId {
    pub const ALL: [ScreenId; 10] = [
        ScreenId::Dash,
        ScreenId::Proc,
        ScreenId::Net,
        ScreenId::Cont,
        ScreenId::Flat,
        ScreenId::Svc,
        ScreenId::Maint,
        ScreenId::Clean,
        ScreenId::Upgrade,
        ScreenId::Hist,
    ];

    pub fn key(self) -> char {
        match self {
            ScreenId::Dash => '1',
            ScreenId::Proc => '2',
            ScreenId::Net => '3',
            ScreenId::Cont => '4',
            ScreenId::Flat | ScreenId::Svc => '5',
            ScreenId::Maint => '6',
            ScreenId::Clean => '7',
            ScreenId::Upgrade => '0',
            ScreenId::Hist => 'H',
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ScreenId::Dash => "Dashboard",
            ScreenId::Proc => "Processes",
            ScreenId::Net => "Network",
            ScreenId::Cont => "Containers",
            ScreenId::Flat => "Flatpaks",
            ScreenId::Svc => "Services",
            ScreenId::Maint => "Maintenance",
            ScreenId::Clean => "Cleanup",
            ScreenId::Upgrade => "Upgrade",
            ScreenId::Hist => "History",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            ScreenId::Dash => "Dash",
            ScreenId::Proc => "Proc",
            ScreenId::Net => "Net",
            ScreenId::Cont => "Cont",
            ScreenId::Flat => "Flat",
            ScreenId::Svc => "Svc",
            ScreenId::Maint => "Maint",
            ScreenId::Clean => "Clean",
            ScreenId::Upgrade => "Upgr",
            ScreenId::Hist => "Hist",
        }
    }

    /// Lowercase name used by `:` commands and `[keys] screen.<slug>`.
    pub fn slug(self) -> &'static str {
        match self {
            ScreenId::Dash => "dashboard",
            ScreenId::Proc => "processes",
            ScreenId::Net => "network",
            ScreenId::Cont => "containers",
            ScreenId::Flat => "flatpaks",
            ScreenId::Svc => "services",
            ScreenId::Maint => "maintenance",
            ScreenId::Clean => "cleanup",
            ScreenId::Upgrade => "upgrade",
            ScreenId::Hist => "history",
        }
    }
}

/// The screens one program has, in strip order, and other names `:` takes for them.
#[derive(Debug, Clone, Copy)]
pub struct ScreenSet {
    pub ids: &'static [ScreenId],
    pub aliases: &'static [(&'static str, ScreenId)],
}

impl ScreenSet {
    pub fn contains(&self, id: ScreenId) -> bool {
        self.ids.contains(&id)
    }

    /// A screen by its slug, short name or an alias (any case); else by the start of its
    /// slug, three letters or more, when only one screen starts so.
    pub fn from_name(&self, s: &str) -> Option<ScreenId> {
        let s = s.to_ascii_lowercase();
        if let Some(id) = self
            .ids
            .iter()
            .copied()
            .find(|id| id.slug() == s || id.short().to_ascii_lowercase() == s)
        {
            return Some(id);
        }
        if let Some((_, id)) = self.aliases.iter().find(|(a, _)| *a == s) {
            return Some(*id);
        }
        if s.len() < 3 {
            return None;
        }
        let mut starts = self
            .ids
            .iter()
            .copied()
            .filter(|id| id.slug().starts_with(&s));
        match (starts.next(), starts.next()) {
            (Some(id), None) => Some(id),
            _ => None,
        }
    }
}

/// List cursor shared by every table screen.
#[derive(Debug, Default, Clone, Copy)]
pub struct Cursor {
    pub sel: usize,
    pub page: usize,
}

impl Cursor {
    /// Apply a navigation action; returns true if it was one.
    pub fn nav(&mut self, a: keys::Action, len: usize) -> bool {
        use keys::Action;
        let page = self.page.max(1);
        let last = len.saturating_sub(1);
        self.sel = match a {
            Action::Down => (self.sel + 1).min(last),
            Action::Up => self.sel.saturating_sub(1),
            Action::Top => 0,
            Action::Bottom => last,
            Action::PageDown => (self.sel + page / 2).min(last),
            Action::PageUp => self.sel.saturating_sub(page / 2),
            // Rows are already filtered, so n/N just walk the matches with wrap-around.
            Action::NextMatch if len > 0 => (self.sel + 1) % len,
            Action::PrevMatch if len > 0 => (self.sel + len - 1) % len,
            _ => return false,
        };
        true
    }

    pub fn clamp(&mut self, len: usize) -> usize {
        self.sel = self.sel.min(len.saturating_sub(1));
        self.sel
    }
}

/// Control messages for the input thread (pause while a child owns the terminal).
enum InputCtl {
    Pause(SyncSender<()>),
    Resume,
}

fn spawn_input<E: From<Input> + Send + 'static>(tx: Sender<E>, ctl: Receiver<InputCtl>) {
    std::thread::spawn(move || {
        loop {
            match ctl.try_recv() {
                Ok(InputCtl::Pause(ack)) => {
                    let _ = ack.send(());
                    // Block until resumed; any other message is a resume too.
                    if ctl.recv().is_err() {
                        return;
                    }
                }
                Ok(InputCtl::Resume) => {}
                Err(mpsc::TryRecvError::Disconnected) => return,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if !event::poll(Duration::from_millis(100)).unwrap_or(false) {
                continue;
            }
            let ev = match event::read() {
                Ok(CEvent::Key(k)) if k.kind != KeyEventKind::Release => Input::Key(k),
                Ok(CEvent::Paste(text)) => Input::Paste(text),
                Ok(CEvent::Resize(..)) => Input::Resize,
                Ok(_) => continue,
                Err(_) => return,
            };
            if tx.send(E::from(ev)).is_err() {
                return;
            }
        }
    });
}

fn spawn_signals<E: From<Input> + Send + 'static>(tx: Sender<E>) {
    use signal_hook::consts::{SIGHUP, SIGTERM};
    let Ok(mut signals) = signal_hook::iterator::Signals::new([SIGTERM, SIGHUP]) else {
        return;
    };
    std::thread::spawn(move || {
        if signals.forever().next().is_some() {
            let _ = tx.send(E::from(Input::Signal));
        }
    });
}

pub struct Term {
    terminal: DefaultTerminal,
    input: Sender<InputCtl>,
}

impl Term {
    /// Hand the terminal to an interactive child, then take it back.
    pub fn suspend<R>(&mut self, f: impl FnOnce() -> R) -> io::Result<R> {
        let (ack_tx, ack_rx) = mpsc::sync_channel(0);
        let _ = self.input.send(InputCtl::Pause(ack_tx));
        let _ = ack_rx.recv_timeout(Duration::from_millis(500));
        terminal::disable_raw_mode()?;
        execute!(
            io::stdout(),
            event::DisableBracketedPaste,
            terminal::LeaveAlternateScreen,
            cursor::Show
        )?;
        let r = f();
        terminal::enable_raw_mode()?;
        execute!(
            io::stdout(),
            terminal::EnterAlternateScreen,
            cursor::Hide,
            event::EnableBracketedPaste
        )?;
        self.terminal.clear()?;
        let _ = self.input.send(InputCtl::Resume);
        Ok(r)
    }
}

/// Set up the terminal, the input and signal threads, run `make`'s app until it quits, and
/// restore the terminal.
pub fn run_ui<U: Ui>(make: impl FnOnce(Sender<U::Ev>) -> U) -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel();
    let (ctl_tx, ctl_rx) = mpsc::channel();
    // ratatui::try_init installs a panic hook that restores the terminal first.
    let terminal = ratatui::try_init()?;
    // A paste arrives whole, not as keys (a newline in it would be Enter). Undone on the way
    // out, a panic's too, or the shell would get the markers around its pastes.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(io::stdout(), event::DisableBracketedPaste);
        hook(info);
    }));
    execute!(io::stdout(), event::EnableBracketedPaste)?;
    let mut term = Term {
        terminal,
        input: ctl_tx,
    };
    spawn_input(tx.clone(), ctl_rx);
    spawn_signals(tx.clone());

    let mut app = make(tx);
    let result = event_loop(&mut term, &mut app, &rx);
    let _ = execute!(io::stdout(), event::DisableBracketedPaste);
    ratatui::restore();
    result
}

fn event_loop<U: Ui>(term: &mut Term, app: &mut U, rx: &Receiver<U::Ev>) -> anyhow::Result<()> {
    app.start(Instant::now());
    let mut drawn = false;
    loop {
        if app.dirty() || !drawn {
            term.terminal.draw(|f| app.draw(f))?;
            drawn = true;
        }
        if let Some((cmd, banner)) = app.take_suspend() {
            let status = term.suspend(|| {
                println!("{banner}");
                cmd.interactive()
            })?;
            app.after_suspend(status);
            // The screen was cleared coming back: draw it now, not at the next change (which
            // may be a long way off while a workflow waits for Enter).
            drawn = false;
            continue;
        }
        if app.quitting() {
            app.shutdown();
            return Ok(());
        }
        let now = Instant::now();
        let wait = app.next_due(now).saturating_duration_since(now);
        match rx.recv_timeout(wait) {
            Ok(ev) => {
                app.on_event(ev, Instant::now());
                // Drain whatever else is queued before redrawing.
                while let Ok(ev) = rx.try_recv() {
                    app.on_event(ev, Instant::now());
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
        app.tick(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screens_by_slug_short_alias_and_prefix() {
        use ScreenId::*;
        let set = ScreenSet {
            ids: &[Dash, Cont, Svc, Maint, Upgrade],
            aliases: &[("overview", Dash), ("run", Upgrade)],
        };
        assert_eq!(set.from_name("maintenance"), Some(Maint));
        assert_eq!(set.from_name("Maint"), Some(Maint));
        assert_eq!(set.from_name("overview"), Some(Dash));
        assert_eq!(set.from_name("ser"), Some(Svc));
        assert_eq!(set.from_name("mai"), Some(Maint));
        // Too short, not this program's, or nothing.
        assert_eq!(set.from_name("ma"), None);
        assert_eq!(set.from_name("flatpaks"), None);
        assert_eq!(set.from_name("nope"), None);
        // Two screens start so: neither.
        let both = ScreenSet {
            ids: &[Cont, Clean],
            aliases: &[],
        };
        assert_eq!(both.from_name("c"), None);
        assert_eq!(both.from_name("cle"), Some(Clean));
        assert!(set.contains(Svc) && !set.contains(Flat));
        assert_eq!((Svc.key(), Flat.key()), ('5', '5'));
    }
}

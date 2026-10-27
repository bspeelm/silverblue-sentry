//! The TUI: terminal lifecycle, event loop, input thread.
//!
//! One main thread owns all state. An input thread forwards key events; background fetches and
//! streamed commands send `Event`s over the same channel. There is no ticker thread: the loop
//! sleeps until the active screen's next refresh is due, so idle screens cost ~nothing.

mod app;
pub(crate) mod chat;
mod data;
pub(crate) mod docview;
pub(crate) mod keys;
pub(crate) mod modal;
mod screens;
pub(crate) mod theme;
mod wf;
pub(crate) mod widgets;

use std::io;
use std::process::ExitStatus;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event as CEvent, KeyEvent, KeyEventKind};
use ratatui::crossterm::{cursor, execute, terminal};
use ratatui::{DefaultTerminal, Frame};

use crate::exec::{Cmd, ExecError, StreamMsg};
pub use data::{Fetch, FetchErr, Payload};

/// What the terminal itself produces, for any TUI built on [`run_ui`].
pub enum Input {
    Key(KeyEvent),
    Resize,
    Signal,
}

impl From<Input> for Event {
    fn from(i: Input) -> Self {
        match i {
            Input::Key(k) => Event::Key(k),
            Input::Resize => Event::Resize,
            Input::Signal => Event::Signal,
        }
    }
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

pub enum Event {
    Key(KeyEvent),
    Resize,
    Data(Fetch, Box<Result<Payload, FetchErr>>),
    Run(u64, StreamMsg),
    Signal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScreenId {
    Dash,
    Proc,
    Net,
    Upd,
    Cont,
    Flat,
    Audit,
    Jobs,
    Clean,
    Upgrade,
    Hist,
}

impl ScreenId {
    pub const ALL: [ScreenId; 11] = [
        ScreenId::Dash,
        ScreenId::Proc,
        ScreenId::Net,
        ScreenId::Upd,
        ScreenId::Cont,
        ScreenId::Flat,
        ScreenId::Audit,
        ScreenId::Jobs,
        ScreenId::Clean,
        ScreenId::Upgrade,
        ScreenId::Hist,
    ];

    pub fn key(self) -> char {
        match self {
            ScreenId::Dash => '1',
            ScreenId::Proc => '2',
            ScreenId::Net => '3',
            ScreenId::Upd => '4',
            ScreenId::Cont => '5',
            ScreenId::Flat => '6',
            ScreenId::Audit => '7',
            ScreenId::Jobs => '8',
            ScreenId::Clean => '9',
            ScreenId::Upgrade => '0',
            ScreenId::Hist => 'H',
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ScreenId::Dash => "Dashboard",
            ScreenId::Proc => "Processes",
            ScreenId::Net => "Network",
            ScreenId::Upd => "Updates",
            ScreenId::Cont => "Containers",
            ScreenId::Flat => "Flatpaks",
            ScreenId::Audit => "Audit",
            ScreenId::Jobs => "Jobs",
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
            ScreenId::Upd => "Upd",
            ScreenId::Cont => "Cont",
            ScreenId::Flat => "Flat",
            ScreenId::Audit => "Audit",
            ScreenId::Jobs => "Jobs",
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
            ScreenId::Upd => "updates",
            ScreenId::Cont => "containers",
            ScreenId::Flat => "flatpaks",
            ScreenId::Audit => "audit",
            ScreenId::Jobs => "jobs",
            ScreenId::Clean => "cleanup",
            ScreenId::Upgrade => "upgrade",
            ScreenId::Hist => "history",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        let s = s.to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|id| id.slug() == s || id.short().to_ascii_lowercase() == s)
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
        execute!(io::stdout(), terminal::LeaveAlternateScreen, cursor::Show)?;
        let r = f();
        terminal::enable_raw_mode()?;
        execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide)?;
        self.terminal.clear()?;
        let _ = self.input.send(InputCtl::Resume);
        Ok(r)
    }
}

pub fn run() -> anyhow::Result<()> {
    run_ui(app::App::new)
}

/// Set up the terminal, the input and signal threads, run `make`'s app until it quits, and
/// restore the terminal.
pub fn run_ui<U: Ui>(make: impl FnOnce(Sender<U::Ev>) -> U) -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel();
    let (ctl_tx, ctl_rx) = mpsc::channel();
    // ratatui::try_init installs a panic hook that restores the terminal first.
    let terminal = ratatui::try_init()?;
    let mut term = Term {
        terminal,
        input: ctl_tx,
    };
    spawn_input(tx.clone(), ctl_rx);
    spawn_signals(tx.clone());

    let mut app = make(tx);
    let result = event_loop(&mut term, &mut app, &rx);
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

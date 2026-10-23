//! The TUI: terminal lifecycle, event loop, input thread.
//!
//! One main thread owns all state. An input thread forwards key events; background fetches and
//! streamed commands send `Event`s over the same channel. There is no ticker thread: the loop
//! sleeps until the active screen's next refresh is due, so idle screens cost ~nothing.

mod app;
mod data;
mod keys;
mod screens;
mod theme;
mod widgets;

use std::io;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event as CEvent, KeyEvent, KeyEventKind};
use ratatui::crossterm::{cursor, execute, terminal};

use crate::exec::StreamMsg;
pub use data::{Fetch, FetchErr, Payload};

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

fn spawn_input(tx: Sender<Event>, ctl: Receiver<InputCtl>) {
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
                Ok(CEvent::Key(k)) if k.kind != KeyEventKind::Release => Event::Key(k),
                Ok(CEvent::Resize(..)) => Event::Resize,
                Ok(_) => continue,
                Err(_) => return,
            };
            if tx.send(ev).is_err() {
                return;
            }
        }
    });
}

fn spawn_signals(tx: Sender<Event>) {
    use signal_hook::consts::{SIGHUP, SIGTERM};
    let Ok(mut signals) = signal_hook::iterator::Signals::new([SIGTERM, SIGHUP]) else {
        return;
    };
    std::thread::spawn(move || {
        if signals.forever().next().is_some() {
            let _ = tx.send(Event::Signal);
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

    let mut app = app::App::new(tx);
    let result = event_loop(&mut term, &mut app, &rx);
    ratatui::restore();
    result
}

fn event_loop(term: &mut Term, app: &mut app::App, rx: &Receiver<Event>) -> anyhow::Result<()> {
    app.start(Instant::now());
    loop {
        if app.dirty {
            term.terminal.draw(|f| app.draw(f))?;
            app.dirty = false;
        }
        if let Some(cmd) = app.take_suspend() {
            let title = cmd.display();
            let status = term.suspend(|| {
                println!("$ {title}");
                cmd.interactive()
            })?;
            app.after_suspend(status);
            continue;
        }
        if app.quit {
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

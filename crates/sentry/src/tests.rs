//! The one window with two targets in it: this machine and the synthetic `myserver`. Nothing
//! is fetched, written or sent (`win.offline`); the records and run state are in the scratch
//! dirs every test process gets.

use std::time::Instant;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use sentry_app::app::render_to_string;
use sentry_app::{App, Event, Needs};
use sentry_core::tui::ScreenId;
use sentry_server::remote::Remote;

const SERVER: &str = "myserver";

/// This machine alone, as `sentry` is without a server.
fn one() -> App {
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut a = App::new(
        tx,
        sentry_local::tui::ID,
        sentry_local::tui::testing::target(Default::default()),
    );
    a.win.offline = true;
    a.win.theme = sentry_core::tui::theme::Theme::truecolor();
    a.win.now_override = Some("2026-10-26T12:00:00Z".parse().unwrap());
    // (A screen that samples nothing: the tests look at the frame around it.)
    a.slots[0].screen = ScreenId::Upgrade;
    a
}

/// This machine (in view) and `myserver`, whose sudo doesn't ask.
fn two() -> App {
    let mut a = one();
    let id = sentry_server::tui::id_of(SERVER);
    a.add(
        &id,
        sentry_server::tui::target(Remote::new(SERVER, &Default::default())),
    );
    a.on_event(
        sentry_server::tui::testing::sudo_ev(SERVER, false),
        Instant::now(),
    );
    a
}

fn key(a: &mut App, c: KeyCode) {
    a.on_event(
        Event::Key(KeyEvent::new(c, KeyModifiers::NONE)),
        Instant::now(),
    );
}

fn ctrl(a: &mut App, c: char) {
    a.on_event(
        Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)),
        Instant::now(),
    );
}

fn typed(a: &mut App, text: &str) {
    for c in text.chars() {
        key(a, KeyCode::Char(c));
    }
}

fn screen(a: &mut App) -> String {
    render_to_string(a, 158, 41)
}

/// The top bar's row, without what changes from run to run (how long this machine is up).
fn top(a: &mut App, w: u16) -> String {
    let s = render_to_string(a, w, 41);
    let row = s.lines().next().unwrap_or_default();
    match row.split_once("  up ") {
        // (`up 3d 04:12` ends where the gap before the right-hand side begins.)
        Some((left, rest)) => match rest.split_once("  ") {
            Some((_, right)) => format!("{left}  up …  {}", right.trim_start()),
            None => format!("{left}  up …"),
        },
        None => row.to_string(),
    }
}

#[test]
fn one_target_has_no_strip() {
    let mut a = one();
    let row = top(&mut a, 158);
    assert!(
        row.starts_with(" sentry   silverblue 44.1  kernel 7.2.8-200.fc44.x86_64"),
        "{row}"
    );
    assert!(!row.contains("F1"), "{row}");
    // The window's target keys do nothing here, and `:local` is where it already is.
    key(&mut a, KeyCode::F(2));
    key(&mut a, KeyCode::Char('}'));
    assert_eq!(a.focus, 0);
    typed(&mut a, ":local");
    key(&mut a, KeyCode::Enter);
    assert_eq!((a.focus, a.toast_for_test()), (0, None));
    typed(&mut a, ":server my");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.toast_for_test(), Some("unknown command :server my"));
}

#[test]
fn the_strip_names_each_target_and_its_keys_give_it_the_window() {
    let mut a = two();
    insta::assert_snapshot!("strip_two_targets_158", top(&mut a, 158));
    // The screen strip and the digits are the target's in view: this machine has Flatpaks.
    let s = screen(&mut a);
    assert!(s.lines().nth(1).unwrap().contains("5 Flatpaks"), "{s}");
    // F2: the server, with its own screens.
    key(&mut a, KeyCode::F(2));
    assert_eq!(a.focus, 1);
    let s = screen(&mut a);
    let tabs = s.lines().nth(1).unwrap();
    assert!(
        tabs.contains("5 Services") && !tabs.contains("Flatpaks") && !tabs.contains("7 Cleanup"),
        "{s}"
    );
    insta::assert_snapshot!("strip_server_in_view_158", top(&mut a, 158));
    key(&mut a, KeyCode::Char('5'));
    assert_eq!(a.slot().screen, ScreenId::Svc);
    // This machine kept its screen meanwhile; `7` is nothing on the server.
    key(&mut a, KeyCode::Char('7'));
    assert_eq!(a.slot().screen, ScreenId::Svc);
    key(&mut a, KeyCode::F(1));
    assert_eq!((a.focus, a.slot().screen), (0, ScreenId::Upgrade));
    key(&mut a, KeyCode::Char('5'));
    assert_eq!(a.slot().screen, ScreenId::Flat);
    // } and { go round; a place nobody has does nothing.
    key(&mut a, KeyCode::Char('}'));
    assert_eq!((a.focus, a.slot().screen), (1, ScreenId::Svc));
    key(&mut a, KeyCode::Char('}'));
    assert_eq!(a.focus, 0);
    key(&mut a, KeyCode::Char('{'));
    assert_eq!(a.focus, 1);
    key(&mut a, KeyCode::F(5));
    assert_eq!(a.focus, 1);
    // By name: `:local`, `:server <the start of its name>`.
    typed(&mut a, ":local");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.focus, 0);
    typed(&mut a, ":server mys");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.focus, 1);
    typed(&mut a, ":server zz");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.focus, 1);
    assert_eq!(a.toast_for_test(), Some("unknown command :server zz"));
    // A screen's own name still goes to the screen.
    typed(&mut a, ":maintenance");
    key(&mut a, KeyCode::Enter);
    assert_eq!((a.focus, a.slot().screen), (1, ScreenId::Maint));
}

#[test]
fn the_strip_fits_a_narrow_terminal() {
    let mut a = two();
    insta::assert_snapshot!("strip_two_targets_80", top(&mut a, 80));
}

#[test]
fn target_keys_can_be_rebound() {
    let mut a = two();
    let mut o = std::collections::BTreeMap::new();
    o.insert("target.next".to_string(), "C-n".to_string());
    o.insert("target.1".to_string(), "F7".to_string());
    assert!(a.set_keys_for_test(&o).is_empty());
    ctrl(&mut a, 'n');
    assert_eq!(a.focus, 1);
    // (The server's keymap is its own: the defaults.)
    key(&mut a, KeyCode::F(1));
    assert_eq!(a.focus, 0);
    key(&mut a, KeyCode::Char('}'));
    assert_eq!(a.focus, 0, "the brace was unbound here");
    key(&mut a, KeyCode::F(2));
    key(&mut a, KeyCode::F(7));
    assert_eq!(
        a.focus, 1,
        "F7 is this machine's key only in its own keymap"
    );
}

#[test]
fn a_target_starts_when_it_first_has_the_window() {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(
        tx,
        sentry_local::tui::ID,
        sentry_local::tui::testing::target(Default::default()),
    );
    a.win.offline = true;
    a.slots[0].screen = ScreenId::Upgrade;
    let id = sentry_server::tui::id_of(SERVER);
    a.add(
        &id,
        sentry_server::tui::target(Remote::new(SERVER, &Default::default())),
    );
    let now = Instant::now();
    a.start(now);
    assert!(a.started_at(0) && !a.started_at(1));
    // Time passes, this machine's screens come and go: nothing of the server's moves, and
    // nothing asks to be woken for it.
    for _ in 0..3 {
        a.tick(Instant::now());
    }
    key(&mut a, KeyCode::Char('0'));
    assert!(!a.started_at(1));
    assert_eq!(a.needs(1), Needs::Nothing);
    // Whatever arrives is this machine's own (its state files, read at start).
    std::thread::sleep(std::time::Duration::from_millis(300));
    while let Ok(ev) = rx.try_recv() {
        match ev {
            Event::Data(t, _) | Event::Stream(t, ..) | Event::Text(t, ..) => {
                assert_eq!(
                    t,
                    sentry_local::tui::ID,
                    "an event for a target never in view"
                )
            }
            _ => {}
        }
    }
    let srv = &a.slots[1];
    assert!(srv.shared.log.is_empty() && srv.run.is_none());
    // In view: it starts, on its Dashboard.
    key(&mut a, KeyCode::F(2));
    assert!(a.started_at(1));
    assert_eq!(a.slot().screen, ScreenId::Dash);
}

#[test]
fn a_prompt_stays_with_its_target_while_another_is_in_view() {
    let mut a = two();
    // A filter being typed on this machine's Flatpaks.
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::Char('/'));
    typed(&mut a, "org.gnome");
    // A character that is a target key is text here; an F-key is the window's everywhere.
    typed(&mut a, "{}");
    assert_eq!(a.focus, 0);
    assert!(screen(&mut a).contains("/org.gnome{}"));
    key(&mut a, KeyCode::F(2));
    assert_eq!(a.focus, 1);
    let s = screen(&mut a);
    assert!(!s.contains("org.gnome"), "the line is this machine's: {s}");
    // The server's own line meanwhile.
    key(&mut a, KeyCode::Char(':'));
    typed(&mut a, "wor");
    key(&mut a, KeyCode::F(1));
    let s = screen(&mut a);
    assert!(s.contains("/org.gnome{}") && !s.contains(":wor"), "{s}");
    // Back on the server: its line as it was left, and it still works.
    key(&mut a, KeyCode::F(2));
    assert!(screen(&mut a).lines().last().unwrap().contains(":wor"));
    typed(&mut a, "kflow");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.slot().screen, ScreenId::Upgrade);
}

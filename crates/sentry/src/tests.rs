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

// ---------------------------------------------------------------- work on two targets at once

use sentry_app::effect::Effect;
use sentry_core::workflows::runner::Next;

/// This machine's runs share one place: the tests that start one take turns.
static LOCAL_RUNS: std::sync::Mutex<()> = std::sync::Mutex::new(());

const LOCAL: usize = 0;
const SRV: usize = 1;

/// This machine and a server of this name (each test its own: their runs are kept by name).
fn two_with(server: &str, sudo_asks: bool) -> App {
    let mut a = one();
    a.add(
        &sentry_server::tui::id_of(server),
        sentry_server::tui::target(Remote::new(server, &Default::default())),
    );
    a.on_event(
        sentry_server::tui::testing::sudo_ev(server, sudo_asks),
        Instant::now(),
    );
    a
}

/// A workflow of this machine's, in its (scratch) workflows directory. Whoever holds the
/// guard has this machine's runs to itself.
fn local_wf(name: &str, steps: &str) -> std::sync::MutexGuard<'static, ()> {
    let turn = LOCAL_RUNS.lock().unwrap_or_else(|e| e.into_inner());
    let _ = std::fs::remove_dir_all(sentry_core::workflows::state::root());
    let dir = sentry_local::workflows::dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{name}.toml")),
        format!("name = \"{name}\"\ndescription = \"test\"\n{steps}"),
    )
    .unwrap();
    turn
}

/// A workflow of the server's own (in its scratch directory), known to its slot.
fn server_wf(a: &mut App, server: &str, name: &str, steps: &str) {
    let _ = std::fs::remove_dir_all(sentry_server::workflow::root(server));
    let text = format!("name = \"{name}\"\ndescription = \"test\"\n{steps}");
    let path = sentry_core::paths::config_dir().join(format!("{server}-{name}.toml"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &text).unwrap();
    a.set_wf_entries_at(
        SRV,
        vec![sentry_core::workflows::Entry {
            name: name.to_string(),
            path,
            wf: sentry_core::workflows::parse(&text),
            issues: Vec::new(),
        }],
    );
}

fn step(id: &str, gate: &str, run: &str) -> String {
    format!("[[steps]]\nid = \"{id}\"\ntitle = \"{id}\"\nrun = \"{run}\"\ngate = \"{gate}\"\n")
}

/// Where the run in slot `i` stands: (its next step, whether one is running, done).
fn run_at(a: &App, i: usize) -> (Next, bool, bool) {
    let r = a.slots[i].run.as_ref().expect("a run");
    (r.next().clone(), r.live().is_some(), r.done())
}

fn begin(a: &mut App, i: usize, name: &str) {
    a.apply_at(i, vec![Effect::StartWorkflow(name.to_string())]);
    assert!(a.slots[i].run.is_some(), "{name} started");
}

#[test]
fn two_workflows_run_at_once_and_end_independently() {
    let mut a = two_with("par", false);
    let _turn = local_wf(
        "harmless-local",
        &(step("one", "auto", "true") + &step("two", "auto", "true")),
    );
    server_wf(
        &mut a,
        "par",
        "harmless-server",
        &(step("a", "auto", "true") + &step("b", "auto", "true")),
    );
    // This machine's, started here; the server's, started over there and then left.
    begin(&mut a, LOCAL, "harmless-local");
    key(&mut a, KeyCode::F(2));
    begin(&mut a, SRV, "harmless-server");
    key(&mut a, KeyCode::F(1));
    assert_eq!(run_at(&a, LOCAL), (Next::Run(0), true, false));
    assert_eq!(run_at(&a, SRV), (Next::Run(0), true, false));
    assert_eq!(
        (a.needs(LOCAL), a.needs(SRV)),
        (Needs::Working, Needs::Working)
    );
    insta::assert_snapshot!("strip_both_working_158", top(&mut a, 158));
    // The server's steps end while this machine is in view: its run goes on by itself.
    a.run_step_exit_at(SRV, 0);
    assert_eq!(run_at(&a, SRV), (Next::Run(1), true, false));
    assert_eq!(run_at(&a, LOCAL), (Next::Run(0), true, false), "untouched");
    a.run_step_exit_at(SRV, 0);
    assert!(run_at(&a, SRV).2, "the server's run is through");
    // Its note is asked on its own line, which isn't the one in view; the strip says so.
    assert_eq!(
        a.needs(SRV),
        Needs::You("a note for the log (the run ended)")
    );
    assert_eq!(
        a.toast_for_test(),
        Some("par · needs you: a note for the log (the run ended)")
    );
    assert!(!screen(&mut a).contains("for the maintenance log"));
    // This machine's run is still where it was, and ends on its own.
    a.run_step_exit_at(LOCAL, 0);
    a.run_step_exit_at(LOCAL, 0);
    assert!(run_at(&a, LOCAL).2);
    // Each is in its own log, under its own name.
    let entry = |i: usize| {
        let log = &a.slots[i].shared.log;
        log.iter()
            .map(|e| (e.head.server.clone(), e.head.workflow.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        entry(LOCAL),
        [(String::new(), "harmless-local".to_string())]
    );
    // (The server's is written when its note is answered: nothing is kept in memory there.)
    key(&mut a, KeyCode::F(2));
    assert!(screen(&mut a).contains("harmless-server done · for the maintenance log"));
    typed(&mut a, "fine");
    key(&mut a, KeyCode::Enter);
    let noted = a.slots[SRV].last_log.as_ref().expect("the server's entry");
    assert_eq!(
        (noted.head.server.as_str(), noted.head.workflow.as_str()),
        ("par", "harmless-server")
    );
    assert!(
        a.slots[LOCAL]
            .last_log
            .as_ref()
            .is_none_or(|e| e.head.server.is_empty())
    );
}

#[test]
fn a_confirm_out_of_view_waits_flags_the_strip_and_says_whose() {
    let mut a = two_with("waits", false);
    server_wf(
        &mut a,
        "waits",
        "careful",
        &(step("look", "auto", "true") + &step("change", "confirm", "true")),
    );
    key(&mut a, KeyCode::F(2));
    begin(&mut a, SRV, "careful");
    key(&mut a, KeyCode::F(1));
    assert_eq!(a.toast_for_test(), None);
    a.run_step_exit_at(SRV, 0);
    // The confirm step is up: it waits, the strip flags it, one toast names the target.
    assert_eq!(run_at(&a, SRV), (Next::Confirm(1), false, false));
    assert_eq!(a.needs(SRV), Needs::You("a step to confirm"));
    assert_eq!(
        a.toast_for_test(),
        Some("waits · needs you: a step to confirm")
    );
    insta::assert_snapshot!("strip_needs_you_158", top(&mut a, 158));
    // Said once: time passing doesn't say it again.
    a.win.toast = None;
    a.tick(Instant::now());
    assert_eq!(a.toast_for_test(), None);
    // Enter here is this machine's key: nothing of the server's is answered.
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('y'));
    a.tick(Instant::now());
    assert_eq!(run_at(&a, SRV), (Next::Confirm(1), false, false));
    // In view, Enter is the confirm.
    key(&mut a, KeyCode::F(2));
    assert_eq!(a.slot().screen, ScreenId::Upgrade);
    key(&mut a, KeyCode::Enter);
    assert_eq!(run_at(&a, SRV), (Next::Confirm(1), true, false));
    assert_eq!(a.needs(SRV), Needs::Working);
}

#[test]
fn auto_out_of_view_answers_what_auto_may() {
    let mut a = two_with("autosrv", false);
    server_wf(
        &mut a,
        "autosrv",
        "routine",
        &(step("look", "auto", "true")
            + &step("change", "confirm", "true")
            + "[[steps]]\nid = \"big\"\ntitle = \"big\"\nrun = \"true\"\ngate = \"confirm\"\nrisky = true\n"),
    );
    // Auto goes on over there (C-a is the key of the target in view), then it's left.
    key(&mut a, KeyCode::F(2));
    ctrl(&mut a, 'a');
    assert!(a.slots[SRV].auto && !a.slots[LOCAL].auto);
    begin(&mut a, SRV, "routine");
    key(&mut a, KeyCode::F(1));
    insta::assert_snapshot!("strip_auto_working_158", top(&mut a, 158));
    a.win.toast = None;
    // The confirm step comes up out of view: auto confirms it, and it runs.
    a.run_step_exit_at(SRV, 0);
    assert_eq!(run_at(&a, SRV), (Next::Confirm(1), true, false));
    assert_eq!(a.needs(SRV), Needs::Working);
    assert_eq!(a.toast_for_test(), None);
    // A risky step is never auto's: it waits and flags, as with auto off.
    a.run_step_exit_at(SRV, 0);
    assert_eq!(run_at(&a, SRV), (Next::Confirm(2), false, false));
    assert_eq!(a.needs(SRV), Needs::You("a step to confirm"));
    assert_eq!(
        a.toast_for_test(),
        Some("autosrv · needs you: a step to confirm")
    );
}

#[test]
fn a_password_for_a_target_out_of_view_waits_for_it() {
    // The server's sudo asks for a password.
    let mut a = two_with("pw", true);
    server_wf(
        &mut a,
        "pw",
        "rooted",
        &(step("look", "auto", "true") + &step("root", "auto", "sudo true")),
    );
    key(&mut a, KeyCode::F(2));
    begin(&mut a, SRV, "rooted");
    key(&mut a, KeyCode::F(1));
    a.run_step_exit_at(SRV, 0);
    // The sudo step needs the password: asked for in the server's own slot, which waits.
    let (what, typed_n) = a.unlock_at(SRV).expect("the password is asked for");
    assert_eq!((what.as_str(), typed_n), ("for rooted · step 2", 0));
    assert_eq!(a.needs(SRV), Needs::You("the sudo password"));
    assert_eq!(
        a.toast_for_test(),
        Some("pw · needs you: the sudo password")
    );
    // Nothing typed here reaches it, and this machine's key bar doesn't ask.
    typed(&mut a, "hunter2");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.unlock_at(SRV).map(|u| u.1), Some(0));
    assert!(a.unlock_at(LOCAL).is_none());
    assert!(!screen(&mut a).contains("sudo password"));
    // In view: the prompt names the target, takes the password, and the step runs.
    key(&mut a, KeyCode::F(2));
    let s = screen(&mut a);
    assert!(
        s.lines()
            .last()
            .unwrap()
            .contains("sudo password (pw · for rooted · step 2)"),
        "{s}"
    );
    typed(&mut a, "hunter2");
    key(&mut a, KeyCode::Enter);
    a.unlock_exit_at(SRV, 0);
    assert_eq!(run_at(&a, SRV), (Next::Run(1), true, false));
    // Held for the server only; C-f forgets the one of the target in view.
    key(&mut a, KeyCode::F(1));
    ctrl(&mut a, 'f');
    assert_eq!(a.toast_for_test(), Some("no sudo password is held"));
    key(&mut a, KeyCode::F(2));
    ctrl(&mut a, 'f');
    assert_eq!(a.toast_for_test(), Some("the sudo password is forgotten"));
}

#[test]
fn this_machines_reboot_waits_for_the_other_targets_work() {
    let mut a = two_with("busy", false);
    let _turn = local_wf(
        "restart",
        "[[steps]]\nid = \"reboot\"\ntitle = \"Reboot\"\nkind = \"reboot\"\n",
    );
    server_wf(&mut a, "busy", "long", &step("work", "auto", "true"));
    key(&mut a, KeyCode::F(2));
    begin(&mut a, SRV, "long");
    key(&mut a, KeyCode::F(1));
    begin(&mut a, LOCAL, "restart");
    assert!(matches!(
        run_at(&a, LOCAL).0,
        Next::Reboot {
            requested: false,
            ..
        }
    ));
    // Enter, then its box: the reboot is asked for, and waits for the server's run.
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("reboot now"));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.toast_for_test(), Some("the reboot waits for busy"));
    assert_eq!(a.needs(LOCAL), Needs::Working);
    let log = |a: &mut App| screen(a);
    assert!(log(&mut a).contains("the reboot waits for busy"));
    assert!(!log(&mut a).contains("offline: not rebooting"));
    // Off its screen the banner says for whom.
    key(&mut a, KeyCode::Char('7'));
    let s = screen(&mut a);
    assert!(
        s.lines()
            .nth(3)
            .unwrap()
            .contains("the reboot waits for busy"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('0'));
    a.tick(Instant::now());
    assert!(!log(&mut a).contains("not rebooting"), "still waiting");
    // The server's run ends: nothing there is at work now, and the reboot goes by itself.
    a.run_step_exit_at(SRV, 0);
    assert_ne!(a.needs(SRV), Needs::Working);
    a.tick(Instant::now());
    let s = log(&mut a);
    assert!(
        s.contains("the other targets settled: rebooting") && s.contains("offline: not rebooting"),
        "{s}"
    );
}

#[test]
fn the_quit_box_lists_what_each_target_has_going() {
    let mut a = two_with("quits", false);
    let _turn = local_wf("slow-local", &step("one", "auto", "true"));
    server_wf(&mut a, "quits", "slow-server", &step("a", "auto", "true"));
    // Nothing going: the question alone.
    key(&mut a, KeyCode::Char('q'));
    let s = screen(&mut a);
    assert!(
        s.contains("Quit sentry? Nothing keeps running after exit.") && !s.contains("in progress"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    begin(&mut a, LOCAL, "slow-local");
    key(&mut a, KeyCode::F(2));
    begin(&mut a, SRV, "slow-server");
    key(&mut a, KeyCode::Char('q'));
    let s = screen(&mut a);
    for want in [
        "silverblue 44.1",
        "slow-local is in progress: its state is saved, and it carries on next time",
        "quits",
        "slow-server is in progress: its state is saved, and it carries on next time",
    ] {
        assert!(s.contains(want), "{want}: {s}");
    }
    // Esc: nothing stopped. Enter on it: the window goes, every slot shut down as one is.
    key(&mut a, KeyCode::Esc);
    assert!(!a.win.quit);
    key(&mut a, KeyCode::Char('q'));
    key(&mut a, KeyCode::Enter);
    assert!(a.win.quit);
}

fn task(id: &str, title: &str) -> sentry_core::maint::tasks::Task {
    sentry_core::maint::tasks::Task {
        id: id.into(),
        title: title.into(),
        why: "It is time.".into(),
        level: sentry_core::maint::Level::Soon,
        every: None,
        act: "by-hand".into(),
        item: None,
        steps: "Look at it.".into(),
        added: None,
        off: false,
        source: Default::default(),
        review: None,
        after: None,
        again: None,
    }
}

const PLAN: &str = "On it.\n```sentry-apply\nsummary = \"do it\"\n[[step]]\ntitle = \"Do\"\n\
                    run = \"true\"\n```";
const DONE: &str = "```sentry-verdict\nstatus = \"done\"\nsummary = \"fine\"\n```";

#[test]
fn ticked_rows_are_done_one_after_another_on_each_target() {
    use sentry_core::apply::session::{Phase, Turn};
    let mut a = two_with("rows", false);
    for i in [LOCAL, SRV] {
        a.slots[i].shared.tasks = vec![task("one", "The first"), task("two", "The second")];
        a.slots[i].screen = ScreenId::Maint;
    }
    let rows = || {
        vec![Effect::SeriesStart(vec![
            ("task:one".to_string(), "The first".to_string()),
            ("task:two".to_string(), "The second".to_string()),
        ])]
    };
    // A series on each: both at their first row, each asking its own Claude.
    a.apply_at(LOCAL, rows());
    a.apply_at(SRV, rows());
    let at = |a: &App, i: usize| {
        let s = a.apply_session_at(i).expect("a session");
        (s.series, s.phase)
    };
    for i in [LOCAL, SRV] {
        assert_eq!(
            at(&a, i),
            (Some((1, 2)), Phase::Thinking(Turn::Investigate)),
            "slot {i}"
        );
    }
    // This machine's first row, start to finish, while the server's waits for its answer.
    a.apply_answer_at(LOCAL, PLAN);
    key(&mut a, KeyCode::Enter);
    a.apply_exit_at(LOCAL, 0);
    a.apply_answer_at(LOCAL, DONE);
    assert_eq!(
        at(&a, LOCAL),
        (Some((2, 2)), Phase::Thinking(Turn::Investigate)),
        "its second row opened by itself"
    );
    assert_eq!(at(&a, SRV).0, Some((1, 2)), "the server's is where it was");
    // The server's plan arrives out of view: to approve there, flagged here.
    a.apply_answer_at(SRV, PLAN);
    assert_eq!(a.needs(SRV), Needs::You("a plan to approve"));
    assert_eq!(
        a.toast_for_test(),
        Some("rows · needs you: a plan to approve")
    );
    // Enter here is nothing of the server's.
    assert_eq!(at(&a, SRV).1, Phase::Review);
    // In view: approved, run, verified; its second row follows, this machine's untouched.
    key(&mut a, KeyCode::F(2));
    key(&mut a, KeyCode::Enter);
    while a.apply_session_at(SRV).is_some_and(|s| s.job.is_some())
        || a.slots[SRV].apply_aux_for_test()
    {
        a.apply_exit_at(SRV, 0);
    }
    a.apply_answer_at(SRV, DONE);
    assert_eq!(
        at(&a, SRV),
        (Some((2, 2)), Phase::Thinking(Turn::Investigate))
    );
    assert_eq!(at(&a, LOCAL).0, Some((2, 2)));
}

#[test]
fn target_keys_are_text_in_a_sessions_message() {
    let mut a = two_with("typing", false);
    a.slots[LOCAL].shared.tasks = vec![task("one", "The first")];
    a.slots[LOCAL].screen = ScreenId::Maint;
    a.apply_at(
        LOCAL,
        vec![Effect::SeriesStart(vec![(
            "task:one".to_string(),
            "The first".to_string(),
        )])],
    );
    a.apply_answer_at(LOCAL, PLAN);
    // The session takes what's typed as its message: the braces too.
    typed(&mut a, "use {a} and }b{");
    assert_eq!(a.focus, LOCAL);
    assert_eq!(
        a.apply_session_at(LOCAL).unwrap().chat.input,
        "use {a} and }b{"
    );
    // An F-key is the window's wherever the keys are; the message stays as typed.
    key(&mut a, KeyCode::F(2));
    assert_eq!(a.focus, SRV);
    key(&mut a, KeyCode::F(1));
    assert_eq!(
        a.apply_session_at(LOCAL).unwrap().chat.input,
        "use {a} and }b{"
    );
}

/// This machine and the disposable sshd container side by side (`scripts/live-container.sh
/// test nopasswd live_two_targets`: scratch XDG dirs, `SENTRY_NO_REBOOT=1`): the
/// container's workflow runs and waits for its confirms while this machine is in view and
/// runs a harmless workflow of its own (two `echo`s on the host). Never the real server.
#[test]
#[ignore]
fn live_two_targets() {
    sentry_core::paths::use_real_dirs();
    let Ok(name) = std::env::var("SENTRY_SERVER_SCRATCH") else {
        return;
    };
    // Only ever in scratch dirs: this writes a workflow and a config.toml.
    for var in ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "SENTRY_NO_REBOOT"] {
        assert!(std::env::var(var).is_ok(), "{var} must be set (scratch)");
    }
    let cfg_dir = sentry_core::paths::config_dir();
    std::fs::write(
        cfg_dir.join("config.toml"),
        "[review]\nat_start = false\nafter_run = false\n",
    )
    .unwrap();
    let dir = sentry_local::workflows::dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("two-echoes.toml"),
        "name = \"two-echoes\"\ndescription = \"harmless\"\n".to_string()
            + &step("one", "auto", "sleep 1; echo local-one")
            + &step("two", "auto", "echo local-two"),
    )
    .unwrap();
    let (file, _) = sentry_server::config::load().unwrap();
    let (n, s) = sentry_server::config::pick(&file, Some(&name)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let (cfg, _) = sentry_core::config::Config::load();
    let mut a = App::new(tx, sentry_local::tui::ID, sentry_local::tui::target(cfg));
    a.slots[LOCAL].screen = ScreenId::Upgrade;
    a.add(
        &sentry_server::tui::id_of(n),
        sentry_server::tui::target(Remote::new(n, s)),
    );
    a.start(Instant::now());
    let pump = |a: &mut App, secs: f32, until: &dyn Fn(&App) -> bool| {
        let end = Instant::now() + std::time::Duration::from_secs_f32(secs);
        while Instant::now() < end && !until(a) {
            if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(50)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
        }
    };
    let never = |_: &App| false;
    // The server hasn't had the window: nothing of it started.
    pump(&mut a, 1.0, &never);
    assert!(a.started_at(LOCAL) && !a.started_at(SRV));
    // Its workflow, started over there (its value's default taken), then left running.
    key(&mut a, KeyCode::F(2));
    assert!(a.started_at(SRV));
    pump(&mut a, 3.0, &never);
    a.apply(
        vec![Effect::StartWorkflow("auto-one".into())],
        Instant::now(),
    );
    key(&mut a, KeyCode::Enter);
    assert!(a.slots[SRV].run.is_some(), "{}", screen(&mut a));
    key(&mut a, KeyCode::F(1));
    // This machine's own, at the same time.
    a.apply(
        vec![Effect::StartWorkflow("two-echoes".into())],
        Instant::now(),
    );
    assert!(a.slots[LOCAL].run.is_some(), "{}", screen(&mut a));
    let waits = |a: &App, i: usize| {
        a.slots[i]
            .run
            .as_ref()
            .is_some_and(|r| r.live().is_none() && matches!(r.next(), Next::Confirm(_)))
    };
    let done = |a: &App, i: usize| a.slots[i].run.as_ref().is_some_and(|r| r.done());
    // Both go on: the server's first step ran out of view and its confirm now waits there,
    // flagged here; this machine's ran through.
    pump(&mut a, 30.0, &|a| waits(a, SRV) && done(a, LOCAL));
    assert!(waits(&a, SRV), "{}", screen(&mut a));
    assert!(done(&a, LOCAL), "{}", screen(&mut a));
    assert_eq!(a.needs(SRV), Needs::You("a step to confirm"));
    let s = screen(&mut a);
    println!("{s}");
    assert!(s.contains("local-one") && s.contains("local-two"), "{s}");
    // Enter here confirms nothing over there.
    let at = a.slots[SRV].run.as_ref().unwrap().next().clone();
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Enter);
    pump(&mut a, 1.0, &never);
    assert_eq!(
        a.slots[SRV].run.as_ref().map(|r| r.next().clone()),
        Some(at)
    );
    // In view: its confirms, one after the other; then it's through.
    key(&mut a, KeyCode::F(2));
    for _ in 0..2 {
        assert!(waits(&a, SRV), "{}", screen(&mut a));
        key(&mut a, KeyCode::Enter);
        pump(&mut a, 30.0, &|a| waits(a, SRV) || done(a, SRV));
    }
    let s = screen(&mut a);
    println!("{s}");
    assert!(done(&a, SRV), "{s}");
    assert!(
        s.contains("hello-from-root") || s.contains("hello-plain"),
        "{s}"
    );
    // Each in its own log.
    key(&mut a, KeyCode::Esc);
    let logged = |scope: &str| {
        sentry_core::maint::log::list(scope)
            .iter()
            .map(|e| e.head.workflow.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(logged(""), ["two-echoes"]);
    assert_eq!(logged(n), ["auto-one"]);
}

// ---- The network target beside the other two.

const NETWORK: &str = "home";

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

/// This machine (in view), `myserver`, and the network `home`.
fn three() -> App {
    let mut a = two();
    a.add(
        &sentry_network::tui::id_of(NETWORK),
        sentry_network::tui::target(sentry_network::remote::Router::new(
            NETWORK,
            &Default::default(),
        )),
    );
    a
}

#[test]
fn the_strip_has_a_network_as_its_third_target() {
    let mut a = three();
    insta::assert_snapshot!("strip_three_targets_158", top(&mut a, 158));
    // F3: the network, with its own screens and nothing of the others'.
    key(&mut a, KeyCode::F(3));
    assert_eq!(a.focus, 2);
    let s = screen(&mut a);
    let tabs = s.lines().nth(1).unwrap();
    assert!(
        tabs.contains("1 Dashboard") && !tabs.contains("Processes") && !tabs.contains("Maint"),
        "{s}"
    );
    assert_eq!(a.slot().screen, ScreenId::Dash);
    // What a probe and the interfaces read bring is drawn in its slot.
    a.on_event(
        sentry_network::tui::testing::ifaces_ev(NETWORK, &fixture("network/ifaces.txt")),
        Instant::now(),
    );
    a.on_event(
        sentry_network::tui::testing::probe_ev(NETWORK, &fixture("network/probe.txt")),
        Instant::now(),
    );
    insta::assert_snapshot!("strip_network_in_view_158", top(&mut a, 158));
    let s = screen(&mut a);
    assert!(s.contains("Example Router AX") && s.contains("● 1G"), "{s}");
    // The digits are the network's: 2, 3, 5 and 6 are nothing there (yet).
    for c in ['2', '3', '5', '6', '0'] {
        key(&mut a, KeyCode::Char(c));
        assert_eq!(a.slot().screen, ScreenId::Dash, "{c}");
    }
    // } goes round all three.
    key(&mut a, KeyCode::Char('}'));
    assert_eq!(a.focus, 0);
    key(&mut a, KeyCode::Char('{'));
    assert_eq!(a.focus, 2);
    insta::assert_snapshot!("strip_three_targets_80", top(&mut a, 80));
}

#[test]
fn net_with_a_name_is_the_network_and_alone_the_screen() {
    let mut a = three();
    // On this machine `:net` is its Network screen, as it always was.
    typed(&mut a, ":net");
    key(&mut a, KeyCode::Enter);
    assert_eq!((a.focus, a.slot().screen), (0, ScreenId::Net));
    // With a name (or the start of one) it is the network of that name.
    typed(&mut a, ":net ho");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.focus, 2);
    assert_eq!(a.slot().target.ident().word, "net");
    typed(&mut a, ":net zz");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.focus, 2);
    assert_eq!(a.toast_for_test(), Some("unknown command :net zz"));
    // From the server too: its own Network screen without a name, the network with one.
    typed(&mut a, ":server my");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.focus, 1);
    typed(&mut a, ":net");
    key(&mut a, KeyCode::Enter);
    assert_eq!((a.focus, a.slot().screen), (1, ScreenId::Net));
    typed(&mut a, ":net home");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.focus, 2);
    // And back.
    typed(&mut a, ":local");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.focus, 0);
}

#[test]
fn a_network_is_asleep_until_it_first_has_the_window() {
    use sentry_network::tui::testing::asked;
    let mut a = three();
    let now = Instant::now();
    a.start(now);
    assert!(a.started_at(0) && !a.started_at(1) && !a.started_at(2));
    // Time passes, this machine's screens come and go: the network asks for nothing (no
    // ssh), sets no time to be woken at, and shows nothing going on.
    for i in 1..=5 {
        a.tick(now + std::time::Duration::from_secs(i));
    }
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char('0'));
    assert!(asked(&a, 2).is_empty(), "{:?}", asked(&a, 2));
    assert!(!a.started_at(2));
    assert_eq!(a.needs(2), Needs::Nothing);
    // The server in view: still nothing of the network's.
    key(&mut a, KeyCode::F(2));
    assert!(asked(&a, 2).is_empty() && !a.started_at(2));
    // It gets the window: it starts, and reads what its Dashboard shows.
    let t1 = Instant::now();
    a.focus(2, t1);
    assert!(a.started_at(2));
    assert_eq!(asked(&a, 2), ["probe", "ifaces"]);
    a.tick(t1 + std::time::Duration::from_millis(1100));
    assert_eq!(asked(&a, 2), ["probe", "ifaces", "probe"]);
    // Out of view again it stops polling at once, and comes back reading.
    let t2 = t1 + std::time::Duration::from_secs(2);
    a.focus(0, t2);
    for i in 1..=5 {
        a.tick(t2 + std::time::Duration::from_secs(i));
    }
    assert_eq!(asked(&a, 2).len(), 3);
    let t3 = t2 + std::time::Duration::from_secs(10);
    a.focus(2, t3);
    assert_eq!(&asked(&a, 2)[3..], ["probe", "ifaces"]);
}

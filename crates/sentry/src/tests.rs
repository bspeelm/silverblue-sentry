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
    // (This machine's runs share one place: whoever starts one takes its turn.)
    let turn = sentry_local::tui::testing::runs_turn();
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
    // A server's runs are kept by its name, in the one scratch root every test of this
    // process shares: two tests with one name would each find the other's run in progress
    // (or remove it). So a name is one test's, and taking it twice fails here, every time.
    static TAKEN: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    {
        let mut taken = TAKEN.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            !taken.iter().any(|t| t == server),
            "the server name {server:?} is another test's: its runs would be shared"
        );
        taken.push(server.to_string());
    }
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
        tabs.contains("1 Dashboard")
            && tabs.contains("2 Clients")
            && tabs.contains("4 Security")
            && tabs.contains("6 Maintenance")
            && tabs.contains("0 Upgrade")
            && !tabs.contains("Processes"),
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
    // The digits are the network's: 2 is its Clients, 3 its own Network, 4 its Security
    // (where the others have Containers), 6 its Maintenance, 0 its workflows; 5 and 7
    // are nothing there.
    for c in ['5', '7'] {
        key(&mut a, KeyCode::Char(c));
        assert_eq!(a.slot().screen, ScreenId::Dash, "{c}");
    }
    for (c, id) in [
        ('0', ScreenId::Upgrade),
        ('2', ScreenId::Clients),
        ('3', ScreenId::Net),
        ('4', ScreenId::Security),
        ('6', ScreenId::Maint),
        ('1', ScreenId::Dash),
    ] {
        key(&mut a, KeyCode::Char(c));
        assert_eq!(a.slot().screen, id, "{c}");
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
    // (The config and the clients too, once per entry: what must be hidden from Claude,
    // the SSIDs and the devices' names, is known wherever it can be asked.)
    const ENTRY: [&str; 6] = ["probe", "ifaces", "services", "report", "uci", "clients"];
    assert_eq!(asked(&a, 2), ENTRY);
    a.tick(t1 + std::time::Duration::from_millis(1100));
    assert_eq!(asked(&a, 2).len(), 7);
    assert_eq!(asked(&a, 2)[6], "probe");
    // Out of view again it stops polling at once, and comes back reading.
    let t2 = t1 + std::time::Duration::from_secs(2);
    a.focus(0, t2);
    for i in 1..=5 {
        a.tick(t2 + std::time::Duration::from_secs(i));
    }
    assert_eq!(asked(&a, 2).len(), 7);
    let t3 = t2 + std::time::Duration::from_secs(10);
    a.focus(2, t3);
    assert_eq!(&asked(&a, 2)[7..], ENTRY);
}

#[test]
fn claude_is_offered_only_where_it_answers() {
    // Claude Code is there (as tests have it): every target offers it in the key bar, on
    // a screen that names no `A` of its own, and in `?`. Auto mode is named where a
    // network's workflows are started: on Maintenance.
    let mut a = three();
    let bar = |a: &mut App| screen(a).lines().last().unwrap().to_string();
    key(&mut a, KeyCode::Char('1'));
    assert!(bar(&mut a).contains("A  ask Claude"), "{}", bar(&mut a));
    key(&mut a, KeyCode::F(2));
    key(&mut a, KeyCode::Char('1'));
    assert!(bar(&mut a).contains("A  ask Claude"), "{}", bar(&mut a));
    key(&mut a, KeyCode::Char('?'));
    assert!(screen(&mut a).contains("ask Claude about the selected thing"));
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::F(3));
    for c in ['1', '2', '3', '6'] {
        key(&mut a, KeyCode::Char(c));
        let b = bar(&mut a);
        assert!(b.contains("laude"), "{c}: {b}");
        assert_eq!(b.contains("C-a  auto"), c == '6', "{c}: {b}");
    }
    key(&mut a, KeyCode::Char('?'));
    let help = screen(&mut a);
    assert!(
        help.contains("Maintenance:") && help.contains("ask Claude") && help.contains("auto mode"),
        "{help}"
    );
    key(&mut a, KeyCode::Esc);
    // Back on this machine, Maintenance still names its own.
    key(&mut a, KeyCode::F(1));
    key(&mut a, KeyCode::Char('6'));
    assert!(bar(&mut a).contains("A  claude"), "{}", bar(&mut a));
    // Nothing of the router has been read here, so what must be hidden from Claude isn't
    // known: A asks nothing, and says why.
    key(&mut a, KeyCode::F(3));
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char('A'));
    assert_eq!(a.toast_for_test(), Some(sentry_network::tui::ask::NOT_YET));
}

/// The same task behaves the same on all three targets: Enter on a task done by hand
/// opens an apply session with Claude at its brief (nothing sent, nothing logged, the task
/// still due); `m` shows its steps, and that box's Enter is what marks it done.
#[test]
fn a_by_hand_task_is_a_session_with_claude_on_every_target() {
    use sentry_core::apply::session::Phase;
    let mut a = three();
    // What must be hidden from Claude on a network is known once these are read.
    for ev in [
        sentry_network::tui::testing::ifaces_ev(NETWORK, &fixture("network/ifaces.txt")),
        sentry_network::tui::testing::uci_ev(NETWORK, &fixture("network/uci.txt")),
        sentry_network::tui::testing::clients_ev(NETWORK, &fixture("network/clients.txt")),
    ] {
        a.on_event(ev, Instant::now());
    }
    for slot in a.slots.iter_mut() {
        slot.shared.tasks = vec![task("hand", "Tidy the thing by hand")];
    }
    for (i, f) in [(0, 1), (1, 2), (2, 3)] {
        key(&mut a, KeyCode::F(f));
        assert_eq!(a.focus, i);
        key(&mut a, KeyCode::Char('6'));
        typed(&mut a, "/Tidy the thing");
        key(&mut a, KeyCode::Enter);
        let s = screen(&mut a);
        assert!(s.contains("Tidy the thing by hand"), "slot {i}: {s}");
        assert!(
            s.contains("By hand: Enter works it out with Claude"),
            "slot {i}: {s}"
        );
        let logged = a.slots[i].shared.log.len();
        key(&mut a, KeyCode::Enter);
        let ses = a.apply_session_at(i).unwrap_or_else(|| {
            panic!("slot {i}: Enter opens no session: {:?}", a.toast_for_test())
        });
        assert_eq!(ses.phase, Phase::Brief, "slot {i}");
        let ap = ses.chat.ask.applying().expect("an apply session");
        assert_eq!(ap.task.as_deref(), Some("hand"), "slot {i}");
        assert!(a.box_yes_for_test().is_none(), "slot {i}: a box");
        key(&mut a, KeyCode::Esc);
        assert!(a.apply_session_at(i).is_none(), "slot {i}");
        assert_eq!(a.slots[i].shared.log.len(), logged, "slot {i}: logged");
        assert!(
            screen(&mut a).contains("Tidy the thing by hand"),
            "slot {i}: still due"
        );
        // m: the steps; the box's yes is the one thing that marks it done.
        key(&mut a, KeyCode::Char('m'));
        let s = screen(&mut a);
        assert!(
            s.contains("Look at it.") && s.contains("mark done"),
            "slot {i}: {s}"
        );
        assert!(
            matches!(a.box_yes_for_test(), Some([Effect::TaskDone(id)]) if id == "hand"),
            "slot {i}"
        );
        key(&mut a, KeyCode::Char('n'));
    }
}

// ── One session, every target ───────────────────────────────────────────────────────────

const NET: usize = 2;
const KEY: &str = "S3cretBouncerKey+abc/123=";
const PASSWORD: &str = "hunter2-Sudo!";

/// This machine, a server whose sudo asks for its password, and a network: each test its
/// own names (runs are kept by name).
fn three_with(server: &str, network: &str) -> App {
    let mut a = two_with(server, true);
    a.add(
        &sentry_network::tui::id_of(network),
        sentry_network::tui::target(sentry_network::remote::Router::new(
            network,
            &Default::default(),
        )),
    );
    for ev in [
        sentry_network::tui::testing::ifaces_ev(network, &fixture("network/ifaces.txt")),
        sentry_network::tui::testing::uci_ev(network, &fixture("network/uci.txt")),
        sentry_network::tui::testing::clients_ev(network, &fixture("network/clients.txt")),
    ] {
        a.on_event(ev, Instant::now());
    }
    a
}

/// Enter on the by-hand task of the slot at `i` (F-key `f`): a session with Claude.
fn task_session(a: &mut App, i: usize, f: u8) {
    a.slots[i].shared.tasks = vec![task("bouncer", "Install the bouncer")];
    key(a, KeyCode::F(f));
    key(a, KeyCode::Char('6'));
    typed(a, "/Install the bouncer");
    key(a, KeyCode::Enter);
    key(a, KeyCode::Enter);
    assert!(a.apply_session_at(i).is_some(), "{:?}", a.toast_for_test());
}

/// Every file under sentry's (scratch) directories that holds `needle`.
fn files_with(needle: &str) -> Vec<std::path::PathBuf> {
    fn walk(d: &std::path::Path, needle: &str, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, needle, out);
            } else if std::fs::read(&p).is_ok_and(|b| String::from_utf8_lossy(&b).contains(needle))
            {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    for d in [
        sentry_core::paths::config_dir(),
        sentry_core::paths::data_dir(),
        sentry_core::paths::cache_dir(),
    ] {
        walk(&d, needle, &mut out);
    }
    out
}

fn tall(a: &mut App) -> String {
    render_to_string(a, 158, 120)
}

fn bouncer_plan() -> String {
    "The server's API listens on loopback only; I open it, make the key there and use it here.\n\
     ```sentry-apply\nsummary = \"bouncer on the router\"\n\n\
     [[step]]\ntitle = \"Listen on the DMZ\"\non = \"srv:crowd\"\n\
     run = \"sudo sed -i s/127.0.0.1:8080/0.0.0.0:8080/ /etc/crowdsec/config.yaml && sudo systemctl restart crowdsec\"\n\n\
     [[step]]\ntitle = \"A key for the router\"\non = \"srv:crowd\"\n\
     run = \"sudo cscli bouncers add router -o raw\"\ncapture = \"key\"\nsecret = true\n\n\
     [[step]]\ntitle = \"Install\"\nrun = \"apk add crowdsec-firewall-bouncer\"\n\n\
     [[step]]\ntitle = \"Its key\"\n\
     run = \"uci set crowdsec.@bouncer[0].api_key='{{key}}' && uci commit crowdsec\"\n\n\
     [[step]]\ntitle = \"Let it through\"\nworkflow = \"guarded-change\"\n\
     vars = { configs = \"firewall\", lines = \"uci set firewall.bouncer=rule; uci set firewall.bouncer.target='ACCEPT'\", services = \"firewall\" }\n\
     ```"
        .to_string()
}

/// The incident this was built for: the router's bouncer needs the server's CrowdSec API,
/// which listens on loopback only. One session, started on the router, does both sides.
#[test]
fn the_crowdsec_case_one_session_across_the_router_and_the_server() {
    use sentry_core::apply::session::{End, Phase, Turn};
    let _ = std::fs::remove_dir_all(sentry_network::workflow::root(&sentry_network::tui::id_of(
        "crowdnet",
    )));
    let mut a = three_with("crowd", "crowdnet");
    a.start(Instant::now());
    // (The network's workflows as they're seeded, in the scratch config dir.)
    a.set_wf_entries_at(
        NET,
        sentry_network::workflow::list_for(&sentry_network::tui::id_of("crowdnet")),
    );
    // Enter on the router's task is such a session; the other targets wake for it,
    // without the window changing hands.
    assert!(!a.started_at(SRV));
    task_session(&mut a, NET, 3);
    assert!(a.started_at(SRV) && a.focus == NET);
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        a.apply_session_at(NET).unwrap().phase,
        Phase::Thinking(Turn::Investigate)
    );

    // What its Claude may do: read on every target through that target's own gateway,
    // with every target's denials kept (the router's session has no web: nobody's has
    // while its gateway is in reach).
    let p = a.session_profile_at(NET);
    for rule in [
        "Bash(sentry-network exec crowdnet:*)",
        "Bash(sentry-network run crowdnet:*)",
        "Bash(sentry-server exec crowd:*)",
        "Bash(sentry-server run crowd:*)",
    ] {
        assert!(
            p.allowed.iter().any(|r| r == rule),
            "{rule}: {:?}",
            p.allowed
        );
    }
    assert!(p.denied.iter().any(|d| d == "WebFetch"), "{:?}", p.denied);
    assert!(
        p.denied.iter().any(|d| d.contains("network_config")),
        "{:?}",
        p.denied
    );
    assert!(
        !p.allowed.iter().any(|r| r == "Bash"),
        "nothing on this machine runs by itself"
    );
    for said in [
        "## The system",
        "`net:crowdnet` (a home network, through its OpenWrt router",
        "This session started here.",
        "`srv:crowd` (a server over ssh",
        "`local` (this machine",
        "fix it THERE",
        "### `srv:crowd`: how you reach it",
        "sentry-server run crowd -- ",
        "NEVER tell me to enter, paste, set, type or run something myself",
        "`ask = \"name\"`",
    ] {
        assert!(p.system.contains(said), "{said}: {}", p.system);
    }

    a.apply_answer_at(NET, &bouncer_plan());
    let s = a.apply_session_at(NET).unwrap();
    assert!(s.can_approve(), "{:?}", s.problems);
    // The plan view says whose each step is.
    let view = tall(&mut a);
    assert!(
        view.contains("A key for the router") && view.contains("crowd"),
        "{view}"
    );
    assert!(
        view.contains("its last line is kept as {{key}} (hidden, never written down)"),
        "{view}"
    );

    // ONE approval. The server's password is asked here, in this session's line, naming
    // the server; typed once.
    key(&mut a, KeyCode::Enter);
    let s = a.apply_session_at(NET).unwrap();
    assert!(matches!(s.phase, Phase::Password { .. }), "{:?}", s.phase);
    assert!(
        tall(&mut a).contains("sudo password (on crowd, for step 1, 2)"),
        "{}",
        tall(&mut a)
    );
    assert!(
        a.unlock_at(SRV).is_none(),
        "nothing waits for the server to be in view"
    );
    typed(&mut a, PASSWORD);
    key(&mut a, KeyCode::Enter);
    a.guest_exit_at(SRV, 0);
    assert!(a.holds_password_at(SRV) && !a.holds_password_at(NET));
    // The first step runs on the server, as the server runs its own: its strip entry
    // says it works, and the session stays where it started.
    assert_eq!(a.guest_at(SRV), (true, false));
    assert_eq!(a.needs(SRV), Needs::Working);
    assert_eq!(a.focus, NET);
    let cmd = a.slots[SRV].last_guest_cmd.clone().unwrap();
    assert!(
        cmd.contains("sed -i") && cmd.contains("@@sentry-ready"),
        "{cmd}"
    );
    assert!(
        !cmd.contains(PASSWORD),
        "the password is no argument: {cmd}"
    );
    a.guest_exit_at(SRV, 0);
    // The second: the password again, without a prompt. What it prints is the key.
    assert!(matches!(
        a.apply_session_at(NET).unwrap().phase,
        Phase::Applying
    ));
    a.guest_line_at(SRV, KEY);
    assert!(!tall(&mut a).contains(KEY));
    a.guest_exit_at(SRV, 0);
    assert_eq!(a.guest_at(SRV), (false, false));
    // The router's own steps: a package, then the key, which is in the command that runs
    // and nowhere on screen.
    assert!(
        a.slots[NET]
            .last_step_cmd
            .as_deref()
            .unwrap()
            .contains("apk add")
    );
    a.apply_exit_at(NET, 0);
    let ran = a.slots[NET].last_step_cmd.clone().unwrap();
    assert!(
        ran.contains(&format!("api_key='\\''{KEY}'\\''")) || ran.contains(KEY),
        "{ran}"
    );
    let view = tall(&mut a);
    assert!(
        !view.contains(KEY) && view.contains("api_key='{{key}}'"),
        "{view}"
    );
    a.apply_exit_at(NET, 0);
    // The firewall's part is the router's guard, as in any router session: its run.
    // (Its values are shown to take or change, as in any router session: Enter each.)
    for _ in 0..4 {
        if a.slots[NET].run.is_none() {
            key(&mut a, KeyCode::Enter);
        }
    }
    let (_, live, done) = run_at(&a, NET);
    assert!(live && !done, "the guard's preview runs");
    a.run_step_exit_at(NET, 0);
    assert!(
        matches!(run_at(&a, NET).0, Next::Confirm(1)),
        "{:?}",
        run_at(&a, NET).0
    );
    a.apply_at(NET, vec![Effect::Wf(sentry_app::effect::WfCmd::Go)]);
    a.run_step_exit_at(NET, 0);
    assert!(run_at(&a, NET).2, "{:?}", run_at(&a, NET));
    // All five done: Claude verifies, from a report that never held the key.
    let s = a.apply_session_at(NET).unwrap();
    assert_eq!(
        s.phase,
        Phase::Thinking(Turn::Verify),
        "{:?}",
        s.chat.entries.last()
    );
    let sent = a.slots[NET].last_prompt.clone().unwrap();
    assert!(
        sent.contains("all 5 steps") && sent.contains("on srv:crowd"),
        "{sent}"
    );
    assert!(!sent.contains(KEY) && !sent.contains(PASSWORD), "{sent}");
    a.apply_answer_at(NET, DONE);
    assert_eq!(
        a.apply_session_at(NET).unwrap().phase,
        Phase::Settled(End::Done)
    );

    // Each target's log says what happened to it; the entries share the run's id.
    let run = format!("run:{}", a.apply_session_at(NET).unwrap().run_id);
    let entry = |a: &App, i: usize| {
        a.slots[i]
            .shared
            .log
            .iter()
            .find(|e| e.head.tags.contains(&run))
            .unwrap_or_else(|| panic!("slot {i}: no entry tagged {run}"))
            .clone()
    };
    let (net, srv) = (entry(&a, NET), entry(&a, SRV));
    assert!(
        net.head.tags.contains(&"with:srv:crowd".to_string()),
        "{:?}",
        net.head.tags
    );
    assert!(
        net.head.tags.contains(&"task:bouncer".to_string()),
        "{:?}",
        net.head.tags
    );
    assert!(
        srv.head.tags.contains(&"with:net:crowdnet".to_string()),
        "{:?}",
        srv.head.tags
    );
    assert!(
        srv.body.contains("A key for the router") && !srv.body.contains("apk add"),
        "{}",
        srv.body
    );
    assert!(
        !a.slots[LOCAL]
            .shared
            .log
            .iter()
            .any(|e| e.head.tags.contains(&run))
    );
    // The key and the password: in no entry, no plan, no prompt, no transcript, and (the
    // records written out as they would be) in no file sentry keeps.
    for slot in &a.slots {
        for e in &slot.shared.log {
            assert!(
                !e.body.contains(KEY) && !e.head.summary.contains(KEY),
                "{}",
                e.body
            );
            sentry_core::maint::log::write(e).unwrap();
        }
        for d in slot.shared.plans.values() {
            assert!(!d.body.contains(KEY), "{}", d.body);
            assert!(
                d.body.contains("{{key}}") && d.body.contains("on = \"srv:crowd\""),
                "{}",
                d.body
            );
            sentry_core::maint::plan::save(d).unwrap();
        }
    }
    for (_, t) in &a.apply_session_at(NET).unwrap().chat.entries {
        assert!(!t.contains(KEY), "{t}");
    }
    assert_eq!(files_with(KEY), Vec::<std::path::PathBuf>::new());
    assert_eq!(files_with(PASSWORD), Vec::<std::path::PathBuf>::new());
}

fn has_web(p: &sentry_core::claude::Profile) -> bool {
    let web = |v: &[String]| v.iter().any(|x| x == "WebFetch");
    web(&p.tools) && web(&p.allowed) && !web(&p.denied)
}

/// The web is a session's until it has read from the router, whoever else is in the
/// window: a server's session researches as before; from the turn after a read through
/// the router's gateway it has none, for good, and its window says so once; a session
/// that starts on the network never has it; a review (which can run and write nothing)
/// always does.
#[test]
fn the_web_goes_once_a_session_has_read_from_the_router() {
    use sentry_app::target::ProfileFor;
    use sentry_core::apply::session::Session;
    use sentry_core::tui::chat::Kind;
    let said = |a: &App, i: usize| {
        a.apply_session_at(i)
            .unwrap()
            .chat
            .entries
            .iter()
            .filter(|(_, t)| t == Session::WEB_OFF)
            .count()
    };

    // Started on the server, a router in the window, nothing read from it: the web.
    let mut a = three_with("websrv", "webnet");
    task_session(&mut a, SRV, 2);
    key(&mut a, KeyCode::Enter);
    assert!(has_web(&a.session_profile_at(SRV)));
    // It reads on the server only: still the web on the next turn.
    a.apply_session()
        .unwrap()
        .chat
        .push(Kind::Tool, "sentry-server exec websrv -- uptime");
    a.apply_answer_at(SRV, "It is up. Anything else?");
    typed(&mut a, "go on");
    key(&mut a, KeyCode::Enter);
    assert!(has_web(&a.session_profile_at(SRV)));
    assert_eq!(said(&a, SRV), 0);
    // It reads through the router's gateway: the turn after that has none.
    a.apply_session().unwrap().chat.push(
        Kind::Tool,
        "sentry-network exec webnet -- uci show firewall",
    );
    a.apply_answer_at(SRV, "The router forwards to it.");
    typed(&mut a, "and then");
    key(&mut a, KeyCode::Enter);
    let p = a.session_profile_at(SRV);
    assert!(!has_web(&p) && p.denied.iter().any(|d| d == "WebSearch"));
    assert!(p.system.contains("no web access"), "{}", p.system);
    assert_eq!(said(&a, SRV), 1);
    // For the rest of the session, and said only once.
    a.apply_answer_at(SRV, "Yes.");
    typed(&mut a, "more");
    key(&mut a, KeyCode::Enter);
    assert!(!has_web(&a.session_profile_at(SRV)));
    assert_eq!(said(&a, SRV), 1);

    // Started on the network: none from the start, and nothing to say about it.
    let mut b = three_with("websrv2", "webnet2");
    b.set_wf_entries_at(
        NET,
        sentry_network::workflow::list_for(&sentry_network::tui::id_of("webnet2")),
    );
    task_session(&mut b, NET, 3);
    key(&mut b, KeyCode::Enter);
    assert!(!has_web(&b.session_profile_at(NET)));
    assert_eq!(said(&b, NET), 0);

    // A review keeps the web on every target, a router among them or not.
    for i in [LOCAL, SRV, NET] {
        let p = b.slots[i].target.profile(ProfileFor::Review, &[]);
        assert!(has_web(&p), "slot {i}: {:?}", p.denied);
        assert!(
            !p.tools.iter().any(|t| t == "Edit" || t == "Write"),
            "slot {i}: a review writes nothing"
        );
    }
}

/// What the three targets would say to the security audit: the router forwards a door to
/// the server where nothing answers (an item across both), the server's ssh takes
/// passwords (its own), this machine's firewall is off (its own), and the router's
/// bouncer is installed and off while the server runs CrowdSec. The server's address and
/// a device's MAC are in the facts and must never be in anything Claude is sent.
const AUDIT_CANARIES: [&str; 2] = ["192.0.2.10", "02:00:5e:00:53:99"];

fn audit_facts(server: &str, network: &str) -> Vec<sentry_core::secaudit::TargetFacts> {
    use sentry_core::secaudit::*;
    let local = TargetFacts {
        firewall: Some(HostFw {
            active: false,
            zone: None,
        }),
        ..TargetFacts::new("local", Kind::Local, "this machine")
    };
    let srv = TargetFacts {
        addrs: vec![AUDIT_CANARIES[0].into()],
        listeners: Some(vec![Listen {
            proto: "tcp".into(),
            port: 22,
            wide: true,
            process: Some("sshd".into()),
        }]),
        ssh: Some(Ssh {
            on: Some(true),
            password: Some(true),
            root: Some("no".into()),
            source: "sshd -T".into(),
        }),
        watch: Some(Watch {
            crowdsec: Some(true),
            bouncers: Some(Vec::new()),
            ..Default::default()
        }),
        ..TargetFacts::new(&format!("srv:{server}"), Kind::Server, server)
    };
    let net = TargetFacts {
        addrs: vec![AUDIT_CANARIES[1].into()],
        watch: Some(Watch {
            enforces: Some(false),
            installed_off: true,
            ..Default::default()
        }),
        // (A backup there is: whether it was ever restored is asked.)
        backup: Some(Backup {
            count: Some(2),
            newest_days: Some(1),
            encrypted: Some(true),
            unsaved: Some(false),
            ..Default::default()
        }),
        router: Some(Router {
            wan_up: Some(true),
            forwards: Some(vec![Forward {
                proto: "tcp".into(),
                // (Not one of the forwards the router fixture has: a door the page has
                // no row of its own for.)
                port: "9443".into(),
                to_port: "9443".into(),
                dest: AUDIT_CANARIES[0].into(),
                zone: Some("dmz".into()),
                probe: None,
            }]),
            ..Default::default()
        }),
        ..TargetFacts::new(&format!("net:{network}"), Kind::Network, network)
    };
    vec![local, srv, net]
}

/// `S` anywhere the system's safety is looked at runs the audit (the first time; after
/// that it shows the report, and `S` there runs it again). It is the window's: said on
/// every target while it reads, its report opens when the facts are in, its task on this
/// machine is done, Claude reviews the evidence with the web and nothing else, and each
/// item is a row on the one target that lists it.
#[test]
fn the_security_audit_is_the_windows_and_each_target_lists_its_rows() {
    let (server, network) = ("auditsrv", "auditnet");
    let mut a = three_with(server, network);
    a.survey();
    // This machine's Maintenance: no report yet, so `S` runs it.
    key(&mut a, KeyCode::Char('6'));
    key(&mut a, KeyCode::Char('S'));
    assert!(a.win.sec.busy() && a.win.sec.report.is_none());
    assert!(
        screen(&mut a).contains("security audit · reading every target"),
        "{}",
        screen(&mut a)
    );
    // Once more is not twice.
    key(&mut a, KeyCode::Char('S'));
    assert_eq!(
        a.toast_for_test(),
        Some("the security audit is already running")
    );
    a.on_event(
        Event::Data(
            sentry_local::tui::ID.into(),
            Box::new(sentry_app::secaudit::Done(audit_facts(server, network))),
        ),
        Instant::now(),
    );
    assert!(!a.win.sec.busy());
    let ids: Vec<String> = a
        .win
        .sec
        .report
        .as_ref()
        .expect("a report")
        .items
        .iter()
        .map(|i| format!("{} {:?} {:?}", i.id, i.state, i.targets))
        .collect();
    let door = format!("sec:door:net:{network}:tcp:9443");
    assert!(ids.iter().any(|i| i.starts_with(&door)), "{ids:#?}");
    // The report is in front, in sections, and says what it isn't.
    let s = tall(&mut a);
    for said in [
        " Security audit ",
        "audited today",
        "Worth doing",
        "It doesn't attack anything",
        "S  run it again",
    ] {
        assert!(s.contains(said), "{said}:\n{s}");
    }
    // Its task is this machine's, and done.
    let e = a.slots[LOCAL].shared.log.first().expect("logged");
    assert!(
        e.head
            .tags
            .iter()
            .any(|t| t == &format!("task:{}", sentry_core::secaudit::TASK_ID)),
        "{:?}",
        e.head.tags
    );
    // Claude reviews the evidence: scrubbed where it was made, the web and nothing else.
    assert!(a.writing() && a.win.sec.reviewing);
    let sent = a.slots[LOCAL].last_prompt.clone().expect("a review asked");
    assert!(sent.contains("### Getting in from the internet"), "{sent}");
    for c in AUDIT_CANARIES {
        assert!(!sent.contains(c), "{c} in the review's brief:\n{sent}");
    }
    let p = a.slots[LOCAL].last_profile.clone().unwrap();
    assert_eq!(p.tools, ["WebFetch", "WebSearch"]);
    assert!(has_web(&p) && p.denied.iter().any(|d| d == "Bash"));
    assert!(tall(&mut a).contains("Claude is reading the evidence"));
    a.writer_answered("## Do these first\nClose the door nobody uses.");
    assert!(!a.win.sec.reviewing);
    let s = tall(&mut a);
    assert!(
        s.contains("What matters most here") && s.contains("Close the door nobody uses."),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);

    // This machine lists what is its alone, as a recommendation.
    let s = tall(&mut a);
    assert!(s.contains("firewall"), "{s}");
    let local: Vec<String> = a.slots[LOCAL]
        .shared
        .sec
        .iter()
        .map(|i| i.id.clone())
        .collect();
    assert!(
        !local.is_empty() && local.iter().all(|i| i.ends_with(":local")),
        "{local:?}"
    );
    // The server lists its own: its ssh login takes passwords.
    key(&mut a, KeyCode::F(2));
    key(&mut a, KeyCode::Char('6'));
    let srv: Vec<String> = a.slots[SRV]
        .shared
        .sec
        .iter()
        .map(|i| i.id.clone())
        .collect();
    assert!(
        srv.contains(&format!("sec:ssh-password:srv:{server}"))
            && srv.iter().all(|i| i.ends_with(&format!("srv:{server}"))),
        "{srv:?}"
    );
    // (Its list isn't drawn before the server was read; the row is there to select.)
    key(&mut a, KeyCode::Char('o'));
    let mut seen = false;
    for _ in 0..6 {
        seen = seen || tall(&mut a).contains("accepts ssh logins with a password");
        key(&mut a, KeyCode::Char('j'));
    }
    assert!(seen, "{}", tall(&mut a));
    // The network's Security page lists its own and what spans targets: the door, and
    // ONE row for CrowdSec at the edge (the audit's item joins the page's own).
    key(&mut a, KeyCode::F(3));
    key(&mut a, KeyCode::Char('4'));
    a.on_event(
        sentry_network::tui::testing::bouncer_ev(network, false),
        Instant::now(),
    );
    a.on_event(
        sentry_server::tui::testing::crowdsec_ev(server, 7, "ssh brute force"),
        Instant::now(),
    );
    a.survey();
    let s = tall(&mut a);
    assert!(
        s.contains("The router lets the internet in on tcp port 9443")
            && s.contains("audited today · S shows it"),
        "{s}"
    );
    // Said once, as a row; the cover points at it, and keeps what the server counted.
    assert_eq!(s.matches("but switched off").count(), 1, "{s}");
    let edge = s
        .lines()
        .find(|l| l.contains("CrowdSec is installed on the router"))
        .and_then(|l| l.trim_start_matches(['│', ' ']).split('.').next())
        .unwrap()
        .to_string();
    assert!(
        s.contains(&format!(
            "✗ off  Blocking attackers at the router: see {edge} above"
        )) && s.contains(&format!(
            "auditsrv blocked 7 attacker(s) today (mostly ssh brute force): see {edge} above"
        )),
        "{s}"
    );
    let net: Vec<String> = a.slots[NET]
        .shared
        .sec
        .iter()
        .map(|i| i.id.clone())
        .collect();
    assert!(
        net.contains(&door) && net.contains(&"sec:watch".to_string()),
        "{net:?}"
    );
    // Nothing is listed twice across the targets.
    for i in &net {
        assert!(!local.contains(i) && !srv.contains(i), "{i} twice");
    }
    // `S` now shows the report; `:audit security` too, from any target.
    key(&mut a, KeyCode::Char('S'));
    assert!(!a.win.sec.busy() && tall(&mut a).contains(" Security audit "));
    key(&mut a, KeyCode::Esc);
}

/// The audit is a task of this machine's (every 30 days, and after a firmware or OS
/// upgrade): Enter on it runs the audit, it isn't a list of steps to do by hand.
#[test]
fn the_audits_task_runs_the_audit() {
    let mut a = one();
    // (From tasks.toml a task is due at once; the derived one counts from the log.)
    a.add_task_for_test(sentry_core::secaudit::task(None, &[], None));
    key(&mut a, KeyCode::Char('6'));
    typed(&mut a, "/Run the security audit");
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(
        s.contains("Run the security audit") && s.contains("Enter  audit"),
        "{s}"
    );
    assert!(!a.win.sec.busy());
    key(&mut a, KeyCode::Enter);
    assert!(a.win.sec.busy(), "{:?}", a.toast_for_test());
    assert!(a.apply_session_at(0).is_none(), "not a session by hand");
    // Done when the audit has run: its entry is this machine's.
    a.on_event(
        Event::Data(
            sentry_local::tui::ID.into(),
            Box::new(sentry_app::secaudit::Done(audit_facts("s", "n"))),
        ),
        Instant::now(),
    );
    let done = a.slots[0].shared.log.iter().any(|e| {
        e.head
            .tags
            .iter()
            .any(|t| t == &format!("task:{}", sentry_core::secaudit::TASK_ID))
    });
    assert!(done);
}

/// The audit's task is this machine's, and an upgrade of firmware or of an operating
/// system on ANY target makes it due again: what the window finds in the other targets'
/// logs is handed to this machine's slot, said with where it ran.
#[test]
fn an_upgrade_on_any_target_makes_the_audit_due_again() {
    use sentry_core::maint::log::LogEntry;
    let (server, network) = ("upsrv", "upnet");
    let mut a = three_with(server, network);
    a.on_event(
        Event::Data(
            sentry_local::tui::ID.into(),
            Box::new(sentry_app::secaudit::Done(audit_facts(server, network))),
        ),
        Instant::now(),
    );
    let audited = a.win.sec.report.as_ref().unwrap().at;
    let again = |a: &mut App| {
        a.survey();
        // (A slot takes it in with its next event.)
        key(a, KeyCode::Char('6'));
        let sh = &a.slots[LOCAL].shared;
        a.slots[LOCAL]
            .target
            .derived_tasks(sh)
            .into_iter()
            .find(|t| t.id == sentry_core::secaudit::TASK_ID)
            .expect("the audit's task is this machine's")
            .again
            .map(|g| g.why)
    };
    assert_eq!(again(&mut a), None);
    let run = |workflow: &str, hours: i64| {
        let mut e = LogEntry::task("", "x", "x", None);
        e.head.workflow = workflow.into();
        e.head.result = "done".into();
        e.head.ended = Some(audited + jiff::SignedDuration::from_hours(hours));
        e
    };
    // An ordinary update on the server changes nothing.
    a.slots[SRV].shared.log.push(run("package-update", 1));
    assert_eq!(again(&mut a), None);
    // The router's firmware was upgraded: due again, and it says where.
    a.slots[NET].shared.log.push(run("firmware-upgrade", 2));
    assert_eq!(
        again(&mut a).as_deref(),
        Some(format!("firmware-upgrade ran on {network} since the last security audit").as_str())
    );
    // The newest one says why; one from before the audit doesn't count.
    a.slots[SRV].shared.log.push(run("release-upgrade", 3));
    a.slots[NET].shared.log.push(run("firmware-upgrade", -30));
    assert_eq!(
        again(&mut a).as_deref(),
        Some(format!("release-upgrade ran on {server} since the last security audit").as_str())
    );
    // A network or a server doesn't hand itself its own.
    key(&mut a, KeyCode::F(3));
    key(&mut a, KeyCode::Char('6'));
    assert!(
        a.slots[NET]
            .shared
            .sec_upgraded
            .as_ref()
            .is_some_and(|(_, what)| what.contains(server))
    );
}

/// `S` is named in Maintenance's key bar on every target, and is the first to go when
/// the bar is narrow.
#[test]
fn maintenance_names_the_audits_key_until_the_bar_is_narrow() {
    let mut a = three_with("keysrv", "keynet");
    for f in [1, 2, 3] {
        key(&mut a, KeyCode::F(f));
        key(&mut a, KeyCode::Char('6'));
        let wide = render_to_string(&mut a, 240, 41);
        let bar = wide.lines().last().unwrap();
        assert!(bar.contains("S  security audit"), "F{f}: {bar}");
        // Narrower: it goes before any other of the screen's keys.
        let width = (60..240)
            .rev()
            .find(|w| {
                let s = render_to_string(&mut a, *w, 41);
                !s.lines().last().unwrap().contains("S  security audit")
            })
            .unwrap();
        let narrow = render_to_string(&mut a, width, 41);
        let (wide, narrow) = (
            render_to_string(&mut a, width + 1, 41),
            narrow.lines().last().unwrap().to_string(),
        );
        let rest = wide
            .lines()
            .last()
            .unwrap()
            .replace("S  security audit   ", "");
        assert_eq!(
            narrow.split_whitespace().collect::<Vec<_>>(),
            rest.split_whitespace().collect::<Vec<_>>(),
            "F{f}: only S went"
        );
    }
}

/// Enter on an audit item that spans targets is one session across them, started where
/// the row is: briefed with the audit's own words (no address in them), no web from the
/// start (a router is among its targets), and its plan's steps run where they belong.
/// What only the user knows is a pick, and the audit's list follows the answer.
#[test]
fn enter_on_an_audit_item_is_a_session_across_its_targets() {
    use sentry_core::apply::session::Phase;
    use sentry_core::secaudit::State;
    let (server, network) = ("doorsrv", "doornet");
    let mut a = three_with(server, network);
    a.set_wf_entries_at(
        NET,
        sentry_network::workflow::list_for(&sentry_network::tui::id_of(network)),
    );
    a.survey();
    a.on_event(
        Event::Data(
            sentry_local::tui::ID.into(),
            Box::new(sentry_app::secaudit::Done(audit_facts(server, network))),
        ),
        Instant::now(),
    );
    a.writer_answered("Fine.");
    key(&mut a, KeyCode::F(3));
    key(&mut a, KeyCode::Char('4'));
    typed(&mut a, "/nothing on doorsrv");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    let s = a.apply_session_at(NET).expect("a session on the network");
    assert_eq!(s.phase, Phase::Brief);
    assert!(s.web_off, "briefed about a router: no web");
    let brief = a.consent_text().unwrap();
    assert!(
        brief.contains("but nothing on doorsrv answers there")
            && brief.contains(&format!("About: net:{network}, srv:{server}")),
        "{brief}"
    );
    for c in AUDIT_CANARIES {
        assert!(!brief.contains(c), "{c}");
    }
    key(&mut a, KeyCode::Enter);
    assert!(!has_web(&a.session_profile_at(NET)));
    // One plan, a step on each: approved once.
    a.apply_answer_at(
        NET,
        &plan_of(&format!(
            "[[step]]\ntitle = \"See what listens\"\non = \"srv:{server}\"\nrun = \"ss -ltn\"\n\n\
             [[step]]\ntitle = \"Look at the forward\"\nrun = \"uci show firewall\"\n"
        )),
    );
    let s = a.apply_session_at(NET).unwrap();
    assert!(s.can_approve(), "{:?}", s.problems);
    assert_eq!(
        s.touched()
            .iter()
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>(),
        [format!("net:{network}"), format!("srv:{server}")]
    );
    a.slots[NET].apply_close_for_test();

    // What only the user knows: Enter is a pick; the answer is remembered and the rules
    // are gone through again over the facts this window read.
    let (id, q) = a
        .win
        .sec
        .report
        .as_ref()
        .unwrap()
        .items
        .iter()
        .find(|i| i.state == State::Ask)
        .map(|i| (i.id.clone(), i.question.clone().unwrap()))
        .expect("something only the user knows");
    let home = (0..3)
        .find(|i| a.slots[*i].shared.sec.iter().any(|x| x.id == id))
        .expect("listed by one target");
    a.apply_at(home, vec![Effect::SecItem(id.clone())]);
    a.focus(home, Instant::now());
    let s = tall(&mut a);
    assert!(
        s.contains("Only you know this") && s.contains("I don't know"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('2'));
    assert_eq!(a.win.sec.answers.get(&q), Some(false));
    let now = a
        .win
        .sec
        .report
        .as_ref()
        .unwrap()
        .items
        .iter()
        .find(|i| i.id == id)
        .map(|i| i.state);
    assert!(now.is_some() && now != Some(State::Ask), "{now:?}");
    assert!(
        !a.slots[home]
            .shared
            .sec
            .iter()
            .any(|x| x.id == id && x.state == State::Ask)
    );
}

/// A session on one of the security audit's rows is done only when the audit says so:
/// its plan runs, the audit reads every target again (once) for the slot that asked, and
/// while the new report still lists the item Claude is told and the row stays; when it no
/// longer does, the session settles done and the row goes. An audit already under way
/// when the session asks is not its answer: a fresh one runs after it.
#[test]
fn a_session_on_an_audit_row_waits_for_the_audit_to_say_it_is_gone() {
    use sentry_core::apply::session::{End, Phase};
    let (server, network) = ("asksrv", "asknet");
    let item = format!("sec:ssh-password:srv:{server}");
    let mut a = three_with(server, network);
    a.survey();
    a.on_event(
        Event::Data(
            sentry_local::tui::ID.into(),
            Box::new(sentry_app::secaudit::Done(audit_facts(server, network))),
        ),
        Instant::now(),
    );
    a.writer_answered("Fine.");
    a.win.sec.rerun_offline = true;
    // (A slot takes the report in with its next event.)
    key(&mut a, KeyCode::F(2));
    key(&mut a, KeyCode::Char('6'));
    let listed = |a: &App| a.slots[SRV].shared.sec.iter().any(|i| i.id == item);
    assert!(listed(&a));
    let srv_id = sentry_server::tui::id_of(server);
    let fixed = || {
        let mut f = audit_facts(server, network);
        f[1].ssh.as_mut().unwrap().password = Some(false);
        f
    };
    let done = |a: &mut App, facts| {
        a.on_event(
            Event::Data(srv_id.clone(), Box::new(sentry_app::secaudit::Done(facts))),
            Instant::now(),
        )
    };

    // The session, its plan, run.
    a.focus(SRV, Instant::now());
    a.apply_at(SRV, vec![Effect::SecItem(item.clone())]);
    key(&mut a, KeyCode::Enter);
    let session = |a: &mut App| {
        a.apply_answer_at(
            SRV,
            &plan_of("[[step]]\ntitle = \"Keys only\"\nrun = \"true\"\n"),
        );
        key(a, KeyCode::Enter);
        a.apply_exit_at(SRV, 0);
    };
    session(&mut a);
    // The audit reads again, for the server's slot; the session waits for it.
    assert!(a.win.sec.busy());
    assert_eq!(a.win.sec.asked.len(), 1);
    assert_eq!(a.win.sec.asked[0].slot, srv_id);
    let s = a.apply_session_at(SRV).unwrap();
    assert!(s.auditing() && s.phase == Phase::Applying);
    // It still lists it: Claude is told, nothing is done, the row stays.
    done(&mut a, audit_facts(server, network));
    let s = a.apply_session_at(SRV).unwrap();
    assert!(!s.auditing());
    assert!(
        s.chat
            .entries
            .iter()
            .any(|(_, l)| l.starts_with("the security audit still reports it")),
        "{:?}",
        s.chat.entries
    );
    assert!(listed(&a));
    a.apply_answer_at(
        SRV,
        "```sentry-verdict\nstatus = \"done\"\nsummary = \"keys only\"\n```",
    );
    let s = a.apply_session_at(SRV).unwrap();
    assert!(
        !matches!(s.phase, Phase::Settled(End::Done)),
        "{:?}",
        s.phase
    );
    assert!(!a.win.sec.busy(), "nothing changed since: no audit");
    assert!(listed(&a));
    // Another plan; this time the audit no longer lists it.
    session(&mut a);
    assert!(a.win.sec.busy());
    done(&mut a, fixed());
    let s = a.apply_session_at(SRV).unwrap();
    assert!(
        s.chat
            .entries
            .iter()
            .any(|(_, l)| l.starts_with("the security audit no longer reports it")),
        "{:?}",
        s.chat.entries
    );
    a.apply_answer_at(
        SRV,
        "```sentry-verdict\nstatus = \"done\"\nsummary = \"keys only\"\n```",
    );
    assert_eq!(
        a.apply_session_at(SRV).unwrap().phase,
        Phase::Settled(End::Done)
    );
    assert!(!a.win.sec.busy(), "done starts no second audit");
    // Its steps changed the server, and the audit it waited for answered after them: the
    // window owes the change no run of its own.
    assert!(a.last_change_at(SRV).is_some());
    assert!(a.win.sec.since().is_empty());
    a.tick(Instant::now());
    assert!(!a.win.sec.busy());
    assert!(!listed(&a));

    // While an audit is already under way, the ask waits for a fresh one.
    let mut a = three_with(server, network);
    a.survey();
    a.on_event(
        Event::Data(
            sentry_local::tui::ID.into(),
            Box::new(sentry_app::secaudit::Done(audit_facts(server, network))),
        ),
        Instant::now(),
    );
    a.writer_answered("Fine.");
    a.win.sec.rerun_offline = true;
    a.focus(SRV, Instant::now());
    a.apply_at(SRV, vec![Effect::SecItem(item.clone())]);
    key(&mut a, KeyCode::Enter);
    // (The user's own run, from this machine.)
    a.apply_at(LOCAL, vec![Effect::SecRun]);
    assert!(a.win.sec.busy());
    a.apply_answer_at(
        SRV,
        "Keys only already.\n```sentry-verdict\nstatus = \"done\"\nsummary = \"keys only\"\n```",
    );
    assert!(a.apply_session_at(SRV).unwrap().auditing());
    assert!(a.win.sec.asked.is_empty() && a.win.sec.again.len() == 1);
    // The run under way ends: not the session's answer; a fresh one starts for it.
    a.on_event(
        Event::Data(
            sentry_local::tui::ID.into(),
            Box::new(sentry_app::secaudit::Done(fixed())),
        ),
        Instant::now(),
    );
    assert!(a.apply_session_at(SRV).unwrap().auditing());
    assert!(a.win.sec.busy() && a.win.sec.asked.len() == 1 && a.win.sec.again.is_empty());
    // Its answer: gone, and the held done settles. (The fresh run was started where the
    // last one ended, this machine's slot: the answer goes to the server's as a parcel.)
    a.on_event(
        Event::Data(
            sentry_local::tui::ID.into(),
            Box::new(sentry_app::secaudit::Done(fixed())),
        ),
        Instant::now(),
    );
    assert_eq!(
        a.apply_session_at(SRV).unwrap().phase,
        Phase::Settled(End::Done)
    );
    assert!(!listed(&a) && !a.win.sec.busy());
}

/// The CrowdSec row on the network's Security page is a session across the server and
/// the router: what the server's guard says is carried by the app (the network target
/// knows no server), and Enter briefs one session with the whole job.
#[test]
fn the_edge_row_is_one_session_across_the_server_and_the_router() {
    use sentry_core::apply::session::Phase;
    let (server, network) = ("edgesrv", "edgenet");
    let mut a = three_with(server, network);
    a.set_wf_entries_at(
        NET,
        sentry_network::workflow::list_for(&sentry_network::tui::id_of(network)),
    );
    a.start(Instant::now());
    // Security is entered: the server, never looked at, starts so it can say.
    assert!(!a.started_at(SRV));
    key(&mut a, KeyCode::F(3));
    a.survey();
    key(&mut a, KeyCode::Char('4'));
    assert!(a.started_at(SRV) && a.focus == NET);
    // No server guard read, no bouncer on the router: no line, no row.
    let s = tall(&mut a);
    assert!(!s.contains("attacker") && !s.contains("CrowdSec"), "{s}");
    a.on_event(
        sentry_network::tui::testing::bouncer_ev(network, false),
        Instant::now(),
    );
    a.on_event(
        sentry_server::tui::testing::crowdsec_ev(server, 12, "http probing"),
        Instant::now(),
    );
    a.survey();
    let s = tall(&mut a);
    assert!(
        s.contains("edgesrv blocked 12 attacker(s) today (mostly http probing): see ")
            && s.contains("CrowdSec is installed on the router but switched off"),
        "{s}"
    );
    typed(&mut a, "/CrowdSec is installed");
    key(&mut a, KeyCode::Enter);
    assert!(
        bar_of(&mut a).contains("Enter  finish it"),
        "{}",
        bar_of(&mut a)
    );
    key(&mut a, KeyCode::Enter);
    let sess = a.apply_session_at(NET).expect("a session");
    assert_eq!(sess.phase, Phase::Brief);
    let brief = a.consent_text().unwrap();
    for said in [
        "local API reachable from the router",
        "captured as a secret",
        "a guarded change",
        "edgesrv blocked 12 attacker(s) today",
    ] {
        assert!(brief.contains(said), "{said}:\n{brief}");
    }
    // The router enforces: the row goes, the line says so.
    a.slots[NET].apply_close_for_test();
    a.on_event(
        sentry_network::tui::testing::bouncer_ev(network, true),
        Instant::now(),
    );
    key(&mut a, KeyCode::Esc);
    let s = tall(&mut a);
    assert!(
        s.contains("refuses them too") && !s.contains("but switched off"),
        "{s}"
    );
}

fn bar_of(a: &mut App) -> String {
    let s = tall(a);
    s.lines().last().unwrap_or_default().to_string()
}

fn ask_about(what: &str) -> Effect {
    Effect::AskConsent(Box::new(sentry_core::claude::Ask::apply(
        what,
        "ctx",
        sentry_core::claude::Apply {
            key: format!("task:{what}"),
            ..Default::default()
        },
    )))
}

fn plan_of(steps: &str) -> String {
    format!("On it.\n```sentry-apply\nsummary = \"do it\"\n{steps}```")
}

/// One thing at a time on a target: a step for one that is busy with a run of its own
/// waits, and says so; if that lasts, Claude hears that the step never started.
#[test]
fn a_step_for_a_busy_target_waits_and_says_so() {
    use sentry_core::apply::session::{Phase, Turn};
    for outlast in [false, true] {
        let name = if outlast { "heldlong" } else { "held" };
        let mut a = two_with(name, false);
        server_wf(&mut a, name, "harmless", &step("one", "auto", "true"));
        begin(&mut a, SRV, "harmless");
        assert!(run_at(&a, SRV).1, "its own run is at work");
        a.apply_at(LOCAL, vec![ask_about("reach")]);
        key(&mut a, KeyCode::Enter);
        a.apply_answer_at(
            LOCAL,
            &plan_of(&format!(
                "[[step]]\ntitle = \"There\"\non = \"srv:{name}\"\nrun = \"true\"\n"
            )),
        );
        key(&mut a, KeyCode::Enter);
        assert_eq!(a.guest_at(SRV), (false, true));
        let said = a.apply_session_at(LOCAL).unwrap().output.join("\n");
        assert_eq!(
            said,
            format!("waiting for {name} to finish its workflow harmless")
        );
        assert_eq!(a.needs(SRV), Needs::Working);
        if outlast {
            a.tick(Instant::now() + sentry_app::slot::guest::GUEST_WAIT);
            assert_eq!(a.guest_at(SRV), (false, false));
            let s = a.apply_session_at(LOCAL).unwrap();
            assert_eq!(s.phase, Phase::Thinking(Turn::Fix));
            let sent = a.slots[LOCAL].last_prompt.clone().unwrap();
            assert!(
                sent.contains("did not fail: it was never started")
                    && sent.contains("was still busy with its workflow harmless"),
                "{sent}"
            );
            continue;
        }
        // Its run ends: the step runs by itself, and the session goes on.
        a.run_step_exit_at(SRV, 0);
        a.tick(Instant::now());
        assert_eq!(a.guest_at(SRV), (true, false));
        // On the server's own screen the banner row says whose step runs there.
        key(&mut a, KeyCode::F(2));
        key(&mut a, KeyCode::Char('1'));
        let s = screen(&mut a);
        assert!(s.contains("· reach · a step of it runs here"), "{s}");
        a.guest_exit_at(SRV, 0);
        assert_eq!(
            a.apply_session_at(LOCAL).unwrap().phase,
            Phase::Thinking(Turn::Verify)
        );
    }
}

/// What a router keeps private stays so in a session that started on the server, and a
/// secret made on the server stays out of what the router's side writes.
#[test]
fn scrubbing_and_secrets_hold_across_targets() {
    use sentry_core::apply::session::{End, Phase};
    const PRIVATE: [&str; 2] = ["02:00:5e:00:53:20", "my-phone"];
    let mut a = three_with("scrubsrv", "scrubnet");
    task_session(&mut a, SRV, 2);
    key(&mut a, KeyCode::Enter);
    let p = a.session_profile_at(SRV);
    let first = a.slots[SRV].last_prompt.clone().unwrap();
    for c in PRIVATE {
        assert!(!p.system.contains(c) && !first.contains(c), "{c}");
    }
    assert!(
        p.allowed
            .iter()
            .any(|r| r == "Bash(sentry-network run scrubnet:*)")
    );
    // The server's session keeps its own way with the server, the web included: it has
    // read nothing from the router yet.
    assert!(p.allowed.iter().any(|d| d == "WebFetch"), "{:?}", p.allowed);
    a.apply_answer_at(
        SRV,
        &plan_of(
            "[[step]]\ntitle = \"Token\"\nrun = \"mktoken\"\ncapture = \"key\"\nsecret = true\n\n\
             [[step]]\ntitle = \"Who\"\non = \"net:scrubnet\"\nrun = \"cat /tmp/dhcp.leases\"\ncapture = \"lease\"\n\n\
             [[step]]\ntitle = \"Tell\"\non = \"net:scrubnet\"\nrun = \"logger -t bouncer '{{key}}'\"\n\n\
             [[step]]\ntitle = \"Use\"\nrun = \"note '{{lease}}'\"\n",
        ),
    );
    let s = a.apply_session_at(SRV).unwrap();
    assert!(s.can_approve(), "{:?}", s.problems);
    key(&mut a, KeyCode::Enter);
    // (No sudo in it: nothing is asked.) The server's own step prints the key.
    a.on_event(
        Event::Stream(
            sentry_server::tui::id_of("scrubsrv"),
            a.apply_session_at(SRV).unwrap().job.unwrap().0,
            sentry_core::exec::StreamMsg::Line {
                stderr: false,
                text: KEY.into(),
            },
        ),
        Instant::now(),
    );
    a.apply_exit_at(SRV, 0);
    // The router's lease line: what it printed reaches the session only scrubbed, and
    // what is captured there is hidden whether or not the step said so.
    let lease = format!("1793052000 {} 192.0.2.20 {} *", PRIVATE[0], PRIVATE[1]);
    a.guest_line_at(NET, &lease);
    assert!(
        !a.apply_session_at(SRV)
            .unwrap()
            .output
            .join("\n")
            .contains(PRIVATE[0])
    );
    a.guest_exit_at(NET, 0);
    // The key goes to the router in the command only; what the router echoes is swept.
    assert!(
        a.slots[NET]
            .last_guest_cmd
            .as_deref()
            .unwrap()
            .contains(KEY)
    );
    a.guest_line_at(NET, &format!("logged {KEY} for {}", PRIVATE[1]));
    let out = a.apply_session_at(SRV).unwrap().output.join("\n");
    assert!(!out.contains(KEY) && !out.contains(PRIVATE[1]), "{out}");
    a.guest_exit_at(NET, 0);
    // The server uses what the router knows: in the command, and in nothing Claude sees.
    assert!(
        a.slots[SRV]
            .last_step_cmd
            .as_deref()
            .unwrap()
            .contains(PRIVATE[0])
    );
    a.apply_exit_at(SRV, 0);
    let sent = a.slots[SRV].last_prompt.clone().unwrap();
    for c in PRIVATE.iter().chain([&KEY]) {
        assert!(!sent.contains(c), "{c}: {sent}");
    }
    assert!(sent.contains("kept as {{lease}} (hidden)"), "{sent}");
    // That turn, the one after the router's output came back, was sent without the web.
    let p = a.session_profile_at(SRV);
    assert!(
        p.denied.iter().any(|d| d == "WebFetch") && !p.allowed.iter().any(|d| d == "WebFetch"),
        "{:?}",
        p.denied
    );
    a.apply_answer_at(SRV, DONE);
    assert_eq!(
        a.apply_session_at(SRV).unwrap().phase,
        Phase::Settled(End::Done)
    );
    for i in [SRV, NET] {
        let e = a.slots[i].shared.log.first().expect("logged");
        assert!(
            e.head.tags.iter().any(|t| t.starts_with("run:")),
            "slot {i}: {:?}",
            e.head.tags
        );
        for c in PRIVATE.iter().chain([&KEY]) {
            assert!(!e.body.contains(c), "slot {i}: {c} in {}", e.body);
        }
    }
    let view = tall(&mut a);
    for c in PRIVATE.iter().chain([&KEY]) {
        assert!(!view.contains(c), "{c}");
    }
}

/// What a session's Claude is told on every kind of target, alone or with others: it never
/// sends the user to do something, and how a value gets where it is needed.
#[test]
fn every_sessions_claude_is_told_never_to_hand_the_work_back() {
    let alone =
        |id: &str,
         make: Box<dyn FnOnce(sentry_app::target::Mail) -> Box<dyn sentry_app::Target>>| {
            let (tx, _rx) = std::sync::mpsc::channel();
            let mut a = App::new(tx, id, make);
            a.win.offline = true;
            a.session_profile_at(0).system
        };
    let mut three = three_with("toldsrv", "toldnet");
    let mut texts = vec![
        alone(
            sentry_local::tui::ID,
            Box::new(sentry_local::tui::testing::target(Default::default())),
        ),
        alone(
            &sentry_server::tui::id_of("toldone"),
            Box::new(sentry_server::tui::target(Remote::new(
                "toldone",
                &Default::default(),
            ))),
        ),
        alone(
            &sentry_network::tui::id_of("toldnet1"),
            Box::new(sentry_network::tui::target(
                sentry_network::remote::Router::new("toldnet1", &Default::default()),
            )),
        ),
    ];
    for t in &texts {
        assert!(
            !t.contains("## The system"),
            "alone, there is no system to describe: {t}"
        );
    }
    for i in [LOCAL, SRV, NET] {
        let t = three.session_profile_at(i).system;
        assert!(
            t.contains("## The system") && t.contains("This session started here."),
            "{t}"
        );
        texts.push(t);
    }
    for t in &texts {
        for said in [
            "NEVER tell me to enter, paste, set, type or run something myself",
            "\"in your own session\"",
            "`capture = \"name\"`",
            "`ask = \"name\"`",
            "That is the ONLY way to get a value from me.",
            "uci set …api_key='{{key}}'",
            "Don't write a check that waits for me to have done something.",
        ] {
            assert!(t.contains(said), "{said}: {t}");
        }
    }
}

/// A secret a plan's own line sets on the router in a config that isn't guarded
/// (`crowdsec`, a bouncer's key written out by Claude) is a tag wherever the line is shown
/// or kept, as a guarded change's secrets are; the router gets the value.
#[test]
fn a_secret_a_plain_router_step_sets_is_a_tag_everywhere_but_on_the_router() {
    use sentry_core::apply::session::{End, Phase};
    const LITERAL: &str = "Literal-Bouncer-Key-77";
    let mut a = three_with("tagsrv", "tagnet");
    task_session(&mut a, NET, 3);
    key(&mut a, KeyCode::Enter);
    a.apply_answer_at(
        NET,
        &plan_of(&format!(
            "[[step]]\ntitle = \"Its key\"\nrun = \"uci set crowdsec.bouncer.api_key='{LITERAL}' && uci commit crowdsec\"\n"
        )),
    );
    let tag = sentry_network::redact::Salt::load(&sentry_network::tui::id_of("tagnet"))
        .unwrap()
        .tag(LITERAL);
    let view = tall(&mut a);
    assert!(
        !view.contains(LITERAL) && view.contains(&format!("api_key='{tag}'")),
        "{view}"
    );
    key(&mut a, KeyCode::Enter);
    let ran = a.slots[NET].last_step_cmd.clone().unwrap();
    assert!(ran.contains(LITERAL), "{ran}");
    a.on_event(
        Event::Stream(
            sentry_network::tui::id_of("tagnet"),
            a.apply_session_at(NET).unwrap().job.unwrap().0,
            sentry_core::exec::StreamMsg::Line {
                stderr: false,
                text: format!("crowdsec.bouncer.api_key='{LITERAL}'"),
            },
        ),
        Instant::now(),
    );
    assert!(!tall(&mut a).contains(LITERAL));
    a.apply_exit_at(NET, 0);
    let sent = a.slots[NET].last_prompt.clone().unwrap();
    assert!(!sent.contains(LITERAL) && sent.contains(&tag), "{sent}");
    a.apply_answer_at(NET, DONE);
    assert_eq!(
        a.apply_session_at(NET).unwrap().phase,
        Phase::Settled(End::Done)
    );
    let e = a.slots[NET].shared.log.first().expect("logged");
    assert!(
        !e.body.contains(LITERAL) && e.body.contains(&tag),
        "{}",
        e.body
    );
    for d in a.slots[NET].shared.plans.values() {
        assert!(!d.body.contains(LITERAL), "{}", d.body);
    }
    for (_, t) in &a.apply_session_at(NET).unwrap().chat.entries {
        assert!(!t.contains(LITERAL), "{t}");
    }
}

/// The two disposable targets together (`scripts/live-resolution.sh up|test|down`: the
/// sshd container whose sudo asks for a password, and the OpenWrt container, on one podman
/// network; scratch XDG dirs). One session, started on the router, Claude's turns scripted
/// (nothing is sent): its check (fetch a port on the server from the router) fails; the
/// plan Claude then sends opens that port on the server with sudo, captures the token the
/// server prints, and the router's check presents it and passes. One Enter approves that
/// plan, the server's password is typed once, in the session's own line; the token is in
/// no file; both targets' logs have the run. Never the real server or router.
#[test]
#[ignore]
fn live_resolution() {
    use sentry_core::apply::session::{End, Phase, Turn};
    sentry_core::paths::use_real_dirs();
    let (Ok(server), Ok(network), Ok(addr), Ok(pw)) = (
        std::env::var("SENTRY_SERVER_SCRATCH"),
        std::env::var("SENTRY_ROUTER_SCRATCH"),
        std::env::var("SENTRY_RESOLUTION_ADDR"),
        std::env::var("SENTRY_SERVER_SCRATCH_PASSWORD"),
    ) else {
        return;
    };
    for var in [
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "SENTRY_SSH_CONFIG",
    ] {
        assert!(std::env::var(var).is_ok(), "{var} must be set (scratch)");
    }
    let password = std::fs::read_to_string(pw).unwrap().trim().to_string();
    let (sfile, _) = sentry_server::config::load().unwrap();
    let (sn, sc) = sentry_server::config::pick(&sfile, Some(&server)).unwrap();
    let (nfile, _) = sentry_network::config::load().unwrap();
    let (nn, nc) = sentry_network::config::pick(&nfile, Some(&network)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let (cfg, _) = sentry_core::config::Config::load();
    let mut a = App::new(tx, sentry_local::tui::ID, sentry_local::tui::target(cfg));
    a.slots[LOCAL].screen = ScreenId::Upgrade;
    a.add(
        &sentry_server::tui::id_of(sn),
        sentry_server::tui::target(Remote::new(sn, sc)),
    );
    a.add(
        &sentry_network::tui::id_of(nn),
        sentry_network::tui::target(sentry_network::remote::Router::new(nn, nc)),
    );
    a.win.scripted_turns = true;
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
    let phase = |a: &App| a.apply_session_at(NET).map(|s| s.phase);
    // The router has the window; the server never does.
    key(&mut a, KeyCode::F(3));
    assert_eq!(a.focus, NET);
    // (What must be hidden from Claude is known once the router was read.)
    pump(&mut a, 6.0, &never);
    assert!(!a.started_at(SRV));

    // The security audit, for real: this machine and both containers read side by side
    // (reads only), from the router's Security page. The page starts the server (it
    // shows what a server's guard says; this one has none, so nothing is said).
    a.win.sec.collect = Some(std::sync::Arc::new(crate::secaudit::collect));
    key(&mut a, KeyCode::Char('4'));
    assert!(a.started_at(SRV) && a.focus == NET);
    key(&mut a, KeyCode::Char('S'));
    assert!(a.win.sec.busy(), "{:?}", a.toast_for_test());
    pump(&mut a, 180.0, &|a| {
        a.win.sec.report.is_some() && !a.win.sec.busy()
    });
    let report = a.win.sec.report.clone().expect("the audit ran");
    for id in [format!("srv:{sn}"), format!("net:{nn}")] {
        assert!(
            report.targets.iter().any(|t| t.id == id && t.reached),
            "{id} wasn't read: {:?}",
            report.errors
        );
    }
    // Behind each door (scripts/live-resolution.sh forwards two to the server): joined to
    // the server's listener and asked once from this machine. Without the inventory, what
    // answers isn't named, and the item says how to get it.
    let doors = |r: &sentry_core::secaudit::Report| {
        let of = |port: u16| {
            r.items
                .iter()
                .find(|i| i.id == format!("sec:door:net:{nn}:tcp:{port}"))
                .cloned()
                .unwrap_or_else(|| panic!("no door {port}: {:#?}", r.items))
        };
        let cert = r
            .items
            .iter()
            .find(|i| i.id == format!("sec:cert:net:{nn}:tcp:9443"))
            .cloned()
            .unwrap_or_else(|| panic!("no certificate item: {:#?}", r.items));
        (of(8081), of(9443), cert)
    };
    let (http, tls, cert) = doors(&report);
    use sentry_core::secaudit::State as Sec;
    for d in [&http, &tls] {
        assert!(d.targets.contains(&format!("srv:{sn}")), "{d:#?}");
    }
    assert!(
        http.evidence
            .iter()
            .any(|e| e.ends_with("without a login: it asks for a login (401)")),
        "{http:#?}"
    );
    assert_eq!(http.state, Sec::Fine, "{http:#?}");
    assert!(
        tls.evidence
            .iter()
            .any(|e| e.ends_with("it shows a page without asking for a login")),
        "{tls:#?}"
    );
    assert_eq!(tls.state, Sec::Ask, "{tls:#?}");
    assert!(tls.title.contains("Is that on purpose"), "{}", tls.title);
    assert_eq!(cert.state, Sec::Worth, "{cert:#?}");
    assert!(
        cert.evidence
            .iter()
            .any(|e| e == "the certificate is self-signed")
            && cert
                .evidence
                .iter()
                .any(|e| e == "it is good for 29 more days" || e == "it is good for 30 more days"),
        "{cert:#?}"
    );
    assert!(
        http.evidence
            .iter()
            .any(|e| e.contains("open the server target and press I")),
        "{http:#?}"
    );
    for i in &report.items {
        assert!(
            i.evidence.iter().all(|e| !e.contains(&addr)),
            "an address in {}: {:?}",
            i.id,
            i.evidence
        );
    }
    println!("doors: {} · {} · {}", http.title, tls.title, cert.title);
    let view = tall(&mut a);
    assert!(
        view.contains(" Security audit ") && view.contains("audited today"),
        "{view}"
    );
    key(&mut a, KeyCode::Esc);
    let page = tall(&mut a);
    assert!(
        page.contains("audited today · S shows it") && !page.contains("attacker"),
        "{page}"
    );
    // One of its items for the router opens a session briefed with the audit's words
    // (nothing is sent: the turns here are the test's).
    let item = a.slots[NET]
        .shared
        .sec
        .iter()
        .find(|i| i.question.is_none())
        .cloned();
    println!(
        "audit: {} · the router lists {} item(s)",
        report.summary(),
        a.slots[NET].shared.sec.len()
    );
    if let Some(item) = item {
        a.apply(vec![Effect::SecItem(item.id.clone())], Instant::now());
        let brief = a.consent_text().expect("a session's brief");
        assert!(brief.contains(&item.title), "{brief}");
        assert!(a.apply_session_at(NET).is_some_and(|s| s.web_off));
        a.slots[NET].apply_close_for_test();
    }

    a.apply(vec![ask_about("reach the server's door")], Instant::now());
    assert!(a.apply_session_at(NET).is_some(), "{}", screen(&mut a));
    assert!(a.started_at(SRV) && a.focus == NET);
    key(&mut a, KeyCode::Enter);
    assert_eq!(phase(&a), Some(Phase::Thinking(Turn::Investigate)));
    // Its Claude may read on the server too, through the server's own gateway.
    let p = a.session_profile_at(NET);
    assert!(
        p.allowed
            .contains(&format!("Bash(sentry-server run {sn}:*)")),
        "{:?}",
        p.allowed
    );
    assert!(
        p.system.contains(&format!("`srv:{sn}` (a server over ssh")),
        "{}",
        p.system
    );

    // The check alone: the router can't reach the port, because nothing listens there.
    let check =
        |token: &str| format!("wget -q -O - 'http://{addr}:8080/{token}' | grep -q door-open");
    a.apply_answer_at(
        NET,
        &plan_of(&format!(
            "[[step]]\ntitle = \"Reach the door\"\ncheck = \"{}\"\n",
            check("none")
        )),
    );
    assert_eq!(phase(&a), Some(Phase::Review), "{}", tall(&mut a));
    key(&mut a, KeyCode::Enter);
    pump(&mut a, 30.0, &|a| {
        phase(a) == Some(Phase::Thinking(Turn::Fix))
    });
    assert_eq!(
        phase(&a),
        Some(Phase::Thinking(Turn::Fix)),
        "{}",
        tall(&mut a)
    );
    let sent = a.slots[NET].last_prompt.clone().unwrap();
    assert!(
        sent.contains("stopped at step 1 (Reach the door), which failed"),
        "{sent}"
    );

    // The fix is on the server: open the door there (sudo), take the token it prints,
    // and present it from the router.
    a.apply_answer_at(
        NET,
        &plan_of(&format!(
            "[[step]]\ntitle = \"Open the door\"\non = \"srv:{sn}\"\nrun = \"sudo /usr/local/sbin/open-door\"\n\
             capture = \"token\"\nsecret = true\n\n\
             [[step]]\ntitle = \"Reach the door\"\ncheck = \"{}\"\n",
            check("{{token}}")
        )),
    );
    assert_eq!(phase(&a), Some(Phase::Review), "{}", tall(&mut a));
    // ONE approval; the server's password is asked here, once.
    key(&mut a, KeyCode::Enter);
    pump(&mut a, 10.0, &|a| {
        matches!(phase(a), Some(Phase::Password { .. }))
    });
    assert!(
        matches!(
            phase(&a),
            Some(Phase::Password {
                tries: 0,
                checking: false
            })
        ),
        "{}",
        tall(&mut a)
    );
    assert!(
        tall(&mut a).contains(&format!("sudo password (on {sn}, for step 1)")),
        "{}",
        tall(&mut a)
    );
    assert_eq!(a.focus, NET);
    typed(&mut a, &password);
    key(&mut a, KeyCode::Enter);
    let mut asked_again = false;
    let end = Instant::now() + std::time::Duration::from_secs(60);
    while Instant::now() < end && phase(&a) != Some(Phase::Thinking(Turn::Verify)) {
        if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(50)) {
            a.on_event(ev, Instant::now());
        }
        a.tick(Instant::now());
        asked_again |= matches!(phase(&a), Some(Phase::Password { tries, .. }) if tries > 0);
        asked_again |= a.unlock_at(SRV).is_some();
    }
    let view = tall(&mut a);
    assert_eq!(phase(&a), Some(Phase::Thinking(Turn::Verify)), "{view}");
    assert!(!asked_again, "the password was asked for once");
    assert!(a.holds_password_at(SRV));
    // The token the server printed: read back from the server, it is in nothing sentry
    // shows, sends or keeps.
    let token = Remote::new(sn, sc)
        .output(&Remote::new(sn, sc).sh("cat /tmp/door-token"))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(token.len(), 24, "the token");
    let sent = a.slots[NET].last_prompt.clone().unwrap();
    assert!(
        sent.contains("all 2 steps") && sent.contains("{{token}}"),
        "{sent}"
    );
    assert!(
        !sent.contains(&token) && !view.contains(&token),
        "{sent}\n{view}"
    );
    assert!(
        view.contains("‹token: hidden›") || view.contains("kept as {{token}} (hidden)"),
        "{view}"
    );
    a.apply_answer_at(NET, DONE);
    assert_eq!(phase(&a), Some(Phase::Settled(End::Done)));
    pump(&mut a, 1.0, &never);
    // Both targets' logs have the run.
    let run = format!("run:{}", a.apply_session_at(NET).unwrap().run_id);
    for (scope, with) in [
        (sentry_network::tui::id_of(nn), format!("with:srv:{sn}")),
        (sn.to_string(), format!("with:net:{nn}")),
    ] {
        let log = sentry_core::maint::log::list(&scope);
        let e = log
            .iter()
            .find(|e| e.head.tags.contains(&run))
            .unwrap_or_else(|| panic!("{scope}: no log entry tagged {run}"));
        assert!(e.head.tags.contains(&with), "{scope}: {:?}", e.head.tags);
        assert!(
            !e.body.contains(&token) && !e.body.contains(&password),
            "{}",
            e.body
        );
    }
    assert_eq!(files_with(&token), Vec::<std::path::PathBuf>::new());
    assert_eq!(files_with(&password), Vec::<std::path::PathBuf>::new());

    // The audit again, now that the server's password is held: the server reads its
    // inventory first, and the doors say what runs there from it, with its age.
    assert!(a.holds_password_at(SRV));
    let before = a.win.sec.report.as_ref().map(|r| r.at);
    a.apply(vec![Effect::SecRun], Instant::now());
    pump(&mut a, 180.0, &|a| {
        !a.win.sec.busy() && a.win.sec.report.as_ref().map(|r| r.at) != before
    });
    let report = a.win.sec.report.clone().expect("the audit ran again");
    let (http, _, _) = doors(&report);
    assert!(
        http.evidence
            .iter()
            .any(|e| e
                == "what runs there is from the server's inventory, read less than an hour ago"),
        "{http:#?}"
    );
    assert!(
        !http.evidence.iter().any(|e| e.contains("press I")),
        "{http:#?}"
    );
    println!(
        "live_resolution: one plan, two targets; the token went from the server to the router unseen; \
         the doors were joined and asked, with and without the inventory"
    );
}

/// Local-only (`#[ignore]`), reads only, against the real targets of the configs in the
/// (scratch) `XDG_CONFIG_HOME`: the window as `sentry` opens it, a network's Security page
/// from live reads, the security audit run from it (`S`: every target read side by side,
/// nothing sent to Claude), and where its rows land. Prints the pages: what they say is
/// the user's own and stays out of anything tracked.
/// `SENTRY_SYSTEM_LIVE=1 XDG_CONFIG_HOME=… XDG_DATA_HOME=… XDG_CACHE_HOME=… cargo test -p sentry live_system_security -- --ignored --nocapture`
#[test]
#[ignore]
fn live_system_security() {
    sentry_core::paths::use_real_dirs();
    if std::env::var("SENTRY_SYSTEM_LIVE").is_err() {
        return;
    }
    for var in ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"] {
        assert!(std::env::var(var).is_ok(), "{var} must be set (scratch)");
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let (cfg, _) = sentry_core::config::Config::load();
    assert!(
        !cfg.review.at_start && !cfg.review.after_run,
        "the scratch config.toml must turn [review] at_start and after_run off: no Claude turn here"
    );
    let mut a = App::new(tx, sentry_local::tui::ID, sentry_local::tui::target(cfg));
    a.slots[LOCAL].screen = ScreenId::Maint;
    let mut net = None;
    if let Ok((f, _)) = sentry_server::config::load() {
        for (name, c) in &f.servers {
            a.add(
                &sentry_server::tui::id_of(name),
                sentry_server::tui::target(Remote::new(name, c)),
            );
        }
    }
    if let Ok((f, _)) = sentry_network::config::load() {
        for (name, c) in &f.networks {
            let i = a.add(
                &sentry_network::tui::id_of(name),
                sentry_network::tui::target(sentry_network::remote::Router::new(name, c)),
            );
            net.get_or_insert(i);
        }
    }
    let net = net.expect("a network in network_config.yaml");
    a.win.scripted_turns = true;
    a.win.sec.collect = Some(std::sync::Arc::new(crate::secaudit::collect));
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
    a.focus(net, Instant::now());
    pump(&mut a, 6.0, &never);
    key(&mut a, KeyCode::Char('4'));
    pump(&mut a, 12.0, &never);
    a.survey();
    println!("=== Security, before the audit\n{}", tall(&mut a));
    key(&mut a, KeyCode::Char('S'));
    pump(&mut a, 300.0, &|a| {
        a.win.sec.report.is_some() && !a.win.sec.busy()
    });
    let report = a.win.sec.report.clone().expect("the audit ran");
    assert!(!report.empty());
    assert!(
        !a.writing() || a.win.sec.reviewing,
        "only the audit's own review"
    );
    println!("=== the report\n{}", tall(&mut a));
    key(&mut a, KeyCode::Esc);
    a.survey();
    pump(&mut a, 3.0, &never);
    let page = tall(&mut a);
    assert!(page.contains("audited today · S shows it"), "{page}");
    println!("=== Security, after the audit\n{page}");
    key(&mut a, KeyCode::Char('o'));
    println!("=== Security, everything\n{}", tall(&mut a));
    for i in 0..a.slots.len() {
        if i == net {
            continue;
        }
        a.focus(i, Instant::now());
        key(&mut a, KeyCode::Char('6'));
        pump(&mut a, 10.0, &never);
        println!(
            "=== Maintenance of slot {i}: {} audit item(s)\n{}",
            a.slots[i].shared.sec.len(),
            tall(&mut a)
        );
    }
    // No item is listed by two targets.
    let mut seen = std::collections::BTreeSet::new();
    for s in &a.slots {
        for i in &s.shared.sec {
            assert!(seen.insert(i.id.clone()), "{} listed twice", i.id);
        }
    }
    sentry_core::tui::Ui::shutdown(&mut a);
}

// ------------------------------------------------------------- a resolved row leaves at once

/// Every way a Maintenance row is resolved, on this machine, a server and a network side
/// by side: each gives what the way must (`Way::expect`: the row leaves at once, stays, or
/// returns), and where two kinds of target both have a way they behave the same. The ways
/// about files changed on disk have a process to themselves (`tests/rows_on_disk.rs`).
#[test]
fn a_resolved_row_leaves_at_once_on_every_target() {
    use sentry_app::resolve::{Outcome, Rig, Way, check};
    let rigs: [&dyn Rig; 3] = [
        &sentry_local::tui::testing::Rig,
        &sentry_server::tui::testing::Rig,
        &sentry_network::tui::testing::Rig,
    ];
    let seen: Vec<Vec<(Way, Outcome)>> = rigs.iter().map(|r| check(*r, false)).collect();
    let mut table = Vec::new();
    for (i, (way, _)) in seen[0].iter().enumerate() {
        let row: Vec<&Outcome> = seen.iter().map(|s| &s[i].1).collect();
        table.push(format!(
            "{way:?}: {}",
            rigs.iter()
                .zip(&row)
                .map(|(r, o)| format!("{} {o:?}", r.kind()))
                .collect::<Vec<_>>()
                .join(" · ")
        ));
        // The same on every target that has it, and what the way says.
        let had: Vec<(bool, bool)> = row
            .iter()
            .filter_map(|o| o.as_ref().ok().copied())
            .collect();
        assert!(!had.is_empty(), "no target has {way:?}: {row:?}");
        assert!(
            had.iter().all(|o| *o == way.expect()),
            "{way:?} differs between targets: {}",
            table.last().unwrap()
        );
        // A server and a network are both hosts with a config that says what must be
        // there: whatever one has, the other has.
        assert_eq!(row[1].is_ok(), row[2].is_ok(), "{}", table.last().unwrap());
    }
    // What this machine hasn't: nothing in its config to stop watching.
    let missing: Vec<Way> = seen[0]
        .iter()
        .filter(|(_, o)| o.is_err())
        .map(|(w, _)| *w)
        .collect();
    assert_eq!(missing, [Way::Unwatch, Way::UnwatchBack], "{table:#?}");
    println!("{}", table.join("\n"));
}

/// The facts `audit_facts` gives, with a tracked app on the server missing security fixes
/// (`sec:app:srv:<server>:web`).
fn audit_facts_with_app(server: &str, network: &str) -> Vec<sentry_core::secaudit::TargetFacts> {
    use sentry_core::secaudit::{Eol, Software};
    let mut f = audit_facts(server, network);
    f[1].software = Some(vec![Software {
        id: "web".into(),
        running: Some("1.0".into()),
        latest: Some("1.2".into()),
        behind: true,
        security: true,
        eol: Eol::Supported,
        container: None,
    }]);
    f
}

/// A server item's run that ends well changed the server: what the security audit's report
/// said of that item is withheld at once, while the server's other rows (its logins) stay;
/// the audit reads every target again by itself, quietly, and its answer is the row's.
#[test]
fn a_run_on_an_item_withholds_its_audit_row_until_the_audit_looks_again() {
    use sentry_app::effect::{ItemChange, WfCmd};
    let (server, network) = ("itemsrv", "itemnet");
    let mut a = three_with(server, network);
    server_wf(&mut a, server, "bump", &step("one", "auto", "true"));
    a.survey();
    a.on_event(
        Event::Data(
            sentry_local::tui::ID.into(),
            Box::new(sentry_app::secaudit::Done(audit_facts_with_app(
                server, network,
            ))),
        ),
        Instant::now(),
    );
    a.writer_answered("Fine.");
    a.win.sec.rerun_offline = true;
    key(&mut a, KeyCode::F(2));
    key(&mut a, KeyCode::Char('6'));
    let app = format!("sec:app:srv:{server}:web");
    let ssh = format!("sec:ssh-password:srv:{server}");
    let listed = |a: &App, id: &str| a.slots[SRV].shared.sec.iter().any(|i| i.id == id);
    assert!(listed(&a, &app) && listed(&a, &ssh));
    a.apply_at(
        SRV,
        vec![Effect::Wf(WfCmd::BeginPrefilled(
            "bump".into(),
            Default::default(),
            Some(ItemChange {
                item: "web".into(),
                from: Some("1.0".into()),
                to: Some("1.2".into()),
            }),
        ))],
    );
    assert!(a.slots[SRV].run.is_some(), "started");
    assert!(!a.win.sec.busy());
    a.run_step_exit_at(SRV, 0);
    assert!(run_at(&a, SRV).2, "done");
    // Withheld at once; the login's row stays. The audit reads again by itself.
    assert!(!listed(&a, &app), "{:?}", a.slots[SRV].shared.sec);
    assert!(listed(&a, &ssh));
    assert!(a.win.sec.busy() && a.win.sec.quiet);
    // Its answer: still missing its fixes (nothing really ran): the row is back.
    a.on_event(
        Event::Data(
            sentry_local::tui::ID.into(),
            Box::new(sentry_app::secaudit::Done(audit_facts_with_app(
                server, network,
            ))),
        ),
        Instant::now(),
    );
    assert!(!a.win.sec.busy() && a.win.sec.since().is_empty());
    key(&mut a, KeyCode::Null);
    assert!(listed(&a, &app) && listed(&a, &ssh));
}

/// A series of rows that each change the host costs one security audit, at its end: none
/// starts while the series is under way.
#[test]
fn a_series_of_changes_is_audited_once_at_its_end() {
    let mut a = two_with("seriesaudit", false);
    a.on_event(
        Event::Data(
            sentry_local::tui::ID.into(),
            Box::new(sentry_app::secaudit::Done(
                audit_facts("seriesaudit", "none")
                    .into_iter()
                    .take(2)
                    .collect(),
            )),
        ),
        Instant::now(),
    );
    a.writer_answered("Fine.");
    a.win.sec.rerun_offline = true;
    a.slots[SRV].shared.tasks = vec![task("one", "The first"), task("two", "The second")];
    a.slots[SRV].screen = ScreenId::Maint;
    key(&mut a, KeyCode::F(2));
    a.apply_at(
        SRV,
        vec![Effect::SeriesStart(vec![
            ("task:one".to_string(), "The first".to_string()),
            ("task:two".to_string(), "The second".to_string()),
        ])],
    );
    let row = |a: &mut App| {
        a.apply_answer_at(SRV, PLAN);
        key(a, KeyCode::Enter);
        while a.apply_session_at(SRV).is_some_and(|s| s.job.is_some())
            || a.slots[SRV].apply_aux_for_test()
        {
            a.apply_exit_at(SRV, 0);
        }
        a.apply_answer_at(SRV, DONE);
    };
    row(&mut a);
    assert_eq!(
        a.win.sec.since().len(),
        1,
        "the first row changed the server"
    );
    assert!(a.last_change_at(SRV).is_some());
    assert!(!a.win.sec.busy(), "the series is under way: no audit yet");
    a.tick(Instant::now());
    assert!(!a.win.sec.busy());
    row(&mut a);
    assert_eq!(a.win.sec.since().len(), 2);
    // The series is over: one quiet run, for both.
    assert_ne!(a.needs(SRV), Needs::Working);
    assert!(a.win.sec.busy() && a.win.sec.quiet);
    let rerun = a.win.sec.rerun_for;
    a.tick(Instant::now());
    assert_eq!(a.win.sec.rerun_for, rerun, "once");
}

/// A security report written while the window is open (`sentry audit security` from the
/// command line) is taken in where the window looks at its files: a newer one replaces
/// the report and its rows follow; an older one, or none new, changes nothing.
#[test]
fn a_security_report_written_meanwhile_is_taken_in() {
    let (server, network) = ("looksrv", "looknet");
    let mut a = three_with(server, network);
    a.survey();
    a.on_event(
        Event::Data(
            sentry_local::tui::ID.into(),
            Box::new(sentry_app::secaudit::Done(audit_facts(server, network))),
        ),
        Instant::now(),
    );
    a.writer_answered("Fine.");
    let at = a.win.sec.report.as_ref().unwrap().at;
    let ssh = format!("sec:ssh-password:srv:{server}");
    key(&mut a, KeyCode::F(2));
    key(&mut a, KeyCode::Char('6'));
    assert!(a.slots[SRV].shared.sec.iter().any(|i| i.id == ssh));
    // (The scratch dir every test process gets.)
    assert!(sentry_core::secaudit::dir().starts_with(std::env::temp_dir()));
    let base = a.win.sec.report.clone().unwrap();
    let written = |hours: i64, items| {
        let mut r = base.clone();
        r.at = at + jiff::SignedDuration::from_hours(hours);
        r.items = items;
        sentry_core::secaudit::save(&r).unwrap();
    };
    // An older one: not taken.
    written(-1, Vec::new());
    assert!(!a.sec_look_now());
    assert_eq!(a.win.sec.report.as_ref().unwrap().at, at);
    // A newer one, by the command line, with nothing to do: taken, and the rows follow.
    written(1, Vec::new());
    assert!(a.sec_look_now());
    assert!(a.win.sec.report.as_ref().unwrap().at > at);
    key(&mut a, KeyCode::Null);
    assert!(!a.slots[SRV].shared.sec.iter().any(|i| i.id == ssh));
    // Nothing new since: nothing is read.
    assert!(!a.sec_look_now());
    let _ = std::fs::remove_dir_all(sentry_core::secaudit::dir());
}

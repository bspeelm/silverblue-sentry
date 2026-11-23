//! The window's Config area: its tab in the strip, its own colour, its screens, staging and
//! the save box, and what follows a save. Nothing is spawned (`win.offline`); each test has
//! its own directory of config files (`ConfigArea::set_dir`), so no test sees another's
//! `config.toml`, and none the real one.

use std::path::{Path, PathBuf};
use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use sentry_app::app::render_to_string;
use sentry_app::cfgarea::agent::Msg;
use sentry_app::cfgarea::discover::{Candidate, Msg as Msg2, Source};
use sentry_app::cfgarea::kind::{CheckLine, Drafted, Probe};
use sentry_app::cfgarea::systems::ChecksDone;
use sentry_app::cfgarea::{Page, Screen, Step};
use sentry_app::{App, Event, Needs};
use sentry_core::cfg::{self, FileId};
use sentry_core::claude::{self, Found, Tested};
use sentry_core::config::Config;
use sentry_core::tui::ScreenId;
use sentry_core::tui::frame;
use sentry_core::workflows::runner::Next;

use crate::tests::{
    begin, key, one, run_at, screen, server_wf, step, three, top, two, two_with, typed,
};

const SERVERS: &str = "servers:\n  myserver:\n    ssh: admin@192.0.2.10\n    services: [app.service]\n    timers: [{unit: backup.timer, max_age: 26h}]\n";
const NETWORKS: &str = "networks:\n  home:\n    router: {ssh: myrouter}\n";

/// A directory of this test's own, holding these config files.
fn dir(files: &[(FileId, &str)]) -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "sentry-cfgtests-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    for (f, text) in files {
        std::fs::write(d.join(f.name()), text).unwrap();
    }
    d
}

/// The window `a` with the Config area reading the files in a directory of the test's.
pub(crate) fn with_files(mut a: App, files: &[(FileId, &str)]) -> (App, PathBuf) {
    let d = dir(files);
    for k in crate::tui::kinds() {
        a.config.register(k);
    }
    a.config.set_dir(&mut a.win, &d);
    (a, d)
}

/// This machine and `myserver`, the server's file saying so; the Config tab in view.
fn config(files: &[(FileId, &str)]) -> (App, PathBuf) {
    let mut all = vec![(FileId::Servers, SERVERS)];
    all.extend(files.iter().copied());
    let (mut a, d) = with_files(two(), &all);
    key(&mut a, KeyCode::F(3));
    assert!(a.in_config);
    (a, d)
}

pub(crate) fn text(d: &Path, f: FileId) -> Option<String> {
    std::fs::read_to_string(d.join(f.name())).ok()
}

fn backups(d: &Path, f: FileId) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(d)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&format!("{}.bak-", f.name())))
        .collect();
    v.sort();
    v
}

/// What is drawn on row `y` with the area's colour behind it (where its accent is).
fn on_accent(a: &mut App, y: u16) -> String {
    let mag = a.win.theme.mag;
    frame::text_on(158, 41, y, mag, |f| a.draw(f))
}

/// What is staged: `x path` ticked, `- path` unticked, `-! path` a conflict.
pub(crate) fn pending(a: &App) -> Vec<String> {
    a.config
        .pending
        .iter()
        .map(|p| {
            format!(
                "{}{} {}",
                if p.change.on { "x" } else { "-" },
                if p.conflict.is_some() { "!" } else { "" },
                p.change.path
            )
        })
        .collect()
}

pub(crate) fn problems(a: &App) -> Vec<String> {
    a.config.problems.iter().map(|p| p.line()).collect()
}

/// The selected field of the form in view is set to `text` (Enter, the line replaced, Enter).
pub(crate) fn set_field(a: &mut App, text: &str) {
    key(a, KeyCode::Enter);
    a.on_event(
        Event::Key(ratatui::crossterm::event::KeyEvent::new(
            KeyCode::Char('u'),
            ratatui::crossterm::event::KeyModifiers::CONTROL,
        )),
        Instant::now(),
    );
    a.on_event(Event::Paste(text.to_string()), Instant::now());
    key(a, KeyCode::Enter);
}

fn found(cmd: &str, path: Option<&str>) -> Event {
    Event::Config(Box::new(Msg::Found(Found {
        command: cmd.to_string(),
        path: path.map(PathBuf::from),
        version: path.map(|_| "2.1.0 (Claude Code)".to_string()),
    })))
}

/// The lines of the save box as it is on screen.
fn save_box(a: &App) -> Vec<String> {
    a.config
        .save
        .as_ref()
        .map(|b| b.lines.clone())
        .unwrap_or_default()
}

#[test]
fn the_config_tab_is_last_in_the_strip_and_the_area_has_its_own_colour() {
    let (mut a, _d) = config(&[]);
    key(&mut a, KeyCode::F(1));
    // Out of it: a tab like any other, after the targets, and nothing in its colour.
    insta::assert_snapshot!("config_tab_out_of_view_158", top(&mut a, 158));
    assert_eq!(on_accent(&mut a, 0), "");
    assert_eq!(on_accent(&mut a, 2), "");
    // In it: the chip says so, the chip and its tab are in its colour, and so is the rule
    // under its screens.
    key(&mut a, KeyCode::F(3));
    let s = screen(&mut a);
    insta::assert_snapshot!("config_overview_158", s);
    assert_eq!(on_accent(&mut a, 0), " sentry config  F3 config ");
    let mag = a.win.theme.mag;
    let rule = frame::text_in(158, 41, 2, mag, |f| a.draw(f));
    assert_eq!(rule, "─".repeat(158));
    // Its own screens, by its own keys: the targets' digits mean nothing here.
    assert!(
        s.lines().nth(1).unwrap().starts_with(
            " 1 Overview   2 Agent   3 This machine   4 Servers   5 Networks   6 Window"
        ),
        "{s}"
    );
    // Narrow: the other targets' names are cut, then left out, as the strip always did.
    insta::assert_snapshot!("config_overview_80", render_to_string(&mut a, 80, 30));
    let narrow = render_to_string(&mut a, 80, 30);
    assert!(narrow.starts_with(" sentry config "), "{narrow}");
    assert!(
        narrow.lines().next().unwrap().contains("F3 config"),
        "{narrow}"
    );
}

#[test]
fn the_tab_says_what_is_staged_and_what_is_wrong() {
    let (mut a, _d) = config(&[(FileId::App, "[keys]\nnope = \"x\"\n")]);
    // A problem in the files: `!` on the tab, wherever the window is.
    key(&mut a, KeyCode::F(1));
    let row = top(&mut a, 158);
    assert!(row.contains(" F3 config ! "), "{row}");
    // Something staged: `*` after its name.
    key(&mut a, KeyCode::F(3));
    key(&mut a, KeyCode::Char('3'));
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(pending(&a), ["x review.at_start"]);
    let row = top(&mut a, 158);
    assert!(row.contains(" F3 config* ! "), "{row}");
    assert!(row.contains("● 1 not saved"), "{row}");
    // The badges: what is staged on the Overview, the problems on the screen they are of.
    let s = screen(&mut a);
    let tabs = s.lines().nth(1).unwrap();
    assert!(
        tabs.contains("1 Overview 1*") && tabs.contains("6 Window 1"),
        "{tabs}"
    );
    // The field it is about says it, in place.
    key(&mut a, KeyCode::Char('6'));
    let s = screen(&mut a);
    assert!(s.contains("! [keys]: unknown action `nope`"), "{s}");
}

#[test]
fn config_and_its_key_give_it_the_window_and_a_target_key_takes_it_back() {
    let (mut a, _d) = with_files(two(), &[(FileId::Servers, SERVERS)]);
    assert!(!a.in_config);
    // `:config` from a target; the screen that target was on is kept for when it's back.
    key(&mut a, KeyCode::Char('5'));
    assert_eq!(a.slot().screen, ScreenId::Flat);
    typed(&mut a, ":config");
    key(&mut a, KeyCode::Enter);
    assert!(a.in_config);
    assert_eq!(a.toast_for_test(), None);
    // A digit is the area's screen now, not the target's.
    key(&mut a, KeyCode::Char('4'));
    assert_eq!(a.config.screen, Screen::Servers);
    assert_eq!(a.slots[0].screen, ScreenId::Flat);
    // A target's key takes the window back; so do the window's `:` commands.
    key(&mut a, KeyCode::F(2));
    assert_eq!((a.in_config, a.focus), (false, 1));
    key(&mut a, KeyCode::F(3));
    assert!(a.in_config);
    typed(&mut a, ":local");
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        (a.in_config, a.focus, a.slot().screen),
        (false, 0, ScreenId::Flat)
    );
    key(&mut a, KeyCode::F(3));
    typed(&mut a, ":server mys");
    key(&mut a, KeyCode::Enter);
    assert_eq!((a.in_config, a.focus), (false, 1));
    // Its own `:` commands are its screens; one nobody knows says so.
    key(&mut a, KeyCode::F(3));
    typed(&mut a, ":window");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.screen, Screen::Window);
    typed(&mut a, ":nonsense");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.toast_for_test(), Some("unknown command :nonsense"));
    assert!(a.in_config);
    // While a field is typed, a brace is a character, not the window's key; an F-key is.
    key(&mut a, KeyCode::Char('2'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    typed(&mut a, "}");
    assert!(a.in_config && screen(&mut a).contains("claude}▏"));
    key(&mut a, KeyCode::Esc);
    // `?` is its own help; `q` asks as everywhere, and says what would be dropped.
    key(&mut a, KeyCode::Char('?'));
    assert!(screen(&mut a).contains("Keys · sentry config"));
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('3'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('q'));
    let s = screen(&mut a);
    assert!(
        s.contains("Quit sentry?") && s.contains("1 change staged in Config is not saved"),
        "{s}"
    );
    assert!(!a.win.quit);
    key(&mut a, KeyCode::Esc);
    assert!(a.win.modal.is_none() && !a.win.quit);
    key(&mut a, KeyCode::Char('q'));
    key(&mut a, KeyCode::Enter);
    assert!(a.win.quit);
}

#[test]
fn sentry_config_opens_the_window_on_its_tab() {
    let mut a = one();
    a.config_at_start();
    a.start(Instant::now());
    assert!(a.in_config);
    assert!(screen(&mut a).starts_with(" sentry config "));
    // No target has had the window yet: this machine starts when it first does.
    assert!(!a.started_at(0));
    key(&mut a, KeyCode::F(1));
    assert!(!a.in_config && a.started_at(0));
    // The plan is `sentry`'s own: every target, this machine behind the tab.
    let p = crate::tui::plan_all(&Config::default(), None, None, crate::tui::Open::Config).unwrap();
    assert!(p.warnings.is_empty());
}

#[test]
fn every_slot_runs_on_while_config_has_the_window() {
    let (mut a, _d) = with_files(two_with("cfgrun", false), &[]);
    server_wf(
        &mut a,
        "cfgrun",
        "careful",
        &(step("look", "auto", "true") + &step("change", "confirm", "true")),
    );
    key(&mut a, KeyCode::F(2));
    begin(&mut a, 1, "careful");
    key(&mut a, KeyCode::F(3));
    assert!(a.in_config);
    assert_eq!(run_at(&a, 1), (Next::Run(0), true, false));
    // Its mark is in the strip while it works.
    assert_eq!(a.needs(1), Needs::Working);
    assert!(top(&mut a, 158).contains(" F2 cfgrun * "));
    // The step ends while the Config area is in view: the run goes on to its confirm, the
    // strip flags it and one toast says whose it is. (The slot that had the window last is
    // out of view too: its events and toasts are a slot's out of view.)
    a.run_step_exit_at(1, 0);
    a.tick(Instant::now());
    assert_eq!(run_at(&a, 1), (Next::Confirm(1), false, false));
    assert_eq!(a.needs(1), Needs::You("a step to confirm"));
    assert_eq!(
        a.toast_for_test(),
        Some("cfgrun · needs you: a step to confirm")
    );
    assert!(top(&mut a, 158).contains(" F2 cfgrun ! "));
    // Enter here is the area's key: nothing of the server's is answered.
    key(&mut a, KeyCode::Enter);
    a.tick(Instant::now());
    assert_eq!(run_at(&a, 1), (Next::Confirm(1), false, false));
    // Back on it, Enter is the confirm.
    key(&mut a, KeyCode::F(2));
    key(&mut a, KeyCode::Enter);
    assert_eq!(run_at(&a, 1), (Next::Confirm(1), true, false));
}

#[test]
fn editing_a_field_stages_it_and_writes_nothing() {
    let (mut a, d) = config(&[]);
    assert_eq!(text(&d, FileId::App), None);
    let servers_before = text(&d, FileId::Servers);
    // The agent's command, in its form: a real line editor.
    key(&mut a, KeyCode::Char('2'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Home);
    typed(&mut a, "/opt/");
    insta::assert_snapshot!("config_form_editing_158", screen(&mut a));
    key(&mut a, KeyCode::Enter);
    assert_eq!(pending(&a), ["x agent.command"]);
    // A yes/no and a list, on This machine.
    key(&mut a, KeyCode::Char('3'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    typed(&mut a, "~/notes/upgrades.md");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Esc);
    assert_eq!(
        pending(&a),
        [
            "x agent.command",
            "x review.at_start",
            "x maintenance.notes"
        ]
    );
    // What the area holds is what would be written; nothing has been.
    let cfg = a.config.app().unwrap();
    assert_eq!(cfg.agent.command, "/opt/claude");
    assert!(!cfg.review.at_start);
    assert_eq!(cfg.maintenance.notes, ["~/notes/upgrades.md"]);
    assert_eq!(
        text(&d, FileId::App),
        None,
        "nothing is written before the save box"
    );
    assert_eq!(text(&d, FileId::Servers), servers_before);
    assert!(backups(&d, FileId::App).is_empty());
    // The Overview lists them; the selected one shows before → after.
    key(&mut a, KeyCode::Char('1'));
    for _ in 0..4 {
        key(&mut a, KeyCode::Char('j'));
    }
    insta::assert_snapshot!("config_overview_pending_158", screen(&mut a));
    // Space leaves one out (what is to be follows), Space again takes it back in.
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(
        pending(&a),
        [
            "x agent.command",
            "- review.at_start",
            "x maintenance.notes"
        ]
    );
    assert!(a.config.app().unwrap().review.at_start);
    key(&mut a, KeyCode::Char(' '));
    assert!(!a.config.app().unwrap().review.at_start);
    // `u` takes the selected one back: it is no change any more, and the value is the
    // file's again.
    key(&mut a, KeyCode::Char('u'));
    assert_eq!(pending(&a), ["x agent.command", "x maintenance.notes"]);
    assert!(a.config.app().unwrap().review.at_start);
    // `u` on a form's field does the same; a field set back to what the file says is no
    // change either.
    key(&mut a, KeyCode::Char('2'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('u'));
    assert_eq!(pending(&a), ["x maintenance.notes"]);
    set_field(&mut a, "claude2");
    set_field(&mut a, "claude");
    assert_eq!(pending(&a), ["x maintenance.notes"]);
    assert_eq!(text(&d, FileId::App), None);
    // What the type wouldn't read is refused in place, and nothing is staged for it.
    key(&mut a, KeyCode::Char('6'));
    for _ in 0..2 {
        key(&mut a, KeyCode::Char('j'));
    }
    set_field(&mut a, "99999999999999");
    let s = screen(&mut a);
    assert!(s.contains("     ! retention.log_months:"), "{s}");
    assert_eq!(pending(&a), ["x maintenance.notes"]);
    set_field(&mut a, "six");
    assert!(screen(&mut a).contains("! `six` isn't a whole number"));
    key(&mut a, KeyCode::Esc);
    assert_eq!(pending(&a), ["x maintenance.notes"]);
}

#[test]
fn the_save_box_says_what_will_be_written_and_enter_writes_it() {
    // A new file.
    let (mut a, d) = config(&[]);
    key(&mut a, KeyCode::Char('3'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('s'));
    assert_eq!(
        save_box(&a),
        [
            "  config.toml           this machine: Review at start  (a new file)",
            "",
            "  this machine · Review at start: off",
            "",
            "What follows: reviews at start and after a run follow it from now",
            "Kept before saving: nothing (there was no file).",
        ]
    );
    assert_eq!(text(&d, FileId::App), None, "the box writes nothing");
    // Esc goes back with everything still staged.
    key(&mut a, KeyCode::Esc);
    assert!(a.config.save.is_none());
    assert_eq!(pending(&a), ["x review.at_start"]);
    assert_eq!(text(&d, FileId::App), None);
    // Enter writes it: the file is what sentry renders for the value, nothing is staged.
    key(&mut a, KeyCode::Char('s'));
    key(&mut a, KeyCode::Enter);
    assert!(a.config.save.is_none() && pending(&a).is_empty());
    let written = text(&d, FileId::App).unwrap();
    let mut want = Config::default();
    want.review.at_start = false;
    assert_eq!(written, cfg::render(&want).unwrap());
    assert!(
        backups(&d, FileId::App).is_empty(),
        "there was nothing to keep"
    );
    assert_eq!(a.toast_for_test(), Some("saved config.toml (new)"));
    // Nothing staged: `s` says so and opens nothing.
    key(&mut a, KeyCode::Char('s'));
    assert!(a.config.save.is_none());
    assert_eq!(a.toast_for_test(), Some("nothing to save"));

    // A file sentry wrote: the copy that will be kept is named, nothing else is said.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('s'));
    assert_eq!(
        save_box(&a),
        [
            "  config.toml           this machine: Review after a run",
            "",
            "  this machine · Review after a run: off",
            "",
            "What follows: reviews at start and after a run follow it from now",
            "Kept before saving: config.toml.bak-<UTC time> (beside it, the newest 5)",
        ]
    );
    key(&mut a, KeyCode::Enter);
    let kept = backups(&d, FileId::App);
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(std::fs::read_to_string(d.join(&kept[0])).unwrap(), written);
    assert!(
        !Config::parse(&text(&d, FileId::App).unwrap())
            .unwrap()
            .0
            .review
            .after_run
    );
}

#[test]
fn a_hand_written_file_is_said_to_lose_its_comments_and_its_problems_are_read_again() {
    let mine =
        "# my own notes about this file\n[ui]\nbogus = 1\n\n[keys]\nnope = \"x\"\nquit = \"Q\"\n";
    let (mut a, d) = config(&[(FileId::App, mine)]);
    assert_eq!(
        problems(&a),
        [
            "config.toml: unknown key `ui.bogus` ignored",
            "config.toml: [keys]: unknown action `nope`",
        ]
    );
    // The bad key is taken out in the form: that problem is gone at once (what is shown is
    // the file as it is to be); the unknown key stays until the file is written.
    key(&mut a, KeyCode::Char('6'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('x'));
    key(&mut a, KeyCode::Esc);
    assert_eq!(pending(&a), ["x keys"]);
    assert_eq!(
        problems(&a),
        ["config.toml: unknown key `ui.bogus` ignored"]
    );
    assert_eq!(a.win.config_problems.len(), 1);
    key(&mut a, KeyCode::Char('s'));
    insta::assert_snapshot!("config_save_box_158", screen(&mut a));
    assert_eq!(
        save_box(&a),
        [
            "  config.toml           window: Keys",
            "",
            "  window · Keys: − nope",
            "",
            "What follows: keys are rebound now, in every target",
            "Kept before saving: config.toml.bak-<UTC time> (beside it, the newest 5)",
            "! config.toml was written by hand: its comments and layout are not kept.",
            "! config.toml: not kept either: unknown key `ui.bogus` ignored",
        ]
    );
    assert_eq!(text(&d, FileId::App).as_deref(), Some(mine));
    key(&mut a, KeyCode::Enter);
    // Written: sentry's own text, the hand-written one beside it, nothing wrong any more.
    let now = text(&d, FileId::App).unwrap();
    assert!(now.starts_with("# sentry's configuration") && !now.contains("my own notes"));
    assert!(now.contains("quit = \"Q\"") && !now.contains("nope") && !now.contains("bogus"));
    let kept = backups(&d, FileId::App);
    assert_eq!(kept.len(), 1);
    assert_eq!(std::fs::read_to_string(d.join(&kept[0])).unwrap(), mine);
    assert!(problems(&a).is_empty() && a.win.config_problems.is_empty());
    assert!(pending(&a).is_empty());
    let row = top(&mut a, 158);
    assert!(row.contains(" F3 config ") && !row.contains("config*") && !row.contains("config !"));
    // The next save of it has nothing to say about comments.
    key(&mut a, KeyCode::Char('3'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('s'));
    assert!(
        !save_box(&a).iter().any(|l| l.starts_with('!')),
        "{:?}",
        save_box(&a)
    );
}

#[test]
fn a_file_changed_on_disk_under_what_is_staged_is_read_again_never_written_over() {
    let mut base = Config::default();
    base.review.at_start = false;
    let ours = cfg::render(&base).unwrap();
    let (mut a, d) = config(&[(FileId::App, ours.as_str())]);
    // Two changes staged against the file as it was.
    key(&mut a, KeyCode::Char('2'));
    key(&mut a, KeyCode::Char('j'));
    set_field(&mut a, "/opt/claude");
    key(&mut a, KeyCode::Char('3'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(pending(&a), ["x agent.command", "x review.after_run"]);
    // Meanwhile the file is rewritten elsewhere: the command is another one now, and the
    // terminal is set.
    let mut theirs = base.clone();
    theirs.agent.command = "claude-beta".into();
    theirs.ui.terminal = Some("ghostty -e".into());
    std::fs::write(d.join("config.toml"), cfg::render(&theirs).unwrap()).unwrap();
    // The save box looks first: the one that still fits is made on the newer file, the one
    // whose `from` isn't there any more is a conflict, unticked, with why.
    key(&mut a, KeyCode::Char('s'));
    assert_eq!(pending(&a), ["-! agent.command", "x review.after_run"]);
    let why = a.config.pending[0].conflict.clone().unwrap();
    assert!(
        why.contains("agent.command is \"claude-beta\" now, not \"claude\""),
        "{why}"
    );
    let cfg_now = a.config.app().unwrap().clone();
    assert_eq!(cfg_now.agent.command, "claude-beta", "theirs stands");
    assert_eq!(cfg_now.ui.terminal.as_deref(), Some("ghostty -e"));
    assert!(!cfg_now.review.after_run, "mine was made on it");
    assert!(
        save_box(&a)
            .iter()
            .any(|l| l == "Left out, still staged: 1 that no longer fit the file."),
        "{:?}",
        save_box(&a)
    );
    // The window follows what the file says now (the command), before anything is saved.
    assert_eq!(claude::command(), "claude-beta");
    // Saving writes theirs with mine on top; the conflict stays staged to look at.
    key(&mut a, KeyCode::Enter);
    let saved = Config::parse(&text(&d, FileId::App).unwrap()).unwrap().0;
    assert_eq!(saved.agent.command, "claude-beta");
    assert_eq!(saved.ui.terminal.as_deref(), Some("ghostty -e"));
    assert!(!saved.review.after_run && !saved.review.at_start);
    assert_eq!(pending(&a), ["-! agent.command"]);
    // Ticking it again says why it can't be; `u` drops it.
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char('G'));
    key(&mut a, KeyCode::Char(' '));
    assert!(
        a.toast_for_test()
            .unwrap()
            .starts_with("it no longer fits the file:")
    );
    assert!(screen(&mut a).contains("! It no longer fits the file"));
    key(&mut a, KeyCode::Char('u'));
    assert!(pending(&a).is_empty());

    // A file changed while the save box is open is not written over either: Enter reads
    // it, says so, and the box shows what the save is now.
    key(&mut a, KeyCode::Char('3'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('s'));
    assert!(a.config.save.is_some());
    let mut again = saved.clone();
    again.retention.reviews = 3;
    let between = cfg::render(&again).unwrap();
    std::fs::write(d.join("config.toml"), &between).unwrap();
    key(&mut a, KeyCode::Enter);
    assert_eq!(text(&d, FileId::App).unwrap(), between, "not written over");
    assert!(a.config.save.is_some());
    assert_eq!(pending(&a), ["x review.at_start"]);
    key(&mut a, KeyCode::Enter);
    let last = Config::parse(&text(&d, FileId::App).unwrap()).unwrap().0;
    assert_eq!((last.retention.reviews, last.review.at_start), (3, true));
}

#[test]
fn e_opens_the_file_and_what_comes_back_is_read_and_checked() {
    let (mut a, d) = config(&[]);
    // On the Overview: the selected system's file. On a screen: that screen's.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('e'));
    let (cmd, _) = a.take_suspend().expect("the editor");
    assert!(
        cmd.quoted_argv().ends_with("server_config.yaml"),
        "{}",
        cmd.quoted_argv()
    );
    key(&mut a, KeyCode::Char('6'));
    key(&mut a, KeyCode::Char('e'));
    let (cmd, _) = a.take_suspend().expect("the editor");
    assert!(
        cmd.quoted_argv().ends_with("config.toml"),
        "{}",
        cmd.quoted_argv()
    );
    // (A slot's own command never has the terminal while the Config area is in view.)
    // The editor wrote something wrong: it is read, checked, and said.
    std::fs::write(d.join("config.toml"), "[ui]\nbogus = 1\n").unwrap();
    a.config_edited_for_test();
    assert_eq!(
        problems(&a),
        ["config.toml: unknown key `ui.bogus` ignored"]
    );
    assert_eq!(
        a.toast_for_test(),
        Some("config.toml read again: 1 problem")
    );
    // One that doesn't parse: no form, the reason, and `e` again.
    std::fs::write(d.join("config.toml"), "[ui\n").unwrap();
    a.config_edited_for_test();
    assert_eq!(a.config.problems.len(), 1);
    let s = screen(&mut a);
    assert!(
        s.contains("config.toml doesn't parse:") && s.contains("e opens it in $EDITOR"),
        "{s}"
    );
    // Put right: the form is back. `c` checks again and says what it found.
    std::fs::write(d.join("config.toml"), "[review]\nat_start = false\n").unwrap();
    a.config_edited_for_test();
    assert!(problems(&a).is_empty());
    key(&mut a, KeyCode::Char('c'));
    assert_eq!(
        a.toast_for_test(),
        Some("checked: nothing wrong in the files")
    );
    assert!(!a.config.app().unwrap().review.at_start);
    // What the file says now is what the window goes by: the edit was followed.
    assert!(!a.win.cfg.review.at_start);
}

#[test]
fn a_saved_keys_change_rebinds_every_slot_at_once() {
    let (mut a, _d) = config(&[]);
    // `quit = Q`, and the server's Services on F9, typed into the Keys list.
    key(&mut a, KeyCode::Char('6'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    typed(&mut a, "quit = Q");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('n'));
    typed(&mut a, "screen.services = F9");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Esc);
    // Staged only: `q` still asks to quit, in the area and in a slot.
    key(&mut a, KeyCode::Char('q'));
    assert!(a.win.modal.is_some());
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('s'));
    assert!(
        save_box(&a).contains(&"What follows: keys are rebound now, in every target".to_string())
    );
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.toast_for_test(), Some("saved config.toml (new)"));
    // Saved: no restart. `q` is nothing now and `Q` asks, here…
    key(&mut a, KeyCode::Char('q'));
    assert!(a.win.modal.is_none());
    key(&mut a, KeyCode::Char('Q'));
    assert!(a.win.modal.is_some());
    key(&mut a, KeyCode::Esc);
    // …on this machine (whose keymap is the window's while it has it)…
    key(&mut a, KeyCode::F(1));
    key(&mut a, KeyCode::Char('q'));
    assert!(a.win.modal.is_none());
    key(&mut a, KeyCode::Char('Q'));
    assert!(a.win.modal.is_some());
    key(&mut a, KeyCode::Esc);
    // …and on the server, which was out of view and has a screen of its own rebound.
    key(&mut a, KeyCode::F(2));
    key(&mut a, KeyCode::Char('q'));
    assert!(a.win.modal.is_none());
    key(&mut a, KeyCode::F(9));
    assert_eq!(a.slot().screen, ScreenId::Svc);
    key(&mut a, KeyCode::Char('Q'));
    assert!(a.win.modal.is_some());
}

#[test]
fn saved_reviews_agent_and_notes_are_what_the_window_goes_by() {
    let (mut a, d) = config(&[]);
    assert_eq!(claude::command(), "claude");
    assert!(a.slots[0].auto_review.at_start && a.slots[1].auto_review.after_run);
    key(&mut a, KeyCode::Char('2'));
    key(&mut a, KeyCode::Char('j'));
    set_field(&mut a, "/opt/claude/bin/claude");
    key(&mut a, KeyCode::Char('3'));
    key(&mut a, KeyCode::Char(' '));
    // (The terminal: the fourth field. Its Upkeep comes after it.)
    for _ in 0..3 {
        key(&mut a, KeyCode::Char('j'));
    }
    set_field(&mut a, "ghostty -e");
    // Staged: the window still goes by the file.
    assert_eq!(claude::command(), "claude");
    assert!(a.slots[1].auto_review.at_start);
    key(&mut a, KeyCode::Char('s'));
    key(&mut a, KeyCode::Enter);
    assert!(
        text(&d, FileId::App)
            .unwrap()
            .contains("command = \"/opt/claude/bin/claude\"")
    );
    // Saved: what `available()` looks for and every turn starts is the new command…
    assert_eq!(claude::command(), "/opt/claude/bin/claude");
    assert!(
        claude::turn_cmd("hi", None)
            .quoted_argv()
            .starts_with("/opt/claude/bin/claude -p hi "),
        "{}",
        claude::turn_cmd("hi", None).quoted_argv()
    );
    assert!(
        claude::interactive_cmd("s")
            .quoted_argv()
            .starts_with("/opt/claude/bin/claude ")
    );
    // …every slot's reviews follow, and the window's copy of the file is the new one (what
    // a target started later is given, and this machine was told: `Target::configured`).
    assert!(!a.slots[0].auto_review.at_start && !a.slots[1].auto_review.at_start);
    assert!(a.slots[1].auto_review.after_run);
    assert_eq!(a.win.cfg.ui.terminal.as_deref(), Some("ghostty -e"));
    assert_eq!(a.win.cfg.agent.command, "/opt/claude/bin/claude");
    // Back at the default, it is `claude` again.
    key(&mut a, KeyCode::Char('2'));
    key(&mut a, KeyCode::Char('j'));
    set_field(&mut a, "claude");
    key(&mut a, KeyCode::Char('s'));
    key(&mut a, KeyCode::Enter);
    assert_eq!(claude::command(), "claude");
    assert!(
        !text(&d, FileId::App).unwrap().contains("[agent]"),
        "a default isn't written"
    );
}

#[test]
fn saved_targets_reorder_and_hide_the_strip_by_id() {
    let (mut a, _d) = with_files(
        three(),
        &[(FileId::Servers, SERVERS), (FileId::Networks, NETWORKS)],
    );
    // This machine has the window and is on Flatpaks; then the Config tab.
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::F(4));
    assert!(a.in_config);
    // Window › Shown: the list starts as the targets there are; the server first, the
    // network out.
    key(&mut a, KeyCode::Char('6'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('J'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('x'));
    key(&mut a, KeyCode::Esc);
    assert_eq!(
        a.config.app().unwrap().targets.show.as_deref(),
        Some(&["srv:myserver".to_string(), "local".to_string()][..])
    );
    // Nothing moved yet.
    assert!(top(&mut a, 158).contains(" F1 silverblue 44.1   F2 myserver   F3 home   F4 config* "));
    key(&mut a, KeyCode::Char('s'));
    assert!(
        save_box(&a).contains(&"What follows: home leaves the strip".to_string()),
        "{:?}",
        save_box(&a)
    );
    key(&mut a, KeyCode::Enter);
    // At once: the strip in that order, the network without a tab, the Config tab's key the
    // next by place.
    insta::assert_snapshot!("config_strip_reordered_158", top(&mut a, 158));
    assert!(a.in_config);
    let titles: Vec<&str> = a.slots.iter().map(|s| s.title()).collect();
    assert_eq!(titles, ["myserver", "silverblue 44.1", "home"]);
    assert_eq!(
        a.slots.iter().map(|s| s.hidden).collect::<Vec<_>>(),
        [false, false, true]
    );
    // By id, not place: the slot behind the tab is still this machine, on its screen.
    assert_eq!(a.slot().title(), "silverblue 44.1");
    key(&mut a, KeyCode::F(2));
    assert_eq!(
        (a.in_config, a.slot().title(), a.slot().screen),
        (false, "silverblue 44.1", ScreenId::Flat)
    );
    key(&mut a, KeyCode::F(1));
    assert_eq!(a.slot().title(), "myserver");
    // The keys go round what is shown; the hidden one has no key and no `:` name.
    key(&mut a, KeyCode::Char('}'));
    assert_eq!(a.slot().title(), "silverblue 44.1");
    key(&mut a, KeyCode::Char('}'));
    assert!(a.in_config);
    key(&mut a, KeyCode::F(4));
    assert!(a.in_config, "F4 is nobody's now");
    typed(&mut a, ":net home");
    key(&mut a, KeyCode::Enter);
    assert!(a.in_config);
    assert_eq!(a.toast_for_test(), Some("unknown command :net home"));
    // The Overview says it is hidden.
    key(&mut a, KeyCode::Char('1'));
    let s = screen(&mut a);
    let row = s.lines().find(|l| l.contains("○ home")).expect("its row");
    assert!(row.contains("network") && row.contains("hidden"), "{s}");
    // Shown again: it is back, last, and its key works.
    key(&mut a, KeyCode::Char('6'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('n'));
    typed(&mut a, "net:home");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('s'));
    assert!(
        save_box(&a).contains(&"What follows: home is back in the strip".to_string()),
        "{:?}",
        save_box(&a)
    );
    key(&mut a, KeyCode::Enter);
    assert!(top(&mut a, 158).contains(" F1 myserver   F2 silverblue 44.1   F3 home   F4 config "));
    key(&mut a, KeyCode::F(3));
    assert_eq!((a.in_config, a.slot().title()), (false, "home"));
    // A name that is no target is a problem, said on the field and on the tab.
    key(&mut a, KeyCode::F(4));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('n'));
    typed(&mut a, "srv:gone");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Esc);
    assert_eq!(
        problems(&a),
        ["config.toml: [targets] show: no target `srv:gone`"]
    );
    assert!(screen(&mut a).contains("! [targets] show: no target `srv:gone`"));
}

#[test]
fn the_agent_screen_says_whether_it_is_there_and_tests_one_turn() {
    let (mut a, _d) = config(&[]);
    key(&mut a, KeyCode::Char('2'));
    // Offline nothing is looked up or asked: the screen says what it knows.
    assert_eq!(a.config.agent.command, "claude");
    assert!(!a.config.agent.finding && a.config.agent.found.is_none());
    let s = screen(&mut a);
    assert!(s.contains("found     not looked up"), "{s}");
    assert!(
        s.contains("Other agents, API connections and locally deployed models are not"),
        "{s}"
    );
    // Not there: said, and there is nothing to test.
    a.on_event(found("claude", None), Instant::now());
    assert!(screen(&mut a).contains("found     ✗ not on PATH"));
    key(&mut a, KeyCode::Char('t'));
    assert_eq!(
        a.toast_for_test(),
        Some("`claude` isn't there: nothing to test")
    );
    assert!(!a.config.agent.testing);
    // There: where, and what it says it is.
    a.on_event(found("claude", Some("/usr/bin/claude")), Instant::now());
    let s = screen(&mut a);
    assert!(
        s.contains("found     ✓ /usr/bin/claude") && s.contains("version   2.1.0 (Claude Code)"),
        "{s}"
    );
    // `t`: one turn is asked for (nothing is sent here); its answer comes back.
    key(&mut a, KeyCode::Char('t'));
    assert!(a.config.agent.testing);
    assert!(screen(&mut a).contains("test      asking for one word…"));
    a.on_event(
        Event::Config(Box::new(Msg::Tested(
            "claude".into(),
            Tested::Answers("ready".into()),
        ))),
        Instant::now(),
    );
    // (What an earlier key said is gone by now.)
    a.win.toast = None;
    insta::assert_snapshot!("config_agent_158", screen(&mut a));
    assert!(screen(&mut a).contains("test      ✓ answers (ready)"));
    // Not logged in: said in plain words, with what to do.
    key(&mut a, KeyCode::Char('t'));
    a.on_event(
        Event::Config(Box::new(Msg::Tested("claude".into(), Tested::NotLoggedIn))),
        Instant::now(),
    );
    let s = screen(&mut a);
    assert!(
        s.contains("test      ✗ not logged in")
            && s.contains("run `claude` once in a terminal, then t again"),
        "{s}"
    );
    // Anything else: its own words.
    key(&mut a, KeyCode::Char('t'));
    a.on_event(
        Event::Config(Box::new(Msg::Tested(
            "claude".into(),
            Tested::Failed("exit 1: model not available".into()),
        ))),
        Instant::now(),
    );
    let s = screen(&mut a);
    assert!(
        s.contains("✗ it didn't answer") && s.contains("exit 1: model not available"),
        "{s}"
    );
    // The command changed in the form: what was known of the other one is gone, and an
    // answer about the other one that arrives late is nobody's.
    key(&mut a, KeyCode::Char('j'));
    set_field(&mut a, "claude-beta");
    assert_eq!(a.config.agent.command, "claude-beta");
    assert!(a.config.agent.found.is_none() && a.config.agent.test.is_none());
    a.on_event(found("claude", Some("/usr/bin/claude")), Instant::now());
    assert!(a.config.agent.found.is_none());
    a.on_event(found("claude-beta", None), Instant::now());
    assert!(screen(&mut a).contains("found     ✗ not on PATH"));
    // A path that isn't there is said as that.
    set_field(&mut a, "/opt/none/claude");
    a.on_event(found("/opt/none/claude", None), Instant::now());
    assert!(screen(&mut a).contains("found     ✗ no such file"));
}

// ---- part 3: systems in forms, checks, discovery, upkeep, following a save, the setup

const TWO_SERVERS: &str = "servers:\n  myserver:\n    ssh: admin@192.0.2.10\n    services: [app.service]\n    timers: [{unit: backup.timer, max_age: 26h}, {unit: x, max_age: 1d}]\n    disks: [{mount: /, warn: 85, crit: 95}]\n  other: {}\n";
const HOME: &str = "networks:\n  home:\n    router: {ssh: myrouter}\n    expect:\n      zones: {lan: [lan], wan: [wan, wan6]}\n      forwards: [{name: web, proto: tcp, port: 443, to: 192.0.2.20}]\n    devices:\n      - {name: nas, mac: \"02:00:5e:00:53:01\"}\n      - {hostname: phone, private_mac: true}\n";

fn probed(ssh: &str, p: Probe) -> Event {
    Event::Config(Box::new(Msg2::Probed(ssh.to_string(), p)))
}

fn candidates(hosts: &[(&str, Source)]) -> Event {
    Event::Config(Box::new(Msg2::Candidates(
        hosts
            .iter()
            .map(|(ssh, source)| Candidate {
                ssh: ssh.to_string(),
                source: *source,
            })
            .collect(),
    )))
}

/// What looking at a Debian server comes to, as `init`'s draft would say it.
fn server_draft(ssh: &str, name: &str) -> Probe {
    let (file, _) = sentry_server::config::parse(
        "servers:\n  x:\n    sudo: [docker ps]\n    services: [app.service, docker.service]\n    timers:\n      - {unit: backup.timer, max_age: 26h}\n    disks:\n      - {mount: /, warn: 85, crit: 95}\n      - {mount: /srv, warn: 85, crit: 95}\n    listeners: [\"*:22/sshd\", \"*:443/*\"]\n",
    )
    .unwrap();
    let mut s = file.servers["x"].clone();
    s.ssh = Some(ssh.to_string());
    Probe::Drafted(Drafted {
        file: FileId::Servers,
        kind: "server",
        name: name.to_string(),
        ssh: ssh.to_string(),
        entry: cfg::Value::of(&s).unwrap(),
        notes: vec![
            cfg::Note::whole("Review every part: it's a starting point, not a verdict."),
            cfg::Note::on(
                "services",
                "admin-written units, and the well-known ones that run",
            ),
            cfg::Note::on(
                "listeners",
                "everything listening now. Remove what you didn't expect: it becomes a finding.",
            ),
        ],
        what: "Debian GNU/Linux 12 (bookworm)".into(),
    })
}

/// What looking at an OpenWrt router comes to.
fn network_draft(ssh: &str) -> Probe {
    let (file, _) = sentry_network::config::parse(
        "networks:\n  x:\n    expect:\n      zones: {lan: [lan], wan: [wan, wan6]}\n      forwards: [{name: web, proto: tcp, port: 443, to: 192.0.2.20}]\n    devices:\n      - {mac: \"02:00:5e:00:53:01\"}\n",
    )
    .unwrap();
    let mut n = file.networks["x"].clone();
    n.router.ssh = Some(ssh.to_string());
    Probe::Drafted(Drafted {
        file: FileId::Networks,
        kind: "network",
        name: "home".to_string(),
        ssh: ssh.to_string(),
        entry: cfg::Value::of(&n).unwrap(),
        notes: vec![cfg::Note::on(
            "devices",
            "every lease now, unnamed: give the ones you know a name",
        )],
        what: "OpenWrt 25.12.5 · Example Router AX".into(),
    })
}

fn refused(ssh: &str) -> Probe {
    Probe::Failed(sentry_app::cfgarea::discover::refusal(
        ssh,
        "root@192.0.2.1: Permission denied (publickey,password).",
    ))
}

/// The value at `path` in the file as it is to be.
pub(crate) fn value(a: &App, path: &str) -> Option<String> {
    let segs = cfg::parse_path(path).unwrap();
    a.config
        .doc(FileId::of_path(path))?
        .tree()
        .at(&segs)
        .map(|v| v.to_string())
}

#[test]
fn a_servers_settings_are_a_form_and_every_edit_is_staged() {
    let (mut a, d) = with_files(
        three(),
        &[(FileId::Servers, TWO_SERVERS), (FileId::Networks, NETWORKS)],
    );
    let before = text(&d, FileId::Servers);
    key(&mut a, KeyCode::F(4));
    // The Overview: every system, a dot for what is wrong, and the add row.
    let s = screen(&mut a);
    let row = |name: &str| {
        s.lines()
            .find(|l| l.contains(&format!("● {name} ")) || l.contains(&format!("○ {name} ")))
            .unwrap_or_else(|| panic!("{name}: {s}"))
            .to_string()
    };
    assert!(row("myserver").contains("server") && row("myserver").contains("1 problem"));
    assert!(row("other").contains("○ other") && row("other").contains("not in the window"));
    assert!(row("home").contains("● home") && row("home").contains("network"));
    assert!(s.contains("+ add a system…"), "{s}");
    // Enter on a server opens its settings as a form: its sections, then its upkeep.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.screen, Screen::Servers);
    insta::assert_snapshot!("config_server_form_158", screen(&mut a));
    insta::assert_snapshot!("config_server_form_80", render_to_string(&mut a, 80, 30));
    let s = screen(&mut a);
    assert!(s.contains("! timer `x` should end in .timer"), "{s}");
    // ssh: a plain setting, staged at its own path.
    key(&mut a, KeyCode::Char('j'));
    set_field(&mut a, "admin@192.0.2.11");
    assert_eq!(pending(&a), ["x servers.myserver.ssh"]);
    // Services: a list, staged whole.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('n'));
    typed(&mut a, "docker.service");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Esc);
    assert_eq!(
        value(&a, "servers.myserver.services").unwrap(),
        "[\"app.service\", \"docker.service\"]"
    );
    // Timers: records. Enter opens the list, Enter on a row its own form.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    assert!(a.config.row.is_some());
    // The unit of the second timer: the one its lint complains about.
    key(&mut a, KeyCode::Enter);
    typed(&mut a, ".timer");
    insta::assert_snapshot!("config_record_row_editing_158", screen(&mut a));
    key(&mut a, KeyCode::Enter);
    assert!(problems(&a).is_empty(), "{:?}", problems(&a));
    // Its max age: a duration; what isn't one is refused in place, nothing staged for it.
    key(&mut a, KeyCode::Char('j'));
    set_field(&mut a, "soon");
    assert!(screen(&mut a).contains("not a duration"));
    key(&mut a, KeyCode::Esc);
    set_field(&mut a, "36h");
    assert_eq!(
        value(&a, "servers.myserver.timers").unwrap(),
        "[{unit: \"backup.timer\", max_age: \"26h\"}, {unit: \"x.timer\", max_age: \"36h\"}]"
    );
    // The whole list is one staged change, like every list.
    assert_eq!(
        pending(&a),
        [
            "x servers.myserver.ssh",
            "x servers.myserver.services",
            "x servers.myserver.timers"
        ]
    );
    // Esc: back to the list of timers. `n` adds one (as its type starts one) and opens it.
    key(&mut a, KeyCode::Esc);
    assert!(a.config.row.is_none());
    key(&mut a, KeyCode::Char('n'));
    assert!(a.config.row.is_some());
    assert!(
        value(&a, "servers.myserver.timers")
            .unwrap()
            .ends_with("{unit: \"\", max_age: \"26h\"}]")
    );
    set_field(&mut a, "sync.timer");
    key(&mut a, KeyCode::Esc);
    // `x` on a row takes it away.
    key(&mut a, KeyCode::Char('k'));
    key(&mut a, KeyCode::Char('k'));
    key(&mut a, KeyCode::Char('x'));
    assert_eq!(
        value(&a, "servers.myserver.timers").unwrap(),
        "[{unit: \"x.timer\", max_age: \"36h\"}, {unit: \"sync.timer\", max_age: \"26h\"}]"
    );
    key(&mut a, KeyCode::Esc);
    // A saved system keeps its name: its records are under it.
    key(&mut a, KeyCode::Home);
    set_field(&mut a, "renamed");
    let s = screen(&mut a);
    assert!(s.contains("is saved under that name"), "{s}");
    assert!(a.config.entries().iter().any(|(_, e)| e.name == "myserver"));
    assert_eq!(pending(&a).len(), 3);
    // Nothing was written by any of it.
    assert_eq!(text(&d, FileId::Servers), before);
    assert!(backups(&d, FileId::Servers).is_empty());
    // The save writes the file sentry would, and it reads back as what the forms said.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('s'));
    let lines = save_box(&a).join("\n");
    assert!(
        lines.contains("What follows: myserver reads its settings again"),
        "{lines}"
    );
    key(&mut a, KeyCode::Enter);
    let (file, warnings) =
        sentry_server::config::parse(&text(&d, FileId::Servers).unwrap()).unwrap();
    assert!(warnings.is_empty());
    let s = &file.servers["myserver"];
    assert_eq!(s.ssh.as_deref(), Some("admin@192.0.2.11"));
    assert_eq!(s.services, ["app.service", "docker.service"]);
    assert_eq!(s.timers.len(), 2);
    assert!(sentry_server::config::lint("myserver", s).is_empty());
    assert!(pending(&a).is_empty());
}

#[test]
fn a_networks_settings_are_a_form_and_its_recipients_make_a_key() {
    let (mut a, d) = with_files(
        three(),
        &[(FileId::Servers, SERVERS), (FileId::Networks, HOME)],
    );
    key(&mut a, KeyCode::F(4));
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::Enter);
    insta::assert_snapshot!("config_network_form_158", screen(&mut a));
    // Zones: each a name and its interfaces, typed `name = a b`, staged as lists.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('n'));
    typed(&mut a, "guest = guest iot");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Esc);
    assert_eq!(
        value(&a, "networks.home.expect.zones").unwrap(),
        "{guest: [\"guest\", \"iot\"], lan: [\"lan\"], wan: [\"wan\", \"wan6\"]}"
    );
    // Forwards: a row's port is typed as it is written, and one typed as it was is no change.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    set_field(&mut a, "443");
    assert_eq!(pending(&a), ["x networks.home.expect.zones"]);
    set_field(&mut a, "8000-8010");
    assert_eq!(
        value(&a, "networks.home.expect.forwards[0].port").unwrap(),
        "\"8000-8010\""
    );
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Esc);
    // Devices: name, MAC or hostname, leave alone, private MAC.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    for label in ["Name", "MAC", "Hostname", "Leave alone", "Private MAC"] {
        assert!(s.contains(label), "{label}: {s}");
    }
    set_field(&mut a, "my-phone");
    for _ in 0..3 {
        key(&mut a, KeyCode::Char('j'));
    }
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(
        value(&a, "networks.home.devices[1]").unwrap(),
        "{name: \"my-phone\", mac: null, hostname: \"phone\", leave_alone: true, private_mac: true}"
    );
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Esc);
    // The recipients: `K` makes a key. Offline nothing is written, and it says so.
    key(&mut a, KeyCode::Char('j'));
    assert!(screen(&mut a).contains(" K  make a key"));
    key(&mut a, KeyCode::Char('K'));
    let s = screen(&mut a);
    assert!(
        s.contains("make a key") && s.contains("~/sentry-home-backup.key"),
        "{s}"
    );
    assert!(
        a.config
            .prompt
            .as_ref()
            .unwrap()
            .help
            .contains("the secret one is in that file and nowhere else")
    );
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        a.toast_for_test(),
        Some("not done: offline: nothing is written")
    );
    assert_eq!(value(&a, "networks.home.backup.recipients").unwrap(), "[]");
    // With what makes the key handed in: the path as typed (`~` is home), and what comes
    // back, the public half, is staged as a recipient. The secret is nowhere here.
    let asked = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let seen = asked.clone();
    a.config.set_act(Box::new(move |path, arg| {
        seen.borrow_mut().push((path.to_string(), arg.to_string()));
        Ok("age1examplepublickey".to_string())
    }));
    key(&mut a, KeyCode::Char('K'));
    key(&mut a, KeyCode::Enter);
    let asked = asked.borrow().clone();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].0, "networks.home.backup.recipients");
    assert!(
        asked[0].1.ends_with("/sentry-home-backup.key") && !asked[0].1.starts_with('~'),
        "{asked:?}"
    );
    assert_eq!(
        value(&a, "networks.home.backup.recipients").unwrap(),
        "[\"age1examplepublickey\"]"
    );
    assert!(
        a.toast_for_test()
            .unwrap()
            .contains("keep a copy elsewhere")
    );
    // Sharing the WAN address: a toggle.
    key(&mut a, KeyCode::Char('G'));
    for _ in 0..20 {
        if a.config.field_for_test().as_deref() == Some("networks.home.claude.share_wan_address") {
            break;
        }
        key(&mut a, KeyCode::Char('k'));
    }
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(
        pending(&a),
        [
            "x networks.home.expect.zones",
            "x networks.home.expect.forwards",
            "x networks.home.devices",
            "x networks.home.backup.recipients",
            "x networks.home.claude.share_wan_address"
        ]
    );
    // Saved, it parses and lints clean.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('s'));
    key(&mut a, KeyCode::Enter);
    let (file, warnings) =
        sentry_network::config::parse(&text(&d, FileId::Networks).unwrap()).unwrap();
    assert!(warnings.is_empty());
    let n = &file.networks["home"];
    assert!(n.claude.share_wan_address);
    assert_eq!(n.expect.zones["guest"], ["guest", "iot"]);
    assert_eq!(n.expect.forwards[0].port.to_string(), "8000-8010");
    // (The recipient here is a stand-in, not a key, as its lint says; nothing else.)
    let lint = sentry_network::config::lint("home", n);
    assert_eq!(lint.len(), 1, "{lint:?}");
    assert_eq!(n.backup.recipients, ["age1examplepublickey"]);
}

#[test]
fn c_on_a_system_checks_its_connection_and_shows_what_came_back() {
    let (mut a, _d) = config(&[]);
    // On this machine there is no host: the files are checked, as before.
    key(&mut a, KeyCode::Char('c'));
    assert_eq!(
        a.toast_for_test(),
        Some("checked: nothing wrong in the files")
    );
    // On a server: its checks run (never offline: the lines are handed in).
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('c'));
    assert_eq!(
        a.toast_for_test(),
        Some("checking myserver: its connection, sudo, tools")
    );
    let s = screen(&mut a);
    assert!(s.contains("Connection") && s.contains("checking…"), "{s}");
    a.on_event(
        Event::Config(Box::new(ChecksDone {
            file: FileId::Servers,
            entry: "myserver".into(),
            lines: vec![
                CheckLine::ok("myserver (admin@192.0.2.10): Debian GNU/Linux 12 · 41 ms"),
                CheckLine::note("sudo asks for a password: monitoring runs without root"),
                CheckLine::ok("tools: systemctl journalctl findmnt ss"),
                CheckLine::bad("sudo: docker ps (sudoers doesn't allow it, or it isn't installed)"),
            ],
        })),
        Instant::now(),
    );
    let s = screen(&mut a);
    assert!(!s.contains("checking…"), "{s}");
    for line in [
        "✓ myserver (admin@192.0.2.10): Debian GNU/Linux 12 · 41 ms",
        "· sudo asks for a password: monitoring runs without root",
        "✓ tools: systemctl journalctl findmnt ss",
        "✗ sudo: docker ps",
    ] {
        assert!(s.contains(line), "{line}: {s}");
    }
    // They stay with the system: its form shows them too.
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(s.contains("✗ sudo: docker ps"), "{s}");
}

#[test]
fn adding_a_system_ticks_hosts_asks_once_and_stages_what_each_drafts() {
    let (mut a, d) = config(&[]);
    a.set_maker(Box::new(crate::tui::make));
    let before = text(&d, FileId::Servers);
    // "+ add a system…": the hosts this machine knows, none ticked. Nothing was read
    // before this (offline, a test hands them in), and what is configured isn't offered.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.page, Page::Add);
    a.on_event(
        candidates(&[
            ("newbox", Source::SshConfig),
            ("admin@192.0.2.10", Source::SshConfig),
            ("backup", Source::SshConfig),
            ("root@192.0.2.1", Source::Gateway),
        ]),
        Instant::now(),
    );
    insta::assert_snapshot!("config_add_candidates_158", screen(&mut a));
    insta::assert_snapshot!("config_add_candidates_80", render_to_string(&mut a, 80, 30));
    let s = screen(&mut a);
    assert!(!s.contains("admin@192.0.2.10"), "{s}");
    // Enter with nothing ticked reads nothing.
    assert!(a.config.hosts_asked().is_empty());
    // Tick two, add one by name; Enter: ONE box says what a look reads.
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('n'));
    typed(&mut a, "pi@192.0.2.30");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    insta::assert_snapshot!("config_probe_box_158", screen(&mut a));
    assert!(
        a.config.hosts_asked().is_empty(),
        "nothing before its Enter"
    );
    // Esc: nothing is looked at.
    key(&mut a, KeyCode::Esc);
    assert!(a.config.hosts_asked().is_empty());
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        a.config.hosts_asked(),
        ["newbox", "root@192.0.2.1", "pi@192.0.2.30"]
    );
    // Each row says where it stands; Enter waits for them.
    let s = screen(&mut a);
    assert_eq!(s.matches("reading…").count(), 3, "{s}");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.toast_for_test(), Some("still reading 3 hosts"));
    // What each came to: a server, a refusal, and one whose name is taken already.
    a.on_event(
        probed("newbox", server_draft("newbox", "newbox")),
        Instant::now(),
    );
    a.on_event(
        probed("root@192.0.2.1", refused("root@192.0.2.1")),
        Instant::now(),
    );
    a.on_event(
        probed("pi@192.0.2.30", server_draft("pi@192.0.2.30", "myserver")),
        Instant::now(),
    );
    a.win.toast = None;
    insta::assert_snapshot!("config_probe_states_158", screen(&mut a));
    // A draft is a staged ADD of its entry, yours (you ticked the host); a name that is
    // taken gets a number.
    assert_eq!(pending(&a), ["x servers.newbox", "x servers.myserver-2"]);
    assert!(
        a.config
            .pending
            .iter()
            .all(|p| p.change.by == cfg::By::You && p.change.from.is_none())
    );
    assert_eq!(a.config.drafts.len(), 2);
    assert_eq!(
        a.config.drafts[0].notes[1].path.as_deref(),
        Some("services")
    );
    // The refusal says why and what to do, and can be tried again: tick it, Enter, the
    // box, Enter.
    for _ in 0..6 {
        key(&mut a, KeyCode::Char('k'));
    }
    for _ in 0..3 {
        if a.config.add.as_ref().unwrap().list.selected().unwrap().key == "root@192.0.2.1" {
            break;
        }
        key(&mut a, KeyCode::Char('j'));
    }
    let s = screen(&mut a);
    assert!(s.contains("couldn't: it refused this machine's key"), "{s}");
    match &a.config.add.as_ref().unwrap().cands[2].state {
        sentry_app::cfgarea::discover::State::Failed(f) => {
            assert!(f.todo.contains("ssh-copy-id root@192.0.2.1"), "{}", f.todo)
        }
        other => panic!("{other:?}"),
    }
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Enter);
    assert!(
        ask_text(&a).contains("sentry logs in to 1 host with your ssh key"),
        "{}",
        ask_text(&a)
    );
    key(&mut a, KeyCode::Enter);
    a.on_event(
        probed("root@192.0.2.1", network_draft("root@192.0.2.1")),
        Instant::now(),
    );
    assert_eq!(
        pending(&a),
        [
            "x servers.newbox",
            "x servers.myserver-2",
            "x networks.home"
        ]
    );
    // Enter with nothing left to look at: the review of the first drafted system. What it
    // proposes to watch is ticked, each list under its heading with the draft's note.
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.page, Page::Review);
    insta::assert_snapshot!("config_review_158", screen(&mut a));
    insta::assert_snapshot!("config_review_80", render_to_string(&mut a, 80, 30));
    // Unticking stages the draft without it.
    assert_eq!(
        value(&a, "servers.newbox.services").unwrap(),
        "[\"app.service\", \"docker.service\"]"
    );
    review_cursor(&mut a, "docker.service");
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(
        value(&a, "servers.newbox.services").unwrap(),
        "[\"app.service\"]"
    );
    // (Ticked again, it is back: the draft is kept whole beside what is staged.)
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(
        value(&a, "servers.newbox.services").unwrap(),
        "[\"app.service\", \"docker.service\"]"
    );
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('G'));
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(
        value(&a, "servers.newbox.listeners").unwrap(),
        "[\"*:22/sshd\"]"
    );
    assert_eq!(pending(&a).len(), 3, "still one change per system");
    // Enter: its name and how it is reached. A name that is taken, or isn't one word, is
    // refused in place.
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Home);
    typed(&mut a, "my ");
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("a name is one word"));
    set_review_field(&mut a, "myserver");
    assert!(screen(&mut a).contains("there is a `myserver` already"));
    set_review_field(&mut a, "box");
    assert_eq!(
        pending(&a),
        ["x servers.myserver-2", "x networks.home", "x servers.box"]
    );
    key(&mut a, KeyCode::Char('j'));
    set_review_field(&mut a, "admin@newbox");
    assert_eq!(value(&a, "servers.box.ssh").unwrap(), "\"admin@newbox\"");
    assert_eq!(
        value(&a, "servers.box.services").unwrap(),
        "[\"app.service\"]"
    );
    // Enter accepts it and goes on to the next; the second is dropped here (x in the
    // Overview later), the network accepted as drafted.
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("myserver-2 · what sentry would watch"));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(s.contains("home · what sentry would watch"), "{s}");
    assert!(s.contains("every lease now, unnamed"), "{s}");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.page, Page::None);
    assert_eq!(
        a.toast_for_test(),
        Some("3 systems staged to be added · s saves, and they get their tabs")
    );
    // In the Overview each is a system already, marked as staged; x on one takes its add
    // back.
    let s = screen(&mut a);
    assert!(s.contains("box") && s.contains("myserver-2"), "{s}");
    for _ in 0..4 {
        key(&mut a, KeyCode::Char('k'));
    }
    let systems = a.config.systems();
    let at = systems
        .iter()
        .position(|(_, e)| e.name == "myserver-2")
        .unwrap();
    for _ in 0..at {
        key(&mut a, KeyCode::Char('j'));
    }
    assert!(screen(&mut a).contains("staged to be added: it gets its tab with the save"));
    key(&mut a, KeyCode::Char('x'));
    assert_eq!(pending(&a), ["x networks.home", "x servers.box"]);
    assert_eq!(a.config.drafts.len(), 2);
    // Nothing was written by any of it.
    assert_eq!(text(&d, FileId::Servers), before);
    assert_eq!(text(&d, FileId::Networks), None);
    // The save box says what is added and what follows.
    key(&mut a, KeyCode::Char('s'));
    a.win.toast = None;
    insta::assert_snapshot!("config_save_box_added_158", screen(&mut a));
    key(&mut a, KeyCode::Enter);
    // Both files parse and lint clean, with what the review left.
    let (file, w) = sentry_server::config::parse(&text(&d, FileId::Servers).unwrap()).unwrap();
    assert!(w.is_empty());
    assert_eq!(file.servers.keys().collect::<Vec<_>>(), ["box", "myserver"]);
    assert_eq!(file.servers["box"].listeners, ["*:22/sshd"]);
    assert!(sentry_server::config::lint("box", &file.servers["box"]).is_empty());
    let (nets, w) = sentry_network::config::parse(&text(&d, FileId::Networks).unwrap()).unwrap();
    assert!(w.is_empty());
    assert_eq!(
        nets.networks["home"].router.ssh.as_deref(),
        Some("root@192.0.2.1")
    );
    // At once: each has a tab, where it would be at the next start (this machine, the
    // servers, the networks, as the files have them), asleep until it has the window.
    assert_eq!(
        a.slots.iter().map(|s| s.title()).collect::<Vec<_>>(),
        ["silverblue 44.1", "box", "myserver", "home"]
    );
    assert!(
        top(&mut a, 158)
            .contains(" F1 silverblue 44.1   F2 box   F3 myserver   F4 home   F5 config ")
    );
    assert!(a.in_config && a.focus == 0);
    assert!(!a.started_at(1) && !a.started_at(3));
    key(&mut a, KeyCode::F(2));
    assert_eq!((a.in_config, a.slot().title()), (false, "box"));
    assert!(a.started_at(1) && !a.started_at(3));
    // Its own screens and keys, like any server.
    let s = screen(&mut a);
    assert!(s.lines().nth(1).unwrap().contains("5 Services"), "{s}");
    typed(&mut a, ":net ho");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.slot().title(), "home");
    // And the Config area knows them as saved systems now.
    key(&mut a, KeyCode::F(5));
    assert!(a.config.drafts.is_empty() && pending(&a).is_empty());
    let s = screen(&mut a);
    assert!(s.contains("● box") && s.contains("● home"), "{s}");
}

/// What the box that asks first says.
fn ask_text(a: &App) -> String {
    a.config
        .ask
        .as_ref()
        .map(|b| b.lines.join(" "))
        .unwrap_or_default()
}

/// The review's cursor on the row that says `text`.
fn review_cursor(a: &mut App, text: &str) {
    let l = &mut a.config.review.as_mut().expect("the review").list;
    l.cur = l
        .rows
        .iter()
        .position(|r| r.text == text)
        .unwrap_or_else(|| panic!("{text}"));
}

/// In the review's name form: the field under the cursor is set to `text`.
fn set_review_field(a: &mut App, text: &str) {
    key(a, KeyCode::Char(' '));
    a.on_event(
        Event::Key(ratatui::crossterm::event::KeyEvent::new(
            KeyCode::Char('u'),
            ratatui::crossterm::event::KeyModifiers::CONTROL,
        )),
        Instant::now(),
    );
    a.on_event(Event::Paste(text.to_string()), Instant::now());
    key(a, KeyCode::Enter);
}

#[test]
fn removing_an_idle_system_closes_its_tab_and_leaves_its_records() {
    let (mut a, d) = with_files(
        three(),
        &[(FileId::Servers, SERVERS), (FileId::Networks, NETWORKS)],
    );
    a.set_maker(Box::new(crate::tui::make));
    // The server has the window when the Config tab takes it.
    key(&mut a, KeyCode::F(2));
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::F(4));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('x'));
    assert_eq!(pending(&a), ["x servers.myserver"]);
    assert_eq!(
        a.toast_for_test(),
        Some("myserver: its removal is staged (its records stay on disk) · u takes it back")
    );
    // Its tab is there until the save.
    assert_eq!(a.slots.len(), 3);
    key(&mut a, KeyCode::Char('s'));
    let lines = save_box(&a).join("\n");
    assert!(lines.contains("myserver: removed"), "{lines}");
    assert!(
        lines.contains("What follows: myserver's tab closes"),
        "{lines}"
    );
    // Where its records are, and that nobody touches them.
    assert!(
        lines.contains(
            "myserver's records (its log, plans, baseline, runs) stay on disk, untouched:"
        ) && lines.contains("servers/myserver"),
        "{lines}"
    );
    key(&mut a, KeyCode::Enter);
    let (file, _) = sentry_server::config::parse(&text(&d, FileId::Servers).unwrap()).unwrap();
    assert!(file.servers.is_empty());
    // Its tab is gone; the slot behind the Config tab is one that is still there, and the
    // keys go round what is left.
    assert_eq!(
        a.slots.iter().map(|s| s.title()).collect::<Vec<_>>(),
        ["silverblue 44.1", "home"]
    );
    assert!(a.in_config);
    assert!(top(&mut a, 158).contains(" F1 silverblue 44.1   F2 home   F3 config "));
    key(&mut a, KeyCode::F(1));
    assert_eq!((a.in_config, a.slot().title()), (false, "silverblue 44.1"));
    // (Its own keymap and screen: nothing of the closed slot's is left in the window.)
    assert_eq!(a.slot().screen, ScreenId::Upgrade);
    key(&mut a, KeyCode::Char('5'));
    assert_eq!(a.slot().screen, ScreenId::Flat);
    key(&mut a, KeyCode::F(2));
    assert_eq!(a.slot().title(), "home");
    typed(&mut a, ":server mys");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.toast_for_test(), Some("unknown command :server mys"));
    // What the window knows of its targets is of the two that are left.
    assert_eq!(a.win.system.len(), 2);
    // Removed while it is in view (not from the Config tab's own save, but the file edited
    // outside and read again): the window goes to a target that is still there.
    let (mut a, d) = with_files(
        three(),
        &[(FileId::Servers, SERVERS), (FileId::Networks, NETWORKS)],
    );
    key(&mut a, KeyCode::F(3));
    key(&mut a, KeyCode::F(4));
    std::fs::remove_file(d.join(FileId::Networks.name())).unwrap();
    key(&mut a, KeyCode::Char('r'));
    assert_eq!(
        a.slots.iter().map(|s| s.title()).collect::<Vec<_>>(),
        ["silverblue 44.1", "myserver"]
    );
    key(&mut a, KeyCode::F(3));
    assert!(a.in_config, "F3 is the Config tab's now");
    key(&mut a, KeyCode::F(1));
    assert_eq!((a.focus, a.slot().title()), (0, "silverblue 44.1"));
}

#[test]
fn removing_a_system_at_work_is_refused_before_anything_is_written() {
    let (mut a, d) = with_files(
        two_with("cfgbusy", false),
        &[(FileId::Servers, "servers:\n  cfgbusy: {}\n")],
    );
    server_wf(
        &mut a,
        "cfgbusy",
        "careful",
        &(step("look", "auto", "true") + &step("change", "confirm", "true")),
    );
    key(&mut a, KeyCode::F(2));
    begin(&mut a, 1, "careful");
    key(&mut a, KeyCode::F(3));
    let before = text(&d, FileId::Servers);
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('x'));
    assert_eq!(pending(&a), ["x servers.cfgbusy"]);
    // The save box refuses, naming what is running there; Enter writes nothing.
    key(&mut a, KeyCode::Char('s'));
    let lines = save_box(&a).join("\n");
    assert!(
        lines.contains("! cfgbusy is to be removed, and it is at work now:"),
        "{lines}"
    );
    assert!(lines.contains("careful is in progress"), "{lines}");
    assert!(lines.contains("Nothing is saved."), "{lines}");
    let s = screen(&mut a);
    assert!(!s.contains(" Enter  save"), "{s}");
    key(&mut a, KeyCode::Enter);
    assert_eq!(text(&d, FileId::Servers), before);
    assert!(backups(&d, FileId::Servers).is_empty());
    assert_eq!(a.slots.len(), 2);
    assert_eq!(pending(&a), ["x servers.cfgbusy"]);
    assert_eq!(run_at(&a, 1), (Next::Run(0), true, false));
    // Taken back (u on it, among what is staged), the rest saves as ever.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('G'));
    key(&mut a, KeyCode::Char('u'));
    assert!(pending(&a).is_empty());
    // Once it has settled, the removal goes through.
    a.run_step_exit_at(1, 0);
    a.tick(Instant::now());
    key(&mut a, KeyCode::F(2));
    key(&mut a, KeyCode::Enter);
    a.run_step_exit_at(1, 0);
    a.tick(Instant::now());
    assert!(run_at(&a, 1).2, "the run is done");
    key(&mut a, KeyCode::F(3));
    key(&mut a, KeyCode::Home);
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('x'));
    key(&mut a, KeyCode::Char('s'));
    assert!(!save_box(&a).join("\n").contains("at work"));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.slots.len(), 1);
    assert_ne!(text(&d, FileId::Servers), before);
}

#[test]
fn upkeep_is_a_section_of_every_system_and_stages_each_kinds_own_cadence() {
    let (mut a, _d) = with_files(
        three(),
        &[(FileId::Servers, SERVERS), (FileId::Networks, NETWORKS)],
    );
    key(&mut a, KeyCode::F(4));
    // A server: its workflows, each with how often it is due.
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Enter);
    // (Upkeep is the last of the open groups: the folded ones come after it.)
    assert!(a.config.go_for_test("@upkeep:apt-maintenance"));
    insta::assert_snapshot!("config_upkeep_server_158", screen(&mut a));
    assert_eq!(
        a.config.field_for_test().as_deref(),
        Some("@upkeep:apt-maintenance")
    );
    // Enter edits "how often": a duration, staged in THAT server's own map.
    set_field(&mut a, "monthly");
    assert!(screen(&mut a).contains("not a duration"));
    assert!(pending(&a).is_empty());
    set_field(&mut a, "30d");
    assert_eq!(pending(&a), ["x servers.myserver.maintenance.cadence"]);
    assert_eq!(
        value(&a, "servers.myserver.maintenance.cadence").unwrap(),
        "{apt-maintenance: \"30d\"}"
    );
    key(&mut a, KeyCode::Char('j'));
    set_field(&mut a, "14d");
    assert_eq!(
        value(&a, "servers.myserver.maintenance.cadence").unwrap(),
        "{apt-maintenance: \"30d\", compose-update: \"14d\"}"
    );
    assert_eq!(pending(&a).len(), 1);
    // `off` (or nothing) takes it off the clock; u takes the staged change back.
    set_field(&mut a, "off");
    assert_eq!(
        value(&a, "servers.myserver.maintenance.cadence").unwrap(),
        "{apt-maintenance: \"30d\"}"
    );
    key(&mut a, KeyCode::Char('u'));
    assert!(pending(&a).is_empty());
    // `o`: its own copy. One box says what is copied where, and that it then no longer
    // follows the shared set; nothing of it is in the save box.
    key(&mut a, KeyCode::Char('o'));
    assert!(screen(&mut a).contains("Its own copy of the workflows"));
    let s = ask_text(&a);
    assert!(
        s.contains("Give myserver its own copy of the workflows? 2 files are copied:"),
        "{s}"
    );
    assert!(
        s.contains("apt-maintenance.toml  compose-update.toml"),
        "{s}"
    );
    assert!(
        s.contains("server-workflows") && s.contains("servers/myserver/workflows"),
        "{s}"
    );
    assert!(
        s.contains("its folder replaces the shared set whole"),
        "{s}"
    );
    assert!(s.contains("not in the save box"), "{s}");
    // Esc: nothing. Enter (offline): nothing is copied, and it says so.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('o'));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.toast_for_test(), Some("offline: nothing is copied"));
    assert!(pending(&a).is_empty());
    assert!(!sentry_server::workflow::server_dir("myserver").exists());
    // A tracked item's workflow is a pick among THAT server's workflows.
    for _ in 0..12 {
        if a.config.field_for_test().as_deref() == Some("servers.myserver.maintenance.items") {
            break;
        }
        key(&mut a, KeyCode::Char('k'));
    }
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('n'));
    for _ in 0..3 {
        key(&mut a, KeyCode::Char('j'));
    }
    assert_eq!(
        a.config.field_for_test().as_deref(),
        Some("servers.myserver.maintenance.items[0].workflow")
    );
    assert!(screen(&mut a).contains("one of: (none), apt-maintenance, compose-update"));
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(
        value(&a, "servers.myserver.maintenance.items[0].workflow").unwrap(),
        "\"apt-maintenance\""
    );
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(
        value(&a, "servers.myserver.maintenance.items[0].workflow").unwrap(),
        "null"
    );
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('u'));
    assert!(pending(&a).is_empty());
    // A network: its own list.
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('G'));
    for _ in 0..16 {
        if a.config.field_for_test().as_deref() == Some("@upkeep:config-backup") {
            break;
        }
        key(&mut a, KeyCode::Char('k'));
    }
    set_field(&mut a, "7d");
    assert_eq!(pending(&a), ["x networks.home.maintenance.cadence"]);
    assert_eq!(
        value(&a, "networks.home.maintenance.cadence").unwrap(),
        "[{workflow: \"config-backup\", every: \"7d\"}]"
    );
    // This machine: its jobs' cadences are `[jobs]`; its workflows have none, and `o`
    // there opens the one file (there is no set per system).
    key(&mut a, KeyCode::Char('3'));
    assert!(a.config.go_for_test("@upkeep:cleanup-cache"));
    a.win.toast = None;
    insta::assert_snapshot!("config_upkeep_machine_158", screen(&mut a));
    for _ in 0..12 {
        if a.config.field_for_test().as_deref() == Some("@upkeep:audit") {
            break;
        }
        key(&mut a, KeyCode::Char('k'));
    }
    set_field(&mut a, "14d");
    assert_eq!(
        pending(&a),
        ["x networks.home.maintenance.cadence", "x jobs"]
    );
    assert_eq!(
        value(&a, "jobs").unwrap(),
        "{audit: {suggested_every: \"14d\"}}"
    );
    for _ in 0..12 {
        if a.config.field_for_test().as_deref() == Some("@upkeep:quick-update") {
            break;
        }
        key(&mut a, KeyCode::Char('k'));
    }
    set_field(&mut a, "7d");
    assert!(screen(&mut a).contains("`quick-update` has no cadence to set here"));
    key(&mut a, KeyCode::Char('o'));
    assert!(a.config.ask.is_none());
    let (cmd, _) = a.take_suspend().expect("the editor");
    assert!(
        cmd.quoted_argv().ends_with("workflows/quick-update.toml"),
        "{}",
        cmd.quoted_argv()
    );
}

#[test]
fn which_targets_show_is_ticked_in_a_list_and_a_changed_entry_is_followed() {
    let (mut a, _d) = with_files(
        three(),
        &[(FileId::Servers, SERVERS), (FileId::Networks, NETWORKS)],
    );
    a.set_maker(Box::new(crate::tui::make));
    key(&mut a, KeyCode::F(4));
    // Window › Shown: Space lists every target, the ones the strip shows ticked.
    key(&mut a, KeyCode::Char('6'));
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(a.config.page, Page::Shown);
    insta::assert_snapshot!("config_targets_shown_158", screen(&mut a));
    // The network unticked: staged as what is left, in the order it had. Nothing moves
    // before the save.
    key(&mut a, KeyCode::Char('G'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.page, Page::None);
    assert_eq!(pending(&a), ["x targets.show"]);
    assert_eq!(
        value(&a, "targets.show").unwrap(),
        "[\"local\", \"srv:myserver\"]"
    );
    assert_eq!(a.slots.iter().filter(|s| s.hidden).count(), 0);
    // None ticked is refused; all ticked again is no setting at all.
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('a'));
    key(&mut a, KeyCode::Char('a'));
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        a.toast_for_test(),
        Some("the strip shows at least one target")
    );
    key(&mut a, KeyCode::Char('a'));
    key(&mut a, KeyCode::Enter);
    assert!(pending(&a).is_empty());
    // A server added by a save is asleep; an entry of it changed by a later save is
    // followed at once: it is built again from the file as it is now, in its place, and
    // still starts only when it first has the window.
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char('G'));
    key(&mut a, KeyCode::Enter);
    a.on_event(candidates(&[("newbox", Source::SshConfig)]), Instant::now());
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    a.on_event(
        probed("newbox", server_draft("newbox", "newbox")),
        Instant::now(),
    );
    for _ in 0..3 {
        key(&mut a, KeyCode::Enter);
    }
    key(&mut a, KeyCode::Char('s'));
    key(&mut a, KeyCode::Enter);
    let titles =
        |a: &App| -> Vec<String> { a.slots.iter().map(|s| s.title().to_string()).collect() };
    assert_eq!(
        titles(&a),
        ["silverblue 44.1", "myserver", "newbox", "home"]
    );
    assert!(!a.started_at(2));
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('j'));
    set_field(&mut a, "admin@newbox");
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('s'));
    assert!(
        save_box(&a)
            .join("\n")
            .contains("What follows: newbox reads its settings again")
    );
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        titles(&a),
        ["silverblue 44.1", "myserver", "newbox", "home"]
    );
    assert!(!a.started_at(2) && a.in_config && a.focus == 0);
    key(&mut a, KeyCode::F(3));
    assert_eq!((a.in_config, a.slot().title()), (false, "newbox"));
    assert!(a.started_at(2));
}

/// A window on a first run: no config file, the setup flow in view.
fn first_run() -> (App, PathBuf) {
    let (mut a, d) = with_files(one(), &[]);
    a.set_maker(Box::new(crate::tui::make));
    a.setup_at_start();
    a.start(Instant::now());
    (a, d)
}

#[test]
fn a_first_run_opens_on_the_setup_and_walks_the_same_screens() {
    let (mut a, d) = first_run();
    assert!(a.in_config);
    assert_eq!(a.config.guide, Some(Step::Agent));
    // Step 1: the Agent screen under the rail. Nothing is looked up offline: Enter goes on
    // without one, and says what that means.
    insta::assert_snapshot!("setup_agent_158", screen(&mut a));
    insta::assert_snapshot!("setup_agent_80", render_to_string(&mut a, 80, 30));
    // Found: Enter tests it (the `t` action), Enter again goes on.
    a.on_event(found("claude", Some("/usr/bin/claude")), Instant::now());
    key(&mut a, KeyCode::Enter);
    assert!(a.config.agent.testing);
    assert_eq!(a.config.guide, Some(Step::Agent));
    a.on_event(
        Event::Config(Box::new(Msg::Tested(
            "claude".into(),
            Tested::Answers("ok".into()),
        ))),
        Instant::now(),
    );
    assert!(screen(&mut a).contains("it answers · Enter goes on"));
    // The screens aren't walked by their own keys here: the rail is the way round.
    key(&mut a, KeyCode::Char('6'));
    assert_eq!(a.config.screen, Screen::Agent);
    assert_eq!(
        a.toast_for_test(),
        Some("the setup walks the screens in order · Esc leaves it")
    );
    // (Nothing said by a key is in the pictures below: a toast goes by the clock.)
    a.win.toast = None;
    key(&mut a, KeyCode::Enter);
    // Step 2: this machine. The two toggles, what sentry does here; nothing required.
    assert_eq!(a.config.guide, Some(Step::Machine));
    insta::assert_snapshot!("setup_machine_158", screen(&mut a));
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(pending(&a), ["x review.at_start"]);
    // b goes back a step, Enter on again.
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(a.config.guide, Some(Step::Agent));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    // Step 3: systems. The hosts, none ticked; with none it is just this machine.
    assert_eq!(a.config.guide, Some(Step::Systems));
    a.on_event(
        candidates(&[
            ("newbox", Source::SshConfig),
            ("root@192.0.2.1", Source::Gateway),
        ]),
        Instant::now(),
    );
    insta::assert_snapshot!("setup_systems_158", screen(&mut a));
    insta::assert_snapshot!("setup_systems_80", render_to_string(&mut a, 80, 30));
    key(&mut a, KeyCode::Char('a'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    a.on_event(
        probed("newbox", server_draft("newbox", "newbox")),
        Instant::now(),
    );
    a.on_event(
        probed("root@192.0.2.1", network_draft("root@192.0.2.1")),
        Instant::now(),
    );
    key(&mut a, KeyCode::Enter);
    // Step 4: the review of each, as from "+ add a system…".
    assert_eq!(a.config.guide, Some(Step::Review));
    insta::assert_snapshot!("setup_review_158", screen(&mut a));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    // Step 5: routine upkeep, with defaults ticked; Enter accepts them all.
    assert_eq!(a.config.guide, Some(Step::Upkeep));
    insta::assert_snapshot!("setup_upkeep_158", screen(&mut a));
    insta::assert_snapshot!("setup_upkeep_80", render_to_string(&mut a, 80, 30));
    // (One unticked: it isn't scheduled.)
    let l = a.config.routine.as_ref().unwrap();
    let at = l
        .rows
        .iter()
        .position(|r| r.text.starts_with("package-update"))
        .unwrap();
    a.config.routine.as_mut().unwrap().cur = at;
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        value(&a, "servers.newbox.maintenance.cadence").unwrap(),
        "{apt-maintenance: \"30d\"}"
    );
    assert_eq!(
        value(&a, "networks.home.maintenance.cadence").unwrap(),
        "[{workflow: \"config-backup\", every: \"30d\"}]"
    );
    // (Still one change per system: its cadence is in the entry it adds.)
    assert_eq!(
        pending(&a),
        ["x review.at_start", "x servers.newbox", "x networks.home"]
    );
    // Step 6: the save box. Nothing was written before it.
    assert_eq!(a.config.guide, Some(Step::Save));
    for f in cfg::FILES {
        assert_eq!(text(&d, f), None, "{}", f.name());
    }
    insta::assert_snapshot!("setup_save_158", screen(&mut a));
    key(&mut a, KeyCode::Enter);
    // Written: all three, each parsing and linting clean.
    let app = text(&d, FileId::App).unwrap();
    assert!(app.contains("at_start = false"), "{app}");
    let (file, _) = sentry_server::config::parse(&text(&d, FileId::Servers).unwrap()).unwrap();
    assert!(sentry_server::config::lint("newbox", &file.servers["newbox"]).is_empty());
    assert_eq!(file.servers["newbox"].maintenance.cadence.len(), 1);
    let (nets, _) = sentry_network::config::parse(&text(&d, FileId::Networks).unwrap()).unwrap();
    assert!(sentry_network::config::lint("home", &nets.networks["home"]).is_empty());
    // The setup is over; the new targets have their tabs, and the first system added has
    // the window.
    assert_eq!(a.config.guide, None);
    assert_eq!(
        a.slots.iter().map(|s| s.title()).collect::<Vec<_>>(),
        ["silverblue 44.1", "newbox", "home"]
    );
    assert_eq!((a.in_config, a.slot().title()), (false, "newbox"));
    assert!(a.started_at(1) && !a.started_at(2));
    // And it isn't a first run any more.
    let files = crate::cfgcmd::read_in(&d);
    assert!(
        !files.first_run() && files.problems.is_empty(),
        "{:?}",
        files.problems
    );
}

#[test]
fn the_setup_with_no_system_is_just_this_machine_and_still_writes_config_toml() {
    let (mut a, d) = first_run();
    // Enter through every step with nothing chosen.
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.guide, Some(Step::Systems));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.guide, Some(Step::Review));
    let s = screen(&mut a);
    assert!(s.contains("no system was added"), "{s}");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.guide, Some(Step::Upkeep));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.guide, Some(Step::Save));
    // Nothing is staged, and the save box still has `config.toml` in it: what ends a
    // first run.
    assert!(pending(&a).is_empty());
    let lines = save_box(&a).join("\n");
    assert!(
        lines.contains("config.toml") && lines.contains("every setting at its default"),
        "{lines}"
    );
    assert!(lines.contains("(a new file)"), "{lines}");
    assert_eq!(text(&d, FileId::App), None);
    key(&mut a, KeyCode::Enter);
    let app = text(&d, FileId::App).unwrap();
    assert!(Config::parse(&app).is_ok());
    assert_eq!(Config::parse(&app).unwrap().0, Config::default());
    assert_eq!(text(&d, FileId::Servers), None);
    assert_eq!((a.config.guide, a.in_config), (None, false));
    assert_eq!(a.slot().title(), "silverblue 44.1");
}

#[test]
fn esc_leaves_the_setup_with_what_is_staged_and_setup_picks_it_up_again() {
    let (mut a, d) = first_run();
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.guide, Some(Step::Systems));
    // Esc asks once, saying what leaving means.
    key(&mut a, KeyCode::Esc);
    assert!(screen(&mut a).contains("Leave the setup"));
    let s = ask_text(&a);
    assert!(s.contains("Leave the setup at \"Systems\"?"), "{s}");
    assert!(s.contains("1 change staged stays staged"), "{s}");
    assert!(
        s.contains(":setup picks the setup up again at this step."),
        "{s}"
    );
    assert!(s.contains("sentry writes config.toml now"), "{s}");
    // Esc there: still in it, nothing written.
    key(&mut a, KeyCode::Esc);
    assert_eq!(a.config.guide, Some(Step::Systems));
    assert_eq!(text(&d, FileId::App), None);
    // Enter: left. What was staged stays staged (and is not in the file written, which is
    // the defaults: nothing is saved without the save box).
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.guide, None);
    assert_eq!(pending(&a), ["x review.at_start"]);
    let app = text(&d, FileId::App).unwrap();
    assert_eq!(Config::parse(&app).unwrap().0, Config::default());
    assert!(a.slots[0].auto_review.at_start);
    assert_eq!(
        a.toast_for_test(),
        Some("setup left: config.toml written · :setup picks it up again")
    );
    assert!(!crate::cfgcmd::read_in(&d).first_run());
    // The area is as ever, its screens by their keys.
    assert!(!screen(&mut a).contains(" Setup  "));
    key(&mut a, KeyCode::Char('6'));
    assert_eq!(a.config.screen, Screen::Window);
    // `:setup` picks it up at the step it was left.
    typed(&mut a, ":setup");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.guide, Some(Step::Systems));
    assert_eq!(a.config.page, Page::Add);
    // Left again, nothing more is written (the file is there), and it says so.
    key(&mut a, KeyCode::Esc);
    let s = ask_text(&a);
    assert!(
        s.contains("Leave the setup") && !s.contains("sentry writes config.toml now"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        a.toast_for_test(),
        Some("setup left · :setup picks it up again")
    );
    // What was staged is saved by the save box, as ever.
    key(&mut a, KeyCode::Char('s'));
    key(&mut a, KeyCode::Enter);
    assert!(text(&d, FileId::App).unwrap().contains("at_start = false"));
}

#[test]
fn an_existing_setup_never_gets_the_setup_by_itself() {
    // Any one of the three files there: not a first run.
    for f in cfg::FILES {
        let d = dir(&[(f, "")]);
        assert!(!crate::cfgcmd::read_in(&d).first_run(), "{}", f.name());
    }
    let d = dir(&[]);
    assert!(crate::cfgcmd::read_in(&d).first_run());
    // The window of an existing setup opens as it always did; `:setup` starts the flow on
    // demand, at its first step, and its Systems step offers only what isn't configured.
    let (mut a, _d) = config(&[(FileId::App, "")]);
    assert_eq!(a.config.guide, None);
    assert!(!screen(&mut a).contains(" Setup  "));
    typed(&mut a, ":setup");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.guide, Some(Step::Agent));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    a.on_event(
        candidates(&[
            ("admin@192.0.2.10", Source::SshConfig),
            ("newbox", Source::SshConfig),
        ]),
        Instant::now(),
    );
    let s = screen(&mut a);
    assert!(
        s.contains("newbox") && !s.contains("admin@192.0.2.10"),
        "{s}"
    );
    // With nothing chosen and nothing staged, its last step has nothing to write: done.
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.guide, None);
    assert_eq!(
        a.toast_for_test(),
        Some("setup done: there was nothing to save")
    );
}

/// Against a DISPOSABLE host only (`scripts/live-container.sh`, `scripts/live-router.sh`:
/// they set `SENTRY_SETUP_HOST` to the container's ssh alias and `SENTRY_SETUP_KIND` to what
/// it is, beside fresh scratch XDG dirs and a throwaway `SENTRY_SSH_CONFIG`). A first run:
/// the window opens on the setup, the container is found among this machine's ssh hosts,
/// ticked, looked at for real (the binary's own prober: reads only), reviewed as drafted,
/// its routine upkeep accepted, and saved. The files then parse and lint clean, `sentry
/// config check` has nothing to say, the system has its tab and the window, and its first
/// read comes in. No agent is asked anything.
#[test]
#[ignore]
fn live_setup() {
    sentry_core::paths::use_real_dirs();
    let (Ok(host), Ok(kind)) = (
        std::env::var("SENTRY_SETUP_HOST"),
        std::env::var("SENTRY_SETUP_KIND"),
    ) else {
        return;
    };
    // Only ever in scratch dirs, against the script's own ssh config.
    for var in [
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "SENTRY_SSH_CONFIG",
    ] {
        assert!(std::env::var(var).is_ok(), "{var} must be set (scratch)");
    }
    let dir = sentry_core::paths::config_dir();
    for f in cfg::FILES {
        assert!(!dir.join(f.name()).exists(), "{} is there", f.name());
    }
    // As `sentry` opens: whatever it was called for, a first run is the setup.
    let opening = match crate::tui::opening(crate::tui::Open::Server(None)) {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    };
    assert!(opening.first);
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = opening.app(tx);
    a.win.theme = sentry_core::tui::theme::Theme::truecolor();
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
    assert!(a.in_config);
    assert_eq!(a.config.guide, Some(Step::Agent));
    // This machine hasn't started: nothing of it runs behind the setup.
    assert!(!a.started_at(0));
    // Step 1: on without an agent (no turn is ever sent from here).
    key(&mut a, KeyCode::Char('n'));
    assert_eq!(a.config.guide, Some(Step::Machine));
    key(&mut a, KeyCode::Enter);
    // Step 3: this machine's own ssh hosts (the script's config) and its gateway.
    assert_eq!(a.config.guide, Some(Step::Systems));
    pump(&mut a, 15.0, &|a| {
        a.config.add.as_ref().is_some_and(|x| !x.looking)
    });
    let add = a.config.add.as_mut().expect("the hosts");
    // (What was found isn't printed: this machine's own gateway is among it.)
    assert!(
        add.cands
            .iter()
            .any(|c| c.ssh == host && c.source == Source::SshConfig),
        "{host} isn't among the hosts found"
    );
    assert!(
        a.config.hosts_asked().is_empty(),
        "nothing is looked at yet"
    );
    // Tick the container (and only it), Enter, the box, Enter.
    let add = a.config.add.as_mut().unwrap();
    add.list.cur = add.list.rows.iter().position(|r| r.key == host).unwrap();
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Enter);
    let said = ask_text(&a);
    assert!(
        said.contains("sentry logs in to 1 host with your ssh key") && said.contains(&host),
        "{said}"
    );
    assert!(said.contains("Nothing is changed on them."), "{said}");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.hosts_asked(), std::slice::from_ref(&host));
    use sentry_app::cfgarea::discover::State;
    let settled = |a: &App| {
        a.config.add.as_ref().is_some_and(|x| {
            x.cands
                .iter()
                .any(|c| c.ssh == host && !matches!(c.state, State::Idle | State::Reading))
        })
    };
    pump(&mut a, 60.0, &settled);
    println!("{}", screen(&mut a));
    let state = a
        .config
        .add
        .as_ref()
        .unwrap()
        .cands
        .iter()
        .find(|c| c.ssh == host)
        .unwrap()
        .state
        .clone();
    let name = match state {
        State::Drafted { kind: k, name } => {
            assert_eq!(k, kind, "what it was drafted as");
            name
        }
        other => panic!("{host}: {other:?}"),
    };
    // A staged add, yours, with the draft's notes kept for the review.
    assert_eq!(a.config.pending.len(), 1);
    assert!(a.config.pending[0].change.from.is_none());
    assert_eq!(a.config.pending[0].change.by, cfg::By::You);
    assert_eq!(a.config.drafts.len(), 1);
    key(&mut a, KeyCode::Enter);
    // Step 4: the review, accepted as drafted.
    assert_eq!(a.config.guide, Some(Step::Review));
    println!("{}", screen(&mut a));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    // Step 5: its routine upkeep, accepted.
    assert_eq!(a.config.guide, Some(Step::Upkeep));
    println!("{}", screen(&mut a));
    key(&mut a, KeyCode::Enter);
    // Step 6: the save box. Nothing was written before it.
    assert_eq!(a.config.guide, Some(Step::Save));
    for f in cfg::FILES {
        assert!(!dir.join(f.name()).exists(), "{} before the save", f.name());
    }
    println!("{}", save_box(&a).join("\n"));
    key(&mut a, KeyCode::Enter);
    // Written: config.toml and the system's own file, which parse and lint clean, and
    // `sentry config check` has nothing to say of them.
    assert!(dir.join(FileId::App.name()).exists());
    let files = crate::cfgcmd::read();
    assert!(!files.first_run());
    assert!(files.problems.is_empty(), "{:?}", files.problems);
    let target = match kind.as_str() {
        "server" => {
            let file = files.servers.as_ref().expect("server_config.yaml");
            let s = file.servers.get(&name).expect("its entry");
            assert_eq!(s.ssh_target(&name), host);
            assert!(sentry_server::config::lint(&name, s).is_empty());
            // (Its routine upkeep was accepted: on a cadence.)
            assert!(s.maintenance.cadence.contains_key("apt-maintenance"));
            assert!(files.networks.is_none());
            sentry_server::tui::id_of(&name)
        }
        _ => {
            let file = files.networks.as_ref().expect("network_config.yaml");
            let n = file.networks.get(&name).expect("its entry");
            assert_eq!(n.ssh_target(&name), host);
            assert!(sentry_network::config::lint(&name, n).is_empty());
            assert!(
                n.maintenance
                    .cadence
                    .iter()
                    .any(|c| c.workflow == "config-backup")
            );
            assert!(!n.expect.zones.is_empty(), "its zones were drafted");
            assert!(files.servers.is_none());
            sentry_network::tui::id_of(&name)
        }
    };
    // The setup is over; the system has its tab and the window, and its first read works.
    assert_eq!(a.config.guide, None);
    let i = a.place(&target).expect("its tab");
    assert_eq!((a.in_config, a.focus), (false, i));
    assert!(a.started_at(i) && !a.started_at(0));
    pump(&mut a, 30.0, &|_| false);
    let s = screen(&mut a);
    println!("{s}");
    assert!(s.contains("● connected"), "its first read didn't come in");
    // Its checks, from the Config area: the same reads `check` does.
    key(&mut a, KeyCode::F(3));
    assert!(a.in_config);
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('c'));
    pump(&mut a, 30.0, &|a| {
        a.config.checks.first().is_some_and(|c| !c.running)
    });
    let s = screen(&mut a);
    println!("{s}");
    let checks = &a.config.checks[0];
    assert!(!checks.lines.is_empty());
    assert!(
        checks
            .lines
            .iter()
            .all(|l| l.mark != sentry_app::cfgarea::kind::Mark::Bad),
        "{:?}",
        checks.lines
    );
    sentry_core::tui::Ui::shutdown(&mut a);
}

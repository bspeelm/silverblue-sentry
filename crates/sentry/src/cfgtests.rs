//! The window's Config area: its tab in the strip, its own colour, its screens, staging and
//! the save box, and what follows a save. Nothing is spawned (`win.offline`); each test has
//! its own directory of config files (`ConfigArea::set_dir`), so no test sees another's
//! `config.toml`, and none the real one.

use std::path::{Path, PathBuf};
use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use sentry_app::app::render_to_string;
use sentry_app::cfgarea::Screen;
use sentry_app::cfgarea::agent::Msg;
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
fn with_files(mut a: App, files: &[(FileId, &str)]) -> (App, PathBuf) {
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

fn text(d: &Path, f: FileId) -> Option<String> {
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
fn pending(a: &App) -> Vec<String> {
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

fn problems(a: &App) -> Vec<String> {
    a.config.problems.iter().map(|p| p.line()).collect()
}

/// The selected field of the form in view is set to `text` (Enter, the line replaced, Enter).
fn set_field(a: &mut App, text: &str) {
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
    key(&mut a, KeyCode::Char('G'));
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

#[test]
fn servers_and_networks_are_listed_with_their_settings_to_read() {
    let (mut a, d) = with_files(
        three(),
        &[
            (
                FileId::Servers,
                "servers:\n  myserver:\n    ssh: admin@192.0.2.10\n    services: [app.service]\n    timers: [{unit: x, max_age: 1d}]\n  other: {}\n",
            ),
            (FileId::Networks, NETWORKS),
        ],
    );
    key(&mut a, KeyCode::F(4));
    // The Overview: every system, a dot for what is wrong, and the add row for later.
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
    let tabs = s.lines().nth(1).unwrap().to_string();
    assert!(tabs.contains("4 Servers 1"), "{tabs}");
    // Enter on a server opens Servers on it.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.screen, Screen::Servers);
    let s = screen(&mut a);
    assert!(s.contains("! timer `x` should end in .timer"), "{s}");
    assert!(
        s.contains("Enter shows its settings · e opens server_config.yaml in $EDITOR"),
        "{s}"
    );
    // Enter: its essential settings, to read, and where its form will come from.
    key(&mut a, KeyCode::Enter);
    insta::assert_snapshot!("config_server_settings_158", screen(&mut a));
    let s = screen(&mut a);
    assert!(
        s.contains("Forms for servers and networks come with the next part."),
        "{s}"
    );
    // Nothing here stages or writes anything.
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('x'));
    assert!(pending(&a).is_empty());
    assert!(backups(&d, FileId::Servers).is_empty());
    // The add row says where adding comes from for now.
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char('G'));
    key(&mut a, KeyCode::Enter);
    assert!(
        a.toast_for_test()
            .unwrap()
            .starts_with("adding a system here comes with the next part")
    );
    // A network: the same, and no device is named anywhere on it.
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(
        s.contains("home · network") && s.contains("myrouter"),
        "{s}"
    );
}

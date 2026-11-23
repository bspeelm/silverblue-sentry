//! Test support: every way a Maintenance row is resolved, driven the same way on every kind
//! of target. A row that is resolved leaves the list at once, with no restart; one that is
//! taken back returns at once.
//!
//! [`Way`] is the list. Each target gives a [`Rig`] (its app with the rows the ways need,
//! and the few things only it can say), and [`run`] does the rest through the app as a user
//! would: keys on Maintenance, a session's answers, a run's exit. A new way is a new
//! variant: [`Way::expect`] and [`run`] match on it without a catch-all, and every target's
//! matrix test goes through [`Way::ALL`], so none can be left out. A new target writes a
//! `Rig` and gets them all.

use std::time::Instant;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::{App, Event};
use sentry_core::maint::Level;
use sentry_core::maint::tasks::Task;
use sentry_core::tui::ScreenId;

/// A task done by hand, every 30 days, never done: due.
pub const TASK: &str = "rows-task";
/// A task done by hand, once.
pub const ONCE: &str = "rows-once";
/// The rig's workflow (one step that runs by itself), and the task its good run resolves.
pub const WF: &str = "rows-harmless";
pub const RUN: &str = "rows-run";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Way {
    /// A finding's fix session settles, and the audit after it no longer has the finding.
    FixGone,
    /// The same, but the audit still reports it: the row stays, and nothing says done.
    FixStill,
    /// `x` on a finding (the box, Enter): expected.
    Expected,
    /// Taken back in Records › Later.
    ExpectedBack,
    /// `B`: every finding of its kind.
    Pattern,
    /// A plan step that stops sentry watching what the finding is about.
    Unwatch,
    /// Watched again, from Records › Later.
    UnwatchBack,
    /// `d` on a task.
    TaskDone,
    /// `m` on a task done by hand: its steps, then "mark done".
    TaskSteps,
    /// `x` on a task: removed.
    TaskRemove,
    /// `z`: later.
    Later,
    /// Taken back in Records › Later.
    LaterBack,
    /// A workflow's run ends well: the task it does leaves.
    Run,
    /// The same for a task a review wrote for an item (`item = …`): a run of the workflow
    /// as a whole (it names no item) does it too.
    RunForItem,
    /// A series of ticked rows ends.
    Series,
    /// A review's changes, applied.
    Review,
    /// A server: `t` tracks what discovery found.
    Track,
    /// A server: an item of its own is untracked.
    Untrack,
    /// A server: `x` ignores what discovery found.
    Ignore,
    /// `tasks.toml` changed on disk: a task taken out by hand.
    DiskTasks,
    /// `later.toml` changed on disk.
    DiskLater,
    /// `baseline.toml` changed on disk.
    DiskBaseline,
    /// A plan's file removed from `plans/`.
    DiskPlan,
    /// The target's own config changed on disk: what the finding is about isn't watched.
    DiskConfig,
}

/// (The row was listed before, it is listed after), or why this kind of target hasn't the
/// way.
pub type Outcome = Result<(bool, bool), &'static str>;

/// What only the process to itself can check: files every test of a process shares.
pub const NEEDS_ALONE: &str =
    "its files are the process's own: crates/sentry/tests/rows_on_disk.rs";

impl Way {
    pub const ALL: [Way; 24] = [
        Way::FixGone,
        Way::FixStill,
        Way::Expected,
        Way::ExpectedBack,
        Way::Pattern,
        Way::Unwatch,
        Way::UnwatchBack,
        Way::TaskDone,
        Way::TaskSteps,
        Way::TaskRemove,
        Way::Later,
        Way::LaterBack,
        Way::Run,
        Way::RunForItem,
        Way::Series,
        Way::Review,
        Way::Track,
        Way::Untrack,
        Way::Ignore,
        Way::DiskTasks,
        Way::DiskLater,
        Way::DiskBaseline,
        Way::DiskPlan,
        Way::DiskConfig,
    ];

    /// What must be seen: listed before, and after.
    pub fn expect(self) -> (bool, bool) {
        match self {
            Way::FixStill => (true, true),
            Way::ExpectedBack | Way::LaterBack | Way::UnwatchBack => (false, true),
            Way::FixGone
            | Way::Expected
            | Way::Pattern
            | Way::Unwatch
            | Way::TaskDone
            | Way::TaskSteps
            | Way::TaskRemove
            | Way::Later
            | Way::Run
            | Way::RunForItem
            | Way::Series
            | Way::Review
            | Way::Track
            | Way::Untrack
            | Way::Ignore
            | Way::DiskTasks
            | Way::DiskLater
            | Way::DiskBaseline
            | Way::DiskPlan
            | Way::DiskConfig => (true, false),
        }
    }

    /// It is about files changed without the app.
    pub fn on_disk(self) -> bool {
        matches!(
            self,
            Way::DiskTasks | Way::DiskLater | Way::DiskBaseline | Way::DiskPlan | Way::DiskConfig
        )
    }

    /// It reads or writes a file every test of a process shares (a target's config): only
    /// a process that is the test's own can check it.
    pub fn alone(self) -> bool {
        self.on_disk() || matches!(self, Way::Track | Way::Untrack | Way::Ignore)
    }
}

/// One kind of target, for the matrix.
pub trait Rig {
    /// What it's called in a failure.
    fn kind(&self) -> &'static str;
    /// The window with this target alone, offline, on Maintenance, an open finding on its
    /// list. `name` is the test's own (a host's records and runs are kept by name).
    fn app(&self, name: &str) -> App;
    /// The finding: its id, and its row's key.
    fn finding(&self) -> (String, String);
    /// The key the plan's `unwatch` step names for what the finding is about (None: this
    /// kind of target has nothing to stop watching).
    fn watched(&self) -> Option<String>;
    /// A new audit's report arrives, as its thread would send it: with the finding or
    /// without.
    fn audited(&self, a: &mut App, still: bool);
    /// The last audit's report is read from disk again, as it was written (entering
    /// Maintenance or the Dashboard does that).
    fn reread(&self, a: &mut App);
    /// [`WF`], startable here. What comes back is held while its run lasts (this
    /// machine's runs take turns).
    fn workflow(&self, a: &mut App, name: &str) -> Box<dyn std::any::Any>;
    /// A way only this kind of target has: (the row's key, listed before, after).
    fn own(&self, _way: Way, _name: &str) -> Option<Outcome> {
        None
    }
    /// Why this kind of target hasn't the way.
    fn not_here(&self, _way: Way) -> Option<&'static str> {
        None
    }
    /// The process is the test's own: the records' scope and the target's config file,
    /// as they'd be on disk for `name`, with the finding's cause watched or not.
    fn config_on_disk(&self, _name: &str, _watched: bool) {}
    /// The records' scope (`maint::root`).
    fn scope(&self, name: &str) -> String;
}

fn key(a: &mut App, c: KeyCode) {
    a.on_event(
        Event::Key(KeyEvent::new(c, KeyModifiers::NONE)),
        Instant::now(),
    );
}

/// Whether Maintenance lists the row (everything, what can wait too).
pub fn listed(a: &mut App, row: &str) -> bool {
    a.rows_for_test().iter().any(|k| k == row)
}

/// The cursor on the row with this key.
pub fn select(a: &mut App, row: &str) {
    if a.slot().screen != ScreenId::Maint {
        key(a, KeyCode::Char(ScreenId::Maint.key()));
    }
    if !a.everything_for_test() {
        key(a, KeyCode::Char('o'));
    }
    key(a, KeyCode::Home);
    for _ in 0..200 {
        if a.row_at_for_test().as_deref() == Some(row) {
            return;
        }
        key(a, KeyCode::Down);
    }
    panic!("no row {row} to select among {:?}", a.rows_for_test());
}

fn task(id: &str, every: Option<&str>, act: &str) -> Task {
    Task {
        id: id.into(),
        title: format!("{id}: a task of the matrix"),
        why: "the matrix needs one".into(),
        level: Level::Routine,
        every: every.map(|e| e.parse().expect("a cadence")),
        act: act.into(),
        item: None,
        steps: "Look, then say it's done.".into(),
        added: None,
        off: false,
        source: sentry_core::maint::tasks::Source::File,
        review: None,
        after: None,
        again: None,
    }
}

fn task_key(id: &str) -> String {
    format!("task:{id}")
}

const VERDICT_DONE: &str =
    "It's fixed.\n```sentry-verdict\nstatus = \"done\"\nsummary = \"fixed\"\n```";

fn plan(step: &str) -> String {
    format!(
        "Found it.\n```sentry-apply\nsummary = \"fix it\"\n\n[[step]]\ntitle = \"Fix\"\n{step}\n```"
    )
}

/// The finding's session, from Enter on its row to the plan approved and run.
fn fix(a: &mut App, row: &str, step: &str, runs: bool) {
    select(a, row);
    // `A`, then 1: apply it with Claude.
    key(a, KeyCode::Char('A'));
    key(a, KeyCode::Char('1'));
    assert!(
        a.apply_session().is_some(),
        "a session opened on {row}: {:?}",
        a.toast_for_test()
    );
    // Enter starts; Claude answers with the plan; Enter approves it.
    key(a, KeyCode::Enter);
    a.apply_answer_for_test(&plan(step));
    key(a, KeyCode::Enter);
    if runs {
        a.apply_exit_for_test(0);
    }
}

/// Close whatever the way left open, so the list is what's looked at.
fn close(a: &mut App) {
    for _ in 0..4 {
        key(a, KeyCode::Esc);
    }
}

/// Records › Later: take the row with this key back.
fn undo(a: &mut App, row_key: &str) {
    assert!(
        a.undo_for_test(row_key),
        "Records › Later has no row {row_key}"
    );
}

/// One way, on one kind of target. `alone`: the process is this test's own, so the files
/// every test of a process shares may be written.
pub fn run(rig: &dyn Rig, way: Way, alone: bool) -> Outcome {
    if let Some(why) = rig.not_here(way) {
        return Err(why);
    }
    let name = format!("rows-{way:?}").to_lowercase();
    if way.alone() && !alone {
        return Err(NEEDS_ALONE);
    }
    if let Some(out) = rig.own(way, &name) {
        return out;
    }
    if way.on_disk() {
        return on_disk(rig, way, &name);
    }
    let mut a = rig.app(&name);
    let (id, row) = rig.finding();
    let now = Instant::now();
    Ok(match way {
        Way::FixGone | Way::FixStill => {
            let still = way == Way::FixStill;
            let before = listed(&mut a, &row);
            fix(&mut a, &row, "run = \"true\"", true);
            // The audit runs again by itself; its report is what the list is made from.
            rig.audited(&mut a, still);
            a.apply_answer_for_test(VERDICT_DONE);
            if still {
                // Claude is told, twice at most; it keeps saying done: never settled done.
                for _ in 0..sentry_core::apply::session::FIX_ROUNDS {
                    a.apply_answer_for_test(VERDICT_DONE);
                }
            }
            let done = a.apply_session().is_some_and(|s| {
                s.phase
                    == sentry_core::apply::session::Phase::Settled(
                        sentry_core::apply::session::End::Done,
                    )
            });
            assert_eq!(done, !still, "{}: settled done", rig.kind());
            let logged_done = a.slot().shared.log.iter().any(|e| {
                e.head.result == "done" && e.head.tags.iter().any(|t| t == &format!("finding:{id}"))
            });
            assert_eq!(logged_done, !still, "{}: logged as done", rig.kind());
            close(&mut a);
            (before, listed(&mut a, &row))
        }
        Way::Expected | Way::ExpectedBack | Way::Pattern => {
            let before = listed(&mut a, &row);
            select(&mut a, &row);
            key(
                &mut a,
                KeyCode::Char(if way == Way::Pattern { 'B' } else { 'x' }),
            );
            key(&mut a, KeyCode::Enter);
            // The stored report is read again, as entering Maintenance does: it says what
            // was expected when it was written, and the row must not come back with it.
            rig.reread(&mut a);
            let after = listed(&mut a, &row);
            if way != Way::ExpectedBack {
                return Ok((before, after));
            }
            undo(&mut a, &id);
            (after, listed(&mut a, &row))
        }
        Way::Unwatch | Way::UnwatchBack => {
            let Some(what) = rig.watched() else {
                return Err("nothing here is watched by a list a session can shorten");
            };
            let before = listed(&mut a, &row);
            fix(
                &mut a,
                &row,
                &format!("unwatch = \"{what}\"\nwhy = \"retired on purpose\""),
                false,
            );
            // Nothing is watched there any more: the row is gone before the audit says so.
            let after = listed(&mut a, &row);
            rig.audited(&mut a, false);
            a.apply_answer_for_test(VERDICT_DONE);
            close(&mut a);
            if way == Way::Unwatch {
                return Ok((before, after && listed(&mut a, &row)));
            }
            undo(&mut a, &what);
            // Watched again: the next audit reports it as before.
            rig.audited(&mut a, true);
            (after, listed(&mut a, &row))
        }
        Way::TaskDone | Way::TaskSteps | Way::TaskRemove | Way::Later | Way::LaterBack => {
            a.add_task_for_test(task(TASK, Some("30d"), "by-hand"));
            let row = task_key(TASK);
            let before = listed(&mut a, &row);
            select(&mut a, &row);
            match way {
                Way::TaskDone => key(&mut a, KeyCode::Char('d')),
                Way::TaskSteps => {
                    key(&mut a, KeyCode::Char('m'));
                    key(&mut a, KeyCode::Enter);
                }
                Way::TaskRemove => {
                    key(&mut a, KeyCode::Char('x'));
                    key(&mut a, KeyCode::Enter);
                }
                _ => {
                    key(&mut a, KeyCode::Char('z'));
                    key(&mut a, KeyCode::Char('1'));
                }
            }
            close(&mut a);
            let after = listed(&mut a, &row);
            if way != Way::LaterBack {
                return Ok((before, after));
            }
            undo(&mut a, &row);
            (after, listed(&mut a, &row))
        }
        Way::Run | Way::RunForItem | Way::Series => {
            let _turn = rig.workflow(&mut a, &name);
            let mut t = task(RUN, Some("30d"), &format!("run {WF}"));
            if way == Way::RunForItem {
                t.item = Some("rows-item".into());
            }
            a.add_task_for_test(t);
            let row = task_key(RUN);
            let before = listed(&mut a, &row);
            select(&mut a, &row);
            if way == Way::Series {
                key(&mut a, KeyCode::Char(' '));
            }
            key(&mut a, KeyCode::Enter);
            // (A start box, where the target has one.)
            if a.box_yes_for_test().is_some() {
                key(&mut a, KeyCode::Enter);
            }
            a.tick(Instant::now());
            a.run_step_exit_for_test(0);
            a.run_logged_for_test();
            close(&mut a);
            (before, listed(&mut a, &row))
        }
        Way::Review => {
            a.add_task_for_test(task(ONCE, None, "by-hand"));
            let row = task_key(ONCE);
            let before = listed(&mut a, &row);
            // R, Enter: Claude writes the review; its changes come ticked, Enter applies them.
            select(&mut a, &row);
            key(&mut a, KeyCode::Char('R'));
            key(&mut a, KeyCode::Enter);
            a.writer_answered(&format!(
                "The list.\n```sentry-changes\n[[remove]]\ntask = \"{ONCE}\"\nwhy = \"done long ago\"\n```"
            ));
            key(&mut a, KeyCode::Enter);
            close(&mut a);
            (before, listed(&mut a, &row))
        }
        Way::Track | Way::Untrack | Way::Ignore => {
            return Err("only a server tracks what discovery finds");
        }
        Way::DiskTasks | Way::DiskLater | Way::DiskBaseline | Way::DiskPlan | Way::DiskConfig => {
            unreachable!("handled above: {now:?}")
        }
    })
}

/// What changed on disk without the app is on the list when the app next looks (`r`,
/// entering a screen, the target getting the window back).
fn on_disk(rig: &dyn Rig, way: Way, name: &str) -> Outcome {
    use sentry_core::maint;
    let scope = rig.scope(name);
    rig.config_on_disk(name, true);
    let mut a = rig.app(name);
    let (id, finding_row) = rig.finding();
    let today = jiff::Zoned::now().date();
    // The records as a session before this one left them.
    let t = task(TASK, Some("30d"), "by-hand");
    maint::tasks::save(&scope, std::slice::from_ref(&t)).expect("tasks.toml");
    let _ = maint::later::replace(&scope, &Default::default());
    let _ = std::fs::remove_file(sentry_core::baseline::path(&scope));
    let looks = |a: &mut App| {
        // What the app does on `r`, on entering a screen, on getting the window back.
        a.look_for_test();
    };
    looks(&mut a);
    let row = match way {
        Way::DiskTasks | Way::DiskLater | Way::DiskPlan => task_key(TASK),
        _ => finding_row,
    };
    let before = match way {
        Way::DiskPlan => {
            a.plan_keep_for_test(TASK, "The plan.");
            looks(&mut a);
            a.slot().shared.plans.contains_key(TASK)
        }
        _ => listed(&mut a, &row),
    };
    // (A file's time has the clock's grain: the change is a later moment.)
    std::thread::sleep(std::time::Duration::from_millis(20));
    match way {
        Way::DiskTasks => maint::tasks::save(&scope, &[]).expect("tasks.toml"),
        Way::DiskLater => {
            let until = today.checked_add(jiff::Span::new().days(30)).unwrap();
            maint::later::set(&scope, &row, until, today).expect("later.toml");
        }
        Way::DiskBaseline => {
            let mut b = sentry_core::baseline::BaselineFile::load(&scope);
            b.findings.push(id);
            b.save(&scope).expect("baseline.toml");
        }
        Way::DiskPlan => {
            std::fs::remove_file(maint::plan::path(&scope, TASK)).expect("the plan's file");
        }
        Way::DiskConfig => rig.config_on_disk(name, false),
        _ => unreachable!(),
    }
    // Nothing yet: nothing watches in the background.
    let unseen = match way {
        Way::DiskPlan => a.slot().shared.plans.contains_key(TASK),
        _ => listed(&mut a, &row),
    };
    assert!(unseen, "{}: nothing reads before the app looks", rig.kind());
    looks(&mut a);
    let after = match way {
        Way::DiskPlan => a.slot().shared.plans.contains_key(TASK),
        _ => listed(&mut a, &row),
    };
    // Left as found, for whoever is next in this process.
    let _ = std::fs::remove_dir_all(maint::root(&scope).join("plans"));
    let _ = std::fs::remove_file(maint::tasks::path(&scope));
    let _ = std::fs::remove_file(maint::later::path(&scope));
    let _ = std::fs::remove_file(sentry_core::baseline::path(&scope));
    Ok((before, after))
}

/// A target's whole matrix: every way gives what it must, or isn't this target's (and why).
pub fn check(rig: &dyn Rig, alone: bool) -> Vec<(Way, Outcome)> {
    let mut out = Vec::new();
    for way in Way::ALL {
        if alone != way.alone() {
            continue;
        }
        let got = run(rig, way, alone);
        if let Ok(seen) = got {
            assert_eq!(
                seen,
                way.expect(),
                "{} · {way:?}: (listed before, listed after)",
                rig.kind()
            );
        }
        out.push((way, got));
    }
    out
}

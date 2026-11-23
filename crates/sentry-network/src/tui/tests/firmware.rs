//! The firmware upgrade in the window: Enter on its row starts it (a copy still marked a
//! draft only from its row's box, never by auto mode or by name), its flash asks in a box
//! that says what happens, and auto never answers the download or the flash.

use super::*;
use sentry_app::effect::{Effect, WfCmd};

const WF: &str = "firmware-upgrade";

fn on_disk() -> Option<sentry_core::workflows::state::Run> {
    sentry_core::workflows::state::in_progress_in(&crate::workflow::root(&super::super::id_of(
        NAME,
    )))
}

/// Maintenance, its cursor on the firmware's item.
fn at_firmware(a: &mut App) -> String {
    let _ = screen(a, '6', 158, 41);
    let mut s = String::new();
    for _ in 0..12 {
        s = render_to_string(a, 158, 41);
        if s.contains("Enter: what has and hasn't been proven of firmware-upgrade") {
            return s;
        }
        key(a, KeyCode::Char('j'));
    }
    panic!("no firmware item: {s}");
}

fn session(a: &mut App) -> &mut crate::workflow::Session {
    a.slot_mut()
        .run
        .as_mut()
        .unwrap()
        .as_any_mut()
        .downcast_mut::<crate::workflow::Session>()
        .unwrap()
}

/// A copy marked a draft: the box says what has and hasn't been proven; auto mode never
/// answers it; its Enter starts the run, and that acknowledgment is used up by that start.
#[test]
fn the_firmware_draft_starts_from_its_box_and_nowhere_else() {
    let _turn = runs();
    for auto in [true, false] {
        let mut a = with_draft(&backup_cfg());
        if auto {
            ctrl(&mut a, 'a');
            assert!(a.slot().auto);
        }
        at_firmware(&mut a);
        key(&mut a, KeyCode::Enter);
        for _ in 0..3 {
            a.tick(Instant::now());
        }
        let s = render_to_string(&mut a, 158, 41);
        assert!(
            s.contains("Upgrade the router's firmware (a draft)")
                && s.contains("Not proven: any other router")
                && s.contains("Proven on a real router"),
            "{s}"
        );
        assert!(a.slot().run.is_none() && on_disk().is_none(), "auto {auto}");
        if auto {
            key(&mut a, KeyCode::Esc);
            assert!(a.slot().run.is_none() && on_disk().is_none());
            continue;
        }
        insta::assert_snapshot!("firmware_draft_box_158x41", s);
        key(&mut a, KeyCode::Enter);
        let run = a.slot().run.as_ref().expect("the box's Enter starts it");
        assert_eq!(run.wf().name, WF);
        assert!(on_disk().is_some());
        let ids: Vec<String> = session(&mut a)
            .wf
            .steps
            .iter()
            .map(|x| x.id.clone())
            .collect();
        assert_eq!(
            ids,
            [
                "check",
                "backup",
                "plan",
                "download",
                "flash",
                "wait",
                "after",
                "add-missing",
                "forget"
            ]
        );
        // The run at its flash step: Enter shows what the flash does, and its Enter runs it.
        {
            let s = session(&mut a);
            // (Offline, the first step "runs" without a process: it is taken as done.)
            s.live = None;
            for i in 0..4 {
                sentry_core::workflows::runner::mark_done(&mut s.run.state, i, "test");
            }
            s.refresh();
            assert_eq!(s.next, Next::Confirm(4));
        }
        let _ = screen(&mut a, '0', 158, 60);
        key(&mut a, KeyCode::Enter);
        let s = render_to_string(&mut a, 158, 60);
        insta::assert_snapshot!("firmware_flash_box_158x60", s);
        assert!(
            a.box_yes_for_test()
                .is_some_and(|y| matches!(y, [Effect::Wf(WfCmd::Go)])),
            "the box's Enter runs the step"
        );
        key(&mut a, KeyCode::Esc);
        assert!(
            session(&mut a).live.is_none(),
            "Esc in the box runs nothing"
        );
        // Abandoned: it doesn't start again but from the box.
        a.apply(vec![Effect::Wf(WfCmd::Abandon)], Instant::now());
        a.apply(vec![Effect::Wf(WfCmd::Close)], Instant::now());
        assert!(on_disk().is_none());
        for cmd in [
            WfCmd::Begin(WF.into()),
            WfCmd::BeginWith(WF.into(), Default::default()),
        ] {
            a.apply(vec![Effect::Wf(cmd)], Instant::now());
            assert!(
                a.slot().run.as_ref().is_none_or(|r| r.done()) && on_disk().is_none(),
                "started without its box"
            );
        }
    }
}

/// The Security page's "newer firmware" row (the security audit's item) goes where the
/// firmware's item on Maintenance goes: Enter starts the upgrade, which shows its plan
/// before anything is downloaded; with auto on, it still stops at the download and at the
/// flash.
#[test]
fn the_security_pages_firmware_row_starts_the_upgrade() {
    let _turn = runs();
    for auto in [false, true] {
        let mut a = with_workflows(&backup_cfg(), None);
        let me = crate::tui::id_of(NAME);
        a.slot_mut().shared.sec = vec![sentry_core::secaudit::Item {
            id: format!("sec:firmware:{me}"),
            group: sentry_core::secaudit::Group::GettingIn,
            state: sentry_core::secaudit::State::DoFirst,
            rank: 0,
            title: "A newer router firmware with security fixes is out".into(),
            why: "It fixes holes.".into(),
            fix: "Upgrade the firmware.".into(),
            targets: vec![me.clone()],
            evidence: vec![],
            brief: String::new(),
            question: None,
        }];
        if auto {
            ctrl(&mut a, 'a');
            assert!(a.slot().auto);
        }
        let _ = screen(&mut a, '4', 158, 41);
        key(&mut a, KeyCode::Esc);
        typed(&mut a, "/A newer router firmware");
        let s = render_to_string(&mut a, 158, 41);
        assert!(
            s.contains("Enter: upgrade the router's software (it shows the plan first)"),
            "{s}"
        );
        key(&mut a, KeyCode::Enter);
        assert_eq!(
            a.slot()
                .run
                .as_ref()
                .expect("its Enter starts it")
                .wf()
                .name,
            WF
        );
        // The first three steps run by themselves (offline: taken as done); the download
        // and the flash wait for a key, auto or not.
        for i in [3, 4] {
            {
                let s = session(&mut a);
                s.live = None;
                for j in 0..i {
                    sentry_core::workflows::runner::mark_done(&mut s.run.state, j, "test");
                }
                s.refresh();
                assert_eq!(s.next, Next::Confirm(i));
            }
            for _ in 0..3 {
                a.tick(Instant::now());
            }
            assert!(
                session(&mut a).live.is_none() && session(&mut a).next == Next::Confirm(i),
                "auto {auto}: step {i} waits for a key"
            );
        }
        a.apply(vec![Effect::Wf(WfCmd::Abandon)], Instant::now());
        a.apply(vec![Effect::Wf(WfCmd::Close)], Instant::now());
    }
}

/// After one good run, the offer to take `draft = true` out of the file takes out that
/// line and nothing else.
#[test]
fn undrafting_takes_out_only_the_draft_line() {
    let d = std::env::temp_dir().join(format!("sentry-undraft-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("firmware-upgrade.toml");
    // A draft as the seeded one was: `draft = true`, and the flash box's line that is only
    // true of a draft.
    let shipped = include_str!("../../../../../assets/network-workflows/firmware-upgrade.toml");
    let text = &shipped
        .replacen("\n[[steps]]", "draft = true\n\n[[steps]]", 1)
        .replacen(
            "\nNever turn the router off",
            &format!(
                "\n{}\n\nNever turn the router off",
                crate::workflow::DRAFT_LINE
            ),
            1,
        );
    assert!(sentry_core::workflows::parse(text).unwrap().draft);
    std::fs::write(&p, text).unwrap();
    crate::workflow::undraft(&p).unwrap();
    let after = std::fs::read_to_string(&p).unwrap();
    let w = sentry_core::workflows::parse(&after).unwrap();
    assert!(!w.draft);
    // `draft = true`, and the flash box's line that is only true of a draft (with its
    // blank line): nothing else.
    assert!(text.contains(crate::workflow::DRAFT_LINE));
    assert!(!after.contains(crate::workflow::DRAFT_LINE));
    let ask = w
        .steps
        .iter()
        .find(|s| s.id == "flash")
        .unwrap()
        .ask
        .clone()
        .unwrap();
    assert!(!ask.contains("\n\n\n") && ask.contains("Never turn the router off"));
    assert_eq!(after.lines().count() + 3, text.lines().count());
    // (What is left is the workflow as shipped now.)
    assert_eq!(after, shipped);
    assert_eq!(
        sentry_core::workflows::parse(text).unwrap().steps.len(),
        w.steps.len()
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The firmware upgrade ends well: every row that said to upgrade leaves without a key.
/// The review's task (`run firmware-upgrade`, item `firmware`) is done by the run; the
/// security audit's item from a report made before it is withheld at once and the audit
/// runs again by itself (the facts only: nothing opens, no review); the router's release,
/// its packages and its own audit are read again by themselves, and once the release
/// read says the new one, the rule's row is gone too.
#[test]
fn a_good_firmware_run_takes_every_upgrade_row_away_by_itself() {
    use sentry_core::secaudit::{Group, Item, Report, State as SecState, TargetFacts};
    let _turn = runs();
    let mut a = with_workflows(&backup_cfg(), None);
    let me = crate::tui::id_of(NAME);
    super::upkeep(&mut a, super::backed_up(1, &[]));
    let mut t = super::a_task(
        "fw-up",
        "Upgrade the router's firmware",
        "run firmware-upgrade",
    );
    t.item = Some("firmware".into());
    a.add_task_for_test(t);
    // The security audit's report from before the run, with its firmware item.
    let item = Item {
        id: format!("sec:firmware:{me}"),
        group: Group::KnownHoles,
        state: SecState::DoFirst,
        rank: 0,
        title: "A newer router firmware with security fixes is out".into(),
        why: "It fixes holes.".into(),
        fix: "Upgrade the firmware.".into(),
        targets: vec![me.clone()],
        evidence: vec![],
        brief: String::new(),
        question: None,
    };
    let before = a.win.now() - jiff::SignedDuration::from_hours(24);
    a.win.sec.report = Some(Report {
        version: 1,
        at: before,
        targets: Vec::new(),
        observed: false,
        items: vec![item.clone()],
        errors: Vec::new(),
        diff: Default::default(),
        alone: String::new(),
    });
    a.win.sec.rev += 1;
    a.win.sec.rerun_offline = true;
    let _ = screen(&mut a, '6', 158, 41);
    let rows = a.rows_for_test();
    let rule = crate::maint::recommend::KEY_FIRMWARE.to_string();
    assert!(rows.contains(&"task:fw-up".to_string()), "{rows:?}");
    assert!(rows.contains(&rule), "{rows:?}");
    assert!(a.slot().shared.sec.iter().any(|i| i.id == item.id));
    let s = screen(&mut a, '4', 158, 41);
    assert!(s.contains("A newer router firmware"), "{s}");
    // The run, to its last step that runs.
    a.apply(vec![Effect::StartWorkflow(WF.into())], Instant::now());
    {
        let s = session(&mut a);
        s.live = None;
        for i in 0..6 {
            sentry_core::workflows::runner::mark_done(&mut s.run.state, i, "test");
        }
        s.refresh();
        assert_eq!(s.next, Next::Run(6), "after");
        s.armed = true;
    }
    let asked = net(&a).asked.len();
    a.tick(Instant::now());
    a.run_step_exit_for_test(0);
    assert!(a.slot().run.as_ref().unwrap().done());
    a.run_logged_for_test();
    // The task is done by the run, the audit's item is withheld: both at once.
    let rows = a.rows_for_test();
    assert!(!rows.contains(&"task:fw-up".to_string()), "{rows:?}");
    assert!(!a.slot().shared.sec.iter().any(|i| i.id == item.id));
    // What the run changed is read again by itself, the audit among it.
    let fetched = &net(&a).asked[asked..];
    for k in [Kind::Ifaces, Kind::Updates, Kind::Audit] {
        assert!(fetched.contains(&k), "{k:?} in {fetched:?}");
    }
    // The next thing the window does: the security audit runs again, quietly.
    a.tick(Instant::now());
    key(&mut a, KeyCode::Null);
    assert!(
        a.win.sec.busy() && a.win.sec.quiet,
        "{:?}",
        a.toast_for_test()
    );
    // The release as the router says it now: the rule's row goes.
    let mut i = super::the_ifaces();
    i.board.version = "25.12.5".into();
    data(&mut a, Kind::Ifaces, Ok(Payload::Ifaces(Box::new(i))));
    let rows = a.rows_for_test();
    assert!(!rows.contains(&rule), "{rows:?}");
    let s = screen(&mut a, '4', 158, 41);
    assert!(!s.contains("A newer router firmware"), "{s}");
    // The audit's answer: a report after the upgrade, nothing opened, no review asked for.
    let facts = vec![TargetFacts::new(
        &me,
        sentry_core::secaudit::Kind::Network,
        NAME,
    )];
    a.on_event(
        super::Event::Data(me.clone(), Box::new(sentry_app::secaudit::Done(facts))),
        Instant::now(),
    );
    assert!(!a.win.sec.busy() && !a.win.sec.quiet);
    assert!(a.win.sec.report.as_ref().unwrap().at > before);
    assert!(
        !a.win.sec.reviewing && !render_to_string(&mut a, 158, 41).contains(" Security audit ")
    );
    assert!(!a.slot().shared.sec.iter().any(|i| i.id == item.id));
    a.apply(vec![Effect::Wf(WfCmd::Close)], Instant::now());
}

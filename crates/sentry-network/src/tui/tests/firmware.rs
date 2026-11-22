//! The firmware upgrade in the window: started from its row's box (it is a draft), never
//! by auto mode or by name, and its flash asks in a box that says what happens.

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

/// The box says what has and hasn't been proven; auto mode never answers it; its Enter
/// starts the run, and that acknowledgment is used up by that start.
#[test]
fn the_firmware_draft_starts_from_its_box_and_nowhere_else() {
    let _turn = runs();
    for auto in [true, false] {
        let mut a = with_workflows(&backup_cfg(), None);
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
                && s.contains("Not proven anywhere yet: the flash itself")
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

/// After one good run, the offer to take `draft = true` out of the file takes out that
/// line and nothing else.
#[test]
fn undrafting_takes_out_only_the_draft_line() {
    let d = std::env::temp_dir().join(format!("sentry-undraft-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("firmware-upgrade.toml");
    let text = include_str!("../../../../../assets/network-workflows/firmware-upgrade.toml");
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
    assert_eq!(
        sentry_core::workflows::parse(text).unwrap().steps.len(),
        w.steps.len()
    );
    let _ = std::fs::remove_dir_all(&d);
}

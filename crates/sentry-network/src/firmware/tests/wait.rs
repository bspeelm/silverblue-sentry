//! The wait for the router, the flash's log, what `plan` and `download` agree on.

use super::super::*;
use super::fx;

#[test]
fn the_wait_tells_back_gone_and_never_flashed_apart_on_a_given_clock() {
    let t0: Timestamp = "2026-11-22T10:00:00Z".parse().unwrap();
    let total = Duration::from_secs(15 * 60);
    let until = deadline(t0, t0, total);
    assert_eq!(until, t0 + total);
    let at = |s: i64| t0 + jiff::SignedDuration::from_secs(s);
    let old = "boot-a";
    let ans = |boot: &str, busy: bool, log: &str| {
        Seen::Answer(Look {
            boot: boot.into(),
            busy,
            log: log.into(),
        })
    };
    let installing = fx("flash-log.txt");
    // No answer: wait, until the deadline; then gone (the calm message).
    assert_eq!(
        poll(&Seen::Nothing, old, at(60), until, None),
        Poll::Waiting
    );
    assert_eq!(
        poll(&Seen::Nothing, old, at(15 * 60), until, None),
        Poll::Gone
    );
    // A new boot is back, even at the last moment.
    assert_eq!(
        poll(&ans("boot-b", false, ""), old, at(15 * 60 + 5), until, None),
        Poll::Back
    );
    // The old boot answers and the flash still works: wait; at the deadline it is stuck,
    // never "gone".
    assert_eq!(
        poll(&ans(old, true, &installing), old, at(60), until, None),
        Poll::StillFlashing
    );
    assert_eq!(
        poll(&ans(old, true, ""), old, at(15 * 60), until, None),
        Poll::Stuck
    );
    // The old boot answers and nothing of the flash runs, and owut never handed the image
    // over (no Installing line): said after 20 s, long before the deadline.
    let quiet = ans(old, false, "Verifying : x\n");
    assert_eq!(poll(&quiet, old, at(10), until, Some(0)), Poll::Waiting);
    assert_eq!(poll(&quiet, old, at(19), until, Some(19)), Poll::Waiting);
    assert_eq!(poll(&quiet, old, at(25), until, Some(20)), Poll::NotFlashed);
    // Handed over to sysupgrade: procd gets two minutes to start.
    let handed = ans(old, false, &installing);
    assert_eq!(poll(&handed, old, at(60), until, Some(60)), Poll::Waiting);
    assert_eq!(
        poll(&handed, old, at(130), until, Some(120)),
        Poll::NotFlashed
    );
    // Answering and idle at the deadline: not flashed either, never "gone".
    assert_eq!(
        poll(&handed, old, at(15 * 60), until, Some(1)),
        Poll::NotFlashed
    );
    assert_eq!(
        poll(&ans("", false, ""), old, at(10), until, None),
        Poll::Waiting
    );
    // Picked up again long after: one more minute of looking.
    let later = at(3600);
    assert_eq!(deadline(t0, later, total), later + GRACE);
    assert_eq!(took(250), "4 min 10 s");
    assert_eq!(took(900), "15 min");
    assert_eq!(took(7), "7 s");
}

#[test]
fn a_look_is_read_from_the_routers_answer() {
    let l = parse_look("boot-a\n@@busy\n1234\n@@log\nInstalling x and rebooting...\n").unwrap();
    assert_eq!(l.boot, "boot-a");
    assert!(l.busy);
    assert_eq!(read_flash_log(&l.log), Flashing::Installing);
    let l = parse_look("boot-a\n@@busy\n@@log\n").unwrap();
    assert!(!l.busy && l.log.is_empty());
    assert!(parse_look("").is_none() && parse_look("@@busy\n@@log\n").is_none());
    assert!(LOOK_SCRIPT.contains("pgrep -x owut") && LOOK_SCRIPT.contains(FLASH_LOG));
}

#[test]
fn never_flashed_is_said_plainly() {
    let st = State {
        from: "25.12.5".into(),
        ..Default::default()
    };
    let l = not_flashed_words(&st, "Verifying : x\nsomething went quiet\n");
    assert!(
        l[0].contains("still running 25.12.5: the flash did not happen. Nothing was changed."),
        "{l:?}"
    );
    assert!(
        l.iter().any(|x| x.contains("something went quiet")),
        "{l:?}"
    );
    assert!(!l.join(" ").contains("recovery"), "{l:?}");
    assert!(
        not_flashed_words(&st, "")
            .iter()
            .any(|x| x.contains("said nothing"))
    );
}

#[test]
fn flash_log_fixture() {
    // owut's own words, as its `install()` prints them
    // (`L.log(0, "Installing %s and rebooting...\n", options.image)`): a rewording fails here.
    let log = fx("flash-log.txt");
    assert!(log.contains("Installing /tmp/sentry-firmware.bin and rebooting...\n"));
    assert_eq!(read_flash_log(&log), Flashing::Installing);
    assert_eq!(
        read_flash_log("ERROR: sha256 doesn't match:\n"),
        Flashing::Refused(vec!["sha256 doesn't match:".into()])
    );
    assert_eq!(
        read_flash_log("Checks complete, image is valid.\n"),
        Flashing::Starting
    );
    let l = flash_line();
    assert!(
        l.starts_with("setsid sh -c 'exec owut install -i /tmp/sentry-firmware.bin"),
        "{l}"
    );
    assert!(!l.contains("nohup"));
}

#[test]
fn an_older_release_stops_and_the_download_asks_for_the_version_shown() {
    let older = "Version-from 25.12.5 a (kernel 1)\nVersion-to 25.12.4 b (kernel 2)\n\n\
                 Package version changes:\n  x 2 1 (downgrade)\n1 packages were downgraded\n\n\
                 It is safe to proceed with an upgrade\n";
    let why = stops(&parse_check(older), 0, "25.12.5");
    assert!(
        why.iter().any(|w| w.contains("older than the 25.12.5")),
        "{why:?}"
    );
    // The fixture's downgrade stops it too (owut's own count).
    assert!(!stops(&parse_check(&fx("check-downgrade.txt")), 0, "25.12.5").is_empty());
    // What `plan` keeps is owut's Version-to, and `download` asks for exactly that.
    let c = parse_check(&fx("check.txt"));
    let to = c.to.unwrap().version;
    assert_eq!(to, "25.12.6");
    let line = download_line(&to);
    assert!(
        line.starts_with("owut download -V 25.12.6 -i /tmp/sentry-firmware.bin "),
        "{line}"
    );
}

/// The tests are a debug build: the knob is read here. A release build never reads it
/// (`cfg!(debug_assertions)` in `knob`), so it always waits the full 15 minutes.
#[test]
fn test_knobs_are_read_only_in_a_debug_build() {
    // SAFETY: only this test touches this variable.
    unsafe { std::env::set_var("SENTRY_FIRMWARE_KNOB_TEST", "7") };
    assert_eq!(
        knob("SENTRY_FIRMWARE_KNOB_TEST").is_some(),
        cfg!(debug_assertions)
    );
    assert_eq!(WAIT, Duration::from_secs(900));
}

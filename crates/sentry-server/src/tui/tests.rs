//! Every tab rendered from synthetic data (no ssh), at the mockup size and the smallest.

use std::time::Instant;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::Ev;
use super::app::{App, render_to_string};
use super::data::{Kind, Payload};
use sentry_core::tui::ScreenId;

/// The screens the server's data fills (`0`, the workflows, has tests of its own).
const SHOWN: [ScreenId; 6] = [
    ScreenId::Dash,
    ScreenId::Proc,
    ScreenId::Net,
    ScreenId::Cont,
    ScreenId::Svc,
    ScreenId::Maint,
];
use crate::audit;
use crate::collect::{self, apt, docker, fixture, health, probe, units};
use crate::config::{DiskRule, Server, TimerRule};
use crate::remote::Remote;
use sentry_core::config::Dur;

fn cfg() -> Server {
    Server {
        services: vec!["app.service".into(), "backup.service".into()],
        timers: vec![TimerRule {
            unit: "backup.timer".into(),
            max_age: Dur::hours(27),
        }],
        disks: vec![
            DiskRule {
                mount: "/".into(),
                warn: 85,
                crit: 95,
            },
            DiskRule {
                mount: "/srv/data".into(),
                warn: 85,
                crit: 95,
            },
        ],
        smart: vec!["/dev/sda".into(), "/dev/sdc".into()],
        listeners: vec!["*:22/*".into()],
        sudo: vec!["journalctl".into(), "docker logs".into()],
        actions: vec![crate::config::CustomAction {
            id: "backup-now".into(),
            title: "Run the backup now".into(),
            run: "systemctl start backup.service".into(),
            sudo: true,
            risky: false,
            undo: None,
        }],
        maintenance: crate::config::Maintenance {
            notes: vec!["~/notes/runbook.md".into()],
            items: maint_items(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn maint_items() -> Vec<crate::config::MaintItem> {
    use crate::config::{ImageRef, MaintItem, Retire, Risk};
    vec![
        MaintItem {
            id: "web".into(),
            image: Some(ImageRef {
                service: Some("web".into()),
                ..Default::default()
            }),
            source: Some("github:example/web".into()),
            hold: Some("1.5 migrates the database one way".into()),
            review_by: Some(jiff::civil::date(2027, 1, 15)),
            workflow: Some("compose-bump".into()),
            ..Default::default()
        },
        MaintItem {
            id: "engine".into(),
            apt: vec!["engine-pkg".into()],
            risk: Risk::High,
            hold: Some("restarts every container".into()),
            ..Default::default()
        },
        MaintItem {
            id: "legacy".into(),
            unit: Some("legacy.service".into()),
            retire: Some(Retire {
                replaced_by: Some("app.service".into()),
                workflow: Some("retire-service".into()),
            }),
            ..Default::default()
        },
        MaintItem {
            id: "os".into(),
            eol: Some("debian/12".into()),
            risk: Risk::High,
            ..Default::default()
        },
    ]
}

/// The maintenance data the tab shows: pins, a security release upstream, an end of life.
fn maint_payload() -> Payload {
    use crate::maint::local::Local;
    use crate::maint::upstream::{Eol, Lookups, Release, Upstream};
    let mut local = std::collections::BTreeMap::new();
    local.insert(
        "web".to_string(),
        Local {
            pinned: Some("1.4.2".into()),
            running: Some("1.4.2".into()),
            repo: Some("example/web".into()),
            ..Default::default()
        },
    );
    local.insert(
        "engine".to_string(),
        Local {
            pinned: Some("5:24.3.1-1".into()),
            running: Some("5:24.3.1-1".into()),
            candidate: Some("5:24.4.0-1".into()),
            held: true,
            ..Default::default()
        },
    );
    let mut lk = Lookups::default();
    lk.sources.insert(
        "github:example/web".into(),
        Upstream {
            releases: vec![
                Release {
                    version: "v1.5.2".into(),
                    date: Some("2026-10-01".into()),
                    security: true,
                    url: None,
                },
                Release {
                    version: "v1.5.1".into(),
                    date: Some("2026-09-12".into()),
                    ..Default::default()
                },
            ],
            err: None,
        },
    );
    lk.eol.insert(
        "debian/12".into(),
        Ok(Eol {
            cycle: "12".into(),
            eol: Some(jiff::civil::date(2026, 12, 10)),
            latest: Some("12.12".into()),
        }),
    );
    let st = crate::maint::eval::evaluate(
        &maint_items(),
        &local,
        Some(&lk),
        &Default::default(),
        &Default::default(),
        jiff::civil::date(2026, 10, 26),
    );
    let found = crate::maint::discover::Found {
        candidates: vec![crate::maint::discover::Candidate {
            key: "image:cache".into(),
            what: "compose service cache (example/cache:7.2)".into(),
            item: crate::config::MaintItem {
                id: "cache".into(),
                image: Some(crate::config::ImageRef {
                    service: Some("cache".into()),
                    ..Default::default()
                }),
                source: Some("docker:example/cache".into()),
                ..Default::default()
            },
        }],
        gone: Vec::new(),
    };
    Payload::Maint(st, local, found)
}

fn data(a: &mut App, k: Kind, p: Payload) {
    a.on_event(Ev::Data(k, Box::new(Ok(p))), Instant::now());
}

fn app() -> App {
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new("myserver", &cfg()), tx);
    a.offline = true;
    a.theme = sentry_core::tui::theme::Theme::truecolor();
    a.now_override = Some("2026-10-26T12:00:00Z".parse().unwrap());
    data(
        &mut a,
        Kind::Sudo,
        Payload::Sudo(crate::remote::SudoMode::NoPasswd),
    );
    data(
        &mut a,
        Kind::Host,
        Payload::Host(
            "Debian GNU/Linux 12 (bookworm)".into(),
            "6.1.0-9-amd64".into(),
        ),
    );
    let p = probe::parse(&fixture("probe.txt")).unwrap();
    for i in 0..3u64 {
        let mut q = p.clone();
        q.cpu.total += i * 100;
        q.cpu.idle += i * 80;
        data(&mut a, Kind::Probe, Payload::Probe(q));
    }
    let u = units::Units {
        all: units::parse_list(&fixture("list-units.json")).unwrap(),
        watched: units::parse_show(&fixture("show.txt")),
    };
    data(&mut a, Kind::Units, Payload::Units(u));
    data(
        &mut a,
        Kind::Docker,
        Payload::Docker(docker::Docker {
            containers: docker::parse_inspect(&fixture("docker-inspect.json")).unwrap(),
            projects: docker::parse_projects(&fixture("compose-ls.json")).unwrap(),
        }),
    );
    data(
        &mut a,
        Kind::Apt,
        Payload::Apt(apt::parse(&fixture("apt.txt"))),
    );
    data(
        &mut a,
        Kind::Disks,
        Payload::Disks(sentry_core::collectors::disk::parse(&fixture("findmnt.json")).unwrap()),
    );
    data(
        &mut a,
        Kind::Smart,
        Payload::Smart(vec![
            Ok(health::parse_smart("/dev/sda", &fixture("smart-ok.json"))),
            Ok(health::parse_smart(
                "/dev/sdc",
                &fixture("smart-asleep.json"),
            )),
        ]),
    );
    data(
        &mut a,
        Kind::Temp,
        Payload::Temp(health::parse_sensors(&fixture("sensors.json"))),
    );
    data(
        &mut a,
        Kind::Journal,
        Payload::Journal(collect::group_journal(
            sentry_core::collectors::journal::parse(&fixture("journal.jsonl")),
        )),
    );
    // A report derived from the same synthetic snapshot.
    let mut snap = collect::Snapshot {
        server: "myserver".into(),
        taken_at: Some("2026-10-26T11:00:00Z".parse().unwrap()),
        ..Default::default()
    };
    snap.units = a.store.units.value.clone();
    snap.docker = a.store.docker.value.clone();
    snap.apt = a.store.apt.value.clone();
    snap.errors = vec![(
        "fail2ban".into(),
        "needs sudo: add `fail2ban-client status` to sudo: in server_config.yaml".into(),
    )];
    let findings = audit::derive(
        &snap,
        &cfg(),
        None,
        &sentry_core::baseline::BaselineFile {
            findings: vec!["srv:docker-sock:*".into()],
            ..Default::default()
        },
    );
    data(
        &mut a,
        Kind::Report,
        Payload::Report(Some(Box::new(audit::Report {
            snapshot: snap,
            findings,
        }))),
    );
    data(&mut a, Kind::Maint, maint_payload());
    data(
        &mut a,
        Kind::Sockets,
        Payload::Sockets(collect::sockets::parse(&fixture("sockets.txt")).unwrap()),
    );
    a.set_wf_entries(
        crate::workflow::SEEDS
            .iter()
            .map(|(name, text)| sentry_core::workflows::Entry {
                name: name.to_string(),
                path: std::path::PathBuf::from(format!("{name}.toml")),
                wf: sentry_core::workflows::parse(text),
                issues: Vec::new(),
            })
            .collect(),
    );
    a
}

/// Two samples of the processes, two seconds apart: the second has CPU shares.
fn feed_procs(a: &mut App) {
    for f in ["procs-1.txt", "procs-2.txt"] {
        data(
            a,
            Kind::Procs,
            Payload::Procs(Box::new(collect::procs::parse(&fixture(f)).unwrap())),
        );
    }
}

/// Select a maintenance item's row (recommendations come first).
fn goto_item(a: &mut App, id: &str) {
    a.apply(
        vec![super::app::Effect::MaintJump(id.into())],
        Instant::now(),
    );
}

fn key(a: &mut App, c: KeyCode) {
    a.on_event(
        Ev::Key(KeyEvent::new(c, KeyModifiers::NONE)),
        Instant::now(),
    );
}

/// Drop the header line: it has no clock, but keep snapshots about the screens.
fn body(s: &str) -> String {
    s.lines().skip(1).collect::<Vec<_>>().join("\n")
}

#[test]
fn every_screen_renders() {
    for tab in SHOWN {
        for (w, h) in [(158, 41), (80, 24)] {
            let mut a = app();
            key(&mut a, KeyCode::Char(tab.key()));
            assert_eq!(a.screen, tab);
            if tab == ScreenId::Proc {
                feed_procs(&mut a);
            }
            let s = render_to_string(&mut a, w, h);
            assert!(
                s.contains("sentry-server") && s.contains("myserver"),
                "{tab:?} {w}x{h}\n{s}"
            );
            assert!(!s.contains("too small"));
            if w == 158 {
                insta::assert_snapshot!(
                    format!("server_{}_158x41", tab.name().to_lowercase()),
                    body(&s)
                );
            }
            // Maintenance when narrow: the same panels, the items in fewer columns.
            if w == 80 && tab == ScreenId::Maint {
                insta::assert_snapshot!("server_maintenance_80x24", body(&s));
            }
        }
    }
}

#[test]
fn overview_status_rows_jump_to_their_tab() {
    let mut a = app();
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("reboot required for 8d · kernel 6.1.0-9-amd64 → 6.1.0-25-amd64"),
        "{s}"
    );
    assert!(
        s.contains("/srv/data") && s.contains(" 93% "),
        "over warn: {s}"
    );
    assert!(s.contains("1 security update(s) waiting"), "{s}");
    assert!(s.contains("backup ran 4h ago and failed"), "{s}");
    assert!(s.contains("down: backup.service"), "{s}");
    assert!(s.contains("1 of 3 containers not running"), "{s}");
    assert!(s.contains("sda ok 31°C") && s.contains("sdc asleep"), "{s}");
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.screen, ScreenId::Maint, "first row: reboot → Maintenance");
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("A reboot has been pending") && s.contains("● reboot required"),
        "its recommendation is selected, with the updates detail: {s}"
    );
}

#[test]
fn findings_are_recommendations_on_maintenance() {
    let mut a = app();
    // Overview's findings row lands on the first finding's recommendation.
    let s = render_to_string(&mut a, 158, 41);
    let rows: Vec<&str> = s
        .lines()
        .skip_while(|l| !l.contains("Status"))
        .skip(1)
        .collect();
    let i = rows
        .iter()
        .position(|r| r.contains("open finding"))
        .expect("findings row");
    for _ in 0..i {
        key(&mut a, KeyCode::Char('j'));
    }
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.screen, ScreenId::Maint);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("What  "), "the finding's details\n{s}");
    assert!(
        s.contains("didn't check:") && s.contains("fail2ban: needs sudo"),
        "{s}"
    );
}

#[test]
fn screens_and_badges() {
    let mut a = app();
    let s = render_to_string(&mut a, 158, 41);
    let tabs = s.lines().nth(1).unwrap();
    assert!(
        tabs.starts_with(
            " 1 Dashboard   2 Processes   3 Network 5   4 Containers 1   5 Services 1   6 Maintenance"
        ),
        "sentry's numbers; five new listeners, db is down, one unit failed: {tabs}"
    );
    assert!(
        !tabs.contains("Updates"),
        "updates live on Maintenance: {tabs}"
    );
    assert!(
        tabs.trim_end().ends_with("0 Upgrade"),
        "always there: {tabs}"
    );
    key(&mut a, KeyCode::Char('l'));
    assert_eq!(a.screen, ScreenId::Proc);
    key(&mut a, KeyCode::Char('h'));
    key(&mut a, KeyCode::Char('h'));
    assert_eq!(a.screen, ScreenId::Upgrade, "wraps around");
}

/// Type a `:` command.
fn colon(a: &mut App, cmd: &str) {
    key(a, KeyCode::Char(':'));
    for c in cmd.chars() {
        key(a, KeyCode::Char(c));
    }
    key(a, KeyCode::Enter);
}

#[test]
fn screen_keys_follow_sentry() {
    let mut a = app();
    for (c, id) in [
        ('2', ScreenId::Proc),
        ('3', ScreenId::Net),
        ('4', ScreenId::Cont),
        ('5', ScreenId::Svc),
        ('6', ScreenId::Maint),
        ('1', ScreenId::Dash),
    ] {
        key(&mut a, KeyCode::Char(c));
        assert_eq!(a.screen, id, "{c}");
    }
    // Screens this program doesn't have (yet): their keys do nothing.
    key(&mut a, KeyCode::Char('7'));
    assert_eq!(a.screen, ScreenId::Dash, "no Cleanup here");
    // 0 is a screen, as in sentry: the workflows, with or without a run.
    key(&mut a, KeyCode::Char('0'));
    assert_eq!(a.screen, ScreenId::Upgrade);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("No workflow in progress."), "{s}");
    assert!(s.lines().nth(1).unwrap().contains("0 Upgrade"), "{s}");
    // Tab walks them in strip order and wraps; the help names them as screens.
    key(&mut a, KeyCode::Tab);
    assert_eq!(a.screen, ScreenId::Dash);
    key(&mut a, KeyCode::BackTab);
    key(&mut a, KeyCode::BackTab);
    assert_eq!(a.screen, ScreenId::Maint);
    key(&mut a, KeyCode::Char('?'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Maintenance:") && s.contains("switch screen"),
        "{s}"
    );
    assert!(!s.contains("tabs (or"), "{s}");
}

#[test]
fn old_names_still_work() {
    let mut a = app();
    for (cmd, id) in [
        ("maintenance", ScreenId::Maint),
        ("overview", ScreenId::Dash),
        ("services", ScreenId::Svc),
        ("dashboard", ScreenId::Dash),
        ("cont", ScreenId::Cont),
        ("dash", ScreenId::Dash),
        ("svc", ScreenId::Svc),
        ("maint", ScreenId::Maint),
        ("con", ScreenId::Cont),
        ("ser", ScreenId::Svc),
    ] {
        colon(&mut a, cmd);
        assert_eq!(a.screen, id, ":{cmd}");
    }
    // Not a screen here.
    colon(&mut a, "flatpaks");
    assert_eq!(a.screen, ScreenId::Svc);
    assert!(render_to_string(&mut a, 158, 41).contains("unknown command :flatpaks"));
}

#[test]
fn the_keys_table_is_honoured() {
    let mut a = app();
    let keys: std::collections::BTreeMap<String, String> = [
        ("quit", "Q"),
        ("screen.maintenance", "M"),
        // sentry's screen, in the same config.toml: skipped without a word.
        ("screen.flatpaks", "F"),
        ("screen.nowhere", "X"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let warnings = a.set_keys_for_test(&keys);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("nowhere"), "{warnings:?}");
    key(&mut a, KeyCode::Char('M'));
    assert_eq!(a.screen, ScreenId::Maint);
    key(&mut a, KeyCode::Char('F'));
    assert_eq!(a.screen, ScreenId::Maint);
    key(&mut a, KeyCode::Char('Q'));
    assert!(render_to_string(&mut a, 158, 41).contains("Quit sentry-server?"));
}

#[test]
fn the_strip_shrinks_like_sentrys() {
    let mut a = app();
    key(&mut a, KeyCode::Char('6'));
    let strip = |a: &mut App, w: u16| {
        sentry_core::tui::frame::render_to_string(w, 24, |f| a.draw(f))
            .lines()
            .nth(1)
            .unwrap()
            .to_string()
    };
    // Room for all: full names.
    let s = strip(&mut a, 120);
    assert!(
        s.starts_with(" 1 Dashboard   2 Processes   3 Network 5   4 Containers 1   5 Services 1   6 Maintenance"),
        "{s}"
    );
    // At 80 columns: short names, the one in view whole.
    let s = strip(&mut a, 80);
    assert!(
        s.starts_with(" 1 Dash   2 Proc   3 Net 5   4 Cont 1   5 Svc 1   6 Maintenance"),
        "{s}"
    );
    // The strip is core's, so it narrows as sentry's does: short names (the one in view
    // stays whole), then keys only.
    let four: Vec<sentry_core::tui::frame::Tab> = SHOWN
        .into_iter()
        .map(|id| sentry_core::tui::frame::Tab {
            id,
            badge: None,
            filter: None,
        })
        .collect();
    let t = sentry_core::tui::theme::Theme::truecolor();
    let at = |w: u16| {
        sentry_core::tui::frame::render_to_string(w, 1, |f| {
            sentry_core::tui::frame::draw_tabs(f, f.area(), &t, &four, ScreenId::Maint)
        })
    };
    assert_eq!(
        at(62).trim_end(),
        " 1 Dash   2 Proc   3 Net   4 Cont   5 Svc   6 Maintenance"
    );
    assert_eq!(at(36).trim_end(), " 1   2   3   4   5   6 Maintenance");
    // A filter shows on its screen's name.
    for c in "/web".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert!(strip(&mut a, 158).contains("/web"));
}

#[test]
fn only_the_screen_in_view_is_fetched() {
    use super::data::Kind;
    use super::screens::Screens;
    let mut a = app();
    let now = Instant::now();
    let polled = |a: &App| {
        let mut k: Vec<String> = a
            .polled_for_test()
            .iter()
            .map(|k| format!("{k:?}"))
            .collect();
        k.sort();
        k
    };
    // The Dashboard samples the server while it's shown.
    a.enter(ScreenId::Dash, now);
    assert_eq!(
        polled(&a),
        ["Disks", "Docker", "Gpu", "Probe", "Smart", "Temp", "Units"]
    );
    // Nothing else polls: what they show is read when they're entered (and on r / c).
    for id in [ScreenId::Cont, ScreenId::Svc, ScreenId::Maint] {
        a.enter(id, now);
        assert!(polled(&a).is_empty(), "{id:?}");
        assert!(
            Screens::polls(id, &a.remote.cfg)
                .iter()
                .all(|p| p.every.is_none() && p.kind != Kind::Probe),
            "{id:?}"
        );
    }
    // Leaving the Dashboard stops its sampling; the next wake-up is no sooner than a toast.
    assert!(a.next_due(now) >= now + std::time::Duration::from_secs(1));
    let at_entry = |id| -> Vec<Kind> {
        Screens::polls(id, &a.remote.cfg)
            .into_iter()
            .map(|p| p.kind)
            .collect()
    };
    assert_eq!(at_entry(ScreenId::Cont), [Kind::Docker]);
    assert_eq!(at_entry(ScreenId::Svc), [Kind::Units, Kind::Journal]);
    assert_eq!(
        at_entry(ScreenId::Maint),
        [Kind::Maint, Kind::Docker, Kind::Report]
    );
}

/// Against a real server: `SENTRY_SERVER_LIVE=<name> cargo test live_screens -- --ignored --nocapture`.
/// Reads ~/.config/sentry/server_config.yaml; prints every screen; read-only.
#[test]
#[ignore]
fn live_screens() {
    sentry_core::paths::use_real_dirs();
    let Ok(name) = std::env::var("SENTRY_SERVER_LIVE") else {
        return;
    };
    let (file, _) = crate::config::load().unwrap();
    let (n, s) = crate::config::pick(&file, Some(&name)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new(n, s), tx);
    a.theme = sentry_core::tui::theme::Theme::truecolor();
    a.start(Instant::now());
    for tab in SHOWN {
        a.enter(tab, Instant::now());
        let until = Instant::now()
            + std::time::Duration::from_secs(if tab == ScreenId::Dash { 6 } else { 4 });
        while Instant::now() < until {
            if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
        }
        println!("{}", render_to_string(&mut a, 158, 41));
    }
}

fn run_msg(a: &mut App, id: u64, m: sentry_core::exec::StreamMsg) {
    a.on_event(Ev::Run(id, m), Instant::now());
}

#[test]
fn restart_asks_first_then_streams() {
    use sentry_core::exec::StreamMsg;
    let mut a = app();
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::Char('R'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("$ sudo systemctl restart app.service") && s.contains("on myserver"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('n'));
    assert!(
        !render_to_string(&mut a, 158, 41).contains("$ sudo"),
        "n cancels"
    );
    key(&mut a, KeyCode::Char('R'));
    key(&mut a, KeyCode::Char('y'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Restart") && s.contains("⠿ running"),
        "sentry's run box: {s}"
    );
    assert!(s.contains("$ sudo -n systemctl restart app.service"), "{s}");
    assert!(s.contains("C-c  terminate"), "{s}");
    run_msg(
        &mut a,
        1,
        StreamMsg::Line {
            stderr: false,
            text: "restarted".into(),
        },
    );
    run_msg(
        &mut a,
        1,
        StreamMsg::Exit {
            code: 0,
            elapsed: std::time::Duration::from_secs(1),
        },
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("✓ done") && s.contains("restarted"), "{s}");
    assert!(s.contains("Esc  close"), "{s}");
    key(&mut a, KeyCode::Esc);
    assert!(!render_to_string(&mut a, 158, 41).contains("✓ done"));
    // ssh is the lifeline: restarting it is flagged.
    key(&mut a, KeyCode::Char('x'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("app.service hasn't failed"),
        "x only for failed units: {s}"
    );
}

#[test]
fn reboot_waits_for_a_new_boot_id() {
    use sentry_core::exec::StreamMsg;
    let mut a = app();
    key(&mut a, KeyCode::Char('B'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("$ sudo systemctl reboot") && s.contains("comes back on kernel 6.1.0-25-amd64"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('y'));
    run_msg(
        &mut a,
        1,
        StreamMsg::Exit {
            code: 255,
            elapsed: std::time::Duration::from_secs(1),
        },
    );
    assert!(render_to_string(&mut a, 158, 41).contains("waiting for the server to come back"));
    let mut p = probe::parse(&fixture("probe.txt")).unwrap();
    data(&mut a, Kind::Probe, Payload::Probe(p.clone()));
    assert!(
        !render_to_string(&mut a, 158, 41).contains("is back"),
        "same boot id: still waiting"
    );
    p.boot_id = "new-boot".into();
    data(&mut a, Kind::Probe, Payload::Probe(p));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("myserver is back after"), "{s}");
    assert!(
        !s.contains("● rebooted"),
        "a reboot we asked for isn't news"
    );
}

#[test]
fn password_sudo_hands_over_the_terminal() {
    let mut a = app();
    data(
        &mut a,
        Kind::Sudo,
        Payload::Sudo(crate::remote::SudoMode::Password),
    );
    key(&mut a, KeyCode::Char(ScreenId::Svc.key()));
    key(&mut a, KeyCode::Char('R'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("terminal is handed over"), "{s}");
    key(&mut a, KeyCode::Char('y'));
    let (cmd, _banner) = a.take_suspend().expect("suspends");
    assert!(
        cmd.remote_line()
            .contains("sudo systemctl restart app.service"),
        "{}",
        cmd.remote_line()
    );
    assert!(!cmd.remote_line().contains("sudo -n"));
    data(
        &mut a,
        Kind::Sudo,
        Payload::Sudo(crate::remote::SudoMode::Absent),
    );
    key(&mut a, KeyCode::Char('R'));
    assert!(render_to_string(&mut a, 158, 41).contains("has no sudo"));
}

#[test]
fn custom_actions_and_logs() {
    let mut a = app();
    key(&mut a, KeyCode::Char('a'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("1  Run the backup now"), "{s}");
    key(&mut a, KeyCode::Char('1'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("$ sudo sh -c 'systemctl start backup.service'"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('L'));
    a.on_event(Ev::Text(1, Ok("line one\nline two".into())), Instant::now());
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("docker logs · db") && s.contains("line two"),
        "{s}"
    );
    assert!(
        s.contains("$ sudo -n docker logs --tail 300 --timestamps db"),
        "{s}"
    );
}

/// Against a disposable sshd (never the real server): streams, kills, runs an action for real.
/// `SENTRY_SSH_CONFIG=<file> SENTRY_SERVER_SCRATCH=<name> XDG_CONFIG_HOME=<scratch>
///  cargo test live_actions -- --ignored --nocapture`
#[test]
#[ignore]
fn live_actions() {
    sentry_core::paths::use_real_dirs();
    use sentry_core::exec::StreamMsg;
    let Ok(name) = std::env::var("SENTRY_SERVER_SCRATCH") else {
        return;
    };
    let (file, _) = crate::config::load().unwrap();
    let (n, s) = crate::config::pick(&file, Some(&name)).unwrap();
    let r = Remote::new(n, s);

    // 1. A streamed remote command dies when its local ssh client is killed (-tt → SIGHUP).
    let (tx, rx) = std::sync::mpsc::channel();
    let pid = r
        .cmd("sleep")
        .arg("612")
        .timeout(None)
        .stream(move |m| {
            let _ = tx.send(m);
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let running = |r: &Remote| r.sh("pgrep -xf 'sleep 612' | wc -l").output().unwrap();
    assert_eq!(running(&r).trim(), "1", "remote sleep started");
    super::app::kill_for_test(pid);
    let exit = rx
        .iter()
        .find_map(|m| match m {
            StreamMsg::Exit { code, .. } => Some(code),
            _ => None,
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert_eq!(
        running(&r).trim(),
        "0",
        "remote sleep killed with the client (exit {exit})"
    );
    println!("✓ killing the local ssh client stopped the remote command (local exit {exit})");

    // 2. Refresh lists through the app: confirm, stream, exit 0, apt re-read.
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(r.clone(), tx);
    a.start(Instant::now());
    let pump = |a: &mut App, secs: u64| {
        let until = Instant::now() + std::time::Duration::from_secs(secs);
        while Instant::now() < until {
            if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(100)) {
                a.on_event(ev, Instant::now());
            }
        }
    };
    pump(&mut a, 3);
    key(&mut a, KeyCode::Char('6'));
    pump(&mut a, 8);
    key(&mut a, KeyCode::Char('C'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("$ sudo apt-get update"), "{s}");
    key(&mut a, KeyCode::Char('y'));
    pump(&mut a, 40);
    let s = render_to_string(&mut a, 158, 41);
    println!("{s}");
    assert!(s.contains("Refresh package lists · done"), "{s}");
    // 3. A custom action without sudo (they're on the Dashboard).
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char('a'));
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char('y'));
    pump(&mut a, 3);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("hello from"), "{s}");
    println!("✓ actions ran: apt-get update, custom action");
    // 4. x on Processes ends one of the login's own processes: a sleep started for this.
    key(&mut a, KeyCode::Esc);
    let (stx, _srx) = std::sync::mpsc::channel();
    let sleeper = r
        .cmd("sleep")
        .arg("613")
        .timeout(None)
        .stream(move |m| {
            let _ = stx.send(m);
        })
        .unwrap();
    let sleeping = |r: &Remote| r.sh("pgrep -xf 'sleep 613' | wc -l").output().unwrap();
    key(&mut a, KeyCode::Char('2'));
    pump(&mut a, 5);
    assert_eq!(sleeping(&r).trim(), "1", "remote sleep started");
    for c in "/sleep 613".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('x'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("$ kill -TERM"), "{s}");
    key(&mut a, KeyCode::Char('y'));
    pump(&mut a, 5);
    assert_eq!(sleeping(&r).trim(), "0", "ended through the TUI");
    super::app::kill_for_test(sleeper);
    println!("✓ x on Processes sent SIGTERM to the sleep");
}

/// apt-maintenance end to end on the disposable sshd container (never the real server).
/// Same environment as `live_actions`.
#[test]
#[ignore]
fn live_workflow() {
    sentry_core::paths::use_real_dirs();
    let Ok(name) = std::env::var("SENTRY_SERVER_SCRATCH") else {
        return;
    };
    let (file, _) = crate::config::load().unwrap();
    let (n, s) = crate::config::pick(&file, Some(&name)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new(n, s), tx);
    a.start(Instant::now());
    let pump = |a: &mut App, secs: u64| {
        let until = Instant::now() + std::time::Duration::from_secs(secs);
        while Instant::now() < until {
            if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(100)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
        }
    };
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    pump(&mut a, 2);
    a.apply(
        vec![super::app::Effect::StartWorkflow("apt-maintenance".into())],
        Instant::now(),
    );
    assert!(screen(&mut a).contains("Start apt-maintenance"));
    key(&mut a, KeyCode::Char('y'));
    // Drive it: Enter on confirm steps, skip the optional one, mark what can't pass in a
    // container (its kernel is the host's) done by hand.
    for _ in 0..30 {
        pump(&mut a, 3);
        let s = screen(&mut a);
        let busy = a.wf.as_ref().is_some_and(|w| w.live.is_some());
        if busy {
            continue;
        }
        let Some(w) = a.wf.as_ref() else { break };
        if w.done() {
            println!("{s}");
            break;
        }
        use sentry_core::workflows::runner::Next;
        match w.next.clone() {
            Next::Confirm(i) if w.wf.steps[i].optional => key(&mut a, KeyCode::Char('s')),
            Next::Confirm(_) => key(&mut a, KeyCode::Enter),
            Next::Reboot {
                requested: false, ..
            } => {
                key(&mut a, KeyCode::Enter);
                key(&mut a, KeyCode::Char('y'));
            }
            Next::Reboot {
                requested: true, ..
            }
            | Next::Stopped(_)
            | Next::Manual { .. } => {
                println!("{s}");
                key(&mut a, KeyCode::Char('d'));
                key(&mut a, KeyCode::Char('y'));
            }
            _ => {}
        }
    }
    let w = a.wf.as_ref().unwrap();
    assert!(w.done(), "{}", screen(&mut a));
    for (i, st) in w.run.state.steps.iter().enumerate() {
        println!("{:<14} {:?} {:?}", w.wf.steps[i].id, st.status, st.note);
    }
}

#[test]
fn fixing_a_finding_on_the_server_is_an_apply_session() {
    use sentry_core::apply::session::{End, Phase, Turn};
    let mut a = app();
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    a.apply(
        vec![super::app::Effect::MaintFind("finding:".into())],
        Instant::now(),
    );
    key(&mut a, KeyCode::Char('A'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Sent to Claude") && s.contains("Audit finding (high"),
        "{s}"
    );
    assert!(
        s.contains("brief › investigate") && s.contains("through `sentry-server exec`"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    a.apply_answer_for_test(
        "Start it.\n```sentry-apply\nsummary = \"start db\"\n[[step]]\ntitle = \"Start\"\n\
         run = \"sudo docker start db\"\n```",
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        !s.contains("Proposed commands") && s.contains("Enter  apply the plan"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    // sudo -n works here: no password asked; the step runs on the server.
    a.apply_exit_for_test(0);
    a.apply_exit_for_test(0);
    // No audit to run here (the server's findings): Claude verifies straight away.
    assert_eq!(
        a.apply_session().unwrap().phase,
        Phase::Thinking(Turn::Verify)
    );
    a.apply_answer_for_test("```sentry-verdict\nstatus = \"done\"\nsummary = \"db is up\"\n```");
    assert_eq!(a.apply_session().unwrap().phase, Phase::Settled(End::Done));
}

#[test]
fn claude_gets_only_the_gateway() {
    let r = Remote::new("myserver", &cfg());
    let p = super::ask::profile(&r, "Debian 13", "6.12", None);
    // Nothing allowed but the gateway; Read/Edit/Write (laptop files) are there only to be
    // asked for, and refused unless granted.
    assert_eq!(p.allowed, ["Bash(sentry-server exec myserver:*)"]);
    assert_eq!(p.tools, ["Bash", "Read", "Edit", "Write"]);
    assert!(p.denied.contains(&"Bash(scp:*)".to_string()));
    assert!(p.denied.contains(&"Bash(ssh:*)".to_string()));
    assert!(p.denied.contains(&"Bash(sudo:*)".to_string()));
    assert!(
        p.system
            .contains("sentry-server exec myserver -- <command>")
    );
}

/// Ask Claude about a real server: `SENTRY_SERVER_LIVE=<name> cargo test live_ask -- --ignored
/// --nocapture`. Needs Claude Code and sentry-server on PATH; read-only on the server.
#[test]
#[ignore]
fn live_ask() {
    sentry_core::paths::use_real_dirs();
    let Ok(name) = std::env::var("SENTRY_SERVER_LIVE") else {
        return;
    };
    let (file, _) = crate::config::load().unwrap();
    let (n, s) = crate::config::pick(&file, Some(&name)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new(n, s), tx);
    a.start(Instant::now());
    let pump = |a: &mut App, secs: u64| {
        let until = Instant::now() + std::time::Duration::from_secs(secs);
        while Instant::now() < until {
            if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(100)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
        }
    };
    pump(&mut a, 8);
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Char('y'));
    for _ in 0..60 {
        pump(&mut a, 3);
        if a.chat_mut().is_some_and(|c| !c.running()) {
            break;
        }
    }
    let c = a.chat_mut().unwrap();
    for (k, t) in &c.entries {
        println!("[{k:?}] {t}");
    }
}

/// Same look as sentry: key chips on the grey (`dim`) background, the badge ink on cyan.
#[test]
fn the_frame_is_sentrys() {
    let mut a = app();
    // The whole screen, top bar and clock included (the clock is the test's).
    insta::assert_snapshot!("server_frame_158x41", render_to_string(&mut a, 158, 41));
    insta::assert_snapshot!("server_frame_80x24", render_to_string(&mut a, 80, 24));
    let s = render_to_string(&mut a, 158, 41);
    let top = s.lines().next().unwrap();
    assert!(
        top.contains("sentry-server") && top.contains("myserver") && top.contains("kernel 6.1"),
        "{top}"
    );
    assert!(
        top.contains("● connected") && top.ends_with("Mon 26 Oct 12:00"),
        "the connection where sentry says live, then the clock: {top}"
    );
    // Narrow: facts go first, the state never.
    let s = render_to_string(&mut a, 80, 24);
    let top = s.lines().next().unwrap();
    assert!(
        top.contains("● connected") && !top.contains("Debian"),
        "{top}"
    );
}

#[test]
fn enter_confirms_and_the_bar_says_so() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::Char('R'));
    let s = screen(&mut a);
    let bar = s.lines().last().unwrap();
    assert!(
        bar.contains("Enter  confirm") && bar.contains("Esc  cancel"),
        "{bar}"
    );
    assert!(!bar.contains("y  confirm"), "{bar}");
    // Esc cancels; Enter confirms (y and n still do too).
    key(&mut a, KeyCode::Esc);
    assert!(!screen(&mut a).contains("$ sudo"));
    key(&mut a, KeyCode::Char('R'));
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("⠿ running"), "Enter started it");
    // A choice names its keys the same way.
    let mut a = app();
    key(&mut a, KeyCode::Char('6'));
    key(&mut a, KeyCode::Char('z'));
    let s = screen(&mut a);
    assert!(s.contains("pick one (1–3, n cancels)"), "{s}");
    let bar = s.lines().last().unwrap();
    assert!(
        bar.contains("1–9  choose") && bar.contains("Esc  cancel"),
        "{bar}"
    );
    key(&mut a, KeyCode::Esc);
    assert!(!screen(&mut a).contains("pick one"));
}

#[test]
fn a_toast_shares_the_key_bar() {
    let mut a = app();
    for c in ":xyz".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    let bar = s.lines().last().unwrap();
    assert!(
        bar.contains("?  help") && bar.contains("q  quit"),
        "the hints stay: {bar}"
    );
    assert!(bar.ends_with("unknown command :xyz"), "at the right: {bar}");
    // It goes by itself, as sentry's does.
    let later = Instant::now() + sentry_core::tui::frame::TOAST_FOR;
    a.tick(later);
    let s = render_to_string(&mut a, 158, 41);
    assert!(!s.contains("unknown command"), "{s}");
}

#[test]
fn boxes_sit_in_the_body_over_a_dimmed_screen() {
    use ratatui::style::Modifier;
    let mut a = app();
    key(&mut a, KeyCode::Char('q'));
    let backend = ratatui::backend::TestBackend::new(158, 41);
    let mut term = ratatui::Terminal::new(backend).unwrap();
    term.draw(|f| a.draw(f)).unwrap();
    let buf = term.backend().buffer().clone();
    // The screen behind is dimmed; the top bar, the strip and the key bar aren't.
    assert!(buf[(2, 6)].modifier.contains(Modifier::DIM), "the body");
    for y in [0, 1, 40] {
        assert!(!buf[(2, y)].modifier.contains(Modifier::DIM), "row {y}");
    }
    // The box is inside the body, also on a small terminal with a long box.
    let mut a = app();
    key(&mut a, KeyCode::Char('?'));
    let s = render_to_string(&mut a, 80, 24);
    let lines: Vec<&str> = s.lines().collect();
    assert!(lines[0].contains("sentry-server"), "the top bar stays: {s}");
    assert!(lines[1].contains("1 Dash"), "the strip stays: {s}");
    assert!(lines[23].contains("q  quit"), "the key bar stays: {s}");
}

#[test]
fn one_input_line_for_every_prompt() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    let bar = |a: &mut App| {
        render_to_string(a, 158, 41)
            .lines()
            .last()
            .unwrap()
            .to_string()
    };
    // A filter and a command.
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::Char('/'));
    key(&mut a, KeyCode::Char('a'));
    assert!(bar(&mut a).starts_with("/a▏   Enter keep · Esc clear"));
    // Backspace on nothing closes a filter (and a command), keeping what it was.
    key(&mut a, KeyCode::Backspace);
    key(&mut a, KeyCode::Backspace);
    assert!(bar(&mut a).contains("?  help"));
    key(&mut a, KeyCode::Char(':'));
    assert!(bar(&mut a).starts_with(":▏"));
    key(&mut a, KeyCode::Backspace);
    assert!(bar(&mut a).contains("?  help"));
    // A plan's note: Esc says it wasn't planned; a box over the line gets the keys first.
    key(&mut a, KeyCode::Char('6'));
    goto_item(&mut a, "engine");
    key(&mut a, KeyCode::Char('p'));
    key(&mut a, KeyCode::Char('1'));
    let b = bar(&mut a);
    assert!(
        b.contains("plan engine →") && b.contains("a note (optional): ▏   Enter save · Esc cancel"),
        "{b}"
    );
    // One Backspace too many loses nothing.
    key(&mut a, KeyCode::Backspace);
    assert!(bar(&mut a).contains("a note (optional)"));
    key(&mut a, KeyCode::Esc);
    assert!(bar(&mut a).ends_with("not planned"));
    // A task done: the note for the log; Esc leaves none.
    a.add_task_for_test(sentry_core::maint::tasks::Task {
        id: "ups".into(),
        title: "Check the UPS battery".into(),
        why: "It is old.".into(),
        level: sentry_core::maint::Level::Soon,
        every: None,
        act: "by-hand".into(),
        item: None,
        steps: String::new(),
        added: None,
        off: false,
        source: Default::default(),
        review: None,
        after: None,
    });
    a.apply(
        vec![super::app::Effect::MaintFind("task:ups".into())],
        Instant::now(),
    );
    key(&mut a, KeyCode::Char('d'));
    let b = bar(&mut a);
    assert!(
        b.contains("ups done · for the maintenance log") && b.contains("Enter save · Esc cancel"),
        "{b}"
    );
    for c in "fine".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("noted in the maintenance log"));
    assert_eq!(
        a.last_log.as_ref().map(|e| e.body.contains("fine")),
        Some(true)
    );
}

#[test]
fn a_var_without_a_value_is_asked_again() {
    let mut a = app();
    a.set_wf_entries(vec![sentry_core::workflows::Entry {
        name: "bump".into(),
        path: "bump.toml".into(),
        wf: sentry_core::workflows::parse(
            "name = \"bump\"\ndescription = \"x\"\ndraft = true\n\
             [vars.image]\nprompt = \"New image\"\n[vars.service]\nprompt = \"Which service\"\n\
             [[steps]]\nid = \"a\"\ntitle = \"a\"\nrun = \"echo {{ service }} {{ image }}\"\n",
        ),
        issues: Vec::new(),
    }]);
    let bar = |a: &mut App| {
        render_to_string(a, 158, 41)
            .lines()
            .last()
            .unwrap()
            .to_string()
    };
    a.apply(
        vec![super::app::Effect::Wf(super::app::WfCmd::Begin(
            "bump".into(),
        ))],
        Instant::now(),
    );
    assert!(bar(&mut a).contains("bump 1/2 · New image (image): ▏   Enter next · Esc cancel"));
    // Nothing typed and no default: the same value is asked again, and says why.
    key(&mut a, KeyCode::Enter);
    let b = bar(&mut a);
    assert!(
        b.contains("bump 1/2 · New image (image): ▏") && b.contains("image needs a value"),
        "{b}"
    );
    // Backspace on nothing doesn't drop the values asked for.
    key(&mut a, KeyCode::Backspace);
    assert!(bar(&mut a).contains("bump 1/2"));
    for c in "example/web:2".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let b = bar(&mut a);
    assert!(
        b.contains("bump 2/2 · Which service (service): ▏   Enter next"),
        "the next one, the note gone: {b}"
    );
}

#[test]
fn a_paste_goes_to_the_open_prompt() {
    let mut a = app();
    let paste = |a: &mut App, text: &str| a.on_event(Ev::Paste(text.into()), Instant::now());
    // Nothing open: a paste does nothing (its letters aren't keys).
    paste(&mut a, "q6");
    assert_eq!(a.screen, ScreenId::Dash);
    assert!(!render_to_string(&mut a, 158, 41).contains("Quit sentry-server?"));
    // The line being typed takes it whole, on one line.
    key(&mut a, KeyCode::Char(':'));
    paste(&mut a, "maint\n");
    assert!(render_to_string(&mut a, 158, 41).contains(":maint▏"));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.screen, ScreenId::Maint);
    // A box in front of a prompt: the paste isn't for the prompt.
    goto_item(&mut a, "engine");
    key(&mut a, KeyCode::Char('p'));
    key(&mut a, KeyCode::Char('1'));
    paste(&mut a, "first");
    assert!(render_to_string(&mut a, 158, 41).contains("a note (optional): first▏"));
    a.apply(
        vec![super::app::Effect::Info("Note".into(), Vec::new())],
        Instant::now(),
    );
    paste(&mut a, " second");
    key(&mut a, KeyCode::Esc);
    assert!(render_to_string(&mut a, 158, 41).contains("a note (optional): first▏"));
}

#[test]
fn help_is_laid_out_like_sentrys() {
    let mut a = app();
    key(&mut a, KeyCode::Char('?'));
    let s = render_to_string(&mut a, 158, 41);
    for has in [
        " Keys ",
        "1–9 0 H   switch screen",
        "j/k ↑↓    move selection",
        ":q  :<screen>  :workflow <name>  :audit [now]  :log  :refresh",
        "Dashboard:",
        "sentry-server:",
        "read what needs root, once, with your sudo password",
        "Nothing keeps running on myserver after sentry-server exits.",
    ] {
        assert!(s.contains(has), "{has} not in: {s}");
    }
    // Maintenance: every row key, in the same grid.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('6'));
    key(&mut a, KeyCode::Char('?'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Maintenance:") && s.contains("z "), "{s}");
}

#[test]
fn chips_and_badge_match_sentry() {
    let mut a = app();
    let backend = ratatui::backend::TestBackend::new(158, 41);
    let mut term = ratatui::Terminal::new(backend).unwrap();
    term.draw(|f| a.draw(f)).unwrap();
    let buf = term.backend().buffer().clone();
    let t = a.theme;
    let bar = 40;
    let q = (0..158)
        .find(|&x| buf[(x, bar)].symbol() == "q" && buf[(x + 2, bar)].symbol() == " ")
        .expect("q chip");
    assert_eq!(buf[(q, bar)].bg, t.dim, "key chip background");
    assert_eq!(buf[(q, bar)].fg, t.chip_fg);
    assert_eq!(buf[(1, 0)].bg, t.cyan, "badge");
    assert_eq!(buf[(1, 0)].fg, t.ink);
}

#[test]
fn chat_input_edits() {
    let mut a = app();
    // A plain question (the Overview): a chat.
    key(&mut a, KeyCode::Char(ScreenId::Dash.key()));
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Enter);
    a.chat_mut().unwrap().on_exit(0);
    for c in "why qj1".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Backspace);
    key(&mut a, KeyCode::Backspace);
    key(&mut a, KeyCode::Char('?'));
    assert_eq!(
        a.chat_mut().unwrap().input,
        "why q?",
        "q, j and digits are text here; Backspace deletes"
    );
}

#[test]
fn quit_asks_and_colon_commands() {
    let mut a = app();
    key(&mut a, KeyCode::Char('q'));
    assert!(!a.quit, "q asks first");
    assert!(render_to_string(&mut a, 158, 41).contains("Quit sentry-server?"));
    key(&mut a, KeyCode::Char('n'));
    assert!(!a.quit);
    for c in ":mai".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    assert!(render_to_string(&mut a, 158, 41).contains(":mai▏"));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.screen, ScreenId::Maint, ":mai goes to Maintenance");
    for c in ":wf compose-update".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert!(render_to_string(&mut a, 158, 41).contains("Start compose-update on myserver"));
    key(&mut a, KeyCode::Esc);
    for c in ":xyz".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert!(render_to_string(&mut a, 158, 41).contains("unknown command :xyz"));
    for c in ":q".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert!(a.quit, ":q quits");
}

#[test]
fn slash_filters_the_tab() {
    let mut a = app();
    let screen = |a: &mut App| body(&render_to_string(a, 158, 41));
    key(&mut a, KeyCode::Char('/'));
    assert!(
        screen(&mut a).contains("nothing to filter"),
        "not on Overview"
    );
    key(&mut a, KeyCode::Char(ScreenId::Cont.key()));
    let all = screen(&mut a);
    assert!(all.contains("│ web") && all.contains("│ runner"));
    for c in "/DB".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    let s = screen(&mut a);
    assert!(s.contains("/DB▏"), "typing shows in the key bar\n{s}");
    assert!(s.contains("│ db") && !s.contains("│ web") && !s.contains("│ runner"));
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(
        s.contains("Containers 1 /DB"),
        "kept filter shows on the tab\n{s}"
    );
    assert!(!s.contains("│ web"));
    // Each tab has its own filter.
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    assert!(!screen(&mut a).contains("Maintenance /"));
    key(&mut a, KeyCode::Char(ScreenId::Cont.key()));
    // n/N wrap around the matches; Esc clears.
    key(&mut a, KeyCode::Char('n'));
    assert!(screen(&mut a).contains("│ db"));
    key(&mut a, KeyCode::Esc);
    let s = screen(&mut a);
    assert!(s.contains("│ web") && !s.contains("/DB"));
    // Esc while typing drops it too; a filter matching nothing leaves the list empty.
    for c in "/zzz".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    assert!(!screen(&mut a).contains("│ db"));
    key(&mut a, KeyCode::Esc);
    assert!(screen(&mut a).contains("│ db"));
}

/// Read-only against the real server: `A` on the updates recommendation opens the consent box
/// (nothing is sent). `SENTRY_SERVER_LIVE=<name> cargo test live_ask_boxes -- --ignored --nocapture`
#[test]
#[ignore]
fn live_ask_boxes() {
    sentry_core::paths::use_real_dirs();
    let Ok(name) = std::env::var("SENTRY_SERVER_LIVE") else {
        return;
    };
    let (file, _) = crate::config::load().unwrap();
    let (n, s) = crate::config::pick(&file, Some(&name)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new(n, s), tx);
    a.start(Instant::now());
    let pump = |a: &mut App, secs: u64| {
        let until = Instant::now() + std::time::Duration::from_secs(secs);
        while Instant::now() < until {
            if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
        }
    };
    // Updates: A on their recommendation, once Maintenance has loaded.
    a.enter(ScreenId::Maint, Instant::now());
    pump(&mut a, 15);
    a.apply(
        vec![super::app::Effect::MaintFind("wf:apt-maintenance".into())],
        Instant::now(),
    );
    key(&mut a, KeyCode::Char('A'));
    let s = render_to_string(&mut a, 158, 41);
    println!("{s}");
    assert!(
        s.contains("Ask Claude"),
        "no consent box on the updates recommendation"
    );
    key(&mut a, KeyCode::Esc);
}

#[test]
fn workflow_vars_are_asked_before_it_starts() {
    let mut a = app();
    let text = "name = \"bump\"\ndescription = \"x\"\ndraft = true\n\
        [vars.service]\nprompt = \"Which service\"\n\
        [vars.image]\nprompt = \"New image\"\ndefault = \"example/web:2\"\n\
        [[steps]]\nid = \"a\"\ntitle = \"a\"\nrun = \"echo {{ service }} {{ image }}\"\n";
    a.set_wf_entries(vec![sentry_core::workflows::Entry {
        name: "bump".into(),
        path: "bump.toml".into(),
        wf: sentry_core::workflows::parse(text),
        issues: Vec::new(),
    }]);
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    a.apply(
        vec![super::app::Effect::Wf(super::app::WfCmd::Begin(
            "bump".into(),
        ))],
        Instant::now(),
    );
    // Asked in name order (image, then service): the default is filled in.
    let s = screen(&mut a);
    assert!(
        s.contains("bump 1/2 · New image (image): example/web:2▏"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(s.contains("bump 2/2 · Which service (service): ▏"), "{s}");
    // No default: an empty answer isn't taken.
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("service needs a value"));
    for c in "web".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    // All asked: it tries to start (this one is a draft, so it's refused before any run exists).
    let s = screen(&mut a);
    assert!(s.contains("bump: draft"), "{s}");
    assert!(a.wf.is_none());
    // Esc cancels the start.
    a.apply(
        vec![super::app::Effect::Wf(super::app::WfCmd::Begin(
            "bump".into(),
        ))],
        Instant::now(),
    );
    key(&mut a, KeyCode::Esc);
    assert!(screen(&mut a).contains("not started"));
}

/// A workflow a test can start: `apt-maintenance` from a real file (starting a run copies
/// it), in the scratch config dir.
fn startable(a: &mut App, file: &str) {
    let (name, text) = crate::workflow::SEEDS
        .iter()
        .find(|(n, _)| *n == "apt-maintenance")
        .unwrap();
    let path = sentry_core::paths::config_dir().join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, text).unwrap();
    a.set_wf_entries(vec![sentry_core::workflows::Entry {
        name: name.to_string(),
        path,
        wf: sentry_core::workflows::parse(text),
        issues: Vec::new(),
    }]);
}

#[test]
fn auto_steps_run_only_on_screen_0() {
    let mut a = app();
    startable(&mut a, "auto-steps-test-apt-maintenance.toml");
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    a.apply(
        vec![super::app::Effect::Wf(super::app::WfCmd::Begin(
            "apt-maintenance".into(),
        ))],
        Instant::now(),
    );
    // Started: its screen, where its steps run.
    assert!(a.wf.is_some(), "{}", screen(&mut a));
    assert_eq!(a.screen, ScreenId::Upgrade);
    assert!(a.wf.as_ref().unwrap().armed);
    let s = screen(&mut a);
    assert!(s.lines().nth(1).unwrap().contains("0 Upgrade ●"), "{s}");
    // The Maintenance rows aren't on screen: z (later) and x aren't theirs here.
    key(&mut a, KeyCode::Char('z'));
    key(&mut a, KeyCode::Char('x'));
    let s = screen(&mut a);
    assert!(!s.contains("in 7 days ("), "{s}");
    assert!(!s.contains("Mark it expected"), "{s}");
    // Another screen: the run stays as it is, and the banner says where it is.
    let at = a.wf.as_ref().unwrap().next.idx();
    key(&mut a, KeyCode::Char('6'));
    a.tick(Instant::now());
    assert_eq!(a.wf.as_ref().unwrap().next.idx(), at, "nothing ran");
    key(&mut a, KeyCode::Char('z'));
    assert!(screen(&mut a).contains("in 7 days ("));
}

#[test]
fn a_run_shows_a_banner_off_screen_0() {
    let mut a = app();
    startable(&mut a, "banner-test-apt-maintenance.toml");
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    a.apply(
        vec![super::app::Effect::Wf(super::app::WfCmd::Begin(
            "apt-maintenance".into(),
        ))],
        Instant::now(),
    );
    // On its own screen: no banner, the run itself.
    let s = screen(&mut a);
    assert!(!s.contains("press 0 to continue"), "{s}");
    insta::assert_snapshot!("server_upgrade_running_158x41", body(&s));
    // Anywhere else: a row of its own under the strip, as in sentry.
    key(&mut a, KeyCode::Char('1'));
    let s = screen(&mut a);
    let banner = s.lines().nth(3).unwrap();
    assert!(
        banner.contains("↻ workflow apt-maintenance · step 1/")
            && banner.contains("press 0 to continue"),
        "{s}"
    );
    assert!(
        s.lines().nth(5).unwrap().contains("CPU"),
        "the body below: {s}"
    );
    key(&mut a, KeyCode::Char('0'));
    assert_eq!(a.screen, ScreenId::Upgrade);
    assert!(!screen(&mut a).contains("press 0 to continue"));
    // a abandons (after its box); the list is back.
    key(&mut a, KeyCode::Char('a'));
    assert!(screen(&mut a).contains("Abandon apt-maintenance?"));
    key(&mut a, KeyCode::Enter);
    // It's logged: the note is asked for (Esc: none), then Enter closes the run.
    assert!(screen(&mut a).contains("for the maintenance log"));
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(
        a.wf.is_none() && s.contains("No workflow in progress."),
        "{s}"
    );
}

#[test]
fn enter_on_a_workflow_asks_its_vars_or_shows_the_start_box() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char('0'));
    let s = screen(&mut a);
    insta::assert_snapshot!("server_upgrade_idle_158x41", body(&s));
    assert!(
        s.contains("Workflows") && s.contains("apt-maintenance") && s.contains("never run"),
        "{s}"
    );
    assert!(s.contains("[Enter] start   [e] edit   lint ✓"), "{s}");
    let bar = s.lines().last().unwrap();
    assert!(
        bar.contains("Enter  start") && bar.contains("e  edit toml") && bar.contains("r  reload"),
        "{bar}"
    );
    // No values to ask: the box that says what starting does. Esc: nothing started.
    let names: Vec<String> = crate::workflow::SEEDS
        .iter()
        .map(|(n, _)| n.to_string())
        .collect();
    let at = |name: &str| names.iter().position(|n| n == name).unwrap();
    for _ in 0..at("apt-maintenance") {
        key(&mut a, KeyCode::Char('j'));
    }
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(s.contains("Start apt-maintenance on myserver"), "{s}");
    assert!(s.contains("Auto steps run right away"), "{s}");
    key(&mut a, KeyCode::Esc);
    assert!(a.wf.is_none());
    // One that takes values: they're asked first, in the key bar, with no box before.
    let mut a = app();
    a.set_wf_entries(vec![sentry_core::workflows::Entry {
        name: "bump".into(),
        path: "bump.toml".into(),
        wf: sentry_core::workflows::parse(
            "name = \"bump\"\ndescription = \"x\"\n[vars.image]\nprompt = \"New image\"\n\
             [[steps]]\nid = \"a\"\ntitle = \"a\"\nrun = \"echo {{ image }}\"\n",
        ),
        issues: Vec::new(),
    }]);
    key(&mut a, KeyCode::Char('0'));
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(!s.contains("Start bump"), "{s}");
    assert!(s.contains("bump 1/1 · New image (image): ▏"), "{s}");
    key(&mut a, KeyCode::Esc);
    assert!(screen(&mut a).contains("not started"));
    // One that can't start says why instead.
    let mut a = app();
    a.set_wf_entries(vec![sentry_core::workflows::Entry {
        name: "broken".into(),
        path: "broken.toml".into(),
        wf: sentry_core::workflows::parse("name = "),
        issues: Vec::new(),
    }]);
    key(&mut a, KeyCode::Char('0'));
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(
        s.contains("broken can't start") && s.contains("parse error"),
        "{s}"
    );
}

#[test]
fn ask_works_on_the_updates_recommendation() {
    let mut a = app();
    // Updates live on Maintenance now: A on their recommendation.
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    a.apply(
        vec![super::app::Effect::MaintFind("wf:apt-maintenance".into())],
        Instant::now(),
    );
    // A offers: 1 help me apply it (Claude beside apt-maintenance), 2 just ask.
    key(&mut a, KeyCode::Char('A'));
    assert!(render_to_string(&mut a, 158, 41).contains("help me apply it"));
    key(&mut a, KeyCode::Char('1'));
    let prompt = a.consent_text().expect("consent");
    assert!(prompt.contains("Updates (simulated)"), "{prompt}");
    assert!(
        prompt.contains("workflow `apt-maintenance`")
            && prompt.contains("workflow = \"apt-maintenance\""),
        "{prompt}"
    );
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Char('2'));
    let prompt = a.consent_text().expect("consent");
    assert!(
        prompt.contains("Updates (simulated)") && !prompt.contains("sentry-apply"),
        "{prompt}"
    );
}

/// Against a disposable sshd whose sudo asks for a password (never the real server): a sudo
/// step hands over the terminal and its output lands in the step log; abandoning a running
/// step stops it on the server. Run under a pty that types the password:
/// `SENTRY_SSH_CONFIG=… SENTRY_SERVER_SCRATCH=<name> XDG_*=scratch cargo test live_password_step -- --ignored --nocapture`
#[test]
#[ignore]
fn live_password_step() {
    sentry_core::paths::use_real_dirs();
    let Ok(name) = std::env::var("SENTRY_SERVER_SCRATCH") else {
        return;
    };
    let (file, _) = crate::config::load().unwrap();
    let (n, s) = crate::config::pick(&file, Some(&name)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new(n, s), tx);
    a.start(Instant::now());
    let pump = |a: &mut App, secs: u64| {
        let until = Instant::now() + std::time::Duration::from_secs(secs);
        while Instant::now() < until {
            if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(100)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
        }
    };
    pump(&mut a, 2);
    a.apply(
        vec![super::app::Effect::StartWorkflow("pw-check".into())],
        Instant::now(),
    );
    key(&mut a, KeyCode::Char('y'));
    key(&mut a, KeyCode::Enter);
    let (cmd, banner) = a
        .take_suspend()
        .expect("the password step hands over the terminal");
    println!("{banner}");
    let status = cmd.interactive();
    a.after_suspend(status);
    pump(&mut a, 3);
    let w = a.wf.as_ref().unwrap();
    let log = std::fs::read_to_string(w.run.log_path("update")).unwrap();
    println!("--- steps/update.log\n{log}---");
    assert!(
        log.contains("Reading package lists"),
        "apt's output is in the log"
    );
    assert!(!log.contains("password"), "the prompt isn't");
    let after = std::fs::read_to_string(w.run.log_path("after")).unwrap();
    assert!(
        after.contains("after-ok"),
        "the auto step ran next: {after}"
    );
    // The long step: start it, abandon, and nothing is left running there.
    key(&mut a, KeyCode::Enter);
    pump(&mut a, 2);
    assert!(a.wf.as_ref().unwrap().live.is_some());
    key(&mut a, KeyCode::Char('a'));
    key(&mut a, KeyCode::Char('y'));
    pump(&mut a, 2);
    let left = a
        .remote
        .output(&a.remote.sh("pgrep -fx 'sleep 600' || true"))
        .unwrap();
    assert!(
        left.trim().is_empty(),
        "still running on the server: {left}"
    );
    let caps = a
        .remote
        .output(
            &a.remote
                .sh("ls -A ~/.cache/sentry-server 2>/dev/null || true"),
        )
        .unwrap();
    assert!(caps.trim().is_empty(), "captures are deleted: {caps}");
    // The run is in the maintenance log, and the note asked for goes into it.
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("for the maintenance log, what to know next time"),
        "{s}"
    );
    for c in "apt mirror was slow".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let log = crate::maint::log::list(&a.remote.name);
    let e = log.first().expect("an entry");
    println!("{}", e.to_md());
    assert_eq!(e.head.result, "abandoned");
    assert!(e.head.summary.starts_with("apt mirror was slow"));
    let ledger =
        std::fs::read_to_string(crate::maint::log::dir(&a.remote.name).join("LOG.md")).unwrap();
    println!("{ledger}");
    assert!(ledger.contains("apt mirror was slow") && ledger.contains("result:abandoned"));
    println!("ok");
}

#[test]
fn reboot_with_a_password_waits_after_the_terminal_comes_back() {
    use std::os::unix::process::ExitStatusExt;
    let mut a = app();
    data(
        &mut a,
        Kind::Sudo,
        Payload::Sudo(crate::remote::SudoMode::Password),
    );
    key(&mut a, KeyCode::Char('B'));
    key(&mut a, KeyCode::Char('y'));
    let (cmd, _) = a
        .take_suspend()
        .expect("hands over the terminal for the password");
    assert!(cmd.remote_line().ends_with("sudo systemctl reboot"));
    // ssh drops (255) as the server goes down: that's the reboot, so wait for it.
    a.after_suspend(Ok(std::process::ExitStatus::from_raw(255 << 8)));
    assert!(render_to_string(&mut a, 158, 41).contains("waiting for myserver to come back"));
    // A wrong password (sudo exits 1) isn't a reboot.
    key(&mut a, KeyCode::Char('B'));
    key(&mut a, KeyCode::Char('y'));
    a.take_suspend().unwrap();
    a.after_suspend(Ok(std::process::ExitStatus::from_raw(1 << 8)));
    assert!(render_to_string(&mut a, 158, 41).contains("reboot didn't start (exit 1)"));
}

/// Read-only against the real server: start a workflow, let its auto steps run, stop at the
/// first step that needs Enter (never pressed), print it, abandon. Use a scratch
/// XDG_DATA_HOME so the run stays out of the real one:
/// `SENTRY_SERVER_LIVE=<name> SENTRY_WORKFLOW=<wf> XDG_DATA_HOME=<scratch> cargo test live_preflight -- --ignored --nocapture`
#[test]
#[ignore]
fn live_preflight() {
    sentry_core::paths::use_real_dirs();
    let (Ok(name), Ok(wf)) = (
        std::env::var("SENTRY_SERVER_LIVE"),
        std::env::var("SENTRY_WORKFLOW"),
    ) else {
        return;
    };
    let (file, _) = crate::config::load().unwrap();
    let (n, s) = crate::config::pick(&file, Some(&name)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new(n, s), tx);
    a.start(Instant::now());
    a.apply(
        vec![super::app::Effect::Wf(super::app::WfCmd::Begin(wf))],
        Instant::now(),
    );
    let until = Instant::now() + std::time::Duration::from_secs(60);
    while Instant::now() < until {
        if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(100)) {
            a.on_event(ev, Instant::now());
        }
        a.tick(Instant::now());
        let w = a.wf.as_ref().expect("started");
        if w.live.is_none() && !matches!(w.next, sentry_core::workflows::runner::Next::Run(_)) {
            break;
        }
    }
    println!("{}", render_to_string(&mut a, 158, 41));
    assert!(a.take_suspend().is_none(), "nothing handed over");
    a.apply(
        vec![super::app::Effect::Wf(super::app::WfCmd::Abandon)],
        Instant::now(),
    );
}

/// Against a disposable sshd whose sudo asks for a password: `I` reads what needs root once,
/// and Containers then shows it (with its age) although `sudo -n docker` is refused. Run under
/// a pty that types the password:
/// `SENTRY_SSH_CONFIG=… SENTRY_SERVER_SCRATCH=<name> XDG_*=scratch cargo test live_inventory -- --ignored --nocapture`
#[test]
#[ignore]
fn live_inventory() {
    sentry_core::paths::use_real_dirs();
    let Ok(name) = std::env::var("SENTRY_SERVER_SCRATCH") else {
        return;
    };
    let (file, _) = crate::config::load().unwrap();
    let (n, s) = crate::config::pick(&file, Some(&name)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new(n, s), tx);
    a.start(Instant::now());
    let pump = |a: &mut App, secs: u64| {
        let until = Instant::now() + std::time::Duration::from_secs(secs);
        while Instant::now() < until {
            if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(100)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
        }
    };
    key(&mut a, KeyCode::Char(ScreenId::Cont.key()));
    pump(&mut a, 3);
    let before = render_to_string(&mut a, 158, 41);
    println!("{before}");
    assert!(
        before.contains("can't be read in the background"),
        "refused before"
    );
    key(&mut a, KeyCode::Char('I'));
    let s = render_to_string(&mut a, 158, 41);
    println!("{s}");
    assert!(s.contains("docker inspect $ids") && s.contains("cat /srv/stack/compose.yaml"));
    key(&mut a, KeyCode::Char('y'));
    let (cmd, _) = a.take_suspend().expect("hands over the terminal");
    let st = cmd.interactive();
    a.after_suspend(st);
    pump(&mut a, 3);
    let s = render_to_string(&mut a, 158, 41);
    println!("{s}");
    assert!(
        s.contains("read with sudo") && s.contains("│ web"),
        "containers from the read"
    );
    let inv = crate::inventory::load("scratch").unwrap().data;
    assert!(
        inv.outputs["cat /srv/stack/compose.yaml"]
            .out
            .contains("example/web:1.2.3")
    );
    // A workflow condition never uses it: it must see the server as it is now.
    let plain = Remote::new("scratch", &a.remote.cfg);
    assert!(crate::collect::docker::collect(&plain).is_err());
    let left = a
        .remote
        .output(
            &a.remote
                .sh("ls -A ~/.cache/sentry-server 2>/dev/null || true"),
        )
        .unwrap();
    assert!(
        left.trim().is_empty(),
        "the read is deleted on the server: {left}"
    );
}

#[test]
fn maintenance_tab_plans_one_item_at_a_time() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    goto_item(&mut a, "web");
    let s = screen(&mut a);
    assert!(
        s.contains("security · 2 newer") && s.contains("⚠ v1.5.2"),
        "{s}"
    );
    assert!(s.contains("eol soon") && s.contains("to retire"), "{s}");
    assert!(
        s.contains("Held because") && s.contains("1.5 migrates the database"),
        "{s}"
    );
    // p: pick the version, then the workflow asks its vars with the item's values filled in.
    a.set_wf_entries(vec![sentry_core::workflows::Entry {
        name: "compose-bump".into(),
        path: "compose-bump.toml".into(),
        wf: sentry_core::workflows::parse(
            "name = \"compose-bump\"\ndescription = \"x\"\ndraft = true\n\
             [vars.service]\nprompt = \"Service\"\n[vars.image]\nprompt = \"Image\"\n\
             [[steps]]\nid = \"a\"\ntitle = \"a\"\nrun = \"echo {{ service }} {{ image }}\"\n",
        ),
        issues: Vec::new(),
    }]);
    key(&mut a, KeyCode::Char('p'));
    let s = screen(&mut a);
    assert!(
        s.contains("Plan: move web from 1.4.2 to")
            && s.contains("1  let Claude recommend a version"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('2'));
    assert!(screen(&mut a).contains("plan web → 1.5.2 · a note (optional): ▏"));
    for c in "after Saturday's backup".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    // A plan of its own, not Ask Claude: the box says what Claude will do and where it's saved.
    let s = screen(&mut a);
    assert!(
        s.contains("Plan web with Claude") && s.contains("plans/web.md"),
        "{s}"
    );
    assert!(!s.contains("Ask Claude"), "{s}");
    key(&mut a, KeyCode::Char('y'));
    // The Plan view opens while Claude writes; no chat.
    assert!(a.chat_mut().is_none());
    let s = screen(&mut a);
    assert!(
        s.contains(" Plan ") && s.contains("Claude is writing it"),
        "{s}"
    );
    assert!(
        s.contains("1.4.2 → 1.5.2") && s.contains("compose-bump"),
        "{s}"
    );
    a.writer_answered(
        "I'll read the notes first.\nTARGET: v1.5.1\n# Plan: web 1.4.2 → 1.5.1\n\n## Assessment\n1.5.2 regresses the export; 1.5.1 has the fix.\n\n## Before\n```sh\nsudo true\n```",
    );
    let s = screen(&mut a);
    assert!(
        s.contains("ready to apply") && s.contains("1.4.2 → 1.5.1"),
        "Claude's TARGET wins: {s}"
    );
    assert!(
        s.contains("Assessment") && s.contains("│ sudo true"),
        "rendered as a document: {s}"
    );
    assert!(
        !s.contains("I'll read the notes first") && !s.contains("TARGET"),
        "{s}"
    );
    assert!(s.contains("note: after Saturday's backup"), "{s}");
    // Back to the list: the item says planned; p says a plan exists, P plans again.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('p'));
    let s = screen(&mut a);
    assert!(
        s.contains("web already has a plan (→ 1.5.1 · ready): Enter opens it · P plans again"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('P'));
    assert!(screen(&mut a).contains("Plan: move web from 1.4.2 to"));
    key(&mut a, KeyCode::Esc);
    let s = screen(&mut a);
    assert!(
        s.contains("planned → 1.5.1")
            && s.contains("Plan: 1.4.2 → 1.5.1 with compose-bump · ready"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("ready to apply"));
    // A draft is for planning, not applying: the reviewed workflow, ready to start.
    a.set_wf_entries(vec![sentry_core::workflows::Entry {
        name: "compose-bump".into(),
        path: "compose-bump.toml".into(),
        wf: sentry_core::workflows::parse(
            "name = \"compose-bump\"\ndescription = \"x\"\n\
             [vars.service]\nprompt = \"Service\"\n[vars.image]\nprompt = \"Image\"\n\
             [[steps]]\nid = \"a\"\ntitle = \"a\"\nrun = \"echo {{ service }} {{ image }}\"\n",
        ),
        issues: Vec::new(),
    }]);
    // Enter in the plan applies it: an apply session, told the plan and its values.
    key(&mut a, KeyCode::Enter);
    let p = a.consent_text().expect("a session");
    assert!(
        p.contains("Claude's plan for it, written earlier (target 1.5.1")
            && p.contains("image = \"example/web:1.5.1\"")
            && p.contains("carry it out"),
        "{p}"
    );
    key(&mut a, KeyCode::Enter);
    // Claude's plan: the workflow, with the plan's values, which it asks with them filled in.
    a.apply_answer_for_test(
        "```sentry-apply\nsummary = \"bump web\"\n[[step]]\ntitle = \"Bump\"\n\
         workflow = \"compose-bump\"\nvars = { image = \"example/web:1.5.1\" }\n```",
    );
    let s = screen(&mut a);
    assert!(
        s.contains("workflow compose-bump (image=example/web:1.5.1)"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(
        s.contains("compose-bump 1/2 · Image (image): example/web:1.5.1▏"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(s.contains("Service (service): web▏"), "{s}");
    key(&mut a, KeyCode::Esc);
    // Its values dismissed, it never started: back in the session, Enter starts it again
    // (not an empty Run view that drops back to Maintenance).
    a.apply_session().unwrap().chat.hidden = false;
    let s = screen(&mut a);
    assert!(s.contains("compose-bump: waiting to start"), "{s}");
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(
        s.contains("compose-bump 1/2 · Image (image): example/web:1.5.1▏"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    // The session waits for the run; close it for now.
    a.apply_session().unwrap().chat.hidden = false;
    a.apply_session().unwrap().phase =
        sentry_core::apply::session::Phase::Settled(sentry_core::apply::session::End::Stopped);
    key(&mut a, KeyCode::Esc);
    // The plan stays until it's applied or dropped.
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    assert!(screen(&mut a).contains("planned → 1.5.1"));
    key(&mut a, KeyCode::Char('x'));
    key(&mut a, KeyCode::Char('y'));
    assert!(!screen(&mut a).contains("planned →"));
    // A plan Claude says to wait on can't be applied.
    a.store.plans.insert(
        "web".into(),
        crate::maint::plan::PlanDoc {
            head: crate::maint::plan::Head {
                item: "web".into(),
                workflow: "compose-bump".into(),
                status: crate::maint::plan::PlanStatus::Wait,
                ..Default::default()
            },
            body: "# Plan\nNot until 1.5.3.".into(),
        },
    );
    assert!(screen(&mut a).contains("plan: wait"));
    goto_item(&mut a, "web");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("Claude advises waiting: r revises it"));
    key(&mut a, KeyCode::Esc);
    // z offers later dates; A asks about the item among everything recommended.
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    key(&mut a, KeyCode::Char('z'));
    assert!(screen(&mut a).contains("in 30 days ("));
    key(&mut a, KeyCode::Esc);
    // A: 2 asks about the item among everything recommended; 1 applies it with Claude, told
    // its standing and its workflow.
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Char('2'));
    let prompt = a.consent_text().expect("consent");
    assert!(
        prompt.contains("recommends maintaining") && prompt.contains("About \"web\""),
        "{prompt}"
    );
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Char('1'));
    let prompt = a.consent_text().expect("consent");
    assert!(
        prompt.contains("Do this for me") && prompt.contains("compose-bump"),
        "{prompt}"
    );
}

#[test]
fn recommendations_come_first_and_enter_does_what_they_say() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    let s = screen(&mut a);
    assert!(s.contains("Recommended ·"), "{s}");
    assert!(s.contains("soon     os: end of life soon"), "{s}");
    assert!(s.contains("tidy     Track cache"), "{s}");
    // Security updates are 'now', first; Enter starts the workflow that applies them.
    assert!(s.contains("now      4 package update(s) waiting, 1"), "{s}");
    assert!(
        s.contains("Enter: start apt-maintenance"),
        "the first row is selected: {s}"
    );
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("Start apt-maintenance on myserver"));
    key(&mut a, KeyCode::Esc);
    // z puts one off.
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    key(&mut a, KeyCode::Char('z'));
    assert!(screen(&mut a).contains("in 7 days ("));
    key(&mut a, KeyCode::Esc);
    // A tidy one: Track.
    let reached = (0..20).any(|_| {
        let here = screen(&mut a).contains("Enter: track it");
        if !here {
            key(&mut a, KeyCode::Char('j'));
        }
        here
    });
    assert!(reached, "reached the Track row");
}

/// The app with apt-maintenance due every 30 days (`maintenance.cadence` in the config).
fn app_with_cadence() -> App {
    let mut a = app();
    std::sync::Arc::make_mut(&mut a.remote.cfg)
        .maintenance
        .cadence
        .insert("apt-maintenance".into(), "30d".parse().unwrap());
    a
}

fn type_over(a: &mut App, text: &str) {
    for _ in 0..8 {
        key(a, KeyCode::Backspace);
    }
    for c in text.chars() {
        key(a, KeyCode::Char(c));
    }
    key(a, KeyCode::Enter);
}

#[test]
fn e_on_a_cadence_asks_how_often() {
    let mut a = app_with_cadence();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    a.apply(
        vec![super::app::Effect::MaintFind(
            "task:cadence-apt-maintenance".into(),
        )],
        Instant::now(),
    );
    let s = screen(&mut a);
    assert!(s.contains("e  every"), "the row takes e: {s}");
    assert!(s.contains("every 30d · from config"), "{s}");
    // e: asked in the key bar, as in sentry (not an editor), with what it is now.
    key(&mut a, KeyCode::Char('e'));
    let s = screen(&mut a);
    assert!(
        s.contains("cadence-apt-maintenance · every (e.g. 30d, 90d, off): 30d"),
        "{s}"
    );
    type_over(&mut a, "soon");
    assert!(screen(&mut a).contains("bad number"), "not a cadence");
    key(&mut a, KeyCode::Char('e'));
    type_over(&mut a, "45d");
    let s = screen(&mut a);
    assert!(s.contains("every 45d (tasks.toml)"), "the toast: {s}");
    assert!(
        s.contains("every 45d · from tasks.toml"),
        "tasks.toml's takes the config's place: {s}"
    );
    // A review is told the cadence that applies.
    key(&mut a, KeyCode::Char('R'));
    let p = a.consent_text_any().expect("the request");
    assert!(p.contains("apt-maintenance every 45 day(s)"), "{p}");
    key(&mut a, KeyCode::Esc);
    // From Records › Tasks too; off takes it off the list.
    colon(&mut a, "tasks");
    key(&mut a, KeyCode::Char('e'));
    let s = screen(&mut a);
    assert!(s.contains("every (e.g. 30d, 90d, off): 45d"), "{s}");
    type_over(&mut a, "off");
    let s = screen(&mut a);
    assert!(s.contains("is off (tasks.toml)"), "{s}");
    assert!(!s.contains("every 45d · from"), "off the list: {s}");
}

#[test]
fn a_review_can_change_a_cadence() {
    let mut a = app_with_cadence();
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    key(&mut a, KeyCode::Char('R'));
    let p = a.consent_text_any().expect("the request");
    assert!(p.contains("- cadence-apt-maintenance:"), "{p}");
    key(&mut a, KeyCode::Enter);
    a.writer_answered(
        "# Maintenance review · myserver\n\n## Routine\n- updates\n\n```sentry-changes\n\
         [[change]]\ntask = \"cadence-apt-maintenance\"\nevery = \"14d\"\n\
         why = \"Security updates pile up.\"\n```",
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("every 30d → every 14d"), "{s}");
    key(&mut a, KeyCode::Enter);
    let t = a
        .store
        .tasks
        .iter()
        .find(|t| t.id == "cadence-apt-maintenance")
        .expect("written to tasks.toml");
    assert_eq!(t.every, Some("14d".parse().unwrap()));
}

#[test]
fn later_is_7_30_90_on_every_row() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    let same = |s: &str| {
        for has in [
            "Look again later",
            "1  in 7 days (",
            "2  in 30 days (",
            "3  in 90 days (",
            "it leaves the list until then",
        ] {
            assert!(s.contains(has), "{has} not in: {s}");
        }
        assert!(!s.contains("180"), "{s}");
    };
    // On a recommendation, and on an item (its date is its review date).
    key(&mut a, KeyCode::Char('z'));
    same(&screen(&mut a));
    key(&mut a, KeyCode::Esc);
    goto_item(&mut a, "engine");
    key(&mut a, KeyCode::Char('z'));
    let s = screen(&mut a);
    same(&s);
    assert!(s.contains("Review engine later"), "{s}");
}

#[test]
fn capital_b_expects_everything_like_it() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    a.apply(
        vec![super::app::Effect::MaintFind(
            "finding:srv:container-down".into(),
        )],
        Instant::now(),
    );
    let s = screen(&mut a);
    assert!(s.contains("container db is exited"), "{s}");
    assert!(s.contains("B  all like it"), "a finding takes B: {s}");
    key(&mut a, KeyCode::Char('B'));
    let s = screen(&mut a);
    assert!(
        s.contains("Baseline pattern")
            && s.contains("Treat every container-down finding as expected?"),
        "{s}"
    );
    assert!(
        s.contains("myserver.baseline.toml ← srv:container-down:*"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(s.contains("marked expected"), "{s}");
    assert!(
        !s.contains("now      container db is exited"),
        "every container-down finding left the list: {s}"
    );
    assert!(
        s.contains("backup.service is failed"),
        "the others stay: {s}"
    );
    // The key is in ? with the other row keys.
    key(&mut a, KeyCode::Char('?'));
    let s = screen(&mut a);
    assert!(
        s.contains("the audit report") && s.contains("the workflows (0)"),
        "{s}"
    );
    assert!(s.contains("edit server_config.yaml (on an item)"), "{s}");
}

#[test]
fn enter_on_an_item_plans_it_or_opens_its_log() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    // Nothing newer, no plan: Enter opens what was done to it.
    goto_item(&mut a, "os");
    let s = screen(&mut a);
    assert!(s.contains("Enter  its log"), "{s}");
    assert!(
        s.contains("Enter opens its log · p: Claude plans it"),
        "{s}"
    );
    // x has nothing to dismiss here, and says so as sentry does.
    key(&mut a, KeyCode::Char('x'));
    assert!(screen(&mut a).contains("only findings can be marked expected"));
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(
        s.contains("Records") && s.contains("Maintenance log"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    // Newer versions: Enter plans it (what p does).
    goto_item(&mut a, "web");
    let s = screen(&mut a);
    assert!(s.contains("Enter  plan"), "{s}");
    assert!(s.contains("Enter: Claude plans it"), "{s}");
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(s.contains("Plan: move web from 1.4.2 to"), "{s}");
    key(&mut a, KeyCode::Esc);
    // To retire: planned too.
    goto_item(&mut a, "legacy");
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("plan legacy → retire · a note"));
}

/// The report on screen with one before it: a finding since gone, and one that's new.
fn two_reports(a: &mut App) {
    let cur = a.store.report.value.clone().flatten().expect("a report");
    let mut prev = cur.clone();
    let new = prev.findings.remove(0);
    prev.findings.push(sentry_core::finding::Finding {
        id: "srv:unit:old.service".into(),
        severity: sentry_core::finding::Sev::Medium,
        category: "units".into(),
        message: "old.service is failed".into(),
        ..Default::default()
    });
    assert!(!new.message.is_empty());
    data(
        a,
        Kind::Report,
        Payload::Reports(Box::new(crate::audit::Shown {
            names: vec!["2026-10-25-120000".into(), "2026-10-26-110000".into()],
            idx: 1,
            cur: Some(cur),
            prev: Some(prev),
        })),
    );
}

#[test]
fn f_opens_the_audit_report_and_esc_comes_back() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    two_reports(&mut a);
    key(&mut a, KeyCode::Char('F'));
    let s = screen(&mut a);
    insta::assert_snapshot!("server_audit_report_158x41", body(&s));
    for has in [
        "Maintenance › Audit report",
        "Findings · 2026-10-26-110000 (2/2)",
        "Worth a look on this server.",
        "Changes · since the audit before",
        "Changed: 1 new, 1 gone",
        "old.service is failed",
        "Esc  back",
    ] {
        assert!(s.contains(has), "{has} not in: {s}");
    }
    // x on the first (the container that's down): expected, and the list follows at once.
    assert!(s.contains("check  container container db is exited"), "{s}");
    key(&mut a, KeyCode::Char('x'));
    let s = screen(&mut a);
    assert!(s.contains("ok     container container db is exited"), "{s}");
    assert!(s.contains("marked expected"), "{s}");
    assert!(s.contains("3 to check"), "one fewer: {s}");
    // Taken back (x on it does the same).
    let id = a
        .store
        .shown
        .as_ref()
        .and_then(|sh| sh.cur.as_ref())
        .and_then(|r| {
            r.findings
                .iter()
                .find(|f| f.message.starts_with("container db"))
        })
        .map(|f| f.id.clone())
        .unwrap();
    a.apply(
        vec![super::app::Effect::Expected(id, false)],
        Instant::now(),
    );
    let s = screen(&mut a);
    assert!(s.contains("check  container container db is exited"), "{s}");
    // B asks about everything like the one selected.
    key(&mut a, KeyCode::Char('B'));
    assert!(screen(&mut a).contains("Baseline pattern"));
    key(&mut a, KeyCode::Esc);
    // Narrow: one pane at a time.
    let s = render_to_string(&mut a, 100, 30);
    assert!(s.contains("Findings ·") && !s.contains("Changes ·"), "{s}");
    // Esc: the list again; `:audit` opens the report from anywhere.
    key(&mut a, KeyCode::Esc);
    let s = screen(&mut a);
    assert!(
        s.contains("Recommended ·") && !s.contains("Audit report"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('1'));
    colon(&mut a, "audit");
    assert_eq!(a.screen, ScreenId::Maint);
    assert!(screen(&mut a).contains("Maintenance › Audit report"));
}

#[test]
fn leaving_maintenance_closes_the_report() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    key(&mut a, KeyCode::Char('F'));
    assert!(screen(&mut a).contains("Audit report"));
    // With no stored list of reports, the latest is shown on its own.
    assert!(screen(&mut a).contains("first report"));
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    let s = screen(&mut a);
    assert!(
        s.contains("Recommended ·") && !s.contains("Audit report"),
        "{s}"
    );
}

#[test]
fn later_takes_the_row_off_at_once() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    assert!(screen(&mut a).contains("4 package update(s) waiting"));
    key(&mut a, KeyCode::Char('z'));
    key(&mut a, KeyCode::Char('1'));
    let s = screen(&mut a);
    assert!(!s.contains("4 package update(s) waiting"), "{s}");
}

#[test]
fn the_writer_profile_adds_the_web_and_only_the_notes() {
    let r = Remote::new("myserver", &cfg());
    let p = super::ask::writer_profile(&r, "Debian 12", "6.1", None);
    assert!(p.tools.contains(&"WebFetch".to_string()));
    assert!(
        !p.denied.iter().any(|d| d.starts_with("Web")),
        "{:?}",
        p.denied
    );
    let plain = super::ask::profile(&r, "Debian 12", "6.1", None);
    assert!(
        plain.denied.contains(&"WebFetch".to_string()),
        "other asks stay offline"
    );
    let home = std::env::var("HOME").unwrap();
    assert!(
        p.allowed
            .contains(&format!("Read(/{home}/notes/runbook.md)")),
        "{:?}",
        p.allowed
    );
    assert_eq!(p.dirs, [format!("{home}/notes")]);
    assert!(
        p.allowed
            .contains(&"Bash(sentry-server exec myserver:*)".to_string())
    );
    assert!(
        !p.allowed
            .iter()
            .any(|a| a == "Read" || a.starts_with("Bash(ssh"))
    );
    assert_eq!(
        sentry_core::maint::read_rules(&["/srv/notes.md".into()]),
        ["Read(//srv/notes.md)"]
    );
}

#[test]
fn a_password_sudo_says_press_i() {
    // A store that never had docker: the tab explains, with the key to press.
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut b = App::new(Remote::new("myserver", &cfg()), tx);
    b.offline = true;
    data(
        &mut b,
        Kind::Sudo,
        Payload::Sudo(crate::remote::SudoMode::Password),
    );
    b.on_event(
        Ev::Data(
            Kind::Docker,
            Box::new(Err(crate::remote::SrvError::SudoPassword(
                "docker ps".into(),
            ))),
        ),
        Instant::now(),
    );
    key(&mut b, KeyCode::Char(ScreenId::Cont.key()));
    let s = render_to_string(&mut b, 158, 41);
    assert!(
        s.contains("Press  I  to read them once with your password"),
        "{s}"
    );
    assert!(s.contains(" I  read with sudo"), "key bar: {s}");
}

#[test]
fn claude_target_lines() {
    use crate::maint::plan::target;
    assert_eq!(
        target("TARGET: v0.64.2\nrest"),
        Some(Some("v0.64.2".into()))
    );
    assert_eq!(
        target("**TARGET:** `2.11.7-alpine`"),
        Some(Some("2.11.7-alpine".into()))
    );
    assert_eq!(target("## TARGET: wait"), Some(None));
    assert_eq!(target("no target here"), None);
}

/// Read-only against the real server: `p` on an item with Claude choosing the version; prints
/// the saved plan. Use a scratch XDG_CONFIG_HOME (a copy of the config) so the plan isn't
/// written to the real state file.
/// `SENTRY_SERVER_LIVE=<name> SENTRY_ITEM=<id> XDG_CONFIG_HOME=<copy> cargo test live_plan -- --ignored --nocapture`
#[test]
#[ignore]
fn live_plan() {
    sentry_core::paths::use_real_dirs();
    let (Ok(name), Ok(item)) = (
        std::env::var("SENTRY_SERVER_LIVE"),
        std::env::var("SENTRY_ITEM"),
    ) else {
        return;
    };
    let (file, _) = crate::config::load().unwrap();
    let (n, s) = crate::config::pick(&file, Some(&name)).unwrap();
    let pos = s
        .maintenance
        .items
        .iter()
        .position(|i| i.id == item)
        .expect("item");
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new(n, s), tx);
    a.start(Instant::now());
    let pump = |a: &mut App, secs: u64| {
        let until = Instant::now() + std::time::Duration::from_secs(secs);
        while Instant::now() < until {
            if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(100)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
        }
    };
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    pump(&mut a, 10);
    for _ in 0..pos {
        key(&mut a, KeyCode::Char('j'));
    }
    key(&mut a, KeyCode::Char('p'));
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('y'));
    assert!(
        a.chat_mut().is_none(),
        "written in the background, nothing opens"
    );
    // Leave the Plan view and move about meanwhile: it's still written and saved.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char(ScreenId::Dash.key()));
    let mut asked = false;
    for _ in 0..300 {
        pump(&mut a, 3);
        // Claude stopped for reads that need root: skip them here (no password in a test);
        // it then writes the plan without them.
        if let Some(reads) = a.take_reads_box() {
            println!("Claude asked to read with sudo first: {reads:?}");
            asked = true;
            key(&mut a, KeyCode::Char('n'));
            continue;
        }
        if !a.writing() && a.store.plans.contains_key(&item) {
            break;
        }
    }
    println!("asked for reads before writing: {asked}");
    pump(&mut a, 1);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    key(&mut a, KeyCode::Enter);
    println!("{}", render_to_string(&mut a, 158, 41));
    let plan = a.store.plans.get(&item).cloned().expect("a saved plan");
    let path = crate::maint::plan::path(&name, &item);
    println!(
        "{}\n{}",
        path.display(),
        std::fs::read_to_string(&path).expect("the .md")
    );
    assert!(
        plan.body.starts_with('#'),
        "the document, not Claude's narration"
    );
}

/// Against a disposable sshd whose sudo asks for a password: a read Claude makes that needs
/// root is queued by the gateway; after the turn the box lists it, one sudo runs it, and the
/// output goes back as the next message. (No claude process: the conversation is offline.)
/// `SENTRY_SSH_CONFIG=… SENTRY_SERVER_SCRATCH=<name> XDG_*=scratch cargo test live_claude_reads -- --ignored --nocapture`
#[test]
#[ignore]
fn live_claude_reads() {
    sentry_core::paths::use_real_dirs();
    let Ok(name) = std::env::var("SENTRY_SERVER_SCRATCH") else {
        return;
    };
    let (file, _) = crate::config::load().unwrap();
    let (n, s) = crate::config::pick(&file, Some(&name)).unwrap();
    let r = Remote::new(n, s);
    // What Claude runs: refused (sudo wants a password), so queued.
    let argv: Vec<String> = ["docker", "ps", "-aq"].map(String::from).to_vec();
    let code = crate::gateway::exec_cli(&r, &argv);
    assert_ne!(code, 0);
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut a = App::new(r, tx);
    a.open_chat(sentry_core::tui::chat::Chat::new(
        sentry_core::claude::Ask::new("s", "c", "q"),
    ));
    a.turn_ended_online_for_reads();
    let reads = a.take_reads_box().expect("the box lists the read");
    println!("{}", render_to_string(&mut a, 158, 41));
    assert_eq!(reads, [argv]);
    key(&mut a, KeyCode::Char('y'));
    let (cmd, _) = a.take_suspend().expect("hands over the terminal");
    let st = cmd.interactive();
    a.offline = true; // the follow-up is shown, not sent
    a.after_suspend(st);
    let sent = a
        .chat_mut()
        .unwrap()
        .entries
        .iter()
        .rev()
        .find(|(k, _)| *k == sentry_core::tui::chat::Kind::You)
        .map(|(_, t)| t.clone())
        .unwrap();
    println!("{sent}");
    assert!(sent.contains("$ sudo docker ps -aq   (exit 0)") && sent.contains("aaa111"));
}

#[test]
fn the_maintenance_log_can_be_reviewed() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    key(&mut a, KeyCode::Char('v'));
    let s = screen(&mut a);
    assert!(
        s.contains("Maintenance log") && s.contains("Nothing logged yet"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    assert!(a.rec_view.is_none());
    // With entries: the ledger as a list, the item's entries marked; Enter opens one.
    let entry = |text: &str| crate::maint::log::LogEntry::parse(text).unwrap();
    let web = entry(
        "+++\nserver = \"myserver\"\nitem = \"web\"\nkind = \"image\"\nworkflow = \"compose-bump\"\n\
         result = \"done\"\nfrom = \"1.4.2\"\nto = \"1.5.1\"\nended = \"2026-10-20T10:00:00Z\"\n\
         summary = \"health check slow; fine\"\ntags = [\"item:web\", \"result:done\"]\n+++\n\n\
         # web 1.4.2 → 1.5.1 · compose-bump · done\n\n## Summary\n\nhealth check slow; fine\n\n\
         ## Steps\n\n| # | Step | Result |\n|---|---|---|\n| 1 | Change the pin (`pin`) | ok |",
    );
    let apt = entry(
        "+++\nserver = \"myserver\"\nkind = \"system\"\nworkflow = \"apt-maintenance\"\n\
         result = \"abandoned\"\nended = \"2026-10-25T09:00:00Z\"\nsummary = \"mirror down\"\n+++\n\n# apt",
    );
    a.rec_view = Some(sentry_core::tui::records::Records::new(
        sentry_core::tui::records::Data {
            dir: "~/.config/sentry/servers/myserver".into(),
            tasks: Vec::new(),
            log: vec![apt, web],
            plans: Vec::new(),
            reviews: Vec::new(),
            later: Vec::new(),
            audited: None,
            now: "2026-10-26T12:00:00Z".parse().unwrap(),
        },
        sentry_core::tui::records::Section::Log,
        Some("web".into()),
    ));
    let s = screen(&mut a);
    assert!(s.contains("2 run(s)") && s.contains("mirror down"), "{s}");
    assert!(
        s.contains("● 2026-10-20 10:00") && s.contains("1.4.2 → 1.5.1"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(
        s.contains("2026-10-20-1000-web-compose-bump.md") && s.contains("item:web result:done"),
        "{s}"
    );
    assert!(
        s.contains("health check slow; fine") && s.contains("Change the pin"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    assert!(screen(&mut a).contains("2 run(s)"), "back to the list");
    key(&mut a, KeyCode::Esc);
    assert!(a.rec_view.is_none());
    // :log from anywhere.
    for c in ":log".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert!(a.rec_view.is_some());
    // Later: what's put off; u brings it back.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    key(&mut a, KeyCode::Char('z'));
    key(&mut a, KeyCode::Char('1'));
    assert!(!screen(&mut a).contains("4 package update(s) waiting"));
    for c in ":later".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(
        s.contains("put off") && s.contains("wf:apt-maintenance:updates"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('u'));
    key(&mut a, KeyCode::Esc);
    assert!(screen(&mut a).contains("4 package update(s) waiting"));
}

#[test]
fn a_read_from_before_the_last_change_says_so() {
    let mut a = app();
    data(
        &mut a,
        Kind::Sudo,
        Payload::Sudo(crate::remote::SudoMode::Password),
    );
    let t = |s: &str| -> jiff::Timestamp { s.parse().unwrap() };
    a.set_inventory_times(t("2026-10-26T10:00:00Z"), t("2026-10-26T11:00:00Z"));
    key(&mut a, KeyCode::Char(ScreenId::Cont.key()));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("before the last change: I reads again"), "{s}");
    a.set_inventory_times(t("2026-10-26T11:30:00Z"), t("2026-10-26T11:00:00Z"));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("read with sudo") && !s.contains("before the last change"),
        "{s}"
    );
}

#[test]
fn the_risk_is_coloured_only_where_something_needs_doing() {
    let mut a = app();
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    let backend = ratatui::backend::TestBackend::new(158, 41);
    let mut term = ratatui::Terminal::new(backend).unwrap();
    term.draw(|f| a.draw(f)).unwrap();
    let buf = term.backend().buffer().clone();
    let t = a.theme;
    let row_of = |item: &str| {
        (0..41)
            .find(|&y| {
                let line: String = (0..158).map(|x| buf[(x, y)].symbol()).collect();
                line.contains(&format!("│ {item} "))
            })
            .unwrap()
    };
    let risk_fg = |y: u16| {
        let x = (0..158)
            .find(|&x| {
                ["medium", "high"].iter().any(|w| {
                    (0..w.len() as u16)
                        .all(|i| buf[(x + i, y)].symbol() == &w[i as usize..i as usize + 1])
                })
            })
            .unwrap();
        buf[(x, y)].fg
    };
    // web: a security release → its risk in colour; engine: held, nothing due → dimmed.
    assert_eq!(risk_fg(row_of("web")), t.yellow, "medium, coloured");
    assert_eq!(risk_fg(row_of("engine")), t.dim, "held and not due: dim");
}

#[test]
fn claude_reviews_the_maintenance_and_it_is_kept() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    // R: the review window on its brief; nothing is sent before Enter.
    key(&mut a, KeyCode::Char('R'));
    let s = screen(&mut a);
    assert!(
        s.contains("Maintenance review") && s.contains("Enter starts the review"),
        "{s}"
    );
    let prompt = a.consent_text_any().expect("the request");
    assert!(
        prompt.contains("- web (medium risk): pinned 1.4.2"),
        "{prompt}"
    );
    assert!(
        prompt.contains("[soon] os: end of life soon"),
        "the rules' list too: {prompt}"
    );
    assert!(
        prompt.contains("## Now:") && prompt.contains("Maintenance ledger"),
        "{prompt}"
    );
    // What its changes may name: every task, row, item and what discovery found.
    for has in [
        "sentry-changes",
        "- web: medium risk; defined in server_config.yaml",
        "- image:cache: compose service cache",
        "`plan web`",
        "[[untrack]]",
    ] {
        assert!(prompt.contains(has), "{has} not in: {prompt}");
    }
    assert!(!prompt.contains("sentry-tasks") && !prompt.contains("## The list"));
    // A filter narrows the screen, not what Claude is told.
    key(&mut a, KeyCode::Esc);
    for c in "/engine".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('R'));
    assert!(
        a.consent_text_any()
            .unwrap()
            .contains("- web (medium risk): pinned 1.4.2")
    );
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(
        s.contains("Maintenance review") && s.contains("appears here"),
        "{s}"
    );
    a.writer_answered("Reading first.\n# Maintenance review · myserver\n\n## Now\n- web: plan 1.5.2 (security)\n\n## Soon\n- os: end of life");
    let s = screen(&mut a);
    assert!(
        s.contains("Now") && s.contains("web: plan 1.5.2 (security)"),
        "{s}"
    );
    assert!(!s.contains("Reading first"), "{s}");
    assert!(s.contains("no changes to the list"), "the toast: {s}");
    key(&mut a, KeyCode::Esc);
    // Every review is kept: Records › Reviews, Enter opens it.
    for c in ":reviews".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(s.contains("Records") && s.contains("Reviews 1"), "{s}");
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("web: plan 1.5.2"), "Enter opens it");
    // R there: the brief for a new one.
    key(&mut a, KeyCode::Char('R'));
    assert!(screen(&mut a).contains("Enter starts the review"));
}

#[test]
fn a_review_that_needs_root_reads_is_not_saved_until_they_are_back() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    key(&mut a, KeyCode::Char('R'));
    key(&mut a, KeyCode::Enter);
    a.writer_answered("READS PENDING\nwaiting for smartctl");
    assert!(a.review_for_test().is_none(), "that isn't a review");
    let s = screen(&mut a);
    assert!(!s.contains("READS PENDING"), "{s}");
    // The reads come back (or are skipped): the same session writes the review.
    a.apply(vec![super::app::Effect::ReadsSkipped], Instant::now());
    assert!(a.writing());
    a.writer_answered("# Maintenance review · myserver\n\n## Now\n- web");
    assert!(a.review_for_test().is_some());
    assert!(screen(&mut a).contains("- web"));
    // Asked again for a review, not a plan.
    let back = super::planview::reads_back("$ sudo smartctl", true);
    assert!(back.contains("review document") && !back.contains("TARGET"));
    assert!(super::planview::reads_skipped(true).contains("review document"));
    assert!(super::planview::reads_back("x", false).contains("TARGET"));
}

/// Read-only against the real server: every recommendation and what discovery found.
/// `SENTRY_SERVER_LIVE=<name> cargo test live_recommend -- --ignored --nocapture`
#[test]
#[ignore]
fn live_recommend() {
    sentry_core::paths::use_real_dirs();
    let Ok(name) = std::env::var("SENTRY_SERVER_LIVE") else {
        return;
    };
    let (file, _) = crate::config::load().unwrap();
    let (n, s) = crate::config::pick(&file, Some(&name)).unwrap();
    let r = Remote::new(n, s).with_inventory();
    let (_, _, found) = crate::collect::maint_read(&r);
    for c in &found.candidates {
        println!(
            "untracked: {} · {} · source {:?}",
            c.key, c.what, c.item.source
        );
    }
    for g in &found.gone {
        println!("gone: {} · {}", g.id, g.why);
    }
}

#[test]
fn audit_findings_are_recommendations() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    let s = screen(&mut a);
    // The fixture report's findings, by severity; its srv:maint:* ones aren't repeated.
    assert!(!s.contains("srv:maint:"), "{s}");
    let rows: Vec<&str> = s.lines().filter(|l| l.contains("│ now ")).collect();
    assert!(!rows.is_empty(), "high findings are 'now': {s}");
    // Walk to the first finding and open it.
    let mut found = false;
    for _ in 0..30 {
        if screen(&mut a).contains("Enter: ask Claude how to fix it") {
            found = true;
            break;
        }
        key(&mut a, KeyCode::Char('j'));
    }
    assert!(found, "a finding row");
    let s = screen(&mut a);
    assert!(
        s.contains("What it is") || s.contains("what") || s.contains("Why"),
        "its explanation: {s}"
    );
    key(&mut a, KeyCode::Enter);
    let prompt = a
        .consent_text()
        .expect("the fix question in the consent box");
    assert!(prompt.contains("Audit finding ("), "{prompt}");
    key(&mut a, KeyCode::Esc);
}

#[test]
fn w_goes_to_screen_0() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    // w on Maintenance: the workflows are a screen, not a chooser.
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    key(&mut a, KeyCode::Char('w'));
    assert_eq!(a.screen, ScreenId::Upgrade);
    let s = screen(&mut a);
    assert!(
        s.contains("Workflows") && s.contains("apt-maintenance") && !s.contains("pick one"),
        "{s}"
    );
    // :wf <name> goes there, selects it and does what Enter does.
    key(&mut a, KeyCode::Char('1'));
    colon(&mut a, "wf apt-maintenance");
    assert_eq!(a.screen, ScreenId::Upgrade);
    assert!(screen(&mut a).contains("Start apt-maintenance on myserver"));
    key(&mut a, KeyCode::Esc);
    // :wf alone, and the old names for the run, open the screen.
    for cmd in ["wf", "run", "workflows", "upgrade"] {
        key(&mut a, KeyCode::Char('1'));
        colon(&mut a, cmd);
        assert_eq!(a.screen, ScreenId::Upgrade, ":{cmd}");
    }
    colon(&mut a, "wf nope");
    assert!(screen(&mut a).contains("no workflow nope"));
}

#[test]
fn an_item_without_a_workflow_is_planned_then_applied_in_a_session() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    goto_item(&mut a, "engine");
    assert!(
        screen(&mut a).contains("Enter: Claude plans it (no workflow: you run its steps)"),
        "{}",
        screen(&mut a)
    );
    key(&mut a, KeyCode::Char('p'));
    // No newer releases known in the fixture, or a choice of them: either way a note next.
    let s = screen(&mut a);
    if s.contains("let Claude recommend a version") {
        key(&mut a, KeyCode::Char('1'));
    }
    let s = screen(&mut a);
    assert!(s.contains("plan engine"), "{s}");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('y'));
    a.writer_answered(
        "TARGET: 29.9.2\n# Plan: engine\n\n## Change\n```sh\nsudo apt-get install docker-ce\n```",
    );
    let s = screen(&mut a);
    assert!(s.contains("ready to apply"), "{s}");
    // Enter: no workflow applies it, so an apply session carries the plan out (you don't
    // run its steps yourself); done, the plan is closed.
    key(&mut a, KeyCode::Enter);
    let p = a.consent_text().expect("a session");
    assert!(
        p.contains("Claude's plan for it, written earlier") && p.contains("carry it out"),
        "{p}"
    );
    key(&mut a, KeyCode::Enter);
    a.apply_answer_for_test(
        "```sentry-apply\nsummary = \"engine\"\n[[step]]\ntitle = \"Install\"\n\
         run = \"sudo apt-get install docker-ce\"\n```",
    );
    key(&mut a, KeyCode::Enter);
    a.apply_exit_for_test(0); // sudo -n works
    a.apply_exit_for_test(0); // the step
    assert!(a.wf.is_none(), "no workflow started");
    a.apply_answer_for_test("```sentry-verdict\nstatus = \"done\"\nsummary = \"29.9.2\"\n```");
    assert!(!a.store.plans.contains_key("engine"), "the plan is closed");
}

#[test]
fn a_review_changes_tasks_and_items_with_one_enter() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    let s = screen(&mut a);
    assert!(s.contains("Track cache") && s.contains("legacy"), "{s}");
    key(&mut a, KeyCode::Char('R'));
    key(&mut a, KeyCode::Enter);
    a.writer_answered(
        "# Maintenance review · myserver\n\n## Now\n- web\n\n```sentry-changes\n\
         [[add]]\nid = \"web-next\"\ntitle = \"Plan web to 1.5.2\"\nwhy = \"Security fix.\"\n\
         level = \"now\"\ndo = \"plan web\"\nitem = \"web\"\n\n\
         [[add]]\nid = \"restore-test\"\ntitle = \"Test a backup restore\"\nwhy = \"Never tried.\"\n\
         level = \"soon\"\nevery = \"180d\"\ndo = \"by-hand\"\nsteps = \"Restore last night's dump to a scratch dir.\"\n\n\
         [[add]]\nid = \"extra\"\ntitle = \"Something else\"\nlevel = \"tidy\"\ndo = \"by-hand\"\n\n\
         [[track]]\nkey = \"image:cache\"\nrisk = \"low\"\nwhy = \"Unpinned and unwatched.\"\n\n\
         [[untrack]]\nitem = \"legacy\"\nwhy = \"Its replacement has run for months.\"\n\n\
         [[item]]\nid = \"web\"\nrisk = \"high\"\nwhy = \"1.5 can't be undone.\"\n\n\
         [[later]]\nkey = \"os\"\nuntil = 2099-01-01\nwhy = \"Nothing to do before the next release.\"\n\n\
         [[ignore]]\nkey = \"image:nope\"\nwhy = \"Not there.\"\n```",
    );
    let s = screen(&mut a);
    let shown: Vec<&str> = s
        .lines()
        .skip(1)
        .filter(|l| !l.contains("/reviews/") && !l.contains("Maintenance review   "))
        .collect();
    insta::assert_snapshot!("server_review_158x41", shown.join("\n"));
    assert!(s.contains("7 changes · Enter applies the 7 ticked"), "{s}");
    for has in [
        "Remove",
        "stop tracking",
        "Add",
        "Test a backup restore · every 180d",
        "compose service cache",
        "Change",
        "risk high",
        "Put off",
        "until 2099-01-01",
        "not used: ignore image:nope: discovery found no such thing",
    ] {
        assert!(s.contains(has), "{has} not in: {s}");
    }
    // Untick the task nobody wants (the fourth row), then one Enter for the rest.
    for _ in 0..3 {
        key(&mut a, KeyCode::Char('j'));
    }
    key(&mut a, KeyCode::Char(' '));
    assert!(screen(&mut a).contains("Enter applies the 6 ticked"));
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(s.contains("6 applied · 1 skipped"), "{s}");
    let log = &a.store.log[0];
    assert_eq!(log.head.kind, "review");
    assert!(
        log.body.contains("applied: add track image:cache")
            && log.body.contains("applied: remove item legacy")
            && log.body.contains("skipped: add task extra"),
        "{}",
        log.body
    );
    key(&mut a, KeyCode::Esc);
    // Maintenance: both tasks, cache tracked, legacy gone, web high risk, os put off.
    let s = screen(&mut a);
    assert!(
        s.contains("Plan web to 1.5.2") && s.contains("Test a backup restore"),
        "{s}"
    );
    assert!(!s.contains("Something else"), "skipped: {s}");
    assert!(!s.contains("Track cache"), "tracked now: {s}");
    assert!(!s.contains("legacy"), "untracked: {s}");
    assert!(!s.contains("os: end of life soon"), "put off: {s}");
    let cfg = &a.remote.cfg.maintenance.items;
    let ids: Vec<&str> = cfg.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids, ["web", "engine", "os", "cache"]);
    assert_eq!(cfg[0].risk, crate::config::Risk::High);
    assert_eq!(cfg[3].risk, crate::config::Risk::Low);
    // R again: nothing left to apply, so the brief for a new review.
    key(&mut a, KeyCode::Char('R'));
    assert!(screen(&mut a).contains("Enter starts the review"));
    key(&mut a, KeyCode::Esc);
    a.apply(
        vec![super::app::Effect::MaintFind("task:restore".into())],
        Instant::now(),
    );
    let s = screen(&mut a);
    assert!(s.contains("Restore last night's dump"), "the steps: {s}");
    // d: logged as done by hand, then the note box; it leaves the list.
    key(&mut a, KeyCode::Char('d'));
    let s = screen(&mut a);
    assert!(
        s.contains("restore-test done · for the maintenance log"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    let s = screen(&mut a);
    assert!(
        !s.contains("soon     Test a backup restore"),
        "done for 180 days: {s}"
    );
}

#[test]
fn files_claude_was_refused_can_be_granted_for_the_conversation() {
    use sentry_core::claude::{Ask, Event};
    use sentry_core::tui::chat::Chat;
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    let notes = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
    let key_file = format!("{}/.ssh/id_ed25519", sentry_core::paths::home().display());
    let mut c = Chat::new(Ask::new("myserver", "ctx", "q"));
    c.begin_turn("q", 1, 1);
    for (tool, path, how) in [
        ("Read", &notes, "read from"),
        ("Read", &key_file, "read from"),
    ] {
        c.on_event(Event::ToolUse {
            name: tool.into(),
            input: path.clone(),
        });
        c.on_event(Event::ToolResult {
            summary: format!("denied: Claude requested permissions to {how} {path}, but no."),
            is_error: true,
        });
    }
    c.on_exit(0);
    a.open_chat(c);
    let s = screen(&mut a);
    assert!(
        s.contains("Enter allows it") && s.contains("grant files"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('g'));
    let s = screen(&mut a);
    assert!(
        s.contains("Grant files to Claude") && s.contains("Cargo.toml"),
        "{s}"
    );
    assert!(s.contains("not granted: keys and"), "{s}");
    key(&mut a, KeyCode::Char('y'));
    // The grantable one is granted, and Claude is told (offline: nothing is sent).
    let c = a.chat_for_test().expect("chat");
    assert_eq!(c.grants.len(), 1);
    assert!(c.grants[0].path.ends_with("Cargo.toml"));
    assert!(
        c.entries
            .iter()
            .any(|(_, t)| t.starts_with("I've granted you: read")),
        "{:?}",
        c.entries
    );
}

#[test]
fn applying_on_a_server_is_one_session() {
    use sentry_core::apply::session::Phase;
    use sentry_core::claude::{Apply, Ask};
    let dir = sentry_core::paths::home().join(".cache/sentry-applyplan-srvtest");
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join(format!("notes-{}.md", std::process::id()));
    std::fs::write(&f, "web runs 1.4.2\n").unwrap();
    let file = f.display().to_string();
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    a.apply(
        vec![super::app::Effect::AskConsent(Box::new(Ask::apply(
            "web",
            "ctx",
            Apply {
                key: "web".into(),
                item: Some("web".into()),
                remote: true,
                ..Default::default()
            },
        )))],
        Instant::now(),
    );
    let s = screen(&mut a);
    assert!(
        s.contains("Sent to Claude") && s.contains("sentry-server exec"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    // An edit of the server's /etc isn't for here: back to Claude by itself.
    a.apply_answer_for_test(
        "```sentry-apply\nsummary = \"x\"\n[[step]]\ntitle = \"t\"\nedit = \"/etc/hosts\"\nold = \"a\"\nnew = \"b\"\n```",
    );
    assert!(screen(&mut a).contains("Claude is correcting the plan"));
    // The notes here, a sudo command there: the password is asked inline.
    a.apply_answer_for_test(&format!(
        "Notes are stale.\n```sentry-apply\nsummary = \"Update the notes\"\nrollback = \"backup\"\n\
         [[step]]\ntitle = \"The version\"\nedit = \"{file}\"\nold = \"1.4.2\"\nnew = \"1.5.1\"\n\n\
         [[step]]\ntitle = \"Restart\"\nrun = \"sudo systemctl restart app\"\n```\n"
    ));
    let s = screen(&mut a);
    assert!(
        s.contains("Plan: Update the notes") && s.contains("Enter applies these 2 steps"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    // sudo -n refuses (exit 1): the password line.
    a.apply_exit_for_test(1);
    for c in "pw".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    let s = screen(&mut a);
    assert!(s.contains("sudo password (for step 2) › ●●"), "{s}");
    key(&mut a, KeyCode::Enter);
    a.apply_exit_for_test(0);
    // The edit is done here; the restart runs there.
    assert_eq!(std::fs::read_to_string(&f).unwrap(), "web runs 1.5.1\n");
    a.apply_exit_for_test(0);
    assert!(screen(&mut a).contains("Claude is checking the result"));
    a.apply_answer_for_test(
        "```sentry-verdict\nstatus = \"done\"\nsummary = \"web notes match\"\n```",
    );
    let sess = a.apply_session().unwrap();
    assert_eq!(
        sess.phase,
        Phase::Settled(sentry_core::apply::session::End::Done)
    );
    assert!(sess.secret.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_workflow_that_wont_start_goes_back_to_claude() {
    use sentry_core::claude::{Apply, Ask};
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    let entry = |draft: &str| sentry_core::workflows::Entry {
        name: "maint-window".into(),
        path: "maint-window.toml".into(),
        wf: sentry_core::workflows::parse(&format!(
            "name = \"maint-window\"\ndescription = \"x\"\n{draft}\
             [[steps]]\nid = \"a\"\ntitle = \"a\"\nrun = \"true\"\n"
        )),
        issues: Vec::new(),
    };
    a.set_wf_entries(vec![entry("draft = true\n")]);
    a.apply(
        vec![super::app::Effect::AskConsent(Box::new(Ask::apply(
            "web",
            "ctx",
            Apply {
                key: "web".into(),
                remote: true,
                ..Default::default()
            },
        )))],
        Instant::now(),
    );
    key(&mut a, KeyCode::Enter);
    let plan = "```sentry-apply\nsummary = \"Web\"\n[[step]]\ntitle = \"Window\"\n\
                workflow = \"maint-window\"\n```";
    // A draft: the plan goes back to Claude before anything is approved.
    a.apply_answer_for_test(plan);
    let s = screen(&mut a);
    assert!(
        s.contains("can't use step 1 as written") && s.contains("Claude is correcting the plan"),
        "{s}"
    );
    // Not a draft when planned, but refused when it starts (here: still a draft after all):
    // the step fails with why and Claude hears it, instead of waiting for a run forever.
    a.set_wf_entries(vec![entry("")]);
    a.apply_answer_for_test(plan);
    assert!(screen(&mut a).contains("Enter applies"));
    a.set_wf_entries(vec![entry("draft = true\n")]);
    key(&mut a, KeyCode::Enter);
    let sess = a.apply_session().unwrap();
    assert_eq!(sess.waiting_workflow(), None);
    let s = screen(&mut a);
    assert!(s.contains("not started: maint-window.toml: draft"), "{s}");
    assert!(!s.contains("waiting to start"), "{s}");
}

#[test]
fn enter_on_a_task_done_by_hand_is_claude_m_its_steps() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    a.add_task_for_test(sentry_core::maint::tasks::Task {
        id: "ups".into(),
        title: "Check the UPS battery".into(),
        why: "It is old.".into(),
        level: sentry_core::maint::Level::Soon,
        every: None,
        act: "by-hand".into(),
        item: None,
        steps: "Run `upsc ups`.".into(),
        added: None,
        off: false,
        source: Default::default(),
        review: None,
        after: None,
    });
    key(&mut a, KeyCode::Char(ScreenId::Maint.key()));
    a.apply(
        vec![super::app::Effect::MaintFind("task:ups".into())],
        Instant::now(),
    );
    let s = screen(&mut a);
    assert!(s.contains("By hand: Enter works it out with Claude"), "{s}");
    key(&mut a, KeyCode::Enter);
    let p = a.consent_text().expect("Enter asks Claude");
    assert!(
        p.contains("Do this for me") && p.contains("Check the UPS battery"),
        "{p}"
    );
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('m'));
    assert!(screen(&mut a).contains("mark done"));
}

/// The names root sees, as `sudo ss -tulpn` (or the inventory read) gives them.
fn names(a: &mut App) {
    data(
        a,
        Kind::Listeners,
        Payload::Listeners(sentry_core::collectors::net::parse_listen(&fixture(
            "ss-tulpn.txt",
        ))),
    );
}

#[test]
fn network_badge_counts_new() {
    let mut a = app();
    let s = render_to_string(&mut a, 158, 41);
    // tcp and udp 443 on both families and tcp 8080: five nothing expects (22 is in
    // listeners:, 5432 is local, udp 68 a client).
    assert!(s.contains("3 Network 5"), "{s}");
    key(&mut a, KeyCode::Char('3'));
    assert_eq!(a.screen, ScreenId::Net);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Listening · ss -tulpn · 9 · 5 new"), "{s}");
    assert!(
        s.contains("Established · 3") && s.contains("198.51.100.23:40112"),
        "{s}"
    );
    for word in ["NEW", "baseline", "local", "client"] {
        assert!(s.contains(word), "{word}: {s}");
    }
    // A port a container publishes says so; its own user's process has its name.
    assert!(
        s.contains("container web") || s.contains("needs sudo: ss -tulpn"),
        "{s}"
    );
    assert!(s.contains("app (901)"), "{s}");
    // :network and :net come here; / filters like sentry's.
    key(&mut a, KeyCode::Char('1'));
    for c in ":net".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.screen, ScreenId::Net);
    for c in "/8080".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Listening · ss -tulpn · 1 · 1 new"), "{s}");
    // A asks about the selected socket; nothing is sent before Enter.
    key(&mut a, KeyCode::Char('A'));
    let p = a.consent_text().expect("the brief");
    assert!(
        p.contains("A listening socket on the server (ss -tulpn): tcp 0.0.0.0:8080")
            && p.contains("process: app (901)")
            && p.contains("new (not expected)"),
        "{p}"
    );
}

#[test]
fn names_come_from_the_inventory_read() {
    let mut a = app();
    key(&mut a, KeyCode::Char('3'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(!s.contains("sshd"), "{s}");
    names(&mut a);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("sshd (612)") && s.contains("postgres (1440)"),
        "{s}"
    );
    assert!(!s.contains("needs sudo"), "{s}");
    // sudo asks for a password and nothing was read with it yet: I reads them.
    let mut a = app();
    data(
        &mut a,
        Kind::Sudo,
        Payload::Sudo(crate::remote::SudoMode::Password),
    );
    key(&mut a, KeyCode::Char('3'));
    assert!(render_to_string(&mut a, 158, 41).contains("needs I"));
}

#[test]
fn b_marks_every_family_of_the_port_and_the_finding() {
    let mut a = app();
    names(&mut a);
    key(&mut a, KeyCode::Char('3'));
    for c in "/tcp".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    // Rows are sorted by proto, address, port: 0.0.0.0:22, 0.0.0.0:443 …
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('b'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("tcp 443: expected (baseline.toml)"), "{s}");
    // Both families, by the name root sees; the finding too. Nothing is written in tests.
    let b = &a.store.baseline;
    assert_eq!(
        b.listeners,
        ["0.0.0.0:443/docker-proxy", "[::]:443/docker-proxy"]
    );
    assert_eq!(b.findings, ["srv:listener:tcp:443"]);
    // A baseline entry is an address, a port and a process, not a protocol: docker-proxy's
    // udp 443 is covered with it, as in sentry.
    assert!(s.contains("3 Network 1"), "only 8080 is still new: {s}");
    // Without the name, the entry must still match once I shows it.
    let mut a = app();
    key(&mut a, KeyCode::Char('3'));
    for c in "/udp".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(a.store.baseline.listeners, ["0.0.0.0:443/*", "[::]:443/*"]);
    names(&mut a);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("3 Network 1"), "still expected with names: {s}");
    // A local or client socket has nothing to mark (the DHCP client's, the second row).
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('b'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("not reachable from outside"), "{s}");
}

#[test]
fn b_again_unmarks() {
    let mut a = app();
    key(&mut a, KeyCode::Char('3'));
    for c in "/8080".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(a.store.baseline.listeners, ["0.0.0.0:8080/app"]);
    assert!(render_to_string(&mut a, 158, 41).contains("baseline"));
    key(&mut a, KeyCode::Char('b'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("tcp 8080: no longer expected"), "{s}");
    assert!(a.store.baseline.listeners.is_empty() && a.store.baseline.findings.is_empty());
    assert!(s.contains("3 Network 5"), "{s}");
    // What server_config.yaml expects stays expected: it isn't rewritten.
    key(&mut a, KeyCode::Esc);
    for c in "/:22".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('b'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("still expected by server_config.yaml"), "{s}");
}

#[test]
fn sort_and_filter_match_sentry() {
    let mut a = app();
    key(&mut a, KeyCode::Char('2'));
    assert_eq!(a.screen, ScreenId::Proc);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("reading processes…"), "{s}");
    assert!(
        s.contains("C/M  sort cpu/mem") && s.contains("x  kill"),
        "sentry's keys: {s}"
    );
    feed_procs(&mut a);
    let s = render_to_string(&mut a, 158, 41);
    let rows = |s: &str| -> Vec<String> {
        s.lines()
            .skip(5)
            .filter(|l| l.trim_start().starts_with(|c: char| c.is_ascii_digit()))
            .map(|l| l.split_whitespace().next().unwrap().to_string())
            .collect()
    };
    // By CPU first: the app at 75% of a core, postgres at 5%; no kernel threads.
    assert!(s.contains("CPU% ▼"), "{s}");
    assert_eq!(rows(&s)[..2], ["901", "1440"], "{s}");
    assert!(s.contains("75.0") && !s.contains("kthreadd"), "{s}");
    // M: by memory; C (or P) back.
    key(&mut a, KeyCode::Char('M'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("MEM% ▼"), "{s}");
    assert_eq!(rows(&s)[..3], ["901", "1440", "733"], "{s}");
    key(&mut a, KeyCode::Char('P'));
    assert!(render_to_string(&mut a, 158, 41).contains("CPU% ▼"));
    // / filters on command, user and pid.
    for c in "/postgres".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert_eq!(rows(&s), ["1440", "1502"], "{s}");
    assert!(
        s.lines().nth(1).unwrap().contains("2 Processes /postgres"),
        "{s}"
    );
    // j moves within what's shown; A asks about that process, on the server.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('A'));
    let p = a.consent_text().expect("A asks about the process");
    assert!(
        p.contains("Server `myserver`")
            && p.contains("Process on the server")
            && p.contains("pid 1502"),
        "{p}"
    );
    assert!(p.contains("What is this process"), "{p}");
    key(&mut a, KeyCode::Esc);
    // ps missing: said, not an error dump.
    let mut a = app();
    key(&mut a, KeyCode::Char('2'));
    a.on_event(
        Ev::Data(
            Kind::Procs,
            Box::new(Err(crate::remote::SrvError::NotFound("ps".into()))),
        ),
        Instant::now(),
    );
    assert!(render_to_string(&mut a, 158, 41).contains("ps not found on myserver"));
}

#[test]
fn the_processes_sample_feeds_the_probe() {
    use super::screens::Screens;
    let mut a = app();
    let before = a.store.mem.0.len();
    feed_procs(&mut a);
    assert_eq!(
        a.store.mem.0.len(),
        before + 2,
        "the Dashboard's series keep going on this screen"
    );
    assert_eq!(a.store.login_uid, Some(1000));
    assert_eq!(a.store.procs.value.as_ref().map(Vec::len), Some(12));
    // One exec per sample, every 2 s, only while the screen is shown; the second after 1 s.
    let polls = Screens::polls(ScreenId::Proc, &a.remote.cfg);
    assert_eq!(polls.len(), 1);
    assert_eq!(
        (polls[0].kind, polls[0].every),
        (Kind::Procs, Some(std::time::Duration::from_secs(2)))
    );
    let now = Instant::now();
    a.enter(ScreenId::Proc, now);
    assert_eq!(a.polled_for_test(), [Kind::Procs]);
    assert_eq!(a.next_due(now), now + std::time::Duration::from_secs(1));
    a.enter(ScreenId::Cont, now);
    assert!(a.polled_for_test().is_empty());
}

/// A day and a half of records, every ten minutes, ending at the tests' clock.
fn history() -> sentry_core::tui::histview::HistData {
    use sentry_core::recorder::ring::{Header, Rec};
    let end = "2026-10-26T12:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    let recs: Vec<Rec> = (0..216i64)
        .map(|i| {
            let x = i as f32;
            Rec {
                ts: end - (215 - i) * 600,
                cpu: 20.0 + 15.0 * (x / 9.0).sin(),
                mem_gib: 11.0 + (x / 40.0).cos(),
                swap_gib: 0.25,
                rx: 400_000.0 + 300_000.0 * (x / 5.0).sin(),
                tx: 90_000.0,
                load1: 0.4,
                cpu_temp: 48.0 + 4.0 * (x / 9.0).sin(),
                gpu: f32::NAN,
                gpu_temp: f32::NAN,
                disk_pct: 41.0,
                top: Vec::new(),
            }
        })
        // Nobody sampled for four hours.
        .filter(|r| !(end - 10 * 3600..end - 6 * 3600).contains(&r.ts))
        .collect();
    sentry_core::tui::histview::HistData {
        header: Some(Header {
            capacity: crate::recorder::capacity(),
            written: recs.len() as u64,
            interval_s: crate::recorder::INTERVAL_S,
        }),
        recs,
        live: None,
        alerts: Vec::new(),
        bytes: 3_317_824,
    }
}

#[test]
fn the_screen_appears_with_the_ring() {
    let mut a = app();
    let strip = |a: &mut App| {
        render_to_string(a, 158, 41)
            .lines()
            .nth(1)
            .unwrap()
            .to_string()
    };
    assert!(!strip(&mut a).contains("History"), "nothing recorded yet");
    // Tab doesn't stop at a screen that isn't in the strip.
    key(&mut a, KeyCode::BackTab);
    assert_eq!(a.screen, ScreenId::Upgrade);
    // H opens it all the same, and says how to get data.
    key(&mut a, KeyCode::Char('H'));
    assert_eq!(a.screen, ScreenId::Hist);
    assert!(strip(&mut a).trim_end().ends_with("H History"));
    key(&mut a, KeyCode::Char('1'));
    assert!(!strip(&mut a).contains("History"));
    // Something was recorded: it's in the strip from then on, last as in sentry.
    data(&mut a, Kind::History, Payload::History(Box::new(history())));
    assert!(strip(&mut a).trim_end().ends_with("0 Upgrade   H History"));
    key(&mut a, KeyCode::BackTab);
    assert_eq!(a.screen, ScreenId::Hist);
    colon(&mut a, "dash");
    colon(&mut a, "hist");
    assert_eq!(a.screen, ScreenId::Hist);
    // Entering it reads the ring (from this machine's disk) and nothing else; nothing polls.
    use super::screens::Screens;
    let polls = Screens::polls(ScreenId::Hist, &a.remote.cfg);
    assert_eq!(polls.len(), 1);
    assert_eq!((polls[0].kind, polls[0].every), (Kind::History, None));
    // The tests sampled the server (three probes), and wrote no ring for it.
    assert!(!sentry_core::recorder::ring::path("myserver").exists());
}

#[test]
fn history_says_how_to_get_data_when_empty() {
    let mut a = app();
    key(&mut a, KeyCode::Char('H'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("No recorder data."), "{s}");
    assert!(
        s.contains("Open the Dashboard for a few seconds, or run `sentry-server record myserver`"),
        "{s}"
    );
    assert!(s.contains("It exits on Ctrl-C."), "{s}");
    assert!(
        s.contains("[ ]  window") && s.contains("←→  scrub") && s.contains("r  reload"),
        "sentry's keys: {s}"
    );
    key(&mut a, KeyCode::Char('A'));
    assert!(
        render_to_string(&mut a, 158, 41).contains("no recorder data"),
        "nothing to ask about"
    );
    // A ring with nothing in it yet reads the same.
    let mut empty = history();
    empty.recs.clear();
    data(&mut a, Kind::History, Payload::History(Box::new(empty)));
    assert!(render_to_string(&mut a, 158, 41).contains("No recorder data."));
}

#[test]
fn history_keys() {
    let mut a = app();
    key(&mut a, KeyCode::Char('H'));
    data(&mut a, Kind::History, Payload::History(Box::new(history())));
    for (w, h) in [(158, 41), (80, 24)] {
        let s = render_to_string(&mut a, w, h);
        assert!(s.contains("History") && !s.contains("too small"), "{s}");
        if w == 158 {
            insta::assert_snapshot!("server_history_158x41", body(&s));
        }
    }
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("last 24h · every 10s"), "{s}");
    assert!(
        s.contains("cpu %") && s.contains("mem GiB") && s.contains("disk /"),
        "{s}"
    );
    assert!(!s.contains("gpu %"), "no GPU was ever read: {s}");
    assert!(
        s.contains("○ recorded while the Dashboard or Processes is open")
            && s.contains("sentry-server record myserver to keep going"),
        "{s}"
    );
    assert!(
        !s.contains("alerts"),
        "a server has no recorder alerts: {s}"
    );
    // [ ] change the window, ← → scrub, as in sentry.
    key(&mut a, KeyCode::Char('['));
    assert!(render_to_string(&mut a, 158, 41).contains("last 6h"));
    key(&mut a, KeyCode::Left);
    assert!(render_to_string(&mut a, 158, 41).contains("last 6h until"));
    key(&mut a, KeyCode::Right);
    key(&mut a, KeyCode::Char(']'));
    key(&mut a, KeyCode::Char(']'));
    assert!(render_to_string(&mut a, 158, 41).contains("last 72h"));
    assert_eq!(
        a.screen,
        ScreenId::Hist,
        "the arrows aren't screen keys here"
    );
    // A recorder running for this server is named.
    let mut h = history();
    h.live = Some(sentry_core::recorder::Live {
        pid: 4242,
        interval_s: 10,
        started: 0,
    });
    data(&mut a, Kind::History, Payload::History(Box::new(h)));
    assert!(render_to_string(&mut a, 158, 41).contains("● recorder running (pid 4242, 10s)"));
    // A: the window's figures, and that gaps are times nobody sampled.
    key(&mut a, KeyCode::Char('A'));
    let p = a.consent_text().expect("A asks about the window");
    assert!(
        p.contains("Server `myserver`")
            && p.contains("only while it was open or recording")
            && p.contains("Anything unusual in this period?"),
        "{p}"
    );
}

/// The Processes screen with the fixture's processes, filtered to those matching `what`.
fn procs_on(a: &mut App, what: &str) {
    key(a, KeyCode::Char('2'));
    feed_procs(a);
    key(a, KeyCode::Char('/'));
    for c in what.chars() {
        key(a, KeyCode::Char(c));
    }
    key(a, KeyCode::Enter);
}

#[test]
fn kill_asks_first_and_shows_the_command() {
    let mut a = app();
    // One of the login user's own processes.
    procs_on(&mut a, "tail -f");
    key(&mut a, KeyCode::Char('x'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Kill process"), "{s}");
    assert!(
        s.contains("Send SIGTERM to 52100 tail -f /var/log/app/app.log?")
            && s.contains("owner admin"),
        "sentry's box: {s}"
    );
    assert!(
        s.contains("$ kill -TERM 52100") && s.contains("on myserver"),
        "{s}"
    );
    assert!(!s.contains("sudo"), "its own process needs none: {s}");
    assert!(!s.contains("hard to undo"), "{s}");
    assert!(
        s.contains("Enter  confirm") && s.contains("Esc  cancel"),
        "{s}"
    );
    // Esc: nothing ran.
    key(&mut a, KeyCode::Esc);
    assert!(!render_to_string(&mut a, 158, 41).contains("Kill process"));
    // Enter: streamed, and only if the pid is still that process.
    key(&mut a, KeyCode::Char('x'));
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Kill process"), "the run pane: {s}");
    let ran = a.pane_cmd_for_test().expect("it runs in the pane");
    assert!(
        ran.contains("/proc/52100/stat")
            && ran.contains("112333100")
            && ran.contains("process 52100 is gone")
            && ran.contains("kill -TERM 52100"),
        "{ran}"
    );
    assert!(!ran.contains("sudo"), "{ran}");
}

#[test]
fn kill_of_another_users_process_goes_through_sudo() {
    use crate::remote::SudoMode;
    let mut a = app();
    procs_on(&mut a, "checkpointer");
    // sudo without a password: streamed, with -n so it can't wait on a prompt.
    key(&mut a, KeyCode::Char('x'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Send SIGTERM to 1502") && s.contains("owner postgres"),
        "{s}"
    );
    assert!(s.contains("$ sudo kill -TERM 1502"), "{s}");
    assert!(!s.contains("handed over"), "{s}");
    key(&mut a, KeyCode::Enter);
    let ran = a.pane_cmd_for_test().expect("streamed");
    assert!(
        ran.contains("sudo -n kill -TERM 1502") && ran.contains("14100"),
        "{ran}"
    );
    key(&mut a, KeyCode::Esc);
    // sudo asks for a password: the terminal is handed over.
    let mut a = app();
    data(&mut a, Kind::Sudo, Payload::Sudo(SudoMode::Password));
    procs_on(&mut a, "checkpointer");
    key(&mut a, KeyCode::Char('x'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("$ sudo kill -TERM 1502") && s.contains("terminal is handed over"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    let (cmd, banner) = a.take_suspend().expect("suspends");
    assert!(
        cmd.remote_line().contains("sudo kill -TERM 1502")
            && !cmd.remote_line().contains("sudo -n"),
        "{}",
        cmd.remote_line()
    );
    assert!(banner.contains("kill 1502 on myserver"), "{banner}");
    // No sudo at all: said, nothing offered.
    data(&mut a, Kind::Sudo, Payload::Sudo(SudoMode::Absent));
    key(&mut a, KeyCode::Char('x'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("1502 is owned by postgres") && !s.contains("Kill process"),
        "{s}"
    );
}

#[test]
fn pid_1_is_refused() {
    let mut a = app();
    procs_on(&mut a, "/sbin/init");
    key(&mut a, KeyCode::Char('x'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("pid 1 is the server's init") && !s.contains("Kill process"),
        "{s}"
    );
    // The ssh session sentry-server itself is on: offered, in the hard-to-undo form.
    let mut a = app();
    procs_on(&mut a, "admin@notty");
    key(&mut a, KeyCode::Char('x'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Send SIGTERM to 52790")
            && s.contains("This is the connection sentry-server talks through")
            && s.contains("This is hard to undo."),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    // The ssh server above it too (root's: through sudo).
    let mut a = app();
    procs_on(&mut a, "[listener]");
    key(&mut a, KeyCode::Char('x'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("$ sudo kill -TERM 612") && s.contains("hard to undo"),
        "{s}"
    );
    // A process that went away since the sample: said, nothing offered.
    let mut a = app();
    procs_on(&mut a, "tail -f");
    a.store.proc_ticks.remove(&52100);
    key(&mut a, KeyCode::Char('x'));
    assert!(render_to_string(&mut a, 158, 41).contains("process 52100 is gone"));
}

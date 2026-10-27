//! Every tab rendered from synthetic data (no ssh), at the mockup size and the smallest.

use std::time::Instant;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::app::{App, render_to_string};
use super::data::{Kind, Payload};
use super::{Ev, Tab};
use crate::config::Dur;
use crate::server::audit;
use crate::server::collect::{self, apt, docker, fixture, health, probe, units};
use crate::server::config::{DiskRule, Server, TimerRule};
use crate::server::remote::Remote;

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
        actions: vec![crate::server::config::CustomAction {
            id: "backup-now".into(),
            title: "Run the backup now".into(),
            run: "systemctl start backup.service".into(),
            sudo: true,
            risky: false,
            undo: None,
        }],
        maintenance: crate::server::config::Maintenance {
            notes: vec!["~/notes/runbook.md".into()],
            items: maint_items(),
        },
        ..Default::default()
    }
}

fn maint_items() -> Vec<crate::server::config::MaintItem> {
    use crate::server::config::{ImageRef, MaintItem, Retire, Tier};
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
            tier: Tier::Red,
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
            tier: Tier::Red,
            ..Default::default()
        },
    ]
}

/// The maintenance data the tab shows: pins, a security release upstream, an end of life.
fn maint_payload() -> Payload {
    use crate::server::maint::local::Local;
    use crate::server::maint::upstream::{Eol, Lookups, Release, Upstream};
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
    let st = crate::server::maint::eval::evaluate(
        &maint_items(),
        &local,
        Some(&lk),
        &Default::default(),
        jiff::civil::date(2026, 10, 26),
    );
    Payload::Maint(st, local)
}

fn data(a: &mut App, k: Kind, p: Payload) {
    a.on_event(Ev::Data(k, Box::new(Ok(p))), Instant::now());
}

fn app() -> App {
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new("myserver", &cfg()), tx);
    a.offline = true;
    a.theme = crate::tui::theme::Theme::truecolor();
    a.now_override = Some("2026-10-26T12:00:00Z".parse().unwrap());
    data(
        &mut a,
        Kind::Sudo,
        Payload::Sudo(crate::server::remote::SudoMode::NoPasswd),
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
        Payload::Disks(crate::collectors::disk::parse(&fixture("findmnt.json")).unwrap()),
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
        Payload::Journal(collect::group_journal(crate::collectors::journal::parse(
            &fixture("journal.jsonl"),
        ))),
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
    let findings = audit::derive(&snap, &cfg(), None, &["srv:docker-sock:*".into()]);
    data(
        &mut a,
        Kind::Report,
        Payload::Report(Some(Box::new(audit::Report {
            snapshot: snap,
            findings,
        }))),
    );
    data(&mut a, Kind::Maint, maint_payload());
    a.set_wf_entries(
        crate::server::workflow::SEEDS
            .iter()
            .map(|(name, text)| crate::workflows::Entry {
                name: name.to_string(),
                path: std::path::PathBuf::from(format!("{name}.toml")),
                wf: crate::workflows::parse(text),
                issues: Vec::new(),
            })
            .collect(),
    );
    a
}

fn key(a: &mut App, c: KeyCode) {
    a.on_event(
        Ev::Key(KeyEvent::new(c, KeyModifiers::NONE)),
        Instant::now(),
    );
}

/// Drop the header line: it has no clock, but keep snapshots about the tabs.
fn body(s: &str) -> String {
    s.lines().skip(1).collect::<Vec<_>>().join("\n")
}

#[test]
fn every_tab_renders() {
    for tab in Tab::ALL {
        for (w, h) in [(158, 41), (80, 24)] {
            let mut a = app();
            key(&mut a, KeyCode::Char(tab.key()));
            assert_eq!(a.tab, tab);
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
    assert_eq!(a.tab, Tab::Updates, "first row: reboot → Updates");
}

#[test]
fn audit_details_and_expected() {
    let mut a = app();
    key(&mut a, KeyCode::Char('5'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("expected") && s.contains("can control docker"),
        "{s}"
    );
    assert!(
        s.contains("Not checked:") && s.contains("fail2ban: needs sudo"),
        "{s}"
    );
    // Enter opens the selected finding in a box; Esc closes it.
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("┌ containers"), "{s}");
    key(&mut a, KeyCode::Esc);
    assert!(!render_to_string(&mut a, 158, 41).contains("┌ containers"));
}

#[test]
fn tabs_and_badges() {
    let mut a = app();
    let s = render_to_string(&mut a, 158, 41);
    let tabs = s.lines().nth(1).unwrap();
    assert!(tabs.contains("2 Services 1"), "one failed unit: {tabs}");
    assert!(tabs.contains("3 Containers 1"), "db is down: {tabs}");
    assert!(tabs.contains("4 Updates 4 ↻"), "{tabs}");
    key(&mut a, KeyCode::Char('l'));
    assert_eq!(a.tab, Tab::Services);
    key(&mut a, KeyCode::Char('h'));
    key(&mut a, KeyCode::Char('h'));
    assert_eq!(a.tab, Tab::Workflows, "wraps around");
}

/// Against a real server: `SENTRY_SERVER_LIVE=<name> cargo test live_tabs -- --ignored --nocapture`.
/// Reads ~/.config/sentry/server_config.yaml; prints every tab; read-only.
#[test]
#[ignore]
fn live_tabs() {
    let Ok(name) = std::env::var("SENTRY_SERVER_LIVE") else {
        return;
    };
    let (file, _) = crate::server::config::load().unwrap();
    let (n, s) = crate::server::config::pick(&file, Some(&name)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new(n, s), tx);
    a.theme = crate::tui::theme::Theme::truecolor();
    a.start(Instant::now());
    for tab in Tab::ALL {
        a.enter(tab, Instant::now());
        let until = Instant::now()
            + std::time::Duration::from_secs(if tab == Tab::Overview { 6 } else { 4 });
        while Instant::now() < until {
            if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
        }
        println!("{}", render_to_string(&mut a, 158, 41));
    }
}

fn run_msg(a: &mut App, id: u64, m: crate::exec::StreamMsg) {
    a.on_event(Ev::Run(id, m), Instant::now());
}

#[test]
fn restart_asks_first_then_streams() {
    use crate::exec::StreamMsg;
    let mut a = app();
    key(&mut a, KeyCode::Char('2'));
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
        s.contains("Restart · running") && s.contains("$ sudo -n systemctl restart app.service"),
        "{s}"
    );
    assert!(s.contains("C-c  stop it"), "{s}");
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
    assert!(
        s.contains("Restart · done") && s.contains("restarted"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    assert!(!render_to_string(&mut a, 158, 41).contains("Restart ·"));
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
    use crate::exec::StreamMsg;
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
        Payload::Sudo(crate::server::remote::SudoMode::Password),
    );
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Char('U'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Install 4 update(s)") && s.contains("It also removes: oldpkg"),
        "{s}"
    );
    assert!(s.contains("terminal is handed over"), "{s}");
    key(&mut a, KeyCode::Char('y'));
    let (cmd, banner) = a.take_suspend().expect("suspends");
    assert!(
        cmd.remote_line()
            .contains("sudo env DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade")
    );
    assert!(!cmd.remote_line().contains("sudo -n"));
    assert!(banner.contains("Upgrade packages on myserver"));
    data(
        &mut a,
        Kind::Sudo,
        Payload::Sudo(crate::server::remote::SudoMode::Absent),
    );
    key(&mut a, KeyCode::Char('C'));
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
    key(&mut a, KeyCode::Char('3'));
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
    use crate::exec::StreamMsg;
    let Ok(name) = std::env::var("SENTRY_SERVER_SCRATCH") else {
        return;
    };
    let (file, _) = crate::server::config::load().unwrap();
    let (n, s) = crate::server::config::pick(&file, Some(&name)).unwrap();
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
    key(&mut a, KeyCode::Char('4'));
    pump(&mut a, 8);
    key(&mut a, KeyCode::Char('C'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("$ sudo apt-get update"), "{s}");
    key(&mut a, KeyCode::Char('y'));
    pump(&mut a, 40);
    let s = render_to_string(&mut a, 158, 41);
    println!("{s}");
    assert!(s.contains("Refresh package lists · done"), "{s}");
    // 3. A custom action without sudo.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('a'));
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char('y'));
    pump(&mut a, 3);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("hello from"), "{s}");
    println!("✓ actions ran: apt-get update, custom action");
}

/// apt-maintenance end to end on the disposable sshd container (never the real server).
/// Same environment as `live_actions`.
#[test]
#[ignore]
fn live_workflow() {
    let Ok(name) = std::env::var("SENTRY_SERVER_SCRATCH") else {
        return;
    };
    let (file, _) = crate::server::config::load().unwrap();
    let (n, s) = crate::server::config::pick(&file, Some(&name)).unwrap();
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
    key(&mut a, KeyCode::Char('0'));
    assert!(screen(&mut a).contains("apt-maintenance"));
    key(&mut a, KeyCode::Enter);
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
        use crate::workflows::runner::Next;
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
fn ask_claude_about_a_finding_and_run_its_proposal() {
    use crate::claude::Event as CEvent;
    use crate::exec::StreamMsg;
    let mut a = app();
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::Char('A'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Ask Claude") && s.contains("Audit finding (high"),
        "{s}"
    );
    assert!(s.contains("through `sentry-server exec`"), "{s}");
    key(&mut a, KeyCode::Char('y'));
    let c = a.chat_mut().expect("chat open");
    c.on_event(CEvent::Text(
        "**Commands**\n```bash\n# why: bring it back\nsudo docker start db\n```\n".into(),
    ));
    c.on_exit(0);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("run a proposed command"), "{s}");
    key(&mut a, KeyCode::Char('r'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("$ sudo docker start db") && s.contains("on myserver"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('y'));
    let id = a.chat_mut().unwrap().job.as_ref().unwrap().0;
    a.on_event(
        Ev::Run(
            id,
            StreamMsg::Line {
                stderr: false,
                text: "db".into(),
            },
        ),
        Instant::now(),
    );
    a.on_event(
        Ev::Run(
            id,
            StreamMsg::Exit {
                code: 0,
                elapsed: std::time::Duration::from_secs(1),
            },
        ),
        Instant::now(),
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("exit 0") && s.contains("s sends the output to Claude"),
        "{s}"
    );
    assert!(
        a.chat_mut()
            .unwrap()
            .offer
            .as_deref()
            .unwrap()
            .contains("$ sudo docker start db")
    );
}

#[test]
fn claude_gets_only_the_gateway() {
    let r = Remote::new("myserver", &cfg());
    let p = super::ask::profile(&r, "Debian 13", "6.12", None);
    assert_eq!(p.allowed, ["Bash(sentry-server exec myserver:*)"]);
    assert_eq!(p.tools, ["Bash"]);
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
    let Ok(name) = std::env::var("SENTRY_SERVER_LIVE") else {
        return;
    };
    let (file, _) = crate::server::config::load().unwrap();
    let (n, s) = crate::server::config::pick(&file, Some(&name)).unwrap();
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
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Char('y'));
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
    for c in ":aud".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    assert!(render_to_string(&mut a, 158, 41).contains(":aud▏"));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.tab, Tab::Audit, ":aud goes to Audit");
    for c in ":wf compose-update".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.tab, Tab::Workflows);
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
    key(&mut a, KeyCode::Char(Tab::Containers.key()));
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
    key(&mut a, KeyCode::Char(Tab::Audit.key()));
    assert!(!screen(&mut a).contains("Audit /"));
    key(&mut a, KeyCode::Char(Tab::Containers.key()));
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

/// Read-only against the real server: `A` on Updates and Workflows opens the consent box
/// (nothing is sent). `SENTRY_SERVER_LIVE=<name> cargo test live_ask_boxes -- --ignored --nocapture`
#[test]
#[ignore]
fn live_ask_boxes() {
    let Ok(name) = std::env::var("SENTRY_SERVER_LIVE") else {
        return;
    };
    let (file, _) = crate::server::config::load().unwrap();
    let (n, s) = crate::server::config::pick(&file, Some(&name)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new(n, s), tx);
    a.start(Instant::now());
    for tab in [Tab::Updates, Tab::Workflows] {
        let t0 = Instant::now();
        a.enter(tab, Instant::now());
        // Ask straight away (as you would), then again once the tab has loaded.
        key(&mut a, KeyCode::Char('A'));
        println!("{tab:?} at once:\n{}", render_to_string(&mut a, 158, 41));
        key(&mut a, KeyCode::Esc);
        while t0.elapsed() < std::time::Duration::from_secs(20) {
            if let Ok(ev) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
            if tab != Tab::Updates || a.store.apt.value.is_some() {
                break;
            }
        }
        println!("{tab:?} loaded after {:?}", t0.elapsed());
        key(&mut a, KeyCode::Char('A'));
        let s = render_to_string(&mut a, 158, 41);
        println!("{s}");
        assert!(s.contains("Ask Claude"), "{tab:?}: no consent box");
        key(&mut a, KeyCode::Esc);
    }
}

#[test]
fn workflow_vars_are_asked_before_it_starts() {
    let mut a = app();
    let text = "name = \"bump\"\ndescription = \"x\"\ndraft = true\n\
        [vars.service]\nprompt = \"Which service\"\n\
        [vars.image]\nprompt = \"New image\"\ndefault = \"example/web:2\"\n\
        [[steps]]\nid = \"a\"\ntitle = \"a\"\nrun = \"echo {{ service }} {{ image }}\"\n";
    a.set_wf_entries(vec![crate::workflows::Entry {
        name: "bump".into(),
        path: "bump.toml".into(),
        wf: crate::workflows::parse(text),
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

#[test]
fn ask_works_on_workflows_and_updates() {
    let mut a = app();
    let screen = |a: &mut App| render_to_string(a, 158, 41);
    key(&mut a, KeyCode::Char(Tab::Workflows.key()));
    key(&mut a, KeyCode::Char('A'));
    let s = screen(&mut a);
    assert!(
        s.contains("Ask Claude") && s.contains("Workflow apt-maintenance"),
        "no run in progress: asks about the selected workflow\n{s}"
    );
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char(Tab::Updates.key()));
    key(&mut a, KeyCode::Char('A'));
    let s = screen(&mut a);
    assert!(s.contains("Ask Claude") && s.contains("Selected:"), "{s}");
}

/// Against a disposable sshd whose sudo asks for a password (never the real server): a sudo
/// step hands over the terminal and its output lands in the step log; abandoning a running
/// step stops it on the server. Run under a pty that types the password:
/// `SENTRY_SSH_CONFIG=… SENTRY_SERVER_SCRATCH=<name> XDG_*=scratch cargo test live_password_step -- --ignored --nocapture`
#[test]
#[ignore]
fn live_password_step() {
    let Ok(name) = std::env::var("SENTRY_SERVER_SCRATCH") else {
        return;
    };
    let (file, _) = crate::server::config::load().unwrap();
    let (n, s) = crate::server::config::pick(&file, Some(&name)).unwrap();
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
    key(&mut a, KeyCode::Char('0'));
    key(&mut a, KeyCode::Enter);
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
    println!("ok");
}

#[test]
fn reboot_with_a_password_waits_after_the_terminal_comes_back() {
    use std::os::unix::process::ExitStatusExt;
    let mut a = app();
    data(
        &mut a,
        Kind::Sudo,
        Payload::Sudo(crate::server::remote::SudoMode::Password),
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
    let (Ok(name), Ok(wf)) = (
        std::env::var("SENTRY_SERVER_LIVE"),
        std::env::var("SENTRY_WORKFLOW"),
    ) else {
        return;
    };
    let (file, _) = crate::server::config::load().unwrap();
    let (n, s) = crate::server::config::pick(&file, Some(&name)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(Remote::new(n, s), tx);
    a.start(Instant::now());
    a.enter(Tab::Workflows, Instant::now());
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
        if w.live.is_none() && !matches!(w.next, crate::workflows::runner::Next::Run(_)) {
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
    let Ok(name) = std::env::var("SENTRY_SERVER_SCRATCH") else {
        return;
    };
    let (file, _) = crate::server::config::load().unwrap();
    let (n, s) = crate::server::config::pick(&file, Some(&name)).unwrap();
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
    key(&mut a, KeyCode::Char(Tab::Containers.key()));
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
    let inv = crate::server::inventory::load("scratch").unwrap().data;
    assert!(
        inv.outputs["cat /srv/stack/compose.yaml"]
            .out
            .contains("example/web:1.2.3")
    );
    // A workflow condition never uses it: it must see the server as it is now.
    let plain = Remote::new("scratch", &a.remote.cfg);
    assert!(crate::server::collect::docker::collect(&plain).is_err());
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
    key(&mut a, KeyCode::Char(Tab::Maint.key()));
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
    a.set_wf_entries(vec![crate::workflows::Entry {
        name: "compose-bump".into(),
        path: "compose-bump.toml".into(),
        wf: crate::workflows::parse(
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
    // Back to the list: the item says planned; Enter opens the plan again.
    key(&mut a, KeyCode::Esc);
    let s = screen(&mut a);
    assert!(
        s.contains("planned → 1.5.1")
            && s.contains("Plan: 1.4.2 → 1.5.1 with compose-bump · ready"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("ready to apply"));
    // Enter in the plan applies it: the workflow asks its vars with the plan's values.
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(
        s.contains("compose-bump 1/2 · Image (image): example/web:1.5.1▏"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("Service (service): web▏"));
    key(&mut a, KeyCode::Esc);
    // The plan stays until it's applied or dropped.
    key(&mut a, KeyCode::Char(Tab::Maint.key()));
    assert!(screen(&mut a).contains("planned → 1.5.1"));
    key(&mut a, KeyCode::Char('x'));
    key(&mut a, KeyCode::Char('y'));
    assert!(!screen(&mut a).contains("planned →"));
    // A plan Claude says to wait on can't be applied.
    a.store.plans.insert(
        "web".into(),
        crate::server::maint::plan::PlanDoc {
            head: crate::server::maint::plan::Head {
                item: "web".into(),
                workflow: "compose-bump".into(),
                status: crate::server::maint::plan::PlanStatus::Wait,
                ..Default::default()
            },
            body: "# Plan\nNot until 1.5.3.".into(),
        },
    );
    assert!(screen(&mut a).contains("plan: wait"));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    assert!(screen(&mut a).contains("Claude advises waiting: r revises it"));
    key(&mut a, KeyCode::Esc);
    // z offers later review dates; A asks with web access named in the consent box.
    key(&mut a, KeyCode::Char(Tab::Maint.key()));
    key(&mut a, KeyCode::Char('z'));
    assert!(screen(&mut a).contains("look again in 30 days"));
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('A'));
    let s = screen(&mut a);
    assert!(
        s.contains("read the web (release notes)") && s.contains("~/notes/runbook.md"),
        "{s}"
    );
}

#[test]
fn the_assessment_profile_adds_the_web_and_only_the_notes() {
    let r = Remote::new("myserver", &cfg());
    let p = super::ask::assess_profile(&r, "Debian 12", "6.1", None);
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
        super::maint::read_rules(&["/srv/notes.md".into()]),
        ["Read(//srv/notes.md)"]
    );
}

/// Read-only against the real server: the Maintenance tab, then one assessment sent to Claude
/// (the selected item, `SENTRY_ITEM`), with the web and notes allowed.
/// `SENTRY_SERVER_LIVE=<name> SENTRY_ITEM=<id> cargo test live_assess -- --ignored --nocapture`
#[test]
#[ignore]
fn live_assess() {
    let (Ok(name), Ok(item)) = (
        std::env::var("SENTRY_SERVER_LIVE"),
        std::env::var("SENTRY_ITEM"),
    ) else {
        return;
    };
    let (file, _) = crate::server::config::load().unwrap();
    let (n, s) = crate::server::config::pick(&file, Some(&name)).unwrap();
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
    key(&mut a, KeyCode::Char(Tab::Maint.key()));
    pump(&mut a, 10);
    for _ in 0..pos {
        key(&mut a, KeyCode::Char('j'));
    }
    println!("{}", render_to_string(&mut a, 158, 41));
    key(&mut a, KeyCode::Char('A'));
    println!("{}", render_to_string(&mut a, 158, 41));
    key(&mut a, KeyCode::Char('y'));
    for _ in 0..100 {
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

#[test]
fn a_password_sudo_says_press_i() {
    // A store that never had docker: the tab explains, with the key to press.
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut b = App::new(Remote::new("myserver", &cfg()), tx);
    b.offline = true;
    data(
        &mut b,
        Kind::Sudo,
        Payload::Sudo(crate::server::remote::SudoMode::Password),
    );
    b.on_event(
        Ev::Data(
            Kind::Docker,
            Box::new(Err(crate::server::remote::SrvError::SudoPassword(
                "docker ps".into(),
            ))),
        ),
        Instant::now(),
    );
    key(&mut b, KeyCode::Char(Tab::Containers.key()));
    let s = render_to_string(&mut b, 158, 41);
    assert!(
        s.contains("Press  I  to read them once with your password"),
        "{s}"
    );
    assert!(s.contains(" I  read with sudo"), "key bar: {s}");
}

#[test]
fn claude_target_lines() {
    use crate::server::maint::plan::target;
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
    let (Ok(name), Ok(item)) = (
        std::env::var("SENTRY_SERVER_LIVE"),
        std::env::var("SENTRY_ITEM"),
    ) else {
        return;
    };
    let (file, _) = crate::server::config::load().unwrap();
    let (n, s) = crate::server::config::pick(&file, Some(&name)).unwrap();
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
    key(&mut a, KeyCode::Char(Tab::Maint.key()));
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
    key(&mut a, KeyCode::Char(Tab::Overview.key()));
    for _ in 0..200 {
        pump(&mut a, 3);
        if !a.writing() {
            break;
        }
    }
    pump(&mut a, 1);
    key(&mut a, KeyCode::Char(Tab::Maint.key()));
    key(&mut a, KeyCode::Enter);
    println!("{}", render_to_string(&mut a, 158, 41));
    let plan = a.store.plans.get(&item).cloned().expect("a saved plan");
    let path = crate::server::maint::plan::path(&name, &item);
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
    let Ok(name) = std::env::var("SENTRY_SERVER_SCRATCH") else {
        return;
    };
    let (file, _) = crate::server::config::load().unwrap();
    let (n, s) = crate::server::config::pick(&file, Some(&name)).unwrap();
    let r = Remote::new(n, s);
    // What Claude runs: refused (sudo wants a password), so queued.
    let argv: Vec<String> = ["docker", "ps", "-aq"].map(String::from).to_vec();
    let code = crate::server::gateway::exec_cli(&r, &argv);
    assert_ne!(code, 0);
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut a = App::new(r, tx);
    a.open_chat(crate::tui::chat::Chat::new(crate::claude::Ask::new(
        "s", "c", "q",
    )));
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
        .find(|(k, _)| *k == crate::tui::chat::Kind::You)
        .map(|(_, t)| t.clone())
        .unwrap();
    println!("{sent}");
    assert!(sent.contains("$ sudo docker ps -aq   (exit 0)") && sent.contains("aaa111"));
}

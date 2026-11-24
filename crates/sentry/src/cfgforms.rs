//! Every setting of the three config files is in a form: the common ones first, the rest in
//! groups that start folded. These tests set every one of them through the forms (keys and
//! pastes, as a person would), save, and read the file back as its type; then set them all
//! back and find the file empty again. And: folding, groups that open by themselves, an
//! unset `Option` against an empty text, dates, fractions, choices, a record within a
//! record. Offline, each test in a directory of its own (as `cfgtests.rs`).

use std::collections::BTreeMap;
use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use sentry_app::app::render_to_string;
use sentry_app::cfgarea::Screen;
use sentry_app::{App, Event};
use sentry_core::cfg::FileId;
use sentry_core::config::{self as app, Config, Dur};
use sentry_core::tui::form;
use sentry_network::config as net;
use sentry_server::config as srv;

use crate::cfgtests::{pending, problems, set_field, text, value, with_files};
use crate::tests::{key, screen, three, two};

/// The cursor of the form in view on the field `key`, its group opened.
fn go(a: &mut App, key: &str) {
    assert!(a.config.go_for_test(key), "no field `{key}` in the form");
}

/// The value under the cursor.
fn now(a: &App) -> form::Value {
    let f = a.config.form_for_test().expect("a form");
    f.field().expect("a field").value.clone()
}

fn editing(a: &App) -> bool {
    a.config.form_for_test().is_some_and(|f| f.editing())
}

/// A text, a number, a duration or a date is typed into the field `key` and taken.
fn set(a: &mut App, path: &str, to: &str) {
    go(a, path);
    set_field(a, to);
    assert!(!editing(a), "`{to}` was refused for {path}:\n{}", screen(a));
}

fn yes(a: &mut App, path: &str, to: bool) {
    go(a, path);
    if now(a) != form::Value::Bool(to) {
        key(a, KeyCode::Char(' '));
    }
    assert_eq!(now(a), form::Value::Bool(to), "{path}");
}

/// Space until the choice is `word`.
fn pick(a: &mut App, path: &str, word: &str) {
    go(a, path);
    for _ in 0..8 {
        if let form::Value::Pick(words, at) = now(a)
            && words[at] == word
        {
            return;
        }
        key(a, KeyCode::Char(' '));
    }
    panic!("{path}: no `{word}` to pick: {:?}", now(a));
}

fn paste(a: &mut App, text: &str) {
    a.on_event(Event::Paste(text.to_string()), Instant::now());
}

/// A list (of words, or of `name = value`) is made exactly `elems`: what is there is taken
/// out with `x`, each element added with `n`.
fn list(a: &mut App, path: &str, elems: &[&str]) {
    go(a, path);
    let n = match now(a) {
        form::Value::List(l) => l.len(),
        form::Value::Pairs(p) => p.len(),
        v => panic!("{path} is no list: {v:?}"),
    };
    if n == 0 && elems.is_empty() {
        return;
    }
    key(a, KeyCode::Enter);
    let mut rest = elems;
    if editing(a) {
        // (An empty list: Enter types its first element.)
        paste(a, elems[0]);
        key(a, KeyCode::Enter);
        rest = &elems[1..];
    } else {
        // (What is there now: a list that started from what there is to choose has more.)
        let n = match now(a) {
            form::Value::List(l) => l.len(),
            form::Value::Pairs(p) => p.len(),
            _ => 0,
        };
        for _ in 0..n {
            key(a, KeyCode::Char('x'));
        }
    }
    for e in rest {
        key(a, KeyCode::Char('n'));
        paste(a, e);
        key(a, KeyCode::Enter);
        assert!(!editing(a), "`{e}` was refused for {path}:\n{}", screen(a));
    }
    key(a, KeyCode::Esc);
}

/// `n` in a list of records: one more, its form in front.
fn add_row(a: &mut App, path: &str) {
    go(a, path);
    key(a, KeyCode::Enter);
    key(a, KeyCode::Char('n'));
    assert!(a.config.row.is_some(), "{path}: no row was added");
}

/// Out of a row's form, then out of its list.
fn close_row(a: &mut App) {
    key(a, KeyCode::Esc);
    assert!(a.config.row.is_none());
    key(a, KeyCode::Esc);
}

/// Every row of a list of records is taken out.
fn no_rows(a: &mut App, path: &str) {
    go(a, path);
    let form::Value::Rows(_, rows) = now(a) else {
        panic!("{path} is no list of records");
    };
    key(a, KeyCode::Enter);
    for _ in 0..rows.len() {
        key(a, KeyCode::Char('x'));
    }
    key(a, KeyCode::Esc);
}

fn save(a: &mut App) {
    key(a, KeyCode::Char('s'));
    assert!(a.config.save.is_some(), "no save box:\n{}", screen(a));
    key(a, KeyCode::Enter);
    assert!(pending(a).is_empty(), "{:?}", pending(a));
}

/// What a config file says besides its header: the lines that aren't comments.
fn said(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .collect()
}

fn words(l: &[&str]) -> Vec<String> {
    l.iter().map(|s| s.to_string()).collect()
}

#[test]
fn every_setting_of_config_toml_is_set_in_a_form_saved_and_set_back() {
    let (mut a, d) = with_files(two(), &[(FileId::Servers, "servers:\n  myserver: {}\n")]);
    key(&mut a, KeyCode::F(3));
    assert!(a.in_config && text(&d, FileId::App).is_none());
    // The agent.
    key(&mut a, KeyCode::Char('2'));
    set(&mut a, "agent.command", "/opt/bin/claude");
    // This machine: its open groups, its upkeep, then every folded group.
    key(&mut a, KeyCode::Char('3'));
    yes(&mut a, "review.at_start", false);
    yes(&mut a, "review.after_run", false);
    list(&mut a, "maintenance.notes", &["~/notes/upgrade.md"]);
    set(&mut a, "ui.terminal", "ghostty -e");
    set(&mut a, "@upkeep:audit", "14d");
    set(&mut a, "ui.dashboard_hz", "2.5");
    set(&mut a, "ui.processes_hz", "4");
    set(&mut a, "cache.update_check_max_age", "12h");
    set(&mut a, "audit.stale_container_days", "14");
    set(&mut a, "audit.cache_warn_mb", "4096");
    set(&mut a, "audit.retention_months", "6");
    set(&mut a, "audit.outside", "ssh probe scan {address} {ports}");
    list(&mut a, "flatpak.flag_filesystems", &["host"]);
    list(&mut a, "flatpak.flag_talk_names", &["org.example.Bus"]);
    list(&mut a, "flatpak.trusted_origins", &["flathub"]);
    set(&mut a, "recorder.interval", "30s");
    set(&mut a, "recorder.retention_hours", "24");
    set(&mut a, "recorder.max_mb", "20");
    list(&mut a, "recorder.alerts", &["cpu>80%:1m"]);
    list(&mut a, "cleanup.cache.delete_dirs", &["pip", "yarn"]);
    list(&mut a, "baseline.listeners", &[]);
    list(&mut a, "baseline.findings", &["flatpak:*"]);
    // The window.
    key(&mut a, KeyCode::Char('6'));
    list(&mut a, "targets.show", &["local"]);
    list(&mut a, "keys", &["quit = Q"]);
    set(&mut a, "retention.log_months", "6");
    set(&mut a, "retention.log_keep", "5");
    set(&mut a, "retention.runs_per_workflow", "3");
    set(&mut a, "retention.done_months", "7");
    set(&mut a, "retention.reviews", "4");
    set(&mut a, "retention.reports", "50");
    assert!(
        text(&d, FileId::App).is_none(),
        "nothing is written before the save"
    );
    save(&mut a);
    // The file reads back as exactly what the forms said.
    let written = text(&d, FileId::App).unwrap();
    let (cfg, warnings) = Config::parse(&written).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    let want = Config {
        ui: app::Ui {
            dashboard_hz: 2.5,
            processes_hz: 4.0,
            terminal: Some("ghostty -e".into()),
        },
        cache: app::CacheCfg {
            update_check_max_age: Dur::hours(12),
        },
        audit: app::Audit {
            retention_months: 6,
            stale_container_days: 14,
            cache_warn_mb: 4096,
            outside: Some("ssh probe scan {address} {ports}".into()),
        },
        flatpak: app::FlatpakCfg {
            flag_filesystems: words(&["host"]),
            flag_talk_names: words(&["org.example.Bus"]),
            trusted_origins: words(&["flathub"]),
        },
        jobs: BTreeMap::from([(
            "audit".to_string(),
            app::JobCfg {
                suggested_every: Some("14d".into()),
            },
        )]),
        cleanup: app::Cleanup {
            cache: app::CleanupCache {
                delete_dirs: words(&["pip", "yarn"]),
            },
        },
        recorder: app::Recorder {
            interval: Dur::secs(30),
            retention_hours: 24,
            max_mb: 20,
            alerts: words(&["cpu>80%:1m"]),
        },
        baseline: app::BaselineCfg {
            listeners: Vec::new(),
            findings: words(&["flatpak:*"]),
        },
        keys: BTreeMap::from([("quit".to_string(), "Q".to_string())]),
        retention: app::Retention {
            log_months: 6,
            log_keep: 5,
            runs_per_workflow: 3,
            done_months: 7,
            reviews: 4,
            reports: 50,
        },
        maintenance: app::Maintenance {
            notes: words(&["~/notes/upgrade.md"]),
        },
        review: app::Review {
            at_start: false,
            after_run: false,
        },
        targets: app::Targets {
            show: Some(words(&["local"])),
        },
        agent: app::Agent {
            kind: app::AgentKind::ClaudeCode,
            command: "/opt/bin/claude".into(),
        },
    };
    assert_eq!(cfg, want, "{written}");
    // Nothing shows as a default now, and each group says how many are set in it.
    key(&mut a, KeyCode::Char('3'));
    let s = screen(&mut a);
    assert!(!s.contains("all defaults"), "{s}");
    for group in [
        "Refresh rates  2 set",
        "Audit          4 set",
        "Cleanup        1 set",
    ] {
        assert!(s.contains(group), "{group}:\n{s}");
    }
    // All of it back to the defaults: each is staged as what the file no longer says.
    key(&mut a, KeyCode::Char('2'));
    set(&mut a, "agent.command", "claude");
    key(&mut a, KeyCode::Char('3'));
    yes(&mut a, "review.at_start", true);
    yes(&mut a, "review.after_run", true);
    list(&mut a, "maintenance.notes", &[]);
    set(&mut a, "ui.terminal", "");
    set(&mut a, "@upkeep:audit", "");
    set(&mut a, "ui.dashboard_hz", "1");
    set(&mut a, "ui.processes_hz", "2");
    set(&mut a, "cache.update_check_max_age", "24h");
    set(&mut a, "audit.stale_container_days", "30");
    set(&mut a, "audit.cache_warn_mb", "2048");
    set(&mut a, "audit.retention_months", "12");
    set(&mut a, "audit.outside", "");
    list(
        &mut a,
        "flatpak.flag_filesystems",
        &["host", "home", "host-os"],
    );
    list(
        &mut a,
        "flatpak.flag_talk_names",
        &["org.freedesktop.Flatpak"],
    );
    list(&mut a, "flatpak.trusted_origins", &["flathub", "fedora"]);
    set(&mut a, "recorder.interval", "10s");
    set(&mut a, "recorder.retention_hours", "72");
    set(&mut a, "recorder.max_mb", "50");
    list(
        &mut a,
        "recorder.alerts",
        &["cpu>90%:5m", "disk_free<5%", "new_listener"],
    );
    list(&mut a, "cleanup.cache.delete_dirs", &[]);
    list(&mut a, "baseline.listeners", &["127.0.0.1:631/cupsd"]);
    list(&mut a, "baseline.findings", &[]);
    key(&mut a, KeyCode::Char('6'));
    list(&mut a, "targets.show", &[]);
    list(&mut a, "keys", &[]);
    set(&mut a, "retention.log_months", "12");
    set(&mut a, "retention.log_keep", "20");
    set(&mut a, "retention.runs_per_workflow", "10");
    set(&mut a, "retention.done_months", "12");
    set(&mut a, "retention.reviews", "10");
    set(&mut a, "retention.reports", "100");
    save(&mut a);
    let written = text(&d, FileId::App).unwrap();
    assert_eq!(Config::parse(&written).unwrap().0, Config::default());
    assert_eq!(said(&written), Vec::<&str>::new(), "{written}");
    key(&mut a, KeyCode::Char('3'));
    let s = screen(&mut a);
    assert!(
        !s.contains(" set  "),
        "every group is at its defaults again:\n{s}"
    );
}

const SRV: &str = "servers.myserver";

#[test]
fn every_setting_of_a_server_is_set_in_a_form_saved_and_set_back() {
    let (mut a, d) = with_files(two(), &[(FileId::Servers, "servers:\n  myserver: {}\n")]);
    key(&mut a, KeyCode::F(3));
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.screen, Screen::Servers);
    let at = |rest: &str| format!("{SRV}.{rest}");
    set(&mut a, &at("ssh"), "admin@192.0.2.10");
    list(&mut a, &at("sudo"), &["docker ps"]);
    list(&mut a, &at("services"), &["app.service"]);
    add_row(&mut a, &at("timers"));
    set(&mut a, &at("timers[0].unit"), "backup.timer");
    set(&mut a, &at("timers[0].max_age"), "36h");
    close_row(&mut a);
    add_row(&mut a, &at("disks"));
    set(&mut a, &at("disks[0].mount"), "/srv");
    set(&mut a, &at("disks[0].warn"), "70");
    set(&mut a, &at("disks[0].crit"), "90");
    close_row(&mut a);
    list(&mut a, &at("smart"), &["/dev/sda"]);
    add_row(&mut a, &at("compose"));
    set(&mut a, &at("compose[0].name"), "stack");
    set(&mut a, &at("compose[0].file"), "/srv/stack/compose.yaml");
    close_row(&mut a);
    list(&mut a, &at("listeners"), &["*:443/*"]);
    // A tracked item, in full: its own settings, then its image and its retirement.
    add_row(&mut a, &at("maintenance.items"));
    let item = |rest: &str| format!("{SRV}.maintenance.items[0].{rest}");
    set(&mut a, &item("id"), "app");
    set(&mut a, &item("source"), "github:example/app");
    pick(&mut a, &item("risk"), "high");
    pick(&mut a, &item("workflow"), "compose-update");
    list(&mut a, &item("apt"), &["docker-ce"]);
    set(&mut a, &item("version_cmd"), "app --version");
    set(&mut a, &item("unit"), "app.service");
    set(&mut a, &item("tag"), "*-alpine");
    set(&mut a, &item("hold"), "pinned until the migration");
    set(&mut a, &item("constraint"), "needs v2 of the database");
    set(&mut a, &item("review_by"), "2027-03-31");
    set(&mut a, &item("eol"), "docker-engine");
    set(&mut a, &item("image.service"), "web");
    set(&mut a, &item("image.compose"), "stack");
    set(&mut a, &item("image.container"), "app-1");
    set(&mut a, &item("retire.replaced_by"), "newapp");
    pick(&mut a, &item("retire.workflow"), "apt-maintenance");
    close_row(&mut a);
    list(&mut a, &at("maintenance.notes"), &["~/notes/server.md"]);
    set(&mut a, "@upkeep:apt-maintenance", "30d");
    // The folded groups.
    set(&mut a, &at("thresholds.mem"), "80");
    set(&mut a, &at("thresholds.load_per_core"), "1.5");
    set(&mut a, &at("thresholds.cpu_temp"), "75");
    set(&mut a, &at("thresholds.gpu_temp"), "70.5");
    list(&mut a, &at("containers.ignore"), &["tmp-*"]);
    set(&mut a, &at("containers.restart_window"), "12h");
    list(&mut a, &at("findings"), &["srv:disk:*"]);
    add_row(&mut a, &at("actions"));
    let action = |rest: &str| format!("{SRV}.actions[0].{rest}");
    set(&mut a, &action("id"), "restart-app");
    set(&mut a, &action("title"), "Restart the app");
    set(&mut a, &action("run"), "systemctl restart app.service");
    yes(&mut a, &action("sudo"), true);
    yes(&mut a, &action("risky"), true);
    set(&mut a, &action("undo"), "start it again");
    close_row(&mut a);
    set(&mut a, &at("suscheck.dir"), "/srv/suscheck/incidents");
    set(&mut a, &at("suscheck.ssh"), "suscheck-reader@192.0.2.10");
    set(&mut a, &at("suscheck.recent"), "50");
    save(&mut a);
    let written = text(&d, FileId::Servers).unwrap();
    let (file, warnings) = srv::parse(&written).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    let want = srv::Server {
        ssh: Some("admin@192.0.2.10".into()),
        sudo: words(&["docker ps"]),
        disks: vec![srv::DiskRule {
            mount: "/srv".into(),
            warn: 70,
            crit: 90,
        }],
        smart: words(&["/dev/sda"]),
        services: words(&["app.service"]),
        timers: vec![srv::TimerRule {
            unit: "backup.timer".into(),
            max_age: Dur::hours(36),
        }],
        compose: vec![srv::Compose {
            name: "stack".into(),
            file: "/srv/stack/compose.yaml".into(),
        }],
        containers: srv::Containers {
            ignore: words(&["tmp-*"]),
            restart_window: Dur::hours(12),
        },
        listeners: words(&["*:443/*"]),
        findings: words(&["srv:disk:*"]),
        thresholds: srv::Thresholds {
            mem: 80.0,
            load_per_core: 1.5,
            cpu_temp: 75.0,
            gpu_temp: 70.5,
        },
        actions: vec![srv::CustomAction {
            id: "restart-app".into(),
            title: "Restart the app".into(),
            run: "systemctl restart app.service".into(),
            sudo: true,
            risky: true,
            undo: Some("start it again".into()),
        }],
        maintenance: srv::Maintenance {
            notes: words(&["~/notes/server.md"]),
            items: vec![srv::MaintItem {
                id: "app".into(),
                image: Some(srv::ImageRef {
                    service: Some("web".into()),
                    compose: Some("stack".into()),
                    container: Some("app-1".into()),
                }),
                apt: words(&["docker-ce"]),
                version_cmd: Some("app --version".into()),
                unit: Some("app.service".into()),
                source: Some("github:example/app".into()),
                tag: Some("*-alpine".into()),
                risk: srv::Risk::High,
                hold: Some("pinned until the migration".into()),
                constraint: Some("needs v2 of the database".into()),
                review_by: Some("2027-03-31".parse().unwrap()),
                eol: Some("docker-engine".into()),
                workflow: Some("compose-update".into()),
                retire: Some(srv::Retire {
                    replaced_by: Some("newapp".into()),
                    workflow: Some("apt-maintenance".into()),
                }),
            }],
            cadence: BTreeMap::from([("apt-maintenance".to_string(), Dur::secs(30 * 86400))]),
        },
        suscheck: srv::Suscheck {
            dir: Some("/srv/suscheck/incidents".into()),
            ssh: Some("suscheck-reader@192.0.2.10".into()),
            recent: 50,
        },
    };
    assert_eq!(file.servers["myserver"], want, "{written}");
    // All of it back: the records out, the lists empty, the numbers at their defaults.
    set(&mut a, &at("ssh"), "");
    list(&mut a, &at("sudo"), &[]);
    list(&mut a, &at("services"), &[]);
    no_rows(&mut a, &at("timers"));
    no_rows(&mut a, &at("disks"));
    list(&mut a, &at("smart"), &[]);
    no_rows(&mut a, &at("compose"));
    list(&mut a, &at("listeners"), &[]);
    no_rows(&mut a, &at("maintenance.items"));
    list(&mut a, &at("maintenance.notes"), &[]);
    set(&mut a, "@upkeep:apt-maintenance", "");
    set(&mut a, &at("thresholds.mem"), "90");
    set(&mut a, &at("thresholds.load_per_core"), "2");
    set(&mut a, &at("thresholds.cpu_temp"), "85");
    set(&mut a, &at("thresholds.gpu_temp"), "83");
    list(&mut a, &at("containers.ignore"), &[]);
    set(&mut a, &at("containers.restart_window"), "24h");
    list(&mut a, &at("findings"), &[]);
    no_rows(&mut a, &at("actions"));
    set(&mut a, &at("suscheck.dir"), "");
    set(&mut a, &at("suscheck.ssh"), "");
    set(&mut a, &at("suscheck.recent"), "200");
    save(&mut a);
    let written = text(&d, FileId::Servers).unwrap();
    let (file, _) = srv::parse(&written).unwrap();
    assert_eq!(file.servers["myserver"], srv::Server::default());
    assert_eq!(said(&written), ["servers:", "  myserver: {}"], "{written}");
}

const NET: &str = "networks.home";

#[test]
fn every_setting_of_a_network_is_set_in_a_form_saved_and_set_back() {
    let (mut a, d) = with_files(
        three(),
        &[
            (FileId::Servers, "servers:\n  myserver: {}\n"),
            (FileId::Networks, "networks:\n  home: {}\n"),
        ],
    );
    key(&mut a, KeyCode::F(4));
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.screen, Screen::Networks);
    let at = |rest: &str| format!("{NET}.{rest}");
    set(&mut a, &at("router.ssh"), "root@192.0.2.1");
    list(
        &mut a,
        &at("expect.zones"),
        &["lan = lan", "wan = wan wan6"],
    );
    add_row(&mut a, &at("expect.forwards"));
    set(&mut a, &at("expect.forwards[0].name"), "web");
    pick(&mut a, &at("expect.forwards[0].proto"), "udp");
    set(&mut a, &at("expect.forwards[0].port"), "8000-8010");
    set(&mut a, &at("expect.forwards[0].to"), "192.0.2.20");
    close_row(&mut a);
    add_row(&mut a, &at("devices"));
    set(&mut a, &at("devices[0].name"), "nas");
    set(&mut a, &at("devices[0].mac"), "02:00:5e:00:53:01");
    set(&mut a, &at("devices[0].hostname"), "nas");
    yes(&mut a, &at("devices[0].leave_alone"), true);
    yes(&mut a, &at("devices[0].private_mac"), true);
    close_row(&mut a);
    list(&mut a, &at("backup.recipients"), &["~/keys/backup.pub"]);
    set(&mut a, &at("backup.keep"), "6");
    list(&mut a, &at("notes"), &["~/notes/network.md"]);
    yes(&mut a, &at("claude.share_wan_address"), true);
    set(&mut a, "@upkeep:config-backup", "7d");
    // The folded groups. (The router's kind is a choice of one so far.)
    go(&mut a, &at("router.kind"));
    assert_eq!(now(&a), form::Value::Pick(words(&["openwrt"]), 0));
    list(&mut a, &at("expect.listeners"), &["tcp:22@lan"]);
    list(&mut a, &at("expect.services"), &["adblock-fast"]);
    set(&mut a, &at("thresholds.load"), "3.5");
    set(&mut a, &at("thresholds.mem_pct"), "70");
    set(&mut a, &at("thresholds.cert_days"), "14");
    set(&mut a, &at("thresholds.backup_age"), "14d");
    set(&mut a, &at("guard.window"), "120");
    add_row(&mut a, &at("maintenance.items"));
    set(&mut a, &at("maintenance.items[0].id"), "packages");
    pick(&mut a, &at("maintenance.items[0].kind"), "packages");
    close_row(&mut a);
    save(&mut a);
    let written = text(&d, FileId::Networks).unwrap();
    let (file, warnings) = net::parse(&written).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    let want = net::Network {
        router: net::RouterCfg {
            ssh: Some("root@192.0.2.1".into()),
            kind: net::RouterKind::Openwrt,
        },
        expect: net::Expect {
            zones: BTreeMap::from([
                ("lan".to_string(), words(&["lan"])),
                ("wan".to_string(), words(&["wan", "wan6"])),
            ]),
            forwards: vec![net::Forward {
                name: "web".into(),
                proto: "udp".into(),
                port: "8000-8010".parse().unwrap(),
                to: "192.0.2.20".into(),
            }],
            listeners: words(&["tcp:22@lan"]),
            services: words(&["adblock-fast"]),
        },
        devices: vec![net::Device {
            name: Some("nas".into()),
            mac: Some("02:00:5e:00:53:01".into()),
            hostname: Some("nas".into()),
            leave_alone: true,
            private_mac: true,
        }],
        thresholds: net::Thresholds {
            load: 3.5,
            mem_pct: 70.0,
            cert_days: 14,
            backup_age: Dur::secs(14 * 86400),
        },
        backup: net::Backup {
            recipients: words(&["~/keys/backup.pub"]),
            keep: 6,
        },
        maintenance: net::Maintenance {
            items: vec![net::Item {
                id: "packages".into(),
                kind: net::ItemKind::Packages,
            }],
            cadence: vec![net::Cadence {
                workflow: "config-backup".into(),
                every: Dur::secs(7 * 86400),
            }],
        },
        notes: words(&["~/notes/network.md"]),
        claude: net::ClaudeCfg {
            share_wan_address: true,
        },
        guard: net::GuardCfg { window: 120 },
    };
    assert_eq!(file.networks["home"], want, "{written}");
    // All of it back.
    set(&mut a, &at("router.ssh"), "");
    list(&mut a, &at("expect.zones"), &[]);
    no_rows(&mut a, &at("expect.forwards"));
    no_rows(&mut a, &at("devices"));
    list(&mut a, &at("backup.recipients"), &[]);
    set(&mut a, &at("backup.keep"), "12");
    list(&mut a, &at("notes"), &[]);
    yes(&mut a, &at("claude.share_wan_address"), false);
    set(&mut a, "@upkeep:config-backup", "");
    list(&mut a, &at("expect.listeners"), &[]);
    list(&mut a, &at("expect.services"), &[]);
    set(&mut a, &at("thresholds.load"), "2");
    set(&mut a, &at("thresholds.mem_pct"), "85");
    set(&mut a, &at("thresholds.cert_days"), "21");
    set(&mut a, &at("thresholds.backup_age"), "30d");
    set(&mut a, &at("guard.window"), "300");
    no_rows(&mut a, &at("maintenance.items"));
    save(&mut a);
    let written = text(&d, FileId::Networks).unwrap();
    let (file, _) = net::parse(&written).unwrap();
    assert_eq!(file.networks["home"], net::Network::default());
    assert_eq!(said(&written), ["networks:", "  home: {}"], "{written}");
}

#[test]
fn the_rest_of_this_machines_settings_are_in_groups_that_fold() {
    let (mut a, _d) = with_files(two(), &[(FileId::Servers, "servers:\n  myserver: {}\n")]);
    key(&mut a, KeyCode::F(3));
    key(&mut a, KeyCode::Char('3'));
    // The common groups are as they were; under them the rest, each a row.
    key(&mut a, KeyCode::Char('G'));
    assert_eq!(
        a.config.field_for_test().as_deref(),
        Some("@group:Expected")
    );
    insta::assert_snapshot!("config_machine_groups_158", screen(&mut a));
    insta::assert_snapshot!("config_machine_groups_80", render_to_string(&mut a, 80, 30));
    let s = screen(&mut a);
    assert!(!s.contains("Stale container") && !s.contains('▾'), "{s}");
    assert!(!s.contains("127.0.0.1:631/cupsd"), "{s}");
    assert!(s.contains("Enter  open the group"), "{s}");
    assert!(
        s.contains("In it: Expected listeners, Expected findings."),
        "{s}"
    );
    // Enter opens the one under the cursor, Space closes it again; nothing is staged.
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(s.contains("▾ Expected"), "{s}");
    assert!(s.contains("127.0.0.1:631/cupsd  (default)"), "{s}");
    assert!(s.contains("Enter  close the group"), "{s}");
    key(&mut a, KeyCode::Char(' '));
    let s = screen(&mut a);
    assert!(
        s.contains("▸ Expected") && !s.contains("127.0.0.1:631/cupsd"),
        "{s}"
    );
    assert!(pending(&a).is_empty());
    // One opened: its settings under its header, the others still a row each.
    go(&mut a, "audit.stale_container_days");
    insta::assert_snapshot!("config_machine_group_open_158", screen(&mut a));
    insta::assert_snapshot!(
        "config_machine_group_open_80",
        render_to_string(&mut a, 80, 30)
    );
    // A fraction; what is out of range or no number is refused in place, nothing staged.
    go(&mut a, "ui.dashboard_hz");
    for (bad, why) in [("fast", "isn't a number"), ("20", "out of range: 0 to 10")] {
        set_field(&mut a, bad);
        assert!(screen(&mut a).contains(why), "{bad}");
        key(&mut a, KeyCode::Esc);
        assert!(pending(&a).is_empty());
    }
    set(&mut a, "ui.dashboard_hz", "0.5");
    assert_eq!(value(&a, "ui.dashboard_hz").unwrap(), "0.5");
    assert_eq!(pending(&a), ["x ui.dashboard_hz"]);
    let s = screen(&mut a);
    assert!(s.contains("Refresh rates  1 set"), "{s}");
    assert!(s.contains("The default is 1."), "{s}");
    // Away and back: the group that holds a staged change is open by itself, no other.
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char('3'));
    let s = screen(&mut a);
    assert!(
        s.contains("▾ Refresh rates") && s.contains("Dashboard rate  0.5"),
        "{s}"
    );
    assert_eq!(s.matches('▾').count(), 1, "{s}");
    // Set back to its default: no change is left, and the next visit finds it folded.
    set(&mut a, "ui.dashboard_hz", "1");
    assert!(pending(&a).is_empty());
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char('3'));
    let s = screen(&mut a);
    assert_eq!(s.matches('▾').count(), 0, "{s}");
    assert!(s.contains("Refresh rates  all defaults"), "{s}");
    // The window's own screen has nothing folded: what is there was all common.
    key(&mut a, KeyCode::Char('6'));
    assert!(!screen(&mut a).contains("More settings"));
}

#[test]
fn a_group_that_holds_a_problem_opens_by_itself() {
    let (mut a, _d) = with_files(
        three(),
        &[
            (FileId::Servers, "servers:\n  myserver: {}\n"),
            (
                FileId::Networks,
                "networks:\n  home:\n    router: {ssh: myrouter}\n    guard: {window: 3}\n",
            ),
        ],
    );
    key(&mut a, KeyCode::F(4));
    key(&mut a, KeyCode::Char('5'));
    key(&mut a, KeyCode::Enter);
    assert_eq!(problems(&a).len(), 1, "{:?}", problems(&a));
    let s = screen(&mut a);
    assert!(s.contains("▾ Guard") && s.contains("1 set"), "{s}");
    assert!(s.contains("Guard window  3"), "{s}");
    assert!(
        s.contains("! guard: window: 3 s (between 5 and 3600"),
        "{s}"
    );
    assert_eq!(s.matches('▾').count(), 1, "{s}");
    insta::assert_snapshot!("config_network_group_open_158", s);
    // What is out of its bounds is refused in place; a fix takes the problem away.
    go(&mut a, "networks.home.guard.window");
    set_field(&mut a, "4000");
    assert!(screen(&mut a).contains("4000 is out of range: 5 to 3600"));
    key(&mut a, KeyCode::Esc);
    assert!(pending(&a).is_empty());
    set(&mut a, "networks.home.guard.window", "300");
    assert!(problems(&a).is_empty(), "{:?}", problems(&a));
    assert_eq!(pending(&a), ["x networks.home.guard.window"]);
    // The groups, folded, in a narrow window.
    key(&mut a, KeyCode::Char('G'));
    insta::assert_snapshot!("config_network_groups_80", render_to_string(&mut a, 80, 30));
}

#[test]
fn an_unset_option_is_an_empty_field_and_the_file_leaves_it_out() {
    let (mut a, d) = with_files(
        two(),
        &[(
            FileId::Servers,
            "servers:\n  myserver:\n    ssh: admin@192.0.2.10\n    compose: [{name: stack, file: /srv/compose.yaml}]\n",
        )],
    );
    key(&mut a, KeyCode::F(3));
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Enter);
    // An optional text that is set: emptied, it is unset (null), not an empty text.
    go(&mut a, "servers.myserver.ssh");
    assert!(screen(&mut a).contains("text, or empty: not set"));
    set(&mut a, "servers.myserver.ssh", "");
    assert_eq!(value(&a, "servers.myserver.ssh").unwrap(), "null");
    let s = screen(&mut a);
    assert!(s.contains("ssh               (its name)"), "{s}");
    // A text the type needs stays a text: empty, and its lint says so.
    go(&mut a, "servers.myserver.compose");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    set(&mut a, "servers.myserver.compose[0].name", "");
    assert_eq!(
        value(&a, "servers.myserver.compose[0].name").unwrap(),
        "\"\""
    );
    set(&mut a, "servers.myserver.compose[0].name", "stack");
    close_row(&mut a);
    save(&mut a);
    let written = text(&d, FileId::Servers).unwrap();
    assert!(
        !said(&written).iter().any(|l| l.contains("ssh")),
        "{written}"
    );
    assert_eq!(
        srv::parse(&written).unwrap().0.servers["myserver"].ssh,
        None
    );
    // And this machine's terminal: set, saved, emptied, gone from the file.
    key(&mut a, KeyCode::Char('3'));
    set(&mut a, "ui.terminal", "ghostty -e");
    save(&mut a);
    assert!(
        text(&d, FileId::App)
            .unwrap()
            .contains("terminal = \"ghostty -e\"")
    );
    set(&mut a, "ui.terminal", "");
    assert_eq!(value(&a, "ui.terminal").unwrap(), "null");
    save(&mut a);
    let written = text(&d, FileId::App).unwrap();
    assert!(!written.contains("terminal"), "{written}");
    assert_eq!(Config::parse(&written).unwrap().0.ui.terminal, None);
}

#[test]
fn a_tracked_item_is_edited_in_full_with_its_image_and_retirement_as_groups() {
    let (mut a, _d) = with_files(
        two(),
        &[(
            FileId::Servers,
            "servers:\n  myserver:\n    maintenance:\n      items:\n        - {id: app, source: \"github:example/app\", risk: low, hold: pinned}\n",
        )],
    );
    key(&mut a, KeyCode::F(3));
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Enter);
    go(&mut a, "servers.myserver.maintenance.items");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    assert!(a.config.row.is_some());
    let item = |rest: &str| format!("servers.myserver.maintenance.items[0].{rest}");
    // What the item says, what it leaves at a default, what it doesn't set.
    insta::assert_snapshot!("config_server_item_158", screen(&mut a));
    let s = screen(&mut a);
    assert!(s.contains("Risk             low"), "{s}");
    assert!(!s.contains("low  (default)"), "{s}");
    assert!(s.contains("Why held         pinned"), "{s}");
    assert!(s.contains("Constraint       (not set)"), "{s}");
    assert!(s.contains("Image · A container image"), "{s}");
    assert!(s.contains("Retire · Planned to be removed."), "{s}");
    assert!(s.contains("Compose service  (not set)"), "{s}");
    // An enumeration is a pick.
    pick(&mut a, &item("risk"), "medium");
    assert!(screen(&mut a).contains("medium  (default)"));
    pick(&mut a, &item("risk"), "high");
    // A date: what isn't one is refused in place and nothing is staged for it.
    go(&mut a, &item("review_by"));
    set_field(&mut a, "next spring");
    assert!(screen(&mut a).contains("`next spring` isn't a date: YYYY-MM-DD"));
    key(&mut a, KeyCode::Esc);
    set_field(&mut a, "2027-13-01");
    assert!(screen(&mut a).contains("isn't a date"));
    key(&mut a, KeyCode::Esc);
    assert_eq!(value(&a, &item("review_by")).unwrap(), "null");
    set(&mut a, &item("review_by"), "2027-03-31");
    assert_eq!(value(&a, &item("review_by")).unwrap(), "\"2027-03-31\"");
    // An optional text of the record: emptied, it is unset.
    set(&mut a, &item("hold"), "");
    assert_eq!(value(&a, &item("hold")).unwrap(), "null");
    // The image is a record within the record: its first setting makes it …
    assert_eq!(value(&a, &item("image")).unwrap(), "null");
    set(&mut a, &item("image.service"), "web");
    assert_eq!(
        value(&a, &item("image")).unwrap(),
        "{service: \"web\", compose: null, container: null}"
    );
    set(&mut a, &item("image.compose"), "stack");
    insta::assert_snapshot!("config_server_item_80", render_to_string(&mut a, 80, 30));
    // … and with its last one unset there is no image again (not an empty one).
    set(&mut a, &item("image.service"), "");
    set(&mut a, &item("image.compose"), "");
    assert_eq!(value(&a, &item("image")).unwrap(), "null");
    // The workflow that retires it is one of this server's.
    go(&mut a, &item("retire.workflow"));
    assert!(screen(&mut a).contains("one of: (none), apt-maintenance, compose-update"));
    pick(&mut a, &item("retire.workflow"), "compose-update");
    assert_eq!(
        value(&a, &item("retire")).unwrap(),
        "{replaced_by: null, workflow: \"compose-update\"}"
    );
    pick(&mut a, &item("retire.workflow"), "(none)");
    assert_eq!(value(&a, &item("retire")).unwrap(), "null");
    // The whole list is one staged change, as before.
    assert_eq!(pending(&a), ["x servers.myserver.maintenance.items"]);
    close_row(&mut a);
    // The server's groups, folded, in a narrow window.
    key(&mut a, KeyCode::Char('G'));
    insta::assert_snapshot!("config_server_groups_80", render_to_string(&mut a, 80, 30));
    // A custom action is a record too, added and opened like any other.
    add_row(&mut a, "servers.myserver.actions");
    let s = screen(&mut a);
    assert!(s.contains("With sudo  [ ] no  (default)"), "{s}");
    assert!(s.contains("Undo       (not set)"), "{s}");
}

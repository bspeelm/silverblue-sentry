use super::*;
use crate::config::{
    Audit, BaselineCfg, CacheCfg, Cleanup, CleanupCache, Config, Dur, FlatpakCfg, JobCfg,
    Maintenance, Recorder, Retention, Review, Targets, Ui,
};

const SPEC_EXAMPLE: &str = r#"
[ui]
dashboard_hz = 1
processes_hz = 2

[cache]
update_check_max_age = "24h"

[audit]
retention_months = 12
stale_container_days = 30
cache_warn_mb = 2048

[flatpak]
flag_filesystems = ["host", "home", "host-os"]
flag_talk_names = ["org.freedesktop.Flatpak"]

[jobs]
audit.suggested_every = "30d"
update-check.suggested_every = "7d"
cleanup-flatpak.suggested_every = "30d"
cleanup-podman.suggested_every = "30d"
cleanup-ostree.suggested_every = "30d"

[cleanup.cache]
delete_dirs = []

[recorder]
interval = "10s"
retention_hours = 72
max_mb = 50
alerts = ["cpu>90%:5m", "disk_free<5%", "new_listener"]

[baseline]
listeners = ["127.0.0.1:631/cupsd"]
"#;

/// Every field at something other than its default, with values a file has to quote.
pub(crate) fn full() -> Config {
    Config {
        ui: Ui {
            dashboard_hz: 0.5,
            processes_hz: 4.0,
            terminal: Some("ghostty -e".into()),
        },
        cache: CacheCfg {
            update_check_max_age: Dur::secs(90),
        },
        audit: Audit {
            retention_months: 3,
            stale_container_days: 7,
            cache_warn_mb: 10,
            outside: Some("ssh vps 'nc -zw2 {address} {ports}' # \"quoted\"".into()),
        },
        flatpak: FlatpakCfg {
            flag_filesystems: vec!["yes".into(), "1.10".into()],
            flag_talk_names: vec![],
            trusted_origins: vec!["*flathub".into(), ":fedora".into()],
        },
        jobs: [
            (
                "audit".to_string(),
                JobCfg {
                    suggested_every: Some("off".into()),
                },
            ),
            ("cleanup.weird".to_string(), JobCfg::default()),
        ]
        .into(),
        cleanup: Cleanup {
            cache: CleanupCache {
                delete_dirs: vec!["pip".into(), "null".into()],
            },
        },
        recorder: Recorder {
            interval: Dur::secs(30),
            retention_hours: 24,
            max_mb: 20,
            alerts: vec![],
        },
        baseline: BaselineCfg {
            listeners: vec![],
            findings: vec!["repo:rpmfusion-*".into()],
        },
        keys: [
            ("quit".to_string(), "Q".to_string()),
            ("screen.history".to_string(), "F9".to_string()),
        ]
        .into(),
        retention: Retention {
            log_months: 1,
            log_keep: 2,
            runs_per_workflow: 3,
            done_months: 4,
            reviews: 5,
            reports: 6,
        },
        maintenance: Maintenance {
            notes: vec!["~/notes/a b.md".into()],
        },
        review: Review {
            at_start: false,
            after_run: false,
        },
        targets: Targets {
            show: Some(vec!["srv:my.server".into(), "local".into()]),
        },
    }
}

fn round_trip<T: ConfigFile + std::fmt::Debug>(v: &T) -> String {
    let text = render(v).unwrap_or_else(|e| panic!("{e}"));
    let (back, warnings) = T::parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
    assert!(warnings.is_empty(), "{warnings:?}\n{text}");
    assert_eq!(&back, v, "{text}");
    assert!(!handwritten(&text, v), "{text}");
    text
}

#[test]
fn config_toml_reads_back_as_what_it_was() {
    let t = round_trip(&Config::default());
    // The defaults are left out: nothing but the header.
    assert_eq!(t, FileId::App.header(), "{t}");
    let (spec, _) = Config::parse(SPEC_EXAMPLE).unwrap();
    round_trip(&spec);
    let t = round_trip(&full());
    insta::assert_snapshot!(t);
    // One setting changed: one line under its table.
    let mut c = Config::default();
    c.review.at_start = false;
    assert_eq!(
        round_trip(&c),
        format!("{}[review]\nat_start = false\n", FileId::App.header())
    );
}

#[test]
fn every_setting_of_config_toml_has_its_field() {
    let tree = Value::of(&full()).unwrap();
    assert_eq!(
        fields::uncovered(crate::config::FIELDS, &tree),
        Vec::<String>::new()
    );
    assert_eq!(
        fields::unused(crate::config::FIELDS, &tree),
        Vec::<&str>::new()
    );
}

#[test]
fn handwritten_is_any_text_sentry_wouldnt_write() {
    let (spec, _) = Config::parse(SPEC_EXAMPLE).unwrap();
    assert!(handwritten(SPEC_EXAMPLE, &spec));
    let mine = render(&spec).unwrap();
    assert!(!handwritten(&mine, &spec));
    assert!(handwritten(&format!("{mine}# a note\n"), &spec));
}

#[test]
fn every_diff_applies_to_the_typed_value() {
    let pairs = [
        (Config::default(), full()),
        (full(), Config::default()),
        (Config::parse(SPEC_EXAMPLE).unwrap().0, full()),
    ];
    for (a, b) in pairs {
        let changes = diff(&a, &b).unwrap();
        assert!(!changes.is_empty());
        let mut x = a.clone();
        for c in &changes {
            apply(&mut x, c).unwrap_or_else(|e| panic!("{e}: {c:?}"));
        }
        assert_eq!(x, b);
    }
    // One setting, by its path; a stale `from` is refused; the type refuses what it can't be.
    let mut c = Config::default();
    let change = Change {
        file: FileId::App,
        path: "ui.dashboard_hz".into(),
        from: Some(Value::Float(1.0)),
        to: Some(Value::Float(2.0)),
        by: By::Agent,
        on: true,
    };
    apply(&mut c, &change).unwrap();
    assert_eq!(c.ui.dashboard_hz, 2.0);
    assert!(apply(&mut c, &change).unwrap_err().contains("is 2.0 now"));
    let bad = Change {
        path: "recorder.interval".into(),
        from: Some(Value::Str("10s".into())),
        to: Some(Value::Str("ten seconds".into())),
        ..change.clone()
    };
    assert!(
        apply(&mut c, &bad)
            .unwrap_err()
            .contains("recorder.interval")
    );
    let elsewhere = Change {
        file: FileId::Servers,
        ..change
    };
    assert!(apply(&mut c, &elsewhere).is_err());
    let add = Change {
        file: FileId::App,
        path: "keys.quit".into(),
        from: None,
        to: Some(Value::Str("Q".into())),
        by: By::You,
        on: true,
    };
    apply(&mut c, &add).unwrap();
    assert_eq!(c.keys["quit"], "Q");
}

/// A scratch dir of this test's own under the test process's config dir.
fn scratch(name: &str) -> PathBuf {
    let d = crate::paths::config_dir().join("cfg-tests").join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_save_keeps_the_file_before_and_only_the_newest_five() {
    let d = scratch("rotation");
    let p = d.join("config.toml");
    assert_eq!(save(&p, "a = 0\n").unwrap(), None, "nothing to keep yet");
    let mut made = Vec::new();
    for i in 1..=7 {
        let b = save(&p, &format!("a = {i}\n")).unwrap().expect("a copy");
        assert_eq!(
            std::fs::read_to_string(&b).unwrap(),
            format!("a = {}\n", i - 1)
        );
        assert!(
            b.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("config.toml.bak-")
        );
        made.push(b);
    }
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "a = 7\n");
    let kept = backups(&p);
    assert_eq!(kept, made[2..], "the newest five, oldest first");
    assert!(!made[0].exists() && !made[1].exists());
}

#[test]
fn a_save_that_fails_leaves_the_file_as_it_was() {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().is_root() {
        return; // root writes anywhere
    }
    let d = scratch("failed");
    let p = d.join("server_config.yaml");
    std::fs::write(&p, "servers: {}\n").unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o500)).unwrap();
    let r = save(&p, "servers: {a: {}}\n");
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(r.is_err());
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "servers: {}\n");
    assert_eq!(
        std::fs::read_dir(&d).unwrap().count(),
        1,
        "nothing left beside it"
    );
}

#[test]
fn a_file_changed_underneath_pending_changes_takes_those_that_still_fit() {
    let d = scratch("rebase");
    let p = d.join("config.toml");
    std::fs::write(&p, "[ui]\ndashboard_hz = 1\n[review]\nat_start = true\n").unwrap();
    let (mut doc, w) = Doc::<Config>::load_from(&p).unwrap();
    assert!(w.is_empty() && !doc.changed_on_disk() && doc.handwritten());
    // Two changes pending: the rate, and the review at start.
    doc.now.ui.dashboard_hz = 2.0;
    doc.now.review.at_start = false;
    let pending = doc.pending().unwrap();
    assert_eq!(
        pending.iter().map(|c| c.path.as_str()).collect::<Vec<_>>(),
        ["ui.dashboard_hz", "review.at_start"]
    );
    // Someone else changes the rate in the file meanwhile (and the length, so the stamp
    // differs even within the file system's time resolution).
    std::fs::write(
        &p,
        "[ui]\ndashboard_hz = 4.0\n[review]\nat_start = true\n# theirs\n",
    )
    .unwrap();
    assert!(doc.changed_on_disk());
    assert!(doc.save().is_err(), "never over what changed");
    let (made, conflicts) = doc.rebase(&pending).unwrap();
    assert_eq!(made.len(), 1);
    assert_eq!(made[0].path, "review.at_start");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].0.path, "ui.dashboard_hz");
    assert!(
        conflicts[0].1.contains("is 4.0 now, not 1.0"),
        "{}",
        conflicts[0].1
    );
    assert_eq!(doc.now.ui.dashboard_hz, 4.0, "theirs stays");
    assert!(!doc.now.review.at_start);
    // Saved: the copy is theirs, the file is the one writer's.
    let b = doc.save().unwrap().expect("a copy");
    assert!(std::fs::read_to_string(b).unwrap().contains("# theirs"));
    let (again, _) = Doc::<Config>::load_from(&p).unwrap();
    assert_eq!(again.now, doc.now);
    assert!(!again.handwritten());
}

#[test]
fn a_file_that_isnt_there_is_the_defaults() {
    let d = scratch("missing");
    let p = d.join("config.toml");
    let (mut doc, _) = Doc::<Config>::load_from(&p).unwrap();
    assert_eq!(doc.now, Config::default());
    assert!(!doc.handwritten() && !doc.changed_on_disk());
    doc.now.review.after_run = false;
    assert_eq!(doc.save().unwrap(), None);
    assert!(
        std::fs::read_to_string(&p)
            .unwrap()
            .contains("after_run = false")
    );
}

#[test]
fn file_ids() {
    assert_eq!(FileId::of_path("servers.a.ssh"), FileId::Servers);
    assert_eq!(FileId::of_path("networks"), FileId::Networks);
    assert_eq!(FileId::of_path("ui.dashboard_hz"), FileId::App);
    assert_eq!(FileId::from_word("servers"), Some(FileId::Servers));
    assert_eq!(FileId::from_word("config.toml"), Some(FileId::App));
    assert!(
        FileId::Servers
            .path()
            .ends_with("sentry/server_config.yaml")
    );
}

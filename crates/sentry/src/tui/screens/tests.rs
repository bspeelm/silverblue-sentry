//! Render tests: every screen from fixture data at the design size and the 80×24 minimum.

use std::time::Instant;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::collectors::{disk, fixture, flatpak, gpu, net, ostree, podman, system::SystemSnap};
use crate::config::Config;
use crate::tui::app::{App, render_to_string};
use crate::tui::data::DataStore;
use crate::tui::{Event, ScreenId};

const NOW: i64 = 1_792_800_000;

fn store() -> DataStore {
    let mut d = DataStore::blank("44.20261002.0".into(), "7.2.8-200.fc44.x86_64".into());
    let mut s = SystemSnap {
        cpu_model: "i9-14900K".into(),
        threads: 32,
        cores: Some(24),
        cpu_total: 34.0,
        per_core: (0..32).map(|i| (i * 7 % 100) as f32).collect(),
        load: [0.95, 1.02, 0.91],
        uptime_s: 3 * 86400 + 4 * 3600 + 12 * 60,
        ..Default::default()
    };
    s.mem.total = 64 << 30;
    s.mem.used = 20 << 30;
    s.mem.avail = 40 << 30;
    s.mem.cache = 30 << 30;
    s.swap.total = 8 << 30;
    s.swap.kind = "zram".into();
    s.temps.cpu = Some(53.0);
    s.temps.nvme = vec![44.0];
    s.net.iface = "enp4s0".into();
    for i in 0..200 {
        d.cpu_hist.push((i as f64 * 0.3).sin().abs() * 80.0);
        d.rx_hist.push((i as f64 * 0.2).cos().abs() * 3e6);
        d.tx_hist.push((i as f64 * 0.5).sin().abs() * 2e5);
    }
    d.sys = Some(s);
    d.counts = Some(net::Counts {
        listening: 7,
        established: 23,
    });
    d.gpu.set(Ok(gpu::parse(&fixture("gpu/nvidia-smi.csv"))));
    d.disks
        .set(Ok(disk::parse(&fixture("disk/findmnt.json")).unwrap()));
    let mut ls = net::parse_listen(&fixture("net/ss-listen.txt"));
    net::classify(
        &mut ls,
        &crate::baseline::Baseline {
            listeners: vec!["127.0.0.1:631/cupsd".into()],
            findings: vec![],
        },
    );
    d.net.set(Ok(net::Net {
        listeners: ls,
        established: net::parse_established(&fixture("net/ss-established.txt")),
    }));
    let mut o = ostree::parse(&fixture("ostree/status.json")).unwrap();
    o.booted_kernel = "7.2.8-200.fc44.x86_64".into();
    d.ostree.set(Ok(o));
    d.podman.set(Ok(podman::Podman {
        containers: podman::parse_ps(&fixture("podman/ps.json"), "/var/home/user", NOW, 30)
            .unwrap(),
        images: podman::parse_images(&fixture("podman/images.json")).unwrap(),
        dangling: podman::parse_images(&fixture("podman/dangling.json")).unwrap(),
        volumes: 3,
    }));
    let cfg = crate::config::FlatpakCfg::default();
    let apps = flatpak::parse_list(&fixture("flatpak/list.tsv"))
        .into_iter()
        .map(|(id, origin, version, installation)| {
            let meta = std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/flatpak/metadata")
                    .join(&id),
            )
            .unwrap_or_default();
            let perms = flatpak::perms_from(&meta, &[]);
            flatpak::App {
                flags: flatpak::flags(&perms, &cfg),
                unverified_origin: !cfg.trusted_origins.contains(&origin),
                overridden: id == "com.valvesoftware.Steam",
                perms,
                id,
                origin,
                version,
                installation,
            }
        })
        .collect();
    d.flatpak.set(Ok(flatpak::Flatpak {
        apps,
        remotes: flatpak::parse_remotes(&fixture("flatpak/remotes.tsv")),
        gl_nvidia: flatpak::parse_gl_nvidia(&fixture("flatpak/runtimes.tsv")),
        overrides: vec!["~/.local/share/flatpak/overrides/com.valvesoftware.Steam".into()],
    }));
    d.units.set(Ok(crate::collectors::units::Units {
        failed: crate::collectors::units::parse_failed(&fixture("units/failed.txt"), "system"),
        ..Default::default()
    }));
    // A machine in use: the jobs ran yesterday, so their cadences aren't due.
    let yesterday = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(24);
    for job in ["audit", "update-check", "cleanup-ostree"] {
        d.maint_log.push(crate::maint::log::LogEntry::event(
            "",
            "job",
            job,
            true,
            "done",
            &[],
            yesterday,
        ));
    }
    d
}

fn app(screen: ScreenId) -> App {
    App::for_test(Config::default(), store(), screen)
}

/// Drop the top bar (clock, uptime) so snapshots are stable.
fn body(s: &str) -> String {
    s.lines().skip(1).collect::<Vec<_>>().join("\n")
}

fn key(a: &mut App, c: KeyCode) {
    a.on_event(
        Event::Key(KeyEvent::new(c, KeyModifiers::NONE)),
        Instant::now(),
    );
}

#[test]
fn every_screen_renders_at_both_sizes() {
    for id in crate::tui::SCREENS.ids.iter().copied() {
        for (w, h) in [(158, 41), (80, 24), (120, 30)] {
            let s = render_to_string(&mut app(id), w, h);
            assert!(s.contains("sentry"), "{id:?} {w}x{h}");
            assert!(!s.contains("too small"), "{id:?} {w}x{h}");
        }
    }
    assert!(render_to_string(&mut app(ScreenId::Dash), 70, 20).contains("too small"));
}

#[test]
fn dashboard_wide() {
    let s = render_to_string(&mut app(ScreenId::Dash), 158, 41);
    for want in [
        "CPU",
        "i9-14900K",
        "24c/32t",
        "c31",
        "Memory",
        "RTX 4090",
        "Disks",
        "/sysroot",
        "Network",
        "Status",
        "kernel changes",
    ] {
        assert!(s.contains(want), "missing {want:?}\n{s}");
    }
    insta::assert_snapshot!("dashboard_158x41", body(&s));
}

#[test]
fn dashboard_narrow() {
    let s = render_to_string(&mut app(ScreenId::Dash), 80, 24);
    insta::assert_snapshot!("dashboard_80x24", body(&s));
}

/// Maintenance with one of its views open (`F` report, `J` jobs, `C` cleanup).
fn maint_view(d: DataStore, k: char) -> App {
    let mut a = App::for_test(Config::default(), d, ScreenId::Maint);
    key(&mut a, KeyCode::Char(k));
    a
}

#[test]
fn maintenance_ranks_updates_and_shows_deployments() {
    let s = render_to_string(&mut app(ScreenId::Maint), 158, 41);
    assert!(s.contains("kmod ritual"), "{s}");
    assert!(s.contains("pinned") && s.contains("Deployments"), "{s}");
    assert!(s.contains("Updates waiting"), "{s}");
    insta::assert_snapshot!("maintenance_158x41", body(&s));
}

#[test]
fn other_screens_snapshot() {
    for (id, name) in [
        (ScreenId::Net, "network"),
        (ScreenId::Cont, "containers"),
        (ScreenId::Flat, "flatpaks"),
    ] {
        let s = render_to_string(&mut app(id), 158, 41);
        insta::assert_snapshot!(format!("{name}_158x41"), body(&s));
    }
}

#[test]
fn navigation_and_modals() {
    let mut a = app(ScreenId::Dash);
    key(&mut a, KeyCode::Char('3'));
    assert_eq!(a.slot().screen, ScreenId::Net);
    key(&mut a, KeyCode::Char('l'));
    assert_eq!(a.slot().screen, ScreenId::Cont);
    key(&mut a, KeyCode::Char('h'));
    key(&mut a, KeyCode::Char('h'));
    assert_eq!(a.slot().screen, ScreenId::Proc);
    key(&mut a, KeyCode::Char('H'));
    assert_eq!(a.slot().screen, ScreenId::Hist);
    key(&mut a, KeyCode::Char('q'));
    let s = render_to_string(&mut a, 120, 30);
    assert!(s.contains("Quit sentry?"), "{s}");
    key(&mut a, KeyCode::Esc);
    assert!(!a.win.quit);
    key(&mut a, KeyCode::Char('q'));
    key(&mut a, KeyCode::Char('y'));
    assert!(a.win.quit);
}

#[test]
fn updates_are_applied_by_quick_update() {
    // (It starts a run for real, in the scratch data dir: one at a time.)
    let _turn = runs_turn();
    let mut a = app(ScreenId::Maint);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Enter: install these updates") && s.contains("Enter  install"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        a.slot().screen,
        ScreenId::Upgrade,
        "Enter starts it on Upgrade"
    );
}

#[test]
fn filter_narrows_rows() {
    let mut a = app(ScreenId::Cont);
    key(&mut a, KeyCode::Char('/'));
    for c in "webapp".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("webapp-api") && !s.contains("devbox-one"), "{s}");
    assert!(s.contains("/webapp"), "tab shows active filter");
    key(&mut a, KeyCode::Esc);
    assert!(render_to_string(&mut a, 158, 41).contains("devbox-one"));
}

#[test]
fn command_line() {
    let mut a = app(ScreenId::Dash);
    key(&mut a, KeyCode::Char(':'));
    for c in "flat".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.slot().screen, ScreenId::Flat);
    key(&mut a, KeyCode::Char(':'));
    key(&mut a, KeyCode::Char('q'));
    key(&mut a, KeyCode::Enter);
    assert!(a.win.quit);
}

fn audit_reports() -> Vec<crate::audit::store::Stored> {
    use crate::audit::*;
    let listen = |key: &str| ListenSec {
        proto: "tcp".into(),
        key: key.into(),
        local: false,
    };
    let app = |id: &str, flags: &[&str]| FpApp {
        id: id.into(),
        origin: "flathub".into(),
        installation: "system".into(),
        flags: flags.iter().map(|s| s.to_string()).collect(),
        filesystems: flags.iter().map(|s| s.to_string()).collect(),
        unverified: false,
    };
    let mut a = test_report(Sections {
        listeners: Some(vec![listen("0.0.0.0:22/?")]),
        flatpak: Some(FlatpakSec {
            apps: vec![app("com.visualstudio.code", &["home"])],
            ..Default::default()
        }),
        ostree: Some(OstreeSec {
            layered: vec!["ghostty".into()],
            local: vec!["kmod-nvidia-7.2.8-200.fc44.x86_64".into()],
            kargs: Some("rhgb quiet nvidia-drm.modeset=1".into()),
            ..Default::default()
        }),
        ..Default::default()
    });
    a.taken_at = jiff::Timestamp::from_second(NOW - 30 * 86400).unwrap();
    let mut b = a.clone();
    b.taken_at = jiff::Timestamp::from_second(NOW).unwrap();
    b.sections.listeners = Some(vec![
        listen("0.0.0.0:22/?"),
        listen("0.0.0.0:22000/syncthing"),
    ]);
    b.sections.flatpak = Some(FlatpakSec {
        apps: vec![
            app("com.visualstudio.code", &["host"]),
            app("org.gnome.Boxes", &[]),
        ],
        gl_nvidia: vec![("GL".into(), "610-57-04".into())],
        ..Default::default()
    });
    b.sections.units = Some(UnitsSec {
        failed: vec!["system:systemd-remount-fs.service".into()],
        ..Default::default()
    });
    let base = crate::baseline::Baseline {
        listeners: vec!["0.0.0.0:22/sshd".into()],
        findings: vec![],
    };
    a.findings = findings::derive(&a, None, &base, &Config::default());
    b.findings = findings::derive(&b, Some(&a), &base, &Config::default());
    vec![
        store::Stored {
            path: "/r/2026-09-23.json".into(),
            report: a,
        },
        store::Stored {
            path: "/r/2026-10-23.json".into(),
            report: b,
        },
    ]
}

#[test]
fn audit_screen() {
    let mut a = maint_view(store(), 'F');
    let empty = render_to_string(&mut a, 158, 41);
    assert!(empty.contains("No audit yet."), "{empty}");
    let mut d = store();
    d.reports.set(Ok(audit_reports()));
    d.baseline.listeners = vec!["0.0.0.0:22/sshd".into()];
    let mut a = maint_view(d, 'F');
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("audit_158x41", body(&s));
    assert!(
        s.contains("6 Maintenance 3"),
        "badge counts what's now or soon: {s}"
    );
    // Browse to the first report: no diff yet.
    key(&mut a, KeyCode::Char('['));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Nothing to compare against yet"), "{s}");
    let s = render_to_string(&mut a, 80, 24);
    assert!(s.contains("Findings"), "{s}");
}

#[test]
fn jobs_and_cleanup_screens() {
    use crate::exec::Cmd;
    use crate::jobs::JobId;
    use crate::jobs::plan::{Act, Item, Plan};
    let mut d = store();
    d.maint_log.clear();
    let at =
        |days_ago: i64| jiff::Timestamp::now() - jiff::SignedDuration::from_hours(24 * days_ago);
    // The jobs' runs are in the maintenance log, newest first.
    for (name, days, ok) in [
        ("update-check", 1, false),
        ("audit", 3, true),
        ("cleanup-podman", 41, true),
    ] {
        let summary = if ok {
            "2 item(s) done"
        } else {
            "rpm-ostree: timeout"
        };
        d.maint_log.push(crate::maint::log::LogEntry::event(
            "",
            "job",
            name,
            ok,
            summary,
            &[],
            at(days),
        ));
    }
    let item = |job, key: &str, label: &str, bytes: Option<u64>, run: bool, on: bool| Item {
        job,
        key: key.into(),
        label: label.into(),
        bytes,
        preview: vec![format!("would remove {label}")],
        act: if run {
            Act::Run(Cmd::host("true"))
        } else {
            Act::ListOnly
        },
        default_on: on,
    };
    d.cleanup.set(Ok(vec![
        Plan {
            items: vec![
                item(
                    JobId::CleanupOstree,
                    "repomd",
                    "rpm-ostree cleanup -m",
                    Some(214 << 20),
                    true,
                    true,
                ),
                item(
                    JobId::CleanupOstree,
                    "base",
                    "rpm-ostree cleanup -b",
                    None,
                    true,
                    false,
                ),
            ],
            notes: vec![],
        },
        Plan {
            items: vec![item(
                JobId::CleanupFlatpak,
                "gl:x",
                "old GL.nvidia-610-57-04",
                Some(855 << 20),
                true,
                true,
            )],
            notes: vec![],
        },
        Plan {
            items: vec![item(
                JobId::CleanupCache,
                "report",
                "~/.cache (opted-in: none)",
                None,
                false,
                false,
            )],
            notes: vec![],
        },
    ]));
    let mut a = App::for_test(Config::default(), d, ScreenId::Maint);
    let s = render_to_string(&mut a, 158, 41);
    // Due by their cadence: tasks. The failed update check folds into its task's row.
    for want in ["routine  Clean up", "soon     Check for updates"] {
        assert!(s.contains(want), "{want}: {s}");
    }
    assert!(!s.contains("update-check failed  "), "one row: {s}");
    assert!(!s.contains("Audit this machine"), "audited 3 days ago: {s}");
    key(&mut a, KeyCode::Char('7'));
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("cleanup_158x41", body(&s));
    // Toggle the opt-in item: the total grows by nothing (no estimate) but it's now checked.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char(' '));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("[x] rpm-ostree cleanup -b"), "{s}");
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Confirm cleanup") && s.contains("run 2 job(s)"),
        "{s}"
    );
    // Auto mode never answers this box: with it on, cleanup asks all the same.
    key(&mut a, KeyCode::Esc);
    auto_on(&mut a);
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Confirm cleanup"), "{s}");
    assert!(a.box_yes_for_test().is_some() && a.pane_for_test().is_none());
}

#[test]
fn upgrade_screen_idle_and_running() {
    use crate::tui::wf::{LogKind, Session};
    use crate::workflows::runner::{self, Next};
    use crate::workflows::state::RunState;
    use crate::workflows::{SEEDS, lint, parse};
    let mut d = store();
    let infos: Vec<crate::tui::screens::upgrade::WfInfo> = SEEDS
        .iter()
        .map(|(name, body)| {
            let wf = parse(body).unwrap();
            crate::tui::screens::upgrade::WfInfo {
                entry: crate::workflows::Entry {
                    name: name.to_string(),
                    path: format!("/var/home/user/.config/sentry/workflows/{name}.toml").into(),
                    issues: lint(&wf),
                    wf: Ok(wf),
                },
                last: None,
            }
        })
        .collect();
    d.workflows.set(Ok(infos));
    let mut a = App::for_test(Config::default(), d, ScreenId::Upgrade);
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("upgrade_idle_158x41", body(&s));

    // Kernel path, waiting at the ritual's confirm gate.
    let wf = parse(SEEDS[0].1).unwrap();
    let ids: Vec<String> = wf.steps.iter().map(|s| s.id.clone()).collect();
    let mut st = RunState::new("quick-update", &ids, Default::default());
    st.started = jiff::Timestamp::from_second(NOW).unwrap();
    st.vars
        .insert("pending_kernel".into(), "7.2.11-200.fc44.x86_64".into());
    st.vars.insert(
        "old_kmod".into(),
        "kmod-nvidia-7.2.8-200.fc44.x86_64-3:615.71.09-3.fc44.x86_64".into(),
    );
    for (i, id) in ids.iter().enumerate() {
        match id.as_str() {
            "preview" | "flatpak-idle" | "flatpak" | "kmod-guard" => {
                runner::finish(&mut st, i, 0, None)
            }
            "toolboxes" => runner::skip(&mut st, i, "skipped by user"),
            "upgrade-routine" | "reboot-routine" => {
                runner::skip(&mut st, i, "when !kernel_changed is false")
            }
            _ => {}
        }
    }
    let ritual = ids.iter().position(|i| i == "upgrade-ritual").unwrap();
    let mut sess = Session::for_test(wf, st, Next::Confirm(ritual));
    sess.push(
        "▶ 5/17 Exactly one layered kmod-nvidia package present",
        LogKind::Info,
    );
    sess.push(
        "✓ kmod-nvidia-7.2.8-200.fc44.x86_64-3:615.71.09-3.fc44.x86_64",
        LogKind::Out,
    );
    let mut a = App::for_test(Config::default(), store(), ScreenId::Upgrade);
    a.set_wf(sess);
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("upgrade_running_158x41", body(&s));
    assert!(s.contains("0 Upgrade ●"), "{s}");
    // Elsewhere: the banner.
    key(&mut a, KeyCode::Char('1'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("↻ workflow quick-update · step 8/19 Stage upgrade, dropping kmod-nvidia"),
        "{s}"
    );
    assert!(s.contains("press 0 to continue"));
    let s = render_to_string(&mut a, 80, 24);
    assert!(s.contains("workflow"), "{s}");
}

#[test]
fn history_screen() {
    use crate::recorder::ring::Rec;
    use crate::tui::screens::history::HistData;
    let newest = jiff::Timestamp::now().as_second();
    let recs: Vec<Rec> = (0..2160)
        .map(|k| {
            let x = k as f32 / 60.0;
            Rec {
                ts: newest - (2160 - k) * 40,
                cpu: 30.0 + 20.0 * x.sin() + if k == 1000 { 60.0 } else { 0.0 },
                mem_gib: 12.0,
                rx: 1e6 * (1.0 + x.cos()),
                cpu_temp: 50.0,
                gpu: f32::NAN,
                gpu_temp: f32::NAN,
                disk_pct: 30.0,
                ..Default::default()
            }
        })
        .collect();
    let mut d = store();
    d.history.set(Ok(Box::new(HistData {
        recs,
        bytes: 3 << 20,
        ..Default::default()
    })));
    let mut a = App::for_test(Config::default(), d, ScreenId::Hist);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("History · last 24h"), "{s}");
    assert!(
        s.contains("cpu %") && s.contains("net rx") && s.contains("now"),
        "{s}"
    );
    assert!(!s.contains("gpu %"), "no GPU samples, no GPU row");
    assert!(
        s.contains("max 74"),
        "stats come from raw samples, not bucket means: {s}"
    );
    assert!(s.contains("recorder off"), "{s}");
    key(&mut a, KeyCode::Char('['));
    assert!(render_to_string(&mut a, 158, 41).contains("last 6h"));
    key(&mut a, KeyCode::Left);
    assert!(render_to_string(&mut a, 158, 41).contains("until"));
    assert!(render_to_string(&mut a, 80, 24).contains("History"));
}

#[test]
fn containers_toolbox_updates() {
    use crate::collectors::toolbox::{BoxUpdates, PkgUpdate, parse_exec};
    let mut d = store();
    let (updates, _) = parse_exec(&fixture("toolbox/exec-output.txt"));
    let at = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(2);
    let mut m = std::collections::BTreeMap::new();
    m.insert(
        "devbox-one".to_string(),
        BoxUpdates {
            checked_at: at,
            updates,
            error: None,
        },
    );
    let names: Vec<String> = d
        .podman
        .get()
        .unwrap()
        .containers
        .iter()
        .filter(|c| c.kind != crate::collectors::podman::Kind::Podman && c.name != "devbox-one")
        .map(|c| c.name.clone())
        .collect();
    for n in names {
        m.insert(
            n,
            BoxUpdates {
                checked_at: at,
                updates: vec![PkgUpdate {
                    name: "bash.x86_64".into(),
                    old: Some("5.3.3-1.fc44".into()),
                    new: "5.3.4-1.fc44".into(),
                    repo: "updates".into(),
                }],
                error: None,
            },
        );
    }
    d.tbx_updates.set(Ok(crate::cache::Cached {
        fetched_at: at,
        data: m,
    }));
    let mut a = App::for_test(Config::default(), d, ScreenId::Cont);
    // Select the toolbox with the fixture's updates.
    key(&mut a, KeyCode::Char('/'));
    for c in "devbox".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("containers_updates_158x41", body(&s));
    assert!(s.contains("3 ↑"), "{s}");
    assert!(s.contains("259.8-1.fc44 → 259.10-1.fc44"), "{s}");
    assert!(s.contains("checked 2h ago"), "{s}");
    key(&mut a, KeyCode::Char('u'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Upgrade 3 package(s) in devbox-one?"), "{s}");
    assert!(
        s.contains("podman exec --user root devbox-one dnf -y upgrade"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('n'));
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('U'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Upgrade all toolboxes"), "{s}");
    assert!(render_to_string(&mut a, 80, 24).contains("Containers"));
}

#[test]
fn ask_claude_context_per_tab() {
    use crate::tui::screens::{Screens, View};
    use crate::tui::theme::Theme;
    let mut d = store();
    d.reports.set(Ok(audit_reports()));
    let cfg = Config::default();
    let t = Theme::truecolor();
    let sh = d.records();
    let v = View {
        d: &d,
        sh: &sh,
        cfg: &cfg,
        t: &t,
        filter: None,
        wf: None,
        everything: false,
    };
    let s = Screens::default();
    let expect: &[(ScreenId, &str)] = &[
        (ScreenId::Dash, "sentry's dashboard status"),
        (ScreenId::Proc, "no process selected"), // processes aren't sampled in the fixture store
        (ScreenId::Net, "known service:"),
        (ScreenId::Maint, "A finding from sentry's audit"),
        (ScreenId::Cont, "A podman container"),
        (ScreenId::Flat, "permissions = metadata + overrides"),
        (ScreenId::Upgrade, "no workflow selected"),
        (ScreenId::Hist, "no recorder data"),
    ];
    for (id, want) in expect {
        let text = match s.ask(*id, &v) {
            Ok(a) => {
                assert!(!a.question.is_empty() && !a.subject.is_empty(), "{id:?}");
                a.prompt()
            }
            Err(e) => e,
        };
        assert!(text.contains(want), "{id:?}: {text}");
    }
}

#[test]
fn chat_pane_and_consent_render() {
    use crate::claude::Ask;
    use crate::tui::chat::{Chat, Kind};
    let mut c = Chat::new(Ask::new("audit · Unknown service on tcp/27500", "ctx", "q"));
    c.begin_turn("Explain this on my machine.", 1, 1);
    c.push(Kind::Tool, "$ ss -tlnp 'sport = :27500'");
    c.push(Kind::Tool, "  → 2 lines");
    c.push(
        Kind::Claude,
        "Port 27500 is owned by root; check it with sudo ss.",
    );
    c.on_exit(0);
    c.session = Some("s1".into());
    let mut a = App::for_test(Config::default(), store(), ScreenId::Maint);
    a.set_chat(c);
    let s = render_to_string(&mut a, 120, 30);
    assert!(
        s.contains("Claude · audit · Unknown service on tcp/27500"),
        "{s}"
    );
    assert!(s.contains("you    Explain this on my machine."), "{s}");
    assert!(s.contains("$ ss -tlnp 'sport = :27500'"), "{s}");
    assert!(s.contains("claude Port 27500 is owned by root"), "{s}");
    assert!(
        s.contains("follow-up") && s.contains("continue in Claude Code"),
        "{s}"
    );
    // Typing goes to the follow-up line; Enter sends what you typed (no box: you wrote it).
    for ch in "who owns it?".chars() {
        key(&mut a, KeyCode::Char(ch));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 120, 30);
    assert!(
        s.contains("you    who owns it?") && s.contains("thinking"),
        "{s}"
    );
    a.on_event(
        Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        Instant::now(),
    );
    key(&mut a, KeyCode::Esc);
    let s = render_to_string(&mut a, 120, 30);
    assert!(!s.contains("Claude ·"), "Esc closes the pane: {s}");
}

#[test]
fn a_failed_cleanup_job_opens_cleanup_focused() {
    use crate::exec::Cmd;
    use crate::jobs::JobId;
    use crate::jobs::plan::{Act, Item, Plan};
    let mut d = store();
    let item = |job, key: &str, on| Item {
        job,
        key: key.into(),
        label: key.into(),
        bytes: Some(1 << 20),
        preview: vec![],
        act: Act::Run(Cmd::host("true")),
        default_on: on,
    };
    d.cleanup.set(Ok(vec![
        Plan {
            items: vec![item(JobId::CleanupOstree, "repomd", true)],
            notes: vec![],
        },
        Plan {
            items: vec![item(JobId::CleanupPodman, "dangling", true)],
            notes: vec![],
        },
    ]));
    d.maint_log.insert(
        0,
        crate::maint::log::LogEntry::event(
            "",
            "job",
            "cleanup-podman",
            false,
            "podman: not found",
            &[],
            jiff::Timestamp::now(),
        ),
    );
    let mut a = App::for_test(Config::default(), d, ScreenId::Maint);
    a.apply_for_test(vec![crate::tui::app::Effect::MaintFind(
        "job:cleanup-podman".into(),
    )]);
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("from dry-run · cleanup-podman selected"), "{s}");
    assert!(
        s.contains("[ ] repomd") && s.contains("[x] dangling"),
        "{s}"
    );
}

#[test]
fn dashboard_rows_jump_to_tabs() {
    let mut a = app(ScreenId::Dash);
    render_to_string(&mut a, 158, 41);
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert_eq!(a.slot().screen, ScreenId::Maint);
    assert!(
        s.contains("soon  Updates waiting"),
        "the updates row selects its recommendation: {s}"
    );
    // The findings row (after updates and the kernel note) lands on a finding.
    let mut d = store();
    d.reports.set(Ok(audit_reports()));
    let mut a = App::for_test(Config::default(), d, ScreenId::Dash);
    render_to_string(&mut a, 158, 41);
    for _ in 0..3 {
        key(&mut a, KeyCode::Char('j'));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("What   "), "a finding's details: {s}");
}

#[test]
fn maintenance_keys_and_views() {
    let mut d = store();
    d.reports.set(Ok(audit_reports()));
    let mut a = App::for_test(Config::default(), d, ScreenId::Maint);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("x  expected"),
        "a finding is selected first: {s}"
    );
    // z: put it off (a choice of 7/30/90 days).
    key(&mut a, KeyCode::Char('z'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("in 30 days"), "{s}");
    key(&mut a, KeyCode::Esc);
    // x marks it expected: it leaves the list.
    let before = render_to_string(&mut a, 158, 41);
    key(&mut a, KeyCode::Char('x'));
    assert!(render_to_string(&mut a, 158, 41).contains("Mark it expected"));
    key(&mut a, KeyCode::Char('y'));
    let after = render_to_string(&mut a, 158, 41);
    assert_ne!(before, after);
    // The report opens as a view and Esc comes back.
    key(&mut a, KeyCode::Char('F'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Maintenance › Audit report"), "{s}");
    key(&mut a, KeyCode::Esc);
    assert!(render_to_string(&mut a, 158, 41).contains("Recommended"));
    // Cleanup is its own screen: C goes there.
    key(&mut a, KeyCode::Char('C'));
    assert_eq!(a.slot().screen, ScreenId::Clean);
}

#[test]
fn audit_fix_key() {
    // Without Claude Code, Enter (or f) is sentry's own list of fixes.
    crate::claude::TEST_AVAILABLE.with(|c| c.set(false));
    let mut d = store();
    d.reports.set(Ok(audit_reports()));
    d.baseline.listeners = vec!["0.0.0.0:22/sshd".into()];
    let mut a = maint_view(d, 'F');
    // Row 1 is "com.visualstudio.code gained filesystem=host": one fix → confirm box.
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Fix    press Enter: Take the permission away"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("$ flatpak override --user --nofilesystem=host com.visualstudio.code"),
        "{s}"
    );
    assert!(
        s.contains("undo: flatpak override --user --filesystem=host com.visualstudio.code"),
        "{s}"
    );
    assert!(s.contains("audits again"), "{s}");
    key(&mut a, KeyCode::Char('n'));
    // Row 2 is the failed unit: several fixes → numbered choice.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('f'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Fix · pick one"), "{s}");
    assert!(s.contains(" 1  Show why it failed (read-only)"), "{s}");
    assert!(s.contains(" 3  Clear the failed state"), "{s}");
    key(&mut a, KeyCode::Esc);
    assert!(!render_to_string(&mut a, 158, 41).contains("pick one"));
    // A row without a fix explains why.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('f'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Remove it from Cleanup") || s.contains("Cleanup"),
        "{s}"
    );
}

#[test]
fn fixing_a_finding_is_an_apply_session() {
    use crate::apply::session::{End, Phase, Turn};
    let mut d = store();
    d.reports.set(Ok(audit_reports()));
    d.baseline.listeners = vec!["0.0.0.0:22/sshd".into()];
    let mut a = maint_view(d, 'F');
    render_to_string(&mut a, 158, 41);
    // `f`: an apply session (no chat, no proposals), the finding and sentry's fixes in its
    // brief; nothing leaves before Enter.
    key(&mut a, KeyCode::Char('f'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("brief › investigate") && s.contains("Enter  start"),
        "{s}"
    );
    let p = a.consent_text().unwrap();
    assert!(
        p.contains("sentry's known fixes") && p.contains("```sentry-apply"),
        "{p}"
    );
    key(&mut a, KeyCode::Enter);
    a.apply_answer_for_test(
        "Mask it.\n```sentry-apply\nsummary = \"mask passim\"\nrollback = \"unmask it\"\n\
         [[step]]\ntitle = \"Check\"\ncheck = \"true\"\n```",
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        !s.contains("Proposed commands") && s.contains("Enter  apply the plan"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    // A quiet step still shows it's alive.
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("… running 0:00, no output yet"), "{s}");
    a.apply_step_exit_for_test(0);
    // The plan ran: sentry audits again before Claude verifies.
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("sentry is auditing again"), "{s}");
    a.apply_step_exit_for_test(0);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Claude is checking the result"), "{s}");
    assert_eq!(
        a.apply_session().unwrap().phase,
        Phase::Thinking(Turn::Verify)
    );
    a.apply_answer_for_test("```sentry-verdict\nstatus = \"done\"\nsummary = \"masked\"\n```");
    assert_eq!(a.apply_session().unwrap().phase, Phase::Settled(End::Done));
    let e = &a.log_for_test()[0];
    assert!(
        e.head.tags.iter().any(|t| t.starts_with("finding:")),
        "{:?}",
        e.head.tags
    );
    // Enter closes it.
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Enter  close"), "{s}");
    key(&mut a, KeyCode::Enter);
    assert!(a.apply_session().is_none());
}

#[test]
fn upgrade_failed_step_fix_with_claude() {
    use crate::tui::wf::Session;
    use crate::workflows::parse;
    use crate::workflows::runner::{self, Next};
    use crate::workflows::state::RunState;
    let wf = parse(
        r#"
name = "flag-test"
description = "test"
[[steps]]
id = "flag"
title = "Flag file exists"
run = "test -f /tmp/flag"
gate = "auto"
on_fail = "stop"
[[steps]]
id = "after"
title = "Afterwards"
run = "true"
gate = "auto"
"#,
    )
    .unwrap();
    let ids: Vec<String> = wf.steps.iter().map(|s| s.id.clone()).collect();
    let mut st = RunState::new("flag-test", &ids, Default::default());
    runner::finish(&mut st, 0, 1, None);
    let sess = Session::for_test(wf, st, Next::Stopped(0));
    let facts = crate::tui::screens::upgrade::step_facts(&sess).unwrap();
    assert_eq!(facts.cmd, "test -f /tmp/flag");
    let keys: Vec<&str> = facts.actions.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, ["retry", "done by hand", "skip", "abandon"]);
    assert_eq!(facts.later, ["after: Afterwards · true"]);
    let mut a = App::for_test(Config::default(), store(), ScreenId::Upgrade);
    a.set_wf(sess);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("[f] fix with Claude"), "{s}");
    // `f`: an apply session for the step; when it's fixed, Enter retries the step.
    key(&mut a, KeyCode::Char('f'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Sent to Claude") && s.contains("step 1/2: Flag file exists"),
        "{s}"
    );
    assert!(
        a.consent_text()
            .unwrap()
            .contains("sentry retries the step")
    );
    key(&mut a, KeyCode::Enter);
    a.apply_answer_for_test(
        "Create it.\n```sentry-apply\nsummary = \"create the flag\"\n\
         [[step]]\ntitle = \"Create\"\nrun = \"touch /tmp/flag\"\n```",
    );
    key(&mut a, KeyCode::Enter);
    a.apply_step_exit_for_test(0);
    a.apply_answer_for_test("```sentry-verdict\nstatus = \"done\"\nsummary = \"it's there\"\n```");
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Enter  retry the step"), "{s}");
    key(&mut a, KeyCode::Enter);
    // The session is done with; the step is retried (here: nothing runs, the run shows).
    assert!(a.apply_session().is_none());
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("flag-test"), "{s}");
}

#[test]
fn a_dry_run_that_finds_nothing_skips_the_step() {
    use crate::tui::wf::{Exec, Session};
    use crate::workflows::parse;
    use crate::workflows::runner::Next;
    use crate::workflows::state::{RunState, StepStatus};
    let wf = parse(
        r#"
name = "up"
description = "test"
[[steps]]
id = "upgrade"
title = "Stage upgrade"
run = "rpm-ostree upgrade"
gate = "confirm"
[[steps]]
id = "after"
title = "Afterwards"
run = "true"
gate = "confirm"
"#,
    )
    .unwrap();
    let ids: Vec<String> = wf.steps.iter().map(|s| s.id.clone()).collect();
    let session = || {
        let st = RunState::new("up", &ids, Default::default());
        Session::for_test(wf.clone(), st, Next::Confirm(0))
    };
    // Enter: the dry run first.
    let mut s = session();
    match s.go() {
        Ok(Some(Exec::Stream { dry: true, .. })) => {}
        _ => panic!("expected the dry run"),
    }
    // Exit 77 from --preview: nothing to upgrade, the step is skipped, the next one is up.
    s.on_exit(0, true, 77, None);
    let st = &s.run.state.steps[0];
    assert_eq!(st.status, StepStatus::Skipped);
    assert_eq!(st.dry_code, Some(77));
    assert!(st.note.as_deref().unwrap_or("").contains("nothing to do"));
    assert!(matches!(s.next, Next::Confirm(1)));
    // Any other failure stays a failed dry run, with its code kept.
    let mut s = session();
    let _ = s.go();
    s.on_exit(0, true, 1, None);
    let st = &s.run.state.steps[0];
    assert_eq!(st.status, StepStatus::Pending);
    assert_eq!((st.dry_code, st.dry_ok), (Some(1), false));
    assert!(matches!(s.next, Next::Confirm(0)));
}

#[test]
fn upgrade_stopped_step_done_by_hand_or_skipped() {
    use crate::tui::wf::Session;
    use crate::workflows::parse;
    use crate::workflows::runner::{self, Next};
    use crate::workflows::state::RunState;
    let wf = parse(
        r#"
name = "flag-test"
description = "test"
[[steps]]
id = "flag"
title = "Flag file exists"
run = "test -f /tmp/flag"
gate = "auto"
on_fail = "stop"
[[steps]]
id = "after"
title = "Afterwards"
run = "true"
gate = "confirm"
"#,
    )
    .unwrap();
    let ids: Vec<String> = wf.steps.iter().map(|s| s.id.clone()).collect();
    let stopped = || {
        let mut st = RunState::new("flag-test", &ids, Default::default());
        runner::finish(&mut st, 0, 1, None);
        Session::for_test(wf.clone(), st, Next::Stopped(0))
    };
    for (k, title, yes) in [
        ('d', "Done by hand", "mark done"),
        ('s', "Skip step", "skip it"),
    ] {
        let mut a = App::for_test(Config::default(), store(), ScreenId::Upgrade);
        a.set_wf(stopped());
        let s = render_to_string(&mut a, 158, 41);
        assert!(
            s.contains("[d] done by hand   [s] skip   [L] log") && !s.contains("Enter  run"),
            "{s}"
        );
        key(&mut a, KeyCode::Char(k));
        let s = render_to_string(&mut a, 158, 41);
        assert!(s.contains(title) && s.contains(yes), "{s}");
        assert!(s.contains("$ test -f /tmp/flag"), "{s}");
        key(&mut a, KeyCode::Char('y'));
        let s = render_to_string(&mut a, 158, 41);
        assert!(s.contains("▶   2 Afterwards"), "{k}: {s}");
    }
    // A narrow window wraps the card's key line instead of cutting keys off.
    let mut a = App::for_test(Config::default(), store(), ScreenId::Upgrade);
    a.set_wf(stopped());
    let s = render_to_string(&mut a, 100, 34);
    assert!(
        s.contains("[a] abandon") && s.contains("[d] done by hand"),
        "{s}"
    );
    // `l` stays next-tab on Upgrade too.
    let mut a = App::for_test(Config::default(), store(), ScreenId::Upgrade);
    a.set_wf(stopped());
    key(&mut a, KeyCode::Char('l'));
    assert_ne!(a.slot().screen, ScreenId::Upgrade);
}

#[test]
fn an_ended_run_is_logged_with_a_note_and_claude_can_look_back() {
    use crate::tui::wf::Session;
    use crate::workflows::parse;
    use crate::workflows::runner::{self, Next};
    use crate::workflows::state::RunState;
    let wf = parse(
        r#"
name = "flag-test"
description = "test"
[[steps]]
id = "flag"
title = "Flag file exists"
run = "test -f /tmp/flag"
gate = "auto"
on_fail = "stop"
[[steps]]
id = "after"
title = "Afterwards"
run = "true"
gate = "confirm"
"#,
    )
    .unwrap();
    let ids: Vec<String> = wf.steps.iter().map(|s| s.id.clone()).collect();
    let mut st = RunState::new("flag-test", &ids, Default::default());
    runner::finish(&mut st, 0, 1, None);
    let mut a = App::for_test(Config::default(), store(), ScreenId::Upgrade);
    a.set_wf(Session::for_test(wf, st, Next::Stopped(0)));
    // Abandoned: the run has ended, so the log asks for a note.
    key(&mut a, KeyCode::Char('a'));
    key(&mut a, KeyCode::Char('y'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("flag-test abandoned · for the log, what to know next time"),
        "{s}"
    );
    for c in "flag needs creating first".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert!(render_to_string(&mut a, 158, 41).contains("noted in the maintenance log"));
    // `A` on the ended run: its steps and what failed, not "complete".
    key(&mut a, KeyCode::Char('A'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Sent to Claude") && s.contains("has ended (abandoned)"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    // `v`: Records on its Log, Esc closes it.
    key(&mut a, KeyCode::Char('v'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Records") && s.contains("Maintenance log   4 run(s)"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    assert!(!render_to_string(&mut a, 158, 41).contains("Maintenance log"));
}

#[test]
fn esc_hides_a_running_chat_and_a_brings_it_back() {
    use crate::claude::Ask;
    use crate::tui::chat::Chat;
    let mut c = Chat::new(Ask::new("dashboard", "ctx", "q"));
    c.begin_turn("q", 1, u32::MAX);
    let mut a = App::for_test(Config::default(), store(), ScreenId::Dash);
    a.set_chat(c);
    assert!(render_to_string(&mut a, 158, 41).contains("hide (it carries on)"));
    key(&mut a, KeyCode::Esc);
    let s = render_to_string(&mut a, 158, 41);
    assert!(!s.contains("Claude · dashboard"), "hidden: {s}");
    assert!(s.contains("Claude answering…"), "the A chip says so: {s}");
    // Keys go to the screen again.
    key(&mut a, KeyCode::Char('2'));
    assert_eq!(a.slot().screen, ScreenId::Proc);
    key(&mut a, KeyCode::Char('A'));
    assert!(render_to_string(&mut a, 158, 41).contains("Claude · dashboard"));
}

#[test]
fn a_workflows_plan_is_its_sessions_and_claude_reviews_maintenance() {
    use sentry_core::apply::session::Phase;
    let mut a = app(ScreenId::Maint);
    // p reads the saved plan: there is none yet, and no second Claude flow writes one.
    key(&mut a, KeyCode::Char('p'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("no plan saved for quick-update yet"), "{s}");
    assert!(a.writer_for_test().is_none());
    // A → 1 on the row: one session. It researches first (the ledger, the notes, the web),
    // and its plan is kept under the workflow.
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Char('1'));
    let p = a.consent_text().expect("the session's brief");
    assert!(
        p.contains("Maintenance ledger:")
            && p.contains("start from the maintenance")
            && p.contains("status = \"wait\""),
        "{p}"
    );
    key(&mut a, KeyCode::Enter);
    a.apply_answer_for_test(
        "TARGET: now\nNothing in the log against it.\n\n```sentry-apply\nsummary = \"update\"\n\
         [[step]]\ntitle = \"Run it\"\nworkflow = \"quick-update\"\n```",
    );
    assert_eq!(a.apply_session().unwrap().phase, Phase::Review);
    let doc = a.slot().shared.plans.get("quick-update").expect("kept");
    assert_eq!(doc.head.status, crate::maint::plan::PlanStatus::Ready);
    assert!(
        doc.body.starts_with("Nothing in the log") && doc.body.contains("```sentry-apply"),
        "{}",
        doc.body
    );
    key(&mut a, KeyCode::Esc);
    // p now opens it, to read; x in its view asks before dropping it.
    key(&mut a, KeyCode::Char('p'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Nothing in the log against it."), "{s}");
    assert!(s.contains("P  start over") && !s.contains("revise"), "{s}");
    key(&mut a, KeyCode::Char('x'));
    assert!(render_to_string(&mut a, 158, 41).contains("Drop the plan"));
    key(&mut a, KeyCode::Char('n'));
    // Enter there: the session opens on that plan, to approve; nothing is sent first.
    key(&mut a, KeyCode::Enter);
    let sess = a.apply_session().expect("a session");
    assert_eq!(sess.phase, Phase::Review);
    assert!(sess.can_approve() && sess.chat.live.is_none());
    key(&mut a, KeyCode::Esc);
    // R with no review yet: the review window on its brief; nothing is sent before Enter.
    key(&mut a, KeyCode::Char('R'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Maintenance review") && s.contains("Enter starts the review"),
        "{s}"
    );
    assert!(s.contains("Enter  start the review"), "the key bar: {s}");
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("C-c  stop Claude"), "Claude is writing: {s}");
}

#[test]
fn a_ready_plan_goes_with_its_workflow_however_it_starts() {
    use sentry_core::apply::session::Phase;
    let mut a = app(ScreenId::Maint);
    // A plan from before plans were a session's: its document and its workflow's values.
    a.plan_written_for_test(
        "quick-update",
        Default::default(),
        "TARGET: 44\n# Plan: quick-update\n\n## Before\n- back up",
    );
    // Its row: Enter opens the session straight on it, as the one workflow step.
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Plan ready: quick-update"), "{s}");
    a.apply_for_test(vec![crate::tui::app::Effect::PlanApply(
        "quick-update".into(),
    )]);
    let sess = a.apply_session().expect("a session");
    assert_eq!(sess.phase, Phase::Review);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("back up")
            && s.contains("workflow quick-update")
            && s.contains("apply the plan"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    // In the Plan view, A → 2 asks about it, told the plan and the workflow.
    a.apply_for_test(vec![crate::tui::app::Effect::PlanOpen(
        "quick-update".into(),
    )]);
    assert!(render_to_string(&mut a, 158, 41).contains("A  claude"));
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Char('2'));
    let p = a.consent_text().expect("consent");
    assert!(
        p.contains("The plan for it, written earlier") && p.contains("back up"),
        "{p}"
    );
}

const REVIEW_WITH_CHANGES: &str = "Reading the ledger.\n# Maintenance review\n\n## Now\n- update\n\n\
```sentry-changes\n\
[[add]]\nid = \"ups\"\ntitle = \"Check the UPS battery\"\nwhy = \"It is three years old.\"\n\
level = \"soon\"\nevery = \"90d\"\ndo = \"by-hand\"\nsteps = \"Run `upsc ups` and read the charge.\"\n\n\
[[add]]\nid = \"update\"\ntitle = \"Install the waiting updates\"\nlevel = \"routine\"\n\
do = \"run quick-update\"\n\n\
[[change]]\ntask = \"job-audit\"\nevery = \"14d\"\nwhy = \"Findings come often.\"\n\n\
[[remove]]\ntask = \"nope\"\nwhy = \"Not there.\"\n```\n";

const REVIEW_LATER: &str = "# Maintenance review\n\n## Soon\n- nothing\n\n```sentry-changes\n\
[[later]]\nkey = \"updates\"\nuntil = 2099-01-01\nwhy = \"Nothing urgent in them.\"\n\n\
[[remove]]\ntask = \"ups\"\nwhy = \"The UPS is gone.\"\n\n\
[[remove]]\ntask = \"job-cleanup\"\nwhy = \"The disk is never tight.\"\n```\n";

#[test]
fn a_review_s_changes_apply_with_one_enter() {
    let mut a = app(ScreenId::Maint);
    a.review_written_for_test(REVIEW_WITH_CHANGES);
    let s = render_to_string(&mut a, 158, 41);
    // Where it's kept is under the test's scratch dir.
    let shown = body(&s);
    let shown: Vec<&str> = shown.lines().filter(|l| !l.contains("/reviews/")).collect();
    insta::assert_snapshot!("review_158x41", shown.join("\n"));
    assert!(s.contains("3 changes · Enter applies the 3 ticked"), "{s}");
    assert!(
        s.contains("Check the UPS battery · every 90d") && s.contains("every 30d → every 14d"),
        "{s}"
    );
    assert!(s.contains("not used: remove nope: no such task"), "{s}");
    assert!(
        !s.contains("sentry-changes"),
        "the block isn't shown as text: {s}"
    );
    // Space unticks the second; Enter applies the rest together, with no box.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char(' '));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Enter applies the 2 ticked") && s.contains("[ ]"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("2 applied · 1 skipped"), "{s}");
    assert!(
        s.contains("review: 2 applied · 1 skipped"),
        "the toast: {s}"
    );
    assert!(!s.contains("[x]") && s.contains("✓"), "{s}");
    // Enter again changes nothing.
    key(&mut a, KeyCode::Enter);
    assert!(render_to_string(&mut a, 158, 41).contains("2 applied · 1 skipped"));
    // The log says what was applied.
    let log = a.log_for_test();
    assert_eq!(log[0].head.kind, "review");
    assert!(
        log[0].body.contains("applied: add task ups")
            && log[0].body.contains("skipped: add task update")
            && log[0].body.contains("applied: change task job-audit"),
        "{}",
        log[0].body
    );
    key(&mut a, KeyCode::Esc);
    // Records › Tasks: the built-in audit cadence is now tasks.toml's, every 14d.
    for c in ":tasks".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("every 14d") && !s.contains("Install the waiting updates"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    // On Maintenance: the task, its steps, d to mark it done.
    a.apply_for_test(vec![crate::tui::app::Effect::MaintFind("task:".into())]);
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("maintenance_task_158x41", body(&s));
    assert!(
        s.contains("Check the UPS battery") && s.contains("upsc ups"),
        "{s}"
    );
    assert!(!s.contains("Install the waiting updates"), "skipped: {s}");
    // Enter: with Claude (it plans, sentry applies); m: the steps, to do it yourself.
    key(&mut a, KeyCode::Enter);
    let p = a.consent_text().expect("Enter asks Claude");
    assert!(
        p.contains("Do this for me") && p.contains("Check the UPS battery"),
        "{p}"
    );
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('m'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("mark done"), "m shows the steps: {s}");
    key(&mut a, KeyCode::Char('n'));
    key(&mut a, KeyCode::Char('d'));
    // Logged at once (it's off the list); the note is asked after, and Esc only skips it.
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Check the UPS battery: done, logged · how it went"),
        "{s}"
    );
    assert!(s.contains("Recommended · 1 ·"), "done for 90 days: {s}");
    for c in "checked, 100%".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("noted in the maintenance log"), "{s}");

    // R: nothing left to apply, so the brief. A new review removes and puts off.
    key(&mut a, KeyCode::Char('R'));
    assert!(render_to_string(&mut a, 158, 41).contains("Enter starts the review"));
    key(&mut a, KeyCode::Esc);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Updates waiting"), "{s}");
    a.review_written_for_test(REVIEW_LATER);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Remove") && s.contains("Put off") && s.contains("until 2099-01-01"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Esc);
    let s = render_to_string(&mut a, 158, 41);
    assert!(!s.contains("Updates waiting"), "put off: {s}");
    for c in ":tasks".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(!s.contains("Check the UPS battery"), "removed: {s}");
    // A built-in one is turned off, not removed.
    let off = s
        .lines()
        .find(|l| l.contains("lean up"))
        .unwrap_or_default();
    assert!(off.contains("off"), "{s}");
    // R on Maintenance with the review applied: R again offers a new one.
    for c in ":later".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert!(render_to_string(&mut a, 158, 41).contains("2099-01-01"));
}

#[test]
fn a_var_left_empty_is_asked_again() {
    use crate::tui::app::{Effect, Prompt};
    let mut a = app(ScreenId::Upgrade);
    a.apply_for_test(vec![Effect::Prompt(
        Prompt::WfVar {
            workflow: "release-rebase".into(),
            key: "target".into(),
            prompt: "Target Fedora version".into(),
            rest: vec![(
                "window".into(),
                "Maintenance window".into(),
                "tonight".into(),
            )],
            vars: Default::default(),
        },
        String::new(),
    )]);
    // Enter on nothing: asked again, and what's still to ask isn't lost.
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Target Fedora version: ▏") && s.contains("target can't be empty"),
        "{s}"
    );
    // One Backspace too many doesn't close a prompt (Esc does).
    key(&mut a, KeyCode::Backspace);
    assert!(render_to_string(&mut a, 158, 41).contains("Target Fedora version: ▏"));
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Char('6'));
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Maintenance window: tonight▏"),
        "the next one: {s}"
    );
    key(&mut a, KeyCode::Esc);
    assert!(!render_to_string(&mut a, 158, 41).contains("Maintenance window"));
    // A command line still closes on Backspace.
    key(&mut a, KeyCode::Char(':'));
    assert!(render_to_string(&mut a, 158, 41).contains(":▏"));
    key(&mut a, KeyCode::Backspace);
    assert!(!render_to_string(&mut a, 158, 41).contains(":▏"));
}

/// Read-only on this machine: Maintenance from the real collectors, its views, and the
/// dashboard. Point XDG_CONFIG_HOME/XDG_DATA_HOME at scratch copies.
/// `cargo test live_maintenance -- --ignored --nocapture`
#[test]
#[ignore]
fn live_maintenance() {
    crate::paths::use_real_dirs();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(tx);
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
    pump(&mut a, 3);
    println!("{}", render_to_string(&mut a, 158, 41));
    key(&mut a, KeyCode::Char('6'));
    pump(&mut a, 8);
    println!("{}", render_to_string(&mut a, 158, 41));
    for k in ['F', 'J'] {
        key(&mut a, KeyCode::Char(k));
        println!("{}", render_to_string(&mut a, 158, 41));
        key(&mut a, KeyCode::Esc);
    }
}

#[test]
fn records_show_every_task_and_bring_back_what_was_put_off() {
    let mut d = store();
    d.snoozes.insert(
        "updates".into(),
        jiff::Zoned::now()
            .date()
            .checked_add(jiff::Span::new().days(30))
            .unwrap(),
    );
    let mut a = App::for_test(Config::default(), d, ScreenId::Maint);
    let s = render_to_string(&mut a, 158, 41);
    assert!(!s.contains("Updates waiting"), "put off: {s}");
    key(&mut a, KeyCode::Char('v'));
    // Tasks: the jobs' cadences, done yesterday, with when they're next due.
    key(&mut a, KeyCode::Char('['));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Records   Tasks 3  Log 3  Plans 0  Reviews 0  Later 1"),
        "{s}"
    );
    assert!(
        s.contains("Check for updates") && s.contains("job update-check") && s.contains("built in"),
        "{s}"
    );
    // Later: the snooze; u brings the updates back.
    key(&mut a, KeyCode::Char('['));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("put off") && s.contains("updates"), "{s}");
    key(&mut a, KeyCode::Char('u'));
    key(&mut a, KeyCode::Esc);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Updates waiting"), "back: {s}");
}

#[test]
fn claude_helps_apply_the_updates_beside_quick_update() {
    let mut a = app(ScreenId::Maint);
    key(&mut a, KeyCode::Char('A'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("help me apply it") && s.contains("just ask"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('1'));
    let p = a.consent_text().expect("consent");
    // What's waiting, the workflow's steps, and the rule: the workflow makes the change.
    assert!(p.contains("pending rpm-ostree update"), "{p}");
    assert!(
        p.contains("workflow `quick-update`") && p.contains("Its steps:"),
        "{p}"
    );
    assert!(
        p.contains("workflow = \"quick-update\"") && p.contains("never its commands"),
        "{p}"
    );
    // `2`: the plain question, no apply rules.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Char('2'));
    let p = a.consent_text().expect("consent");
    assert!(!p.contains("sentry-apply"), "{p}");
}

#[test]
fn a_long_plan_keeps_its_running_step_in_view() {
    use crate::claude::{Apply, Ask};
    let mut a = app(ScreenId::Maint);
    a.apply_for_test(vec![crate::tui::screens::Effect::AskConsent(Ask::apply(
        "many steps",
        "ctx",
        Apply {
            key: "x".into(),
            ..Default::default()
        },
    ))]);
    key(&mut a, KeyCode::Enter);
    let steps: String = (1..=40)
        .map(|i| format!("[[step]]\ntitle = \"Check number {i}\"\ncheck = \"true\"\n"))
        .collect();
    a.apply_answer_for_test(&format!(
        "Many.\n```sentry-apply\nsummary = \"forty checks\"\n{steps}```"
    ));
    key(&mut a, KeyCode::Enter);
    // Step 1 runs: it's on screen (with its clock), not the untouched end of the list.
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("▶ 1. Check number 1") && s.contains("… running 0:00"),
        "{s}"
    );
    for _ in 0..19 {
        a.apply_step_exit_for_test(0);
    }
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("▶ 20. Check number 20"), "{s}");
    // Step 20 fails: Claude is asked by itself, and its plan for the rest waits for you,
    // which the window says plainly.
    a.apply_step_exit_for_test(1);
    a.apply_answer_for_test(
        "Fixed.\n```sentry-apply\nsummary = \"the rest\"\n[[step]]\ntitle = \"Again\"\ncheck = \"true\"\n```",
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("▶ Your turn: the plan stopped at step 20 (Check number 20); Claude sent a plan for the rest · Enter apply the plan"),
        "{s}"
    );
}

#[test]
fn a_plans_workflow_step_waits_for_its_run() {
    // (It starts a run for real, in the scratch data dir: one at a time.)
    let _turn = runs_turn();
    use crate::apply::session::{Phase, Turn};
    use crate::claude::{Apply, Ask};
    let mut a = app(ScreenId::Maint);
    a.apply_for_test(vec![crate::tui::screens::Effect::AskConsent(Ask::apply(
        "updates",
        "ctx",
        Apply {
            key: "updates".into(),
            workflow: Some("quick-update".into()),
            ..Default::default()
        },
    ))]);
    key(&mut a, KeyCode::Enter);
    a.apply_answer_for_test(
        "Run it.\n```sentry-apply\nsummary = \"install the updates\"\n[[step]]\ntitle = \"Install\"\nworkflow = \"quick-update\"\n```",
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("workflow quick-update") && s.contains("Enter applies these 1 steps"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        a.apply_session().unwrap().waiting_workflow(),
        Some("quick-update")
    );
    // The run ends: the plan carries on (here, to the check), and the session shows again.
    let mut e = crate::maint::log::LogEntry::event(
        crate::maint::LOCAL,
        "workflow",
        "quick-update",
        true,
        "updated",
        &[],
        jiff::Timestamp::now(),
    );
    e.head.workflow = "quick-update".into();
    a.run_ended_for_test(&e);
    let sess = a.apply_session().unwrap();
    assert_eq!(sess.phase, Phase::Thinking(Turn::Verify));
    assert!(!sess.chat.hidden);
}

#[test]
fn g_shows_the_files_claude_asked_for() {
    use crate::claude::{Ask, Event};
    use crate::tui::chat::Chat;
    let mut a = app(ScreenId::Maint);
    let file = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
    let mut c = Chat::new(Ask::new("s", "ctx", "q"));
    c.begin_turn("q", 1, 1);
    c.on_event(Event::ToolUse {
        name: "Edit".into(),
        input: "/etc/hosts".into(),
    });
    c.on_event(Event::ToolResult {
        summary: "denied: Claude requested permissions to write to /etc/hosts, but no.".into(),
        is_error: true,
    });
    c.on_event(Event::ToolUse {
        name: "Read".into(),
        input: file.clone(),
    });
    c.on_event(Event::ToolResult {
        summary: format!("denied: Claude requested permissions to read from {file}, but no."),
        is_error: true,
    });
    c.on_exit(0);
    a.set_chat(c);
    key(&mut a, KeyCode::Char('g'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Grant files to Claude"), "{s}");
    // The real path (in a toolbox /etc/hosts is /run/host/etc/hosts): root's, refused.
    assert!(
        s.contains("etc/hosts") && s.contains("not granted: it's root's"),
        "{s}"
    );
    assert!(s.contains("Cargo.toml"), "{s}");
}

#[test]
fn applying_a_task_is_one_session_start_to_done() {
    use crate::claude::{Apply, Ask};
    // A file under home, removed at the end.
    let dir = crate::paths::home().join(".cache/sentry-applyplan-apptest");
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join(format!("cheatsheet-{}.md", std::process::id()));
    std::fs::write(&f, "# Cheatsheet\n**Layered:** akmods code\nend\n").unwrap();
    let file = f.display().to_string();
    let plan = |old: &str| {
        format!(
            "The layered line is stale.\n\n```sentry-apply\nsummary = \"Fix the layered line\"\n\
             rollback = \"sentry restores the backup\"\n\n[[step]]\ntitle = \"Line 2\"\n\
             edit = \"{file}\"\nold = \"\"\"{old}\"\"\"\nnew = \"\"\"**Layered:** akmods ghostty\"\"\"\n\n\
             [[step]]\ntitle = \"Check it\"\ncheck = \"grep -q ghostty {file}\"\n```\n"
        )
    };
    let mut a = app(ScreenId::Maint);
    a.apply_for_test(vec![crate::tui::screens::Effect::AskConsent(Ask::apply(
        "the cheatsheet",
        "A task: fix the cheatsheet.",
        Apply {
            key: "task:sheet".into(),
            task: Some("sheet".into()),
            ..Default::default()
        },
    ))]);
    // 1. The brief, nothing sent: Enter starts.
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("brief › investigate")
            && s.contains("Sent to Claude")
            && s.contains("Enter  start"),
        "{s}"
    );
    assert!(s.contains("A task: fix the cheatsheet."), "{s}");
    key(&mut a, KeyCode::Enter);
    assert!(render_to_string(&mut a, 158, 41).contains("Claude is looking into it"));
    // A plan sentry can't use goes back to Claude by itself: no key, no box.
    a.apply_answer_for_test(&plan("**Layered:** nope"));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("sentry can't use step 1 as written")
            && s.contains("Claude is correcting the plan"),
        "{s}"
    );
    // 2. The plan: Enter applies it.
    a.apply_answer_for_test(&plan("**Layered:** akmods code"));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Plan: Fix the layered line") && s.contains("Enter applies these 2 steps"),
        "{s}"
    );
    assert!(s.contains("Enter  apply the plan"), "{s}");
    assert!(
        !s.contains("Proposed commands") && !s.contains("```") && !s.contains("press s"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    // The edit is done; the check runs; then the results go to Claude by themselves.
    assert_eq!(
        std::fs::read_to_string(&f).unwrap(),
        "# Cheatsheet\n**Layered:** akmods ghostty\nend\n"
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("✓ 1. Line 2") && s.contains("▶ 2. Check it"),
        "{s}"
    );
    a.apply_step_exit_for_test(0);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("all 2 steps done") && s.contains("Claude is checking the result"),
        "{s}"
    );
    // The verdict: done, logged, the task with it.
    a.apply_answer_for_test(
        "The line is right.\n```sentry-verdict\nstatus = \"done\"\nsummary = \"the cheatsheet matches the system\"\nnext = \"nothing\"\n```",
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("✓ Done · the cheatsheet matches the system") && s.contains("task marked done"),
        "{s}"
    );
    let e = &a.log_for_test()[0];
    assert_eq!(e.head.kind, "apply");
    assert!(
        e.head.tags.contains(&"task:sheet".to_string()),
        "{:?}",
        e.head.tags
    );
    assert!(e.head.tags.contains(&format!("file:{file}")));
    key(&mut a, KeyCode::Esc);
    assert!(a.apply_session().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A task done by hand, due since it was added.
fn by_hand_task(id: &str, title: &str) -> crate::maint::tasks::Task {
    crate::maint::tasks::Task {
        id: id.into(),
        title: title.into(),
        why: "It matters.".into(),
        level: crate::maint::Level::Routine,
        every: Some("90d".parse().unwrap()),
        act: "by-hand".into(),
        item: None,
        steps: "Look at it.".into(),
        added: "2026-10-01T12:00:00Z".parse().ok(),
        off: false,
        source: crate::maint::tasks::Source::File,
        review: None,
        after: None,
        again: None,
    }
}

/// A one-step workflow whose run has just ended well.
fn ended_run(a: &mut App, name: &str) {
    use crate::tui::wf::Session;
    use crate::workflows::runner::{self, Next};
    use crate::workflows::state::{RunState, RunStatus};
    let wf = crate::workflows::parse(&format!(
        "name = \"{name}\"\ndescription = \"test\"\n[[steps]]\nid = \"firmware\"\n\
         title = \"Update the firmware\"\nrun = \"fwupdmgr update\"\ngate = \"confirm\"\n"
    ))
    .unwrap();
    let mut st = RunState::new(name, &["firmware".to_string()], Default::default());
    runner::finish(&mut st, 0, 0, None);
    st.status = RunStatus::Done;
    st.ended = Some(jiff::Timestamp::now());
    a.set_wf(Session::for_test(wf, st, Next::Done));
    a.run_logged_for_test();
}

#[test]
fn after_a_run_claude_says_which_tasks_it_did() {
    let mut a = app(ScreenId::Upgrade);
    a.add_task_for_test(by_hand_task("firmware", "Update the firmware"));
    a.add_task_for_test(by_hand_task("ups", "Check the UPS battery"));
    let due = a.tasks_due_for_test();
    assert!(due.contains(&"firmware".to_string()) && due.contains(&"ups".to_string()));
    ended_run(&mut a, "fw-update");
    // The note first; nothing is started while it's asked.
    assert!(render_to_string(&mut a, 158, 41).contains("for the log, what to know next time"));
    assert!(a.auto_review_for_test().is_none());
    key(&mut a, KeyCode::Esc);
    // No note: the review starts by itself, about that run, with no window.
    let (origin, run) = a.auto_review_for_test().expect("a review is being written");
    assert_eq!(origin, "run");
    assert!(
        run.as_deref().is_some_and(|f| f.ends_with("-fw-update.md")),
        "{run:?}"
    );
    assert!(!render_to_string(&mut a, 158, 41).contains("Claude is writing"));
    a.writer_answered_for_test(
        "# Maintenance review\n\n## Done by this run\n- firmware\n\n```sentry-changes\n\
         [[done]]\ntask = \"firmware\"\nwhy = \"The run updated the firmware.\"\n\n\
         [[again]]\ntask = \"ups\"\nlevel = \"soon\"\nwhy = \"The new firmware resets its settings.\"\n```\n",
    );
    // It opens with what it found, ticked; Enter applies both.
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("2 changes · Enter applies the 2 ticked"), "{s}");
    assert!(
        s.contains("Update the firmware") && s.contains("due again"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    assert!(render_to_string(&mut a, 158, 41).contains("2 applied"));
    // Done as of the run, in the log; the other is due and says why.
    assert_eq!(a.tasks_due_for_test(), ["ups"]);
    let log = a.log_for_test();
    let done = log
        .iter()
        .find(|e| e.head.tags.contains(&"task:firmware".to_string()))
        .expect("an entry for the task");
    assert!(
        done.body.contains("Done by the fw-update run"),
        "{}",
        done.body
    );
    assert!(done.head.tags.iter().any(|t| t.starts_with("run:")));
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('6'));
    a.apply_for_test(vec![crate::tui::app::Effect::MaintFind("task:ups".into())]);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("The new firmware resets its settings."), "{s}");
}

#[test]
fn a_run_with_no_task_left_due_asks_claude_nothing() {
    let mut a = app(ScreenId::Upgrade);
    // Turn the built-in cadences off: nothing is due.
    let due = a.tasks_due_for_test();
    for id in due {
        let mut t = by_hand_task(&id, "off");
        t.off = true;
        a.add_task_for_test(t);
    }
    assert!(a.tasks_due_for_test().is_empty());
    ended_run(&mut a, "fw-update");
    key(&mut a, KeyCode::Esc);
    assert!(a.auto_review_for_test().is_none());
}

#[test]
fn the_review_at_start_shows_only_when_something_changed() {
    let mut a = app(ScreenId::Maint);
    a.add_task_for_test(by_hand_task("ups", "Check the UPS battery"));
    a.start_check_for_test();
    assert_eq!(
        a.auto_review_for_test().map(|(o, _)| o).as_deref(),
        Some("start")
    );
    // Nothing changed: nothing is shown or kept.
    a.writer_answered_for_test(
        "# Maintenance review\n\n## Changed\nNothing\n\n```sentry-changes\n```\n",
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        !s.contains("changes to the tasks") && !s.contains("Enter applies"),
        "{s}"
    );
    // Something did: a line says so, and R shows it.
    a.start_check_for_test();
    a.writer_answered_for_test(
        "# Maintenance review\n\n## Changed\n- kernel\n\n```sentry-changes\n\
         [[again]]\ntask = \"job-audit\"\nlevel = \"soon\"\nwhy = \"A new kernel was booted.\"\n```\n",
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("since last time: 1 change to the tasks (R shows them)"),
        "{s}"
    );
    assert!(
        !s.contains("Enter applies"),
        "it doesn't open by itself: {s}"
    );
    key(&mut a, KeyCode::Char('R'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("1 change · Enter applies the 1 ticked"), "{s}");
    // Asking for a review yourself takes the place of one sentry started.
    key(&mut a, KeyCode::Esc);
    a.start_check_for_test();
    assert!(a.auto_review_for_test().is_some());
    a.review_written_for_test(REVIEW_LATER);
    assert!(a.auto_review_for_test().is_none());
}

const SERIES_PLAN: &str = "On it.\n```sentry-apply\nsummary = \"do it\"\nrollback = \"nothing to undo\"\n\
                           [[step]]\ntitle = \"Check\"\ncheck = \"true\"\n```";

/// Maintenance with two tasks done by hand due, both ticked (the updates row is first).
fn two_ticked() -> App {
    let mut a = app(ScreenId::Maint);
    a.add_task_for_test(by_hand_task("firmware", "Update the firmware"));
    a.add_task_for_test(by_hand_task("ups", "Check the UPS battery"));
    render_to_string(&mut a, 158, 41);
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char(' '));
    a
}

#[test]
fn ticked_rows_are_done_one_after_another() {
    use crate::apply::session::{Phase, Turn};
    let mut a = two_ticked();
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("· 2 ticked ·") && s.contains("Enter  do the ticked") && s.contains("✓ routine"),
        "{s}"
    );
    // Space again unticks; a ticks every row that can be, a again none; Esc none.
    key(&mut a, KeyCode::Char(' '));
    assert!(render_to_string(&mut a, 158, 41).contains("· 1 ticked ·"));
    key(&mut a, KeyCode::Char('a'));
    assert!(render_to_string(&mut a, 158, 41).contains("· 3 ticked ·"));
    key(&mut a, KeyCode::Esc);
    assert!(!render_to_string(&mut a, 158, 41).contains("ticked"));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('k'));
    key(&mut a, KeyCode::Char(' '));
    // One Enter starts the series: the first row's session, already asking Claude.
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Claude · 1 of 2 · apply · Update the firmware")
            && s.contains("1 of 2 in the series · it starts by itself"),
        "{s}"
    );
    assert_eq!(
        a.apply_session().unwrap().phase,
        Phase::Thinking(Turn::Investigate)
    );
    // Its plan is the one thing to press Enter for.
    a.apply_answer_for_test(SERIES_PLAN);
    assert!(render_to_string(&mut a, 158, 41).contains("Enter  apply the plan"));
    key(&mut a, KeyCode::Enter);
    a.apply_step_exit_for_test(0);
    a.apply_answer_for_test("```sentry-verdict\nstatus = \"done\"\nsummary = \"flashed\"\n```");
    // Done: the next row opens by itself, already started.
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Claude · 2 of 2 · apply · Check the UPS battery"),
        "{s}"
    );
    assert_eq!(
        a.apply_session().unwrap().phase,
        Phase::Thinking(Turn::Investigate)
    );
    assert!(!a.tasks_due_for_test().contains(&"firmware".to_string()));
    a.apply_answer_for_test(SERIES_PLAN);
    key(&mut a, KeyCode::Enter);
    a.apply_step_exit_for_test(0);
    a.apply_answer_for_test("```sentry-verdict\nstatus = \"done\"\nsummary = \"fine\"\n```");
    // Through: no window left, both done, nothing ticked.
    assert!(a.apply_session().is_none());
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("series: 2 of 2 done"), "{s}");
    assert!(!s.contains("ticked") && !s.contains("series 2 of 2"), "{s}");
    assert!(a.tasks_due_for_test().is_empty());
}

#[test]
fn a_row_that_fails_waits_and_esc_stops_the_series() {
    let mut a = two_ticked();
    key(&mut a, KeyCode::Enter);
    a.apply_answer_for_test(SERIES_PLAN);
    key(&mut a, KeyCode::Enter);
    a.apply_step_exit_for_test(0);
    a.apply_answer_for_test(
        "```sentry-verdict\nstatus = \"failed\"\nsummary = \"no firmware found\"\n```",
    );
    // It didn't end well: it stays open; Enter goes on with the next.
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Claude · 1 of 2") && s.contains("Enter  go on with the next"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Claude · 2 of 2 · apply · Check the UPS battery"),
        "{s}"
    );
    // Esc on its plan closes it: the series stops, and what isn't done stays ticked.
    a.apply_answer_for_test(SERIES_PLAN);
    key(&mut a, KeyCode::Esc);
    assert!(a.apply_session().is_none());
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("series stopped at 2 of 2 · 2 still ticked") && s.contains("· 2 ticked ·"),
        "{s}"
    );
    // A row Enter does by itself can't be ticked.
    let mut a = app(ScreenId::Maint);
    a.add_task_for_test(crate::maint::tasks::Task {
        act: "job cleanup".into(),
        every: None,
        added: Some(jiff::Timestamp::now()),
        ..by_hand_task("tidy", "Tidy up")
    });
    render_to_string(&mut a, 158, 41);
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char(' '));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("it can't go in a series") && !s.contains("ticked"),
        "{s}"
    );
}

/// Tests that start a run for real (in the scratch data dir, where only one can be in
/// progress and others leave quick-update started): they take turns, each beginning with
/// no run left there.
fn runs_turn() -> std::sync::MutexGuard<'static, ()> {
    static RUNS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let turn = RUNS.lock().unwrap_or_else(|e| e.into_inner());
    let _ = std::fs::remove_dir_all(crate::workflows::state::root());
    turn
}

#[test]
fn a_series_runs_a_workflow_and_goes_on_when_it_ends_well() {
    let _turn = runs_turn();
    // A workflow of the test's own, in the scratch config dir; its one step waits for Enter,
    // so starting it runs nothing.
    let name = "series-fw";
    let dir = crate::workflows::dir();
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(format!("{name}.toml"));
    std::fs::write(
        &file,
        format!(
            "name = \"{name}\"\ndescription = \"test\"\n[[steps]]\nid = \"firmware\"\n\
             title = \"Update the firmware\"\nrun = \"fwupdmgr update\"\ngate = \"confirm\"\n"
        ),
    )
    .unwrap();
    let mut a = app(ScreenId::Maint);
    a.add_task_for_test(crate::maint::tasks::Task {
        act: format!("run {name}"),
        ..by_hand_task("fw", "Update the firmware")
    });
    a.add_task_for_test(by_hand_task("ups", "Check the UPS battery"));
    render_to_string(&mut a, 158, 41);
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Enter);
    // The run, on its screen, with no start box: the series' Enter was the start.
    let s = render_to_string(&mut a, 158, 41);
    assert_eq!(a.slot().screen, ScreenId::Upgrade, "{s}");
    assert!(
        s.contains("Update the firmware") && !s.contains(&format!("Start {name}")),
        "{s}"
    );
    // It ends well: no note is asked, the run closes, and the next row's session opens.
    ended_run(&mut a, name);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Claude · 2 of 2 · apply · Check the UPS battery"),
        "{s}"
    );
    assert!(!s.contains("what to know next time"), "{s}");
    assert_eq!(a.slot().screen, ScreenId::Maint);
    assert!(!a.tasks_due_for_test().contains(&"fw".to_string()));
    let _ = std::fs::remove_file(&file);
}

#[test]
fn a_sudo_step_asks_for_the_password_in_the_key_bar_never_the_terminal() {
    use crate::tui::wf::Session;
    use crate::workflows::parse;
    use crate::workflows::runner::Next;
    use crate::workflows::state::RunState;
    let wf = parse(
        "name = \"fix\"\ndescription = \"test\"\n[[steps]]\nid = \"repo\"\n\
         title = \"Remove the repo file\"\nrun = \"sudo rm /etc/yum.repos.d/x.repo\"\n\
         gate = \"confirm\"\ndry_run = false\n[[steps]]\nid = \"again\"\ntitle = \"Again\"\n\
         run = \"sudo true\"\ngate = \"confirm\"\ndry_run = false\n",
    )
    .unwrap();
    let ids: Vec<String> = wf.steps.iter().map(|s| s.id.clone()).collect();
    let st = RunState::new("fix", &ids, Default::default());
    let mut a = app(ScreenId::Upgrade);
    a.set_wf(Session::for_test(wf, st, Next::Confirm(0)));
    // Enter on the confirm step: the one approval. Then the password, typed here.
    key(&mut a, KeyCode::Enter);
    assert!(a.take_suspend().is_none(), "the terminal stays the TUI's");
    let (what, ..) = a.unlock_for_test().expect("the password is asked for");
    assert_eq!(what, "for fix · step 1");
    let s = render_to_string(&mut a, 120, 36);
    assert!(s.contains("sudo password (for fix · step 1) › ▏"), "{s}");
    for c in "s3cret-pw".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    a.unlock_exit_for_test(0);
    assert!(a.holds_password_for_test() && a.unlock_for_test().is_none());
    let s = render_to_string(&mut a, 120, 36);
    assert!(s.contains("$ sudo rm /etc/yum.repos.d/x.repo"), "{s}");
    assert!(!s.contains("s3cret-pw") && !s.contains("SENTRY_"), "{s}");
    // Esc on the prompt, another time: the step isn't run, and says why.
    let mut b = app(ScreenId::Upgrade);
    let wf = parse(
        "name = \"fix\"\ndescription = \"test\"\n[[steps]]\nid = \"repo\"\ntitle = \"x\"\n\
         run = \"sudo true\"\ngate = \"confirm\"\ndry_run = false\n",
    )
    .unwrap();
    let st = RunState::new("fix", &["repo".to_string()], Default::default());
    b.set_wf(Session::for_test(wf, st, Next::Confirm(0)));
    key(&mut b, KeyCode::Enter);
    key(&mut b, KeyCode::Esc);
    assert!(b.unlock_for_test().is_none() && !b.holds_password_for_test());
    let s = render_to_string(&mut b, 120, 36);
    assert!(
        s.contains("sudo needs your password, which wasn't given"),
        "{s}"
    );
}

// ── Auto mode ──────────────────────────────────────────────────────────────────────────

fn ctrl(a: &mut App, c: char) {
    a.on_event(
        Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)),
        Instant::now(),
    );
}

/// Auto on: this machine's sudo asks (in tests it always does), so the password is asked
/// for at once; typed and accepted.
fn auto_on(a: &mut App) {
    ctrl(a, 'a');
    let (what, ..) = a.unlock_for_test().expect("the password, at once");
    assert_eq!(what, "for auto mode");
    for c in "s3cret-pw".chars() {
        key(a, KeyCode::Char(c));
    }
    key(a, KeyCode::Enter);
    a.unlock_exit_for_test(0);
    assert!(a.slot().auto && a.holds_password_for_test());
}

#[test]
fn auto_does_a_series_with_one_password_and_no_other_key() {
    use crate::apply::session::{Phase, Turn};
    let _turn = runs_turn();
    // A workflow of the test's own: a value with a default, a step that waits for a confirm.
    let name = "series-auto";
    let dir = crate::workflows::dir();
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(format!("{name}.toml"));
    std::fs::write(
        &file,
        format!(
            "name = \"{name}\"\ndescription = \"test\"\n[vars.level]\nprompt = \"How far\"\n\
             default = \"all\"\n[[steps]]\nid = \"tidy\"\ntitle = \"Tidy {{{{ level }}}}\"\n\
             run = \"echo tidy {{{{ level }}}}\"\ngate = \"confirm\"\n"
        ),
    )
    .unwrap();
    let mut a = app(ScreenId::Maint);
    a.add_task_for_test(crate::maint::tasks::Task {
        act: format!("run {name}"),
        ..by_hand_task("tidy", "Tidy up")
    });
    a.add_task_for_test(by_hand_task("firmware", "Update the firmware"));
    a.add_task_for_test(by_hand_task("ups", "Check the UPS battery"));
    render_to_string(&mut a, 158, 41);
    auto_on(&mut a);
    // The three tasks (never the updates row above them, which is the real quick-update):
    // the workflow's and the two done by hand.
    for _ in 0..3 {
        key(&mut a, KeyCode::Char('j'));
        key(&mut a, KeyCode::Char(' '));
    }
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("· 3 ticked ·"), "{s}");
    for row in [
        "✓ routine  Tidy up",
        "✓ routine  Update the firmware",
        "✓ routine  Check the UPS",
    ] {
        assert!(s.contains(row), "{row}: {s}");
    }
    let ticked = 3;
    key(&mut a, KeyCode::Enter);
    // From here no key: steps end, Claude answers, auto gives every Enter.
    let mut seen = Vec::new();
    for _ in 0..60 {
        assert!(a.unlock_for_test().is_none(), "no second prompt");
        assert!(a.box_yes_for_test().is_none(), "no box");
        if let Some(r) = a.slot().run.as_ref() {
            assert_eq!(r.wf().name, name, "only the test's own workflow");
        }
        if a.slot().run.as_ref().is_some_and(|r| r.live().is_some()) {
            seen.push("a step".to_string());
            a.run_step_exit_for_test(0);
            continue;
        }
        let Some(sess) = a.apply_session() else { break };
        seen.push(sess.chat.ask.subject.clone());
        match sess.phase {
            Phase::Thinking(Turn::Verify) => a.apply_answer_for_test(
                "```sentry-verdict\nstatus = \"done\"\nsummary = \"fine\"\n```",
            ),
            Phase::Thinking(_) => a.apply_answer_for_test(SERIES_PLAN),
            Phase::Applying if sess.job.is_some() => a.apply_step_exit_for_test(0),
            p => panic!(
                "it waits for a key at {p:?}: {}",
                render_to_string(&mut a, 158, 41)
            ),
        }
    }
    let s = render_to_string(&mut a, 158, 41);
    let seen = seen.join(" | ");
    assert!(a.apply_session().is_none(), "{s}\n{seen}");
    assert!(
        s.contains(&format!("series: {ticked} of {ticked} done")),
        "{s}\n{seen}"
    );
    assert!(
        !s.contains("ticked ·") && !s.contains("what to know next time"),
        "{s}"
    );
    for want in ["a step", "Update the firmware", "Check the UPS battery"] {
        assert!(seen.contains(want), "{want}: {seen}");
    }
    assert!(a.tasks_due_for_test().is_empty());
    // The log marks auto's answers: the run's values and its step, each session's plan.
    let log = a.log_for_test();
    let run = log
        .iter()
        .find(|e| e.head.workflow == name)
        .expect("the run's entry");
    assert!(
        run.head.tags.contains(&"auto".to_string()),
        "{:?}",
        run.head.tags
    );
    assert!(
        run.body.contains("(`tidy`) | ok | 0 |")
            && run.body.contains("| confirmed by auto |")
            && run
                .body
                .contains("- its values: the defaults, taken without asking")
            && run.body.contains("- confirmed: `tidy`"),
        "{}",
        run.body
    );
    let applied: Vec<_> = log.iter().filter(|e| e.head.kind == "apply").collect();
    assert!(applied.len() >= 2);
    for e in applied {
        assert!(
            e.head.tags.contains(&"auto".to_string()),
            "{:?}",
            e.head.tags
        );
        assert!(
            e.body
                .contains("Answered by auto: approved the plan (do it)"),
            "{}",
            e.body
        );
    }
    let _ = std::fs::remove_file(&file);
}

#[test]
fn auto_stages_the_upgrade_and_stops_at_the_reboot() {
    use crate::tui::wf::Session;
    use crate::workflows::runner::{self, Next};
    use crate::workflows::state::{RunState, StepStatus};
    // The shipped quick-update, at its staging step: an update is waiting, same kernel.
    let text = crate::workflows::SEEDS
        .iter()
        .find(|(n, _)| *n == "quick-update")
        .unwrap()
        .1;
    let wf = crate::workflows::parse(text).unwrap();
    let at = |id: &str| wf.steps.iter().position(|s| s.id == id).unwrap();
    let (stage, reboot) = (at("upgrade-routine"), at("reboot-routine"));
    assert!(wf.steps[stage].stage && wf.steps[at("upgrade-ritual")].stage);
    assert_eq!(
        wf.steps.iter().filter(|s| s.stage).count(),
        2,
        "only the two steps that stage an upgrade"
    );
    let ids: Vec<String> = wf.steps.iter().map(|s| s.id.clone()).collect();
    let mut st = RunState::new("quick-update", &ids, Default::default());
    for (c, v) in [
        ("routine_update", true),
        ("kernel_changed", false),
        ("flatpak_gl_nvidia", true),
        ("master_repo_present", false),
    ] {
        st.conds.insert(c.into(), v);
    }
    for i in 0..stage {
        runner::finish(&mut st, i, 0, None);
    }
    let mut run = Session::for_test(wf, st, Next::Confirm(stage));
    // (A real directory: the run's state and step logs are written as it goes.)
    run.run.dir = std::env::temp_dir().join(format!("sentry-auto-stage-{}", std::process::id()));
    std::fs::create_dir_all(run.run.dir.join("steps")).unwrap();
    let dir = run.run.dir.clone();
    let mut a = app(ScreenId::Upgrade);
    a.set_wf(run);
    // Auto off: the staging step waits for Enter, as ever.
    a.tick(Instant::now());
    let live = |a: &App| a.slot().run.as_ref().unwrap().live().copied();
    assert!(live(&a).is_none());
    auto_on(&mut a);
    // On: its dry run (the preview), then the step itself, with no key.
    let l = live(&a).expect("the dry run");
    assert!(l.dry && l.idx == stage);
    a.run_step_exit_for_test(0);
    let l = live(&a).expect("the upgrade is staged");
    assert!(!l.dry && l.idx == stage);
    a.run_step_exit_for_test(0);
    // The reboot is never auto's: it waits, no box is open, nothing was asked of root.
    let r = a.slot().run.as_ref().unwrap();
    assert!(live(&a).is_none());
    assert!(
        matches!(*r.next(), Next::Reboot { idx, requested: false } if idx == reboot),
        "{:?}",
        r.next()
    );
    assert_eq!(r.run().state.steps[stage].status, StepStatus::Ok);
    assert_eq!(r.run().state.auto, [format!("step:{}", ids[stage])]);
    assert!(a.box_yes_for_test().is_none());
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("auto leaves step") && s.contains("a reboot is yours to start"),
        "{s}"
    );
    a.tick(Instant::now());
    assert!(matches!(
        *a.slot().run.as_ref().unwrap().next(),
        Next::Reboot {
            requested: false,
            ..
        }
    ));
    // Enter asks first, as with auto off.
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Reboot") && s.contains("reboot now"), "{s}");
    assert!(a.box_yes_for_test().is_some());
    let _ = std::fs::remove_dir_all(&dir);

    // The same command where the workflow doesn't mark it: asked.
    let wf = crate::workflows::parse(
        "name = \"other\"\ndescription = \"test\"\n[[steps]]\nid = \"up\"\ntitle = \"Upgrade\"\n\
         run = \"rpm-ostree upgrade\"\ngate = \"confirm\"\n",
    )
    .unwrap();
    let st = RunState::new("other", &["up".to_string()], Default::default());
    let mut b = app(ScreenId::Upgrade);
    b.set_wf(Session::for_test(wf, st, Next::Confirm(0)));
    auto_on(&mut b);
    assert!(b.slot().run.as_ref().unwrap().live().is_none());
    let s = render_to_string(&mut b, 158, 41);
    assert!(s.contains("auto leaves step 1 to you"), "{s}");
    // And a mark on anything but a staging upgrade is a lint error.
    let bad = crate::workflows::parse(
        "name = \"bad\"\ndescription = \"test\"\n[[steps]]\nid = \"x\"\ntitle = \"x\"\n\
         run = \"rpm-ostree rebase y\"\nstage = true\n",
    )
    .unwrap();
    let issues = crate::workflows::lint_with(&bad, &crate::workflows::LOCAL);
    assert!(
        issues
            .iter()
            .any(|i| i.error && i.msg.contains("stage = true is only for")),
        "{issues:?}"
    );
}

#[test]
fn auto_takes_a_workflows_default_values() {
    let _turn = runs_turn();
    let name = "auto-taken";
    let dir = crate::workflows::dir();
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(format!("{name}.toml"));
    std::fs::write(
        &file,
        format!(
            "name = \"{name}\"\ndescription = \"test\"\n[vars.target]\nprompt = \"Which\"\n\
             default = \"44\"\n[[steps]]\nid = \"go\"\ntitle = \"Go\"\nkind = \"manual\"\n\
             manual = \"do it\"\n"
        ),
    )
    .unwrap();
    // (Here a value always has a default: a workflow with one that hasn't can't start.)
    let mut a = app(ScreenId::Upgrade);
    // Auto off: the value is asked, its default filled in.
    a.apply_for_test(vec![crate::tui::app::Effect::StartWorkflow(name.into())]);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Which") && s.contains("44▏"), "{s}");
    assert!(a.slot().run.is_none());
    key(&mut a, KeyCode::Esc);
    // On: taken, and the run says so. Its manual step is never auto's.
    auto_on(&mut a);
    a.apply_for_test(vec![crate::tui::app::Effect::StartWorkflow(name.into())]);
    let r = a.slot().run.as_ref().expect("started");
    assert_eq!(
        r.run().state.vars.get("target").map(String::as_str),
        Some("44")
    );
    assert_eq!(r.run().state.auto, ["values"]);
    assert!(r.live().is_none() && !r.done());
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("auto leaves step 1 to you: it is done by hand"),
        "{s}"
    );
    let _ = std::fs::remove_file(file);
}

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
                    .join("tests/fixtures/flatpak/metadata")
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
    for id in ScreenId::ALL {
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

#[test]
fn updates_shows_kernel_ritual() {
    let s = render_to_string(&mut app(ScreenId::Upd), 158, 41);
    assert!(s.contains("kmod ritual"), "{s}");
    assert!(s.contains("pinned"));
    insta::assert_snapshot!("updates_158x41", body(&s));
}

#[test]
fn other_screens_snapshot() {
    for (id, name) in [
        (ScreenId::Net, "network"),
        (ScreenId::Cont, "containers"),
        (ScreenId::Flat, "flatpaks"),
        (ScreenId::Audit, "audit_empty"),
    ] {
        let s = render_to_string(&mut app(id), 158, 41);
        insta::assert_snapshot!(format!("{name}_158x41"), body(&s));
    }
}

#[test]
fn navigation_and_modals() {
    let mut a = app(ScreenId::Dash);
    key(&mut a, KeyCode::Char('3'));
    assert_eq!(a.screen, ScreenId::Net);
    key(&mut a, KeyCode::Char('l'));
    assert_eq!(a.screen, ScreenId::Upd);
    key(&mut a, KeyCode::Char('h'));
    key(&mut a, KeyCode::Char('h'));
    assert_eq!(a.screen, ScreenId::Proc);
    key(&mut a, KeyCode::Char('H'));
    assert_eq!(a.screen, ScreenId::Hist);
    key(&mut a, KeyCode::Char('q'));
    let s = render_to_string(&mut a, 120, 30);
    assert!(s.contains("Quit sentry?"), "{s}");
    key(&mut a, KeyCode::Esc);
    assert!(!a.quit);
    key(&mut a, KeyCode::Char('q'));
    key(&mut a, KeyCode::Char('y'));
    assert!(a.quit);
}

#[test]
fn upgrade_on_kernel_change_offers_quick_update() {
    let mut a = app(ScreenId::Upd);
    key(&mut a, KeyCode::Char('u'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Kernel changes · use quick-update"), "{s}");
    assert!(
        s.contains("kmod-nvidia-7.2.8-200.fc44.x86_64-3:615.71.09-3.fc44.x86_64"),
        "{s}"
    );
    assert!(s.contains("start quick-update"), "{s}");
    assert!(
        !s.contains("--uninstall"),
        "no standalone ritual step 1 any more"
    );
    key(&mut a, KeyCode::Char('n'));
    assert!(!render_to_string(&mut a, 158, 41).contains("use quick-update"));
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
    assert_eq!(a.screen, ScreenId::Flat);
    key(&mut a, KeyCode::Char(':'));
    key(&mut a, KeyCode::Char('q'));
    key(&mut a, KeyCode::Enter);
    assert!(a.quit);
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
    let mut a = app(ScreenId::Audit);
    let empty = render_to_string(&mut a, 158, 41);
    assert!(empty.contains("No audit yet."), "{empty}");
    let mut d = store();
    d.reports.set(Ok(audit_reports()));
    d.baseline.listeners = vec!["0.0.0.0:22/sshd".into()];
    let mut a = App::for_test(Config::default(), d, ScreenId::Audit);
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("audit_158x41", body(&s));
    assert!(
        s.contains("7 Audit !1"),
        "badge counts findings to check: {s}"
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
    use crate::jobs::state::{Run, Runs};
    let mut d = store();
    let at =
        |days_ago: i64| jiff::Timestamp::now() - jiff::SignedDuration::from_hours(24 * days_ago);
    let mut runs = Runs::new();
    for (name, days, ok) in [
        ("audit", 3, true),
        ("cleanup-podman", 41, true),
        ("update-check", 1, false),
    ] {
        runs.insert(
            name.into(),
            Run {
                at: at(days),
                ok,
                summary: if ok {
                    "2 item(s) done".into()
                } else {
                    "rpm-ostree: timeout".into()
                },
            },
        );
    }
    d.job_runs.set(Ok(crate::jobs::state::Records {
        runs,
        cadence: Default::default(),
    }));
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
    let mut a = App::for_test(Config::default(), d, ScreenId::Jobs);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("8 Jobs 3"),
        "due badge: never-run + overdue jobs: {s}"
    );
    for want in [
        "cleanup-podman",
        "DUE",
        "failed",
        "11d over",
        "Cadence is a reminder",
    ] {
        assert!(s.contains(want), "{want}: {s}");
    }
    key(&mut a, KeyCode::Char('9'));
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
        s.contains("↻ workflow quick-update · step 8/17 Stage upgrade, dropping kmod-nvidia"),
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
    let v = View {
        d: &d,
        cfg: &cfg,
        t: &t,
        filter: None,
        wf: None,
    };
    let s = Screens::default();
    let expect: &[(ScreenId, &str)] = &[
        (ScreenId::Dash, "sentry's dashboard status"),
        (ScreenId::Proc, "no process selected"), // processes aren't sampled in the fixture store
        (ScreenId::Net, "known service:"),
        (ScreenId::Upd, "KERNEL CHANGES"),
        (ScreenId::Cont, "A podman container"),
        (ScreenId::Flat, "permissions = metadata + overrides"),
        (ScreenId::Audit, "sentry's generic explanation"),
        (ScreenId::Jobs, "--dry-run` shows its exact plan"),
        (ScreenId::Clean, "plans still loading"),
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
    let mut a = App::for_test(Config::default(), store(), ScreenId::Audit);
    a.set_chat(c);
    let s = render_to_string(&mut a, 120, 30);
    assert!(
        s.contains("Claude · audit · Unknown service on tcp/27500"),
        "{s}"
    );
    assert!(s.contains("you    Explain this on my machine."), "{s}");
    assert!(s.contains("$ ss -tlnp 'sport = :27500'"), "{s}");
    assert!(s.contains("claude Port 27500 is owned by root"), "{s}");
    assert!(s.contains("ask a follow-up"), "{s}");
    // Typing goes to the follow-up line; Enter asks for consent first.
    for ch in "who owns it?".chars() {
        key(&mut a, KeyCode::Char(ch));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 120, 30);
    assert!(
        s.contains("Ask Claude") && s.contains("who owns it?"),
        "{s}"
    );
    assert!(s.contains("read-only commands"), "{s}");
    key(&mut a, KeyCode::Char('n'));
    key(&mut a, KeyCode::Esc);
    let s = render_to_string(&mut a, 120, 30);
    assert!(!s.contains("Claude ·"), "Esc closes the pane: {s}");
}

#[test]
fn jobs_enter_on_cleanup_opens_cleanup_focused() {
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
    let mut a = App::for_test(Config::default(), d, ScreenId::Jobs);
    // cleanup-podman is the 5th job row.
    for _ in 0..4 {
        key(&mut a, KeyCode::Char('j'));
    }
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
    assert!(
        s.contains("rpm-ostree · deployments"),
        "first row opens Updates: {s}"
    );
}

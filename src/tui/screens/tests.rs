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
    assert_eq!(a.screen, ScreenId::Net);
    key(&mut a, KeyCode::Char('l'));
    assert_eq!(a.screen, ScreenId::Cont);
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
fn updates_are_applied_by_quick_update() {
    let mut a = app(ScreenId::Maint);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Same as quick-update on the Upgrade screen (0)"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.screen, ScreenId::Upgrade, "Enter starts it on Upgrade");
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
    let mut a = maint_view(d, 'J');
    let s = render_to_string(&mut a, 158, 41);
    for want in [
        "cleanup-podman",
        "DUE",
        "failed",
        "11d over",
        "Cadence is a reminder",
    ] {
        assert!(s.contains(want), "{want}: {s}");
    }
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
        s.contains("↻ workflow quick-update · step 8/18 Stage upgrade, dropping kmod-nvidia"),
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
    let mut a = maint_view(d, 'J');
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
    assert_eq!(a.screen, ScreenId::Maint);
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
    let after = render_to_string(&mut a, 158, 41);
    assert_ne!(before, after);
    // The views open and Esc comes back.
    for (k, title) in [('F', "Audit report"), ('J', "Jobs")] {
        key(&mut a, KeyCode::Char(k));
        let s = render_to_string(&mut a, 158, 41);
        assert!(s.contains(&format!("Maintenance › {title}")), "{k}: {s}");
        key(&mut a, KeyCode::Esc);
        assert!(render_to_string(&mut a, 158, 41).contains("Recommended"));
    }
    // Cleanup is its own screen: C goes there.
    key(&mut a, KeyCode::Char('C'));
    assert_eq!(a.screen, ScreenId::Clean);
}

#[test]
fn audit_fix_key() {
    // Without Claude Code, `f` is sentry's own list of fixes.
    crate::claude::TEST_AVAILABLE.with(|c| c.set(false));
    let mut d = store();
    d.reports.set(Ok(audit_reports()));
    d.baseline.listeners = vec!["0.0.0.0:22/sshd".into()];
    let mut a = maint_view(d, 'F');
    // Row 1 is "com.visualstudio.code gained filesystem=host": one fix → confirm box.
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Fix    press f: Take the permission away"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('f'));
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
fn audit_fix_with_claude() {
    use crate::claude::{Ask, Event};
    use crate::tui::chat::Chat;
    let mut d = store();
    d.reports.set(Ok(audit_reports()));
    d.baseline.listeners = vec!["0.0.0.0:22/sshd".into()];
    let mut a = maint_view(d, 'F');
    render_to_string(&mut a, 158, 41);
    // `f` shows what would be sent (finding + sentry's known fixes) before anything leaves.
    key(&mut a, KeyCode::Char('f'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Ask Claude") && s.contains("sentry's known fixes"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('n'));
    // An answer with a proposal: `r` opens the confirm box, `n` runs nothing.
    let f = crate::audit::Finding {
        id: "listener:svc:passim (fwupd firmware cache)".into(),
        message: "passim".into(),
        ..Default::default()
    };
    let mut c = Chat::new(Ask::fix(&f));
    c.begin_turn("q", 1, 1);
    c.on_event(Event::Text(
        "**Commands**\n```bash\n# why: stop LAN sharing\nsudo systemctl mask --now passim.service\n```\n"
            .into(),
    ));
    c.on_exit(0);
    a.set_chat(c);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("run a proposed command"), "{s}");
    key(&mut a, KeyCode::Char('r'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Run Claude's proposal"), "{s}");
    assert!(
        s.contains("undo: sudo systemctl unmask passim.service"),
        "{s}"
    );
    assert!(s.contains("sentry runs this as you, not Claude"), "{s}");
    key(&mut a, KeyCode::Char('n'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        !s.contains("Run Claude's proposal") && s.contains("Proposed commands"),
        "{s}"
    );
}

#[test]
fn upgrade_failed_step_fix_with_claude() {
    use crate::claude::{Ask, Event};
    use crate::tui::chat::Chat;
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
    key(&mut a, KeyCode::Char('f'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Ask Claude") && s.contains("step 1/2: Flag file exists"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('n'));

    // Claude proposes a fix; after it, `t` retries the step behind a confirm box.
    let mut c = Chat::new(Ask::step_fix(&facts));
    c.begin_turn("q", 1, 1);
    c.on_event(Event::Text(
        "**Commands**\n```bash\n# why: create it\ntouch /tmp/flag\n```\nThen retry (r).".into(),
    ));
    c.on_exit(0);
    a.set_chat(c);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("run a proposed command") && s.contains("retry the step"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('t'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Retry step 1/2 of flag-test") && s.contains("$ test -f /tmp/flag"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('n'));
    // The step fails again (as if retried): the chat says so and offers the log.
    a.step_exit_for_test(0, 1);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("✗ flag failed again (exit 1)"), "{s}");
    assert!(s.contains("send output"), "{s}");
    a.step_exit_for_test(0, 0);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("✓ flag done"), "{s}");
    assert!(!s.contains("retry the step"), "{s}");
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
    assert_ne!(a.screen, ScreenId::Upgrade);
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
        s.contains("Ask Claude") && s.contains("has ended (abandoned)"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('n'));
    // `v`: the Log view, Esc closes it.
    key(&mut a, KeyCode::Char('v'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Maintenance log") && s.contains("Nothing logged yet"),
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
    assert_eq!(a.screen, ScreenId::Proc);
    key(&mut a, KeyCode::Char('A'));
    assert!(render_to_string(&mut a, 158, 41).contains("Claude · dashboard"));
}

#[test]
fn claude_plans_a_workflow_and_reviews_maintenance() {
    let mut a = app(ScreenId::Maint);
    // p on the updates recommendation: a note first, then what Claude will do.
    key(&mut a, KeyCode::Char('p'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("plan quick-update · a note for Claude"), "{s}");
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Plan quick-update with Claude"), "{s}");
    assert!(
        s.contains("Nothing on this") && s.contains("machine changes"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('n'));
    // Claude's answer becomes the plan: TARGET sets the workflow's target var.
    a.plan_written_for_test(
        "release-rebase",
        [("target".to_string(), "45".to_string())].into(),
        "Reading the ledger.\nTARGET: 46\n# Plan: release-rebase 44 → 46\n\n## Before\n```sh\nrpm-ostree status\n```",
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("ready to apply") && s.contains("→ 46"), "{s}");
    assert!(
        s.contains("rpm-ostree status") && !s.contains("Reading the ledger"),
        "{s}"
    );
    assert!(s.contains("apply (start its workflow)"), "{s}");
    key(&mut a, KeyCode::Esc);
    // It's a recommendation now; x in its view asks before dropping it.
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Plan ready: release-rebase"), "{s}");
    a.apply_for_test(vec![crate::tui::app::Effect::PlanOpen(
        "release-rebase".into(),
    )]);
    key(&mut a, KeyCode::Char('x'));
    assert!(render_to_string(&mut a, 158, 41).contains("Drop the plan for release-rebase"));
    key(&mut a, KeyCode::Char('n'));
    key(&mut a, KeyCode::Esc);
    // R with no review yet: what Claude will do.
    key(&mut a, KeyCode::Char('R'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Review maintenance with Claude"), "{s}");
}

const REVIEW_WITH_TASKS: &str = "Reading the ledger.\n# Maintenance review\n\n## Now\n- update\n\n\
```sentry-tasks\n\
[[task]]\nid = \"ups\"\ntitle = \"Check the UPS battery\"\nwhy = \"It is three years old.\"\n\
level = \"soon\"\nevery = \"90d\"\ndo = \"by-hand\"\nsteps = \"Run `upsc ups` and read the charge.\"\n\n\
[[task]]\nid = \"update\"\ntitle = \"Install the waiting updates\"\nlevel = \"routine\"\n\
do = \"run quick-update\"\n```\n";

#[test]
fn review_suggestions_become_maintenance_tasks() {
    let mut a = app(ScreenId::Maint);
    a.review_written_for_test(REVIEW_WITH_TASKS);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("2 suggested tasks · a adds one"), "{s}");
    assert!(
        s.contains("Suggested tasks") && s.contains("Check the UPS battery"),
        "{s}"
    );
    assert!(
        !s.contains("sentry-tasks"),
        "the block isn't shown as text: {s}"
    );
    // a: pick one, see what's written, confirm.
    key(&mut a, KeyCode::Char('a'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Add which task?"), "{s}");
    key(&mut a, KeyCode::Char('1'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Add this task to Maintenance") && s.contains("[[task]]"),
        "{s}"
    );
    assert!(
        s.contains("tasks.toml") && s.contains("every = \"90d\""),
        "{s}"
    );
    key(&mut a, KeyCode::Char('y'));
    // x: the one left is skipped.
    key(&mut a, KeyCode::Char('x'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("added") && s.contains("skipped"), "{s}");
    assert!(!s.contains("suggested task"), "none open: {s}");
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
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("mark done"), "Enter shows the steps: {s}");
    key(&mut a, KeyCode::Char('n'));
    key(&mut a, KeyCode::Char('d'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("ups done · for the log"), "{s}");
    for c in "checked, 100%".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Recommended · 1 ·"), "done for 90 days: {s}");
    assert!(s.contains("done, in the maintenance log"), "{s}");
}

/// Read-only on this machine: Maintenance from the real collectors, its views, and the
/// dashboard. Point XDG_CONFIG_HOME/XDG_DATA_HOME at scratch copies.
/// `cargo test live_maintenance -- --ignored --nocapture`
#[test]
#[ignore]
fn live_maintenance() {
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

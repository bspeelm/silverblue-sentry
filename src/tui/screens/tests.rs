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
fn upgrade_modal_uses_exact_kmod() {
    let mut a = app(ScreenId::Upd);
    key(&mut a, KeyCode::Char('u'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("rpm-ostree upgrade --uninstall"), "{s}");
    assert!(
        s.contains("kmod-nvidia-7.2.8-200.fc44.x86_64-3:615.71.09-3.fc44.x86_64"),
        "{s}"
    );
    assert!(s.contains("mirror lag"), "modal not clipped:\n{s}");
    key(&mut a, KeyCode::Char('n'));
    assert!(!render_to_string(&mut a, 158, 41).contains("--uninstall"));
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
    b.sections.listeners = Some(vec![listen("0.0.0.0:22/?"), listen("0.0.0.0:22000/syncthing")]);
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
    assert!(s.contains("7 Audit !2"), "badge counts open highs: {s}");
    // Browse to the first report: no diff yet.
    key(&mut a, KeyCode::Char('['));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Nothing to compare against yet"), "{s}");
    let s = render_to_string(&mut a, 80, 24);
    assert!(s.contains("Findings"), "{s}");
}

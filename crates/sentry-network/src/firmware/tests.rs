use super::*;

fn fx(name: &str) -> String {
    std::fs::read_to_string(format!("../../tests/fixtures/network/firmware/{name}")).unwrap()
}

#[test]
fn a_safe_check_is_read_whole_and_its_notices_dont_stop_it() {
    let c = parse_check(&fx("check.txt"));
    assert_eq!(c.from.as_ref().unwrap().version, "25.12.5");
    assert_eq!(
        c.to,
        Some(Ver {
            version: "25.12.6".into(),
            rev: "r33311-981c978eff".into(),
            kernel: "6.12.112".into()
        })
    );
    assert_eq!(c.changes.len(), 6);
    assert_eq!(
        c.changes[2],
        ("example-addon".into(), "1.2.3-r1".into(), "1.2.4-r1".into())
    );
    assert_eq!(c.out_of_date, 6);
    // (`--verbose` lists the defaults instead of counting them: one provided by another.)
    assert_eq!((c.default_missing, c.default_modified), (0, 1));
    assert_eq!((c.failures_here, c.failures_elsewhere), (0, 5));
    assert_eq!(c.verdict, Verdict::Safe);
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    assert!(stops(&c, 0, "25.12.5").is_empty());
    let s = summary(&c, &["example-addon".into(), "luci-app-example".into()]);
    assert!(s[0].contains("From 25.12.5 to 25.12.6"), "{s:?}");
    assert!(
        s.iter().any(|l| l.contains("5 package(s) fail to build")),
        "{s:?}"
    );
}

#[test]
fn colour_codes_dont_hide_the_lines() {
    let text = "\x1b[32mVersion-from\x1b[0m   25.12.5 r1-a (kernel 6.1)\n\
                Version-to     25.12.6 r2-b (kernel 6.2)\n\
                \x1b[1;33mWARNING\x1b[0m: There are 2 missing default packages, confirm this is expected before proceeding\n";
    let c = parse_check(text);
    assert_eq!(c.to.unwrap().version, "25.12.6");
    assert!(c.from.is_some());
    assert_eq!(c.warnings, [Warn::MissingDefaults(2)]);
}

#[test]
fn every_warning_owut_raises_stops_the_plan_and_says_what_it_means() {
    let d = parse_check(&fx("check-downgrade.txt"));
    assert_eq!(d.downgrades, 2);
    assert_eq!(d.verdict, Verdict::Downgrades);
    assert_eq!(d.warnings, [Warn::Downgrades(2)]);
    let why = stops(&d, 0, "25.12.5");
    assert!(why[0].contains("older version"), "{why:?}");

    let f = parse_check(&fx("check-failing.txt"));
    assert_eq!(f.verdict, Verdict::Errors);
    assert_eq!(f.missing, 1);
    assert_eq!((f.failures_here, f.failures_elsewhere), (1, 3));
    assert_eq!(f.default_missing, 1);
    for w in [
        Warn::CustomDefaults,
        Warn::MissingDefaults(1),
        Warn::Missing(1),
        Warn::BuildFailures(1),
    ] {
        assert!(f.warnings.contains(&w), "{w:?} in {:?}", f.warnings);
    }
    let why = stops(&f, 1, "25.12.5");
    assert!(why.len() >= 4, "{why:?}");
    assert!(why.iter().any(|w| w.contains("first-boot settings script")));
    // Anything else it warns about is said as it said it, and stops too.
    let c = parse_check(
        "Version-from 25.12.5 a (kernel 1)\nVersion-to 25.12.6 b (kernel 2)\nWARNING: something new\nIt is safe to proceed with an upgrade\n",
    );
    assert_eq!(c.warnings, [Warn::Other("something new".into())]);
    assert_eq!(stops(&c, 0, "25.12.5"), ["owut said: something new"]);
    for w in [
        "WARNING: Could not access SSL certificates: x",
        "WARNING: Package 'foo' has no available current version",
    ] {
        let c = parse_check(&format!(
            "Version-from 25.12.5 a (kernel 1)\nVersion-to 25.12.6 b (kernel 2)\n{w}\nIt is safe to proceed with an upgrade\n"
        ));
        assert_eq!(stops(&c, 0, "25.12.5").len(), 1, "{w}");
    }
}

#[test]
fn only_a_patch_release_of_the_same_series_goes_on() {
    let ok = "Version-from 25.12.5 a (kernel 1)\nVersion-to 25.12.6 b (kernel 2)\n\nPackage version changes:\n  x 1 2\n\nIt is safe to proceed with an upgrade\n";
    assert!(stops(&parse_check(ok), 0, "25.12.5").is_empty());
    let jump = ok.replace("25.12.6", "26.06.0");
    let why = stops(&parse_check(&jump), 0, "25.12.5");
    assert!(
        why.iter()
            .any(|w| w.contains("from the 25.12 series to 26.06")
                && w.contains("only does patch releases")),
        "{why:?}"
    );
    let snap = ok.replace("25.12.6", "SNAPSHOT");
    assert!(!stops(&parse_check(&snap), 0, "25.12.5").is_empty());
    // The router's own word and owut's disagree: nothing.
    assert!(!stops(&parse_check(ok), 0, "25.12.4").is_empty());
    // Nothing newer.
    let none = "Version-from 25.12.6 a (kernel 1)\nVersion-to 25.12.6 a (kernel 1)\nAll packages are up-to-date\nThere are no changes, upgrade not necessary\n";
    let why = stops(&parse_check(none), 0, "25.12.6");
    assert!(why.iter().any(|w| w.contains("nothing newer")), "{why:?}");
    // No answer at all.
    assert!(!stops(&parse_check(""), 1, "25.12.5").is_empty());
    // owut not saying it's safe isn't a yes.
    let quiet = "Version-from 25.12.5 a (kernel 1)\nVersion-to 25.12.6 b (kernel 2)\n";
    assert!(!stops(&parse_check(quiet), 0, "25.12.5").is_empty());
}

#[test]
fn the_download_is_read_and_the_image_is_checked_against_the_server() {
    let d = parse_download(&fx("download.txt"));
    assert_eq!(d.saved.as_deref(), Some(IMAGE));
    assert_eq!(d.bytes, Some(15247680));
    assert!(d.sum_ok && d.valid && !d.build_failed);
    assert_eq!(d.build_s, Some(76));
    let f = parse_download(&fx("download-failed.txt"));
    assert!(f.build_failed && !f.valid && f.saved.is_none());
    assert_eq!(f.errors.len(), 1, "{:?}", f.errors);

    let m = parse_manifest(&fx("manifest.json")).unwrap();
    assert_eq!(m.version, "25.12.6");
    let (name, sum, size) = m.image.clone().unwrap();
    assert!(name.contains("sysupgrade"));
    assert_eq!(size, 15247680);
    let world: Vec<String> = ["dnsmasq", "example-addon", "luci-app-example", "kernel"]
        .map(String::from)
        .into();
    assert!(image_problems(&m, "25.12.6", &sum, size, &world).is_empty());
    // A different file on the router: its checksum says so.
    let bad = "0".repeat(64);
    let why = image_problems(&m, "25.12.6", &bad, size, &world);
    assert!(why[0].contains("checksum"), "{why:?}");
    assert!(!image_problems(&m, "25.12.6", &sum, size - 1, &world).is_empty());
    assert!(!image_problems(&m, "25.12.7", &sum, size, &world).is_empty());
    // An add-on the image wouldn't have.
    let mut more = world.clone();
    more.push("crowdsec-example-bouncer".into());
    let why = image_problems(&m, "25.12.6", &sum, size, &more);
    assert!(why[0].contains("crowdsec-example-bouncer"), "{why:?}");
    assert!(parse_manifest("not json").is_err());
}

#[test]
fn what_was_installed_by_name_is_looked_for_after_the_flash() {
    // What rpc-sys says: names as a build asks for them (a library without its ABI
    // suffix), the kernel and C library left out.
    let top = r#"{"packages": {"base-files": "1711~f5dae5ece4", "dnsmasq": "2.93-r1",
        "example-addon": "1.2.3-r1", "kernel": "6.12.94", "libubox": "2026.06.19~7dd12784-r1",
        "luci-app-example": "26.180"}}"#;
    let before: Vec<String> = packagelist(top).unwrap().into_iter().collect();
    assert_eq!(
        before,
        [
            "base-files",
            "dnsmasq",
            "example-addon",
            "libubox",
            "luci-app-example"
        ]
    );
    assert!(packagelist("{}").is_err() && packagelist("nope").is_err());
    let now = packagelist(
        r#"{"packages": {"base-files": "1718", "dnsmasq": "2.93-r2", "libubox": "2026.11.02",
        "luci-app-example": "26.325", "new-name": "1"}}"#,
    )
    .unwrap();
    assert_eq!(missing_after(&before, &now, &[]), ["example-addon"]);
    // owut's own replacement: the new name stands for the old; a removal isn't missed.
    let r = vec![("example-addon".to_string(), Some("new-name".to_string()))];
    assert!(missing_after(&before, &now, &r).is_empty());
    let r = vec![("example-addon".to_string(), None)];
    assert!(missing_after(&before, &now, &r).is_empty());
    // What ran before and doesn't now; what was already down isn't counted.
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(
        services_lost(&s(&["dropbear", "uhttpd"]), &s(&["dropbear"])),
        ["uhttpd"]
    );
    assert!(services_lost(&s(&["dropbear"]), &s(&["dropbear", "dnsmasq"])).is_empty());
    assert!(plain_name("luci-app-example") && plain_name("libstdcpp6+x"));
    for bad in ["", "-x", "a;b", "a b", "$(x)", "--force-broken-world"] {
        assert!(!plain_name(bad), "{bad}");
    }
}

#[test]
fn free_memory_is_read_and_judged() {
    let text = "MemTotal:        1010032 kB\nMemFree:          778540 kB\nMemAvailable:     800392 kB\n@@df\nFilesystem           1K-blocks      Used Available Use% Mounted on\ntmpfs                   505016     14144    490872   3% /tmp\n";
    let m = parse_mem(text).unwrap();
    assert_eq!(m.available, 800392 * 1024);
    assert_eq!(m.tmp_free, 490872 * 1024);
    assert!(enough_before(&m).is_ok());
    assert!(enough_for(&m, 15 << 20).is_ok());
    let tight = Mem {
        available: 100 << 20,
        tmp_free: 490 << 20,
    };
    let e = enough_before(&tight).unwrap_err();
    assert!(
        e.contains("100 MiB") && e.contains("Nothing was changed"),
        "{e}"
    );
    assert!(enough_for(&tight, 40 << 20).is_err());
    assert!(parse_mem("MemAvailable: 1 kB\n").is_none());
}

#[test]
fn losing_the_router_is_said_calmly_and_exactly() {
    let st = State {
        backup: Some("2026-11-22T100000Z-25.12.5.tar.gz.age".into()),
        backed_up_at: Some("2026-11-22 10:00".into()),
        step: "the flash (owut checking the image once more, then writing it and restarting the router)".into(),
        ..Default::default()
    };
    let l = lost_words(&st, 900);
    insta::assert_snapshot!(l.join("\n"));
}

#[test]
fn the_runs_record_round_trips() {
    let scope = "net:firmware-state-test";
    let _ = std::fs::remove_file(state_path(scope));
    assert_eq!(State::load(scope), State::default());
    assert!(!missing_now(scope));
    let st = State {
        from: "25.12.5".into(),
        to: "25.12.6".into(),
        world: vec!["a".into()],
        replaced: vec![("x".into(), None), ("y".into(), Some("z".into()))],
        flashed_at: Some("2026-11-22T10:00:00Z".parse().unwrap()),
        missing: vec!["a".into()],
        ..Default::default()
    };
    st.save(scope).unwrap();
    assert_eq!(State::load(scope), st);
    assert!(missing_now(scope));
    let _ = std::fs::remove_file(state_path(scope));
}

mod wait;

/// After the flash, the family filter is read back and said in one line: in place for
/// every device noted, or which of them it isn't whole on.
#[test]
fn the_family_filter_is_said_after_the_flash() {
    use crate::security::blocks::{Blocks, Dev, Filtered};
    use crate::security::family::Found;
    let found = |tag: &str, parts: usize| Found {
        tag: tag.into(),
        mac: "02:00:5e:00:53:01".into(),
        zone: "lan".into(),
        resolver: Some("192.0.2.53".into()),
        sections: (0..parts)
            .map(|i| format!("sentry_filter_{tag}_{i}"))
            .collect(),
    };
    let mut noted = Blocks::default();
    for (tag, label) in [("aa11", "tablet"), ("bb22", "laptop")] {
        noted.filter.insert(tag.into(), Filtered::default());
        noted.device.insert(
            tag.into(),
            Dev {
                label: label.into(),
                ..Default::default()
            },
        );
    }
    assert_eq!(
        family_after(&[found("aa11", 3), found("bb22", 3)], &noted),
        Ok("✓ The family filter's rules are still in place for 2 devices.".into())
    );
    let lost = family_after(&[found("aa11", 3), found("bb22", 2)], &noted).unwrap_err();
    assert!(lost.contains("for laptop (of 2 devices)"), "{lost}");
    let lost = family_after(&[], &noted).unwrap_err();
    assert!(lost.contains("tablet, laptop"), "{lost}");
}

/// The flash asks the guard again and holds its lock: no guarded change starts while the
/// router is flashed, and none under way or waiting lets the flash start.
#[test]
fn no_guarded_change_crosses_a_flash() {
    let scope = format!("net:fw-guard-{}", std::process::id());
    {
        let held = crate::guard::turn(&scope).expect("free");
        let e = no_guard(&scope).err().expect("a guard under way stops it");
        assert!(e.contains("one at a time"), "{e}");
        drop(held);
    }
    // (A child another test forks at that moment holds the lock's descriptor until its
    // exec closes it: free again within a moment.)
    let free = || {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match no_guard(&scope) {
                Ok(t) => return t,
                Err(e) if std::time::Instant::now() > until => panic!("free again: {e}"),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
    };
    let t = free();
    assert!(
        crate::guard::turn(&scope).is_err(),
        "while the flash holds it, no guard starts"
    );
    drop(t);
    let p = crate::guard::pending_path(&scope);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let waiting = crate::guard::Pending {
        token: "t".into(),
        deadline: 0,
        change: crate::guard::Change::parse("dhcp", "uci set dhcp.lan.limit=9", "", false).unwrap(),
    };
    std::fs::write(&p, serde_json::to_string(&waiting).unwrap()).unwrap();
    assert!(crate::guard::pending(&scope).is_some());
    let e = no_guard(&scope).err().expect("a change waiting stops it");
    assert!(e.contains("waiting to be kept"), "{e}");
    let _ = std::fs::remove_dir_all(sentry_core::maint::data_root(&scope));
}

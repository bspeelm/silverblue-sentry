//! Live tests against the disposable router (`scripts/live-router.sh up|test|down`): the
//! only place anything that changes a router is run. Each is `#[ignore]` and does nothing
//! without `SENTRY_ROUTER_SCRATCH=<name>` (the script sets it, with `SENTRY_SSH_CONFIG`
//! and scratch XDG dirs). Never point these at a real router: they stage, commit, break
//! and revert its config.

use std::time::Duration;

use crate::guard::{self, Change, Outcome};
use crate::remote::Router;
use sentry_core::exec::{Cmd, Output};

fn router() -> Option<Router> {
    sentry_core::paths::use_real_dirs();
    let name = std::env::var("SENTRY_ROUTER_SCRATCH").ok()?;
    for v in [
        "SENTRY_SSH_CONFIG",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
    ] {
        assert!(
            std::env::var_os(v).is_some(),
            "{v} isn't set: run these through scripts/live-router.sh"
        );
    }
    let (file, _) = crate::config::load().unwrap();
    let (n, cfg) = crate::config::pick(&file, Some(&name)).unwrap();
    Some(Router::new(n, cfg))
}

/// The program beside the tests (`cargo build -p sentry`; the script builds it).
fn sentry(args: &[&str]) -> Output {
    let me = std::env::current_exe().unwrap();
    let bin = me
        .ancestors()
        .skip(1)
        .take(7)
        .map(|d| d.join("sentry"))
        .find(|p| p.is_file())
        .expect("target/debug/sentry: cargo build -p sentry");
    Cmd::local(&bin.display().to_string())
        .args(args.iter().copied())
        .timeout(Some(Duration::from_secs(180)))
        .run()
        .unwrap()
}

/// On the router, directly: the tests' own looking and setting up.
fn on(r: &Router, script: &str) -> Output {
    r.sh(script)
        .own_connection()
        .timeout(Some(Duration::from_secs(20)))
        .run()
        .unwrap()
}

fn sums(r: &Router, configs: &[&str]) -> String {
    let files: Vec<String> = configs.iter().map(|c| format!("/etc/config/{c}")).collect();
    let o = on(r, &format!("sha256sum {}", files.join(" ")));
    assert_eq!(o.code, 0, "{}", o.stderr);
    o.stdout
}

/// Nothing of a guard is left on the router: no directory, no dead-man, no sleeper.
fn nothing_left(r: &Router, window: u64) {
    let o = on(
        r,
        &format!(
            "ls -d /tmp/sentry-guard-* 2>/dev/null; ps w | grep -e 'deadman[.]sh' -e 'reload[.]sh' -e ' sleep {window}$' | grep -v 'ps w'; true"
        ),
    );
    assert_eq!(o.stdout.trim(), "", "left on the router: {}", o.stdout);
}

fn journal(r: &Router) -> Vec<serde_json::Value> {
    std::fs::read_to_string(guard::journal_path(&r.scope))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn run(r: &Router, c: &Change) -> (Outcome, Vec<String>) {
    let mut said = Vec::new();
    let o = guard::run(r, c, r.cfg.guard.window, &mut |l| {
        println!("  {l}");
        said.push(l);
    });
    println!("→ {o:?}");
    (o, said)
}

/// Real lines through both gateways: a read runs and comes back scrubbed; every other
/// class is refused, and nothing of a refused line ran (a canary file none of them made).
#[test]
#[ignore]
fn live_router_policy() {
    let Some(r) = router() else { return };
    let name = r.name.clone();
    on(&r, "rm -f /tmp/sentry-canary");
    // What the script planted, and must never come back.
    const PRIVATE: &[&str] = &[
        "correct horse battery",
        "planted sae secret",
        "Example Net",
        "kitchen-tablet",
        "storage-box",
        "00:00:5e:00:53:77",
        "02:00:5e:00:53:01",
    ];
    for line in [
        "uci show wireless",
        "uci export wireless",
        "uci -q show wireless | grep -e key -e ssid -e sae",
        "uci show dhcp",
        "cat /tmp/dhcp.leases",
        "grep -v nothing /tmp/dhcp.leases | sort | head -n 20",
        "uci show wireless.default_radio0.key",
        "sh -c 'uci show wireless'",
    ] {
        let o = sentry(&["network", "run", &name, "--", line]);
        assert_eq!(o.code, 0, "{line}: {}", o.stderr);
        assert!(!o.stdout.trim().is_empty(), "{line}: printed nothing");
        for p in PRIVATE {
            assert!(
                !o.stdout.contains(p) && !o.stderr.contains(p),
                "{line}: `{p}` came back"
            );
        }
    }
    let wifi = sentry(&["network", "run", &name, "--", "uci show wireless"]).stdout;
    assert!(
        wifi.contains(".key='redacted:") && wifi.contains(".ssid='‹ssid-1›'"),
        "{wifi}"
    );
    let leases = sentry(&["network", "exec", &name, "--", "cat", "/tmp/dhcp.leases"]).stdout;
    assert!(
        leases.contains("‹nas›")
            && leases.contains("00:00:5e:xx:xx:xx")
            && leases.contains("‹host-"),
        "{leases}"
    );
    // Refused, each in its class's words (126), and none of it ran.
    let asks = "requires approval";
    for (line, says) in [
        ("touch /tmp/sentry-canary", asks),
        ("echo x > /tmp/sentry-canary", asks),
        ("nice touch /tmp/sentry-canary", asks),
        ("sh -c 'touch /tmp/sentry-canary'", asks),
        ("awk 'BEGIN{system(\"touch /tmp/sentry-canary\")}'", asks),
        (
            "find /tmp -maxdepth 0 -exec touch /tmp/sentry-canary \\;",
            asks,
        ),
        ("sort -o /tmp/sentry-canary /tmp/dhcp.leases", asks),
        ("sed -n 'w /tmp/sentry-canary' /proc/uptime", asks),
        ("ls /tmp | xargs touch /tmp/sentry-canary", asks),
        ("touch /tmp/sentry-canary; uci commit network", "guard step"),
        (
            "touch /tmp/sentry-canary; /etc/init.d/dropbear restart",
            "guard step",
        ),
        ("touch /tmp/sentry-canary && apk upgrade", "workflow"),
        ("touch /tmp/sentry-canary; reboot", "workflow"),
        ("touch /tmp/sentry-canary; cat /etc/shadow", "not run"),
        (
            "touch /tmp/sentry-canary; cat /etc/config/wireless",
            "uci show",
        ),
        ("$(touch /tmp/sentry-canary)", "not run"),
        ("ls `touch /tmp/sentry-canary`", "not run"),
        ("uci show wireless | tee /tmp/sentry-canary", "not run"),
        ("uci show wireless > /tmp/sentry-canary", "not run"),
        ("uci show wireless | cut -d= -f2", "not run"),
        ("x=$(uci show wireless); echo ${x#*key=}", "not run"),
        ("sysupgrade -b /tmp/sentry-canary", "not run"),
    ] {
        let o = sentry(&["network", "run", &name, "--", line]);
        assert_eq!(o.code, 126, "{line}: {} {}", o.stdout, o.stderr);
        assert!(o.stderr.contains(says), "{line}: {}", o.stderr);
        assert_eq!(o.stdout, "", "{line}");
        // The chat's gateway turns all of it down, a request too.
        let e = sentry(&["network", "exec", &name, "--", "sh", "-c", line]);
        assert_eq!(e.code, 126, "exec {line}: {} {}", e.stdout, e.stderr);
        assert!(!e.stderr.contains(asks), "exec {line}: {}", e.stderr);
    }
    let canary = on(&r, "ls /tmp/sentry-canary /tmp/b.tgz 2>/dev/null; true");
    assert_eq!(canary.stdout.trim(), "", "a refused line ran");
}

/// Someone else's staged line on a config the change would commit: stopped before
/// anything is snapshotted or armed, and their line is still theirs.
#[test]
#[ignore]
fn live_guard_foreign_staged() {
    let Some(r) = router() else { return };
    let before = sums(&r, &["dhcp"]);
    assert_eq!(on(&r, "uci set dhcp.lan.limit='99'").code, 0);
    let c = Change::parse("dhcp", "uci set dhcp.lan.leasetime='6h'", "dnsmasq", false).unwrap();
    let (o, _) = run(&r, &c);
    let Outcome::Stopped(why) = &o else {
        panic!("{o:?}")
    };
    assert!(
        why.contains("someone else's") && why.contains("dhcp.lan.limit"),
        "{why}"
    );
    nothing_left(&r, r.cfg.guard.window);
    assert_eq!(sums(&r, &["dhcp"]), before);
    let staged = on(&r, "uci changes dhcp").stdout;
    assert!(
        staged.contains("limit") && !staged.contains("leasetime"),
        "{staged}"
    );
    assert_eq!(journal(&r).last().unwrap()["outcome"], "stopped");
    on(&r, "uci revert dhcp");
}

/// The dead-man can't be started (no `setsid` here): its pid is never seen alive, so the
/// guard stops with nothing staged, nothing committed and nothing left behind.
#[test]
#[ignore]
fn live_guard_arm_unverified() {
    let Some(r) = router() else { return };
    let before = sums(&r, &["dhcp"]);
    assert_eq!(on(&r, "mv /usr/bin/setsid /usr/bin/setsid.off").code, 0);
    let c = Change::parse("dhcp", "uci set dhcp.lan.leasetime='6h'", "dnsmasq", false).unwrap();
    let (o, _) = run(&r, &c);
    on(&r, "mv /usr/bin/setsid.off /usr/bin/setsid");
    let Outcome::Stopped(why) = &o else {
        panic!("{o:?}")
    };
    assert!(
        why.contains("couldn't be armed") && why.contains("nothing was changed"),
        "{why}"
    );
    nothing_left(&r, r.cfg.guard.window);
    assert_eq!(sums(&r, &["dhcp"]), before);
    assert_eq!(on(&r, "uci changes dhcp").stdout.trim(), "");
}

/// A harmless change to two guarded configs: applied, confirmed on a new connection,
/// disarmed. The config is changed, and no sleeper or snapshot is left.
#[test]
#[ignore]
fn live_guard_keeps() {
    let Some(r) = router() else { return };
    let before = sums(&r, &["dhcp", "firewall"]);
    let c = Change::parse(
        "dhcp,firewall",
        "uci set dhcp.lan.leasetime='6h'; uci set firewall.web_https.dest_port='8443'",
        "dnsmasq",
        false,
    )
    .unwrap();
    let (o, said) = run(&r, &c);
    assert_eq!(o, Outcome::Kept, "{said:#?}");
    assert!(said.iter().any(|l| l.starts_with("armed:")), "{said:#?}");
    assert!(said.iter().any(|l| l.starts_with("disarmed:")), "{said:#?}");
    nothing_left(&r, r.cfg.guard.window);
    let now = on(
        &r,
        "uci get dhcp.lan.leasetime; uci get firewall.web_https.dest_port",
    )
    .stdout;
    assert_eq!(now, "6h\n8443\n");
    assert_ne!(sums(&r, &["dhcp", "firewall"]), before);
    assert_eq!(
        on(&r, "uci changes dhcp; uci changes firewall")
            .stdout
            .trim(),
        ""
    );
    assert!(guard::pending(&r.scope).is_none());
    assert_eq!(journal(&r).last().unwrap()["outcome"], "kept");
}

/// The change moves ssh to a port nothing reaches (the lock-out a guard is for): sentry
/// can't reconnect, does nothing, and the router puts its configs back byte for byte at
/// the deadline, reloads the same services (ssh answers again) and says so in its log.
#[test]
#[ignore]
fn live_guard_reverts() {
    let Some(r) = router() else { return };
    let window = r.cfg.guard.window;
    assert!(
        window <= 10,
        "a short window for this one (the script sets 6)"
    );
    let before = sums(&r, &["dropbear", "dhcp"]);
    let c = Change::parse(
        "dropbear,dhcp",
        "uci set dropbear.main.Port='2222'; uci set dhcp.lan.leasetime='1h'",
        "dnsmasq,dropbear",
        false,
    )
    .unwrap();
    let (o, said) = run(&r, &c);
    let Outcome::Reverted(why) = &o else {
        panic!("{o:?}: {said:#?}")
    };
    println!("not confirmed because: {why}");
    assert!(
        said.iter().any(|l| l.contains("sentry does nothing more")),
        "{said:#?}"
    );
    // Reachable again on the old port: the door's reload happened.
    assert_eq!(sums(&r, &["dropbear", "dhcp"]), before, "not byte for byte");
    assert_eq!(
        on(&r, "uci changes dropbear; uci changes dhcp")
            .stdout
            .trim(),
        ""
    );
    nothing_left(&r, window);
    let log = on(&r, "logread -e sentry-guard").stdout;
    assert!(
        log.contains("not confirmed within")
            && log.contains("restored dropbear dhcp; reloaded dnsmasq dropbear"),
        "{log}"
    );
    let last = journal(&r).pop().unwrap();
    assert_eq!(last["outcome"], "reverted", "{last}");
}

/// A wireless change is applied and confirmed, and then asks: it stays armed. With no
/// answer the router takes it back at the deadline, and a late "keep" says so.
#[test]
#[ignore]
fn live_guard_wifi_asks() {
    let Some(r) = router() else { return };
    let window = r.cfg.guard.window;
    assert!(
        window <= 10,
        "a short window for this one (the script sets 6)"
    );
    let before = sums(&r, &["wireless"]);
    // (No radio here: nothing reloads it. The config is staged and committed all the same.)
    let c = Change::parse("wireless", "uci set wireless.radio0.channel='6'", "", false).unwrap();
    assert!(c.asks());
    let (o, said) = run(&r, &c);
    assert_eq!(o, Outcome::Waiting, "{said:#?}");
    assert!(said.iter().any(|l| l.starts_with("KEEP?")), "{said:#?}");
    assert!(
        said.iter().any(|l| l.contains("stations before")),
        "{said:#?}"
    );
    assert!(guard::pending(&r.scope).is_some());
    assert_eq!(on(&r, "uci get wireless.radio0.channel").stdout.trim(), "6");
    // Still armed, and a second change can't start meanwhile.
    let armed = on(&r, "ls -d /tmp/sentry-guard-*/armed").stdout;
    assert!(armed.contains("/armed"), "{armed}");
    let (again, _) = run(&r, &c);
    assert!(matches!(again, Outcome::Stopped(_)), "{again:?}");
    // Nobody answers.
    std::thread::sleep(Duration::from_secs(window + 4));
    assert_eq!(sums(&r, &["wireless"]), before, "not byte for byte");
    nothing_left(&r, window);
    let kept = guard::keep(&r, window, &mut |l| println!("  {l}"));
    assert!(matches!(kept, Outcome::Reverted(_)), "{kept:?}");
    assert!(guard::pending(&r.scope).is_none());
    assert_eq!(journal(&r).last().unwrap()["outcome"], "reverted");
}

/// `package-update`'s steps as far as this image goes: the preview refreshes the index
/// and lists; an upgrade without names, with a base package outside the risky step, or
/// with something that isn't a name is refused before any connection.
#[test]
#[ignore]
fn live_package_update() {
    let Some(r) = router() else { return };
    let name = r.name.clone();
    for (rest, says) in [
        (&["upgrade"][..], "no package named"),
        (&["upgrade", "--", "busybox"], "base-system"),
        (
            &["upgrade", "--", "tcpdump;reboot"],
            "isn't a package's name",
        ),
        (
            &["upgrade", "--", "--force-broken-world"],
            "isn't a package's name",
        ),
    ] {
        let mut args = vec!["network", "packages", name.as_str()];
        args.extend(rest);
        let o = sentry(&args);
        assert_eq!(o.code, 3, "{rest:?}: {} {}", o.stdout, o.stderr);
        assert!(o.stderr.contains(says), "{rest:?}: {}", o.stderr);
    }
    let p = sentry(&["network", "packages", &name, "preview"]);
    println!("{}{}", p.stdout, p.stderr);
    assert_eq!(p.code, 0);
    assert!(p.stdout.contains("package(s) could be upgraded"));
    // One that isn't the base system, if the image has one to upgrade.
    let one = p
        .stdout
        .lines()
        .filter(|l| l.starts_with("  ") && !l.contains("(base system)"))
        .find_map(|l| l.split_whitespace().next());
    match one {
        Some(pkg) => {
            let o = sentry(&["network", "packages", &name, "upgrade", "--", pkg]);
            println!("{}{}", o.stdout, o.stderr);
            assert_eq!(o.code, 0, "upgrading {pkg}");
            let c = sentry(&["network", "packages", &name, "check"]);
            println!("check: exit {}\n{}{}", c.code, c.stdout, c.stderr);
        }
        None => println!(
            "nothing but base packages to upgrade in this image: the upgrade itself wasn't run"
        ),
    }
}

/// Against a REAL router, reads only (`SENTRY_NETWORK_LIVE=<name>`, scratch XDG dirs with
/// a copy of the config): what the gateway prints for a set of reads holds none of the
/// uplink's addresses, no unnamed device's MAC in full, no SSID, no unnamed lease's
/// hostname, and no quoted value that is one of the config's secrets. Refused lines and
/// the guard's preflight (reads) are tried too. It prints which check failed, never the
/// output.
#[test]
#[ignore]
fn live_real_router_scrub() {
    sentry_core::paths::use_real_dirs();
    let Ok(name) = std::env::var("SENTRY_NETWORK_LIVE") else {
        return;
    };
    assert!(
        std::env::var_os("XDG_CONFIG_HOME").is_some()
            && std::env::var_os("XDG_DATA_HOME").is_some(),
        "scratch XDG dirs"
    );
    let (file, _) = crate::config::load().unwrap();
    let (n, cfg) = crate::config::pick(&file, Some(&name)).unwrap();
    let r = Router::new(n, cfg);
    let ifaces = crate::collect::ifaces::collect(&r).unwrap();
    let uci = crate::collect::uci::collect(&r).unwrap();
    let raw = crate::collect::clients::collect(&r).unwrap();
    let facts = crate::redact::Facts::of(&ifaces, &uci, &crate::redact::leases_of(&raw));
    let salt = crate::redact::Salt::load(&r.scope).unwrap();
    let named: Vec<String> = r
        .cfg
        .devices
        .iter()
        .filter(|d| d.name.is_some())
        .filter_map(|d| crate::config::mac(d.mac.as_deref()?))
        .collect();
    let known_hosts: Vec<&str> = r
        .cfg
        .devices
        .iter()
        .filter_map(|d| d.hostname.as_deref())
        .collect();
    let mut private: Vec<(&str, String)> = Vec::new();
    for a in &facts.wan {
        let ip = a.split('/').next().unwrap_or(a).to_string();
        // (A delegated prefix is matched by its network part.)
        private.push(("an uplink address", ip.trim_end_matches("::").to_string()));
    }
    for s in &facts.ssids {
        private.push(("an SSID", s.clone()));
    }
    for (host, mac) in &facts.leases {
        if let Some(m) = mac
            && !named.contains(m)
        {
            private.push(("an unnamed MAC", m.clone()));
            private.push(("an unnamed MAC", m.to_uppercase()));
            if host.len() >= 4 && !known_hosts.contains(&host.as_str()) && host != "*" {
                private.push(("an unnamed hostname", host.clone()));
            }
        }
    }
    private.retain(|(_, v)| v.len() >= 4);
    println!(
        "{} private values to look for, {} secret tags",
        private.len(),
        facts.tags.len()
    );
    assert!(!private.is_empty());
    let mut failed = 0;
    let lines = [
        "uci show wireless",
        "uci export wireless",
        "uci show network",
        "uci show dhcp",
        "uci show firewall",
        "ubus call network.interface dump",
        "ubus call network.wireless status",
        "ubus call network.device status",
        "wifi status",
        "cat /tmp/dhcp.leases",
        "cat /tmp/odhcpd.leases",
        "ip addr show",
        "ip -6 addr show",
        "ip route show",
        "ip -6 route show",
        "ip neigh show",
        "cat /proc/net/arp",
        "brctl showmacs br-lan",
        "iwinfo",
        "iw dev",
        "logread -l 300",
        "nft list ruleset",
        "netstat -lntup",
        "ps w",
    ];
    for line in lines {
        let o = sentry(&["network", "run", &name, "--", line]);
        if o.code != 0 {
            println!(
                "{line}: exit {} ({} bytes of stderr)",
                o.code,
                o.stderr.len()
            );
        }
        let out = format!("{}{}", o.stdout, o.stderr);
        for (what, v) in &private {
            // A hostname is a word; the rest are found anywhere.
            let found = if *what == "an unnamed hostname" {
                out.split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_'))
                    .any(|w| w == v)
            } else {
                out.contains(v.as_str())
            };
            if found {
                // Its shape only: every letter and digit masked.
                let shape: Vec<String> = out
                    .lines()
                    .filter(|l| l.contains(v.as_str()))
                    .take(3)
                    .map(|l| {
                        l.replace(v.as_str(), "<V>")
                            .chars()
                            .map(|c| if c.is_ascii_hexdigit() { 'h' } else { c })
                            .collect()
                    })
                    .collect();
                println!("LEAK: `{line}` printed {what} (len {}): {shape:?}", v.len());
                failed += 1;
            }
        }
        for q in ['\'', '"'] {
            for s in out.split(q).skip(1).step_by(2) {
                if s.len() >= 3 && facts.tags.contains(&salt.tag(s)) {
                    println!("LEAK: `{line}` printed a secret's value");
                    failed += 1;
                }
            }
        }
        println!("{line}: {} lines checked", out.lines().count());
    }
    // Refused before any connection.
    for line in [
        "touch /tmp/x",
        "uci commit network",
        "reboot",
        "cat /etc/config/wireless",
    ] {
        assert_eq!(
            sentry(&["network", "run", &name, "--", line]).code,
            126,
            "{line}"
        );
    }
    // The guard's preflight: reads only. (Whether it could start is printed, not judged.)
    let p = sentry(&[
        "network",
        "guard",
        &name,
        "preview",
        "configs=dropbear",
        "--",
        "uci set dropbear.main.Port='22'",
    ]);
    println!("guard preview (dropbear): exit {}", p.code);
    let p = sentry(&[
        "network",
        "guard",
        &name,
        "preview",
        "configs=dhcp",
        "services=dnsmasq",
        "--",
        "uci set dhcp.lan.leasetime='12h'",
    ]);
    println!(
        "guard preview (dhcp + dnsmasq): exit {}{}",
        p.code,
        if p.stderr.contains("someone else's") {
            " (stopped: lines staged by something else)"
        } else {
            ""
        }
    );
    assert_eq!(failed, 0, "{failed} leak(s)");
}

/// An apply session through the app, Claude's turns scripted (nothing is sent): a plan
/// with a change that is a plain command and one guard step → approved with Enter → the
/// command runs on the router, the `guarded-change` workflow starts, its guard step waits
/// for Enter, applies and is kept → Claude's verdict → the session's entry in the log.
/// (The change is a plan's `run` step, not a request made mid-turn: a refused tool call
/// can't be scripted without a real turn.)
#[test]
#[ignore]
fn live_router_session() {
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use sentry_app::{App, Event};
    use sentry_core::apply::session::Phase;
    use sentry_core::claude::{Apply, Ask, Refuses};
    use sentry_core::workflows::runner::Next;
    use std::time::Instant;

    let Some(r) = router() else { return };
    let name = r.name.clone();
    let scope = r.scope.clone();
    on(&r, "rm -f /tmp/sentry-session-canary");
    let before = sums(&r, &["dhcp"]);
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(
        tx,
        &crate::tui::id_of(&name),
        crate::tui::target(router().unwrap()),
    );
    a.win.scripted_turns = true;
    a.win.theme = sentry_core::tui::theme::Theme::truecolor();
    a.start(Instant::now());
    a.slot_mut().auto_review.after_run = false;
    a.slot_mut().auto_review.at_start = false;
    let pump = |a: &mut App, secs: u64| {
        let until = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < until {
            if let Ok(ev) = rx.recv_timeout(Duration::from_millis(100)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
        }
    };
    let key = |a: &mut App, c: KeyCode| {
        a.on_event(
            Event::Key(KeyEvent::new(c, KeyModifiers::NONE)),
            Instant::now(),
        );
    };
    let screen = |a: &mut App| sentry_app::app::render_to_string(a, 158, 41);
    pump(&mut a, 3);
    let ask = Ask::apply(
        "a shorter lease",
        format!("Network `{name}`: make the lan's DHCP leases six hours."),
        Apply {
            key: "live:session".into(),
            remote: true,
            refuses: Refuses(Some(crate::tui::ask::refuses)),
            asks_each: true,
            ..Default::default()
        },
    );
    a.apply(
        vec![sentry_app::effect::Effect::AskConsent(Box::new(ask))],
        Instant::now(),
    );
    assert!(a.apply_session().is_some(), "{}", screen(&mut a));
    key(&mut a, KeyCode::Enter);
    assert!(
        matches!(a.apply_session().unwrap().phase, Phase::Thinking(_)),
        "{}",
        screen(&mut a)
    );
    // A plan the router's rules send back: a guarded line as a plain step.
    a.apply_answer_for_test(
        "```sentry-apply\nsummary = \"lease\"\n\n[[step]]\ntitle = \"commit\"\nrun = \"uci set dhcp.lan.leasetime='6h'; uci commit dhcp\"\n```\n",
    );
    let s = screen(&mut a);
    let sent = a.slot().last_prompt.clone().unwrap_or_default();
    assert!(
        matches!(a.apply_session().unwrap().phase, Phase::Thinking(_))
            && s.contains("can't use step 1 as written")
            && sent.contains("guard step"),
        "a guarded line in a plan goes back to Claude, with why: {sent}\n{s}"
    );
    assert_eq!(sums(&r, &["dhcp"]), before);
    // The plan as it should be.
    a.apply_answer_for_test(
        "```sentry-apply\nsummary = \"a marker, then the lease through the guard\"\n\n\
         [[step]]\ntitle = \"leave a marker\"\nrun = \"touch /tmp/sentry-session-canary\"\n\n\
         [[step]]\ntitle = \"six-hour leases\"\nworkflow = \"guarded-change\"\n\
         vars = { configs = \"dhcp\", lines = \"uci set dhcp.lan.leasetime='6h'\", services = \"dnsmasq\" }\n```\n",
    );
    assert!(
        matches!(a.apply_session().unwrap().phase, Phase::Review),
        "{}",
        screen(&mut a)
    );
    // Nothing has run yet.
    assert_ne!(on(&r, "ls /tmp/sentry-session-canary").code, 0);
    key(&mut a, KeyCode::Enter);
    // From here: Enter only where the guard step waits for it; the verdict when asked.
    let until = Instant::now() + Duration::from_secs(120);
    let mut confirmed = false;
    let mut verdict = false;
    loop {
        pump(&mut a, 1);
        let run_next = a
            .slot()
            .run
            .as_ref()
            .map(|w| (w.next().clone(), w.live().is_some()));
        if let Some((Next::Confirm(i), false)) = run_next
            && !confirmed
        {
            assert_eq!(i, 1, "the guard step");
            // The marker was made by the first step, before the guard was asked for.
            assert_eq!(on(&r, "ls /tmp/sentry-session-canary").code, 0);
            assert_eq!(
                sums(&r, &["dhcp"]),
                before,
                "nothing changed before the Enter"
            );
            key(&mut a, KeyCode::Char('0'));
            key(&mut a, KeyCode::Enter);
            confirmed = true;
            continue;
        }
        let thinking = a.apply_session().is_some_and(|s| s.chat.live.is_some());
        if confirmed && thinking && !verdict {
            let prompt = a.slot().last_prompt.clone().unwrap_or_default();
            assert!(!prompt.contains("correct horse battery") && !prompt.contains("Example Net"));
            a.apply_answer_for_test(
                "The lease is six hours.\n\n```sentry-verdict\nstatus = \"done\"\nsummary = \"leases are six hours\"\n```\n",
            );
            verdict = true;
            continue;
        }
        if verdict
            && a.apply_session()
                .is_some_and(|s| matches!(s.phase, Phase::Settled(_)))
        {
            break;
        }
        // A note for the run's log entry: none.
        if matches!(a.win.input, sentry_core::tui::input::Input::Prompt(..)) {
            key(&mut a, KeyCode::Enter);
        }
        assert!(
            Instant::now() < until,
            "it never settled: {}",
            screen(&mut a)
        );
    }
    let s = screen(&mut a);
    println!("{s}");
    assert_eq!(on(&r, "uci get dhcp.lan.leasetime").stdout.trim(), "6h");
    nothing_left(&r, r.cfg.guard.window);
    assert_eq!(journal(&r).last().unwrap()["outcome"], "kept");
    let log = sentry_core::maint::log::list(&scope);
    let kinds: Vec<String> = log
        .iter()
        .map(|e| format!("{}/{}/{}", e.head.kind, e.head.workflow, e.head.result))
        .collect();
    println!("{kinds:?}");
    assert!(
        log.iter()
            .any(|e| e.head.workflow == "guarded-change" && e.head.result == "done"),
        "{kinds:?}"
    );
    assert!(log.iter().any(|e| e.head.kind == "apply"), "{kinds:?}");
}

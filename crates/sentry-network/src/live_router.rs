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

/// Nothing of a guard is left on the router: no directory, no snapshot or boot hook on
/// flash, no dead-man, no sleeper.
fn nothing_left(r: &Router, window: u64) {
    let o = on(
        r,
        &format!(
            "ls -d /tmp/sentry-guard-* /etc/sentry-guard /etc/sentry-guard/* /etc/uci-defaults/*sentry-guard* 2>/dev/null; ps w | grep -e 'deadman[.]sh' -e 'reload[.]sh' -e ' sleep {window}$' | grep -v 'ps w'; true"
        ),
    );
    assert_eq!(o.stdout.trim(), "", "left on the router: {}", o.stdout);
}

/// What the router itself says of how a guard ended.
fn last(r: &Router) -> String {
    on(
        r,
        "cat /tmp/sentry-guard.last /etc/sentry-guard.last 2>/dev/null; true",
    )
    .stdout
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

/// The program with the gateway's trace on: every line it sends to the router is
/// appended to `trace`, exactly as sent.
fn traced(trace: &std::path::Path, args: &[&str]) -> Output {
    let me = std::env::current_exe().unwrap();
    let bin = me
        .ancestors()
        .skip(1)
        .take(7)
        .map(|d| d.join("sentry"))
        .find(|p| p.is_file())
        .expect("target/debug/sentry: cargo build -p sentry");
    Cmd::local("env")
        .arg(format!("SENTRY_GATEWAY_TRACE={}", trace.display()))
        .arg(bin.display().to_string())
        .args(args.iter().copied())
        .timeout(Some(Duration::from_secs(180)))
        .run()
        .unwrap()
}

/// Real lines through both gateways: a read runs, rebuilt, and comes back scrubbed; every
/// other class is refused, and nothing of a refused line ran (a canary file none of them
/// made, and nothing in the trace of what was sent).
#[test]
#[ignore]
fn live_router_policy() {
    let Some(r) = router() else { return };
    let name = r.name.clone();
    on(
        &r,
        "rm -f /tmp/sentry-canary /tmp/sentry-proof; echo keep > /tmp/sentry-victim",
    );
    let trace = std::env::temp_dir().join(format!("sentry-trace-{}", std::process::id()));
    let _ = std::fs::remove_file(&trace);
    let sent = || std::fs::read_to_string(&trace).unwrap_or_default();
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
    // (the line, what the router was sent for it)
    for (line, router_saw) in [
        ("uci show wireless", "uci 'show' 'wireless'"),
        ("uci export wireless", "uci 'export' 'wireless'"),
        (
            "uci -q show wireless | grep -e key -e ssid -e sae",
            "uci '-q' 'show' 'wireless'",
        ),
        ("uci show dhcp", "uci 'show' 'dhcp'"),
        ("cat /tmp/dhcp.leases", "cat '/tmp/dhcp.leases'"),
        (
            "grep -v nothing /tmp/dhcp.leases | sort | head -n 20",
            "cat '/tmp/dhcp.leases'",
        ),
        (
            "uci show wireless.default_radio0.key",
            "uci 'show' 'wireless.default_radio0.key'",
        ),
        // Cut up, but here, after the scrubbing: the router only prints the file.
        ("cut -d' ' -f2,4 /tmp/dhcp.leases", "cat '/tmp/dhcp.leases'"),
        (
            "cat /tmp//./dhcp.leases | cut -c1-40",
            "cat '/tmp/dhcp.leases'",
        ),
        ("ls -d /sys/class/net/*", "ls '-d' /sys/class/net/*"),
        (
            "cat /sys/class/net/*/address",
            "cat /sys/class/net/*/address",
        ),
        (
            "find /etc/config -name 'wire*' -type f",
            "find '/etc/config' '-name' 'wire*' '-type' 'f'",
        ),
        (
            "/etc/init.d/dropbear status",
            "/etc/init.d/dropbear 'status'",
        ),
        ("logread -l 20 -e dropbear", "logread '-l' '20'"),
    ] {
        let _ = std::fs::remove_file(&trace);
        let o = traced(&trace, &["network", "run", &name, "--", line]);
        assert_eq!(o.code, 0, "{line}: {}", o.stderr);
        assert_eq!(sent().trim_end(), router_saw, "{line}");
        if !line.starts_with("logread") {
            assert!(!o.stdout.trim().is_empty(), "{line}: printed nothing");
        }
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
    // A pattern is matched on what the scrubbing left, never on the router: the planted
    // key does start with `c`, and a grep there would have said 1.
    let direct = on(&r, "uci show wireless | grep -c \"key='c\"");
    assert_eq!(direct.stdout.trim(), "1", "the plant is there");
    let _ = std::fs::remove_file(&trace);
    let o = traced(
        &trace,
        &[
            "network",
            "run",
            &name,
            "--",
            "uci show wireless | grep -c \"key='c\"",
        ],
    );
    assert_eq!((o.stdout.trim(), o.code), ("0", 1), "{}", o.stderr);
    assert_eq!(sent().trim_end(), "uci 'show' 'wireless'");
    let o = sentry(&[
        "network",
        "run",
        &name,
        "--",
        "grep -c 00:00:5e:00:53:77 /tmp/dhcp.leases",
    ]);
    assert_eq!(
        o.stdout.trim(),
        "0",
        "a MAC's hidden half can't be asked for"
    );

    // These are real on this router's shell (BusyBox 1.37 ash), run directly: that is
    // what the gateway must never pass on.
    // Review item 6: ash does read `$'…'` (ANSI-C quoting), so the quote closes early
    // and what follows the `;` runs.
    on(&r, "echo $'\\'' ; touch /tmp/sentry-proof #'");
    assert_eq!(on(&r, "ls /tmp/sentry-proof").code, 0, "ash reads $'…'");
    on(&r, "rm -f /tmp/sentry-proof");
    // Item 2: a `#` starts a comment, so its quote never opens.
    on(&r, "echo x #'\ntouch /tmp/sentry-proof\n#'");
    assert_eq!(on(&r, "ls /tmp/sentry-proof").code, 0, "ash reads comments");
    on(&r, "rm -f /tmp/sentry-proof");
    // Item 4: this busybox's `sort` takes `-uo<file>` without complaint (exit 0) but its
    // `-o` isn't built in: the sorted text goes to stdout and no file is written. So the
    // cluster wasn't a write here; it is refused all the same (another build's would be).
    let s = on(
        &r,
        "sort -uo/tmp/sentry-proof /proc/uptime; echo rc=$?; ls /tmp/sentry-proof",
    );
    println!("sort -uo<file> on this router: {:?}", s.stdout);
    assert!(s.stdout.contains("rc=0"), "{}", s.stdout);
    on(&r, "rm -f /tmp/sentry-proof");

    // Refused, each in its class's words (126), and none of it ran.
    let asks = "requires approval";
    let _ = std::fs::remove_file(&trace);
    for (line, says) in [
        ("touch /tmp/sentry-canary", asks),
        ("echo x > /tmp/sentry-canary", asks),
        ("nice touch /tmp/sentry-canary", asks),
        ("sh -c 'touch /tmp/sentry-canary'", asks),
        ("awk 'BEGIN{system(\"touch /tmp/sentry-canary\")}'", asks),
        ("sort -o /tmp/sentry-canary /tmp/dhcp.leases", asks),
        ("sed -n 'w /tmp/sentry-canary' /proc/uptime", asks),
        ("ls /tmp | xargs touch /tmp/sentry-canary", asks),
        // The review's inputs, with a canary where the dangerous half was.
        // 1: a substitution in double quotes.
        ("echo \"$(touch /tmp/sentry-canary)\"", asks),
        ("echo \"`touch /tmp/sentry-canary`\"", asks),
        ("X=\"$(touch /tmp/sentry-canary)\"", asks),
        (
            "echo \"$(wifi down; touch /tmp/sentry-canary)\"",
            "guard step",
        ),
        ("X=\"$(touch /tmp/sentry-canary; reboot)\"", "workflow"),
        // 2: a comment that swallows a quote.
        ("echo x #'\ntouch /tmp/sentry-canary\n#'", asks),
        // 3: find's second -exec, -delete, -fprint.
        (
            "find /tmp -maxdepth 0 -exec ls {} \x5c; -exec touch /tmp/sentry-canary \x5c;",
            asks,
        ),
        ("find /tmp/sentry-victim -delete", asks),
        ("find /etc/config -delete", "not run"),
        ("find /tmp -maxdepth 0 -fprint /tmp/sentry-canary", asks),
        // 4: a flag in a cluster.
        ("sort -uo/tmp/sentry-canary /proc/uptime", asks),
        ("sort -uo/etc/sentry-canary /proc/uptime", "not run"),
        // 5: a change spelled as a flag.
        ("ifconfig lo -arp", "guard step"),
        ("arp -ns 192.0.2.9 02:00:5e:00:53:09", "guard step"),
        // 6: ANSI-C quoting.
        ("echo $'\\'' ; touch /tmp/sentry-canary #'", asks),
        // 7: transforms on the router.
        ("tr -d : < /tmp/dhcp.leases", asks),
        ("cut -c1-9 < /tmp/dhcp.leases", asks),
        ("awk '{print $2}' < /tmp/dhcp.leases", asks),
        ("od -c /tmp/dhcp.leases", asks),
        ("hexdump -C /proc/net/arp", asks),
        // 8: `//`.
        ("cat /etc//config/wireless", "uci show"),
        (
            "cat /sys//kernel/debug/ieee80211/phy0/keys/0/key",
            "not run",
        ),
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
        ("uci show wireless | tr -d \"'\"", "not run"),
        ("x=$(uci show wireless); echo ${x#*key=}", "not run"),
        ("sysupgrade -b /tmp/sentry-canary", "not run"),
        ("sysupgrade -l", "not run"),
    ] {
        let o = traced(&trace, &["network", "run", &name, "--", line]);
        assert_eq!(o.code, 126, "{line}: {} {}", o.stdout, o.stderr);
        assert!(o.stderr.contains(says), "{line}: {}", o.stderr);
        assert_eq!(o.stdout, "", "{line}");
        // The chat's gateway turns all of it down, a request too.
        let e = traced(&trace, &["network", "exec", &name, "--", "sh", "-c", line]);
        assert_eq!(e.code, 126, "exec {line}: {} {}", e.stdout, e.stderr);
        assert!(!e.stderr.contains(asks), "exec {line}: {}", e.stderr);
        assert_eq!(sent(), "", "{line}: something was sent to the router");
    }
    let canary = on(
        &r,
        "ls /tmp/sentry-canary /etc/sentry-canary /tmp/b.tgz 2>/dev/null; cat /tmp/sentry-victim",
    );
    assert_eq!(canary.stdout.trim(), "keep", "a refused line ran");
    on(&r, "rm -f /tmp/sentry-victim");
    let _ = std::fs::remove_file(&trace);
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
    assert!(
        said.iter()
            .any(|l| l.contains("confirmed on a new connection, twice")),
        "{said:#?}"
    );
    nothing_left(&r, r.cfg.guard.window);
    // "Kept" is what the router says too: the disarm's claim was the one that held.
    assert!(last(&r).contains(" kept "), "{}", last(&r));
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
        "a short window for this one (the script sets 8)"
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
        "a short window for this one (the script sets 8)"
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
    // Still armed, and a second change can't start meanwhile. What a restart would
    // restore from is on flash while it waits.
    let armed = on(
        &r,
        "ls -d /tmp/sentry-guard-*/armed /etc/sentry-guard/*/config/wireless /etc/uci-defaults/zz-sentry-guard-*",
    );
    assert_eq!(armed.stdout.lines().count(), 3, "{}", armed.stdout);
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

/// The disarm and the dead-man meet. (1) The sleeper has the guard and is in the middle
/// of its restore (held there for the test): a disarm arriving then loses, touches
/// nothing, and sentry reports what the router did, not "kept". (2) A disarm sent right
/// around the moment the timer fires, many times over: each time exactly one side has
/// the guard, and the router's config and its own word agree with which. Also: the
/// sleeper outlives the connection that started it (dropbear closed that session).
#[test]
#[ignore]
fn live_guard_race() {
    let Some(r) = router() else { return };
    let before = sums(&r, &["dhcp"]);
    let c = Change::parse("dhcp", "uci set dhcp.lan.leasetime='6h'", "dnsmasq", false).unwrap();
    let lease = || {
        on(&r, "uci get dhcp.lan.leasetime")
            .stdout
            .trim()
            .to_string()
    };
    let has = |out: &str, word: &str| out.lines().any(|l| l.trim() == word);

    // (1) Mid-restore.
    let token = "ace0000000000001";
    let arm = on(&r, &guard::arm_script_slow(&c, token, 2, 5));
    assert_eq!(arm.code, 0, "{}", arm.stderr);
    // A new connection: the one that armed it is closed, and the sleeper is still there.
    let alive = on(&r, &guard::armed_script(token)).stdout;
    assert!(
        alive.starts_with("armed "),
        "the sleeper died with its session: {alive}"
    );
    assert!(
        on(&r, &guard::apply_script(&c, token))
            .stdout
            .contains("@@launched")
    );
    assert_eq!(lease(), "6h");
    std::thread::sleep(Duration::from_millis(3200));
    // It woke at 2 s, took the guard, and is held before its restore until 7 s.
    let raw = on(&r, &guard::disarm_script(token)).stdout;
    println!("a disarm mid-restore says: {raw:?}");
    assert!(
        has(&raw, "lost") && has(&raw, "restoring") && !has(&raw, "claimed"),
        "{raw}"
    );
    let still = on(
        &r,
        &format!(
            "ls -d /tmp/sentry-guard-{token}/claim.deadman /etc/sentry-guard/{token}/config/dhcp /etc/uci-defaults/zz-sentry-guard-{token}; kill -0 $(cat /tmp/sentry-guard-{token}/pid) && echo alive"
        ),
    )
    .stdout;
    assert_eq!(
        still.lines().count(),
        4,
        "the disarm touched something: {still}"
    );
    assert_eq!(lease(), "6h", "nothing restored yet, nothing removed");
    // A signal doesn't stop it half-way either.
    on(
        &r,
        &format!(
            "kill -TERM $(cat /tmp/sentry-guard-{token}/pid); kill -HUP $(cat /tmp/sentry-guard-{token}/pid); true"
        ),
    );
    // sentry's own disarm at this moment: it lost, so it waits and asks.
    let mut said = Vec::new();
    let o = guard::disarm(&r, token, 20, Duration::from_secs(6), &mut |l| {
        println!("  {l}");
        said.push(l);
    });
    println!("→ {o:?}");
    assert!(matches!(o, Outcome::Reverted(_)), "{o:?}");
    assert!(
        !said.iter().any(|l| l.starts_with("disarmed:")),
        "{said:#?}"
    );
    assert_eq!(sums(&r, &["dhcp"]), before, "restored whole, byte for byte");
    assert!(
        last(&r).contains(&format!("{token} reverted")),
        "{}",
        last(&r)
    );
    let log = on(&r, "logread -e sentry-guard").stdout;
    assert!(
        log.contains(&format!("{token}: restored dhcp; reloaded dnsmasq")),
        "the reloads were skipped: {log}"
    );
    nothing_left(&r, 2);

    // (2) At the wire: a 1 s window, the disarm sent from just before to just after it.
    let (mut kept, mut reverted) = (0, 0);
    // (Put back by hand after a round that was kept, uci writes the file its own way:
    // what "as before" is from then on.)
    let mut base = before.clone();
    for (i, wait_ms) in [550u64, 650, 700, 750, 800, 850, 900, 950, 1000, 1100]
        .into_iter()
        .enumerate()
    {
        let token = format!("ace00000000001{i:02x}");
        let armed = std::time::Instant::now();
        assert_eq!(on(&r, &guard::arm_script(&c, &token, 1)).code, 0);
        let applied = on(&r, &guard::apply_script(&c, &token));
        // (The sleeper may have fired before the lines were staged: then nothing was.)
        let staged = applied.stdout.contains("@@launched");
        std::thread::sleep(Duration::from_millis(wait_ms).saturating_sub(armed.elapsed()));
        let raw = on(&r, &guard::disarm_script(&token)).stdout;
        let at = armed.elapsed().as_millis();
        std::thread::sleep(Duration::from_millis(2500));
        let word = last(&r);
        let claimed = has(&raw, "claimed");
        let took_back = word.contains(&format!("{token} reverted"));
        println!(
            "disarm sent {wait_ms} ms after arming (answered at {at} ms): {} · router: {}",
            if claimed { "claimed" } else { "lost" },
            word.trim()
        );
        assert!(has(&raw, "claimed") != has(&raw, "lost"), "{raw}");
        assert!(
            claimed != took_back,
            "both sides, or neither, had the guard: {raw} / {word}"
        );
        if claimed {
            kept += 1;
            assert!(word.contains(&format!("{token} kept")), "{word}");
            if staged {
                assert_eq!(lease(), "6h", "kept, and the change is in place");
            }
            on(&r, "uci set dhcp.lan.leasetime='12h'; uci commit dhcp");
            base = sums(&r, &["dhcp"]);
        } else {
            reverted += 1;
        }
        assert_eq!(lease(), "12h", "round {i}");
        assert_eq!(sums(&r, &["dhcp"]), base, "round {i}: not byte for byte");
        assert_eq!(on(&r, "uci changes dhcp").stdout.trim(), "");
        nothing_left(&r, 1);
    }
    println!("{kept} disarms had the guard, {reverted} times the sleeper did");
    assert!(kept + reverted == 10);
}

/// A restart inside the window. The sleeper and everything in /tmp are gone with it; the
/// snapshot and the one-shot hook are on flash, and what OpenWrt's boot does with
/// /etc/uci-defaults (run here as `/etc/init.d/boot` has it: a container can't be
/// rebooted) puts the configs back byte for byte and removes the hook. A change that was
/// kept leaves neither, and a restart after it restores nothing.
#[test]
#[ignore]
fn live_guard_reboot() {
    let Some(r) = router() else { return };
    // The boot's own lines, as this image has them: what is run below is the same.
    let boot = on(&r, "cat /etc/init.d/boot").stdout;
    assert!(
        boot.contains("cd /etc/uci-defaults || return 0")
            && boot.contains("( . \"./$(basename $file)\" ) && applied=\"$applied $file\"")
            && boot.contains("rm -f $applied"),
        "this image's boot doesn't run /etc/uci-defaults the way the hook expects:\n{boot}"
    );
    const AT_BOOT: &str = "cd /etc/uci-defaults || exit 0\nfiles=\"$(ls)\"\n[ -z \"$files\" ] && exit 0\napplied=\"\"\nfor file in $files; do\n\t( . \"./$(basename $file)\" ) && applied=\"$applied $file\"\ndone\nuci commit\nsync\nrm -f $applied\n";
    let before = sums(&r, &["dhcp", "firewall"]);
    let c = Change::parse(
        "dhcp,firewall",
        "uci set dhcp.lan.leasetime='6h'; uci set firewall.web_https.dest_port='8443'; uci add firewall rule; uci set firewall.@rule[-1].name='new'",
        "dnsmasq",
        false,
    )
    .unwrap();
    let token = "b0070000000000aa";
    assert_eq!(on(&r, &guard::arm_script(&c, token, 300)).code, 0);
    assert!(
        on(&r, &guard::apply_script(&c, token))
            .stdout
            .contains("@@launched")
    );
    assert_ne!(sums(&r, &["dhcp", "firewall"]), before, "committed");
    // Something staged by someone else when the power goes: the boot's `uci commit`
    // must not make it part of what is restored.
    on(&r, "uci set dhcp.lan.limit='99'");
    let flash = on(
        &r,
        &format!(
            "ls -ld /etc/sentry-guard /etc/sentry-guard/{token} | cut -c1-10; ls /etc/sentry-guard/{token}/config; wc -c < /etc/uci-defaults/zz-sentry-guard-{token}; du -sk /etc/sentry-guard | cut -f1"
        ),
    )
    .stdout;
    println!("on flash while armed:\n{flash}");
    assert!(
        flash.starts_with("drwx------\ndrwx------\n") && flash.contains("dhcp\nfirewall\n"),
        "{flash}"
    );
    // The restart: no process survives, /tmp is empty.
    on(
        &r,
        &format!(
            "kill -9 $(cat /tmp/sentry-guard-{token}/pid) $(cat /tmp/sentry-guard-{token}/sleep.pid); rm -rf /tmp/sentry-guard-{token} /tmp/sentry-guard.last /tmp/.uci"
        ),
    );
    let o = on(&r, AT_BOOT);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert_eq!(
        sums(&r, &["dhcp", "firewall"]),
        before,
        "not byte for byte after the boot hook"
    );
    assert!(
        last(&r).contains(&format!("{token} reverted")) && last(&r).contains("at boot"),
        "{}",
        last(&r)
    );
    nothing_left(&r, 300);
    // Asked afterwards, the router says so.
    let said = on(&r, &guard::settled_script(token)).stdout;
    assert!(said.contains(&format!("{token} reverted")), "{said}");
    on(&r, "rm -f /etc/sentry-guard.last");

    // Kept: neither the snapshot nor the hook is left, and a restart restores nothing.
    let c = Change::parse("dhcp", "uci set dhcp.lan.leasetime='6h'", "dnsmasq", false).unwrap();
    let (o, said) = run(&r, &c);
    assert_eq!(o, Outcome::Kept, "{said:#?}");
    nothing_left(&r, r.cfg.guard.window);
    let kept = sums(&r, &["dhcp"]);
    assert_eq!(on(&r, AT_BOOT).code, 0);
    assert_eq!(
        sums(&r, &["dhcp"]),
        kept,
        "a restart took a kept change back"
    );
    assert_eq!(on(&r, "uci get dhcp.lan.leasetime").stdout.trim(), "6h");
    assert!(!last(&r).contains("at boot"), "{}", last(&r));
}

/// What an earlier guard left with nothing alive to settle it (its sleeper never
/// started or died, and the link was gone before sentry could clear it) doesn't block
/// the next one until a restart: applying takes back what was never confirmed and
/// clears it. A guard whose sleeper lives is left alone.
#[test]
#[ignore]
fn live_guard_stale_leftover() {
    let Some(r) = router() else { return };
    let before = sums(&r, &["dhcp", "firewall"]);
    // (a) Armed, a change applied under it, and then its sleeper is gone.
    let old = Change::parse("dhcp", "uci set dhcp.lan.leasetime='6h'", "dnsmasq", false).unwrap();
    let token = "5ea1e00000000001";
    assert_eq!(on(&r, &guard::arm_script(&old, token, 300)).code, 0);
    assert!(
        on(&r, &guard::apply_script(&old, token))
            .stdout
            .contains("@@launched")
    );
    on(
        &r,
        &format!(
            "kill -9 $(cat /tmp/sentry-guard-{token}/pid) $(cat /tmp/sentry-guard-{token}/sleep.pid)"
        ),
    );
    assert_eq!(on(&r, "uci get dhcp.lan.leasetime").stdout.trim(), "6h");
    // (b) And an arm that never got that far: a directory, nothing else.
    on(&r, "mkdir /tmp/sentry-guard-5ea1e00000000002");
    let new = Change::parse(
        "firewall",
        "uci set firewall.web_https.dest_port='8443'",
        "",
        false,
    )
    .unwrap();
    // A preview only reads: it says what applying will clear, and clears nothing.
    let mut lines = Vec::new();
    guard::preview(&r, &new, &mut |l| lines.push(l)).expect("it could start");
    assert!(
        lines.iter().any(|l| l.contains("applying clears it first")),
        "{lines:#?}"
    );
    assert_eq!(
        on(&r, "ls -d /tmp/sentry-guard-* | wc -l").stdout.trim(),
        "2"
    );
    let (o, said) = run(&r, &new);
    assert_eq!(o, Outcome::Kept, "{said:#?}");
    assert!(
        said.iter()
            .any(|l| l.contains(token) && l.contains("put back")),
        "{said:#?}"
    );
    assert!(
        said.iter()
            .any(|l| l.contains("5ea1e00000000002") && l.contains("were cleared")),
        "{said:#?}"
    );
    // The old change is taken back, the new one is in place, nothing is left.
    assert_eq!(on(&r, "uci get dhcp.lan.leasetime").stdout.trim(), "12h");
    assert_eq!(
        on(&r, "uci get firewall.web_https.dest_port").stdout.trim(),
        "8443"
    );
    assert_eq!(sums(&r, &["dhcp"]), sums_of(&before, "dhcp"));
    nothing_left(&r, 300);

    // (c) One whose sleeper lives isn't a leftover: nothing starts beside it, nothing
    // clears it, and it settles by itself.
    let token = "5ea1e00000000003";
    assert_eq!(on(&r, &guard::arm_script(&old, token, 4)).code, 0);
    let (o, _) = run(&r, &new);
    let Outcome::Stopped(why) = &o else {
        panic!("{o:?}")
    };
    assert!(why.contains("another guarded change is armed"), "{why}");
    assert!(
        on(&r, &guard::armed_script(token))
            .stdout
            .starts_with("armed "),
        "the live guard was cleared"
    );
    std::thread::sleep(Duration::from_secs(7));
    nothing_left(&r, 4);
    // Two from this machine at once: the second is turned away before anything is asked.
    let _held = guard::turn(&r.scope).expect("the lock");
    let (o, _) = run(&r, &new);
    assert!(
        matches!(&o, Outcome::Stopped(w) if w.contains("one at a time")),
        "{o:?}"
    );
}

/// The line of `sums` for one config.
fn sums_of(all: &str, config: &str) -> String {
    all.lines()
        .filter(|l| l.ends_with(&format!("/etc/config/{config}")))
        .map(|l| format!("{l}\n"))
        .collect()
}

/// `package-update`'s steps on this image: the preview refreshes the index and lists;
/// `plan` shows the whole transaction apk would make (simulated: nothing changes); an
/// upgrade without names, of something that isn't a name, or whose transaction holds
/// anything but leaves is refused with nothing upgraded; a leaf is upgraded, and the base
/// package that was upgradable beside it is still as it was.
/// (apk-tools 3.0.5 here: `apk upgrade --simulate <names>` prints `(1/1) Upgrading <name>
/// (<old> -> <new>)` and `OK: …`, and leaves /lib/apk/db byte for byte as it was; with
/// `--no-network` it prints only the `OK:` line, so the simulation is run without it.)
#[test]
#[ignore]
fn live_package_update() {
    let Some(r) = router() else { return };
    let name = r.name.clone();
    let run = |rest: &[&str]| {
        let mut args = vec!["network", "packages", name.as_str()];
        args.extend(rest);
        sentry(&args)
    };
    let p = run(&["preview"]);
    println!("{}{}", p.stdout, p.stderr);
    assert_eq!(p.code, 0);
    assert!(p.stdout.contains("package(s) could be upgraded"));
    let upgradable: Vec<&str> = p
        .stdout
        .lines()
        .filter(|l| l.starts_with("  "))
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    let version = |pkg: &str| {
        on(&r, &format!("apk --no-network list --installed {pkg}"))
            .stdout
            .trim()
            .to_string()
    };
    let db = || on(&r, "sha256sum /lib/apk/db/installed").stdout;
    let before = db();
    for (rest, says) in [
        (&["upgrade"][..], "no package named"),
        (
            &["upgrade", "--", "tcpdump;reboot"],
            "isn't a package's name",
        ),
        (
            &["upgrade", "--", "--force-broken-world"],
            "isn't a package's name",
        ),
        (&["plan", "--", "$(reboot)"], "isn't a package's name"),
    ] {
        let o = run(rest);
        assert_eq!(o.code, 3, "{rest:?}: {} {}", o.stdout, o.stderr);
        assert!(o.stderr.contains(says), "{rest:?}: {}", o.stderr);
    }
    // A base-system package and one that is neither: shown for what they are by `plan`,
    // refused by the plain upgrade step, nothing changed.
    let base = upgradable
        .iter()
        .copied()
        .find(|p| crate::packages::base_package(p));
    let other = upgradable
        .iter()
        .copied()
        .find(|p| !crate::packages::base_package(p) && !crate::packages::leaf_package(p));
    let leaf = upgradable
        .iter()
        .copied()
        .find(|p| crate::packages::leaf_package(p));
    println!("base {base:?} · other {other:?} · leaf {leaf:?}");
    for pkg in [base, other].into_iter().flatten() {
        let was = version(pkg);
        let plan = run(&["plan", "--", pkg]);
        println!("{}{}", plan.stdout, plan.stderr);
        assert_eq!(plan.code, 0, "{pkg}");
        assert!(
            plan.stdout.contains(&format!("upgrading {pkg} "))
                && plan.stdout.contains("more than leaves"),
            "{}",
            plan.stdout
        );
        let o = run(&["upgrade", "--", pkg]);
        assert_eq!(o.code, 3, "{pkg}: {} {}", o.stdout, o.stderr);
        assert!(
            o.stderr.contains("isn't on the list of leaves")
                && o.stderr.contains("Nothing was upgraded"),
            "{}",
            o.stderr
        );
        assert_eq!(version(pkg), was, "{pkg} was upgraded all the same");
        // A leaf named beside it doesn't carry it through.
        if let Some(leaf) = leaf {
            let o = run(&["upgrade", "--", leaf, pkg]);
            assert_eq!(o.code, 3, "{leaf} {pkg}: {}", o.stderr);
            assert_eq!(version(pkg), was);
        }
    }
    assert_eq!(
        db(),
        before,
        "a simulation or a refusal changed the package database"
    );
    // The condition the workflow chooses its step by is the same simulation.
    let leaves = |pkg: &str| {
        crate::packages::simulate(&r, &[pkg]).is_ok_and(|tx| crate::packages::all_leaves(&tx))
    };
    if let Some(b) = base {
        assert!(!leaves(b));
    }
    assert!(!leaves("busybox"), "nothing to do isn't a yes");
    assert!(!leaves("no-such-package-xyz"));
    match leaf {
        Some(pkg) => {
            assert!(leaves(pkg));
            let base_was = base.map(version);
            let plan = run(&["plan", "--", pkg]);
            assert!(
                plan.code == 0 && !plan.stdout.contains("more than leaves"),
                "{}",
                plan.stdout
            );
            let o = run(&["upgrade", "--", pkg]);
            println!("{}{}", o.stdout, o.stderr);
            assert_eq!(o.code, 0, "upgrading {pkg}");
            assert_ne!(db(), before, "{pkg} wasn't upgraded");
            assert!(!leaves(pkg), "it is as new as the index knows now");
            if let (Some(b), Some(was)) = (base, base_was) {
                assert_eq!(version(b), was, "the base package went along");
            }
            let c = run(&["check"]);
            println!("check: exit {}\n{}{}", c.code, c.stdout, c.stderr);
        }
        None => println!("no leaf to upgrade in this image: the upgrade itself wasn't run"),
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
    for g in &facts.gateways {
        if let Ok(std::net::IpAddr::V4(v)) = g.parse::<std::net::IpAddr>() {
            private.push(("the uplink's gateway", v.to_string()));
            // As /proc/net/route writes it.
            let n = u32::from(v);
            private.push(("the gateway as hex", format!("{:08X}", n.swap_bytes())));
            private.push(("the gateway as hex", format!("{n:08X}")));
        }
    }
    for a in &facts.wan {
        if let Ok(v) = a
            .split('/')
            .next()
            .unwrap_or(a)
            .parse::<std::net::Ipv4Addr>()
        {
            let n = u32::from(v);
            private.push((
                "an uplink address as hex",
                format!("{:08X}", n.swap_bytes()),
            ));
            private.push(("an uplink address mapped", format!("::ffff:{v}")));
        }
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
            private.push(("an unnamed MAC, dashed", m.replace(':', "-")));
            private.push(("an unnamed MAC, bare", m.replace(':', "")));
            // The interface id an address is given from it (EUI-64): its last two groups.
            let b: Vec<u16> = m
                .split(':')
                .filter_map(|x| u16::from_str_radix(x, 16).ok())
                .collect();
            if b.len() == 6 {
                private.push((
                    "an unnamed MAC in an address",
                    format!("{:x}:{:x}", 0xfe00 | b[3], (b[4] << 8) | b[5]),
                ));
            }
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
        "cat /proc/net/route",
        "cat /proc/net/ipv6_route",
        "cat /proc/net/if_inet6",
        "cat /sys/class/net/*/address",
        "netstat -rn",
        "ip -6 neigh show",
        "ip route show table all",
        "ip -6 route show table all",
        "ifstatus wan",
        "ubus call network.interface.wan status",
        "top -b -n 1",
        "dmesg",
        "cat /tmp/hosts/odhcpd",
        "cut -d' ' -f2,3 /tmp/dhcp.leases",
        "uci show network | grep -e gateway -e ipaddr -e macaddr",
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
         vars = { configs = \"dhcp\", lines = \"uci set dhcp.lan.leasetime='6h'; uci set dhcp.lan.sentry_test_token='c4nary-Live-Token-71'\", services = \"dnsmasq\" }\n```\n",
    );
    // (The second line sets an option whose name says secret: its value reaches the
    // router and nothing sentry writes down or sends. Checked at the end.)
    const CANARY: &str = "c4nary-Live-Token-71";
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
            // Its card shows the tag where the value is.
            let card = screen(&mut a);
            assert!(!card.contains(CANARY), "{card}");
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
            assert!(!prompt.contains(CANARY), "{prompt}");
            // (A verdict that says the value: the log's entry still doesn't.)
            a.apply_answer_for_test(
                "The lease is six hours.\n\n```sentry-verdict\nstatus = \"done\"\nsummary = \"leases are six hours, the token is c4nary-Live-Token-71\"\n```\n",
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
    // The secret the change set is on the router, as given, and in nothing sentry keeps:
    // the run's state and step logs, the guard's journal, the log's entries and ledger.
    assert_eq!(
        on(&r, "uci get dhcp.lan.sentry_test_token").stdout.trim(),
        CANARY
    );
    let tag = crate::redact::Salt::load(&scope).unwrap().tag(CANARY);
    let mut tagged = Vec::new();
    let mut dirs: Vec<std::path::PathBuf> = ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"]
        .iter()
        .map(|v| std::env::var_os(v).unwrap().into())
        .collect();
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() && !p.is_symlink() {
                dirs.push(p);
            } else if let Ok(bytes) = std::fs::read(&p) {
                let text = String::from_utf8_lossy(&bytes);
                assert!(!text.contains(CANARY), "{} has the secret", p.display());
                if text.contains(&tag) {
                    tagged.push(p.display().to_string());
                }
            }
        }
    }
    println!("its tag {tag} is in: {tagged:#?}");
    for f in [
        "state.json",
        "steps/show.log",
        "steps/guard.log",
        "-guarded-change.md",
    ] {
        assert!(tagged.iter().any(|p| p.ends_with(f)), "{f}: {tagged:#?}");
    }
    assert!(
        log.iter()
            .any(|e| e.head.kind == "apply" && e.body.contains(&format!("the token is {tag}"))),
        "the session's entry has the tag where the verdict said the value"
    );
}

/// Security's reads on a router that has little of what they look for (no nft or fw4
/// table, no uplink, perhaps no connection table, neither DNS package): each read either
/// answers with the missing parts absent or says the thing isn't there. None fails, none
/// reports a zero it didn't count, and the audit still stands with nothing found of it.
#[test]
#[ignore]
fn live_router_security() {
    use crate::collect::{CollectError, counters, dnsstate, flows, seclog};
    let Some(r) = router() else { return };
    let c = counters::collect(&r).expect("the counters' read stands without a firewall");
    println!(
        "counters: fw4 table {} · conntrack {} · dnsmasq counters {} · reset known {}",
        c.rules.is_some(),
        c.conntrack.is_some(),
        c.dns.is_some(),
        c.reset_at.is_some()
    );
    assert!(c.uptime > 0.0 && c.now > 1_600_000_000);
    if let Some(rules) = &c.rules {
        assert!(rules.iter().all(|x| !x.chain.is_empty()));
    }
    let f = match flows::collect(&r) {
        Ok(f) => {
            println!("flows: {} lines, accounting {:?}", f.lines, f.acct);
            assert_eq!(f.flows.len(), f.lines, "a line that isn't a flow");
            Some(f)
        }
        Err(CollectError::Unavailable(what)) => {
            println!("flows: {what} isn't there");
            None
        }
        Err(e) => panic!("flows: {e}"),
    };
    let log = match seclog::collect(&r) {
        Ok(l) => {
            println!(
                "log: {} lines, {} events, own address known {}",
                l.lines,
                l.events.len(),
                l.me.is_some()
            );
            // This run's own logins are in it, and recognised as its own.
            let sum = crate::security::log_sum(&l, &[]);
            if l.lines > 0 {
                assert!(
                    l.me.is_some(),
                    "the router didn't say where the login came from"
                );
                assert!(sum.ssh_own >= 1 && sum.unknown() == 0, "{sum:?}");
            }
            Some(l)
        }
        Err(CollectError::Unavailable(what)) => {
            println!("log: {what} isn't there");
            None
        }
        Err(e) => panic!("log: {e}"),
    };
    let d = dnsstate::collect(&r).expect("the status read stands without the packages");
    assert!(d.blocklist.is_none() && d.proxy.is_none(), "{d:?}");
    // What the screen is made of, from that: nothing is claimed.
    let ifaces = crate::collect::ifaces::collect(&r).unwrap();
    let uci = crate::collect::uci::collect(&r).unwrap();
    let rated = crate::security::Rated::default();
    let p = crate::security::Picture::of(&crate::security::Read {
        ifaces: Some(&ifaces),
        uci: Some(&uci),
        counters: Some(&c),
        rated: Some(&rated),
        flows: f.as_ref(),
        log: log.as_ref(),
        dns: Some(&d),
        ..Default::default()
    });
    if c.rules.is_none() {
        assert!(p.wan_rejects.is_none() && p.dot.is_none() && p.out_new.is_none());
        assert!(p.forwards.iter().all(|x| x.new.is_none()));
    }
    assert!(p.crossings().is_empty(), "{:?}", p.marks);
    // The audit: its two reads more leave no error behind where the thing isn't there,
    // and nothing is found.
    let snap = crate::audit::snapshot(&r).expect("the audit's reads");
    for (part, why) in &snap.errors {
        assert!(!matches!(part.as_str(), "flows" | "log"), "{part}: {why}");
    }
    let found = crate::audit::derive(&snap, &r.cfg, None, &Default::default());
    assert!(
        found
            .iter()
            .all(|x| !x.id.starts_with("net:flow:") && x.id != "net:ssh:failed"),
        "{:?}",
        found.iter().map(|x| &x.id).collect::<Vec<_>>()
    );
}

// ── What Enter on the Security screen does, for real ───────────────────────────────────
//
// The container may not load a firewall (`nft`, `fw4 reload`: not permitted), so the
// firewall actions are carried out with nothing reloaded (`run::NO_FIREWALL_RELOAD`):
// proven here is everything up to and including the committed config and the guard
// around it (snapshot, armed revert, confirmed twice, kept or taken back). That fw4
// makes the rule it is meant to, and that a device is then really refused, is not.

use crate::security::actions::Do;
use crate::security::blocks::{self, Blocks, Dev, Note, Reach};
use crate::security::run as secrun;

/// A Security action, as the workflow's second step runs it.
fn act(r: &Router, word: &str) -> (u8, Vec<String>) {
    let mut said = Vec::new();
    let code = secrun::apply(r, &Do::parse(word).unwrap(), &mut |l| {
        println!("  {l}");
        said.push(l);
    });
    println!("→ {word}: exit {code}");
    (code, said)
}

fn no_firewall_reload() {
    secrun::NO_FIREWALL_RELOAD.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Block a device by MAC through the guard, and unblock it: sentry's rule and only it.
#[test]
#[ignore]
fn live_security_block() {
    let Some(r) = router() else { return };
    no_firewall_reload();
    const MAC: &str = "02:00:5e:00:53:44";
    let tag = blocks::tag(&r.name, MAC).expect("a tag (the network's salt)");
    let sec = format!("sentry_block_{tag}");
    // Rules of someone else's that look like sentry's: a section named like one with
    // another name, sentry's name on a section that isn't sentry's, a tag that isn't one.
    let o = on(
        &r,
        &format!(
            "uci set firewall.sentry_block_kids=rule && uci set firewall.sentry_block_kids.name='sentry-block-kids' \
             && uci set firewall.sentry_block_kids.src='lan' && uci set firewall.sentry_block_kids.target='REJECT' \
             && uci set firewall.mine=rule && uci set firewall.mine.name='sentry-block-{tag}' \
             && uci set firewall.mine.src='lan' && uci set firewall.mine.target='ACCEPT' \
             && uci commit firewall"
        ),
    );
    assert_eq!(o.code, 0, "{}", o.stderr);
    let before = sums(&r, &["firewall"]);

    // A tag sentry has no note of: nothing is guessed, nothing changes.
    let word = format!("block:{tag}:internet");
    let (code, said) = act(&r, &word);
    assert_eq!(code, 3, "{said:#?}");
    assert!(
        said.iter().any(|l| l.contains("pick it on Security again")),
        "{said:#?}"
    );
    assert_eq!(sums(&r, &["firewall"]), before);

    // What the screen notes when the device is picked.
    let mut b = Blocks::load(&r.scope);
    b.device.insert(
        tag.clone(),
        Dev {
            mac: MAC.into(),
            label: "a tablet".into(),
            zone: "lan".into(),
            wifi: None,
        },
    );
    b.block.insert(
        tag.clone(),
        Note {
            since: 1,
            until: None,
            reach: Reach::Internet,
            why: "live test".into(),
        },
    );
    b.save(&r.scope).unwrap();

    // The first step: the plan and the guard's preview. It only reads.
    let mut shown = Vec::new();
    secrun::show(&r, &Do::parse(&word).unwrap(), &mut |l| shown.push(l)).unwrap();
    let text = shown.join("\n");
    println!("{text}");
    assert!(
        text.contains("Block a tablet from the internet")
            && text.contains(&format!("uci set firewall.{sec}.src_mac='{MAC}'"))
            && text.contains("Nothing has changed."),
        "{text}"
    );
    assert_eq!(sums(&r, &["firewall"]), before);
    nothing_left(&r, r.cfg.guard.window);

    // The second: through the guard, kept.
    let (code, said) = act(&r, &word);
    assert_eq!(code, 0, "{said:#?}");
    assert!(said.iter().any(|l| l.starts_with("armed:")), "{said:#?}");
    assert!(
        said.iter()
            .any(|l| l.contains("confirmed on a new connection, twice")),
        "{said:#?}"
    );
    assert!(said.iter().any(|l| l.starts_with("KEPT")), "{said:#?}");
    nothing_left(&r, r.cfg.guard.window);
    assert_eq!(journal(&r).last().unwrap()["outcome"], "kept");
    let rule = on(&r, &format!("uci show firewall.{sec}")).stdout;
    for want in [
        format!("firewall.{sec}=rule"),
        format!("firewall.{sec}.name='sentry-block-{tag}'"),
        format!("firewall.{sec}.src='lan'"),
        format!("firewall.{sec}.src_mac='{MAC}'"),
        format!("firewall.{sec}.dest='wan'"),
        format!("firewall.{sec}.target='REJECT'"),
    ] {
        assert!(rule.contains(&want), "{want}:\n{rule}");
    }
    assert_eq!(on(&r, "uci changes firewall").stdout.trim(), "");
    // As the screen reads it back: one block, this device's.
    let uci = crate::collect::uci::collect(&r).unwrap();
    let found = blocks::found(&uci);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        (found[0].tag.as_str(), found[0].mac.as_str(), found[0].reach),
        (tag.as_str(), MAC, Reach::Internet)
    );
    // Blocked already: said, nothing more is staged.
    let (code, said) = act(&r, &word);
    assert_eq!(code, 3, "{said:#?}");
    assert!(
        said.iter().any(|l| l.contains("already blocked")),
        "{said:#?}"
    );

    // Unblock: exactly sentry's section goes; the look-alikes stay as they were.
    let (code, said) = act(&r, &format!("unblock:{tag}"));
    assert_eq!(code, 0, "{said:#?}");
    assert_ne!(on(&r, &format!("uci -q get firewall.{sec}")).code, 0);
    assert_eq!(
        on(
            &r,
            "uci get firewall.sentry_block_kids.name; uci get firewall.mine.name; uci get firewall.mine.target"
        )
        .stdout,
        format!("sentry-block-kids\nsentry-block-{tag}\nACCEPT\n")
    );
    assert_eq!(
        sums(&r, &["firewall"]),
        before,
        "as before the block, byte for byte"
    );
    assert!(!Blocks::load(&r.scope).block.contains_key(&tag));
    nothing_left(&r, r.cfg.guard.window);
    // Nothing of sentry's left to remove: said.
    let (code, said) = act(&r, &format!("unblock:{tag}"));
    assert_eq!(code, 3, "{said:#?}");
    assert!(
        said.iter().any(|l| l.contains("nothing to unblock")),
        "{said:#?}"
    );
}

/// Switch a port forward off and on again through the guard; and a change whose own
/// check fails is taken back by the router, byte for byte.
#[test]
#[ignore]
fn live_security_forward() {
    let Some(r) = router() else { return };
    no_firewall_reload();
    let before = sums(&r, &["firewall"]);
    // The config expects this forward: the guard is told the change means to close it.
    let (code, said) = act(&r, "forward-off:web_https");
    assert_eq!(code, 0, "{said:#?}");
    assert_eq!(
        on(&r, "uci get firewall.web_https.enabled").stdout.trim(),
        "0"
    );
    assert_ne!(sums(&r, &["firewall"]), before);
    let (code, said) = act(&r, "forward-off:web_https");
    assert_eq!(code, 3, "{said:#?}");
    assert!(
        said.iter().any(|l| l.contains("already switched off")),
        "{said:#?}"
    );
    // On again, from the same place.
    let (code, said) = act(&r, "forward-on:web_https");
    assert_eq!(code, 0, "{said:#?}");
    assert_eq!(
        on(&r, "uci get firewall.web_https.enabled").stdout.trim(),
        "1"
    );
    nothing_left(&r, r.cfg.guard.window);

    // The same change with a check that never holds (as a proof failing after the
    // change would): sentry does nothing more, and the router takes it back.
    let before = sums(&r, &["firewall"]);
    let c = Change::parse(
        "firewall",
        "uci set firewall.web_https.enabled='0'",
        "",
        false,
    )
    .unwrap();
    let closing = vec!["tcp 443 → 192.0.2.10".to_string()];
    let broken = || Err("deliberately broken".to_string());
    let mut said = Vec::new();
    let o = guard::run_also(
        &r,
        &c,
        r.cfg.guard.window,
        &guard::Also {
            check: Some(&broken),
            closing: &closing,
        },
        &mut |l| {
            println!("  {l}");
            said.push(l);
        },
    );
    let Outcome::Reverted(why) = &o else {
        panic!("{o:?}: {said:#?}")
    };
    assert!(why.contains("deliberately broken"), "{why}");
    assert_eq!(sums(&r, &["firewall"]), before, "not byte for byte");
    assert_eq!(
        on(&r, "uci get firewall.web_https.enabled").stdout.trim(),
        "1"
    );
    nothing_left(&r, r.cfg.guard.window);
    assert_eq!(journal(&r).last().unwrap()["outcome"], "reverted");
    // Without being told, the guard holds a forward the config expects against a change
    // that closes it: that is what `closing` is for.
    let expected = guard::expected_forwards(&r.cfg);
    assert!(expected.contains(&closing[0]), "{expected:?}");
}

/// ssh with keys only: nothing changes unless a key login is proven on a new connection
/// first; then both options go off through the guard, and a new login still works.
#[test]
#[ignore]
fn live_security_ssh_keys_only() {
    let Some(r) = router() else { return };
    // As a router is out of the box: passwords allowed.
    let o = on(
        &r,
        "uci set dropbear.main.PasswordAuth='on' && uci set dropbear.main.RootPasswordAuth='on' && uci commit dropbear",
    );
    assert_eq!(o.code, 0, "{}", o.stderr);
    let before = sums(&r, &["dropbear"]);

    // The negative: the router loses its key file while the shared connection is still
    // up. Everything read over that connection still answers; a NEW login can't get in,
    // so the proof fails, and nothing is changed.
    let shared = |script: &str| r.sh(script).timeout(Some(Duration::from_secs(20))).run();
    let off =
        shared("mv /etc/dropbear/authorized_keys /etc/dropbear/authorized_keys.off && echo moved")
            .unwrap();
    assert!(
        off.stdout.contains("moved"),
        "{} {}",
        off.stdout,
        off.stderr
    );
    let (code, said) = act(&r, "ssh-keys-only");
    // (Put the key back first, over the connection that is still open, whatever happened.)
    let back =
        shared("mv /etc/dropbear/authorized_keys.off /etc/dropbear/authorized_keys && echo back")
            .unwrap();
    assert!(
        back.stdout.contains("back"),
        "{} {}",
        back.stdout,
        back.stderr
    );
    assert_eq!(code, 3, "{said:#?}");
    assert!(
        said.iter().any(|l| l.starts_with(
            "STOPPED, nothing was changed: a new connection with a key didn't get in"
        )),
        "{said:#?}"
    );
    assert!(!said.iter().any(|l| l.starts_with("armed:")), "{said:#?}");
    assert_eq!(sums(&r, &["dropbear"]), before, "nothing was changed");
    nothing_left(&r, r.cfg.guard.window);

    // The positive: proven, changed through the guard (which reloads dropbear), proven
    // again before it is kept.
    let (code, said) = act(&r, "ssh-keys-only");
    assert_eq!(code, 0, "{said:#?}");
    let at = |what: &str| said.iter().position(|l| l.starts_with(what));
    let (proof, armed, kept) = (
        at("proven: a new connection logged in with a key"),
        at("armed:"),
        at("KEPT"),
    );
    assert!(
        proof.is_some() && proof < armed && armed < kept,
        "proven before anything is armed: {said:#?}"
    );
    assert_eq!(
        on(
            &r,
            "uci get dropbear.main.PasswordAuth; uci get dropbear.main.RootPasswordAuth"
        )
        .stdout,
        "off\noff\n"
    );
    assert_eq!(on(&r, "uci changes dropbear").stdout.trim(), "");
    nothing_left(&r, r.cfg.guard.window);
    assert_eq!(journal(&r).last().unwrap()["outcome"], "kept");
    // Already so: nothing to do.
    let (code, said) = act(&r, "ssh-keys-only");
    assert_eq!(code, 3, "{said:#?}");
    assert!(said.iter().any(|l| l.contains("already off")), "{said:#?}");
}

/// The firmware upgrade through the window, against the stand-ins `scripts/live-router.sh`
/// puts on the disposable router (a pretend owut, sysupgrade's `--test` and flash, a
/// pretend restart that drops ssh logins and changes the boot id). In turn: a warning owut
/// raises stops the plan before any download; an image whose checksum isn't the server's
/// stops before the flash and is removed; the router not back by the deadline ends the
/// wait failed, and a window opened once it answers carries on at the checks; a package
/// missing after the flash is installed again by the step that offers it; a good run
/// offers to take the draft off. Nothing here can flash, restart or write a real router.
#[test]
#[ignore]
fn live_firmware_upgrade() {
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use sentry_app::effect::{Effect, WfCmd};
    use sentry_app::{App, Event};
    use sentry_core::workflows::runner::Next;
    use sentry_core::workflows::state::RunStatus;
    use std::time::Instant;

    // The backup goes to a throwaway key in the scratch dir (the script's config names
    // its file).
    let Some(scratch) = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
    else {
        return;
    };
    if std::env::var("SENTRY_ROUTER_SCRATCH").is_err() {
        return;
    }
    let to = crate::backup::make_key(&scratch.join("identity.txt")).unwrap();
    std::fs::write(scratch.join("recipients.txt"), format!("{to}\n")).unwrap();
    // Short enough for a test; the stand-in comes back after 8 s, or 45 s when slow.
    // SAFETY: these tests run one at a time (`--test-threads=1`), nothing reads it meanwhile.
    unsafe { std::env::set_var("SENTRY_FIRMWARE_WAIT", "20") };
    let Some(r) = router() else { return };
    let name = r.name.clone();
    // Until a new login is let in (the script's seed has just restarted dropbear; the
    // pretend restart stops it for a while).
    let answers = |r: &Router, secs: u64| {
        let until = Instant::now() + Duration::from_secs(secs);
        while r
            .cmd("true")
            .own_connection()
            .timeout(Some(Duration::from_secs(5)))
            .run()
            .map_or(true, |o| o.code != 0)
        {
            assert!(Instant::now() < until, "the router never answered");
            std::thread::sleep(Duration::from_secs(1));
        }
    };
    answers(&r, 30);
    let mode = |m: &str| {
        on(
            &r,
            &format!(
                "echo {m} >/etc/sentry-stub/mode; S=/usr/share/sentry-stub; cp $S/os-release /usr/lib/os-release; cp $S/openwrt_release /etc/openwrt_release"
            ),
        )
    };
    let image_there = |r: &Router| on(r, "ls /tmp/sentry-firmware.bin").code == 0;

    let open = || {
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
        // The window's first reads go first (dropbear lets few logins be made at once).
        let until = Instant::now() + Duration::from_secs(4);
        while Instant::now() < until {
            if let Ok(ev) = rx.recv_timeout(Duration::from_millis(100)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
        }
        (a, rx)
    };
    let key = |a: &mut App, c: KeyCode| {
        a.on_event(
            Event::Key(KeyEvent::new(c, KeyModifiers::NONE)),
            Instant::now(),
        );
    };
    let screen = |a: &mut App| sentry_app::app::render_to_string(a, 158, 50);
    // Until the run waits on a step (none: it ended), answering a note's prompt with none.
    let settle = |a: &mut App, rx: &std::sync::mpsc::Receiver<Event>, secs: u64| {
        let until = Instant::now() + Duration::from_secs(secs);
        loop {
            if let Ok(ev) = rx.recv_timeout(Duration::from_millis(100)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
            if matches!(a.win.input, sentry_core::tui::input::Input::Prompt(..)) {
                key(a, KeyCode::Enter);
            }
            match a.slot().run.as_ref() {
                Some(s) if s.live().is_none() && s.done() => return None,
                Some(s) if s.live().is_none() && !matches!(s.next(), Next::Run(_)) => {
                    return Some(s.next().clone());
                }
                None => return None,
                _ => {}
            }
            assert!(Instant::now() < until, "nothing settled: {}", screen(a));
        }
    };
    let log = |a: &App| -> String {
        a.slot()
            .run
            .as_ref()
            .map(|s| {
                s.as_any()
                    .downcast_ref::<crate::workflow::Session>()
                    .unwrap()
                    .log
                    .iter()
                    .map(|(l, _)| l.clone())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    };
    let start = |a: &mut App| {
        a.apply(
            vec![Effect::own(crate::tui::Own::FirmwareStart)],
            Instant::now(),
        );
        assert!(a.slot().run.is_some(), "{}", screen(a));
        key(a, KeyCode::Char('0'));
    };
    let done_with = |a: &mut App| {
        a.apply(vec![Effect::Wf(WfCmd::Abandon)], Instant::now());
        a.apply(vec![Effect::Wf(WfCmd::Close)], Instant::now());
    };
    let boot = |r: &Router| on(r, "cat /proc/sys/kernel/random/boot_id").stdout;

    // 1. A warning owut raises stops the plan: nothing downloaded.
    mode("warn");
    let (mut a, rx) = open();
    start(&mut a);
    let next = settle(&mut a, &rx, 120);
    assert!(
        matches!(
            next,
            Some(Next::Manual {
                idx: 2,
                failed: true
            })
        ),
        "{next:?}\n{}",
        log(&a)
    );
    let said = log(&a);
    assert!(
        said.contains("STOPPED before anything was downloaded") && said.contains("older version"),
        "{said}"
    );
    assert!(!image_there(&r));
    done_with(&mut a);
    drop(a);

    // 2. The image isn't the one the server built: stopped before the flash, removed.
    mode("badsum");
    let (mut a, rx) = open();
    start(&mut a);
    assert_eq!(
        settle(&mut a, &rx, 120),
        Some(Next::Confirm(3)),
        "{}",
        log(&a)
    );
    let boot_before = boot(&r);
    key(&mut a, KeyCode::Enter);
    let next = settle(&mut a, &rx, 120);
    assert!(
        matches!(
            next,
            Some(Next::Manual {
                idx: 3,
                failed: true
            })
        ),
        "{next:?}\n{}",
        log(&a)
    );
    assert!(log(&a).contains("checksum"), "{}", log(&a));
    assert!(
        !image_there(&r),
        "the image was left in the router's memory"
    );
    assert_eq!(boot(&r), boot_before, "nothing restarted");
    done_with(&mut a);
    drop(a);

    // 3. Not back by the deadline: the wait fails, calmly; a window opened when the router
    //    answers again carries on at the checks.
    mode("slow");
    let (mut a, rx) = open();
    start(&mut a);
    assert_eq!(
        settle(&mut a, &rx, 120),
        Some(Next::Confirm(3)),
        "{}",
        log(&a)
    );
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        settle(&mut a, &rx, 120),
        Some(Next::Confirm(4)),
        "{}",
        log(&a)
    );
    assert!(image_there(&r));
    // The flash's box first: what happens, then its Enter.
    key(&mut a, KeyCode::Enter);
    let s = screen(&mut a);
    assert!(s.contains("What can't be helped from here"), "{s}");
    key(&mut a, KeyCode::Enter);
    let next = settle(&mut a, &rx, 120);
    assert!(
        matches!(
            next,
            Some(Next::Manual {
                idx: 5,
                failed: true
            })
        ),
        "{next:?}\n{}",
        log(&a)
    );
    let said = log(&a);
    for words in [
        "hasn't answered for",
        "What was running when contact was lost: the flash",
        "Your settings were backed up at",
        "device's own recovery procedure",
    ] {
        assert!(said.contains(words), "{words}: {said}");
    }
    drop(a);
    // The stand-in comes back by itself.
    answers(&r, 90);
    let (mut a, rx) = open();
    key(&mut a, KeyCode::Char('0'));
    let next = settle(&mut a, &rx, 180);
    assert!(next.is_none(), "{next:?}\n{}", log(&a));
    let s = a.slot().run.as_ref().unwrap();
    assert_eq!(s.run().state.status, RunStatus::Done, "{}", log(&a));
    let said = log(&a);
    assert!(
        said.contains("runs OpenWrt 25.12.6")
            && said.contains("installed by name before are installed"),
        "{said}"
    );
    // The good run offers to take the draft off (Esc: it stays one).
    let s = screen(&mut a);
    assert!(s.contains("The firmware upgrade ran end to end"), "{s}");
    key(&mut a, KeyCode::Esc);
    a.apply(vec![Effect::Wf(WfCmd::Close)], Instant::now());
    drop(a);

    // 4. A package gone after the flash: named, and installed again by the step that offers
    //    it (it asks: risky, never auto's).
    mode("missing");
    let (mut a, rx) = open();
    start(&mut a);
    assert_eq!(
        settle(&mut a, &rx, 120),
        Some(Next::Confirm(3)),
        "{}",
        log(&a)
    );
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        settle(&mut a, &rx, 120),
        Some(Next::Confirm(4)),
        "{}",
        log(&a)
    );
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Enter);
    let next = settle(&mut a, &rx, 240);
    assert_eq!(next, Some(Next::Confirm(7)), "{}", log(&a));
    assert!(
        log(&a).contains("Missing since the flash: partx-utils"),
        "{}",
        log(&a)
    );
    assert_ne!(on(&r, "apk --no-network info -e partx-utils").code, 0);
    key(&mut a, KeyCode::Enter);
    let next = settle(&mut a, &rx, 600);
    assert!(next.is_none(), "{next:?}\n{}", log(&a));
    assert_eq!(
        a.slot().run.as_ref().unwrap().run().state.status,
        RunStatus::Done,
        "{}",
        log(&a)
    );
    assert_eq!(on(&r, "apk --no-network info -e partx-utils").code, 0);
    let _ = std::fs::remove_file(scratch.join("identity.txt"));
}

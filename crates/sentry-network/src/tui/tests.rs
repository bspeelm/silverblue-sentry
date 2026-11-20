//! The network target's screens rendered from the synthetic fixtures (no ssh), and how it
//! behaves as a target: what it fetches and when, and what it answers the app.

use std::time::{Duration, Instant};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::data::{Data, Kind, Payload};
use super::{Event, NetworkTarget};
use crate::collect::probe::Probe;
use crate::collect::{CollectError, fixture, ifaces, probe};
use crate::config::Network;
use crate::remote::Router;
use sentry_app::Target;
use sentry_app::app::{App, render_to_string};
use sentry_core::tui::ScreenId;

const NAME: &str = "home";

/// The network alone in the window, nothing read yet.
fn blank() -> App {
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut a = App::new(
        tx,
        &super::id_of(NAME),
        super::target(Router::new(NAME, &Network::default())),
    );
    a.win.offline = true;
    a.win.theme = sentry_core::tui::theme::Theme::truecolor();
    a.win.now_override = Some("2026-10-26T12:00:00Z".parse().unwrap());
    a
}

fn net(a: &App) -> &NetworkTarget {
    a.slot()
        .target
        .as_any()
        .downcast_ref()
        .expect("the network")
}

fn data(a: &mut App, k: Kind, p: Result<Payload, CollectError>) {
    a.on_event(
        Event::Data(super::id_of(NAME), Box::new(Data(k, Box::new(p)))),
        Instant::now(),
    );
}

fn key(a: &mut App, c: KeyCode) {
    a.on_event(
        Event::Key(KeyEvent::new(c, KeyModifiers::NONE)),
        Instant::now(),
    );
}

fn typed(a: &mut App, text: &str) {
    for c in text.chars() {
        key(a, KeyCode::Char(c));
    }
    key(a, KeyCode::Enter);
}

fn first() -> Probe {
    probe::parse(&fixture("network/probe.txt")).unwrap()
}

/// The fixture's probe `secs` later by the router's clock: the uplink took in 1.5 MB and
/// sent 250 kB a second, lan1 carried most of it, the 5 GHz radio a little; the rest idle.
fn later(secs: u64) -> Probe {
    let mut p = first();
    p.uptime += secs as f64;
    p.host.uptime_s += secs;
    p.host.cpu.total += secs * 400;
    p.host.cpu.idle += secs * 372;
    for port in &mut p.ports {
        let (rx, tx) = match port.name.as_str() {
            "eth1" => (1_500_000, 250_000),
            "lan1" => (230_000, 1_450_000),
            "phy1-ap0" => (20_000, 50_000),
            "lan2" => (0, 125),
            _ => (0, 0),
        };
        port.rx_bytes += rx * secs;
        port.tx_bytes += tx * secs;
    }
    p
}

fn the_ifaces() -> ifaces::Ifaces {
    ifaces::parse(&fixture("network/ifaces.txt")).unwrap()
}

/// The Dashboard with everything read: the interfaces, and four probes a second apart.
fn app() -> App {
    let mut a = blank();
    data(
        &mut a,
        Kind::Ifaces,
        Ok(Payload::Ifaces(Box::new(the_ifaces()))),
    );
    for s in 0..4 {
        data(&mut a, Kind::Probe, Ok(Payload::Probe(later(s))));
    }
    a
}

/// The line of the screen that has `what` in it.
fn line(s: &str, what: &str) -> String {
    s.lines()
        .find(|l| l.contains(what))
        .unwrap_or_else(|| panic!("no line with {what:?} in\n{s}"))
        .to_string()
}

#[test]
fn dashboard_wide() {
    let mut a = app();
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("dashboard_158x41", s);
    // The top bar: what it runs, the board, how long it's been up, and the connection.
    let top = s.lines().next().unwrap();
    assert!(
        top.starts_with(" sentry-network   home  OpenWrt 25.12.3  Example Router AX  up 15d 18:36"),
        "{top}"
    );
    assert!(top.contains("● connected"), "{top}");
    // One target: no strip. Its screens: the Dashboard, and no History until there's a ring.
    let tabs = s.lines().nth(1).unwrap();
    assert!(
        tabs.contains("1 Dashboard") && !tabs.contains("History"),
        "{tabs}"
    );
    // The uplink first, with the rate the router's own clock gives: 1.5 MB/s is 12 Mbit/s.
    let wan = line(&s, "eth1");
    assert!(wan.contains("wan") && wan.contains("● 1G"), "{wan}");
    assert!(wan.contains("12.0 M") && wan.contains("2.0 M"), "{wan}");
    assert!(line(&s, "lan2").contains("100M"));
    // Radios are rows too: no speed to read, so none is made up.
    assert!(line(&s, "phy1-ap0").contains("● wifi"));
    // The port the switch hangs off, the bridge and the loopback aren't ports.
    assert!(
        !s.contains("eth0") && !s.contains("br-lan") && !s.contains(" lo "),
        "{s}"
    );
    assert!(s.contains("6 of 7 up"), "{s}");
    assert!(line(&s, "│ lease").contains("2h · 1h 20m left"));
    assert!(line(&s, "IPv6").contains("prefix 2001:db8:1200::/56"));
    assert!(line(&s, "flash").contains("6% of 7.2 GiB"));
    // Nothing is promised that isn't there.
    assert!(!s.contains("stage") && !s.contains("soon"), "{s}");
}

#[test]
fn dashboard_narrow() {
    let mut a = app();
    let s = render_to_string(&mut a, 80, 24);
    insta::assert_snapshot!("dashboard_80x24", s);
    assert!(s.lines().all(|l| l.chars().count() <= 80));
    // Every port still has its row, link and rates.
    for port in [
        "eth1", "lan1", "lan2", "lan3", "lan4", "phy0-ap0", "phy1-ap0",
    ] {
        assert!(s.contains(port), "{port} in\n{s}");
    }
    assert!(line(&s, "eth1").contains("12.0 M"));
}

#[test]
fn a_port_without_link_says_so_and_has_no_speed() {
    let mut a = app();
    let s = render_to_string(&mut a, 158, 41);
    let row = line(&s, "lan3");
    assert!(row.contains("○ no link"), "{row}");
    assert!(!row.contains('G') && !row.contains("100M"), "{row}");
    // Its counters stand still: that is a rate of nothing, not an unknown one.
    assert!(!row.contains('–'), "{row}");
    // Unplugged between two probes: the row follows within the second, ahead of the
    // slower interfaces read.
    let mut p = later(4);
    let lan1 = p.ports.iter_mut().find(|x| x.name == "lan1").unwrap();
    (lan1.carrier, lan1.speed) = (Some(false), None);
    data(&mut a, Kind::Probe, Ok(Payload::Probe(p)));
    let s = render_to_string(&mut a, 158, 41);
    assert!(line(&s, "lan1").contains("○ no link"), "{s}");
    assert!(s.contains("5 of 7 up"), "{s}");
}

#[test]
fn dashboard_wan_down() {
    let mut a = app();
    let mut i = the_ifaces();
    for x in i.interfaces.iter_mut().filter(|x| x.device == "eth1") {
        x.up = false;
        x.uptime_s = 0;
        x.ipv4.clear();
        x.prefixes.clear();
        x.gateway = None;
        x.gateway6 = None;
        x.dns.clear();
    }
    data(&mut a, Kind::Ifaces, Ok(Payload::Ifaces(Box::new(i))));
    // The cable is out: nothing moves any more.
    let mut p = later(3);
    p.uptime += 1.0;
    let eth1 = p.ports.iter_mut().find(|x| x.name == "eth1").unwrap();
    (eth1.carrier, eth1.speed) = (Some(false), None);
    p.host.iface = None;
    data(&mut a, Kind::Probe, Ok(Payload::Probe(p)));
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("dashboard_wan_down_158x41", s);
    assert!(s.contains("WAN · down"), "{s}");
    assert!(line(&s, "address").contains("● down · dhcp on eth1"));
    assert!(line(&s, "IPv6").contains("● down"));
    assert!(!s.contains("│ lease") && !s.contains("gateway"), "{s}");
    assert!(line(&s, "eth1").contains("○ no link"));
    assert!(s.contains("no default route"), "{s}");
}

#[test]
fn the_first_sample_has_no_rates_and_a_reboot_starts_over() {
    let mut a = blank();
    data(&mut a, Kind::Probe, Ok(Payload::Probe(first())));
    let s = render_to_string(&mut a, 158, 41);
    // Before the interfaces are read: every interface the kernel has but the loopback.
    assert!(
        s.contains("br-lan") && s.contains("eth0") && !s.contains(" lo "),
        "{s}"
    );
    let row = line(&s, "eth1");
    assert_eq!(row.matches('–').count(), 2, "{row}");
    assert!(line(&s, "load").contains("0.42 0.31 0.18"));
    // A second later there are rates.
    data(&mut a, Kind::Probe, Ok(Payload::Probe(later(1))));
    let s = render_to_string(&mut a, 158, 41);
    assert!(line(&s, "eth1").contains("12.0 M"), "{s}");
    // The router rebooted: its counters are a new boot's, so no rate, and it says so.
    let mut p = later(2);
    p.host.boot_id = "another-boot".into();
    p.uptime = 30.0;
    data(&mut a, Kind::Probe, Ok(Payload::Probe(p.clone())));
    let s = render_to_string(&mut a, 158, 41);
    assert_eq!(line(&s, "eth1").matches('–').count(), 2, "{s}");
    assert!(
        s.contains("● rebooted") && s.contains("the router rebooted"),
        "{s}"
    );
    // One counter reset (the port was taken down and up): only that row has no rate.
    p.uptime = 31.0;
    for port in &mut p.ports {
        port.rx_bytes += 1000;
    }
    p.ports
        .iter_mut()
        .find(|x| x.name == "lan1")
        .unwrap()
        .rx_bytes = 7;
    data(&mut a, Kind::Probe, Ok(Payload::Probe(p)));
    let s = render_to_string(&mut a, 158, 41);
    assert_eq!(line(&s, "lan1").matches('–').count(), 2, "{s}");
    assert!(line(&s, "eth1").contains("8 k"), "{s}");
}

#[test]
fn what_went_wrong_is_said_where_the_data_would_be() {
    let mut a = blank();
    let s = render_to_string(&mut a, 120, 30);
    assert!(s.contains("○ connecting…") && s.contains("reading…"), "{s}");
    // No ubus there: not an OpenWrt. Said, not a crash; the probe still shows.
    data(
        &mut a,
        Kind::Ifaces,
        Err(CollectError::Unavailable("ubus".into())),
    );
    data(&mut a, Kind::Probe, Ok(Payload::Probe(first())));
    let s = render_to_string(&mut a, 120, 30);
    assert!(s.contains("ubus isn't on the router"), "{s}");
    assert!(s.contains("eth1") && s.contains("● connected"), "{s}");
    // ssh itself failing keeps what was last known, and says so.
    data(
        &mut a,
        Kind::Probe,
        Err(CollectError::Unreachable("myrouter: timed out".into())),
    );
    let s = render_to_string(&mut a, 120, 30);
    assert!(s.contains("○ unreachable · retrying"), "{s}");
    assert!(
        s.contains("can't reach home: myrouter") && s.contains("eth1"),
        "{s}"
    );
    data(&mut a, Kind::Probe, Ok(Payload::Probe(later(1))));
    assert!(render_to_string(&mut a, 120, 30).contains("● connected"));
}

/// A day and a half of records, every ten minutes, ending at the tests' clock.
fn history() -> sentry_core::tui::histview::HistData {
    use sentry_core::recorder::ring::{Header, Rec};
    let end = "2026-10-26T12:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    let recs: Vec<Rec> = (0..216i64)
        .map(|i| {
            let x = i as f32;
            Rec {
                ts: end - (215 - i) * 600,
                cpu: 6.0 + 4.0 * (x / 9.0).sin(),
                mem_gib: 0.2 + 0.02 * (x / 40.0).cos(),
                swap_gib: 0.0,
                rx: 400_000.0 + 300_000.0 * (x / 5.0).sin(),
                tx: 90_000.0,
                load1: 0.4,
                cpu_temp: 51.0 + 3.0 * (x / 9.0).sin(),
                gpu: f32::NAN,
                gpu_temp: f32::NAN,
                disk_pct: 6.0,
                top: Vec::new(),
            }
        })
        // Nobody sampled for four hours.
        .filter(|r| !(end - 10 * 3600..end - 6 * 3600).contains(&r.ts))
        .collect();
    sentry_core::tui::histview::HistData {
        header: Some(Header {
            capacity: crate::recorder::capacity(),
            written: recs.len() as u64,
            interval_s: crate::recorder::INTERVAL_S,
        }),
        recs,
        live: None,
        alerts: Vec::new(),
        bytes: 3_317_824,
    }
}

#[test]
fn history_shows_the_ring_and_joins_the_strip_with_it() {
    let mut a = app();
    let strip = |a: &mut App| {
        render_to_string(a, 158, 41)
            .lines()
            .nth(1)
            .unwrap()
            .to_string()
    };
    assert!(!strip(&mut a).contains("History"), "nothing recorded yet");
    // H opens it all the same, and says how to get data.
    key(&mut a, KeyCode::Char('H'));
    assert_eq!(a.slot().screen, ScreenId::Hist);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("No recorder data.") && s.contains("sentry-network record home"),
        "{s}"
    );
    // Entering it reads the ring from this machine's disk (and polls nothing).
    assert_eq!(net(&a).asked.last(), Some(&Kind::History));
    data(
        &mut a,
        Kind::History,
        Ok(Payload::History(Box::new(history()))),
    );
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("history_158x41", s);
    assert!(s.contains("○ recorded while the Dashboard is open"), "{s}");
    key(&mut a, KeyCode::Char('1'));
    assert!(strip(&mut a).trim_end().ends_with("H History"));
    // `[` narrows the window; `r` reads the ring again.
    key(&mut a, KeyCode::Char('H'));
    key(&mut a, KeyCode::Char('['));
    assert!(render_to_string(&mut a, 158, 41).contains("last 6h"));
    let before = net(&a).asked.len();
    key(&mut a, KeyCode::Char('r'));
    assert_eq!(&net(&a).asked[before..], [Kind::History]);
}

#[test]
fn the_dashboard_polls_only_while_it_has_the_window() {
    let mut a = blank();
    let t0 = Instant::now();
    a.start(t0);
    // Entering the Dashboard reads both at once.
    assert_eq!(net(&a).asked, [Kind::Probe, Kind::Ifaces]);
    // The probe every second, the interfaces every thirty.
    a.tick(t0 + Duration::from_millis(500));
    assert_eq!(net(&a).asked.len(), 2);
    assert!(a.next_due(t0) <= t0 + Duration::from_secs(1));
    a.tick(t0 + Duration::from_millis(1001));
    a.tick(t0 + Duration::from_millis(2002));
    assert_eq!(&net(&a).asked[2..], [Kind::Probe, Kind::Probe]);
    a.tick(t0 + Duration::from_secs(31));
    assert_eq!(&net(&a).asked[4..], [Kind::Probe, Kind::Ifaces]);
    // On History nothing is polled.
    let t1 = t0 + Duration::from_secs(40);
    a.on_event(
        Event::Key(KeyEvent::new(KeyCode::Char('H'), KeyModifiers::NONE)),
        t1,
    );
    let n = net(&a).asked.len();
    assert_eq!(net(&a).asked[n - 1], Kind::History);
    a.tick(t1 + Duration::from_secs(120));
    assert_eq!(net(&a).asked.len(), n);
    assert_eq!(
        a.next_due(t1),
        t1 + Duration::from_secs(60),
        "the app's idle wait"
    );
    // `r` on the Dashboard reads both again.
    key(&mut a, KeyCode::Char('1'));
    let n = net(&a).asked.len();
    key(&mut a, KeyCode::Char('r'));
    assert_eq!(&net(&a).asked[n..], [Kind::Probe, Kind::Ifaces]);
}

#[test]
fn samples_become_the_ring_but_tests_write_none() {
    let mut a = app();
    // Offline nothing is written, so History stays out of the strip.
    assert!(!sentry_core::recorder::ring::path("net:home").exists());
    let tabs = render_to_string(&mut a, 158, 41);
    assert!(!tabs.lines().nth(1).unwrap().contains("History"));
    // What the recorder was fed: the uplink's rate in bytes a second, as the ring keeps it.
    let mut s = super::data::Store::default();
    s.apply(Kind::Probe, Ok(Payload::Probe(first())));
    assert_eq!(
        s.sampled.map(|x| (x.cpu, x.rx, x.temp)),
        Some((None, None, Some(51.5)))
    );
    s.apply(Kind::Probe, Ok(Payload::Probe(later(1))));
    let x = s.sampled.unwrap();
    assert_eq!((x.rx, x.tx), (Some(1_500_000.0), Some(250_000.0)));
    assert!((x.cpu.unwrap() - 7.0).abs() < 0.01, "{:?}", x.cpu);
    assert_eq!(s.traffic["eth1"].last(), Some(14_000_000.0));
}

#[test]
fn maintenance_claude_and_workflows_say_what_isnt_there_yet() {
    use sentry_app::target::{Asks, Cx, Host, ProfileFor, Upkeep};
    let mut a = app();
    // A: nothing is asked, and it says why (whether or not Claude Code is installed).
    key(&mut a, KeyCode::Char('A'));
    assert_eq!(
        a.toast_for_test(),
        Some("Claude isn't set up for a network yet")
    );
    assert!(a.chat_for_test().is_none() && a.apply_session().is_none());
    // No workflows: `:wf` says so and stays where it is.
    typed(&mut a, ":wf package-update");
    assert_eq!(
        a.toast_for_test(),
        Some("there are no workflows for a network yet")
    );
    typed(&mut a, ":workflow");
    assert_eq!(a.slot().screen, ScreenId::Dash);
    // The digits of screens it doesn't have do nothing.
    for c in ['2', '3', '6', '0'] {
        key(&mut a, KeyCode::Char(c));
        assert_eq!(a.slot().screen, ScreenId::Dash, "{c}");
    }
    let s = render_to_string(&mut a, 158, 41);
    assert!(!s.contains("Maintenance") && !s.contains("Upgrade"), "{s}");
    // What the app would be told if it asked.
    let slot = a.slot();
    let t = net(&a);
    let theme = sentry_core::tui::theme::Theme::truecolor();
    let cx = Cx {
        theme: &theme,
        now: jiff::Timestamp::UNIX_EPOCH,
        screen: ScreenId::Dash,
        filter: None,
        everything: true,
        writer: None,
        run: None,
        last_change: None,
        offline: true,
        at: Instant::now(),
        modal: false,
        pane: None,
        chat_running: false,
        finding: None,
        root: false,
        auto: false,
        focused: true,
        target: NAME,
    };
    assert!(t.derived_tasks(&slot.shared).is_empty());
    assert!(t.series_step("anything", &slot.shared, &cx).is_none());
    assert!(t.apply_ask(&slot.shared, &cx).is_none());
    assert!(t.ask(&slot.shared, &cx).is_err());
    assert!(t.records(&slot.shared, &cx).0.is_empty());
    let (wfs, dir) = t.workflows();
    assert!(wfs.is_empty());
    assert!(dir.ends_with("networks/home/workflows"));
    assert!(t.resume_run().is_none());
    // A profile that allows nothing, should one ever be asked for.
    let p = t.profile(ProfileFor::Session, &[]);
    assert!(p.tools.is_empty() && p.allowed.is_empty() && p.denied.contains(&"Bash".into()));
    // A command line is the router's shell's, over ssh as root, streamed the dropbear way.
    let c = t.command("logread -l 5");
    assert_eq!(c.remote_line(), "env LC_ALL=C sh -c 'logread -l 5'");
    assert!(c.holds_stdin());
    // Its records are a network's.
    let id = t.ident();
    assert_eq!(
        (id.id.as_str(), id.scope.as_str(), id.word),
        ("net:home", "net:home", "net")
    );
    assert!(id.runs.ends_with("networks/home/workflows"));
}

#[test]
fn help_and_quit_speak_of_the_router() {
    let mut a = app();
    key(&mut a, KeyCode::Char('?'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("sentry-network") && s.contains("read again"),
        "{s}"
    );
    assert!(s.contains("Nothing is installed on home's router"), "{s}");
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('q'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Nothing keeps running on home's router after exit."),
        "{s}"
    );
}

/// The network named by `SENTRY_NETWORK_LIVE`, from the real (or scratch) config dir.
fn live_router() -> Option<Router> {
    sentry_core::paths::use_real_dirs();
    let name = std::env::var("SENTRY_NETWORK_LIVE").ok()?;
    let (file, _) = crate::config::load().unwrap();
    let (n, cfg) = crate::config::pick(&file, Some(&name)).unwrap();
    Some(Router::new(n, cfg))
}

/// Against a real router, read-only there. The ring the Dashboard's samples become is
/// written under XDG_DATA_HOME, so point that and XDG_CONFIG_HOME (holding a
/// network_config.yaml) at a scratch dir:
/// `SENTRY_NETWORK_LIVE=<name> XDG_CONFIG_HOME=… XDG_DATA_HOME=… cargo test -p sentry-network live_network_screens -- --ignored --nocapture`
/// prints both screens.
#[test]
#[ignore]
fn live_network_screens() {
    let Some(r) = live_router() else {
        return;
    };
    assert!(
        std::env::var_os("XDG_DATA_HOME").is_some(),
        "set XDG_DATA_HOME to a scratch dir: the samples taken here are recorded"
    );
    let scope = r.scope.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut a = App::new(tx, &super::id_of(&r.name), super::target(r));
    a.win.theme = sentry_core::tui::theme::Theme::truecolor();
    a.start(Instant::now());
    let pump = |a: &mut App, secs: u64| {
        let until = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < until {
            if let Ok(ev) = rx.recv_timeout(Duration::from_millis(100)) {
                a.on_event(ev, Instant::now());
            }
            a.tick(Instant::now());
        }
    };
    // Long enough for a dozen probes and the first record of the ring (ten seconds).
    pump(&mut a, 13);
    let s = render_to_string(&mut a, 158, 41);
    println!("{s}");
    assert!(s.contains("● connected"), "not connected");
    assert!(s.contains("│ release  OpenWrt"), "no release line");
    assert!(s.contains("│ memory") && s.contains("│ flash"));
    let t = net(&a);
    let p = t.store.probe.value.as_ref().expect("a probe");
    assert!(p.ports.len() >= 2 && p.host.cores >= 1);
    let asked = t.asked.iter().filter(|k| **k == Kind::Probe).count();
    assert!((10..=15).contains(&asked), "{asked} probes in 13 s");
    assert_eq!(t.asked.iter().filter(|k| **k == Kind::Ifaces).count(), 1);
    // Every row has a rate by now, and the uplink is among them.
    let rows = super::screens::dashboard::port_rows(&super::screens::View {
        t: &a.win.theme,
        s: &t.store,
        cfg: &t.router.cfg,
        name: &t.router.name,
    });
    assert!(rows.len() >= 2, "{} rows", rows.len());
    assert!(
        rows.iter().all(|r| r.rate.is_some()),
        "a row without a rate"
    );
    assert!(rows.iter().any(|r| r.net.as_deref() == Some("wan")));
    assert!(
        sentry_core::recorder::ring::path(&scope).exists(),
        "the samples became a ring"
    );
    // History reads that ring.
    key(&mut a, KeyCode::Char('H'));
    pump(&mut a, 2);
    let s = render_to_string(&mut a, 158, 41);
    println!("{s}");
    assert!(
        s.contains("History · last 24h · every 10s"),
        "no ring shown"
    );
    assert!(s.lines().nth(1).unwrap().contains("H History"));
}

/// The gate "rates are right", against a real router (read-only): two readings ten seconds
/// apart, each one exec holding the probe and, before it, the kernel's own per-interface
/// counters from `/sys/class/net/<if>/statistics` with `/proc/uptime`. What the Dashboard's
/// rate logic makes of the two probes must agree with the rate worked out here from the
/// other counters, within 5 % (or 2 kbit/s on a port that is nearly idle).
/// `SENTRY_NETWORK_LIVE=<name> XDG_CONFIG_HOME=… cargo test -p sentry-network live_rates -- --ignored --nocapture`
#[test]
#[ignore]
fn live_rates() {
    use std::collections::HashMap;
    let Some(r) = live_router() else {
        return;
    };
    let script = format!(
        "echo @@by-hand; cat /proc/uptime; cd /sys/class/net && for n in *; do \
         read rx <$n/statistics/rx_bytes; read tx <$n/statistics/tx_bytes; \
         echo \"$n $rx $tx\"; done; cd /; {}",
        probe::script()
    );
    // (uptime, name → (rx, tx)) as read by hand, and the probe of the same exec.
    let read = || {
        let out = r.output(&r.sh(&script)).unwrap();
        let hand = crate::collect::sections(&out)
            .into_iter()
            .find(|(n, _)| *n == "by-hand")
            .unwrap()
            .1
            .to_string();
        let mut lines = hand.lines();
        let up: f64 = lines
            .next()
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let counters: HashMap<String, (u64, u64)> = lines
            .filter_map(|l| {
                let w: Vec<&str> = l.split_whitespace().collect();
                Some((
                    w.first()?.to_string(),
                    (w.get(1)?.parse().ok()?, w.get(2)?.parse().ok()?),
                ))
            })
            .collect();
        (up, counters, probe::parse(&out).unwrap())
    };
    let (up0, c0, p0) = read();
    std::thread::sleep(Duration::from_secs(10));
    let (up1, c1, p1) = read();
    let mut rates = crate::rates::Rates::default();
    assert!(rates.feed(&p0).is_empty());
    let got = rates.feed(&p1);
    let dt = up1 - up0;
    assert!((9.5..12.0).contains(&dt), "{dt} s between the readings");
    let mut worst: f64 = 0.0;
    let mut busiest: f64 = 0.0;
    for (i, name) in c1.keys().enumerate() {
        let (Some(a), Some(b), Some(g)) = (c0.get(name), c1.get(name), got.get(name)) else {
            panic!("a port without a rate");
        };
        for (dir, hand, ours) in [
            ("in", (b.0 - a.0) as f64 * 8.0 / dt, g.rx),
            ("out", (b.1 - a.1) as f64 * 8.0 / dt, g.tx),
        ] {
            let off = (ours - hand).abs();
            let pct = if hand > 0.0 { 100.0 * off / hand } else { 0.0 };
            // (Ports by number, not name: what's printed may be kept.)
            println!(
                "port {i} {dir:<3} by hand {:>14}  dashboard {:>14}  off {pct:.2}%",
                crate::rates::bits(hand),
                crate::rates::bits(ours)
            );
            assert!(
                off <= hand * 0.05 || off <= 2000.0,
                "port {i} {dir}: {ours} against {hand} by hand"
            );
            if hand >= 50_000.0 {
                worst = worst.max(pct);
            }
            busiest = busiest.max(hand);
        }
    }
    println!(
        "over {dt:.2} s of the router's clock: busiest {} · worst difference on a port moving \
         50 kbit/s or more: {worst:.2}%",
        crate::rates::bits(busiest)
    );
}

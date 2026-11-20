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
    blank_with(&Network::default())
}

fn blank_with(cfg: &Network) -> App {
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut a = App::new(
        tx,
        &super::id_of(NAME),
        super::target(Router::new(NAME, cfg)),
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
    // Entering the Dashboard reads what it shows at once (the last report is this
    // machine's file, not the router's).
    assert_eq!(
        net(&a).asked,
        [Kind::Probe, Kind::Ifaces, Kind::Services, Kind::Report]
    );
    // The probe every second, the interfaces every thirty, the services every minute.
    a.tick(t0 + Duration::from_millis(500));
    assert_eq!(net(&a).asked.len(), 4);
    assert!(a.next_due(t0) <= t0 + Duration::from_secs(1));
    a.tick(t0 + Duration::from_millis(1001));
    a.tick(t0 + Duration::from_millis(2002));
    assert_eq!(&net(&a).asked[4..], [Kind::Probe, Kind::Probe]);
    a.tick(t0 + Duration::from_secs(31));
    assert_eq!(&net(&a).asked[6..], [Kind::Probe, Kind::Ifaces]);
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
    // `r` on the Dashboard reads it all again.
    key(&mut a, KeyCode::Char('1'));
    let n = net(&a).asked.len();
    key(&mut a, KeyCode::Char('r'));
    assert_eq!(
        &net(&a).asked[n..],
        [Kind::Probe, Kind::Ifaces, Kind::Services, Kind::Report]
    );
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
fn claude_and_workflows_say_what_isnt_there_yet() {
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
    for c in ['4', '5', '7', '0'] {
        key(&mut a, KeyCode::Char(c));
        assert_eq!(a.slot().screen, ScreenId::Dash, "{c}");
    }
    let s = render_to_string(&mut a, 158, 41);
    assert!(!s.contains("Upgrade") && !s.contains("Containers"), "{s}");
    // Nothing that isn't there is offered: no Claude in the key bar or in `?`, no auto
    // mode, on any of its screens.
    for c in ['1', '2', '3', '6'] {
        key(&mut a, KeyCode::Char(c));
        let s = render_to_string(&mut a, 158, 41);
        let bar = s.lines().last().unwrap();
        assert!(!bar.to_lowercase().contains("claude"), "{c}: {bar}");
        assert!(
            !bar.contains("auto") && !bar.contains("review"),
            "{c}: {bar}"
        );
        key(&mut a, KeyCode::Char('?'));
        let help = render_to_string(&mut a, 158, 41);
        assert!(
            !help.contains("Claude") && !help.contains("auto mode"),
            "{c}: {help}"
        );
        key(&mut a, KeyCode::Esc);
    }
    key(&mut a, KeyCode::Char('1'));
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
    assert!(
        t.series_step("finding:net:ssh:password", &slot.shared, &cx)
            .is_none()
    );
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
/// prints the Dashboard and History, and the audit's findings by kind.
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
    assert!(s.contains("│ services ● dnsmasq"), "no services row");
    // Every row has a rate by now, and the uplink is among them.
    let rows = super::screens::dashboard::port_rows(&super::screens::View {
        t: &a.win.theme,
        s: &t.store,
        sh: &a.slot().shared,
        cfg: &t.router.cfg,
        name: &t.router.name,
        cur: 0,
        now: jiff::Timestamp::now(),
        filter: None,
        everything: false,
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
    // Clients, Network and Maintenance: each reads what it shows; entering Maintenance
    // with no report yet audits (reads only; the report, the salt and what was seen go
    // under the scratch dirs).
    assert!(
        std::env::var_os("XDG_CONFIG_HOME").is_some(),
        "set XDG_CONFIG_HOME to a scratch dir: the audit keeps its state there"
    );
    for (c, want) in [('2', "Clients"), ('3', "Listening"), ('6', "Recommended")] {
        key(&mut a, KeyCode::Char(c));
        pump(&mut a, 3);
        let s = render_to_string(&mut a, 158, 41);
        // (Not printed: who is on the network is nobody else's business.)
        assert!(s.contains(want), "{want} isn't drawn");
        assert!(!s.contains("reading"), "{want}: still reading after 3 s");
    }
    let t = net(&a);
    assert!(t.store.clients.as_ref().is_some_and(|c| !c.is_empty()));
    assert!(
        t.store
            .listeners
            .value
            .as_ref()
            .is_some_and(|l| l.len() > 3)
    );
    let u = t.store.uci.value.as_ref().expect("the config");
    assert!(!u.zones().is_empty() && u.config("wireless").iter().any(|s| s.kind == "wifi-iface"));
    // Every Wi-Fi passphrase is a tag by the time it's here.
    for sec in u.config("wireless") {
        for k in ["key", "sae_password"] {
            assert!(
                sec.one(k).is_none_or(crate::redact::is_tag),
                "{k} isn't tagged"
            );
        }
    }
    let rep = t
        .store
        .report
        .value
        .as_ref()
        .and_then(|r| r.as_deref())
        .expect("a report");
    assert!(rep.snapshot.errors.is_empty(), "{:?}", rep.snapshot.errors);
    let mut kinds: std::collections::BTreeMap<String, usize> = Default::default();
    for f in rep.open() {
        let kind: Vec<&str> = f.id.split(':').take(2).collect();
        *kinds.entry(kind.join(":")).or_default() += 1;
    }
    println!("findings by kind: {kinds:?}");
    assert!(crate::redact::path(&scope).exists() && crate::clients::Seen::path(&scope).exists());
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

// ---- Clients, Network, Maintenance: the fixtures as a network set up as its config says.

use crate::audit::{self, Report, Shown};
use sentry_core::finding::Sev;

fn fx_cfg() -> Network {
    audit::tests::cfg()
}

/// A report as read from disk: the newest of `n` kept.
fn shown(report: Report, prev: Option<Report>, n: usize) -> Shown {
    Shown {
        names: (0..n)
            .map(|i| format!("2026-10-2{}-120000", 6 + i - (n - 1)))
            .collect(),
        idx: n - 1,
        cur: Some(Box::new(report)),
        prev: prev.map(Box::new),
    }
}

fn report_for(cfg: &Network, snap: audit::Snapshot, a: &App) -> Report {
    let findings = audit::derive(&snap, cfg, None, &a.slot().shared.baseline);
    Report {
        snapshot: snap,
        findings,
    }
}

/// Everything read: the Dashboard's samples, then the clients (twice: a lease held two
/// reads running), the listeners, the config, the certificate, the services, and the last
/// audit's report (taken five minutes ago).
fn full_with(cfg: &Network, snap: impl Fn(&Network) -> audit::Snapshot) -> App {
    let mut a = blank_with(cfg);
    data(
        &mut a,
        Kind::Ifaces,
        Ok(Payload::Ifaces(Box::new(the_ifaces()))),
    );
    for s in 0..4 {
        data(&mut a, Kind::Probe, Ok(Payload::Probe(later(s))));
    }
    let s = snap(cfg);
    let raw = crate::collect::clients::parse(&fixture("network/clients.txt")).unwrap();
    for _ in 0..2 {
        data(
            &mut a,
            Kind::Clients,
            Ok(Payload::Clients(Box::new(raw.clone()))),
        );
    }
    data(
        &mut a,
        Kind::Listeners,
        Ok(Payload::Listeners(s.listeners.clone().unwrap())),
    );
    data(
        &mut a,
        Kind::Uci,
        Ok(Payload::Uci(Box::new(s.uci.clone().unwrap()))),
    );
    data(&mut a, Kind::Cert, Ok(Payload::Cert(s.cert)));
    data(
        &mut a,
        Kind::Services,
        Ok(Payload::Services(s.services.clone().unwrap())),
    );
    let mut s = s;
    s.taken_at = Some("2026-10-26T11:55:00Z".parse().unwrap());
    let rep = report_for(cfg, s, &a);
    data(
        &mut a,
        Kind::Report,
        Ok(Payload::Reports(Box::new(shown(rep, None, 1)))),
    );
    a
}

fn full() -> App {
    full_with(&fx_cfg(), audit::tests::snap)
}

/// A network nobody described: no zones, forwards, listeners or devices expected, ssh
/// taking passwords, the web interface over HTTP, a socket on the uplink's address.
fn messy() -> App {
    let mut cfg = fx_cfg();
    cfg.expect.forwards.remove(1);
    cfg.expect.forwards.push(crate::config::Forward {
        name: "cam".into(),
        proto: "tcp".into(),
        port: "8554".parse().unwrap(),
        to: "192.0.2.50".into(),
    });
    cfg.expect.zones.remove("dmz");
    cfg.expect.listeners.retain(|l| !l.contains(":53@"));
    cfg.devices
        .retain(|d| !matches!(d.name.as_deref(), Some("desk" | "dock")));
    full_with(&cfg, |c| {
        let mut s = audit::tests::snap_wan(c);
        let text = fixture("network/uci.txt")
            .replace(
                "dropbear.main.PasswordAuth='off'",
                "dropbear.main.PasswordAuth='on'",
            )
            .replace(
                "uhttpd.main.redirect_https='1'",
                "uhttpd.main.redirect_https='0'",
            );
        s.uci = Some(crate::collect::uci::parse(
            &text,
            &crate::redact::Salt::fixed([7; 16]),
        ));
        s
    })
}

fn screen(a: &mut App, c: char, w: u16, h: u16) -> String {
    key(a, KeyCode::Char(c));
    render_to_string(a, w, h)
}

#[test]
fn dashboard_with_status() {
    let mut a = full();
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("dashboard_status_158x41", s);
    assert!(
        line(&s, "│ clients").contains("8 · 5 wired · 3 Wi-Fi")
            && !line(&s, "│ clients").contains("new"),
        "{s}"
    );
    assert!(line(&s, "│ services").contains("● dnsmasq ● dropbear ● uhttpd"));
    assert!(line(&s, "│ audit").contains("✓ nothing to check · 5m ago"));
    assert!(line(&s, "│ cert").contains("157 days left"));
    let tabs = s.lines().nth(1).unwrap();
    assert!(
        tabs.contains("1 Dashboard")
            && tabs.contains("2 Clients")
            && tabs.contains("3 Network")
            && tabs.contains("6 Maintenance"),
        "{tabs}"
    );
    // What needs a look shows where it is: on the rows, and beside the screens' names.
    let mut a = messy();
    let s = render_to_string(&mut a, 158, 41);
    assert!(line(&s, "│ clients").contains("2 new"), "{s}");
    assert!(
        line(&s, "│ audit").contains("2 to check · 6 to review"),
        "{s}"
    );
    let tabs = s.lines().nth(1).unwrap();
    assert!(
        tabs.contains("2 Clients 2") && tabs.contains("6 Maintenance 8"),
        "{tabs}"
    );
    // A service down, a certificate near its end.
    let mut sv = audit::tests::snap(&fx_cfg()).services.unwrap();
    sv.0.get_mut("uhttpd").unwrap().running = 0;
    data(&mut a, Kind::Services, Ok(Payload::Services(sv)));
    a.win.now_override = Some("2027-03-20T00:00:00Z".parse().unwrap());
    let s = render_to_string(&mut a, 158, 41);
    assert!(line(&s, "│ services").contains("○ uhttpd"), "{s}");
    assert!(line(&s, "│ cert").contains("ends in 13 days"), "{s}");
    assert!(s.lines().all(|l| l.chars().count() <= 158));
    let narrow = render_to_string(&mut a, 80, 24);
    assert!(line(&narrow, "│ clients").chars().count() <= 80, "{narrow}");
}

#[test]
fn clients_wide_narrow_and_filtered() {
    let mut a = full();
    let s = screen(&mut a, '2', 158, 41);
    insta::assert_snapshot!("clients_158x41", s);
    assert!(
        s.contains("8 here · 5 wired · 3 Wi-Fi · 0 new · by name"),
        "{s}"
    );
    // Named by the config; a private MAC marked `~` under the hostname it gives.
    assert!(line(&s, " nas ").contains("lan1") && line(&s, " nas ").contains("192.0.2.10"));
    let phone = line(&s, "~phone");
    assert!(
        phone.contains("phy1-ap0 ▂▄▆█ -46") && phone.contains("192.0.2.20"),
        "{phone}"
    );
    assert!(line(&s, "panel").contains("(leave alone)"));
    assert!(line(&s, " web ").contains("dmz · lan4"));
    // Its lease runs another 6 h; one that's gone is dimmed with when it was last seen.
    assert!(line(&s, " nas ").contains("6h") && line(&s, " nas ").contains("now"));
    assert!(line(&s, "printer").contains("–") && s.contains("(an IPv6 lease)"));
    assert!(!s.contains("NEW"), "{s}");
    let narrow = render_to_string(&mut a, 80, 24);
    insta::assert_snapshot!("clients_80x24", narrow);
    assert!(narrow.lines().all(|l| l.chars().count() <= 80));
    assert!(narrow.contains("~phone") && narrow.contains("192.0.2.20") && !narrow.contains("SEEN"));
    // `/`: by name, address, link or MAC.
    key(&mut a, KeyCode::Char('/'));
    for c in "wifi".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("clients_filter_158x41", s);
    assert!(
        s.contains("~phone") && s.contains("panel") && !s.contains(" nas "),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    // `s`: by link, by signal (strongest first), by lease.
    key(&mut a, KeyCode::Char('s'));
    assert_eq!(a.toast_for_test(), Some("sorted by link"));
    key(&mut a, KeyCode::Char('s'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("LINK · SIGNAL ▼"), "{s}");
    let at = |what: &str| s.find(what).unwrap_or_else(|| panic!("{what}"));
    assert!(at("~phone") < at("~02:00:5e:00:53:21") && at("~02:00:5e:00:53:21") < at("panel"));
    // The Clients screen reads every ten seconds, and only while it's in view.
    let n = net(&a).asked.len();
    let t0 = Instant::now();
    a.tick(t0 + Duration::from_secs(11));
    assert!(
        net(&a).asked[n..].contains(&Kind::Clients),
        "{:?}",
        &net(&a).asked[n..]
    );
}

#[test]
fn a_clients_details_and_marking_one_expected() {
    let mut a = messy();
    let s = screen(&mut a, '2', 158, 41);
    // The unknown ones first, marked; the private one on Wi-Fi isn't one of them.
    assert!(s.contains("2 new"), "{s}");
    let first = s.lines().find(|l| l.contains("NEW")).unwrap();
    assert!(
        first.contains("00:00:5e:00:53:11") && first.contains("lan2"),
        "{first}"
    );
    assert!(line(&s, "~02:00:5e:00:53:22").contains("NEW"));
    assert!(!line(&s, "~02:00:5e:00:53:21").contains("NEW"));
    // Enter: what's known, and the line that would name it.
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("clients_detail_158x41", s);
    assert!(
        s.contains("00:00:5e:00:53:11 · vendor prefix 00:00:5e"),
        "{s}"
    );
    assert!(s.contains("wired port lan2") && s.contains("first seen"));
    assert!(
        s.contains("- { name: a-name, mac: \"00:00:5e:00:53:11\" }"),
        "{s}"
    );
    key(&mut a, KeyCode::Esc);
    // The phone: a private address, named by the hostname it gives.
    let find = |a: &mut App, what: &str| {
        key(a, KeyCode::Char('/'));
        for c in what.chars() {
            key(a, KeyCode::Char(c));
        }
        key(a, KeyCode::Enter);
    };
    find(&mut a, "phone");
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("private (randomised): no vendor"), "{s}");
    assert!(s.contains("Wi-Fi on phy1-ap0 · -46 dBm"), "{s}");
    assert!(s.contains("the passphrase vouches for it"), "{s}");
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(
        a.toast_for_test(),
        Some("a private address on Wi-Fi is never flagged: nothing to mark")
    );
    // b: the unknown one is expected, by its MAC, in the baseline (nothing is written:
    // tests are offline); its finding goes with it. b again takes it back.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(a.toast_for_test(), Some("marked expected (baseline.toml)"));
    assert_eq!(
        a.slot().shared.baseline.findings,
        ["net:client:00:00:5e:00:53:11"]
    );
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("1 new") && line(&s, "00:00:5e:00:53:11").contains("expected"),
        "{s}"
    );
    let open = |a: &App| -> Vec<String> {
        let r = net(a)
            .store
            .report
            .value
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap();
        r.open()
            .filter(|f| f.id.starts_with("net:client"))
            .map(|f| f.id.clone())
            .collect()
    };
    assert_eq!(open(&a), ["net:client:02:00:5e:00:53:22"]);
    // It sorted down among the rest: find it again, and take it back.
    key(&mut a, KeyCode::Char('/'));
    for c in "53:11".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(a.toast_for_test(), Some("no longer expected"));
    assert!(a.slot().shared.baseline.findings.is_empty());
    assert_eq!(open(&a).len(), 2);
    assert!(
        !crate::clients::Seen::path("net:home").exists(),
        "tests write nothing"
    );
}

#[test]
fn network_clean_and_with_differences() {
    let mut a = full();
    let s = screen(&mut a, '3', 158, 41);
    insta::assert_snapshot!("network_158x41", s);
    assert!(
        s.contains("Zones · 3 · as expected") && s.contains("Forwards · 2 · as expected"),
        "{s}"
    );
    assert!(line(&s, "│ wan").contains("reject") && line(&s, "│ wan").contains("✓"));
    assert!(s.contains("let in from outside: udp 68 · icmp"), "{s}");
    assert!(line(&s, "old-cam").contains("off"));
    assert!(s.contains("netstat -lntup · 24 · 0 new"), "{s}");
    // Loopback is local, a client's socket a client's, the rest what the config expects.
    assert!(line(&s, "127.0.0.1:5053").contains("https-dns-prox (3404)"));
    assert!(line(&s, "127.0.0.1:5053").contains("local"));
    assert!(line(&s, "0.0.0.0:51234").contains("client"));
    assert!(line(&s, "0.0.0.0:22").contains("baseline"));
    assert!(
        !s.contains("Established"),
        "a router's own connections aren't a panel"
    );
    let narrow = render_to_string(&mut a, 80, 24);
    assert!(narrow.lines().all(|l| l.chars().count() <= 80));
    assert!(narrow.contains("Zones") && narrow.contains("Listening"));

    let mut a = messy();
    let s = screen(&mut a, '3', 158, 41);
    insta::assert_snapshot!("network_differences_158x41", s);
    assert!(
        s.contains("Zones · 3 · 1 differ") && s.contains("Forwards · 2 · 2 differ"),
        "{s}"
    );
    assert!(line(&s, "│ dmz").contains("≠ isn't in expect.zones"), "{s}");
    assert!(line(&s, "│ game").contains("NEW"));
    assert!(line(&s, "│ cam").contains("≠ missing"));
    assert!(line(&s, "198.51.100.23:1900").contains("NEW"));
    assert!(s.contains("· 9 new"), "{s}");
    assert!(s.lines().nth(1).unwrap().contains("3 Network 9"));
    // b on a listener: the port on every address, and its finding, are expected; b again
    // takes both back. Nothing is written (offline).
    key(&mut a, KeyCode::Char('/'));
    for c in ":1900".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(
        a.toast_for_test(),
        Some("udp 1900: expected (baseline.toml)")
    );
    let b = &a.slot().shared.baseline;
    assert_eq!(b.listeners, ["198.51.100.23:1900/?"]);
    assert_eq!(b.findings, ["net:listener:udp:1900"]);
    let s = render_to_string(&mut a, 158, 41);
    assert!(line(&s, "198.51.100.23:1900").contains("baseline"), "{s}");
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(a.toast_for_test(), Some("udp 1900: no longer expected"));
    let b = &a.slot().shared.baseline;
    assert!(b.listeners.is_empty() && b.findings.is_empty());
    // What the config expects isn't the file's to take back; what nothing can reach isn't
    // anything's to mark.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('/'));
    for c in "0.0.0.0:22".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(
        a.toast_for_test(),
        Some("expected by network_config.yaml (expect.listeners): change it there")
    );
    // Entering Network reads what listens and the config, once.
    let asked = &net(&a).asked;
    assert_eq!(asked.iter().filter(|k| **k == Kind::Uci).count(), 1);
    assert_eq!(asked.iter().filter(|k| **k == Kind::Listeners).count(), 1);
}

#[test]
fn maintenance_lists_the_findings_and_b_and_pattern_round_trip() {
    let mut a = messy();
    let s = screen(&mut a, '6', 158, 41);
    insta::assert_snapshot!("maintenance_findings_158x41", s);
    assert!(
        s.contains("Recommended · 8 · 2 can wait (o) · audited 5m ago"),
        "{s}"
    );
    // The most pressing first: what the internet can reach.
    let first = s.lines().find(|l| l.contains("│ now")).unwrap();
    assert!(
        first.contains("is open to the internet") || first.contains("is forwarded to"),
        "{first}"
    );
    assert!(s.contains("ssh accepts passwords") && s.contains("the web interface answers over"));
    assert!(s.contains("unknown device 00:00:5e"));
    // What the last audit looked at, beside the list.
    assert!(line(&s, "● firewall").contains("3 zones · 2 forwards"));
    assert!(line(&s, "● access").contains("ssh takes passwords · web interface over HTTP too"));
    assert!(line(&s, "● clients").contains("2 unknown"));
    assert!(line(&s, "✓ services").contains("3 of 3 running"));
    // The key bar: what this row takes, and nothing that does nothing.
    let bar = s.lines().last().unwrap();
    for k in [
        "Enter  in the report",
        "x  expected",
        "B  all like it",
        "z  later",
        "o  everything",
        "r  audit",
        "F  report",
        "v  records",
    ] {
        assert!(bar.contains(k), "{k} in {bar}");
    }
    assert!(!bar.contains("Space") && !bar.contains("A  "), "{bar}");
    // o: the low ones too (listeners only the inside reaches).
    key(&mut a, KeyCode::Char('o'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Recommended · 10 ·") && s.contains("listens on the rout"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('o'));
    // b: the selected finding is expected and leaves the list; Records › Later has it.
    let n = |a: &App| {
        net(a)
            .store
            .report
            .value
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .open()
            .count()
    };
    let before = n(&a);
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(a.toast_for_test(), Some("marked expected (baseline.toml)"));
    assert_eq!(n(&a), before - 1);
    let marked = a.slot().shared.baseline.findings[0].clone();
    assert!(marked.starts_with("net:"), "{marked}");
    // x asks first, and says where it's written.
    key(&mut a, KeyCode::Char('x'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Mark it expected") && s.contains("baseline.toml"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('n'));
    assert_eq!(a.slot().shared.baseline.findings.len(), 1);
    // B on a client finding: every client finding, after its box.
    key(&mut a, KeyCode::Char('/'));
    for c in "unknown device".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('B'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Treat every client finding as expected?"), "{s}");
    assert!(
        s.contains("networks/home/baseline.toml ← net:client:*"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('y'));
    assert_eq!(
        a.slot().shared.baseline.findings,
        [marked.clone(), "net:client:*".to_string()]
    );
    assert_eq!(n(&a), before - 3);
    key(&mut a, KeyCode::Esc);
    // The pattern covers the Clients screen's rows too.
    let s = screen(&mut a, '2', 158, 41);
    assert!(s.contains("0 new") && s.contains("expected"), "{s}");
    // Taking the pattern back (as Records › Later does): they're findings again.
    use sentry_app::target::{Cx, Upkeep};
    let row = sentry_core::tui::records::LaterRow {
        kind: sentry_core::tui::records::LaterKind::Expected,
        key: "net:client:*".into(),
        file: "baseline.toml",
    };
    let theme = sentry_core::tui::theme::Theme::truecolor();
    let cx = Cx {
        theme: &theme,
        now: "2026-10-26T12:00:00Z".parse().unwrap(),
        screen: ScreenId::Maint,
        filter: None,
        everything: false,
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
    let (slot, _) = a.parts();
    let t: &mut NetworkTarget = slot.target.as_any_mut().downcast_mut().unwrap();
    let fx = t.undo(&row, &mut slot.shared, &cx).unwrap();
    assert_eq!(fx.len(), 1);
    let (later, audited) = t.records(&slot.shared, &cx);
    assert!(later.is_empty());
    assert_eq!(audited, Some("2026-10-26T11:55:00Z".parse().unwrap()));
}

#[test]
fn the_audit_report_view() {
    let mut a = messy();
    key(&mut a, KeyCode::Char('6'));
    // Enter on a finding: the report, on that finding.
    key(&mut a, KeyCode::Char('j'));
    let s = render_to_string(&mut a, 158, 41);
    let picked = s
        .lines()
        .filter(|l| l.contains("│ now") || l.contains("│ soon"))
        .nth(1)
        .unwrap()
        .to_string();
    key(&mut a, KeyCode::Enter);
    assert_eq!(*net(&a).asked.last().unwrap(), Kind::Report);
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("report_158x41", s);
    assert!(s.contains("Maintenance › Audit report"), "{s}");
    assert!(s.contains("Worth a look on this network."));
    assert!(s.contains("2 to check") || s.contains("check 2"), "{s}");
    assert!(s.contains("Nothing to compare against yet."));
    assert!(
        s.contains("net:forward:udp:8000-8010") || s.contains("net:listener:udp:1900"),
        "{s}"
    );
    let _ = picked;
    let bar = s.lines().last().unwrap();
    assert!(
        bar.contains("b  expected on/off") && !bar.to_lowercase().contains("claude"),
        "{bar}"
    );
    // b: expected, and back; the list shows it at once.
    let n = |a: &App| {
        net(a)
            .store
            .report
            .value
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .open()
            .count()
    };
    let before = n(&a);
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(n(&a), before - 1);
    // (Marked, it sorts to the end: select it again there.)
    key(&mut a, KeyCode::Char('G'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("expected (b takes it back)"), "{s}");
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(n(&a), before);
    assert!(a.slot().shared.baseline.findings.is_empty());
    // c audits again; Esc is the list.
    key(&mut a, KeyCode::Char('c'));
    assert_eq!(*net(&a).asked.last().unwrap(), Kind::Audit);
    assert_eq!(a.toast_for_test(), Some("auditing the network…"));
    key(&mut a, KeyCode::Esc);
    assert!(render_to_string(&mut a, 158, 41).contains("Recommended"));
    // `:audit` opens it from anywhere; `F` too.
    key(&mut a, KeyCode::Char('1'));
    typed(&mut a, ":audit");
    assert_eq!(a.slot().screen, ScreenId::Maint);
    assert!(render_to_string(&mut a, 158, 41).contains("Maintenance › Audit report"));
    // The audit that just ran, compared with the one before.
    let cfg = fx_cfg();
    let old = report_for(&cfg, audit::tests::snap_wan(&cfg), &a);
    let new = report_for(&cfg, audit::tests::snap(&cfg), &a);
    assert_eq!((old.findings.len(), new.findings.len()), (1, 0));
    data(
        &mut a,
        Kind::Audit,
        Ok(Payload::Reports(Box::new(shown(new, Some(old), 2)))),
    );
    assert_eq!(a.toast_for_test(), Some("audit done · report saved"));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Changed: 0 new, 1 gone"), "{s}");
    assert!(s.contains("Nothing to report."), "{s}");
    assert_eq!(n(&a), 0);
    assert_eq!(Sev::High.as_str(), "high");
}

#[test]
fn maintenance_audits_on_entry_when_the_last_report_is_old() {
    let cfg = fx_cfg();
    let report_at = |a: &mut App, when: Option<&str>| {
        let rep = when.map(|w| {
            let mut s = audit::tests::snap(&cfg);
            s.taken_at = Some(w.parse().unwrap());
            report_for(&cfg, s, a)
        });
        let shown = match rep {
            Some(r) => shown(r, None, 1),
            None => Shown::default(),
        };
        data(a, Kind::Report, Ok(Payload::Reports(Box::new(shown))));
    };
    // Five minutes old: entering Maintenance reads the report from disk and leaves it.
    let mut a = blank_with(&cfg);
    key(&mut a, KeyCode::Char('6'));
    assert_eq!(net(&a).asked, [Kind::Report]);
    report_at(&mut a, Some("2026-10-26T11:55:00Z"));
    // (It's a day's worth of certificate, too.)
    assert_eq!(net(&a).asked, [Kind::Report]);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("✓ nothing needs attention right now · r audits again"),
        "{s}"
    );
    // Nothing listed: only the screen's own keys.
    assert!(
        s.lines()
            .last()
            .unwrap()
            .starts_with(" r  audit   F  report"),
        "{s}"
    );
    // r audits whenever asked.
    key(&mut a, KeyCode::Char('r'));
    assert_eq!(net(&a).asked, [Kind::Report, Kind::Audit]);
    // Eight days old: the audit runs by itself, once.
    let mut a = blank_with(&cfg);
    key(&mut a, KeyCode::Char('6'));
    report_at(&mut a, Some("2026-10-18T11:00:00Z"));
    assert_eq!(net(&a).asked, [Kind::Report, Kind::Audit]);
    assert_eq!(a.toast_for_test(), Some("auditing the network…"));
    report_at(&mut a, Some("2026-10-18T11:00:00Z"));
    assert_eq!(
        net(&a).asked.iter().filter(|k| **k == Kind::Audit).count(),
        1,
        "not again for the same visit"
    );
    // Until it has run, the row says it's due.
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Audit the network") && s.contains("The last audit was 8 days ago."),
        "{s}"
    );
    // Never audited: the same; and it failing says so.
    let mut a = blank_with(&cfg);
    key(&mut a, KeyCode::Char('6'));
    report_at(&mut a, None);
    assert_eq!(net(&a).asked, [Kind::Report, Kind::Audit]);
    data(
        &mut a,
        Kind::Audit,
        Err(CollectError::Failed("no route".into())),
    );
    assert_eq!(a.toast_for_test(), Some("audit failed: no route"));
    // On the Dashboard an old report audits nothing; with none, the certificate is read.
    let mut a = blank_with(&cfg);
    a.start(Instant::now());
    report_at(&mut a, Some("2026-10-10T11:00:00Z"));
    assert_eq!(
        net(&a).asked,
        [
            Kind::Probe,
            Kind::Ifaces,
            Kind::Services,
            Kind::Report,
            Kind::Cert
        ]
    );
}

#[test]
fn tasks_by_hand_work_on_a_network() {
    let mut a = full();
    let (slot, _) = a.parts();
    slot.shared.tasks.push(sentry_core::maint::tasks::Task {
        id: "check-upnp".into(),
        title: "Check UPnP is off".into(),
        why: "Devices can open ports by themselves with it.".into(),
        level: sentry_core::maint::Level::Soon,
        every: None,
        act: "by-hand".into(),
        item: None,
        steps: "1. Open the web interface\n2. Services, UPnP: off".into(),
        added: None,
        review: None,
        after: None,
        again: None,
        off: false,
        source: Default::default(),
    });
    let s = screen(&mut a, '6', 158, 41);
    assert!(s.contains("Check UPnP is off"), "{s}");
    let bar = s.lines().last().unwrap();
    for k in [
        "Enter  its steps",
        "d  done",
        "e  every",
        "m  steps",
        "x  remove",
    ] {
        assert!(bar.contains(k), "{k} in {bar}");
    }
    // m (and Enter): its steps, and the box marks it done.
    key(&mut a, KeyCode::Char('m'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Open the web interface") && s.contains("mark done"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('n'));
    // Space: nothing of a network's can go in a series yet.
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(
        a.toast_for_test(),
        Some(sentry_core::tui::maintlist::NOT_IN_A_SERIES)
    );
    // z: put off; the row leaves the list.
    key(&mut a, KeyCode::Char('z'));
    key(&mut a, KeyCode::Char('1'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(!s.contains("Check UPnP is off"), "{s}");
    // v: Records, with the network's tasks.
    key(&mut a, KeyCode::Char('v'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Tasks") && s.contains("Later"), "{s}");
}

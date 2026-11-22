use super::*;

fn day() -> Date {
    jiff::civil::date(2026, 11, 21)
}

fn at() -> Timestamp {
    "2026-11-21T10:00:00Z".parse().unwrap()
}

// Values that must never reach an item, a report or a brief.
const SERVER_ADDR: &str = "192.0.2.93";
const WAN_ADDR: &str = "203.0.113.7";

fn forward(port: &str, to: &str) -> Forward {
    Forward {
        proto: "tcp".into(),
        port: port.into(),
        to_port: to.into(),
        dest: SERVER_ADDR.into(),
        zone: Some("dmz".into()),
    }
}

/// A router as one would hope to find it: one door, a DMZ kept apart, nothing weak.
fn net() -> TargetFacts {
    TargetFacts {
        backup: Some(Backup {
            count: Some(3),
            newest_days: Some(2),
            encrypted: Some(true),
            unsaved: Some(false),
            ..Default::default()
        }),
        watch: Some(Watch {
            enforces: Some(true),
            ..Default::default()
        }),
        router: Some(Router {
            wan_up: Some(true),
            wan_addr: Some(WAN_ADDR.into()),
            firmware: Some(Firmware {
                version: "25.12.3".into(),
                latest: Some("25.12.3".into()),
                newer: false,
                security: Some(false),
                eol: Eol::Supported,
            }),
            packages: Some(Packages {
                behind: 0,
                index_days: Some(1),
            }),
            forwards: Some(vec![forward("443", "8443")]),
            wan_input_accept: Some(false),
            wan_listeners: Some(vec![]),
            v6_inbound: Some(vec![]),
            ssh_password: Some(false),
            admin_http: Some(false),
            wifi: Some(vec![Wifi {
                label: "Wi-Fi 1".into(),
                encryption: "sae-mixed".into(),
                wps: false,
                guest: false,
            }]),
            zones: Some(vec![
                Zone {
                    name: "wan".into(),
                    wan: true,
                    input: "REJECT".into(),
                    ..Default::default()
                },
                Zone {
                    name: "lan".into(),
                    input: "ACCEPT".into(),
                    reaches: vec!["wan".into(), "dmz".into()],
                    devices: Some(9),
                    ..Default::default()
                },
                Zone {
                    name: "dmz".into(),
                    input: "REJECT".into(),
                    reaches: vec!["wan".into()],
                    devices: Some(1),
                    ..Default::default()
                },
                // The gadgets' own network: what keeps the home side from being flat.
                Zone {
                    name: "iot".into(),
                    input: "REJECT".into(),
                    reaches: vec!["wan".into()],
                    devices: Some(4),
                    ..Default::default()
                },
            ]),
            crossings: Some(vec![]),
            devices: Some(Devices {
                total: 10,
                unknown: 0,
            }),
            dns_filter: Some(DnsFilter {
                on: true,
                age_days: Some(1),
            }),
            log_kept: Some(true),
            outside: None,
        }),
        ..TargetFacts::new("net:home", Kind::Network, "home")
    }
}

/// A server as one would hope to find it, behind that door.
fn srv() -> TargetFacts {
    TargetFacts {
        addrs: vec![SERVER_ADDR.into()],
        os: Some(Os {
            name: "Debian GNU/Linux 13".into(),
            updates: Some(0),
            security: Some(0),
            auto_updates: Some(true),
            updated_days: Some(3),
            ..Default::default()
        }),
        listeners: Some(vec![
            Listen {
                proto: "tcp".into(),
                port: 8443,
                wide: true,
                process: Some("docker-proxy".into()),
            },
            Listen {
                proto: "tcp".into(),
                port: 22,
                wide: true,
                process: Some("sshd".into()),
            },
        ]),
        ssh: Some(Ssh {
            on: Some(true),
            password: Some(false),
            root: Some("no".into()),
            source: "sshd -T".into(),
        }),
        sudo_nopasswd: Some(false),
        containers: Some(vec![Ctr {
            name: "web".into(),
            image: "example/web:1.4".into(),
            ports: vec![8443],
            ..Default::default()
        }]),
        software: Some(vec![Software {
            id: "web".into(),
            running: Some("1.4".into()),
            latest: Some("1.4".into()),
            container: Some("web".into()),
            eol: Eol::Supported,
            ..Default::default()
        }]),
        watch: Some(Watch {
            crowdsec: Some(true),
            bouncers: Some(vec!["firewall".into()]),
            ..Default::default()
        }),
        backup: Some(Backup {
            signals: vec!["restic-backup.timer".into()],
            ..Default::default()
        }),
        ..TargetFacts::new("srv:myserver", Kind::Server, "myserver")
    }
}

fn answered() -> Answers {
    let mut a = Answers::default();
    a.set("door-login:net:home:tcp:443", true, day());
    a.set("restore-tested:net:home", true, day());
    a.set("restore-tested:srv:myserver", true, day());
    a
}

fn state(items: &[Item], id: &str) -> Option<State> {
    items.iter().find(|i| i.id == id).map(|i| i.state)
}

fn eval(net: TargetFacts, srv: TargetFacts, a: &Answers) -> Vec<Item> {
    evaluate(&[srv, net], a, day())
}

#[test]
fn a_system_in_good_order_is_all_fine_and_says_so() {
    let items = eval(net(), srv(), &answered());
    let open: Vec<&Item> = items.iter().filter(|i| i.state != State::Fine).collect();
    assert!(open.is_empty(), "{open:#?}");
    assert_eq!(
        state(&items, "sec:door:net:home:tcp:443"),
        Some(State::Fine)
    );
    assert_eq!(state(&items, "sec:watch"), Some(State::Fine));
    assert_eq!(state(&items, "sec:apart:net:home:dmz"), Some(State::Fine));
    let r = Report::build(&[srv(), net()], &answered(), None, at());
    let text = render(&r);
    assert!(text.contains("Do these first (0)\n  Nothing the audit can see needs doing first."));
    assert!(text.contains("\nFine ("));
    assert!(!text.contains("Worth doing"));
    for l in LIMITS {
        assert!(text.contains(l));
    }
    assert!(text.contains("(inferred from configuration, not observed from outside)"));
}

#[test]
fn what_only_the_user_knows_is_asked_and_remembered() {
    let items = eval(net(), srv(), &Answers::default());
    let door = items
        .iter()
        .find(|i| i.id == "sec:door:net:home:tcp:443")
        .unwrap();
    assert_eq!(door.state, State::Ask);
    assert_eq!(
        door.question.as_deref(),
        Some("door-login:net:home:tcp:443")
    );
    assert_eq!(door.targets, ["net:home", "srv:myserver"]);
    assert_eq!(state(&items, "sec:restore:srv:myserver"), Some(State::Ask));
    // "No" on the door: the first thing to do.
    let mut a = answered();
    a.set("door-login:net:home:tcp:443", false, day());
    let items = eval(net(), srv(), &a);
    assert_eq!(items[0].id, "sec:door:net:home:tcp:443");
    assert_eq!(items[0].state, State::DoFirst);
    assert!(
        items[0]
            .evidence
            .iter()
            .any(|e| e == "you answered no on 2026-11-21")
    );
    // No sign of a backup: asked; "no" is a recovery gap, last of the first.
    let mut s = srv();
    s.backup = Some(Backup::default());
    let items = eval(net(), s.clone(), &a);
    assert_eq!(state(&items, "sec:backup:srv:myserver"), Some(State::Ask));
    a.set("backup-exists:srv:myserver", false, day());
    let items = eval(net(), s, &a);
    let first: Vec<&str> = items
        .iter()
        .filter(|i| i.state == State::DoFirst)
        .map(|i| i.id.as_str())
        .collect();
    assert_eq!(
        first,
        ["sec:door:net:home:tcp:443", "sec:backup:srv:myserver"]
    );
}

/// Each rule: what's changed from the good system, the item, its state.
#[test]
fn each_rule_fires_on_its_evidence_only() {
    type Change = fn(&mut TargetFacts, &mut TargetFacts);
    let table: Vec<(&str, Change, &str, State)> = vec![
        (
            "an exposed app missing security fixes",
            |_, s| s.software.as_mut().unwrap()[0].security = true,
            "sec:door:net:home:tcp:443",
            State::DoFirst,
        ),
        (
            "an exposed app past its end of life",
            |_, s| s.software.as_mut().unwrap()[0].eol = Eol::Past(40),
            "sec:door:net:home:tcp:443",
            State::DoFirst,
        ),
        (
            "an exposed app merely behind",
            |_, s| s.software.as_mut().unwrap()[0].behind = true,
            "sec:door:net:home:tcp:443",
            State::Worth,
        ),
        (
            "a door nothing answers",
            |_, s| drop(s.listeners.as_mut().unwrap().remove(0)),
            "sec:door:net:home:tcp:443",
            State::Worth,
        ),
        (
            "a door to a server whose sockets weren't read",
            |_, s| s.listeners = None,
            "sec:door:net:home:tcp:443",
            State::CouldNotCheck,
        ),
        (
            "a door to a device sentry doesn't manage",
            |_, s| s.addrs.clear(),
            "sec:door:net:home:tcp:443",
            State::CouldNotCheck,
        ),
        (
            "ssh forwarded, passwords on",
            |n, s| {
                n.router
                    .as_mut()
                    .unwrap()
                    .forwards
                    .as_mut()
                    .unwrap()
                    .push(forward("2222", "22"));
                s.ssh.as_mut().unwrap().password = Some(true);
            },
            "sec:door:net:home:tcp:2222",
            State::DoFirst,
        ),
        (
            "ssh forwarded, keys only",
            |n, _| {
                n.router
                    .as_mut()
                    .unwrap()
                    .forwards
                    .as_mut()
                    .unwrap()
                    .push(forward("2222", "22"))
            },
            "sec:door:net:home:tcp:2222",
            State::Fine,
        ),
        (
            "ssh forwarded, settings unread",
            |n, s| {
                n.router
                    .as_mut()
                    .unwrap()
                    .forwards
                    .as_mut()
                    .unwrap()
                    .push(forward("2222", "22"));
                s.ssh = None;
            },
            "sec:door:net:home:tcp:2222",
            State::CouldNotCheck,
        ),
        (
            "the uplink accepts input",
            |n, _| n.router.as_mut().unwrap().wan_input_accept = Some(true),
            "sec:wan-input:net:home",
            State::DoFirst,
        ),
        (
            "the router's ssh on the uplink",
            |n, _| {
                n.router.as_mut().unwrap().wan_listeners = Some(vec![WanListen {
                    proto: "tcp".into(),
                    port: 22,
                    process: Some("dropbear".into()),
                }])
            },
            "sec:wan-mgmt:net:home:tcp:22",
            State::DoFirst,
        ),
        (
            "the router's sockets unread",
            |n, _| n.router.as_mut().unwrap().wan_listeners = None,
            "sec:wan-mgmt:net:home",
            State::CouldNotCheck,
        ),
        (
            "an IPv6 rule into the LAN",
            |n, _| n.router.as_mut().unwrap().v6_inbound = Some(vec!["tcp 8443 to lan".into()]),
            "sec:v6-inbound:net:home",
            State::Worth,
        ),
        (
            "firmware past its end of life",
            |n, _| n.router.as_mut().unwrap().firmware.as_mut().unwrap().eol = Eol::Past(10),
            "sec:firmware:net:home",
            State::DoFirst,
        ),
        (
            "firmware with security fixes out",
            |n, _| {
                let f = n.router.as_mut().unwrap().firmware.as_mut().unwrap();
                f.newer = true;
                f.security = Some(true);
            },
            "sec:firmware:net:home",
            State::DoFirst,
        ),
        (
            "firmware merely behind",
            |n, _| {
                let f = n.router.as_mut().unwrap().firmware.as_mut().unwrap();
                f.newer = true;
                f.security = None;
            },
            "sec:firmware:net:home",
            State::Worth,
        ),
        (
            "firmware not looked up",
            |n, _| {
                let f = n.router.as_mut().unwrap().firmware.as_mut().unwrap();
                f.latest = None;
                f.eol = Eol::Unknown;
            },
            "sec:firmware:net:home",
            State::CouldNotCheck,
        ),
        (
            "a stale package list",
            |n, _| {
                n.router
                    .as_mut()
                    .unwrap()
                    .packages
                    .as_mut()
                    .unwrap()
                    .index_days = Some(45)
            },
            "sec:packages:net:home",
            State::CouldNotCheck,
        ),
        (
            "packages behind",
            |n, _| n.router.as_mut().unwrap().packages.as_mut().unwrap().behind = 4,
            "sec:packages:net:home",
            State::Worth,
        ),
        (
            "router ssh takes passwords",
            |n, _| n.router.as_mut().unwrap().ssh_password = Some(true),
            "sec:ssh-password:net:home",
            State::Worth,
        ),
        (
            "admin page on plain HTTP",
            |n, _| n.router.as_mut().unwrap().admin_http = Some(true),
            "sec:admin-http:net:home",
            State::Worth,
        ),
        (
            "an open Wi-Fi",
            |n, _| n.router.as_mut().unwrap().wifi.as_mut().unwrap()[0].encryption = "none".into(),
            "sec:wifi:net:home:wi-fi-1",
            State::DoFirst,
        ),
        (
            "WPS on",
            |n, _| n.router.as_mut().unwrap().wifi.as_mut().unwrap()[0].wps = true,
            "sec:wps:net:home",
            State::Worth,
        ),
        (
            "one flat network",
            |n, _| {
                let r = n.router.as_mut().unwrap();
                r.zones.as_mut().unwrap().truncate(2);
                r.forwards.as_mut().unwrap()[0].zone = Some("lan".into());
            },
            "sec:flat:net:home",
            State::Worth,
        ),
        (
            // The server has its own side, and everything at home still shares one.
            "a home network with only the server's side apart",
            |n, _| {
                n.router.as_mut().unwrap().zones.as_mut().unwrap().pop();
            },
            "sec:flat:net:home",
            State::Worth,
        ),
        (
            "the router's bouncer installed and switched off",
            |n, _| {
                n.watch = Some(Watch {
                    enforces: Some(false),
                    installed_off: true,
                    ..Default::default()
                });
            },
            "sec:watch",
            State::Worth,
        ),
        (
            "the door's zone may open connections into the LAN",
            |n, _| {
                n.router.as_mut().unwrap().zones.as_mut().unwrap()[2]
                    .reaches
                    .push("lan".into())
            },
            "sec:apart:net:home:dmz",
            State::DoFirst,
        ),
        (
            "the door's zone reaches the router's logins",
            |n, _| n.router.as_mut().unwrap().zones.as_mut().unwrap()[2].input = "ACCEPT".into(),
            "sec:apart:net:home:dmz",
            State::Worth,
        ),
        (
            "live flows from the door's zone into the LAN",
            |n, _| {
                n.router.as_mut().unwrap().crossings = Some(vec![Crossing {
                    from: "dmz".into(),
                    to: "lan".into(),
                    flows: 2,
                }])
            },
            "sec:crossing:net:home:dmz:lan",
            State::DoFirst,
        ),
        (
            "devices nobody named",
            |n, _| n.router.as_mut().unwrap().devices.as_mut().unwrap().unknown = 2,
            "sec:unknown-devices:net:home",
            State::Worth,
        ),
        (
            "an old blocklist",
            |n, _| {
                n.router
                    .as_mut()
                    .unwrap()
                    .dns_filter
                    .as_mut()
                    .unwrap()
                    .age_days = Some(40)
            },
            "sec:dns-filter:net:home",
            State::Worth,
        ),
        (
            "a log kept in memory",
            |n, _| n.router.as_mut().unwrap().log_kept = Some(false),
            "sec:logs:net:home",
            State::Worth,
        ),
        (
            "no router backup",
            |n, _| n.backup.as_mut().unwrap().count = Some(0),
            "sec:backup:net:home",
            State::Worth,
        ),
        (
            "unsaved router changes",
            |n, _| n.backup.as_mut().unwrap().unsaved = Some(true),
            "sec:backup:net:home",
            State::Worth,
        ),
        (
            "security updates on the exposed server",
            |_, s| s.os.as_mut().unwrap().security = Some(3),
            "sec:os:srv:myserver",
            State::DoFirst,
        ),
        (
            "plain updates waiting",
            |_, s| s.os.as_mut().unwrap().updates = Some(5),
            "sec:os:srv:myserver",
            State::Worth,
        ),
        (
            "the system unread",
            |_, s| s.os = None,
            "sec:os:srv:myserver",
            State::CouldNotCheck,
        ),
        (
            "a restart pending",
            |_, s| s.os.as_mut().unwrap().reboot_pending = true,
            "sec:reboot:srv:myserver",
            State::Worth,
        ),
        (
            "no automatic security updates",
            |_, s| s.os.as_mut().unwrap().auto_updates = Some(false),
            "sec:auto-updates:srv:myserver",
            State::Worth,
        ),
        (
            "automatic updates unread",
            |_, s| s.os.as_mut().unwrap().auto_updates = None,
            "sec:auto-updates:srv:myserver",
            State::CouldNotCheck,
        ),
        (
            "an app not behind a door, past its end of life",
            |_, s| {
                s.software.as_mut().unwrap().push(Software {
                    id: "db".into(),
                    eol: Eol::Past(5),
                    ..Default::default()
                })
            },
            "sec:app:srv:myserver:db",
            State::Worth,
        ),
        (
            "an app not behind a door, behind",
            |_, s| {
                s.software.as_mut().unwrap().push(Software {
                    id: "db".into(),
                    behind: true,
                    ..Default::default()
                })
            },
            "sec:apps-behind:srv:myserver",
            State::Worth,
        ),
        (
            "ssh passwords on, not forwarded",
            |_, s| s.ssh.as_mut().unwrap().password = Some(true),
            "sec:ssh-password:srv:myserver",
            State::Worth,
        ),
        (
            "ssh settings unread",
            |_, s| s.ssh.as_mut().unwrap().password = None,
            "sec:ssh-password:srv:myserver",
            State::CouldNotCheck,
        ),
        (
            "root may log in",
            |_, s| s.ssh.as_mut().unwrap().root = Some("yes".into()),
            "sec:ssh-root:srv:myserver",
            State::Worth,
        ),
        (
            "sudo without a password",
            |_, s| s.sudo_nopasswd = Some(true),
            "sec:sudo:srv:myserver",
            State::Worth,
        ),
        (
            "the exposed container holds the Docker socket",
            |_, s| s.containers.as_mut().unwrap()[0].docker_sock = true,
            "sec:ctr:srv:myserver:web",
            State::DoFirst,
        ),
        (
            "another container is privileged",
            |_, s| {
                s.containers.as_mut().unwrap().push(Ctr {
                    name: "tool".into(),
                    privileged: true,
                    ..Default::default()
                })
            },
            "sec:ctr:srv:myserver:tool",
            State::Worth,
        ),
        (
            "containers unread",
            |_, s| s.containers = None,
            "sec:ctrs:srv:myserver",
            State::CouldNotCheck,
        ),
        (
            "more listening widely than the doors need",
            |_, s| {
                s.listeners.as_mut().unwrap().push(Listen {
                    proto: "tcp".into(),
                    port: 5432,
                    wide: true,
                    process: Some("postgres".into()),
                })
            },
            "sec:listen-wide:srv:myserver",
            State::Worth,
        ),
        (
            "bans enforced on the server only",
            |n, _| {
                n.watch = Some(Watch {
                    enforces: Some(false),
                    ..Default::default()
                })
            },
            "sec:watch",
            State::Worth,
        ),
        (
            "nothing watches the doors",
            |n, s| {
                n.watch = Some(Watch::default());
                s.watch = Some(Watch::default());
            },
            "sec:watch",
            State::Worth,
        ),
        (
            "CrowdSec runs, its bouncers unread",
            |n, s| {
                n.watch = Some(Watch {
                    enforces: Some(false),
                    ..Default::default()
                });
                s.watch.as_mut().unwrap().bouncers = None;
            },
            "sec:watch",
            State::CouldNotCheck,
        ),
        (
            "the watcher unread",
            |_, s| s.watch = None,
            "sec:watch",
            State::CouldNotCheck,
        ),
    ];
    let good = eval(net(), srv(), &answered());
    for (what, change, id, want) in table {
        let (mut n, mut s) = (net(), srv());
        change(&mut n, &mut s);
        let items = eval(n, s, &answered());
        assert_eq!(state(&items, id), Some(want), "{what}: {id}");
        // And not without the change (the good system has it fine, or not at all).
        assert!(
            matches!(state(&good, id), None | Some(State::Fine)),
            "{what}: {id} fires without its evidence"
        );
        // Every open item says why and what it takes, in a sentence.
        let i = items.iter().find(|i| i.id == id).unwrap();
        assert!(
            !i.title.is_empty() && (want == State::Fine || !i.fix.is_empty()),
            "{what}"
        );
        assert!(i.brief.contains(&i.title));
    }
}

/// The home side is one network only when more than a handful share it and nothing else is
/// there to put gadgets on: a few devices, or a guest Wi-Fi, and it isn't said. What it
/// says names no device and guesses no kind.
#[test]
fn a_flat_home_network_is_said_only_on_evidence() {
    let flat = |devices: Option<usize>, guest: bool| {
        let mut n = net();
        let r = n.router.as_mut().unwrap();
        r.zones.as_mut().unwrap().pop();
        r.zones.as_mut().unwrap()[1].devices = devices;
        r.wifi.as_mut().unwrap()[0].guest = guest;
        let items = eval(n, srv(), &answered());
        items
            .into_iter()
            .find(|i| i.id == "sec:flat:net:home")
            .unwrap()
    };
    let i = flat(Some(9), false);
    assert_eq!(i.state, State::Worth);
    assert!(
        i.title
            .starts_with("Every device at home shares one network")
    );
    assert_eq!(
        i.evidence,
        [
            "9 devices on lan",
            "only the server's side is separate (dmz)",
            "no guest or gadgets network"
        ]
    );
    assert!(i.fix.contains("separate network for gadgets"));
    // A handful, an unknown count, or a guest network: not said.
    assert_eq!(flat(Some(5), false).state, State::Fine);
    assert_eq!(flat(None, false).state, State::Fine);
    assert_eq!(flat(Some(9), true).state, State::Fine);

    // The router's bouncer installed and off: one sentence, and what a session is told
    // is the whole job across both.
    let mut n = net();
    n.watch = Some(Watch {
        enforces: Some(false),
        installed_off: true,
        ..Default::default()
    });
    let items = eval(n, srv(), &answered());
    let w = items.iter().find(|i| i.id == "sec:watch").unwrap();
    assert!(
        w.title.starts_with(
            "CrowdSec's blocker is installed on the router but not switched on: the blocklist of"
        ) && w.title.ends_with("isn't enforced at the edge yet"),
        "{}",
        w.title
    );
    assert!(w.targets.len() == 2 && w.brief.contains("captured as a secret"));

    // What needs root on a server is asked for in sentry's own terms, never a command.
    let mut s = srv();
    s.watch.as_mut().unwrap().bouncers = None;
    s.needs_inventory = true;
    let mut n = net();
    n.watch = Some(Watch {
        enforces: Some(false),
        ..Default::default()
    });
    let items = eval(n, s, &answered());
    let w = items.iter().find(|i| i.id == "sec:watch").unwrap();
    assert_eq!(w.state, State::CouldNotCheck);
    assert!(
        w.fix.starts_with("Open the server target and press I once"),
        "{}",
        w.fix
    );
    for i in &items {
        assert!(
            !i.fix.contains("sudo sshd") && !i.fix.contains("yourself"),
            "{}: {}",
            i.id,
            i.fix
        );
    }
}

#[test]
fn this_machine_has_its_own_rules() {
    let mut l = TargetFacts {
        os: Some(Os {
            name: "Fedora Silverblue 44".into(),
            updated_days: Some(60),
            ..Default::default()
        }),
        ssh: Some(Ssh {
            on: Some(false),
            ..Default::default()
        }),
        firewall: Some(HostFw {
            active: false,
            zone: None,
        }),
        keys: Some(Keys { total: 2, loose: 1 }),
        backup: Some(Backup::default()),
        ..TargetFacts::new(LOCAL, Kind::Local, "this machine")
    };
    let items = evaluate(std::slice::from_ref(&l), &Answers::default(), day());
    assert_eq!(state(&items, "sec:os:local"), Some(State::Worth));
    assert_eq!(state(&items, "sec:ssh-password:local"), Some(State::Fine));
    assert_eq!(state(&items, "sec:firewall:local"), Some(State::Worth));
    assert_eq!(state(&items, "sec:keys:local"), Some(State::Worth));
    assert_eq!(state(&items, "sec:backup:local"), Some(State::Ask));
    // No server-only "couldn't check" for a workstation, and no watcher without a door.
    assert_eq!(state(&items, "sec:auto-updates:local"), None);
    assert_eq!(state(&items, "sec:ctrs:local"), None);
    assert_eq!(state(&items, "sec:watch"), None);
    l.os.as_mut().unwrap().updated_days = Some(5);
    l.firewall.as_mut().unwrap().active = true;
    l.keys = Some(Keys { total: 2, loose: 0 });
    let items = evaluate(&[l], &Answers::default(), day());
    for id in ["sec:os:local", "sec:firewall:local", "sec:keys:local"] {
        assert_eq!(state(&items, id), Some(State::Fine), "{id}");
    }
}

#[test]
fn a_target_that_didnt_answer_is_said_and_the_rest_still_stands() {
    let gone = TargetFacts::unreachable("srv:myserver", Kind::Server, "myserver", "timed out");
    let r = Report::build(&[gone, net()], &answered(), None, at());
    assert_eq!(
        state(&r.items, "sec:reach:srv:myserver"),
        Some(State::CouldNotCheck)
    );
    // Its door leads to something sentry can't see now.
    assert_eq!(
        state(&r.items, "sec:door:net:home:tcp:443"),
        Some(State::CouldNotCheck)
    );
    assert_eq!(state(&r.items, "sec:firmware:net:home"), Some(State::Fine));
    assert!(!r.empty());
    assert!(render(&r).contains("myserver (not reached)"));
    let none = Report::build(
        &[TargetFacts::unreachable(
            LOCAL,
            Kind::Local,
            "this machine",
            "x",
        )],
        &Answers::default(),
        None,
        at(),
    );
    assert!(none.empty());
}

#[test]
fn do_first_is_ranked_by_what_an_attacker_reaches_first() {
    let (mut n, mut s) = (net(), srv());
    let r = n.router.as_mut().unwrap();
    r.firmware.as_mut().unwrap().eol = Eol::Past(3);
    r.zones.as_mut().unwrap()[2].reaches.push("lan".into());
    r.wifi.as_mut().unwrap()[0].encryption = "none".into();
    s.software.as_mut().unwrap()[0].security = true;
    let mut a = answered();
    s.backup = Some(Backup::default());
    a.set("backup-exists:srv:myserver", false, day());
    let items = eval(n, s, &a);
    let first: Vec<(&str, u8)> = items
        .iter()
        .filter(|i| i.state == State::DoFirst)
        .map(|i| (i.id.as_str(), i.rank))
        .collect();
    assert_eq!(
        first,
        [
            ("sec:door:net:home:tcp:443", rank::EXPOSED),
            ("sec:wifi:net:home:wi-fi-1", rank::WEAK_LOGIN),
            ("sec:firmware:net:home", rank::OUTDATED),
            ("sec:apart:net:home:dmz", rank::FLAT),
            ("sec:backup:srv:myserver", rank::RECOVERY),
        ]
    );
}

#[test]
fn the_outside_check_confirms_or_contradicts_the_configuration() {
    let with = |open: Vec<u16>, error: Option<&str>| {
        let mut n = net();
        n.router.as_mut().unwrap().outside = Some(Outside {
            asked: vec![22, 80, 443],
            open,
            error: error.map(str::to_string),
        });
        Report::build(&[srv(), n], &answered(), None, at())
    };
    let r = with(vec![443], None);
    assert!(r.observed);
    assert_eq!(state(&r.items, "sec:outside:net:home"), Some(State::Fine));
    assert!(!render(&r).contains("not observed from outside"));
    let r = with(vec![22, 443], None);
    assert_eq!(
        state(&r.items, "sec:outside:net:home:tcp:22"),
        Some(State::DoFirst)
    );
    assert_eq!(state(&r.items, "sec:outside:net:home"), None);
    let r = with(vec![], Some("ssh: no route"));
    assert!(!r.observed);
    assert_eq!(
        state(&r.items, "sec:outside:net:home"),
        Some(State::CouldNotCheck)
    );

    // The line: only an address and numbers go in.
    assert_eq!(
        outside_line("check {address} {ports}", "203.0.113.7", &[22, 443]).unwrap(),
        "check 203.0.113.7 22,443"
    );
    assert!(outside_line("check {address}", "203.0.113.7; rm -rf ~", &[22]).is_err());
    assert!(outside_line("check {ports}", "203.0.113.7", &[22]).is_err());
    // The answer: only ports that were asked for.
    assert_eq!(
        outside_parse("443\n22/tcp open\nhello\n9999\n443\n", &[22, 443]),
        [22, 443]
    );
    // What's asked: the management ports and the forwarded TCP ports, nothing else.
    let n = net();
    let o = outside(
        "true {address} {ports}",
        &Router {
            wan_addr: None,
            ..n.router.unwrap()
        },
    );
    assert!(o.error.is_some());
    assert_eq!(o.asked, MGMT_PORTS);
}

#[test]
fn two_reports_are_compared_by_id() {
    let i = |id: &str, state: State| Item {
        id: id.into(),
        group: Group::Logins,
        state,
        rank: 0,
        title: id.into(),
        why: String::new(),
        fix: String::new(),
        targets: vec![],
        evidence: vec![],
        brief: String::new(),
        question: None,
    };
    use State::*;
    let table: Vec<(Option<State>, Option<State>, &str)> = vec![
        (None, Some(DoFirst), "new"),
        (None, Some(Ask), "new"),
        (None, Some(Fine), "same"),
        (Some(Fine), Some(Worth), "new"),
        (Some(Worth), Some(Fine), "fixed"),
        (Some(DoFirst), None, "fixed"),
        (Some(Worth), Some(DoFirst), "worse"),
        (Some(CouldNotCheck), Some(Worth), "worse"),
        (Some(DoFirst), Some(Worth), "better"),
        (Some(Worth), Some(Ask), "better"),
        (Some(Worth), Some(Worth), "same"),
        (Some(Ask), Some(CouldNotCheck), "same"),
        (Some(Ask), Some(Fine), "better"),
        (Some(Fine), None, "gone"),
    ];
    for (was, is, want) in table {
        let prev: Vec<Item> = was.iter().map(|s| i("x", *s)).collect();
        let now: Vec<Item> = is.iter().map(|s| i("x", *s)).collect();
        let d = diff(&prev, &now);
        let got = if !d.new.is_empty() {
            "new"
        } else if !d.fixed.is_empty() {
            "fixed"
        } else if !d.worse.is_empty() {
            "worse"
        } else if !d.better.is_empty() {
            "better"
        } else if d.same == 1 {
            "same"
        } else {
            "gone"
        };
        assert_eq!(got, want, "{was:?} → {is:?}");
    }
}

#[test]
fn reports_are_kept_by_stamp_and_the_newest_is_the_latest() {
    let d = std::env::temp_dir().join(format!("sentry-secaudit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    assert!(latest_in(&d).is_none());
    let first = Report::build(&[srv(), net()], &Answers::default(), None, at());
    assert!(first.diff.first);
    let p = save_in(&d, &first).unwrap();
    assert_eq!(p.file_name().unwrap(), "20261121T100000Z.toml");
    assert_eq!(latest_in(&d).unwrap(), first);
    // A later one, compared with it: answering the questions made things better.
    let later: Timestamp = "2026-11-22T10:00:00Z".parse().unwrap();
    let second = Report::build(&[srv(), net()], &answered(), Some(&first), later);
    assert!(!second.diff.first);
    assert_eq!(second.diff.better.len(), 3, "{:?}", second.diff);
    assert!(second.diff.new.is_empty() && second.diff.worse.is_empty());
    save_in(&d, &second).unwrap();
    assert_eq!(latest_in(&d).unwrap().at, later);
    assert!(render(&second).contains("Since the last audit: 0 new, 0 fixed, 0 worse, 3 better"));
    // Only the newest KEEP stay; answers.toml beside them is never taken for a report.
    std::fs::write(d.join("answers.toml"), "").unwrap();
    for n in 0..KEEP + 3 {
        let at = later + jiff::SignedDuration::from_hours(1 + n as i64);
        save_in(
            &d,
            &Report {
                at,
                ..second.clone()
            },
        )
        .unwrap();
    }
    assert_eq!(reports_in(&d).len(), KEEP);
    assert!(d.join("answers.toml").exists());
    assert!(!p.exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn answers_are_remembered_with_their_date() {
    let mut a = Answers::default();
    a.set("restore-tested:net:home", false, day());
    let text = toml::to_string(&a).unwrap();
    assert!(
        text.contains("[answers.\"restore-tested:net:home\"]"),
        "{text}"
    );
    assert!(
        text.contains("at = \"2026-11-21\"") || text.contains("at = 2026-11-21"),
        "{text}"
    );
    let back: Answers = toml::from_str(&text).unwrap();
    assert_eq!(back, a);
    assert_eq!(back.get("restore-tested:net:home"), Some(false));
    assert_eq!(back.get("other"), None);
}

/// Addresses are match-only: none reaches an item, the saved report, the rendering, the
/// brief for Claude, or the facts as they'd be serialized.
#[test]
fn private_values_never_leave_the_facts() {
    let (mut n, mut s) = (net(), srv());
    // The worst case: everything fires, so every evidence line is written.
    let r = n.router.as_mut().unwrap();
    r.wan_listeners = Some(vec![WanListen {
        proto: "tcp".into(),
        port: 22,
        process: Some("dropbear".into()),
    }]);
    r.outside = Some(Outside {
        asked: vec![22, 443],
        open: vec![22, 443],
        error: None,
    });
    r.crossings = Some(vec![Crossing {
        from: "dmz".into(),
        to: "lan".into(),
        flows: 1,
    }]);
    s.software.as_mut().unwrap()[0].security = true;
    s.containers.as_mut().unwrap()[0].privileged = true;
    let facts = [s, n];
    let rep = Report::build(&facts, &Answers::default(), None, at());
    let all = [
        toml::to_string(&rep).unwrap(),
        render(&rep),
        review_brief(&rep),
        serde_json::to_string(&facts).unwrap(),
        rep.items.iter().map(|i| format!("{:?}", i.ask())).collect(),
    ];
    for text in &all {
        for canary in [SERVER_ADDR, WAN_ADDR] {
            assert!(!text.contains(canary), "{canary} in:\n{text}");
        }
    }
    // The brief holds the evidence and the rules for reading it.
    let brief = &all[2];
    assert!(brief.contains("Never invent a finding the evidence below doesn't hold"));
    assert!(brief.contains("Look up security advisories for the exact software versions"));
    assert!(brief.contains("[do first] web on myserver is open to the internet (tcp port 443)"));
    assert!(brief.contains("web: running 1.4"));
    assert!(!brief.contains("sentry-changes"));
}

#[test]
fn an_item_becomes_a_session_ask() {
    let (n, mut s) = (net(), srv());
    s.sudo_nopasswd = Some(true);
    let items = eval(n, s, &answered());
    let i = items
        .iter()
        .find(|i| i.id == "sec:sudo:srv:myserver")
        .unwrap();
    let ask = i.ask();
    assert!(
        ask.subject
            .starts_with("Security · On myserver, your login")
    );
    assert!(
        ask.question
            .contains("What it takes: Make sudo ask for a password")
    );
    assert!(ask.context.contains("About: srv:myserver"));
    let Some(claude::Target::Apply(a)) = ask.target else {
        panic!("no target")
    };
    assert_eq!(a.key, "sec:sudo:srv:myserver");
    assert!(a.remote);
}

#[test]
fn the_task_is_due_every_30_days_and_after_an_upgrade() {
    let t = task(None, &[]);
    assert_eq!(t.id, TASK_ID);
    assert_eq!(t.every.map(|d| d.0.as_secs()), Some(30 * 86_400));
    assert!(t.again.is_none());
    let run = |workflow: &str, kind: &str, result: &str, ended: &str| {
        let mut e = LogEntry::task("", "x", "x", None);
        e.head.workflow = workflow.into();
        e.head.kind = kind.into();
        e.head.result = result.into();
        e.head.ended = Some(ended.parse().unwrap());
        e
    };
    let last: Timestamp = "2026-11-01T00:00:00Z".parse().unwrap();
    let logs = [
        run("quick-update", "system", "done", "2026-11-10T00:00:00Z"),
        run(
            "firmware-upgrade",
            "system",
            "abandoned",
            "2026-11-11T00:00:00Z",
        ),
        run("firmware-upgrade", "system", "done", "2026-10-11T00:00:00Z"),
    ];
    assert!(task(Some(last), &logs).again.is_none());
    let logs = [run(
        "firmware-upgrade",
        "system",
        "done",
        "2026-11-12T00:00:00Z",
    )];
    let again = task(Some(last), &logs).again.unwrap();
    assert_eq!(
        again.why,
        "firmware-upgrade ran since the last security audit"
    );
    // Never audited: the task is simply due, nothing to be "again" about.
    assert!(task(None, &logs).again.is_none());
    assert!(
        done_entry("3 to do first")
            .head
            .tags
            .contains(&format!("task:{TASK_ID}"))
    );
}

#[test]
fn names_that_look_like_a_backup_and_addresses_that_are_the_machines_own() {
    for (name, is) in [
        ("restic-backup.timer", true),
        ("borgmatic.service", true),
        ("org.gnome.World.PikaBackup", true),
        ("dpkg-db-backup.timer", false),
        ("nginx.service", false),
    ] {
        assert_eq!(backup_signal(name), is, "{name}");
    }
    for a in ["127.0.0.53%lo", "[::1]", "127.0.0.1"] {
        assert!(loopback(a), "{a}");
    }
    for a in ["0.0.0.0", "*", "[::]", "192.0.2.93", ""] {
        assert!(!loopback(a), "{a}");
    }
}

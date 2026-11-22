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
        probe: None,
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
            family: None,
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
            life: Some(Life {
                release: "Debian 13".into(),
                ends: Some(jiff::civil::date(2030, 6, 30)),
                error: None,
            }),
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
        logs: Some(Logs {
            kept: Some(true),
            days: Some(90),
            limit: None,
        }),
        ..TargetFacts::new("srv:myserver", Kind::Server, "myserver")
    }
}

/// The good router, with what its one door said when this machine asked.
fn door_said(n: &mut TargetFacts, web: Web, tls: Option<(Option<i64>, Issuer)>) {
    n.router.as_mut().unwrap().forwards.as_mut().unwrap()[0].probe = Some(Answered {
        web,
        tls: tls.map(|(days_left, issuer)| Tls { days_left, issuer }),
    });
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
    assert!(text.contains("(read from the router's settings, not seen from outside)"));
    assert!(text.contains("sentry only looks while it is open"));
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
            "a family filter on two devices",
            |n, _| {
                n.router.as_mut().unwrap().family = Some(Family {
                    devices: 2,
                    trouble: None,
                })
            },
            "sec:family:net:home",
            State::Fine,
        ),
        (
            "a family filter with forced lookups in front of it",
            |n, _| {
                n.router.as_mut().unwrap().family = Some(Family {
                    devices: 2,
                    trouble: Some(FamilyTrouble::Forced),
                })
            },
            "sec:family-forced:net:home",
            State::DoFirst,
        ),
        (
            "a family filter whose browser names aren't refused",
            |n, _| {
                n.router.as_mut().unwrap().family = Some(Family {
                    devices: 1,
                    trouble: Some(FamilyTrouble::Canaries),
                })
            },
            "sec:family-canaries:net:home",
            State::DoFirst,
        ),
        (
            "a family filter with nobody's lookups forced",
            |n, _| {
                n.router.as_mut().unwrap().family = Some(Family {
                    devices: 1,
                    trouble: Some(FamilyTrouble::Unforced),
                })
            },
            "sec:family-unforced:net:home",
            State::DoFirst,
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
        (
            "an exposed server past its system's end of support",
            |_, s| {
                s.os.as_mut().unwrap().life.as_mut().unwrap().ends =
                    Some(jiff::civil::date(2026, 6, 30))
            },
            "sec:os-life:srv:myserver",
            State::DoFirst,
        ),
        (
            "a server's system near its end of support",
            |_, s| {
                s.os.as_mut().unwrap().life.as_mut().unwrap().ends =
                    Some(jiff::civil::date(2027, 3, 1))
            },
            "sec:os-life:srv:myserver",
            State::Worth,
        ),
        (
            "a system's end of support not looked up",
            |_, s| {
                s.os.as_mut().unwrap().life = Some(Life {
                    error: Some("endoflife.date didn't answer".into()),
                    ..Default::default()
                })
            },
            "sec:os-life:srv:myserver",
            State::CouldNotCheck,
        ),
        (
            "tracked apps whose newest version wasn't looked up",
            |_, s| s.software.as_mut().unwrap()[0].latest = None,
            "sec:apps-behind:srv:myserver",
            State::CouldNotCheck,
        ),
        (
            "a server that forgets its log",
            |_, s| s.logs.as_mut().unwrap().kept = Some(false),
            "sec:logs:srv:myserver",
            State::Worth,
        ),
        (
            "a server's log that goes back days only",
            |_, s| s.logs.as_mut().unwrap().days = Some(4),
            "sec:logs:srv:myserver",
            State::Worth,
        ),
        (
            "a server's log unread",
            |_, s| s.logs = None,
            "sec:logs:srv:myserver",
            State::CouldNotCheck,
        ),
        (
            "a door's certificate expired",
            |n, _| {
                door_said(
                    n,
                    Web::Login("401".into()),
                    Some((Some(-1), Issuer::Public)),
                )
            },
            "sec:cert:net:home:tcp:443",
            State::DoFirst,
        ),
        (
            "a door's certificate about to expire",
            |n, _| door_said(n, Web::Login("401".into()), Some((Some(5), Issuer::Public))),
            "sec:cert:net:home:tcp:443",
            State::Worth,
        ),
        (
            "a door's certificate self-signed",
            |n, _| {
                door_said(
                    n,
                    Web::Login("401".into()),
                    Some((Some(300), Issuer::SelfSigned)),
                )
            },
            "sec:cert:net:home:tcp:443",
            State::Worth,
        ),
        (
            "a door's certificate from a private authority",
            |n, _| {
                door_said(
                    n,
                    Web::Login("401".into()),
                    Some((Some(300), Issuer::Private)),
                )
            },
            "sec:cert:net:home:tcp:443",
            State::Worth,
        ),
        (
            "a door's certificate public and current",
            |n, _| {
                door_said(
                    n,
                    Web::Login("401".into()),
                    Some((Some(60), Issuer::Public)),
                )
            },
            "sec:cert:net:home:tcp:443",
            State::Fine,
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
    assert!(
        i.fix
            .contains("this router has Wi-Fi, so it can run that network itself")
    );
    // What is known of the devices without guessing their kind.
    let mut n = net();
    let r = n.router.as_mut().unwrap();
    r.zones.as_mut().unwrap().pop();
    let z = &mut r.zones.as_mut().unwrap()[1];
    (z.named, z.wifi, z.wired) = (Some(6), Some(5), Some(3));
    let items = eval(n, srv(), &answered());
    let i = items.iter().find(|i| i.id == "sec:flat:net:home").unwrap();
    assert_eq!(
        i.evidence[..3],
        [
            "9 devices on lan",
            "6 of them named in sentry, 3 not",
            "3 on a cable, 5 on Wi-Fi"
        ]
    );
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
    // (The sentence the network's Security page and its finding say too.)
    assert_eq!(w.title, edge_off(true));
    assert_eq!(
        w.title,
        "CrowdSec is installed on the router but switched off: attackers the server banned \
         aren't turned away there"
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
    // What a door said when this machine asked, and the certificate it showed.
    r.forwards.as_mut().unwrap()[0].probe = Some(Answered {
        web: Web::Open,
        tls: Some(Tls {
            days_left: Some(-2),
            issuer: Issuer::SelfSigned,
        }),
    });
    s.software.as_mut().unwrap()[0].security = true;
    s.containers.as_mut().unwrap()[0].privileged = true;
    s.inventory_hours = Some(80);
    s.logs = Some(Logs {
        kept: Some(true),
        days: Some(3),
        limit: Some("MaxRetentionSec=3day".into()),
    });
    s.os.as_mut().unwrap().life = Some(Life {
        release: "Debian 11".into(),
        ends: Some(jiff::civil::date(2026, 8, 31)),
        error: None,
    });
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
    assert!(
        brief.contains("[do first] web 1.4 on myserver is open to the internet (tcp port 443)"),
        "{brief}"
    );
    assert!(brief.contains("[do first] The certificate the internet sees on port 443 has expired"));
    assert!(brief.contains("asked once from this machine, without a login: it shows a page"));
    assert!(
        brief.contains("[do first] myserver's system (Debian 11) no longer gets security fixes")
    );
    assert!(brief.contains("myserver's system log goes back only 3 days"));
    assert!(brief.contains("read 3 days ago: it may be out of date"));
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
    let t = task(None, &[], None);
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
    assert!(task(Some(last), &logs, None).again.is_none());
    let logs = [run(
        "firmware-upgrade",
        "system",
        "done",
        "2026-11-12T00:00:00Z",
    )];
    let again = task(Some(last), &logs, None).again.unwrap();
    assert_eq!(
        again.why,
        "firmware-upgrade ran since the last security audit"
    );
    // Never audited: the task is simply due, nothing to be "again" about.
    assert!(task(None, &logs, None).again.is_none());
    // An upgrade logged under any other target counts as this machine's own does: the
    // newest one after the audit says why, with where it ran.
    let at = |s: &str| -> Timestamp { s.parse().unwrap() };
    let elsewhere = (
        at("2026-11-14T00:00:00Z"),
        "firmware-upgrade ran on home".to_string(),
    );
    let again = task(Some(last), &[], Some(&elsewhere)).again.unwrap();
    assert_eq!(
        (again.at, again.why.as_str()),
        (
            elsewhere.0,
            "firmware-upgrade ran on home since the last security audit"
        )
    );
    assert_eq!(
        task(Some(last), &logs, Some(&elsewhere)).again.unwrap().at,
        elsewhere.0
    );
    let before = (at("2026-10-30T00:00:00Z"), "release ran on myserver".into());
    assert!(task(Some(last), &[], Some(&before)).again.is_none());
    assert!(task(None, &[], Some(&elsewhere)).again.is_none());
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

/// What answered behind the door decides whether it is asked: a login seen needs no
/// question, a page open to all is asked as one ("is that on purpose?"), and nothing
/// learned leaves the old question. An answer given before still counts.
#[test]
fn what_answers_behind_a_door_decides_the_question() {
    let door = |web: Option<Web>, a: &Answers, s: TargetFacts| {
        let mut n = net();
        if let Some(w) = web {
            door_said(&mut n, w, None);
        }
        eval(n, s, a)
            .into_iter()
            .find(|i| i.id == "sec:door:net:home:tcp:443")
            .unwrap()
    };
    let none = Answers::default();
    let i = door(Some(Web::Login("401".into())), &none, srv());
    assert_eq!((i.state, i.question.as_deref()), (State::Fine, None));
    assert_eq!(
        i.title,
        "web 1.4 on myserver is open to the internet (tcp port 443) and asks for a login \
         first; it is up to date"
    );
    assert!(
        i.evidence.iter().any(
            |e| e == "asked once from this machine, without a login: it asks for a login (401)"
        ),
        "{:?}",
        i.evidence
    );
    let mut s = srv();
    s.software.as_mut().unwrap()[0].behind = true;
    assert_eq!(door(Some(Web::LoginPage), &none, s).state, State::Worth);
    let i = door(Some(Web::Open), &none, srv());
    assert_eq!(i.state, State::Ask);
    assert!(
        i.title
            .contains("without asking for a login. Is that on purpose"),
        "{}",
        i.title
    );
    let i = door(Some(Web::NotWeb), &none, srv());
    assert_eq!(i.state, State::Ask);
    assert!(i.title.contains("Is everything it serves meant for anyone"));
    assert_eq!(door(None, &none, srv()).state, State::Ask);
    // "No" stands whatever the page said.
    let mut no = Answers::default();
    no.set("door-login:net:home:tcp:443", false, day());
    assert_eq!(
        door(Some(Web::Login("403".into())), &no, srv()).state,
        State::DoFirst
    );

    // What runs there: from the inventory, said with its age; without it, how to get it.
    let mut s = srv();
    s.inventory_hours = Some(5);
    let i = door(None, &none, s);
    assert!(
        i.evidence
            .iter()
            .any(|e| e == "what runs there is from the server's inventory, read 5 hours ago"),
        "{:?}",
        i.evidence
    );
    assert!(
        i.evidence
            .iter()
            .any(|e| e == "the container web runs the image example/web:1.4")
    );
    let mut s = srv();
    s.containers = None;
    s.listeners.as_mut().unwrap()[0].process = None;
    let i = door(None, &none, s);
    assert!(
        i.title.starts_with("myserver is open to the internet"),
        "{}",
        i.title
    );
    assert!(
        i.evidence
            .iter()
            .any(|e| e.contains("open the server target and press I")),
        "{:?}",
        i.evidence
    );
    // A container sentry doesn't follow is said so.
    let mut s = srv();
    s.software = Some(vec![]);
    let i = door(None, &none, s);
    assert!(i.title.starts_with("web on myserver"), "{}", i.title);
    assert!(
        i.evidence
            .iter()
            .any(|e| e.starts_with("sentry doesn't follow this app's updates"))
    );

    // Which doors are asked: TCP to one of sentry's own machines, never its ssh, never
    // a device it doesn't manage, never a range.
    let mut n = net();
    let r = n.router.as_mut().unwrap();
    let fw = r.forwards.as_mut().unwrap();
    fw.push(forward("2222", "22"));
    fw.push(Forward {
        proto: "udp".into(),
        ..forward("443", "8443")
    });
    fw.push(Forward {
        dest: "198.51.100.9".into(),
        ..forward("8080", "8080")
    });
    fw.push(forward("9000-9010", "9000-9010"));
    let mut facts = vec![srv(), n];
    assert_eq!(
        doors_to_ask(&facts),
        [(1, 0, SERVER_ADDR.to_string(), 8443)]
    );
    probe_doors_with(&mut facts, |addr, port| {
        assert_eq!((addr, port), (SERVER_ADDR, 8443));
        Some(Answered {
            web: Web::Open,
            tls: None,
        })
    });
    let fw = facts[1].router.as_ref().unwrap().forwards.as_ref().unwrap();
    assert_eq!(fw[0].probe.as_ref().unwrap().web, Web::Open);
    assert!(fw[1..].iter().all(|f| f.probe.is_none()));
}

/// This machine weighs least: past its end of support is worth doing, not first; near it
/// only in the last two months. Its waiting updates are said in a few words.
#[test]
fn this_machines_end_of_support_and_updates() {
    let l = |ends: (i16, i8, i8), detail: Vec<String>| {
        let t = TargetFacts {
            os: Some(Os {
                name: "Fedora Linux 44".into(),
                updates: Some(3),
                updated_days: Some(9),
                detail,
                life: Some(Life {
                    release: "Fedora 44".into(),
                    ends: Some(jiff::civil::date(ends.0, ends.1, ends.2)),
                    error: None,
                }),
                ..Default::default()
            }),
            ..TargetFacts::new(LOCAL, Kind::Local, "this machine")
        };
        evaluate(&[t], &Answers::default(), day())
    };
    let items = l((2026, 11, 1), vec![]);
    let i = items.iter().find(|i| i.id == "sec:os-life:local").unwrap();
    assert_eq!(i.state, State::Worth);
    assert!(
        i.title
            .starts_with("This machine's system (Fedora 44) no longer gets"),
        "{}",
        i.title
    );
    assert_eq!(
        state(&l((2027, 1, 10), vec![]), "sec:os-life:local"),
        Some(State::Worth)
    );
    assert_eq!(
        state(&l((2027, 6, 2), vec![]), "sec:os-life:local"),
        Some(State::Fine)
    );
    let items = l(
        (2027, 6, 2),
        vec!["2 app updates".into(), "1 system update".into()],
    );
    let os = items.iter().find(|i| i.id == "sec:os:local").unwrap();
    assert_eq!(os.state, State::Worth);
    assert!(
        os.evidence.contains(&"2 app updates".to_string()),
        "{:?}",
        os.evidence
    );
    assert!(
        os.evidence
            .contains(&"last update run 9 days ago".to_string())
    );
}

/// The operating system releases sentry knows where to look up, by `/etc/os-release`.
#[test]
fn a_release_is_looked_up_by_its_id_and_version() {
    let r = |text: &str| release_of(text);
    assert_eq!(
        r("ID=debian\nVERSION_ID=\"12\"\n"),
        Some(("debian".into(), "12".into(), "Debian 12".into()))
    );
    assert_eq!(
        r("ID=ubuntu\nVERSION_ID=\"24.04\"\n").map(|x| x.1),
        Some("24.04".into())
    );
    assert_eq!(
        r("NAME=Fedora\nID=fedora\nVERSION_ID=44\nVARIANT_ID=silverblue\n"),
        Some(("fedora".into(), "44".into(), "Fedora 44".into()))
    );
    assert_eq!(
        r("ID=alpine\nVERSION_ID=3.20.3\n").map(|x| x.1),
        Some("3.20".into())
    );
    assert_eq!(
        r("ID=rocky\nVERSION_ID=\"9.4\"\n").map(|x| x.0),
        Some("rocky-linux".into())
    );
    assert_eq!(r("ID=gentoo\nVERSION_ID=2.15\n"), None);
    assert_eq!(r("ID=debian\n"), None, "testing/sid has no version");
}

/// The report as text: "Do these first" holds five at most (the rest lead "Worth doing",
/// said in the header), questions come last, and one line says what goes on while sentry
/// is closed.
#[test]
fn the_report_reads_in_order() {
    let (mut n, mut s) = (net(), srv());
    let r = n.router.as_mut().unwrap();
    r.firmware.as_mut().unwrap().eol = Eol::Past(3);
    r.zones.as_mut().unwrap()[2].reaches.push("lan".into());
    r.wifi.as_mut().unwrap()[0].encryption = "none".into();
    r.wan_input_accept = Some(true);
    door_said(&mut n, Web::Open, Some((Some(-3), Issuer::SelfSigned)));
    s.software.as_mut().unwrap()[0].security = true;
    s.backup = Some(Backup::default());
    s.logs = None;
    let mut a = Answers::default();
    a.set("backup-exists:srv:myserver", false, day());
    let rep = Report::build(&[s, n], &a, None, at());
    assert!(rep.of(State::DoFirst).len() > FIRST);
    assert_eq!(rep.first().len(), FIRST);
    let text = render(&rep);
    insta::assert_snapshot!("render_capped", text);
    let pos = |t: &str| text.find(t).unwrap_or_else(|| panic!("{t} in:\n{text}"));
    assert!(pos("\nDo these first (5)") < pos("\nWorth doing ("));
    assert!(pos("\nCouldn't check (") < pos("\nNeeds your answer ("));
    assert!(text.contains("As pressing as those first, after the five"));
    assert!(text.contains(
        "sentry only looks while it is open: nothing of it runs in the background. Without \
         it: CrowdSec on myserver bans attackers and the router blocks them; myserver installs \
         security updates by itself."
    ));
    // Every title, why and fix is at most two sentences.
    for i in &rep.items {
        for t in [&i.title, &i.why, &i.fix] {
            let inner = t.trim_end_matches(['.', '?']);
            let sentences = inner.matches(". ").count() + inner.matches("? ").count();
            assert!(sentences <= 1, "{}: {t}", i.id);
        }
    }
}

/// The family filter is said by count, never by device, and its trouble is an item of its
/// own beside the line that says it is set up.
#[test]
fn the_family_filter_is_said_by_count() {
    let with = |devices, trouble| {
        let mut n = net();
        n.router.as_mut().unwrap().family = Some(Family { devices, trouble });
        eval(n, srv(), &answered())
    };
    let title = |items: &[Item], id: &str| {
        items
            .iter()
            .find(|i| i.id == id)
            .map(|i| (i.state, i.title.clone()))
    };
    let none = with(0, None);
    assert_eq!(
        title(&none, "sec:family:net:home").map(|t| t.0),
        Some(State::Fine)
    );
    assert!(
        title(&none, "sec:family:net:home")
            .unwrap()
            .1
            .contains("No device")
    );
    let three = with(3, None);
    assert!(
        title(&three, "sec:family:net:home")
            .unwrap()
            .1
            .contains("on for 3 devices")
    );
    assert!(!three.iter().any(|i| i.id.starts_with("sec:family-")));
    let broken = with(3, Some(FamilyTrouble::Forced));
    assert!(
        title(&broken, "sec:family:net:home")
            .unwrap()
            .1
            .contains("has stopped working")
    );
    assert_eq!(
        title(&broken, "sec:family-forced:net:home").map(|t| t.0),
        Some(State::DoFirst)
    );
    // Not read: nothing said either way.
    let unread = eval(net(), srv(), &answered());
    assert!(!unread.iter().any(|i| i.id.contains("family")));
}

/// A network's firmware upgrade, logged as its workflow's run writes it, makes the audit's
/// task due again (`upgrade_in`): a run that ended well, and not one abandoned.
#[test]
fn a_routers_firmware_upgrade_makes_the_audit_due_again() {
    use crate::maint::log::LogEntry;
    use crate::workflows::state::{RunState, RunStatus};
    let text =
        std::fs::read_to_string("../../assets/network-workflows/firmware-upgrade.toml").unwrap();
    let wf = crate::workflows::parse(&text).unwrap();
    let ids: Vec<String> = wf.steps.iter().map(|s| s.id.clone()).collect();
    let mut st = RunState::new(&wf.name, &ids, Default::default());
    st.status = RunStatus::Done;
    st.ended = Some(st.started);
    let done = LogEntry::from_run("net:home", &wf, &st, std::path::Path::new("x"), None, None);
    let (at, what) = upgrade_in(std::slice::from_ref(&done)).expect("the upgrade counts");
    assert_eq!((at, what.as_str()), (st.started, "firmware-upgrade"));
    st.status = RunStatus::Abandoned;
    let left = LogEntry::from_run("net:home", &wf, &st, std::path::Path::new("x"), None, None);
    assert_eq!(upgrade_in(&[left]), None);
}

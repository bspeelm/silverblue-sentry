//! What Enter on the Security screen does to the router, as a plan (pure): what it says in
//! plain words, the uci lines the guard stages, the commands run as written, and what is
//! proven before anything changes and again before the change is kept.
//!
//! Every plan is carried out by `run::apply` (the `security-action` workflow's step): a
//! change to a guarded config goes through the guard and nothing else; the few that aren't
//! config (a blocklist's refresh, a station sent off the Wi-Fi) are single commands shown
//! first. Nothing here is a bare toggle, and none asks the user to type a command.

use super::blocks::{self, Blocks, Reach};
use crate::collect::uci::Uci;

/// One action, as the workflow's `action` value says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Do {
    Block {
        tag: String,
        reach: Reach,
    },
    Unblock {
        tag: String,
    },
    /// Switch a port forward off (it stays in the config), on again, or delete it.
    ForwardOff {
        section: String,
    },
    ForwardOn {
        section: String,
    },
    ForwardRemove {
        section: String,
    },
    /// ssh: keys only.
    SshKeys,
    /// The admin page: plain HTTP is sent on to HTTPS.
    AdminHttps,
    /// The blocklist: fetched and built again now.
    ListRefresh,
    /// The blocklist: its own scheduled update on.
    ListSchedule,
    /// Send a station off the Wi-Fi and keep it off for this many seconds.
    Kick {
        tag: String,
        secs: u32,
    },
}

impl Do {
    /// `block:<tag>:internet`, `forward-off:<section>`, `ssh-keys-only`…
    pub fn word(&self) -> String {
        match self {
            Do::Block { tag, reach } => format!("block:{tag}:{}", reach.word()),
            Do::Unblock { tag } => format!("unblock:{tag}"),
            Do::ForwardOff { section } => format!("forward-off:{section}"),
            Do::ForwardOn { section } => format!("forward-on:{section}"),
            Do::ForwardRemove { section } => format!("forward-remove:{section}"),
            Do::SshKeys => "ssh-keys-only".into(),
            Do::AdminHttps => "admin-https".into(),
            Do::ListRefresh => "blocklist-refresh".into(),
            Do::ListSchedule => "blocklist-schedule".into(),
            Do::Kick { tag, secs } => format!("kick:{tag}:{secs}"),
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        let tag = |t: &str| {
            blocks::is_tag(t)
                .then(|| t.to_string())
                .ok_or(format!("`{t}` isn't a device's tag"))
        };
        // A section as uci names it: a plain word, or `@redirect[3]`.
        let section = |x: &str| {
            let plain = !x.is_empty() && x.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
            let nth = x
                .strip_prefix("@redirect[")
                .and_then(|r| r.strip_suffix(']'))
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
            (plain || nth)
                .then(|| x.to_string())
                .ok_or(format!("`{x}` isn't a forward's section"))
        };
        Ok(match parts.as_slice() {
            ["block", t, r] => Do::Block {
                tag: tag(t)?,
                reach: Reach::parse(r).ok_or(format!("`{r}` isn't internet or everything"))?,
            },
            ["unblock", t] => Do::Unblock { tag: tag(t)? },
            ["forward-off", x] => Do::ForwardOff {
                section: section(x)?,
            },
            ["forward-on", x] => Do::ForwardOn {
                section: section(x)?,
            },
            ["forward-remove", x] => Do::ForwardRemove {
                section: section(x)?,
            },
            ["ssh-keys-only"] => Do::SshKeys,
            ["admin-https"] => Do::AdminHttps,
            ["blocklist-refresh"] => Do::ListRefresh,
            ["blocklist-schedule"] => Do::ListSchedule,
            ["kick", t, n] => Do::Kick {
                tag: tag(t)?,
                secs: n
                    .parse()
                    .ok()
                    .filter(|n| (1..=86_400).contains(n))
                    .ok_or(format!("`{n}` isn't a time in seconds (1–86400)"))?,
            },
            _ => return Err(format!("`{s}` isn't an action of the Security screen")),
        })
    }
}

/// Something proven from this machine: before anything changes, and again before the
/// change is kept (a proof that fails then lets the router take the change back).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    /// A new connection logs in with a key: no shared connection, nothing that could type
    /// a password, and the router has a key on file.
    KeyLogin,
    /// The admin page answers on HTTPS at the address ssh reaches the router at.
    Https,
}

impl Proof {
    pub fn says(self) -> &'static str {
        match self {
            Proof::KeyLogin => {
                "a new connection logs in with a key (nothing on it could type a password)"
            }
            Proof::Https => "the admin page answers on HTTPS from this machine",
        }
    }
}

/// The part of a plan the guard carries out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Guarded {
    pub configs: &'static str,
    /// `uci …` lines, as they are staged.
    pub lines: Vec<String>,
    pub services: &'static str,
    /// Port forwards (as the guard words them, `tcp 443 → 192.0.2.10`) this change is
    /// meant to close: the guard doesn't hold their absence against it.
    pub closing: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Planned {
    /// One line: what this is.
    pub title: String,
    /// What it does and what it doesn't, in plain words.
    pub says: Vec<String>,
    pub proofs: Vec<Proof>,
    pub guard: Option<Guarded>,
    /// Commands run on the router as written, after the guard's part.
    pub runs: Vec<String>,
}

impl Planned {
    /// The plan as text: what the workflow's first step prints.
    pub fn text(&self) -> Vec<String> {
        let mut l = vec![self.title.clone(), String::new()];
        l.extend(self.says.iter().cloned());
        if !self.proofs.is_empty() {
            l.push(String::new());
            l.push("Proven first, and again before the change is kept:".into());
            l.extend(self.proofs.iter().map(|p| format!("  {}", p.says())));
        }
        if let Some(g) = &self.guard {
            l.push(String::new());
            l.push(format!(
                "Through the guard ({}; reloads {}):",
                g.configs,
                if g.services.is_empty() {
                    "nothing"
                } else {
                    g.services
                }
            ));
            l.extend(g.lines.iter().map(|x| format!("  {x}")));
            l.push(
                "The router is armed to undo this by itself first; it is kept only if the \
                 router still answers as before."
                    .into(),
            );
        }
        if !self.runs.is_empty() {
            l.push(String::new());
            l.push("Run on the router as written:".into());
            l.extend(self.runs.iter().map(|x| format!("  {x}")));
        }
        l
    }
}

/// What a plan is made from.
pub struct Facts<'a> {
    pub uci: &'a Uci,
    /// The uplink's zone.
    pub wan: &'a str,
    pub blocks: &'a Blocks,
    /// `network_config.yaml` expects these forwards (as the guard words them).
    pub expected: &'a [String],
}

fn forward(f: &Facts, section: &str) -> Result<crate::collect::uci::Redirect, String> {
    f.uci
        .forwards()
        .into_iter()
        .find(|r| r.section == section)
        .ok_or(format!(
            "the router has no port forward `{section}` any more: read again (r) on Security"
        ))
}

/// A forward as the guard words it, one per protocol.
fn guard_words(r: &crate::collect::uci::Redirect) -> Vec<String> {
    r.protos
        .iter()
        .map(|p| format!("{p} {} → {}", r.port, r.dest_ip))
        .collect()
}

fn door(r: &crate::collect::uci::Redirect) -> String {
    format!(
        "{} ({} port {} → {}:{})",
        r.name,
        r.protos.join("+"),
        r.port,
        r.dest_ip,
        r.dest_port.as_deref().unwrap_or(&r.port)
    )
}

/// The plan for an action. Err: why there is nothing to do, or why it can't be done.
pub fn plan(d: &Do, f: &Facts) -> Result<Planned, String> {
    let fw = |lines: Vec<String>, closing: Vec<String>| Guarded {
        configs: "firewall",
        lines,
        services: "firewall",
        closing,
    };
    let who = |tag: &str| {
        f.blocks.device.get(tag).ok_or(format!(
            "sentry doesn't know which device `{tag}` is any more: pick it on Security again"
        ))
    };
    Ok(match d {
        Do::Block { tag, reach } => {
            let dev = who(tag)?;
            if blocks::found(f.uci).iter().any(|b| &b.tag == tag) {
                return Err(format!(
                    "{} is already blocked: unblock it first to change how",
                    dev.label
                ));
            }
            let lines = blocks::block_lines(tag, &dev.mac, &dev.zone, f.wan, *reach)?;
            Planned {
                title: format!("Block {} from {}", dev.label, reach.says()),
                says: match reach {
                    Reach::Internet => vec![
                        format!(
                            "One firewall rule refuses whatever the device with MAC {} sends \
                             from {} towards the internet.",
                            dev.mac, dev.zone
                        ),
                        "It stays on your network: other devices there still see it.".into(),
                    ],
                    Reach::Everything => vec![
                        format!(
                            "Two firewall rules refuse whatever the device with MAC {} sends \
                             from {}: to any other network, and to the router itself (no \
                             names, no addresses, no admin page).",
                            dev.mac, dev.zone
                        ),
                        "What the router can't stop: devices on the same switch or Wi-Fi talk \
                         to each other without passing it."
                            .into(),
                    ],
                }
                .into_iter()
                .chain([
                    "Connections it already has open run on until they close.".into(),
                    "A device that changes its MAC (phones can) gets past a rule by MAC: \
                     changing the Wi-Fi password is what keeps a device out."
                        .into(),
                    format!("The rule is named sentry-block-{tag}: Enter under Blocked by you removes it."),
                ])
                .collect(),
                guard: Some(fw(lines, Vec::new())),
                ..Default::default()
            }
        }
        Do::Unblock { tag } => {
            let lines = blocks::unblock_lines(f.uci, tag);
            if lines.is_empty() {
                return Err(format!(
                    "the router has no rule sentry-block-{tag}: nothing to unblock"
                ));
            }
            let label = f
                .blocks
                .device
                .get(tag)
                .map_or("the device", |d| d.label.as_str());
            Planned {
                title: format!("Unblock {label}"),
                says: vec![
                    "Removes exactly the firewall rule(s) sentry added for it; no other rule \
                     is touched."
                        .into(),
                ],
                guard: Some(fw(lines, Vec::new())),
                ..Default::default()
            }
        }
        Do::ForwardOff { section } => {
            let r = forward(f, section)?;
            if !r.enabled {
                return Err(format!("{} is already switched off", r.name));
            }
            let words = guard_words(&r);
            let listed = words.iter().any(|w| f.expected.contains(w));
            let mut says = vec![
                format!(
                    "Closes the door {}: nobody on the internet reaches that device on that \
                     port any more.",
                    door(&r)
                ),
                "It stays in the router's config, switched off: Enter under Blocked by you \
                 opens it again."
                    .into(),
            ];
            if listed {
                says.push(
                    "network_config.yaml lists it under expect.forwards: once it is closed \
                     the audit will say it is missing until you take it out there."
                        .into(),
                );
            }
            Planned {
                title: format!("Close the port forward {}", r.name),
                says,
                guard: Some(fw(
                    vec![format!("uci set firewall.{section}.enabled='0'")],
                    words,
                )),
                ..Default::default()
            }
        }
        Do::ForwardOn { section } => {
            let r = forward(f, section)?;
            if r.enabled {
                return Err(format!("{} is already open", r.name));
            }
            Planned {
                title: format!("Open the port forward {} again", r.name),
                says: vec![format!(
                    "Opens the door {} again: anyone on the internet can reach that device \
                     on that port.",
                    door(&r)
                )],
                guard: Some(fw(
                    vec![format!("uci set firewall.{section}.enabled='1'")],
                    Vec::new(),
                )),
                ..Default::default()
            }
        }
        Do::ForwardRemove { section } => {
            let r = forward(f, section)?;
            Planned {
                title: format!("Remove the port forward {}", r.name),
                says: vec![
                    format!("Deletes the door {} from the router's config.", door(&r)),
                    "To have it back it must be made again (the config backup has it).".into(),
                ],
                guard: Some(fw(
                    vec![format!("uci delete firewall.{section}")],
                    guard_words(&r),
                )),
                ..Default::default()
            }
        }
        Do::SshKeys => {
            let open: Vec<_> = f
                .uci
                .dropbear()
                .into_iter()
                .filter(|d| d.password_auth || d.root_password_auth)
                .collect();
            if open.is_empty() {
                return Err("password logins over ssh are already off".into());
            }
            Planned {
                title: "ssh: logins with a key only".into(),
                says: vec![
                    "Turns password logins to the router off (PasswordAuth and \
                     RootPasswordAuth): a password can be guessed, a key can't."
                        .into(),
                    "sentry itself logs in with a key. Before anything changes it proves that \
                     on a new connection; if that fails, nothing is changed. After the change \
                     it proves it again, and if that fails the router takes the change back \
                     by itself."
                        .into(),
                    "The admin page's own password login is not touched.".into(),
                ],
                proofs: vec![Proof::KeyLogin],
                guard: Some(Guarded {
                    configs: "dropbear",
                    lines: open
                        .iter()
                        .flat_map(|d| {
                            [
                                format!("uci set dropbear.{}.PasswordAuth='off'", d.section),
                                format!("uci set dropbear.{}.RootPasswordAuth='off'", d.section),
                            ]
                        })
                        .collect(),
                    services: "dropbear",
                    closing: Vec::new(),
                }),
                ..Default::default()
            }
        }
        Do::AdminHttps => {
            let sections: Vec<&str> = f
                .uci
                .config("uhttpd")
                .iter()
                .filter(|s| s.kind == "uhttpd" && !s.flag("redirect_https", false))
                .map(|s| s.name.as_str())
                .collect();
            let u = f
                .uci
                .uhttpd()
                .ok_or("the router has no admin page (uhttpd)")?;
            if sections.is_empty() {
                return Err("the admin page already sends plain HTTP on to HTTPS".into());
            }
            if u.listen_https.is_empty() {
                return Err(
                    "the admin page doesn't listen on HTTPS at all: sending HTTP there would \
                     lock it. That needs its certificate set up first (A asks Claude)"
                        .into(),
                );
            }
            Planned {
                title: "Admin page: plain HTTP is sent on to HTTPS".into(),
                says: vec![
                    "Sets redirect_https on the router's web server and nothing else: opening \
                     the admin page without encryption then lands on the encrypted one, so \
                     its password is never typed in the clear."
                        .into(),
                    "The router's certificate is its own: the browser will ask once whether \
                     to trust it."
                        .into(),
                ],
                proofs: vec![Proof::Https],
                guard: Some(Guarded {
                    configs: "uhttpd",
                    lines: sections
                        .iter()
                        .map(|s| format!("uci set uhttpd.{s}.redirect_https='1'"))
                        .collect(),
                    services: "uhttpd",
                    closing: Vec::new(),
                }),
                ..Default::default()
            }
        }
        Do::ListRefresh => Planned {
            title: "Fetch the list of bad sites again".into(),
            says: vec![
                "Runs the blocklist package's own download (adblock-fast): it fetches its \
                 lists, builds the file dnsmasq blocks from, and restarts dnsmasq, so names \
                 don't resolve for a few seconds."
                    .into(),
                "It writes that file in the router's memory and nothing in its config.".into(),
            ],
            runs: vec![LIST_REFRESH.into()],
            ..Default::default()
        },
        Do::ListSchedule => Planned {
            title: "Let the list of bad sites update by itself".into(),
            says: vec![
                "Turns on the blocklist package's own scheduled update (adblock-fast's \
                 auto_update_enabled) and has the package write its line in root's crontab."
                    .into(),
                "It touches the package's own config and the crontab; not the firewall, the \
                 network or dnsmasq's config."
                    .into(),
            ],
            runs: LIST_SCHEDULE.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        },
        Do::Kick { tag, secs } => {
            let dev = who(tag)?;
            let ap = dev.wifi.as_deref().ok_or(format!(
                "{} isn't on the Wi-Fi: there is nothing to disconnect",
                dev.label
            ))?;
            if !ap
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(format!("`{ap}` isn't an access point's name"));
            }
            let mac = crate::config::mac(&dev.mac).ok_or("that isn't a MAC address")?;
            Planned {
                title: format!("Send {} off the Wi-Fi", dev.label),
                says: vec![
                    format!(
                        "The access point drops the device and refuses it for {}.",
                        said_secs(*secs)
                    ),
                    "After that it can join again if it has the password: changing the Wi-Fi \
                     password is what keeps a device out."
                        .into(),
                ],
                runs: vec![format!(
                    "ubus call hostapd.{ap} del_client '{{\"addr\":\"{mac}\",\"reason\":5,\"deauth\":true,\"ban_time\":{}}}'",
                    u64::from(*secs) * 1000
                )],
                ..Default::default()
            }
        }
    })
}

/// adblock-fast's own action that downloads and rebuilds its lists.
pub const LIST_REFRESH: &str = "/etc/init.d/adblock-fast dl";
/// Its scheduled update: the option LuCI's page sets, committed, then the package's own
/// sync of root's crontab. (The names are the package's, from its source; not run on a
/// router by sentry's tests.)
pub const LIST_SCHEDULE: &[&str] = &[
    "uci set adblock-fast.config.auto_update_enabled='1'",
    "uci commit adblock-fast",
    "ubus call luci.adblock-fast syncCron '{\"name\":\"adblock-fast\",\"action\":\"create\"}'",
];

fn said_secs(s: u32) -> String {
    match s {
        0..=119 => format!("{s} seconds"),
        120..=7199 => format!("{} minutes", s / 60),
        _ => format!("{} hours", s / 3600),
    }
}

/// The uci lines that give these access points a new passphrase (the `guarded-change`
/// workflow's `lines`). Err: a passphrase WPA wouldn't take, or one that can't be quoted.
pub fn wifi_key_lines(sections: &[String], key: &str) -> Result<String, String> {
    let n = key.chars().count();
    if !(8..=63).contains(&n) {
        return Err("a Wi-Fi password is 8 to 63 characters".into());
    }
    if key.contains('\'') || key.chars().any(|c| c.is_control() || !c.is_ascii()) {
        return Err("letters, digits, spaces and punctuation, but no ' (the apostrophe)".into());
    }
    if sections.is_empty() {
        return Err("no access point to change".into());
    }
    Ok(sections
        .iter()
        .map(|s| format!("uci set wireless.{s}.key='{key}'"))
        .collect::<Vec<_>>()
        .join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::Change;
    use crate::redact::Salt;
    use crate::security::blocks::Dev;

    fn uci(text: &str) -> Uci {
        crate::collect::uci::parse(text, &Salt::fixed([7; 16]))
    }

    fn facts<'a>(u: &'a Uci, b: &'a Blocks, expected: &'a [String]) -> Facts<'a> {
        Facts {
            uci: u,
            wan: "wan",
            blocks: b,
            expected,
        }
    }

    fn known() -> Blocks {
        let mut b = Blocks::default();
        b.device.insert(
            "ab12cd34".into(),
            Dev {
                mac: "02:00:5e:00:53:21".into(),
                label: "tablet".into(),
                zone: "lan".into(),
                wifi: Some("phy0-ap0".into()),
            },
        );
        b.device.insert(
            "00000002".into(),
            Dev {
                mac: "02:00:5e:00:53:22".into(),
                label: "printer".into(),
                zone: "lan".into(),
                wifi: None,
            },
        );
        b
    }

    const FW: &str = "@@firewall\n\
        firewall.web=redirect\nfirewall.web.name='web'\nfirewall.web.src='wan'\n\
        firewall.web.proto='tcp'\nfirewall.web.src_dport='443'\nfirewall.web.dest_ip='192.0.2.10'\n\
        firewall.web.target='DNAT'\n\
        firewall.@redirect[1]=redirect\nfirewall.@redirect[1].name='cam'\nfirewall.@redirect[1].src='wan'\n\
        firewall.@redirect[1].proto='tcp'\nfirewall.@redirect[1].src_dport='8554'\n\
        firewall.@redirect[1].dest_ip='192.0.2.40'\nfirewall.@redirect[1].target='DNAT'\n\
        firewall.@redirect[1].enabled='0'\n\
        @@dropbear\n\
        dropbear.main=dropbear\ndropbear.main.Port='22'\n\
        @@uhttpd\n\
        uhttpd.main=uhttpd\nuhttpd.main.listen_http='0.0.0.0:80'\nuhttpd.main.listen_https='0.0.0.0:443'\n";

    /// Every guarded part of a plan is one the guard takes as written.
    fn staged(p: &Planned) -> Change {
        let g = p.guard.as_ref().expect("a guarded part");
        Change::parse(g.configs, &g.lines.join("; "), g.services, false)
            .unwrap_or_else(|e| panic!("{e}: {:?}", g.lines))
    }

    #[test]
    fn every_action_has_a_word_and_reads_back() {
        let all = [
            Do::Block {
                tag: "ab12cd34".into(),
                reach: Reach::Internet,
            },
            Do::Block {
                tag: "ab12cd34".into(),
                reach: Reach::Everything,
            },
            Do::Unblock {
                tag: "ab12cd34".into(),
            },
            Do::ForwardOff {
                section: "web".into(),
            },
            Do::ForwardOn {
                section: "@redirect[1]".into(),
            },
            Do::ForwardRemove {
                section: "cfg0e3837".into(),
            },
            Do::SshKeys,
            Do::AdminHttps,
            Do::ListRefresh,
            Do::ListSchedule,
            Do::Kick {
                tag: "ab12cd34".into(),
                secs: 600,
            },
        ];
        for d in &all {
            let w = d.word();
            assert!(!w.contains(char::is_whitespace), "{w}");
            assert_eq!(Do::parse(&w).as_ref(), Ok(d), "{w}");
        }
        // No word carries a MAC, and nothing but these is an action.
        for bad in [
            "block:02:00:5e:00:53:21:internet",
            "block:ab12cd34:lan",
            "unblock:kids",
            "forward-off:web;reboot",
            "forward-off:@rule[0]",
            "forward-off:",
            "kick:ab12cd34:0",
            "kick:ab12cd34:999999",
            "reboot",
            "",
        ] {
            assert!(Do::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn each_actions_plan() {
        let u = uci(FW);
        let b = known();
        let expected = vec!["tcp 443 → 192.0.2.10".to_string()];
        let f = facts(&u, &b, &expected);
        let plan_of = |w: &str| plan(&Do::parse(w).unwrap(), &f);

        // Block: one rule towards the uplink's zone, by MAC, through the guard.
        let p = plan_of("block:ab12cd34:internet").unwrap();
        assert_eq!(p.title, "Block tablet from the internet");
        let c = staged(&p);
        assert_eq!(
            (c.configs.as_slice(), c.services.as_slice()),
            (&["firewall".to_string()][..], &["firewall".to_string()][..])
        );
        assert_eq!(c.lines.len(), 7);
        assert!(p.runs.is_empty() && p.proofs.is_empty());
        let text = p.text().join("\n");
        assert!(
            text.contains("uci set firewall.sentry_block_ab12cd34.src_mac='02:00:5e:00:53:21'")
                && text.contains("armed to undo this by itself")
                && text.contains("already has open run on"),
            "{text}"
        );
        assert_eq!(
            staged(&plan_of("block:ab12cd34:everything").unwrap())
                .lines
                .len(),
            13
        );
        // A device sentry has no note of: nothing is guessed.
        assert!(
            plan_of("block:99999999:internet")
                .unwrap_err()
                .contains("pick it on Security again")
        );
        // Unblock with no rule there: nothing to do.
        assert!(
            plan_of("unblock:ab12cd34")
                .unwrap_err()
                .contains("nothing to unblock")
        );

        // A forward: off keeps it in the config; the guard is told it is meant to go, and
        // the plan says the config expects it.
        let p = plan_of("forward-off:web").unwrap();
        let g = p.guard.as_ref().unwrap();
        assert_eq!(g.lines, ["uci set firewall.web.enabled='0'"]);
        assert_eq!(g.closing, ["tcp 443 → 192.0.2.10"]);
        assert!(
            p.says.iter().any(|s| s.contains("expect.forwards")),
            "{:?}",
            p.says
        );
        assert!(
            p.says[0].contains("web (tcp port 443 → 192.0.2.10:443)"),
            "{:?}",
            p.says
        );
        staged(&p);
        assert!(
            plan_of("forward-on:web")
                .unwrap_err()
                .contains("already open")
        );
        // An anonymous section, switched off: on again, or removed.
        let p = plan_of("forward-on:@redirect[1]").unwrap();
        assert_eq!(
            p.guard.as_ref().unwrap().lines,
            ["uci set firewall.@redirect[1].enabled='1'"]
        );
        staged(&p);
        assert!(
            plan_of("forward-off:@redirect[1]")
                .unwrap_err()
                .contains("already switched off")
        );
        let p = plan_of("forward-remove:@redirect[1]").unwrap();
        assert_eq!(
            p.guard.as_ref().unwrap().lines,
            ["uci delete firewall.@redirect[1]"]
        );
        assert!(!p.says.iter().any(|s| s.contains("expect.forwards")));
        staged(&p);
        assert!(
            plan_of("forward-off:gone")
                .unwrap_err()
                .contains("no port forward")
        );

        // ssh: both options off, the key login proven before and after.
        let p = plan_of("ssh-keys-only").unwrap();
        assert_eq!(p.proofs, [Proof::KeyLogin]);
        assert_eq!(
            p.guard.as_ref().unwrap().lines,
            [
                "uci set dropbear.main.PasswordAuth='off'",
                "uci set dropbear.main.RootPasswordAuth='off'"
            ]
        );
        assert_eq!(staged(&p).services, ["dropbear"]);
        assert!(
            p.text()
                .join("\n")
                .contains("if that fails, nothing is changed")
        );

        // The admin page: redirect_https and nothing else, HTTPS proven from here.
        let p = plan_of("admin-https").unwrap();
        assert_eq!(p.proofs, [Proof::Https]);
        assert_eq!(
            p.guard.as_ref().unwrap().lines,
            ["uci set uhttpd.main.redirect_https='1'"]
        );
        assert_eq!(staged(&p).services, ["uhttpd"]);

        // The blocklist: the package's own commands, no guard (and nothing of dnsmasq's
        // config).
        let p = plan_of("blocklist-refresh").unwrap();
        assert!(p.guard.is_none());
        assert_eq!(p.runs, ["/etc/init.d/adblock-fast dl"]);
        let p = plan_of("blocklist-schedule").unwrap();
        assert!(p.guard.is_none() && p.runs.len() == 3);
        assert!(!p.runs.iter().any(|l| l.contains("dhcp")), "{:?}", p.runs);
        assert!(p.says.iter().any(|s| s.contains("crontab")));

        // A station: the access point's own call, with a ban time.
        let p = plan_of("kick:ab12cd34:600").unwrap();
        assert_eq!(
            p.runs,
            [
                "ubus call hostapd.phy0-ap0 del_client '{\"addr\":\"02:00:5e:00:53:21\",\"reason\":5,\"deauth\":true,\"ban_time\":600000}'"
            ]
        );
        assert!(p.says[0].contains("for 10 minutes"), "{:?}", p.says);
        assert!(
            plan_of("kick:00000002:600")
                .unwrap_err()
                .contains("isn't on the Wi-Fi")
        );
    }

    #[test]
    fn what_is_already_so_is_not_planned_again() {
        let u = uci("@@firewall\n\
             firewall.sentry_block_ab12cd34=rule\n\
             firewall.sentry_block_ab12cd34.name='sentry-block-ab12cd34'\n\
             firewall.sentry_block_ab12cd34.src_mac='02:00:5e:00:53:21'\n\
             @@dropbear\n\
             dropbear.main=dropbear\ndropbear.main.PasswordAuth='off'\ndropbear.main.RootPasswordAuth='off'\n\
             @@uhttpd\n\
             uhttpd.main=uhttpd\nuhttpd.main.listen_http='0.0.0.0:80'\n");
        let b = known();
        let f = facts(&u, &b, &[]);
        let plan_of = |w: &str| plan(&Do::parse(w).unwrap(), &f);
        assert!(
            plan_of("block:ab12cd34:internet")
                .unwrap_err()
                .contains("already blocked")
        );
        assert!(
            plan_of("ssh-keys-only")
                .unwrap_err()
                .contains("already off")
        );
        // No HTTPS listener: a redirect there would lock the page.
        assert!(
            plan_of("admin-https")
                .unwrap_err()
                .contains("doesn't listen on HTTPS")
        );
        // Unblock: exactly sentry's section.
        let p = plan_of("unblock:ab12cd34").unwrap();
        assert_eq!(p.title, "Unblock tablet");
        assert_eq!(
            p.guard.as_ref().unwrap().lines,
            ["uci delete firewall.sentry_block_ab12cd34"]
        );
        staged(&p);
    }

    #[test]
    fn a_new_wifi_password_as_guard_lines() {
        let s = vec!["default_radio0".to_string(), "default_radio1".to_string()];
        let l = wifi_key_lines(&s, "correct horse 9").unwrap();
        assert_eq!(
            l,
            "uci set wireless.default_radio0.key='correct horse 9'; uci set wireless.default_radio1.key='correct horse 9'"
        );
        let c = Change::parse("wireless", &l, "wifi", false).unwrap();
        assert!(c.wifi() && c.asks(), "a Wi-Fi change waits for its keep");
        // The value is a secret: what is shown while typing and what is written down
        // have dots or a tag.
        assert!(crate::guard::typed(&l).is_some());
        for bad in [
            "short",
            &"x".repeat(64),
            "it's a secret",
            "tab\there9",
            "ünïcode99",
        ] {
            assert!(wifi_key_lines(&s, bad).is_err(), "{bad}");
        }
        assert!(wifi_key_lines(&[], "long enough").is_err());
    }
}

//! What Enter on the Security screen does to the router, as a plan (pure): what it says in
//! plain words, the uci lines the guard stages, the commands run as written, and what is
//! proven before anything changes and again before the change is kept.
//!
//! Every plan is carried out by `run::apply` (the `security-action` workflow's step): a
//! change to a guarded config goes through the guard and nothing else; the few that aren't
//! config (a blocklist's refresh, a station sent off the Wi-Fi) are single commands shown
//! first. Nothing here is a bare toggle, and none asks the user to type a command.

use super::blocks::{self, Blocks, Reach};
use super::family;
use crate::collect::counters::Counters;
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
    /// The family filter on exactly these devices (by tag, sorted), off for every other:
    /// one change, however many devices it adds or takes off.
    Filter {
        tags: Vec<String>,
        /// With no device left: keep sentry's forcing of lookups instead of handing it
        /// back to the DNS proxy (`filter:none:keep`).
        keep: bool,
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
            Do::Filter { tags, keep: true } if tags.is_empty() => "filter:none:keep".into(),
            Do::Filter { tags, .. } if tags.is_empty() => "filter:none".into(),
            Do::Filter { tags, .. } => format!("filter:{}", tags.join(",")),
        }
    }

    /// The family filter on these devices: sorted, each once.
    pub fn filter<I: IntoIterator<Item = String>>(tags: I) -> Self {
        let mut tags: Vec<String> = tags.into_iter().collect();
        tags.sort();
        tags.dedup();
        Do::Filter { tags, keep: false }
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
            ["filter", "none"] => Do::Filter {
                tags: Vec::new(),
                keep: false,
            },
            ["filter", "none", "keep"] => Do::Filter {
                tags: Vec::new(),
                keep: true,
            },
            ["filter", list] => {
                let tags = list.split(',').map(tag).collect::<Result<Vec<_>, _>>()?;
                let d = Do::filter(tags);
                if d.word() != s {
                    return Err(format!("`{s}` isn't the filter's list of devices, sorted"));
                }
                d
            }
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
    /// The router still looks up an ordinary name through its own resolver.
    OwnResolver,
    /// The family service answers the router, and refuses its own test name.
    Family,
    /// Read back from the firewall as loaded: every filtered device's rule before the
    /// catch-all, no other program's DNS redirect in front, the 853 refusal there.
    Precedence,
}

impl Proof {
    pub fn says(self) -> &'static str {
        match self {
            Proof::KeyLogin => {
                "a new connection logs in with a key (nothing on it could type a password)"
            }
            Proof::Https => "the admin page answers on HTTPS from this machine",
            Proof::OwnResolver => {
                "the router still looks up an ordinary name (openwrt.org) through its own resolver"
            }
            Proof::Family => {
                "CleanBrowsing Family answers the router, and refuses its own test name (pornhub.com)"
            }
            Proof::Precedence => {
                "the firewall as loaded has each filtered device's rule before the catch-all, no other program's in front, and port 853 still refused"
            }
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
    /// Proven only once the change is made, before it is kept.
    pub after: Vec<Proof>,
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
        if !self.after.is_empty() {
            l.push(String::new());
            l.push("Proven once the change is made, before it is kept:".into());
            l.extend(self.after.iter().map(|p| format!("  {}", p.says())));
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
    /// What the firewall counts (None: not read): whose DNS redirect comes first.
    pub counters: Option<&'a Counters>,
    /// Other nft tables that redirect DNS themselves (`family::foreign_tables`).
    pub tables: &'a [String],
    /// What the DNS proxy hands the firewall (None: not read).
    pub forced: Option<&'a [family::Forced]>,
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
        Do::Filter { tags, keep } => filter_plan(tags, *keep, f)?,
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

/// "a", "a and b", "a, b and c".
fn and(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [most @ .., last] => format!("{} and {last}", most.join(", ")),
    }
}

fn cap_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// What a filter plan says once, whatever it changes: what it is for and what it isn't.
pub const FILTER_LIMITS: &str = "What it is for: accidents and casual browsing. It doesn't \
     stop a VPN, mobile data, a browser's own encrypted lookups (DNS over HTTPS), or a device \
     that changes its MAC.";

/// The family filter on exactly `tags`: what it changes against what the router has.
fn filter_plan(tags: &[String], keep_forcing: bool, f: &Facts) -> Result<Planned, String> {
    let svc = family::service();
    let have = family::found(f.uci);
    let label = |t: &str| {
        f.blocks
            .device
            .get(t)
            .map(|d| d.label.clone())
            .filter(|l| !l.is_empty())
            .or_else(|| have.iter().find(|h| h.tag == t).map(|h| h.mac.clone()))
            .unwrap_or_else(|| format!("the device {t}"))
    };
    let mut want = Vec::new();
    for t in tags {
        let w = match (f.blocks.device.get(t), have.iter().find(|h| &h.tag == t)) {
            (Some(d), _) => family::Want {
                tag: t.clone(),
                mac: d.mac.clone(),
                zone: d.zone.clone(),
            },
            (None, Some(h)) => family::Want {
                tag: t.clone(),
                mac: h.mac.clone(),
                zone: h.zone.clone(),
            },
            (None, None) => {
                return Err(format!(
                    "sentry doesn't know which device `{t}` is any more: tick it on Security again"
                ));
            }
        };
        want.push(w);
    }
    let taken = !family::dns_found(f.uci).is_empty();
    // Whose forced lookups come first: another program's is refused; the DNS proxy's is
    // taken over, once, in this same change (`family`'s notes on what that is). A filter
    // already in place that the proxy's forcing is back in front of is put right too.
    let mut takeover = false;
    let adding = want.iter().any(|w| {
        !have
            .iter()
            .any(|h| h.tag == w.tag && h.whole() && h.zone == w.zone)
    });
    if !want.is_empty() && (adding || f.counters.is_some()) {
        let Some(c) = f.counters else {
            return Err(
                "the router's firewall rules couldn't be read, so sentry can't tell whether a \
                 filter would work there: read again (r) on Security"
                    .into(),
            );
        };
        for w in &want {
            let hijack = family::hijacked(c, &w.zone);
            if let Some(why) = family::refused(&w.zone, &hijack, f.tables) {
                return Err(format!(
                    "the family filter can't work on this router yet: {why}"
                ));
            }
            takeover |= hijack.iter().any(|h| h == family::PROXY);
        }
    }
    // (An earlier takeover's sections are made again from what the proxy hands over now:
    // counted as gone where sentry's filters are put in front of a DNS redirect.)
    let gone: std::collections::BTreeSet<String> = match takeover {
        true => family::dns_found(f.uci)
            .into_iter()
            .map(|(s, _, _)| s)
            .collect(),
        false => Default::default(),
    };
    let mut d = family::delta_without(f.uci, &want, f.wan, svc, &gone)?;
    if takeover {
        let (sec, _) = family::proxy_forces(f.uci).ok_or(
            "the router's firewall says the DNS proxy forces lookups, but its settings weren't \
             read: read again (r) on Security",
        )?;
        let forced = f.forced.ok_or(
            "what the DNS proxy hands the firewall couldn't be read, so sentry can't take its \
             place exactly",
        )?;
        for s in gone.iter().rev() {
            d.lines.insert(0, format!("uci delete firewall.{s}"));
        }
        d.lines.extend(family::takeover_lines(&sec, forced)?);
    }
    // sentry's forcing gone while the proxy's is off (nobody's lookups forced): made again,
    // from the proxy's own settings, without touching them.
    let remake = !want.is_empty()
        && !takeover
        && !taken
        && family::proxy_forces(f.uci).is_some_and(|(_, on)| !on)
        && !have.is_empty();
    if remake {
        let mut l = family::takeover_lines("config", &family::default_forced(f.uci))?;
        l.remove(0);
        d.lines.extend(l);
    }
    // The last device off: the forcing goes back to the DNS proxy, unless asked to stay.
    let handback = want.is_empty() && taken && !keep_forcing;
    if handback {
        d.lines.extend(family::handback_lines(f.uci));
    }
    if d.is_empty() {
        return Err(match tags.len() {
            0 => "the family filter isn't on any device: nothing to change".into(),
            _ => "the family filter is already on exactly these devices: nothing to change".into(),
        });
    }
    let on: Vec<&family::Want> = want
        .iter()
        .filter(|w| d.add.contains(&w.tag) || d.redo.contains(&w.tag))
        .collect();
    let added: Vec<String> = d.add.iter().chain(&d.redo).map(|t| label(t)).collect();
    let removed: Vec<String> = d.remove.iter().map(|t| label(t)).collect();
    let title = match (added.as_slice(), removed.as_slice()) {
        ([], []) if takeover => {
            "Family filter: put back in front of the router's forced lookups".into()
        }
        ([], []) if remake => "Family filter: lookups forced through the router again".into(),
        ([], []) => "Family filter: the router's forced lookups handed back".into(),
        ([], r) => format!("Family filter: off for {}", and(r)),
        (a, []) => format!("Family filter: on for {}", and(a)),
        (a, r) => format!("Family filter: on for {}, off for {}", and(a), and(r)),
    };
    let mut says = Vec::new();
    if takeover {
        says.push(format!(
            "First, once: sentry takes over from the DNS proxy ({}) the job of sending every \
             device's lookups through the router. Nothing changes for the household: lookups \
             are still forced through the router as before, and encrypted lookups (port 853) \
             still refused; sentry does it so the devices you picked can be sent to {} first.",
            family::PROXY,
            svc.name
        ));
        says.push(
            "The DNS proxy and then the firewall are reloaded: a few seconds, with lookups \
             forced by the old rules until the new ones are in. The proxy's reload saves \
             whatever its neighbours left pending in the DHCP settings and restarts the \
             router's own resolver, as it does every time it reloads: a second or two \
             without answers."
                .into(),
        );
    }
    if remake {
        says.push(
            "sentry's rules that force every device's lookups through the router are gone \
             (the DNS proxy's own forcing is off): they are made again from the proxy's \
             settings, ahead of nothing but the filtered devices' rules."
                .into(),
        );
    }
    if handback {
        says.push(format!(
            "The last device is off, so the job of forcing lookups through the router goes \
             back to the DNS proxy ({}) and sentry's own rules for it are removed: nothing of \
             sentry's is left. The proxy and the firewall are reloaded (a few seconds).",
            family::PROXY
        ));
    }
    if !added.is_empty() {
        says.push(format!(
            "The name lookups of {} go to {} instead of the router: adult and other unwanted \
             sites don't open there by name.",
            and(&added),
            svc.name
        ));
        says.push(format!(
            "How: for each device, one firewall rule sends whatever it asks on the DNS port \
             (53) to {} ({}), matched by the device's MAC. Its lookups over IPv6 are refused, \
             so it asks again over IPv4 at once (sent to a service outside, some devices' \
             IPv6 lookups would get no answer and keep them waiting).",
            svc.name, svc.v4[0]
        ));
    }
    if !removed.is_empty() {
        says.push(format!(
            "{} go back to the router's own lookups: exactly the rules sentry added for {} are \
             removed.",
            cap_first(&and(&removed)),
            if removed.len() == 1 { "it" } else { "them" }
        ));
    }
    if !d.keep.is_empty() {
        let kept: Vec<String> = d.keep.iter().map(|t| label(t)).collect();
        says.push(format!(
            "{} {} filtered as before.",
            cap_first(&and(&kept)),
            if kept.len() == 1 { "stays" } else { "stay" }
        ));
    }
    says.push("Every other device is left as it is.".into());
    if !added.is_empty() {
        says.push(FILTER_LIMITS.into());
        says.push(format!(
            "A filtered device's lookups skip the router's own blocklist; {} blocks malware \
             and scam sites too.",
            svc.name
        ));
        for w in &on {
            let wifi = f
                .blocks
                .device
                .get(&w.tag)
                .is_some_and(|d| d.wifi.is_some());
            if wifi && crate::config::local_mac(&w.mac) {
                says.push(format!(
                    "{} uses a private (random) Wi-Fi address: turn 'private address' off on \
                     the device for this Wi-Fi, or it will slip out of the filter.",
                    label(&w.tag)
                ));
            }
        }
        says.push(format!(
            "sentry can't test from the device itself: once this is kept, open {} on {}; it \
             should be blocked.",
            svc.blocked_test,
            if added.len() == 1 { "it" } else { "each" }
        ));
    }
    says.push(format!(
        "The rules are named {}<tag>: Enter under Filtered by you takes a device off.",
        family::PREFIX
    ));
    let proxy = takeover || handback;
    Ok(Planned {
        title,
        says,
        proofs: if added.is_empty() && !takeover {
            vec![Proof::OwnResolver]
        } else {
            vec![Proof::OwnResolver, Proof::Family]
        },
        // Once the change is made: who comes first, as the firewall has it loaded.
        after: if !want.is_empty() && (takeover || taken || remake) {
            vec![Proof::Precedence]
        } else {
            Vec::new()
        },
        guard: Some(Guarded {
            configs: if proxy {
                "firewall,https-dns-proxy"
            } else {
                "firewall"
            },
            lines: d.lines,
            services: if proxy {
                "https-dns-proxy,firewall"
            } else {
                "firewall"
            },
            closing: Vec::new(),
        }),
        ..Default::default()
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
            counters: None,
            tables: &[],
            forced: None,
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

    /// Three devices this machine knows: two plugged in, one on Wi-Fi with a private MAC.
    fn kids() -> Blocks {
        let mut b = Blocks::default();
        for (tag, n, label, wifi) in [
            ("0000000a", 0x31, "kid's tablet", Some("phy0-ap0")),
            ("0000000b", 0x32, "games console", None),
            ("0000000c", 0x33, "kid's laptop", None),
        ] {
            b.device.insert(
                tag.into(),
                Dev {
                    mac: format!("02:00:5e:00:53:{n:x}"),
                    label: label.into(),
                    zone: "lan".into(),
                    wifi: wifi.map(str::to_string),
                },
            );
        }
        b
    }

    #[test]
    fn the_family_filter_is_one_change_for_any_number_of_devices() {
        // Words: the whole set, sorted; none is a word too.
        let d = Do::filter(["0000000c".to_string(), "0000000a".into(), "0000000a".into()]);
        assert_eq!(d.word(), "filter:0000000a,0000000c");
        assert_eq!(Do::parse("filter:0000000a,0000000c"), Ok(d));
        assert_eq!(
            Do::parse("filter:none"),
            Ok(Do::Filter {
                tags: vec![],
                keep: false
            })
        );
        assert_eq!(
            Do::parse("filter:none:keep").map(|d| d.word()),
            Ok("filter:none:keep".into())
        );
        for bad in [
            "filter:",
            "filter:0000000c,0000000a",
            "filter:kids",
            "filter:02:00:5e:00:53:31",
        ] {
            assert!(Do::parse(bad).is_err(), "{bad}");
        }
        let u = uci("@@firewall\nfirewall.@defaults[0]=defaults\n");
        let b = kids();
        let calm = Counters {
            rules: Some(Vec::new()),
            ..Default::default()
        };
        let f = Facts {
            counters: Some(&calm),
            ..facts(&u, &b, &[])
        };
        let all = ["0000000a", "0000000b", "0000000c"].map(String::from);
        // Nothing asked, nothing there: nothing to do.
        assert!(
            plan(&Do::filter([]), &f)
                .unwrap_err()
                .contains("nothing to change")
        );
        // One device.
        let p = plan(&Do::filter(all[1..2].to_vec()), &f).unwrap();
        assert_eq!(p.title, "Family filter: on for games console");
        assert_eq!(p.proofs, [Proof::OwnResolver, Proof::Family]);
        assert_eq!(staged(&p).lines.len(), 29);
        // Three: one change, one guard, one approval.
        let p = plan(&Do::filter(all.to_vec()), &f).unwrap();
        assert_eq!(
            p.title,
            "Family filter: on for kid's tablet, games console and kid's laptop"
        );
        assert_eq!(staged(&p).lines.len(), 3 * 29);
        let text = p.text().join("\n");
        insta::assert_snapshot!("family_plan_three", text);
        for said in [
            "accidents and casual browsing",
            "DNS over HTTPS",
            "skip the router's own blocklist",
            "kid's tablet uses a private (random) Wi-Fi address",
            "sentry can't test from the device itself: once this is kept, open pornhub.com",
            "Every other device is left as it is.",
        ] {
            assert!(text.contains(said), "{said}:\n{text}");
        }
        // Only the tablet is on Wi-Fi: only it is warned of.
        assert_eq!(text.matches("private (random)").count(), 1);
        // A device this machine has no note of, and none on the router: nothing guessed.
        assert!(
            plan(&Do::filter(["00000099".to_string()]), &f)
                .unwrap_err()
                .contains("tick it on Security again")
        );
        // The firewall not read: sentry can't tell whether it would work.
        let blind = facts(&u, &b, &[]);
        assert!(
            plan(&Do::filter(all.to_vec()), &blind)
                .unwrap_err()
                .contains("couldn't be read")
        );
    }

    const PROXY_ON: &str =
        "@@https-dns-proxy\nhttps-dns-proxy.config=main\nhttps-dns-proxy.config.force_dns='1'\n";

    fn forced() -> Vec<family::Forced> {
        family::parse_forced(&crate::collect::fixture(
            "network/service-https-dns-proxy.json",
        ))
        .unwrap()
    }

    #[test]
    fn where_the_dns_proxy_forces_lookups_the_first_filter_takes_that_over() {
        let u = uci(&format!(
            "@@firewall\nfirewall.@defaults[0]=defaults\n{PROXY_ON}"
        ));
        let b = kids();
        let c = crate::collect::counters::parse(&crate::collect::fixture("network/counters.txt"))
            .unwrap();
        let fd = forced();
        // What the proxy hands over isn't read: nothing guessed.
        let f = Facts {
            counters: Some(&c),
            ..facts(&u, &b, &[])
        };
        let e = plan(&Do::filter(["0000000a".to_string()]), &f).unwrap_err();
        assert!(e.contains("couldn't be read"), "{e}");
        // Read: one change, the takeover with the filter's own rules.
        let f = Facts {
            counters: Some(&c),
            forced: Some(&fd),
            ..facts(&u, &b, &[])
        };
        let p = plan(&Do::filter(["0000000a".to_string(), "0000000b".into()]), &f).unwrap();
        let g = p.guard.as_ref().unwrap();
        assert_eq!(g.configs, "firewall,https-dns-proxy");
        let c2 = Change::parse_action(g.configs, &g.lines.join("; "), g.services, false).unwrap();
        // The proxy is reloaded before the firewall.
        assert_eq!(c2.services, ["https-dns-proxy", "firewall"]);
        // Not a change Claude's own lines may make.
        assert!(Change::parse(g.configs, &g.lines.join("; "), g.services, false).is_err());
        let at = |what: &str| g.lines.iter().position(|l| l.contains(what)).unwrap();
        assert!(
            g.lines
                .contains(&"uci set https-dns-proxy.config.force_dns='0'".to_string())
        );
        // The catch-all and the 853 refusal as the proxy had them, after both devices.
        assert!(at("sentry_filter_0000000b=redirect") < at("sentry_dns_0=redirect"));
        for want in [
            "uci set firewall.sentry_dns_0.src_dport='53'",
            "uci set firewall.sentry_dns_0.dest_port='53'",
            "uci set firewall.sentry_dns_0.family='any'",
            "uci set firewall.sentry_dns_1=rule",
            "uci set firewall.sentry_dns_1.dest='*'",
            "uci set firewall.sentry_dns_1.dest_port='853'",
            "uci set firewall.sentry_dns_1.target='REJECT'",
        ] {
            assert!(g.lines.iter().any(|l| l == want), "{want}: {:#?}", g.lines);
        }
        assert_eq!(p.after, [Proof::Precedence]);
        let text = p.text().join("\n");
        insta::assert_snapshot!("family_plan_takeover", text);
        assert!(text.contains("Nothing changes for the household"), "{text}");
        assert!(text.contains("reloaded: a few seconds"), "{text}");

        // Taken over before: the filter on one more device is ahead of sentry's catch-all.
        let mut text = String::from("@@firewall\nfirewall.@defaults[0]=defaults\n");
        for l in g.lines.iter().filter(|l| !l.contains("https-dns-proxy")) {
            if let Some(x) = l.strip_prefix("uci set ") {
                text.push_str(x);
                text.push('\n');
            }
        }
        text.push_str("@@https-dns-proxy\nhttps-dns-proxy.config=main\nhttps-dns-proxy.config.force_dns='0'\n");
        let taken = uci(&text);
        let calm = crate::collect::counters::Counters {
            rules: Some(Vec::new()),
            ..Default::default()
        };
        let f = Facts {
            counters: Some(&calm),
            forced: Some(&[]),
            ..facts(&taken, &b, &[])
        };
        let p = plan(
            &Do::filter(["0000000a".into(), "0000000b".into(), "0000000c".into()]),
            &f,
        )
        .unwrap();
        let g = p.guard.as_ref().unwrap();
        assert_eq!(g.configs, "firewall", "the proxy isn't touched again");
        assert!(
            g.lines
                .last()
                .unwrap()
                .starts_with("uci reorder firewall.sentry_filter_0000000c="),
            "{:#?}",
            g.lines
        );
        assert_eq!(p.after, [Proof::Precedence]);
        // The last device off: handed back by default, nothing of sentry's left.
        let p = plan(&Do::filter([]), &f).unwrap();
        let g = p.guard.as_ref().unwrap();
        assert_eq!(g.services, "https-dns-proxy,firewall");
        assert!(
            g.lines
                .contains(&"uci set https-dns-proxy.config.force_dns='1'".to_string())
        );
        assert!(
            g.lines
                .contains(&"uci delete firewall.sentry_dns_0".to_string())
        );
        assert!(p.text().join("\n").contains("nothing of sentry's is left"));
        // Or kept, if asked.
        let p = plan(&Do::parse("filter:none:keep").unwrap(), &f).unwrap();
        let g = p.guard.as_ref().unwrap();
        assert!(
            !g.lines
                .iter()
                .any(|l| l.contains("sentry_dns") || l.contains("force_dns"))
        );

        // Another program's forcing: refused, said plainly.
        let mut other = c.clone();
        for r in other.rules.iter_mut().flatten() {
            r.name = r.name.replace("https-dns-proxy", "other-dns");
        }
        let f = Facts {
            counters: Some(&other),
            forced: Some(&fd),
            ..facts(&u, &b, &[])
        };
        let e = plan(&Do::filter(["0000000a".to_string()]), &f).unwrap_err();
        assert!(
            e.contains("can't work on this router yet") && e.contains("other-dns"),
            "{e}"
        );
        // Another nft table on DNS: refused, naming it.
        let tables = vec!["ip other".to_string()];
        let f = Facts {
            counters: Some(&calm),
            tables: &tables,
            ..facts(&u, &b, &[])
        };
        let e = plan(&Do::filter(["0000000a".to_string()]), &f).unwrap_err();
        assert!(
            e.contains("ip other") && e.contains("won't work against it"),
            "{e}"
        );
        // Another zone, where nothing forces DNS: it can.
        let mut g = kids();
        g.device.get_mut("0000000a").unwrap().zone = "guest".into();
        let f = Facts {
            counters: Some(&c),
            ..facts(&u, &g, &[])
        };
        assert!(plan(&Do::filter(["0000000a".to_string()]), &f).is_ok());
    }

    #[test]
    fn taking_devices_off_touches_only_their_rules() {
        let svc = family::service();
        let mut text = String::from("@@firewall\nfirewall.@defaults[0]=defaults\n");
        for (t, n) in [("0000000a", 0x31), ("0000000b", 0x32)] {
            let w = family::Want {
                tag: t.into(),
                mac: format!("02:00:5e:00:53:{n:x}"),
                zone: "lan".into(),
            };
            for l in family::device_lines(&w, "wan", svc).unwrap() {
                text.push_str(l.strip_prefix("uci set ").unwrap());
                text.push('\n');
            }
        }
        let u = uci(&text);
        let b = kids();
        // Taking one off needs no reading of what forces DNS: nothing is added.
        let f = facts(&u, &b, &[]);
        let p = plan(&Do::filter(["0000000a".to_string()]), &f).unwrap();
        assert_eq!(p.title, "Family filter: off for games console");
        assert_eq!(p.proofs, [Proof::OwnResolver]);
        assert_eq!(staged(&p).lines.len(), 3);
        assert!(
            p.text()
                .join("\n")
                .contains("Kid's tablet stays filtered as before")
        );
        let p = plan(&Do::filter([]), &f).unwrap();
        assert_eq!(
            p.title,
            "Family filter: off for kid's tablet and games console"
        );
        assert_eq!(staged(&p).lines.len(), 6);
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

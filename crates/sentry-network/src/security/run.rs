//! Carrying a Security action out on the router (`sentry-network security <name>
//! plan|apply <action>`, the two steps of the `security-action` workflow).
//!
//! `show` only reads: the plan in words, the guard's own preview of its lines, and each
//! proof, so whatever would stop the change is known before the Enter that makes it.
//! `apply` proves again, then hands the config part to the guard (snapshot, the router's
//! own revert armed, commit, reload, confirmed twice on new connections, with the proofs
//! among what must hold before it is kept), then runs the few commands that aren't config.
//! A proof that fails before: nothing is changed. One that fails after: sentry does
//! nothing more and the router takes the change back at its deadline.

use std::time::Duration;

use super::actions::{self, Do, Facts, Planned, Proof};
use super::blocks::{Blocks, Filtered};
use super::family;
use crate::guard::{self, Also, Change, Outcome};
use crate::remote::Router;
use sentry_core::exec::Cmd;

/// Tests against the disposable router: its container may not reload the firewall, so a
/// firewall change is staged, committed and confirmed there with nothing reloaded.
#[cfg(test)]
pub static NO_FIREWALL_RELOAD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn services(asked: &'static str) -> String {
    #[cfg(test)]
    if NO_FIREWALL_RELOAD.load(std::sync::atomic::Ordering::Relaxed) {
        return asked
            .split(',')
            .filter(|s| *s != "firewall")
            .collect::<Vec<_>>()
            .join(",");
    }
    asked.to_string()
}

/// What the family service answers for the canary names, from the router (reads): whether
/// a filtered device is covered whatever the router's resolver does with them.
fn canaries_at_family(r: &Router) -> String {
    let svc = family::service();
    let mut not = Vec::new();
    for (n, _) in family::CANARIES {
        match lookup(r, n, svc.v4[0]) {
            Ok(out) if family::blocked(&out) => {}
            _ => not.push(n),
        }
    }
    match not.as_slice() {
        [] => format!(
            "{} itself refuses the names that keep Firefox's own encrypted lookups and iCloud \
             Private Relay off: on the filtered devices they stay off whatever happens to the \
             router's own entries.",
            svc.name
        ),
        n => format!(
            "{} doesn't refuse {}: on the filtered devices, Firefox's own encrypted lookups or \
             iCloud Private Relay can switch on if the router's own entries go, and then their \
             lookups skip the filter.",
            svc.name,
            n.join(", ")
        ),
    }
}

/// What the DNS proxy hands the firewall now (procd's service data; a read).
fn forced(r: &Router) -> Option<Vec<family::Forced>> {
    r.output(&r.sh(&format!(
        "ubus call service list '{{\"name\":\"{}\"}}'",
        family::PROXY
    )))
    .ok()
    .and_then(|t| family::parse_forced(&t).ok())
}

/// The precedence proof's read: each zone sentry's filter or takeover is in, its NAT chain
/// and its forward chain as fw4 loaded them.
fn chains(r: &Router, zone: &str) -> Result<String, String> {
    #[cfg(test)]
    if NO_FIREWALL_RELOAD.load(std::sync::atomic::Ordering::Relaxed) {
        // The disposable router can't load a firewall: the chains are made from the
        // config the way fw4.uc orders them (the procd-supplied rules first, then the
        // config's redirects in order), by `family::simulated`.
        let uci = crate::collect::uci::collect(r).map_err(|e| e.to_string())?;
        return Ok(family::simulated(
            &uci,
            zone,
            &forced(r).unwrap_or_default(),
        ));
    }
    let script = format!(
        "nft list chain inet fw4 dstnat_{zone}; echo @@forward; nft list chain inet fw4 forward_{zone}"
    );
    r.output(&r.sh(&script))
        .map_err(|e| format!("the firewall's rules for {zone} couldn't be read back ({e})"))
}

/// Tests against the disposable router: its dnsmasq doesn't run, and what it sends to port
/// 53 outside may be answered by whatever the network this machine is on puts in the way.
/// So each lookup proof is taken to hold, or not, as these say (one per proof, in order)
/// instead of being asked. Empty: asked for real.
#[cfg(test)]
pub static LOOKUPS: std::sync::Mutex<Vec<bool>> = std::sync::Mutex::new(Vec::new());

/// One lookup from the router (busybox `nslookup`, a read): what it printed. Err: the
/// router has no lookup tool.
fn lookup(r: &Router, name: &str, server: &str) -> Result<String, String> {
    let o = r
        .sh(&format!(
            "command -v nslookup >/dev/null || exit 127; nslookup '{name}' '{server}' 2>&1"
        ))
        .timeout(Some(Duration::from_secs(20)))
        .run()
        .map_err(|e| e.to_string())?;
    if o.code == 127 {
        return Err("the router has no nslookup, so lookups can't be checked from it".into());
    }
    Ok(o.stdout)
}

/// Prove something from this machine. Ok: what was seen.
pub fn prove(r: &Router, p: Proof) -> Result<String, String> {
    let svc = family::service();
    #[cfg(test)]
    if matches!(p, Proof::OwnResolver | Proof::Family) {
        let mut l = LOOKUPS.lock().unwrap();
        if !l.is_empty() {
            return match l.remove(0) {
                true => Ok(format!("(test) taken to hold: {}", p.says())),
                false => Err(format!("(test) taken to fail: {}", p.says())),
            };
        }
    }
    match p {
        // dnsmasq on the router's own loopback: what every device that isn't filtered asks.
        Proof::OwnResolver => {
            let out = lookup(r, svc.ordinary, "127.0.0.1")?;
            if family::answered(&out).is_empty() {
                return Err(format!(
                    "the router's own resolver didn't answer for {}",
                    svc.ordinary
                ));
            }
            Ok(format!(
                "the router's own resolver answers for {}",
                svc.ordinary
            ))
        }
        // The service from the router: it answers an ordinary name and refuses its test.
        Proof::Family => {
            let server = svc.v4[0];
            let out = lookup(r, svc.ordinary, server)?;
            if family::answered(&out).is_empty() {
                return Err(format!(
                    "{} ({server}) didn't answer the router for {}: devices sent there would \
                     get no answers",
                    svc.name, svc.ordinary
                ));
            }
            let out = lookup(r, svc.blocked_test, server)?;
            if !family::blocked(&out) {
                return Err(format!(
                    "{} ({server}) gave an address for its own test name {}: it isn't \
                     filtering as documented",
                    svc.name, svc.blocked_test
                ));
            }
            Ok(format!(
                "{} answers the router for {} and refuses {}",
                svc.name, svc.ordinary, svc.blocked_test
            ))
        }
        // How the router's resolver answers the canary names: what the check compares.
        Proof::Canaries => {
            let uci = crate::collect::uci::collect(r)
                .map_err(|e| format!("the config couldn't be read: {e}"))?;
            let mut said = Vec::new();
            for (n, _) in family::CANARIES {
                #[cfg(test)]
                let refused = if NO_FIREWALL_RELOAD.load(std::sync::atomic::Ordering::Relaxed) {
                    // (The disposable router's dnsmasq doesn't run: what its config would
                    // make it answer.)
                    family::refused_by_config(&uci, n)
                } else {
                    family::blocked(&lookup(r, n, "127.0.0.1")?)
                };
                #[cfg(not(test))]
                let refused = family::blocked(&lookup(r, n, "127.0.0.1")?);
                said.push(format!(
                    "{n} {}",
                    if refused { "refused" } else { "answered" }
                ));
            }
            let _ = uci;
            Ok(said.join(", "))
        }
        // Who comes first, read back from the firewall as it is loaded now.
        Proof::Precedence => {
            let uci = crate::collect::uci::collect(r)
                .map_err(|e| format!("the config couldn't be read: {e}"))?;
            let mut zones: Vec<String> = family::found(&uci).into_iter().map(|f| f.zone).collect();
            zones.sort();
            zones.dedup();
            let mut seen = Vec::new();
            for z in &zones {
                let rejects = family::dns_found(&uci)
                    .iter()
                    .filter(|(_, kind, src)| kind == "rule" && src == z)
                    .count();
                seen.push(family::precedence(z, &chains(r, z)?, rejects)?);
            }
            Ok(seen.join("; "))
        }
        _ => prove_access(r, p),
    }
}

fn prove_access(r: &Router, p: Proof) -> Result<String, String> {
    match p {
        // Its own connection (never the shared one, which is already logged in) in batch
        // mode, where ssh can't ask for or type a password: it gets in by key or not at
        // all. And the router has a key on file, so it isn't an open door that let it in.
        Proof::KeyLogin => {
            let out = r
                .sh("[ -s /etc/dropbear/authorized_keys ] && echo key-on-file || echo no-key-file")
                .own_connection()
                .timeout(Some(Duration::from_secs(20)))
                .output()
                .map_err(|e| format!("a new connection with a key didn't get in ({e})"))?;
            if out.contains("key-on-file") {
                Ok("a new connection logged in with a key, and the router has one on file".into())
            } else {
                Err(
                    "the router has no key on file (/etc/dropbear/authorized_keys): this login \
                     isn't proof that a key works"
                        .into(),
                )
            }
        }
        // The address ssh reaches the router at is the one a browser here would use.
        Proof::Https => {
            let conn = r
                .sh("echo $SSH_CONNECTION")
                .timeout(Some(Duration::from_secs(20)))
                .output()
                .map_err(|e| e.to_string())?;
            let addr = conn
                .split_whitespace()
                .nth(2)
                .and_then(|a| a.parse::<std::net::IpAddr>().ok())
                .ok_or("the router didn't say which of its addresses this machine reaches")?;
            let url = match addr {
                std::net::IpAddr::V4(a) => format!("https://{a}/"),
                std::net::IpAddr::V6(a) => format!("https://[{a}]/"),
            };
            // (-k: the certificate is the router's own; what is proven is that the page
            // answers over TLS, not who signed it.)
            let code = Cmd::host("curl")
                .args([
                    "-ksS",
                    "-o",
                    "/dev/null",
                    "-m",
                    "8",
                    "-w",
                    "%{http_code}",
                    &url,
                ])
                .timeout(Some(Duration::from_secs(12)))
                .output()
                .map_err(|e| format!("the admin page didn't answer on HTTPS from here ({e})"))?;
            match code.trim().parse::<u16>() {
                Ok(n) if (200..500).contains(&n) => {
                    Ok(format!("the admin page answers on HTTPS from here ({n})"))
                }
                _ => Err(format!(
                    "the admin page didn't answer on HTTPS from here (it said `{}`)",
                    code.trim()
                )),
            }
        }
        Proof::OwnResolver | Proof::Family | Proof::Precedence | Proof::Canaries => prove(r, p),
    }
}

struct Got {
    uci: crate::collect::uci::Uci,
    wan: String,
    blocks: Blocks,
    expected: Vec<String>,
    counters: Option<crate::collect::counters::Counters>,
    tables: Vec<String>,
    forced: Option<Vec<family::Forced>>,
}

fn read(r: &Router, d: &Do) -> Result<Got, String> {
    let uci =
        crate::collect::uci::collect(r).map_err(|e| format!("the config couldn't be read: {e}"))?;
    // The uplink's zone: the firewall's zone that holds the uplink's interface.
    let wan = crate::collect::ifaces::collect(r)
        .ok()
        .map(|i| super::Nets::new(&i, Some(&uci)).wan_zone().to_string())
        .unwrap_or_else(|| "wan".into());
    // Whose DNS redirect comes first: what fw4 counts, and the other tables (both only
    // where the action is the family filter's; reads).
    let (counters, tables) = if matches!(d, Do::Filter { .. }) {
        // (No rules read is not "nothing comes first": the plan then refuses. The
        // disposable router can't list its firewall at all.)
        #[cfg(test)]
        let unread = NO_FIREWALL_RELOAD.load(std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(test))]
        let unread = false;
        (
            crate::collect::counters::collect(r)
                .ok()
                .filter(|c| c.rules.is_some() || unread),
            r.output(&r.sh("nft list ruleset"))
                .map(|t| family::foreign_tables(&t))
                .unwrap_or_default(),
        )
    } else {
        (None, Vec::new())
    };
    // What the DNS proxy hands the firewall: what a takeover reproduces (a read).
    let forced = matches!(d, Do::Filter { .. }).then(|| forced(r)).flatten();
    // (The disposable router has no nft: what fw4 would count is made from procd's data,
    // a DNS redirect of the proxy's in each zone it names.)
    #[cfg(test)]
    let counters = match (counters, &forced) {
        (Some(mut c), Some(f)) if c.rules.is_none() => {
            c.rules = Some(
                f.iter()
                    .filter(|x| x.kind == "redirect")
                    .map(|x| crate::collect::counters::Counted {
                        chain: format!("dstnat_{}", x.src),
                        name: format!("ubus:{}[instance1] redirect 0", family::PROXY),
                        on: "udp:53".into(),
                        packets: 0,
                        bytes: 0,
                        role: crate::collect::counters::Role::DnsRedirect {
                            zone: x.src.clone(),
                            proto: "udp".into(),
                        },
                    })
                    .collect(),
            );
            Some(c)
        }
        (c, _) => c,
    };
    Ok(Got {
        uci,
        wan,
        blocks: Blocks::load(&r.scope),
        expected: guard::expected_forwards(&r.cfg),
        counters,
        tables,
        forced,
    })
}

fn planned(r: &Router, d: &Do) -> Result<(Planned, Got), String> {
    let got = read(r, d)?;
    let p = actions::plan(
        d,
        &Facts {
            uci: &got.uci,
            wan: &got.wan,
            blocks: &got.blocks,
            expected: &got.expected,
            counters: got.counters.as_ref(),
            tables: &got.tables,
            forced: got.forced.as_deref(),
        },
    )?;
    Ok((p, got))
}

fn change(p: &Planned) -> Result<Option<Change>, String> {
    p.guard
        .as_ref()
        .map(|g| {
            let mut c =
                Change::parse_action(g.configs, &g.lines.join("; "), &services(g.services), false)?;
            // The family filter's takeover touches dhcp, which the DNS proxy's reload
            // commits anyway: another package's staged lines there are let through only
            // when they change nothing (`guard::Change::tolerate`).
            if c.configs.iter().any(|x| x == "dhcp") {
                c.tolerate = vec!["dhcp".into()];
            }
            Ok(c)
        })
        .transpose()
}

/// The plan, and whether it could start. Reads only.
pub fn show(r: &Router, d: &Do, say: &mut dyn FnMut(String)) -> Result<(), String> {
    let (p, _) = planned(r, d)?;
    for l in p.text() {
        say(l);
    }
    for proof in &p.proofs {
        say(String::new());
        say(format!("proven now: {}", prove(r, *proof)?));
    }
    if p.proofs.contains(&Proof::Canaries) {
        say(String::new());
        say(canaries_at_family(r));
    }
    if let Some(c) = change(&p)? {
        say(String::new());
        guard::preview(r, &c, say)?;
    }
    say(String::new());
    say("Nothing has changed. The next step does it.".into());
    Ok(())
}

/// How an action ended, as an exit code: 0 done; the guard's codes when it didn't keep
/// the change; 3 when nothing was changed.
pub fn apply(r: &Router, d: &Do, say: &mut dyn FnMut(String)) -> u8 {
    let (p, _) = match planned(r, d) {
        Ok(x) => x,
        Err(e) => {
            say(format!("STOPPED, nothing was changed: {e}"));
            return 3;
        }
    };
    say(p.title.clone());
    // (The canary names: what they are now is what they must stay.)
    let mut canaries_before = None;
    for proof in &p.proofs {
        match prove(r, *proof) {
            Ok(seen) => {
                if *proof == Proof::Canaries {
                    canaries_before = Some(seen.clone());
                }
                say(format!("proven: {seen}"))
            }
            Err(why) => {
                say(format!("STOPPED, nothing was changed: {why}"));
                return 3;
            }
        }
    }
    match change(&p) {
        Err(e) => {
            say(format!("STOPPED, nothing was changed: {e}"));
            return 3;
        }
        Ok(None) => {}
        Ok(Some(c)) => {
            let closing = p
                .guard
                .as_ref()
                .map(|g| g.closing.clone())
                .unwrap_or_default();
            // Held before the change is kept: every proof, once more, on the router as
            // it is now.
            let check = || {
                p.proofs.iter().chain(&p.after).try_for_each(|x| {
                    let seen = prove(r, *x)?;
                    match (&canaries_before, *x) {
                        (Some(b), Proof::Canaries) if *b != seen => Err(format!(
                            "the router answers the names that keep Firefox's own encrypted \
                             lookups and iCloud Private Relay off differently now ({seen}; \
                             before: {b})"
                        )),
                        _ => Ok(()),
                    }
                })
            };
            let also = Also {
                check: (!p.proofs.is_empty() || !p.after.is_empty())
                    .then_some(&check as &dyn Fn() -> Result<(), String>),
                closing: &closing,
            };
            let o = guard::run_also(r, &c, r.cfg.guard.window, &also, say);
            match &o {
                Outcome::Kept => say("KEPT: the change is in place.".into()),
                // (No action here touches Wi-Fi or the uplink, the two cases the guard
                // asks about before keeping: this workflow has no keep step, so one that
                // did would be taken back, and is said so rather than called done.)
                Outcome::Waiting => say(
                    "NOT KEPT: this change needs a keep this action can't ask for; the \
                     router takes it back by itself at its deadline."
                        .into(),
                ),
                Outcome::Stopped(why) => say(format!("STOPPED, nothing was changed: {why}")),
                Outcome::Failed(why) => say(format!("FAILED: {why}")),
                Outcome::Reverted(why) => say(format!(
                    "REVERTED: the change was not kept ({why}). The router restored its \
                     configs and reloaded the same services by itself."
                )),
                Outcome::Unknown(why) => say(format!(
                    "NOT CONFIRMED: {why}. The router restores itself at its deadline; look \
                     at it before trying again."
                )),
            }
            if o == Outcome::Waiting {
                return 1;
            }
            if o != Outcome::Kept {
                return o.code();
            }
        }
    }
    for line in &p.runs {
        say(format!("$ {line}"));
        match r.sh(line).timeout(Some(Duration::from_secs(180))).run() {
            Ok(o) => {
                for l in o.stdout.lines().chain(o.stderr.lines()) {
                    say(format!("  {l}"));
                }
                if o.code != 0 {
                    say(format!("FAILED: it exited {}", o.code));
                    return 1;
                }
            }
            Err(e) => {
                say(format!("FAILED: {e}"));
                return 1;
            }
        }
    }
    settle(r, d, &p);
    if p.proofs.contains(&Proof::Family) {
        let svc = family::service();
        say(format!(
            "sentry can't test from the device itself: open {} on it; it should be blocked.",
            svc.blocked_test
        ));
    }
    say("DONE.".into());
    0
}

/// What this machine remembers, after an action that undid something: the note goes.
fn settle(r: &Router, d: &Do, p: &Planned) {
    let mut b = Blocks::load(&r.scope);
    let before = b.clone();
    match d {
        Do::Unblock { tag } => {
            b.block.remove(tag);
        }
        Do::ForwardOn { section } | Do::ForwardRemove { section } => {
            b.door.remove(section);
        }
        // Who is filtered is what was kept: these tags, the ones already noted keeping
        // their date.
        Do::Filter { tags, .. } => {
            let now = jiff::Timestamp::now().as_second();
            let svc = family::service();
            b.filter.retain(|t, _| tags.contains(t));
            for t in tags {
                b.filter.entry(t.clone()).or_insert_with(|| Filtered {
                    since: now,
                    service: svc.id.into(),
                });
            }
        }
        _ => {}
    }
    if let Some(c) = &p.canaries {
        b.canaries = c.clone();
    }
    if b != before {
        let _ = b.save(&r.scope);
    }
}

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
use super::blocks::Blocks;
use crate::guard::{self, Also, Change, Outcome};
use crate::remote::Router;
use sentry_core::exec::Cmd;

/// Tests against the disposable router: its container may not reload the firewall, so a
/// firewall change is staged, committed and confirmed there with nothing reloaded.
#[cfg(test)]
pub static NO_FIREWALL_RELOAD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn services(asked: &'static str) -> &'static str {
    #[cfg(test)]
    if asked == "firewall" && NO_FIREWALL_RELOAD.load(std::sync::atomic::Ordering::Relaxed) {
        return "";
    }
    asked
}

/// Prove something from this machine. Ok: what was seen.
pub fn prove(r: &Router, p: Proof) -> Result<String, String> {
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
    }
}

struct Got {
    uci: crate::collect::uci::Uci,
    wan: String,
    blocks: Blocks,
    expected: Vec<String>,
}

fn read(r: &Router) -> Result<Got, String> {
    let uci =
        crate::collect::uci::collect(r).map_err(|e| format!("the config couldn't be read: {e}"))?;
    // The uplink's zone: the firewall's zone that holds the uplink's interface.
    let wan = crate::collect::ifaces::collect(r)
        .ok()
        .map(|i| super::Nets::new(&i, Some(&uci)).wan_zone().to_string())
        .unwrap_or_else(|| "wan".into());
    Ok(Got {
        uci,
        wan,
        blocks: Blocks::load(&r.scope),
        expected: guard::expected_forwards(&r.cfg),
    })
}

fn planned(r: &Router, d: &Do) -> Result<(Planned, Got), String> {
    let got = read(r)?;
    let p = actions::plan(
        d,
        &Facts {
            uci: &got.uci,
            wan: &got.wan,
            blocks: &got.blocks,
            expected: &got.expected,
        },
    )?;
    Ok((p, got))
}

fn change(p: &Planned) -> Result<Option<Change>, String> {
    p.guard
        .as_ref()
        .map(|g| Change::parse(g.configs, &g.lines.join("; "), services(g.services), false))
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
    for proof in &p.proofs {
        match prove(r, *proof) {
            Ok(seen) => say(format!("proven: {seen}")),
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
            let check = || p.proofs.iter().try_for_each(|x| prove(r, *x).map(|_| ()));
            let also = Also {
                check: (!p.proofs.is_empty()).then_some(&check as &dyn Fn() -> Result<(), String>),
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
    settle(r, d);
    say("DONE.".into());
    0
}

/// What this machine remembers, after an action that undid something: the note goes.
fn settle(r: &Router, d: &Do) {
    let mut b = Blocks::load(&r.scope);
    let before = b.clone();
    match d {
        Do::Unblock { tag } => {
            b.block.remove(tag);
        }
        Do::ForwardOn { section } | Do::ForwardRemove { section } => {
            b.door.remove(section);
        }
        _ => {}
    }
    if b != before {
        let _ = b.save(&r.scope);
    }
}

//! One session, every target: what the app composes so that a session started on one target
//! can read, plan and act on the others. Targets never know each other; each says what it is
//! ([`SystemLine`]), how a session elsewhere may reach it (its `ProfileFor::Peer` profile) and
//! the rules it keeps ([`Peer`]). The app puts those together (the system text, the merged
//! profile), carries what one slot's session asks of another slot ([`Parcel`], through
//! `Win::outbox`), and keeps one sweep of the secrets a session holds over everything any
//! slot writes down ([`Sweep`]).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use sentry_core::apply::session::Peer;
use sentry_core::apply::sudo::Secret;
use sentry_core::claude::Profile;

use crate::target::TargetId;

/// What a target is, for a session's "the system" section. Nothing private goes in here
/// in a form Claude may read: `what` and what `knows` says are already as the target lets
/// Claude see them; `addrs` and the keys of `knows` are only matched by the app, never
/// printed.
#[derive(Debug, Clone, Default)]
pub struct SystemLine {
    /// "this machine", "a server over ssh", "a home network, through its router".
    pub kind: String,
    /// One line on what it is.
    pub what: String,
    /// How other hosts may know this one: its addresses and names (matched, not shown).
    pub addrs: Vec<String>,
    /// What it knows about hosts by address or name: the key (matched, not shown), and
    /// what it says of whoever has it ("‹nas› on its own routed port, network `dmz`").
    pub knows: Vec<(String, String)>,
    /// Named facts it says of itself for the other targets' screens (`guard.blocked`…):
    /// counts and names it would show itself, never an address. The app only carries
    /// them (`Cx::system`); a target that knows a name reads it.
    pub facts: Vec<(String, String)>,
}

impl SystemLine {
    pub fn fact(&self, name: &str) -> Option<&str> {
        self.facts
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// One target, surveyed: its rules, what it is, and how a session elsewhere reaches it.
#[derive(Debug, Clone, Default)]
pub struct Sys {
    pub peer: Peer,
    pub line: SystemLine,
    pub reach: Profile,
}

/// What one slot's session hands the app for another slot, and what comes back.
pub enum Parcel {
    /// A session opened elsewhere may need this target: it starts if it never has.
    Wake,
    /// Run a plan step's command here, as this target runs its own.
    Step {
        from: TargetId,
        cmd: String,
        sudo: bool,
        what: String,
    },
    /// Whether sudo here needs a password.
    CheckSudo {
        from: TargetId,
    },
    /// The password typed in the session's line, for this target: checked, then held here.
    CheckPassword {
        from: TargetId,
        typed: Secret,
    },
    /// Start this target's workflow for the session's plan.
    Workflow {
        from: TargetId,
        name: String,
        vars: BTreeMap<String, String>,
    },
    /// The security audit is about to read every target (`Why::Facts`).
    Facts,
    /// The security audit this target's session waited for answered (`item`: the item's
    /// id; Ok(None): no longer reported, Ok(Some(how)): still reported, Err(why): it
    /// couldn't check).
    SecAudited {
        item: String,
        answer: crate::secaudit::Answer,
    },
    /// A log entry of this target's, made elsewhere in the window (the audit's task done).
    Entry(Box<sentry_core::maint::log::LogEntry>),
    /// This target's own log entry of what the session ran here.
    Log {
        ok: bool,
        body: String,
        tags: Vec<String>,
    },
    // ---- back to the session's slot
    Started {
        id: u64,
        pid: u32,
    },
    Line {
        shown: String,
        raw: String,
        stderr: bool,
    },
    Exit {
        code: i32,
    },
    /// Said under the step while it waits for the target to be free.
    Waiting(String),
    /// The target stayed busy: the step was never started.
    Deferred(String),
    SudoChecked {
        on: TargetId,
        needs: bool,
    },
    PasswordChecked {
        on: TargetId,
        ok: bool,
    },
    /// The target holds its password (or just forgot it).
    Held {
        on: TargetId,
    },
    Forgot {
        on: TargetId,
    },
    WorkflowEnded {
        on: TargetId,
        name: String,
        ok: bool,
        note: String,
    },
}

/// The secret values the window's sessions hold, for as long as it is open: every log
/// entry and plan document any slot writes goes through `clean`, whichever target the
/// value came from. In memory only.
#[derive(Clone, Default)]
pub struct Sweep(Arc<Mutex<Vec<(String, String)>>>);

impl Sweep {
    /// `secrets`: (what stands for it, the value).
    pub fn add(&self, secrets: Vec<(String, String)>) {
        let Ok(mut held) = self.0.lock() else { return };
        for (label, v) in secrets {
            if !held.iter().any(|(_, x)| *x == v) {
                held.push((label, v));
            }
        }
    }

    /// None: nothing of it is a secret.
    pub fn clean(&self, text: &str) -> Option<String> {
        let held = self.0.lock().ok()?;
        if !held.iter().any(|(_, v)| text.contains(v.as_str())) {
            return None;
        }
        let mut out = text.to_string();
        for (label, v) in held.iter() {
            out = out.replace(v.as_str(), label);
        }
        Some(out)
    }

    /// The values held (for a target that sweeps what it writes by itself).
    pub fn values(&self) -> Vec<String> {
        self.0
            .lock()
            .map(|h| h.iter().map(|(_, v)| v.clone()).collect())
            .unwrap_or_default()
    }
}

/// What every session's Claude is told, on every target: it never sends the user to do
/// something, and how a value gets from where it exists to where it is needed.
pub const HANDS: &str = "\n\nNEVER tell me to enter, paste, set, type or run something myself: not in \
sentry, not \"in your own session\" on a host, not \"before approving the plan\". Whatever has to \
happen is a step of your plan, and sentry carries it out. A value one step produces and another \
needs travels inside the plan: on the step that prints it add `capture = \"name\"` (the last \
line the step prints on stdout, trimmed, is kept; so make the command print the value alone, \
last) and `secret = true` when it is a key, token or password; later steps use it as \
`'{{name}}'`, always inside single quotes. sentry fills it in when the step runs: you never \
see a secret's value, it is in no plan, log or file, so never try to read it back or print it. \
A value that exists only in my head or my password manager (and only such a value) is asked \
for by a step of its own: `[[step]]` with `ask = \"name\"`, `prompt = \"one line saying what \
to type\"` and `secret = true`; when the plan reaches it I type it into this session's own \
line, hidden, and the plan goes on by itself. That is the ONLY way to get a value from me. \
When a config option's value is a secret (an API key, a passphrase), set it with a plan step \
that uses a captured or asked value (`uci set …api_key='{{key}}'`), never a literal you made \
up or read, and never by asking me to put it there. Don't write a check that waits for me to \
have done something.";

/// The system as a session is told it: every target, what it is, how they connect as far
/// as their configs say, and that a cause is fixed where it is. Empty with one target.
pub fn text(all: &[Sys], home: &str) -> String {
    if all.len() < 2 {
        return String::new();
    }
    let mut out = String::from(
        "\n\n## The system\nThis session is not confined to the target it started on. sentry \
         has these targets open, and they are parts of ONE system:\n",
    );
    for s in all {
        out.push_str(&format!(
            "- `{}` ({}; on screen \"{}\"): {}{}\n",
            s.peer.name(),
            s.line.kind,
            s.peer.title,
            s.line.what,
            if s.peer.id == home {
                " This session started here."
            } else {
                ""
            }
        ));
    }
    for line in links(all) {
        out.push_str(&format!("- {line}\n"));
    }
    out.push_str(
        "When something is refused, fails or can't be reached, find the cause wherever it is: \
         read on any target through that target's own gateway (described below; each keeps \
         its own rules, and what a router prints stays scrubbed). If the cause is on another \
         target, fix it THERE: put each plan step on the target it belongs to with \
         `on = \"<id>\"` in the step (left out: the target this session started on), then \
         retry what failed. One plan may have steps on several targets; I approve it once, \
         and sentry runs each step on its target with that target's own mechanics (its sudo \
         password, asked here once; a router's guarded configs only through its guard step, \
         `workflow = \"guarded-change\"` with `on` that network; upgrades and reboots only \
         as that target's workflow steps). Never give up, hand the rest to me or call it \
         failed because the cause is on another target: only when the cause is outside \
         every target listed here is the verdict `failed`, and then it says exactly what is \
         wrong and where.\n",
    );
    out
}

/// How the targets connect, as far as one knows another: "`srv:x` is, as `net:home` knows
/// it, ‹x› on its own routed port".
pub fn links(all: &[Sys]) -> Vec<String> {
    let mut out = Vec::new();
    for a in all {
        for b in all.iter().filter(|b| b.peer.id != a.peer.id) {
            let mut said: Vec<&str> = Vec::new();
            for (key, says) in &b.line.knows {
                if a.line.addrs.iter().any(|x| x.eq_ignore_ascii_case(key))
                    && !said.contains(&says.as_str())
                {
                    said.push(says);
                }
            }
            if !said.is_empty() {
                out.push(format!(
                    "`{}` is, as `{}` knows it: {}.",
                    a.peer.name(),
                    b.peer.name(),
                    said.join("; ")
                ));
            }
        }
    }
    out
}

const WEB: [&str; 2] = ["WebFetch", "WebSearch"];

/// What a session is told once it has no web.
pub const NO_WEB: &str = "\n\nThis session has no web access (WebFetch and WebSearch are off): \
it has read from the router, and what a router prints is partly other people's text. What you \
need from upstream's notes is in the review or the plan you were given, or ask me for it.";

/// A session's profile: its own target's, plus how it reaches every other target, with
/// every target's denials kept (what one denies stays denied whoever's session it is).
/// The web is the one thing that goes by what the session has read, not by who is in the
/// window: it is the home target's to give (a router's session never has it), another
/// target's denial of it doesn't take it away, and `web` false (the session has read from
/// a router: `Session::web_goes`) does, for good.
pub fn merged(mut p: Profile, all: &[Sys], home: &str, write_granted: bool, web: bool) -> Profile {
    p.system.push_str(HANDS);
    p.system.push_str(&text(all, home));
    for s in all.iter().filter(|s| s.peer.id != home) {
        p.system.push_str(&format!(
            "\n### `{}`: how you reach it\n{}\n",
            s.peer.name(),
            s.reach.system
        ));
        for (mine, theirs) in [
            (&mut p.tools, &s.reach.tools),
            (&mut p.allowed, &s.reach.allowed),
            (&mut p.denied, &s.reach.denied),
            (&mut p.dirs, &s.reach.dirs),
        ] {
            for x in theirs {
                if !mine.contains(x) && !WEB.contains(&x.as_str()) {
                    mine.push(x.clone());
                }
            }
        }
    }
    if !web {
        let had = p.allowed.iter().any(|a| WEB.contains(&a.as_str()));
        p.tools.retain(|t| !WEB.contains(&t.as_str()));
        p.allowed.retain(|t| !WEB.contains(&t.as_str()));
        for d in WEB {
            if !p.denied.iter().any(|x| x == d) {
                p.denied.push(d.into());
            }
        }
        if had {
            p.system.push_str(NO_WEB);
        }
    }
    // (A file I granted for writing lifts the bare denial, as in a session alone; the
    // paths a target denies stay denied.)
    if write_granted {
        p.denied.retain(|d| d != "Edit" && d != "Write");
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys(id: &str, addrs: &[&str], knows: &[(&str, &str)], denied: &[&str]) -> Sys {
        Sys {
            peer: Peer {
                id: id.into(),
                title: id
                    .trim_start_matches("srv:")
                    .trim_start_matches("net:")
                    .into(),
                ..Default::default()
            },
            line: SystemLine {
                kind: "a host".into(),
                what: "It is one.".into(),
                addrs: addrs.iter().map(|s| s.to_string()).collect(),
                knows: knows
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                facts: Vec::new(),
            },
            reach: Profile {
                system: format!("call {id}"),
                tools: vec!["Bash".into()],
                allowed: vec![format!("Bash(gw {id}:*)")],
                denied: denied.iter().map(|s| s.to_string()).collect(),
                dirs: Vec::new(),
            },
        }
    }

    /// How targets connect is said in the words of the one that knows, and the address
    /// they were matched by is never printed.
    #[test]
    fn a_server_is_found_in_what_the_network_knows_by_its_address() {
        let all = [
            sys("", &[], &[], &[]),
            sys("srv:myserver", &["myserver", "203.0.113.10"], &[], &[]),
            sys(
                "net:home",
                &[],
                &[
                    (
                        "203.0.113.10",
                        "‹nas› on a routed port of its own, in the network `dmz`",
                    ),
                    (
                        "203.0.113.10",
                        "the destination of the port forward `web_https` (tcp from zone wan)",
                    ),
                    ("192.0.2.20", "‹host-1›, a Wi-Fi host"),
                ],
                &["WebFetch", "Read(//etc/secret)"],
            ),
        ];
        assert_eq!(
            links(&all),
            [
                "`srv:myserver` is, as `net:home` knows it: ‹nas› on a routed port of its own, in the network `dmz`; the destination of the port forward `web_https` (tcp from zone wan)."
            ]
        );
        let t = text(&all, "net:home");
        assert!(
            !t.contains("203.0.113.10") && !t.contains("192.0.2.20"),
            "{t}"
        );
        assert!(
            t.contains("- `local` (a host; on screen \"\"): It is one."),
            "{t}"
        );
        assert!(
            text(&all[..1], "").is_empty(),
            "one target: no system to describe"
        );

        // The merged profile: every other target's gateway, and every target's denials,
        // whoever's session it is. A write I granted lifts only the bare denial.
        let own = Profile {
            system: "mine".into(),
            tools: vec!["Bash".into(), "WebFetch".into()],
            allowed: vec!["WebFetch".into()],
            denied: vec!["Edit".into()],
            dirs: Vec::new(),
        };
        let p = merged(own.clone(), &all, "srv:myserver", false, true);
        assert!(
            p.system.starts_with("mine")
                && p.system
                    .contains("### `net:home`: how you reach it\ncall net:home")
        );
        assert!(!p.system.contains("call srv:myserver"));
        assert_eq!(
            p.allowed,
            ["WebFetch", "Bash(gw :*)", "Bash(gw net:home:*)"]
        );
        // The web is the session's own until it has read from a router: another
        // target's denial of it is not merged in.
        assert_eq!(p.denied, ["Edit", "Read(//etc/secret)"]);
        assert!(p.tools.iter().any(|t| t == "WebFetch") && !p.system.contains("no web access"));
        let p = merged(own.clone(), &all, "srv:myserver", true, true);
        assert_eq!(p.denied, ["Read(//etc/secret)"]);
        // Once it has: gone from the tools and the allow rules, denied, and said.
        let p = merged(own, &all, "srv:myserver", false, false);
        assert!(!p.tools.iter().any(|t| t == "WebFetch"));
        assert_eq!(p.allowed, ["Bash(gw :*)", "Bash(gw net:home:*)"]);
        assert_eq!(
            p.denied,
            ["Edit", "Read(//etc/secret)", "WebFetch", "WebSearch"]
        );
        assert!(p.system.ends_with(NO_WEB));
    }
}

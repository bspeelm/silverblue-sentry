//! How Claude's commands reach a router: `sentry-network exec <name> -- <argv>` (chats and
//! reviews: one command, reads only) and `sentry-network run <name> -- '<line>'` (a
//! session: a line). Both read the line with `policy` before anything else happens. Only a
//! `Read` is carried out, and not as written: `read::Plan` is what sentry understood of
//! it, and each of its commands is sent to the router rebuilt (the program from sentry's
//! list, every argument quoted here), as root over ssh. What it printed is scrubbed
//! (`redact::Scrub`) before anything else is done with it; a line's filters (`| grep …`)
//! are then done here, on the scrubbed text. A `Change` is refused in the words that make
//! it a request for the user; everything else is refused with what to do instead. There
//! is no queue of root reads here: the login is root, a read simply runs.

use crate::policy::{self, Class};
use crate::read::{Join, Plan, Source};
use crate::redact::Scrub;
use crate::remote::Router;
use sentry_app::remote::gateway::Held;

pub const RUN: &str = "sentry-network run";
pub const EXEC: &str = "sentry-network exec";

fn held(v: policy::Verdict, chat: bool) -> Held {
    match v.class {
        // The words `claude::requested` knows: the session shows the user the line.
        Class::Change if !chat => Held::Asks,
        Class::Change => Held::Never(format!(
            "{}: only reads go through `exec`. Changes aren't made in a conversation",
            v.why
        )),
        _ => Held::Never(v.refusal().unwrap_or(v.why)),
    }
}

/// A session's line as it is carried out, or what it is held for.
pub fn runnable(line: &str) -> Result<Plan, Held> {
    crate::read::plan(line).map_err(|_| held(policy::verdict(line), false))
}

/// A chat's command (its words) as it is carried out, or why it is refused: anything but
/// a read.
pub fn readable(argv: &[String]) -> Result<Plan, Held> {
    crate::read::plan_argv(argv).map_err(|_| held(policy::verdict_argv(argv), true))
}

/// What ran on the router, for the tests that prove it: with `SENTRY_GATEWAY_TRACE=<file>`
/// every line sent is appended there, exactly as sent.
fn trace(line: &str) {
    use std::io::Write;
    if let Some(p) = std::env::var_os("SENTRY_GATEWAY_TRACE")
        && let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
    {
        let _ = writeln!(f, "{line}");
    }
}

/// What one command printed, scrubbed.
#[derive(Debug, Default, PartialEq)]
pub struct Said {
    pub out: String,
    pub err: String,
    pub code: i32,
}

/// Carry a read out: `remote` runs one rebuilt line on the router and gives back what it
/// printed, already scrubbed. The joiners and the filters are done here.
pub fn carry_out(plan: &Plan, remote: &mut dyn FnMut(&str) -> Result<Said, String>) -> Said {
    let mut all = Said::default();
    for l in &plan.lines {
        let skip = match l.join {
            Join::First | Join::Seq => false,
            Join::And => all.code != 0,
            Join::Or => all.code == 0,
        };
        if skip {
            continue;
        }
        let mut said = match &l.source {
            Source::Remote(r) => match remote(&r.line()) {
                Ok(s) => s,
                Err(e) => {
                    all.err.push_str(&format!("{e}\n"));
                    all.code = 125;
                    return all;
                }
            },
            Source::Echo(t) => Said {
                out: t.clone(),
                ..Default::default()
            },
            Source::Status(c) => Said {
                code: *c,
                ..Default::default()
            },
            Source::Sleep(n) => {
                std::thread::sleep(std::time::Duration::from_secs(*n));
                Said::default()
            }
        };
        for f in &l.filters {
            let (out, code) = f.filter.run(&said.out);
            said.out = out;
            said.code = code;
        }
        if l.discard {
            said.out.clear();
        }
        all.out.push_str(&said.out);
        all.err.push_str(&said.err);
        all.code = said.code;
    }
    all
}

fn go(prog: &str, r: &Router, plan: Result<Plan, Held>, shown: &str) -> u8 {
    let plan = match plan {
        Ok(p) => p,
        Err(Held::Asks) => {
            eprintln!("{prog}: this needs root and requires approval: {shown}");
            return 126;
        }
        Err(Held::Never(why)) => {
            eprintln!("{prog}: not run: {why}");
            return 126;
        }
    };
    // What the scrubbing is made from is read only once the line is allowed, and before
    // anything of it runs: when that can't be read, nothing is run and nothing is shown.
    let scrub = match Scrub::read(r) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{prog}: not run: {e}");
            return 125;
        }
    };
    let mut remote = |line: &str| -> Result<Said, String> {
        trace(line);
        match r
            .sh(line)
            .timeout(Some(std::time::Duration::from_secs(120)))
            .run()
        {
            Ok(o) => Ok(Said {
                out: scrub.text(&o.stdout),
                err: scrub.text(&o.stderr),
                code: o.code,
            }),
            Err(e) => {
                let e: sentry_app::remote::Error = e.into();
                Err(format!("{prog}: {e}"))
            }
        }
    };
    let said = carry_out(&plan, &mut remote);
    print!("{}", said.out);
    eprint!("{}", said.err);
    said.code.clamp(0, 255) as u8
}

/// `run <name> -- '<line>'`.
pub fn run_cli(r: &Router, line: &str) -> u8 {
    go(RUN, r, runnable(line), line)
}

/// `exec <name> -- <argv…>`: each argument one word, never syntax.
pub fn exec_cli(r: &Router, argv: &[String]) -> u8 {
    go(EXEC, r, readable(argv), &argv.join(" "))
}

/// How Claude is told what reads freely.
pub fn summary() -> &'static str {
    "ubus list; ubus call <object> <method> for the methods that only read (board, info, \
     status, dump, get_clients, list, …); uci show|changes|export [<config>] and uci get \
     <config>.<section>.<option> (one config per call, no flag but -q; secrets come back as \
     tags); nft list …; fw4 print|check; logread [-l <n>] [-e <pattern>] [-t]; dmesg; `ip \
     <object> [show [dev <device>]]` spelled out (addr, link, route, neigh, rule; no \
     addresses or prefixes to select by); iw dev|phy|list, iw dev <if> info|link, iw dev \
     <if> station dump (no scan); iwinfo; brctl show|showmacs; netstat -lntup; apk \
     --no-network list|info|search|version|policy|query; /etc/init.d/<service> \
     status|enabled|running; service; wifi status; ifstatus <interface>; ps w; top -b -n 1; \
     df; free; uptime; date; uname; sysctl <key>; ls, stat, du, test -e and find (by name, \
     type, depth, age, size) on full paths; cat of named files: /proc/loadavg, meminfo, \
     stat, cpuinfo, mounts and the like, anything under /proc/net, /proc/sys, \
     /sys/class/net, /sys/class/thermal and /sys/class/ieee80211 (a `*` is expanded only \
     there), the lease files (/tmp/dhcp.leases, /tmp/odhcpd.leases), /etc/hosts, \
     /etc/openwrt_release, /etc/board.json, /etc/init.d/*, /usr/share/*. Literal arguments \
     only: no variables, substitutions, backslashes, comments or `cd`; quote with single \
     quotes. Nothing else reads without asking: not awk, sed, tr, od, hexdump or strings, \
     not /etc/config/* (use uci show), not a file that isn't on that list"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Network;

    /// A router nobody can reach: connecting to it would fail (125), so a 126 says the
    /// line was turned down before any connection was tried.
    fn nowhere() -> Router {
        let cfg = Network {
            router: crate::config::RouterCfg {
                ssh: Some("nobody@host.invalid".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        Router::new("gw-test", &cfg)
    }

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn each_class_is_held_in_its_own_words() {
        assert!(runnable("uci show dhcp").is_ok());
        assert!(matches!(runnable("apk add tcpdump"), Err(Held::Asks)));
        let said = |line: &str| match runnable(line) {
            Err(Held::Never(why)) => why,
            other => panic!("{line}: {:?}", other.map(|p| p.shown())),
        };
        assert!(said("uci commit network").contains("ONE guard step"));
        assert!(said("/etc/init.d/network restart").contains("guarded-change"));
        assert!(said("reboot").contains("workflow step"));
        assert!(said("apk upgrade").contains("package-update"));
        assert!(said("cat /etc/shadow").contains("secrets"));
        assert!(said("sysupgrade -b /tmp/x").contains("encrypted"));
        // A chat never gets a request out of it.
        assert!(readable(&argv("uci show dhcp")).is_ok());
        assert!(
            matches!(readable(&argv("apk add tcpdump")), Err(Held::Never(w)) if w.contains("only reads"))
        );
        assert!(matches!(readable(&argv("reboot")), Err(Held::Never(_))));
    }

    #[test]
    fn a_refused_line_makes_no_connection() {
        let r = nowhere();
        for line in [
            "apk add tcpdump",
            "uci commit network",
            "wifi reload",
            "reboot",
            "sysupgrade /tmp/x.bin",
            "cat /etc/shadow",
            "cat /etc/config/wireless",
            "frobnicate",
            "echo \"$(touch /tmp/x)\"",
        ] {
            assert_eq!(run_cli(&r, line), 126, "{line}");
            assert_eq!(exec_cli(&r, &[line.to_string()]), 126, "{line} (one word)");
            assert_eq!(
                exec_cli(&r, &["sh".into(), "-c".into(), line.to_string()]),
                126,
                "sh -c {line}"
            );
        }
        assert_eq!(exec_cli(&r, &argv("uci commit network")), 126);
        assert_eq!(exec_cli(&r, &argv("logger hello")), 126);
        // A read is let through, and only then is the router asked for anything: it
        // can't be reached, so nothing is shown (125).
        assert_eq!(run_cli(&r, "uci show dhcp"), 125);
        assert_eq!(exec_cli(&r, &argv("uci show dhcp")), 125);
    }

    #[test]
    fn exec_hands_the_router_words_never_syntax() {
        // A `;` in a word is text: the word isn't a config's name, so it isn't a read,
        // and nothing of it is ever a second command.
        let words: Vec<String> = ["uci", "show", "dhcp; reboot"].map(String::from).to_vec();
        assert!(matches!(readable(&words), Err(Held::Never(_))));
        let p = readable(&["grep".into(), "a; reboot".into(), "/proc/version".into()]).unwrap();
        assert_eq!(p.remotes().len(), 1);
        assert_eq!(p.remotes()[0].line(), "cat '/proc/version'");
    }

    /// A router that prints what it is told to, and keeps what it was sent.
    fn fake<'a>(
        sent: &'a mut Vec<String>,
        answers: &'a [(&'a str, &'a str, i32)],
    ) -> impl FnMut(&str) -> Result<Said, String> + 'a {
        move |line: &str| {
            sent.push(line.to_string());
            let (_, out, code) = answers
                .iter()
                .find(|(l, _, _)| *l == line)
                .unwrap_or_else(|| panic!("not expected on the router: {line}"));
            Ok(Said {
                out: out.to_string(),
                err: String::new(),
                code: *code,
            })
        }
    }

    #[test]
    fn a_read_is_carried_out_a_command_at_a_time_and_filtered_here() {
        let answers = [
            (
                "uci 'show' 'wireless'",
                "wireless.r.ssid='‹ssid-1›'\nwireless.r.key='redacted:0a1b2c3d'\n",
                0,
            ),
            ("test '-e' '/tmp/x'", "", 1),
            ("cat '/proc/uptime'", "100.00 50.00\n", 0),
            ("uptime", "up\n", 0),
        ];
        let run = |line: &str| {
            let mut sent = Vec::new();
            let said = carry_out(&runnable(line).unwrap(), &mut fake(&mut sent, &answers));
            (said, sent)
        };
        // The filter sees what the scrubbing left: the pattern never reaches the router,
        // and a count of the real key's first letter is a count of nothing.
        let (said, sent) = run("uci show wireless | grep -c \"key='c\"");
        assert_eq!(sent, ["uci 'show' 'wireless'"]);
        assert_eq!((said.out.as_str(), said.code), ("0\n", 1));
        let (said, _) = run("uci show wireless | grep key | cut -d= -f2");
        assert_eq!(said.out, "'redacted:0a1b2c3d'\n");
        // `&&` and `||` go by the status of what came before, here.
        let (said, sent) = run("test -e /tmp/x && uptime; echo done");
        assert_eq!(sent, ["test '-e' '/tmp/x'"]);
        assert_eq!((said.out.as_str(), said.code), ("done\n", 0));
        let (said, sent) = run("test -e /tmp/x || uptime");
        assert_eq!(sent.len(), 2);
        assert_eq!(said.out, "up\n");
        let (said, sent) = run("uci show wireless | grep -q nothing || echo none");
        assert_eq!(sent.len(), 1);
        assert_eq!(said.out, "none\n");
        let (said, _) = run("cut -d' ' -f2 /proc/uptime | wc -c >/dev/null; true && false");
        assert_eq!((said.out.as_str(), said.code), ("", 1));
        // The router gone mid-line: nothing more is tried.
        let mut n = 0;
        let said = carry_out(&runnable("uptime; uptime; echo x").unwrap(), &mut |_| {
            n += 1;
            Err("unreachable".into())
        });
        assert_eq!((n, said.code, said.out.as_str()), (1, 125, ""));
    }
}

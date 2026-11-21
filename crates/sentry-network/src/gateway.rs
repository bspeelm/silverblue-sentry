//! How Claude's commands reach a router: `sentry-network exec <name> -- <argv>` (chats and
//! reviews: one command, reads only) and `sentry-network run <name> -- '<line>'` (a
//! session: a shell line). Both read the line with `policy::classify` before anything
//! else happens: only a `Read` is run, as root over ssh, and what it printed is scrubbed
//! (`redact::Scrub`) before a byte of it is shown. A `Change` is refused in the words that
//! make it a request for the user; everything else is refused with what to do instead.
//! There is no queue of root reads here: the login is root, a read simply runs.

use crate::policy::{self, Class};
use crate::redact::Scrub;
use crate::remote::Router;
use sentry_app::remote::gateway::{self as shared, Held};

pub const RUN: &str = "sentry-network run";
pub const EXEC: &str = "sentry-network exec";

/// What a session's line is held for, if it isn't simply run.
pub fn runnable(line: &str) -> Result<(), Held> {
    let v = policy::verdict(line);
    match v.class {
        Class::Read => Ok(()),
        // The words `claude::requested` knows: the session shows the user the line.
        Class::Change => Err(Held::Asks),
        _ => Err(Held::Never(v.refusal().unwrap_or(v.why))),
    }
}

/// What a chat's command is refused for, if it is: anything but a read.
pub fn readable(line: &str) -> Result<(), Held> {
    let v = policy::verdict(line);
    match v.class {
        Class::Read => Ok(()),
        Class::Change => Err(Held::Never(format!(
            "{}: only reads go through `exec`. Changes aren't made in a conversation",
            v.why
        ))),
        _ => Err(Held::Never(v.refusal().unwrap_or(v.why))),
    }
}

/// What the scrubbing is made from is read only once the line is allowed, and before it
/// runs: when that can't be read, nothing is run and nothing is shown.
type Filter = Box<dyn Fn(&str) -> String>;

fn scrubbed(
    router: &Router,
) -> impl FnOnce(&sentry_app::remote::Remote) -> Result<Filter, String> + '_ {
    move |_| {
        let s = Scrub::read(router)?;
        Ok(Box::new(move |t: &str| s.text(t)) as Filter)
    }
}

/// `run <name> -- '<line>'`.
pub fn run_cli(r: &Router, line: &str) -> u8 {
    shared::run_cli_with(RUN, r, line, runnable, scrubbed(r))
}

/// `exec <name> -- <argv…>`: each argument one word for the router's shell.
pub fn exec_cli(r: &Router, argv: &[String]) -> u8 {
    let line = argv
        .iter()
        .map(|a| sentry_core::exec::sh_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    shared::run_cli_with(EXEC, r, &line, readable, scrubbed(r))
}

/// How Claude is told what reads freely.
pub fn summary() -> &'static str {
    "ubus list; ubus call <object> <method> for the methods that only read (board, info, \
     status, dump, get_clients, list, …); uci show|get|changes|export (one config per call, \
     no flag but -q; secrets come back as tags); nft list …; fw4 print|check; logread \
     (-l <n>, -e <regex>; never -f); dmesg; `ip <object>` alone or with show (spelled out: \
     no abbreviated verbs); iw's dump/info/link forms; iwinfo; brctl show; netstat -lntup; \
     apk --no-network list|info|search|version|policy; sysupgrade -l; \
     /etc/init.d/<service> status|enabled; ubus call service list; ps w; df; free; ls, stat \
     and find anywhere; cat/grep/head/tail/wc of files under /proc and /sys, the lease \
     files (/tmp/dhcp.leases, /tmp/odhcpd.leases), /etc/openwrt_release, /etc/board.json, \
     /etc/hosts, /etc/init.d/* and /usr/share/*, named by their full path. Any other \
     file, a ping, and anything that cuts lines up (cut, tr, sed s///, awk after a pipe, \
     grep -o) is a request, not a read: sentry hides secrets, MACs and names by the line \
     they stand in, so print whole lines"
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

    #[test]
    fn each_class_is_held_in_its_own_words() {
        assert_eq!(runnable("uci show dhcp"), Ok(()));
        assert_eq!(runnable("apk add tcpdump"), Err(Held::Asks));
        let said = |line: &str| match runnable(line) {
            Err(Held::Never(why)) => why,
            other => panic!("{line}: {other:?}"),
        };
        assert!(said("uci commit network").contains("ONE guard step"));
        assert!(said("/etc/init.d/network restart").contains("guarded-change"));
        assert!(said("reboot").contains("workflow step"));
        assert!(said("apk upgrade").contains("package-update"));
        assert!(said("cat /etc/shadow").contains("secrets"));
        assert!(said("sysupgrade -b /tmp/x").contains("encrypted"));
        // A chat never gets a request out of it.
        assert_eq!(readable("uci show dhcp"), Ok(()));
        assert!(
            matches!(readable("apk add tcpdump"), Err(Held::Never(w)) if w.contains("only reads"))
        );
        assert!(matches!(readable("reboot"), Err(Held::Never(_))));
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
        ] {
            assert_eq!(run_cli(&r, line), 126, "{line}");
            assert_eq!(exec_cli(&r, &[line.to_string()]), 126, "{line} (one word)");
        }
        let argv = |s: &str| s.split_whitespace().map(str::to_string).collect::<Vec<_>>();
        assert_eq!(exec_cli(&r, &argv("uci commit network")), 126);
        assert_eq!(exec_cli(&r, &argv("logger hello")), 126);
        // A read is let through, and only then is the router asked for anything: it
        // can't be reached, so nothing is shown (125).
        assert_eq!(run_cli(&r, "uci show dhcp"), 125);
        assert_eq!(exec_cli(&r, &argv("uci show dhcp")), 125);
    }

    #[test]
    fn exec_hands_the_router_words_never_syntax() {
        // Each argument is quoted: a `;` in one is text, and the line it makes is read
        // as that one command.
        let line = ["uci", "show", "dhcp; reboot"]
            .iter()
            .map(|a| sentry_core::exec::sh_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(line, "uci show 'dhcp; reboot'");
        assert_eq!(policy::classify(&line), Class::Read);
    }
}

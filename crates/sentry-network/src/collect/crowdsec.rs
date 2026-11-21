//! CrowdSec's firewall bouncer, where the router has it: read only, in the services' exec
//! (no exec of its own). Whether it's switched on, how long it has run, and how many
//! addresses its nft sets hold. The addresses are counted on the router (an `awk` over
//! `nft list table`): only the two numbers come back, so no report, screen or prompt can
//! hold one. A router without the package prints no `@@crowdsec` part: `None`, nothing shown.
//!
//! The package wasn't on a router at hand: the names are read from its source. OpenWrt's
//! `crowdsec-firewall-bouncer` (`net/crowdsec-firewall-bouncer/files/` in
//! <https://github.com/openwrt/packages>: `crowdsec-firewall-bouncer.initd`,
//! `crowdsec.config`) installs `/usr/bin/cs-firewall-bouncer`, is the procd service
//! `crowdsec-firewall-bouncer`, reads `/etc/config/crowdsec` (`config bouncer`, `option
//! enabled '0'` as shipped) and makes the tables `ip crowdsec` and `ip6 crowdsec6`. The
//! bouncer fills `crowdsec-blacklists` / `crowdsec6-blacklists` there, and newer ones a set
//! per origin beside them (`pkg/nftables/nftables_context.go` in
//! <https://github.com/crowdsecurity/cs-firewall-bouncer>), so every set in the table is
//! counted. How `nft list table` prints a set's elements is from memory of nftables, not
//! from this package: the fixture is modelled, and a table that can't be read is `None`
//! for its count, never an error.

use serde::{Deserialize, Serialize};

/// The procd service.
pub const SERVICE: &str = "crowdsec-firewall-bouncer";

/// Counts every element of every set in the table on stdin; prints nothing when it holds no
/// set (no such table). Elements are `a, b,` over lines between `elements = {` and `}`.
const COUNT: &str = "awk '/^[ \\t]*set /{s=1} /elements = [{]/{e=1} e{n+=gsub(/,/,\",\")} \
    e&&/[}]/{e=0;n++} END{if(s)print n+0}'";

/// The part's lines: the switch, each family's count, how long the process has run.
fn body() -> String {
    format!(
        "echo \"enabled=$(uci -q get crowdsec.@bouncer[0].enabled)\"\n\
         echo \"v4=$(nft list table ip crowdsec 2>/dev/null | {COUNT})\"\n\
         echo \"v6=$(nft list table ip6 crowdsec6 2>/dev/null | {COUNT})\"\n\
         p=$(pidof cs-firewall-bouncer); p=${{p##* }}\n\
         if [ -n \"$p\" ]; then awk 'NR==FNR{{u=$1;next}}{{print \"age=\" int(u-$22/100)}}' \
         /proc/uptime \"/proc/$p/stat\" 2>/dev/null; fi"
    )
}

/// What the services' script adds: the `@@crowdsec` part, only where the package is.
pub fn script() -> String {
    format!(
        "if [ -x /usr/bin/cs-firewall-bouncer ] || [ -x /etc/init.d/{SERVICE} ]; then\n\
         echo; echo @@crowdsec\n{}\nfi\n:",
        body()
    )
}

/// The bouncer as the router has it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bouncer {
    /// `option enabled` of its config (None: the option isn't set, or no config).
    pub enabled: Option<bool>,
    /// Addresses in the IPv4 table's sets (None: no such table).
    pub blocked4: Option<u32>,
    /// The same for IPv6.
    pub blocked6: Option<u32>,
    /// How long its process has run, in seconds (None: not running, or unknown).
    pub age_s: Option<u64>,
}

impl Bouncer {
    /// Addresses blocked now; None when neither table could be read.
    pub fn blocked(&self) -> Option<u32> {
        match (self.blocked4, self.blocked6) {
            (None, None) => None,
            (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
        }
    }
    pub fn on(&self) -> bool {
        self.enabled == Some(true)
    }
}

/// The `@@crowdsec` part: `key=value` lines, any of them missing or empty.
pub fn parse(part: &str) -> Bouncer {
    let mut b = Bouncer::default();
    for l in part.lines() {
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let v = v.trim();
        match k.trim() {
            "enabled" => {
                b.enabled = match v {
                    "1" | "yes" | "on" | "true" | "enabled" => Some(true),
                    "0" | "no" | "off" | "false" | "disabled" => Some(false),
                    _ => None,
                }
            }
            "v4" => b.blocked4 = v.parse().ok(),
            "v6" => b.blocked6 = v.parse().ok(),
            "age" => b.age_s = v.parse().ok(),
            _ => {}
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    #[test]
    fn the_part_is_read_whatever_is_missing() {
        assert_eq!(
            parse("enabled=1\nv4=1204\nv6=37\nage=262800\n"),
            Bouncer {
                enabled: Some(true),
                blocked4: Some(1204),
                blocked6: Some(37),
                age_s: Some(262800),
            }
        );
        // Installed and never switched on: no tables, no process.
        let off = parse("enabled=0\nv4=\nv6=\n");
        assert_eq!(
            off,
            Bouncer {
                enabled: Some(false),
                ..Default::default()
            }
        );
        assert_eq!(off.blocked(), None);
        assert!(!off.on());
        // IPv6 switched off: its table isn't there, the other counts.
        assert_eq!(parse("enabled=1\nv4=0\nv6=\n").blocked(), Some(0));
        // No config, or something this doesn't know: present, unread.
        assert_eq!(
            parse("enabled=\nwhat\nv4=many\nage=-3\n"),
            Bouncer::default()
        );
        assert_eq!(parse(""), Bouncer::default());
    }

    /// The count is made on the router, so the awk is run here on what `nft list table`
    /// prints (modelled): several sets, elements over several lines, an empty set, the
    /// chains' own braces.
    #[test]
    fn the_sets_elements_are_counted_where_they_are() {
        let count = |text: &str| -> String {
            let o = sentry_core::exec::Cmd::local("sh")
                .args(["-c", COUNT])
                .input(text)
                .run()
                .unwrap();
            o.stdout.trim().to_string()
        };
        assert_eq!(count(&fixture("network/crowdsec-nft-table.txt")), "7");
        assert_eq!(
            count(
                "table ip crowdsec {\n\tset crowdsec-blacklists {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n}\n"
            ),
            "0"
        );
        assert_eq!(
            count(
                "table ip crowdsec {\n\tset s {\n\t\telements = { 192.0.2.1 timeout 4h expires 3h }\n\t}\n}\n"
            ),
            "1"
        );
        // No such table: nft prints nothing on stdout, and neither does this.
        assert_eq!(count(""), "");
        // A table without a set isn't the bouncer's.
        assert_eq!(count("table ip crowdsec {\n}\n"), "");
    }

    /// The part as a shell prints it, with the router's commands stood in for: `uci` says
    /// 1, `nft` prints the modelled table, `pidof` names this shell (and one before it, as
    /// under a jail).
    #[test]
    fn the_part_as_a_shell_prints_it() {
        let table = format!(
            "{}/../../tests/fixtures/network/crowdsec-nft-table.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        let stubs = format!(
            "uci() {{ echo 1; }}; nft() {{ cat {}; }}; pidof() {{ echo 1 $$; }}\n",
            sentry_core::exec::sh_quote(&table)
        );
        let o = sentry_core::exec::Cmd::local("sh")
            .args(["-c", &format!("{stubs}{}", body())])
            .run()
            .unwrap();
        let b = parse(&o.stdout);
        assert_eq!(
            (b.enabled, b.blocked4, b.blocked6),
            (Some(true), Some(7), Some(7)),
            "{o:?}"
        );
        assert!(b.age_s.is_some(), "{o:?}");
        // Not running, no tables, no config: every line is there and empty.
        let stubs = "uci() { return 1; }; nft() { return 1; }; pidof() { return 1; }\n";
        let o = sentry_core::exec::Cmd::local("sh")
            .args(["-c", &format!("{stubs}{}", body())])
            .run()
            .unwrap();
        assert_eq!(o.stdout, "enabled=\nv4=\nv6=\n");
        assert_eq!(parse(&o.stdout), Bouncer::default());
    }

    #[test]
    fn the_script_asks_only_where_the_package_is_and_only_reads() {
        let s = script();
        assert!(s.starts_with("if [ -x /usr/bin/cs-firewall-bouncer ]"));
        for w in s.split(|c: char| c.is_whitespace() || c == ';') {
            assert!(
                !matches!(w, "add" | "delete" | "flush" | "set" | "commit" | "restart"),
                "{w} in {s}"
            );
        }
        // Nothing there: the part isn't printed, and the script still ends well.
        let o = sentry_core::exec::Cmd::local("sh")
            .args(["-c", &s])
            .run()
            .unwrap();
        if !std::path::Path::new("/usr/bin/cs-firewall-bouncer").exists() {
            assert_eq!((o.code, o.stdout.as_str()), (0, ""));
        }
    }
}

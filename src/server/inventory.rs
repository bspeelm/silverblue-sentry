//! The inventory: what needs root to read, read once on request with the user's sudo password.
//! When sudo asks for a password, the read-only `sudo:` commands can't run in the background;
//! this runs each of them (the collectors' own argv) in one `sudo sh -c`, with the terminal
//! handed over for the password, and keeps their output. `Remote::output` answers a refused
//! `sudo -n` from it, so the collectors and the audit work unchanged, and the TUI says how old
//! it is. Workflow conditions never use it: they must see the server as it is now.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::collect::{self, docker, health};
use super::remote::Remote;
use crate::cache::{self, Cached};
use crate::exec::sh_quote;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Captured {
    pub code: i32,
    pub out: String,
}

/// Each command's output, keyed by its argv as quoted for the server (`docker ps -aq`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    pub outputs: BTreeMap<String, Captured>,
}

const MARK: &str = "@@sentry-cmd ";
const RC: &str = "@@sentry-rc ";

fn key(r: &Remote, argv: &[&str]) -> String {
    r.cmd(argv[0]).args(&argv[1..]).quoted_argv()
}

/// One framed section: the key, the command's stdout, its exit code.
fn section(key_expr: &str, run: &str) -> String {
    format!("printf '\\n{MARK}%s\\n' {key_expr}\n{run} 2>/dev/null\nprintf '\\n{RC}%s\\n' \"$?\"\n")
}

fn fixed(r: &Remote, argv: &[&str]) -> String {
    let k = key(r, argv);
    section(&sh_quote(&k), &k)
}

/// The script run as root: every read-only command the collectors would run with sudo (only
/// those the `sudo:` allowlist permits), plus the configured compose files.
pub fn script(r: &Remote) -> String {
    let allowed = |argv: &[&str]| r.cfg.sudo_allows(argv);
    let mut s = String::new();
    if allowed(docker::PS_ARGV) {
        s += &fixed(r, docker::PS_ARGV);
        // `docker inspect <ids>` with the ids `docker ps -aq` just listed, as the collector asks.
        s += "ids=$(docker ps -aq 2>/dev/null | tr '\\n' ' ' | sed 's/ $//')\n";
        s += "if [ -n \"$ids\" ]; then\n";
        s += &section("\"docker inspect $ids\"", "docker inspect $ids");
        s += "fi\n";
    }
    if allowed(docker::COMPOSE_LS_ARGV) {
        s += &fixed(r, docker::COMPOSE_LS_ARGV);
    }
    for dev in &r.cfg.smart {
        let argv = health::smart_argv(dev);
        if allowed(&argv) {
            s += &fixed(r, &argv);
        }
    }
    if allowed(collect::JOURNAL_ARGV) {
        s += &fixed(r, collect::JOURNAL_ARGV);
    }
    if allowed(health::F2B_ARGV) {
        s += &fixed(r, health::F2B_ARGV);
        s += "for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do\n";
        s += &section(
            "\"fail2ban-client status $j\"",
            "fail2ban-client status \"$j\"",
        );
        s += "done\n";
    }
    for argv in collect::SS_ARGVS {
        if allowed(argv) {
            s += &fixed(r, argv);
            break;
        }
    }
    for c in &r.cfg.compose {
        s += &fixed(r, &["cat", &c.file]);
    }
    s
}

/// What runs over ssh with the terminal handed over: sudo asks for the password on the
/// terminal; the output goes to a file in the login's home, read back by `read_back`.
pub fn wrapper(r: &Remote) -> String {
    format!(
        "f=\"$HOME/{CAPTURE}\"; mkdir -p \"${{f%/*}}\" || exit 1\n\
         echo 'Reading what needs root on {name} (nothing is changed)…'\n\
         sudo sh -c {} >\"$f\"",
        sh_quote(&script(r)),
        name = r.name,
    )
}

const CAPTURE: &str = ".cache/sentry-server/inventory.out";

/// After the wrapper ran: fetch its output and delete it on the server.
pub fn read_back(r: &Remote) -> Result<Inventory, super::remote::SrvError> {
    let text = r.output(&r.sh(&format!("f=\"$HOME/{CAPTURE}\"; cat \"$f\"; rm -f \"$f\"")))?;
    Ok(parse(&text))
}

pub fn parse(text: &str) -> Inventory {
    let mut outputs = BTreeMap::new();
    let mut cur: Option<(String, Vec<&str>)> = None;
    for line in text.lines() {
        if let Some(k) = line.strip_prefix(MARK) {
            cur = Some((k.to_string(), Vec::new()));
        } else if let Some(code) = line.strip_prefix(RC) {
            if let Some((k, mut lines)) = cur.take() {
                // The frame adds one newline before the code line.
                if lines.last() == Some(&"") {
                    lines.pop();
                }
                let mut out = lines.join("\n");
                if !out.is_empty() {
                    out.push('\n');
                }
                let code = code.trim().parse().unwrap_or(-1);
                outputs.insert(k, Captured { code, out });
            }
        } else if let Some((_, lines)) = cur.as_mut() {
            lines.push(line);
        }
    }
    Inventory { outputs }
}

fn cache_key(server: &str) -> String {
    format!("server-{server}-inventory")
}

pub fn save(server: &str, inv: &Inventory) -> anyhow::Result<jiff::Timestamp> {
    cache::store(&cache_key(server), inv)
}

pub fn load(server: &str) -> Option<Cached<Inventory>> {
    cache::load(&cache_key(server))
}

/// A refused `sudo -n <argv>`, answered from the last inventory.
pub fn lookup(server: &str, quoted_argv: &str) -> Option<Captured> {
    load(server)?.data.outputs.get(quoted_argv).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::config::Server;

    fn remote() -> Remote {
        let s = Server {
            sudo: vec![
                "docker ps".into(),
                "docker inspect".into(),
                "docker compose ls".into(),
                "smartctl".into(),
                "fail2ban-client status".into(),
            ],
            smart: vec!["/dev/sda".into()],
            compose: vec![crate::server::config::Compose {
                name: "stack".into(),
                file: "/srv/stack/compose.yaml".into(),
            }],
            ..Default::default()
        };
        Remote::new("myserver", &s)
    }

    #[test]
    fn the_script_runs_only_allowed_commands_with_the_collectors_argv() {
        let s = script(&remote());
        assert!(s.contains("docker ps -aq 2>/dev/null"), "{s}");
        assert!(s.contains("docker inspect $ids 2>/dev/null"));
        assert!(s.contains("smartctl -j -n standby -H -A -i /dev/sda"));
        assert!(s.contains("cat /srv/stack/compose.yaml"));
        assert!(s.contains("fail2ban-client status \"$j\""));
        // journalctl isn't on this allowlist.
        assert!(!s.contains("journalctl"));
        // Every fixed key is the collector's own argv, as quoted for the server.
        let r = remote();
        let k = key(&r, &health::smart_argv("/dev/sda"));
        assert!(s.contains(&format!("{MARK}%s\\n' {}", sh_quote(&k))), "{s}");
    }

    #[test]
    fn script_output_parses_and_keeps_exit_codes() {
        // What the script prints, with the frames and a smartctl that exited 2 (asleep).
        let text = format!(
            "Reading…\n\n{MARK}docker ps -aq\nabc\ndef\n\n{RC}0\n\n{MARK}docker inspect abc def\n[{{}}]\n\n{RC}0\n\n\
             {MARK}smartctl -j -n standby -H -A -i /dev/sda\n{{\"x\":1}}\n{RC}2\n\n{MARK}cat /srv/stack/compose.yaml\n\n{RC}1\n"
        );
        let inv = parse(&text);
        assert_eq!(
            inv.outputs["docker ps -aq"],
            Captured {
                code: 0,
                out: "abc\ndef\n".into()
            }
        );
        assert_eq!(inv.outputs["docker inspect abc def"].out, "[{}]\n");
        assert_eq!(
            inv.outputs["smartctl -j -n standby -H -A -i /dev/sda"].code,
            2
        );
        assert_eq!(inv.outputs["cat /srv/stack/compose.yaml"].out, "");
        assert_eq!(inv.outputs.len(), 4);
    }

    #[test]
    fn the_script_frames_parse_back_when_run() {
        // Run the framing itself with a local sh (commands replaced by echo/false).
        let s = format!(
            "{}{}",
            section("'echo a'", "printf 'one\\ntwo\\n'"),
            section("\"x $HOME\"", "false")
        );
        let o = crate::exec::Cmd::local("sh")
            .args(["-c", &s])
            .run()
            .unwrap();
        let inv = parse(&o.stdout);
        assert_eq!(inv.outputs["echo a"].out, "one\ntwo\n");
        assert_eq!(inv.outputs.iter().filter(|(_, c)| c.code == 1).count(), 1);
    }
}

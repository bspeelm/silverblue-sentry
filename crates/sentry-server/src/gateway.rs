//! `sentry-server exec <server> -- <argv>`: the only way Claude reaches a server. The command
//! must be on a read-only allowlist; it runs as the login user, or with `sudo -n` when the
//! server's `sudo:` list allows it. Arguments are shell-quoted for the server, so `;`, `|` and
//! `$( )` arrive as plain text: one command per call, never a shell.

use super::remote::{Remote, SrvError};
use sentry_app::remote::gateway as shared;
pub use sentry_app::remote::gateway::{Held, SECRET, queue_read};

/// Allowed commands, as leading words. `*` stands for one word of any value.
const READ_ONLY: &[&[&str]] = &[
    &["systemctl", "status"],
    &["systemctl", "show"],
    &["systemctl", "cat"],
    &["systemctl", "list-units"],
    &["systemctl", "list-timers"],
    &["systemctl", "list-unit-files"],
    &["systemctl", "list-sockets"],
    &["systemctl", "is-active"],
    &["systemctl", "is-enabled"],
    &["systemctl", "is-failed"],
    &["systemctl", "--failed"],
    &["journalctl"],
    &["docker", "ps"],
    &["docker", "inspect"],
    &["docker", "logs"],
    &["docker", "images"],
    &["docker", "image", "ls"],
    &["docker", "stats", "--no-stream"],
    &["docker", "compose", "ls"],
    &["docker", "compose", "ps"],
    &["docker", "version"],
    &["docker", "info"],
    &["ss"],
    &["df"],
    &["findmnt"],
    &["lsblk"],
    &["free"],
    &["uptime"],
    &["uname"],
    &["ps"],
    &["ip", "addr"],
    &["ip", "route"],
    &["ip", "link"],
    &["apt", "list"],
    &["apt-cache", "policy"],
    &["apt-cache", "show"],
    &["dpkg", "-l"],
    &["dpkg", "-s"],
    &["dpkg", "-L"],
    &["ls"],
    &["cat"],
    &["head"],
    &["tail"],
    &["stat"],
    &["smartctl"],
    &["fail2ban-client", "status"],
    &["nvidia-smi"],
    &["sensors"],
    &["hostnamectl", "status"],
    &["timedatectl", "status"],
];

/// Arguments that turn an allowed command into one that changes things (or never ends).
fn never(cmd: &str) -> &'static [&'static str] {
    match cmd {
        "journalctl" => &[
            "-f",
            "--follow",
            "--vacuum-size",
            "--vacuum-time",
            "--vacuum-files",
            "--rotate",
            "--flush",
            "--sync",
            "--relinquish-var",
            "--setup-keys",
        ],
        "docker" => &["-f", "--follow"],
        "smartctl" => &[
            "-s", "--smart", "-t", "--test", "-X", "--abort", "-o", "-S", "--set",
        ],
        "tail" => &["-f", "-F", "--follow"],
        _ => &[],
    }
}

/// Why a line that names SusCheck's incidents is never run for sentry's agent.
pub const SUSCHECK_PRIVATE: &str = "SusCheck's incidents are a household's private mail and may \
    carry text written by an attacker: sentry's agent never reads them";

/// The names inside the incidents folder, and its pointer file's.
const SUSCHECK_WORDS: &[&str] = &[
    "incident.json",
    "screenshot.png",
    "index.jsonl",
    "incidents.path",
    // (A check made from an email keeps the message's text: a household member's mail.)
    "message.txt",
];

/// A path as its text says where it leads: `//` and `/./` squashed, `..` taken with the
/// part before it, no trailing slash.
fn plain_path(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            x => parts.push(x),
        }
    }
    format!("/{}", parts.join("/"))
}

/// Why `line` isn't run on a server whose config names SusCheck's incidents folder: it
/// names that folder (as written, or with `//`, `/./`, `..`, a trailing slash, quotes or
/// backslashes in it), the pointer file, or one of the folder's file names. None: the rule
/// has nothing to say, and always None for a server without the block.
///
/// This is a match on the line's words, the second layer. A shell line can reach a folder
/// without naming it (`cd` to its parent and a relative path, a glob, a variable, a name
/// put together by a command, a symlink, `find … -exec`): what stops those is the server
/// itself, when the folder has a login of its own (`suscheck.ssh`) and the server's
/// ordinary login isn't in its group.
pub fn suscheck_private(cfg: &crate::config::Server, line: &str) -> Option<&'static str> {
    let dir = plain_path(cfg.suscheck.on()?);
    // Quoting taken out: `/srv/"suscheck"/incidents` names it too.
    let bare: String = line
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect();
    let lower = bare.to_lowercase();
    if SUSCHECK_WORDS.iter().any(|w| lower.contains(w)) {
        return Some(SUSCHECK_PRIVATE);
    }
    // Every stretch of the line that reads as an absolute path, made plain.
    let named = bare
        .split(|c: char| c.is_whitespace() || ";|&<>()=,:`${}".contains(c))
        .filter(|w| w.contains('/'))
        .any(|w| {
            let at = w.find('/').unwrap_or(0);
            let p = plain_path(&w[at..]);
            p == dir || p.starts_with(&format!("{dir}/"))
        });
    // And as it stands, for a path glued to something the split doesn't know.
    let squashed = {
        let mut s = bare.clone();
        while s.contains("//") || s.contains("/./") {
            s = s.replace("/./", "/").replace("//", "/");
        }
        s
    };
    (dir != "/" && (named || squashed.contains(&dir))).then_some(SUSCHECK_PRIVATE)
}

/// [`allowed`], for this server: first what its config keeps from the agent whatever the
/// command is.
pub fn allowed_on(cfg: &crate::config::Server, argv: &[String]) -> Result<(), String> {
    if let Some(why) = suscheck_private(cfg, &argv.join(" ")) {
        return Err(why.into());
    }
    allowed(argv)
}

/// [`runnable`], for this server.
pub fn runnable_on(cfg: &crate::config::Server, line: &str) -> Result<(), Held> {
    if let Some(why) = suscheck_private(cfg, line) {
        return Err(Held::Never(why.into()));
    }
    runnable(line)
}

pub fn allowed(argv: &[String]) -> Result<(), String> {
    let words: Vec<&str> = argv.iter().map(String::as_str).collect();
    if words.is_empty() {
        return Err("no command".into());
    }
    if words.iter().any(|w| w.contains('\n')) {
        return Err("one line per argument".into());
    }
    let ok = READ_ONLY.iter().any(|p| {
        words.len() >= p.len() && words.iter().zip(p.iter()).all(|(w, p)| *p == "*" || w == p)
    });
    // `apt-get` only as a simulation.
    let apt_sim = words[0] == "apt-get" && words.iter().any(|w| *w == "-s" || *w == "--simulate");
    if !ok && !apt_sim {
        return Err(format!(
            "`{}` isn't on sentry-server's read-only list",
            words.iter().take(2).copied().collect::<Vec<_>>().join(" ")
        ));
    }
    let args = &words[1..];
    let reads_files = matches!(words[0], "cat" | "head" | "tail" | "stat" | "ls");
    let forbidden = |a: &&&str| {
        never(words[0])
            .iter()
            .any(|n| **a == *n || a.strip_prefix(n).is_some_and(|r| r.starts_with('=')))
    };
    if let Some(bad) = args.iter().find(forbidden) {
        return Err(format!("`{bad}` isn't allowed with {}", words[0]));
    }
    if words[0] == "smartctl" && !(words.windows(2).any(|w| w == ["-n", "standby"])) {
        return Err("smartctl needs `-n standby` (don't wake sleeping disks)".into());
    }
    if reads_files {
        for a in args
            .iter()
            .filter(|a| a.starts_with('/') || a.contains('/'))
        {
            let lower = a.to_lowercase();
            if SECRET.iter().any(|s| lower.contains(s)) {
                return Err(format!("{a} may hold secrets"));
            }
            if !(a.starts_with("/etc/")
                || a.starts_with("/proc/")
                || a.starts_with("/var/log/")
                || a.starts_with("/sys/")
                || a.starts_with("/opt/")
                || a.starts_with("/srv/")
                || a.starts_with("/usr/")
                || a.starts_with("/boot/")
                || words[0] == "ls")
            {
                return Err(format!(
                    "{a}: only /etc, /proc, /sys, /var/log, /opt, /srv, /usr, /boot"
                ));
            }
        }
    }
    Ok(())
}

/// Run it: plain, or `sudo -n` when the server's sudo list covers it. Output passes through.
pub fn exec_cli(r: &Remote, argv: &[String]) -> u8 {
    if let Err(e) = allowed_on(&r.cfg, argv) {
        eprintln!("sentry-server exec: refused: {e}");
        return 126;
    }
    let words: Vec<&str> = argv.iter().map(String::as_str).collect();
    let cmd = r
        .privileged(&words)
        .unwrap_or_else(|_| r.cmd(&argv[0]).args(&argv[1..]))
        .timeout(Some(std::time::Duration::from_secs(60)));
    match cmd.run() {
        Ok(o) => {
            print!("{}", o.stdout);
            eprint!("{}", o.stderr);
            let needs_root = o.code != 0
                && (super::remote::password_refused(&o.stderr)
                    || o.stderr.contains("Permission denied")
                    || o.stderr.contains("permission denied"));
            if needs_root {
                let queued = queue_read(&r.name, argv).is_ok();
                eprintln!(
                    "(this needs root, and sudo on the server asks the user for a password: {})",
                    if queued {
                        "the request is queued. When your answer ends, the user is shown it and \
                         can run it with their password; its output then comes back to you in \
                         the next message. Don't wait for it: carry on with what you can, and \
                         say what you'd conclude from it"
                    } else {
                        "give the user the command to run themselves"
                    }
                );
            }
            o.code.clamp(0, 255) as u8
        }
        Err(e) => {
            let e: SrvError = e.into();
            eprintln!("sentry-server exec: {e}");
            125
        }
    }
}

/// A shell command line from an apply session (`sentry-server run`): anything goes that the
/// login user may do, so Claude can find out what it needs as you would over ssh. Held back:
/// what needs root (it becomes a request), turning the server off (the Reboot action's, or
/// a plan's) and files that may hold secrets.
pub fn runnable(line: &str) -> Result<(), Held> {
    let words = shared::words(line);
    if words.is_empty() {
        return Err(Held::Never("no command".into()));
    }
    let lower = line.to_lowercase();
    if let Some(s) = SECRET.iter().find(|s| lower.contains(**s)) {
        return Err(Held::Never(format!(
            "it names `{s}`, which may hold secrets: those never leave the server"
        )));
    }
    let off = [
        "reboot",
        "poweroff",
        "halt",
        "shutdown",
        "kexec",
        "soft-reboot",
    ];
    // Each command of the line: its first word (past sudo and the like, and what `-c` runs).
    for w in shared::commands(line) {
        for (i, word) in w.iter().enumerate() {
            let cmd = shared::is_command(&w, i);
            if (cmd && off.contains(&word.as_str()))
                || (cmd
                    && word == "systemctl"
                    && w[i + 1..].iter().any(|n| off.contains(&n.as_str())))
            {
                return Err(Held::Never(
                    "turning the server off or restarting it is the Reboot action's (or a \
                     plan's step), never a session's command"
                        .into(),
                ));
            }
        }
    }
    if words
        .iter()
        .any(|w| ["sudo", "su", "pkexec", "doas", "run0"].contains(&shared::base(w).as_str()))
    {
        return Err(Held::Asks);
    }
    Ok(())
}

/// Run it as the login user; output passes through.
pub fn run_cli(r: &Remote, line: &str) -> u8 {
    shared::run_cli("sentry-server run", r, line, |l| runnable_on(&r.cfg, l))
}

/// The queued reads (each still on the read-only list, no repeats), and the queue emptied.
pub fn take_reads(r: &Remote) -> Vec<Vec<String>> {
    shared::take_reads(&r.name, |argv| allowed_on(&r.cfg, argv).is_ok())
}

/// How Claude is told to use the gateway.
pub fn summary() -> String {
    "read-only commands only: systemctl status/show/cat/list-*/is-*, journalctl, docker \
     ps/inspect/logs/images/compose ls/compose ps, ss, df, findmnt, lsblk, free, uptime, uname, \
     ps, ip addr/route/link, apt list, apt-cache policy/show, apt-get -s, dpkg -l/-s/-L, \
     cat/head/tail/stat/ls under /etc /proc /sys /var/log /opt /srv /usr /boot, smartctl -n \
     standby, fail2ban-client status, nvidia-smi, sensors"
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> bool {
        allowed(&s.split_whitespace().map(str::to_string).collect::<Vec<_>>()).is_ok()
    }

    #[test]
    fn a_session_runs_anything_but_root_power_and_secrets() {
        for good in [
            "dmesg | tail -50",
            "lspci -vv",
            "ps aux | sort -k3 -r | head",
            "docker ps -a --format '{{.Names}}' 2>/dev/null",
            "journalctl -b -p err --no-pager | grep -c app",
            "for u in app.service db.service; do systemctl is-active $u; done",
            "cat /etc/fstab; df -h",
            "systemctl --user restart app",
            "grep -r reboot /etc/cron.d",
        ] {
            assert_eq!(runnable(good), Ok(()), "{good}");
        }
        for asks in [
            "sudo smartctl -a /dev/sda",
            "dmesg || sudo dmesg",
            "echo x | sudo tee /etc/motd",
            "sh -c 'sudo docker ps'",
            "x=$(sudo cat /var/log/auth.log)",
            "/usr/bin/sudo -n true",
            "su - root -c id",
        ] {
            assert_eq!(runnable(asks), Err(Held::Asks), "{asks}");
        }
        for never in [
            "reboot",
            "sudo reboot",
            "systemctl poweroff",
            "true && /sbin/shutdown -h now",
            "sudo systemctl reboot",
            "cat /etc/shadow",
            "sudo cat /srv/app/.env",
            "cat ~/.ssh/id_ed25519",
            "",
        ] {
            assert!(matches!(runnable(never), Err(Held::Never(_))), "{never}");
        }
    }

    /// Every spelling of the incidents folder, its pointer file and its file names is
    /// refused by both commands on a server that has SusCheck, with the plain reason; the
    /// same lines on a server without it, and ordinary lines on one with it, are as ever.
    #[test]
    fn nothing_that_names_suscheck_s_incidents_is_run_for_the_agent() {
        use crate::config::{Server, Suscheck};
        let with = Server {
            suscheck: Suscheck {
                dir: Some("/srv/suscheck/incidents/".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let without = Server::default();
        let argv = |s: &str| s.split_whitespace().map(str::to_string).collect::<Vec<_>>();
        let refused = [
            // The folder, as written and around it.
            "cat /srv/suscheck/incidents/status.json",
            "ls -la /srv/suscheck/incidents",
            "ls /srv/suscheck/incidents/",
            "ls /srv//suscheck///incidents",
            "ls /srv/./suscheck/./incidents/.",
            "ls /srv/suscheck/../suscheck/incidents",
            "ls /srv/suscheck/incidents/../incidents/20261101T091500Z-a1b2",
            "ls /opt/../srv/suscheck/incidents",
            "stat /srv/suscheck/incidents/20261101T091500Z-a1b2",
            "head -c 100 /srv/suscheck/incidents/20261101T091500Z-a1b2/anything",
            "tail -n 5 /SRV/../srv/suscheck/incidents/x",
            // The files' names, wherever they are said to be.
            "cat /srv/elsewhere/incident.json",
            "cat /opt/copy/20261101T091500Z-a1b2/screenshot.png",
            "tail -n 200 /srv/x/index.jsonl",
            "cat /srv/x/INDEX.JSONL",
            "cat /opt/copy/20261101T091500Z-a1b2/message.txt",
            // The pointer.
            "cat /etc/suscheck/incidents.path",
            "head -n 1 /etc//suscheck/./incidents.path",
        ];
        for line in refused {
            assert_eq!(
                allowed_on(&with, &argv(line)),
                Err(SUSCHECK_PRIVATE.to_string()),
                "exec: {line}"
            );
            assert_eq!(
                runnable_on(&with, line),
                Err(Held::Never(SUSCHECK_PRIVATE.into())),
                "run: {line}"
            );
            assert_eq!(suscheck_private(&without, line), None, "{line}");
        }
        // What only a shell line can say.
        for line in [
            "cat '/srv/suscheck/incidents/index'",
            "cat \"/srv/suscheck\"/incidents/x",
            "cat /srv/susch\\eck/incidents/x",
            "cat /srv/sus''check/incidents/x",
            "x=/srv/suscheck/incidents; ls $x",
            "d=$(cat /etc/suscheck/incidents.path); ls \"$d\"",
            "sudo tar c /srv/suscheck/incidents | base64",
            "(cd /srv/suscheck/incidents && ls)",
            "find /srv -name incident.json",
            "find / -name 'screenshot.png' 2>/dev/null",
            "scp host:/srv/suscheck/incidents/a /tmp",
            "ls /srv/suscheck/incidents;id",
            "cat</srv/suscheck/incidents/status.json",
            "sudo cat /srv/suscheck/incidents/x/incident.json",
        ] {
            assert_eq!(
                runnable_on(&with, line),
                Err(Held::Never(SUSCHECK_PRIVATE.into())),
                "run: {line}"
            );
        }
        assert!(SUSCHECK_PRIVATE.starts_with(
            "SusCheck's incidents are a household's private mail and may carry text written \
             by an attacker: sentry's agent never reads them"
        ));
        // Ordinary lines, and SusCheck's own service, are untouched by it.
        for line in [
            "systemctl status suscheck.service",
            "journalctl -u suscheck -n 50 --no-pager",
            "ls -la /srv",
            "ls /srv/suscheck",
            "cat /etc/fstab",
            "df -h /srv",
            "docker ps -a",
        ] {
            assert_eq!(suscheck_private(&with, line), None, "{line}");
            assert_eq!(
                allowed_on(&with, &argv(line)),
                allowed(&argv(line)),
                "{line}"
            );
            assert_eq!(runnable_on(&with, line), runnable(line), "{line}");
        }
        // The rest of both gateways is what it was, with the block or without.
        for line in [
            "cat /etc/shadow",
            "systemctl restart app.service",
            "sudo id",
            "reboot",
        ] {
            assert_eq!(
                allowed_on(&with, &argv(line)),
                allowed(&argv(line)),
                "{line}"
            );
            assert_eq!(runnable_on(&with, line), runnable(line), "{line}");
        }
        // Past the words (what the folder's own login is for): none of these names it.
        for line in [
            "cd /srv/suscheck && cat incidents/status.json",
            "cat /srv/suscheck/inc*/status.json",
            "cat /srv/suscheck/$(echo incidents)/status.json",
        ] {
            assert_eq!(suscheck_private(&with, line), None, "{line}");
        }
    }

    #[test]
    fn read_only_only() {
        for good in [
            "systemctl status app.service",
            "journalctl -u app.service -n 50 --no-pager",
            "docker ps -a",
            "docker logs --tail 100 web",
            "docker compose ls",
            "apt-get -s dist-upgrade",
            "cat /etc/fstab",
            "smartctl -n standby -H /dev/sda",
            "ls -la /opt",
            "ss -tulpn",
            "ss -t -l",
            "journalctl -t sshd -n 20",
        ] {
            assert!(ok(good), "{good}");
        }
        for bad in [
            "systemctl restart app.service",
            "docker rm web",
            "docker compose up -d",
            "journalctl --vacuum-time=1d",
            "journalctl -f",
            "apt-get install vim",
            "rm -rf /",
            "sh -c id",
            "cat /etc/shadow",
            "cat /home/admin/.ssh/id_ed25519",
            "cat /root/notes",
            "smartctl -H /dev/sda",
            "smartctl -n standby -t long /dev/sda",
            "tail -f /var/log/syslog",
            "docker logs -f web",
        ] {
            assert!(!ok(bad), "{bad}");
        }
    }

    #[test]
    fn reads_are_queued_once_and_only_while_on_the_read_only_list() {
        let server = format!("test-queue-{}", std::process::id());
        let v = |s: &str| s.split_whitespace().map(str::to_string).collect::<Vec<_>>();
        queue_read(&server, &v("docker logs --since 72h web")).unwrap();
        queue_read(&server, &v("docker logs --since 72h web")).unwrap();
        queue_read(&server, &v("journalctl -u app.service -n 15")).unwrap();
        // Written by hand into the queue: still refused.
        queue_read(&server, &v("docker rm web")).unwrap();
        let r = Remote::new(&server, &crate::config::Server::default());
        let reads = take_reads(&r);
        assert_eq!(
            reads,
            [
                v("docker logs --since 72h web"),
                v("journalctl -u app.service -n 15")
            ]
        );
        assert!(take_reads(&r).is_empty(), "taken means gone");
    }
}

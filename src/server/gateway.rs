//! `sentry-server exec <server> -- <argv>`: the only way Claude reaches a server. The command
//! must be on a read-only allowlist; it runs as the login user, or with `sudo -n` when the
//! server's `sudo:` list allows it. Arguments are shell-quoted for the server, so `;`, `|` and
//! `$( )` arrive as plain text: one command per call, never a shell.

use super::remote::{Remote, SrvError};

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

/// Files whose contents shouldn't leave the server even when readable.
const SECRET: &[&str] = &[
    "shadow",
    "gshadow",
    "password",
    "passwd-",
    "secret",
    "token",
    "private",
    "id_rsa",
    "id_ed25519",
    ".key",
    "credentials",
    ".env",
];

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
    if let Err(e) = allowed(argv) {
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

/// Reads Claude asked for that need root, waiting for the user (one per line, as JSON).
/// Under the runtime directory: the gateway runs as Claude's child, possibly elsewhere than the
/// TUI's environment, and this is the same for both.
fn reads_path(server: &str) -> std::path::PathBuf {
    crate::exec::control_dir().join(format!("reads-{server}.jsonl"))
}

pub fn queue_read(server: &str, argv: &[String]) -> std::io::Result<()> {
    use std::io::Write;
    let p = reads_path(server);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)?;
    writeln!(f, "{}", serde_json::to_string(argv).unwrap_or_default())
}

/// The queued reads (each still on the read-only list, no repeats), and the queue emptied.
pub fn take_reads(server: &str) -> Vec<Vec<String>> {
    let p = reads_path(server);
    let text = std::fs::read_to_string(&p).unwrap_or_default();
    let _ = std::fs::remove_file(&p);
    let mut out: Vec<Vec<String>> = Vec::new();
    for l in text.lines() {
        if let Ok(argv) = serde_json::from_str::<Vec<String>>(l)
            && allowed(&argv).is_ok()
            && !out.contains(&argv)
        {
            out.push(argv);
        }
    }
    out
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
        let reads = take_reads(&server);
        assert_eq!(
            reads,
            [
                v("docker logs --since 72h web"),
                v("journalctl -u app.service -n 15")
            ]
        );
        assert!(take_reads(&server).is_empty(), "taken means gone");
    }
}

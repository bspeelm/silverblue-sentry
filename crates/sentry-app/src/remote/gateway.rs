//! How Claude's commands reach a remote host: what a kind of host lets through is its own
//! policy; reading a command line as its commands, running an allowed one as the login user
//! and the queue of reads that wait for the user are the same for all of them.

use super::{Error, Remote};

/// Files whose contents shouldn't leave the host even when readable.
pub const SECRET: &[&str] = &[
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

/// Why an apply session's command line isn't simply run on the host.
#[derive(Debug, PartialEq, Eq)]
pub enum Held {
    /// It needs root: the user is shown it, and allows it or not.
    Asks,
    /// Never from a session, and why.
    Never(String),
}

/// A command line's words, whatever shell syntax stands between them.
pub fn words(line: &str) -> Vec<&str> {
    line.split(|c: char| c.is_whitespace() || ";&|()`$'\"{}".contains(c))
        .filter(|w| !w.is_empty())
        .collect()
}

/// A word without its directory (`/usr/bin/sudo` → `sudo`).
pub fn base(w: &str) -> String {
    w.rsplit('/').next().unwrap_or(w).to_string()
}

/// Each command of a line (split at `;`, `&`, `|`, newlines, parentheses and backticks):
/// its words, without quotes, `$`, braces or directories.
pub fn commands(line: &str) -> Vec<Vec<String>> {
    line.split([';', '&', '|', '\n', '(', ')', '`'])
        .map(|part| {
            part.split_whitespace()
                .map(|w| base(w.trim_matches(|c| "'\"${}".contains(c))))
                .collect()
        })
        .collect()
}

/// Whether word `i` of a command is itself a command: the first, one past only `sudo` and
/// the like, or what a `-c` runs.
pub fn is_command(w: &[String], i: usize) -> bool {
    i == 0
        || w[..i]
            .iter()
            .all(|p| ["sudo", "-n", "exec", "nohup", "time", "env"].contains(&p.as_str()))
        || w[i - 1] == "-c"
}

/// Run a session's command line as the login user when `policy` lets it; output passes
/// through. `prog` names the gateway in what Claude is told (`sentry-server run`).
pub fn run_cli(
    prog: &str,
    r: &Remote,
    line: &str,
    policy: impl Fn(&str) -> Result<(), Held>,
) -> u8 {
    run_cli_with(prog, r, line, policy, |_| Ok(|s: &str| s.to_string()))
}

/// The same, with what the command printed passed through a filter before any of it is
/// shown (a router's output is scrubbed). `filter` is made only once the policy let the
/// line through, and before the command runs: when it can't be made, nothing is run.
pub fn run_cli_with<F: Fn(&str) -> String>(
    prog: &str,
    r: &Remote,
    line: &str,
    policy: impl Fn(&str) -> Result<(), Held>,
    filter: impl FnOnce(&Remote) -> Result<F, String>,
) -> u8 {
    match policy(line) {
        // The words `claude::refused` knows: the session makes it a request for the user.
        Err(Held::Asks) => {
            eprintln!("{prog}: this needs root and requires approval: {line}");
            return 126;
        }
        Err(Held::Never(why)) => {
            eprintln!("{prog}: not run: {why}");
            return 126;
        }
        Ok(()) => {}
    }
    let filter = match filter(r) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{prog}: not run: {e}");
            return 125;
        }
    };
    match r
        .sh(line)
        .timeout(Some(std::time::Duration::from_secs(120)))
        .run()
    {
        Ok(o) => {
            print!("{}", filter(&o.stdout));
            eprint!("{}", filter(&o.stderr));
            if o.code != 0
                && (o.stderr.contains("Permission denied")
                    || o.stderr.contains("permission denied"))
            {
                eprintln!(
                    "(if this needs root, call it again with sudo: the user is asked, and the \
                     output comes back to you)"
                );
            }
            o.code.clamp(0, 255) as u8
        }
        Err(e) => {
            let e: Error = e.into();
            eprintln!("{prog}: {e}");
            125
        }
    }
}

/// Reads Claude asked for that need root, waiting for the user (one per line, as JSON).
/// Under the runtime directory: the gateway runs as Claude's child, possibly elsewhere than the
/// TUI's environment, and this is the same for both.
fn reads_path(scope: &str) -> std::path::PathBuf {
    sentry_core::exec::control_dir().join(format!("reads-{scope}.jsonl"))
}

pub fn queue_read(scope: &str, argv: &[String]) -> std::io::Result<()> {
    use std::io::Write;
    let p = reads_path(scope);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)?;
    writeln!(f, "{}", serde_json::to_string(argv).unwrap_or_default())
}

/// The queued reads (each still one `allowed` lets through, no repeats), and the queue
/// emptied.
pub fn take_reads(scope: &str, allowed: impl Fn(&[String]) -> bool) -> Vec<Vec<String>> {
    let p = reads_path(scope);
    let text = std::fs::read_to_string(&p).unwrap_or_default();
    let _ = std::fs::remove_file(&p);
    let mut out: Vec<Vec<String>> = Vec::new();
    for l in text.lines() {
        if let Ok(argv) = serde_json::from_str::<Vec<String>>(l)
            && allowed(&argv)
            && !out.contains(&argv)
        {
            out.push(argv);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_read_as_its_commands() {
        assert_eq!(
            words("x=$(sudo cat '/var/log/a b'); echo \"{y}\""),
            ["x=", "sudo", "cat", "/var/log/a", "b", "echo", "y"]
        );
        let c = commands("dmesg | /usr/bin/sudo -n tail -5; sh -c 'reboot'");
        assert_eq!(c[0], ["dmesg"]);
        assert_eq!(c[1], ["sudo", "-n", "tail", "-5"]);
        assert_eq!(c[2], ["sh", "-c", "reboot"]);
        // `tail` is what sudo runs, `-5` is its argument; `reboot` is what `-c` runs.
        assert!(is_command(&c[1], 0) && is_command(&c[1], 2) && !is_command(&c[1], 3));
        assert!(is_command(&c[2], 2) && !is_command(&c[2], 1));
    }

    #[test]
    fn a_held_line_is_refused_before_anything_runs() {
        // An unroutable host: reaching it would fail differently (125).
        let r = Remote::new(
            "x",
            "nobody@host.invalid",
            "x",
            super::super::Privilege::Root,
        );
        assert_eq!(run_cli("t run", &r, "sudo id", |_| Err(Held::Asks)), 126);
        assert_eq!(
            run_cli("t run", &r, "id", |_| Err(Held::Never("no".into()))),
            126
        );
    }

    #[test]
    fn reads_are_queued_once_and_only_while_allowed() {
        let scope = format!("test-queue-app-{}", std::process::id());
        let v = |s: &str| s.split_whitespace().map(str::to_string).collect::<Vec<_>>();
        queue_read(&scope, &v("logread -l 50")).unwrap();
        queue_read(&scope, &v("logread -l 50")).unwrap();
        queue_read(&scope, &v("rm -rf /")).unwrap();
        let reads = take_reads(&scope, |a| a[0] != "rm");
        assert_eq!(reads, [v("logread -l 50")]);
        assert!(take_reads(&scope, |_| true).is_empty(), "taken means gone");
    }
}

//! One configured server: builds its `Cmd::ssh` commands and decides which may use sudo.

use std::sync::Arc;

use crate::exec::{Cmd, ExecError};

use super::config::{self, Server};

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SrvError {
    /// ssh couldn't connect (or the server went away).
    #[error("{0}")]
    Unreachable(String),
    #[error("{0} not found")]
    NotFound(String),
    /// The command needs root and isn't in the `sudo:` allowlist.
    #[error("needs sudo: add `{0}` to sudo: in server_config.yaml")]
    NeedsSudo(String),
    /// Allowed, but sudo on the server asks for a password, so it can't run unattended.
    #[error(
        "sudo on the server asks for a password, so `{0}` can't be read in the background \
         (press I to read it once with your password)"
    )]
    SudoPassword(String),
    #[error("{0}")]
    Failed(String),
    #[error("{0}")]
    Parse(String),
}

impl From<ExecError> for SrvError {
    fn from(e: ExecError) -> Self {
        match e {
            ExecError::Unreachable(s) => Self::Unreachable(s),
            ExecError::NotFound(s) => Self::NotFound(s),
            e => Self::Failed(e.to_string()),
        }
    }
}

/// How `sudo` behaves for this login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudoMode {
    /// `sudo -n` works: no password needed.
    NoPasswd,
    /// sudo exists but asks for a password: maintenance hands over the terminal.
    Password,
    /// No sudo for this user.
    Absent,
}

#[derive(Debug, Clone)]
pub struct Remote {
    pub name: String,
    pub host: &'static str,
    pub cfg: Arc<Server>,
    /// Answer a refused `sudo -n` from the last inventory (the TUI and the audit; never
    /// workflow conditions, which must see the server as it is now).
    pub inventory: bool,
}

impl Remote {
    pub fn new(name: &str, cfg: &Server) -> Self {
        Self {
            name: name.to_string(),
            host: config::host(cfg.ssh_target(name)),
            cfg: Arc::new(cfg.clone()),
            inventory: false,
        }
    }

    /// Fall back to the last inventory when sudo asks for a password.
    pub fn with_inventory(mut self) -> Self {
        self.inventory = true;
        self
    }

    /// A refused `sudo -n …` command's output from the last inventory, if it has it.
    pub fn from_inventory(&self, cmd: &Cmd) -> Option<String> {
        if !self.inventory {
            return None;
        }
        let line = cmd.quoted_argv();
        let argv = line.strip_prefix("sudo -n ")?;
        super::inventory::lookup(&self.name, argv).map(|c| c.out)
    }

    /// A command as the login user (never sudo).
    pub fn cmd(&self, bin: &str) -> Cmd {
        Cmd::ssh(self.host, bin)
    }

    /// A shell snippet run by the server's `sh`.
    pub fn sh(&self, script: &str) -> Cmd {
        self.cmd("sh").args(["-c", script])
    }

    /// `sudo -n <argv>` when the allowlist permits it.
    pub fn privileged(&self, argv: &[&str]) -> Result<Cmd, SrvError> {
        if self.cfg.sudo_allows(argv) {
            Ok(self.cmd("sudo").arg("-n").args(argv))
        } else {
            // Suggest the command and its subcommand, not its flags (`docker ps`, `smartctl`).
            let n = if argv.get(1).is_some_and(|w| !w.starts_with('-')) {
                2
            } else {
                1
            };
            Err(SrvError::NeedsSudo(argv[..n.min(argv.len())].join(" ")))
        }
    }

    /// Run and return stdout; a non-zero exit is `Failed` with stderr.
    pub fn output(&self, cmd: &Cmd) -> Result<String, SrvError> {
        cmd.output().or_else(|e| match e {
            ExecError::Failed { stderr, .. }
                if cmd.bin() == "sudo" && password_refused(&stderr) =>
            {
                self.from_inventory(cmd)
                    .ok_or_else(|| SrvError::SudoPassword(sudo_words(cmd)))
            }
            ExecError::Failed { code, stderr, .. } => Err(SrvError::Failed(format!(
                "{} exited {code}: {}",
                cmd.bin(),
                stderr.lines().last().unwrap_or("").trim()
            ))),
            e => Err(e.into()),
        })
    }

    /// How sudo behaves right now: `sudo -n true`. Checked again before anything that uses
    /// sudo, since the server's sudoers can change while sentry-server is open.
    pub fn sudo_mode(&self) -> Result<SudoMode, SrvError> {
        let o = self
            .sh("command -v sudo >/dev/null || exit 3; sudo -n true 2>/dev/null")
            .run()?;
        Ok(match o.code {
            0 => SudoMode::NoPasswd,
            3 => SudoMode::Absent,
            _ => SudoMode::Password,
        })
    }
}

/// sudo's refusal to run without a password (`sudo -n`, or no terminal to ask on).
pub fn password_refused(stderr: &str) -> bool {
    stderr.contains("a password is required") || stderr.contains("a terminal is required")
}

/// `docker ps` from `sudo -n docker ps -aq`: the command and its subcommand, as in `sudo:`.
fn sudo_words(cmd: &Cmd) -> String {
    let line = cmd.remote_line();
    let words: Vec<&str> = line
        .split_whitespace()
        .skip_while(|w| *w != "sudo")
        .skip(1)
        .filter(|w| *w != "-n")
        .collect();
    let n = if words.get(1).is_some_and(|w| !w.starts_with('-')) {
        2
    } else {
        1
    };
    words[..n.min(words.len())].join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileged_only_through_the_allowlist() {
        let s = Server {
            ssh: Some("admin@myserver.example".into()),
            sudo: vec!["docker ps".into()],
            ..Default::default()
        };
        let r = Remote::new("myserver", &s);
        assert_eq!(r.host, "admin@myserver.example");
        let c = r.privileged(&["docker", "ps", "-aq"]).unwrap();
        assert_eq!(c.remote_line(), "env LC_ALL=C sudo -n docker ps -aq");
        assert_eq!(
            r.privileged(&["smartctl", "-H", "/dev/sda"]).unwrap_err(),
            SrvError::NeedsSudo("smartctl".into())
        );
        assert_eq!(sudo_words(&c), "docker ps");
        assert!(password_refused("sudo: a password is required\n"));
        assert_eq!(
            r.sh("cat /proc/loadavg; echo x").remote_line(),
            "env LC_ALL=C sh -c 'cat /proc/loadavg; echo x'"
        );
    }
}

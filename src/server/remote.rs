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
}

impl Remote {
    pub fn new(name: &str, cfg: &Server) -> Self {
        Self {
            name: name.to_string(),
            host: config::host(cfg.ssh_target(name)),
            cfg: Arc::new(cfg.clone()),
        }
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
        cmd.output().map_err(|e| match e {
            ExecError::Failed { code, stderr, .. } => SrvError::Failed(format!(
                "{} exited {code}: {}",
                cmd.bin(),
                stderr.lines().last().unwrap_or("").trim()
            )),
            e => e.into(),
        })
    }

    /// Probed once per connection: `sudo -n true`.
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
        assert_eq!(
            r.sh("cat /proc/loadavg; echo x").remote_line(),
            "env LC_ALL=C sh -c 'cat /proc/loadavg; echo x'"
        );
    }
}

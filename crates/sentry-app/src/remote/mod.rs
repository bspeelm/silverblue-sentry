//! A host reached over ssh: builds its `Cmd::ssh` commands and decides which may run as root.
//! Nothing is installed on it; everything runs from this machine.

pub mod audit;
pub mod gateway;
pub mod probe;
pub mod recorder;
pub mod upstream;
pub mod workflow;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use sentry_core::exec::{Cmd, ExecError};

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Error {
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

impl From<ExecError> for Error {
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
    /// sudo exists but asks for a password: it's asked for once, in the TUI, and held.
    Password,
    /// No sudo for this user.
    Absent,
    /// The login is root: nothing needs sudo, and nothing is asked.
    Root,
}

impl SudoMode {
    /// Root's commands run without a password prompt: by `sudo -n`, or as root already.
    pub fn unattended(self) -> bool {
        matches!(self, Self::NoPasswd | Self::Root)
    }
}

/// How the login gets root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Privilege {
    /// Through `sudo -n`, for the commands the allowlist covers (entries as leading words:
    /// `docker ps`, `smartctl`).
    Sudo { allow: Arc<[String]> },
    /// The login is root (a router): there is no sudo, and no list.
    Root,
}

impl Privilege {
    pub fn sudo(allow: &[String]) -> Self {
        Self::Sudo {
            allow: allow.into(),
        }
    }
}

/// Whether `argv` starts with one of the allowlist's entries' words.
pub fn allows(allow: &[String], argv: &[&str]) -> bool {
    allow.iter().any(|entry| {
        let words: Vec<&str> = entry.split_whitespace().collect();
        !words.is_empty() && argv.len() >= words.len() && argv[..words.len()] == words[..]
    })
}

/// The ssh destination as a `&'static str` (what `Cmd::ssh` wants): interned once per target.
pub fn host(target: &str) -> &'static str {
    static HOSTS: OnceLock<Mutex<HashMap<String, &'static str>>> = OnceLock::new();
    let mut m = HOSTS.get_or_init(Default::default).lock().expect("hosts");
    m.entry(target.to_string())
        .or_insert_with(|| Box::leak(target.to_string().into_boxed_str()))
}

#[derive(Debug, Clone)]
pub struct Remote {
    pub name: String,
    pub host: &'static str,
    /// Where its records and data live (`maint::root`, the ring): a server's name, or
    /// `net:<name>`.
    pub scope: String,
    pub privilege: Privilege,
}

impl Remote {
    /// `target`: what ssh connects to.
    pub fn new(name: &str, target: &str, scope: &str, privilege: Privilege) -> Self {
        Self {
            name: name.to_string(),
            host: host(target),
            scope: scope.to_string(),
            privilege,
        }
    }

    /// A command as the login user (never sudo).
    pub fn cmd(&self, bin: &str) -> Cmd {
        Cmd::ssh(self.host, bin)
    }

    /// A shell snippet run by the host's `sh`.
    pub fn sh(&self, script: &str) -> Cmd {
        self.cmd("sh").args(["-c", script])
    }

    /// `argv` as root: `sudo -n <argv>` when the allowlist permits it, the bare command when
    /// the login is root.
    pub fn privileged(&self, argv: &[&str]) -> Result<Cmd, Error> {
        match &self.privilege {
            Privilege::Root => match argv.split_first() {
                Some((bin, rest)) => Ok(self.cmd(bin).args(rest)),
                None => Err(Error::Failed("no command".into())),
            },
            Privilege::Sudo { allow } if allows(allow, argv) => {
                Ok(self.cmd("sudo").arg("-n").args(argv))
            }
            Privilege::Sudo { .. } => {
                // Suggest the command and its subcommand, not its flags (`docker ps`, `smartctl`).
                let n = if argv.get(1).is_some_and(|w| !w.starts_with('-')) {
                    2
                } else {
                    1
                };
                Err(Error::NeedsSudo(argv[..n.min(argv.len())].join(" ")))
            }
        }
    }

    /// Run and return stdout; a non-zero exit is `Failed` with stderr. A `sudo -n` that was
    /// refused for want of a password is `SudoPassword`.
    pub fn output(&self, cmd: &Cmd) -> Result<String, Error> {
        cmd.output().map_err(|e| match e {
            ExecError::Failed { stderr, .. }
                if cmd.bin() == "sudo" && password_refused(&stderr) =>
            {
                Error::SudoPassword(sudo_words(cmd))
            }
            ExecError::Failed { code, stderr, .. } => Error::Failed(format!(
                "{} exited {code}: {}",
                cmd.bin(),
                stderr.lines().last().unwrap_or("").trim()
            )),
            e => e.into(),
        })
    }

    /// How sudo behaves right now: `sudo -n true`. Checked again before anything that uses
    /// sudo, since the server's sudoers can change while sentry-server is open. A root login
    /// is `Root` without asking the host anything.
    pub fn sudo_mode(&self) -> Result<SudoMode, Error> {
        if self.privilege == Privilege::Root {
            return Ok(SudoMode::Root);
        }
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
pub fn sudo_words(cmd: &Cmd) -> String {
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

/// A file under the repo's `tests/fixtures/`.
#[cfg(test)]
pub(crate) fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudo_only_through_the_allowlist() {
        let r = Remote::new(
            "myserver",
            "admin@myserver.example",
            "myserver",
            Privilege::sudo(&["docker ps".into(), "smartctl".into()]),
        );
        assert_eq!(r.host, "admin@myserver.example");
        assert_eq!(host("a"), host("a"));
        let c = r.privileged(&["docker", "ps", "-aq"]).unwrap();
        assert_eq!(c.remote_line(), "env LC_ALL=C sudo -n docker ps -aq");
        assert_eq!(sudo_words(&c), "docker ps");
        assert_eq!(
            r.privileged(&["docker", "rm", "web"]).unwrap_err(),
            Error::NeedsSudo("docker rm".into())
        );
        assert_eq!(
            r.privileged(&["journalctl", "-n", "5"]).unwrap_err(),
            Error::NeedsSudo("journalctl".into())
        );
        assert!(
            r.privileged(&["docker"]).is_err(),
            "all of an entry's words"
        );
        assert!(r.privileged(&["smartctl", "-H", "/dev/sda"]).is_ok());
        assert!(password_refused("sudo: a password is required\n"));
    }

    #[test]
    fn a_root_login_needs_no_sudo() {
        let r = Remote::new("home", "root@router.example", "net:home", Privilege::Root);
        // Anything, bare: there is no list and no sudo on the host.
        let c = r.privileged(&["logread", "-l", "50"]).unwrap();
        assert_eq!(c.remote_line(), "env LC_ALL=C logread -l 50");
        assert_eq!(c.bin(), "logread");
        assert!(r.privileged(&[]).is_err());
        // Answered here: nothing is run to find out (there's no such host to reach).
        assert_eq!(r.sudo_mode(), Ok(SudoMode::Root));
        assert!(SudoMode::Root.unattended() && SudoMode::NoPasswd.unattended());
        assert!(!SudoMode::Password.unattended() && !SudoMode::Absent.unattended());
        // Its records and metrics are a network's.
        assert_eq!(
            sentry_core::maint::root(&r.scope),
            sentry_core::paths::config_dir().join("networks/home")
        );
    }
}

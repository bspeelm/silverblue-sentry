//! Every external command goes through here.
//!
//! `Cmd::host` targets host userspace (rpm-ostree, flatpak, podman, systemctl, ...). Inside a
//! toolbox those binaries only exist on the host, so the command is wrapped in
//! `flatpak-spawn --host`. Availability is probed by path *before* spawning because a missing
//! binary behind flatpak-spawn surfaces as exit 1 plus a portal error, not as ENOENT.
//!
//! `Cmd::ssh` targets a server: the argv runs there through one multiplexed `ssh` connection
//! (`sentry-server`). Exit 127 means the command is missing there, 255 that ssh itself failed.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Site {
    Host,
    /// Container-local binaries (tests; nothing in the app needs it yet).
    #[cfg_attr(not(test), allow(dead_code))]
    Local,
    /// A server, by ssh alias. Leaked once per configured server so `Site` stays `Copy`.
    Ssh(&'static str),
}

#[derive(Clone, Debug)]
pub struct Cmd {
    site: Site,
    argv: Vec<OsString>,
    timeout: Option<Duration>,
    dir: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("{0} not found")]
    NotFound(String),
    #[error("timed out after {0:?}")]
    Timeout(Duration),
    #[error("exit {code}: {}", stderr.trim())]
    Failed {
        code: i32,
        stdout: String,
        stderr: String,
    },
    #[error("{0}")]
    Unreachable(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Messages emitted by [`Cmd::stream`].
#[derive(Debug, Clone)]
pub enum StreamMsg {
    Line { stderr: bool, text: String },
    Exit { code: i32, elapsed: Duration },
}

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// True when host commands must be wrapped in `flatpak-spawn --host`.
pub fn spawn_mode() -> bool {
    static MODE: OnceLock<bool> = OnceLock::new();
    *MODE.get_or_init(|| match std::env::var("SENTRY_HOST_EXEC").as_deref() {
        Ok("direct") => false,
        Ok("spawn") => true,
        _ => in_toolbox(),
    })
}

pub fn in_toolbox() -> bool {
    Path::new("/run/.containerenv").exists()
}

/// Quote for a POSIX shell when needed (`kmod nvidia` → `'kmod nvidia'`).
pub fn sh_quote(s: &str) -> String {
    if s.is_empty()
        || s.contains(|c: char| c.is_whitespace() || "'\"$`\\|&;<>()*?#~{}[]!".contains(c))
    {
        format!("'{}'", s.replace('\'', r"'\''"))
    } else {
        s.to_string()
    }
}

/// Where ssh's multiplexing sockets live: short, because a socket path must stay under 108
/// bytes, and private (0700).
pub fn control_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        Some(d) => PathBuf::from(d).join("sentry-server"),
        None => PathBuf::from(format!(
            "/tmp/sentry-server-{}",
            rustix::process::getuid().as_raw()
        )),
    }
}

/// How a remote command gets a terminal: none (captured), forced (`-tt`: streamed, so killing
/// the local ssh hangs up the remote command too), or the user's own (`-t`: interactive).
#[derive(Clone, Copy, PartialEq)]
enum Tty {
    No,
    Forced,
    Inherit,
}

impl Cmd {
    pub fn host(bin: &str) -> Self {
        Self {
            site: Site::Host,
            argv: vec![bin.into()],
            timeout: Some(DEFAULT_TIMEOUT),
            dir: None,
        }
    }

    /// Run `bin` on a server over ssh (`host` is an ssh alias or `user@host`).
    pub fn ssh(host: &'static str, bin: &str) -> Self {
        Self {
            site: Site::Ssh(host),
            argv: vec![bin.into()],
            timeout: Some(DEFAULT_TIMEOUT),
            dir: None,
        }
    }

    pub fn site(&self) -> Site {
        self.site
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn local(bin: &str) -> Self {
        Self {
            site: Site::Local,
            argv: vec![bin.into()],
            timeout: Some(DEFAULT_TIMEOUT),
            dir: None,
        }
    }

    pub fn arg(mut self, a: impl Into<OsString>) -> Self {
        self.argv.push(a.into());
        self
    }

    pub fn args<I, S>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.argv.extend(it.into_iter().map(Into::into));
        self
    }

    /// Working directory for the command (on the host for `Cmd::host` in a toolbox).
    pub fn dir(mut self, d: impl Into<PathBuf>) -> Self {
        self.dir = Some(d.into());
        self
    }

    pub fn timeout(mut self, t: Option<Duration>) -> Self {
        self.timeout = t;
        self
    }

    pub fn bin(&self) -> String {
        self.argv[0].to_string_lossy().into_owned()
    }

    /// Shell-ish rendering for logs and confirm modals.
    pub fn display(&self) -> String {
        if self.argv.len() == 3 && self.argv[0] == "sh" && self.argv[1] == "-c" {
            return self.argv[2].to_string_lossy().into_owned();
        }
        self.quoted_argv()
    }

    fn quoted_argv(&self) -> String {
        self.argv
            .iter()
            .map(|a| sh_quote(&a.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn available(&self) -> bool {
        match self.site {
            // Whether the remote command exists is only known by running it (exit 127).
            Site::Ssh(_) => bin_available(Site::Local, "ssh"),
            s => bin_available(s, &self.bin()),
        }
    }

    /// The command line the server's shell runs: C locale, optional working directory.
    pub fn remote_line(&self) -> String {
        let cd = self
            .dir
            .as_ref()
            .map(|d| format!("cd {} && ", sh_quote(&d.to_string_lossy())))
            .unwrap_or_default();
        format!("{cd}env LC_ALL=C {}", self.quoted_argv())
    }

    fn command(&self) -> Command {
        self.command_tty(Tty::No)
    }

    fn command_tty(&self, tty: Tty) -> Command {
        if let Site::Ssh(host) = self.site {
            let dir = control_dir();
            if !dir.exists() {
                let _ = std::fs::create_dir_all(&dir);
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
            let mut c = Command::new("ssh");
            c.args(ssh_opts(&dir, tty == Tty::No));
            match tty {
                Tty::No => {}
                Tty::Forced => {
                    c.arg("-tt");
                }
                Tty::Inherit => {
                    c.arg("-t");
                }
            }
            c.arg("--").arg(host).arg(self.remote_line());
            c.env("LC_ALL", "C");
            return c;
        }
        let mut c = if self.site == Site::Host && spawn_mode() {
            let mut c = Command::new("flatpak-spawn");
            c.arg("--host").arg("--env=LC_ALL=C");
            if let Some(d) = &self.dir {
                c.arg(format!("--directory={}", d.display()));
            }
            c.args(&self.argv);
            c
        } else {
            let mut c = Command::new(&self.argv[0]);
            c.args(&self.argv[1..]);
            if let Some(d) = &self.dir {
                c.current_dir(d);
            }
            c
        };
        c.env("LC_ALL", "C");
        c
    }

    fn check(&self) -> Result<(), ExecError> {
        if self.available() {
            Ok(())
        } else {
            Err(ExecError::NotFound(self.bin()))
        }
    }

    /// Run to completion, capturing output; any exit code is returned (over ssh, 127 and 255
    /// become `NotFound` and `Unreachable`).
    pub fn run(&self) -> Result<Output, ExecError> {
        let o = self.run_raw()?;
        if let Site::Ssh(host) = self.site {
            match o.code {
                127 => return Err(ExecError::NotFound(format!("{} on {host}", self.bin()))),
                255 => {
                    let why = o.stderr.trim();
                    return Err(ExecError::Unreachable(if why.is_empty() {
                        format!("{host}: ssh failed")
                    } else {
                        format!("{host}: {why}")
                    }));
                }
                _ => {}
            }
        }
        Ok(o)
    }

    fn run_raw(&self) -> Result<Output, ExecError> {
        self.check()?;
        let mut child = self
            .command()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut out = child.stdout.take().expect("piped");
        let mut err = child.stderr.take().expect("piped");
        let t_out = thread::spawn(move || {
            let mut s = Vec::new();
            let _ = out.read_to_end(&mut s);
            s
        });
        let t_err = thread::spawn(move || {
            let mut s = Vec::new();
            let _ = err.read_to_end(&mut s);
            s
        });
        let start = Instant::now();
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if let Some(t) = self.timeout
                && start.elapsed() > t
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ExecError::Timeout(t));
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
        let stderr = String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned();
        Ok(Output {
            code: status.code().unwrap_or(-1),
            stdout,
            stderr,
        })
    }

    /// Run to completion; non-zero exit is an error. Returns stdout.
    pub fn output(&self) -> Result<String, ExecError> {
        let o = self.run()?;
        if o.code == 0 {
            Ok(o.stdout)
        } else {
            Err(ExecError::Failed {
                code: o.code,
                stdout: o.stdout,
                stderr: o.stderr,
            })
        }
    }

    /// Spawn and stream stdout/stderr lines to `sink`, followed by exactly one `Exit`.
    /// Returns the child's pid. No timeout: streamed commands are user-confirmed actions.
    pub fn stream(
        &self,
        sink: impl Fn(StreamMsg) + Send + Sync + 'static,
    ) -> Result<u32, ExecError> {
        self.check()?;
        let mut child = self
            .command_tty(if matches!(self.site, Site::Ssh(_)) {
                Tty::Forced
            } else {
                Tty::No
            })
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let pid = child.id();
        let sink = Arc::new(sink);
        let readers: Vec<_> = [
            (
                false,
                Box::new(child.stdout.take().expect("piped")) as Box<dyn Read + Send>,
            ),
            (
                true,
                Box::new(child.stderr.take().expect("piped")) as Box<dyn Read + Send>,
            ),
        ]
        .into_iter()
        .map(|(is_err, r)| {
            let sink = Arc::clone(&sink);
            thread::spawn(move || {
                for chunk in BufReader::new(r).split(b'\n') {
                    let Ok(chunk) = chunk else { break };
                    sink(StreamMsg::Line {
                        stderr: is_err,
                        text: clean_line(&String::from_utf8_lossy(&chunk)),
                    });
                }
            })
        })
        .collect();
        let start = Instant::now();
        thread::spawn(move || {
            for r in readers {
                let _ = r.join();
            }
            let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
            sink(StreamMsg::Exit {
                code,
                elapsed: start.elapsed(),
            });
        });
        Ok(pid)
    }

    /// Run with the terminal inherited. The caller must have suspended the TUI.
    pub fn interactive(&self) -> Result<ExitStatus, ExecError> {
        self.check()?;
        Ok(self.command_tty(Tty::Inherit).status()?)
    }

    /// Start in its own session and forget about it (new terminal windows, Flatseal).
    pub fn detach(&self) -> Result<(), ExecError> {
        if matches!(self.site, Site::Ssh(_)) {
            return Err(ExecError::Io(io::Error::other(
                "can't detach a remote command",
            )));
        }
        self.check()?;
        let mut c = if self.site == Site::Host && spawn_mode() {
            let mut c = Command::new("flatpak-spawn");
            c.arg("--host").arg("setsid").args(&self.argv);
            c
        } else {
            let mut c = Command::new("setsid");
            c.args(&self.argv);
            c
        };
        let mut child = c
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        thread::spawn(move || child.wait());
        Ok(())
    }
}

/// Batch mode (never prompt) and quick failure when the server is gone. Captured commands share
/// one multiplexed connection that outlives the last command by at most 15 s. Streamed and
/// interactive ones (actions) get a connection of their own: through the shared one, killing
/// the local client leaves the remote command running, because the master keeps its session.
/// One line of terminal output as text: progress bars redraw with \r, so the last segment
/// wins; colour and cursor escapes go.
pub fn clean_line(raw: &str) -> String {
    let last = raw.rsplit('\r').find(|s| !s.is_empty()).unwrap_or("");
    let mut out = String::with_capacity(last.len());
    let mut chars = last.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => match chars.next() {
                // CSI: parameters, then one final letter.
                Some('[') => {
                    for c in chars.by_ref() {
                        if c.is_ascii_alphabetic() || c == '~' {
                            break;
                        }
                    }
                }
                // OSC (window titles): up to BEL or ESC \.
                Some(']') => {
                    while let Some(c) = chars.next() {
                        if c == '\x07' || (c == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                            break;
                        }
                    }
                }
                _ => {}
            },
            c if c.is_control() && c != '\t' => {}
            c => out.push(c),
        }
    }
    out
}

/// Captured terminal output as clean lines.
pub fn clean_lines(text: &str) -> Vec<String> {
    text.lines().map(clean_line).collect()
}

fn ssh_opts(control: &Path, shared: bool) -> Vec<String> {
    // Tests point ssh at a throwaway server without touching ~/.ssh/config.
    let file = std::env::var("SENTRY_SSH_CONFIG")
        .ok()
        .filter(|f| !f.is_empty())
        .map(|f| vec!["-F".to_string(), f])
        .unwrap_or_default();
    file.into_iter()
        .chain(
            [
                "BatchMode=yes".to_string(),
                "ConnectTimeout=5".into(),
                "ServerAliveInterval=10".into(),
                "ServerAliveCountMax=3".into(),
            ]
            .into_iter()
            .chain(if shared {
                vec![
                    "ControlMaster=auto".to_string(),
                    format!("ControlPath={}/%C", control.display()),
                    "ControlPersist=15s".into(),
                ]
            } else {
                vec!["ControlPath=none".to_string()]
            })
            .flat_map(|o| ["-o".to_string(), o])
            // Own connections (streamed, interactive): no "Connection to … closed." in the output.
            .chain((!shared).then(|| "-q".to_string())),
        )
        .collect()
}

fn search_dirs(site: Site) -> Vec<PathBuf> {
    let path_dirs = || -> Vec<PathBuf> {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default()
    };
    if site == Site::Host && spawn_mode() {
        let mut v: Vec<PathBuf> = ["/usr/local/bin", "/usr/bin", "/usr/sbin", "/usr/local/sbin"]
            .iter()
            .map(|d| Path::new("/run/host").join(d.trim_start_matches('/')))
            .collect();
        // $HOME is shared with the host, so user-installed tools resolve directly.
        if let Some(h) = std::env::var_os("HOME") {
            v.push(PathBuf::from(h).join(".local/bin"));
        }
        v
    } else {
        path_dirs()
    }
}

pub fn bin_available(site: Site, bin: &str) -> bool {
    static CACHE: OnceLock<Mutex<HashMap<(Site, String), bool>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let key = (site, bin.to_string());
    if let Some(&v) = cache.lock().expect("exec cache").get(&key) {
        return v;
    }
    let found = if bin.contains('/') {
        let p = if site == Site::Host && spawn_mode() {
            Path::new("/run/host").join(bin.trim_start_matches('/'))
        } else {
            PathBuf::from(bin)
        };
        p.exists()
    } else {
        search_dirs(site).iter().any(|d| d.join(bin).is_file())
    };
    cache.lock().expect("exec cache").insert(key, found);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_quotes_when_needed() {
        let c = Cmd::host("rpm-ostree")
            .arg("upgrade")
            .arg("--uninstall")
            .arg("kmod nvidia");
        assert_eq!(c.display(), "rpm-ostree upgrade --uninstall 'kmod nvidia'");
    }

    /// Whatever the argument, the server's shell gets it back literally: `;`, `$( )` and
    /// quotes never become shell syntax.
    #[test]
    fn sh_quote_round_trips_through_a_shell() {
        for arg in [
            "plain",
            "two words",
            "it's",
            "a;rm -rf ~",
            "$(id)",
            "`id`",
            "{{json .}}",
            "#comment",
            "",
            "back\\slash",
        ] {
            let o = Cmd::local("sh")
                .arg("-c")
                .arg(format!("printf %s {}", sh_quote(arg)))
                .run()
                .unwrap();
            assert_eq!(o.stdout, arg, "{arg:?} quoted as {}", sh_quote(arg));
        }
    }

    #[test]
    fn ssh_remote_line() {
        let c = Cmd::ssh("myserver", "docker")
            .args(["ps", "--format", "{{json .}}"])
            .dir("/opt/my stack");
        assert_eq!(
            c.remote_line(),
            "cd '/opt/my stack' && env LC_ALL=C docker ps --format '{{json .}}'"
        );
        assert_eq!(c.site(), Site::Ssh("myserver"));
        assert!(c.detach().is_err());
    }

    #[test]
    fn missing_binary_is_not_found() {
        let e = Cmd::local("definitely-not-a-binary-xyz")
            .output()
            .unwrap_err();
        assert!(matches!(e, ExecError::NotFound(b) if b == "definitely-not-a-binary-xyz"));
    }

    #[test]
    fn captures_output_and_exit_code() {
        let o = Cmd::local("sh")
            .arg("-c")
            .arg("echo hi; echo err >&2; exit 3")
            .run()
            .unwrap();
        assert_eq!(
            (o.code, o.stdout.as_str(), o.stderr.as_str()),
            (3, "hi\n", "err\n")
        );
    }

    #[test]
    fn timeout_kills() {
        let e = Cmd::local("sleep")
            .arg("5")
            .timeout(Some(Duration::from_millis(100)))
            .run()
            .unwrap_err();
        assert!(matches!(e, ExecError::Timeout(_)));
    }

    #[test]
    fn terminal_output_is_cleaned() {
        assert_eq!(
            clean_line("0% [Working]\rHit:1 http://deb stable InRelease"),
            "Hit:1 http://deb stable InRelease"
        );
        assert_eq!(clean_line("\x1b[1;31mE:\x1b[0m locked\r"), "E: locked");
        assert_eq!(clean_line("\x1b]0;title\x07done"), "done");
        assert_eq!(clean_lines("a\r\nb\n"), vec!["a", "b"]);
    }

    #[test]
    fn stream_emits_lines_then_exit() {
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        Cmd::local("sh")
            .arg("-c")
            .arg("echo a; echo b >&2; printf 'x\\ry\\n'; printf 'crlf\\r\\n'")
            .stream(move |m| tx.lock().unwrap().send(m).unwrap())
            .unwrap();
        let msgs: Vec<_> = rx
            .iter()
            .take_while(|m| !matches!(m, StreamMsg::Exit { .. }))
            .collect();
        let lines: Vec<_> = msgs
            .iter()
            .filter_map(|m| match m {
                StreamMsg::Line { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert!(lines.contains(&"a") && lines.contains(&"b") && lines.contains(&"y"));
        // `ssh -tt` ends lines with \r\n: the text survives.
        assert!(lines.contains(&"crlf"), "{lines:?}");
    }
}

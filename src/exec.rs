//! Every external command goes through here.
//!
//! `Cmd::host` targets host userspace (rpm-ostree, flatpak, podman, systemctl, ...). Inside a
//! toolbox those binaries only exist on the host, so the command is wrapped in
//! `flatpak-spawn --host`. Availability is probed by path *before* spawning because a missing
//! binary behind flatpak-spawn surfaces as exit 1 plus a portal error, not as ENOENT.

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
    Local,
}

#[derive(Clone, Debug)]
pub struct Cmd {
    site: Site,
    argv: Vec<OsString>,
    timeout: Option<Duration>,
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

impl Cmd {
    pub fn host(bin: &str) -> Self {
        Self {
            site: Site::Host,
            argv: vec![bin.into()],
            timeout: Some(DEFAULT_TIMEOUT),
        }
    }

    pub fn local(bin: &str) -> Self {
        Self {
            site: Site::Local,
            argv: vec![bin.into()],
            timeout: Some(DEFAULT_TIMEOUT),
        }
    }

    /// `sh -c <script>` on the host.
    pub fn sh(script: &str) -> Self {
        Self::host("sh").arg("-c").arg(script)
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

    pub fn timeout(mut self, t: Option<Duration>) -> Self {
        self.timeout = t;
        self
    }

    pub fn bin(&self) -> String {
        self.argv[0].to_string_lossy().into_owned()
    }

    pub fn site(&self) -> Site {
        self.site
    }

    /// Shell-ish rendering for logs and confirm modals.
    pub fn display(&self) -> String {
        if self.argv.len() == 3 && self.argv[0] == "sh" && self.argv[1] == "-c" {
            return self.argv[2].to_string_lossy().into_owned();
        }
        self.argv
            .iter()
            .map(|a| {
                let s = a.to_string_lossy();
                if s.is_empty()
                    || s.contains(|c: char| c.is_whitespace() || "'\"$`\\|&;<>()*?".contains(c))
                {
                    format!("'{}'", s.replace('\'', r"'\''"))
                } else {
                    s.into_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn available(&self) -> bool {
        bin_available(self.site, &self.bin())
    }

    fn command(&self) -> Command {
        let mut c = if self.site == Site::Host && spawn_mode() {
            let mut c = Command::new("flatpak-spawn");
            c.arg("--host").arg("--env=LC_ALL=C").args(&self.argv);
            c
        } else {
            let mut c = Command::new(&self.argv[0]);
            c.args(&self.argv[1..]);
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

    /// Run to completion, capturing output; any exit code is returned.
    pub fn run(&self) -> Result<Output, ExecError> {
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
            .command()
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
                    // Progress bars redraw with \r; keep the last segment.
                    let text = String::from_utf8_lossy(&chunk);
                    let text = text.rsplit('\r').find(|s| !s.is_empty()).unwrap_or("");
                    sink(StreamMsg::Line {
                        stderr: is_err,
                        text: text.to_string(),
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
        Ok(self.command().status()?)
    }

    /// Start in its own session and forget about it (new terminal windows, Flatseal).
    pub fn detach(&self) -> Result<(), ExecError> {
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
        assert_eq!(Cmd::sh("ls | wc -l").display(), "ls | wc -l");
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
    fn stream_emits_lines_then_exit() {
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        Cmd::local("sh")
            .arg("-c")
            .arg("echo a; echo b >&2; printf 'x\\ry\\n'")
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
    }
}

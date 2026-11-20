//! A workflow run on a remote host: the same TOML format and state machine as the local ones
//! (`workflows::runner`), with every step run by the host's `sh` over ssh. What a kind of host
//! has of its own (conditions, built-ins, the seeded workflows) comes in as the run's `Env`.
//! Runs are kept in `~/.local/share/sentry/servers/<name>/workflows/` (a network's under
//! `networks/`).
//!
//! A step that starts with the program's own name (`sentry-server cond …`) runs here and
//! checks the host, so verification needs nothing installed there.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::time::Instant;

use super::{Remote, SudoMode};
use sentry_core::exec::Cmd;
use sentry_core::workflows::runner::{self, Env, Next};
use sentry_core::workflows::state::{Run, RunState, RunStatus, StepStatus};
use sentry_core::workflows::{self, Entry, Kind, Workflow};

/// A host's own workflows: these replace the generic ones when there are any.
pub fn own_dir(scope: &str) -> PathBuf {
    sentry_core::maint::root(scope).join("workflows")
}

/// Where its runs are kept.
pub fn root(scope: &str) -> PathBuf {
    sentry_core::maint::data_root(scope).join("workflows")
}

/// The workflow files in a directory.
pub fn tomls(d: &std::path::Path) -> Vec<PathBuf> {
    std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect()
}

/// A host's own directory if it has any workflows, else the generic one.
pub fn pick_dir(own: PathBuf, generic: PathBuf) -> PathBuf {
    if tomls(&own).is_empty() { generic } else { own }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    Info,
    Cmd,
    Out,
    Ok,
    Err,
}

/// What the app runs for the session.
pub enum Exec {
    /// Stream into the log.
    Stream { cmd: Cmd, idx: usize },
    /// Hand over the terminal (sudo that asks for a password). The output is also written to
    /// `capture` on the server, read back into the step's log afterwards (`tty_output`).
    Tty {
        cmd: Cmd,
        idx: usize,
        capture: String,
    },
    /// `sudo systemctl reboot`; the app then waits for a new boot id. `tty`: sudo asks for a
    /// password, so the terminal is handed over for it.
    Reboot { cmd: Cmd, tty: bool },
}

/// A streamed step can't answer a password prompt: its `sudo` fails at once instead of
/// waiting on a prompt nobody sees.
pub fn no_prompt(cmd: &str) -> String {
    format!("sudo() {{ command sudo -n \"$@\"; }}\n{cmd}")
}

/// A step run with the terminal handed over: its output still goes to the terminal, and to
/// `capture` (under the login's home on the server) so it lands in the step's log. The exit
/// code is the command's, not tee's.
pub fn tee_to(cmd: &str, capture: &str) -> String {
    format!(
        "f=\"$HOME/{capture}\"; mkdir -p \"${{f%/*}}\" || exit 1\n\
         {{ ( {cmd}\n) 2>&1; echo $? >\"$f.rc\"; }} | tee \"$f\"\n\
         exit \"$(cat \"$f.rc\" 2>/dev/null || echo 1)\""
    )
}

/// What a step that sudo refused says on its card.
pub const SUDO_REFUSED: &str =
    "sudo asked for a password · r retries with the terminal handed over";

pub struct Live {
    pub id: u64,
    pub idx: usize,
    pub pid: Option<u32>,
    pub started: Instant,
}

const LOG_LINES: usize = 2000;

pub struct Session {
    pub wf: Workflow,
    pub run: Run,
    pub next: Next,
    pub log: VecDeque<(String, LogKind)>,
    pub live: Option<Live>,
    /// Auto steps may run (the user opened the run (0) or started it).
    pub armed: bool,
    pub error: Option<String>,
    /// The running step's output had sudo refusing to run without a password.
    sudo_refused: bool,
    r: Remote,
    /// The program whose steps run on this machine (`sentry-server cond …`), and whose name
    /// the host's capture directory carries.
    prog: &'static str,
    env: Box<dyn Env>,
}

impl Session {
    fn new(wf: Workflow, run: Run, r: &Remote, prog: &'static str, env: Box<dyn Env>) -> Self {
        let mut s = Self {
            wf,
            run,
            next: Next::Done,
            log: VecDeque::new(),
            live: None,
            armed: false,
            error: None,
            sudo_refused: false,
            r: r.clone(),
            prog,
            env,
        };
        s.refresh();
        s
    }

    /// The run still in progress on this host, if any. `env` answers its conditions and
    /// built-ins; a step that starts with `<prog> ` runs here, by that program.
    pub fn resume(r: &Remote, prog: &'static str, env: Box<dyn Env>) -> Option<Self> {
        let mut run = sentry_core::workflows::state::in_progress_in(&root(&r.scope))?;
        let wf = workflows::parse(&run.workflow_text().ok()?).ok()?;
        runner::recover(&mut run.state, &wf);
        let mut s = Self::new(wf, run, r, prog, env);
        s.push(format!("↻ resumed {}", s.wf.name), LogKind::Info);
        Some(s)
    }

    /// Start a run. `vars`: the workflow's `[vars]`, asked for before it starts.
    pub fn begin(
        entry: &Entry,
        r: &Remote,
        vars: BTreeMap<String, String>,
        prog: &'static str,
        env: Box<dyn Env>,
    ) -> anyhow::Result<Self> {
        if let Some(why) = entry.blocked() {
            anyhow::bail!("{}: {why}", entry.name);
        }
        if let Some(cur) = sentry_core::workflows::state::in_progress_in(&root(&r.scope)) {
            anyhow::bail!(
                "{} is already in progress on {}; finish or abandon it first",
                cur.state.workflow,
                r.name
            );
        }
        let wf = entry.wf.as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
        let text = std::fs::read_to_string(&entry.path)?;
        let ids: Vec<String> = wf.steps.iter().map(|s| s.id.clone()).collect();
        let run = Run::create_in(
            &root(&r.scope),
            &entry.name,
            &text,
            RunState::new(&entry.name, &ids, vars),
        )?;
        let mut s = Self::new(wf.clone(), run, r, prog, env);
        s.armed = true;
        s.push(
            format!("▶ started {} on {}", s.wf.name, r.name),
            LogKind::Info,
        );
        Ok(s)
    }

    pub fn push(&mut self, text: impl Into<String>, kind: LogKind) {
        if self.log.len() == LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back((text.into(), kind));
    }

    fn save(&mut self) {
        if let Err(e) = self.run.save() {
            self.error = Some(format!("state.json: {e}"));
        }
    }

    pub fn refresh(&mut self) {
        match runner::advance(&self.wf, &mut self.run.state, self.env.as_ref()) {
            Ok(n) => {
                self.next = n;
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
        self.save();
    }

    pub fn done(&self) -> bool {
        self.run.state.status != RunStatus::InProgress
    }

    pub fn title(&self, idx: usize) -> String {
        runner::preview(&self.run.state, &self.wf.steps[idx].title)
    }

    pub fn state_word(&self) -> &'static str {
        if self.live.is_some() {
            return "running";
        }
        if self.error.is_some() {
            return "error";
        }
        match self.next {
            Next::Done => "done",
            Next::Run(_) => "ready",
            Next::Confirm(_) => "waiting for confirm",
            Next::Reboot {
                requested: true, ..
            } => "rebooting",
            Next::Reboot { .. } => "reboot pending",
            Next::Shell(_) => "shell step",
            Next::Manual { failed: true, .. } | Next::Stopped(_) => "failed",
            Next::Manual { .. } => "manual step",
        }
    }

    /// The rendered command for a step (built-ins resolved now).
    pub fn rendered(&mut self, idx: usize) -> Result<String, String> {
        let run = self.wf.steps[idx].run.clone().unwrap_or_default();
        runner::render(&mut self.run.state, self.env.as_ref(), &run)
    }

    /// What follows the program's name in a step that runs on this machine (`<prog> cond …`).
    fn here<'a>(&self, cmd: &'a str) -> Option<&'a str> {
        cmd.strip_prefix(self.prog)?.strip_prefix(' ')
    }

    fn exec_step(&mut self, idx: usize, sudo: Option<SudoMode>) -> Option<Exec> {
        if self.live.is_some() || self.run.state.steps[idx].status == StepStatus::Running {
            return None;
        }
        let id = self.wf.steps[idx].id.clone();
        let cmd = match self.rendered(idx) {
            Ok(c) => c,
            Err(e) => {
                self.run
                    .append_log(&id, &format!("✗ the command never ran: {e}"));
                self.push(format!("✗ {e}"), LogKind::Err);
                runner::finish(&mut self.run.state, idx, 2, Some(e));
                self.refresh();
                return None;
            }
        };
        let n = self.wf.steps.len();
        let header = format!("▶ {}/{n} {}", idx + 1, self.title(idx));
        self.push(header, LogKind::Info);
        // One line in the view (the step's log file keeps the command as written).
        self.push(format!("$ {}", cmd.replace('\n', " ⏎ ")), LogKind::Cmd);
        let boot = self.env.boot_id();
        runner::start(&mut self.run.state, idx, boot);
        self.save();
        self.run.append_log(&id, &format!("$ {cmd}"));
        // `sentry-server cond …` checks the server from here; everything else runs there.
        let here = self.here(&cmd);
        let full = match here {
            Some(rest) => Cmd::local(&exe(self.prog))
                .arg(rest.split_whitespace().next().unwrap_or("cond"))
                .arg(&self.r.name)
                .args(rest.split_whitespace().skip(1))
                .timeout(None),
            None => self.r.sh(&cmd).timeout(None),
        };
        // A root login has no sudo to ask or to refuse.
        let uses_sudo = here.is_none() && runner::needs_tty(&cmd) && sudo != Some(SudoMode::Root);
        self.sudo_refused = false;
        Some(if uses_sudo && sudo == Some(SudoMode::Password) {
            self.push(
                "(sudo asks for a password: the terminal is handed over)",
                LogKind::Info,
            );
            let capture = format!(
                ".cache/{}/{}-{id}.out",
                self.prog,
                self.run
                    .dir
                    .file_name()
                    .map_or("run".into(), |n| n.to_string_lossy())
            );
            Exec::Tty {
                cmd: self.r.sh(&tee_to(&cmd, &capture)).timeout(None),
                idx,
                capture,
            }
        } else if uses_sudo {
            Exec::Stream {
                cmd: self.r.sh(&no_prompt(&cmd)).timeout(None),
                idx,
            }
        } else {
            Exec::Stream { cmd: full, idx }
        })
    }

    /// An auto step to run now, if armed and idle.
    pub fn auto(&mut self, sudo: Option<SudoMode>) -> Option<Exec> {
        if !self.armed || self.live.is_some() || self.error.is_some() {
            return None;
        }
        match self.next {
            Next::Run(i) => self.exec_step(i, sudo),
            _ => None,
        }
    }

    /// Enter on the step card. Reboots are confirmed by a modal first.
    pub fn go(&mut self, sudo: Option<SudoMode>) -> Result<Option<Exec>, String> {
        if self.live.is_some() {
            return Err("a step is running".into());
        }
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        match self.next {
            Next::Done => Err("workflow complete".into()),
            Next::Run(i) | Next::Confirm(i) => Ok(self.exec_step(i, sudo)),
            Next::Reboot { idx, .. } => {
                runner::request_reboot(&self.wf, &mut self.run.state, idx, self.env.as_ref())?;
                // Now `Reboot { requested: true }`: Enter mustn't send a second reboot.
                self.refresh();
                self.push(
                    format!(
                        "↻ rebooting the server · {} waits for it to come back",
                        self.prog
                    ),
                    LogKind::Info,
                );
                let tty = !sudo.is_some_and(SudoMode::unattended);
                let cmd = if tty {
                    self.r.cmd("sudo").args(["systemctl", "reboot"])
                } else if sudo == Some(SudoMode::Root) {
                    self.r.cmd("systemctl").arg("reboot")
                } else {
                    self.r.cmd("sudo").args(["-n", "systemctl", "reboot"])
                };
                Ok(Some(Exec::Reboot {
                    cmd: cmd.timeout(None),
                    tty,
                }))
            }
            Next::Shell(_) => Err("shell steps aren't supported on servers".into()),
            Next::Manual { idx, failed: false } => {
                runner::mark_done(&mut self.run.state, idx, "done by hand");
                self.push(
                    format!("✓ {} marked done", self.wf.steps[idx].id),
                    LogKind::Ok,
                );
                self.refresh();
                Ok(None)
            }
            Next::Manual { failed: true, .. } | Next::Stopped(_) => Err(
                "this step failed: r retries · d marks it done by hand · s skips it · a abandons"
                    .into(),
            ),
        }
    }

    pub fn skip(&mut self, force: bool) -> Result<(), String> {
        let Some(i) = self.next.idx() else {
            return Err("nothing to skip".into());
        };
        if self.live.is_some() {
            return Err("a step is running".into());
        }
        if !self.wf.steps[i].optional && !force {
            return Err(format!("{} is not optional", self.wf.steps[i].id));
        }
        runner::skip(&mut self.run.state, i, "skipped by user");
        self.push(format!("– skipped {}", self.wf.steps[i].id), LogKind::Info);
        self.refresh();
        Ok(())
    }

    pub fn retry(&mut self) -> Result<(), String> {
        match self.next {
            Next::Stopped(i)
            | Next::Manual {
                idx: i,
                failed: true,
            } => {
                runner::retry(&mut self.run.state, i);
                self.push(format!("↻ retry {}", self.wf.steps[i].id), LogKind::Info);
                self.refresh();
                Ok(())
            }
            _ => Err("nothing failed".into()),
        }
    }

    pub fn mark_done(&mut self) -> Result<(), String> {
        match self.next {
            Next::Manual { idx, .. }
            | Next::Stopped(idx)
            | Next::Reboot {
                idx,
                requested: true,
            } => {
                runner::mark_done(&mut self.run.state, idx, "done by hand");
                self.push(
                    format!("✓ {} marked done", self.wf.steps[idx].id),
                    LogKind::Ok,
                );
                self.refresh();
                Ok(())
            }
            _ => Err("d marks a failed or manual step done · s skips a step".into()),
        }
    }

    pub fn abandon(&mut self) {
        runner::abandon(&mut self.run.state);
        self.push("■ abandoned", LogKind::Err);
        self.next = Next::Done;
        self.save();
    }

    /// Output line of the running step: into the view and the step's log file.
    pub fn on_line(&mut self, text: &str) {
        if super::password_refused(text) {
            self.sudo_refused = true;
        }
        if let Some(l) = &self.live {
            let id = self.wf.steps[l.idx].id.clone();
            self.run.append_log(&id, text);
        }
        self.push(text.to_string(), LogKind::Out);
    }

    pub fn on_exit(&mut self, idx: usize, code: i32) {
        self.live = None;
        let id = self.wf.steps[idx].id.clone();
        let note = (code != 0 && self.sudo_refused).then(|| SUDO_REFUSED.to_string());
        runner::complete(
            &self.wf,
            &mut self.run.state,
            idx,
            code,
            note,
            self.env.as_ref(),
        );
        if code == 0 {
            self.push(format!("✓ {id} done"), LogKind::Ok);
        } else {
            self.push(
                format!("✗ {id} failed (exit {code}) · L shows its log"),
                LogKind::Err,
            );
        }
        self.refresh();
        if self.done() {
            self.push(format!("✓ {} complete", self.wf.name), LogKind::Ok);
        }
    }

    /// The next step runs `sudo` on the server (or is a reboot).
    pub fn next_uses_sudo(&self) -> bool {
        let Some(i) = self.next.idx() else {
            return false;
        };
        let step = &self.wf.steps[i];
        step.kind == Kind::Reboot
            || step
                .run
                .as_deref()
                .is_some_and(|r| self.here(r).is_none() && runner::needs_tty(r))
    }

    /// Whether sudo refused the last step for want of a password (the app checks sudo again).
    pub fn sudo_refused(&self) -> bool {
        self.sudo_refused
    }

    /// After a step that had the terminal: read its output back from the server into the
    /// step's log, and delete it there.
    pub fn tty_output(&mut self, idx: usize, capture: &str) {
        let id = self.wf.steps[idx].id.clone();
        let r = &self.r;
        let script =
            format!("f=\"$HOME/{capture}\"; cat \"$f\" 2>/dev/null; rm -f \"$f\" \"$f.rc\"");
        match r.output(&r.sh(&script)) {
            Ok(text) => {
                for l in sentry_core::exec::clean_lines(&text) {
                    self.run.append_log(&id, &l);
                    self.push(l, LogKind::Out);
                }
            }
            Err(e) => {
                let msg = format!("(couldn't read the step's output back: {e})");
                self.run.append_log(&id, &msg);
                self.push(msg, LogKind::Err);
            }
        }
    }

    /// While a reboot step waits: the app saw a new boot id, so check again.
    pub fn after_reboot(&mut self) {
        let before = self.next.clone();
        self.refresh();
        if before != self.next {
            self.push("↻ the server is back · reboot step complete", LogKind::Ok);
        }
    }

    pub fn waiting_for_reboot(&self) -> bool {
        matches!(
            self.next,
            Next::Reboot {
                requested: true,
                ..
            }
        )
    }

    pub fn step_log(&self) -> Option<(String, String)> {
        let i = self
            .next
            .idx()
            .or_else(|| self.wf.steps.len().checked_sub(1))?;
        let id = &self.wf.steps[i].id;
        let text = std::fs::read_to_string(self.run.log_path(id)).ok()?;
        Some((format!("steps/{id}.log"), text))
    }

    pub fn kind(&self, idx: usize) -> Kind {
        self.wf.steps[idx].kind
    }
}

/// The program's binary: this one, one next to it (tests run from `deps/`), or PATH's.
fn exe(prog: &str) -> String {
    let me = std::env::current_exe().ok();
    if let Some(p) = &me
        && p.file_name().is_some_and(|n| n == prog)
    {
        return p.display().to_string();
    }
    me.as_deref()
        .and_then(|p| p.parent())
        .into_iter()
        .flat_map(|d| [d.join(prog), d.join("..").join(prog)])
        .find(|p| p.is_file())
        .map_or_else(|| prog.into(), |p| p.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a wrapper script with a local `sh`, in a scratch HOME with a fake `sudo` first on
    /// PATH that prints its arguments.
    fn run_sh(script: &str) -> (i32, String, std::path::PathBuf) {
        let home = std::env::temp_dir().join(format!(
            "sentry-wrap-{}-{}",
            std::process::id(),
            script.len()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("bin")).unwrap();
        std::fs::write(home.join("bin/sudo"), "#!/bin/sh\necho \"sudo got: $*\"\n").unwrap();
        sentry_core::exec::Cmd::local("chmod")
            .args(["+x", &home.join("bin/sudo").display().to_string()])
            .run()
            .unwrap();
        let wrapped = format!(
            "HOME={0}; PATH={0}/bin:$PATH\n{script}",
            sentry_core::exec::sh_quote(&home.display().to_string())
        );
        let o = sentry_core::exec::Cmd::local("sh")
            .args(["-c", &wrapped])
            .run()
            .unwrap();
        (o.code, o.stdout, home)
    }

    #[test]
    fn streamed_sudo_never_prompts() {
        let (code, out, _) = run_sh(&no_prompt("sudo apt-get update && echo next"));
        assert_eq!(code, 0);
        assert_eq!(out, "sudo got: -n apt-get update\nnext\n");
    }

    #[test]
    fn handed_over_steps_keep_output_and_exit_code() {
        let cap = ".cache/sentry-server/run-1-update.out";
        let (code, out, home) = run_sh(&tee_to("echo out; echo err >&2\nexit 3", cap));
        assert_eq!(code, 3, "the command's exit code, not tee's");
        assert!(out.contains("out") && out.contains("err"), "{out}");
        let saved = std::fs::read_to_string(home.join(cap)).unwrap();
        assert!(
            saved.contains("out\n") && saved.contains("err\n"),
            "{saved}"
        );
        let (code, _, _) = run_sh(&tee_to("true", cap));
        assert_eq!(code, 0);
    }

    #[test]
    fn runs_and_own_workflows_follow_the_scope() {
        use sentry_core::paths::{config_dir, data_dir};
        assert_eq!(
            root("myserver"),
            data_dir().join("servers/myserver/workflows")
        );
        assert_eq!(
            own_dir("myserver"),
            config_dir().join("servers/myserver/workflows")
        );
        assert_eq!(root("net:home"), data_dir().join("networks/home/workflows"));
    }
}

//! Server workflows: the same TOML format and state machine as the local ones
//! (`workflows::runner`), with server built-ins and conditions read over ssh. Definitions live in
//! `~/.config/sentry/servers/<name>/workflows/` when that has any (a server's own, replacing
//! the generic ones), otherwise `~/.config/sentry/server-workflows/` (seeded); runs in
//! `~/.local/share/sentry/servers/<name>/workflows/`.
//!
//! Steps run on the server (`sh -c` over ssh); a step that starts with `sentry-server cond` runs
//! here and checks the server, so verification needs nothing installed there.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::collect::{apt, docker, units};
use super::remote::{Remote, SrvError, SudoMode};
use crate::exec::Cmd;
use crate::paths;
use crate::workflows::runner::{self, Env, Next};
use crate::workflows::state::{Run, RunState, RunStatus, StepStatus};
use crate::workflows::{self, Entry, Kind, LintRules, Workflow};

pub const BUILTINS: &[&str] = &[
    "running_kernel",
    "newest_kernel",
    "server",
    "compose_project",
    "compose_file",
];
/// Read fresh every time (a reboot changes them; freezing them would be wrong).
const LIVE: &[&str] = &["running_kernel", "newest_kernel"];

pub const CONDS: &[&str] = &[
    "reboot_required",
    "kernel_pending",
    "updates_pending",
    "services_ok",
    "containers_healthy",
];

pub const RULES: LintRules = LintRules {
    builtins: BUILTINS,
    cond: |c| CONDS.contains(&c),
    check: |_| false,
};

pub const SEEDS: &[(&str, &str)] = &[
    (
        "apt-maintenance",
        include_str!("../../assets/server-workflows/apt-maintenance.toml"),
    ),
    (
        "compose-update",
        include_str!("../../assets/server-workflows/compose-update.toml"),
    ),
];

pub fn dir() -> PathBuf {
    paths::config_dir().join("server-workflows")
}

/// A server's own workflows: these replace the generic ones when there are any.
pub fn server_dir(server: &str) -> PathBuf {
    paths::config_dir()
        .join("servers")
        .join(server)
        .join("workflows")
}

fn tomls(d: &std::path::Path) -> Vec<PathBuf> {
    std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect()
}

/// Where a server's workflows come from: its own directory if it has any, else the generic one.
pub fn dir_for(server: &str) -> PathBuf {
    pick_dir(server_dir(server), dir())
}

fn pick_dir(own: PathBuf, generic: PathBuf) -> PathBuf {
    if tomls(&own).is_empty() { generic } else { own }
}

pub fn root(server: &str) -> PathBuf {
    paths::data_dir()
        .join("servers")
        .join(server)
        .join("workflows")
}

/// A server's workflows, with their lint results: its own if it has any, else the generic ones
/// (seeded first).
pub fn list_for(server: &str) -> Vec<Entry> {
    let d = dir_for(server);
    if d == dir() {
        let _ = std::fs::create_dir_all(&d);
        let _ = workflows::seed_with(&d, SEEDS, &[]);
    }
    load_dir(&d)
}

fn load_dir(d: &std::path::Path) -> Vec<Entry> {
    let mut v: Vec<Entry> = tomls(d)
        .into_iter()
        .map(|p| {
            let mut e = workflows::load_path_with(&p, &RULES);
            if let Ok(w) = &e.wf {
                e.issues.extend(lint_conds(w));
            }
            e
        })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

/// `sentry-server cond <name>` steps must name a real condition.
fn lint_conds(w: &Workflow) -> Vec<workflows::Issue> {
    w.steps
        .iter()
        .filter_map(|s| {
            let run = s.run.as_deref()?;
            let name = run
                .strip_prefix("sentry-server cond ")?
                .split_whitespace()
                .next()?;
            (!CONDS.contains(&name)).then(|| workflows::Issue {
                error: true,
                msg: format!("step {:?}: unknown condition `{name}`", s.id),
            })
        })
        .collect()
}

/// A condition, with a line saying why.
pub fn cond(r: &Remote, name: &str) -> Result<(bool, String), SrvError> {
    match name {
        "reboot_required" => {
            let o = r.output(&r.sh("[ -f /var/run/reboot-required ] && echo yes || echo no"))?;
            let yes = o.trim() == "yes";
            Ok((
                yes,
                if yes {
                    "a reboot is required".into()
                } else {
                    "no reboot required".into()
                },
            ))
        }
        "kernel_pending" => {
            let a = apt::collect(r)?;
            Ok((
                a.kernel_pending(),
                format!(
                    "running {}, newest installed {}",
                    a.running_kernel,
                    a.newest_kernel.as_deref().unwrap_or("?")
                ),
            ))
        }
        "updates_pending" => {
            let a = apt::collect(r)?;
            Ok((
                !a.upgrades.is_empty(),
                format!("{} update(s) waiting", a.upgrades.len()),
            ))
        }
        "services_ok" => {
            if r.cfg.services.is_empty() {
                return Ok((true, "no services: listed in server_config.yaml".into()));
            }
            let u = units::collect(r)?;
            let down: Vec<&str> = r
                .cfg
                .services
                .iter()
                .filter(|s| u.get(s).is_none_or(|st| st.active != "active"))
                .map(String::as_str)
                .collect();
            Ok(if down.is_empty() {
                (true, format!("{} service(s) running", r.cfg.services.len()))
            } else {
                (false, format!("not running: {}", down.join(", ")))
            })
        }
        "containers_healthy" => {
            let d = docker::collect(r)?;
            let ignored = |c: &docker::Container| {
                r.cfg
                    .containers
                    .ignore
                    .iter()
                    .any(|g| crate::baseline::glob(g, &c.name))
            };
            let bad: Vec<String> = d
                .containers
                .iter()
                .filter(|c| !ignored(c) && !c.finished())
                .filter(|c| {
                    c.status != "running"
                        || matches!(c.health.as_deref(), Some("unhealthy" | "starting"))
                })
                .map(|c| {
                    format!(
                        "{} ({})",
                        c.name,
                        c.health.clone().unwrap_or_else(|| c.status.clone())
                    )
                })
                .collect();
            let n = d
                .containers
                .iter()
                .filter(|c| c.status == "running")
                .count();
            Ok(if bad.is_empty() {
                (true, format!("{n} container(s) running, none unhealthy"))
            } else {
                (false, format!("not ready: {}", bad.join(", ")))
            })
        }
        n => Err(SrvError::Failed(format!(
            "unknown condition `{n}` (one of: {})",
            CONDS.join(", ")
        ))),
    }
}

pub struct RemoteEnv {
    pub r: Remote,
}

impl Env for RemoteEnv {
    fn cond(&self, name: &str) -> Result<bool, String> {
        cond(&self.r, name)
            .map(|(b, _)| b)
            .map_err(|e| e.to_string())
    }

    fn builtin(&self, name: &str) -> Result<String, String> {
        let r = &self.r;
        let first = || {
            r.cfg
                .compose
                .first()
                .ok_or_else(|| "no compose: projects in server_config.yaml".to_string())
        };
        match name {
            "server" => Ok(r.name.clone()),
            "running_kernel" => r
                .output(&r.cmd("uname").arg("-r"))
                .map(|s| s.trim().to_string())
                .map_err(|e| e.to_string()),
            "newest_kernel" => apt::collect(r)
                .map_err(|e| e.to_string())?
                .newest_kernel
                .ok_or_else(|| "no kernel found in /boot".into()),
            "compose_project" => first().map(|c| c.name.clone()),
            "compose_file" => first().map(|c| c.file.clone()),
            n => Err(format!("unknown built-in {n}")),
        }
    }

    fn boot_id(&self) -> String {
        self.r
            .output(&self.r.cmd("cat").arg("/proc/sys/kernel/random/boot_id"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    fn builtins(&self) -> &'static [&'static str] {
        BUILTINS
    }

    fn live(&self) -> &'static [&'static str] {
        LIVE
    }
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
    /// Auto steps may run (the user opened the Workflows tab or started the run).
    pub armed: bool,
    pub error: Option<String>,
    /// The running step's output had sudo refusing to run without a password.
    sudo_refused: bool,
    env: RemoteEnv,
}

impl Session {
    fn new(wf: Workflow, run: Run, r: Remote) -> Self {
        let mut s = Self {
            wf,
            run,
            next: Next::Done,
            log: VecDeque::new(),
            live: None,
            armed: false,
            error: None,
            sudo_refused: false,
            env: RemoteEnv { r },
        };
        s.refresh();
        s
    }

    /// The run still in progress on this server, if any.
    pub fn resume(r: &Remote) -> Option<Self> {
        let mut run = crate::workflows::state::in_progress_in(&root(&r.name))?;
        let wf = workflows::parse(&run.workflow_text().ok()?).ok()?;
        runner::recover(&mut run.state, &wf);
        let mut s = Self::new(wf, run, r.clone());
        s.push(format!("↻ resumed {}", s.wf.name), LogKind::Info);
        Some(s)
    }

    /// Start a run. `vars`: the workflow's `[vars]`, asked for before it starts.
    pub fn begin(
        entry: &Entry,
        r: &Remote,
        vars: BTreeMap<String, String>,
    ) -> anyhow::Result<Self> {
        if let Some(why) = entry.blocked() {
            anyhow::bail!("{}: {why}", entry.name);
        }
        if let Some(cur) = crate::workflows::state::in_progress_in(&root(&r.name)) {
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
            &root(&r.name),
            &entry.name,
            &text,
            RunState::new(&entry.name, &ids, vars),
        )?;
        let mut s = Self::new(wf.clone(), run, r.clone());
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
        match runner::advance(&self.wf, &mut self.run.state, &self.env) {
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
        runner::render(&mut self.run.state, &self.env, &run)
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
        let full = match cmd.strip_prefix("sentry-server ") {
            Some(rest) => Cmd::local(&server_exe())
                .arg(rest.split_whitespace().next().unwrap_or("cond"))
                .arg(&self.env.r.name)
                .args(rest.split_whitespace().skip(1))
                .timeout(None),
            None => self.env.r.sh(&cmd).timeout(None),
        };
        let local = cmd.starts_with("sentry-server ");
        let uses_sudo = !local && runner::needs_tty(&cmd);
        self.sudo_refused = false;
        Some(if uses_sudo && sudo == Some(SudoMode::Password) {
            self.push(
                "(sudo asks for a password: the terminal is handed over)",
                LogKind::Info,
            );
            let capture = format!(
                ".cache/sentry-server/{}-{id}.out",
                self.run
                    .dir
                    .file_name()
                    .map_or("run".into(), |n| n.to_string_lossy())
            );
            Exec::Tty {
                cmd: self.env.r.sh(&tee_to(&cmd, &capture)).timeout(None),
                idx,
                capture,
            }
        } else if uses_sudo {
            Exec::Stream {
                cmd: self.env.r.sh(&no_prompt(&cmd)).timeout(None),
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
                runner::request_reboot(&self.wf, &mut self.run.state, idx, &self.env)?;
                // Now `Reboot { requested: true }`: Enter mustn't send a second reboot.
                self.refresh();
                self.push(
                    "↻ rebooting the server · sentry-server waits for it to come back",
                    LogKind::Info,
                );
                let tty = sudo != Some(SudoMode::NoPasswd);
                let cmd = if tty {
                    self.env.r.cmd("sudo").args(["systemctl", "reboot"])
                } else {
                    self.env.r.cmd("sudo").args(["-n", "systemctl", "reboot"])
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
        if super::remote::password_refused(text) {
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
        runner::complete(&self.wf, &mut self.run.state, idx, code, note, &self.env);
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
                .is_some_and(|r| !r.starts_with("sentry-server ") && runner::needs_tty(r))
    }

    /// Whether sudo refused the last step for want of a password (the app checks sudo again).
    pub fn sudo_refused(&self) -> bool {
        self.sudo_refused
    }

    /// After a step that had the terminal: read its output back from the server into the
    /// step's log, and delete it there.
    pub fn tty_output(&mut self, idx: usize, capture: &str) {
        let id = self.wf.steps[idx].id.clone();
        let r = &self.env.r;
        let script =
            format!("f=\"$HOME/{capture}\"; cat \"$f\" 2>/dev/null; rm -f \"$f\" \"$f.rc\"");
        match r.output(&r.sh(&script)) {
            Ok(text) => {
                for l in crate::exec::clean_lines(&text) {
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

/// The sentry-server binary: this one, one next to it (tests run from `deps/`), or PATH's.
fn server_exe() -> String {
    let me = std::env::current_exe().ok();
    if let Some(p) = &me
        && p.file_name().is_some_and(|n| n == "sentry-server")
    {
        return p.display().to_string();
    }
    me.as_deref()
        .and_then(|p| p.parent())
        .into_iter()
        .flat_map(|d| [d.join("sentry-server"), d.join("../sentry-server")])
        .find(|p| p.is_file())
        .map_or_else(|| "sentry-server".into(), |p| p.display().to_string())
}

/// `sentry-server cond <server> <name> [--wait SECS]`: exit 0 when true. With --wait it keeps
/// checking every 5 s until it's true or the time is up.
pub fn cond_cli(r: &Remote, name: &str, wait: Option<u64>) -> u8 {
    let until = Instant::now() + Duration::from_secs(wait.unwrap_or(0));
    loop {
        match cond(r, name) {
            Ok((true, why)) => {
                println!("✓ {why}");
                return 0;
            }
            Ok((false, why)) if Instant::now() >= until => {
                println!("✗ {why}");
                return 1;
            }
            Ok((false, why)) => println!("… {why}"),
            // Waiting won't fix these.
            Err(
                e @ (SrvError::NeedsSudo(_) | SrvError::SudoPassword(_) | SrvError::NotFound(_)),
            ) => {
                println!("✗ {e}");
                return 2;
            }
            Err(e) if Instant::now() >= until => {
                println!("✗ {e}");
                return 2;
            }
            Err(e) => println!("… {e}"),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_lint_clean() {
        for (name, text) in SEEDS {
            let w = workflows::parse(text).unwrap_or_else(|e| panic!("{name}: {e}"));
            let mut issues = workflows::lint_with(&w, &RULES);
            issues.extend(lint_conds(&w));
            let errors: Vec<_> = issues.iter().filter(|i| i.error).collect();
            assert!(errors.is_empty(), "{name}: {errors:?}");
        }
        // The local rules would reject them: these are server built-ins.
        let w = workflows::parse(SEEDS[0].1).unwrap();
        assert!(
            workflows::lint(&w)
                .iter()
                .any(|i| i.msg.contains("newest_kernel"))
        );
    }

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
        crate::exec::Cmd::local("chmod")
            .args(["+x", &home.join("bin/sudo").display().to_string()])
            .run()
            .unwrap();
        let wrapped = format!(
            "HOME={0}; PATH={0}/bin:$PATH\n{script}",
            crate::exec::sh_quote(&home.display().to_string())
        );
        let o = crate::exec::Cmd::local("sh")
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
    fn a_servers_own_workflows_replace_the_generic_ones() {
        let base = std::env::temp_dir().join(format!("sentry-wfdir-{}", std::process::id()));
        let (own, generic) = (base.join("own"), base.join("generic"));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&generic).unwrap();
        // No directory, or one without workflows: the generic ones.
        assert_eq!(pick_dir(own.clone(), generic.clone()), generic);
        std::fs::create_dir_all(&own).unwrap();
        std::fs::write(own.join("notes.txt"), "x").unwrap();
        assert_eq!(pick_dir(own.clone(), generic.clone()), generic);
        std::fs::write(own.join("bump.toml"), SEEDS[1].1).unwrap();
        assert_eq!(pick_dir(own.clone(), generic.clone()), own);
        let names: Vec<String> = load_dir(&own).into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["bump"]);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn cond_steps_are_linted() {
        let w = workflows::parse(
            "name = \"x\"\ndescription = \"x\"\n[[steps]]\nid = \"a\"\ntitle = \"a\"\nrun = \"sentry-server cond nope\"\ngate = \"auto\"\n",
        )
        .unwrap();
        assert_eq!(
            lint_conds(&w)[0].msg,
            "step \"a\": unknown condition `nope`"
        );
    }
}

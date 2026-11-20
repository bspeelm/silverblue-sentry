//! The TUI's workflow session: the in-progress run, its log and the step that's executing.
//! Decisions come from `workflows::runner`; the app only executes the `Exec`s returned here.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use crate::exec::Cmd;
use crate::workflows::cli::{self, RealEnv};
use crate::workflows::runner::{self, Env, Next};
use crate::workflows::state::{Run, RunStatus, StepStatus};
use crate::workflows::{Entry, Kind, Workflow, dry_run_of};

pub use sentry_app::run::{How, Live, LogKind};

/// Something the app has to execute for the session.
pub enum Exec {
    /// Stream into the log pane (`dry` = the rpm-ostree dry-run sibling). A step that uses
    /// sudo is `How::Root`: the app runs it with the password, asked once in the key bar.
    Stream {
        how: How,
        idx: usize,
        dry: bool,
        timeout: Option<Duration>,
    },
    /// Interactive `$SHELL` for a `kind = "shell"` step.
    Shell {
        idx: usize,
    },
    Reboot,
}

const LOG_LINES: usize = 2000;

pub struct Session {
    pub wf: Workflow,
    pub run: Run,
    pub next: Next,
    pub log: VecDeque<(String, LogKind)>,
    pub live: Option<Live>,
    /// Auto steps may run: the user opened the Upgrade screen this session (or started the
    /// run). Nothing runs behind the user's back after a resume.
    pub armed: bool,
    pub error: Option<String>,
    pub scroll: usize,
}

impl Session {
    fn new(wf: Workflow, run: Run) -> Self {
        let mut s = Self {
            wf,
            run,
            next: Next::Done,
            log: VecDeque::new(),
            live: None,
            armed: false,
            error: None,
            scroll: 0,
        };
        s.refresh();
        s
    }

    /// Resume the run in progress, if any (spec §9.3).
    pub fn resume() -> Option<Self> {
        let run = crate::workflows::state::in_progress()?;
        let (wf, run) = cli::open(run).ok()?;
        let before: Vec<StepStatus> = run.state.steps.iter().map(|s| s.status).collect();
        let mut s = Self::new(wf, run);
        s.push(
            format!("↻ resumed {} · {}", s.wf.name, s.run.dir.display()),
            LogKind::Info,
        );
        for (i, st) in s.run.state.steps.iter().enumerate() {
            if before.get(i) == Some(&StepStatus::Running) && st.status == StepStatus::Ok {
                s.log.push_back((
                    format!("↻ boot id changed → {} complete", st.id),
                    LogKind::Info,
                ));
            }
            if before.get(i) == Some(&StepStatus::Running) && st.status == StepStatus::Failed {
                s.log.push_back((
                    format!("✗ {} was interrupted (sentry exited while it ran)", st.id),
                    LogKind::Err,
                ));
            }
        }
        s.tail_current_log();
        Some(s)
    }

    pub fn begin(entry: &Entry, vars: BTreeMap<String, String>) -> anyhow::Result<Self> {
        let run = cli::start(entry, vars)?;
        let (wf, run) = cli::open(run)?;
        let mut s = Self::new(wf, run);
        s.armed = true;
        s.push(
            format!("▶ started {} · {}", s.wf.name, s.run.dir.display()),
            LogKind::Info,
        );
        Ok(s)
    }

    /// A session over an in-memory run (render tests): no disk, no checks.
    #[cfg(test)]
    pub fn for_test(wf: Workflow, state: crate::workflows::state::RunState, next: Next) -> Self {
        Self {
            wf,
            run: Run {
                dir: std::path::PathBuf::from(
                    "/var/home/user/.local/share/sentry/workflows/quick-update/run-20261023-180000",
                ),
                state,
            },
            next,
            log: VecDeque::new(),
            live: None,
            armed: true,
            error: None,
            scroll: 0,
        }
    }

    pub fn push(&mut self, text: impl Into<String>, kind: LogKind) {
        if self.log.len() == LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back((text.into(), kind));
    }

    /// Show the end of the current step's log after a resume.
    fn tail_current_log(&mut self) {
        let Some(i) = self.next.idx() else { return };
        let id = self.wf.steps[i].id.clone();
        let Ok(text) = std::fs::read_to_string(self.run.log_path(&id)) else {
            return;
        };
        let lines: Vec<&str> = text.lines().collect();
        for l in &lines[lines.len().saturating_sub(12)..] {
            self.push(format!("  {l}"), LogKind::Out);
        }
    }

    fn save(&mut self) {
        if let Err(e) = self.run.save() {
            self.error = Some(format!("state.json: {e}"));
        }
    }

    pub fn refresh(&mut self) {
        match runner::advance(&self.wf, &mut self.run.state, &RealEnv) {
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

    /// Short state for the banner and dashboard.
    pub fn state_word(&self) -> &'static str {
        if self.live.is_some() {
            return "running";
        }
        if self.error.is_some() {
            return "error";
        }
        match self.next {
            Next::Done => "done",
            Next::Run(_) => {
                if self.armed {
                    "running"
                } else {
                    "ready"
                }
            }
            Next::Confirm(_) => "waiting for confirm",
            Next::Reboot { .. } => "reboot pending",
            Next::Shell(_) => "shell step",
            Next::Manual { failed: true, .. } | Next::Stopped(_) => "failed",
            Next::Manual { .. } => "manual step",
        }
    }

    fn rendered(&mut self, idx: usize) -> Result<String, String> {
        let run = self.wf.steps[idx].run.clone().unwrap_or_default();
        runner::render(&mut self.run.state, &RealEnv, &run)
    }

    fn exec_step(&mut self, idx: usize) -> Option<Exec> {
        // Never start a step twice: Running is set before the app gets the Exec.
        if self.live.is_some() || self.run.state.steps[idx].status == StepStatus::Running {
            return None;
        }
        let cmd = match self.rendered(idx) {
            Ok(c) => c,
            Err(e) => {
                // Into the step's log too, so `L` and fix-with-Claude see why it never ran.
                let id = self.wf.steps[idx].id.clone();
                self.run
                    .append_log(&id, &format!("✗ the command never ran: {e}"));
                self.push(format!("✗ {e}"), LogKind::Err);
                runner::finish(&mut self.run.state, idx, 2, Some(e));
                self.refresh();
                return None;
            }
        };
        let id = self.wf.steps[idx].id.clone();
        let timeout = self.wf.steps[idx].timeout.map(|d| d.0);
        let n = self.wf.steps.len();
        let header = format!("▶ {}/{n} {}", idx + 1, self.title(idx));
        self.push(header, LogKind::Info);
        self.push(format!("$ {cmd}"), LogKind::Cmd);
        runner::start(&mut self.run.state, idx, RealEnv.boot_id());
        self.save();
        self.run.append_log(&id, &format!("$ {cmd}"));
        // sudo in it: the app runs the same script with the password (asked once, there).
        let how = if runner::needs_tty(&cmd) {
            How::Root(cli::step_script(&self.run, &id, &cmd))
        } else {
            How::Plain(cli::step_cmd(&self.run, &id, &cmd))
        };
        Some(Exec::Stream {
            how,
            idx,
            dry: false,
            timeout,
        })
    }

    /// An auto step to run now, if the session is armed and idle.
    pub fn auto(&mut self) -> Option<Exec> {
        if !self.armed || self.live.is_some() || self.error.is_some() {
            return None;
        }
        match self.next {
            Next::Run(i) => self.exec_step(i),
            _ => None,
        }
    }

    /// `Enter` on the gate card. Reboots are confirmed by the screen's modal first.
    pub fn go(&mut self) -> Result<Option<Exec>, String> {
        if self.live.is_some() {
            return Err("a step is running".into());
        }
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        match self.next {
            Next::Done => Err("workflow complete".into()),
            Next::Run(i) => Ok(self.exec_step(i)),
            Next::Confirm(i) => {
                let cmd = self.rendered(i)?;
                let wants_dry = self.wf.steps[i].dry_run != Some(false);
                if wants_dry
                    && !self.run.state.steps[i].dry_ok
                    && let Some(dry) = dry_run_of(&cmd)
                {
                    let id = self.wf.steps[i].id.clone();
                    self.push(
                        format!("▶ dry run first · {}", self.title(i)),
                        LogKind::Info,
                    );
                    self.push(format!("$ {dry}"), LogKind::Cmd);
                    self.run.append_log(&id, &format!("$ {dry}   (dry run)"));
                    return Ok(Some(Exec::Stream {
                        how: How::Plain(cli::step_cmd(&self.run, &id, &dry)),
                        idx: i,
                        dry: true,
                        timeout: Some(Duration::from_secs(1800)),
                    }));
                }
                Ok(self.exec_step(i))
            }
            Next::Reboot { idx, .. } => {
                runner::request_reboot(&self.wf, &mut self.run.state, idx, &RealEnv)?;
                self.save();
                self.push(
                    "↻ rebooting · state saved; run `sentry` after login",
                    LogKind::Info,
                );
                Ok(Some(Exec::Reboot))
            }
            Next::Shell(idx) => {
                runner::start(&mut self.run.state, idx, RealEnv.boot_id());
                self.save();
                Ok(Some(Exec::Shell { idx }))
            }
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

    /// `force`: the user confirmed skipping a step that isn't optional.
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

    /// Accept a manual or failed step as done (after fixing or checking things by hand).
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

    pub fn skip_dry(&mut self) -> Result<(), String> {
        match self.next {
            Next::Confirm(i) => {
                self.run.state.steps[i].dry_ok = true;
                let id = self.wf.steps[i].id.clone();
                self.run.append_log(&id, "dry run skipped by user (D)");
                self.push("dry run skipped by user", LogKind::Info);
                self.save();
                Ok(())
            }
            _ => Err("no dry run pending".into()),
        }
    }

    pub fn abandon(&mut self) {
        runner::abandon(&mut self.run.state);
        self.push("■ abandoned", LogKind::Err);
        self.next = Next::Done;
        self.save();
    }

    /// Rendered commands of the `rollback = true` steps, in order.
    pub fn rollback_cmds(&mut self) -> Vec<(String, Cmd)> {
        let ids: Vec<usize> = (0..self.wf.steps.len())
            .filter(|i| self.wf.steps[*i].rollback && self.wf.steps[*i].kind == Kind::Run)
            .collect();
        ids.into_iter()
            .filter_map(|i| {
                let cmd = self.rendered(i).ok()?;
                let id = self.wf.steps[i].id.clone();
                Some((cmd.clone(), cli::step_cmd(&self.run, &id, &cmd)))
            })
            .collect()
    }

    pub fn on_line(&mut self, text: String, stderr: bool) {
        self.push(text, if stderr { LogKind::Err } else { LogKind::Out });
    }

    /// A streamed or terminal-run command finished.
    pub fn on_exit(&mut self, idx: usize, dry: bool, code: i32, note: Option<String>) {
        self.live = None;
        let id = self.wf.steps[idx].id.clone();
        if dry {
            // Kept in the step's log and state, whatever comes next.
            self.run.state.steps[idx].dry_code = Some(code);
            self.run.append_log(&id, &format!("(dry run exit {code})"));
            let dry_cmd = self.rendered(idx).ok().and_then(|c| dry_run_of(&c));
            if dry_cmd.is_some_and(|d| crate::workflows::dry_nothing_to_do(&d, code)) {
                let why = "nothing to do: the dry run found no update (exit 77)";
                self.run.append_log(&id, why);
                runner::skip(&mut self.run.state, idx, why);
                self.push(format!("– {id}: {why}"), LogKind::Info);
                self.refresh();
                return;
            }
            if code == 0 {
                self.run.state.steps[idx].dry_ok = true;
                self.push("✓ dry run ok · Enter runs it for real", LogKind::Ok);
            } else {
                self.push(
                    format!("✗ dry run failed (exit {code}) · Enter retries · D skips the dry run"),
                    LogKind::Err,
                );
            }
            self.save();
            return;
        }
        if let Some(n) = &note {
            self.push(n.clone(), LogKind::Err);
        }
        runner::complete(&self.wf, &mut self.run.state, idx, code, note, &RealEnv);
        if code == 0 {
            self.push(format!("✓ {id} done"), LogKind::Ok);
        } else {
            self.push(
                format!("✗ {id} failed (exit {code}) · steps/{id}.log"),
                LogKind::Err,
            );
        }
        self.refresh();
        if self.done() {
            self.push(format!("✓ {} complete", self.wf.name), LogKind::Ok);
        }
    }

    pub fn after_shell(&mut self, idx: usize) {
        runner::mark_done(&mut self.run.state, idx, "shell exited");
        self.push("✓ shell exited", LogKind::Ok);
        self.refresh();
    }
}

/// The run as the app holds it. Its steps become commands in `LocalTarget::run_go`.
impl sentry_app::run::WfRun for Session {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    fn wf(&self) -> &Workflow {
        &self.wf
    }
    fn run(&self) -> &Run {
        &self.run
    }
    fn next(&self) -> &Next {
        &self.next
    }
    fn live(&self) -> Option<&Live> {
        self.live.as_ref()
    }
    fn set_live(&mut self, live: Option<Live>) -> Option<Live> {
        std::mem::replace(&mut self.live, live)
    }
    fn armed(&self) -> bool {
        self.armed
    }
    fn arm(&mut self) {
        self.armed = true;
    }
    fn done(&self) -> bool {
        Session::done(self)
    }
    fn title(&self, idx: usize) -> String {
        Session::title(self, idx)
    }
    fn state_word(&self) -> &'static str {
        Session::state_word(self)
    }
    fn push(&mut self, text: String, kind: LogKind) {
        Session::push(self, text, kind);
    }
    fn on_line(&mut self, text: &str, stderr: bool) {
        Session::on_line(self, text.to_string(), stderr);
    }
    /// The running step's exit (its dry run's, if that's what ran).
    fn on_exit(&mut self, idx: usize, code: i32) {
        let dry = self.live.as_ref().is_some_and(|l| l.dry);
        Session::on_exit(self, idx, dry, code, None);
    }
    fn spawn_failed(&mut self, idx: usize, dry: bool, err: &str) {
        Session::on_exit(self, idx, dry, 127, Some(err.to_string()));
    }
    fn after_shell(&mut self, idx: usize) {
        Session::after_shell(self, idx);
    }
    fn skip(&mut self, force: bool) -> Result<(), String> {
        Session::skip(self, force)
    }
    /// `r`: after an error of sentry's own (state.json, a tty that isn't there) the run is
    /// looked at again; otherwise the failed step is retried.
    fn retry(&mut self) -> Result<(), String> {
        if self.error.is_some() {
            self.refresh();
            Ok(())
        } else {
            Session::retry(self)
        }
    }
    fn mark_done(&mut self) -> Result<(), String> {
        Session::mark_done(self)
    }
    fn abandon(&mut self) {
        Session::abandon(self);
    }
    /// This machine's reboot ends the TUI; the run is resumed by the next one.
    fn after_reboot(&mut self) {}
    /// `L` opens the step's log file in a pager (`WfOwn::OpenLog`).
    fn step_log(&self) -> Option<(String, String)> {
        None
    }
    fn command(&mut self, idx: usize) -> Option<String> {
        self.wf.steps[idx].run.as_ref()?;
        self.rendered(idx).ok()
    }
    fn auto_answered(&mut self, what: &str) {
        if !self.run.state.auto.iter().any(|a| a == what) {
            self.run.state.auto.push(what.to_string());
            self.save();
        }
    }
}

//! One apply session, start to finish, as a state machine both programs drive. The user makes
//! two decisions (start it, approve the plan); everything between follows by itself:
//!
//! ```text
//! Brief ─Enter→ Thinking(Investigate) → Review ─Enter→ [SudoCheck → Password] → Applying
//!                  ↑   ↑ problems / a failed step: Thinking(Fix), at most FIX_ROUNDS │
//!                  │   └──────────────────────────────────────────────────────────────┤
//!                  │                              all steps done → Thinking(Verify) ←┘
//!                  └── typed text (Review, Settled)        verdict → Settled / Review (more)
//! ```
//!
//! The session never runs anything itself except edits of your own files: it returns `Fx`,
//! and each app carries them out (a Claude turn, a command, sudo's check, a workflow) and
//! reports back (`turn_ended`, `step_ended`, `sudo_checked`, `password_checked`,
//! `workflow_ended`).

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::plan::{self, Action, Kind as StepKind, Plan, Run, RunState};
use super::sudo::{self, Owner, RootWrite, Secret};
use super::verdict::{self, Status};
use crate::claude::Ask;
use crate::tui::chat::{Chat, Kind};

/// Times sentry goes back to Claude by itself (a plan it can't use, a failed step, no
/// verdict) before it waits for the user.
pub const FIX_ROUNDS: u8 = 2;

/// Why Claude is answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Turn {
    /// The first turn, or the user asked for something.
    Investigate,
    /// sentry sent a problem with the plan, or a failed step.
    Fix,
    /// sentry sent the results to verify.
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// Verified: the task is done.
    Done,
    /// Claude says it didn't work, or the fix rounds ran out.
    Failed,
    /// The user stopped it (C-c on a step).
    Stopped,
    /// Applied, but Claude didn't give a verdict.
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The brief, before anything is sent: Enter starts.
    Brief,
    Thinking(Turn),
    /// What Claude answered, a plan with it or not: Enter applies, typing asks for a change.
    Review,
    /// Whether sudo asks for a password (`sudo -n true`), before the first sudo step.
    SudoCheck,
    /// The password, typed inline; `checking` while sudo checks it.
    Password {
        tries: u8,
        checking: bool,
    },
    Applying,
    Settled(End),
}

/// What the app carries out for the session.
#[derive(Debug, Clone, PartialEq)]
pub enum Fx {
    /// A Claude turn (resuming the conversation once there is one). `shown`: the user's own
    /// words for the transcript; None for what sentry sends (its line is already there).
    Turn {
        prompt: String,
        shown: Option<String>,
    },
    /// Stop the running turn or step.
    Kill(u32),
    /// Run a step's command in a shell; `sudo`: through `sudo::wrap` with the password when
    /// one was given.
    Command {
        cmd: String,
        sudo: bool,
    },
    /// `sudo -n true`: then `sudo_checked`.
    CheckSudo,
    /// The typed password, through `sudo::check_script`: then `password_checked`.
    CheckPassword,
    StartWorkflow(String),
    /// The workflow needs the user (a confirm, a manual step): show its run.
    OpenRun,
    /// One maintenance-log entry (`kind = "apply"`).
    Log {
        ok: bool,
        body: String,
        tags: Vec<String>,
    },
    /// Audit again (a finding's session): then `reaudited`.
    Reaudit,
    /// Retry the failed workflow step this session fixed (and show its run).
    RetryStep,
    /// Mark the task (or the plan done by hand) done, by hand: Claude didn't say it is.
    MarkDone,
    /// A check for later, as a one-time task on Maintenance (due after its `after`).
    AddTask(Box<crate::maint::tasks::Task>),
    /// A task done with nothing else logged: logged as such (tagged `task:<id>`). Usually
    /// the apply entry carries the tag instead.
    TaskDone(String),
    Hide,
    Close,
}

pub struct Session {
    /// The transcript and Claude's turns.
    pub chat: Chat,
    pub phase: Phase,
    /// Every plan Claude sent, the current one last; each is a `Kind::Plan` entry in the
    /// transcript, where it was sent.
    pub runs: Vec<Run>,
    /// Why an earlier plan was replaced (by index).
    pub replaced: Vec<(usize, String)>,
    /// What stops the current plan, when the fix rounds have run out.
    pub problems: Vec<(usize, String)>,
    /// Why the current plan went back to Claude (shown when the next one replaces it).
    sent_back: Option<String>,
    fixes: u8,
    /// The transcript's length when the turn started: the answer comes after.
    turn_from: usize,
    /// The step's command running, and what it printed.
    pub job: Option<(u64, u32)>,
    /// When the running step started (the window shows how long it's been).
    pub job_started: Option<std::time::Instant>,
    pub output: Vec<String>,
    root: Option<RootWrite>,
    /// C-c on a step: it ends as stopped, nothing sent.
    stopping: bool,
    /// The sudo password, once given and accepted (`secret_ok`); wiped when it settles.
    pub secret: Secret,
    pub secret_ok: bool,
    /// The plan needs no password (sudo didn't ask).
    sudo_free: bool,
    /// Runs already in the log.
    logged: usize,
    /// Tab: the brief shown whole.
    pub brief_open: bool,
    /// The run's report, while the audit runs before the verify turn.
    audit_for: Option<String>,
}

impl Session {
    pub fn new(ask: Ask) -> Self {
        Self {
            chat: Chat::new(ask),
            phase: Phase::Brief,
            runs: Vec::new(),
            replaced: Vec::new(),
            problems: Vec::new(),
            sent_back: None,
            fixes: 0,
            turn_from: 0,
            job: None,
            job_started: None,
            output: Vec::new(),
            root: None,
            stopping: false,
            secret: Secret::default(),
            secret_ok: false,
            sudo_free: false,
            logged: 0,
            brief_open: false,
            audit_for: None,
        }
    }

    /// From a chat about the same thing (`a`): the conversation so far, Claude's session
    /// with it (the first turn resumes it), what was granted; `ask` is the apply ask.
    pub fn from_chat(mut chat: Chat, ask: Ask) -> Self {
        chat.ask = ask;
        chat.pending = false;
        chat.hidden = false;
        chat.apply_with = None;
        chat.input.clear();
        let mut s = Self::new(chat.ask.clone());
        s.chat = chat;
        s
    }

    /// What Enter does now on an empty input, in a word or two (None: nothing).
    pub fn enter_word(&self) -> Option<&'static str> {
        let a = self.chat.ask.applying();
        match self.phase {
            Phase::Brief => Some("start"),
            Phase::Review if self.can_approve() => Some("apply the plan"),
            Phase::Review if self.run().is_none() || self.run().is_some_and(|r| r.finished()) => {
                Some("ask for a plan")
            }
            Phase::Applying if self.waiting_workflow().is_some() => Some("open the workflow"),
            Phase::Settled(End::Done) if a.is_some_and(|a| a.step.is_some()) => {
                Some("retry the step")
            }
            Phase::Settled(End::Done) => Some("close"),
            Phase::Settled(_) if a.is_some_and(|a| a.finding.is_some() && !a.remote) => {
                Some("audit again")
            }
            Phase::Settled(_) if a.is_some_and(|a| a.can_mark_done()) => Some("mark it done"),
            _ => None,
        }
    }

    /// The plan on screen (the latest).
    pub fn run(&self) -> Option<&Run> {
        self.runs.last()
    }

    fn run_mut(&mut self) -> Option<&mut Run> {
        self.runs.last_mut()
    }

    /// The task this session does, if it's one.
    pub fn task(&self) -> Option<&str> {
        self.chat.ask.applying().and_then(|a| a.task.as_deref())
    }

    /// The workflow the plan waits for.
    pub fn waiting_workflow(&self) -> Option<&str> {
        let r = self.run()?;
        match r.state {
            RunState::WaitingWorkflow(i) => match &r.plan.steps[i].kind {
                StepKind::Workflow(w) => Some(w),
                _ => None,
            },
            _ => None,
        }
    }

    /// Enter applies: a plan, not started, nothing in its way.
    pub fn can_approve(&self) -> bool {
        self.phase == Phase::Review
            && self.problems.is_empty()
            && self.run().is_some_and(|r| r.state == RunState::Proposed)
    }

    /// Something runs (a turn, a step, a check): Esc hides instead of closing.
    pub fn busy(&self) -> bool {
        self.audit_for.is_some()
            || matches!(
                self.phase,
                Phase::Thinking(_)
                    | Phase::Applying
                    | Phase::SudoCheck
                    | Phase::Password { checking: true, .. }
            )
    }

    /// The steps that need sudo (numbered from 1), for the password line.
    pub fn sudo_steps(&self) -> Vec<usize> {
        let Some(r) = self.run() else {
            return Vec::new();
        };
        r.plan
            .steps
            .iter()
            .enumerate()
            .filter(|(_, s)| needs_sudo(s))
            .map(|(i, _)| i + 1)
            .collect()
    }

    fn turn(&mut self, why: Turn, prompt: String, shown: Option<String>) -> Vec<Fx> {
        self.phase = Phase::Thinking(why);
        self.turn_from = self.chat.entries.len();
        vec![Fx::Turn { prompt, shown }]
    }

    /// sentry goes back to Claude by itself (`line`: what the transcript says), while it
    /// may; otherwise the plan waits in Review with `problems` shown.
    fn fix(&mut self, line: String, prompt: String) -> Option<Vec<Fx>> {
        if self.fixes >= FIX_ROUNDS {
            return None;
        }
        self.fixes += 1;
        self.chat.push(Kind::Info, line);
        Some(self.turn(Turn::Fix, crate::claude::apply_fix(&prompt), None))
    }

    /// The verdict is missing or wrong: asked again, as a verify turn (its answer is a
    /// verdict, not a plan), while the rounds last.
    fn ask_verdict(&mut self, line: String, prompt: String) -> Option<Vec<Fx>> {
        if self.fixes >= FIX_ROUNDS {
            return None;
        }
        self.fixes += 1;
        self.chat.push(Kind::Info, line);
        Some(self.turn(Turn::Verify, prompt, None))
    }

    // ── Keys ────────────────────────────────────────────────────────────────────────────

    pub fn key(&mut self, k: KeyEvent) -> Vec<Fx> {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && k.code == KeyCode::Char('c') {
            return self.stop();
        }
        match k.code {
            KeyCode::Up => self.chat.scroll_by(1),
            KeyCode::Down => self.chat.scroll_by(-1),
            KeyCode::PageUp => self.chat.scroll_by(10),
            KeyCode::PageDown => self.chat.scroll_by(-10),
            KeyCode::Home => self.chat.scroll_top(),
            KeyCode::End => self.chat.scroll_bottom(),
            KeyCode::Tab => self.brief_open = !self.brief_open,
            KeyCode::Esc => return self.esc(),
            _ => return self.typed(k.code, ctrl),
        }
        Vec::new()
    }

    fn stop(&mut self) -> Vec<Fx> {
        match self.phase {
            Phase::Thinking(_) => match self.chat.live {
                Some((_, pid)) => vec![Fx::Kill(pid)],
                None => Vec::new(),
            },
            Phase::Applying => match self.job {
                Some((_, pid)) => {
                    self.stopping = true;
                    vec![Fx::Kill(pid)]
                }
                None => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    fn esc(&mut self) -> Vec<Fx> {
        match self.phase {
            Phase::Brief => vec![Fx::Close],
            Phase::Password {
                checking: false, ..
            } => {
                self.secret.clear();
                self.phase = Phase::Review;
                Vec::new()
            }
            _ if self.busy() => vec![Fx::Hide],
            // Done with: what ran and isn't logged yet goes in the log first.
            _ => {
                let mut fx = self.log_runs(None);
                fx.push(Fx::Close);
                fx
            }
        }
    }

    fn typed(&mut self, code: KeyCode, ctrl: bool) -> Vec<Fx> {
        if let Phase::Password {
            tries,
            checking: false,
        } = self.phase
        {
            match code {
                KeyCode::Char(c) if !ctrl => self.secret.push(c),
                KeyCode::Backspace => self.secret.pop(),
                KeyCode::Enter if !self.secret.is_empty() => {
                    self.phase = Phase::Password {
                        tries,
                        checking: true,
                    };
                    return vec![Fx::CheckPassword];
                }
                _ => {}
            }
            return Vec::new();
        }
        if self.phase == Phase::Applying {
            if code == KeyCode::Enter && self.waiting_workflow().is_some() {
                return vec![Fx::OpenRun];
            }
            return Vec::new();
        }
        if !matches!(self.phase, Phase::Brief | Phase::Review | Phase::Settled(_)) {
            return Vec::new();
        }
        match code {
            KeyCode::Char(c) if !ctrl => self.chat.input.push(c),
            KeyCode::Backspace => {
                self.chat.input.pop();
            }
            KeyCode::Enter => return self.enter(),
            _ => {}
        }
        Vec::new()
    }

    fn enter(&mut self) -> Vec<Fx> {
        let text = std::mem::take(&mut self.chat.input);
        let text = text.trim().to_string();
        // The user decided something: sentry may go back to Claude again by itself.
        self.fixes = 0;
        match self.phase {
            Phase::Brief => {
                let mut prompt = self.chat.ask.prompt();
                let shown = if text.is_empty() {
                    "Help me apply this.".to_string()
                } else {
                    prompt.push_str(&format!("\n\nFrom me: {text}"));
                    text
                };
                self.turn(Turn::Investigate, prompt, Some(shown))
            }
            Phase::Review if text.is_empty() => match self.enter_word() {
                Some("apply the plan") => self.approve(),
                Some("ask for a plan") => self.turn(
                    Turn::Investigate,
                    "Answer with the plan, as one sentry-apply block.".into(),
                    Some("Send the plan.".into()),
                ),
                _ => Vec::new(),
            },
            Phase::Settled(_) if text.is_empty() => match self.enter_word() {
                Some("retry the step") => vec![Fx::RetryStep, Fx::Close],
                Some("close") => vec![Fx::Close],
                Some("audit again") => {
                    self.chat.push(Kind::Info, "auditing again…");
                    vec![Fx::Reaudit]
                }
                Some("mark it done") => {
                    self.chat.push(Kind::Info, "marked done by hand · logged");
                    self.phase = Phase::Settled(End::Done);
                    vec![Fx::MarkDone]
                }
                _ => Vec::new(),
            },
            _ if text.is_empty() => Vec::new(),
            _ => self.turn(Turn::Investigate, text.clone(), Some(text)),
        }
    }

    // ── Applying ────────────────────────────────────────────────────────────────────────

    fn approve(&mut self) -> Vec<Fx> {
        let sudo = self
            .run()
            .is_some_and(|r| r.plan.steps.iter().any(needs_sudo));
        if sudo && !self.secret_ok && !self.sudo_free {
            self.phase = Phase::SudoCheck;
            return vec![Fx::CheckSudo];
        }
        self.start()
    }

    fn start(&mut self) -> Vec<Fx> {
        self.phase = Phase::Applying;
        let Some(r) = self.run_mut() else {
            return Vec::new();
        };
        let a = r.start();
        self.drive(a)
    }

    /// `sudo -n true` came back: no password needed, or ask for it.
    pub fn sudo_checked(&mut self, needs_password: bool) -> Vec<Fx> {
        if self.phase != Phase::SudoCheck {
            return Vec::new();
        }
        if needs_password {
            self.phase = Phase::Password {
                tries: 0,
                checking: false,
            };
            Vec::new()
        } else {
            self.sudo_free = true;
            self.start()
        }
    }

    /// sudo checked the password.
    pub fn password_checked(&mut self, ok: bool) -> Vec<Fx> {
        let Phase::Password { tries, .. } = self.phase else {
            return Vec::new();
        };
        if ok {
            self.secret_ok = true;
            return self.start();
        }
        self.secret.clear();
        if tries + 1 >= 3 {
            self.phase = Phase::Review;
            self.chat
                .push(Kind::Err, "sudo refused the password 3 times; nothing ran");
        } else {
            self.phase = Phase::Password {
                tries: tries + 1,
                checking: false,
            };
        }
        Vec::new()
    }

    /// Carry the plan on from `a`: your own files are edited here, the rest goes to the app.
    fn drive(&mut self, mut a: Action) -> Vec<Fx> {
        loop {
            let Some(r) = self.runs.last_mut() else {
                return Vec::new();
            };
            match a {
                Action::Edit(i) => {
                    let step = r.plan.steps[i].clone();
                    let StepKind::Edit { file, old, new } = &step.kind else {
                        a = r.step_done(false, "not an edit".into());
                        continue;
                    };
                    match sudo::edit_target(file) {
                        Ok(Owner::You) => {
                            let (ok, note) = match plan::apply_edit(&step) {
                                Ok((b, before, after)) => (
                                    true,
                                    format!("{before} → {after} lines · backup {}", b.display()),
                                ),
                                Err(e) => (false, e),
                            };
                            a = r.step_done(ok, note);
                        }
                        Ok(Owner::Root) => match sudo::prepare_root_edit(file, old, new) {
                            Ok(w) => {
                                let cmd = w.script();
                                self.root = Some(w);
                                self.output.clear();
                                return vec![Fx::Command { cmd, sudo: true }];
                            }
                            Err(e) => a = r.step_done(false, e),
                        },
                        Err(e) => a = r.step_done(false, e),
                    }
                }
                Action::Command { cmd, .. } => {
                    self.output.clear();
                    return vec![Fx::Command {
                        sudo: sudo::uses_sudo(&cmd),
                        cmd,
                    }];
                }
                Action::StartWorkflow(_, wf) => {
                    self.output.clear();
                    return vec![Fx::StartWorkflow(wf)];
                }
                Action::Finished => return self.finished(),
            }
        }
    }

    /// The step's command started (`id`, `pid`), printed a line, ended.
    pub fn step_started(&mut self, id: u64, pid: u32) {
        self.job = Some((id, pid));
        self.job_started = Some(std::time::Instant::now());
    }

    pub fn step_line(&mut self, text: String) {
        self.output.push(text);
        if self.output.len() > 400 {
            self.output.drain(..200);
        }
    }

    pub fn step_ended(&mut self, code: i32) -> Vec<Fx> {
        self.job = None;
        let out = plan::tail(&self.output.join("\n"), 15);
        let mut note = if self.stopping {
            "stopped".to_string()
        } else {
            format!("exit {code}")
        };
        if let Some(w) = self.root.take() {
            w.cleanup();
            if code == 0 {
                note = format!(
                    "{} → {} lines · backup {}",
                    w.before,
                    w.after,
                    w.backup.display()
                );
            }
        }
        if !out.trim().is_empty() {
            note.push('\n');
            note.push_str(&out);
        }
        let ok = code == 0 && !self.stopping;
        let Some(r) = self.run_mut() else {
            return Vec::new();
        };
        let a = r.step_done(ok, note);
        self.drive(a)
    }

    /// The audit ran again (`gone`: the finding isn't reported any more): after the plan, the
    /// verify turn says so; after the session ended, it's done if the finding is gone.
    pub fn reaudited(&mut self, gone: bool) -> Vec<Fx> {
        let line = if gone {
            "sentry's audit no longer reports the finding"
        } else {
            "sentry's audit still reports the finding"
        };
        if let Some(report) = self.audit_for.take() {
            self.chat.push(
                if gone { Kind::Good } else { Kind::Err },
                format!("{line} · Claude is verifying the result"),
            );
            let prompt = crate::claude::apply_verify(&format!("{report}\n\nAfter it, {line}."));
            return self.turn(Turn::Verify, prompt, None);
        }
        if matches!(self.phase, Phase::Settled(_)) {
            self.chat
                .push(if gone { Kind::Good } else { Kind::Err }, line.to_string());
            if gone {
                self.phase = Phase::Settled(End::Done);
            }
        }
        Vec::new()
    }

    /// A workflow run ended: the step that waited for it is done (or failed).
    pub fn workflow_ended(&mut self, workflow: &str, ok: bool, note: String) -> Vec<Fx> {
        if self.waiting_workflow() != Some(workflow) {
            return Vec::new();
        }
        let Some(r) = self.run_mut() else {
            return Vec::new();
        };
        let a = r.step_done(ok, note);
        self.drive(a)
    }

    /// The last step ended, or one failed.
    fn finished(&mut self) -> Vec<Fx> {
        let Some(r) = self.run() else {
            return Vec::new();
        };
        let report = r.report();
        match r.state {
            RunState::Failed(k) => {
                let title = r.plan.steps[k].title.clone();
                if std::mem::take(&mut self.stopping) {
                    self.chat
                        .push(Kind::Err, format!("stopped at step {} ({title})", k + 1));
                    return self.settle(End::Stopped);
                }
                let line = format!(
                    "✗ step {} ({title}) failed · sentry sent Claude what happened, for a plan for the rest",
                    k + 1
                );
                match self.fix(line, report) {
                    Some(fx) => fx,
                    None => {
                        self.chat.push(
                            Kind::Err,
                            format!("step {} ({title}) failed again; it's yours now", k + 1),
                        );
                        self.settle(End::Failed)
                    }
                }
            }
            _ => {
                let n = r.plan.steps.len();
                if self
                    .chat
                    .ask
                    .applying()
                    .is_some_and(|a| a.finding.is_some() && !a.remote)
                {
                    self.chat.push(
                        Kind::Info,
                        format!("✓ all {n} steps done · sentry is auditing again"),
                    );
                    self.audit_for = Some(report);
                    return vec![Fx::Reaudit];
                }
                self.chat.push(
                    Kind::Info,
                    format!("✓ all {n} steps done · Claude is verifying the result"),
                );
                self.turn(Turn::Verify, crate::claude::apply_verify(&report), None)
            }
        }
    }

    // ── Claude's answers ────────────────────────────────────────────────────────────────

    /// The turn ended (`code`: claude's exit): what the answer means for the session.
    /// `workflows`: the names sentry knows, for the plan's problems.
    pub fn turn_ended(&mut self, code: i32, workflows: &[String]) -> Vec<Fx> {
        self.chat.on_exit(code);
        let Phase::Thinking(why) = self.phase else {
            return Vec::new();
        };
        let Some(at) = (self.turn_from..self.chat.entries.len())
            .rev()
            .find(|i| self.chat.entries[*i].0 == Kind::Claude)
        else {
            // No answer (an error, or stopped).
            return match why {
                Turn::Verify => self.settle(End::Unverified),
                _ => {
                    self.phase = Phase::Review;
                    Vec::new()
                }
            };
        };
        match why {
            Turn::Investigate | Turn::Fix => self.answered(at, workflows),
            Turn::Verify => self.verified(at, workflows),
        }
    }

    /// An answer that should carry a plan.
    fn answered(&mut self, at: usize, workflows: &[String]) -> Vec<Fx> {
        let (body, plan) = plan::take(&self.chat.entries[at].1);
        self.chat.entries[at].1 = body;
        match plan {
            Some(Ok(p)) => self.new_plan(at, p, workflows),
            Some(Err(why)) => {
                let line = format!("the plan didn't parse ({why}) · sentry asked Claude again");
                match self.fix(
                    line,
                    format!("sentry couldn't read your sentry-apply block: {why}."),
                ) {
                    Some(fx) => fx,
                    None => {
                        self.chat
                            .push(Kind::Err, format!("the plan didn't parse: {why}"));
                        self.phase = Phase::Review;
                        Vec::new()
                    }
                }
            }
            None => {
                self.phase = Phase::Review;
                Vec::new()
            }
        }
    }

    fn new_plan(&mut self, at: usize, p: Plan, workflows: &[String]) -> Vec<Fx> {
        if let Some(i) = self.runs.len().checked_sub(1) {
            let why = match (self.runs[i].state, self.sent_back.take()) {
                (RunState::Failed(k), _) => format!("stopped at step {}", k + 1),
                (RunState::Done, _) => "done".into(),
                (_, Some(why)) => why,
                _ if !self.problems.is_empty() => "it couldn't be used".into(),
                _ => "replaced".into(),
            };
            self.replaced.push((i, why));
        }
        self.problems.clear();
        let mut problems = plan::problems(&p, workflows);
        // On a server, root's files are changed there (`run`), not here.
        if self.chat.ask.applying().is_some_and(|a| a.remote) {
            for (i, st) in p.steps.iter().enumerate() {
                if let StepKind::Edit { file, .. } = &st.kind
                    && sudo::edit_target(file) != Ok(Owner::You)
                    && !problems.iter().any(|(k, _)| *k == i)
                {
                    problems.push((
                        i,
                        format!("{file}: edit steps are for files on this machine; change the server's with a run step"),
                    ));
                }
            }
            problems.sort_by_key(|(i, _)| *i);
        }
        self.runs.push(Run::new(p));
        self.chat
            .entries
            .insert(at + 1, (Kind::Plan, (self.runs.len() - 1).to_string()));
        if problems.is_empty() {
            self.phase = Phase::Review;
            return Vec::new();
        }
        let r = self.run().expect("just pushed");
        let list: Vec<String> = problems
            .iter()
            .map(|(i, why)| format!("- step {} ({}): {why}", i + 1, r.plan.steps[*i].title))
            .collect();
        let line = format!(
            "sentry can't use step {} as written · asked Claude for a corrected plan",
            problems
                .iter()
                .map(|(i, _)| (i + 1).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        let prompt = format!(
            "sentry can't apply your plan as it is:\n{}",
            list.join("\n")
        );
        self.sent_back = Some(format!(
            "sent back: step {}: {}",
            problems[0].0 + 1,
            problems[0].1
        ));
        match self.fix(line, prompt) {
            Some(fx) => fx,
            None => {
                self.problems = problems;
                self.phase = Phase::Review;
                Vec::new()
            }
        }
    }

    /// The verify turn's answer: a verdict (and, with `more`, a plan).
    fn verified(&mut self, at: usize, workflows: &[String]) -> Vec<Fx> {
        let (body, v) = verdict::take(&self.chat.entries[at].1);
        self.chat.entries[at].1 = body;
        let v = match v {
            Some(Ok(v)) => v,
            Some(Err(why)) => {
                let line = format!("the verdict didn't parse ({why}) · sentry asked again");
                return self
                    .ask_verdict(line, format!("sentry couldn't read your sentry-verdict block: {why}. Answer with the verdict block."))
                    .unwrap_or_else(|| self.settle(End::Unverified));
            }
            None => {
                return self
                    .ask_verdict(
                        "no verdict · sentry asked Claude for one".into(),
                        "Your answer has no sentry-verdict block. Answer with it.".into(),
                    )
                    .unwrap_or_else(|| self.settle(End::Unverified));
            }
        };
        let next = |s: &mut Self| {
            if !v.next.is_empty() {
                s.chat.push(Kind::Info, format!("next: {}", v.next));
            }
        };
        match v.status {
            Status::Done => {
                self.chat
                    .push(Kind::Good, format!("✓ Done · {}", v.summary));
                next(self);
                let mut fx = self.settle_with(End::Done, Some(&v.summary));
                if let Some(f) = &v.follow_up {
                    let t = self.follow_up_task(f, workflows);
                    self.chat.push(
                        Kind::Info,
                        format!("follow-up on Maintenance: {} ({})", t.title, t.when()),
                    );
                    fx.push(Fx::AddTask(Box::new(t)));
                }
                fx
            }
            Status::Failed => {
                self.chat
                    .push(Kind::Err, format!("✗ Not done · {}", v.summary));
                next(self);
                self.settle_with(End::Failed, Some(&v.summary))
            }
            Status::More => {
                self.chat
                    .push(Kind::Info, format!("Something's left · {}", v.summary));
                let (body, plan) = plan::take(&self.chat.entries[at].1);
                match plan {
                    Some(Ok(p)) => {
                        self.chat.entries[at].1 = body;
                        // What ran so far goes in the log now; the next plan gets its own.
                        let mut fx = self.log_runs(Some(&v.summary));
                        fx.extend(self.new_plan(at, p, workflows));
                        fx
                    }
                    _ => self.settle_with(End::Unverified, Some(&v.summary)),
                }
            }
        }
    }

    /// Claude's check for later, as a task: done by hand (Enter works it out with Claude),
    /// due after the workflow's next good run or the wait. An `after` sentry doesn't know
    /// goes into the steps instead.
    fn follow_up_task(
        &self,
        f: &verdict::FollowUp,
        workflows: &[String],
    ) -> crate::maint::tasks::Task {
        let slug: String = f
            .title
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .split('-')
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join("-");
        let slug: String = slug.chars().take(40).collect();
        let now = jiff::Timestamp::now();
        let known = |a: &String| {
            a.parse::<crate::config::Dur>().is_ok() || workflows.iter().any(|w| w == a)
        };
        let mut steps = f.steps.clone();
        let after = match &f.after {
            Some(a) if known(a) => Some(a.clone()),
            Some(a) => {
                steps = format!("Once {a}:\n\n{steps}");
                None
            }
            None => None,
        };
        crate::maint::tasks::Task {
            id: format!(
                "check-{}-{}",
                slug.trim_end_matches('-'),
                now.strftime("%Y%m%d")
            ),
            title: f.title.clone(),
            why: format!(
                "A follow-up of: {}",
                self.chat.ask.subject.trim_start_matches("apply · ")
            ),
            level: crate::maint::Level::Routine,
            every: None,
            act: "by-hand".into(),
            item: self.chat.ask.applying().and_then(|a| a.item.clone()),
            steps,
            added: Some(now),
            off: false,
            source: Default::default(),
            review: None,
            after,
        }
    }

    // ── The end ─────────────────────────────────────────────────────────────────────────

    fn settle(&mut self, end: End) -> Vec<Fx> {
        self.settle_with(end, None)
    }

    fn settle_with(&mut self, end: End, verdict: Option<&str>) -> Vec<Fx> {
        self.phase = Phase::Settled(end);
        self.secret.clear();
        self.secret_ok = false;
        let mut fx = self.log_runs(verdict);
        if end == End::Done
            && let Some(id) = self.task().map(str::to_string)
        {
            // The apply entry, tagged with the task, is what marks it done.
            match fx.iter_mut().find_map(|f| match f {
                Fx::Log { tags, .. } => Some(tags),
                _ => None,
            }) {
                Some(tags) => tags.push(format!("task:{id}")),
                None => fx.push(Fx::TaskDone(id)),
            }
            self.chat.push(Kind::Info, "task marked done · logged");
        } else if !fx.is_empty() {
            self.chat.push(Kind::Info, "logged");
        }
        fx
    }

    /// The runs that started since the last log entry, as one entry.
    fn log_runs(&mut self, verdict: Option<&str>) -> Vec<Fx> {
        let started: Vec<&Run> = self.runs[self.logged.min(self.runs.len())..]
            .iter()
            .filter(|r| !r.results.is_empty())
            .collect();
        if started.is_empty() {
            return Vec::new();
        }
        let ok = started.last().is_some_and(|r| r.state == RunState::Done)
            && !matches!(self.phase, Phase::Settled(End::Failed | End::Stopped));
        let mut body = Vec::new();
        let mut tags: Vec<String> = self
            .chat
            .ask
            .applying()
            .map(|a| format!("apply:{}", a.key))
            .into_iter()
            .collect();
        if let Some(f) = self.chat.ask.applying().and_then(|a| a.finding.clone()) {
            tags.push(format!("finding:{f}"));
        }
        for r in &started {
            body.push(format!("{}\n\n{}", r.plan.summary, r.report()));
            if !r.plan.rollback.trim().is_empty() {
                body.push(format!("To undo: {}", r.plan.rollback.trim()));
            }
            for (s, res) in r.plan.steps.iter().zip(&r.results) {
                if let StepKind::Edit { file, .. } = &s.kind
                    && res.ok
                {
                    let t = format!("file:{file}");
                    if !tags.contains(&t) {
                        tags.push(t);
                    }
                }
            }
        }
        if let Some(v) = verdict {
            body.push(format!("Claude: {v}"));
        }
        self.logged = self.runs.len();
        vec![Fx::Log {
            ok,
            body: body.join("\n\n"),
            tags,
        }]
    }
}

fn needs_sudo(s: &plan::Step) -> bool {
    match &s.kind {
        StepKind::Run(c) | StepKind::Check(c) => sudo::uses_sudo(c),
        StepKind::Edit { file, .. } => sudo::edit_target(file) == Ok(Owner::Root),
        StepKind::Workflow(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claude::{Apply, Event};

    fn key(s: &mut Session, c: KeyCode) -> Vec<Fx> {
        s.key(KeyEvent::new(c, KeyModifiers::NONE))
    }

    fn type_in(s: &mut Session, text: &str) {
        for c in text.chars() {
            key(s, KeyCode::Char(c));
        }
    }

    fn session() -> Session {
        Session::new(Ask::apply(
            "the cheatsheet",
            "ctx",
            Apply {
                key: "task:sheet".into(),
                task: Some("sheet".into()),
                ..Default::default()
            },
        ))
    }

    /// The app's side of a turn: started, Claude's text, ended.
    fn answer(s: &mut Session, fx: &[Fx], text: &str) -> Vec<Fx> {
        let Some(Fx::Turn { shown, .. }) = fx.iter().find(|f| matches!(f, Fx::Turn { .. })) else {
            panic!("no turn in {fx:?}");
        };
        match shown {
            Some(q) => s.chat.begin_turn(q, 1, 7),
            None => s.chat.begin_quiet(1, 7),
        }
        s.chat.on_event(Event::Text(text.into()));
        s.turn_ended(0, &["quick-update".into()])
    }

    fn plan(steps: &str) -> String {
        format!(
            "Found it.\n\n```sentry-apply\nsummary = \"fix it\"\nrollback = \"restore the backup\"\n{steps}```\n"
        )
    }

    const CHECKS: &str = "[[step]]\ntitle = \"one\"\ncheck = \"true\"\n\n[[step]]\ntitle = \"two\"\nrun = \"echo hi\"\n";

    #[test]
    fn two_decisions_and_the_rest_follows() {
        let mut s = session();
        assert_eq!(s.phase, Phase::Brief);
        type_in(&mut s, "keep it short");
        let fx = key(&mut s, KeyCode::Enter);
        let Fx::Turn { prompt, shown } = &fx[0] else {
            panic!("{fx:?}")
        };
        assert!(prompt.starts_with("ctx") && prompt.ends_with("From me: keep it short"));
        assert_eq!(shown.as_deref(), Some("keep it short"));
        // The plan: shown, nothing runs until Enter.
        let fx = answer(&mut s, &fx, &plan(CHECKS));
        assert!(fx.is_empty() && s.can_approve(), "{fx:?}");
        assert!(
            s.chat
                .entries
                .iter()
                .any(|(k, t)| *k == Kind::Plan && t == "0")
        );
        assert!(!s.chat.entries.iter().any(|(_, t)| t.contains("```")));
        let fx = key(&mut s, KeyCode::Enter);
        assert_eq!(
            fx,
            [Fx::Command {
                cmd: "true".into(),
                sudo: false
            }]
        );
        s.step_started(2, 9);
        assert_eq!(
            s.step_ended(0),
            [Fx::Command {
                cmd: "echo hi".into(),
                sudo: false
            }]
        );
        s.step_line("hi".into());
        // The last step: the results go to Claude by themselves.
        let fx = s.step_ended(0);
        let Fx::Turn {
            prompt,
            shown: None,
        } = &fx[0]
        else {
            panic!("{fx:?}")
        };
        assert!(prompt.contains("carried out all 2 steps") && prompt.contains("sentry-verdict"));
        assert_eq!(s.phase, Phase::Thinking(Turn::Verify));
        // Verified: logged, and the task is done.
        let fx = answer(
            &mut s,
            &fx,
            "All good.\n```sentry-verdict\nstatus = \"done\"\nsummary = \"fixed\"\nnext = \"reboot later\"\n```",
        );
        assert_eq!(s.phase, Phase::Settled(End::Done));
        assert!(
            matches!(&fx[..], [Fx::Log { ok: true, tags, .. }] if tags == &["apply:task:sheet", "task:sheet"]),
            "{fx:?}"
        );
        assert!(
            s.chat
                .entries
                .iter()
                .any(|(k, t)| *k == Kind::Good && t == "✓ Done · fixed")
        );
        assert!(
            s.chat
                .entries
                .iter()
                .any(|(_, t)| t == "next: reboot later")
        );
        assert_eq!(key(&mut s, KeyCode::Esc), [Fx::Close]);
    }

    #[test]
    fn problems_and_failures_go_back_to_claude_by_themselves() {
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        // A workflow sentry doesn't know: sent back at once, no key.
        let bad = plan("[[step]]\ntitle = \"w\"\nworkflow = \"nope\"\n");
        let fx = answer(&mut s, &fx, &bad);
        let Fx::Turn {
            prompt,
            shown: None,
        } = &fx[0]
        else {
            panic!("{fx:?}")
        };
        assert!(prompt.contains("step 1 (w): no workflow nope"), "{prompt}");
        assert_eq!(s.phase, Phase::Thinking(Turn::Fix));
        // Twice more: the rounds run out, and it waits for the user, the problem in red.
        let fx = answer(&mut s, &fx, &bad);
        assert!(matches!(fx[0], Fx::Turn { .. }));
        let fx = answer(&mut s, &fx, &bad);
        assert!(fx.is_empty() && s.phase == Phase::Review && !s.can_approve());
        assert_eq!(s.problems.len(), 1);
        assert_eq!(s.replaced.len(), 2);
        // The user asks; a good plan; a failing check goes back by itself.
        type_in(&mut s, "use quick-update");
        let fx = key(&mut s, KeyCode::Enter);
        let fx = answer(&mut s, &fx, &plan(CHECKS));
        assert!(fx.is_empty() && s.can_approve());
        key(&mut s, KeyCode::Enter);
        s.step_line("boom".into());
        let fx = s.step_ended(1);
        let Fx::Turn { prompt, .. } = &fx[0] else {
            panic!("{fx:?}")
        };
        assert!(
            prompt.contains("stopped at step 1 (one), which failed") && prompt.contains("boom")
        );
        assert!(
            s.chat
                .entries
                .iter()
                .any(|(_, t)| t.starts_with("✗ step 1 (one) failed"))
        );
    }

    #[test]
    fn sudo_is_asked_inline_once() {
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(
            &mut s,
            &fx,
            &plan("[[step]]\ntitle = \"r\"\nrun = \"sudo systemctl daemon-reload\"\n"),
        );
        assert_eq!(s.sudo_steps(), [1]);
        assert_eq!(key(&mut s, KeyCode::Enter), [Fx::CheckSudo]);
        assert!(s.sudo_checked(true).is_empty());
        type_in(&mut s, "pw");
        assert_eq!(format!("{:?}", s.secret), "Secret(2 chars)");
        assert_eq!(key(&mut s, KeyCode::Enter), [Fx::CheckPassword]);
        // Wrong: asked again, the typed one gone.
        assert!(s.password_checked(false).is_empty());
        assert!(s.secret.is_empty() && matches!(s.phase, Phase::Password { tries: 1, .. }));
        type_in(&mut s, "ok");
        key(&mut s, KeyCode::Enter);
        assert_eq!(
            s.password_checked(true),
            [Fx::Command {
                cmd: "sudo systemctl daemon-reload".into(),
                sudo: true
            }]
        );
        assert!(s.secret_ok);
        // C-c on the step: stopped, logged, nothing sent; the password gone.
        s.step_started(3, 33);
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(s.key(k), [Fx::Kill(33)]);
        let fx = s.step_ended(-1);
        assert_eq!(s.phase, Phase::Settled(End::Stopped));
        assert!(matches!(&fx[..], [Fx::Log { ok: false, .. }]), "{fx:?}");
        assert!(s.secret.is_empty() && !s.secret_ok);
    }

    #[test]
    fn a_check_for_later_becomes_a_task() {
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(&mut s, &fx, &plan(CHECKS));
        key(&mut s, KeyCode::Enter);
        s.step_ended(0);
        let fx = s.step_ended(0);
        let fx = answer(
            &mut s,
            &fx,
            "```sentry-verdict\nstatus = \"done\"\nsummary = \"off\"\n[follow_up]\n\
             title = \"Confirm GNOME Software starts no upgrade\"\n\
             steps = \"journalctl -u rpm-ostreed -g 'Initiated txn Upgrade'\"\nafter = \"quick-update\"\n```",
        );
        let Some(Fx::AddTask(t)) = fx.iter().find(|f| matches!(f, Fx::AddTask(_))) else {
            panic!("{fx:?}")
        };
        assert!(
            t.id.starts_with("check-confirm-gnome-software-starts-no-upgrade-"),
            "{}",
            t.id
        );
        assert_eq!(t.after.as_deref(), Some("quick-update"));
        assert_eq!(t.act, "by-hand");
        assert!(t.why.contains("the cheatsheet"));
        assert!(s.chat.entries.iter().any(|(_, x)| x
            == "follow-up on Maintenance: Confirm GNOME Software starts no upgrade (once, after the next quick-update run)"));
        // An `after` sentry doesn't know: due now, the condition in its steps.
        let t = s.follow_up_task(
            &verdict::FollowUp {
                title: "x".into(),
                steps: "look".into(),
                after: Some("next boot".into()),
            },
            &[],
        );
        assert!(t.after.is_none() && t.steps.starts_with("Once next boot:"));
    }

    #[test]
    fn a_chat_hands_over_and_a_finding_is_audited_again() {
        let f = crate::finding::Finding {
            id: "listener:svc:passim".into(),
            message: "passim".into(),
            ..Default::default()
        };
        let mut c = Chat::new(Ask::new("passim", "ctx", "What is it?"));
        c.begin_turn("What is it?", 1, 7);
        c.on_event(Event::Init {
            session_id: "sess-1".into(),
        });
        c.on_event(Event::Text("A firmware cache.".into()));
        c.on_exit(0);
        // `a` in the chat: the conversation goes on, as a session.
        let mut s = Session::from_chat(c, Ask::for_finding(&f, &[]));
        assert_eq!(s.chat.session.as_deref(), Some("sess-1"));
        assert!(s.chat.entries.iter().any(|(_, t)| t == "A firmware cache."));
        assert_eq!(s.enter_word(), Some("start"));
        let fx = key(&mut s, KeyCode::Enter);
        answer(&mut s, &fx, &plan(CHECKS));
        key(&mut s, KeyCode::Enter);
        s.step_ended(0);
        // The last step: the audit first, then Claude, told what it found.
        assert_eq!(s.step_ended(0), [Fx::Reaudit]);
        assert!(s.busy());
        let fx = s.reaudited(true);
        let Fx::Turn { prompt, .. } = &fx[0] else {
            panic!("{fx:?}")
        };
        assert!(prompt.contains("After it, sentry's audit no longer reports the finding."));
        let fx = answer(
            &mut s,
            &fx,
            "```sentry-verdict\nstatus = \"failed\"\nsummary = \"still open\"\n```",
        );
        assert!(
            matches!(&fx[0], Fx::Log { tags, .. } if tags.contains(&"finding:listener:svc:passim".to_string()))
        );
        // Not done: Enter audits again; gone, it's done.
        assert_eq!(s.enter_word(), Some("audit again"));
        assert_eq!(key(&mut s, KeyCode::Enter), [Fx::Reaudit]);
        s.reaudited(true);
        assert_eq!(s.phase, Phase::Settled(End::Done));
        assert_eq!(s.enter_word(), Some("close"));
    }

    #[test]
    fn enter_does_the_next_thing() {
        // A task Claude couldn't verify: Enter marks it done.
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(&mut s, &fx, "Nothing to plan, it's fine.");
        assert_eq!(s.enter_word(), Some("ask for a plan"));
        let fx = key(&mut s, KeyCode::Enter);
        assert!(matches!(&fx[0], Fx::Turn { prompt, .. } if prompt.contains("sentry-apply")));
        answer(&mut s, &fx, &plan(CHECKS));
        key(&mut s, KeyCode::Enter);
        s.step_ended(0);
        let fx = s.step_ended(0);
        // No verdict: asked again, as a verify turn; twice, then it's the user's.
        let fx = answer(&mut s, &fx, "no verdict");
        assert_eq!(s.phase, Phase::Thinking(Turn::Verify));
        let fx = answer(&mut s, &fx, "still none");
        answer(&mut s, &fx, "none again");
        assert_eq!(s.phase, Phase::Settled(End::Unverified));
        assert_eq!(s.enter_word(), Some("mark it done"));
        assert_eq!(key(&mut s, KeyCode::Enter), [Fx::MarkDone]);
        // A failed step fixed: Enter retries it.
        let mut s = Session::new(Ask::apply(
            "flag",
            "ctx",
            Apply {
                key: "step:wf:flag".into(),
                step: Some(crate::claude::StepRef {
                    workflow: "wf".into(),
                    idx: 0,
                    id: "flag".into(),
                }),
                ..Default::default()
            },
        ));
        s.phase = Phase::Settled(End::Done);
        assert_eq!(s.enter_word(), Some("retry the step"));
        assert_eq!(key(&mut s, KeyCode::Enter), [Fx::RetryStep, Fx::Close]);
    }

    #[test]
    fn a_workflow_step_waits_for_its_run() {
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(
            &mut s,
            &fx,
            &plan("[[step]]\ntitle = \"u\"\nworkflow = \"quick-update\"\n"),
        );
        assert_eq!(
            key(&mut s, KeyCode::Enter),
            [Fx::StartWorkflow("quick-update".into())]
        );
        assert_eq!(s.waiting_workflow(), Some("quick-update"));
        assert_eq!(key(&mut s, KeyCode::Enter), [Fx::OpenRun]);
        assert!(s.workflow_ended("other", true, String::new()).is_empty());
        let fx = s.workflow_ended("quick-update", true, "done".into());
        assert!(matches!(&fx[0], Fx::Turn { shown: None, .. }));
    }

    #[test]
    fn more_to_do_comes_with_a_plan() {
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(&mut s, &fx, &plan(CHECKS));
        key(&mut s, KeyCode::Enter);
        s.step_ended(0);
        let fx = s.step_ended(0);
        let more = format!(
            "One more thing.\n```sentry-verdict\nstatus = \"more\"\nsummary = \"half\"\n```\n{}",
            plan("[[step]]\ntitle = \"three\"\ncheck = \"true\"\n")
        );
        let fx = answer(&mut s, &fx, &more);
        // The first run is logged; the new plan waits for Enter.
        assert!(matches!(&fx[..], [Fx::Log { ok: true, .. }]), "{fx:?}");
        assert!(s.can_approve() && s.runs.len() == 2);
        assert_eq!(s.replaced, [(0, "done".to_string())]);
    }
}

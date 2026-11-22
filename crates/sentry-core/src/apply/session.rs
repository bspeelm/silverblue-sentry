//! One apply session, start to finish, as a state machine both programs drive. The user makes
//! the decisions (start it, approve the plan, allow what Claude asks to do); everything between
//! follows by itself:
//!
//! ```text
//! Brief ─Enter→ Thinking(Investigate) → Review ─Enter→ [SudoCheck → Password] → Applying
//!                  ↑   ↑ problems / a failed step: Thinking(Fix), at most FIX_ROUNDS │
//!                  │   └──────────────────────────────────────────────────────────────┤
//!                  │                              all steps done → Thinking(Verify) ←┘
//!                  └── typed text (Review, Settled)        verdict → Settled / Review (more)
//! ```
//!
//! Claude asking to run a changing or root command (refused, then allowed with Enter) is the
//! same road with a plan of its own: sentry runs it (`asked`), the password asked if sudo needs
//! one, and the output goes back to Claude, who carries on.
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
    /// Claude advises waiting: nothing changed, and the row is put off.
    Waited,
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
    /// A plan's `ask` step: the value, typed inline (hidden when it's a secret).
    Value,
    Settled(End),
}

/// A target the window has, as a session needs to know it: where a step may run, and the
/// rules that target keeps whoever's session the step belongs to.
#[derive(Debug, Clone, Default)]
pub struct Peer {
    /// `""` this machine, `srv:<name>`, `net:<name>`.
    pub id: String,
    /// What it's called on screen.
    pub title: String,
    /// It's reached over ssh: root's files there are changed by a run step, not an edit.
    pub remote: bool,
    /// What it never runs from a session.
    pub refuses: crate::claude::Refuses,
    /// Its login is root: auto answers nothing that touches it.
    pub asks_each: bool,
    /// What it prints is scrubbed before Claude sees it: a value captured there is kept
    /// hidden, whatever the step says.
    pub hides: bool,
    /// How Claude's commands name it (its gateway's words): a call to one is a read there.
    pub calls: Vec<String>,
    /// The secret values a command line for it sets in plain (a router's `uci set` of an
    /// option that is a secret), each with the tag that stands for it wherever the line
    /// is shown or written down.
    pub masks: Masks,
}

/// A host's own rule for which values in a command line are secrets: (value, tag).
#[derive(Clone, Default)]
pub struct Masks(pub Option<MaskRule>);

/// (value, tag) for each secret a command line sets in plain.
pub type MaskRule = std::sync::Arc<dyn Fn(&str) -> Vec<(String, String)> + Send + Sync>;

impl std::fmt::Debug for Masks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "Masks(rule)"
        } else {
            "Masks(none)"
        })
    }
}

impl Peer {
    /// Its id as Claude writes it (`local` for this machine).
    pub fn name(&self) -> &str {
        if self.id.is_empty() {
            "local"
        } else {
            &self.id
        }
    }
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
    /// Start a workflow with these values (the rest are asked when it starts).
    StartWorkflow(String, std::collections::BTreeMap<String, String>),
    /// The workflow needs the user (a confirm, a manual step): show its run. Its name and
    /// the step's values: when it has no run (its values were dismissed, it was refused),
    /// the app starts it again rather than show nothing.
    OpenRun(String, std::collections::BTreeMap<String, String>),
    /// For another target the window has (its id): a step's command, sudo's checks, a
    /// workflow, that target's own log entry. The app routes it to that target's slot,
    /// which carries it out as its own and reports back here.
    On(String, Box<Fx>),
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
    /// The written plan this session carried out is done (it moves to plans/done/).
    PlanDone(String),
    /// The plan Claude just sent is ready to approve: its document (the assessment, then
    /// the plan's block) is kept under `key` in plans/, so it is there to read and can seed
    /// a session another day.
    PlanSave {
        key: String,
        body: String,
    },
    /// Claude advises waiting: put the row (`key`) off, `again` from now if it said when,
    /// and keep what it wrote (`body`) as the plan's document when the session has one.
    Wait {
        key: String,
        why: String,
        again: Option<String>,
        body: String,
    },
    /// Mark the task (or the plan done by hand) done, by hand: Claude didn't say it is.
    MarkDone,
    /// A check for later, as a one-time task on Maintenance (due after its `after`).
    AddTask(Box<crate::maint::tasks::Task>),
    /// A task done with nothing else logged: logged as such (tagged `task:<id>`). Usually
    /// the apply entry carries the tag instead.
    TaskDone(String),
    Hide,
    Close,
    /// In a series: this one is over (done, or the user goes on); close it and open the next.
    Next,
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
    /// How long each step that ran a command took: (plan, step) → time.
    pub took: std::collections::HashMap<(usize, usize), std::time::Duration>,
    pub output: Vec<String>,
    root: Option<RootWrite>,
    /// C-c on a step: it ends as stopped, nothing sent.
    stopping: bool,
    /// The sudo password as it's typed here; once sudo accepts it the program takes it
    /// (`take_typed`) and holds it for its target, and `secret_ok` says it does.
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
    /// The current run is what Claude asked for and the user allowed: its result goes back
    /// to Claude to carry on (not to verify). What else was allowed with it, in words.
    asked: Option<String>,
    /// The running step was stopped for taking longer than a request may (`ASKED_LIMIT`).
    timed_out: bool,
    /// Its place in a series of ticked rows (2, 5): it starts by itself, and hands on when
    /// it's done.
    pub series: Option<(usize, usize)>,
    /// It opened on a plan saved earlier (its document): Claude hasn't seen the brief yet,
    /// so the first turn carries it.
    seed: Option<String>,
    /// Auto mode is on for the target (the program says so): `auto_go` answers what
    /// `auto::answers` lets it.
    pub auto: bool,
    /// What auto answered since the last log entry, in words (they go in the next one).
    auto_log: Vec<String>,
    /// Answers auto gave in a row, with no key from the user between.
    auto_run: u8,
    /// The target it started on, and the others the window has (none: it is alone, and a
    /// step's `on` has nowhere to point).
    pub home: Option<Peer>,
    pub peers: Vec<Peer>,
    /// What steps captured and the user was asked, for this session's life only:
    /// name → (value, secret). A secret is never shown, written or sent: `clean` takes it
    /// out of everything said.
    values: std::collections::BTreeMap<String, (String, bool)>,
    /// Secret values a plan's own lines set in plain, by their host's rule: (value, tag).
    literals: Vec<(String, String)>,
    /// The running step captures: the name, whether it's hidden, what stdout said.
    cap: Option<(String, bool, Vec<String>)>,
    /// The other targets whose sudo is known to go (its password held, or none asked).
    away_ok: std::collections::BTreeSet<String>,
    /// Whose sudo is being checked or typed for (None: the home target's).
    pub sudo_for: Option<String>,
    /// What ties this session's log entries together when it ran steps on several targets.
    pub run_id: String,
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
            took: Default::default(),
            output: Vec::new(),
            root: None,
            stopping: false,
            secret: Secret::default(),
            secret_ok: false,
            sudo_free: false,
            logged: 0,
            brief_open: false,
            audit_for: None,
            asked: None,
            timed_out: false,
            series: None,
            seed: None,
            auto: false,
            auto_log: Vec::new(),
            auto_run: 0,
            home: None,
            peers: Vec::new(),
            values: Default::default(),
            literals: Vec::new(),
            cap: None,
            away_ok: Default::default(),
            sudo_for: None,
            run_id: format!(
                "{:08x}",
                jiff::Timestamp::now().as_millisecond() as u64 & 0xffff_ffff
            ),
        }
        .acting()
    }

    /// Opened on a plan saved earlier (`saved`: its document, the plan's block in it):
    /// nothing is sent, the plan is there to approve. None: the document has no plan sentry
    /// can run (one written before plans were a session's).
    pub fn seeded(ask: Ask, saved: &str, workflows: &[plan::WfInfo]) -> Option<Self> {
        let (body, p) = plan::take(saved);
        let p = p?.ok()?;
        let mut s = Self::new(ask);
        s.chat.push(
            Kind::Info,
            "the plan saved earlier · Enter applies it, or type what to change",
        );
        s.chat.push(Kind::Claude, body.clone());
        s.problems = plan::problems(&p, workflows);
        s.runs.push(Run::new(p));
        s.chat.push(Kind::Plan, "0");
        s.phase = Phase::Review;
        s.seed = Some(body);
        Some(s)
    }

    /// A session carries out what's allowed: here, or on its server.
    fn acting(mut self) -> Self {
        let a = self.chat.ask.applying();
        self.chat.acts = a.is_some();
        if a.is_some_and(|a| !a.remote) {
            self.chat.privacy = crate::claude::acting_summary();
        }
        self
    }

    /// The session is about a server (its commands run there; files here aren't its to edit).
    fn remote(&self) -> bool {
        self.chat.ask.applying().is_some_and(|a| a.remote)
    }

    /// The window's targets: where this session started, and the others its steps may be
    /// `on`. A plan it already holds (a saved one) is read against them.
    pub fn in_system(&mut self, home: Peer, peers: Vec<Peer>) {
        self.home = Some(home);
        self.peers = peers;
        if let Some(mut r) = self.runs.pop() {
            let unknown = self.place(&mut r.plan);
            self.problems.extend(unknown);
            self.runs.push(r);
        }
    }

    /// Each step's `on` as the session means it: none for the home target, a peer's id
    /// otherwise. Returns the steps that name a target the window doesn't have.
    fn place(&self, p: &mut Plan) -> Vec<(usize, String)> {
        let mut bad = Vec::new();
        let home = self.home.as_ref().map(|h| h.id.as_str());
        for (i, st) in p.steps.iter_mut().enumerate() {
            let Some(on) = st.on.as_deref() else { continue };
            let on = if on == "local" { "" } else { on };
            if Some(on) == home {
                st.on = None;
            } else if self.peers.iter().any(|x| x.id == on) {
                st.on = Some(on.to_string());
            } else {
                let mut ids: Vec<&str> = self.home.iter().map(Peer::name).collect();
                ids.extend(self.peers.iter().map(Peer::name));
                bad.push((
                    i,
                    if ids.is_empty() {
                        format!("on = \"{on}\": this window has no other target; leave `on` out")
                    } else {
                        format!(
                            "on = \"{on}\" names no target sentry has; the targets are: {}",
                            ids.join(", ")
                        )
                    },
                ));
            }
        }
        bad
    }

    /// The other target a step runs on (None: the home target).
    fn peer_of(&self, st: &plan::Step) -> Option<&Peer> {
        let on = st.on.as_deref()?;
        self.peers.iter().find(|p| p.id == on)
    }

    /// The step runs on a host over ssh.
    fn step_remote(&self, st: &plan::Step) -> bool {
        match (st.on.as_deref(), self.peer_of(st)) {
            (Some(_), Some(p)) => p.remote,
            _ => self.remote(),
        }
    }

    fn step_needs_sudo(&self, st: &plan::Step) -> bool {
        match &st.kind {
            StepKind::Edit { .. } => !self.step_remote(st) && needs_sudo(st),
            _ => needs_sudo(st),
        }
    }

    /// More than one target has a step in a plan of this session (the window then says
    /// which step is whose).
    pub fn several(&self) -> bool {
        self.runs
            .iter()
            .any(|r| r.plan.steps.iter().any(|s| s.on.is_some()))
    }

    /// What a step's row says of where it runs, when the plans touch several targets.
    pub fn step_place(&self, st: &plan::Step) -> Option<String> {
        if !self.several() {
            return None;
        }
        Some(match self.peer_of(st) {
            Some(p) => p.title.clone(),
            None => self
                .home
                .as_ref()
                .map_or_else(|| "here".to_string(), |h| h.title.clone()),
        })
    }

    /// Every target this session has to do with: its own, the ones its plans' steps and
    /// its requests are on, and any it read through that target's gateway.
    pub fn touched(&self) -> Vec<&Peer> {
        let mut out: Vec<&Peer> = self.home.iter().collect();
        for p in &self.peers {
            let stepped = self
                .runs
                .last()
                .is_some_and(|r| r.plan.steps.iter().any(|s| s.on.as_deref() == Some(&p.id)));
            let asked = self
                .chat
                .requests
                .iter()
                .any(|g| self.grant_peer(g).is_some_and(|x| x.id == p.id));
            let read = self.chat.entries.iter().any(|(k, t)| {
                matches!(k, Kind::Tool | Kind::ToolErr) && p.calls.iter().any(|c| t.contains(c))
            });
            if stepped || asked || read {
                out.push(p);
            }
        }
        out
    }

    /// The other target a request is for: the one whose gateway refused it, or this
    /// machine for a command Claude Code refused (None: the home target, or none the
    /// window has).
    fn grant_peer(&self, g: &crate::claude::Grant) -> Option<&Peer> {
        let id = g.on.as_deref().unwrap_or("");
        self.peers.iter().find(|p| p.id == id)
    }

    /// The request is for the home target.
    fn grant_home(&self, g: &crate::claude::Grant) -> bool {
        match (&self.home, g.on.as_deref()) {
            (Some(h), on) => h.id == on.unwrap_or(""),
            (None, on) => on.is_some() == self.remote(),
        }
    }

    /// `text` with every secret value this session holds taken out: its name stands there.
    pub fn clean(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (name, (v, secret)) in &self.values {
            if *secret && out.contains(v.as_str()) {
                out = out.replace(v.as_str(), &format!("‹{name}›"));
            }
        }
        for (v, tag) in &self.literals {
            if out.contains(v.as_str()) {
                out = out.replace(v.as_str(), tag);
            }
        }
        out
    }

    /// The step's host, as the session knows it (None: the home target, unknown).
    fn host_of(&self, st: &plan::Step) -> Option<&Peer> {
        match st.on {
            Some(_) => self.peer_of(st),
            None => self.home.as_ref(),
        }
    }

    /// The secret values held (for the app's sweep of everything it writes down).
    pub fn secrets(&self) -> Vec<(String, String)> {
        self.values
            .iter()
            .filter(|(_, (_, s))| *s)
            .map(|(n, (v, _))| (format!("‹{n}›"), v.clone()))
            .chain(self.literals.iter().map(|(v, t)| (t.clone(), v.clone())))
            .collect()
    }

    fn keep_value(&mut self, name: &str, v: &str, secret: bool) -> Result<String, String> {
        if let Some(why) = plan::value_problem(v) {
            return Err(format!("{{{{{name}}}}} can't be kept: {why}"));
        }
        if secret && v.chars().count() < 4 {
            return Err(format!(
                "{{{{{name}}}}} can't be kept hidden: under four characters it would be found in everything"
            ));
        }
        self.values
            .insert(name.to_string(), (v.to_string(), secret));
        Ok(if secret {
            format!("kept as {{{{{name}}}}} (hidden)")
        } else {
            format!("kept as {{{{{name}}}}} = {v}")
        })
    }

    /// `name` is (or, by this plan, will be) a hidden value.
    fn secret_name(&self, name: &str, p: &Plan) -> bool {
        self.values.get(name).is_some_and(|(_, s)| *s)
            || p.steps.iter().any(|st| {
                st.gives() == Some(name) && (st.secret || self.host_of(st).is_some_and(|h| h.hides))
            })
    }

    fn filled(&self, text: &str) -> Result<String, String> {
        plan::fill(text, &|n| self.values.get(n).map(|(v, _)| v.clone()))
    }

    /// The `ask` step the plan is at: its name, its prompt, whether what's typed is hidden.
    pub fn asking(&self) -> Option<(&str, &str, bool)> {
        if self.phase != Phase::Value {
            return None;
        }
        let r = self.run()?;
        let st = r.plan.steps.get(r.current())?;
        match &st.kind {
            StepKind::Ask { name, prompt } => Some((name, prompt, st.secret)),
            _ => None,
        }
    }

    /// What is being typed for an `ask` step that isn't a secret (a secret shows as dots).
    pub fn value_typed(&self) -> String {
        String::from_utf8_lossy(&self.secret.stdin())
            .trim_end_matches('\n')
            .to_string()
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
        s.acting()
    }

    /// What Enter does now on an empty input, in a word or two (None: nothing).
    pub fn enter_word(&self) -> Option<&'static str> {
        let a = self.chat.ask.applying();
        match self.phase {
            Phase::Brief => Some("start"),
            Phase::Review if self.can_approve() => Some("apply the plan"),
            Phase::Review | Phase::Settled(_) if self.can_grant() => Some("allow it"),
            Phase::Review if self.run().is_none() || self.run().is_some_and(|r| r.finished()) => {
                Some("ask for a plan")
            }
            Phase::Applying if self.waiting_workflow().is_some() => Some("open the workflow"),
            // In a series the next row follows; this one stays ticked if it isn't done.
            Phase::Settled(_) if self.series.is_some() => Some("go on with the next"),
            Phase::Settled(End::Waited) => Some("close"),
            Phase::Settled(End::Done) if a.is_some_and(|a| a.step.is_some()) => {
                Some("retry the step")
            }
            Phase::Settled(End::Done) => Some("close"),
            Phase::Settled(_)
                if a.is_some_and(|a| a.finding.is_some() && (!a.remote || a.reaudits)) =>
            {
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
        self.waiting_step().map(|(name, _)| name)
    }

    /// The workflow the plan waits for, with the step's values for it.
    fn waiting_step(&self) -> Option<(&str, &std::collections::BTreeMap<String, String>)> {
        let r = self.run()?;
        match r.state {
            RunState::WaitingWorkflow(i) => match &r.plan.steps[i].kind {
                StepKind::Workflow { name, vars } => Some((name, vars)),
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
            .filter(|(_, s)| s.on == self.sudo_for && self.step_needs_sudo(s))
            .map(|(i, _)| i + 1)
            .collect()
    }

    /// A step on another target needs sudo there.
    pub fn sudo_away(&self) -> bool {
        self.run().is_some_and(|r| {
            r.plan
                .steps
                .iter()
                .any(|s| s.on.is_some() && self.step_needs_sudo(s))
        })
    }

    /// Whose sudo password is being asked for, when it isn't the home target's.
    pub fn sudo_title(&self) -> Option<&str> {
        let id = self.sudo_for.as_deref()?;
        self.peers
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.title.as_str())
    }

    fn turn(&mut self, why: Turn, prompt: String, shown: Option<String>) -> Vec<Fx> {
        // Opened on a saved plan: Claude hears what it's about with the first thing sent.
        let prompt = match self.seed.take() {
            Some(doc) => format!(
                "{}\n\nThe plan for it, written earlier, which I approved as it is:\n{doc}\n\n{prompt}",
                self.chat.ask.context.trim_end()
            ),
            None => prompt,
        };
        self.phase = Phase::Thinking(why);
        self.turn_from = self.chat.entries.len();
        // Whatever the words, a secret this session holds isn't among them.
        let prompt = self.clean(&prompt);
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
                self.sudo_for = None;
                self.phase = Phase::Review;
                Vec::new()
            }
            // The value isn't given: nothing further runs, and the session waits.
            Phase::Value => {
                self.secret.clear();
                let what = self
                    .asking()
                    .map(|(n, p, _)| format!("{p} ({{{{{n}}}}})"))
                    .unwrap_or_default();
                if let Some(r) = self.run_mut() {
                    r.step_done(false, "not given".into());
                }
                self.chat.push(
                    Kind::Info,
                    format!("waiting: {what} wasn't given · nothing further ran"),
                );
                self.phase = Phase::Settled(End::Waited);
                self.log_runs(Some(&format!("Waiting for a value only I have: {what}")))
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
                    return vec![self.at(self.sudo_for.clone(), Fx::CheckPassword)];
                }
                _ => {}
            }
            return Vec::new();
        }
        if self.phase == Phase::Value {
            match code {
                KeyCode::Char(c) if !ctrl => self.secret.push(c),
                KeyCode::Backspace => self.secret.pop(),
                KeyCode::Enter if !self.secret.is_empty() => return self.value_given(),
                _ => {}
            }
            return Vec::new();
        }
        if self.phase == Phase::Applying {
            if code == KeyCode::Enter
                && let Some((name, vars)) = self.waiting_step()
            {
                // On another target the run is that target's to show: its strip entry
                // says it needs you.
                if self.waiting_on().is_some() {
                    return Vec::new();
                }
                let vars = vars
                    .iter()
                    .map(|(k, v)| (k.clone(), self.filled(v).unwrap_or_else(|_| v.clone())))
                    .collect();
                return vec![Fx::OpenRun(name.to_string(), vars)];
            }
            return Vec::new();
        }
        if !matches!(self.phase, Phase::Brief | Phase::Review | Phase::Settled(_)) {
            return Vec::new();
        }
        match code {
            KeyCode::Char('g') if self.can_grant() => return self.grant(),
            KeyCode::Char(c) if !ctrl => self.chat.input.push(c),
            KeyCode::Backspace => {
                self.chat.input.pop();
            }
            KeyCode::Enter => return self.enter(),
            _ => {}
        }
        Vec::new()
    }

    /// Pasted text: all of it into what's being typed (never as keys).
    pub fn paste(&mut self, text: &str) {
        match self.phase {
            Phase::Password {
                checking: false, ..
            } => text
                .trim_end_matches(['\r', '\n'])
                .chars()
                .for_each(|c| self.secret.push(c)),
            Phase::Value => text
                .trim_end_matches(['\r', '\n'])
                .chars()
                .for_each(|c| self.secret.push(c)),
            Phase::Brief | Phase::Review | Phase::Settled(_) => self.chat.paste(text),
            _ => {}
        }
    }

    /// An effect for the target `on` (None: the home target's own).
    fn at(&self, on: Option<String>, fx: Fx) -> Fx {
        match on {
            Some(id) => Fx::On(id, Box::new(fx)),
            None => fx,
        }
    }

    /// Enter on an `ask` step's value: kept, and the plan goes on by itself.
    fn value_given(&mut self) -> Vec<Fx> {
        let Some((name, _, secret)) = self
            .asking()
            .map(|(n, p, s)| (n.to_string(), p.to_string(), s))
        else {
            return Vec::new();
        };
        let v = self.value_typed();
        self.secret.clear();
        match self.keep_value(&name, &v, secret) {
            Ok(note) => {
                self.phase = Phase::Applying;
                let Some(r) = self.run_mut() else {
                    return Vec::new();
                };
                let a = r.step_done(true, format!("given · {note}"));
                self.drive(a)
            }
            Err(why) => {
                self.chat.push(Kind::Err, format!("{why} · type it again"));
                Vec::new()
            }
        }
    }

    /// Claude asked for something the user can allow, and nothing's typed. (On a server
    /// changes go in the plan: there, files aren't asked for here either.)
    pub fn can_grant(&self) -> bool {
        self.chat.can_allow()
            && matches!(self.phase, Phase::Review | Phase::Settled(_))
            && self.chat.requests.iter().any(|g| self.grants_here(g))
    }

    fn grants_here(&self, g: &crate::claude::Grant) -> bool {
        self.chat.allowed(g).is_ok()
            && ((self.chat.acts && !self.remote()) || g.access != crate::claude::Access::Write)
    }

    /// What Claude asked for is allowed. Reads, read-only commands and your own files become
    /// grants for the session, and Claude carries on by itself (a file is backed up first).
    /// Commands that change things or need root, sentry runs and sends Claude the result.
    fn grant(&mut self) -> Vec<Fx> {
        use crate::claude::Access;
        let mut not: Vec<String> = Vec::new();
        let mut run: Vec<(String, Option<String>)> = Vec::new();
        let mut rest = Vec::new();
        for g in std::mem::take(&mut self.chat.requests) {
            if !self.grants_here(&g) {
                let why = self
                    .chat
                    .allowed(&g)
                    .err()
                    .unwrap_or("not in a server's session");
                not.push(format!("{} {}: {why}", g.word(), g.path));
            } else if let Some(why) = Some(&g)
                .filter(|g| g.access == Access::Run)
                .and_then(|g| self.refused(g))
            {
                not.push(format!("run {}: {why}", g.line()));
            } else if g.access == Access::Run && crate::claude::workflow_only(g.line()) {
                not.push(format!(
                    "run {}: upgrades, rebases, rollbacks and reboots are run by sentry's \
                     workflows (a `workflow` step in your plan), never as a command",
                    g.line()
                ));
            } else if g.access == Access::Run
                && !self.grant_home(&g)
                && let Some(peer) = self.grant_peer(&g).map(|p| p.id.clone())
            {
                // Another target's: its gateway refused the line (or Claude Code did, a
                // command on this machine). What only reads here is a grant; the rest
                // sentry runs there, as that target runs its own.
                if g.on.is_none() && !g.changes() {
                    rest.push(g);
                } else {
                    run.push((g.line().to_string(), Some(peer)));
                }
            } else if g.access == Access::Run && !self.grant_home(&g) {
                // The gateway's refusal is a line for the server; Claude Code's own is a
                // command on this machine. Neither is ever run on the other.
                if g.remote() {
                    not.push(format!("run {}: this isn't a server's session", g.line()));
                } else if g.changes() {
                    not.push(format!(
                        "run {}: that would change this machine, and this session changes \
                         only the server (call the server's through the gateway; my files \
                         here are `edit` steps)",
                        g.line()
                    ));
                } else {
                    // It only reads, here: a grant, and Claude runs it itself.
                    rest.push(g);
                }
            } else if g.access == Access::Run && (g.changes() || self.chat.acts) {
                // In a session whatever was refused is run here: a grant couldn't lift the
                // rule that refused it. All of it, as Claude wrote it.
                run.push((g.line().to_string(), None));
            } else if g.access == Access::Write {
                match crate::claude::backup(&g.path) {
                    Ok(b) => {
                        self.chat.push(
                            Kind::Info,
                            format!("backed up {} → {}", g.path, b.display()),
                        );
                        self.chat.watch(&g.path, b);
                        rest.push(g);
                    }
                    Err(e) => {
                        // No backup, no write.
                        self.chat.push(
                            Kind::Err,
                            format!("couldn't back up {}: {e} (not allowed)", g.path),
                        );
                        not.push(format!("{} {}: no backup could be made", g.word(), g.path));
                    }
                }
            } else {
                rest.push(g);
            }
        }
        self.chat.requests = rest;
        let mut told = self.chat.grant().unwrap_or_default();
        if !not.is_empty() {
            told.push_str(&format!("\nNot allowed: {}.", not.join("; ")));
        }
        let told = told.trim().to_string();
        if run.is_empty() {
            return if told.is_empty() {
                Vec::new()
            } else {
                self.turn(Turn::Investigate, told.clone(), Some(told))
            };
        }
        if let Some(i) = self.runs.len().checked_sub(1) {
            self.replaced.push((i, "replaced".into()));
        }
        self.problems.clear();
        self.runs.push(Run::new(Plan {
            summary: "What Claude asked to run, and you allowed".into(),
            rollback: String::new(),
            steps: run
                .into_iter()
                .map(|(cmd, on)| plan::Step {
                    on,
                    ..plan::Step::new(cmd.chars().take(60).collect::<String>(), StepKind::Run(cmd))
                })
                .collect(),
        }));
        self.chat
            .push(Kind::Plan, (self.runs.len() - 1).to_string());
        self.asked = Some(told);
        self.fixes = 0;
        self.approve()
    }

    /// Why a command Claude asked for is never run, by the rule of the target it is for;
    /// a command on this machine answers to every target's rule about this machine (a
    /// router's files here stay closed whoever's session asks).
    fn refused(&self, g: &crate::claude::Grant) -> Option<String> {
        let own = self.chat.ask.applying().map(|a| a.refuses);
        if g.remote() {
            return match self.grant_peer(g) {
                Some(p) if !self.grant_home(g) => p.refuses.why(g.line(), true),
                _ => own.and_then(|r| r.why(g.line(), true)),
            };
        }
        own.into_iter()
            .chain(self.peers.iter().map(|p| p.refuses))
            .find_map(|r| r.why(g.line(), false))
    }

    fn enter(&mut self) -> Vec<Fx> {
        let text = std::mem::take(&mut self.chat.input);
        let text = text.trim().to_string();
        // The user decided something: sentry may go back to Claude again by itself.
        self.fixes = 0;
        self.auto_run = 0;
        match self.phase {
            Phase::Brief => self.begin(text),
            Phase::Review if text.is_empty() => match self.enter_word() {
                Some("apply the plan") => self.approve(),
                Some("allow it") => self.grant(),
                Some("ask for a plan") => self.turn(
                    Turn::Investigate,
                    "Answer with the plan, as one sentry-apply block.".into(),
                    Some("Send the plan.".into()),
                ),
                _ => Vec::new(),
            },
            Phase::Settled(_) if text.is_empty() => match self.enter_word() {
                Some("allow it") => self.grant(),
                Some("retry the step") => vec![Fx::RetryStep, Fx::Close],
                Some("close") => vec![Fx::Close],
                Some("go on with the next") => {
                    let mut fx = self.log_runs(None);
                    fx.push(Fx::Next);
                    fx
                }
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

    /// Answers auto gives in a row before it waits for a key (a plan that keeps coming back
    /// with "more", a request after every answer): the user looks before it goes on.
    pub const AUTO_LIMIT: u8 = 12;

    /// Auto mode: what Enter would do now is done without it, where auto may answer
    /// (`auto::answers`): the brief is sent, a plan approved, what Claude asks for allowed.
    /// Nothing while the user is typing, and nothing auto never answers: that waits for the
    /// key as with auto off, with a line saying why. Empty: nothing was answered.
    pub fn auto_go(&mut self) -> Vec<Fx> {
        use crate::auto::{Asked, answers};
        if !self.auto || !self.chat.input.is_empty() || self.busy() {
            return Vec::new();
        }
        let waits = |s: &mut Self, why: String| {
            let line = format!("auto leaves this to you: {why}");
            if s.chat.entries.last().is_none_or(|(_, l)| *l != line) {
                s.chat.push(Kind::Info, line);
            }
            Vec::new()
        };
        enum Do {
            Start,
            Approve,
            Allow,
        }
        let what = match self.phase {
            Phase::Brief => Do::Start,
            Phase::Review if self.can_approve() => Do::Approve,
            Phase::Review | Phase::Settled(_) if self.can_grant() => Do::Allow,
            _ => return Vec::new(),
        };
        if self.auto_run >= Self::AUTO_LIMIT {
            return waits(
                self,
                format!("it answered {} times in a row here", Self::AUTO_LIMIT),
            );
        }
        match what {
            Do::Start if !answers(true, &Asked::Start) => Vec::new(),
            Do::Start => {
                self.auto_did("started it");
                self.begin(String::new())
            }
            Do::Approve if self.chat.ask.applying().is_some_and(|a| a.asks_each) => waits(
                self,
                "a plan for a host reached as root is yours to approve · Enter applies the plan"
                    .to_string(),
            ),
            // One rule over every target the session has to do with: each one's own
            // strictness, and the strictest decides.
            Do::Approve if !crate::auto::answers_on(true, &Asked::Start, &self.strictness()) => {
                let who = self.strict_peer();
                waits(
                    self,
                    format!(
                        "this session has to do with {who}, a host reached as root: its plan is yours to approve · Enter applies the plan"
                    ),
                )
            }
            Do::Approve => {
                let steps = self.run().map(|r| r.plan.steps.clone()).unwrap_or_default();
                for (i, st) in steps.iter().enumerate() {
                    if let StepKind::Run(c) | StepKind::Check(c) = &st.kind
                        && !answers(true, &Asked::Plan(&[c.as_str()]))
                    {
                        let why = crate::auto::never(c).unwrap_or("it is yours to decide");
                        return waits(
                            self,
                            format!(
                                "step {} ({}): {why} · Enter applies the plan",
                                i + 1,
                                st.title
                            ),
                        );
                    }
                }
                let summary = self
                    .run()
                    .map(|r| r.plan.summary.clone())
                    .unwrap_or_default();
                self.auto_did(&format!("approved the plan ({summary})"));
                self.approve()
            }
            Do::Allow => {
                let reqs = self.chat.requests.clone();
                for g in &reqs {
                    // On a host reached as root nothing Claude asks for is auto's to
                    // allow: not a command there, and not a file here either (what the
                    // host said is text someone else may have written, a device's name
                    // or a log line, and a file read here is how it would be answered).
                    if self.chat.ask.applying().is_some_and(|a| a.asks_each) {
                        let why = if g.access == crate::claude::Access::Run {
                            "a command run as root on the host is yours to allow"
                        } else {
                            "in a session on a host reached as root, a file here is yours to allow"
                        };
                        return waits(self, format!("{} {}: {why}", g.word(), g.path));
                    }
                    if !crate::auto::answers_on(true, &Asked::Start, &self.strictness()) {
                        let who = self.strict_peer();
                        return waits(
                            self,
                            format!(
                                "{} {}: this session has to do with {who}, a host reached as root, so each request is yours to allow",
                                g.word(),
                                g.path
                            ),
                        );
                    }
                    let ok = self.grants_here(g);
                    if !answers(
                        true,
                        &Asked::Request {
                            grant: g,
                            grantable: ok,
                        },
                    ) {
                        let why = match self.chat.allowed(g) {
                            Err(why) => why,
                            Ok(()) if g.access == crate::claude::Access::Run => {
                                crate::auto::never(g.line()).unwrap_or("it is yours to decide")
                            }
                            Ok(()) => "not in a server's session",
                        };
                        return waits(self, format!("{} {}: {why}", g.word(), g.path));
                    }
                }
                let list: Vec<String> = reqs
                    .iter()
                    .map(|g| format!("{} {}", g.word(), g.path))
                    .collect();
                self.auto_did(&format!("allowed: {}", list.join("; ")));
                // The fix rounds are the user's to renew, not auto's.
                let fixes = self.fixes;
                let fx = self.grant();
                self.fixes = fixes;
                fx
            }
        }
    }

    /// How strict each target this session touches is (`auto::answers_on`).
    fn strictness(&self) -> Vec<crate::auto::Strict> {
        let home = self.chat.ask.applying().is_some_and(|a| a.asks_each);
        let mut v = vec![crate::auto::Strict { asks_each: home }];
        v.extend(self.touched().into_iter().map(|p| crate::auto::Strict {
            asks_each: p.asks_each,
        }));
        v
    }

    fn strict_peer(&self) -> String {
        self.touched()
            .into_iter()
            .find(|p| p.asks_each)
            .map_or_else(|| "a target".to_string(), |p| p.title.clone())
    }

    /// Auto answered something: in the transcript, and kept for the log entry.
    fn auto_did(&mut self, what: &str) {
        self.auto_run += 1;
        self.auto_log.push(what.to_string());
        self.chat.push(Kind::Info, format!("auto: {what}"));
    }

    /// The first turn: the brief, and what the user added to it.
    fn begin(&mut self, text: String) -> Vec<Fx> {
        let mut prompt = self.chat.ask.prompt();
        let shown = if text.is_empty() {
            "Do this for me.".to_string()
        } else {
            prompt.push_str(&format!("\n\nFrom me: {text}"));
            text
        };
        self.turn(Turn::Investigate, prompt, Some(shown))
    }

    /// Start without Enter, as row `pos` of a series (its Enter was the start). Nothing once
    /// it has begun.
    pub fn start_in_series(&mut self, pos: (usize, usize)) -> Vec<Fx> {
        self.series = Some(pos);
        self.chat.push(
            Kind::Info,
            format!("{} of {} in the series · it starts by itself", pos.0, pos.1),
        );
        match self.phase {
            Phase::Brief => self.begin(String::new()),
            _ => Vec::new(),
        }
    }

    /// The password just typed, for the program to check and then hold.
    pub fn take_typed(&mut self) -> sudo::Secret {
        self.secret.take()
    }

    /// The program holds the target's password already: nothing is asked.
    pub fn password_held(&mut self) -> Vec<Fx> {
        self.secret_ok = true;
        if self.phase != Phase::SudoCheck || self.sudo_for.is_some() {
            return Vec::new();
        }
        self.approve()
    }

    /// Another target holds its password already (or its sudo asks for none).
    pub fn password_held_on(&mut self, id: &str) -> Vec<Fx> {
        self.away_ok.insert(id.to_string());
        if self.phase != Phase::SudoCheck || self.sudo_for.as_deref() != Some(id) {
            return Vec::new();
        }
        self.approve()
    }

    /// Another target forgot its password: the next plan with a sudo step there asks.
    pub fn password_gone_on(&mut self, id: &str) {
        self.away_ok.remove(id);
    }

    /// The program forgot the password (the key for it, or sudo refused it): the next step
    /// that needs it asks again.
    pub fn password_gone(&mut self) {
        self.secret_ok = false;
        self.sudo_free = false;
    }

    // ── Applying ────────────────────────────────────────────────────────────────────────

    /// The one approval: sudo is made sure of on each target the plan needs it on (the
    /// home target first, then the others in the plan's order: one password each, asked
    /// here), then the steps run.
    fn approve(&mut self) -> Vec<Fx> {
        let steps = self.run().map(|r| r.plan.steps.clone()).unwrap_or_default();
        let sudo = steps
            .iter()
            .any(|s| s.on.is_none() && self.step_needs_sudo(s));
        if sudo && !self.secret_ok && !self.sudo_free {
            self.phase = Phase::SudoCheck;
            self.sudo_for = None;
            return vec![Fx::CheckSudo];
        }
        for st in &steps {
            if let Some(id) = st.on.clone()
                && self.step_needs_sudo(st)
                && !self.away_ok.contains(&id)
            {
                self.phase = Phase::SudoCheck;
                self.sudo_for = Some(id.clone());
                return vec![Fx::On(id, Box::new(Fx::CheckSudo))];
            }
        }
        self.sudo_for = None;
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
            match self.sudo_for.clone() {
                Some(id) => {
                    self.away_ok.insert(id);
                }
                None => self.sudo_free = true,
            }
            self.approve()
        }
    }

    /// sudo checked the password.
    pub fn password_checked(&mut self, ok: bool) -> Vec<Fx> {
        let Phase::Password { tries, .. } = self.phase else {
            return Vec::new();
        };
        if ok {
            // The program took what was typed before it said so.
            self.secret.clear();
            match self.sudo_for.clone() {
                Some(id) => {
                    self.away_ok.insert(id);
                }
                None => self.secret_ok = true,
            }
            return self.approve();
        }
        self.secret.clear();
        if tries + 1 >= 3 {
            self.sudo_for = None;
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
                    // Root's files on this machine are edited through this machine's sudo.
                    let on = step.on.clone();
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
                                return vec![self.at(on, Fx::Command { cmd, sudo: true })];
                            }
                            Err(e) => a = r.step_done(false, e),
                        },
                        Err(e) => a = r.step_done(false, e),
                    }
                }
                Action::Command { idx, cmd } => {
                    let step = r.plan.steps[idx].clone();
                    self.output.clear();
                    // The values it uses go in now, in memory: the plan keeps the names.
                    let cmd = match self.filled(&cmd) {
                        Ok(c) => c,
                        Err(why) => {
                            let Some(r) = self.runs.last_mut() else {
                                return Vec::new();
                            };
                            a = r.step_done(false, format!("not run: {why}"));
                            continue;
                        }
                    };
                    if let Some(name) = &step.capture {
                        // What a host whose output is scrubbed prints is never shown raw.
                        let hides = match self.peer_of(&step) {
                            Some(p) => p.hides,
                            None => self.home.as_ref().is_some_and(|h| h.hides),
                        };
                        self.cap = Some((name.clone(), step.secret || hides, Vec::new()));
                    }
                    return vec![self.at(
                        step.on.clone(),
                        Fx::Command {
                            sudo: sudo::uses_sudo(&cmd),
                            cmd,
                        },
                    )];
                }
                Action::StartWorkflow(idx, wf, vars) => {
                    let on = r.plan.steps[idx].on.clone();
                    self.output.clear();
                    let mut given = std::collections::BTreeMap::new();
                    let mut bad = None;
                    for (k, v) in vars {
                        match self.filled(&v) {
                            Ok(v) => {
                                given.insert(k, v);
                            }
                            Err(why) => bad = Some(why),
                        }
                    }
                    if let Some(why) = bad {
                        let Some(r) = self.runs.last_mut() else {
                            return Vec::new();
                        };
                        a = r.step_done(false, format!("not started: {why}"));
                        continue;
                    }
                    return vec![self.at(on, Fx::StartWorkflow(wf, given))];
                }
                // The value is typed here, in the session's own line; then it goes on.
                Action::Ask(_) => {
                    self.secret.clear();
                    self.phase = Phase::Value;
                    return Vec::new();
                }
                Action::Finished => return self.finished(),
            }
        }
    }

    /// A command Claude asked for and the user allowed is running: it only looks or does one
    /// small thing, so one that hasn't ended after this long is stopped (as the gateway
    /// stops what it runs), and Claude is told. A plan's own steps have no limit.
    pub const ASKED_LIMIT: std::time::Duration = std::time::Duration::from_secs(120);

    /// The running step is past its limit: stop it (the pid to end), once.
    pub fn overdue(&mut self) -> Option<u32> {
        let (_, pid) = self.job?;
        if self.asked.is_none() || self.timed_out || self.job_started?.elapsed() < Self::ASKED_LIMIT
        {
            return None;
        }
        self.timed_out = true;
        self.step_line(format!(
            "stopped by sentry: no end after {} s",
            Self::ASKED_LIMIT.as_secs()
        ));
        Some(pid)
    }

    /// The running step is a request with a time limit (the window says so).
    pub fn limited(&self) -> bool {
        self.asked.is_some() && self.job.is_some()
    }

    /// The step's command started (`id`, `pid`), printed a line, ended.
    pub fn step_started(&mut self, id: u64, pid: u32) {
        self.job = Some((id, pid));
        self.job_started = Some(std::time::Instant::now());
    }

    /// What the running step said: `shown` as the target lets Claude see it, `raw` as it
    /// came. A capturing step's stdout is kept for its value; a hidden one's isn't shown.
    pub fn step_said(&mut self, shown: String, raw: &str, stderr: bool) {
        if let Some((name, secret, lines)) = self.cap.as_mut()
            && !stderr
        {
            lines.push(raw.to_string());
            if *secret {
                let mark = format!("‹{name}: hidden›");
                if self.output.last() != Some(&mark) {
                    self.output.push(mark);
                }
                return;
            }
        }
        self.step_line(shown);
    }

    pub fn step_line(&mut self, text: String) {
        let text = self.clean(&text);
        self.output.push(text);
        if self.output.len() > 400 {
            self.output.drain(..200);
        }
    }

    pub fn step_ended(&mut self, code: i32) -> Vec<Fx> {
        self.job = None;
        self.timed_out = false;
        if let (Some(at), Some(r)) = (self.job_started.take(), self.run()) {
            self.took
                .insert((self.runs.len() - 1, r.current()), at.elapsed());
        }
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
        let mut ok = code == 0 && !self.stopping;
        if let Some((name, secret, lines)) = self.cap.take()
            && ok
        {
            let v = lines
                .iter()
                .rev()
                .map(|l| l.trim())
                .find(|l| !l.is_empty())
                .unwrap_or("")
                .to_string();
            match self.keep_value(&name, &v, secret) {
                Ok(kept) => note = format!("{} · {kept}", self.clean(&note)),
                Err(why) => {
                    ok = false;
                    note = format!("nothing captured: {why}");
                }
            }
        }
        let Some(r) = self.run_mut() else {
            return Vec::new();
        };
        let a = r.step_done(ok, note);
        self.drive(a)
    }

    /// The step couldn't start on its target because that target is busy with work of
    /// its own, and stayed so: Claude hears it as what happened, not as the step failing
    /// (no fix round is spent on it).
    pub fn step_deferred(&mut self, why: &str) -> Vec<Fx> {
        self.job = None;
        self.job_started = None;
        self.cap = None;
        let Some(r) = self.run_mut() else {
            return Vec::new();
        };
        r.step_done(false, format!("not run: {why}"));
        let report = r.report();
        self.asked = None;
        self.chat.push(
            Kind::Info,
            format!("{why} · sentry told Claude, to plan around it"),
        );
        let prompt = format!(
            "{report}\n\nThat step did not fail: it was never started, because {why}. \
             Nothing is wrong with the command. Say whether to wait and try again (send the \
             rest as a plan), or do it another way."
        );
        self.turn(Turn::Fix, prompt, None)
    }

    /// A workflow run on another target ended (as `workflow_ended`, for a step that is
    /// `on` it).
    pub fn workflow_ended_on(
        &mut self,
        id: &str,
        workflow: &str,
        ok: bool,
        note: String,
    ) -> Vec<Fx> {
        let on = self.run().and_then(|r| match r.state {
            RunState::WaitingWorkflow(i) => r.plan.steps[i].on.clone(),
            _ => None,
        });
        if on.as_deref() != Some(id) {
            return Vec::new();
        }
        self.workflow_ended(workflow, ok, note)
    }

    /// The target the plan's waiting workflow runs on, when it isn't the home target.
    pub fn waiting_on(&self) -> Option<&str> {
        let r = self.run()?;
        match r.state {
            RunState::WaitingWorkflow(i) => r.plan.steps[i].on.as_deref(),
            _ => None,
        }
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
        let Some(report) = self.run().map(Run::report) else {
            return Vec::new();
        };
        if !self.stopping
            && let Some(told) = self.asked.take()
        {
            self.chat
                .push(Kind::Info, "sentry sent Claude what happened, to carry on");
            let prompt = format!("{told}\n\n{}", crate::claude::apply_ran(&report));
            return self.turn(Turn::Investigate, prompt.trim().to_string(), None);
        }
        self.asked = None;
        let Some(r) = self.run() else {
            return Vec::new();
        };
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
                    .is_some_and(|a| a.finding.is_some() && (!a.remote || a.reaudits))
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
    pub fn turn_ended(&mut self, code: i32, workflows: &[plan::WfInfo]) -> Vec<Fx> {
        self.chat.on_exit(code);
        let edits = self.edits();
        let Phase::Thinking(why) = self.phase else {
            return edits;
        };
        let mut fx = edits;
        fx.extend(self.answer(why, workflows));
        fx
    }

    /// Files Claude changed this turn (allowed, backed up): in the transcript and the log.
    fn edits(&mut self) -> Vec<Fx> {
        let tag = self.chat.ask.applying().map(|a| format!("apply:{}", a.key));
        self.chat
            .changed()
            .into_iter()
            .map(|(path, backup, before, after)| {
                let line = format!(
                    "Claude changed {path} ({before} → {after} lines) · backup {}",
                    backup.display()
                );
                self.chat.push(Kind::Info, line.clone());
                let tags = tag
                    .iter()
                    .cloned()
                    .chain([format!("file:{path}")])
                    .collect();
                Fx::Log {
                    ok: true,
                    body: line,
                    tags,
                }
            })
            .collect()
    }

    fn answer(&mut self, why: Turn, workflows: &[plan::WfInfo]) -> Vec<Fx> {
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
    fn answered(&mut self, at: usize, workflows: &[plan::WfInfo]) -> Vec<Fx> {
        // It did the job with commands the user allowed, and says how it went.
        if verdict::take(&self.chat.entries[at].1).1.is_some() {
            return self.verified(at, workflows);
        }
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

    fn new_plan(&mut self, at: usize, mut p: Plan, workflows: &[plan::WfInfo]) -> Vec<Fx> {
        let unknown = self.place(&mut p);
        // Claude's own plan: what it asked to run earlier (and wasn't) is replaced by it.
        self.asked = None;
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
        // (A workflow on another target is that target's to know: it says so when asked
        // to start it.)
        let here = Plan {
            steps: p
                .steps
                .iter()
                .map(|st| match (&st.kind, &st.on) {
                    (StepKind::Workflow { .. }, Some(_)) => {
                        plan::Step::new("", StepKind::Check(String::new()))
                    }
                    _ => st.clone(),
                })
                .collect(),
            ..p.clone()
        };
        let mut problems = plan::problems(&here, workflows);
        problems.extend(unknown);
        let own = self.chat.ask.applying().map(|a| a.refuses);
        let mut given: Vec<&str> = self.values.keys().map(String::as_str).collect();
        for (i, st) in p.steps.iter().enumerate() {
            // What the step's host never runs from a session (a router's guarded
            // commands), by that host's rule, whoever's session this is.
            let rule = match self.peer_of(st) {
                Some(peer) => Some(peer.refuses),
                None => own,
            };
            if let StepKind::Run(c) | StepKind::Check(c) = &st.kind
                && let Some(why) = rule.and_then(|r| r.why(c, true))
            {
                problems.push((i, why));
            }
            // And the files on this machine no plan may edit (a target's own config,
            // its workflows: what sentry runs on that host), by every target's rule.
            if let StepKind::Edit { file, .. } = &st.kind
                && let Some(why) = own
                    .into_iter()
                    .chain(self.peers.iter().map(|x| x.refuses))
                    .find_map(|r| r.why(file, false))
            {
                problems.push((i, format!("{file}: {why}")));
            }
            // On a host over ssh, root's files are changed there (`run`), not here.
            if let StepKind::Edit { file, .. } = &st.kind
                && self.step_remote(st)
                && sudo::edit_target(file) != Ok(Owner::You)
                && !problems.iter().any(|(k, _)| *k == i)
            {
                problems.push((
                    i,
                    format!("{file}: edit steps are for files on this machine; change the server's with a run step"),
                ));
            }
            // A secret the line sets in plain is a tag wherever the line is shown or kept
            // (it runs as written). One that came back as a tag was never kept: it can't
            // be set again from the plan.
            if let StepKind::Run(c) | StepKind::Check(c) = &st.kind
                && let Some(f) = self.host_of(st).and_then(|h| h.masks.0.clone())
            {
                if c.contains("redacted:") && !problems.iter().any(|(k, _)| *k == i) {
                    problems.push((
                        i,
                        "it sets a secret to its tag (`redacted:…`): the value was never kept; capture it from the target that has it or ask for it with an `ask` step".into(),
                    ));
                }
                for (v, tag) in f(c) {
                    if !self.literals.iter().any(|(x, _)| *x == v) {
                        self.literals.push((v, tag));
                    }
                }
            }
            // A workflow's values are written into its run's state, except on a host
            // that keeps its own secrets out of it (a router's guard).
            if let StepKind::Workflow { vars, .. } = &st.kind
                && !self.host_of(st).is_some_and(|h| h.hides)
                && let Some(name) = vars
                    .values()
                    .flat_map(|v| plan::placeholders(v))
                    .find(|n| self.secret_name(n, &p))
            {
                problems.push((
                    i,
                    format!("{{{{{name}}}}} is a secret, and a workflow's values are written into its run's state here: use it in a run step instead"),
                ));
            }
            // A value is used only after the step that gives it.
            for name in st.texts().into_iter().flat_map(plan::placeholders) {
                if !given.contains(&name) && !problems.iter().any(|(k, _)| *k == i) {
                    problems.push((
                        i,
                        format!(
                            "it uses {{{{{name}}}}}, which no earlier step captures or asks for"
                        ),
                    ));
                }
            }
            if let Some(name) = st.gives() {
                given.push(name);
            }
        }
        problems.sort_by_key(|(i, _)| *i);
        let saved = self
            .chat
            .ask
            .applying()
            .and_then(|a| a.plan.clone())
            .map(|key| Fx::PlanSave {
                key,
                body: self.clean(&format!(
                    "{}\n\n{}",
                    self.chat.entries[at].1.trim(),
                    plan::to_block(&p)
                )),
            });
        self.runs.push(Run::new(p));
        self.chat
            .entries
            .insert(at + 1, (Kind::Plan, (self.runs.len() - 1).to_string()));
        if problems.is_empty() {
            self.phase = Phase::Review;
            return saved.into_iter().collect();
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
    fn verified(&mut self, at: usize, workflows: &[plan::WfInfo]) -> Vec<Fx> {
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
            // Nothing to do now: nothing changed, the row is put off, and in a series the
            // next one follows.
            Status::Wait => {
                self.chat.push(
                    Kind::Info,
                    format!("Claude advises waiting · {}", v.summary),
                );
                next(self);
                self.phase = Phase::Settled(End::Waited);
                let mut fx = self.log_runs(Some(&v.summary));
                let a = self.chat.ask.applying().cloned().unwrap_or_default();
                fx.push(Fx::Wait {
                    key: a.key,
                    why: v.summary.clone(),
                    again: v.again.clone(),
                    body: self.chat.entries[at].1.trim().to_string(),
                });
                if self.series.is_some() {
                    fx.push(Fx::Next);
                }
                fx
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
        workflows: &[plan::WfInfo],
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
            a.parse::<crate::config::Dur>().is_ok()
                || workflows.iter().any(|w| &w.name == a)
                || crate::maint::tasks::after_task(a).is_some()
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
            again: None,
        }
    }

    // ── The end ─────────────────────────────────────────────────────────────────────────

    fn settle(&mut self, end: End) -> Vec<Fx> {
        self.settle_with(end, None)
    }

    fn settle_with(&mut self, end: End, verdict: Option<&str>) -> Vec<Fx> {
        self.phase = Phase::Settled(end);
        self.secret.clear();
        let mut fx = self.log_runs(verdict);
        if end == End::Done
            && let Some(p) = self.chat.ask.applying().and_then(|a| a.plan.clone())
        {
            fx.push(Fx::PlanDone(p));
        }
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
        // Done, nothing left to allow: the series goes on by itself.
        if end == End::Done && self.series.is_some() && !self.can_grant() {
            fx.push(Fx::Next);
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
        // What nobody pressed a key for.
        if !self.auto_log.is_empty() {
            body.push(format!(
                "Answered by auto: {}",
                std::mem::take(&mut self.auto_log).join("; ")
            ));
            tags.push("auto".into());
        }
        // The other targets its steps ran on: each gets an entry of its own, under its
        // own scope, saying what ran there; all share the run's id and name each other.
        let mut away: Vec<String> = Vec::new();
        for r in &started {
            for (st, _) in r.plan.steps.iter().zip(&r.results) {
                if let Some(on) = &st.on
                    && !away.contains(on)
                {
                    away.push(on.clone());
                }
            }
        }
        let name = |id: &str| {
            if id.is_empty() {
                "local".to_string()
            } else {
                id.to_string()
            }
        };
        let home = self.home.as_ref().map(|h| h.name().to_string());
        let mut out = Vec::new();
        for id in &away {
            let mut lines = Vec::new();
            for r in &started {
                for (i, (st, res)) in r.plan.steps.iter().zip(&r.results).enumerate() {
                    if st.on.as_ref() == Some(id) {
                        lines.push(format!(
                            "{}. {} {} ({} {}): {}",
                            i + 1,
                            if res.ok { "✓" } else { "✗" },
                            st.title,
                            st.kind.word(),
                            st.kind.target(),
                            res.note
                        ));
                    }
                }
            }
            let mut t: Vec<String> = tags
                .iter()
                .filter(|t| t.starts_with("apply:") || *t == "auto")
                .cloned()
                .collect();
            t.push(format!("run:{}", self.run_id));
            t.extend(home.iter().map(|h| format!("with:{h}")));
            t.extend(
                away.iter()
                    .filter(|o| *o != id)
                    .map(|o| format!("with:{}", name(o))),
            );
            let what = self.chat.ask.subject.trim_start_matches("apply · ");
            out.push(Fx::On(
                id.clone(),
                Box::new(Fx::Log {
                    ok: ok && !lines.iter().any(|l| l.contains(". ✗ ")),
                    body: self.clean(&format!(
                        "Steps run here by a session started on {} ({what}):\n{}",
                        home.as_deref().unwrap_or("another target"),
                        lines.join("\n")
                    )),
                    tags: t,
                }),
            ));
        }
        if !away.is_empty() {
            tags.push(format!("run:{}", self.run_id));
            tags.extend(away.iter().map(|o| format!("with:{}", name(o))));
        }
        self.logged = self.runs.len();
        out.insert(
            0,
            Fx::Log {
                ok,
                body: self.clean(&body.join("\n\n")),
                tags,
            },
        );
        out
    }
}

fn needs_sudo(s: &plan::Step) -> bool {
    match &s.kind {
        StepKind::Run(c) | StepKind::Check(c) => sudo::uses_sudo(c),
        StepKind::Edit { file, .. } => sudo::edit_target(file) == Ok(Owner::Root),
        StepKind::Workflow { .. } | StepKind::Ask { .. } => false,
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
    fn auto_answers_the_routine_and_leaves_the_rest_to_you() {
        use crate::claude::{Access, Grant};
        let run = |c: &str| Grant {
            access: Access::Run,
            path: c.into(),
            ..Default::default()
        };
        // Off (as every session starts): nothing is answered.
        let mut s = session();
        assert!(s.auto_go().is_empty());
        assert_eq!(s.phase, Phase::Brief);
        // On: the brief is sent, the plan approved as it arrives, and the rest follows.
        s.auto = true;
        let fx = s.auto_go();
        assert_eq!(s.phase, Phase::Thinking(Turn::Investigate));
        assert!(s.auto_go().is_empty(), "nothing while Claude answers");
        answer(&mut s, &fx, &plan(CHECKS));
        assert!(s.can_approve());
        let fx = s.auto_go();
        assert_eq!(s.phase, Phase::Applying);
        assert_eq!(
            fx,
            vec![Fx::Command {
                cmd: "true".into(),
                sudo: false
            }]
        );
        s.step_started(1, 2);
        let fx = s.step_ended(0);
        assert!(matches!(fx[0], Fx::Command { .. }), "{fx:?}");
        s.step_started(1, 2);
        let fx = s.step_ended(0);
        let fx = answer(
            &mut s,
            &fx,
            "```sentry-verdict\nstatus = \"done\"\nsummary = \"fine\"\n```",
        );
        // The log entry says which answers were auto's.
        let Some(Fx::Log { body, tags, .. }) = fx.iter().find(|f| matches!(f, Fx::Log { .. }))
        else {
            panic!("{fx:?}")
        };
        assert!(
            body.contains("Answered by auto: started it; approved the plan (fix it)"),
            "{body}"
        );
        assert!(tags.contains(&"auto".to_string()), "{tags:?}");
        assert!(s.auto_go().is_empty(), "settled: nothing left to answer");

        // A request Claude may have: allowed, and sentry runs it. The user's fix rounds
        // aren't renewed by it.
        let mut s = session();
        s.auto = true;
        let fx = s.auto_go();
        answer(&mut s, &fx, "It's refused; I asked.");
        s.sudo_free = true;
        s.fixes = 1;
        s.chat.requests = vec![run("systemctl --user restart foo.service")];
        let fx = s.auto_go();
        assert_eq!(
            fx,
            vec![Fx::Command {
                cmd: "systemctl --user restart foo.service".into(),
                sudo: false
            }]
        );
        assert_eq!(s.fixes, 1);

        // What auto never allows waits for Enter, exactly as with auto off, and says why:
        // a reboot, an upgrade, where keys live.
        for (req, why) in [
            (run("sudo systemctl reboot"), "restarts the system"),
            (run("rpm-ostree rollback"), "rolls back"),
            (
                run("cat ~/.ssh/id_ed25519"),
                "keys and passwords live there",
            ),
        ] {
            let mut s = session();
            s.auto = true;
            let fx = s.auto_go();
            answer(&mut s, &fx, "Asked.");
            s.chat.requests = vec![run("uname -a"), req.clone()];
            assert!(s.auto_go().is_empty(), "{req:?}");
            assert_eq!(s.phase, Phase::Review);
            assert_eq!(s.chat.requests.len(), 2, "nothing was allowed");
            let last = &s.chat.entries.last().unwrap().1;
            assert!(
                last.starts_with("auto leaves this to you") && last.contains(why),
                "{last}"
            );
            // Said once, not at every look.
            let n = s.chat.entries.len();
            assert!(s.auto_go().is_empty());
            assert_eq!(s.chat.entries.len(), n);
            // The key still does what it did.
            assert_eq!(s.enter_word(), Some("allow it"));
        }

        // A plan with a step auto never runs isn't approved by it.
        let mut s = session();
        s.auto = true;
        let fx = s.auto_go();
        answer(
            &mut s,
            &fx,
            &plan("[[step]]\ntitle = \"flash\"\nrun = \"sudo fwupdmgr update -y\"\n"),
        );
        assert!(s.can_approve());
        assert!(s.auto_go().is_empty());
        assert_eq!(s.phase, Phase::Review);
        assert!(
            s.chat
                .entries
                .last()
                .unwrap()
                .1
                .contains("step 1 (flash): it flashes firmware"),
            "{:?}",
            s.chat.entries.last()
        );
        // While the user types, auto doesn't act under them.
        let mut s = session();
        s.auto = true;
        s.chat.input.push('x');
        assert!(s.auto_go().is_empty());
        assert_eq!(s.phase, Phase::Brief);

        // A verdict that isn't "done" is the user's: nothing is marked or carried on.
        let mut s = session();
        s.auto = true;
        s.series = Some((1, 2));
        let fx = s.auto_go();
        answer(&mut s, &fx, &plan(CHECKS));
        let _ = s.auto_go();
        s.step_started(1, 2);
        let _ = s.step_ended(0);
        s.step_started(1, 2);
        let fx = s.step_ended(0);
        let fx = answer(
            &mut s,
            &fx,
            "```sentry-verdict\nstatus = \"failed\"\nsummary = \"no\"\n```",
        );
        assert!(!fx.contains(&Fx::Next), "{fx:?}");
        assert_eq!(s.phase, Phase::Settled(End::Failed));
        assert!(s.auto_go().is_empty());
    }

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
    fn in_a_series_it_starts_by_itself_and_hands_on() {
        const DONE: &str = "```sentry-verdict\nstatus = \"done\"\nsummary = \"fixed\"\n```";
        let mut s = session();
        // No Enter: the series' Enter was the start.
        let fx = s.start_in_series((2, 5));
        assert!(matches!(&fx[..], [Fx::Turn { shown: Some(q), .. }] if q == "Do this for me."));
        assert!(s.start_in_series((2, 5)).is_empty(), "once");
        // The plan is still the user's to approve.
        let fx = answer(&mut s, &fx, &plan(CHECKS));
        assert!(fx.is_empty() && s.enter_word() == Some("apply the plan"));
        key(&mut s, KeyCode::Enter);
        s.step_ended(0);
        let fx = s.step_ended(0);
        // Done: logged, then on to the next by itself.
        let fx = answer(&mut s, &fx, DONE);
        assert!(
            matches!(&fx[..], [Fx::Log { ok: true, .. }, Fx::Next]),
            "{fx:?}"
        );

        // One that doesn't end well waits: Enter goes on, Esc closes (the series stops).
        let mut s = session();
        let fx = s.start_in_series((1, 2));
        let fx = answer(&mut s, &fx, &plan(CHECKS));
        assert!(fx.is_empty());
        key(&mut s, KeyCode::Enter);
        s.step_ended(0);
        let fx = s.step_ended(0);
        let fx = answer(
            &mut s,
            &fx,
            "```sentry-verdict\nstatus = \"failed\"\nsummary = \"still broken\"\n```",
        );
        assert!(!fx.contains(&Fx::Next), "{fx:?}");
        assert!(matches!(s.phase, Phase::Settled(e) if e != End::Done));
        assert_eq!(s.enter_word(), Some("go on with the next"));
        assert_eq!(key(&mut s, KeyCode::Enter), [Fx::Next]);
        assert_eq!(key(&mut s, KeyCode::Esc), [Fx::Close]);

        // Outside a series nothing changes: Done waits for its close.
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        let fx = answer(&mut s, &fx, &plan(CHECKS));
        assert!(fx.is_empty());
        key(&mut s, KeyCode::Enter);
        s.step_ended(0);
        let fx = s.step_ended(0);
        let fx = answer(&mut s, &fx, DONE);
        assert!(!fx.contains(&Fx::Next), "{fx:?}");
        assert_eq!(s.enter_word(), Some("close"));
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
        // Accepted: the program takes it, to hold for everything on this target.
        assert_eq!(s.take_typed().stdin(), b"ok\n");
        assert_eq!(
            s.password_checked(true),
            [Fx::Command {
                cmd: "sudo systemctl daemon-reload".into(),
                sudo: true
            }]
        );
        assert!(s.secret_ok);
        // C-c on the step: stopped, logged, nothing sent.
        s.step_started(3, 33);
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(s.key(k), [Fx::Kill(33)]);
        let fx = s.step_ended(-1);
        assert_eq!(s.phase, Phase::Settled(End::Stopped));
        assert!(matches!(&fx[..], [Fx::Log { ok: false, .. }]), "{fx:?}");
        assert!(s.secret.is_empty());
        // The next plan with sudo in it asks nothing: the program holds the password.
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(
            &mut s,
            &fx,
            &plan("[[step]]\ntitle = \"r\"\nrun = \"sudo true\"\n"),
        );
        assert_eq!(key(&mut s, KeyCode::Enter), [Fx::CheckSudo]);
        assert_eq!(
            s.password_held(),
            [Fx::Command {
                cmd: "sudo true".into(),
                sudo: true
            }]
        );
        // Forgotten (the key, or sudo refused it): asked again at the next plan.
        s.password_gone();
        assert!(!s.secret_ok);
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
    fn g_grants_reads_but_changes_go_in_the_plan() {
        use crate::claude::{Access, Grant};
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(&mut s, &fx, &plan(CHECKS));
        s.chat.requests = vec![
            Grant {
                access: Access::Read,
                path: "/etc/hosts".into(),
                ..Default::default()
            },
            Grant {
                access: Access::Write,
                path: "/etc/hosts".into(),
                ..Default::default()
            },
        ];
        assert!(s.can_grant());
        let fx = key(&mut s, KeyCode::Char('g'));
        let Some(Fx::Turn { prompt, .. }) = fx.first() else {
            panic!("{fx:?}")
        };
        // Root's file: Claude is told it goes in a plan.
        assert!(
            prompt.contains("read /etc/hosts") && prompt.contains("plan's edit step"),
            "{prompt}"
        );
        assert!(s.chat.grants.iter().all(|g| g.access == Access::Read));
        // Typing: `g` is a letter.
        s.chat.requests = vec![Grant {
            access: Access::Read,
            path: "/etc/os-release".into(),
            ..Default::default()
        }];
        s.phase = Phase::Review;
        s.chat.input.push('x');
        assert!(!s.can_grant());
    }

    #[test]
    fn enter_allows_what_claude_asked_and_sentry_runs_the_changes() {
        use crate::claude::{Access, Grant};
        let run = |c: &str| Grant {
            access: Access::Run,
            path: c.into(),
            ..Default::default()
        };
        // A session's Claude runs what it likes, so what was refused is under a rule no
        // grant lifts: sentry runs it, read-only or not, and tells Claude what it printed.
        let mut s = session();
        assert!(
            s.chat
                .privacy
                .contains("any command here that needs no root")
        );
        let fx = key(&mut s, KeyCode::Enter);
        answer(&mut s, &fx, "It's refused; I asked.");
        s.sudo_free = true;
        s.chat.requests = vec![run("rpm-ostree upgrade --preview")];
        assert_eq!(s.enter_word(), Some("allow it"));
        let fx = key(&mut s, KeyCode::Enter);
        assert_eq!(
            fx,
            vec![Fx::Command {
                cmd: "rpm-ostree upgrade --preview".into(),
                sudo: false
            }]
        );
        assert!(s.chat.grants.is_empty());

        // Upgrading and rebooting are a workflow's: Claude is told, nothing runs.
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(&mut s, &fx, "Asked.");
        s.chat.requests = vec![run("sudo rpm-ostree upgrade"), run("systemctl reboot")];
        let fx = key(&mut s, KeyCode::Enter);
        let Some(Fx::Turn { prompt, .. }) = fx.first() else {
            panic!("{fx:?}")
        };
        assert!(
            prompt.contains("run sudo rpm-ostree upgrade: upgrades, rebases")
                && prompt.contains("run systemctl reboot:"),
            "{prompt}"
        );
        assert!(s.runs.is_empty());

        // On a server too: what needs root is asked for, then run there with the password.
        let mut s = Session::new(Ask::apply(
            "the disk",
            "ctx",
            Apply {
                key: "task:disk".into(),
                task: Some("disk".into()),
                remote: true,
                ..Default::default()
            },
        ));
        let fx = key(&mut s, KeyCode::Enter);
        answer(&mut s, &fx, "It needs root; I asked.");
        // (The gateway refused it: it's a line for the server.)
        let gateway = |c: &str| crate::claude::Grant {
            on: Some("srv:myserver".into()),
            ..run(c)
        };
        s.chat.requests = vec![gateway("sudo smartctl -a /dev/sda")];
        assert!(s.can_grant());
        assert_eq!(key(&mut s, KeyCode::Enter), vec![Fx::CheckSudo]);
        // What Claude Code refused of a command on this machine never goes to the server:
        // one that only reads becomes a grant (Claude runs it here itself), one that
        // changes something is refused, with why.
        let mut s3 = Session::new(s.chat.ask.clone());
        let fx = key(&mut s3, KeyCode::Enter);
        answer(&mut s3, &fx, "Asked.");
        s3.chat.requests = vec![run("journalctl -b -p 3"), run("touch /tmp/x")];
        let fx = key(&mut s3, KeyCode::Enter);
        let [Fx::Turn { prompt, .. }] = &fx[..] else {
            panic!("{fx:?}")
        };
        assert!(s3.runs.is_empty(), "nothing is run over ssh");
        assert!(
            prompt.contains("I've granted you: run journalctl -b -p 3")
                && prompt.contains("run touch /tmp/x: that would change this machine"),
            "{prompt}"
        );
        assert_eq!(s3.chat.grants.len(), 1);
        // And a server's line is never run here.
        let mut s4 = session();
        let fx = key(&mut s4, KeyCode::Enter);
        answer(&mut s4, &fx, "Asked.");
        s4.chat.requests = vec![gateway("sudo true")];
        let fx = key(&mut s4, KeyCode::Enter);
        assert!(
            matches!(&fx[..], [Fx::Turn { prompt, .. }] if prompt.contains("isn't a server's session")),
            "{fx:?}"
        );
        assert!(s4.runs.is_empty());
        // A piece of a pipeline is never run by itself: the command as Claude wrote it is.
        let mut s5 = session();
        let fx = key(&mut s5, KeyCode::Enter);
        answer(&mut s5, &fx, "Asked.");
        s5.chat.requests = vec![
            crate::claude::requested(
                "Bash",
                "journalctl -b | head -20; echo ---; git -C /x status --short 2>&1",
                "denied: This Bash command contains multiple operations. The following part \
                 requires approval: head -20; echo ---; git -C /x status --short 2>&1",
            )
            .unwrap(),
        ];
        let fx = key(&mut s5, KeyCode::Enter);
        assert_eq!(
            fx,
            [Fx::Command {
                cmd: "journalctl -b | head -20; echo ---; git -C /x status --short 2>&1".into(),
                sudo: false
            }]
        );
        // A request that hasn't ended after two minutes is stopped; a plan's step isn't.
        s5.step_started(4, 44);
        assert!(s5.limited() && s5.overdue().is_none());
        s5.job_started = std::time::Instant::now().checked_sub(Session::ASKED_LIMIT);
        assert_eq!(s5.overdue(), Some(44));
        assert_eq!(s5.overdue(), None, "once");
        assert!(s5.output.last().unwrap().contains("no end after 120 s"));
        // A file on the laptop still isn't a server session's to edit.
        let mut s2 = Session::new(s.chat.ask.clone());
        let fx = key(&mut s2, KeyCode::Enter);
        answer(&mut s2, &fx, "Asked.");
        s2.chat.requests = vec![Grant {
            access: Access::Write,
            path: crate::paths::home().join("notes.md").display().to_string(),
            ..Default::default()
        }];
        assert!(!s2.can_grant());

        // A root command: sentry asks for the password, runs it, tells Claude, logs it.
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(&mut s, &fx, "I need root for this.");
        s.chat.requests = vec![run("sudo systemctl restart x")];
        let fx = key(&mut s, KeyCode::Enter);
        assert_eq!(fx, vec![Fx::CheckSudo]);
        assert_eq!(s.sudo_checked(true), vec![]);
        type_in(&mut s, "pw");
        assert_eq!(key(&mut s, KeyCode::Enter), vec![Fx::CheckPassword]);
        let fx = s.password_checked(true);
        assert_eq!(
            fx,
            vec![Fx::Command {
                cmd: "sudo systemctl restart x".into(),
                sudo: true
            }]
        );
        s.step_started(5, 55);
        s.step_line("restarted".into());
        let fx = s.step_ended(0);
        let Some(Fx::Turn { prompt, shown }) = fx.first() else {
            panic!("{fx:?}")
        };
        assert!(prompt.contains("sentry ran it for you") && prompt.contains("restarted"));
        assert!(prompt.contains("sentry-verdict") && shown.is_none());
        // It finished the job: its verdict settles the session, and the run is logged.
        let fx = answer(
            &mut s,
            &fx,
            "Done.\n\n```sentry-verdict\nstatus = \"done\"\nsummary = \"restarted\"\n```\n",
        );
        assert_eq!(s.phase, Phase::Settled(End::Done));
        assert!(
            fx.iter()
                .any(|f| matches!(f, Fx::Log { body, .. } if body.contains("restarted")))
        );

        // A failed command goes back to Claude too; a ready plan keeps Enter.
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(&mut s, &fx, "Asked.");
        s.sudo_free = true;
        s.chat.requests = vec![run("rm /tmp/x")];
        let fx = key(&mut s, KeyCode::Enter);
        assert_eq!(fx.len(), 1);
        let fx = s.step_ended(1);
        assert!(matches!(&fx[0], Fx::Turn { prompt, .. } if prompt.contains("exit 1")));
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(&mut s, &fx, &plan(CHECKS));
        s.chat.requests = vec![run("sudo dmesg")];
        assert_eq!(s.enter_word(), Some("apply the plan"));
    }

    #[test]
    fn your_file_is_backed_up_and_its_change_logged() {
        use crate::claude::{Access, Grant};
        let tmp = std::env::temp_dir().join(format!("sentry-sess-{}.md", std::process::id()));
        std::fs::write(&tmp, "a\n").unwrap();
        let path = tmp.display().to_string();
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(&mut s, &fx, "I asked to edit it.");
        s.chat.requests = vec![Grant {
            access: Access::Write,
            path: path.clone(),
            ..Default::default()
        }];
        let fx = key(&mut s, KeyCode::Enter);
        assert!(matches!(&fx[0], Fx::Turn { prompt, .. } if prompt.contains("edit")));
        std::fs::write(&tmp, "a\nb\n").unwrap();
        s.chat.begin_quiet(2, 2);
        let fx = answer(&mut s, &fx, "Edited.");
        assert!(
            fx.iter().any(
                |f| matches!(f, Fx::Log { tags, .. } if tags.contains(&format!("file:{path}")))
            ),
            "{fx:?}"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn a_paste_is_typed_never_keys() {
        let mut s = session();
        s.paste("g line one\r\nline two\n");
        assert_eq!(s.phase, Phase::Brief);
        assert_eq!(s.chat.input, "g line one\nline two\n");
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
            [Fx::StartWorkflow("quick-update".into(), Default::default())]
        );
        assert_eq!(s.waiting_workflow(), Some("quick-update"));
        assert_eq!(
            key(&mut s, KeyCode::Enter),
            [Fx::OpenRun("quick-update".into(), Default::default())]
        );
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

    fn item_session() -> Session {
        Session::new(Ask::apply(
            "web",
            "ctx about web",
            Apply {
                key: "web".into(),
                item: Some("web".into()),
                plan: Some("web".into()),
                ..Default::default()
            },
        ))
    }

    #[test]
    fn the_plan_is_kept_as_it_is_shown_and_seeds_a_session_later() {
        let mut s = item_session();
        let fx = key(&mut s, KeyCode::Enter);
        // Research, then the plan: shown once, and kept (the assessment with its block).
        let fx = answer(
            &mut s,
            &fx,
            &format!(
                "TARGET: 1.5.2\n# Plan: web\nNotes say it's safe.\n\n{}",
                &plan(CHECKS)[11..]
            ),
        );
        let [Fx::PlanSave { key: k, body }] = &fx[..] else {
            panic!("{fx:?}")
        };
        assert_eq!(k, "web");
        assert!(
            body.starts_with("TARGET: 1.5.2\n# Plan: web") && body.contains("```sentry-apply"),
            "{body}"
        );
        assert!(s.can_approve());
        // Another day: opened on that document, straight at the plan; nothing is sent.
        let mut s = Session::seeded(item_session().chat.ask, body, &[]).expect("a plan in it");
        assert_eq!(s.phase, Phase::Review);
        assert!(s.can_approve() && s.run().unwrap().plan.steps.len() == 2);
        let fx = key(&mut s, KeyCode::Enter);
        assert!(matches!(&fx[..], [Fx::Command { .. }]), "{fx:?}");
        s.step_ended(0);
        // The first thing Claude hears carries what it's about and the plan approved.
        let fx = s.step_ended(0);
        let [Fx::Turn { prompt, .. }] = &fx[..] else {
            panic!("{fx:?}")
        };
        assert!(
            prompt.starts_with("ctx about web\n\nThe plan for it, written earlier")
                && prompt.contains("Notes say it's safe.")
                && prompt.contains("carried out all 2 steps"),
            "{prompt}"
        );
        let fx = answer(
            &mut s,
            &fx,
            "```sentry-verdict\nstatus = \"done\"\nsummary = \"1.5.2 runs\"\n```",
        );
        assert!(fx.contains(&Fx::PlanDone("web".into())), "{fx:?}");
        // A document with no plan in it (written before) doesn't seed one.
        assert!(Session::seeded(item_session().chat.ask, "# Plan\nby hand", &[]).is_none());
    }

    #[test]
    fn wait_settles_with_nothing_changed_and_puts_the_row_off() {
        let mut s = item_session();
        let fx = key(&mut s, KeyCode::Enter);
        let fx = answer(
            &mut s,
            &fx,
            "1.5.2 has an open data-loss bug.\n```sentry-verdict\nstatus = \"wait\"\n\
             summary = \"wait for 1.5.3\"\nagain = \"14d\"\n```",
        );
        assert_eq!(s.phase, Phase::Settled(End::Waited));
        assert_eq!(
            fx,
            [Fx::Wait {
                key: "web".into(),
                why: "wait for 1.5.3".into(),
                again: Some("14d".into()),
                body: "1.5.2 has an open data-loss bug.".into(),
            }]
        );
        assert!(s.runs.is_empty());
        assert_eq!(s.enter_word(), Some("close"));
        assert_eq!(key(&mut s, KeyCode::Enter), [Fx::Close]);
        // In a series the next row follows by itself.
        let mut s = item_session();
        let fx = s.start_in_series((1, 2));
        let fx = answer(
            &mut s,
            &fx,
            "```sentry-verdict\nstatus = \"wait\"\nsummary = \"not yet\"\n```",
        );
        assert!(
            matches!(&fx[..], [Fx::Wait { again: None, .. }, Fx::Next]),
            "{fx:?}"
        );
    }

    // ── One session, every target ───────────────────────────────────────────────────────

    fn router_refuses(line: &str, remote: bool) -> Option<String> {
        (remote && line.contains("uci commit network"))
            .then(|| "a guarded config changes only through the guard step".to_string())
    }

    fn peer(id: &str, title: &str) -> Peer {
        Peer {
            id: id.into(),
            title: title.into(),
            remote: !id.is_empty(),
            calls: vec![format!("sentry-x exec {title}")],
            ..Default::default()
        }
    }

    fn router() -> Peer {
        Peer {
            refuses: crate::claude::Refuses(Some(router_refuses)),
            asks_each: true,
            hides: true,
            masks: Masks(Some(std::sync::Arc::new(|line: &str| {
                line.split('\'')
                    .nth(1)
                    .filter(|_| line.contains("api_key=") && !line.contains("{{"))
                    .map(|v| vec![(v.to_string(), "redacted:0badc0de".to_string())])
                    .unwrap_or_default()
            }))),
            ..peer("net:home", "home")
        }
    }

    /// A session that started on the router, in a window that also has the server and
    /// this machine.
    fn on_router() -> Session {
        let mut s = Session::new(Ask::apply(
            "the bouncer",
            "ctx",
            Apply {
                key: "task:bouncer".into(),
                task: Some("bouncer".into()),
                plan: Some("bouncer".into()),
                remote: true,
                refuses: crate::claude::Refuses(Some(router_refuses)),
                asks_each: true,
                ..Default::default()
            },
        ));
        s.in_system(
            router(),
            vec![peer("", "laptop"), peer("srv:myserver", "myserver")],
        );
        s
    }

    const KEY: &str = "S3cretBouncerKey+abc/123=";

    const BOUNCER: &str = "[[step]]\ntitle = \"Listen\"\non = \"srv:myserver\"\nrun = \"sudo sed -i s/127.0.0.1/0.0.0.0/ /etc/crowdsec/config.yaml\"\n\n\
[[step]]\ntitle = \"Key\"\non = \"srv:myserver\"\nrun = \"sudo cscli bouncers add router -o raw\"\ncapture = \"key\"\nsecret = true\n\n\
[[step]]\ntitle = \"Install\"\nrun = \"apk add crowdsec-firewall-bouncer\"\n\n\
[[step]]\ntitle = \"Set the key\"\nrun = \"uci set crowdsec.@bouncer[0].api_key='{{key}}' && uci commit crowdsec\"\n\n\
[[step]]\ntitle = \"Reach it\"\ncheck = \"wget -qO- --header 'X-Api-Key: {{key}}' http://server:8080/v1/decisions\"\n";

    fn sent(fx: &[Fx]) -> &str {
        match fx.iter().find(|f| matches!(f, Fx::Turn { .. })) {
            Some(Fx::Turn { prompt, .. }) => prompt,
            _ => panic!("no turn in {fx:?}"),
        }
    }

    #[test]
    fn one_plan_runs_on_several_targets_and_a_secret_goes_between_them_unseen() {
        let mut s = on_router();
        let fx = key(&mut s, KeyCode::Enter);
        let fx = answer(&mut s, &fx, &plan(BOUNCER));
        // The plan is kept as it was written: the name, never a value.
        let Some(Fx::PlanSave { body, .. }) = fx.iter().find(|f| matches!(f, Fx::PlanSave { .. }))
        else {
            panic!("{fx:?}")
        };
        assert!(
            body.contains("{{key}}") && body.contains("on = \"srv:myserver\""),
            "{body}"
        );
        assert!(s.can_approve() && s.several());
        let r = s.run().unwrap();
        assert_eq!(s.step_place(&r.plan.steps[0]).as_deref(), Some("myserver"));
        assert_eq!(s.step_place(&r.plan.steps[2]).as_deref(), Some("home"));
        // ONE approval. The server's sudo is looked into there, and its password typed
        // here, in the session's own line.
        let fx = key(&mut s, KeyCode::Enter);
        assert_eq!(fx, [Fx::On("srv:myserver".into(), Box::new(Fx::CheckSudo))]);
        assert!(s.sudo_checked(true).is_empty());
        assert_eq!(s.sudo_title(), Some("myserver"));
        assert_eq!(s.sudo_steps(), [1, 2]);
        type_in(&mut s, "hunter2");
        assert_eq!(
            key(&mut s, KeyCode::Enter),
            [Fx::On("srv:myserver".into(), Box::new(Fx::CheckPassword))]
        );
        let fx = s.password_checked(true);
        let on = |fx: &[Fx]| match &fx[0] {
            Fx::On(id, f) => match &**f {
                Fx::Command { cmd, sudo } => (id.clone(), cmd.clone(), *sudo),
                f => panic!("{f:?}"),
            },
            f => panic!("{f:?}"),
        };
        assert_eq!(on(&fx).0, "srv:myserver");
        assert!(on(&fx).2);
        s.step_started(1, 2);
        // The second server step: no password again. What it prints is the key: never
        // shown, kept for the session.
        let fx = s.step_ended(0);
        assert!(on(&fx).1.contains("cscli bouncers add"), "{fx:?}");
        s.step_started(3, 4);
        s.step_said(KEY.into(), KEY, false);
        assert!(!s.output.join("\n").contains(KEY), "{:?}", s.output);
        assert_eq!(s.output, ["‹key: hidden›"]);
        let fx = s.step_ended(0);
        // The router's steps are the home target's own: plain effects, the value filled
        // in only in the command that runs.
        assert_eq!(
            fx,
            [Fx::Command {
                cmd: "apk add crowdsec-firewall-bouncer".into(),
                sudo: false
            }]
        );
        s.step_started(5, 6);
        let fx = s.step_ended(0);
        let Fx::Command { cmd, .. } = &fx[0] else {
            panic!("{fx:?}")
        };
        assert_eq!(
            *cmd,
            format!("uci set crowdsec.@bouncer[0].api_key='{KEY}' && uci commit crowdsec")
        );
        s.step_started(7, 8);
        // Whatever echoes it is swept.
        s.step_said(format!("set to {KEY}"), &format!("set to {KEY}"), false);
        assert_eq!(s.output, ["set to ‹key›"]);
        let fx = s.step_ended(0);
        assert!(matches!(&fx[0], Fx::Command { cmd, .. } if cmd.contains(KEY)));
        s.step_started(9, 10);
        let fx = s.step_ended(0);
        // Claude verifies from a report that names the value, not what it is.
        assert!(
            sent(&fx).contains("api_key='{{key}}'") && !sent(&fx).contains(KEY),
            "{}",
            sent(&fx)
        );
        let fx = answer(
            &mut s,
            &fx,
            "```sentry-verdict\nstatus = \"done\"\nsummary = \"installed\"\n```",
        );
        // One entry per target touched, sharing the run's id and naming each other; the
        // home one carries the task.
        let logs: Vec<(Option<&str>, &String, &Vec<String>)> = fx
            .iter()
            .filter_map(|f| match f {
                Fx::Log { body, tags, .. } => Some((None, body, tags)),
                Fx::On(id, f) => match &**f {
                    Fx::Log { body, tags, .. } => Some((Some(id.as_str()), body, tags)),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(logs.len(), 2, "{fx:?}");
        let run = format!("run:{}", s.run_id);
        assert!(logs[0].0.is_none() && logs[0].2.contains(&run));
        assert!(logs[0].2.contains(&"with:srv:myserver".to_string()));
        assert!(logs[0].2.contains(&"task:bouncer".to_string()));
        assert_eq!(logs[1].0, Some("srv:myserver"));
        assert!(logs[1].2.contains(&run) && logs[1].2.contains(&"with:net:home".to_string()));
        assert!(
            logs[1].1.contains("2. ✓ Key") && !logs[1].1.contains("Install"),
            "{}",
            logs[1].1
        );
        for (_, body, _) in &logs {
            assert!(!body.contains(KEY), "{body}");
        }
        // Nothing the session says holds it: the transcript, the plans, what it sent.
        for (_, t) in &s.chat.entries {
            assert!(!t.contains(KEY), "{t}");
        }
        assert_eq!(s.secrets(), [("‹key›".to_string(), KEY.to_string())]);
        assert_eq!(s.phase, Phase::Settled(End::Done));
    }

    #[test]
    fn a_step_that_fails_on_another_target_is_fixed_there_and_retried() {
        let mut s = on_router();
        let fx = key(&mut s, KeyCode::Enter);
        answer(
            &mut s,
            &fx,
            &plan(
                "[[step]]\ntitle = \"Reach it\"\ncheck = \"wget -qO- http://server:8080/health\"\n",
            ),
        );
        let fx = key(&mut s, KeyCode::Enter);
        assert!(matches!(&fx[0], Fx::Command { .. }));
        s.step_started(1, 2);
        s.step_line("Connection refused".into());
        // The failure goes back to Claude; its fix is on the server, the retry here.
        let fx = s.step_ended(1);
        assert!(sent(&fx).contains("Connection refused"));
        let fx = answer(
            &mut s,
            &fx,
            &plan(
                "[[step]]\ntitle = \"Listen\"\non = \"srv:myserver\"\nrun = \"systemctl --user restart api\"\n\n\
                   [[step]]\ntitle = \"Reach it\"\ncheck = \"wget -qO- http://server:8080/health\"\n",
            ),
        );
        assert!(fx.iter().all(|f| !matches!(f, Fx::Turn { .. })) && s.can_approve());
        let fx = key(&mut s, KeyCode::Enter);
        assert!(
            matches!(&fx[0], Fx::On(id, _) if id == "srv:myserver"),
            "{fx:?}"
        );
        s.step_started(3, 4);
        let fx = s.step_ended(0);
        assert_eq!(
            fx,
            [Fx::Command {
                cmd: "wget -qO- http://server:8080/health".into(),
                sudo: false
            }]
        );
        s.step_started(5, 6);
        let fx = s.step_ended(0);
        assert_eq!(s.phase, Phase::Thinking(Turn::Verify));
        assert!(sent(&fx).contains("all 2 steps"));
        // The same session throughout.
        assert_eq!(s.runs.len(), 2);
    }

    #[test]
    fn a_step_is_checked_by_the_rules_of_the_target_it_is_on() {
        // An unknown target: refused back, with the ids there are.
        let mut s = on_router();
        let fx = key(&mut s, KeyCode::Enter);
        let fx = answer(
            &mut s,
            &fx,
            &plan("[[step]]\non = \"srv:nope\"\nrun = \"true\"\n"),
        );
        assert!(
            sent(&fx).contains(
                "names no target sentry has; the targets are: net:home, local, srv:myserver"
            ),
            "{}",
            sent(&fx)
        );
        // `on` the session's own target, and `local`, are understood.
        let fx = answer(
            &mut s,
            &fx,
            &plan(
                "[[step]]\non = \"net:home\"\nrun = \"true\"\n\n[[step]]\non = \"local\"\nrun = \"true\"\n",
            ),
        );
        assert!(fx.iter().all(|f| !matches!(f, Fx::Turn { .. })), "{fx:?}");
        let st = &s.run().unwrap().plan.steps;
        assert_eq!((st[0].on.as_deref(), st[1].on.as_deref()), (None, Some("")));

        // The router's rule holds for a step on it from a session that started elsewhere,
        // exactly as in its own session; and not for the same line on the server.
        let mut s = Session::new(Ask::apply(
            "x",
            "ctx",
            Apply {
                remote: true,
                ..Default::default()
            },
        ));
        s.in_system(peer("srv:myserver", "myserver"), vec![router()]);
        let fx = key(&mut s, KeyCode::Enter);
        let fx = answer(
            &mut s,
            &fx,
            &plan(
                "[[step]]\ntitle = \"a\"\non = \"net:home\"\nrun = \"uci commit network\"\n\n[[step]]\ntitle = \"b\"\nrun = \"uci commit network\"\n",
            ),
        );
        let p = sent(&fx);
        assert!(
            p.contains("- step 1 (a): a guarded config changes only through the guard step"),
            "{p}"
        );
        assert!(!p.contains("step 2"), "{p}");

        // A value is used only after a step gives it; a secret never goes into a
        // workflow's values where those are written down.
        let mut s = on_router();
        let fx = key(&mut s, KeyCode::Enter);
        let fx = answer(&mut s, &fx, &plan("[[step]]\nrun = \"echo '{{key}}'\"\n"));
        assert!(sent(&fx).contains("uses {{key}}, which no earlier step captures or asks for"));
        let fx = answer(
            &mut s,
            &fx,
            &plan(
                "[[step]]\nask = \"key\"\nprompt = \"The key\"\nsecret = true\n\n[[step]]\non = \"srv:myserver\"\nworkflow = \"quick-update\"\nvars = { k = \"{{key}}\" }\n",
            ),
        );
        assert!(
            sent(&fx).contains("{{key}} is a secret, and a workflow's values"),
            "{}",
            sent(&fx)
        );

        // A secret a line sets in plain shows and is kept as its tag; it runs as written.
        let mut s = on_router();
        let fx = key(&mut s, KeyCode::Enter);
        let fx = answer(
            &mut s,
            &fx,
            &plan(
                "[[step]]\ntitle = \"k\"\nrun = \"uci set crowdsec.bouncer.api_key='Literal-Secret-1'\"\n",
            ),
        );
        let Some(Fx::PlanSave { body, .. }) = fx.iter().find(|f| matches!(f, Fx::PlanSave { .. }))
        else {
            panic!("{fx:?}")
        };
        assert!(
            body.contains("api_key='redacted:0badc0de'") && !body.contains("Literal-Secret-1"),
            "{body}"
        );
        assert_eq!(s.clean("x Literal-Secret-1"), "x redacted:0badc0de");
        let fx = key(&mut s, KeyCode::Enter);
        assert!(matches!(&fx[0], Fx::Command { cmd, .. } if cmd.contains("Literal-Secret-1")));
        s.step_started(1, 2);
        let fx = s.step_ended(1);
        assert!(!sent(&fx).contains("Literal-Secret-1"), "{}", sent(&fx));
        // Sent back as its tag, it can't be set: the value was never kept.
        let fx = answer(
            &mut s,
            &fx,
            &plan(
                "[[step]]\ntitle = \"k\"\nrun = \"uci set crowdsec.bouncer.api_key='redacted:0badc0de'\"\n",
            ),
        );
        assert!(
            sent(&fx).contains("the value was never kept"),
            "{}",
            sent(&fx)
        );
    }

    #[test]
    fn a_value_only_the_user_has_is_asked_for_in_the_sessions_own_line() {
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(
            &mut s,
            &fx,
            &plan(
                "[[step]]\ntitle = \"Portal\"\nask = \"pass\"\nprompt = \"The portal's password\"\nsecret = true\n\n\
                   [[step]]\ntitle = \"Use it\"\nrun = \"login --password '{{pass}}'\"\n",
            ),
        );
        // Approved once; the plan reaches the step and waits for the value, typed here.
        assert!(key(&mut s, KeyCode::Enter).is_empty());
        assert_eq!(s.phase, Phase::Value);
        assert_eq!(s.asking(), Some(("pass", "The portal's password", true)));
        s.auto = true;
        assert!(s.auto_go().is_empty(), "auto never answers it");
        assert!(!crate::auto::answers(true, &crate::auto::Asked::Value));
        // Too short to keep hidden: asked again.
        type_in(&mut s, "abc");
        assert!(key(&mut s, KeyCode::Enter).is_empty());
        assert_eq!(s.phase, Phase::Value);
        s.paste("correct horse; $battery\n");
        // It goes on by itself, the value in the command only.
        let fx = key(&mut s, KeyCode::Enter);
        assert_eq!(
            fx,
            [Fx::Command {
                cmd: "login --password 'correct horse; $battery'".into(),
                sudo: false
            }]
        );
        s.step_started(1, 2);
        s.step_line("welcome, correct horse; $battery".into());
        assert_eq!(s.output, ["welcome, ‹pass›"]);
        let fx = s.step_ended(0);
        assert!(!sent(&fx).contains("correct horse"), "{}", sent(&fx));
        assert!(
            s.chat
                .entries
                .iter()
                .all(|(_, t)| !t.contains("correct horse"))
        );

        // Esc: nothing further runs, the session waits, and says for what.
        let mut s = session();
        let fx = key(&mut s, KeyCode::Enter);
        answer(
            &mut s,
            &fx,
            &plan(
                "[[step]]\ntitle = \"one\"\nrun = \"true\"\n\n[[step]]\nask = \"pass\"\nprompt = \"The portal's password\"\nsecret = true\n\n[[step]]\nrun = \"use '{{pass}}'\"\n",
            ),
        );
        key(&mut s, KeyCode::Enter);
        s.step_started(1, 2);
        assert!(s.step_ended(0).is_empty());
        assert_eq!(s.phase, Phase::Value);
        let fx = key(&mut s, KeyCode::Esc);
        assert_eq!(s.phase, Phase::Settled(End::Waited));
        let Some(Fx::Log { ok, body, .. }) = fx.first() else {
            panic!("{fx:?}")
        };
        assert!(
            !ok && body.contains("Waiting for a value only I have: The portal's password"),
            "{body}"
        );
        assert!(
            !fx.iter()
                .any(|f| matches!(f, Fx::Command { .. } | Fx::Wait { .. }))
        );
    }

    #[test]
    fn auto_answers_a_session_only_if_it_would_on_every_target_it_touches() {
        // This machine and a server: a plan with steps on both is approved by auto.
        let mut s = session();
        s.in_system(
            peer("", "laptop"),
            vec![peer("srv:myserver", "myserver"), router()],
        );
        s.auto = true;
        s.away_ok.insert("srv:myserver".into());
        let fx = s.auto_go();
        answer(
            &mut s,
            &fx,
            &plan("[[step]]\nrun = \"true\"\n\n[[step]]\non = \"srv:myserver\"\nrun = \"true\"\n"),
        );
        assert!(!s.auto_go().is_empty());
        assert_eq!(s.phase, Phase::Applying);
        // A step on the router: never, wherever the session started and auto is on.
        let mut s = session();
        s.in_system(
            peer("", "laptop"),
            vec![peer("srv:myserver", "myserver"), router()],
        );
        s.auto = true;
        let fx = s.auto_go();
        answer(
            &mut s,
            &fx,
            &plan("[[step]]\nrun = \"true\"\n\n[[step]]\non = \"net:home\"\nrun = \"apk add x\"\n"),
        );
        assert!(s.can_approve() && s.auto_go().is_empty());
        assert_eq!(s.phase, Phase::Review);
        assert!(
            s.chat
                .entries
                .last()
                .unwrap()
                .1
                .contains("has to do with home, a host reached as root")
        );
        // Having read the router counts too: what it prints is other people's text.
        let mut s = session();
        s.in_system(peer("", "laptop"), vec![router()]);
        s.auto = true;
        let fx = s.auto_go();
        s.chat.begin_quiet(1, 7);
        s.chat
            .entries
            .push((Kind::Tool, "sentry-x exec home -- uci show dhcp".into()));
        s.chat.on_event(Event::Text(plan(CHECKS)));
        let _ = fx;
        s.turn_ended(0, &[]);
        assert!(s.can_approve() && s.auto_go().is_empty());
        // A step that waited too long for a busy target is told to Claude as what
        // happened: no fix round is spent.
        let mut s = on_router();
        let fx = key(&mut s, KeyCode::Enter);
        answer(
            &mut s,
            &fx,
            &plan("[[step]]\ntitle = \"there\"\non = \"srv:myserver\"\nrun = \"true\"\n"),
        );
        key(&mut s, KeyCode::Enter);
        let fixes = s.fixes;
        let fx = s.step_deferred("myserver was still busy with its workflow os-update after 120 s");
        assert!(
            sent(&fx).contains("did not fail: it was never started"),
            "{}",
            sent(&fx)
        );
        assert_eq!((s.fixes, s.phase), (fixes, Phase::Thinking(Turn::Fix)));
    }
}

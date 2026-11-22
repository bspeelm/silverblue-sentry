//! This machine as a target of the app (`sentry_app::Target`): what only it has. Its fetches
//! and store, its screens and their effects, jobs, cleanup, Flatpaks, toolboxes, the
//! deployments and rollback, the local audit, quick-update and what's still waiting after
//! it, host bash commands, its workflow session and how a plan starts one. Everything else
//! (sessions, series, reviews, records, the workflow run's flow, the frame) is the app's.
//! `upkeep` holds what its maintenance lists hold and what Claude is asked and allowed.

use std::any::Any;
use std::collections::BTreeMap;
use std::process::ExitStatus;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Color;

mod upkeep;

use super::SCREENS;
use super::app::{self as local, BaselineEdit};
use super::data::{Data, DataStore, Fetch, Payload};
use super::screens::maint::Sub;
use super::screens::{Screens, View};
use super::wf::{self, Session};
use crate::config::Config;
use crate::exec::{Cmd, ExecError, StreamMsg};
use crate::fmt;
use sentry_app::effect::{self, Effect, OwnPrompt, Suspend, WfCmd};
use sentry_app::run::{Exec, How, LogKind, WfRun};
use sentry_app::shared::Shared;
use sentry_app::target::{Cx, Hints, Host, Ident, Mail, Settle, TabInfo, Target, Ways, Why};
use sentry_core::tui::ScreenId;
use sentry_core::tui::keys::Action;
use sentry_core::workflows::Entry;

/// What the target asks of itself, on its way through the app (`Effect::Own`) beside the
/// screens' own effects.
enum Own {
    /// `:workflow <name>`, a recommendation, a series' row: Upgrade's Enter on it.
    StartWf(String),
    /// The audit report, over Maintenance (`:audit`).
    OpenReport,
    /// The terminal is back from a command: what to do then.
    After(Vec<local::Effect>),
    /// A pane's command ended: what's read again, said and logged.
    PaneEnd {
        title: String,
        then: Vec<Fetch>,
        ok_toast: String,
        log: Option<(String, Vec<String>)>,
    },
    /// The run is looked at again (after the reboot command returned).
    WfRefresh,
}

fn own(o: Own) -> effect::Own {
    effect::Own(Rc::new(o))
}

/// A screen's effects as the app's: what the app does for every target is handed on, the
/// rest comes back to this target (`on_own`).
pub fn lifted(e: Vec<local::Effect>) -> Vec<Effect> {
    e.into_iter().map(lift).collect()
}

fn lift_modal(m: local::Modal) -> effect::Modal {
    effect::Modal {
        title: m.title,
        color: m.color,
        lines: m.lines,
        yes: m.yes.map(|(word, e)| (word, lifted(e))),
    }
}

fn lift(e: local::Effect) -> Effect {
    use local::Effect as L;
    match e {
        L::Toast(s) => Effect::Toast(s),
        L::Confirm(m) => Effect::Confirm(lift_modal(m)),
        L::Choose(c) => Effect::Choose(effect::Choice {
            title: c.title,
            lines: c.lines,
            options: c
                .options
                .into_iter()
                .map(|(word, e)| (word, lifted(e)))
                .collect(),
        }),
        L::Goto(id) => Effect::Goto(id),
        L::AskConsent(ask) => Effect::AskConsent(Box::new(ask)),
        L::StartWorkflow(name) => Effect::StartWorkflow(name),
        L::LogOpen => Effect::LogOpen(None),
        L::Everything => Effect::Everything,
        L::SeriesStart(rows) => Effect::SeriesStart(rows),
        L::PlanOpen(wf) => Effect::PlanOpen(wf),
        L::PlanApply(wf) => Effect::PlanApply(wf),
        L::PlanAgain(wf) => Effect::PlanAgain(wf),
        L::ReviewOpen => Effect::ReviewOpen,
        L::TaskRemove(id) => Effect::TaskRemove(id),
        L::TaskDone(id) => Effect::TaskDone(id),
        L::LogEvent(e) => Effect::LogEvent(e),
        L::Prompt(local::Prompt::TaskEvery(id), init) => {
            Effect::Prompt(effect::Prompt::TaskEvery(id), init)
        }
        L::Prompt(p, init) => Effect::Prompt(own_prompt(p, &init), init),
        L::Run(spec) => run_spec(spec, None),
        L::RunRoot(spec, line) => run_spec(spec, Some(line)),
        L::Suspend(cmd) => suspend(cmd, Vec::new()),
        L::Interactive(cmd, then) => suspend(cmd, then),
        L::Wf(c) => match c {
            local::WfCmd::Arm => Effect::Wf(WfCmd::Arm),
            local::WfCmd::Begin(name, vars) => Effect::Wf(WfCmd::BeginWith(name, vars)),
            local::WfCmd::Go => Effect::Wf(WfCmd::Go),
            local::WfCmd::Skip => Effect::Wf(WfCmd::Skip(false)),
            local::WfCmd::SkipAnyway => Effect::Wf(WfCmd::Skip(true)),
            local::WfCmd::Retry => Effect::Wf(WfCmd::Retry),
            local::WfCmd::Done => Effect::Wf(WfCmd::Done),
            local::WfCmd::Abandon => Effect::Wf(WfCmd::Abandon),
            // What the run takes from this machine alone.
            c @ (local::WfCmd::SkipDry
            | local::WfCmd::Rollback
            | local::WfCmd::OpenLog
            | local::WfCmd::Scroll(_)) => Effect::Wf(WfCmd::Own(effect::Own(Rc::new(c)))),
            // Checked, or carried out, here first.
            c @ (local::WfCmd::Close | local::WfCmd::Edit(_)) => Effect::own(L::Wf(c)),
        },
        other => Effect::own(other),
    }
}

/// A command for the pane (`root`: the line with sudo in it that runs in its place).
fn run_spec(spec: local::RunSpec, root: Option<String>) -> Effect {
    Effect::Run(effect::RunSpec {
        title: spec.title.clone(),
        cmd: spec.cmd,
        then: Vec::new(),
        reboot: false,
        queue: spec.queue,
        end: Some(own(Own::PaneEnd {
            title: spec.title,
            then: spec.then,
            ok_toast: spec.ok_toast,
            log: spec.log,
        })),
        root,
    })
}

/// One of this machine's prompts, as the app holds it.
/// `init`: what the line starts with (a value's default).
fn own_prompt(p: local::Prompt, init: &str) -> effect::Prompt {
    effect::Prompt::Own(OwnPrompt {
        label: p.label(),
        enter: "save",
        workflow: match &p {
            local::Prompt::WfVar { workflow, .. } => Some(workflow.clone()),
            _ => None,
        },
        defaults: match &p {
            local::Prompt::WfVar { rest, .. } => {
                !init.is_empty() && rest.iter().all(|(_, _, d)| !d.is_empty())
            }
            _ => false,
        },
        own: effect::Own(Rc::new(p)),
    })
}

/// Hand the terminal to `cmd` (its command line above it); `then` follows when it's back.
fn suspend(cmd: Cmd, then: Vec<local::Effect>) -> Effect {
    Effect::Suspend(Suspend {
        banner: format!("$ {}", cmd.display()),
        cmd,
        then: Vec::new(),
        own: Some(own(Own::After(then))),
    })
}

fn kill(pid: u32) -> std::io::Result<()> {
    let pid = rustix::process::Pid::from_raw(pid as i32)
        .ok_or_else(|| std::io::Error::other("bad pid"))?;
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).map_err(std::io::Error::from)
}

/// The transcript's one line for a first question (the whole of it is in the brief).
fn first_sentence(ask: &crate::claude::Ask) -> String {
    match ask.question.split_once(". ") {
        Some((first, _)) if ask.target.is_some() => format!("{first}."),
        _ => ask.question.clone(),
    }
}

/// This program's words for the prompts the app asks.
fn label(p: &effect::Prompt) -> Option<(String, &'static str)> {
    use effect::Prompt as P;
    let label = match p {
        P::LogNote(e) => format!(
            "{} {} · for the log, what to know next time (optional): ",
            e.head.workflow, e.head.result
        ),
        P::LogAddNote(e) => format!("a note for {}: ", e.file_name()),
        _ => return None,
    };
    Some((label, "save"))
}

/// What kind of change a workflow makes, for the log.
fn log_kind(workflow: &str) -> &'static str {
    let w = workflow.to_ascii_lowercase();
    if w.contains("rebase") || w.contains("release") {
        "rebase"
    } else if w.contains("kmod") || w.contains("nvidia") || w.contains("akmod") {
        "kmod"
    } else if w.contains("update") || w.contains("upgrade") {
        "os-update"
    } else {
        "system"
    }
}

struct Sched {
    sys: Instant,
    counts: Instant,
    gpu: Instant,
    slow: Instant,
    procs: Instant,
    net: Instant,
}

pub struct LocalTarget {
    ident: Ident,
    cfg: Arc<Config>,
    mail: Mail,
    pub data: DataStore,
    pub screens: Screens,
    sched: Sched,
    last_minute: i64,
    /// The OS version booted when the run began.
    wf_from: Option<String>,
    /// The ready plan the run applies (by its workflow).
    wf_plan: Option<String>,
    /// The audit after a finding's plan (its stream).
    pub(super) reaudit: Option<u64>,
}

fn view_of<'a>(d: &'a DataStore, cfg: &'a Config, sh: &'a Shared, cx: &Cx<'a>) -> View<'a> {
    View {
        d,
        sh,
        cfg,
        t: cx.theme,
        filter: cx.filter.filter(|s| !s.is_empty()),
        wf: cx.run.and_then(|r| r.as_any().downcast_ref::<Session>()),
        everything: cx.everything,
        auto: cx.auto,
        target: cx.target,
    }
}

impl LocalTarget {
    /// This machine's id as a target, and the key of its records.
    pub const ID: &'static str = crate::maint::LOCAL;

    pub fn new(cfg: Config, mail: Mail) -> Self {
        Self::with(cfg, DataStore::new(), mail)
    }

    pub fn with(cfg: Config, data: DataStore, mail: Mail) -> Self {
        let now = Instant::now();
        let privacy = crate::claude::allowlist_summary();
        Self {
            ident: Ident {
                id: Self::ID.to_string(),
                title: format!("silverblue {}", data.os_version),
                scope: Self::ID.to_string(),
                place: "this machine",
                word: "local",
                app: "sentry",
                screens: &SCREENS,
                runs: crate::workflows::state::root(),
                wf_dir: "~/.config/sentry/workflows/".into(),
                ways: Ways {
                    no_claude: "Claude Code not found (expected ~/.local/bin/claude)",
                    auto_polled: false,
                    reboot_ends_tui: true,
                    resume_opens_run: false,
                    workflows_at_start: false,
                    docs_keep_run_key: false,
                    review_over_plan: false,
                    label,
                    typed: |_, _| None,
                    not_started: None,
                    noted: "noted in the maintenance log (v opens it)",
                    task_note: true,
                    log_task_title: true,
                    plans_by_hand: false,
                    log_item_tag: false,
                    plan_done_says: false,
                    no_plan: Some(|wf| {
                        format!("no plan saved for {wf} yet: A → 1 works it out with Claude")
                    }),
                    plan_hints: &[
                        ("Enter", "apply"),
                        ("A", "claude"),
                        ("P", "start over"),
                        ("x", "drop"),
                        ("j/k", "scroll"),
                        ("Esc", "back"),
                    ],
                    plan_stopped: "stopped",
                    series_waits_writer: false,
                    series_closes_plan: false,
                    audit_in_pane: true,
                    server_changes: false,
                    due_counts_audit: true,
                    writer_place: "machine",
                    first_shown: first_sentence,
                    offline_turns_live: true,
                    needs_you: " needs you · the plan carries on when its run ends (A shows it)",
                    exit_kills_run: false,
                    exit_kills_session: true,
                    run_checks: false,
                    log_kept: true,
                    pane_lines: 2000,
                    pane_took: true,
                    pane_failed: ("", 127),
                    pane_kill: Some("sent SIGTERM"),
                    pane_busy: "still running — Ctrl-C terminates",
                    pane_clamp: false,
                },
                quit: "Quit sentry? Nothing keeps running after exit.".into(),
                help_globals: &[],
                commands: ":q  :<screen>  :job <name>  :workflow <name>  :refresh",
                help_footer: "Nothing runs in the background after sentry exits.".into(),
                // What a session's Claude may do here (as a session says it itself).
                session_privacy: crate::claude::acting_summary(),
                privacy,
            },
            cfg: Arc::new(cfg),
            mail,
            data,
            screens: Screens::default(),
            sched: Sched {
                sys: now,
                counts: now,
                gpu: now,
                slow: now,
                procs: now,
                net: now,
            },
            last_minute: 0,
            wf_from: None,
            wf_plan: None,
            reaudit: None,
        }
    }

    fn fetch(&mut self, f: Fetch) {
        self.data.fetch(f, &self.cfg, &self.mail);
    }

    fn view<'a>(&'a self, sh: &'a Shared, cx: &Cx<'a>) -> View<'a> {
        view_of(&self.data, &self.cfg, sh, cx)
    }

    /// The view a flow reads the lists with: everything, whatever is filtered or hidden.
    fn view_all<'a>(&'a self, sh: &'a Shared, cx: &Cx<'a>) -> View<'a> {
        View {
            filter: None,
            everything: true,
            ..self.view(sh, cx)
        }
    }

    /// Every task that applies: `tasks.toml`'s and the jobs' cadences.
    #[cfg(test)]
    pub fn all_tasks(&self, sh: &Shared) -> Vec<crate::maint::tasks::Task> {
        crate::maint::tasks::effective(&sh.tasks, crate::jobs::state::tasks(&self.cfg))
    }

    fn hz(v: f32) -> Duration {
        Duration::from_secs_f32(1.0 / v.clamp(0.1, 10.0))
    }

    fn booted_version(&self) -> Option<String> {
        let o = self.data.ostree.value.as_ref()?;
        o.booted().map(|d| d.version.clone())
    }

    /// When the audit last ran.
    fn audited(&self) -> Option<jiff::Timestamp> {
        self.data
            .reports
            .get()
            .and_then(|r| r.last())
            .map(|s| s.report.taken_at)
    }

    /// What quick-update changed shows at once: what's still waiting is checked again, since
    /// the counts on disk are from before the run.
    fn recheck_updates(&mut self) {
        for f in [
            Fetch::Ostree,
            Fetch::Flatpak,
            Fetch::OstreeCheck,
            Fetch::FlatpakUpdates,
            Fetch::ToolboxUpdates,
        ] {
            self.fetch(f);
        }
    }

    fn visible_tabs(&self, screen: ScreenId) -> Vec<ScreenId> {
        // History only appears once the recorder has produced data (spec §11); `H` still opens it.
        let has_rec = crate::recorder::ring::path(crate::maint::LOCAL).exists();
        SCREENS
            .ids
            .iter()
            .copied()
            .filter(|s| *s != ScreenId::Hist || has_rec || screen == ScreenId::Hist)
            .collect()
    }

    fn badge(&self, id: ScreenId, sh: &Shared, cx: &Cx) -> Option<(String, Color)> {
        let t = cx.theme;
        let v = self.view(sh, cx);
        match id {
            ScreenId::Maint => {
                let (n, level) = super::screens::maint::badge(&v)?;
                Some((
                    format!(" {n}"),
                    super::screens::maint::level_color(t, level),
                ))
            }
            ScreenId::Cont => {
                let n = crate::collectors::toolbox::total(&self.data.tbx_waiting(&sh.log)?.data);
                (n > 0).then(|| (format!(" {n}"), t.yellow))
            }
            ScreenId::Net => {
                let n = self.data.net.get().map_or(0, |n| {
                    n.listeners
                        .iter()
                        .filter(|l| l.status == crate::collectors::net::ListenStatus::New)
                        .count()
                });
                (n > 0).then(|| (format!(" {n}"), t.red))
            }
            ScreenId::Upgrade => match cx.run.filter(|s| !s.done()) {
                Some(_) => Some((" ●".into(), t.yellow)),
                // Updates waiting: quick-update has something to do.
                None => {
                    super::screens::upgrade::updates_waiting(&v).map(|_| (" ↑".into(), t.yellow))
                }
            },
            _ => None,
        }
    }

    /// `:workflow <name>` and whatever else starts one by name: Upgrade's Enter on it.
    fn start_wf(&mut self, name: &str, sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        if cx.run.is_some_and(|s| !s.done()) {
            return vec![Effect::Toast("a workflow is already in progress".into())];
        }
        // The list loads in the background on entry; this needs it now (a few small files).
        let infos = super::screens::upgrade::load_infos();
        let Some(i) = infos.iter().position(|w| w.entry.name == name) else {
            return vec![Effect::Toast(format!(
                "no workflow {name} in ~/.config/sentry/workflows"
            ))];
        };
        self.took_workflows(&infos, sh);
        self.data.workflows.set(Ok(infos));
        self.screens.select_workflow(i);
        let v = View {
            filter: None,
            ..view_of(&self.data, &self.cfg, sh, cx)
        };
        lifted(self.screens.handle(ScreenId::Upgrade, Action::Enter, &v))
    }

    /// The workflows as read: the app checks a plan's steps against them.
    fn took_workflows(&self, infos: &[super::screens::upgrade::WfInfo], sh: &mut Shared) {
        sh.wf_entries = infos.iter().map(|i| i.entry.clone()).collect();
        sh.workflows = sh.wf_entries.iter().map(|e| e.name.clone()).collect();
    }

    fn baseline(&mut self, edit: &BaselineEdit, sh: &mut Shared) -> Vec<Effect> {
        use crate::baseline::BaselineFile;
        let (r, label) = match edit {
            BaselineEdit::Listener(k) => (
                BaselineFile::add_listener(crate::maint::LOCAL, k),
                k.clone(),
            ),
            BaselineEdit::Listeners(v) => (
                v.iter().try_fold(false, |any, k| {
                    BaselineFile::add_listener(crate::maint::LOCAL, k).map(|added| any | added)
                }),
                format!("{} address(es)", v.len()),
            ),
            BaselineEdit::Finding(k) => {
                (BaselineFile::add_finding(crate::maint::LOCAL, k), k.clone())
            }
        };
        let say = match r {
            Ok(true) => {
                self.data.baseline = crate::baseline::Baseline::effective(&self.cfg);
                if !matches!(edit, BaselineEdit::Finding(_)) {
                    self.fetch(Fetch::Net);
                }
                format!("{label} marked expected (baseline.toml)")
            }
            Ok(false) => format!("{label} is already in the baseline"),
            Err(e) => format!("baseline.toml: {e}"),
        };
        sh.baseline = BaselineFile::load(crate::maint::LOCAL);
        vec![Effect::Toast(say)]
    }

    fn unbaseline(&mut self, edit: &BaselineEdit, sh: &mut Shared) -> Vec<Effect> {
        use crate::baseline::BaselineFile;
        let (r, label) = match edit {
            BaselineEdit::Listener(k) => (
                BaselineFile::remove_listeners(crate::maint::LOCAL, std::slice::from_ref(k)),
                k.clone(),
            ),
            BaselineEdit::Listeners(v) => (
                BaselineFile::remove_listeners(crate::maint::LOCAL, v),
                format!("{} address(es)", v.len()),
            ),
            BaselineEdit::Finding(k) => (
                BaselineFile::remove_finding(crate::maint::LOCAL, k),
                k.clone(),
            ),
        };
        self.data.baseline = crate::baseline::Baseline::effective(&self.cfg);
        sh.baseline = BaselineFile::load(crate::maint::LOCAL);
        let still = match edit {
            BaselineEdit::Listener(k) => self.data.baseline.has_listener(k),
            BaselineEdit::Listeners(v) => v.iter().any(|k| self.data.baseline.has_listener(k)),
            BaselineEdit::Finding(k) => self
                .data
                .baseline
                .findings
                .iter()
                .any(|p| crate::baseline::glob(p, k)),
        };
        let say = match r {
            Err(e) => format!("baseline.toml: {e}"),
            Ok(_) if still => format!(
                "{label}: still expected by an entry in config.toml [baseline] (edit it there)"
            ),
            Ok(0) => format!("{label} wasn't marked expected"),
            Ok(n) => format!(
                "{label} no longer expected ({n} baseline.toml entr{} removed)",
                if n == 1 { "y" } else { "ies" }
            ),
        };
        if !matches!(edit, BaselineEdit::Finding(_)) {
            self.fetch(Fetch::Net);
        }
        vec![Effect::Toast(say)]
    }

    /// One of the screens' effects that only this machine carries out.
    fn on_local(&mut self, e: &local::Effect, sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        use local::Effect as L;
        let toast = |s: String| vec![Effect::Toast(s)];
        match e {
            L::Fetch(f) => {
                self.fetch(*f);
                Vec::new()
            }
            L::Detach(cmd, msg) => match cmd.detach() {
                Ok(()) => toast(msg.clone()),
                Err(e) => toast(format!("{}: {e}", cmd.bin())),
            },
            L::Kill(pid, msg) => match kill(*pid) {
                Ok(()) => {
                    self.sched.procs = cx.at;
                    toast(msg.clone())
                }
                Err(e) => toast(format!("kill {pid}: {e}")),
            },
            L::Baseline(edit) => self.baseline(edit, sh),
            L::Unbaseline(edit) => self.unbaseline(edit, sh),
            L::ChatBack => vec![Effect::ChatNote("back from Claude Code".into())],
            L::CleanupFocus(job) => {
                self.screens.focus_cleanup(*job);
                vec![Effect::Goto(ScreenId::Clean)]
            }
            L::MaintFind(prefix) => {
                self.screens.find_maint(prefix);
                vec![Effect::Goto(ScreenId::Maint)]
            }
            L::Snooze(key, days) => {
                let today = jiff::Zoned::now().date();
                let until = today
                    .checked_add(jiff::Span::new().days(*days))
                    .unwrap_or(today);
                if !cx.offline
                    && let Err(e) = crate::maint::later::set(crate::maint::LOCAL, key, until, today)
                {
                    toast(format!("couldn't save it: {e}"))
                } else {
                    sh.later.insert(key.clone(), until);
                    toast(format!("put off until {until} (Records › Later)"))
                }
            }
            // Only a run that's over is closed.
            L::Wf(local::WfCmd::Close) => {
                if cx.run.is_some_and(|s| s.done()) {
                    self.fetch(Fetch::Workflows);
                    vec![Effect::Wf(WfCmd::Close)]
                } else {
                    Vec::new()
                }
            }
            L::Wf(local::WfCmd::Edit(path)) => {
                let editor = std::env::var("VISUAL")
                    .or_else(|_| std::env::var("EDITOR"))
                    .unwrap_or_else(|_| "nano".into());
                let mut parts = editor.split_whitespace();
                let bin = parts.next().unwrap_or("nano").to_string();
                let cmd = Cmd::local(&bin)
                    .args(parts.map(str::to_string))
                    .arg(path.as_os_str())
                    .timeout(None);
                self.fetch(Fetch::Workflows);
                vec![suspend(cmd, Vec::new())]
            }
            // The app's own: never sent back here.
            _ => Vec::new(),
        }
    }

    /// A pane's command ended.
    fn pane_end(
        &mut self,
        title: &str,
        then: &[Fetch],
        ok_toast: &str,
        log: &Option<(String, Vec<String>)>,
        code: i32,
        tail: &[String],
    ) -> Vec<Effect> {
        let mut fx = Vec::new();
        for f in then {
            self.fetch(*f);
        }
        if let Some((kind, tags)) = log {
            fx.push(Effect::LogEvent(Box::new(
                crate::maint::log::LogEntry::event(
                    crate::maint::LOCAL,
                    kind,
                    kind,
                    code == 0,
                    &format!("{title} (exit {code})\n\n```\n{}\n```", tail.join("\n")),
                    tags,
                    jiff::Timestamp::now(),
                ),
            )));
        }
        fx.push(Effect::Toast(if code == 0 {
            ok_toast.to_string()
        } else {
            format!("{title} failed (exit {code})")
        }));
        // A series may be waiting for the audit.
        fx.push(Effect::AuditEnded(code == 0));
        fx
    }

    fn open_maint_view(&mut self, s: Sub) -> Vec<Effect> {
        self.screens.maint.open(s);
        Vec::new()
    }
}

impl Target for LocalTarget {
    fn ident(&self) -> &Ident {
        &self.ident
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn start(&mut self, _sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        // State files only (cheap): the dashboard Status panel and tab badges need them.
        self.fetch(Fetch::Reports);
        self.fetch(Fetch::Log);
        // What a review at start is told about.
        if !cx.offline && self.cfg.review.at_start && crate::claude::available() {
            self.fetch(Fetch::Ostree);
        }
        Vec::new()
    }

    fn enter(&mut self, from: ScreenId, now: Instant, sh: &Shared, cx: &Cx) -> Vec<Effect> {
        let id = cx.screen;
        // Coming back to Maintenance from another screen shows its list, not a view left open.
        if id == ScreenId::Maint && from != id {
            self.screens.maint.view = None;
        }
        match id {
            ScreenId::Dash => {
                // Second CPU sample shortly after the first so the bars aren't empty for 1 s.
                self.sched.sys = now;
                self.sched.counts = now;
                self.sched.gpu = now;
                self.sched.slow = now;
            }
            ScreenId::Proc => self.sched.procs = now,
            ScreenId::Net => self.sched.net = now,
            _ => {}
        }
        lifted(self.screens.on_enter(id, &self.view(sh, cx)))
    }

    fn due(&mut self, now: Instant, cx: &Cx) -> bool {
        // Only while this machine has the window: out of view nothing is sampled or fetched
        // for a screen, and nothing of it is drawn.
        if !cx.focused {
            return false;
        }
        let mut dirty = false;
        let first_sample = self.data.sys.is_none();
        match cx.screen {
            ScreenId::Dash => {
                if now >= self.sched.sys {
                    self.data.sample_system();
                    self.sched.sys = now
                        + if first_sample {
                            Duration::from_millis(300)
                        } else {
                            Self::hz(self.cfg.ui.dashboard_hz)
                        };
                    dirty = true;
                }
                if now >= self.sched.counts {
                    self.data.sample_counts();
                    self.sched.counts = now + Duration::from_secs(5);
                }
                if now >= self.sched.gpu {
                    self.fetch(Fetch::Gpu);
                    self.sched.gpu = now + Duration::from_secs(5);
                }
                if now >= self.sched.slow {
                    for f in [Fetch::Disks, Fetch::Units, Fetch::Ostree] {
                        self.fetch(f);
                    }
                    self.data.recorder = crate::recorder::live();
                    self.sched.slow = now + Duration::from_secs(60);
                }
            }
            ScreenId::Proc if now >= self.sched.procs => {
                let first = self.data.procs.is_empty();
                self.data.sample_procs();
                self.sched.procs = now
                    + if first {
                        Duration::from_millis(300)
                    } else {
                        Self::hz(self.cfg.ui.processes_hz)
                    };
                dirty = true;
            }
            ScreenId::Net if now >= self.sched.net => {
                self.fetch(Fetch::Net);
                self.sched.net = now + Duration::from_secs(3);
            }
            _ => {}
        }
        // The clock in the top bar.
        let minute = jiff::Timestamp::now().as_second() / 60;
        if minute != self.last_minute {
            self.last_minute = minute;
            dirty = true;
        }
        // What shows time passing: a command in the pane, Claude answering, a step running.
        dirty
            || cx.pane == Some(true)
            || cx.chat_running
            || cx.run.is_some_and(|s| s.live().is_some())
    }

    fn next_due(&self, now: Instant, cx: &Cx) -> Option<Instant> {
        // Out of view nothing here sets a time (a run's own limits are the app's).
        if !cx.focused {
            return None;
        }
        let mut due =
            now + Duration::from_secs(60 - (jiff::Timestamp::now().as_second() % 60) as u64);
        let mut at = |t: Instant| due = due.min(t);
        match cx.screen {
            ScreenId::Dash => {
                at(self.sched.sys);
                at(self.sched.counts);
                at(self.sched.gpu);
                at(self.sched.slow);
            }
            ScreenId::Proc => at(self.sched.procs),
            ScreenId::Net => at(self.sched.net),
            _ => {}
        }
        if cx.pane == Some(true) {
            at(now + Duration::from_secs(1));
        }
        if cx.run.is_some_and(|s| s.live().is_some()) || cx.chat_running {
            at(now + Duration::from_millis(250));
        }
        Some(due)
    }

    fn on_data(&mut self, data: Box<dyn Any + Send>, sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        let Ok(data) = data.downcast::<Data>() else {
            return Vec::new();
        };
        let Data(f, r) = *data;
        let mut r = *r;
        let mut fx = Vec::new();
        if let Err(e) = &r
            && matches!(
                f,
                Fetch::OstreeCheck
                    | Fetch::FlatpakUpdates
                    | Fetch::ToolboxUpdates
                    | Fetch::Breakdown
                    | Fetch::Reports
                    | Fetch::Plan(_)
                    | Fetch::Cleanup
            )
        {
            fx.push(Effect::Toast(e.text()));
        }
        // The log is the app's record.
        if let Ok(Payload::Log(v)) = &mut r {
            sh.log = std::mem::take(v);
        }
        if let (Fetch::Workflows, Ok(Payload::Workflows(infos))) = (f, &r) {
            self.took_workflows(infos, sh);
        }
        self.data.apply(f, r);
        // What a review at start is told about has been read: the deployments and the audit
        // reports (and the log isn't on its way).
        if self.data.ostree.get().is_some()
            && self.data.reports.get().is_some()
            && !self.data.loading(Fetch::Log)
        {
            fx.push(Effect::Loaded);
        }
        // An update check is the update-check job: its run is in the log now.
        if f == Fetch::OstreeCheck {
            self.fetch(Fetch::Log);
        }
        if let Fetch::Plan(job) = f
            && let Some(p) = self.data.plan.take()
            && !cx.modal
            && cx.pane.is_none()
        {
            fx.push(Effect::Confirm(lift_modal(
                super::screens::jobs::plan_modal(cx.theme, job, &p),
            )));
        }
        fx
    }

    /// The audit after a finding's plan: is the finding gone?
    fn on_stream(&mut self, id: u64, m: &StreamMsg, cx: &Cx) -> Option<Vec<Effect>> {
        if self.reaudit != Some(id) {
            return None;
        }
        let StreamMsg::Exit { code, .. } = m else {
            return Some(Vec::new());
        };
        self.reaudit = None;
        let finding = cx.finding.unwrap_or_default();
        let gone = *code == 0
            && !crate::audit::store::latest()
                .is_some_and(|r| r.findings.iter().any(|f| f.id == finding));
        self.fetch(Fetch::Reports);
        self.fetch(Fetch::Log);
        Some(vec![Effect::Reaudited(gone)])
    }

    fn refresh(&mut self, why: Why, cx: &Cx) -> Vec<Effect> {
        match why {
            // The lists are computed from what's loaded; a step's effects show on their
            // screens' own refresh.
            Why::Lists | Why::Step | Why::Edited => {}
            // Keep tabs, dashboard and the workflow list in step with the run.
            Why::Run => self.fetch(Fetch::Workflows),
            Why::Changed => {
                let quick = cx
                    .run
                    .is_some_and(|s| s.wf().name == crate::maint::local::UPDATE_WORKFLOW);
                if quick && !cx.offline {
                    self.recheck_updates();
                }
            }
            Why::Logged => {
                if !cx.offline {
                    crate::maint::retention::purge(
                        crate::maint::LOCAL,
                        &crate::workflows::state::root(),
                        &self.cfg.retention,
                        jiff::Timestamp::now(),
                    );
                }
            }
            // After a finding's plan: the audit, and whether the finding is gone.
            Why::Reaudit => {
                let id = self.mail.next();
                self.reaudit = Some(id);
                if !cx.offline
                    && let Err(e) = self
                        .mail
                        .stream(id, &super::screens::sentry_cmd(&["job", "audit"]))
                {
                    self.reaudit = None;
                    return vec![Effect::Toast(format!("couldn't audit: {e}"))];
                }
            }
            // A series' row: the audit, as a run in the pane.
            Why::Audit => return vec![lift(super::screens::maint::audit_run())],
            Why::Baseline => {
                self.data.baseline = crate::baseline::Baseline::effective(&self.cfg);
                self.fetch(Fetch::Net);
            }
        }
        Vec::new()
    }

    fn on_own(&mut self, fx: &effect::Own, sh: &mut Shared, cx: &Cx) -> Vec<Effect> {
        if let Some(e) = fx.0.downcast_ref::<local::Effect>() {
            return self.on_local(e, sh, cx);
        }
        match fx.0.downcast_ref::<Own>() {
            Some(Own::StartWf(name)) => self.start_wf(name, sh, cx),
            Some(Own::OpenReport) => self.open_maint_view(Sub::Report),
            _ => Vec::new(),
        }
    }

    fn on_prompt(
        &mut self,
        own: &effect::Own,
        answer: Option<&str>,
        _sh: &mut Shared,
        _cx: &Cx,
    ) -> Vec<Effect> {
        let (Some(p), Some(text)) = (own.0.downcast_ref::<local::Prompt>(), answer) else {
            return Vec::new();
        };
        match p.clone() {
            local::Prompt::WfVar {
                workflow,
                key,
                prompt,
                mut rest,
                mut vars,
            } => {
                // Nothing given and no default: asked again, with the rest still to come.
                if text.is_empty() {
                    return vec![
                        Effect::Toast(format!("{key} can't be empty")),
                        Effect::Prompt(
                            own_prompt(
                                local::Prompt::WfVar {
                                    workflow,
                                    key,
                                    prompt,
                                    rest,
                                    vars,
                                },
                                "",
                            ),
                            String::new(),
                        ),
                    ];
                }
                vars.insert(key, text.to_string());
                if rest.is_empty() {
                    return vec![Effect::Wf(WfCmd::BeginWith(workflow, vars))];
                }
                let (key, prompt, default) = rest.remove(0);
                vec![Effect::Prompt(
                    own_prompt(
                        local::Prompt::WfVar {
                            workflow,
                            key,
                            prompt,
                            rest,
                            vars,
                        },
                        &default,
                    ),
                    default,
                )]
            }
            local::Prompt::TaskEvery(_) => Vec::new(),
        }
    }

    fn pane_ended(
        &mut self,
        end: &effect::Own,
        code: i32,
        tail: &[String],
        _sh: &mut Shared,
        _cx: &Cx,
    ) -> Vec<Effect> {
        match end.0.downcast_ref::<Own>() {
            Some(Own::PaneEnd {
                title,
                then,
                ok_toast,
                log,
            }) => self.pane_end(title, then, ok_toast, log, code, tail),
            _ => Vec::new(),
        }
    }

    fn after_suspend(
        &mut self,
        own: &effect::Own,
        status: Result<ExitStatus, ExecError>,
        _sh: &mut Shared,
        _cx: &Cx,
    ) -> Vec<Effect> {
        let Some(Own::After(then)) = own.0.downcast_ref::<Own>() else {
            return Vec::new();
        };
        if then.is_empty() {
            return vec![Effect::Toast(match status {
                Ok(s) if s.success() => "back in sentry".into(),
                Ok(s) => format!("exited with {}", s.code().unwrap_or(-1)),
                Err(e) => e.to_string(),
            })];
        }
        let mut fx = vec![Effect::Toast(match &status {
            Ok(s) if s.success() => "done · checking again".into(),
            Ok(s) => format!("exited with {} · checking again", s.code().unwrap_or(-1)),
            Err(e) => e.to_string(),
        })];
        fx.extend(lifted(then.clone()));
        fx
    }

    fn handle(&mut self, a: Action, sh: &Shared, cx: &Cx) -> Vec<Effect> {
        let v = view_of(&self.data, &self.cfg, sh, cx);
        lifted(self.screens.handle(cx.screen, a, &v))
    }

    fn render(&mut self, f: &mut Frame, area: Rect, sh: &Shared, cx: &Cx) {
        let v = view_of(&self.data, &self.cfg, sh, cx);
        self.screens.render(cx.screen, f, area, &v);
    }

    fn hints(&self, help: bool, sh: &Shared, cx: &Cx) -> Hints {
        let mut hints = self.screens.hints(cx.screen, &self.view(sh, cx));
        // `?` on Maintenance's list: every row key, not only the selected row's.
        if help && cx.screen == ScreenId::Maint && self.screens.maint.view.is_none() {
            let row = ["Enter", "p", "P", "t", "d", "e", "m", "x", "B", "z", "A"];
            hints = super::maintlist::GRAMMAR
                .iter()
                .copied()
                .chain(hints.into_iter().filter(|(k, _)| !row.contains(k)))
                // Not on the key bar, to keep it to what the row takes.
                .chain([
                    ("F", "the audit report"),
                    ("C", "Cleanup (7)"),
                    ("w", "the workflows (0)"),
                ])
                .collect();
        }
        hints
    }

    fn tabs(&self, sh: &Shared, cx: &Cx) -> Vec<TabInfo> {
        self.visible_tabs(cx.screen)
            .into_iter()
            .map(|id| TabInfo {
                id,
                badge: self.badge(id, sh, cx),
                // `/` opens on every screen here.
                filterable: true,
            })
            .collect()
    }

    fn settle(&mut self, why: Settle, _sh: &Shared, cx: &Cx) {
        match why {
            Settle::Filter => self.screens.reset_cursor(cx.screen),
            Settle::Ticks(left) => self.screens.maint.ticks = left.into_iter().collect(),
            Settle::Workflow(i) => self.screens.select_workflow(i),
            // The screens keep their own cursors on what's there when they draw.
            Settle::Key | Settle::Lists | Settle::FilterCleared => {}
        }
    }

    /// The top bar: kernel and uptime; whether this screen samples.
    fn top(&self, cx: &Cx) -> (Vec<String>, (String, Color)) {
        let t = cx.theme;
        let up = self
            .data
            .sys
            .as_ref()
            .map(|s| s.uptime_s)
            .unwrap_or_else(sysinfo::System::uptime);
        let state = match cx.screen {
            ScreenId::Dash => (format!("● live {} Hz", self.cfg.ui.dashboard_hz), t.green),
            ScreenId::Proc => (format!("● live {} Hz", self.cfg.ui.processes_hz), t.green),
            ScreenId::Net => ("● live 3 s".to_string(), t.green),
            _ => ("○ idle".to_string(), t.dim),
        };
        (
            vec![
                format!("kernel {}", self.data.kernel),
                format!("up {}", fmt::uptime(up)),
            ],
            state,
        )
    }

    fn colon(
        &mut self,
        line: &str,
        cmd: &str,
        arg: Option<&str>,
        _sh: &Shared,
        cx: &Cx,
    ) -> Option<Vec<Effect>> {
        use ratatui::crossterm::event::{KeyCode, KeyEvent};
        let toast = |s: String| Some(vec![Effect::Toast(s)]);
        match (cmd, arg) {
            ("refresh" | "r", _) => Some(vec![Effect::Key(KeyEvent::from(KeyCode::Char('r')))]),
            ("help" | "h", _) => Some(vec![Effect::Help]),
            // A job's plan, then a confirm, then it runs (as `sentry job <name>`).
            ("job", Some(name)) => match crate::jobs::JobId::from_name(name) {
                Some(j) => {
                    self.fetch(Fetch::Plan(j));
                    Some(vec![Effect::Goto(ScreenId::Maint)])
                }
                None => toast(format!("unknown job {name}")),
            },
            ("job" | "jobs", None) => Some(vec![
                Effect::Goto(ScreenId::Maint),
                Effect::Toast(":job <name> runs one; due jobs are tasks on Maintenance".into()),
            ]),
            ("audit", None) => Some(vec![
                Effect::Goto(ScreenId::Maint),
                Effect::Own(own(Own::OpenReport)),
            ]),
            ("rollback", None) => match self.data.ostree.get() {
                Some(o) => Some(lifted(super::screens::updates::rollback_effects(
                    cx.theme, o,
                ))),
                None => toast("rpm-ostree status isn't loaded yet".into()),
            },
            // Records' sections take no argument here.
            ("log" | "records" | "rec" | "tasks" | "plans" | "reviews" | "later", Some(_)) => {
                toast(format!("unknown command :{line}"))
            }
            _ => None,
        }
    }
}

impl Host for LocalTarget {
    fn command(&self, line: &str) -> Cmd {
        Cmd::host("bash").args(["-c", line])
    }

    /// `sudo -n true`, now: a ticket from a moment ago counts as not asking. Tests: it asks.
    fn sudo_asks(&mut self, cx: &Cx) -> Result<bool, String> {
        if cx.offline {
            return Ok(true);
        }
        match Cmd::host("sudo").args(["-n", "true"]).run() {
            Ok(o) => Ok(o.code != 0),
            Err(e) => Err(format!("sudo: {e}")),
        }
    }

    fn workflows(&self) -> (Vec<Entry>, std::path::PathBuf) {
        (crate::workflows::list(), crate::workflows::dir())
    }

    /// As the file is now, whatever the list read earlier says.
    fn find_workflow(&self, name: &str) -> Option<Entry> {
        crate::workflows::find(name)
    }

    fn begin_run(
        &mut self,
        entry: &Entry,
        vars: BTreeMap<String, String>,
        sh: &Shared,
    ) -> Result<Box<dyn WfRun>, String> {
        let s = Session::begin(entry, vars).map_err(|e| format!("{e:#}"))?;
        self.wf_from = self.booted_version();
        // However it was started, a ready plan for it is what this run applies.
        self.wf_plan = sh
            .plans
            .get(&entry.name)
            .filter(|p| p.head.status == crate::maint::plan::PlanStatus::Ready)
            .map(|_| entry.name.clone());
        Ok(Box::new(s))
    }

    fn resume_run(&self) -> Option<Box<dyn WfRun>> {
        let s = Session::resume()?;
        Some(Box::new(s))
    }

    fn wf_start(&mut self, name: &str, _sh: &Shared, _cx: &Cx) -> Option<Vec<Effect>> {
        Some(vec![
            Effect::Goto(ScreenId::Upgrade),
            Effect::Own(own(Own::StartWf(name.to_string()))),
        ])
    }

    /// A plan's workflow step: with values, it starts with them; without, as from Upgrade
    /// (its start box, its ready plan).
    fn session_starts(
        &mut self,
        wf: &str,
        vars: &BTreeMap<String, String>,
        _sh: &Shared,
        _cx: &Cx,
    ) -> Option<Vec<Effect>> {
        Some(if vars.is_empty() {
            vec![Effect::StartWorkflow(wf.to_string())]
        } else {
            vec![
                Effect::Goto(ScreenId::Upgrade),
                Effect::Wf(WfCmd::BeginWith(wf.to_string(), vars.clone())),
            ]
        })
    }

    fn run_go(
        &mut self,
        run: &mut dyn WfRun,
        auto: bool,
        _cx: &Cx,
    ) -> Result<Option<Exec>, String> {
        let Some(s) = run.as_any_mut().downcast_mut::<Session>() else {
            return Ok(None);
        };
        let e = if auto { s.auto() } else { s.go()? };
        Ok(e.map(|e| match e {
            wf::Exec::Stream {
                how,
                idx,
                dry,
                timeout,
            } => Exec::Stream {
                how,
                idx,
                dry,
                timeout,
            },
            wf::Exec::Shell { idx } => Exec::Shell { idx },
            wf::Exec::Reboot => Exec::Reboot {
                how: How::Plain(crate::workflows::cli::reboot_cmd()),
            },
        }))
    }

    fn run_cmd(
        &mut self,
        run: &mut dyn WfRun,
        own: &effect::Own,
        _sh: &Shared,
        _cx: &Cx,
    ) -> Result<Vec<Effect>, String> {
        let Some(s) = run.as_any_mut().downcast_mut::<Session>() else {
            return Ok(Vec::new());
        };
        if let Some(Own::WfRefresh) = own.0.downcast_ref::<Own>() {
            s.refresh();
            return Ok(Vec::new());
        }
        match own.0.downcast_ref::<local::WfCmd>() {
            Some(local::WfCmd::SkipDry) => s.skip_dry().map(|_| Vec::new()),
            Some(local::WfCmd::Scroll(d)) => {
                s.scroll = if *d == i32::MIN {
                    0
                } else {
                    (s.scroll as i64 + *d as i64).clamp(0, s.log.len() as i64) as usize
                };
                Ok(Vec::new())
            }
            Some(local::WfCmd::OpenLog) => {
                let id = s
                    .next
                    .idx()
                    .or_else(|| s.wf.steps.len().checked_sub(1))
                    .map(|i| s.wf.steps[i].id.clone());
                let path = id.map(|id| s.run.log_path(&id));
                match path.filter(|p| p.exists()) {
                    Some(p) => Ok(vec![suspend(
                        Cmd::local("less")
                            .args(["-R", "+G"])
                            .arg(p.as_os_str())
                            .timeout(None),
                        Vec::new(),
                    )]),
                    None => Err("no log for this step yet".into()),
                }
            }
            Some(local::WfCmd::Rollback) => {
                let cmds = s.rollback_cmds();
                s.abandon();
                let mut it = cmds.into_iter().map(|(_, c)| c);
                Ok(match it.next() {
                    Some(first) => vec![lift(local::Effect::Run(local::RunSpec {
                        title: "rollback steps".into(),
                        cmd: first,
                        queue: it.collect(),
                        then: vec![Fetch::Ostree, Fetch::Workflows],
                        ok_toast: "rollback steps done · workflow abandoned".into(),
                        log: None,
                    }))],
                    None => Vec::new(),
                })
            }
            _ => Ok(Vec::new()),
        }
    }

    /// This machine's reboot: the command is run here and now (it ends the TUI with the
    /// session; with `SENTRY_NO_REBOOT` it only says what it would do).
    fn reboot(&mut self, cmd: Cmd, _old_boot: String, cx: &Cx) -> Vec<Effect> {
        // Tests never reboot the machine they run on: decided before the command, not after.
        let msg = if cx.offline {
            "offline: not rebooting".to_string()
        } else {
            match cmd.run() {
                Ok(o) => format!("{}{}", o.stdout.trim(), o.stderr.trim()),
                Err(e) => e.to_string(),
            }
        };
        let mut fx = vec![
            Effect::RunNote(msg.clone(), LogKind::Info),
            Effect::Wf(WfCmd::Own(own(Own::WfRefresh))),
        ];
        if !msg.is_empty() {
            fx.push(Effect::Toast(msg));
        }
        fx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::App;
    use crate::tui::app::{Effect, RunSpec};
    use crate::tui::data::DataStore;

    fn sh(script: &str) -> Cmd {
        Cmd::local("sh").args(["-c", script]).timeout(None)
    }

    /// Run `spec` to completion, pumping stream events through the app.
    fn run(spec: RunSpec) -> (Vec<String>, Option<(i32, Duration)>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut a = App::for_test_on(
            tx,
            Config::default(),
            DataStore::blank(String::new(), String::new()),
            ScreenId::Dash,
        );
        a.win.offline = false;
        a.apply_for_test(vec![Effect::Run(spec)]);
        while a.pane_for_test().is_some_and(|(_, done)| done.is_none()) {
            let ev = rx.recv_timeout(Duration::from_secs(5)).expect("event");
            a.on_event(ev, Instant::now());
        }
        let (lines, done) = a.pane_for_test().unwrap();
        (lines, done.map(|code| (code, Duration::ZERO)))
    }

    #[test]
    fn queue_runs_in_order_and_stops_on_failure() {
        let spec = |first: &str| RunSpec {
            title: "t".into(),
            cmd: sh(first),
            queue: vec![sh("echo two"), sh("echo three")],
            then: vec![],
            ok_toast: "ok".into(),
            log: None,
        };
        let (lines, done) = run(spec("echo one"));
        let text = lines.join("|");
        assert!(text.starts_with("one|"), "{text}");
        assert!(
            text.contains("$ echo two|two") && text.ends_with("three"),
            "{text}"
        );
        assert_eq!(done.map(|d| d.0), Some(0));
        let (lines, done) = run(spec("echo bad; exit 3"));
        assert_eq!(lines, vec!["bad"]);
        assert_eq!(done.map(|d| d.0), Some(3));
    }
}

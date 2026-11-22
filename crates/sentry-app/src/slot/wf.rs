use super::*;

impl Slot {
    /// The workflows there are (a host's own, else the seeded ones), with their last runs.
    pub(crate) fn load_wf_entries(&mut self) {
        let (entries, d) = self.target.workflows();
        self.shared.wf_entries = entries;
        self.shared.wf_list = sentry_core::tui::wflist::load_infos(
            self.shared.wf_entries.clone(),
            &self.target.ident().runs,
        );
        self.shared.workflows = self
            .shared
            .wf_entries
            .iter()
            .map(|e| e.name.clone())
            .collect();
        let home = std::env::var("HOME").unwrap_or_default();
        let shown = d.display().to_string();
        self.shared.wf_dir = match shown.strip_prefix(&home) {
            Some(rest) if !home.is_empty() => format!("~{rest}/"),
            _ => format!("{shown}/"),
        };
    }

    /// Why the workflow `name` won't start now, if it won't.
    pub(crate) fn wf_refusal(&mut self, w: &mut Win, name: &str) -> Option<String> {
        if let Some(s) = self.run.as_ref().filter(|s| !s.done()) {
            return Some(format!(
                "{} is in progress: finish or abandon it first",
                s.wf().name
            ));
        }
        if self.shared.wf_entries.is_empty() && !w.offline {
            self.load_wf_entries();
        }
        let Some(e) = self.shared.wf_entries.iter().find(|e| e.name == name) else {
            return Some(format!(
                "no workflow {name} in {}",
                self.shared.wf_dir.trim_end_matches('/')
            ));
        };
        if let Some(why) = e.blocked() {
            return Some(format!("{}: {why}", e.path.display()));
        }
        if w.offline {
            return None;
        }
        sentry_core::workflows::state::in_progress_in(&self.target.ident().runs).map(|cur| {
            format!(
                "{} is already in progress: finish or abandon it first",
                cur.state.workflow
            )
        })
    }

    /// How the workflow the apply session waits for is doing, for its step.
    pub(crate) fn wf_glimpse(&self) -> Vec<String> {
        let Some(name) = self.apply.as_ref().and_then(|s| s.waiting_workflow()) else {
            return Vec::new();
        };
        let Some(s) = self.run.as_ref().filter(|s| s.wf().name == name) else {
            return vec![format!("{name}: waiting to start · Enter opens it")];
        };
        let n = s.wf().steps.len();
        if let Some(l) = s.live() {
            return vec![format!(
                "{name} · step {}/{n}: {}",
                l.idx + 1,
                s.wf().steps[l.idx].title
            )];
        }
        match s.next().idx() {
            Some(i) => vec![format!(
                "{name} · step {}/{n}: {} · it needs you: Enter opens it",
                i + 1,
                s.wf().steps[i].title
            )],
            None => vec![format!("{name} · finishing")],
        }
    }

    /// A workflow run ended: the apply session waiting for it carries on (and shows again).
    pub(crate) fn apply_run_ended(&mut self, w: &mut Win, e: &sentry_core::maint::log::LogEntry) {
        let Some(sess) = self.apply.as_mut() else {
            return;
        };
        let h = &e.head;
        let note = format!("{} {}: {}", h.workflow, h.result, h.summary);
        // What goes back to Claude is what the target lets it see.
        let note = self.target.hides(&note).unwrap_or(note);
        let fx = sess.workflow_ended(&h.workflow, h.result == "done", note);
        if !fx.is_empty() || sess.phase != sentry_core::apply::session::Phase::Applying {
            sess.chat.hidden = false;
        }
        self.apply_fx(w, fx);
    }

    /// When the workflow started from a maintenance item has ended: log the change.
    pub(crate) fn wf_log_change(&mut self, w: &mut Win) {
        let Some(s) = self.run.as_ref().filter(|s| s.done()) else {
            return;
        };
        if self.wf_logged.as_ref() == Some(&s.run().dir) {
            return;
        }
        use sentry_core::workflows::state::RunStatus;
        let done = s.run().state.status == RunStatus::Done;
        // Auto asks for no note after a run (in a series nobody is asked anyway): the entry
        // says so.
        let no_note = self.auto_skips_note();
        if no_note
            && self.series.is_none()
            && let Some(s) = self.run.as_mut()
        {
            s.auto_answered("note");
        }
        // What the run changed shows at once: the target reads again what a run can change.
        self.refresh(w, Why::Run);
        let Some(s) = self.run.as_ref() else { return };
        self.wf_logged = Some(s.run().dir.clone());
        use sentry_core::maint::{log, plan};
        let change = self.wf_change.take();
        // A plan carried out is done with (it moves to plans/done/); an abandoned run leaves it.
        let mut plan_path = None;
        if let Some(key) = self.target.run_plan(&**s, change.as_ref())
            && done
            && let Some(doc) = self.shared.plans.remove(&key)
        {
            plan_path = if w.offline {
                Some(plan::path(&self.scope, &key))
            } else {
                plan::close(&doc, PlanStatus::Done).ok()
            };
        }
        let info = self.target.run_info(&**s, change.as_ref(), plan_path);
        let mut entry = log::LogEntry::from_run(
            &self.scope,
            s.wf(),
            &s.run().state,
            &s.run().dir,
            info.as_ref(),
            None,
        );
        sentry_core::maint::tasks::tag_run(&mut entry, &self.all_tasks());
        let entry = self.kept_entry(entry);
        self.apply_run_ended(w, &entry);
        self.guest_run_ended(w, &entry);
        if !w.offline {
            if let Err(e) = log::write(&entry) {
                w.toast(&format!("couldn't write the maintenance log: {e}"));
            }
            self.shared.log = log::list(&self.scope);
            self.refresh(w, Why::Lists);
            self.refresh(w, Why::Logged);
        } else if self.ways.log_kept {
            // Tests write nothing, but what's done is still read from the log: one entry
            // per run, newest first.
            self.shared
                .log
                .retain(|e| e.head.run.is_none() || e.head.run != entry.head.run);
            self.shared.log.insert(0, entry.clone());
        }
        if done {
            self.review_run = Some(entry.clone());
            self.last_change_at = Some(jiff::Timestamp::now());
            self.refresh(w, Why::Changed);
        }
        // In a series nothing is asked between its rows: the note can be added in Records;
        // what the target offers after a run and the one review come at its end.
        if self.series_run_ended(w, &entry.head.workflow, done) {
            return;
        }
        if no_note {
            self.settled(w);
            return self.review_after_run(w);
        }
        // What to know next time: asked now, while it's fresh.
        w.input = Input::Prompt(Prompt::LogNote(Box::new(entry)), String::new());
    }

    /// The note for the maintenance log, typed: saved with the entry (empty is fine). `add`:
    /// it's added to an entry from Records, not the one a run or task just wrote.
    pub(crate) fn log_note_submit(
        &mut self,
        w: &mut Win,
        entry: sentry_core::maint::log::LogEntry,
        note: &str,
        add: bool,
    ) {
        let note = note.trim();
        // From Records: appended, dated, to the entry as it is.
        if add {
            if note.is_empty() {
                return;
            }
            let mut with_note = entry.clone();
            with_note.add_note(note);
            if !w.offline
                && let Err(e) = sentry_core::maint::log::write_replacing(&entry, &with_note)
            {
                return w.toast(&format!("couldn't write the note: {e}"));
            }
            self.last_log = Some(with_note);
            self.shared.log = if w.offline {
                self.shared.log.clone()
            } else {
                sentry_core::maint::log::list(&self.scope)
            };
            w.toast("noted in the maintenance log");
            return self.open_records(w, sentry_core::tui::records::Section::Log, None);
        }
        self.settled(w);
        if note.is_empty() {
            return;
        }
        // Done by hand (no run): the same entry, with the note.
        if entry.head.run.is_none() {
            let h = &entry.head;
            let task = h.tags.iter().find_map(|t| t.strip_prefix("task:"));
            let with_note = match task {
                Some(id) => sentry_core::maint::log::LogEntry::task(
                    &h.server,
                    id,
                    &self
                        .shared
                        .tasks
                        .iter()
                        .find(|t| t.id == id)
                        .map_or(id.to_string(), |t| t.title.clone()),
                    Some(note),
                ),
                None => sentry_core::maint::log::LogEntry::by_hand(
                    &h.server,
                    h.item.as_deref().unwrap_or("?"),
                    &h.kind,
                    h.from.clone(),
                    h.to.clone(),
                    h.plan.as_deref().map(std::path::Path::new),
                    Some(note),
                ),
            };
            if !w.offline
                && let Err(e) = sentry_core::maint::log::write_replacing(&entry, &with_note)
            {
                return w.toast(&format!("couldn't write the note: {e}"));
            }
            self.last_log = Some(with_note);
            return w.toast("noted in the maintenance log");
        }
        let Some(s) = self.run.as_ref() else { return };
        // Rebuilt with the note (it replaces the entry written when the run ended).
        let info = entry
            .head
            .item
            .as_ref()
            .map(|item| sentry_core::maint::log::ItemInfo {
                item: item.clone(),
                kind: entry.head.kind.clone(),
                risk: entry.head.risk.clone().unwrap_or_default(),
                from: entry.head.from.clone(),
                to: entry.head.to.clone(),
                plan: entry.head.plan.clone().map(Into::into),
            });
        let mut with_note = sentry_core::maint::log::LogEntry::from_run(
            &self.scope,
            s.wf(),
            &s.run().state,
            &s.run().dir,
            info.as_ref(),
            Some(note),
        );
        sentry_core::maint::tasks::tag_run(&mut with_note, &self.all_tasks());
        let with_note = self.kept_entry(with_note);
        if !w.offline
            && let Err(e) = sentry_core::maint::log::write(&with_note)
        {
            return w.toast(&format!("couldn't write the note: {e}"));
        }
        if !self.ways.log_kept {
        } else if w.offline {
            self.shared
                .log
                .retain(|e| e.head.run.is_none() || e.head.run != with_note.head.run);
            self.shared.log.insert(0, with_note.clone());
        } else {
            self.shared.log = sentry_core::maint::log::list(&self.scope);
        }
        self.last_log = Some(with_note);
        w.toast(self.ways.noted);
    }

    /// Stop the workflow's running step (abandoning, closing or quitting).
    pub(crate) fn wf_stop_live(&mut self) {
        if let Some(pid) = self
            .run
            .as_mut()
            .and_then(|s| s.set_live(None))
            .and_then(|l| l.pid)
        {
            let _ = kill(pid);
        }
    }

    pub(crate) fn wf_cmd(&mut self, w: &mut Win, c: WfCmd) {
        if matches!(c, WfCmd::Abandon | WfCmd::Close) {
            self.wf_stop_live();
            self.reboot_held = None;
        }
        let r: Result<Option<Exec>, String> = match c {
            WfCmd::Arm => {
                if let Some(s) = self.run.as_mut() {
                    s.arm();
                }
                self.wf_auto_now(w);
                Ok(None)
            }
            WfCmd::Own(own) => match self.run.as_deref_mut() {
                None => return,
                Some(s) => {
                    let r = self
                        .target
                        .run_cmd(s, &own, &self.shared, &cx!(self, w, norun));
                    match r {
                        Ok(e) => {
                            self.apply(w, e, w.at);
                            Ok(None)
                        }
                        Err(e) => Err(e),
                    }
                }
            },
            WfCmd::Begin(name) => {
                let asks: Vec<(String, String, Option<String>)> = self
                    .shared
                    .wf_entries
                    .iter()
                    .find(|e| e.name == name)
                    .and_then(|e| e.wf.as_ref().ok())
                    .map(|w| {
                        w.vars
                            .iter()
                            .map(|(k, v)| (k.clone(), v.prompt.clone(), v.default.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                if asks.is_empty() {
                    return self.wf_cmd(w, WfCmd::BeginWith(name, BTreeMap::new()));
                }
                // Auto: a default for each, and it starts with them.
                if let Some(values) = self.auto_values(&asks) {
                    return self.wf_cmd(w, WfCmd::BeginWith(name, values));
                }
                let buf = asks[0].2.clone().unwrap_or_default();
                w.input = Input::Prompt(
                    Prompt::WfVar(VarInput {
                        workflow: name,
                        asks,
                        values: BTreeMap::new(),
                        note: None,
                    }),
                    buf,
                );
                w.dirty = true;
                return;
            }
            WfCmd::BeginPrefilled(name, given, change) => {
                if self.run.as_ref().is_some_and(|s| !s.done()) {
                    w.toast("a workflow is already in progress");
                    return;
                }
                if self.shared.wf_entries.is_empty() && !w.offline {
                    self.load_wf_entries();
                }
                let Some(e) = self.shared.wf_entries.iter().find(|e| e.name == name) else {
                    w.toast(&format!(
                        "no workflow {name} in {}",
                        self.shared.wf_dir.trim_end_matches('/')
                    ));
                    return;
                };
                self.wf_change = change;
                let asks: Vec<(String, String, Option<String>)> =
                    e.wf.as_ref()
                        .map(|w| {
                            w.vars
                                .iter()
                                .map(|(k, v)| (k.clone(), v.prompt.clone(), v.default.clone()))
                                .collect()
                        })
                        .unwrap_or_default();
                // What was given takes the place of the workflow's own defaults.
                let asks: Vec<(String, String, Option<String>)> = asks
                    .into_iter()
                    .map(|(k, p, d)| {
                        let d = given.get(&k).cloned().or(d);
                        (k, p, d)
                    })
                    .collect();
                if asks.is_empty() {
                    return self.wf_cmd(w, WfCmd::BeginWith(name, BTreeMap::new()));
                }
                if let Some(values) = self.auto_values(&asks) {
                    return self.wf_cmd(w, WfCmd::BeginWith(name, values));
                }
                let buf = asks[0].2.clone().unwrap_or_default();
                w.input = Input::Prompt(
                    Prompt::WfVar(VarInput {
                        workflow: name,
                        asks,
                        values: BTreeMap::new(),
                        note: None,
                    }),
                    buf,
                );
                w.dirty = true;
                return;
            }
            WfCmd::BeginWith(name, vars) => {
                let entry = self.target.find_workflow(&name).or_else(|| {
                    self.shared
                        .wf_entries
                        .iter()
                        .find(|e| e.name == name)
                        .cloned()
                });
                match entry {
                    Some(e) => match self.target.begin_run(&e, vars, &self.shared) {
                        Ok(mut s) => {
                            if std::mem::take(&mut self.auto_took_values) {
                                s.auto_answered("values");
                                s.push(
                                    "auto: started with the default values".into(),
                                    LogKind::Info,
                                );
                            }
                            self.auto_held = None;
                            self.run = Some(s);
                            // Its screen: the run is followed there, and its auto steps start.
                            self.enter(w, ScreenId::Upgrade, w.at);
                            Ok(None)
                        }
                        Err(e) => Err(e),
                    },
                    None => Err(format!("no workflow {name}")),
                }
            }
            WfCmd::Close => {
                self.run = None;
                if !w.offline {
                    self.load_wf_entries();
                }
                Ok(None)
            }
            c => match self.run.as_deref_mut() {
                None => Ok(None),
                Some(s) => match c {
                    // What the step needs of the host (sudo) is the target's to check.
                    WfCmd::Go => self.target.run_go(s, false, &cx!(self, w, norun)),
                    WfCmd::Skip(force) => s.skip(force).map(|_| None),
                    WfCmd::Done => s.mark_done().map(|_| None),
                    WfCmd::Retry => s.retry().map(|_| None),
                    WfCmd::Abandon => {
                        s.abandon();
                        Ok(None)
                    }
                    WfCmd::Begin(_)
                    | WfCmd::BeginWith(..)
                    | WfCmd::BeginPrefilled(..)
                    | WfCmd::Arm
                    | WfCmd::Own(_)
                    | WfCmd::Close => Ok(None),
                },
            },
        };
        match r {
            Ok(Some(e)) => self.wf_exec(w, e),
            Ok(None) => {}
            Err(e) => w.toast(&e),
        }
        if self.ways.auto_polled {
            self.wf_auto(w);
        } else {
            self.wf_log_change(w);
        }
        // Auto mode: the step that now waits for its confirm.
        self.auto_step(w);
        w.dirty = true;
    }

    /// Run the next auto step, whatever screen and whichever target is in view: a run that
    /// was started or opened goes on by itself until a step needs the user.
    pub(crate) fn wf_auto(&mut self, w: &mut Win) {
        self.wf_log_change(w);
        self.wf_auto_now(w);
        // Auto mode: the step that waits for its confirm.
        self.auto_step(w);
    }

    /// The next auto step, if the run is armed and idle.
    pub(crate) fn wf_auto_now(&mut self, w: &mut Win) {
        if !self
            .run
            .as_ref()
            .is_some_and(|s| s.armed() && s.live().is_none() && matches!(s.next(), Next::Run(_)))
        {
            return;
        }
        let e = match self.run.as_deref_mut() {
            Some(s) => self.target.run_go(s, true, &cx!(self, w, norun)),
            None => return,
        };
        if let Ok(Some(e)) = e {
            self.wf_exec(w, e);
        }
    }

    pub(crate) fn wf_exec(&mut self, w: &mut Win, e: Exec) {
        match e {
            Exec::Stream {
                how,
                idx,
                dry,
                timeout,
            } => self.wf_how(w, how, idx, dry, timeout),
            Exec::Shell { idx } => {
                let sh = std::env::var("SHELL").unwrap_or_else(|_| "bash".into());
                let cmd = sentry_core::exec::Cmd::local(&sh).timeout(None);
                self.suspend_shell = Some(idx);
                self.suspend = Some(Suspend {
                    banner: format!("$ {}", cmd.display()),
                    cmd,
                    then: Vec::new(),
                    own: None,
                });
            }
            // What rebooting this host means (waiting for it, or the end of the TUI) is the
            // target's.
            Exec::Reboot { how } => {
                let old = self
                    .run
                    .as_ref()
                    .and_then(|s| {
                        s.next()
                            .idx()
                            .and_then(|i| s.run().state.steps[i].boot_id.clone())
                    })
                    .unwrap_or_default();
                // A reboot that ends the TUI would cut the other targets' work off: it
                // waits for them (`reboot_when_settled`).
                if self.ways.reboot_ends_tui && !w.others_working.is_empty() {
                    let who = w.others_working.join(", ");
                    if let Some(s) = self.run.as_mut() {
                        s.push(
                            format!(
                                "↻ the reboot waits for {who}: it goes by itself when that \
                                 settles (or stop it there)"
                            ),
                            LogKind::Info,
                        );
                    }
                    w.toast(&format!("the reboot waits for {who}"));
                    self.reboot_held = Some((how, old, who));
                    return;
                }
                self.reboot_now(w, how, old);
            }
        }
    }

    /// The host reboots now.
    fn reboot_now(&mut self, w: &mut Win, how: crate::run::How, old: String) {
        match how {
            crate::run::How::Plain(cmd) => {
                let e = self.target.reboot(cmd, old, &cx!(self, w));
                self.apply(w, e, w.at);
            }
            crate::run::How::Root(line) => {
                let what = format!("to reboot {}", self.title);
                self.with_root(w, what, root::Waiting::Reboot(line, old));
            }
        }
    }

    /// The reboot that waited for the other targets: they're through, so it goes.
    pub(crate) fn reboot_when_settled(&mut self, w: &mut Win) {
        if self.reboot_held.is_none() {
            return;
        }
        if !w.others_working.is_empty() {
            // Whoever it waits for now (one may have ended while another began).
            let who = w.others_working.join(", ");
            if let Some(h) = self.reboot_held.as_mut().filter(|h| h.2 != who) {
                h.2 = who;
                w.dirty = true;
            }
            return;
        }
        let Some((how, old, _)) = self.reboot_held.take() else {
            return;
        };
        if let Some(s) = self.run.as_mut() {
            s.push(
                "↻ the other targets settled: rebooting".into(),
                LogKind::Info,
            );
        }
        self.reboot_now(w, how, old);
        w.dirty = true;
    }

    /// Start the step's command; its lines and exit arrive as the run's live step.
    pub(crate) fn wf_stream(
        &mut self,
        w: &mut Win,
        cmd: sentry_core::exec::Cmd,
        idx: usize,
        dry: bool,
        timeout: Option<Duration>,
    ) {
        let id = self.mail.next();
        let mut pid = None;
        if !w.offline {
            match self.mail.stream(id, &cmd) {
                Ok(p) => pid = Some(p),
                Err(err) => {
                    if let Some(s) = self.run.as_mut() {
                        s.spawn_failed(idx, dry, &err.to_string());
                    }
                    return;
                }
            }
        }
        if let Some(s) = self.run.as_mut() {
            s.set_live(Some(Live {
                id,
                idx,
                pid,
                started: Instant::now(),
                dry,
                deadline: timeout.map(|t| Instant::now() + t),
            }));
        }
        w.dirty = true;
    }

    /// Enter on a workflow (screen 0, a row, `:wf <name>`): it starts. Enter was the approval:
    /// its auto steps run, and every step that changes something still waits for its own
    /// confirm. Values it takes are asked first; one that can't start says why.
    pub(crate) fn wf_start(&mut self, w: &mut Win, name: &str, now: Instant) {
        // The target's own way of starting one (its screen's Enter).
        if let Some(e) = self.target.wf_start(name, &self.shared, &cx!(self, w)) {
            return self.apply(w, e, now);
        }
        if self.screen != ScreenId::Upgrade {
            self.enter(w, ScreenId::Upgrade, now);
        }
        if self.run.as_ref().is_some_and(|s| !s.done()) {
            return w.toast("a workflow is in progress: finish or abandon it first");
        }
        if self.shared.wf_entries.is_empty() && !w.offline {
            self.load_wf_entries();
        }
        let t = w.theme;
        let Some(i) = self.shared.wf_entries.iter().position(|e| e.name == name) else {
            return w.toast(&format!("no workflow {name}"));
        };
        self.settle(w, Settle::Workflow(i));
        let e = &self.shared.wf_entries[i];
        if let Some(why) = e.blocked() {
            self.modal = Some(Modal {
                title: format!("{} can't start", e.name),
                color: t.cyan,
                lines: vec![
                    Line::styled(why, t.s(t.yellow)),
                    Line::styled(
                        format!("Edit with e: {}", widgets::short_home(&e.path)),
                        t.dim(),
                    ),
                ],
                yes: None,
            });
            return;
        }
        self.wf_cmd(w, WfCmd::Begin(name.to_string()));
    }

    /// The workflows the target has, with their values, for checking a plan's steps.
    pub(crate) fn wf_infos(&self) -> Vec<sentry_core::apply::plan::WfInfo> {
        use sentry_core::apply::plan::WfInfo;
        if self.shared.wf_entries.is_empty() {
            self.shared
                .workflows
                .iter()
                .map(|n| WfInfo::from(n.as_str()))
                .collect()
        } else {
            self.shared.wf_entries.iter().map(WfInfo::of).collect()
        }
    }
}

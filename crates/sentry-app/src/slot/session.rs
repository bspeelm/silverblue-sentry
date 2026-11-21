use super::*;

impl Slot {
    /// A stream that belongs to the apply session (Claude's turn, a step, sudo's check).
    pub(crate) fn apply_stream(&mut self, w: &mut Win, id: u64, m: &StreamMsg) -> bool {
        use sentry_core::apply::session::Phase;
        let Some(sess) = self.apply.as_mut() else {
            return false;
        };
        if sess.chat.live.is_some_and(|(cid, _)| cid == id) {
            match m {
                StreamMsg::Line {
                    stderr: false,
                    text,
                } => {
                    for e in claude::parse_line(text) {
                        sess.chat.on_event(e);
                    }
                }
                StreamMsg::Line { stderr: true, text } => sess.chat.on_raw(text.clone()),
                StreamMsg::Exit { code, .. } => {
                    // The plan's steps are checked against the workflows as they are.
                    if self.shared.wf_entries.is_empty() && !w.offline {
                        self.load_wf_entries();
                    }
                    let names = self.wf_infos();
                    let Some(sess) = self.apply.as_mut() else {
                        return true;
                    };
                    let fx = sess.turn_ended(*code, &names);
                    if sess.chat.hidden && !sess.busy() {
                        w.toast("Claude answered · A opens it");
                    }
                    self.apply_fx(w, fx);
                }
            }
            return true;
        }
        if sess.job.is_some_and(|(jid, _)| jid == id) {
            match m {
                StreamMsg::Line { text, .. } => {
                    // What goes back to Claude is what the target lets it see.
                    let seen = self.target.hides(text);
                    sess.step_line(seen.unwrap_or_else(|| text.clone()));
                    self.saw_line(w, text);
                }
                StreamMsg::Exit { code, .. } => {
                    let fx = sess.step_ended(*code);
                    self.apply_fx(w, fx);
                    self.refresh(w, Why::Step);
                }
            }
            return true;
        }
        if let Some((_, password)) = self.apply_aux.filter(|(aid, _)| *aid == id) {
            if let StreamMsg::Exit { code, .. } = m {
                self.apply_aux = None;
                let fx = match (password, sess.phase) {
                    // Accepted: held here from now on, for everything on this target.
                    (true, Phase::Password { .. }) if *code == 0 => {
                        let typed = sess.take_typed();
                        let fx = sess.password_checked(true);
                        self.hold(typed);
                        fx
                    }
                    (true, Phase::Password { .. }) => sess.password_checked(false),
                    (false, Phase::SudoCheck) => sess.sudo_checked(*code != 0),
                    _ => Vec::new(),
                };
                self.apply_fx(w, fx);
            }
            return true;
        }
        false
    }

    /// Carry out what the apply session asks for: commands on the host, edits of local
    /// files (the session does those), Claude's turns with the gateway.
    pub(crate) fn apply_fx(&mut self, w: &mut Win, fx: Vec<sentry_core::apply::session::Fx>) {
        use sentry_core::apply::session::Fx;
        for f in fx {
            match f {
                Fx::Turn { prompt, shown } => {
                    let Some(sess) = self.apply.as_ref() else {
                        return;
                    };
                    let resume = sess.chat.session.clone();
                    let grants = sess.chat.grants.clone();
                    let r = self.spawn_turn(w, &prompt, resume.as_deref(), &grants);
                    let Some(sess) = self.apply.as_mut() else {
                        return;
                    };
                    match (r, shown) {
                        (Ok((id, pid)), Some(q)) => sess.chat.begin_turn(&q, id, pid),
                        (Ok((id, pid)), None) => sess.chat.begin_quiet(id, pid),
                        (Err(e), _) => {
                            sess.chat
                                .push(chatmod::Kind::Err, format!("couldn't start claude: {e}"));
                            let names = self.wf_infos();
                            if let Some(sess) = self.apply.as_mut() {
                                let fx = sess.turn_ended(-1, &names);
                                self.apply_fx(w, fx);
                            }
                        }
                    }
                }
                Fx::Kill(pid) => {
                    let _ = kill(pid);
                }
                Fx::Command { cmd, sudo } => {
                    if self.apply.is_none() {
                        return;
                    }
                    let c = if sudo && self.secret_ok {
                        self.root_cmd(&cmd, true)
                    } else {
                        // Nothing sentry runs for Claude waits on stdin (over ssh the
                        // command's is a terminal, which never ends).
                        self.target
                            .command(&sentry_core::apply::sudo::detached(&cmd))
                            .timeout(None)
                    };
                    let id = self.mail.next();
                    let r = if w.offline {
                        Ok(0)
                    } else {
                        self.mail.stream(id, &c).map_err(|e| e.to_string())
                    };
                    let Some(sess) = self.apply.as_mut() else {
                        return;
                    };
                    match r {
                        Ok(pid) => sess.step_started(id, pid),
                        Err(e) => {
                            sess.step_line(format!("couldn't start it: {e}"));
                            let fx = sess.step_ended(-1);
                            self.apply_fx(w, fx);
                        }
                    }
                }
                // What checking a fix again means is the target's (a server leaves it to
                // Claude's own read-only check).
                Fx::Reaudit => self.refresh(w, Why::Reaudit),
                Fx::RetryStep if self.ways.auto_polled => {
                    self.wf_cmd(w, WfCmd::Retry);
                    self.enter(w, ScreenId::Upgrade, w.at);
                }
                // Where the next step isn't looked for by itself: the step runs again now, a
                // confirm step too (the retry was the confirm).
                Fx::RetryStep => {
                    self.wf_cmd(w, WfCmd::Retry);
                    self.wf_auto(w);
                    if self
                        .run
                        .as_ref()
                        .is_some_and(|s| s.live().is_none() && matches!(s.next(), Next::Confirm(_)))
                    {
                        self.wf_cmd(w, WfCmd::Go);
                    }
                    self.apply(w, vec![Effect::Goto(ScreenId::Upgrade)], w.at);
                }
                Fx::MarkDone => {
                    let a = self
                        .apply
                        .as_ref()
                        .and_then(|s| s.chat.ask.applying().cloned())
                        .unwrap_or_default();
                    match (a.task, a.plan) {
                        (Some(id), _) => {
                            let title = self.task_title(&id);
                            let e = sentry_core::maint::log::LogEntry::task(
                                &self.scope,
                                &id,
                                &title,
                                None,
                            );
                            self.log_event(w, e);
                        }
                        (None, Some(item)) if self.ways.plans_by_hand => {
                            self.apply(w, vec![Effect::PlanDoneByHand(item)], w.at)
                        }
                        _ => {}
                    }
                }
                // The password is held already: nothing is asked or checked.
                Fx::CheckSudo if self.secret_ok => {
                    if let Some(sess) = self.apply.as_mut() {
                        let fx = sess.password_held();
                        self.apply_fx(w, fx);
                    }
                }
                Fx::CheckSudo | Fx::CheckPassword => {
                    let password = f == Fx::CheckPassword;
                    let Some(sess) = self.apply.as_ref() else {
                        return;
                    };
                    let c = if password {
                        self.target
                            .command(sentry_core::apply::sudo::check_script())
                            .input(sess.secret.stdin())
                    } else {
                        self.target.command("sudo -n true")
                    }
                    .timeout(None);
                    let id = self.mail.next();
                    self.apply_aux = Some((id, password));
                    if !w.offline
                        && let Err(e) = self.mail.stream(id, &c)
                    {
                        self.apply_aux = None;
                        w.toast(&format!("couldn't run sudo: {e}"));
                    }
                }
                Fx::StartWorkflow(wf, vars) => {
                    // The target's own way of starting one for a session.
                    let own = self
                        .target
                        .session_starts(&wf, &vars, &self.shared, &cx!(self, w));
                    if let Some(e) = own {
                        self.apply(w, e, w.at);
                        // A workflow that needs you first (a value, a confirm): its run, in
                        // front.
                        let going = self.run.as_ref().is_some_and(|s| s.live().is_some());
                        if !going || w.input.is_open() {
                            if let Some(sess) = self.apply.as_mut() {
                                sess.chat.hidden = true;
                            }
                            w.toast(&format!("{wf}{}", self.ways.needs_you));
                        }
                        continue;
                    }
                    // It can't start (a draft, another run open): the step fails with why, and
                    // Claude hears it, rather than the plan waiting for a run that never comes.
                    if let Some(why) = self.wf_refusal(w, &wf) {
                        if let Some(sess) = self.apply.as_mut() {
                            sess.chat.hidden = false;
                            let fx = sess.workflow_ended(&wf, false, format!("not started: {why}"));
                            self.apply_fx(w, fx);
                        }
                        continue;
                    }
                    // The item it changes goes in the log with the run (and its plan, if any,
                    // is closed when the run ends well).
                    let change = self
                        .apply
                        .as_ref()
                        .and_then(|s| s.chat.ask.applying())
                        .and_then(|a| a.item.clone())
                        .map(|item| {
                            let plan = self.shared.plans.get(&item);
                            ItemChange {
                                from: plan.and_then(|p| p.head.from.clone()),
                                to: plan.and_then(|p| p.head.to.clone()),
                                item,
                            }
                        });
                    // The plan's values are the base; the step's own come on top.
                    let mut given: BTreeMap<String, String> = change
                        .as_ref()
                        .and_then(|c| self.shared.plans.get(&c.item))
                        .filter(|p| p.head.workflow == wf)
                        .map(|p| p.head.vars.clone())
                        .unwrap_or_default();
                    given.extend(vars);
                    self.apply(
                        w,
                        vec![Effect::Wf(WfCmd::BeginPrefilled(wf.clone(), given, change))],
                        w.at,
                    );
                    let going = self.run.as_ref().is_some_and(|s| s.live().is_some());
                    if !going || self.asking_vars(w).is_some() {
                        if let Some(sess) = self.apply.as_mut() {
                            sess.chat.hidden = true;
                        }
                        w.toast(&format!("{wf}{}", self.ways.needs_you));
                    }
                }
                Fx::PlanDone(item) => {
                    // Already closed when its workflow's run ended: nothing left to do.
                    if let Some(doc) = self.shared.plans.remove(&item) {
                        if !w.offline {
                            let _ = sentry_core::maint::plan::close(&doc, PlanStatus::Done);
                        }
                        if self.ways.plan_done_says {
                            self.plan_view = None;
                            w.toast(&format!("the plan for {item} is done (plans/done/)"));
                        }
                    }
                }
                Fx::PlanSave { key, body } => self.plan_keep(w, &key, &body, PlanStatus::Ready),
                // Nothing changed: what Claude wrote is kept as the plan's document (when
                // the session has one), the row is put off, and the log says why.
                Fx::Wait {
                    key,
                    why,
                    again,
                    body,
                } => {
                    let plan = self
                        .apply
                        .as_ref()
                        .and_then(|s| s.chat.ask.applying())
                        .and_then(|a| a.plan.clone());
                    if let Some(pk) = plan {
                        let doc = format!("{body}\n\nClaude advises waiting: {why}");
                        self.plan_keep(w, &pk, &doc, PlanStatus::Wait);
                    }
                    let days = again
                        .as_deref()
                        .and_then(|a| a.parse::<sentry_core::config::Dur>().ok())
                        .map_or(30, |d| (d.0.as_secs() / 86_400).max(1) as i64);
                    let today = jiff::Zoned::now().date();
                    let until = today
                        .checked_add(jiff::Span::new().days(days))
                        .unwrap_or(today);
                    if !w.offline
                        && let Err(e) =
                            sentry_core::maint::later::set(&self.scope, &key, until, today)
                    {
                        w.toast(&format!("couldn't save it: {e}"));
                        continue;
                    }
                    self.shared.later.insert(key.clone(), until);
                    let e = sentry_core::maint::log::LogEntry::event(
                        &self.scope,
                        "wait",
                        "wait",
                        true,
                        &format!("Claude advises waiting with {key} until {until}: {why}"),
                        &[format!("apply:{key}"), "wait".into()],
                        jiff::Timestamp::now(),
                    );
                    if w.offline {
                        self.shared.log.insert(0, e);
                    } else if sentry_core::maint::log::write(&e).is_ok() {
                        self.shared.log = sentry_core::maint::log::list(&self.scope);
                    }
                    self.refresh(w, Why::Lists);
                    w.toast(&format!(
                        "{key}: it can wait · look again {until} (Records › Later)"
                    ));
                }
                Fx::OpenRun(wf, vars) if !self.ways.run_checks => {
                    let running = self
                        .run
                        .as_ref()
                        .is_some_and(|s| s.wf().name == wf && !s.done());
                    if !running && !w.input.is_open() {
                        // It never started (its values dismissed, refused): start it again.
                        self.apply_fx(w, vec![Fx::StartWorkflow(wf, vars)]);
                        continue;
                    }
                    if let Some(sess) = self.apply.as_mut() {
                        sess.chat.hidden = true;
                    }
                    self.apply(w, vec![Effect::Goto(ScreenId::Upgrade)], w.at);
                    w.toast("the plan carries on when the run ends · A shows it");
                }
                Fx::OpenRun(wf, vars) => {
                    // Its values being asked: they're in front already.
                    let asking = self.asking_vars(w) == Some(wf.as_str());
                    let running = self
                        .run
                        .as_ref()
                        .is_some_and(|s| s.wf().name == wf && !s.done());
                    let other = self
                        .run
                        .as_ref()
                        .filter(|s| s.wf().name != wf && !s.done())
                        .map(|s| s.wf().name.clone());
                    if let Some(other) = other {
                        if let Some(sess) = self.apply.as_mut() {
                            sess.chat.hidden = true;
                        }
                        self.enter(w, ScreenId::Upgrade, w.at);
                        w.toast(&format!(
                            "{other} is in progress: finish it, then A · Enter starts {wf}"
                        ));
                        continue;
                    }
                    if !asking && !running {
                        // It never started (its values dismissed, refused): start it again.
                        self.apply_fx(w, vec![Fx::StartWorkflow(wf, vars)]);
                        continue;
                    }
                    if let Some(sess) = self.apply.as_mut() {
                        sess.chat.hidden = true;
                    }
                    if running {
                        self.enter(w, ScreenId::Upgrade, w.at);
                    }
                    w.toast("the plan carries on when the run ends · A shows it");
                }
                Fx::Log { ok, body, tags } => {
                    let mut tags = tags;
                    if let Some(i) = self
                        .apply
                        .as_ref()
                        .and_then(|s| s.chat.ask.applying())
                        .and_then(|a| a.item.clone())
                        .filter(|_| self.ways.log_item_tag)
                    {
                        tags.push(format!("item:{i}"));
                    }
                    let e = sentry_core::maint::log::LogEntry::event(
                        &self.scope,
                        "apply",
                        "apply",
                        ok,
                        &body,
                        &tags,
                        jiff::Timestamp::now(),
                    );
                    self.log_event(w, e);
                }
                Fx::TaskDone(id) => {
                    let title = self.task_title(&id);
                    let e = sentry_core::maint::log::LogEntry::task(&self.scope, &id, &title, None);
                    self.log_event(w, e);
                }
                Fx::AddTask(t) => self.task_add(w, *t),
                Fx::Hide => {
                    if let Some(sess) = self.apply.as_mut() {
                        sess.chat.hidden = true;
                    }
                    w.toast("it carries on · A brings it back");
                }
                Fx::Close => {
                    self.apply = None;
                    // The series' row, closed without going on: the series stops there.
                    if self.series_waits(&sentry_core::maint::series::Wait::Session) {
                        self.series_stop(w);
                    }
                }
                Fx::Next => self.series_next(w),
            }
        }
        self.auto_step(w);
    }

    /// What a task done in a session is logged as: its title, or (the app's own way) its id.
    fn task_title(&self, id: &str) -> String {
        if !self.ways.log_task_title {
            return id.to_string();
        }
        self.all_tasks()
            .into_iter()
            .find(|t| t.id == id)
            .map_or(id.to_string(), |t| t.title)
    }

    /// Open the conversation, nothing sent yet: an apply session, or a chat, showing the
    /// brief; Enter sends it.
    pub(crate) fn open_ask(&mut self, w: &mut Win, ask: Ask) {
        if !claude::available() {
            w.toast(self.ways.no_claude);
            return;
        }
        if ask.applying().is_some() {
            // A series has its own session open (hidden, perhaps): not replaced.
            if self.apply.is_some()
                && let Some(sr) = &self.series
            {
                let line = format!("{} · A shows it", sr.line());
                return w.toast(&line);
            }
            if let Some(pid) = self.apply.as_ref().and_then(|s| s.chat.live.map(|l| l.1)) {
                let _ = kill(pid);
            }
            let sess = self.session_for(w, ask);
            self.apply = Some(sess);
            // Auto: it starts by itself.
            self.auto_step(w);
            return;
        }
        if let Some((_, pid)) = self.chat.as_ref().and_then(|c| c.live) {
            let _ = kill(pid);
        }
        let mut c = Chat::new(ask);
        c.pending = true;
        c.privacy = self.target.ident().privacy.clone();
        self.chat = Some(c);
    }

    /// The session for `ask`. When a plan is saved and ready for what it's about, it opens
    /// on that plan, to approve (nothing is sent first); one written before plans were a
    /// session's, for a workflow, is that workflow with the plan's values.
    pub(crate) fn session_for(
        &mut self,
        w: &mut Win,
        ask: Ask,
    ) -> sentry_core::apply::session::Session {
        use sentry_core::apply::plan::{self, Kind, Plan, Step};
        use sentry_core::apply::session::Session;
        if self.shared.wf_entries.is_empty() && !w.offline {
            self.load_wf_entries();
        }
        let infos = self.wf_infos();
        let saved = ask
            .applying()
            .and_then(|a| a.plan.as_ref())
            .and_then(|k| self.shared.plans.get(k))
            .filter(|d| d.head.status == PlanStatus::Ready);
        let seeded = saved.and_then(|d| {
            Session::seeded(ask.clone(), &d.body, &infos).or_else(|| {
                let h = &d.head;
                if h.workflow.is_empty() {
                    return None;
                }
                let block = plan::to_block(&Plan {
                    summary: match &h.to {
                        Some(to) => format!("{} → {to}", h.item),
                        None => h.item.clone(),
                    },
                    rollback: String::new(),
                    steps: vec![Step {
                        title: format!("Run {}", h.workflow),
                        kind: Kind::Workflow {
                            name: h.workflow.clone(),
                            vars: h.vars.clone(),
                        },
                    }],
                });
                Session::seeded(ask.clone(), &format!("{}\n\n{block}", d.body), &infos)
            })
        });
        let mut sess = seeded.unwrap_or_else(|| Session::new(ask));
        sess.chat.privacy = self.target.ident().session_privacy.clone();
        sess.secret_ok = self.secret_ok;
        sess.auto = self.auto;
        sess
    }

    /// A follow-up in the open chat, as typed (or what sentry offered to send).
    pub(crate) fn ask_turn(&mut self, w: &mut Win, text: String) {
        let session = self.chat.as_ref().and_then(|c| c.session.clone());
        self.start_turn(w, ReadsFor::Chat, &text, text.clone(), session);
    }

    /// Start a Claude turn with the gateway, the notes files and `grants`. Offline (tests):
    /// nothing starts; the id is real, the pid 0.
    pub(crate) fn spawn_turn(
        &mut self,
        w: &mut Win,
        prompt: &str,
        resume: Option<&str>,
        grants: &[sentry_core::claude::Grant],
    ) -> Result<(u64, u32), String> {
        // The target's profile for a session, plus what the user granted in it.
        let profile = self.target.profile(ProfileFor::Session, grants);
        let id = self.mail.next();
        if w.offline || w.scripted_turns {
            self.last_prompt = Some(prompt.to_string());
            return Ok((id, 0));
        }
        let cmd = claude::turn_cmd_with(prompt, resume, &profile);
        self.mail
            .stream(id, &cmd)
            .map(|pid| (id, pid))
            .map_err(|e| e.to_string())
    }

    /// Send one turn to Claude, into the open chat or the background plan.
    pub(crate) fn start_turn(
        &mut self,
        w: &mut Win,
        to: ReadsFor,
        prompt: &str,
        shown: String,
        resume: Option<String>,
    ) {
        // The target's profile for a chat, plus what the user granted in this conversation.
        let grants = self
            .chat
            .as_ref()
            .map(|c| c.grants.clone())
            .unwrap_or_default();
        let profile = self.target.profile(ProfileFor::Chat, &grants);
        let cmd = claude::turn_cmd_with(prompt, resume.as_deref(), &profile);
        let id = self.mail.next();
        let _ = to;
        let Some(c) = self.chat.as_mut() else { return };
        c.pending = false;
        if w.offline && self.ways.offline_turns_live {
            return c.begin_turn(&shown, id, 0);
        }
        if w.offline {
            c.push(chatmod::Kind::You, shown);
            return;
        }
        match self.mail.stream(id, &cmd) {
            Ok(pid) => c.begin_turn(&shown, id, pid),
            Err(e) => c.push(chatmod::Kind::Err, format!("couldn't start claude: {e}")),
        }
    }

    pub(crate) fn chat_key(&mut self, w: &mut Win, k: KeyEvent) {
        use ratatui::crossterm::event::{KeyCode, KeyModifiers};
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let t = w.theme;
        let Some(c) = self.chat.as_mut() else { return };
        if c.pending {
            match k.code {
                KeyCode::Esc => self.chat = None,
                KeyCode::Enter => {
                    let note = std::mem::take(&mut c.input);
                    let mut prompt = c.ask.prompt();
                    let shown = match note.trim() {
                        "" => (self.ways.first_shown)(&c.ask),
                        n => {
                            prompt.push_str(&format!("\n\nFrom me: {n}"));
                            n.to_string()
                        }
                    };
                    self.start_turn(w, ReadsFor::Chat, &prompt, shown, None);
                }
                KeyCode::Backspace => {
                    c.input.pop();
                }
                KeyCode::Char(ch) if !ctrl => c.input.push(ch),
                _ => {}
            }
            w.dirty = true;
            return;
        }
        let idle = c.input.is_empty() && !c.busy();
        // Carried on somewhere else, where the target has such a place.
        if k.code == KeyCode::Char('C')
            && !ctrl
            && idle
            && let Some(session) = c.session.clone()
            && let Some(e) = self.target.chat_continue(&session)
        {
            w.dirty = true;
            return self.apply(w, e, w.at);
        }
        let Some(c) = self.chat.as_mut() else { return };
        match k.code {
            KeyCode::Char('c') if ctrl => {
                if let Some((_, pid)) = c.live {
                    let _ = kill(pid);
                    c.push(chatmod::Kind::Info, "stopped");
                }
            }
            // Apply what the chat is about: a session takes the conversation over.
            KeyCode::Char('a') if c.can_apply() => {
                if let Some(c) = self.chat.take()
                    && let Some(apply) = c.apply_with.clone()
                {
                    let mut sess = sentry_core::apply::session::Session::from_chat(c, apply);
                    sess.chat.privacy = self.target.ident().session_privacy.clone();
                    sess.secret_ok = self.secret_ok;
                    sess.auto = self.auto;
                    self.apply = Some(sess);
                    self.auto_step(w);
                }
            }
            // What Claude was refused: Enter allows it, for this conversation.
            KeyCode::Enter if c.can_allow() => self.chat_grant(w),
            // The same, shown first.
            KeyCode::Char('g') if idle && !c.requests.is_empty() => {
                let lines = c.grant_lines(&t);
                self.modal = Some(Modal {
                    title: "Grant files to Claude".into(),
                    color: t.yellow,
                    lines,
                    yes: Some(("grant".into(), vec![Effect::ChatGrant])),
                });
            }
            KeyCode::Char('k') if ctrl => c.scroll_by(1),
            KeyCode::Char('j') if ctrl => c.scroll_by(-1),
            KeyCode::Up => c.scroll_by(1),
            KeyCode::Down => c.scroll_by(-1),
            KeyCode::PageUp => c.scroll_by(10),
            KeyCode::PageDown => c.scroll_by(-10),
            KeyCode::Home => c.scroll_top(),
            KeyCode::End => c.scroll_bottom(),
            KeyCode::Esc => {
                if c.esc() {
                    self.chat = None;
                } else {
                    w.toast("Claude carries on · A brings the chat back");
                }
            }
            // What you typed is what's sent: no box.
            KeyCode::Enter if !c.running() && !c.input.trim().is_empty() => {
                let text = std::mem::take(&mut c.input);
                self.ask_turn(w, text);
            }
            KeyCode::Backspace => {
                c.input.pop();
            }
            KeyCode::Char(ch) if !ctrl && !c.busy() => c.input.push(ch),
            _ => {}
        }
        w.dirty = true;
    }

    /// `y` on the grant box: back up what Claude may write, grant it, and tell Claude.
    pub(crate) fn chat_grant(&mut self, w: &mut Win) {
        use sentry_core::claude::{Access, backup, grantable};
        let offline = w.offline;
        let Some(c) = self.chat.as_mut() else { return };
        for g in c.requests.clone() {
            if g.access == Access::Write && grantable(&g).is_ok() {
                let b = if offline {
                    Ok(std::path::PathBuf::from("(offline: no backup)"))
                } else {
                    backup(&g.path)
                };
                match b {
                    Ok(b) => {
                        c.push(
                            chatmod::Kind::Info,
                            format!("backed up {} → {}", g.path, b.display()),
                        );
                        c.watch(&g.path, b);
                    }
                    Err(e) => {
                        // No backup, no write.
                        c.requests.retain(|r| r != &g);
                        c.push(
                            chatmod::Kind::Err,
                            format!("couldn't back up {}: {e} (not granted)", g.path),
                        );
                    }
                }
            }
        }
        if let Some(text) = c.grant() {
            self.ask_turn(w, text);
        }
    }

    /// After Claude's turn: files it changed (granted, watched) go in the chat and the log.
    pub(crate) fn chat_edits(&mut self, w: &mut Win) {
        let Some(c) = self.chat.as_mut() else { return };
        let key = c.ask.applying().map(|a| a.key.clone());
        let changed = c.changed();
        for (path, b, before, after) in &changed {
            c.push(
                chatmod::Kind::Info,
                format!(
                    "✎ edited {path} ({before} → {after} lines) · backup {}",
                    b.display()
                ),
            );
        }
        for (path, b, before, after) in changed {
            let tags: Vec<String> = std::iter::once(format!("file:{path}"))
                .chain(key.as_ref().map(|k| format!("apply:{k}")))
                .collect();
            let e = sentry_core::maint::log::LogEntry::event(
                &self.scope,
                "edit",
                "edit",
                true,
                &format!(
                    "Claude edited {path} ({before} → {after} lines). Backup: {}",
                    b.display()
                ),
                &tags,
                jiff::Timestamp::now(),
            );
            self.log_event(w, e);
        }
    }

    /// Something done outside a workflow (a reboot, a fix): into the maintenance log.
    pub(crate) fn log_event(&mut self, w: &mut Win, e: sentry_core::maint::log::LogEntry) {
        if !w.offline {
            if let Err(err) = sentry_core::maint::log::write(&e) {
                return w.toast(&format!("couldn't write the maintenance log: {err}"));
            }
            self.shared.log = sentry_core::maint::log::list(&self.scope);
        } else {
            self.shared.log.insert(0, e);
        }
        self.last_change_at = Some(jiff::Timestamp::now());
    }
}

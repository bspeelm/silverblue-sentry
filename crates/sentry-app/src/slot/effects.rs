use super::*;

impl Slot {
    pub(crate) fn apply(&mut self, w: &mut Win, effects: Vec<Effect>, now: Instant) {
        for e in effects {
            match e {
                Effect::Own(own) => {
                    let e = self.target.on_own(&own, &mut self.shared, &cx!(self, w));
                    self.apply(w, e, now);
                }
                Effect::Key(k) => self.on_key(w, k, now),
                Effect::Help => self.show_help(w),
                // Auto: a workflow's values, each with a default, are taken as they are.
                Effect::Prompt(Prompt::Own(o), init)
                    if o.workflow.is_some()
                        && sentry_core::auto::answers(
                            self.auto,
                            &sentry_core::auto::Asked::Values {
                                defaults: o.defaults,
                            },
                        ) =>
                {
                    self.auto_took_values = true;
                    self.submit(w, Prompt::Own(o), init.trim());
                }
                Effect::Prompt(p, init) => w.input = Input::Prompt(p, init),
                Effect::LogEvent(e) => self.log_event(w, *e),
                Effect::PlanClose => self.plan_view = None,
                Effect::ChatNote(text) => {
                    if let Some(c) = self.chat.as_mut() {
                        c.push(chatmod::Kind::Info, text);
                    }
                }
                Effect::Reaudited(gone) => {
                    if let Some(sess) = self.apply.as_mut() {
                        let fx = sess.reaudited(gone);
                        self.apply_fx(w, fx);
                    }
                }
                Effect::SecShow => self.sec_show(w),
                Effect::SecRun => self.sec_run(w),
                Effect::SecItem(id) => self.sec_item(w, &id),
                Effect::SecAnswer(key, said) => self.sec_answer(w, &key, said),
                Effect::Wake(id) => {
                    if w.system.iter().any(|s| s.peer.id == id) {
                        w.outbox.push_back((id, crate::system::Parcel::Wake));
                    }
                }
                Effect::Toast(s) => w.toast(&s),
                Effect::Quit => w.quit = true,
                Effect::Info(title, lines) => {
                    self.modal = Some(Modal {
                        title,
                        color: w.theme.cyan,
                        lines,
                        yes: None,
                    })
                }
                Effect::Goto(t) => self.enter(w, t, now),
                Effect::Wf(c) => self.wf_cmd(w, c),
                Effect::ChatGrant => self.chat_grant(w),
                Effect::ApplyAsk => {
                    if self.shared.wf_entries.is_empty() && !w.offline {
                        self.load_wf_entries();
                    }
                    let apply = self.target.apply_ask(&self.shared, &cx!(self, w));
                    match apply {
                        Some(ask) => self.open_ask(w, ask),
                        None => w.toast("nothing for Claude to apply here"),
                    }
                }
                Effect::AskConsent(ask) => self.open_ask(w, *ask),
                Effect::AskWith(ask, apply) => {
                    self.open_ask(w, *ask);
                    if let Some(c) = self.chat.as_mut() {
                        c.apply_with = Some(*apply);
                    }
                }
                Effect::Confirm(m) => self.modal = Some(m),
                Effect::ConfirmOr(m, no) => {
                    self.modal_no = Some((m.title.clone(), no));
                    self.modal = Some(m);
                }
                Effect::Choose(c) => self.choice = Some(c),
                Effect::PlanDrop(id) => {
                    if let Some(doc) = self.shared.plans.remove(&id)
                        && !w.offline
                    {
                        let _ = sentry_core::maint::plan::close(&doc, PlanStatus::Dropped);
                    }
                    self.plan_view = None;
                    w.toast(&format!("{id}: plan dropped (kept in plans/done/)"));
                }
                // To read: there's only something to open once a session has shown its plan.
                Effect::PlanOpen(id) if !self.shared.plans.contains_key(&id) => {
                    w.toast(&match self.ways.no_plan {
                        Some(say) => say(&id),
                        None => format!("no plan saved for {id} yet: Enter starts it"),
                    })
                }
                Effect::PlanOpen(id) => {
                    self.rec_view = None;
                    self.review_view = None;
                    self.plan_view = Some((id, 0));
                }
                Effect::PlanAgain(id) => {
                    if let Some(doc) = self.shared.plans.remove(&id)
                        && !w.offline
                    {
                        let _ = sentry_core::maint::plan::close(&doc, PlanStatus::Replaced);
                    }
                    self.plan_view = None;
                    self.apply_plan(w, &id, now);
                }
                Effect::PlanApply(id) => self.apply_plan(w, &id, now),
                Effect::PlanDoneByHand(id) => self.plan_done_by_hand(w, &id),
                Effect::Everything => self.everything = !self.everything,
                Effect::SeriesStart(rows) => self.series_start(w, rows),
                Effect::LogOpen(item) => {
                    self.open_records(w, sentry_core::tui::records::Section::Log, item)
                }
                Effect::ReviewOpen => self.review_open(),
                Effect::TaskRemove(id) => {
                    let all = self.all_tasks();
                    let Some(t) = all.into_iter().find(|t| t.id == id) else {
                        return;
                    };
                    if w.offline {
                        self.shared.tasks.retain(|x| x.id != id);
                        return;
                    }
                    match sentry_core::maint::tasks::remove_or_off(
                        &self.scope,
                        &t,
                        &self.shared.tasks,
                    ) {
                        Ok(off) => w.toast(&if off {
                            format!("{} is off (tasks.toml)", t.title)
                        } else {
                            format!("{} is off the list (tasks.toml)", t.title)
                        }),
                        Err(e) => return w.toast(&format!("couldn't change it: {e}")),
                    }
                    self.shared.tasks = sentry_core::maint::tasks::load(&self.scope);
                }
                Effect::TaskDone(id) => self.task_done(w, &id),
                Effect::StartWorkflow(name) => self.wf_start(w, &name, now),
                Effect::ReloadWorkflows => {
                    if !w.offline {
                        self.load_wf_entries();
                    }
                    w.toast("workflows read again");
                }
                Effect::StepLog => match self.run.as_ref().and_then(|s| s.step_log()) {
                    Some((title, text)) => {
                        let mut pane = Pane::new(self.mail.next(), title, String::new());
                        pane.lines = text.lines().map(str::to_string).collect();
                        pane.done = Some(0);
                        self.pane = Some(pane);
                    }
                    None => w.toast("no log for this step yet"),
                },
                Effect::Snooze(id, until) => {
                    let today = jiff::Zoned::now().date();
                    match sentry_core::maint::later::set(&self.scope, &id, until, today) {
                        Ok(()) => {
                            w.toast(&format!("{id}: look again {until} (Records › Later)"));
                            // The recommendations filter on the loaded dates: read them again.
                            self.shared.later = sentry_core::maint::later::load(&self.scope);
                            self.refresh(w, Why::Lists);
                        }
                        Err(e) => w.toast(&format!("couldn't save it: {e}")),
                    }
                }
                Effect::TaskEvery(id) => {
                    let cur = self
                        .all_tasks()
                        .iter()
                        .find(|t| t.id == id)
                        .and_then(|t| t.every)
                        .map_or(String::new(), |d| d.to_string());
                    w.input = Input::Prompt(Prompt::TaskEvery(id), cur);
                }
                Effect::Edit(path) => {
                    let editor = std::env::var("VISUAL")
                        .or_else(|_| std::env::var("EDITOR"))
                        .unwrap_or_else(|_| "vi".into());
                    let mut words = editor.split_whitespace();
                    let cmd = sentry_core::exec::Cmd::local(words.next().unwrap_or("vi"))
                        .args(words)
                        .arg(path.display().to_string())
                        .timeout(None);
                    self.suspend = Some(Suspend {
                        cmd,
                        banner: String::new(),
                        then: Vec::new(),
                        own: None,
                    });
                    self.suspend_edit = true;
                }
                Effect::Suspend(s) => self.suspend = Some(s),
                Effect::Run(spec) => self.start_run(w, spec),
                Effect::RootRead(r) => {
                    let what = r.what.clone();
                    self.with_root(w, what, root::Waiting::Read(r));
                }
                Effect::Forget => {
                    let held = self.forget();
                    w.toast(if held {
                        "the sudo password is forgotten"
                    } else {
                        "no sudo password is held"
                    });
                }
                Effect::Logs(title, cmd) => {
                    let id = self.mail.next();
                    self.pane = Some(Pane::new(id, title, cmd.display()));
                    if !w.offline {
                        self.mail.text(id, cmd);
                    }
                }
                Effect::AuditEnded(ok) => self.series_audit_ended(w, ok),
                Effect::Loaded => self.review_at_start(w),
                Effect::Rebooted(msg) => {
                    if let Some(s) = self.run.as_mut() {
                        s.after_reboot();
                    }
                    self.wf_auto(w);
                    if let Some(pane) = self.pane.as_mut() {
                        pane.lines.push_back(msg.clone());
                    }
                    w.toast(&msg);
                }
                Effect::PaneLine(line) => {
                    if let Some(p) = self.pane.as_mut() {
                        p.lines.push_back(line);
                    }
                }
                Effect::RunNote(text, kind) => {
                    if let Some(s) = self.run.as_mut() {
                        s.push(text, kind);
                    }
                }
                Effect::WriterFollow(prompt) => self.writer_follow(w, prompt),
                Effect::ChatTurn(text) => {
                    if self.chat.is_some() {
                        self.ask_turn(w, text);
                    } else {
                        w.toast("the conversation is closed: the output wasn't sent");
                    }
                }
            }
        }
        w.dirty = true;
    }

    /// A command for the pane: one that needs root first gets it (the password is asked for
    /// once, if sudo wants one and none is held).
    pub(crate) fn start_run(&mut self, w: &mut Win, spec: RunSpec) {
        if spec.root.is_some() {
            let what = format!("for {}", spec.title.to_lowercase());
            return self.with_root(w, what, root::Waiting::Run(spec));
        }
        self.start_pane(w, spec, None);
    }

    /// `shown`: the command line the pane shows, when it isn't the command's own (one run
    /// through the sudo wrapper shows what was asked for, never the wrapper).
    pub(crate) fn start_pane(&mut self, w: &mut Win, spec: RunSpec, shown: Option<String>) {
        if spec.reboot {
            let e = sentry_core::maint::log::LogEntry::event(
                &self.scope,
                "reboot",
                "reboot",
                true,
                &spec.title,
                &[],
                jiff::Timestamp::now(),
            );
            self.log_event(w, e);
        }
        let id = self.mail.next();
        let mut pane = Pane::new(id, spec.title, shown.unwrap_or_else(|| spec.cmd.display()));
        pane.then = spec.then;
        pane.queue = spec.queue.into();
        pane.end = spec.end;
        if !w.offline {
            match self.mail.stream(id, &spec.cmd) {
                Ok(pid) => pane.pid = Some(pid),
                Err(e) => {
                    let (before, code) = self.ways.pane_failed;
                    pane.lines.push_back(format!("{before}{e}"));
                    pane.done = Some(code);
                    pane.took = Some(Duration::ZERO);
                }
            }
        }
        self.pane = Some(pane);
    }
}

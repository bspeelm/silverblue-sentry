use super::*;

impl Slot {
    pub(crate) fn writing_review(&self) -> bool {
        self.writer
            .as_ref()
            .is_some_and(|w| w.review.is_some() && w.running())
    }

    /// Claude writes (a plan or a review) in the background; its view opens.
    pub(crate) fn start_writer(
        &mut self,
        w: &mut Win,
        mut wr: Writer,
        prompt: String,
        resume: Option<String>,
    ) {
        match self.writer.as_ref().filter(|x| x.running()) {
            // What you ask for takes the place of a review the app started by itself.
            Some(x) if x.quiet && !wr.quiet => {
                if let Some((_, pid)) = x.live.filter(|(_, pid)| *pid != 0) {
                    let _ = kill(pid);
                }
                self.writer = None;
            }
            Some(_) if wr.quiet => return,
            Some(_) => {
                return w.toast("Claude is already writing: wait for it, or C-c in its view");
            }
            None => {}
        }
        let profile = if wr.review.is_some() {
            if !wr.quiet {
                self.review_view
                    .get_or_insert_with(sentry_core::tui::reviewview::ReviewView::show)
                    .brief = false;
            }
            self.target.profile(ProfileFor::Review, &[])
        } else {
            self.plan_view = Some((wr.item.clone(), 0));
            self.target.profile(ProfileFor::Plan, &[])
        };
        let cmd = claude::turn_cmd_with(&prompt, resume.as_deref(), &profile);
        let rid = self.mail.next();
        if w.offline {
            wr.live = Some((rid, 0));
            self.writer = Some(wr);
            return;
        }
        match self.mail.stream(rid, &cmd) {
            Ok(pid) => {
                wr.live = Some((rid, pid));
                self.writer = Some(wr);
            }
            Err(e) => w.toast(&format!("couldn't start claude: {e}")),
        }
    }

    /// Another turn for the plan being written (in its Claude session).
    pub(crate) fn writer_follow(&mut self, w: &mut Win, prompt: String) {
        match self.writer.as_ref() {
            Some(wr) if !wr.running() => {
                let session = wr.session.clone();
                let next = match &wr.review {
                    Some(r) => Writer::review(r.clone()),
                    None => Writer::new(&wr.item, wr.doc.clone()),
                };
                self.start_writer(w, next, prompt, session);
            }
            _ => w.toast("it isn't being written any more"),
        }
    }

    /// `R` on Maintenance: the review window. A review with changes still to apply shows
    /// them; otherwise the brief, and Enter starts a new one.
    pub(crate) fn review_open(&mut self) {
        use sentry_core::tui::reviewview::ReviewView;
        self.rec_view = None;
        self.plan_view = None;
        self.review_view = Some(if self.writing_review() {
            ReviewView::show()
        } else {
            ReviewView::open(self.shared.review.as_ref())
        });
    }

    /// Everything on Maintenance a review's changes may name, and `f` with it.
    pub(crate) fn with_known<R>(
        &self,
        w: &Win,
        f: impl FnOnce(&sentry_core::maint::changes::Known) -> R,
    ) -> R {
        let (mut f, mut out) = (Some(f), None);
        self.target
            .with_known(&self.shared, &cx!(self, w), &mut |k| {
                if let Some(f) = f.take() {
                    out = Some(f(k));
                }
            });
        out.expect("the target answers with what it knows")
    }

    /// What a review is sent.
    pub(crate) fn review_prompt(&self, w: &Win) -> String {
        let changes = self.with_known(w, |k| sentry_core::maint::changes::request_section(k, true));
        self.target
            .review_request(None, &changes, &self.shared, &cx!(self, w))
    }

    /// Enter on the brief: Claude writes the review.
    pub(crate) fn review_start(&mut self, w: &mut Win) {
        if !claude::available() {
            return w.toast("reviews are written by Claude Code, which isn't installed");
        }
        let prompt = self.review_prompt(w);
        let doc = sentry_core::maint::review::ReviewDoc::new(&self.scope);
        self.start_writer(w, Writer::review(doc), prompt, None);
    }

    /// A review the app starts by itself, in the background: after a run that ended well
    /// (`run`), or at start. Nothing opens while Claude writes.
    pub(crate) fn review_auto(
        &mut self,
        w: &mut Win,
        run: Option<sentry_core::maint::log::LogEntry>,
    ) {
        use sentry_core::maint::review;
        if !claude::available() || self.writer.as_ref().is_some_and(|w| w.running()) {
            return;
        }
        let changes = self.with_known(w, |k| sentry_core::maint::changes::request_section(k, true));
        let ask = match &run {
            Some(r) => review::run_ask(r),
            None => review::start_ask(),
        };
        let prompt = self
            .target
            .review_request(Some(&ask), &changes, &self.shared, &cx!(self, w));
        let mut doc = review::ReviewDoc::new(&self.scope);
        doc.head.origin = if run.is_some() {
            review::RUN
        } else {
            review::START
        }
        .into();
        doc.head.run = run.map(|r| r.file_name());
        let mut wr = Writer::review(doc);
        wr.quiet = true;
        self.start_writer(w, wr, prompt, None);
    }

    /// The run that just ended, once its note is given or skipped: Claude checks which
    /// tasks it did. Not when none is due (the ones that run this workflow are done already).
    pub(crate) fn review_after_run(&mut self, w: &mut Win) {
        let Some(mut run) = self.review_run.take() else {
            return;
        };
        if !self.auto_review.after_run {
            return;
        }
        // With its note, when one was given.
        if let Some(l) = self
            .last_log
            .as_ref()
            .filter(|l| l.head.run == run.head.run)
        {
            run = l.clone();
        }
        let now = jiff::Timestamp::now();
        let due = self
            .all_tasks()
            .iter()
            .any(|t| sentry_core::maint::tasks::due(t, &self.shared.log, None, now));
        if due {
            self.review_auto(w, Some(run));
        }
    }

    /// The review at start, once what it's told about is read (the target says when:
    /// `Effect::Loaded`).
    pub(crate) fn review_at_start(&mut self, w: &mut Win) {
        if !self.start_check {
            return;
        }
        self.start_check = false;
        if self.review_run.is_some() || w.input.is_open() {
            return;
        }
        self.review_auto(w, None);
    }

    /// A review the app started by itself is written: kept only when it proposes
    /// something. After a run it opens (if nothing else is); the one at start only says so.
    pub(crate) fn auto_review_ended(
        &mut self,
        w: &mut Win,
        mut rd: sentry_core::maint::review::ReviewDoc,
        answer: Option<&str>,
    ) {
        let after_run = rd.head.origin == sentry_core::maint::review::RUN;
        self.writer = None;
        let Some(a) = answer.filter(|a| !a.trim().is_empty() && !self.target.waits_for_reads(a))
        else {
            if after_run {
                w.toast(
                    "no review of the tasks after the run: Claude gave no answer (R asks again)",
                );
            }
            return;
        };
        let today = jiff::Zoned::now().date();
        self.with_known(w, |k| rd.take_answer(a, k, today));
        let n = rd.open().len();
        if n == 0 {
            if after_run {
                w.toast("the run did none of the tasks still due");
            }
            return;
        }
        if !w.offline
            && let Err(e) = sentry_core::maint::review::save(&rd)
        {
            return w.toast(&format!("couldn't save the review: {e}"));
        }
        self.shared.review = Some(rd);
        let nothing_open = matches!(frame::layer(&self.open(w)), Layer::Screen);
        if after_run && nothing_open {
            self.review_view = Some(sentry_core::tui::reviewview::ReviewView::show());
            w.toast(&format!(
                "after the run: {} to the tasks (Enter applies)",
                sentry_core::tui::reviewview::changes_word(n)
            ));
        } else if after_run {
            w.toast(&format!(
                "after the run: {} to the tasks (R shows them)",
                sentry_core::tui::reviewview::changes_word(n)
            ));
        } else {
            w.toast(&format!(
                "since last time: {} to the tasks (R shows them)",
                sentry_core::tui::reviewview::changes_word(n)
            ));
        }
    }

    /// Enter on a review's changes: those ticked are applied together, the rest skipped,
    /// and the log says what was done.
    pub(crate) fn review_apply(&mut self, w: &mut Win) {
        use sentry_core::maint::{changes, later, log, tasks as tk};
        let Some(mut rd) = self.shared.review.clone() else {
            return;
        };
        let (name, app) = (self.scope.clone(), self.app);
        let derived = self.target.derived_tasks(&self.shared);
        let mut tasks = self.shared.tasks.clone();
        let mut snoozes = self.shared.later.clone();
        // What only this kind of target has (the items it tracks…), settled with the rest.
        let mut own = self.target.changes(&self.shared, &cx!(self, w));
        let now = jiff::Timestamp::now();
        // The run a review after a run is about: it dates the tasks found done.
        let by = rd.head.run.as_ref().and_then(|f| {
            self.shared
                .log
                .iter()
                .find(|e| &e.file_name() == f)
                .cloned()
        });
        let all = tk::effective(&tasks, derived.clone());
        let mut found_done = Vec::new();
        let (done, skipped, failed) = changes::settle(&mut rd.head.changes, |c| {
            let r = changes::apply(c, &mut tasks, &mut snoozes, &derived, now)
                .or_else(|| own.apply(c))
                .unwrap_or_else(|| Err(format!("not something {app} can change")));
            if let (Ok(_), Some(id)) = (&r, c.done_task()) {
                let title = all.iter().find(|t| t.id == id).map_or(id, |t| &t.title);
                found_done.push(log::LogEntry::task_found_done(
                    &name,
                    id,
                    title,
                    &c.why,
                    by.as_ref(),
                ));
            }
            r
        });
        if !w.offline {
            let saved = tk::save(&name, &tasks)
                .and_then(|_| later::replace(&name, &snoozes))
                .map_err(|e| e.to_string())
                .and_then(|_| own.save())
                .and_then(|_| {
                    sentry_core::maint::review::save(&rd)
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                });
            if let Err(e) = saved {
                return w.toast(&format!("couldn't apply the changes: {e}"));
            }
        }
        self.shared.tasks = tasks;
        self.shared.later = snoozes;
        for e in found_done {
            if w.offline {
                self.shared.log.insert(0, e);
            } else if let Err(err) = log::write(&e) {
                w.toast(&format!("couldn't write the maintenance log: {err}"));
            }
        }
        if done + failed > 0 {
            let entry = log::LogEntry::event(
                &name,
                "review",
                "review",
                failed == 0,
                &changes::summary(&rd.head.changes),
                &[format!("review:{}", rd.file_name())],
                now,
            );
            if w.offline {
                self.shared.log.insert(0, entry);
            } else if let Err(e) = log::write(&entry) {
                w.toast(&format!("couldn't write the maintenance log: {e}"));
            } else {
                self.shared.log = log::list(&name);
            }
        }
        self.shared.review = Some(rd);
        // What changed on the target's side: it takes that in; else its lists are read again.
        let fx = own.done();
        if !fx.is_empty() {
            self.apply(w, fx, Instant::now());
        } else if !w.offline {
            self.refresh(w, Why::Lists);
        }
        self.settle(w, Settle::Lists);
        w.toast(&format!(
            "review: {}",
            sentry_core::tui::reviewview::outcome(done, skipped, failed)
        ));
    }

    /// Keys in the Review window: its own, and what they ask for.
    pub(crate) fn review_view_key(&mut self, w: &mut Win, k: KeyEvent) {
        use sentry_core::tui::reviewview::Fx;
        w.dirty = true;
        let writing = self.writing_review();
        let Some(v) = self.review_view.as_mut() else {
            return;
        };
        match v.key(k, self.shared.review.as_mut(), writing) {
            Fx::None => {}
            Fx::Close => self.review_view = None,
            Fx::Start => self.review_start(w),
            Fx::Apply => self.review_apply(w),
            Fx::Stop => {
                if let Some(pid) = self
                    .writer
                    .as_ref()
                    .filter(|w| w.review.is_some())
                    .and_then(|w| w.live.map(|(_, p)| p))
                {
                    let _ = kill(pid);
                    w.toast("stopped");
                }
            }
        }
    }

    /// A task from an apply session's follow-up: into `tasks.toml`.
    pub(crate) fn task_add(&mut self, w: &mut Win, task: sentry_core::maint::tasks::Task) {
        let mut task = task;
        task.added = Some(jiff::Timestamp::now());
        if !w.offline
            && let Err(e) = sentry_core::maint::tasks::add(&self.scope, task.clone())
        {
            return w.toast(&format!("couldn't add it: {e}"));
        }
        let (id, title) = (task.id.clone(), task.title.clone());
        self.shared.tasks.retain(|t| t.id != id);
        self.shared.tasks.push(task);
        w.toast(&format!("added to Maintenance (6): {title}"));
    }

    /// A task done by hand: logged now (tagged `task:<id>`, which takes it off the list),
    /// then the note box, as for a plan done by hand.
    pub(crate) fn task_done(&mut self, w: &mut Win, id: &str) {
        let title = self
            .all_tasks()
            .into_iter()
            .find(|t| t.id == id)
            .map_or(id.to_string(), |t| t.title);
        let entry = sentry_core::maint::log::LogEntry::task(&self.scope, id, &title, None);
        if !w.offline {
            if let Err(e) = sentry_core::maint::log::write(&entry) {
                return w.toast(&format!("couldn't write the maintenance log: {e}"));
            }
            self.shared.log = sentry_core::maint::log::list(&self.scope);
        } else {
            self.shared.log.insert(0, entry.clone());
        }
        self.last_change_at = Some(jiff::Timestamp::now());
        w.input = Input::Prompt(Prompt::LogNote(Box::new(entry)), String::new());
    }

    /// After a turn: what Claude asked to read that only the user can allow, if the target
    /// has such a thing. `waiting`: the answer waits for them.
    pub fn offer_reads(&mut self, w: &mut Win, to: ReadsFor, waiting: bool) {
        let e = self.target.offer_reads(to, waiting, &cx!(self, w));
        self.apply(w, e, Instant::now());
    }

    /// The writer's turn ended: save its answer as the plan, then any reads it asked for.
    pub(crate) fn writer_turn_ended(&mut self, w: &mut Win) {
        if let Some(mut rd) = self.writer.as_ref().and_then(|x| x.review.clone()) {
            let (answer, err, session) = self
                .writer
                .as_ref()
                .map(|x| (x.answer.clone(), x.err.clone(), x.session.clone()))
                .unwrap_or_default();
            rd.head.session = session.or(rd.head.session);
            if self.writer.as_ref().is_some_and(|x| x.quiet) {
                return self.auto_review_ended(w, rd, answer.as_deref());
            }
            // Waiting for reads that need root: no review yet; ask for them.
            if answer
                .as_deref()
                .is_some_and(|a| self.target.waits_for_reads(a))
            {
                if let Some(wr) = self.writer.as_mut() {
                    wr.review = Some(rd);
                    wr.doing = "waiting for reads that need root".into();
                }
                return self.offer_reads(w, ReadsFor::Plan, true);
            }
            let msg = match (&answer, &err) {
                (Some(a), _) if !a.trim().is_empty() => {
                    let today = jiff::Zoned::now().date();
                    self.with_known(w, |k| rd.take_answer(a, k, today));
                    match rd.open().len() {
                        0 => "the review is saved: no changes to the list".to_string(),
                        n => format!("the review is saved: {n} changes to apply (Enter)"),
                    }
                }
                (_, err) => format!(
                    "no review: {}",
                    err.clone()
                        .unwrap_or_else(|| "Claude gave no answer".into())
                ),
            };
            if let Some(wr) = self.writer.as_mut() {
                wr.review = Some(rd.clone());
            }
            if rd.head.status == PlanStatus::Ready {
                if !w.offline
                    && let Err(e) = sentry_core::maint::review::save(&rd)
                {
                    return w.toast(&format!("couldn't save the review: {e}"));
                }
                self.shared.review = Some(rd);
                if let Some(v) = self.review_view.as_mut() {
                    *v = sentry_core::tui::reviewview::ReviewView::show();
                }
            }
            w.toast(&msg);
            return self.offer_reads(w, ReadsFor::Plan, false);
        }
        let waits = self
            .writer
            .as_ref()
            .and_then(|x| x.answer.as_deref())
            .is_some_and(|a| self.target.waits_for_reads(a));
        let Some(wr) = self.writer.as_mut() else {
            return;
        };
        let mut doc = wr.doc.clone();
        doc.head.session = wr.session.clone().or(doc.head.session);
        // Waiting for reads that need root: no plan yet; ask for them (with nothing queued
        // after all, the target has it write the plan).
        if waits {
            wr.doc.head.session = wr.session.clone().or(wr.doc.head.session.clone());
            wr.doing = "waiting for reads that need root".into();
            return self.offer_reads(w, ReadsFor::Plan, true);
        }
        let msg = match (&wr.answer, &wr.err) {
            (Some(a), _) if !a.trim().is_empty() => {
                doc.take_answer(a);
                match doc.head.status {
                    PlanStatus::Wait => format!("plan for {}: Claude advises waiting", wr.item),
                    _ => format!(
                        "plan for {} saved: → {} · Enter applies it",
                        wr.item,
                        doc.head.to.as_deref().unwrap_or("retire")
                    ),
                }
            }
            (_, err) => {
                // A revision that failed keeps the plan it had.
                if doc.body.trim().is_empty() {
                    doc.head.status = PlanStatus::Failed;
                    doc.body = format!(
                        "Claude didn't write the plan: {}",
                        err.clone().unwrap_or_else(|| "no answer".into())
                    );
                }
                format!(
                    "no plan for {}: {}",
                    wr.item,
                    err.clone()
                        .unwrap_or_else(|| "Claude gave no answer".into())
                )
            }
        };
        wr.doc = doc.clone();
        let item = wr.item.clone();
        if !w.offline
            && let Err(e) = sentry_core::maint::plan::save(&doc)
        {
            return w.toast(&format!("couldn't save the plan: {e}"));
        }
        self.shared.plans.insert(item.clone(), doc);
        w.toast(&msg);
        self.offer_reads(w, ReadsFor::Plan, false);
        // Unless reads are being offered (the plan may still change), the series goes on.
        if self.modal.is_none() {
            self.series_plan_written(w, &item);
        }
    }
}

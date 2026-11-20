use super::*;

impl Slot {
    // ---------------------------------------------------------------- the series

    /// The series waits for this.
    pub(crate) fn series_waits(&self, w: &sentry_core::maint::series::Wait) -> bool {
        self.series.as_ref().is_some_and(|s| &s.wait == w)
    }

    /// Enter with rows ticked: do them one after another.
    pub(crate) fn series_start(&mut self, w: &mut Win, rows: Vec<(String, String)>) {
        if let Some(sr) = &self.series {
            let line = format!("{} · A shows it", sr.line());
            return w.toast(&line);
        }
        if self.apply.is_some() {
            return w.toast("an apply session is open: finish it first (A shows it)");
        }
        if self.run.as_ref().is_some_and(|s| !s.done()) {
            return w.toast("a workflow run is in progress: finish it first (0)");
        }
        if self.ways.series_waits_writer
            && self
                .writer
                .as_ref()
                .is_some_and(|w| w.running() && !w.quiet)
        {
            return w.toast("Claude is writing: wait for it, or C-c in its view");
        }
        self.series = Some(sentry_core::maint::series::Series::new(rows));
        self.series_planned = None;
        self.series_go(w);
    }

    /// Open what the row the series is at needs; rows that left the list are passed over.
    pub(crate) fn series_go(&mut self, w: &mut Win) {
        use sentry_core::maint::series::{Outcome, Wait};
        if self.shared.wf_entries.is_empty() && !w.offline {
            self.load_wf_entries();
        }
        loop {
            let Some(sr) = self.series.as_mut() else {
                return;
            };
            let Some(cur) = sr.current().cloned() else {
                return self.series_end(w);
            };
            let pos = sr.pos();
            sr.wait = Wait::Nothing;
            let step = self
                .target
                .series_step(&cur.key, &self.shared, &cx!(self, w));
            let Some(sr) = self.series.as_mut() else {
                return;
            };
            match step {
                None => {
                    sr.ended(Outcome::Skipped("no longer on the list".into()));
                }
                Some(SeriesStep::Session(ask)) => {
                    sr.wait = Wait::Session;
                    let (secret, ok) = (std::mem::take(&mut sr.secret), sr.secret_ok);
                    let mut sess = sentry_core::apply::session::Session::new(ask);
                    sess.chat.privacy = self.target.ident().session_privacy.clone();
                    let fx = sess.start_in_series(pos, secret, ok);
                    if self.ways.series_closes_plan {
                        self.plan_view = None;
                    }
                    self.apply = Some(sess);
                    self.apply_fx(w, fx);
                    return;
                }
                // Its plan first (the version is Claude's to recommend); once it's ready the
                // same row is an apply session.
                Some(SeriesStep::Plan(item, _))
                    if self.series_planned.as_deref() == Some(item.as_str()) =>
                {
                    return self.series_stop(w);
                }
                Some(SeriesStep::Plan(item, doc)) => {
                    sr.wait = Wait::Plan(item.clone());
                    self.series_planned = Some(item.clone());
                    self.ask_for_plan(w, item.clone(), doc);
                    self.series_answer_box(w);
                    let writing = self
                        .writer
                        .as_ref()
                        .is_some_and(|w| w.review.is_none() && w.item == item && w.running());
                    if !writing {
                        self.series_stop(w);
                    }
                    return;
                }
                Some(SeriesStep::Workflow(name)) => {
                    sr.wait = Wait::Workflow(name.clone());
                    self.wf_start(w, &name, w.at);
                    self.series_answer_box(w);
                    let asked = self.asking_vars(w).is_some();
                    let going = self
                        .run
                        .as_ref()
                        .is_some_and(|s| s.wf().name == name && !s.done());
                    if !asked && !going {
                        self.series_stop(w);
                    }
                    return;
                }
                Some(SeriesStep::Audit) => {
                    sr.wait = Wait::Audit;
                    self.refresh(w, Why::Audit);
                    if w.offline {
                        // Nothing is fetched offline (tests): the audit counts as run.
                        self.series_audit_ended(w, true);
                    }
                    return;
                }
            }
        }
    }

    /// The series' Enter was the start: a box that only asks whether to start is answered.
    /// One with nothing to confirm says why it can't, and stays.
    pub(crate) fn series_answer_box(&mut self, w: &mut Win) {
        if self.modal.as_ref().is_some_and(|m| m.yes.is_some())
            && let Some((_, effects)) = self.modal.take().and_then(|m| m.yes)
        {
            self.apply(w, effects, w.at);
        }
    }

    /// The series' session is over (done, or the user goes on): the next row.
    pub(crate) fn series_next(&mut self, w: &mut Win) {
        use sentry_core::apply::session::{End, Phase};
        use sentry_core::maint::series::Outcome;
        let Some(mut sess) = self.apply.take() else {
            return;
        };
        let Some(sr) = self.series.as_mut() else {
            return;
        };
        (sr.secret, sr.secret_ok) = sess.take_secret();
        sr.ended(match sess.phase {
            Phase::Settled(End::Done) => Outcome::Done,
            Phase::Settled(End::Failed) => Outcome::Failed("it failed".into()),
            Phase::Settled(End::Stopped) => Outcome::Failed("stopped".into()),
            _ => Outcome::Failed("not verified".into()),
        });
        if self.ways.series_closes_plan {
            self.plan_view = None;
        }
        self.series_go(w);
    }

    /// A workflow run ended and was logged. True: a series is going on, so nothing is asked
    /// about the run now (and if it was the series' row, the series went on or stopped).
    pub(crate) fn series_run_ended(&mut self, w: &mut Win, workflow: &str, done: bool) -> bool {
        use sentry_core::maint::series::{Outcome, Wait};
        if self.series.is_none() {
            return false;
        }
        if !self.series_waits(&Wait::Workflow(workflow.to_string())) {
            // A run a session's plan started: the session carries on by itself.
            return true;
        }
        if !done {
            self.series_stop(w);
            return false;
        }
        // Done: the run closes, and the next row opens over Maintenance.
        self.run = None;
        if !w.offline {
            self.load_wf_entries();
        }
        self.enter(w, ScreenId::Maint, w.at);
        if let Some(sr) = self.series.as_mut() {
            sr.ended(Outcome::Done);
        }
        self.series_go(w);
        true
    }

    /// The series' plan was written: ready, its session; advising to wait, the next row.
    pub(crate) fn series_plan_written(&mut self, w: &mut Win, item: &str) {
        use sentry_core::maint::series::{Outcome, Wait};
        if !self.series_waits(&Wait::Plan(item.to_string())) {
            return;
        }
        match self.shared.plans.get(item).map(|d| d.head.status) {
            // The same row again: with its plan ready it's an apply session.
            Some(PlanStatus::Ready) => self.series_go(w),
            Some(PlanStatus::Wait) => {
                if let Some(sr) = self.series.as_mut() {
                    sr.ended(Outcome::Skipped("its plan says wait".into()));
                }
                self.plan_view = None;
                self.series_go(w);
            }
            _ => self.series_stop(w),
        }
    }

    /// The series' audit ended.
    pub(crate) fn series_audit_ended(&mut self, w: &mut Win, ok: bool) {
        use sentry_core::maint::series::{Outcome, Wait};
        if !self.series_waits(&Wait::Audit) {
            return;
        }
        if !ok {
            return self.series_stop(w);
        }
        if self.ways.audit_in_pane {
            self.pane = None;
        }
        if let Some(sr) = self.series.as_mut() {
            sr.ended(Outcome::Done);
        }
        self.series_go(w);
    }

    /// Through: what's done leaves the ticks, the rest is said; then what a run would have
    /// asked for by itself (what the target offers then, the review).
    pub(crate) fn series_end(&mut self, w: &mut Win) {
        let Some(mut sr) = self.series.take() else {
            return;
        };
        sr.wipe();
        self.settle(w, Settle::Ticks(sr.left().into_iter().collect()));
        w.toast(&sr.summary());
        self.settled(w);
        self.review_after_run(w);
    }

    /// Stopped before its end (a row closed or failed to start): what's left stays ticked.
    pub(crate) fn series_stop(&mut self, w: &mut Win) {
        let Some(mut sr) = self.series.take() else {
            return;
        };
        sr.wipe();
        self.settle(w, Settle::Ticks(sr.left().into_iter().collect()));
        w.toast(&sr.stopped());
        self.settled(w);
        self.review_after_run(w);
    }
}

use super::*;

impl Slot {
    pub(crate) fn start(&mut self, w: &mut Win, now: Instant) {
        let cfg = (!w.offline).then(|| sentry_core::config::Config::load().0);
        if cfg.is_some() {
            // Before a target moves old files of its own: they may hold what these do now.
            self.shared.later = sentry_core::maint::later::load(&self.scope);
            self.shared.baseline = sentry_core::baseline::BaselineFile::load(&self.scope);
        }
        let e = self.target.start(&mut self.shared, &cx!(self, w));
        self.apply(w, e, now);
        if let Some(cfg) = cfg {
            self.auto_review = cfg.review;
            if self.auto_review.at_start && claude::available() {
                self.start_check = true;
                self.refresh(w, Why::Lists);
            }
            sentry_core::maint::retention::purge(
                &self.scope,
                &self.target.ident().runs,
                &cfg.retention,
                jiff::Timestamp::now(),
            );
            self.run = self.target.resume_run();
            // A run left in progress: show it (its auto steps wait until it's open).
            if self.run.is_some() {
                self.screen = ScreenId::Upgrade;
            }
            self.shared.plans = sentry_core::maint::plan::list(&self.scope);
            self.shared.review = sentry_core::maint::review::latest(&self.scope);
            self.shared.tasks = sentry_core::maint::tasks::load(&self.scope);
            self.shared.log = sentry_core::maint::log::list(&self.scope);
            self.last_change_at = self
                .shared
                .log
                .first()
                .and_then(|e| e.head.ended.or(e.head.started));
            self.load_wf_entries();
        }
        self.enter(w, self.screen, now);
    }

    /// Switch screens; what the screen shows is fetched right away, and from then on only
    /// what it polls.
    pub(crate) fn enter(&mut self, w: &mut Win, id: ScreenId, now: Instant) {
        let from = self.screen;
        self.screen = id;
        if id == ScreenId::Upgrade {
            if self.shared.wf_entries.is_empty() && !w.offline {
                self.load_wf_entries();
            }
            // Its auto steps may run now that it's in view.
            if let Some(s) = self.run.as_mut() {
                s.arm();
            }
        }
        let e = self.target.enter(from, now, &self.shared, &cx!(self, w));
        self.apply(w, e, now);
        self.tick(w, now);
        w.dirty = true;
    }

    /// A chat or an apply session working in view: its clocks tick.
    fn talking(&self) -> bool {
        self.chat.as_ref().is_some_and(|c| c.running() && !c.hidden)
            || self
                .apply
                .as_ref()
                .is_some_and(|s| s.busy() && !s.chat.hidden)
    }

    pub(crate) fn tick(&mut self, w: &mut Win, now: Instant) {
        if self.talking() {
            w.dirty = true;
        }
        if w.toast.as_ref().is_some_and(|t| t.over(now)) {
            w.toast = None;
            w.dirty = true;
        }
        if self.screen == ScreenId::Upgrade {
            self.wf_auto(w);
        }
        // Only what the screen in view polls (and what the target waits for).
        self.target.due(now, &cx!(self, w));
    }

    /// When this slot next has something to do by itself.
    pub(crate) fn next_due(&self, now: Instant) -> Option<Instant> {
        let mut due = self.target.next_due();
        if self.talking() {
            let t = now + Duration::from_secs(1);
            due = Some(due.map_or(t, |d| d.min(t)));
        }
        due
    }

    /// Something one of the target's threads read.
    pub(crate) fn on_data(&mut self, w: &mut Win, data: Box<dyn std::any::Any + Send>) {
        let e = self.target.on_data(data, &mut self.shared, &cx!(self, w));
        self.apply(w, e, Instant::now());
        self.settle(w, Settle::Lists);
        w.dirty = true;
    }

    /// Output fetched for the pane (logs).
    pub(crate) fn on_text(&mut self, w: &mut Win, id: u64, res: Result<String, String>) {
        if let Some(p) = self.pane.as_mut().filter(|p| p.id == id) {
            match res {
                Ok(text) => p.lines.extend(text.lines().map(str::to_string)),
                Err(e) => p.lines.push_back(format!("✗ {e}")),
            }
            p.done = Some(0);
            // Logs open at their end, like `less +G`.
            p.scroll = 0;
        }
        w.dirty = true;
    }

    /// A line or the exit of a stream: whichever of the slot's it belongs to.
    pub(crate) fn on_run(&mut self, w: &mut Win, id: u64, m: StreamMsg) {
        if let Some(wr) = self.writer.as_mut()
            && wr.live.is_some_and(|(wid, _)| wid == id)
        {
            match m {
                StreamMsg::Line {
                    stderr: false,
                    text,
                } => {
                    for e in claude::parse_line(&text) {
                        wr.on_event(e);
                    }
                }
                StreamMsg::Line { .. } => {}
                StreamMsg::Exit { code, .. } => {
                    wr.live = None;
                    if wr.answer.is_none() && wr.err.is_none() && code != 0 {
                        wr.err = Some(format!("claude exited with {code}"));
                    }
                    self.writer_turn_ended(w);
                }
            }
            w.dirty = true;
            return;
        }
        if self.apply_stream(w, id, &m) {
            w.dirty = true;
            return;
        }
        if let Some(c) = self.chat.as_mut()
            && c.live.is_some_and(|(cid, _)| cid == id)
        {
            match m {
                StreamMsg::Line {
                    stderr: false,
                    text,
                } => {
                    for e in claude::parse_line(&text) {
                        c.on_event(e);
                    }
                }
                StreamMsg::Line { stderr: true, text } => c.on_raw(text),
                StreamMsg::Exit { code, .. } => {
                    c.on_exit(code);
                    if c.hidden {
                        w.toast("Claude answered · A opens the chat");
                    }
                    self.chat_edits(w);
                    let e = self
                        .target
                        .offer_reads(ReadsFor::Chat, false, &cx!(self, w));
                    self.apply(w, e, Instant::now());
                }
            }
            w.dirty = true;
            return;
        }
        if let Some(s) = self.run.as_mut()
            && let Some(l) = s.live().filter(|l| l.id == id)
        {
            let idx = l.idx;
            match m {
                StreamMsg::Line { text, .. } => s.on_line(&text),
                StreamMsg::Exit { code, .. } => {
                    s.on_exit(idx, code);
                    // What the step's end means for the host (sudo changed under us…).
                    if let Some(s) = self.run.as_deref() {
                        self.target.step_ended(s, &cx!(self, w, norun));
                    }
                    self.wf_auto(w);
                }
            }
            w.dirty = true;
            return;
        }
        if let Some(e) = self.target.on_stream(id, &m, &cx!(self, w)) {
            self.apply(w, e, Instant::now());
            w.dirty = true;
            return;
        }
        let Some(p) = self.pane.as_mut().filter(|p| p.id == id) else {
            return;
        };
        match m {
            StreamMsg::Line { text, .. } => {
                if p.lines.len() == PANE_LINES {
                    p.lines.pop_front();
                }
                p.lines.push_back(text);
            }
            StreamMsg::Exit { code, .. } => {
                p.done = Some(code);
                p.pid = None;
                let then = p.then.clone();
                self.apply(w, then, Instant::now());
            }
        }
        w.dirty = true;
    }

    /// What's in front now, for [`frame::layer`]: who gets a key or a paste, and whose keys
    /// the key bar names.
    pub(crate) fn open(&self, w: &Win) -> frame::Open {
        frame::Open {
            run: self.pane.is_some(),
            choice: self.choice.is_some(),
            modal: self.modal.is_some() || w.modal.is_some(),
            apply: self.apply.as_ref().is_some_and(|s| !s.chat.hidden),
            chat: self.chat.as_ref().is_some_and(|c| !c.hidden),
            input: w.input.is_open(),
            docs: self.rec_view.is_some() || self.plan_view.is_some() || self.review_view.is_some(),
        }
    }

    /// A paste goes to the input that has the focus, whole; with none, it does nothing (its
    /// letters must never act as keys).
    pub(crate) fn on_paste(&mut self, w: &mut Win, text: &str) {
        w.dirty = true;
        match frame::layer(&self.open(w)) {
            Layer::Apply => {
                if let Some(s) = self.apply.as_mut() {
                    s.paste(text);
                }
            }
            Layer::Chat => {
                if let Some(c) = self.chat.as_mut().filter(|c| !c.running()) {
                    c.paste(text);
                }
            }
            Layer::Input => w.input.paste(text),
            Layer::Run | Layer::Choice | Layer::Modal | Layer::Docs | Layer::Screen => {}
        }
    }

    /// The workflow whose values are being asked for.
    pub(crate) fn asking_vars<'a>(&self, w: &'a Win) -> Option<&'a str> {
        match &w.input {
            Input::Prompt(Prompt::WfVar(v), _) => Some(&v.workflow),
            _ => None,
        }
    }

    pub(crate) fn on_key(&mut self, w: &mut Win, k: KeyEvent, now: Instant) {
        w.dirty = true;
        self.on_key_inner(w, k, now);
        self.settle(w, Settle::Key);
    }

    /// The screens in the strip, and whether the one in view takes a `/` filter.
    fn strip(&self, w: &Win) -> (Vec<ScreenId>, bool) {
        let tabs = self.target.tabs(&self.shared, &cx!(self, w));
        let filterable = tabs.iter().any(|t| t.id == self.screen && t.filterable);
        (tabs.into_iter().map(|t| t.id).collect(), filterable)
    }

    fn on_key_inner(&mut self, w: &mut Win, k: KeyEvent, now: Instant) {
        use modal::{Answer, Pick};
        match frame::layer(&self.open(w)) {
            Layer::Run => return self.pane_key(w, k),
            Layer::Choice => {
                let n = self.choice.as_ref().map_or(0, |c| c.options.len());
                match modal::pick(&k, n) {
                    Pick::Option(i) => {
                        if let Some(c) = self.choice.take() {
                            self.apply(w, c.options[i].1.clone(), now);
                        }
                    }
                    Pick::Close => self.choice = None,
                    Pick::Stay => {}
                }
                return;
            }
            // The window's own box (help, quit) is in front of the slot's.
            Layer::Modal if w.modal.is_some() => {
                let has_yes = w.modal.as_ref().is_some_and(|m| m.yes.is_some());
                match modal::answer(&k, has_yes) {
                    Answer::Yes => {
                        if let Some((_, effects)) = w.modal.take().and_then(|m| m.yes) {
                            self.apply(w, effects, now);
                        }
                    }
                    Answer::No => w.modal = None,
                    Answer::Stay => {}
                }
                return;
            }
            Layer::Modal => {
                let has_yes = self.modal.as_ref().is_some_and(|m| m.yes.is_some());
                match modal::answer(&k, has_yes) {
                    Answer::Yes => {
                        self.modal_no = None;
                        if let Some((_, effects)) = self.modal.take().and_then(|m| m.yes) {
                            self.apply(w, effects, now);
                        }
                    }
                    Answer::No => {
                        let title = self.modal.take().map(|m| m.title);
                        if let Some((t, effects)) = self.modal_no.take()
                            && Some(t) == title
                        {
                            self.apply(w, effects, now);
                        }
                    }
                    Answer::Stay => {}
                }
                return;
            }
            // The apply session and the chat take raw keys (Backspace, any character).
            Layer::Apply => {
                let fx = self.apply.as_mut().map(|s| s.key(k)).unwrap_or_default();
                return self.apply_fx(w, fx);
            }
            Layer::Chat => return self.chat_key(w, k),
            Layer::Input => return self.input_key(w, k, now),
            Layer::Docs => {
                // Over Records, a plan or a review: a screen key goes there, `:` still works.
                match w.keys.resolve(&k) {
                    Some(Action::Screen(id)) if id != ScreenId::Upgrade => {
                        self.rec_view = None;
                        self.review_view = None;
                        self.plan_view = None;
                        return self.enter(w, id, now);
                    }
                    Some(Action::Command) => {
                        w.input = Input::Command(String::new());
                        return;
                    }
                    _ => {}
                }
                if self.rec_view.is_some() {
                    self.records_key(w, k, now);
                } else if self.review_view.is_some() {
                    self.review_view_key(w, k);
                } else {
                    self.plan_view_key(w, k, now);
                }
                return;
            }
            Layer::Screen => {}
        }
        let Some(a) = w.keys.resolve(&k) else {
            return;
        };
        match a {
            // C-c on a running step stops the step, as in sentry.
            Action::Interrupt
                if self.screen == ScreenId::Upgrade
                    && self
                        .run
                        .as_ref()
                        .is_some_and(|s| s.live().is_some_and(|l| l.pid.is_some())) =>
            {
                // Its exit ends the step as failed; the run stays.
                if let Some(pid) = self.run.as_ref().and_then(|s| s.live()?.pid) {
                    let _ = kill(pid);
                }
                w.toast("sent SIGTERM to the step");
            }
            // As in sentry: q and Ctrl-C ask first, `:q` quits.
            Action::Quit | Action::Interrupt => {
                w.modal = Some(frame::quit_modal(
                    &w.theme,
                    self.target.ident().quit.clone(),
                    Effect::Quit,
                ))
            }
            Action::Command => w.input = Input::Command(String::new()),
            Action::Filter if self.strip(w).1 => {
                w.input =
                    Input::Filter(self.filters.get(&self.screen).cloned().unwrap_or_default());
            }
            Action::Filter => w.toast("nothing to filter on this screen"),
            Action::Esc
                if self
                    .filters
                    .get(&self.screen)
                    .is_some_and(|f| !f.is_empty()) =>
            {
                self.filters.remove(&self.screen);
                self.settle(w, Settle::Lists);
            }
            Action::Screen(id) => self.enter(w, id, now),
            Action::NextScreen | Action::PrevScreen => {
                let ids = self.strip(w).0;
                let i = ids.iter().position(|s| *s == self.screen).unwrap_or(0);
                let step = if a == Action::NextScreen {
                    1
                } else {
                    ids.len() - 1
                };
                self.enter(w, ids[(i + step) % ids.len()], now);
            }
            Action::Help => self.show_help(w),
            Action::Ask => {
                if let Some(sess) = self.apply.as_mut().filter(|s| s.chat.hidden) {
                    sess.chat.hidden = false;
                } else if let Some(c) = self.chat.as_mut().filter(|c| c.hidden) {
                    c.hidden = false;
                } else if !claude::available() {
                    w.toast("Claude Code isn't installed (or not on PATH)");
                } else {
                    if self.screen == ScreenId::Maint && self.shared.wf_entries.is_empty() {
                        self.load_wf_entries();
                    }
                    let ask = self.target.ask(&self.shared, &cx!(self, w));
                    let apply = (self.screen == ScreenId::Maint)
                        .then(|| self.target.apply_ask(&self.shared, &cx!(self, w)))
                        .flatten();
                    match (ask, apply) {
                        (Ok(ask), Some(apply)) => {
                            self.choice = Some(claude_choice(&w.theme, self.app, apply, ask));
                        }
                        (Err(_), Some(apply)) => self.open_ask(w, apply),
                        (Ok(ask), None) => self.open_ask(w, ask),
                        (Err(why), None) => w.toast(&why),
                    }
                }
            }
            // The rest is the target's: its screen's moving, Enter, r, c and its own letters.
            a => {
                let e = self.target.handle(a, &self.shared, &cx!(self, w));
                self.apply(w, e, now);
            }
        }
    }

    /// A key for the line being typed in the key bar.
    pub(crate) fn input_key(&mut self, w: &mut Win, k: KeyEvent, now: Instant) {
        match w.input.key(&k) {
            Typed::Filter(f) => {
                self.filters.insert(self.screen, f);
                self.settle(w, Settle::Filter);
            }
            Typed::FilterCleared => {
                self.filters.remove(&self.screen);
                self.settle(w, Settle::Filter);
            }
            Typed::Command(c) => self.command(w, c.trim(), now),
            Typed::Submit(p, text) => self.submit(w, p, text.trim()),
            Typed::Cancelled(Some(p)) => self.cancelled(w, p),
            Typed::Editing | Typed::FilterKept | Typed::Cancelled(None) => {}
        }
    }

    /// Enter on a prompt: what was asked for is done with the answer.
    pub(crate) fn submit(&mut self, w: &mut Win, p: Prompt, text: &str) {
        match p {
            // A workflow's values, one at a time: an empty answer takes the default; with
            // none, it's asked again.
            Prompt::WfVar(mut v) => {
                let Some((name, _, default)) = v.current().cloned() else {
                    return;
                };
                let val = match text {
                    "" => default.unwrap_or_default(),
                    s => s.to_string(),
                };
                if val.is_empty() {
                    v.note = Some(format!("{name} needs a value"));
                    w.input = Input::Prompt(Prompt::WfVar(v), String::new());
                    return;
                }
                v.note = None;
                v.values.insert(name, val);
                match v.current().map(|(_, _, d)| d.clone().unwrap_or_default()) {
                    Some(next) => w.input = Input::Prompt(Prompt::WfVar(v), next),
                    None => self.wf_cmd(w, WfCmd::BeginWith(v.workflow, v.values)),
                }
            }
            Prompt::LogNote(e) => {
                self.log_note_submit(w, *e, text, false);
                self.review_after_run(w);
            }
            Prompt::LogAddNote(e) => self.log_note_submit(w, *e, text, true),
            // The plan's note: an empty one is fine.
            Prompt::PlanNote(id, mut plan) => {
                plan.head.note = (!text.is_empty()).then(|| text.to_string());
                if !claude::available() {
                    return w.toast("plans are written by Claude Code, which isn't installed");
                }
                self.ask_for_plan(w, id, *plan);
            }
            Prompt::PlanRevise(id) => {
                let Some(doc) = self.shared.plans.get(&id).cloned() else {
                    return;
                };
                if text.is_empty() {
                    return;
                }
                let session = doc.head.session.clone();
                self.write_plan(w, id, doc, self.target.plan_revise(text), session);
            }
            // A task's cadence: tasks.toml's task takes the place of one from the config.
            Prompt::TaskEvery(id) => {
                use sentry_core::maint::tasks;
                let every = match tasks::parse_every(text) {
                    Ok(e) => e,
                    Err(e) => return w.toast(&e),
                };
                let Some(t) = self.all_tasks().into_iter().find(|t| t.id == id) else {
                    return;
                };
                if w.offline {
                    self.shared.tasks.retain(|x| x.id != id);
                    self.shared.tasks.push(tasks::Task {
                        every: every.or(t.every),
                        off: every.is_none(),
                        source: tasks::Source::File,
                        ..t.clone()
                    });
                } else {
                    if let Err(e) = tasks::set_every(&self.scope, &t, every) {
                        return w.toast(&format!("tasks.toml: {e}"));
                    }
                    self.shared.tasks = tasks::load(&self.scope);
                }
                self.settle(w, Settle::Lists);
                w.toast(&match every {
                    Some(d) => format!("{} every {d} (tasks.toml)", t.title),
                    None => format!("{} is off (tasks.toml)", t.title),
                });
            }
        }
    }

    /// Esc on a prompt.
    pub(crate) fn cancelled(&mut self, w: &mut Win, p: Prompt) {
        match p {
            Prompt::WfVar(v) => {
                w.toast("not started");
                // The series' workflow, its values dismissed: it never starts.
                if self.series_waits(&sentry_core::maint::series::Wait::Workflow(v.workflow)) {
                    self.series_stop(w);
                }
            }
            Prompt::PlanNote(..) => w.toast("not planned"),
            // No note: what the run changed may still want reading again.
            Prompt::LogNote(_) => {
                self.settled(w);
                self.review_after_run(w);
            }
            Prompt::LogAddNote(_) | Prompt::PlanRevise(_) | Prompt::TaskEvery(_) => {}
        }
    }

    /// A key for the pane (a command's streamed output, or a log being read).
    pub(crate) fn pane_key(&mut self, w: &mut Win, k: KeyEvent) {
        use frame::RunKey;
        let Some(p) = self.pane.as_mut() else { return };
        let len = p.lines.len();
        match frame::run_key(&k, p.done.is_none()) {
            RunKey::Close => self.pane = None,
            RunKey::Kill => {
                if let Some(pid) = p.pid {
                    let _ = kill(pid);
                    p.lines.push_back("■ stopping…".into());
                }
            }
            RunKey::Busy => w.toast("running · C-c stops it"),
            RunKey::Scroll(n) => p.scroll = p.scroll.saturating_add_signed(n as isize).min(len),
            RunKey::End => p.scroll = 0,
            RunKey::Top => p.scroll = len,
            RunKey::None => {}
        }
    }
    /// `?`: the screen's keys, laid out as in sentry.
    pub(crate) fn show_help(&mut self, w: &mut Win) {
        let keys = self.target.hints(true, &self.shared, &cx!(self, w));
        let id = self.target.ident();
        w.modal = Some(frame::help_modal(
            &w.theme,
            &frame::Help {
                screen: self.screen.name(),
                hints: &keys,
                globals: id.help_globals,
                app: id.app,
                commands: id.commands,
                footer: &[
                    "Destructive actions: preview → confirm → streamed output.",
                    &id.help_footer,
                ],
            },
        ));
    }

    /// `:` commands, as in sentry.
    pub(crate) fn command(&mut self, w: &mut Win, c: &str, now: Instant) {
        use sentry_core::tui::records::Section;
        let mut parts = c.split_whitespace();
        let (name, arg) = (parts.next(), parts.next());
        // One only this kind of target has.
        if let Some(n) = name
            && let Some(e) = self.target.colon(n, arg, &self.shared, &cx!(self, w))
        {
            return self.apply(w, e, now);
        }
        match (name, arg) {
            (Some("q" | "q!" | "quit" | "qa"), _) => w.quit = true,
            (Some("refresh" | "r"), _) => {
                let e = self
                    .target
                    .handle(Action::Refresh, &self.shared, &cx!(self, w));
                self.apply(w, e, now);
            }
            (Some("help" | "h"), _) => {
                let k = ratatui::crossterm::event::KeyEvent::from(
                    ratatui::crossterm::event::KeyCode::Char('?'),
                );
                self.on_key(w, k, now);
            }
            (Some("log"), _) => self.open_records(w, Section::Log, None),
            (Some("records" | "rec" | "tasks"), _) => self.open_records(w, Section::Tasks, None),
            (Some("plans"), _) => self.open_records(w, Section::Plans, None),
            (Some("reviews"), _) => self.open_records(w, Section::Reviews, None),
            (Some("later"), _) => self.open_records(w, Section::Later, None),
            // As in sentry: screen 0, and Enter on the workflow named.
            (Some("workflow" | "wf"), name) => match name {
                Some(n) => self.wf_start(w, n, now),
                None => self.enter(w, ScreenId::Upgrade, now),
            },
            // A screen, by sentry's names (and the ones the tabs had).
            (Some(name), None) => match self.target.ident().screens.from_name(name) {
                Some(id) => self.enter(w, id, now),
                None => w.toast(&format!("unknown command :{c}")),
            },
            _ if c.is_empty() => {}
            _ => w.toast(&format!("unknown command :{c}")),
        }
    }

    /// The command waiting for the terminal, with its banner.
    pub(crate) fn take_suspend(&mut self, w: &mut Win) -> Option<(sentry_core::exec::Cmd, String)> {
        let s = self.suspend.take()?;
        // Re-read afterwards whatever the command changed.
        self.apply(w, s.then, Instant::now());
        self.suspend_own = s.own;
        Some((s.cmd, s.banner))
    }

    pub(crate) fn after_suspend(&mut self, w: &mut Win, status: Result<ExitStatus, ExecError>) {
        if let Some((idx, capture)) = self.suspend_step.take()
            && let Some(s) = self.run.as_mut()
        {
            let code = match &status {
                Ok(st) => st.code().unwrap_or(-1),
                Err(_) => -1,
            };
            s.tty_ended(idx, &capture, code, !w.offline);
            self.wf_auto(w);
            return;
        }
        if std::mem::take(&mut self.suspend_edit) {
            self.refresh(w, Why::Edited);
            self.load_wf_entries();
            self.shared.tasks = sentry_core::maint::tasks::load(&self.scope);
            return;
        }
        if let Some(own) = self.suspend_own.take() {
            let e = self
                .target
                .after_suspend(&own, status, &mut self.shared, &cx!(self, w));
            return self.apply(w, e, Instant::now());
        }
        match status {
            Ok(s) if s.success() => w.toast("done"),
            Ok(s) => w.toast(&format!("exited {}", s.code().unwrap_or(-1))),
            Err(e) => w.toast(&e.to_string()),
        }
    }
}

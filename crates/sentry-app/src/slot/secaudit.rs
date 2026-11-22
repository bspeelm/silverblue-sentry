//! The security audit's flows, the same on every target (`crate::secaudit`): `S` shows the
//! latest report (or runs the first one), `S` there runs it again; every target's facts
//! are read on a worker thread, the report opens when it is done and Claude reviews its
//! evidence in the background; Enter on one of its rows is a session that fixes it (one
//! across targets when the item spans them), or, for what only the user knows, a pick.

use super::*;
use crate::secaudit::{self as sec, Done};
use crate::system::Parcel;
use sentry_core::secaudit::{self as core, Report, State};

impl Slot {
    /// `S`, `:audit security`: the report as it stands; with none yet, the audit runs.
    pub(crate) fn sec_show(&mut self, w: &mut Win) {
        if w.sec.report.is_none() {
            return self.sec_run(w);
        }
        self.rec_view = None;
        self.plan_view = None;
        self.review_view = None;
        self.sec_view = Some(0);
    }

    /// Run the audit. What a target reads as root while its password is held is read
    /// again first (the app starts the worker when those reads are in: `App::sec_go`).
    pub(crate) fn sec_run(&mut self, w: &mut Win) {
        if w.sec.busy() {
            return w.toast("the security audit is already running");
        }
        if w.sec.collect.is_none() && !w.offline {
            return w.toast("the security audit isn't available in this window");
        }
        w.sec.pending = Some((w.at, self.mail.id().clone()));
        let me = self.mail.id().clone();
        let others: Vec<String> = w
            .system
            .iter()
            .map(|s| s.peer.id.clone())
            .filter(|id| *id != me)
            .collect();
        for id in others {
            w.outbox.push_back((id, Parcel::Facts));
        }
        self.refresh(w, Why::Facts);
        w.toast("security audit · reading every target (a minute or two)");
    }

    /// Every target's facts are in: the report, its task done, the view, Claude's review.
    pub(crate) fn sec_done(&mut self, w: &mut Win, facts: Vec<core::TargetFacts>) {
        w.sec.running = None;
        w.dirty = true;
        let report = if w.offline {
            Report::build(&facts, &w.sec.answers, w.sec.report.as_ref(), w.now())
        } else {
            w.sec.answers = core::Answers::load();
            match Report::finish(&facts) {
                Ok((r, _)) => r,
                Err(e) => return w.toast(&format!("security audit: {e}")),
            }
        };
        if report.empty() {
            return w.toast("security audit: nothing could be read from any target");
        }
        // Its task is this machine's, and done.
        w.outbox.push_back((
            String::new(),
            Parcel::Entry(Box::new(core::done_entry(&report.summary()))),
        ));
        let n = report.of(State::DoFirst).len();
        w.sec.report = Some(report);
        w.sec.facts = facts;
        w.sec.review = None;
        w.sec.rev += 1;
        self.sec_sync(w);
        if w.focused && matches!(frame::layer(&self.open(w)), Layer::Screen | Layer::Docs) {
            self.rec_view = None;
            self.plan_view = None;
            self.review_view = None;
            self.sec_view = Some(0);
        } else {
            w.toast(&format!(
                "security audit done: {n} to do first · {} shows it",
                sec::KEY
            ));
        }
        self.sec_review(w);
    }

    /// Layer 2: Claude reads the evidence (scrubbed where it was made) and says what
    /// matters most here. It gets the web and nothing else.
    fn sec_review(&mut self, w: &mut Win) {
        let Some(r) = &w.sec.report else { return };
        if !claude::available() || self.writer.as_ref().is_some_and(|x| x.running()) {
            return;
        }
        let prompt = core::review_brief(r);
        let mut wr = Writer::new(sec::REVIEW, PlanDoc::default());
        wr.quiet = true;
        self.start_writer_with(w, wr, prompt, None, Some(sec::review_profile()));
        w.sec.reviewing = self
            .writer
            .as_ref()
            .is_some_and(|x| x.item == sec::REVIEW && x.running());
    }

    /// Claude's review of the audit is written (or wasn't).
    pub(crate) fn sec_review_ended(&mut self, w: &mut Win) {
        let Some(wr) = self.writer.take() else { return };
        w.sec.reviewing = false;
        w.dirty = true;
        match wr.answer.filter(|a| !a.trim().is_empty()) {
            Some(a) => {
                if !w.offline
                    && let Some(r) = &w.sec.report
                {
                    let _ = core::save_review(r, &a);
                }
                w.sec.review = Some(a);
                if self.sec_view.is_none() {
                    w.toast(&format!(
                        "security audit: Claude's review is in · {} shows it",
                        sec::KEY
                    ));
                }
            }
            None => w.toast(&format!(
                "security audit: no review ({})",
                wr.err.unwrap_or_else(|| "Claude gave no answer".into())
            )),
        }
    }

    /// Enter on one of the audit's rows: a pick for what only the user knows, else a
    /// session that fixes it.
    pub(crate) fn sec_item(&mut self, w: &mut Win, id: &str) {
        let Some(item) = w
            .sec
            .report
            .as_ref()
            .and_then(|r| r.items.iter().find(|i| i.id == id))
            .cloned()
        else {
            return w.toast("the audit no longer lists it");
        };
        if let (State::Ask, Some(key)) = (item.state, item.question.clone()) {
            let pick = |said| vec![Effect::SecAnswer(key.clone(), said)];
            let mut c = modal::Choice::numbered(
                &w.theme,
                "Only you know this",
                vec![
                    ("Yes".into(), pick(Some(true))),
                    ("No".into(), pick(Some(false))),
                    (
                        "I don't know (asked again in 30 days)".into(),
                        vec![Effect::SecAnswer(id.to_string(), None)],
                    ),
                ],
            );
            c.lines
                .insert(0, Line::styled(item.title.clone(), w.theme.fg()));
            c.lines.insert(1, Line::raw(""));
            self.choice = Some(c);
            return;
        }
        if !claude::available() {
            return w.toast(self.ways.no_claude);
        }
        if self.shared.wf_entries.is_empty() && !w.offline {
            self.load_wf_entries();
        }
        let ask = self.target.sec_ask(&item, &self.shared, &cx!(self, w));
        self.open_ask(w, ask);
        // Briefed with what a router said (an item about one): no web from the start.
        let hides = |t: &String| {
            w.system
                .iter()
                .any(|s| sec::name(&s.peer.id) == t && s.peer.hides)
        };
        if item.targets.iter().any(hides)
            && let Some(s) = self.apply.as_mut()
        {
            s.web_off = true;
        }
    }

    /// The answer to one of the audit's questions: remembered, and the audit's rules are
    /// gone through again with it (over the facts this window read; with none in memory
    /// the next audit takes it in). None: not known, asked again in 30 days.
    pub(crate) fn sec_answer(&mut self, w: &mut Win, key: &str, said: Option<bool>) {
        let Some(yes) = said else {
            // (`key` is the item's id here.)
            let until = w
                .now()
                .to_zoned(jiff::tz::TimeZone::UTC)
                .date()
                .saturating_add(jiff::Span::new().days(30));
            self.apply(w, vec![Effect::Snooze(sec::row_key(key), until)], w.at);
            return w.toast("left open · asked again in 30 days");
        };
        let today = w.now().to_zoned(jiff::tz::TimeZone::UTC).date();
        w.sec.answers.set(key, yes, today);
        w.sec.rev += 1;
        if !w.offline
            && let Err(e) = w.sec.answers.save()
        {
            return w.toast(&format!("couldn't remember the answer: {e}"));
        }
        let said = if yes { "yes" } else { "no" };
        if w.sec.facts.is_empty() {
            self.sec_sync(w);
            self.settle(w, Settle::Lists);
            return w.toast(&format!(
                "{said}, remembered · the next audit takes it into account ({} runs it)",
                sec::KEY
            ));
        }
        if let Some(old) = w.sec.report.take() {
            let mut r = Report::build(&w.sec.facts, &w.sec.answers, None, old.at);
            r.diff = old.diff;
            if !w.offline {
                let _ = core::save(&r);
            }
            w.sec.report = Some(r);
        }
        self.sec_sync(w);
        self.settle(w, Settle::Lists);
        w.toast(&format!("{said}, remembered · the audit's list follows"));
    }

    /// Keys in the audit's report: scroll, run it again, back.
    pub(crate) fn sec_view_key(&mut self, w: &mut Win, k: KeyEvent) {
        use ratatui::crossterm::event::KeyCode;
        let Some(scroll) = self.sec_view else { return };
        w.dirty = true;
        let set = |me: &mut Self, s: usize| me.sec_view = Some(s);
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => self.sec_view = None,
            KeyCode::Char(c) if c == sec::KEY => self.sec_run(w),
            KeyCode::Down | KeyCode::Char('j') => set(self, scroll + 1),
            KeyCode::Up | KeyCode::Char('k') => set(self, scroll.saturating_sub(1)),
            KeyCode::PageDown | KeyCode::Char(' ') => set(self, scroll + 20),
            KeyCode::PageUp => set(self, scroll.saturating_sub(20)),
            KeyCode::Home | KeyCode::Char('g') => set(self, 0),
            KeyCode::End | KeyCode::Char('G') => set(self, usize::MAX / 2),
            _ => {}
        }
    }

    /// The audit's report over the screen.
    pub(crate) fn sec_draw(&self, w: &Win, f: &mut Frame, area: ratatui::layout::Rect) {
        use ratatui::layout::{Constraint, Layout};
        use ratatui::style::{Modifier, Style};
        use ratatui::text::Span;
        use ratatui::widgets::{Clear, Paragraph, Wrap};
        let Some(scroll) = self.sec_view else { return };
        let t = &w.theme;
        f.render_widget(Clear, area);
        let [head, rule, body] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .areas(area);
        let (state, color) = match (&w.sec.report, w.sec.busy()) {
            (_, true) => ("reading every target again…".to_string(), t.cyan),
            (Some(r), _) => (sec::audited(w.now(), r.at), t.dim),
            (None, _) => ("never run".to_string(), t.dim),
        };
        let l1 = Line::from(vec![
            Span::styled(
                " Security audit ",
                Style::new()
                    .fg(t.ink)
                    .bg(t.mag)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  every target, as one system", t.fg()),
            Span::styled(format!("  · {state}"), t.s(color)),
        ]);
        let l2 = Line::styled(
            match &w.sec.report {
                Some(r) => format!(
                    " {} · its rows are on Security and Maintenance: Enter there acts",
                    r.summary()
                ),
                None => String::new(),
            },
            t.dim(),
        );
        f.render_widget(Paragraph::new(vec![l1, l2]), head);
        f.render_widget(
            Paragraph::new(Line::styled("─".repeat(rule.width as usize), t.s(t.border))),
            rule,
        );
        let lines = sentry_core::tui::docview::markdown(t, &sec::document(&w.sec));
        let max = lines.len().saturating_sub(body.height as usize / 2);
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .scroll((scroll.min(max) as u16, 0)),
            body,
        );
    }

    /// The audit's keys, for the key bar.
    pub(crate) fn sec_hints() -> frame::Hints<'static> {
        vec![
            ("S", "run it again"),
            ("j/k PgUp/Dn", "scroll"),
            ("Esc", "back"),
        ]
    }

    /// This target's copy of the audit's items it lists follows the window's report.
    pub(crate) fn sec_sync(&mut self, w: &Win) {
        let now = (w.sec.rev, w.system.len());
        if self.sec_seen == now {
            return;
        }
        self.sec_seen = now;
        self.shared.sec_last = w.sec.report.as_ref().map(|r| r.at);
        self.shared.sec = sec::mine(&w.sec, self.mail.id(), &w.system)
            .into_iter()
            .cloned()
            .collect();
    }

    /// Whether anything is being read as root for the target right now.
    pub(crate) fn reading(&self) -> bool {
        !self.reads.is_empty()
    }
}

impl crate::App {
    /// The report on disk, once (at start).
    pub(crate) fn sec_load(&mut self) {
        let s = &mut self.win.sec;
        if s.loaded || self.win.offline {
            return;
        }
        s.loaded = true;
        s.answers = core::Answers::load();
        s.report = core::latest();
        s.review = s.report.as_ref().and_then(core::review_of);
        s.rev += 1;
    }

    /// An audit was asked for: once nothing is still being read as root for it (or that
    /// took too long), every target's facts are read on a worker thread.
    pub(crate) fn sec_go(&mut self) {
        let Some((since, id)) = self.win.sec.pending.clone() else {
            return;
        };
        let waited = self.win.at.duration_since(since) >= Duration::from_secs(20);
        if self.slots.iter().any(|s| s.reading()) && !waited {
            return;
        }
        self.win.sec.pending = None;
        self.win.sec.running = Some(self.win.at);
        self.win.dirty = true;
        // (Tests: nothing is read; they hand the facts in.)
        let (Some(collect), false) = (self.win.sec.collect.clone(), self.win.offline) else {
            return;
        };
        let tx = self.sender();
        std::thread::spawn(move || {
            let _ = tx.send(crate::Event::Data(id, Box::new(Done(collect()))));
        });
    }
}

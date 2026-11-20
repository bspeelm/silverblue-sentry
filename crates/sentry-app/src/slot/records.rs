use super::*;

impl Slot {
    /// What Records shows, read now.
    pub(crate) fn records_data(&self, w: &Win) -> sentry_core::tui::records::Data {
        use sentry_core::maint::{log, plan, review};
        use sentry_core::tui::records::{LaterKind, LaterRow};
        let name = &self.scope;
        // Rows of the target's own (what it ignores…), and when it was last audited.
        let (own, audited) = self.target.records(&self.shared, &cx!(self, w));
        let today = jiff::Zoned::now().date();
        let mut later: Vec<LaterRow> = self
            .shared
            .later
            .iter()
            .filter(|(_, d)| **d > today)
            .map(|(k, d)| LaterRow {
                kind: LaterKind::Snoozed(*d),
                key: k.clone(),
                file: "later.toml",
            })
            .collect();
        if !w.offline {
            later.extend(self.shared.baseline.findings.iter().map(|k| LaterRow {
                kind: LaterKind::Expected,
                key: k.clone(),
                file: "baseline.toml",
            }));
            later.extend(self.shared.baseline.listeners.iter().map(|k| LaterRow {
                kind: LaterKind::Listener,
                key: k.clone(),
                file: "baseline.toml",
            }));
            later.extend(own);
        }
        let home = std::env::var("HOME").unwrap_or_default();
        let root = sentry_core::maint::root(name);
        let dir = root.display().to_string();
        // Tests: the same wherever the scratch dirs are.
        let rel = root
            .strip_prefix(sentry_core::paths::config_dir())
            .map_or(String::new(), |r| r.display().to_string());
        sentry_core::tui::records::Data {
            dir: match dir.strip_prefix(&home) {
                Some(r) if !home.is_empty() && !w.offline => format!("~{r}"),
                _ if w.offline => format!("~/.config/sentry/{rel}"),
                _ => dir,
            },
            tasks: self.all_tasks(),
            log: if w.offline {
                self.shared.log.clone()
            } else {
                log::list(name)
            },
            plans: if w.offline {
                Vec::new()
            } else {
                plan::all(name)
            },
            reviews: if w.offline {
                // Tests: the one in memory.
                self.shared
                    .review
                    .iter()
                    .map(|d| (review::dir(name).join(d.file_name()), d.clone()))
                    .collect()
            } else {
                review::list(name)
            },
            later,
            audited,
            now: jiff::Timestamp::now(),
        }
    }

    pub(crate) fn open_records(
        &mut self,
        w: &mut Win,
        s: sentry_core::tui::records::Section,
        item: Option<String>,
    ) {
        self.plan_view = None;
        self.review_view = None;
        self.rec_view = Some(sentry_core::tui::records::Records::new(
            self.records_data(w),
            s,
            item,
        ));
    }

    pub(crate) fn records_key(&mut self, w: &mut Win, k: KeyEvent, now: Instant) {
        use sentry_core::tui::records::{Fx, LaterKind};
        w.dirty = true;
        let Some(r) = self.rec_view.as_mut() else {
            return;
        };
        let Some(fx) = r.key(k.code) else {
            return;
        };
        let t = w.theme;
        let task = r.task().cloned();
        match fx {
            Fx::Close => self.rec_view = None,
            Fx::TaskDo(id) => {
                self.rec_view = None;
                let e = self.target.task_enter(&id, &self.shared, &cx!(self, w));
                self.apply(w, e, now);
            }
            Fx::TaskEvery(id) => {
                self.rec_view = None;
                self.apply(w, vec![Effect::TaskEvery(id)], now);
            }
            Fx::TaskRemove(id) => {
                self.rec_view = None;
                self.modal = Some(Modal {
                    title: "Remove this task".into(),
                    color: t.yellow,
                    lines: vec![
                        Line::styled(task.map_or(id.clone(), |t| t.title), t.fg()),
                        Line::styled(
                            "It comes off tasks.toml (a built-in one is turned off there). \
                             The log keeps what was done.",
                            t.dim(),
                        ),
                    ],
                    yes: Some(("remove".into(), vec![Effect::TaskRemove(id)])),
                });
            }
            Fx::TaskDone(id) => {
                self.rec_view = None;
                self.task_done(w, &id);
            }
            Fx::Note(e) => {
                self.rec_view = None;
                w.input = Input::Prompt(Prompt::LogAddNote(e), String::new());
            }
            Fx::OpenPlan(item) => {
                self.rec_view = None;
                self.plan_view = Some((item, 0));
            }
            Fx::OpenReview(p) => match sentry_core::maint::review::read(&p).or_else(|| {
                self.shared
                    .review
                    .clone()
                    .filter(|d| p.ends_with(d.file_name()))
            }) {
                Some(d) => {
                    self.shared.review = Some(d);
                    self.rec_view = None;
                    self.review_view = Some(sentry_core::tui::reviewview::ReviewView::show());
                }
                None => w.toast("couldn't read that review"),
            },
            Fx::NewReview => {
                self.rec_view = None;
                self.review_view = Some(sentry_core::tui::reviewview::ReviewView {
                    brief: true,
                    ..Default::default()
                });
            }
            Fx::Undo(row) => {
                let name = self.scope.clone();
                match row.kind {
                    LaterKind::Snoozed(_) => {
                        if !w.offline
                            && let Err(e) = sentry_core::maint::later::remove(&name, &row.key)
                        {
                            return w.toast(&format!("later.toml: {e}"));
                        }
                        self.shared.later.remove(&row.key);
                        self.refresh(w, Why::Lists);
                    }
                    // What only the target can take back: something it ignores, or marked
                    // expected (its findings are its own).
                    LaterKind::Expected | LaterKind::Ignored => {
                        let r = self.target.undo(&row, &mut self.shared, &cx!(self, w));
                        match r {
                            Ok(e) => self.apply(w, e, now),
                            Err(e) => return w.toast(&e),
                        }
                    }
                    // A listener marked expected on Network: new again.
                    LaterKind::Listener => {
                        let mut b = self.shared.baseline.clone();
                        b.listeners.retain(|k| k != &row.key);
                        if !w.offline
                            && let Err(e) = b.save(&name)
                        {
                            return w.toast(&format!("baseline.toml: {e}"));
                        }
                        self.shared.baseline = b;
                    }
                }
                w.toast(&format!("{}: back on Maintenance", row.key));
                let item = None;
                self.open_records(w, sentry_core::tui::records::Section::Later, item);
            }
        }
    }

    /// Keys in the Plan view: scroll, apply (Enter), revise (r), drop (x), back (Esc).
    pub(crate) fn plan_view_key(&mut self, w: &mut Win, k: KeyEvent, now: Instant) {
        use ratatui::crossterm::event::{KeyCode, KeyModifiers};
        let Some((id, scroll)) = self.plan_view.clone() else {
            return;
        };
        w.dirty = true;
        let set = |me: &mut Self, s: usize| me.plan_view = Some((id.clone(), s));
        let writing = self
            .writer
            .as_ref()
            .is_some_and(|w| w.item == id && w.running());
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => self.plan_view = None,
            // Claude alongside: apply this plan, or ask about it.
            KeyCode::Char('A') if !writing => {
                if !claude::available() {
                    return w.toast("Claude Code isn't installed (or not on PATH)");
                }
                if self.shared.wf_entries.is_empty() {
                    self.load_wf_entries();
                }
                let apply =
                    self.target
                        .plan_ask(&id, format!("plan:{id}"), &self.shared, &cx!(self, w));
                match apply {
                    Some(apply) => {
                        let ask = sentry_core::claude::Ask::new(
                            format!("{} · the plan for {id}", self.title),
                            apply.context.clone(),
                            format!(
                                "Is this plan still right for {} as it is now? What would you \
                                 check or change first?",
                                self.target.ident().place
                            ),
                        );
                        self.choice = Some(claude_choice(&w.theme, self.app, apply, ask));
                    }
                    None => w.toast(&format!("{id} isn't tracked any more")),
                }
            }
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(pid) = self
                    .writer
                    .as_ref()
                    .filter(|w| w.item == id)
                    .and_then(|w| w.live.map(|(_, p)| p))
                {
                    let _ = kill(pid);
                    w.toast("stopped: the plan keeps what it had");
                }
            }
            KeyCode::Down | KeyCode::Char('j') => set(self, scroll + 1),
            KeyCode::Up | KeyCode::Char('k') => set(self, scroll.saturating_sub(1)),
            KeyCode::PageDown | KeyCode::Char(' ') => set(self, scroll + 20),
            KeyCode::PageUp => set(self, scroll.saturating_sub(20)),
            KeyCode::Home | KeyCode::Char('g') => set(self, 0),
            KeyCode::End | KeyCode::Char('G') => set(self, usize::MAX / 2),
            _ if writing => w.toast("Claude is writing it · C-c stops · Esc goes back"),
            KeyCode::Enter => self.apply_plan(w, &id, now),
            KeyCode::Char('r') => match self.shared.plans.get(&id) {
                Some(d) if d.head.session.is_some() => {
                    w.input = Input::Prompt(Prompt::PlanRevise(id.clone()), String::new())
                }
                Some(_) => w.toast("no Claude session for this plan: p writes a new one"),
                None => {}
            },
            KeyCode::Char('x') if self.shared.plans.contains_key(&id) => {
                let t = w.theme;
                self.modal = Some(Modal {
                    title: "Drop the plan".into(),
                    color: t.yellow,
                    lines: vec![Line::styled(
                        format!(
                            "Drop the plan for {id}? It moves to plans/done/; nothing on {} changes.",
                            self.target.ident().place
                        ),
                        t.fg(),
                    )],
                    yes: Some(("drop".into(), vec![Effect::PlanDrop(id.clone())])),
                });
            }
            _ => {}
        }
    }

    /// A plan carried out by hand: it moves to plans/done/, and the change is logged (the
    /// note box follows, as after a run).
    pub(crate) fn plan_done_by_hand(&mut self, w: &mut Win, id: &str) {
        use sentry_core::maint::{log, plan};
        let Some(doc) = self.shared.plans.remove(id) else {
            return;
        };
        self.plan_view = None;
        let path = if w.offline {
            Some(plan::path(&self.scope, id))
        } else {
            plan::close(&doc, PlanStatus::Done).ok()
        };
        let kind = self
            .target
            .item_kind(id)
            .map_or("system".to_string(), |(kind, _)| kind);
        let entry = log::LogEntry::by_hand(
            &self.scope,
            id,
            &kind,
            doc.head.from.clone(),
            doc.head.to.clone(),
            path.as_deref(),
            None,
        );
        if !w.offline {
            if let Err(e) = log::write(&entry) {
                w.toast(&format!("couldn't write the maintenance log: {e}"));
            }
            self.shared.log = log::list(&self.scope);
            self.refresh(w, Why::Lists);
        }
        self.last_change_at = Some(jiff::Timestamp::now());
        w.input = Input::Prompt(Prompt::LogNote(Box::new(entry)), String::new());
    }

    /// Enter in the Plan view: the item's workflow, with the plan's values filled in.
    /// Enter on a ready plan (in the Plan view, or its recommendation): carried out in an
    /// apply session seeded with the plan (its checks, its workflow with the plan's values).
    pub(crate) fn apply_plan(&mut self, w: &mut Win, id: &str, _now: Instant) {
        let Some(d) = self.shared.plans.get(id) else {
            return;
        };
        match d.head.status {
            PlanStatus::Ready => {}
            PlanStatus::Wait => {
                return w.toast("Claude advises waiting: r revises it, or p plans again");
            }
            s => return w.toast(&format!("this plan is {}: p plans again", s.word())),
        }
        if self.shared.wf_entries.is_empty() && !w.offline {
            self.load_wf_entries();
        }
        let ask = self
            .target
            .plan_ask(id, id.to_string(), &self.shared, &cx!(self, w));
        match ask {
            Some(ask) => {
                self.plan_view = None;
                self.open_ask(w, ask);
            }
            None => w.toast(&format!("{id} isn't tracked any more")),
        }
    }

    /// `p`, after the note: what Claude is asked, in a confirm box; yes starts the writer.
    pub(crate) fn ask_for_plan(&mut self, w: &mut Win, id: String, doc: PlanDoc) {
        if self.shared.wf_entries.is_empty() && !w.offline {
            self.load_wf_entries();
        }
        // What the box says and what's sent are the target's: its item, its notes, its reads.
        let brief = self
            .target
            .plan_brief(&id, &doc, &self.shared, &cx!(self, w));
        let (lines, prompt) = match brief {
            Ok(b) => b,
            Err(why) => return w.toast(&why),
        };
        let t = w.theme;
        self.modal = Some(Modal {
            title: format!("Plan {id} with Claude"),
            color: t.mag,
            lines,
            yes: Some(("write it".into(), vec![Effect::PlanWrite(id, doc, prompt)])),
        });
    }

    /// Start (or continue) Claude writing a plan in the background; the Plan view shows it.
    pub(crate) fn write_plan(
        &mut self,
        w: &mut Win,
        id: String,
        doc: PlanDoc,
        prompt: String,
        resume: Option<String>,
    ) {
        self.start_writer(w, Writer::new(&id, doc), prompt, resume);
    }
}

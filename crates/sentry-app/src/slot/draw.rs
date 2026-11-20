use super::*;

impl Slot {
    pub(crate) fn draw(&mut self, w: &mut Win, f: &mut Frame) {
        let t = w.theme;
        // A run in progress, on every screen but its own.
        let banner = self
            .run
            .as_ref()
            .filter(|_| self.screen != ScreenId::Upgrade);
        // A series in progress takes the row when no workflow's banner does, and its
        // session isn't in front saying so itself.
        let hidden = self.apply.as_ref().is_some_and(|a| a.chat.hidden);
        let series = self
            .series
            .as_ref()
            .filter(|_| banner.is_none() && (self.apply.is_none() || hidden))
            .map(|s| (s.line(), if hidden { "A shows it" } else { "" }))
            // A session out of view says where it stands, as a run does off its screen.
            .or_else(|| {
                self.apply
                    .as_ref()
                    .filter(|a| a.chat.hidden && banner.is_none())
                    .map(|a| (sentry_core::tui::applyview::banner(a), "A shows it"))
            });
        // Auto mode says so in the row, with whatever else is there (or by itself).
        let series = match series {
            Some((line, hint)) if self.auto => Some((format!("{line} · auto"), hint)),
            None if self.auto && banner.is_none() => Some((
                "auto · routine steps and questions go by themselves".to_string(),
                "C-a turns it off",
            )),
            s => s,
        };
        let Some(areas) = frame::layout(f, &t, banner.is_some() || series.is_some()) else {
            return;
        };
        if let Some((line, hint)) = &series {
            frame::draw_series(f, areas.banner, &t, line, hint);
        }
        let body = areas.body;
        frame::draw_top(f, areas.top, &t, &self.top(w));
        self.draw_tabs(w, f, areas.tabs);
        if let Some(s) = banner {
            let n = s.wf().steps.len();
            // A reboot that waits says for whom.
            let waits = self
                .reboot_held
                .as_ref()
                .map(|h| format!("the reboot waits for {}", h.2));
            frame::draw_banner(
                f,
                areas.banner,
                &t,
                &frame::Banner {
                    workflow: &s.wf().name,
                    step: s.next().idx().map(|i| (i + 1, n, s.title(i).to_string())),
                    state: waits.as_deref().unwrap_or(s.state_word()),
                    auto: self.auto,
                },
            );
        }
        self.target.render(f, body, &self.shared, &cx!(self, w));
        let front = self.doc_front();
        if let Some(rv) = self
            .review_view
            .as_ref()
            .filter(|_| front == Some(Doc::Review))
        {
            let writer = self.writer.as_ref().filter(|w| w.review.is_some());
            let path = self.shared.review.as_ref().map_or(String::new(), |d| {
                sentry_core::tui::widgets::short_home(
                    &sentry_core::maint::review::dir(&self.scope).join(d.file_name()),
                )
            });
            sentry_core::tui::reviewview::draw(
                f,
                body,
                &t,
                rv,
                &sentry_core::tui::reviewview::Shown {
                    doc: self.shared.review.as_ref(),
                    writer,
                    brief: &self.review_brief(w),
                    path: &path,
                },
            );
        } else if let Some(r) = self
            .rec_view
            .as_ref()
            .filter(|_| front == Some(Doc::Records))
        {
            sentry_core::tui::records::draw(f, body, &t, r);
        } else if let Some((id, scroll)) = &self.plan_view {
            let path = sentry_core::maint::plan::path(&self.scope, id)
                .display()
                .to_string();
            let home = std::env::var("HOME").unwrap_or_default();
            let path = match path.strip_prefix(&home) {
                Some(r) if !home.is_empty() => format!("~{r}"),
                _ => path,
            };
            sentry_core::tui::docview::draw(
                f,
                body,
                &t,
                self.shared.plans.get(id),
                None,
                *scroll,
                &path,
            );
        }
        self.draw_keybar(w, f, areas.keybar);
        // Whatever is in front sits in the body, over the screen dimmed.
        if let Some(c) = self.chat.as_ref().filter(|c| !c.hidden) {
            widgets::dim_backdrop(f.buffer_mut(), body);
            chatmod::draw(f, body, &t, c);
        }
        if let Some(sess) = self.apply.as_ref().filter(|s| !s.chat.hidden) {
            widgets::dim_backdrop(f.buffer_mut(), body);
            let wf = self.wf_glimpse();
            sentry_core::tui::applyview::draw(f, body, &t, sess, &self.title, &wf);
        }
        if let Some(m) = &self.modal {
            widgets::dim_backdrop(f.buffer_mut(), body);
            modal::draw(f, body, &t, m);
        }
        // The window's own box (help, quit).
        if let Some(m) = &w.modal {
            widgets::dim_backdrop(f.buffer_mut(), body);
            modal::draw(f, body, &t, m);
        }
        if let Some(c) = &self.choice {
            widgets::dim_backdrop(f.buffer_mut(), body);
            modal::draw_choice(f, body, &t, c);
        }
        if let Some(p) = &self.pane {
            widgets::dim_backdrop(f.buffer_mut(), body);
            frame::draw_run(
                f,
                body,
                &t,
                &frame::RunView {
                    title: &p.title,
                    cmd: &p.cmd,
                    len: p.lines.len(),
                    scroll: p.scroll,
                    started: p.started,
                    done: p
                        .done
                        .map(|code| (code, p.took.filter(|_| self.ways.pane_took))),
                },
                p.lines.iter().map(String::as_str),
            );
        }
    }

    /// The top bar: the target, what it runs and how long it's been up; the connection.
    fn top(&self, w: &Win) -> frame::Top<'static> {
        let (facts, state) = self.target.top(&cx!(self, w));
        let now = w.now().to_zoned(jiff::tz::TimeZone::system());
        frame::Top {
            // One program, whichever of its targets is in view; alone, a target's own name
            // for it (`sentry-server`).
            app: if w.several() { "sentry" } else { self.app },
            subject: self.title.clone(),
            auto: self.auto,
            facts,
            state,
            clock: frame::clock(&now),
            targets: w.strip.clone(),
            focus: w.strip_focus,
        }
    }

    /// What a review reads and does, shown before one is started.
    fn review_brief(&self, w: &Win) -> Vec<Line<'static>> {
        let t = w.theme;
        if !claude::available() {
            return vec![Line::styled(
                "  Reviews are written by Claude Code, which isn't installed.",
                t.s(t.yellow),
            )];
        }
        self.target.review_brief(&cx!(self, w))
    }

    /// The strip: sentry's, with the target's screens.
    pub(crate) fn draw_tabs(&self, w: &Win, f: &mut Frame, area: ratatui::layout::Rect) {
        let tabs: Vec<frame::Tab> = self
            .target
            .tabs(&self.shared, &cx!(self, w))
            .into_iter()
            .map(|tab| frame::Tab {
                id: tab.id,
                badge: tab.badge,
                filter: self
                    .filters
                    .get(&tab.id)
                    .filter(|_| tab.filterable)
                    .cloned(),
            })
            .collect();
        frame::draw_tabs(f, area, &w.theme, &tabs, self.screen);
    }

    /// The key bar: what's being typed, or the keys of whatever is in front.
    pub(crate) fn draw_keybar(&self, w: &Win, f: &mut Frame, area: ratatui::layout::Rect) {
        let toast = w.toast.as_ref().map(|t| t.msg());
        let layer = frame::layer(&self.open(w));
        // The sudo password, asked for here: the same line a session asks on.
        if let Some(u) = &self.unlock {
            // With several targets open, whose password it is.
            let what = if w.several() {
                format!("{} · {}", self.title, u.what)
            } else {
                u.what.clone()
            };
            let line = sentry_core::tui::applyview::password_line(
                &w.theme,
                &what,
                u.typed.len(),
                u.tries,
                u.checking.is_some(),
            );
            return frame::draw_keybar(f, area, &w.theme, &frame::KeyBar::Password(line), toast);
        }
        // A box or a conversation over the line: its keys, not the line's.
        if layer == Layer::Input
            && let Some(mut bar) = w.input.bar()
        {
            // The target's own words for a prompt.
            if let (Input::Prompt(p, _), frame::KeyBar::Prompt { label, enter, .. }) =
                (&w.input, &mut bar)
                && let Some((own, word)) = (self.ways.label)(p)
            {
                *label = own;
                *enter = word;
            }
            return frame::draw_keybar(f, area, &w.theme, &bar, toast);
        }
        let hints: frame::Hints = match layer {
            Layer::Unlock => Vec::new(),
            Layer::Run => frame::run_hints(self.pane.as_ref().is_some_and(|p| p.done.is_some())),
            Layer::Choice => frame::CHOICE_HINTS.to_vec(),
            Layer::Modal
                if w.modal
                    .as_ref()
                    .or(self.modal.as_ref())
                    .is_some_and(|m| m.yes.is_some()) =>
            {
                frame::CONFIRM_HINTS.to_vec()
            }
            // Their windows have their own key line.
            Layer::Apply | Layer::Chat => Vec::new(),
            // Records, a plan or a review (an info box over one leaves its keys named).
            _ if self.open(w).docs => self.doc_hints(),
            _ => {
                let mut h = self.target.hints(false, &self.shared, &cx!(self, w));
                // Where work is started and followed: auto mode's key.
                if self.target.offered()
                    && matches!(self.screen, ScreenId::Maint | ScreenId::Upgrade)
                {
                    h.push(self.auto_hint());
                }
                // A hidden conversation waiting takes `A` over.
                let hidden = self
                    .apply
                    .as_ref()
                    .filter(|s| s.chat.hidden)
                    .map(|s| {
                        if s.busy() {
                            "applying…"
                        } else {
                            "the apply session"
                        }
                    })
                    .or_else(|| {
                        self.chat
                            .as_ref()
                            .filter(|c| c.hidden)
                            .map(|c| c.hidden_word())
                    });
                frame::with_globals(h, hidden, self.target.offered() && claude::available())
            }
        };
        frame::draw_keybar(f, area, &w.theme, &frame::KeyBar::Hints(hints), toast);
    }

    /// The keys of Records, a plan or a review, whichever is over the screen.
    pub(crate) fn doc_hints(&self) -> frame::Hints<'_> {
        // The app's own way names the review's keys first, then Records', then the plan's;
        // the other names the plan's first.
        let plan_first = !self.ways.review_over_plan && self.plan_view.is_some();
        if let Some(rv) = self.review_view.as_ref().filter(|_| !plan_first) {
            rv.hints(self.shared.review.as_ref(), self.writing_review())
        } else if let Some(r) = self.rec_view.as_ref().filter(|_| !plan_first) {
            r.hints()
        } else if self.plan_view.is_some() {
            self.ways.plan_hints.to_vec()
        } else {
            Vec::new()
        }
    }
}

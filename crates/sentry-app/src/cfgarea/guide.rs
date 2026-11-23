//! The setup flow: the same screens, forms, lists and pending changes as ever, walked in
//! order under a rail of steps. It opens by itself only on a first run (none of the three
//! config files is there: the binary says so); `:setup` in the Config area starts it on
//! demand, at the step it was left. Enter goes on, `b` (or Backspace) goes back a step, Esc
//! leaves it: what is staged stays staged. Nothing here stages or saves by a path of its
//! own: the steps call what the screens call.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use sentry_core::cfg::FileId;
use sentry_core::claude::Tested;
use sentry_core::tui::theme::Theme;
use sentry_core::tui::ticklist::{self, Row, TickList};

use super::discover::AddFx;
use super::{Ask, ConfigArea, Fx, Page, Screen, Yes};
use crate::app::Win;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Agent,
    Machine,
    Systems,
    Review,
    Upkeep,
    Save,
}

impl Step {
    pub const ALL: [Step; 6] = [
        Step::Agent,
        Step::Machine,
        Step::Systems,
        Step::Review,
        Step::Upkeep,
        Step::Save,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Step::Agent => "Agent",
            Step::Machine => "This machine",
            Step::Systems => "Systems",
            Step::Review => "Review",
            Step::Upkeep => "Upkeep",
            Step::Save => "Save",
        }
    }

    fn at(self) -> usize {
        Step::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }
}

/// What sentry does without an agent, said where one may be skipped.
pub const WITHOUT_AGENT: &str = "Without an agent sentry still watches, audits, runs your \
    workflows and keeps the log. It won't offer what an agent does: fixes for findings, \
    plans, reviews, the security audit's reading, help in this setup.";

/// What sentry does on this machine, said on its step.
pub const HERE: &str = "On this machine sentry watches the system as you use it (updates, \
    containers, Flatpaks, what listens, what is filling up), audits it, and walks you \
    through its upkeep. It runs only while this window is open: nothing is installed, no \
    service, no timer.";

/// The key of a routine row: `<file>|<entry>|<workflow>|<every>`.
fn routine_key(file: FileId, entry: &str, wf: &str, every: &str) -> String {
    format!("{}|{entry}|{wf}|{every}", file.word())
}

impl ConfigArea {
    /// Start the setup flow (again): at the step it was left, else at the first.
    pub fn start_guide(&mut self, w: &mut Win) {
        let at = self.guide_left.take().unwrap_or(Step::Agent);
        self.guide = Some(at);
        self.guide_show(w);
    }

    /// Before the window is up (a first run): the flow is what it opens on.
    pub fn guide_at_start(&mut self) {
        self.guide = Some(Step::Agent);
    }

    /// The step's page or screen is put in view.
    pub(crate) fn guide_show(&mut self, w: &mut Win) {
        let Some(step) = self.guide else {
            return;
        };
        self.page = Page::None;
        self.row = None;
        match step {
            Step::Agent => self.enter(w, Screen::Agent),
            Step::Machine => self.enter(w, Screen::Machine),
            Step::Systems => {
                self.enter(w, Screen::Overview);
                self.open_add(w);
            }
            Step::Review => {
                self.enter(w, Screen::Overview);
                for d in &mut self.drafts {
                    d.reviewed = false;
                }
                self.open_review(w);
                self.page = Page::Review;
            }
            Step::Upkeep => {
                self.enter(w, Screen::Overview);
                self.routine = Some(self.routine_list());
                self.page = Page::Routine;
            }
            Step::Save => {
                self.enter(w, Screen::Overview);
                self.guide_save(w);
            }
        }
        w.dirty = true;
    }

    fn guide_go(&mut self, w: &mut Win, forward: bool) -> Option<Fx> {
        let at = self.guide?.at();
        let to = match forward {
            true => at + 1,
            false => match at.checked_sub(1) {
                Some(i) => i,
                None => {
                    w.toast("this is the first step · Esc leaves the setup");
                    return None;
                }
            },
        };
        self.guide = Step::ALL.get(to).copied();
        self.guide_show(w);
        None
    }

    /// The last step: the save box (with `config.toml` in it whatever is staged, when it
    /// isn't there yet). Nothing to save at all: the flow is done.
    fn guide_save(&mut self, w: &mut Win) -> Option<Fx> {
        self.write_app = !self.doc(FileId::App).is_some_and(|d| d.there());
        let fx = self.open_save(w);
        if self.save.is_none() {
            w.toast("setup done: there was nothing to save");
            self.guide_done();
        }
        fx
    }

    /// The flow is over: the window goes to the first system added, else this machine.
    pub(crate) fn guide_done(&mut self) {
        self.guide = None;
        self.guide_left = None;
        self.write_app = false;
        self.page = Page::None;
        self.add = None;
        self.review = None;
        self.routine = None;
        self.leave_to = Some(
            self.added
                .first()
                .cloned()
                .unwrap_or_else(|| "local".to_string()),
        );
    }

    /// Esc in the flow: asked once, saying what leaving means.
    fn guide_leave_box(&mut self) {
        let step = self.guide.map_or("", Step::name);
        let mut lines = vec![
            format!("Leave the setup at \"{step}\"?"),
            String::new(),
            match self.pending.len() {
                0 => "Nothing is staged.".to_string(),
                n => format!(
                    "{} staged {} staged: s saves, u takes one back.",
                    super::count(n, "change"),
                    if n == 1 { "stays" } else { "stay" }
                ),
            },
            ":setup picks the setup up again at this step.".to_string(),
        ];
        if !self.doc(FileId::App).is_some_and(|d| d.there()) {
            lines.push(String::new());
            lines.push(
                "sentry writes config.toml now, as it is on disk (every setting at its \
                 default; nothing staged goes into it), so the next start opens the window \
                 as usual, not the setup."
                    .to_string(),
            );
        }
        self.ask = Some(Ask {
            title: "Leave the setup".into(),
            lines,
            enter: "leave",
            yes: Yes::LeaveGuide,
        });
    }

    /// Enter in that box: the flow is left where it is; `config.toml` is written if there
    /// is none, which is what ends a first run.
    pub(crate) fn guide_leave(&mut self, w: &mut Win) -> Option<Fx> {
        self.guide_left = self.guide.take();
        self.page = Page::None;
        self.enter(w, Screen::Overview);
        let wrote = self.write_app_file(w);
        w.toast(match wrote {
            true => "setup left: config.toml written · :setup picks it up again",
            false => "setup left · :setup picks it up again",
        });
        wrote.then(|| Fx::Changed(vec![FileId::App]))
    }

    /// `config.toml` as it is on disk (nothing staged), written when it isn't there.
    fn write_app_file(&mut self, w: &mut Win) -> bool {
        let Some(i) = self.at(FileId::App) else {
            return false;
        };
        let Some(mut bare) = self.files[i]
            .doc
            .as_ref()
            .filter(|d| !d.there())
            .map(|d| d.on_disk())
        else {
            return false;
        };
        if let Err(e) = bare.save() {
            w.toast(&format!("config.toml not written: {e}"));
            return false;
        }
        let fresh = self.read(self.kinds[i].as_ref());
        self.files[i] = fresh;
        self.restage();
        self.lint(w);
        true
    }

    /// The routine upkeep of every system added here, with what the setup proposes for
    /// each ticked; this machine's, to read.
    fn routine_list(&self) -> TickList {
        let mut rows = Vec::new();
        if let Some((k, d)) = self.kind_doc(FileId::App) {
            let up = k.upkeep(d, super::MACHINE, self.disk);
            rows.push(Row::head("this machine").note("its jobs have their cadences already"));
            for r in up.rows.iter().filter(|r| r.what == "job") {
                let every = match (r.every.as_str(), r.default.as_str()) {
                    ("", "") => "not on a cadence".to_string(),
                    ("", "off") | ("off", _) => "off".to_string(),
                    ("", d) => format!("every {d}"),
                    (e, _) => format!("every {e}"),
                };
                rows.push(
                    Row::info(&format!("@job:{}", r.name), &format!("{}  {every}", r.name)).detail(
                        &format!(
                            "{} This machine's Upkeep (screen 3) changes how often.",
                            r.title
                        ),
                    ),
                );
            }
        }
        for d in &self.drafts {
            let Some((k, doc)) = self.kind_doc(d.file) else {
                continue;
            };
            let up = k.upkeep(doc, &d.name, self.disk);
            rows.push(Row::head(&d.name).note(d.kind));
            for r in &up.rows {
                let about = format!(
                    "{}{}",
                    r.title,
                    if r.draft {
                        " (A draft: it won't start until its file says otherwise.)"
                    } else {
                        ""
                    }
                );
                match r.suggest {
                    Some(every) => rows.push(
                        Row::tick(
                            &routine_key(d.file, &d.name, &r.name, every),
                            &format!("{}  every {every}", r.name),
                            r.every.is_empty() || r.every == every,
                        )
                        .detail(&format!(
                            "{about}\nTicked: {} is recommended on {} when it last ran longer \
                             ago than {every}. Its Upkeep changes that later.",
                            r.name, d.name
                        )),
                    ),
                    None => rows.push(
                        Row::info(
                            &format!("@wf:{}:{}", d.name, r.name),
                            &format!("{}  when it is needed", r.name),
                        )
                        .detail(&format!(
                            "{about}\nNot on a cadence: it runs when there is something for it \
                             to do."
                        )),
                    ),
                }
            }
        }
        if self.drafts.is_empty() {
            rows.push(Row::head("no system was added"));
            rows.push(Row::info("@none", "nothing to schedule: Enter goes on"));
        }
        TickList::new("Routine upkeep", rows)
    }

    /// Enter on the routine step: what is ticked is staged in each system's entry.
    fn routine_accept(&mut self, w: &mut Win) {
        let Some(list) = self.routine.as_ref() else {
            return;
        };
        let rows: Vec<(String, bool)> = list
            .rows
            .iter()
            .filter(|r| r.kind == ticklist::Kind::Tick)
            .map(|r| (r.key.clone(), r.ticked))
            .collect();
        for (key, ticked) in rows {
            let mut parts = key.splitn(4, '|');
            let (Some(file), Some(entry), Some(wf), Some(every)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let Some(file) = FileId::from_word(file) else {
                continue;
            };
            let text = if ticked { every } else { "" };
            if let Err(why) = self.set_cadence(w, file, entry, wf, text) {
                w.toast(&format!("{entry} · {wf}: {why}"));
            }
        }
    }

    /// A key while the setup flow is on and nothing is in front of its step. None: not
    /// the flow's key (the step's own page or screen takes it).
    pub(crate) fn guide_key(&mut self, w: &mut Win, k: &KeyEvent) -> Option<Option<Fx>> {
        let step = self.guide?;
        match k.code {
            KeyCode::Esc => {
                self.guide_leave_box();
                return Some(None);
            }
            KeyCode::Backspace | KeyCode::Char('b') => return Some(self.guide_go(w, false)),
            _ => {}
        }
        match step {
            Step::Agent => match k.code {
                KeyCode::Enter => {
                    let there = self.agent.found.as_ref().is_some_and(|f| f.path.is_some());
                    if there && self.agent.test.is_none() && !self.agent.testing {
                        self.agent_test(w);
                        w.toast("asking it for one word · Enter goes on");
                        return Some(None);
                    }
                    if matches!(self.agent.test, Some(Tested::NotLoggedIn)) {
                        w.toast("going on without an agent: it isn't logged in");
                    }
                    Some(self.guide_go(w, true))
                }
                KeyCode::Char('n') => {
                    w.toast("going on without an agent");
                    Some(self.guide_go(w, true))
                }
                // Space edits what the cursor is on (Enter is the flow's).
                KeyCode::Char(' ') => Some(self.form_key(w, &KeyEvent::from(KeyCode::Enter))),
                _ => None,
            },
            Step::Machine => match k.code {
                KeyCode::Enter => Some(self.guide_go(w, true)),
                _ => None,
            },
            Step::Systems => match self.add_key(w, k) {
                AddFx::Done => Some(self.guide_go(w, true)),
                AddFx::Leave => {
                    self.guide_leave_box();
                    Some(None)
                }
                AddFx::Stay => Some(None),
            },
            Step::Review => {
                if self.review.is_none() {
                    return match k.code {
                        KeyCode::Enter => Some(self.guide_go(w, true)),
                        _ => Some(None),
                    };
                }
                match self.review_key(w, k) {
                    AddFx::Done => Some(self.guide_go(w, true)),
                    AddFx::Leave => {
                        self.guide_leave_box();
                        Some(None)
                    }
                    AddFx::Stay => Some(None),
                }
            }
            Step::Upkeep => {
                let fx = self
                    .routine
                    .as_mut()
                    .map_or(ticklist::Fx::Enter, |l| l.key(k));
                match fx {
                    ticklist::Fx::Enter => {
                        self.routine_accept(w);
                        Some(self.guide_go(w, true))
                    }
                    ticklist::Fx::Leave => {
                        self.guide_leave_box();
                        Some(None)
                    }
                    _ => Some(None),
                }
            }
            Step::Save => match k.code {
                KeyCode::Enter => Some(self.guide_save(w)),
                _ => None,
            },
        }
    }

    /// The rail over the area's content: the steps, the one in view marked.
    pub(crate) fn draw_rail(&self, f: &mut Frame, area: Rect, t: &Theme) {
        let Some(step) = self.guide else {
            return;
        };
        let narrow = area.width < 100;
        let mut spans = vec![Span::styled(" Setup  ", t.s(t.mag))];
        for (i, s) in Step::ALL.iter().enumerate() {
            if i > 0 {
                spans.push(Span::styled(" › ", t.dim()));
            }
            let here = *s == step;
            let text = match (narrow, here) {
                (true, false) => format!("{}", i + 1),
                _ => format!("{} {}", i + 1, s.name()),
            };
            spans.push(match (here, i < step.at()) {
                (true, _) => Span::styled(format!(" {text} "), t.chip(t.mag)),
                (false, true) => Span::styled(text, t.fg()),
                (false, false) => Span::styled(text, t.dim()),
            });
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    /// What the step in view says under the rail: what Enter does here.
    pub(crate) fn guide_line(&self) -> String {
        let Some(step) = self.guide else {
            return String::new();
        };
        match step {
            Step::Agent => {
                let there = self.agent.found.as_ref().is_some_and(|f| f.path.is_some());
                match (there, &self.agent.test, self.agent.testing) {
                    (true, None, false) => {
                        "Enter tests the agent (one turn, no tools) · n goes on without one"
                    }
                    (true, _, true) => "asking it for one word… · Enter goes on",
                    (true, Some(Tested::Answers(_)), _) => "it answers · Enter goes on",
                    (true, Some(_), _) => "Enter goes on without an agent · t tests it again",
                    (false, _, _) => {
                        "Enter goes on without an agent · Space edits its command, r looks again"
                    }
                }
            }
            Step::Machine => "nothing is required here · Space toggles · Enter goes on",
            Step::Systems => {
                "Space ticks · Enter looks at what is ticked, then goes on · none: this machine"
            }
            Step::Review if self.review.as_ref().is_some_and(|r| r.naming) => {
                "Space edits its name or ssh · Enter accepts and goes on"
            }
            Step::Review if self.review.is_some() => {
                "everything ticked is watched · Space unticks · Enter goes on to its name"
            }
            Step::Review => "no system was added: nothing to review · Enter goes on",
            Step::Upkeep => "Enter accepts what is ticked and goes on · Space unticks",
            Step::Save => "Enter opens the save box: nothing is written before its Enter",
        }
        .to_string()
    }

    /// The box of the area's own that asks before something is done.
    pub(crate) fn step_hints(&self) -> Vec<(&'static str, &'static str)> {
        if self.guide.is_none() {
            return Vec::new();
        }
        vec![
            ("Enter", "go on"),
            ("b", "back"),
            ("Esc", "leave the setup"),
        ]
    }
}

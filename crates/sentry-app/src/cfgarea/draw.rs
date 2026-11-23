//! How the Config area looks: the window's frame in its own colour (the chip, its tab, the
//! rule under its screens), then the screen in view, the key bar, and whatever is in front.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use sentry_core::cfg::{By, FileId};
use sentry_core::tui::form;
use sentry_core::tui::frame;
use sentry_core::tui::modal;
use sentry_core::tui::theme::Theme;
use sentry_core::tui::ticklist;
use sentry_core::tui::widgets::{self, chip};

use super::kind::{Mark, plain, what_changed};
use super::save::Whole;
use super::{ConfigArea, Entry, Page, Problem, Screen, Step, count};
use crate::app::Win;

/// The area's colour: where magenta is, you are in Config.
pub fn accent(t: &Theme) -> Color {
    t.mag
}

impl ConfigArea {
    /// The problems of one entry of a file (None: the file's own).
    fn problems_of(&self, file: FileId, entry: Option<&str>) -> Vec<&Problem> {
        self.problems
            .iter()
            .filter(|p| p.file == file && (file == FileId::App || p.entry.as_deref() == entry))
            .collect()
    }

    pub(crate) fn draw(&mut self, w: &mut Win, f: &mut Frame) {
        let t = w.theme;
        let Some(areas) = frame::layout_ruled(f, &t, false, Some(accent(&t))) else {
            return;
        };
        let now = w.now().to_zoned(jiff::tz::TimeZone::system());
        let conflicts = self.pending.iter().filter(|p| p.conflict.is_some()).count();
        let state = match (self.unsaved(), conflicts, self.problems.len()) {
            (0, 0, 0) => ("○ nothing to save".to_string(), t.dim),
            (0, 0, n) => (format!("! {}", count(n, "problem")), t.yellow),
            (n, 0, _) => (format!("● {n} not saved"), t.yellow),
            (_, c, _) => (format!("! {} no longer fit", count(c, "change")), t.red),
        };
        frame::draw_top(
            f,
            areas.top,
            &t,
            &frame::Top {
                app: "sentry config",
                subject: String::new(),
                auto: false,
                facts: vec!["nothing is written before the save box".to_string()],
                state,
                clock: frame::clock(&now),
                targets: w.strip.clone(),
                focus: w.strip_focus,
                accent: Some(accent(&t)),
            },
        );
        let tabs: Vec<frame::TabItem> = Screen::ALL
            .into_iter()
            .map(|s| {
                let n = self
                    .problems
                    .iter()
                    .filter(|p| self.screen_of(p) == s)
                    .count();
                frame::TabItem {
                    key: s.key().to_string(),
                    name: s.name().to_string(),
                    short: s.short().to_string(),
                    badge: match (s, n) {
                        (Screen::Overview, _) if self.unsaved() > 0 => {
                            Some((format!(" {}*", self.unsaved()), t.yellow))
                        }
                        (Screen::Overview, _) | (_, 0) => None,
                        (_, n) => Some((format!(" {n}"), t.yellow)),
                    },
                    filter: None,
                }
            })
            .collect();
        frame::draw_tab_items(
            f,
            areas.tabs,
            &t,
            &tabs,
            Screen::ALL.iter().position(|s| *s == self.screen),
        );
        // The setup's rail over the content: the steps, and what Enter does on this one.
        let body = match self.guide {
            Some(_) if areas.body.height > 6 => {
                let [rail, line, body] = Layout::vertical([
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                ])
                .areas(areas.body);
                self.draw_rail(f, rail, &t);
                f.render_widget(
                    Paragraph::new(Line::styled(
                        format!(
                            " {}",
                            widgets::trunc(&self.guide_line(), line.width as usize - 2)
                        ),
                        t.dim(),
                    )),
                    line,
                );
                body
            }
            _ => areas.body,
        };
        let panel_w = |body: Rect| {
            let width = if body.width >= 100 {
                body.width as usize * 45 / 100
            } else {
                body.width as usize
            };
            width.saturating_sub(4).max(20)
        };
        let wrapped = |text: &str, body: Rect| -> Vec<Line<'static>> {
            widgets::wrap(text, panel_w(body))
                .into_iter()
                .map(|l| Line::styled(l, t.fg()))
                .collect()
        };
        match (self.page, self.screen) {
            (Page::Add, _) => {
                if let Some(add) = &self.add {
                    let extra = self.add_lines(&t, w.offline);
                    ticklist::draw_panels(f, body, &t, &add.list, &extra);
                }
            }
            (Page::Review, _) => match &self.review {
                Some(r) if r.naming => form::draw_panels(
                    f,
                    body,
                    &t,
                    &r.form,
                    &[Line::styled(
                        "Space edits the field under the cursor · Enter accepts both",
                        t.dim(),
                    )],
                ),
                Some(r) => {
                    let n = self.drafts.len();
                    let extra = vec![Line::styled(
                        format!(
                            "System {} of {n}: what is ticked is what sentry watches there. \
                             Nothing is written before the save box.",
                            r.at + 1
                        ),
                        t.dim(),
                    )];
                    ticklist::draw_panels(f, body, &t, &r.list, &extra);
                }
                None => widgets::placeholder(
                    f,
                    body,
                    &t,
                    &[
                        ("no system was added", t.fg()),
                        ("there is nothing to review: just this machine", t.dim()),
                    ],
                ),
            },
            (Page::Routine, _) => {
                if let Some(l) = &self.routine {
                    let extra = vec![Line::styled(
                        "How often each routine workflow is recommended. Enter accepts what is \
                         ticked; every system's Upkeep changes it later.",
                        t.dim(),
                    )];
                    ticklist::draw_panels(f, body, &t, l, &extra);
                }
            }
            (Page::Shown, _) => {
                if let Some(l) = &self.shown {
                    let extra = vec![Line::styled(
                        "Enter stages it (nothing is written before the save box). Their \
                         order is the field's own list: Enter on it, then J/K.",
                        t.dim(),
                    )];
                    ticklist::draw_panels(f, body, &t, l, &extra);
                }
            }
            (Page::None, _) if self.row.is_some() => {
                if let Some(r) = &self.row {
                    form::draw_panels(
                        f,
                        body,
                        &t,
                        &r.form,
                        &[Line::styled(
                            "One entry of the list: each field is staged as it is set · Esc back",
                            t.dim(),
                        )],
                    );
                }
            }
            (Page::None, Screen::Overview) => self.draw_overview(f, body, &t),
            (Page::None, Screen::Servers | Screen::Networks) => match (&self.form, self.open) {
                (Some(form), true) => {
                    let extra = self
                        .open_system()
                        .map(|(file, e)| self.system_extra(&t, file, &e, panel_w(body)))
                        .unwrap_or_default();
                    form::draw_panels(f, body, &t, form, &extra);
                }
                _ => self.draw_list(f, body, &t),
            },
            (Page::None, Screen::Agent | Screen::Machine | Screen::Window) => match &self.form {
                Some(form) => {
                    let extra = match (self.screen, self.guide) {
                        (Screen::Agent, g) => {
                            let mut l = self.agent.lines(&t, w.offline, panel_w(body));
                            if g == Some(Step::Agent) {
                                l.push(Line::raw(""));
                                l.extend(wrapped(super::guide::WITHOUT_AGENT, body));
                            }
                            l
                        }
                        (Screen::Machine, Some(Step::Machine)) => wrapped(super::guide::HERE, body),
                        _ => Vec::new(),
                    };
                    form::draw_panels(f, body, &t, form, &extra);
                }
                None => {
                    let why = self
                        .file(FileId::App)
                        .and_then(|x| x.err.clone())
                        .unwrap_or_else(|| "config.toml isn't known to this window".into());
                    widgets::placeholder(
                        f,
                        body,
                        &t,
                        &[
                            ("config.toml doesn't parse:", t.s(t.red)),
                            (&why, t.fg()),
                            ("e opens it in $EDITOR", t.dim()),
                        ],
                    );
                }
            },
        }
        // The key bar: the `:` line, else the keys of what is in front.
        let toast = w.toast.as_ref().map(|x| x.msg());
        match &self.cmd {
            Some(line) => {
                let mut spans = vec![Span::styled(":", t.fg())];
                spans.extend(line.spans(&t));
                f.render_widget(Paragraph::new(Line::from(spans)), areas.keybar);
            }
            None => frame::draw_keybar(
                f,
                areas.keybar,
                &t,
                &frame::KeyBar::Hints(self.hints()),
                toast,
            ),
        }
        if self.save.is_some() {
            widgets::dim_backdrop(f.buffer_mut(), body);
            self.draw_save(f, body, &t);
        }
        if self.ask.is_some() || self.prompt.is_some() {
            widgets::dim_backdrop(f.buffer_mut(), body);
            self.draw_box(f, body, &t);
        }
        if let Some(m) = &w.modal {
            widgets::dim_backdrop(f.buffer_mut(), body);
            modal::draw(f, body, &t, m);
        }
    }

    /// What a system is, beside its name: its kind; this machine, what the window calls it.
    fn kind_word(&self, e: &Entry) -> String {
        match self
            .targets
            .iter()
            .find(|x| Some(&x.id) == e.target.as_ref())
        {
            Some(x) if e.name == e.kind => x.title.clone(),
            _ if e.name == e.kind => String::new(),
            _ => e.kind.to_string(),
        }
    }

    /// A system's row: a dot (what is wrong with it), its name, its kind, a word about it.
    fn system_row(&self, t: &Theme, file: FileId, e: &Entry, width: usize) -> Line<'static> {
        let problems = match file {
            FileId::App => self.problems_of(file, None).len(),
            _ => self.problems_of(file, Some(&e.name)).len(),
        };
        let here = self
            .targets
            .iter()
            .find(|x| Some(&x.id) == e.target.as_ref());
        let (dot, color) = match (problems, here) {
            (0, Some(x)) if !x.hidden => ("●", t.green),
            (0, _) => ("○", t.dim),
            _ => ("●", t.yellow),
        };
        let note = match (problems, here) {
            (0, Some(x)) if x.hidden => "hidden".to_string(),
            (0, None) if self.staged_add(file, &e.name).is_some() => "to be added".to_string(),
            (0, None) => "not in the window".to_string(),
            (0, _) => String::new(),
            (n, _) => count(n, "problem"),
        };
        let name = widgets::trunc(&e.name, width.saturating_sub(34).max(12));
        Line::from(vec![
            Span::styled(format!(" {dot} "), t.s(color)),
            Span::styled(format!("{name:<16} "), t.fg()),
            Span::styled(
                format!("{:<17}", widgets::trunc(&self.kind_word(e), 16)),
                t.dim(),
            ),
            Span::styled(note, if problems > 0 { t.s(t.yellow) } else { t.dim() }),
        ])
    }

    /// A staged change's row: `[x] <entry> <field> <what changed>`.
    fn pending_row(&self, t: &Theme, i: usize, width: usize) -> Line<'static> {
        let p = &self.pending[i];
        let (entry, label) = self.named(p);
        let (tick, color) = match (&p.conflict, p.change.on) {
            (Some(_), _) => ("[!]", t.red),
            (None, true) => ("[x]", t.green),
            (None, false) => ("[ ]", t.dim),
        };
        // A system added or removed as a whole says so, not what is in it.
        let (label, what) = match self.whole(p) {
            Some((Whole::Added, _, _)) => (
                "added".to_string(),
                "a new system, as drafted and reviewed".to_string(),
            ),
            Some((Whole::Removed, _, _)) => (
                "removed".to_string(),
                "its records stay on disk".to_string(),
            ),
            None => (
                label,
                what_changed(p.change.from.as_ref(), p.change.to.as_ref()),
            ),
        };
        let by = match p.change.by {
            By::You => "",
            By::Agent => "  (Claude)",
        };
        let head = format!("{entry}  {label}  ");
        let room = width.saturating_sub(head.chars().count() + by.len() + 6);
        Line::from(vec![
            Span::styled(format!(" {tick} "), t.s(color)),
            Span::styled(format!("{entry}  "), t.dim()),
            Span::styled(format!("{label}  "), t.fg()),
            Span::styled(
                widgets::trunc(&what, room),
                if p.conflict.is_some() {
                    t.s(t.red)
                } else {
                    t.s(t.yellow)
                },
            ),
            Span::styled(by, t.s(t.mag)),
        ])
    }

    fn draw_overview(&mut self, f: &mut Frame, body: Rect, t: &Theme) {
        let systems = self.systems();
        let rows = self.overview_rows();
        self.cur = self.cur.min(rows.saturating_sub(1));
        let (left, right) = split(body);
        let pend_h = (self.pending.len() as u16 + 2).clamp(3, (left.height / 2).max(3));
        let [sys_area, pend_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(pend_h)]).areas(left);
        let sel = Style::new().bg(t.sel_bg);

        let block = widgets::panel(t, "Systems", "");
        let inner = widgets::inner(&block, sys_area);
        f.render_widget(block, sys_area);
        let mut lines: Vec<Line> = systems
            .iter()
            .map(|(file, e)| self.system_row(t, *file, e, inner.width as usize))
            .collect();
        lines.push(Line::styled(" + add a system…", t.s(t.mag)));
        for (i, l) in lines.iter_mut().enumerate() {
            if i == self.cur {
                *l = std::mem::take(l).style(sel);
            }
        }
        // Whatever doesn't parse isn't a system yet: said under them.
        for file in &self.files {
            if let Some(e) = &file.err {
                lines.push(Line::styled(
                    format!(
                        " ! {} doesn't parse: {}",
                        file.id.name(),
                        widgets::trunc(e, inner.width as usize)
                    ),
                    t.s(t.red),
                ));
            }
        }
        let off = scroll(
            self.cur.min(lines.len()),
            lines.len(),
            inner.height as usize,
        );
        f.render_widget(
            Paragraph::new(lines.into_iter().skip(off).collect::<Vec<_>>()),
            inner,
        );

        let block = widgets::panel(
            t,
            "Pending",
            match self.pending.len() {
                0 => "nothing staged".to_string(),
                n => count(n, "change"),
            },
        );
        let inner = widgets::inner(&block, pend_area);
        f.render_widget(block, pend_area);
        let at = self.pending_at();
        let lines: Vec<Line> = (0..self.pending.len())
            .map(|i| {
                let l = self.pending_row(t, i, inner.width as usize);
                if Some(i) == at { l.style(sel) } else { l }
            })
            .collect();
        let off = scroll(at.unwrap_or(0), lines.len(), inner.height as usize);
        f.render_widget(
            Paragraph::new(lines.into_iter().skip(off).collect::<Vec<_>>()),
            inner,
        );

        // The right: what the cursor is on.
        let width = right.width.saturating_sub(4) as usize;
        let (title, detail, lines) = match (systems.get(self.cur), at) {
            (Some((file, e)), _) => {
                let (title, detail) = (e.name.clone(), self.kind_word(e));
                (title, detail, self.system_lines(t, *file, e, width))
            }
            (None, Some(i)) => {
                let (entry, label) = self.named(&self.pending[i]);
                (entry, label, self.pending_lines(t, i, width))
            }
            (None, None) => (
                "Add a system".to_string(),
                String::new(),
                widgets::wrap(
                    "A server, or a network through its OpenWrt router. Enter lists the hosts \
                     sentry could look at: the ones in your ssh config, this machine's \
                     default gateway, or one you name. You tick, one box says what is read, \
                     and what each host says becomes a draft you review.",
                    width.max(20),
                )
                .into_iter()
                .map(|l| Line::styled(l, t.fg()))
                .chain([
                    Line::raw(""),
                    Line::styled(
                        "Nothing is read anywhere before you tick, and nothing is ever",
                        t.dim(),
                    ),
                    Line::styled("changed on a host by looking at it.", t.dim()),
                    Line::raw(""),
                    Line::styled(
                        "On the command line: sentry-server init · sentry-network init",
                        t.dim(),
                    ),
                ])
                .collect(),
            ),
        };
        let block = widgets::panel(t, &title, detail);
        let inner = widgets::inner(&block, right);
        f.render_widget(block, right);
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    /// What the Overview says of the selected system.
    fn system_lines(&self, t: &Theme, file: FileId, e: &Entry, width: usize) -> Vec<Line<'static>> {
        let row = |name: &str, text: String| {
            Line::from(vec![
                Span::styled(format!("{name:<12} "), t.dim()),
                Span::styled(text, t.fg()),
            ])
        };
        let mut out = vec![row("What", e.summary.clone())];
        let here = self
            .targets
            .iter()
            .find(|x| Some(&x.id) == e.target.as_ref());
        out.push(row(
            "Window",
            match here {
                Some(x) if x.hidden => {
                    format!("hidden: [targets] show leaves {} out", x.id)
                }
                Some(x) if x.working => format!("a tab ({}), at work now", x.title),
                Some(x) => format!("a tab ({})", x.title),
                None if self
                    .pending
                    .iter()
                    .any(|p| p.change.from.is_none() && self.named(p).0 == e.name) =>
                {
                    "staged to be added: it gets its tab with the save".into()
                }
                None => "not in the window".into(),
            },
        ));
        let doc = self.doc(file);
        out.push(row(
            "File",
            format!(
                "{} · {}",
                file.name(),
                match doc {
                    Some(d) if !d.there() => "not there yet: every setting at its default",
                    Some(d) if d.handwritten() => "written by hand (a save rewrites it)",
                    Some(_) => "as sentry wrote it",
                    None => "doesn't parse",
                }
            ),
        ));
        let problems = match file {
            FileId::App => self.problems_of(file, None),
            _ => self.problems_of(file, Some(&e.name)),
        };
        if !problems.is_empty() {
            out.push(Line::raw(""));
        }
        for p in problems {
            for (i, l) in widgets::wrap(&p.text, width.saturating_sub(2).max(20))
                .into_iter()
                .enumerate()
            {
                out.push(Line::styled(
                    format!("{} {l}", if i == 0 { "!" } else { " " }),
                    t.s(t.yellow),
                ));
            }
        }
        out.extend(self.check_lines(t, file, &e.name, width));
        out.push(Line::raw(""));
        out.push(Line::styled(
            match file {
                FileId::App => format!("Enter opens it · e opens {} in $EDITOR", file.name()),
                _ => "Enter opens it · c checks its connection · x removes it".to_string(),
            },
            t.dim(),
        ));
        out
    }

    /// What a system's connection checks said, as lines.
    fn check_lines(
        &self,
        t: &Theme,
        file: FileId,
        entry: &str,
        width: usize,
    ) -> Vec<Line<'static>> {
        let Some(c) = self.checks_of(file, entry) else {
            return Vec::new();
        };
        let mut out = vec![
            Line::raw(""),
            Line::styled("Connection".to_string(), t.s(t.mag)),
        ];
        if c.running {
            out.push(Line::styled(
                "checking… (reads only: reachable, sudo, tools)",
                t.dim(),
            ));
        }
        for l in &c.lines {
            let style = match l.mark {
                Mark::Ok => t.s(t.green),
                Mark::Note => t.fg(),
                Mark::Bad => t.s(t.red),
            };
            for (i, part) in widgets::wrap(&l.line(), width.saturating_sub(2).max(20))
                .into_iter()
                .enumerate()
            {
                out.push(Line::styled(
                    if i == 0 { part } else { format!("  {part}") },
                    style,
                ));
            }
        }
        out
    }

    /// What a system's form says beside its fields: what is wrong in it, its checks.
    fn system_extra(&self, t: &Theme, file: FileId, e: &Entry, width: usize) -> Vec<Line<'static>> {
        let mut out = Vec::new();
        for p in self.problems_of(file, Some(&e.name)) {
            for (i, l) in widgets::wrap(&p.text, width.saturating_sub(2).max(20))
                .into_iter()
                .enumerate()
            {
                out.push(Line::styled(
                    format!("{} {l}", if i == 0 { "!" } else { " " }),
                    t.s(t.yellow),
                ));
            }
        }
        out.extend(self.check_lines(t, file, &e.name, width));
        if self.checks_of(file, &e.name).is_none() {
            out.push(Line::styled(
                "c checks its connection (reads only)",
                t.dim(),
            ));
        }
        out
    }

    /// A box of the area's own: one that asks before something is done, or a line typed.
    fn draw_box(&self, f: &mut Frame, body: Rect, t: &Theme) {
        let w = 96u16.min(body.width.saturating_sub(2));
        let text_w = w.saturating_sub(4).max(10) as usize;
        let (title, text, keys): (&str, Vec<Line>, Vec<Span>) = match (&self.ask, &self.prompt) {
            (Some(a), _) => {
                let mut lines = Vec::new();
                for l in &a.lines {
                    if l.starts_with("  ") {
                        lines.push(Line::styled(widgets::trunc(l, text_w), t.fg()));
                        continue;
                    }
                    let wrapped = widgets::wrap(l, text_w);
                    if wrapped.is_empty() {
                        lines.push(Line::raw(""));
                    }
                    lines.extend(wrapped.into_iter().map(|p| Line::styled(p, t.fg())));
                }
                let mut keys = chip(t, "Enter", a.enter, accent(t));
                keys.push(Span::raw("   "));
                keys.extend(chip(t, "Esc", "back", t.dim));
                (a.title.as_str(), lines, keys)
            }
            (None, Some(p)) => {
                let mut lines: Vec<Line> = widgets::wrap(&p.help, text_w)
                    .into_iter()
                    .map(|l| Line::styled(l, t.dim()))
                    .collect();
                lines.push(Line::raw(""));
                let mut spans = vec![Span::styled(format!("{}  ", p.label), t.dim())];
                spans.extend(p.line.spans(t));
                lines.push(Line::from(spans));
                let mut keys = chip(t, "Enter", "do it", accent(t));
                keys.push(Span::raw("   "));
                keys.extend(chip(t, "Esc", "leave it", t.dim));
                (p.title.as_str(), lines, keys)
            }
            (None, None) => return,
        };
        let room = body.height.saturating_sub(6) as usize;
        let h = (text.len().min(room) as u16) + 5;
        let rect = widgets::centered(body, w, h);
        let inner = widgets::overlay(f, rect, t, title, accent(t));
        let [area, _, bar] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(inner);
        let area = Rect {
            y: area.y + 1,
            height: area.height.saturating_sub(1),
            ..area
        };
        f.render_widget(
            Paragraph::new(text.into_iter().take(room).collect::<Vec<_>>()),
            area,
        );
        f.render_widget(Paragraph::new(Line::from(keys)), bar);
    }

    /// What the Overview says of the selected staged change: before → after.
    fn pending_lines(&self, t: &Theme, i: usize, width: usize) -> Vec<Line<'static>> {
        let p = &self.pending[i];
        let c = &p.change;
        let wrapped = |name: &str, text: String, style: Style| -> Vec<Line<'static>> {
            widgets::wrap(&text, width.saturating_sub(8).max(20))
                .into_iter()
                .enumerate()
                .map(|(j, l)| {
                    Line::from(vec![
                        Span::styled(format!("{:<7} ", if j == 0 { name } else { "" }), t.dim()),
                        Span::styled(l, style),
                    ])
                })
                .collect()
        };
        let mut out = vec![Line::styled(
            format!("{} · {}", c.file.name(), c.path),
            t.dim(),
        )];
        out.push(Line::raw(""));
        out.extend(wrapped("before", plain(c.from.as_ref()), t.fg()));
        out.extend(wrapped("after", plain(c.to.as_ref()), t.s(t.yellow)));
        out.push(Line::raw(""));
        if let Some(why) = &p.conflict {
            out.extend(
                widgets::wrap(
                    &format!("! It no longer fits the file: {why}"),
                    width.max(20),
                )
                .into_iter()
                .map(|l| Line::styled(l, t.s(t.red))),
            );
            out.push(Line::styled(
                "u takes it back · Space tries it again",
                t.dim(),
            ));
            return out;
        }
        if c.by == By::Agent {
            out.push(Line::styled("Proposed by Claude.", t.s(t.mag)));
        }
        if let Some(help) = self.kind(c.file).and_then(|k| k.explain(&c.path)) {
            out.extend(
                widgets::wrap(help, width.max(20))
                    .into_iter()
                    .map(|l| Line::styled(l, t.dim())),
            );
            out.push(Line::raw(""));
        }
        out.push(Line::styled(
            if c.on {
                "In the next save · Space leaves it out · u takes it back"
            } else {
                "Left out of the next save · Space ticks it · u takes it back"
            },
            t.dim(),
        ));
        out
    }

    /// Servers and Networks: the entries, and the selected one's settings to read.
    fn draw_list(&mut self, f: &mut Frame, body: Rect, t: &Theme) {
        let Some(file) = self.screen.file() else {
            return;
        };
        let entries = self.entries_of(self.screen);
        let l = self.list_of(self.screen).unwrap_or(0);
        self.list[l] = self.list[l].min(entries.len().saturating_sub(1));
        let (left, right) = split(body);
        let block = widgets::panel(
            t,
            self.screen.name(),
            match entries.len() {
                0 => String::new(),
                n => n.to_string(),
            },
        );
        let inner = widgets::inner(&block, left);
        f.render_widget(block, left);
        let err = self.file(file).and_then(|x| x.err.clone());
        if let Some(e) = &err {
            widgets::placeholder(
                f,
                inner,
                t,
                &[
                    (&format!("{} doesn't parse:", file.name()), t.s(t.red)),
                    (e, t.fg()),
                    ("e opens it in $EDITOR", t.dim()),
                ],
            );
        } else if entries.is_empty() {
            let (none, init) = match self.screen {
                Screen::Servers => ("no servers configured", "sentry-server init <ssh-host>"),
                _ => ("no networks configured", "sentry-network init <ssh-host>"),
            };
            widgets::placeholder(
                f,
                inner,
                t,
                &[
                    (none, t.dim()),
                    ("Enter looks for one to add", t.fg()),
                    (&format!("on the command line: {init}"), t.dim()),
                ],
            );
        } else {
            let lines: Vec<Line> = entries
                .iter()
                .enumerate()
                .map(|(i, e)| {
                    let line = self.system_row(t, file, e, inner.width as usize);
                    if i == self.list[l] {
                        line.style(Style::new().bg(t.sel_bg))
                    } else {
                        line
                    }
                })
                .collect();
            let off = scroll(self.list[l], lines.len(), inner.height as usize);
            f.render_widget(
                Paragraph::new(lines.into_iter().skip(off).collect::<Vec<_>>()),
                inner,
            );
        }
        let Some(e) = entries.get(self.list[l]) else {
            let block = widgets::panel(t, file.name(), "");
            f.render_widget(block, right);
            return;
        };
        let block = widgets::panel(t, &e.name, self.kind_word(e));
        let inner = widgets::inner(&block, right);
        f.render_widget(block, right);
        let width = inner.width as usize;
        let mut lines = self.system_lines(t, file, e, width);
        lines.pop();
        lines.push(Line::styled(
            format!(
                "Enter opens its settings · c checks its connection · x removes it · e opens {}",
                file.name()
            ),
            t.dim(),
        ));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    /// The save box, over the body: its lines wrapped, scrolled when there are too many.
    fn draw_save(&self, f: &mut Frame, body: Rect, t: &Theme) {
        let Some(b) = &self.save else {
            return;
        };
        let w = 100u16.min(body.width.saturating_sub(2));
        let text_w = w.saturating_sub(4).max(10) as usize;
        let mut lines: Vec<Line> = Vec::new();
        for l in &b.lines {
            let style = if l.starts_with('!') {
                t.s(t.yellow)
            } else if l.starts_with("  ") {
                t.fg()
            } else {
                t.dim()
            };
            // What is written, line by line: cut, never wrapped (its columns stay).
            if l.starts_with("  ") {
                lines.push(Line::styled(widgets::trunc(l, text_w), style));
                continue;
            }
            let wrapped = widgets::wrap(l, text_w);
            if wrapped.is_empty() {
                lines.push(Line::raw(""));
            }
            lines.extend(wrapped.into_iter().map(|part| Line::styled(part, style)));
        }
        let room = body.height.saturating_sub(6) as usize;
        let over = lines.len() > room;
        let h = (lines.len().min(room) as u16) + 5;
        let rect = widgets::centered(body, w, h);
        let inner = widgets::overlay(f, rect, t, "Save configuration", accent(t));
        let [text, _, keys] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(inner);
        let text = Rect {
            y: text.y + 1,
            height: text.height.saturating_sub(1),
            ..text
        };
        let off = self.save_at().min(lines.len().saturating_sub(room));
        f.render_widget(
            Paragraph::new(lines.into_iter().skip(off).take(room).collect::<Vec<_>>()),
            text,
        );
        let mut spans = match b.refused {
            true => Vec::new(),
            false => {
                let mut s = chip(t, "Enter", "save", accent(t));
                s.push(Span::raw("   "));
                s
            }
        };
        spans.extend(chip(t, "Esc", "back", t.dim));
        if over {
            spans.push(Span::raw("   "));
            spans.extend(chip(t, "j/k", "the rest", t.dim));
        }
        spans.push(Span::styled(
            "   nothing is written before Enter",
            t.dim().add_modifier(Modifier::ITALIC),
        ));
        f.render_widget(Paragraph::new(Line::from(spans)), keys);
    }
}

/// Left and right of the body: side by side where there is room, else one over the other.
fn split(body: Rect) -> (Rect, Rect) {
    if body.width >= 100 {
        let [l, r] =
            Layout::horizontal([Constraint::Percentage(46), Constraint::Fill(1)]).areas(body);
        (l, r)
    } else {
        let [l, r] =
            Layout::vertical([Constraint::Percentage(55), Constraint::Fill(1)]).areas(body);
        (l, r)
    }
}

/// How far a list of `len` is scrolled so the row `at` is in `height`.
fn scroll(at: usize, len: usize, height: usize) -> usize {
    if height == 0 || len <= height {
        return 0;
    }
    at.saturating_sub(height / 2).min(len - height)
}

//! The Review window (`R` on Maintenance), in both programs: Claude's review with the
//! changes it proposes to the list on top, ticked. Space unticks one, Enter applies those
//! left ticked together. Before a review: the brief, and Enter starts it.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Wrap};

use super::docview::{Writer, markdown};
use super::theme::Theme;
use super::widgets::trunc;
use crate::maint::changes::{Change, Group, State};
use crate::maint::review::ReviewDoc;

/// The window's own state; the review it shows is the app's.
#[derive(Debug, Clone, Default)]
pub struct ReviewView {
    /// The change selected.
    pub cur: usize,
    /// The review's text, lines scrolled from the top.
    pub scroll: usize,
    /// Showing what a new review would read: Enter starts it.
    pub brief: bool,
}

/// What a key asks the app to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fx {
    None,
    Close,
    /// Have Claude write a review.
    Start,
    /// Stop Claude writing.
    Stop,
    /// Apply the ticked changes.
    Apply,
}

impl ReviewView {
    /// The brief when there's nothing left to apply, else the review.
    pub fn open(doc: Option<&ReviewDoc>) -> Self {
        Self {
            brief: doc.is_none_or(|d| d.open().is_empty()),
            ..Default::default()
        }
    }

    /// A review, as it is (from Records).
    pub fn show() -> Self {
        Self::default()
    }

    pub fn key(&mut self, k: KeyEvent, doc: Option<&mut ReviewDoc>, writing: bool) -> Fx {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => return Fx::Close,
            KeyCode::Char('c') if ctrl && writing => return Fx::Stop,
            KeyCode::PageDown => self.scroll += 10,
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Home => self.scroll = 0,
            KeyCode::End => self.scroll = usize::MAX / 2,
            _ if writing => match k.code {
                KeyCode::Down | KeyCode::Char('j') => self.scroll += 1,
                KeyCode::Up | KeyCode::Char('k') => self.scroll = self.scroll.saturating_sub(1),
                _ => {}
            },
            KeyCode::Enter if self.brief => return Fx::Start,
            _ if self.brief => {}
            KeyCode::Char('R') => {
                self.brief = true;
                self.scroll = 0;
            }
            _ => {
                let Some(doc) = doc else { return Fx::None };
                let n = doc.head.changes.len();
                match k.code {
                    // With no changes the keys scroll the text.
                    KeyCode::Down | KeyCode::Char('j') if n == 0 => self.scroll += 1,
                    KeyCode::Up | KeyCode::Char('k') if n == 0 => {
                        self.scroll = self.scroll.saturating_sub(1)
                    }
                    KeyCode::Down | KeyCode::Char('j') => self.cur = (self.cur + 1).min(n - 1),
                    KeyCode::Up | KeyCode::Char('k') => self.cur = self.cur.saturating_sub(1),
                    KeyCode::Char('g') => self.cur = 0,
                    KeyCode::Char('G') => self.cur = n.saturating_sub(1),
                    KeyCode::Char(' ') => {
                        if let Some(c) = doc.head.changes.get_mut(self.cur)
                            && c.state == State::Open
                        {
                            c.on = !c.on;
                        }
                    }
                    KeyCode::Enter if !doc.open().is_empty() => return Fx::Apply,
                    _ => {}
                }
            }
        }
        Fx::None
    }

    pub fn hints(
        &self,
        doc: Option<&ReviewDoc>,
        writing: bool,
    ) -> Vec<(&'static str, &'static str)> {
        if writing {
            return vec![
                ("j/k", "scroll"),
                ("C-c", "stop Claude"),
                ("Esc", "back (it carries on)"),
            ];
        }
        if self.brief {
            return vec![("Enter", "start the review"), ("Esc", "back")];
        }
        let mut h = Vec::new();
        if doc.is_some_and(|d| !d.open().is_empty()) {
            h.extend([
                ("Enter", "apply the ticked"),
                ("Space", "tick/untick"),
                ("j/k", "select"),
            ]);
        } else if doc.is_some_and(|d| !d.head.changes.is_empty()) {
            h.push(("j/k", "select"));
        } else {
            h.push(("j/k", "scroll"));
        }
        h.extend([
            ("PgUp/Dn", "scroll"),
            ("R", "review again"),
            ("Esc", "back"),
        ]);
        h
    }
}

/// "6 applied · 1 skipped", for the header and the toast.
pub fn outcome(done: usize, skipped: usize, failed: usize) -> String {
    let mut w = vec![format!("{done} applied")];
    if skipped > 0 {
        w.push(format!("{skipped} skipped"));
    }
    if failed > 0 {
        w.push(format!("{failed} failed"));
    }
    w.join(" · ")
}

fn rule(f: &mut Frame, area: Rect, t: &Theme) {
    f.render_widget(
        Paragraph::new("─".repeat(area.width as usize)).style(t.s(t.border)),
        area,
    );
}

/// What the window shows.
pub struct Shown<'a> {
    pub doc: Option<&'a ReviewDoc>,
    /// Claude writing a review now.
    pub writer: Option<&'a Writer>,
    /// What a new review would read (shown before one is started).
    pub brief: &'a [Line<'static>],
    /// Where the review shown is kept.
    pub path: &'a str,
}

pub fn draw(f: &mut Frame, area: Rect, t: &Theme, v: &ReviewView, s: &Shown) {
    let Shown {
        doc,
        writer,
        brief,
        path,
    } = *s;
    f.render_widget(Clear, area);
    let writing = writer.is_some_and(|w| w.running());
    let changes: &[Change] = doc.map_or(&[], |d| &d.head.changes);
    let listed = !writing && !v.brief && !changes.is_empty();
    // The list's lines: a heading per group, then its changes.
    let mut list: Vec<(Option<usize>, Line<'static>)> = Vec::new();
    if listed {
        let mut group: Option<Group> = None;
        for (i, c) in changes.iter().enumerate() {
            if group != Some(c.group()) {
                group = Some(c.group());
                list.push((
                    None,
                    Line::styled(
                        format!(" {}", c.group().word()),
                        t.s(t.mag).add_modifier(Modifier::BOLD),
                    ),
                ));
            }
            list.push((Some(i), row(t, c, i == v.cur, area.width as usize)));
        }
        for d in doc.into_iter().flat_map(|d| &d.head.dropped) {
            list.push((None, Line::styled(format!("   not used: {d}"), t.dim())));
        }
    }
    let room = area.height.saturating_sub(3);
    let list_h = (list.len() as u16).min(room / 2);
    let detail_h = if listed { 2 } else { 0 };
    let [head, r1, list_area, r2, detail, r3, body] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(list_h),
        Constraint::Length(listed as u16),
        Constraint::Length(detail_h),
        Constraint::Length(listed as u16),
        Constraint::Fill(1),
    ])
    .areas(area);

    // Header.
    let mut l1 = vec![Span::styled(
        " Maintenance review ",
        Style::new()
            .fg(t.ink)
            .bg(t.mag)
            .add_modifier(Modifier::BOLD),
    )];
    if let Some(d) = doc.filter(|_| !v.brief || writing) {
        l1.push(Span::styled(
            format!(
                "  {}",
                d.head
                    .created
                    .map_or(String::new(), |u| u.strftime("%Y-%m-%d %H:%M").to_string())
            ),
            t.fg(),
        ));
    }
    let open: Vec<&Change> = changes.iter().filter(|c| c.state == State::Open).collect();
    let count = |s: State| changes.iter().filter(|c| c.state == s).count();
    if listed && !open.is_empty() {
        let ticked = open.iter().filter(|c| c.on).count();
        l1.push(Span::styled(
            format!(
                "  {} change{} · Enter applies the {ticked} ticked",
                open.len(),
                if open.len() == 1 { "" } else { "s" }
            ),
            t.s(t.yellow),
        ));
    } else if listed {
        l1.push(Span::styled(
            format!(
                "  {}",
                outcome(
                    count(State::Applied),
                    count(State::Skipped),
                    count(State::Failed)
                )
            ),
            t.s(t.green),
        ));
    }
    let l2 = match writer.filter(|w| w.running()) {
        Some(w) => Line::styled(format!(" {}", w.progress()), t.s(t.cyan)),
        None if v.brief => Line::styled(
            " what to maintain next, and how the list should change · Enter starts",
            t.dim(),
        ),
        None if doc.is_some() => Line::styled(format!(" {path}"), t.dim()),
        None => Line::raw(""),
    };
    f.render_widget(Paragraph::new(vec![Line::from(l1), l2]), head);
    rule(f, r1, t);

    if listed {
        // Keep the selected change in view.
        let at = list
            .iter()
            .position(|(i, _)| *i == Some(v.cur))
            .unwrap_or(0);
        let h = list_h as usize;
        let top = (at + 1).saturating_sub(h).min(list.len().saturating_sub(h));
        // Its group heading too, when it fits.
        let top = if at > 0 && top == at {
            top.saturating_sub(1)
        } else {
            top
        };
        let lines: Vec<Line> = list.into_iter().map(|(_, l)| l).skip(top).take(h).collect();
        f.render_widget(Paragraph::new(lines), list_area);
        rule(f, r2, t);
        if let Some(c) = changes.get(v.cur) {
            let w = area.width.saturating_sub(2) as usize;
            let l1 = Line::from(vec![
                Span::styled(
                    format!(" {} {}: ", c.word(), c.name()),
                    t.fg().add_modifier(Modifier::BOLD),
                ),
                Span::styled(trunc(&c.label, w), t.fg()),
            ]);
            let l2 = if c.note.is_empty() {
                Line::styled(format!(" {}", trunc(&c.why, w)), t.dim())
            } else {
                Line::styled(
                    format!(" {}", trunc(&c.note, w)),
                    t.s(if c.state == State::Failed {
                        t.red
                    } else {
                        t.green
                    }),
                )
            };
            f.render_widget(Paragraph::new(vec![l1, l2]), detail);
        }
        rule(f, r3, t);
    }

    let lines: Vec<Line> = if v.brief && !writing {
        brief.to_vec()
    } else {
        match doc {
            Some(d) if writing => {
                let mut l = vec![
                    Line::styled(
                        "  Claude is writing a new review; the last one is below.",
                        t.s(t.cyan),
                    ),
                    Line::raw(""),
                ];
                l.extend(markdown(t, &d.body));
                l
            }
            Some(d) => markdown(t, &d.body),
            None if writing => vec![Line::styled(
                "  The review appears here when Claude has gathered what it needs and written it.",
                t.dim(),
            )],
            None => brief.to_vec(),
        }
    };
    let top = v
        .scroll
        .min(lines.len().saturating_sub(body.height as usize));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((top as u16, 0)),
        body,
    );
}

/// One change: ` ▸[x] task   ups-check     Check the UPS battery     the UPS was retired`.
fn row(t: &Theme, c: &Change, selected: bool, width: usize) -> Line<'static> {
    let (mark, mark_style) = match c.state {
        State::Open if c.on => ("[x]", t.s(t.yellow)),
        State::Open => ("[ ]", t.dim()),
        State::Applied => (" ✓ ", t.s(t.green)),
        State::Skipped => (" – ", t.dim()),
        State::Failed => (" ✗ ", t.s(t.red)),
    };
    let live = c.state == State::Applied || (c.state == State::Open && c.on);
    let text = if live { t.fg() } else { t.dim() };
    // What's left after the fixed columns is shared by the label and the why.
    let rest = width.saturating_sub(2 + 3 + 1 + 7 + 22 + 4);
    let label_w = (rest * 2 / 5).clamp(12, 44);
    let why_w = rest.saturating_sub(label_w);
    let why = if c.state == State::Failed {
        &c.note
    } else {
        &c.why
    };
    let mut l = Line::from(vec![
        Span::styled(if selected { " ▸" } else { "  " }, t.s(t.cyan)),
        Span::styled(mark, mark_style),
        Span::styled(format!(" {:<7}", c.word()), t.dim()),
        Span::styled(format!("{:<22}", trunc(c.name(), 21)), text),
        Span::styled(format!("{:<label_w$}  ", trunc(&c.label, label_w)), text),
        Span::styled(
            trunc(why, why_w),
            if c.state == State::Failed {
                t.s(t.red)
            } else {
                t.dim()
            },
        ),
    ]);
    if selected {
        l = l.style(Style::new().bg(t.sel_bg));
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maint::changes::{Known, settle};

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    #[test]
    fn space_unticks_and_enter_applies_once() {
        let rows = [("updates".to_string(), "Install updates".to_string())];
        let mut d = ReviewDoc::new("");
        d.take_answer(
            "# Review\n```sentry-changes\n\
             [[add]]\nid = \"a\"\ntitle = \"A\"\nlevel = \"soon\"\ndo = \"by-hand\"\n\n\
             [[later]]\nkey = \"updates\"\nuntil = 2027-01-01\n```",
            &Known {
                rows: &rows,
                ..Default::default()
            },
            "2026-11-16".parse().unwrap(),
        );
        // Nothing to apply: the brief, and Enter starts a review.
        let mut v = ReviewView::open(None);
        assert!(v.brief);
        assert_eq!(v.key(key(KeyCode::Enter), None, false), Fx::Start);
        // A review with changes: the list.
        let mut v = ReviewView::open(Some(&d));
        assert!(!v.brief);
        assert_eq!(v.hints(Some(&d), false)[0], ("Enter", "apply the ticked"));
        v.key(key(KeyCode::Char('j')), Some(&mut d), false);
        v.key(key(KeyCode::Char('j')), Some(&mut d), false);
        assert_eq!(v.cur, 1, "stops at the last");
        v.key(key(KeyCode::Char(' ')), Some(&mut d), false);
        assert!(d.head.changes[0].on && !d.head.changes[1].on);
        assert_eq!(v.key(key(KeyCode::Enter), Some(&mut d), false), Fx::Apply);
        assert_eq!(
            settle(&mut d.head.changes, |_| Ok("done".into())),
            (1, 1, 0)
        );
        // Applied: Enter and Space do nothing more; R offers a new one.
        assert_eq!(v.key(key(KeyCode::Enter), Some(&mut d), false), Fx::None);
        v.key(key(KeyCode::Char(' ')), Some(&mut d), false);
        assert_eq!(d.head.changes[1].state, State::Skipped);
        assert_eq!(
            v.key(key(KeyCode::Char('R')), Some(&mut d), false),
            Fx::None
        );
        assert!(v.brief);
        assert_eq!(v.key(key(KeyCode::Enter), Some(&mut d), false), Fx::Start);
        // While Claude writes: only scrolling, stopping, leaving.
        let mut v = ReviewView::show();
        assert_eq!(v.key(key(KeyCode::Enter), Some(&mut d), true), Fx::None);
        assert_eq!(
            v.key(
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                Some(&mut d),
                true
            ),
            Fx::Stop
        );
        assert_eq!(v.key(key(KeyCode::Esc), Some(&mut d), true), Fx::Close);
        assert_eq!(outcome(6, 1, 0), "6 applied · 1 skipped");
    }
}

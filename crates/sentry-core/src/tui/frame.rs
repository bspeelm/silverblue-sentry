//! The frame both programs draw in, so they look and answer keys the same: the top bar, the
//! screen strip, a workflow's banner, the body, and the key bar (hints, a toast, or the line
//! being typed). Also what sits over the body (the run pane, help, the quit and Claude boxes)
//! and the one order in which whatever is open gets a key.

use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::ScreenId;
use super::modal::{Choice, Modal};
use super::theme::Theme;
use super::widgets::{self, chip};

/// Where everything goes. The body starts one row under the strip's rule (or the banner).
pub struct Areas {
    pub top: Rect,
    pub tabs: Rect,
    /// One row while a workflow runs off its own screen, else none.
    pub banner: Rect,
    pub body: Rect,
    pub keybar: Rect,
}

/// Lay the frame out and draw its two rules. None: the terminal is under 80×24, and says so.
pub fn layout(f: &mut Frame, t: &Theme, banner: bool) -> Option<Areas> {
    let area = f.area();
    if area.width < 80 || area.height < 24 {
        widgets::placeholder(
            f,
            area,
            t,
            &[(
                &format!(
                    "terminal too small ({}×{}, need 80×24)",
                    area.width, area.height
                ),
                t.dim(),
            )],
        );
        return None;
    }
    let [top, tabs, rule, banner, body, keyrule, keybar] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(banner as u16),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    for r in [rule, keyrule] {
        f.render_widget(
            Paragraph::new("─".repeat(r.width as usize)).style(t.s(t.border)),
            r,
        );
    }
    Some(Areas {
        top,
        tabs,
        banner,
        body: Rect {
            y: body.y + 1,
            height: body.height.saturating_sub(1),
            ..body
        },
        keybar,
    })
}

/// The clock in the top bar.
pub fn clock(now: &jiff::Zoned) -> String {
    now.strftime("%a %d %b %H:%M").to_string()
}

/// What a target in the strip is doing, as its mark says: nothing, at work (`*`), or waiting
/// for the user (`!`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mark {
    #[default]
    None,
    Working,
    You,
}

/// One target in the top bar's strip.
#[derive(Debug, Clone, Default)]
pub struct TargetTab {
    /// The key that gives it the window (`F1`), if one is bound.
    pub key: Option<String>,
    pub name: String,
    pub mark: Mark,
    /// Auto mode is on for it.
    pub auto: bool,
}

/// The top bar: the program, what it watches and a few facts on the left; its state and
/// the clock on the right.
pub struct Top<'a> {
    /// The chip: `sentry`, `sentry-server`.
    pub app: &'a str,
    pub subject: String,
    /// Auto mode is on for it: said beside its name.
    pub auto: bool,
    /// Dim, in order; the first go first when it's narrow.
    pub facts: Vec<String>,
    pub state: (String, Color),
    pub clock: String,
    /// The target strip, when more than one target is open: it takes the subject's place
    /// (`focus` is the one in view). With one target there is no strip.
    pub targets: Vec<TargetTab>,
    pub focus: usize,
}

/// How the targets' names are written: in full, the others cut short, or the others as their
/// keys and marks only. The one in view is always in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetNames {
    Full,
    Short,
    Keys,
}

/// The target strip: key, name, mark and `auto` each; the one in view inverted.
fn target_spans(t: &Theme, top: &Top, how: TargetNames) -> Vec<Span<'static>> {
    let mut spans = vec![Span::raw(" ")];
    for (i, tab) in top.targets.iter().enumerate() {
        let on = i == top.focus;
        let (fg, kc, bg) = if on {
            (t.ink, t.ink, Style::new().bg(t.fg))
        } else {
            (t.fg, t.dim, Style::new())
        };
        let name: String = match how {
            _ if on => tab.name.clone(),
            TargetNames::Full => tab.name.clone(),
            TargetNames::Short if tab.name.chars().count() > 8 => {
                tab.name.chars().take(7).chain(['…']).collect()
            }
            TargetNames::Short => tab.name.clone(),
            // Without a key to name it by, a letter or two still says which it is.
            TargetNames::Keys if tab.key.is_none() => tab.name.chars().take(2).collect(),
            TargetNames::Keys => String::new(),
        };
        if let Some(k) = &tab.key {
            spans.push(Span::styled(format!(" {k}"), bg.fg(kc)));
        }
        if !name.is_empty() {
            spans.push(Span::styled(format!(" {name}"), bg.fg(fg)));
        }
        match tab.mark {
            Mark::None => {}
            Mark::Working => spans.push(Span::styled(" *", bg.fg(if on { t.ink } else { t.cyan }))),
            Mark::You => spans.push(Span::styled(
                " !",
                bg.fg(if on { t.ink } else { t.yellow })
                    .add_modifier(Modifier::BOLD),
            )),
        }
        if tab.auto {
            spans.push(Span::styled(
                " auto",
                bg.fg(if on { t.ink } else { t.yellow })
                    .add_modifier(Modifier::BOLD),
            ));
        }
        spans.push(Span::styled(" ", bg));
        spans.push(Span::raw(" "));
    }
    spans
}

/// The two sides of the top bar as they fit in `width`: facts are dropped from the front,
/// then the clock, then the other targets' names are cut short and left out; never the state.
fn top_lines(t: &Theme, top: &Top, width: u16) -> (Line<'static>, Line<'static>) {
    let mut facts = top.facts.clone();
    let mut clock = Some(top.clock.clone());
    let mut names = TargetNames::Full;
    loop {
        let mut left = vec![Span::styled(
            format!(" {} ", top.app),
            Style::new()
                .fg(t.ink)
                .bg(t.cyan)
                .add_modifier(Modifier::BOLD),
        )];
        if top.targets.len() > 1 {
            left.extend(target_spans(t, top, names));
        } else {
            left.push(Span::styled(format!("  {}", top.subject), t.fg()));
            if top.auto {
                left.push(Span::styled(
                    " · auto",
                    t.s(t.yellow).add_modifier(Modifier::BOLD),
                ));
            }
        }
        left.extend(
            facts
                .iter()
                .map(|x| Span::styled(format!("  {x}"), t.dim())),
        );
        let right = Line::from(vec![
            Span::styled(top.state.0.clone(), t.s(top.state.1)),
            Span::styled(
                match &clock {
                    Some(c) => format!("   {c} "),
                    None => " ".to_string(),
                },
                t.dim(),
            ),
        ]);
        let left = Line::from(left);
        if left.width() + right.width() < width as usize {
            return (left, right);
        }
        if !facts.is_empty() {
            facts.remove(0);
        } else if clock.is_some() {
            clock = None;
        } else if top.targets.len() > 1 && names != TargetNames::Keys {
            names = match names {
                TargetNames::Full => TargetNames::Short,
                _ => TargetNames::Keys,
            };
        } else {
            return (left, right);
        }
    }
}

pub fn draw_top(f: &mut Frame, area: Rect, t: &Theme, top: &Top) {
    let (left, right) = top_lines(t, top, area.width);
    let rw = (right.width() as u16).min(area.width);
    f.render_widget(Paragraph::new(left), area);
    f.render_widget(
        Paragraph::new(right),
        Rect {
            x: area.right().saturating_sub(rw),
            width: rw,
            ..area
        },
    );
}

/// One screen in the strip.
pub struct Tab {
    pub id: ScreenId,
    pub badge: Option<(String, Color)>,
    /// Its `/` filter, when there is one.
    pub filter: Option<String>,
}

/// How the names are written in `width`: all in full, short (the active one stays full), or
/// keys only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Names {
    Full,
    Short,
    Keys,
}

fn names(tabs: &[Tab], width: usize) -> Names {
    let full: usize = tabs.iter().map(|s| s.id.name().len() + 4).sum();
    let short: usize = tabs.iter().map(|s| s.id.short().len() + 4).sum();
    if full + 6 <= width {
        Names::Full
    } else if short + 6 <= width {
        Names::Short
    } else {
        Names::Keys
    }
}

/// The screen strip: key, name, badge and filter each; the active one inverted.
pub fn draw_tabs(f: &mut Frame, area: Rect, t: &Theme, tabs: &[Tab], active: ScreenId) {
    let how = names(tabs, area.width as usize);
    let mut spans = Vec::new();
    for tab in tabs {
        let id = tab.id;
        let on = id == active;
        let name = match how {
            _ if on => id.name(),
            Names::Full => id.name(),
            Names::Short => id.short(),
            Names::Keys => "",
        };
        let (fg, kc, bg) = if on {
            (t.ink, t.ink, t.fg)
        } else {
            (t.fg, t.dim, Color::Reset)
        };
        let bg_style = if on {
            Style::new().bg(bg)
        } else {
            Style::new()
        };
        spans.push(Span::styled(format!(" {}", id.key()), bg_style.fg(kc)));
        if !name.is_empty() {
            spans.push(Span::styled(format!(" {name}"), bg_style.fg(fg)));
        }
        if let Some((b, c)) = &tab.badge {
            spans.push(Span::styled(
                b.clone(),
                bg_style.fg(if on { t.ink } else { *c }),
            ));
        }
        if let Some(flt) = tab.filter.as_ref().filter(|s| !s.is_empty()) {
            spans.push(Span::styled(
                format!(" /{flt}"),
                bg_style.fg(if on { t.ink } else { t.cyan }),
            ));
        }
        spans.push(Span::styled(" ", bg_style));
        spans.push(Span::raw(" "));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// A workflow in progress, shown on every screen but its own.
pub struct Banner<'a> {
    pub workflow: &'a str,
    /// The step it's at: (number, of how many, its title).
    pub step: Option<(usize, usize, String)>,
    pub state: &'a str,
    /// Auto mode is on.
    pub auto: bool,
}

pub fn draw_banner(f: &mut Frame, area: Rect, t: &Theme, b: &Banner) {
    let hint = "press 0 to continue";
    let n = b.step.as_ref().map_or(0, |s| s.1);
    let state = if b.auto {
        format!("{} · auto", b.state)
    } else {
        b.state.to_string()
    };
    // The step's title gets what the rest leaves.
    let fixed = format!(" ↻ workflow {} · step 99/{n}  · {state}   ", b.workflow);
    let room = (area.width as usize).saturating_sub(fixed.chars().count() + hint.len());
    let step = b.step.as_ref().map_or(String::new(), |(i, n, title)| {
        format!("step {i}/{n} {}", widgets::trunc(title, room))
    });
    let line = Line::from(vec![
        Span::styled(
            format!(" ↻ workflow {} · {step} · {state}   ", b.workflow),
            t.s(t.yellow),
        ),
        Span::styled(hint, t.dim()),
    ]);
    f.render_widget(
        Paragraph::new(line).style(Style::new().bg(t.banner_bg)),
        area,
    );
}

/// A series in progress, in the banner row (when no workflow's banner is there).
pub fn draw_series(f: &mut Frame, area: Rect, t: &Theme, line: &str, hint: &str) {
    let room = (area.width as usize).saturating_sub(hint.chars().count() + 8);
    let line = Line::from(vec![
        Span::styled(
            format!(" ▸ {}   ", widgets::trunc(line, room)),
            t.s(t.yellow),
        ),
        Span::styled(hint.to_string(), t.dim()),
    ]);
    f.render_widget(
        Paragraph::new(line).style(Style::new().bg(t.banner_bg)),
        area,
    );
}

pub type Hints<'a> = Vec<(&'a str, &'a str)>;

/// What the key bar shows: the line being typed, or the keys that act now.
pub enum KeyBar<'a> {
    Filter(&'a str),
    Command(&'a str),
    Prompt {
        label: String,
        text: &'a str,
        /// What Enter does, in a word.
        enter: &'a str,
        /// What was wrong with the last answer: shown in place of the hint.
        note: Option<String>,
    },
    Hints(Hints<'a>),
    /// The sudo password being typed (`applyview::password_line`).
    Password(Line<'a>),
}

pub const CONFIRM_HINTS: [(&str, &str); 2] = [("Enter", "confirm"), ("Esc", "cancel")];
pub const CHOICE_HINTS: [(&str, &str); 2] = [("1–9", "choose"), ("Esc", "cancel")];

/// The run pane's keys.
pub fn run_hints(done: bool) -> Hints<'static> {
    if done {
        vec![("Esc", "close"), ("j/k", "scroll")]
    } else {
        vec![("C-c", "terminate"), ("j/k", "scroll")]
    }
}

/// A screen's hints with the keys that work everywhere after them. `A` is global but
/// invisible unless it's in the bar: a screen may name its own; a hidden conversation
/// (`hidden`: what it's doing) takes the key over; otherwise it asks Claude when there is one.
pub fn with_globals<'a>(mut h: Hints<'a>, hidden: Option<&'a str>, claude: bool) -> Hints<'a> {
    match hidden {
        Some(word) => {
            h.retain(|(k, _)| *k != "A");
            h.push(("A", word));
        }
        None if claude && !h.iter().any(|(k, _)| *k == "A") => h.push(("A", "ask Claude")),
        None => {}
    }
    h.extend([("?", "help"), ("q", "quit")]);
    h
}

/// Too wide for `room`: hints go from the end, but never the global ones (A, ?, q) that end
/// the list. A chip is ` k ` + ` d` + two spaces.
pub fn fit_hints<'a>(mut hints: Hints<'a>, room: usize) -> Hints<'a> {
    let width = |h: &[(&str, &str)]| -> usize {
        h.iter()
            .map(|(k, d)| k.chars().count() + d.chars().count() + 5)
            .sum()
    };
    let globals = hints
        .iter()
        .rev()
        .take_while(|(k, _)| matches!(*k, "A" | "?" | "q"))
        .count();
    while width(&hints) > room && hints.len() > globals {
        hints.remove(hints.len() - globals - 1);
    }
    hints
}

/// How long a toast stays.
pub const TOAST_FOR: Duration = Duration::from_millis(2600);

/// A line that says what just happened, at the right of the key bar for a moment.
#[derive(Debug, Clone)]
pub struct Toast {
    msg: String,
    at: Instant,
}

impl Toast {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            msg: msg.into(),
            at: Instant::now(),
        }
    }

    pub fn msg(&self) -> &str {
        &self.msg
    }

    /// When it goes.
    pub fn until(&self) -> Instant {
        self.at + TOAST_FOR
    }

    pub fn over(&self, now: Instant) -> bool {
        now >= self.until()
    }
}

/// The cells a toast takes at the right of a bar `width` wide: at most half of it.
fn toast_width(msg: &str, width: u16) -> u16 {
    (msg.chars().count() as u16 + 1).min(width / 2)
}

/// The key bar: what's typed or the hints that fit, with the toast at the right.
pub fn draw_keybar(f: &mut Frame, area: Rect, t: &Theme, bar: &KeyBar, toast: Option<&str>) {
    let mut spans = Vec::new();
    match bar {
        KeyBar::Filter(s) => {
            spans.push(Span::styled(format!("/{s}"), t.fg()));
            spans.push(Span::styled("▏", t.s(t.cyan)));
            spans.push(Span::styled("   Enter keep · Esc clear", t.dim()));
        }
        KeyBar::Command(s) => {
            spans.push(Span::styled(format!(":{s}"), t.fg()));
            spans.push(Span::styled("▏", t.s(t.cyan)));
        }
        KeyBar::Prompt {
            label,
            text,
            enter,
            note,
        } => {
            spans.push(Span::styled(label.clone(), t.dim()));
            spans.push(Span::styled(text.to_string(), t.fg()));
            spans.push(Span::styled("▏", t.s(t.cyan)));
            match note {
                Some(n) => spans.push(Span::styled(format!("   {n}"), t.s(t.red))),
                None => spans.push(Span::styled(
                    format!("   Enter {enter} · Esc cancel"),
                    t.dim(),
                )),
            }
        }
        KeyBar::Password(line) => {
            spans.extend(line.spans.iter().cloned());
            spans.push(Span::styled("   Enter unlock · Esc cancel", t.dim()));
        }
        KeyBar::Hints(hints) => {
            let room =
                (area.width as usize).saturating_sub(toast.map_or(0, |m| m.chars().count() + 2));
            for (k, d) in fit_hints(hints.clone(), room) {
                spans.extend(chip(t, k, d, t.dim));
                spans.push(Span::raw("  "));
            }
        }
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
    if let Some(msg) = toast {
        let w = toast_width(msg, area.width);
        let r = Rect {
            x: area.right() - w,
            width: w,
            ..area
        };
        f.render_widget(
            Paragraph::new(Span::styled(
                widgets::trunc(msg, (w as usize).saturating_sub(1)),
                t.fg(),
            )),
            r,
        );
    }
}

/// What can be in front, in the order it gets keys (and pastes, and names the key bar's
/// hints): the first that's open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// The sudo password, typed in the key bar: nothing else takes a key meanwhile.
    Unlock,
    /// A command's streamed output.
    Run,
    Choice,
    /// A confirm or info box (help and quit are boxes).
    Modal,
    /// An apply session's window.
    Apply,
    Chat,
    /// The line being typed in the key bar.
    Input,
    /// Records, a plan or a review, over the screen.
    Docs,
    Screen,
}

/// What's open now (apply, chat: shown, not hidden).
#[derive(Debug, Clone, Copy, Default)]
pub struct Open {
    /// The sudo password is being asked for in the key bar.
    pub unlock: bool,
    pub run: bool,
    pub choice: bool,
    pub modal: bool,
    pub apply: bool,
    pub chat: bool,
    pub input: bool,
    pub docs: bool,
}

pub fn layer(o: &Open) -> Layer {
    [
        (o.unlock, Layer::Unlock),
        (o.run, Layer::Run),
        (o.choice, Layer::Choice),
        (o.modal, Layer::Modal),
        (o.apply, Layer::Apply),
        (o.chat, Layer::Chat),
        (o.input, Layer::Input),
        (o.docs, Layer::Docs),
    ]
    .into_iter()
    .find(|(open, _)| *open)
    .map_or(Layer::Screen, |(_, l)| l)
}

/// What `?` shows.
pub struct Help<'a> {
    pub screen: &'a str,
    /// The screen's own keys.
    pub hints: &'a [(&'a str, &'a str)],
    /// The program's own keys that work on every screen (under `app`).
    pub globals: &'a [(&'a str, &'a str)],
    pub app: &'a str,
    /// The `:` commands, on one line.
    pub commands: &'a str,
    pub footer: &'a [&'a str],
}

pub fn help_modal<E>(t: &Theme, h: &Help) -> Modal<E> {
    let l = |s: &str| Line::styled(s.to_string(), t.fg());
    let mut lines = vec![
        l("1–9 0 H   switch screen        Tab/S-Tab, h/l  next/prev screen"),
        l("j/k ↑↓    move selection       gg/G  top/bottom   C-d/C-u  page"),
        l("/         filter (Esc clears)  n/N   next/prev    C-h/C-l  pane focus"),
        l("r         refresh current      c     check now    C-j/C-k  scroll log/diff"),
        l("Enter     select / act         Esc   cancel       ?  help    q  quit"),
    ];
    // The screen names its own `A` when it has one.
    if !h.hints.iter().any(|(k, _)| *k == "A") {
        lines.push(l(
            "A         ask Claude about the selected thing (you see what's sent first)",
        ));
    }
    lines.push(l(
        "C-f       forget the sudo password    C-a  auto mode: routine steps need no key",
    ));
    lines.push(l(h.commands));
    let mut grid = |title: &str, hints: &[(&str, &str)]| {
        lines.push(Line::raw(""));
        lines.push(Line::styled(format!("{title}:"), t.s(t.cyan)));
        let mut row = String::new();
        for (k, d) in hints {
            let cell = format!("{k:<7} {d:<22}");
            if row.chars().count() + cell.chars().count() > 76 {
                lines.push(l(row.trim_end()));
                row.clear();
            }
            row.push_str(&cell);
        }
        if !row.is_empty() {
            lines.push(l(row.trim_end()));
        }
    };
    grid(h.screen, h.hints);
    if !h.globals.is_empty() {
        grid(h.app, h.globals);
    }
    lines.push(Line::raw(""));
    lines.extend(
        h.footer
            .iter()
            .map(|s| Line::styled(s.to_string(), t.dim())),
    );
    Modal {
        title: "Keys".into(),
        color: t.cyan,
        lines,
        yes: None,
    }
}

/// The box `q` opens: `quit` is what confirming does.
pub fn quit_modal<E>(t: &Theme, line: String, quit: E) -> Modal<E> {
    Modal {
        title: "Quit".into(),
        color: t.dim,
        lines: vec![Line::styled(line, t.fg())],
        yes: Some(("quit".into(), vec![quit])),
    }
}

/// `A` on something Claude can also apply: have it applied, or just ask.
pub fn claude_choice<E>(t: &Theme, app: &str, apply: Vec<E>, ask: Vec<E>) -> Choice<E> {
    Choice {
        title: "Claude · pick one (1–2, n cancels)".into(),
        lines: vec![
            Line::styled(
                format!("1  help me apply it: Claude plans, you approve, {app} runs it"),
                t.fg(),
            ),
            Line::styled("2  just ask about it", t.fg()),
            Line::raw(""),
            Line::styled("Either way you see what's sent first.", t.dim()),
        ],
        options: vec![
            ("help me apply it".into(), apply),
            ("just ask about it".into(), ask),
        ],
    }
}

/// A command's streamed output, in a box over the body.
pub struct RunView<'a> {
    pub title: &'a str,
    pub cmd: &'a str,
    /// How many lines there are, and how many the view is scrolled up from the end.
    pub len: usize,
    pub scroll: usize,
    pub started: Instant,
    /// Its exit code, and how long it took when that's known.
    pub done: Option<(i32, Option<Duration>)>,
}

pub fn draw_run<'a>(
    f: &mut Frame,
    area: Rect,
    t: &Theme,
    r: &RunView,
    lines: impl Iterator<Item = &'a str>,
) {
    let rect = widgets::centered(
        area,
        area.width.saturating_sub(8).max(60),
        area.height.saturating_sub(2),
    );
    let took =
        |d: Option<Duration>| d.map_or(String::new(), |d| format!(" · {:.1}s", d.as_secs_f32()));
    let (color, status) = match r.done {
        None => {
            let s = r.started.elapsed().as_secs();
            (t.cyan, format!("⠿ running · {}:{:02}", s / 60, s % 60))
        }
        Some((0, d)) => (t.green, format!("✓ done{}", took(d))),
        Some((c, d)) => (t.red, format!("✗ exit {c}{}", took(d))),
    };
    let inner = widgets::overlay(f, rect, t, r.title, color);
    let [cmd, log, foot] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    f.render_widget(
        Paragraph::new(Span::styled(format!("$ {}", r.cmd), t.dim())),
        cmd,
    );
    let h = log.height as usize;
    let end = r.len.saturating_sub(r.scroll);
    let start = end.saturating_sub(h);
    let lines: Vec<Line> = lines
        .skip(start)
        .take(end - start)
        .map(|s| {
            let st = if s.contains("error") || s.contains("Error") {
                t.s(t.red)
            } else {
                t.fg()
            };
            Line::styled(widgets::trunc(s, log.width as usize), st)
        })
        .collect();
    f.render_widget(Paragraph::new(lines), log);
    f.render_widget(Paragraph::new(Span::styled(status, t.s(color))), foot);
}

/// What a key asks of the run pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKey {
    Close,
    /// Ctrl-C while it runs.
    Kill,
    /// Lines up (older) when positive, down when negative.
    Scroll(i32),
    /// Back to the newest lines.
    End,
    /// To the oldest.
    Top,
    /// Esc while it runs: it can't be closed yet.
    Busy,
    None,
}

pub fn run_key(k: &KeyEvent, running: bool) -> RunKey {
    let ctrl_c = k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL);
    match k.code {
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') if !running => RunKey::Close,
        _ if ctrl_c && running => RunKey::Kill,
        KeyCode::Esc if running => RunKey::Busy,
        KeyCode::Char('k') | KeyCode::Up => RunKey::Scroll(1),
        KeyCode::Char('j') | KeyCode::Down => RunKey::Scroll(-1),
        KeyCode::PageUp => RunKey::Scroll(10),
        KeyCode::PageDown => RunKey::Scroll(-10),
        KeyCode::Char('G') | KeyCode::End => RunKey::End,
        KeyCode::Home => RunKey::Top,
        _ => RunKey::None,
    }
}

/// Draw a whole frame into plain text (render tests): lines right-trimmed.
#[cfg(any(test, feature = "testing"))]
pub fn render_to_string(w: u16, h: u16, draw: impl FnOnce(&mut Frame)) -> String {
    let backend = ratatui::backend::TestBackend::new(w, h);
    let mut term = ratatui::Terminal::new(backend).unwrap();
    term.draw(draw).unwrap();
    let buf = term.backend().buffer().clone();
    let mut out = String::new();
    for y in 0..h {
        let mut line = String::new();
        for x in 0..w {
            line.push_str(buf[(x, y)].symbol());
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn top() -> Top<'static> {
        Top {
            app: "sentry",
            subject: "silverblue 44.1".into(),
            auto: false,
            facts: vec!["kernel 7.2.8-200.fc44.x86_64".into(), "up 3d 04:12".into()],
            state: ("○ idle".into(), Color::Reset),
            clock: "Mon 16 Nov 20:46".into(),
            targets: Vec::new(),
            focus: 0,
        }
    }

    #[test]
    fn hints_drop_from_the_end_keeping_globals() {
        let h: Hints = vec![
            ("Enter", "fix"),
            ("x", "expected"),
            ("z", "later"),
            ("A", "claude"),
            ("?", "help"),
            ("q", "quit"),
        ];
        let keys = |h: &Hints| h.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(" ");
        assert_eq!(keys(&fit_hints(h.clone(), 200)), "Enter x z A ? q");
        // Each chip is its key and word plus five: these six take 13+14+11+12+10+10.
        assert_eq!(keys(&fit_hints(h.clone(), 69)), "Enter x A ? q");
        assert_eq!(keys(&fit_hints(h.clone(), 46)), "Enter A ? q");
        // Never the global ones, however narrow.
        assert_eq!(keys(&fit_hints(h, 5)), "A ? q");
        // The globals: a screen's own A stays; a hidden conversation takes the key.
        let own = with_globals(vec![("A", "claude")], None, true);
        assert_eq!(own, [("A", "claude"), ("?", "help"), ("q", "quit")]);
        let none = with_globals(vec![("r", "reload")], None, false);
        assert_eq!(keys(&none), "r ? q");
        let asks = with_globals(vec![("r", "reload")], None, true);
        assert_eq!(asks[1], ("A", "ask Claude"));
        let hidden = with_globals(vec![("A", "claude")], Some("applying…"), false);
        assert_eq!(hidden[0], ("A", "applying…"));
    }

    #[test]
    fn a_toast_takes_at_most_half_the_bar() {
        assert_eq!(toast_width("saved", 100), 6);
        assert_eq!(toast_width(&"x".repeat(80), 100), 50);
        let t = Theme::truecolor();
        let long = "y".repeat(80);
        let s = render_to_string(80, 24, |f| {
            let a = layout(f, &t, false).unwrap();
            let hints = KeyBar::Hints(vec![("Enter", "open"), ("?", "help"), ("q", "quit")]);
            draw_keybar(f, a.keybar, &t, &hints, Some(&long));
        });
        let bar = s.lines().last().unwrap();
        // The hints that still fit on the left, the toast cut to its half on the right.
        assert!(bar.starts_with(" ? "), "{bar}");
        assert!(bar.ends_with(&format!("{}…", "y".repeat(38))), "{bar}");
        assert_eq!(bar.chars().count(), 79);
        let toast = Toast::new("saved");
        assert_eq!(toast.msg(), "saved");
        assert!(!toast.over(Instant::now()));
        assert!(toast.over(toast.until()));
    }

    /// The top bar's row as drawn at this width.
    fn top_row(top: &Top, w: u16) -> String {
        let t = Theme::truecolor();
        let s = render_to_string(w, 24, |f| {
            let a = layout(f, &t, false).unwrap();
            draw_top(f, a.top, &t, top);
        });
        s.lines().next().unwrap().to_string()
    }

    #[test]
    fn one_target_has_no_strip_and_several_have_one_with_marks() {
        // One target: the bar as it always was.
        let row = top_row(&top(), 110);
        assert!(
            row.starts_with(
                " sentry   silverblue 44.1  kernel 7.2.8-200.fc44.x86_64  up 3d 04:12 "
            ),
            "{row}"
        );
        assert!(row.ends_with(" ○ idle   Mon 16 Nov 20:46"), "{row}");
        let tab = |key: &str, name: &str, mark, auto| TargetTab {
            key: Some(key.into()),
            name: name.into(),
            mark,
            auto,
        };
        let mut two = top();
        two.targets = vec![
            tab("F1", "silverblue 44.1", Mark::Working, false),
            tab("F2", "myserver", Mark::You, true),
            tab("F3", "other", Mark::None, false),
        ];
        // Each with its key, name, mark and `auto`, in place of the one name.
        let row = top_row(&two, 140);
        assert!(
            row.starts_with(
                " sentry   F1 silverblue 44.1 *   F2 myserver ! auto   F3 other    \
                 kernel 7.2.8-200.fc44.x86_64  up 3d 04:12 "
            ),
            "{row}"
        );
        assert!(row.ends_with(" ○ idle   Mon 16 Nov 20:46"), "{row}");
        // Narrower: the facts go, then the clock; the strip stays whole while it fits.
        let row = top_row(&two, 80);
        assert!(
            row.starts_with(" sentry   F1 silverblue 44.1 *   F2 myserver ! auto   F3 other  "),
            "{row}"
        );
        assert!(row.ends_with("  ○ idle"), "{row}");
        // The one in view is the one inverted (legible without colour too: its marks stay).
        let t = Theme::truecolor();
        let (l, _) = top_lines(&t, &two, 130);
        let inverted: String = l
            .spans
            .iter()
            .filter(|s| s.style.bg == Some(t.fg))
            .map(|s| s.content.as_ref())
            .collect();
        assert_eq!(inverted, " F1 silverblue 44.1 * ");
    }

    #[test]
    fn a_strip_too_wide_cuts_the_other_names_then_leaves_keys_and_marks() {
        let tab = |i: usize, name: &str, mark| TargetTab {
            key: Some(format!("F{i}")),
            name: name.into(),
            mark,
            auto: false,
        };
        let mut many = top();
        many.focus = 1;
        many.targets = vec![
            tab(1, "silverblue 44.1", Mark::Working),
            tab(2, "myserver", Mark::None),
            tab(3, "another-server", Mark::You),
            tab(4, "a-third-server", Mark::None),
            tab(5, "the-fourth-one", Mark::None),
        ];
        // Cut short, the one in view in full.
        let row = top_row(&many, 100);
        assert!(
            row.starts_with(
                " sentry   F1 silverb… *   F2 myserver   F3 another… !   F4 a-third…   F5 the-fou…  "
            ),
            "{row}"
        );
        assert!(row.ends_with(" ○ idle"), "{row}");
        // Narrower still: keys and marks only for the others.
        let row = top_row(&many, 80);
        assert!(
            row.starts_with(" sentry   F1 *   F2 myserver   F3 !   F4   F5  "),
            "{row}"
        );
        assert!(row.ends_with(" ○ idle"), "{row}");
    }

    #[test]
    fn the_top_bar_drops_facts_then_the_clock() {
        let t = Theme::truecolor();
        let text = |w: u16| {
            let (l, r) = top_lines(&t, &top(), w);
            (l.to_string(), r.to_string())
        };
        let (l, r) = text(120);
        assert_eq!(
            l,
            " sentry   silverblue 44.1  kernel 7.2.8-200.fc44.x86_64  up 3d 04:12"
        );
        assert_eq!(r, "○ idle   Mon 16 Nov 20:46 ");
        // Narrower: the first fact goes, then the next, then the clock; never the state.
        assert_eq!(text(90).0, " sentry   silverblue 44.1  up 3d 04:12");
        assert_eq!(text(60).0, " sentry   silverblue 44.1");
        assert_eq!(text(60).1, "○ idle   Mon 16 Nov 20:46 ");
        assert_eq!(text(40).1, "○ idle ");
        assert_eq!(text(10).1, "○ idle ");
    }

    #[test]
    fn the_strip_goes_full_short_then_keys() {
        use ScreenId::*;
        let tabs: Vec<Tab> = [Dash, Proc, Net, Cont, Flat, Maint, Clean, Upgrade]
            .into_iter()
            .map(|id| Tab {
                id,
                badge: (id == Maint).then(|| (" 2".to_string(), Color::Red)),
                filter: (id == Proc).then(|| "ssh".to_string()),
            })
            .collect();
        assert_eq!(names(&tabs, 158), Names::Full);
        assert_eq!(names(&tabs, 80), Names::Short);
        assert_eq!(names(&tabs, 60), Names::Keys);
        let t = Theme::truecolor();
        let strip = |w: u16| {
            let s = render_to_string(w, 24, |f| {
                let a = Rect::new(0, 0, w, 1);
                draw_tabs(f, a, &t, &tabs, Maint);
            });
            s.lines().next().unwrap().to_string()
        };
        assert!(
            strip(158).starts_with(" 1 Dashboard   2 Processes /ssh   3 Network"),
            "{}",
            strip(158)
        );
        // Short names, but the screen you're on keeps its own.
        let s = strip(80);
        assert!(
            s.contains("1 Dash") && s.contains("2 Proc /ssh") && s.contains("6 Maintenance 2"),
            "{s}"
        );
        assert!(strip(60).starts_with(" 1   2 /ssh   3   4   5   6 Maintenance 2"));
    }

    #[test]
    fn layers_in_order() {
        // The sudo password is typed before anything else gets a key.
        let unlock = Open {
            unlock: true,
            run: true,
            modal: true,
            ..Default::default()
        };
        assert_eq!(layer(&unlock), Layer::Unlock);
        let all = Open {
            unlock: false,
            run: true,
            choice: true,
            modal: true,
            apply: true,
            chat: true,
            input: true,
            docs: true,
        };
        assert_eq!(layer(&all), Layer::Run);
        assert_eq!(layer(&Open { run: false, ..all }), Layer::Choice);
        let o = Open {
            run: false,
            choice: false,
            ..all
        };
        assert_eq!(layer(&o), Layer::Modal);
        // A box comes before what's typed; a conversation before the line under it.
        let o = Open {
            apply: true,
            chat: true,
            input: true,
            docs: true,
            ..Default::default()
        };
        assert_eq!(layer(&o), Layer::Apply);
        assert_eq!(layer(&Open { apply: false, ..o }), Layer::Chat);
        let o = Open {
            input: true,
            docs: true,
            ..Default::default()
        };
        assert_eq!(layer(&o), Layer::Input);
        assert_eq!(layer(&Open { input: false, ..o }), Layer::Docs);
        assert_eq!(layer(&Open::default()), Layer::Screen);
    }

    #[test]
    fn the_run_pane_s_keys_and_the_boxes() {
        let key = |c, m| KeyEvent::new(c, m);
        let none = KeyModifiers::NONE;
        assert_eq!(run_key(&key(KeyCode::Esc, none), true), RunKey::Busy);
        assert_eq!(run_key(&key(KeyCode::Esc, none), false), RunKey::Close);
        assert_eq!(
            run_key(&key(KeyCode::Char('c'), KeyModifiers::CONTROL), true),
            RunKey::Kill
        );
        assert_eq!(
            run_key(&key(KeyCode::Char('c'), KeyModifiers::CONTROL), false),
            RunKey::None
        );
        assert_eq!(run_key(&key(KeyCode::Char('q'), none), true), RunKey::None);
        assert_eq!(
            run_key(&key(KeyCode::Char('k'), none), true),
            RunKey::Scroll(1)
        );
        assert_eq!(run_key(&key(KeyCode::Char('G'), none), false), RunKey::End);
        let t = Theme::truecolor();
        let help: Modal<()> = help_modal(
            &t,
            &Help {
                screen: "Maintenance",
                hints: &[("Enter", "fix"), ("A", "claude")],
                globals: &[("I", "read what needs root")],
                app: "sentry-server",
                commands: ":q  :<screen>",
                footer: &["Nothing keeps running."],
            },
        );
        let text: Vec<String> = help.lines.iter().map(|l| l.to_string()).collect();
        // The screen has its own A, so the general line is left out.
        assert!(text[5].starts_with("C-f       forget the sudo password"));
        assert!(text[5].contains("C-a  auto mode"));
        assert_eq!(text[6], ":q  :<screen>");
        assert_eq!(text[8], "Maintenance:");
        assert_eq!(text[11], "sentry-server:");
        assert_eq!(text.last().unwrap(), "Nothing keeps running.");
        let c: Choice<u8> = claude_choice(&t, "sentry", vec![1], vec![2]);
        assert!(c.lines[0].to_string().ends_with("sentry runs it"));
        assert_eq!(c.options[1].1, [2]);
        let q: Modal<u8> = quit_modal(&t, "Quit?".into(), 9);
        assert_eq!(q.yes.unwrap().1, [9]);
    }
}

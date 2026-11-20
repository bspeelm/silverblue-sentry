//! A remote host's Upgrade screen (`0`), for a target whose runs are [`Session`]s: the
//! workflows while nothing runs (the list is core's `wflist`), and a run in progress (its
//! steps, its log and the current step's card). The words for the host are the run's own
//! (`Session::on`); a target passes what else it shows as [`Shown`].

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};

use super::workflow::{LogKind, Session, Words};
use crate::effect::{Effect, Modal, WfCmd};
use sentry_core::tui::keys::Action;
use sentry_core::tui::stepview;
use sentry_core::tui::theme::Theme;
use sentry_core::tui::wflist::{self, WfInfo};
use sentry_core::tui::widgets::{inner, panel, trunc};
use sentry_core::workflows::runner::{Next, preview};

pub type Hints = Vec<(&'static str, &'static str)>;

/// What the screen is drawn from.
pub struct Shown<'a> {
    pub t: &'a Theme,
    /// The run in progress (or just ended).
    pub wf: Option<&'a Session>,
    pub list: &'a [WfInfo],
    /// The workflow selected in the list.
    pub cur: usize,
    /// The target's name.
    pub name: &'a str,
    pub auto: bool,
    /// What the host is called when no run says it (`Words`).
    pub words: Words,
    /// The program's name ("sentry-network waits here").
    pub prog: &'a str,
    /// The command a reboot step runs, as shown before it's confirmed.
    pub reboot: &'a str,
    /// What the list says when it's empty.
    pub none: &'a str,
}

/// Screen `0`'s own state: the list's cursor.
#[derive(Default)]
pub struct Upgrade {
    pub cur: sentry_core::tui::Cursor,
}

fn failed(s: &Session) -> bool {
    matches!(s.next, Next::Stopped(_) | Next::Manual { failed: true, .. })
}

pub fn hints(wf: Option<&Session>) -> Hints {
    match wf {
        None => vec![
            ("j/k", "select"),
            ("Enter", "start"),
            ("e", "edit toml"),
            ("r", "reload"),
            ("v", "records"),
        ],
        Some(s) if s.done() => vec![("Enter", "close"), ("L", "step log"), ("v", "records")],
        Some(s) if s.live.is_some() => vec![("C-c", "terminate step"), ("L", "log")],
        Some(s) if failed(s) => vec![
            ("r", "retry"),
            ("d", "done by hand"),
            ("s", "skip"),
            ("a", "abandon"),
            ("L", "log"),
        ],
        Some(_) => vec![
            ("Enter", "run the step"),
            ("s", "skip"),
            ("a", "abandon"),
            ("L", "log"),
        ],
    }
}

impl Upgrade {
    pub fn handle(&mut self, a: Action, v: &Shown) -> Vec<Effect> {
        match v.wf {
            Some(s) => running(a, v, s),
            None => self.idle(a, v),
        }
    }

    /// Nothing runs: the list. Enter starts the workflow selected (its values first).
    fn idle(&mut self, a: Action, v: &Shown) -> Vec<Effect> {
        let info = v.list.get(self.cur.clamp(v.list.len()));
        match (a, info) {
            (Action::Refresh, _) => vec![Effect::ReloadWorkflows],
            (Action::Char('v'), _) => vec![Effect::LogOpen(None)],
            (Action::Char('e'), Some(i)) => vec![Effect::Edit(i.entry.path.clone())],
            (Action::Enter, Some(i)) => vec![Effect::StartWorkflow(i.entry.name.clone())],
            _ => Vec::new(),
        }
    }
}

/// A run in progress: its step's keys.
fn running(a: Action, v: &Shown, s: &Session) -> Vec<Effect> {
    let t = v.t;
    if s.done() {
        return match a {
            Action::Enter | Action::Esc => vec![Effect::Wf(WfCmd::Close)],
            Action::Char('L') => vec![Effect::StepLog],
            Action::Char('v') => vec![Effect::LogOpen(None)],
            _ => Vec::new(),
        };
    }
    let idx = s.next.idx();
    let title = idx.map(|i| s.title(i)).unwrap_or_default();
    let ask = |title: &str, line: String, label: &str, cmd: WfCmd, color| {
        vec![Effect::Confirm(Modal {
            title: title.into(),
            color,
            lines: vec![Line::styled(line, t.fg())],
            yes: Some((label.into(), vec![Effect::Wf(cmd)])),
        })]
    };
    match a {
        Action::Enter => match s.next {
            Next::Reboot {
                requested: false, ..
            } => vec![Effect::Confirm(Modal {
                title: format!("Reboot {}", v.words.host),
                color: t.red,
                lines: vec![
                    Line::styled(title, t.fg()),
                    Line::styled(format!("$ {}   on {}", v.reboot, v.name), t.fg()),
                    Line::styled(
                        format!(
                            "Everything on it stops until it's back; {} waits here.",
                            v.prog
                        ),
                        t.s(t.yellow),
                    ),
                ],
                yes: Some(("reboot".into(), vec![Effect::Wf(WfCmd::Go)])),
            })],
            _ => vec![Effect::Wf(WfCmd::Go)],
        },
        Action::Char('s') => match idx {
            Some(i) if s.wf.steps[i].optional => vec![Effect::Wf(WfCmd::Skip(false))],
            Some(_) => ask(
                "Skip step",
                format!("{title}: it isn't optional, later steps may expect it."),
                "skip it",
                WfCmd::Skip(true),
                t.yellow,
            ),
            None => Vec::new(),
        },
        Action::Char('d') if idx.is_some() => ask(
            "Done by hand",
            format!("{title}: mark it done only if you've made sure of it yourself."),
            "mark done",
            WfCmd::Done,
            t.yellow,
        ),
        Action::Refresh if failed(s) => vec![Effect::Wf(WfCmd::Retry)],
        Action::Char('a') => ask(
            "Abandon workflow",
            format!(
                "Abandon {}? {} is left as it is now.",
                s.wf.name,
                capital(v.words.host)
            ),
            "abandon",
            WfCmd::Abandon,
            t.red,
        ),
        Action::Char('L') => vec![Effect::StepLog],
        _ => Vec::new(),
    }
}

pub fn draw(f: &mut Frame, area: Rect, v: &Shown) {
    let cols = wflist::split(area);
    match v.wf {
        Some(s) => draw_session(f, cols, v, s),
        None => wflist::draw_idle(
            f,
            cols,
            v.t,
            v.list,
            v.cur.min(v.list.len().saturating_sub(1)),
            v.none,
            &|_, _| wflist::Notes::default(),
        ),
    }
}

/// "The router", at the start of a sentence.
fn capital(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// What the running step has printed so far (the lines since its command).
fn step_output(s: &Session) -> Vec<String> {
    let from = s
        .log
        .iter()
        .rposition(|(_, k)| *k == LogKind::Cmd)
        .map_or(0, |i| i + 1);
    s.log
        .iter()
        .skip(from)
        .filter(|(_, k)| matches!(k, LogKind::Out | LogKind::Err))
        .map(|(l, _)| l.clone())
        .collect()
}

fn draw_session(f: &mut Frame, (left, right): (Rect, Rect), v: &Shown, s: &Session) {
    let (t, target, auto) = (v.t, v.name, v.auto);
    let n = s.wf.steps.len();
    let b = panel(
        t,
        &s.wf.name,
        format!("{} · {}", s.state_word(), s.run.state.done_count()),
    );
    let r = inner(&b, left);
    f.render_widget(b, left);
    let cur = s.next.idx();
    // The steps, as a session's plan is drawn: the same header, rows and place for what
    // the running step prints.
    let live = s.live.as_ref().map(|l| l.idx);
    let rows = stepview::run_rows(&s.wf, &s.run.state, &s.next, live, &|i| s.title(i));
    let out = step_output(s);
    stepview::draw(
        f,
        r,
        t,
        &stepview::Steps {
            target,
            what: &s.wf.name,
            auto,
            state: stepview::run_state(&s.next, live.is_some()),
            rows: &rows,
            at: live.or(cur),
            output: &out,
            since: s.live.as_ref().map(|l| l.started),
            stop: "C-c stops it",
        },
    );

    let card = card(v, s);
    let card_h = (card.len() as u16 + 2).min(right.height / 2);
    let [log_a, card_a] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(card_h)]).areas(right);
    let b = panel(
        t,
        "Log",
        cur.map_or(String::new(), |i| {
            format!("step {}/{n} · steps/{}.log", i + 1, s.wf.steps[i].id)
        }),
    );
    let r = inner(&b, log_a);
    f.render_widget(b, log_a);
    let h = r.height as usize;
    let shown: Vec<Line> = s
        .log
        .iter()
        .skip(s.log.len().saturating_sub(h))
        .map(|(l, k)| {
            let c = match k {
                LogKind::Info => t.cyan,
                LogKind::Cmd => t.dim,
                LogKind::Out => t.fg,
                LogKind::Ok => t.green,
                LogKind::Err => t.red,
            };
            Line::styled(trunc(l, r.width as usize), t.s(c))
        })
        .collect();
    f.render_widget(Paragraph::new(shown), r);
    let color = match s.next {
        Next::Stopped(_) | Next::Manual { failed: true, .. } => t.red,
        Next::Reboot { .. } => t.mag,
        Next::Done => t.green,
        _ => t.yellow,
    };
    let block = ratatui::widgets::Block::new()
        .borders(ratatui::widgets::Borders::ALL)
        .border_style(t.s(color));
    let r = block.inner(card_a);
    f.render_widget(block, card_a);
    f.render_widget(Paragraph::new(card).wrap(Wrap { trim: false }), r);
}

fn card(v: &Shown, s: &Session) -> Vec<Line<'static>> {
    let t = v.t;
    let Some(i) = s.next.idx() else {
        return vec![
            Line::styled(
                format!("✓ {} {}", s.wf.name, if s.done() { "finished" } else { "" }),
                t.s(t.green),
            ),
            Line::styled("[Enter] close", t.dim()),
        ];
    };
    let step = &s.wf.steps[i];
    let title = s.title(i);
    let cmd = step
        .run
        .as_deref()
        .map(|r| format!("$ {}", preview(&s.run.state, r)));
    let manual = step
        .manual
        .as_deref()
        .map(|m| preview(&s.run.state, m))
        .unwrap_or_default();
    let mut out = Vec::new();
    match s.next {
        Next::Run(_) | Next::Confirm(_) => {
            out.push(Line::styled(
                format!("▶ {title} · {}", step.tag()),
                t.s(t.yellow),
            ));
            out.extend(cmd.map(|c| Line::styled(c, t.fg())));
            out.push(Line::styled(
                format!(
                    "[Enter] run{}   [L] log   [a] abandon",
                    if step.optional {
                        "   [s] skip"
                    } else {
                        "   [s] skip (asks)"
                    }
                ),
                t.dim(),
            ));
        }
        Next::Reboot { requested, .. } => {
            out.push(Line::styled(format!("↻ {title}"), t.s(t.mag)));
            out.push(Line::styled(
                if requested {
                    format!(
                        "Waiting for {} to come back (its boot id changes)…",
                        v.words.host
                    )
                } else {
                    format!(
                        "{} on {}; {} waits for it here.",
                        v.reboot, v.words.host, v.prog
                    )
                },
                t.fg(),
            ));
            out.push(Line::styled(
                if requested {
                    "[d] it's back, mark done   [a] abandon"
                } else {
                    "[Enter] reboot now   [s] skip (asks)   [a] abandon"
                },
                t.dim(),
            ));
        }
        Next::Manual { failed: false, .. } => {
            out.push(Line::styled(format!("✋ {title} · manual"), t.s(t.yellow)));
            out.extend(manual.lines().map(|l| Line::styled(l.to_string(), t.fg())));
            out.push(Line::styled("[Enter] done   [a] abandon", t.dim()));
        }
        Next::Manual { failed: true, .. } | Next::Stopped(_) => {
            let code = s.run.state.steps[i]
                .code
                .map_or("?".into(), |c| c.to_string());
            out.push(Line::styled(
                format!("✗ {title} · failed (exit {code})"),
                t.s(t.red),
            ));
            if let Some(note) = &s.run.state.steps[i].note {
                out.push(Line::styled(note.clone(), t.dim()));
            }
            out.extend(manual.lines().map(|l| Line::styled(l.to_string(), t.fg())));
            out.push(Line::styled(
                "[r] retry   [d] done by hand   [s] skip   [L] log   [a] abandon",
                t.dim(),
            ));
        }
        Next::Shell(_) | Next::Done => {}
    }
    if let Some(e) = &s.error {
        out.push(Line::styled(e.clone(), t.s(t.red)));
    }
    out
}

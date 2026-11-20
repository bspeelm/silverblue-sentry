//! Upgrade (`0`): workflows. Idle: the list with lint status and the step chain. Running: the
//! step list with status glyphs, the streaming log, and a gate card for the current step.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use super::{Cursor, Hints, View};
use crate::tui::app::{Effect, Modal, Prompt, WfCmd};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::theme::Theme;
use crate::tui::wf::{LogKind, Session};
use crate::tui::widgets::{inner, panel, short_home, trunc, wrap};
use crate::workflows::cli::{RealEnv, initial_vars};
use crate::workflows::runner::{Next, preview};
use crate::workflows::state::StepStatus;

#[derive(Default)]
pub struct Upgrade {
    pub cur: Cursor,
}

use crate::tui::stepview;
pub use crate::tui::wflist::WfInfo;
use crate::tui::wflist::{self, gate_card, key_rows, when};

pub fn load_infos() -> Vec<WfInfo> {
    wflist::load_infos(crate::workflows::list(), &crate::workflows::state::root())
}

/// What's waiting to be installed, as Maintenance says it (None: nothing).
pub fn updates_waiting(v: &View) -> Option<String> {
    super::maint::recs(v)
        .into_iter()
        .find(|r| r.key == "updates")
        .map(|r| r.title)
}

pub fn on_enter(_v: &View) -> Vec<Effect> {
    vec![Effect::Fetch(Fetch::Workflows), Effect::Wf(WfCmd::Arm)]
}

pub fn hints(v: &View) -> Hints {
    match v.wf {
        None => vec![
            ("j/k", "select"),
            ("Enter", "start"),
            ("e", "edit toml"),
            ("r", "reload"),
            ("p", "read plan"),
            ("P", "with Claude"),
            ("v", "records"),
        ],
        Some(s) if s.done() => vec![("Enter", "close"), ("L", "step log"), ("v", "records")],
        Some(s) => {
            // `l` is next-tab everywhere, so the log is `L`.
            let mut h = if failed(s) {
                vec![
                    ("r", "retry"),
                    ("d", "done by hand"),
                    ("s", "skip"),
                    ("a", "abandon"),
                    ("L", "log"),
                ]
            } else {
                vec![
                    ("Enter", "run the step"),
                    ("s", "skip"),
                    ("a", "abandon"),
                    ("L", "log"),
                ]
            };
            if failed(s) && crate::claude::available() {
                h.insert(0, ("f", "fix (with Claude)"));
            }
            if s.live.is_some() {
                h = vec![("C-c", "terminate step"), ("C-j/k", "scroll")];
            }
            h
        }
    }
}

fn failed(s: &Session) -> bool {
    matches!(s.next, Next::Stopped(_) | Next::Manual { failed: true, .. })
}

/// `s`: optional steps skip at once; any other step asks first, since later steps may
/// depend on it (you decide, e.g. after doing it another way).
fn skip_keys(s: &Session, t: &Theme) -> Vec<Effect> {
    let Some(i) = s.next.idx() else {
        return Vec::new();
    };
    if s.wf.steps[i].optional {
        return vec![Effect::Wf(WfCmd::Skip)];
    }
    vec![Effect::Confirm(Modal {
        title: "Skip step".into(),
        color: t.yellow,
        lines: step_lines(
            s,
            i,
            t,
            "This step isn't optional: later steps may expect it to have run.",
        ),
        yes: Some(("skip it".into(), vec![Effect::Wf(WfCmd::SkipAnyway)])),
    })]
}

/// `d`: a manual step is done at once; a failed check or command asks first, because you are
/// vouching for what it would have checked.
fn done_keys(s: &Session, t: &Theme) -> Vec<Effect> {
    match s.next {
        Next::Stopped(i) => vec![Effect::Confirm(Modal {
            title: "Done by hand".into(),
            color: t.yellow,
            lines: step_lines(
                s,
                i,
                t,
                "Mark it done only if you've made sure of this yourself; the workflow continues with the next step.",
            ),
            yes: Some(("mark done".into(), vec![Effect::Wf(WfCmd::Done)])),
        })],
        _ => vec![Effect::Wf(WfCmd::Done)],
    }
}

fn step_lines(s: &Session, i: usize, t: &Theme, warn: &str) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        format!("{}/{} {}", i + 1, s.wf.steps.len(), s.title(i)),
        t.fg(),
    )];
    if let Some(cmd) = &s.wf.steps[i].run {
        lines.push(Line::styled(
            format!("$ {}", preview(&s.run.state, cmd)),
            t.dim(),
        ));
    }
    lines.push(Line::styled(warn.to_string(), t.s(t.yellow)));
    lines
}

/// What `f` sends about the failed step: its command, log tail, the workflow's own advice and
/// the actions sentry offers now.
pub fn step_facts(s: &Session) -> Option<crate::claude::StepFacts> {
    if !failed(s) {
        return None;
    }
    let i = s.next.idx()?;
    let step = &s.wf.steps[i];
    let st = &s.run.state.steps[i];
    let log = std::fs::read_to_string(s.run.log_path(&step.id)).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    // Named, not keyed: the chat retries with `t`, the Upgrade screen with `r`.
    let mut actions = vec![
        ("retry", "run the step again (t in this chat)"),
        (
            "done by hand",
            "accept the step as done, when the system already is the way it checks for",
        ),
        (
            "skip",
            if step.optional {
                "skip this optional step"
            } else {
                "skip the step (it isn't optional: later steps may expect it)"
            },
        ),
    ];
    if s.wf.steps.iter().any(|x| x.rollback) {
        actions.push((
            "rollback",
            "run the workflow's rollback steps, then abandon it",
        ));
    }
    actions.push(("abandon", "stop the workflow, leaving the system as it is"));
    Some(crate::claude::StepFacts {
        workflow: s.wf.name.clone(),
        idx: i,
        total: s.wf.steps.len(),
        id: step.id.clone(),
        title: s.title(i),
        prev: i.checked_sub(1).map(|j| s.title(j)),
        next: (i + 1 < s.wf.steps.len()).then(|| s.title(i + 1)),
        later: (i + 1..s.wf.steps.len())
            .filter(|&j| s.run.state.steps[j].status == StepStatus::Pending)
            .map(|j| {
                let cmd = s.wf.steps[j]
                    .run
                    .as_deref()
                    .map_or("(reboot or manual)".into(), |c| preview(&s.run.state, c));
                format!("{}: {} · {cmd}", s.wf.steps[j].id, s.title(j))
            })
            .collect(),
        cmd: preview(&s.run.state, step.run.as_deref().unwrap_or("(no command)")),
        code: st.code,
        vars: s
            .run
            .state
            .vars
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect(),
        log_tail: lines[lines.len().saturating_sub(60)..].join("\n"),
        manual: step.manual.as_deref().map(|m| preview(&s.run.state, m)),
        actions,
    })
}

impl Upgrade {
    fn infos<'a>(&self, v: &View<'a>) -> &'a [WfInfo] {
        v.d.workflows.get().map_or(&[], |w| w.as_slice())
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        match v.wf {
            Some(s) => self.handle_running(a, v, s),
            None => self.handle_idle(a, v),
        }
    }

    fn handle_idle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        let infos = self.infos(v);
        if self.cur.nav(a, infos.len()) {
            return Vec::new();
        }
        let t = v.t;
        let Some(info) = infos.get(self.cur.clamp(infos.len())) else {
            return match a {
                Action::Refresh => vec![Effect::Fetch(Fetch::Workflows)],
                _ => Vec::new(),
            };
        };
        match a {
            Action::Refresh => vec![Effect::Fetch(Fetch::Workflows)],
            Action::Char('v') => vec![Effect::LogOpen],
            // Its saved plan, to read; `P`: a session works it out (research, then its plan).
            Action::Char('p') => vec![Effect::PlanOpen(info.entry.name.clone())],
            Action::Char('P') => vec![Effect::PlanAgain(info.entry.name.clone())],
            Action::Char('e') => vec![Effect::Wf(WfCmd::Edit(info.entry.path.clone()))],
            Action::Enter => {
                if let Some(why) = info.entry.blocked() {
                    return vec![Effect::Confirm(crate::tui::app::info_modal(
                        t,
                        &format!("{} can't start", info.entry.name),
                        vec![
                            Line::styled(why, t.s(t.yellow)),
                            Line::styled(
                                format!("Edit with e: {}", short_home(&info.entry.path)),
                                t.dim(),
                            ),
                        ],
                    ))];
                }
                let Ok(wf) = &info.entry.wf else {
                    return Vec::new();
                };
                // A plan ready for this workflow: its values, and the run applies it.
                let plan = ready_plan(v, &info.entry.name);
                let preset = plan.map(|p| p.head.vars.clone()).unwrap_or_default();
                let vars = match initial_vars(wf, &RealEnv, &preset) {
                    Ok(v) => v,
                    Err(e) => return vec![Effect::Toast(e)],
                };
                // Prompts for user vars (pre-filled with the rendered default), then start.
                let mut rest: Vec<(String, String, String)> = wf
                    .vars
                    .iter()
                    .map(|(k, s)| (k.clone(), s.prompt.clone(), vars[k].clone()))
                    .collect();
                if !rest.is_empty() {
                    let (key, prompt, default) = rest.remove(0);
                    return vec![Effect::Prompt(
                        Prompt::WfVar {
                            workflow: info.entry.name.clone(),
                            key,
                            prompt,
                            rest,
                            vars,
                        },
                        default,
                    )];
                }
                // Enter was the approval: it starts. Its auto steps run; every step that
                // changes something waits for its own confirm, and reboots never run on
                // their own.
                let mut e = vec![Effect::Wf(WfCmd::Begin(info.entry.name.clone(), vars))];
                if plan.is_some() {
                    e.push(Effect::Toast(
                        "started with Claude's plan (its values): it closes when the run ends well"
                            .into(),
                    ));
                }
                e
            }
            _ => Vec::new(),
        }
    }

    fn handle_running(&mut self, a: Action, v: &View, s: &Session) -> Vec<Effect> {
        let t = v.t;
        if s.done() {
            return match a {
                Action::Enter | Action::Esc => vec![Effect::Wf(WfCmd::Close)],
                Action::Char('L') => vec![Effect::Wf(WfCmd::OpenLog)],
                Action::Char('v') => vec![Effect::LogOpen],
                _ => Vec::new(),
            };
        }
        match a {
            Action::Down | Action::LogDown => vec![Effect::Wf(WfCmd::Scroll(-1))],
            Action::Up | Action::LogUp => vec![Effect::Wf(WfCmd::Scroll(1))],
            Action::PageDown => vec![Effect::Wf(WfCmd::Scroll(-10))],
            Action::PageUp => vec![Effect::Wf(WfCmd::Scroll(10))],
            Action::Bottom => vec![Effect::Wf(WfCmd::Scroll(i32::MIN))],
            Action::Char('L') => vec![Effect::Wf(WfCmd::OpenLog)],
            _ if s.live.is_some() => vec![Effect::Toast(
                "a step is running · C-c terminates it".into(),
            )],
            Action::Enter => match s.next {
                Next::Reboot { idx, requested } => vec![Effect::Confirm(Modal {
                    title: "Reboot".into(),
                    color: t.mag,
                    lines: vec![
                        Line::styled(
                            format!("{}/{} {}", idx + 1, s.wf.steps.len(), s.title(idx)),
                            t.fg(),
                        ),
                        Line::styled(
                            if requested {
                                "A reboot was requested but this is still the same boot."
                            } else {
                                "State is saved before rebooting."
                            },
                            t.dim(),
                        ),
                        Line::styled("$ systemctl reboot", t.dim()),
                        Line::styled("Run `sentry` after login to continue.", t.s(t.yellow)),
                    ],
                    yes: Some(("reboot now".into(), vec![Effect::Wf(WfCmd::Go)])),
                })],
                _ => vec![Effect::Wf(WfCmd::Go)],
            },
            // Claude reads the step's log and says what to run; you run it, then retry.
            Action::Char('f') => match step_facts(s) {
                Some(facts) if crate::claude::available() => {
                    vec![Effect::AskConsent(crate::claude::Ask::step_fix(&facts))]
                }
                Some(_) => vec![Effect::Toast(
                    "Claude Code not found: see the step's advice and its log (L)".into(),
                )],
                None => vec![Effect::Toast("f helps with a failed step".into())],
            },
            Action::Char('s') => skip_keys(s, t),
            Action::Char('r') | Action::Refresh => vec![Effect::Wf(WfCmd::Retry)],
            Action::Char('d') => done_keys(s, t),
            Action::Char('D') => vec![Effect::Wf(WfCmd::SkipDry)],
            Action::Char('a') => {
                let has_rb = s.wf.steps.iter().any(|x| x.rollback);
                let mut lines = vec![
                    Line::styled(
                        format!("Abandon {}? The system is left as it is now.", s.wf.name),
                        t.fg(),
                    ),
                    Line::styled(format!("Run dir kept: {}", short_home(&s.run.dir)), t.dim()),
                ];
                if has_rb {
                    lines.push(Line::styled(
                        "This workflow has rollback steps: press R instead to run them first.",
                        t.s(t.yellow),
                    ));
                }
                vec![Effect::Confirm(Modal {
                    title: "Abandon workflow".into(),
                    color: t.red,
                    lines,
                    yes: Some(("abandon".into(), vec![Effect::Wf(WfCmd::Abandon)])),
                })]
            }
            Action::Char('R') => {
                let rb: Vec<String> =
                    s.wf.steps
                        .iter()
                        .filter(|x| x.rollback)
                        .map(|x| {
                            format!(
                                "• {}  $ {}",
                                preview(&s.run.state, &x.title),
                                preview(&s.run.state, x.run.as_deref().unwrap_or(""))
                            )
                        })
                        .collect();
                if rb.is_empty() {
                    return vec![Effect::Toast("no rollback steps in this workflow".into())];
                }
                let mut lines: Vec<Line> =
                    rb.into_iter().map(|l| Line::styled(l, t.fg())).collect();
                lines.push(Line::styled("Then the run is abandoned.", t.dim()));
                vec![Effect::Confirm(Modal {
                    title: "Roll back and abandon".into(),
                    color: t.red,
                    lines,
                    yes: Some(("roll back".into(), vec![Effect::Wf(WfCmd::Rollback)])),
                })]
            }
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let (left, right) = wflist::split(area);
        match v.wf {
            Some(s) => self.render_running(f, left, right, v, s),
            None => self.render_idle(f, (left, right), v),
        }
    }

    fn render_idle(&mut self, f: &mut Frame, cols: (Rect, Rect), v: &View) {
        let t = v.t;
        let infos = self.infos(v);
        let sel = self.cur.clamp(infos.len());
        let empty = v.d.workflows.status(v.d.loading(Fetch::Workflows));
        // quick-update is what Maintenance's updates recommendation starts: say what waits.
        let notes = |info: &WfInfo, width: usize| {
            if info.entry.name != crate::maint::local::UPDATE_WORKFLOW {
                return wflist::Notes::default();
            }
            let waiting = updates_waiting(v);
            let mut right = vec![Line::raw("")];
            right.extend(
                waiting
                    .clone()
                    .map(|title| Line::styled(title, t.s(t.yellow))),
            );
            for l in wrap(
                "Maintenance (6) lists these updates too. Enter there does the same as Enter \
                 here.",
                width,
            ) {
                right.push(Line::styled(l, t.dim()));
            }
            wflist::Notes {
                waiting: waiting.map(|w| {
                    let w = w.strip_prefix("Updates waiting: ").unwrap_or(&w);
                    format!("↑ waiting now: {w} · Enter installs")
                }),
                right,
            }
        };
        wflist::draw_idle(f, cols, t, infos, sel, &empty, &notes);
    }

    fn render_running(&mut self, f: &mut Frame, left: Rect, right: Rect, v: &View, s: &Session) {
        let t = v.t;
        let n = s.wf.steps.len();
        let block = panel(t, &s.wf.name, format!("{}/{n}", s.run.state.done_count()));
        let r = inner(&block, left);
        f.render_widget(block, left);
        let [list, info] = Layout::vertical([Constraint::Fill(1), Constraint::Length(4)]).areas(r);
        let cur = s.next.idx();
        // The steps, as a session's plan is drawn: the same header, rows and place for what
        // the running step prints.
        let live = s.live.as_ref().map(|l| l.idx);
        let rows = stepview::run_rows(&s.wf, &s.run.state, &s.next, live, &|i| s.title(i));
        let from = s
            .log
            .iter()
            .rposition(|(_, k)| *k == LogKind::Cmd)
            .map_or(0, |i| i + 1);
        let out: Vec<String> = s
            .log
            .iter()
            .skip(from)
            .filter(|(_, k)| matches!(k, LogKind::Out | LogKind::Err))
            .map(|(l, _)| l.clone())
            .collect();
        stepview::draw(
            f,
            list,
            t,
            &stepview::Steps {
                target: v.target,
                what: &s.wf.name,
                auto: v.auto,
                state: if s.done() {
                    stepview::State::Done
                } else {
                    stepview::run_state(&s.next, live.is_some())
                },
                rows: &rows,
                at: live.or(cur).filter(|_| !s.done()),
                output: &out,
                since: s.live.as_ref().map(|l| l.started),
                stop: "C-c stops it",
            },
        );
        let user_vars: Vec<String> = s
            .run
            .state
            .vars
            .iter()
            .filter(|(k, _)| s.wf.vars.contains_key(*k) || *k == "pending_kernel")
            .map(|(k, v)| format!("{k} = {v}"))
            .collect();
        f.render_widget(
            Paragraph::new(vec![
                Line::styled("─".repeat(info.width as usize), t.s(t.rule)),
                Line::styled(trunc(&user_vars.join("   "), info.width as usize), t.dim()),
                Line::styled(format!("started {}", when(s.run.state.started)), t.dim()),
                Line::styled(trunc(&short_home(&s.run.dir), info.width as usize), t.dim()),
            ]),
            info,
        );

        // Right: log + gate card.
        let log_name = cur.map_or("—".into(), |i| format!("steps/{}.log", s.wf.steps[i].id));
        let block = panel(t, "Log", log_name);
        let r = inner(&block, right);
        f.render_widget(block, right);
        let (card_color, head, body, sub) = card_for(v, s);
        // Rows after wrapping inside the card's borders and padding.
        let cw = r.width.saturating_sub(4).max(1) as usize;
        let rows: usize = std::iter::once(&head)
            .chain(body.iter())
            .map(|l| l.width().max(1).div_ceil(cw))
            .sum();
        let rows = rows + key_rows(&sub, cw).len();
        let card_h = (rows as u16 + 2).min(r.height / 2);
        let [log, _, card] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(card_h),
        ])
        .areas(r);
        let lh = log.height as usize;
        let end = s.log.len().saturating_sub(s.scroll);
        let begin = end.saturating_sub(lh);
        let shown: Vec<Line> = s
            .log
            .iter()
            .skip(begin)
            .take(end - begin)
            .map(|(l, k)| {
                let c = match k {
                    LogKind::Info => t.cyan,
                    LogKind::Cmd => t.dim,
                    LogKind::Out => t.fg,
                    LogKind::Ok => t.green,
                    LogKind::Err => t.red,
                };
                Line::styled(trunc(l, log.width as usize), t.s(c))
            })
            .collect();
        f.render_widget(Paragraph::new(shown), log);
        gate_card(f, card, card_color, head, body, sub);
    }
}

fn card_for(v: &View, s: &Session) -> (Color, Line<'static>, Vec<Line<'static>>, Line<'static>) {
    let t = v.t;
    let n = s.wf.steps.len();
    if let Some(e) = &s.error {
        return (
            t.red,
            Line::styled("✗ can't continue", t.s(t.red)),
            vec![Line::styled(e.clone(), t.fg())],
            Line::styled("[r] re-check   [a] abandon", t.dim()),
        );
    }
    if let Some(l) = &s.live {
        let el = l.started.elapsed().as_secs();
        let step = &s.wf.steps[l.idx];
        let mut body = format!("elapsed {}:{:02}", el / 60, el % 60);
        if let Some(to) = step.timeout {
            body.push_str(&format!(" · timeout {to}"));
        }
        return (
            t.cyan,
            Line::styled(
                format!(
                    "⠿ running · {}{}",
                    step.id,
                    if l.dry { " (dry run)" } else { "" }
                ),
                t.s(t.cyan),
            ),
            vec![Line::styled(body, t.fg())],
            Line::styled(
                format!("output → steps/{}.log   C-c terminates", step.id),
                t.dim(),
            ),
        );
    }
    if s.done() {
        let st = &s.run.state;
        let dur = st
            .ended
            .map_or(0, |e| e.as_second() - st.started.as_second());
        return (
            t.green,
            Line::styled(format!("✓ {} complete", s.wf.name), t.s(t.green)),
            vec![Line::styled(
                format!(
                    "{} steps · {} skipped · {}m",
                    st.done_count(),
                    st.steps
                        .iter()
                        .filter(|x| x.status == StepStatus::Skipped)
                        .count(),
                    dur / 60
                ),
                t.fg(),
            )],
            Line::styled("[Enter] close   [L] log", t.dim()),
        );
    }
    let Some(i) = s.next.idx() else {
        return (t.dim, Line::raw(""), vec![], Line::raw(""));
    };
    let step = &s.wf.steps[i];
    let title = format!("{}/{n} {}", i + 1, s.title(i));
    let cmd = step
        .run
        .as_deref()
        .map(|r| preview(&s.run.state, r))
        .unwrap_or_default();
    let opt = if step.optional {
        "   [s] skip optional"
    } else {
        ""
    };
    let manual_text = step
        .manual
        .as_deref()
        .map(|m| preview(&s.run.state, m))
        .unwrap_or_default();
    match s.next {
        Next::Confirm(_) | Next::Run(_) => {
            let mut body = vec![Line::styled(format!("$ {cmd}"), t.fg())];
            let dry = step.dry_run != Some(false) && !s.run.state.steps[i].dry_ok;
            let dry_cmd = crate::workflows::dry_run_of(&cmd).filter(|_| dry);
            if let Some(d) = &dry_cmd {
                body.push(Line::styled(format!("dry run first: $ {d}"), t.dim()));
            } else if cmd.starts_with("rpm-ostree rebase") {
                body.push(Line::styled("rpm-ostree rebase has no dry run; `rpm-ostree cleanup -p` undoes a staged rebase", t.dim()));
            }
            let auto = matches!(s.next, Next::Run(_));
            (
                t.yellow,
                Line::styled(
                    format!("▶ {title} · {}", if auto { "auto" } else { "confirm" }),
                    t.s(t.yellow),
                ),
                body,
                Line::styled(
                    format!(
                        // Every key that applies, so a failing dry run isn't a loop on Enter.
                        "[Enter] {}{}   [s] skip   [L] log   [a] abandon",
                        if dry_cmd.is_some() {
                            "dry run"
                        } else if auto {
                            "run now"
                        } else {
                            "run"
                        },
                        if dry_cmd.is_some() {
                            "   [D] skip the dry run"
                        } else {
                            ""
                        }
                    ),
                    t.dim(),
                ),
            )
        }
        Next::Reboot { requested, .. } => (
            t.mag,
            Line::styled(format!("↻ {title}"), t.s(t.mag)),
            vec![Line::styled(
                if requested {
                    "A reboot was requested but this is still the same boot."
                } else {
                    "State saved — run `sentry` after login to continue."
                },
                t.fg(),
            )],
            Line::styled(
                if requested {
                    "[Enter] reboot now   [d] mark done   [a] abandon"
                } else {
                    "[Enter] reboot now · reboot never runs on its own"
                },
                t.dim(),
            ),
        ),
        Next::Shell(_) => (
            t.yellow,
            Line::styled(format!("▶ {title} · shell"), t.s(t.yellow)),
            vec![Line::styled(
                "Opens $SHELL here; exit it to continue the workflow.",
                t.fg(),
            )],
            Line::styled(format!("[Enter] open shell{opt}   [a] abandon"), t.dim()),
        ),
        Next::Manual { failed: false, .. } => (
            t.yellow,
            Line::styled(format!("✋ {title} · manual"), t.s(t.yellow)),
            manual_text
                .lines()
                .map(|l| Line::styled(l.to_string(), t.fg()))
                .collect(),
            Line::styled(format!("[Enter] done{opt}   [a] abandon"), t.dim()),
        ),
        Next::Manual { failed: true, .. } | Next::Stopped(_) => {
            let code = s.run.state.steps[i]
                .code
                .map_or("?".into(), |c| c.to_string());
            let mut body: Vec<Line> = manual_text
                .lines()
                .map(|l| Line::styled(l.to_string(), t.fg()))
                .collect();
            if let Some(note) = &s.run.state.steps[i].note {
                body.insert(0, Line::styled(note.clone(), t.dim()));
            }
            (
                t.red,
                Line::styled(format!("✗ {title} · failed (exit {code})"), t.s(t.red)),
                body,
                Line::styled(
                    format!(
                        "{}[r] retry   [d] done by hand   [s] skip   [L] log   [a] abandon",
                        if crate::claude::available() {
                            "[f] fix with Claude   "
                        } else {
                            ""
                        },
                    ),
                    t.dim(),
                ),
            )
        }
        Next::Done => (t.dim, Line::raw(""), vec![], Line::raw("")),
    }
}

impl Upgrade {
    pub fn ask(&self, v: &View) -> Result<crate::claude::Ask, String> {
        let Some(s) = v.wf else {
            let infos = self.infos(v);
            let info = infos
                .get(self.cur.sel.min(infos.len().saturating_sub(1)))
                .ok_or("no workflow selected")?;
            let text = std::fs::read_to_string(&info.entry.path).unwrap_or_default();
            return Ok(crate::claude::Ask::new(
                format!("workflow {}", info.entry.name),
                format!(
                    "A sentry upgrade workflow ({}):\n{text}",
                    info.entry.path.display()
                ),
                "Walk me through what this workflow does on my machine and what could go wrong.",
            ));
        };
        let Some(i) = s.next.idx() else {
            return Ok(ask_finished(s));
        };
        let step = &s.wf.steps[i];
        let st = &s.run.state.steps[i];
        let log = std::fs::read_to_string(s.run.log_path(&step.id)).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        let tail = lines[lines.len().saturating_sub(60)..].join("\n");
        let failed = matches!(st.status, crate::workflows::state::StepStatus::Failed);
        let vars: Vec<String> = s
            .run
            .state
            .vars
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        Ok(crate::claude::Ask::new(
            format!("{} · {}", s.wf.name, step.id),
            format!(
                "Step {}/{} of the sentry workflow {} on my machine:\ntitle {}\ncommand {}\nstatus {:?}{}\nvars {}\nlast lines of steps/{}.log:\n{}",
                i + 1,
                s.wf.steps.len(),
                s.wf.name,
                s.title(i),
                preview(&s.run.state, step.run.as_deref().unwrap_or("(no command)")),
                st.status,
                st.code.map_or(String::new(), |c| format!(", exit {c}")),
                vars.join(" "),
                step.id,
                if tail.is_empty() {
                    "(empty)".into()
                } else {
                    tail
                }
            ),
            if failed {
                "Why did this fail and what should I do next?"
            } else {
                "What does this step do and what could go wrong?"
            },
        ))
    }
}

/// A run that has ended: its steps, the failed step's last lines, and earlier runs of the
/// same workflow from the ledger.
fn ask_finished(s: &Session) -> crate::claude::Ask {
    let e = crate::maint::log::LogEntry::from_run(
        crate::maint::LOCAL,
        &s.wf,
        &s.run.state,
        &s.run.dir,
        None,
        None,
    );
    let mut ctx = format!(
        "The sentry workflow {} on my machine has ended ({}). Its record:\n\n{}\n",
        s.wf.name, e.head.result, e.body
    );
    if let Some(id) = e.head.failed.last() {
        let log = std::fs::read_to_string(s.run.log_path(id)).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        ctx.push_str(&format!(
            "\nLast lines of steps/{id}.log:\n{}\n",
            lines[lines.len().saturating_sub(60)..].join("\n")
        ));
    }
    let earlier: Vec<String> = crate::maint::log::list(crate::maint::LOCAL)
        .iter()
        .filter(|x| x.head.workflow == s.wf.name && x.head.run != e.head.run)
        .take(5)
        .map(|x| format!("- {}", x.line()))
        .collect();
    if !earlier.is_empty() {
        ctx.push_str(&format!(
            "\nEarlier runs (maintenance ledger):\n{}\n",
            earlier.join("\n")
        ));
    }
    crate::claude::Ask::new(
        format!("{} · {}", s.wf.name, e.head.result),
        ctx,
        if e.head.failed.is_empty() && e.head.result == "done" {
            "This run is done. Is there anything I should check now that it's finished?"
        } else {
            "What happened in this run, what state is my machine in now, and what should I do next?"
        },
    )
}

/// The plan ready for this workflow, if there is one.
pub fn ready_plan<'a>(v: &View<'a>, wf: &str) -> Option<&'a crate::maint::plan::PlanDoc> {
    v.sh.plans
        .get(wf)
        .filter(|p| p.head.status == crate::maint::plan::PlanStatus::Ready)
}

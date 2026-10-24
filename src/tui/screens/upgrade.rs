//! Upgrade (`0`): workflows. Idle: the list with lint status and the step chain. Running: the
//! step list with status glyphs, the streaming log, and a gate card for the current step.

use std::collections::BTreeMap;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use super::{Cursor, Hints, View};
use crate::tui::app::{Effect, Modal, Prompt, WfCmd};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::wf::{LogKind, Session};
use crate::tui::widgets::{inner, panel, trunc, wrap};
use crate::workflows::Kind;
use crate::workflows::cli::{RealEnv, initial_vars};
use crate::workflows::runner::{Next, preview};
use crate::workflows::state::{RunStatus, StepStatus};

#[derive(Default)]
pub struct Upgrade {
    pub cur: Cursor,
}

/// A workflow file plus its most recent run (for the idle list).
#[derive(Debug, Clone)]
pub struct WfInfo {
    pub entry: crate::workflows::Entry,
    pub last: Option<(RunStatus, jiff::Timestamp, usize, usize)>,
}

pub fn load_infos() -> Vec<WfInfo> {
    crate::workflows::list()
        .into_iter()
        .map(|entry| {
            let last = crate::workflows::state::runs_of(&entry.name)
                .last()
                .map(|r| {
                    (
                        r.state.status,
                        r.state.started,
                        r.state.done_count(),
                        r.state.steps.len(),
                    )
                });
            WfInfo { entry, last }
        })
        .collect()
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
        ],
        Some(s) if s.done() => vec![("Enter", "close"), ("l", "log")],
        Some(s) => {
            let mut h = vec![
                ("Enter", "run"),
                ("s", "skip optional"),
                ("a", "abandon"),
                ("l", "log"),
            ];
            if failed(s) {
                h.insert(1, ("r", "retry"));
                if matches!(s.next, Next::Manual { .. }) {
                    h.insert(2, ("d", "done by hand"));
                }
                if crate::claude::available() {
                    h.insert(1, ("f", "fix (with Claude)"));
                }
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
    let mut actions = vec![("retry", "run the step again (t in this chat)")];
    if matches!(s.next, Next::Manual { .. }) {
        actions.push((
            "done by hand",
            "accept the step as done after fixing it yourself",
        ));
    }
    if step.optional {
        actions.push(("skip", "skip this optional step"));
    }
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

fn when(ts: jiff::Timestamp) -> String {
    ts.to_zoned(jiff::tz::TimeZone::system())
        .strftime("%Y-%m-%d %H:%M")
        .to_string()
}

fn short_home(p: &std::path::Path) -> String {
    let h = crate::paths::home();
    match p.strip_prefix(&h) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => p.display().to_string(),
    }
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
                let vars = match initial_vars(wf, &RealEnv, &BTreeMap::new()) {
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
                let chain: Vec<&str> = wf.steps.iter().map(|s| s.id.as_str()).collect();
                vec![Effect::Confirm(Modal {
                    title: format!("Start {}", info.entry.name),
                    color: t.yellow,
                    lines: vec![
                        Line::styled(wf.description.clone(), t.fg()),
                        Line::styled(chain.join(" → "), t.dim()),
                        Line::styled(
                            "Auto steps run right away; every other step waits for Enter. Reboots never run on their own.",
                            t.dim(),
                        ),
                    ],
                    yes: Some((
                        "start".into(),
                        vec![Effect::Wf(WfCmd::Begin(info.entry.name.clone(), vars))],
                    )),
                })]
            }
            _ => Vec::new(),
        }
    }

    fn handle_running(&mut self, a: Action, v: &View, s: &Session) -> Vec<Effect> {
        let t = v.t;
        if s.done() {
            return match a {
                Action::Enter | Action::Esc => vec![Effect::Wf(WfCmd::Close)],
                Action::Char('l') => vec![Effect::Wf(WfCmd::OpenLog)],
                _ => Vec::new(),
            };
        }
        match a {
            Action::Down | Action::LogDown => vec![Effect::Wf(WfCmd::Scroll(-1))],
            Action::Up | Action::LogUp => vec![Effect::Wf(WfCmd::Scroll(1))],
            Action::PageDown => vec![Effect::Wf(WfCmd::Scroll(-10))],
            Action::PageUp => vec![Effect::Wf(WfCmd::Scroll(10))],
            Action::Bottom => vec![Effect::Wf(WfCmd::Scroll(i32::MIN))],
            Action::Char('l') => vec![Effect::Wf(WfCmd::OpenLog)],
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
                    "Claude Code not found: see the step's advice and its log (l)".into(),
                )],
                None => vec![Effect::Toast("f helps with a failed step".into())],
            },
            Action::Char('s') => vec![Effect::Wf(WfCmd::Skip)],
            Action::Char('r') | Action::Refresh => vec![Effect::Wf(WfCmd::Retry)],
            Action::Char('d') => vec![Effect::Wf(WfCmd::Done)],
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
        let [left, right] = Layout::horizontal([
            Constraint::Length(60.min(area.width / 2)),
            Constraint::Fill(1),
        ])
        .spacing(2)
        .areas(area);
        match v.wf {
            Some(s) => self.render_running(f, left, right, v, s),
            None => self.render_idle(f, left, right, v),
        }
    }

    fn render_idle(&mut self, f: &mut Frame, left: Rect, right: Rect, v: &View) {
        let t = v.t;
        let infos = self.infos(v);
        let dir = infos
            .first()
            .and_then(|i| i.entry.path.parent().map(short_home))
            .unwrap_or_default();
        let block = panel(t, "Workflows", dir);
        let r = inner(&block, left);
        f.render_widget(block, left);
        let sel = self.cur.clamp(infos.len());
        let mut y = r.y;
        for (i, info) in infos.iter().enumerate() {
            let e = &info.entry;
            let steps = e.wf.as_ref().map_or(0, |w| w.steps.len());
            let desc =
                e.wf.as_ref()
                    .map_or(String::new(), |w| w.description.clone());
            let mut head = vec![
                Span::styled(e.name.clone(), t.fg()),
                Span::styled(format!("  {steps} steps"), t.dim()),
            ];
            if e.wf.as_ref().is_ok_and(|w| w.draft) {
                head.push(Span::styled("  draft", t.s(t.yellow)));
            }
            if e.errors().next().is_some() || e.wf.is_err() {
                head.push(Span::styled("  lint ✗", t.s(t.red)));
            }
            let (last, lc) = match info.last {
                Some((RunStatus::Done, ts, d, n)) => {
                    (format!("✓ {} · {d}/{n} · completed", when(ts)), t.green)
                }
                Some((RunStatus::Abandoned, ts, d, n)) => {
                    (format!("■ {} · {d}/{n} · abandoned", when(ts)), t.dim)
                }
                Some((RunStatus::InProgress, ts, d, n)) => {
                    (format!("● {} · {d}/{n} · in progress", when(ts)), t.yellow)
                }
                None => ("never run".into(), t.dim),
            };
            let mut lines = vec![Line::from(head)];
            lines.extend(
                wrap(&desc, r.width as usize)
                    .into_iter()
                    .map(|l| Line::styled(l, t.dim())),
            );
            lines.push(Line::styled(last, t.s(lc)));
            let h = lines.len() as u16;
            let rect = Rect {
                y,
                height: h.min(r.bottom().saturating_sub(y)),
                ..r
            };
            let style = if i == sel {
                Style::new().bg(t.sel_bg)
            } else {
                Style::new()
            };
            f.render_widget(Paragraph::new(lines).style(style), rect);
            y += h + 1;
            if y >= r.bottom() {
                break;
            }
        }
        if infos.is_empty() {
            f.render_widget(
                Paragraph::new(v.d.workflows.status(v.d.loading(Fetch::Workflows))).style(t.dim()),
                r,
            );
        }

        // Right: last result + card for the selected workflow.
        let block = panel(t, "Last result", "");
        let r = inner(&block, right);
        f.render_widget(block, right);
        let Some(info) = infos.get(sel) else { return };
        let chain = info
            .entry
            .wf
            .as_ref()
            .map(|w| {
                w.steps
                    .iter()
                    .filter(|s| !s.rollback)
                    .map(|s| s.id.as_str())
                    .collect::<Vec<_>>()
                    .join(" → ")
            })
            .unwrap_or_default();
        let file = info
            .entry
            .path
            .file_name()
            .map_or(String::new(), |n| n.to_string_lossy().into_owned());
        let blocked = info.entry.blocked();
        let mut body = vec![Line::styled(chain, t.fg())];
        if let Some(why) = &blocked {
            body.push(Line::styled(why.clone(), t.s(t.yellow)));
        }
        let cw = r.width.saturating_sub(4).max(1) as usize;
        let rows: usize = body.iter().map(|l| l.width().max(1).div_ceil(cw)).sum();
        let card_h = (rows as u16 + 4).min(r.height.saturating_sub(4));
        let [log, card] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(card_h)]).areas(r);
        let mut lines = vec![
            Line::styled("No workflow in progress.", t.dim()),
            Line::raw(""),
        ];
        match info.last {
            Some((st, ts, d, n)) => {
                lines.push(Line::styled(
                    format!("last run  {}  {}", info.entry.name, when(ts)),
                    t.fg(),
                ));
                lines.push(Line::styled(
                    format!("          {d}/{n} steps · {st:?}").to_lowercase(),
                    t.dim(),
                ));
            }
            None => lines.push(Line::styled(
                format!("{} has never run.", info.entry.name),
                t.dim(),
            )),
        }
        f.render_widget(Paragraph::new(lines), log);
        let lint = match blocked {
            None => Span::styled("lint ✓", t.s(t.green)),
            Some(_) => Span::styled("can't start", t.s(t.yellow)),
        };
        gate_card(
            f,
            card,
            t.dim,
            Line::styled(file, t.dim()),
            body,
            Line::from(vec![
                Span::styled("[Enter] start   [e] edit   ", t.dim()),
                lint,
            ]),
        );
    }

    fn render_running(&mut self, f: &mut Frame, left: Rect, right: Rect, v: &View, s: &Session) {
        let t = v.t;
        let n = s.wf.steps.len();
        let block = panel(t, &s.wf.name, format!("{}/{n}", s.run.state.done_count()));
        let r = inner(&block, left);
        f.render_widget(block, left);
        let [list, info] = Layout::vertical([Constraint::Fill(1), Constraint::Length(4)]).areas(r);
        let cur = s.next.idx();
        let spin = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let tick = (jiff::Timestamp::now().as_millisecond() / 250) as usize % spin.len();
        // Keep the current step in view.
        let h = list.height as usize;
        let start = cur.map_or(0, |c| c.saturating_sub(h.saturating_sub(3)));
        let lines: Vec<Line> =
            s.wf.steps
                .iter()
                .enumerate()
                .skip(start)
                .take(h)
                .map(|(i, step)| {
                    let st = &s.run.state.steps[i];
                    let is_cur = cur == Some(i) && !s.done();
                    let live = s.live.as_ref().is_some_and(|l| l.idx == i);
                    let (g, c) = match st.status {
                        _ if live => (spin[tick], t.cyan),
                        StepStatus::Ok => ("✓", t.green),
                        StepStatus::Skipped => ("–", t.dim),
                        StepStatus::Failed => ("✗", t.red),
                        StepStatus::Running if step.kind == Kind::Reboot => ("↻", t.yellow),
                        _ if is_cur && step.kind == Kind::Reboot => ("↻", t.yellow),
                        _ if is_cur => ("▶", t.yellow),
                        _ if step.kind == Kind::Reboot => ("↻", t.dim),
                        _ => ("○", t.dim),
                    };
                    let tag = step.tag();
                    let tc = match tag {
                        "reboot" => t.mag,
                        "confirm" => t.yellow,
                        _ => t.dim,
                    };
                    let title_c = match st.status {
                        StepStatus::Skipped => t.dim,
                        StepStatus::Pending if !is_cur => t.dim,
                        _ => t.fg,
                    };
                    let w = list.width as usize;
                    let title = trunc(&s.title(i), w.saturating_sub(4 + 3 + 10));
                    let pad = w.saturating_sub(4 + 3 + title.chars().count() + tag.len());
                    let style = if is_cur {
                        Style::new().bg(t.sel_bg)
                    } else {
                        Style::new()
                    };
                    Line::from(vec![
                        Span::styled(format!("{g}  "), t.s(c)),
                        Span::styled(format!("{:>2} ", i + 1), t.dim()),
                        Span::styled(title, t.s(title_c)),
                        Span::raw(" ".repeat(pad)),
                        Span::styled(tag, t.s(tc)),
                    ])
                    .style(style)
                })
                .collect();
        f.render_widget(Paragraph::new(lines), list);
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
        let card_h = (rows as u16 + 3).min(r.height / 2);
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
            Line::styled("[Enter] close   [l] log", t.dim()),
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
                        "[Enter] {}{opt}   [a] abandon",
                        if dry_cmd.is_some() {
                            "dry run"
                        } else if auto {
                            "run now"
                        } else {
                            "run"
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
            let manual = matches!(s.next, Next::Manual { .. });
            (
                t.red,
                Line::styled(format!("✗ {title} · failed (exit {code})"), t.s(t.red)),
                body,
                Line::styled(
                    format!(
                        "{}[r] retry   {}[l] log   [a] abandon",
                        if crate::claude::available() {
                            "[f] fix with Claude   "
                        } else {
                            ""
                        },
                        if manual { "[d] done by hand   " } else { "" }
                    ),
                    t.dim(),
                ),
            )
        }
        Next::Done => (t.dim, Line::raw(""), vec![], Line::raw("")),
    }
}

fn gate_card(f: &mut Frame, area: Rect, color: Color, head: Line, body: Vec<Line>, sub: Line) {
    if area.height < 3 {
        return;
    }
    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(color));
    let r = block.inner(area);
    let r = Rect {
        x: r.x + 1,
        width: r.width.saturating_sub(2),
        ..r
    };
    f.render_widget(block, area);
    let mut lines = vec![head];
    lines.extend(body);
    let [b, s] = Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(r);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), b);
    f.render_widget(Paragraph::new(sub), s);
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
        let i = s.next.idx().ok_or("the workflow is complete")?;
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

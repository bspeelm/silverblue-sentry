//! The apply session's window (both programs): where it stands at the top, then the brief,
//! Claude's answers, each plan where it was sent (the current one as a live checklist, the
//! running step's output under it), the verdict; an input line and only the keys that mean
//! something now.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::chat::{brief_lines, entry_lines, show_focused};
use super::theme::Theme;
use super::widgets::{self, chip, wrap};
use crate::apply::plan::{Kind as K, Run, RunState};
use crate::apply::session::{End, Phase, Session, Turn};

const STAGES: [&str; 6] = ["brief", "investigate", "plan", "apply", "verify", "done"];

fn stage(p: Phase) -> usize {
    match p {
        Phase::Brief => 0,
        Phase::Thinking(Turn::Investigate | Turn::Fix) => 1,
        Phase::Review => 2,
        Phase::SudoCheck | Phase::Password { .. } | Phase::Applying => 3,
        Phase::Thinking(Turn::Verify) => 4,
        Phase::Settled(_) => 5,
    }
}

/// `wf`: how the workflow the plan waits for is doing (one or two lines, from the app).
pub fn draw(f: &mut Frame, area: ratatui::layout::Rect, t: &Theme, s: &Session, wf: &[String]) {
    f.render_widget(ratatui::widgets::Clear, area);
    let rect = widgets::centered(
        area,
        area.width.saturating_sub(6).max(60),
        area.height.saturating_sub(2),
    );
    let color = if s.busy() { t.cyan } else { t.mag };
    let c = &s.chat;
    let inner = widgets::overlay(f, rect, t, &format!("Claude · {}", c.ask.subject), color);
    let [head, log, rule, input, keyline] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    f.render_widget(Paragraph::new(stages(t, s.phase)), head);
    let w = log.width as usize;
    let mut lines = brief_lines(c, t, w, s.brief_open || s.phase == Phase::Brief);
    lines.extend(entry_lines(c, t, w, true, &|i| plan_lines(s, i, t, w, wf)));
    if let Some(l) = status(s, t) {
        lines.push(l);
    }
    // Applying: the running (or waiting) step stays in view, however long the plan.
    let focus = matches!(s.phase, Phase::Applying)
        .then(|| {
            lines.iter().rposition(|l| {
                l.spans
                    .first()
                    .is_some_and(|x| x.content.contains('▶') || x.content.contains('⏸'))
            })
        })
        .flatten();
    show_focused(f, log, c, lines, focus);
    f.render_widget(
        Paragraph::new("─".repeat(rule.width as usize)).style(t.s(t.rule)),
        rule,
    );
    f.render_widget(Paragraph::new(input_line(s, t)), input);
    let mut spans = Vec::new();
    for (k, d) in keys(s) {
        spans.extend(chip(t, k, d, t.dim));
        spans.push(Span::raw("  "));
    }
    if c.cost > 0.0 {
        spans.push(Span::styled(format!("session ${:.3}", c.cost), t.dim()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), keyline);
}

fn stages(t: &Theme, p: Phase) -> Line<'static> {
    let now = stage(p);
    let failed = matches!(p, Phase::Settled(End::Failed | End::Stopped));
    let mut v = vec![Span::raw(" ")];
    for (i, name) in STAGES.iter().enumerate() {
        if i > 0 {
            v.push(Span::styled(" › ", t.dim()));
        }
        let st = if i == now {
            if failed && i == STAGES.len() - 1 {
                t.s(t.red)
            } else {
                t.s(t.cyan).add_modifier(ratatui::style::Modifier::BOLD)
            }
        } else if i < now {
            t.s(t.green)
        } else {
            t.dim()
        };
        let word = if i == STAGES.len() - 1 {
            match p {
                Phase::Settled(End::Failed) => "not done",
                Phase::Settled(End::Stopped) => "stopped",
                Phase::Settled(End::Unverified) => "unverified",
                _ => name,
            }
        } else {
            name
        };
        v.push(Span::styled(word.to_string(), st));
    }
    Line::from(v)
}

/// What's happening right now, under everything.
fn status(s: &Session, t: &Theme) -> Option<Line<'static>> {
    let secs = s.chat.started.map_or(0, |x| x.elapsed().as_secs());
    let clock = format!("({}:{:02})", secs / 60, secs % 60);
    let text = match s.phase {
        Phase::Thinking(Turn::Investigate) => format!("… Claude is looking into it {clock}"),
        Phase::Thinking(Turn::Fix) => format!("… Claude is correcting the plan {clock}"),
        Phase::Thinking(Turn::Verify) => format!("… Claude is checking the result {clock}"),
        Phase::SudoCheck => "… checking whether sudo needs your password".into(),
        Phase::Password { checking: true, .. } => "… checking the password".into(),
        // Waiting for the user: said plainly, at the bottom, where the eye ends up.
        Phase::Review | Phase::Settled(_) => {
            let word = s.enter_word()?;
            let why = match (s.phase, s.runs.len().checked_sub(2).map(|i| &s.runs[i])) {
                (Phase::Review, Some(prev)) if matches!(prev.state, RunState::Failed(_)) => {
                    let RunState::Failed(k) = prev.state else {
                        unreachable!()
                    };
                    format!(
                        "the plan stopped at step {} ({}); Claude sent a plan for the rest · ",
                        k + 1,
                        prev.plan.steps[k].title
                    )
                }
                (Phase::Review, _) if s.can_approve() => "the plan is ready · ".into(),
                _ => String::new(),
            };
            return Some(Line::styled(
                format!("     ▶ Your turn: {why}Enter {word}"),
                t.s(t.yellow).add_modifier(ratatui::style::Modifier::BOLD),
            ));
        }
        _ => return None,
    };
    Some(Line::styled(format!("       {text}"), t.dim()))
}

fn input_line(s: &Session, t: &Theme) -> Line<'static> {
    let c = &s.chat;
    let typed = |hint: &str| {
        if c.input.is_empty() {
            Line::from(vec![
                Span::styled("› ", t.s(t.cyan)),
                Span::styled("▏", t.s(t.cyan)),
                Span::styled(hint.to_string(), t.dim()),
            ])
        } else {
            Line::from(vec![
                Span::styled("› ", t.s(t.cyan)),
                Span::styled(c.input.clone(), t.fg()),
                Span::styled("▏", t.s(t.cyan)),
            ])
        }
    };
    match s.phase {
        Phase::Brief => typed("add anything Claude should know, or just press Enter"),
        Phase::Review if s.can_approve() => {
            typed("Enter applies the plan · or type to ask for a change")
        }
        Phase::Review if s.run().is_none() => typed("Enter asks for a plan · or type what to do"),
        Phase::Review => typed("tell Claude what to do"),
        Phase::Settled(_) => typed("type to ask Claude more"),
        Phase::Password { tries, checking } => {
            let steps: Vec<String> = s.sudo_steps().iter().map(|n| n.to_string()).collect();
            let mut v = vec![
                Span::styled(
                    format!("sudo password (for step {}) › ", steps.join(", ")),
                    t.s(t.yellow),
                ),
                Span::styled("●".repeat(s.secret.len()), t.fg()),
            ];
            if !checking {
                v.push(Span::styled("▏", t.s(t.cyan)));
            }
            if tries > 0 {
                v.push(Span::styled(
                    format!("   sudo refused it · {} of 3", tries + 1),
                    t.s(t.red),
                ));
            }
            Line::from(v)
        }
        _ => Line::styled("  (working · C-c stops it · Esc hides this)", t.dim()),
    }
}

pub fn keys(s: &Session) -> Vec<(&'static str, &'static str)> {
    let typed = !s.chat.input.is_empty();
    let mut k = Vec::new();
    let typing = matches!(s.phase, Phase::Brief | Phase::Review | Phase::Settled(_));
    if typed && typing && s.phase != Phase::Brief {
        k.push(("Enter", "send"));
    } else if let Some(w) = s.enter_word() {
        k.push(("Enter", w));
    }
    if s.can_grant() {
        k.push(("g", "grant it"));
    }
    match s.phase {
        Phase::Brief => {
            k.push(("Tab", "the whole brief"));
            k.push(("Esc", "cancel"));
        }
        Phase::Review | Phase::Settled(_) => k.push(("Esc", "close")),
        Phase::Password {
            checking: false, ..
        } => {
            k.push(("Enter", "unlock"));
            k.push(("Esc", "back"));
        }
        _ => {
            k.push(("C-c", "stop"));
            k.push(("Esc", "hide"));
        }
    }
    k.push(("↑↓ PgUp/Dn", "scroll"));
    k
}

/// The plan at `idx`, where it was sent: an earlier one folded, the current one as a live
/// checklist.
fn plan_lines(s: &Session, idx: usize, t: &Theme, w: usize, wf: &[String]) -> Vec<Line<'static>> {
    let Some(r) = s.runs.get(idx) else {
        return Vec::new();
    };
    let fit = |x: &str, pad: usize| widgets::trunc(x, w.saturating_sub(pad).max(10));
    if idx + 1 < s.runs.len() {
        let why = s
            .replaced
            .iter()
            .find(|(i, _)| *i == idx)
            .map(|(_, w)| w.as_str())
            .unwrap_or("replaced");
        let mut l = vec![Line::styled(
            fit(
                &format!("       Plan {}: {} · {why}", idx + 1, r.plan.summary),
                1,
            ),
            t.dim(),
        )];
        for (i, (st, res)) in r.plan.steps.iter().zip(&r.results).enumerate() {
            let (g, col) = if res.ok {
                ("✓", t.green)
            } else {
                ("✗", t.red)
            };
            l.push(Line::from(vec![
                Span::styled(format!("     {g} "), t.s(col)),
                Span::styled(fit(&format!("{}. {}", i + 1, st.title), 8), t.dim()),
            ]));
        }
        l.push(Line::raw(""));
        return l;
    }
    let mut l = vec![Line::styled(
        fit(&format!("       Plan: {}", r.plan.summary), 1),
        t.s(t.yellow),
    )];
    if s.phase == Phase::Review && r.state == RunState::Proposed {
        let line = if s.can_approve() {
            let sudo = s.sudo_steps();
            format!(
                "Enter applies these {} steps · edited files are backed up first{} · then Claude checks the result",
                r.plan.steps.len(),
                if sudo.is_empty() {
                    String::new()
                } else {
                    " · sudo asks for your password once".into()
                }
            )
        } else {
            "sentry can't apply it as written (in red below) · tell Claude what to do".into()
        };
        for x in wrap(&line, w.saturating_sub(8).max(10)) {
            l.push(Line::styled(
                format!("       {x}"),
                t.s(if s.can_approve() { t.cyan } else { t.red }),
            ));
        }
    }
    for (i, st) in r.plan.steps.iter().enumerate() {
        l.extend(step_lines(s, r, i, t, w, wf));
        let _ = st;
    }
    if r.state == RunState::Proposed && !r.plan.rollback.trim().is_empty() {
        for x in wrap(
            &format!("To undo: {}", r.plan.rollback.trim()),
            w.saturating_sub(9).max(10),
        ) {
            l.push(Line::styled(format!("       {x}"), t.dim()));
        }
    }
    l.push(Line::raw(""));
    l
}

fn step_lines(
    s: &Session,
    r: &Run,
    i: usize,
    t: &Theme,
    w: usize,
    wf: &[String],
) -> Vec<Line<'static>> {
    let st = &r.plan.steps[i];
    let running = r.state == RunState::Running && i == r.current() && s.phase == Phase::Applying;
    let waiting = r.state == RunState::WaitingWorkflow(i);
    let (glyph, color) = match r.results.get(i) {
        Some(x) if x.ok => ("✓", t.green),
        Some(_) => ("✗", t.red),
        None if waiting => ("⏸", t.yellow),
        None if running => ("▶", t.cyan),
        None => ("○", t.dim),
    };
    let body = w.saturating_sub(9).max(10);
    let mut l = vec![Line::from(vec![
        Span::styled(format!("     {glyph} "), t.s(color)),
        Span::styled(
            widgets::trunc(
                &format!("{}. {}", i + 1, st.title),
                w.saturating_sub(8).max(10),
            ),
            t.fg(),
        ),
    ])];
    let push = |l: &mut Vec<Line<'static>>, text: &str, style| {
        for x in wrap(text, body) {
            l.push(Line::styled(format!("         {x}"), style));
        }
    };
    match &st.kind {
        K::Edit { file, old, new } => {
            let root = crate::apply::sudo::edit_target(file) == Ok(crate::apply::sudo::Owner::Root);
            push(
                &mut l,
                &format!(
                    "edit {file}{}",
                    if root { "  (root's: with sudo)" } else { "" }
                ),
                t.dim(),
            );
            let (o, n): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
            for x in o.iter().take(3) {
                l.push(Line::styled(
                    format!("         - {}", widgets::trunc(x, body.saturating_sub(2))),
                    t.s(t.red),
                ));
            }
            for x in n.iter().take(3) {
                l.push(Line::styled(
                    format!("         + {}", widgets::trunc(x, body.saturating_sub(2))),
                    t.s(t.green),
                ));
            }
            let more = o.len().saturating_sub(3) + n.len().saturating_sub(3);
            if more > 0 {
                l.push(Line::styled(
                    format!("         … {more} more lines"),
                    t.dim(),
                ));
            }
        }
        K::Run(c) | K::Check(c) => {
            let col = if crate::claude::risky(c).is_some() {
                t.red
            } else {
                t.cyan
            };
            for (j, x) in c.lines().enumerate() {
                let w0 = if j == 0 { st.kind.word() } else { "     " };
                push(&mut l, &format!("{w0} $ {x}"), t.s(col));
            }
        }
        K::Workflow { name, vars } => {
            let given: Vec<String> = vars.iter().map(|(k, v)| format!("{k}={v}")).collect();
            push(
                &mut l,
                &if given.is_empty() {
                    format!("workflow {name}")
                } else {
                    format!("workflow {name} ({})", given.join(", "))
                },
                t.s(t.cyan),
            )
        }
    }
    for (_, why) in s.problems.iter().filter(|(k, _)| *k == i) {
        push(&mut l, &format!("✗ {why}"), t.s(t.red));
    }
    if running {
        let n = s.output.len();
        for x in &s.output[n.saturating_sub(6)..] {
            push(&mut l, &format!("│ {x}"), t.dim());
        }
        // A step that prints nothing for minutes (a backup, `systemctl start` of a long
        // job) still shows it's alive.
        if let Some(at) = s.job_started {
            let e = at.elapsed().as_secs();
            push(
                &mut l,
                &format!(
                    "… running {}:{:02}{}",
                    e / 60,
                    e % 60,
                    if n == 0 { ", no output yet" } else { "" }
                ),
                t.s(t.cyan),
            );
        }
    }
    if waiting {
        for x in wf {
            push(&mut l, x, t.s(t.yellow));
        }
    }
    if let Some(res) = r.results.get(i) {
        let mut lines = res.note.lines();
        let first = lines.next().unwrap_or("");
        push(&mut l, &format!("→ {first}"), t.dim());
        let rest: Vec<&str> = lines.collect();
        let keep = if res.ok { 3 } else { 15 };
        for x in &rest[rest.len().saturating_sub(keep)..] {
            push(
                &mut l,
                &format!("│ {x}"),
                if res.ok { t.dim() } else { t.s(t.red) },
            );
        }
    }
    l
}

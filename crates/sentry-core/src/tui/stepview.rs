//! One look for work in steps, whoever does it: a workflow run (`0`, both programs) and an
//! apply session's plan are drawn from here. The header says whose it is, what it is,
//! whether auto mode is on, and where it stands, in the same words; each step is one row
//! (its mark, number, title, what kind it is, how long it took); what the running step
//! prints sits under its row, with how long it's been running.

use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::theme::Theme;
use super::widgets::trunc;
use crate::workflows::runner::Next;
use crate::workflows::state::{RunState, StepStatus};
use crate::workflows::{Kind, Workflow};

/// Where a step stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// Not reached.
    Todo,
    /// The next one, waiting for the user.
    Up,
    Running,
    /// It waits for something else (a workflow's run, a reboot).
    Waiting,
    Done,
    Failed,
    Skipped,
}

/// The mark's glyph and colour: the same wherever steps are listed.
pub fn glyph(t: &Theme, m: Mark) -> (&'static str, Color) {
    match m {
        Mark::Todo => ("○", t.dim),
        Mark::Up => ("▶", t.yellow),
        Mark::Running => ("▶", t.cyan),
        Mark::Waiting => ("⏸", t.yellow),
        Mark::Done => ("✓", t.green),
        Mark::Failed => ("✗", t.red),
        Mark::Skipped => ("–", t.dim),
    }
}

/// Where the whole thing stands, for the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// A step is running.
    Running,
    /// It waits for a key: what Enter does.
    You(String),
    /// Someone else is at work (Claude, a check): what.
    Working(String),
    Done,
    Failed,
    Stopped,
    /// Nothing to say.
    Idle,
}

impl State {
    /// The words, the same for a run and a session.
    pub fn words(&self) -> String {
        match self {
            State::Running => "▶ running".into(),
            State::You(enter) => format!("⏸ waiting on you · Enter {enter}"),
            State::Working(what) => format!("… {what}"),
            State::Done => "✓ done".into(),
            State::Failed => "✗ failed".into(),
            State::Stopped => "■ stopped".into(),
            State::Idle => String::new(),
        }
    }

    fn color(&self, t: &Theme) -> Color {
        match self {
            State::Running | State::Working(_) => t.cyan,
            State::You(_) => t.yellow,
            State::Done => t.green,
            State::Failed | State::Stopped => t.red,
            State::Idle => t.dim,
        }
    }
}

/// `m:ss`.
pub fn clock(d: Duration) -> String {
    let s = d.as_secs();
    format!("{}:{:02}", s / 60, s % 60)
}

/// The header: target · what · auto, then where it stands. One line where it fits; two (who
/// and what, then where it stands) where it doesn't, as in a narrow panel.
pub fn head(
    t: &Theme,
    target: &str,
    what: &str,
    auto: bool,
    state: &State,
    width: usize,
) -> Vec<Line<'static>> {
    let words = state.words();
    let auto_w = if auto { 7 } else { 0 };
    let who_w = 1 + target.chars().count() + 3 + what.chars().count() + auto_w;
    let one = words.is_empty() || who_w + 3 + words.chars().count() <= width;
    let room = width.saturating_sub(1 + target.chars().count() + 3 + auto_w);
    let mut who = vec![
        Span::styled(format!(" {target}"), t.s(t.fg).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" · {}", trunc(what, room.max(8))), t.fg()),
    ];
    if auto {
        who.push(Span::styled(
            " · auto",
            t.s(t.yellow).add_modifier(Modifier::BOLD),
        ));
    }
    let state_style = t.s(state.color(t)).add_modifier(Modifier::BOLD);
    if words.is_empty() {
        vec![Line::from(who)]
    } else if one {
        who.push(Span::styled(format!("   {words}"), state_style));
        vec![Line::from(who)]
    } else {
        vec![
            Line::from(who),
            Line::styled(
                format!(" {}", trunc(&words, width.saturating_sub(1))),
                state_style,
            ),
        ]
    }
}

/// One step.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub mark: Mark,
    pub title: String,
    /// What kind of step it is, in a word (`auto`, `confirm`, `reboot`…), if that says
    /// anything.
    pub tag: String,
    /// How long it took, once it ended.
    pub took: Option<Duration>,
}

/// A step's row: `▶  3. Title        confirm  0:42`. `current`: it's the one being done, or
/// waited on (highlighted).
pub fn row(t: &Theme, n: usize, r: &Row, width: usize, current: bool) -> Line<'static> {
    let (g, c) = glyph(t, r.mark);
    let took = r.took.map(clock).unwrap_or_default();
    let right = match (r.tag.is_empty(), took.is_empty()) {
        (true, true) => String::new(),
        (false, true) => r.tag.clone(),
        (true, false) => took,
        (false, false) => format!("{}  {took}", r.tag),
    };
    let lead = format!("{g} {n:>2}. ");
    let room = width.saturating_sub(lead.chars().count() + right.chars().count() + 2);
    let title = trunc(&r.title, room.max(8));
    let pad =
        width.saturating_sub(lead.chars().count() + title.chars().count() + right.chars().count());
    let title_style = match r.mark {
        Mark::Todo | Mark::Skipped => t.dim(),
        _ => t.fg(),
    };
    let tag_color = match r.tag.as_str() {
        "reboot" => t.mag,
        "confirm" | "risky" => t.yellow,
        _ => t.dim,
    };
    let line = Line::from(vec![
        Span::styled(lead, t.s(c)),
        Span::styled(title, title_style),
        Span::raw(" ".repeat(pad)),
        Span::styled(right, t.s(tag_color)),
    ]);
    if current {
        line.style(Style::new().bg(t.sel_bg))
    } else {
        line
    }
}

/// What the running step printed last, under its row: `│ line`, the last `keep`.
pub fn output(
    t: &Theme,
    lines: &[String],
    keep: usize,
    width: usize,
    indent: usize,
) -> Vec<Line<'static>> {
    let pad = " ".repeat(indent);
    lines[lines.len().saturating_sub(keep)..]
        .iter()
        .map(|x| {
            Line::styled(
                format!(
                    "{pad}│ {}",
                    trunc(x, width.saturating_sub(indent + 2).max(8))
                ),
                t.dim(),
            )
        })
        .collect()
}

/// The line under a running step: how long it's been, and how to stop it.
pub fn running(t: &Theme, since: Instant, quiet: bool, hint: &str, indent: usize) -> Line<'static> {
    Line::styled(
        format!(
            "{}… running {}{}{}",
            " ".repeat(indent),
            clock(since.elapsed()),
            if quiet { ", no output yet" } else { "" },
            if hint.is_empty() {
                String::new()
            } else {
                format!(" · {hint}")
            }
        ),
        t.s(t.cyan),
    )
}

/// A workflow run's steps as rows. `live`: the step running now; `title`: a step's title
/// with its values filled in.
pub fn run_rows(
    wf: &Workflow,
    st: &RunState,
    next: &Next,
    live: Option<usize>,
    title: &dyn Fn(usize) -> String,
) -> Vec<Row> {
    let cur = next.idx();
    wf.steps
        .iter()
        .zip(&st.steps)
        .enumerate()
        .map(|(i, (step, s))| {
            let mark = match s.status {
                _ if live == Some(i) => Mark::Running,
                StepStatus::Ok => Mark::Done,
                StepStatus::Skipped => Mark::Skipped,
                StepStatus::Failed => Mark::Failed,
                // A reboot asked for: the host is going down, or coming back.
                StepStatus::Running if step.kind == Kind::Reboot => Mark::Waiting,
                StepStatus::Running => Mark::Running,
                StepStatus::Pending if cur == Some(i) => Mark::Up,
                StepStatus::Pending => Mark::Todo,
            };
            let took = match (s.started, s.ended) {
                (Some(a), Some(b)) if matches!(mark, Mark::Done | Mark::Failed) => Some(
                    Duration::from_secs((b.as_second() - a.as_second()).max(0) as u64),
                ),
                _ => None,
            };
            Row {
                mark,
                title: title(i),
                tag: if step.risky {
                    "risky".into()
                } else {
                    step.tag().into()
                },
                took,
            }
        })
        .collect()
}

/// Where a run stands, in the header's words. `live`: a step is running.
pub fn run_state(next: &Next, live: bool) -> State {
    if live {
        return State::Running;
    }
    match next {
        Next::Done => State::Done,
        Next::Run(_) | Next::Confirm(_) => State::You("run the step".into()),
        Next::Reboot {
            requested: false, ..
        } => State::You("reboot now".into()),
        Next::Reboot { .. } => State::Working("waiting for the reboot".into()),
        Next::Shell(_) => State::You("open a shell".into()),
        Next::Manual { failed: false, .. } => State::You("done by hand".into()),
        Next::Manual { failed: true, .. } | Next::Stopped(_) => State::Failed,
    }
}

/// The steps of something, as one list.
pub struct Steps<'a> {
    pub target: &'a str,
    pub what: &'a str,
    pub auto: bool,
    pub state: State,
    pub rows: &'a [Row],
    /// The row that is being done or waited on.
    pub at: Option<usize>,
    /// What the running step printed (its tail is shown), and since when it runs.
    pub output: &'a [String],
    pub since: Option<Instant>,
    /// How to stop the running step, in a few words.
    pub stop: &'a str,
}

/// The header, a blank line, then the rows, the running one's output under it.
pub fn lines(t: &Theme, s: &Steps, width: usize) -> (Vec<Line<'static>>, Option<usize>) {
    // Two rows for the header, whichever way it fits.
    let mut l = head(t, s.target, s.what, s.auto, &s.state, width);
    l.resize(2, Line::raw(""));
    let mut focus = None;
    for (i, r) in s.rows.iter().enumerate() {
        let current = s.at == Some(i);
        if current {
            focus = Some(l.len());
        }
        l.push(row(t, i + 1, r, width, current));
        if current && r.mark == Mark::Running {
            l.extend(output(t, s.output, 6, width, 6));
            if let Some(since) = s.since {
                l.push(running(t, since, s.output.is_empty(), s.stop, 6));
            }
        }
    }
    (l, focus)
}

/// Draw the list in `area`, the current step kept in view.
pub fn draw(f: &mut Frame, area: Rect, t: &Theme, s: &Steps) {
    let (l, focus) = lines(t, s, area.width as usize);
    let h = area.height as usize;
    // The header stays; the rows scroll under it so the current one (and its output) shows.
    let body = h.saturating_sub(2);
    let start = match focus {
        Some(at) if l.len() > h => (at + 8).saturating_sub(h).min(l.len().saturating_sub(h)),
        _ => 0,
    };
    let mut shown: Vec<Line> = l.iter().take(2).cloned().collect();
    shown.extend(l.iter().skip(2 + start).take(body).cloned());
    f.render_widget(Paragraph::new(shown), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_words_and_marks_for_a_run_and_a_session() {
        let t = Theme::truecolor();
        assert_eq!(State::Running.words(), "▶ running");
        assert_eq!(
            State::You("apply the plan".into()).words(),
            "⏸ waiting on you · Enter apply the plan"
        );
        assert_eq!(State::Done.words(), "✓ done");
        assert_eq!(State::Failed.words(), "✗ failed");
        let h = head(&t, "myserver", "apt-maintenance", true, &State::Running, 80);
        assert_eq!(h.len(), 1);
        assert_eq!(
            h[0].to_string(),
            " myserver · apt-maintenance · auto   ▶ running"
        );
        let h = head(&t, "this machine", "quick-update", false, &State::Done, 80);
        assert_eq!(h[0].to_string(), " this machine · quick-update   ✓ done");
        // Too narrow for one line: who and what, then where it stands.
        let h = head(
            &t,
            "myserver",
            "apt-maintenance",
            true,
            &State::You("run the step".into()),
            50,
        );
        let h: Vec<String> = h.iter().map(|l| l.to_string()).collect();
        assert_eq!(
            h,
            [
                " myserver · apt-maintenance · auto",
                " ⏸ waiting on you · Enter run the step"
            ]
        );
        let r = Row {
            mark: Mark::Done,
            title: "Refresh package lists".into(),
            tag: "confirm".into(),
            took: Some(Duration::from_secs(75)),
        };
        assert_eq!(
            row(&t, 2, &r, 50, false).to_string(),
            "✓  2. Refresh package lists          confirm  1:15"
        );
        let out = output(&t, &["a".into(), "b".into(), "c".into()], 2, 40, 6);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].to_string(), "      │ c");
        let rows = [
            r.clone(),
            Row {
                mark: Mark::Running,
                title: "Install".into(),
                tag: String::new(),
                took: None,
            },
        ];
        let (l, focus) = lines(
            &t,
            &Steps {
                target: "myserver",
                what: "apt",
                auto: false,
                state: State::Running,
                rows: &rows,
                at: Some(1),
                output: &["Reading…".to_string()],
                since: Some(Instant::now()),
                stop: "C-c stops it",
            },
            60,
        );
        assert_eq!(focus, Some(3));
        let text: Vec<String> = l.iter().map(|x| x.to_string()).collect();
        assert!(text[3].starts_with("▶  2. Install"), "{text:?}");
        assert_eq!(text[4], "      │ Reading…");
        assert_eq!(text[5], "      … running 0:00 · C-c stops it");
    }
}

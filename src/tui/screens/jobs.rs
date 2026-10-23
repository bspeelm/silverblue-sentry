//! Jobs: last run, cadence and due status. `Enter` plans the job in the background, shows the
//! plan in a confirm modal, then streams `sentry job <name> --yes`. `e` edits the cadence.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row};

use super::{Cursor, Hints, View, sentry_cmd};
use crate::fmt;
use crate::jobs::JobId;
use crate::jobs::plan::{Act, Plan};
use crate::jobs::state::{self, Due, Every};
use crate::tui::app::{Effect, Modal, Prompt, RunSpec};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::theme::Theme;
use crate::tui::widgets::{TableSpec, table};

#[derive(Default)]
pub struct Jobs {
    pub cur: Cursor,
}

pub fn on_enter(_v: &View) -> Vec<Effect> {
    vec![Effect::Fetch(Fetch::Jobs)]
}

pub fn hints() -> Hints {
    vec![
        ("j/k", "select"),
        ("Enter", "run now"),
        ("e", "edit cadence"),
        ("r", "refresh"),
    ]
}

/// Collectors to refresh after a job finishes.
pub fn then_for(job: JobId) -> Vec<Fetch> {
    let mut v = vec![Fetch::Jobs];
    v.extend(match job {
        JobId::Audit => vec![Fetch::Reports],
        JobId::UpdateCheck | JobId::UpdateApply => {
            vec![Fetch::Ostree, Fetch::FlatpakUpdates, Fetch::Flatpak]
        }
        JobId::CleanupFlatpak => vec![Fetch::Flatpak, Fetch::Cleanup],
        JobId::CleanupPodman => vec![Fetch::Podman, Fetch::Cleanup],
        JobId::CleanupOstree | JobId::CleanupCache => vec![Fetch::Cleanup],
    });
    v
}

/// Confirm modal for a planned job (opened by the app when `Fetch::Plan` returns).
pub fn plan_modal(t: &Theme, job: JobId, p: &Plan) -> Modal {
    let mut lines = vec![
        Line::styled(format!("sentry job {}", job.name()), t.fg()),
        Line::styled(job.description(), t.dim()),
        Line::raw(""),
    ];
    let mut runnable = 0;
    for i in &p.items {
        let on = matches!(i.act, Act::Run(_) | Act::Builtin) && i.default_on;
        runnable += on as usize;
        let size = i
            .bytes
            .map_or(String::new(), |b| format!("  ≈ {}", fmt::bytes(b)));
        let (mark, c) = match (&i.act, on) {
            (Act::ListOnly | Act::Nothing, _) => ("·", t.dim),
            (_, false) => ("○", t.dim),
            (_, true) => ("•", t.fg),
        };
        lines.push(Line::styled(format!("{mark} {}{size}", i.label), t.s(c)));
        for pl in i.preview.iter().take(4) {
            lines.push(Line::styled(format!("    {pl}"), t.dim()));
        }
        if !on && i.runnable() {
            lines.push(Line::styled(
                "    opt-in: select it on Cleanup (9)",
                t.dim(),
            ));
        }
    }
    for n in &p.notes {
        lines.push(Line::styled(format!("! {n}"), t.s(t.yellow)));
    }
    if runnable == 0 {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Nothing to run.", t.fg()));
        return crate::tui::app::info_modal(t, &format!("Job · {}", job.name()), lines);
    }
    Modal {
        title: "Run job".into(),
        color: t.yellow,
        lines,
        yes: Some((
            "run now".into(),
            vec![Effect::Run(RunSpec {
                title: format!("sentry job {}", job.name()),
                cmd: sentry_cmd(&["job", job.name(), "--yes"]),
                queue: Vec::new(),
                then: then_for(job),
                ok_toast: format!("{} finished", job.name()),
            })],
        )),
    }
}

struct RowData {
    job: JobId,
    last: String,
    every: Every,
    status: (&'static str, Color),
    action: String,
}

impl Jobs {
    fn rows(&self, v: &View) -> Vec<RowData> {
        let t = v.t;
        let runs = v.d.job_runs.get().cloned().unwrap_or_default();
        let now = jiff::Timestamp::now();
        JobId::ALL
            .into_iter()
            .filter(|j| v.matches(&[j.name(), j.description()]))
            .map(|job| {
                let every = state::every(job, v.cfg);
                let run = runs.get(job.name());
                let due = state::due(job, every, &runs, now);
                let last = run.map_or("never".into(), |r| {
                    r.at.to_zoned(jiff::tz::TimeZone::system())
                        .strftime("%Y-%m-%d %H:%M")
                        .to_string()
                });
                let status = match (run, &due) {
                    (Some(r), _) if !r.ok => ("failed", t.red),
                    (_, d) if d.is_due() => ("DUE", t.yellow),
                    (_, Due::NotTracked) => ("—", t.dim),
                    _ => ("ok", t.dim),
                };
                let when = match due {
                    Due::In(s) if s > 0 => format!("in {} · ", fmt::age(s)),
                    Due::In(s) => format!("{} over · ", fmt::age(-s)),
                    Due::Never => "never run · ".into(),
                    Due::NotTracked => String::new(),
                };
                RowData {
                    job,
                    last,
                    every,
                    status,
                    action: format!("{when}{}", job.description()),
                }
            })
            .collect()
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        let rows = self.rows(v);
        if self.cur.nav(a, rows.len()) {
            return Vec::new();
        }
        let Some(r) = rows.get(self.cur.clamp(rows.len())) else {
            return Vec::new();
        };
        match a {
            Action::Refresh => vec![Effect::Fetch(Fetch::Jobs)],
            Action::Enter => vec![
                Effect::Fetch(Fetch::Plan(r.job)),
                Effect::Toast(format!("planning {}…", r.job.name())),
            ],
            Action::Char('e') => vec![Effect::Prompt(
                Prompt::Cadence(r.job),
                match r.every {
                    Every::Never => String::new(),
                    e => e.label(),
                },
            )],
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let rows = self.rows(v);
        let sel = self.cur.clamp(rows.len());
        let [list, _, foot] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(2),
        ])
        .areas(area);
        self.cur.page = list.height as usize;
        let body: Vec<Row> = rows
            .iter()
            .map(|r| {
                Row::new(vec![
                    Cell::from(r.job.name()),
                    Cell::from(r.last.clone()).style(t.dim()),
                    Cell::from(r.every.label()).style(t.dim()),
                    Cell::from(r.status.0).style(t.s(r.status.1)),
                    Cell::from(r.action.clone()).style(t.dim()),
                ])
            })
            .collect();
        table(
            f,
            list,
            t,
            TableSpec {
                header: vec!["JOB", "LAST RUN", "EVERY", "STATUS", "ACTION"],
                widths: vec![
                    Constraint::Length(20),
                    Constraint::Length(18),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Fill(1),
                ],
                rows: body,
                selected: (!rows.is_empty()).then_some(sel),
            },
        );
        let last = rows.get(sel).and_then(|r| {
            v.d.job_runs
                .get()
                .and_then(|runs| runs.get(r.job.name()))
                .map(|run| (r.job, run.clone()))
        });
        let mut lines = vec![Line::styled(
            "Cadence is a reminder. Nothing runs until you press Enter.",
            t.dim(),
        )];
        if let Some((job, run)) = last {
            lines.push(Line::from(vec![
                Span::styled(format!("last {} · ", job.name()), t.dim()),
                Span::styled(run.summary, t.s(if run.ok { t.fg } else { t.red })),
            ]));
        }
        f.render_widget(Paragraph::new(lines), foot);
    }
}

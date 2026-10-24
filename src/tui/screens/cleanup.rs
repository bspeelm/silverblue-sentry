//! Cleanup: reclaimable space from the cleanup jobs' dry-run plans, with checkboxes. `Enter`
//! confirms the selection and streams `sentry job <job> --yes --only <keys>` per job.

use std::collections::HashMap;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Wrap};

use super::jobs::then_for;
use super::{Cursor, Hints, View, sentry_cmd};
use crate::exec::Cmd;
use crate::fmt;
use crate::jobs::JobId;
use crate::jobs::plan::{Act, Item};
use crate::tui::app::{Effect, Modal, RunSpec};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::widgets::{TableSpec, inner, panel, table};

#[derive(Default)]
pub struct Cleanup {
    pub cur: Cursor,
    /// User toggles, keyed by (job, item key); absent = the item's default.
    checked: HashMap<(JobId, String), bool>,
    /// Opened from Jobs for one job: only its items start selected.
    pub focus: Option<JobId>,
    /// Move the cursor to the focused job's first item once plans are loaded.
    pub jump: bool,
}

pub fn on_enter(v: &View) -> Vec<Effect> {
    // Plans need a flatpak transaction preview and a few `du`s: fetch once, refresh on `r`.
    if v.d.cleanup.get().is_none() {
        vec![Effect::Fetch(Fetch::Cleanup)]
    } else {
        Vec::new()
    }
}

pub fn hints() -> Hints {
    vec![
        ("j/k", "select"),
        ("Space", "toggle"),
        ("Enter", "preview & confirm"),
        ("r", "re-plan"),
    ]
}

impl Cleanup {
    fn items<'a>(&self, v: &View<'a>) -> Vec<&'a Item> {
        v.d.cleanup.get().map_or(Vec::new(), |plans| {
            plans
                .iter()
                .flat_map(|p| p.items.iter())
                .filter(|i| v.matches(&[&i.label, i.job.name()]))
                .collect()
        })
    }

    pub fn reset_checks(&mut self) {
        self.checked.clear();
    }

    fn is_on(&self, i: &Item) -> bool {
        let default = i.default_on && self.focus.is_none_or(|j| j == i.job);
        i.runnable()
            && *self
                .checked
                .get(&(i.job, i.key.clone()))
                .unwrap_or(&default)
    }

    fn selected<'a>(&self, v: &View<'a>) -> Vec<&'a Item> {
        v.d.cleanup.get().map_or(Vec::new(), |plans| {
            plans
                .iter()
                .flat_map(|p| p.items.iter())
                .filter(|i| self.is_on(i))
                .collect()
        })
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        let items = self.items(v);
        if self.cur.nav(a, items.len()) {
            return Vec::new();
        }
        match a {
            Action::Refresh | Action::Check => {
                self.checked.clear();
                self.focus = None;
                vec![
                    Effect::Fetch(Fetch::Cleanup),
                    Effect::Toast("re-planning cleanup (dry runs)…".into()),
                ]
            }
            Action::Char(' ') => {
                if let Some(i) = items.get(self.cur.clamp(items.len())) {
                    if !i.runnable() {
                        return vec![Effect::Toast(format!("{}: list only", i.label))];
                    }
                    let on = self.is_on(i);
                    self.checked.insert((i.job, i.key.clone()), !on);
                }
                Vec::new()
            }
            Action::Enter => self.confirm(v),
            _ => Vec::new(),
        }
    }

    fn confirm(&self, v: &View) -> Vec<Effect> {
        let t = v.t;
        let sel = self.selected(v);
        if sel.is_empty() {
            return vec![Effect::Toast("nothing selected (Space toggles)".into())];
        }
        let total: u64 = sel.iter().filter_map(|i| i.bytes).sum();
        let mut lines: Vec<Line> = sel
            .iter()
            .map(|i| {
                Line::styled(
                    format!(
                        "• {:<52} {}",
                        i.label,
                        i.bytes.map_or("—".into(), fmt::bytes)
                    ),
                    t.fg(),
                )
            })
            .collect();
        lines.push(Line::styled(
            format!(
                "Total ≈ {} · the rollback deployment is kept",
                fmt::bytes(total)
            ),
            t.dim(),
        ));
        // One `sentry job` per job, in the order the plans are listed.
        let mut cmds: Vec<Cmd> = Vec::new();
        let mut then = Vec::new();
        for job in JobId::CLEANUP {
            let keys: Vec<&str> = sel
                .iter()
                .filter(|i| i.job == job)
                .map(|i| i.key.as_str())
                .collect();
            if keys.is_empty() {
                continue;
            }
            cmds.push(sentry_cmd(&[
                "job",
                job.name(),
                "--yes",
                "--only",
                &keys.join(","),
            ]));
            then.extend(then_for(job));
        }
        then.sort_by_key(|f| format!("{f:?}"));
        then.dedup();
        let jobs = cmds.len();
        let mut cmds = cmds.into_iter();
        let Some(first) = cmds.next() else {
            return Vec::new();
        };
        vec![Effect::Confirm(Modal {
            title: "Confirm cleanup".into(),
            color: t.yellow,
            lines,
            yes: Some((
                format!("run {jobs} job(s)"),
                vec![Effect::Run(RunSpec {
                    title: "cleanup".into(),
                    cmd: first,
                    queue: cmds.collect(),
                    then,
                    ok_toast: format!("cleanup complete · ≈ {} reclaimed", fmt::bytes(total)),
                })],
            )),
        })]
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let [left, right] = Layout::horizontal([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
            .spacing(2)
            .areas(area);
        if self.jump
            && let Some(j) = self.focus
            && let Some(i) = self.items(v).iter().position(|x| x.job == j)
        {
            self.cur.sel = i;
            self.jump = false;
        }
        let detail = match self.focus {
            Some(j) => format!("from dry-run · {} selected", j.name()),
            None => "from dry-run".into(),
        };
        let block = panel(t, "Reclaimable", detail);
        let r = inner(&block, left);
        f.render_widget(block, left);
        let Some(plans) = v.d.cleanup.get() else {
            let msg = v.d.cleanup.status(v.d.loading(Fetch::Cleanup));
            let msg = if msg == "loading…" {
                "planning (flatpak transaction preview, du)…".to_string()
            } else {
                msg
            };
            f.render_widget(Paragraph::new(msg).style(t.dim()), r);
            return;
        };
        let items = self.items(v);
        let sel = self.cur.clamp(items.len());
        let [list, sum] = Layout::vertical([Constraint::Fill(1), Constraint::Length(2)]).areas(r);
        self.cur.page = list.height as usize;
        let body: Vec<Row> = items
            .iter()
            .map(|i| {
                let on = self.is_on(i);
                let (bx, bc) = match (i.runnable(), on) {
                    (false, _) => (" · ", t.dim),
                    (true, true) => ("[x]", t.green),
                    (true, false) => ("[ ]", t.dim),
                };
                let size = match (i.bytes, &i.act) {
                    (Some(b), _) => fmt::bytes(b),
                    (None, Act::ListOnly) => "list only".into(),
                    (None, Act::Nothing) => "nothing".into(),
                    (None, _) => "—".into(),
                };
                Row::new(vec![
                    Cell::from(bx).style(t.s(bc)),
                    Cell::from(i.label.clone()).style(if i.runnable() { t.fg() } else { t.dim() }),
                    Cell::from(Line::from(size).right_aligned()).style(if i.bytes.is_some() {
                        t.fg()
                    } else {
                        t.dim()
                    }),
                ])
            })
            .collect();
        table(
            f,
            list,
            t,
            TableSpec {
                header: vec!["", "ITEM", "SIZE"],
                widths: vec![
                    Constraint::Length(3),
                    Constraint::Fill(1),
                    Constraint::Length(10),
                ],
                rows: body,
                selected: (!items.is_empty()).then_some(sel),
            },
        );
        let total: u64 = self.selected(v).iter().filter_map(|i| i.bytes).sum();
        let w = sum.width as usize;
        let tot = format!("≈ {}", fmt::bytes(total));
        f.render_widget(
            Paragraph::new(vec![
                Line::styled("─".repeat(w), t.s(t.rule)),
                Line::from(vec![
                    Span::styled("selected", t.dim()),
                    Span::raw(" ".repeat(w.saturating_sub(8 + tot.chars().count()))),
                    Span::styled(tot, t.s(t.green)),
                ]),
            ]),
            sum,
        );

        // Preview of the cursor item.
        let Some(i) = items.get(sel) else { return };
        let block = panel(t, "Preview", i.label.clone());
        let r = inner(&block, right);
        f.render_widget(block, right);
        let mut lines = vec![Line::styled(
            format!("sentry job {} --only {}", i.job.name(), i.key),
            t.dim(),
        )];
        lines.extend(i.preview.iter().map(|l| Line::styled(l.clone(), t.fg())));
        if let Act::Run(c) = &i.act {
            lines.push(Line::raw(""));
            lines.push(Line::styled(format!("$ {}", c.display()), t.dim()));
        }
        if let Some(b) = i.bytes {
            lines.push(Line::styled(format!("≈ {}", fmt::bytes(b)), t.s(t.green)));
        }
        let notes: Vec<&String> = plans
            .iter()
            .filter(|p| p.items.first().is_some_and(|x| x.job == i.job))
            .flat_map(|p| p.notes.iter())
            .collect();
        for n in notes {
            lines.push(Line::styled(format!("! {n}"), t.s(t.yellow)));
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), r);
    }
}

impl Cleanup {
    pub fn ask(&self, v: &View) -> Result<crate::claude::Ask, String> {
        let items = self.items(v);
        let i = items
            .get(self.cur.sel.min(items.len().saturating_sub(1)))
            .ok_or("no cleanup item (plans still loading?)")?;
        let cmd = match &i.act {
            Act::Run(c) => c.display(),
            _ => "nothing to run".into(),
        };
        Ok(crate::claude::Ask::new(
            format!("cleanup · {}", i.label),
            format!(
                "A cleanup item from sentry's dry-run plan:\n{}\njob {}\nsize {}\npreview:\n{}\ncommand: {cmd}",
                i.label,
                i.job.name(),
                i.bytes.map_or("unknown".to_string(), fmt::bytes),
                i.preview
                    .iter()
                    .map(|l| format!("  {l}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            "Is this safe to delete, and what would I lose?",
        ))
    }
}

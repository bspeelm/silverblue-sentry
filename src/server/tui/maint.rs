//! The Maintenance tab: what's pinned or held on purpose, how it stands against upstream, and
//! the deliberate way to change it (assess with Claude, plan with its workflow, or look again
//! later).

use std::collections::BTreeMap;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Wrap};

use super::app::Effect;
use super::tabs::View;
use crate::claude::Ask;
use crate::fmt;
use crate::server::config::{MaintItem, Tier};
use crate::server::maint::eval::{Flag, Status};
use crate::server::maint::plan::{Head, PlanDoc, PlanStatus};
use crate::server::maint::{self, local};
use crate::server::remote::Remote;
use crate::tui::widgets::{self, TableSpec, inner, panel};

/// Items in table order (the config's), filtered.
pub fn rows<'a>(v: &View<'a>) -> Vec<&'a Status> {
    let Some(st) = &v.s.maint.value else {
        return Vec::new();
    };
    st.iter()
        .filter(|s| {
            let flags: Vec<&str> = s.flags.iter().map(|f| f.word()).collect();
            v.matches(&[
                &s.id,
                s.tier.as_str(),
                &flags.join(" "),
                s.pinned.as_deref().unwrap_or(""),
            ])
        })
        .collect()
}

pub fn selected<'a>(v: &View<'a>) -> Option<(&'a Status, &'a MaintItem)> {
    let s = rows(v).get(v.cur).copied()?;
    let it = v.cfg.maintenance.items.iter().find(|i| i.id == s.id)?;
    Some((s, it))
}

fn tier_color(v: &View, t: Tier) -> Color {
    match t {
        Tier::Green => v.t.green,
        Tier::Amber => v.t.yellow,
        Tier::Red => v.t.red,
    }
}

/// The word and colour for an item's state: the most pressing flag.
fn state(v: &View, s: &Status) -> (String, Color) {
    let t = v.t;
    let n = s.newer.len();
    let held = s.has(Flag::Held);
    if v.planning.as_deref() == Some(s.id.as_str()) {
        return ("planning…".into(), t.cyan);
    }
    if let Some(p) = v.plans.get(&s.id) {
        let to = p.head.to.clone().unwrap_or_else(|| "retire".into());
        return match p.head.status {
            PlanStatus::Wait => ("plan: wait".into(), t.dim),
            PlanStatus::Failed => ("plan failed".into(), t.red),
            _ => (
                format!("planned → {to}"),
                if s.has(Flag::Security) { t.red } else { t.mag },
            ),
        };
    }
    if s.has(Flag::Security) {
        (format!("security · {n} newer"), t.red)
    } else if s.has(Flag::Eol) {
        ("end of life".into(), t.red)
    } else if s.has(Flag::Drift) {
        ("drift".into(), t.yellow)
    } else if s.has(Flag::ReviewDue) {
        ("review due".into(), t.yellow)
    } else if s.has(Flag::EolSoon) {
        ("eol soon".into(), t.yellow)
    } else if s.has(Flag::Retire) {
        ("to retire".into(), t.mag)
    } else if s.has(Flag::Behind) && held {
        (format!("held · {n} newer"), t.dim)
    } else if s.has(Flag::Behind) {
        (format!("{n} newer"), t.cyan)
    } else if s.has(Flag::Current) {
        ("current".into(), t.green)
    } else {
        ("unknown".into(), t.dim)
    }
}

/// Something to act on: a security fix or end of life, drift, a review due, a plan, a
/// retirement, or newer versions it isn't held back from.
fn needs_attention(v: &View, s: &Status) -> bool {
    v.plans.contains_key(&s.id)
        || [
            Flag::Security,
            Flag::Eol,
            Flag::EolSoon,
            Flag::Drift,
            Flag::ReviewDue,
            Flag::Retire,
        ]
        .iter()
        .any(|f| s.has(*f))
        || (s.has(Flag::Behind) && !s.has(Flag::Held))
}

/// The count on the tab: security fixes, end of life, drift and reviews due.
pub fn badge(v: &View) -> Option<(String, Color)> {
    let st = v.s.maint.value.as_ref()?;
    let urgent = st
        .iter()
        .filter(|s| s.has(Flag::Security) || s.has(Flag::Eol))
        .count();
    let due = st
        .iter()
        .filter(|s| s.has(Flag::Drift) || s.has(Flag::ReviewDue) || s.has(Flag::EolSoon))
        .count();
    match (urgent, due) {
        (0, 0) => None,
        (0, d) => Some((format!(" {d}"), v.t.yellow)),
        (u, d) => Some((format!(" {}", u + d), v.t.red)),
    }
}

pub fn draw(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let [list_a, detail_a] =
        Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(area);
    let up = v
        .upstream
        .map_or("upstream not looked up (c)".to_string(), |at| {
            format!("upstream {}", fmt::ago(v.secs_since(at)))
        });
    let b = panel(
        t,
        "Maintenance",
        format!(
            "{} items · {up}{}",
            v.cfg.maintenance.items.len(),
            v.inv_note()
        ),
    );
    let r = inner(&b, list_a);
    f.render_widget(b, list_a);
    if v.cfg.maintenance.items.is_empty() {
        f.render_widget(
            Paragraph::new(vec![
                Line::styled("Nothing tracked yet.", t.fg()),
                Line::styled(
                    "Add what you keep at a deliberate version under maintenance: in \
                     server_config.yaml (e opens it): images, held packages, apps, an OS's end of life.",
                    t.dim(),
                ),
            ])
            .wrap(Wrap { trim: false }),
            r,
        );
        return;
    }
    if v.s.maint.value.is_none() {
        let msg = match &v.s.maint.err {
            Some(e) => Line::styled(format!("maintenance: {e}"), t.s(t.red)),
            None => Line::styled("reading what the server has…", t.dim()),
        };
        f.render_widget(Paragraph::new(msg), r);
        return;
    }
    let list = rows(v);
    let cut = |s: Option<&str>, n: usize| -> String {
        let s = s.unwrap_or("-");
        if s.chars().count() > n {
            format!("{}…", s.chars().take(n - 1).collect::<String>())
        } else {
            s.to_string()
        }
    };
    let rows_: Vec<Row> = list
        .iter()
        .map(|s| {
            let (word, c) = state(v, s);
            let running = match (&s.running, &s.pinned) {
                (Some(r), Some(p)) if r == p => "=".to_string(),
                (r, _) => cut(r.as_deref(), 14),
            };
            Row::new(vec![
                Cell::from(s.id.clone()).style(t.fg()),
                // The tier in colour only where it matters now: something to act on.
                Cell::from(s.tier.as_str()).style(if needs_attention(v, s) {
                    t.s(tier_color(v, s.tier))
                } else {
                    t.dim()
                }),
                Cell::from(cut(s.pinned.as_deref(), 16)).style(t.fg()),
                Cell::from(running).style(t.dim()),
                Cell::from(cut(s.latest.as_deref(), 16)).style(t.dim()),
                Cell::from(word).style(t.s(c)),
                Cell::from(s.review_by.map_or(String::new(), |d| d.to_string())).style(t.dim()),
            ])
        })
        .collect();
    widgets::table(
        f,
        r,
        t,
        TableSpec {
            header: vec![
                "Item", "Tier", "Pinned", "Running", "Latest", "State", "Review",
            ],
            widths: vec![
                Constraint::Fill(2),
                Constraint::Length(5),
                Constraint::Fill(2),
                Constraint::Length(14),
                Constraint::Fill(2),
                Constraint::Length(19),
                Constraint::Length(10),
            ],
            rows: rows_,
            selected: Some(v.cur),
        },
    );
    let b = panel(t, "Details", "");
    let r = inner(&b, detail_a);
    f.render_widget(b, detail_a);
    let lines = match selected(v) {
        Some((s, it)) => detail(v, s, it),
        None => vec![Line::styled("nothing matches", t.dim())],
    };
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), r);
}

fn detail(v: &View, s: &Status, it: &MaintItem) -> Vec<Line<'static>> {
    let t = v.t;
    let mut l = vec![Line::from(vec![
        Span::styled(s.id.clone(), t.s(t.cyan)),
        Span::styled(
            format!("  {} tier", s.tier.as_str()),
            t.s(tier_color(v, s.tier)),
        ),
    ])];
    let kv = |k: &str, val: String, c: Color| {
        Line::from(vec![
            Span::styled(format!("{k:<10}"), t.dim()),
            Span::styled(val, t.s(c)),
        ])
    };
    l.push(kv("pinned", s.pinned.clone().unwrap_or("?".into()), t.fg));
    if s.running.is_some() && s.running != s.pinned {
        l.push(kv(
            "running",
            s.running.clone().unwrap_or_default(),
            t.yellow,
        ));
    }
    if let Some(x) = &s.latest {
        l.push(kv("latest", x.clone(), t.fg));
    }
    if let Some(e) = &s.eol {
        l.push(kv(
            "eol",
            format!(
                "{} {}",
                e.cycle,
                e.eol.map_or("no end announced".into(), |d| d.to_string())
            ),
            if s.has(Flag::Eol) { t.red } else { t.fg },
        ));
    }
    if let Some(d) = s.review_by {
        l.push(kv("review", d.to_string(), t.fg));
    }
    if let Some(h) = &it.hold {
        l.push(Line::raw(""));
        l.push(Line::styled("Held because", t.dim()));
        l.push(Line::styled(h.clone(), t.fg()));
    }
    if let Some(c) = &it.constraint {
        l.push(Line::raw(""));
        l.push(Line::styled("Constraint", t.dim()));
        l.push(Line::styled(c.clone(), t.fg()));
    }
    if let Some(r) = &it.retire {
        l.push(Line::raw(""));
        l.push(Line::styled(
            format!(
                "To be retired{}",
                r.replaced_by
                    .as_deref()
                    .map_or(String::new(), |x| format!(", replaced by {x}"))
            ),
            t.s(t.mag),
        ));
    }
    if !s.newer.is_empty() {
        l.push(Line::raw(""));
        l.push(Line::styled(
            format!("Newer ({}), newest first", s.newer.len()),
            t.dim(),
        ));
        for r in s.newer.iter().take(8) {
            l.push(Line::from(vec![
                Span::styled(if r.security { "⚠ " } else { "  " }, t.s(t.red)),
                Span::styled(format!("{:<14}", r.version), t.fg()),
                Span::styled(r.date.clone().unwrap_or_default(), t.dim()),
            ]));
        }
        if s.newer.len() > 8 {
            l.push(Line::styled(
                format!("  … {} more", s.newer.len() - 8),
                t.dim(),
            ));
        }
    }
    if let Some(n) = &s.note {
        l.push(Line::raw(""));
        l.push(Line::styled(n.clone(), t.dim()));
    }
    if let Some(p) = v.plans.get(&s.id) {
        let h = &p.head;
        l.push(Line::raw(""));
        l.push(Line::styled(
            format!(
                "Plan: {} → {} with {} · {}",
                h.from.as_deref().unwrap_or("?"),
                h.to.as_deref().unwrap_or("(retire)"),
                h.workflow,
                h.status.word()
            ),
            t.s(t.mag),
        ));
        if let Some(n) = &h.note {
            l.push(Line::styled(format!("note: {n}"), t.fg()));
        }
        l.push(Line::styled("Enter opens it", t.dim()));
    } else if v.planning.as_deref() == Some(s.id.as_str()) {
        l.push(Line::raw(""));
        l.push(Line::styled(
            "Claude is writing the plan… (Enter watches it)",
            t.s(t.cyan),
        ));
    }
    if let Some(a) =
        v.s.maint_state
            .assessments
            .get(&s.id)
            .filter(|_| !v.plans.contains_key(&s.id))
    {
        l.push(Line::raw(""));
        l.push(Line::styled(
            format!(
                "Assessment{} (L shows it all)",
                a.at.map_or(String::new(), |t| format!(" {}", t.strftime("%Y-%m-%d")))
            ),
            t.dim(),
        ));
        // Its recommendation if it has one, else its start.
        let lines: Vec<&str> = a.text.lines().filter(|x| !x.trim().is_empty()).collect();
        let from = lines
            .iter()
            .position(|x| x.to_lowercase().contains("recommendation"))
            .unwrap_or(0);
        for x in lines.iter().skip(from).take(4) {
            l.push(Line::styled(x.to_string(), t.fg()));
        }
    }
    let hist = maint::history(v.name, &s.id);
    if !hist.is_empty() {
        l.push(Line::raw(""));
        l.push(Line::styled("Changes", t.dim()));
        for c in hist.iter().take(4) {
            l.push(Line::styled(
                format!(
                    "{} {} → {} · {} ({})",
                    c.at.strftime("%Y-%m-%d"),
                    c.from.as_deref().unwrap_or("?"),
                    c.to.as_deref().unwrap_or("?"),
                    c.workflow,
                    c.result
                ),
                t.fg(),
            ));
        }
    }
    l.push(Line::raw(""));
    let mut keys = vec!["A assess"];
    if it.workflow.is_some() || it.retire.as_ref().is_some_and(|r| r.workflow.is_some()) {
        keys.push(if v.plans.contains_key(&s.id) {
            "Enter opens the plan · P plans again"
        } else {
            "p plan"
        });
    }
    keys.extend(["z review later", "e edit config"]);
    l.push(Line::styled(keys.join(" · "), t.dim()));
    l
}

/// The workflow that changes an item: its own, or its retire workflow.
fn workflow_of(it: &MaintItem) -> Option<&str> {
    it.retire
        .as_ref()
        .and_then(|r| r.workflow.as_deref())
        .or(it.workflow.as_deref())
}

/// Keys on the tab.
pub fn key(c: char, v: &View) -> Vec<Effect> {
    let Some((s, it)) = selected(v) else {
        return Vec::new();
    };
    match c {
        'z' => {
            let today = jiff::Zoned::now().date();
            let choices = [30, 90, 180]
                .into_iter()
                .map(|d| {
                    let until = today
                        .checked_add(jiff::Span::new().days(d))
                        .unwrap_or(today);
                    (
                        format!("look again in {d} days ({until})"),
                        vec![Effect::Snooze(s.id.clone(), until)],
                    )
                })
                .collect();
            vec![Effect::Choose(format!("Review {} later", s.id), choices)]
        }
        // A plan already there: say so, rather than quietly replacing it.
        'p' if v.plans.contains_key(&s.id) || v.planning.as_deref() == Some(s.id.as_str()) => {
            let what = match v.plans.get(&s.id) {
                Some(p) => format!(
                    "→ {} · {}",
                    p.head.to.as_deref().unwrap_or("retire"),
                    p.head.status.word()
                ),
                None => "being written".into(),
            };
            vec![Effect::Toast(format!(
                "{} already has a plan ({what}): Enter opens it · P plans again",
                s.id
            ))]
        }
        'p' | 'P' => {
            let Some(wf) = workflow_of(it) else {
                return vec![Effect::Toast(format!(
                    "{} has no workflow: (or retire: workflow:) in server_config.yaml",
                    s.id
                ))];
            };
            let l = local::Local {
                pinned: s.pinned.clone(),
                repo: v
                    .s
                    .maint_local
                    .as_ref()
                    .and_then(|m| m.get(&s.id))
                    .and_then(|x| x.repo.clone()),
                ..Default::default()
            };
            let plan = |target: Option<&str>| {
                vec![Effect::PlanNote(
                    s.id.clone(),
                    PlanDoc {
                        head: Head {
                            item: s.id.clone(),
                            server: v.name.to_string(),
                            from: s.pinned.clone(),
                            to: target.map(|t| maint::version::like_pin(t, s.pinned.as_deref())),
                            workflow: wf.to_string(),
                            vars: local::vars_for(it, &l, target),
                            created: Some(jiff::Timestamp::now()),
                            repo: l.repo.clone(),
                            ..Default::default()
                        },
                        body: String::new(),
                    },
                )]
            };
            if it.retire.is_some() || s.newer.is_empty() {
                return plan(None);
            }
            let choices =
                std::iter::once(("let Claude recommend a version".to_string(), plan(None)))
                    .chain(s.newer.iter().take(8).map(|r| {
                        (
                            format!(
                                "{}{}{}",
                                r.version,
                                r.date
                                    .as_deref()
                                    .map_or(String::new(), |d| format!("  {d}")),
                                if r.security { "  ⚠ security" } else { "" }
                            ),
                            plan(Some(r.version.as_str())),
                        )
                    }))
                    .collect();
            vec![Effect::Choose(
                format!(
                    "Plan: move {} from {} to",
                    s.id,
                    s.pinned.as_deref().unwrap_or("?")
                ),
                choices,
            )]
        }
        // Enter opens the item's plan (or the one being written).
        '\n' if v.plans.contains_key(&s.id) || v.planning.as_deref() == Some(s.id.as_str()) => {
            vec![Effect::PlanOpen(s.id.clone())]
        }
        '\n' => vec![Effect::Toast(format!("no plan for {}: p makes one", s.id))],
        'x' => match v.plans.get(&s.id) {
            Some(p) => vec![Effect::Confirm(super::app::Modal {
                title: "Drop the plan".into(),
                color: v.t.yellow,
                lines: vec![Line::styled(
                    format!(
                        "Drop the plan to move {} to {}? It moves to plans/done/; nothing on the server changes.",
                        s.id,
                        p.head.to.as_deref().unwrap_or("(retire)")
                    ),
                    v.t.fg(),
                )],
                yes: Some(("drop".into(), vec![Effect::PlanDrop(s.id.clone())])),
            })],
            None => vec![Effect::Toast(format!("no plan for {}", s.id))],
        },
        _ => Vec::new(),
    }
}

/// `A` on the tab: an assessment, with release notes from the web and the notes files.
pub fn ask(v: &View, r: &Remote) -> Option<Ask> {
    let (s, it) = selected(v)?;
    Some(Ask::new(
        format!("{} · assess {}", r.name, s.id),
        context(v, r, s, it),
        "Assess moving this item. Read the release notes between the pinned version and the \
         newest (use the web), and the notes files above. Answer in four parts:\n\
         **What changed**: breaking changes, one-way migrations, security fixes, and anything that \
         touches how this server uses it.\n\
         **Does the hold still apply**: is the reason it's held still true?\n\
         **Recommendation**: wait, or which version, and which tier the change really is.\n\
         **Steps**: in the terms of its workflow (what to check before, what to watch after, how \
         to roll back). Don't change anything yourself.",
    ))
}

/// What Claude is told about an item (for `A` and `p`).
pub fn context(v: &View, r: &Remote, s: &Status, it: &MaintItem) -> String {
    let newer: Vec<String> = s
        .newer
        .iter()
        .take(15)
        .map(|r| {
            format!(
                "{}{}{}{}",
                r.version,
                r.date
                    .as_deref()
                    .map_or(String::new(), |d| format!(" ({d})")),
                if r.security {
                    " [notes mention security]"
                } else {
                    ""
                },
                r.url.as_deref().map_or(String::new(), |u| format!(" {u}"))
            )
        })
        .collect();
    let depends: Vec<String> =
        v.s.docker
            .value
            .as_ref()
            .and_then(|d| {
                let svc = it.image.as_ref()?.service.as_ref()?;
                d.containers
                    .iter()
                    .find(|c| c.service.as_deref() == Some(svc.as_str()))
                    .map(|c| format!("container {} ({}, {})", c.name, c.status, c.image))
            })
            .into_iter()
            .collect();
    // This item's own entries; the ledger has everything else.
    let history: Vec<String> = maint::log::for_item(&r.name, &s.id)
        .iter()
        .take(5)
        .map(|e| e.line())
        .collect();
    let ledger = if maint::log::dir(&r.name).join("LOG.md").exists() {
        ledger_path(&r.name)
    } else {
        "none yet (no maintenance has been logged on this server)".into()
    };
    let what = if let Some(img) = &it.image {
        format!(
            "image ({})",
            img.service
                .as_deref()
                .map(|s| format!("compose service {s}"))
                .or(img.container.as_deref().map(|c| format!("container {c}")))
                .unwrap_or_default()
        )
    } else if !it.apt.is_empty() {
        format!("packages {}", it.apt.join(" "))
    } else if it.version_cmd.is_some() {
        "app on the host".into()
    } else {
        "release".into()
    };
    let notes = if v.cfg.maintenance.notes.is_empty() {
        String::new()
    } else {
        format!(
            "\nNotes about this server you may read: {}",
            v.cfg.maintenance.notes.join(", ")
        )
    };
    let ctx = format!(
        "Server `{}`. Maintenance item `{}`: {what}, tier {} (green: routine, amber: has a rollback \
         step, red: can break the server or needs a window).\nsource: {}\npinned: {}\nrunning: {}\n\
         newest upstream: {}\nnewer releases: {}\nheld because: {}\nconstraint: {}\nreview by: {}\n\
         end of life: {}\nworkflow that changes it: {}\nwhat runs it: {}\nthis item in the maintenance log: {}\n\
         maintenance ledger (every run on this server, with a one-line summary and tags each; \
         start there and read the entries that bear on this): {ledger}{notes}",
        r.name,
        s.id,
        s.tier.as_str(),
        it.source.as_deref().unwrap_or("apt / none"),
        s.pinned.as_deref().unwrap_or("?"),
        s.running.as_deref().unwrap_or("?"),
        s.latest.as_deref().unwrap_or("?"),
        if newer.is_empty() {
            "none".into()
        } else {
            newer.join("; ")
        },
        it.hold.as_deref().unwrap_or("-"),
        it.constraint.as_deref().unwrap_or("-"),
        s.review_by.map_or("-".into(), |d| d.to_string()),
        s.eol.as_ref().map_or("-".into(), |e| format!(
            "{} {}",
            e.cycle,
            e.eol.map_or("none announced".into(), |d| d.to_string())
        )),
        workflow_of(it).unwrap_or("none"),
        if depends.is_empty() {
            "-".into()
        } else {
            depends.join("; ")
        },
        if history.is_empty() {
            "none".into()
        } else {
            history.join("; ")
        },
    );
    ctx
}

/// The ledger's path as Claude Code sees it (its permission checks use the real path).
pub fn ledger_path(server: &str) -> String {
    real_path(&maint::log::dir(server).join("LOG.md"))
}

/// A path with its symlinks resolved, even when its end doesn't exist yet (nothing is created).
fn real_path(p: &std::path::Path) -> String {
    let mut base = p.to_path_buf();
    let mut rest = Vec::new();
    while !base.exists() {
        match (base.file_name().map(|n| n.to_owned()), base.parent()) {
            (Some(n), Some(parent)) => {
                rest.push(n);
                base = parent.to_path_buf();
            }
            _ => break,
        }
    }
    let mut real = std::fs::canonicalize(&base).unwrap_or(base);
    for n in rest.into_iter().rev() {
        real.push(n);
    }
    real.display().to_string()
}

/// Notes paths as Claude Code sees them: `~` expanded and symlinks resolved (its permission
/// checks use the real path).
pub fn resolve_notes(notes: &[String]) -> Vec<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    notes
        .iter()
        .map(|n| {
            let p = match n.strip_prefix("~/") {
                Some(rest) => format!("{home}/{rest}"),
                None => n.clone(),
            };
            std::fs::canonicalize(&p)
                .map(|c| c.display().to_string())
                .unwrap_or(p)
        })
        .collect()
}

/// Notes files as Claude Code `Read(…)` permissions (`~/…` as is, `/abs` as `//abs`).
pub fn read_rules(notes: &[String]) -> Vec<String> {
    notes
        .iter()
        .map(|n| match n.strip_prefix('/') {
            Some(abs) => format!("Read(//{abs})"),
            None => format!("Read({n})"),
        })
        .collect()
}

/// Vars a prefilled start shows: the workflow's own, with the item's values as defaults.
pub fn merge_defaults(
    asks: Vec<(String, String, Option<String>)>,
    given: &BTreeMap<String, String>,
) -> Vec<(String, String, Option<String>)> {
    asks.into_iter()
        .map(|(k, p, d)| {
            let d = given.get(&k).cloned().or(d);
            (k, p, d)
        })
        .collect()
}

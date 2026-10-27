//! The Maintenance tab: what to maintain next and why (recommendations, on top), then
//! everything tracked, how it stands against upstream, and the deliberate way to change it
//! (a plan Claude writes, applied with its workflow; or look again later).

use std::collections::BTreeMap;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Wrap};

use super::app::Effect;
use super::tabs::View;
use crate::fmt;
use crate::server::config::{MaintItem, Risk};
use crate::server::maint::eval::{Flag, Status};
use crate::server::maint::plan::{Head, PlanDoc, PlanStatus};
use crate::server::maint::recommend::{self, Action, Level, Rec};
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
                s.risk.as_str(),
                &flags.join(" "),
                s.pinned.as_deref().unwrap_or(""),
            ])
        })
        .collect()
}

/// What to maintain next (filtered like the items).
pub fn recs(v: &View) -> Vec<Rec> {
    let empty = Vec::new();
    let mut r = recommend::recommend(&recommend::Inputs {
        items: &v.cfg.maintenance.items,
        statuses: v.s.maint.value.as_ref().unwrap_or(&empty),
        plans: v.plans,
        found: &v.s.maint_found,
        apt: v.s.apt.value.as_ref(),
        log: &v.s.log,
        cadence: &v.cfg.maintenance.cadence,
        workflows: &v.s.workflows,
        snooze: &v.s.maint_state.snooze,
        now: v.now,
    });
    r.retain(|x| v.matches(&[&x.title, &x.why, x.level.word()]));
    r
}

/// The selected row: a recommendation (they come first) or an item.
pub enum Sel<'a> {
    Rec(Rec),
    Item(&'a Status, &'a MaintItem),
}

pub fn pick<'a>(v: &View<'a>) -> Option<Sel<'a>> {
    let r = recs(v);
    if let Some(x) = r.get(v.cur) {
        return Some(Sel::Rec(x.clone()));
    }
    let s = rows(v).get(v.cur - r.len()).copied()?;
    let it = item_of(v, &s.id)?;
    Some(Sel::Item(s, it))
}

fn item_of<'a>(v: &View<'a>, id: &str) -> Option<&'a MaintItem> {
    v.cfg.maintenance.items.iter().find(|i| i.id == id)
}

fn status_of<'a>(v: &View<'a>, id: &str) -> Option<&'a Status> {
    v.s.maint.value.as_ref()?.iter().find(|s| s.id == id)
}

/// The item the selected row is about.
pub fn selected<'a>(v: &View<'a>) -> Option<(&'a Status, &'a MaintItem)> {
    match pick(v)? {
        Sel::Item(s, it) => Some((s, it)),
        Sel::Rec(r) => {
            let id = r.item?;
            Some((status_of(v, &id)?, item_of(v, &id)?))
        }
    }
}

/// Rows on the tab: recommendations, then items.
pub fn count(v: &View) -> usize {
    recs(v).len() + rows(v).len()
}

/// What the row at `cur` is, to find it again after the list changes: a recommendation's
/// key, or `item:<id>`.
pub fn row_key(v: &View) -> Option<String> {
    match pick(v)? {
        Sel::Rec(r) => Some(format!("rec:{}:{}", r.key, r.title)),
        Sel::Item(s, _) => Some(format!("item:{}", s.id)),
    }
}

/// The row with that key now, if it's still there.
pub fn row_with(v: &View, key: &str) -> Option<usize> {
    if let Some(id) = key.strip_prefix("item:") {
        return row_of(v, id);
    }
    recs(v)
        .iter()
        .position(|r| format!("rec:{}:{}", r.key, r.title) == key)
}

/// Where an item's row is (for jumping to it).
pub fn row_of(v: &View, id: &str) -> Option<usize> {
    Some(recs(v).len() + rows(v).iter().position(|s| s.id == id)?)
}

fn level_color(v: &View, l: Level) -> Color {
    match l {
        Level::Now => v.t.red,
        Level::Soon => v.t.yellow,
        Level::Routine => v.t.cyan,
        Level::Tidy => v.t.dim,
    }
}

/// What Enter does on a recommendation, in words.
fn action_words(a: &Action) -> String {
    match a {
        Action::Plan(id) => format!("Enter: Claude writes a plan for {id}"),
        Action::OpenPlan(id) => format!("Enter: open the plan for {id}"),
        Action::Run(wf) => format!("Enter: start {wf}"),
        Action::Track(_) => "Enter or t: track it · x: ignore it".into(),
        Action::Remove(id) => format!("Enter: stop tracking {id}"),
        Action::Look(_) => "Enter: go to the item".into(),
    }
}

fn risk_color(v: &View, t: Risk) -> Color {
    match t {
        Risk::Low => v.t.green,
        Risk::Medium => v.t.yellow,
        Risk::High => v.t.red,
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
    v.s.maint.value.as_ref()?;
    let r = recs(v);
    let now = r.iter().filter(|x| x.level == Level::Now).count();
    let soon = r.iter().filter(|x| x.level == Level::Soon).count();
    match (now, soon) {
        (0, 0) => None,
        (0, n) => Some((format!(" {n}"), v.t.yellow)),
        (n, m) => Some((format!(" {}", n + m), v.t.red)),
    }
}

pub fn draw(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let [list_a, detail_a] =
        Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(area);
    // What to maintain next, on top; everything tracked below.
    let recs = if v.s.maint.value.is_some() {
        recs(v)
    } else {
        Vec::new()
    };
    let rec_h = (recs.len().clamp(1, 10) + 3) as u16;
    let [rec_a, list_a] =
        Layout::vertical([Constraint::Length(rec_h), Constraint::Fill(1)]).areas(list_a);
    draw_recs(f, rec_a, v, &recs);
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
                // The risk in colour only where it matters now: something to act on.
                Cell::from(s.risk.as_str()).style(if needs_attention(v, s) {
                    t.s(risk_color(v, s.risk))
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
                "Item", "Risk", "Pinned", "Running", "Latest", "State", "Review",
            ],
            widths: vec![
                Constraint::Fill(2),
                Constraint::Length(6),
                Constraint::Fill(2),
                Constraint::Length(14),
                Constraint::Fill(2),
                Constraint::Length(19),
                Constraint::Length(10),
            ],
            rows: rows_,
            selected: v.cur.checked_sub(recs.len()),
        },
    );
    let b = panel(t, "Details", "");
    let r = inner(&b, detail_a);
    f.render_widget(b, detail_a);
    let lines = match pick(v) {
        Some(Sel::Item(s, it)) => detail(v, s, it),
        Some(Sel::Rec(x)) => {
            let mut l = vec![
                Line::from(vec![
                    Span::styled(
                        format!(" {} ", x.level.word()),
                        ratatui::style::Style::new()
                            .fg(t.ink)
                            .bg(level_color(v, x.level)),
                    ),
                    Span::styled(format!(" {}", x.title), t.fg()),
                ]),
                Line::raw(""),
                Line::styled(x.why.clone(), t.fg()),
                Line::raw(""),
                Line::styled(action_words(&x.action), t.s(t.cyan)),
                Line::styled("z: look again later", t.dim()),
            ];
            if let Some((s, it)) = x
                .item
                .as_deref()
                .and_then(|id| Some((status_of(v, id)?, item_of(v, id)?)))
            {
                l.push(Line::raw(""));
                l.extend(detail(v, s, it));
            }
            l
        }
        None => vec![Line::styled("nothing matches", t.dim())],
    };
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), r);
}

fn draw_recs(f: &mut Frame, area: Rect, v: &View, recs: &[Rec]) {
    let t = v.t;
    let b = panel(
        t,
        "Recommended",
        if v.s.maint.value.is_none() {
            String::new()
        } else {
            match &v.s.review {
                Some(r) => format!(
                    "{} · last review {}: R opens it",
                    recs.len(),
                    r.head
                        .updated
                        .or(r.head.created)
                        .map_or("?".into(), |u| fmt::ago(v.secs_since(u)))
                ),
                None => format!("{} · R reviews it all with Claude", recs.len()),
            }
        },
    );
    let r = inner(&b, area);
    f.render_widget(b, area);
    if v.s.maint.value.is_none() {
        f.render_widget(Paragraph::new(Line::styled("reading…", t.dim())), r);
        return;
    }
    if recs.is_empty() {
        f.render_widget(
            Paragraph::new(Line::styled(
                "✓ nothing to maintain right now",
                t.s(t.green),
            )),
            r,
        );
        return;
    }
    let rows: Vec<Row> = recs
        .iter()
        .map(|x| {
            Row::new(vec![
                Cell::from(x.level.word()).style(t.s(level_color(v, x.level))),
                Cell::from(x.title.clone()).style(t.fg()),
                Cell::from(x.why.clone()).style(t.dim()),
            ])
        })
        .collect();
    widgets::table(
        f,
        r,
        t,
        TableSpec {
            header: vec!["", "What", "Why"],
            widths: vec![
                Constraint::Length(8),
                Constraint::Fill(3),
                Constraint::Fill(4),
            ],
            rows,
            selected: (v.cur < recs.len()).then_some(v.cur),
        },
    );
}

fn detail(v: &View, s: &Status, it: &MaintItem) -> Vec<Line<'static>> {
    let t = v.t;
    let mut l = vec![Line::from(vec![
        Span::styled(s.id.clone(), t.s(t.cyan)),
        Span::styled(
            format!("  {} risk", s.risk.as_str()),
            t.s(risk_color(v, s.risk)),
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
    let mut keys = Vec::new();
    if it.workflow.is_some() || it.retire.as_ref().is_some_and(|r| r.workflow.is_some()) {
        keys.push(if v.plans.contains_key(&s.id) {
            "Enter opens the plan · P plans again"
        } else {
            "p: Claude plans it"
        });
    }
    keys.extend(["z review later", "v its log", "e edit config"]);
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

/// Keys on the tab: on a recommendation, Enter does what it recommends; the item keys work
/// on the item it's about.
pub fn key(c: char, v: &View) -> Vec<Effect> {
    match pick(v) {
        Some(Sel::Rec(r)) => rec_key(c, v, r),
        Some(Sel::Item(s, it)) => item_key(c, v, s, it),
        None => Vec::new(),
    }
}

fn later(key: &str, what: &str) -> Vec<Effect> {
    let today = jiff::Zoned::now().date();
    let choices = [7, 30, 90]
        .into_iter()
        .map(|d| {
            let until = today
                .checked_add(jiff::Span::new().days(d))
                .unwrap_or(today);
            (
                format!("look again in {d} days ({until})"),
                vec![Effect::Snooze(key.to_string(), until)],
            )
        })
        .collect();
    vec![Effect::Choose(format!("{what}: later"), choices)]
}

fn rec_key(c: char, v: &View, r: Rec) -> Vec<Effect> {
    let found = &v.s.maint_found;
    match (c, &r.action) {
        ('\n', Action::Plan(id)) => match status_of(v, id).zip(item_of(v, id)) {
            Some((s, it)) => item_key('P', v, s, it),
            None => Vec::new(),
        },
        ('\n', Action::OpenPlan(id)) => vec![Effect::PlanOpen(id.clone())],
        ('\n', Action::Run(wf)) => vec![Effect::StartWorkflow(wf.clone())],
        ('\n' | 't', Action::Track(n)) => match found.candidates.get(*n) {
            Some(c) => vec![Effect::Track(c.item.clone())],
            None => Vec::new(),
        },
        ('x', Action::Track(n)) => match found.candidates.get(*n) {
            Some(c) => vec![Effect::Ignore(c.key.clone(), c.item.id.clone())],
            None => Vec::new(),
        },
        ('\n' | 'x', Action::Remove(id)) => vec![Effect::Untrack(id.clone())],
        ('\n', Action::Look(id)) if !id.is_empty() => vec![Effect::MaintJump(id.clone())],
        ('z', _) => later(&r.key, &r.title),
        // Plan keys work on the item the recommendation is about.
        ('p' | 'P' | 'x', _) => match r
            .item
            .as_deref()
            .and_then(|id| Some((status_of(v, id)?, item_of(v, id)?)))
        {
            Some((s, it)) => item_key(c, v, s, it),
            None => Vec::new(),
        },
        _ => Vec::new(),
    }
}

fn item_key(c: char, v: &View, s: &Status, it: &MaintItem) -> Vec<Effect> {
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

/// What a review is given: every item's standing, the rules' recommendations, what
/// discovery found, updates and reboots waiting, cadences, the ledger and the notes.
pub fn review_context(v: &View, r: &Remote) -> String {
    let mut s = format!("Server `{}`.\n\nTracked items:\n", r.name);
    for st in rows(v) {
        let it = item_of(v, &st.id);
        let flags: Vec<&str> = st.flags.iter().map(|f| f.word()).collect();
        s.push_str(&format!(
            "- {} ({} risk): pinned {}, running {}, newest {} [{}]{}{}{}{}{}\n",
            st.id,
            st.risk.as_str(),
            st.pinned.as_deref().unwrap_or("?"),
            st.running.as_deref().unwrap_or("?"),
            st.latest.as_deref().unwrap_or("?"),
            flags.join(", "),
            it.and_then(|i| i.source.as_deref())
                .map_or(String::new(), |x| format!("; source {x}")),
            it.and_then(|i| i.hold.as_deref())
                .map_or(String::new(), |x| format!("; held because: {x}")),
            it.and_then(|i| i.constraint.as_deref())
                .map_or(String::new(), |x| format!("; constraint: {x}")),
            st.review_by
                .map_or(String::new(), |d| format!("; review by {d}")),
            v.plans.get(&st.id).map_or(String::new(), |p| format!(
                "; has a plan → {} ({})",
                p.head.to.as_deref().unwrap_or("retire"),
                p.head.status.word()
            )),
        ));
    }
    s.push_str("\nWhat sentry-server's rules recommend:\n");
    for x in recs(v) {
        s.push_str(&format!("- [{}] {}: {}\n", x.level.word(), x.title, x.why));
    }
    if let Some(a) = &v.s.apt.value {
        s.push_str(&format!(
            "\nPackages: {} update(s) waiting; held back: {}; reboot {}.\n",
            a.upgrades.len(),
            if a.kept_back.is_empty() {
                "none".into()
            } else {
                a.kept_back.join(" ")
            },
            a.reboot_since.map_or("not required".into(), |t| format!(
                "required for {} day(s) (running {}, newest {})",
                (a.now - t) / 86_400,
                a.running_kernel,
                a.newest_kernel.as_deref().unwrap_or("?")
            ))
        ));
    }
    if !v.cfg.maintenance.cadence.is_empty() {
        let c: Vec<String> = v
            .cfg
            .maintenance
            .cadence
            .iter()
            .map(|(k, d)| format!("{k} every {} day(s)", d.0.as_secs() / 86_400))
            .collect();
        s.push_str(&format!("Routine workflows: {}.\n", c.join(", ")));
    }
    let ledger = if maint::log::dir(&r.name).join("LOG.md").exists() {
        ledger_path(&r.name)
    } else {
        "none yet (no maintenance has been logged on this server)".into()
    };
    s.push_str(&format!(
        "\nMaintenance ledger (start there, then read the entries that bear on this): {ledger}\n"
    ));
    if !v.cfg.maintenance.notes.is_empty() {
        s.push_str(&format!(
            "Notes about this server you may read: {}\n",
            v.cfg.maintenance.notes.join(", ")
        ));
    }
    s
}

/// What Claude is told about an item (for its plan).
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
        "Server `{}`. Maintenance item `{}`: {what}, risk {} (low: routine; medium: have a rollback \
         ready; high: can break the server or can't be undone, needs a backup and a window).\nsource: {}\npinned: {}\nrunning: {}\n\
         newest upstream: {}\nnewer releases: {}\nheld because: {}\nconstraint: {}\nreview by: {}\n\
         end of life: {}\nworkflow that changes it: {}\nwhat runs it: {}\nthis item in the maintenance log: {}\n\
         maintenance ledger (every run on this server, with a one-line summary and tags each; \
         start there and read the entries that bear on this): {ledger}{notes}",
        r.name,
        s.id,
        s.risk.as_str(),
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

//! The Maintenance screen: what to maintain next and why (recommendations, on top), then
//! everything tracked, how it stands against upstream, and the deliberate way to change it
//! (a plan Claude writes, applied with its workflow; or look again later).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Wrap};

use super::View;
use crate::config::{MaintItem, Risk};
use crate::maint::eval::{Flag, Status};
use crate::maint::plan::{Head, PlanDoc, PlanStatus};
use crate::maint::recommend::{self, Action, Level, Rec};
use crate::maint::{self, local};
use crate::remote::Remote;
use crate::tui::target::{Effect, Modal, Own};
use sentry_core::fmt;
use sentry_core::tui::maintlist::{self, Dismiss, Verbs};
use sentry_core::tui::reportview::ReportView;
use sentry_core::tui::widgets::{self, TableSpec, inner, panel};

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

/// What to maintain next: what's due or urgent (everything with `o`), filtered like the items.
pub fn recs(v: &View) -> Vec<Rec> {
    let mut r = sentry_core::maint::rec::needed(every_rec(v), v.everything).0;
    r.retain(|x| v.matches(&[&x.title, &x.why, x.level.word()]));
    r
}

/// How many recommendations wait, not shown (`o` shows them).
pub fn waiting(v: &View) -> usize {
    sentry_core::maint::rec::needed(every_rec(v), v.everything).1
}

/// Which row here is already about the subject of one of the security audit's items:
/// the updates waiting, the reboot, an item that is behind, a container's socket.
fn audit_same(i: &sentry_core::secaudit::Item, recs: &[Rec]) -> Option<usize> {
    let what = i.id.split(':').nth(1).unwrap_or("");
    let last = i.id.rsplit(':').next().unwrap_or("");
    let key = |f: &dyn Fn(&str) -> bool| recs.iter().position(|r| f(&r.key));
    match what {
        // The updates waiting: their own row, or the routine run that takes them in.
        "os" => key(&|k| k.ends_with(":updates") || k.starts_with("finding:srv:updates")).or_else(
            || {
                recs.iter().position(|r| match &r.action {
                    Action::Run(wf) => wf == "apt-maintenance",
                    Action::Task(_) => r.key.contains("apt-maintenance"),
                    _ => false,
                })
            },
        ),
        "reboot" => key(&|k| k == "reboot" || k == "finding:srv:reboot-required"),
        "app" => recs
            .iter()
            .position(|r| r.item.as_deref() == Some(last) || r.key == last),
        "ctr" => key(&|k| k == format!("finding:srv:docker-sock:{last}")),
        "watch" => key(&|k| k.starts_with("finding:srv:crowdsec:")),
        _ => None,
    }
}

/// Every recommendation there is, whatever is shown: the server's own, then the security
/// audit's items that are this server's alone.
pub fn every_rec(v: &View) -> Vec<Rec> {
    sentry_core::maint::rec::with_audit(
        own_recs(v),
        &v.sh.sec,
        &v.sh.later,
        v.now.to_zoned(jiff::tz::TimeZone::UTC).date(),
        audit_same,
        Action::Security,
    )
}

fn own_recs(v: &View) -> Vec<Rec> {
    let empty = Vec::new();
    recommend::recommend(&recommend::Inputs {
        items: &v.cfg.maintenance.items,
        statuses: v.s.maint.value.as_ref().unwrap_or(&empty),
        plans: v.plans,
        found: &v.s.maint_found,
        apt: v.s.apt.value.as_ref(),
        log: &v.sh.log,
        workflows: &v.sh.workflows,
        snooze: &v.sh.later,
        now: v.now,
        findings: report(v).map_or(&[][..], |r| &r.findings[..]),
        audited: report(v).and_then(|r| r.snapshot.taken_at),
        tasks: &all_tasks(v),
    })
}

/// Every task that applies: `tasks.toml`'s and `maintenance.cadence`.
pub fn all_tasks(v: &View) -> Vec<sentry_core::maint::tasks::Task> {
    sentry_core::maint::tasks::effective(&v.sh.tasks, maint::cadence_tasks(v.cfg, &v.sh.workflows))
}

/// The latest audit report, when there is one.
fn report<'a>(v: &View<'a>) -> Option<&'a crate::audit::Report> {
    v.s.report.value.as_ref()?.as_deref()
}

/// A finding of the latest audit, by id.
pub fn finding<'a>(v: &View<'a>, id: &str) -> Option<&'a sentry_core::finding::Finding> {
    report(v)?.findings.iter().find(|f| f.id == id)
}

/// A view over the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sub {
    /// The audit report (`F`).
    Report,
}

impl Sub {
    pub fn title(self) -> &'static str {
        match self {
            Sub::Report => "Audit report",
        }
    }
}

/// Maintenance's own state: the cursor, the row it's on (kept when the list changes), and
/// the view over it, as sentry's has.
#[derive(Default)]
pub struct Maint {
    pub cur: sentry_core::tui::Cursor,
    /// The row selected ([`row_key`]).
    pub sel: Option<String>,
    /// A recommendation to select once it's there (its key starts with this).
    pub find: Option<String>,
    pub view: Option<Sub>,
    pub report: ReportView,
    /// The rows ticked for a series (Space), by key.
    pub ticks: maintlist::Ticks,
}

/// How a series takes care of a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeriesKind {
    /// An apply session for this finding.
    Finding(String),
    /// An apply session for the row (a task done by hand, an item: on its ready plan when
    /// it has one, else from its research).
    Apply,
    /// A run of this workflow.
    Workflow(String),
    Audit,
}

/// What a series does for this row (None: Enter does it by itself, it can't be ticked).
pub fn series_kind(v: &View, x: &Rec) -> Option<SeriesKind> {
    use sentry_core::maint::tasks::Do;
    let claude = sentry_core::claude::available();
    let item = || claude.then_some(SeriesKind::Apply);
    match &x.action {
        Action::Fix(id) if claude => Some(SeriesKind::Finding(id.clone())),
        Action::Plan(_) | Action::OpenPlan(_) => item(),
        Action::Run(wf) => Some(SeriesKind::Workflow(wf.clone())),
        Action::Audit => Some(SeriesKind::Audit),
        Action::Task(id) => match all_tasks(v).into_iter().find(|t| &t.id == id)?.action() {
            Do::Run(wf) => Some(SeriesKind::Workflow(wf)),
            Do::Plan(_) => item(),
            Do::Audit => Some(SeriesKind::Audit),
            Do::ByHand if claude => Some(SeriesKind::Apply),
            _ => None,
        },
        // Tracking, untracking and looking are one key each.
        _ => None,
    }
}

/// How many of the rows there are ticked.
pub fn ticked(v: &View, ticks: &maintlist::Ticks) -> usize {
    if ticks.is_empty() {
        return 0;
    }
    every_rec(v)
        .iter()
        .filter(|r| ticks.contains(&r.key))
        .count()
}

/// A plan to be written for an item: to `target`, or (None) the version Claude recommends.
pub fn plan_doc(v: &View, s: &Status, it: &MaintItem, target: Option<&str>) -> PlanDoc {
    // No workflow: a plan done by hand (every step a command the user runs).
    let wf = workflow_of(it).unwrap_or("");
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
    }
}

impl Maint {
    pub fn handle(
        &mut self,
        a: sentry_core::tui::keys::Action,
        v: &View,
        _r: &Remote,
    ) -> Vec<Effect> {
        use crate::tui::data::Kind;
        use sentry_core::tui::keys::Action as A;
        if self.view.is_some() {
            if a == A::Esc {
                self.view = None;
                return Vec::new();
            }
            return super::report::handle(&mut self.report, a, v);
        }
        // A key on the list: whatever was to be found has been, or isn't wanted any more.
        self.find = None;
        match a {
            A::Refresh => vec![Own::fetch(Kind::Maint), Own::fetch(Kind::Report)],
            // Check everything: audit the server and look upstream up again.
            A::Check => vec![
                Own::fetch(Kind::Audit),
                Own::fetch(Kind::Upstream),
                Effect::Toast("auditing the server and looking up newer versions…".into()),
            ],
            // Ticks: Space the row, a every row that can be, Esc none.
            A::Char(' ') => match pick(v) {
                Some(Sel::Rec(r)) if series_kind(v, &r).is_some() => {
                    maintlist::tick(&mut self.ticks, &r.key);
                    Vec::new()
                }
                _ => vec![Effect::Toast(maintlist::NOT_IN_A_SERIES.into())],
            },
            A::Char('a') => {
                let can = recs(v)
                    .iter()
                    .filter(|r| series_kind(v, r).is_some())
                    .map(|r| r.key.clone())
                    .collect();
                maintlist::tick_all(&mut self.ticks, can);
                Vec::new()
            }
            A::Esc => {
                self.ticks.clear();
                Vec::new()
            }
            // With rows ticked, Enter does those, one after another.
            A::Enter => {
                let rows: Vec<(String, String)> = every_rec(v)
                    .into_iter()
                    .filter(|r| self.ticks.contains(&r.key))
                    .map(|r| (r.key, r.title))
                    .collect();
                if rows.is_empty() {
                    self.ticks.clear();
                    key('\n', v)
                } else {
                    vec![Effect::SeriesStart(rows)]
                }
            }
            A::Char(c @ ('z' | 'p' | 'P' | 'x' | 't' | 'd' | 'm' | 'B')) => key(c, v),
            // A task: how often it recurs; anything else: the config, where items are.
            A::Char('e') => match key('e', v) {
                e if e.is_empty() => vec![Effect::Edit(crate::config::path())],
                e => e,
            },
            A::Char('F') => self.open_report(),
            A::Char('R') => vec![Effect::ReviewOpen],
            A::Char('o') => vec![Effect::Everything],
            A::Char('w') => vec![Effect::Goto(sentry_core::tui::ScreenId::Upgrade)],
            A::Char('v') => vec![Effect::LogOpen(selected(v).map(|(s, _)| s.id.clone()))],
            _ => Vec::new(),
        }
    }

    /// `F`, `:audit`: the audit report over the list; its reports are read from disk.
    pub fn open_report(&mut self) -> Vec<Effect> {
        self.view = Some(Sub::Report);
        self.report = ReportView::default();
        vec![Own::fetch(crate::tui::data::Kind::Report)]
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let Some(s) = self.view else {
            return draw(f, area, v, &self.ticks);
        };
        let t = v.t;
        let [head, body] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!(" Maintenance › {} ", s.title()), t.s(t.cyan)),
                Span::styled(" Esc back", t.dim()),
            ])),
            head,
        );
        match s {
            Sub::Report => super::report::draw(&mut self.report, f, body, v),
        }
    }

    /// The list changed under the cursor: put it back on the row it was on.
    pub fn keep(&mut self, v: &View) {
        if let Some(prefix) = &self.find
            && let Some(i) = recs(v).iter().position(|r| r.key.starts_with(prefix))
        {
            self.find = None;
            return self.select(i, row_key_at(v, i));
        }
        if let Some(key) = &self.sel
            && let Some(i) = row_with(v, key)
        {
            self.cur.sel = i;
        }
    }

    /// Select a row, by where it is and what it is.
    pub fn select(&mut self, i: usize, key: Option<String>) {
        self.cur.sel = i;
        self.sel = key;
    }
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

pub fn item_of<'a>(v: &View<'a>, id: &str) -> Option<&'a MaintItem> {
    v.cfg.maintenance.items.iter().find(|i| i.id == id)
}

pub fn status_of<'a>(v: &View<'a>, id: &str) -> Option<&'a Status> {
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

/// Rows on the screen: recommendations, then items.
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

/// The key of the row at index `i` (after a jump).
pub fn row_key_at(v: &View, i: usize) -> Option<String> {
    recs(v).get(i).map(|r| format!("rec:{}:{}", r.key, r.title))
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

/// The keys the selected row takes besides Enter (the key bar shows only these).
pub fn verbs(v: &View) -> Verbs {
    let mut vb = row_verbs(v);
    if let Some(Sel::Rec(r)) = pick(v) {
        vb.series = series_kind(v, &r).is_some();
    }
    vb
}

fn row_verbs(v: &View) -> Verbs {
    let planned = |id: &str| v.plans.contains_key(id);
    let item = |id: &str, enter: &'static str| Verbs {
        enter,
        plan: true,
        planned: planned(id),
        dismiss: v.plans.contains_key(id).then_some(Dismiss::DropPlan),
        ..Default::default()
    };
    let only = |enter: &'static str| Verbs {
        enter,
        ..Default::default()
    };
    match pick(v) {
        None => Verbs::default(),
        Some(Sel::Item(s, it)) => item(&s.id, item_enter(v, s, it).word()),
        Some(Sel::Rec(r)) => match &r.action {
            Action::Track(_) => Verbs {
                track: true,
                dismiss: Some(Dismiss::Ignore),
                ..only("track")
            },
            Action::Remove(_) => Verbs {
                dismiss: Some(Dismiss::Untrack),
                ..only("untrack")
            },
            Action::Fix(_) => Verbs {
                dismiss: Some(Dismiss::Expected),
                like: true,
                ..only("fix")
            },
            Action::Task(id) => {
                let by_hand = all_tasks(v)
                    .iter()
                    .any(|t| &t.id == id && t.action() == sentry_core::maint::tasks::Do::ByHand);
                Verbs {
                    done: true,
                    every: true,
                    manual: by_hand,
                    dismiss: Some(Dismiss::Remove),
                    ..only(if by_hand && sentry_core::claude::available() {
                        "with Claude"
                    } else {
                        "do it"
                    })
                }
            }
            Action::Audit => only("audit"),
            Action::Security(id) => only(
                if v.sh.sec.iter().any(|i| &i.id == id && i.question.is_some()) {
                    "answer"
                } else {
                    "fix"
                },
            ),
            Action::Run(_) => match r.item.as_deref() {
                Some(id) => item(id, "start"),
                None => only("start"),
            },
            Action::Plan(id) => item(id, "with Claude"),
            Action::OpenPlan(id) => item(id, "apply the plan"),
            Action::Look(id) if !id.is_empty() => item(id, "go to item"),
            Action::Look(_) => only("details"),
        },
    }
}

/// What Enter does on an item's own row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemEnter {
    /// It has a plan ready: its session opens on it, to approve.
    OpenPlan,
    /// There are newer versions, or it's to retire: its session, from the research.
    Plan,
    /// Nothing to do to it: what was done to it.
    Log,
}

impl ItemEnter {
    fn word(self) -> &'static str {
        match self {
            ItemEnter::OpenPlan => "apply the plan",
            ItemEnter::Plan => "with Claude",
            ItemEnter::Log => "its log",
        }
    }
}

fn item_enter(v: &View, s: &Status, it: &MaintItem) -> ItemEnter {
    let ready = v
        .plans
        .get(&s.id)
        .is_some_and(|p| p.head.status == PlanStatus::Ready);
    if ready {
        ItemEnter::OpenPlan
    } else if !s.newer.is_empty() || it.retire.is_some() {
        ItemEnter::Plan
    } else {
        ItemEnter::Log
    }
}

/// What Enter does on a recommendation, in words.
fn action_words(a: &Action) -> String {
    match a {
        Action::Plan(id) => {
            format!(
                "Enter: Claude looks into {id}, then shows its plan (nothing changes before you approve it)"
            )
        }
        Action::OpenPlan(id) => format!("Enter: the plan for {id}, to approve (p reads it)"),
        Action::Run(wf) => format!("Enter: start {wf}"),
        Action::Track(_) => "Enter: track it".into(),
        Action::Remove(id) => format!("Enter: stop tracking {id}"),
        Action::Look(_) => "Enter: go to the item".into(),
        Action::Fix(_) => "Enter: ask Claude how to fix it".into(),
        Action::Audit => "Enter: audit the server now".into(),
        Action::Security(_) => {
            "From the security audit (S shows it). Enter: a session with Claude that fixes it, or your answer where only you know".into()
        }
        Action::Task(_) => "A task: Enter does it".into(),
    }
}

/// What Enter does on a task, in words.
fn task_words(task: &sentry_core::maint::tasks::Task) -> String {
    use sentry_core::maint::tasks::Do;
    match task.action() {
        Do::Run(wf) => format!("Enter starts {wf}; it's done when the run ends well."),
        Do::Plan(id) => format!("Enter: Claude plans {id}; it's done when {id}'s change is."),
        Do::Audit => "Enter audits now; it's done with the audit.".into(),
        Do::Job(j) => format!("{j} is one of sentry's jobs (a desktop's): d marks it done."),
        Do::ByHand => "By hand: Enter works it out with Claude (it plans, sentry applies).".into(),
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
    } else if s.has(Flag::Retired) {
        ("retired".into(), t.dim)
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

/// The count on the strip: security fixes, end of life, drift and reviews due.
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

pub fn draw(f: &mut Frame, area: Rect, v: &View, ticks: &maintlist::Ticks) {
    let t = v.t;
    // What to maintain next, on top; everything tracked below. The panels are sentry's.
    let recs = if v.s.maint.value.is_some() {
        recs(v)
    } else {
        Vec::new()
    };
    let (rec_a, list_a, detail_a) = maintlist::split(area, recs.len());
    draw_recs(f, rec_a, v, &recs, ticks);
    draw_details(f, detail_a, v);
    let up = v
        .upstream
        .map_or("upstream not looked up yet".to_string(), |at| {
            format!("upstream {}", fmt::ago(v.secs_since(at)))
        });
    let b = panel(
        t,
        "Items",
        format!("{} · {up}{}", v.cfg.maintenance.items.len(), v.inv_note()),
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
    // Narrow: what matters most, as many columns as fit.
    let cols: &[usize] = match r.width {
        w if w >= 72 => &[0, 1, 2, 3, 4, 5, 6],
        w if w >= 50 => &[0, 1, 2, 5],
        _ => &[0, 5],
    };
    let headers = [
        "Item", "Risk", "Pinned", "Running", "Latest", "State", "Review",
    ];
    let widths = [
        Constraint::Fill(2),
        Constraint::Length(6),
        Constraint::Fill(2),
        Constraint::Length(14),
        Constraint::Fill(2),
        Constraint::Length(19),
        Constraint::Length(10),
    ];
    let rows_: Vec<Row> = list
        .iter()
        .map(|s| {
            let (word, c) = state(v, s);
            let running = match (&s.running, &s.pinned) {
                (Some(r), Some(p)) if r == p => "=".to_string(),
                (r, _) => cut(r.as_deref(), 14),
            };
            let cells = [
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
            ];
            Row::new(cols.iter().map(|i| cells[*i].clone()).collect::<Vec<_>>())
        })
        .collect();
    widgets::table(
        f,
        r,
        t,
        TableSpec {
            header: cols.iter().map(|i| headers[*i]).collect(),
            widths: cols.iter().map(|i| widths[*i]).collect(),
            rows: rows_,
            selected: v.cur.checked_sub(recs.len()),
        },
    );
}

/// The Details panel: the selected recommendation or item.
fn draw_details(f: &mut Frame, detail_a: Rect, v: &View) {
    let t = v.t;
    let b = panel(t, "Details", "");
    let r = inner(&b, detail_a);
    f.render_widget(b, detail_a);
    let lines = match pick(v) {
        Some(Sel::Item(s, it)) => detail(v, s, it),
        Some(Sel::Rec(x)) => {
            let mut l = maintlist::detail_head(t, &x, r.width as usize);
            l.push(Line::styled(action_words(&x.action), t.s(t.cyan)));
            if let Some((s, it)) = x
                .item
                .as_deref()
                .and_then(|id| Some((status_of(v, id)?, item_of(v, id)?)))
            {
                l.push(Line::raw(""));
                l.extend(detail(v, s, it));
            }
            // Updates and the reboot: what's waiting, as the old Updates tab showed it.
            if x.key.starts_with("wf:apt-maintenance") || x.key == "reboot" {
                l.push(Line::raw(""));
                l.extend(super::updates_lines(v));
            }
            if let Action::Task(id) = &x.action
                && let Some(task) = all_tasks(v).into_iter().find(|t| &t.id == id)
            {
                l.push(Line::raw(""));
                l.push(Line::styled(task_words(&task), t.fg()));
                l.push(Line::styled(
                    format!(
                        "{} · {}",
                        task.when(),
                        match &task.review {
                            Some(r) => format!("from the review {r}"),
                            None => format!("from {}", task.source.word()),
                        }
                    ),
                    t.dim(),
                ));
                if !task.steps.trim().is_empty() {
                    l.push(Line::raw(""));
                    l.extend(sentry_core::tui::docview::markdown(t, &task.steps));
                }
            }
            if let Action::Fix(id) = &x.action
                && let Some(f) = finding(v, id)
            {
                l.push(Line::raw(""));
                l.extend(super::report::finding_lines(t, f, r.width as usize));
            }
            // What the last audit couldn't check, beside its findings.
            if (matches!(x.action, Action::Fix(_)) || x.key == "audit")
                && let Some(Some(rep)) = v.s.report.value.as_ref()
                && !rep.snapshot.errors.is_empty()
            {
                l.push(Line::raw(""));
                l.push(Line::styled("The last audit didn't check:", t.dim()));
                for (sec, e) in &rep.snapshot.errors {
                    l.push(Line::styled(format!("{sec}: {e}"), t.dim()));
                }
            }
            l
        }
        None => vec![Line::styled("nothing matches", t.dim())],
    };
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), r);
}

fn draw_recs(f: &mut Frame, area: Rect, v: &View, recs: &[Rec], ticks: &maintlist::Ticks) {
    let t = v.t;
    let note = if v.s.maint.value.is_none() {
        String::new()
    } else {
        format!(
            "{} · {}",
            sentry_core::maint::rec::note(recs.len(), ticked(v, ticks), waiting(v)),
            match report(v).and_then(|r| r.snapshot.taken_at) {
                Some(at) => format!("audited {}", fmt::ago(v.secs_since(at))),
                None => "no audit yet".into(),
            }
        )
    };
    let empty = if v.s.maint.value.is_none() {
        "reading…".to_string()
    } else if v.filter.is_some() {
        maintlist::NO_MATCH.to_string()
    } else {
        maintlist::empty(waiting(v))
    };
    let empty = (empty.as_str(), t.dim());
    maintlist::draw(
        f,
        area,
        t,
        recs,
        maintlist::List {
            note,
            selected: (v.cur < recs.len()).then_some(v.cur),
            empty,
            ticks,
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
        l.push(Line::styled("p reads it", t.dim()));
    }
    let hist = maint::history(&v.sh.log, &s.id);
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
    keys.push(match (item_enter(v, s, it), workflow_of(it).is_some()) {
        (ItemEnter::OpenPlan, _) => "Enter: its plan, to approve · P starts over",
        (ItemEnter::Plan, true) => "Enter: with Claude (it looks into it, then shows its plan)",
        (ItemEnter::Plan, false) => {
            "Enter: with Claude (no workflow: its plan is the steps, which sentry-server runs)"
        }
        (ItemEnter::Log, _) => "Enter opens its log",
    });
    keys.extend(["z review later", "v its log", "e edit config"]);
    l.push(Line::styled(keys.join(" · "), t.dim()));
    l
}

/// The workflow that changes an item: its own, or its retire workflow.
pub fn workflow_of(it: &MaintItem) -> Option<&str> {
    it.retire
        .as_ref()
        .and_then(|r| r.workflow.as_deref())
        .or(it.workflow.as_deref())
}

/// Keys on the screen: on a recommendation, Enter does what it recommends; the item keys work
/// on the item it's about.
pub fn key(c: char, v: &View) -> Vec<Effect> {
    match pick(v) {
        Some(Sel::Rec(r)) => rec_key(c, v, r),
        Some(Sel::Item(s, it)) => item_key(c, v, s, it),
        None => Vec::new(),
    }
}

/// `z`: look again in 7, 30 or 90 days, on every row (an item's date is its review date).
fn later(v: &View, key: &str, what: &str) -> Vec<Effect> {
    vec![Effect::Choose(maintlist::later_choice(
        v.t,
        what,
        jiff::Zoned::now().date(),
        |_, until| vec![Effect::Snooze(key.to_string(), until)],
    ))]
}

fn rec_key(c: char, v: &View, r: Rec) -> Vec<Effect> {
    let found = &v.s.maint_found;
    match (c, &r.action) {
        // An item to move or retire: its session (on its plan, when one is ready).
        ('\n', Action::Plan(id) | Action::OpenPlan(id)) => vec![Effect::PlanApply(id.clone())],
        ('\n', Action::Run(wf)) => vec![Effect::StartWorkflow(wf.clone())],
        ('\n' | 't', Action::Track(n)) => match found.candidates.get(*n) {
            Some(c) => vec![Own::track(c.item.clone())],
            None => Vec::new(),
        },
        ('x', Action::Track(n)) => match found.candidates.get(*n) {
            Some(c) => dismiss(
                v,
                "Ignore this",
                &r.title,
                "Discovery stops suggesting it (ignore: in items.toml).",
                Own::ignore(c.key.clone(), c.item.id.clone()),
            ),
            None => Vec::new(),
        },
        ('\n' | 'x', Action::Remove(id)) => dismiss(
            v,
            "Stop tracking it",
            &r.title,
            "It comes off items.toml; the log keeps its history.",
            Own::untrack(id.clone()),
        ),
        ('\n', Action::Look(id)) if !id.is_empty() => vec![Own::maint_jump(id.clone())],
        ('\n', Action::Fix(id)) => vec![Own::fix_finding(id.clone())],
        ('x', Action::Fix(id)) => dismiss(
            v,
            "Mark it expected",
            &r.title,
            "The audit stops listing it (the server's baseline.toml).",
            Own::expected(id.clone(), true),
        ),
        ('\n', Action::Audit) => vec![
            Own::fetch(crate::tui::data::Kind::Audit),
            Effect::Toast("auditing the server…".into()),
        ],
        ('\n', Action::Security(id)) => vec![Effect::SecItem(id.clone())],
        ('\n', Action::Task(id)) => task_enter(v, id),
        ('d', Action::Task(id)) => vec![Effect::TaskDone(id.clone())],
        ('m', Action::Task(id)) => task_manual(v, id),
        // How often it recurs: asked for, and written to tasks.toml (a cadence from the
        // config too: the file's takes its place).
        ('e', Action::Task(id)) => vec![Effect::TaskEvery(id.clone())],
        ('B', Action::Fix(id)) => {
            finding(v, id).map_or(Vec::new(), |f| super::report::pattern_effects(v, f))
        }
        ('x', Action::Task(id)) => vec![Effect::Confirm(Modal {
            title: "Remove this task".into(),
            color: v.t.yellow,
            lines: vec![
                Line::styled(r.title.clone(), v.t.fg()),
                Line::styled(
                    "It comes off tasks.toml and leaves Maintenance. The log keeps what was done.",
                    v.t.dim(),
                ),
            ],
            yes: Some(("remove".into(), vec![Effect::TaskRemove(id.clone())])),
        })],
        ('z', _) => later(v, &r.key, &r.title),
        // Plan keys work on the item the recommendation is about.
        ('p' | 'P' | 'x', _) => match r
            .item
            .as_deref()
            .and_then(|id| Some((status_of(v, id)?, item_of(v, id)?)))
        {
            Some((s, it)) => item_key(c, v, s, it),
            None if c == 'x' => vec![Effect::Toast(maintlist::NOTHING_TO_DISMISS.into())],
            None => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// `x` on a recommendation: say what it writes where, then do it.
fn dismiss(v: &View, title: &str, what: &str, how: &str, e: Effect) -> Vec<Effect> {
    vec![Effect::Confirm(Modal {
        title: title.into(),
        color: v.t.yellow,
        lines: vec![
            Line::styled(what.to_string(), v.t.fg()),
            Line::styled(how.to_string(), v.t.dim()),
        ],
        yes: Some(("yes".into(), vec![e])),
    })]
}

/// Enter on a task: its workflow, the item's plan, the audit, or (by hand) its steps.
pub fn task_enter(v: &View, id: &str) -> Vec<Effect> {
    use sentry_core::maint::tasks::Do;
    let Some(task) = all_tasks(v).into_iter().find(|x| x.id == id) else {
        return Vec::new();
    };
    match task.action() {
        Do::Run(wf) => vec![Effect::StartWorkflow(wf)],
        Do::Plan(it) => match status_of(v, &it) {
            Some(_) => vec![Effect::PlanApply(it)],
            None => vec![Effect::Toast(format!("{it} isn't tracked any more"))],
        },
        Do::Audit => vec![
            Own::fetch(crate::tui::data::Kind::Audit),
            Effect::Toast("auditing the server…".into()),
        ],
        Do::Job(j) => vec![Effect::Toast(format!(
            "{j} is a job of sentry's (on a desktop), not the server's: d marks it done"
        ))],
        // By hand: with Claude, who plans it and sentry applies it (without Claude Code, or
        // with `m`, the steps to do it yourself).
        Do::ByHand if sentry_core::claude::available() => vec![Effect::ApplyAsk],
        Do::ByHand => task_manual(v, id),
    }
}

/// `m` on a task done by hand: its steps, to do it yourself, then mark it done.
pub fn task_manual(v: &View, id: &str) -> Vec<Effect> {
    use sentry_core::maint::tasks::Do;
    let t = v.t;
    let Some(task) = all_tasks(v).into_iter().find(|x| x.id == id) else {
        return Vec::new();
    };
    match task.action() {
        Do::ByHand => {
            let mut lines = vec![Line::styled(task.why.clone(), t.fg()), Line::raw("")];
            if task.steps.trim().is_empty() {
                lines.push(Line::styled("(no steps given: see the review)", t.dim()));
            } else {
                lines.extend(sentry_core::tui::docview::markdown(t, &task.steps));
            }
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "Do it yourself, then mark it done: it's logged, and leaves the list.",
                t.dim(),
            ));
            vec![Effect::Confirm(Modal {
                title: task.title.clone(),
                color: t.cyan,
                lines,
                yes: Some(("mark done".into(), vec![Effect::TaskDone(id.to_string())])),
            })]
        }
        _ => Vec::new(),
    }
}

fn item_key(c: char, v: &View, s: &Status, it: &MaintItem) -> Vec<Effect> {
    match c {
        'z' => later(v, &s.id, &format!("Review {} later", s.id)),
        // The saved plan, to read; started over, it's set aside and the session begins again.
        'p' => vec![Effect::PlanOpen(s.id.clone())],
        'P' if v.plans.contains_key(&s.id) => vec![Effect::PlanAgain(s.id.clone())],
        'P' => vec![Effect::PlanApply(s.id.clone())],
        // Enter: its session when there's something to do to it, else what was done to it.
        '\n' => match item_enter(v, s, it) {
            ItemEnter::OpenPlan | ItemEnter::Plan => vec![Effect::PlanApply(s.id.clone())],
            ItemEnter::Log => vec![Effect::LogOpen(Some(s.id.clone()))],
        },
        'x' => match v.plans.get(&s.id) {
            Some(p) => vec![Effect::Confirm(crate::tui::target::Modal {
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
            None => vec![Effect::Toast(maintlist::NOTHING_TO_DISMISS.into())],
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
    // Routine runs as they apply now: the config's cadences, or what tasks.toml made of them.
    let c: Vec<String> = all_tasks(v)
        .iter()
        .filter(|t| !t.off)
        .filter_map(|t| match (t.action(), t.every) {
            (sentry_core::maint::tasks::Do::Run(wf), Some(d)) => {
                Some(format!("{wf} every {} day(s)", d.0.as_secs() / 86_400))
            }
            _ => None,
        })
        .collect();
    if !c.is_empty() {
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

pub use sentry_core::maint::real_path;

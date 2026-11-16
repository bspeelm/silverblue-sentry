//! The screens: what each draws, how many selectable rows it has, and what its keys do.
//! Their numbers and names are sentry's (`super::SCREENS`).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Wrap};

pub mod containers;
pub mod dashboard;
pub mod maint;
pub mod network;
pub mod processes;
pub mod report;
pub mod services;
pub mod upgrade;

use std::time::Duration;

use super::app::Effect;
use super::data::{Kind, Store};
use crate::collect::apt::{Kind as PkgKind, Pkg};
use crate::collect::docker::Container;
use crate::collect::health::SmartHealth;
use crate::config::Server;
use crate::remote::Remote;
use sentry_core::claude::Ask;
use sentry_core::finding::{Finding, Sev};
use sentry_core::fmt;
use sentry_core::tui::keys::Action;
use sentry_core::tui::theme::Theme;
use sentry_core::tui::widgets::{self, TableSpec, bar, graph, inner, panel, trunc};
use sentry_core::tui::{Cursor, ScreenId};

pub struct View<'a> {
    pub t: &'a Theme,
    pub s: &'a Store,
    pub cfg: &'a Server,
    pub name: &'a str,
    /// The row selected on the screen in view (a copy of its cursor).
    pub cur: usize,
    pub now: jiff::Timestamp,
    /// The screen's `/` filter, when one is set.
    pub filter: Option<&'a str>,
    /// When sudo asks for a password: when the root-only data shown was read (`I`).
    pub inventory: Option<jiff::Timestamp>,
    /// When upstream versions were last looked up.
    pub upstream: Option<jiff::Timestamp>,
    /// That read with sudo is from before the last maintenance run.
    pub inventory_stale: bool,
    /// The maintenance item Claude is writing a plan for.
    pub planning: Option<String>,
    /// Open plans, by item.
    pub plans: &'a std::collections::BTreeMap<String, crate::maint::plan::PlanDoc>,
    /// The workflow run in progress (or just ended).
    pub wf: Option<&'a crate::workflow::Session>,
    /// The workflows there are, each with its last run.
    pub wf_list: &'a [sentry_core::tui::wflist::WfInfo],
}

impl View<'_> {
    /// " · read with sudo 3h ago" where root-only data comes from the inventory.
    pub fn inv_note(&self) -> String {
        self.inventory.map_or(String::new(), |at| {
            if self.inventory_stale {
                format!(
                    " · read with sudo {}, before the last change: I reads again",
                    fmt::ago(self.secs_since(at))
                )
            } else {
                format!(" · read with sudo {}", fmt::ago(self.secs_since(at)))
            }
        })
    }

    /// Case-insensitive substring match of the filter against any field, as in sentry.
    pub fn matches(&self, fields: &[&str]) -> bool {
        match self.filter {
            None => true,
            Some(f) => {
                let f = f.to_lowercase();
                fields.iter().any(|x| x.to_lowercase().contains(&f))
            }
        }
    }

    pub fn secs_since(&self, t: jiff::Timestamp) -> i64 {
        self.now.as_second() - t.as_second()
    }
}

// ---------- the screens ----------

pub type Hints = Vec<(&'static str, &'static str)>;

/// A fetch a screen wants while it's in view: when it's entered, then every `every`
/// (None: at entry only).
pub struct Poll {
    pub kind: Kind,
    pub every: Option<Duration>,
}

const PROBE: Duration = Duration::from_secs(1);
const FAST: Duration = Duration::from_secs(5);
const SLOW: Duration = Duration::from_secs(60);
/// Updates and the apt simulation are slow-moving; re-read on entering a screen at most hourly.
const APT_MAX_AGE: Duration = Duration::from_secs(3600);

/// Every screen's own state. A screen is a struct holding at least its `Cursor`; the app
/// reaches them only through the methods here.
#[derive(Default)]
pub struct Screens {
    pub dash: dashboard::Dashboard,
    pub cont: containers::Containers,
    pub svc: services::Services,
    pub maint: maint::Maint,
    pub upgrade: upgrade::Upgrade,
    pub net: network::Network,
    pub procs: processes::Processes,
}

impl Screens {
    /// What the screen fetches while it's the one in view.
    pub fn polls(id: ScreenId, cfg: &Server) -> Vec<Poll> {
        let at = |kind, every: Option<Duration>| Poll { kind, every };
        match id {
            ScreenId::Dash => {
                let mut p = vec![
                    at(Kind::Probe, Some(PROBE)),
                    at(Kind::Gpu, Some(FAST)),
                    at(Kind::Temp, Some(FAST)),
                    at(Kind::Disks, Some(SLOW)),
                    // Status rows need a little of everything.
                    at(Kind::Units, Some(SLOW)),
                    at(Kind::Docker, Some(SLOW)),
                    at(Kind::Report, None),
                ];
                if !cfg.smart.is_empty() {
                    p.push(at(Kind::Smart, Some(SLOW)));
                }
                p
            }
            // One exec per sample: the probe and every process.
            ScreenId::Proc => vec![at(Kind::Procs, Some(processes::EVERY))],
            ScreenId::Svc => vec![at(Kind::Units, None), at(Kind::Journal, None)],
            ScreenId::Cont => vec![at(Kind::Docker, None)],
            // One `ss` without sudo while it's shown; the names root sees and the
            // containers' ports are read once.
            ScreenId::Net => vec![
                at(Kind::Sockets, Some(FAST)),
                at(Kind::Listeners, None),
                at(Kind::Docker, None),
            ],
            ScreenId::Maint => vec![
                at(Kind::Maint, None),
                at(Kind::Docker, None),
                at(Kind::Report, None),
            ],
            _ => Vec::new(),
        }
    }

    /// What else entering the screen fetches, depending on what's already known.
    pub fn on_enter(&mut self, id: ScreenId, v: &View) -> Vec<Effect> {
        let mut e = Vec::new();
        if matches!(id, ScreenId::Dash | ScreenId::Maint)
            && v.s.apt.at.is_none_or(|t| t.elapsed() > APT_MAX_AGE)
        {
            e.push(Effect::Fetch(Kind::Apt));
        }
        if id == ScreenId::Maint {
            // Upstream changes slowly: looked up again at most daily without `c`.
            let stale = v
                .upstream
                .is_none_or(|at| jiff::Timestamp::now().as_second() - at.as_second() > 86400);
            if stale && !v.cfg.maintenance.items.is_empty() {
                e.push(Effect::Fetch(Kind::Upstream));
            }
        }
        e
    }

    /// The selectable rows the screen has now.
    pub fn rows(id: ScreenId, v: &View) -> usize {
        match id {
            ScreenId::Dash => dashboard::status_rows(v).len(),
            ScreenId::Svc => services::unit_rows(v).len(),
            ScreenId::Cont => containers::container_list(v).len(),
            ScreenId::Maint => maint::count(v),
            ScreenId::Net => network::rows(v).len(),
            ScreenId::Proc => processes::count(v),
            // The list, while nothing runs.
            ScreenId::Upgrade if v.wf.is_none() => v.wf_list.len(),
            _ => 0,
        }
    }

    /// A key on the screen: moving is the cursor's, the rest is the screen's.
    pub fn handle(&mut self, id: ScreenId, a: Action, v: &View, r: &Remote) -> Vec<Effect> {
        // A view over Maintenance has its own list.
        if id == ScreenId::Maint && self.maint.view.is_some() {
            return self.maint.handle(a, v, r);
        }
        let n = Self::rows(id, v);
        if self.cursor_mut(id).nav(a, n) {
            return Vec::new();
        }
        match id {
            ScreenId::Dash => self.dash.handle(a, v, r),
            ScreenId::Svc => self.svc.handle(a, v, r),
            ScreenId::Cont => self.cont.handle(a, v, r),
            ScreenId::Maint => self.maint.handle(a, v, r),
            ScreenId::Upgrade => self.upgrade.handle(a, v, r),
            ScreenId::Net => self.net.handle(a, v),
            ScreenId::Proc => self.procs.handle(a, v),
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, id: ScreenId, f: &mut Frame, area: Rect, v: &View) {
        // PgUp/PgDn move half of what's roughly on screen.
        self.cursor_mut(id).page = area.height.saturating_sub(4) as usize;
        match id {
            ScreenId::Dash => dashboard::overview(f, area, v),
            ScreenId::Svc => services::services(f, area, v),
            ScreenId::Cont => containers::containers(f, area, v),
            ScreenId::Maint => self.maint.render(f, area, v),
            ScreenId::Upgrade => upgrade::draw(f, area, v),
            ScreenId::Net => self.net.render(f, area, v),
            ScreenId::Proc => self.procs.render(f, area, v),
            _ => {}
        }
    }

    pub fn hints(&self, id: ScreenId, v: &View) -> Hints {
        match id {
            ScreenId::Dash => vec![
                ("j/k", "select"),
                ("Enter", "open screen"),
                ("r", "refresh"),
            ],
            ScreenId::Svc => vec![("j/k", "select"), ("Enter", "details"), ("r", "refresh")],
            ScreenId::Cont => vec![
                ("j/k", "select"),
                ("Enter", "details"),
                ("c", "cpu/mem"),
                ("r", "refresh"),
            ],
            // The selected row's keys, then the screen's.
            ScreenId::Maint if self.maint.view.is_some() => report::hints(v),
            ScreenId::Maint => {
                let mut h = sentry_core::tui::maintlist::hints(&maint::verbs(v));
                // The screen's own few; w, e and the rest are in `?`.
                h.extend([("c", "check"), ("v", "records"), ("R", "review")]);
                h
            }
            ScreenId::Upgrade => upgrade::hints(v),
            ScreenId::Net => network::hints(),
            ScreenId::Proc => processes::hints(),
            _ => Vec::new(),
        }
    }

    /// What Claude is asked about the screen (its selected row), or why there's nothing.
    pub fn ask(&self, id: ScreenId, v: &View, r: &Remote) -> Result<Ask, String> {
        // In the audit report: the finding selected there.
        if id == ScreenId::Maint && self.maint.view.is_some() {
            return report::selected(&self.maint.report, v)
                .map(|f| crate::tui::ask::ask_finding(v, r, f))
                .ok_or_else(|| "no finding selected (c audits the server)".to_string());
        }
        // The process selected, in the order the screen lists them.
        if id == ScreenId::Proc {
            return self.procs.ask(v, r);
        }
        crate::tui::ask::ask_for(id, v, r)
            .ok_or_else(|| crate::tui::ask::nothing_here(id, v).to_string())
    }

    /// The count shown next to the screen's name.
    pub fn badge(&self, id: ScreenId, v: &View) -> Option<(String, Color)> {
        let t = v.t;
        match id {
            ScreenId::Svc => {
                let n = v.s.units.value.as_ref()?.failed().count();
                (n > 0).then(|| (format!(" {n}"), t.red))
            }
            ScreenId::Cont => {
                let n =
                    v.s.docker
                        .value
                        .as_ref()?
                        .containers
                        .iter()
                        .filter(|c| c.down() || c.health.as_deref() == Some("unhealthy"))
                        .count();
                (n > 0).then(|| (format!(" {n}"), t.red))
            }
            ScreenId::Maint => maint::badge(v),
            // Listeners open to the network that nothing expects.
            ScreenId::Net => {
                let n = network::new_count(v);
                (n > 0).then(|| (format!(" {n}"), t.red))
            }
            // A run in progress.
            ScreenId::Upgrade => {
                v.wf.filter(|s| !s.done())
                    .map(|_| (" ●".to_string(), t.yellow))
            }
            _ => None,
        }
    }

    /// Screens whose list `/` filters.
    pub fn filterable(id: ScreenId) -> bool {
        matches!(
            id,
            ScreenId::Svc | ScreenId::Cont | ScreenId::Maint | ScreenId::Net | ScreenId::Proc
        )
    }

    /// Keys that change the server as root: sudo is checked again first.
    pub fn uses_root(id: ScreenId, c: char) -> bool {
        matches!(
            (id, c),
            (ScreenId::Dash, 'a' | 'B')
                | (ScreenId::Svc, 'R' | 'x')
                | (ScreenId::Cont, 'R' | 'p' | 'u')
        )
    }

    fn cursor_mut(&mut self, id: ScreenId) -> &mut Cursor {
        match id {
            ScreenId::Svc => &mut self.svc.cur,
            ScreenId::Cont => &mut self.cont.cur,
            ScreenId::Maint => &mut self.maint.cur,
            ScreenId::Upgrade => &mut self.upgrade.cur,
            ScreenId::Net => &mut self.net.cur,
            ScreenId::Proc => &mut self.procs.cur,
            _ => &mut self.dash.cur,
        }
    }

    /// The row selected on the screen.
    pub fn cur(&self, id: ScreenId) -> usize {
        match id {
            ScreenId::Svc => self.svc.cur.sel,
            ScreenId::Cont => self.cont.cur.sel,
            ScreenId::Maint => self.maint.cur.sel,
            ScreenId::Upgrade => self.upgrade.cur.sel,
            ScreenId::Net => self.net.cur.sel,
            ScreenId::Proc => self.procs.cur.sel,
            _ => self.dash.cur.sel,
        }
    }

    pub fn reset_cursor(&mut self, id: ScreenId) {
        self.cursor_mut(id).sel = 0;
    }

    /// The data changed: Maintenance stays on the row it was on, and the cursor of the
    /// screen in view stays inside its list.
    pub fn clamp(&mut self, id: ScreenId, v: &View) {
        self.maint.keep(v);
        let n = Self::rows(id, v);
        self.cursor_mut(id).clamp(n);
    }
}

fn sev_color(t: &Theme, s: Sev) -> Color {
    match s {
        Sev::High => t.red,
        Sev::Medium => t.yellow,
        Sev::Low => t.dim,
    }
}

fn waiting<T>(v: &View, slot: &super::data::Slot<T>, what: &str) -> Line<'static> {
    match &slot.err {
        Some(e) => Line::styled(format!("{what}: {e}"), v.t.s(v.t.red)),
        None => Line::styled(format!("reading {what}…"), v.t.dim()),
    }
}

/// What to do when sudo wants a password for something this screen needs.
fn needs_password(v: &View, what: &str) -> Vec<Line<'static>> {
    let t = v.t;
    vec![
        Line::styled(
            format!(
                "sudo on {} asks for a password, so {what} can't be read in the background.",
                v.name
            ),
            t.fg(),
        ),
        Line::raw(""),
        Line::from(vec![
            Span::styled("Press ", t.fg()),
            Span::styled(" I ", Style::new().fg(t.chip_fg).bg(t.dim)),
            Span::styled(
                " to read them once with your password: one sudo, read-only. The terminal is \
                 handed over for the password, then this screen shows that read (with its age) until \
                 you read again.",
                t.fg(),
            ),
        ]),
    ]
}

// ---------- Updates ----------

/// What's waiting in packages: reboot, refresh times, held back, then each update (security
/// first). The details of the updates and reboot recommendations on Maintenance.
pub fn updates_lines(v: &View) -> Vec<Line<'static>> {
    let t = v.t;
    let Some(a) = &v.s.apt.value else {
        return vec![waiting(v, &v.s.apt, "apt (simulated upgrade)")];
    };
    let mut info = Vec::new();
    match a.reboot_since {
        Some(since) => {
            info.push(Line::from(vec![
                Span::styled(
                    "● reboot required ",
                    t.s(if a.now - since > 14 * 86400 {
                        t.red
                    } else {
                        t.yellow
                    }),
                ),
                Span::styled(
                    format!(
                        "for {} · running {} · newest installed {}",
                        fmt::age(a.now - since),
                        a.running_kernel,
                        a.newest_kernel.as_deref().unwrap_or("?")
                    ),
                    t.fg(),
                ),
            ]));
            if !a.reboot_pkgs.is_empty() {
                info.push(Line::styled(
                    format!("  asked for by {}", a.reboot_pkgs.join(", ")),
                    t.dim(),
                ));
            }
        }
        None => info.push(Line::styled(
            format!("✓ no reboot needed · kernel {}", a.running_kernel),
            t.s(t.green),
        )),
    }
    let stamp = |n: &str| a.stamp(n).map_or("never".into(), |s| fmt::ago(a.now - s));
    info.push(Line::styled(
        format!(
            "package lists refreshed {} · unattended upgrade ran {}",
            stamp("update"),
            stamp("unattended-upgrades")
        ),
        t.dim(),
    ));
    if !a.kept_back.is_empty() {
        info.push(Line::styled(
            format!(
                "held back (phased or would remove packages): {}",
                a.kept_back.join(" ")
            ),
            t.dim(),
        ));
    }
    if !a.removals.is_empty() {
        info.push(Line::styled(
            format!("would remove: {}", a.removals.join(" ")),
            t.s(t.yellow),
        ));
    }
    if !a.upgrades.is_empty() {
        info.push(Line::raw(""));
        info.push(Line::styled(
            format!("{} update(s), simulated with apt-get -s:", a.upgrades.len()),
            t.dim(),
        ));
        let mut pkgs: Vec<&Pkg> = a.upgrades.iter().collect();
        pkgs.sort_by(|x, y| x.kind.cmp(&y.kind).then(x.name.cmp(&y.name)));
        for p in pkgs {
            let (k, c) = match p.kind {
                PkgKind::Security => ("security", t.red),
                PkgKind::Updates => ("update", t.fg),
                PkgKind::Other => ("vendor", t.cyan),
            };
            info.push(Line::from(vec![
                Span::styled(format!("{k:<9}"), t.s(c)),
                Span::styled(p.name.clone(), t.fg()),
                Span::styled(
                    format!(" {} → {}", p.old.as_deref().unwrap_or("(new)"), p.new),
                    t.dim(),
                ),
            ]));
        }
    }
    info
}

fn smart_word(h: &SmartHealth) -> &'static str {
    match h {
        SmartHealth::Passed => "ok",
        SmartHealth::Failed => "FAILING",
        SmartHealth::Asleep => "asleep",
        SmartHealth::Unknown(_) => "?",
    }
}

// ---------- for Ask Claude ----------

pub fn status_text(v: &View) -> Vec<String> {
    dashboard::status_rows(v)
        .into_iter()
        .map(|r| format!("{} {}", r.icon, r.text))
        .collect()
}

pub fn selected_unit(v: &View) -> Option<String> {
    services::unit_rows(v)
        .into_iter()
        .nth(v.cur)
        .map(|u| u.unit)
}

pub fn unit_text(v: &View, unit: &str) -> String {
    let mut out = format!("Unit {unit}");
    if let Some(st) = v.s.units.value.as_ref().and_then(|u| u.get(unit)) {
        out.push_str(&format!(
            ": {} ({}), last result {} (exit {})",
            st.active,
            st.sub,
            st.result,
            st.exit.map_or("-".into(), |e| e.to_string())
        ));
        if let Some(l) = st.last_trigger {
            out.push_str(&format!(", last run {l}"));
        }
        if let Some(t) = &st.triggers {
            out.push_str(&format!(", starts {t}"));
        }
    }
    let ident = unit.trim_end_matches(".timer").trim_end_matches(".service");
    if let Some(j) = v.s.journal.value.as_ref().and_then(|js| {
        js.iter()
            .find(|j| j.ident.trim_end_matches(".service") == ident)
    }) {
        out.push_str(&format!(
            "\n{} error(s) in its journal in 24 h; the last: {}",
            j.count, j.last
        ));
    }
    out
}

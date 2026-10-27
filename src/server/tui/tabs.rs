//! The five tabs: what each draws, how many selectable rows it has, and what its keys do.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Wrap};

use super::Tab;
use super::app::Effect;
use super::data::{Kind, Store};
use crate::audit::{Finding, Sev};
use crate::fmt;
use crate::server::collect::apt::{Kind as PkgKind, Pkg};
use crate::server::collect::docker::Container;
use crate::server::collect::health::SmartHealth;
use crate::server::config::Server;
use crate::tui::theme::Theme;
use crate::tui::widgets::{self, TableSpec, bar, graph, inner, panel, trunc};

pub struct View<'a> {
    pub t: &'a Theme,
    pub s: &'a Store,
    pub cfg: &'a Server,
    pub name: &'a str,
    pub cur: usize,
    pub now: jiff::Timestamp,
    /// The tab's `/` filter, when one is set.
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
    pub plans: &'a std::collections::BTreeMap<String, crate::server::maint::plan::PlanDoc>,
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

// ---------- shared ----------

pub fn rows(tab: Tab, v: &View) -> usize {
    match tab {
        Tab::Overview => status_rows(v).len(),
        Tab::Services => unit_rows(v).len(),
        Tab::Containers => container_list(v).len(),
        Tab::Maint => super::maint::count(v),
    }
}

pub fn hints(tab: Tab, _v: &View) -> Vec<(&'static str, &'static str)> {
    match tab {
        Tab::Overview => vec![("j/k", "select"), ("Enter", "open tab"), ("r", "refresh")],
        Tab::Services => vec![("j/k", "select"), ("Enter", "details"), ("r", "refresh")],
        Tab::Containers => vec![
            ("j/k", "select"),
            ("Enter", "details"),
            ("c", "cpu/mem"),
            ("r", "refresh"),
        ],
        Tab::Maint => vec![
            ("j/k", "select"),
            ("Enter", "do it"),
            ("p", "plan"),
            ("t", "track"),
            ("R", "review"),
            ("w", "workflow"),
            ("x", "drop/ignore"),
            ("v", "log"),
            ("z", "later"),
            ("c", "check all"),
            ("e", "edit"),
        ],
    }
}

pub fn refresh(tab: Tab) -> Vec<Effect> {
    match tab {
        Tab::Overview => [
            Kind::Probe,
            Kind::Disks,
            Kind::Units,
            Kind::Docker,
            Kind::Report,
        ]
        .into_iter()
        .map(Effect::Fetch)
        .collect(),
        Tab::Services => vec![Effect::Fetch(Kind::Units), Effect::Fetch(Kind::Journal)],
        Tab::Containers => vec![Effect::Fetch(Kind::Docker)],
        Tab::Maint => vec![Effect::Fetch(Kind::Maint)],
    }
}

pub fn check(tab: Tab) -> Vec<Effect> {
    match tab {
        Tab::Containers => vec![
            Effect::Fetch(Kind::Stats),
            Effect::Toast("docker stats…".into()),
        ],
        // Check everything: audit the server and look upstream up again.
        Tab::Maint => vec![
            Effect::Fetch(Kind::Audit),
            Effect::Fetch(Kind::Upstream),
            Effect::Toast("auditing the server and looking up newer versions…".into()),
        ],
        t => refresh(t),
    }
}

pub fn enter(tab: Tab, v: &View) -> Vec<Effect> {
    match tab {
        Tab::Overview => match status_rows(v).get(v.cur) {
            Some(StatusRow {
                goto: Some(t),
                pick,
                ..
            }) => {
                let mut e = vec![Effect::Goto(*t)];
                e.extend(pick.map(|p| Effect::MaintFind(p.into())));
                e
            }
            _ => Vec::new(),
        },
        Tab::Services => unit_detail(v),
        Tab::Containers => container_detail(v),
        Tab::Maint => super::maint::key('\n', v),
    }
}

pub fn key(tab: Tab, c: char, v: &View, r: &crate::server::remote::Remote) -> Vec<Effect> {
    use super::actions;
    match (tab, c) {
        (Tab::Services, 'R' | 'x' | 'L') => match unit_rows(v).into_iter().nth(v.cur) {
            Some(u) => {
                let failed = u.state.starts_with("failed")
                    || v.s
                        .units
                        .value
                        .as_ref()
                        .is_some_and(|x| x.failed().any(|f| f.unit == u.unit));
                actions::services(v, r, c, &u.unit, failed)
            }
            None => Vec::new(),
        },
        (Tab::Containers, 'R' | 'L' | 'p' | 'u') => match selected_container(v) {
            Some(ct) => actions::containers(v, r, c, &ct.name, ct.compose.as_deref()),
            None => Vec::new(),
        },
        (Tab::Maint, 'z' | 'p' | 'P' | 'x' | 't') => super::maint::key(c, v),
        (Tab::Maint, 'e') => vec![Effect::EditConfig],
        (Tab::Maint, 'R') => vec![Effect::ReviewOpen],
        (Tab::Maint, 'w') => vec![Effect::ChooseWorkflow],
        (Tab::Maint, 'v') => vec![Effect::LogOpen(
            super::maint::selected(v).map(|(s, _)| s.id.clone()),
        )],
        _ => Vec::new(),
    }
}

/// Tabs whose list `/` filters.
pub fn filterable(tab: Tab) -> bool {
    matches!(tab, Tab::Services | Tab::Containers | Tab::Maint)
}

/// The count shown next to a tab name.
pub fn badge(tab: Tab, v: &View) -> Option<(String, Color)> {
    let t = v.t;
    match tab {
        Tab::Services => {
            let n = v.s.units.value.as_ref()?.failed().count();
            (n > 0).then(|| (format!(" {n}"), t.red))
        }
        Tab::Containers => {
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
        Tab::Maint => super::maint::badge(v),
        Tab::Overview => None,
    }
}

fn sev_color(t: &Theme, s: Sev) -> Color {
    match s {
        Sev::High => t.red,
        Sev::Medium => t.yellow,
        Sev::Low => t.dim,
    }
}

pub fn draw(f: &mut Frame, area: Rect, tab: Tab, v: &View) {
    match tab {
        Tab::Overview => overview(f, area, v),
        Tab::Services => services(f, area, v),
        Tab::Containers => containers(f, area, v),
        Tab::Maint => super::maint::draw(f, area, v),
    }
}

fn waiting<T>(v: &View, slot: &super::data::Slot<T>, what: &str) -> Line<'static> {
    match &slot.err {
        Some(e) => Line::styled(format!("{what}: {e}"), v.t.s(v.t.red)),
        None => Line::styled(format!("reading {what}…"), v.t.dim()),
    }
}

/// What to do when sudo wants a password for something this tab needs.
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
                 handed over for the password, then this tab shows that read (with its age) until \
                 you read again.",
                t.fg(),
            ),
        ]),
    ]
}

// ---------- Overview ----------

struct StatusRow {
    color: Color,
    icon: &'static str,
    text: String,
    goto: Option<Tab>,
    /// On Maintenance: the recommendation to select (a key prefix).
    pick: Option<&'static str>,
}

fn status_rows(v: &View) -> Vec<StatusRow> {
    let t = v.t;
    let s = v.s;
    let ok = |text: String, goto| StatusRow {
        color: t.green,
        icon: "✓",
        text,
        goto,
        pick: None,
    };
    let bad = |c, text: String, goto| StatusRow {
        color: c,
        icon: "●",
        text,
        goto,
        pick: None,
    };
    let mut out = Vec::new();
    if let Some((_, why)) = &s.unreachable {
        out.push(bad(t.red, format!("can't reach {}: {why}", v.name), None));
    }
    if s.rebooted() {
        out.push(bad(
            t.mag,
            "the server rebooted since sentry-server started".into(),
            None,
        ));
    }
    match &s.apt.value {
        Some(a) => {
            if let Some(since) = a.reboot_since {
                let k = match &a.newest_kernel {
                    Some(n) if a.kernel_pending() => {
                        format!(" · kernel {} → {n}", a.running_kernel)
                    }
                    _ => String::new(),
                };
                out.push(bad(
                    if a.now - since > 14 * 86400 {
                        t.red
                    } else {
                        t.yellow
                    },
                    format!("reboot required for {}{k}", fmt::age(a.now - since)),
                    Some(Tab::Maint),
                ));
                if let Some(r) = out.last_mut() {
                    r.pick = Some("reboot");
                }
            }
            let sec = a
                .upgrades
                .iter()
                .filter(|p| p.kind == PkgKind::Security)
                .count();
            if sec > 0 {
                out.push(bad(
                    t.red,
                    format!(
                        "{sec} security update(s) waiting ({} in all)",
                        a.upgrades.len()
                    ),
                    Some(Tab::Maint),
                ));
                if let Some(r) = out.last_mut() {
                    r.pick = Some("wf:apt-maintenance");
                }
            } else if !a.upgrades.is_empty() {
                out.push(bad(
                    t.yellow,
                    format!("{} update(s) waiting", a.upgrades.len()),
                    Some(Tab::Maint),
                ));
                if let Some(r) = out.last_mut() {
                    r.pick = Some("wf:apt-maintenance");
                }
            } else {
                out.push(ok("packages up to date".into(), Some(Tab::Maint)));
            }
        }
        None => out.push(StatusRow {
            color: t.dim,
            icon: "·",
            text: s
                .apt
                .err
                .as_ref()
                .map_or("reading updates…".into(), |e| format!("updates: {e}")),
            goto: Some(Tab::Maint),
            pick: None,
        }),
    }
    if let Some(u) = &s.units.value {
        for rule in &v.cfg.timers {
            let Some(st) = u.get(&rule.unit) else {
                continue;
            };
            let ran = st.triggers.as_deref().and_then(|x| u.get(x));
            let failed = ran.is_some_and(|r| !r.result.is_empty() && r.result != "success");
            match st.last_trigger {
                Some(l) => {
                    let age = v.secs_since(l);
                    let stale = age > rule.max_age.0.as_secs() as i64;
                    let text = format!(
                        "{} ran {}{}",
                        rule.unit.trim_end_matches(".timer"),
                        fmt::ago(age),
                        if failed { " and failed" } else { "" }
                    );
                    out.push(if failed || stale {
                        bad(t.red, text, Some(Tab::Services))
                    } else {
                        ok(text, Some(Tab::Services))
                    });
                }
                None => out.push(bad(
                    t.red,
                    format!("{} never ran", rule.unit),
                    Some(Tab::Services),
                )),
            }
        }
        let down: Vec<&str> = v
            .cfg
            .services
            .iter()
            .filter(|svc| u.get(svc).is_some_and(|st| st.active != "active"))
            .map(String::as_str)
            .collect();
        let failed = u.failed().count();
        if !down.is_empty() {
            out.push(bad(
                t.red,
                format!("down: {}", down.join(", ")),
                Some(Tab::Services),
            ));
        } else if !v.cfg.services.is_empty() {
            out.push(ok(
                format!("{} services running", v.cfg.services.len()),
                Some(Tab::Services),
            ));
        }
        if failed > 0 {
            out.push(bad(
                t.yellow,
                format!("{failed} failed unit(s)"),
                Some(Tab::Services),
            ));
        }
    }
    if let Some(d) = &s.docker.value {
        let n = d.containers.iter().filter(|c| !c.finished()).count();
        let running = d
            .containers
            .iter()
            .filter(|c| c.status == "running")
            .count();
        let unhealthy = d
            .containers
            .iter()
            .filter(|c| c.health.as_deref() == Some("unhealthy"))
            .count();
        let healthy = d
            .containers
            .iter()
            .filter(|c| c.health.as_deref() == Some("healthy"))
            .count();
        if running < n || unhealthy > 0 {
            out.push(bad(
                t.red,
                format!(
                    "{} of {n} containers not running · {unhealthy} unhealthy",
                    n - running
                ),
                Some(Tab::Containers),
            ));
        } else if n > 0 {
            out.push(ok(
                format!("{n} containers running · {healthy} healthy"),
                Some(Tab::Containers),
            ));
        }
    } else if let Some(e) = &s.docker.err {
        out.push(StatusRow {
            color: t.dim,
            icon: "·",
            text: format!("containers: {e}"),
            goto: Some(Tab::Containers),
            pick: None,
        });
    }
    match s.report.value.as_ref().map(|r| r.as_deref()) {
        Some(Some(r)) => {
            let open: Vec<&Finding> = r.open().collect();
            let when = r.snapshot.taken_at.map_or(String::new(), |ts| {
                format!(" (audit {})", fmt::ago(v.secs_since(ts)))
            });
            match open.iter().map(|f| f.severity).max() {
                Some(top) => {
                    let mut r = bad(
                        sev_color(t, top),
                        format!("{} open finding(s){when}", open.len()),
                        Some(Tab::Maint),
                    );
                    r.pick = Some("finding:");
                    out.push(r);
                }
                None => out.push(ok(format!("no open findings{when}"), Some(Tab::Maint))),
            }
        }
        Some(None) => out.push(StatusRow {
            color: t.dim,
            icon: "·",
            text: "no audit yet: c on Maintenance".into(),
            goto: Some(Tab::Maint),
            pick: Some("audit"),
        }),
        None => {}
    }
    out
}

fn overview(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let s = v.s;
    let [row1, row2, row3] = Layout::vertical([
        Constraint::Length(7),
        Constraint::Length(5),
        Constraint::Fill(1),
    ])
    .areas(area);
    let halves = |r: Rect| {
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas::<2>(r)
    };

    let [cpu_a, mem_a] = halves(row1);
    let p = s.probe.value.as_ref();
    let cpu_detail = match p {
        Some(p) => format!(
            "{:.0}% · load {:.2} {:.2} {:.2} · {} cores",
            s.cpu.last().unwrap_or(0.0),
            p.load[0],
            p.load[1],
            p.load[2],
            p.cores
        ),
        None => "…".into(),
    };
    let b = panel(t, "CPU", cpu_detail);
    let r = inner(&b, cpu_a);
    f.render_widget(b, cpu_a);
    graph(
        f.buffer_mut(),
        r,
        &s.cpu.vec(),
        100.0,
        t.load(s.cpu.last().unwrap_or(0.0)),
    );
    let mem_detail = match p {
        Some(p) => {
            let swap = if p.swap_total_kib > 0 {
                format!(
                    " · swap {:.0}%",
                    100.0 * (p.swap_total_kib - p.swap_free_kib.min(p.swap_total_kib)) as f64
                        / p.swap_total_kib as f64
                )
            } else {
                String::new()
            };
            format!(
                "{:.0}% of {}{swap}",
                p.mem_used_pct(),
                fmt::bytes(p.mem_total_kib * 1024)
            )
        }
        None => "…".into(),
    };
    let b = panel(t, "Memory", mem_detail);
    let r = inner(&b, mem_a);
    f.render_widget(b, mem_a);
    graph(f.buffer_mut(), r, &s.mem.vec(), 100.0, t.blue);

    let [net_a, hw_a] = halves(row2);
    let net_detail = match p.and_then(|p| p.iface.clone()) {
        Some(i) => format!(
            "{i} ↓ {} ↑ {}",
            fmt::rate(s.rx.last().unwrap_or(0.0)),
            fmt::rate(s.tx.last().unwrap_or(0.0))
        ),
        None => "…".into(),
    };
    let b = panel(t, "Network", net_detail);
    let r = inner(&b, net_a);
    f.render_widget(b, net_a);
    let rx = s.rx.vec();
    let max = rx.iter().cloned().fold(1.0, f64::max);
    graph(f.buffer_mut(), r, &rx, max, t.cyan);
    let b = panel(t, "Hardware", "");
    let r = inner(&b, hw_a);
    f.render_widget(b, hw_a);
    let mut hw = Vec::new();
    match &s.temp.value {
        Some(Some(c)) => hw.push(Line::from(vec![
            Span::styled("CPU  ", t.dim()),
            Span::styled(
                format!("{:.0}°C", c.c),
                t.s(if c.c >= v.cfg.thresholds.cpu_temp {
                    t.red
                } else {
                    t.fg
                }),
            ),
        ])),
        Some(None) => hw.push(Line::styled("CPU  no temperature sensor", t.dim())),
        None => {}
    }
    if let Some(Some(g)) = &s.gpu.value {
        hw.push(Line::from(vec![
            Span::styled("GPU  ", t.dim()),
            Span::styled(
                format!(
                    "{} · {:.0}°C · {:.0}% · VRAM {}/{} GiB",
                    g.name,
                    g.temp,
                    g.util,
                    g.vram_used_mib / 1024,
                    g.vram_total_mib / 1024
                ),
                t.s(if g.temp >= v.cfg.thresholds.gpu_temp {
                    t.red
                } else {
                    t.fg
                }),
            ),
        ]));
    }
    f.render_widget(Paragraph::new(hw), r);

    let [disk_a, status_a] = halves(row3);
    let b = panel(t, "Disks", "");
    let r = inner(&b, disk_a);
    f.render_widget(b, disk_a);
    let mut lines = Vec::new();
    match &s.disks.value {
        Some(mounts) => {
            let w = r.width.saturating_sub(30).clamp(6, 30);
            for m in mounts {
                let pct = m.pct();
                let rule = v.cfg.disks.iter().find(|d| d.mount == m.target);
                let c = match rule {
                    Some(d) if pct >= d.crit as f64 => t.red,
                    Some(d) if pct >= d.warn as f64 => t.yellow,
                    _ => t.load(pct),
                };
                let mut sp = vec![Span::styled(
                    format!("{:<12} ", trunc(&m.target, 12)),
                    t.fg(),
                )];
                sp.extend(bar(t, pct, w, c));
                sp.push(Span::styled(
                    format!(" {pct:>3.0}% {}", fmt::bytes_short(m.size)),
                    t.dim(),
                ));
                lines.push(Line::from(sp));
            }
            for d in &v.cfg.disks {
                if !mounts.iter().any(|m| m.target == d.mount) {
                    lines.push(Line::styled(
                        format!("{:<12} not mounted", trunc(&d.mount, 12)),
                        t.s(t.red),
                    ));
                }
            }
        }
        None => lines.push(waiting(v, &s.disks, "disks")),
    }
    if let Some(sm) = &s.smart.value {
        let mut sp = vec![Span::styled("SMART  ", t.dim())];
        for res in sm {
            match res {
                Ok(d) => {
                    let bad =
                        d.health == SmartHealth::Failed || d.bad_sectors > 0 || d.uncorrectable > 0;
                    let c = if bad {
                        t.red
                    } else if d.health == SmartHealth::Passed {
                        t.green
                    } else {
                        t.dim
                    };
                    let temp = d.temp_c.map_or(String::new(), |c| format!(" {c}°C"));
                    sp.push(Span::styled(
                        format!(
                            "{} {}{temp}   ",
                            d.dev.trim_start_matches("/dev/"),
                            if bad {
                                "damaged"
                            } else {
                                smart_word(&d.health)
                            }
                        ),
                        t.s(c),
                    ));
                }
                Err(e) => sp.push(Span::styled(format!("{e}   "), t.dim())),
            }
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(sp));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), r);

    let b = panel(t, "Status", "");
    let r = inner(&b, status_a);
    f.render_widget(b, status_a);
    let rows: Vec<Line> = status_rows(v)
        .into_iter()
        .enumerate()
        .map(|(i, row)| {
            let style = if i == v.cur {
                ratatui::style::Style::new().bg(t.sel_bg)
            } else {
                ratatui::style::Style::new()
            };
            Line::from(vec![
                Span::styled(format!("{} ", row.icon), t.s(row.color)),
                Span::styled(trunc(&row.text, r.width.saturating_sub(4) as usize), t.fg()),
            ])
            .style(style)
        })
        .collect();
    f.render_widget(Paragraph::new(rows), r);
}

// ---------- Services ----------

struct UnitLine {
    unit: String,
    state: String,
    state_color: Color,
    last: String,
    next: String,
    result: String,
}

fn unit_rows(v: &View) -> Vec<UnitLine> {
    let t = v.t;
    let Some(u) = &v.s.units.value else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for svc in &v.cfg.services {
        let (state, c, result) = match u.get(svc) {
            Some(st) if st.load == "not-found" => {
                ("not installed".to_string(), t.red, String::new())
            }
            Some(st) => (
                format!("{} ({})", st.active, st.sub),
                if st.active == "active" {
                    t.green
                } else {
                    t.red
                },
                st.result.clone(),
            ),
            None => ("?".into(), t.dim, String::new()),
        };
        out.push(UnitLine {
            unit: svc.clone(),
            state,
            state_color: c,
            last: String::new(),
            next: String::new(),
            result,
        });
    }
    for rule in &v.cfg.timers {
        let Some(st) = u.get(&rule.unit) else {
            continue;
        };
        let ran = st.triggers.as_deref().and_then(|x| u.get(x));
        let failed = ran.is_some_and(|r| !r.result.is_empty() && r.result != "success");
        let age = st.last_trigger.map(|l| v.secs_since(l));
        let stale = age.is_none_or(|a| a > rule.max_age.0.as_secs() as i64);
        out.push(UnitLine {
            unit: rule.unit.clone(),
            state: format!("{} ({})", st.active, st.sub),
            state_color: if failed || stale { t.red } else { t.green },
            last: age.map_or("never".into(), fmt::ago),
            next: st
                .next
                .map_or("-".into(), |n| format!("in {}", fmt::age(-v.secs_since(n)))),
            result: ran.map_or(String::new(), |r| match r.exit {
                Some(c) if r.result != "success" => format!("{} (exit {c})", r.result),
                _ => r.result.clone(),
            }),
        });
    }
    for row in u.failed() {
        if v.cfg.services.contains(&row.unit) {
            continue;
        }
        out.push(UnitLine {
            unit: row.unit.clone(),
            state: format!("failed ({})", row.sub),
            state_color: t.red,
            last: String::new(),
            next: String::new(),
            result: row.description.clone(),
        });
    }
    out.retain(|u| v.matches(&[&u.unit, &u.state, &u.result]));
    out
}

fn services(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let b = panel(
        t,
        "Services and timers",
        format!("{} watched", v.cfg.services.len() + v.cfg.timers.len()),
    );
    let r = inner(&b, area);
    f.render_widget(b, area);
    if v.s.units.value.is_none() {
        f.render_widget(Paragraph::new(waiting(v, &v.s.units, "systemd units")), r);
        return;
    }
    let rows: Vec<Row> = unit_rows(v)
        .into_iter()
        .map(|u| {
            Row::new(vec![
                Cell::from(u.unit).style(t.fg()),
                Cell::from(u.state).style(t.s(u.state_color)),
                Cell::from(u.last).style(t.dim()),
                Cell::from(u.next).style(t.dim()),
                Cell::from(u.result).style(t.dim()),
            ])
        })
        .collect();
    widgets::table(
        f,
        r,
        t,
        TableSpec {
            header: vec!["Unit", "State", "Last run", "Next", "Result"],
            widths: vec![
                Constraint::Fill(2),
                Constraint::Length(20),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Fill(1),
            ],
            rows,
            selected: Some(v.cur),
        },
    );
}

fn unit_detail(v: &View) -> Vec<Effect> {
    let Some(row) = unit_rows(v).into_iter().nth(v.cur) else {
        return Vec::new();
    };
    let t = v.t;
    let mut lines = vec![Line::styled(format!("state   {}", row.state), t.fg())];
    if let Some(st) = v.s.units.value.as_ref().and_then(|u| u.get(&row.unit)) {
        lines.push(Line::styled(
            format!(
                "result  {} (exit {})",
                st.result,
                st.exit.map_or("-".into(), |e| e.to_string())
            ),
            t.fg(),
        ));
        if let Some(l) = st.last_trigger {
            lines.push(Line::styled(
                format!("last    {l} ({})", fmt::ago(v.secs_since(l))),
                t.fg(),
            ));
        }
        if let Some(svc) = &st.triggers {
            lines.push(Line::styled(format!("runs    {svc}"), t.fg()));
        }
    }
    let ident = row
        .unit
        .trim_end_matches(".timer")
        .trim_end_matches(".service");
    if let Some(j) = v.s.journal.value.as_ref().and_then(|js| {
        js.iter()
            .find(|j| j.ident.trim_end_matches(".service") == ident)
    }) {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!("{} error(s) in 24 h; last:", j.count),
            t.s(t.yellow),
        ));
        lines.push(Line::styled(j.last.clone(), t.dim()));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!("journalctl -u {} -n 50", row.unit),
        t.dim(),
    ));
    vec![Effect::Info(row.unit, lines)]
}

// ---------- Containers ----------

fn containers(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let Some(d) = &v.s.docker.value else {
        let b = panel(t, "Containers", "");
        let r = inner(&b, area);
        f.render_widget(b, area);
        let text = match &v.s.docker.err {
            Some(crate::server::remote::SrvError::SudoPassword(_)) => {
                needs_password(v, "the containers")
            }
            _ => vec![waiting(v, &v.s.docker, "docker")],
        };
        f.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), r);
        return;
    };
    let projects = d
        .projects
        .iter()
        .map(|p| format!("{} {}", p.name, p.status))
        .collect::<Vec<_>>()
        .join(" · ");
    let b = panel(t, "Containers", format!("{projects}{}", v.inv_note()));
    let r = inner(&b, area);
    f.render_widget(b, area);
    let stats = v.s.stats.value.as_ref();
    let rows: Vec<Row> = container_list(v)
        .into_iter()
        .map(|c| {
            let (state_c, health_c) = (
                if c.status == "running" {
                    t.green
                } else if c.finished() {
                    t.dim
                } else {
                    t.red
                },
                match c.health.as_deref() {
                    Some("healthy") => t.green,
                    Some("unhealthy") => t.red,
                    _ => t.dim,
                },
            );
            let st = stats.and_then(|s| s.iter().find(|s| s.name == c.name));
            let ports = c
                .ports
                .iter()
                .filter(|(ip, _, _)| ip != "::")
                .map(|(ip, hp, inner)| {
                    let ip = if ip == "0.0.0.0" { "" } else { ip.as_str() };
                    format!("{ip}:{hp}→{}", inner.trim_end_matches("/tcp"))
                })
                .collect::<Vec<_>>()
                .join(" ");
            Row::new(vec![
                Cell::from(c.name.clone()).style(t.fg()),
                Cell::from(c.compose.clone().unwrap_or_else(|| "-".into())).style(t.dim()),
                Cell::from(if c.finished() {
                    "done".to_string()
                } else {
                    c.status.clone()
                })
                .style(t.s(state_c)),
                Cell::from(c.health.clone().unwrap_or_else(|| "-".into())).style(t.s(health_c)),
                Cell::from(c.restarts.to_string()).style(t.dim()),
                Cell::from(c.started_at.map_or("-".into(), |s| {
                    fmt::age(v.secs_since(s)).replace("just now", "now")
                }))
                .style(t.dim()),
                Cell::from(ports).style(t.dim()),
                Cell::from(st.map_or(String::new(), |s| format!("{:.1}%", s.cpu_pct)))
                    .style(t.fg()),
                Cell::from(st.map_or(String::new(), |s| {
                    s.mem.split(" / ").next().unwrap_or("").to_string()
                }))
                .style(t.fg()),
            ])
        })
        .collect();
    widgets::table(
        f,
        r,
        t,
        TableSpec {
            header: vec![
                "Name", "Project", "State", "Health", "Restarts", "Up", "Ports", "CPU", "Mem",
            ],
            widths: vec![
                Constraint::Fill(2),
                Constraint::Fill(1),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Fill(3),
                Constraint::Length(6),
                Constraint::Length(9),
            ],
            rows,
            selected: Some(v.cur),
        },
    );
}

/// Containers in table order, filtered.
fn container_list<'a>(v: &View<'a>) -> Vec<&'a Container> {
    let Some(d) = &v.s.docker.value else {
        return Vec::new();
    };
    d.containers
        .iter()
        .filter(|c| {
            v.matches(&[
                &c.name,
                &c.image,
                &c.status,
                c.compose.as_deref().unwrap_or(""),
                c.health.as_deref().unwrap_or(""),
            ])
        })
        .collect()
}

pub fn selected_container<'a>(v: &View<'a>) -> Option<&'a Container> {
    container_list(v).get(v.cur).copied()
}

fn container_detail(v: &View) -> Vec<Effect> {
    let Some(c) = selected_container(v) else {
        return Vec::new();
    };
    let t = v.t;
    let mut lines = vec![
        Line::styled(format!("image     {}", c.image), t.fg()),
        Line::styled(
            format!(
                "state     {} (exit {}){}",
                c.status,
                c.exit_code,
                if c.oom {
                    " · killed: out of memory"
                } else {
                    ""
                }
            ),
            t.fg(),
        ),
        Line::styled(
            format!(
                "health    {}",
                c.health.as_deref().unwrap_or("no health check")
            ),
            t.fg(),
        ),
        Line::styled(format!("restarts  {}", c.restarts), t.fg()),
    ];
    if let Some(s) = c.started_at {
        lines.push(Line::styled(
            format!("started   {s} ({})", fmt::ago(v.secs_since(s))),
            t.fg(),
        ));
    }
    for (ip, hp, inner) in &c.ports {
        lines.push(Line::styled(
            format!("port      {ip}:{hp} → {inner}"),
            t.fg(),
        ));
    }
    if c.docker_sock {
        lines.push(Line::styled(
            "mounts /var/run/docker.sock: can control docker (root on the host)",
            t.s(t.yellow),
        ));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!("docker logs --tail 50 {}", c.name),
        t.dim(),
    ));
    vec![Effect::Info(c.name.clone(), lines)]
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

// ---------- findings ----------

pub fn finding_lines(t: &Theme, x: &Finding) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        x.message.clone(),
        t.s(if x.expected {
            t.dim
        } else {
            sev_color(t, x.severity)
        }),
    )];
    for (label, text) in [("What", &x.what), ("Why", &x.why), ("Fix", &x.fix)] {
        if !text.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled(format!("{label}  "), t.dim()),
                Span::styled(text.clone(), t.fg()),
            ]));
        }
    }
    if !x.evidence.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(x.evidence.clone(), t.dim()));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!(
            "{}{}",
            x.id,
            if x.expected {
                " · expected (x to undo)"
            } else {
                ""
            }
        ),
        t.dim(),
    ));
    lines
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
    status_rows(v)
        .into_iter()
        .map(|r| format!("{} {}", r.icon, r.text))
        .collect()
}

pub fn selected_unit(v: &View) -> Option<String> {
    unit_rows(v).into_iter().nth(v.cur).map(|u| u.unit)
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

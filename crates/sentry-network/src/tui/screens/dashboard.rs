//! The Dashboard: the router at a glance. What it is and how loaded, its uplink (address,
//! lease, IPv6), and a row per port and radio with link, speed and how fast it moves data
//! now. Everything here is read by the probe (1 Hz) and the interfaces read (30 s).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::{Hints, View, span};
use crate::collect::ifaces::{DevKind, Ifaces, LeaseLeft};
use crate::rates::{self, Rate};
use crate::tui::data::{Kind, Ring};
use crate::tui::target::{Effect, Own};
use sentry_core::fmt;
use sentry_core::tui::keys::Action;
use sentry_core::tui::widgets::{bar, graph, inner, panel, trunc};

pub fn hints() -> Hints {
    vec![("r", "read again")]
}

pub fn handle(a: Action) -> Vec<Effect> {
    match a {
        Action::Refresh | Action::Check => vec![
            Own::fetch(Kind::Probe),
            Own::fetch(Kind::Ifaces),
            Own::fetch(Kind::Services),
            Own::fetch(Kind::Report),
        ],
        _ => Vec::new(),
    }
}

/// The Status panel: what is known cheaply besides the load. Who is on the network (from
/// the last time the clients were read), the services the network depends on, the last
/// audit, and the web interface's certificate. A row is there once its part was read.
fn status_lines(v: &View, w: usize) -> Vec<Line<'static>> {
    let t = v.t;
    let s = v.s;
    let room = w.saturating_sub(9);
    let mut lines = Vec::new();
    if let Some((there, wired, wifi, new)) = super::clients::counts(v) {
        let mut sp = vec![
            label(t, "clients"),
            Span::styled(
                fit(
                    &format!("{there}"),
                    &format!(" · {wired} wired · {wifi} Wi-Fi"),
                    room.saturating_sub(8),
                ),
                t.fg(),
            ),
        ];
        if new > 0 {
            sp.push(Span::styled(format!(" · {new} new"), t.s(t.yellow)));
        }
        lines.push(Line::from(sp));
    }
    if let Some(sv) = &s.services.value {
        use crate::collect::services::State;
        let mut sp = vec![label(t, "services")];
        let mut used = 0;
        for name in sv.watched(&v.cfg.expect.services) {
            let (dot, c) = match sv.state(name) {
                State::Running | State::NotADaemon => ("●", t.green),
                State::Down | State::Missing => ("○", t.red),
            };
            used += name.chars().count() + 3;
            if used > room {
                break;
            }
            sp.push(Span::styled(format!("{dot} "), t.s(c)));
            sp.push(Span::styled(format!("{name} "), t.fg()));
        }
        lines.push(Line::from(sp));
    }
    // CrowdSec's firewall bouncer, only where the router has it: how many addresses it
    // blocks now (a count: the addresses themselves never leave the router).
    if let Some(Some(b)) = &s.crowdsec.value {
        use crate::collect::services::State;
        let running = s
            .services
            .value
            .as_ref()
            .map(|sv| sv.state(crate::collect::crowdsec::SERVICE) == State::Running);
        let (said, c) = match (running, b.blocked()) {
            (Some(false), _) if b.on() => ("○ not running".to_string(), t.red),
            (Some(false) | None, _) if !b.on() => ("not switched on".to_string(), t.dim),
            (_, Some(n)) => (format!("{n} blocked"), t.fg),
            (_, None) => ("running".to_string(), t.fg),
        };
        lines.push(Line::from(vec![
            label(t, "crowdsec"),
            Span::styled(said, t.s(c)),
        ]));
    }
    // What flows through, from the last time Security read it (nothing is read for this).
    if let Some((said, grave)) = super::security::status(v) {
        // (Where the panel is narrow the uplink goes without saying.)
        let said = if said.chars().count() > room {
            said.replace("WAN rejects", "rejects")
        } else {
            said
        };
        lines.push(Line::from(vec![
            label(t, "security"),
            Span::styled(trunc(&said, room), t.s(if grave { t.red } else { t.fg })),
        ]));
    }
    if let Some(rep) = &s.report.value {
        let line = match rep.as_deref() {
            None => Line::from(vec![label(t, "audit"), Span::styled("none yet", t.dim())]),
            Some(r) => {
                let open = |sev| r.open().filter(|f| f.severity == sev).count();
                use sentry_core::finding::Sev;
                let (check, review) = (open(Sev::High), open(Sev::Medium));
                let (said, c) = match (check, review) {
                    (0, 0) => ("✓ nothing to check".to_string(), t.green),
                    (0, n) => (format!("{n} to review"), t.yellow),
                    (n, 0) => (format!("{n} to check"), t.red),
                    (n, m) => (format!("{n} to check · {m} to review"), t.red),
                };
                let when = r.snapshot.taken_at.map_or(String::new(), |at| {
                    format!(" · {}", fmt::ago(v.secs_since(at)))
                });
                Line::from(vec![
                    label(t, "audit"),
                    Span::styled(said.clone(), t.s(c)),
                    Span::styled(
                        fit("", &when, room.saturating_sub(said.chars().count())),
                        t.dim(),
                    ),
                ])
            }
        };
        lines.push(line);
    }
    if let Some(Some(c)) = &s.cert.value {
        let days = c.days_left(v.now);
        let (said, color) = match days {
            d if d < 0 => (format!("ended {} days ago", -d), t.red),
            d if d <= v.cfg.thresholds.cert_days as i64 => (format!("ends in {d} days"), t.yellow),
            d => (format!("{d} days left"), t.fg),
        };
        lines.push(Line::from(vec![
            label(t, "cert"),
            Span::styled(said, t.s(color)),
        ]));
    }
    lines
}

/// One row of the Ports panel.
#[derive(Debug, Clone, PartialEq)]
pub struct PortRow {
    pub name: String,
    /// The logical interface it belongs to (`wan`, `lan`), once known.
    pub net: Option<String>,
    pub wireless: bool,
    /// Link: None where it isn't known.
    pub link: Option<bool>,
    /// Mbit/s.
    pub speed: Option<u32>,
    /// None: no rate yet (the first sample, a reset counter, a reboot).
    pub rate: Option<Rate>,
}

/// The rows: the uplink's port, the wired ports, the radios. Link and speed are the probe's
/// (each second); which interfaces are ports, and whose, is the interfaces read's. Until
/// that has arrived, every interface the kernel has but the loopback.
pub fn port_rows(v: &View) -> Vec<PortRow> {
    let Some(p) = v.s.probe.value.as_ref() else {
        return Vec::new();
    };
    let port = |name: &str| p.ports.iter().find(|x| x.name == name);
    match v.s.ifaces.value.as_ref() {
        Some(i) => i
            .rows()
            .into_iter()
            .map(|d| {
                let live = port(&d.name);
                PortRow {
                    name: d.name.clone(),
                    net: i.net_of(&d.name).map(str::to_string),
                    wireless: d.kind == DevKind::Wireless,
                    link: live.map_or(Some(d.carrier), |x| x.carrier),
                    speed: live.map_or(d.speed, |x| x.speed),
                    rate: v.s.rate.get(&d.name).copied(),
                }
            })
            .collect(),
        None => p
            .ports
            .iter()
            .filter(|x| x.name != "lo")
            .map(|x| PortRow {
                name: x.name.clone(),
                net: None,
                wireless: false,
                link: x.carrier,
                speed: x.speed,
                rate: v.s.rate.get(&x.name).copied(),
            })
            .collect(),
    }
}

/// A rate for a narrow column, bits per second: `12.3 M`, `412 k`, `2.35 G`, `0`.
fn short(bps: f64) -> String {
    rates::bits(bps)
        .trim_end_matches("bit/s")
        .trim_end()
        .to_string()
}

const EIGHTHS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// The last `w` samples as one row of eighth-blocks, newest at the right, scaled to the
/// largest shown (never to less than 10 kbit/s, so an idle port stays flat).
fn spark(ring: Option<&Ring>, w: usize) -> String {
    spark_from(ring, w, 10_000.0)
}

/// The same for any series: `floor` is the least the row's full height stands for.
pub(super) fn spark_from(ring: Option<&Ring>, w: usize, floor: f64) -> String {
    let data: Vec<f64> = ring.map(Ring::vec).unwrap_or_default();
    let shown = &data[data.len().saturating_sub(w)..];
    let max = shown.iter().copied().fold(floor, f64::max);
    let mut out: String = " ".repeat(w - shown.len());
    out.extend(shown.iter().map(|v| {
        let level = ((v / max).clamp(0.0, 1.0) * 8.0).round() as usize;
        match level {
            0 => ' ',
            l => EIGHTHS[l - 1],
        }
    }));
    out
}

/// `base` with `more` after it when both fit in `room`; else `base` alone, cut if it must be.
fn fit(base: &str, more: &str, room: usize) -> String {
    if base.chars().count() + more.chars().count() <= room {
        format!("{base}{more}")
    } else {
        trunc(base, room)
    }
}

fn label(t: &sentry_core::tui::theme::Theme, name: &str) -> Span<'static> {
    Span::styled(format!("{name:<9}"), t.dim())
}

fn router_lines(v: &View, w: usize) -> Vec<Line<'static>> {
    let t = v.t;
    let s = v.s;
    let mut lines = Vec::new();
    if let Some((_, why)) = &s.unreachable {
        lines.push(Line::styled(
            trunc(&format!("can't reach {}: {why}", v.name), w),
            t.s(t.red),
        ));
    }
    if s.rebooted() {
        lines.push(Line::styled(
            "the router rebooted since this was opened",
            t.s(t.mag),
        ));
    }
    let room = w.saturating_sub(9);
    match (&s.ifaces.value, &s.ifaces.err) {
        (Some(i), _) => {
            let b = &i.board;
            lines.push(Line::from(vec![
                label(t, "release"),
                Span::styled(
                    fit(
                        &format!("{} {}", b.distribution, b.version),
                        &format!(" ({})", b.revision),
                        room,
                    ),
                    t.fg(),
                ),
            ]));
            lines.push(Line::from(vec![
                label(t, "board"),
                Span::styled(fit(&b.model, &format!(" · {}", b.target), room), t.fg()),
            ]));
        }
        (None, Some(e)) => lines.push(Line::styled(trunc(&e.to_string(), w), t.s(t.yellow))),
        (None, None) => {}
    }
    let Some(p) = &s.probe.value else {
        if let Some(e) = &s.probe.err {
            lines.push(Line::styled(trunc(&e.to_string(), w), t.s(t.yellow)));
        } else if s.unreachable.is_none() {
            lines.push(Line::styled("reading…", t.dim()));
        }
        return lines;
    };
    let h = &p.host;
    let kernel = s
        .ifaces
        .value
        .as_ref()
        .map_or(String::new(), |i| format!(" · kernel {}", i.board.kernel));
    lines.push(Line::from(vec![
        label(t, "up"),
        Span::styled(fit(&fmt::uptime(h.uptime_s), &kernel, room), t.fg()),
    ]));
    let load = format!("{:.2} {:.2} {:.2}", h.load[0], h.load[1], h.load[2]);
    let cpu = s
        .cpu
        .last()
        .map(|c| format!(" · cpu {c:.0}%"))
        .filter(|c| load.len() + c.chars().count() <= room)
        .unwrap_or_default();
    let temp = p
        .temp_c
        .map(|c| format!(" · {c:.0}°C"))
        .filter(|x| load.len() + cpu.chars().count() + x.chars().count() <= room)
        .unwrap_or_default();
    lines.push(Line::from(vec![
        label(t, "load"),
        Span::styled(
            load,
            t.s(if h.load[0] >= v.cfg.thresholds.load {
                t.red
            } else {
                t.fg
            }),
        ),
        Span::styled(format!("{cpu}{temp}"), t.dim()),
    ]));
    // A bar, the share and what it's of: `████░░░░  21% of 986 MiB`.
    let gauge = |name: &str, pct: f64, of: u64, color: Color| {
        let tail = if room < 26 {
            format!(" {pct:>3.0}% of {}", fmt::bytes_short(of))
        } else {
            format!(" {pct:>3.0}% of {}", fmt::bytes(of))
        };
        let bw = room.saturating_sub(tail.chars().count()).clamp(4, 24) as u16;
        let mut sp = vec![label(t, name)];
        sp.extend(bar(t, pct, bw, color));
        sp.push(Span::styled(tail, t.dim()));
        Line::from(sp)
    };
    let mem = h.mem_used_pct() as f64;
    lines.push(gauge(
        "memory",
        mem,
        h.mem_total_kib * 1024,
        if mem >= v.cfg.thresholds.mem_pct as f64 {
            t.red
        } else {
            t.load(mem)
        },
    ));
    if let Some((i, pct)) = s
        .ifaces
        .value
        .as_ref()
        .and_then(|i| Some((i, i.info.root_pct()?)))
    {
        lines.push(gauge(
            "flash",
            pct as f64,
            i.info.root_total_kib * 1024,
            t.load(pct as f64),
        ));
    }
    lines
}

/// The WAN panel: its state for the title, and its lines.
fn wan_lines(v: &View, i: &Ifaces, w: usize) -> (String, Vec<Line<'static>>) {
    let t = v.t;
    let room = w.saturating_sub(9);
    let row = |name: &str, text: String| {
        Line::from(vec![
            label(t, name),
            Span::styled(trunc(&text, room), t.fg()),
        ])
    };
    let mut lines = Vec::new();
    let state = match i.wan() {
        None => {
            lines.push(Line::styled("no uplink interface found", t.dim()));
            String::new()
        }
        Some(wan) if !wan.up => {
            lines.push(Line::from(vec![
                label(t, "address"),
                Span::styled("● down", t.s(t.red)),
                Span::styled(format!(" · {} on {}", wan.proto, wan.device), t.dim()),
            ]));
            "down".to_string()
        }
        Some(wan) => {
            lines.push(match wan.ipv4.first() {
                Some(a) => row("address", a.clone()),
                None => Line::from(vec![
                    label(t, "address"),
                    Span::styled("none yet", t.s(t.yellow)),
                ]),
            });
            if let Some(g) = &wan.gateway {
                lines.push(row("gateway", g.clone()));
            }
            match (wan.lease_time_s, wan.lease_left()) {
                (Some(lease), Some(LeaseLeft::Exact(left))) => lines.push(row(
                    "lease",
                    format!("{} · {} left", span(lease), span(left)),
                )),
                (Some(lease), Some(LeaseLeft::Between(lo, hi))) => lines.push(row(
                    "lease",
                    format!("{} · renewed, {}–{} left", span(lease), span(lo), span(hi)),
                )),
                _ => {}
            }
            if !wan.dns.is_empty() {
                lines.push(row("dns", wan.dns.join(", ")));
            }
            format!("up {}", span(wan.uptime_s))
        }
    };
    if let Some(w6) = i.wan6() {
        let text = match (w6.up, w6.ipv6.first(), w6.prefixes.first()) {
            (false, _, _) => None,
            (_, Some(a), Some(p)) => Some(format!("{a} · prefix {p}")),
            (_, Some(a), None) => Some(a.clone()),
            (_, None, Some(p)) => Some(format!("prefix {p}")),
            (_, None, None) => Some("up, no address".to_string()),
        };
        lines.push(match text {
            Some(x) => row("IPv6", x),
            None => Line::from(vec![label(t, "IPv6"), Span::styled("● down", t.s(t.red))]),
        });
    }
    (state, lines)
}

fn ports_panel(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let rows = port_rows(v);
    let up = rows.iter().filter(|r| r.link == Some(true)).count();
    let detail = if rows.is_empty() {
        String::new()
    } else {
        format!("{up} of {} up", rows.len())
    };
    let b = panel(t, "Ports", detail);
    let r = inner(&b, area);
    f.render_widget(b, area);
    if rows.is_empty() {
        let why = match (&v.s.probe.err, &v.s.unreachable) {
            (Some(e), _) => e.to_string(),
            (None, Some(_)) => "not reachable".to_string(),
            (None, None) => "reading…".to_string(),
        };
        f.render_widget(Paragraph::new(Line::styled(why, t.dim())), r);
        return;
    }
    // port 9 · net 4 · link 10 · ↓ 8 · ↑ 8, then the sparkline in what's left (6 or more).
    let fixed = 9 + 4 + 10 + 8 + 8;
    let sw = (r.width as usize).saturating_sub(fixed + 1);
    let sw = if sw >= 6 { sw.min(60) } else { 0 };
    let mut lines = vec![Line::styled(
        format!(
            "{:<9}{:<4}{:<10}{:>8}{:>8}{}",
            "port",
            "net",
            "link",
            "↓ bit/s",
            "↑ bit/s",
            if sw >= 9 { "  in + out" } else { "" }
        ),
        t.dim(),
    )];
    for row in rows {
        let (dot, word, color) = match (row.link, row.speed, row.wireless) {
            (Some(false), _, _) => ("○", "no link".to_string(), t.dim),
            (None, _, _) => ("○", "down".to_string(), t.dim),
            (Some(true), Some(m), _) => ("●", rates::speed(m), t.green),
            (Some(true), None, true) => ("●", "wifi".to_string(), t.green),
            (Some(true), None, false) => ("●", "up".to_string(), t.green),
        };
        let rate = |x: Option<f64>| match x {
            Some(b) => format!("{:>8}", short(b)),
            None => format!("{:>8}", "–"),
        };
        let quiet = row.link != Some(true);
        let mut sp = vec![
            Span::styled(
                format!("{:<9}", trunc(&row.name, 8)),
                if quiet { t.dim() } else { t.fg() },
            ),
            Span::styled(
                format!("{:<4}", trunc(row.net.as_deref().unwrap_or(""), 3)),
                t.s(if row.net.as_deref() == Some("wan") {
                    t.cyan
                } else {
                    t.dim
                }),
            ),
            Span::styled(format!("{dot} "), t.s(color)),
            Span::styled(
                format!("{:<8}", trunc(&word, 7)),
                if quiet { t.dim() } else { t.fg() },
            ),
            Span::styled(rate(row.rate.map(|r| r.rx)), t.fg()),
            Span::styled(rate(row.rate.map(|r| r.tx)), t.fg()),
        ];
        if sw > 0 {
            sp.push(Span::raw(" "));
            sp.push(Span::styled(
                spark(v.s.traffic.get(&row.name), sw),
                t.s(t.cyan),
            ));
        }
        lines.push(Line::from(sp));
    }
    f.render_widget(Paragraph::new(lines), r);
}

pub fn render(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let s = v.s;
    let left_w = if area.width < 100 {
        30
    } else {
        (area.width * 2 / 5).min(56)
    };
    let [left, right] =
        Layout::horizontal([Constraint::Length(left_w), Constraint::Fill(1)]).areas(area);
    let w = left_w.saturating_sub(4) as usize;

    let router = router_lines(v, w);
    let (wan_state, wan) = match &s.ifaces.value {
        Some(i) => wan_lines(v, i, w),
        None => (String::new(), Vec::new()),
    };
    let router_h = (router.len() as u16 + 2).max(3);
    let wan_h = if wan.is_empty() {
        0
    } else {
        wan.len() as u16 + 2
    };
    let status = status_lines(v, w);
    let status_h = if status.is_empty() {
        0
    } else {
        status.len() as u16 + 2
    };
    let [router_a, wan_a, status_a, rest] = Layout::vertical([
        Constraint::Length(router_h),
        Constraint::Length(wan_h),
        Constraint::Length(status_h),
        Constraint::Fill(1),
    ])
    .areas(left);
    if status_h > 0 {
        let b = panel(t, "Status", "");
        let r = inner(&b, status_a);
        f.render_widget(b, status_a);
        f.render_widget(Paragraph::new(status), r);
    }
    let b = panel(t, "Router", v.name.to_string());
    let r = inner(&b, router_a);
    f.render_widget(b, router_a);
    f.render_widget(Paragraph::new(router), r);
    if wan_h > 0 {
        let b = panel(t, "WAN", wan_state);
        let r = inner(&b, wan_a);
        f.render_widget(b, wan_a);
        f.render_widget(Paragraph::new(wan), r);
    }
    // Room to spare below: CPU over time, and the uplink's traffic under it.
    if rest.height >= 4 && s.probe.value.is_some() {
        let two = rest.height >= 10;
        let [cpu_a, up_a] = Layout::vertical(if two {
            [Constraint::Percentage(50), Constraint::Percentage(50)]
        } else {
            [Constraint::Fill(1), Constraint::Length(0)]
        })
        .areas(rest);
        let cpu = s.cpu.last().unwrap_or(0.0);
        let b = panel(t, "CPU", format!("{cpu:.0}%"));
        let r = inner(&b, cpu_a);
        f.render_widget(b, cpu_a);
        graph(f.buffer_mut(), r, &s.cpu.vec(), 100.0, t.load(cpu));
        if two {
            let dev = s.probe.value.as_ref().and_then(|p| p.host.iface.clone());
            let rate = dev.as_ref().and_then(|d| s.rate.get(d));
            let detail = match (&dev, rate) {
                (Some(d), Some(r)) => {
                    format!("{d} ↓ {} ↑ {}", rates::bits(r.rx), rates::bits(r.tx))
                }
                (Some(d), None) => d.clone(),
                (None, _) => "no default route".to_string(),
            };
            let b = panel(t, "Uplink", detail);
            let r = inner(&b, up_a);
            f.render_widget(b, up_a);
            let data = dev
                .and_then(|d| s.traffic.get(&d))
                .map(Ring::vec)
                .unwrap_or_default();
            let max = data.iter().copied().fold(10_000.0, f64::max);
            graph(f.buffer_mut(), r, &data, max, t.cyan);
        }
    }
    ports_panel(f, right, v);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rows_sparkline_is_the_newest_samples_scaled_to_the_largest() {
        let mut r = Ring::default();
        for v in [0.0, 1e6, 2e6, 4e6, 8e6] {
            r.push(v);
        }
        assert_eq!(spark(Some(&r), 5), " ▁▂▄█");
        // Wider than what there is: the newest stays at the right.
        assert_eq!(spark(Some(&r), 7), "   ▁▂▄█");
        assert_eq!(spark(Some(&r), 2), "▄█");
        // Idle chatter under 10 kbit/s doesn't fill the row.
        let mut idle = Ring::default();
        idle.push(900.0);
        idle.push(1200.0);
        assert_eq!(spark(Some(&idle), 2), "▁▁");
        assert_eq!(spark(None, 3), "   ");
        assert_eq!(short(12_340_000.0), "12.3 M");
        assert_eq!(short(412_000.0), "412 k");
        assert_eq!(short(0.0), "0");
    }
}

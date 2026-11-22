//! Security: what flows through the router, read only. Ingress (what the outside tried and
//! what came in through the port forwards), Egress (each device's live flows out),
//! Segmentation (the firewall's zone pairs beside what is observed now), DNS and Wi-Fi.
//! The firewall's counters and dnsmasq's are read every 10 s, the flows every 30 s, the log
//! and the packages' own status on entry and `r`; everything is made into one
//! [`Picture`] (`crate::security`), which the Dashboard's row and a brief for Claude share.
//!
//! Nothing here changes the router or touches a device: `r` reads again, `s` sorts, `/`
//! filters, Enter shows one device's flows. What each number is not is in `?` ([`help`])
//! and, where it matters, beside the number.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row};

use super::{Hints, View, span};
use crate::security::{Allowed, Count, Device, Mfp, Picture, Read};
use crate::tui::data::Kind;
use crate::tui::target::{Effect, Own};
use sentry_core::fmt;
use sentry_core::tui::Cursor;
use sentry_core::tui::keys::Action;
use sentry_core::tui::widgets::{self, TableSpec, inner, panel, trunc};

/// How the Egress table is ordered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Sort {
    #[default]
    Flows,
    Bytes,
    Dests,
    Name,
}

impl Sort {
    fn next(self) -> Self {
        match self {
            Sort::Flows => Sort::Bytes,
            Sort::Bytes => Sort::Dests,
            Sort::Dests => Sort::Name,
            Sort::Name => Sort::Flows,
        }
    }
    fn word(self) -> &'static str {
        match self {
            Sort::Flows => "flows",
            Sort::Bytes => "bytes",
            Sort::Dests => "destinations",
            Sort::Name => "name",
        }
    }
}

#[derive(Default)]
pub struct Security {
    /// The list's cursor (what needs attention, then what is shut).
    pub cur: Cursor,
    /// The panels' cursor (Egress's devices).
    pub pcur: Cursor,
    /// The numbers are shown (`d`), not the list.
    pub panels: bool,
    pub sort: Sort,
    /// The list's row at the cursor (its key), kept when the list changes.
    pub sel: Option<String>,
}

/// The panels' keys.
pub fn hints() -> Hints {
    vec![
        ("j/k", "select"),
        ("Enter", "its flows"),
        ("s", "sort"),
        ("/", "filter"),
        ("r", "read again"),
        ("d", "the list"),
    ]
}

/// Everything read again.
pub fn read_again() -> Vec<Effect> {
    vec![
        Own::fetch(Kind::Counters),
        Own::fetch(Kind::Flows),
        Own::fetch(Kind::Clients),
        Own::fetch(Kind::SecLog),
        Own::fetch(Kind::DnsState),
        Own::fetch(Kind::Uci),
        Own::fetch(Kind::Ifaces),
        Own::fetch(Kind::Listeners),
        Own::fetch(Kind::Services),
    ]
}

/// `?`: each number in a line, with what it is not.
pub fn help() -> Hints {
    vec![
        (
            "rejects",
            "packets from outside nobody asked for: packets, not attackers",
        ),
        (
            "new/min",
            "connections opened (a flow's first packet), never traffic",
        ),
        (
            "since",
            "counters restart when the firewall reloads; that interval is –",
        ),
        (
            "flows",
            "live now, bytes so far; one that ended is gone: no totals",
        ),
        (
            "!",
            "flows out to a port ordinary devices rarely use (Enter: why)",
        ),
        (
            "zones",
            "live flows per pair; blocked tries between inside zones: not counted",
        ),
        (
            "DNS",
            "blocked names are in \"answered locally\"; other DoH can't be seen",
        ),
        (
            "log",
            "counts cover the log's window only; sentry's own logins left out",
        ),
        (
            "keys",
            "r read again · s sort · / filter · Enter a device's flows · d the list",
        ),
    ]
}

/// What was read so far.
pub fn read<'a>(v: &View<'a>) -> Read<'a> {
    let s = v.s;
    Read {
        ifaces: s.ifaces.value.as_ref(),
        uci: s.uci.value.as_ref(),
        clients: s.clients.as_deref(),
        stations: s.raw_clients.value.as_ref().map(|r| &r.stations[..]),
        counters: s.counters.value.as_ref(),
        rated: s.counters.value.as_ref().map(|_| &s.rated),
        flows: s.flows.value.as_ref(),
        log: s.seclog.value.as_ref(),
        dns: s.dnsstate.value.as_ref(),
    }
}

/// The picture of what was read so far.
pub fn picture(v: &View) -> Picture {
    Picture::of(&read(v))
}

/// A count for a narrow column: `902`, `31.2k`, `1.4M`.
pub fn num(n: u64) -> String {
    match n {
        0..=9_999 => n.to_string(),
        10_000..=999_999 => format!("{:.1}k", n as f64 / 1e3),
        _ => format!("{:.1}M", n as f64 / 1e6),
    }
}

/// A rate per minute: `0`, `2.5`, `21`, `140`; `–` when there is none.
pub fn per_min(rate: Option<f64>) -> String {
    match rate.map(|r| r * 60.0) {
        None => "–".into(),
        Some(0.0) => "0".into(),
        Some(m) if m >= 10.0 => format!("{m:.0}"),
        Some(m) => format!("{m:.1}"),
    }
}

/// `a → b`.
fn arrow(a: &str, b: &str) -> String {
    format!("{a}→{b}")
}

/// The devices the filter keeps, in the order asked for.
pub fn rows(v: &View, p: &Picture, sort: Sort) -> Vec<Device> {
    let mut d: Vec<Device> = p
        .devices
        .iter()
        .filter(|d| {
            v.matches(&[
                &d.label,
                &d.key,
                &d.zone,
                &d.top_ports(usize::MAX),
                if d.odd().next().is_some() { "!" } else { "" },
            ])
        })
        .cloned()
        .collect();
    match sort {
        // As the picture has them.
        Sort::Flows => {}
        Sort::Bytes => d.sort_by(|a, b| {
            let all = |x: &Device| x.up.unwrap_or(0) + x.down.unwrap_or(0);
            all(b).cmp(&all(a)).then(a.label.cmp(&b.label))
        }),
        Sort::Dests => d.sort_by(|a, b| b.dests.cmp(&a.dests).then(a.label.cmp(&b.label))),
        Sort::Name => d.sort_by_key(|a| a.label.to_lowercase()),
    }
    d
}

fn bytes(b: Option<u64>) -> String {
    b.map_or("–".into(), fmt::bytes_short)
}

/// Enter's box: one device's live flows, by destination port, with the far ends.
fn detail(v: &View, d: &Device) -> Vec<Line<'static>> {
    let t = v.t;
    let mut l = vec![
        Line::from(vec![
            Span::styled(format!("{:<10}", "zone"), t.dim()),
            Span::styled(d.zone.clone(), t.fg()),
        ]),
        Line::from(vec![
            Span::styled(format!("{:<10}", "now"), t.dim()),
            Span::styled(
                format!(
                    "{} live flow(s) to {} far end(s) · ↑ {} ↓ {} so far",
                    d.flows,
                    d.dests,
                    bytes(d.up),
                    bytes(d.down)
                ),
                t.fg(),
            ),
        ]),
        Line::raw(""),
        Line::styled(
            format!("{:<12}{:>6}  {}", "port", "flows", "far ends"),
            t.dim(),
        ),
    ];
    for f in &d.far {
        let ends: Vec<String> = f.addrs.iter().take(4).map(|a| a.to_string()).collect();
        let more = match f.addrs.len().saturating_sub(4) {
            0 => String::new(),
            n => format!(" +{n}"),
        };
        l.push(Line::from(vec![
            Span::styled(
                format!("{:<12}", format!("{}/{}", f.proto, f.port)),
                t.s(if f.odd.is_some() { t.yellow } else { t.fg }),
            ),
            Span::styled(format!("{:>6}  ", f.flows), t.fg()),
            Span::styled(format!("{}{more}", ends.join(", ")), t.dim()),
        ]));
        if let Some(why) = f.odd {
            l.push(Line::styled(format!("            ! {why}"), t.s(t.yellow)));
        }
    }
    l.push(Line::raw(""));
    l.push(Line::styled(
        "Live flows only: one that ended has left the table, and its bytes with it.",
        t.dim(),
    ));
    l.push(Line::styled(
        "What it sends to the router itself (DNS, DHCP) isn't listed here.",
        t.dim(),
    ));
    l
}

fn label(t: &sentry_core::tui::theme::Theme, name: &str) -> Span<'static> {
    Span::styled(format!("{name:<11}"), t.dim())
}

/// "since 1d ago" for the counters, by the router's own clock.
fn since(v: &View) -> Option<String> {
    let c = v.s.counters.value.as_ref()?;
    // No table, nothing counted: nothing started anywhere.
    c.rules.as_ref()?;
    Some(match c.reset_at {
        Some(at) => format!("since {}", fmt::ago(c.now - at)),
        None => "since the firewall last reloaded".into(),
    })
}

fn window(p: &Picture) -> String {
    match p.log.as_ref().and_then(|l| l.window_s) {
        Some(w) => format!("in the last {}", span(w)),
        None => "in the log".into(),
    }
}

fn total(v: &View, c: Count) -> String {
    match since(v) {
        Some(s) => format!("{} {s}", num(c.total)),
        None => num(c.total),
    }
}

/// Why a part has nothing to show: its error, the connection, or still reading.
fn waiting<T>(v: &View, slot: &crate::tui::data::Slot<T>, what: &str) -> String {
    match (&slot.err, &v.s.unreachable) {
        (Some(e), _) => e.to_string(),
        (None, Some(_)) => "not reachable".into(),
        (None, None) => format!("reading {what}…"),
    }
}

/// `compact`: the logins in one line (a narrow window).
pub fn ingress_lines(v: &View, p: &Picture, w: usize, compact: bool) -> Vec<Line<'static>> {
    let t = v.t;
    let mut l = Vec::new();
    match (p.wan_rejects, &v.s.counters.value) {
        (Some(c), _) => {
            let said = total(v, c);
            let sw = w.saturating_sub(11 + 12 + 1 + said.chars().count()).min(24);
            let mut sp = vec![
                label(t, "rejected"),
                Span::styled(
                    format!("{:<12}", format!("{}/min", per_min(c.rate))),
                    t.fg(),
                ),
            ];
            if sw >= 6 {
                sp.push(Span::styled(
                    super::dashboard::spark_from(Some(&v.s.rejects), sw, 6.0),
                    t.s(t.cyan),
                ));
                sp.push(Span::raw(" "));
            }
            sp.push(Span::styled(said, t.dim()));
            l.push(Line::from(sp));
        }
        (None, Some(c)) if c.rules.is_none() => l.push(Line::from(vec![
            label(t, "rejected"),
            Span::styled("no fw4 table on this router: nothing is counted", t.dim()),
        ])),
        (None, Some(_)) => l.push(Line::from(vec![
            label(t, "rejected"),
            Span::styled("the uplink's reject rule has no counter", t.dim()),
        ])),
        (None, None) => l.push(Line::styled(
            waiting(v, &v.s.counters, "the firewall's counters"),
            t.dim(),
        )),
    }
    if v.s.uci.value.is_some() || !p.forwards.is_empty() {
        let name_w = w.saturating_sub(4 + 11 + 22 + 8 + 7 + 5).clamp(6, 22);
        l.push(Line::styled(
            format!(
                "{:<name_w$}{:<4}{:<11}{:<22}{:>8}{:>7}{:>5}",
                "forward", "", "port", "to", "new/min", "total", "live"
            ),
            t.dim(),
        ));
        for f in &p.forwards {
            let live = f.live.map_or("–".into(), |n| n.to_string());
            l.push(Line::from(vec![
                Span::styled(format!("{:<name_w$}", trunc(&f.name, name_w - 1)), t.fg()),
                Span::styled(format!("{:<4}", trunc(&f.proto, 3)), t.dim()),
                Span::styled(format!("{:<11}", trunc(&f.port, 10)), t.fg()),
                Span::styled(format!("{:<22}", trunc(&f.to, 21)), t.fg()),
                Span::styled(
                    format!("{:>8}", per_min(f.new.and_then(|c| c.rate))),
                    t.fg(),
                ),
                Span::styled(
                    format!("{:>7}", f.new.map_or("–".into(), |c| num(c.total))),
                    t.dim(),
                ),
                Span::styled(
                    format!("{live:>5}"),
                    t.s(if f.live.unwrap_or(0) > 0 {
                        t.cyan
                    } else {
                        t.dim
                    }),
                ),
            ]));
        }
        if p.forwards.is_empty() {
            l.push(Line::styled("no port is forwarded", t.dim()));
        }
    }
    let inbound = p.count(|c| matches!(c, crate::security::Class::Inbound { .. }));
    if inbound > 0 {
        l.push(Line::from(vec![
            label(t, "direct"),
            Span::styled(
                format!("{inbound} flow(s) from outside straight to inside addresses"),
                t.s(t.yellow),
            ),
        ]));
    }
    if let (Some(log), true) = (&p.log, compact) {
        let refused = log.failed();
        l.push(Line::from(vec![
            label(t, "ssh logins"),
            Span::styled(
                format!(
                    "{} from here · {} other",
                    log.ssh_own,
                    log.ssh_known + log.unknown()
                ),
                t.fg(),
            ),
            Span::styled(
                format!(" · {refused} refused"),
                t.s(if refused > 0 { t.red } else { t.dim }),
            ),
            Span::styled(format!(" · {}", window(p)), t.dim()),
        ]));
    } else if let Some(log) = &p.log {
        // Who logged in; then who didn't, and how far back the log goes.
        let mut sp = vec![label(t, "ssh logins")];
        let mut said = vec![format!("{} from here", log.ssh_own)];
        if log.ssh_known > 0 {
            said.push(format!("{} from named devices", log.ssh_known));
        }
        sp.push(Span::styled(said.join(" · "), t.fg()));
        if log.unknown() > 0 {
            sp.push(Span::styled(
                format!(" · {} from elsewhere", log.unknown()),
                t.s(t.yellow),
            ));
        }
        l.push(Line::from(sp));
        let mut sp = vec![label(t, "")];
        match log.failed() {
            0 => sp.push(Span::styled("none refused", t.dim())),
            n => sp.push(Span::styled(format!("{n} refused"), t.s(t.red))),
        }
        if log.ssh_left > 0 {
            sp.push(Span::styled(
                format!(" · {} left before logging in", log.ssh_left),
                t.dim(),
            ));
        }
        sp.push(Span::styled(format!(" · {}", window(p)), t.dim()));
        l.push(Line::from(sp));
    } else if v.s.seclog.err.is_some() {
        l.push(Line::from(vec![
            label(t, "ssh logins"),
            Span::styled(waiting(v, &v.s.seclog, "the log"), t.dim()),
        ]));
    }
    l
}

/// `compact`: only the pairs between inside zones, and whatever is crossed (a narrow window).
pub fn seg_lines(v: &View, p: &Picture, w: usize, compact: bool) -> Vec<Line<'static>> {
    let t = v.t;
    let Some(m) = &p.matrix else {
        return vec![Line::styled(
            waiting(v, &v.s.uci, "the firewall's config"),
            t.dim(),
        )];
    };
    let flows = v.s.flows.value.is_some();
    let mut l = Vec::new();
    for x in m.iter().filter(|x| !compact || !x.outside || x.breach()) {
        let (word, c): (String, Color) = match &x.allowed {
            Allowed::Yes => ("allowed".into(), t.fg),
            Allowed::Rules(r) => (format!("only {}", trunc(&r.join(", "), 22)), t.fg),
            Allowed::No => ("rejected".into(), t.dim),
        };
        let mut now = match (flows, x.flows) {
            (false, _) => "–".to_string(),
            (true, 0) => "none now".to_string(),
            (true, 1) => "1 live flow".to_string(),
            (true, n) => format!("{n} live flows"),
        };
        if x.forwarded > 0 {
            now = format!("{} through forwards", x.forwarded);
            if x.flows > 0 {
                now.push_str(&format!(" · {} not", x.flows));
            }
        }
        let bad = x.breach();
        let st = if bad { t.s(t.red) } else { t.s(c) };
        let mut sp = vec![
            Span::styled(
                format!("{:<12}", arrow(&x.from, &x.to)),
                if bad { st } else { t.fg() },
            ),
            Span::styled(format!("{:<28}", trunc(&word, 27)), st),
            Span::styled(
                now.clone(),
                if bad {
                    st
                } else if x.flows + x.forwarded > 0 {
                    t.fg()
                } else {
                    t.dim()
                },
            ),
        ];
        if bad {
            sp.push(Span::styled(
                trunc(
                    "  ≠ should have been refused",
                    w.saturating_sub(40 + now.chars().count()),
                ),
                st,
            ));
        }
        l.push(Line::from(sp));
    }
    if !compact && m.iter().any(|x| x.allowed == Allowed::No) {
        l.push(Line::styled(
            trunc(
                "rejected pairs: live flows only. Blocked tries have no counter on this firewall.",
                w,
            ),
            t.dim(),
        ));
    }
    l
}

pub fn dns_lines(v: &View, p: &Picture, w: usize) -> Vec<Line<'static>> {
    let t = v.t;
    let room = w.saturating_sub(11);
    let row = |name: &str, text: String, c: Color| {
        Line::from(vec![
            label(t, name),
            Span::styled(trunc(&text, room), t.s(c)),
        ])
    };
    let mut l = Vec::new();
    match v.s.counters.value.as_ref().map(|c| c.dns) {
        Some(Some(d)) => {
            let (f, a) = match v.s.rated.dns {
                Some((f, a)) => (Some(f), Some(a)),
                None => (None, None),
            };
            l.push(row(
                "queries",
                format!(
                    "forwarded {}/min · answered locally {}/min",
                    per_min(f),
                    per_min(a)
                ),
                t.fg,
            ));
            l.push(row(
                "",
                format!(
                    "{} / {} since dnsmasq started",
                    num(d.forwarded),
                    num(d.local)
                ),
                t.dim,
            ));
        }
        Some(None) => l.push(row(
            "queries",
            "dnsmasq publishes no counters here".into(),
            t.dim,
        )),
        None => {}
    }
    if !p.upstreams.is_empty() {
        l.push(row("upstreams", p.upstreams.join(", "), t.fg));
    }
    let proxy = v.s.dnsstate.value.as_ref().and_then(|d| d.proxy.as_ref());
    match p.forced_dns {
        Some(true) => {
            let ports = proxy
                .filter(|x| !x.ports.is_empty())
                .map(|x| {
                    let p: Vec<String> = x.ports.iter().map(u16::to_string).collect();
                    format!(" (ports {})", p.join(", "))
                })
                .unwrap_or_default();
            l.push(row("forced", format!("on{ports}"), t.fg));
        }
        Some(false) => l.push(row(
            "forced",
            "off: a device can use any resolver".into(),
            t.dim,
        )),
        None => {}
    }
    if let Some(d) = p.dot {
        let rising = d.rate.is_some_and(|r| r > 0.0);
        l.push(row(
            "DoT tries",
            format!("{}/min rejected · {}", per_min(d.rate), total(v, d)),
            if rising { t.yellow } else { t.fg },
        ));
    }
    if let Some(d) = &v.s.dnsstate.value {
        if let Some(b) = &d.blocklist {
            let mut said = vec![match (b.running, b.entries) {
                (false, _) => "not running".to_string(),
                (true, Some(n)) => format!("{n} names"),
                (true, None) => "running".to_string(),
            }];
            let old = d.list_age_days();
            if let Some(days) = old {
                said.push(match days {
                    0 => "built today".into(),
                    n => format!("{n}d old"),
                });
            }
            match b.auto_update {
                Some(false) => said.push("not updated by itself".into()),
                Some(true) => said.push("updates by itself".into()),
                None => {}
            }
            if b.errors > 0 {
                said.push(format!("{} error(s)", b.errors));
            }
            let c = if !b.running || b.errors > 0 {
                t.red
            } else if old.is_some_and(|d| d >= crate::security::LIST_OLD_DAYS) {
                t.yellow
            } else {
                t.fg
            };
            l.push(row("blocklist", said.join(" · "), c));
        }
        if let Some(x) = &d.proxy {
            l.push(row(
                "DoH proxy",
                if x.running { "running" } else { "not running" }.into(),
                if x.running { t.fg } else { t.red },
            ));
        }
    }
    if l.is_empty() {
        l.push(Line::styled(
            waiting(v, &v.s.counters, "the counters"),
            t.dim(),
        ));
    }
    l
}

pub fn wifi_lines(v: &View, p: &Picture, w: usize) -> Vec<Line<'static>> {
    let t = v.t;
    let mut l = Vec::new();
    for a in &p.aps {
        let stations = match a.stations {
            None => "–".to_string(),
            Some(1) => "1 station".to_string(),
            Some(n) => format!("{n} stations"),
        };
        let mut sp = vec![
            Span::styled(format!("{:<8}", trunc(&a.device, 7)), t.fg()),
            Span::styled(
                format!("{:<11}", trunc(&a.encryption, 10)),
                t.s(if a.encryption == "none" { t.red } else { t.fg }),
            ),
            Span::styled(format!("MFP {:<9}", a.mfp.word()), t.dim()),
            Span::styled(
                if a.wps { "WPS on  " } else { "WPS off " },
                t.s(if a.wps { t.yellow } else { t.dim }),
            ),
            Span::styled(stations, t.fg()),
        ];
        if a.without_mfp > 0 && a.mfp != Mfp::Off {
            sp.push(Span::styled(
                format!(" · {} without MFP", a.without_mfp),
                t.s(t.yellow),
            ));
        }
        l.push(Line::from(sp));
    }
    if let Some(log) = &p.log
        && (!p.aps.is_empty() || log.wifi_connects + log.wifi_auth_failed > 0)
    {
        let mut sp = vec![
            Span::styled(format!("{:<8}", "log"), t.dim()),
            Span::styled(
                format!(
                    "{} joined · {} left",
                    log.wifi_connects, log.wifi_disconnects
                ),
                t.fg(),
            ),
        ];
        match log.wifi_auth_failed {
            0 => sp.push(Span::styled(" · no wrong passphrase", t.dim())),
            1 => sp.push(Span::styled(" · 1 wrong passphrase", t.s(t.yellow))),
            n => sp.push(Span::styled(
                format!(" · {n} wrong passphrases"),
                t.s(t.yellow),
            )),
        }
        sp.push(Span::styled(format!(" · {}", window(p)), t.dim()));
        l.push(Line::from(sp));
    }
    if l.is_empty() {
        l.push(Line::styled(
            match v.s.uci.value {
                Some(_) => "no access point is switched on".to_string(),
                None => waiting(v, &v.s.uci, "the wireless config"),
            },
            t.dim(),
        ));
    }
    l.into_iter()
        .map(|line| {
            // (Kept inside the panel: a long row is cut, never wrapped.)
            let width: usize = line.spans.iter().map(|s| s.content.chars().count()).sum();
            if width <= w {
                return line;
            }
            let mut left = w;
            Line::from(
                line.spans
                    .into_iter()
                    .map(|s| {
                        let cut = trunc(&s.content, left);
                        left = left.saturating_sub(cut.chars().count());
                        Span::styled(cut, s.style)
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

/// The one line under everything: when the counters started, how far back the log goes,
/// how full the table is, and what makes the numbers undercount.
fn footer(v: &View, p: &Picture) -> Option<Line<'static>> {
    let t = v.t;
    let mut said: Vec<(String, Color)> = Vec::new();
    // What makes the numbers undercount comes first: a narrow window cuts the end.
    if p.offload {
        said.push((
            "flow offloading is on: bytes and counts undercount".into(),
            t.yellow,
        ));
    }
    if v.s
        .flows
        .value
        .as_ref()
        .is_some_and(|f| f.acct == Some(false))
    {
        said.push(("flow accounting is off: no bytes".into(), t.yellow));
    }
    if let Some(s) = since(v) {
        let reset = if v.s.rated.reset {
            ", just started over"
        } else {
            ""
        };
        said.push((format!("counters {s}{reset}"), t.dim));
    }
    if let Some(w) = p.log.as_ref().and_then(|l| l.window_s) {
        said.push((format!("log window {}", span(w)), t.dim));
    }
    let listed = v.s.flows.value.as_ref().map(|f| f.flows.len());
    match (
        v.s.counters.value.as_ref().and_then(|c| c.conntrack),
        listed,
    ) {
        (Some((n, max)), Some(l)) => {
            said.push((
                format!("{n} of {max} connections tracked, {l} listed"),
                t.dim,
            ));
        }
        (Some((n, max)), None) => said.push((format!("{n} of {max} connections tracked"), t.dim)),
        (None, Some(l)) => said.push((format!("{l} flows listed"), t.dim)),
        (None, None) => {}
    }
    if said.is_empty() {
        return None;
    }
    let mut sp = vec![Span::raw(" ")];
    for (i, (text, c)) in said.into_iter().enumerate() {
        if i > 0 {
            sp.push(Span::styled(" · ", t.dim()));
        }
        sp.push(Span::styled(text, t.s(c)));
    }
    Some(Line::from(sp))
}

impl Security {
    /// The cursor of the view shown.
    pub fn cursor(&mut self) -> &mut Cursor {
        if self.panels {
            &mut self.pcur
        } else {
            &mut self.cur
        }
    }

    pub fn at(&self) -> usize {
        if self.panels {
            self.pcur.sel
        } else {
            self.cur.sel
        }
    }

    pub fn count(&self, v: &View) -> usize {
        if self.panels {
            rows(v, &picture(v), self.sort).len()
        } else {
            super::threats::count(v)
        }
    }

    /// The list changed under the cursor: put it back on the row it was on.
    pub fn keep(&mut self, v: &View) {
        if !self.panels
            && let Some(i) = self
                .sel
                .as_deref()
                .and_then(|k| super::threats::position(v, k))
        {
            self.cur.sel = i;
        }
        let n = self.count(v);
        self.cursor().clamp(n);
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        // `d`: the list, or the numbers behind it.
        if a == Action::Char('d') {
            self.panels = !self.panels;
            return Vec::new();
        }
        if !self.panels {
            return super::threats::handle(self, a, v);
        }
        match a {
            Action::Esc => {
                self.panels = false;
                Vec::new()
            }
            Action::Refresh | Action::Check => read_again(),
            Action::Char('s') => {
                self.sort = self.sort.next();
                self.pcur.sel = 0;
                vec![Effect::Toast(format!("sorted by {}", self.sort.word()))]
            }
            Action::Enter => {
                let p = picture(v);
                let r = rows(v, &p, self.sort);
                match r.get(v.cur.min(r.len().saturating_sub(1))) {
                    Some(d) => vec![Effect::Info(
                        format!("{}{}", if d.private { "~" } else { "" }, d.label),
                        detail(v, d),
                    )],
                    None => Vec::new(),
                }
            }
            _ => Vec::new(),
        }
    }

    /// `mark`: None in the panels (the cursor is here); in the list, the device the
    /// selected row is about (its place here, when it has live flows).
    pub fn egress(
        &mut self,
        f: &mut Frame,
        area: Rect,
        v: &View,
        p: &Picture,
        mark: Option<Option<usize>>,
    ) {
        let t = v.t;
        let shown = rows(v, p, self.sort);
        let flows: usize = p.devices.iter().map(|d| d.flows).sum();
        let mut note = match (&v.s.flows.value, p.devices.len()) {
            (None, _) => String::new(),
            (Some(_), 1) => format!("1 device · {flows} live flows"),
            (Some(_), n) => format!("{n} devices · {flows} live flows"),
        };
        if let Some(c) = p.out_new {
            // One counter for every zone allowed out, and the router: not split.
            let sep = if note.is_empty() { "" } else { " · " };
            note.push_str(&format!(
                "{sep}new connections out {}/min, all zones",
                per_min(c.rate)
            ));
        }
        let b = panel(t, "Egress", note);
        let r = inner(&b, area);
        f.render_widget(b, area);
        if v.s.flows.value.is_none() || v.s.ifaces.value.is_none() {
            let why = match v.s.flows.value {
                None => waiting(v, &v.s.flows, "the connection table"),
                Some(_) => waiting(v, &v.s.ifaces, "the interfaces"),
            };
            return f.render_widget(Paragraph::new(Line::styled(why, t.dim())), r);
        }
        if shown.is_empty() {
            let why = if v.filter.is_some() {
                "nothing matches the filter"
            } else {
                "no device has a live flow out right now"
            };
            return f.render_widget(Paragraph::new(Line::styled(why, t.dim())), r);
        }
        let wide = r.width >= 70;
        let sel = match mark {
            None => Some(v.cur.min(shown.len() - 1)),
            Some(at) => at,
        };
        let table: Vec<Row> = shown
            .iter()
            .map(|d| {
                let odd = d.odd().next().is_some();
                let name = format!(
                    "{}{}{}",
                    if odd { "! " } else { "" },
                    if d.private { "~" } else { "" },
                    d.label
                );
                let st = if odd { t.s(t.yellow) } else { t.fg() };
                let mut cells = vec![
                    Cell::from(name).style(st),
                    Cell::from(d.zone.clone()).style(t.dim()),
                    Cell::from(format!("{:>5}", d.flows)).style(t.fg()),
                ];
                if wide {
                    cells.push(Cell::from(format!("{:>5}", d.dests)).style(t.fg()));
                }
                cells.push(Cell::from(d.top_ports(if wide { 4 } else { 2 })).style(st));
                cells.push(Cell::from(format!("{:>8}", bytes(d.up))).style(t.fg()));
                cells.push(Cell::from(format!("{:>8}", bytes(d.down))).style(t.fg()));
                Row::new(cells)
            })
            .collect();
        let (header, widths) = if wide {
            (
                vec![
                    "device",
                    "zone",
                    "flows",
                    "dests",
                    "top ports",
                    "       ↑",
                    "       ↓",
                ],
                vec![
                    Constraint::Fill(2),
                    Constraint::Length(5),
                    Constraint::Length(5),
                    Constraint::Length(5),
                    Constraint::Fill(2),
                    Constraint::Length(8),
                    Constraint::Length(8),
                ],
            )
        } else {
            (
                vec![
                    "device",
                    "zone",
                    "flows",
                    "top ports",
                    "       ↑",
                    "       ↓",
                ],
                vec![
                    Constraint::Fill(2),
                    Constraint::Length(4),
                    Constraint::Length(5),
                    Constraint::Fill(1),
                    Constraint::Length(8),
                    Constraint::Length(8),
                ],
            )
        };
        if mark.is_none() {
            self.pcur.page = r.height.saturating_sub(1) as usize;
        }
        widgets::table(
            f,
            r,
            t,
            TableSpec {
                header,
                widths,
                rows: table,
                selected: sel,
            },
        );
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        if !self.panels {
            return super::threats::render(self, f, area, v);
        }
        let t = v.t;
        let p = picture(v);
        let foot = footer(v, &p);
        let [body, foot_a] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(u16::from(foot.is_some())),
        ])
        .areas(area);
        if let Some(line) = foot {
            f.render_widget(Paragraph::new(line), foot_a);
        }
        let draw = |f: &mut Frame, a: Rect, name: &str, note: String, lines: Vec<Line<'static>>| {
            if a.height < 3 {
                return;
            }
            let b = panel(t, name, note);
            let r = inner(&b, a);
            f.render_widget(b, a);
            f.render_widget(Paragraph::new(lines), r);
        };
        let seg_note = |p: &Picture| match p.crossings().len() {
            0 if v.s.flows.value.is_some() && p.matrix.is_some() => {
                "nothing crosses what the firewall keeps apart".to_string()
            }
            0 => String::new(),
            n => format!("{n} crossing(s)"),
        };
        let ingress_note = "from outside".to_string();
        let h = |n: usize| n as u16 + 2;
        if body.width >= 120 {
            // Two columns: what comes in, names and radios at the left; who goes out and
            // what crosses zones at the right.
            let left_w = (body.width * 46 / 100).clamp(62, 84);
            let [left, right] =
                Layout::horizontal([Constraint::Length(left_w), Constraint::Fill(1)]).areas(body);
            let w = left_w.saturating_sub(4) as usize;
            let (ing, dns, wifi) = (
                ingress_lines(v, &p, w, false),
                dns_lines(v, &p, w),
                wifi_lines(v, &p, w),
            );
            let marks: Vec<Line> = p
                .marks
                .iter()
                .map(|m| {
                    Line::styled(
                        trunc(&format!("! {}", m.text()), w),
                        t.s(if m.grave() { t.red } else { t.yellow }),
                    )
                })
                .collect();
            let [ing_a, dns_a, wifi_a, marks_a] = Layout::vertical([
                Constraint::Length(h(ing.len())),
                Constraint::Length(h(dns.len())),
                Constraint::Length(h(wifi.len())),
                Constraint::Fill(1),
            ])
            .areas(left);
            draw(f, ing_a, "Ingress", ingress_note, ing);
            draw(f, dns_a, "DNS", String::new(), dns);
            draw(f, wifi_a, "Wi-Fi", String::new(), wifi);
            if !marks.is_empty() {
                let room = marks_a.height.min(h(marks.len()));
                let a = Rect {
                    height: room,
                    ..marks_a
                };
                draw(f, a, "Worth a look", format!("{}", marks.len()), marks);
            }
            let seg = seg_lines(v, &p, right.width.saturating_sub(4) as usize, false);
            let [egress_a, seg_a] = Layout::vertical([
                Constraint::Fill(1),
                Constraint::Length(h(seg.len()).min(right.height / 2)),
            ])
            .areas(right);
            self.egress(f, egress_a, v, &p, None);
            draw(f, seg_a, "Segmentation", seg_note(&p), seg);
            return;
        }
        // Narrow: one column. Egress keeps at least six rows; then what crosses zones,
        // then what came in; DNS, then Wi-Fi, only where there is room left.
        let w = body.width.saturating_sub(4) as usize;
        let ing = ingress_lines(v, &p, w, true);
        let seg = seg_lines(v, &p, w, true);
        let dns = dns_lines(v, &p, w);
        let wifi = wifi_lines(v, &p, w);
        let mut left = body.height.saturating_sub(6);
        let mut take = |want: u16| {
            let got = if want <= left { want } else { 0 };
            left -= got;
            got
        };
        let seg_h = take(h(seg.len()));
        let ing_h = take(h(ing.len()));
        let (dns_h, wifi_h) = (take(h(dns.len())), take(h(wifi.len())));
        let [ing_a, egress_a, seg_a, dns_a, wifi_a] = Layout::vertical([
            Constraint::Length(ing_h),
            Constraint::Fill(1),
            Constraint::Length(seg_h),
            Constraint::Length(dns_h),
            Constraint::Length(wifi_h),
        ])
        .areas(body);
        draw(f, ing_a, "Ingress", ingress_note, ing);
        self.egress(f, egress_a, v, &p, None);
        draw(f, seg_a, "Segmentation", seg_note(&p), seg);
        draw(f, dns_a, "DNS", String::new(), dns);
        draw(f, wifi_a, "Wi-Fi", String::new(), wifi);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_for_narrow_columns() {
        assert_eq!(
            [0, 902, 9_999, 31_200, 902_114, 1_400_000].map(num),
            ["0", "902", "9999", "31.2k", "902.1k", "1.4M"]
        );
        assert_eq!(
            [None, Some(0.0), Some(0.5), Some(2.0 / 60.0), Some(3.0)].map(per_min),
            ["–", "0", "30", "2.0", "180"]
        );
        assert_eq!(arrow("dmz", "lan"), "dmz→lan");
        assert_eq!(Sort::default().next().next().next().next(), Sort::Flows);
    }
}

//! Network: the firewall as it is against what network_config.yaml expects (its zones and
//! its port forwards, differences marked), over what listens on the router (the shared
//! Listening panel, each socket with its status by the audit's own rule). `b` marks the
//! selected port expected, or takes that back (`networks/<name>/baseline.toml`).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::{Hints, View};
use crate::audit::{self, Exposure, Snapshot};
use crate::tui::data::Kind;
use crate::tui::target::{Effect, Own};
use sentry_core::baseline::glob;
use sentry_core::collectors::net::{ListenStatus, Listener};
use sentry_core::finding::{Finding, Sev};
use sentry_core::tui::Cursor;
use sentry_core::tui::keys::Action;
use sentry_core::tui::netview::{self, ListenRow, NetView};
use sentry_core::tui::widgets::{inner, panel, trunc};

#[derive(Default)]
pub struct Network {
    pub cur: Cursor,
}

pub fn hints() -> Hints {
    netview::hints()
}

/// Every listener with its status, once they were read. A socket whose finding is marked
/// expected is baseline too, so marking it here or on Maintenance comes to the same.
pub fn all(v: &View) -> Option<Vec<Listener>> {
    let ls = v.s.listeners.value.as_ref()?;
    let ex = Exposure::new(v.s.ifaces.value.as_ref(), v.s.uci.value.as_ref());
    let expected = ex.expected_keys(ls, v.cfg);
    let base = &v.sh.baseline;
    Some(
        ls.iter()
            .map(|l| {
                let mut l = l.clone();
                l.status = match ex.status(&l, &expected, base) {
                    ListenStatus::New
                        if base
                            .findings
                            .iter()
                            .any(|g| glob(g, &audit::listener_id(&l))) =>
                    {
                        ListenStatus::Baseline
                    }
                    s => s,
                };
                l
            })
            .collect(),
    )
}

/// Those the `/` filter keeps.
pub fn rows(v: &View) -> Vec<Listener> {
    all(v)
        .unwrap_or_default()
        .into_iter()
        .filter(|l| v.matches(&[&l.local(), l.process.as_deref().unwrap_or(""), &l.proto]))
        .collect()
}

pub fn selected(v: &View) -> Option<Listener> {
    let r = rows(v);
    let i = v.cur.min(r.len().checked_sub(1)?);
    r.into_iter().nth(i)
}

/// How many listeners nothing expects: the count beside the screen's name.
pub fn new_count(v: &View) -> usize {
    all(v)
        .unwrap_or_default()
        .iter()
        .filter(|l| l.status == ListenStatus::New)
        .count()
}

/// What the audit would say about the firewall as it was last read: the rule the two
/// panels mark their differences by (so they never disagree with Maintenance).
fn firewall_findings(v: &View) -> Vec<Finding> {
    let snap = Snapshot {
        taken_at: Some(v.now),
        ifaces: v.s.ifaces.value.clone(),
        uci: v.s.uci.value.clone(),
        ..Default::default()
    };
    audit::derive(&snap, v.cfg, None, &v.sh.baseline)
}

fn mark(v: &View, f: Option<&Finding>) -> (&'static str, Color) {
    let t = v.t;
    match f {
        None => ("✓", t.green),
        Some(f) if f.expected => ("expected", t.dim),
        Some(f) if f.severity == Sev::High => ("≠ check", t.red),
        Some(_) => ("≠", t.yellow),
    }
}

/// The Zones panel: each zone the firewall has, then each one expected and gone.
fn zone_lines(v: &View, found: &[Finding], w: usize) -> Vec<Line<'static>> {
    let t = v.t;
    let Some(u) = &v.s.uci.value else {
        return Vec::new();
    };
    let of = |zone: &str| found.iter().find(|f| f.id == format!("net:zone:{zone}"));
    let mut lines = vec![Line::styled(
        format!(
            "{:<8}{:<16}{:<8}{:<8}",
            "zone", "interfaces", "input", "forward"
        ),
        t.dim(),
    )];
    let zones = u.zones();
    for z in &zones {
        let f = of(&z.name);
        let (word, c) = mark(v, f);
        let policy = |p: &str| {
            Span::styled(
                format!("{:<8}", p.to_lowercase()),
                t.s(if p == "ACCEPT" { t.fg } else { t.dim }),
            )
        };
        let mut sp = vec![
            Span::styled(format!("{:<8}", trunc(&z.name, 7)), t.fg()),
            Span::styled(format!("{:<16}", trunc(&z.networks.join(" "), 15)), t.fg()),
            policy(&z.input),
            policy(&z.forward),
            Span::styled(word, t.s(c)),
        ];
        if let Some(f) = f.filter(|f| !f.expected) {
            let said = f
                .message
                .trim_start_matches(&format!("zone {} ", z.name))
                .to_string();
            sp.push(Span::styled(
                format!(
                    " {}",
                    trunc(&said, w.saturating_sub(42 + word.chars().count()))
                ),
                t.dim(),
            ));
        }
        lines.push(Line::from(sp));
    }
    for (name, nets) in &v.cfg.expect.zones {
        if !zones.iter().any(|z| &z.name == name) {
            let (word, c) = mark(v, of(name));
            lines.push(Line::from(vec![
                Span::styled(format!("{:<8}", trunc(name, 7)), t.dim()),
                Span::styled(format!("{:<32}", trunc(&nets.join(" "), 31)), t.dim()),
                Span::styled(format!("{word} not in the firewall"), t.s(c)),
            ]));
        }
    }
    // What the uplink's zone lets in for the router itself.
    let ex = Exposure::new(v.s.ifaces.value.as_ref(), Some(u));
    let open: Vec<String> = u
        .openings()
        .iter()
        .filter(|o| ex.wan.contains(&o.src))
        .map(|o| match (o.protos.is_empty(), o.ports.is_empty()) {
            (true, true) => o.name.clone(),
            (_, true) => o.protos.join("/"),
            _ => format!("{} {}", o.protos.join("/"), o.ports.join(",")),
        })
        .collect();
    if !open.is_empty() {
        lines.push(Line::styled(
            trunc(&format!("let in from outside: {}", open.join(" · ")), w),
            t.dim(),
        ));
    }
    lines
}

/// The Forwards panel: each redirect the firewall has, then each one expected and gone.
fn forward_lines(v: &View, found: &[Finding], w: usize) -> Vec<Line<'static>> {
    let t = v.t;
    let Some(u) = &v.s.uci.value else {
        return Vec::new();
    };
    let name_w = w.saturating_sub(4 + 12 + 24 + 10).clamp(6, 28);
    let mut lines = vec![Line::styled(
        format!("{:<name_w$}{:<4}{:<12}{:<24}", "forward", "", "port", "to"),
        t.dim(),
    )];
    let fwds = u.forwards();
    for r in &fwds {
        // One row for each protocol, as the findings are.
        for proto in &r.protos {
            let f = found
                .iter()
                .find(|f| f.id == format!("net:forward:{proto}:{}", r.port));
            let (word, c) = match r.enabled {
                true => mark(v, f),
                false => ("off", t.dim),
            };
            let st = if r.enabled { t.fg() } else { t.dim() };
            let to = format!(
                "{}:{}",
                r.dest_ip,
                r.dest_port.as_deref().unwrap_or(&r.port)
            );
            lines.push(Line::from(vec![
                Span::styled(format!("{:<name_w$}", trunc(&r.name, name_w - 1)), st),
                Span::styled(format!("{proto:<4}"), t.dim()),
                Span::styled(format!("{:<12}", trunc(&r.port, 11)), st),
                Span::styled(format!("{:<24}", trunc(&to, 23)), st),
                Span::styled(if word == "≠ check" { "NEW" } else { word }, t.s(c)),
            ]));
        }
    }
    for e in &v.cfg.expect.forwards {
        let id = format!("net:forward:missing:{}", e.name);
        if let Some(f) = found.iter().find(|f| f.id == id) {
            let (word, c) = mark(v, Some(f));
            lines.push(Line::from(vec![
                Span::styled(format!("{:<name_w$}", trunc(&e.name, name_w - 1)), t.dim()),
                Span::styled(format!("{:<4}", trunc(&e.proto, 3)), t.dim()),
                Span::styled(format!("{:<12}", e.port.to_string()), t.dim()),
                Span::styled(format!("{:<24}", trunc(&e.to, 23)), t.dim()),
                Span::styled(
                    if f.expected {
                        word.to_string()
                    } else {
                        "≠ missing".to_string()
                    },
                    t.s(c),
                ),
            ]));
        }
    }
    if lines.len() == 1 {
        lines.push(Line::styled("no port is forwarded", t.dim()));
    }
    lines
}

impl Network {
    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        match a {
            Action::Refresh | Action::Check => vec![
                Own::fetch(Kind::Listeners),
                Own::fetch(Kind::Uci),
                Own::fetch(Kind::Ifaces),
            ],
            // `b` toggles expected (`e` too, as elsewhere), for the port on every address:
            // that's what the audit's finding is about.
            Action::Char('b' | 'e') => {
                let Some(l) = selected(v) else {
                    return Vec::new();
                };
                let group: Vec<Listener> = all(v)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|x| x.proto == l.proto && x.port == l.port)
                    .collect();
                let id = audit::listener_id(&l);
                let what = format!("{} {}", l.proto, l.port);
                match l.status {
                    ListenStatus::New => vec![Effect::own(Own::ListenExpected {
                        keys: group
                            .iter()
                            .filter(|x| x.status == ListenStatus::New)
                            .map(Listener::key)
                            .collect(),
                        id,
                        what,
                        on: true,
                    })],
                    ListenStatus::Baseline => vec![Effect::own(Own::ListenExpected {
                        keys: group.iter().map(Listener::key).collect(),
                        id,
                        what,
                        on: false,
                    })],
                    _ => vec![Effect::Toast(
                        "not reachable from the network: nothing to mark".into(),
                    )],
                }
            }
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let found = firewall_findings(v);
        let half = (area.width / 2).saturating_sub(5) as usize;
        let zones = zone_lines(v, &found, half);
        let fwds = forward_lines(v, &found, half);
        // The two firewall panels take what they need, up to half the height.
        let want = zones.len().max(fwds.len()).max(1) as u16 + 2;
        let [top, rest] = Layout::vertical([
            Constraint::Length(want.min(area.height / 2)),
            Constraint::Fill(1),
        ])
        .areas(area);
        let [za, fa] = Layout::horizontal([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
            .spacing(2)
            .areas(top);
        let waiting = |what: &str| match (&v.s.uci.err, &v.s.unreachable) {
            (Some(e), _) => Line::styled(format!("{what}: {e}"), t.s(t.yellow)),
            (None, Some(_)) => Line::styled("not reachable", t.dim()),
            (None, None) => Line::styled("reading the firewall…", t.dim()),
        };
        let differ = |prefix: &str| {
            found
                .iter()
                .filter(|f| f.id.starts_with(prefix) && !f.expected)
                .count()
        };
        let note = |n: usize, differ: usize| match (v.s.uci.value.is_some(), differ) {
            (false, _) => String::new(),
            (true, 0) => format!("{n} · as expected"),
            (true, d) => format!("{n} · {d} differ"),
        };
        let n_zones = v.s.uci.value.as_ref().map_or(0, |u| u.zones().len());
        let b = panel(t, "Zones", note(n_zones, differ("net:zone:")));
        let r = inner(&b, za);
        f.render_widget(b, za);
        f.render_widget(
            Paragraph::new(if zones.is_empty() {
                vec![waiting("config")]
            } else {
                zones
            }),
            r,
        );
        let n_fwd =
            v.s.uci
                .value
                .as_ref()
                .map_or(0, |u| u.forwards().iter().filter(|x| x.enabled).count());
        let b = panel(t, "Forwards", note(n_fwd, differ("net:forward:")));
        let r = inner(&b, fa);
        f.render_widget(b, fa);
        f.render_widget(
            Paragraph::new(if fwds.is_empty() {
                vec![waiting("config")]
            } else {
                fwds
            }),
            r,
        );

        let shown = v.s.listeners.value.as_ref().map(|_| rows(v));
        let n = shown.as_ref().map_or(0, Vec::len);
        let listen = shown.as_ref().map(|rows| {
            rows.iter()
                .map(|l| ListenRow {
                    l,
                    process: netview::owner(l).unwrap_or_else(|| "kernel".into()),
                })
                .collect()
        });
        let waiting = match (&v.s.listeners.err, &v.s.unreachable) {
            (Some(e), _) => format!("listeners: {e}"),
            (None, Some(_)) => "not reachable".to_string(),
            (None, None) => "reading what listens…".to_string(),
        };
        self.cur.page = netview::draw_listening(
            f,
            rest,
            t,
            &NetView {
                listen,
                waiting,
                source: "netstat -lntup",
                note: String::new(),
                established: &[],
                sel: v.cur.min(n.saturating_sub(1)),
            },
        );
    }
}

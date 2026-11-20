//! Clients: who is on the network (the shared table, `sentry_core::tui::clientview`), read
//! every 10 s while it's in view. Nothing here touches a client's device: `b` marks an
//! unknown one expected in the network's baseline file (or takes that back), Enter shows
//! what's known about it and the line that would name it in network_config.yaml.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::{Hints, View};
use crate::audit;
use crate::clients::{Client, Link, State};
use crate::tui::data::Kind;
use crate::tui::target::{Effect, Own};
use sentry_core::baseline::glob;
use sentry_core::tui::Cursor;
use sentry_core::tui::clientview::{self, Row, Sort, Standing};
use sentry_core::tui::keys::Action;
use sentry_core::tui::widgets::{inner, panel};

#[derive(Default)]
pub struct Clients {
    pub cur: Cursor,
    pub sort: Sort,
}

pub fn hints() -> Hints {
    clientview::hints()
}

/// Marked expected: its finding is in the baseline file (by MAC, or a pattern).
pub fn expected(v: &View, c: &Client) -> bool {
    c.mac.as_deref().is_some_and(|m| {
        let id = audit::client_id(m);
        v.sh.baseline.findings.iter().any(|g| glob(g, &id))
    })
}

fn standing(v: &View, c: &Client) -> Standing {
    match (c.unknown(), expected(v, c)) {
        (false, _) => Standing::Fine,
        (true, true) => Standing::Expected,
        (true, false) => Standing::Unknown,
    }
}

fn link(l: &Link) -> clientview::Link {
    match l {
        Link::Wired { port } => clientview::Link::Wired(port.clone()),
        Link::Wifi { ifname, signal } => clientview::Link::Wifi(ifname.clone(), *signal),
        Link::Dmz { port, net } if net.is_empty() => clientview::Link::Other(port.clone()),
        Link::Dmz { port, net } => clientview::Link::Other(format!("{net} · {port}")),
        Link::Unknown => clientview::Link::None,
    }
}

/// What the list calls it; one known only by an IPv6 lease has no MAC to go by.
fn name(c: &Client) -> String {
    match (&c.mac, &c.hostname) {
        (None, None) => "(an IPv6 lease)".to_string(),
        _ => c.label().to_string(),
    }
}

fn row(v: &View, c: &Client) -> Row {
    let now = v.now.as_second();
    Row {
        name: name(c),
        private: c.private,
        link: link(&c.link),
        addr: c.addrs.first().cloned().unwrap_or_else(|| "–".into()),
        lease_left: c.lease_end.map(|e| e - now),
        seen_ago: c.last_seen.map(|t| now - t),
        online: c.state != State::Away,
        standing: standing(v, c),
        leave_alone: c.leave_alone,
    }
}

/// The clients the filter keeps, in the order asked for, each with its row.
pub fn rows<'a>(v: &View<'a>, sort: Sort) -> Vec<(&'a Client, Row)> {
    let mut rows: Vec<(&Client, Row)> =
        v.s.clients
            .iter()
            .flatten()
            .filter(|c| {
                let link = match &c.link {
                    Link::Wired { port } => format!("wired {port}"),
                    Link::Wifi { ifname, .. } => format!("wifi wi-fi {ifname}"),
                    Link::Dmz { port, net } => format!("{net} {port}"),
                    Link::Unknown => String::new(),
                };
                let word = match standing(v, c) {
                    Standing::Unknown => "new unknown",
                    Standing::Expected => "expected",
                    Standing::Fine => "",
                };
                v.matches(&[
                    c.label(),
                    c.hostname.as_deref().unwrap_or(""),
                    &c.key,
                    &c.addrs.join(" "),
                    &link,
                    word,
                ])
            })
            .map(|c| (c, row(v, c)))
            .collect();
    clientview::sort(&mut rows, sort, |r| &r.1);
    rows
}

/// How many are there in all: (wired, on Wi-Fi, unknown and not marked expected).
pub fn counts(v: &View) -> Option<(usize, usize, usize, usize)> {
    let c = v.s.clients.as_ref()?;
    let there = |x: &&Client| x.state != State::Away;
    Some((
        c.iter().filter(there).count(),
        c.iter()
            .filter(there)
            .filter(|x| matches!(x.link, Link::Wired { .. } | Link::Dmz { .. }))
            .count(),
        c.iter()
            .filter(there)
            .filter(|x| matches!(x.link, Link::Wifi { .. }))
            .count(),
        c.iter()
            .filter(|x| standing(v, x) == Standing::Unknown)
            .count(),
    ))
}

/// The line that names it in network_config.yaml.
fn yaml_line(c: &Client) -> Option<String> {
    let mac = c.mac.as_deref()?;
    let name = c.hostname.as_deref().unwrap_or("a-name").to_lowercase();
    Some(match (&c.hostname, c.private) {
        // A private MAC changes: it's known by the hostname it gives.
        (Some(h), true) if matches!(c.link, Link::Wifi { .. }) => {
            format!("- {{ name: {name}, hostname: {h}, private_mac: true }}")
        }
        _ => format!("- {{ name: {name}, mac: \"{mac}\" }}"),
    })
}

/// Everything known about one, for the box Enter opens.
pub fn detail(v: &View, c: &Client) -> Vec<Line<'static>> {
    let t = v.t;
    let now = v.now.as_second();
    let kv = |k: &str, val: String| {
        Line::from(vec![
            Span::styled(format!("{k:<11}"), t.dim()),
            Span::styled(val, t.fg()),
        ])
    };
    let mut l = Vec::new();
    if let Some(n) = &c.name {
        l.push(kv("name", n.clone()));
    }
    if let Some(h) = &c.hostname {
        l.push(kv("hostname", h.clone()));
    }
    match &c.mac {
        Some(mac) => l.push(kv(
            "MAC",
            match c.vendor_prefix() {
                Some(p) => format!("{mac} · vendor prefix {p}"),
                None => format!("{mac} · private (randomised): no vendor"),
            },
        )),
        None => l.push(kv("known by", format!("its IPv6 lease only ({})", c.key))),
    }
    l.push(kv(
        "link",
        match &c.link {
            Link::Wired { port } => format!("wired port {port}"),
            Link::Wifi { ifname, signal } => format!(
                "Wi-Fi on {ifname}{}{}{}",
                signal.map_or(String::new(), |s| format!(" · {s} dBm")),
                c.rates.map_or(String::new(), |(rx, tx)| format!(
                    " · ↓ {} ↑ {}",
                    crate::rates::bits(tx as f64),
                    crate::rates::bits(rx as f64)
                )),
                c.connected_s.map_or(String::new(), |s| format!(
                    " · connected {}",
                    super::span(s)
                )),
            ),
            Link::Dmz { port, net } if net.is_empty() => format!("its own port {port}"),
            Link::Dmz { port, net } => format!("{net}, on port {port}"),
            Link::Unknown => "not on any port now".into(),
        },
    ));
    for (i, a) in c.addrs.iter().enumerate() {
        l.push(kv(if i == 0 { "addresses" } else { "" }, a.clone()));
    }
    if let Some(end) = c.lease_end {
        l.push(kv(
            "lease",
            match end - now {
                left if left > 0 => format!("{} left", super::span(left as u64)),
                _ => "ended".into(),
            },
        ));
    }
    let date = |ts: i64| {
        jiff::Timestamp::from_second(ts)
            .map(|t| t.strftime("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_default()
    };
    if let Some(first) = c.first_seen {
        l.push(kv("first seen", date(first)));
    }
    if let Some(last) = c.last_seen.filter(|_| c.state == State::Away) {
        l.push(kv("last seen", date(last)));
    }
    if c.leave_alone {
        l.push(kv(
            "",
            "leave_alone: nothing sentry does may touch it".into(),
        ));
    }
    l.push(Line::raw(""));
    match (standing(v, c), yaml_line(c)) {
        (Standing::Fine, _) if c.known => {
            l.push(Line::styled("Named in network_config.yaml.", t.dim()));
        }
        (Standing::Fine, line) => {
            l.push(Line::styled(
                "A private address on Wi-Fi: the passphrase vouches for it, so it's never flagged.",
                t.dim(),
            ));
            if let Some(line) = line.filter(|_| c.name.is_none() && c.hostname.is_some()) {
                l.push(Line::styled(
                    "To give it a name, under devices: in network_config.yaml:",
                    t.dim(),
                ));
                l.push(Line::styled(format!("  {line}"), t.s(t.cyan)));
            }
        }
        (st, line) => {
            l.push(Line::styled(
                if st == Standing::Expected {
                    "Unknown, and marked expected (b takes that back)."
                } else {
                    "Unknown: nothing names it. b marks it expected; to name it, under devices:"
                },
                t.fg(),
            ));
            if let Some(line) = line {
                l.push(Line::styled(format!("  {line}"), t.s(t.cyan)));
            }
        }
    }
    l
}

impl Clients {
    pub fn count(&self, v: &View) -> usize {
        rows(v, self.sort).len()
    }

    pub fn selected<'a>(&self, v: &View<'a>) -> Option<&'a Client> {
        let r = rows(v, self.sort);
        let i = v.cur.min(r.len().checked_sub(1)?);
        Some(r[i].0)
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        match a {
            Action::Refresh | Action::Check => {
                vec![Own::fetch(Kind::Clients), Own::fetch(Kind::Ifaces)]
            }
            Action::Char('s') => {
                self.sort = self.sort.next();
                self.cur.sel = 0;
                vec![Effect::Toast(format!("sorted by {}", self.sort.word()))]
            }
            Action::Enter => match self.selected(v) {
                Some(c) => vec![Effect::Info(name(c), detail(v, c))],
                None => Vec::new(),
            },
            Action::Char('b' | 'e') => {
                let Some(c) = self.selected(v) else {
                    return Vec::new();
                };
                let toast = |s: &str| vec![Effect::Toast(s.to_string())];
                match (standing(v, c), &c.mac) {
                    (_, None) => toast("known only by an IPv6 lease: nothing to mark"),
                    (Standing::Fine, _) if c.known => toast("it's named in network_config.yaml"),
                    (Standing::Fine, _) => {
                        toast("a private address on Wi-Fi is never flagged: nothing to mark")
                    }
                    (st, Some(mac)) => vec![Effect::own(Own::Expected(
                        audit::client_id(mac),
                        st == Standing::Unknown,
                    ))],
                }
            }
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let rows = rows(v, self.sort);
        let note = match counts(v) {
            Some((there, wired, wifi, new)) => format!(
                "{there} here · {wired} wired · {wifi} Wi-Fi · {new} new · by {}{}",
                self.sort.word(),
                match v.s.raw_clients.at {
                    Some(at) => format!(
                        " · read {}",
                        sentry_core::fmt::ago(at.elapsed().as_secs() as i64)
                    ),
                    None if v.s.clients.is_some() => " · from the last audit".to_string(),
                    None => String::new(),
                }
            ),
            None => String::new(),
        };
        let b = panel(t, "Clients", note);
        let r = inner(&b, area);
        f.render_widget(b, area);
        self.cur.page = r.height as usize;
        if v.s.clients.is_none() {
            let why = match (&v.s.raw_clients.err, &v.s.unreachable) {
                (Some(e), _) => format!("clients: {e}"),
                (None, Some(_)) => "not reachable".to_string(),
                (None, None) => "reading who is on the network…".to_string(),
            };
            f.render_widget(Paragraph::new(Line::styled(why, t.dim())), r);
            return;
        }
        if rows.is_empty() {
            let why = if v.filter.is_some() {
                "no client matches the filter"
            } else {
                "nobody is on the network"
            };
            f.render_widget(Paragraph::new(Line::styled(why, t.dim())), r);
            return;
        }
        let shown: Vec<Row> = rows.into_iter().map(|(_, r)| r).collect();
        let sel = v.cur.min(shown.len() - 1);
        clientview::draw(f, r, t, &shown, Some(sel), self.sort);
    }
}

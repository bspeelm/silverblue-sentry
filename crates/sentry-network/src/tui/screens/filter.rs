//! The family filter on Security: "Filtered by you" (who is filtered and since when, and
//! the entry that chooses), and the device list it opens in the list's place.
//!
//! The list: named devices first, then the rest; Space ticks, `a` ticks every named one,
//! `/` filters, `n` names the one at the cursor first, Enter applies the whole selection as
//! ONE change (the `security-action` workflow with `filter:<tags>`), Esc leaves. Devices
//! the router already filters start ticked. sentry's own targets (the server, this machine)
//! and devices `network_config.yaml` says to leave alone aren't offered. A device on Wi-Fi
//! with a private (random) address is tickable, with a warning: the filter matches by MAC.

use std::collections::BTreeSet;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row as TRow};

use super::View;
use super::threats::Want;
use crate::clients::Link;
use crate::security::Nets;
use crate::security::actions::{self, Do};
use crate::security::attention::{DevRef, Via, dev_of};
use crate::security::family;
use crate::tui::target::{Effect, Own};
use sentry_app::effect::{self, OwnPrompt, Prompt};
use sentry_core::tui::Cursor;
use sentry_core::tui::keys::Action as Key;
use sentry_core::tui::widgets::{self, TableSpec, inner, panel, trunc, wrap};

/// The list, while it is open.
#[derive(Debug, Default)]
pub struct Menu {
    /// The tags ticked.
    pub ticks: BTreeSet<String>,
    pub cur: Cursor,
}

/// A device the list offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub dev: DevRef,
    /// The router filters it now.
    pub filtered: bool,
    /// It is on the network now.
    pub here: bool,
    /// A private (random) MAC on Wi-Fi: it can slip out of a filter by MAC.
    pub private_wifi: bool,
}

/// What the router filters now, by tag (sentry's own sections only).
pub fn on_router(v: &View) -> Vec<family::Found> {
    v.s.uci
        .value
        .as_ref()
        .map(family::found)
        .unwrap_or_default()
}

/// Every device the list offers, named first, the `/` filter applied.
pub fn menu_rows(v: &View) -> Vec<Entry> {
    let nets =
        v.s.ifaces
            .value
            .as_ref()
            .map(|i| Nets::new(i, v.s.uci.value.as_ref()));
    let on = on_router(v);
    let mut out: Vec<Entry> = Vec::new();
    for c in v.s.clients.iter().flatten() {
        let Some(mac) = c.mac.as_deref() else {
            continue;
        };
        if c.leave_alone || v.s.targets.iter().any(|t| t.eq_ignore_ascii_case(mac)) {
            continue;
        }
        let Some(dev) = dev_of(v.name, c, nets.as_ref()) else {
            continue;
        };
        if out.iter().any(|e| e.dev.tag == dev.tag) {
            continue;
        }
        out.push(Entry {
            filtered: on.iter().any(|f| f.tag == dev.tag),
            here: true,
            private_wifi: c.private && matches!(c.link, Link::Wifi { .. }),
            dev,
        });
    }
    // Filtered and not on the network right now: still listed, to be taken off.
    for f in &on {
        if out.iter().any(|e| e.dev.tag == f.tag) {
            continue;
        }
        let noted = v.s.blocks.device.get(&f.tag);
        out.push(Entry {
            dev: DevRef {
                mac: f.mac.clone(),
                tag: f.tag.clone(),
                label: noted
                    .map(|d| d.label.clone())
                    .filter(|l| !l.is_empty())
                    .unwrap_or_else(|| f.mac.clone()),
                zone: f.zone.clone(),
                wifi: noted.and_then(|d| d.wifi.clone()),
                named: noted.is_some(),
                via: Via::Other,
            },
            filtered: true,
            here: false,
            private_wifi: false,
        });
    }
    out.retain(|e| v.matches(&[&e.dev.label, &e.dev.mac]));
    out.sort_by_key(|e| (!e.dev.named, e.dev.label.to_lowercase()));
    out
}

/// The list opened: what the router filters now, ticked.
pub fn open(v: &View) -> Menu {
    Menu {
        ticks: on_router(v).into_iter().map(|f| f.tag).collect(),
        cur: Cursor::default(),
    }
}

/// What would stop the filter working for a device in this zone (None: nothing seen).
pub fn refused(v: &View, zone: &str) -> Option<String> {
    let c = v.s.counters.value.as_ref()?;
    family::refused(zone, &family::hijacked(c, zone), &[])
}

/// One row of "Filtered by you": the entry that chooses, then each device filtered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filtered {
    Choose {
        n: usize,
    },
    Device {
        tag: String,
        label: String,
        since: Option<i64>,
    },
}

impl Filtered {
    pub fn key(&self) -> String {
        match self {
            Filtered::Choose { .. } => "filter:choose".into(),
            Filtered::Device { tag, .. } => format!("filter:{tag}"),
        }
    }
}

/// "Filtered by you" (empty until the config was read).
pub fn filtered(v: &View) -> Vec<Filtered> {
    if v.s.uci.value.is_none() {
        return Vec::new();
    }
    let on = on_router(v);
    let mut out = vec![Filtered::Choose { n: on.len() }];
    for f in on {
        out.push(Filtered::Device {
            label: crate::security::attention::filtered_label(
                &v.s.blocks,
                v.s.clients.as_deref(),
                &f.tag,
                &f.mac,
            ),
            since: v.s.blocks.filter.get(&f.tag).map(|n| n.since),
            tag: f.tag,
        });
    }
    out
}

/// Start the change: the filter on exactly `tags`.
pub fn start(tags: Vec<String>, devs: Vec<DevRef>) -> Vec<Effect> {
    vec![Effect::own(Own::Security(Want::Filter {
        act: Do::filter(tags),
        devs,
    }))]
}

/// The filter on what the router has now, but for `tag`: Enter under Filtered by you.
pub fn lift(v: &View, tag: &str) -> Vec<Effect> {
    let tags = on_router(v)
        .into_iter()
        .map(|f| f.tag)
        .filter(|t| t != tag)
        .collect();
    start(tags, Vec::new())
}

/// The filter on what the router has now, and `tag` too (a filter noted here put back).
pub fn put_back(v: &View, tag: &str) -> Vec<Effect> {
    let mut tags: Vec<String> = on_router(v).into_iter().map(|f| f.tag).collect();
    tags.push(tag.to_string());
    start(tags, Vec::new())
}

/// A key while the list is open: whether the list closes, and what follows.
pub fn handle(m: &mut Menu, a: Key, v: &View) -> (bool, Vec<Effect>) {
    let rows = menu_rows(v);
    let at = rows.get(m.cur.sel.min(rows.len().saturating_sub(1)));
    (
        false,
        match a {
            Key::Esc => return (true, Vec::new()),
            Key::Char(' ') => match at {
                Some(e) => {
                    if !m.ticks.remove(&e.dev.tag) {
                        m.ticks.insert(e.dev.tag.clone());
                    }
                    Vec::new()
                }
                None => Vec::new(),
            },
            Key::Char('a') => {
                let named: Vec<&Entry> = rows.iter().filter(|e| e.dev.named).collect();
                if named.is_empty() {
                    return (
                        false,
                        vec![Effect::Toast(
                            "no device has a name yet: e names the one at the cursor".into(),
                        )],
                    );
                }
                for e in named {
                    m.ticks.insert(e.dev.tag.clone());
                }
                Vec::new()
            }
            Key::Char('e') => match at {
                Some(e) if !e.dev.named => vec![Effect::Prompt(
                    Prompt::Own(OwnPrompt {
                        label: format!("A name for {}: ", e.dev.label),
                        enter: "name it",
                        workflow: None,
                        defaults: false,
                        own: effect::Own(std::rc::Rc::new(Own::Security(Want::Name {
                            mac: e.dev.mac.clone(),
                            label: e.dev.label.clone(),
                        }))),
                    }),
                    String::new(),
                )],
                Some(_) => vec![Effect::Toast("it has a name already".into())],
                None => Vec::new(),
            },
            Key::Enter => {
                let now: BTreeSet<String> = on_router(v).into_iter().map(|f| f.tag).collect();
                if m.ticks == now {
                    return (
                        false,
                        vec![Effect::Toast(
                            "nothing to change: the filter is on exactly these devices already"
                                .into(),
                        )],
                    );
                }
                // (Every device offered, ticked or not: the ticked ones are noted.)
                let all = menu_rows(&View {
                    filter: None,
                    ..v.at(v.cur)
                });
                let devs: Vec<DevRef> = all
                    .iter()
                    .filter(|e| m.ticks.contains(&e.dev.tag))
                    .map(|e| e.dev.clone())
                    .collect();
                // What can't work is said here, before anything starts.
                for d in devs.iter().filter(|d| !now.contains(&d.tag)) {
                    if let Some(why) = refused(v, &d.zone) {
                        let t = v.t;
                        let mut lines: Vec<Line<'static>> = Vec::new();
                        for l in wrap(
                            &format!(
                                "Nothing was changed. The family filter can't work on this router yet: {why}."
                            ),
                            70,
                        ) {
                            lines.push(Line::styled(l, t.fg()));
                        }
                        return (false, vec![Effect::Info("The family filter".into(), lines)]);
                    }
                }
                let tags = m.ticks.iter().cloned().collect();
                return (true, start(tags, devs));
            }
            _ => Vec::new(),
        },
    )
}

/// The key bar while the list is open.
pub fn hints(m: &Menu, v: &View) -> super::Hints {
    let rows = menu_rows(v);
    let mut h = vec![("Enter", "apply"), ("Space", "tick"), ("a", "all named")];
    if rows.get(m.cur.sel).is_some_and(|e| !e.dev.named) {
        h.push(("e", "name it"));
    }
    h.extend([("Esc", "back"), ("/", "filter")]);
    h
}

fn how(e: &Entry) -> &'static str {
    match (e.here, e.dev.via) {
        (false, _) => "not here now",
        (_, Via::Wifi) => "Wi-Fi",
        (_, Via::Wired) => "plugged in",
        (_, Via::Routed) => "server's side",
        (_, Via::Other) => "",
    }
}

/// The list, in the list's place: `left` its column, `detail` where the selected one is
/// said (the right column, or the left's last lines).
pub fn render(m: &mut Menu, f: &mut Frame, left: Rect, detail: Option<Rect>, v: &View) {
    let t = v.t;
    let rows = menu_rows(v);
    m.cur.clamp(rows.len());
    let ticked = m.ticks.len();
    let bl = panel(
        t,
        "Family filter: which devices",
        format!("{ticked} ticked · Enter applies them all"),
    );
    let r = inner(&bl, left);
    f.render_widget(bl, left);
    m.cur.page = r.height.saturating_sub(1) as usize;
    if rows.is_empty() {
        let said = if v.filter.is_some() {
            sentry_core::tui::maintlist::NO_MATCH
        } else if v.s.clients.is_none() {
            "reading who is on the network…"
        } else {
            "no device to offer (sentry's own targets and the devices left alone aren't)"
        };
        widgets::placeholder(f, r, t, &[(said, t.dim())]);
    } else {
        let w = r.width.saturating_sub(4 + 15 + 3) as usize;
        let table: Vec<TRow> = rows
            .iter()
            .map(|e| {
                let on = m.ticks.contains(&e.dev.tag);
                let change = match (on, e.filtered) {
                    (true, false) => " (new)",
                    (false, true) => " (off)",
                    _ => "",
                };
                TRow::new(vec![
                    Cell::from(if on { "[x]" } else { "[ ]" }).style(t.s(if on {
                        t.green
                    } else {
                        t.dim
                    })),
                    Cell::from(Line::from(vec![
                        Span::styled(
                            trunc(&e.dev.label, w.saturating_sub(change.len())),
                            if e.dev.named { t.fg() } else { t.dim() },
                        ),
                        Span::styled(change, t.s(t.cyan)),
                    ])),
                    Cell::from(how(e)).style(t.dim()),
                    Cell::from(if e.private_wifi { "!" } else { "" }).style(t.s(t.yellow)),
                ])
            })
            .collect();
        widgets::table(
            f,
            r,
            t,
            TableSpec {
                header: vec!["", "device (named first)", "", ""],
                widths: vec![
                    ratatui::layout::Constraint::Length(3),
                    ratatui::layout::Constraint::Fill(1),
                    ratatui::layout::Constraint::Length(13),
                    ratatui::layout::Constraint::Length(1),
                ],
                rows: table,
                selected: Some(m.cur.sel),
            },
        );
    }
    let Some(d) = detail.filter(|d| d.height >= 3) else {
        return;
    };
    let bl = panel(t, "Details", "");
    let r = inner(&bl, d);
    f.render_widget(bl, d);
    let w = r.width as usize;
    let mut l: Vec<Line<'static>> = Vec::new();
    let mut say = |s: &str, st| {
        for x in wrap(s, w.max(8)) {
            l.push(Line::styled(x, st));
        }
    };
    if let Some(e) = rows.get(m.cur.sel) {
        say(&e.dev.label, t.fg());
        say(
            match (m.ticks.contains(&e.dev.tag), e.filtered) {
                (true, true) => "filtered now, and stays so",
                (true, false) => "not filtered now: Enter starts filtering it",
                (false, true) => "filtered now: Enter takes it off",
                (false, false) => "not filtered",
            },
            t.dim(),
        );
        if e.private_wifi {
            say(
                "It uses a private (random) Wi-Fi address: turn 'private address' off on the \
                 device for this Wi-Fi, or it will slip out of the filter.",
                t.s(t.yellow),
            );
        }
        if !e.dev.named {
            say("No name yet: e names it first.", t.dim());
        }
        if let Some(who) =
            v.s.counters
                .value
                .as_ref()
                .map(|c| family::hijacked(c, &e.dev.zone))
                .filter(|w| !w.is_empty())
        {
            say(
                &format!(
                    "It can't be filtered on this router yet: {} sends its lookups to the \
                     router first (Enter says more).",
                    who.join(", ")
                ),
                t.s(t.yellow),
            );
        }
        say("", t.dim());
    }
    let svc = family::service();
    say(
        &format!(
            "A ticked device's name lookups go to {} instead of the router, so adult and \
             other unwanted sites don't open on it. Every other device is left as it is.",
            svc.name
        ),
        t.fg(),
    );
    say(actions::FILTER_LIMITS, t.dim());
    say(
        "Enter shows the plan first: one change for every device ticked or unticked, made \
         through the guard.",
        t.s(t.cyan),
    );
    f.render_widget(Paragraph::new(l), r);
}

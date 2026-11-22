//! Network: what listens on the server (with its status against the baseline, the audit's
//! own rule) and the established connections. Drawn like sentry's. `b` marks the selected
//! port expected, or takes that back (`servers/<name>/baseline.toml`).

use ratatui::Frame;
use ratatui::layout::Rect;

use super::{Hints, View};
use crate::audit;
use crate::config::Server;
use crate::remote::SudoMode;
use crate::tui::data::Kind;
use crate::tui::target::{Effect, Own};
use sentry_core::baseline::{BaselineFile, glob};
use sentry_core::collectors::net::{ListenStatus, Listener};
use sentry_core::tui::Cursor;
use sentry_core::tui::keys::Action;
use sentry_core::tui::netview::{self, ListenRow, NetView};

#[derive(Default)]
pub struct Network {
    pub cur: Cursor,
}

pub fn hints() -> Hints {
    netview::hints()
}

/// The listeners as the screen shows them: `sockets` (read without sudo) with the process
/// names root sees filled in from `names`, each with its status. A socket the audit would
/// flag but whose finding is marked expected is baseline too, so marking it here or on
/// Maintenance comes to the same.
pub fn net_rows(
    sockets: &[Listener],
    names: Option<&[Listener]>,
    cfg: &Server,
    base: &BaselineFile,
) -> Vec<Listener> {
    sockets
        .iter()
        .map(|l| {
            let mut l = l.clone();
            if l.process.is_none()
                && let Some(n) = names.into_iter().flatten().find(|n| {
                    n.proto == l.proto
                        && n.addr == l.addr
                        && n.port == l.port
                        && n.process.is_some()
                })
            {
                l.process = n.process.clone();
                l.pid = n.pid;
            }
            l.status = match audit::listener_status(&l, cfg, base) {
                ListenStatus::New
                    if cfg
                        .findings
                        .iter()
                        .chain(&base.findings)
                        .any(|g| glob(g, &audit::listener_id(&l))) =>
                {
                    ListenStatus::Baseline
                }
                s => s,
            };
            l
        })
        .collect()
}

/// The process names only root sees; from the inventory read they come without pids (those
/// may have changed since).
fn names(v: &View) -> Option<Vec<Listener>> {
    let mut n = v.s.listeners.value.clone()?;
    if v.inventory.is_some() {
        for l in &mut n {
            l.pid = None;
        }
    }
    Some(n)
}

/// Every listener, once the sockets were read.
pub fn all(v: &View) -> Option<Vec<Listener>> {
    let s = v.s.sockets.value.as_ref()?;
    Some(net_rows(
        &s.listeners,
        names(v).as_deref(),
        v.cfg,
        &v.sh.baseline,
    ))
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

/// The container that publishes a port.
fn container<'a>(v: &View<'a>, l: &Listener) -> Option<&'a str> {
    v.s.docker
        .value
        .as_ref()?
        .containers
        .iter()
        .find(|c| c.ports.iter().any(|(_, hp, _)| *hp == l.port))
        .map(|c| c.name.as_str())
}

/// The PROCESS column: its name; else the container publishing the port; else how to get
/// the name.
fn process(v: &View, l: &Listener) -> String {
    if let Some(o) = netview::owner(l) {
        return o;
    }
    if let Some(c) = container(v, l) {
        return format!("container {c}");
    }
    if v.s.sudo.value == Some(SudoMode::Password) && v.inventory.is_none() {
        "needs I".into()
    } else {
        "needs sudo: ss -tulpn".into()
    }
}

/// How many listeners are new: the count beside the screen's name. Before the screen was
/// opened, from what the last audit saw.
pub fn new_count(v: &View) -> usize {
    let from_report = || {
        let r = v.s.report.value.as_ref()?.as_deref()?;
        Some(net_rows(
            r.snapshot.listeners.as_deref()?,
            None,
            v.cfg,
            &v.sh.baseline,
        ))
    };
    all(v)
        .or_else(from_report)
        .unwrap_or_default()
        .iter()
        .filter(|l| l.status == ListenStatus::New)
        .count()
}

impl Network {
    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        match a {
            Action::Refresh => vec![Own::fetch(Kind::Sockets), Own::fetch(Kind::Listeners)],
            // `b` toggles expected (`e` too, as in sentry), for the port on every address:
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
                        // A name not known yet must still match once `I` shows it.
                        keys: group
                            .iter()
                            .filter(|x| x.status == ListenStatus::New)
                            .map(|x| {
                                format!("{}/{}", x.local(), x.process.as_deref().unwrap_or("*"))
                            })
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
                        "not reachable from outside: nothing to mark".into(),
                    )],
                }
            }
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let shown = v.s.sockets.value.as_ref().map(|_| rows(v));
        let n = shown.as_ref().map_or(0, Vec::len);
        let listen = shown.as_ref().map(|rows| {
            rows.iter()
                .map(|l| ListenRow {
                    l,
                    process: process(v, l),
                })
                .collect()
        });
        let waiting = match &v.s.sockets.err {
            Some(crate::remote::SrvError::NotFound(_)) => format!("ss not found on {}", v.name),
            Some(e) => format!("sockets: {e}"),
            None => "reading sockets…".into(),
        };
        // Names from the inventory read: say how old that is.
        let note = if v.s.listeners.value.is_some() {
            v.inv_note().trim_start_matches(" · ").to_string()
        } else {
            String::new()
        };
        self.cur.page = netview::draw(
            f,
            area,
            v.t,
            &NetView {
                listen,
                waiting,
                source: "ss -tulpn",
                note,
                established: v.s.sockets.value.as_ref().map_or(&[], |s| &s.established),
                sel: v.cur.min(n.saturating_sub(1)),
            },
        );
    }
}

/// What Claude is told about the selected listener.
pub fn ask_text(v: &View, l: &Listener) -> String {
    let id = audit::listener_id(l);
    let finding =
        v.s.report
            .value
            .as_ref()
            .and_then(|r| r.as_deref())
            .and_then(|r| r.findings.iter().find(|f| f.id == id))
            .map_or("none".to_string(), |f| {
                format!("{id}, {}", if f.expected { "expected" } else { "open" })
            });
    format!(
        "A listening socket on the server (ss -tulpn): {} {}; process: {}; published by \
         container: {}; sentry-server status: {}; the audit's finding: {finding}",
        l.proto,
        l.local(),
        netview::owner(l).unwrap_or_else(|| "not visible without root".into()),
        container(v, l).unwrap_or("none"),
        match l.status {
            ListenStatus::New => "new (not expected)",
            ListenStatus::Baseline => "expected (baseline)",
            ListenStatus::Local => "local only",
            ListenStatus::Ephemeral => "a client socket",
        },
    )
}

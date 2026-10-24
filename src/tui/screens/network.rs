//! Network: listeners (with baseline status) and established connections. `e` marks the
//! selected listener as expected (written to baseline.toml).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::widgets::{Cell, Paragraph, Row};

use super::{Cursor, Hints, View};
use crate::collectors::net::{ListenStatus, Listener};
use crate::tui::app::{BaselineEdit, Effect};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::widgets::{TableSpec, inner, panel, table};

#[derive(Default)]
pub struct Network {
    pub cur: Cursor,
}

pub fn hints() -> Hints {
    vec![
        ("j/k", "select"),
        ("b", "mark expected"),
        ("/", "filter"),
        ("r", "refresh"),
    ]
}

impl Network {
    fn rows<'a>(&self, v: &View<'a>) -> Vec<&'a Listener> {
        v.d.net.get().map_or(Vec::new(), |n| {
            n.listeners
                .iter()
                .filter(|l| v.matches(&[&l.local(), l.process.as_deref().unwrap_or(""), &l.proto]))
                .collect()
        })
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        let rows = self.rows(v);
        if self.cur.nav(a, rows.len()) {
            return Vec::new();
        }
        match a {
            Action::Refresh => vec![Effect::Fetch(Fetch::Net)],
            // `b` everywhere marks things expected (`e` kept as an alias). A known service is
            // marked on all of its sockets at once, as the Audit tab groups it.
            Action::Char('b' | 'e') => match rows.get(self.cur.clamp(rows.len())) {
                Some(l) if l.status == ListenStatus::Baseline => {
                    vec![Effect::Toast(format!(
                        "{} is already in the baseline",
                        l.key()
                    ))]
                }
                Some(l) => {
                    let svc = |x: &Listener| {
                        x.port
                            .parse()
                            .ok()
                            .and_then(|p| crate::audit::known::service(&x.proto, p))
                            .map(|s| s.name)
                    };
                    match svc(l) {
                        Some(name) => {
                            let keys: Vec<String> = v
                                .d
                                .net
                                .get()
                                .map(|n| {
                                    n.listeners
                                        .iter()
                                        .filter(|x| {
                                            svc(x) == Some(name) && x.status == ListenStatus::New
                                        })
                                        .map(Listener::key)
                                        .collect()
                                })
                                .unwrap_or_default();
                            vec![Effect::Baseline(BaselineEdit::Listeners(keys))]
                        }
                        None => vec![Effect::Baseline(BaselineEdit::Listener(l.key()))],
                    }
                }
                None => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let [left, right] =
            Layout::horizontal([Constraint::Ratio(55, 100), Constraint::Ratio(45, 100)])
                .spacing(2)
                .areas(area);
        let rows = self.rows(v);
        let sel = self.cur.clamp(rows.len());
        let new = rows
            .iter()
            .filter(|l| l.status == ListenStatus::New)
            .count();
        let block = panel(
            t,
            "Listening",
            format!("ss -tulpn · {} · {new} new", rows.len()),
        );
        let r = inner(&block, left);
        f.render_widget(block, left);
        self.cur.page = r.height as usize;
        if v.d.net.get().is_none() {
            f.render_widget(
                Paragraph::new(v.d.net.status(v.d.loading(Fetch::Net))).style(t.dim()),
                r,
            );
        } else {
            let body: Vec<Row> = rows
                .iter()
                .map(|l| {
                    let (txt, c) = match l.status {
                        ListenStatus::New => ("NEW", t.red),
                        ListenStatus::Baseline => ("baseline", t.dim),
                        ListenStatus::Local => ("local", t.green),
                        ListenStatus::Ephemeral => ("client", t.dim),
                    };
                    let svc = l
                        .port
                        .parse()
                        .ok()
                        .and_then(|p| crate::audit::known::service(&l.proto, p))
                        .map(|s| s.name);
                    let proc = match (&l.process, l.pid, svc) {
                        (Some(p), Some(pid), _) => format!("{p} ({pid})"),
                        (Some(p), None, _) => p.clone(),
                        // Root-owned: ss can't show the process to a normal user.
                        (None, _, Some(s)) => format!("root · {s}"),
                        _ => "root · unknown".into(),
                    };
                    Row::new(vec![
                        Cell::from(l.proto.clone()).style(t.dim()),
                        Cell::from(l.local()),
                        Cell::from(proc),
                        Cell::from(txt).style(t.s(c)),
                    ])
                })
                .collect();
            table(
                f,
                r,
                t,
                TableSpec {
                    header: vec!["PROTO", "LOCAL", "PROCESS", "STATUS"],
                    widths: vec![
                        Constraint::Length(5),
                        Constraint::Fill(3),
                        Constraint::Fill(2),
                        Constraint::Length(8),
                    ],
                    rows: body,
                    selected: (!rows.is_empty()).then_some(sel),
                },
            );
        }

        let est =
            v.d.net
                .get()
                .map_or(Vec::new(), |n| n.established.iter().collect::<Vec<_>>());
        let block = panel(t, "Established", est.len().to_string());
        let r = inner(&block, right);
        f.render_widget(block, right);
        let body: Vec<Row> = est
            .iter()
            .map(|c| {
                Row::new(vec![
                    Cell::from(c.peer.clone()),
                    Cell::from(c.process.clone().unwrap_or_else(|| "?".into())).style(t.dim()),
                ])
            })
            .collect();
        table(
            f,
            r,
            t,
            TableSpec {
                header: vec!["PEER", "PROCESS"],
                widths: vec![Constraint::Fill(1), Constraint::Length(18)],
                rows: body,
                selected: None,
            },
        );
    }
}

impl Network {
    pub fn ask(&self, v: &View) -> Result<crate::claude::Ask, String> {
        let rows = self.rows(v);
        let l = rows
            .get(self.cur.sel.min(rows.len().saturating_sub(1)))
            .ok_or("no listener selected")?;
        let svc = l
            .port
            .parse()
            .ok()
            .and_then(|p| crate::audit::known::service(&l.proto, p))
            .map_or("not a port sentry recognises".to_string(), |s| {
                s.name.to_string()
            });
        let owner = match (&l.process, l.pid) {
            (Some(p), Some(pid)) => format!("{p} (pid {pid})"),
            (Some(p), None) => p.clone(),
            _ => "owned by root (not visible to an unprivileged ss)".into(),
        };
        Ok(crate::claude::Ask::new(
            format!("listener {} {}", l.proto, l.local()),
            format!(
                "A listening socket on my machine (ss -tulpn):\n{} {}\nprocess: {owner}\nknown service: {svc}\nreachable from: {}\nsentry status: {:?}",
                l.proto,
                l.local(),
                crate::audit::known::scope(&l.addr),
                l.status
            ),
            "What is this, does it need to be reachable, and how do I close it if not?",
        ))
    }
}

//! Network: listeners (with baseline status) and established connections. `e` marks the
//! selected listener as expected (written to baseline.toml).

use ratatui::Frame;
use ratatui::layout::Rect;

use super::{Cursor, Hints, View};
use crate::collectors::net::{ListenStatus, Listener};
use crate::tui::app::{BaselineEdit, Effect};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::netview::{self, ListenRow, NetView};

#[derive(Default)]
pub struct Network {
    pub cur: Cursor,
}

pub fn hints() -> Hints {
    netview::hints()
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
            // `b` toggles expected (`e` kept as an alias). A known service is marked or
            // un-marked on all of its sockets at once, as the Audit tab groups it.
            Action::Char('b' | 'e') => match rows.get(self.cur.clamp(rows.len())) {
                Some(l) => {
                    let svc = |x: &Listener| {
                        x.port
                            .parse()
                            .ok()
                            .and_then(|p| crate::audit::known::service(&x.proto, p))
                            .map(|s| s.name)
                    };
                    let unmark = l.status == ListenStatus::Baseline;
                    let keys: Vec<String> = match svc(l) {
                        Some(name) => {
                            v.d.net
                                .get()
                                .map(|n| {
                                    n.listeners
                                        .iter()
                                        .filter(|x| {
                                            svc(x) == Some(name)
                                                && (x.status == ListenStatus::Baseline) == unmark
                                                && (unmark || x.status == ListenStatus::New)
                                        })
                                        .map(Listener::key)
                                        .collect()
                                })
                                .unwrap_or_default()
                        }
                        None => vec![l.key()],
                    };
                    let edit = BaselineEdit::Listeners(keys);
                    vec![if unmark {
                        Effect::Unbaseline(edit)
                    } else {
                        Effect::Baseline(edit)
                    }]
                }
                None => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let rows = self.rows(v);
        let sel = self.cur.clamp(rows.len());
        let net = v.d.net.get();
        let listen = net.map(|_| {
            rows.iter()
                .map(|l| {
                    let svc = l
                        .port
                        .parse()
                        .ok()
                        .and_then(|p| crate::audit::known::service(&l.proto, p))
                        .map(|s| s.name);
                    let process = match (netview::owner(l), svc) {
                        (Some(o), _) => o,
                        // Root-owned: ss can't show the process to a normal user.
                        (None, Some(s)) => format!("root · {s}"),
                        _ => "root · unknown".into(),
                    };
                    ListenRow { l, process }
                })
                .collect()
        });
        self.cur.page = netview::draw(
            f,
            area,
            v.t,
            &NetView {
                listen,
                waiting: v.d.net.status(v.d.loading(Fetch::Net)),
                source: "ss -tulpn",
                note: String::new(),
                established: net.map_or(&[], |n| &n.established),
                sel,
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

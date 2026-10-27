//! Flatpaks: installed apps with permission flags (metadata + overrides, read live), the
//! GL.nvidia/GL32 pair check, `o` to open Flatseal, `Enter` for full permissions.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row};

use super::{Cursor, Hints, View};
use crate::collectors::flatpak::{App, Severity, gl_pair_status, gl_version_for_driver};
use crate::exec::Cmd;
use crate::tui::app::{Effect, info_modal};
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::widgets::{TableSpec, table};

const FLATSEAL: &str = "com.github.tchx84.Flatseal";

#[derive(Default)]
pub struct Flatpaks {
    pub cur: Cursor,
}

pub fn on_enter(_v: &View) -> Vec<Effect> {
    vec![Effect::Fetch(Fetch::Flatpak)]
}

pub fn hints() -> Hints {
    vec![
        ("j/k", "select"),
        ("Enter", "permissions"),
        ("o", "open in Flatseal"),
        ("c", "rescan perms"),
    ]
}

impl Flatpaks {
    fn rows<'a>(&self, v: &View<'a>) -> Vec<&'a App> {
        v.d.flatpak.get().map_or(Vec::new(), |fp| {
            fp.apps
                .iter()
                .filter(|a| {
                    let flags: Vec<&str> = a.flags.iter().map(|f| f.label.as_str()).collect();
                    v.matches(&[&a.id, &a.origin, &flags.join(" ")])
                })
                .collect()
        })
    }

    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        let rows = self.rows(v);
        if self.cur.nav(a, rows.len()) {
            return Vec::new();
        }
        match a {
            Action::Check | Action::Refresh => vec![
                Effect::Fetch(Fetch::Flatpak),
                Effect::Toast("rescanning permissions…".into()),
            ],
            Action::Char('o') => {
                let Some(app) = rows.get(self.cur.clamp(rows.len())) else {
                    return Vec::new();
                };
                let installed =
                    v.d.flatpak
                        .get()
                        .is_some_and(|fp| fp.apps.iter().any(|a| a.id == FLATSEAL));
                if !installed {
                    return vec![Effect::Toast("Flatseal is not installed (flatpak install flathub com.github.tchx84.Flatseal)".into())];
                }
                vec![Effect::Detach(
                    Cmd::host("flatpak").args(["run", FLATSEAL, &app.id]),
                    format!("opening {} in Flatseal", app.id),
                )]
            }
            Action::Enter => {
                let Some(app) = rows.get(self.cur.clamp(rows.len())) else {
                    return Vec::new();
                };
                let t = v.t;
                let p = &app.perms;
                let row = |k: &str, vals: &[String]| {
                    Line::from(vec![
                        Span::styled(format!("{k:<12}"), t.dim()),
                        Span::styled(
                            if vals.is_empty() {
                                "—".into()
                            } else {
                                vals.join(" ")
                            },
                            t.fg(),
                        ),
                    ])
                };
                let mut lines = vec![
                    row("filesystems", &p.filesystems),
                    row("shared", &p.shared),
                    row("sockets", &p.sockets),
                    row("devices", &p.devices),
                    row("talk", &p.talk),
                    row("own", &p.own),
                ];
                if app.overridden {
                    lines.push(Line::styled("* includes local overrides", t.dim()));
                }
                vec![Effect::Confirm(info_modal(
                    t,
                    &format!("{} · {}", app.id, app.origin),
                    lines,
                ))]
            }
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let [list, _, foot] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(2),
        ])
        .areas(area);
        let Some(fp) = v.d.flatpak.get() else {
            f.render_widget(
                Paragraph::new(v.d.flatpak.status(v.d.loading(Fetch::Flatpak))).style(t.dim()),
                list,
            );
            return;
        };
        let rows = self.rows(v);
        self.cur.page = list.height as usize;
        let sel = self.cur.clamp(rows.len());
        let body: Vec<Row> = rows
            .iter()
            .map(|a| {
                let worst = a.flags.iter().map(|f| f.severity).max();
                let flags = a
                    .flags
                    .iter()
                    .map(|f| f.label.as_str())
                    .collect::<Vec<_>>()
                    .join("  ");
                let fc = match worst {
                    Some(Severity::High) => t.red,
                    Some(_) => t.yellow,
                    None => t.dim,
                };
                let name = if a.overridden {
                    format!("{} *", a.id)
                } else {
                    a.id.clone()
                };
                Row::new(vec![
                    Cell::from(name),
                    Cell::from(a.origin.clone()).style(t.s(if a.unverified_origin {
                        t.yellow
                    } else {
                        t.dim
                    })),
                    Cell::from(a.version.clone()).style(t.dim()),
                    Cell::from(if flags.is_empty() {
                        "—".into()
                    } else {
                        flags
                    })
                    .style(t.s(fc)),
                ])
            })
            .collect();
        table(
            f,
            list,
            t,
            TableSpec {
                header: vec!["APPLICATION", "ORIGIN", "VERSION", "FLAGS"],
                widths: vec![
                    Constraint::Length(40),
                    Constraint::Length(10),
                    Constraint::Length(14),
                    Constraint::Fill(1),
                ],
                rows: body,
                selected: (!rows.is_empty()).then_some(sel),
            },
        );

        let mut lines = vec![Line::styled(
            format!(
                "permissions read live from metadata + overrides · overrides: {} (* marks apps with one)",
                fp.overrides.len()
            ),
            t.dim(),
        )];
        // GL.nvidia + GL32 must match the host driver, or 32-bit games lose GL.
        let driver =
            v.d.gpu
                .get()
                .and_then(|g| g.as_ref())
                .map(|g| g.driver.clone());
        if let Some(d) = driver {
            let (gl, gl32) = gl_pair_status(&fp.gl_nvidia, &d);
            let ok = gl && gl32;
            let stale: Vec<String> = fp
                .gl_nvidia
                .iter()
                .filter(|(_, ver)| *ver != gl_version_for_driver(&d))
                .map(|(k, ver)| format!("{k}.nvidia-{ver}"))
                .collect();
            let mut spans = vec![
                Span::styled(format!("host driver {d} · "), t.dim()),
                Span::styled(
                    format!(
                        "GL {} · GL32 {}",
                        if gl { "✓" } else { "✗" },
                        if gl32 { "✓" } else { "✗" }
                    ),
                    t.s(if ok { t.green } else { t.red }),
                ),
            ];
            if !stale.is_empty() {
                spans.push(Span::styled(
                    format!(
                        " · old extensions (not removed by --unused): {} · remove them in Cleanup (C on Maintenance)",
                        stale.join(", ")
                    ),
                    t.dim(),
                ));
            }
            lines.push(Line::from(spans));
        }
        f.render_widget(Paragraph::new(lines), foot);
    }
}

impl Flatpaks {
    pub fn ask(&self, v: &View) -> Result<crate::claude::Ask, String> {
        let rows = self.rows(v);
        let a = rows
            .get(self.cur.sel.min(rows.len().saturating_sub(1)))
            .ok_or("no app selected")?;
        let p = &a.perms;
        let j = |x: &[String]| {
            if x.is_empty() {
                "—".to_string()
            } else {
                x.join(" ")
            }
        };
        Ok(crate::claude::Ask::new(
            format!("flatpak {}", a.id),
            format!(
                "An installed Flatpak app (permissions = metadata + overrides):\nid {}\norigin {}\nversion {}\ninstallation {}\nfilesystems {}\nshared {}\nsockets {}\ndevices {}\ntalk-name {}\nown-name {}\nlocal overrides: {}",
                a.id,
                a.origin,
                a.version,
                a.installation,
                j(&p.filesystems),
                j(&p.shared),
                j(&p.sockets),
                j(&p.devices),
                j(&p.talk),
                j(&p.own),
                if a.overridden { "yes" } else { "no" }
            ),
            "Does this app need these permissions, and what can I safely restrict?",
        ))
    }
}

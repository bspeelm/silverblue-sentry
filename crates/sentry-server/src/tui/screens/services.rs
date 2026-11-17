//! Services and timers: the units the config names, and anything else that failed.

use super::*;

#[derive(Default)]
pub struct Services {
    pub cur: Cursor,
}

impl Services {
    pub fn handle(&mut self, a: Action, v: &View, r: &Remote) -> Vec<Effect> {
        match a {
            Action::Refresh | Action::Check => {
                vec![Effect::Fetch(Kind::Units), Effect::Fetch(Kind::Journal)]
            }
            Action::Enter => unit_detail(v),
            Action::Char(c @ ('R' | 'x' | 'L')) => match unit_rows(v).into_iter().nth(v.cur) {
                Some(u) => {
                    let failed = u.state.starts_with("failed")
                        || v.s
                            .units
                            .value
                            .as_ref()
                            .is_some_and(|x| x.failed().any(|f| f.unit == u.unit));
                    crate::tui::actions::services(v, r, c, &u.unit, failed)
                }
                None => Vec::new(),
            },
            _ => Vec::new(),
        }
    }
}

pub struct UnitLine {
    pub unit: String,
    pub state: String,
    pub state_color: Color,
    pub last: String,
    pub next: String,
    pub result: String,
}

pub fn unit_rows(v: &View) -> Vec<UnitLine> {
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

pub fn services(f: &mut Frame, area: Rect, v: &View) {
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

pub fn unit_detail(v: &View) -> Vec<Effect> {
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

//! Containers: what docker runs, and how each is doing.

use super::*;

#[derive(Default)]
pub struct Containers {
    pub cur: Cursor,
}

impl Containers {
    pub fn handle(&mut self, a: Action, v: &View, r: &Remote) -> Vec<Effect> {
        match a {
            Action::Refresh => vec![Own::fetch(Kind::Docker)],
            Action::Check => vec![
                Own::fetch(Kind::Stats),
                Effect::Toast("docker stats…".into()),
            ],
            Action::Enter => container_detail(v),
            Action::Char(c @ ('R' | 'L' | 'p' | 'u')) => match selected_container(v) {
                Some(ct) => {
                    crate::tui::actions::containers(v, r, c, &ct.name, ct.compose.as_deref())
                }
                None => Vec::new(),
            },
            _ => Vec::new(),
        }
    }
}

pub fn containers(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let Some(d) = &v.s.docker.value else {
        let b = panel(t, "Containers", "");
        let r = inner(&b, area);
        f.render_widget(b, area);
        let text = match &v.s.docker.err {
            Some(crate::remote::SrvError::SudoPassword(_)) => needs_password(v, "the containers"),
            _ => vec![waiting(v, &v.s.docker, "docker")],
        };
        f.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), r);
        return;
    };
    let projects = d
        .projects
        .iter()
        .map(|p| format!("{} {}", p.name, p.status))
        .collect::<Vec<_>>()
        .join(" · ");
    let b = panel(t, "Containers", format!("{projects}{}", v.inv_note()));
    let r = inner(&b, area);
    f.render_widget(b, area);
    let stats = v.s.stats.value.as_ref();
    let rows: Vec<Row> = container_list(v)
        .into_iter()
        .map(|c| {
            let (state_c, health_c) = (
                if c.status == "running" {
                    t.green
                } else if c.finished() {
                    t.dim
                } else {
                    t.red
                },
                match c.health.as_deref() {
                    Some("healthy") => t.green,
                    Some("unhealthy") => t.red,
                    _ => t.dim,
                },
            );
            let st = stats.and_then(|s| s.iter().find(|s| s.name == c.name));
            let ports = c
                .ports
                .iter()
                .filter(|(ip, _, _)| ip != "::")
                .map(|(ip, hp, inner)| {
                    let ip = if ip == "0.0.0.0" { "" } else { ip.as_str() };
                    format!("{ip}:{hp}→{}", inner.trim_end_matches("/tcp"))
                })
                .collect::<Vec<_>>()
                .join(" ");
            Row::new(vec![
                Cell::from(c.name.clone()).style(t.fg()),
                Cell::from(c.compose.clone().unwrap_or_else(|| "-".into())).style(t.dim()),
                Cell::from(if c.finished() {
                    "done".to_string()
                } else {
                    c.status.clone()
                })
                .style(t.s(state_c)),
                Cell::from(c.health.clone().unwrap_or_else(|| "-".into())).style(t.s(health_c)),
                Cell::from(c.restarts.to_string()).style(t.dim()),
                Cell::from(c.started_at.map_or("-".into(), |s| {
                    fmt::age(v.secs_since(s)).replace("just now", "now")
                }))
                .style(t.dim()),
                Cell::from(ports).style(t.dim()),
                Cell::from(st.map_or(String::new(), |s| format!("{:.1}%", s.cpu_pct)))
                    .style(t.fg()),
                Cell::from(st.map_or(String::new(), |s| {
                    s.mem.split(" / ").next().unwrap_or("").to_string()
                }))
                .style(t.fg()),
            ])
        })
        .collect();
    widgets::table(
        f,
        r,
        t,
        TableSpec {
            header: vec![
                "Name", "Project", "State", "Health", "Restarts", "Up", "Ports", "CPU", "Mem",
            ],
            widths: vec![
                Constraint::Fill(2),
                Constraint::Fill(1),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Fill(3),
                Constraint::Length(6),
                Constraint::Length(9),
            ],
            rows,
            selected: Some(v.cur),
        },
    );
}

/// Containers in table order, filtered.
pub fn container_list<'a>(v: &View<'a>) -> Vec<&'a Container> {
    let Some(d) = &v.s.docker.value else {
        return Vec::new();
    };
    d.containers
        .iter()
        .filter(|c| {
            v.matches(&[
                &c.name,
                &c.image,
                &c.status,
                c.compose.as_deref().unwrap_or(""),
                c.health.as_deref().unwrap_or(""),
            ])
        })
        .collect()
}

pub fn selected_container<'a>(v: &View<'a>) -> Option<&'a Container> {
    container_list(v).get(v.cur).copied()
}

pub fn container_detail(v: &View) -> Vec<Effect> {
    let Some(c) = selected_container(v) else {
        return Vec::new();
    };
    let t = v.t;
    let mut lines = vec![
        Line::styled(format!("image     {}", c.image), t.fg()),
        Line::styled(
            format!(
                "state     {} (exit {}){}",
                c.status,
                c.exit_code,
                if c.oom {
                    " · killed: out of memory"
                } else {
                    ""
                }
            ),
            t.fg(),
        ),
        Line::styled(
            format!(
                "health    {}",
                c.health.as_deref().unwrap_or("no health check")
            ),
            t.fg(),
        ),
        Line::styled(format!("restarts  {}", c.restarts), t.fg()),
    ];
    if let Some(s) = c.started_at {
        lines.push(Line::styled(
            format!("started   {s} ({})", fmt::ago(v.secs_since(s))),
            t.fg(),
        ));
    }
    for (ip, hp, inner) in &c.ports {
        lines.push(Line::styled(
            format!("port      {ip}:{hp} → {inner}"),
            t.fg(),
        ));
    }
    if c.docker_sock {
        lines.push(Line::styled(
            "mounts /var/run/docker.sock: can control docker (root on the host)",
            t.s(t.yellow),
        ));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!("docker logs --tail 50 {}", c.name),
        t.dim(),
    ));
    vec![Effect::Info(c.name.clone(), lines)]
}

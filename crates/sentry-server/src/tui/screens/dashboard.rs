//! The Dashboard: the server at a glance, and a status list that jumps to what needs a look.

use super::*;

#[derive(Default)]
pub struct Dashboard {
    pub cur: Cursor,
}

impl Dashboard {
    pub fn handle(&mut self, a: Action, v: &View, r: &Remote) -> Vec<Effect> {
        match a {
            Action::Refresh | Action::Check => [
                Kind::Probe,
                Kind::Disks,
                Kind::Units,
                Kind::Docker,
                Kind::Report,
            ]
            .into_iter()
            .map(Effect::Fetch)
            .collect(),
            // A status row: the screen it's about, on the row it means.
            Action::Enter => match status_rows(v).get(v.cur) {
                Some(StatusRow {
                    goto: Some(t),
                    pick,
                    ..
                }) => {
                    let mut e = vec![Effect::Goto(*t)];
                    e.extend(pick.map(|p| Effect::MaintFind(p.into())));
                    e
                }
                _ => Vec::new(),
            },
            Action::Char('a') => crate::tui::actions::custom(v, r),
            Action::Char('B') => crate::tui::actions::reboot(v, r),
            _ => Vec::new(),
        }
    }
}

pub struct StatusRow {
    pub color: Color,
    pub icon: &'static str,
    pub text: String,
    pub goto: Option<ScreenId>,
    /// On Maintenance: the recommendation to select (a key prefix).
    pub pick: Option<&'static str>,
}

pub fn status_rows(v: &View) -> Vec<StatusRow> {
    let t = v.t;
    let s = v.s;
    let ok = |text: String, goto| StatusRow {
        color: t.green,
        icon: "✓",
        text,
        goto,
        pick: None,
    };
    let bad = |c, text: String, goto| StatusRow {
        color: c,
        icon: "●",
        text,
        goto,
        pick: None,
    };
    let mut out = Vec::new();
    if let Some((_, why)) = &s.unreachable {
        out.push(bad(t.red, format!("can't reach {}: {why}", v.name), None));
    }
    if s.rebooted() {
        out.push(bad(
            t.mag,
            "the server rebooted since sentry-server started".into(),
            None,
        ));
    }
    match &s.apt.value {
        Some(a) => {
            if let Some(since) = a.reboot_since {
                let k = match &a.newest_kernel {
                    Some(n) if a.kernel_pending() => {
                        format!(" · kernel {} → {n}", a.running_kernel)
                    }
                    _ => String::new(),
                };
                out.push(bad(
                    if a.now - since > 14 * 86400 {
                        t.red
                    } else {
                        t.yellow
                    },
                    format!("reboot required for {}{k}", fmt::age(a.now - since)),
                    Some(ScreenId::Maint),
                ));
                if let Some(r) = out.last_mut() {
                    r.pick = Some("reboot");
                }
            }
            let sec = a
                .upgrades
                .iter()
                .filter(|p| p.kind == PkgKind::Security)
                .count();
            if sec > 0 {
                out.push(bad(
                    t.red,
                    format!(
                        "{sec} security update(s) waiting ({} in all)",
                        a.upgrades.len()
                    ),
                    Some(ScreenId::Maint),
                ));
                if let Some(r) = out.last_mut() {
                    r.pick = Some("wf:apt-maintenance");
                }
            } else if !a.upgrades.is_empty() {
                out.push(bad(
                    t.yellow,
                    format!("{} update(s) waiting", a.upgrades.len()),
                    Some(ScreenId::Maint),
                ));
                if let Some(r) = out.last_mut() {
                    r.pick = Some("wf:apt-maintenance");
                }
            } else {
                out.push(ok("packages up to date".into(), Some(ScreenId::Maint)));
            }
        }
        None => out.push(StatusRow {
            color: t.dim,
            icon: "·",
            text: s
                .apt
                .err
                .as_ref()
                .map_or("reading updates…".into(), |e| format!("updates: {e}")),
            goto: Some(ScreenId::Maint),
            pick: None,
        }),
    }
    if let Some(u) = &s.units.value {
        for rule in &v.cfg.timers {
            let Some(st) = u.get(&rule.unit) else {
                continue;
            };
            let ran = st.triggers.as_deref().and_then(|x| u.get(x));
            let failed = ran.is_some_and(|r| !r.result.is_empty() && r.result != "success");
            match st.last_trigger {
                Some(l) => {
                    let age = v.secs_since(l);
                    let stale = age > rule.max_age.0.as_secs() as i64;
                    let text = format!(
                        "{} ran {}{}",
                        rule.unit.trim_end_matches(".timer"),
                        fmt::ago(age),
                        if failed { " and failed" } else { "" }
                    );
                    out.push(if failed || stale {
                        bad(t.red, text, Some(ScreenId::Svc))
                    } else {
                        ok(text, Some(ScreenId::Svc))
                    });
                }
                None => out.push(bad(
                    t.red,
                    format!("{} never ran", rule.unit),
                    Some(ScreenId::Svc),
                )),
            }
        }
        let down: Vec<&str> = v
            .cfg
            .services
            .iter()
            .filter(|svc| u.get(svc).is_some_and(|st| st.active != "active"))
            .map(String::as_str)
            .collect();
        let failed = u.failed().count();
        if !down.is_empty() {
            out.push(bad(
                t.red,
                format!("down: {}", down.join(", ")),
                Some(ScreenId::Svc),
            ));
        } else if !v.cfg.services.is_empty() {
            out.push(ok(
                format!("{} services running", v.cfg.services.len()),
                Some(ScreenId::Svc),
            ));
        }
        if failed > 0 {
            out.push(bad(
                t.yellow,
                format!("{failed} failed unit(s)"),
                Some(ScreenId::Svc),
            ));
        }
    }
    if let Some(d) = &s.docker.value {
        let n = d.containers.iter().filter(|c| !c.finished()).count();
        let running = d
            .containers
            .iter()
            .filter(|c| c.status == "running")
            .count();
        let unhealthy = d
            .containers
            .iter()
            .filter(|c| c.health.as_deref() == Some("unhealthy"))
            .count();
        let healthy = d
            .containers
            .iter()
            .filter(|c| c.health.as_deref() == Some("healthy"))
            .count();
        if running < n || unhealthy > 0 {
            out.push(bad(
                t.red,
                format!(
                    "{} of {n} containers not running · {unhealthy} unhealthy",
                    n - running
                ),
                Some(ScreenId::Cont),
            ));
        } else if n > 0 {
            out.push(ok(
                format!("{n} containers running · {healthy} healthy"),
                Some(ScreenId::Cont),
            ));
        }
    } else if let Some(e) = &s.docker.err {
        out.push(StatusRow {
            color: t.dim,
            icon: "·",
            text: format!("containers: {e}"),
            goto: Some(ScreenId::Cont),
            pick: None,
        });
    }
    match s.report.value.as_ref().map(|r| r.as_deref()) {
        Some(Some(r)) => {
            // The findings Maintenance lists (not the ones its item rows already say, nor
            // the ones put off), so the count and the rows it jumps to agree.
            let listed: Vec<String> = super::maint::recs(v)
                .into_iter()
                .filter_map(|x| match x.action {
                    crate::maint::recommend::Action::Fix(id) => Some(id),
                    _ => None,
                })
                .collect();
            let open: Vec<&Finding> = r
                .findings
                .iter()
                .filter(|f| listed.contains(&f.id))
                .collect();
            let when = r.snapshot.taken_at.map_or(String::new(), |ts| {
                format!(" (audit {})", fmt::ago(v.secs_since(ts)))
            });
            match open.iter().map(|f| f.severity).max() {
                Some(top) => {
                    let mut r = bad(
                        sev_color(t, top),
                        format!("{} open finding(s){when}", open.len()),
                        Some(ScreenId::Maint),
                    );
                    r.pick = Some("finding:");
                    out.push(r);
                }
                None => out.push(ok(format!("no open findings{when}"), Some(ScreenId::Maint))),
            }
        }
        Some(None) => out.push(StatusRow {
            color: t.dim,
            icon: "·",
            text: "no audit yet: c on Maintenance".into(),
            goto: Some(ScreenId::Maint),
            pick: Some("audit"),
        }),
        None => {}
    }
    out
}

pub fn overview(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let s = v.s;
    let [row1, row2, row3] = Layout::vertical([
        Constraint::Length(7),
        Constraint::Length(5),
        Constraint::Fill(1),
    ])
    .areas(area);
    let halves = |r: Rect| {
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas::<2>(r)
    };

    let [cpu_a, mem_a] = halves(row1);
    let p = s.probe.value.as_ref();
    let cpu_detail = match p {
        Some(p) => format!(
            "{:.0}% · load {:.2} {:.2} {:.2} · {} cores",
            s.cpu.last().unwrap_or(0.0),
            p.load[0],
            p.load[1],
            p.load[2],
            p.cores
        ),
        None => "…".into(),
    };
    let b = panel(t, "CPU", cpu_detail);
    let r = inner(&b, cpu_a);
    f.render_widget(b, cpu_a);
    graph(
        f.buffer_mut(),
        r,
        &s.cpu.vec(),
        100.0,
        t.load(s.cpu.last().unwrap_or(0.0)),
    );
    let mem_detail = match p {
        Some(p) => {
            let swap = if p.swap_total_kib > 0 {
                format!(
                    " · swap {:.0}%",
                    100.0 * (p.swap_total_kib - p.swap_free_kib.min(p.swap_total_kib)) as f64
                        / p.swap_total_kib as f64
                )
            } else {
                String::new()
            };
            format!(
                "{:.0}% of {}{swap}",
                p.mem_used_pct(),
                fmt::bytes(p.mem_total_kib * 1024)
            )
        }
        None => "…".into(),
    };
    let b = panel(t, "Memory", mem_detail);
    let r = inner(&b, mem_a);
    f.render_widget(b, mem_a);
    graph(f.buffer_mut(), r, &s.mem.vec(), 100.0, t.blue);

    let [net_a, hw_a] = halves(row2);
    let net_detail = match p.and_then(|p| p.iface.clone()) {
        Some(i) => format!(
            "{i} ↓ {} ↑ {}",
            fmt::rate(s.rx.last().unwrap_or(0.0)),
            fmt::rate(s.tx.last().unwrap_or(0.0))
        ),
        None => "…".into(),
    };
    let b = panel(t, "Network", net_detail);
    let r = inner(&b, net_a);
    f.render_widget(b, net_a);
    let rx = s.rx.vec();
    let max = rx.iter().cloned().fold(1.0, f64::max);
    graph(f.buffer_mut(), r, &rx, max, t.cyan);
    let b = panel(t, "Hardware", "");
    let r = inner(&b, hw_a);
    f.render_widget(b, hw_a);
    let mut hw = Vec::new();
    match &s.temp.value {
        Some(Some(c)) => hw.push(Line::from(vec![
            Span::styled("CPU  ", t.dim()),
            Span::styled(
                format!("{:.0}°C", c.c),
                t.s(if c.c >= v.cfg.thresholds.cpu_temp {
                    t.red
                } else {
                    t.fg
                }),
            ),
        ])),
        Some(None) => hw.push(Line::styled("CPU  no temperature sensor", t.dim())),
        None => {}
    }
    if let Some(Some(g)) = &s.gpu.value {
        hw.push(Line::from(vec![
            Span::styled("GPU  ", t.dim()),
            Span::styled(
                format!(
                    "{} · {:.0}°C · {:.0}% · VRAM {}/{} GiB",
                    g.name,
                    g.temp,
                    g.util,
                    g.vram_used_mib / 1024,
                    g.vram_total_mib / 1024
                ),
                t.s(if g.temp >= v.cfg.thresholds.gpu_temp {
                    t.red
                } else {
                    t.fg
                }),
            ),
        ]));
    }
    f.render_widget(Paragraph::new(hw), r);

    let [disk_a, status_a] = halves(row3);
    let b = panel(t, "Disks", "");
    let r = inner(&b, disk_a);
    f.render_widget(b, disk_a);
    let mut lines = Vec::new();
    match &s.disks.value {
        Some(mounts) => {
            let w = r.width.saturating_sub(30).clamp(6, 30);
            for m in mounts {
                let pct = m.pct();
                let rule = v.cfg.disks.iter().find(|d| d.mount == m.target);
                let c = match rule {
                    Some(d) if pct >= d.crit as f64 => t.red,
                    Some(d) if pct >= d.warn as f64 => t.yellow,
                    _ => t.load(pct),
                };
                let mut sp = vec![Span::styled(
                    format!("{:<12} ", trunc(&m.target, 12)),
                    t.fg(),
                )];
                sp.extend(bar(t, pct, w, c));
                sp.push(Span::styled(
                    format!(" {pct:>3.0}% {}", fmt::bytes_short(m.size)),
                    t.dim(),
                ));
                lines.push(Line::from(sp));
            }
            for d in &v.cfg.disks {
                if !mounts.iter().any(|m| m.target == d.mount) {
                    lines.push(Line::styled(
                        format!("{:<12} not mounted", trunc(&d.mount, 12)),
                        t.s(t.red),
                    ));
                }
            }
        }
        None => lines.push(waiting(v, &s.disks, "disks")),
    }
    if let Some(sm) = &s.smart.value {
        let mut sp = vec![Span::styled("SMART  ", t.dim())];
        for res in sm {
            match res {
                Ok(d) => {
                    let bad =
                        d.health == SmartHealth::Failed || d.bad_sectors > 0 || d.uncorrectable > 0;
                    let c = if bad {
                        t.red
                    } else if d.health == SmartHealth::Passed {
                        t.green
                    } else {
                        t.dim
                    };
                    let temp = d.temp_c.map_or(String::new(), |c| format!(" {c}°C"));
                    sp.push(Span::styled(
                        format!(
                            "{} {}{temp}   ",
                            d.dev.trim_start_matches("/dev/"),
                            if bad {
                                "damaged"
                            } else {
                                smart_word(&d.health)
                            }
                        ),
                        t.s(c),
                    ));
                }
                Err(e) => sp.push(Span::styled(format!("{e}   "), t.dim())),
            }
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(sp));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), r);

    let b = panel(t, "Status", "");
    let r = inner(&b, status_a);
    f.render_widget(b, status_a);
    let rows: Vec<Line> = status_rows(v)
        .into_iter()
        .enumerate()
        .map(|(i, row)| {
            let style = if i == v.cur {
                ratatui::style::Style::new().bg(t.sel_bg)
            } else {
                ratatui::style::Style::new()
            };
            Line::from(vec![
                Span::styled(format!("{} ", row.icon), t.s(row.color)),
                Span::styled(trunc(&row.text, r.width.saturating_sub(4) as usize), t.fg()),
            ])
            .style(style)
        })
        .collect();
    f.render_widget(Paragraph::new(rows), r);
}

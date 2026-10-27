//! Dashboard: CPU (total, history graph, per-core grid, temps), memory + GPU, disks with
//! breakdown, network sparklines, and the status panel. Layout follows the mockup grid.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::{Hints, View};
use crate::collectors::system::SystemSnap;
use crate::fmt;
use crate::tui::ScreenId;
use crate::tui::app::Effect;
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::widgets::{bar, graph, inner, panel, trunc};

#[derive(Default)]
pub struct Dashboard {
    /// Selected Status row (j/k); Enter opens the tab behind it.
    sel: Option<usize>,
    /// Tab behind each Status row, from the last render, and the Maintenance
    /// recommendation to select there (its key prefix).
    targets: Vec<(ScreenId, Option<&'static str>)>,
}

pub fn hints() -> Hints {
    vec![
        ("1-7 0", "screens"),
        ("c", "check updates"),
        ("r", "measure disks"),
        ("j/k Enter", "open a status row"),
    ]
}

impl Dashboard {
    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        match a {
            Action::Check => vec![
                Effect::Fetch(Fetch::OstreeCheck),
                Effect::Fetch(Fetch::FlatpakUpdates),
                Effect::Fetch(Fetch::ToolboxUpdates),
                Effect::Toast("checking rpm-ostree, flatpak and toolbox updates…".into()),
            ],
            Action::Refresh => {
                let mut e = vec![Effect::Fetch(Fetch::Disks), Effect::Fetch(Fetch::Units)];
                if !v.d.loading(Fetch::Breakdown) {
                    e.push(Effect::Fetch(Fetch::Breakdown));
                    e.push(Effect::Toast(
                        "measuring containers / flatpak / ~/.cache / ostree…".into(),
                    ));
                }
                e
            }
            Action::Down | Action::Up if !self.targets.is_empty() => {
                let n = self.targets.len();
                self.sel = Some(match (self.sel, a) {
                    (None, Action::Down) => 0,
                    (None, _) => n - 1,
                    (Some(i), Action::Down) => (i + 1).min(n - 1),
                    (Some(i), _) => i.saturating_sub(1),
                });
                Vec::new()
            }
            Action::Esc => {
                self.sel = None;
                Vec::new()
            }
            Action::Enter => match self.sel.and_then(|i| self.targets.get(i)) {
                Some((_, Some(pick))) => vec![Effect::MaintFind((*pick).into())],
                Some((id, None)) => vec![Effect::Goto(*id)],
                None => vec![Effect::Toast(
                    "j/k selects a Status row; Enter opens it".into(),
                )],
            },
            _ => Vec::new(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let wide = area.width >= 110;
        let s = v.d.sys.clone().unwrap_or_default();
        if wide {
            let cpu_h = cpu_height(&s, area.width * 2 / 3, area.height);
            let [r1, _, r2] = Layout::vertical([
                Constraint::Length(cpu_h),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .areas(area);
            let [cpu, mem] = Layout::horizontal([Constraint::Ratio(2, 3), Constraint::Ratio(1, 3)])
                .spacing(2)
                .areas(r1);
            let [disks, net, status] = Layout::horizontal([Constraint::Ratio(1, 3); 3])
                .spacing(2)
                .areas(r2);
            draw_cpu(f, cpu, v, &s);
            draw_mem(f, mem, v, &s);
            draw_disks(f, disks, v);
            draw_net(f, net, v);
            self.targets = draw_status(f, status, v, self.sel);
        } else {
            // Short terminals: compact CPU (graph + heat strip) so the other panels get rows.
            let cpu_h = if area.height < 30 {
                8
            } else {
                cpu_height(&s, area.width, area.height / 2)
            };
            let [r1, r2, r3] = Layout::vertical([
                Constraint::Length(cpu_h),
                Constraint::Fill(1),
                Constraint::Fill(1),
            ])
            .areas(area);
            let [mem, status] = Layout::horizontal([Constraint::Ratio(1, 2); 2])
                .spacing(1)
                .areas(r2);
            let [disks, net] = Layout::horizontal([Constraint::Ratio(1, 2); 2])
                .spacing(1)
                .areas(r3);
            draw_cpu(f, r1, v, &s);
            draw_mem(f, mem, v, &s);
            self.targets = draw_status(f, status, v, self.sel);
            draw_disks(f, disks, v);
            draw_net(f, net, v);
        }
    }
}

/// Core grid columns: as many ~18-cell columns as fit, at least enough to stay ≤ 8 rows.
fn core_cols(threads: usize, inner_w: u16) -> usize {
    let fit = (inner_w as usize / 18).clamp(1, 8);
    // Fewest columns that keep the grid ≤ 8 rows; at least 2 like the mockup's 8-core layout.
    threads.div_ceil(8).max(2).min(fit)
}

fn cpu_height(s: &SystemSnap, width: u16, max_h: u16) -> u16 {
    let threads = s.per_core.len().max(8);
    let rows = threads.div_ceil(core_cols(threads, width.saturating_sub(4))) as u16;
    // borders 2 + total 1 + gap + graph 4 + gap + cores + gap + temps 1
    (2 + 1 + 1 + 4 + 1 + rows + 1 + 1).min(max_h.max(10))
}

fn draw_cpu(f: &mut Frame, area: Rect, v: &View, s: &SystemSnap) {
    let t = v.t;
    let detail = if s.cpu_model.is_empty() {
        String::new()
    } else {
        match s.cores {
            Some(c) => format!("{} · {}c/{}t", s.cpu_model, c, s.threads),
            None => format!("{} · {}t", s.cpu_model, s.threads),
        }
    };
    let block = panel(t, "CPU", detail);
    let r = inner(&block, area);
    f.render_widget(block, area);
    if r.height < 3 {
        return;
    }
    // total line
    let label_w = 7u16;
    let tail = format!(
        " {:>3}%   load {:.2} {:.2} {:.2}",
        s.cpu_total.round(),
        s.load[0],
        s.load[1],
        s.load[2]
    );
    let bw = r.width.saturating_sub(label_w + tail.len() as u16).max(4);
    let mut spans = vec![Span::styled(format!("{:<7}", "total"), t.dim())];
    spans.extend(bar(t, s.cpu_total as f64, bw, t.cyan));
    spans.push(Span::styled(tail, t.fg()));
    f.render_widget(Paragraph::new(Line::from(spans)), Rect { height: 1, ..r });

    let threads = s.per_core.len();
    let cols = core_cols(threads.max(1), r.width);
    let core_rows = threads.div_ceil(cols) as u16;
    // Remaining height after total(1)+gap(1) and gap+temps(2) is split graph vs cores.
    let avail = r.height.saturating_sub(4);
    // Not enough room for the grid: collapse cores into a one-line heat strip.
    let strip = avail < core_rows + 2;
    let core_rows = if strip { 1 } else { core_rows };
    let graph_h = avail.saturating_sub(core_rows + 1).clamp(1, 4);
    let g = Rect {
        y: r.y + 2,
        height: graph_h,
        ..r
    };
    graph(f.buffer_mut(), g, &v.d.cpu_hist.vec(), 100.0, t.cyan);

    let cores_y = g.bottom() + 1;
    // Rows between the graph and the temps line (which sits on the last row).
    let cores_h = core_rows.min(r.bottom().saturating_sub(1).saturating_sub(cores_y));
    if strip && cores_h > 0 {
        let mut spans = vec![Span::styled("cores  ", t.dim())];
        for pct in s.per_core.iter().take(r.width.saturating_sub(7) as usize) {
            let lv = ((*pct as f64 / 100.0) * 7.0).round().clamp(0.0, 7.0) as usize;
            spans.push(Span::styled(
                ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'][lv].to_string(),
                t.s(t.load(*pct as f64)),
            ));
        }
        f.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect {
                y: cores_y,
                height: 1,
                ..r
            },
        );
    } else if cores_h > 0 && threads > 0 {
        let col_w = r.width / cols as u16;
        for (i, pct) in s.per_core.iter().enumerate() {
            let (col, row) = (i / threads.div_ceil(cols), i % threads.div_ceil(cols));
            if row as u16 >= cores_h {
                continue;
            }
            let x = r.x + col as u16 * col_w;
            let name = format!("c{i:<3}");
            let pct_s = format!("{:>4}%", pct.round());
            let bw = col_w
                .saturating_sub(name.len() as u16 + pct_s.len() as u16 + 2)
                .max(2);
            let mut spans = vec![Span::styled(name, t.dim())];
            spans.extend(bar(t, *pct as f64, bw, t.load(*pct as f64)));
            spans.push(Span::styled(pct_s, t.fg()));
            f.render_widget(
                Paragraph::new(Line::from(spans)),
                Rect {
                    x,
                    y: cores_y + row as u16,
                    width: col_w.saturating_sub(1),
                    height: 1,
                },
            );
        }
    }
    // temps
    let deg = |v: Option<f32>| v.map_or("—".to_string(), |c| format!("{c:.0}°C"));
    let gpu_t = v.d.gpu.get().and_then(|g| g.as_ref()).map(|g| g.temp);
    let nvme = s
        .temps
        .nvme
        .iter()
        .copied()
        .fold(None, |m: Option<f32>, x| Some(m.map_or(x, |m| m.max(x))));
    let line = Line::from(vec![
        Span::styled("temp   cpu ", t.dim()),
        Span::styled(deg(s.temps.cpu), t.fg()),
        Span::styled("   gpu ", t.dim()),
        Span::styled(deg(gpu_t), t.fg()),
        Span::styled("   nvme ", t.dim()),
        Span::styled(deg(nvme), t.fg()),
    ]);
    f.render_widget(
        Paragraph::new(line),
        Rect {
            y: r.bottom() - 1,
            height: 1,
            ..r
        },
    );
}

fn draw_mem(f: &mut Frame, area: Rect, v: &View, s: &SystemSnap) {
    let t = v.t;
    let block = panel(t, "Memory", "");
    let r = inner(&block, area);
    f.render_widget(block, area);
    let m = &s.mem;
    let mem_pct = if m.total > 0 {
        m.used as f64 / m.total as f64 * 100.0
    } else {
        0.0
    };
    let swap_pct = if s.swap.total > 0 {
        s.swap.used as f64 / s.swap.total as f64 * 100.0
    } else {
        0.0
    };
    let bw = r.width.saturating_sub(6);
    let mut lines = vec![
        Line::from(vec![
            Span::styled("mem   ", t.dim()),
            Span::styled(format!("{:.1}", fmt::gib(m.used)), t.fg()),
            Span::styled(format!(" / {:.1} GiB", fmt::gib(m.total)), t.dim()),
        ]),
        Line::from(
            [
                bar(t, mem_pct, bw, t.mag),
                vec![Span::styled(format!(" {mem_pct:>3.0}%"), t.fg())],
            ]
            .concat(),
        ),
        Line::default(),
        Line::from(vec![
            Span::styled("swap  ", t.dim()),
            Span::styled(format!("{:.1}", fmt::gib(s.swap.used)), t.fg()),
            Span::styled(
                format!(" / {:.1} GiB {}", fmt::gib(s.swap.total), s.swap.kind),
                t.dim(),
            ),
        ]),
        Line::from(
            [
                bar(t, swap_pct, bw, t.mag),
                vec![Span::styled(format!(" {swap_pct:>3.0}%"), t.fg())],
            ]
            .concat(),
        ),
        Line::default(),
        Line::styled(
            format!(
                "cache {:.1} GiB · avail {:.1} GiB",
                fmt::gib(m.cache),
                fmt::gib(m.avail)
            ),
            t.dim(),
        ),
    ];
    // GPU section hides when nvidia-smi is missing or fails (spec §6).
    if let Some(Some(g)) = v.d.gpu.get() {
        lines.push(Line::styled("─".repeat(r.width as usize), t.s(t.rule)));
        lines.push(Line::from(vec![
            Span::styled("GPU  ", t.dim()),
            Span::styled(g.name.clone(), t.fg()),
            Span::styled(format!(" · nvidia {}", g.driver), t.dim()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("util ", t.dim()),
            Span::styled(format!("{:.0}%", g.util), t.fg()),
            Span::styled("  vram ", t.dim()),
            Span::styled(format!("{:.1}", g.vram_used_mib as f64 / 1024.0), t.fg()),
            Span::styled(
                format!("/{:.0} GiB", g.vram_total_mib as f64 / 1024.0),
                t.dim(),
            ),
            Span::styled("  temp ", t.dim()),
            Span::styled(format!("{:.0}°C", g.temp), t.fg()),
        ]));
    }
    f.render_widget(Paragraph::new(lines), r);
}

fn draw_disks(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let block = panel(t, "Disks", "");
    let r = inner(&block, area);
    f.render_widget(block, area);
    let mut lines = Vec::new();
    match v.d.disks.get() {
        Some(mounts) => {
            // Two lines per mount; leave 2 lines for the breakdown.
            let fit = if r.height >= 6 {
                (r.height - 2) / 2
            } else {
                r.height / 2
            } as usize;
            for m in mounts.iter().take(fit) {
                let right = format!(
                    "{} / {}",
                    fmt::bytes_short(m.used),
                    fmt::bytes_short(m.size)
                );
                let left = trunc(
                    &format!("{}  {}", m.target, m.fstype),
                    (r.width as usize).saturating_sub(right.len() + 1),
                );
                let pad = (r.width as usize).saturating_sub(left.chars().count() + right.len());
                let name_style = if m.removable { t.dim() } else { t.fg() };
                lines.push(Line::from(vec![
                    Span::styled(left, name_style),
                    Span::raw(" ".repeat(pad)),
                    Span::styled(right, t.dim()),
                ]));
                let color = if m.pct() > 90.0 {
                    t.red
                } else if m.pct() > 80.0 {
                    t.yellow
                } else {
                    t.blue
                };
                lines.push(Line::from(
                    [
                        bar(t, m.pct(), r.width.saturating_sub(5), color),
                        vec![Span::styled(format!(" {:>3.0}%", m.pct()), t.fg())],
                    ]
                    .concat(),
                ));
            }
        }
        None => lines.push(Line::styled(
            v.d.disks.status(v.d.loading(Fetch::Disks)),
            t.dim(),
        )),
    }
    let used = lines.len() as u16;
    f.render_widget(Paragraph::new(lines), r);

    let b_y = (r.y + used)
        .max(r.bottom().saturating_sub(2))
        .min(r.bottom());
    let b_area = Rect {
        y: b_y,
        height: r.bottom() - b_y,
        ..r
    };
    let lines = match v.d.breakdown.get() {
        Some(c) => {
            let b = &c.data;
            let warn = b.cache > v.cfg.audit.cache_warn_mb * 1024 * 1024;
            let num = |n: u64| Span::styled(format!("≈{}", fmt::bytes_short(n)), t.fg());
            vec![
                Line::from(vec![
                    Span::styled("containers ", t.dim()),
                    num(b.containers),
                    Span::styled("  flatpak ", t.dim()),
                    num(b.flatpak),
                ]),
                Line::from(vec![
                    Span::styled("~/.cache   ", t.dim()),
                    Span::styled(
                        format!(
                            "≈{}{}",
                            fmt::bytes_short(b.cache),
                            if warn { " ▲" } else { "" }
                        ),
                        t.s(if warn { t.yellow } else { t.fg }),
                    ),
                    Span::styled("  ostree ", t.dim()),
                    num(b.ostree),
                    Span::styled(
                        format!("  {}", fmt::ago(c.age_secs(jiff::Timestamp::now()))),
                        t.dim(),
                    ),
                ]),
            ]
        }
        None if v.d.loading(Fetch::Breakdown) => vec![Line::styled("measuring…", t.dim())],
        None => vec![Line::styled("breakdown not measured · press r", t.dim())],
    };
    f.render_widget(Paragraph::new(lines), b_area);
}

fn draw_net(f: &mut Frame, area: Rect, v: &View) {
    let t = v.t;
    let iface =
        v.d.sys
            .as_ref()
            .map(|s| s.net.iface.clone())
            .unwrap_or_default();
    let block = panel(t, "Network", iface);
    let r = inner(&block, area);
    f.render_widget(block, area);
    let (rx, tx) =
        v.d.sys
            .as_ref()
            .map_or((0.0, 0.0), |s| (s.net.rx_bps, s.net.tx_bps));
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("↓ {}", fmt::rate(rx)), t.s(t.green)),
            Span::raw("   "),
            Span::styled(format!("↑ {}", fmt::rate(tx)), t.s(t.mag)),
        ])),
        Rect { height: 1, ..r },
    );
    // Graphs scale to the visible window's peak so quiet links still show shape.
    let rows_left = r.height.saturating_sub(4);
    let (rx_h, tx_h) = match rows_left {
        0 => (0, 0),
        1..=2 => (1, 1.min(rows_left - 1)),
        3..=4 => (2, rows_left - 2),
        _ => (3, 2),
    };
    let w = r.width as usize;
    let tail = |h: &crate::tui::data::Ring| {
        let v = h.vec();
        let n = v.len().saturating_sub(w);
        v[n..].to_vec()
    };
    let rxs = tail(&v.d.rx_hist);
    let txs = tail(&v.d.tx_hist);
    let peak = |xs: &[f64]| xs.iter().copied().fold(1024.0, f64::max);
    graph(
        f.buffer_mut(),
        Rect {
            y: r.y + 2,
            height: rx_h,
            ..r
        },
        &rxs,
        peak(&rxs),
        t.green,
    );
    graph(
        f.buffer_mut(),
        Rect {
            y: r.y + 2 + rx_h,
            height: tx_h,
            ..r
        },
        &txs,
        peak(&txs),
        t.mag,
    );
    let c = v.d.counts.unwrap_or_default();
    let foot = vec![
        Line::from(vec![
            Span::styled("listening ", t.dim()),
            Span::styled(c.listening.to_string(), t.fg()),
            Span::styled(" · established ", t.dim()),
            Span::styled(c.established.to_string(), t.fg()),
        ]),
        match &v.d.recorder {
            Some(l) => Line::from(vec![
                Span::styled("recorder ", t.dim()),
                Span::styled("●", t.s(t.green)),
                Span::styled(format!(" every {}s · H for history", l.interval_s), t.dim()),
            ]),
            None => Line::styled("recorder off · history needs `sentry record`", t.dim()),
        },
    ];
    f.render_widget(
        Paragraph::new(foot),
        Rect {
            y: r.bottom().saturating_sub(2),
            height: 2.min(r.height),
            ..r
        },
    );
}

/// Draws the Status panel; returns the tab each row links to.
fn draw_status(
    f: &mut Frame,
    area: Rect,
    v: &View,
    sel: Option<usize>,
) -> Vec<(ScreenId, Option<&'static str>)> {
    let t = v.t;
    let block = panel(t, "Status", "");
    let r = inner(&block, area);
    f.render_widget(block, area);
    let now = jiff::Timestamp::now();
    let mut rows: Vec<(&str, String, ratatui::style::Color, String)> = Vec::new();

    // updates: ostree from rpm-ostree's cached-update, flatpak from our cache
    let os = v.d.ostree.get().map(|o| {
        o.update
            .as_ref()
            .map_or(0, |u| u.upgraded.len() + u.added.len())
    });
    let fp = v.d.fp_updates.get().map(|c| c.data.len());
    let tb =
        v.d.tbx_updates
            .get()
            .map(|c| crate::collectors::toolbox::total(&c.data));
    let checking = v.d.loading(Fetch::OstreeCheck)
        || v.d.loading(Fetch::FlatpakUpdates)
        || v.d.loading(Fetch::ToolboxUpdates);
    let age =
        v.d.ostree_checked
            .map(|ts| (now.as_second() - ts.as_second()).max(0));
    let stale = age.is_none_or(|a| a as u64 > v.cfg.cache.update_check_max_age.0.as_secs());
    let (os_l, fp_l, tb_l) = if r.width < 56 {
        ("os", "fp", "tb")
    } else {
        ("ostree", "flatpak", "tbx")
    };
    let n = |x: Option<usize>| x.map_or("?".into(), |n| n.to_string());
    let upd_text = format!("{} {os_l} · {} {fp_l} · {} {tb_l}", n(os), n(fp), n(tb));
    let any = os.unwrap_or(0) + fp.unwrap_or(0) + tb.unwrap_or(0) > 0;
    let note = match (checking, age) {
        (true, _) => "checking…".to_string(),
        (false, None) => "never · press c".into(),
        (false, Some(a)) if stale => format!("{} · stale, c", fmt::ago(a)),
        (false, Some(a)) => fmt::ago(a),
    };
    rows.push(("updates", upd_text, if any { t.yellow } else { t.fg }, note));
    if v.d
        .ostree
        .get()
        .and_then(|o| o.update.as_ref())
        .is_some_and(|u| u.kernel_changed)
    {
        rows.push(("", "kernel changes".into(), t.yellow, "kmod ritual".into()));
    }
    if let Some(s) =
        v.d.ostree
            .get()
            .and_then(|o| o.deployments.iter().find(|d| d.staged && !d.booted))
    {
        rows.push((
            "reboot",
            format!("into {}", s.version),
            t.yellow,
            "staged".into(),
        ));
    }

    match v.d.reports.get().and_then(|r| r.last()) {
        Some(last) => {
            let c = last.report.counts(&v.d.baseline);
            let color = if c.high > 0 {
                t.red
            } else if c.medium > 0 {
                t.yellow
            } else {
                t.fg
            };
            rows.push((
                "findings",
                format!("{} check · {} review · {} info", c.high, c.medium, c.low),
                color,
                fmt::ago(now.as_second() - last.report.taken_at.as_second()),
            ));
        }
        None => rows.push((
            "findings",
            "no audit yet".into(),
            t.dim,
            "c on Maintenance".into(),
        )),
    }
    match v.d.units.get() {
        Some(u) => {
            let n = u.failed.len();
            let note = u
                .failed
                .iter()
                .map(|f| f.unit.trim_end_matches(".service"))
                .collect::<Vec<_>>()
                .join(", ");
            rows.push((
                "failed units",
                n.to_string(),
                if n > 0 { t.yellow } else { t.fg },
                note,
            ));
        }
        None => rows.push((
            "failed units",
            v.d.units.status(v.d.loading(Fetch::Units)),
            t.dim,
            String::new(),
        )),
    }
    match v.d.job_runs.get() {
        Some(runs) => {
            let due = runs.due_jobs(v.cfg, now);
            let names: Vec<&str> = due.iter().map(|j| j.name()).collect();
            rows.push((
                "jobs due",
                due.len().to_string(),
                if due.is_empty() { t.fg } else { t.yellow },
                names.join(", "),
            ));
        }
        None => rows.push(("jobs due", "—".into(), t.dim, String::new())),
    }
    match v.wf.filter(|s| !s.done()) {
        Some(s) => rows.push((
            "workflow",
            format!(
                "{} {}/{}",
                s.wf.name,
                s.next.idx().map_or(s.wf.steps.len(), |i| i + 1),
                s.wf.steps.len()
            ),
            t.yellow,
            s.state_word().into(),
        )),
        None => rows.push(("workflow", "none".into(), t.dim, String::new())),
    }
    match &v.d.recorder {
        Some(l) => rows.push((
            "recorder",
            "running".into(),
            t.green,
            format!(
                "pid {} · since {}",
                l.pid,
                jiff::Timestamp::from_second(l.started)
                    .map(|ts| {
                        ts.to_zoned(jiff::tz::TimeZone::system())
                            .strftime("%a %H:%M")
                            .to_string()
                    })
                    .unwrap_or_default()
            ),
        )),
        None => rows.push(("recorder", "off".into(), t.dim, String::new())),
    }

    let mut targets = Vec::new();
    let mut last = (ScreenId::Maint, Some("updates"));
    let lines: Vec<Line> = rows
        .into_iter()
        .enumerate()
        .map(|(i, (k, val, c, note))| {
            last = match k {
                "updates" => (ScreenId::Maint, Some("updates")),
                "reboot" => (ScreenId::Maint, Some("reboot")),
                "findings" => (ScreenId::Maint, Some("finding:")),
                "failed units" => (ScreenId::Maint, Some("finding:unit-failed")),
                "jobs due" => (ScreenId::Maint, Some("job:")),
                "workflow" => (ScreenId::Upgrade, None),
                "recorder" => (ScreenId::Hist, None),
                _ => last, // continuation rows (kernel note) go where their parent goes
            };
            targets.push(last);
            let w = r.width as usize;
            let note = trunc(&note, w.saturating_sub(14 + val.chars().count() + 2));
            let line = Line::from(vec![
                Span::styled(format!("{k:<13} "), t.dim()),
                Span::styled(val, t.s(c)),
                Span::styled(format!("  {note}"), t.dim()),
            ]);
            if sel == Some(i) {
                line.style(ratatui::style::Style::new().bg(t.sel_bg))
            } else {
                line
            }
        })
        .collect();
    f.render_widget(Paragraph::new(lines), r);
    targets
}

/// `A` on the dashboard: the Status panel's facts, as one summary.
pub fn ask(v: &View) -> Result<crate::claude::Ask, String> {
    let d = v.d;
    let mut lines = vec![format!("Silverblue {} · kernel {}", d.os_version, d.kernel)];
    if let Some(o) = d.ostree.get() {
        match &o.update {
            Some(u) => lines.push(format!(
                "rpm-ostree update pending: {} packages{}",
                u.upgraded.len() + u.added.len(),
                if u.kernel_changed {
                    format!(
                        ", kernel changes to {}",
                        u.new_kernel.as_deref().unwrap_or("?")
                    )
                } else {
                    String::new()
                }
            )),
            None => lines.push("no rpm-ostree update known".into()),
        }
    }
    if let Some(c) = d.fp_updates.get() {
        lines.push(format!("{} Flatpak updates", c.data.len()));
    }
    if let Some(c) = d.tbx_updates.get() {
        lines.push(format!(
            "{} package updates inside toolboxes",
            crate::collectors::toolbox::total(&c.data)
        ));
    }
    if let Some(r) = d.reports.get().and_then(|r| r.last()) {
        let c = r.report.counts(&d.baseline);
        lines.push(format!(
            "last audit: {} to check, {} to review, {} info",
            c.high, c.medium, c.low
        ));
        for f in r.report.open(&d.baseline).take(6) {
            lines.push(format!("  - {}", f.message));
        }
    }
    if let Some(u) = d.units.get() {
        for f in &u.failed {
            lines.push(format!("failed unit: {} ({})", f.unit, f.scope));
        }
    }
    if let Some(rec) = d.job_runs.get() {
        let due: Vec<&str> = rec
            .due_jobs(v.cfg, jiff::Timestamp::now())
            .iter()
            .map(|j| j.name())
            .collect();
        lines.push(format!(
            "jobs due: {}",
            if due.is_empty() {
                "none".into()
            } else {
                due.join(", ")
            }
        ));
    }
    if let Some(s) = v.wf.filter(|s| !s.done()) {
        lines.push(format!(
            "workflow in progress: {} ({})",
            s.wf.name,
            s.state_word()
        ));
    }
    for m in d.disks.get().into_iter().flatten() {
        lines.push(format!(
            "disk {} {}: {} of {} used",
            m.target,
            m.fstype,
            fmt::bytes(m.used),
            fmt::bytes(m.size)
        ));
    }
    if let Some(s) = &d.sys {
        lines.push(format!(
            "cpu {:.0}% · load {:.2} · memory {} of {} · cpu temp {}",
            s.cpu_total,
            s.load[0],
            fmt::bytes(s.mem.used),
            fmt::bytes(s.mem.total),
            s.temps.cpu.map_or("?".into(), |t| format!("{t:.0}°C"))
        ));
    }
    Ok(crate::claude::Ask::new(
        "dashboard",
        format!(
            "sentry's dashboard status for my machine:\n{}",
            lines.join("\n")
        ),
        "Anything here I should act on, and in what order?",
    ))
}

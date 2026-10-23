//! History (`H`): the recorder's ring file as per-metric graphs over a 6h/24h/72h window.
//! `[`/`]` change the window, `←`/`→` scrub. Shown as a tab only once recorder data exists.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::{Hints, View};
use crate::fmt;
use crate::recorder::ring::{Header, Rec};
use crate::recorder::{self, Live};
use crate::tui::app::Effect;
use crate::tui::data::Fetch;
use crate::tui::keys::Action;
use crate::tui::widgets::{graph, inner, panel, placeholder};

/// What the History screen renders, read in the background.
#[derive(Debug, Clone, Default)]
pub struct HistData {
    pub header: Option<Header>,
    pub recs: Vec<Rec>,
    pub live: Option<Live>,
    pub alerts: Vec<(String, String)>,
    pub bytes: u64,
}

pub fn load() -> HistData {
    let p = recorder::ring::path();
    let (header, recs) = match recorder::ring::read_metrics(&p) {
        Some((h, r)) => (Some(h), r),
        None => (None, Vec::new()),
    };
    HistData {
        header,
        recs,
        live: recorder::live(),
        alerts: recorder::recent_alerts(3),
        bytes: std::fs::metadata(&p).map_or(0, |m| m.len()),
    }
}

const WINDOWS: [(i64, &str); 3] = [(6 * 3600, "6h"), (24 * 3600, "24h"), (72 * 3600, "72h")];

pub struct History {
    win: usize,
    /// Seconds back from the newest sample.
    offset: i64,
}

impl Default for History {
    fn default() -> Self {
        Self { win: 1, offset: 0 }
    }
}

pub fn on_enter(_v: &View) -> Vec<Effect> {
    vec![Effect::Fetch(Fetch::History)]
}

pub fn hints() -> Hints {
    vec![("[ ]", "window"), ("←→", "scrub"), ("r", "reload")]
}

/// Mean of each of `cols` equal time buckets in [start, end); NaN where there's no sample.
pub fn buckets(
    recs: &[Rec],
    start: i64,
    end: i64,
    cols: usize,
    f: impl Fn(&Rec) -> f32,
) -> Vec<f64> {
    let mut sum = vec![0.0f64; cols];
    let mut n = vec![0u32; cols];
    let span = (end - start).max(1) as f64;
    for r in recs.iter().filter(|r| r.ts >= start && r.ts < end) {
        let v = f(r);
        if v.is_nan() {
            continue;
        }
        let i = (((r.ts - start) as f64 / span) * cols as f64) as usize;
        let i = i.min(cols - 1);
        sum[i] += v as f64;
        n[i] += 1;
    }
    sum.iter()
        .zip(&n)
        .map(|(s, c)| if *c == 0 { f64::NAN } else { s / *c as f64 })
        .collect()
}

fn stats(v: &[f64]) -> (f64, f64) {
    let vals: Vec<f64> = v.iter().copied().filter(|x| !x.is_nan()).collect();
    if vals.is_empty() {
        return (f64::NAN, f64::NAN);
    }
    let avg = vals.iter().sum::<f64>() / vals.len() as f64;
    let max = vals.iter().copied().fold(f64::MIN, f64::max);
    (avg, max)
}

impl History {
    pub fn handle(&mut self, a: Action, v: &View) -> Vec<Effect> {
        let w = WINDOWS[self.win].0;
        let span =
            v.d.history
                .get()
                .and_then(|h| Some(h.recs.last()?.ts - h.recs.first()?.ts))
                .unwrap_or(0);
        match a {
            Action::Char('[') => self.win = self.win.saturating_sub(1),
            Action::Char(']') => self.win = (self.win + 1).min(WINDOWS.len() - 1),
            Action::Left => {
                self.offset = (self.offset + w / 4).min(span.saturating_sub(w / 4).max(0))
            }
            Action::Right => self.offset = (self.offset - w / 4).max(0),
            Action::Refresh => return vec![Effect::Fetch(Fetch::History)],
            _ => {}
        }
        Vec::new()
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, v: &View) {
        let t = v.t;
        let Some(h) = v.d.history.get().filter(|h| !h.recs.is_empty()) else {
            let loading = v.d.loading(Fetch::History);
            placeholder(
                f,
                area,
                t,
                &[
                    (
                        if loading {
                            "reading metrics…"
                        } else {
                            "No recorder data."
                        },
                        t.fg(),
                    ),
                    ("", t.dim()),
                    (
                        "Run `sentry record --interval 10s` in a spare terminal. It exits on Ctrl-C.",
                        t.dim(),
                    ),
                ],
            );
            return;
        };
        let (win, label) = WINDOWS[self.win];
        let newest = h.recs.last().map_or(0, |r| r.ts);
        let end = newest - self.offset + 1;
        let start = end - win;
        let block = panel(
            t,
            "History",
            format!(
                "last {label}{} · every {}s · metrics/ring.bin {}",
                if self.offset > 0 {
                    format!(" until {}", clock(end, win))
                } else {
                    String::new()
                },
                h.header.map_or(0, |x| x.interval_s),
                fmt::bytes(h.bytes)
            ),
        );
        let r = inner(&block, area);
        f.render_widget(block, area);
        let has_gpu = h.recs.iter().any(|x| !x.gpu.is_nan());
        type Metric<'a> = (
            &'a str,
            Color,
            u16,
            Box<dyn Fn(&Rec) -> f32>,
            Box<dyn Fn(&[f64]) -> (f64, String)>,
        );
        let mut metrics: Vec<Metric> = vec![
            (
                "cpu %",
                t.cyan,
                3,
                Box::new(|r: &Rec| r.cpu),
                Box::new(|v: &[f64]| {
                    let (a, m) = stats(v);
                    (100.0, format!("avg {a:.0} · max {m:.0}"))
                }),
            ),
            (
                "mem GiB",
                t.mag,
                2,
                Box::new(|r: &Rec| r.mem_gib),
                Box::new(|v: &[f64]| {
                    let (a, m) = stats(v);
                    ((m * 1.15).max(1.0), format!("avg {a:.1} · max {m:.1}"))
                }),
            ),
            (
                "net rx",
                t.green,
                3,
                Box::new(|r: &Rec| r.rx),
                Box::new(|v: &[f64]| {
                    let (_, m) = stats(v);
                    (m.max(1.0), format!("peak {}", fmt::rate(m)))
                }),
            ),
            (
                "cpu °C",
                t.yellow,
                2,
                Box::new(|r: &Rec| r.cpu_temp),
                Box::new(|v: &[f64]| {
                    let (_, m) = stats(v);
                    (100.0, format!("max {m:.0}°C"))
                }),
            ),
        ];
        if has_gpu {
            metrics.push((
                "gpu %",
                t.blue,
                2,
                Box::new(|r: &Rec| r.gpu),
                Box::new(|v: &[f64]| {
                    let (a, m) = stats(v);
                    (100.0, format!("avg {a:.0} · max {m:.0}"))
                }),
            ));
        }
        metrics.push((
            "disk /",
            t.blue,
            1,
            Box::new(|r: &Rec| r.disk_pct),
            Box::new(|v: &[f64]| {
                let last = v
                    .iter()
                    .rev()
                    .find(|x| !x.is_nan())
                    .copied()
                    .unwrap_or(f64::NAN);
                (100.0, format!("{last:.0}% used"))
            }),
        ));

        let name_w = 12u16;
        let stat_w = 20u16;
        let gw = r.width.saturating_sub(name_w + stat_w + 2);
        let mut y = r.y;
        for (name, color, rows, get, stat) in &metrics {
            if y + rows > r.bottom().saturating_sub(4) {
                break;
            }
            let data = buckets(&h.recs, start, end, gw.max(1) as usize, get);
            // Stats from the raw samples: bucket means would flatten short spikes.
            let raw: Vec<f64> = h
                .recs
                .iter()
                .filter(|r| r.ts >= start && r.ts < end)
                .map(|r| get(r) as f64)
                .collect();
            let (max, s) = stat(&raw);
            f.render_widget(
                Paragraph::new(Span::styled(*name, t.dim())),
                Rect::new(r.x, y + rows - 1, name_w, 1),
            );
            graph(
                f.buffer_mut(),
                Rect::new(r.x + name_w + 1, y, gw, *rows),
                &data,
                max,
                *color,
            );
            f.render_widget(
                Paragraph::new(Span::styled(s, t.dim())),
                Rect::new(r.x + name_w + gw + 2, y + rows - 1, stat_w, 1),
            );
            y += rows + 1;
        }
        // Time axis: five labels across the graph width.
        let labels: Vec<String> = (0..5).map(|i| clock(start + win * i / 4, win)).collect();
        let mut axis = String::new();
        let slot = gw as usize / 4;
        for (i, l) in labels.iter().enumerate() {
            let pos = (i * slot).min((gw as usize).saturating_sub(l.chars().count()));
            while axis.chars().count() < pos {
                axis.push(' ');
            }
            if i == 4 && self.offset == 0 {
                axis.push_str("now");
            } else {
                axis.push_str(l);
            }
        }
        f.render_widget(
            Paragraph::new(Span::styled(axis, t.dim())),
            Rect::new(r.x + name_w + 1, y, gw, 1),
        );

        let rec = match &h.live {
            Some(l) => Span::styled(
                format!("● recorder running (pid {}, {}s)", l.pid, l.interval_s),
                t.s(t.green),
            ),
            None => Span::styled("○ recorder off · `sentry record` to resume", t.dim()),
        };
        let mut foot = vec![Line::from(vec![
            Span::styled(
                format!("alerts  {}   ", v.cfg.recorder.alerts.join(" · ")),
                t.dim(),
            ),
            rec,
        ])];
        for (ts, msg) in h.alerts.iter().rev() {
            let when = ts
                .parse::<jiff::Timestamp>()
                .map(|t| {
                    t.to_zoned(jiff::tz::TimeZone::system())
                        .strftime("%a %H:%M")
                        .to_string()
                })
                .unwrap_or_default();
            foot.push(Line::from(vec![
                Span::styled(format!("  {when}  "), t.dim()),
                Span::styled(msg.clone(), t.s(t.yellow)),
            ]));
        }
        let fy = r.bottom().saturating_sub(foot.len() as u16);
        f.render_widget(
            Paragraph::new(foot),
            Rect::new(r.x, fy, r.width, r.bottom() - fy),
        );
    }
}

/// Axis label: `HH:MM` for short windows, `Tue 14h` for 72 h.
fn clock(ts: i64, win: i64) -> String {
    let Ok(t) = jiff::Timestamp::from_second(ts) else {
        return String::new();
    };
    let z = t.to_zoned(jiff::tz::TimeZone::system());
    if win > 24 * 3600 {
        z.strftime("%a %Hh").to_string()
    } else {
        z.strftime("%H:%M").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_means_and_gaps() {
        let recs: Vec<Rec> = [(0, 10.0), (5, 20.0), (25, 40.0)]
            .iter()
            .map(|(ts, cpu)| Rec {
                ts: *ts,
                cpu: *cpu,
                ..Default::default()
            })
            .collect();
        let b = buckets(&recs, 0, 30, 3, |r| r.cpu);
        assert_eq!(b[0], 15.0);
        assert!(b[1].is_nan(), "no samples in 10..20");
        assert_eq!(b[2], 40.0);
    }
}

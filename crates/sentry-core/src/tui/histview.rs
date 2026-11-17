//! The History screen, in both programs: a recorder's ring file as per-metric graphs over a
//! 6h/24h/72h window. `[`/`]` change the window, `←`/`→` scrub. Each program says how to get
//! data when there is none, and what goes in the footer.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::keys::Action;
use super::theme::Theme;
use super::widgets::{graph, inner, panel, placeholder};
use crate::fmt;
use crate::recorder::ring::{Header, Rec};
use crate::recorder::{self, Live};

/// What the History screen renders, read in the background.
#[derive(Debug, Clone, Default)]
pub struct HistData {
    pub header: Option<Header>,
    pub recs: Vec<Rec>,
    pub live: Option<Live>,
    pub alerts: Vec<(String, String)>,
    pub bytes: u64,
}

/// Read a ring from disk: this machine's (`""`) or a server's.
pub fn load(server: &str) -> HistData {
    let p = recorder::ring::path(server);
    let (header, recs) = match recorder::ring::read_metrics(&p) {
        Some((h, r)) => (Some(h), r),
        None => (None, Vec::new()),
    };
    HistData {
        header,
        recs,
        live: recorder::live(server),
        alerts: recorder::recent_alerts(server, 3),
        bytes: std::fs::metadata(&p).map_or(0, |m| m.len()),
    }
}

const WINDOWS: [(i64, &str); 3] = [(6 * 3600, "6h"), (24 * 3600, "24h"), (72 * 3600, "72h")];

/// Which window is shown, and how far back it ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistState {
    pub win: usize,
    /// Seconds back from the newest sample.
    pub offset: i64,
}

impl Default for HistState {
    fn default() -> Self {
        Self { win: 1, offset: 0 }
    }
}

impl HistState {
    /// `[` `]` change the window, `←` `→` scrub by a quarter of it. True: the key was one of
    /// these.
    pub fn key(&mut self, a: Action, d: Option<&HistData>) -> bool {
        let w = WINDOWS[self.win].0;
        let span = d
            .and_then(|h| Some(h.recs.last()?.ts - h.recs.first()?.ts))
            .unwrap_or(0);
        match a {
            Action::Char('[') => self.win = self.win.saturating_sub(1),
            Action::Char(']') => self.win = (self.win + 1).min(WINDOWS.len() - 1),
            Action::Left => {
                self.offset = (self.offset + w / 4).min(span.saturating_sub(w / 4).max(0))
            }
            Action::Right => self.offset = (self.offset - w / 4).max(0),
            _ => return false,
        }
        true
    }

    /// The window: (its label, start, end) in seconds, ending at the newest sample less the
    /// offset.
    fn window(&self, d: &HistData) -> (&'static str, i64, i64) {
        let (win, label) = WINDOWS[self.win];
        let newest = d.recs.last().map_or(0, |r| r.ts);
        let end = newest - self.offset + 1;
        (label, end - win, end)
    }
}

pub fn hints() -> Vec<(&'static str, &'static str)> {
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

/// The footer's word on the recorder: running (green), or `off` (what to say when it isn't).
pub fn recorder_span(t: &Theme, live: Option<&Live>, off: &str) -> Span<'static> {
    match live {
        Some(l) => Span::styled(
            format!("● recorder running (pid {}, {}s)", l.pid, l.interval_s),
            t.s(t.green),
        ),
        None => Span::styled(off.to_string(), t.dim()),
    }
}

/// The alert lines of a footer, newest first: when, and what.
pub fn alert_lines(t: &Theme, d: &HistData) -> Vec<Line<'static>> {
    d.alerts
        .iter()
        .rev()
        .map(|(ts, msg)| {
            let when = ts
                .parse::<jiff::Timestamp>()
                .map(|t| {
                    t.to_zoned(jiff::tz::TimeZone::system())
                        .strftime("%a %H:%M")
                        .to_string()
                })
                .unwrap_or_default();
            Line::from(vec![
                Span::styled(format!("  {when}  "), t.dim()),
                Span::styled(msg.clone(), t.s(t.yellow)),
            ])
        })
        .collect()
}

/// The screen. With no samples: "reading metrics…" while `loading`, else "No recorder data.",
/// then the `empty` lines (how to get some). `footer` goes at the bottom of the panel.
#[allow(clippy::too_many_arguments)]
pub fn draw(
    f: &mut Frame,
    area: Rect,
    t: &Theme,
    d: Option<&HistData>,
    s: &HistState,
    loading: bool,
    empty: &[&str],
    footer: Vec<Line<'static>>,
) {
    let Some(h) = d.filter(|h| !h.recs.is_empty()) else {
        let mut lines = vec![(
            if loading {
                "reading metrics…"
            } else {
                "No recorder data."
            },
            t.fg(),
        )];
        lines.extend(empty.iter().map(|l| (*l, t.dim())));
        placeholder(f, area, t, &lines);
        return;
    };
    let win = WINDOWS[s.win].0;
    let (label, start, end) = s.window(h);
    let block = panel(
        t,
        "History",
        format!(
            "last {label}{} · every {}s · metrics/ring.bin {}",
            if s.offset > 0 {
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
        let (max, st) = stat(&raw);
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
            Paragraph::new(Span::styled(st, t.dim())),
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
        if i == 4 && s.offset == 0 {
            axis.push_str("now");
        } else {
            axis.push_str(l);
        }
    }
    f.render_widget(
        Paragraph::new(Span::styled(axis, t.dim())),
        Rect::new(r.x + name_w + 1, y, gw, 1),
    );

    let fy = r.bottom().saturating_sub(footer.len() as u16);
    f.render_widget(
        Paragraph::new(footer),
        Rect::new(r.x, fy, r.width, r.bottom() - fy),
    );
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

/// What Claude is told about the window shown: (its label, a line for the window and one per
/// metric). None: no samples.
pub fn ask_lines(d: &HistData, s: &HistState) -> Option<(String, Vec<String>)> {
    if d.recs.is_empty() {
        return None;
    }
    let (label, start, end) = s.window(d);
    let span: Vec<&Rec> = d
        .recs
        .iter()
        .filter(|r| r.ts >= start && r.ts < end)
        .collect();
    let stat = |name: &str, f: &dyn Fn(&Rec) -> f32| {
        let vals: Vec<f32> = span.iter().map(|r| f(r)).filter(|x| !x.is_nan()).collect();
        if vals.is_empty() {
            return format!("{name}: no data");
        }
        let avg = vals.iter().sum::<f32>() / vals.len() as f32;
        let max = vals.iter().copied().fold(f32::MIN, f32::max);
        let min = vals.iter().copied().fold(f32::MAX, f32::min);
        format!("{name}: avg {avg:.1} · min {min:.1} · max {max:.1}")
    };
    Some((
        label.to_string(),
        vec![
            format!("window: last {label}, {} samples", span.len()),
            stat("cpu %", &|r| r.cpu),
            stat("memory GiB", &|r| r.mem_gib),
            stat("swap GiB", &|r| r.swap_gib),
            stat("net rx B/s", &|r| r.rx),
            stat("net tx B/s", &|r| r.tx),
            stat("load1", &|r| r.load1),
            stat("cpu °C", &|r| r.cpu_temp),
            stat("gpu %", &|r| r.gpu),
            stat("gpu °C", &|r| r.gpu_temp),
            stat("/ used %", &|r| r.disk_pct),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recs(pairs: &[(i64, f32)]) -> Vec<Rec> {
        pairs
            .iter()
            .map(|(ts, cpu)| Rec {
                ts: *ts,
                cpu: *cpu,
                gpu: f32::NAN,
                ..Default::default()
            })
            .collect()
    }

    #[test]
    fn bucket_means_and_gaps() {
        let recs = recs(&[(0, 10.0), (5, 20.0), (25, 40.0)]);
        let b = buckets(&recs, 0, 30, 3, |r| r.cpu);
        assert_eq!(b[0], 15.0);
        assert!(b[1].is_nan(), "no samples in 10..20");
        assert_eq!(b[2], 40.0);
    }

    #[test]
    fn windows_scrub_and_what_claude_is_told() {
        let day = 24 * 3600;
        let d = HistData {
            recs: recs(&[
                (1_000, 10.0),
                (1_000 + 2 * day, 30.0),
                (1_000 + 3 * day, 50.0),
            ]),
            ..Default::default()
        };
        let mut s = HistState::default();
        assert_eq!((s.win, s.offset), (1, 0));
        // The last 24h holds the newest sample only.
        let (label, lines) = ask_lines(&d, &s).unwrap();
        assert_eq!(label, "24h");
        assert_eq!(lines[0], "window: last 24h, 1 samples");
        assert_eq!(lines[1], "cpu %: avg 50.0 · min 50.0 · max 50.0");
        assert!(lines.contains(&"gpu %: no data".to_string()));
        // ] widens to 72h; ← goes back a quarter window, → comes back, never past now.
        assert!(s.key(Action::Char(']'), Some(&d)));
        assert!(s.key(Action::Char(']'), Some(&d)));
        assert_eq!(s.win, 2);
        assert_eq!(
            ask_lines(&d, &s).unwrap().1[0],
            "window: last 72h, 2 samples"
        );
        assert!(s.key(Action::Left, Some(&d)));
        assert_eq!(s.offset, 18 * 3600);
        assert!(s.key(Action::Right, Some(&d)));
        assert!(s.key(Action::Right, Some(&d)));
        assert_eq!(s.offset, 0);
        assert!(!s.key(Action::Refresh, Some(&d)), "not one of its keys");
        assert!(ask_lines(&HistData::default(), &s).is_none());
    }
}

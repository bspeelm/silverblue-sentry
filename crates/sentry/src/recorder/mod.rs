//! `sentry record` (spec §10): a foreground recorder for a spare terminal or tmux pane. It
//! samples into `metrics/ring.bin`, raises threshold alerts with `notify-send` while it runs,
//! and exits on Ctrl-C. No unit, no autostart: when it stops, nothing keeps recording.

pub mod ring;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::collectors::system::Sampler;
use crate::collectors::{Ctx, gpu, net};
use crate::config::{Config, Dur};
use crate::exec::Cmd;
use ring::Rec;

/// `metrics/recorder.pid`: pid, interval seconds, start time.
#[derive(Debug, Clone, PartialEq)]
pub struct Live {
    pub pid: u32,
    pub interval_s: u32,
    pub started: i64,
}

fn pid_path() -> std::path::PathBuf {
    ring::dir().join("recorder.pid")
}

fn alerts_path() -> std::path::PathBuf {
    ring::dir().join("alerts.log")
}

/// The running recorder, if its pid file points at a live `sentry` process.
pub fn live() -> Option<Live> {
    let text = std::fs::read_to_string(pid_path()).ok()?;
    let mut it = text.split_whitespace();
    let l = Live {
        pid: it.next()?.parse().ok()?,
        interval_s: it.next()?.parse().ok()?,
        started: it.next()?.parse().ok()?,
    };
    let comm = std::fs::read_to_string(format!("/proc/{}/comm", l.pid)).ok()?;
    comm.trim().starts_with("sentry").then_some(l)
}

/// Recent alert lines (`<rfc3339>\t<text>`), newest last.
pub fn recent_alerts(n: usize) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(alerts_path()).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..]
        .iter()
        .filter_map(|l| {
            let (ts, msg) = l.split_once('\t')?;
            Some((ts.to_string(), msg.to_string()))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    /// `cpu>90%:5m`, `mem>90%`, `swap>50%`, `cpu_temp>90:2m`, `gpu_temp>85`.
    Over {
        metric: String,
        limit: f32,
        for_s: u64,
    },
    /// `disk_free<5%`
    DiskFreeUnder(f32),
    /// `new_listener`
    NewListener,
}

pub fn parse_rule(s: &str) -> Result<Rule, String> {
    let s = s.trim();
    if s == "new_listener" {
        return Ok(Rule::NewListener);
    }
    if let Some(v) = s.strip_prefix("disk_free<") {
        let v = v.trim_end_matches('%');
        return v
            .parse()
            .map(Rule::DiskFreeUnder)
            .map_err(|_| format!("alert {s:?}: bad percentage"));
    }
    let (metric, rest) = s.split_once('>').ok_or_else(|| {
        format!("alert {s:?}: expected metric>limit[:duration], disk_free<N% or new_listener")
    })?;
    if !["cpu", "mem", "swap", "cpu_temp", "gpu_temp"].contains(&metric) {
        return Err(format!("alert {s:?}: unknown metric {metric:?}"));
    }
    let (limit, dur) = match rest.split_once(':') {
        Some((l, d)) => (l, Some(d)),
        None => (rest, None),
    };
    let limit: f32 = limit
        .trim_end_matches('%')
        .parse()
        .map_err(|_| format!("alert {s:?}: bad limit"))?;
    let for_s = match dur {
        Some(d) => d
            .parse::<Dur>()
            .map_err(|e| format!("alert {s:?}: {e}"))?
            .0
            .as_secs(),
        None => 0,
    };
    Ok(Rule::Over {
        metric: metric.into(),
        limit,
        for_s,
    })
}

/// Debounced alert: fires once when its condition has held long enough, re-arms when it clears.
struct Alert {
    rule: Rule,
    text: String,
    since: Option<i64>,
    fired: bool,
}

impl Alert {
    /// Feed one observation; returns true when the alert should fire now.
    fn observe(&mut self, now: i64, on: bool, for_s: u64) -> bool {
        if !on {
            self.since = None;
            self.fired = false;
            return false;
        }
        let since = *self.since.get_or_insert(now);
        if !self.fired && (now - since) as u64 >= for_s {
            self.fired = true;
            return true;
        }
        false
    }
}

fn notify(summary: &str, body: &str) {
    let _ = Cmd::host("notify-send")
        .args(["-a", "sentry", "-i", "dialog-warning", summary, body])
        .timeout(Some(Duration::from_secs(5)))
        .run();
    let line = format!("{}\t{summary}: {body}\n", jiff::Timestamp::now());
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(alerts_path())
    {
        let _ = f.write_all(line.as_bytes());
    }
    println!("! {summary}: {body}");
}

fn disk_used_pct() -> f32 {
    match rustix::fs::statvfs(crate::paths::host("/sysroot")) {
        Ok(st) if st.f_blocks > 0 => 100.0 * (1.0 - st.f_bavail as f32 / st.f_blocks as f32),
        _ => f32::NAN,
    }
}

/// Top processes by CPU from a CPU-only refresh (kernel `comm` names: no cmdline or user
/// reads), which keeps the recorder near its 0.1% budget.
struct TopSampler {
    sys: sysinfo::System,
}

impl TopSampler {
    fn new() -> Self {
        let mut t = Self {
            sys: sysinfo::System::new(),
        };
        t.sample();
        t
    }

    fn sample(&mut self) -> Vec<(String, f32)> {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate};
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_cpu(),
        );
        let mut v: Vec<(String, f32)> = self
            .sys
            .processes()
            .values()
            .filter(|p| p.thread_kind().is_none())
            .map(|p| {
                (
                    p.name().to_string_lossy().chars().take(16).collect(),
                    p.cpu_usage(),
                )
            })
            .collect();
        v.sort_by(|a, b| b.1.total_cmp(&a.1));
        v.truncate(3);
        v
    }
}

/// `sentry record`: returns the exit code.
pub fn run_cli(interval: Option<&str>) -> u8 {
    let (cfg, warnings) = Config::load();
    warnings.iter().for_each(|w| eprintln!("{w}"));
    let interval = match interval {
        Some(s) => match s.parse::<Dur>() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("sentry record: --interval {e}");
                return 2;
            }
        },
        None => cfg.recorder.interval,
    };
    let secs = interval.0.as_secs().max(1) as u32;
    match record(&cfg, secs) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("sentry record: {e:#}");
            1
        }
    }
}

fn record(cfg: &Config, secs: u32) -> anyhow::Result<()> {
    if let Some(l) = live() {
        anyhow::bail!(
            "a recorder is already running (pid {}, every {}s)",
            l.pid,
            l.interval_s
        );
    }
    let cap = ring::capacity(cfg.recorder.retention_hours, secs, cfg.recorder.max_mb);
    let mut w = ring::Writer::open(&ring::path(), cap, secs)?;
    let started = jiff::Timestamp::now().as_second();
    crate::paths::write_atomic(
        &pid_path(),
        format!("{} {secs} {started}\n", std::process::id()).as_bytes(),
    )?;
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ] {
        signal_hook::flag::register(sig, Arc::clone(&stop))?;
    }
    let mut alerts: Vec<Alert> = Vec::new();
    for a in &cfg.recorder.alerts {
        match parse_rule(a) {
            Ok(rule) => alerts.push(Alert {
                rule,
                text: a.clone(),
                since: None,
                fired: false,
            }),
            Err(e) => eprintln!("{e} (ignored)"),
        }
    }
    println!(
        "recording every {secs}s → {} ({} samples ≈ {}h kept) · alerts: {} · Ctrl-C stops",
        ring::path().display(),
        cap,
        cap * secs as u64 / 3600,
        if alerts.is_empty() {
            "none".to_string()
        } else {
            alerts
                .iter()
                .map(|a| a.text.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );

    let ctx = Ctx::new(cfg.clone());
    let mut sys = Sampler::new();
    sys.sample();
    let mut procs = TopSampler::new();
    let mut top: (Instant, Vec<(String, f32)>) = (Instant::now(), Vec::new());
    let mut gpu_last: (Instant, Option<gpu::Gpu>) =
        (Instant::now() - Duration::from_secs(3600), None);
    let mut net_last = Instant::now() - Duration::from_secs(3600);
    let mut known: Option<std::collections::BTreeSet<String>> = None;
    let mut next = Instant::now() + Duration::from_secs(secs as u64);
    while !stop.load(Ordering::Relaxed) {
        // Sleep in short steps so Ctrl-C is prompt.
        let now = Instant::now();
        if now < next {
            std::thread::sleep((next - now).min(Duration::from_millis(250)));
            continue;
        }
        next += Duration::from_secs(secs as u64);
        if next < Instant::now() {
            next = Instant::now() + Duration::from_secs(secs as u64);
        }
        let s = sys.sample();
        // nvidia-smi costs ~40 ms of CPU per call: every 3 minutes.
        if gpu_last.0.elapsed() >= Duration::from_secs(180) {
            gpu_last = (Instant::now(), gpu::collect().ok().flatten());
        }
        // A full process scan is the other big cost: once a minute (CPU % averaged over it).
        if top.1.is_empty() || top.0.elapsed() >= Duration::from_secs(60) {
            top = (Instant::now(), procs.sample());
        }
        let r = Rec {
            ts: jiff::Timestamp::now().as_second(),
            cpu: s.cpu_total,
            mem_gib: crate::fmt::gib(s.mem.used) as f32,
            swap_gib: crate::fmt::gib(s.swap.used) as f32,
            rx: s.net.rx_bps as f32,
            tx: s.net.tx_bps as f32,
            load1: s.load[0] as f32,
            cpu_temp: s.temps.cpu.unwrap_or(f32::NAN),
            gpu: gpu_last.1.as_ref().map_or(f32::NAN, |g| g.util),
            gpu_temp: gpu_last.1.as_ref().map_or(f32::NAN, |g| g.temp),
            disk_pct: disk_used_pct(),
            top: top.1.clone(),
        };
        w.push(&r)?;
        println!(
            "{} cpu {:>3.0}% mem {:>5.1}G rx {:>9} tx {:>9} / {:>3.0}%{}",
            jiff::Zoned::now().strftime("%H:%M:%S"),
            r.cpu,
            r.mem_gib,
            crate::fmt::rate(r.rx as f64),
            crate::fmt::rate(r.tx as f64),
            r.disk_pct,
            r.top
                .first()
                .map_or(String::new(), |(n, c)| format!("  top {n} {c:.0}%"))
        );

        let mem_pct = 100.0 * s.mem.used as f32 / s.mem.total.max(1) as f32;
        let swap_pct = 100.0 * s.swap.used as f32 / s.swap.total.max(1) as f32;
        let check_net = net_last.elapsed() >= Duration::from_secs(60);
        let listeners = if check_net && alerts.iter().any(|a| a.rule == Rule::NewListener) {
            net_last = Instant::now();
            // /proc/net instead of `ss`: no spawn, no process names; the baseline still
            // matches `addr:port/?` on the address alone.
            let low = net::ephemeral_low();
            let baseline = crate::baseline::Baseline::effective(&ctx.cfg);
            Some(
                net::proc_listeners()
                    .into_iter()
                    .filter(|(proto, addr, port)| {
                        let l = net::Listener {
                            proto: proto.clone(),
                            addr: addr.clone(),
                            port: port.clone(),
                            process: None,
                            pid: None,
                            status: net::ListenStatus::New,
                        };
                        !net::is_local(addr)
                            && !net::is_ephemeral(&l, low)
                            && !baseline.has_listener(&l.key())
                    })
                    .map(|(proto, addr, port)| format!("{proto} {addr}:{port}"))
                    .collect::<std::collections::BTreeSet<_>>(),
            )
        } else {
            None
        };
        for a in &mut alerts {
            match a.rule.clone() {
                Rule::Over {
                    metric,
                    limit,
                    for_s,
                } => {
                    let v = match metric.as_str() {
                        "cpu" => r.cpu,
                        "mem" => mem_pct,
                        "swap" => swap_pct,
                        "cpu_temp" => r.cpu_temp,
                        _ => r.gpu_temp,
                    };
                    if a.observe(r.ts, v > limit, for_s) {
                        notify(
                            &format!("{metric} above {limit}"),
                            &format!("{v:.0} ({})", a.text),
                        );
                    }
                }
                Rule::DiskFreeUnder(pct) => {
                    let free = 100.0 - r.disk_pct;
                    if a.observe(r.ts, free < pct, 0) {
                        notify("disk space low", &format!("/ has {free:.1}% free"));
                    }
                }
                Rule::NewListener => {
                    let Some(now_set) = &listeners else { continue };
                    // The first scan is the reference; alert on listeners that appear later.
                    if let Some(prev) = &known {
                        let new: Vec<&String> = now_set.difference(prev).collect();
                        if !new.is_empty() {
                            notify(
                                "new listener",
                                &new.iter()
                                    .map(|s| s.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            );
                        }
                    }
                    known = Some(now_set.clone());
                }
            }
        }
    }
    let _ = std::fs::remove_file(pid_path());
    println!("recorder stopped · {} kept", ring::path().display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert_eq!(
            parse_rule("cpu>90%:5m").unwrap(),
            Rule::Over {
                metric: "cpu".into(),
                limit: 90.0,
                for_s: 300
            }
        );
        assert_eq!(
            parse_rule("disk_free<5%").unwrap(),
            Rule::DiskFreeUnder(5.0)
        );
        assert_eq!(parse_rule("new_listener").unwrap(), Rule::NewListener);
        assert!(parse_rule("bogus>1").is_err());
        assert!(parse_rule("cpu>x").is_err());
    }

    #[test]
    fn debounce() {
        let mut a = Alert {
            rule: Rule::NewListener,
            text: String::new(),
            since: None,
            fired: false,
        };
        assert!(!a.observe(0, true, 300));
        assert!(!a.observe(200, true, 300));
        assert!(a.observe(300, true, 300), "held for 5 minutes");
        assert!(!a.observe(310, true, 300), "fires once");
        assert!(!a.observe(320, false, 300));
        assert!(!a.observe(330, true, 300), "re-armed, timer restarts");
    }
}

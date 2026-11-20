//! A remote host's metrics over time, kept on this machine: `<data>/servers/<name>/metrics/ring.bin`
//! (a network's under `networks/`) in sentry's ring format, for the History screen. Nothing
//! records on the host. The ring is written by whoever samples it from here: the TUI, from
//! the samples the Dashboard and Processes take anyway, and `sentry-server record`, in the
//! foreground until Ctrl-C. So there's data only for the time one of them was running.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::{Remote, probe};
use sentry_core::recorder::ring::{self, Rec};
use sentry_core::recorder::{live, pid_path};

/// One record per this many seconds, kept for [`HOURS`]: the widest window History shows.
/// The shape is fixed, since two writers with different ones would each move the other's
/// file aside.
pub const INTERVAL_S: u32 = 10;
pub const HOURS: u32 = 72;
/// A temperature or GPU reading older than this isn't the interval's.
pub const FRESH: Duration = Duration::from_secs(30);

pub fn capacity() -> u64 {
    HOURS as u64 * 3600 / INTERVAL_S as u64
}

/// A reading taken at `at`, unless it's too old to stand for now.
pub fn fresh<T>(v: Option<T>, at: Option<Instant>, now: Instant) -> Option<T> {
    v.filter(|_| at.is_some_and(|at| now.duration_since(at) <= FRESH))
}

/// A mean being taken.
#[derive(Debug, Default, Clone, Copy)]
struct Mean(f64, u32);

impl Mean {
    fn add(&mut self, v: Option<f64>) {
        if let Some(v) = v {
            self.0 += v;
            self.1 += 1;
        }
    }
    fn take(&mut self) -> f32 {
        let m = std::mem::take(self);
        if m.1 == 0 {
            f32::NAN
        } else {
            (m.0 / m.1 as f64) as f32
        }
    }
}

/// Samples in, a record out every [`INTERVAL_S`].
#[derive(Debug, Default)]
pub struct Recorder {
    /// When the interval being gathered began.
    since: Option<i64>,
    cpu: Mean,
    rx: Mean,
    tx: Mean,
}

impl Recorder {
    /// One sample: CPU %, bytes per second in and out (each since the sample before, when
    /// there was one) and the probe they came from; the rest is whatever was last read. A
    /// record once ten seconds of wall clock have passed since the last: CPU and network as
    /// the interval's means, memory and load as they are now, what's unknown as NaN.
    #[allow(clippy::too_many_arguments)]
    pub fn feed(
        &mut self,
        now_s: i64,
        cpu: Option<f32>,
        rx: Option<f64>,
        tx: Option<f64>,
        p: &probe::Probe,
        temp: Option<f32>,
        gpu: Option<(f32, f32)>,
        disk_pct: Option<f32>,
    ) -> Option<Rec> {
        self.cpu.add(cpu.map(f64::from));
        self.rx.add(rx);
        self.tx.add(tx);
        let since = *self.since.get_or_insert(now_s);
        // A clock set back: start over rather than wait for it to catch up.
        if now_s < since {
            self.since = Some(now_s);
            return None;
        }
        if now_s - since < INTERVAL_S as i64 {
            return None;
        }
        self.since = Some(now_s);
        const GIB: f32 = 1024.0 * 1024.0;
        Some(Rec {
            ts: now_s,
            cpu: self.cpu.take(),
            mem_gib: p.mem_total_kib.saturating_sub(p.mem_avail_kib) as f32 / GIB,
            swap_gib: p.swap_total_kib.saturating_sub(p.swap_free_kib) as f32 / GIB,
            rx: self.rx.take(),
            tx: self.tx.take(),
            load1: p.load[0],
            cpu_temp: temp.unwrap_or(f32::NAN),
            gpu: gpu.map_or(f32::NAN, |g| g.0),
            gpu_temp: gpu.map_or(f32::NAN, |g| g.1),
            disk_pct: disk_pct.unwrap_or(f32::NAN),
            top: Vec::new(),
        })
    }
}

/// A record from the TUI into the server's ring. Not when `offline` (tests), and not while
/// `sentry-server record` runs for this server: one writer at a time. True: written.
pub fn write(server: &str, offline: bool, r: &Rec) -> std::io::Result<bool> {
    if offline || live(server).is_some() {
        return Ok(false);
    }
    ring::append(&ring::path(server), capacity(), INTERVAL_S, r)?;
    Ok(true)
}

/// `/`'s share used, from the disks read.
pub fn root_pct(disks: &[sentry_core::collectors::disk::Mount]) -> Option<f32> {
    disks
        .iter()
        .find(|m| m.target == "/")
        .map(|m| m.pct() as f32)
}

/// What a probe doesn't give: read once a minute by whoever knows how on this kind of host.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Extras {
    pub cpu_temp: Option<f32>,
    /// Utilisation and temperature.
    pub gpu: Option<(f32, f32)>,
    /// `/`'s share used.
    pub disk_pct: Option<f32>,
}

/// `sentry-server record [server]`: sample the host every ten seconds into its ring, in
/// the foreground, until Ctrl-C. One probe per sample; `extras` (disks, temperature, GPU)
/// once a minute. Read-only on the host, and nothing is left there.
pub fn record(r: &Remote, extras: impl FnMut(&Remote) -> Extras) -> anyhow::Result<()> {
    let (name, scope) = (&r.name, &r.scope);
    if let Some(l) = live(scope) {
        anyhow::bail!(
            "a recorder is already running for {name} (pid {}, every {}s)",
            l.pid,
            l.interval_s
        );
    }
    let path = ring::path(scope);
    // Create it (or move an incompatible one aside) before saying where it is.
    drop(ring::Writer::open(&path, capacity(), INTERVAL_S)?);
    let started = jiff::Timestamp::now().as_second();
    sentry_core::paths::write_atomic(
        &pid_path(scope),
        format!("{} {INTERVAL_S} {started}\n", std::process::id()).as_bytes(),
    )?;
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ] {
        signal_hook::flag::register(sig, Arc::clone(&stop))?;
    }
    println!(
        "recording {name} every {INTERVAL_S}s → {} ({} samples = {HOURS}h kept) · Ctrl-C stops",
        path.display(),
        capacity()
    );
    let out = run(r, &stop, extras);
    let _ = std::fs::remove_file(pid_path(scope));
    println!("stopped");
    out
}

/// The sampling loop, until `stop` is set.
pub fn run(
    r: &Remote,
    stop: &AtomicBool,
    mut extras: impl FnMut(&Remote) -> Extras,
) -> anyhow::Result<()> {
    let every = Duration::from_secs(INTERVAL_S as u64);
    let slow = Duration::from_secs(60);
    let path = ring::path(&r.scope);
    let mut rec = Recorder::default();
    let mut cpu = probe::CpuDelta::default();
    let mut net: Option<(u64, u64, Instant)> = None;
    let mut slow_at: Option<Instant> = None;
    let (mut temp, mut gpu, mut disk): (Option<f32>, Option<(f32, f32)>, Option<f32>) =
        (None, None, None);
    let mut down = false;
    let mut next = Instant::now();
    let mut printed = Instant::now() - slow;
    while !stop.load(Ordering::Relaxed) {
        // Sleep in short steps so Ctrl-C is prompt.
        let now = Instant::now();
        if now < next {
            std::thread::sleep((next - now).min(Duration::from_millis(250)));
            continue;
        }
        next += every;
        if next < Instant::now() {
            next = Instant::now() + every;
        }
        let p = match probe::collect(r) {
            Ok(p) => p,
            Err(e) => {
                // A gap in the ring, said once.
                if !down {
                    eprintln!("{}: {e} (still trying)", r.name);
                }
                down = true;
                net = None;
                continue;
            }
        };
        down = false;
        if slow_at.is_none_or(|t| t.elapsed() >= slow) {
            slow_at = Some(Instant::now());
            let x = extras(r);
            (temp, gpu, disk) = (x.cpu_temp, x.gpu, x.disk_pct);
        }
        let at = Instant::now();
        let rates = net.and_then(|(rx, tx, was)| {
            let dt = at.duration_since(was).as_secs_f64();
            (dt > 0.0 && p.rx_bytes >= rx && p.tx_bytes >= tx)
                .then(|| ((p.rx_bytes - rx) as f64 / dt, (p.tx_bytes - tx) as f64 / dt))
        });
        net = Some((p.rx_bytes, p.tx_bytes, at));
        let Some(row) = rec.feed(
            jiff::Timestamp::now().as_second(),
            cpu.pct(p.cpu),
            rates.map(|r| r.0),
            rates.map(|r| r.1),
            &p,
            temp,
            gpu,
            disk,
        ) else {
            continue;
        };
        ring::append(&path, capacity(), INTERVAL_S, &row)?;
        if printed.elapsed() >= slow {
            printed = Instant::now();
            println!(
                "{}  cpu {:.0}%  mem {:.1} GiB  load {:.2}  rx {}",
                jiff::Zoned::now().strftime("%H:%M:%S"),
                row.cpu,
                row.mem_gib,
                row.load1,
                sentry_core::fmt::rate(row.rx as f64)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe() -> probe::Probe {
        probe::Probe {
            mem_total_kib: 32 * 1024 * 1024,
            mem_avail_kib: 20 * 1024 * 1024,
            swap_total_kib: 4 * 1024 * 1024,
            swap_free_kib: 3 * 1024 * 1024,
            load: [0.5, 0.4, 0.3],
            ..Default::default()
        }
    }

    #[test]
    fn a_record_needs_ten_seconds() {
        let mut r = Recorder::default();
        let p = probe();
        for s in 0..10 {
            assert!(
                r.feed(1000 + s, Some(10.0), None, None, &p, None, None, None)
                    .is_none(),
                "{s}"
            );
        }
        let rec = r
            .feed(1010, Some(10.0), None, None, &p, None, None, None)
            .expect("ten seconds on");
        assert_eq!(rec.ts, 1010);
        // The next interval starts there.
        assert!(
            r.feed(1019, Some(10.0), None, None, &p, None, None, None)
                .is_none()
        );
        assert!(
            r.feed(1020, Some(10.0), None, None, &p, None, None, None)
                .is_some()
        );
        // A clock set back starts over.
        assert!(
            r.feed(500, Some(10.0), None, None, &p, None, None, None)
                .is_none()
        );
        assert!(
            r.feed(510, Some(10.0), None, None, &p, None, None, None)
                .is_some()
        );
        assert_eq!(capacity(), 25_920);
    }

    #[test]
    fn means_over_ten_seconds() {
        let mut r = Recorder::default();
        let p = probe();
        // The first sample has no rates yet.
        r.feed(0, None, None, None, &p, None, None, None);
        r.feed(4, Some(20.0), Some(100.0), Some(10.0), &p, None, None, None);
        r.feed(8, Some(40.0), Some(300.0), Some(30.0), &p, None, None, None);
        let rec = r
            .feed(
                10,
                Some(90.0),
                Some(500.0),
                Some(50.0),
                &p,
                Some(51.0),
                Some((12.0, 60.0)),
                Some(41.5),
            )
            .unwrap();
        assert_eq!((rec.cpu, rec.rx, rec.tx), (50.0, 300.0, 30.0));
        // Memory, swap and load as they are now.
        assert_eq!((rec.mem_gib, rec.swap_gib, rec.load1), (12.0, 1.0, 0.5));
        assert_eq!(
            (rec.cpu_temp, rec.gpu, rec.gpu_temp, rec.disk_pct),
            (51.0, 12.0, 60.0, 41.5)
        );
        assert!(rec.top.is_empty());
        // The means start again; an interval with no rate at all has none.
        let rec = r.feed(20, None, None, None, &p, None, None, None).unwrap();
        assert!(rec.cpu.is_nan() && rec.rx.is_nan() && rec.gpu.is_nan());
    }

    #[test]
    fn stale_temperature_is_nan() {
        let now = Instant::now();
        let long_ago = now.checked_sub(Duration::from_secs(31));
        let just_now = now.checked_sub(Duration::from_secs(5));
        assert_eq!(fresh(Some(48.0), just_now, now), Some(48.0));
        assert_eq!(fresh(Some(48.0), long_ago, now), None);
        assert_eq!(fresh(Some(48.0), None, now), None);
        let mut r = Recorder::default();
        let p = probe();
        r.feed(0, None, None, None, &p, None, None, None);
        let rec = r
            .feed(
                10,
                None,
                None,
                None,
                &p,
                fresh(Some(48.0), long_ago, now),
                None,
                None,
            )
            .unwrap();
        assert!(rec.cpu_temp.is_nan() && rec.disk_pct.is_nan());
    }

    #[test]
    fn offline_writes_nothing() {
        let name = "ring-offline-test";
        let rec = Rec {
            ts: 1,
            ..Default::default()
        };
        assert!(!write(name, true, &rec).unwrap());
        assert!(!ring::path(name).exists());
    }

    #[test]
    fn the_tui_stands_back_for_a_running_recorder() {
        let name = "ring-standback-test";
        let rec = |ts| Rec {
            ts,
            ..Default::default()
        };
        // A recorder's pid file naming a live sentry process (this test binary is one).
        std::fs::create_dir_all(ring::dir(name)).unwrap();
        std::fs::write(
            pid_path(name),
            format!("{} {INTERVAL_S} 0\n", std::process::id()),
        )
        .unwrap();
        assert!(live(name).is_some(), "the test binary counts as sentry");
        assert!(!write(name, false, &rec(1)).unwrap());
        assert!(!ring::path(name).exists());
        // It stopped: the TUI writes, in the fixed shape.
        std::fs::remove_file(pid_path(name)).unwrap();
        assert!(write(name, false, &rec(2)).unwrap());
        assert!(write(name, false, &rec(3)).unwrap());
        let (h, recs) = ring::read_metrics(&ring::path(name)).unwrap();
        assert_eq!((h.capacity, h.interval_s), (capacity(), INTERVAL_S));
        assert_eq!(recs.iter().map(|r| r.ts).collect::<Vec<_>>(), [2, 3]);
        let _ = std::fs::remove_dir_all(ring::dir(name));
    }

    #[test]
    fn the_root_disk_is_the_one_recorded() {
        use sentry_core::collectors::disk::Mount;
        let m = |target: &str, used| Mount {
            target: target.into(),
            source: String::new(),
            fstype: String::new(),
            size: 200,
            used,
            removable: false,
        };
        assert_eq!(root_pct(&[m("/srv/data", 186), m("/", 50)]), Some(25.0));
        assert_eq!(root_pct(&[m("/srv/data", 186)]), None);
    }
}

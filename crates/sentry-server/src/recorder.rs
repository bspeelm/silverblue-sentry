//! A server's metrics over time, kept on this machine (`sentry_app::remote::recorder`: the
//! ring's shape, the TUI's feed and the foreground loop). What only a server has is here:
//! where its temperature, GPU and disks are read.

pub use sentry_app::remote::recorder::*;

use crate::collect::{self, health};
use crate::remote::Remote;

/// Disks, temperature and GPU, read once a minute.
fn extras(r: &Remote) -> Extras {
    Extras {
        cpu_temp: health::cpu_temp(r).ok().flatten().map(|t| t.c),
        gpu: collect::gpu(r).ok().flatten().map(|g| (g.util, g.temp)),
        disk_pct: collect::disks(r).ok().and_then(|d| root_pct(&d)),
    }
}

/// `sentry-server record [server]`: in the foreground until Ctrl-C.
pub fn record(r: &Remote) -> anyhow::Result<()> {
    sentry_app::remote::recorder::record(r, |_| extras(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::recorder::ring;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// Against a real server, read-only there; the ring goes under XDG_DATA_HOME, so point
    /// that at a scratch dir:
    /// `SENTRY_SERVER_LIVE=<name> XDG_DATA_HOME=<scratch> cargo test live_record -- --ignored`.
    #[test]
    #[ignore]
    fn live_record() {
        sentry_core::paths::use_real_dirs();
        let Ok(name) = std::env::var("SENTRY_SERVER_LIVE") else {
            return;
        };
        let (file, _) = crate::config::load().unwrap();
        let (n, s) = crate::config::pick(&file, Some(&name)).unwrap();
        let r = Remote::new(n, s);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(25));
            flag.store(true, Ordering::Relaxed);
        });
        run(&r, &stop, |_| extras(&r)).unwrap();
        t.join().unwrap();
        let (h, recs) = ring::read_metrics(&ring::path(&r.name)).unwrap();
        assert_eq!(h.interval_s, INTERVAL_S);
        assert!(recs.len() >= 2, "{} record(s) in 25 s", recs.len());
        assert!(recs.iter().all(|x| x.mem_gib > 0.0));
    }
}

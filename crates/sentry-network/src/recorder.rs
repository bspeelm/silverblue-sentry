//! The router's metrics over time, kept on this machine (`sentry_app::remote::recorder`: the
//! ring's shape, the TUI's feed and the foreground loop), under
//! `<data>/networks/<name>/metrics/`. What only a router has is here: the disk recorded is
//! its overlay, read with `ubus`, and the temperature its SoC's thermal zone. There is no GPU.

pub use sentry_app::remote::recorder::*;

use crate::collect::ifaces;
use crate::remote::Router;

/// The SoC's temperature, where there is a thermal zone.
fn temp(r: &Router) -> Option<f32> {
    let out = r
        .output(&r.sh("cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null; true"))
        .ok()?;
    out.trim().parse::<f32>().ok().map(|m| m / 1000.0)
}

/// How full the overlay is and how warm the SoC, read once a minute.
fn extras(r: &Router) -> Extras {
    Extras {
        cpu_temp: temp(r),
        gpu: None,
        disk_pct: ifaces::info(r).ok().and_then(|i| i.root_pct()),
    }
}

/// `sentry-network record [name]`: in the foreground until Ctrl-C. One `/proc` probe per ten
/// seconds; nothing runs on the router between them, and nothing is left there.
pub fn record(r: &Router) -> anyhow::Result<()> {
    sentry_app::remote::recorder::record(r, |_| extras(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::recorder::ring;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// Against a real router, read-only there; the ring goes under XDG_DATA_HOME, so point
    /// that (and XDG_CONFIG_HOME, with a network_config.yaml) at a scratch dir:
    /// `SENTRY_NETWORK_LIVE=<name> XDG_DATA_HOME=… XDG_CONFIG_HOME=… cargo test -p sentry-network live_record -- --ignored`.
    #[test]
    #[ignore]
    fn live_record() {
        sentry_core::paths::use_real_dirs();
        let Ok(name) = std::env::var("SENTRY_NETWORK_LIVE") else {
            return;
        };
        let (file, _) = crate::config::load().unwrap();
        let (n, cfg) = crate::config::pick(&file, Some(&name)).unwrap();
        let r = Router::new(n, cfg);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(25));
            flag.store(true, Ordering::Relaxed);
        });
        run(&r, &stop, |_| extras(&r)).unwrap();
        t.join().unwrap();
        let path = ring::path(&r.scope);
        assert!(path.ends_with(format!("networks/{n}/metrics/ring.bin")));
        let (h, recs) = ring::read_metrics(&path).unwrap();
        assert_eq!(h.interval_s, INTERVAL_S);
        assert!(recs.len() >= 2, "{} record(s) in 25 s", recs.len());
        assert!(recs.iter().all(|x| x.mem_gib > 0.0 && x.disk_pct > 0.0));
    }
}

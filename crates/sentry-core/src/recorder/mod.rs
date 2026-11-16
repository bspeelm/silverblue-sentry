//! What a recorder leaves behind, for both programs: the metrics ring ([`ring`]), the pid
//! file of a recorder that is running, and its alert log. This machine's (`server` `""`) are
//! written by `sentry record`; a server's by sentry-server, from this machine. Recorders run
//! in the foreground only: when one stops, nothing keeps recording.

pub mod ring;

use std::path::PathBuf;

/// `metrics/recorder.pid`: pid, interval seconds, start time.
#[derive(Debug, Clone, PartialEq)]
pub struct Live {
    pub pid: u32,
    pub interval_s: u32,
    pub started: i64,
}

pub fn pid_path(server: &str) -> PathBuf {
    ring::dir(server).join("recorder.pid")
}

pub fn alerts_path(server: &str) -> PathBuf {
    ring::dir(server).join("alerts.log")
}

/// The running recorder, if its pid file points at a live `sentry` process.
pub fn live(server: &str) -> Option<Live> {
    let text = std::fs::read_to_string(pid_path(server)).ok()?;
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
pub fn recent_alerts(server: &str, n: usize) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(alerts_path(server)).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..]
        .iter()
        .filter_map(|l| {
            let (ts, msg) = l.split_once('\t')?;
            Some((ts.to_string(), msg.to_string()))
        })
        .collect()
}

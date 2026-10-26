//! Collectors for a server. Each has a pure `parse` (tested on synthetic fixtures in
//! `tests/fixtures/server/`) and a `collect(&Remote)`. [`snapshot`] runs them all, in
//! parallel, keeping going past the ones that fail.

pub mod apt;
pub mod docker;
pub mod health;
pub mod probe;
pub mod units;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::remote::{Remote, SrvError};
use crate::collectors::{disk, gpu, journal, net};

/// Errors in the last 24 h, per unit or syslog identifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JournalUnit {
    pub ident: String,
    pub count: usize,
    pub last: String,
    pub last_us: u64,
}

pub fn group_journal(entries: Vec<journal::Entry>) -> Vec<JournalUnit> {
    let mut out: Vec<JournalUnit> = Vec::new();
    for e in entries {
        match out.iter_mut().find(|u| u.ident == e.ident) {
            Some(u) => {
                u.count += 1;
                if e.ts_us >= u.last_us {
                    u.last = e.message;
                    u.last_us = e.ts_us;
                }
            }
            None => out.push(JournalUnit {
                ident: e.ident,
                count: 1,
                last: e.message,
                last_us: e.ts_us,
            }),
        }
    }
    out.sort_by(|a, b| b.count.cmp(&a.count).then(a.ident.cmp(&b.ident)));
    out
}

pub fn journal(r: &Remote) -> Result<Vec<JournalUnit>, SrvError> {
    let c = r.privileged(&[
        "journalctl",
        "-p",
        "err",
        "--since",
        "-24h",
        "-o",
        "json",
        "--output-fields=_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,MESSAGE,PRIORITY",
        "-n",
        "500",
        "--no-pager",
    ])?;
    Ok(group_journal(journal::parse(&r.output(&c)?)))
}

/// Listening sockets; with process names when `ss -tulpn` is allowed through sudo.
pub fn listeners(r: &Remote) -> Result<Vec<net::Listener>, SrvError> {
    let c = r
        .privileged(&["ss", "-tulpnH"])
        .or_else(|_| r.privileged(&["ss", "-tulpn", "-H"]))
        .unwrap_or_else(|_| r.cmd("ss").arg("-tulnH"));
    Ok(net::parse_listen(&r.output(&c)?))
}

pub fn disks(r: &Remote) -> Result<Vec<disk::Mount>, SrvError> {
    let opts = ["-J", "-b", "-o", "TARGET,SOURCE,FSTYPE,SIZE,USED"];
    let j = r.output(&r.cmd("findmnt").arg("--real").args(opts))?;
    let mut mounts = disk::parse(&j).map_err(|e| SrvError::Parse(e.to_string()))?;
    // `--real` leaves out overlay and tmpfs mounts; a configured one is looked up directly
    // before it's called missing.
    for rule in &r.cfg.disks {
        if mounts.iter().any(|m| m.target == rule.mount) {
            continue;
        }
        let c = r
            .cmd("findmnt")
            .args(opts)
            .args(["--mountpoint", &rule.mount]);
        if let Ok(j) = r.output(&c)
            && let Ok(found) = disk::parse(&j)
        {
            mounts.extend(found.into_iter().filter(|m| m.target == rule.mount));
        }
    }
    Ok(mounts)
}

pub fn gpu(r: &Remote) -> Result<Option<gpu::Gpu>, SrvError> {
    let c = r
        .cmd("nvidia-smi")
        .args([gpu::QUERY, "--format=csv,noheader,nounits"]);
    match r.output(&c) {
        Ok(csv) => Ok(gpu::parse(&csv)),
        Err(SrvError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// OS name and kernel.
pub fn host(r: &Remote) -> Result<(String, String), SrvError> {
    let o = r.output(&r.sh(". /etc/os-release; echo \"$PRETTY_NAME\"; uname -r"))?;
    let mut l = o.lines();
    Ok((
        l.next().unwrap_or("").to_string(),
        l.next().unwrap_or("").to_string(),
    ))
}

/// Everything sentry-server knows about a server at one moment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub server: String,
    pub taken_at: Option<Timestamp>,
    pub os: String,
    pub kernel: String,
    pub probe: Option<probe::Probe>,
    pub units: Option<units::Units>,
    pub docker: Option<docker::Docker>,
    pub apt: Option<apt::Apt>,
    pub smart: Vec<health::Smart>,
    pub cpu_temp: Option<health::CpuTemp>,
    pub gpu: Option<gpu::Gpu>,
    pub jails: Option<Vec<health::Jail>>,
    pub disks: Option<Vec<disk::Mount>>,
    pub listeners: Option<Vec<net::Listener>>,
    pub journal: Option<Vec<JournalUnit>>,
    /// (section, why it's missing)
    pub errors: Vec<(String, String)>,
}

/// Run every collector the config calls for, in parallel. A section that fails is left
/// empty and its error recorded; the snapshot as a whole only fails if ssh does.
pub fn snapshot(r: &Remote) -> Result<Snapshot, SrvError> {
    let (os, kernel) = host(r)?;
    let mut s = Snapshot {
        server: r.name.clone(),
        taken_at: Some(Timestamp::now()),
        os,
        kernel,
        ..Default::default()
    };
    let mut errors: Vec<(String, String)> = Vec::new();
    fn keep<T>(
        errors: &mut Vec<(String, String)>,
        name: &str,
        r: Result<T, SrvError>,
    ) -> Option<T> {
        r.map_err(|e| errors.push((name.to_string(), e.to_string())))
            .ok()
    }
    std::thread::scope(|sc| {
        let probe = sc.spawn(|| probe::collect(r));
        let units = sc.spawn(|| units::collect(r));
        let docker = sc.spawn(|| docker::collect(r));
        let apt = sc.spawn(|| apt::collect(r));
        let smart = sc.spawn(|| {
            r.cfg
                .smart
                .iter()
                .map(|d| health::smart(r, d))
                .collect::<Vec<_>>()
        });
        let temp = sc.spawn(|| health::cpu_temp(r));
        let gpu_ = sc.spawn(|| gpu(r));
        let jails = sc.spawn(|| health::fail2ban(r));
        let disks_ = sc.spawn(|| disks(r));
        let listen = sc.spawn(|| listeners(r));
        let journal_ = sc.spawn(|| journal(r));
        fn join<T>(
            h: std::thread::ScopedJoinHandle<'_, Result<T, SrvError>>,
        ) -> Result<T, SrvError> {
            h.join()
                .unwrap_or_else(|_| Err(SrvError::Failed("collector panicked".into())))
        }
        s.probe = keep(&mut errors, "probe", join(probe));
        s.units = keep(&mut errors, "units", join(units));
        s.docker = keep(&mut errors, "docker", join(docker));
        s.apt = keep(&mut errors, "apt", join(apt));
        for (d, res) in r.cfg.smart.iter().zip(smart.join().unwrap_or_default()) {
            if let Some(v) = keep(&mut errors, &format!("smart {d}"), res) {
                s.smart.push(v);
            }
        }
        s.cpu_temp = keep(&mut errors, "sensors", join(temp)).flatten();
        s.gpu = keep(&mut errors, "gpu", join(gpu_)).flatten();
        s.jails = keep(&mut errors, "fail2ban", join(jails));
        s.disks = keep(&mut errors, "disks", join(disks_));
        s.listeners = keep(&mut errors, "listeners", join(listen));
        s.journal = keep(&mut errors, "journal", join(journal_));
    });
    s.errors = errors;
    Ok(s)
}

/// One collector by name, as JSON (`sentry-server collect <server> <kind>`).
pub fn collect_json(r: &Remote, kind: &str) -> Result<serde_json::Value, SrvError> {
    let j = |v: Result<serde_json::Value, serde_json::Error>| {
        v.map_err(|e| SrvError::Parse(e.to_string()))
    };
    match kind {
        "probe" => j(serde_json::to_value(probe::collect(r)?)),
        "units" => j(serde_json::to_value(units::collect(r)?)),
        "docker" => j(serde_json::to_value(docker::collect(r)?)),
        "docker-stats" => j(serde_json::to_value(docker::stats(r)?)),
        "apt" => j(serde_json::to_value(apt::collect(r)?)),
        "smart" => j(serde_json::to_value(
            r.cfg
                .smart
                .iter()
                .map(|d| health::smart(r, d))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        "sensors" => j(serde_json::to_value(health::cpu_temp(r)?)),
        "gpu" => j(serde_json::to_value(gpu(r)?)),
        "fail2ban" => j(serde_json::to_value(health::fail2ban(r)?)),
        "disks" => j(serde_json::to_value(disks(r)?)),
        "listeners" => j(serde_json::to_value(listeners(r)?)),
        "journal" => j(serde_json::to_value(journal(r)?)),
        "snapshot" => j(serde_json::to_value(snapshot(r)?)),
        k => Err(SrvError::Failed(format!(
            "unknown collector `{k}` (one of: {})",
            KINDS.join(", ")
        ))),
    }
}

pub const KINDS: &[&str] = &[
    "probe",
    "units",
    "docker",
    "docker-stats",
    "apt",
    "smart",
    "sensors",
    "gpu",
    "fail2ban",
    "disks",
    "listeners",
    "journal",
    "snapshot",
];

#[cfg(test)]
pub(crate) fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/server/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_groups_by_unit() {
        let g = group_journal(journal::parse(&fixture("journal.jsonl")));
        assert_eq!(g.len(), 2);
        assert_eq!((g[0].ident.as_str(), g[0].count), ("app.service", 2));
        assert_eq!(g[0].last, "connection refused (second)");
    }

    /// The real server's captures, kept out of git in `tests/fixtures/server/local/`.
    /// `cargo test -- --ignored` on the developer's machine checks the parsers against them.
    #[test]
    #[ignore]
    fn parses_local_captures() {
        let dir = format!("{}/tests/fixtures/server/local", env!("CARGO_MANIFEST_DIR"));
        let read = |f: &str| std::fs::read_to_string(format!("{dir}/{f}")).unwrap();
        assert!(probe::parse(&read("probe.txt")).unwrap().cores > 0);
        assert!(
            !units::parse_list(&read("list-units.json"))
                .unwrap()
                .is_empty()
        );
        assert!(
            units::parse_show(&read("show-utc.txt"))[0]
                .last_trigger
                .is_some()
        );
        assert!(
            !docker::parse_inspect(&read("docker-inspect.json"))
                .unwrap()
                .is_empty()
        );
        assert!(!docker::parse_stats(&read("docker-stats.jsonl")).is_empty());
        assert!(
            !docker::parse_projects(&read("compose-ls.json"))
                .unwrap()
                .is_empty()
        );
        let mut text = read("apt-sim.txt");
        text.push_str("@@stamps\n");
        text.push_str(&read("apt-state.txt"));
        let a = apt::parse(&text);
        assert!(!a.running_kernel.is_empty() && a.now > 0);
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("smart-") {
                let s = health::parse_smart(&name, &read(&name));
                assert!(
                    !matches!(s.health, health::SmartHealth::Unknown(_)),
                    "{name}: {s:?}"
                );
            }
        }
        assert!(health::parse_sensors(&read("sensors.json")).is_some());
        let f = read("f2b.txt");
        assert!(!health::parse_jail_list(&f).is_empty());
        assert!(!net::parse_listen(&read("ss-tulpn.txt")).is_empty());
        assert!(!group_journal(journal::parse(&read("journal.jsonl"))).is_empty());
        assert!(gpu::parse(&read("gpu.csv")).is_some());
    }
}

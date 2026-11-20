//! Findings for a server: what in a [`Snapshot`] needs attention, given what the config says
//! is normal. Pure ([`derive`]), so every rule is tested on synthetic snapshots. Reports go to
//! `~/.local/share/sentry/servers/<name>/reports/`; findings marked expected go to
//! `~/.config/sentry/servers/<name>/baseline.toml` (the Network screen's expected listeners too).

use std::path::PathBuf;

use super::collect::Snapshot;
use super::collect::apt::Kind;
use super::collect::health::SmartHealth;
use super::config::Server;
use super::remote::{Remote, SrvError};
use jiff::Timestamp;
use sentry_app::remote::audit as store;
pub use sentry_app::remote::audit::{names, reports_dir, set_expected, set_expected_in};
use sentry_core::baseline::{BaselineFile, glob};
use sentry_core::collectors::net::{ListenStatus, Listener};
use sentry_core::finding::{Finding, Sev};

/// The finding namespace of everything a server's audit says.
pub const NS: &str = "srv";

/// A server's audit: its snapshot and what that found.
pub type Report = store::Report<Snapshot>;
/// A report as the report view shows it, with the one before.
pub type Shown = store::Shown<Snapshot>;

/// The finding a listener open to the network gets (one per protocol and port).
pub fn listener_id(l: &Listener) -> String {
    store::listener_id(NS, l)
}

/// How a listening socket stands, for the audit and the Network screen alike: loopback is
/// local, DHCP's client sockets are clients, what `listeners:` in the config or the baseline
/// file covers is expected, and the rest is new.
pub fn listener_status(l: &Listener, cfg: &Server, base: &BaselineFile) -> ListenStatus {
    store::listener_status(l, &cfg.listeners, base)
}

fn f(id: String, sev: Sev, category: &str, message: String) -> Finding {
    Finding {
        id,
        severity: sev,
        category: category.into(),
        message,
        ..Default::default()
    }
}

trait Explain {
    fn explain(self, what: &str, why: &str, fix: &str) -> Self;
    fn evidence(self, e: String) -> Self;
}

impl Explain for Finding {
    fn explain(mut self, what: &str, why: &str, fix: &str) -> Self {
        self.what = what.into();
        self.why = why.into();
        self.fix = fix.into();
        self
    }
    fn evidence(mut self, e: String) -> Self {
        self.evidence = e;
        self
    }
}

fn ago(secs: i64) -> String {
    let s = secs.max(0);
    if s >= 2 * 86400 {
        format!("{} days", s / 86400)
    } else if s >= 3600 {
        format!("{} h", s / 3600)
    } else {
        format!("{} min", s / 60)
    }
}

/// Every finding for this snapshot. `prev` is the last report's snapshot (restart counts),
/// `base` what was marked expected outside the config (findings, and listeners).
pub fn derive(
    s: &Snapshot,
    cfg: &Server,
    prev: Option<&Snapshot>,
    base: &BaselineFile,
) -> Vec<Finding> {
    let now = s.taken_at.unwrap_or_else(Timestamp::now);
    let mut out = Vec::new();

    if let Some(u) = &s.units {
        for svc in &cfg.services {
            match u.get(svc) {
                Some(st) if st.load == "not-found" => out.push(
                    f(
                        format!("srv:service-missing:{svc}"),
                        Sev::High,
                        "services",
                        format!("{svc} doesn't exist on the server"),
                    )
                    .explain(
                        "A service listed in server_config.yaml isn't installed.",
                        "Either it was removed or the name in the config is wrong.",
                        "Fix the name in services:, or remove it.",
                    ),
                ),
                Some(st) if st.active != "active" => out.push(
                    f(
                        format!("srv:service-down:{svc}"),
                        Sev::High,
                        "services",
                        format!("{svc} is {} ({})", st.active, st.sub),
                    )
                    .explain(
                        "A service you said must be running isn't.",
                        "Whatever it provides is down.",
                        "Look at its log (L on Services), then restart it (R).",
                    )
                    .evidence(format!(
                        "ActiveState={} SubState={} Result={}",
                        st.active, st.sub, st.result
                    )),
                ),
                _ => {}
            }
        }
        for row in u.failed() {
            if cfg.services.contains(&row.unit) {
                continue; // already a service-down finding
            }
            out.push(
                f(
                    format!("srv:unit-failed:{}", row.unit),
                    Sev::Medium,
                    "services",
                    format!("{} failed", row.unit),
                )
                .explain(
                    "systemd marks this unit failed.",
                    "It either crashed or a one-off job exited with an error.",
                    "Read its log; if it's harmless, reset-failed (x on Services).",
                )
                .evidence(format!("{} · {}", row.description, row.sub)),
            );
        }
        for t in &cfg.timers {
            let Some(st) = u.get(&t.unit) else { continue };
            let id = format!("srv:timer-stale:{}", t.unit);
            let ran = st.triggers.as_deref().and_then(|svc| u.get(svc));
            let failed = ran.filter(|r| !r.result.is_empty() && r.result != "success");
            match (st.last_trigger, failed) {
                (_, Some(r)) => out.push(
                    f(id, Sev::High, "timers", format!("{}: last run failed ({}, exit {})", t.unit, r.result, r.exit.unwrap_or(-1)))
                        .explain("The job this timer runs failed the last time.", "Scheduled work (backups, renewals) isn't getting done.", "Read the service's log (L) and fix the cause; it runs again at the next tick.")
                        .evidence(format!("{} Result={} ExecMainStatus={}", r.id, r.result, r.exit.unwrap_or(-1))),
                ),
                (None, None) => out.push(
                    f(id, Sev::High, "timers", format!("{} has never run", t.unit))
                        .explain("The timer has no last trigger time.", "Its job may never have run.", "Check it's enabled (systemctl list-timers)."),
                ),
                (Some(last), None) => {
                    let age = now.as_second() - last.as_second();
                    if age > t.max_age.0.as_secs() as i64 {
                        out.push(
                            f(id, Sev::High, "timers", format!("{}: last ran {} ago (max {})", t.unit, ago(age), t.max_age))
                                .explain("The timer hasn't fired as often as it should.", "Scheduled work is late: the timer may be stopped, or the server was off.", "Check `systemctl list-timers`, and that the timer is enabled and active.")
                                .evidence(format!("LastTriggerUSec={last} NextElapse={}", st.next.map_or("-".into(), |n| n.to_string()))),
                        );
                    }
                }
            }
        }
    }

    if let Some(d) = &s.docker {
        for c in &d.containers {
            if cfg.containers.ignore.iter().any(|g| glob(g, &c.name)) {
                continue;
            }
            if c.down() {
                out.push(
                    f(format!("srv:container-down:{}", c.name), Sev::High, "containers", format!("container {} is {} (exit {}{})", c.name, c.status, c.exit_code, if c.oom { ", killed: out of memory" } else { "" }))
                        .explain("A container isn't running.", "The service it provides is down.", "Look at its logs (L on Containers), then restart it (R) or bring the project up (u).")
                        .evidence(format!("{} · {}", c.image, c.status)),
                );
            } else if c.health.as_deref() == Some("unhealthy") {
                out.push(
                    f(
                        format!("srv:container-unhealthy:{}", c.name),
                        Sev::Medium,
                        "containers",
                        format!("container {} is unhealthy", c.name),
                    )
                    .explain(
                        "Its health check is failing.",
                        "It's running but not working properly.",
                        "Look at its logs (L), then restart it (R).",
                    ),
                );
            }
            let before = prev
                .and_then(|p| p.docker.as_ref())
                .and_then(|pd| pd.containers.iter().find(|x| x.name == c.name));
            let more_restarts = before.is_some_and(|b| c.restarts > b.restarts);
            let recent = c.started_at.is_some_and(|t| {
                now.as_second() - t.as_second() < cfg.containers.restart_window.0.as_secs() as i64
            });
            if c.status == "running" && (more_restarts || recent || c.oom) {
                let when = c.started_at.map_or(String::new(), |t| {
                    format!(" {} ago", ago(now.as_second() - t.as_second()))
                });
                out.push(
                    f(
                        format!("srv:container-restarted:{}", c.name),
                        Sev::Low,
                        "containers",
                        format!(
                            "container {} restarted{when} ({} restarts in total)",
                            c.name, c.restarts
                        ),
                    )
                    .explain(
                        "The container started recently.",
                        "Fine after an update or reboot; repeated restarts mean it keeps crashing.",
                        "If you didn't restart it, look at its logs (L).",
                    ),
                );
            }
            if c.docker_sock {
                out.push(
                    f(format!("srv:docker-sock:{}", c.name), Sev::Medium, "containers", format!("container {} can control docker (docker.sock mounted)", c.name))
                        .explain("/var/run/docker.sock is mounted inside it.", "Whoever controls that container can start containers with any host path mounted: in effect, root on the server.", "Expected for CI runners and container managers: press b. Otherwise remove the mount."),
                );
            }
        }
    }

    if let Some(ls) = &s.listeners {
        let mut seen: Vec<String> = Vec::new();
        for l in ls {
            if listener_status(l, cfg, base) != ListenStatus::New {
                continue;
            }
            let id = listener_id(l);
            if seen.contains(&id) {
                continue;
            }
            seen.push(id.clone());
            let owner = s
                .docker
                .as_ref()
                .and_then(|d| {
                    d.containers
                        .iter()
                        .find(|c| c.ports.iter().any(|(_, hp, _)| *hp == l.port))
                })
                .map(|c| format!("container {}", c.name))
                .or_else(|| l.process.clone())
                .unwrap_or_else(|| "unknown process".into());
            out.push(
                f(id, Sev::Medium, "listeners", format!("{} port {} open to the network ({owner})", l.proto, l.port))
                    .explain("Something listens on this port on every address, and it isn't in listeners:.", "Anything that can reach the server can talk to it.", "If you meant it, add it to listeners: in server_config.yaml (or press b); otherwise stop it or bind it to 127.0.0.1.")
                    .evidence(l.key()),
            );
        }
    }

    if let Some(a) = &s.apt {
        if let Some(since) = a.reboot_since {
            let age = a.now - since;
            let sev = if age > 14 * 86400 {
                Sev::High
            } else {
                Sev::Medium
            };
            out.push(
                f("srv:reboot-required".into(), sev, "updates", format!("reboot required for {}", ago(age)))
                    .explain("Updated packages only take effect after a reboot.", "Until then the server runs the old kernel or libraries, with their known bugs and security holes.", "Reboot when it suits you (B on Updates).")
                    .evidence(format!("running {} · newest installed {} · asked for by: {}", a.running_kernel, a.newest_kernel.as_deref().unwrap_or("?"), a.reboot_pkgs.join(", "))),
            );
        }
        let security: Vec<&str> = a
            .upgrades
            .iter()
            .filter(|p| p.kind == Kind::Security)
            .map(|p| p.name.as_str())
            .collect();
        if !security.is_empty() {
            out.push(
                f(
                    "srv:updates:security".into(),
                    Sev::High,
                    "updates",
                    format!("{} security update(s) waiting", security.len()),
                )
                .explain(
                    "The distribution has published security fixes that aren't installed.",
                    "They fix known vulnerabilities.",
                    "Upgrade (U on Updates).",
                )
                .evidence(security.join(" ")),
            );
        } else if !a.upgrades.is_empty() {
            out.push(
                f(
                    "srv:updates:pending".into(),
                    Sev::Low,
                    "updates",
                    format!("{} update(s) waiting", a.upgrades.len()),
                )
                .explain(
                    "Package updates are available.",
                    "None are security fixes.",
                    "Upgrade when convenient (U on Updates).",
                )
                .evidence(
                    a.upgrades
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
            );
        }
        if let Some(t) = a.stamp("update")
            && a.now - t > 2 * 86400
        {
            out.push(
                f("srv:apt-lists-stale".into(), Sev::Medium, "updates", format!("package lists last refreshed {} ago", ago(a.now - t)))
                    .explain("apt hasn't downloaded fresh package lists recently.", "Updates published since then aren't known, so the list above may be incomplete.", "Refresh (c on Updates); check that apt-daily.timer runs."),
            );
        }
    }

    for d in &s.smart {
        let bad = match &d.health {
            SmartHealth::Failed => Some("SMART health check FAILED".to_string()),
            _ if d.bad_sectors > 0 || d.uncorrectable > 0 => Some(format!(
                "{} bad sector(s), {} uncorrectable error(s)",
                d.bad_sectors, d.uncorrectable
            )),
            _ => None,
        };
        if let Some(why) = bad {
            out.push(
                f(
                    format!("srv:smart:{}", d.dev),
                    Sev::High,
                    "disks",
                    format!("{}: {why}", d.dev),
                )
                .explain(
                    "The disk reports damage.",
                    "Disks that start losing sectors often fail soon.",
                    "Make sure the backup is current, then plan to replace the disk.",
                )
                .evidence(format!(
                    "{} · {} h powered on",
                    d.model.as_deref().unwrap_or("?"),
                    d.power_on_hours.unwrap_or(0)
                )),
            );
        }
    }

    if let Some(mounts) = &s.disks {
        for rule in &cfg.disks {
            match mounts.iter().find(|m| m.target == rule.mount) {
                None => out.push(
                    f(
                        format!("srv:disk-missing:{}", rule.mount),
                        Sev::High,
                        "disks",
                        format!("{} isn't mounted", rule.mount),
                    )
                    .explain(
                        "A filesystem from disks: isn't mounted.",
                        "Anything writing there writes to the parent disk instead, or fails.",
                        "Check the disk and mount it (and its fstab entry).",
                    ),
                ),
                Some(m) => {
                    let pct = m.pct();
                    let sev = if pct >= rule.crit as f64 {
                        Some(Sev::High)
                    } else if pct >= rule.warn as f64 {
                        Some(Sev::Medium)
                    } else {
                        None
                    };
                    if let Some(sev) = sev {
                        out.push(
                            f(
                                format!("srv:disk:{}", rule.mount),
                                sev,
                                "disks",
                                format!("{} is {pct:.0}% full", rule.mount),
                            )
                            .explain(
                                "The filesystem is filling up.",
                                "When it's full, writes fail: databases, logs and backups break.",
                                "Find what grew (du -xh --max-depth=2) and clean up, or add space.",
                            )
                            .evidence(format!("{} on {} ({})", m.target, m.source, m.fstype)),
                        );
                    }
                }
            }
        }
    }

    if let Some(p) = &s.probe {
        let t = &cfg.thresholds;
        if p.mem_used_pct() >= t.mem {
            out.push(f(
                "srv:mem-high".into(),
                Sev::Medium,
                "load",
                format!("memory {:.0}% used", p.mem_used_pct()),
            ));
        }
        if p.cores > 0 && p.load[1] / p.cores as f32 >= t.load_per_core {
            out.push(f(
                "srv:load-high".into(),
                Sev::Medium,
                "load",
                format!("load {:.1} on {} cores (5 min)", p.load[1], p.cores),
            ));
        }
    }
    if let Some(c) = s.cpu_temp
        && c.c >= cfg.thresholds.cpu_temp
    {
        out.push(f(
            "srv:cpu-hot".into(),
            Sev::Medium,
            "load",
            format!("CPU at {:.0}°C", c.c),
        ));
    }
    if let Some(g) = &s.gpu
        && g.temp >= cfg.thresholds.gpu_temp
    {
        out.push(f(
            "srv:gpu-hot".into(),
            Sev::Medium,
            "load",
            format!("GPU at {:.0}°C", g.temp),
        ));
    }

    for j in s.jails.iter().flatten() {
        if j.banned > 0 {
            out.push(
                f(
                    format!("srv:fail2ban:{}", j.name),
                    Sev::Low,
                    "security",
                    format!("fail2ban jail {}: {} address(es) banned", j.name, j.banned),
                )
                .explain(
                    "fail2ban is blocking addresses that failed to log in too often.",
                    "That's it doing its job; many bans means someone is trying.",
                    "Nothing to do unless you locked yourself out.",
                ),
            );
        }
    }
    for j in s.journal.iter().flatten() {
        out.push(
            f(
                format!("srv:journal:{}", j.ident),
                Sev::Low,
                "logs",
                format!("{}: {} error(s) in 24 h", j.ident, j.count),
            )
            .explain(
                "Errors were logged in the last day.",
                "Often noise; repeated ones point at something broken.",
                "Read them: journalctl -p err --since -24h",
            )
            .evidence(j.last.clone()),
        );
    }

    out.extend(crate::maint::eval::findings(
        &s.maint,
        &cfg.maintenance.items,
    ));

    for x in &mut out {
        x.expected = cfg
            .findings
            .iter()
            .chain(&base.findings)
            .any(|g| glob(g, &x.id));
    }
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
    out
}

/// One stored report, by name.
pub fn load(server: &str, name: &str) -> Option<Report> {
    store::load(server, name)
}

/// The report at `idx` (None: the newest), read from disk.
pub fn shown(server: &str, idx: Option<usize>) -> Shown {
    store::shown(server, idx)
}

/// `B`: the pattern for every finding like this one (`srv:<kind>:*`), and what that is in
/// words. None for a finding that is the only one of its kind.
pub fn pattern_for(id: &str) -> Option<(String, String)> {
    store::pattern_for(NS, id)
}

/// The newest stored report.
pub fn latest(server: &str) -> Option<Report> {
    store::latest(server)
}

/// Snapshot, derive, store (keeping the newest 200 reports).
pub fn run(r: &Remote) -> Result<(Report, PathBuf), SrvError> {
    let snap = super::collect::snapshot(r)?;
    let prev = latest(&r.name);
    let base = BaselineFile::load(&r.name);
    let findings = derive(&snap, &r.cfg, prev.as_ref().map(|p| &p.snapshot), &base);
    let report = Report {
        snapshot: snap,
        findings,
    };
    let path = store::store(&r.name, &report)?;
    Ok((report, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::{apt, docker, fixture, health, units};
    use crate::config::{DiskRule, TimerRule};
    use sentry_core::collectors::{disk::Mount, net};
    use sentry_core::config::Dur;

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn a_pattern_covers_everything_of_a_kind() {
        let (p, what) = pattern_for("srv:container:db:exited").unwrap();
        assert_eq!(
            (p.as_str(), what.as_str()),
            ("srv:container:*", "every container finding")
        );
        assert!(glob(&p, "srv:container:web:unhealthy"));
        assert!(!glob(&p, "srv:unit:backup.service"));
        // The only one of its kind, or not the server's: no pattern.
        assert_eq!(pattern_for("srv:reboot-required"), None);
        assert_eq!(pattern_for("listener:x"), None);
    }

    #[test]
    fn stored_reports_are_listed_and_read_with_the_one_before() {
        let server = "shown-test";
        let dir = reports_dir(server);
        std::fs::create_dir_all(&dir).unwrap();
        let rep = |id: &str| Report {
            snapshot: Default::default(),
            findings: vec![f(id.into(), Sev::Low, "logs", id.into())],
        };
        for (name, id) in [
            ("2026-10-01-000000", "srv:a:1"),
            ("2026-10-02-000000", "srv:a:2"),
        ] {
            std::fs::write(
                dir.join(format!("{name}.json")),
                serde_json::to_vec(&rep(id)).unwrap(),
            )
            .unwrap();
        }
        assert_eq!(names(server), ["2026-10-01-000000", "2026-10-02-000000"]);
        let s = shown(server, None);
        assert!(s.latest() && s.idx == 1);
        assert_eq!(s.cur.unwrap().findings[0].id, "srv:a:2");
        assert_eq!(s.prev.unwrap().findings[0].id, "srv:a:1");
        let s = shown(server, Some(0));
        assert!(!s.latest() && s.prev.is_none());
        assert_eq!(s.cur.unwrap().findings[0].id, "srv:a:1");
        assert!(shown("nothing-kept", None).cur.is_none());
    }

    fn snap() -> Snapshot {
        let mut u = units::Units {
            all: units::parse_list(&fixture("list-units.json")).unwrap(),
            watched: units::parse_show(&fixture("show.txt")),
        };
        u.watched.retain(|w| w.id != "gone.service");
        Snapshot {
            server: "myserver".into(),
            taken_at: Some(ts("2026-10-26T12:00:00Z")),
            units: Some(u),
            docker: Some(docker::Docker {
                containers: docker::parse_inspect(&fixture("docker-inspect.json")).unwrap(),
                projects: vec![],
            }),
            apt: Some(apt::parse(&fixture("apt.txt"))),
            smart: ["smart-ok.json", "smart-bad.json", "smart-asleep.json"]
                .iter()
                .zip(["/dev/sda", "/dev/sdb", "/dev/sdc"])
                .map(|(f, d)| health::parse_smart(d, &fixture(f)))
                .collect(),
            disks: Some(vec![Mount {
                target: "/".into(),
                source: "/dev/sda2".into(),
                fstype: "ext4".into(),
                size: 100,
                used: 90,
                removable: false,
            }]),
            listeners: Some(net::parse_listen(&fixture("ss-tuln.txt"))),
            ..Default::default()
        }
    }

    fn cfg() -> Server {
        Server {
            services: vec!["app.service".into(), "backup.service".into()],
            timers: vec![TimerRule {
                unit: "backup.timer".into(),
                max_age: Dur::hours(27),
            }],
            disks: vec![
                DiskRule {
                    mount: "/".into(),
                    warn: 85,
                    crit: 95,
                },
                DiskRule {
                    mount: "/srv/data".into(),
                    warn: 85,
                    crit: 95,
                },
            ],
            listeners: vec!["*:22/*".into()],
            ..Default::default()
        }
    }

    fn none() -> BaselineFile {
        BaselineFile::default()
    }

    #[test]
    fn listener_status_matches_the_findings() {
        let s = snap();
        let f = derive(&s, &cfg(), None, &none());
        let ls = s.listeners.as_ref().unwrap();
        // Every new listener has its finding, and nothing else has one.
        for l in ls {
            let new = listener_status(l, &cfg(), &none()) == ListenStatus::New;
            let found = f.iter().any(|x| x.id == listener_id(l));
            assert_eq!(new, found, "{} {}", l.proto, l.local());
        }
        let word = |proto: &str, addr: &str, port: &str| {
            let l = ls
                .iter()
                .find(|l| l.proto == proto && l.addr == addr && l.port == port)
                .unwrap();
            listener_status(l, &cfg(), &none())
        };
        assert_eq!(word("tcp", "127.0.0.1", "5432"), ListenStatus::Local);
        assert_eq!(
            word("udp", "192.0.2.10%eth0", "68"),
            ListenStatus::Ephemeral
        );
        assert_eq!(word("tcp", "0.0.0.0", "22"), ListenStatus::Baseline);
        assert_eq!(word("tcp", "[::]", "443"), ListenStatus::New);
        // A UDP service on a high port is new too (it isn't taken for a client socket).
        let vpn = Listener {
            proto: "udp".into(),
            addr: "0.0.0.0".into(),
            port: "51820".into(),
            process: None,
            pid: None,
            status: ListenStatus::New,
        };
        assert_eq!(listener_status(&vpn, &cfg(), &none()), ListenStatus::New);
    }

    #[test]
    fn baseline_listeners_silence_the_finding() {
        let base = BaselineFile {
            listeners: vec!["0.0.0.0:443/*".into(), "[::]:443/*".into()],
            ..Default::default()
        };
        let f = derive(&snap(), &cfg(), None, &base);
        let ids = ids(&f);
        assert!(!ids.contains(&"srv:listener:tcp:443"), "{ids:?}");
        assert!(!ids.contains(&"srv:listener:udp:443"), "{ids:?}");
        // One family only: the other still shows.
        let half = BaselineFile {
            listeners: vec!["0.0.0.0:443/*".into()],
            ..Default::default()
        };
        assert!(
            ids_of(&derive(&snap(), &cfg(), None, &half))
                .contains(&"srv:listener:tcp:443".to_string())
        );
        // Marking the finding expected, and taking that back.
        let mut b = none();
        assert!(set_expected_in(&mut b, "srv:listener:tcp:443", true));
        assert!(!set_expected_in(&mut b, "srv:listener:tcp:443", true));
        let f = derive(&snap(), &cfg(), None, &b);
        assert!(
            f.iter()
                .find(|x| x.id == "srv:listener:tcp:443")
                .unwrap()
                .expected
        );
        assert!(set_expected_in(&mut b, "srv:listener:tcp:443", false));
        assert!(!set_expected_in(&mut b, "srv:listener:tcp:443", false));
    }

    fn ids_of(f: &[Finding]) -> Vec<String> {
        f.iter().map(|f| f.id.clone()).collect()
    }

    fn ids(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.id.as_str()).collect()
    }

    #[test]
    fn every_rule_on_one_snapshot() {
        let f = derive(&snap(), &cfg(), None, &none());
        let ids = ids(&f);
        for want in [
            "srv:service-down:backup.service",
            "srv:unit-failed:report.service",
            "srv:timer-stale:backup.timer", // its service failed
            "srv:container-down:db",
            "srv:container-restarted:web",
            "srv:docker-sock:runner",
            "srv:listener:tcp:443",
            "srv:listener:udp:443",
            "srv:reboot-required",
            "srv:updates:security",
            "srv:smart:/dev/sdb",
            "srv:disk:/",
            "srv:disk-missing:/srv/data",
        ] {
            assert!(ids.contains(&want), "missing {want} in {ids:?}");
        }
        for not in [
            "srv:smart:/dev/sda",
            "srv:smart:/dev/sdc",
            "srv:listener:tcp:22",
            "srv:listener:tcp:5432",
            "srv:listener:udp:68",
            "srv:service-down:app.service",
        ] {
            assert!(!ids.contains(&not), "unexpected {not}");
        }
        let t = f
            .iter()
            .find(|f| f.id == "srv:timer-stale:backup.timer")
            .unwrap();
        assert!(
            t.message.contains("last run failed (exit-code, exit 1)"),
            "{}",
            t.message
        );
        let r = f.iter().find(|f| f.id == "srv:reboot-required").unwrap();
        assert_eq!(r.severity, Sev::Medium, "8 days: medium");
        let l = f.iter().find(|f| f.id == "srv:listener:tcp:443").unwrap();
        assert!(l.message.contains("container web"), "{}", l.message);
        assert_eq!(f[0].severity, Sev::High, "sorted by severity");
        let d = f.iter().find(|f| f.id == "srv:disk:/").unwrap();
        assert_eq!(d.severity, Sev::Medium, "90% is over warn, under crit");
    }

    #[test]
    fn stale_timer_and_expected() {
        let mut s = snap();
        // The service succeeded, but the timer last fired 2 days ago.
        let u = s.units.as_mut().unwrap();
        u.watched
            .iter_mut()
            .find(|w| w.id == "backup.service")
            .unwrap()
            .result = "success".into();
        s.taken_at = Some(ts("2026-10-28T08:00:00Z"));
        let f = derive(
            &s,
            &cfg(),
            None,
            &BaselineFile {
                findings: vec!["srv:docker-sock:*".into()],
                ..Default::default()
            },
        );
        let t = f
            .iter()
            .find(|f| f.id == "srv:timer-stale:backup.timer")
            .unwrap();
        assert!(
            t.message.contains("last ran 2 days ago (max 27h)"),
            "{}",
            t.message
        );
        assert!(
            f.iter()
                .find(|f| f.id == "srv:docker-sock:runner")
                .unwrap()
                .expected
        );
        assert!(!t.expected);
    }

    #[test]
    fn restarts_since_the_last_report() {
        let s = snap();
        let mut prev = snap();
        let mut c = cfg();
        c.containers.restart_window = Dur::secs(60);
        // web started > 1 min before the snapshot; restarts went 2 → 3 since the last report.
        prev.docker
            .as_mut()
            .unwrap()
            .containers
            .iter_mut()
            .find(|c| c.name == "web")
            .unwrap()
            .restarts = 2;
        assert!(
            ids(&derive(&s, &c, Some(&prev), &none())).contains(&"srv:container-restarted:web")
        );
        assert!(!ids(&derive(&s, &c, Some(&s), &none())).contains(&"srv:container-restarted:web"));
    }
}

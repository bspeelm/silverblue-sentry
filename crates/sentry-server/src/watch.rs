//! What of a server's config sentry can stop watching (`servers/<name>/watch.toml`, core
//! `maint::watch`): the lists that say what must be there. The YAML is never rewritten;
//! `Remote::new` applies the file over it, so the collectors' expectations and the audit
//! simply don't have the thing any more.
//!
//! Covered: `timers` (by unit), `services` (by unit), `disks` (by mount), `smart` (by
//! device) and one container (by name: it joins `containers.ignore`). A maintenance item
//! has its own way already (`untracked` in items.toml).

use sentry_core::baseline::glob;
use sentry_core::maint::watch::{Watch, key, split};

use crate::config::Server;

pub const TIMER: &str = "timer";
pub const SERVICE: &str = "service";
pub const DISK: &str = "disk";
pub const SMART: &str = "smart";
pub const CONTAINER: &str = "container";

/// Everything the config lists that a session may stop watching: (its key, what it is).
pub fn watched(cfg: &Server) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for t in &cfg.timers {
        out.push((
            key(TIMER, &t.unit),
            format!("a timer that must have run within {}", t.max_age),
        ));
    }
    for s in &cfg.services {
        out.push((key(SERVICE, s), "a service that must be active".into()));
    }
    for d in &cfg.disks {
        out.push((
            key(DISK, &d.mount),
            "a filesystem that must be mounted".into(),
        ));
    }
    for d in &cfg.smart {
        out.push((key(SMART, d), "a disk whose SMART health is read".into()));
    }
    out
}

/// What a finding is about, as the key a plan's `unwatch` step names.
pub fn of_finding(id: &str) -> Option<String> {
    let rest = id.strip_prefix("srv:")?;
    let (kind, name) = rest.split_once(':')?;
    let kind = match kind {
        "timer-stale" => TIMER,
        "service-missing" | "service-down" => SERVICE,
        "disk-missing" | "disk" => DISK,
        "smart" => SMART,
        "container-down" | "container-unhealthy" | "container-restarted" => CONTAINER,
        _ => return None,
    };
    (!name.is_empty()).then(|| key(kind, name))
}

/// What a session about this finding may stop watching: what the finding is about first
/// (a container is watched without being listed), then the rest of the lists.
pub fn offered(cfg: &Server, finding: &str) -> Vec<(String, String)> {
    let mut all = watched(cfg);
    let Some(k) = of_finding(finding) else {
        return all;
    };
    match all.iter().position(|(x, _)| *x == k) {
        Some(i) => {
            let first = all.remove(i);
            all.insert(0, first);
        }
        None if k.starts_with("container:") => {
            all.insert(0, (k, "a container that must be running".into()));
        }
        None => {}
    }
    all
}

/// Whether `key` names something this config watches (a container: any name).
pub fn known(cfg: &Server, k: &str) -> bool {
    match split(k) {
        Some((CONTAINER, _)) => true,
        Some(_) => watched(cfg).iter().any(|(x, _)| x == k),
        None => false,
    }
}

/// The config without what's no longer watched.
pub fn applied(cfg: &Server, w: &Watch) -> Server {
    let mut s = cfg.clone();
    s.timers.retain(|t| !w.has(TIMER, &t.unit));
    s.services.retain(|x| !w.has(SERVICE, x));
    s.disks.retain(|d| !w.has(DISK, &d.mount));
    s.smart.retain(|d| !w.has(SMART, d));
    for c in w.names(CONTAINER) {
        if !s.containers.ignore.iter().any(|g| g == c) {
            s.containers.ignore.push(c.to_string());
        }
    }
    s
}

/// A stored finding is about something this config (the file applied) still watches. One
/// that isn't can't come from a new audit: whoever shows a stored report drops it, so the
/// row leaves when the watching stops, not at the next audit.
pub fn still_watched(cfg: &Server, finding: &str) -> bool {
    let Some(k) = of_finding(finding) else {
        return true;
    };
    match split(&k) {
        Some((TIMER, n)) => cfg.timers.iter().any(|t| t.unit == n),
        Some((SERVICE, n)) => cfg.services.iter().any(|s| s == n),
        Some((DISK, n)) => cfg.disks.iter().any(|d| d.mount == n),
        Some((SMART, n)) => cfg.smart.iter().any(|d| d == n),
        Some((CONTAINER, n)) => !cfg.containers.ignore.iter().any(|g| glob(g, n)),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DiskRule, TimerRule};
    use sentry_core::config::Dur;

    fn cfg() -> Server {
        Server {
            services: vec!["app.service".into(), "old.service".into()],
            timers: vec![
                TimerRule {
                    unit: "backup.timer".into(),
                    max_age: Dur::hours(27),
                },
                TimerRule {
                    unit: "report.timer".into(),
                    max_age: Dur::hours(200),
                },
            ],
            disks: vec![DiskRule {
                mount: "/srv/data".into(),
                warn: 85,
                crit: 95,
            }],
            smart: vec!["/dev/sda".into()],
            ..Default::default()
        }
    }

    #[test]
    fn what_is_no_longer_watched_leaves_the_config_and_nothing_else_does() {
        let d = "2026-11-21".parse().unwrap();
        let mut w = Watch::default();
        for (kind, name) in [
            (TIMER, "report.timer"),
            (SERVICE, "old.service"),
            (DISK, "/srv/data"),
            (SMART, "/dev/sda"),
            (CONTAINER, "legacy"),
        ] {
            assert!(known(&cfg(), &key(kind, name)), "{kind}:{name}");
            w.add(kind, name, d, "retired");
        }
        let s = applied(&cfg(), &w);
        assert_eq!(
            s.timers.iter().map(|t| t.unit.as_str()).collect::<Vec<_>>(),
            ["backup.timer"]
        );
        assert_eq!(s.services, ["app.service"]);
        assert!(s.disks.is_empty() && s.smart.is_empty());
        assert_eq!(s.containers.ignore, ["legacy"]);
        // Twice is once.
        assert_eq!(applied(&s, &w).containers.ignore, ["legacy"]);
        assert!(!known(&cfg(), "timer:nope.timer") && !known(&cfg(), "cron:x"));
    }

    #[test]
    fn a_finding_names_what_it_is_about() {
        for (id, k) in [
            ("srv:timer-stale:report.timer", Some("timer:report.timer")),
            ("srv:service-down:old.service", Some("service:old.service")),
            (
                "srv:service-missing:old.service",
                Some("service:old.service"),
            ),
            ("srv:disk-missing:/srv/data", Some("disk:/srv/data")),
            ("srv:disk:/srv/data", Some("disk:/srv/data")),
            ("srv:smart:/dev/sda", Some("smart:/dev/sda")),
            ("srv:container-down:legacy", Some("container:legacy")),
            ("srv:updates:security", None),
            ("srv:reboot-required", None),
            ("net:service:dnsmasq", None),
        ] {
            assert_eq!(of_finding(id).as_deref(), k, "{id}");
        }
        // What the finding is about is offered first; a container without being listed.
        let o = offered(&cfg(), "srv:timer-stale:report.timer");
        assert_eq!(o[0].0, "timer:report.timer");
        assert_eq!(o.len(), 6);
        assert_eq!(
            offered(&cfg(), "srv:container-down:legacy")[0].0,
            "container:legacy"
        );
        assert_eq!(offered(&cfg(), "srv:updates:security").len(), 6);
    }

    #[test]
    fn a_stored_finding_about_something_not_watched_any_more_is_not_shown() {
        let d = "2026-11-21".parse().unwrap();
        let mut w = Watch::default();
        w.add(TIMER, "report.timer", d, "retired");
        w.add(CONTAINER, "legacy", d, "retired");
        let s = applied(&cfg(), &w);
        assert!(!still_watched(&s, "srv:timer-stale:report.timer"));
        assert!(still_watched(&s, "srv:timer-stale:backup.timer"));
        assert!(!still_watched(&s, "srv:container-down:legacy"));
        assert!(still_watched(&s, "srv:container-down:web"));
        assert!(still_watched(&s, "srv:updates:security"));
    }
}

//! What of a network's config sentry can stop watching (`networks/<name>/watch.toml`, core
//! `maint::watch`): the lists under `expect` that say what must be there. The YAML is never
//! rewritten; `Router::new` applies the file over it, so the audit doesn't look for the
//! thing any more.
//!
//! Covered: `expect.services` (a service that must run) and `expect.forwards` (a port
//! forward that must exist, by its name). `expect.zones` and `expect.listeners` say what
//! is allowed, not what must be there: taking an entry out adds findings, so they aren't.

use sentry_core::maint::watch::{Watch, key, split};

use crate::config::Network;

pub const SERVICE: &str = "service";
pub const FORWARD: &str = "forward";

/// Everything the config lists that a session may stop watching: (its key, what it is).
pub fn watched(cfg: &Network) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for s in &cfg.expect.services {
        out.push((key(SERVICE, s), "a service that must be running".into()));
    }
    for f in &cfg.expect.forwards {
        out.push((
            key(FORWARD, &f.name),
            format!("a port forward that must exist ({} {})", f.proto, f.port),
        ));
    }
    out
}

/// What a finding is about, as the key a plan's `unwatch` step names.
pub fn of_finding(id: &str) -> Option<String> {
    let rest = id.strip_prefix("net:")?;
    if let Some(name) = rest.strip_prefix("forward:missing:") {
        return (!name.is_empty()).then(|| key(FORWARD, name));
    }
    let name = rest.strip_prefix("service:")?;
    (!name.is_empty()).then(|| key(SERVICE, name))
}

/// What a session about this finding may stop watching: what it is about first.
pub fn offered(cfg: &Network, finding: &str) -> Vec<(String, String)> {
    let mut all = watched(cfg);
    if let Some(i) = of_finding(finding).and_then(|k| all.iter().position(|(x, _)| *x == k)) {
        let first = all.remove(i);
        all.insert(0, first);
    }
    all
}

pub fn known(cfg: &Network, k: &str) -> bool {
    watched(cfg).iter().any(|(x, _)| x == k)
}

/// The config without what's no longer watched.
pub fn applied(cfg: &Network, w: &Watch) -> Network {
    let mut n = cfg.clone();
    n.expect.services.retain(|s| !w.has(SERVICE, s));
    n.expect.forwards.retain(|f| !w.has(FORWARD, &f.name));
    n
}

/// A stored finding is about something this config (the file applied) no longer watches:
/// it can't come from a new audit, so it isn't shown. (dnsmasq, dropbear and uhttpd are
/// watched without being listed: theirs stay.)
pub fn dropped(cfg: &Network, finding: &str) -> bool {
    let Some(k) = of_finding(finding) else {
        return false;
    };
    match split(&k) {
        Some((SERVICE, n)) => {
            !crate::collect::services::ESSENTIAL.contains(&n)
                && !cfg.expect.services.iter().any(|s| s == n)
        }
        Some((FORWARD, n)) => !cfg.expect.forwards.iter().any(|f| f.name == n),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Forward;

    fn cfg() -> Network {
        let mut n = Network::default();
        n.expect.services = vec!["wireguard".into(), "adblock".into()];
        n.expect.forwards = vec![Forward {
            name: "cam".into(),
            proto: "tcp".into(),
            port: "8554".parse().unwrap(),
            to: "192.0.2.50".into(),
        }];
        n
    }

    #[test]
    fn what_is_no_longer_watched_leaves_expect_and_nothing_else_does() {
        let d = "2026-11-21".parse().unwrap();
        let mut w = Watch::default();
        assert!(known(&cfg(), "service:adblock") && known(&cfg(), "forward:cam"));
        assert!(!known(&cfg(), "service:dnsmasq") && !known(&cfg(), "zone:lan"));
        w.add(SERVICE, "adblock", d, "replaced by the resolver's own list");
        w.add(FORWARD, "cam", d, "the camera is gone");
        let n = applied(&cfg(), &w);
        assert_eq!(n.expect.services, ["wireguard"]);
        assert!(n.expect.forwards.is_empty());
        assert!(dropped(&n, "net:service:adblock"));
        assert!(dropped(&n, "net:forward:missing:cam"));
        assert!(!dropped(&n, "net:service:wireguard"));
        // One sentry watches wherever it's installed: never dropped.
        assert!(!dropped(&n, "net:service:dnsmasq"));
        assert!(!dropped(&n, "net:ssh:password"));
        assert_eq!(
            offered(&cfg(), "net:forward:missing:cam")[0].0,
            "forward:cam"
        );
        assert_eq!(
            of_finding("net:service:adblock").as_deref(),
            Some("service:adblock")
        );
        assert_eq!(of_finding("net:forward:tcp:8554"), None);
    }
}

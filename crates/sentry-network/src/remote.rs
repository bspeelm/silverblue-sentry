//! One configured network's router: the shared ssh `Remote` (`sentry_app::remote`) with a root
//! login (there is no sudo on OpenWrt) and dropbear's way of streaming, plus its config.

use std::sync::Arc;

use super::config::Network;
pub use sentry_app::remote::{Error, Privilege};

/// The key of a network's records and data: `net:<name>` (`networks/<name>/` on disk).
pub fn scope(name: &str) -> String {
    format!("{}{name}", sentry_core::maint::NET)
}

#[derive(Debug, Clone)]
pub struct Router {
    base: sentry_app::remote::Remote,
    pub cfg: Arc<Network>,
    /// The config as it lists things, before what's no longer watched was taken out.
    listed: Arc<Network>,
    /// What sentry stopped watching here (`watch.toml`), applied over `listed`.
    pub watch: Arc<sentry_core::maint::watch::Watch>,
}

/// Name, host, scope, commands: the shared remote's.
impl std::ops::Deref for Router {
    type Target = sentry_app::remote::Remote;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl Router {
    pub fn new(name: &str, cfg: &Network) -> Self {
        // The names given on the Security screen (sentry's own `names.toml`) count as
        // the config's `devices` everywhere a client is shown, judged or hidden.
        let mut cfg = cfg.clone();
        crate::security::names::Names::load(&scope(name)).merge(&mut cfg.devices);
        let watch = sentry_core::maint::watch::load(&scope(name));
        let listed = cfg;
        let cfg = &crate::watch::applied(&listed, &watch);
        Self {
            base: sentry_app::remote::Remote::new(
                name,
                cfg.ssh_target(name),
                &scope(name),
                Privilege::Root,
            )
            // OpenWrt's ssh server; an OpenSSH one streams the same way with this on.
            .dropbear(),
            cfg: Arc::new(cfg.clone()),
            listed: Arc::new(listed),
            watch: Arc::new(watch),
        }
    }

    /// The same router, no longer watching (or watching again) what `watch` says.
    pub fn with_watch(mut self, watch: sentry_core::maint::watch::Watch) -> Self {
        self.cfg = Arc::new(crate::watch::applied(&self.listed, &watch));
        self.watch = Arc::new(watch);
        self
    }

    /// The config's lists as written (what could be watched again).
    pub fn listed(&self) -> &Network {
        &self.listed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_router_is_root_over_dropbear_under_its_networks_scope() {
        let cfg = Network {
            router: crate::config::RouterCfg {
                ssh: Some("myrouter".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let r = Router::new("home", &cfg);
        assert_eq!((r.name.as_str(), r.host), ("home", "myrouter"));
        assert_eq!(r.scope, "net:home");
        assert_eq!(r.privilege, Privilege::Root);
        assert!(r.sh("true").holds_stdin());
        assert_eq!(
            sentry_core::recorder::ring::path(&r.scope),
            sentry_core::paths::data_dir().join("networks/home/metrics/ring.bin")
        );
        // Without `ssh:`, the network's name is what ssh connects to.
        assert_eq!(Router::new("home", &Network::default()).host, "home");
    }
}

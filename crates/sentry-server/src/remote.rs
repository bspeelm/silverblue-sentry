//! One configured server: the shared ssh `Remote` (`sentry_app::remote`, sudo through the
//! config's `sudo:` allowlist) with what only a server has, its config and its inventory.

use std::sync::Arc;

use sentry_core::exec::Cmd;

use super::config::Server;
pub use sentry_app::remote::{Error as SrvError, Privilege, SudoMode, password_refused};

#[derive(Debug, Clone)]
pub struct Remote {
    base: sentry_app::remote::Remote,
    pub cfg: Arc<Server>,
    /// The config as it lists things, before what's no longer watched was taken out.
    listed: Arc<Server>,
    /// What sentry stopped watching here (`watch.toml`), applied over `listed`.
    pub watch: Arc<sentry_core::maint::watch::Watch>,
    /// Answer a refused `sudo -n` from the last inventory (the TUI and the audit; never
    /// workflow conditions, which must see the server as it is now).
    pub inventory: bool,
}

/// Name, host, commands: the shared remote's.
impl std::ops::Deref for Remote {
    type Target = sentry_app::remote::Remote;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl Remote {
    /// A server, with the maintenance items sentry-server tracks for it added to its
    /// config, and what it no longer watches taken out.
    pub fn new(name: &str, cfg: &Server) -> Self {
        let tracked = super::maint::tracked::load(name);
        let listed = super::maint::tracked::merged(cfg, &tracked);
        let watch = sentry_core::maint::watch::load(name);
        Self {
            base: sentry_app::remote::Remote::new(
                name,
                cfg.ssh_target(name),
                name,
                Privilege::sudo(&cfg.sudo),
            ),
            cfg: Arc::new(super::watch::applied(&listed, &watch)),
            listed: Arc::new(listed),
            watch: Arc::new(watch),
            inventory: false,
        }
    }

    /// The same server, no longer watching (or watching again) what `watch` says.
    pub fn with_watch(mut self, watch: sentry_core::maint::watch::Watch) -> Self {
        self.cfg = Arc::new(super::watch::applied(&self.listed, &watch));
        self.watch = Arc::new(watch);
        self
    }

    /// The config's lists as written (what could be watched again).
    pub fn listed(&self) -> &Server {
        &self.listed
    }

    /// Fall back to the last inventory when sudo asks for a password.
    pub fn with_inventory(mut self) -> Self {
        self.inventory = true;
        self
    }

    /// A refused `sudo -n …` command's output from the last inventory, if it has it.
    pub fn from_inventory(&self, cmd: &Cmd) -> Option<String> {
        if !self.inventory {
            return None;
        }
        let line = cmd.quoted_argv();
        let argv = line.strip_prefix("sudo -n ")?;
        super::inventory::lookup(&self.name, argv).map(|c| c.out)
    }

    /// Run and return stdout; a non-zero exit is `Failed` with stderr. A `sudo -n` refused
    /// for want of a password is answered from the inventory when that is on.
    pub fn output(&self, cmd: &Cmd) -> Result<String, SrvError> {
        self.base.output(cmd).or_else(|e| match e {
            SrvError::SudoPassword(_) => self.from_inventory(cmd).ok_or(e),
            e => Err(e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileged_only_through_the_allowlist() {
        let s = Server {
            ssh: Some("admin@myserver.example".into()),
            sudo: vec!["docker ps".into()],
            ..Default::default()
        };
        let r = Remote::new("myserver", &s);
        assert_eq!(r.host, "admin@myserver.example");
        assert_eq!(
            (r.scope.as_str(), r.name.as_str()),
            ("myserver", "myserver")
        );
        let c = r.privileged(&["docker", "ps", "-aq"]).unwrap();
        assert_eq!(c.remote_line(), "env LC_ALL=C sudo -n docker ps -aq");
        assert_eq!(
            r.privileged(&["smartctl", "-H", "/dev/sda"]).unwrap_err(),
            SrvError::NeedsSudo("smartctl".into())
        );
        assert_eq!(sentry_app::remote::sudo_words(&c), "docker ps");
        assert!(password_refused("sudo: a password is required\n"));
        assert_eq!(
            r.sh("cat /proc/loadavg; echo x").remote_line(),
            "env LC_ALL=C sh -c 'cat /proc/loadavg; echo x'"
        );
    }
}

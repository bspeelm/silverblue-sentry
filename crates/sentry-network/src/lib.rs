//! The network target: a home network through its router (OpenWrt, over ssh as root). Nothing
//! is installed on the router; everything here runs from this machine through
//! `sentry_app::remote` (`exec::Cmd::ssh`), and reads only: the one thing asked of the router
//! that writes is `apk update` (its in-memory package index), on the user's `r`. What exists
//! now: the config, the collectors (the 1 Hz probe, the interfaces, the clients, the
//! listeners, the configuration with its secrets tagged, the certificate, the services, the
//! upgradable packages), the audit, the upkeep (firmware against upstream, packages,
//! encrypted config backups and the workflow that makes one), the screens (Dashboard,
//! Clients, Network, Security, Maintenance, Upgrade, History), what flows through the
//! router as far as its own counters and connection table say ([`security`]), the recorder,
//! and the `sentry-network` commands.

pub mod audit;
pub mod backup;
pub mod cfgkind;
pub mod cli;
pub mod clients;
pub mod collect;
pub mod config;
pub mod filter;
pub mod firmware;
pub mod gateway;
pub mod guard;
pub mod init;
#[cfg(test)]
mod live_router;
pub mod maint;
pub mod packages;
pub mod policy;
pub mod rates;
pub mod read;
pub mod recorder;
pub mod redact;
pub mod remote;
pub mod secfacts;
pub mod security;
pub mod tui;
pub mod watch;
pub mod workflow;

#[cfg(test)]
mod tests {
    /// This crate's tests get sentry-core's scratch dirs, never the real config or data.
    #[test]
    fn tests_never_see_the_real_dirs() {
        let tmp = std::env::temp_dir();
        for d in [
            sentry_core::paths::config_dir(),
            sentry_core::paths::data_dir(),
            sentry_core::paths::cache_dir(),
        ] {
            assert!(d.starts_with(&tmp), "{}", d.display());
        }
    }
}

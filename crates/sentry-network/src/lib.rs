//! The network target: a home network through its router (OpenWrt, over ssh as root). Nothing
//! is installed on the router; everything here runs from this machine through
//! `sentry_app::remote` (`exec::Cmd::ssh`), read-only unless a later stage's guarded flow says
//! otherwise. What exists now: the config, the collectors (the 1 Hz probe, the interfaces, the
//! clients, the listeners, the configuration with its secrets tagged, the certificate, the
//! services), the audit, the screens (Dashboard, Clients, Network, Maintenance, History),
//! the recorder, and the `sentry-network` commands.

pub mod audit;
pub mod cli;
pub mod clients;
pub mod collect;
pub mod config;
pub mod init;
pub mod rates;
pub mod recorder;
pub mod redact;
pub mod remote;
pub mod tui;

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

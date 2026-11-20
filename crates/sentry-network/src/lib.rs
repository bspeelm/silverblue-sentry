//! The network target: a home network through its router (OpenWrt, over ssh as root). Nothing
//! is installed on the router; everything here runs from this machine through
//! `sentry_app::remote` (`exec::Cmd::ssh`), read-only unless a later stage's guarded flow says
//! otherwise. What exists now: the config, the 1 Hz probe and the interfaces read, the
//! Dashboard and History, the recorder, and the `sentry-network` commands.

pub mod cli;
pub mod collect;
pub mod config;
pub mod init;
pub mod rates;
pub mod recorder;
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

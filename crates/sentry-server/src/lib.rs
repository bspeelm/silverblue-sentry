//! sentry-server: the same monitor-and-maintain idea for a server, over ssh. Nothing is
//! installed on the server; everything here runs from this machine through `exec::Cmd::ssh`.

pub mod audit;
pub mod cli;
pub mod collect;
pub mod config;
pub mod gateway;
pub mod init;
pub mod inventory;
pub mod maint;
pub mod remote;
pub mod tui;
pub mod workflow;

#[cfg(test)]
mod tests {
    /// This crate's tests get sentry-core's scratch dirs (its `testing` feature, from the
    /// dev-dependency), never the real config, data or cache.
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

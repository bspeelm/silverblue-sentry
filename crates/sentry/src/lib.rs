//! sentry (this machine): the TUI, its collectors, the audit, jobs, checks, workflows' local
//! side, the recorder. What it shares with sentry-server is `sentry_core`, re-exported here
//! under the same names.

pub use sentry_core::{applyplan, baseline, cache, claude, config, exec, finding, fmt, paths};

pub mod audit;
pub mod checks;
pub mod collectors;
pub mod jobs;
pub mod keyfile;
pub mod maint;
pub mod recorder;
pub mod resume;
pub mod status;
pub mod tui;
pub mod workflows;

#[cfg(test)]
mod tests {
    /// This crate's tests get sentry-core's scratch dirs (its `testing` feature, from the
    /// dev-dependency), never the real config, data or cache.
    #[test]
    fn tests_never_see_the_real_dirs() {
        let tmp = std::env::temp_dir();
        for d in [
            crate::paths::config_dir(),
            crate::paths::data_dir(),
            crate::paths::cache_dir(),
        ] {
            assert!(d.starts_with(&tmp), "{}", d.display());
        }
    }
}

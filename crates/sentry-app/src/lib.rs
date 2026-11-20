//! What sentry's targets share beyond the kit (`sentry-core`). For now: [`remote`], the pieces
//! of a host reached over ssh, used by sentry-server and by whatever else is one.

pub mod remote;

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

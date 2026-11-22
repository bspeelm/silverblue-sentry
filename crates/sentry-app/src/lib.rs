//! What sentry's targets share beyond the kit (`sentry-core`): the app itself. [`target`] is
//! what a host is to it, [`app`] the window, [`slot`] one target with everything that belongs
//! to it and the flows written once for all of them, [`shared`] a target's records, [`effect`]
//! what keys and boxes ask for, [`run`] a workflow run as the app sees it; [`remote`] is the
//! pieces of a host reached over ssh, used by sentry-server and by whatever else is one.

pub mod app;
pub mod effect;
pub mod remote;
pub mod run;
pub mod secaudit;
pub mod shared;
pub mod slot;
pub mod system;
pub mod target;

pub use app::{App, Event, Win};
pub use effect::Effect;
pub use slot::{Needs, Slot};
pub use target::Target;

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

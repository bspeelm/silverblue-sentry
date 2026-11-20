//! The maintenance records (`sentry_core::maint`, re-exported) and this machine's own rules:
//! what to maintain next (`local`).

pub use sentry_core::maint::*;

pub mod local;

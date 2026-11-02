//! Workflows: the format and runner are `sentry_core::workflows` (re-exported); this machine's
//! shipped workflows, where they live, how they're linted (`local`), and the CLI (`cli`).

pub use sentry_core::workflows::*;

pub mod cli;
mod local;

pub use local::*;

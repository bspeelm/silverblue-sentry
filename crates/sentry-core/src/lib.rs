//! What sentry (this machine) and sentry-server (a server over ssh) share: running commands
//! (`exec`), where things live (`paths`), the config, the maintenance records (`maint`: log,
//! plans, reviews, tasks, what's put off), workflows (format and runner), Claude Code, the
//! audit finding type, a few parsers, and the TUI kit both apps are built on.

pub mod baseline;
pub mod cache;
pub mod claude;
pub mod collectors;
pub mod config;
pub mod exec;
pub mod finding;
pub mod fmt;
pub mod maint;
pub mod paths;
pub mod tui;
pub mod workflows;

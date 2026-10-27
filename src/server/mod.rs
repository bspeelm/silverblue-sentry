//! sentry-server: the same monitor-and-maintain idea for a server, over ssh. Nothing is
//! installed on the server; everything here runs from this machine through `exec::Cmd::ssh`.

pub mod audit;
pub mod cli;
pub mod collect;
pub mod config;
pub mod gateway;
pub mod init;
pub mod inventory;
pub mod remote;
pub mod tui;
pub mod workflow;

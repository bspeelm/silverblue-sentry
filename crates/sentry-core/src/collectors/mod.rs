//! What collectors share (their context and error), and the parsers both programs use on
//! command output: `disk` (findmnt), `gpu` (nvidia-smi), `journal`, `net` (ss), `procfs`. This machine's collectors are
//! sentry's own.

use std::path::PathBuf;

use jiff::Timestamp;

use crate::config::Config;
use crate::exec::ExecError;

pub mod disk;
pub mod gpu;
pub mod journal;
pub mod net;
pub mod procfs;

pub struct Ctx {
    pub cfg: Config,
    pub home: PathBuf,
    pub now: Timestamp,
}

impl Ctx {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            home: crate::paths::home(),
            now: Timestamp::now(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    #[error("{0} not found")]
    Unavailable(String),
    #[error(transparent)]
    Exec(ExecError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<ExecError> for CollectError {
    fn from(e: ExecError) -> Self {
        match e {
            ExecError::NotFound(b) => CollectError::Unavailable(b),
            e => CollectError::Exec(e),
        }
    }
}

impl From<serde_json::Error> for CollectError {
    fn from(e: serde_json::Error) -> Self {
        CollectError::Other(e.into())
    }
}

impl From<std::io::Error> for CollectError {
    fn from(e: std::io::Error) -> Self {
        CollectError::Other(e.into())
    }
}

pub type CResult<T> = Result<T, CollectError>;

/// Split on runs of whitespace, like `awk`.
pub fn fields(line: &str) -> Vec<&str> {
    line.split_whitespace().collect()
}

#[cfg(test)]
pub(crate) fn fixture(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("fixture {}: {e}", p.display()))
}

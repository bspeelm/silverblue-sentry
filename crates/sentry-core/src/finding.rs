//! An audit finding, as both programs report one (sentry's audit, sentry-server's), and its
//! severity.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sev {
    #[default]
    Low,
    Medium,
    High,
}

impl Sev {
    pub fn as_str(self) -> &'static str {
        match self {
            Sev::High => "high",
            Sev::Medium => "medium",
            Sev::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// Stable across reports; what `baseline.toml findings` stores.
    pub id: String,
    pub severity: Sev,
    pub category: String,
    pub message: String,
    pub evidence: String,
    /// Suppressed by the baseline when the report was taken.
    #[serde(default)]
    pub expected: bool,
    /// Plain-language: what this is, why it's listed, what to do. Empty in old reports.
    #[serde(default)]
    pub what: String,
    #[serde(default)]
    pub why: String,
    #[serde(default)]
    pub fix: String,
    /// Baseline keys of a grouped listener finding (`b` marks them all expected).
    #[serde(default)]
    pub listeners: Vec<String>,
}

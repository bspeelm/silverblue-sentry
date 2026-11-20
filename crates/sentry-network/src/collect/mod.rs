//! What is read from the router: each kind a pure `parse()` (fixture-tested) and a `collect()`
//! (one ssh exec + parse). A command that isn't on the router is `Unavailable`, never a panic.

pub mod ifaces;
pub mod probe;

use sentry_app::remote::{Error, Remote};

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CollectError {
    /// The router has no such command (not an OpenWrt, or a build without it).
    #[error("{0} isn't on the router")]
    Unavailable(String),
    /// ssh couldn't connect (or the router went away).
    #[error("{0}")]
    Unreachable(String),
    #[error("{0}")]
    Failed(String),
    #[error("{0}")]
    Parse(String),
}

impl From<Error> for CollectError {
    fn from(e: Error) -> Self {
        match e {
            Error::Unreachable(s) => Self::Unreachable(s),
            Error::NotFound(s) => Self::Unavailable(s),
            Error::Parse(s) => Self::Parse(s),
            e => Self::Failed(e.to_string()),
        }
    }
}

/// Run a script whose first line gives up with 127 when `bin` isn't there.
pub(crate) fn output_needing(r: &Remote, bin: &str, script: &str) -> Result<String, CollectError> {
    let guarded = format!("command -v {bin} >/dev/null || exit 127; {script}");
    r.output(&r.sh(&guarded)).map_err(|e| match e {
        Error::NotFound(_) => CollectError::Unavailable(bin.to_string()),
        e => e.into(),
    })
}

/// The bodies between lines that start with `@@`, each with its mark's name.
pub fn sections(text: &str) -> Vec<(&str, &str)> {
    let mut out: Vec<(&str, &str)> = Vec::new();
    let mut at = 0;
    let mut open: Option<(&str, usize)> = None;
    for line in text.split_inclusive('\n') {
        if let Some(name) = line.strip_prefix("@@") {
            if let Some((n, from)) = open.take() {
                out.push((n, &text[from..at]));
            }
            open = Some((name.trim(), at + line.len()));
        }
        at += line.len();
    }
    if let Some((n, from)) = open {
        out.push((n, &text[from..]));
    }
    out
}

/// The kinds `sentry-network collect` knows.
pub const KINDS: &[&str] = &["probe", "ifaces"];

/// One kind, read now, as JSON (`sentry-network collect`).
pub fn collect_json(r: &Remote, kind: &str) -> Result<serde_json::Value, CollectError> {
    let json = |v: Result<serde_json::Value, serde_json::Error>| {
        v.map_err(|e| CollectError::Parse(e.to_string()))
    };
    match kind {
        "probe" => json(serde_json::to_value(probe::collect(r)?)),
        "ifaces" => json(serde_json::to_value(ifaces::collect(r)?)),
        other => Err(CollectError::Failed(format!(
            "no collector `{other}` (there are: {})",
            KINDS.join(", ")
        ))),
    }
}

/// A file under the repo's `tests/fixtures/`.
#[cfg(test)]
pub(crate) fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_are_cut_at_marks() {
        let s = sections("noise\n@@a\none\ntwo\n@@b\n@@c x\n{\n\t\"k\": \"@@not a mark\"\n}\n");
        assert_eq!(
            s,
            [
                ("a", "one\ntwo\n"),
                ("b", ""),
                ("c x", "{\n\t\"k\": \"@@not a mark\"\n}\n")
            ]
        );
        assert!(sections("").is_empty());
    }

    #[test]
    fn a_missing_command_is_unavailable() {
        assert_eq!(
            CollectError::from(Error::NotFound("ubus on myrouter".into())),
            CollectError::Unavailable("ubus on myrouter".into())
        );
        assert_eq!(
            CollectError::Unavailable("ubus".into()).to_string(),
            "ubus isn't on the router"
        );
        let r = Remote::new(
            "home",
            "myrouter",
            "net:home",
            sentry_app::remote::Privilege::Root,
        );
        let e = collect_json(&r, "nope").unwrap_err();
        assert!(e.to_string().contains("probe, ifaces"), "{e}");
    }
}

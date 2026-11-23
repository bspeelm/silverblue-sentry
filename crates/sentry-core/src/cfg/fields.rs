//! What each setting is, beside the type it describes: a static table per config file (path
//! pattern, label, help, kind, whether the window's forms cover it). `sentry config explain`
//! prints it; the forms and the agent's proposals will be checked against it. Each config
//! module's tests check that every field its type serializes has an entry
//! ([`uncovered`], [`unused`]), so a table can't drift from its type.

use super::value::{Seg, Value};

/// What kind of value a setting takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    Bool,
    Number,
    /// `10s`, `5m`, `24h`, `30d`.
    Duration,
    /// One of these words.
    Choice(&'static [&'static str]),
    /// A list of words.
    List,
    /// A list of records, each with fields of its own.
    Records,
    /// Named entries (a map).
    Map,
    /// A group of settings.
    Section,
}

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Kind::Text => "text",
            Kind::Bool => "yes/no",
            Kind::Number => "number",
            Kind::Duration => "duration",
            Kind::Choice(_) => "one of",
            Kind::List => "list",
            Kind::Records => "list of records",
            Kind::Map => "named entries",
            Kind::Section => "section",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Field {
    /// `servers.*.timers[].max_age`: `*` is any name (a map's key), `[]` any list element.
    pub path: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub kind: Kind,
    /// The window's forms cover it (the rest: the file in `$EDITOR`).
    pub essential: bool,
}

/// One step of a pattern.
#[derive(Debug, PartialEq)]
enum Pat<'a> {
    Key(&'a str),
    AnyKey,
    AnyIndex,
}

fn pattern(p: &str) -> Vec<Pat<'_>> {
    let mut out = Vec::new();
    for part in p.split('.') {
        let (key, mut rest) = part.split_at(part.find('[').unwrap_or(part.len()));
        out.push(if key == "*" {
            Pat::AnyKey
        } else {
            Pat::Key(key)
        });
        while let Some(r) = rest.strip_prefix("[]") {
            out.push(Pat::AnyIndex);
            rest = r;
        }
    }
    out
}

fn fits(pat: &[Pat], path: &[Seg]) -> bool {
    pat.len() == path.len()
        && pat.iter().zip(path).all(|(p, s)| match (p, s) {
            (Pat::Key(k), Seg::Key(x)) => k == x,
            (Pat::AnyKey, Seg::Key(_)) => true,
            (Pat::AnyIndex, Seg::Index(_)) => true,
            _ => false,
        })
}

impl Field {
    /// This setting is at `path` exactly.
    pub fn is(&self, path: &[Seg]) -> bool {
        fits(&pattern(self.path), path)
    }

    /// `path` is this setting or a value in it: an element of a list of words, an entry of
    /// named entries.
    pub fn covers(&self, path: &[Seg]) -> bool {
        let pat = pattern(self.path);
        match (self.kind, path.split_last()) {
            _ if fits(&pat, path) => true,
            (Kind::List, Some((Seg::Index(_), up))) => fits(&pat, up),
            (Kind::Map, Some((Seg::Key(_), up))) => fits(&pat, up),
            _ => false,
        }
    }

    /// The setting's pattern leads to `path` (a section or a record list over it).
    fn above(&self, path: &[Seg]) -> bool {
        let pat = pattern(self.path);
        pat.len() < path.len() && fits(&pat, &path[..pat.len()])
    }
}

/// The setting at a path (`servers.myserver.timers[2]`; a literal `<name>` or `*` for a name
/// and `[]` for an index are read too): the one that is it, else the one it is a value in.
pub fn find<'a>(fields: &'a [Field], path: &str) -> Option<&'a Field> {
    let segs = loose(path)?;
    fields
        .iter()
        .find(|f| f.is(&segs))
        .or_else(|| fields.iter().find(|f| f.covers(&segs)))
}

/// A path as someone types it: `[]` is index 0, and a key is whatever stands between dots.
fn loose(path: &str) -> Option<Vec<Seg>> {
    if let Ok(segs) = super::value::parse_path(path) {
        return Some(segs);
    }
    let mut out = Vec::new();
    for part in path.split('.') {
        let (key, mut rest) = part.split_at(part.find('[').unwrap_or(part.len()));
        if key.is_empty() {
            return None;
        }
        out.push(Seg::Key(key.to_string()));
        while let Some(open) = rest.strip_prefix('[') {
            let close = open.find(']')?;
            out.push(Seg::Index(open[..close].parse().unwrap_or(0)));
            rest = &open[close + 1..];
        }
    }
    Some(out)
}

/// The leaves of `full` (a value with every field set) that no field covers.
pub fn uncovered(fields: &[Field], full: &Value) -> Vec<String> {
    full.leaves()
        .into_iter()
        .filter(|p| !fields.iter().any(|f| f.covers(p)))
        .map(|p| super::value::path_string(&p))
        .collect()
}

/// The fields that no leaf of `full` is, is in, or is under: stale entries.
pub fn unused<'a>(fields: &'a [Field], full: &Value) -> Vec<&'a str> {
    let leaves = full.leaves();
    fields
        .iter()
        .filter(|f| !leaves.iter().any(|p| f.covers(p) || f.above(p)))
        .map(|f| f.path)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &[Field] = &[
        Field {
            path: "servers.*.timers",
            label: "Timers",
            help: "",
            kind: Kind::Records,
            essential: true,
        },
        Field {
            path: "servers.*.timers[].max_age",
            label: "Max age",
            help: "",
            kind: Kind::Duration,
            essential: true,
        },
        Field {
            path: "servers.*.sudo",
            label: "sudo",
            help: "",
            kind: Kind::List,
            essential: true,
        },
        Field {
            path: "keys",
            label: "Keys",
            help: "",
            kind: Kind::Map,
            essential: true,
        },
    ];

    #[test]
    fn a_path_finds_its_setting() {
        let f = |p: &str| find(T, p).map(|f| f.label);
        assert_eq!(f("servers.myserver.timers"), Some("Timers"));
        assert_eq!(
            f("servers.\"my.server\".timers[2].max_age"),
            Some("Max age")
        );
        assert_eq!(f("servers.<name>.timers[].max_age"), Some("Max age"));
        assert_eq!(f("servers.*.sudo[3]"), Some("sudo"));
        assert_eq!(f("keys.\"screen.history\""), Some("Keys"));
        assert_eq!(f("servers.myserver.nope"), None);
        assert_eq!(f("servers.myserver.timers[0].unit"), None);
    }
}

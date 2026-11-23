//! A config value as a tree: what a change holds (`from`, `to`), what changes are made on (by
//! path), and what a file is rendered from. Ordered (a struct's fields come out in the order
//! the type declares them, a map's entries as the map has them), with a null (an `Option`
//! that is `None`), and nothing a config file can't hold. A typed value goes to it and comes
//! back through JSON, so the type's own `Serialize`/`Deserialize` decide everything: a
//! change the type wouldn't accept fails as the type says.

use std::fmt;

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    /// A struct's fields or a map's entries, in order.
    Map(Vec<(String, Value)>),
}

impl Value {
    /// The tree of a typed value.
    pub fn of<T: Serialize + ?Sized>(v: &T) -> Result<Self, String> {
        let json = serde_json::to_string(v).map_err(|e| e.to_string())?;
        serde_json::from_str(&json).map_err(|e| e.to_string())
    }

    /// The typed value this tree is, as the type reads it.
    pub fn to<T: DeserializeOwned>(&self) -> Result<T, String> {
        let json = serde_json::to_string(self).map_err(|e| e.to_string())?;
        serde_json::from_str(&json).map_err(|e| e.to_string())
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// What is at `path`, if anything.
    pub fn at(&self, path: &[Seg]) -> Option<&Value> {
        path.iter().try_fold(self, |v, s| match (s, v) {
            (Seg::Key(k), Value::Map(m)) => m.iter().find(|(x, _)| x == k).map(|(_, v)| v),
            (Seg::Index(i), Value::List(l)) => l.get(*i),
            _ => None,
        })
    }

    pub fn at_mut(&mut self, path: &[Seg]) -> Option<&mut Value> {
        path.iter().try_fold(self, |v, s| match (s, v) {
            (Seg::Key(k), Value::Map(m)) => m.iter_mut().find(|(x, _)| x == k).map(|(_, v)| v),
            (Seg::Index(i), Value::List(l)) => l.get_mut(*i),
            _ => None,
        })
    }

    /// Put `to` at `path` (None: take what is there away), whatever was there: a map's entry
    /// is made when it isn't there, a list's element must be (or be the next one). Fails,
    /// changing nothing, when the path leads nowhere.
    pub fn set(&mut self, path: &[Seg], to: Option<Value>) -> Result<(), String> {
        let Some((last, parent)) = path.split_last() else {
            return match to {
                Some(v) => {
                    *self = v;
                    Ok(())
                }
                None => Err("nothing to take away".into()),
            };
        };
        let nowhere = || format!("{}: there's no such setting", path_string(path));
        match (last, self.at_mut(parent).ok_or_else(nowhere)?) {
            (Seg::Key(k), Value::Map(m)) => match (m.iter().position(|(x, _)| x == k), to) {
                (Some(i), Some(v)) => m[i].1 = v,
                (Some(i), None) => {
                    m.remove(i);
                }
                (None, Some(v)) => m.push((k.clone(), v)),
                (None, None) => {}
            },
            (Seg::Index(i), Value::List(l)) => match to {
                Some(v) if *i < l.len() => l[*i] = v,
                Some(v) if *i == l.len() => l.push(v),
                None if *i < l.len() => {
                    l.remove(*i);
                }
                _ => return Err(nowhere()),
            },
            _ => return Err(nowhere()),
        }
        Ok(())
    }

    /// Every leaf's path: a scalar, a null, an empty list or map.
    pub fn leaves(&self) -> Vec<Vec<Seg>> {
        fn walk(v: &Value, at: &mut Vec<Seg>, out: &mut Vec<Vec<Seg>>) {
            match v {
                Value::Map(m) if !m.is_empty() => {
                    for (k, v) in m {
                        at.push(Seg::Key(k.clone()));
                        walk(v, at, out);
                        at.pop();
                    }
                }
                Value::List(l) if !l.is_empty() => {
                    for (i, v) in l.iter().enumerate() {
                        at.push(Seg::Index(i));
                        walk(v, at, out);
                        at.pop();
                    }
                }
                _ => out.push(at.clone()),
            }
        }
        let mut out = Vec::new();
        walk(self, &mut Vec::new(), &mut out);
        out
    }

    /// The same tree without nulls in maps (TOML has no null: a field left out is `None`).
    pub(crate) fn without_nulls(&self) -> Value {
        match self {
            Value::Map(m) => Value::Map(
                m.iter()
                    .filter(|(_, v)| *v != Value::Null)
                    .map(|(k, v)| (k.clone(), v.without_nulls()))
                    .collect(),
            ),
            Value::List(l) => Value::List(l.iter().map(Value::without_nulls).collect()),
            v => v.clone(),
        }
    }
}

/// Shown inline, as JSON writes it (`"30d"`, `[1, 2]`, `{"unit": "x.timer"}`).
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Str(s) => f.write_str(&serde_json::to_string(s).map_err(|_| fmt::Error)?),
            Value::List(l) => {
                f.write_str("[")?;
                for (i, v) in l.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("]")
            }
            Value::Map(m) => {
                f.write_str("{")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{k}: {v}")?;
                }
                f.write_str("}")
            }
            Value::Null => f.write_str("null"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(n) => write!(f, "{n}"),
            Value::Float(x) => write!(f, "{x:?}"),
        }
    }
}

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self {
            Value::Null => s.serialize_none(),
            Value::Bool(b) => s.serialize_bool(*b),
            Value::Int(n) => s.serialize_i64(*n),
            Value::Float(x) => s.serialize_f64(*x),
            Value::Str(x) => s.serialize_str(x),
            Value::List(l) => {
                let mut seq = s.serialize_seq(Some(l.len()))?;
                for v in l {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }
            Value::Map(m) => {
                let mut map = s.serialize_map(Some(m.len()))?;
                for (k, v) in m {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Value;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a config value")
            }
            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
                Value::deserialize(d)
            }
            fn visit_bool<E>(self, b: bool) -> Result<Value, E> {
                Ok(Value::Bool(b))
            }
            fn visit_i64<E>(self, n: i64) -> Result<Value, E> {
                Ok(Value::Int(n))
            }
            fn visit_u64<E: de::Error>(self, n: u64) -> Result<Value, E> {
                i64::try_from(n)
                    .map(Value::Int)
                    .map_err(|_| E::custom(format!("{n} is too large for a config file")))
            }
            fn visit_f64<E>(self, x: f64) -> Result<Value, E> {
                Ok(Value::Float(x))
            }
            fn visit_str<E>(self, s: &str) -> Result<Value, E> {
                Ok(Value::Str(s.to_string()))
            }
            fn visit_string<E>(self, s: String) -> Result<Value, E> {
                Ok(Value::Str(s))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
                let mut l = Vec::new();
                while let Some(v) = a.next_element()? {
                    l.push(v);
                }
                Ok(Value::List(l))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
                let mut m = Vec::new();
                while let Some((k, v)) = a.next_entry::<String, Value>()? {
                    m.push((k, v));
                }
                Ok(Value::Map(m))
            }
        }
        d.deserialize_any(V)
    }
}

/// One step of a path: a struct field or a map's key, or a list's index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg {
    Key(String),
    Index(usize),
}

/// A key is written bare when it is a plain word (letters, digits, `_`, `-`), else quoted as
/// JSON quotes a string: `servers."my.server".timers[2].max_age`.
pub fn bare(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// A path as it is written.
pub fn path_string(path: &[Seg]) -> String {
    let mut s = String::new();
    for seg in path {
        match seg {
            Seg::Key(k) => {
                if !s.is_empty() {
                    s.push('.');
                }
                if bare(k) {
                    s.push_str(k);
                } else {
                    s.push_str(&serde_json::to_string(k).unwrap_or_default());
                }
            }
            Seg::Index(i) => s.push_str(&format!("[{i}]")),
        }
    }
    s
}

/// `servers."my.server".timers[2]` as its steps.
pub fn parse_path(text: &str) -> Result<Vec<Seg>, String> {
    let bad = |why: &str| format!("`{text}`: {why}");
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut want_key = true;
    while i < b.len() {
        match b[i] {
            b'[' => {
                let end = text[i..]
                    .find(']')
                    .ok_or_else(|| bad("a `[` without its `]`"))?
                    + i;
                let n: usize = text[i + 1..end]
                    .parse()
                    .map_err(|_| bad("an index is a number"))?;
                out.push(Seg::Index(n));
                i = end + 1;
                want_key = false;
            }
            b'.' if !want_key && i + 1 < b.len() => {
                i += 1;
                want_key = true;
            }
            b'"' if want_key => {
                // A quoted key ends at the first `"` not escaped.
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                if j >= b.len() {
                    return Err(bad("a quoted key isn't closed"));
                }
                let key: String =
                    serde_json::from_str(&text[i..=j]).map_err(|_| bad("a quoted key"))?;
                out.push(Seg::Key(key));
                i = j + 1;
                want_key = false;
            }
            _ if want_key => {
                let end = text[i..].find(['.', '[']).map_or(text.len(), |e| e + i);
                let key = &text[i..end];
                if !bare(key) {
                    return Err(bad(&format!("`{key}` isn't a plain name (quote it)")));
                }
                out.push(Seg::Key(key.to_string()));
                i = end;
                want_key = false;
            }
            _ => return Err(bad("a `.` or `[` was expected")),
        }
    }
    if want_key && !out.is_empty() {
        return Err(bad("it ends with a `.`"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_written_and_read_back() {
        for p in [
            "ui.dashboard_hz",
            "servers.myserver.timers[2].max_age",
            "servers.\"my.server\".sudo[0]",
            "keys.\"screen.history\"",
            "networks.home.expect.zones.wan[1]",
            "servers.\"a \\\"b\\\"\".ssh",
        ] {
            let segs = parse_path(p).unwrap();
            assert_eq!(path_string(&segs), p, "{segs:?}");
        }
        assert_eq!(
            parse_path("servers.\"my.server\".timers[2]").unwrap(),
            [
                Seg::Key("servers".into()),
                Seg::Key("my.server".into()),
                Seg::Key("timers".into()),
                Seg::Index(2)
            ]
        );
        for bad in ["a..b", "a.", "a[x]", "a[1", "my server.x", "\"open"] {
            assert!(parse_path(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_path("").unwrap(), []);
    }

    #[test]
    fn a_tree_keeps_the_order_and_comes_back_typed() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct S {
            z: u32,
            a: Option<String>,
            m: std::collections::BTreeMap<String, f32>,
        }
        let s = S {
            z: 3,
            a: None,
            m: [("b".to_string(), 0.1), ("a".to_string(), 2.0)].into(),
        };
        let v = Value::of(&s).unwrap();
        let keys: Vec<&str> = match &v {
            Value::Map(m) => m.iter().map(|(k, _)| k.as_str()).collect(),
            _ => vec![],
        };
        assert_eq!(keys, ["z", "a", "m"]);
        assert_eq!(v.get("a"), Some(&Value::Null));
        assert_eq!(v.to::<S>().unwrap(), s);
        assert_eq!(v.to_string(), "{z: 3, a: null, m: {a: 2.0, b: 0.1}}");
        assert_eq!(
            v.leaves()
                .iter()
                .map(|p| path_string(p))
                .collect::<Vec<_>>(),
            ["z", "a", "m.a", "m.b"]
        );
    }

    #[test]
    fn a_value_is_put_at_a_path_whatever_was_there() {
        let v = |json: &str| -> Value { serde_json::from_str(json).unwrap() };
        let mut t = v(r#"{"a": {"l": ["x", "y"]}, "n": 1}"#);
        let p = |s: &str| parse_path(s).unwrap();
        t.set(&p("n"), Some(v("2"))).unwrap();
        t.set(&p("a.l[1]"), Some(v("\"z\""))).unwrap();
        t.set(&p("a.l[2]"), Some(v("\"w\""))).unwrap();
        t.set(&p("a.new"), Some(v("true"))).unwrap();
        assert_eq!(
            t,
            v(r#"{"a": {"l": ["x", "z", "w"], "new": true}, "n": 2}"#)
        );
        // Taken away: a map's entry, a list's element.
        t.set(&p("a.new"), None).unwrap();
        t.set(&p("a.l[0]"), None).unwrap();
        t.set(&p("gone"), None).unwrap();
        assert_eq!(t, v(r#"{"a": {"l": ["z", "w"]}, "n": 2}"#));
        // A path that leads nowhere changes nothing.
        let before = t.clone();
        assert!(t.set(&p("a.l[5]"), Some(v("1"))).is_err());
        assert!(t.set(&p("nope.x"), Some(v("1"))).is_err());
        assert!(t.set(&p("n.x"), Some(v("1"))).is_err());
        assert_eq!(t, before);
    }
}

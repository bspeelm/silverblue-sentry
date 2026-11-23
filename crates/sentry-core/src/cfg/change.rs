//! A change to a config file, by path: what was there (`from`), what is to be there (`to`).
//! `None` on one side is an entry or list element added or taken away. Changes are made on
//! the value tree and read back through the type, so the type validates them; one whose
//! `from` isn't what is there fails, which is how a change made against an older file shows
//! as a conflict instead of overwriting what someone else wrote.

use super::value::{Seg, Value, parse_path, path_string};
use super::{ConfigFile, FileId};

/// Who proposed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum By {
    You,
    Agent,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    pub file: FileId,
    /// `servers.myserver.timers[2].max_age`, `ui.dashboard_hz`.
    pub path: String,
    pub from: Option<Value>,
    pub to: Option<Value>,
    pub by: By,
    /// Ticked: it goes into the next save.
    pub on: bool,
}

/// What changed from `before` to `after`, each as a change that [`apply`] makes, in the order
/// they are applied (a list's indices are where the element is when its change comes).
pub fn diff<T: ConfigFile>(before: &T, after: &T) -> Result<Vec<Change>, String> {
    let (a, b) = (Value::of(before)?, Value::of(after)?);
    let mut out = Vec::new();
    diff_trees(&mut Vec::new(), &a, &b, &mut out);
    Ok(out
        .into_iter()
        .map(|(path, from, to)| Change {
            file: T::FILE,
            path,
            from,
            to,
            by: By::You,
            on: true,
        })
        .collect())
}

type Raw = (String, Option<Value>, Option<Value>);

pub(crate) fn diff_trees(at: &mut Vec<Seg>, a: &Value, b: &Value, out: &mut Vec<Raw>) {
    match (a, b) {
        _ if a == b => {}
        (Value::Map(x), Value::Map(y)) => {
            for (k, va) in x {
                at.push(Seg::Key(k.clone()));
                match b.get(k) {
                    Some(vb) => diff_trees(at, va, vb, out),
                    None => out.push((path_string(at), Some(va.clone()), None)),
                }
                at.pop();
            }
            for (k, vb) in y.iter().filter(|(k, _)| a.get(k).is_none()) {
                at.push(Seg::Key(k.clone()));
                out.push((path_string(at), None, Some(vb.clone())));
                at.pop();
            }
        }
        (Value::List(x), Value::List(y)) => diff_lists(at, x, y, out),
        _ => out.push((path_string(at), Some(a.clone()), Some(b.clone()))),
    }
}

/// Elements kept are matched as the longest common subsequence; between two kept ones, the
/// first of those taken away and of those added pair up as one element changed (so a
/// record's field changed is that field's change), the rest are taken away, then added.
fn diff_lists(at: &mut Vec<Seg>, x: &[Value], y: &[Value], out: &mut Vec<Raw>) {
    let (n, m) = (x.len(), y.len());
    // lcs[i][j]: the longest common subsequence of x[i..] and y[j..].
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if x[i] == y[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j, mut k) = (0, 0, 0);
    let mut gone: Vec<usize> = Vec::new();
    let mut new: Vec<usize> = Vec::new();
    let mut flush = |gone: &mut Vec<usize>, new: &mut Vec<usize>, k: &mut usize| {
        let pairs = gone.len().min(new.len());
        for p in 0..pairs {
            at.push(Seg::Index(*k));
            diff_trees(at, &x[gone[p]], &y[new[p]], out);
            at.pop();
            *k += 1;
        }
        for &g in &gone[pairs..] {
            at.push(Seg::Index(*k));
            out.push((path_string(at), Some(x[g].clone()), None));
            at.pop();
        }
        for &a in &new[pairs..] {
            at.push(Seg::Index(*k));
            out.push((path_string(at), None, Some(y[a].clone())));
            at.pop();
            *k += 1;
        }
        gone.clear();
        new.clear();
    };
    while i < n || j < m {
        if i < n && j < m && x[i] == y[j] {
            flush(&mut gone, &mut new, &mut k);
            i += 1;
            j += 1;
            k += 1;
        } else if j >= m || (i < n && lcs[i + 1][j] >= lcs[i][j + 1]) {
            gone.push(i);
            i += 1;
        } else {
            new.push(j);
            j += 1;
        }
    }
    flush(&mut gone, &mut new, &mut k);
}

/// Make one change to a typed value. Fails, changing nothing, when the change is for another
/// file, its path leads nowhere, what is there isn't its `from`, or the type refuses the
/// result.
pub fn apply<T: ConfigFile>(doc: &mut T, c: &Change) -> Result<(), String> {
    if c.file != T::FILE {
        return Err(format!(
            "{}: a change for {}",
            T::FILE.name(),
            c.file.name()
        ));
    }
    let mut tree = Value::of(doc)?;
    apply_tree(&mut tree, &c.path, c.from.as_ref(), c.to.as_ref())?;
    *doc = tree.to().map_err(|e| format!("{}: {e}", c.path))?;
    Ok(())
}

pub(crate) fn apply_tree(
    tree: &mut Value,
    path: &str,
    from: Option<&Value>,
    to: Option<&Value>,
) -> Result<(), String> {
    let segs = parse_path(path)?;
    let Some((last, parent)) = segs.split_last() else {
        return Err("a change names no setting".into());
    };
    let none = || "nothing".to_string();
    let show = |v: Option<&Value>| v.map_or_else(none, Value::to_string);
    let stale = |now: Option<&Value>| {
        format!(
            "{path} is {} now, not {} as the change expected",
            show(now),
            show(from)
        )
    };
    let Some(parent) = tree.at_mut(parent) else {
        return Err(format!("{path}: there's no such setting"));
    };
    match (last, parent) {
        (Seg::Key(k), Value::Map(m)) => {
            let at = m.iter().position(|(x, _)| x == k);
            let now = at.map(|i| &m[i].1);
            if now != from {
                return Err(stale(now));
            }
            match (at, to) {
                (Some(i), Some(v)) => m[i].1 = v.clone(),
                (Some(i), None) => {
                    m.remove(i);
                }
                (None, Some(v)) => m.push((k.clone(), v.clone())),
                (None, None) => {}
            }
        }
        (Seg::Index(i), Value::List(l)) => match from {
            // Added: it goes in at that place.
            None if *i <= l.len() => {
                if let Some(v) = to {
                    l.insert(*i, v.clone());
                }
            }
            None => return Err(format!("{path}: the list has {} entries", l.len())),
            Some(f) => {
                if l.get(*i) != Some(f) {
                    return Err(stale(l.get(*i)));
                }
                match to {
                    Some(v) => l[*i] = v.clone(),
                    None => {
                        l.remove(*i);
                    }
                }
            }
        },
        _ => return Err(format!("{path}: there's no such setting")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(json: &str) -> Value {
        serde_json::from_str(json).unwrap()
    }

    fn roundtrip(a: &str, b: &str) -> Vec<Raw> {
        let (a, b) = (v(a), v(b));
        let mut out = Vec::new();
        diff_trees(&mut Vec::new(), &a, &b, &mut out);
        let mut t = a.clone();
        for (p, from, to) in &out {
            apply_tree(&mut t, p, from.as_ref(), to.as_ref()).unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(t, b, "{out:?}");
        out
    }

    #[test]
    fn every_diff_applies_back_to_the_other_side() {
        let a = r#"{"x": 1, "l": ["a", "b", "c", "d"], "r": [{"u": "t1", "m": "1d"}, {"u": "t2", "m": "2d"}], "map": {"k": 1}}"#;
        for b in [
            r#"{"x": 2, "l": ["a", "c", "d", "e"], "r": [{"u": "t1", "m": "1d"}, {"u": "t2", "m": "3d"}], "map": {"k": 1, "n": 2}}"#,
            r#"{"x": 1, "l": [], "r": [], "map": {}}"#,
            r#"{"x": 1, "l": ["z", "a", "y", "b", "c", "d", "w"], "r": [{"u": "t0", "m": "1d"}, {"u": "t1", "m": "1d"}, {"u": "t2", "m": "2d"}], "map": {"j": 0}}"#,
            r#"{"x": null, "l": ["d", "c", "b", "a"], "r": [{"u": "t2", "m": "2d"}], "map": {"k": [1]}}"#,
            a,
        ] {
            roundtrip(a, b);
            roundtrip(b, a);
        }
        // One field of one record: that field's path.
        let out = roundtrip(
            r#"{"r": [{"u": "t1", "m": "1d"}, {"u": "t2", "m": "2d"}]}"#,
            r#"{"r": [{"u": "t1", "m": "1d"}, {"u": "t2", "m": "3d"}]}"#,
        );
        assert_eq!(
            out,
            [("r[1].m".to_string(), Some(v("\"2d\"")), Some(v("\"3d\"")))]
        );
        // One element taken away: that element.
        let out = roundtrip(r#"{"l": ["a", "b", "c"]}"#, r#"{"l": ["a", "c"]}"#);
        assert_eq!(out, [("l[1]".to_string(), Some(v("\"b\"")), None)]);
    }

    #[test]
    fn a_stale_from_is_an_error_and_changes_nothing() {
        let mut t = v(r#"{"a": {"b": 1}, "l": ["x"]}"#);
        let before = t.clone();
        let e = apply_tree(&mut t, "a.b", Some(&v("2")), Some(&v("3"))).unwrap_err();
        assert!(e.contains("a.b is 1 now, not 2"), "{e}");
        let e = apply_tree(&mut t, "a.c", Some(&v("2")), None).unwrap_err();
        assert!(e.contains("is nothing now"), "{e}");
        let e = apply_tree(&mut t, "a.b", None, Some(&v("3"))).unwrap_err();
        assert!(e.contains("not nothing"), "{e}");
        assert!(apply_tree(&mut t, "l[0]", Some(&v("\"y\"")), None).is_err());
        assert!(apply_tree(&mut t, "l[5]", None, Some(&v("1"))).is_err());
        assert!(apply_tree(&mut t, "nope.x", None, Some(&v("1"))).is_err());
        assert_eq!(t, before);
    }
}

//! Ordering versions as people write them: `4.7.1`, `v0.41.7`, `3.2.4-alpine`,
//! `5:24.3.1-1~deb12`, date tags like `2025.3.4-a1b2c3d4e`.

use std::cmp::Ordering;

#[derive(Debug, PartialEq, Eq)]
enum Part<'a> {
    Num(u64),
    Text(&'a str),
}

fn parts(v: &str) -> Vec<Part<'_>> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let mut out = Vec::new();
    let mut start = 0;
    let b = v.as_bytes();
    while start < b.len() {
        let digit = b[start].is_ascii_digit();
        let mut end = start;
        while end < b.len()
            && b[end].is_ascii_digit() == digit
            && (digit || b[end].is_ascii_alphabetic())
        {
            end += 1;
        }
        if end == start {
            // A separator (`.`, `-`, `:`, `~`, `+`): skip it.
            start += 1;
            continue;
        }
        let s = &v[start..end];
        out.push(if digit {
            Part::Num(s.parse().unwrap_or(u64::MAX))
        } else {
            Part::Text(s)
        });
        start = end;
    }
    out
}

/// Compare two versions part by part: numbers by value, words alphabetically; a version that
/// runs out first is older (`1.2` < `1.2.1`).
pub fn cmp(a: &str, b: &str) -> Ordering {
    let (pa, pb) = (parts(a), parts(b));
    for (x, y) in pa.iter().zip(&pb) {
        let o = match (x, y) {
            (Part::Num(x), Part::Num(y)) => x.cmp(y),
            (Part::Text(x), Part::Text(y)) => x.cmp(y),
            // A number sorts after a word (`1.0-rc` < `1.0.1`).
            (Part::Num(_), Part::Text(_)) => Ordering::Greater,
            (Part::Text(_), Part::Num(_)) => Ordering::Less,
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    pa.len().cmp(&pb.len())
}

/// A release tag rather than a channel or a build: starts with a digit (after an optional
/// `v`) and isn't a pre-release.
pub fn is_release(tag: &str) -> bool {
    let t = tag.strip_prefix('v').unwrap_or(tag);
    let lower = t.to_ascii_lowercase();
    t.starts_with(|c: char| c.is_ascii_digit())
        && !["rc", "beta", "alpha", "dev", "nightly", "preview", "pre"]
            .iter()
            .any(|w| {
                lower
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .any(|p| p.starts_with(w) && p[w.len()..].chars().all(|c| c.is_ascii_digit()))
            })
}

/// The first version-looking word in a command's output (`app 0.9.3` → `0.9.3`).
pub fn find(text: &str) -> Option<String> {
    text.split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')')
        .map(|w| w.trim_matches(|c: char| !c.is_ascii_alphanumeric()))
        .find(|w| {
            let w = w.strip_prefix('v').unwrap_or(w);
            w.starts_with(|c: char| c.is_ascii_digit()) && w.contains('.')
        })
        .map(str::to_string)
}

/// The tag of an image reference (`ghcr.io/org/app:1.2` → `1.2`; a registry port isn't one).
pub fn image_tag(image: &str) -> Option<&str> {
    let name = image.split('@').next().unwrap_or(image);
    let last = name.rsplit('/').next().unwrap_or(name);
    last.split_once(':').map(|(_, t)| t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_versions_as_written() {
        let lt = |a, b| assert_eq!(cmp(a, b), Ordering::Less, "{a} < {b}");
        lt("0.41.7", "0.42.0");
        lt("v0.9.0", "v0.10.0");
        lt("1.2", "1.2.1");
        lt("3.2.4-alpine", "3.2.10-alpine");
        lt("4.7.0-1", "4.7.1-1");
        lt("5:24.3.1-1~deb12", "5:24.4.0-1~deb12");
        lt("2025.3.4-a1b2c3d4e", "2025.11.2-0f9e8d7c6");
        lt("1.0-rc1", "1.0.1");
        assert_eq!(cmp("v1.2.3", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn releases_and_versions_in_text() {
        assert!(is_release("0.42.0") && is_release("v5.12.3") && is_release("3.2.4-alpine"));
        assert!(!is_release("latest") && !is_release("1.0.0-rc2") && !is_release("2.0-beta"));
        assert!(!is_release("main") && !is_release("0.5.0-dev"));
        assert_eq!(find("app 0.9.3 (abc)").as_deref(), Some("0.9.3"));
        assert_eq!(find("{\"version\": \"2.6.1\"}").as_deref(), Some("2.6.1"));
        assert_eq!(image_tag("example/web:1.2.3"), Some("1.2.3"));
        assert_eq!(image_tag("registry:5000/web"), None);
        assert_eq!(image_tag("ghcr.io/org/app:v0.7.4"), Some("v0.7.4"));
    }
}

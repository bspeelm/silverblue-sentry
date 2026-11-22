//! The filters of a read line (`grep`, `head`, `tail`, `sort`, `uniq`, `wc`, `cut`), done
//! here, on this machine, on what the router printed *after* it was scrubbed. Never on the
//! router: a pattern matched there is matched against the unscrubbed text, and a count or
//! an exit status is then an oracle for everything the scrubbing hides (`grep -c
//! "key='a"`, one character at a time). Run after the scrubbing, any filter is harmless,
//! cutting lines up included.

use regex::Regex;

/// Which lines `head` or `tail` keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Take {
    /// The first (head) or last (tail) n.
    N(usize),
    /// head `-n -N`: all but the last n. tail `-n +N`: from line n on.
    Rest(usize),
}

/// 1-based, inclusive ranges (`cut -f 1,3-5`); `usize::MAX`: to the end.
pub type Ranges = Vec<(usize, usize)>;

#[derive(Debug, Clone)]
pub enum Filter {
    Grep {
        re: Regex,
        invert: bool,
        count: bool,
        number: bool,
        quiet: bool,
        max: Option<usize>,
        before: usize,
        after: usize,
    },
    Head(Take),
    Tail(Take),
    Sort {
        unique: bool,
        reverse: bool,
        numeric: bool,
        fold: bool,
        key: Option<usize>,
        sep: Option<char>,
    },
    Uniq {
        count: bool,
        dups: bool,
        uniques: bool,
        fold: bool,
    },
    Wc {
        lines: bool,
        words: bool,
        bytes: bool,
        /// The file it was pointed at: printed after the counts, as wc does.
        name: Option<String>,
    },
    Cut {
        delim: char,
        fields: Option<Ranges>,
        chars: Option<Ranges>,
        only_delimited: bool,
    },
}

/// `1,3-5,7-` as ranges. None: not a list.
pub fn ranges(list: &str) -> Option<Ranges> {
    let mut out = Vec::new();
    for part in list.split(',') {
        let n = |s: &str| s.parse::<usize>().ok().filter(|n| *n > 0);
        out.push(match part.split_once('-') {
            None => {
                let a = n(part)?;
                (a, a)
            }
            Some(("", b)) => (1, n(b)?),
            Some((a, "")) => (n(a)?, usize::MAX),
            Some((a, b)) => {
                let (a, b) = (n(a)?, n(b)?);
                if a > b {
                    return None;
                }
                (a, b)
            }
        });
    }
    (!out.is_empty()).then_some(out)
}

/// A pattern as `grep` (basic), `grep -E` or `grep -F` reads it, for the regex crate.
/// Err: what it can't take (a back-reference).
pub fn pattern(
    pats: &[String],
    extended: bool,
    fixed: bool,
    ignore_case: bool,
    word: bool,
    line: bool,
) -> Result<Regex, String> {
    let each: Vec<String> = pats
        .iter()
        .map(|p| {
            if fixed {
                regex::escape(p)
            } else if extended {
                gnu_words(p)
            } else {
                gnu_words(&basic(p))
            }
        })
        .collect();
    let mut re = format!("(?:{})", each.join("|"));
    if word {
        re = format!(r"\b{re}\b");
    }
    if line {
        re = format!("^{re}$");
    }
    if ignore_case {
        re = format!("(?i){re}");
    }
    Regex::new(&re).map_err(|_| {
        format!(
            "grep: sentry's own grep can't read the pattern `{}`",
            pats.join("` / `")
        )
    })
}

/// `\<` and `\>` are word edges.
fn gnu_words(p: &str) -> String {
    p.replace(r"\<", r"\b").replace(r"\>", r"\b")
}

/// A basic regular expression as an extended one: in a basic one `( ) { } | + ?` are
/// themselves and their escaped forms are the operators.
fn basic(p: &str) -> String {
    let mut out = String::with_capacity(p.len() + 4);
    let mut chars = p.chars().peekable();
    let mut bracket = false;
    while let Some(c) = chars.next() {
        if bracket {
            out.push(c);
            if c == ']' {
                bracket = false;
            }
            continue;
        }
        match c {
            '[' => {
                bracket = true;
                out.push(c);
                // A `]` (or `^]`) right after the `[` is a member, not the end.
                if chars.peek() == Some(&'^') {
                    out.push(chars.next().expect("peeked"));
                }
                if chars.peek() == Some(&']') {
                    chars.next();
                    out.push_str(r"\]");
                }
            }
            '\\' => match chars.next() {
                Some(n) if "(){}|+?".contains(n) => out.push(n),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push_str(r"\\"),
            },
            c if "(){}|+?".contains(c) => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

fn lines_of(input: &str) -> Vec<&str> {
    input.lines().collect()
}

fn joined(lines: &[impl AsRef<str>]) -> String {
    let mut out = String::new();
    for l in lines {
        out.push_str(l.as_ref());
        out.push('\n');
    }
    out
}

fn picked(ranges: &Ranges, n: usize) -> bool {
    ranges.iter().any(|(a, b)| n >= *a && n <= *b)
}

impl Filter {
    /// What it prints for `input`, and its exit status.
    pub fn run(&self, input: &str) -> (String, i32) {
        let lines = lines_of(input);
        match self {
            Filter::Grep {
                re,
                invert,
                count,
                number,
                quiet,
                max,
                before,
                after,
            } => {
                let mut hits: Vec<usize> = lines
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| re.is_match(l) != *invert)
                    .map(|(i, _)| i)
                    .collect();
                if let Some(m) = max {
                    hits.truncate(*m);
                }
                let status = i32::from(hits.is_empty());
                if *quiet {
                    return (String::new(), status);
                }
                if *count {
                    return (format!("{}\n", hits.len()), status);
                }
                let mut out = String::new();
                let mut last: Option<usize> = None;
                for h in &hits {
                    let from = h.saturating_sub(*before).max(last.map_or(0, |l| l + 1));
                    let to = (h + after).min(lines.len().saturating_sub(1));
                    if (*before > 0 || *after > 0) && last.is_some_and(|l| from > l + 1) {
                        out.push_str("--\n");
                    }
                    for (i, line) in lines.iter().enumerate().take(to + 1).skip(from) {
                        if last.is_some_and(|l| i <= l) {
                            continue;
                        }
                        if *number {
                            let sep = if hits.contains(&i) { ':' } else { '-' };
                            out.push_str(&format!("{}{sep}", i + 1));
                        }
                        out.push_str(line);
                        out.push('\n');
                        last = Some(i);
                    }
                }
                (out, status)
            }
            Filter::Head(t) => {
                let n = match t {
                    Take::N(n) => (*n).min(lines.len()),
                    Take::Rest(n) => lines.len().saturating_sub(*n),
                };
                (joined(&lines[..n]), 0)
            }
            Filter::Tail(t) => {
                let from = match t {
                    Take::N(n) => lines.len().saturating_sub(*n),
                    Take::Rest(n) => n.saturating_sub(1).min(lines.len()),
                };
                (joined(&lines[from..]), 0)
            }
            Filter::Sort {
                unique,
                reverse,
                numeric,
                fold,
                key,
                sep,
            } => {
                let field = |l: &str| -> String {
                    let f = match key {
                        None => l.to_string(),
                        Some(k) => match sep {
                            Some(s) => l.split(*s).nth(k - 1).unwrap_or("").to_string(),
                            None => l.split_whitespace().nth(k - 1).unwrap_or("").to_string(),
                        },
                    };
                    if *fold { f.to_lowercase() } else { f }
                };
                let number = |s: &str| -> f64 {
                    let t = s.trim_start();
                    let end = t
                        .char_indices()
                        .find(|(i, c)| !(c.is_ascii_digit() || *c == '.' || (*i == 0 && *c == '-')))
                        .map_or(t.len(), |(i, _)| i);
                    t[..end].parse().unwrap_or(0.0)
                };
                let mut v: Vec<&str> = lines.clone();
                v.sort_by(|a, b| {
                    let (ka, kb) = (field(a), field(b));
                    let o = if *numeric {
                        number(&ka)
                            .partial_cmp(&number(&kb))
                            .unwrap_or(std::cmp::Ordering::Equal)
                    } else {
                        ka.cmp(&kb)
                    };
                    o.then_with(|| a.cmp(b))
                });
                if *unique {
                    v.dedup_by(|a, b| {
                        if *numeric {
                            number(&field(a)) == number(&field(b))
                        } else {
                            field(a) == field(b)
                        }
                    });
                }
                if *reverse {
                    v.reverse();
                }
                (joined(&v), 0)
            }
            Filter::Uniq {
                count,
                dups,
                uniques,
                fold,
            } => {
                let mut groups: Vec<(&str, usize)> = Vec::new();
                for l in &lines {
                    match groups.last_mut() {
                        Some((p, n))
                            if *p == *l || (*fold && p.to_lowercase() == l.to_lowercase()) =>
                        {
                            *n += 1
                        }
                        _ => groups.push((l, 1)),
                    }
                }
                let mut out = String::new();
                for (l, n) in groups {
                    if (*dups && n < 2) || (*uniques && n > 1) {
                        continue;
                    }
                    if *count {
                        out.push_str(&format!("{n:>7} "));
                    }
                    out.push_str(l);
                    out.push('\n');
                }
                (out, 0)
            }
            Filter::Wc {
                lines: l,
                words: w,
                bytes: b,
                name,
            } => {
                let all = !l && !w && !b;
                let mut cols: Vec<String> = Vec::new();
                if *l || all {
                    cols.push(input.matches('\n').count().to_string());
                }
                if *w || all {
                    cols.push(input.split_whitespace().count().to_string());
                }
                if *b || all {
                    cols.push(input.len().to_string());
                }
                if let Some(n) = name {
                    cols.push(n.clone());
                }
                (format!("{}\n", cols.join(" ")), 0)
            }
            Filter::Cut {
                delim,
                fields,
                chars,
                only_delimited,
            } => {
                let mut out = String::new();
                for line in &lines {
                    if let Some(r) = chars {
                        out.extend(
                            line.chars()
                                .enumerate()
                                .filter(|(i, _)| picked(r, i + 1))
                                .map(|(_, c)| c),
                        );
                        out.push('\n');
                    } else if let Some(r) = fields {
                        if !line.contains(*delim) {
                            if !only_delimited {
                                out.push_str(line);
                                out.push('\n');
                            }
                            continue;
                        }
                        let kept: Vec<&str> = line
                            .split(*delim)
                            .enumerate()
                            .filter(|(i, _)| picked(r, i + 1))
                            .map(|(_, f)| f)
                            .collect();
                        out.push_str(&kept.join(&delim.to_string()));
                        out.push('\n');
                    }
                }
                (out, 0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grep(pats: &[&str], flags: &str) -> Filter {
        let pats: Vec<String> = pats.iter().map(|p| p.to_string()).collect();
        let has = |c: char| flags.contains(c);
        Filter::Grep {
            re: pattern(&pats, has('E'), has('F'), has('i'), has('w'), has('x')).unwrap(),
            invert: has('v'),
            count: has('c'),
            number: has('n'),
            quiet: has('q'),
            max: None,
            before: 0,
            after: 0,
        }
    }

    #[test]
    fn grep_reads_patterns_as_grep_does() {
        let text = "alpha one\nbeta (two)\ngamma a+b\nAlpha three\n";
        let run = |f: Filter| f.run(text);
        assert_eq!(run(grep(&["alpha"], "")).0, "alpha one\n");
        assert_eq!(run(grep(&["alpha"], "i")).0, "alpha one\nAlpha three\n");
        assert_eq!(run(grep(&["alpha"], "ic")), ("2\n".into(), 0));
        assert_eq!(run(grep(&["nothing"], "c")), ("0\n".into(), 1));
        assert_eq!(run(grep(&["nothing"], "q")), (String::new(), 1));
        assert_eq!(run(grep(&["a"], "v")).0, "");
        assert_eq!(
            run(grep(&["one", "three"], "n")).0,
            "1:alpha one\n4:Alpha three\n"
        );
        // Basic: `(`, `+` and `|` are themselves; escaped, they are the operators.
        assert_eq!(run(grep(&["(two)"], "")).0, "beta (two)\n");
        assert_eq!(run(grep(&["a+b"], "")).0, "gamma a+b\n");
        assert_eq!(run(grep(&[r"one\|two"], "")).0, "alpha one\nbeta (two)\n");
        assert_eq!(run(grep(&[r"\(alpha\|beta\) "], "c")).0, "2\n");
        assert_eq!(run(grep(&["^[ab]"], "c")).0, "2\n");
        // Extended: the other way round.
        assert_eq!(run(grep(&["one|two"], "E")).0, "alpha one\nbeta (two)\n");
        assert_eq!(run(grep(&[r"\(two\)"], "E")).0, "beta (two)\n");
        // Fixed: nothing is an operator.
        assert_eq!(run(grep(&["a+b"], "F")).0, "gamma a+b\n");
        assert_eq!(run(grep(&[".*"], "Fc")).0, "0\n");
        // Whole words, whole lines.
        assert_eq!(run(grep(&["alph"], "wc")).0, "0\n");
        assert_eq!(run(grep(&["alpha one"], "x")).0, "alpha one\n");
        // A back-reference isn't taken.
        assert!(pattern(&[r"\(a\)\1".to_string()], false, false, false, false, false).is_err());
        // Context.
        let ctx = Filter::Grep {
            re: pattern(&["gamma".into()], false, false, false, false, false).unwrap(),
            invert: false,
            count: false,
            number: false,
            quiet: false,
            max: None,
            before: 1,
            after: 1,
        };
        assert_eq!(ctx.run(text).0, "beta (two)\ngamma a+b\nAlpha three\n");
    }

    #[test]
    fn the_other_filters() {
        let text = "b 2\na 10\nc 1\na 10\n";
        assert_eq!(Filter::Head(Take::N(2)).run(text).0, "b 2\na 10\n");
        assert_eq!(Filter::Head(Take::Rest(3)).run(text).0, "b 2\n");
        assert_eq!(Filter::Tail(Take::N(1)).run(text).0, "a 10\n");
        assert_eq!(Filter::Tail(Take::Rest(3)).run(text).0, "c 1\na 10\n");
        let sort = |unique, reverse, numeric, key| Filter::Sort {
            unique,
            reverse,
            numeric,
            fold: false,
            key,
            sep: None,
        };
        assert_eq!(
            sort(false, false, false, None).run(text).0,
            "a 10\na 10\nb 2\nc 1\n"
        );
        assert_eq!(
            sort(true, true, false, None).run(text).0,
            "c 1\nb 2\na 10\n"
        );
        assert_eq!(
            sort(true, false, true, Some(2)).run(text).0,
            "c 1\nb 2\na 10\n"
        );
        let uniq = Filter::Uniq {
            count: true,
            dups: false,
            uniques: false,
            fold: false,
        };
        assert_eq!(uniq.run("a\na\nb\n").0, "      2 a\n      1 b\n");
        let wc = |lines, name: Option<&str>| Filter::Wc {
            lines,
            words: false,
            bytes: false,
            name: name.map(str::to_string),
        };
        assert_eq!(wc(true, None).run(text).0, "4\n");
        assert_eq!(wc(false, Some("/proc/x")).run("a b\n").0, "1 2 4 /proc/x\n");
        let cut = Filter::Cut {
            delim: ' ',
            fields: ranges("2"),
            chars: None,
            only_delimited: false,
        };
        assert_eq!(cut.run(text).0, "2\n10\n1\n10\n");
        let chars = Filter::Cut {
            delim: '\t',
            fields: None,
            chars: ranges("1,3-"),
            only_delimited: false,
        };
        assert_eq!(chars.run("abcd\n").0, "acd\n");
        assert_eq!(
            ranges("1,3-5,7-"),
            Some(vec![(1, 1), (3, 5), (7, usize::MAX)])
        );
        assert_eq!(ranges("-2"), Some(vec![(1, 2)]));
        for bad in ["", "0", "a", "3-1", "1,,2"] {
            assert_eq!(ranges(bad), None, "{bad}");
        }
    }
}

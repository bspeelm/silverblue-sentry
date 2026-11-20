//! Suspicious patterns in shell rc files (spec §6: curl|wget|base64|eval).

use serde::{Deserialize, Serialize};

use super::Ctx;

pub const FILES: &[&str] = &[".bashrc", ".bash_profile", ".profile", ".zshrc"];
pub const PATTERNS: &[&str] = &["curl", "wget", "base64", "eval"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hit {
    pub file: String,
    pub line: usize,
    pub pattern: String,
    pub text: String,
}

pub fn collect(ctx: &Ctx) -> Vec<Hit> {
    FILES
        .iter()
        .filter_map(|f| {
            let text = std::fs::read_to_string(ctx.home.join(f)).ok()?;
            Some(scan(&format!("~/{f}"), &text))
        })
        .flatten()
        .collect()
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Whole-word occurrence of `word` in `line`.
fn has_word(line: &str, word: &str) -> bool {
    line.match_indices(word).any(|(i, _)| {
        let before = line[..i].chars().next_back();
        let after = line[i + word.len()..].chars().next();
        !before.is_some_and(is_word) && !after.is_some_and(is_word)
    })
}

pub fn scan(file: &str, text: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        if let Some(p) = PATTERNS.iter().find(|p| has_word(t, p)) {
            out.push(Hit {
                file: file.to_string(),
                line: n + 1,
                pattern: p.to_string(),
                text: t.to_string(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_matches_only() {
        let h = scan(
            "~/.bashrc",
            "# curl in comment\nalias x='curl -s y'\nexport CURLOPT=1\neval \"$(starship init bash)\"\nevaluate=1\n",
        );
        let lines: Vec<_> = h.iter().map(|h| (h.line, h.pattern.as_str())).collect();
        assert_eq!(lines, vec![(2, "curl"), (4, "eval")]);
    }
}

//! The window's config area. For now only what it will show first: what is wrong in the three
//! config files, found offline when the window starts (`Win.config_problems`).

use sentry_core::cfg::{FileId, Seg, parse_path};

/// One thing wrong in a config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub file: FileId,
    /// The server or network it is about (None: the file as a whole, or config.toml).
    pub entry: Option<String>,
    pub text: String,
}

impl Problem {
    /// A problem of `file`: its text without the file's or the entry's name in front (they are
    /// fields here), the entry told from that name or from a key's path in the text.
    pub fn of(file: FileId, entry: Option<&str>, text: &str) -> Self {
        let mut text = text;
        for prefix in [file.name(), "config"] {
            if let Some(rest) = text.strip_prefix(prefix).and_then(|r| r.strip_prefix(": ")) {
                text = rest;
            }
        }
        if let Some(rest) = entry
            .and_then(|e| text.strip_prefix(e))
            .and_then(|r| r.strip_prefix(": "))
        {
            text = rest;
        }
        let entry = entry.map(str::to_string).or_else(|| entry_in(file, text));
        Self {
            file,
            entry,
            text: text.to_string(),
        }
    }

    /// `server_config.yaml · myserver: timer `x` should end in .timer`.
    pub fn line(&self) -> String {
        match &self.entry {
            Some(e) => format!("{} · {e}: {}", self.file.name(), self.text),
            None => format!("{}: {}", self.file.name(), self.text),
        }
    }
}

/// The entry a key's path in backticks names (`servers.a.sudoo` → `a`).
fn entry_in(file: FileId, text: &str) -> Option<String> {
    let top = match file {
        FileId::Servers => "servers",
        FileId::Networks => "networks",
        FileId::App => return None,
    };
    let path = text.split('`').nth(1)?;
    match parse_path(path).ok()?.as_slice() {
        [Seg::Key(t), Seg::Key(e), ..] if t == top => Some(e.clone()),
        _ => None,
    }
}

/// What the window says once it is up: the first problem, how many there are, and where to
/// see them all. None: nothing is wrong.
pub fn toast(problems: &[Problem]) -> Option<String> {
    let first = problems.first()?.line();
    Some(match problems.len() {
        1 => format!("{first} (`sentry config check`)"),
        n => format!("{n} config problems, `sentry config check` lists them · {first}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_problem_knows_its_file_and_entry() {
        let p = Problem::of(
            FileId::Servers,
            None,
            "server_config.yaml: unknown key `servers.my-box.sudoo` ignored",
        );
        assert_eq!(p.entry.as_deref(), Some("my-box"));
        assert_eq!(p.text, "unknown key `servers.my-box.sudoo` ignored");
        let p = Problem::of(
            FileId::Servers,
            Some("a"),
            "a: timer `x` should end in .timer",
        );
        assert_eq!(
            p.line(),
            "server_config.yaml · a: timer `x` should end in .timer"
        );
        let p = Problem::of(FileId::App, None, "config: unknown key `ui.bogus` ignored");
        assert_eq!(p.line(), "config.toml: unknown key `ui.bogus` ignored");
        assert_eq!(toast(&[]), None);
        assert_eq!(
            toast(std::slice::from_ref(&p)).unwrap(),
            "config.toml: unknown key `ui.bogus` ignored (`sentry config check`)"
        );
        assert!(
            toast(&[p.clone(), p])
                .unwrap()
                .starts_with("2 config problems")
        );
    }
}

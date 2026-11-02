//! What needs root in a plan, and how sentry does it without leaving the TUI: the password is
//! asked inline once, held in a `Secret`, and fed on stdin to a shell whose `sudo` reads it
//! (`wrap`): never in argv, the environment or a file, never logged or sent.
//!
//! A plan may edit your own files (anywhere), and root's configuration under /etc (not the
//! files that control who may log in or use sudo): sentry backs the file up, writes the new
//! text to a private temp file, and copies it over the original in place with sudo, which
//! keeps the file's owner, mode and SELinux label.

use std::path::{Path, PathBuf};

use crate::claude::{Access, Grant};

/// Under /etc, but never these: a mistake there locks you out.
const NEVER_ROOT: &[&str] = &[
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/passwd",
    "/etc/group",
    "/etc/pam.d",
];

/// Who writes an edit's file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// Your own file: sentry writes it.
    You,
    /// Root's, under /etc: written with sudo.
    Root,
}

/// Whether a plan may edit `file` (an absolute path on the host), and who writes it.
pub fn edit_target(file: &str) -> Result<Owner, String> {
    let mine = Grant {
        access: Access::Write,
        path: crate::maint::real_path(Path::new(file)),
    };
    let why = match crate::claude::grantable(&mine) {
        Ok(()) => return Ok(Owner::You),
        Err(why) => why,
    };
    let p = Path::new(file);
    if !p.starts_with("/etc") || p.components().any(|c| c.as_os_str() == "..") {
        return Err(format!("{file}: {why} (root's files only under /etc)"));
    }
    if NEVER_ROOT.iter().any(|n| p.starts_with(n)) {
        return Err(format!(
            "{file}: sudo and login files stay yours to edit by hand"
        ));
    }
    let host = crate::paths::host(file);
    match std::fs::symlink_metadata(&host) {
        Err(_) => Err(format!("{file}: not there")),
        Ok(m) if m.file_type().is_symlink() => {
            Err(format!("{file}: a link; edit what it points to"))
        }
        Ok(m) if !m.is_file() => Err(format!("{file}: not a file")),
        Ok(_) if std::fs::read_to_string(&host).is_err() => Err(format!(
            "{file}: not readable, so its text can't be checked"
        )),
        Ok(_) => Ok(Owner::Root),
    }
}

/// The text of an edit's file as it is now (root's files through the host's root).
pub fn read(file: &str, owner: Owner) -> std::io::Result<String> {
    match owner {
        Owner::You => std::fs::read_to_string(file),
        Owner::Root => std::fs::read_to_string(crate::paths::host(file)),
    }
}

/// A root edit, prepared: the file backed up (as you: it's readable), the new text in a
/// private temp file. `script` copies it over the original with sudo.
#[derive(Debug, Clone, PartialEq)]
pub struct RootWrite {
    pub file: String,
    pub tmp: PathBuf,
    pub backup: PathBuf,
    pub before: usize,
    pub after: usize,
}

impl RootWrite {
    /// The command (run through `wrap`): copy in place, keeping owner, mode and label.
    pub fn script(&self) -> String {
        format!(
            "sudo sh -c 'cat \"$1\" > \"$2\"' _ {} {}",
            crate::exec::sh_quote(&self.tmp.display().to_string()),
            crate::exec::sh_quote(&self.file)
        )
    }

    /// Done (either way): the temp file goes.
    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.tmp);
    }
}

/// Back up `file`, check `old` is there once, write the result to a 0600 temp file.
pub fn prepare_root_edit(file: &str, old: &str, new: &str) -> Result<RootWrite, String> {
    let host = crate::paths::host(file);
    let text = std::fs::read_to_string(&host).map_err(|e| format!("{file}: {e}"))?;
    if text.matches(old).count() != 1 {
        return Err(format!(
            "{file}: its old text isn't there exactly once any more"
        ));
    }
    let backup =
        crate::claude::backup(&host.display().to_string()).map_err(|e| format!("backup: {e}"))?;
    let changed = text.replacen(old, new, 1);
    let dir = crate::claude::cwd().join("apply");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = dir.join(format!(
        "{}-{}",
        std::process::id(),
        Path::new(file)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".into())
    ));
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(changed.as_bytes())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
    }
    Ok(RootWrite {
        file: file.to_string(),
        tmp,
        backup,
        before: text.lines().count(),
        after: changed.lines().count(),
    })
}

/// Whether a command uses sudo.
pub fn uses_sudo(cmd: &str) -> bool {
    cmd.split(|c: char| c.is_whitespace() || ";&|()`$".contains(c))
        .any(|w| w == "sudo")
}

/// The script a sudo command runs in: the first line of stdin is the password, and `sudo`
/// is a function that hands it to the real sudo (`-S`, no prompt). The command itself runs
/// with nothing more on stdin.
pub fn wrap(cmd: &str) -> String {
    format!(
        "IFS= read -r SENTRY_P\n\
         sudo() {{ printf '%s\\n' \"$SENTRY_P\" | command sudo -S -p '' \"$@\"; }}\n\
         exec </dev/null\n\
         {cmd}"
    )
}

/// The check of a password: sudo accepts it (and nothing else runs).
pub fn check_script() -> &'static str {
    "IFS= read -r SENTRY_P\nprintf '%s\\n' \"$SENTRY_P\" | command sudo -S -p '' true"
}

/// A sudo password, typed into the session. Never shown (Debug says how long it is), wiped
/// when dropped.
#[derive(Clone, Default, PartialEq)]
pub struct Secret(String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({} chars)", self.0.chars().count())
    }
}

impl Secret {
    pub fn push(&mut self, c: char) {
        self.0.push(c);
    }

    pub fn pop(&mut self) {
        self.0.pop();
    }

    pub fn len(&self) -> usize {
        self.0.chars().count()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// What goes to the script's stdin: the password and a newline.
    pub fn stdin(&self) -> Vec<u8> {
        format!("{}\n", self.0).into_bytes()
    }

    pub fn clear(&mut self) {
        // Overwrite, then empty: the bytes don't linger in the old allocation.
        let n = self.0.len();
        self.0.clear();
        self.0.extend(std::iter::repeat_n('\0', n));
        self.0.clear();
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_a_plan_may_edit() {
        let mine = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
        assert_eq!(edit_target(&mine), Ok(Owner::You));
        // Root's configuration: with sudo (/etc/hosts is in every container and host).
        assert_eq!(edit_target("/etc/hosts"), Ok(Owner::Root));
        for f in [
            "/etc/sudoers",
            "/etc/sudoers.d/x",
            "/etc/shadow",
            "/etc/pam.d/sudo",
        ] {
            assert!(edit_target(f).unwrap_err().contains("by hand"), "{f}");
        }
        assert!(
            edit_target("/usr/bin/sh")
                .unwrap_err()
                .contains("only under /etc")
        );
        assert!(edit_target("/etc/../usr/x").is_err());
        assert!(
            edit_target("/etc/sentry-no-such-file")
                .unwrap_err()
                .contains("not there")
        );
    }

    #[test]
    fn a_root_edit_is_prepared_not_done() {
        let text = std::fs::read_to_string(crate::paths::host("/etc/hosts")).unwrap();
        let first = text
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap()
            .to_string();
        if text.matches(first.as_str()).count() != 1 {
            return;
        }
        let w = prepare_root_edit("/etc/hosts", &first, "# changed").unwrap();
        assert_eq!(
            std::fs::read_to_string(&w.tmp).unwrap(),
            text.replacen(&first, "# changed", 1)
        );
        assert_eq!(std::fs::read_to_string(&w.backup).unwrap(), text);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&w.tmp).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            w.script()
                .starts_with("sudo sh -c 'cat \"$1\" > \"$2\"' _ ")
        );
        assert!(w.script().ends_with(" /etc/hosts"));
        // The original is untouched.
        assert_eq!(
            std::fs::read_to_string(crate::paths::host("/etc/hosts")).unwrap(),
            text
        );
        w.cleanup();
        assert!(!w.tmp.exists());
        let _ = std::fs::remove_file(&w.backup);
        assert!(prepare_root_edit("/etc/hosts", "no such text 123", "x").is_err());
    }

    #[test]
    fn sudo_gets_the_password_on_stdin_only() {
        assert!(uses_sudo("a && sudo systemctl restart x"));
        assert!(uses_sudo("(sudo true)"));
        assert!(!uses_sudo("echo pseudo; grep sudoers /etc/x"));
        // The wrapped script: `sudo` is a function feeding the first stdin line to `sudo -S`.
        let out = crate::exec::Cmd::local("bash")
            .arg("-c")
            .arg(wrap(
                "sudo() { echo \"would run: $*\"; read -r x || echo eof; }; sudo ls",
            ))
            .input("pw\n")
            .output()
            .unwrap();
        assert_eq!(out, "would run: ls\neof\n");
        let s = wrap("sudo ls");
        assert!(s.contains("command sudo -S -p ''") && !s.contains("pw"));
        let mut p = Secret::default();
        for c in "hunter2".chars() {
            p.push(c);
        }
        assert_eq!(format!("{p:?}"), "Secret(7 chars)");
        assert_eq!(p.stdin(), b"hunter2\n");
        p.clear();
        assert!(p.is_empty());
    }
}

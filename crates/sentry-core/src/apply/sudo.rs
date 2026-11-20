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

/// The script a sudo command runs in (POSIX sh, here or on a server): the first line of
/// stdin is the password. A `sudo` stand-in goes first on PATH for the step, in a private temp
/// dir removed when it ends: it runs the real sudo with an askpass helper beside it (`-A`, no
/// prompt). Being on PATH, it's the `sudo` of everything the step starts, however nested
/// (`sh -c '… sudo …'`, `xargs sudo`, a script): a shell function wouldn't reach those, and
/// the real sudo, with nobody to ask, would fail.
///
/// The helper takes the password from a fifo in that dir, which only this script holds open
/// (descriptor 9, closed for the step itself), and puts it back for the next call; it answers
/// once for each sudo, so a password that stopped working is one failed attempt, not three.
/// So the password is in no command line, no file and no environment: what the step runs
/// can't print it by printing its own, and it is gone when the script ends, however it ends.
///
/// sudo's stdin is the step's: a terminal when the step has one (over ssh it does), which is
/// what makes sudo end its command when that terminal hangs up, i.e. when the step is stopped
/// from here. With no terminal the step gets nothing on stdin.
pub fn wrap(cmd: &str) -> String {
    format!("IFS= read -r SENTRY_P\n{}", wrapped(cmd))
}

/// A line a streamed sudo command prints when it is ready for the password (`wrap_ready`).
pub const READY: &str = "@@sentry-ready";

/// `wrap` for a command that is streamed (`Cmd::input_after(READY, …)`): it may have a
/// terminal, whose echo is turned off before the password is asked for, and back on after.
pub fn wrap_ready(cmd: &str) -> String {
    format!(
        "stty -echo 2>/dev/null\n\
         echo {READY}\n\
         IFS= read -r SENTRY_P\n\
         stty echo 2>/dev/null\n{}",
        wrapped(cmd)
    )
}

fn wrapped(cmd: &str) -> String {
    format!(
        "SENTRY_SUDO=$(command -v sudo) || {{ echo 'sudo not found' >&2; exit 127; }}\n\
         SENTRY_D=$(mktemp -d) || exit 1\n\
         trap 'rm -rf \"$SENTRY_D\"' EXIT\n\
         mkfifo -m 600 \"$SENTRY_D/p\" || exit 1\n\
         exec 9<>\"$SENTRY_D/p\" || exit 1\n\
         printf '%s\\n' \"$SENTRY_P\" \"$SENTRY_P\" \"$SENTRY_P\" \"$SENTRY_P\" >&9\n\
         unset SENTRY_P\n\
         export SENTRY_SUDO SENTRY_D\n\
         printf '%s\\n' '#!/bin/sh' \
         'case \"$1\" in -n*|-S*|-A*|-k|-K|-V|-h) exec \"$SENTRY_SUDO\" \"$@\";; esac' \
         'SENTRY_M=\"$SENTRY_D/m.$$\"' \
         ': > \"$SENTRY_M\"' \
         'export SENTRY_M' \
         'SUDO_ASKPASS=\"$SENTRY_D/ask\" exec \"$SENTRY_SUDO\" -A \"$@\"' > \"$SENTRY_D/sudo\"\n\
         printf '%s\\n' '#!/bin/sh' \
         '[ -e \"$SENTRY_M\" ] || exit 1' \
         'rm -f \"$SENTRY_M\"' \
         'IFS= read -r p < \"$SENTRY_D/p\" || exit 1' \
         'printf \"%s\\\\n\" \"$p\" > \"$SENTRY_D/p\"' \
         'printf \"%s\\\\n\" \"$p\"' > \"$SENTRY_D/ask\"\n\
         chmod 700 \"$SENTRY_D/sudo\" \"$SENTRY_D/ask\"\n\
         PATH=\"$SENTRY_D:$PATH\"\n\
         export PATH\n\
         [ -t 0 ] || exec </dev/null\n\
         (\n\
         exec 9>&-\n\
         {cmd}\n\
         )\n"
    )
}

/// A sudo command run without a password to give: its `sudo` fails at once instead of
/// waiting on a prompt nobody sees.
pub fn no_prompt(cmd: &str) -> String {
    format!("sudo() {{ command sudo -n \"$@\"; }}\n{cmd}")
}

/// The check of a password: sudo accepts it (and nothing else runs). `-k`: a ticket from
/// earlier doesn't count, so a wrong password is refused whatever was typed before.
pub fn check_script() -> &'static str {
    "IFS= read -r SENTRY_P\nprintf '%s\\n' \"$SENTRY_P\" | command sudo -k -S -p '' true"
}

/// sudo saying the password it was handed is wrong.
pub fn wrong_password(line: &str) -> bool {
    line.contains("incorrect password attempt") || line.contains("Sorry, try again")
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

    /// The password, moved out (what's left is empty).
    pub fn take(&mut self) -> Secret {
        std::mem::take(self)
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
        // The wrapped script, with a fake "real" sudo first on PATH (it asks its askpass
        // helper, as sudo -A does, twice to see the second answer refused): every sudo the
        // step runs, nested in `sh -c` too, gets the password; the command itself gets
        // nothing on stdin; the password is in no environment; the dir is gone afterwards.
        let fake = std::env::temp_dir().join(format!("sentry-fake-sudo-{}", std::process::id()));
        std::fs::create_dir_all(&fake).unwrap();
        std::fs::write(
            fake.join("sudo"),
            "#!/bin/sh\npw=none\nif [ \"$1\" = -A ]; then shift; pw=$(\"$SUDO_ASKPASS\"); \
             \"$SUDO_ASKPASS\" >/dev/null && pw=twice; fi\necho \"sudo $* (pw=$pw)\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(fake.join("sudo"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let step = "sudo -n true\nsudo ls\nsh -c 'sudo id -u'\nread -r x || echo stdin-empty\necho \"dir=$SENTRY_D\"\nenv | grep -c pw-9 || true";
        let script = format!("PATH={}:$PATH; export PATH\n{}", fake.display(), wrap(step));
        // POSIX only: servers run it with dash.
        let posix = crate::exec::Cmd::local("bash")
            .args(["--posix", "-c", &script])
            .input("pw-9\n")
            .output()
            .unwrap();
        assert!(posix.contains("sudo id -u (pw=pw-9)"), "{posix}");
        let out = crate::exec::Cmd::local("sh")
            .arg("-c")
            .arg(script)
            .input("pw-9\n")
            .output()
            .unwrap();
        let lines: Vec<&str> = out.lines().collect();
        // `sudo -n` stays what it is: no password is offered to it.
        assert_eq!(lines[0], "sudo -n true (pw=none)", "{out}");
        assert_eq!(lines[1], "sudo ls (pw=pw-9)", "{out}");
        assert_eq!(lines[2], "sudo id -u (pw=pw-9)", "nested: {out}");
        assert_eq!(lines[3], "stdin-empty", "{out}");
        let dir = lines[4].trim_start_matches("dir=");
        assert!(
            !dir.is_empty() && !std::path::Path::new(dir).exists(),
            "{out}"
        );
        // Not in the step's environment, however many times sudo was called.
        assert_eq!(lines[5], "0", "{out}");
        let _ = std::fs::remove_dir_all(&fake);
        assert!(!wrap("sudo ls").contains("pw-9"));
        // Streamed: the password is read after the ready line, and the step is the same.
        let ready = wrap_ready("echo hi");
        assert!(ready.starts_with("stty -echo 2>/dev/null\necho @@sentry-ready\nIFS= read -r"));
        assert!(wrong_password("sudo: 1 incorrect password attempt"));
        assert!(!wrong_password("Reading package lists..."));
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

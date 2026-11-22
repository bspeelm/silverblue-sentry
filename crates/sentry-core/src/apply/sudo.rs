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
        ..Default::default()
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
/// The step, and everything sudo starts for it, gets nothing on stdin (`/dev/null`): a
/// command that reads it (`head`, `cat`) ends at once instead of waiting. Stopping the step
/// from here (TERM to the script on this machine; over ssh its terminal hangs up) ends what
/// sudo started too: see `rooted`.
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
    rooted(true, cmd)
}

/// The script both `wrap` and `no_prompt` run a step in. `password`: the first line of
/// stdin was the password (in `SENTRY_P`), and each sudo gets it through the askpass helper;
/// without one every sudo is `sudo -n`.
///
/// Stopping it has to reach what runs as root, which the user can't signal and which, with
/// no terminal (on this machine there never is one), no hangup reaches either. So each sudo
/// is started in a session of its own (`setsid`, through the `own` helper, which writes its
/// process group to a file the stand-in removes when it ends), and on HUP, TERM or INT the
/// script signals every group still listed, as root, through the same stand-in (the password
/// is still in the fifo), then the rest of the step (everything it started; its whole
/// process group only when the group is its own, as over ssh: on this machine the group is
/// the program's); it waits a few seconds for root's processes to go and kills what's left.
/// Without `setsid` the one sudo process is signalled, as before.
fn rooted(password: bool, cmd: &str) -> String {
    const HEAD: &str = r#"SENTRY_SUDO=$(command -v sudo) || { echo 'sudo not found' >&2; exit 127; }
SENTRY_SETSID=$(command -v setsid) || SENTRY_SETSID=
SENTRY_D=$(mktemp -d) || exit 1
trap 'rm -rf "$SENTRY_D"' EXIT
"#;
    const FIFO: &str = r#"mkfifo -m 600 "$SENTRY_D/p" || exit 1
exec 9<>"$SENTRY_D/p" || exit 1
printf '%s\n' "$SENTRY_P" "$SENTRY_P" "$SENTRY_P" "$SENTRY_P" >&9
unset SENTRY_P
cat > "$SENTRY_D/ask" <<'SENTRY_EOF'
#!/bin/sh
[ -e "$SENTRY_M" ] || exit 1
rm -f "$SENTRY_M"
IFS= read -r p < "$SENTRY_D/p" || exit 1
printf '%s\n' "$p" > "$SENTRY_D/p"
printf '%s\n' "$p"
SENTRY_EOF
"#;
    // How the stand-in calls the real sudo: with the askpass helper (once per call: the
    // marker), unless the step chose for itself; or never asking.
    const ASKS: &str = r#"case "$1" in -n*|-S*|-A*|-k|-K|-V|-h) SENTRY_A=;; *) SENTRY_A=-A; SENTRY_M="$SENTRY_D/m.$$"; : > "$SENTRY_M"; export SENTRY_M;; esac"#;
    const NEVER: &str = "SENTRY_A=-n";
    const REST: &str = r#"export SENTRY_SUDO SENTRY_SETSID SENTRY_D
cat > "$SENTRY_D/sudo" <<'SENTRY_EOF'
#!/bin/sh
{HOW}
SENTRY_G="$SENTRY_D/k.$$"
export SENTRY_A SENTRY_G
${SENTRY_SETSID:+"$SENTRY_SETSID"} "$SENTRY_D/own" "$@" </dev/null &
wait $!
SENTRY_R=$?
rm -f "$SENTRY_G"
exit $SENTRY_R
SENTRY_EOF
cat > "$SENTRY_D/own" <<'SENTRY_EOF'
#!/bin/sh
if [ -n "$SENTRY_SETSID" ]; then echo "-$$"; else echo "$$"; fi > "$SENTRY_G"
SUDO_ASKPASS="$SENTRY_D/ask" exec "$SENTRY_SUDO" $SENTRY_A "$@"
SENTRY_EOF
chmod 700 "$SENTRY_D/sudo" "$SENTRY_D/own"
[ ! -e "$SENTRY_D/ask" ] || chmod 700 "$SENTRY_D/ask"
PATH="$SENTRY_D:$PATH"
export PATH
sentry_each() {
  for SENTRY_F in "$SENTRY_D"/k.*; do
    [ -e "$SENTRY_F" ] || continue
    IFS= read -r SENTRY_T < "$SENTRY_F" || continue
    "$SENTRY_D/sudo" kill "-$1" -- "$SENTRY_T" 2>/dev/null
  done
}
sentry_left() {
  for SENTRY_F in "$SENTRY_D"/k.*; do
    [ -e "$SENTRY_F" ] || continue
    IFS= read -r SENTRY_T < "$SENTRY_F" || continue
    case "$SENTRY_T" in
      -*) pgrep -g "${SENTRY_T#-}" >/dev/null 2>&1 && return 0 ;;
      *) [ -d "/proc/$SENTRY_T" ] && return 0 ;;
    esac
  done
  return 1
}
sentry_tree() {
  for SENTRY_C in $(pgrep -P "$1" 2>/dev/null); do sentry_tree "$SENTRY_C"; done
  [ "$1" = "$$" ] || kill -HUP "$1" 2>/dev/null
}
sentry_end() {
  trap '' HUP TERM INT
  sentry_each TERM
  sentry_tree "$$"
  kill -HUP "$SENTRY_STEP" 2>/dev/null
  if [ "$(ps -o pgid= -p "$$" 2>/dev/null | tr -d ' ')" = "$$" ]; then kill -HUP 0 2>/dev/null; fi
  SENTRY_N=0
  while [ "$SENTRY_N" -lt 25 ] && sentry_left; do sleep 0.2; SENTRY_N=$((SENTRY_N + 1)); done
  if sentry_left; then sentry_each KILL; fi
  exit 129
}
trap sentry_end HUP TERM INT
exec </dev/null
(
{CLOSE}{CMD}
) &
SENTRY_STEP=$!
wait "$SENTRY_STEP"
"#;
    let mut s = String::from(HEAD);
    if password {
        s.push_str(FIFO);
    }
    s.push_str(
        &REST
            .replace("{HOW}", if password { ASKS } else { NEVER })
            .replace("{CLOSE}", if password { "exec 9>&-\n" } else { "" })
            .replace("{CMD}", cmd),
    );
    s
}

/// A sudo command run without a password to give: its `sudo`, however nested, fails at once
/// (`-n`) instead of waiting on a prompt nobody sees. Nothing on stdin either, and stopping
/// it ends what sudo started, as in `wrap`.
pub fn no_prompt(cmd: &str) -> String {
    rooted(false, cmd)
}

/// A command sentry runs for Claude or as a step, with nothing on stdin: over ssh a streamed
/// command has a terminal there, which never ends, so `head` or `cat` with no file would
/// wait on it for ever.
pub fn detached(cmd: &str) -> String {
    format!("exec </dev/null\n{cmd}")
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

    /// A stand-in for the real sudo that runs the command as whoever runs the test (root
    /// isn't to be had in a unit test): what the wrapper does around it is the same.
    fn fake_sudo() -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sentry-fake-root-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("sudo"),
            "#!/bin/sh\nwhile [ \"$1\" = -A ] || [ \"$1\" = -n ]; do shift; done\nexec \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(dir.join("sudo"), std::fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    #[test]
    fn stopping_a_sudo_step_ends_what_sudo_started() {
        use crate::exec::{Cmd, StreamMsg};
        let running = |mark: &str| {
            Cmd::local("pgrep")
                .args(["-f", mark])
                .run()
                .map(|o| o.stdout.trim().to_string())
                .unwrap_or_default()
        };
        // What sudo starts, and what that starts (a shell with two children, one in the
        // background): none of it may be left, with a password held and without.
        for (i, password) in [true, false].into_iter().enumerate() {
            let fake = fake_sudo();
            let mark = format!("3{}{i}", std::process::id());
            let step = format!("echo started; sudo sh -c 'sleep {mark} & sleep {mark}; wait'");
            let script = format!(
                "PATH={}:$PATH; export PATH\n{}",
                fake.display(),
                if password {
                    wrap_ready(&step)
                } else {
                    no_prompt(&step)
                }
            );
            let (tx, rx) = std::sync::mpsc::channel();
            let mut cmd = Cmd::local("sh").args(["-c", &script]).timeout(None);
            if password {
                cmd = cmd.input_after(READY, "pw-9\n");
            }
            let pid = cmd
                .stream(move |m| {
                    let _ = tx.send(m);
                })
                .unwrap();
            let wait = std::time::Duration::from_secs(10);
            match rx.recv_timeout(wait) {
                Ok(StreamMsg::Line { text, .. }) => assert_eq!(text, "started"),
                other => panic!("no first line: {other:?}"),
            }
            // (The two sleeps are up a moment after the line.)
            let until = std::time::Instant::now() + wait;
            while running(&format!("sleep {mark}")).lines().count() < 2 {
                assert!(std::time::Instant::now() < until, "the step never started");
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Cmd::local("kill")
                .args(["-TERM", &pid.to_string()])
                .run()
                .unwrap();
            let code = loop {
                match rx.recv_timeout(wait) {
                    Ok(StreamMsg::Exit { code, .. }) => break code,
                    Ok(_) => {}
                    Err(_) => panic!("the wrapper didn't end (password: {password})"),
                }
            };
            assert_eq!(code, 129, "password: {password}");
            let left = running(&format!("sleep {mark}"));
            assert!(
                left.is_empty(),
                "left running (password: {password}): {left}"
            );
            let _ = std::fs::remove_dir_all(&fake);
        }
        // The script says how: each sudo in a session of its own, its group signalled as
        // root when the step is stopped, and killed if it stays.
        let s = no_prompt("sudo x");
        assert!(s.contains("${SENTRY_SETSID:+\"$SENTRY_SETSID\"} \"$SENTRY_D/own\""));
        assert!(s.contains("\"$SENTRY_D/sudo\" kill \"-$1\" -- \"$SENTRY_T\""));
        assert!(s.contains("trap sentry_end HUP TERM INT") && s.contains("sentry_each KILL"));
        assert!(s.contains("SENTRY_A=-n") && !s.contains("mkfifo"));
        assert!(wrap("sudo x").contains("SENTRY_A=-A") && wrap("sudo x").contains("mkfifo"));
    }

    #[test]
    fn nothing_run_for_claude_waits_on_stdin() {
        use crate::exec::{Cmd, StreamMsg};
        // `head` with no file reads stdin: it must see the end of it at once, streamed (as
        // a session's command and a step are) and with a password fed first.
        for script in [
            detached("head -5; echo after"),
            no_prompt("head -5; echo after"),
        ] {
            let (tx, rx) = std::sync::mpsc::channel();
            Cmd::local("sh")
                .args(["-c", &script])
                .timeout(None)
                .stream(move |m| {
                    let _ = tx.send(m);
                })
                .unwrap();
            let mut lines = Vec::new();
            loop {
                match rx.recv_timeout(std::time::Duration::from_secs(10)) {
                    Ok(StreamMsg::Line { text, .. }) => lines.push(text),
                    Ok(StreamMsg::Exit { code, .. }) => {
                        assert_eq!(code, 0);
                        break;
                    }
                    Err(_) => panic!("still waiting on stdin: {script}"),
                }
            }
            assert_eq!(lines, ["after"], "{script}");
        }
        // Through the sudo wrapper: the password line is the wrapper's, never the step's.
        let out = Cmd::local("sh")
            .args(["-c", &wrap("head -5; echo after")])
            .input("pw-9\nmore\n")
            .output()
            .unwrap();
        assert_eq!(out, "after\n");
        let (tx, rx) = std::sync::mpsc::channel();
        Cmd::local("sh")
            .args(["-c", &wrap_ready("cat; echo after")])
            .input_after(READY, "pw-9\n")
            .timeout(None)
            .stream(move |m| {
                let _ = tx.send(m);
            })
            .unwrap();
        let mut lines = Vec::new();
        while let Ok(m) = rx.recv_timeout(std::time::Duration::from_secs(10)) {
            match m {
                StreamMsg::Line { text, .. } => lines.push(text),
                StreamMsg::Exit { .. } => break,
            }
        }
        assert_eq!(
            lines,
            ["after"],
            "the ready line and the password aren't output"
        );
    }
}

//! Root on the target, one way for everything: a workflow's sudo step, a session's, a root
//! action or kill, the reads only root can make. The password is asked once, in the key bar
//! (the session asks in its own window, the same line), when the first of them needs it and
//! sudo wants one; then it is held here for as long as the window is open and handed to each
//! command on its stdin (`sudo::wrap`). It goes at quit, when sudo refuses it, and with `C-f`.
//! The terminal is never handed over for it.

use super::*;
use crate::effect::RootRead;
use crate::run::How;
use sentry_core::apply::sudo::{self, Secret};

/// The password being asked for in the key bar, and what waits for it.
pub(crate) struct Unlock {
    /// What it's for, in the prompt.
    pub(crate) what: String,
    pub(crate) typed: Secret,
    pub(crate) tries: u8,
    /// sudo is checking what was typed (the check's stream).
    pub(crate) checking: Option<u64>,
    wait: Waiting,
}

/// What runs once root can be had.
pub(crate) enum Waiting {
    /// A command for the pane.
    Run(RunSpec),
    /// Something read quietly, for the target.
    Read(RootRead),
    /// The workflow run's step.
    Step {
        line: String,
        idx: usize,
        dry: bool,
        timeout: Option<Duration>,
    },
    /// The workflow run's reboot (the boot id it had).
    Reboot(String, String),
}

impl Slot {
    /// `line` (a shell command line with sudo in it) as a command on the target: with the
    /// password held, through `sudo::wrap`; without, its sudo fails at once rather than wait
    /// on a prompt nobody sees. `streamed`: its output is followed line by line (over ssh it
    /// keeps a terminal, so stopping it here stops it there).
    pub(crate) fn root_cmd(&self, line: &str, streamed: bool) -> sentry_core::exec::Cmd {
        let c = if !self.secret_ok {
            self.target.command(&sudo::no_prompt(line))
        } else if streamed {
            self.target
                .command(&sudo::wrap_ready(line))
                .input_after(sudo::READY, self.secret.stdin())
        } else {
            self.target
                .command(&sudo::wrap(line))
                .input(self.secret.stdin())
        };
        c.timeout(None)
    }

    /// Do `wait` as root: now, when the password is held or sudo doesn't ask for one; else
    /// after the one prompt (`what`: what it says the password is for).
    pub(crate) fn with_root(&mut self, w: &mut Win, what: String, wait: Waiting) {
        if self.secret_ok {
            return self.rooted(w, wait);
        }
        let asks = self.target.sudo_asks(&cx!(self, w));
        match asks {
            Ok(false) => self.rooted(w, wait),
            Ok(true) => {
                self.unlock = Some(Unlock {
                    what,
                    typed: Secret::default(),
                    tries: 0,
                    checking: None,
                    wait,
                });
                w.dirty = true;
            }
            Err(why) => {
                w.toast(&why);
                self.unrooted(w, wait);
            }
        }
    }

    /// Root can be had: what waited runs.
    fn rooted(&mut self, w: &mut Win, wait: Waiting) {
        match wait {
            Waiting::Run(mut spec) => {
                if let Some(line) = spec.root.take() {
                    spec.cmd = self.root_cmd(&line, true);
                    return self.start_pane(w, spec, Some(line));
                }
                self.start_pane(w, spec, None)
            }
            Waiting::Read(r) => {
                let id = self.mail.next();
                let cmd = self.root_cmd(&r.line, false);
                self.reads.insert(id, r.own);
                if !w.offline {
                    self.mail.text(id, cmd);
                }
            }
            Waiting::Step {
                line,
                idx,
                dry,
                timeout,
            } => {
                let cmd = self.root_cmd(&line, true);
                self.wf_stream(w, cmd, idx, dry, timeout);
            }
            Waiting::Reboot(line, old) => {
                let cmd = self.root_cmd(&line, true);
                let e = self.target.reboot(cmd, old, &cx!(self, w));
                self.apply(w, e, w.at);
            }
        }
    }

    /// The password wasn't given (Esc, refused three times, no sudo): what waited doesn't
    /// run, and says so where it would have shown.
    fn unrooted(&mut self, w: &mut Win, wait: Waiting) {
        const WHY: &str = "sudo needs your password, which wasn't given";
        match wait {
            Waiting::Run(spec) => w.toast(&format!("{}: not run", spec.title)),
            Waiting::Read(r) => self.apply(w, r.skipped, w.at),
            Waiting::Step { idx, dry, .. } => {
                if let Some(s) = self.run.as_mut() {
                    s.spawn_failed(idx, dry, WHY);
                }
                self.wf_auto(w);
            }
            Waiting::Reboot(..) => {
                if let Some(s) = self.run.as_mut() {
                    s.push(format!("✗ the reboot didn't start: {WHY}"), LogKind::Err);
                }
            }
        }
        w.dirty = true;
    }

    /// A key while the password is asked for: it's typed, checked on Enter, dropped on Esc.
    pub(crate) fn unlock_key(&mut self, w: &mut Win, k: KeyEvent) {
        use ratatui::crossterm::event::{KeyCode, KeyModifiers};
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let Some(u) = self.unlock.as_mut() else {
            return;
        };
        if u.checking.is_some() {
            return;
        }
        match k.code {
            KeyCode::Esc => {
                if let Some(u) = self.unlock.take() {
                    self.unrooted(w, u.wait);
                }
            }
            KeyCode::Char('c') if ctrl => {
                if let Some(u) = self.unlock.take() {
                    self.unrooted(w, u.wait);
                }
            }
            KeyCode::Char(c) if !ctrl => u.typed.push(c),
            KeyCode::Backspace => u.typed.pop(),
            KeyCode::Enter if !u.typed.is_empty() => {
                let id = self.mail.next();
                u.checking = Some(id);
                let cmd = self
                    .target
                    .command(sudo::check_script())
                    .input(u.typed.stdin())
                    .timeout(None);
                if !w.offline
                    && let Err(e) = self.mail.stream(id, &cmd)
                {
                    w.toast(&format!("couldn't run sudo: {e}"));
                    if let Some(u) = self.unlock.take() {
                        self.unrooted(w, u.wait);
                    }
                }
            }
            _ => {}
        }
    }

    /// A paste while the password is asked for: all of it is typed.
    pub(crate) fn unlock_paste(&mut self, text: &str) {
        if let Some(u) = self.unlock.as_mut().filter(|u| u.checking.is_none()) {
            text.trim_end_matches(['\r', '\n'])
                .chars()
                .for_each(|c| u.typed.push(c));
        }
    }

    /// sudo's check of the password typed in the key bar ended. True: it was that stream.
    pub(crate) fn unlock_stream(&mut self, w: &mut Win, id: u64, m: &StreamMsg) -> bool {
        if self.unlock.as_ref().and_then(|u| u.checking) != Some(id) {
            return false;
        }
        let StreamMsg::Exit { code, .. } = m else {
            return true;
        };
        let Some(mut u) = self.unlock.take() else {
            return true;
        };
        u.checking = None;
        if *code == 0 {
            self.hold(u.typed.take());
            self.rooted(w, u.wait);
        } else if u.tries + 1 >= 3 {
            w.toast("sudo refused the password 3 times; nothing ran");
            self.unrooted(w, u.wait);
        } else {
            u.typed.clear();
            u.tries += 1;
            self.unlock = Some(u);
        }
        true
    }

    /// sudo accepted the password: it's held for this target from now on.
    pub(crate) fn hold(&mut self, secret: Secret) {
        self.secret = secret;
        self.secret_ok = true;
        if let Some(s) = self.apply.as_mut() {
            s.secret_ok = true;
        }
    }

    /// Forget the password (`C-f`, a password sudo refused): the next thing that needs it
    /// asks again. True: one was held.
    pub(crate) fn forget(&mut self) -> bool {
        let held = self.secret_ok;
        self.secret.clear();
        self.secret_ok = false;
        if let Some(s) = self.apply.as_mut() {
            s.password_gone();
        }
        held
    }

    /// A line a command run with the held password printed: sudo refusing that password
    /// means it's wrong now, so it isn't used again.
    pub(crate) fn saw_line(&mut self, w: &mut Win, text: &str) {
        if self.secret_ok && sudo::wrong_password(text) {
            self.forget();
            w.toast("sudo refused the password: forgotten, and asked for again next time");
        }
    }

    /// Something read as root came back: it's the target's.
    pub(crate) fn read_back(&mut self, w: &mut Win, id: u64, res: Result<String, String>) -> bool {
        let Some(own) = self.reads.remove(&id) else {
            return false;
        };
        if let Err(e) = &res {
            self.saw_line(w, e);
        }
        let e = self
            .target
            .root_read(&own, res, &mut self.shared, &cx!(self, w));
        self.apply(w, e, w.at);
        true
    }

    /// The reads under way, oldest first (tests).
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn reads_for_test(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.reads.keys().copied().collect();
        ids.sort();
        ids
    }

    /// The workflow step's command (or its reboot), as the run said to run it.
    pub(crate) fn wf_how(
        &mut self,
        w: &mut Win,
        how: How,
        idx: usize,
        dry: bool,
        timeout: Option<Duration>,
    ) {
        match how {
            How::Plain(cmd) => self.wf_stream(w, cmd, idx, dry, timeout),
            How::Root(line) => {
                let what = match self.run.as_ref() {
                    Some(s) => format!("for {} · step {}", s.wf().name, idx + 1),
                    None => "for this step".into(),
                };
                self.with_root(
                    w,
                    what,
                    Waiting::Step {
                        line,
                        idx,
                        dry,
                        timeout,
                    },
                );
            }
        }
    }
}

//! Work this slot does for a session that started on another target, and what its own
//! session hears back from the others (`crate::system::Parcel`). A step that is `on` this
//! target runs here exactly as this target runs its own: through `Host::command` and
//! `root_cmd` (this slot's password, this host's policy), its output shown as this target
//! lets Claude see it. One thing at a time: while this slot is busy with a run, a session or
//! a pane of its own, the step waits and says so; if that lasts, the session hears that the
//! step was never started (not that it failed).

use super::*;
use crate::system::Parcel;
use sentry_core::apply::sudo;

/// A step running here for a session elsewhere.
pub(crate) struct Guest {
    pub(crate) from: String,
    pub(crate) id: u64,
    pub(crate) pid: u32,
    /// For the banner row here: whose session, and what it runs.
    pub(crate) what: String,
}

/// A step that waits for this slot to be free.
pub(crate) struct GuestWait {
    from: String,
    cmd: String,
    sudo: bool,
    what: String,
    since: Instant,
}

/// How long a step waits for a busy target before the session is told.
pub const GUEST_WAIT: Duration = Duration::from_secs(120);

impl Slot {
    /// This target as a session needs to know it, on whichever target it started.
    pub(crate) fn surveyed(&self, w: &Win) -> crate::system::Sys {
        crate::system::Sys {
            peer: self.target.peer(),
            line: self.target.describe(&self.shared, &cx!(self, w)),
            reach: self.target.profile(ProfileFor::Peer, &[]),
        }
    }

    fn send(&self, w: &mut Win, to: &str, p: Parcel) {
        w.outbox.push_back((to.to_string(), p));
    }

    /// What this slot is busy with of its own, in words (None: free for a guest's step).
    fn busy_with(&self) -> Option<String> {
        if let Some(r) = self.run.as_ref().filter(|r| !r.done()) {
            return Some(format!("its workflow {}", r.wf().name));
        }
        if let Some(s) = self.apply.as_ref().filter(|s| s.busy()) {
            return Some(format!(
                "its own session ({})",
                s.chat.ask.subject.trim_start_matches("apply · ")
            ));
        }
        if let Some(p) = self.pane.as_ref().filter(|p| p.done.is_none()) {
            return Some(p.title.clone());
        }
        self.guest.as_ref().map(|g| g.what.clone())
    }

    /// A parcel for this slot: a session elsewhere asks something of this target, or one
    /// of the others answers this slot's session.
    pub(crate) fn parcel(&mut self, w: &mut Win, p: Parcel) {
        use sentry_core::apply::session::Phase;
        w.dirty = true;
        let me = self.mail.id().clone();
        // What the window's sessions hold in secret is this target's to keep out of
        // what it writes by itself, before anything of theirs runs here.
        let held = self.sweep.values();
        if !held.is_empty() {
            self.target.given(&held);
        }
        match p {
            Parcel::Wake => {
                if std::mem::take(&mut self.asleep) {
                    self.start(w, w.at);
                }
            }
            Parcel::Step {
                from,
                cmd,
                sudo,
                what,
            } => {
                if let Some(busy) = self.busy_with() {
                    self.send(
                        w,
                        &from,
                        Parcel::Waiting(format!("waiting for {} to finish {busy}", self.title)),
                    );
                    self.guest_wait = Some(GuestWait {
                        from,
                        cmd,
                        sudo,
                        what,
                        since: w.at,
                    });
                    return;
                }
                self.guest_run(w, from, cmd, sudo, what);
            }
            Parcel::CheckSudo { from } => {
                let reply = if self.secret_ok {
                    Parcel::Held { on: me }
                } else {
                    match self.target.sudo_asks(&cx!(self, w)) {
                        Ok(needs) => Parcel::SudoChecked { on: me, needs },
                        // No sudo to use: the step says so when it runs.
                        Err(why) => {
                            w.toast(&why);
                            Parcel::SudoChecked {
                                on: me,
                                needs: false,
                            }
                        }
                    }
                };
                self.send(w, &from, reply);
            }
            Parcel::CheckPassword { from, typed } => {
                let c = self
                    .target
                    .command(sudo::check_script())
                    .input(typed.stdin())
                    .timeout(None);
                let id = self.mail.next();
                self.guest_aux = Some((id, from.clone(), typed));
                if !w.offline
                    && let Err(e) = self.mail.stream(id, &c)
                {
                    self.guest_aux = None;
                    w.toast(&format!("couldn't run sudo: {e}"));
                    self.send(w, &from, Parcel::PasswordChecked { on: me, ok: false });
                }
            }
            Parcel::Workflow { from, name, vars } => {
                if self.shared.wf_entries.is_empty() && !w.offline {
                    self.load_wf_entries();
                }
                if let Some(why) = self.wf_refusal(w, &name) {
                    return self.send(
                        w,
                        &from,
                        Parcel::WorkflowEnded {
                            on: me,
                            name,
                            ok: false,
                            note: format!("not started: {why}"),
                        },
                    );
                }
                self.guest_wf = Some((from, name.clone()));
                let own = self
                    .target
                    .session_starts(&name, &vars, &self.shared, &cx!(self, w));
                let e = own.unwrap_or_else(|| {
                    vec![Effect::Wf(WfCmd::BeginPrefilled(name.clone(), vars, None))]
                });
                self.apply(w, e, w.at);
                // It didn't start (its values dismissed, a lint error): the session hears.
                if self.run.as_ref().is_none_or(|r| r.wf().name != name)
                    && !w.input.is_open()
                    && let Some((from, name)) = self.guest_wf.take()
                {
                    self.send(
                        w,
                        &from,
                        Parcel::WorkflowEnded {
                            on: me,
                            name,
                            ok: false,
                            note: "not started".into(),
                        },
                    );
                }
            }
            Parcel::Facts => {
                if !self.asleep {
                    self.refresh(w, Why::Facts);
                }
            }
            Parcel::Entry(e) => {
                self.log_event(w, *e);
            }
            Parcel::Log { ok, body, tags } => {
                let e = sentry_core::maint::log::LogEntry::event(
                    &self.scope,
                    "apply",
                    "apply",
                    ok,
                    &body,
                    &tags,
                    jiff::Timestamp::now(),
                );
                self.log_event(w, e);
            }
            // ---- answers, for this slot's own session
            Parcel::Started { id, pid } => {
                if let Some(s) = self.apply.as_mut() {
                    s.step_started(id, pid);
                }
            }
            Parcel::Line { shown, raw, stderr } => {
                if let Some(s) = self.apply.as_mut() {
                    s.step_said(shown, &raw, stderr);
                }
            }
            Parcel::Waiting(text) => {
                if let Some(s) = self.apply.as_mut() {
                    s.step_line(text);
                }
            }
            Parcel::Exit { code } => {
                if let Some(s) = self.apply.as_mut() {
                    let fx = s.step_ended(code);
                    self.apply_fx(w, fx);
                }
            }
            Parcel::Deferred(why) => {
                if let Some(s) = self.apply.as_mut() {
                    let fx = s.step_deferred(&why);
                    self.apply_fx(w, fx);
                }
            }
            Parcel::SudoChecked { on, needs } => {
                if let Some(s) = self
                    .apply
                    .as_mut()
                    .filter(|s| s.sudo_for.as_deref() == Some(&on))
                {
                    let fx = s.sudo_checked(needs);
                    self.apply_fx(w, fx);
                }
            }
            Parcel::Held { on } => {
                if let Some(s) = self.apply.as_mut() {
                    let fx = s.password_held_on(&on);
                    self.apply_fx(w, fx);
                }
            }
            Parcel::Forgot { on } => {
                if let Some(s) = self.apply.as_mut() {
                    s.password_gone_on(&on);
                }
            }
            Parcel::PasswordChecked { on, ok } => {
                if let Some(s) = self.apply.as_mut().filter(|s| {
                    s.sudo_for.as_deref() == Some(&on) && matches!(s.phase, Phase::Password { .. })
                }) {
                    let fx = s.password_checked(ok);
                    self.apply_fx(w, fx);
                }
            }
            Parcel::WorkflowEnded { on, name, ok, note } => {
                if let Some(s) = self.apply.as_mut() {
                    let fx = s.workflow_ended_on(&on, &name, ok, note);
                    s.chat.hidden = false;
                    self.apply_fx(w, fx);
                }
            }
        }
    }

    /// Run a guest's step here, as one of this target's own.
    fn guest_run(&mut self, w: &mut Win, from: String, cmd: String, sudo: bool, what: String) {
        let me = self.mail.id().clone();
        // The password this slot held is gone and sudo wants one: the session asks for it
        // again with its next plan, rather than the step failing on a prompt nobody sees.
        if sudo && !self.secret_ok && self.target.sudo_asks(&cx!(self, w)) == Ok(true) {
            self.send(w, &from, Parcel::Forgot { on: me });
            self.send(
                w,
                &from,
                Parcel::Line {
                    shown: format!(
                        "sudo on {} wants its password, which isn't held any more: send the \
                         plan again and it is asked for",
                        self.title
                    ),
                    raw: String::new(),
                    stderr: true,
                },
            );
            return self.send(w, &from, Parcel::Exit { code: 1 });
        }
        let c = if sudo && self.secret_ok {
            self.root_cmd(&cmd, true)
        } else {
            self.target.command(&sudo::detached(&cmd)).timeout(None)
        };
        let id = self.mail.next();
        let r = if w.offline {
            self.last_guest_cmd = Some(c.quoted_argv());
            Ok(0)
        } else {
            self.mail.stream(id, &c).map_err(|e| e.to_string())
        };
        match r {
            Ok(pid) => {
                self.guest = Some(Guest {
                    from: from.clone(),
                    id,
                    pid,
                    what,
                });
                self.send(w, &from, Parcel::Started { id, pid });
            }
            Err(e) => {
                self.send(
                    w,
                    &from,
                    Parcel::Line {
                        shown: format!("couldn't start it: {e}"),
                        raw: String::new(),
                        stderr: true,
                    },
                );
                self.send(w, &from, Parcel::Exit { code: -1 });
            }
        }
    }

    /// A stream that belongs to a guest's step, or to the check of a password typed in a
    /// session elsewhere for this target.
    pub(crate) fn guest_stream(&mut self, w: &mut Win, id: u64, m: &StreamMsg) -> bool {
        let me = self.mail.id().clone();
        if self.guest.as_ref().is_some_and(|g| g.id == id) {
            let from = self
                .guest
                .as_ref()
                .map(|g| g.from.clone())
                .unwrap_or_default();
            match m {
                StreamMsg::Line { text, stderr } => {
                    self.saw_line(w, text);
                    // What goes back to Claude is what this target lets it see.
                    let shown = self.target.hides(text).unwrap_or_else(|| text.clone());
                    self.send(
                        w,
                        &from,
                        Parcel::Line {
                            shown,
                            raw: text.clone(),
                            stderr: *stderr,
                        },
                    );
                }
                StreamMsg::Exit { code, .. } => {
                    self.guest = None;
                    if !self.secret_ok {
                        self.send(w, &from, Parcel::Forgot { on: me });
                    }
                    self.send(w, &from, Parcel::Exit { code: *code });
                    self.refresh(w, Why::Step);
                }
            }
            return true;
        }
        if self.guest_aux.as_ref().is_some_and(|(aid, ..)| *aid == id) {
            if let StreamMsg::Exit { code, .. } = m
                && let Some((_, from, mut typed)) = self.guest_aux.take()
            {
                let ok = *code == 0;
                if ok {
                    // Accepted: held here from now on, for everything on this target.
                    self.hold(typed.take());
                }
                typed.clear();
                self.send(w, &from, Parcel::PasswordChecked { on: me, ok });
            }
            return true;
        }
        false
    }

    /// Each tick: a step that waited runs once this slot is free; one that waited too
    /// long goes back to its session as never started.
    pub(crate) fn guest_tick(&mut self, w: &mut Win, now: Instant) {
        let Some(g) = self.guest_wait.as_ref() else {
            return;
        };
        match self.busy_with() {
            None => {
                if let Some(g) = self.guest_wait.take() {
                    self.guest_run(w, g.from, g.cmd, g.sudo, g.what);
                }
            }
            Some(busy) if now.duration_since(g.since) >= GUEST_WAIT => {
                let why = format!(
                    "{} was still busy with {busy} after {} s",
                    self.title,
                    GUEST_WAIT.as_secs()
                );
                if let Some(g) = self.guest_wait.take() {
                    self.send(w, &g.from, Parcel::Deferred(why));
                }
            }
            Some(_) => {}
        }
    }

    /// A workflow run here ended: the session elsewhere whose plan started it hears.
    pub(crate) fn guest_run_ended(&mut self, w: &mut Win, e: &sentry_core::maint::log::LogEntry) {
        let h = &e.head;
        if self.guest_wf.as_ref().is_none_or(|(_, n)| *n != h.workflow) {
            return;
        }
        let Some((from, name)) = self.guest_wf.take() else {
            return;
        };
        let note = format!("{} {}: {}", h.workflow, h.result, h.summary);
        let note = self.target.hides(&note).unwrap_or(note);
        let me = self.mail.id().clone();
        self.send(
            w,
            &from,
            Parcel::WorkflowEnded {
                on: me,
                name,
                ok: h.result == "done",
                note,
            },
        );
    }

    /// The session's `Fx::On`: handed to the app for the slot of that target.
    pub(crate) fn apply_fx_on(
        &mut self,
        w: &mut Win,
        to: String,
        fx: sentry_core::apply::session::Fx,
    ) {
        use sentry_core::apply::session::Fx;
        let from = self.mail.id().clone();
        let Some(sess) = self.apply.as_ref() else {
            return;
        };
        let what = format!(
            "session on {} · {}",
            self.title,
            sess.chat.ask.subject.trim_start_matches("apply · ")
        );
        let p = match fx {
            Fx::Command { cmd, sudo } => Parcel::Step {
                from,
                cmd,
                sudo,
                what,
            },
            Fx::CheckSudo => Parcel::CheckSudo { from },
            Fx::CheckPassword => Parcel::CheckPassword {
                from,
                typed: sess.secret.clone(),
            },
            Fx::StartWorkflow(name, vars) => Parcel::Workflow { from, name, vars },
            Fx::Log { ok, body, tags } => Parcel::Log { ok, body, tags },
            _ => return,
        };
        // A target the window lost (it can't: targets stay for as long as it's open).
        if !w.system.iter().any(|s| s.peer.id == to) {
            return;
        }
        w.outbox.push_back((to, p));
    }
}

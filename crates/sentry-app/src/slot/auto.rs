//! Auto mode (`C-a`): while it's on for this target, the questions `sentry_core::auto`
//! allows are answered without a key, each where it would have been asked: the session's
//! brief, plan and requests (`Session::auto_go`), a workflow's values and confirm steps, the
//! note after a run, a series' next row. Everything else stops and asks as with auto off.
//! Off at start, never saved; turning it on asks for the sudo password at once when the
//! target's sudo wants one and none is held, so nothing asks for it later.

use super::*;
use sentry_core::auto::{Asked, answers, never};

/// The key, as the key bar and `?` name it.
pub const KEY: &str = "C-a";

impl Slot {
    /// The key bar's word for the key.
    pub(crate) fn auto_hint(&self) -> (&'static str, &'static str) {
        (KEY, if self.auto { "auto off" } else { "auto" })
    }

    /// `C-a`: on or off, for this target.
    pub(crate) fn auto_toggle(&mut self, w: &mut Win) {
        if self.auto {
            self.auto_set(false);
            // Its own prompt goes with it (the password, if held, is kept: `C-f` forgets it).
            if self.unlock.as_ref().is_some_and(|u| u.for_auto()) {
                self.unlock = None;
            }
            return w.toast("auto is off: every step asks again");
        }
        self.auto_set(true);
        self.auto_held = None;
        w.toast("auto is on · reboots and the like still ask");
        // The last prompt: the password, when sudo wants one and none is held. (One being
        // asked for already, for something else, is that prompt.)
        if self.unlock.is_none() {
            self.with_root(w, "for auto mode".into(), root::Waiting::Auto);
        }
    }

    pub(crate) fn auto_set(&mut self, on: bool) {
        self.auto = on;
        if let Some(s) = self.apply.as_mut() {
            s.auto = on;
        }
    }

    /// Whatever waits for a key that auto may give gets it. Called wherever something may
    /// have come to such a point (a turn or a step ended, a run moved, the mode went on);
    /// what it starts may bring the next one, so it goes round until nothing moves.
    pub(crate) fn auto_step(&mut self, w: &mut Win) {
        if !self.auto || self.unlock.is_some() {
            return;
        }
        if self.auto_busy {
            self.auto_again = true;
            return;
        }
        self.auto_busy = true;
        for _ in 0..16 {
            self.auto_again = false;
            self.auto_session(w);
            self.auto_series(w);
            self.auto_confirm(w);
            if !self.auto_again {
                break;
            }
        }
        self.auto_busy = false;
    }

    /// The session's brief, plan and requests.
    fn auto_session(&mut self, w: &mut Win) {
        for _ in 0..8 {
            let Some(sess) = self.apply.as_mut() else {
                return;
            };
            sess.auto = true;
            let fx = sess.auto_go();
            if fx.is_empty() {
                return;
            }
            self.apply_fx(w, fx);
        }
    }

    /// A series' row that didn't end done: auto doesn't go on past it. The series stops
    /// there, what's left stays ticked, and the session stays open to look at.
    fn auto_series(&mut self, w: &mut Win) {
        use sentry_core::apply::session::{End, Phase};
        use sentry_core::maint::series::Wait;
        if !self.series_waits(&Wait::Session) {
            return;
        }
        let Some(sess) = self.apply.as_mut() else {
            return;
        };
        let Phase::Settled(end) = sess.phase else {
            return;
        };
        let done = matches!(end, End::Done | End::Waited);
        if answers(true, &Asked::SeriesNext { done }) || sess.can_grant() {
            return;
        }
        sess.series = None;
        sess.chat.hidden = false;
        sess.chat.push(
            chatmod::Kind::Info,
            "auto: this one isn't done, so the series stops here · what's left stays ticked",
        );
        self.series_stop(w);
    }

    /// The run's step that waits for its confirm.
    fn auto_confirm(&mut self, w: &mut Win) {
        if self.modal.is_some() {
            return;
        }
        let Some(s) = self.run.as_deref_mut() else {
            return;
        };
        if !s.armed() || s.live().is_some() || s.done() {
            return;
        }
        let (i, confirm) = match *s.next() {
            Next::Confirm(i) => (i, true),
            Next::Reboot {
                idx,
                requested: false,
            }
            | Next::Shell(idx) => (idx, false),
            Next::Manual { idx, failed: false } => (idx, false),
            _ => return,
        };
        // Once for a step as it stands: confirmed or left to the user, it isn't tried or
        // said again until something about it changes (its dry run passed, it ran). So a
        // dry run that fails, or a step that can't start, is the user's from there.
        let key = (
            s.run().dir.clone(),
            i,
            s.run().state.steps[i].dry_ok,
            s.run().state.steps[i].started,
        );
        if self.auto_held.as_ref() == Some(&key) {
            return;
        }
        let step = s.wf().steps[i].clone();
        let cmd = s.command(i).unwrap_or_default();
        let asked = Asked::Step {
            step: &step,
            cmd: &cmd,
        };
        if !confirm || !answers(true, &asked) {
            let why = if step.risky {
                "it is marked risky"
            } else {
                match step.kind {
                    sentry_core::workflows::Kind::Reboot => "a reboot is yours to start",
                    sentry_core::workflows::Kind::Manual => "it is done by hand",
                    sentry_core::workflows::Kind::Shell => "it opens a shell",
                    sentry_core::workflows::Kind::Run => {
                        never(&cmd).unwrap_or("it is yours to decide")
                    }
                }
            };
            s.push(
                format!("auto leaves step {} to you: {why}", i + 1),
                LogKind::Info,
            );
            w.toast(&format!(
                "{}: step {} needs you ({why})",
                s.wf().name,
                i + 1
            ));
            self.auto_held = Some(key);
            return;
        }
        s.auto_answered(&format!("step:{}", step.id));
        s.push(format!("auto: confirmed {}", step.id), LogKind::Info);
        self.auto_held = Some(key);
        self.wf_cmd(w, WfCmd::Go);
        self.auto_again = true;
    }

    /// A workflow's values: with a default for each, auto takes them.
    pub(crate) fn auto_values(
        &mut self,
        asks: &[(String, String, Option<String>)],
    ) -> Option<BTreeMap<String, String>> {
        let defaults = asks
            .iter()
            .all(|(_, _, d)| d.as_ref().is_some_and(|d| !d.is_empty()));
        if !answers(self.auto, &Asked::Values { defaults }) {
            return None;
        }
        self.auto_took_values = true;
        Some(
            asks.iter()
                .map(|(k, _, d)| (k.clone(), d.clone().unwrap_or_default()))
                .collect(),
        )
    }

    /// The note for the log, about to be asked for: auto doesn't ask (the entry is logged
    /// without one; Records adds one any time). True: nothing is to be asked.
    pub(crate) fn auto_skips_note(&self) -> bool {
        answers(self.auto, &Asked::LogNote)
    }
}

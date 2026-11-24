//! The one path for "something that can change the Maintenance rows happened": the
//! records are read again, the target makes again what it derives from them and reads what
//! its rows need, the cursors follow, and Records, if open, shows what's there now.
//!
//! Every way a row is resolved ends here ([`Slot::rows_changed`]): a task done or removed,
//! a row put off or marked expected, a review's changes, a run or a session ending, an
//! entry in the log. What changed on disk without the app (an editor, Claude's allowed
//! edit, another program) is found by [`Slot::look`], which compares the files' times: on
//! `r`, on entering a screen, when the target gets the window back, after a turn of
//! Claude's and after an editor. Nothing watches in the background.

use std::path::PathBuf;
use std::time::SystemTime;

use super::*;

/// A file's (or directory's) time and size as last seen; None: it isn't there.
type Stamp = Option<(SystemTime, u64)>;

/// What the rows were made from, as the files stood when they were last read.
#[derive(Default, PartialEq)]
pub(crate) struct Stamps {
    /// The records every target has (`maint::root(scope)`).
    records: Vec<(PathBuf, Stamp)>,
    /// The target's own (`Target::files`).
    own: Vec<(PathBuf, Stamp)>,
}

fn stamp(p: &std::path::Path) -> Stamp {
    let m = std::fs::metadata(p).ok()?;
    Some((m.modified().ok()?, m.len()))
}

impl Slot {
    /// The files the rows are made from, as they stand now. A directory's time changes
    /// when a file is added to it or taken away (a plan removed by hand, a log entry
    /// written by another program).
    fn stamps(&self) -> Stamps {
        use sentry_core::maint;
        let records = [
            maint::tasks::path(&self.scope),
            maint::later::path(&self.scope),
            sentry_core::baseline::path(&self.scope),
            maint::plan::dir(&self.scope),
            maint::log::dir(&self.scope),
            maint::review::dir(&self.scope),
        ];
        let seen = |p: PathBuf| {
            let s = stamp(&p);
            (p, s)
        };
        Stamps {
            records: records.into_iter().map(seen).collect(),
            own: self.target.files().into_iter().map(seen).collect(),
        }
    }

    /// The records as they are on disk now.
    pub(crate) fn read_records(&mut self) {
        use sentry_core::maint;
        self.shared.later = maint::later::load(&self.scope);
        self.shared.baseline = sentry_core::baseline::BaselineFile::load(&self.scope);
        self.shared.plans = maint::plan::list(&self.scope);
        self.shared.review = maint::review::latest(&self.scope);
        self.shared.tasks = maint::tasks::load(&self.scope);
        self.shared.log = maint::log::list(&self.scope);
        self.stamps = self.stamps();
    }

    /// Something that can change the rows happened. Tests (offline) write and read
    /// nothing: what the flow put in memory is what there is.
    pub(crate) fn rows_changed(&mut self, w: &mut Win) {
        // Asleep (never in view): its records are read when it first has the window.
        if self.asleep {
            return;
        }
        if !w.offline {
            self.read_records();
        }
        self.rows_follow(w);
    }

    /// The records in memory are what there is now: everything made from them follows.
    fn rows_follow(&mut self, w: &mut Win) {
        // The audit's items it lists, as its log now says (an upgrade withholds some).
        self.sec_sync(w);
        self.refresh(w, Why::Lists);
        self.settle(w, Settle::Lists);
        // Records, if open, lists what there is now, where it was.
        if self.rec_view.is_some() {
            let data = self.records_data(w);
            if let Some(r) = self.rec_view.as_mut() {
                r.set_data(data);
            }
        }
        w.dirty = true;
    }

    /// What's on disk, if it isn't what was read: a file of the records, or one of the
    /// target's own, changed without the app. A handful of `stat`s.
    pub(crate) fn look(&mut self, w: &mut Win) {
        if !w.offline && !self.asleep {
            self.look_now(w);
            // (And the window at the security audit's reports: `App::sec_look`.)
            w.sec.look = true;
        }
    }

    /// (Tests call this one: their app is offline, and their files are a scratch scope's.)
    pub fn look_now(&mut self, w: &mut Win) -> bool {
        let now = self.stamps();
        if now == self.stamps {
            return false;
        }
        let own = now.own != self.stamps.own;
        self.read_records();
        // The target's own file first: its config as it is now decides the rest.
        if own {
            self.refresh(w, Why::Edited);
        }
        self.rows_follow(w);
        true
    }

    /// Tests: the target with what it is asked with (its records, the view), to see what
    /// it would make for Claude.
    #[cfg(any(test, feature = "testing"))]
    pub fn asks_for_test<R>(
        &self,
        w: &Win,
        f: impl FnOnce(&dyn crate::target::Target, &crate::shared::Shared, &crate::target::Cx) -> R,
    ) -> R {
        f(self.target.as_ref(), &self.shared, &cx!(self, w))
    }

    /// Tests: the keys of every row Maintenance lists (what can wait too).
    #[cfg(any(test, feature = "testing"))]
    pub fn rows_for_test(&self, w: &Win) -> Vec<String> {
        let mut rows = Vec::new();
        self.target
            .with_known(&self.shared, &cx!(self, w), &mut |k| {
                rows = k.rows.iter().map(|(key, _)| key.clone()).collect();
            });
        rows
    }

    /// Tests: the key of the row the cursor is on.
    #[cfg(any(test, feature = "testing"))]
    pub fn row_at_for_test(&self, w: &Win) -> Option<String> {
        self.target.row_at(&self.shared, &cx!(self, w))
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn everything_for_test(&self) -> bool {
        self.everything
    }

    /// Tests: Records › Later's row with this key, taken back (`u`). False: no such row.
    #[cfg(any(test, feature = "testing"))]
    pub fn undo_for_test(&mut self, w: &mut Win, key: &str) -> bool {
        use sentry_core::tui::records::{LaterKind, LaterRow};
        let (own, _) = self.target.records(&self.shared, &cx!(self, w));
        let row = if let Some(d) = self.shared.later.get(key) {
            LaterRow {
                kind: LaterKind::Snoozed(*d),
                key: key.to_string(),
                file: "later.toml",
            }
        } else if let Some(r) = own.into_iter().find(|r| r.key == key) {
            r
        } else if self.shared.baseline.findings.iter().any(|f| f == key) {
            LaterRow {
                kind: LaterKind::Expected,
                key: key.to_string(),
                file: "baseline.toml",
            }
        } else {
            return false;
        };
        self.records_undo(w, row, w.at);
        true
    }

    /// Tests: a plan kept under `key`, on disk too (what `look` then finds or misses).
    #[cfg(any(test, feature = "testing"))]
    pub fn plan_keep_for_test(&mut self, w: &mut Win, key: &str, body: &str) {
        self.plan_keep(w, key, body, PlanStatus::Ready);
        if let Some(doc) = self.shared.plans.get(key) {
            sentry_core::maint::plan::save(doc).expect("the plan's file");
        }
    }
}

/// What already read a host after a change sentry made to it (`Slot::host_changed`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Covered {
    /// The target's own audit (a finding's session audits again after its plan).
    pub own_audit: bool,
    /// The security audit, every target (a session on one of its items waits for it).
    pub security: bool,
}

impl Covered {
    /// What a session's own audit read after the steps it logs.
    pub(crate) fn by(s: Option<&sentry_core::apply::session::Session>) -> Self {
        Self {
            own_audit: s.is_some_and(|s| s.reaudit_covers_its_changes()),
            security: s.is_some_and(|s| s.audit_covers_its_changes()),
        }
    }
}

impl Slot {
    /// sentry changed the host (`LogEntry::changed_host`: a run or a session's steps that
    /// ended well, here or for a session elsewhere): what was read of it is a snapshot from
    /// before, so it is read again, and the window knows (the security audit looks again
    /// once nothing is at work, `App::sec_after_change`; until then what the report said of
    /// what the change may have settled isn't a row). The one place `last_change_at` is
    /// set. `covered`: what already read the host after the change (a session's own audit).
    pub(crate) fn host_changed(
        &mut self,
        w: &mut Win,
        entry: &sentry_core::maint::log::LogEntry,
        covered: Covered,
    ) {
        self.last_change_at = Some(jiff::Timestamp::now());
        if let Some(log) = self.slept_log.as_mut() {
            log.insert(0, entry.clone());
        }
        // (A slot never in view reads what it shows when it first has the window.)
        if !self.asleep {
            let why = if covered.own_audit {
                Why::ChangedAudited
            } else {
                Why::Changed
            };
            self.refresh(w, why);
        }
        if !covered.security
            && let Some(c) = crate::secaudit::Changed::of(self.mail.id(), entry)
        {
            w.sec.note(c);
        }
    }

    /// What the log says sentry changed on this target since the security audit's report
    /// (a run while the window was closed, or by `sentry` on the command line): kept by the
    /// window once, at the slot's start (its own, or the window's for one never in view).
    pub(crate) fn note_logged_changes(&mut self, w: &mut Win) {
        if std::mem::replace(&mut self.changes_noted, true) {
            return;
        }
        let Some(to) = w.sec.report.as_ref().map(|r| r.at) else {
            // (No report: the first one is from after every change.)
            return;
        };
        let id = self.mail.id().clone();
        for e in self.host_log(w) {
            if let Some(c) = crate::secaudit::Changed::of(&id, &e)
                && c.at > to
            {
                w.sec.note(c);
            }
        }
    }

    /// The entries of this target's log that changed the host. A slot that never had the
    /// window hasn't read its log: it is read here, once.
    pub(crate) fn host_log(&mut self, w: &Win) -> Vec<sentry_core::maint::log::LogEntry> {
        let changed = |v: Vec<sentry_core::maint::log::LogEntry>| {
            v.into_iter().filter(|e| e.changed_host()).collect()
        };
        if self.asleep && !w.offline {
            let scope = self.scope.clone();
            return self
                .slept_log
                .get_or_insert_with(|| changed(sentry_core::maint::log::list(&scope)))
                .clone();
        }
        changed(self.shared.log.clone())
    }
}

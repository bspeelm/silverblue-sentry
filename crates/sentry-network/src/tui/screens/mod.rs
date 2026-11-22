//! The network target's screens: `1` Dashboard, `2` Clients, `3` Network, `4` Security,
//! `6` Maintenance,
//! `0` Upgrade (the shared `remote::wfview`) and `H` History. Their numbers and names are
//! sentry's (`super::SCREENS`).

pub mod clients;
pub mod dashboard;
pub mod history;
pub mod maint;
pub mod network;
pub mod report;
pub mod security;
pub mod threats;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Color;

use super::data::Store;
use super::target::Effect;
use crate::config::Network;
use sentry_app::remote::wfview;
use sentry_core::tui::keys::Action;
use sentry_core::tui::theme::Theme;
use sentry_core::tui::{Cursor, ScreenId};

pub type Hints = Vec<(&'static str, &'static str)>;

/// What a screen draws from.
pub struct View<'a> {
    pub t: &'a Theme,
    pub s: &'a Store,
    /// The network's records (tasks, the log, what's expected or put off): the app's.
    pub sh: &'a sentry_app::shared::Shared,
    pub cfg: &'a Network,
    /// The network's name.
    pub name: &'a str,
    /// The row selected on the screen in view (a copy of its cursor).
    pub cur: usize,
    pub now: jiff::Timestamp,
    /// The screen's `/` filter, when one is set.
    pub filter: Option<&'a str>,
    /// Maintenance lists what can wait too (`o`).
    pub everything: bool,
    /// The workflow run in progress (or just ended).
    pub wf: Option<&'a crate::workflow::Session>,
    pub auto: bool,
    /// The window's other targets, as last surveyed: what each says of itself
    /// (`SystemLine::facts`; a server's guard, for Security).
    pub system: &'a [sentry_app::system::Sys],
    /// Security's list being gone through (`Security::group`).
    pub group: Option<String>,
}

impl View<'_> {
    /// Case-insensitive substring match of the filter against any field.
    pub fn matches(&self, fields: &[&str]) -> bool {
        match self.filter {
            None => true,
            Some(f) => {
                let f = f.to_lowercase();
                fields.iter().any(|x| x.to_lowercase().contains(&f))
            }
        }
    }

    pub fn secs_since(&self, t: jiff::Timestamp) -> i64 {
        self.now.as_second() - t.as_second()
    }

    /// The same view with the cursor elsewhere.
    pub fn at(&self, cur: usize) -> View<'_> {
        View {
            t: self.t,
            s: self.s,
            sh: self.sh,
            cfg: self.cfg,
            name: self.name,
            cur,
            now: self.now,
            filter: self.filter,
            everything: self.everything,
            wf: self.wf,
            auto: self.auto,
            system: self.system,
            group: self.group.clone(),
        }
    }
}

/// Every screen's own state.
#[derive(Default)]
pub struct Screens {
    pub clients: clients::Clients,
    pub net: network::Network,
    pub security: security::Security,
    pub maint: maint::Maint,
    pub hist: history::History,
    pub upgrade: wfview::Upgrade,
}

/// The Upgrade screen as the shared view draws it, in a router's words.
fn upgrade<'a>(v: &'a View, cur: usize) -> wfview::Shown<'a> {
    wfview::Shown {
        t: v.t,
        wf: v.wf,
        list: &v.sh.wf_list,
        cur,
        name: v.name,
        auto: v.auto,
        words: crate::workflow::WORDS,
        prog: crate::workflow::PROG,
        reboot: "reboot",
        none: "No workflows: a network's own go in ~/.config/sentry/networks/<name>/workflows/.",
    }
}

impl Screens {
    /// The screens that take a `/` filter.
    pub fn filterable(id: ScreenId) -> bool {
        matches!(
            id,
            ScreenId::Clients | ScreenId::Net | ScreenId::Security | ScreenId::Maint
        )
    }

    fn cursor_mut(&mut self, id: ScreenId) -> Option<&mut Cursor> {
        match id {
            ScreenId::Clients => Some(&mut self.clients.cur),
            ScreenId::Net => Some(&mut self.net.cur),
            ScreenId::Security => Some(self.security.cursor()),
            ScreenId::Maint => Some(&mut self.maint.cur),
            ScreenId::Upgrade => Some(&mut self.upgrade.cur),
            _ => None,
        }
    }

    /// The row selected on the screen.
    pub fn cur(&self, id: ScreenId) -> usize {
        match id {
            ScreenId::Clients => self.clients.cur.sel,
            ScreenId::Net => self.net.cur.sel,
            ScreenId::Security => self.security.at(),
            ScreenId::Maint => self.maint.cur.sel,
            ScreenId::Upgrade => self.upgrade.cur.sel,
            _ => 0,
        }
    }

    /// The selectable rows the screen has now.
    fn rows(&self, id: ScreenId, v: &View) -> usize {
        match id {
            ScreenId::Clients => self.clients.count(v),
            ScreenId::Net => network::rows(v).len(),
            ScreenId::Security => self.security.count(v),
            ScreenId::Maint => self.maint.count(v),
            ScreenId::Upgrade if v.wf.is_none() => v.sh.wf_list.len(),
            _ => 0,
        }
    }

    /// A key on the screen: moving is the cursor's, the rest is the screen's.
    pub fn handle(&mut self, id: ScreenId, a: Action, v: &View) -> Vec<Effect> {
        // A view over Maintenance has its own list; History has none (the arrows scrub).
        if id == ScreenId::Maint && self.maint.view.is_some() {
            return self.maint.handle(a, v);
        }
        if id == ScreenId::Hist {
            return self.hist.handle(a, v);
        }
        let n = self.rows(id, v);
        if let Some(c) = self.cursor_mut(id)
            && c.nav(a, n)
        {
            // Security's list: the row the cursor is on now is the one it stays on.
            if id == ScreenId::Security && !self.security.panels {
                let at = self.security.cur.sel;
                self.security.sel = threats::row_key(&v.at(at));
            }
            return Vec::new();
        }
        match id {
            ScreenId::Clients => self.clients.handle(a, v),
            ScreenId::Net => self.net.handle(a, v),
            ScreenId::Security => self.security.handle(a, v),
            ScreenId::Maint => self.maint.handle(a, v),
            ScreenId::Upgrade => self.upgrade.handle(a, &upgrade(v, v.cur)),
            _ => dashboard::handle(a),
        }
    }

    pub fn render(&mut self, id: ScreenId, f: &mut Frame, area: Rect, v: &View) {
        match id {
            ScreenId::Clients => self.clients.render(f, area, v),
            ScreenId::Net => self.net.render(f, area, v),
            ScreenId::Security => self.security.render(f, area, v),
            ScreenId::Maint => self.maint.render(f, area, v),
            ScreenId::Hist => self.hist.render(f, area, v),
            ScreenId::Upgrade => wfview::draw(f, area, &upgrade(v, v.cur)),
            _ => dashboard::render(f, area, v),
        }
    }

    pub fn hints(&self, id: ScreenId, v: &View) -> Hints {
        match id {
            ScreenId::Clients => clients::hints(),
            ScreenId::Net => network::hints(),
            ScreenId::Security if self.security.panels => security::hints(),
            ScreenId::Security => threats::hints(v),
            ScreenId::Maint if self.maint.view.is_some() => report::hints(v),
            ScreenId::Maint => maint::hints(v, maint::ticked(v, &self.maint.ticks)),
            ScreenId::Upgrade => wfview::hints(v.wf),
            ScreenId::Hist => history::hints(),
            _ => dashboard::hints(),
        }
    }

    /// The count shown next to the screen's name.
    pub fn badge(&self, id: ScreenId, v: &View) -> Option<(String, Color)> {
        let t = v.t;
        match id {
            ScreenId::Maint => maint::badge(v),
            // Devices nobody named, and listeners nothing expects.
            ScreenId::Clients => {
                let new = clients::counts(v)?.3;
                (new > 0).then(|| (format!(" {new}"), t.yellow))
            }
            ScreenId::Net => {
                let n = network::new_count(v);
                (n > 0).then(|| (format!(" {n}"), t.yellow))
            }
            // What asks something of you, once something was read.
            ScreenId::Security => threats::badge(v),
            _ => None,
        }
    }

    /// The lists changed: each cursor stays inside its list, Maintenance on its row.
    pub fn clamp(&mut self, id: ScreenId, v: &View) {
        if id == ScreenId::Maint {
            return self.maint.keep(v);
        }
        if id == ScreenId::Security {
            return self.security.keep(v);
        }
        let n = self.rows(id, v);
        if let Some(c) = self.cursor_mut(id) {
            c.clamp(n);
        }
    }

    pub fn reset_cursor(&mut self, id: ScreenId) {
        if let Some(c) = self.cursor_mut(id) {
            c.sel = 0;
        }
    }
}

/// A length of time as it's said: `45s`, `40m`, `1h 20m`, `2h`, `3d 4h`.
pub fn span(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    match (d, h, m) {
        (0, 0, 0) => format!("{secs}s"),
        (0, 0, m) => format!("{m}m"),
        (0, h, 0) => format!("{h}h"),
        (0, h, m) => format!("{h}h {m}m"),
        (d, 0, _) => format!("{d}d"),
        (d, h, _) => format!("{d}d {h}h"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_as_said() {
        let said: Vec<String> = [45, 2400, 4800, 7200, 86400, 273_600, 1_363_000]
            .into_iter()
            .map(span)
            .collect();
        assert_eq!(
            said,
            ["45s", "40m", "1h 20m", "2h", "1d", "3d 4h", "15d 18h"]
        );
    }
}

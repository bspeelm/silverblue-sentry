//! Screens: each owns its UI state (cursor, sort, focus) and renders from the shared
//! `DataStore`. They return `Effect`s instead of doing I/O.

mod audit;
mod cleanup;
mod containers;
mod dashboard;
mod flatpaks;
pub mod history;
pub mod jobs;
pub mod maint;
mod network;
mod processes;
pub mod updates;
pub mod upgrade;

use ratatui::Frame;
use ratatui::layout::Rect;

use super::ScreenId;
use super::app::Effect;
use super::data::DataStore;
use super::keys::Action;
use super::theme::Theme;
use crate::config::Config;

pub struct View<'a> {
    pub d: &'a DataStore,
    pub cfg: &'a Config,
    pub t: &'a Theme,
    pub filter: Option<&'a str>,
    pub wf: Option<&'a crate::tui::wf::Session>,
}

impl View<'_> {
    /// Case-insensitive substring match of the active filter against any field.
    pub fn matches(&self, fields: &[&str]) -> bool {
        match self.filter {
            None => true,
            Some(f) => {
                let f = f.to_lowercase();
                fields.iter().any(|x| x.to_lowercase().contains(&f))
            }
        }
    }
}

pub type Hints = Vec<(&'static str, &'static str)>;

/// This binary as a streamable command (`sentry job …`), so TUI and headless runs match.
pub fn sentry_cmd(args: &[&str]) -> crate::exec::Cmd {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "sentry".into());
    crate::exec::Cmd::local(&exe)
        .args(args.iter().copied())
        .timeout(None)
}

/// List cursor shared by every table screen.
#[derive(Debug, Default, Clone, Copy)]
pub struct Cursor {
    pub sel: usize,
    pub page: usize,
}

impl Cursor {
    /// Apply a navigation action; returns true if it was one.
    pub fn nav(&mut self, a: Action, len: usize) -> bool {
        let page = self.page.max(1);
        let last = len.saturating_sub(1);
        self.sel = match a {
            Action::Down => (self.sel + 1).min(last),
            Action::Up => self.sel.saturating_sub(1),
            Action::Top => 0,
            Action::Bottom => last,
            Action::PageDown => (self.sel + page / 2).min(last),
            Action::PageUp => self.sel.saturating_sub(page / 2),
            // Rows are already filtered, so n/N just walk the matches with wrap-around.
            Action::NextMatch if len > 0 => (self.sel + 1) % len,
            Action::PrevMatch if len > 0 => (self.sel + len - 1) % len,
            _ => return false,
        };
        true
    }

    pub fn clamp(&mut self, len: usize) -> usize {
        self.sel = self.sel.min(len.saturating_sub(1));
        self.sel
    }
}

#[derive(Default)]
pub struct Screens {
    dash: dashboard::Dashboard,
    proc: processes::Processes,
    net: network::Network,
    cont: containers::Containers,
    flat: flatpaks::Flatpaks,
    pub maint: maint::Maint,
    clean: cleanup::Cleanup,
    upgrade: upgrade::Upgrade,
    hist: history::History,
}

impl Screens {
    pub fn on_enter(&self, id: ScreenId, v: &View) -> Vec<Effect> {
        match id {
            ScreenId::Cont => containers::on_enter(v),
            ScreenId::Flat => flatpaks::on_enter(v),
            ScreenId::Maint => maint::on_enter(v),
            ScreenId::Clean => cleanup::on_enter(v),
            ScreenId::Upgrade => upgrade::on_enter(v),
            ScreenId::Hist => history::on_enter(v),
            _ => Vec::new(),
        }
    }

    pub fn handle(&mut self, id: ScreenId, a: Action, v: &View) -> Vec<Effect> {
        match id {
            ScreenId::Dash => self.dash.handle(a, v),
            ScreenId::Proc => self.proc.handle(a, v),
            ScreenId::Net => self.net.handle(a, v),
            ScreenId::Cont => self.cont.handle(a, v),
            ScreenId::Flat => self.flat.handle(a, v),
            ScreenId::Maint => self.maint.handle(a, v),
            ScreenId::Clean => self.clean.handle(a, v),
            ScreenId::Upgrade => self.upgrade.handle(a, v),
            ScreenId::Hist => self.hist.handle(a, v),
        }
    }

    pub fn render(&mut self, id: ScreenId, f: &mut Frame, area: Rect, v: &View) {
        match id {
            ScreenId::Dash => self.dash.render(f, area, v),
            ScreenId::Proc => self.proc.render(f, area, v),
            ScreenId::Net => self.net.render(f, area, v),
            ScreenId::Cont => self.cont.render(f, area, v),
            ScreenId::Flat => self.flat.render(f, area, v),
            ScreenId::Maint => self.maint.render(f, area, v),
            ScreenId::Clean => self.clean.render(f, area, v),
            ScreenId::Upgrade => self.upgrade.render(f, area, v),
            ScreenId::Hist => self.hist.render(f, area, v),
        }
    }

    pub fn hints(&self, id: ScreenId, v: &View) -> Hints {
        match id {
            ScreenId::Dash => dashboard::hints(),
            ScreenId::Proc => processes::hints(),
            ScreenId::Net => network::hints(),
            ScreenId::Cont => containers::hints(),
            ScreenId::Flat => flatpaks::hints(),
            ScreenId::Maint => maint::hints(v, &self.maint),
            ScreenId::Clean => cleanup::hints(),
            ScreenId::Upgrade => upgrade::hints(v),
            ScreenId::Hist => history::hints(),
        }
    }

    /// `A`: the selected thing as a question for Claude (spec: "ask" per tab).
    pub fn ask(&self, id: ScreenId, v: &View) -> Result<crate::claude::Ask, String> {
        match id {
            ScreenId::Dash => dashboard::ask(v),
            ScreenId::Proc => self.proc.ask(v),
            ScreenId::Net => self.net.ask(v),
            ScreenId::Cont => self.cont.ask(v),
            ScreenId::Flat => self.flat.ask(v),
            ScreenId::Maint => self.maint.ask(v),
            ScreenId::Clean => self.clean.ask(v),
            ScreenId::Upgrade => self.upgrade.ask(v),
            ScreenId::Hist => self.hist.ask(v),
        }
    }

    /// Cleanup with only this job's items selected.
    pub fn focus_cleanup(&mut self, job: crate::jobs::JobId) {
        self.clean.focus = Some(job);
        self.clean.jump = true;
        self.clean.reset_checks();
    }

    /// Maintenance with the first recommendation whose key starts with `prefix` selected.
    pub fn find_maint(&mut self, prefix: &str) {
        self.maint.view = None;
        self.maint.find = Some(prefix.to_string());
    }

    pub fn select_workflow(&mut self, i: usize) {
        self.upgrade.cur.sel = i;
    }

    /// Start the next workflow with these values as the defaults (a plan's).
    pub fn preset_workflow(&mut self, vars: std::collections::BTreeMap<String, String>) {
        self.upgrade.preset = vars;
    }

    pub fn reset_cursor(&mut self, id: ScreenId) {
        match id {
            ScreenId::Proc => self.proc.cur.sel = 0,
            ScreenId::Net => self.net.cur.sel = 0,
            ScreenId::Cont => self.cont.cur.sel = 0,
            ScreenId::Flat => self.flat.cur.sel = 0,
            ScreenId::Maint => self.maint.cur.sel = 0,
            ScreenId::Clean => self.clean.cur.sel = 0,
            ScreenId::Upgrade => self.upgrade.cur.sel = 0,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;

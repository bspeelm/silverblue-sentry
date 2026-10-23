//! Screens: each owns its UI state (cursor, sort, focus) and renders from the shared
//! `DataStore`. They return `Effect`s instead of doing I/O.

mod containers;
mod dashboard;
mod flatpaks;
mod network;
mod placeholder;
mod processes;
mod updates;

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
    upd: updates::Updates,
    cont: containers::Containers,
    flat: flatpaks::Flatpaks,
}

impl Screens {
    pub fn on_enter(&self, id: ScreenId, v: &View) -> Vec<Effect> {
        match id {
            ScreenId::Upd => updates::on_enter(v),
            ScreenId::Cont => containers::on_enter(v),
            ScreenId::Flat => flatpaks::on_enter(v),
            _ => Vec::new(),
        }
    }

    pub fn handle(&mut self, id: ScreenId, a: Action, v: &View) -> Vec<Effect> {
        match id {
            ScreenId::Dash => self.dash.handle(a, v),
            ScreenId::Proc => self.proc.handle(a, v),
            ScreenId::Net => self.net.handle(a, v),
            ScreenId::Upd => self.upd.handle(a, v),
            ScreenId::Cont => self.cont.handle(a, v),
            ScreenId::Flat => self.flat.handle(a, v),
            _ => placeholder::handle(id, a),
        }
    }

    pub fn render(&mut self, id: ScreenId, f: &mut Frame, area: Rect, v: &View) {
        match id {
            ScreenId::Dash => self.dash.render(f, area, v),
            ScreenId::Proc => self.proc.render(f, area, v),
            ScreenId::Net => self.net.render(f, area, v),
            ScreenId::Upd => self.upd.render(f, area, v),
            ScreenId::Cont => self.cont.render(f, area, v),
            ScreenId::Flat => self.flat.render(f, area, v),
            _ => placeholder::render(id, f, area, v),
        }
    }

    pub fn hints(&self, id: ScreenId, v: &View) -> Hints {
        match id {
            ScreenId::Dash => dashboard::hints(),
            ScreenId::Proc => processes::hints(),
            ScreenId::Net => network::hints(),
            ScreenId::Upd => updates::hints(v),
            ScreenId::Cont => containers::hints(),
            ScreenId::Flat => flatpaks::hints(),
            _ => placeholder::hints(id),
        }
    }

    pub fn reset_cursor(&mut self, id: ScreenId) {
        match id {
            ScreenId::Proc => self.proc.cur.sel = 0,
            ScreenId::Net => self.net.cur.sel = 0,
            ScreenId::Cont => self.cont.cur.sel = 0,
            ScreenId::Flat => self.flat.cur.sel = 0,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;

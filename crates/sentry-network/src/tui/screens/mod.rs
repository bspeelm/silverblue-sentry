//! The network target's screens: `1` Dashboard and `H` History. Their numbers and names are
//! sentry's (`super::SCREENS`).

pub mod dashboard;
pub mod history;

use super::data::Store;
use crate::config::Network;
use sentry_core::tui::theme::Theme;

pub type Hints = Vec<(&'static str, &'static str)>;

/// What a screen draws from.
pub struct View<'a> {
    pub t: &'a Theme,
    pub s: &'a Store,
    pub cfg: &'a Network,
    /// The network's name.
    pub name: &'a str,
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

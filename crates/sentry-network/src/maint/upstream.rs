//! What OpenWrt has released, looked up from this machine (never from the router: `owut`
//! is not run for this) through `sentry_app::remote::upstream`: endoflife.date's `openwrt`
//! product for the series' end of life and its latest patch release, and GitHub's
//! `openwrt/openwrt` releases for the patch level when that is missing and for whether a
//! release's notes speak of security fixes. Cached for a day per network, as the server's
//! lookups are; fetched only when asked (`r` on Maintenance).

use serde::{Deserialize, Serialize};

use sentry_app::remote::upstream::{Eol, Release, fetch_eol, fetch_github};
use sentry_core::cache;

/// endoflife.date's product, and the repository.
pub const PRODUCT: &str = "openwrt";
pub const REPO: &str = "openwrt/openwrt";

/// A lookup is good for this long.
pub const FRESH_S: i64 = 86_400;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Upstream {
    /// The series it was looked up for (`25.12`).
    pub series: String,
    pub eol: Result<Eol, String>,
    pub releases: Result<Vec<Release>, String>,
}

fn cache_key(network: &str) -> String {
    format!("network-{network}-upstream")
}

pub fn load(network: &str) -> Option<cache::Cached<Upstream>> {
    cache::load(&cache_key(network))
}

/// What's cached still answers for this series: looked up within the day, both sources.
pub fn fresh(c: &cache::Cached<Upstream>, series: &str, now: jiff::Timestamp) -> bool {
    c.data.series == series
        && c.age_secs(now) < FRESH_S
        && c.data.eol.is_ok()
        && c.data.releases.is_ok()
}

/// Look both sources up (side by side) and cache the answer.
pub fn lookup(network: &str, series: &str) -> cache::Cached<Upstream> {
    let key = format!("{PRODUCT}/{series}");
    let (eol, releases) = std::thread::scope(|sc| {
        let e = sc.spawn(|| fetch_eol(&key));
        let r = sc.spawn(|| fetch_github(REPO));
        (
            e.join().unwrap_or_else(|_| Err("lookup panicked".into())),
            r.join().unwrap_or_else(|_| Err("lookup panicked".into())),
        )
    });
    let data = Upstream {
        series: series.to_string(),
        eol,
        releases,
    };
    let fetched_at =
        cache::store(&cache_key(network), &data).unwrap_or_else(|_| jiff::Timestamp::now());
    cache::Cached { fetched_at, data }
}

/// The cached answer when it's fresh for this series, else a new lookup.
pub fn get(network: &str, series: &str) -> cache::Cached<Upstream> {
    match load(network) {
        Some(c) if fresh(&c, series, jiff::Timestamp::now()) => c,
        _ => lookup(network, series),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lookup_is_good_for_a_day_and_for_its_series() {
        let at: jiff::Timestamp = "2026-10-26T12:00:00Z".parse().unwrap();
        let c = |eol: Result<Eol, String>| cache::Cached {
            fetched_at: at,
            data: Upstream {
                series: "25.12".into(),
                eol,
                releases: Ok(Vec::new()),
            },
        };
        let later = |h: i64| jiff::Timestamp::from_second(at.as_second() + h * 3600).unwrap();
        assert!(fresh(&c(Ok(Eol::default())), "25.12", later(23)));
        assert!(!fresh(&c(Ok(Eol::default())), "25.12", later(25)));
        // The router moved to another series, or a source failed: look again.
        assert!(!fresh(&c(Ok(Eol::default())), "26.06", later(1)));
        assert!(!fresh(&c(Err("timeout".into())), "25.12", later(1)));
        // It round-trips through the cache's JSON.
        let text = serde_json::to_string(&c(Err("x".into()))).unwrap();
        let back: cache::Cached<Upstream> = serde_json::from_str(&text).unwrap();
        assert_eq!(back.data, c(Err("x".into())).data);
    }
}

//! Which packages could be upgraded, as apk (v3) lists them from the index it has, and how
//! old that index is. Reading never contacts the network (`--no-network`: apk would fetch a
//! stale index by itself otherwise). The index lives in tmpfs, so it is gone after a reboot
//! and only as new as the last `apk update`; that refresh ([`REFRESH`]) is run only when
//! asked for (`r` on Maintenance), never by itself.

use serde::{Deserialize, Serialize};

use super::{CollectError, output_needing, sections};
use sentry_app::remote::Remote;

/// apk's index cache (`/var` is tmpfs on OpenWrt), the listing, and the router's clock.
pub const SCRIPT: &str = "echo @@list; apk --no-network list --upgradable 2>/dev/null; \
     echo @@index; for f in /var/cache/apk/APKINDEX.*; do \
     [ -e \"$f\" ] && date -r \"$f\" +%s; done; echo @@now; date +%s";

/// Fetch the package index again (it writes the tmpfs cache, nothing on flash).
pub const REFRESH: &str = "apk update >/dev/null 2>&1; echo @@updated $?";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    /// The version installed.
    pub from: String,
    /// The version the index has.
    pub to: String,
    /// Where it's built from (`feeds/base/network/services/dnsmasq`).
    pub origin: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Updates {
    pub packages: Vec<Package>,
    /// When the index was last fetched, by the router's clock (none: never since it booted).
    pub index_at: Option<i64>,
    /// The router's clock at the read.
    pub now: i64,
    /// The refresh asked for with this read failed (apk's exit code).
    pub refresh_failed: Option<i32>,
}

impl Updates {
    /// How old the index is, in seconds (none: there is no index).
    pub fn index_age(&self) -> Option<i64> {
        self.index_at.map(|t| (self.now - t).max(0))
    }

    /// The index's age as it's said on a row.
    pub fn index_said(&self) -> String {
        match self.index_age() {
            None => "no index since boot".to_string(),
            Some(s) => format!("index {}", sentry_core::fmt::ago(s)),
        }
    }
}

/// `name-version` cut where the version starts: apk versions begin with a digit and may end
/// in `-r<N>`, and names have dashes and digits of their own (`libmbedtls21-3.6.7-r1`,
/// `kmod-nft-core-6.12.94-r1`, `luci-26.315.12466~1a2b3c4d`).
pub fn split(pkgver: &str) -> Option<(&str, &str)> {
    let is_rel = |s: &str| {
        s.strip_prefix('r')
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    };
    let (head, rel) = match pkgver.rsplit_once('-') {
        Some((h, r)) if is_rel(r) => (h, Some(r)),
        _ => (pkgver, None),
    };
    let (name, _) = head.rsplit_once('-')?;
    let ver = &pkgver[name.len() + 1..];
    let starts = ver.bytes().next().is_some_and(|b| b.is_ascii_digit());
    let _ = rel;
    (!name.is_empty() && starts).then_some((name, ver))
}

/// One line of the listing:
/// `name-new arch {origin} (licence) [upgradable from: name-old]`.
pub fn line(l: &str) -> Option<Package> {
    let l = l.trim();
    let from = l
        .rsplit_once("[upgradable from: ")?
        .1
        .strip_suffix(']')?
        .trim();
    let new = l.split_whitespace().next()?;
    let origin = l
        .split_once('{')
        .and_then(|(_, rest)| rest.split_once('}'))
        .map_or("", |(o, _)| o);
    // The old one names the package too: where both agree is the name, whatever it looks like.
    let (name, to) = split(new)?;
    let from = match from.strip_prefix(name).and_then(|v| v.strip_prefix('-')) {
        Some(v) => v,
        None => split(from)?.1,
    };
    Some(Package {
        name: name.to_string(),
        from: from.to_string(),
        to: to.to_string(),
        origin: origin.to_string(),
    })
}

pub fn parse(text: &str) -> Result<Updates, String> {
    let mut u = Updates::default();
    let mut seen_now = false;
    for (name, body) in sections(text) {
        let mut words = name.split_whitespace();
        match words.next() {
            Some("list") => {
                u.packages = body.lines().filter_map(line).collect();
                u.packages.sort_by(|a, b| a.name.cmp(&b.name));
            }
            // The newest of the index files.
            Some("index") => {
                u.index_at = body.lines().filter_map(|l| l.trim().parse().ok()).max();
            }
            Some("now") => {
                u.now = body
                    .lines()
                    .find_map(|l| l.trim().parse().ok())
                    .ok_or("the router's clock wasn't read")?;
                seen_now = true;
            }
            Some("updated") => {
                u.refresh_failed = words
                    .next()
                    .and_then(|c| c.parse::<i32>().ok())
                    .filter(|c| *c != 0);
            }
            _ => {}
        }
    }
    if !seen_now {
        return Err("the package listing is cut short".into());
    }
    Ok(u)
}

/// What could be upgraded, from the index the router has.
pub fn collect(r: &Remote) -> Result<Updates, CollectError> {
    parse(&output_needing(r, "apk", SCRIPT)?).map_err(CollectError::Parse)
}

/// Fetch the index again, then the same read. Only ever asked for by the user.
pub fn refresh(r: &Remote) -> Result<Updates, CollectError> {
    let script = format!("{REFRESH}; {SCRIPT}");
    let guarded = format!("command -v apk >/dev/null || exit 127; {script}");
    let cmd = r
        .sh(&guarded)
        .timeout(Some(std::time::Duration::from_secs(90)));
    let out = r.output(&cmd).map_err(|e| match e {
        sentry_app::remote::Error::NotFound(_) => CollectError::Unavailable("apk".into()),
        e => e.into(),
    })?;
    parse(&out).map_err(CollectError::Parse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    #[test]
    fn names_and_versions_are_cut_where_the_version_starts() {
        for (pkgver, name, ver) in [
            ("dnsmasq-2.93-r2", "dnsmasq", "2.93-r2"),
            ("libmbedtls21-3.6.7-r1", "libmbedtls21", "3.6.7-r1"),
            ("kmod-nft-core-6.12.94-r1", "kmod-nft-core", "6.12.94-r1"),
            ("ca-bundle-20250419-r2", "ca-bundle", "20250419-r2"),
            (
                "luci-26.315.12466~1a2b3c4d",
                "luci",
                "26.315.12466~1a2b3c4d",
            ),
            (
                "libubox20260213-2026.11.02~0f1e2d3c-r1",
                "libubox20260213",
                "2026.11.02~0f1e2d3c-r1",
            ),
            (
                "wpad-basic-mbedtls-2025.08.26~aa11bb22-r7",
                "wpad-basic-mbedtls",
                "2025.08.26~aa11bb22-r7",
            ),
            ("libstdcpp6-14.3.0-r5", "libstdcpp6", "14.3.0-r5"),
            ("6in4-29", "6in4", "29"),
        ] {
            assert_eq!(split(pkgver), Some((name, ver)), "{pkgver}");
        }
        assert_eq!(split("noversion"), None);
        assert_eq!(split("name-only-r1"), None);
    }

    #[test]
    fn the_listing_as_apk_prints_it() {
        let u = parse(&fixture("network/updates.txt")).unwrap();
        let names: Vec<&str> = u.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "ca-bundle",
                "dnsmasq",
                "libmbedtls21",
                "libubox20260213",
                "luci",
                "luci-app-firewall",
                "wpad-basic-mbedtls"
            ]
        );
        let d = &u.packages[1];
        assert_eq!(
            (d.from.as_str(), d.to.as_str(), d.origin.as_str()),
            ("2.93-r1", "2.93-r2", "feeds/base/network/services/dnsmasq")
        );
        // A licence with spaces, and a version with a hash and no release.
        let ca = &u.packages[0];
        assert_eq!(
            (ca.from.as_str(), ca.to.as_str()),
            ("20250419-r1", "20250419-r2")
        );
        let luci = &u.packages[4];
        assert_eq!(luci.to, "26.315.12466~1a2b3c4d");
        assert_eq!(luci.from, "26.301.40111~9f8e7d6c");
        // The newest index file's time, against the router's clock: nine days.
        assert_eq!(u.index_age(), Some(9 * 86_400 + 3600));
        assert_eq!(u.index_said(), "index 9d ago");
        assert_eq!(u.refresh_failed, None);
    }

    #[test]
    fn the_index_has_three_states() {
        // Never fetched since the router booted: nothing listed, and no index file.
        let none = parse("@@list\n@@index\n@@now\n1792497600\n").unwrap();
        assert!(none.packages.is_empty());
        assert_eq!(none.index_age(), None);
        assert_eq!(none.index_said(), "no index since boot");
        // Just fetched.
        let fresh =
            parse("@@updated 0\n@@list\n@@index\n1792497590\n1792497595\n@@now\n1792497600\n")
                .unwrap();
        assert_eq!(fresh.index_age(), Some(5));
        assert_eq!(fresh.refresh_failed, None);
        // The refresh failed (no route): what was there is still read.
        let failed =
            parse("@@updated 1\n@@list\n@@index\n1791000000\n@@now\n1792497600\n").unwrap();
        assert_eq!(failed.refresh_failed, Some(1));
        assert!(failed.index_age().unwrap() > 86_400);
        // A clock set back never gives a negative age.
        let back = parse("@@list\n@@index\n1792497700\n@@now\n1792497600\n").unwrap();
        assert_eq!(back.index_age(), Some(0));
        assert!(parse("@@list\n").is_err());
    }

    #[test]
    fn lines_that_arent_packages_are_left_out() {
        assert_eq!(line("WARNING: opening from cache"), None);
        assert_eq!(
            line("dnsmasq-2.93-r2 aarch64 {x} (GPL-2.0) [installed]"),
            None
        );
        let p = line(
            "odd.name+x-1.0-r0 noarch {feeds/x} (MIT AND BSD-3-Clause) [upgradable from: odd.name+x-0.9-r3]",
        )
        .unwrap();
        assert_eq!(
            (p.name.as_str(), p.from.as_str(), p.to.as_str()),
            ("odd.name+x", "0.9-r3", "1.0-r0")
        );
    }
}

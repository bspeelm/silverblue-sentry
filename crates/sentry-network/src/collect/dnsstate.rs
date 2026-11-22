//! How the name filtering stands, where the router has it: adblock-fast's own status (how
//! many names it blocks, whether it updates by itself, and when its list was last built:
//! the file's time) and https-dns-proxy's (whether DNS is forced through the router, on
//! which ports). One exec, when Security is entered and on `r`. A router without a package
//! has no such part: `None`, nothing shown, never a zero.
//!
//! Only `get…Status` calls: the same ubus objects have methods that write.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{CollectError, output_needing, sections};
use sentry_app::remote::Remote;

pub const SCRIPT: &str = "echo @@now; date +%s; \
     if ubus list luci.adblock-fast >/dev/null 2>&1; then \
     echo @@abf; ubus call luci.adblock-fast getInitStatus '{\"name\":\"adblock-fast\"}'; \
     echo @@abf-cron; ubus call luci.adblock-fast getCronStatus '{\"name\":\"adblock-fast\"}'; \
     echo @@abf-files; for f in /var/run/adblock-fast/*; do [ -f \"$f\" ] && \
     echo \"$f $(date -r \"$f\" +%s)\"; done; fi; \
     if ubus list luci.https-dns-proxy >/dev/null 2>&1; then \
     echo @@hdp; ubus call luci.https-dns-proxy getInitStatus '{\"name\":\"https-dns-proxy\"}'; \
     fi; true";

/// adblock-fast, as it says of itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocklist {
    pub enabled: bool,
    pub running: bool,
    /// Names blocked (None: it didn't say).
    pub entries: Option<u64>,
    /// How it blocks (`dnsmasq.servers`…).
    pub mode: String,
    /// The lists it is made from.
    pub lists: usize,
    pub errors: usize,
    /// It fetches the lists again by itself (None: unknown).
    pub auto_update: Option<bool>,
    /// When the list in use was built (its file's time).
    pub built_at: Option<i64>,
}

/// https-dns-proxy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proxy {
    pub enabled: bool,
    pub running: bool,
    /// Other resolvers on these ports are redirected or refused.
    pub force_dns: bool,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsState {
    /// The router's clock at the read.
    pub now: i64,
    pub blocklist: Option<Blocklist>,
    pub proxy: Option<Proxy>,
}

impl DnsState {
    /// How old the blocklist is, in days.
    pub fn list_age_days(&self) -> Option<i64> {
        let at = self.blocklist.as_ref()?.built_at?;
        Some((self.now - at).max(0) / 86_400)
    }
}

fn blocklist(status: &str, cron: &str, files: &str) -> Option<Blocklist> {
    let v: Value = serde_json::from_str(status).ok()?;
    let s = v.get("adblock-fast")?;
    let out = s["outputFile"].as_str().unwrap_or("");
    let times: Vec<(&str, i64)> = files
        .lines()
        .filter_map(|l| {
            let (f, t) = l.rsplit_once(' ')?;
            Some((f, t.trim().parse().ok()?))
        })
        .collect();
    let cron: Option<Value> = serde_json::from_str(cron).ok();
    Some(Blocklist {
        enabled: s["enabled"].as_bool().unwrap_or(false),
        running: s["running"].as_bool().unwrap_or(false),
        entries: s["entries"].as_u64(),
        mode: s["dns"].as_str().unwrap_or("").to_string(),
        lists: s["file_url"].as_array().map_or(0, Vec::len),
        errors: s["errors"].as_array().map_or(0, Vec::len),
        auto_update: cron
            .as_ref()
            .and_then(|c| c["adblock-fast"]["auto_update_enabled"].as_bool()),
        // The file it names; none named: nothing is guessed.
        built_at: times.iter().find(|(f, _)| *f == out).map(|(_, t)| *t),
    })
}

fn proxy(status: &str) -> Option<Proxy> {
    let v: Value = serde_json::from_str(status).ok()?;
    let s = v.get("https-dns-proxy")?;
    Some(Proxy {
        enabled: s["enabled"].as_bool().unwrap_or(false),
        running: s["running"].as_bool().unwrap_or(false),
        force_dns: s["force_dns_active"].as_bool().unwrap_or(false),
        ports: s["force_dns_ports"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| u16::try_from(p.as_u64()?).ok())
            .collect(),
    })
}

pub fn parse(text: &str) -> Result<DnsState, String> {
    let secs = sections(text);
    let body = |name: &str| secs.iter().find(|(n, _)| *n == name).map(|(_, b)| *b);
    Ok(DnsState {
        now: body("now")
            .and_then(|b| b.trim().parse().ok())
            .ok_or("no clock")?,
        blocklist: body("abf").and_then(|s| {
            blocklist(
                s,
                body("abf-cron").unwrap_or(""),
                body("abf-files").unwrap_or(""),
            )
        }),
        proxy: body("hdp").and_then(proxy),
    })
}

pub fn collect(r: &Remote) -> Result<DnsState, CollectError> {
    parse(&output_needing(r, "ubus", SCRIPT)?).map_err(CollectError::Parse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    #[test]
    fn both_packages_as_they_say() {
        let d = parse(&fixture("network/dnsstate.txt")).unwrap();
        assert_eq!(
            d.blocklist,
            Some(Blocklist {
                enabled: true,
                running: true,
                entries: Some(104200),
                mode: "dnsmasq.servers".into(),
                lists: 2,
                errors: 0,
                auto_update: Some(false),
                built_at: Some(1791806400),
            })
        );
        // The list's own file, not the newest file beside it.
        assert_eq!(d.list_age_days(), Some(14));
        assert_eq!(
            d.proxy,
            Some(Proxy {
                enabled: true,
                running: true,
                force_dns: true,
                ports: vec![53, 853],
            })
        );
    }

    #[test]
    fn a_router_without_them_has_neither() {
        let d = parse(&fixture("network/dnsstate-bare.txt")).unwrap();
        assert_eq!(d.list_age_days(), None);
        assert_eq!((d.blocklist, d.proxy, d.now), (None, None, 1793016000));
        // The package is there and said something this doesn't know: present, mostly unread.
        let odd = parse("@@now\n5\n@@abf\n{\"adblock-fast\": {}}\n@@abf-files\n").unwrap();
        let b = odd.blocklist.unwrap();
        assert_eq!((b.entries, b.built_at, b.auto_update), (None, None, None));
        // Not JSON at all: absent.
        assert_eq!(
            parse("@@now\n5\n@@abf\nubus: not found\n")
                .unwrap()
                .blocklist,
            None
        );
        assert!(parse("").is_err());
    }

    #[test]
    fn the_script_calls_only_status_methods() {
        for call in SCRIPT.split("ubus call ").skip(1) {
            let method = call.split_whitespace().nth(1).unwrap();
            assert!(
                method.starts_with("get") && method.ends_with("Status"),
                "{method}"
            );
        }
    }
}

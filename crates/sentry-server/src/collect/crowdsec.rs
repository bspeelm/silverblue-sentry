//! CrowdSec, where the server runs it: read only. The agent's unit, `cscli`'s version, how
//! many decisions are active (by type and by origin), the alerts of the last day, hub items
//! that are behind or edited, and whether each bouncer still pulls. Nothing is installed,
//! registered, added or deleted; a server without `cscli` gives `None` and nothing is shown.
//!
//! What leaves this module is counts, scenario names and bouncer names: the addresses in
//! alerts, decisions and the bouncers' list are dropped as they're parsed, so no report,
//! screen or prompt ever holds one.
//!
//! No host with CrowdSec was at hand when this was written: the shapes are read from
//! CrowdSec's source (each parser names the file), and the fixtures in
//! `tests/fixtures/server/crowdsec-*` are written after those structs, not captured. So
//! every part is optional and an unreadable one is said, never an error for the rest.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::remote::{Remote, SrvError};

/// How the agent's systemd unit stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Agent {
    Running,
    /// The unit is there and isn't active (`failed`, `inactive`, …).
    Down(String),
    /// `cscli` is there without a `crowdsec.service` (the agent runs elsewhere, e.g. in a
    /// container): nothing to say about it.
    NoUnit,
}

/// Active decisions, counted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decisions {
    /// `ban`, `captcha`, …
    pub by_type: BTreeMap<String, u32>,
    /// `crowdsec` (a local scenario), `cscli` (by hand), `CAPI` (the community blocklist),
    /// `lists` (a subscribed blocklist), …
    pub by_origin: BTreeMap<String, u32>,
    /// Counted from `cscli decisions list`, which leaves the blocklists out: local only.
    pub local_only: bool,
}

/// An origin that is this server's own doing, not a blocklist's.
pub fn local_origin(origin: &str) -> bool {
    !(origin.eq_ignore_ascii_case("capi") || origin.to_ascii_lowercase().starts_with("lists"))
}

impl Decisions {
    pub fn total(&self) -> u32 {
        self.by_origin.values().sum()
    }
    pub fn local(&self) -> u32 {
        self.by_origin
            .iter()
            .filter(|(o, _)| local_origin(o))
            .map(|(_, n)| n)
            .sum()
    }
}

/// How many alerts `ALERTS_ARGV` asks for at most.
pub const ALERTS_LIMIT: u32 = 500;

/// The alerts of the last 24 hours.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alerts {
    pub count: u32,
    /// The list was cut at [`ALERTS_LIMIT`]: there are at least that many.
    pub capped: bool,
    /// The scenarios that fired most, most first (at most five).
    pub top: Vec<(String, u32)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HubState {
    /// A newer version is in the hub.
    Outdated,
    /// Edited locally: upgrades skip it.
    Tainted,
}

/// A hub item that isn't as the hub has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubItem {
    /// `collections`, `parsers`, `scenarios`, …
    pub kind: String,
    pub name: String,
    pub version: String,
    pub state: HubState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bouncer {
    pub name: String,
    /// `crowdsec-firewall-bouncer`, …
    pub kind: String,
    pub revoked: bool,
    /// When it last asked for decisions (epoch seconds); None: never.
    pub last_pull: Option<i64>,
}

/// A bouncer is quiet when it hasn't pulled for this long.
pub const QUIET_S: i64 = 3600;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Crowdsec {
    pub agent: Agent,
    pub version: Option<String>,
    /// The server's clock when it was read (epoch seconds).
    pub now: i64,
    pub decisions: Option<Decisions>,
    pub alerts: Option<Alerts>,
    /// The items behind or tainted (empty: all as the hub has them).
    pub hub: Option<Vec<HubItem>>,
    pub bouncers: Option<Vec<Bouncer>>,
    /// The parts that couldn't be read, and why.
    #[serde(default)]
    pub unread: Vec<(String, String)>,
}

impl Crowdsec {
    /// The registered bouncers that stopped pulling (or never did), while the agent runs.
    pub fn quiet_bouncers(&self) -> Vec<&Bouncer> {
        if self.agent != Agent::Running {
            return Vec::new();
        }
        self.bouncers
            .iter()
            .flatten()
            .filter(|b| !b.revoked && b.last_pull.is_none_or(|t| self.now - t > QUIET_S))
            .collect()
    }
}

/// What the server's own guard says, for another target's screen (a network's Security
/// page, through `SystemLine::facts`): the alerts of the last day, what they were for,
/// and the bouncers that pull its decisions now. Counts and names only (the addresses
/// were dropped as it was parsed).
pub fn guard_facts(c: &Crowdsec) -> Vec<(String, String)> {
    let mut out = vec![
        ("guard.name".to_string(), "CrowdSec".to_string()),
        (
            "guard.running".to_string(),
            (!matches!(c.agent, Agent::Down(_))).to_string(),
        ),
    ];
    if let Some(a) = &c.alerts {
        out.push(("guard.blocked".into(), a.count.to_string()));
        let top: Vec<&str> = a.top.iter().map(|(n, _)| n.as_str()).collect();
        out.push(("guard.scenarios".into(), top.join("\n")));
    }
    if let Some(b) = &c.bouncers {
        let live: Vec<String> = b
            .iter()
            .filter(|x| !x.revoked && x.last_pull.is_some_and(|t| c.now - t <= QUIET_S))
            .map(|x| format!("{} ({})", x.name, x.kind))
            .collect();
        out.push(("guard.bouncers".into(), live.join("\n")));
    }
    out
}

/// A name with anything that reads as an address taken out: a scenario's name is free text
/// (`manual 'ban' from '…'`, an import's file name).
pub fn scrub(name: &str) -> String {
    let is_addr = |w: &str| {
        let w = w.trim_matches(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'));
        let ip = w.split('/').next().unwrap_or(w);
        ip.parse::<std::net::IpAddr>().is_ok()
    };
    name.split(' ')
        .map(|w| if is_addr(w) { "<address>" } else { w })
        .collect::<Vec<_>>()
        .join(" ")
}

fn json(text: &str) -> Result<Value, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("no output".into());
    }
    serde_json::from_str(t).map_err(|e| format!("not JSON: {e}"))
}

/// `[…]`, or `null` (what older releases print for an empty list).
fn list(v: &Value) -> Result<&[Value], String> {
    match v {
        Value::Null => Ok(&[]),
        Value::Array(a) => Ok(a),
        _ => Err("not a list".into()),
    }
}

/// `cscli decisions list -o json`: the alerts that hold active decisions, each with its
/// `decisions: [{ origin, type, scope, value, duration, scenario, simulated }]`
/// (`pkg/models/alert.go`, `pkg/models/decision.go`, printed by
/// `cmd/crowdsec-cli/clidecision/decisions.go` in
/// <https://github.com/crowdsecurity/crowdsec>). Without `--all` the blocklists' decisions
/// aren't listed, so this counts the local ones. `null` or `[]` when there are none.
pub fn parse_decisions(text: &str) -> Result<Decisions, String> {
    let v = json(text)?;
    let mut d = Decisions {
        local_only: true,
        ..Default::default()
    };
    for alert in list(&v)? {
        for dec in alert["decisions"].as_array().into_iter().flatten() {
            if dec["simulated"] == true {
                continue;
            }
            let ty = dec["type"].as_str().unwrap_or("unknown");
            let origin = dec["origin"].as_str().unwrap_or("unknown");
            *d.by_type.entry(ty.to_string()).or_default() += 1;
            *d.by_origin.entry(origin.to_string()).or_default() += 1;
        }
    }
    Ok(d)
}

/// `cscli metrics -o json`: of its tables only `decisions`, `{ reason: { origin: { action:
/// count } } }` (`statDecision` in `cmd/crowdsec-cli/climetrics/statdecision.go`; the same
/// key in 1.5's `cmd/crowdsec-cli/metrics.go`). It counts every active decision, the
/// blocklists' too, without listing one. None when the table isn't there (the agent's
/// Prometheus endpoint is off, or nothing is active).
pub fn parse_metrics(text: &str) -> Result<Option<Decisions>, String> {
    let v = json(text)?;
    let Some(reasons) = v["decisions"].as_object() else {
        return Ok(None);
    };
    let mut d = Decisions::default();
    for origins in reasons.values() {
        for (origin, actions) in origins.as_object().into_iter().flatten() {
            for (action, n) in actions.as_object().into_iter().flatten() {
                let n = n.as_u64().unwrap_or(0) as u32;
                *d.by_type.entry(action.clone()).or_default() += n;
                *d.by_origin.entry(origin.clone()).or_default() += n;
            }
        }
    }
    Ok((d.total() > 0).then_some(d))
}

/// `cscli alerts list --since 24h -l 500 -o json`: `[{ id, scenario, created_at, source: {
/// ip, scope, value, … }, decisions, events_count, … }]` (`pkg/models/alert.go`, printed by
/// `cmd/crowdsec-cli/clialert/alerts.go`; `[]` when there are none, `null` before that was
/// fixed). Only the scenarios are kept.
pub fn parse_alerts(text: &str) -> Result<Alerts, String> {
    let v = json(text)?;
    let alerts = list(&v)?;
    let mut by: BTreeMap<String, u32> = BTreeMap::new();
    for a in alerts {
        let s = a["scenario"].as_str().unwrap_or("unknown");
        *by.entry(scrub(s)).or_default() += 1;
    }
    let mut top: Vec<(String, u32)> = by.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    top.truncate(5);
    Ok(Alerts {
        count: alerts.len() as u32,
        capped: alerts.len() as u32 >= ALERTS_LIMIT,
        top,
    })
}

/// `cscli hub list -o json`: `{ "collections": [{ name, status, local_version, local_path,
/// description, utf8_status }], "parsers": […], … }` (`cmd/crowdsec-cli/clihub/items.go`);
/// `status` is `ItemState.Text()` (`pkg/cwhub/state.go`): `enabled`, `disabled`, then
/// `,local`, `,tainted` or `,update-available`. Only what is behind or tainted is kept.
pub fn parse_hub(text: &str) -> Result<Vec<HubItem>, String> {
    let v = json(text)?;
    let kinds = v.as_object().ok_or("not an object")?;
    let mut out = Vec::new();
    for (kind, items) in kinds {
        for it in items.as_array().into_iter().flatten() {
            let status = it["status"].as_str().unwrap_or("");
            let state = if status.contains("tainted") {
                HubState::Tainted
            } else if status.contains("update-available") {
                HubState::Outdated
            } else {
                continue;
            };
            out.push(HubItem {
                kind: kind.clone(),
                name: it["name"].as_str().unwrap_or("?").to_string(),
                version: it["local_version"].as_str().unwrap_or("").to_string(),
                state,
            });
        }
    }
    Ok(out)
}

/// `cscli bouncers list -o json`: `[{ name, revoked, ip_address, type, version, last_pull,
/// auth_type, created_at, updated_at, … }]` (`bouncerInfo` in
/// `cmd/crowdsec-cli/clibouncer/bouncers.go`: `last_pull` is `null` until the first pull;
/// through 1.6.2 it was `ent.Bouncer` itself, where a bouncer that never pulled has the zero
/// time `0001-01-01T00:00:00Z`). The address isn't kept.
pub fn parse_bouncers(text: &str) -> Result<Vec<Bouncer>, String> {
    let v = json(text)?;
    Ok(list(&v)?
        .iter()
        .map(|b| Bouncer {
            name: b["name"].as_str().unwrap_or("?").to_string(),
            kind: b["type"].as_str().unwrap_or("").to_string(),
            revoked: b["revoked"] == true,
            last_pull: b["last_pull"]
                .as_str()
                .and_then(|t| t.parse::<jiff::Timestamp>().ok())
                .map(|t| t.as_second())
                .filter(|s| *s > 0),
        })
        .collect())
}

/// `cscli version`: `version: v1.6.4-…` among its lines (`pkg/cwversion/version.go`;
/// older releases logged them to stderr, each inside a log line: that form is from memory).
pub fn parse_version(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.split_once("version: "))
        .map(|(_, v)| v.split_whitespace().next().unwrap_or(""))
        .map(|v| v.trim_end_matches('"').to_string())
        .filter(|v| !v.is_empty())
}

/// The first exec's answer: the clock, the unit, the version.
pub fn parse_head(text: &str) -> (i64, Agent, Option<String>) {
    let (mut now, mut load, mut active, mut version) = (0, "", "", String::new());
    let mut part = "";
    for l in text.lines() {
        if let Some(p) = l.strip_prefix("@@") {
            part = p.trim();
            continue;
        }
        match part {
            "now" => now = l.trim().parse().unwrap_or(now),
            "unit" => {
                if let Some(v) = l.strip_prefix("LoadState=") {
                    load = v.trim();
                } else if let Some(v) = l.strip_prefix("ActiveState=") {
                    active = v.trim();
                }
            }
            "version" => {
                version.push_str(l);
                version.push('\n');
            }
            _ => {}
        }
    }
    let agent = match (load, active) {
        ("loaded", "active" | "activating" | "reloading") => Agent::Running,
        ("loaded", s) => Agent::Down(s.to_string()),
        _ => Agent::NoUnit,
    };
    (now, agent, parse_version(&version))
}

/// Whether `cscli` is there, the clock, the unit and the version: no root needed.
const HEAD: &str = "command -v cscli >/dev/null 2>&1 || exit 127\n\
    echo @@now; date +%s\n\
    echo @@unit; systemctl show -p LoadState -p ActiveState crowdsec.service 2>/dev/null\n\
    echo @@version; cscli version 2>&1\n\
    true";

pub const DECISIONS_ARGV: &[&str] = &["cscli", "decisions", "list", "-o", "json"];
pub const METRICS_ARGV: &[&str] = &["cscli", "metrics", "-o", "json"];
pub const ALERTS_ARGV: &[&str] = &[
    "cscli", "alerts", "list", "--since", "24h", "-l", "500", "-o", "json",
];
pub const HUB_ARGV: &[&str] = &["cscli", "hub", "list", "-o", "json"];
pub const BOUNCERS_ARGV: &[&str] = &["cscli", "bouncers", "list", "-o", "json"];

/// Every read that talks to the local API or reads `/etc/crowdsec`: root's, as a rule.
pub const ARGVS: &[&[&str]] = &[
    DECISIONS_ARGV,
    METRICS_ARGV,
    ALERTS_ARGV,
    HUB_ARGV,
    BOUNCERS_ARGV,
];

/// One `cscli` read: through sudo when the allowlist has it (answered from the inventory
/// when sudo wants a password), else as the login user, who may be allowed to.
fn read(r: &Remote, argv: &[&str]) -> Result<String, SrvError> {
    match r.privileged(argv) {
        Ok(c) => r.output(&c),
        Err(needs) => r
            .output(&r.cmd(argv[0]).args(&argv[1..]))
            .map_err(|_| needs),
    }
}

/// None when the server has no `cscli`. One exec says so; the five reads follow only where
/// it is there (each its own `sudo -n`, as the inventory keys them), at once.
pub fn collect(r: &Remote) -> Result<Option<Crowdsec>, SrvError> {
    let head = match r.output(&r.sh(&format!("{}{HEAD}", crate::init::SBIN))) {
        Ok(o) => o,
        Err(SrvError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let (now, agent, version) = parse_head(&head);
    let mut c = Crowdsec {
        agent,
        version,
        now,
        decisions: None,
        alerts: None,
        hub: None,
        bouncers: None,
        unread: Vec::new(),
    };
    let outs: Vec<Result<String, SrvError>> = std::thread::scope(|sc| {
        let hs: Vec<_> = ARGVS
            .iter()
            .map(|argv| sc.spawn(move || read(r, argv)))
            .collect();
        hs.into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(SrvError::Failed("collector panicked".into())))
            })
            .collect()
    });
    let mut outs = outs.into_iter();
    let mut part = |name: &str, unread: &mut Vec<(String, String)>| -> Option<String> {
        match outs.next()? {
            Ok(o) => Some(o),
            Err(e) => {
                unread.push((name.to_string(), e.to_string()));
                None
            }
        }
    };
    fn parsed<T>(
        name: &str,
        text: Option<String>,
        unread: &mut Vec<(String, String)>,
        parse: impl Fn(&str) -> Result<T, String>,
    ) -> Option<T> {
        parse(&text?)
            .map_err(|e| unread.push((name.to_string(), format!("unreadable: {e}"))))
            .ok()
    }
    let mut unread = Vec::new();
    let listed = part("decisions", &mut unread);
    // The metrics are a bonus (the blocklists' counts): not having them isn't said.
    let metrics = part("metrics", &mut Vec::new());
    let alerts = part("alerts", &mut unread);
    let hub = part("hub", &mut unread);
    let bouncers = part("bouncers", &mut unread);
    c.decisions = metrics
        .and_then(|m| parse_metrics(&m).ok().flatten())
        .or_else(|| parsed("decisions", listed, &mut unread, parse_decisions));
    c.alerts = parsed("alerts", alerts, &mut unread, parse_alerts);
    c.hub = parsed("hub", hub, &mut unread, parse_hub);
    c.bouncers = parsed("bouncers", bouncers, &mut unread, parse_bouncers);
    // With the agent down the local API doesn't answer: that is the finding, not five more.
    if c.agent == Agent::Running || c.agent == Agent::NoUnit {
        c.unread = unread;
    }
    Ok(Some(c))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::fixture;
    use super::*;

    /// A server with CrowdSec as the fixtures have it, read at 2026-10-26 12:00 UTC.
    pub(crate) fn sample() -> Crowdsec {
        let (now, agent, version) = parse_head(&fixture("crowdsec-head.txt"));
        Crowdsec {
            agent,
            version,
            now,
            decisions: parse_metrics(&fixture("crowdsec-metrics.json")).unwrap(),
            alerts: Some(parse_alerts(&fixture("crowdsec-alerts.json")).unwrap()),
            hub: Some(parse_hub(&fixture("crowdsec-hub.json")).unwrap()),
            bouncers: Some(parse_bouncers(&fixture("crowdsec-bouncers.json")).unwrap()),
            unread: Vec::new(),
        }
    }

    fn counts(pairs: &[(&str, u32)]) -> BTreeMap<String, u32> {
        pairs.iter().map(|(k, n)| (k.to_string(), *n)).collect()
    }

    #[test]
    fn the_head_says_the_clock_the_unit_and_the_version() {
        let (now, agent, version) = parse_head(&fixture("crowdsec-head.txt"));
        assert_eq!(now, 1793016000);
        assert_eq!(agent, Agent::Running);
        assert_eq!(version.as_deref(), Some("v1.6.4-debian-pragmatic-amd64"));
        let down = "@@now\n5\n@@unit\nLoadState=loaded\nActiveState=failed\n@@version\n";
        assert_eq!(parse_head(down), (5, Agent::Down("failed".into()), None));
        // No unit (cscli beside an agent that runs elsewhere), and nothing at all.
        let none = "@@unit\nLoadState=not-found\nActiveState=inactive\n";
        assert_eq!(parse_head(none).1, Agent::NoUnit);
        assert_eq!(parse_head(""), (0, Agent::NoUnit, None));
        // Older releases log it to stderr, each line after a prefix.
        let old = "time=\"2026-10-26T12:00:00Z\" level=info msg=\"version: v1.4.6-5f71037b\"";
        assert_eq!(parse_version(old).as_deref(), Some("v1.4.6-5f71037b"));
    }

    #[test]
    fn listed_decisions_are_counted_by_type_and_origin_without_their_addresses() {
        let d = parse_decisions(&fixture("crowdsec-decisions.json")).unwrap();
        assert_eq!(d.by_type, counts(&[("ban", 3), ("captcha", 1)]));
        assert_eq!(d.by_origin, counts(&[("crowdsec", 3), ("cscli", 1)]));
        assert!(d.local_only);
        assert_eq!(
            (d.total(), d.local()),
            (4, 4),
            "the simulated one is left out"
        );
        // Nothing active: `null` (older releases), `[]`, an alert without decisions.
        for empty in ["null", "[]", "[{\"id\": 1, \"decisions\": null}]"] {
            assert_eq!(parse_decisions(empty).unwrap().total(), 0, "{empty}");
        }
        assert!(parse_decisions("").is_err());
        assert!(parse_decisions("{}").is_err());
        assert!(parse_decisions("No active decisions").is_err());
        let s = serde_json::to_string(&d).unwrap();
        assert!(!s.contains("192.0.2.") && !s.contains("2001:db8"), "{s}");
    }

    #[test]
    fn the_metrics_count_the_blocklists_too() {
        let d = parse_metrics(&fixture("crowdsec-metrics.json"))
            .unwrap()
            .unwrap();
        assert_eq!(d.by_type, counts(&[("ban", 15240), ("captcha", 1)]));
        assert_eq!(
            d.by_origin,
            counts(&[
                ("CAPI", 15000),
                ("crowdsec", 3),
                ("cscli", 1),
                ("lists", 237)
            ])
        );
        assert_eq!((d.total(), d.local()), (15241, 4));
        assert!(!d.local_only);
        // The endpoint is off, or nothing is active: no table, so the list is used.
        assert_eq!(parse_metrics("{}").unwrap(), None);
        assert_eq!(parse_metrics("{\"decisions\": {}}").unwrap(), None);
        assert_eq!(parse_metrics("{\"decisions\": null}").unwrap(), None);
        assert!(parse_metrics("").is_err());
    }

    #[test]
    fn alerts_keep_their_scenarios_only() {
        let a = parse_alerts(&fixture("crowdsec-alerts.json")).unwrap();
        assert_eq!(a.count, 6);
        assert!(!a.capped);
        assert_eq!(
            a.top,
            [
                ("example/ssh-bf".to_string(), 3),
                ("example/http-probing".to_string(), 2),
                ("manual 'ban' from <address>".to_string(), 1),
            ]
        );
        let s = serde_json::to_string(&a).unwrap();
        for addr in ["192.0.2.", "198.51.100.", "203.0.113.", "2001:db8"] {
            assert!(!s.contains(addr), "{addr} in {s}");
        }
        for empty in ["null", "[]"] {
            assert_eq!(parse_alerts(empty).unwrap(), Alerts::default());
        }
        let many = format!("[{}]", vec!["{\"scenario\":\"x/y\"}"; 500].join(","));
        let a = parse_alerts(&many).unwrap();
        assert!(a.capped && a.count == 500 && a.top == [("x/y".to_string(), 500)]);
        assert!(parse_alerts("No active alerts").is_err());
    }

    #[test]
    fn addresses_in_a_name_are_taken_out() {
        assert_eq!(scrub("example/ssh-bf"), "example/ssh-bf");
        assert_eq!(
            scrub("crowdsecurity/CVE-2022-26134"),
            "crowdsecurity/CVE-2022-26134"
        );
        assert_eq!(
            scrub("manual 'ban' from '192.0.2.7'"),
            "manual 'ban' from <address>"
        );
        assert_eq!(scrub("import 203.0.113.0/24 now"), "import <address> now");
        assert_eq!(scrub("ban 2001:db8::1"), "ban <address>");
        assert_eq!(scrub("update : +15000/-12 IPs"), "update : +15000/-12 IPs");
    }

    #[test]
    fn hub_items_behind_or_tainted_are_kept() {
        let h = parse_hub(&fixture("crowdsec-hub.json")).unwrap();
        let said: Vec<(&str, &str, HubState)> = h
            .iter()
            .map(|i| (i.kind.as_str(), i.name.as_str(), i.state))
            .collect();
        assert_eq!(
            said,
            [
                ("collections", "example/linux", HubState::Outdated),
                ("parsers", "example/sshd-logs", HubState::Tainted),
                ("scenarios", "example/ssh-bf", HubState::Outdated),
            ]
        );
        assert_eq!(h[0].version, "0.2");
        // Everything as the hub has it, a kind with no items, a kind that is null.
        let fine = r#"{"collections":[{"name":"a/b","status":"enabled","local_version":"1"}],
                       "parsers":[],"scenarios":null,"contexts":[{"name":"c","status":"enabled,local"}]}"#;
        assert!(parse_hub(fine).unwrap().is_empty());
        assert!(parse_hub("[]").is_err() && parse_hub("").is_err());
    }

    #[test]
    fn bouncers_with_when_they_last_pulled() {
        let b = parse_bouncers(&fixture("crowdsec-bouncers.json")).unwrap();
        assert_eq!(b.len(), 4);
        let now = 1793016000;
        assert_eq!(
            (b[0].name.as_str(), b[0].kind.as_str(), b[0].revoked),
            ("firewall-myserver", "crowdsec-firewall-bouncer", false)
        );
        assert_eq!(b[0].last_pull, Some(now - 8));
        assert_eq!(b[1].last_pull, Some(now - 3 * 86400), "an offset, not Z");
        assert_eq!(b[2].last_pull, None, "null: it never pulled");
        assert_eq!(b[3].last_pull, None, "the zero time of older releases");
        assert!(b[3].revoked);
        let s = serde_json::to_string(&b).unwrap();
        assert!(!s.contains("192.0.2.") && !s.contains("ip_address"), "{s}");
        for empty in ["null", "[]"] {
            assert!(parse_bouncers(empty).unwrap().is_empty());
        }
        assert!(parse_bouncers("{}").is_err());

        // Quiet: not revoked, and no pull within the hour, while the agent runs.
        let mut c = sample();
        let quiet: Vec<&str> = c.quiet_bouncers().iter().map(|b| b.name.as_str()).collect();
        assert_eq!(quiet, ["web-proxy", "new-bouncer"]);
        c.agent = Agent::Down("failed".into());
        assert!(c.quiet_bouncers().is_empty(), "the agent is the finding");
    }
}

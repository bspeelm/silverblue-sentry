//! What the firewall has counted, in one exec: every fw4 rule that carries a counter
//! (`nft -j list table inet fw4`), when those counters last started from zero (the mtime of
//! `/var/run/fw4.state`: a reload flushes the table), how full the connection table is, and
//! dnsmasq's own counters (`ubus call dnsmasq metrics`). Read every 10 s while Security is
//! in view.
//!
//! fw4 accepts established packets before any counted rule, so **a counter counts packets
//! that open a flow** (a new connection, a rejected packet), never traffic. Only some rules
//! have one: each uci rule and redirect, and each zone's closing accept, reject or drop.
//! What rejects traffic between two inside zones on a default config has none.
//!
//! A part the router doesn't have (no fw4 table, no dnsmasq object on ubus, no state file)
//! is absent here, never zero.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{CollectError, sections};
use sentry_app::remote::Remote;

pub const SCRIPT: &str = "command -v nft >/dev/null && { echo @@nft; \
     nft -j list table inet fw4 2>/dev/null; echo; }; \
     echo @@ct; cat /proc/sys/net/netfilter/nf_conntrack_count \
     /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null; \
     echo @@dns; ubus call dnsmasq metrics 2>/dev/null; \
     echo @@up; cat /proc/uptime; \
     echo @@state; date +%s; date -r /var/run/fw4.state +%s 2>/dev/null; true";

/// What a counted rule is, as far as its chain and its matches say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "role")]
pub enum Role {
    /// The zone's closing reject for what comes in from it (for the uplink's zone:
    /// unsolicited packets from outside).
    RejectFrom {
        zone: String,
    },
    /// The zone's closing reject for what would be forwarded into it.
    RejectTo {
        zone: String,
    },
    DropTo {
        zone: String,
    },
    /// New connections forwarded (or sent by the router) into the zone. Every zone allowed
    /// to reach it shares this one counter.
    AcceptTo {
        zone: String,
    },
    /// New connections from the zone to the router itself.
    AcceptFrom {
        zone: String,
    },
    /// A port forward: new connections from `zone` to `port`, sent on to `to`.
    Dnat {
        zone: String,
        proto: String,
        port: String,
        to: String,
    },
    /// DNS from the zone redirected to the router. It matches every DNS packet from there,
    /// those meant for the router too: not a count of anything bypassing it.
    DnsRedirect {
        zone: String,
        proto: String,
    },
    /// DNS over TLS (port 853) from the zone, rejected.
    DotReject {
        zone: String,
        proto: String,
    },
    /// Any other counted rule (a uci rule by its name).
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counted {
    pub chain: String,
    /// The rule's comment without fw4's mark: a uci rule's or redirect's name.
    pub name: String,
    /// The protocol and destination port it matches (`tcp:53`), where it matches one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub on: String,
    pub packets: u64,
    pub bytes: u64,
    #[serde(flatten)]
    pub role: Role,
}

impl Counted {
    /// What tells this rule from the others across reads (handles change on a reload).
    /// Two rules can still share it (one uci rule made into two that differ only in what
    /// this doesn't read): whoever compares reads adds those up.
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.chain, self.name, self.on)
    }
}

/// dnsmasq's counters since it started. There is no "blocked" among them: a blocked name
/// is answered locally, like a cache hit or a local name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsMetrics {
    pub forwarded: u64,
    pub local: u64,
    pub unanswered: u64,
    pub cache_inserted: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Counters {
    /// The counted rules (None: the router has no fw4 table, or no `nft`).
    pub rules: Option<Vec<Counted>>,
    /// The router's clock: seconds since boot, and the epoch.
    pub uptime: f64,
    pub now: i64,
    /// When the firewall was last loaded (its counters started from zero); None: unknown.
    pub reset_at: Option<i64>,
    /// Connections tracked, and how many the table holds.
    pub conntrack: Option<(u64, u64)>,
    pub dns: Option<DnsMetrics>,
}

fn port_of(right: &Value) -> Option<String> {
    if let Some(n) = right.as_u64() {
        return Some(n.to_string());
    }
    if let Some([a, b]) = right["range"].as_array().map(Vec::as_slice) {
        return Some(format!("{}-{}", a.as_u64()?, b.as_u64()?));
    }
    let set: Vec<String> = right["set"]
        .as_array()?
        .iter()
        .filter_map(port_of)
        .collect();
    (!set.is_empty()).then(|| set.join(","))
}

/// One rule of the table, when it has a counter.
fn counted(rule: &Value) -> Option<Counted> {
    let chain = rule["chain"].as_str()?.to_string();
    let exprs = rule["expr"].as_array()?;
    let c = exprs.iter().find_map(|e| e.get("counter"))?;
    let (mut proto, mut dport) = (None, None);
    let (mut verdict, mut to) = ("", String::new());
    for e in exprs {
        if let Some(m) = e.get("match") {
            let pay = &m["left"]["payload"];
            if pay["field"].as_str() == Some("dport") && m["op"].as_str() == Some("==") {
                proto = pay["protocol"].as_str().map(str::to_string);
                dport = port_of(&m["right"]);
            }
        } else if e.get("accept").is_some() {
            verdict = "accept";
        } else if e.get("drop").is_some() {
            verdict = "drop";
        } else if let Some(j) = e.get("jump").or(e.get("goto")) {
            if j["target"].as_str() == Some("handle_reject") {
                verdict = "reject";
            }
        } else if e.get("reject").is_some() {
            verdict = "reject";
        } else if let Some(d) = e.get("dnat") {
            verdict = "dnat";
            let addr = d["addr"].as_str().unwrap_or("?");
            to = match d["port"].as_u64() {
                Some(p) if addr.contains(':') => format!("[{addr}]:{p}"),
                Some(p) => format!("{addr}:{p}"),
                None => addr.to_string(),
            };
        } else if let Some(r) = e.get("redirect") {
            verdict = "redirect";
            to = r["port"].as_u64().map_or(String::new(), |p| p.to_string());
        }
    }
    let zone = |prefix: &str| chain.strip_prefix(prefix).map(str::to_string);
    let p = || proto.clone().unwrap_or_default();
    let role = if let (Some(zone), "reject") = (zone("reject_from_"), verdict) {
        Role::RejectFrom { zone }
    } else if let (Some(zone), "reject") = (zone("reject_to_"), verdict) {
        Role::RejectTo { zone }
    } else if let (Some(zone), "drop") = (zone("drop_to_"), verdict) {
        Role::DropTo { zone }
    } else if let (Some(zone), "accept") = (zone("accept_to_"), verdict) {
        Role::AcceptTo { zone }
    } else if let (Some(zone), "accept") = (zone("accept_from_"), verdict) {
        Role::AcceptFrom { zone }
    } else if let (Some(zone), "dnat", Some(port)) = (zone("dstnat_"), verdict, &dport) {
        Role::Dnat {
            zone,
            proto: p(),
            port: port.clone(),
            to: to.clone(),
        }
    } else if let (Some(zone), "redirect", Some("53"), "53") =
        (zone("dstnat_"), verdict, dport.as_deref(), to.as_str())
    {
        Role::DnsRedirect { zone, proto: p() }
    } else if let (Some(zone), "reject", Some("853")) =
        (zone("forward_"), verdict, dport.as_deref())
    {
        Role::DotReject { zone, proto: p() }
    } else {
        Role::Other
    };
    Some(Counted {
        chain,
        name: rule["comment"]
            .as_str()
            .unwrap_or("")
            .trim_start_matches("!fw4: ")
            .to_string(),
        on: match (&proto, &dport) {
            (Some(p), Some(d)) => format!("{p}:{d}"),
            _ => String::new(),
        },
        packets: c["packets"].as_u64()?,
        bytes: c["bytes"].as_u64().unwrap_or(0),
        role,
    })
}

/// The counted rules of `nft -j list table inet fw4`.
pub fn rules(json: &str) -> Result<Vec<Counted>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("nft: {e}"))?;
    Ok(v["nftables"]
        .as_array()
        .ok_or("nft: no `nftables` list")?
        .iter()
        .filter_map(|o| o.get("rule"))
        .filter(|r| r["table"].as_str() == Some("fw4"))
        .filter_map(counted)
        .collect())
}

pub fn parse(text: &str) -> Result<Counters, String> {
    let secs = sections(text);
    let body = |name: &str| {
        secs.iter()
            .find(|(n, _)| *n == name)
            .map(|(_, b)| b.trim())
            .filter(|b| !b.is_empty())
    };
    let up = body("up").ok_or("no uptime")?;
    let uptime: f64 = up
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or("uptime: not a number")?;
    let mut state = body("state")
        .unwrap_or("")
        .lines()
        .map(|l| l.trim().parse::<i64>().ok());
    let now = state.next().flatten().ok_or("no clock")?;
    let reset_at = state.next().flatten();
    let conntrack = body("ct").and_then(|b| {
        let mut n = b.lines().map(|l| l.trim().parse::<u64>().ok());
        Some((n.next()??, n.next()??))
    });
    let dns = body("dns").and_then(|b| {
        let v: Value = serde_json::from_str(b).ok()?;
        Some(DnsMetrics {
            forwarded: v["dns_queries_forwarded"].as_u64()?,
            local: v["dns_local_answered"].as_u64()?,
            unanswered: v["dns_unanswered"].as_u64().unwrap_or(0),
            cache_inserted: v["dns_cache_inserted"].as_u64().unwrap_or(0),
        })
    });
    Ok(Counters {
        rules: body("nft").map(rules).transpose()?,
        uptime,
        now,
        reset_at,
        conntrack,
        dns,
    })
}

pub fn collect(r: &Remote) -> Result<Counters, CollectError> {
    parse(&r.output(&r.sh(SCRIPT))?).map_err(CollectError::Parse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    #[test]
    fn the_counted_rules_by_what_they_are() {
        let c = parse(&fixture("network/counters.txt")).unwrap();
        let rules = c.rules.as_ref().unwrap();
        // 34 rules in the table; only those with a counter are kept.
        assert_eq!(rules.len(), 19, "{rules:#?}");
        let by = |f: &dyn Fn(&Role) -> bool| -> Vec<&Counted> {
            rules.iter().filter(|r| f(&r.role)).collect()
        };
        let wan = by(&|r| matches!(r, Role::RejectFrom { zone } if zone == "wan"));
        assert_eq!(
            (wan.len(), wan[0].packets, wan[0].bytes),
            (1, 31200, 1716000)
        );
        assert_eq!(wan[0].name, "reject wan IPv4/IPv6 traffic");
        // The port forwards, one rule for each protocol: a port, and a range with no
        // port of its own on the far side.
        let fw = by(&|r| matches!(r, Role::Dnat { .. }));
        assert_eq!(fw.len(), 2);
        assert_eq!(
            fw[0].role,
            Role::Dnat {
                zone: "wan".into(),
                proto: "tcp".into(),
                port: "443".into(),
                to: "203.0.113.93:443".into()
            }
        );
        assert_eq!((fw[0].name.as_str(), fw[0].packets), ("web", 5210));
        assert_eq!(
            fw[1].role,
            Role::Dnat {
                zone: "wan".into(),
                proto: "udp".into(),
                port: "8000-8010".into(),
                to: "192.0.2.20".into()
            }
        );
        // Forced DNS: the redirect on 53 and the reject on 853, each protocol its own.
        let dot = by(&|r| matches!(r, Role::DotReject { .. }));
        assert_eq!(dot.iter().map(|r| r.packets).collect::<Vec<_>>(), [1640, 0]);
        assert_ne!(dot[0].key(), dot[1].key(), "same comment, two rules");
        assert_eq!(by(&|r| matches!(r, Role::DnsRedirect { .. })).len(), 2);
        // The zones' closing rules. "Prevent NAT leakage" sits in accept_to_wan and drops:
        // it isn't the accept.
        let out = by(&|r| matches!(r, Role::AcceptTo { zone } if zone == "wan"));
        assert_eq!((out.len(), out[0].packets), (1, 902114));
        assert!(
            by(&|r| matches!(r, Role::RejectTo { zone } if zone == "dmz")).len() == 1
                && by(&|r| matches!(r, Role::RejectFrom { zone } if zone == "dmz")).len() == 1
                && by(&|r| matches!(r, Role::AcceptFrom { zone } if zone == "lan")).len() == 1
        );
        let other: Vec<&str> = by(&|r| *r == Role::Other)
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            other,
            [
                "Allow-DHCP-Renew",
                "Allow-Ping",
                "Prevent NAT leakage",
                "Allow-DMZ-DNS",
                "Allow-DMZ-DNS"
            ]
        );
        // The rest of the exec.
        assert_eq!(c.conntrack, Some((212, 16384)));
        assert_eq!(c.uptime, 1363000.50);
        assert_eq!((c.now, c.reset_at), (1793016000, Some(1792929600)));
        assert_eq!(
            c.dns,
            Some(DnsMetrics {
                forwarded: 37600,
                local: 20200,
                unanswered: 10,
                cache_inserted: 3120
            })
        );
    }

    /// No fw4 table, no dnsmasq object, no state file, no conntrack: each is absent, and
    /// the read still stands (the clock is all it needs).
    #[test]
    fn what_the_router_lacks_is_absent_not_zero() {
        let c = parse(&fixture("network/counters-bare.txt")).unwrap();
        assert_eq!(
            c,
            Counters {
                rules: None,
                uptime: 412.07,
                now: 1793016000,
                reset_at: None,
                conntrack: None,
                dns: None,
            }
        );
        // An empty table is a table: nothing counted, which is not the same as absent.
        let empty = parse("@@nft\n{\"nftables\": []}\n@@up\n1.0 1.0\n@@state\n5\n").unwrap();
        assert_eq!(empty.rules, Some(Vec::new()));
        // A rule without a counter isn't a zero.
        let one = rules(
            r#"{"nftables":[{"rule":{"family":"inet","table":"fw4","chain":"reject_from_wan",
            "expr":[{"jump":{"target":"handle_reject"}}]}}]}"#,
        )
        .unwrap();
        assert!(one.is_empty());
        // Another table's rules aren't fw4's.
        let other = rules(
            r#"{"nftables":[{"rule":{"family":"inet","table":"other","chain":"reject_from_wan",
            "expr":[{"counter":{"packets":1,"bytes":1}},{"jump":{"target":"handle_reject"}}]}}]}"#,
        )
        .unwrap();
        assert!(other.is_empty());
        assert!(parse("@@nft\nnot json\n@@up\n1 1\n@@state\n5\n").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn the_script_only_reads() {
        for w in SCRIPT.split(|c: char| c.is_whitespace() || c == ';') {
            assert!(
                !matches!(w, "add" | "delete" | "flush" | "reset" | "insert" | "kill"),
                "{w}"
            );
        }
        assert!(SCRIPT.contains("nft -j list table inet fw4"));
    }
}

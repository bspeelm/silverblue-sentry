//! The connections the router tracks now: `/proc/net/nf_conntrack`, one line a flow, with
//! what each side has sent so far where accounting is on. Read every 30 s while Security
//! is in view.
//!
//! These are live flows only: a flow leaves the table shortly after it ends (a minute or
//! three for UDP, two minutes for a closed TCP connection) and its counts go with it, so
//! nothing here is a total or a history. The table's own count
//! (`nf_conntrack_count`, the counters' read) can be larger than the lines listed: it
//! includes entries waiting to be collected.
//!
//! The output holds the addresses of everything the network talks to: it is never sent
//! anywhere, and a prompt gets counts and ports only (`tui::ask`).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::CollectError;
use sentry_app::remote::Remote;

/// The table, after a line that says whether per-flow accounting is on.
pub const SCRIPT: &str = "[ -r /proc/net/nf_conntrack ] || exit 127; \
     echo \"@acct $(cat /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null)\"; \
     cat /proc/net/nf_conntrack";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flow {
    /// `tcp`, `udp`, `icmp`…
    pub proto: String,
    /// As the first packet had them.
    pub src: IpAddr,
    pub dst: IpAddr,
    /// 0 where the protocol has none.
    pub sport: u16,
    pub dport: u16,
    /// TCP's state (`ESTABLISHED`, `TIME_WAIT`…); none for the others.
    pub state: Option<String>,
    /// Packets and bytes from the side that opened it, so far (None: accounting is off).
    pub packets: Option<u64>,
    pub bytes: Option<u64>,
    /// The same for the answers.
    pub reply_packets: Option<u64>,
    pub reply_bytes: Option<u64>,
    /// Nothing has answered yet.
    pub unreplied: bool,
    /// The kernel has handed it to a flow table: its counts may lag or stand still.
    pub offloaded: bool,
    /// Where it was really sent when that isn't where it was addressed: the address and
    /// port that answer (a port forward's target, the router for redirected DNS).
    pub dnat: Option<(IpAddr, u16)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flows {
    pub flows: Vec<Flow>,
    /// Lines the table had (a line that couldn't be read isn't a flow).
    pub lines: usize,
    /// Per-flow accounting (`nf_conntrack_acct`); None: the router didn't say.
    pub acct: Option<bool>,
}

/// One side's `src= dst= sport= dport= packets= bytes=`.
#[derive(Default)]
struct Side {
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    sport: u16,
    dport: u16,
    packets: Option<u64>,
    bytes: Option<u64>,
}

fn flow(line: &str) -> Option<Flow> {
    let w: Vec<&str> = line.split_whitespace().collect();
    // family, its number, protocol, its number, seconds left, [state], then the two sides.
    let proto = w.get(2)?.to_string();
    let state = w.get(5).filter(|s| !s.contains('=')).map(|s| s.to_string());
    let mut sides = [Side::default(), Side::default()];
    let mut at = 0;
    for kv in &w[5..] {
        let Some((k, v)) = kv.split_once('=') else {
            continue;
        };
        // A second `src=` starts the answering side.
        if k == "src" && sides[at].src.is_some() {
            at = 1;
        }
        let s = &mut sides[at.min(1)];
        match k {
            "src" => s.src = v.parse().ok(),
            "dst" => s.dst = v.parse().ok(),
            "sport" => s.sport = v.parse().unwrap_or(0),
            "dport" => s.dport = v.parse().unwrap_or(0),
            "packets" => s.packets = v.parse().ok(),
            "bytes" => s.bytes = v.parse().ok(),
            _ => {}
        }
    }
    let [o, r] = sides;
    let (src, dst) = (o.src?, o.dst?);
    let dnat = r
        .src
        .filter(|a| *a != dst || r.sport != o.dport)
        .map(|a| (a, r.sport));
    Some(Flow {
        proto,
        src,
        dst,
        sport: o.sport,
        dport: o.dport,
        state,
        packets: o.packets,
        bytes: o.bytes,
        reply_packets: r.packets,
        reply_bytes: r.bytes,
        unreplied: line.contains("[UNREPLIED]"),
        offloaded: line.contains("[OFFLOAD]") || line.contains("[HW_OFFLOAD]"),
        dnat,
    })
}

pub fn parse(text: &str) -> Flows {
    let mut out = Flows::default();
    for l in text.lines() {
        if let Some(a) = l.strip_prefix("@acct") {
            out.acct = match a.trim() {
                "1" => Some(true),
                "0" => Some(false),
                _ => None,
            };
            continue;
        }
        if l.trim().is_empty() {
            continue;
        }
        out.lines += 1;
        out.flows.extend(flow(l));
    }
    out
}

pub fn collect(r: &Remote) -> Result<Flows, CollectError> {
    use sentry_app::remote::Error;
    // The script gives up with 127 where the kernel has no such table.
    let text = r.output(&r.sh(SCRIPT)).map_err(|e| match e {
        Error::NotFound(_) => {
            CollectError::Unavailable("the connection table (/proc/net/nf_conntrack)".into())
        }
        e => e.into(),
    })?;
    Ok(parse(&text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn conntrack_lines_become_flows() {
        let text = format!("@acct 1\n{}", fixture("network/conntrack.txt"));
        let f = parse(&text);
        assert_eq!((f.lines, f.flows.len(), f.acct), (20, 20, Some(true)));
        // TCP out through the uplink: the state, both sides' counts, nothing rewritten on
        // the way there (the answer comes from where it was sent).
        let a = &f.flows[0];
        assert_eq!(
            (a.proto.as_str(), a.src, a.dst, a.sport, a.dport),
            ("tcp", ip("192.0.2.10"), ip("198.18.0.80"), 51514, 443)
        );
        assert_eq!(a.state.as_deref(), Some("ESTABLISHED"));
        assert_eq!(
            (a.packets, a.bytes, a.reply_packets, a.reply_bytes),
            (Some(120), Some(14200), Some(210), Some(260100))
        );
        assert!(!a.unreplied && !a.offloaded && a.dnat.is_none());
        // UDP has no state word.
        let u = f.flows.iter().find(|x| x.dport == 53).unwrap();
        assert_eq!((u.proto.as_str(), u.state.as_deref()), ("udp", None));
        // Forwarded in: addressed to the uplink, answered by the server behind it.
        let fwd: Vec<&Flow> = f
            .flows
            .iter()
            .filter(|x| x.dst == ip("198.51.100.23") && x.dport == 443)
            .collect();
        assert_eq!(fwd.len(), 2);
        assert_eq!(fwd[0].dnat, Some((ip("203.0.113.93"), 443)));
        // DNS addressed elsewhere and answered by the router: redirected.
        let forced = f.flows.iter().find(|x| x.dst == ip("198.18.8.8")).unwrap();
        assert_eq!(forced.dnat, Some((ip("192.0.2.1"), 53)));
        // Not answered yet.
        let syn = f.flows.iter().find(|x| x.sport == 40001).unwrap();
        assert!(syn.unreplied && syn.reply_packets == Some(0));
        assert_eq!(syn.state.as_deref(), Some("SYN_SENT"));
        // ICMP has no ports.
        let ping = f.flows.iter().find(|x| x.proto == "icmp").unwrap();
        assert_eq!((ping.sport, ping.dport, ping.dnat), (0, 0, None));
        // IPv6, as the kernel writes it (every group, every zero).
        let six: Vec<&Flow> = f.flows.iter().filter(|x| x.src.is_ipv6()).collect();
        assert_eq!(six.len(), 3);
        assert_eq!(six[0].src, ip("2001:db8:1200::114"));
        assert_eq!(six[0].dst, ip("2001:db8:ffff::1"));
        assert_eq!(six[0].bytes, Some(7200));
    }

    #[test]
    fn accounting_off_offload_and_noise() {
        // Without accounting a line has no counts: unknown, not nothing.
        let f = parse(
            "@acct 0\nipv4     2 udp      17 4 src=192.0.2.10 dst=198.18.0.1 sport=5 dport=6 \
             src=198.18.0.1 dst=198.51.100.23 sport=6 dport=5 [OFFLOAD] mark=0 zone=0 use=2\n\
             garbage\n\n",
        );
        assert_eq!((f.lines, f.flows.len(), f.acct), (2, 1, Some(false)));
        let x = &f.flows[0];
        assert_eq!((x.packets, x.bytes, x.reply_bytes), (None, None, None));
        assert!(x.offloaded);
        assert_eq!(parse("@acct \n").acct, None);
        assert_eq!(parse(""), Flows::default());
    }
}

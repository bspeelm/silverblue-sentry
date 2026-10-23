//! Listening and established sockets via `ss`; cheap counts from /proc/net for the dashboard.

use serde::{Deserialize, Serialize};

use super::{CResult, Ctx, fields};
use crate::baseline::Baseline;
use crate::exec::Cmd;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenStatus {
    /// Matched by the baseline.
    Baseline,
    /// Loopback or multicast group: not reachable from outside, not a finding.
    Local,
    /// UDP socket on an ephemeral port (browser WebRTC/QUIC, mDNS clients): a client socket
    /// rather than a service, not a finding.
    Ephemeral,
    /// Reachable bind not in the baseline.
    New,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Listener {
    pub proto: String,
    pub addr: String,
    pub port: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub status: ListenStatus,
}

impl Listener {
    pub fn local(&self) -> String {
        format!("{}:{}", self.addr, self.port)
    }

    /// Baseline key: `addr:port/process`.
    pub fn key(&self) -> String {
        format!(
            "{}/{}",
            self.local(),
            self.process.as_deref().unwrap_or("?")
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Conn {
    pub local: String,
    pub peer: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Net {
    pub listeners: Vec<Listener>,
    pub established: Vec<Conn>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct Counts {
    pub listening: usize,
    pub established: usize,
}

pub fn collect(ctx: &Ctx) -> CResult<Net> {
    let listen = Cmd::host("ss").arg("-tulpnH").output()?;
    let est = Cmd::host("ss")
        .args(["-tnpH", "state", "established"])
        .output()?;
    let mut n = Net {
        listeners: parse_listen(&listen),
        established: parse_established(&est),
    };
    classify(&mut n.listeners, &Baseline::effective(&ctx.cfg));
    Ok(n)
}

pub fn classify(ls: &mut [Listener], b: &Baseline) {
    let low = ephemeral_low();
    for l in ls {
        l.status = if b.has_listener(&l.key()) {
            ListenStatus::Baseline
        } else if is_local(&l.addr) {
            ListenStatus::Local
        } else if is_ephemeral(l, low) {
            ListenStatus::Ephemeral
        } else {
            ListenStatus::New
        };
    }
}

/// Lower bound of the kernel's ephemeral port range (`ip_local_port_range`, default 32768).
pub fn ephemeral_low() -> u16 {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(32768)
}

/// UDP bound to an ephemeral port: a client socket. TCP LISTEN is always deliberate.
pub fn is_ephemeral(l: &Listener, low: u16) -> bool {
    l.proto.starts_with("udp") && l.port.parse::<u16>().is_ok_and(|p| p >= low)
}

pub fn is_local(addr: &str) -> bool {
    let a = addr.trim_start_matches('[').trim_end_matches(']');
    if a.starts_with("127.") || a == "::1" || a.contains("%lo") {
        return true;
    }
    // IPv4 multicast groups (224.0.0.0/4) and IPv6 multicast (ff00::/8).
    let first = a.split('.').next().and_then(|o| o.parse::<u8>().ok());
    matches!(first, Some(224..=239)) || a.to_ascii_lowercase().starts_with("ff")
}

/// `127.0.0.53%lo:53` → (`127.0.0.53%lo`, `53`); `[::]:22` → (`[::]`, `22`); `*:5353` → (`*`, `5353`).
pub fn split_addr(s: &str) -> (String, String) {
    match s.rsplit_once(':') {
        Some((a, p)) => (a.to_string(), p.to_string()),
        None => (s.to_string(), String::new()),
    }
}

/// `users:(("wsdd",pid=19947,fd=12),("x",pid=1,fd=2))` → first (name, pid).
pub fn parse_users(s: &str) -> Option<(String, Option<u32>)> {
    let inner = s.strip_prefix("users:((")?;
    let name_start = inner.find('"')? + 1;
    let name_end = name_start + inner[name_start..].find('"')?;
    let name = inner[name_start..name_end].to_string();
    let pid = inner[name_end..]
        .split([',', ')'])
        .find_map(|t| t.strip_prefix("pid="))
        .and_then(|p| p.parse().ok());
    Some((name, pid))
}

/// The process column may contain spaces inside quotes, so it's everything from `users:(`.
fn split_users(line: &str) -> (&str, Option<&str>) {
    match line.find("users:(") {
        Some(i) => (&line[..i], Some(line[i..].trim())),
        None => (line, None),
    }
}

/// `ss -tulpnH`: `netid state recv-q send-q local peer [users:(...)]`.
pub fn parse_listen(text: &str) -> Vec<Listener> {
    let mut out: Vec<Listener> = Vec::new();
    for line in text.lines() {
        let (head, users) = split_users(line);
        let f = fields(head);
        if f.len() < 5 {
            continue;
        }
        let (addr, port) = split_addr(f[4]);
        let (process, pid) = users
            .and_then(parse_users)
            .map(|(n, p)| (Some(n), p))
            .unwrap_or((None, None));
        let l = Listener {
            proto: f[0].to_string(),
            addr,
            port,
            process,
            pid,
            status: ListenStatus::New,
        };
        if !out.iter().any(|o| {
            o.proto == l.proto && o.addr == l.addr && o.port == l.port && o.process == l.process
        }) {
            out.push(l);
        }
    }
    out.sort_by(|a, b| (&a.proto, &a.addr, &a.port).cmp(&(&b.proto, &b.addr, &b.port)));
    out
}

/// `ss -tnpH state established`: `recv-q send-q local peer [users:(...)]` (no netid/state).
pub fn parse_established(text: &str) -> Vec<Conn> {
    text.lines()
        .filter_map(|line| {
            let (head, users) = split_users(line);
            let f = fields(head);
            if f.len() < 4 {
                return None;
            }
            let (process, pid) = users
                .and_then(parse_users)
                .map(|(n, p)| (Some(n), p))
                .unwrap_or((None, None));
            Some(Conn {
                local: f[2].to_string(),
                peer: f[3].to_string(),
                process,
                pid,
            })
        })
        .collect()
}

/// Socket counts straight from /proc/net (no subprocess); used at dashboard refresh rate.
pub fn proc_counts() -> Counts {
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    let mut c = Counts::default();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let (l, e) = count_tcp(&read(f));
        c.listening += l;
        c.established += e;
    }
    for f in ["/proc/net/udp", "/proc/net/udp6"] {
        // Unconnected UDP sockets (state 07) are the UDP equivalent of listeners.
        c.listening += read(f)
            .lines()
            .skip(1)
            .filter(|l| fields(l).get(3) == Some(&"07"))
            .count();
    }
    c
}

pub fn count_tcp(text: &str) -> (usize, usize) {
    let mut listen = 0;
    let mut est = 0;
    for l in text.lines().skip(1) {
        match fields(l).get(3).copied() {
            Some("0A") => listen += 1,
            Some("01") => est += 1,
            _ => {}
        }
    }
    (listen, est)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::fixture;

    #[test]
    fn listen_fixture() {
        let ls = parse_listen(&fixture("net/ss-listen.txt"));
        assert!(ls.len() > 5);
        let wsdd = ls
            .iter()
            .find(|l| l.process.as_deref() == Some("wsdd"))
            .unwrap();
        assert_eq!(wsdd.pid, Some(19947));
        assert!(
            ls.iter()
                .any(|l| l.addr == "127.0.0.53%lo" && l.port == "53" && l.process.is_none())
        );
        // duplicate multicast binds collapse
        let brave = ls
            .iter()
            .filter(|l| l.process.as_deref() == Some("brave") && l.port == "5353")
            .count();
        assert_eq!(brave, 1);
    }

    #[test]
    fn edge_cases() {
        let text = "tcp LISTEN 0 4096 [::]:22 [::]:* users:((\"sshd\",pid=880,fd=4))\n\
                    udp UNCONN 0 0 [fe80::1%enp4s0]:546 [::]:*\n\
                    tcp LISTEN 0 128 *:5355 *:* users:((\"my app\",pid=7,fd=3),(\"other\",pid=8,fd=3))\n";
        let ls = parse_listen(text);
        let ssh = ls.iter().find(|l| l.port == "22").unwrap();
        assert_eq!(
            (ssh.addr.as_str(), ssh.process.as_deref()),
            ("[::]", Some("sshd"))
        );
        assert!(
            ls.iter()
                .any(|l| l.addr == "[fe80::1%enp4s0]" && l.port == "546")
        );
        let star = ls.iter().find(|l| l.port == "5355").unwrap();
        assert_eq!(
            (star.addr.as_str(), star.process.as_deref(), star.pid),
            ("*", Some("my app"), Some(7))
        );
    }

    #[test]
    fn established_fixture() {
        let es = parse_established(&fixture("net/ss-established.txt"));
        assert!(!es.is_empty());
        assert!(es.iter().all(|c| c.peer.contains(':')));
        assert!(es.iter().any(|c| c.process.as_deref() == Some("slack")));
    }

    #[test]
    fn classification() {
        let mut ls = parse_listen(
            "tcp LISTEN 0 5 127.0.0.1:631 0.0.0.0:* users:((\"cupsd\",pid=1,fd=1))\n\
             tcp LISTEN 0 5 0.0.0.0:22000 0.0.0.0:* users:((\"syncthing\",pid=2,fd=1))\n\
             tcp LISTEN 0 5 127.0.0.1:8384 0.0.0.0:* users:((\"syncthing\",pid=2,fd=1))\n\
             udp UNCONN 0 0 224.0.0.251:5353 0.0.0.0:* users:((\"brave\",pid=3,fd=1))\n\
             udp UNCONN 0 0 0.0.0.0:35905 0.0.0.0:* users:((\"wsdd\",pid=4,fd=1))\n",
        );
        classify(
            &mut ls,
            &Baseline {
                listeners: vec!["127.0.0.1:631/cupsd".into()],
                findings: vec![],
            },
        );
        let st = |port: &str| ls.iter().find(|l| l.port == port).unwrap().status;
        assert_eq!(st("631"), ListenStatus::Baseline);
        assert_eq!(st("22000"), ListenStatus::New);
        assert_eq!(st("8384"), ListenStatus::Local);
        assert_eq!(st("5353"), ListenStatus::Local);
        assert_eq!(
            st("35905"),
            ListenStatus::Ephemeral,
            "udp on an ephemeral port"
        );
    }

    #[test]
    fn proc_net_counts() {
        let tcp = "  sl  local_address rem_address   st tx_queue\n\
                   0: 0100007F:0277 00000000:0000 0A 00000000:00000000\n\
                   1: 2401A8C0:B0C2 5DF66B22:01BB 01 00000000:00000000\n\
                   2: 2401A8C0:B0C4 5DF66B22:01BB 06 00000000:00000000\n";
        assert_eq!(count_tcp(tcp), (1, 1));
    }

    #[test]
    fn users_parser() {
        assert_eq!(
            parse_users("users:((\"wsdd\",pid=19947,fd=12))"),
            Some(("wsdd".into(), Some(19947)))
        );
        assert_eq!(parse_users("garbage"), None);
    }
}

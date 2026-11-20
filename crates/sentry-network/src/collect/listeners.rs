//! What listens on the router: `netstat -lntup` (busybox; there is no `ss`), as the listeners
//! the shared Network view and the audit's rule take. Program names come cut at 14
//! characters. Read on entering Network and on `r`.

use sentry_core::collectors::net::{ListenStatus, Listener};

use super::{CollectError, output_needing};
use sentry_app::remote::Remote;

pub const SCRIPT: &str = "netstat -lntup";

/// `0.0.0.0:443` → (`0.0.0.0`, `443`); `:::22` → (`[::]`, `22`); `fe80::1:53` →
/// (`[fe80::1]`, `53`): the port follows the last colon, and an IPv6 address is bracketed
/// as `ss` writes it.
fn split(local: &str) -> Option<(String, String)> {
    let (addr, port) = local.rsplit_once(':')?;
    let addr = if addr.contains(':') {
        format!("[{addr}]")
    } else {
        addr.to_string()
    };
    Some((addr, port.to_string()))
}

/// `Proto Recv-Q Send-Q Local Foreign [State] PID/Program`; a UDP row has no state.
pub fn parse(text: &str) -> Vec<Listener> {
    let mut out: Vec<Listener> = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let Some(proto) = f
            .first()
            .filter(|p| p.starts_with("tcp") || p.starts_with("udp"))
        else {
            continue;
        };
        let Some((addr, port)) = f.get(3).and_then(|l| split(l)) else {
            continue;
        };
        if proto.starts_with("tcp") && f.get(5) != Some(&"LISTEN") {
            continue;
        }
        // The owner is the last column; `-` where the kernel holds the socket.
        let (pid, process) = match f.last().and_then(|o| o.split_once('/')) {
            Some((pid, name)) if f.len() > 5 => (pid.parse().ok(), Some(name.to_string())),
            _ => (None, None),
        };
        let l = Listener {
            // `tcp6` and `udp6` (other builds) are the same protocols.
            proto: proto.trim_end_matches('6').to_string(),
            addr,
            port,
            process,
            pid,
            status: ListenStatus::New,
        };
        // A link-local address is listed once for each interface that has it.
        if !out.contains(&l) {
            out.push(l);
        }
    }
    out
}

pub fn collect(r: &Remote) -> Result<Vec<Listener>, CollectError> {
    Ok(parse(&output_needing(r, "netstat", SCRIPT)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    #[test]
    fn netstat_rows_become_listeners() {
        let l = parse(&fixture("network/netstat.txt"));
        assert_eq!(l.len(), 25, "{l:#?}");
        let find = |proto: &str, local: &str| {
            l.iter()
                .find(|x| x.proto == proto && x.local() == local)
                .unwrap_or_else(|| panic!("{proto} {local}"))
        };
        let web = find("tcp", "0.0.0.0:443");
        assert_eq!(
            (web.process.as_deref(), web.pid),
            (Some("uhttpd"), Some(2101))
        );
        assert_eq!(web.key(), "0.0.0.0:443/uhttpd");
        // IPv6: the port is what follows the last colon.
        assert_eq!(find("tcp", "[::]:22").process.as_deref(), Some("dropbear"));
        assert_eq!(find("tcp", "[2001:db8:1200::1]:53").port, "53");
        assert_eq!(
            find("udp", "[fe80::5eff:fe00:53a0]:53").addr,
            "[fe80::5eff:fe00:53a0]"
        );
        assert_eq!(find("tcp", "[::1]:53").addr, "[::1]");
        // A name longer than 14 characters arrives cut; it's kept as given.
        assert_eq!(
            find("tcp", "127.0.0.1:5053").process.as_deref(),
            Some("https-dns-prox")
        );
        // UDP has no state column, and the kernel's own socket no owner.
        assert_eq!(
            find("udp", "0.0.0.0:67").process.as_deref(),
            Some("dnsmasq")
        );
        let bare = find("udp", "198.51.100.23:1900");
        assert_eq!((bare.process.as_deref(), bare.pid), (None, None));
        assert_eq!(bare.key(), "198.51.100.23:1900/?");
    }

    #[test]
    fn the_same_socket_twice_is_one_row_and_noise_is_none() {
        let text = "Active Internet connections (only servers)\n\
            Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\n\
            tcp 0 0 fe80::1:53 :::* LISTEN 2202/dnsmasq\n\
            tcp 0 0 fe80::1:53 :::* LISTEN 2202/dnsmasq\n\
            tcp 0 0 192.0.2.1:40000 192.0.2.9:22 ESTABLISHED 1/x\n\
            tcp6 0 0 :::80 :::* LISTEN 9/uhttpd\n";
        let l = parse(text);
        assert_eq!(l.len(), 2);
        assert_eq!(
            (l[1].proto.as_str(), l[1].local()),
            ("tcp", "[::]:80".to_string())
        );
        assert!(parse("").is_empty());
    }
}

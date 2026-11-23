//! What the Config tab's wizard may be shown of a config file: the words that stand in for
//! what is hidden, and [`mask`], the net under every rule. Each kind of config hides what is
//! private in its own file by its own rules (an ssh target, a path, a device); `mask` then
//! goes over every text that is sent or printed and takes out whatever still looks like an
//! address, a MAC, a `user@host` or a path under someone's home, wherever it stands.

/// What stands where something was hidden.
pub const HIDDEN: &str = "‹hidden›";
pub const ADDR: &str = "‹addr›";
pub const MAC: &str = "‹mac›";
pub const LOGIN: &str = "‹user@host›";

/// A file's path as the wizard may see it: its last name only (`…/notes.md`).
pub fn file_name(path: &str) -> String {
    let name = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default();
    match name.is_empty() {
        true => HIDDEN.to_string(),
        false => format!("…/{name}"),
    }
}

/// An age recipient as the wizard may see it: a public key by its first characters, a file
/// holding keys by its name only.
pub fn recipient(r: &str) -> String {
    match r.trim().strip_prefix("age1") {
        Some(rest) => format!("age1{}…", rest.chars().take(4).collect::<String>()),
        None => file_name(r),
    }
}

fn hex_pair(b: &[u8]) -> bool {
    b.len() == 2 && b.iter().all(u8::is_ascii_hexdigit)
}

/// The length of the MAC that starts at `b` (six hex pairs with `:` or `-` between), if one
/// does and nothing that could be more of it follows.
fn mac_at(b: &[u8]) -> Option<usize> {
    if b.len() < 17 {
        return None;
    }
    let sep = b[2];
    if sep != b':' && sep != b'-' {
        return None;
    }
    for i in 0..6 {
        if !hex_pair(&b[3 * i..3 * i + 2]) || (i < 5 && b[3 * i + 2] != sep) {
            return None;
        }
    }
    match b.get(17) {
        Some(c) if c.is_ascii_hexdigit() || *c == sep => None,
        _ => Some(17),
    }
}

/// Twelve hex digits in three dotted groups (`0200.5e00.5301`).
fn dotted_mac_at(b: &[u8]) -> Option<usize> {
    if b.len() < 14 {
        return None;
    }
    for i in 0..3 {
        if !b[5 * i..5 * i + 4].iter().all(u8::is_ascii_hexdigit) || (i < 2 && b[5 * i + 4] != b'.')
        {
            return None;
        }
    }
    match b.get(14) {
        Some(c) if c.is_ascii_alphanumeric() || *c == b'.' => None,
        _ => Some(14),
    }
}

/// Every MAC in `text` is `‹mac›`.
fn without_macs(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut start = 0;
    while i < b.len() {
        let boundary = i == 0 || !(b[i - 1].is_ascii_hexdigit());
        if boundary
            && b[i].is_ascii_hexdigit()
            && let Some(n) = mac_at(&b[i..]).or_else(|| dotted_mac_at(&b[i..]))
        {
            out.push_str(&text[start..i]);
            out.push_str(MAC);
            i += n;
            start = i;
            continue;
        }
        i += 1;
    }
    out.push_str(&text[start..]);
    out
}

/// An address that says nothing about anyone's network: loopback, or "any".
fn anyones(ip: &std::net::IpAddr) -> bool {
    ip.is_loopback() || ip.is_unspecified()
}

/// A word that is an address (with a port or a prefix length after it, perhaps): what
/// stands for it. None: not an address, or one that is anyone's.
fn addr(word: &str) -> Option<String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    // What follows a slash stays as it is: a prefix length, or a socket's process
    // (`addr:port/process`).
    let (head, len) = match word.split_once('/') {
        Some((h, l)) => (h, format!("/{l}")),
        None => (word, String::new()),
    };
    // v4, with a port perhaps (a number, or `*` for any).
    let (host, port) = match head.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && (p == "*" || p.bytes().all(|c| c.is_ascii_digit())) => {
            (h, format!(":{p}"))
        }
        _ => (head, String::new()),
    };
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return (!anyones(&IpAddr::V4(ip))).then(|| format!("{ADDR}{port}{len}"));
    }
    // v6, with a zone perhaps.
    let bare = head.split('%').next().unwrap_or(head);
    if let Ok(ip) = bare.parse::<Ipv6Addr>() {
        return (!anyones(&IpAddr::V6(ip))).then(|| format!("{ADDR}{len}"));
    }
    None
}

/// `user@host`: a login name, an `@`, and something after it.
fn login(word: &str) -> bool {
    let name = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
    };
    match word.split_once('@') {
        Some((user, host)) => {
            name(user)
                && !host.is_empty()
                && host.chars().all(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '[' | ']')
                })
        }
        None => false,
    }
}

/// A path under someone's home (it names them): its last name only.
fn home_path(word: &str) -> Option<String> {
    ["/home/", "/var/home/", "/root/", "/Users/"]
        .iter()
        .any(|p| word.starts_with(p))
        .then(|| file_name(word))
}

/// `text` without anything in it that looks like an address (but loopback and "any"), a
/// MAC, a `user@host` or a path under a home directory. Hostnames and names can't be told
/// from other words: those are hidden where they are known to stand, by each kind's rules.
pub fn mask(text: &str) -> String {
    let text = without_macs(text);
    let mut out = String::with_capacity(text.len());
    // A word is what stands between spaces, quotes and brackets; what ends a sentence
    // after it isn't part of it.
    let breaks = |c: char| c.is_whitespace() || "\"'`()<>{},;=|".contains(c);
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let end = rest.find(breaks).unwrap_or(rest.len());
        if end == 0 {
            let c = rest.chars().next().map_or(1, char::len_utf8);
            out.push_str(&rest[..c]);
            rest = &rest[c..];
            continue;
        }
        let word = &rest[..end];
        rest = &rest[end..];
        let core = word.trim_end_matches(['.', ':', '!', '?']);
        let tail = &word[core.len()..];
        // (An address in brackets, as a socket is written: `[2001:db8::1]:443`.)
        let unbracketed = core
            .strip_prefix('[')
            .and_then(|c| c.split_once(']'))
            .map(|(a, port)| (a, port.to_string()));
        let masked = if login(core) {
            Some(LOGIN.to_string())
        } else if let Some((a, port)) = &unbracketed {
            addr(a).map(|m| format!("{m}{port}"))
        } else {
            addr(core).or_else(|| home_path(core))
        };
        match masked {
            Some(m) => {
                out.push_str(&m);
                out.push_str(tail);
            }
            None => out.push_str(word),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whatever_looks_private_is_masked_wherever_it_stands() {
        for (text, want) in [
            ("holds 192.0.2.44 now", "holds ‹addr› now"),
            ("to `192.0.2.7:8443` isn't", "to `‹addr›:8443` isn't"),
            ("net 198.51.100.0/24.", "net ‹addr›/24."),
            ("[2001:db8::1]:443 and 2001:db8::5", "‹addr›:443 and ‹addr›"),
            ("fe80::1%eth0", "‹addr›"),
            (
                "198.51.100.7:8443/app and 192.0.2.9:*/*",
                "‹addr›:8443/app and ‹addr›:*/*",
            ),
            ("MAC 02:00:5E:00:53:01 is", "MAC ‹mac› is"),
            ("sta:02-00-5e-00-53-0a,", "sta:‹mac›,"),
            ("0200.5e00.5301 x", "‹mac› x"),
            (
                "from admin@192.0.2.10 (Debian)",
                "from ‹user@host› (Debian)",
            ),
            ("ssh root@myrouter.lan once", "ssh ‹user@host› once"),
            ("/home/someone/notes/run.md", "…/run.md"),
            ("/var/home/someone/x.yml,", "…/x.yml,"),
        ] {
            assert_eq!(mask(text), want, "{text}");
        }
        // What is anyone's, and what only looks like one, stays.
        for text in [
            "*:443/* and 127.0.0.1:*/* and [::1]:*/*",
            "0.0.0.0:22 :: tcp:22@lan",
            "25.12.5 at 13:10, 26h, /mnt/tank 85%",
            "backup.timer app.service docker:library/nginx",
            "aa:bb:cc and 12:34",
        ] {
            assert_eq!(mask(text), text);
        }
    }

    #[test]
    fn a_path_is_its_name_and_a_recipient_its_first_characters() {
        assert_eq!(
            file_name("/srv/stack/docker-compose.yml"),
            "…/docker-compose.yml"
        );
        assert_eq!(file_name("~/keys/"), "…/keys");
        assert_eq!(file_name(""), HIDDEN);
        assert_eq!(recipient("age1qqqqexamplekeyexamplekey"), "age1qqqq…");
        assert_eq!(recipient("~/.config/keys/backup.pub"), "…/backup.pub");
    }
}

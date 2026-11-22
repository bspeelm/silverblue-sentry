//! Secrets never leave the read that found them: the value of a `uci` option that looks like
//! one (a key, a password, a token) is replaced, as it's parsed, by a tag that says only
//! whether it changed. The tag is a keyed hash's first bytes; the key is a random salt kept
//! for each network beside its records (`networks/<name>/salt`, mode 0600), so the same value
//! gives the same tag on this machine and nothing else can be learnt from it.

use std::io::{Read, Write};
use std::path::PathBuf;

/// The option names whose values are secrets, compared with the option's last name segment
/// only: `wireless.x.key` is one, `dropbear.main.PasswordAuth` and `uhttpd.defaults.key_type`
/// (which the audit reads) are not.
const SECRET: &[&str] = &[
    "key",
    "key1",
    "key2",
    "key3",
    "key4",
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "psk",
    "pmk",
    "secret",
    "token",
    "private",
    "pin",
    "pincode",
    "apikey",
    "sae_password",
    // 802.11r key holders: each value ends in the key they share.
    "r0kh",
    "r1kh",
];

/// Whether an option (its own name, or the whole `pkg.section.option`) holds a secret.
pub fn secret(option: &str) -> bool {
    let last = option
        .rsplit('.')
        .next()
        .unwrap_or(option)
        .to_ascii_lowercase();
    SECRET
        .iter()
        .any(|s| last == *s || last.ends_with(&format!("_{s}")))
}

/// The same, or one of a daemon's own names for a passphrase: what a staging line must
/// never be written down with.
pub fn secret_option(option: &str) -> bool {
    secret(option) || wifi_secret(option)
}

/// A network's salt.
#[derive(Clone, PartialEq, Eq)]
pub struct Salt([u8; 16]);

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Salt(..)")
    }
}

pub fn path(scope: &str) -> PathBuf {
    sentry_core::maint::root(scope).join("salt")
}

fn unhex(text: &str) -> Option<[u8; 16]> {
    let t = text.trim();
    if t.len() != 32 || !t.is_ascii() {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

impl Salt {
    /// A salt given outright (tests).
    pub fn fixed(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The network's salt, made the first time it's needed.
    pub fn load(scope: &str) -> std::io::Result<Self> {
        let p = path(scope);
        if let Some(s) = std::fs::read_to_string(&p).ok().as_deref().and_then(unhex) {
            return Ok(Self(s));
        }
        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        opts.open(&p)?.write_all(format!("{hex}\n").as_bytes())?;
        Ok(Self(bytes))
    }

    /// What stands in for a secret value: `redacted:1a2b3c4d`. The same value, the same tag.
    pub fn tag(&self, value: &str) -> String {
        let k0 = u64::from_le_bytes(self.0[..8].try_into().expect("8 bytes"));
        let k1 = u64::from_le_bytes(self.0[8..].try_into().expect("8 bytes"));
        format!("redacted:{:08x}", siphash24(k0, k1, value.as_bytes()) >> 32)
    }
}

/// A tag, wherever it stands.
pub fn is_tag(value: &str) -> bool {
    value
        .strip_prefix("redacted:")
        .is_some_and(|h| h.len() == 8 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// SipHash-2-4 (Aumasson, Bernstein): a keyed hash that's short to write down, so the tags
/// don't depend on a library's choice of algorithm.
fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    fn round(v: &mut [u64; 4]) {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13);
        v[1] ^= v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16);
        v[3] ^= v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21);
        v[3] ^= v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17);
        v[1] ^= v[2];
        v[2] = v[2].rotate_left(32);
    }
    let (chunks, rest) = data.as_chunks::<8>();
    for c in chunks {
        let m = u64::from_le_bytes(*c);
        v[3] ^= m;
        round(&mut v);
        round(&mut v);
        v[0] ^= m;
    }
    let mut last = [0u8; 8];
    last[..rest.len()].copy_from_slice(rest);
    last[7] = data.len() as u8;
    let m = u64::from_le_bytes(last);
    v[3] ^= m;
    round(&mut v);
    round(&mut v);
    v[0] ^= m;
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

// ---- what Claude sees

/// What must not leave this machine in anything Claude is sent: built from what the router
/// says about itself now (its uplink's addresses, its SSIDs, who holds a lease) and from the
/// config (which devices have names). One `text` pass over anything from the router that
/// goes into a prompt or comes back through the gateway:
/// - the value of a secret option, as `uci show` and `uci export` print it, in JSON and in
///   `name=value` files → the same tag the collectors use; a private key block and a
///   password hash → a word saying so;
/// - the uplink's addresses and the prefix delegated to it → `‹wan›` / `‹wan6›`, unless
///   `claude.share_wan_address`;
/// - a MAC the config names → `‹name›`; any other → its first three bytes and `:xx:xx:xx`;
/// - an SSID → `‹ssid-N›`, numbered in the config's order;
/// - a lease's hostname → the config's name for the device, or `‹host-xxxx›` (a tag of the
///   name, the same every time).
#[derive(Debug, Clone)]
pub struct Scrub {
    salt: Salt,
    /// The uplink's own addresses.
    wan4: Vec<std::net::Ipv4Addr>,
    /// The networks they are on: every other address there is the provider's.
    net4: Vec<(std::net::Ipv4Addr, u8)>,
    gw4: Vec<std::net::Ipv4Addr>,
    /// An address is a /128; a delegated prefix, and the network an address is on, cover
    /// everything under them.
    wan6: Vec<(std::net::Ipv6Addr, u8)>,
    gw6: Vec<std::net::Ipv6Addr>,
    /// MAC → the name the config gives its device.
    named: Vec<(String, String)>,
    ssids: Vec<String>,
    /// Hostname → what stands for it.
    hosts: Vec<(String, String)>,
    /// The tags of the secrets the config holds: a value that hashes to one of them is a
    /// secret wherever it stands (the values themselves are never kept).
    tags: Vec<String>,
}

/// What the router said, for a [`Scrub`].
#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// The uplink's addresses and delegated prefixes, with or without a mask.
    pub wan: Vec<String>,
    pub ssids: Vec<String>,
    /// The uplink's gateways (the provider's side of it).
    pub gateways: Vec<String>,
    /// (hostname, MAC) of each lease and static host.
    pub leases: Vec<(String, Option<String>)>,
    /// The tags of every secret option the config was read with.
    pub tags: Vec<String>,
}

fn private4(a: std::net::Ipv4Addr) -> bool {
    // (The documentation ranges are nobody's address: what the fixtures use for a LAN.)
    a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_documentation()
}

fn private6(a: std::net::Ipv6Addr) -> bool {
    let s = a.segments()[0];
    a.is_loopback() || a.is_unspecified() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
}

impl Facts {
    /// From the collectors' reads. Every address of an interface that has the default
    /// route or is called `wan…`, and every public address of any other.
    pub fn of(
        ifaces: &crate::collect::ifaces::Ifaces,
        uci: &crate::collect::uci::Uci,
        leases: &[(String, Option<String>)],
    ) -> Self {
        let mut wan = Vec::new();
        let mut gateways = Vec::new();
        for i in &ifaces.interfaces {
            gateways.extend(i.gateway.iter().chain(&i.gateway6).cloned());
            let uplink = i.gateway.is_some() || i.gateway6.is_some() || i.name.starts_with("wan");
            for a in i
                .ipv4
                .iter()
                .chain(&i.ipv6)
                .chain(&i.local6)
                .chain(&i.prefixes)
            {
                let ip = a.split('/').next().unwrap_or(a);
                let public = match ip.parse::<std::net::IpAddr>() {
                    Ok(std::net::IpAddr::V4(v)) => !private4(v),
                    Ok(std::net::IpAddr::V6(v)) => !private6(v),
                    Err(_) => false,
                };
                if uplink || public {
                    wan.push(a.clone());
                }
            }
        }
        let mut leases = leases.to_vec();
        // Static hosts: a name the config gives a MAC.
        for s in uci.config("dhcp").iter().filter(|s| s.kind == "host") {
            if let Some(n) = s.one("name") {
                leases.push((n.to_string(), s.one("mac").and_then(crate::config::mac)));
            }
        }
        let mut tags: Vec<String> = uci
            .configs
            .values()
            .flatten()
            .flat_map(|s| s.opts.values().flatten())
            .filter(|v| is_tag(v))
            .cloned()
            .collect();
        tags.sort();
        tags.dedup();
        Self {
            wan,
            gateways,
            ssids: uci.wifi().into_iter().map(|w| w.ssid).collect(),
            leases,
            tags,
        }
    }
}

impl Scrub {
    pub fn new(cfg: &crate::config::Network, salt: Salt, facts: &Facts) -> Self {
        let mut wan4 = Vec::new();
        let mut net4 = Vec::new();
        let mut gw4 = Vec::new();
        let mut wan6 = Vec::new();
        let mut gw6 = Vec::new();
        if !cfg.claude.share_wan_address {
            for a in &facts.wan {
                let (ip, len) = match a.split_once('/') {
                    Some((ip, l)) => (ip, l.parse::<u8>().ok()),
                    None => (a.as_str(), None),
                };
                match ip.parse::<std::net::IpAddr>() {
                    Ok(std::net::IpAddr::V4(v)) => {
                        wan4.push(v);
                        if let Some(l) = len.filter(|l| (8..=30).contains(l)) {
                            net4.push((v, l));
                        }
                    }
                    Ok(std::net::IpAddr::V6(v)) => match len {
                        // A delegated prefix (no host bits) covers everything under it;
                        // so does the network an address is on (its neighbours there are
                        // the provider's).
                        Some(l) if (16..128).contains(&l) => wan6.push((v, l)),
                        _ => wan6.push((v, 128)),
                    },
                    Err(_) => {}
                }
            }
            for g in &facts.gateways {
                match g.parse::<std::net::IpAddr>() {
                    Ok(std::net::IpAddr::V4(v)) => gw4.push(v),
                    Ok(std::net::IpAddr::V6(v)) => gw6.push(v),
                    Err(_) => {}
                }
            }
        }
        let named: Vec<(String, String)> = cfg
            .devices
            .iter()
            .filter_map(|d| Some((crate::config::mac(d.mac.as_deref()?)?, d.name.clone()?)))
            .collect();
        let mut ssids: Vec<String> = Vec::new();
        for s in facts.ssids.iter().filter(|s| !s.is_empty()) {
            if !ssids.contains(s) {
                ssids.push(s.clone());
            }
        }
        let mut hosts: Vec<(String, String)> = Vec::new();
        for (host, mac) in &facts.leases {
            if host.is_empty() || host == "*" || host == "-" || hosts.iter().any(|(h, _)| h == host)
            {
                continue;
            }
            let by_mac = mac
                .as_ref()
                .and_then(|m| named.iter().find(|(nm, _)| nm == m))
                .map(|(_, n)| n.clone());
            let by_host = cfg
                .devices
                .iter()
                .find(|d| d.hostname.as_deref() == Some(host.as_str()))
                .and_then(|d| d.name.clone());
            let shown = match by_mac.or(by_host) {
                Some(n) => n,
                None => {
                    let t = salt.tag(host);
                    format!("‹host-{}›", &t[t.len() - 4..])
                }
            };
            hosts.push((host.clone(), shown));
        }
        // The longest first: one name inside another is replaced whole.
        hosts.sort_by_key(|(h, _)| std::cmp::Reverse(h.len()));
        Self {
            salt,
            wan4,
            net4,
            gw4,
            wan6,
            gw6,
            named,
            ssids,
            hosts,
            tags: facts.tags.clone(),
        }
    }

    /// What the router says now, read over ssh (three reads on the shared connection).
    /// Err: it couldn't be read, so nothing can be shown.
    pub fn read(r: &crate::remote::Router) -> Result<Self, String> {
        let why = |what: &str, e: &dyn std::fmt::Display| {
            format!("couldn't read {what} to know what must be hidden: {e}")
        };
        let salt = Salt::load(&r.scope).map_err(|e| why("the salt", &e))?;
        let ifaces = crate::collect::ifaces::collect(r).map_err(|e| why("the interfaces", &e))?;
        let uci = crate::collect::uci::collect(r).map_err(|e| why("the config", &e))?;
        let raw = crate::collect::clients::collect(r).map_err(|e| why("the leases", &e))?;
        Ok(Self::new(
            &r.cfg,
            salt,
            &Facts::of(&ifaces, &uci, &leases_of(&raw)),
        ))
    }

    pub fn text(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut in_key = false;
        for line in text.split_inclusive('\n') {
            let (body, nl) = match line.strip_suffix('\n') {
                Some(b) => (b, "\n"),
                None => (line, ""),
            };
            // A private key block: nothing of it.
            if body.contains("-----BEGIN") && body.contains("PRIVATE KEY") {
                in_key = true;
                out.push_str("(a private key: hidden)");
                out.push_str(nl);
                continue;
            }
            if in_key {
                in_key = !body.contains("-----END");
                continue;
            }
            if body.chars().filter(|c| *c == '\u{fffd}').count() > 3 {
                out.push_str("(binary: hidden)");
                out.push_str(nl);
                continue;
            }
            out.push_str(&self.line(body));
            out.push_str(nl);
        }
        out
    }

    fn line(&self, line: &str) -> String {
        let mut l = self.after_password(&self.known(&self.secrets(line)));
        for (host, shown) in &self.hosts {
            l = replace_word(&l, host, shown);
        }
        l = self.dhcp_log(&l);
        // An SSID may hold spaces: wherever it stands.
        let mut by_len: Vec<(usize, &String)> = self.ssids.iter().enumerate().collect();
        by_len.sort_by_key(|(_, s)| std::cmp::Reverse(s.len()));
        for (i, ssid) in by_len {
            l = l.replace(ssid.as_str(), &format!("‹ssid-{}›", i + 1));
        }
        self.nets(&l)
    }

    /// A command line carries a password as the word after its option (`pppd … password
    /// <it>`, as `ps` shows netifd starting it): that word, whatever it is.
    fn after_password(&self, line: &str) -> String {
        const BEFORE: &[&str] = &["password", "--password", "-password", "passwd", "--psk"];
        if !BEFORE.iter().any(|b| line.contains(b)) {
            return line.to_string();
        }
        let mut out: Vec<String> = Vec::new();
        let mut hide = false;
        for w in line.split(' ') {
            if hide && !w.is_empty() {
                hide = false;
                out.push(if is_tag(w) || w.starts_with('-') {
                    w.to_string()
                } else {
                    "‹hidden›".to_string()
                });
                continue;
            }
            hide = BEFORE.contains(&w);
            out.push(w.to_string());
        }
        out.join(" ")
    }

    fn host_tag(&self, host: &str) -> String {
        let t = self.salt.tag(host);
        format!("‹host-{}›", &t[t.len() - 4..])
    }

    /// dnsmasq's log names who asked (`DHCPACK(br-lan) <address> <mac> <hostname>`): a
    /// name no lease holds any more is still a device's name.
    fn dhcp_log(&self, line: &str) -> String {
        if !line.contains("dnsmasq-dhcp") || !line.contains("DHCP") {
            return line.to_string();
        }
        let words: Vec<&str> = line.split(' ').collect();
        let Some(i) = words.iter().rposition(|w| crate::config::mac(w).is_some()) else {
            return line.to_string();
        };
        let mut out: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        for w in out.iter_mut().skip(i + 1) {
            if !w.is_empty()
                && !w.starts_with('‹')
                && !self.hosts.iter().any(|(_, shown)| shown == w)
            {
                *w = self.host_tag(w);
            }
        }
        out.join(" ")
    }

    /// A value that is one of the config's secrets, wherever it stands and whatever
    /// printed it: each quoted string, each word and what follows a `=` or a `: ` is
    /// hashed and looked up among the tags the config was read with.
    fn known(&self, line: &str) -> String {
        if self.tags.is_empty() {
            return line.to_string();
        }
        let mut cands: Vec<&str> = vec![line.trim()];
        for q in ['\'', '"'] {
            cands.extend(line.split(q).skip(1).step_by(2));
        }
        for sep in ["=", ": ", ":"] {
            if let Some((_, v)) = line.split_once(sep) {
                let v = v.trim().trim_end_matches(',');
                cands.push(v);
                cands.push(v.trim_matches(|c| c == '\'' || c == '"'));
            }
        }
        cands.extend(line.split(|c: char| c.is_whitespace() || "'\"=,;()[]{}".contains(c)));
        // A value of several words with nothing around it (a command line's argument).
        let words: Vec<(usize, &str)> = line
            .split(' ')
            .scan(0usize, |at, w| {
                let here = *at;
                *at += w.len() + 1;
                Some((here, w))
            })
            .filter(|(_, w)| !w.is_empty())
            .collect();
        for n in 2..=6usize {
            for run in words.windows(n) {
                let (from, last) = (run[0].0, run[n - 1]);
                cands.push(&line[from..last.0 + last.1.len()]);
            }
        }
        let mut out = line.to_string();
        for c in cands {
            if c.len() < 3 || is_tag(c) || !out.contains(c) {
                continue;
            }
            let tag = self.salt.tag(c);
            if self.tags.contains(&tag) {
                out = out.replace(c, &tag);
            }
        }
        out
    }

    /// JSON, however it is laid out: the value of every `"name": "value"` whose name is a
    /// secret's.
    fn json_secrets(&self, line: &str) -> String {
        let b = line.as_bytes();
        // The end of the string that starts at `from` (after its opening quote).
        let close = |from: usize| {
            let mut i = from;
            while i < b.len() {
                match b[i] {
                    b'\\' => i += 2,
                    b'"' => return Some(i),
                    _ => i += 1,
                }
            }
            None
        };
        let mut out = String::with_capacity(line.len());
        let mut at = 0;
        let mut i = 0;
        while i < b.len() {
            if b[i] != b'"' {
                i += 1;
                continue;
            }
            let Some(end) = close(i + 1) else { break };
            let name = &line[i + 1..end];
            let mut j = end + 1;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < b.len() && b[j] == b':' {
                j += 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < b.len()
                    && b[j] == b'"'
                    && let Some(vend) = close(j + 1)
                {
                    if secret(name) || wifi_secret(name) {
                        let v = &line[j + 1..vend];
                        out.push_str(&line[at..j + 1]);
                        out.push_str(&if is_tag(v) {
                            v.to_string()
                        } else {
                            self.salt.tag(v)
                        });
                        at = vend;
                    }
                    i = vend + 1;
                    continue;
                }
            }
            i = end + 1;
        }
        out.push_str(&line[at..]);
        out
    }

    /// A secret's value, however the line carries it.
    fn secrets(&self, line: &str) -> String {
        let t = line.trim_start();
        let indent = &line[..line.len() - t.len()];
        let tag = |v: &str| {
            let v = v.trim().trim_matches(|c| c == '\'' || c == '"');
            if is_tag(v) {
                v.to_string()
            } else {
                self.salt.tag(v)
            }
        };
        // `uci export` and the config files: `option key 'value'`.
        for kw in ["option ", "list "] {
            if let Some(rest) = t.strip_prefix(kw)
                && let Some((name, value)) = rest.trim_start().split_once(char::is_whitespace)
                && secret(name.trim_matches('\''))
            {
                return format!("{indent}{kw}{name} '{}'", tag(value));
            }
        }
        // A password hash (`root:$1$…:`), as /etc/shadow has them.
        if let Some((user, rest)) = t.split_once(':')
            && rest.starts_with('$')
            && rest.matches('$').count() >= 3
            && !user.contains(char::is_whitespace)
        {
            return format!("{indent}{user}:(the hash of a password: hidden)");
        }
        // `uci show`: `pkg.section.option='value'`; a daemon's file: `name=value`.
        if let Some((name, value)) = t.split_once('=')
            && !name.contains(char::is_whitespace)
            && !name.is_empty()
            && (secret(name) || wifi_secret(name))
        {
            return format!("{indent}{name}='{}'", tag(value));
        }
        self.json_secrets(line)
    }

    /// A MAC as it is shown: a named device by its name, any other by its vendor half.
    /// `sep`: what stood between its bytes (none: it was written without).
    fn mac_shown(&self, mac: &str, sep: Option<char>) -> String {
        match self.named.iter().find(|(nm, _)| nm == mac) {
            Some((_, name)) => format!("‹{name}›"),
            None => match sep {
                Some(c) => format!("{}{c}xx{c}xx{c}xx", mac[..8].replace(':', &c.to_string())),
                None => format!("{}xxxxxx", mac[..8].replace(':', "")),
            },
        }
    }

    fn four(&self, a: std::net::Ipv4Addr) -> Option<&'static str> {
        if self.wan4.contains(&a) {
            return Some("‹wan›");
        }
        if self.gw4.contains(&a) {
            return Some("‹wan-gw›");
        }
        let bits = u32::from(a);
        self.net4
            .iter()
            .any(|(n, len)| (u32::from(*n) ^ bits) >> (32 - u32::from(*len)) == 0)
            .then_some("‹wan-net›")
    }

    /// An IPv6 address as it is shown, if anything of it is hidden.
    fn six(&self, a: std::net::Ipv6Addr) -> Option<String> {
        if let Some(v4) = a.to_ipv4_mapped() {
            return self.four(v4).map(|s| format!("::ffff:{s}"));
        }
        if self
            .wan6
            .iter()
            .any(|(net, len)| same_prefix(*net, a, *len))
        {
            return Some("‹wan6›".into());
        }
        if self.gw6.contains(&a) && !private6(a) {
            return Some("‹wan6-gw›".into());
        }
        // An interface id made from a MAC (EUI-64: `ff:fe` in its middle) is that MAC.
        let s = a.segments();
        if s[5] & 0x00ff == 0x00ff && s[6] >> 8 == 0xfe {
            let mac = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                (s[4] >> 8) ^ 0x02,
                s[4] & 0xff,
                s[5] >> 8,
                s[6] & 0xff,
                s[7] >> 8,
                s[7] & 0xff
            );
            let prefix = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
            return Some(format!(
                "{prefix}‹eui64 {}›",
                self.mac_shown(&mac, Some(':')).trim_matches(['‹', '›'])
            ));
        }
        None
    }

    /// Addresses and MACs, wherever they stand and however they are written: each
    /// candidate is parsed and its value compared, never its text (upper case, leading
    /// zeros, `::ffff:` in front, a port or a zone behind, a MAC with dashes, dots or
    /// nothing between its bytes, an address as /proc/net/route's hex).
    fn nets(&self, line: &str) -> String {
        let b = line.as_bytes();
        let mut out = String::with_capacity(line.len());
        let mut i = 0;
        while i < b.len() {
            let prev = if i > 0 { b[i - 1] } else { b' ' };
            let starts = b[i].is_ascii_hexdigit() || b[i] == b':';
            if starts
                && !prev.is_ascii_alphanumeric()
                && prev != b'.'
                && let Some((len, shown)) = self.net_at(line, i)
            {
                out.push_str(&shown);
                i += len;
                continue;
            }
            let ch = line[i..].chars().next().expect("in bounds");
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }

    /// What stands at `i`, if it is an address or a MAC: how much of the line it takes and
    /// what is shown for it (itself, when it is nothing that is hidden).
    fn net_at(&self, line: &str, i: usize) -> Option<(usize, String)> {
        let rest = &line[i..];
        let b = rest.as_bytes();
        let hex = |k: usize| b.get(k).is_some_and(|c| c.is_ascii_hexdigit());
        let prev = |back: usize| {
            i.checked_sub(back)
                .map(|k| line.as_bytes()[k])
                .unwrap_or(b' ')
        };
        // Pairs: `hh:hh:hh:hh:hh:hh` (or with dashes) is a MAC, more of them an id made
        // from one (a DHCP client id, a DUID).
        if hex(0) && hex(1) && !hex(2) {
            let sep = b.get(2).copied().filter(|c| matches!(c, b':' | b'-'));
            let mut n = 1;
            if let Some(sep) = sep {
                while b.get(3 * n - 1) == Some(&sep)
                    && hex(3 * n)
                    && hex(3 * n + 1)
                    && !hex(3 * n + 2)
                {
                    n += 1;
                }
            }
            // Not the tail of a longer run that was looked at already.
            let inside = matches!(prev(1), b':' | b'-')
                && prev(2).is_ascii_hexdigit()
                && prev(3).is_ascii_hexdigit()
                && !prev(4).is_ascii_alphanumeric();
            let len = 3 * n - 1;
            if n == 6 && !inside {
                let sep = sep.expect("six pairs have one") as char;
                let mac = rest[..len].to_ascii_lowercase().replace('-', ":");
                return Some((len, self.mac_shown(&mac, Some(sep))));
            }
            if n >= 7 && !inside && sep == Some(b':') {
                return Some((len, "‹id›".into()));
            }
        }
        // `hhhh.hhhh.hhhh`.
        if (0..14).all(|k| {
            if k % 5 == 4 {
                b.get(k) == Some(&b'.')
            } else {
                hex(k)
            }
        }) && !b
            .get(14)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'.')
            && prev(1) != b':'
        {
            let h: String = rest[..14].replace('.', "").to_ascii_lowercase();
            let mac = (0..6)
                .map(|k| &h[2 * k..2 * k + 2])
                .collect::<Vec<_>>()
                .join(":");
            return Some((
                14,
                match self.named.iter().find(|(nm, _)| *nm == mac) {
                    Some((_, name)) => format!("‹{name}›"),
                    None => format!("{}.{}xx.xxxx", &h[..4], &h[4..6]),
                },
            ));
        }
        // A run of hex with nothing joined to it.
        let run = b.iter().take_while(|c| c.is_ascii_hexdigit()).count();
        let after = b.get(run).copied().unwrap_or(b' ');
        if run > 0
            && !after.is_ascii_alphanumeric()
            && !matches!(after, b':' | b'.')
            && prev(1) != b':'
        {
            let h = &rest[..run];
            // A DUID (which is made from a MAC) or a file's plain hash.
            if run >= 20 {
                return Some((run, "‹hex›".into()));
            }
            // A MAC written without separators (a number of twelve digits is a number).
            if run == 12 && h.bytes().any(|c| c.is_ascii_alphabetic()) {
                let l = h.to_ascii_lowercase();
                let mac = (0..6)
                    .map(|k| &l[2 * k..2 * k + 2])
                    .collect::<Vec<_>>()
                    .join(":");
                return Some((run, self.mac_shown(&mac, None)));
            }
            // An address as /proc/net/route writes it: eight hex digits, in the
            // machine's byte order.
            if run == 8
                && let Ok(v) = u32::from_str_radix(h, 16)
            {
                for a in [v, v.swap_bytes()] {
                    if let Some(shown) = self.four(std::net::Ipv4Addr::from(a)) {
                        return Some((run, shown.into()));
                    }
                }
            }
        }
        if prev(1) == b':' {
            return None;
        }
        // IPv4: four numbers, and not a part of five.
        let v4 = b
            .iter()
            .take_while(|c| c.is_ascii_digit() || **c == b'.')
            .count();
        let t = rest[..v4].trim_end_matches('.');
        if t.matches('.').count() == 3
            && let Ok(a) = t.parse::<std::net::Ipv4Addr>()
        {
            return Some((t.len(), self.four(a).unwrap_or(t).to_string()));
        }
        // IPv6: the longest beginning of the run that is an address and is hidden (a port
        // or a label's `:` may follow one); else the run as it is.
        let v6 = b
            .iter()
            .take_while(|c| c.is_ascii_hexdigit() || matches!(**c, b':' | b'.'))
            .count();
        if rest[..v6].matches(':').count() >= 2 {
            let mut whole = None;
            for end in (2..=v6).rev() {
                let Ok(a) = rest[..end].parse::<std::net::Ipv6Addr>() else {
                    continue;
                };
                if let Some(shown) = self.six(a) {
                    return Some((end, shown));
                }
                whole.get_or_insert(end);
            }
            if let Some(end) = whole {
                return Some((end, rest[..end].to_string()));
            }
        }
        None
    }
}

/// The hostname and MAC of every lease a read found.
pub fn leases_of(raw: &crate::collect::clients::Raw) -> Vec<(String, Option<String>)> {
    raw.leases
        .iter()
        .filter_map(|l| Some((l.hostname.clone()?, Some(l.mac.clone()))))
        .chain(
            raw.leases6
                .iter()
                .filter_map(|l| Some((l.hostname.clone()?, l.mac.clone()))),
        )
        .collect()
}

/// A daemon's own name for a passphrase (hostapd's files, `wpa_passphrase=…`).
fn wifi_secret(name: &str) -> bool {
    let n = name.rsplit('.').next().unwrap_or(name).to_ascii_lowercase();
    matches!(
        n.as_str(),
        "wpa_passphrase" | "passphrase" | "wpa_psk" | "sae_password" | "wep_key0" | "auth_secret"
    )
}

fn same_prefix(net: std::net::Ipv6Addr, a: std::net::Ipv6Addr, len: u8) -> bool {
    if len == 0 {
        return false;
    }
    let shift = 128 - u32::from(len.min(128));
    (u128::from(net) >> shift) == (u128::from(a) >> shift)
}

/// `word` replaced where it stands alone (not inside a longer name).
fn replace_word(text: &str, word: &str, with: &str) -> String {
    if word.is_empty() || !text.contains(word) {
        return text.to_string();
    }
    let inner = |c: char| c.is_alphanumeric() || c == '-' || c == '_';
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(word) {
        let before = rest[..i].chars().next_back();
        let after = rest[i + word.len()..].chars().next();
        out.push_str(&rest[..i]);
        if before.is_some_and(inner) || after.is_some_and(inner) {
            out.push_str(word);
        } else {
            out.push_str(with);
        }
        rest = &rest[i + word.len()..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siphash_is_the_reference_one() {
        // The paper's test vector: key 00..0f, message 00..0e.
        let key: Vec<u8> = (0..16).collect();
        let msg: Vec<u8> = (0..15).collect();
        let k0 = u64::from_le_bytes(key[..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..].try_into().unwrap());
        assert_eq!(siphash24(k0, k1, &msg), 0xa129_ca61_49be_45e5);
    }

    #[test]
    fn only_the_last_name_segment_makes_a_secret() {
        for yes in [
            "wireless.default_radio0.key",
            "wireless.x.sae_password",
            "network.wan.password",
            "network.wg0.private_key",
            "network.wg0.preshared_key",
            "x.y.PSK",
            "ddns.home.Token",
            "a.b.wps_pin",
            "key",
            "wireless.w.key1",
            "wireless.w.key4",
            "wireless.w.pincode",
            "wireless.w.priv_key_pwd",
            "wireless.w.r0kh",
            "wireless.w.r1kh",
            "wireless.w.passphrase",
        ] {
            assert!(secret(yes), "{yes}");
        }
        for no in [
            "dropbear.main.PasswordAuth",
            "dropbear.main.RootPasswordAuth",
            "uhttpd.defaults.key_type",
            "wireless.radio0.keys_dir",
            "firewall.token.name",
            "dhcp.lan.pinned",
            "network.wan.username",
            "wireless.radio0.keys",
            "wireless.w.key_mgmt",
        ] {
            assert!(!secret(no), "{no}");
        }
    }

    #[test]
    fn a_tag_says_changed_and_nothing_else() {
        let a = Salt::fixed([7; 16]);
        let b = Salt::fixed([8; 16]);
        let t = a.tag("correct horse battery");
        assert!(is_tag(&t), "{t}");
        assert_eq!(t, a.tag("correct horse battery"));
        assert_ne!(t, a.tag("correct horse battery!"));
        assert_ne!(
            t,
            b.tag("correct horse battery"),
            "another salt, another tag"
        );
        assert!(!t.contains("horse"));
        assert!(!is_tag("redacted:xyz") && !is_tag("/etc/uhttpd.key"));
        assert_eq!(format!("{a:?}"), "Salt(..)");
    }

    #[test]
    fn the_salt_is_made_once_and_kept_private() {
        let scope = "net:salt-test";
        let _ = std::fs::remove_file(path(scope));
        let first = Salt::load(scope).unwrap();
        assert!(path(scope).ends_with("networks/salt-test/salt"));
        assert!(
            Salt::load(scope).unwrap() == first,
            "read back, not made again"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path(scope)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_file(path(scope));
    }

    fn scrub(share: bool) -> Scrub {
        let (file, _) = crate::config::parse(&format!(
            "networks:\n  home:\n    devices:\n      - {{ name: nas, mac: \"02:00:5E:00:53:01\" }}\n      - {{ name: phone, hostname: my-phone, private_mac: true }}\n    claude: {{ share_wan_address: {share} }}\n"
        ))
        .unwrap();
        let cfg = file.networks["home"].clone();
        let facts = Facts {
            wan: vec![
                "203.0.113.7/24".into(),
                "2001:db8:aa::2/64".into(),
                "2001:db8:bb00::/56".into(),
            ],
            gateways: vec![
                "203.0.113.254".into(),
                "198.51.100.1".into(),
                "fe80::1".into(),
            ],
            ssids: vec![
                "Example Net".into(),
                "Example Net 5G".into(),
                "Example Net".into(),
                "Caf\u{e9} (5G) [x].*+?".into(),
            ],
            leases: vec![
                ("storage-box".into(), Some("02:00:5e:00:53:01".into())),
                ("kitchen-tablet".into(), Some("00:00:5e:00:53:77".into())),
                ("my-phone".into(), Some("d6:00:5e:00:53:99".into())),
                ("*".into(), None),
            ],
            tags: vec![Salt::fixed([7; 16]).tag("correct horse battery")],
        };
        Scrub::new(&cfg, Salt::fixed([7; 16]), &facts)
    }

    #[test]
    fn what_claude_sees_is_scrubbed() {
        let s = scrub(false);
        // (what the router printed, what is shown)
        let table: &[(&str, &str)] = &[
            // Secrets, in each form a config is printed in.
            (
                "wireless.default_radio0.key='correct horse battery'",
                "wireless.default_radio0.key='redacted:",
            ),
            (
                "\toption key 'correct horse battery'",
                "\toption key 'redacted:",
            ),
            (
                "\toption sae_password 'it is secret'",
                "\toption sae_password 'redacted:",
            ),
            (
                "wpa_passphrase=correct horse battery",
                "wpa_passphrase='redacted:",
            ),
            (
                "\t\"key\": \"correct horse battery\",",
                "\t\"key\": \"redacted:",
            ),
            (
                "network.wg0.private_key='abc='",
                "network.wg0.private_key='redacted:",
            ),
            (
                "root:$1$abcdefgh$0123456789abcdef:19000:0:99999:7:::",
                "root:(the hash of a password: hidden)",
            ),
            // What the audit reads stays readable.
            (
                "dropbear.main.PasswordAuth='off'",
                "dropbear.main.PasswordAuth='off'",
            ),
            (
                "uhttpd.defaults.key_type='ec'",
                "uhttpd.defaults.key_type='ec'",
            ),
            // The uplink.
            (
                "inet 203.0.113.7/24 brd 203.0.113.255",
                "inet ‹wan›/24 brd ‹wan-net›",
            ),
            ("\"address\": \"203.0.113.7\",", "\"address\": \"‹wan›\","),
            (
                "inet6 2001:db8:aa::2/64 scope global",
                "inet6 ‹wan6›/64 scope global",
            ),
            (
                "2001:db8:bb00:12::1 dev br-lan lladdr 00:00:5e:00:53:77",
                "‹wan6› dev br-lan lladdr 00:00:5e:xx:xx:xx",
            ),
            ("[2001:db8:bb00:ab::5]:443", "[‹wan6›]:443"),
            // A prefix ends in `::`, with its length or without.
            (
                "2001:db8:bb00:ab::/64 dev br-lan metric 1024",
                "‹wan6›/64 dev br-lan metric 1024",
            ),
            (
                "\"address\": \"2001:db8:bb00:ab::\",",
                "\"address\": \"‹wan6›\",",
            ),
            (
                "default from 2001:db8:bb00::/56 via fe80::1 dev wan",
                "default from ‹wan6›/56 via fe80::1 dev wan",
            ),
            ("addr: 203.0.113.7.", "addr: ‹wan›."),
            ("2001:db8:aa::2: reachable", "‹wan6›: reachable"),
            // However it is written: the value is compared, not the text.
            (
                "tcp 0 0 203.0.113.7:22 0.0.0.0:* LISTEN",
                "tcp 0 0 ‹wan›:22 0.0.0.0:* LISTEN",
            ),
            (
                "tcp 0 0 ::ffff:203.0.113.7:443 :::*",
                "tcp 0 0 ::ffff:‹wan›:443 :::*",
            ),
            (
                "src=::ffff:203.0.113.7 dst=192.0.2.5",
                "src=::ffff:‹wan› dst=192.0.2.5",
            ),
            ("2001:DB8:AA::2 upper", "‹wan6› upper"),
            (
                "2001:0db8:00aa:0000:0000:0000:0000:0002 expanded",
                "‹wan6› expanded",
            ),
            ("2001:db8:aa::2%wan zoned", "‹wan6›%wan zoned"),
            (
                // (Where a port can't be told from the address's last group, both go.)
                "tcp 0 0 2001:db8:aa::2:443 :::*",
                "tcp 0 0 ‹wan6› :::*",
            ),
            ("[2001:db8:bb00:ab::5%br-lan]:53", "[‹wan6›%br-lan]:53"),
            // The provider's side: the gateway, and whatever else is on the uplink's network.
            (
                "default via 203.0.113.254 dev wan",
                "default via ‹wan-gw› dev wan",
            ),
            (
                "203.0.113.0/24 dev wan scope link",
                "‹wan-net›/24 dev wan scope link",
            ),
            ("peer 198.51.100.1 (pppoe)", "peer ‹wan-gw› (pppoe)"),
            ("2001:db8:aa::1 dev wan router", "‹wan6› dev wan router"),
            // /proc/net/route: the same addresses as hex, in either byte order.
            (
                "wan\t00000000\tFE7100CB\t0003\t0\t0\t0",
                "wan\t00000000\t‹wan-gw›\t0003\t0\t0\t0",
            ),
            (
                "wan\t007100CB\t00000000\t0001",
                "wan\t‹wan-net›\t00000000\t0001",
            ),
            ("gw CB0071FE be", "gw ‹wan-gw› be"),
            ("br-lan\t000200C0\t00000000", "br-lan\t000200C0\t00000000"),
            // An address made from a MAC is that MAC.
            (
                "fe80::200:5eff:fe00:5377 dev br-lan lladdr 00:00:5e:00:53:77",
                "fe80::‹eui64 00:00:5e:xx:xx:xx› dev br-lan lladdr 00:00:5e:xx:xx:xx",
            ),
            (
                "fd00:db8:1:0:0:5eff:fe00:5301/64 scope global",
                "fd00:db8:1::‹eui64 nas›/64 scope global",
            ),
            ("fe80::1 dev wan", "fe80::1 dev wan"),
            // Not the uplink's: as it is.
            (
                "192.0.2.10 fd00:db8:1::1 fe80::1 2001:db8:cc::1",
                "192.0.2.10 fd00:db8:1::1 fe80::1 2001:db8:cc::1",
            ),
            // MACs: a named device by its name, any other by its vendor.
            ("02:00:5e:00:53:01", "‹nas›"),
            ("02-00-5E-00-53-01", "‹nas›"),
            ("00-00-5E-00-53-77", "00-00-5e-xx-xx-xx"),
            ("02005e005301", "‹nas›"),
            ("id 00005E005377 seen", "id 00005exxxxxx seen"),
            ("0200.5e00.5301 on Gi0/1", "‹nas› on Gi0/1"),
            ("0000.5e00.5377", "0000.5exx.xxxx"),
            (
                "sta:00:00:5e:00:53:77 authenticated",
                "sta:00:00:5e:xx:xx:xx authenticated",
            ),
            ("rx_bytes 123456789012 tx", "rx_bytes 123456789012 tx"),
            (
                "10:00:00 2026-11-21 1.2.3 6.12.94",
                "10:00:00 2026-11-21 1.2.3 6.12.94",
            ),
            (
                "net:client:00:00:5e:00:53:77 is new",
                "net:client:00:00:5e:xx:xx:xx is new",
            ),
            ("id: net:client:02:00:5e:00:53:01", "id: net:client:‹nas›"),
            (
                "00:00:5e:00:53:77: seen twice",
                "00:00:5e:xx:xx:xx: seen twice",
            ),
            (
                "lladdr 00:00:5e:00:53:77 REACHABLE",
                "lladdr 00:00:5e:xx:xx:xx REACHABLE",
            ),
            ("\"d6:00:5e:00:53:99\": {", "\"d6:00:5e:xx:xx:xx\": {"),
            (
                "192.0.2.10 storage-box 01:02:00:5e:00:53:01",
                "192.0.2.10 nas ‹id›",
            ),
            (
                "# br-lan 00030001d6005e005399 1 my-phone 1790000000",
                "# br-lan ‹hex› 1 phone 1790000000",
            ),
            (
                "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8  /etc/x",
                "‹hex›  /etc/x",
            ),
            // SSIDs, by number.
            (
                "wireless.default_radio1.ssid='Example Net 5G'",
                "wireless.default_radio1.ssid='‹ssid-2›'",
            ),
            ("ESSID: \"Example Net\"", "ESSID: \"‹ssid-1›\""),
            ("ssid Caf\u{e9} (5G) [x].*+? on", "ssid ‹ssid-3› on"),
            // Hostnames: the config's name, or a tag.
            (
                "1790000000 02:00:5e:00:53:01 192.0.2.10 storage-box *",
                "1790000000 ‹nas› 192.0.2.10 nas *",
            ),
            ("192.0.2.130 my-phone", "192.0.2.130 phone"),
            ("my-phone-2 stays", "my-phone-2 stays"),
            // JSON on one line, as `ubus -S` and a script would print it.
            (
                "{\"ssid\":\"x\",\"key\":\"p\\\"q r\",\"sae_password\": \"zz\",\"mode\":\"ap\"}",
                "{\"ssid\":\"x\",\"key\":\"redacted:",
            ),
            // The config's own secret, with nothing around it that says so.
            ("correct horse battery", "redacted:"),
            ("'correct horse battery'", "'redacted:"),
            (
                "psk is \"correct horse battery\" here",
                "psk is \"redacted:",
            ),
            ("x=correct horse battery", "x=redacted:"),
            // A password as a command's argument, as `ps` shows it.
            (
                " 1234 root  1234 S  /usr/sbin/pppd nodetach user me@isp password hunter2 ifname pppoe-wan",
                " 1234 root  1234 S  /usr/sbin/pppd nodetach user me@isp password ‹hidden› ifname pppoe-wan",
            ),
            (
                "/usr/sbin/pppd user x password correct horse battery mtu 1492",
                "/usr/sbin/pppd user x password redacted:",
            ),
            // More of the names a secret goes by.
            ("wireless.w.key1='0123456789'", "wireless.w.key1='redacted:"),
            (
                "wireless.w.r0kh='02:00:5e:00:53:01,nas,000102'",
                "wireless.w.r0kh='redacted:",
            ),
            ("x.y.wps_pincode='12345670'", "x.y.wps_pincode='redacted:"),
            (
                "wireless.w.priv_key_pwd='pw'",
                "wireless.w.priv_key_pwd='redacted:",
            ),
            // A device's name in the log, whether or not it still holds a lease.
            (
                "Sat Nov 21 10:00:00 2026 daemon.info dnsmasq-dhcp[1]: DHCPACK(br-lan) 192.0.2.77 00:00:5e:00:53:42 old-laptop",
                "Sat Nov 21 10:00:00 2026 daemon.info dnsmasq-dhcp[1]: DHCPACK(br-lan) 192.0.2.77 00:00:5e:xx:xx:xx ‹host-",
            ),
        ];
        for (raw, shown) in table {
            let got = s.text(raw);
            assert!(got.starts_with(shown), "{raw}\n  → {got}\n  wanted {shown}");
        }
        let one_line = s.text("{\"key\":\"p q\",\"sae_password\": \"zz\",\"mode\":\"ap\"}");
        assert!(
            !one_line.contains("p q")
                && !one_line.contains("zz")
                && one_line.contains("\"mode\":\"ap\""),
            "{one_line}"
        );
        for raw in [
            "correct horse battery",
            "a 'correct horse battery' b",
            "k: correct horse battery",
        ] {
            assert!(!s.text(raw).contains("horse"), "{raw}");
        }
        assert!(
            !s.text("dnsmasq-dhcp[1]: DHCPREQUEST(br-lan) 192.0.2.77 00:00:5e:00:53:42 old-laptop")
                .contains("old-laptop")
        );
        let tablet = s.text("192.0.2.120 kitchen-tablet");
        assert!(
            tablet.starts_with("192.0.2.120 ‹host-") && !tablet.contains("kitchen"),
            "{tablet}"
        );
        assert_eq!(
            tablet,
            s.text("192.0.2.120 kitchen-tablet"),
            "the same every time"
        );
        // A private key is dropped whole; lines keep their ends.
        let key = "a\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\nb\n";
        assert_eq!(s.text(key), "a\n(a private key: hidden)\nb\n");
        // A tag is never tagged again.
        let once = s.text("wireless.x.key='secret'");
        assert_eq!(s.text(&once), once);
        // Asked to share the uplink's address: only that is left in.
        let shared = scrub(true).text("inet 203.0.113.7/24 lladdr 00:00:5e:00:53:77");
        assert_eq!(shared, "inet 203.0.113.7/24 lladdr 00:00:5e:xx:xx:xx");
        assert_eq!(
            scrub(true).text("default via 203.0.113.254 dev wan"),
            "default via 203.0.113.254 dev wan"
        );
    }

    #[test]
    fn the_uplinks_addresses_come_from_what_the_router_says() {
        let ifaces =
            crate::collect::ifaces::parse(&crate::collect::fixture("network/ifaces.txt")).unwrap();
        let uci = crate::collect::uci::parse(
            &crate::collect::fixture("network/uci.txt"),
            &Salt::fixed([1; 16]),
        );
        let f = Facts::of(&ifaces, &uci, &[]);
        let wan = ifaces.wan().expect("an uplink");
        for a in wan.ipv4.iter().chain(&wan.ipv6).chain(&wan.prefixes) {
            assert!(
                f.wan.contains(a),
                "{a} of the uplink isn't hidden: {:?}",
                f.wan
            );
        }
        // The LAN's own private addresses aren't the uplink's.
        assert!(
            !f.wan.iter().any(|a| a.starts_with("192.0.2.1/")),
            "{:?}",
            f.wan
        );
        assert!(f.ssids.contains(&"Example Net".to_string()));
    }
}

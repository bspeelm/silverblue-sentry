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
    "password",
    "psk",
    "secret",
    "token",
    "private",
    "pin",
    "sae_password",
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
}

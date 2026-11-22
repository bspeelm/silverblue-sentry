//! The web interface's certificate: until when it's good. The router keeps it as DER and has
//! no openssl, so the file comes over as hex (`hexdump`) and its validity is read here: a
//! short walk down the ASN.1 to the two dates, nothing else of it is looked at. Read once a
//! day at most.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::{CollectError, output_needing};
use sentry_app::remote::Remote;

/// The path is uhttpd's own (`uci get uhttpd.main.cert`); the file is read, never written.
pub const SCRIPT: &str = "c=$(uci -q get uhttpd.main.cert) || exit 0; [ -r \"$c\" ] || exit 0; \
     hexdump -v -e '1/1 \"%02x\"' \"$c\"";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cert {
    pub not_before: Timestamp,
    pub not_after: Timestamp,
}

impl Cert {
    /// Whole days until it ends (negative: since it did).
    pub fn days_left(&self, now: Timestamp) -> i64 {
        (self.not_after.as_second() - now.as_second()).div_euclid(86400)
    }
}

/// One DER element at the start of `d`: (tag, its contents, what follows it).
fn tlv(d: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = d.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, b| (a << 8) | *b as usize);
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// `YYMMDDHHMMSSZ` (UTCTime, tag 0x17) or `YYYYMMDDHHMMSSZ` (GeneralizedTime, 0x18).
fn time(tag: u8, body: &[u8]) -> Option<Timestamp> {
    let s = std::str::from_utf8(body).ok()?.strip_suffix('Z')?;
    let (year, rest) = match (tag, s.len()) {
        (0x17, 12) => {
            let yy: i32 = s[..2].parse().ok()?;
            // RFC 5280: 00–49 are 20xx, 50–99 are 19xx.
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &s[2..])
        }
        (0x18, 14) => (s[..4].parse().ok()?, &s[4..]),
        _ => return None,
    };
    if !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    format!(
        "{year:04}-{}-{}T{}:{}:{}Z",
        &rest[..2],
        &rest[2..4],
        &rest[4..6],
        &rest[6..8],
        &rest[8..10]
    )
    .parse()
    .ok()
}

/// The validity of an X.509 certificate in DER: Certificate → tbsCertificate → (version,
/// serial, signature, issuer) → validity.
pub fn validity(der: &[u8]) -> Option<Cert> {
    const SEQ: u8 = 0x30;
    let (tag, cert, _) = tlv(der)?;
    let (tag2, mut tbs, _) = tlv(cert)?;
    if tag != SEQ || tag2 != SEQ {
        return None;
    }
    // The version is there only when it isn't 1 (an explicit [0]).
    if tbs.first() == Some(&0xa0) {
        tbs = tlv(tbs)?.2;
    }
    for _ in 0..3 {
        tbs = tlv(tbs)?.2;
    }
    let (tag, val, _) = tlv(tbs)?;
    if tag != SEQ {
        return None;
    }
    let (t1, b1, rest) = tlv(val)?;
    let (t2, b2, _) = tlv(rest)?;
    Some(Cert {
        not_before: time(t1, b1)?,
        not_after: time(t2, b2)?,
    })
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    if t.is_empty() || !t.len().is_multiple_of(2) || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..t.len() / 2)
        .map(|i| u8::from_str_radix(&t[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// The exec's output: hex of the file. Nothing: uhttpd has no certificate (None).
pub fn parse(text: &str) -> Result<Option<Cert>, String> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let der = unhex(text).ok_or("the certificate didn't arrive as hex")?;
    validity(&der)
        .map(Some)
        .ok_or_else(|| "the certificate's dates couldn't be read (not X.509 in DER?)".to_string())
}

pub fn collect(r: &Remote) -> Result<Option<Cert>, CollectError> {
    parse(&output_needing(r, "hexdump", SCRIPT)?).map_err(CollectError::Parse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    /// The fixture with its end date (ASCII inside the DER) written over.
    pub(crate) fn ending(utc: &str) -> String {
        let hex = |s: &str| s.bytes().map(|b| format!("{b:02x}")).collect::<String>();
        let text = fixture("network/cert.hex");
        let old = hex("270402000000Z");
        assert!(text.contains(&old));
        text.replace(&old, &hex(utc))
    }

    #[test]
    fn the_dates_are_read_from_the_der() {
        let c = parse(&fixture("network/cert.hex")).unwrap().unwrap();
        assert_eq!(c.not_before, ts("2026-03-01T00:00:00Z"));
        assert_eq!(c.not_after, ts("2027-04-02T00:00:00Z"));
        assert_eq!(c.days_left(ts("2027-03-12T00:00:00Z")), 21);
        assert_eq!(c.days_left(ts("2027-04-01T12:00:00Z")), 0);
    }

    #[test]
    fn an_expired_one_counts_the_days_since() {
        let c = parse(&ending("261001120000Z")).unwrap().unwrap();
        assert_eq!(c.not_after, ts("2026-10-01T12:00:00Z"));
        assert_eq!(c.days_left(ts("2026-10-26T12:00:00Z")), -25);
        assert_eq!(c.days_left(ts("2026-10-01T12:00:01Z")), -1);
    }

    #[test]
    fn both_time_forms_and_long_lengths() {
        assert_eq!(
            time(0x17, b"491231235959Z"),
            Some(ts("2049-12-31T23:59:59Z"))
        );
        assert_eq!(
            time(0x17, b"500101000000Z"),
            Some(ts("1950-01-01T00:00:00Z"))
        );
        assert_eq!(
            time(0x18, b"20500101000000Z"),
            Some(ts("2050-01-01T00:00:00Z"))
        );
        assert_eq!(time(0x17, b"2704020000Z"), None);
        assert_eq!(time(0x17, b"27040200000xZ"), None);
        // A two-byte length, as every real certificate's outer sequence has.
        let mut d = vec![0x30, 0x82, 0x01, 0x00];
        d.extend(std::iter::repeat_n(0u8, 256));
        let (tag, body, rest) = tlv(&d).unwrap();
        assert_eq!((tag, body.len(), rest.len()), (0x30, 256, 0));
        assert!(tlv(&[0x30, 0x82, 0x01]).is_none() && tlv(&[0x30, 0x05, 1]).is_none());
    }

    #[test]
    fn nothing_or_nonsense_is_said_not_guessed() {
        assert_eq!(parse("\n"), Ok(None));
        assert!(parse("zz").unwrap_err().contains("hex"));
        assert!(parse("3003020101").unwrap_err().contains("dates"));
        // PEM (text) isn't what the router keeps: its hex is no certificate.
        let pem: String = "-----BEGIN CERTIFICATE-----"
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(parse(&pem).is_err());
    }
}

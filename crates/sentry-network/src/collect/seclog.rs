//! What the router's log says about who logged in and who joined the Wi-Fi: `logread`, read
//! when Security is entered and on `r`. The log is a small ring in memory (128 KiB by
//! default: a few hours on a busy network), so every number made from it is a number "in
//! the window", and the window is part of the answer ([`SecLog::window_s`]).
//!
//! ssh (dropbear): logins that succeeded, with where from, and the ones that didn't (a bad
//! password, a user that doesn't exist, a connection that left before logging in). Each
//! new connection sentry itself makes is a login in that log, so the address this exec
//! came from is read with it (`$SSH_CLIENT`): [`SecLog::me`]. Wi-Fi (hostapd): stations
//! connecting and leaving, and the one line that says a passphrase was wrong.
//!
//! Seen on a real router: the successful logins, the station lines. From dropbear's and
//! hostapd's sources, not seen there: the failed-login lines (`Bad password attempt for`,
//! `Login attempt for nonexistent user`, `Max auth tries reached`, `Exit before auth`) and
//! `AP-STA-POSSIBLE-PSK-MISMATCH`.
//!
//! The output holds addresses and MACs: it stays on this machine.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::{CollectError, output_needing, sections};
use crate::config;
use sentry_app::remote::Remote;

pub const SCRIPT: &str = "echo @@me; echo \"${SSH_CLIENT%% *}\"; \
     echo @@now; date '+%a %b %d %H:%M:%S %Y'; echo @@log; logread";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Failed {
    BadPassword,
    NoSuchUser,
    MaxTries,
    /// It connected and left without logging in.
    LeftBeforeAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "event")]
pub enum Event {
    SshLogin {
        from: Option<IpAddr>,
        user: String,
        /// With a password (else a key).
        password: bool,
    },
    SshFailed {
        from: Option<IpAddr>,
        why: Failed,
    },
    WifiConnected {
        ifname: String,
        mac: String,
        /// `auth_alg=sae` (WPA3); false: the WPA2 handshake; None: the line didn't say.
        sae: Option<bool>,
    },
    WifiDisconnected {
        ifname: String,
        mac: String,
    },
    /// A station offered a wrong passphrase.
    WifiAuthFailed {
        ifname: String,
        mac: Option<String>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecLog {
    /// (when, by the router's own clock as written: seconds, no zone; what)
    pub events: Vec<(i64, Event)>,
    /// The oldest line's time and the router's time at the read, the same way.
    pub first: Option<i64>,
    pub now: Option<i64>,
    pub lines: usize,
    /// Where this read's ssh connection came from, as the router sees it.
    pub me: Option<IpAddr>,
}

impl SecLog {
    /// How far back the log reaches, in seconds.
    pub fn window_s(&self) -> Option<u64> {
        let (first, now) = (self.first?, self.now?);
        u64::try_from(now - first).ok()
    }
}

/// `Mon Oct 26 09:10:00 2026`, as seconds (the clock as written, no zone), and the rest.
fn stamp(line: &str) -> Option<(i64, &str)> {
    let mut at = 0;
    let mut w = [""; 5];
    for slot in &mut w {
        let rest = &line[at..];
        let start = rest.find(|c: char| !c.is_whitespace())?;
        let len = rest[start..]
            .find(char::is_whitespace)
            .unwrap_or(rest.len() - start);
        *slot = &rest[start..start + len];
        at += start + len;
    }
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month = MONTHS.iter().position(|m| *m == w[1])? as i8 + 1;
    let mut hms = w[3].split(':').map(|x| x.parse::<i8>().ok());
    let dt = jiff::civil::DateTime::new(
        w[4].parse().ok()?,
        month,
        w[2].parse().ok()?,
        hms.next()??,
        hms.next()??,
        hms.next()??,
        0,
    )
    .ok()?;
    let secs = dt
        .to_zoned(jiff::tz::TimeZone::UTC)
        .ok()?
        .timestamp()
        .as_second();
    Some((secs, line[at..].trim_start()))
}

/// `192.0.2.11:41562`, `<192.0.2.11:41562>:`, `2001:db8::1:51000`: the address.
fn addr(word: &str) -> Option<IpAddr> {
    let w = word.trim_matches(|c| matches!(c, '<' | '>' | ':' | ','));
    let (a, _port) = w.rsplit_once(':')?;
    a.trim_matches(|c| c == '[' || c == ']').parse().ok()
}

/// The address after the last ` from `.
fn from(msg: &str) -> Option<IpAddr> {
    let (_, rest) = msg.rsplit_once(" from ")?;
    addr(rest.split_whitespace().next()?)
}

fn quoted(msg: &str) -> Option<&str> {
    let (_, rest) = msg.split_once('\'')?;
    rest.split_once('\'').map(|(u, _)| u)
}

fn dropbear(msg: &str) -> Option<Event> {
    let failed = |why| {
        Some(Event::SshFailed {
            from: from(msg),
            why,
        })
    };
    if msg.contains("auth succeeded for") {
        return Some(Event::SshLogin {
            from: from(msg),
            user: quoted(msg).unwrap_or("").to_string(),
            password: msg.starts_with("Password") || msg.starts_with("PAM password"),
        });
    }
    if msg.contains("password attempt for") {
        return failed(Failed::BadPassword);
    }
    if msg.starts_with("Login attempt for nonexistent user") {
        return failed(Failed::NoSuchUser);
    }
    if msg.starts_with("Exit before auth") {
        // The exit that follows refused tries says so; the tries were their own lines.
        return if msg.contains("Max auth tries") {
            failed(Failed::MaxTries)
        } else if msg.contains(" fails)") && !msg.contains(", 0 fails)") {
            None
        } else {
            failed(Failed::LeftBeforeAuth)
        };
    }
    if msg.starts_with("Max auth tries reached") {
        return failed(Failed::MaxTries);
    }
    None
}

fn hostapd(msg: &str) -> Option<Event> {
    let (ifname, rest) = msg.split_once(": ")?;
    let ifname = ifname.to_string();
    let mut w = rest.split_whitespace();
    match w.next()? {
        "AP-STA-CONNECTED" => Some(Event::WifiConnected {
            ifname,
            mac: config::mac(w.next()?)?,
            sae: w
                .find_map(|x| x.strip_prefix("auth_alg="))
                .map(|a| a == "sae"),
        }),
        "AP-STA-DISCONNECTED" => Some(Event::WifiDisconnected {
            ifname,
            mac: config::mac(w.next()?)?,
        }),
        "AP-STA-POSSIBLE-PSK-MISMATCH" => Some(Event::WifiAuthFailed {
            ifname,
            mac: w.next().and_then(config::mac),
        }),
        _ => None,
    }
}

/// `facility.level tag[pid]: message` → the tag and the message.
fn tagged(rest: &str) -> Option<(&str, &str)> {
    let (_level, rest) = rest.split_once(' ')?;
    let (tag, msg) = rest.split_once(": ")?;
    Some((tag.split('[').next().unwrap_or(tag), msg))
}

pub fn parse(text: &str) -> SecLog {
    let secs = sections(text);
    let body = |name: &str| secs.iter().find(|(n, _)| *n == name).map_or("", |(_, b)| b);
    let mut out = SecLog {
        me: body("me").trim().parse().ok(),
        now: stamp(body("now").trim()).map(|(t, _)| t),
        ..Default::default()
    };
    for l in body("log").lines() {
        out.lines += 1;
        let Some((at, rest)) = stamp(l) else {
            continue;
        };
        out.first.get_or_insert(at);
        let ev = match tagged(rest) {
            Some(("dropbear", msg)) => dropbear(msg),
            Some(("hostapd", msg)) => hostapd(msg),
            _ => None,
        };
        out.events.extend(ev.map(|e| (at, e)));
    }
    out
}

pub fn collect(r: &Remote) -> Result<SecLog, CollectError> {
    Ok(parse(&output_needing(r, "logread", SCRIPT)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn the_log_becomes_events_with_its_window() {
        let l = parse(&fixture("network/logread.txt"));
        assert_eq!(l.lines, 35);
        assert_eq!(l.me, ip("192.0.2.11"));
        // From the oldest line to the router's clock at the read: 2 h 50 min.
        assert_eq!(l.window_s(), Some(2 * 3600 + 50 * 60));
        let ssh: Vec<&Event> = l
            .events
            .iter()
            .map(|(_, e)| e)
            .filter(|e| matches!(e, Event::SshLogin { .. } | Event::SshFailed { .. }))
            .collect();
        // Four logins: two from here (sentry's own), one with a password from a device,
        // one from an IPv6 address.
        let logins: Vec<(Option<IpAddr>, bool)> = ssh
            .iter()
            .filter_map(|e| match e {
                Event::SshLogin { from, password, .. } => Some((*from, *password)),
                _ => None,
            })
            .collect();
        assert_eq!(
            logins,
            [
                (ip("192.0.2.11"), false),
                (ip("192.0.2.10"), true),
                (ip("192.0.2.11"), false),
                (ip("2001:db8:1200::c40"), false),
            ]
        );
        // Two bad passwords and a user that doesn't exist. The exit after the bad
        // passwords repeats them and isn't a third; the one after the unknown user had
        // no failed try of its own counted: it left before logging in.
        let failed: Vec<(Option<IpAddr>, Failed)> = ssh
            .iter()
            .filter_map(|e| match e {
                Event::SshFailed { from, why } => Some((*from, *why)),
                _ => None,
            })
            .collect();
        assert_eq!(
            failed,
            [
                (ip("192.0.2.77"), Failed::BadPassword),
                (ip("192.0.2.77"), Failed::BadPassword),
                (ip("192.0.2.77"), Failed::NoSuchUser),
                (ip("192.0.2.77"), Failed::LeftBeforeAuth),
            ]
        );
        // Wi-Fi: two connects (one WPA3), one disconnect, a wrong passphrase twice.
        let n = |f: &dyn Fn(&Event) -> bool| l.events.iter().filter(|(_, e)| f(e)).count();
        assert_eq!(n(&|e| matches!(e, Event::WifiConnected { .. })), 2);
        assert_eq!(
            n(&|e| matches!(
                e,
                Event::WifiConnected {
                    sae: Some(true),
                    ..
                }
            )),
            1
        );
        assert_eq!(n(&|e| matches!(e, Event::WifiDisconnected { .. })), 1);
        assert_eq!(
            n(
                &|e| matches!(e, Event::WifiAuthFailed { mac: Some(m), .. } if m == "02:00:5e:00:53:55")
            ),
            2
        );
        // When: the clock as written.
        assert_eq!(l.events[0].0 - l.first.unwrap(), 4 * 60 + 2);
    }

    #[test]
    fn lines_as_they_come() {
        // A single-digit day is padded with a space.
        let (t, rest) = stamp("Sun Nov  1 00:00:05 2026 daemon.info x: y").unwrap();
        assert_eq!(rest, "daemon.info x: y");
        let (t2, _) = stamp("Sat Oct 31 23:59:55 2026 daemon.info x: y").unwrap();
        assert_eq!(t - t2, 10);
        assert!(stamp("not a log line at all").is_none());
        assert_eq!(addr("<192.0.2.77:50100>:"), ip("192.0.2.77"));
        assert_eq!(addr("2001:db8::1:51000"), ip("2001:db8::1"));
        assert_eq!(addr("nonsense"), None);
        assert_eq!(
            dropbear(
                "Exit before auth from <198.18.0.9:4000>: Max auth tries reached - user 'root'"
            ),
            Some(Event::SshFailed {
                from: ip("198.18.0.9"),
                why: Failed::MaxTries
            })
        );
        assert_eq!(dropbear("Child connection from 192.0.2.11:41562"), None);
        assert_eq!(
            hostapd("phy0-ap0: STA 02:00:5e:00:53:21 IEEE 802.11: authenticated"),
            None
        );
        // An empty ring, a router that didn't say where the connection came from.
        let l = parse("@@me\n\n@@now\nMon Oct 26 12:00:00 2026\n@@log\n");
        assert_eq!(
            (l.me, l.first, l.window_s(), l.lines),
            (None, None, None, 0)
        );
        assert_eq!(parse(""), SecLog::default());
    }
}

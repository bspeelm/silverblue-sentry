//! What answers behind a door, asked once from this machine: the one exception to "the
//! audit only reads". For each TCP port a router forwards to one of sentry's own servers,
//! sentry asks that server's inside address on the port the forward arrives on (never
//! anything else, never another device): one `GET /`, no redirect followed, no login, 5 s.
//!
//! - first over HTTPS with the certificate checked by this machine's trust store (curl
//!   stops after the handshake when the check fails: no request is sent then);
//! - if the check failed, the same GET over HTTPS without the check, to see the page;
//! - if the port doesn't speak TLS at all, the GET over plain HTTP instead.
//!
//! So at most two connections and exactly one HTTP request. What comes back is classified
//! conservatively ([`classify`]): a login is said only on a 401/403, a redirect to a page
//! named like a login, or a page with a password field; a page that answers is a question,
//! never an accusation. Nothing of it is kept but the class and the certificate's days and
//! kind of issuer: no body, no header, no name, no address.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::exec::Cmd;

/// How a door's front page answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "is", content = "how")]
pub enum Web {
    /// 401, 403, or a redirect to a login page: the status or `redirect`.
    Login(String),
    /// A page with a password field.
    LoginPage,
    /// A page with content and no sign of a login.
    Open,
    /// It answered, and what it means can't be told: why, in words.
    Unclear(String),
    /// Something answered that doesn't speak HTTP.
    NotWeb,
    /// It speaks TLS but refused without a site name sentry doesn't know.
    NeedsName,
    /// Nothing answered from this machine: why.
    NoAnswer(String),
}

impl Web {
    pub fn asks_login(&self) -> bool {
        matches!(self, Web::Login(_) | Web::LoginPage)
    }

    /// In words, for the evidence.
    pub fn said(&self) -> String {
        match self {
            Web::Login(how) if how == "redirect" => "it sends visitors to a login page".into(),
            Web::Login(code) => format!("it asks for a login ({code})"),
            Web::LoginPage => "it shows a login page".into(),
            Web::Open => "it shows a page without asking for a login".into(),
            Web::Unclear(why) => format!("it answers, but {why}"),
            Web::NotWeb => "something answers there that isn't a web page".into(),
            Web::NeedsName => {
                "it speaks HTTPS only for site names sentry doesn't know, so nothing more \
                 could be seen"
                    .into()
            }
            Web::NoAnswer(why) => format!("it didn't answer from this machine ({why})"),
        }
    }
}

/// Who vouches for the certificate a door shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Issuer {
    /// An authority this machine trusts (browsers do too).
    Public,
    /// The certificate vouches for itself.
    SelfSigned,
    /// An authority this machine doesn't know (a private one).
    Private,
    Unknown,
}

impl Issuer {
    pub fn said(self) -> &'static str {
        match self {
            Issuer::Public => "from a public authority",
            Issuer::SelfSigned => "self-signed",
            Issuer::Private => "from an authority this machine doesn't know",
            Issuer::Unknown => {
                "from an issuer sentry couldn't tell (it asked by address, not by name)"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tls {
    /// Days until it expires (negative: expired that long ago). None: not read.
    pub days_left: Option<i64>,
    pub issuer: Issuer,
}

/// What one door answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answered {
    pub web: Web,
    /// It spoke HTTPS: its certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
}

/// Names in a redirect's target that mean a login.
const LOGIN_WORDS: &[&str] = &[
    "login", "log-in", "signin", "sign-in", "sign_in", "auth", "sso", "oauth", "account", "session",
];

/// A page that asks for a password.
fn password_field(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    ["type=\"password\"", "type='password'", "type=password"]
        .iter()
        .any(|p| b.contains(p))
}

/// The class of one answer: status, the redirect's target (if any) and the body.
pub fn classify(code: u16, redirect: &str, body: &str) -> Web {
    let to = redirect.to_ascii_lowercase();
    match code {
        401 | 407 => Web::Login(code.to_string()),
        403 => Web::Login(code.to_string()),
        300..=399 if LOGIN_WORDS.iter().any(|w| to.contains(w)) => Web::Login("redirect".into()),
        300..=399 if to.starts_with("https://") => {
            Web::Unclear("only sends the browser on to HTTPS".into())
        }
        300..=399 => Web::Unclear("sends visitors elsewhere, not to a login page".into()),
        200..=299 if password_field(body) => Web::LoginPage,
        200..=299 if body.trim().is_empty() => Web::Unclear("with an empty page".into()),
        200..=299 => Web::Open,
        404 => Web::Unclear(
            "shows nothing at its front page (404): a proxy that picks sites by name does that"
                .into(),
        ),
        500..=599 => Web::Unclear(format!("with an error ({code})")),
        _ => Web::Unclear(format!("with an unusual status ({code})")),
    }
}

/// What curl writes after the body (`-w`), framed so the body can't be mistaken for it.
const MARK: &str = "\n@@sentry-probe\n";
const WRITE_OUT: &str = "\n@@sentry-probe\n%{http_code}\n%{redirect_url}\n%{certs}";

/// One curl answer: the status, the redirect, the body, the certificates' text.
#[derive(Debug, Default, PartialEq)]
pub struct Reply {
    pub code: u16,
    pub redirect: String,
    pub body: String,
    pub certs: String,
}

pub fn parse_reply(stdout: &str) -> Option<Reply> {
    let at = stdout.rfind(MARK)?;
    let (body, rest) = (&stdout[..at], &stdout[at + MARK.len()..]);
    let mut lines = rest.splitn(3, '\n');
    let code = lines.next()?.trim().parse().ok()?;
    Some(Reply {
        code,
        redirect: lines.next().unwrap_or("").trim().to_string(),
        body: body.to_string(),
        certs: lines.next().unwrap_or("").to_string(),
    })
}

/// The first certificate's expiry (`Expire date:Dec 25 22:56:35 2026 GMT`) as days from
/// `now`, and whether it is the only one and vouches for itself (subject = issuer).
pub fn parse_certs(text: &str, now: Timestamp) -> (Option<i64>, bool) {
    let field = |name: &str| -> Vec<&str> {
        text.lines()
            .filter_map(|l| l.strip_prefix(name))
            .map(str::trim)
            .collect()
    };
    let expiry = field("Expire date:").first().and_then(|d| {
        let d = d.split_whitespace().collect::<Vec<_>>().join(" ");
        let d = d.trim_end_matches(" GMT");
        jiff::civil::DateTime::strptime("%b %d %H:%M:%S %Y", d)
            .ok()
            .and_then(|t| t.to_zoned(jiff::tz::TimeZone::UTC).ok())
            .map(|z| z.timestamp())
    });
    let days = expiry.map(|t| (t.as_second() - now.as_second()).div_euclid(86_400));
    let (subjects, issuers) = (field("Subject:"), field("Issuer:"));
    let own = subjects.len() == 1 && issuers.len() == 1 && subjects[0] == issuers[0];
    (days, own)
}

/// What a failed check (curl's exit 60) says of the issuer.
pub fn issuer_of(stderr: &str) -> Issuer {
    let e = stderr.to_ascii_lowercase();
    if e.contains("self-signed certificate in certificate chain") {
        Issuer::Private
    } else if e.contains("self-signed certificate") || e.contains("self signed certificate") {
        Issuer::SelfSigned
    } else if e.contains("unable to get local issuer") || e.contains("unable to get issuer") {
        Issuer::Private
    } else if e.contains("subject name") || e.contains("host name") || e.contains("hostname") {
        // Only the name (an address here) is said not to match: curl may say so before
        // it judges the chain, so who vouches for it isn't known from this.
        Issuer::Unknown
    } else {
        Issuer::Unknown
    }
}

/// curl's exit 35 on a port that isn't TLS at all (an HTTP server answering a handshake).
fn not_tls(stderr: &str) -> bool {
    let e = stderr.to_ascii_lowercase();
    [
        "wrong version number",
        "packet length too long",
        "record layer failure",
        "http request",
        "unexpected eof",
    ]
    .iter()
    .any(|w| e.contains(w))
}

fn why_not(code: i32) -> String {
    match code {
        7 => "the connection was refused".into(),
        28 => "no answer within 5 seconds".into(),
        6 | 3 => "the address couldn't be used".into(),
        n => format!("curl said {n}"),
    }
}

/// The URL for an address literal and a port (nothing else is ever put in).
pub fn url(scheme: &str, addr: &str, port: u16) -> Option<String> {
    match addr.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(a) => Some(format!("{scheme}://{a}:{port}/")),
        std::net::IpAddr::V6(a) => Some(format!("{scheme}://[{a}]:{port}/")),
    }
}

/// One curl run, as `run` gives it: the exit code, stdout, stderr.
pub type Outcome = (i32, String, String);

/// The decisions of [`ask`], over whatever runs curl (`get(url, checked)`): pure, so the
/// order and what each answer means are tested without a network.
pub fn decide(
    addr: &str,
    port: u16,
    now: Timestamp,
    mut get: impl FnMut(&str, bool) -> Outcome,
) -> Option<Answered> {
    let https = url("https", addr, port)?;
    let reply = |out: &str, tls: Option<Tls>| -> Answered {
        match parse_reply(out) {
            Some(r) => Answered {
                web: classify(r.code, &r.redirect, &r.body),
                tls,
            },
            None => Answered {
                web: Web::NotWeb,
                tls,
            },
        }
    };
    let with_certs = |out: &str, issuer: Issuer| -> Tls {
        let (days, own) = parse_reply(out).map_or((None, false), |r| parse_certs(&r.certs, now));
        Tls {
            days_left: days,
            issuer: if issuer == Issuer::Unknown && own {
                Issuer::SelfSigned
            } else {
                issuer
            },
        }
    };
    let (code, out, err) = get(&https, true);
    Some(match code {
        // Checked and trusted: that answer is the one request.
        0 => {
            let t = with_certs(&out, Issuer::Public);
            reply(&out, Some(t))
        }
        // The check failed before any request: see the page without it.
        60 => {
            let issuer = issuer_of(&err);
            let (code, out, _) = get(&https, false);
            if code == 0 {
                let t = with_certs(&out, issuer);
                reply(&out, Some(t))
            } else {
                Answered {
                    web: Web::NoAnswer(why_not(code)),
                    tls: None,
                }
            }
        }
        35 if !not_tls(&err) => Answered {
            web: Web::NeedsName,
            tls: None,
        },
        // (28: a plain HTTP server may wait for a line a TLS handshake never sends.)
        28 | 35 | 52 | 56 => {
            let http = url("http", addr, port)?;
            let (code, out, _) = get(&http, true);
            match code {
                0 => reply(&out, None),
                // A proxy that picks sites by name may close on a bare address.
                52 => Answered {
                    web: Web::Unclear(
                        "closes the connection without an answer: a proxy that picks sites by \
                         name does that"
                            .into(),
                    ),
                    tls: None,
                },
                1 | 8 => Answered {
                    web: Web::NotWeb,
                    tls: None,
                },
                n => Answered {
                    web: Web::NoAnswer(why_not(n)),
                    tls: None,
                },
            }
        }
        n => Answered {
            web: Web::NoAnswer(why_not(n)),
            tls: None,
        },
    })
}

/// Ask one door, for real: curl on this machine, as described at the top.
pub fn ask(addr: &str, port: u16) -> Option<Answered> {
    // (Test knob: `SENTRY_PROBE_PREFIX`, words put before curl, so the disposable targets'
    // rootless network is reached from its own namespace: scripts/live-resolution.sh.)
    let prefix: Vec<String> = std::env::var("SENTRY_PROBE_PREFIX")
        .map(|p| p.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    decide(addr, port, Timestamp::now(), |url, checked| {
        let start = match prefix.split_first() {
            Some((bin, rest)) => Cmd::host(bin).args(rest).arg("curl"),
            None => Cmd::host("curl"),
        };
        let mut c = start.args([
            "-sS",
            "--max-time",
            "5",
            "--max-filesize",
            "1000000",
            "-A",
            "sentry-security-audit",
            "-o",
            "-",
            "-w",
            WRITE_OUT,
        ]);
        if !checked {
            c = c.arg("-k");
        }
        match c
            .arg(url)
            .timeout(Some(std::time::Duration::from_secs(8)))
            .run()
        {
            Ok(o) => (o.code, o.stdout, o.stderr),
            Err(e) => (-1, String::new(), e.to_string()),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        "2026-11-21T10:00:00Z".parse().unwrap()
    }

    #[test]
    fn what_a_front_page_says_is_classified_conservatively() {
        let table: &[(u16, &str, &str, Web)] = &[
            (401, "", "", Web::Login("401".into())),
            (403, "", "forbidden", Web::Login("403".into())),
            (
                302,
                "https://x/login?next=/",
                "",
                Web::Login("redirect".into()),
            ),
            (303, "/auth/realms/x", "", Web::Login("redirect".into())),
            (
                301,
                "https://x/",
                "",
                Web::Unclear("only sends the browser on to HTTPS".into()),
            ),
            (
                302,
                "/welcome",
                "",
                Web::Unclear("sends visitors elsewhere, not to a login page".into()),
            ),
            (
                200,
                "",
                "<form><input TYPE=\"password\" name=p></form>",
                Web::LoginPage,
            ),
            (200, "", "<h1>My photos</h1>", Web::Open),
            (200, "", "  \n", Web::Unclear("with an empty page".into())),
            (
                404,
                "",
                "not found",
                Web::Unclear(
                    "shows nothing at its front page (404): a proxy that picks sites by name \
                     does that"
                        .into(),
                ),
            ),
            (502, "", "", Web::Unclear("with an error (502)".into())),
        ];
        for (code, to, body, want) in table {
            assert_eq!(&classify(*code, to, body), want, "{code} {to:?} {body:?}");
        }
        assert!(Web::LoginPage.asks_login() && !Web::Open.asks_login());
    }

    const PUBLIC: &str = "Subject:CN = example.org\nIssuer:C = US, O = Example CA, CN = R1\n\
        Start date:Oct  1 00:00:00 2026 GMT\nExpire date:Dec 30 00:00:00 2026 GMT\n\
        Subject:C = US, O = Example CA, CN = R1\nIssuer:C = US, O = Example Root\n\
        Expire date:May 27 19:49:44 2035 GMT\n";
    const SELF: &str = "Subject:CN = myserver\nIssuer:CN = myserver\n\
        Expire date:Nov 21 10:00:00 2027 GMT\n";
    const EXPIRING: &str = "Subject:CN = a\nIssuer:CN = b\nExpire date:Nov 30 09:00:00 2026 GMT\n";
    const EXPIRED: &str = "Subject:CN = a\nIssuer:CN = b\nExpire date:Nov  1 00:00:00 2026 GMT\n";

    #[test]
    fn certificates_say_their_days_and_whether_they_vouch_for_themselves() {
        assert_eq!(parse_certs(PUBLIC, now()), (Some(38), false));
        assert_eq!(parse_certs(SELF, now()), (Some(365), true));
        assert_eq!(parse_certs(EXPIRING, now()), (Some(8), false));
        assert_eq!(parse_certs(EXPIRED, now()), (Some(-21), false));
        assert_eq!(parse_certs("", now()), (None, false));
        // What curl says when its check fails.
        let e = |s: &str| {
            issuer_of(&format!(
                "curl: (60) SSL certificate OpenSSL verify result: {s}"
            ))
        };
        assert_eq!(e("self-signed certificate (18)"), Issuer::SelfSigned);
        assert_eq!(
            e("self-signed certificate in certificate chain (19)"),
            Issuer::Private
        );
        assert_eq!(
            e("unable to get local issuer certificate (20)"),
            Issuer::Private
        );
        assert_eq!(
            issuer_of(
                "curl: (60) SSL: no alternative certificate subject name matches target ipv4 address '192.0.2.93'"
            ),
            Issuer::Unknown
        );
        assert_eq!(e("certificate has expired (10)"), Issuer::Unknown);
    }

    fn out(code: u16, redirect: &str, body: &str, certs: &str) -> String {
        format!("{body}{MARK}{code}\n{redirect}\n{certs}")
    }

    /// The order of the asking, and that a checked, trusted answer is the only request.
    #[test]
    fn a_door_is_asked_once_and_what_it_said_decides() {
        let run = |answers: Vec<Outcome>| {
            let mut asked = Vec::new();
            let mut it = answers.into_iter();
            let got = decide("192.0.2.93", 8443, now(), |u, checked| {
                asked.push(format!("{u} {}", if checked { "checked" } else { "-k" }));
                it.next().unwrap_or((7, String::new(), String::new()))
            });
            (got, asked)
        };
        // Trusted: one run.
        let (a, asked) = run(vec![(0, out(401, "", "", PUBLIC), String::new())]);
        assert_eq!(asked, ["https://192.0.2.93:8443/ checked"]);
        let a = a.unwrap();
        assert_eq!(a.web, Web::Login("401".into()));
        assert_eq!(
            a.tls,
            Some(Tls {
                days_left: Some(38),
                issuer: Issuer::Public
            })
        );
        // Self-signed: the check stops before any request, then the page without it.
        let (a, asked) = run(vec![
            (
                60,
                String::new(),
                "verify result: self-signed certificate (18)".into(),
            ),
            (0, out(200, "", "<p>hello</p>", SELF), String::new()),
        ]);
        assert_eq!(
            asked,
            [
                "https://192.0.2.93:8443/ checked",
                "https://192.0.2.93:8443/ -k"
            ]
        );
        let a = a.unwrap();
        assert_eq!(a.web, Web::Open);
        assert_eq!(a.tls.unwrap().issuer, Issuer::SelfSigned);
        // Plain HTTP: the handshake fails as not TLS, then one GET over HTTP.
        let (a, asked) = run(vec![
            (
                35,
                String::new(),
                "SSL routines::wrong version number".into(),
            ),
            (0, out(302, "http://x/login", "", ""), String::new()),
        ]);
        assert_eq!(asked[1], "http://192.0.2.93:8443/ checked");
        assert_eq!(
            a.unwrap(),
            Answered {
                web: Web::Login("redirect".into()),
                tls: None
            }
        );
        // TLS that wants a site name: nothing more.
        let (a, asked) = run(vec![(35, String::new(), "tls alert internal error".into())]);
        assert_eq!((a.unwrap().web, asked.len()), (Web::NeedsName, 1));
        // Not HTTP behind plain TCP; nothing listening.
        let (a, _) = run(vec![
            (35, String::new(), "packet length too long".into()),
            (1, String::new(), "Received HTTP/0.9".into()),
        ]);
        assert_eq!(a.unwrap().web, Web::NotWeb);
        let (a, _) = run(vec![
            (52, String::new(), "Empty reply from server".into()),
            (52, String::new(), "Empty reply from server".into()),
        ]);
        assert!(
            matches!(a.unwrap().web, Web::Unclear(w) if w.starts_with("closes the connection"))
        );
        // A plain HTTP server that waits on the handshake: tried over HTTP after it.
        let (a, asked) = run(vec![
            (28, String::new(), "timed out".into()),
            (0, out(401, "", "", ""), String::new()),
        ]);
        assert_eq!(
            (a.unwrap().web, asked[1].as_str()),
            (Web::Login("401".into()), "http://192.0.2.93:8443/ checked")
        );
        let (a, _) = run(vec![(7, String::new(), "refused".into())]);
        assert_eq!(
            a.unwrap().web,
            Web::NoAnswer("the connection was refused".into())
        );
        // Only an address literal is ever put into a URL.
        assert_eq!(url("https", "myserver.example", 443), None);
        assert_eq!(
            url("http", "2001:db8::93", 80).as_deref(),
            Some("http://[2001:db8::93]:80/")
        );
        assert!(decide("not an address", 1, now(), |_, _| unreachable!()).is_none());
    }
}

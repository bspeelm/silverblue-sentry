//! The router's configuration as `uci show` prints it, one config per call (it takes only
//! one), and what is staged but not committed (`uci changes`), all in one exec cut at `@@`
//! marks. Secrets are replaced by tags as it's parsed ([`crate::redact`]), so nothing read
//! here can leak one. Over it, the views the audit and the Network screen read: the
//! firewall's zones, port forwards and what it lets in from outside; how ssh and the web
//! interface are set up; the Wi-Fi networks. Read on entering Network and on `r`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{CollectError, output_needing, sections};
use crate::redact::{self, Salt};
use sentry_app::remote::Remote;

/// The configs read.
pub const CONFIGS: &[&str] = &[
    "firewall", "dropbear", "uhttpd", "wireless", "dhcp", "network", "system",
];

/// The configs whose staged changes the audit reports (another package's are its own
/// business: adblock-fast keeps some staged for as long as it runs).
pub const AUDITED: &[&str] = &[
    "network", "firewall", "wireless", "dhcp", "dropbear", "uhttpd",
];

pub const SCRIPT: &str = "for c in firewall dropbear uhttpd wireless dhcp network system; do \
     echo @@$c; uci show $c 2>/dev/null; done; echo @@changes; uci changes";

/// One section: its name (`@zone[0]`, `web_https`), its type and its options.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub kind: String,
    pub opts: BTreeMap<String, Vec<String>>,
}

impl Section {
    pub fn one(&self, k: &str) -> Option<&str> {
        self.opts.get(k)?.first().map(String::as_str)
    }

    /// A list's values; one written as a single option holds its words.
    pub fn list(&self, k: &str) -> Vec<String> {
        self.opts.get(k).map_or(Vec::new(), |v| {
            v.iter()
                .flat_map(|x| x.split_whitespace().map(str::to_string))
                .collect()
        })
    }

    /// An option that's on unless it says otherwise (`enabled`), or off unless it says so.
    pub fn flag(&self, k: &str, default: bool) -> bool {
        match self.one(k).map(str::to_ascii_lowercase).as_deref() {
            Some("1" | "on" | "yes" | "true" | "enabled") => true,
            Some("0" | "off" | "no" | "false" | "disabled") => false,
            _ => default,
        }
    }
}

/// The quoted values after `=`: `'wan' 'wan6'` (a list) or `'it'\''s'` (one, with a quote).
pub fn values(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                quoted = !quoted;
                any = true;
            }
            '\\' if !quoted => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// `uci show <config>` as it stands: `pkg.section=type`, then `pkg.section.option='value'`.
/// Nothing is redacted here: [`parse`] is what the collectors use.
pub fn show(text: &str) -> Vec<Section> {
    let mut out: Vec<Section> = Vec::new();
    for line in text.lines() {
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let mut parts = key.splitn(3, '.');
        let (Some(_pkg), Some(section)) = (parts.next(), parts.next()) else {
            continue;
        };
        match parts.next() {
            None => out.push(Section {
                name: section.to_string(),
                kind: values(val).into_iter().next().unwrap_or_default(),
                opts: BTreeMap::new(),
            }),
            Some(opt) => {
                if let Some(s) = out.iter_mut().rev().find(|s| s.name == section) {
                    s.opts.insert(opt.to_string(), values(val));
                }
            }
        }
    }
    out
}

/// Everything read: each config's sections, and the lines staged but not committed. Every
/// secret value in it is already a tag.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Uci {
    pub configs: BTreeMap<String, Vec<Section>>,
    /// `uci changes`, every package's.
    pub staged: Vec<String>,
}

/// A staged line with its secret, if it has one, tagged: `pkg.sec.opt='value'`,
/// `pkg.sec.opt+='value'`, `-pkg.sec.opt`.
fn staged_line(line: &str, salt: &Salt) -> String {
    match line.split_once('=') {
        Some((key, val)) if redact::secret(key.trim_end_matches('+')) => {
            let tagged: Vec<String> = values(val)
                .iter()
                .map(|v| format!("'{}'", salt.tag(v)))
                .collect();
            format!("{key}={}", tagged.join(" "))
        }
        _ => line.to_string(),
    }
}

pub fn parse(text: &str, salt: &Salt) -> Uci {
    let mut u = Uci::default();
    for (name, body) in sections(text) {
        if name == "changes" {
            u.staged = body
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| staged_line(l, salt))
                .collect();
            continue;
        }
        let mut secs = show(body);
        for s in &mut secs {
            for (opt, vals) in &mut s.opts {
                if redact::secret(opt) {
                    for v in vals {
                        *v = salt.tag(v);
                    }
                }
            }
        }
        u.configs.insert(name.to_string(), secs);
    }
    u
}

pub fn collect(r: &Remote) -> Result<Uci, CollectError> {
    let text = output_needing(r, "uci", SCRIPT)?;
    let salt = Salt::load(&r.scope)
        .map_err(|e| CollectError::Failed(format!("{}: {e}", redact::path(&r.scope).display())))?;
    Ok(parse(&text, &salt))
}

/// A firewall zone.
#[derive(Debug, Clone, PartialEq)]
pub struct Zone {
    pub name: String,
    /// The interfaces in it (`network`, and any `device`).
    pub networks: Vec<String>,
    /// `ACCEPT`, `REJECT` or `DROP`: what reaches the router itself, and what passes.
    pub input: String,
    pub forward: String,
}

/// A port forward (a DNAT redirect).
#[derive(Debug, Clone, PartialEq)]
pub struct Redirect {
    pub section: String,
    pub name: String,
    /// `tcp`, `udp` (both when the rule says neither).
    pub protos: Vec<String>,
    pub src: String,
    /// The port outside, or a range (`8000-8010`).
    pub port: String,
    pub dest_ip: String,
    pub dest_port: Option<String>,
    pub enabled: bool,
}

/// A rule that lets something from a zone reach the router itself.
#[derive(Debug, Clone, PartialEq)]
pub struct Opening {
    pub name: String,
    pub src: String,
    /// `tcp`, `udp`, `icmp`…; empty: any.
    pub protos: Vec<String>,
    /// The ports, as written (`68`, `8000-8010`); none: every port of those protocols.
    pub ports: Vec<String>,
}

impl Opening {
    /// Whether it lets `proto` to `port` in.
    pub fn covers(&self, proto: &str, port: u16) -> bool {
        let proto_ok = self.protos.is_empty()
            || self
                .protos
                .iter()
                .any(|p| p == proto || p == "all" || p == "tcpudp");
        proto_ok && (self.ports.is_empty() || self.ports.iter().any(|p| {
            let (a, b) = p.split_once(['-', ':']).unwrap_or((p, p));
            matches!((a.parse::<u16>(), b.parse::<u16>()), (Ok(a), Ok(b)) if a <= port && port <= b)
        }))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Dropbear {
    pub section: String,
    pub password_auth: bool,
    pub root_password_auth: bool,
    pub port: String,
    /// The interface it's bound to; none: every address.
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Uhttpd {
    pub listen_http: Vec<String>,
    pub listen_https: Vec<String>,
    pub redirect_https: bool,
    pub cert: Option<String>,
}

/// A Wi-Fi network the router offers. The SSID is the user's own: shown on screen, never
/// sent anywhere.
#[derive(Debug, Clone, PartialEq)]
pub struct Wifi {
    pub section: String,
    pub device: String,
    pub ssid: String,
    pub encryption: String,
    /// It has a passphrase (which is only ever a tag here).
    pub key: bool,
    pub disabled: bool,
}

/// `8000:8010` as `8000-8010`.
fn ports(s: &str) -> String {
    s.replace(':', "-")
}

impl Uci {
    pub fn config(&self, name: &str) -> &[Section] {
        self.configs.get(name).map_or(&[], Vec::as_slice)
    }

    fn firewall(&self, kind: &'static str) -> impl Iterator<Item = &Section> {
        self.config("firewall")
            .iter()
            .filter(move |s| s.kind == kind)
    }

    pub fn zones(&self) -> Vec<Zone> {
        let defaults = self.firewall("defaults").next();
        let policy = |s: &Section, k: &str| {
            s.one(k)
                .or_else(|| defaults.and_then(|d| d.one(k)))
                .unwrap_or("REJECT")
                .to_ascii_uppercase()
        };
        self.firewall("zone")
            .filter_map(|s| {
                let mut networks = s.list("network");
                networks.extend(s.list("device"));
                Some(Zone {
                    name: s.one("name")?.to_string(),
                    networks,
                    input: policy(s, "input"),
                    forward: policy(s, "forward"),
                })
            })
            .collect()
    }

    /// Every DNAT redirect, the disabled ones too.
    pub fn forwards(&self) -> Vec<Redirect> {
        self.firewall("redirect")
            .filter(|s| {
                s.one("target")
                    .is_none_or(|t| t.eq_ignore_ascii_case("DNAT"))
            })
            .filter_map(|s| {
                let mut protos: Vec<String> = s
                    .list("proto")
                    .iter()
                    .flat_map(|p| match p.as_str() {
                        "tcpudp" | "all" | "any" => vec!["tcp".to_string(), "udp".to_string()],
                        p => vec![p.to_string()],
                    })
                    .collect();
                if protos.is_empty() {
                    protos = vec!["tcp".into(), "udp".into()];
                }
                Some(Redirect {
                    section: s.name.clone(),
                    name: s.one("name").unwrap_or(&s.name).to_string(),
                    protos,
                    src: s.one("src").unwrap_or("wan").to_string(),
                    port: ports(s.one("src_dport")?),
                    dest_ip: s.one("dest_ip")?.to_string(),
                    dest_port: s.one("dest_port").map(ports),
                    enabled: s.flag("enabled", true),
                })
            })
            .collect()
    }

    /// The rules that accept traffic for the router itself (no `dest`), by where it comes
    /// from.
    pub fn openings(&self) -> Vec<Opening> {
        self.firewall("rule")
            .filter(|s| {
                s.one("target")
                    .is_some_and(|t| t.eq_ignore_ascii_case("ACCEPT"))
                    && s.one("dest").is_none()
                    && s.flag("enabled", true)
            })
            .filter_map(|s| {
                Some(Opening {
                    name: s.one("name").unwrap_or(&s.name).to_string(),
                    src: s.one("src")?.to_string(),
                    protos: s.list("proto"),
                    ports: s.list("dest_port").iter().map(|p| ports(p)).collect(),
                })
            })
            .collect()
    }

    /// The ssh servers that are on. Password logins are allowed unless it says otherwise.
    pub fn dropbear(&self) -> Vec<Dropbear> {
        self.config("dropbear")
            .iter()
            .filter(|s| s.kind == "dropbear" && s.flag("enable", true))
            .map(|s| Dropbear {
                section: s.name.clone(),
                password_auth: s.flag("PasswordAuth", true),
                root_password_auth: s.flag("RootPasswordAuth", true),
                port: s.one("Port").unwrap_or("22").to_string(),
                interface: s.one("Interface").map(str::to_string),
            })
            .collect()
    }

    pub fn uhttpd(&self) -> Option<Uhttpd> {
        let all: Vec<&Section> = self
            .config("uhttpd")
            .iter()
            .filter(|s| s.kind == "uhttpd")
            .collect();
        let first = all.first()?;
        Some(Uhttpd {
            listen_http: all.iter().flat_map(|s| s.list("listen_http")).collect(),
            listen_https: all.iter().flat_map(|s| s.list("listen_https")).collect(),
            redirect_https: all.iter().all(|s| s.flag("redirect_https", false)),
            cert: first.one("cert").map(str::to_string),
        })
    }

    pub fn wifi(&self) -> Vec<Wifi> {
        self.config("wireless")
            .iter()
            .filter(|s| s.kind == "wifi-iface")
            .map(|s| Wifi {
                section: s.name.clone(),
                device: s.one("device").unwrap_or_default().to_string(),
                ssid: s.one("ssid").unwrap_or_default().to_string(),
                encryption: s.one("encryption").unwrap_or("none").to_string(),
                key: ["key", "sae_password"]
                    .iter()
                    .any(|k| s.one(k).is_some_and(|v| !v.is_empty())),
                disabled: s.flag("disabled", false),
            })
            .collect()
    }

    /// The staged lines the audit reports: those of the audited configs. A dnsmasq option
    /// adblock-fast stages for itself (it keeps its own lines staged beside it) isn't one.
    pub fn staged_audited(&self) -> Vec<&str> {
        let pkg = |l: &str| {
            l.trim_start_matches('-')
                .split('.')
                .next()
                .unwrap_or("")
                .to_string()
        };
        let adblock = self.staged.iter().any(|l| pkg(l) == "adblock-fast");
        self.staged
            .iter()
            .map(String::as_str)
            .filter(|l| AUDITED.contains(&pkg(l).as_str()))
            .filter(|l| {
                let key = l.split('=').next().unwrap_or("").trim_end_matches('+');
                let opt = key.rsplit('.').next().unwrap_or("");
                !(adblock
                    && pkg(l) == "dhcp"
                    && matches!(opt, "serversfile" | "addnhosts" | "addnmount" | "confdir"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    pub(crate) fn salt() -> Salt {
        Salt::fixed([7; 16])
    }

    fn uci() -> Uci {
        parse(&fixture("network/uci.txt"), &salt())
    }

    #[test]
    fn every_config_is_read_and_lists_and_quotes_survive() {
        let u = uci();
        let names: Vec<&str> = u.configs.keys().map(String::as_str).collect();
        let mut want = CONFIGS.to_vec();
        want.sort();
        assert_eq!(names, want);
        let fw = u.config("firewall");
        assert_eq!(fw[2].one("name"), Some("wan"));
        assert_eq!(fw[2].list("network"), ["wan", "wan6"]);
        assert_eq!(values("'a b' 'c'"), ["a b", "c"]);
        assert_eq!(values("'it'\\''s'"), ["it's"]);
        assert_eq!(values("''"), [""]);
        // The script reads each config by itself, as uci wants.
        for c in CONFIGS {
            assert!(SCRIPT.contains(c), "{c}");
        }
        assert!(SCRIPT.contains("uci show $c") && SCRIPT.ends_with("uci changes"));
    }

    #[test]
    fn secrets_are_tags_and_what_the_audit_reads_stays_readable() {
        let u = uci();
        let s = salt();
        let w = &u.config("wireless");
        let key = w
            .iter()
            .find(|x| x.name == "default_radio0")
            .unwrap()
            .one("key")
            .unwrap();
        assert_eq!(key, s.tag("correct horse battery"));
        let sae = w.iter().find(|x| x.name == "default_radio1").unwrap();
        // A quote in the value is part of what's hashed, not of what's shown.
        assert_eq!(
            sae.one("sae_password"),
            Some(s.tag("it's a secret").as_str())
        );
        let net = u.config("network");
        let one = |sec: &str, k: &str| {
            net.iter()
                .find(|x| x.name == sec)
                .unwrap()
                .one(k)
                .unwrap()
                .to_string()
        };
        assert!(redact::is_tag(&one("wan", "password")));
        assert!(redact::is_tag(&one("wg0", "private_key")));
        assert_eq!(one("wan", "username"), "user@example.net");
        // The path of the web interface's key is tagged with the rest: nothing reads it.
        assert!(redact::is_tag(u.config("uhttpd")[0].one("key").unwrap()));
        assert_eq!(u.config("uhttpd")[1].one("key_type"), Some("ec"));
        let d = &u.config("dropbear")[0];
        assert_eq!(d.one("PasswordAuth"), Some("off"));
        assert_eq!(d.one("RootPasswordAuth"), Some("off"));
        // Nowhere in what was read is a secret left.
        let all = serde_json::to_string(&u).unwrap();
        for secret in [
            "horse",
            "hunter2",
            "it's a secret",
            "aGVsbG8",
            "/etc/uhttpd.key",
        ] {
            assert!(!all.contains(secret), "{secret} survived");
        }
        // A staged secret is tagged too, as the same value's tag.
        let staged = parse(
            "@@changes\nwireless.default_radio0.key='correct horse battery'\n-wireless.guest.key\nnetwork.lan.ipaddr='192.0.2.2'\n",
            &s,
        );
        assert_eq!(
            staged.staged,
            [
                format!("wireless.default_radio0.key='{key}'"),
                "-wireless.guest.key".to_string(),
                "network.lan.ipaddr='192.0.2.2'".to_string(),
            ]
        );
    }

    #[test]
    fn the_firewall_as_zones_forwards_and_openings() {
        let u = uci();
        let z = u.zones();
        let said: Vec<(String, String, String, String)> = z
            .iter()
            .map(|z| {
                (
                    z.name.clone(),
                    z.networks.join(" "),
                    z.input.clone(),
                    z.forward.clone(),
                )
            })
            .collect();
        let row = |a: &str, b: &str, c: &str, d: &str| {
            (a.to_string(), b.to_string(), c.to_string(), d.to_string())
        };
        assert_eq!(
            said,
            [
                row("lan", "lan", "ACCEPT", "ACCEPT"),
                row("wan", "wan wan6", "REJECT", "DROP"),
                row("dmz", "dmz", "REJECT", "REJECT"),
            ]
        );
        let f = u.forwards();
        assert_eq!(f.len(), 3);
        assert_eq!(
            (
                f[0].name.as_str(),
                f[0].port.as_str(),
                f[0].dest_ip.as_str()
            ),
            ("web", "443", "203.0.113.93")
        );
        assert_eq!(f[0].protos, ["tcp"]);
        assert_eq!(f[0].dest_port.as_deref(), Some("443"));
        assert_eq!(
            (f[1].name.as_str(), f[1].port.as_str()),
            ("game", "8000-8010")
        );
        assert!(f[1].enabled && !f[2].enabled);
        // What the firewall lets in for the router itself; a rule with a dest is a forward.
        let o = u.openings();
        let names: Vec<&str> = o.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["Allow-DHCP-Renew", "Allow-Ping", "Allow-DMZ-DNS"]);
        assert!(o[0].covers("udp", 68) && !o[0].covers("tcp", 68) && !o[0].covers("udp", 67));
        assert!(o[2].covers("tcp", 53) && o[2].covers("udp", 53));
        assert!(!o[1].covers("tcp", 22));
        let any = Opening {
            name: "x".into(),
            src: "wan".into(),
            protos: vec![],
            ports: vec!["8000-8010".into()],
        };
        assert!(any.covers("tcp", 8005) && !any.covers("tcp", 8011));
    }

    #[test]
    fn ssh_the_web_interface_and_wifi() {
        let u = uci();
        let d = u.dropbear();
        assert_eq!(d.len(), 1);
        assert!(!d[0].password_auth && !d[0].root_password_auth);
        assert_eq!(
            (d[0].port.as_str(), d[0].interface.as_deref()),
            ("22", Some("lan"))
        );
        // Nothing said: password logins are on, as dropbear has it.
        let bare = parse(
            "@@dropbear\ndropbear.main=dropbear\ndropbear.off=dropbear\ndropbear.off.enable='0'\n",
            &salt(),
        );
        let d = bare.dropbear();
        assert_eq!(d.len(), 1);
        assert!(d[0].password_auth && d[0].root_password_auth && d[0].interface.is_none());
        let h = u.uhttpd().unwrap();
        assert_eq!(h.listen_http, ["0.0.0.0:80", "[::]:80"]);
        assert_eq!(h.listen_https.len(), 2);
        assert!(h.redirect_https);
        assert_eq!(h.cert.as_deref(), Some("/etc/uhttpd.crt"));
        assert!(parse("", &salt()).uhttpd().is_none());
        let w = u.wifi();
        assert_eq!(w.len(), 3);
        assert_eq!(
            (w[0].ssid.as_str(), w[0].encryption.as_str(), w[0].key),
            ("Example Net", "sae-mixed", true)
        );
        assert!(w[1].key, "a sae_password is a passphrase too");
        assert!(w[2].disabled && !w[2].key && w[2].encryption == "none");
    }

    #[test]
    fn staged_lines_count_only_for_the_audited_configs() {
        // As a router with adblock-fast always has it: nothing of its own to report.
        let u = uci();
        assert_eq!(u.staged.len(), 2);
        assert!(u.staged_audited().is_empty(), "{:?}", u.staged_audited());
        let more = parse(
            "@@changes\nadblock-fast.cfg0a1b2c.size='1'\ndhcp.cfg01411c.serversfile='/var/run/x'\n\
             firewall.cfg10.name='new'\n-wireless.guest.disabled\nsystem.ntp.enabled='0'\ndhcp.lan.limit='200'\n",
            &salt(),
        );
        assert_eq!(
            more.staged_audited(),
            [
                "firewall.cfg10.name='new'",
                "-wireless.guest.disabled",
                "dhcp.lan.limit='200'"
            ]
        );
        // Without adblock-fast's own lines beside it, a staged serversfile is someone's edit.
        let lone = parse("@@changes\ndhcp.cfg01411c.serversfile='/tmp/x'\n", &salt());
        assert_eq!(lone.staged_audited().len(), 1);
    }
}

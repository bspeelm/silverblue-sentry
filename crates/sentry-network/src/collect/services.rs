//! Which services run: `ubus call service list`, every procd service at once (asking each
//! init script takes half a second). A service that isn't a daemon (the firewall, a blocker
//! that only writes dnsmasq's lists) has no instance, which isn't "down".

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::crowdsec::{self, Bouncer};
use super::{CollectError, output_needing};
use sentry_app::remote::Remote;

pub const SCRIPT: &str = "ubus call service list";

/// The services that are there without ever having an instance to run.
pub const NOT_DAEMONS: &[&str] = &[
    "firewall",
    "adblock-fast",
    "gpio_switch",
    "packet_steering",
    "system",
    "ucitrack",
    "ubihealthd",
    "urandom_seed",
    "boot",
    "done",
    "sysctl",
    "led",
];

/// The services the router's own running depends on: watched wherever they are installed.
pub const ESSENTIAL: &[&str] = &["dnsmasq", "dropbear", "uhttpd"];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub instances: u32,
    pub running: u32,
}

/// Every service procd knows, by name.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Services(pub BTreeMap<String, Service>);

/// How one service stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Running,
    /// It has no instance, and is one that never has.
    NotADaemon,
    Down,
    /// procd doesn't know it.
    Missing,
}

impl Services {
    pub fn state(&self, name: &str) -> State {
        match self.0.get(name) {
            None => State::Missing,
            Some(s) if s.running > 0 => State::Running,
            Some(s) if s.instances == 0 && NOT_DAEMONS.contains(&name) => State::NotADaemon,
            Some(_) => State::Down,
        }
    }

    /// The services to watch: the essential ones that are installed, and what the config
    /// names. In that order, once each.
    pub fn watched<'a>(&'a self, named: &'a [String]) -> Vec<&'a str> {
        let mut out: Vec<&str> = ESSENTIAL
            .iter()
            .copied()
            .filter(|n| self.0.contains_key(*n))
            .collect();
        for n in named {
            if !out.contains(&n.as_str()) {
                out.push(n);
            }
        }
        out
    }
}

/// The services, from the JSON before any `@@` part.
pub fn parse(text: &str) -> Result<Services, String> {
    let json = match text.find("\n@@") {
        Some(at) => &text[..at],
        None => text,
    };
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let obj = v.as_object().ok_or("not an object")?;
    Ok(Services(
        obj.iter()
            .map(|(name, s)| {
                let inst = s["instances"].as_object();
                (
                    name.clone(),
                    Service {
                        instances: inst.map_or(0, |i| i.len() as u32),
                        running: inst.map_or(0, |i| {
                            i.values().filter(|x| x["running"] == true).count() as u32
                        }),
                    },
                )
            })
            .collect(),
    ))
}

/// CrowdSec's firewall bouncer from the same answer: None where the router hasn't got it.
pub fn parse_bouncer(text: &str) -> Option<Bouncer> {
    super::sections(text)
        .into_iter()
        .find(|(name, _)| *name == "crowdsec")
        .map(|(_, part)| crowdsec::parse(part))
}

pub fn collect(r: &Remote) -> Result<Services, CollectError> {
    Ok(collect_with(r)?.0)
}

/// The services, and in the same exec the firewall bouncer where it is installed.
pub fn collect_with(r: &Remote) -> Result<(Services, Option<Bouncer>), CollectError> {
    let script = format!("{SCRIPT} || exit $?\n{}", crowdsec::script());
    let out = output_needing(r, "ubus", &script)?;
    Ok((
        parse(&out).map_err(CollectError::Parse)?,
        parse_bouncer(&out),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    #[test]
    fn running_instances_are_counted_and_no_instance_isnt_down_for_what_never_has_one() {
        let s = parse(&fixture("network/services.json")).unwrap();
        assert_eq!(
            s.0["dnsmasq"],
            Service {
                instances: 1,
                running: 1
            }
        );
        assert_eq!(
            s.0["https-dns-proxy"],
            Service {
                instances: 2,
                running: 1
            }
        );
        assert_eq!(s.state("dnsmasq"), State::Running);
        assert_eq!(s.state("https-dns-proxy"), State::Running);
        assert_eq!(s.state("firewall"), State::NotADaemon);
        assert_eq!(s.state("adblock-fast"), State::NotADaemon);
        // It ran once at boot and exited: that's what it does.
        assert_eq!(s.state("urandom_seed"), State::Down);
        // A daemon with nothing running is down; one procd never heard of is missing.
        assert_eq!(s.state("cron"), State::Down);
        assert_eq!(s.state("wireguard"), State::Missing);
        let named = ["odhcpd".to_string(), "dnsmasq".to_string()];
        assert_eq!(
            s.watched(&named),
            ["dnsmasq", "dropbear", "uhttpd", "odhcpd"]
        );
        assert!(parse("[]").is_err() && parse("not json").is_err());
    }

    #[test]
    fn the_bouncer_rides_the_same_answer_and_is_absent_without_its_part() {
        let json = fixture("network/services.json");
        assert_eq!(parse_bouncer(&json), None);
        let with = format!("{json}\n@@crowdsec\nenabled=1\nv4=1204\nv6=37\nage=262800\n");
        assert_eq!(parse(&with).unwrap(), parse(&json).unwrap());
        let b = parse_bouncer(&with).unwrap();
        assert_eq!(
            (b.blocked(), b.on(), b.age_s),
            (Some(1241), true, Some(262800))
        );
        // The package is there and nothing about it could be read: present, unread.
        assert_eq!(
            parse_bouncer(&format!("{json}\n@@crowdsec\n")),
            Some(Bouncer::default())
        );
    }
}

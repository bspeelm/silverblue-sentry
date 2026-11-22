//! Blocking a device: firewall rules by MAC that are sentry's own, and what sentry remembers
//! about them on this machine.
//!
//! On the router a block is one or two `rule` sections of the firewall config, named so
//! that only sentry's are ever touched: the section `sentry_block_<tag>` with
//! `name='sentry-block-<tag>'` (what the device sends on to other networks is refused), and
//! for a block from everything `sentry_block_<tag>_in` / `sentry-block-<tag>-in` (what it
//! sends to the router itself: DNS, DHCP, the admin page). `<tag>` is the salted tag of
//! the MAC that names the device's finding (`audit::client_id`), so a run's values and its
//! log entry never hold a MAC. A rule is sentry's only when section and name both match
//! and say the same tag; anything else, however alike it is named, is left alone.
//!
//! What can't be blocked this way, and the plan says so: traffic between two devices on
//! the same switch or Wi-Fi never passes the router's firewall, and connections already
//! open run on until they close.
//!
//! `networks/<name>/blocks.toml` (this machine) keeps who each tag is (the MAC, what it
//! was called, its zone), since when and why it is blocked, and when a pause ends. The
//! router has no timer of sentry's: a pause that ended is a row on Security, and Enter
//! there unblocks.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::collect::uci::{Section, Uci};

pub const FILE: &str = "blocks.toml";
/// A rule's `name` starts with this.
pub const PREFIX: &str = "sentry-block-";
/// A rule's section starts with this.
pub const SECTION: &str = "sentry_block_";

/// How far a block reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reach {
    /// It can't reach the internet; the home network still works for it.
    Internet,
    /// It can reach nothing through the router, the router itself included.
    Everything,
}

impl Reach {
    pub fn word(self) -> &'static str {
        match self {
            Reach::Internet => "internet",
            Reach::Everything => "everything",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "internet" => Some(Reach::Internet),
            "everything" => Some(Reach::Everything),
            _ => None,
        }
    }
    /// As a sentence's end: "blocked from …".
    pub fn says(self) -> &'static str {
        match self {
            Reach::Internet => "the internet",
            Reach::Everything => "everything, the router included",
        }
    }
}

/// A tag is eight hex digits (`redact::Salt::tag` without its prefix).
pub fn is_tag(s: &str) -> bool {
    s.len() == 8
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// The tag that names a device everywhere but on this screen (None: no salt, no tag).
pub fn tag(network: &str, mac: &str) -> Option<String> {
    let id = crate::audit::client_id(network, mac);
    let t = id.rsplit(':').next()?;
    is_tag(t).then(|| t.to_string())
}

fn word(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The uci lines that block the device: from the internet (what it sends on towards the
/// uplink's zone is refused), or from everything (what it sends on anywhere, and what it
/// sends to the router). Err: something that can't go into a rule.
pub fn block_lines(
    tag: &str,
    mac: &str,
    zone: &str,
    wan: &str,
    reach: Reach,
) -> Result<Vec<String>, String> {
    if !is_tag(tag) {
        return Err("no tag for this device (the network's salt couldn't be read)".into());
    }
    let mac = crate::config::mac(mac).ok_or("that isn't a MAC address")?;
    if !word(zone) || !word(wan) {
        return Err(format!("a zone's name isn't a plain word ({zone}, {wan})"));
    }
    let rule = |sec: &str, name: &str, dest: Option<&str>| {
        let mut l = vec![
            format!("uci set firewall.{sec}=rule"),
            format!("uci set firewall.{sec}.name='{name}'"),
            format!("uci set firewall.{sec}.src='{zone}'"),
            format!("uci set firewall.{sec}.src_mac='{mac}'"),
        ];
        if let Some(d) = dest {
            l.push(format!("uci set firewall.{sec}.dest='{d}'"));
        }
        l.push(format!("uci set firewall.{sec}.proto='all'"));
        l.push(format!("uci set firewall.{sec}.target='REJECT'"));
        l
    };
    let sec = format!("{SECTION}{tag}");
    let name = format!("{PREFIX}{tag}");
    Ok(match reach {
        Reach::Internet => rule(&sec, &name, Some(wan)),
        Reach::Everything => {
            let mut l = rule(&sec, &name, Some("*"));
            l.extend(rule(&format!("{sec}_in"), &format!("{name}-in"), None));
            l
        }
    })
}

/// A block as the router's firewall config has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub tag: String,
    pub mac: String,
    pub zone: String,
    pub reach: Reach,
    /// Its sections: one, or two for a block from everything.
    pub sections: Vec<String>,
}

/// The tag a section is sentry's rule for: `rule` it must be, its section and its name
/// must both be sentry's and name the same tag.
fn ours(s: &Section) -> Option<(String, bool)> {
    if s.kind != "rule" {
        return None;
    }
    let rest = s.name.strip_prefix(SECTION)?;
    let (tag, input) = match rest.strip_suffix("_in") {
        Some(t) => (t, true),
        None => (rest, false),
    };
    let want = format!("{PREFIX}{tag}{}", if input { "-in" } else { "" });
    (is_tag(tag) && s.one("name") == Some(want.as_str())).then(|| (tag.to_string(), input))
}

/// Sentry's blocks on the router, by tag.
pub fn found(uci: &Uci) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    for s in uci.config("firewall") {
        let Some((tag, input)) = ours(s) else {
            continue;
        };
        let everything = input || s.one("dest") == Some("*");
        match out.iter_mut().find(|f| f.tag == tag) {
            Some(f) => {
                f.sections.push(s.name.clone());
                if everything {
                    f.reach = Reach::Everything;
                }
            }
            None => out.push(Found {
                tag,
                mac: s.one("src_mac").unwrap_or_default().to_ascii_lowercase(),
                zone: s.one("src").unwrap_or_default().to_string(),
                reach: if everything {
                    Reach::Everything
                } else {
                    Reach::Internet
                },
                sections: vec![s.name.clone()],
            }),
        }
    }
    out
}

/// The uci lines that take a block away: exactly the sections that are sentry's for this
/// tag. Empty: the router has none.
pub fn unblock_lines(uci: &Uci, tag: &str) -> Vec<String> {
    found(uci)
        .into_iter()
        .filter(|f| f.tag == tag)
        .flat_map(|f| f.sections)
        .map(|s| format!("uci delete firewall.{s}"))
        .collect()
}

/// Who a tag is, as last seen when something was started for it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Dev {
    pub mac: String,
    pub label: String,
    pub zone: String,
    /// The access point it was on (`phy0-ap0`), on Wi-Fi.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wifi: Option<String>,
}

/// A block sentry was asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// Epoch seconds.
    pub since: i64,
    /// A pause: when it ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    pub reach: Reach,
    #[serde(default)]
    pub why: String,
}

/// A port forward sentry switched off (by its section): listed so it can be switched on
/// again from the same place.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Door {
    pub name: String,
    pub since: i64,
}

/// A device the family filter is on (`family.rs`), as this machine remembers it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Filtered {
    /// Epoch seconds.
    pub since: i64,
    /// The service (`family::Service::id`).
    pub service: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Blocks {
    pub device: BTreeMap<String, Dev>,
    pub block: BTreeMap<String, Note>,
    pub door: BTreeMap<String, Door>,
    /// The devices the family filter is on, by tag: what the router had when the last
    /// filter change was kept.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub filter: BTreeMap<String, Filtered>,
}

impl Blocks {
    pub fn path(scope: &str) -> PathBuf {
        sentry_core::maint::root(scope).join(FILE)
    }

    pub fn load(scope: &str) -> Self {
        std::fs::read_to_string(Self::path(scope))
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, scope: &str) -> std::io::Result<()> {
        sentry_core::paths::write_atomic(
            &Self::path(scope),
            toml::to_string(self).unwrap_or_default().as_bytes(),
        )
    }

    /// A pause that has ended (the rule may still be on the router).
    pub fn ended(&self, tag: &str, now: i64) -> bool {
        self.block
            .get(tag)
            .and_then(|n| n.until)
            .is_some_and(|u| u <= now)
    }
}

/// One row of "Blocked by you".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shut {
    Device {
        tag: String,
        /// What it was called when it was blocked; else its MAC.
        label: String,
        reach: Reach,
        since: Option<i64>,
        until: Option<i64>,
        why: String,
    },
    /// A port forward switched off from here.
    Door {
        section: String,
        name: String,
        since: i64,
    },
}

impl Shut {
    pub fn key(&self) -> String {
        match self {
            Shut::Device { tag, .. } => format!("block:{tag}"),
            Shut::Door { section, .. } => format!("door:{section}"),
        }
    }
}

/// What is shut now: sentry's rules as the router has them, each with what this machine
/// remembers of it, then the forwards switched off from here that are still off.
pub fn shut(uci: &Uci, b: &Blocks) -> Vec<Shut> {
    let mut out: Vec<Shut> = found(uci)
        .into_iter()
        .map(|f| {
            let note = b.block.get(&f.tag);
            Shut::Device {
                label: b
                    .device
                    .get(&f.tag)
                    .map(|d| d.label.clone())
                    .filter(|l| !l.is_empty())
                    .unwrap_or(f.mac),
                reach: f.reach,
                since: note.map(|n| n.since),
                until: note.and_then(|n| n.until),
                why: note.map(|n| n.why.clone()).unwrap_or_default(),
                tag: f.tag,
            }
        })
        .collect();
    for r in uci.forwards().into_iter().filter(|r| !r.enabled) {
        if let Some(d) = b.door.get(&r.section) {
            out.push(Shut::Door {
                section: r.section,
                name: r.name,
                since: d.since,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::Salt;

    pub(crate) fn uci_of(firewall: &str) -> Uci {
        crate::collect::uci::parse(&format!("@@firewall\n{firewall}"), &Salt::fixed([7; 16]))
    }

    const MAC: &str = "02:00:5e:00:53:21";

    #[test]
    fn a_block_is_one_rule_or_two_and_names_itself_sentrys() {
        let l = block_lines(
            "ab12cd34",
            "02-00-5E-00-53-21",
            "lan",
            "wan",
            Reach::Internet,
        )
        .unwrap();
        assert_eq!(
            l,
            [
                "uci set firewall.sentry_block_ab12cd34=rule",
                "uci set firewall.sentry_block_ab12cd34.name='sentry-block-ab12cd34'",
                "uci set firewall.sentry_block_ab12cd34.src='lan'",
                "uci set firewall.sentry_block_ab12cd34.src_mac='02:00:5e:00:53:21'",
                "uci set firewall.sentry_block_ab12cd34.dest='wan'",
                "uci set firewall.sentry_block_ab12cd34.proto='all'",
                "uci set firewall.sentry_block_ab12cd34.target='REJECT'",
            ]
        );
        let l = block_lines("ab12cd34", MAC, "lan", "wan", Reach::Everything).unwrap();
        assert_eq!(l.len(), 13);
        assert!(l.contains(&"uci set firewall.sentry_block_ab12cd34.dest='*'".to_string()));
        assert!(
            l.contains(
                &"uci set firewall.sentry_block_ab12cd34_in.name='sentry-block-ab12cd34-in'"
                    .to_string()
            )
        );
        // The rule towards the router has no dest: that is what makes it an input rule.
        assert!(!l.iter().any(|x| x.contains("_in.dest")));
        // Every line is one the guard stages.
        let c = crate::guard::Change::parse("firewall", &l.join("; "), "firewall", false);
        assert!(c.is_ok(), "{c:?}");
        // What can't be a rule.
        for (tag, mac, zone) in [
            ("unnamed", MAC, "lan"),
            ("AB12CD34", MAC, "lan"),
            ("ab12cd34", "nope", "lan"),
            ("ab12cd34", MAC, "l'an"),
            ("ab12cd34", MAC, ""),
        ] {
            assert!(
                block_lines(tag, mac, zone, "wan", Reach::Internet).is_err(),
                "{tag} {mac} {zone}"
            );
        }
        assert_eq!(tag("home", MAC).map(|t| t.len()), Some(8));
    }

    #[test]
    fn only_sentrys_own_rules_are_found_and_taken_away() {
        let u = uci_of(
            "firewall.sentry_block_ab12cd34=rule\n\
             firewall.sentry_block_ab12cd34.name='sentry-block-ab12cd34'\n\
             firewall.sentry_block_ab12cd34.src='lan'\n\
             firewall.sentry_block_ab12cd34.src_mac='02:00:5E:00:53:21'\n\
             firewall.sentry_block_ab12cd34.dest='*'\n\
             firewall.sentry_block_ab12cd34.target='REJECT'\n\
             firewall.sentry_block_ab12cd34_in=rule\n\
             firewall.sentry_block_ab12cd34_in.name='sentry-block-ab12cd34-in'\n\
             firewall.sentry_block_ab12cd34_in.src='lan'\n\
             firewall.sentry_block_ab12cd34_in.src_mac='02:00:5E:00:53:21'\n\
             firewall.sentry_block_ab12cd34_in.target='REJECT'\n\
             firewall.sentry_block_00000001=rule\n\
             firewall.sentry_block_00000001.name='sentry-block-00000001'\n\
             firewall.sentry_block_00000001.src='iot'\n\
             firewall.sentry_block_00000001.src_mac='02:00:5e:00:53:30'\n\
             firewall.sentry_block_00000001.dest='wan'\n\
             firewall.sentry_block_00000001.target='REJECT'\n\
             firewall.sentry_block_ab12cd35=rule\n\
             firewall.sentry_block_ab12cd35.name='my own rule'\n\
             firewall.sentry_block_ab12cd35.src_mac='02:00:5e:00:53:31'\n\
             firewall.@rule[0]=rule\n\
             firewall.@rule[0].name='sentry-block-ab12cd34'\n\
             firewall.@rule[0].src_mac='02:00:5e:00:53:32'\n\
             firewall.sentry_block_kids=rule\n\
             firewall.sentry_block_kids.name='sentry-block-kids'\n\
             firewall.sentry_block_ab12cd36=redirect\n\
             firewall.sentry_block_ab12cd36.name='sentry-block-ab12cd36'\n",
        );
        let f = found(&u);
        assert_eq!(f.len(), 2, "{f:?}");
        assert_eq!(
            (f[0].tag.as_str(), f[0].mac.as_str(), f[0].reach),
            ("ab12cd34", MAC, Reach::Everything)
        );
        assert_eq!(
            f[0].sections,
            ["sentry_block_ab12cd34", "sentry_block_ab12cd34_in"]
        );
        assert_eq!((f[1].zone.as_str(), f[1].reach), ("iot", Reach::Internet));
        assert_eq!(
            unblock_lines(&u, "ab12cd34"),
            [
                "uci delete firewall.sentry_block_ab12cd34",
                "uci delete firewall.sentry_block_ab12cd34_in"
            ]
        );
        // A rule of someone else's with a name like ours, or ours' name on another
        // section, a tag that isn't one, another kind of section: never touched.
        for foreign in ["ab12cd35", "kids", "ab12cd36", "ffffffff"] {
            assert!(unblock_lines(&u, foreign).is_empty(), "{foreign}");
        }
    }

    #[test]
    fn what_is_shut_is_the_routers_rules_with_what_is_remembered_here() {
        let u = uci_of(
            "firewall.sentry_block_ab12cd34=rule\n\
             firewall.sentry_block_ab12cd34.name='sentry-block-ab12cd34'\n\
             firewall.sentry_block_ab12cd34.src='lan'\n\
             firewall.sentry_block_ab12cd34.src_mac='02:00:5e:00:53:21'\n\
             firewall.sentry_block_ab12cd34.dest='wan'\n\
             firewall.sentry_block_00000001=rule\n\
             firewall.sentry_block_00000001.name='sentry-block-00000001'\n\
             firewall.sentry_block_00000001.src_mac='02:00:5e:00:53:30'\n\
             firewall.cam=redirect\n\
             firewall.cam.name='cam'\n\
             firewall.cam.src='wan'\n\
             firewall.cam.src_dport='8554'\n\
             firewall.cam.dest_ip='192.0.2.40'\n\
             firewall.cam.target='DNAT'\n\
             firewall.cam.enabled='0'\n\
             firewall.old=redirect\n\
             firewall.old.name='old'\n\
             firewall.old.src='wan'\n\
             firewall.old.src_dport='99'\n\
             firewall.old.dest_ip='192.0.2.41'\n\
             firewall.old.target='DNAT'\n\
             firewall.old.enabled='0'\n",
        );
        let mut b = Blocks::default();
        b.device.insert(
            "ab12cd34".into(),
            Dev {
                mac: MAC.into(),
                label: "tablet".into(),
                zone: "lan".into(),
                wifi: None,
            },
        );
        b.block.insert(
            "ab12cd34".into(),
            Note {
                since: 1000,
                until: Some(4600),
                reach: Reach::Internet,
                why: "paused for an hour".into(),
            },
        );
        // A note with no rule on the router is nothing shut.
        b.block.insert(
            "99999999".into(),
            Note {
                since: 1,
                until: None,
                reach: Reach::Internet,
                why: String::new(),
            },
        );
        b.door.insert(
            "cam".into(),
            Door {
                name: "cam".into(),
                since: 2000,
            },
        );
        let s = shut(&u, &b);
        assert_eq!(s.len(), 3, "{s:?}");
        assert!(
            matches!(&s[0], Shut::Device { label, until: Some(4600), .. } if label == "tablet")
        );
        // A rule nothing here remembers: by its MAC, no dates.
        assert!(
            matches!(&s[1], Shut::Device { label, since: None, .. } if label == "02:00:5e:00:53:30")
        );
        // Only the forward switched off from here; one off for another reason isn't listed.
        assert!(matches!(&s[2], Shut::Door { section, .. } if section == "cam"));
        assert_eq!(s[0].key(), "block:ab12cd34");
        assert!(!b.ended("ab12cd34", 4599) && b.ended("ab12cd34", 4600));
        assert!(!b.ended("99999999", i64::MAX));
        // The file, and back.
        let text = toml::to_string(&b).unwrap();
        assert_eq!(toml::from_str::<Blocks>(&text).unwrap(), b);
    }
}

//! The names you gave devices on the Security screen: `networks/<name>/names.toml`, sentry's
//! own file beside the baseline. `network_config.yaml` is yours and sentry never writes it,
//! so a name given in the window lands here and is merged with the config's `devices`
//! wherever clients are shown or judged (`Router::new`): a device named here is known, by
//! that name, exactly as one the config names.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::Device;

pub const FILE: &str = "names.toml";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Named {
    pub name: String,
    /// When it was named (epoch seconds).
    #[serde(default)]
    pub since: i64,
}

/// By MAC, as sentry compares them (`config::mac`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Names {
    pub device: BTreeMap<String, Named>,
}

/// A name as it may be given: trimmed, one line, at most 40 characters.
pub fn name(text: &str) -> Result<String, String> {
    let n = text.trim();
    if n.is_empty() {
        return Err("no name given".into());
    }
    if n.chars().count() > 40 {
        return Err("a name is at most 40 characters".into());
    }
    if n.chars().any(char::is_control) {
        return Err("a name is one line of plain text".into());
    }
    Ok(n.to_string())
}

impl Names {
    pub fn path(scope: &str) -> PathBuf {
        sentry_core::maint::root(scope).join(FILE)
    }

    /// The file as it is; missing or unreadable: no names.
    pub fn load(scope: &str) -> Self {
        std::fs::read_to_string(Self::path(scope))
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, scope: &str) -> std::io::Result<()> {
        let p = Self::path(scope);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        sentry_core::paths::write_atomic(&p, toml::to_string(self).unwrap_or_default().as_bytes())
    }

    /// Name the device with this MAC (again: the new name replaces the old).
    pub fn set(&mut self, mac: &str, text: &str, now: i64) -> Result<String, String> {
        let mac = crate::config::mac(mac).ok_or("that isn't a MAC address")?;
        let n = name(text)?;
        self.device.insert(
            mac,
            Named {
                name: n.clone(),
                since: now,
            },
        );
        Ok(n)
    }

    /// Over the config's devices: an entry for the same MAC that has no name gets this
    /// one (the config's own name wins); a MAC the config doesn't list is added.
    pub fn merge(&self, devices: &mut Vec<Device>) {
        for (mac, n) in &self.device {
            let same = |d: &&mut Device| {
                d.mac.as_deref().and_then(crate::config::mac).as_deref() == Some(mac.as_str())
            };
            match devices.iter_mut().find(same) {
                Some(d) => {
                    if d.name.is_none() {
                        d.name = Some(n.name.clone());
                    }
                }
                None => devices.push(Device {
                    name: Some(n.name.clone()),
                    mac: Some(mac.clone()),
                    ..Default::default()
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_given_here_is_a_device_the_config_knows() {
        let mut n = Names::default();
        assert_eq!(
            n.set("02-00-5E-00-53-21", "  the TV ", 100).as_deref(),
            Ok("the TV")
        );
        assert!(n.set("nonsense", "x", 0).is_err());
        assert!(n.set("02:00:5e:00:53:21", "  ", 0).is_err());
        assert!(n.set("02:00:5e:00:53:21", &"x".repeat(41), 0).is_err());
        assert!(n.set("02:00:5e:00:53:21", "a\nb", 0).is_err());
        // The file's shape, and back.
        let text = toml::to_string(&n).unwrap();
        assert_eq!(
            text,
            "[device.\"02:00:5e:00:53:21\"]\nname = \"the TV\"\nsince = 100\n"
        );
        assert_eq!(toml::from_str::<Names>(&text).unwrap(), n);
        // Merged: a new device; an unnamed entry of the config's gets the name; a name
        // the config gives stays.
        n.set("02:00:5e:00:53:22", "lamp", 0).unwrap();
        n.set("02:00:5e:00:53:23", "not this", 0).unwrap();
        let mut devices = vec![
            Device {
                mac: Some("02:00:5E:00:53:22".into()),
                ..Default::default()
            },
            Device {
                name: Some("printer".into()),
                mac: Some("02:00:5e:00:53:23".into()),
                leave_alone: true,
                ..Default::default()
            },
        ];
        n.merge(&mut devices);
        let said: Vec<(&str, &str)> = devices
            .iter()
            .map(|d| (d.name.as_deref().unwrap(), d.mac.as_deref().unwrap()))
            .collect();
        assert_eq!(
            said,
            [
                ("lamp", "02:00:5E:00:53:22"),
                ("printer", "02:00:5e:00:53:23"),
                ("the TV", "02:00:5e:00:53:21"),
            ]
        );
        assert!(devices[1].leave_alone);
    }
}

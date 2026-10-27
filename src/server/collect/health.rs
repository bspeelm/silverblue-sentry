//! Hardware and intrusion health: SMART (`smartctl -j -n standby`, so sleeping disks stay
//! asleep), CPU temperature (`sensors -j`) and fail2ban jails.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::remote::{Remote, SrvError};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmartHealth {
    Passed,
    Failed,
    /// In standby: not woken to be asked.
    Asleep,
    /// smartctl couldn't say (USB bridges without SAT, permissions, …).
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Smart {
    pub dev: String,
    pub health: SmartHealth,
    pub model: Option<String>,
    pub temp_c: Option<i64>,
    pub power_on_hours: Option<u64>,
    /// Sectors remapped, pending, or unreadable (ATA 5/197/198), or NVMe media errors.
    pub bad_sectors: u64,
    /// ATA 187: errors the drive couldn't correct.
    pub uncorrectable: u64,
}

pub fn parse_smart(dev: &str, json: &str) -> Smart {
    let mut s = Smart {
        dev: dev.to_string(),
        health: SmartHealth::Unknown("no output".into()),
        model: None,
        temp_c: None,
        power_on_hours: None,
        bad_sectors: 0,
        uncorrectable: 0,
    };
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return s;
    };
    let messages: Vec<&str> = v["smartctl"]["messages"]
        .as_array()
        .map(|a| a.iter().filter_map(|m| m["string"].as_str()).collect())
        .unwrap_or_default();
    s.model = v["model_name"].as_str().map(str::to_string);
    s.health = match v["smart_status"]["passed"].as_bool() {
        Some(true) => SmartHealth::Passed,
        Some(false) => SmartHealth::Failed,
        None if messages
            .iter()
            .any(|m| m.contains("SLEEP") || m.contains("STANDBY")) =>
        {
            SmartHealth::Asleep
        }
        None => SmartHealth::Unknown(
            messages
                .first()
                .map_or("no SMART status".to_string(), |m| m.to_string()),
        ),
    };
    s.temp_c = v["temperature"]["current"].as_i64();
    s.power_on_hours = v["power_on_time"]["hours"].as_u64();
    if let Some(table) = v["ata_smart_attributes"]["table"].as_array() {
        for a in table {
            let raw = a["raw"]["value"].as_u64().unwrap_or(0);
            match a["id"].as_u64() {
                Some(5 | 197 | 198) => s.bad_sectors += raw,
                Some(187) => s.uncorrectable += raw,
                _ => {}
            }
        }
    }
    if let Some(n) = v["nvme_smart_health_information_log"]["media_errors"].as_u64() {
        s.bad_sectors += n;
    }
    s
}

pub fn smart(r: &Remote, dev: &str) -> Result<Smart, SrvError> {
    let c = r.privileged(&["smartctl", "-j", "-n", "standby", "-H", "-A", "-i", dev])?;
    // smartctl's exit code is a bit mask (2 = asleep, 4 = some command failed, …): the JSON
    // says what happened either way.
    let o = c.run()?;
    if o.stdout.trim().is_empty() {
        if crate::server::remote::password_refused(&o.stderr) {
            return Err(SrvError::SudoPassword("smartctl".into()));
        }
        return Err(SrvError::Failed(o.stderr.trim().to_string()));
    }
    Ok(parse_smart(dev, &o.stdout))
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CpuTemp {
    pub c: f32,
    pub crit: Option<f32>,
}

/// The CPU package temperature from `sensors -j`: Intel `coretemp` "Package id 0", AMD
/// `k10temp` "Tctl"; otherwise the hottest reading on those chips.
pub fn parse_sensors(json: &str) -> Option<CpuTemp> {
    let v: Value = serde_json::from_str(json).ok()?;
    let chips = v.as_object()?;
    let mut best: Option<CpuTemp> = None;
    for (chip, feats) in chips {
        if !["coretemp", "k10temp", "zenpower"]
            .iter()
            .any(|p| chip.starts_with(p))
        {
            continue;
        }
        for (feat, vals) in feats.as_object()? {
            let Some(vals) = vals.as_object() else {
                continue;
            };
            let get = |suffix: &str| {
                vals.iter()
                    .find(|(k, _)| k.ends_with(suffix))
                    .and_then(|(_, v)| v.as_f64())
                    .map(|f| f as f32)
            };
            let Some(c) = get("_input") else { continue };
            let t = CpuTemp {
                c,
                crit: get("_crit"),
            };
            if feat.starts_with("Package") || feat == "Tctl" || feat == "Tdie" {
                return Some(t);
            }
            if best.is_none_or(|b| t.c > b.c) {
                best = Some(t);
            }
        }
    }
    best
}

pub fn cpu_temp(r: &Remote) -> Result<Option<CpuTemp>, SrvError> {
    Ok(parse_sensors(&r.output(&r.cmd("sensors").arg("-j"))?))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Jail {
    pub name: String,
    pub banned: u32,
    pub total_banned: u32,
    pub failed: u32,
}

/// `fail2ban-client status`: `` `- Jail list: a, b ``
pub fn parse_jail_list(text: &str) -> Vec<String> {
    text.lines()
        .find_map(|l| l.split_once("Jail list:"))
        .map(|(_, list)| {
            list.split(',')
                .map(|j| j.trim().to_string())
                .filter(|j| !j.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// `fail2ban-client status <jail>`
pub fn parse_jail(name: &str, text: &str) -> Jail {
    let num = |key: &str| {
        text.lines()
            .find_map(|l| l.split_once(key))
            .and_then(|(_, v)| v.trim().parse().ok())
            .unwrap_or(0)
    };
    Jail {
        name: name.to_string(),
        banned: num("Currently banned:"),
        total_banned: num("Total banned:"),
        failed: num("Currently failed:"),
    }
}

pub fn fail2ban(r: &Remote) -> Result<Vec<Jail>, SrvError> {
    let list = parse_jail_list(&r.output(&r.privileged(&["fail2ban-client", "status"])?)?);
    list.iter()
        .map(|j| {
            let t = r.output(&r.privileged(&["fail2ban-client", "status", j])?)?;
            Ok(parse_jail(j, &t))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::fixture;
    use super::*;

    #[test]
    fn smart_passed_failing_and_asleep() {
        let ok = parse_smart("/dev/sda", &fixture("smart-ok.json"));
        assert_eq!(ok.health, SmartHealth::Passed);
        assert_eq!(
            (ok.temp_c, ok.power_on_hours, ok.bad_sectors),
            (Some(31), Some(12873), 0)
        );
        let bad = parse_smart("/dev/sdb", &fixture("smart-bad.json"));
        assert_eq!(bad.health, SmartHealth::Passed, "SMART says passed …");
        assert_eq!(
            (bad.bad_sectors, bad.uncorrectable),
            (16, 2),
            "… but sectors are going"
        );
        let zz = parse_smart("/dev/sdc", &fixture("smart-asleep.json"));
        assert_eq!(zz.health, SmartHealth::Asleep);
        assert!(matches!(
            parse_smart("/dev/x", "").health,
            SmartHealth::Unknown(_)
        ));
    }

    #[test]
    fn cpu_package_temperature() {
        let t = parse_sensors(&fixture("sensors.json")).unwrap();
        assert_eq!((t.c, t.crit), (41.0, Some(100.0)));
        assert_eq!(parse_sensors("{}"), None);
    }

    #[test]
    fn fail2ban_jails() {
        let f = fixture("fail2ban.txt");
        let (list, jail) = f.split_once("---\n").unwrap();
        assert_eq!(parse_jail_list(list), ["sshd", "web-auth"]);
        assert_eq!(
            parse_jail("sshd", jail),
            Jail {
                name: "sshd".into(),
                banned: 2,
                total_banned: 7,
                failed: 1
            }
        );
    }
}

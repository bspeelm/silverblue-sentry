//! systemd on the server: every service and timer (`list-units`), plus the details of the
//! units the config watches (`systemctl show`, run with `TZ=UTC` so times parse).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::super::remote::{Remote, SrvError};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRow {
    pub unit: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    #[serde(default)]
    pub description: String,
}

/// One unit's `systemctl show` block.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UnitState {
    pub id: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    /// `success`, `exit-code`, `timeout`, …
    pub result: String,
    pub exit: Option<i32>,
    /// Timers: when it last fired, when it fires next, and the unit it starts.
    pub last_trigger: Option<Timestamp>,
    pub next: Option<Timestamp>,
    pub triggers: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Units {
    pub all: Vec<UnitRow>,
    /// The services and timers from the config, and the services those timers start.
    pub watched: Vec<UnitState>,
}

impl Units {
    pub fn get(&self, id: &str) -> Option<&UnitState> {
        self.watched.iter().find(|u| u.id == id)
    }

    pub fn failed(&self) -> impl Iterator<Item = &UnitRow> {
        self.all.iter().filter(|u| u.active == "failed")
    }
}

const PROPS: &str = "Id,LoadState,ActiveState,SubState,Result,ExecMainStatus,LastTriggerUSec,NextElapseUSecRealtime,Unit";

/// `systemctl list-timers --output=json`: (unit, next run).
pub fn parse_timer_next(json: &str) -> Vec<(String, Timestamp)> {
    let v: Vec<serde_json::Value> = serde_json::from_str(json).unwrap_or_default();
    v.iter()
        .filter_map(|t| {
            let us = t["next"].as_i64().filter(|n| *n > 0)?;
            Some((
                t["unit"].as_str()?.to_string(),
                Timestamp::from_microsecond(us).ok()?,
            ))
        })
        .collect()
}

pub fn parse_list(json: &str) -> Result<Vec<UnitRow>, String> {
    serde_json::from_str(json).map_err(|e| e.to_string())
}

/// `systemctl show` blocks; times look like `Mon 2026-10-26 08:00:00 UTC`.
pub fn parse_show(text: &str) -> Vec<UnitState> {
    text.split("\n\n")
        .filter(|b| !b.trim().is_empty())
        .map(|block| {
            let mut u = UnitState::default();
            for line in block.lines() {
                let Some((k, v)) = line.split_once('=') else {
                    continue;
                };
                match k {
                    "Id" => u.id = v.to_string(),
                    "LoadState" => u.load = v.to_string(),
                    "ActiveState" => u.active = v.to_string(),
                    "SubState" => u.sub = v.to_string(),
                    "Result" => u.result = v.to_string(),
                    "ExecMainStatus" => u.exit = v.parse().ok(),
                    "LastTriggerUSec" => u.last_trigger = utc(v),
                    "NextElapseUSecRealtime" => u.next = utc(v),
                    "Unit" if !v.is_empty() => u.triggers = Some(v.to_string()),
                    _ => {}
                }
            }
            u
        })
        .filter(|u| !u.id.is_empty())
        .collect()
}

fn utc(v: &str) -> Option<Timestamp> {
    // Drop the weekday and the zone name: `2026-10-26 08:00:00`.
    let mut w = v.split_whitespace();
    let (_, date, time) = (w.next()?, w.next()?, w.next()?);
    let dt: jiff::civil::DateTime = format!("{date}T{time}").parse().ok()?;
    dt.to_zoned(jiff::tz::TimeZone::UTC)
        .ok()
        .map(|z| z.timestamp())
}

fn show(r: &Remote, units: &[String]) -> Result<Vec<UnitState>, SrvError> {
    if units.is_empty() {
        return Ok(Vec::new());
    }
    let c = r
        .cmd("env")
        .args(["TZ=UTC", "systemctl", "show", "-p", PROPS, "--"])
        .args(units);
    Ok(parse_show(&r.output(&c)?))
}

pub fn collect(r: &Remote) -> Result<Units, SrvError> {
    let all = parse_list(&r.output(&r.cmd("systemctl").args([
        "list-units",
        "--type=service,timer",
        "--all",
        "--output=json",
        "--no-pager",
    ]))?)
    .map_err(SrvError::Parse)?;
    let named: Vec<String> = r
        .cfg
        .services
        .iter()
        .cloned()
        .chain(r.cfg.timers.iter().map(|t| t.unit.clone()))
        .collect();
    let mut watched = show(r, &named)?;
    // The service a timer starts carries the result of its last run.
    let started: Vec<String> = watched
        .iter()
        .filter_map(|u| u.triggers.clone())
        .filter(|s| !named.contains(s))
        .collect();
    watched.extend(show(r, &started)?);
    // Timers relative to their last run (OnUnitActiveSec) have no wall-clock NextElapse in
    // `show`; list-timers knows when they fire next.
    if watched
        .iter()
        .any(|u| u.id.ends_with(".timer") && u.next.is_none())
        && let Ok(j) = r.output(&r.cmd("systemctl").args([
            "list-timers",
            "--all",
            "--output=json",
            "--no-pager",
        ]))
    {
        for (unit, next) in parse_timer_next(&j) {
            if let Some(u) = watched
                .iter_mut()
                .find(|u| u.id == unit && u.next.is_none())
            {
                u.next = Some(next);
            }
        }
    }
    Ok(Units { all, watched })
}

#[cfg(test)]
mod tests {
    use super::super::fixture;
    use super::*;

    #[test]
    fn show_blocks_and_utc_times() {
        let u = parse_show(&fixture("show.txt"));
        assert_eq!(u.len(), 4);
        let t = &u[1];
        assert_eq!(
            (t.id.as_str(), t.active.as_str()),
            ("backup.timer", "active")
        );
        assert_eq!(t.triggers.as_deref(), Some("backup.service"));
        assert_eq!(t.last_trigger.unwrap().to_string(), "2026-10-26T08:00:00Z");
        assert_eq!(t.next.unwrap().to_string(), "2026-10-27T08:00:00Z");
        let s = &u[2];
        assert_eq!((s.result.as_str(), s.exit), ("exit-code", Some(1)));
        assert_eq!(s.triggers, None, "services have an empty Unit=");
        assert_eq!(u[3].load, "not-found");
    }

    #[test]
    fn timer_next_from_list_timers() {
        let n = parse_timer_next(&fixture("list-timers.json"));
        assert_eq!(n[0].0, "backup.timer");
        assert_eq!(n[0].1.as_second(), 1_793_086_400);
    }

    #[test]
    fn list_units() {
        let l = parse_list(&fixture("list-units.json")).unwrap();
        let units = Units {
            all: l,
            watched: vec![],
        };
        assert_eq!(
            units.failed().map(|u| u.unit.as_str()).collect::<Vec<_>>(),
            ["report.service"]
        );
    }
}

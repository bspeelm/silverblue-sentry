//! Enabled and failed systemd units (user + system, read-only) and XDG autostart entries.

use serde::{Deserialize, Serialize};

use super::{CResult, Ctx, fields};
use crate::exec::Cmd;
use crate::keyfile::KeyFile;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Units {
    pub user_enabled: Vec<String>,
    pub system_enabled: Vec<String>,
    pub failed: Vec<Failed>,
    pub autostart: Vec<Autostart>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Failed {
    pub scope: String,
    pub unit: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Autostart {
    pub file: String,
    pub exec: String,
    pub hidden: bool,
}

pub fn collect(ctx: &Ctx) -> CResult<Units> {
    let sc = |user: bool, args: &[&str]| {
        let c = Cmd::host("systemctl");
        let c = if user { c.arg("--user") } else { c };
        c.args(args.iter().copied())
            .args(["--no-legend", "--plain", "--no-pager"])
            .output()
    };
    let enabled = ["list-unit-files", "--state=enabled"];
    let mut failed = parse_failed(&sc(false, &["--failed"])?, "system");
    failed.extend(parse_failed(
        &sc(true, &["--failed"]).unwrap_or_default(),
        "user",
    ));
    Ok(Units {
        user_enabled: parse_unit_files(&sc(true, &enabled).unwrap_or_default()),
        system_enabled: parse_unit_files(&sc(false, &enabled)?),
        failed,
        autostart: autostart(&ctx.home.join(".config/autostart")),
    })
}

pub fn parse_unit_files(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| fields(l).first().map(|s| s.to_string()))
        .collect()
}

/// `systemctl --failed --plain`: `UNIT LOAD ACTIVE SUB DESCRIPTION...`
pub fn parse_failed(text: &str, scope: &str) -> Vec<Failed> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim_start_matches('●').trim();
            let f = fields(l);
            (f.len() >= 4).then(|| Failed {
                scope: scope.to_string(),
                unit: f[0].to_string(),
                description: f[4..].join(" "),
            })
        })
        .collect()
}

fn autostart(dir: &std::path::Path) -> Vec<Autostart> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<Autostart> = rd
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "desktop"))
        .filter_map(|e| {
            let kf = KeyFile::parse(&std::fs::read_to_string(e.path()).ok()?);
            Some(Autostart {
                file: e.file_name().to_string_lossy().into_owned(),
                exec: kf
                    .get("Desktop Entry", "Exec")
                    .unwrap_or_default()
                    .to_string(),
                hidden: kf.get("Desktop Entry", "Hidden") == Some("true")
                    || kf.get("Desktop Entry", "X-GNOME-Autostart-enabled") == Some("false"),
            })
        })
        .collect();
    v.sort_by(|a, b| a.file.cmp(&b.file));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::fixture;

    #[test]
    fn fixtures() {
        let f = parse_failed(&fixture("units/failed.txt"), "system");
        assert_eq!(f[0].unit, "systemd-remount-fs.service");
        assert!(f[0].description.starts_with("Remount"));
        let e = parse_unit_files(&fixture("units/system-enabled.txt"));
        assert!(e.contains(&"cups.path".to_string()));
        assert!(!parse_unit_files(&fixture("units/user-enabled.txt")).is_empty());
    }

    #[test]
    fn bullet_prefix() {
        let f = parse_failed("● foo.service loaded failed failed Foo thing\n", "user");
        assert_eq!(
            (f[0].unit.as_str(), f[0].description.as_str()),
            ("foo.service", "Foo thing")
        );
    }
}

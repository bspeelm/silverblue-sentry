//! `rpm-ostree status --json`: deployments, layering, and the daemon's own `cached-update`
//! (filled by `rpm-ostree upgrade --preview/--check`), which tells us about pending updates
//! without any network access.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::CResult;
use crate::exec::Cmd;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ostree {
    pub deployments: Vec<Deploy>,
    pub update: Option<Update>,
    pub kargs: Option<String>,
    pub booted_kernel: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Deploy {
    pub booted: bool,
    pub staged: bool,
    pub pinned: bool,
    pub origin: String,
    pub version: String,
    pub timestamp: i64,
    pub layered: Vec<String>,
    pub local: Vec<String>,
    pub removals: Vec<String>,
    pub sig_valid: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Update {
    pub version: Option<String>,
    pub timestamp: Option<i64>,
    pub upgraded: Vec<PkgChange>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub advisories: usize,
    pub kernel_changed: bool,
    /// New kernel version-release, e.g. `7.2.9-200.fc44`.
    pub new_kernel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PkgChange {
    pub name: String,
    pub old: String,
    pub new: String,
}

impl Ostree {
    pub fn booted(&self) -> Option<&Deploy> {
        self.deployments.iter().find(|d| d.booted)
    }

    /// The `kmod-nvidia-*` local packages on the booted deployment.
    pub fn kmods(&self) -> Vec<&str> {
        self.booted()
            .map(|d| {
                d.local
                    .iter()
                    .filter(|p| p.starts_with("kmod-nvidia-"))
                    .map(String::as_str)
                    .collect()
            })
            .unwrap_or_default()
    }

}

pub fn collect() -> CResult<Ostree> {
    let status = Cmd::host("rpm-ostree")
        .args(["status", "--json"])
        .output()?;
    let mut o = parse(&status)?;
    o.kargs = Cmd::host("rpm-ostree")
        .arg("kargs")
        .output()
        .ok()
        .map(|s| s.trim().to_string());
    o.booted_kernel = booted_kernel();
    Ok(o)
}

pub fn booted_kernel() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse(json: &str) -> anyhow::Result<Ostree> {
    let v: Value = serde_json::from_str(json)?;
    let deployments = v["deployments"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("rpm-ostree status: no deployments array"))?
        .iter()
        .map(|d| Deploy {
            booted: d["booted"].as_bool().unwrap_or(false),
            staged: d["staged"].as_bool().unwrap_or(false),
            pinned: d["pinned"].as_bool().unwrap_or(false),
            origin: d["origin"].as_str().unwrap_or_default().to_string(),
            version: d["version"].as_str().unwrap_or_default().to_string(),
            timestamp: d["timestamp"].as_i64().unwrap_or(0),
            layered: strs(&d["requested-packages"]),
            local: strs(&d["requested-local-packages"]),
            removals: strs(&d["requested-base-removals"]),
            // signatures is a list of positional arrays; element 0 is "valid".
            sig_valid: d["signatures"]
                .get(0)
                .and_then(|s| s.get(0))
                .and_then(Value::as_bool),
        })
        .collect();
    Ok(Ostree {
        deployments,
        update: parse_update(&v["cached-update"]),
        ..Default::default()
    })
}

fn evr(v: &Value) -> String {
    // [evr, arch]
    v.get(0)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn parse_update(cu: &Value) -> Option<Update> {
    if cu.is_null() {
        return None;
    }
    let diff = &cu["rpm-diff"];
    let list = |k: &str| diff[k].as_array().cloned().unwrap_or_default();
    let upgraded: Vec<PkgChange> = list("upgraded")
        .iter()
        .chain(list("downgraded").iter())
        .filter_map(|e| {
            Some(PkgChange {
                name: e.get(1)?.as_str()?.to_string(),
                old: evr(e.get(2)?),
                new: evr(e.get(3)?),
            })
        })
        .collect();
    let names = |k: &str| -> Vec<String> {
        list(k)
            .iter()
            .filter_map(|e| e.get(1).and_then(Value::as_str).map(String::from))
            .collect()
    };
    let kernel = upgraded
        .iter()
        .find(|p| matches!(p.name.as_str(), "kernel" | "kernel-core"));
    let added = names("added");
    Some(Update {
        version: cu["version"].as_str().map(String::from),
        timestamp: cu["timestamp"].as_i64(),
        kernel_changed: kernel.is_some() || added.iter().any(|n| n == "kernel-core"),
        new_kernel: kernel.map(|k| {
            k.new
                .split_once(':')
                .map_or(k.new.as_str(), |(_, v)| v)
                .to_string()
        }),
        upgraded,
        added,
        removed: names("removed"),
        advisories: cu["advisories"].as_array().map_or(0, Vec::len),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::fixture;

    #[test]
    fn parses_status_fixture() {
        let o = parse(&fixture("ostree/status.json")).unwrap();
        assert!(o.deployments.len() >= 2);
        let b = o.booted().unwrap();
        assert!(b.origin.contains("silverblue"));
        assert_eq!(b.sig_valid, Some(true));
        assert!(b.layered.iter().any(|p| p == "akmods"));
        assert_eq!(o.kmods().len(), 1, "{:?}", b.local);
        assert!(o.deployments.iter().any(|d| d.pinned));
        let u = o.update.unwrap();
        assert!(u.kernel_changed);
        assert!(u.new_kernel.unwrap().ends_with(".fc44"));
        assert!(u.upgraded.len() > 10);
    }

    #[test]
    fn no_cached_update_and_ambiguous_kmods() {
        let j = r#"{"deployments":[{"booted":true,"version":"44.1","requested-local-packages":
            ["kmod-nvidia-7.1.3-201.fc44.x86_64-3:610-1.fc44.x86_64","kmod-nvidia-7.1.4-200.fc44.x86_64-3:610-1.fc44.x86_64"]}],
            "cached-update":null}"#;
        let o = parse(j).unwrap();
        assert!(o.update.is_none());
        assert_eq!(o.kmods().len(), 2);
    }

    #[test]
    fn kernel_core_only_change() {
        let j = r#"{"deployments":[],"cached-update":{"version":"44.2","rpm-diff":{"upgraded":
            [[0,"kernel-core",["7.2.8-200.fc44","x86_64"],["7.2.9-200.fc44","x86_64"]]],"added":[],"removed":[],"downgraded":[]}}}"#;
        let u = parse(j).unwrap().update.unwrap();
        assert!(u.kernel_changed);
        assert_eq!(u.new_kernel.as_deref(), Some("7.2.9-200.fc44"));
    }
}

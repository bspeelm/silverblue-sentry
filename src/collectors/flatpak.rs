//! Flatpak apps, remotes, permissions (metadata keyfiles + overrides, read live) and the
//! GL.nvidia extension pair. `remote-ls --updates` is network-bound and cached by the caller.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{CResult, Ctx};
use crate::config::FlatpakCfg;
use crate::exec::Cmd;
use crate::keyfile::KeyFile;
use crate::paths;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Flatpak {
    pub apps: Vec<App>,
    pub remotes: Vec<Remote>,
    /// (`GL` | `GL32`, `615-71-09`) for every installed nvidia GL extension.
    pub gl_nvidia: Vec<(String, String)>,
    pub overrides: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub id: String,
    pub origin: String,
    pub version: String,
    pub installation: String,
    pub perms: Perms,
    pub flags: Vec<Flag>,
    pub overridden: bool,
    pub unverified_origin: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Perms {
    pub filesystems: Vec<String>,
    pub shared: Vec<String>,
    pub sockets: Vec<String>,
    pub devices: Vec<String>,
    pub talk: Vec<String>,
    pub own: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Flag {
    pub label: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Remote {
    pub name: String,
    pub url: String,
    pub options: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FpUpdate {
    pub id: String,
    pub origin: String,
    pub version: String,
}

pub fn collect(ctx: &Ctx) -> CResult<Flatpak> {
    let list = Cmd::host("flatpak")
        .args([
            "list",
            "--app",
            "--columns=application,origin,version,installation",
        ])
        .output()?;
    let runtimes = Cmd::host("flatpak")
        .args(["list", "--runtime", "--columns=application,version,branch"])
        .output()?;
    let remotes = Cmd::host("flatpak")
        .args(["remotes", "--columns=name,url,options"])
        .output()?;

    let sys_root = paths::host("/var/lib/flatpak");
    let user_root = ctx.home.join(".local/share/flatpak");
    let read = |p: PathBuf| std::fs::read_to_string(p).ok();

    let mut apps = Vec::new();
    for (id, origin, version, installation) in parse_list(&list) {
        let base = if installation == "user" {
            &user_root
        } else {
            &sys_root
        };
        let metadata =
            read(base.join("app").join(&id).join("current/active/metadata")).unwrap_or_default();
        let overrides: Vec<String> = [
            sys_root.join("overrides/global"),
            sys_root.join("overrides").join(&id),
            user_root.join("overrides/global"),
            user_root.join("overrides").join(&id),
        ]
        .into_iter()
        .filter_map(read)
        .collect();
        let perms = perms_from(
            &metadata,
            &overrides.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let unverified_origin = !ctx.cfg.flatpak.trusted_origins.contains(&origin);
        apps.push(App {
            flags: flags(&perms, &ctx.cfg.flatpak),
            overridden: !overrides.is_empty(),
            unverified_origin,
            perms,
            id,
            origin,
            version,
            installation,
        });
    }

    let overrides = [sys_root.join("overrides"), user_root.join("overrides")]
        .iter()
        .flat_map(|d| list_files(d))
        .collect();
    Ok(Flatpak {
        apps,
        remotes: parse_remotes(&remotes),
        gl_nvidia: parse_gl_nvidia(&runtimes),
        overrides,
    })
}

pub fn collect_updates() -> CResult<Vec<FpUpdate>> {
    let out = Cmd::host("flatpak")
        .args([
            "remote-ls",
            "--updates",
            "--columns=application,origin,version",
        ])
        .timeout(Some(std::time::Duration::from_secs(120)))
        .output()?;
    Ok(parse_updates(&out))
}

/// Refs `flatpak uninstall --unused` would remove, per installation. Flatpak has no dry-run, so
/// the prompt is answered `n`: the transaction table is printed and nothing changes.
pub fn collect_unused() -> CResult<Vec<String>> {
    let mut out = Vec::new();
    for inst in ["--system", "--user"] {
        let o = Cmd::host("sh")
            .args([
                "-c",
                &format!("printf 'n\\n' | flatpak uninstall --unused {inst}"),
            ])
            .timeout(Some(std::time::Duration::from_secs(60)))
            .run()?;
        out.extend(parse_unused(&o.stdout));
    }
    Ok(out)
}

/// Rows of the transaction table: ` 1.     org.gnome.Platform     47     r`.
pub fn parse_unused(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let n = f.first()?.strip_suffix('.')?;
            n.parse::<u32>().ok()?;
            Some(match f.get(2) {
                Some(branch) => format!("{}//{branch}", f.get(1)?),
                None => f.get(1)?.to_string(),
            })
        })
        .collect()
}

fn list_files(d: &Path) -> Vec<String> {
    std::fs::read_dir(d)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path().display().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn tsv(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split('\t').map(str::trim).collect())
}

pub fn parse_list(text: &str) -> Vec<(String, String, String, String)> {
    tsv(text)
        .filter_map(|f| {
            Some((
                f.first()?.to_string(),
                f.get(1).unwrap_or(&"").to_string(),
                f.get(2).unwrap_or(&"").to_string(),
                f.get(3).unwrap_or(&"system").to_string(),
            ))
        })
        .collect()
}

pub fn parse_remotes(text: &str) -> Vec<Remote> {
    tsv(text)
        .filter_map(|f| {
            Some(Remote {
                name: f.first()?.to_string(),
                url: f.get(1).unwrap_or(&"").to_string(),
                options: f.get(2).unwrap_or(&"").to_string(),
            })
        })
        .collect()
}

pub fn parse_updates(text: &str) -> Vec<FpUpdate> {
    tsv(text)
        .filter_map(|f| {
            Some(FpUpdate {
                id: f.first()?.to_string(),
                origin: f.get(1).unwrap_or(&"").to_string(),
                version: f.get(2).unwrap_or(&"").to_string(),
            })
        })
        .collect()
}

/// `org.freedesktop.Platform.GL32.nvidia-615-71-09` → (`GL32`, `615-71-09`).
pub fn parse_gl_nvidia(runtimes: &str) -> Vec<(String, String)> {
    tsv(runtimes)
        .filter_map(|f| {
            let rest = f.first()?.strip_prefix("org.freedesktop.Platform.")?;
            let (kind, ver) = rest.split_once(".nvidia-")?;
            matches!(kind, "GL" | "GL32").then(|| (kind.to_string(), ver.to_string()))
        })
        .collect()
}

/// Host driver `615.71.09` → GL extension suffix `615-71-09`.
pub fn gl_version_for_driver(driver: &str) -> String {
    driver.replace('.', "-")
}

/// Does the GL + GL32 pair exist for this driver version? (`(has_gl, has_gl32)`)
pub fn gl_pair_status(gl: &[(String, String)], driver: &str) -> (bool, bool) {
    let want = gl_version_for_driver(driver);
    let has = |k: &str| gl.iter().any(|(kind, v)| kind == k && *v == want);
    (has("GL"), has("GL32"))
}

fn base(entry: &str) -> &str {
    entry
        .trim_start_matches('!')
        .split(':')
        .next()
        .unwrap_or(entry)
}

fn apply_list(list: &mut Vec<String>, overrides: Vec<String>) {
    for o in overrides {
        list.retain(|e| base(e) != base(&o));
        if !o.starts_with('!') {
            list.push(o);
        }
    }
}

/// Effective permissions: app metadata, then each override file in order.
pub fn perms_from(metadata: &str, overrides: &[&str]) -> Perms {
    let mut p = Perms::default();
    for (i, text) in std::iter::once(&metadata)
        .chain(overrides.iter())
        .enumerate()
    {
        let kf = KeyFile::parse(text);
        for (key, list) in [
            ("filesystems", &mut p.filesystems),
            ("shared", &mut p.shared),
            ("sockets", &mut p.sockets),
            ("devices", &mut p.devices),
        ] {
            let vals = kf.list("Context", key);
            if i == 0 {
                *list = vals.into_iter().filter(|v| !v.starts_with('!')).collect();
            } else {
                apply_list(list, vals);
            }
        }
        if let Some(sec) = kf.section("Session Bus Policy") {
            for (name, policy) in sec {
                p.talk.retain(|n| n != name);
                p.own.retain(|n| n != name);
                match policy.as_str() {
                    "talk" => p.talk.push(name.clone()),
                    "own" => p.own.push(name.clone()),
                    _ => {}
                }
            }
        }
    }
    p
}

pub fn flags(p: &Perms, cfg: &FlatpakCfg) -> Vec<Flag> {
    let mut out = Vec::new();
    for fs in &p.filesystems {
        let b = base(fs);
        if cfg.flag_filesystems.iter().any(|f| f == b) {
            let severity = if b == "home" {
                Severity::Medium
            } else {
                Severity::High
            };
            out.push(Flag {
                label: b.to_string(),
                severity,
            });
        }
    }
    for name in p.talk.iter().chain(p.own.iter()) {
        if cfg.flag_talk_names.iter().any(|f| f == name) {
            out.push(Flag {
                label: format!("talk:{name}"),
                severity: Severity::High,
            });
        }
    }
    if p.devices.iter().any(|d| d == "all") {
        out.push(Flag {
            label: "devices=all".into(),
            severity: Severity::Medium,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unused_table() {
        let t = super::super::fixture("flatpak/uninstall-unused.txt");
        assert_eq!(
            parse_unused(&t),
            vec![
                "org.gnome.Platform//47",
                "org.freedesktop.Platform.GL.nvidia-570-153-02//1.4"
            ]
        );
        assert!(parse_unused("Nothing unused to uninstall\n").is_empty());
    }
    use crate::collectors::fixture;

    #[test]
    fn list_and_remotes_fixtures() {
        let l = parse_list(&fixture("flatpak/list.tsv"));
        assert!(
            l.iter()
                .any(|(id, o, _, inst)| id == "com.valvesoftware.Steam"
                    && o == "flathub"
                    && inst == "system")
        );
        let r = parse_remotes(&fixture("flatpak/remotes.tsv"));
        assert!(
            r.iter()
                .any(|r| r.name == "fedora" && r.options.contains("oci"))
        );
    }

    #[test]
    fn gl_nvidia_fixture() {
        let gl = parse_gl_nvidia(&fixture("flatpak/runtimes.tsv"));
        assert!(gl.contains(&("GL".into(), "615-71-09".into())));
        assert!(!gl.iter().any(|(k, _)| k.contains("VAAPI")));
        assert_eq!(gl_pair_status(&gl, "615.71.09"), (true, true));
        assert_eq!(gl_pair_status(&gl, "610.57.04"), (true, false));
    }

    #[test]
    fn steam_with_override() {
        let meta = fixture("flatpak/metadata/com.valvesoftware.Steam");
        let ov = fixture("flatpak/overrides/com.valvesoftware.Steam");
        let p = perms_from(&meta, &[&ov]);
        assert!(p.devices.contains(&"all".to_string()));
        assert!(
            p.filesystems.contains(&"/var/mnt/vault/games".to_string()),
            "override applied: {:?}",
            p.filesystems
        );
        let f = flags(&p, &FlatpakCfg::default());
        assert_eq!(
            f,
            vec![Flag {
                label: "devices=all".into(),
                severity: Severity::Medium
            }]
        );
    }

    #[test]
    fn negation_and_talk_flags() {
        let meta = "[Context]\nfilesystems=home;host-os:ro;\n[Session Bus Policy]\norg.freedesktop.Flatpak=talk\n";
        let ov = "[Context]\nfilesystems=!home;xdg-download;\n";
        let p = perms_from(meta, &[ov]);
        assert_eq!(p.filesystems, vec!["host-os:ro", "xdg-download"]);
        let labels: Vec<_> = flags(&p, &FlatpakCfg::default())
            .into_iter()
            .map(|f| f.label)
            .collect();
        assert_eq!(labels, vec!["host-os", "talk:org.freedesktop.Flatpak"]);
        let ov2 = "[Session Bus Policy]\norg.freedesktop.Flatpak=none\n";
        assert!(perms_from(meta, &[ov2]).talk.is_empty());
    }

    #[test]
    fn updates_tsv() {
        let u =
            parse_updates("org.mozilla.firefox\tflathub\t144.0.2\norg.gnome.Platform\tflathub\t\n");
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].version, "144.0.2");
    }
}

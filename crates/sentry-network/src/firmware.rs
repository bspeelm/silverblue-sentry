//! The router's firmware upgrade: what the `firmware-upgrade` workflow's steps run
//! (`sentry-network firmware <name> check|backup|plan|download|flash|wait|after|add-missing|forget`),
//! and the pure parsers and rules they are made of.
//!
//! The tool is `owut` (OpenWrt's upgrade tool, a ucode script at `/usr/bin/owut`). What it
//! does, read from its source (owut 2026.07.08, `cat /usr/bin/owut` on a 25.12 router) and
//! run on a real router (`check` and `download` only, the image deleted afterwards):
//! - `check`: downloads JSON from the Attended SysUpgrade server
//!   (https://sysupgrade.openwrt.org, or `attendedsysupgrade.server.url`) into
//!   `/tmp/owut-*`, reads and deletes each; asks `rpc-sys packagelist` and `apk query` on
//!   the router (reads). Prints the versions, the package changes (`--verbose`), the
//!   default-package analysis and the server's build failures, ends with one verdict line.
//!   Exit 0 unless the build would fail. Without `-V` it targets the newest release of the
//!   installed series (`collect_build_info`: "Any unspecified non-snapshot gets latest from
//!   same branch").
//! - `download`: the same checks, then a build request; the server builds an image with
//!   every package installed now, by name (`top_level`); the image goes to `-i` (default
//!   `/tmp/firmware.bin`), its expected sha256 to `<image stem>.sha256sums`, the server's
//!   answer to `<image stem>-manifest.json`; then `verify_image`: busybox `sha256sum -c`
//!   against the saved sum and `sysupgrade --test <image>`; a failed image is deleted.
//!   Seen on the real router: about 80 s (76 s of it the server building), a 15 MB image.
//! - `sysupgrade --test`: `validate_firmware_image` (fwtool writes `/tmp/sysupgrade.meta`,
//!   the platform's check reads the image's tar), no backup archive made, `exit 0` before
//!   anything is flashed (`/sbin/sysupgrade`, read on the router).
//! - `install` (what `flash` runs): `verify_image` again, then `sysupgrade <image>` through
//!   rpcd's `file exec`; sysupgrade hands the image to procd (`ubus call system
//!   sysupgrade`), which closes every session, writes the image keeping the config files
//!   (`sysupgrade -l`: /etc/config, the dropbear host keys, …) and restarts. `upgrade` is
//!   `download` + `install` in one; sentry runs the two apart, so what was shown is what is
//!   flashed.
//!
//! What only a real flash can show is in CLAUDE.md and on the flash step's box.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::remote::Router;

/// Where the image is downloaded to, on the router (tmpfs: its memory). Its sums and
/// manifest are owut's names beside it.
pub const IMAGE: &str = "/tmp/sentry-firmware.bin";
pub const SUMS: &str = "/tmp/sentry-firmware.sha256sums";
pub const MANIFEST: &str = "/tmp/sentry-firmware-manifest.json";
/// What `owut install` says while it flashes, on the router (gone with the restart).
pub const FLASH_LOG: &str = "/tmp/sentry-flash.log";

/// What the router must have free before anything is downloaded: memory, and room in
/// `/tmp`. Judgment, not owut's: images for routers are some 8 to 64 MiB (the real one's
/// was 15), and sysupgrade's second stage copies itself into a RAM disk.
pub const MIN_AVAILABLE: u64 = 128 << 20;
pub const MIN_TMP: u64 = 64 << 20;
/// What must stay free beside the downloaded image for the flash.
pub const HEADROOM: u64 = 64 << 20;

/// How long `wait` waits for the router to come back, from the moment the flash started.
/// OpenWrt's flash writes for 2 to 4 minutes and boots in about one; a router may take
/// longer to answer (a slow storage write, its uplink coming up). Fifteen minutes is three
/// times the usual, so a slow one isn't called lost; more would leave the user without a
/// word for too long. `SENTRY_FIRMWARE_WAIT=<seconds>` shortens it (tests).
pub const WAIT: Duration = Duration::from_secs(15 * 60);
/// A run picked up after the wait gave up looks for this long before saying so again.
pub const GRACE: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_secs(5);

// ---- owut's output ---------------------------------------------------------------

/// A version line: `Version-to     25.12.6 r33311-981c978eff (kernel 6.12.112)`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ver {
    pub version: String,
    pub rev: String,
    pub kernel: String,
}

/// What owut warned about (its `WARNING:` lines, and the counts it prints instead of one).
/// Every one of these stops the run before anything is downloaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warn {
    /// A package would go to an older version.
    Downgrades(usize),
    /// A package the router has isn't built for the new release.
    Missing(usize),
    /// A package of the new release's default set wouldn't be in the image.
    MissingDefaults(usize),
    /// The image the router runs was built with a first-boot script of its own, which the
    /// new one wouldn't have.
    CustomDefaults,
    /// A package installed here fails to build for the new release.
    BuildFailures(usize),
    /// owut couldn't check the upgrade server's certificate.
    Certificates,
    /// No version of this package is known for the new release.
    NoVersion(String),
    /// Anything else owut warned or erred about, as it said it.
    Other(String),
}

impl Warn {
    /// What it means, in plain words.
    pub fn said(&self) -> String {
        match self {
            Warn::Downgrades(n) => format!(
                "{n} package(s) would go back to an older version. owut only does that when \
                 forced, and sentry doesn't force it."
            ),
            Warn::Missing(n) => format!(
                "{n} package(s) the router has now aren't available for the new release, so \
                 the new firmware would be built without them."
            ),
            Warn::MissingDefaults(n) => format!(
                "{n} package(s) that every router of this kind normally has wouldn't be in the \
                 new firmware. Something may stop working after the upgrade."
            ),
            Warn::CustomDefaults => "The firmware the router runs was built with a first-boot \
                 settings script of its own; the new one wouldn't have it."
                .into(),
            Warn::BuildFailures(n) => format!(
                "{n} package(s) installed on the router don't build for the new release yet, \
                 so the new firmware can't be made with them. This usually clears up in a few \
                 days."
            ),
            Warn::Certificates => "The router couldn't check the upgrade server's \
                 certificate (its proof of who it is), so what it downloads can't be trusted."
                .into(),
            Warn::NoVersion(p) => format!(
                "No version of {p} is known for the new release: owut can't say what it would \
                 become."
            ),
            Warn::Other(t) => format!("owut said: {t}"),
        }
    }
}

/// `owut check --verbose`, read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Check {
    pub from: Option<Ver>,
    pub to: Option<Ver>,
    /// `<name> <old> <new>` of each package that changes.
    pub changes: Vec<(String, String, String)>,
    pub out_of_date: usize,
    pub missing: usize,
    pub downgrades: usize,
    pub default_missing: usize,
    pub default_modified: usize,
    /// Build failures that touch a package installed here, and those that don't.
    pub failures_here: usize,
    pub failures_elsewhere: usize,
    /// owut's own replacements: an old name and what replaces it (none: removed).
    pub replaced: Vec<(String, Option<String>)>,
    pub warnings: Vec<Warn>,
    /// owut's last word: "safe to proceed", "no changes", …
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Verdict {
    /// "It is safe to proceed with an upgrade".
    Safe,
    /// "There are no changes, upgrade not necessary".
    NoChanges,
    /// "Checks reveal package downgrades".
    Downgrades,
    /// "Checks reveal errors, do not upgrade".
    Errors,
    #[default]
    Unknown,
}

/// The short list of what owut prints that doesn't stop the run (anything else it
/// warns about does), each established from its source:
/// - "There are 0 missing and N modified default packages": a default package provided
///   by another (here `nftables` by `nftables-json`), listed under "Provided-by";
/// - "N package build failures don't affect this device": failures of packages not
///   installed here;
/// - its version banner, the server's address, the build's progress lines.
pub const HARMLESS: &[&str] = &[
    "modified default packages (provided by another package)",
    "build failures that don't affect this device",
];

fn ver(rest: &str) -> Ver {
    // `25.12.6 r33311-981c978eff (kernel 6.12.112)`
    let mut w = rest.split_whitespace();
    let version = w.next().unwrap_or("").to_string();
    let rev = w.next().unwrap_or("").to_string();
    let kernel = rest
        .split("(kernel ")
        .nth(1)
        .and_then(|k| k.split(')').next())
        .unwrap_or("")
        .to_string();
    Ver {
        version,
        rev,
        kernel,
    }
}

fn first_num(s: &str) -> Option<usize> {
    s.split_whitespace().find_map(|w| w.parse().ok())
}

/// `owut check --verbose` (stdout and stderr together: its `WARNING:`/`ERROR:` lines are
/// stderr). Colour codes, if any, are taken out first.
pub fn parse_check(text: &str) -> Check {
    let mut c = Check::default();
    #[derive(PartialEq)]
    enum In {
        Nothing,
        Changes,
        Replaced,
        Defaults,
    }
    let mut at = In::Nothing;
    let (mut listed_missing, mut listed_modified) = (0, 0);
    for raw in text.lines() {
        let line = strip_ansi(raw);
        let l = line.trim_end();
        let t = l.trim();
        if let Some(r) = l.strip_prefix("Version-from") {
            c.from = Some(ver(r.trim()));
            continue;
        }
        if let Some(r) = l.strip_prefix("Version-to") {
            c.to = Some(ver(r.trim()));
            continue;
        }
        if t.starts_with("Package version changes:") {
            at = In::Changes;
            continue;
        }
        if t.starts_with("Automatic package replacements/removals:") {
            at = In::Replaced;
            continue;
        }
        if t.starts_with("Default package analysis:") {
            at = In::Defaults;
            continue;
        }
        if t.is_empty() {
            at = In::Nothing;
            continue;
        }
        if let Some(w) = t
            .strip_prefix("WARNING:")
            .or_else(|| t.strip_prefix("ERROR:"))
        {
            let w = w.trim();
            let warn = if w.contains("missing default packages") {
                Warn::MissingDefaults(first_num(w).unwrap_or(1))
            } else if w.contains("package downgrades") {
                Warn::Downgrades(c.downgrades.max(1))
            } else if w.contains("custom uci-defaults script") {
                Warn::CustomDefaults
            } else if w.contains("SSL certificates") {
                Warn::Certificates
            } else if let Some(p) = w
                .strip_prefix("Package '")
                .and_then(|r| r.split_once("' has no available current version"))
            {
                Warn::NoVersion(p.0.to_string())
            } else if w.contains("Checks reveal errors") || w.contains("can't proceed") {
                // Its summary of what is already counted.
                continue;
            } else {
                Warn::Other(w.to_string())
            };
            if !c.warnings.contains(&warn) {
                c.warnings.push(warn);
            }
            continue;
        }
        if l.starts_with("  ") && at != In::Nothing {
            let w: Vec<&str> = t.split_whitespace().collect();
            match at {
                In::Changes if w.len() >= 3 => {
                    let new = if w[2] == "missing" {
                        "missing to-version".to_string()
                    } else {
                        w[2].to_string()
                    };
                    c.changes.push((w[0].into(), w[1].into(), new));
                }
                In::Replaced if w.len() >= 2 && w[0] != "Package" => {
                    let to = (w[1] != "removed").then(|| w[1].to_string());
                    c.replaced.push((w[0].into(), to));
                }
                // `--verbose` lists them instead of counting: a default provided by
                // another package, or missing.
                In::Defaults if w.len() == 2 && w[0] != "Default" => {
                    if w[1].contains("missing") {
                        listed_missing += 1;
                    } else {
                        listed_modified += 1;
                    }
                }
                _ => {}
            }
            continue;
        }
        if t.ends_with("packages are out-of-date") {
            c.out_of_date = first_num(t).unwrap_or(0);
        } else if t.contains("packages missing in target version") {
            c.missing = first_num(t).unwrap_or(0);
        } else if t.ends_with("packages were downgraded") {
            c.downgrades = first_num(t).unwrap_or(0);
        } else if let Some(r) = t.strip_prefix("There are ")
            && r.contains("missing and")
            && r.contains("modified default packages")
        {
            let n: Vec<usize> = r
                .split_whitespace()
                .filter_map(|w| w.parse().ok())
                .collect();
            c.default_missing = n.first().copied().unwrap_or(0);
            c.default_modified = n.get(1).copied().unwrap_or(0);
        } else if t.contains("package build failures affect this device") {
            // "2 of 12 package build failures affect this device:"
            c.failures_here = first_num(t).unwrap_or(0);
            let all = t
                .split(" of ")
                .nth(1)
                .and_then(first_num)
                .unwrap_or(c.failures_here);
            c.failures_elsewhere = all.saturating_sub(c.failures_here);
        } else if t.contains("package build failures don't affect this device") {
            c.failures_elsewhere = first_num(t).unwrap_or(0);
        } else if t.starts_with("It is safe to proceed with an upgrade") {
            c.verdict = Verdict::Safe;
        } else if t.starts_with("There are no changes") {
            c.verdict = Verdict::NoChanges;
        }
    }
    c.default_missing = c.default_missing.max(listed_missing);
    c.default_modified = c.default_modified.max(listed_modified);
    // The counts owut prints for the problems it doesn't warn about by name.
    if text.contains("Checks reveal package downgrades") && c.verdict == Verdict::Unknown {
        c.verdict = Verdict::Downgrades;
    }
    if text.contains("Checks reveal errors") {
        c.verdict = Verdict::Errors;
    }
    let mut add = |w: Warn| {
        if !c
            .warnings
            .iter()
            .any(|x| std::mem::discriminant(x) == std::mem::discriminant(&w))
        {
            c.warnings.push(w);
        }
    };
    if c.downgrades > 0 {
        add(Warn::Downgrades(c.downgrades));
    }
    if c.missing > 0 {
        add(Warn::Missing(c.missing));
    }
    if c.default_missing > 0 {
        add(Warn::MissingDefaults(c.default_missing));
    }
    if c.failures_here > 0 {
        add(Warn::BuildFailures(c.failures_here));
    }
    c
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(ch) = it.next() {
        if ch == '\u{1b}' {
            // ESC [ … letter
            if it.peek() == Some(&'[') {
                it.next();
                for c in it.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

/// Why the plan stops here (empty: it goes on to the download). `installed`: the version
/// `ubus call system board` says the router runs.
pub fn stops(c: &Check, code: i32, installed: &str) -> Vec<String> {
    let mut why: Vec<String> = c.warnings.iter().map(Warn::said).collect();
    let (Some(from), Some(to)) = (&c.from, &c.to) else {
        why.push("owut's answer didn't say which version the router would be upgraded to.".into());
        return why;
    };
    if from.version != installed {
        why.push(format!(
            "owut read the router as {} but it says it runs {installed}: nothing is upgraded \
             on a reading that doesn't agree.",
            from.version
        ));
    }
    match (
        crate::maint::eval::series(&from.version),
        crate::maint::eval::series(&to.version),
    ) {
        (Some(a), Some(b)) if a == b => {}
        (Some(a), Some(b)) => why.push(format!(
            "This would move the router from the {a} series to {b}: a new series changes \
             much more than a patch release (settings can be read differently, packages are \
             renamed), and sentry only does patch releases. Nothing was changed."
        )),
        _ => why.push(format!(
            "{} → {} isn't a move between two releases of one series (a development build?): \
             sentry only does patch releases.",
            from.version, to.version
        )),
    }
    if c.verdict == Verdict::NoChanges || to.version == from.version && c.changes.is_empty() {
        why.push(format!(
            "There is nothing newer for the router: it runs {}, the newest release of its series.",
            from.version
        ));
    }
    if code != 0 && why.is_empty() {
        why.push(format!("owut ended with exit {code} without saying why."));
    }
    if c.verdict == Verdict::Unknown && why.is_empty() {
        why.push("owut didn't say it is safe to go on.".into());
    }
    why
}

/// The plan in a few plain lines.
pub fn summary(c: &Check, world: &[String]) -> Vec<String> {
    let (from, to) = (
        c.from.clone().unwrap_or_default(),
        c.to.clone().unwrap_or_default(),
    );
    let mut out = vec![
        format!(
            "From {} to {} (a patch release of the same series), kernel {} → {}.",
            from.version, to.version, from.kernel, to.kernel
        ),
        format!(
            "{} package(s) change, each to a newer version; the new firmware is built with \
             every package installed now ({} by name), so your add-ons come along.",
            c.changes.len().max(c.out_of_date),
            world.len()
        ),
        "Your settings are kept: the flash keeps the configuration (sysupgrade's list of \
         files: the network, Wi-Fi, firewall, passwords and the router's ssh keys)."
            .into(),
    ];
    if c.default_modified > 0 {
        out.push(format!(
            "Noted, harmless: {} default package(s) are provided by another package here.",
            c.default_modified
        ));
    }
    if c.failures_elsewhere > 0 {
        out.push(format!(
            "Noted, harmless: {} package(s) fail to build for the new release, none of them \
             installed here.",
            c.failures_elsewhere
        ));
    }
    for (old, new) in &c.replaced {
        out.push(match new {
            Some(n) => format!("owut replaces {old} with {n} (the new release renamed it)."),
            None => format!("owut leaves {old} out (the new release has no such package)."),
        });
    }
    out
}

/// `owut download` said, read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Download {
    pub saved: Option<String>,
    pub bytes: Option<u64>,
    /// "Saved sha256 matches".
    pub sum_ok: bool,
    /// "Checks complete, image is valid."
    pub valid: bool,
    /// Its `ERROR:` lines.
    pub errors: Vec<String>,
    /// "Build succeeded in  76s total …" (seconds), or failed.
    pub build_s: Option<u64>,
    pub build_failed: bool,
}

pub fn parse_download(text: &str) -> Download {
    let mut d = Download::default();
    for raw in text.lines() {
        let line = strip_ansi(raw);
        let t = line.trim();
        if let Some(p) = t.strip_prefix("Image saved :") {
            d.saved = Some(p.trim().to_string());
        } else if let Some(r) = t.strip_prefix("Verifying   :") {
            // `/tmp/x.bin (15247680 bytes) against …`
            d.bytes = r
                .split('(')
                .nth(1)
                .and_then(|b| b.split_whitespace().next())
                .and_then(|n| n.parse().ok());
        } else if t == "Saved sha256 matches" {
            d.sum_ok = true;
        } else if t.starts_with("Checks complete, image is valid") {
            d.valid = true;
        } else if let Some(r) = t.strip_prefix("Build succeeded in") {
            d.build_s = r
                .split_whitespace()
                .next()
                .and_then(|n| n.trim_end_matches('s').parse().ok());
        } else if t.starts_with("Build failed") {
            d.build_failed = true;
        } else if let Some(e) = t.strip_prefix("ERROR:") {
            d.errors.push(e.trim().to_string());
        }
    }
    d
}

/// The server's answer, as owut keeps it (`<image stem>-manifest.json`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Manifest {
    pub version: String,
    pub version_code: String,
    /// The sysupgrade image it built: name, sha256, size.
    pub image: Option<(String, String, u64)>,
    pub packages: BTreeMap<String, String>,
}

pub fn parse_manifest(json: &str) -> Result<Manifest, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("the build's manifest isn't JSON: {e}"))?;
    let s = |p: &serde_json::Value| p.as_str().unwrap_or("").to_string();
    let image = v["images"].as_array().and_then(|imgs| {
        imgs.iter().find(|i| i["type"] == "sysupgrade").map(|i| {
            (
                s(&i["name"]),
                s(&i["sha256"]),
                i["size"].as_u64().unwrap_or(0),
            )
        })
    });
    let packages = v["manifest"]
        .as_object()
        .map(|m| m.iter().map(|(k, x)| (k.clone(), s(x))).collect())
        .unwrap_or_default();
    Ok(Manifest {
        version: if s(&v["version_number"]).is_empty() {
            s(&v["request"]["version"])
        } else {
            s(&v["version_number"])
        },
        version_code: s(&v["version_code"]),
        image,
        packages,
    })
}

/// sentry's own look at the image owut downloaded, before anything is flashed: the sum
/// the router computes now against the one the server published for it, its size, the
/// version, and every package asked for is in it. Empty: it is the image that was shown.
pub fn image_problems(
    m: &Manifest,
    to: &str,
    sum_now: &str,
    size_now: u64,
    world: &[String],
) -> Vec<String> {
    let mut why = Vec::new();
    match &m.image {
        None => why.push("The build's manifest names no sysupgrade image.".into()),
        Some((_, sum, size)) => {
            if sum.len() != 64 || !sum.eq_ignore_ascii_case(sum_now) {
                why.push(
                    "The image on the router isn't the one the upgrade server built: its \
                     checksum (a fingerprint of the file) differs from the server's."
                        .into(),
                );
            }
            if *size != size_now {
                why.push(format!(
                    "The image on the router is {size_now} bytes; the server built one of {size}."
                ));
            }
        }
    }
    if m.version != to {
        why.push(format!(
            "The image is of {} where {to} was planned.",
            if m.version.is_empty() {
                "an unnamed version"
            } else {
                &m.version
            }
        ));
    }
    let lacking: Vec<&String> = world
        .iter()
        .filter(|p| !NON_UPGRADABLE.contains(&p.as_str()) && !m.packages.contains_key(*p))
        .collect();
    if !lacking.is_empty() {
        why.push(format!(
            "The image doesn't have {} package(s) the router has now: {}.",
            lacking.len(),
            lacking
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    why
}

/// owut leaves these out of a build: the kernel and C library come with the image.
pub const NON_UPGRADABLE: &[&str] = &["kernel", "libgcc", "libc"];

// ---- the router's packages -------------------------------------------------------

/// `ubus call rpc-sys packagelist '{"all":false}'` (or `true`): the packages by the names
/// a build asks for (what owut itself reads: libraries without their ABI suffix,
/// `libubox`, not `libubox20260213` as `/etc/apk/world` has it), without what comes with
/// the image.
pub fn packagelist(json: &str) -> Result<BTreeSet<String>, String> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| format!("the router's package list isn't JSON: {e}"))?;
    let m = v["packages"]
        .as_object()
        .ok_or("the router's package list has no packages")?;
    Ok(m.keys()
        .filter(|n| !NON_UPGRADABLE.contains(&n.as_str()))
        .cloned()
        .collect())
}

pub const TOP_LEVEL: &str = "ubus call rpc-sys packagelist '{\"all\":false}'";
pub const ALL_INSTALLED: &str = "ubus call rpc-sys packagelist '{\"all\":true}'";

/// What was installed by name before the flash and isn't now (owut's own replacements
/// accounted for: the new name stands for the old, a removal isn't missed).
pub fn missing_after(
    before: &[String],
    now: &BTreeSet<String>,
    replaced: &[(String, Option<String>)],
) -> Vec<String> {
    before
        .iter()
        .filter(|p| !now.contains(*p))
        .filter(|p| match replaced.iter().find(|(old, _)| old == *p) {
            Some((_, None)) => false,
            Some((_, Some(new))) => !now.contains(new),
            None => true,
        })
        .cloned()
        .collect()
}

/// A package's name, as apk would take it: nothing that a shell or apk reads as more.
pub fn plain_name(n: &str) -> bool {
    !n.is_empty()
        && !n.starts_with('-')
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
}

// ---- memory ----------------------------------------------------------------------

/// Free memory and room in `/tmp`, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mem {
    pub available: u64,
    pub tmp_free: u64,
}

/// `/proc/meminfo`, then `@@df`, then `df -k /tmp` (POSIX columns).
pub fn parse_mem(text: &str) -> Option<Mem> {
    let (info, df) = text.split_once("@@df")?;
    let available = info.lines().find_map(|l| {
        let r = l.strip_prefix("MemAvailable:")?;
        r.split_whitespace().next()?.parse::<u64>().ok()
    })? * 1024;
    let tmp_free = df.lines().find_map(|l| {
        let w: Vec<&str> = l.split_whitespace().collect();
        (w.len() >= 6 && w[5] == "/tmp")
            .then(|| w[3].parse::<u64>().ok())
            .flatten()
    })? * 1024;
    Some(Mem {
        available,
        tmp_free,
    })
}

pub const MEM_SCRIPT: &str = "cat /proc/meminfo; echo @@df; df -k /tmp";

fn mib(b: u64) -> String {
    format!("{} MiB", b >> 20)
}

/// Before the download: room for an image of any likely size.
pub fn enough_before(m: &Mem) -> Result<(), String> {
    if m.available < MIN_AVAILABLE || m.tmp_free < MIN_TMP {
        return Err(format!(
            "The router has {} of memory free and {} free in its temporary storage; the \
             upgrade needs at least {} and {} (the new firmware is downloaded into memory, \
             and the flash runs from memory). Nothing was changed.",
            mib(m.available),
            mib(m.tmp_free),
            mib(MIN_AVAILABLE),
            mib(MIN_TMP)
        ));
    }
    Ok(())
}

/// After it: the image is in memory, and the flash still has room beside it.
pub fn enough_for(m: &Mem, image: u64) -> Result<(), String> {
    if m.available < image + HEADROOM {
        return Err(format!(
            "With the {} image in memory the router has {} left; the flash needs {} beside it.",
            mib(image),
            mib(m.available),
            mib(HEADROOM)
        ));
    }
    Ok(())
}

// ---- waiting for the router ------------------------------------------------------

/// What one look at the router found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    /// It answered with this boot id.
    Boot(String),
    /// No answer.
    Nothing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    /// A new boot: it restarted.
    Back,
    /// Not yet: look again.
    Waiting,
    /// The deadline passed.
    Over,
}

/// When the wait gives up: `total` after the flash started; once that has passed (a run
/// picked up again later), `GRACE` from now.
pub fn deadline(flashed: Timestamp, now: Timestamp, total: Duration) -> Timestamp {
    let a = flashed + total;
    if now >= a { now + GRACE } else { a }
}

/// One look, judged: back only on a boot id that isn't the one before the flash.
pub fn poll(seen: &Seen, before: &str, now: Timestamp, until: Timestamp) -> Poll {
    match seen {
        Seen::Boot(id) if !id.is_empty() && id != before => Poll::Back,
        _ if now >= until => Poll::Over,
        _ => Poll::Waiting,
    }
}

/// "4 min 10 s".
pub fn took(secs: i64) -> String {
    let s = secs.max(0);
    match (s / 60, s % 60) {
        (0, s) => format!("{s} s"),
        (m, 0) => format!("{m} min"),
        (m, s) => format!("{m} min {s} s"),
    }
}

/// The wait's last word when the router didn't come back: calm, and exact.
pub fn lost_words(st: &State, waited: i64) -> Vec<String> {
    let backed = match (&st.backup, &st.backed_up_at) {
        (Some(f), Some(at)) => {
            format!("Your settings were backed up at {at} ({f}), before anything was flashed.")
        }
        _ => "Your settings were backed up by this run's backup step, before anything was flashed."
            .into(),
    };
    vec![
        format!(
            "The router hasn't answered for {} since the flash started.",
            took(waited)
        ),
        format!(
            "What was running when contact was lost: {}.",
            if st.step.is_empty() {
                "the flash"
            } else {
                st.step.as_str()
            }
        ),
        backed,
        "Nothing more happens by itself. A router writing its firmware can take longer than \
         usual: if its light says it is still busy, leave its power on."
            .into(),
        "When it answers again, open this run (0): it carries on with the checks after the \
         restart."
            .into(),
        "If it never answers, it is brought back by the device's own recovery procedure \
         (its OpenWrt page describes it), and the backup puts your settings back."
            .into(),
    ]
}

// ---- the run's own record ---------------------------------------------------------

/// What the run knows across its steps (each is a process of its own), kept beside the
/// network's data on this machine: `networks/<name>/firmware.json`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub from: String,
    pub to: String,
    pub sha256: String,
    pub size: u64,
    /// The backup the run made, and when.
    pub backup: Option<String>,
    pub backed_up_at: Option<String>,
    /// The packages installed by name before the flash.
    pub world: Vec<String>,
    pub replaced: Vec<(String, Option<String>)>,
    pub boot_before: String,
    pub leases_before: usize,
    pub wan_up_before: bool,
    /// The watched services that ran before the flash (what was already down isn't the
    /// upgrade's to bring up).
    #[serde(default)]
    pub services_before: Vec<String>,
    /// When the flash started.
    pub flashed_at: Option<Timestamp>,
    /// What was running, in words (for the message when contact is lost).
    pub step: String,
    /// What `after` found missing.
    pub missing: Vec<String>,
}

pub fn state_path(scope: &str) -> std::path::PathBuf {
    sentry_core::maint::data_root(scope).join("firmware.json")
}

impl State {
    pub fn load(scope: &str) -> State {
        std::fs::read_to_string(state_path(scope))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, scope: &str) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let p = state_path(scope);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        sentry_core::paths::write_atomic(&p, text.as_bytes()).map_err(|e| e.to_string())
    }
}

/// The `firmware_missing` condition: `after` found packages missing.
pub fn missing_now(scope: &str) -> bool {
    !State::load(scope).missing.is_empty()
}

/// How long `wait` waits (`SENTRY_FIRMWARE_WAIT` in tests).
pub fn wait_total() -> Duration {
    std::env::var("SENTRY_FIRMWARE_WAIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or(WAIT, Duration::from_secs)
}

// ---- the steps ---------------------------------------------------------------------

/// What a step prints and how it ends.
pub struct Out<'a> {
    pub say: &'a mut dyn FnMut(String),
    pub err: &'a mut dyn FnMut(String),
}

fn boot_id(r: &Router) -> Seen {
    match r
        .cmd("cat")
        .arg("/proc/sys/kernel/random/boot_id")
        .own_connection()
        .timeout(Some(Duration::from_secs(15)))
        .output()
    {
        Ok(s) => Seen::Boot(s.trim().to_string()),
        Err(_) => Seen::Nothing,
    }
}

fn run_sh(r: &Router, script: &str, secs: u64) -> Result<sentry_core::exec::Output, String> {
    r.sh(script)
        .timeout(Some(Duration::from_secs(secs)))
        .run()
        .map_err(|e| e.to_string())
}

fn mem(r: &Router) -> Result<Mem, String> {
    let o = run_sh(r, MEM_SCRIPT, 30)?;
    parse_mem(&o.stdout).ok_or_else(|| "the router's free memory didn't read".to_string())
}

fn board(r: &Router) -> Result<crate::collect::ifaces::Board, String> {
    crate::collect::ifaces::collect(r)
        .map(|i| i.board)
        .map_err(|e| e.to_string())
}

fn world(r: &Router) -> Result<Vec<String>, String> {
    let o = run_sh(r, TOP_LEVEL, 60)?;
    if o.code != 0 {
        return Err("the router's list of installed packages didn't read".into());
    }
    Ok(packagelist(&o.stdout)?.into_iter().collect())
}

fn installed_now(r: &Router) -> Result<BTreeSet<String>, String> {
    let o = run_sh(r, ALL_INSTALLED, 60)?;
    if o.code != 0 {
        return Err("the router's packages didn't read".into());
    }
    packagelist(&o.stdout)
}

/// The watched services that run (or need not: not daemons), by name.
fn services_running(r: &Router) -> Result<Vec<String>, String> {
    use crate::collect::services::{self, State as S};
    let svc = services::collect(r).map_err(|e| e.to_string())?;
    Ok(svc
        .watched(&r.cfg.expect.services)
        .into_iter()
        .filter(|n| matches!(svc.state(n), S::Running | S::NotADaemon))
        .map(str::to_string)
        .collect())
}

/// What ran before the flash and doesn't now (empty: all back).
pub fn services_lost(before: &[String], now: &[String]) -> Vec<String> {
    before
        .iter()
        .filter(|s| !now.contains(s))
        .cloned()
        .collect()
}

/// The services that ran before run again; said either way.
fn services_back(r: &Router, st: &State, o: &mut Out) -> bool {
    match services_running(r) {
        Ok(now) => {
            let lost = services_lost(&st.services_before, &now);
            if lost.is_empty() {
                (o.say)(format!(
                    "✓ The services that ran before run again ({}).",
                    if st.services_before.is_empty() {
                        "none were noted".to_string()
                    } else {
                        st.services_before.join(", ")
                    }
                ));
                true
            } else {
                (o.err)(format!(
                    "✗ Running before the flash and not now: {}.",
                    lost.join(", ")
                ));
                false
            }
        }
        Err(e) => {
            (o.err)(format!("the services didn't read: {e}"));
            false
        }
    }
}

/// Removes the image and its owut files from the router's memory.
fn forget_image(r: &Router) {
    // (`/tmp/sysupgrade.meta` is what `sysupgrade --test` leaves: its own reading of the
    // image's metadata.)
    let _ = run_sh(
        r,
        &format!("rm -f {IMAGE} {SUMS} {MANIFEST} {FLASH_LOG} /tmp/sysupgrade.meta"),
        30,
    );
}

/// `check`: the release, its series, what upstream knows, free memory, no guarded change
/// waiting, a backup recipient, owut there.
pub fn check(r: &Router, o: &mut Out) -> u8 {
    let b = match board(r) {
        Ok(b) => b,
        Err(e) => {
            (o.err)(format!("The router didn't answer: {e}"));
            return 1;
        }
    };
    (o.say)(format!(
        "The router runs {} {} ({}).",
        b.distribution, b.version, b.target
    ));
    let Some(series) = crate::maint::eval::series(&b.version) else {
        (o.err)(format!(
            "{} isn't a release (a development build): sentry only upgrades releases.",
            b.version
        ));
        return 3;
    };
    let up = crate::maint::upstream::get(&r.name, &series);
    let fw = crate::maint::eval::firmware(
        &b.version,
        Some(&up.data),
        Timestamp::now().to_zoned(jiff::tz::TimeZone::UTC).date(),
    );
    match (&fw.latest, fw.newer) {
        (Some(l), true) => (o.say)(format!(
            "{l} is the newest release of the {series} series{}.",
            match fw.security {
                Some(true) => ", and its notes list security fixes",
                _ => "",
            }
        )),
        (Some(l), false) => (o.say)(format!(
            "Upstream lists {l} as the newest of {series}; owut asks the upgrade server itself next."
        )),
        (None, _) => (o.say)(
            "Upstream couldn't be asked from here; owut asks the upgrade server itself next."
                .into(),
        ),
    }
    let mut ok = true;
    if r.cfg.backup.recipients.is_empty() {
        (o.err)(
            "No backup recipient is set: an upgrade starts with an encrypted backup of the \
             router's settings, and there is no key to encrypt it to. Set backup.recipients \
             in network_config.yaml (sentry-network backup key makes one)."
                .into(),
        );
        ok = false;
    }
    if crate::guard::pending(&r.scope).is_some() {
        (o.err)("A guarded change is still waiting to be kept or undone: finish it first.".into());
        ok = false;
    }
    match crate::guard::turn(&r.scope) {
        Ok(t) => drop(t),
        Err(e) => {
            (o.err)(format!("{e}."));
            ok = false;
        }
    }
    match run_sh(r, "command -v owut", 30) {
        Ok(x) if x.code == 0 => {}
        _ => {
            (o.err)(
                "The router has no owut (OpenWrt's upgrade tool), which this upgrade uses.".into(),
            );
            ok = false;
        }
    }
    match mem(r) {
        Ok(m) => match enough_before(&m) {
            Ok(()) => (o.say)(format!(
                "Free: {} of memory, {} of temporary storage.",
                mib(m.available),
                mib(m.tmp_free)
            )),
            Err(e) => {
                (o.err)(e);
                ok = false;
            }
        },
        Err(e) => {
            (o.err)(e);
            ok = false;
        }
    }
    if !ok {
        (o.err)("Nothing was changed.".into());
        return 3;
    }
    let st = State {
        from: b.version.clone(),
        ..Default::default()
    };
    if let Err(e) = st.save(&r.scope) {
        (o.err)(format!("the run's record couldn't be written: {e}"));
        return 1;
    }
    0
}

/// `backup`: an encrypted config backup, verified, remembered for the run.
pub fn backup(r: &Router, o: &mut Out) -> u8 {
    let made = match crate::backup::run(r) {
        Ok(m) => m,
        Err(e) => {
            (o.err)(format!("No backup was made, so nothing is flashed: {e}"));
            return 1;
        }
    };
    made.lines().into_iter().for_each(|l| (o.say)(l));
    match crate::backup::verify(r) {
        Ok(s) => (o.say)(format!("✓ {s}")),
        Err(e) => {
            (o.err)(format!(
                "The backup didn't verify, so nothing is flashed: {e}"
            ));
            return 1;
        }
    }
    let mut st = State::load(&r.scope);
    st.backup = made
        .path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned());
    st.backed_up_at = Some(
        Timestamp::now()
            .to_zoned(jiff::tz::TimeZone::system())
            .strftime("%Y-%m-%d %H:%M")
            .to_string(),
    );
    match st.save(&r.scope) {
        Ok(()) => 0,
        Err(e) => {
            (o.err)(format!("the run's record couldn't be written: {e}"));
            1
        }
    }
}

/// `plan`: `owut check --verbose`, read; stops on anything owut warns about.
pub fn plan(r: &Router, o: &mut Out) -> u8 {
    let b = match board(r) {
        Ok(b) => b,
        Err(e) => {
            (o.err)(format!("The router didn't answer: {e}"));
            return 1;
        }
    };
    let world = match world(r) {
        Ok(w) => w,
        Err(e) => {
            (o.err)(e);
            return 1;
        }
    };
    (o.say)(
        "$ owut check --verbose   (on the router; it asks the upgrade server, writes nothing)"
            .into(),
    );
    let x = match run_sh(r, "owut check --verbose 2>&1", 600) {
        Ok(x) => x,
        Err(e) => {
            (o.err)(format!("owut check didn't run: {e}"));
            return 1;
        }
    };
    let c = parse_check(&x.stdout);
    let why = stops(&c, x.code, &b.version);
    if !why.is_empty() {
        (o.err)("STOPPED before anything was downloaded:".into());
        why.into_iter().for_each(|w| (o.err)(format!("  · {w}")));
        (o.say)("owut's own words:".into());
        x.stdout
            .lines()
            .filter(|l| !l.starts_with("  ") || l.contains("downgrade") || l.contains("missing"))
            .for_each(|l| (o.say)(format!("  {}", strip_ansi(l))));
        return 3;
    }
    summary(&c, &world).into_iter().for_each(|l| (o.say)(l));
    (o.say)("What changes:".into());
    for (n, a, b) in &c.changes {
        (o.say)(format!("  {n:<30} {a} → {b}"));
    }
    let mut st = State::load(&r.scope);
    st.from = b.version;
    st.to = c.to.map(|t| t.version).unwrap_or_default();
    st.world = world;
    st.replaced = c.replaced;
    match st.save(&r.scope) {
        Ok(()) => 0,
        Err(e) => {
            (o.err)(format!("the run's record couldn't be written: {e}"));
            1
        }
    }
}

/// `download`: owut builds, downloads and verifies the image; sentry compares it with the
/// server's own sum, size, version and packages, and `sysupgrade --test`s it.
pub fn download(r: &Router, o: &mut Out) -> u8 {
    let mut st = State::load(&r.scope);
    if st.to.is_empty() || st.world.is_empty() {
        (o.err)("The plan step hasn't run in this run: nothing to download.".into());
        return 3;
    }
    match mem(r).and_then(|m| enough_before(&m)) {
        Ok(()) => {}
        Err(e) => {
            (o.err)(e);
            return 3;
        }
    }
    // sysupgrade runs (`--test`): nothing else of sentry's runs it meanwhile.
    let turn = match crate::backup::turn(&r.scope) {
        Ok(t) => t,
        Err(e) => {
            (o.err)(format!("the sysupgrade lock: {e}"));
            return 1;
        }
    };
    let line = format!("owut download -V {} -i {IMAGE} --verbose 2>&1", st.to);
    if !plain_name(&st.to) {
        (o.err)("the planned version isn't a version".into());
        return 3;
    }
    (o.say)(format!("$ {line}   (on the router; into its memory)"));
    let t = Instant::now();
    let x = match run_sh(r, &line, 1800) {
        Ok(x) => x,
        Err(e) => {
            forget_image(r);
            (o.err)(format!(
                "owut download didn't finish: {e}. Nothing was flashed."
            ));
            return 1;
        }
    };
    let d = parse_download(&x.stdout);
    for l in x.stdout.lines().filter(|l| {
        let l = strip_ansi(l);
        l.starts_with("Build ") || l.starts_with("Image saved") || l.starts_with("Verifying")
    }) {
        (o.say)(strip_ansi(l));
    }
    if x.code != 0 || !d.valid || !d.sum_ok {
        forget_image(r);
        (o.err)("STOPPED: the image wasn't downloaded or didn't verify. Nothing was flashed, and nothing is left in the router's memory.".into());
        if d.build_failed {
            (o.err)("The upgrade server couldn't build it; this is often the server lagging behind a release. r tries again later.".into());
        }
        d.errors
            .iter()
            .for_each(|e| (o.err)(format!("  owut: {e}")));
        return 1;
    }
    // sentry's own look.
    let looked = (|| -> Result<(Manifest, String, u64), String> {
        let m = run_sh(r, &format!("cat {MANIFEST}"), 30)?;
        let m = parse_manifest(&m.stdout)?;
        let s = run_sh(r, &format!("sha256sum {IMAGE}; wc -c < {IMAGE}"), 120)?;
        let mut l = s.stdout.lines();
        let sum = l
            .next()
            .and_then(|x| x.split_whitespace().next())
            .unwrap_or("")
            .to_string();
        let size = l.next().and_then(|x| x.trim().parse().ok()).unwrap_or(0);
        Ok((m, sum, size))
    })();
    let (m, sum, size) = match looked {
        Ok(x) => x,
        Err(e) => {
            forget_image(r);
            (o.err)(format!(
                "STOPPED: the image couldn't be checked ({e}). Nothing was flashed; it was removed from the router's memory."
            ));
            return 1;
        }
    };
    let mut why = image_problems(&m, &st.to, &sum, size, &st.world);
    match run_sh(r, &format!("sysupgrade --test {IMAGE} 2>&1"), 120) {
        Ok(x) if x.code == 0 => (o.say)(format!(
            "✓ sysupgrade --test: the router's own check takes this image ({})",
            x.stdout.trim().lines().last().unwrap_or("valid")
        )),
        Ok(x) => why.push(format!(
            "The router's own check refuses the image (sysupgrade --test: {}).",
            x.stdout.trim().lines().last().unwrap_or("no reason given")
        )),
        Err(e) => why.push(format!("sysupgrade --test didn't run: {e}")),
    }
    drop(turn);
    match mem(r) {
        Ok(mm) => {
            if let Err(e) = enough_for(&mm, size) {
                why.push(e);
            } else {
                (o.say)(format!(
                    "Memory: the {} image is in, {} still free.",
                    mib(size),
                    mib(mm.available)
                ));
            }
        }
        Err(e) => why.push(e),
    }
    if !why.is_empty() {
        forget_image(r);
        (o.err)("STOPPED before the flash:".into());
        why.into_iter().for_each(|w| (o.err)(format!("  · {w}")));
        (o.err)("Nothing was flashed; the image was removed from the router's memory.".into());
        return 1;
    }
    (o.say)(format!(
        "✓ {} {} image, {} bytes, checksum {}…, matches what the server built ({} s).",
        m.version,
        m.version_code,
        size,
        &sum[..12.min(sum.len())],
        t.elapsed().as_secs()
    ));
    st.sha256 = sum;
    st.size = size;
    match st.save(&r.scope) {
        Ok(()) => 0,
        Err(e) => {
            (o.err)(format!("the run's record couldn't be written: {e}"));
            1
        }
    }
}

/// The line that starts the flash on the router, apart from the ssh session that starts
/// it (`setsid`: this busybox has no `nohup`), its words into `FLASH_LOG`.
pub fn flash_line() -> String {
    format!(
        "setsid sh -c 'exec owut install -i {IMAGE} >{FLASH_LOG} 2>&1' </dev/null >/dev/null 2>&1 & echo started"
    )
}

/// What the flash's log says so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flashing {
    /// "Installing … and rebooting".
    Installing,
    /// owut refused (its ERROR lines).
    Refused(Vec<String>),
    /// Nothing decisive yet.
    Starting,
}

pub fn read_flash_log(text: &str) -> Flashing {
    let errors: Vec<String> = text
        .lines()
        .filter_map(|l| {
            strip_ansi(l)
                .trim()
                .strip_prefix("ERROR:")
                .map(|e| e.trim().to_string())
        })
        .collect();
    if !errors.is_empty() {
        return Flashing::Refused(errors);
    }
    if text.contains("Installing ") && text.contains("rebooting") {
        return Flashing::Installing;
    }
    Flashing::Starting
}

/// `flash`: with sentry's sysupgrade lock held, the image is checked once more, what is
/// there before is noted, and `owut install` is started apart from the session; ends when
/// the router has gone (or owut refused).
pub fn flash(r: &Router, o: &mut Out) -> u8 {
    let mut st = State::load(&r.scope);
    if st.sha256.is_empty() {
        (o.err)("No checked image in this run: the download step comes first.".into());
        return 3;
    }
    let _turn = match crate::backup::turn(&r.scope) {
        Ok(t) => t,
        Err(e) => {
            (o.err)(format!("the sysupgrade lock: {e}"));
            return 1;
        }
    };
    let now_sum = run_sh(r, &format!("sha256sum {IMAGE} 2>/dev/null"), 120)
        .ok()
        .and_then(|x| x.stdout.split_whitespace().next().map(str::to_string))
        .unwrap_or_default();
    if now_sum != st.sha256 {
        (o.err)(
            "The downloaded image isn't in the router's memory as it was checked (did the \
             router restart?). Nothing was flashed: run the download again (r on that step)."
                .into(),
        );
        return 3;
    }
    let Seen::Boot(boot) = boot_id(r) else {
        (o.err)("The router didn't answer: nothing was flashed.".into());
        return 1;
    };
    st.boot_before = boot;
    if let Ok(w) = world(r) {
        st.world = w;
    }
    if let Ok(c) = crate::collect::clients::collect(r) {
        st.leases_before = c.leases.len();
    }
    st.services_before = services_running(r).unwrap_or_default();
    st.wan_up_before = crate::collect::ifaces::collect(r)
        .ok()
        .and_then(|i| i.wan().map(|w| w.up))
        .unwrap_or(false);
    st.flashed_at = Some(Timestamp::now());
    st.step =
        "the flash (owut checking the image once more, then writing it and restarting the router)"
            .into();
    if let Err(e) = st.save(&r.scope) {
        (o.err)(format!(
            "the run's record couldn't be written, so nothing was flashed: {e}"
        ));
        return 1;
    }
    (o.say)(format!(
        "$ owut install -i {IMAGE}   (on the router, apart from this session)"
    ));
    match run_sh(r, &flash_line(), 60) {
        Ok(x) if x.stdout.contains("started") => {}
        Ok(x) => {
            (o.err)(format!(
                "The flash didn't start ({}). Nothing was flashed.",
                x.stderr.trim()
            ));
            return 1;
        }
        Err(e) => {
            (o.err)(format!(
                "The flash couldn't be started ({e}): nothing was flashed."
            ));
            return 1;
        }
    }
    // Watch it go: owut checks the image again, then the router closes every session.
    let until = Instant::now() + Duration::from_secs(180);
    let mut said_installing = false;
    while Instant::now() < until {
        std::thread::sleep(Duration::from_secs(3));
        let x = r
            .sh(&format!("cat {FLASH_LOG} 2>/dev/null"))
            .own_connection()
            .timeout(Some(Duration::from_secs(15)))
            .run();
        match x {
            Err(_) => {
                (o.say)(
                    "The router has closed its sessions: it is writing the new firmware.".into(),
                );
                return 0;
            }
            Ok(x) if x.code == 255 => {
                (o.say)(
                    "The router has closed its sessions: it is writing the new firmware.".into(),
                );
                return 0;
            }
            Ok(x) => match read_flash_log(&x.stdout) {
                Flashing::Refused(errs) => {
                    (o.err)("owut refused to flash the image. Nothing was flashed; the router keeps running as it was.".into());
                    errs.iter().for_each(|e| (o.err)(format!("  owut: {e}")));
                    forget_image(r);
                    let mut st = State::load(&r.scope);
                    st.flashed_at = None;
                    let _ = st.save(&r.scope);
                    return 1;
                }
                Flashing::Installing if !said_installing => {
                    said_installing = true;
                    (o.say)("owut checked the image and handed it to sysupgrade: the router is about to restart.".into());
                }
                _ => {}
            },
        }
    }
    if said_installing {
        (o.say)("The flash was handed over; the router is still answering. The next step waits for it to restart.".into());
        return 0;
    }
    (o.err)(
        "The flash was started but owut hasn't said anything for three minutes. The next \
         step waits for the router to restart, or says it didn't."
            .into(),
    );
    0
}

/// `wait`: new connections every few seconds until the boot id changes, or the deadline.
pub fn wait(r: &Router, o: &mut Out) -> u8 {
    let st = State::load(&r.scope);
    let Some(flashed) = st.flashed_at else {
        (o.err)("This run hasn't flashed anything: nothing to wait for.".into());
        return 3;
    };
    let total = wait_total();
    let until = deadline(flashed, Timestamp::now(), total);
    (o.say)(format!(
        "Waiting for the router to restart and answer again: usually 3 to 5 minutes, up to {} \
         after the flash started. The internet and Wi-Fi are off meanwhile.",
        took(total.as_secs() as i64)
    ));
    let mut last_said = Instant::now();
    loop {
        let now = Timestamp::now();
        let seen = boot_id(r);
        let since = (now - flashed).get_seconds();
        match poll(&seen, &st.boot_before, now, until) {
            Poll::Back => {
                let v = board(r).map(|b| b.version).unwrap_or_default();
                (o.say)(format!(
                    "✓ The router is back after {}{}.",
                    took(since),
                    if v.is_empty() {
                        String::new()
                    } else {
                        format!(", running {v}")
                    }
                ));
                let mut st = State::load(&r.scope);
                st.step = "the checks after the restart".into();
                let _ = st.save(&r.scope);
                return 0;
            }
            Poll::Over => {
                lost_words(&st, since).into_iter().for_each(|l| (o.err)(l));
                return 1;
            }
            Poll::Waiting => {
                if last_said.elapsed() >= Duration::from_secs(30) {
                    last_said = Instant::now();
                    (o.say)(format!(
                        "… {} since the flash started{}",
                        took(since),
                        match seen {
                            Seen::Boot(_) => " (it still answers on the old boot)",
                            Seen::Nothing => "",
                        }
                    ));
                }
                std::thread::sleep(POLL);
            }
        }
    }
}

/// `after`: the new version runs, the add-ons are there (or named), the services, the
/// uplink, the clients, the audit, a fresh backup.
pub fn after(r: &Router, o: &mut Out, audit: &dyn Fn() -> u8) -> u8 {
    let mut st = State::load(&r.scope);
    let mut ok = true;
    match board(r) {
        Ok(b) if !st.to.is_empty() && b.version != st.to => {
            (o.err)(format!(
                "✗ The router runs {} where {} was flashed: the new firmware didn't take.",
                b.version, st.to
            ));
            ok = false;
        }
        Ok(b) => (o.say)(format!(
            "✓ The router runs {} {}.",
            b.distribution, b.version
        )),
        Err(e) => {
            (o.err)(format!("The router didn't answer: {e}"));
            return 1;
        }
    }
    match installed_now(r) {
        Ok(now) => {
            let missing = missing_after(&st.world, &now, &st.replaced);
            if missing.is_empty() {
                (o.say)(format!(
                    "✓ All {} packages installed by name before are installed.",
                    st.world.len()
                ));
            } else {
                (o.err)(format!(
                    "✗ Missing since the flash: {}. The next step offers to install exactly these.",
                    missing.join(", ")
                ));
            }
            st.missing = missing;
        }
        Err(e) => {
            (o.err)(e);
            ok = false;
        }
    }
    if !services_back(r, &st, o) {
        ok = false;
    }
    match crate::collect::ifaces::collect(r) {
        Ok(i) => {
            let up = i.wan().is_some_and(|w| w.up);
            match (st.wan_up_before, up) {
                (true, false) => {
                    (o.err)(
                        "✗ The internet connection (WAN) was up before the flash and isn't now."
                            .into(),
                    );
                    ok = false;
                }
                (_, true) => (o.say)("✓ The internet connection (WAN) is up.".into()),
                (false, false) => (o.say)(
                    "· The internet connection (WAN) is down, as it was before the flash.".into(),
                ),
            }
        }
        Err(e) => {
            (o.err)(format!("the interfaces didn't read: {e}"));
            ok = false;
        }
    }
    match crate::collect::clients::collect(r) {
        Ok(c) if st.leases_before > 0 && c.leases.is_empty() => {
            (o.err)(format!(
                "✗ No device has asked for an address yet ({} had one before). Devices come back over a few minutes: r checks again.",
                st.leases_before
            ));
            ok = false;
        }
        Ok(c) => (o.say)(format!(
            "✓ {} device(s) hold an address ({} before the flash).",
            c.leases.len(),
            st.leases_before
        )),
        Err(e) => (o.err)(format!("the clients didn't read: {e}")),
    }
    if audit() != 0 {
        ok = false;
    }
    match crate::backup::run(r) {
        Ok(m) => {
            m.lines().into_iter().take(1).for_each(|l| (o.say)(l));
            if let Err(e) = crate::backup::verify(r) {
                (o.err)(format!("✗ The fresh backup didn't verify: {e}"));
                ok = false;
            }
        }
        Err(e) => {
            (o.err)(format!("✗ No fresh backup was made: {e}"));
            ok = false;
        }
    }
    st.step = "the checks after the restart".into();
    let _ = st.save(&r.scope);
    if ok { 0 } else { 1 }
}

/// `add-missing`: `apk add` exactly the packages `after` found missing.
pub fn add_missing(r: &Router, o: &mut Out) -> u8 {
    let mut st = State::load(&r.scope);
    if st.missing.is_empty() {
        (o.say)("Nothing is missing.".into());
        return 0;
    }
    if let Some(bad) = st.missing.iter().find(|n| !plain_name(n)) {
        (o.err)(format!(
            "`{bad}` isn't a package's name: nothing was installed."
        ));
        return 3;
    }
    let names = st.missing.join(" ");
    let line = format!("apk update && apk add {names}");
    (o.say)(format!("$ {line}"));
    match run_sh(r, &format!("{line} 2>&1"), 900) {
        Ok(x) => {
            x.stdout.lines().for_each(|l| (o.say)(l.to_string()));
            if x.code != 0 {
                (o.err)(format!(
                    "apk ended with exit {}: the packages above weren't all installed.",
                    x.code
                ));
                return 1;
            }
        }
        Err(e) => {
            (o.err)(format!("apk didn't run: {e}"));
            return 1;
        }
    }
    let now = match installed_now(r) {
        Ok(n) => n,
        Err(e) => {
            (o.err)(e);
            return 1;
        }
    };
    st.missing = missing_after(&st.missing, &now, &[]);
    let _ = st.save(&r.scope);
    if !st.missing.is_empty() {
        (o.err)(format!("Still missing: {}", st.missing.join(", ")));
        return 1;
    }
    (o.say)(format!("✓ Installed again: {names}"));
    if services_back(r, &st, o) { 0 } else { 1 }
}

/// `forget` (abandon's step): the downloaded image out of the router's memory.
pub fn forget(r: &Router, o: &mut Out) -> u8 {
    forget_image(r);
    (o.say)("The downloaded image was removed from the router's memory.".into());
    0
}

#[cfg(test)]
mod tests;

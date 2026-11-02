//! This machine's workflows: the shipped ones (seeded into `~/.config/sentry/workflows/`), how
//! they're found and linted against sentry's own checks.

use std::path::{Path, PathBuf};

use super::{BUILTINS, Entry, Issue, LintRules, Workflow, lint_with, load_path_with, seed_with};
use crate::paths;

pub fn dir() -> PathBuf {
    paths::config_dir().join("workflows")
}

pub const SEEDS: &[(&str, &str)] = &[
    (
        "quick-update",
        include_str!("../../../../assets/workflows/quick-update.toml"),
    ),
    (
        "release-rebase",
        include_str!("../../../../assets/workflows/release-rebase.toml"),
    ),
    (
        "rpmfusion-migrate",
        include_str!("../../../../assets/workflows/rpmfusion-migrate.toml"),
    ),
];

/// Every version of a seed that has shipped before (computed from git history), so an
/// unedited old copy written before `.seeded.json` existed is still recognised.
const SHIPPED: &[(&str, u64)] = &[
    ("quick-update", 0x7f63b533fa286d4a),
    ("quick-update", 0x62c1578a44eea6ad),
    ("quick-update", 0xde8871690062d69b),
    ("quick-update", 0x2d312982ded1964f),
    ("quick-update", 0xf52047aecfabc312),
    ("quick-update", 0x6622cb14519df822),
    ("release-rebase", 0x88a4b4c8c169a61b),
    ("release-rebase", 0xacf631c5205f1724),
    ("release-rebase", 0x66f7dd06dad74b07),
    ("release-rebase", 0x198de706696c120d),
];

/// Write the shipped workflows where they're missing, and upgrade copies that are an
/// unmodified earlier version (by recorded hash). A file the user has edited is never touched.
pub fn seed() -> std::io::Result<Vec<String>> {
    seed_in(&dir())
}

pub fn seed_in(d: &Path) -> std::io::Result<Vec<String>> {
    seed_with(d, SEEDS, SHIPPED)
}

/// What lint accepts here: the built-ins, and sentry's own conditions and checks.
pub const LOCAL: LintRules = LintRules {
    builtins: BUILTINS,
    cond: |c| crate::checks::cond_check(c).is_some(),
    check: |c| crate::checks::NAMES.contains(&c),
};

pub fn load_path(path: &Path) -> Entry {
    load_path_with(path, &LOCAL)
}

/// Every `*.toml` in the workflows directory (seeded first), sorted by name.
pub fn list() -> Vec<Entry> {
    let _ = seed();
    let mut v: Vec<Entry> = std::fs::read_dir(dir())
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .map(|p| load_path(&p))
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

pub fn find(name: &str) -> Option<Entry> {
    let _ = seed();
    let p = dir().join(format!("{name}.toml"));
    p.exists().then(|| load_path(&p))
}

/// Spec §9.6 lint: ids, templates, `when` names, `sentry check` names, kind/field combinations.
pub fn lint(w: &Workflow) -> Vec<Issue> {
    lint_with(w, &LOCAL)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::workflows::*;

    #[test]
    fn seeds_parse_and_lint_clean() {
        for (name, body) in SEEDS {
            let w = parse(body).unwrap_or_else(|e| panic!("{name}: {e}"));
            let errs: Vec<_> = lint(&w).into_iter().filter(|i| i.error).collect();
            assert!(errs.is_empty(), "{name}: {errs:?}");
        }
        let rr = parse(SEEDS[1].1).unwrap();
        assert!(rr.draft);
    }

    #[test]
    fn seeding_upgrades_only_unedited_copies() {
        let d = std::env::temp_dir().join(format!("sentry-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert!(
            seed_in(&d).unwrap().is_empty(),
            "fresh install writes, doesn't upgrade"
        );
        // Simulate an older seed we wrote, and a user edit.
        std::fs::write(
            d.join("quick-update.toml"),
            "name = \"quick-update\"\n# old\nsteps = []\n",
        )
        .unwrap();
        let mut rec: BTreeMap<String, u64> =
            serde_json::from_str(&std::fs::read_to_string(d.join(".seeded.json")).unwrap())
                .unwrap();
        rec.insert(
            "quick-update".into(),
            fnv(b"name = \"quick-update\"\n# old\nsteps = []\n"),
        );
        std::fs::write(d.join(".seeded.json"), serde_json::to_vec(&rec).unwrap()).unwrap();
        std::fs::write(d.join("release-rebase.toml"), "# mine\n").unwrap();
        assert_eq!(seed_in(&d).unwrap(), vec!["quick-update"]);
        assert_eq!(
            std::fs::read_to_string(d.join("quick-update.toml")).unwrap(),
            SEEDS[0].1
        );
        assert_eq!(
            std::fs::read_to_string(d.join("release-rebase.toml")).unwrap(),
            "# mine\n"
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn lint_catches_mistakes() {
        let w = parse(
            r#"
name = "x"
[[steps]]
id = "a"
title = "uses {{ nope }}"
run = "sentry check bogus && echo {{ target }}"
when = "!not_a_condition"
[[steps]]
id = "a"
title = "dup"
kind = "reboot"
run = "systemctl reboot"
[[steps]]
id = "m"
title = "manual without text"
kind = "manual"
"#,
        )
        .unwrap();
        let msgs: Vec<String> = lint(&w).into_iter().map(|i| i.msg).collect();
        let has = |s: &str| msgs.iter().any(|m| m.contains(s));
        assert!(has("undefined variable `nope`"), "{msgs:#?}");
        assert!(has("undefined variable `target`"));
        assert!(has("unknown check `sentry check bogus`"));
        assert!(has("unknown `when` condition \"not_a_condition\""));
        assert!(has("duplicate step id \"a\""));
        assert!(has("`run` is not used by kind = Reboot"));
        assert!(has("manual steps need `manual`"));
        assert!(
            parse("name = \"x\"\nbogus = 1\nsteps = []")
                .unwrap_err()
                .contains("bogus")
        );
    }

    #[test]
    fn dry_run_siblings() {
        assert_eq!(
            dry_run_of("rpm-ostree install /var/cache/akmods/nvidia/kmod-nvidia-x.rpm").as_deref(),
            Some("rpm-ostree install --dry-run /var/cache/akmods/nvidia/kmod-nvidia-x.rpm")
        );
        assert_eq!(
            dry_run_of("rpm-ostree upgrade").as_deref(),
            Some("rpm-ostree upgrade --preview")
        );
        assert_eq!(dry_run_of("rpm-ostree upgrade --uninstall kmod-x"), None);
        assert_eq!(
            dry_run_of("rpm-ostree rebase fedora:fedora/45/x86_64/silverblue"),
            None
        );
        assert_eq!(dry_run_of("flatpak update -y"), None);
        // --preview's 77 is "no update", not a failure; other dry runs' 77 is.
        assert!(dry_nothing_to_do("rpm-ostree upgrade --preview", 77));
        assert!(!dry_nothing_to_do("rpm-ostree upgrade --preview", 1));
        assert!(!dry_nothing_to_do("rpm-ostree install --dry-run x", 77));
    }
}

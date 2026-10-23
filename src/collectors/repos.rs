//! Third-party dnf/rpm-ostree repositories in host `/etc/yum.repos.d`.

use serde::{Deserialize, Serialize};

use super::CResult;
use crate::keyfile::KeyFile;
use crate::paths;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Repo {
    pub file: String,
    pub section: String,
    pub name: String,
    pub enabled: bool,
    pub url: String,
    pub copr: bool,
    pub third_party: bool,
}

pub fn collect() -> CResult<Vec<Repo>> {
    let dir = paths::host("/etc/yum.repos.d");
    let mut files: Vec<_> = std::fs::read_dir(&dir)?
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "repo"))
        .collect();
    files.sort_by_key(|e| e.file_name());
    let mut out = Vec::new();
    for e in files {
        let text = std::fs::read_to_string(e.path()).unwrap_or_default();
        out.extend(parse(&e.file_name().to_string_lossy(), &text));
    }
    Ok(out)
}

pub fn parse(file: &str, text: &str) -> Vec<Repo> {
    let kf = KeyFile::parse(text);
    kf.order
        .iter()
        .map(|sec| {
            let get = |k: &str| kf.get(sec, k).unwrap_or_default().to_string();
            let url = [get("baseurl"), get("metalink"), get("mirrorlist")]
                .into_iter()
                .find(|u| !u.is_empty())
                .unwrap_or_default();
            Repo {
                file: file.to_string(),
                section: sec.clone(),
                name: get("name"),
                enabled: matches!(get("enabled").as_str(), "1" | "true" | "True" | ""),
                url,
                copr: file.starts_with("_copr") || sec.starts_with("copr:"),
                third_party: !file.starts_with("fedora"),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::fixture;

    #[test]
    fn copr_and_fedora() {
        let f = "_copr_scottames-ghostty.repo";
        let r = parse(f, &fixture(&format!("repos/{f}")));
        assert!(r.iter().all(|r| r.copr && r.third_party));
        let fed = parse("fedora.repo", &fixture("repos/fedora.repo"));
        assert!(fed.iter().all(|r| !r.third_party));
        assert!(
            fed.iter()
                .any(|r| r.enabled && r.url.contains("metalink") || r.url.contains("mirrors"))
        );
    }

    #[test]
    fn disabled_flag() {
        let r = parse("x.repo", "[a]\nname=A\nenabled=0\nbaseurl=http://x\n");
        assert!(!r[0].enabled && r[0].third_party && !r[0].copr);
    }
}

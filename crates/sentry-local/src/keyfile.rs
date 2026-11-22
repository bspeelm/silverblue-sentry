//! Minimal GLib keyfile / INI parser: Flatpak metadata & overrides, yum .repo files, .desktop files.

use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct KeyFile {
    pub sections: BTreeMap<String, BTreeMap<String, String>>,
    /// Section names in file order (repo files care about order for display).
    pub order: Vec<String>,
}

impl KeyFile {
    pub fn parse(text: &str) -> Self {
        let mut kf = KeyFile::default();
        let mut cur: Option<String> = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                let name = name.trim().to_string();
                if !kf.sections.contains_key(&name) {
                    kf.order.push(name.clone());
                }
                kf.sections.entry(name.clone()).or_default();
                cur = Some(name);
                continue;
            }
            if let (Some(sec), Some((k, v))) = (&cur, line.split_once('=')) {
                kf.sections
                    .get_mut(sec)
                    .expect("section")
                    .insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        kf
    }

    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.sections.get(section)?.get(key).map(String::as_str)
    }

    pub fn section(&self, section: &str) -> Option<&BTreeMap<String, String>> {
        self.sections.get(section)
    }

    /// `a;b;c;` → `["a","b","c"]`.
    pub fn list(&self, section: &str, key: &str) -> Vec<String> {
        self.get(section, key).map(split_list).unwrap_or_default()
    }
}

pub fn split_list(v: &str) -> Vec<String> {
    v.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sections_lists_and_comments() {
        let kf = KeyFile::parse(
            "# c\n[Context]\nshared=ipc;network;\nfilesystems = !home;xdg-download\n\n[Session Bus Policy]\norg.x=talk\n",
        );
        assert_eq!(kf.list("Context", "shared"), vec!["ipc", "network"]);
        assert_eq!(
            kf.list("Context", "filesystems"),
            vec!["!home", "xdg-download"]
        );
        assert_eq!(kf.get("Session Bus Policy", "org.x"), Some("talk"));
        assert_eq!(kf.order, vec!["Context", "Session Bus Policy"]);
    }
}

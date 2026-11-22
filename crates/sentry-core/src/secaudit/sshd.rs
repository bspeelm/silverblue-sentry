//! What an ssh server allows, from `sshd -T` (its effective settings) or from its config
//! files where that needs root. Pure.

use super::Ssh;

/// The shell lines that print the config files, each after a `#@file <path>` line: the
/// main file, then what `sshd_config.d` holds. `root` is where `/etc` is (a toolbox sees
/// the host's under `/run/host`).
pub fn files_script(root: &str) -> String {
    format!(
        "for f in {root}/etc/ssh/sshd_config {root}/etc/ssh/sshd_config.d/*.conf; do \
         [ -r \"$f\" ] && {{ echo \"#@file ${{f#{root}}}\"; cat \"$f\"; echo; }}; done; true"
    )
}

/// One setting's first value among the lines that apply to everyone (sshd takes the first
/// it reads; a `Match` block ends what applies to everyone).
fn first<'a>(lines: &[(&'a str, &'a str)], key: &str) -> Option<&'a str> {
    lines
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| *v)
}

fn settings(text: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    for l in text.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let (k, v) = match l.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (k, v.trim().trim_start_matches('=').trim().trim_matches('"')),
            None => (l, ""),
        };
        if k.eq_ignore_ascii_case("match") {
            break;
        }
        out.push((k, v));
    }
    out
}

fn ssh(lines: &[(&str, &str)], source: &str, defaults: bool) -> Ssh {
    let yes = |v: &str| v.eq_ignore_ascii_case("yes");
    Ssh {
        on: None,
        password: first(lines, "PasswordAuthentication")
            .map(yes)
            .or(defaults.then_some(true)),
        root: first(lines, "PermitRootLogin")
            .map(|v| match v.to_ascii_lowercase().as_str() {
                "without-password" => "prohibit-password".to_string(),
                v => v.to_string(),
            })
            .or(defaults.then(|| "prohibit-password".to_string())),
        source: source.to_string(),
    }
}

/// `sshd -T`: every setting as it is in force, lower-case.
pub fn parse_effective(text: &str) -> Ssh {
    ssh(&settings(text), "sshd -T", false)
}

/// The config files as [`files_script`] prints them. The main file's `Include` lines are
/// followed in place (the files it names that were printed); what no file sets is sshd's
/// default. None: the main file wasn't readable, so nothing can be said.
pub fn parse_files(text: &str) -> Option<Ssh> {
    let mut files: Vec<(&str, String)> = Vec::new();
    for l in text.lines() {
        if let Some(p) = l.strip_prefix("#@file ") {
            files.push((p.trim(), String::new()));
        } else if let Some((_, body)) = files.last_mut() {
            body.push_str(l);
            body.push('\n');
        }
    }
    let main = files.iter().find(|(p, _)| p.ends_with("/sshd_config"))?;
    let mut flat = String::new();
    for l in main.1.lines() {
        let t = l.trim();
        let include = t
            .split_once(char::is_whitespace)
            .filter(|(k, _)| k.eq_ignore_ascii_case("include"));
        match include {
            Some((_, pattern)) => {
                // `/etc/ssh/sshd_config.d/*.conf`: the directory's files, in name order.
                let dir = pattern.trim().rsplit_once('/').map_or("", |(d, _)| d);
                let mut inc: Vec<&(&str, String)> = files
                    .iter()
                    .filter(|(p, _)| !dir.is_empty() && p.starts_with(dir) && *p != main.0)
                    .collect();
                inc.sort_by_key(|(p, _)| *p);
                for (_, body) in inc {
                    // A `Match` in an included file ends with that file.
                    for (k, v) in settings(body) {
                        flat.push_str(&format!("{k} {v}\n"));
                    }
                }
            }
            None => {
                flat.push_str(l);
                flat.push('\n');
            }
        }
    }
    Some(ssh(&settings(&flat), "its config files", true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_settings_are_read_as_they_stand() {
        let s = parse_effective(
            "port 22\npasswordauthentication no\npermitrootlogin without-password\n",
        );
        assert_eq!(s.password, Some(false));
        assert_eq!(s.root.as_deref(), Some("prohibit-password"));
        // Not said: not known (sshd -T always says, so this is a cut-off output).
        assert_eq!(parse_effective("port 22\n").password, None);
    }

    #[test]
    fn the_first_value_wins_and_includes_come_where_they_stand() {
        let text = "#@file /etc/ssh/sshd_config\n\
                    Include /etc/ssh/sshd_config.d/*.conf\n\
                    #PasswordAuthentication yes\n\
                    PasswordAuthentication yes\n\
                    PermitRootLogin no\n\
                    Match User backup\n\
                    PasswordAuthentication yes\n\
                    #@file /etc/ssh/sshd_config.d/10-keys.conf\n\
                    PasswordAuthentication no\n\
                    #@file /etc/ssh/sshd_config.d/50-other.conf\n\
                    PasswordAuthentication yes\n";
        let s = parse_files(text).unwrap();
        assert_eq!(s.password, Some(false), "the included file is read first");
        assert_eq!(s.root.as_deref(), Some("no"));
        assert_eq!(s.source, "its config files");
    }

    #[test]
    fn what_no_file_sets_is_the_default_and_no_main_file_is_unknown() {
        let s = parse_files("#@file /etc/ssh/sshd_config\nPort 22\n").unwrap();
        assert_eq!(s.password, Some(true));
        assert_eq!(s.root.as_deref(), Some("prohibit-password"));
        assert_eq!(parse_files(""), None);
        assert_eq!(
            parse_files("#@file /etc/ssh/sshd_config.d/a.conf\nPasswordAuthentication no\n"),
            None
        );
    }

    #[test]
    fn the_script_reads_under_a_root() {
        let s = files_script("/run/host");
        assert!(s.contains("/run/host/etc/ssh/sshd_config "));
        assert!(s.contains("${f#/run/host}"));
        assert!(files_script("").contains("for f in /etc/ssh/sshd_config "));
    }
}

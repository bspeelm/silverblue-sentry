//! Recent journal warnings/errors and failed logins (input for the audit in M3).
//! Messages can contain secrets: never capture these as fixtures.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::CResult;
use crate::exec::Cmd;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Journal {
    pub user_warn: Vec<Entry>,
    /// `None` when the system journal isn't readable by this user.
    pub sys_err: Option<Vec<Entry>>,
    pub failed_logins: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub ts_us: u64,
    pub priority: u8,
    pub ident: String,
    pub message: String,
}

const FIELDS: &str =
    "--output-fields=MESSAGE,PRIORITY,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT,__REALTIME_TIMESTAMP";

fn query(user: bool, extra: &[&str]) -> Cmd {
    let c = Cmd::host("journalctl");
    let c = if user { c.arg("--user") } else { c };
    c.args(["--since", "-24h", "-o", "json", "--no-pager", FIELDS])
        .args(extra.iter().copied())
}

pub fn collect() -> CResult<Journal> {
    let user = query(true, &["-p", "warning", "-n", "500"]).output()?;
    let sys = query(false, &["-p", "err", "-n", "500"]).output().ok();
    let auth = query(false, &["SYSLOG_FACILITY=10", "-n", "500"])
        .output()
        .unwrap_or_default();
    Ok(Journal {
        user_warn: parse(&user),
        sys_err: sys.map(|s| parse(&s)),
        failed_logins: parse(&auth)
            .iter()
            .filter(|e| e.message.contains("authentication failure"))
            .count(),
    })
}

fn message(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        // Non-UTF-8 messages are emitted as byte arrays.
        Value::Array(a) => String::from_utf8_lossy(
            &a.iter()
                .filter_map(|b| b.as_u64().map(|b| b as u8))
                .collect::<Vec<_>>(),
        )
        .into_owned(),
        _ => String::new(),
    }
}

/// One JSON object per line.
pub fn parse(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .map(|v| Entry {
            ts_us: v["__REALTIME_TIMESTAMP"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            priority: v["PRIORITY"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(6),
            ident: v["SYSLOG_IDENTIFIER"]
                .as_str()
                .or_else(|| v["_SYSTEMD_UNIT"].as_str())
                .unwrap_or("?")
                .to_string(),
            message: message(&v["MESSAGE"]),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_lines() {
        let t = r#"{"__REALTIME_TIMESTAMP":"1792785985930628","PRIORITY":"4","SYSLOG_IDENTIFIER":"gnome-shell","MESSAGE":"something odd"}
{"__REALTIME_TIMESTAMP":"1792785985930629","PRIORITY":"3","_SYSTEMD_UNIT":"foo.service","MESSAGE":[104,105,255]}
not json
"#;
        let e = parse(t);
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].priority, e[0].ident.as_str()), (4, "gnome-shell"));
        assert_eq!(e[1].ident, "foo.service");
        assert!(e[1].message.starts_with("hi"));
    }
}

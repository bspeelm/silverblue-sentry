//! The Network screen's sample: what listens and what's connected, from one unprivileged
//! `ss` exec. No sudo here: this is polled, and a polled `sudo` would fill the server's auth
//! log. The process names only root sees come from [`super::listeners`] instead.

use serde::{Deserialize, Serialize};

use crate::remote::{Remote, SrvError};
use sentry_core::collectors::net;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Sockets {
    pub listeners: Vec<net::Listener>,
    pub established: Vec<net::Conn>,
}

pub fn script() -> &'static str {
    "command -v ss >/dev/null || echo '@@missing ss'; echo @@listen; ss -tulpnH; \
     echo @@established; ss -tnpH state established"
}

/// The two sections, each in `ss`'s own format. `Err("ss")`: it isn't installed.
pub fn parse(text: &str) -> Result<Sockets, String> {
    let mut section = "";
    let (mut listen, mut established) = (String::new(), String::new());
    for l in text.lines() {
        match l.trim() {
            "@@missing ss" => return Err("ss".into()),
            "@@listen" => section = "listen",
            "@@established" => section = "established",
            _ => {
                let to = match section {
                    "listen" => &mut listen,
                    "established" => &mut established,
                    _ => continue,
                };
                to.push_str(l);
                to.push('\n');
            }
        }
    }
    Ok(Sockets {
        listeners: net::parse_listen(&listen),
        established: net::parse_established(&established),
    })
}

pub fn collect(r: &Remote) -> Result<Sockets, SrvError> {
    parse(&r.output(&r.sh(script()))?).map_err(SrvError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::fixture;

    #[test]
    fn parses_both_sections() {
        let s = parse(&fixture("sockets.txt")).unwrap();
        assert_eq!(s.listeners.len(), 9);
        assert_eq!(s.established.len(), 3);
        let app = s.listeners.iter().find(|l| l.port == "8080").unwrap();
        assert_eq!(
            (app.process.as_deref(), app.pid),
            (Some("app"), Some(901)),
            "its own user's sockets have their names"
        );
        assert!(
            s.listeners
                .iter()
                .filter(|l| l.port != "8080")
                .all(|l| l.process.is_none())
        );
        assert_eq!(s.established[0].peer, "192.0.2.77:51514");
        assert_eq!(s.established[2].process.as_deref(), Some("app"));
        // Nothing listening, nothing connected: both empty, not an error.
        assert_eq!(
            parse("@@listen\n@@established\n").unwrap(),
            Sockets::default()
        );
    }

    #[test]
    fn missing_ss_is_not_found() {
        assert_eq!(
            parse("@@missing ss\n@@listen\n@@established\n"),
            Err("ss".into())
        );
    }
}

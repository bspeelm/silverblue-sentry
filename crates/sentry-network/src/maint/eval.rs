//! How the router's firmware stands against upstream. Pure: the installed release
//! (`ubus call system board`) and what was looked up ([`super::upstream`]).

use jiff::civil::Date;

use super::upstream::Upstream;
use sentry_app::remote::upstream::{Release, comparable};
use sentry_core::maint::version;

/// A series this close to its end of life is said to end soon.
pub const EOL_SOON_DAYS: i64 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EolState {
    /// Not looked up, or the series isn't one upstream lists.
    Unknown,
    /// No end announced, or far off.
    Supported,
    /// Ends in this many days.
    Soon(i64),
    /// Ended this many days ago.
    Past(i64),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Firmware {
    pub installed: String,
    /// `25.12` (none: a snapshot build, or not a release number).
    pub series: Option<String>,
    /// The newest patch release of that series, when known.
    pub latest: Option<String>,
    /// `latest` is newer than what's installed.
    pub newer: bool,
    /// Whether a release newer than the installed one speaks of security fixes (none:
    /// its notes couldn't be read).
    pub security: Option<bool>,
    pub eol: Option<Date>,
    pub eol_state: EolState,
    /// Why something isn't known.
    pub note: Option<String>,
}

/// `25.12` of `25.12.5` (none: `SNAPSHOT`, or anything that isn't `N.N.N`).
pub fn series(version: &str) -> Option<String> {
    let mut parts = version.trim().split('.');
    let (a, b, c) = (parts.next()?, parts.next()?, parts.next()?);
    let num = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    // A release candidate (`25.12.0-rc2`) is of its series too.
    let patch = c.split('-').next().unwrap_or("");
    (num(a) && num(b) && num(patch)).then(|| format!("{a}.{b}"))
}

fn in_series(v: &str, s: &str) -> bool {
    series(v.strip_prefix('v').unwrap_or(v)).as_deref() == Some(s)
}

pub fn firmware(installed: &str, up: Option<&Upstream>, today: Date) -> Firmware {
    let series = series(installed);
    let mut f = Firmware {
        installed: installed.to_string(),
        series: series.clone(),
        latest: None,
        newer: false,
        security: None,
        eol: None,
        eol_state: EolState::Unknown,
        note: None,
    };
    let Some(s) = series else {
        f.note = Some("not a release (a snapshot build?): nothing to compare with".into());
        return f;
    };
    let Some(up) = up.filter(|u| u.series == s) else {
        f.note = Some("upstream not looked up yet (r)".into());
        return f;
    };
    // The series' releases as GitHub has them, newest first.
    let releases: Vec<Release> = up
        .releases
        .as_ref()
        .map(|r| comparable(r, None, Some("v0.0.0")))
        .unwrap_or_default()
        .into_iter()
        .filter(|r| in_series(&r.version, &s))
        .collect();
    let plain = |v: &str| v.strip_prefix('v').unwrap_or(v).to_string();
    match &up.eol {
        Ok(e) => {
            f.eol = e.eol;
            f.eol_state = match e.eol {
                None => EolState::Supported,
                Some(d) => {
                    let days = (d - today).get_days() as i64;
                    match days {
                        d if d < 0 => EolState::Past(-d),
                        d if d <= EOL_SOON_DAYS => EolState::Soon(d),
                        _ => EolState::Supported,
                    }
                }
            };
            f.latest = e.latest.clone().filter(|l| in_series(l, &s));
        }
        Err(e) => f.note = Some(format!("end of life: {e}")),
    }
    // The second source, where the first has no patch level (or a newer one is tagged).
    if let Some(r) = releases.first() {
        let v = plain(&r.version);
        if f.latest
            .as_deref()
            .is_none_or(|l| version::cmp(&v, l).is_gt())
        {
            f.latest = Some(v);
        }
    }
    f.newer = f
        .latest
        .as_deref()
        .is_some_and(|l| version::cmp(l, installed).is_gt());
    if f.newer {
        f.security = match &up.releases {
            Err(e) => {
                f.note.get_or_insert(format!("release notes: {e}"));
                None
            }
            Ok(_) => {
                let newer: Vec<&Release> = releases
                    .iter()
                    .filter(|r| version::cmp(&plain(&r.version), installed).is_gt())
                    .collect();
                // No notes for what's newer: it can't be said.
                (!newer.is_empty()).then(|| newer.iter().any(|r| r.security))
            }
        };
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::date;
    use sentry_app::remote::upstream::Eol;

    fn rel(v: &str, security: bool) -> Release {
        Release {
            version: v.into(),
            security,
            ..Default::default()
        }
    }

    fn up(
        eol: Option<Date>,
        latest: Option<&str>,
        releases: Result<Vec<Release>, String>,
    ) -> Upstream {
        Upstream {
            series: "25.12".into(),
            eol: Ok(Eol {
                cycle: "25.12".into(),
                eol,
                latest: latest.map(str::to_string),
            }),
            releases,
        }
    }

    const TODAY: Date = date(2026, 10, 26);

    #[test]
    fn a_series_is_the_first_two_numbers() {
        assert_eq!(series("25.12.5").as_deref(), Some("25.12"));
        assert_eq!(series("25.12.0-rc2").as_deref(), Some("25.12"));
        assert_eq!(series("SNAPSHOT"), None);
        assert_eq!(series("25.12"), None);
        assert_eq!(series("25.12-SNAPSHOT"), None);
    }

    #[test]
    fn firmware_against_upstream() {
        let notes = || {
            Ok(vec![
                rel("v26.06.0-rc1", false),
                rel("v25.12.5", true),
                rel("v25.12.4", false),
                rel("v25.12.3", false),
                rel("v24.10.8", true),
            ])
        };
        // (installed, upstream) → (latest, newer, security, eol state)
        type Want<'a> = (Option<&'a str>, bool, Option<bool>, EolState);
        let table: Vec<(&str, &str, Option<Upstream>, Want)> = vec![
            (
                "up to date",
                "25.12.5",
                Some(up(None, Some("25.12.5"), notes())),
                (Some("25.12.5"), false, None, EolState::Supported),
            ),
            (
                "a newer patch release with security fixes",
                "25.12.3",
                Some(up(None, Some("25.12.5"), notes())),
                (Some("25.12.5"), true, Some(true), EolState::Supported),
            ),
            (
                "a newer one without",
                "25.12.3",
                Some(up(
                    None,
                    Some("25.12.4"),
                    Ok(vec![rel("v25.12.4", false), rel("v25.12.3", true)]),
                )),
                (Some("25.12.4"), true, Some(false), EolState::Supported),
            ),
            (
                "the notes couldn't be read: security isn't known",
                "25.12.3",
                Some(up(None, Some("25.12.5"), Err("rate limited".into()))),
                (Some("25.12.5"), true, None, EolState::Supported),
            ),
            (
                "no patch level from the first source: the tags give it",
                "25.12.3",
                Some(up(None, None, notes())),
                (Some("25.12.5"), true, Some(true), EolState::Supported),
            ),
            (
                "a newer series is not an update of this one",
                "25.12.5",
                Some(up(None, Some("26.06.1"), notes())),
                (Some("25.12.5"), false, None, EolState::Supported),
            ),
            (
                "past its end of life",
                "25.12.5",
                Some(up(Some(date(2026, 9, 30)), Some("25.12.5"), notes())),
                (Some("25.12.5"), false, None, EolState::Past(26)),
            ),
            (
                "ending soon",
                "25.12.5",
                Some(up(Some(date(2026, 12, 1)), Some("25.12.5"), notes())),
                (Some("25.12.5"), false, None, EolState::Soon(36)),
            ),
            (
                "ending, but not soon",
                "25.12.5",
                Some(up(Some(date(2027, 6, 30)), Some("25.12.5"), notes())),
                (Some("25.12.5"), false, None, EolState::Supported),
            ),
            (
                "not looked up",
                "25.12.5",
                None,
                (None, false, None, EolState::Unknown),
            ),
            (
                "looked up for another series",
                "24.10.2",
                Some(up(None, Some("25.12.5"), notes())),
                (None, false, None, EolState::Unknown),
            ),
            (
                "a snapshot",
                "SNAPSHOT",
                Some(up(None, Some("25.12.5"), notes())),
                (None, false, None, EolState::Unknown),
            ),
        ];
        for (what, installed, upstream, (latest, newer, security, eol)) in table {
            let f = firmware(installed, upstream.as_ref(), TODAY);
            assert_eq!(
                (f.latest.as_deref(), f.newer, f.security, f.eol_state),
                (latest, newer, security, eol),
                "{what}"
            );
        }
        // Why something isn't known is said.
        let f = firmware("25.12.5", None, TODAY);
        assert_eq!(f.note.as_deref(), Some("upstream not looked up yet (r)"));
        let mut broken = up(None, None, Err("offline".into()));
        broken.eol = Err("offline".into());
        let f = firmware("25.12.5", Some(&broken), TODAY);
        assert_eq!(f.eol_state, EolState::Unknown);
        assert_eq!(f.note.as_deref(), Some("end of life: offline"));
    }
}

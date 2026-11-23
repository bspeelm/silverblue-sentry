//! Claude's verdict after sentry has carried a plan out: one ```` ```sentry-verdict ```` TOML
//! block, `status = "done" | "more" | "failed"` (or, before any plan, `"wait"`: it shouldn't be
//! done now, with `again` for when to look again; or `"expected"`: a finding or an audit's
//! item is fine as it is, and sentry marks it expected; or `"ask"`: only the user can decide,
//! and `summary` is the question), a one-line `summary`, and `next` (what the
//! user does later, e.g. reboot to confirm: words, never commands). `more` comes with a new
//! sentry-apply block for what's left. Something that can only be confirmed later is a
//! `[follow_up]`: sentry adds it to Maintenance as a one-time task, due then.

use serde::Deserialize;

const FENCE: &str = "```sentry-verdict";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// It worked: the task is done.
    Done,
    /// Something's left: a new plan comes with it.
    More,
    /// It didn't work, and Claude has no plan that would.
    Failed,
    /// It shouldn't be done now: nothing changes, and the row is put off.
    Wait,
    /// What the session is about (a finding, one of the security audit's items) is fine as
    /// it is: nothing changes, and it is marked expected. For anything else: done.
    Expected,
    /// Only the user can decide: `summary` is the question, and the session waits for the
    /// answer they type (nothing is logged, the row stays).
    Ask,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub status: Status,
    pub summary: String,
    pub next: String,
    pub follow_up: Option<FollowUp>,
    /// With `wait`: when to look again (`30d`), if Claude said.
    pub again: Option<String>,
}

/// A check for later: what to confirm, how (read-only), and when it's due (`after`: a sentry
/// workflow whose next good run makes it due, or a wait like `7d`).
#[derive(Debug, Clone, PartialEq)]
pub struct FollowUp {
    pub title: String,
    pub steps: String,
    pub after: Option<String>,
}

#[derive(Deserialize)]
struct Raw {
    status: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    next: String,
    follow_up: Option<RawFollow>,
    again: Option<String>,
}

#[derive(Deserialize)]
struct RawFollow {
    title: String,
    #[serde(default)]
    steps: String,
    after: Option<String>,
}

/// The answer without its verdict block, and the verdict (Err: there but wrong, and why).
pub fn take(answer: &str) -> (String, Option<Result<Verdict, String>>) {
    let Some((body, block)) = crate::maint::fenced_block(answer, FENCE) else {
        return (answer.to_string(), None);
    };
    let v = toml::from_str::<Raw>(&block)
        .map_err(|e| e.message().to_string())
        .and_then(|r| {
            let status = match r.status.trim() {
                "done" => Status::Done,
                "more" => Status::More,
                "failed" => Status::Failed,
                "wait" => Status::Wait,
                "expected" => Status::Expected,
                "ask" => Status::Ask,
                s => {
                    return Err(format!(
                        "status is \"{s}\": done, more, failed, wait, expected or ask"
                    ));
                }
            };
            Ok(Verdict {
                status,
                summary: r.summary.trim().to_string(),
                next: r.next.trim().to_string(),
                again: r
                    .again
                    .map(|a| a.trim().to_string())
                    .filter(|a| !a.is_empty()),
                follow_up: r
                    .follow_up
                    .filter(|f| !f.title.trim().is_empty())
                    .map(|f| FollowUp {
                        title: f.title.trim().to_string(),
                        steps: f.steps.trim().to_string(),
                        after: f
                            .after
                            .map(|a| a.trim().to_string())
                            .filter(|a| !a.is_empty()),
                    }),
            })
        });
    (body, Some(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_verdict_is_taken_out_of_the_answer() {
        let a = "All seven checks hold.\n\n```sentry-verdict\nstatus = \"done\"\n\
                 summary = \"remount-fs no longer fails\"\nnext = \"reboot when it suits you\"\n```\n";
        let (body, v) = take(a);
        assert_eq!(body.trim(), "All seven checks hold.");
        assert_eq!(
            v.unwrap().unwrap(),
            Verdict {
                status: Status::Done,
                summary: "remount-fs no longer fails".into(),
                next: "reboot when it suits you".into(),
                follow_up: None,
                again: None,
            }
        );
        let (_, v) = take(
            "```sentry-verdict\nstatus = \"wait\"\nsummary = \"1.5.3 fixes it\"\nagain = \"14d\"\n```",
        );
        let v = v.unwrap().unwrap();
        assert_eq!((v.status, v.again.as_deref()), (Status::Wait, Some("14d")));
        let (_, v) = take(
            "```sentry-verdict\nstatus = \"done\"\nsummary = \"s\"\n[follow_up]\n\
             title = \"Confirm it\"\nsteps = \"journalctl -g x\"\nafter = \"quick-update\"\n```",
        );
        assert_eq!(
            v.unwrap().unwrap().follow_up,
            Some(FollowUp {
                title: "Confirm it".into(),
                steps: "journalctl -g x".into(),
                after: Some("quick-update".into()),
            })
        );
        assert!(take("no verdict").1.is_none());
        let bad = take("```sentry-verdict\nstatus = \"maybe\"\n```")
            .1
            .unwrap();
        assert!(
            bad.unwrap_err()
                .contains("done, more, failed, wait, expected or ask")
        );
        let (_, v) = take(
            "```sentry-verdict\nstatus = \"ask\"\nsummary = \"Is port 8443 meant to be open?\"\n```",
        );
        let v = v.unwrap().unwrap();
        assert_eq!(
            (v.status, v.summary.as_str()),
            (Status::Ask, "Is port 8443 meant to be open?")
        );
    }
}

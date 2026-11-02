//! Claude's verdict after sentry has carried a plan out: one ```` ```sentry-verdict ```` TOML
//! block, `status = "done" | "more" | "failed"`, a one-line `summary`, and `next` (what the
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub status: Status,
    pub summary: String,
    pub next: String,
    pub follow_up: Option<FollowUp>,
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
                s => return Err(format!("status is \"{s}\": done, more or failed")),
            };
            Ok(Verdict {
                status,
                summary: r.summary.trim().to_string(),
                next: r.next.trim().to_string(),
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
            }
        );
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
        assert!(bad.unwrap_err().contains("done, more or failed"));
    }
}

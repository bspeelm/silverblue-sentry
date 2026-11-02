//! Claude's verdict after sentry has carried a plan out: one ```` ```sentry-verdict ```` TOML
//! block, `status = "done" | "more" | "failed"`, a one-line `summary`, and `next` (what the
//! user does later, e.g. reboot to confirm: words, never commands). `more` comes with a new
//! sentry-apply block for what's left.

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
}

#[derive(Deserialize)]
struct Raw {
    status: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    next: String,
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
            }
        );
        assert!(take("no verdict").1.is_none());
        let bad = take("```sentry-verdict\nstatus = \"maybe\"\n```")
            .1
            .unwrap();
        assert!(bad.unwrap_err().contains("done, more or failed"));
    }
}

//! `sentry audit security`: the security audit across every configured target as one
//! system (core `secaudit`). Each target's facts are read side by side (`secfacts` in its
//! crate: this machine, each server, each network); a target that doesn't answer is said
//! and the audit still completes. Reads only; the one thing run that isn't sentry's own
//! read is the user's `[audit] outside` command, and only with `--outside`.

use std::process::ExitCode;

use sentry_core::config::Config;
use sentry_core::secaudit::{self, Answers, Report, State, TargetFacts};

const USAGE: &str = "usage: sentry audit security [--json] [--outside]\n       \
                     sentry audit security answers [<key> yes|no]";

pub fn main(args: &[String]) -> ExitCode {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["security", "answers", rest @ ..] => answers(rest),
        ["security", flags @ ..] if flags.iter().all(|f| ["--json", "--outside"].contains(f)) => {
            run(flags.contains(&"--json"), flags.contains(&"--outside"))
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Every configured target's facts, read side by side: this machine first. What a window
/// calls from a worker thread too.
pub fn collect() -> Vec<TargetFacts> {
    let servers = sentry_server::config::load().ok().map(|(f, _)| f);
    let networks = sentry_network::config::load().ok().map(|(f, _)| f);
    std::thread::scope(|sc| {
        let local = sc.spawn(sentry_local::secfacts::collect);
        let srv: Vec<_> = servers
            .iter()
            .flat_map(|f| &f.servers)
            .map(|(name, cfg)| {
                sc.spawn(move || {
                    let r = sentry_server::remote::Remote::new(name, cfg);
                    sentry_server::secfacts::collect(&r)
                })
            })
            .collect();
        let net: Vec<_> = networks
            .iter()
            .flat_map(|f| &f.networks)
            .map(|(name, cfg)| {
                sc.spawn(move || {
                    let r = sentry_network::remote::Router::new(name, cfg);
                    sentry_network::secfacts::collect(&r)
                })
            })
            .collect();
        std::iter::once(local)
            .chain(srv)
            .chain(net)
            .filter_map(|h| h.join().ok())
            .collect()
    })
}

fn run(json: bool, outside: bool) -> ExitCode {
    let (cfg, warnings) = Config::load();
    warnings.iter().for_each(|w| eprintln!("{w}"));
    eprintln!("Reading every target (this takes a moment)…");
    let mut facts = collect();
    if outside {
        match &cfg.audit.outside {
            Some(template) => {
                for r in facts.iter_mut().filter_map(|f| f.router.as_mut()) {
                    eprintln!("Checking from outside…");
                    r.outside = Some(secaudit::outside(template, r));
                }
            }
            None => eprintln!(
                "--outside: no [audit] outside command in config.toml; nothing was checked \
                 from outside"
            ),
        }
    }
    let (report, path) = match Report::finish(&facts) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sentry audit security: {e}");
            return ExitCode::FAILURE;
        }
    };
    if !report.empty() {
        // The audit ran: its task on this machine is done (the log is where tasks look).
        let entry = secaudit::done_entry(&report.summary());
        if let Err(e) = sentry_core::maint::log::write(&entry) {
            eprintln!("(the maintenance log wasn't written: {e})");
        }
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        print!("{}", secaudit::render(&report));
        println!("\nSaved: {}", path.display());
    }
    if report.empty() {
        eprintln!("sentry audit security: nothing could be read from any target");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// List what's asked and what was answered, or remember an answer.
fn answers(args: &[&str]) -> ExitCode {
    match args {
        [] => {
            let known = Answers::load();
            let asked: Vec<(String, String)> = secaudit::latest()
                .iter()
                .flat_map(|r| &r.items)
                .filter_map(|i| Some((i.question.clone()?, question(i))))
                .collect();
            if asked.is_empty() && known.answers.is_empty() {
                println!("Nothing is asked yet: run `sentry audit security` first.");
                return ExitCode::SUCCESS;
            }
            for (key, text) in &asked {
                let said = known
                    .answers
                    .get(key)
                    .map_or("not answered".to_string(), |a| {
                        format!("{} ({})", a.answer, a.at)
                    });
                println!("{key}\n    {text}\n    {said}");
            }
            for (key, a) in &known.answers {
                if !asked.iter().any(|(k, _)| k == key) {
                    println!(
                        "{key}\n    (not asked by the last audit)\n    {} ({})",
                        a.answer, a.at
                    );
                }
            }
            println!("\nAnswer one: sentry audit security answers <key> yes|no");
            ExitCode::SUCCESS
        }
        [key, said @ ("yes" | "no")] => match Answers::remember(key, *said == "yes") {
            Ok(()) => {
                println!("{key}: {said}. The next audit takes it into account.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("sentry audit security answers: {e}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// What an item asks, whatever its state is now (an answered one's title is the answer).
fn question(i: &secaudit::Item) -> String {
    match i.state {
        State::Ask => i.title.clone(),
        _ => format!("answered: {}", i.title),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_line() {
        let run = |a: &[&str]| main(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        // (Only what never reads a target.)
        assert_eq!(run(&[]), ExitCode::from(2));
        assert_eq!(run(&["security", "--scan"]), ExitCode::from(2));
        assert_eq!(run(&["network"]), ExitCode::from(2));
        assert_eq!(
            run(&["security", "answers", "k", "maybe"]),
            ExitCode::from(2)
        );
        // An answer is remembered (in the tests' scratch config) and listed.
        assert_eq!(
            run(&["security", "answers", "restore-tested:local", "no"]),
            ExitCode::SUCCESS
        );
        assert_eq!(Answers::load().get("restore-tested:local"), Some(false));
        assert_eq!(run(&["security", "answers"]), ExitCode::SUCCESS);
    }
}

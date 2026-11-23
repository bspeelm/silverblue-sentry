//! The Config tab's wizard (`A`): the chat over the area, what it is told, what it may run,
//! and what becomes of what it proposes. Nothing is spawned and no agent is asked: a test
//! hands the answer in (`wizard_answer_for_test`), as the sessions' tests do.

use std::cell::RefCell;
use std::time::Instant;

use ratatui::crossterm::event::KeyCode;
use sentry_app::app::render_to_string;
use sentry_app::cfgarea::discover::Source;
use sentry_app::cfgarea::kind::Probe;
use sentry_app::cfgarea::{Page, Screen, Step, wizard};
use sentry_app::{App, Event};
use sentry_core::cfg::{self, By, FileId, Value};
use sentry_core::claude;
use sentry_core::tui::chat::Kind;

use crate::cfgcmd;
use crate::cfgtests::{
    candidates, config, first_run, network_draft, pending, probed, refused, save_box, server_draft,
    text,
};
use crate::tests::{ctrl, key, screen, typed};

/// What nothing sent to an agent or printed for one may hold: every address, MAC,
/// hostname, login and path the files and drafts below are full of.
const CANARIES: &[&str] = &[
    "192.0.2.",
    "198.51.100.",
    "203.0.113.",
    "2001:db8",
    "02:00:5e",
    "02:00:5E",
    "nas-box",
    "kids-phone",
    "secret-laptop",
    "myrouter",
    "edge-router",
    "internal-host",
    "admin@",
    "root@",
    "deploy@",
    "backup@",
    "someone",
    "/srv/stack",
    "/home/",
    "nmap",
    "rotate-keys",
    "age1qqqqqqqqexamplekeyexamplekey",
];

const C_APP: &str = "[maintenance]\nnotes = [\"/home/someone/notes/local.md\"]\n\
    [audit]\noutside = \"nmap -Pn {address} -p {ports} -S 203.0.113.50\"\n";

const C_SERVERS: &str = "servers:\n  myserver:\n    ssh: admin@192.0.2.10\n    \
    services: [app.service]\n    timers: [{unit: backup.timer, max_age: 26h}]\n    \
    compose: [{name: stack, file: /srv/stack/docker-compose.yml}]\n    \
    listeners: [\"198.51.100.7:8443/app\", \"*:22/sshd\"]\n    \
    actions: [{id: rotate, title: Rotate, run: \"ssh backup@203.0.113.9 rotate-keys\"}]\n    \
    maintenance:\n      notes: [/home/someone/notes/runbook.md]\n      \
    items: [{id: app, version_cmd: \"/home/someone/bin/app --version\", source: \"github:example/app\"}]\n";

const C_NETWORKS: &str = "networks:\n  saltednet:\n    router: {ssh: root@myrouter.lan}\n    \
    expect:\n      zones: {lan: [lan], wan: [wan]}\n      \
    forwards:\n        - {name: web, proto: tcp, port: 443, to: 192.0.2.20}\n        \
    - {name: bad, proto: tcp, port: 80, to: internal-host.lan}\n    \
    devices:\n      - {name: nas, mac: \"02:00:5e:00:53:01\", hostname: nas-box}\n      \
    - {hostname: kids-phone, private_mac: true}\n    \
    notes: [/home/someone/net.md]\n    \
    backup: {recipients: [age1qqqqqqqqexamplekeyexamplekey, /home/someone/keys/backup.pub]}\n  \
    rawnet:\n    router: {ssh: root@edge-router.lan}\n    \
    expect:\n      zones: {lan: [lan]}\n      \
    forwards: [{name: game, proto: udp, port: 27015, to: 192.0.2.99}]\n    \
    devices:\n      - {name: tv, mac: \"02:00:5e:00:53:44\", hostname: living-room-nas-box}\n";

/// `saltednet` has a salt (it was saved and looked at once); `rawnet` never had one.
fn salted() {
    let p = sentry_network::redact::path(&sentry_network::remote::scope("saltednet"));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, "07".repeat(16)).unwrap();
}

fn canary_files() -> [(FileId, &'static str); 3] {
    [
        (FileId::App, C_APP),
        (FileId::Servers, C_SERVERS),
        (FileId::Networks, C_NETWORKS),
    ]
}

fn clean(what: &str, text: &str) {
    for c in CANARIES {
        assert!(!text.contains(c), "{what} has `{c}`:\n{text}");
    }
}

/// `:add`, the hosts ticked, the box's Enter, and what each came to.
fn drafted(a: &mut App, hosts: &[(&str, Probe)]) {
    typed(a, ":add");
    key(a, KeyCode::Enter);
    assert_eq!(a.config.page, Page::Add);
    let cands: Vec<(&str, Source)> = hosts.iter().map(|(h, _)| (*h, Source::SshConfig)).collect();
    a.on_event(candidates(&cands), Instant::now());
    key(a, KeyCode::Char('a'));
    key(a, KeyCode::Enter);
    key(a, KeyCode::Enter);
    for (h, p) in hosts {
        a.on_event(probed(h, p.clone()), Instant::now());
    }
}

/// What the chat says, a line per entry.
fn said(a: &App) -> Vec<String> {
    a.config
        .chat
        .as_ref()
        .map(|c| {
            c.entries
                .iter()
                .map(|(k, t)| {
                    format!(
                        "{}: {t}",
                        match k {
                            Kind::You => "you",
                            Kind::Claude => "claude",
                            Kind::Info => "info",
                            Kind::Good => "good",
                            Kind::Err => "err",
                            _ => "tool",
                        }
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn answer(a: &mut App, text: &str) {
    a.config.wizard_answer_for_test(&mut a.win, text);
}

/// `A`, Enter, and the agent's answer.
fn ask(a: &mut App, text: &str) {
    key(a, KeyCode::Char('A'));
    key(a, KeyCode::Enter);
    answer(a, text);
}

fn by(a: &App) -> Vec<String> {
    a.config
        .pending
        .iter()
        .map(|p| {
            format!(
                "{} {}",
                match p.change.by {
                    By::You => "you",
                    By::Agent => "claude",
                },
                p.change.path
            )
        })
        .collect()
}

#[test]
fn a_opens_the_wizard_esc_hides_it_while_it_answers_and_a_brings_it_back() {
    let (mut a, _d) = config(&[]);
    // The key bar offers it, after what the screen does.
    let s = screen(&mut a);
    assert!(s.contains("s  save…   A  wizard   c  check"), "{s}");
    // A: the chat over the area, nothing sent yet: what would be is shown first.
    key(&mut a, KeyCode::Char('A'));
    assert!(a.config.wizard_visible());
    let c = a.config.chat.as_ref().unwrap();
    assert!(c.pending && !c.running());
    assert!(a.config.wizard_prompt_for_test().is_none(), "nothing sent");
    insta::assert_snapshot!("wizard_pending_158", screen(&mut a));
    insta::assert_snapshot!("wizard_pending_80", render_to_string(&mut a, 80, 30));
    // Tab: all of what would be sent, to read before it is.
    key(&mut a, KeyCode::Tab);
    let s = screen(&mut a);
    assert!(
        s.contains("Systems configured:") && s.contains("myserver (server)"),
        "{s}"
    );
    assert!(s.contains("Tab  fold what is sent"), "{s}");
    key(&mut a, KeyCode::Tab);
    assert!(!screen(&mut a).contains("Systems configured:"));
    // It has the keys: what is typed is its line, never a key of the area behind it.
    typed(&mut a, "sux2q?:");
    assert_eq!(a.config.chat.as_ref().unwrap().input, "sux2q?:");
    assert!(a.config.save.is_none() && a.config.screen == Screen::Overview);
    assert!(a.win.modal.is_none() && !a.win.quit);
    // A paste goes to its line too.
    a.on_event(Event::Paste(" pasted".into()), Instant::now());
    assert_eq!(a.config.chat.as_ref().unwrap().input, "sux2q?: pasted");
    // Esc before anything is sent: it is gone.
    key(&mut a, KeyCode::Esc);
    assert!(a.config.chat.is_none());
    // A, Enter: the brief and the question go; it answers.
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Enter);
    let sent = a.config.wizard_prompt_for_test().unwrap().to_string();
    assert!(
        sent.starts_with("sentry's Config tab, as the window shows it now."),
        "{sent}"
    );
    assert!(sent.contains("  screen: Overview"), "{sent}");
    assert!(sent.contains("  myserver (server)"), "{sent}");
    assert!(
        sent.ends_with(&format!("Question: {}", wizard::QUESTION)),
        "{sent}"
    );
    assert!(a.config.chat.as_ref().unwrap().running());
    // Esc while it answers hides it: it carries on, the area has its keys again, and the
    // key bar says where it is.
    key(&mut a, KeyCode::Esc);
    assert!(!a.config.wizard_visible() && a.config.chat.is_some());
    assert_eq!(
        a.toast_for_test(),
        Some("Claude carries on · A brings the chat back")
    );
    a.win.toast = None;
    let s = screen(&mut a);
    assert!(s.contains("A  Claude answering…"), "{s}");
    key(&mut a, KeyCode::Char('2'));
    assert_eq!(a.config.screen, Screen::Agent);
    // It answers out of sight: said once; A brings it back with the answer.
    answer(&mut a, "Nothing needs changing here.");
    assert_eq!(
        a.toast_for_test(),
        Some("Claude answered · A opens the chat")
    );
    a.win.toast = None;
    assert!(screen(&mut a).contains("A  Claude answered"));
    key(&mut a, KeyCode::Char('A'));
    assert!(a.config.wizard_visible());
    assert_eq!(
        said(&a),
        [
            "you: What would you do next here?",
            "claude: Nothing needs changing here.",
        ]
    );
    // A follow-up is what was typed, after the window as it is now (another screen).
    typed(&mut a, "and the agent?");
    key(&mut a, KeyCode::Enter);
    let sent = a.config.wizard_prompt_for_test().unwrap().to_string();
    assert!(sent.starts_with("The Config tab now:\n"), "{sent}");
    assert!(sent.contains("  screen: Agent"), "{sent}");
    assert!(sent.ends_with("From me: and the agent?"), "{sent}");
    // C-c stops the turn; it stays open, and it is never the quit box's key here.
    ctrl(&mut a, 'c');
    let c = a.config.chat.as_ref().unwrap();
    assert!(!c.running());
    assert_eq!(said(&a).last().unwrap(), "info: stopped");
    assert!(a.win.modal.is_none());
    // It can't be carried on elsewhere, and nothing can be granted in it.
    let keys: Vec<&str> = sentry_core::tui::chat::keys(c)
        .iter()
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(keys, ["Enter", "Esc", "↑↓ PgUp/Dn"]);
    // Another target and back: it is as it was.
    key(&mut a, KeyCode::F(1));
    assert!(!a.in_config);
    key(&mut a, KeyCode::F(3));
    assert!(a.config.wizard_visible());
    // Esc with nothing running closes it.
    key(&mut a, KeyCode::Esc);
    assert!(a.config.chat.is_none());
}

#[test]
fn without_an_agent_a_says_where_one_is_set_up() {
    let (mut a, _d) = config(&[]);
    claude::TEST_AVAILABLE.with(|c| c.set(false));
    let s = screen(&mut a);
    assert!(!s.contains("wizard"), "{s}");
    key(&mut a, KeyCode::Char('A'));
    assert!(a.config.chat.is_none());
    assert_eq!(
        a.toast_for_test(),
        Some("no agent is connected: screen 2 (Agent) sets one up")
    );
    claude::TEST_AVAILABLE.with(|c| c.set(true));
}

const PROPOSAL: &str = "The backup timer has no slack, and web.service isn't watched.\n\n\
```sentry-config\n\
[[set]]\npath = \"servers.myserver.timers[0].max_age\"\nvalue = \"30h\"\n\
why = \"it runs daily: 26h leaves little slack\"\n\
[[add]]\npath = \"servers.myserver.services\"\nvalue = \"web.service\"\nwhy = \"it serves the app\"\n\
[[set]]\npath = \"review.after_run\"\nvalue = false\nwhy = \"you said reviews are noisy\"\n\
[[set]]\npath = \"servers.myserver.nope\"\nvalue = 1\n\
[[set]]\npath = \"servers.myserver.timers[0].max_age\"\nvalue = \"soon\"\n\
[[add]]\npath = \"servers\"\nkey = \"other\"\nvalue = {}\n\
[[remove]]\npath = \"servers.myserver\"\n\
[[set]]\npath = \"agent.command\"\nvalue = \"/tmp/other-agent\"\n\
[[set]]\npath = \"agent.kind\"\nvalue = \"claude-code\"\n\
[[set]]\npath = \"review.at_start\"\nvalue = true\n\
```\n";

#[test]
fn what_the_wizard_proposes_is_staged_ticked_and_marked_and_what_does_not_hold_is_dropped() {
    let (mut a, d) = config(&[]);
    let before = text(&d, FileId::Servers);
    // Something of the user's own first: Review at start, on This machine.
    key(&mut a, KeyCode::Char('3'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('1'));
    assert_eq!(by(&a), ["you review.at_start"]);
    ask(&mut a, PROPOSAL);
    // What held is staged, ticked, the agent's; a list is one change of its setting.
    assert_eq!(
        by(&a),
        [
            "you review.at_start",
            "claude servers.myserver.timers",
            "claude review.after_run",
            "claude servers.myserver.services",
        ]
    );
    assert!(a.config.pending.iter().all(|p| p.change.on));
    assert_eq!(
        a.config.why_of("servers.myserver.timers"),
        Some("it runs daily: 26h leaves little slack")
    );
    assert_eq!(a.config.why_of("review.at_start"), None);
    // The chat says each one, each dropped one with why, and where they are.
    assert_eq!(
        said(&a),
        [
            "you: What would you do next here?",
            "claude: The backup timer has no slack, and web.service isn't watched.",
            "good: proposed: myserver · Timers · backup.timer · max_age 26h → 30h",
            "good: proposed: this machine · Review after a run · on → off",
            "good: proposed: myserver · Services · + web.service",
            "info: dropped: set servers.myserver.nope · no such setting (`sentry config \
             explain` lists them)",
            "info: dropped: set servers.myserver.timers[0].max_age · bad number in \"soon\"",
            "info: dropped: set agent.command · which program sentry starts as its agent is \
             yours alone to say",
            "info: dropped: set agent.kind · which program sentry starts as its agent is \
             yours alone to say",
            "info: dropped: set review.at_start · you changed this yourself",
            "info: dropped: add servers · adding a system goes through discovery: `+ add a \
             system` in the Overview",
            "info: dropped: remove servers.myserver · removing a system is yours: x on it in \
             the Overview",
            "info: 3 changes are in Pending, ticked and marked (Claude): Space on one in the \
             Overview unticks it · s saves · nothing is written before that",
        ]
    );
    insta::assert_snapshot!("wizard_answered_158", screen(&mut a));
    // Nothing is written by any of it.
    assert_eq!(text(&d, FileId::Servers), before);
    assert_eq!(text(&d, FileId::App), None);
    // Behind the chat: Pending, each marked, and the agent's reason beside its change.
    key(&mut a, KeyCode::Esc);
    for _ in 0..4 {
        key(&mut a, KeyCode::Char('j'));
    }
    let s = screen(&mut a);
    insta::assert_snapshot!("wizard_pending_rows_158", s);
    assert!(
        s.contains("Its reason: it runs daily: 26h leaves little slack"),
        "{s}"
    );
    assert_eq!(s.matches("(Claude)").count(), 3, "{s}");
    // Space unticks one of them (the services); the save box lists the agent's apart
    // from the user's, and says what is left out.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(
        pending(&a),
        [
            "x review.at_start",
            "x servers.myserver.timers",
            "x review.after_run",
            "- servers.myserver.services",
        ]
    );
    key(&mut a, KeyCode::Char('s'));
    assert_eq!(
        save_box(&a),
        [
            "  config.toml           this machine: Review at start, Review after a run  (a new file)",
            "  server_config.yaml    myserver: Timers",
            "",
            "  this machine · Review at start: off",
            "",
            "Proposed by Claude, not by you (2 changes; Esc, then Space on one in the Overview \
             unticks it):",
            "  this machine · Review after a run: on → off  (Claude)",
            "      its reason: you said reviews are noisy",
            "  myserver · Timers: backup.timer · max_age 26h → 30h  (Claude)",
            "      its reason: it runs daily: 26h leaves little slack",
            "",
            "What follows: reviews at start and after a run follow it from now · myserver \
             reads its settings again",
            "Kept before saving: server_config.yaml.bak-<UTC time> (beside it, the newest 5)",
            "! server_config.yaml was written by hand: its comments and layout are not kept.",
            "Left out, still staged: 1 unticked.",
        ]
    );
    insta::assert_snapshot!("wizard_save_box_158", screen(&mut a));
    // Enter writes what is ticked and only that.
    key(&mut a, KeyCode::Enter);
    let servers = text(&d, FileId::Servers).unwrap();
    assert!(servers.contains("max_age: 30h"), "{servers}");
    assert!(!servers.contains("web.service"), "{servers}");
    let app = text(&d, FileId::App).unwrap();
    assert!(
        app.contains("at_start = false") && app.contains("after_run = false"),
        "{app}"
    );
    assert!(!app.contains("agent"), "{app}");
    assert_eq!(pending(&a), ["- servers.myserver.services"]);
}

#[test]
fn a_proposal_that_does_not_parse_is_said_once_and_stages_nothing() {
    let (mut a, _d) = config(&[]);
    ask(
        &mut a,
        "Try this.\n\n```sentry-config\n[[set\npath = \n```\n",
    );
    assert!(a.config.pending.is_empty());
    let lines = said(&a);
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(lines[1], "claude: Try this.");
    assert!(
        lines[2].starts_with("info: dropped: the whole block · the proposal didn't parse: "),
        "{lines:?}"
    );
    // An answer with no block is just an answer.
    typed(&mut a, "ok");
    key(&mut a, KeyCode::Enter);
    answer(&mut a, "Nothing to change.");
    assert_eq!(said(&a).last().unwrap(), "claude: Nothing to change.");
    assert!(a.config.pending.is_empty());
}

/// What it asks for beyond its commands can never be allowed in this chat.
#[test]
fn a_refused_tool_call_stays_refused() {
    let (mut a, _d) = config(&[]);
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Enter);
    let c = a.config.chat.as_mut().unwrap();
    c.on_event(claude::Event::ToolUse {
        name: "Read".into(),
        input: "/etc/hostname".into(),
    });
    c.on_event(claude::Event::ToolResult {
        summary: "Claude requested permissions to read from /etc/hostname, but you haven't \
                  granted it yet."
            .into(),
        is_error: true,
    });
    answer(&mut a, "I couldn't read that.");
    let c = a.config.chat.as_ref().unwrap();
    assert!(c.requests.is_empty() && c.grants.is_empty());
    assert!(!c.can_allow());
    let lines = said(&a);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("refused. Nothing can be allowed here")),
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("Enter allows it")),
        "{lines:?}"
    );
    // Enter with nothing typed sends nothing and grants nothing.
    key(&mut a, KeyCode::Enter);
    assert!(!a.config.chat.as_ref().unwrap().running());
}

#[test]
fn the_chat_never_fights_a_box_a_field_being_edited_or_the_setup() {
    let (mut a, _d) = config(&[]);
    // The save box is in front: A isn't the wizard's key there, and the box is as it was.
    key(&mut a, KeyCode::Char('3'));
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Char('s'));
    assert!(a.config.save.is_some());
    key(&mut a, KeyCode::Char('A'));
    assert!(a.config.chat.is_none() && a.config.save.is_some());
    let s = screen(&mut a);
    assert!(!s.contains("wizard"), "{s}");
    key(&mut a, KeyCode::Esc);
    // A field being edited: A is a letter of its text.
    key(&mut a, KeyCode::Char('2'));
    key(&mut a, KeyCode::Char('j'));
    assert_eq!(a.config.field_for_test().as_deref(), Some("agent.command"));
    key(&mut a, KeyCode::Enter);
    typed(&mut a, "A");
    assert!(a.config.chat.is_none());
    assert!(a.config.takes_text());
    key(&mut a, KeyCode::Enter);
    assert!(pending(&a).contains(&"x agent.command".to_string()));
    // The `:` line: the same.
    typed(&mut a, ":A");
    assert!(a.config.chat.is_none());
    key(&mut a, KeyCode::Esc);
    // With the chat in front, nothing behind it gets a key: no save box, no undo, no
    // screen, no `:` line; and the window's own box (help, here) is over the chat.
    let staged = pending(&a);
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Enter);
    answer(&mut a, "Fine as it is.");
    for c in ['s', 'u', 'x', '1', ':', 'e'] {
        key(&mut a, KeyCode::Char(c));
    }
    assert_eq!(pending(&a), staged);
    assert!(a.config.save.is_none() && a.config.screen == Screen::Agent);
    assert_eq!(a.config.chat.as_ref().unwrap().input, "sux1:e");
    assert!(a.take_suspend().is_none(), "no editor was asked for");

    // The setup flow: A opens the same chat, told which step it is; Esc closes the chat,
    // not the setup, and Enter in it sends, it doesn't go on a step.
    let (mut a, _d) = first_run();
    assert_eq!(a.config.guide, Some(Step::Agent));
    let s = screen(&mut a);
    assert!(s.contains("A  wizard"), "{s}");
    key(&mut a, KeyCode::Char('A'));
    assert!(a.config.wizard_visible());
    let brief = a.config.wizard_brief();
    assert!(
        brief.contains("the setup flow, step 1 of 6: Agent"),
        "{brief}"
    );
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.guide, Some(Step::Agent), "Enter was the chat's");
    answer(&mut a, "Press Enter to test the agent.");
    key(&mut a, KeyCode::Char('b'));
    key(&mut a, KeyCode::Char('n'));
    assert_eq!(a.config.guide, Some(Step::Agent), "b and n were typed");
    key(&mut a, KeyCode::Backspace);
    key(&mut a, KeyCode::Backspace);
    key(&mut a, KeyCode::Esc);
    assert!(a.config.chat.is_none());
    assert!(a.config.ask.is_none(), "Esc didn't ask to leave the setup");
    assert_eq!(a.config.guide, Some(Step::Agent));
    // Behind it the flow is as it was: n goes on.
    key(&mut a, KeyCode::Char('n'));
    assert_eq!(a.config.guide, Some(Step::Machine));
}

/// On the Review step the wizard is told which draft is in view and may look at exactly
/// the hosts ticked; what it proposes for a draft is laid over it as its own change.
#[test]
fn in_the_review_the_wizard_proposes_over_the_draft_and_looks_only_at_what_was_ticked() {
    let (mut a, d) = config(&[]);
    let hosts = std::env::temp_dir().join(format!(
        "sentry-cfgwizard-{}-review/run/config-hosts",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(hosts.parent().unwrap().parent().unwrap());
    a.config.set_hosts_file(&hosts);
    drafted(
        &mut a,
        &[(
            "deploy@203.0.113.77",
            server_draft("deploy@203.0.113.77", "newbox"),
        )],
    );
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.config.page, Page::Review);
    let brief = a.config.wizard_brief();
    assert!(
        brief.contains("in front: the review of the drafted server `newbox`"),
        "{brief}"
    );
    assert!(
        brief.contains("  on the system: newbox (server)"),
        "{brief}"
    );
    assert!(
        brief.contains("    services (2): app.service, docker.service"),
        "{brief}"
    );
    assert!(
        brief.contains("`sentry config probe` may look at: newbox."),
        "{brief}"
    );
    clean("the brief", &brief);
    // Only the host that was ticked is in the list the command reads: the server that is
    // configured was never ticked here.
    assert_eq!(
        wizard::read_hosts(&hosts).unwrap(),
        [("srv:newbox".to_string(), "deploy@203.0.113.77".to_string())]
    );
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Enter);
    answer(
        &mut a,
        "Port 443 is open to all.\n```sentry-config\n[[remove]]\n\
         path = \"servers.newbox.listeners[1]\"\nvalue = \"*:443/*\"\nwhy = \"nothing serves it\"\n```",
    );
    assert_eq!(
        by(&a),
        ["you servers.newbox", "claude servers.newbox.listeners"]
    );
    assert!(
        said(&a).contains(&"good: proposed: newbox · Listeners · − *:443/*".to_string()),
        "{:?}",
        said(&a)
    );
    // Saved with it ticked: the draft, without that listener.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Esc);
    typed(&mut a, ":save");
    key(&mut a, KeyCode::Enter);
    let lines = save_box(&a);
    assert!(
        lines.contains(&"  newbox · Listeners: − *:443/*  (Claude)".to_string()),
        "{lines:?}"
    );
    key(&mut a, KeyCode::Enter);
    let servers = text(&d, FileId::Servers).unwrap();
    assert!(
        servers.contains("newbox:") && servers.contains("*:22/sshd"),
        "{servers}"
    );
    assert!(!servers.contains("*:443/*"), "{servers}");
    let _ = std::fs::remove_dir_all(hosts.parent().unwrap().parent().unwrap());
}

/// The list of hosts the wizard's `probe` may look at: written for this user alone when a
/// host is ticked and drafted, rewritten as that changes, gone when the window closes.
#[test]
fn the_hosts_ticked_here_are_listed_for_the_gateway_and_gone_at_close() {
    use std::os::unix::fs::PermissionsExt;
    let (mut a, _d) = config(&[]);
    let root = std::env::temp_dir().join(format!("sentry-cfgwizard-{}-hosts", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let hosts = root.join("run").join("config-hosts");
    a.config.set_hosts_file(&hosts);
    // Nothing ticked: nothing written, whatever is configured. A list left there by
    // someone else is not this window's: gone before a turn of its wizard starts.
    std::fs::create_dir_all(hosts.parent().unwrap()).unwrap();
    std::fs::write(&hosts, "srv:stale\tadmin@192.0.2.10\n").unwrap();
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Enter);
    assert!(!hosts.exists());
    answer(&mut a, "ok");
    key(&mut a, KeyCode::Esc);
    assert!(a.config.chat.is_none() && !hosts.exists());
    drafted(
        &mut a,
        &[
            (
                "deploy@203.0.113.77",
                server_draft("deploy@203.0.113.77", "newbox"),
            ),
            ("root@192.0.2.1", network_draft("root@192.0.2.1")),
            ("root@192.0.2.9", refused("root@192.0.2.9")),
        ],
    );
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(hosts.parent().unwrap()), 0o700);
    assert_eq!(mode(&hosts), 0o600);
    // What was drafted, by the name it has here; the one that refused is no system.
    assert_eq!(
        wizard::read_hosts(&hosts).unwrap(),
        [
            ("srv:newbox".to_string(), "deploy@203.0.113.77".to_string()),
            ("net:home".to_string(), "root@192.0.2.1".to_string()),
        ]
    );
    // One taken back is off the list.
    key(&mut a, KeyCode::Esc);
    assert_eq!(a.config.page, Page::None);
    for _ in 0..8 {
        key(&mut a, KeyCode::Char('j'));
    }
    key(&mut a, KeyCode::Char('u'));
    assert_eq!(pending(&a), ["x servers.newbox"]);
    assert_eq!(
        wizard::read_hosts(&hosts).unwrap(),
        [("srv:newbox".to_string(), "deploy@203.0.113.77".to_string())]
    );
    // The window closes: no list is left behind.
    sentry_core::tui::Ui::shutdown(&mut a);
    assert!(!hosts.exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// Files, staged changes and drafts full of addresses, MACs, hostnames, logins and paths:
/// none of it is in what the wizard is told.
#[test]
fn the_brief_has_no_address_mac_hostname_login_or_path() {
    salted();
    let (mut a, _d) = config(&canary_files());
    assert_eq!(
        a.config
            .problems
            .iter()
            .filter(|p| p.file == FileId::Networks)
            .count(),
        3,
        "{:?}",
        a.config.problems
    );
    // By hand: another host for the server, one more device, a notes file.
    a.config
        .stage(
            "servers.myserver.ssh",
            Some(Value::Str("root@198.51.100.99".into())),
            By::You,
        )
        .unwrap();
    let devices = a
        .config
        .doc(FileId::Networks)
        .unwrap()
        .tree()
        .at(&cfg::parse_path("networks.saltednet.devices").unwrap())
        .cloned()
        .unwrap();
    let Value::List(mut devices) = devices else {
        panic!("{devices}");
    };
    let mut more = devices[0].clone();
    more.set(
        &cfg::parse_path("mac").unwrap(),
        Some(Value::Str("02:00:5e:00:53:77".into())),
    )
    .unwrap();
    more.set(
        &cfg::parse_path("hostname").unwrap(),
        Some(Value::Str("secret-laptop".into())),
    )
    .unwrap();
    more.set(
        &cfg::parse_path("name").unwrap(),
        Some(Value::Str("laptop".into())),
    )
    .unwrap();
    devices.push(more);
    a.config
        .stage(
            "networks.saltednet.devices",
            Some(Value::List(devices)),
            By::You,
        )
        .unwrap();
    a.config
        .stage(
            "maintenance.notes",
            Some(Value::List(vec![Value::Str(
                "/home/someone/secret-plan.md".into(),
            )])),
            By::You,
        )
        .unwrap();
    // One of them unticked, so its values are read another way.
    a.config.tick(0);
    // Looked at here: a server and a router, their drafts saying what drafts say.
    let mut server = server_draft("deploy@203.0.113.77", "newbox");
    let mut router = network_draft("root@192.0.2.1");
    if let (Probe::Drafted(s), Probe::Drafted(r)) = (&mut server, &mut router) {
        s.notes.push(cfg::Note::whole(
            "Drafted by `sentry-server init` from deploy@203.0.113.77 (Debian GNU/Linux 12).",
        ));
        s.notes.push(cfg::Note::on(
            "listeners",
            "also on 2001:db8::5 and 198.51.100.7",
        ));
        s.what = "Debian GNU/Linux 12 at deploy@203.0.113.77".into();
        r.notes
            .push(cfg::Note::on("devices[0]", "holds 192.0.2.44 now"));
        r.notes.push(cfg::Note::on(
            "expect.forwards",
            "not taken: redirect to 192.0.2.61 from kids-phone",
        ));
        r.notes
            .push(cfg::Note::on("router", "reached as root@192.0.2.1"));
    }
    drafted(
        &mut a,
        &[("deploy@203.0.113.77", server), ("root@192.0.2.1", router)],
    );
    assert_eq!(a.config.drafts.len(), 2);
    let brief = a.config.wizard_brief();
    clean("the brief", &brief);
    insta::assert_snapshot!("wizard_brief_canary", brief);
    // What it keeps: the systems by name and kind, the names you gave things, counts.
    for kept in [
        "  myserver (server)",
        "  saltednet (network)",
        "  rawnet (network)",
        "  newbox (server) · staged to be added, not saved yet",
        "  home (network) · staged to be added, not saved yet",
        "rawnet: devices: 1 (1 named), not shown",
        "home: devices: 1 (0 named), not shown",
        "+ name = laptop, mac = redacted:",
        "…/secret-plan.md",
        "`sentry config probe` may look at: newbox, home.",
    ] {
        assert!(brief.contains(kept), "{kept}\n{brief}");
    }
    // And what is sent is that brief: the same text, through the same door.
    key(&mut a, KeyCode::Char('A'));
    key(&mut a, KeyCode::Enter);
    let sent = a.config.wizard_prompt_for_test().unwrap();
    assert!(sent.starts_with(&brief), "{sent}");
    clean("what is sent", sent);
    // The chat's own picture of it too (the brief's first lines are on screen).
    clean("the screen", &screen(&mut a).replace("F2 myserver", ""));
}

#[test]
fn show_agent_prints_the_files_with_everything_private_hidden() {
    salted();
    let (_a, d) = config(&canary_files());
    let f = cfgcmd::read_in(&d);
    let (text, bad) = cfgcmd::shown_for_agent(&f, &cfg::FILES);
    assert!(!bad, "{text}");
    clean("show-agent", &text);
    insta::assert_snapshot!("show_agent_canary", text);
    // The network that has no salt is refused, by name, with why and counts; the one that
    // has one is printed with its devices as tags and their names kept.
    assert!(
        text.contains("# `rawnet` is left out: not saved yet: its devices can't be shown"),
        "{text}"
    );
    assert!(!text.contains("  rawnet:"), "{text}");
    assert!(
        text.contains("# rawnet: devices: 1 (1 named), not shown"),
        "{text}"
    );
    assert!(
        text.contains("  saltednet:") && text.contains("name: nas"),
        "{text}"
    );
    assert!(text.contains("mac: redacted:"), "{text}");
    // Paths by their names, a public key by its start, commands and hosts not at all.
    for kept in [
        "…/docker-compose.yml",
        "…/runbook.md",
        "…/local.md",
        "…/backup.pub",
        "age1qqqq…",
        "ssh: ‹hidden›",
        "run: ‹hidden›",
        "to: ‹hidden›",
        "‹addr›:8443/app",
        "\"*:22/sshd\"",
    ] {
        assert!(text.contains(kept), "{kept}\n{text}");
    }
    // One file, by its word; a file that isn't there says so.
    let (one, _) = cfgcmd::shown_for_agent(&f, &[FileId::Servers]);
    assert!(one.starts_with("# ── server_config.yaml ──\n"), "{one}");
    assert!(!one.contains("config.toml"), "{one}");
    let (_a, d) = config(&[]);
    let f = cfgcmd::read_in(&d);
    let (none, bad) = cfgcmd::shown_for_agent(&f, &[FileId::Networks]);
    assert!(
        !bad && none.contains("(isn't there: no networks)"),
        "{none}"
    );
}

#[test]
fn probe_looks_only_at_a_host_ticked_in_the_window() {
    let hosts = vec![
        ("srv:newbox".to_string(), "deploy@203.0.113.77".to_string()),
        ("net:home".to_string(), "root@192.0.2.1".to_string()),
        ("srv:gone".to_string(), "root@192.0.2.9".to_string()),
    ];
    let asked: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let prober = |ssh: &str| {
        asked.borrow_mut().push(ssh.to_string());
        match ssh {
            "deploy@203.0.113.77" => {
                let mut p = server_draft(ssh, "x");
                if let Probe::Drafted(d) = &mut p {
                    d.notes.push(cfg::Note::whole(format!(
                        "Drafted by `sentry-server init` from {ssh} (Debian)."
                    )));
                    d.what = format!("Debian GNU/Linux 12 at {ssh}");
                }
                p
            }
            "root@192.0.2.1" => {
                let mut p = network_draft(ssh);
                if let Probe::Drafted(d) = &mut p {
                    d.notes
                        .push(cfg::Note::on("devices[0]", "holds 192.0.2.44 now"));
                }
                p
            }
            _ => refused(ssh),
        }
    };
    // No list (no window has hosts ticked), a host that isn't on it, what ssh connects to
    // instead of the system's name: refused, and nothing is looked at.
    for (name, list) in [
        ("newbox", None),
        ("myserver", Some(hosts.as_slice())),
        ("deploy@203.0.113.77", Some(hosts.as_slice())),
        ("192.0.2.1", Some(hosts.as_slice())),
        ("", Some(hosts.as_slice())),
    ] {
        let (code, text) = cfgcmd::probe_for_agent(name, list, &prober);
        assert_eq!(code, 126, "{name}: {text}");
        assert!(
            text.contains(
                "add it in the Config tab first: only hosts you ticked there can be looked at"
            ),
            "{text}"
        );
        clean("a refusal", &text);
    }
    assert!(asked.borrow().is_empty(), "{:?}", asked.borrow());
    // A server that was ticked: looked at, and its draft comes back as its file would
    // hold it, with nothing that names the host.
    let (code, server) = cfgcmd::probe_for_agent("newbox", Some(&hosts), &prober);
    assert_eq!(code, 0, "{server}");
    assert_eq!(*asked.borrow(), ["deploy@203.0.113.77"]);
    clean("a server's draft", &server);
    insta::assert_snapshot!("probe_server", server);
    // A router's, by its id: devices and zones counted, forwards without where they go.
    let (code, router) = cfgcmd::probe_for_agent("net:home", Some(&hosts), &prober);
    assert_eq!(code, 0, "{router}");
    clean("a router's draft", &router);
    insta::assert_snapshot!("probe_router", router);
    assert!(
        router.contains("# devices: 1 (0 named), not shown"),
        "{router}"
    );
    assert!(
        router.contains("name: web") && router.contains("to: ‹hidden›"),
        "{router}"
    );
    // One that can't be looked at: why, without what names it.
    let (code, failed) = cfgcmd::probe_for_agent("gone", Some(&hosts), &prober);
    assert_eq!(code, 1);
    assert!(failed.contains("gone couldn't be looked at: it refused this machine's key"));
    clean("a failed look", &failed);
    assert_eq!(asked.borrow().len(), 3);
}

/// The three commands the wizard is allowed are the ones `sentry config` has, and
/// `explain` is the settings' own documentation: nothing of any file is in it.
#[test]
fn the_wizards_commands_are_the_config_commands_and_explain_only_documents() {
    let allowed = wizard::profile().allowed;
    for sub in ["explain", "show-agent", "probe"] {
        assert!(
            allowed.contains(&format!("Bash(sentry config {sub}:*)")),
            "{sub}"
        );
    }
    assert_eq!(allowed.len(), 3);
    // (A setting's path is all `explain` takes: a server's name in it is never looked up.)
    let a = cfgcmd::explained("servers.myserver.timers").unwrap();
    let b = cfgcmd::explained("servers.someone-else.timers").unwrap();
    assert_eq!(a, b);
}

//! Security as a list: what needs attention, how the network is covered, what is shut,
//! and what Enter starts.

use super::*;
use crate::security::blocks;
use sentry_core::tui::input::Input;

fn list(a: &mut App, w: u16, h: u16) -> String {
    key(a, KeyCode::Char('4'));
    if net(a).screens.security.panels {
        key(a, KeyCode::Char('d'));
    }
    render_to_string(a, w, h)
}

/// A network nobody described, with everything Security reads.
fn busy() -> App {
    secured_with(messy(), the_flows())
}

/// With the network's workflows as they're seeded.
fn armed(mut a: App) -> App {
    let list = {
        let _turn = crate::workflow::seeding();
        crate::workflow::list_for(&crate::tui::id_of(NAME))
    };
    a.set_wf_entries(list);
    a
}

/// The row whose sentence has `what`, under the cursor (the `/` filter leaves only it).
fn on_row(a: &mut App, what: &str) -> String {
    key(a, KeyCode::Char('4'));
    key(a, KeyCode::Esc);
    typed(a, &format!("/{what}"));
    let s = render_to_string(a, 158, 41);
    assert!(s.contains(what), "no row with {what:?}:\n{s}");
    s
}

fn bar(s: &str) -> &str {
    s.lines().last().unwrap()
}

/// The run started from the list: its workflow and the action it was given.
fn started(a: &App) -> (String, String) {
    let run = wf(a).unwrap_or_else(|| panic!("no run: {:?}", a.toast_for_test()));
    (
        run.wf.name.clone(),
        run.run
            .state
            .vars
            .get("action")
            .cloned()
            .unwrap_or_default(),
    )
}

/// Another app may start a run: the network's runs directory holds one at a time.
fn runs_cleared() {
    let _ = std::fs::remove_dir_all(crate::workflow::root(&crate::tui::id_of(NAME)));
}

#[test]
fn security_list_wide() {
    let mut a = secured();
    let s = list(&mut a, 158, 41);
    insta::assert_snapshot!("threats_158x41", s);
    // The list first, in sentences, ranked; the count beside the screen's name is what
    // asks something of you.
    assert!(
        s.lines()
            .nth(1)
            .unwrap()
            .contains("4 Security 3   6 Maintenance"),
        "{s}"
    );
    assert!(
        s.contains("Needs attention · 4 · o shows 2 good to know"),
        "{s}"
    );
    // Numbered, the first three under "Start here", the rest under "Then"; under each
    // sentence, what Enter does.
    let at = |what: &str| s.lines().position(|l| l.contains(what)).unwrap();
    assert!(
        at("Start here") < at("│  1. look     The router refused a login 3 times in the last"),
        "{s}"
    );
    assert_eq!(
        at("│  1. look ") + 1,
        at("Enter: see the numbers behind it (nothing to change)"),
        "{s}"
    );
    assert!(
        at("│  3. look ") < at("│              Then")
            && at("│              Then")
                < at("│  4. note     Someone tried a wrong Wi-Fi password twice"),
        "{s}"
    );
    assert!(s.contains("Enter: set a new Wi-Fi password"), "{s}");
    // How the network is covered, a sentence and a state each.
    for said in [
        "✓ ok   2 doors are open from the internet, to 2 devices: web, phone",
        "✓ ok   The server's side (dmz) can't reach your home side (lan): the rules say so,",
        "✓ ok   Logging in to the router takes a key, and its admin page is encrypted",
    ] {
        assert!(s.contains(said), "{said}:\n{s}");
    }
    // The selected row: why it matters, what Enter does, and the panel with its numbers.
    assert!(s.contains("A refused login is the lock holding"), "{s}");
    assert!(
        s.contains("Ingress · the numbers · d shows them all"),
        "{s}"
    );
    assert!(s.contains("3 refused · 1 left before logging in"), "{s}");
    assert!(
        bar(&s).contains(
            "Enter  the numbers   x  expected   z  later   o  everything   S  audit   d  numbers"
        ),
        "{}",
        bar(&s)
    );
    // Nothing shut: no such panel.
    assert!(!s.contains("Blocked by you"), "{s}");
    // o: what is only good to know, too.
    key(&mut a, KeyCode::Char('o'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("Needs attention · 6 "), "{s}");
    assert!(
        s.contains("The list of bad sites doesn't update by itself"),
        "{s}"
    );
    assert!(bar(&s).contains("o  needed only"), "{}", bar(&s));
    // A row about a device: Egress, on that device.
    key(&mut a, KeyCode::Char('o'));
    key(&mut a, KeyCode::Char('j'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("telnet: unencrypted logins"), "{s}");
    assert!(
        s.contains("┌ Egress ·") && s.contains("! 192.0.2.77"),
        "{s}"
    );
    // `?`: the keys, how a change is made, and what isn't seen.
    key(&mut a, KeyCode::Char('?'));
    let help = render_to_string(&mut a, 158, 41);
    for what in [
        "never a bare switch",
        "undone by the router if it goes quiet",
        "what is inside the traffic",
    ] {
        assert!(help.contains(what), "{what}: {help}");
    }
}

#[test]
fn security_list_busy_and_narrow() {
    let mut a = busy();
    let s = list(&mut a, 158, 41);
    insta::assert_snapshot!("threats_busy_158x41", s);
    assert!(
        s.lines().nth(1).unwrap().contains("4 Security 7 "),
        "red: something is wrong now; naming devices isn't counted: {s}"
    );
    // What is wrong now comes first, and no act-now is under a look.
    let rank = |word: &str| -> Vec<usize> {
        s.lines()
            .enumerate()
            .filter(|(_, l)| l.contains(&format!(". {word}")))
            .map(|(i, _)| i)
            .collect()
    };
    let (now, look, note) = (rank("act now"), rank("look"), rank("note"));
    assert!(
        now.last() < look.first() && look.last() < note.first(),
        "{s}"
    );
    for said in [
        "│  1. act now  An unlisted door from the internet is open: game (udp port 8000-8010)",
        "Enter: close it, remove it, or say it's meant to be open",
        "The router's remote login (ssh) still accepts a password",
        "Enter: logins by key only (sentry checks its key works first)",
        "The router's admin page can be opened without encryption",
        "Enter: make the admin page use encryption (HTTPS)",
        // Two unnamed devices: two rows, housekeeping, last.
        "note     A device plugged into lan2 has no name yet: ",
        "Enter: name it if it's yours, or block or pause it",
        // What is weak in the cover points at its rows instead of saying it again.
        "! weak What the internet can reach: see 1 above",
        "! weak Logging in to the router: see 6 and 7 above",
        "! weak Who is on the network: see 8 and 9 above",
    ] {
        assert!(s.contains(said), "{said}:\n{s}");
    }
    // What only differs from the config's expectations is Maintenance's, not a threat.
    assert!(!s.contains("expect.zones"), "{s}");
    // Narrow: one column, nothing cut off the side; the list and the cover stay.
    let s = render_to_string(&mut a, 80, 24);
    insta::assert_snapshot!("threats_busy_80x24", s);
    assert!(s.lines().all(|l| l.chars().count() <= 80), "{s}");
    assert!(
        s.contains("Needs attention") && s.contains("How you're covered"),
        "{s}"
    );
}

#[test]
fn a_calm_page_says_so_and_still_says_how_you_are_covered() {
    // Nothing odd in the flows, nothing in the log.
    let mut f = the_flows();
    f.flows.retain(|x| x.dport != 23);
    let mut a = full();
    for secs in [0, 60] {
        data(
            &mut a,
            Kind::Counters,
            Ok(Payload::Counters(Box::new(counters_later(secs)))),
        );
    }
    data(&mut a, Kind::Flows, Ok(Payload::Flows(Box::new(f))));
    data(
        &mut a,
        Kind::SecLog,
        Ok(Payload::SecLog(Box::new(seclog::parse("")))),
    );
    data(
        &mut a,
        Kind::DnsState,
        Ok(Payload::DnsState(Box::new(
            dnsstate::parse(&fixture("network/dnsstate.txt")).unwrap(),
        ))),
    );
    let s = list(&mut a, 158, 41);
    insta::assert_snapshot!("threats_calm_158x41", s);
    assert!(
        s.contains("✓ Nothing needs you. How the network is covered is below."),
        "{s}"
    );
    assert!(
        s.contains("Needs attention · nothing needs you · o shows"),
        "{s}"
    );
    assert_eq!(s.matches("✓ ok ").count(), 7, "the whole cover: {s}");
    assert!(
        s.lines()
            .nth(1)
            .unwrap()
            .contains("4 Security   6 Maintenance"),
        "no count: {s}"
    );
    // No row needs you: the cursor is on the family filter's entry, the one thing to
    // choose on a calm page.
    assert!(bar(&s).starts_with(" Enter  choose devices"), "{}", bar(&s));
    // The Dashboard says the same in two words.
    key(&mut a, KeyCode::Char('1'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(line(&s, "│ security").contains("all quiet"), "{s}");
    // Before anything was read: reading, never "nothing needs you".
    let mut b = blank();
    let s = list(&mut b, 158, 41);
    assert!(
        s.contains("reading…") && !s.contains("Nothing needs you"),
        "{s}"
    );
}

#[test]
fn the_key_bar_names_what_enter_does_on_each_kind_of_row() {
    let mut a = busy();
    for (row, enter) in [
        ("An unlisted door from the internet", "Enter  close it"),
        ("remote login (ssh) still accepts", "Enter  keys only"),
        ("opened without encryption", "Enter  use HTTPS"),
        ("lan2 has no name yet", "Enter  decide"),
        ("a port ordinary devices rarely use", "Enter  the numbers"),
        ("wrong Wi-Fi password", "Enter  new password"),
    ] {
        let s = on_row(&mut a, row);
        assert!(bar(&s).contains(enter), "{row}: {}", bar(&s));
        assert!(
            bar(&s).contains("x  expected   z  later"),
            "{row}: {}",
            bar(&s)
        );
        // No ticks here: each row is its own decision.
        assert!(!bar(&s).contains("Space"), "{}", bar(&s));
    }
    // A finding with no fixed remedy: a session with Claude; without Claude Code, the
    // numbers.
    let s = on_row(&mut a, "open to the internet");
    assert!(bar(&s).contains("Enter  fix"), "{}", bar(&s));
    sentry_core::claude::TEST_AVAILABLE.with(|c| c.set(false));
    let s = render_to_string(&mut a, 158, 41);
    sentry_core::claude::TEST_AVAILABLE.with(|c| c.set(true));
    assert!(bar(&s).contains("Enter  the numbers"), "{}", bar(&s));
    // The blocklist, with what can wait shown.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('o'));
    let s = on_row(&mut a, "doesn't update by itself");
    assert!(bar(&s).contains("Enter  keep updated"), "{}", bar(&s));
}

fn audit_item(
    id: &str,
    state: sentry_core::secaudit::State,
    title: &str,
    targets: &[&str],
) -> sentry_core::secaudit::Item {
    sentry_core::secaudit::Item {
        id: id.into(),
        group: sentry_core::secaudit::Group::GettingIn,
        state,
        rank: 0,
        title: title.into(),
        why: format!(
            "The audit's why for {}.",
            id.split(':').nth(1).unwrap_or_default()
        ),
        fix: "Fix it.".into(),
        targets: targets.iter().map(|t| t.to_string()).collect(),
        evidence: vec!["seen by the audit".into()],
        brief: format!("Fix this finding of the security audit: {title}"),
        question: (state == sentry_core::secaudit::State::Ask).then(|| format!("q:{id}")),
    }
}

/// The security audit's items on this page: one row per subject. Where the page already
/// has the row (the one with the action), it stays, more urgent if the audit says so and
/// with the audit's why; what the page reads for itself isn't listed again; the rest are
/// rows of their own whose Enter fixes, answers, or goes to Maintenance.
#[test]
fn the_audits_items_join_the_pages_own_rows() {
    use sentry_core::secaudit::State;
    let me = crate::tui::id_of(NAME);
    let mut a = busy();
    let before = {
        let s = list(&mut a, 158, 60);
        s.matches("An unlisted door from the internet").count()
    };
    assert!(before >= 1);
    a.slot_mut().shared.sec_last = Some("2026-10-23T12:00:00Z".parse().unwrap());
    a.slot_mut().shared.sec = vec![
        // The page lists this door as one nobody listed: one row, with the action.
        audit_item(
            &format!("sec:door:{me}:udp:8000-8010"),
            State::DoFirst,
            "The internet can reach an old game server",
            &[&me, "srv:myserver"],
        ),
        // A door you listed has no row here: what answers behind it is the audit's.
        audit_item(
            &format!("sec:door:{me}:tcp:443"),
            State::Worth,
            "The internet can reach a web app that is behind",
            &[&me, "srv:myserver"],
        ),
        // The page reads who is on the network itself.
        audit_item(
            &format!("sec:unknown-devices:{me}"),
            State::Worth,
            "Devices nobody named are on the network",
            &[&me],
        ),
        // The page has its own row for password logins.
        audit_item(
            &format!("sec:ssh-password:{me}"),
            State::DoFirst,
            "The router's ssh login takes passwords",
            &[&me],
        ),
        // Nothing here says these: rows of the audit's own.
        audit_item(
            &format!("sec:flat:{me}"),
            State::Worth,
            "Every device at home shares one network",
            &[&me],
        ),
        audit_item(
            &format!("sec:restore:{me}"),
            State::Ask,
            "Have you ever restored from the backup?",
            &[&me],
        ),
        audit_item(
            &format!("sec:firmware:{me}"),
            State::Worth,
            "The router's firmware is behind",
            &[&me],
        ),
    ];
    let s = list(&mut a, 158, 60);
    // Not twice: the door, the unnamed devices, password logins.
    assert_eq!(
        s.matches("An unlisted door from the internet").count(),
        before,
        "{s}"
    );
    assert!(
        s.contains("The internet can reach a web app that is behind"),
        "{s}"
    );
    for gone in [
        "The internet can reach an old game server",
        "Devices nobody named are on the network",
        "The router's ssh login takes passwords",
    ] {
        assert!(!s.contains(gone), "{gone}:\n{s}");
    }
    assert!(s.contains("audited 3 days ago · S shows it"), "{s}");
    // The page's row has the action, and now the audit's why.
    let s = on_row(&mut a, "An unlisted door from the internet is open: game");
    assert!(bar(&s).contains("Enter  close it"), "{}", bar(&s));
    assert!(s.contains("The audit's why for door."), "{s}");
    let s = on_row(&mut a, "remote login (ssh) still accepts");
    assert!(
        s.contains("act now") && bar(&s).contains("Enter  keys only"),
        "{s}"
    );
    // The audit's own rows, and what Enter does on each.
    for (row, enter) in [
        ("Every device at home shares one network", "Enter  fix"),
        ("Have you ever restored from the backup?", "Enter  answer"),
        ("The router's firmware is behind", "Enter  Maintenance"),
    ] {
        let s = on_row(&mut a, row);
        assert!(bar(&s).contains(enter), "{row}: {}", bar(&s));
    }
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.slot().screen, ScreenId::Maint);
    // Put off like any row; marked expected, gone.
    let s = on_row(&mut a, "Every device at home shares one network");
    assert!(bar(&s).contains("x  expected   z  later"), "{}", bar(&s));
    key(&mut a, KeyCode::Char('b'));
    key(&mut a, KeyCode::Esc);
    let s = list(&mut a, 158, 60);
    assert!(
        !s.contains("Every device at home shares one network"),
        "{s}"
    );
}

#[test]
fn an_unknown_device_is_named_blocked_or_paused() {
    let _turn = runs();
    let mut a = armed(busy());
    let s = on_row(&mut a, "lan2 has no name yet");
    assert!(s.contains("block it or pause it"), "{s}");
    // Enter: one question.
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("threats_device_choice_158x41", s);
    for option in [
        "1  It's mine: give it a name",
        "2  Block it from the internet (it stays on your network)",
        "3  Block it from everything, the router included",
        "4  Pause its internet for an hour",
        "5  Pause its internet until tomorrow morning",
        "6  Look again in a week",
        "the router undoes the change by itself",
    ] {
        assert!(s.contains(option), "{option}:\n{s}");
    }
    assert!(!s.contains("Send it off the Wi-Fi"), "it is wired: {s}");
    // 1: a name, typed in the key bar. It lands in sentry's own file (nothing is written
    // in tests), counts as a device the config knows, and the row is gone.
    key(&mut a, KeyCode::Char('1'));
    assert!(
        matches!(a.win.input, Input::Prompt(..)),
        "a name is asked for"
    );
    assert!(bar(&render_to_string(&mut a, 158, 41)).contains("A name for "));
    let unnamed = |a: &App| {
        net(a)
            .store
            .clients
            .iter()
            .flatten()
            .filter(|c| c.unknown())
            .count()
    };
    assert_eq!(unnamed(&a), 2);
    typed(&mut a, "the old desktop");
    let toast = a.toast_for_test().unwrap_or_default().to_string();
    assert!(
        toast.contains("is now \"the old desktop\" on every screen")
            && toast.contains("names.toml")
            && toast.contains("network_config.yaml is yours and untouched"),
        "{toast}"
    );
    assert_eq!(unnamed(&a), 1);
    assert!(
        net(&a)
            .router
            .cfg
            .devices
            .iter()
            .any(|d| d.name.as_deref() == Some("the old desktop") && d.mac.is_some())
    );
    key(&mut a, KeyCode::Esc);
    let s = screen(&mut a, '2', 158, 41);
    assert!(
        s.contains("the old desktop"),
        "Clients shows it by name: {s}"
    );
    // A name that isn't one changes nothing.
    on_row(&mut a, "lan2 has no name yet");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('1'));
    typed(&mut a, "   ");
    assert_eq!(a.toast_for_test(), Some("not named: no name given"));
    assert_eq!(unnamed(&a), 1);

    // 4: paused for an hour. What is started is the security-action workflow, given a
    // tag (never the MAC); sentry notes here who the tag is and when the pause ends.
    on_row(&mut a, "lan2 has no name yet");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('4'));
    let (name, action) = started(&a);
    assert_eq!(name, "security-action");
    let tag = action
        .strip_prefix("block:")
        .and_then(|x| x.strip_suffix(":internet"))
        .unwrap_or_else(|| panic!("{action}"))
        .to_string();
    assert!(blocks::is_tag(&tag), "{action}");
    let b = &net(&a).store.blocks;
    let dev = &b.device[&tag];
    assert!(dev.mac.starts_with("0") && dev.zone == "lan", "{dev:?}");
    let now = a.win.now_override.unwrap().as_second();
    assert_eq!(
        (b.block[&tag].until, b.block[&tag].reach),
        (Some(now + 3600), blocks::Reach::Internet)
    );
    // It is followed on its own screen: the plan is shown first (a step that only
    // reads), and the change waits for Enter there. Auto never answers it.
    assert_eq!(a.slot().screen, ScreenId::Upgrade);
    let run = wf(&a).unwrap();
    assert_eq!(run.live.as_ref().map(|l| l.idx), Some(0), "the plan first");
    let s = render_to_string(&mut a, 200, 41);
    assert!(
        s.contains(&format!(
            "$ sentry-network security plan block:{tag}:internet"
        )),
        "{s}"
    );
    assert!(
        !s.contains(&dev_mac(&a, &tag)),
        "no MAC in the run's own words: {s}"
    );
    a.run_step_exit_for_test(0);
    let run = wf(&a).unwrap();
    assert!(
        matches!(run.next, Next::Confirm(1)) && run.live.is_none(),
        "{:?}",
        run.next
    );
    let step = &run.wf.steps[1];
    assert!(step.risky, "auto mode never confirms a risky step");
    // Auto on: it still waits for you.
    ctrl(&mut a, 'a');
    let run = wf(&a).unwrap();
    assert!(
        matches!(run.next, Next::Confirm(1)) && run.live.is_none(),
        "auto answered it: {:?}",
        run.next
    );
    ctrl(&mut a, 'a');
    // A second action while one runs: said, not started.
    on_row(&mut a, "remote login (ssh) still accepts");
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        a.toast_for_test(),
        Some("a workflow is already in progress (0 shows it): one at a time")
    );
    // Enter on the run's screen is the approval: the second step runs, and the run ends.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('0'));
    key(&mut a, KeyCode::Enter);
    let run = wf(&a).unwrap();
    assert_eq!(run.live.as_ref().map(|l| l.idx), Some(1), "{:?}", run.next);
    let s = render_to_string(&mut a, 200, 41);
    assert!(
        s.contains(&format!(
            "$ sentry-network security apply block:{tag}:internet"
        )),
        "{s}"
    );
    a.run_step_exit_for_test(0);
    assert!(wf(&a).is_none_or(|r| r.done()), "the run ended");

    // 3, on a fresh window: from everything.
    runs_cleared();
    let mut a = armed(busy());
    on_row(&mut a, "lan2 has no name yet");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('3'));
    let (_, action) = started(&a);
    assert!(
        action.starts_with("block:") && action.ends_with(":everything"),
        "{action}"
    );
    let tag = action.split(':').nth(1).unwrap().to_string();
    assert_eq!(net(&a).store.blocks.block[&tag].until, None);

    // 6: looked at again in a week (the later list Maintenance uses).
    runs_cleared();
    let mut a = armed(busy());
    on_row(&mut a, "lan2 has no name yet");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('6'));
    assert!(wf(&a).is_none());
    assert_eq!(
        a.slot().shared.later.values().next().map(|d| d.to_string()),
        Some("2026-11-02".to_string())
    );

    // Without the workflow (a network with its own set): said, nothing noted.
    let mut a = busy();
    on_row(&mut a, "lan2 has no name yet");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('2'));
    assert!(
        a.toast_for_test()
            .is_some_and(|t| t.starts_with("this network has no workflow security-action")),
        "{:?}",
        a.toast_for_test()
    );
    assert!(net(&a).store.blocks.block.is_empty() && wf(&a).is_none());
}

fn dev_mac(a: &App, tag: &str) -> String {
    net(a).store.blocks.device[tag].mac.clone()
}

/// The fixture's config with sentry's block on the dock, and the game forward switched
/// off.
fn shut_uci(tag: &str) -> crate::collect::uci::Uci {
    let text = fixture("network/uci.txt").replacen(
        "@@dropbear",
        &format!(
            "firewall.sentry_block_{tag}=rule\n\
             firewall.sentry_block_{tag}.name='sentry-block-{tag}'\n\
             firewall.sentry_block_{tag}.src='lan'\n\
             firewall.sentry_block_{tag}.src_mac='02:00:5e:00:53:22'\n\
             firewall.sentry_block_{tag}.dest='wan'\n\
             firewall.sentry_block_{tag}.target='REJECT'\n\
             firewall.@redirect[0].enabled='0'\n\
             @@dropbear"
        ),
        1,
    );
    crate::collect::uci::parse(&text, &crate::redact::Salt::fixed([7; 16]))
}

#[test]
fn blocked_by_you_lists_sentrys_rules_and_enter_unblocks() {
    let _turn = runs();
    let tag = blocks::tag(NAME, "02:00:5e:00:53:22").unwrap();
    let mut a = armed(secured());
    data(
        &mut a,
        Kind::Uci,
        Ok(Payload::Uci(Box::new(shut_uci(&tag)))),
    );
    let now = a.win.now_override.unwrap().as_second();
    {
        let (slot, _) = a.parts();
        let t: &mut NetworkTarget = slot.target.as_any_mut().downcast_mut().unwrap();
        let b = &mut t.store.blocks;
        b.device.insert(
            tag.clone(),
            blocks::Dev {
                mac: "02:00:5e:00:53:22".into(),
                label: "dock".into(),
                zone: "lan".into(),
                wifi: None,
            },
        );
        b.block.insert(
            tag.clone(),
            blocks::Note {
                since: now - 7200,
                until: Some(now + 1800),
                reach: blocks::Reach::Internet,
                why: "paused for an hour".into(),
            },
        );
        b.door.insert(
            "@redirect[0]".into(),
            blocks::Door {
                name: "game".into(),
                since: now - 86_400,
            },
        );
    }
    let s = list(&mut a, 158, 41);
    insta::assert_snapshot!("threats_blocked_158x41", s);
    assert!(s.contains("Blocked by you · 2"), "{s}");
    let row = line(&s, "│ dock");
    assert!(
        row.contains("from internet") && row.contains("paused, ends in 30 minutes"),
        "{row}"
    );
    assert!(line(&s, "│ door game").contains("since a day ago"), "{s}");
    // The cursor runs on from the list into it; Enter unblocks.
    for _ in 0..4 {
        key(&mut a, KeyCode::Char('j'));
    }
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("dock is blocked from the internet"), "{s}");
    assert!(s.contains("a pause: it ends in 30 minutes"), "{s}");
    assert!(bar(&s).starts_with(" Enter  unblock   "), "{}", bar(&s));
    assert!(!bar(&s).contains("later"), "{}", bar(&s));
    key(&mut a, KeyCode::Char('z'));
    assert_eq!(
        a.toast_for_test(),
        Some("Enter lifts it: there is nothing to put off or expect")
    );
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        started(&a),
        ("security-action".to_string(), format!("unblock:{tag}"))
    );

    // The pause ends: a row offers to lift it (the router has no timer of sentry's).
    runs_cleared();
    let mut a = armed(secured());
    data(
        &mut a,
        Kind::Uci,
        Ok(Payload::Uci(Box::new(shut_uci(&tag)))),
    );
    {
        let (slot, _) = a.parts();
        let t: &mut NetworkTarget = slot.target.as_any_mut().downcast_mut().unwrap();
        t.store.blocks.block.insert(
            tag.clone(),
            blocks::Note {
                since: now - 7200,
                until: Some(now - 60),
                reach: blocks::Reach::Internet,
                why: "paused for an hour".into(),
            },
        );
    }
    let s = on_row(&mut a, "The pause on");
    assert!(s.contains("has ended: it is still blocked"), "{s}");
    assert!(bar(&s).contains("Enter  unblock"), "{}", bar(&s));
    assert!(!bar(&s).contains("expected"), "{}", bar(&s));
    assert!(line(&s, "from internet").contains("pause ended"), "{s}");
    key(&mut a, KeyCode::Enter);
    assert_eq!(started(&a).1, format!("unblock:{tag}"));

    // The door closed from here: Enter opens it again.
    runs_cleared();
    let mut a = armed(secured());
    data(
        &mut a,
        Kind::Uci,
        Ok(Payload::Uci(Box::new(shut_uci(&tag)))),
    );
    {
        let (slot, _) = a.parts();
        let t: &mut NetworkTarget = slot.target.as_any_mut().downcast_mut().unwrap();
        t.store.blocks.door.insert(
            "@redirect[0]".into(),
            blocks::Door {
                name: "game".into(),
                since: now - 86_400,
            },
        );
    }
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Char('G'));
    // (The last row is the family filter's entry: the door is just above it.)
    key(&mut a, KeyCode::Char('k'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("The door game is closed"), "{s}");
    assert!(bar(&s).starts_with(" Enter  open again   "), "{}", bar(&s));
    key(&mut a, KeyCode::Enter);
    assert_eq!(started(&a).1, "forward-on:@redirect[0]");
}

#[test]
fn enter_starts_each_action_as_its_plan() {
    let _turn = runs();
    // A door nobody listed: close it, remove it, or say it is meant.
    let mut a = armed(busy());
    on_row(&mut a, "An unlisted door from the internet");
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    for option in [
        "The door game · pick one (1–3, n cancels)",
        "1  Close it for now (it can be opened again from here)",
        "2  Remove it from the router",
        "3  It is meant to be open: expected",
    ] {
        assert!(s.contains(option), "{option}:\n{s}");
    }
    key(&mut a, KeyCode::Char('1'));
    assert_eq!(
        started(&a),
        (
            "security-action".to_string(),
            "forward-off:@redirect[0]".to_string()
        )
    );
    assert_eq!(net(&a).store.blocks.door["@redirect[0]"].name, "game");
    runs_cleared();
    let mut a = armed(busy());
    on_row(&mut a, "An unlisted door from the internet");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('2'));
    assert_eq!(started(&a).1, "forward-remove:@redirect[0]");
    assert!(net(&a).store.blocks.door.is_empty());
    let mut b = armed(busy());
    on_row(&mut b, "An unlisted door from the internet");
    key(&mut b, KeyCode::Enter);
    key(&mut b, KeyCode::Char('3'));
    assert_eq!(b.toast_for_test(), Some("marked expected (baseline.toml)"));
    assert!(wf(&b).is_none());

    // ssh with keys only, the admin page on HTTPS: straight to the plan.
    for (row, action) in [
        ("remote login (ssh) still accepts", "ssh-keys-only"),
        ("opened without encryption", "admin-https"),
    ] {
        runs_cleared();
        let mut a = armed(busy());
        let s = on_row(&mut a, row);
        assert!(s.contains("Enter: "), "{s}");
        key(&mut a, KeyCode::Enter);
        assert_eq!(
            started(&a),
            ("security-action".to_string(), action.to_string()),
            "{row}"
        );
        assert!(asks_nothing(&a), "no box in between");
    }

    // The blocklist: its schedule (the fixture's list is fresh, and doesn't update).
    runs_cleared();
    let mut a = armed(secured());
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Char('o'));
    on_row(&mut a, "doesn't update by itself");
    key(&mut a, KeyCode::Enter);
    assert_eq!(started(&a).1, "blocklist-schedule");
    // Old as well: fetch it now, or its schedule, as one question.
    runs_cleared();
    let mut a = armed(secured());
    let mut dns = dnsstate::parse(&fixture("network/dnsstate.txt")).unwrap();
    dns.now += 40 * 86_400;
    data(&mut a, Kind::DnsState, Ok(Payload::DnsState(Box::new(dns))));
    let s = on_row(&mut a, "The list of bad sites is 54 days old");
    assert!(bar(&s).contains("Enter  refresh"), "{}", bar(&s));
    assert!(
        s.contains("! weak Filtering of bad sites: see 1 above"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("1  Fetch it again now") && s.contains("2  Turn on its own scheduled update"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('1'));
    assert_eq!(started(&a).1, "blocklist-refresh");
}

#[test]
fn a_new_wifi_password_is_typed_as_dots_and_goes_through_the_guard() {
    const SECRET: &str = "a new long passphrase";
    let _turn = runs();
    let mut a = armed(secured());
    let s = on_row(&mut a, "wrong Wi-Fi password");
    assert!(
        s.contains("a new one the fix if you think it got out"),
        "{s}"
    );
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("1  Change the password of Example Net")
            && s.contains("2  Look again in a week"),
        "{s}"
    );
    assert!(
        s.contains("goes through the guard and waits for your"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('1'));
    for c in SECRET.chars() {
        key(&mut a, KeyCode::Char(c));
    }
    let s = render_to_string(&mut a, 200, 41);
    assert!(!s.contains(SECRET), "{s}");
    assert!(
        bar(&s).contains(&format!(
            "The new password for Example Net (8–63 characters): {}",
            "•".repeat(SECRET.chars().count())
        )),
        "{}",
        bar(&s)
    );
    key(&mut a, KeyCode::Enter);
    // The guarded-change workflow, on every access point of that name; what is written
    // down has the tag, never the value.
    let run = wf(&a).unwrap_or_else(|| panic!("no run: {:?}", a.toast_for_test()));
    assert_eq!(run.wf.name, "guarded-change");
    let vars = &run.run.state.vars;
    assert_eq!(
        (vars["configs"].as_str(), vars["services"].as_str()),
        ("wireless", "wifi")
    );
    assert!(
        vars["lines"].starts_with("uci set wireless.default_radio0.key=redacted:")
            && vars["lines"].contains("; uci set wireless.default_radio1.key=redacted:"),
        "{}",
        vars["lines"]
    );
    // (Its third step asks before a Wi-Fi change is kept.)
    assert_eq!(run.wf.steps[2].id, "keep");
    let s = render_to_string(&mut a, 200, 41);
    assert!(!s.contains(SECRET), "{s}");

    // One that WPA wouldn't take: said, nothing started.
    runs_cleared();
    let mut a = armed(secured());
    on_row(&mut a, "wrong Wi-Fi password");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('1'));
    typed(&mut a, "short");
    assert_eq!(
        a.toast_for_test(),
        Some("not changed: a Wi-Fi password is 8 to 63 characters")
    );
    assert!(wf(&a).is_none());
}

#[test]
fn a_row_dismissed_here_is_dismissed_on_maintenance() {
    let mut a = busy();
    let s = screen(&mut a, '6', 158, 41);
    assert!(s.contains("ssh accepts passwords"), "{s}");
    assert!(s.contains("the web interface"), "{s}");
    // b: expected, at once. One baseline: Maintenance stops listing the finding too.
    on_row(&mut a, "remote login (ssh) still accepts");
    key(&mut a, KeyCode::Char('b'));
    assert_eq!(a.toast_for_test(), Some("marked expected (baseline.toml)"));
    assert!(
        a.slot()
            .shared
            .baseline
            .findings
            .contains(&"net:ssh:password".to_string())
    );
    key(&mut a, KeyCode::Esc);
    let s = render_to_string(&mut a, 158, 41);
    assert!(!s.contains("remote login (ssh) still accepts"), "{s}");
    // (The cover is still weak: expected isn't fixed. It points at the row that is left.)
    assert!(s.contains("! weak Logging in to the router: see "), "{s}");
    let s = screen(&mut a, '6', 158, 41);
    assert!(!s.contains("ssh accepts passwords"), "{s}");
    // x asks first.
    on_row(&mut a, "opened without encryption");
    key(&mut a, KeyCode::Char('x'));
    assert!(a.box_yes_for_test().is_some(), "a box");
    key(&mut a, KeyCode::Char('y'));
    assert_eq!(a.toast_for_test(), Some("marked expected (baseline.toml)"));
    // z: later. The same key in the same list as Maintenance's row for the finding.
    on_row(&mut a, "An unlisted door from the internet");
    key(&mut a, KeyCode::Char('z'));
    key(&mut a, KeyCode::Char('1'));
    let later: Vec<&String> = a.slot().shared.later.keys().collect();
    assert_eq!(later, ["finding:net:forward:udp:8000-8010"]);
    key(&mut a, KeyCode::Esc);
    let s = render_to_string(&mut a, 158, 41);
    assert!(!s.contains("A door from the internet"), "{s}");
    let s = screen(&mut a, '6', 158, 41);
    assert!(
        !s.lines().any(|l| l.contains("│ now") && l.contains("game")),
        "{s}"
    );
    // A row that isn't a finding is dismissed by its own key, in the same baseline.
    on_row(&mut a, "wrong Wi-Fi password");
    key(&mut a, KeyCode::Char('b'));
    assert!(
        a.slot()
            .shared
            .baseline
            .findings
            .contains(&"sec:wifi:psk".to_string())
    );
    key(&mut a, KeyCode::Esc);
    assert!(!render_to_string(&mut a, 158, 41).contains("wrong Wi-Fi password"));
}

#[test]
fn a_finding_without_a_fixed_remedy_is_a_session_with_claude() {
    let mut a = busy();
    on_row(&mut a, "open to the internet");
    key(&mut a, KeyCode::Enter);
    let s = a.apply_session().expect("a session");
    let ap = s.chat.ask.applying().expect("applying").clone();
    assert_eq!(ap.finding.as_deref(), Some("net:listener:udp:1900"));
    // A router's session: its plan is always yours to approve, the audit says whether
    // it is gone.
    assert!(ap.asks_each && ap.reaudits && ap.remote);
    assert!(s.chat.ask.context.contains("net:listener:udp:1900"));
    // Without Claude Code: the numbers behind it.
    let mut a = busy();
    sentry_core::claude::TEST_AVAILABLE.with(|c| c.set(false));
    on_row(&mut a, "open to the internet");
    key(&mut a, KeyCode::Enter);
    sentry_core::claude::TEST_AVAILABLE.with(|c| c.set(true));
    assert!(a.apply_session().is_none());
    assert!(net(&a).screens.security.panels);
    assert_eq!(
        a.toast_for_test(),
        Some("the numbers behind it · d brings the list back")
    );
}

#[test]
fn the_numbers_are_one_key_away_and_back() {
    let mut a = secured();
    let s = list(&mut a, 158, 41);
    assert!(
        s.contains("Needs attention") && !s.contains("┌ Segmentation"),
        "{s}"
    );
    key(&mut a, KeyCode::Char('d'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("┌ Segmentation") && s.contains("┌ Egress") && !s.contains("Needs attention"),
        "{s}"
    );
    assert!(bar(&s).contains("d  the list"), "{}", bar(&s));
    // Each view has its own cursor.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('d'));
    assert_eq!(
        (
            net(&a).screens.security.cur.sel,
            net(&a).screens.security.pcur.sel
        ),
        (0, 2)
    );
    // Esc on the numbers is the way back too.
    key(&mut a, KeyCode::Char('d'));
    key(&mut a, KeyCode::Esc);
    assert!(!net(&a).screens.security.panels);
    // The cursor stays on its row when the list changes above it.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    let before = render_to_string(&mut a, 158, 41);
    assert!(before.contains("A login that worked"), "{before}");
    let mut f = the_flows();
    f.flows.retain(|x| x.dport != 23);
    data(&mut a, Kind::Flows, Ok(Payload::Flows(Box::new(f))));
    let after = render_to_string(&mut a, 158, 41);
    assert!(!after.contains("ordinary devices rarely use"), "{after}");
    assert!(after.contains("A login that worked"), "{after}");
}

fn net_mut(a: &mut App) -> &mut NetworkTarget {
    a.slot_mut()
        .target
        .as_any_mut()
        .downcast_mut()
        .expect("the network")
}

/// `n` devices nobody has named beside whatever the network has, every one first seen
/// weeks ago: every other one plugged in, the rest on the Wi-Fi.
fn unnamed(a: &mut App, n: usize) {
    let now = a.win.now_override.unwrap().as_second();
    let list = net_mut(a).store.clients.as_mut().unwrap();
    let base = list.iter().find(|c| c.mac.is_some()).unwrap().clone();
    for c in list.iter_mut() {
        c.first_seen = Some(now - 40 * 86_400);
    }
    for i in 0..n {
        let mac = format!("00:00:5e:00:54:{i:02x}");
        list.push(crate::clients::Client {
            key: mac.clone(),
            mac: Some(mac),
            name: None,
            known: false,
            private: false,
            flagged: true,
            leave_alone: false,
            hostname: Some(format!("thing-{i}")),
            addrs: vec![format!("192.0.2.{}", 200 + i)],
            link: if i % 2 == 1 {
                crate::clients::Link::Wifi {
                    ifname: "phy0-ap0".into(),
                    signal: None,
                }
            } else {
                crate::clients::Link::Wired {
                    port: "lan3".into(),
                }
            },
            first_seen: Some(now - 30 * 86_400),
            connected_s: None,
            ..base.clone()
        });
    }
}

/// A network like the one this page was first judged on: one thing to act on now (the
/// router's firmware has security fixes waiting), then password logins, the admin page
/// without encryption, CrowdSec's blocker off, packages, a log lost on restart, one flat
/// network, no backup, three doors to answer for, and seven devices nobody has named.
fn the_users_shape() -> App {
    use sentry_core::secaudit::State;
    let me = crate::tui::id_of(NAME);
    let mut f = the_flows();
    f.flows.retain(|x| x.dport != 23);
    let mut a = full_with(&fx_cfg(), |c| {
        let mut s = audit::tests::snap(c);
        let text = fixture("network/uci.txt")
            .replace(
                "dropbear.main.PasswordAuth='off'",
                "dropbear.main.PasswordAuth='on'",
            )
            .replace(
                "uhttpd.main.redirect_https='1'",
                "uhttpd.main.redirect_https='0'",
            );
        s.uci = Some(crate::collect::uci::parse(
            &text,
            &crate::redact::Salt::fixed([7; 16]),
        ));
        s
    });
    for secs in [0, 60] {
        data(
            &mut a,
            Kind::Counters,
            Ok(Payload::Counters(Box::new(counters_later(secs)))),
        );
    }
    data(&mut a, Kind::Flows, Ok(Payload::Flows(Box::new(f))));
    data(
        &mut a,
        Kind::SecLog,
        Ok(Payload::SecLog(Box::new(seclog::parse("")))),
    );
    data(
        &mut a,
        Kind::DnsState,
        Ok(Payload::DnsState(Box::new(
            dnsstate::parse(&fixture("network/dnsstate.txt")).unwrap(),
        ))),
    );
    let off = crate::collect::crowdsec::Bouncer {
        enabled: Some(false),
        ..Default::default()
    };
    data(&mut a, Kind::Crowdsec, Ok(Payload::Crowdsec(Some(off))));
    unnamed(&mut a, 7);
    let item = |what: &str, state, title: &str| {
        let mut i = audit_item(&format!("sec:{what}:{me}"), state, title, &[&me]);
        i.why = String::new();
        i
    };
    a.slot_mut().shared.sec_last = Some("2026-10-23T12:00:00Z".parse().unwrap());
    a.slot_mut().shared.sec = vec![
        item(
            "firmware",
            State::DoFirst,
            "The router's firmware has security fixes waiting",
        ),
        item(
            "ssh-password",
            State::Worth,
            "The router's ssh login takes passwords",
        ),
        item(
            "admin-http",
            State::Worth,
            "The router's admin page is plain HTTP",
        ),
        item(
            "unknown-devices",
            State::Worth,
            "Devices nobody named are on the network",
        ),
        item(
            "packages",
            State::Worth,
            "12 of the router's packages can be updated",
        ),
        item(
            "logs",
            State::Worth,
            "The router forgets its log when it restarts",
        ),
        item(
            "flat",
            State::Worth,
            "Every device at home shares one network",
        ),
        item(
            "backup",
            State::Worth,
            "There is no backup of the router's configuration",
        ),
        item(
            "door:tcp:443",
            State::Ask,
            "Does the web app behind port 443 ask for a login?",
        ),
        item(
            "door:tcp:8443",
            State::Ask,
            "Does the app behind port 8443 ask for a login?",
        ),
        item(
            "door:udp:8000-8010",
            State::Ask,
            "Does the game server behind ports 8000-8010 ask for a login?",
        ),
    ];
    a
}

/// The page that was "17 equal look rows led by seven devices": ten rows now, what to do
/// first, second and third said, the devices and the questions one row each at the end.
#[test]
fn the_page_says_what_to_do_first_second_and_third() {
    let mut a = the_users_shape();
    let s = list(&mut a, 158, 41);
    insta::assert_snapshot!("threats_users_shape_158x41", s);
    let rows: Vec<&str> = s
        .lines()
        .filter_map(|l| l.strip_prefix("│ "))
        .filter(|l| l.get(2..4) == Some(". "))
        .map(|l| l.split('│').next().unwrap().trim())
        .collect();
    let want = [
        " 1. act now  The router's firmware has security fixes waiting",
        " 2. look     12 of the router's packages can be updated",
        " 3. look     The router's remote login (ssh) still accepts a password",
        " 4. look     The router's admin page can be opened without encryption",
        " 5. look     CrowdSec is installed on the router but switched off: known attackers",
        " 6. look     Every device at home shares one network",
        " 7. look     The router forgets its log when it restarts",
        " 8. look     There is no backup of the router's configuration",
        " 9. note     7 devices have no name yet: 4 plugged in, 3 on Wi-Fi",
        "10. note     3 doors from the internet: tell sentry whether each asks for a login",
    ];
    assert_eq!(rows.len(), want.len(), "{rows:#?}");
    for (got, want) in rows.iter().zip(want) {
        assert!(got.starts_with(want.trim_start()), "{want}:\n{rows:#?}");
    }
    // The first three are where to start; the rest follow.
    let at = |what: &str| s.lines().position(|l| l.contains(what)).unwrap();
    assert!(
        at("Start here") < at(" 1. act now")
            && at(" 3. look") < at("│              Then")
            && at("│              Then") < at(" 4. look"),
        "{s}"
    );
    // Each says what Enter does, under its sentence.
    for (row, step) in [
        (
            " 1. act now",
            "Enter: update the router's software (Maintenance does it)",
        ),
        (
            " 3. look",
            "Enter: logins by key only (sentry checks its key works first)",
        ),
        (
            " 9. note",
            "Enter: go through them (name, block or pause each)",
        ),
        ("10. note", "Enter: answer them one after another"),
    ] {
        assert!(
            s.lines().nth(at(row) + 1).unwrap().contains(step),
            "{row}: {step}\n{s}"
        );
    }
    // Only what asks something is counted beside the screen's name: not housekeeping.
    assert!(s.lines().nth(1).unwrap().contains("4 Security 8 "), "{s}");
    assert!(s.contains("Needs attention · 10 "), "{s}");
    // What is weak in the cover points at its row.
    for said in [
        "! weak Who is on the network: see 9 above",
        "! weak Logging in to the router: see 3 and 4 above",
        "✗ off  Blocking attackers at the router: see 5 above",
    ] {
        assert!(s.contains(said), "{said}:\n{s}");
    }
    // Narrow: the three to start with are all there.
    let s = render_to_string(&mut a, 80, 24);
    insta::assert_snapshot!("threats_users_shape_80x24", s);
    assert!(s.lines().all(|l| l.chars().count() <= 80), "{s}");
    assert!(
        s.contains(" 1. act now") && s.contains(" 3. look") && s.contains("Start here"),
        "{s}"
    );
}

/// Enter on "7 devices…" lists them in the page's place. Each is its own decision, with
/// the same question as a device's own row; naming one keeps the list open, one shorter.
#[test]
fn the_unnamed_devices_are_gone_through_in_one_list() {
    let _turn = runs();
    let mut a = armed(the_users_shape());
    let unnamed = |a: &App| {
        net(a)
            .store
            .clients
            .iter()
            .flatten()
            .filter(|c| c.unknown())
            .count()
    };
    assert_eq!(unnamed(&a), 7);
    let s = on_row(&mut a, "devices have no name yet");
    assert!(bar(&s).contains("Enter  list them"), "{}", bar(&s));
    // Several as one can't be marked expected: each of them can.
    assert!(!bar(&s).contains("x  expected"), "{}", bar(&s));
    assert!(s.contains("thing-0") && s.contains("thing-6"), "{s}");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Esc);
    assert_eq!(
        net(&a).screens.security.group.as_deref(),
        Some("group:devices"),
        "Esc took the filter away, the list is still open"
    );
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("threats_devices_open_158x41", s);
    assert!(s.contains("┌ 7 devices with no name yet · Esc back"), "{s}");
    assert!(
        s.contains("A device plugged into lan3 has no name yet: thing-0")
            && s.contains("A device on the Wi-Fi has no name yet: thing-1")
            && s.contains("Enter: name it if it's yours, or block or pause it"),
        "{s}"
    );
    assert!(
        bar(&s).contains("Enter  decide") && bar(&s).contains("Esc  back"),
        "{}",
        bar(&s)
    );
    // The first: it's mine, a name. The list stays, with six.
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("1  It's mine: give it a name"), "{s}");
    key(&mut a, KeyCode::Char('1'));
    typed(&mut a, "the printer");
    assert_eq!(unnamed(&a), 6);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("┌ 6 devices with no name yet · Esc back")
            && !s.contains("no name yet: thing-0"),
        "{s}"
    );
    // The next one is under the cursor already: another name, five left.
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('1'));
    typed(&mut a, "the tv");
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("┌ 5 devices with no name yet"), "{s}");
    // Esc: the page again, on the row that is now five.
    key(&mut a, KeyCode::Esc);
    assert!(net(&a).screens.security.group.is_none());
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("5 devices have no name yet: 3 plugged in, 2 on Wi-Fi"),
        "{s}"
    );
    // (The cursor is on it: its detail says what Enter does.)
    assert!(s.contains("Enter: the list of them."), "{s}");
    // Down to two: still the list while it is open; closed, they are rows of their own.
    key(&mut a, KeyCode::Enter);
    for name in ["a", "b", "c"] {
        key(&mut a, KeyCode::Enter);
        key(&mut a, KeyCode::Char('1'));
        typed(&mut a, &format!("thing {name}"));
    }
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("┌ 2 devices with no name yet"), "{s}");
    // Pausing one from the list is the same action its own row starts: a block with an
    // end, by tag.
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("4  Pause its internet for an hour"), "{s}");
    key(&mut a, KeyCode::Char('4'));
    let (name, action) = started(&a);
    assert_eq!(name, "security-action");
    assert!(
        action.starts_with("block:") && action.ends_with(":internet"),
        "{action}"
    );
    let tag = action.split(':').nth(1).unwrap();
    assert!(blocks::is_tag(tag), "{action}");
    assert!(net(&a).store.blocks.block[tag].until.is_some());
    // Back on the page, the two that are left are two rows.
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Esc);
    let s = render_to_string(&mut a, 158, 41);
    assert!(net(&a).screens.security.group.is_none(), "{s}");
    assert_eq!(s.matches(". note     A device ").count(), 2, "{s}");
    assert!(!s.contains("devices have no name yet"), "{s}");
}

/// The doors to answer for are one row and one list; a list whose last row is gone
/// closes by itself.
#[test]
fn the_doors_are_answered_in_one_list() {
    let mut a = the_users_shape();
    let s = on_row(&mut a, "doors from the internet: tell sentry");
    assert!(bar(&s).contains("Enter  list them"), "{}", bar(&s));
    assert!(
        s.contains("Does the web app behind port 443 ask for a login?"),
        "the detail names them: {s}"
    );
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Esc);
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("threats_doors_open_158x41", s);
    assert!(s.contains("┌ 3 doors from the internet · Esc back"), "{s}");
    assert_eq!(
        s.matches("Enter: answer yes, no, or don't know").count(),
        3,
        "{s}"
    );
    assert!(
        bar(&s).contains("Enter  answer") && bar(&s).contains("Esc  back"),
        "{}",
        bar(&s)
    );
    // An answer takes the question off the audit's list: two left, the list still open.
    a.slot_mut()
        .shared
        .sec
        .retain(|i| !i.id.contains("door:tcp:443"));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("┌ 2 doors from the internet · Esc back"), "{s}");
    // The last ones answered: the page again, without the row.
    a.slot_mut().shared.sec.retain(|i| !i.id.contains("door:"));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("┌ Needs attention · 9 ") && !s.contains("doors from the internet"),
        "{s}"
    );
    assert!(net(&a).screens.security.group.is_none());
}

/// A device that is another of the window's targets is that target, by its name: never
/// "nobody has named", here, on Clients or on Maintenance.
#[test]
fn a_target_of_the_window_is_never_an_unnamed_device() {
    let mut a = the_users_shape();
    let before = list(&mut a, 158, 41);
    assert!(before.contains("7 devices have no name yet"), "{before}");
    let sys = |id: &str, title: &str, known_as: &[&str]| sentry_app::system::Sys {
        peer: sentry_core::apply::session::Peer {
            id: id.into(),
            title: title.into(),
            ..Default::default()
        },
        line: sentry_app::system::SystemLine {
            addrs: known_as.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        },
        ..Default::default()
    };
    a.win.system = vec![
        // The server, by the address its ssh name resolves to.
        sys("srv:myserver", "myserver", &["myserver", "192.0.2.200"]),
        // This machine, by the MAC of its own interface.
        sys("", "this machine", &["00:00:5E:00:54:01"]),
        // The network itself is no device of its own.
        sys(&crate::tui::id_of(NAME), NAME, &["192.0.2.202"]),
    ];
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("5 devices have no name yet"), "{s}");
    let named: Vec<(String, bool)> = net(&a)
        .store
        .clients
        .iter()
        .flatten()
        .filter(|c| {
            c.hostname
                .as_deref()
                .is_some_and(|h| h.starts_with("thing-"))
        })
        .take(3)
        .map(|c| (c.label().to_string(), c.unknown()))
        .collect();
    assert_eq!(
        named,
        [
            ("myserver".to_string(), false),
            ("this machine".to_string(), false),
            ("thing-2".to_string(), true)
        ]
    );
    let s = screen(&mut a, '2', 158, 41);
    assert!(s.contains("myserver") && s.contains("this machine"), "{s}");
}

/// The firewall's counters as a router without a package that forces DNS has them.
fn dns_not_forced(a: &mut App) {
    let mut c = counters_later(120);
    c.rules
        .as_mut()
        .unwrap()
        .retain(|r| !r.name.starts_with("ubus:"));
    data(a, Kind::Counters, Ok(Payload::Counters(Box::new(c))));
}

fn mac_of(a: &App, label: &str) -> String {
    net(a)
        .store
        .clients
        .iter()
        .flatten()
        .find(|c| c.label() == label)
        .and_then(|c| c.mac.clone())
        .unwrap_or_else(|| panic!("no client {label}"))
}

/// The family filter's list, open from its entry (the page's last row).
fn filter_menu(a: &mut App) {
    key(a, KeyCode::Char('4'));
    key(a, KeyCode::Esc);
    key(a, KeyCode::Char('G'));
    key(a, KeyCode::Enter);
    assert!(net(a).screens.security.filter.is_some(), "the list is open");
}

#[test]
fn the_family_filter_is_chosen_in_one_list_and_applied_as_one_change() {
    let _turn = runs();
    let mut a = armed(busy());
    dns_not_forced(&mut a);
    filter_menu(&mut a);
    let s = render_to_string(&mut a, 158, 41);
    insta::assert_snapshot!("threats_filter_menu_158x41", s);
    // Named first, the rest by what they are known by; how each is on the network; a
    // private Wi-Fi address marked.
    let at = |s: &str, what: &str| s.lines().position(|l| l.contains(what)).unwrap();
    assert!(at(&s, "[ ] cam") < at(&s, "[ ] 00:00:5e:00:53:11"), "{s}");
    let phone = line(&s, "[ ] phone");
    assert!(phone.contains("Wi-Fi") && phone.contains("! │"), "{s}");
    assert!(
        bar(&s).starts_with(" Enter  apply   Space  tick   a  all named"),
        "{}",
        bar(&s)
    );
    insta::assert_snapshot!(
        "threats_filter_menu_80x24",
        render_to_string(&mut a, 80, 24)
    );
    // On the phone: it stays tickable, with the warning said plainly.
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("It uses a private (random) Wi-Fi address: turn 'private address'"),
        "{s}"
    );
    // An unnamed one can be named first.
    key(&mut a, KeyCode::Char('G'));
    assert!(bar(&render_to_string(&mut a, 158, 41)).contains("e  name it"));
    key(&mut a, KeyCode::Char('e'));
    assert!(
        matches!(a.win.input, Input::Prompt(..)),
        "a name is asked for"
    );
    key(&mut a, KeyCode::Esc);
    // Space ticks one, a ticks every named one; Enter applies them all as one change.
    key(&mut a, KeyCode::Home);
    key(&mut a, KeyCode::Char(' '));
    assert!(render_to_string(&mut a, 158, 41).contains("1 ticked"));
    key(&mut a, KeyCode::Char('a'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("5 ticked") && s.contains("[x] phone"), "{s}");
    assert!(
        s.contains("[ ] 00:00:5e:00:53:11"),
        "unnamed ones aren't ticked by a: {s}"
    );
    key(&mut a, KeyCode::Enter);
    assert!(net(&a).screens.security.filter.is_none(), "the list closed");
    let (name, action) = started(&a);
    assert_eq!(name, "security-action");
    let tags: Vec<&str> = action
        .strip_prefix("filter:")
        .unwrap_or_else(|| panic!("{action}"))
        .split(',')
        .collect();
    assert_eq!(tags.len(), 5, "{action}");
    assert!(
        tags.iter().all(|t| blocks::is_tag(t)),
        "tags, never MACs: {action}"
    );
    let mut sorted = tags.clone();
    sorted.sort();
    assert_eq!(tags, sorted);
    // Who each tag is, noted here for the step (nothing is written in tests).
    let b = &net(&a).store.blocks;
    assert!(tags.iter().all(|t| b.device.contains_key(*t)), "{b:?}");
    assert!(!b.device[tags[0]].zone.is_empty());
    // The plan first (reads only), then the change waits for Enter; auto never answers it.
    let run = wf(&a).unwrap();
    assert_eq!(run.live.as_ref().map(|l| l.idx), Some(0));
    let s = render_to_string(&mut a, 200, 41);
    assert!(
        s.contains(&format!("$ sentry-network security plan {action}")),
        "{s}"
    );
    assert!(
        !s.contains(&mac_of(&a, "phone")),
        "no MAC in the run's own words: {s}"
    );
    a.run_step_exit_for_test(0);
    let run = wf(&a).unwrap();
    assert!(matches!(run.next, Next::Confirm(1)), "{:?}", run.next);
    assert!(run.wf.steps[1].risky);
    ctrl(&mut a, 'a');
    assert!(
        matches!(wf(&a).unwrap().next, Next::Confirm(1)),
        "auto answered it"
    );
    ctrl(&mut a, 'a');
    key(&mut a, KeyCode::Char('0'));
    key(&mut a, KeyCode::Enter);
    let run = wf(&a).unwrap();
    assert_eq!(run.live.as_ref().map(|l| l.idx), Some(1));
    let s = render_to_string(&mut a, 200, 41);
    assert!(
        s.contains(&format!("$ sentry-network security apply {action}")),
        "{s}"
    );
    a.run_step_exit_for_test(0);
    assert!(wf(&a).is_none_or(|r| r.done()), "the run ended");

    // Nothing changed in the list: said, nothing started.
    runs_cleared();
    let mut a = armed(busy());
    dns_not_forced(&mut a);
    filter_menu(&mut a);
    key(&mut a, KeyCode::Enter);
    assert_eq!(
        a.toast_for_test(),
        Some("nothing to change: the filter is on exactly these devices already")
    );
    assert!(wf(&a).is_none());

    // A router where a package forces every lookup to itself: said before anything
    // starts, and nothing does.
    let mut a = armed(busy());
    filter_menu(&mut a);
    key(&mut a, KeyCode::Char(' '));
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(
        s.contains("Nothing was changed. The family filter can't work on this router yet")
            && s.contains("https-dns-proxy"),
        "{s}"
    );
    assert!(wf(&a).is_none());

    // sentry's own targets aren't offered.
    let mut a = armed(busy());
    let cam = mac_of(&a, "cam");
    a.win.system = vec![sentry_app::system::Sys {
        peer: sentry_core::apply::session::Peer {
            id: "srv:myserver".into(),
            title: "myserver".into(),
            ..Default::default()
        },
        line: sentry_app::system::SystemLine {
            addrs: vec![cam.clone()],
            ..Default::default()
        },
        ..Default::default()
    }];
    filter_menu(&mut a);
    let s = render_to_string(&mut a, 158, 41);
    assert!(!s.contains("[ ] cam") && !s.contains("[ ] myserver"), "{s}");
}

/// The fixture's config with sentry's family filter on these devices.
fn filtered_uci(devs: &[(&str, &str)]) -> crate::collect::uci::Uci {
    let mut add = String::new();
    for (tag, mac) in devs {
        let w = crate::security::family::Want {
            tag: tag.to_string(),
            mac: mac.to_string(),
            zone: "lan".into(),
        };
        for l in
            crate::security::family::device_lines(&w, "wan", crate::security::family::service())
                .unwrap()
        {
            add.push_str(l.strip_prefix("uci set ").unwrap());
            add.push('\n');
        }
    }
    let text = fixture("network/uci.txt").replacen("@@dropbear", &format!("{add}@@dropbear"), 1);
    crate::collect::uci::parse(&text, &crate::redact::Salt::fixed([7; 16]))
}

#[test]
fn filtered_by_you_lists_the_routers_filters_and_enter_takes_one_off() {
    let _turn = runs();
    let mut a = armed(busy());
    dns_not_forced(&mut a);
    let (phone, cam) = (mac_of(&a, "phone"), mac_of(&a, "cam"));
    let (tp, tc) = (
        blocks::tag(NAME, &phone).unwrap(),
        blocks::tag(NAME, &cam).unwrap(),
    );
    let gone = "0000abcd".to_string();
    data(
        &mut a,
        Kind::Uci,
        Ok(Payload::Uci(Box::new(filtered_uci(&[
            (&tp, &phone),
            (&tc, &cam),
        ])))),
    );
    let now = a.win.now_override.unwrap().as_second();
    {
        let (slot, _) = a.parts();
        let t: &mut NetworkTarget = slot.target.as_any_mut().downcast_mut().unwrap();
        let b = &mut t.store.blocks;
        for (tag, mac, label) in [(&tp, &phone, "phone"), (&gone, &cam, "old tablet")] {
            b.device.insert(
                tag.clone(),
                blocks::Dev {
                    mac: mac.clone(),
                    label: label.into(),
                    zone: "lan".into(),
                    wifi: None,
                },
            );
        }
        // The phone's filter is noted; the cam's isn't (made elsewhere); the tablet's
        // noted filter is no longer on the router.
        for tag in [&tp, &gone] {
            b.filter.insert(
                tag.clone(),
                blocks::Filtered {
                    since: now - 3 * 86_400,
                    service: "cleanbrowsing-family".into(),
                },
            );
        }
    }
    let s = list(&mut a, 158, 41);
    insta::assert_snapshot!("threats_filtered_158x41", s);
    assert!(
        s.contains("Filtered by you · family filter: 2 devices"),
        "{s}"
    );
    assert!(line(&s, "│ phone ").contains("since 3 days ago"), "{s}");
    assert!(
        s.contains("! weak The family filter: see 6 and 7 above"),
        "{s}"
    );
    // What differs between the router and this machine: a look each.
    assert!(
        s.contains("A family filter is on cam that sentry has no note of"),
        "{s}"
    );
    assert!(
        s.contains("The family filter on old tablet isn't on the router any more"),
        "{s}"
    );
    // The one sentry has no note of: kept, noted here, nothing on the router.
    on_row(&mut a, "that sentry has no note of");
    key(&mut a, KeyCode::Enter);
    let s = render_to_string(&mut a, 158, 41);
    assert!(s.contains("1  Keep it: note it here as filtered"), "{s}");
    key(&mut a, KeyCode::Char('1'));
    assert!(net(&a).store.blocks.filter.contains_key(&tc));
    assert!(wf(&a).is_none());
    // The one gone from the router: forgotten here.
    on_row(&mut a, "isn't on the router any more");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('2'));
    assert!(!net(&a).store.blocks.filter.contains_key(&gone));
    key(&mut a, KeyCode::Esc);
    let s = list(&mut a, 158, 41);
    assert!(
        !s.contains("that sentry has no note of") && !s.contains("isn't on the router any more"),
        "{s}"
    );
    assert!(line(&s, "│ cam ").contains("since just now"), "{s}");
    // Enter under Filtered by you takes one off: the filter on the rest, as one change.
    key(&mut a, KeyCode::Char('G'));
    let s = render_to_string(&mut a, 158, 41);
    assert!(bar(&s).starts_with(" Enter  take it off"), "{}", bar(&s));
    let last = net(&a)
        .store
        .uci
        .value
        .as_ref()
        .map(crate::security::family::found)
        .unwrap();
    let off = &last.last().unwrap().tag;
    key(&mut a, KeyCode::Enter);
    let (_, action) = started(&a);
    let rest: Vec<&String> = last.iter().map(|f| &f.tag).filter(|t| *t != off).collect();
    assert_eq!(action, format!("filter:{}", rest[0]));
    // Clients marks the filtered ones.
    let s = screen(&mut a, '2', 158, 41);
    assert!(
        s.contains("phone  (filtered)") && s.contains("cam  (filtered)"),
        "{s}"
    );
}

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
    assert!(
        line(&s, "│ look     Someone tried to log in").contains("3 times and was refused"),
        "{s}"
    );
    assert!(
        s.contains("│ note     Someone tried a wrong Wi-Fi password twice"),
        "{s}"
    );
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
        bar(&s)
            .contains("Enter  the numbers   x  expected   z  later   o  everything   d  numbers"),
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
        s.lines().nth(1).unwrap().contains("4 Security 9 "),
        "red: something is wrong now: {s}"
    );
    // What is wrong now comes first.
    let first = s.lines().position(|l| l.contains("│ act now")).unwrap();
    let look = s.lines().position(|l| l.contains("│ look")).unwrap();
    assert!(first < look, "{s}");
    for said in [
        "A door from the internet is open that you haven't listed: game, udp port",
        "The router lets people log in over ssh with a password",
        "The router's admin page can be opened without encryption (plain HTTP)",
        "A device nobody has named is plugged into lan",
        "! weak ssh takes a password, and the admin page can be opened without encryption",
        "2 not named",
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
    assert_eq!(s.matches("✓ ok ").count(), 6, "the whole cover: {s}");
    assert!(
        s.lines()
            .nth(1)
            .unwrap()
            .contains("4 Security   6 Maintenance"),
        "no count: {s}"
    );
    // The key bar names no Enter where there is no row.
    assert!(!bar(&s).contains("Enter"), "{}", bar(&s));
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
        ("A door from the internet", "Enter  close it"),
        ("log in over ssh with a password", "Enter  keys only"),
        ("without encryption (plain HTTP)", "Enter  use HTTPS"),
        ("nobody has named is plugged", "Enter  decide"),
        ("in a way ordinary devices rarely do", "Enter  the numbers"),
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

#[test]
fn an_unknown_device_is_named_blocked_or_paused() {
    let _turn = runs();
    let mut a = armed(busy());
    let s = on_row(&mut a, "nobody has named is plugged");
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
    on_row(&mut a, "nobody has named is plugged");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('1'));
    typed(&mut a, "   ");
    assert_eq!(a.toast_for_test(), Some("not named: no name given"));
    assert_eq!(unnamed(&a), 1);

    // 4: paused for an hour. What is started is the security-action workflow, given a
    // tag (never the MAC); sentry notes here who the tag is and when the pause ends.
    on_row(&mut a, "nobody has named is plugged");
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
    on_row(&mut a, "log in over ssh with a password");
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
    on_row(&mut a, "nobody has named is plugged");
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
    on_row(&mut a, "nobody has named is plugged");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('6'));
    assert!(wf(&a).is_none());
    assert_eq!(
        a.slot().shared.later.values().next().map(|d| d.to_string()),
        Some("2026-11-02".to_string())
    );

    // Without the workflow (a network with its own set): said, nothing noted.
    let mut a = busy();
    on_row(&mut a, "nobody has named is plugged");
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
    on_row(&mut a, "A door from the internet");
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
    on_row(&mut a, "A door from the internet");
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Char('2'));
    assert_eq!(started(&a).1, "forward-remove:@redirect[0]");
    assert!(net(&a).store.blocks.door.is_empty());
    let mut b = armed(busy());
    on_row(&mut b, "A door from the internet");
    key(&mut b, KeyCode::Enter);
    key(&mut b, KeyCode::Char('3'));
    assert_eq!(b.toast_for_test(), Some("marked expected (baseline.toml)"));
    assert!(wf(&b).is_none());

    // ssh with keys only, the admin page on HTTPS: straight to the plan.
    for (row, action) in [
        ("log in over ssh with a password", "ssh-keys-only"),
        ("without encryption (plain HTTP)", "admin-https"),
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
    let s = on_row(
        &mut a,
        "The list of bad sites the router blocks is 54 days old",
    );
    assert!(bar(&s).contains("Enter  refresh"), "{}", bar(&s));
    assert!(s.contains("! weak Bad sites are filtered"), "{s}");
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
    on_row(&mut a, "log in over ssh with a password");
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
    assert!(!s.contains("log in over ssh with a password"), "{s}");
    // (The cover still says how it is: expected isn't fixed.)
    assert!(s.contains("! weak ssh takes a password"), "{s}");
    let s = screen(&mut a, '6', 158, 41);
    assert!(!s.contains("ssh accepts passwords"), "{s}");
    // x asks first.
    on_row(&mut a, "without encryption (plain HTTP)");
    key(&mut a, KeyCode::Char('x'));
    assert!(a.box_yes_for_test().is_some(), "a box");
    key(&mut a, KeyCode::Char('y'));
    assert_eq!(a.toast_for_test(), Some("marked expected (baseline.toml)"));
    // z: later. The same key in the same list as Maintenance's row for the finding.
    on_row(&mut a, "A door from the internet");
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
    assert!(!after.contains("ordinary devices rarely do"), "{after}");
    assert!(after.contains("A login that worked"), "{after}");
}

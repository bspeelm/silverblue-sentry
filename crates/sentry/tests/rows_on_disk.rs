//! What changed on disk without sentry is on the Maintenance list when sentry next looks
//! (`r`, entering a screen, the target getting the window back): a task taken out of
//! `tasks.toml` by hand, a row put off in `later.toml`, a finding added to `baseline.toml`,
//! a plan's file removed from `plans/`, the target's own config no longer listing what a
//! finding is about; and, on a server, what tracking, untracking and ignoring write to
//! `items.toml`.
//!
//! One test, in a process of its own: these files are the ones every test of a process
//! shares (this machine's records, `server_config.yaml`, `network_config.yaml`), so here
//! nothing else reads them. The ways themselves are `sentry_app::resolve`'s, the same that
//! each target's own tests and `src/tests.rs` drive in memory.

use sentry_app::resolve::{Outcome, Rig, Way, check};

#[test]
fn what_changes_on_disk_is_picked_up_without_a_restart() {
    // (The scratch dirs every test process gets: never the real config or data.)
    let tmp = std::env::temp_dir();
    assert!(sentry_core::paths::config_dir().starts_with(&tmp));
    let rigs: [&dyn Rig; 3] = [
        &sentry_local::tui::testing::Rig,
        &sentry_server::tui::testing::Rig,
        &sentry_network::tui::testing::Rig,
    ];
    let mut table = Vec::new();
    let seen: Vec<Vec<(Way, Outcome)>> = rigs.iter().map(|r| check(*r, true)).collect();
    for (i, (way, _)) in seen[0].iter().enumerate() {
        let row: Vec<&Outcome> = seen.iter().map(|s| &s[i].1).collect();
        table.push(format!(
            "{way:?}: {}",
            rigs.iter()
                .zip(&row)
                .map(|(r, o)| format!("{} {o:?}", r.kind()))
                .collect::<Vec<_>>()
                .join(" · ")
        ));
        let server_only = matches!(way, Way::Track | Way::Untrack | Way::Ignore);
        for (r, o) in rigs.iter().zip(&row) {
            let has = match r.kind() {
                "server" => true,
                // This machine's config lists nothing that must be there.
                "this machine" => !server_only && *way != Way::DiskConfig,
                _ => !server_only,
            };
            assert_eq!(o.is_ok(), has, "{} · {way:?}: {o:?}", r.kind());
        }
    }
    assert_eq!(seen[0].len(), Way::ALL.iter().filter(|w| w.alone()).count());
    println!("{}", table.join("\n"));
}

# sentry: Silverblue monitor & maintenance TUI (Rust + ratatui)

Spec: `docs/spec.md`. Binding amendments: `docs/spec-addendum.md` (read both before changing behavior).
Design for M3–M7: `docs/design/m3-m7.md`.
Visual target: `docs/design/sentry-tui.dc.html` (read the source; don't render it).
Upgrade procedures: `docs/cheatsheets/` are the source of truth for `assets/workflows/*.toml`.

## Commands
- Build/test: `cargo build --release && cargo test && cargo clippy --all-targets -- -D warnings`
- Snapshot tests: `cargo insta review` (or `INSTA_UPDATE=always cargo test` and then inspect `git diff`)
- Re-capture fixtures: `scripts/capture-fixtures.sh` (scrubs the username and IPs; journal fixtures are synthetic, never captured)
- Install: `install -Dm755 target/release/sentry ~/.local/bin/sentry`
- Try a collector: `cargo run -q -- collect ostree`

## Notes
- `XDG_CACHE_HOME` may be set (e.g. bothy shells): caches then live there, not `~/.cache/sentry`.
- Render tests: `src/tui/screens/tests.rs` builds a `DataStore` from fixtures; snapshots in `src/tui/screens/snapshots/`.
- `assets/workflows/*.toml` are seeded but not loaded until M5; `release-rebase` is `draft = true` (no cheatsheet covers a rebase).

## Rules
- **No background processes**: no systemd units, timers or autostart. Threads die with the TUI.
- Every external command goes through `exec::Cmd` (`Cmd::host` for host userspace). Never call `std::process::Command` directly. Dev happens in a toolbox, where `Cmd::host` adds the `flatpak-spawn --host` prefix.
- Host `/etc` is read via `paths::host_root()`.
- Collectors: a pure `parse()` (fixture-tested) and a `collect()` (exec + parse). A missing binary is `CollectError::Unavailable`, never a panic.
- Slow or network collectors run only on `c`/`r` and are cached (`cache.rs`). Nothing refreshes unless its screen is visible.
- Destructive actions: preview → confirm modal → streamed output.
- Never run `rpm-ostree upgrade/rollback/rebase`, `systemctl reboot`, or podman rm/stop for real while developing.

## Milestones (spec §13)
- [x] Prep: docs, fixtures, seeded workflows
- [x] M1 skeleton: CLI, config, TUI shell, live dashboard
- [x] M2 collectors + Dashboard/Processes/Network/Updates/Containers/Flatpaks
  (measured on host: 0.7% of one core incl. children at 1 Hz dashboard, 8 MB RSS)
- [x] M3 audit (`src/audit/`, `sentry job audit`, Audit screen)
- [ ] M4 jobs · [ ] M5 workflows · [ ] M6 recorder · [ ] M7 polish

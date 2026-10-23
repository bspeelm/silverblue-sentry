# sentry: Silverblue monitor & maintenance TUI (Rust + ratatui)

Spec: `docs/spec.md`. Binding amendments: `docs/spec-addendum.md` (read both before changing behavior).
Visual target: `docs/design/sentry-tui.dc.html` (read the source; don't render it).
Upgrade procedures: `docs/cheatsheets/` are the source of truth for `assets/workflows/*.toml`.

## Commands
- Build/test: `cargo build --release && cargo test && cargo clippy --all-targets -- -D warnings`
- Snapshot tests: `cargo insta review` (or `INSTA_UPDATE=always cargo test` and then inspect `git diff`)
- Re-capture fixtures: `scripts/capture-fixtures.sh` (scrubs the username and IPs; journal fixtures are synthetic, never captured)
- Install: `install -Dm755 target/release/sentry ~/.local/bin/sentry`
- Try a collector: `cargo run -q -- collect ostree`

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
- [ ] M1 skeleton: CLI, config, TUI shell, live dashboard
- [ ] M2 collectors + Dashboard/Processes/Network/Updates/Containers/Flatpaks
- [ ] M3 audit · [ ] M4 jobs · [ ] M5 workflows · [ ] M6 recorder · [ ] M7 polish

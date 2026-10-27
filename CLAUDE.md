# sentry: Silverblue monitor & maintenance TUI (Rust + ratatui)

Spec: `docs/spec.md`. Binding amendments: `docs/spec-addendum.md` (read both before changing behavior).
Design for M3–M7: `docs/design/m3-m7.md`.
Visual target: `docs/design/sentry-tui.dc.html` (read the source; don't render it).
Upgrade procedures: the user's personal notes in `docs/cheatsheets/` (gitignored, never commit or publish them) are the source for `assets/workflows/*.toml`.

## Commands
- Build/test: `make check` (= `cargo build --release && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`)
- Snapshot tests: `cargo insta review` (or `INSTA_UPDATE=always cargo test` and then inspect `git diff`)
- Re-capture fixtures: `scripts/capture-fixtures.sh` (scrubs the username and IPs; journal fixtures are synthetic, never captured)
- Install: `make install-binary` (copies `target/release/sentry` to `~/.local/bin/sentry`)
- Try a collector: `cargo run -q -- collect ostree`; a job plan: `cargo run -q -- job cleanup-flatpak --dry-run`
- Manual TUI tests: point `XDG_DATA_HOME`/`XDG_CONFIG_HOME` at a scratch dir so reports, jobs.json and baseline.toml stay out of the real ones

## Notes
- `XDG_CACHE_HOME` may be set (some dev shells set it): caches then live there, not `~/.cache/sentry`.
- Render tests: `src/tui/screens/tests.rs` builds a `DataStore` from fixtures; snapshots in `src/tui/screens/snapshots/`.
- `assets/workflows/*.toml` are embedded and seeded to `~/.config/sentry/workflows/` when missing; `release-rebase` is `draft = true` (no rebase has been run end to end).
- Workflow tests: put a harmless TOML in a scratch `XDG_CONFIG_HOME`, run with `SENTRY_NO_REBOOT=1`, fake a reboot by editing `boot_id` in `state.json`.

## Rules
- **No background processes**: no systemd units, timers or autostart. Threads die with the TUI.
- Every external command goes through `exec::Cmd` (`Cmd::host` for host userspace). Never call `std::process::Command` directly. Dev happens in a toolbox, where `Cmd::host` adds the `flatpak-spawn --host` prefix.
- Host `/etc` is read via `paths::host_root()`.
- Collectors: a pure `parse()` (fixture-tested) and a `collect()` (exec + parse). A missing binary is `CollectError::Unavailable`, never a panic.
- Slow or network collectors run only on `c`/`r` and are cached (`cache.rs`). Nothing refreshes unless its screen is visible.
- Destructive actions: preview → confirm modal → streamed output.
- Never run `rpm-ostree upgrade/rollback/rebase`, `systemctl reboot`, or podman rm/stop for real while developing.

## sentry-server (`src/server/`, `src/bin/sentry-server.rs`)
- A second binary from the same library: monitors a server over ssh (`exec::Cmd::ssh`), configured by `~/.config/sentry/server_config.yaml` (sample: `assets/server_config.example.yaml`).
- **The repo is public: nothing about the developer's real server goes into git** (names, IPs, services, containers, ports, disks), nor into commit messages or release notes. Server fixtures in `tests/fixtures/server/` are synthetic (real formats, invented content: `myserver`, `app.service`, `stack`, 192.0.2.x). Captures from the real server go only in the gitignored `tests/fixtures/server/local/`.
- Run `make privacy-check` before every commit and release (patterns live in the gitignored `.private-patterns`).
- Against the real server, only read-only commands while developing; anything that changes it is exercised up to its confirm modal. Mutating mechanics are tested against a disposable local sshd container.
- sudo may ask for a password (the developer's server does): sudo is checked again before each sudo step or action; password → terminal handed over, the step's output tee'd to `~/.cache/sentry-server/` on the server and read back into its log; streamed steps get `sudo -n` so they fail instead of waiting on a prompt nobody sees.
- A server's own workflows: `~/.config/sentry/servers/<name>/workflows/` (local, never in git) replace the seeded generic ones.
- The one background exception: ssh's multiplex master (`ControlPersist=15s`) outlives the last command by at most 15 s, then exits by itself. Streamed and interactive commands (actions, workflow steps) use their own connection: through the shared one, killing the local client leaves the remote command running.
- Test knobs: `SENTRY_SSH_CONFIG=<file>` passes `-F` to ssh (point it at a throwaway sshd without touching ~/.ssh). Local-only live tests (`#[ignore]`): `SENTRY_SERVER_LIVE=<name> cargo test live_tabs|live_ask -- --ignored --nocapture` (read-only against the real server); `SENTRY_SERVER_LIVE=<name> cargo test live_ask_boxes -- --ignored` (A opens the consent box, nothing sent); `SENTRY_SERVER_LIVE=<name> SENTRY_WORKFLOW=<wf> XDG_DATA_HOME=<scratch> cargo test live_preflight -- --ignored` (a workflow's auto steps up to the first confirm, never pressed); `SENTRY_SSH_CONFIG=… SENTRY_SERVER_SCRATCH=<name> XDG_*=scratch cargo test live_actions|live_workflow -- --ignored` (against a disposable sshd container only); `live_password_step` likewise, against a container whose sudo asks for a password, run under a pty that types it; `cargo test parses_local_captures -- --ignored` (parsers vs gitignored real captures).
- Measured on the real server: Overview at 1 Hz costs 0.67% of one core incl. its ssh commands, 6.9 MB RSS.

## Milestones (spec §13)
- [x] Prep: docs, fixtures, seeded workflows
- [x] M1 skeleton: CLI, config, TUI shell, live dashboard
- [x] M2 collectors + Dashboard/Processes/Network/Updates/Containers/Flatpaks
  (measured on host: 0.7% of one core incl. children at 1 Hz dashboard, 8 MB RSS)
- [x] M3 audit (`src/audit/`, `sentry job audit`, Audit screen)
- [x] M4 jobs (`src/jobs/`: plans, `sentry job`, Jobs + Cleanup screens, cadence)
- [x] M5 workflows (`src/workflows/`, `src/checks.rs`, `src/tui/wf.rs`, Upgrade screen)
- [x] M6 recorder (`src/recorder/`, `sentry record`, History screen; 0.07% CPU, 9.8 MB on host)
- [x] M7 polish (per-screen help, `:workflow`, narrow layouts, missing-binary paths, README)
  (TUI on host: 0.77% of one core incl. children at 1 Hz dashboard, 8.3 MB RSS)

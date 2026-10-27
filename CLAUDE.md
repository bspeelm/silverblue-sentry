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
- Screens: `1` Dashboard, `2` Processes, `3` Network, `4` Containers, `5` Flatpaks, `6` Maintenance, `7` Cleanup, `0` Upgrade, `H` History. Maintenance (`src/tui/screens/maint.rs`) ranks `src/maint/local.rs` (pure) recommendations: findings, updates (Enter = `quick-update`, the one apply path), a staged reboot, due/failed jobs, cleanup, a run in progress, ready plans. The old Audit/Jobs screens are views inside it (`F`/`J`, `Maint::view`); Cleanup stayed a screen (the cleanup recommendation and `C` go there); `updates.rs` is only helpers (deployments panel, rollback, what's waiting).
- `src/maint/` is shared by both binaries: the log + `LOG.md` ledger, plans, reviews (server `""` = this machine: `~/.config/sentry/{log,plans,reviews}/`; a server's under `servers/<name>/`), snoozes, `Level`, and `retention` (`[retention]` in config.toml, pruned at TUI start and after writes). Plans/reviews are written by `docview::Writer` (shared with sentry-server); local prompts in `src/tui/plans.rs`. Tests use `App::for_test` (`records: false`): nothing is written or sent.
- Chat: Esc while Claude answers hides it (`Chat::hidden`); `A` brings it back. Both binaries.

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
- The inventory (`src/server/inventory.rs`, key `I`): the collectors' own sudo argv run once in one `sudo sh -c` with the password, cached; `Remote::output` answers a refused `sudo -n` from it only when `Remote::inventory` is set (the TUI), never for workflow conditions.
- Maintenance (`src/server/maint/`, tab `4`, `sentry-server maint`): `maintenance:` items in the config; the server's side in `local.rs`, upstream (curl from this machine: GitHub releases, Docker Hub, GHCR, endoflife.date) cached daily in `upstream.rs`, pure `eval.rs` → flags and `srv:maint:*` findings. Snoozes in `servers/<name>.maint.toml`, changes in `maintenance.jsonl`. Plans and reviews get WebFetch/WebSearch and Read of the `notes:` files only.
- Claude's reads that need root: the gateway queues them in `$XDG_RUNTIME_DIR/sentry-server/reads-<server>.jsonl` (the runtime dir is the same for the TUI and Claude's child processes); after a turn the TUI offers them, runs them in one `sudo sh -c` (inventory's capture helpers) and sends the output as the next turn. Plans (`p`) are a separate flow from Ask Claude (`src/server/tui/planview.rs`): their own system prompt (no length cap; answer with only the plan document, `TARGET:` first), a background `Writer` whose final answer (`Done.result`) becomes `servers/<name>/plans/<item>.md` (`src/server/maint/plan.rs`: `+++` TOML header, then Markdown); the Plan view renders it; applied or dropped plans move to `plans/done/`.
- Maintenance review: `maint/discover.rs` (untracked / gone), `maint/tracked.rs` (`servers/<name>/items.toml`, merged in `Remote::new`), `maint/recommend.rs` (pure rules → ranked recommendations with actions; cadences from `maintenance.cadence` against the log), `maint/review.rs` + `R` (Claude review, same writer as plans). The Maintenance tab is recommendations then items, one cursor; `App::maint_sel` keeps the selection on its row when the list changes. Audit findings, package updates and reboots are recommendations there (no Audit/Updates tabs); a workflow run shows in the Run view (`0`, `:wf`, `w` to start one), not a tab. Tabs: `1` Overview, `2` Services, `3` Containers, `4` Maintenance.
- Maintenance log (`src/server/maint/log.rs`): every finished workflow run → `servers/<name>/log/<when>-<item>-<workflow>.md` (+++ TOML header with tags, steps table, note) and the `LOG.md` ledger; written when the run ends, rewritten when the note is given. Plans and reviews get Read on the log dir and are told to start from the ledger.
- A server's own workflows: `~/.config/sentry/servers/<name>/workflows/` (local, never in git) replace the seeded generic ones.
- The one background exception: ssh's multiplex master (`ControlPersist=15s`) outlives the last command by at most 15 s, then exits by itself. Streamed and interactive commands (actions, workflow steps) use their own connection: through the shared one, killing the local client leaves the remote command running.
- Test knobs: `SENTRY_SSH_CONFIG=<file>` passes `-F` to ssh (point it at a throwaway sshd without touching ~/.ssh). Local-only live tests (`#[ignore]`): `SENTRY_SERVER_LIVE=<name> cargo test live_tabs|live_ask -- --ignored --nocapture` (read-only against the real server); `SENTRY_SERVER_LIVE=<name> cargo test live_ask_boxes -- --ignored` (A on the updates recommendation opens the consent box, nothing sent; Claude Code checks Read permissions against the resolved path, so notes paths are canonicalized and their dirs passed with `--add-dir`); `SENTRY_SERVER_LIVE=<name> SENTRY_WORKFLOW=<wf> XDG_DATA_HOME=<scratch> cargo test live_preflight -- --ignored` (a workflow's auto steps up to the first confirm, never pressed); `SENTRY_SSH_CONFIG=… SENTRY_SERVER_SCRATCH=<name> XDG_*=scratch cargo test live_actions|live_workflow -- --ignored` (against a disposable sshd container only); `live_password_step` and `live_inventory` likewise, against a container whose sudo asks for a password (a fake root-only `docker` printing the synthetic fixtures), run under a pty that types it; `cargo test parses_local_captures -- --ignored` (parsers vs gitignored real captures).
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

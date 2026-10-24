# silverblue-sentry

A daemon-free monitor and maintenance TUI for **Fedora Silverblue**: live system health, security audits with month-over-month diffs, dry-run-first cleanup, and resumable multi-reboot upgrade workflows that know about the NVIDIA kmod dance. The binary is called `sentry`.

```
 sentry   silverblue 44.20261002.0  up 3d 04:12  ● live 1 Hz   Fri 23 Oct 16:04
 1 Dashboard   2   3 12   4 !   5   6   7   8   9   0
────────────────────────────────────────────────────────────────────────────────
┌ CPU · i9-14900K · 24c/32t ───────────────────────────────────────────────────┐
│ total  ██████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░  34%   load 0.95 1.02 0.91 │
│ ▃▁▁▂▄▅▆▆▆▅▄▂ ▂▃▅▆▆▆▆▅▃▁▁▃▄▅▆▆▆▅▄▂ ▂▃▅▆▆▆▆▄▃▁▁▃▄▆▆▆▆▅▄▂ ▂▄▅▆▆▆▆▄▃▁▁▃▄▆▆▆▆▅▄▂  │
│ cores  ▁▁▂▂▃▃▄▄▅▅▆▆▇▇█▁▂▂▃▃▄▄▅▅▆▆▇▇█▁▂▂                                      │
│ temp   cpu 53°C   gpu 36°C   nvme 44°C                                       │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Memory ──────────────────────────────┐ ┌ Status ─────────────────────────────┐
│ mem   20.0 / 64.0 GiB                │ │ updates       216 os · 5 fp  2h ago │
│ █████████░░░░░░░░░░░░░░░░░░░░░  31%  │ │               kernel changes  kmod… │
│                                      │ │ findings      0 high · 2 med · 1 low│
└──────────────────────────────────────┘ └─────────────────────────────────────┘
 1-0  screens   c  check updates   r  measure disks   ?  help   q  quit
```

## Who it's for

People running Fedora Silverblue (or another rpm-ostree desktop) who want one place to see what the system is doing and to do routine maintenance carefully. It's most useful if you run **NVIDIA through RPM Fusion akmods with the built `kmod-nvidia` layered as a local package** (needed with Secure Boot): `quick-update` encodes the drop-old-kmod → reboot → build/layer-new-kmod → reboot ritual so you can't skip a step. Without NVIDIA, the GPU parts simply hide and the routine upgrade path is a single step.

It is opinionated about one kind of setup and encodes procedures proven on one machine. Read a workflow's TOML (`e` on the Upgrade screen) before trusting it on yours.

## Status and safety

**v0.1.1, early.** Everything here is built and tested against fixtures and a real Silverblue 44 machine, but some paths have only been exercised up to their confirm modal, never executed for real during development: `rpm-ostree upgrade`/`rollback`/`cleanup`, reboots, `akmods`, `flatpak uninstall`, `podman` prune/remove.

- Nothing runs in the background: no services, timers or autostart. The recorder is a foreground process you start and stop.
- Every destructive action shows a preview, waits for your confirmation, and streams its output. Reboots never happen on their own.
- `release-rebase` ships as a **draft** and refuses to start until you've reviewed it and removed `draft = true`.
- Workflow steps that need `sudo` must run from a host terminal, not from inside a toolbox.
- Never root: privileged operations go through `rpm-ostree` (polkit) or `sudo` prompts in your terminal.

## Install

From the [latest release](https://github.com/bspeelm/silverblue-sentry/releases/latest) (x86_64; built on Fedora 44 and linked only against glibc):

```sh
curl -LO https://github.com/bspeelm/silverblue-sentry/releases/download/v0.1.1/silverblue-sentry-0.1.1-x86_64-linux-gnu.tar.gz
curl -LO https://github.com/bspeelm/silverblue-sentry/releases/download/v0.1.1/silverblue-sentry-0.1.1-x86_64-linux-gnu.tar.gz.sha256
sha256sum -c silverblue-sentry-0.1.1-x86_64-linux-gnu.tar.gz.sha256
tar xf silverblue-sentry-0.1.1-x86_64-linux-gnu.tar.gz
install -Dm755 silverblue-sentry-0.1.1/sentry ~/.local/bin/sentry
```

From source (a toolbox with `cargo` works fine; Rust 1.85+):

```sh
cargo build --release
install -Dm755 target/release/sentry ~/.local/bin/sentry
```

Inside a toolbox, host tools (`rpm-ostree`, `flatpak`, `podman`, …) are reached through `flatpak-spawn --host`, so `sentry` works from either side. It leaves files only under `~/.config/sentry`, `~/.local/share/sentry` and `~/.cache/sentry` (or the `XDG_*_HOME` locations).

## Commands

| Command | What it does |
|---|---|
| `sentry` | Open the TUI and resume any workflow in progress |
| `sentry job <name> [--dry-run] [--yes] [--only k1,k2] [--tag T] [--diff-against T]` | Run a job (below). It prints its plan, asks `[y/N]` on a terminal, then runs. Without a terminal it needs `--yes`. |
| `sentry check <name> [args]` | A built-in check: exit 0/1 plus one line of reason (2 = usage error) |
| `sentry workflow <name> [--var k=v]` | Start or continue a workflow in this terminal |
| `sentry workflow list` · `lint [name]` · `abandon` | List workflows, validate them, or abandon the run in progress |
| `sentry record [--interval 10s]` | Foreground metrics recorder for a spare terminal or tmux pane; Ctrl-C stops it |
| `sentry status [--short]` | One line from state files only (workflow, due jobs, high findings); runs no collectors. `--short` prints nothing when there's nothing to say. |
| `sentry collect <name>` | A collector as JSON: `system processes gpu disk disk-breakdown net ostree flatpak flatpak-updates podman units repos shell journal`. Exit 3 = the tool it needs isn't installed. |

**Jobs:** `audit`, `update-check`, `update-apply`, `cleanup-flatpak`, `cleanup-podman`, `cleanup-ostree`, `cleanup-cache`. `--dry-run` shows the plan (what would run, what it would free) and changes nothing.

**Checks:** `preflight --target N`, `booted-version --expect N`, `booted-kernel --expect KVER`, `kernel-changed`, `nvidia-module`, `nvidia-loaded`, `rpmfusion-version --target N`, `rpmfusion-pinned`, `kargs`, `secureboot-mok`, `kmod-local [--exactly-one]`, `akmods-built [--exactly-one]`, `flatpak-gl-nvidia`, `flatpak-idle [--app ID]`, `master-repo-present`.

## Screens

| Key | Screen | Highlights |
|---|---|---|
| `1` | Dashboard | CPU (per-core), memory/zram, GPU, disks + breakdown, network graphs, status (updates, findings, failed units, due jobs, workflow, recorder) |
| `2` | Processes | `C`/`M` sort, `x` SIGTERM (confirmed) |
| `3` | Network | listeners as `baseline` / `local` / `client` / `NEW`; `e` marks one expected |
| `4` | Updates | deployments, cached rpm-ostree and Flatpak updates. `c` checks, `u` upgrades (kmod ritual aware), `f` updates Flatpaks, `R` rolls back |
| `5` | Containers | toolbox / distrobox / podman, stale and `$HOME` flags, and pending dnf updates inside each toolbox (`old → new`). `c` checks (stopped toolboxes are started, then stopped again), `u`/`U` upgrade one/all, `Enter` opens a shell, `s` stops, `d` removes |
| `6` | Flatpaks | permission flags from metadata + overrides, GL.nvidia pair check, `o` opens Flatseal |
| `7` | Audit | what's worth a look, each explained (what it is, why it's listed, what to do) and marked `check` / `review` / `info`; known services are named and grouped; diff against the previous audit. `f` fixes the selected finding: with Claude Code, Claude reads the logs and tells you what to run (see below); without it, sentry's own fixes (the exact command and how to undo it, asked first, the terminal handed over for sudo, then a re-audit), `b` toggles expected, `A` asks Claude, `Enter` audits, `[`/`]` browse reports |
| `8` | Jobs | last run, cadence, due status. `Enter` shows the plan, then runs; `e` edits the cadence |
| `9` | Cleanup | reclaimable space from dry runs; `Space` toggles, `Enter` confirms and runs the selection |
| `0` | Upgrade | workflows: start, step cards (confirm / reboot / manual), streaming log, `s` skip, `a` abandon, `R` roll back, `l` log |
| `H` | History | recorder data over 6h/24h/72h (`[`/`]`), `←`/`→` to scrub; the tab appears once `sentry record` has run |

`A` asks Claude about the selected thing (see below). Vim keys work everywhere: `j/k`, `gg/G`, `C-d/C-u`, `h/l` (previous/next screen), `/` filter with `n/N`, and `:` commands (`:q`, `:net`, `:job audit`, `:workflow quick-update`). `C-h`/`C-l` switch panes and `C-j`/`C-k` scroll logs. `?` shows the keys for the current screen.

**Refresh:**
- Live data refreshes only while its screen is visible: the dashboard at 1 Hz, Processes at 2 Hz, Network every 3 s.
- Update checks (`c`), the disk breakdown (`r` on the dashboard) and cleanup plans run only when you ask, and are cached.
- Every destructive action shows a preview, asks you to confirm, then streams its output.

Measured on the host: the open dashboard uses about 0.8% of one core including children, and 8 MB of memory. The recorder uses 0.07% and 10 MB.

## Ask Claude

Press **`A`** on any tab to ask your local [Claude Code](https://claude.com/claude-code) about the selected thing: a finding, a listener, a process, a container, a Flatpak, a pending update, a cleanup item, a failed workflow step, or the dashboard as a whole. It uses the `claude` CLI and the login you already have, so there's no API key and nothing to configure. If `claude` isn't installed, `A` just says so.

- **You see what's sent.** Before every question, a screen shows the exact text that will go to Anthropic. `y` sends it.
- **Claude can investigate, read-only.** It may run a fixed allowlist of read-only commands (`ss`, `systemctl status`, `journalctl`, `rpm -q`, `rpm-ostree status`, `flatpak info`, `podman inspect`, `firewall-cmd --list-all`, …) and read `/etc`, `/proc` and `/usr/lib/systemd`. Claude Code refuses anything else, including `sudo` and any writes. The list is `ALLOWED` in `src/claude.rs`.
- **The answer streams into a chat pane.** You'll see the commands Claude ran and their results. Type a follow-up and press Enter to continue the same session. Esc closes the pane and stops Claude, and nothing keeps running after that.

### Fixing a finding with Claude (`f` on Audit)

`f` sends the finding and sentry's known fixes for it, and asks Claude for three things: what's going on, what it recommends (leaving it alone and marking it expected is a valid answer), and the commands to run, each with a `# why:` line.

- **Claude proposes; you run.** Claude still can't change anything. Its commands show up as a numbered list under the answer. Press `r` (then `1`–`9`) to see one in a confirm box: the exact command, why, the undo if it's one of sentry's known fixes, and whether it needs sudo. Patterns like `curl … | sh` or `rm -rf /` are shown in red. `y` runs it: sentry runs it as you, not Claude.
  - `sudo` commands hand over the terminal so you type your own password.
  - Other commands stream into the chat.
  - Commands that change something are followed by a re-audit, and the chat says whether the finding is gone.
- **The output stays with you** until you press `s`, which shows the follow-up ("I ran X, exit N, output…") before sending it.
- **`C` continues in Claude Code.** It opens the same conversation as an interactive `claude` session in this terminal. Read-only commands are pre-allowed and sudo and file edits stay off; Claude Code asks you before anything else. Quit it to return to sentry, which audits again.

### Fixing a failed workflow step (`f` on Upgrade)

When a workflow step fails, the failure card offers `[f] fix with Claude`. Claude gets the step's command, exit code, the last 60 lines of its log, the workflow's own advice for that failure, and the actions open to you (retry, done by hand, skip, rollback, abandon). It answers in the same three parts, ending with which of those actions to take. It's told not to propose upgrades, rebases, rollbacks or reboots, because the workflow does those itself.

- `r` runs one of its commands, as above. If a command would change deployments or reboot while a workflow is in progress, the confirm box warns you.
- **`t` retries the step** from the chat, after a confirm box showing the step's command. The step's output goes to the workflow log; the chat says whether it passed or failed again, and `s` sends the new log to Claude. The conversation carries on across retries.

## Workflows

Workflows are TOML files in `~/.config/sentry/workflows/`. The shipped ones are written there the first time you open Upgrade. A copy you haven't edited is upgraded when a new version ships; a copy you have edited is never touched.
- `quick-update`: A routine upgrade is one step. When the kernel changes, it runs the NVIDIA kmod ritual: drop the exact layered kmod, reboot, build or layer the new kmod, reboot, then verify the driver and Flatpak GL.
- `rpmfusion-migrate` (one time): RPM Fusion's release packages, installed from a URL, are pinned local packages tied to one Fedora version. This swaps them for the repo-tracked packages (one reboot), so they move with the system and a release rebase needs no swap.
- `release-rebase` ships with `draft = true`: sentry won't start it until you've read it and deleted that line. Before anything is staged, it checks:
  - that every enabled third-party repo (COPRs, RPM Fusion, vendor repos) already has metadata for the target release;
  - that `rpmfusion-migrate` is done.

  Then it pins today's deployment, so a current Fedora N stays in the boot menu after the two new deployments, and does the rebase with the kmod ritual. Optionally it then distro-syncs your toolboxes, after saving each one's package list. Abandoning offers `rollback`, which makes the pinned deployment the next boot.

Each run lives in `~/.local/share/sentry/workflows/<name>/run-<time>/`, holding `state.json`, a copy of the TOML, and `steps/<id>.log`.

Reboots happen only after you confirm them. After one, open `sentry` again. Sentry compares boot ids to tell whether the reboot actually happened, and continues once you open Upgrade (`0`).

Lint (`sentry workflow lint`) checks for unknown fields, duplicate ids, undefined variables, unknown `when` conditions and unknown `sentry check` names. The file format is spec §9.2 plus a few additions described in `docs/spec-addendum.md` A3/A12.

## Config

`~/.config/sentry/config.toml` follows `docs/spec.md` §12, and every key is optional. Additions:
- `[ui] terminal = "ghostty -e"`: the terminal used to enter containers.
- `[flatpak] trusted_origins = ["flathub", "fedora"]`: remotes that aren't flagged as unverified.
- `[baseline] findings = ["repo:rpmfusion-*"]`: audit findings to treat as expected (globs allowed).
- `[keys]`: rebinds, for example `quit = "Q"` or `"screen.history" = "F9"`.

Sentry never writes `config.toml`. What you decide in the TUI goes to machine-written files next to it:
- `baseline.toml`: listeners and findings marked expected.
- `cadence.toml`: job cadences set with `e`.

## Development

`cargo build --release && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`. Parsers are tested against fixtures captured from a real machine (`scripts/capture-fixtures.sh` scrubs usernames, addresses and interface names); screens have insta snapshot tests. `CLAUDE.md` holds the working notes the project was built with.

## Docs

- `docs/spec.md`: the build spec.
- `docs/spec-addendum.md`: binding amendments made after probing the real machine.
- `docs/design/m3-m7.md`: design for the audit, jobs, workflows and recorder.
- `docs/design/sentry-tui.dc.html`: the visual target.

## License

MIT. See [LICENSE](LICENSE).

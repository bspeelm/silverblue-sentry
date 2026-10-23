# sentry

A daemon-free monitor and maintenance TUI for Fedora Silverblue (Rust + ratatui). It runs only while you have it open. Nothing is installed as a service, timer or autostart entry. When it exits, the only things left behind are files under `~/.config/sentry`, `~/.local/share/sentry` and `~/.cache/sentry` (or the `XDG_*_HOME` locations if those are set).

## Install

```sh
cargo build --release
install -Dm755 target/release/sentry ~/.local/bin/sentry
```

You can build inside a toolbox. The binary links only against glibc, so it runs on the host as-is. Inside a toolbox, host tools (`rpm-ostree`, `flatpak`, `podman`, …) are reached through `flatpak-spawn --host`. Run it from a **host** terminal when a workflow step needs `sudo`: a toolbox can't give sudo a terminal to prompt on.

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
| `5` | Containers | toolbox / distrobox / podman, stale and `$HOME` flags. `Enter` opens a shell, `s` stops, `d` removes |
| `6` | Flatpaks | permission flags from metadata + overrides, GL.nvidia pair check, `o` opens Flatseal |
| `7` | Audit | findings + evidence, diff against the previous report. `Enter` audits, `b`/`B` baseline, `[`/`]` browse reports |
| `8` | Jobs | last run, cadence, due status. `Enter` shows the plan, then runs; `e` edits the cadence |
| `9` | Cleanup | reclaimable space from dry runs; `Space` toggles, `Enter` confirms and runs the selection |
| `0` | Upgrade | workflows: start, step cards (confirm / reboot / manual), streaming log, `s` skip, `a` abandon, `R` roll back, `l` log |
| `H` | History | recorder data over 6h/24h/72h (`[`/`]`), `←`/`→` to scrub; the tab appears once `sentry record` has run |

Vim keys work everywhere: `j/k`, `gg/G`, `C-d/C-u`, `h/l` (previous/next screen), `/` filter with `n/N`, and `:` commands (`:q`, `:net`, `:job audit`, `:workflow quick-update`). `C-h`/`C-l` switch panes and `C-j`/`C-k` scroll logs. `?` shows the keys for the current screen.

**Refresh:**
- Live data refreshes only while its screen is visible: the dashboard at 1 Hz, Processes at 2 Hz, Network every 3 s.
- Update checks (`c`), the disk breakdown (`r` on the dashboard) and cleanup plans run only when you ask, and are cached.
- Every destructive action shows a preview, asks you to confirm, then streams its output.

Measured on the host: the open dashboard uses about 0.8% of one core including children, and 8 MB of memory. The recorder uses 0.07% and 10 MB.

## Workflows

Workflows are TOML files in `~/.config/sentry/workflows/`. `quick-update` and `release-rebase` are written there the first time you open Upgrade, and your edits are never overwritten.
- `quick-update` follows `docs/cheatsheets/silverblue-upgrade-cheatsheet.md`. A routine upgrade is one step. When the kernel changes, it runs the NVIDIA kmod ritual: drop the exact layered kmod, reboot, build or layer the new kmod, reboot, then verify the driver and Flatpak GL.
- `release-rebase` ships with `draft = true`. Sentry won't start it until you've reviewed the steps and deleted that line. Neither cheatsheet covers a rebase with locally layered RPM Fusion release packages.

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

## Docs

- `docs/spec.md`: the build spec.
- `docs/spec-addendum.md`: binding amendments made after probing the real machine.
- `docs/design/m3-m7.md`: design for the audit, jobs, workflows and recorder.
- `docs/design/sentry-tui.dc.html`: the visual target.
- `docs/cheatsheets/`: the upgrade procedures the workflows encode.

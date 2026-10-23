# sentry

A daemon-free monitor and maintenance TUI for Fedora Silverblue (Rust + ratatui). It runs only while you have it open. When it exits, the only things it leaves behind are files under `~/.config/sentry`, `~/.local/share/sentry` and `~/.cache/sentry`, using the `XDG_*_HOME` locations if those are set.

## Install

```sh
cargo build --release
install -Dm755 target/release/sentry ~/.local/bin/sentry
```

You can build inside a toolbox. The binary links only against glibc, so it runs on the host as-is. When it runs inside a toolbox, host tools (`rpm-ostree`, `flatpak`, `podman`, …) are reached through `flatpak-spawn --host`.

## Use

| Command | What it does |
|---|---|
| `sentry` | Opens the TUI |
| `sentry collect <name>` | Prints a collector as JSON: `system processes gpu disk disk-breakdown net ostree flatpak flatpak-updates podman units repos shell journal`. Exit code 3 means the tool it needs isn't installed. |
| `sentry status [--short]` | One line built from state files only; runs no collectors |
| `sentry job / check / workflow / record` | Defined, but not built yet (milestones 4–6) |

**Screens:** `1` Dashboard · `2` Processes · `3` Network · `4` Updates · `5` Containers · `6` Flatpaks · `7` Audit · `8` Jobs · `9` Cleanup · `0` Upgrade · `H` History.
Vim keys work everywhere: `j/k`, `gg/G`, `C-d/C-u`, `h/l` (previous/next screen), `/` filter with `n/N`, and a `:` command line (`:q`, `:net`). `?` shows help.

**Refresh behaviour:**
- Live data only refreshes while its screen is visible: the dashboard at 1 Hz, Processes at 2 Hz, and Network every 3 s.
- Update checks (`c`) and the disk breakdown (`r` on the dashboard) are cached and run only when you ask.
- Every destructive action shows a preview, asks you to confirm, then streams its output.

## Config

`~/.config/sentry/config.toml` uses the schema in `docs/spec.md` §12, and every key is optional. Two additions:
- `[ui] terminal = "ghostty -e"`: the terminal used to enter containers.
- `[flatpak] trusted_origins`: remotes that are not flagged as unverified.

Keys can be rebound under `[keys]`, for example `quit = "Q"` or `"screen.history" = "F9"`.

Listeners you mark as expected are written to `~/.config/sentry/baseline.toml`. Sentry never writes `config.toml`.

## Docs

- `docs/spec.md`: the build spec.
- `docs/spec-addendum.md`: binding amendments made after probing the real machine.
- `docs/design/sentry-tui.dc.html`: the visual target.
- `docs/cheatsheets/`: the upgrade procedures that `assets/workflows/*.toml` encode.

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

**v0.3.0, early.** Everything here is built and tested against fixtures and a real Silverblue 44 machine. The quick-update kernel path (`rpm-ostree upgrade`, both reboots, layering the kmod, the GL runtimes) has been run end to end on that machine. Some paths have still only been exercised up to their confirm modal, never executed for real during development: `rpm-ostree rollback`/`cleanup`, `akmods` building a kmod, `flatpak uninstall`, `podman` prune/remove.

- Nothing runs in the background: no services, timers or autostart. The recorder is a foreground process you start and stop.
- Every destructive action shows a preview, waits for your confirmation, and streams its output. Reboots never happen on their own.
- `release-rebase` ships as a **draft** and refuses to start until you've reviewed it and removed `draft = true`.
- Workflow steps that need `sudo` must run from a host terminal, not from inside a toolbox.
- Never root: privileged operations go through `rpm-ostree` (polkit) or `sudo` prompts in your terminal.

## Install

From the [latest release](https://github.com/bspeelm/silverblue-sentry/releases/latest) (x86_64; built on Fedora 44 and linked only against glibc):

```sh
curl -LO https://github.com/bspeelm/silverblue-sentry/releases/download/v0.3.0/silverblue-sentry-0.3.0-x86_64-linux-gnu.tar.gz
curl -LO https://github.com/bspeelm/silverblue-sentry/releases/download/v0.3.0/silverblue-sentry-0.3.0-x86_64-linux-gnu.tar.gz.sha256
sha256sum -c silverblue-sentry-0.3.0-x86_64-linux-gnu.tar.gz.sha256
tar xf silverblue-sentry-0.3.0-x86_64-linux-gnu.tar.gz
install -Dm755 silverblue-sentry-0.3.0/sentry ~/.local/bin/sentry
install -Dm755 silverblue-sentry-0.3.0/sentry-server ~/.local/bin/sentry-server   # optional: servers over ssh
```

From source (a toolbox with `cargo` and `make` works fine; Rust 1.89+):

```sh
make install-binary      # builds sentry and sentry-server and copies them to ~/.local/bin
```

`make uninstall-binary` removes it again, and `make check` runs the build, tests, clippy and fmt.

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
| `0` | Upgrade | workflows: start, step cards (confirm / reboot / manual), streaming log, `s` skip (asks first unless the step is optional), `a` abandon, `R` roll back, `L` log. On a failed step: `r` retry, `d` done by hand (asks first for a failed check), `f` fix with Claude |
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

When a workflow step fails, the failure card offers `[f] fix with Claude`. Claude gets the step's command, exit code, the last 60 lines of its log, the workflow's own advice for that failure, the steps still to come, and the actions open to you (retry, done by hand, skip, rollback, abandon). It answers in the same three parts, ending with which of those actions to take; when the system is already the way the step checks for, it says so and recommends done by hand. It's told not to change deployments (upgrade, rebase, rollback, install/uninstall, override), run akmods or reboot, and not to do later steps itself, because the workflow does those and would fall out of step with the system.

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

## sentry-server: a server over ssh

`sentry-server` is a second binary from the same source, for a server you reach with `ssh`: a Debian or Ubuntu box running systemd services, timers and docker compose. It follows the same rules as `sentry`:
- **Nothing is installed on the server.** It runs read-only commands through one multiplexed ssh connection while you have it open. That connection closes by itself 15 s after the last command.
- **Nothing changes without a confirm box** showing the exact command.
- **The server is described in one file you write,** `~/.config/sentry/server_config.yaml` ([sample](assets/server_config.example.yaml)). sentry-server never rewrites it.

**Setting up a server:**

```sh
sentry-server init myserver --write   # look around (read-only) and draft its entry
$EDITOR ~/.config/sentry/server_config.yaml
sentry-server lint                     # the file, and that what it names exists there
sentry-server check                    # connection, sudo, tools, and each sudo entry
sentry-server                          # the TUI (or: sentry-server myserver)
```

Key-based ssh login is required. **`sudo:` lists read-only commands** sentry-server may run as `sudo -n` (`docker ps`, `smartctl`, `journalctl`, …), because the docker socket, SMART and system journals usually need root. Write commands are refused there. Maintenance gets sudo from its own confirm box. sudo is checked again before each one: if it asks for a password, the terminal is handed over for it (a workflow step's output still lands in its log), and if it stops asking, the command streams. If sudo asks for a password, the read-only commands in `sudo:` can't run in the background; **`I` reads them once with your password** (containers, compose files, SMART, the journal, fail2ban: one sudo, all read-only), and Containers, SMART and the audit use that read, with its age shown, until you read again. Workflow checks never use it: they need the server as it is now.

| Tab | What it shows | Keys |
|---|---|---|
| `1` Overview | CPU, memory and network at 1 Hz; temperatures and GPU; disks against their thresholds, SMART (sleeping disks are left asleep); status rows that jump to their tab | `a` your actions, `B` reboot |
| `2` Services | configured services and timers (last run, next run, result), failed units | `R` restart (or run a timer's job now), `x` reset failed, `L` journal |
| `3` Containers | containers by compose project: state, health, restarts, ports; `c` loads CPU/mem | `R` restart, `L` logs, `p` pull, `u` up -d |
| `4` Updates | a simulated `apt-get dist-upgrade`, held-back packages, reboot required and why | `C` refresh lists, `U` upgrade, `B` reboot |
| `5` Audit | findings: services down, stale or failing timers, containers down or restarted, the docker socket mounted in a container, unexpected listeners, reboot required, updates, SMART damage, full or missing disks… | `c` audit now, `b` mark expected |
| `6` Maintenance | what's kept at a deliberate version (`maintenance:` in the config): images, held packages, apps, an OS's end of life, things to retire. Pinned vs running vs newest upstream (looked up from this machine, at most daily unless you press `c`), security releases marked ⚠, why it's held, its review date. Findings wait for a held item's review date | `A` assess (Claude reads the release notes on the web and your `notes:` files; the answer is kept, `L` shows it), `p` plan the move (pick a version or let Claude recommend one, add a note; Claude writes the execution plan, saved as a Markdown file), `Enter` open the plan (there: `Enter` applies it with the item's workflow, `r` revises it, `x` drops it), `z` look again later, `e` edit the config |
| `0` Workflows | multi-step maintenance in the same TOML format as the local workflows: `apt-maintenance` and `compose-update` are seeded in `~/.config/sentry/server-workflows/`. A server's own workflows go in `~/.config/sentry/servers/<name>/workflows/` and replace the generic ones for that server; `[vars]` are asked for when one starts | Enter, `s`, `d`, `r`, `a`, `L` as on Upgrade |

On Services, Containers, Updates and Audit, `/` filters the list (any column, case-insensitive; `n`/`N` step through, `Esc` clears); each tab keeps its own filter.

A reboot, from `B` or a workflow step, waits in place: sentry-server polls the server's boot id and says when it's back, then a workflow carries on. **`A` asks Claude** about whatever is selected. Claude reaches the server only through `sentry-server exec <server> -- <command>`, an allowlist of read-only commands with no shell, and ssh itself is denied. A read that needs root while sudo asks for a password is queued: when Claude's answer ends you see the exact commands, one sudo with your password runs them (read-only), and the output goes back to Claude. Whatever it proposes, you run after a confirm box.

### Deliberate maintenance

Pinning everything is fine for a while; eventually the pins have to move. `maintenance:` in the config lists what you keep at a deliberate version: compose images, held packages, apps on the host, an OS release's end of life, and things you mean to retire. Each item says why it's held, what limits the choice and when to look at it again. sentry-server then keeps that list honest without ever upgrading anything by itself:

1. **Track** (tab `6`, `sentry-server maint`): pinned vs running vs the newest upstream release, looked up from your machine. Newer releases whose notes mention a security fix are marked; so are drift (what runs isn't the pin), end of life and review dates that have passed. A held item doesn't nag until its review date.
2. **Assess** (`A`): Claude reads the release notes between your pin and the candidates, plus your own notes files, checks the server through the read-only gateway, and says what changed, whether the hold still applies, which version (or "wait"), how risky it really is, and how to roll back.
3. **Plan** (`p`): pick the version, or let Claude recommend one, and add a note ("after Saturday's backup"). Claude researches it (release notes, your notes, the server read-only; reads that need root are asked for) and writes the execution plan: the target, the assessment, what to check and back up before, what to expect at each step of the item's workflow, how to verify, how to roll back, and whether it needs a window. It's saved as `~/.config/sentry/servers/<name>/plans/<item>.md`: a header saying how to apply it (target, workflow, its values, status), then the plan. The Plan view shows it as a document; `r` has Claude revise it.
4. **Apply** (`Enter` in the Plan view): the item's workflow starts with the plan's values filled in, one item at a time, every step behind its confirm card. When it completes the plan moves to `plans/done/`. `z` moves the review date instead. (`p` on an item that has a plan says so: `Enter` opens it, `P` plans again.)
5. **Log**: every workflow run, from a plan or not, is written to `~/.config/sentry/servers/<name>/log/` when it ends: one Markdown entry per run (a `+++` header with item, kind, from/to, workflow, result, when, the steps that failed or were done by hand, the plan it applied, a one-line summary and `key:value` tags, then the steps as a table and your note on what to know next time), and `LOG.md`, a ledger of every entry with its summary and tags. Plans and assessments start from the ledger: Claude picks the earlier runs that bear on the change and reads those entries.

A server's own workflows (`~/.config/sentry/servers/<name>/workflows/`) are where its specific procedure lives: what to check before, the exact pin change, how to verify and roll back.

Headless: `sentry-server audit`, `collect <server> <kind>` (JSON), `cond <server> <condition> [--wait]`, `workflow list|lint [server]`, `maint [server] [--refresh]` (each maintenance item's standing; see `maintenance:` in the sample config). Reports, run state and baselines live under `~/.local/share/sentry/servers/<name>/` and `~/.config/sentry/servers/`.

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

`make check` (build, tests, clippy, fmt). Parsers are tested against fixtures captured from a real machine (`scripts/capture-fixtures.sh` scrubs usernames, addresses and interface names); sentry-server's fixtures are synthetic, in the real commands' formats. Screens have insta snapshot tests. `make privacy-check` keeps private strings (listed one per line in a gitignored `.private-patterns`) out of tracked files, unpushed commit messages and release tarballs. `CLAUDE.md` holds the working notes the project was built with.

## Docs

- `docs/spec.md`: the build spec.
- `docs/spec-addendum.md`: binding amendments made after probing the real machine.
- `docs/design/m3-m7.md`: design for the audit, jobs, workflows and recorder.
- `docs/design/sentry-tui.dc.html`: the visual target.

## License

MIT. See [LICENSE](LICENSE).

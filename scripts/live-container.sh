#!/usr/bin/env bash
# A disposable sshd container for sentry-server's mutating live tests (`#[ignore]`):
#   nopasswd  live_actions, live_workflow, live_sudo_stop   (sudo -n works)
#   password  live_password_step, live_inventory, live_claude_reads, live_sudo_stop
#             (sudo asks; the tests type the password into the TUI's own prompt)
#
#   scripts/live-container.sh up [nopasswd|password]    start one, print how to run its tests
#   scripts/live-container.sh test [nopasswd|password]  run that variant's tests against it
#   scripts/live-container.sh test <mode> <test>...     run only these
#   scripts/live-container.sh env <mode> <test>         the environment one test runs in
#   scripts/live-container.sh down                      remove what `up` made, nothing else
#
# Everything is local: a Debian container published on 127.0.0.1 at a random port, the login
# `tester`, a throwaway key and ssh config in a temp dir (never ~/.ssh), scratch XDG dirs
# (never ~/.config/sentry). Works on the host or inside a toolbox (podman through
# flatpak-spawn --host; ssh and cargo run where the script does).
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=localhost/sentry-live:latest
LABEL=sentry-live
SERVER=scratch # live_inventory reads the inventory of a server with this name
LOGIN=tester
FIX=tests/fixtures/server

if command -v podman >/dev/null 2>&1; then
  P=(podman)
elif command -v flatpak-spawn >/dev/null 2>&1 && flatpak-spawn --host podman --version >/dev/null 2>&1; then
  P=(flatpak-spawn --host podman)
else
  echo "podman not found (tried: podman, flatpak-spawn --host podman)" >&2
  exit 1
fi

die() {
  echo "$*" >&2
  exit 1
}

tests_of() {
  case "$1" in
    nopasswd) echo "live_actions live_workflow live_sudo_stop" ;;
    password) echo "live_password_step live_inventory live_claude_reads live_sudo_stop" ;;
    *) die "mode: nopasswd or password, not \`$1\`" ;;
  esac
}

# The container of a mode, if `up` made one.
ctr_of() {
  "${P[@]}" ps -a --filter "label=$LABEL=1" --filter "label=$LABEL.mode=$1" --format '{{.Names}}' | head -n1
}

dir_of() {
  "${P[@]}" inspect --format "{{ index .Config.Labels \"$LABEL.dir\" }}" "$1"
}

build() {
  # No build context: the files go in over stdin at `up`, so nothing has to be visible to
  # both the host and a toolbox.
  "${P[@]}" build -q -t "$IMAGE" -f - <<EOF >/dev/null
FROM docker.io/library/debian:stable-slim
RUN apt-get update \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \\
      openssh-server sudo procps iproute2 util-linux ca-certificates \\
 && mkdir -p /run/sshd /usr/local/share/fake-docker /srv/stack \\
 && useradd -m -s /bin/bash $LOGIN && usermod -p '*' $LOGIN \\
 && install -d -m 700 -o $LOGIN -g $LOGIN /home/$LOGIN/.ssh
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
EOF
}

# stdin → a file in the container, root's, with this mode.
put() {
  "${P[@]}" exec -i "$1" sh -c "cat >'$2' && chmod $3 '$2'"
}

# A root-only `docker` that prints the synthetic fixtures: what the collectors and the
# inventory ask for, nothing else.
fake_docker() {
  local c=$1
  put "$c" /usr/local/share/fake-docker/inspect.json 600 <"$FIX/docker-inspect.json"
  put "$c" /usr/local/share/fake-docker/compose-ls.json 600 <"$FIX/compose-ls.json"
  put "$c" /usr/local/share/fake-docker/stats.jsonl 600 <"$FIX/docker-stats.jsonl"
  grep -o '"Id": *"[^"]*"' "$FIX/docker-inspect.json" | cut -d'"' -f4 |
    put "$c" /usr/local/share/fake-docker/ids 600
  put "$c" /usr/local/bin/docker 700 <<'EOF'
#!/bin/sh
d=/usr/local/share/fake-docker
case "$1 ${2:-}" in
  "ps -aq") cat "$d/ids" ;;
  "inspect "*) cat "$d/inspect.json" ;;
  "compose ls") cat "$d/compose-ls.json" ;;
  "stats "*) cat "$d/stats.jsonl" ;;
  "logs "*) echo "2026-01-01T00:00:00Z fake docker: no logs" ;;
  *) echo "fake docker: \`$*\` isn't one of the reads it knows" >&2; exit 1 ;;
esac
EOF
  "${P[@]}" exec "$c" chmod 700 /srv/stack
  put "$c" /srv/stack/compose.yaml 600 <<'EOF'
services:
  web:
    image: example/web:1.2.3
EOF
}

# One test's scratch XDG dirs, made afresh: the server's config, and the workflow
# live_password_step starts (beside the seeded ones). Only the password variant has the fake
# docker and its `sudo:` reads: its fixtures have an unhealthy container, which
# apt-maintenance's last step would wait three minutes for.
scratch() {
  local dir=$1 mode=$2 t=$3 x="$1/xdg/$3" reads=""
  [[ $mode != password ]] || reads="
    sudo: [docker ps, docker inspect, docker compose ls]
    compose:
      - name: stack
        file: /srv/stack/compose.yaml"
  rm -rf "$x"
  mkdir -p "$x/config/sentry/server-workflows" "$x/data" "$x/cache"
  cat >"$x/config/sentry/server_config.yaml" <<EOF
servers:
  $SERVER:
    ssh: $SERVER$reads
    actions:
      - id: hello
        title: Say hello
        run: echo "hello from \$(hostname)"
EOF
  cat >"$x/config/sentry/server-workflows/pw-check.toml" <<'EOF'
name = "pw-check"
description = "A sudo step (the password is asked for), an auto step and another sudo step after it, a long sudo step to abandon"

[[steps]]
id = "update"
title = "Refresh package lists"
run = "sudo apt-get update"
gate = "confirm"

[[steps]]
id = "after"
title = "Runs by itself afterwards"
run = "echo after-ok"
gate = "auto"

[[steps]]
id = "again"
title = "sudo again, nested: nothing is asked, and nothing waits on stdin"
run = "head -5; sudo head -5; sh -c 'sudo sh -c \"sudo id -un\"' | sed 's/$/-again/'"
gate = "auto"

[[steps]]
id = "long"
title = "A long step, to abandon"
run = "sudo sleep 600"
gate = "confirm"
EOF
}

env_of() {
  local dir=$1 t=$2 x="$1/xdg/$2"
  printf 'SENTRY_SSH_CONFIG=%q SENTRY_SERVER_SCRATCH=%q XDG_CONFIG_HOME=%q XDG_DATA_HOME=%q XDG_CACHE_HOME=%q' \
    "$dir/ssh_config" "$SERVER" "$x/config" "$x/data" "$x/cache"
  # The file that holds the container's sudo password (never the password itself).
  [[ ! -f "$dir/password" ]] || printf ' SENTRY_SERVER_SCRATCH_PASSWORD=%q' "$dir/password"
}

up() {
  local mode=$1 c dir port pw
  tests_of "$mode" >/dev/null
  [[ -z "$(ctr_of "$mode")" ]] || die "a $mode container is already up ($(ctr_of "$mode")): \`$0 down\` first"
  build
  dir=$(mktemp -d "${TMPDIR:-/tmp}/sentry-live.XXXXXXXX")
  touch "$dir/.sentry-live"
  c="sentry-live-$mode-${dir##*.}"
  "${P[@]}" run -d --name "$c" --label "$LABEL=1" --label "$LABEL.mode=$mode" \
    --label "$LABEL.dir=$dir" -p 127.0.0.1::22 "$IMAGE" >/dev/null
  port=$("${P[@]}" port "$c" 22/tcp | head -n1)
  port=${port##*:}

  ssh-keygen -q -t ed25519 -N '' -C sentry-live -f "$dir/key"
  put "$c" "/home/$LOGIN/.ssh/authorized_keys" 600 <"$dir/key.pub"
  "${P[@]}" exec "$c" chown "$LOGIN:$LOGIN" "/home/$LOGIN/.ssh/authorized_keys"
  cat >"$dir/ssh_config" <<EOF
Host $SERVER
  HostName 127.0.0.1
  Port $port
  User $LOGIN
  IdentityFile $dir/key
  IdentitiesOnly yes
  IdentityAgent none
  StrictHostKeyChecking no
  UserKnownHostsFile $dir/known_hosts
  GlobalKnownHostsFile /dev/null
  LogLevel ERROR
EOF

  if [[ $mode == password ]]; then
    pw=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
    (umask 077 && printf '%s\n' "$pw" >"$dir/password")
    printf '%s:%s\n' "$LOGIN" "$pw" | "${P[@]}" exec -i "$c" chpasswd
    # Asked every time: a password typed for one step never answers a later `sudo -n`.
    printf '%s ALL=(ALL) ALL\nDefaults timestamp_timeout=0\n' "$LOGIN" | put "$c" /etc/sudoers.d/live 440
    fake_docker "$c"
  else
    printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$LOGIN" | put "$c" /etc/sudoers.d/live 440
  fi

  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    ssh -F "$dir/ssh_config" -o BatchMode=yes -o ConnectTimeout=2 "$SERVER" true 2>/dev/null && break
    [[ $i -lt 10 ]] || die "sshd in $c didn't answer on 127.0.0.1:$port"
    sleep 1
  done
  for t in $(tests_of "$mode"); do scratch "$dir" "$mode" "$t"; done

  echo "$c is up: $LOGIN@127.0.0.1:$port, sudo: $mode, files in $dir"
  echo
  echo "Run its tests:   $0 test $mode"
  echo "or one by hand (cargo build -p sentry-server first: workflow steps run the binary):"
  for t in $(tests_of "$mode"); do
    echo "  $(env_of "$dir" "$t") \\"
    echo "    cargo test -p sentry-server $t -- --ignored --nocapture"
  done
  echo "Remove it:       $0 down"
}

run_tests() {
  local mode=$1 c dir t rc=0
  shift
  c=$(ctr_of "$mode")
  [[ -n "$c" ]] || die "no $mode container: \`$0 up $mode\` first"
  dir=$(dir_of "$c")
  [[ $# -gt 0 ]] || set -- $(tests_of "$mode")
  # Workflow steps (`sentry-server cond …`) run the binary beside the test's.
  cargo build -q -p sentry-server
  for t in "$@"; do
    scratch "$dir" "$mode" "$t"
    echo "=== $t ($mode)"
    local cmd=(env "SENTRY_SSH_CONFIG=$dir/ssh_config" "SENTRY_SERVER_SCRATCH=$SERVER"
      "XDG_CONFIG_HOME=$dir/xdg/$t/config" "XDG_DATA_HOME=$dir/xdg/$t/data"
      "XDG_CACHE_HOME=$dir/xdg/$t/cache"
      cargo test -q -p sentry-server "$t" -- --ignored --nocapture --test-threads=1)
    # The tests type the password into the TUI's prompt: no terminal is involved.
    [[ $mode != password ]] || cmd=(env "SENTRY_SERVER_SCRATCH_PASSWORD=$dir/password" "${cmd[@]}")
    "${cmd[@]}" </dev/null || rc=$?
    [[ $rc -eq 0 ]] && echo "=== $t: ok" || { echo "=== $t: FAILED (exit $rc)"; return "$rc"; }
  done
}

down() {
  local c dir n=0
  for c in $("${P[@]}" ps -a --filter "label=$LABEL=1" --format '{{.Names}}'); do
    dir=$(dir_of "$c")
    "${P[@]}" rm -f "$c" >/dev/null
    # Only a directory `up` made: it left this marker in it.
    if [[ -n "$dir" && -f "$dir/.sentry-live" ]]; then
      rm -rf "$dir"
    fi
    echo "removed $c and $dir"
    n=$((n + 1))
  done
  [[ $n -gt 0 ]] || echo "nothing to remove"
}

case "${1:-}" in
  up) up "${2:-nopasswd}" ;;
  test)
    mode=${2:-nopasswd}
    shift $(($# > 2 ? 2 : $#))
    run_tests "$mode" "$@"
    ;;
  env)
    [[ $# -eq 3 ]] || die "usage: $0 env <mode> <test>"
    c=$(ctr_of "$2")
    [[ -n "$c" ]] || die "no $2 container: \`$0 up $2\` first"
    env_of "$(dir_of "$c")" "$3"
    echo
    ;;
  down) down ;;
  *)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac

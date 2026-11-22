#!/usr/bin/env bash
# The two disposable targets together, for `live_resolution` (`crates/sentry`, `#[ignore]`):
# the Debian sshd container whose sudo asks for a password ("the server",
# scripts/live-container.sh) and the OpenWrt container ("the router",
# scripts/live-router.sh), on one podman network so the router can reach the server.
# One session, started on the router, whose check (fetch a port on the server) fails; its
# plan opens that port on the server with sudo, captures the token the server prints, and
# the router's check presents it.
#
#   scripts/live-resolution.sh up     start both, on a network of their own
#   scripts/live-resolution.sh test   run live_resolution against them
#   scripts/live-resolution.sh down   remove both, the network and the scratch dir
#
# Everything is local and throwaway, as in the two scripts it calls: keys, ssh config and
# XDG dirs in temp dirs, never ~/.ssh or ~/.config/sentry.
set -euo pipefail
cd "$(dirname "$0")/.."

NETWORK=sentry-resolution

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

server() {
  "${P[@]}" ps -a --filter "label=sentry-live=1" --filter "label=sentry-live.mode=password" --format '{{.Names}}' | head -n1
}

router() {
  "${P[@]}" ps -a --filter "label=sentry-router=1" --format '{{.Names}}' | head -n1
}

dir_of() {
  "${P[@]}" inspect --format "{{ index .Config.Labels \"$2\" }}" "$1"
}

# What the server's step runs as root: a listener on 8080 that answers only a request
# naming the token it prints (its last line).
door() {
  "${P[@]}" exec -i "$1" sh -c 'cat >/usr/local/sbin/open-door && chmod 700 /usr/local/sbin/open-door' <<'DOOR'
#!/bin/sh
t=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '%s\n' "$t" >/tmp/door-token
chmod 644 /tmp/door-token
pkill -f door-listener 2>/dev/null
setsid perl -e '
  # door-listener
  use IO::Socket::INET;
  my $t = shift;
  my $s = IO::Socket::INET->new(LocalPort => 8080, Listen => 5, ReuseAddr => 1) or die;
  while (my $c = $s->accept) {
    my $l = <$c>;
    if (defined $l && index($l, $t) >= 0) { print $c "HTTP/1.0 200 OK\r\n\r\ndoor-open\n" }
    else { print $c "HTTP/1.0 403 Forbidden\r\n\r\nno\n" }
    close $c;
  }' "$t" >/dev/null 2>&1 </dev/null &
sleep 1
echo "the door is open on 8080"
echo "$t"
DOOR
}

up() {
  [[ -z "$(server)" && -z "$(router)" ]] || die "a live container or router is already up: \`$0 down\` (or the other scripts' down) first"
  "${P[@]}" network exists "$NETWORK" || "${P[@]}" network create "$NETWORK" >/dev/null
  SENTRY_LIVE_NET=$NETWORK scripts/live-container.sh up password >/dev/null
  SENTRY_LIVE_NET=$NETWORK scripts/live-router.sh up >/dev/null
  door "$(server)"
  echo "$(server) and $(router) are up on the podman network $NETWORK"
  echo "Run the test:   $0 test"
  echo "Remove them:    $0 down"
}

run_test() {
  local s r sdir rdir dir addr x
  s=$(server)
  r=$(router)
  [[ -n "$s" && -n "$r" ]] || die "not up: \`$0 up\` first"
  sdir=$(dir_of "$s" sentry-live.dir)
  rdir=$(dir_of "$r" sentry-router.dir)
  addr=$("${P[@]}" inspect --format "{{ (index .NetworkSettings.Networks \"$NETWORK\").IPAddress }}" "$s")
  [[ -n "$addr" ]] || die "$s has no address on $NETWORK"
  # One scratch dir for the window: both ssh hosts, both configs.
  dir="$sdir/resolution"
  x="$dir/xdg"
  rm -rf "$dir"
  mkdir -p "$x/config/sentry" "$x/data" "$x/cache"
  cat "$sdir/ssh_config" "$rdir/ssh_config" >"$dir/ssh_config"
  cat >"$x/config/sentry/server_config.yaml" <<YAML
servers:
  scratch:
    ssh: scratch
YAML
  cat >"$x/config/sentry/network_config.yaml" <<YAML
networks:
  lab:
    router: { ssh: lab-router, kind: openwrt }
    expect:
      zones: { lan: [lan], dmz: [dmz], wan: [wan, wan6] }
    guard: { window: 20 }
YAML
  printf '[review]\nat_start = false\nafter_run = false\n' >"$x/config/sentry/config.toml"
  "${P[@]}" exec "$s" sh -c "pkill -f '[d]oor-listener'; rm -f /tmp/door-token; true"
  cargo build -q -p sentry
  echo "=== live_resolution"
  env "SENTRY_SSH_CONFIG=$dir/ssh_config" SENTRY_SERVER_SCRATCH=scratch SENTRY_ROUTER_SCRATCH=lab \
    "SENTRY_SERVER_SCRATCH_PASSWORD=$sdir/password" "SENTRY_RESOLUTION_ADDR=$addr" \
    "XDG_CONFIG_HOME=$x/config" "XDG_DATA_HOME=$x/data" "XDG_CACHE_HOME=$x/cache" SENTRY_NO_REBOOT=1 \
    cargo test -q -p sentry live_resolution -- --ignored --nocapture --test-threads=1 </dev/null
  echo "=== live_resolution: ok"
}

down() {
  scripts/live-container.sh down
  scripts/live-router.sh down
  if "${P[@]}" network exists "$NETWORK"; then
    "${P[@]}" network rm "$NETWORK" >/dev/null && echo "removed the network $NETWORK"
  fi
}

case "${1:-}" in
  up) up ;;
  test) run_test ;;
  down) down ;;
  *)
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac

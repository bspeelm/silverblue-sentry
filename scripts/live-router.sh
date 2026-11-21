#!/usr/bin/env bash
# A disposable OpenWrt router for the network target's mutating live tests (`#[ignore]`):
#   live_router_policy, live_guard_keeps, live_guard_reverts, live_guard_wifi_asks,
#   live_guard_foreign_staged, live_guard_arm_unverified, live_router_session,
#   live_package_update
# Everything that changes a router is developed and proven against this, never a real one.
#
#   scripts/live-router.sh up                 start it, print how to run its tests
#   scripts/live-router.sh test [<test>...]   run the tests (all, or only these) against it
#   scripts/live-router.sh env <test>         the environment one test runs in
#   scripts/live-router.sh sh [<command>]     a root shell (or one command) on it, over ssh
#   scripts/live-router.sh down               remove what `up` made, nothing else
#
# What it is: the official `openwrt/rootfs` userland (x86_64, the release below) under
# podman with its own init: procd, ubus, netifd, logd, rpcd, uhttpd, odhcpd and dropbear
# all run; `uci`, `apk`, `logread`, `setsid`, `sysupgrade -l` work. Root logs in with a
# throwaway key on 127.0.0.1 at a random port; the ssh config and scratch XDG dirs live in
# a temp dir (never ~/.ssh, never ~/.config/sentry). `/etc/config` is a synthetic set:
# network (lan, dmz, wan, wan6), firewall (lan/wan/dmz zones, three redirects), dhcp (two
# static hosts), wireless (two radios, keys planted for the scrubbing tests), dropbear,
# uhttpd; `/tmp/dhcp.leases` has invented leases.
#
# What it can't emulate (rootless, no CAP_NET_ADMIN, no radios):
#   - Wi-Fi: no radio, no hostapd/wpad, no `wifi`, `iw` or `iwinfo`. The wireless config can
#     be staged and committed; nothing applies it, and no station is ever counted.
#   - nft/fw4: `nft` and `fw4 reload` fail (not permitted). The firewall config is only a file.
#   - Interfaces: lan, dmz, wan and wan6 exist in netifd but are down (no such device); no
#     DSA ports, no bridge. `ip` shows the container's own interface, which podman (pasta)
#     gives this machine's addresses: never paste its output anywhere.
#   - dnsmasq doesn't run (its jail can't be made); its reload is still a command that exits 0.
#   - sysupgrade/owut flashing, and a reboot (which would only stop the container).
#   - adblock-fast and its always-staged lines; the real router's package set.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=docker.io/openwrt/rootfs:x86_64-v25.12.5
LABEL=sentry-router
NET=lab         # the network's name in the scratch network_config.yaml
ALIAS=lab-router # what ssh connects to (the scratch ssh config's Host)

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

TESTS="live_router_policy live_guard_foreign_staged live_guard_arm_unverified live_guard_keeps live_guard_reverts live_guard_wifi_asks live_router_session live_package_update"

ctr() {
  "${P[@]}" ps -a --filter "label=$LABEL=1" --format '{{.Names}}' | head -n1
}

dir_of() {
  "${P[@]}" inspect --format "{{ index .Config.Labels \"$LABEL.dir\" }}" "$1"
}

# stdin → a file in the container, root's, with this mode.
put() {
  "${P[@]}" exec -i "$1" sh -c "cat >'$2' && chmod $3 '$2'"
}

# The synthetic /etc/config set and leases (documentation addresses, invented names), and
# nothing staged, no guard left over. Run at `up` and before every test.
seed() {
  local c=$1
  "${P[@]}" exec "$c" sh -c 'rm -rf /tmp/.uci /tmp/sentry-guard* /tmp/sentry-canary /tmp/sentry-victim /tmp/sentry-proof; [ -x /usr/bin/setsid.off ] && mv /usr/bin/setsid.off /usr/bin/setsid; true'
  put "$c" /etc/config/network 600 <<'EOF'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1/8'

config globals 'globals'
	option ula_prefix 'fd00:db8:1::/48'

config device
	option name 'br-lan'
	option type 'bridge'
	list ports 'lan1'
	list ports 'lan2'

config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.0.2.1/24'

config interface 'dmz'
	option device 'lan5'
	option proto 'static'
	option ipaddr '198.51.100.1/24'

config interface 'wan'
	option device 'wan'
	option proto 'dhcp'

config interface 'wan6'
	option device 'wan'
	option proto 'dhcpv6'
EOF
  put "$c" /etc/config/firewall 600 <<'EOF'
config defaults
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option synflood_protect '1'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'

config zone
	option name 'wan'
	list network 'wan'
	list network 'wan6'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'

config zone
	option name 'dmz'
	list network 'dmz'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'

config forwarding
	option src 'lan'
	option dest 'wan'

config redirect 'web_https'
	option name 'web'
	option target 'DNAT'
	option src 'wan'
	option dest 'lan'
	option proto 'tcp'
	option src_dport '443'
	option dest_ip '192.0.2.10'
	option dest_port '443'

config redirect
	option name 'game'
	option target 'DNAT'
	option src 'wan'
	option dest 'lan'
	option proto 'udp'
	option src_dport '8000-8010'
	option dest_ip '192.0.2.20'

config redirect
	option name 'old-cam'
	option target 'DNAT'
	option src 'wan'
	option proto 'tcp'
	option src_dport '8554'
	option dest_ip '192.0.2.50'
	option enabled '0'
EOF
  put "$c" /etc/config/dhcp 600 <<'EOF'
config dnsmasq
	option domainneeded '1'
	option localise_queries '1'
	option local '/lan/'
	option domain 'lan'
	option authoritative '1'
	option leasefile '/tmp/dhcp.leases'

config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
	option leasetime '12h'

config dhcp 'wan'
	option interface 'wan'
	option ignore '1'

config host
	option name 'nas'
	option mac '02:00:5e:00:53:01'
	option ip '192.0.2.10'

config host
	option name 'panel'
	option mac '02:00:5e:00:53:02'
	option ip '192.0.2.11'
EOF
  put "$c" /etc/config/wireless 600 <<'EOF'
config wifi-device 'radio0'
	option type 'mac80211'
	option band '2g'
	option channel '1'

config wifi-iface 'default_radio0'
	option device 'radio0'
	option network 'lan'
	option mode 'ap'
	option ssid 'Example Net'
	option encryption 'sae-mixed'
	option key 'correct horse battery'

config wifi-device 'radio1'
	option type 'mac80211'
	option band '5g'
	option channel '36'

config wifi-iface 'default_radio1'
	option device 'radio1'
	option network 'lan'
	option mode 'ap'
	option ssid 'Example Net 5G'
	option encryption 'sae'
	option sae_password 'planted sae secret'
EOF
  put "$c" /etc/config/dropbear 600 <<'EOF'
config dropbear 'main'
	option enable '1'
	option PasswordAuth 'off'
	option RootPasswordAuth 'off'
	option Port '22'
EOF
  # (uhttpd's own config is the image's.)
  put "$c" /tmp/dhcp.leases 644 <<'EOF'
1790000000 02:00:5e:00:53:01 192.0.2.10 storage-box 01:02:00:5e:00:53:01
1790000000 02:00:5e:00:53:02 192.0.2.11 panel *
1790000000 00:00:5e:00:53:77 192.0.2.120 kitchen-tablet *
1790000000 00:00:5e:00:53:78 192.0.2.121 * *
EOF
  "${P[@]}" exec "$c" sh -c '/etc/init.d/dropbear reload >/dev/null 2>&1; /etc/init.d/network reload >/dev/null 2>&1; true'
}

# One test's scratch XDG dirs, made afresh: the network's config (a short guard window
# where the test waits for a revert), nothing else.
scratch() {
  local dir=$1 t=$2 x="$1/xdg/$2" window=20
  case "$t" in
    live_guard_reverts | live_guard_wifi_asks) window=6 ;;
  esac
  rm -rf "$x"
  mkdir -p "$x/config/sentry" "$x/data" "$x/cache"
  cat >"$x/config/sentry/network_config.yaml" <<EOF
networks:
  $NET:
    router: { ssh: $ALIAS, kind: openwrt }
    expect:
      zones: { lan: [lan], dmz: [dmz], wan: [wan, wan6] }
      forwards:
        - { name: web, proto: tcp, port: 443, to: 192.0.2.10 }
        - { name: game, proto: udp, port: 8000-8010, to: 192.0.2.20 }
    devices:
      - { name: nas, mac: "02:00:5e:00:53:01" }
      - { name: panel, mac: "02:00:5e:00:53:02", leave_alone: true }
    guard: { window: $window }
EOF
}

env_of() {
  local dir=$1 t=$2 x="$1/xdg/$2"
  printf 'SENTRY_SSH_CONFIG=%q SENTRY_ROUTER_SCRATCH=%q XDG_CONFIG_HOME=%q XDG_DATA_HOME=%q XDG_CACHE_HOME=%q' \
    "$dir/ssh_config" "$NET" "$x/config" "$x/data" "$x/cache"
}

up() {
  local c dir port i
  [[ -z "$(ctr)" ]] || die "a router is already up ($(ctr)): \`$0 down\` first"
  dir=$(mktemp -d "${TMPDIR:-/tmp}/sentry-router.XXXXXXXX")
  touch "$dir/.sentry-router"
  c="sentry-router-${dir##*.}"
  "${P[@]}" run -d --name "$c" --label "$LABEL=1" --label "$LABEL.dir=$dir" \
    -p 127.0.0.1::22 "$IMAGE" /sbin/init >/dev/null
  port=$("${P[@]}" port "$c" 22/tcp | head -n1)
  port=${port##*:}

  ssh-keygen -q -t ed25519 -N '' -C sentry-router -f "$dir/key"
  # procd is up when ubus answers.
  for i in $(seq 1 30); do
    "${P[@]}" exec "$c" ubus call system board >/dev/null 2>&1 && break
    [[ $i -lt 30 ]] || die "procd in $c didn't come up"
    sleep 1
  done
  "${P[@]}" exec "$c" mkdir -p /etc/dropbear
  put "$c" /etc/dropbear/authorized_keys 600 <"$dir/key.pub"
  seed "$c"
  cat >"$dir/ssh_config" <<EOF
Host $ALIAS
  HostName 127.0.0.1
  Port $port
  User root
  IdentityFile $dir/key
  IdentitiesOnly yes
  IdentityAgent none
  StrictHostKeyChecking no
  UserKnownHostsFile $dir/known_hosts
  GlobalKnownHostsFile /dev/null
  LogLevel ERROR
EOF
  for i in $(seq 1 15); do
    ssh -F "$dir/ssh_config" -o BatchMode=yes -o ConnectTimeout=2 "$ALIAS" true 2>/dev/null && break
    [[ $i -lt 15 ]] || die "dropbear in $c didn't answer on 127.0.0.1:$port"
    sleep 1
  done
  for t in $TESTS; do scratch "$dir" "$t"; done

  echo "$c is up: root@127.0.0.1:$port (OpenWrt ${IMAGE##*-v}), files in $dir"
  echo
  echo "Run its tests:   $0 test"
  echo "or one by hand (cargo build -p sentry first: workflow steps run the binary):"
  echo "  $(env_of "$dir" live_guard_keeps) \\"
  echo "    cargo test -p sentry-network live_guard_keeps -- --ignored --nocapture"
  echo "A shell on it:   $0 sh"
  echo "Remove it:       $0 down"
}

run_tests() {
  local c dir t rc=0
  c=$(ctr)
  [[ -n "$c" ]] || die "no router: \`$0 up\` first"
  dir=$(dir_of "$c")
  [[ $# -gt 0 ]] || set -- $TESTS
  # Workflow steps (`sentry-network guard …`) run the binary beside the test's.
  cargo build -q -p sentry
  for t in "$@"; do
    seed "$c"
    scratch "$dir" "$t"
    echo "=== $t"
    env "SENTRY_SSH_CONFIG=$dir/ssh_config" "SENTRY_ROUTER_SCRATCH=$NET" \
      "XDG_CONFIG_HOME=$dir/xdg/$t/config" "XDG_DATA_HOME=$dir/xdg/$t/data" \
      "XDG_CACHE_HOME=$dir/xdg/$t/cache" \
      cargo test -q -p sentry-network "$t" -- --ignored --nocapture --test-threads=1 </dev/null || rc=$?
    [[ $rc -eq 0 ]] && echo "=== $t: ok" || {
      echo "=== $t: FAILED (exit $rc)"
      return "$rc"
    }
  done
  seed "$c"
}

down() {
  local c dir n=0
  for c in $("${P[@]}" ps -a --filter "label=$LABEL=1" --format '{{.Names}}'); do
    dir=$(dir_of "$c")
    "${P[@]}" rm -f "$c" >/dev/null
    # Only a directory `up` made: it left this marker in it.
    if [[ -n "$dir" && -f "$dir/.sentry-router" ]]; then
      rm -rf "$dir"
    fi
    echo "removed $c and $dir"
    n=$((n + 1))
  done
  [[ $n -gt 0 ]] || echo "nothing to remove"
}

case "${1:-}" in
  up) up ;;
  test)
    shift
    run_tests "$@"
    ;;
  env)
    [[ $# -eq 2 ]] || die "usage: $0 env <test>"
    c=$(ctr)
    [[ -n "$c" ]] || die "no router: \`$0 up\` first"
    env_of "$(dir_of "$c")" "$2"
    echo
    ;;
  sh)
    c=$(ctr)
    [[ -n "$c" ]] || die "no router: \`$0 up\` first"
    shift
    exec ssh -F "$(dir_of "$c")/ssh_config" "$ALIAS" "$@"
    ;;
  down) down ;;
  *)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac

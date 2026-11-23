#!/usr/bin/env bash
# A disposable OpenWrt router for the network target's mutating live tests (`#[ignore]`):
#   live_router_policy, live_guard_keeps, live_guard_reverts, live_guard_wifi_asks,
#   live_guard_foreign_staged, live_guard_arm_unverified, live_guard_race,
#   live_guard_reboot, live_guard_stale_leftover, live_router_session, live_package_update,
#   live_router_security, live_security_block, live_security_forward, live_security_ssh_keys_only,
#   live_firmware_upgrade, live_security_filter, live_security_takeover,
#   live_setup (the window's own: a first run with no config at all; the setup flow finds
#   the router among the ssh hosts, looks at it for real, drafts it as a network, and
#   saves; then its tab reads. Reads only.)
# Everything that changes a router is developed and proven against this, never a real one.
#
#   scripts/live-router.sh up                 start it, print how to run its tests
#   scripts/live-router.sh test [<test>...]   run the tests (all, or only these) against it
#   scripts/live-router.sh env <test>         the environment one test runs in
#   scripts/live-router.sh sh [<command>]     a root shell (or one command) on it, over ssh
#   scripts/live-router.sh down               remove what `up` made, nothing else
#   (SENTRY_ROUTER_LABEL=<word> in front of each: a second router beside one already up)
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
#   - sysupgrade/owut flashing, and a reboot (which would only stop the container). For the
#     firmware upgrade there are stand-ins (`stubs`): `/usr/bin/owut` prints sentry's
#     synthetic fixtures and makes a random "image" with a real checksum and a manifest of
#     the packages installed here; `/sbin/sysupgrade` is the real one but for `--test`
#     (passes any file that isn't empty) and a flash, which is pretend: after 2 s dropbear
#     stops (new logins fail; sessions already open stay, unlike a real restart), the files
#     in /tmp it was given go, then after a delay (8 s; 45 s in mode `slow`) the boot id
#     changes (the container's boot_id is a file of the script's, bind-mounted over
#     /proc/sys/kernel/random/boot_id), os-release says 25.12.6, `partx-utils` is removed in
#     mode `missing`, and dropbear starts again. Nothing is written to any storage but the
#     container's, nothing restarts, the kernel and every other process stay as they were.
#     The mode is in /etc/sentry-stub/mode (ok, warn, badsum, slow, missing; newest: owut check says there is nothing newer; silent: owut install ends without a word and flashes nothing; hang: owut install keeps working for 5 min, the router answering); `seed` puts
#     it back to ok and the release back to 25.12.5.
#   - adblock-fast and its always-staged lines; the real router's package set.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=docker.io/openwrt/rootfs:x86_64-v25.12.5
LABEL=${SENTRY_ROUTER_LABEL:-sentry-router} # another label: a second router beside the first
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

TESTS="live_router_policy live_guard_foreign_staged live_guard_arm_unverified live_guard_keeps live_guard_reverts live_guard_wifi_asks live_guard_race live_guard_reboot live_guard_stale_leftover live_router_session live_package_update live_router_security live_security_block live_security_forward live_security_ssh_keys_only live_firmware_upgrade live_security_filter live_security_takeover live_setup"

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
# Stand-ins for the firmware upgrade (see the header): owut, sysupgrade's --test and flash,
# a pretend restart. The real ones are kept beside them (owut.real, sysupgrade.real).
stubs() {
  local c=$1 f=tests/fixtures/network/firmware
  "${P[@]}" exec "$c" sh -c 'mkdir -p /usr/share/sentry-stub /etc/sentry-stub; S=/usr/share/sentry-stub; cp /usr/lib/os-release $S/os-release; cp /etc/openwrt_release $S/openwrt_release; [ -e /usr/bin/owut.real ] || mv /usr/bin/owut /usr/bin/owut.real; [ -e /sbin/sysupgrade.real ] || mv /sbin/sysupgrade /sbin/sysupgrade.real; echo ok >/etc/sentry-stub/mode'
  put "$c" /usr/share/sentry-stub/check.txt 644 <"$f/check.txt"
  put "$c" /usr/share/sentry-stub/check-downgrade.txt 644 <"$f/check-downgrade.txt"
  put "$c" /usr/share/sentry-stub/check-newest.txt 644 <"$f/check-newest.txt"
  put "$c" /usr/share/sentry-stub/download.txt 644 <"$f/download.txt"
  put "$c" /usr/bin/owut 755 <<'EOF'
#!/bin/sh
# A stand-in for owut (scripts/live-router.sh): sentry's synthetic fixtures, a random image.
S=/usr/share/sentry-stub
mode=$(cat /etc/sentry-stub/mode 2>/dev/null || echo ok)
cmd=$1
[ $# -gt 0 ] && shift
img=/tmp/firmware.bin
while [ $# -gt 0 ]; do
  case "$1" in -i) img=$2; shift ;; esac
  shift
done
stem=${img%.*}
case "$cmd" in
check)
  [ "$mode" = warn ] && { cat $S/check-downgrade.txt; exit 0; }
  [ "$mode" = newest ] && { cat $S/check-newest.txt; exit 0; }
  cat $S/check.txt
  ;;
download)
  [ "$mode" = warn ] && { cat $S/check-downgrade.txt; echo "ERROR: Update checks reveal package downgrades" >&2; exit 1; }
  head -c 1048576 /dev/urandom >"$img"
  sum=$(sha256sum "$img" | cut -d' ' -f1)
  size=$(wc -c <"$img")
  echo "$sum  $img" >"$stem.sha256sums"
  [ "$mode" = badsum ] && sum=0000000000000000000000000000000000000000000000000000000000000000
  {
    printf '{"version_number":"25.12.6","version_code":"r33311-981c978eff","images":[{"type":"sysupgrade","name":"stub-sysupgrade.bin","sha256":"%s","size":%s}],"manifest":' "$sum" "$size"
    ubus call rpc-sys packagelist '{"all":true}' | jsonfilter -e '@.packages'
    printf '}\n'
  } >"$stem-manifest.json"
  sed "s#/tmp/sentry-firmware#$stem#g" $S/download.txt
  /sbin/sysupgrade --test "$img" || { rm -f "$img"; exit 1; }
  ;;
install)
  [ -s "$img" ] || { echo "ERROR: Image file '$img' does not exist" >&2; exit 1; }
  sha256sum -c "$stem.sha256sums" >/dev/null 2>&1 || { echo "ERROR: sha256 doesn't match:" >&2; exit 1; }
  echo "Checks complete, image is valid."
  # Refused without a word, or at work for a long while (the router answering meanwhile).
  [ "$mode" = silent ] && exit 0
  [ "$mode" = hang ] && { sleep 300; exit 0; }
  echo "Installing $img and rebooting..."
  /sbin/sysupgrade "$img"
  ;;
*)
  echo "ERROR: '$cmd' isn't stubbed" >&2
  exit 1
  ;;
esac
EOF
  put "$c" /sbin/sysupgrade 755 <<'EOF'
#!/bin/sh
# A stand-in for sysupgrade's --test and flash (scripts/live-router.sh); the rest is real.
case "$1" in
-T | --test)
  [ -s "$2" ] && { echo "verifying sysupgrade tar file integrity" >&2; exit 0; }
  echo "Image check failed." >&2
  exit 1
  ;;
-*) exec /sbin/sysupgrade.real "$@" ;;
esac
[ -s "$1" ] || exec /sbin/sysupgrade.real "$@"
mode=$(cat /etc/sentry-stub/mode 2>/dev/null || echo ok)
down=8
[ "$mode" = slow ] && down=45
img=$1
setsid sh -c "sleep 2; /etc/init.d/dropbear stop; rm -f ${img%.*}* /tmp/sentry-flash.log; sleep $down; cat /proc/sys/kernel/random/uuid >/run/sentry-boot/boot_id; sed -i 's/25\.12\.5/25.12.6/g' /usr/lib/os-release /etc/openwrt_release; [ $mode = missing ] && apk --no-network del -q partx-utils; /etc/init.d/dropbear start" </dev/null >/dev/null 2>&1 &
exit 0
EOF
}

seed() {
  local c=$1
  "${P[@]}" exec "$c" sh -c 'for p in /tmp/sentry-guard-*/pid /tmp/sentry-guard-*/sleep.pid; do [ -s "$p" ] && kill -9 "$(cat "$p")" 2>/dev/null; done; rm -rf /tmp/.uci /tmp/sentry-guard* /etc/sentry-guard /etc/sentry-guard.last /etc/uci-defaults/zz-sentry-guard-* /tmp/sentry-canary /tmp/sentry-victim /tmp/sentry-proof; [ -x /usr/bin/setsid.off ] && mv /usr/bin/setsid.off /usr/bin/setsid; [ -x /etc/init.d/https-dns-proxy ] && /etc/init.d/https-dns-proxy stop >/dev/null 2>&1; rm -f /etc/init.d/https-dns-proxy /etc/config/https-dns-proxy; [ -s /tmp/sentry-dm.pid ] && kill \"$(cat /tmp/sentry-dm.pid)\" 2>/dev/null; rm -f /tmp/sentry-dm.pid; true'
  # The firmware stand-ins: back to the release it was, nothing downloaded, mode ok.
  "${P[@]}" exec "$c" sh -c 'S=/usr/share/sentry-stub; [ -d $S ] || exit 0; for p in /proc/[0-9]*; do grep -qE "run/sentry-bo[o]t|owut[^a-z]*[i]nstall" $p/cmdline 2>/dev/null && kill ${p#/proc/} 2>/dev/null; done; cp $S/os-release /usr/lib/os-release; cp $S/openwrt_release /etc/openwrt_release; echo ok >/etc/sentry-stub/mode; rm -f /tmp/sentry-firmware* /tmp/sentry-flash.log /tmp/sysupgrade.meta; apk --no-network info -e partx-utils >/dev/null 2>&1 || apk add -q partx-utils >/dev/null 2>&1; /etc/init.d/dropbear start >/dev/null 2>&1; true'
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
    live_guard_reverts | live_guard_wifi_asks) window=8 ;;
  esac
  rm -rf "$x"
  # live_setup: a first run. No config file at all: the setup flow writes them.
  if [[ $t == live_setup ]]; then
    mkdir -p "$x/config" "$x/data" "$x/cache"
    return
  fi
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
  # The firmware upgrade starts with a backup: to a throwaway key the test makes there.
  if [[ $t == live_firmware_upgrade ]]; then
    echo "    backup: { recipients: [\"$x/recipients.txt\"] }" >>"$x/config/sentry/network_config.yaml"
  fi
}

env_of() {
  local dir=$1 t=$2 x="$1/xdg/$2"
  printf 'SENTRY_SSH_CONFIG=%q SENTRY_ROUTER_SCRATCH=%q XDG_CONFIG_HOME=%q XDG_DATA_HOME=%q XDG_CACHE_HOME=%q' \
    "$dir/ssh_config" "$NET" "$x/config" "$x/data" "$x/cache"
  # live_setup: the host the setup flow is to find and add, and what it is.
  [[ $t != live_setup ]] || printf ' SENTRY_SETUP_HOST=%q SENTRY_SETUP_KIND=network' "$ALIAS"
}

# The crate a test is in: the window's own are the binary's.
pkg_of() {
  case "$1" in
    live_setup) echo sentry ;;
    *) echo sentry-network ;;
  esac
}

up() {
  local c dir port i
  [[ -z "$(ctr)" ]] || die "a router is already up ($(ctr)): \`$0 down\` first"
  dir=$(mktemp -d "${TMPDIR:-/tmp}/sentry-router.XXXXXXXX")
  touch "$dir/.sentry-router"
  mkdir -p "$dir/boot"
  cat /proc/sys/kernel/random/uuid >"$dir/boot/boot_id"
  c="sentry-router-${dir##*.}"
  # SENTRY_LIVE_NET: a podman network to join (scripts/live-resolution.sh: it must reach
  # the server container beside it).
  "${P[@]}" run -d --name "$c" --label "$LABEL=1" --label "$LABEL.dir=$dir" \
    ${SENTRY_LIVE_NET:+--network "$SENTRY_LIVE_NET"} \
    -v "$dir/boot:/run/sentry-boot:z" \
    --mount "type=bind,src=$dir/boot/boot_id,dst=/proc/sys/kernel/random/boot_id,relabel=shared" \
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
  stubs "$c"
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
      "SENTRY_SETUP_HOST=$ALIAS" SENTRY_SETUP_KIND=network \
      "XDG_CONFIG_HOME=$dir/xdg/$t/config" "XDG_DATA_HOME=$dir/xdg/$t/data" \
      "XDG_CACHE_HOME=$dir/xdg/$t/cache" \
      cargo test -q -p "$(pkg_of "$t")" "$t" -- --ignored --nocapture --test-threads=1 </dev/null || rc=$?
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

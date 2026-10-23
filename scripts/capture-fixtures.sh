#!/usr/bin/env bash
# Capture real command output into tests/fixtures/, scrubbed.
# Re-runnable. Works on the host or inside a toolbox (uses flatpak-spawn --host).
set -euo pipefail
cd "$(dirname "$0")/.."
F=tests/fixtures
H=()
[[ -f /run/.containerenv ]] && H=(flatpak-spawn --host)
R=/; [[ -f /run/.containerenv ]] && R=/run/host/
USER_NAME=$(id -un)

scrub() {
  # username -> user; every IPv4 except loopback/wildcard/multicast -> stable TEST-NET address;
  # IPv6 -> documentation/link-local placeholders; VPN interface names -> tun0.
  # Review container, unit and repo names by hand: project names can leak through them.
  python3 -I -c '
import re,sys
user=sys.argv[1]; seen={}
def ip(m):
    a=m.group(0); o=a.split(".")
    if any(int(x)>255 for x in o): return a
    if o[0] in ("127","0") or 224<=int(o[0])<=239 or a.startswith("255."): return a
    if a not in seen:
        n=len(seen)+1
        seen[a]=("192.0.2.%d" if int(o[0]) in (10,192,172) else "198.51.100.%d")%n
    return seen[a]
six={}
def ip6(m):
    # Link-local, ULA and global IPv6 identify the machine or its VPN: map to 2001:db8::/32
    # (fe80:: stays link-local). Loopback, wildcard and multicast stay as they are.
    a=m.group(0); low=a.lower()
    if low in ("::","::1") or low.startswith("ff") or ":" not in a.strip(":"): return a
    if a not in six:
        n=len(six)+1
        six[a]=("fe80::%x" if low.startswith("fe80") else "2001:db8::%x")%n
    return six[a]
t=sys.stdin.read().replace(user,"user")
if sys.argv[2]!="ip": sys.stdout.write(t); sys.exit()
t=re.sub(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",ip,t)
t=re.sub(r"(?<=\[)[0-9a-fA-F:]+(?=[]%])",ip6,t)
# Interface names other than lo/enp*/eth*/wl* (VPN tunnels name their server): -> tun0
t=re.sub(r"%(?!lo\b|enp|eth|wl)[A-Za-z0-9_.-]+",r"%tun0",t)
sys.stdout.write(t)
' "$USER_NAME" "${1:-}"
}
cap() { local out=$1; shift; mkdir -p "$(dirname "$F/$out")"; local mode=""; [[ $out == net/* ]] && mode=ip; "$@" 2>/dev/null | scrub $mode > "$F/$out" || true; }
host() { "${H[@]}" "$@"; }

cap ostree/status.json        host rpm-ostree status --json
cap ostree/kargs.txt          host rpm-ostree kargs
cap podman/ps.json            host podman ps -a --format json
cap podman/images.json        host podman image ls --format json
cap podman/dangling.json      host podman image ls --filter dangling=true --format json
cap podman/volumes.json       host podman volume ls --format json
cap flatpak/list.tsv          host flatpak list --app --columns=application,origin,version,installation
cap flatpak/runtimes.tsv      host flatpak list --runtime --columns=application,version,branch
cap flatpak/remotes.tsv       host flatpak remotes --columns=name,url,options
cap net/ss-listen.txt         host ss -tulpnH
cap net/ss-established.txt    host ss -tpH state established
cap units/user-enabled.txt    host systemctl --user list-unit-files --state=enabled --no-legend --plain
cap units/system-enabled.txt  host systemctl list-unit-files --state=enabled --no-legend --plain
cap units/failed.txt          host systemctl --failed --no-legend --plain
cap disk/findmnt.json         host findmnt -J -b --real -o TARGET,SOURCE,FSTYPE,SIZE,USED
cap gpu/nvidia-smi.csv        host nvidia-smi --query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,driver_version --format=csv,noheader,nounits

# flatpak keyfiles: first two system apps + any user overrides
mkdir -p $F/flatpak/metadata $F/flatpak/overrides
for id in $(host flatpak list --app --columns=application | head -2) com.valvesoftware.Steam; do
  m=/var/lib/flatpak/app/$id/current/active/metadata
  [[ -f $m ]] && scrub < "$m" > "$F/flatpak/metadata/$id"
done
for o in "$HOME"/.local/share/flatpak/overrides/*; do [[ -f $o ]] && scrub < "$o" > "$F/flatpak/overrides/$(basename "$o")"; done

mkdir -p $F/repos
for r in "${R}"etc/yum.repos.d/*.repo; do scrub < "$r" > "$F/repos/$(basename "$r")"; done
echo "fixtures captured into $F"

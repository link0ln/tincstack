#!/usr/bin/env bash
# dpi-proof capture — runs INSIDE the privileged lab container (tincstack/natlab).
# Two tinc nodes in two network namespaces over one veth pair; the wire between
# them is captured with tcpdump and handed to dpi-fingerprint, which reports the
# byte patterns that identify a tinc session today. Each obfuscation tier (M5)
# is a profile: extra tinc.conf lines in /opt/dpi-profiles/<profile>.conf that
# both nodes get. `plain` is the empty profile (stock tinc wire image).
#
#   dpi-capture <profile> [--out DIR] [--image core|baseline] [--seconds N]
#
# Output: DIR/<profile>.pcap, DIR/<profile>.fingerprint.json, DIR/<profile>.report.txt,
#         DIR/<profile>.{dpia,dpib}.log, exit 0 when the tunnel came up and the
#         capture was analysed (the *verdict* about fingerprints is dpi-compare's job).
set -euo pipefail

PROFILE="${1:-}"; [ -n "$PROFILE" ] || { sed -n '2,15p' "$0"; exit 2; }; shift
OUT=/out; IMG=core; SECONDS_CAP=20
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --image) IMG="$2"; shift 2 ;;
        --seconds) SECONDS_CAP="$2"; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done
PROFDIR="${DPI_PROFILES:-/opt/dpi-profiles}"
PROF="$PROFDIR/$PROFILE.conf"
[ -r "$PROF" ] || { echo "dpi-capture: no profile $PROF" >&2; exit 2; }
case "$IMG" in
    core) TINCD=/usr/local/sbin/tincd; TINC=/usr/local/sbin/tinc ;;
    baseline) TINCD=/opt/baseline/sbin/tincd; TINC=/opt/baseline/sbin/tinc ;;
    *) echo "bad --image" >&2; exit 2 ;;
esac
KEYGEN=/usr/local/sbin/tinc
LAB=/lab/dpi; A_IP=192.168.99.1; B_IP=192.168.99.2; VPN_A=10.78.0.1; VPN_B=10.78.0.2; PORT=655
mkdir -p "$OUT" "$LAB"
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

cleanup() {
    pkill -x tincd 2>/dev/null || true
    pkill -x tcpdump 2>/dev/null || true
    sleep 0.3
    ip netns del dpiA 2>/dev/null || true
    ip netns del dpiB 2>/dev/null || true
    rm -rf "$LAB"
}
cleanup; mkdir -p "$LAB"
trap cleanup EXIT

write_node() { # name vpn extra...
    local name="$1" vpn="$2"; shift 2
    local d="$LAB/$name"; mkdir -p "$d/hosts"
    { echo "Name = $name"; echo "Mode = router"; echo "Port = $PORT"; echo "AddressFamily = ipv4"
      for l in "$@"; do echo "$l"; done
      cat "$PROF"; } > "$d/tinc.conf"
    printf 'Subnet = %s/32\n' "$vpn" > "$d/hosts/$name"
    [ "$name" = dpia ] && printf 'Address = %s\nPort = %s\n' "$A_IP" "$PORT" >> "$d/hosts/$name"
    # shellcheck disable=SC2016  # $INTERFACE is expanded by tincd, not here
    printf '#!/bin/sh\nip link set "$INTERFACE" up\nip addr add %s/24 dev "$INTERFACE"\n' "$vpn" > "$d/tinc-up"
    chmod +x "$d/tinc-up"
    "$KEYGEN" -c "$d" generate-keys >/dev/null 2>&1
}
write_node dpia "$VPN_A"
write_node dpib "$VPN_B" "ConnectTo = dpia"
cp "$LAB/dpia/hosts/dpia" "$LAB/dpib/hosts/"; cp "$LAB/dpib/hosts/dpib" "$LAB/dpia/hosts/"

ip netns add dpiA; ip netns add dpiB
ip link add veth-a type veth peer name veth-b
ip link set veth-a netns dpiA; ip link set veth-b netns dpiB
ip netns exec dpiA sh -c "ip addr add $A_IP/24 dev veth-a; ip link set veth-a up; ip link set lo up"
ip netns exec dpiB sh -c "ip addr add $B_IP/24 dev veth-b; ip link set veth-b up; ip link set lo up"

PCAP="$OUT/$PROFILE.pcap"
ip netns exec dpiB tcpdump -i veth-b -n -U -w "$PCAP" "not arp" > "$OUT/$PROFILE.tcpdump.log" 2>&1 &
TCPD=$!
sleep 1
ip netns exec dpiA "$TINCD" -D -d5 -c "$LAB/dpia" --pidfile "$LAB/dpia.pid" > "$OUT/$PROFILE.dpia.log" 2>&1 &
sleep 0.5
ip netns exec dpiB "$TINCD" -D -d5 -c "$LAB/dpib" --pidfile "$LAB/dpib.pid" > "$OUT/$PROFILE.dpib.log" 2>&1 &

up=0
for _ in $(seq 1 30); do
    r="$("$TINC" -c "$LAB/dpib" --pidfile "$LAB/dpib.pid" info dpia 2>/dev/null | awk -F': *' '/^Reachability:/{print $2}' || true)"
    [ "$r" = "directly with UDP" ] && { up=1; break; }
    ip netns exec dpiB ping -c 1 -W 1 "$VPN_A" >/dev/null 2>&1 || true
    sleep 1
done
[ "$up" -eq 1 ] || log "warning: direct UDP not reported within 30 s (capture continues)"
ip netns exec dpiB ping -c "$SECONDS_CAP" -i 1 -s 200 "$VPN_A" > "$OUT/$PROFILE.ping.txt" 2>&1 || true
"$TINC" -c "$LAB/dpib" --pidfile "$LAB/dpib.pid" info dpia > "$OUT/$PROFILE.info.txt" 2>&1 || true
sleep 1
kill -INT "$TCPD" 2>/dev/null || true; wait "$TCPD" 2>/dev/null || true
pkill -x tincd 2>/dev/null || true

dpi-fingerprint "$PCAP" --port "$PORT" --json "$OUT/$PROFILE.fingerprint.json" > "$OUT/$PROFILE.report.txt"
cat "$OUT/$PROFILE.report.txt"
[ "$up" -eq 1 ]

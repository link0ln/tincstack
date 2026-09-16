#!/bin/sh
# obfs-mtu-test.sh -- prove the obfuscated-UDP carrier works on a path whose
# MTU is smaller than the 1500-byte docker bridge every other lab runs on
# (stream AB).
#
# WHY THIS EXISTS
#   obfs adds a seal (magic 0/4 + nonce 8 + clen 2 + Poly1305 tag 16) and up to
#   ObfsInit/TransportHeaderJunkSize bytes of tail padding on TOP of a frame
#   tinc has already sized to the path. tinc sets IP_MTU_DISCOVER, so a
#   datagram over the path MTU is not fragmented: the kernel refuses it with
#   EMSGSIZE ("Message too long"). Before the fix, the junk was clamped only
#   against the constant OBFS_MAX_JUNK and the SPTPS datagram size was tinc's
#   idea of the path, which knows nothing about the seal, so:
#     * every handshake frame could be unsendable -> the SF SYN and its three
#       retries all failed -> the dial "hung" for ~3.5 s and fell back to plain;
#     * every full-size data datagram was 26-30 bytes over the path and the
#       EMSGSIZE was swallowed, so tinc's PMTU discovery never converged.
#   Both were measured between two real hosts over the internet on 2026-09-16
#   and neither was visible on a 1500-byte docker bridge, which is exactly why
#   this test puts the pair on a REDUCED-MTU docker network instead.
#
# PART 1  MTU 1400, with the shaping options that used to make every handshake
#         frame unsendable (init header junk at the OBFS_MAX_JUNK ceiling, a
#         transport header junk, both magic headers):
#           * the link comes up ON THE OBFS CARRIER (no fallback to plain);
#           * ping is clean both ways;
#           * no EMSGSIZE is logged by either node;
#           * NO datagram on the wire exceeds the path MTU;
#           * junk is still emitted -- the fix makes junk FIT, it does not
#             remove it.
# PART 2  MTU 1280 (the IPv6 minimum link MTU, the smallest a path may be)
#         with default shaping: the link still comes up and pings clean.
# PART 3  the same pair on a normal 1500-MTU network: tinc's PMTU discovery
#         converges to a value that accounts for the seal, and no EMSGSIZE is
#         logged. This is the case that was silently broken everywhere, 1500
#         included, so it is asserted on the standard MTU too.
#
# No fixed sleeps for readiness: every phase polls with a deadline, like
# obfs-test.sh, so a loaded host only makes the test slower, not red.
#
# tcpdump runs in a throwaway container attached to a node's netns, so nothing
# is installed on the host.
#
# Usage: [LAB=prefix] [SUBNET=10.37.92] testing/transports/obfs-mtu-test.sh [image]
#   LAB (default wsab) prefixes every container name, the docker network
#   (<LAB>mtu) and the /tmp data directories; a non-default LAB also gets its
#   own /24 (see lab-env.sh), so two runs can share a host.
#   The image is the first argument, else tincstack/core:$TINCSTACK_TAG.
set -e

IMG=${1:-tincstack/core:${TINCSTACK_TAG:-dev}}
TCPDUMP_IMG=nicolaka/netshoot
DEFAULT_LAB=wsab; DEFAULT_SUBNET=10.37.92
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"
NET=${LAB}mtu
BASE=/tmp/$LAB-mtu
WAIT=120

A_IP=$SUBNET.10
B_IP=$SUBNET.12
A_VPN=10.184.0.1
B_VPN=10.184.0.3

fail=0
cleanup() {
	docker rm -f "$LAB-a" "$LAB-b" "$LAB-cap" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
# shellcheck disable=SC2329  # invoked from the EXIT trap below
cleanup_exit() { cleanup; rm -rf "$BASE"-a "$BASE"-b; }
trap cleanup_exit EXIT
cleanup

# --- helpers ----------------------------------------------------------------

# $1 dir  $2 name  $3 extra option lines (already indented 6 spaces)
gen() {
	{
		echo "networks:"
		echo "  wsab:"
		echo "    options:"
		echo "      Name: $2"
		echo "      Mode: router"
		echo "      Port: 655"
		echo "      AddressPool: 10.184.0.0/24"
		printf '%s\n' "$3"
	} > "$1/tinc.yaml"
}

materialise() {
	for d in "$@"; do
		timeout 5 docker run --rm -v "$BASE-$d":/etc/tincstack "$IMG" \
			tincd -c /etc/tincstack/tinc.yaml -n wsab -D -d1 >/dev/null 2>&1 || true
	done
}

crossinject() {
	python3 - "$BASE" "$A_IP" "$B_IP" "$A_VPN" "$B_VPN" <<'PYEOF'
import re, sys
base, aip, bip, avpn, bvpn = sys.argv[1:6]
names = {'a': 'nodea', 'b': 'nodeb'}
vpn = {'a': avpn, 'b': bvpn}
ip = {'a': aip, 'b': bip}
paths = {k: '%s-%s/tinc.yaml' % (base, k) for k in names}

def block(path, name):
    s = open(path).read()
    m = re.search(r'^      %s: \|\n((?:(?:        .*)?\n)+)' % re.escape(name), s, re.M)
    lines = [l[8:] for l in m.group(1).split('\n') if l.startswith('        ')]
    return [l for l in lines if l.strip()]

blocks = {k: [re.sub(r'Subnet = .*', 'Subnet = %s/32' % vpn[k], l) for l in block(paths[k], names[k])]
          for k in names}

for k in names:
    s = open(paths[k]).read()
    s = re.sub(r'(%s: \|\n(?:        .*\n)*?        Subnet = )[^\n]*' % names[k],
               lambda m: m.group(1) + '%s/32' % vpn[k], s)
    open(paths[k], 'w').write(s)

def inject(path, name, extra):
    s = open(path).read()
    if '      %s: |' % name in s:
        return
    s = s.replace('    hosts:\n',
                  '    hosts:\n      %s: |\n' % name + ''.join('        ' + l + '\n' for l in extra), 1)
    open(path, 'w').write(s)

for k in names:
    for j in names:
        if j == k:
            continue
        rec = ['Address = ' + ip[j], 'Port = 655'] + [l for l in blocks[j] if not l.startswith(('Address', 'Port'))]
        inject(paths[k], names[j], rec)
print("configs merged")
PYEOF
}

start() { # letter ip dir
	docker run -d --name "$LAB-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN \
		--device /dev/net/tun -v "$3":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n wsab -D -d5 >/dev/null
}
setvpn() { # letter vpnip (idempotent: the device may not exist right after start)
	docker exec "$LAB-$1" ip addr add "$2/24" dev wsab >/dev/null 2>&1 || true
	docker exec "$LAB-$1" ip link set wsab up >/dev/null 2>&1 || true
}
logs() { docker logs "$LAB-$1" 2>&1; }
activated() { logs "$1" | grep -c ' activated' >/dev/null; }
# NB: never `producer | grep -q` under `set -e` -- grep leaves on the first
# match, the producer takes SIGPIPE and the pipeline fails although the pattern
# WAS found. `grep -c ... >/dev/null` reads to the end and cannot do that.
has() { logs "$1" | grep -c "$2" >/dev/null; }
count() { logs "$1" | grep -c "$2" || true; }

# Times the KERNEL refused a datagram (EMSGSIZE). obfs's own "would not fit the
# path ... reducing the packet size" line is deliberately NOT counted: that one
# is the designed feedback into tinc's PMTU discovery (it is what replaces the
# swallowed EMSGSIZE), and it fires while discovery converges. A kernel refusal
# means a datagram obfs believed would fit did not, which is the defect.
emsgsize() { n=0; for l in "$@"; do n=$(( n + $(count "$l" 'Message too long') + $(count "$l" 'refused a') )); done; echo "$n"; }
junk_events() { n=0; for l in "$@"; do n=$(( n + $(count "$l" 'obfs junk datagram') )); done; echo "$n"; }
# Value tinc fixed its PMTU to, as logged by try_fix_mtu() (DEBUG_TRAFFIC, -d5).
fixed_mtu() { logs "$1" | sed -n 's/.*Fixing MTU of [^ ]* ([^)]*) to \([0-9]*\) .*/\1/p' | tail -1; }

wait_link() {
	deadline=$(( $(date +%s) + WAIT ))
	while :; do
		setvpn a "$A_VPN"; setvpn b "$B_VPN"
		if activated a && activated b \
		   && docker exec "$LAB-a" ping -c1 -W1 "$B_VPN" >/dev/null 2>&1 \
		   && docker exec "$LAB-b" ping -c1 -W1 "$A_VPN" >/dev/null 2>&1; then
			return 0
		fi
		if [ "$(date +%s)" -ge "$deadline" ]; then
			echo "TIMEOUT: link a<->b not ready within ${WAIT}s; logs follow"
			logs a | tail -20; logs b | tail -20
			return 1
		fi
		sleep 1
	done
}
# Poll a FULL ping run until it reports 0% loss. Echoes the ping tail; the
# RETURN CODE is the result, so read it via `if out=$(wait_clean ...); then`.
wait_clean() { # from to-vpn [count]
	deadline=$(( $(date +%s) + WAIT ))
	cnt=${3:-8}
	while :; do
		out=$(docker exec "$LAB-$1" ping -c"$cnt" -W2 "$2" 2>&1 | tail -2)
		if echo "$out" | grep -c " 0% packet loss" >/dev/null; then echo "$out"; return 0; fi
		if [ "$(date +%s)" -ge "$deadline" ]; then echo "$out"; return 1; fi
		sleep 2
	done
}
loss() { echo "$1" | grep -oE '[0-9]+(\.[0-9]+)?% packet loss' || echo '?'; }
# Wait until tinc has fixed a PMTU for the peer, so PART 1/3 assert a converged
# value instead of racing discovery.
wait_mtu() { # letter
	deadline=$(( $(date +%s) + WAIT ))
	while :; do
		[ -n "$(fixed_mtu "$1")" ] && return 0
		[ "$(date +%s)" -ge "$deadline" ] && return 1
		sleep 2
	done
}

capture_start() { # letter
	docker rm -f "$LAB-cap" >/dev/null 2>&1 || true
	docker run -d --name "$LAB-cap" --net "container:$LAB-$1" --cap-add NET_RAW "$TCPDUMP_IMG" \
		tcpdump -n -i eth0 'udp port 655' >/dev/null 2>&1
	sleep 2
}
capture_stop() {
	docker stop "$LAB-cap" >/dev/null 2>&1 || true
	docker logs "$LAB-cap" 2>&1
	docker rm -f "$LAB-cap" >/dev/null 2>&1 || true
}
# Largest UDP payload seen in a capture. Only packet lines carry "UDP, length
# N"; tcpdump's own banner also contains the word "length" ("snapshot length
# 262144 bytes"), which a bare 'length [0-9]+' match would report as the largest
# datagram on the wire.
max_len() { echo "$1" | grep -oE 'UDP, length [0-9]+' | awk '{if($3>n)n=$3} END{print n+0}'; }

# Bring the pair up on a network of the given MTU with the given extra options.
# $1 mtu  $2 extra option lines
lab_up() {
	cleanup
	docker network create --subnet "$SUBNET.0/24" \
		--opt com.docker.network.driver.mtu="$1" "$NET" >/dev/null
	rm -rf "$BASE"-a "$BASE"-b; mkdir -p "$BASE"-a "$BASE"-b
	gen "$BASE-b" nodeb "$2"
	gen "$BASE-a" nodea "$2
      ConnectTo: [nodeb]"
	materialise b a
	crossinject >/dev/null
	start b "$B_IP" "$BASE-b"; start a "$A_IP" "$BASE-a"
}

############ PART 1: small-MTU path with the worst-case shaping ##############
PATHMTU=1400
SHAPED="      ObfsJunkPacketCount: 6
      ObfsJunkPacketMinSize: 1200
      ObfsJunkPacketMaxSize: 1400
      ObfsInitHeaderJunkSize: 1400
      ObfsTransportHeaderJunkSize: 36
      ObfsInitMagicHeader: 305419896
      ObfsTransportMagicHeader: 878082192
      PreferredTransports: [obfs, plain]"

echo "===== PART 1: obfs on a ${PATHMTU}-byte path, junk at the OBFS_MAX_JUNK ceiling ====="
lab_up "$PATHMTU" "$SHAPED"
capture_start b
if ! wait_link; then fail=1; fi
if p1ab=$(wait_clean a "$B_VPN"); then p1ab_ok=1; else p1ab_ok=0; fi
if p1ba=$(wait_clean b "$A_VPN"); then p1ba_ok=1; else p1ba_ok=0; fi
wait_mtu a || true
cap1=$(capture_stop)

p1_emsg=$(emsgsize a b)
p1_junk=$(junk_events a b)
p1_max=$(max_len "$cap1")
p1_mtu=$(fixed_mtu a)
p1_budget=$(( PATHMTU - 28 ))

echo "  path MTU $PATHMTU -> usable UDP payload $p1_budget bytes"
echo "  A->B: $(loss "$p1ab") ; B->A: $(loss "$p1ba")"
echo "  carrier: $(logs b | grep -oE 'Connection from .* \(obfuscated single-flow UDP\)' | head -1)"
echo "  EMSGSIZE lines on either node: $p1_emsg ; junk events: $p1_junk"
echo "  largest UDP payload on the wire: $p1_max bytes (budget $p1_budget)"
echo "  tinc PMTU fixed to: ${p1_mtu:-<not converged>}"

[ "$p1ab_ok" = 1 ] || { echo "MISS: A->B never went clean on a ${PATHMTU}-byte path"; fail=1; }
[ "$p1ba_ok" = 1 ] || { echo "MISS: B->A never went clean on a ${PATHMTU}-byte path"; fail=1; }
# The ACCEPTOR's line, not the dialler's: "Dialling ... via obfuscated
# single-flow UDP" is logged even for a dial that then fails over to plain.
has b 'Connection from .*obfuscated single-flow UDP' || { echo "MISS: the link did not come up on the obfs carrier"; fail=1; }
[ "$(count a 'Carrier obfs failed')" = 0 ] || { echo "MISS: the obfs carrier failed and fell back (the defect)"; fail=1; }
[ "$p1_emsg" = 0 ] || { echo "MISS: $p1_emsg EMSGSIZE/oversize lines -- obfs still emits datagrams the path refuses"; fail=1; }
[ "$p1_junk" -gt 0 ] || { echo "MISS: no junk emitted -- the fix must make junk FIT, not remove it"; fail=1; }
[ "$p1_max" -gt 0 ] || { echo "MISS: captured no UDP traffic (test setup)"; fail=1; }
[ "$p1_max" -le "$p1_budget" ] || { echo "MISS: a $p1_max-byte datagram went out on a $p1_budget-byte path"; fail=1; }
[ -n "$p1_mtu" ] || { echo "MISS: tinc's PMTU discovery never converged on the obfs link"; fail=1; }

############ PART 2: the smallest MTU a path may have ########################
echo "===== PART 2: obfs on a 1280-byte path (the IPv6 minimum link MTU) ====="
DEFAULTS="      ObfsJunkPacketCount: 4
      PreferredTransports: [obfs, plain]"
lab_up 1280 "$DEFAULTS"
if ! wait_link; then fail=1; fi
if p2ab=$(wait_clean a "$B_VPN"); then p2ab_ok=1; else p2ab_ok=0; fi
if p2ba=$(wait_clean b "$A_VPN"); then p2ba_ok=1; else p2ba_ok=0; fi
p2_emsg=$(emsgsize a b)
echo "  A->B: $(loss "$p2ab") ; B->A: $(loss "$p2ba") ; EMSGSIZE lines: $p2_emsg"
[ "$p2ab_ok" = 1 ] || { echo "MISS: A->B never went clean on a 1280-byte path"; fail=1; }
[ "$p2ba_ok" = 1 ] || { echo "MISS: B->A never went clean on a 1280-byte path"; fail=1; }
has b 'Connection from .*obfuscated single-flow UDP' || { echo "MISS: the 1280-byte link did not come up on the obfs carrier"; fail=1; }
[ "$p2_emsg" = 0 ] || { echo "MISS: $p2_emsg EMSGSIZE lines on a 1280-byte path"; fail=1; }

############ PART 3: the standard 1500-byte lab was broken too ###############
# tinc sizes an SPTPS datagram to exactly the path MTU (choose_initial_maxmtu()
# subtracts IP/UDP/SPTPS and knows nothing about a carrier), so the seal put
# every full-size data datagram 26 bytes over -- on EVERY path, 1500 included.
# The EMSGSIZE was swallowed, so PMTU discovery lost every top-end probe.
echo "===== PART 3: the data path on a normal 1500-byte network ====="
lab_up 1500 "$DEFAULTS"
if ! wait_link; then fail=1; fi
if p3ab=$(wait_clean a "$B_VPN"); then p3ab_ok=1; else p3ab_ok=0; fi
wait_mtu a || true
p3_emsg=$(emsgsize a b)
p3_mtu=$(fixed_mtu a)
echo "  A->B: $(loss "$p3ab") ; EMSGSIZE lines: $p3_emsg ; tinc PMTU fixed to: ${p3_mtu:-<not converged>}"
[ "$p3ab_ok" = 1 ] || { echo "MISS: A->B never went clean on a 1500-byte path"; fail=1; }
[ "$p3_emsg" = 0 ] || { echo "MISS: $p3_emsg EMSGSIZE lines on the standard 1500-byte lab"; fail=1; }
[ -n "$p3_mtu" ] || { echo "MISS: PMTU discovery did not converge on the 1500-byte lab"; fail=1; }
# The seal costs bytes, so the converged tinc MTU must be BELOW the value a
# plain link would reach (1500 - IP 20 - UDP 8 - SPTPS 21 - relay ids 8 = 1443).
[ -n "$p3_mtu" ] && [ "$p3_mtu" -lt 1443 ] || { echo "MISS: PMTU ${p3_mtu:-?} does not account for the obfs seal"; fail=1; }

echo "==========================================================="
if [ "$fail" = 0 ]; then
	echo "PASS: obfs brings a tunnel up and carries traffic on 1400- and 1280-byte"
	echo "      paths with junk at the ceiling, emits nothing the path refuses,"
	echo "      keeps its junk, and converges tinc's PMTU with the seal accounted for"
	exit 0
else
	echo "FAIL"
	exit 1
fi

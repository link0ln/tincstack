#!/bin/sh
# obfs-test.sh -- prove the obfuscated-UDP carrier (M5, stream G2).
#
# PART 1  two nodes, dialer prefers obfs:
#   * the tunnel comes up FROM COLD and ping works both ways;
#   * the SPTPS/single-flow fingerprint is GONE from the wire -- the SF magic
#     9f747366...  is visible in a SingleFlow (sf) capture but ABSENT in the obfs
#     capture (it is sealed);
#   * junk is emitted around the handshake and NOT during a steady ping flood.
#     Junk is counted by the SENDER'S OWN MARKER: every obfs_send_junk() call
#     logs "Sent N obfs junk datagram(s) around a handshake" (obfs.c, visible at
#     -d2). Junk datagrams are random bytes by design, so they cannot be told
#     apart on the wire from other variable-size datagrams -- in particular
#     tinc's PMTU probes, which land in any size window and made an earlier
#     size-window count flaky. The wire size-window count is still printed
#     for the handshake window, as information only.
# PART 2  three nodes A - R - B, A<->B direct blocked with iptables DROP:
#   * traffic still flows, relayed through R, each hop independently sealed
#     (no double-prefix corruption).
# PART 3  defaults (obfs compiled but NOT selected, ObfsJunkPacketCount 0):
#   * the tunnel works and the wire is plain SPTPS -- no obfs seal, no SF magic.
#
# No fixed sleeps: every phase polls for readiness (both daemons logged
# "activated" and a ping succeeds) with a 60 s deadline, like
# platforms/linux/docker/two-nodes.sh wait_ready, so a loaded host only makes
# the test slower, not red.
#
# tcpdump runs in a throwaway container attached to a node's netns, so nothing
# is installed on the host. Image: tincstack/core:ws-g2.
#
# Usage: testing/transports/obfs-test.sh [image]
set -e

IMG=${1:-tincstack/core:ws-g2}
TCPDUMP_IMG=nicolaka/netshoot
NET=wsg2obfs
BASE=/tmp/wsg2-obfs
PFX=wsg2o
WAIT=60

A_IP=10.37.9.10
R_IP=10.37.9.11
B_IP=10.37.9.12
A_VPN=10.182.0.1
R_VPN=10.182.0.2
B_VPN=10.182.0.3

# junk size window used for the informational wire count only
JMIN=600
JMAX=650
JCOUNT=8

fail=0
cleanup() {
	docker rm -f ${PFX}-a ${PFX}-r ${PFX}-b ${PFX}-cap >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --subnet 10.37.9.0/24 "$NET" >/dev/null

rm -rf "$BASE"-a "$BASE"-r "$BASE"-b
mkdir -p "$BASE"-a "$BASE"-r "$BASE"-b

# --- config generator -------------------------------------------------------
# $1 dir  $2 name  $3 extra option lines (already indented 6 spaces)
gen() {
	dir=$1
	name=$2
	extra=$3
	{
		echo "networks:"
		echo "  wsg2:"
		echo "    options:"
		echo "      Name: $name"
		echo "      Mode: router"
		echo "      Port: 655"
		echo "      AddressPool: 10.182.0.0/24"
		printf '%s\n' "$extra"
	} > "$dir/tinc.yaml"
}

materialise() {
	for d in "$@"; do
		timeout 3 docker run --rm -v "$BASE-$d":/etc/tincstack "$IMG" \
			tincd -c /etc/tincstack/tinc.yaml -n wsg2 -D -d1 >/dev/null 2>&1 || true
	done
}

# cross-inject host records so every node knows every other node's key, VPN
# subnet and dial Address. args: list of node letters present.
crossinject() {
	python3 - "$BASE" "$A_IP" "$R_IP" "$B_IP" "$A_VPN" "$R_VPN" "$B_VPN" "$@" <<'PYEOF'
import re, sys
base, aip, rip, bip, avpn, rvpn, bvpn = sys.argv[1:8]
want = sys.argv[8:]  # node letters present
names = {'a': 'nodea', 'r': 'noder', 'b': 'nodeb'}
vpn = {'a': avpn, 'r': rvpn, 'b': bvpn}
ip = {'a': aip, 'r': rip, 'b': bip}
paths = {k: '%s-%s/tinc.yaml' % (base, k) for k in want}

def block(path, name):
    s = open(path).read()
    m = re.search(r'^      %s: \|\n((?:(?:        .*)?\n)+)' % re.escape(name), s, re.M)
    lines = [l[8:] for l in m.group(1).split('\n') if l.startswith('        ')]
    return [l for l in lines if l.strip()]

def setsubnet(lines, subnetip):
    return [re.sub(r'Subnet = .*', 'Subnet = %s/32' % subnetip, l) for l in lines]

blocks = {k: setsubnet(block(paths[k], names[k]), vpn[k]) for k in want}

# fix each node's own Subnet in its own file
for k in want:
    s = open(paths[k]).read()
    s = re.sub(r'(%s: \|\n(?:        .*\n)*?        Subnet = )[^\n]*' % names[k],
               lambda m: m.group(1) + '%s/32' % vpn[k], s)
    open(paths[k], 'w').write(s)

def indent(lines): return ''.join('        ' + l + '\n' for l in lines)

def inject(path, name, extra):
    s = open(path).read()
    if '      %s: |' % name in s:
        return
    s = s.replace('    hosts:\n', '    hosts:\n      %s: |\n' % name + indent(extra), 1)
    open(path, 'w').write(s)

# every node learns every other node, with that node's dial Address + Port.
for k in want:
    for j in want:
        if j == k:
            continue
        rec = ['Address = ' + ip[j], 'Port = 655'] + [l for l in blocks[j] if not l.startswith(('Address', 'Port'))]
        inject(paths[k], names[j], rec)
print("configs merged")
PYEOF
}

start() { # letter ip dir
	docker run -d --name "${PFX}-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN \
		--device /dev/net/tun -v "$3":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n wsg2 -D -d2 >/dev/null
}
setvpn() { # letter vpnip  (idempotent; the device may not exist yet right after start)
	docker exec "${PFX}-$1" ip addr add "$2/24" dev wsg2 >/dev/null 2>&1 || true
	docker exec "${PFX}-$1" ip link set wsg2 up >/dev/null 2>&1 || true
}
logs() { docker logs "${PFX}-$1" 2>&1; }
activated() { logs "$1" | grep -q ' activated'; }

# wait_link <from> <from-vpn> <to> <to-vpn>: both daemons logged "activated"
# and <from> pings <to> over the tunnel. Polls 1 s up to $WAIT s.
wait_link() {
	deadline=$(( $(date +%s) + WAIT ))
	while :; do
		setvpn "$1" "$2"; setvpn "$3" "$4"
		if activated "$1" && activated "$3" && docker exec "${PFX}-$1" ping -c1 -W1 "$4" >/dev/null 2>&1; then
			return 0
		fi
		if [ "$(date +%s)" -ge "$deadline" ]; then
			echo "TIMEOUT: link $1<->$3 not ready within ${WAIT}s; logs follow"
			logs "$1" | tail -15; logs "$3" | tail -15
			return 1
		fi
		sleep 1
	done
}
# wait_ping <from> <to-vpn>: one ping succeeds within $WAIT s
wait_ping() {
	deadline=$(( $(date +%s) + WAIT ))
	until docker exec "${PFX}-$1" ping -c1 -W1 "$2" >/dev/null 2>&1; do
		[ "$(date +%s)" -ge "$deadline" ] && return 1
		sleep 1
	done
}
loss() { echo "$1" | grep -oE '[0-9]+% packet loss' || echo '?'; }

capture_start() { # letter
	docker run -d --name ${PFX}-cap --net container:${PFX}-$1 --cap-add NET_RAW "$TCPDUMP_IMG" \
		tcpdump -n -xx -i eth0 'udp port 655' >/dev/null 2>&1
	sleep 1
}
capture_stop() {
	docker stop ${PFX}-cap >/dev/null 2>&1 || true
	docker logs ${PFX}-cap 2>&1
	docker rm -f ${PFX}-cap >/dev/null 2>&1 || true
}
hex_of() { echo "$1" | grep -oE '0x[0-9a-f]+:.*' | sed 's/0x[0-9a-f]*://' | tr -dc '0-9a-f'; }
count_len_between() { echo "$1" | grep -oE 'length [0-9]+' | awk -v lo="$2" -v hi="$3" '{if($2>=lo&&$2<=hi)n++} END{print n+0}'; }
sfmagic() { echo "$1" | grep -c '9f7473666c77' || true; }
# junk events by the sender's marker, summed over both nodes' logs
junk_events() { n=0; for l in "$@"; do n=$(( n + $(logs "$l" | grep -c 'obfs junk datagram' || true) )); done; echo "$n"; }

reset_lab() {
	cleanup
	docker network create --subnet 10.37.9.0/24 "$NET" >/dev/null 2>&1 || true
	rm -rf "$BASE"-a "$BASE"-r "$BASE"-b; mkdir -p "$BASE"-a "$BASE"-r "$BASE"-b
}

########################## PART 1: obfs two nodes ###########################
echo "===== PART 1: obfs, two nodes, cold-start + fingerprint + junk ====="

# Reference (BEFORE): SingleFlow only -> SF magic is visible on the wire.
gen "$BASE-b" nodeb "      SingleFlow: yes"
gen "$BASE-a" nodea "      SingleFlow: yes
      ConnectTo: [nodeb]"
materialise b a
crossinject a b
start b "$B_IP" "$BASE-b"; start a "$A_IP" "$BASE-a"
wait_link a "$A_VPN" b "$B_VPN" || fail=1
capture_start a
docker exec ${PFX}-a ping -c3 -W2 "$B_VPN" >/dev/null 2>&1 || true
sf_cap=$(capture_stop)
sf_magic=$(sfmagic "$(hex_of "$sf_cap")")
echo "BEFORE (sf):  SF magic 9f747366 occurrences on the wire = $sf_magic"

# AFTER: obfs preferred.
reset_lab
OBFS_OPTS="      ObfsJunkPacketCount: $JCOUNT
      ObfsJunkPacketMinSize: $JMIN
      ObfsJunkPacketMaxSize: $JMAX
      PreferredTransports: [obfs, plain]"
gen "$BASE-b" nodeb "$OBFS_OPTS"
gen "$BASE-a" nodea "$OBFS_OPTS
      ConnectTo: [nodeb]"
materialise b a
crossinject a b
start b "$B_IP" "$BASE-b"
# capture the cold handshake window: from before A's first dial until the link is up
capture_start b
start a "$A_IP" "$BASE-a"
wait_link a "$A_VPN" b "$B_VPN" || fail=1
hs_cap=$(capture_stop)
junk_hs=$(junk_events a b)

ab=$(docker exec ${PFX}-a ping -c3 -W2 "$B_VPN" 2>&1 | tail -2)
ba=$(docker exec ${PFX}-b ping -c3 -W2 "$A_VPN" 2>&1 | tail -2)

# steady-state flood: no new handshake, so the sender's junk counter must not move
junk_before=$(junk_events a b)
docker exec ${PFX}-a ping -c30 -i0.2 -W2 "$B_VPN" >/dev/null 2>&1 || true
junk_after=$(junk_events a b)
junk_steady=$(( junk_after - junk_before ))

obfs_magic=$(sfmagic "$(hex_of "$hs_cap")")
junk_hs_wire=$(count_len_between "$hs_cap" "$JMIN" "$JMAX")
echo "AFTER (obfs): SF magic 9f747366 occurrences on the wire = $obfs_magic"
echo "A->B: $(loss "$ab")"
echo "B->A: $(loss "$ba")"
echo "junk (sender marker 'Sent N obfs junk datagram(s)'): handshake events = $junk_hs ; new events during steady flood = $junk_steady"
echo "  (info) wire datagrams of $JMIN-$JMAX B in the handshake window = $junk_hs_wire"
echo "  dialer log: $(logs a | grep -oE 'Dialling .* via obfuscated single-flow UDP|Connection with nodeb .* activated' | head -2 | tr '\n' ';')"
echo "  acceptor log: $(logs b | grep -oE 'Cold-classified an obfs datagram[^;]*|Connection from .* \(obfuscated single-flow UDP\)' | head -2 | tr '\n' ';')"

echo "$ab" | grep -q " 0% packet loss" || { echo "MISS: cold obfs A->B ping failed"; fail=1; }
echo "$ba" | grep -q " 0% packet loss" || { echo "MISS: cold obfs B->A ping failed"; fail=1; }
[ "$sf_magic" -gt 0 ] || { echo "MISS: SF magic not seen in the sf reference capture (test setup)"; fail=1; }
[ "$obfs_magic" = 0 ] || { echo "MISS: SF/SPTPS fingerprint (SF magic) still visible under obfs"; fail=1; }
[ "$junk_hs" -gt 0 ] || { echo "MISS: no junk emitted around the handshake"; fail=1; }
[ "$junk_steady" = 0 ] || { echo "MISS: junk emitted during steady state (should be per-handshake only)"; fail=1; }

########################## PART 2: obfs relay ###############################
echo "===== PART 2: obfs A - R - B relay, A<->B direct blocked ====="
reset_lab
RELAY_OPTS="      ObfsJunkPacketCount: 4
      PreferredTransports: [obfs, plain]"
gen "$BASE-r" noder "$RELAY_OPTS"
gen "$BASE-a" nodea "$RELAY_OPTS
      ConnectTo: [noder]"
gen "$BASE-b" nodeb "$RELAY_OPTS
      ConnectTo: [noder]"
materialise r a b
crossinject a r b
start r "$R_IP" "$BASE-r"; start a "$A_IP" "$BASE-a"; start b "$B_IP" "$BASE-b"
wait_link a "$A_VPN" r "$R_VPN" || fail=1
wait_link b "$B_VPN" r "$R_VPN" || fail=1
# Sever direct A<->B reachability so traffic must go through R.
docker exec ${PFX}-a iptables -A INPUT  -s "$B_IP" -j DROP
docker exec ${PFX}-a iptables -A OUTPUT -d "$B_IP" -j DROP
docker exec ${PFX}-b iptables -A INPUT  -s "$A_IP" -j DROP
docker exec ${PFX}-b iptables -A OUTPUT -d "$A_IP" -j DROP
# The first packets trigger the relayed SPTPS key exchange through R; poll
# until one ping gets through (<= 60 s), then require a clean run.
t0=$(date +%s)
if wait_ping a "$B_VPN"; then
	ping2=$(docker exec ${PFX}-a ping -c4 -W3 "$B_VPN" 2>&1 | tail -2)
	recv=$(echo "$ping2" | grep -oE '[0-9]+ received' | grep -oE '[0-9]+')
	echo "relay up after $(( $(date +%s) - t0 )) s: $(echo "$ping2" | head -1)"
	if [ "${recv:-0}" -ge 3 ]; then
		echo "relay A<->B reachable through R (obfs, per-hop sealed)"
	else
		echo "MISS: relayed obfs A<->B ping lossy after establishment"; fail=1
	fi
else
	echo "MISS: relayed obfs A<->B never came up within ${WAIT}s"; fail=1
	logs r | tail -20
fi

########################## PART 3: defaults (obfs off) ######################
echo "===== PART 3: obfs compiled but NOT selected -> plain-tinc wire ====="
reset_lab
gen "$BASE-b" nodeb ""            # defaults: PreferredTransports plain, junk 0
gen "$BASE-a" nodea "      ConnectTo: [nodeb]"
materialise b a
crossinject a b
start b "$B_IP" "$BASE-b"; start a "$A_IP" "$BASE-a"
wait_link a "$A_VPN" b "$B_VPN" || fail=1
capture_start b
docker exec ${PFX}-a ping -c3 -W2 "$B_VPN" >/dev/null 2>&1 || true
def_cap=$(capture_stop)
def_ping=$(docker exec ${PFX}-a ping -c3 -W2 "$B_VPN" 2>&1 | tail -2)
def_magic=$(sfmagic "$(hex_of "$def_cap")")
udpn=$(echo "$def_cap" | grep -c 'UDP' || true)
def_junk=$(junk_events a b)
echo "default: $(loss "$def_ping") ; SF magic=$def_magic ; UDP datagrams=$udpn ; junk events=$def_junk"
echo "$def_ping" | grep -q " 0% packet loss" || { echo "MISS: default tunnel ping failed"; fail=1; }
[ "$def_magic" = 0 ] || { echo "MISS: SF magic on the wire with defaults (should be plain SPTPS)"; fail=1; }
[ "$udpn" -gt 0 ] || { echo "MISS: no UDP data on the wire with defaults"; fail=1; }
[ "$def_junk" = 0 ] || { echo "MISS: junk emitted with obfs not selected"; fail=1; }

echo "==========================================================="
if [ "$fail" = 0 ]; then
	echo "PASS: obfs cold-start works, fingerprint gone, junk per-handshake, relay intact, defaults plain"
	exit 0
else
	echo "FAIL"
	exit 1
fi

#!/bin/sh
# obfs-test.sh -- prove the obfuscated-UDP carrier (M5, stream G2).
#
# PART 1  two nodes, dialer prefers obfs:
#   * the tunnel comes up FROM COLD and ping works both ways;
#   * the SPTPS/single-flow fingerprint is GONE from the wire -- the SF magic
#     9f747366...  is visible in a SingleFlow (sf) capture but ABSENT in the obfs
#     capture (it is sealed);
#   * junk datagrams (a distinctive size window) appear around the handshake but
#     are ZERO during a steady ping flood (junk is per-handshake, not per-packet).
# PART 2  three nodes A - R - B, A<->B direct blocked with iptables DROP:
#   * traffic still flows, relayed through R, each hop independently sealed
#     (no double-prefix corruption).
# PART 3  defaults (obfs compiled but NOT selected, ObfsJunkPacketCount 0):
#   * the tunnel works and the wire is plain SPTPS -- no obfs seal, no SF magic.
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

A_IP=10.37.9.10
R_IP=10.37.9.11
B_IP=10.37.9.12
A_VPN=10.182.0.1
R_VPN=10.182.0.2
B_VPN=10.182.0.3

# distinctive junk size window: far from the small sealed handshake frames and
# from the small sealed ping datagrams, so a capture-length filter isolates junk.
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

start() { # name ip dir extra-args
	docker run -d --name "${PFX}-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN \
		--device /dev/net/tun -v "$3":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n wsg2 -D -d2 >/dev/null
}
setvpn() { # name vpnip
	docker exec "${PFX}-$1" ip addr add "$2/24" dev wsg2 2>/dev/null || true
	docker exec "${PFX}-$1" ip link set wsg2 up
}

# capture hex on a container's tinc port; $1 container-letter $2 seconds -> stdout=hex text
capture_start() {
	docker run -d --name ${PFX}-cap --net container:${PFX}-$1 --cap-add NET_RAW "$TCPDUMP_IMG" \
		tcpdump -n -xx -i eth0 'udp port 655' >/dev/null 2>&1
	sleep 1
}
capture_stop() {
	docker stop ${PFX}-cap >/dev/null 2>&1 || true
	docker logs ${PFX}-cap 2>&1
	docker rm -f ${PFX}-cap >/dev/null 2>&1 || true
}
# concatenated payload hex (no spaces) from a -xx capture
hex_of() { echo "$1" | grep -oE '0x[0-9a-f]+:.*' | sed 's/0x[0-9a-f]*://' | tr -dc '0-9a-f'; }
# count UDP datagrams whose "length N" is within [lo,hi]
count_len_between() { echo "$1" | grep -oE 'length [0-9]+' | awk -v lo="$2" -v hi="$3" '{if($2>=lo&&$2<=hi)n++} END{print n+0}'; }
sfmagic() { echo "$1" | grep -c '9f7473666c77' || true; }

########################## PART 1: obfs two nodes ###########################
echo "===== PART 1: obfs, two nodes, cold-start + fingerprint + junk ====="

# Reference (BEFORE): SingleFlow only -> SF magic is visible on the wire.
gen "$BASE-b" nodeb "      SingleFlow: yes"
gen "$BASE-a" nodea "      SingleFlow: yes
      ConnectTo: [nodeb]"
materialise b a
crossinject a b
start b "$B_IP" "$BASE-b"; start a "$A_IP" "$BASE-a"
sleep 5; setvpn b "$B_VPN"; setvpn a "$A_VPN"
capture_start a 0
docker exec ${PFX}-a ping -c3 -W2 "$B_VPN" >/dev/null 2>&1 || true
sf_cap=$(capture_stop)
sf_magic=$(sfmagic "$(hex_of "$sf_cap")")
echo "BEFORE (sf):  SF magic 9f747366 occurrences on the wire = $sf_magic"
cleanup; docker network create --subnet 10.37.9.0/24 "$NET" >/dev/null 2>&1 || true

# AFTER: obfs preferred.
rm -rf "$BASE"-a "$BASE"-b; mkdir -p "$BASE"-a "$BASE"-b
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
sleep 3
# capture the cold handshake window while A dials B for the first time
capture_start b 0
start a "$A_IP" "$BASE-a"
sleep 5
setvpn b "$B_VPN"; setvpn a "$A_VPN"
sleep 2
hs_cap=$(capture_stop)

ab=$(docker exec ${PFX}-a ping -c3 -W2 "$B_VPN" 2>&1 | tail -2)
ba=$(docker exec ${PFX}-b ping -c3 -W2 "$A_VPN" 2>&1 | tail -2)

# steady-state flood window: no new handshake, so no junk expected
capture_start b 0
docker exec ${PFX}-a ping -c30 -i0.2 -W2 "$B_VPN" >/dev/null 2>&1 || true
steady_cap=$(capture_stop)

obfs_magic=$(sfmagic "$(hex_of "$hs_cap")")
junk_hs=$(count_len_between "$hs_cap" "$JMIN" "$JMAX")
junk_steady=$(count_len_between "$steady_cap" "$JMIN" "$JMAX")

echo "AFTER (obfs): SF magic 9f747366 occurrences on the wire = $obfs_magic"
echo "A->B: $(echo "$ab" | grep -oE '[0-9]+% packet loss' || echo '?')"
echo "B->A: $(echo "$ba" | grep -oE '[0-9]+% packet loss' || echo '?')"
echo "junk datagrams (size $JMIN-$JMAX) around handshake = $junk_hs ; during steady flood = $junk_steady"

echo "$ab" | grep -q "0% packet loss" || { echo "MISS: cold obfs A->B ping failed"; fail=1; }
echo "$ba" | grep -q "0% packet loss" || { echo "MISS: cold obfs B->A ping failed"; fail=1; }
[ "$sf_magic" -gt 0 ] || { echo "MISS: SF magic not seen in the sf reference capture (test setup)"; fail=1; }
[ "$obfs_magic" = 0 ] || { echo "MISS: SF/SPTPS fingerprint (SF magic) still visible under obfs"; fail=1; }
[ "$junk_hs" -gt 0 ] || { echo "MISS: no junk datagrams around the handshake"; fail=1; }
[ "$junk_steady" = 0 ] || { echo "MISS: junk datagrams during steady state (should be per-handshake only)"; fail=1; }

########################## PART 2: obfs relay ###############################
echo "===== PART 2: obfs A - R - B relay, A<->B direct blocked ====="
cleanup; docker network create --subnet 10.37.9.0/24 "$NET" >/dev/null 2>&1 || true
rm -rf "$BASE"-a "$BASE"-r "$BASE"-b; mkdir -p "$BASE"-a "$BASE"-r "$BASE"-b
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
sleep 5
setvpn r "$R_VPN"; setvpn a "$A_VPN"; setvpn b "$B_VPN"
docker exec ${PFX}-a iptables -A INPUT  -s "$B_IP" -j DROP
docker exec ${PFX}-a iptables -A OUTPUT -d "$B_IP" -j DROP
docker exec ${PFX}-b iptables -A INPUT  -s "$A_IP" -j DROP
docker exec ${PFX}-b iptables -A OUTPUT -d "$A_IP" -j DROP
relay_ok=0
i=0
while [ "$i" -lt 5 ]; do
	i=$((i + 1)); sleep 5
	ping2=$(docker exec ${PFX}-a ping -c4 -W3 "$B_VPN" 2>&1 | tail -2)
	recv=$(echo "$ping2" | grep -oE '[0-9]+ received' | grep -oE '[0-9]+')
	echo "relay attempt $i: $(echo "$ping2" | head -1)"
	[ "${recv:-0}" -ge 3 ] && { relay_ok=1; break; }
done
if [ "$relay_ok" = 1 ]; then echo "relay A<->B reachable through R (obfs, per-hop sealed)"; else echo "MISS: relayed obfs A<->B ping failed"; fail=1; fi

########################## PART 3: defaults (obfs off) ######################
echo "===== PART 3: obfs compiled but NOT selected -> plain-tinc wire ====="
cleanup; docker network create --subnet 10.37.9.0/24 "$NET" >/dev/null 2>&1 || true
rm -rf "$BASE"-a "$BASE"-b; mkdir -p "$BASE"-a "$BASE"-b
gen "$BASE-b" nodeb ""            # defaults: PreferredTransports plain, junk 0
gen "$BASE-a" nodea "      ConnectTo: [nodeb]"
materialise b a
crossinject a b
start b "$B_IP" "$BASE-b"; start a "$A_IP" "$BASE-a"
sleep 5; setvpn b "$B_VPN"; setvpn a "$A_VPN"
capture_start b 0
docker exec ${PFX}-a ping -c3 -W2 "$B_VPN" >/dev/null 2>&1 || true
def_cap=$(capture_stop)
def_ping=$(docker exec ${PFX}-a ping -c3 -W2 "$B_VPN" 2>&1 | tail -2)
def_magic=$(sfmagic "$(hex_of "$def_cap")")
udpn=$(echo "$def_cap" | grep -c 'UDP' || true)
echo "default: $(echo "$def_ping" | grep -oE '[0-9]+% packet loss') ; SF magic=$def_magic ; UDP datagrams=$udpn"
echo "$def_ping" | grep -q "0% packet loss" || { echo "MISS: default tunnel ping failed"; fail=1; }
[ "$def_magic" = 0 ] || { echo "MISS: SF magic on the wire with defaults (should be plain SPTPS)"; fail=1; }
[ "$udpn" -gt 0 ] || { echo "MISS: no UDP data on the wire with defaults"; fail=1; }

echo "==========================================================="
if [ "$fail" = 0 ]; then
	echo "PASS: obfs cold-start works, fingerprint gone, junk per-handshake, relay intact, defaults plain"
	exit 0
else
	echo "FAIL"
	exit 1
fi

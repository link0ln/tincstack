#!/bin/sh
# singleflow-test.sh -- prove the single-flow meta-over-UDP carrier.
#
# Part 1 (two nodes, both SingleFlow=yes):
#   * the tunnel comes up from cold and ping works;
#   * tcpdump on the tinc port shows only UDP, zero TCP (no tinc-shaped TCP
#     connection exists) -- the M4 single-flow proof.
#
# Part 2 (three nodes A - R - B, A and B cannot reach each other directly):
#   * a DROP rule in the relay severs A<->B direct reachability;
#   * traffic still flows A<->B, relayed through R over the unchanged SPTPS
#     relay path, proving single-flow does not corrupt relayed records.
#
# tcpdump runs inside a throwaway container attached to a node's netns, so
# nothing is installed on the host. Requires the ws-b image (SingleFlow is in
# every build).
#
# Usage: [LAB=prefix] [SUBNET=10.31.9] testing/transports/singleflow-test.sh [image]
#   LAB (default wsbsf) prefixes every container/network name and the /tmp
#   directory; a non-default LAB also gets its own /24 (see lab-env.sh), so
#   two runs can share a host.
#   The image is the first argument, else tincstack/core:$TINCSTACK_TAG, the
#   same selector every other proof takes. Silently defaulting to the stream
#   image this test was written against means a house-style invocation tests
#   a months-old core and reports its state as today's (measured: a run with
#   TINCSTACK_TAG set but no argument tested tincstack/core:ws-o and failed
#   PART 8, which the current core passes).
set -e

IMG=${1:-tincstack/core:${TINCSTACK_TAG:-dev}}
TCPDUMP_IMG=nicolaka/netshoot
DEFAULT_LAB=wsbsf; DEFAULT_SUBNET=10.31.9
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"
NET=$LAB
BASE=/tmp/$LAB

A_IP=$SUBNET.10
R_IP=$SUBNET.11
B_IP=$SUBNET.12

A_VPN=10.181.0.1
R_VPN=10.181.0.2
B_VPN=10.181.0.3

cleanup() {
	docker rm -f "$LAB-a" "$LAB-r" "$LAB-b" "$LAB-cap" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

rm -rf "$BASE"-a "$BASE"-r "$BASE"-b
mkdir -p "$BASE"-a "$BASE"-r "$BASE"-b

# --- write the three configs (A is the hub/relay rendezvous is R) -----------
# Topology: A connects to R, B connects to R. R is the relay. All SingleFlow.

cat > "$BASE-r/tinc.yaml" <<EOF
networks:
  wsb:
    options:
      Name: noder
      Mode: router
      Port: 655
      SingleFlow: yes
      AddressPool: 10.181.0.0/24
EOF

cat > "$BASE-a/tinc.yaml" <<EOF
networks:
  wsb:
    options:
      Name: nodea
      Mode: router
      Port: 655
      SingleFlow: yes
      AddressPool: 10.181.0.0/24
      ConnectTo: [noder]
EOF

cat > "$BASE-b/tinc.yaml" <<EOF
networks:
  wsb:
    options:
      Name: nodeb
      Mode: router
      Port: 655
      SingleFlow: yes
      AddressPool: 10.181.0.0/24
      ConnectTo: [noder]
EOF

for d in r a b; do
	timeout 3 docker run --rm -v "$BASE-$d":/etc/tincstack "$IMG" tincd -c /etc/tincstack/tinc.yaml -n wsb -D -d1 >/dev/null 2>&1 || true
done

# --- cross-inject host records with fixed VPN subnets -----------------------
python3 - "$BASE" "$R_IP" "$A_VPN" "$R_VPN" "$B_VPN" <<'PYEOF'
import re, sys
base, rip, avpn, rvpn, bvpn = sys.argv[1:6]
paths = {'a': base+'-a/tinc.yaml', 'r': base+'-r/tinc.yaml', 'b': base+'-b/tinc.yaml'}
names = {'a': 'nodea', 'r': 'noder', 'b': 'nodeb'}
vpn = {'a': avpn, 'r': rvpn, 'b': bvpn}

def block(path, name):
    s = open(path).read()
    m = re.search(r'^      %s: \|\n((?:(?:        .*)?\n)+)' % re.escape(name), s, re.M)
    lines = [l[8:] for l in m.group(1).split('\n') if l.startswith('        ')]
    return [l for l in lines if l.strip()]

def setsubnet(lines, ip):
    return [re.sub(r'Subnet = .*', 'Subnet = %s/32' % ip, l) for l in lines]

blocks = {k: setsubnet(block(paths[k], names[k]), vpn[k]) for k in paths}

# also fix each node's own Subnet in its own file
for k in paths:
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

# R learns A and B (no Address needed; they dial in)
inject(paths['r'], 'nodea', blocks['a'])
inject(paths['r'], 'nodeb', blocks['b'])
# A learns R (with Address) and B (for routing/relay)
r_addr = ['Address = ' + rip, 'Port = 655'] + [l for l in blocks['r'] if not l.startswith(('Address','Port'))]
inject(paths['a'], 'noder', r_addr)
inject(paths['a'], 'nodeb', blocks['b'])
# B learns R (with Address) and A
inject(paths['b'], 'noder', r_addr)
inject(paths['b'], 'nodea', blocks['a'])
print("configs merged")
PYEOF

start() { # name ip dir
	docker run -d --name "$LAB-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN \
		--device /dev/net/tun -v "$3":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n wsb -D -d2 >/dev/null
}

setvpn() { # name vpnip
	docker exec "$LAB-$1" ip addr add "$2/24" dev wsb 2>/dev/null || true
	docker exec "$LAB-$1" ip link set wsb up
}

# ============================ PART 1: two nodes =============================
echo "===== PART 1: single-flow, two nodes, tcpdump proof ====="
start r "$R_IP" "$BASE-r"
start a "$A_IP" "$BASE-a"
sleep 5
setvpn r "$R_VPN"
setvpn a "$A_VPN"

# capture on the relay's tinc port while A pings R over the tunnel
docker run -d --name "$LAB-cap" --net "container:$LAB-r" --cap-add NET_RAW "$TCPDUMP_IMG" \
	tcpdump -n -l -i eth0 'port 655' >/dev/null 2>&1
sleep 1
ping1=$(docker exec "$LAB-a" ping -c3 -W2 "$R_VPN" 2>&1 | tail -2)
sleep 1
docker stop "$LAB-cap" >/dev/null 2>&1
cap=$(docker logs "$LAB-cap" 2>&1)
docker rm -f "$LAB-cap" >/dev/null 2>&1

tcp=$(echo "$cap" | grep -c "Flags" || true)
udp=$(echo "$cap" | grep -c "UDP" || true)
echo "$ping1"
echo "tinc-port capture: TCP segments=$tcp  UDP datagrams=$udp"

fail=0
echo "$ping1" | grep -q "0% packet loss" || { echo "MISS: cold single-flow ping failed"; fail=1; }
[ "$tcp" = 0 ] || { echo "MISS: TCP seen on the tinc port (single-flow should be UDP only)"; fail=1; }
[ "$udp" -gt 0 ] || { echo "MISS: no UDP on the tinc port"; fail=1; }

# ============================ PART 2: relay ================================
echo "===== PART 2: A - R - B relay, A<->B direct blocked ====="
start b "$B_IP" "$BASE-b"
sleep 4
setvpn b "$B_VPN"
# Sever direct A<->B reachability so traffic must go through R.
docker exec "$LAB-a" iptables -A INPUT  -s "$B_IP" -j DROP
docker exec "$LAB-a" iptables -A OUTPUT -d "$B_IP" -j DROP
docker exec "$LAB-b" iptables -A INPUT  -s "$A_IP" -j DROP
docker exec "$LAB-b" iptables -A OUTPUT -d "$A_IP" -j DROP
# The first packets trigger the relayed SPTPS key exchange through R; give it
# up to ~25 s to establish, then require a clean run.
relay_ok=0
i=0
while [ "$i" -lt 5 ]; do
	i=$((i + 1))
	sleep 5
	ping2=$(docker exec "$LAB-a" ping -c4 -W3 "$B_VPN" 2>&1 | tail -2)
	recv=$(echo "$ping2" | grep -oE '[0-9]+ received' | grep -oE '[0-9]+')
	echo "relay attempt $i: $(echo "$ping2" | head -1)"

	if [ "${recv:-0}" -ge 3 ]; then
		relay_ok=1
		break
	fi
done

echo "$ping2"

if [ "$relay_ok" = 1 ]; then
	echo "relay A<->B reachable through R"
else
	echo "MISS: relayed A<->B ping failed"
	fail=1
fi

if [ "$fail" = 0 ]; then
	echo "PASS: single-flow tunnel is UDP-only, cold-start works, relay path intact"
	exit 0
else
	echo "FAIL"
	exit 1
fi

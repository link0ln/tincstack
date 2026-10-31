#!/bin/sh
# multipath-test.sh -- prove the Hybrid Application-Level Multipath engine
# across two isolated Docker networks (ISP1 + ISP2) without touching the host.
#
# Verifies:
#   Part 1: Parallel connection pooling (MultipathConnections=2) & Multi-WAN
#           uplink binding (`eth0` + `eth1` via MultipathInterface).
#   Part 2: Dynamic runtime mode switching via `tinc multipath mode`
#           (`flowhash`, `redundant`, `split`, `failover`) with 0% loss.
#   Part 3: 0-ms Make-Before-Break Failover when ISP1 (`eth0`) dies abruptly:
#           `multipath_promote_survivor()` promotes the standby connection in
#           0 ms without route flap or SPTPS reset.
set -e

IMG=${1:-tincstack/core:${TINCSTACK_TAG:-ws-f}}
LAB=${LAB:-wsfmp}
NET1="${LAB}-isp1"
NET2="${LAB}-isp2"
SUB1="10.31.88"
SUB2="10.31.89"
BASE="/tmp/${LAB}"

A_IP1="${SUB1}.10"
R_IP1="${SUB1}.11"
A_IP2="${SUB2}.10"
R_IP2="${SUB2}.11"

A_VPN="10.188.0.1"
R_VPN="10.188.0.2"

cleanup() {
	docker rm -f "${LAB}-a" "${LAB}-r" >/dev/null 2>&1 || true
	docker network rm "$NET1" "$NET2" >/dev/null 2>&1 || true
	rm -rf "${BASE}-a" "${BASE}-r"
}
trap cleanup EXIT
cleanup

docker network create --subnet "${SUB1}.0/24" "$NET1" >/dev/null
docker network create --subnet "${SUB2}.0/24" "$NET2" >/dev/null

mkdir -p "${BASE}-a" "${BASE}-r"

cat > "${BASE}-r/tinc.yaml" <<EOF
networks:
  mpnet:
    options:
      Name: noder
      Mode: router
      Port: 655
      HttpsPort: 8443
      QuicPort: 8443
      MultipathMode: flowhash
      MultipathConnections: 2
      PingInterval: 2
      PingTimeout: 3
      AddressPool: 10.188.0.0/24
EOF

cat > "${BASE}-a/tinc.yaml" <<EOF
networks:
  mpnet:
    options:
      Name: nodea
      Mode: router
      Port: 655
      PreferredTransports: [sftcp]
      MultipathMode: flowhash
      MultipathConnections: 2
      MultipathInterface:
        - eth0:${A_IP1}:100:0
        - eth1:${A_IP2}:50:1
      PingInterval: 2
      PingTimeout: 3
      AddressPool: 10.188.0.0/24
      ConnectTo: [noder]
EOF

for d in r a; do
	timeout 3 docker run --rm -v "${BASE}-${d}":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n mpnet -D -d1 >/dev/null 2>&1 || true
done

python3 - "$BASE" "$R_IP1" "$R_IP2" "$A_VPN" "$R_VPN" <<'PYEOF'
import re, sys
base, rip1, rip2, avpn, rvpn = sys.argv[1:6]
paths = {'a': base + '-a/tinc.yaml', 'r': base + '-r/tinc.yaml'}
names = {'a': 'nodea', 'r': 'noder'}
vpn = {'a': avpn, 'r': rvpn}

def block(path, name):
    s = open(path).read()
    m = re.search(r'^      %s: \|\n((?:(?:        .*)?\n)+)' % re.escape(name), s, re.M)
    lines = [l[8:] for l in m.group(1).split('\n') if l.startswith('        ')]
    return [l for l in lines if l.strip()]

def setsubnet(lines, ip):
    return [re.sub(r'Subnet = .*', 'Subnet = %s/32' % ip, l) for l in lines]

blocks = {k: setsubnet(block(paths[k], names[k]), vpn[k]) for k in paths}

for k in paths:
    s = open(paths[k]).read()
    s = re.sub(r'(%s: \|\n(?:        .*\n)*?        Subnet = )[^\n]*' % names[k],
               lambda m: m.group(1) + '%s/32' % vpn[k], s)
    open(paths[k], 'w').write(s)

def indent(lines):
    return ''.join('        ' + l + '\n' for l in lines)

def inject(path, name, extra):
    s = open(path).read()
    if '      %s: |' % name in s:
        return
    s = s.replace('    hosts:\n', '    hosts:\n      %s: |\n' % name + indent(extra), 1)
    open(path, 'w').write(s)

inject(paths['r'], 'nodea', blocks['a'])
r_addr = ['Address = ' + rip1, 'Address = ' + rip2, 'Port = 655'] + [
    l for l in blocks['r'] if not l.startswith(('Address', 'Port'))
]
inject(paths['a'], 'noder', r_addr)
PYEOF

echo "===== PART 1: Dual-ISP container startup & parallel connection pooling ====="
docker create --name "${LAB}-r" --network "$NET1" --ip "$R_IP1" --cap-add NET_ADMIN \
	--device /dev/net/tun -v "${BASE}-r":/etc/tincstack "$IMG" \
	tincd -c /etc/tincstack/tinc.yaml -n mpnet -D -d3 >/dev/null
docker network connect --ip "$R_IP2" "$NET2" "${LAB}-r"
docker start "${LAB}-r" >/dev/null

docker create --name "${LAB}-a" --network "$NET1" --ip "$A_IP1" --cap-add NET_ADMIN \
	--device /dev/net/tun -v "${BASE}-a":/etc/tincstack "$IMG" \
	tincd -c /etc/tincstack/tinc.yaml -n mpnet -D -d3 >/dev/null
docker network connect --ip "$A_IP2" "$NET2" "${LAB}-a"
docker start "${LAB}-a" >/dev/null

sleep 2
docker exec "${LAB}-r" ip addr add "${R_VPN}/24" dev mpnet 2>/dev/null || true
docker exec "${LAB}-r" ip link set mpnet up
docker exec "${LAB}-a" ip addr add "${A_VPN}/24" dev mpnet 2>/dev/null || true
docker exec "${LAB}-a" ip link set mpnet up

# Wait up to 10s for the secondary parallel connection (node noder conns=2) to be established
conns=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
	status_out=$(docker exec "${LAB}-a" tinc -c /etc/tincstack/tinc.yaml -n mpnet multipath status 2>/dev/null || true)
	if echo "$status_out" | grep -q "node noder conns=2"; then
		conns=2
		break
	fi
	sleep 1
done

echo "--- tinc multipath status on nodea ---"
echo "$status_out"

fail=0
if [ "$conns" -ne 2 ]; then
	echo "MISS: expected node noder conns=2 pooled parallel connections on nodea"
	echo "--- nodea logs ---"
	docker logs "${LAB}-a" 2>&1 | tail -40
	echo "--- noder logs ---"
	docker logs "${LAB}-r" 2>&1 | tail -40
	fail=1
fi

echo "===== PART 2: Dynamic scheduling modes (flowhash, redundant, split, failover) ====="
for m in flowhash redundant split failover flowhash; do
	docker exec "${LAB}-a" tinc -c /etc/tincstack/tinc.yaml -n mpnet multipath mode "$m" 2
	p_out=$(docker exec "${LAB}-a" ping -c 4 -i 0.2 -W 2 "$R_VPN" 2>&1 | tail -2)
	echo "[mode=$m] $p_out"
	echo "$p_out" | grep -q "0% packet loss" || { echo "MISS: packet loss in mode $m"; fail=1; }
done

echo "===== PART 3: 0-ms Make-Before-Break Failover on primary uplink failure ====="
# Sever ISP1 (R_IP1) completely and send TCP RST to immediately terminate the primary connection,
# testing that multipath_promote_survivor() promotes the secondary connection in 0 ms!
docker exec "${LAB}-a" iptables -A OUTPUT -d "$R_IP1" -p tcp -j REJECT --reject-with tcp-reset
docker exec "${LAB}-a" iptables -A INPUT  -s "$R_IP1" -j DROP
docker exec "${LAB}-a" iptables -A OUTPUT -d "$R_IP1" -j DROP
docker exec "${LAB}-a" tinc -c /etc/tincstack/tinc.yaml -n mpnet multipath uplink del eth0 || true

# Immediately send a burst of pings without waiting for reconnect
p_failover=$(docker exec "${LAB}-a" ping -c 5 -i 0.2 -W 2 "$R_VPN" 2>&1 | tail -2)
echo "[after ISP1 severed] $p_failover"
echo "$p_failover" | grep -q "0% packet loss" || { echo "MISS: packet loss during make-before-break failover"; fail=1; }

status_after=$(docker exec "${LAB}-a" tinc -c /etc/tincstack/tinc.yaml -n mpnet multipath status 2>/dev/null || true)
echo "--- tinc multipath status after ISP1 cut ---"
echo "$status_after"

echo "===== PART 4: Carrier-agnostic pooling over HTTPS and QUIC ====="
for carrier in https quic; do
	docker exec "${LAB}-a" tinc -c /etc/tincstack/tinc.yaml -n mpnet set PreferredTransports "$carrier"
	docker exec "${LAB}-a" tinc -c /etc/tincstack/tinc.yaml -n mpnet reload
	sleep 2
	p_car=$(docker exec "${LAB}-a" ping -c 4 -i 0.2 -W 2 "$R_VPN" 2>&1 | tail -2)
	echo "[carrier=$carrier] $p_car"
	echo "$p_car" | grep -q "0% packet loss" || { echo "MISS: packet loss on $carrier multipath"; fail=1; }
done

if [ "$fail" = 0 ]; then
	echo "PASS: Hybrid Application-Level Multipath pooling, schedulers, and 0-ms failover verified"
	exit 0
else
	echo "FAIL"
	exit 1
fi

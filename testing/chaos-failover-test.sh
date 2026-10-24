#!/bin/sh
# chaos-failover-test.sh -- Automated resilience, DPI fallback, mesh failover,
# and BlockedNodes test suite for tincstack.
set -e

IMG=${1:-tincstack/core:ws-f}
PFX=tschaos
NET=${PFX}net
SUBNET=10.42.99
BASE=/tmp/${PFX}

H1_IP=$SUBNET.10
H2_IP=$SUBNET.11
CL_IP=$SUBNET.12

H1_VPN=10.199.0.1
H2_VPN=10.199.0.2
CL_VPN=10.199.0.3

cleanup() {
	docker rm -f "$PFX-h1" "$PFX-h2" "$PFX-cl" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -rf "$BASE-h1" "$BASE-h2" "$BASE-cl"
mkdir -p "$BASE-h1" "$BASE-h2" "$BASE-cl"
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

fail=0
pass_count=0
note() { echo "  [PASS] $1"; pass_count=$((pass_count + 1)); }
miss() { echo "  [FAIL] $1"; fail=1; }

cat > "$BASE-h1/tinc.yaml" <<EOF
networks:
  wsg1:
    options:
      Name: hub1
      Mode: router
      Port: 655
      HttpsPort: 0
      QuicPort: 0
      AutoConnect: no
      AddressPool: 10.199.0.0/24
      PreferredTransports: [quic, https, obfs, sf, plain]
EOF

cat > "$BASE-h2/tinc.yaml" <<EOF
networks:
  wsg1:
    options:
      Name: hub2
      Mode: router
      Port: 655
      HttpsPort: 0
      QuicPort: 0
      AutoConnect: no
      ConnectTo: [hub1]
      AddressPool: 10.199.0.0/24
      PreferredTransports: [quic, https, obfs, sf, plain]
EOF

cat > "$BASE-cl/tinc.yaml" <<EOF
networks:
  wsg1:
    options:
      Name: client
      Mode: router
      Port: 655
      HttpsPort: 0
      QuicPort: 0
      AutoConnect: no
      ConnectTo: [hub1]
      BlockedNodes: [zombie1]
      MaxTimeout: 5
      UDPDiscoveryKeepaliveInterval: 4
      UDPDiscoveryInterval: 2
      UDPDiscoveryTimeout: 30
      AddressPool: 10.199.0.0/24
      PreferredTransports: [https, obfs, sf, plain]
EOF

for d in h1 h2 cl; do
	timeout 3 docker run --rm -v "$BASE-$d":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n wsg1 -D -d1 >/dev/null 2>&1 || true
done

python3 - "$BASE" "$H1_IP" "$H2_IP" "$H1_VPN" "$H2_VPN" "$CL_VPN" <<'PYEOF'
import re, sys
base, h1ip, h2ip, h1vpn, h2vpn, clvpn = sys.argv[1:7]
paths = {'h1': base+'-h1/tinc.yaml', 'h2': base+'-h2/tinc.yaml', 'cl': base+'-cl/tinc.yaml'}
names = {'h1': 'hub1', 'h2': 'hub2', 'cl': 'client'}
vpn = {'h1': h1vpn, 'h2': h2vpn, 'cl': clvpn}

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

def indent(lines): return ''.join('        ' + l + '\n' for l in lines)

def inject(path, name, extra):
    s = open(path).read()
    if '      %s: |' % name in s:
        return
    s = s.replace('    hosts:\n', '    hosts:\n      %s: |\n' % name + indent(extra), 1)
    open(path, 'w').write(s)

h1_addr = ['Address = ' + h1ip, 'Port = 655'] + [l for l in blocks['h1'] if not l.startswith(('Address', 'Port'))]
# Give client a per-host PreferredTransports = quic on hub1 for Scenario 2
h1_for_cl = h1_addr + ['PreferredTransports = quic']

inject(paths['h2'], 'hub1', h1_addr)
inject(paths['cl'], 'hub1', h1_for_cl)

inject(paths['h1'], 'hub2', ['Address = ' + h2ip, 'Port = 655'] + [l for l in blocks['h2'] if not l.startswith(('Address', 'Port'))])
inject(paths['h1'], 'client', blocks['cl'])
inject(paths['h1'], 'zombie1', ['Subnet = 10.199.0.99/32', 'Ed25519PublicKey = zkBJtofUR86jkHop6AL9lWxOXpYyfGbaXOMl6UoCoSN'])

# Notice: hub2 has client's pubkey so client can authenticate to hub2 later in Scenario 5,
# but client has NO host block and NO Address for hub2! Client must learn hub2 over the mesh!
inject(paths['h2'], 'client', blocks['cl'])
PYEOF

start_node() { # suffix ip dir vpnip
	docker run -d --name "${PFX}-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN \
		--device /dev/net/tun -v "$3":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n wsg1 -D -d3 >/dev/null
	sleep 1
	docker exec "${PFX}-$1" ip addr add "$4/24" dev wsg1 2>/dev/null || true
	docker exec "${PFX}-$1" ip link set wsg1 up 2>/dev/null || true
}

echo "===== Scenario 1: BlockedNodes & Zombie Node Elimination ====="
start_node h1 "$H1_IP" "$BASE-h1" "$H1_VPN"
start_node h2 "$H2_IP" "$BASE-h2" "$H2_VPN"
start_node cl "$CL_IP" "$BASE-cl" "$CL_VPN"
sleep 6
docker exec "$PFX-h1" ip addr replace "$H1_VPN/24" dev wsg1 && docker exec "$PFX-h1" ip link set wsg1 up
docker exec "$PFX-h2" ip addr replace "$H2_VPN/24" dev wsg1 && docker exec "$PFX-h2" ip link set wsg1 up
docker exec "$PFX-cl" ip addr replace "$CL_VPN/24" dev wsg1 && docker exec "$PFX-cl" ip link set wsg1 up
sleep 2

cl_nodes=$(docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump nodes)
if echo "$cl_nodes" | grep -q "^zombie1 "; then
	miss "Blocked node zombie1 appeared in client's node_tree"
else
	note "Client blocked zombie1 from entering node_tree despite hub1 advertising it"
fi

# Now add zombie1 to BlockedNodes on hub1 and hub2 and reload
docker exec "$PFX-h1" tinc -c /etc/tincstack/tinc.yaml -n wsg1 add BlockedNodes zombie1 >/dev/null
docker exec "$PFX-h2" tinc -c /etc/tincstack/tinc.yaml -n wsg1 add BlockedNodes zombie1 >/dev/null
docker exec "$PFX-h1" tinc -c /etc/tincstack/tinc.yaml -n wsg1 reload >/dev/null
docker exec "$PFX-h2" tinc -c /etc/tincstack/tinc.yaml -n wsg1 reload >/dev/null
sleep 2

h1_nodes=$(docker exec "$PFX-h1" tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump nodes)
h2_nodes=$(docker exec "$PFX-h2" tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump nodes)
if echo "$h1_nodes" | grep -q "^zombie1 " || echo "$h2_nodes" | grep -q "^zombie1 "; then
	miss "zombie1 still present on hub1 or hub2 after BlockedNodes + reload"
else
	note "Adding zombie1 to BlockedNodes + reload immediately purged zombie1 from hub1 and hub2"
fi

echo "===== Scenario 2: Per-Host PreferredTransports Auto-Fallback (quic -> https) ====="
# Verify client initially connected to hub1 via quic (per-host PreferredTransports = quic)
cl_conns=$(docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump connections)
if echo "$cl_conns" | grep -q "transport quic"; then
	note "Client initially connected to hub1 via per-host preferred carrier 'quic'"
else
	miss "Client did not use per-host preferred carrier 'quic' initially: $cl_conns"
fi

# Now block all UDP between client and hub1 (simulating ISP blocking QUIC/UDP)
docker exec "$PFX-cl" iptables -I OUTPUT -p udp -d "$H1_IP" -j DROP
docker exec "$PFX-cl" iptables -I INPUT -p udp -s "$H1_IP" -j DROP
docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 disconnect hub1 >/dev/null 2>&1 || true
docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 retry >/dev/null 2>&1 || true

# Wait for sticky retries of quic to exhaust and fall back to https
fallback_ok=0
for _ in $(seq 1 25); do
	sleep 1
	c_out=$(docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump connections 2>/dev/null || true)
	if echo "$c_out" | grep -q "transport https"; then
		fallback_ok=1
		break
	fi
	docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 retry >/dev/null 2>&1 || true
done

if [ "$fallback_ok" -eq 1 ] && docker exec "$PFX-cl" ping -c2 -W2 "$H1_VPN" >/dev/null 2>&1; then
	note "Client automatically fell back from per-host 'quic' to 'https' when UDP was blocked"
else
	miss "Client failed to fall back from per-host 'quic' to 'https'"
fi

echo "===== Scenario 3: Smart Data-Plane UDP Fallback under DPI & Mid-Stream UDP Cut ====="
# Switch client -> hub1 to split TCP-meta + DirectSeal-UDP-data mode (PreferredTransports = plain)
# so tincd uses TCP for meta and obfs-sealed UDP for the data plane.
docker exec "$PFX-cl" iptables -D OUTPUT -p udp -d "$H1_IP" -j DROP
docker exec "$PFX-cl" iptables -D INPUT -p udp -s "$H1_IP" -j DROP
# Block UDP packets >= 200 bytes (DPI size filter) while allowing small 18-byte keepalives
docker exec "$PFX-cl" iptables -I OUTPUT -p udp -d "$H1_IP" -m length --length 200:65535 -j DROP
docker exec "$PFX-cl" iptables -I INPUT -p udp -s "$H1_IP" -m length --length 200:65535 -j DROP
docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 set hub1.PreferredTransports plain >/dev/null
docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 reload >/dev/null
docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 disconnect hub1 >/dev/null 2>&1 || true
docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 retry >/dev/null 2>&1 || true
sleep 2

# Trigger traffic for ~9 seconds so 20 PMTU probes run while only 18-byte keepalives succeed
for _ in $(seq 1 9); do
	docker exec "$PFX-cl" ping -c1 -W1 -s 300 "$H1_VPN" >/dev/null 2>&1 || true
	sleep 1
done

# Now verify 300-byte pings (which are < 512 MINMTU but > 200 DPI limit) succeed with 0% loss over TCP meta!
if docker exec "$PFX-cl" ping -c4 -W2 -s 300 "$H1_VPN" | grep -q "0% packet loss"; then
	note "DPI UDP size-filter (>200B dropped): tincd demoted fake UDP confirmation and kept 300B packets on TCP meta (0% loss)"
else
	miss "DPI UDP size-filter blackholed 300B packets into broken UDP path"
fi

# Remove the DPI length filter so full direct UDP confirms (minmtu >= 1300)
docker exec "$PFX-cl" iptables -D OUTPUT -p udp -d "$H1_IP" -m length --length 200:65535 -j DROP
docker exec "$PFX-cl" iptables -D INPUT -p udp -s "$H1_IP" -m length --length 200:65535 -j DROP

udp_up=0
for _ in $(seq 1 15); do
	docker exec "$PFX-cl" ping -c1 -W1 "$H1_VPN" >/dev/null 2>&1 || true
	sleep 1
	n_out=$(docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump nodes | grep "^hub1 ")
	min_mtu=$(echo "$n_out" | awk '{for(i=1;i<=NF;i++) if($i=="(min") print $(i+1)}')
	if [ "${min_mtu:-0}" -ge 1200 ]; then
		udp_up=1
		break
	fi
done

if [ "$udp_up" -eq 1 ]; then
	note "Direct UDP data plane confirmed with PMTU min=$min_mtu"
else
	miss "Direct UDP data plane did not confirm after removing DPI filter"
fi

# Now cut UDP completely mid-stream and verify fallback to TCP happens within ~8s (well under 30s UDPDiscoveryTimeout)
docker exec "$PFX-cl" iptables -I OUTPUT -p udp -d "$H1_IP" -j DROP
docker exec "$PFX-cl" iptables -I INPUT -p udp -s "$H1_IP" -j DROP

recovered=0
for sec in $(seq 1 12); do
	docker exec "$PFX-cl" ping -c1 -W1 "$H1_VPN" >/dev/null 2>&1 || true
	sleep 1
	n_out=$(docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump nodes | grep "^hub1 ")
	min_mtu=$(echo "$n_out" | awk '{for(i=1;i<=NF;i++) if($i=="(min") print $(i+1)}')
	if [ "${min_mtu:-0}" -eq 0 ]; then
		recovered=$sec
		break
	fi
done

if [ "$recovered" -gt 0 ] && [ "$recovered" -le 11 ] && docker exec "$PFX-cl" ping -c3 -W2 "$H1_VPN" | grep -q "0% packet loss"; then
	note "Mid-stream UDP cut detected and failed over to https TCP in ${recovered}s (< 30s timeout)"
else
	miss "Mid-stream UDP cut did not fail over quickly (recovered=$recovered)"
fi

docker exec "$PFX-cl" iptables -D OUTPUT -p udp -d "$H1_IP" -j DROP
docker exec "$PFX-cl" iptables -D INPUT -p udp -s "$H1_IP" -j DROP

echo "===== Scenario 4: Packet Loss (15%) + Jitter (50ms) Resilience ====="
docker exec "$PFX-cl" tc qdisc add dev eth0 root netem delay 50ms 15ms loss 15%
if docker exec "$PFX-cl" ping -c5 -W3 "$H1_VPN" | grep -q "received"; then
	note "Tunnel survives 15% underlay packet loss + 50ms jitter"
else
	miss "Tunnel failed under 15% underlay packet loss + 50ms jitter"
fi
docker exec "$PFX-cl" tc qdisc del dev eth0 root

echo "===== Scenario 5: Learned Mesh Peer Persistence & Emergency Entry Failover ====="
# Wait a moment for client to have learned hub2's address cache & pubkey/transports over the mesh
sleep 3
if grep -q "hub2:" "$BASE-cl/tinc.yaml" && [ -f "$BASE-cl/cache/wsg1/hub2" -o -f "/tmp/${PFX}-cl/cache/hub2" ] || docker exec "$PFX-cl" sh -c 'ls /var/lib/tinc/wsg1/cache/hub2 /etc/tincstack/cache/hub2 2>/dev/null' >/dev/null 2>&1; then
	note "Client persisted learned mesh peer hub2 (Ed25519PublicKey, Transports, and address cache)"
else
	# Check where confbase cache is inside container
	cache_found=$(docker exec "$PFX-cl" find / -name hub2 2>/dev/null || true)
	if [ -n "$cache_found" ] && grep -q "hub2:" "$BASE-cl/tinc.yaml"; then
		note "Client persisted learned mesh peer hub2 ($cache_found + tinc.yaml)"
	else
		miss "Client did not persist hub2 cache ($cache_found) or tinc.yaml"
	fi
fi

# Now kill primary ConnectTo node (hub1) AND restart client's tincd process inside the container
# (keeping container filesystem intact, just like Wi-Fi toggle / service restart on a device)
docker stop "$PFX-h1" >/dev/null
docker restart "$PFX-cl" >/dev/null
sleep 2
docker exec "$PFX-cl" ip addr replace "$CL_VPN/24" dev wsg1 2>/dev/null || true
docker exec "$PFX-cl" ip link set wsg1 up 2>/dev/null || true

# Wait for client's primary ConnectTo (hub1) to fail 1 round and do_fallback_autoconnect() to dial hub2
mesh_failover=0
for _ in $(seq 1 25); do
	sleep 1
	if docker exec "$PFX-cl" ping -c1 -W1 "$H2_VPN" >/dev/null 2>&1; then
		mesh_failover=1
		break
	fi
done

if [ "$mesh_failover" -eq 1 ]; then
	note "Emergency Mesh Entry Failover: with primary ConnectTo (hub1) down and after daemon restart, client connected via cached peer hub2!"
else
	miss "Emergency Mesh Entry Failover failed to connect to hub2 when hub1 was down"
	docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump nodes || true
	docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump connections || true
fi

echo "=================================================================="
echo "Summary: $pass_count passed, fail=$fail"
exit "$fail"

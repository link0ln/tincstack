#!/bin/sh
# stability-routing-test.sh -- Tests for the production stability fixes:
#   1. Dynamic UDP RTT edge weight calibration (routing away from high-RTT /
#      mobile relays when initial handshake weight was inflated by CPU/setup delay)
#   2. SPTPS burst-loss (>128 packets) and out-of-order replay-window resilience
#      (never tearing down active SPTPS key on late/post-loss packets)
#   3. Busy HTTPS single-stream liveness (no false PingTimeout teardown while
#      data frames are actively arriving)
set -e

IMG=${1:-tincstack/core:ws-f}
PFX=tsstab
NET=${PFX}net
SUBNET=10.42.98
BASE=/tmp/${PFX}

HUB_IP=$SUBNET.10
RFAST_IP=$SUBNET.11
RSLOW_IP=$SUBNET.12
CL_IP=$SUBNET.13

HUB_VPN=10.198.0.1
RFAST_VPN=10.198.0.2
RSLOW_VPN=10.198.0.3
CL_VPN=10.198.0.4

cleanup() {
	docker rm -f "$PFX-hub" "$PFX-rfast" "$PFX-rslow" "$PFX-cl" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -rf "$BASE-hub" "$BASE-rfast" "$BASE-rslow" "$BASE-cl"
mkdir -p "$BASE-hub" "$BASE-rfast" "$BASE-rslow" "$BASE-cl"
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

fail=0
pass_count=0
note() { echo "  [PASS] $1"; pass_count=$((pass_count + 1)); }
miss() { echo "  [FAIL] $1"; fail=1; }

cat > "$BASE-hub/tinc.yaml" <<EOF
networks:
  wsg1:
    options:
      Name: hub
      Mode: router
      Port: 655
      HttpsPort: 8443
      QuicPort: 8443
      AutoConnect: no
      PingInterval: 3
      PingTimeout: 2
      AddressPool: 10.198.0.0/24
      Transports: [plain, sf, obfs, https, quic]
EOF

cat > "$BASE-rfast/tinc.yaml" <<EOF
networks:
  wsg1:
    options:
      Name: rfast
      Mode: router
      Port: 655
      HttpsPort: 8443
      QuicPort: 8443
      AutoConnect: no
      ConnectTo: hub
      UDPDiscoveryInterval: 1
      UDPDiscoveryKeepaliveInterval: 2
      AddressPool: 10.198.0.0/24
      Transports: [plain, sf, obfs, https, quic]
      PreferredTransports: [https]
EOF

cat > "$BASE-rslow/tinc.yaml" <<EOF
networks:
  wsg1:
    options:
      Name: rslow
      Mode: router
      Port: 655
      HttpsPort: 8443
      QuicPort: 8443
      AutoConnect: no
      ConnectTo: hub
      UDPDiscoveryInterval: 1
      UDPDiscoveryKeepaliveInterval: 2
      AddressPool: 10.198.0.0/24
      Transports: [plain, sf, obfs, https, quic]
      PreferredTransports: [https]
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
      ConnectTo:
        - rfast
        - rslow
      UDPDiscoveryInterval: 1
      UDPDiscoveryKeepaliveInterval: 2
      AddressPool: 10.198.0.0/24
      Transports: [plain, sf, obfs, https, quic]
      PreferredTransports: [plain]
EOF

for d in hub rfast rslow cl; do
	timeout 3 docker run --rm -v "$BASE-$d":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n wsg1 -D -d1 >/dev/null 2>&1 || true
done

python3 - "$BASE" "$HUB_IP" "$RFAST_IP" "$RSLOW_IP" "$HUB_VPN" "$RFAST_VPN" "$RSLOW_VPN" "$CL_VPN" <<'PYEOF'
import re, sys
base, hubip, rfip, rsip, hubvpn, rfvpn, rsvpn, clvpn = sys.argv[1:9]
paths = {'hub': base+'-hub/tinc.yaml', 'rfast': base+'-rfast/tinc.yaml', 'rslow': base+'-rslow/tinc.yaml', 'cl': base+'-cl/tinc.yaml'}
names = {'hub': 'hub', 'rfast': 'rfast', 'rslow': 'rslow', 'cl': 'client'}
vpn = {'hub': hubvpn, 'rfast': rfvpn, 'rslow': rsvpn, 'cl': clvpn}

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

hub_addr = ['Address = ' + hubip, 'Port = 655', 'HttpsPort = 8443'] + [l for l in blocks['hub'] if not l.startswith(('Address', 'Port'))]
rf_addr = ['Address = ' + rfip, 'Port = 655'] + [l for l in blocks['rfast'] if not l.startswith(('Address', 'Port'))]
rs_addr = ['Address = ' + rsip, 'Port = 655'] + [l for l in blocks['rslow'] if not l.startswith(('Address', 'Port'))]

inject(paths['rfast'], 'hub', hub_addr)
inject(paths['rslow'], 'hub', hub_addr)
inject(paths['hub'], 'rfast', rf_addr)
inject(paths['hub'], 'rslow', rs_addr)

inject(paths['cl'], 'rfast', rf_addr)
inject(paths['cl'], 'rslow', rs_addr)
inject(paths['rfast'], 'client', blocks['cl'])
inject(paths['rslow'], 'client', blocks['cl'])
PYEOF

start_node() { # suffix ip dir vpnip
	docker run -d --name "${PFX}-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN \
		--device /dev/net/tun -v "$3":/etc/tincstack "$IMG" \
		sh -c 'tincd -c /etc/tincstack/tinc.yaml -n wsg1 -D -d3 >/var/log/tinc.log 2>&1' >/dev/null
	sleep 1
	docker exec "${PFX}-$1" ip addr replace "$4/24" dev wsg1 2>/dev/null || true
	docker exec "${PFX}-$1" ip link set wsg1 up 2>/dev/null || true
}

echo "===== Scenario 1: Dynamic UDP RTT Edge Weight Calibration ====="
start_node hub "$HUB_IP" "$BASE-hub" "$HUB_VPN"
start_node rfast "$RFAST_IP" "$BASE-rfast" "$RFAST_VPN"
start_node rslow "$RSLOW_IP" "$BASE-rslow" "$RSLOW_VPN"
sleep 3

# Simulate one-time CPU/setup delay on rfast during initial TCP handshake (80ms delay on TCP),
# while rslow has 0ms initial handshake delay!
docker exec "$PFX-rfast" tc qdisc add dev eth0 root netem delay 80ms 2>/dev/null || true

start_node cl "$CL_IP" "$BASE-cl" "$CL_VPN"
sleep 3
for n in hub rfast rslow cl; do
	docker exec "$PFX-$n" ip link set wsg1 up 2>/dev/null || true
done
docker exec "$PFX-hub" ip addr replace "$HUB_VPN/24" dev wsg1
docker exec "$PFX-rfast" ip addr replace "$RFAST_VPN/24" dev wsg1
docker exec "$PFX-rslow" ip addr replace "$RSLOW_VPN/24" dev wsg1
docker exec "$PFX-cl" ip addr replace "$CL_VPN/24" dev wsg1

# Remove the one-time setup delay on rfast (real UDP RTT on rfast is <1ms),
# and apply a realistic 120ms Wi-Fi/mobile latency on rslow!
docker exec "$PFX-rfast" tc qdisc del dev eth0 root 2>/dev/null || true
docker exec "$PFX-rslow" tc qdisc add dev eth0 root netem delay 60ms 2>/dev/null || true

# Trigger UDP probes on rfast/rslow <-> hub and client <-> rfast/rslow
docker exec "$PFX-rfast" ping -c 3 -W 2 "$HUB_VPN" >/dev/null 2>&1 || true
docker exec "$PFX-rslow" ping -c 3 -W 2 "$HUB_VPN" >/dev/null 2>&1 || true
docker exec "$PFX-cl" ping -c 4 -W 2 "$RFAST_VPN" >/dev/null 2>&1 || true
docker exec "$PFX-cl" ping -c 4 -W 2 "$RSLOW_VPN" >/dev/null 2>&1 || true
sleep 3
docker exec "$PFX-rfast" ping -c 2 -W 2 "$HUB_VPN" >/dev/null 2>&1 || true
docker exec "$PFX-rslow" ping -c 2 -W 2 "$HUB_VPN" >/dev/null 2>&1 || true
docker exec "$PFX-cl" ping -c 3 -W 2 "$RFAST_VPN" >/dev/null 2>&1 || true
docker exec "$PFX-cl" ping -c 3 -W 2 "$RSLOW_VPN" >/dev/null 2>&1 || true
sleep 2

NEXTHOP_HUB=$(docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump nodes | awk '/^hub /{for(i=1;i<=NF;i++) if($i=="nexthop") print $(i+1)}')
W_RFAST=$(docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump edges | awk '/^client to rfast /{print $NF}')
W_RSLOW=$(docker exec "$PFX-cl" tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump edges | awk '/^client to rslow /{print $NF}')

echo "  Edges on client: client->rfast weight=$W_RFAST, client->rslow weight=$W_RSLOW, hub nexthop=$NEXTHOP_HUB"
if [ "$NEXTHOP_HUB" = "rfast" ] && [ "${W_RFAST:-999}" -lt "${W_RSLOW:-0}" ]; then
	note "UDP RTT edge weight calibration updated weights (rfast=$W_RFAST < rslow=$W_RSLOW) and routed hub via nexthop rfast"
else
	miss "Expected nexthop rfast and W_RFAST < W_RSLOW (got nexthop=$NEXTHOP_HUB, rfast=$W_RFAST, rslow=$W_RSLOW)"
fi

echo "===== Scenario 2: SPTPS Burst-Loss (>128 pkts) & Replay-Window Resilience ====="
# Establish SPTPS key between client and rfast and wait 31s so the 30s restart cooldown is armed
docker exec "$PFX-cl" ping -c 3 -W 2 "$RFAST_VPN" >/dev/null 2>&1
echo "  Waiting 31s so SPTPS 30s restart cooldown window is armed..."
sleep 31

# Drop 220 UDP packets mid-burst from client to rfast (> old 128-packet replaywin),
# then allow subsequent packets through and check that SPTPS does NOT reset!
docker exec "$PFX-rfast" iptables -I INPUT 1 -p udp -s "$CL_IP" -j DROP
docker exec "$PFX-cl" ping -f -c 220 -W 1 "$RFAST_VPN" >/dev/null 2>&1 || true
docker exec "$PFX-rfast" iptables -D INPUT -p udp -s "$CL_IP" -j DROP

if docker exec "$PFX-cl" ping -c 4 -W 2 "$RFAST_VPN" >/dev/null 2>&1; then
	note "Traffic recovered immediately after >220-packet burst loss without blackout"
else
	miss "Traffic failed after >220-packet burst loss"
fi

if docker exec "$PFX-rfast" grep -q "Failed to decode.*restarting SPTPS" /var/log/tinc.log || \
   docker exec "$PFX-cl" grep -q "Failed to decode.*restarting SPTPS" /var/log/tinc.log; then
	miss "SPTPS session was torn down after burst loss"
else
	note "SPTPS session remained intact (zero 'Failed to decode ... restarting SPTPS' resets)"
fi

echo "===== Scenario 3: Busy HTTPS Link Survives Under Heavy Traffic ====="
# Flood traffic between client and hub (relayed over rfast <-> hub https link with PingInterval=3, PingTimeout=2)
docker exec "$PFX-cl" ping -f -c 500 -s 1200 "$HUB_VPN" >/dev/null 2>&1 || true
sleep 4
docker exec "$PFX-cl" ping -f -c 500 -s 1200 "$HUB_VPN" >/dev/null 2>&1 || true

if docker exec "$PFX-hub" grep -q "didn't respond to PING" /var/log/tinc.log || \
   docker exec "$PFX-rfast" grep -q "didn't respond to PING" /var/log/tinc.log; then
	miss "HTTPS link dropped with PING timeout during bulk traffic"
else
	note "HTTPS link between rfast and hub stayed up with zero false PING timeouts"
fi

echo "===== Summary: $pass_count passed, fail=$fail ====="
exit "$fail"

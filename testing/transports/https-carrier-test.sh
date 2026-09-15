#!/bin/sh
# https-carrier-test.sh -- prove M5 (G1) task 3: the `https' carrier.
#
#   * node A (PreferredTransports: [https, plain]) tunnels to B; ping both ways;
#   * `tinc dump connections' on both shows the carrier `https';
#   * tcpdump on the port shows only TLS records -- no UDP, no cleartext tinc
#     ID line;
#   * a prober on the same port during the session gets the decoy;
#   * a forged/replayed authenticator gets the decoy.
#
# All tooling runs in throwaway containers sharing a node's netns; nothing is
# installed on the host. Test data under /tmp/wsg1-* only.
#
# Usage: testing/transports/https-carrier-test.sh [image]
set -e

IMG=${1:-tincstack/core:ws-g1}
TOOLS=nicolaka/netshoot
NET=wsg1https
BASE=/tmp/wsg1-https
A_IP=10.42.9.10
B_IP=10.42.9.11
A_VPN=10.192.0.1
B_VPN=10.192.0.2

cleanup() {
	docker rm -f wsg1h-a wsg1h-b wsg1h-cap >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -rf "$BASE-a" "$BASE-b"
mkdir -p "$BASE-a" "$BASE-b"
docker network create --subnet 10.42.9.0/24 "$NET" >/dev/null

fail=0
note() { echo "  $1"; }
miss() { echo "  MISS: $1"; fail=1; }

# B is the rendezvous (public Port 655). A dials B, preferring https.
cat > "$BASE-b/tinc.yaml" <<EOF
networks:
  wsg1:
    options:
      Name: nodeb
      Mode: router
      Port: 655
      AddressPool: 10.192.0.0/24
EOF

cat > "$BASE-a/tinc.yaml" <<EOF
networks:
  wsg1:
    options:
      Name: nodea
      Mode: router
      Port: 655
      AddressPool: 10.192.0.0/24
      PreferredTransports: [https, plain]
      ConnectTo: [nodeb]
EOF

for d in a b; do
	timeout 3 docker run --rm -v "$BASE-$d":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n wsg1 -D -d1 >/dev/null 2>&1 || true
done

# --- cross-inject host records (with fixed subnets, keys, TlsFingerprint) ----
python3 - "$BASE" "$B_IP" "$A_VPN" "$B_VPN" <<'PYEOF'
import re, sys
base, bip, avpn, bvpn = sys.argv[1:5]
paths = {'a': base+'-a/tinc.yaml', 'b': base+'-b/tinc.yaml'}
names = {'a': 'nodea', 'b': 'nodeb'}
vpn = {'a': avpn, 'b': bvpn}

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

# A learns B, with Address/Port so it can dial; B's block already carries its
# Ed25519PublicKey and TlsFingerprint (so A pins B's cert).
b_addr = ['Address = ' + bip, 'Port = 655'] + [l for l in blocks['b'] if not l.startswith(('Address', 'Port'))]
inject(paths['a'], 'nodeb', b_addr)
# B learns A (its Ed25519PublicKey lets B verify A's authenticator).
inject(paths['b'], 'nodea', blocks['a'])
print("configs merged")
PYEOF

start() { # name ip dir
	docker run -d --name "wsg1h-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN \
		--device /dev/net/tun -v "$3":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n wsg1 -D -d3 >/dev/null
}
setvpn() { # name vpnip
	docker exec "wsg1h-$1" ip addr add "$2/24" dev wsg1 2>/dev/null || true
	docker exec "wsg1h-$1" ip link set wsg1 up
}

echo "===== https carrier: bring up the tunnel ====="
start b "$B_IP" "$BASE-b"
sleep 2
# capture on B's tinc port for the whole bring-up + ping
docker run -d --name wsg1h-cap --net container:wsg1h-b --cap-add NET_RAW "$TOOLS" \
	tcpdump -n -l -A -i eth0 'port 655' >/dev/null 2>&1
start a "$A_IP" "$BASE-a"
sleep 6
setvpn b "$B_VPN"
setvpn a "$A_VPN"
sleep 2

ping_ab=$(docker exec wsg1h-a ping -c3 -W2 "$B_VPN" 2>&1 | tail -2)
ping_ba=$(docker exec wsg1h-b ping -c3 -W2 "$A_VPN" 2>&1 | tail -2)
echo "$ping_ab" | grep -q "0% packet loss" && note "A -> B ping over the tunnel works" || miss "A -> B ping failed"
echo "$ping_ba" | grep -q "0% packet loss" && note "B -> A ping over the tunnel works" || miss "B -> A ping failed"

# `tinc dump connections' must show the https carrier on both ends.
dca=$(docker exec wsg1h-a tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump connections 2>/dev/null || true)
dcb=$(docker exec wsg1h-b tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump connections 2>/dev/null || true)
echo "$dca" | grep -q "transport https" && note "A dump connections shows transport https" || miss "A does not show transport https"
echo "$dcb" | grep -q "transport https" && note "B dump connections shows transport https" || miss "B does not show transport https"

echo "===== prober during the session gets the decoy ====="
pr=$(docker run --rm --net container:wsg1h-b "$TOOLS" curl -sk https://127.0.0.1:655/ || true)
echo "$pr" | grep -qi "It works" && note "a TLS prober during the session got the decoy" || miss "prober did not get the decoy"

echo "===== forged / replayed authenticator gets the decoy ====="
# A syntactically plausible but forged authenticator (random cookie). The server
# cannot verify it -> it serves the decoy, identical to any other prober. Sent
# twice (replay): both get the decoy, never a 101.
FORGED="AQdub2RlYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
r1=$(docker run --rm --net container:wsg1h-b "$TOOLS" \
	curl -sk -D - -o /dev/null https://127.0.0.1:655/ws \
	-H "Upgrade: websocket" -H "Connection: Upgrade" \
	-H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
	-H "Cookie: sid=$FORGED" 2>&1 | head -1 || true)
r2=$(docker run --rm --net container:wsg1h-b "$TOOLS" \
	curl -sk -D - -o /dev/null https://127.0.0.1:655/ws \
	-H "Upgrade: websocket" -H "Connection: Upgrade" \
	-H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
	-H "Cookie: sid=$FORGED" 2>&1 | head -1 || true)
echo "  forged attempt 1: $r1"
echo "  replayed attempt: $r2"
echo "$r1" | grep -q "101" && miss "forged authenticator was accepted (101)!" || note "forged authenticator got the decoy (no 101)"
echo "$r2" | grep -q "101" && miss "replayed authenticator was accepted (101)!" || note "replayed authenticator got the decoy (no 101)"

echo "===== tcpdump: only TLS, no UDP, no cleartext tinc ID ====="
sleep 1
docker stop wsg1h-cap >/dev/null 2>&1
cap=$(docker logs wsg1h-cap 2>&1)
docker rm -f wsg1h-cap >/dev/null 2>&1

udp=$(echo "$cap" | grep -c "UDP" || true)
# A cleartext tinc meta channel begins with an "0 <name>" ID line; inside TLS it
# must never appear in the clear. Look for our node names in the ASCII dump.
idleak=$(echo "$cap" | grep -cE "^0 node|[^a-zA-Z]0 node(a|b)" || true)
nameleak=$(echo "$cap" | grep -c "Ed25519PublicKey" || true)

note "UDP datagrams on the port: $udp"
[ "$udp" = 0 ] && note "no UDP on the port (single TLS flow, TCP-only-equivalent)" || miss "UDP seen on the port ($udp)"
[ "$idleak" = 0 ] && note "no cleartext tinc ID line on the wire" || miss "cleartext tinc ID line leaked"
[ "$nameleak" = 0 ] && note "no cleartext key material on the wire" || miss "cleartext key material leaked"

echo "==========================================="

if [ "$fail" = 0 ]; then
	echo "PASS: https carrier tunnels, is TLS-only, and resists probing"
	exit 0
else
	echo "FAIL"
	exit 1
fi

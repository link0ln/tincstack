#!/bin/sh
# https-carrier-test.sh -- prove M5 (G1) task 3: the `https' carrier.
#
#   * node A (PreferredTransports: [https, plain]) tunnels to B; ping both ways;
#   * `tinc dump connections' on both shows the carrier `https';
#   * tcpdump on the port shows only TLS records -- no UDP, no cleartext tinc
#     ID line;
#   * a prober on the same port during the session gets the decoy;
#   * a forged/replayed authenticator gets the decoy;
#   * (review M5-1) with B's HttpsDecoyUpstream black-holed, TLS probes at B do
#     not delay the tunnel ping A->B;
#   * (review M5-7) a TLS bump (socat with its own certificate) between A and
#     B on A's first dial leaves NO TlsFingerprint pin in A's host record for
#     B; a legitimate first dial pins B's real fingerprint once SPTPS
#     authenticated the peer.
#   * (review L-2) an *activated* https link that drops (B reload, TCP reset,
#     B's daemon killed and kept down past A's reconnect backoff) comes back
#     as https, never plain; a carrier that once activated is abandoned only
#     after three pre-activation failures in a row, and even then the next
#     reconnect starts again from the operator's first preference.
#
# All tooling runs in throwaway containers sharing a node's netns; nothing is
# installed on the host. Test data under /tmp/<PFX>-https-* only.
#
# Usage: [LAB=wslh] [SUBNET=10.42.9] testing/transports/https-carrier-test.sh [image]
#   LAB names the containers (<LAB>-a, -b, -cap, -mitm), the network and the
#   data directory; SUBNET is the lab /24 (a non-default LAB gets its own,
#   see lab-env.sh). PFX/NETBASE are accepted as aliases.
set -e

IMG=${1:-tincstack/core:${TINCSTACK_TAG:-ws-l}}
TOOLS=nicolaka/netshoot
DEFAULT_LAB=wslh; DEFAULT_SUBNET=10.42.9
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"
# LAB/SUBNET (lab-env.sh, the convention of every proof here) feed the names
# below; PFX/NETBASE are accepted as aliases for compatibility.
PFX=${PFX:-$LAB}
NETBASE=${NETBASE:-$SUBNET}
NET=${PFX}https
BASE=/tmp/${PFX}-https
A_IP=$NETBASE.10
B_IP=$NETBASE.11
A_VPN=10.192.0.1
B_VPN=10.192.0.2
MITM_IP=$NETBASE.30

cleanup() {
	docker rm -f ${PFX}-a ${PFX}-b ${PFX}-cap ${PFX}-mitm >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -rf "$BASE-a" "$BASE-b"
mkdir -p "$BASE-a" "$BASE-b"
docker network create --subnet "$NETBASE.0/24" "$NET" >/dev/null

fail=0
note() { echo "  $1"; }
miss() { echo "  MISS: $1"; fail=1; }

# B is the rendezvous (public Port 655). A dials B, preferring https. A's
# reconnect backoff is capped at 10 s (MaxTimeout) so the L-2 cases below,
# which need several consecutive re-dials, run in seconds, not minutes.
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
      MaxTimeout: 10
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
	docker run -d --name "${PFX}-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN \
		--device /dev/net/tun -v "$3":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n wsg1 -D -d3 >/dev/null
}
setvpn() { # name vpnip
	docker exec "${PFX}-$1" ip addr add "$2/24" dev wsg1 2>/dev/null || true
	docker exec "${PFX}-$1" ip link set wsg1 up
}

echo "===== https carrier: bring up the tunnel ====="
start b "$B_IP" "$BASE-b"
sleep 2
# capture on B's tinc port for the whole bring-up + ping
docker run -d --name ${PFX}-cap --net container:${PFX}-b --cap-add NET_RAW "$TOOLS" \
	tcpdump -n -l -A -i eth0 'port 655' >/dev/null 2>&1
start a "$A_IP" "$BASE-a"
sleep 6
setvpn b "$B_VPN"
setvpn a "$A_VPN"
sleep 2

ping_ab=$(docker exec ${PFX}-a ping -c3 -W2 "$B_VPN" 2>&1 | tail -2)
ping_ba=$(docker exec ${PFX}-b ping -c3 -W2 "$A_VPN" 2>&1 | tail -2)
echo "$ping_ab" | grep -q "0% packet loss" && note "A -> B ping over the tunnel works" || miss "A -> B ping failed"
echo "$ping_ba" | grep -q "0% packet loss" && note "B -> A ping over the tunnel works" || miss "B -> A ping failed"

# `tinc dump connections' must show the https carrier on both ends.
dca=$(docker exec ${PFX}-a tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump connections 2>/dev/null || true)
dcb=$(docker exec ${PFX}-b tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump connections 2>/dev/null || true)
echo "$dca" | grep -q "transport https" && note "A dump connections shows transport https" || miss "A does not show transport https"
echo "$dcb" | grep -q "transport https" && note "B dump connections shows transport https" || miss "B does not show transport https"

echo "===== prober during the session gets the decoy ====="
pr=$(docker run --rm --net container:${PFX}-b "$TOOLS" curl -sk https://127.0.0.1:655/ || true)
echo "$pr" | grep -qi "It works" && note "a TLS prober during the session got the decoy" || miss "prober did not get the decoy"

echo "===== forged / replayed authenticator gets the decoy ====="
# A syntactically plausible but forged authenticator (random cookie). The server
# cannot verify it -> it serves the decoy, identical to any other prober. Sent
# twice (replay): both get the decoy, never a 101.
FORGED="AQdub2RlYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
r1=$(docker run --rm --net container:${PFX}-b "$TOOLS" \
	curl -sk -D - -o /dev/null https://127.0.0.1:655/ws \
	-H "Upgrade: websocket" -H "Connection: Upgrade" \
	-H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
	-H "Cookie: sid=$FORGED" 2>&1 | head -1 || true)
r2=$(docker run --rm --net container:${PFX}-b "$TOOLS" \
	curl -sk -D - -o /dev/null https://127.0.0.1:655/ws \
	-H "Upgrade: websocket" -H "Connection: Upgrade" \
	-H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
	-H "Cookie: sid=$FORGED" 2>&1 | head -1 || true)
echo "  forged attempt 1: $r1"
echo "  replayed attempt: $r2"
echo "$r1" | grep -q "101" && miss "forged authenticator was accepted (101)!" || note "forged authenticator got the decoy (no 101)"
echo "$r2" | grep -q "101" && miss "replayed authenticator was accepted (101)!" || note "replayed authenticator got the decoy (no 101)"

# The wire proof above is judged on the capture up to here: the review-R
# sections below reload B (which closes and re-dials the link) and dial
# through a bump, which is out of scope for the TLS-only check.
docker stop ${PFX}-cap >/dev/null 2>&1

echo "===== M5-1: black-holed upstream at B must not stall B's loop ====="
# $NETBASE.250 has no host: B's upstream connect never completes. Three TLS
# probes hit B while A pings B through the tunnel. Before the fix each probe
# blocked B's event loop for 3 s (connect + recv timeouts): RTT in seconds
# and lost pings; after it the fetch is asynchronous.
docker exec ${PFX}-b sh -c "sed -i 's/      AddressPool:/      HttpsDecoyUpstream: $NETBASE.250:80\n      AddressPool:/' /etc/tincstack/tinc.yaml"
docker exec ${PFX}-b tinc -c /etc/tincstack/tinc.yaml -n wsg1 reload >/dev/null 2>&1 || true
# In YAML mode a reload sees every host record as changed and closes the
# link; wait for A to re-establish it before measuring.
deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
	docker exec ${PFX}-a ping -c1 -W1 "$B_VPN" >/dev/null 2>&1 && break
	sleep 1
done
note "after B's reload A reconnected: $(docker exec ${PFX}-a tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump connections 2>/dev/null | grep nodeb | grep -o 'transport [a-z]*')"
for n in a b; do
	[ "$(docker inspect -f '{{.State.Running}}' ${PFX}-$n 2>/dev/null)" = true ] || { miss "node $n is not running before the M5-1 probes"; docker logs --tail 5 ${PFX}-$n 2>&1 | sed 's/^/    /'; }
done
(for _ in 1 2 3; do docker run --rm --net container:${PFX}-b "$TOOLS" curl -sk --max-time 10 -o /dev/null https://127.0.0.1:655/ >/dev/null 2>&1; done) &
sleep 0.3
pp=$(docker exec ${PFX}-a ping -c 12 -i 0.5 -W 3 "$B_VPN" 2>&1 | tail -2)
wait
echo "$pp" | sed 's/^/    /'
for n in a b; do
	[ "$(docker inspect -f '{{.State.Running}}' ${PFX}-$n 2>/dev/null)" = true ] || { miss "node $n died during the M5-1 probes"; docker logs --tail 8 ${PFX}-$n 2>&1 | sed 's/^/    /'; }
done
pmax=$(echo "$pp" | grep -o 'rtt.*' | awk -F'/' '{print $6}')
ploss=$(echo "$pp" | sed -n 's/.* \([0-9]*\)\(\.[0-9]*\)\{0,1\}% packet loss.*/\1/p')
note "ping A->B during three probes against the black-holed upstream: loss ${ploss:-?}%, max RTT ${pmax:-?} ms"
if [ "${ploss:-100}" = 0 ] && awk "BEGIN{exit !(${pmax:-99999} < 500)}"; then
	note "M5-1: tunnel latency unaffected by decoy upstream probes"
else
	miss "M5-1: probes against the black-holed upstream stalled the tunnel (loss ${ploss:-?}%, max ${pmax:-?} ms)"
fi

echo "===== L-2: an activated https link that drops must come back as https ====="
# Review row L-2. A dropped *activated* link is a plain reconnect that starts
# the carrier walk from the first preference again; only failures *before*
# activation advance it, and the carrier that last activated is given
# TRANSPORT_STICKY_FAILURES (3) consecutive such failures before it is
# abandoned (docs/transports.md §2). Before the fix one refused re-dial
# (B still restarting) was enough: `Carrier https failed for nodeb, falling
# back to plain', and A stayed on plain.
carrier_of_a() { docker exec ${PFX}-a tinc -c /etc/tincstack/tinc.yaml -n wsg1 dump connections 2>/dev/null | grep nodeb | grep -o 'transport [a-z]*'; }
closes_of_a() { docker logs ${PFX}-a 2>&1 | grep -c "Closing connection with nodeb" || true; }
alog_has() { docker logs ${PFX}-a 2>&1 | grep -q "$1"; }
wait_for() { # deadline-s command...: poll until the command succeeds
	deadline=$(( $(date +%s) + $1 )); shift
	while [ "$(date +%s)" -lt "$deadline" ]; do
		"$@" && return 0
		sleep 1
	done
	return 1
}
closed_since() { [ "$(closes_of_a)" -gt "$1" ]; }
tunnel_up() { docker exec ${PFX}-a ping -c1 -W1 "$B_VPN" >/dev/null 2>&1; }
l2_check() { # label expected-carrier
	if wait_for 60 tunnel_up && [ "$(carrier_of_a)" = "transport $2" ]; then
		pl=$(docker exec ${PFX}-a ping -c5 -i0.2 -W2 "$B_VPN" 2>&1 | grep -o '[0-9]*% packet loss')
		[ "$pl" = "0% packet loss" ] && note "L-2 $1: A is back on $2, tunnel $pl" || miss "L-2 $1: back on $2 but tunnel loss: $pl"
	else
		miss "L-2 $1: A reconnected over '$(carrier_of_a)' (expected $2); log: $(docker logs ${PFX}-a 2>&1 | grep -E 'Carrier|via ' | tail -4 | tr '\n' '|')"
	fi
}

# (1) reload: B closes the activated link cleanly.
c0=$(closes_of_a)
docker exec ${PFX}-b tinc -c /etc/tincstack/tinc.yaml -n wsg1 reload >/dev/null 2>&1 || true
wait_for 20 closed_since "$c0" || miss "L-2 reload: B's reload did not drop A's link"
l2_check "reload" https

# (2) TCP reset: B's kernel socket is destroyed, A sees a RST.
c0=$(closes_of_a)
docker run --rm --net container:${PFX}-b --cap-add NET_ADMIN "$TOOLS" ss -K -t dst "$A_IP" >/dev/null 2>&1 || true
wait_for 20 closed_since "$c0" || miss "L-2 reset: ss -K did not drop A's link (kernel without INET_DIAG_DESTROY?)"
l2_check "TCP reset" https

# (3) kill -9: B's daemon dies and stays down until A's first re-dial has
# been refused, which before the fix was the downgrade to plain.
c0=$(closes_of_a)
docker kill -s KILL ${PFX}-b >/dev/null
wait_for 20 closed_since "$c0" || miss "L-2 kill: A did not notice B's death"
if wait_for 30 alog_has "Carrier https failed for nodeb before activation (1/3) but worked before, retrying it"; then
	note "L-2 kill: A log: $(docker logs ${PFX}-a 2>&1 | grep 'before activation (1/3)' | tail -1 | sed 's/.*Carrier/Carrier/')"
else
	miss "L-2 kill: A did not retry https after the refused re-dial: $(docker logs ${PFX}-a 2>&1 | grep -E 'Carrier|refused' | tail -3 | tr '\n' '|')"
fi
docker start ${PFX}-b >/dev/null
l2_check "kill -9 + restart" https

# (4) three refused re-dials in a row: only then does A fall back to plain
# (B is kept down until A logs that), and once the plain link is dropped
# again A starts from https, not from plain.
c0=$(closes_of_a)
docker kill -s KILL ${PFX}-b >/dev/null
wait_for 20 closed_since "$c0" || miss "L-2 3x: A did not notice B's death"
if wait_for 90 alog_has "Carrier https failed 3 times in a row for nodeb, no longer preferred"; then
	note "L-2 3x: A log: $(docker logs ${PFX}-a 2>&1 | grep -E 'no longer preferred|falling back' | tail -2 | sed 's/.*Carrier/Carrier/' | tr '\n' '|')"
else
	miss "L-2 3x: A never gave https up after three refused dials: $(docker logs ${PFX}-a 2>&1 | grep -E 'Carrier' | tail -4 | tr '\n' '|')"
fi
docker start ${PFX}-b >/dev/null
l2_check "after three refused https dials" plain
c0=$(closes_of_a)
docker exec ${PFX}-b tinc -c /etc/tincstack/tinc.yaml -n wsg1 reload >/dev/null 2>&1 || true
wait_for 20 closed_since "$c0" || miss "L-2 3x: B's reload did not drop the plain link"
l2_check "plain link dropped, walk restarts from the preference" https

echo "===== M5-7: a TLS bump on A's first dial must not leave a pin ====="
b_fp=$(python3 - "$BASE-b/tinc.yaml" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
m = re.search(r'      nodeb: \|\n((?:        .*\n)+)', s)
fp = re.search(r'TlsFingerprint = ([0-9a-fA-F]+)', m.group(1))
print(fp.group(1).lower() if fp else "")
PY
)
# Reset A: no pin for nodeb, Address -> the given one, and no cached address
# (tinc dials the address cache before the host record's Address).
unpin_a() { # address
	rm -f "$BASE-a"/wsg1/cache/nodeb
	python3 - "$BASE-a/tinc.yaml" "$1" <<'PY'
import re, sys
path, addr = sys.argv[1:3]
s = open(path).read()
def fix(m):
    lines = [l for l in m.group(1).split('\n') if l.strip() and 'TlsFingerprint' not in l]
    lines = [re.sub(r'Address = .*', 'Address = ' + addr, l) for l in lines]
    return '      nodeb: |\n' + '\n'.join(lines) + '\n'
s = re.sub(r'      nodeb: \|\n((?:        .*\n)+)', fix, s, count=1)
open(path, 'w').write(s)
PY
}
pin_of_a() {
	python3 - "$BASE-a/tinc.yaml" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
m = re.search(r'      nodeb: \|\n((?:        .*\n)+)', s)
fps = re.findall(r'TlsFingerprint = ([0-9a-fA-F]+)', m.group(1)) if m else []
print(' '.join(f.lower() for f in fps))
PY
}
docker rm -f ${PFX}-a >/dev/null 2>&1 || true
unpin_a "$MITM_IP"
# The bump: its own P-256 certificate, re-encrypts towards B.
docker run -d --name ${PFX}-mitm --network "$NET" --ip "$MITM_IP" "$TOOLS" sh -c "
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /tmp/k.pem -out /tmp/c.pem -subj /CN=localhost -days 1 >/dev/null 2>&1
	cat /tmp/c.pem /tmp/k.pem > /tmp/mitm.pem
	openssl x509 -in /tmp/c.pem -noout -fingerprint -sha256 | sed 's/.*=//;s/://g' | tr 'A-F' 'a-f' > /tmp/mitm.fp
	exec socat openssl-listen:655,reuseaddr,fork,cert=/tmp/mitm.pem,verify=0 openssl-connect:$B_IP:655,verify=0" >/dev/null
sleep 2
mitm_fp=$(docker exec ${PFX}-mitm cat /tmp/mitm.fp 2>/dev/null || true)
start a "$A_IP" "$BASE-a"
# Give A time for at least two dial attempts through the bump.
deadline=$(( $(date +%s) + 15 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
	docker logs ${PFX}-a 2>&1 | grep -q "falling back to plain" && break
	sleep 1
done
pins=$(pin_of_a)
note "MITM cert fingerprint: ${mitm_fp:-?}"
note "A's pins for nodeb after dialling through the bump: '${pins:-none}'"
if [ -z "$pins" ]; then
	note "M5-7: no TlsFingerprint pinned from the unauthenticated (bumped) dial"
elif echo "$pins" | grep -q "$mitm_fp"; then
	miss "M5-7: A pinned the MITM's certificate on first contact"
else
	miss "M5-7: A pinned an unexpected fingerprint: $pins"
fi
docker logs ${PFX}-a 2>&1 | grep -q "https: authenticated\|transport https" && miss "M5-7: A established https through the bump?!" || note "M5-7: https through the bump failed (no 101), as it must"

echo "===== M5-7: a legitimate first dial pins B's real fingerprint ====="
docker rm -f ${PFX}-a ${PFX}-mitm >/dev/null 2>&1 || true
unpin_a "$B_IP"
start a "$A_IP" "$BASE-a"
deadline=$(( $(date +%s) + 20 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
	docker logs ${PFX}-a 2>&1 | grep -q "pinning TlsFingerprint" && break
	sleep 1
done
sleep 1
pins=$(pin_of_a)
note "B's real fingerprint: $b_fp"
note "A's pins for nodeb after a legitimate first dial: '${pins:-none}'"
if [ "$pins" = "$b_fp" ]; then
	note "M5-7: pinned exactly B's fingerprint, once, after SPTPS authenticated B"
else
	miss "M5-7: expected pin '$b_fp', got '${pins:-none}'"
fi
docker logs ${PFX}-a 2>&1 | grep "SPTPS authenticated .* pinning" | head -1 | sed 's/^/    /'
setvpn a "$A_VPN"
sleep 1
docker exec ${PFX}-a ping -c2 -W2 "$B_VPN" 2>&1 | grep -q "0% packet loss" && note "M5-7: tunnel up over https after the pin" || miss "M5-7: tunnel not up after the legitimate dial"

echo "===== tcpdump: only TLS, no UDP, no cleartext tinc ID ====="
cap=$(docker logs ${PFX}-cap 2>&1)
docker rm -f ${PFX}-cap >/dev/null 2>&1

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

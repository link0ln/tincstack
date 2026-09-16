#!/bin/sh
# quic-carrier-test.sh -- prove the M5 `quic' carrier (PLAN M5, stream G3).
#
#   (a) two nodes, A `PreferredTransports: [quic, plain]', B default: ping both
#       ways 0% loss; `dump connections' shows quic on both; tcpdump on the
#       port shows only QUIC (long header first, then short headers), no
#       SPTPS-shaped datagrams, no TCP meta connection;
#   (b) NAT rebind: the SNAT port of A's datagrams is flipped mid-session
#       -> B logs path validation, no re-handshake, ping keeps working;
#   (c) fallback: B `Transports: [plain]', B built without QUIC, and UDP to B
#       blocked -> A ends up on plain and the tunnel still carries traffic;
#   (d) a wrong-key dialler's authenticator is rejected and it falls back;
#   (f) relay A-R-B with A-R on quic and R-B on plain, A<->B DROP'd.
#   (l) review L-2: an *activated* quic link dropped by B's reload, by a UDP
#       black-hole and by B's daemon being killed and kept down until A's
#       first re-dial failed comes back as quic each time, never plain.
#
# All tooling runs in throwaway containers (nicolaka/netshoot for tcpdump and
# the NAT gateway); nothing is installed on the host. Data under /tmp/<PFX>-quic-*.
#
# Usage: [ONLY="a b"] [LAB=wsg3q] [SUBNET=10.44.9] testing/transports/quic-carrier-test.sh [image] [image-without-quic]
#   The images default to tincstack/core:${TINCSTACK_TAG} and ...-noquic; PFX
#   names the containers, network and data directory and NETBASE is the lab
#   /24, so two copies of this lab can run side by side on one host.
set -e
[ -n "$QUIC_TRACE" ] && set -x

IMG=${1:-tincstack/core:${TINCSTACK_TAG:-ws-g3}}
IMG_NOQUIC=${2:-${IMG}-noquic}
TOOLS=nicolaka/netshoot
DEFAULT_LAB=wsg3q; DEFAULT_SUBNET=10.44.9
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"
# LAB/SUBNET (lab-env.sh, the convention of every proof here) feed the names
# below; PFX/NETBASE are accepted as aliases for compatibility.
PFX=${PFX:-$LAB}
NETBASE=${NETBASE:-$SUBNET}
BASE=/tmp/${PFX}-quic
NET=${PFX}net

A_IP=$NETBASE.10
B_IP=$NETBASE.11
R_IP=$NETBASE.12
A_VPN=10.193.0.1
B_VPN=10.193.0.2
R_VPN=10.193.0.3

fail=0
note() { echo "  $1"; }
miss() { echo "  MISS: $1"; fail=1; }

cleanup() {
	docker rm -f ${PFX}-a ${PFX}-b ${PFX}-r ${PFX}-gw ${PFX}-cap >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
[ -z "$KEEP" ] && trap cleanup EXIT
cleanup
rm -rf "$BASE"-*
mkdir -p "$BASE-a" "$BASE-b" "$BASE-r" "$BASE-x"
docker network create --subnet "$NETBASE.0/24" "$NET" >/dev/null

# --- configs ----------------------------------------------------------------
writecfg() { # dir name extra-yaml-lines...
	d=$1
	n=$2
	shift 2
	{
		echo "networks:"
		echo "  wsg3:"
		echo "    options:"
		echo "      Name: $n"
		echo "      Mode: router"
		echo "      Port: 655"
		echo "      PingTimeout: 5"
		echo "      AddressPool: 10.193.0.0/24"
		for l in "$@"; do echo "      $l"; done
	} > "$d/tinc.yaml"
}

writecfg "$BASE-b" nodeb
writecfg "$BASE-r" noder
writecfg "$BASE-a" nodea "PreferredTransports: [quic, plain]" "ConnectTo: [nodeb]"
writecfg "$BASE-x" nodex

# Materialise keys, cert, TlsFingerprint and the Transports line.
for d in a b r x; do
	timeout 3 docker run --rm -v "$BASE-$d":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n wsg3 -D -d1 >/dev/null 2>&1 || true
done

# Save pristine copies; the scenarios below re-derive from them.
for d in a b r x; do cp "$BASE-$d/tinc.yaml" "$BASE-$d/pristine.yaml"; done

# merge <dst-dir> <dst-name> <src-dir> <src-name> <src-ip> <src-vpn> [own-vpn]
#   inject <src-name>'s host block (with Address/Port and a fixed Subnet) into
#   <dst>'s YAML, and fix <dst>'s own Subnet when own-vpn is given.
merge() {
	python3 - "$@" <<'PYEOF'
import re, sys
dst, dname, src, sname, sip, svpn = sys.argv[1:7]
ownvpn = sys.argv[7] if len(sys.argv) > 7 else None
dpath, spath = dst + '/tinc.yaml', src + '/pristine.yaml'

def block(path, name):
    s = open(path).read()
    m = re.search(r'^      %s: \|\n((?:(?:        .*)?\n)+)' % re.escape(name), s, re.M)
    lines = [l[8:] for l in m.group(1).split('\n') if l.startswith('        ')]
    return [l for l in lines if l.strip()]

sb = ['Address = ' + sip, 'Port = 655'] + \
     [re.sub(r'Subnet = .*', 'Subnet = %s/32' % svpn, l) for l in block(spath, sname)
      if not l.startswith(('Address', 'Port'))]

s = open(dpath).read()
if ownvpn:
    s = re.sub(r'(%s: \|\n(?:        .*\n)*?        Subnet = )[^\n]*' % dname,
               lambda m: m.group(1) + '%s/32' % ownvpn, s)
if '      %s: |' % sname not in s:
    s = s.replace('    hosts:\n', '    hosts:\n      %s: |\n' % sname +
                  ''.join('        ' + l + '\n' for l in sb), 1)
open(dpath, 'w').write(s)
PYEOF
}

reset_cfgs() { for d in a b r x; do cp "$BASE-$d/pristine.yaml" "$BASE-$d/tinc.yaml"; done; }

start() { # name ip dir [image]
	img=${4:-$IMG}
	docker run -d --name "${PFX}-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN \
		--device /dev/net/tun -v "$3":/etc/tincstack "$img" \
		tincd -c /etc/tincstack/tinc.yaml -n wsg3 -D -d3 >/dev/null
}
setvpn() { docker exec "${PFX}-$1" ip addr add "$2/24" dev wsg3 2>/dev/null || true; docker exec "${PFX}-$1" ip link set wsg3 up; }
dumpc() { docker exec "${PFX}-$1" tinc -c /etc/tincstack/tinc.yaml -n wsg3 dump connections 2>/dev/null || true; }
pingok() { docker exec "${PFX}-$1" ping -c3 -W2 "$2" 2>&1 | tail -2 | grep -q "0% packet loss"; }
waitping() { # name target tries
	i=0
	while [ $i -lt "$3" ]; do
		if pingok "$1" "$2"; then return 0; fi
		i=$((i + 1))
	done
	return 1
}
stopall() { [ -n "$KEEP" ] && { echo "KEEP set: leaving containers up"; exit 0; }; docker rm -f ${PFX}-a ${PFX}-b ${PFX}-r ${PFX}-gw ${PFX}-cap >/dev/null 2>&1 || true; }

sec_a() {
# ============================================================================
echo "===== (a) quic-negotiated link: A prefers quic, B default ====="
reset_cfgs
merge "$BASE-a" nodea "$BASE-b" nodeb "$B_IP" "$B_VPN" "$A_VPN"
merge "$BASE-b" nodeb "$BASE-a" nodea "$A_IP" "$A_VPN" "$B_VPN"
grep -q "quic" "$BASE-b/tinc.yaml" && note "B's own host record advertises quic (zeroconf default list)" || miss "B does not advertise quic"

start b "$B_IP" "$BASE-b"
sleep 2
docker run -d --name ${PFX}-cap --net container:${PFX}-b --cap-add NET_RAW "$TOOLS" \
	tcpdump -n -l -x -i eth0 'port 655' >/dev/null 2>&1
start a "$A_IP" "$BASE-a"
sleep 6
setvpn b "$B_VPN"
setvpn a "$A_VPN"
sleep 2

waitping a "$B_VPN" 3 && note "A -> B ping 0% loss" || miss "A -> B ping failed"
waitping b "$A_VPN" 3 && note "B -> A ping 0% loss" || miss "B -> A ping failed"
docker exec ${PFX}-a ping -c40 -i0.1 -W2 "$B_VPN" >/dev/null 2>&1 || true
sleep 1

dumpc a | grep -q "transport quic" && note "A dump connections: transport quic" || miss "A dump connections lacks quic: $(dumpc a)"
dumpc b | grep -q "transport quic" && note "B dump connections: transport quic" || miss "B dump connections lacks quic: $(dumpc b)"
docker exec ${PFX}-b tinc -c /etc/tincstack/tinc.yaml -n wsg3 info nodea 2>/dev/null | grep -q "Transports:.*quic" \
	&& note "tinc info nodea on B lists quic in Transports" || miss "tinc info does not list quic"
docker logs ${PFX}-a 2>&1 | grep -q "Dialling nodeb .* via quic" && note "A log: Dialling nodeb via quic" || miss "A never dialled quic"
docker logs ${PFX}-b 2>&1 | grep -q "quic: authenticated peer nodea" && note "B log: quic: authenticated peer nodea" || miss "B did not authenticate A over quic"

docker stop ${PFX}-cap >/dev/null 2>&1
docker logs ${PFX}-cap > "$BASE-cap.txt" 2>&1
docker rm -f ${PFX}-cap >/dev/null 2>&1

if python3 - "$BASE-cap.txt" <<'PYEOF'
import re, sys
lines = open(sys.argv[1], errors='replace').read().split('\n')
pkts, cur, hdr = [], [], None
for l in lines:
    if l and not l.startswith('\t') and not l.startswith(' '):
        if hdr is not None: pkts.append((hdr, cur))
        cur, hdr = [], l
    else:
        m = re.match(r'\s*0x[0-9a-f]{4}:\s+((?:[0-9a-f]{4} ?)+)', l)
        if m: cur.extend(m.group(1).split())
if hdr is not None: pkts.append((hdr, cur))
tcp = [h for h, _ in pkts if 'Flags [' in h]
synack = sum(1 for h in tcp if 'Flags [S.]' in h)
tcpdata = sum(1 for h in tcp if 'length 0' not in h)
udp = [c for h, c in pkts if 'UDP' in h]
first = []
for c in udp:
    hexs = ''.join(c)
    if len(hexs) < 58: continue
    first.append(int(hexs[56:58], 16))   # byte 28: after IPv4(20)+UDP(8)
longh = sum(1 for b in first if b & 0xc0 == 0xc0)
shorth = sum(1 for b in first if b & 0xc0 == 0x40)
nofixed = sum(1 for b in first if not (b & 0x40))
seq = ''.join('L' if b & 0xc0 == 0xc0 else 'S' if b & 0xc0 == 0x40 else '?' for b in first)
print("  capture: %d UDP datagrams; TCP on port 655: %d segments, %d SYN-ACK, %d with payload (tinc's autoconnect SYN before the peer is up is RST'd)" % (len(first), len(tcp), synack, tcpdata))
print("  QUIC long headers: %d, short headers: %d, fixed bit clear (SPTPS-shaped): %d" % (longh, shorth, nofixed))
print("  header sequence (L=long S=short): %s%s" % (seq[:60], '...' if len(seq) > 60 else ''))
ok = synack == 0 and tcpdata == 0 and nofixed == 0 and longh >= 2 and shorth >= 40 and seq.startswith('L')
sys.exit(0 if ok else 1)
PYEOF
then note "wire: QUIC only (Initial long headers first, then short), no TCP connection established, no SPTPS-shaped datagram"; else miss "wire capture is not QUIC-only"; fi
stopall
}

sec_b() {
echo "===== (b) NAT rebind: A's source port flipped mid-session ====="
# The NAT lives in A's own network namespace: an SNAT rule rewrites the
# source port of A's datagrams to B (conntrack un-translates the replies), so
# from B's side this is exactly a NAT whose mapping changes mid-session. The
# tooling (iptables, conntrack) runs from netshoot sharing A's netns.
reset_cfgs
merge "$BASE-a" nodea "$BASE-b" nodeb "$B_IP" "$B_VPN" "$A_VPN"
merge "$BASE-b" nodeb "$BASE-a" nodea "$A_IP" "$A_VPN" "$B_VPN"
# B must not dial A first (its autoconnect would pick plain): B only listens.
sed -i 's/^      AddressPool:/      AutoConnect: no\n      AddressPool:/' "$BASE-b/tinc.yaml"
nat() { docker run --rm --net container:${PFX}-a --cap-add NET_ADMIN "$TOOLS" "$@"; }

start b "$B_IP" "$BASE-b"
sleep 2
docker run -d --name ${PFX}-a --network "$NET" --ip "$A_IP" --cap-add NET_ADMIN --device /dev/net/tun \
	-v "$BASE-a":/etc/tincstack "$IMG" sleep 3600 >/dev/null
nat iptables -t nat -A POSTROUTING -p udp -d "$B_IP" -j SNAT --to-source "$A_IP:40000-40000"
docker exec -d ${PFX}-a tincd -c /etc/tincstack/tinc.yaml -n wsg3 -D -d3 --logfile=/etc/tincstack/a.log
sleep 6
setvpn b "$B_VPN"
setvpn a "$A_VPN"
sleep 2
waitping a "$B_VPN" 3 && note "tunnel up behind the NAT (A -> B 0% loss)" || miss "no tunnel through the NAT"
dumpc b | grep nodea | grep -q "transport quic" && note "B dump connections: $(dumpc b | grep nodea | sed 's/ options.*transport/ transport/')" \
	|| miss "B is not on quic: $(dumpc b | grep nodea); B log: $(docker logs ${PFX}-b 2>&1 | grep -iE 'quic|nodea' | tail -5 | tr '\n' '|')"
dumpc b | grep nodea | grep -q "port 40000" && note "B sees A's mapped port 40000" || miss "B does not see port 40000"
hs1=$(docker logs ${PFX}-b 2>&1 | grep -c "quic: connection from" || true)

# Flip the mapping: same flow, new source port. conntrack is flushed so the
# very next datagram leaves with the new port -- a NAT rebind as B sees it.
nat iptables -t nat -R POSTROUTING 1 -p udp -d "$B_IP" -j SNAT --to-source "$A_IP:40001-40001"
nat conntrack -F >/dev/null 2>&1 || true
note "NAT mapping flipped 40000 -> 40001, conntrack flushed"
sleep 1
docker exec ${PFX}-a ping -c5 -i0.2 -W2 "$B_VPN" >/dev/null 2>&1 || true
sleep 2
waitping a "$B_VPN" 3 && note "A -> B ping still 0% loss after the rebind" || miss "ping broke after the rebind"
waitping b "$A_VPN" 3 && note "B -> A ping still 0% loss after the rebind" || miss "reverse ping broke after the rebind"
docker logs ${PFX}-b 2>&1 | grep "quic: path validated" | tail -1 | grep -q "40001" \
	&& note "B log: $(docker logs ${PFX}-b 2>&1 | grep 'quic: path validated' | tail -1 | sed 's/.*quic:/quic:/')" \
	|| miss "B did not log path validation to port 40001: $(docker logs ${PFX}-b 2>&1 | grep -i 'path' | tail -3)"
hs2=$(docker logs ${PFX}-b 2>&1 | grep -c "quic: connection from" || true)
[ "$hs1" = "$hs2" ] && [ "$hs2" -ge 1 ] && note "no re-handshake (B saw $hs2 QUIC connection before and after)" || miss "B re-handshook ($hs1 -> $hs2 connections)"
dumpc b | grep nodea | grep -q "port 40001" && note "B dump connections: nodea now at port 40001" || miss "B's connection address did not follow: $(dumpc b | grep nodea)"
grep -q "Dialling nodeb" "$BASE-a/a.log" && ! grep -q "falling back" "$BASE-a/a.log" && note "A never fell back or re-dialled" || miss "A re-dialled: $(grep -iE 'carrier|Dialling' "$BASE-a/a.log" | tr '\n' '|')"
stopall
}

sec_c() {
# ============================================================================
echo "===== (c) fallback: peer without quic (config / build / blocked UDP) ====="
for case in accept build blocked; do
	reset_cfgs
	merge "$BASE-a" nodea "$BASE-b" nodeb "$B_IP" "$B_VPN" "$A_VPN"
	merge "$BASE-b" nodeb "$BASE-a" nodea "$A_IP" "$A_VPN" "$B_VPN"
	bimg=$IMG
	case $case in
	accept)
		sed -i 's/^      AddressPool:/      Transports: [plain]\n      AddressPool:/' "$BASE-b/tinc.yaml"
		sed -i 's/Transports = plain, sf, obfs, https, quic/Transports = plain/' "$BASE-a/tinc.yaml"
		label="B config Transports: [plain]" ;;
	build)
		bimg=$IMG_NOQUIC
		sed -i 's/Transports = plain, sf, obfs, https, quic/Transports = plain, sf, obfs, https/' "$BASE-a/tinc.yaml"
		label="B built without QUIC ($IMG_NOQUIC)" ;;
	blocked)
		label="UDP to B's port DROP'd (QUIC handshake times out)" ;;
	esac

	start b "$B_IP" "$BASE-b" "$bimg"
	sleep 2
	[ $case = blocked ] && docker exec ${PFX}-b iptables -A INPUT -p udp --dport 655 -j DROP
	start a "$A_IP" "$BASE-a"
	[ $case = blocked ] && sleep 10 || sleep 5
	setvpn b "$B_VPN"
	setvpn a "$A_VPN"
	sleep 2
	echo "  -- $label"
	waitping a "$B_VPN" 4 && note "tunnel up, A -> B 0% loss" || miss "$case: no tunnel"
	dumpc a | grep nodeb | grep -q "transport plain" && note "A dump connections: transport plain" || miss "$case: A not on plain: $(dumpc a)"
	case $case in
	blocked)
		docker logs ${PFX}-a 2>&1 | grep -q "Carrier quic failed for nodeb, falling back to plain" \
			&& note "A log: Carrier quic failed for nodeb, falling back to plain (M4 fallback)" || miss "$case: no fallback line in A's log" ;;
	*)
		docker logs ${PFX}-a 2>&1 | grep -q "Carrier candidates for nodeb: plain" \
			&& note "A log: Carrier candidates for nodeb: plain (quic not in B's accept list)" || miss "$case: A did not exclude quic: $(docker logs ${PFX}-a 2>&1 | grep 'Carrier candidates')" ;;
	esac
	stopall
done
}

sec_d() {
# ============================================================================
echo "===== (d) wrong-key dialler: authenticator rejected, dialler falls back ====="
reset_cfgs
merge "$BASE-a" nodea "$BASE-b" nodeb "$B_IP" "$B_VPN" "$A_VPN"
merge "$BASE-b" nodeb "$BASE-a" nodea "$A_IP" "$A_VPN" "$B_VPN"
# A keeps its name but runs with nodex's Ed25519 key: B's host DB has nodea's
# real key, so the authenticator signature fails.
python3 - "$BASE-a/tinc.yaml" "$BASE-x/pristine.yaml" <<'PYEOF'
import re, sys
a = open(sys.argv[1]).read(); x = open(sys.argv[2]).read()
kx = re.search(r'      ed25519_priv: \|\n((?:        .*\n)+)', x).group(1)
a = re.sub(r'(      ed25519_priv: \|\n)(?:        .*\n)+', lambda m: m.group(1) + kx, a, count=1)
open(sys.argv[1], 'w').write(a)
PYEOF
start b "$B_IP" "$BASE-b"
sleep 2
start a "$A_IP" "$BASE-a"
sleep 8
docker logs ${PFX}-b 2>&1 | grep -q "quic: authenticator from .* rejected" && note "B log: quic: authenticator from A rejected" || miss "B did not reject the wrong-key authenticator: $(docker logs ${PFX}-b 2>&1 | grep -i quic | tail -3)"
docker logs ${PFX}-b 2>&1 | grep -q "quic: authenticated peer" && miss "B authenticated a wrong-key peer!" || note "B never authenticated the wrong-key peer"
docker logs ${PFX}-a 2>&1 | grep -q "Carrier quic failed for nodeb, falling back to plain" && note "A log: Carrier quic failed for nodeb, falling back to plain" || miss "A did not fall back: $(docker logs ${PFX}-a 2>&1 | grep -i 'carrier\|quic' | tail -3)"
docker logs ${PFX}-a 2>&1 | grep -q "via plain" && note "A then dialled plain (which fails SPTPS auth too, as it must)" || miss "A never dialled plain"
docker logs ${PFX}-b 2>&1 | grep -qiE "tinc|sptps" || true
stopall
}

sec_f() {
# ============================================================================
echo "===== (f) relay A-R-B: A-R on quic, R-B on plain, A<->B severed ====="
reset_cfgs
writecfg "$BASE-a" nodea "PreferredTransports: [quic, plain]" "ConnectTo: [noder]"
writecfg "$BASE-b" nodeb "PreferredTransports: [plain]" "ConnectTo: [noder]"
# keep identities: put the pristine hosts/keys back under the new options
python3 - "$BASE" <<'PYEOF'
import re, sys
base = sys.argv[1]
for d in ('a', 'b'):
    new = open(f'{base}-{d}/tinc.yaml').read()
    old = open(f'{base}-{d}/pristine.yaml').read()
    tail = old[old.index('    hosts:'):]
    open(f'{base}-{d}/tinc.yaml', 'w').write(new + tail)
PYEOF
merge "$BASE-a" nodea "$BASE-r" noder "$R_IP" "$R_VPN" "$A_VPN"
merge "$BASE-b" nodeb "$BASE-r" noder "$R_IP" "$R_VPN" "$B_VPN"
merge "$BASE-r" noder "$BASE-a" nodea "$A_IP" "$A_VPN" "$R_VPN"
merge "$BASE-r" noder "$BASE-b" nodeb "$B_IP" "$B_VPN"
start r "$R_IP" "$BASE-r"
sleep 2
start a "$A_IP" "$BASE-a"
start b "$B_IP" "$BASE-b"
docker exec ${PFX}-a iptables -A INPUT  -s "$B_IP" -j DROP
docker exec ${PFX}-a iptables -A OUTPUT -d "$B_IP" -j DROP
docker exec ${PFX}-b iptables -A INPUT  -s "$A_IP" -j DROP
docker exec ${PFX}-b iptables -A OUTPUT -d "$A_IP" -j DROP
sleep 6
setvpn r "$R_VPN"
setvpn a "$A_VPN"
setvpn b "$B_VPN"
sleep 2
dumpc r | grep nodea | grep -q "transport quic" && note "R: A's link is quic" || miss "A-R not quic: $(dumpc r)"
dumpc r | grep nodeb | grep -q "transport plain" && note "R: B's link is plain" || miss "R-B not plain: $(dumpc r)"
waitping a "$R_VPN" 3 && note "A -> R over quic 0% loss" || miss "A -> R failed"
waitping a "$B_VPN" 10 && note "A -> B relayed through R (mixed quic/plain hops) 0% loss" || miss "A -> B relay failed"
waitping b "$A_VPN" 5 && note "B -> A relayed 0% loss" || miss "B -> A relay failed"
docker exec ${PFX}-a ping -c1 -W1 "$B_IP" >/dev/null 2>&1 && miss "A can reach B directly (DROP not effective)" || note "A <-> B direct path confirmed severed"
stopall
}

sec_l() {
# ============================================================================
echo "===== (l) review L-2: an activated quic link that drops comes back as quic ====="
# A dropped *activated* link is a plain reconnect that starts the carrier
# walk from the first preference again; only failures before activation
# advance it, and the carrier that last activated is abandoned only after
# three such failures in a row (docs/transports.md §2). B does not dial A
# itself (AutoConnect: no): the dialler chooses the carrier and B's own
# preference is plain, so a B-initiated link would say nothing about A's
# selection (that race is a separate, documented residual of L-2).
reset_cfgs
merge "$BASE-a" nodea "$BASE-b" nodeb "$B_IP" "$B_VPN" "$A_VPN"
merge "$BASE-b" nodeb "$BASE-a" nodea "$A_IP" "$A_VPN" "$B_VPN"
sed -i 's/^      AddressPool:/      AutoConnect: no\n      AddressPool:/' "$BASE-b/tinc.yaml"
# A pings B every 5 s so a black-holed UDP path is declared dead in ~10 s.
sed -i 's/^      AddressPool:/      PingInterval: 5\n      AddressPool:/' "$BASE-a/tinc.yaml"
closes_of_a() { docker logs ${PFX}-a 2>&1 | grep -c "Closing connection with nodeb" || true; }
closed_since() { [ "$(closes_of_a)" -gt "$1" ]; }
alog_has() { docker logs ${PFX}-a 2>&1 | grep -q "$1"; }
tunnel_up() { docker exec ${PFX}-a ping -c1 -W1 "$B_VPN" >/dev/null 2>&1; }
wait_for() { # deadline-s command...: poll until the command succeeds
	deadline=$(( $(date +%s) + $1 )); shift
	while [ "$(date +%s)" -lt "$deadline" ]; do
		"$@" && return 0
		sleep 1
	done
	return 1
}
l2_check() { # label
	if wait_for 60 tunnel_up && dumpc a | grep nodeb | grep -q "transport quic" && dumpc b | grep nodea | grep -q "transport quic"; then
		pl=$(docker exec ${PFX}-a ping -c5 -i0.2 -W2 "$B_VPN" 2>&1 | grep -o '[0-9]*% packet loss')
		[ "$pl" = "0% packet loss" ] && note "L-2 $1: A is back on quic (both ends), tunnel $pl" || miss "L-2 $1: back on quic but tunnel loss: $pl"
	else
		miss "L-2 $1: A reconnected over '$(dumpc a | grep nodeb | grep -o 'transport [a-z]*')' (expected quic); A log: $(docker logs ${PFX}-a 2>&1 | grep -E 'Carrier|via ' | tail -4 | tr '\n' '|')"
	fi
}

start b "$B_IP" "$BASE-b"
sleep 2
start a "$A_IP" "$BASE-a"
wait_for 20 alog_has "Connection with nodeb .* activated" || miss "L-2: no quic link to begin with"
setvpn b "$B_VPN"
setvpn a "$A_VPN"
waitping a "$B_VPN" 3 && dumpc a | grep nodeb | grep -q "transport quic" && note "L-2: tunnel up over quic" || miss "L-2: initial link is not quic: $(dumpc a)"

# (1) reload: B closes the activated link cleanly.
c0=$(closes_of_a)
docker exec ${PFX}-b tinc -c /etc/tincstack/tinc.yaml -n wsg3 reload >/dev/null 2>&1 || true
wait_for 20 closed_since "$c0" || miss "L-2 reload: B's reload did not drop A's link"
l2_check "reload"

# (2) UDP black-hole at B until A declares the link dead, then lifted.
c0=$(closes_of_a)
docker exec ${PFX}-b iptables -I INPUT -p udp -s "$A_IP" -j DROP
wait_for 60 closed_since "$c0" || miss "L-2 black-hole: A never declared the link dead"
docker exec ${PFX}-b iptables -D INPUT -p udp -s "$A_IP" -j DROP
l2_check "UDP black-hole"

# (3) kill -9: B's daemon dies and stays down until A's first re-dial has
# failed -- before the fix that single failure downgraded A to plain.
c0=$(closes_of_a)
docker kill -s KILL ${PFX}-b >/dev/null
wait_for 30 closed_since "$c0" || miss "L-2 kill: A did not notice B's death"
if wait_for 40 alog_has "Carrier quic failed for nodeb before activation (1/3) but worked before, retrying it"; then
	note "L-2 kill: A log: $(docker logs ${PFX}-a 2>&1 | grep 'before activation (1/3)' | tail -1 | sed 's/.*Carrier/Carrier/')"
else
	miss "L-2 kill: A did not retry quic after the failed re-dial: $(docker logs ${PFX}-a 2>&1 | grep -E 'Carrier' | tail -3 | tr '\n' '|')"
fi
docker start ${PFX}-b >/dev/null
l2_check "kill -9 + restart"
docker logs ${PFX}-a 2>&1 | grep -q "falling back to plain" && miss "L-2: A fell back to plain at some point" || note "L-2: A never fell back to plain"
stopall
}

for sec in ${ONLY:-a b c d f l}; do sec_$sec; done

echo "==========================================="
if [ "$fail" = 0 ]; then
	echo "PASS: quic carrier negotiates, survives NAT rebind, falls back, rejects bad auth, relays, keeps its carrier across link drops"
	exit 0
else
	echo "FAIL"
	exit 1
fi

#!/bin/sh
# obfs-test.sh -- prove the obfuscated-UDP carrier (M5, stream G2; hardened by
# stream O for security review R findings M5-2..M5-6).
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
# PART 4-6 (review R):
#   * (a, M5-2) a third party holding both nodes' PUBLIC keys derives the old
#     public-key bootstrap key (obfs_probe.py) and can read only the cold-start
#     frames, NOT the steady traffic, which uses the per-link session key;
#   * (b, M5-4) replaying a captured datagram from a different address does not
#     repoint the link (A<->B keeps pinging);
#   * (c, M5-5) reflecting a datagram back to its sender does not close it.
# PART 7 (e, M5-6): with 35 extra peers in the node tree the cold scan is not
#   starved and the last peer's link still comes up.
# (d, M5-3 nonce uniqueness) is a unit self-test in core/tincd/test/fuzz/fuzz_obfs.c.
#
# No fixed sleeps: every phase polls for readiness (both daemons logged
# "activated" and a ping succeeds) with a 60 s deadline, like
# platforms/linux/docker/two-nodes.sh wait_ready, so a loaded host only makes
# the test slower, not red.
#
# tcpdump runs in a throwaway container attached to a node's netns, so nothing
# is installed on the host. Image: tincstack/core:ws-g2.
#
# Usage: [LAB=prefix] [SUBNET=10.37.90] testing/transports/obfs-test.sh [image]
#   LAB (default wso) prefixes every container name, the docker network
#   (<LAB>obfs) and the /tmp data directories; a non-default LAB also gets its
#   own /24 (see lab-env.sh), so two runs can share a host.
#   The image is the first argument, else tincstack/core:$TINCSTACK_TAG, the
#   same selector every other proof takes. Silently defaulting to the stream
#   image this test was written against means a house-style invocation tests
#   a months-old core and reports its state as today's (measured: a run with
#   TINCSTACK_TAG set but no argument tested tincstack/core:ws-o and failed
#   PART 8, which the current core passes).
set -e

IMG=${1:-tincstack/core:${TINCSTACK_TAG:-dev}}
TCPDUMP_IMG=nicolaka/netshoot
DEFAULT_LAB=wso; DEFAULT_SUBNET=10.37.90
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"
NET=${LAB}obfs
BASE=/tmp/$LAB-obfs
PCAPDIR=/tmp/$LAB-obfs-pcap
WAIT=120   # deadline ceiling for every readiness poll; the happy path exits as
           # soon as the link is clean (observed 17-81 s for the relayed obfs KEX
           # under load), so a larger ceiling only adds tolerance, never latency.

A_IP=$SUBNET.10
R_IP=$SUBNET.11
B_IP=$SUBNET.12
ATK1_IP=$SUBNET.50
ATK2_IP=$SUBNET.51
A_VPN=10.182.0.1
R_VPN=10.182.0.2
B_VPN=10.182.0.3

# junk size window used for the informational wire count only
JMIN=600
JMAX=650
JCOUNT=8

fail=0
cleanup() {
	docker rm -f "$LAB-a" "$LAB-r" "$LAB-b" "$LAB-cap" "$LAB-atk" >/dev/null 2>&1 || true
}
# On exit take the network down too -- reset_lab() between parts must keep it,
# but a finished run must not leave one docker network per LAB behind.
# shellcheck disable=SC2329  # invoked from the EXIT trap below
cleanup_exit() {
	cleanup
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup_exit EXIT
cleanup
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

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
	docker run -d --name "$LAB-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN \
		--device /dev/net/tun -v "$3":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n wsg2 -D -d2 >/dev/null
}
setvpn() { # letter vpnip  (idempotent; the device may not exist yet right after start)
	docker exec "$LAB-$1" ip addr add "$2/24" dev wsg2 >/dev/null 2>&1 || true
	docker exec "$LAB-$1" ip link set wsg2 up >/dev/null 2>&1 || true
}
logs() { docker logs "$LAB-$1" 2>&1; }
activated() { logs "$1" | grep -q ' activated'; }
cli() { docker exec "$LAB-$1" tinc -c /etc/tincstack/tinc.yaml -n wsg2 "$2" "$3" 2>/dev/null || true; }
# number of "obfs session key established" lines a node has logged (monotone,
# so a replacement that re-negotiated shows up as an increase).
sesscount() { logs "$1" | grep -c 'obfs session key established' || true; }

# wait_link <n1> <n1-vpn> <n2> <n2-vpn>: both daemons logged "activated" AND the
# tunnel pings clean in BOTH directions (each obfs data path is warmed/confirmed
# independently, so the assertion pings that follow are not racing a still-cold
# reverse direction). Polls 1 s up to $WAIT s.
wait_link() {
	deadline=$(( $(date +%s) + WAIT ))
	while :; do
		setvpn "$1" "$2"; setvpn "$3" "$4"
		if activated "$1" && activated "$3" \
		   && docker exec "$LAB-$1" ping -c1 -W1 "$4" >/dev/null 2>&1 \
		   && docker exec "$LAB-$3" ping -c1 -W1 "$2" >/dev/null 2>&1; then
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
# wait_clean <from> <to-vpn> [count]: poll a full ping run until it reports a
# clean " 0% packet loss" within $WAIT s, echoing the final ping tail. A fresh
# cold link needs a moment for tinc's UDP discovery to confirm each direction
# independently; polling a *clean* run (not a single snapshot) tolerates that
# convergence window under host load while still failing if a direction never
# stabilises. Echoes the final ping tail; RETURN CODE is the result (0 clean,
# 1 timed out) -- read it via `if out=$(wait_clean ...); then`, since a global
# set here would not survive the command substitution.
wait_clean() {
	deadline=$(( $(date +%s) + WAIT ))
	cnt=${3:-4}
	while :; do
		out=$(docker exec "$LAB-$1" ping -c"$cnt" -W2 "$2" 2>&1 | tail -2)
		if echo "$out" | grep -q " 0% packet loss"; then
			echo "$out"
			return 0
		fi
		if [ "$(date +%s)" -ge "$deadline" ]; then
			echo "$out"
			return 1
		fi
		sleep 2
	done
}
loss() { echo "$1" | grep -oE '[0-9]+(\.[0-9]+)?% packet loss' || echo '?'; }

capture_start() { # letter
	docker run -d --name "$LAB-cap" --net "container:$LAB-$1" --cap-add NET_RAW "$TCPDUMP_IMG" \
		tcpdump -n -xx -i eth0 'udp port 655' >/dev/null 2>&1
	sleep 1
}
capture_stop() {
	docker stop "$LAB-cap" >/dev/null 2>&1 || true
	docker logs "$LAB-cap" 2>&1
	docker rm -f "$LAB-cap" >/dev/null 2>&1 || true
}
hex_of() { echo "$1" | grep -oE '0x[0-9a-f]+:.*' | sed 's/0x[0-9a-f]*://' | tr -dc '0-9a-f'; }
count_len_between() { echo "$1" | grep -oE 'length [0-9]+' | awk -v lo="$2" -v hi="$3" '{if($2>=lo&&$2<=hi)n++} END{print n+0}'; }
sfmagic() { echo "$1" | grep -c '9f7473666c77' || true; }
# junk events by the sender's marker, summed over both nodes' logs
junk_events() { n=0; for l in "$@"; do n=$(( n + $(logs "$l" | grep -c 'obfs junk datagram' || true) )); done; echo "$n"; }

reset_lab() {
	cleanup
	docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null 2>&1 || true
	rm -rf "$BASE"-a "$BASE"-r "$BASE"-b; mkdir -p "$BASE"-a "$BASE"-r "$BASE"-b
}

# --- pcap capture (for the third-party probe and replay/reflection) ---------
# Writes a real pcap into a host-mounted dir so obfs_probe.py can parse the UDP
# payloads (log-hex parsing cannot separate the payload from the IP/UDP header).
cap_pcap_start() { # letter file
	rm -f "$PCAPDIR/$2"
	mkdir -p "$PCAPDIR"
	docker rm -f "$LAB-cap" >/dev/null 2>&1 || true
	docker run -d --name "$LAB-cap" --net "container:$LAB-$1" -v "$PCAPDIR":/cap --cap-add NET_RAW "$TCPDUMP_IMG" \
		tcpdump -n -U -w "/cap/$2" -i eth0 'udp port 655' >/dev/null 2>&1
	# poll until the pcap header is on disk (24 bytes), deadline WAIT, then a
	# short settle so libpcap's BPF filter is actually attached before the
	# caller generates traffic (a sub-second handshake was otherwise missed).
	d=$(( $(date +%s) + WAIT ))
	while :; do
		[ -s "$PCAPDIR/$2" ] && [ "$(wc -c <"$PCAPDIR/$2" 2>/dev/null)" -ge 24 ] && break
		[ "$(date +%s)" -ge "$d" ] && break
		sleep 1
	done
	sleep 2
}
cap_pcap_stop() { docker stop "$LAB-cap" >/dev/null 2>&1 || true; docker rm -f "$LAB-cap" >/dev/null 2>&1 || true; }

# node's OWN Ed25519 public key, read from its host block in its own yaml.
ownpubkey() { # letter name
	awk -v n="$2" '
		$0 ~ "^      " n ": \\|" {inblk=1; next}
		inblk && /^      [A-Za-z0-9_]+: \|/ {inblk=0}
		inblk && /Ed25519PublicKey/ {print $3; exit}
	' "$BASE-$1/tinc.yaml"
}

# send a raw UDP payload (hex) to a node's port from a DISTINCT source address,
# impersonating an off-path attacker. Uses a throwaway netshoot container.
raw_send() { # atk_ip dst_ip hexpayload repeat
	docker rm -f "$LAB-atk" >/dev/null 2>&1 || true
	docker run --rm --name "$LAB-atk" --network "$NET" --ip "$1" "$TCPDUMP_IMG" \
		python3 -c "
import socket,sys
data=bytes.fromhex('$3')
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for _ in range($4):
    s.sendto(data,('$2',655))
print('sent',$4,'x',len(data),'bytes')
" 2>&1 || true
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
docker exec "$LAB-a" ping -c3 -W2 "$B_VPN" >/dev/null 2>&1 || true
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

if ab=$(wait_clean a "$B_VPN"); then ab_ok=1; else ab_ok=0; fi
if ba=$(wait_clean b "$A_VPN"); then ba_ok=1; else ba_ok=0; fi

# steady-state flood: no new handshake, so the sender's junk counter must not move
junk_before=$(junk_events a b)
docker exec "$LAB-a" ping -c30 -i0.2 -W2 "$B_VPN" >/dev/null 2>&1 || true
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

[ "$ab_ok" = 1 ] || { echo "MISS: cold obfs A->B ping never went clean within ${WAIT}s"; fail=1; }
[ "$ba_ok" = 1 ] || { echo "MISS: cold obfs B->A ping never went clean within ${WAIT}s"; fail=1; }
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
docker exec "$LAB-a" iptables -A INPUT  -s "$B_IP" -j DROP
docker exec "$LAB-a" iptables -A OUTPUT -d "$B_IP" -j DROP
docker exec "$LAB-b" iptables -A INPUT  -s "$A_IP" -j DROP
docker exec "$LAB-b" iptables -A OUTPUT -d "$A_IP" -j DROP
# The first packets trigger the relayed SPTPS key exchange through R; poll until
# a full ping run is clean (<= WAIT s), which covers establishment + convergence.
t0=$(date +%s)
if ping2=$(wait_clean a "$B_VPN" 4); then
	echo "relay up after $(( $(date +%s) - t0 )) s: $ping2"
	echo "relay A<->B reachable through R (obfs, per-hop sealed)"
else
	echo "MISS: relayed obfs A<->B never went clean within ${WAIT}s: $ping2"; fail=1
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
docker exec "$LAB-a" ping -c3 -W2 "$B_VPN" >/dev/null 2>&1 || true
def_cap=$(capture_stop)
if def_ping=$(wait_clean a "$B_VPN"); then def_ok=1; else def_ok=0; fi
def_magic=$(sfmagic "$(hex_of "$def_cap")")
udpn=$(echo "$def_cap" | grep -c 'UDP' || true)
def_junk=$(junk_events a b)
echo "default: $(loss "$def_ping") ; SF magic=$def_magic ; UDP datagrams=$udpn ; junk events=$def_junk"
[ "$def_ok" = 1 ] || { echo "MISS: default tunnel ping never went clean within ${WAIT}s"; fail=1; }
[ "$def_magic" = 0 ] || { echo "MISS: SF magic on the wire with defaults (should be plain SPTPS)"; fail=1; }
[ "$udpn" -gt 0 ] || { echo "MISS: no UDP data on the wire with defaults"; fail=1; }
[ "$def_junk" = 0 ] || { echo "MISS: junk emitted with obfs not selected"; fail=1; }

########## PART 4-6: session key, replay, reflection (review R M5-2/4/5) ######
# One A<->B obfs lab drives all three: a third party with both public keys
# cannot read steady traffic (M5-2), a replayed datagram does not repoint the
# link (M5-4), and a reflected datagram does not tear the session down (M5-5).
echo "===== PART 4-6: session key / replay / reflection ====="
reset_lab
SEC_OPTS="      ObfsJunkPacketCount: 4
      PreferredTransports: [obfs, plain]"
gen "$BASE-b" nodeb "$SEC_OPTS"
gen "$BASE-a" nodea "$SEC_OPTS
      ConnectTo: [nodeb]"
materialise b a
crossinject a b
PKA=$(ownpubkey a nodea); PKB=$(ownpubkey b nodeb)
echo "  A pubkey ${PKA:-<none>} ; B pubkey ${PKB:-<none>}"

start b "$B_IP" "$BASE-b"
cap_pcap_start b cold.pcap        # capture from cold: catches the bootstrap frames
start a "$A_IP" "$BASE-a"
wait_link a "$A_VPN" b "$B_VPN" || fail=1

# wait for the per-link session key to be established on BOTH ends
d=$(( $(date +%s) + WAIT ))
while :; do
	if logs a | grep -q 'obfs session key established' && logs b | grep -q 'obfs session key established'; then sess_ok=1; break; fi
	if [ "$(date +%s)" -ge "$d" ]; then sess_ok=0; break; fi
	sleep 1
done
cap_pcap_stop
[ "${sess_ok:-0}" = 1 ] || { echo "MISS: obfs session key never established on both ends"; fail=1; }

# Warm and settle the link so any initial cold re-dial is over before the
# steady capture, otherwise a transient re-handshake sprays bootstrap frames.
wait_clean a "$B_VPN" >/dev/null 2>&1 || true
wait_clean b "$A_VPN" >/dev/null 2>&1 || true

# steady-state capture, well after the session key switch, both directions.
cap_pcap_start b steady.pcap
docker exec "$LAB-a" ping -c30 -i0.2 -W2 "$B_VPN" >/dev/null 2>&1 || true
docker exec "$LAB-b" ping -c30 -i0.2 -W2 "$A_VPN" >/dev/null 2>&1 || true
cap_pcap_stop

# ---- (a) M5-2: third party with both public keys cannot decrypt steady traffic
# Positive control (deterministic): the probe derives the public-key bootstrap
# key and unseals a frame it sealed under it. This proves the derivation is
# correct WITHOUT depending on capturing a bootstrap-keyed datagram -- the
# OBFS_KEY seed exchange runs over the reliable TCP meta channel and usually
# completes before any UDP data flows, so there may be zero bootstrap-keyed
# DATA frames on the wire to capture. The cold capture is kept as informational
# only.
sc=$(python3 "$(dirname "$0")/obfs_probe.py" selftest "$PKA" "$PKB" 2>/dev/null)
dec_cold=$(python3 "$(dirname "$0")/obfs_probe.py" decrypt "$PCAPDIR/cold.pcap" "$PKA" "$PKB" 2>/dev/null)
dec_steady=$(python3 "$(dirname "$0")/obfs_probe.py" decrypt "$PCAPDIR/steady.pcap" "$PKA" "$PKB" 2>/dev/null)
echo "  probe positive control (seal+unseal with public-key bootstrap key): $sc"
echo "  probe on wire (bootstrap key from public keys): cold [$dec_cold] (info) ; steady [$dec_steady]"
n_steady=$(echo "$dec_steady" | sed -n 's/.*decryptable=\([0-9]*\).*/\1/p')
t_steady=$(echo "$dec_steady" | sed -n 's/.*total=\([0-9]*\).*/\1/p')
[ "$sc" = "selftest=ok" ] || { echo "MISS: probe positive control failed -- bootstrap derivation wrong, steady result meaningless"; fail=1; }
[ "${t_steady:-0}" -gt 0 ] || { echo "MISS: captured 0 steady obfs frames -- nothing to test M5-2 against"; fail=1; }
[ "${n_steady:-1}" = 0 ] || { echo "MISS: a third party decrypted steady obfs traffic (M5-2 not fixed)"; fail=1; }

# a real A->B steady datagram to replay/reflect
PAYLOAD=$(python3 "$(dirname "$0")/obfs_probe.py" dump "$PCAPDIR/steady.pcap" "$B_IP" 1 2>/dev/null | head -1)
echo "  captured A->B datagram: $(printf '%s' "$PAYLOAD" | cut -c1-24)... (${#PAYLOAD} hex chars)"

# ---- (b) M5-4: replay from a DIFFERENT address must not repoint the link
if [ -n "$PAYLOAD" ]; then
	raw_send "$ATK1_IP" "$B_IP" "$PAYLOAD" 20 >/dev/null 2>&1
	# if the replay had repointed B's link to the attacker, A<->B would stall
	if rep=$(wait_clean a "$B_VPN"); then
		echo "  (b) after replay flood from $ATK1_IP: A<->B $(loss "$rep") -- link not repointed"
	else
		echo "MISS: A<->B did not recover after a replay flood (link may have been repointed, M5-4)"; fail=1
	fi
else
	echo "MISS: could not capture an A->B datagram to replay"; fail=1
fi

# ---- (c) M5-5: a reflected datagram must not close the session
if [ -n "$PAYLOAD" ]; then
	closes_before=$(logs a | grep -c 'session closed\|session reset' || true)
	raw_send "$ATK2_IP" "$A_IP" "$PAYLOAD" 20 >/dev/null 2>&1   # reflect A's own tx frame back to A
	closes_after=$(logs a | grep -c 'session closed\|session reset' || true)
	if refl=$(wait_clean a "$B_VPN"); then
		echo "  (c) after reflecting A's frame to A: A<->B $(loss "$refl") ; teardown log lines ${closes_before}->${closes_after}"
	else
		echo "MISS: A<->B did not survive a reflected datagram (M5-5)"; fail=1
	fi
	[ "$closes_before" = "$closes_after" ] || { echo "MISS: a reflected datagram triggered a session close/reset (M5-5)"; fail=1; }
fi

########## PART 7: cold-scan fairness with > 30 peers (review R M5-6) #########
echo "===== PART 7: cold-scan classifies the last peer among > 30 ====="
reset_lab
SCAN_OPTS="      ObfsJunkPacketCount: 2
      PreferredTransports: [obfs, plain]"
gen "$BASE-b" nodeb "$SCAN_OPTS"
gen "$BASE-a" nodea "$SCAN_OPTS
      ConnectTo: [nodeb]"
materialise b a
crossinject a b
# stuff B's node tree with 35 dummy peers, so a cold obfs datagram from A must
# survive a scan far larger than the old global 25/s budget.
python3 - "$BASE-b/tinc.yaml" <<'PYEOF'
import sys, os, base64
path = sys.argv[1]
s = open(path).read()
block = ""
for i in range(1, 36):
    key = base64.b64encode(os.urandom(32)).decode().rstrip("=")
    block += "      dummy%02d: |\n        Ed25519PublicKey = %s\n        Subnet = 10.181.%d.1/32\n" % (i, key, i)
s = s.replace("    hosts:\n", "    hosts:\n" + block, 1)
open(path, "w").write(s)
print("added 35 dummy peers to B")
PYEOF
start b "$B_IP" "$BASE-b"; start a "$A_IP" "$BASE-a"
if wait_link a "$A_VPN" b "$B_VPN"; then
	echo "  A<->B obfs tunnel came up with 35 extra peers in B's node tree (cold scan not starved)"
	if s7=$(wait_clean a "$B_VPN"); then echo "  (e) $(loss "$s7") with > 30 peers configured"; else echo "MISS: tunnel unstable with >30 peers"; fail=1; fi
else
	echo "MISS: cold obfs link did not come up with > 30 peers (M5-6 scan starved)"; fail=1
fi

########## PART 8: connection-replacement churn keeps the session key #########
# Review R M5-2 residual: a connection replacement (both nodes ConnectTo each
# other, so a disconnect makes both re-dial and one connection supersedes the
# other) must NOT drop the link back to the mesh-wide bootstrap key. We force
# CHURN replacements and, after each, capture steady traffic and assert a third
# party holding both public keys can read NONE of it, and that a per-link
# session key was (re)established. The window from a replacement to the new
# session key is measured from the daemon log timestamps and reported.
#
# This part IS a before/after demonstrator, on an idle host: measured 2026-09-16
# on the same lab minutes apart, pre-fix tincstack/core:ws-o -> 6 of 10
# replacements stuck on the bootstrap key for the full ${WAIT} s deadline and
# 673 of 1099 steady frames readable with the public-key bootstrap key; post-fix
# tincstack/core:w -> 0 stuck, 0 of 1172 readable, worst window 1 s. (The
# earlier note here said the symptom needed heavy host load and that both builds
# pass when idle -- that was wrong, and it is why the fix was nearly closed on
# unit evidence alone.) Post-fix runs so far: 0 of 3530 steady frames over three
# runs, idle and under a parallel fuzz campaign. The mechanism proof stays the
# fuzz_obfs self-test `selftest_close_preserves_session', which aborts on the
# pre-fix obfs_close() condition.
echo "===== PART 8: connection-replacement churn keeps the per-link session key (M5-2) ====="
reset_lab
CHURN=${OBFS_CHURN:-10}
CHURN_OPTS="      ObfsJunkPacketCount: 4
      PreferredTransports: [obfs, plain]"
gen "$BASE-a" nodea "$CHURN_OPTS
      ConnectTo: [nodeb]"
gen "$BASE-b" nodeb "$CHURN_OPTS
      ConnectTo: [nodea]"
materialise a b
crossinject a b
PKA8=$(ownpubkey a nodea); PKB8=$(ownpubkey b nodeb)
start b "$B_IP" "$BASE-b"; start a "$A_IP" "$BASE-a"
wait_link a "$A_VPN" b "$B_VPN" || fail=1
# initial session key on both ends
d=$(( $(date +%s) + WAIT ))
while :; do
	[ "$(sesscount a)" -ge 1 ] && [ "$(sesscount b)" -ge 1 ] && break
	[ "$(date +%s)" -ge "$d" ] && { echo "MISS: no initial obfs session key before churn"; fail=1; break; }
	sleep 1
done

churn_dec=0; churn_frames=0; churn_stuck=0; churn_worst=0
for i in $(seq 1 "$CHURN"); do
	pre_a=$(sesscount a); pre_b=$(sesscount b)
	# simultaneous disconnect on both ends -> both re-dial -> replacement
	cli a disconnect nodeb & cli b disconnect nodea & wait
	if ! wait_link a "$A_VPN" b "$B_VPN"; then
		echo "  repl $i: link did not recover within ${WAIT}s"; churn_stuck=$(( churn_stuck + 1 )); fail=1; continue
	fi
	# The bootstrap-key window is from the link coming back up (here) until BOTH
	# ends have (re)established a per-link session key. Poll for both and time
	# it -- a fresh connection legitimately seals a few frames under the
	# bootstrap key until its OBFS_KEY exchange completes; the defect was this
	# never completing (stuck for up to one 30 s tick). No fixed sleeps.
	t0=$(date +%s); d=$(( t0 + WAIT )); post_a=$pre_a; post_b=$pre_b
	while :; do
		post_a=$(sesscount a); post_b=$(sesscount b)
		[ "$post_a" -gt "$pre_a" ] && [ "$post_b" -gt "$pre_b" ] && break
		[ "$(date +%s)" -ge "$d" ] && break; sleep 1
	done
	win=$(( $(date +%s) - t0 ))
	if [ "$post_a" -le "$pre_a" ] || [ "$post_b" -le "$pre_b" ]; then
		echo "  repl $i: session key not re-established on both ends within ${WAIT}s (stuck on bootstrap)"; churn_stuck=$(( churn_stuck + 1 )); fail=1
	fi
	[ "$win" -gt "$churn_worst" ] && churn_worst=$win
	# settle both directions, then steady capture WELL AFTER both session keys
	# are up: a mesh member with both public keys must read NONE of it.
	wait_clean a "$B_VPN" >/dev/null 2>&1 || true
	wait_clean b "$A_VPN" >/dev/null 2>&1 || true
	cap_pcap_start b "churn$i.pcap"
	docker exec "$LAB-a" ping -c20 -i0.15 -W2 "$B_VPN" >/dev/null 2>&1 || true
	docker exec "$LAB-b" ping -c20 -i0.15 -W2 "$A_VPN" >/dev/null 2>&1 || true
	cap_pcap_stop
	dec=$(python3 "$(dirname "$0")/obfs_probe.py" decrypt "$PCAPDIR/churn$i.pcap" "$PKA8" "$PKB8" 2>/dev/null)
	n=$(echo "$dec" | sed -n 's/.*decryptable=\([0-9]*\).*/\1/p'); t=$(echo "$dec" | sed -n 's/.*total=\([0-9]*\).*/\1/p')
	churn_dec=$(( churn_dec + ${n:-0} )); churn_frames=$(( churn_frames + ${t:-0} ))
	echo "  repl $i: A sess $pre_a->$post_a B sess $pre_b->$post_b ; session-key window ${win}s ; steady bootstrap-decryptable=${n:-?}/${t:-?}"
	[ "${n:-0}" = 0 ] || fail=1
done
echo "  churn total over $CHURN replacements: steady bootstrap-decryptable=$churn_dec / $churn_frames ; worst session-key window=${churn_worst}s ; stuck=$churn_stuck"
[ "$churn_dec" = 0 ] || { echo "MISS: steady traffic was bootstrap-key readable after both ends had a session key (M5-2 residual)"; fail=1; }
[ "$churn_stuck" = 0 ] || { echo "MISS: a replacement left a link stuck on the bootstrap key (M5-2 residual)"; fail=1; }

echo "==========================================================="
if [ "$fail" = 0 ]; then
	echo "PASS: obfs cold-start works, fingerprint gone, junk per-handshake, relay intact, defaults plain;"
	echo "      session key blinds a third party (M5-2), replay does not repoint (M5-4),"
	echo "      reflection does not close (M5-5), cold scan survives > 30 peers (M5-6),"
	echo "      connection-replacement churn keeps the session key (M5-2 residual)"
	exit 0
else
	echo "FAIL"
	exit 1
fi

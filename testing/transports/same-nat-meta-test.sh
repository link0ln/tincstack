#!/bin/sh
# same-nat-meta-test.sh -- defect E: two nodes behind ONE NAT never form a meta
# connection and retry for ever, while their UDP data path is direct and fine.
#
# Topology (the field pair `router'+`laptop' behind one home NAT, in Docker):
#
#      outside $SUBNET.0/26            natgw            nodea $SUBNET.64/26
#      relay .10  <------------>  .20 "public IP"  .66 <----> .70  Port 6551
#      (founder, public)                           .130 <---> .134 Port 6552
#                                                        nodeb $SUBNET.128/26
#
# The gateway is the whole point. Three properties, all asserted before the
# test believes anything:
#
#   * port-preserving cone NAT for UDP, hairpin included: a node reaching the
#     public address on the other node's port is DNATed back in and its source
#     rewritten to the gateway -- what a home router with NAT loopback does;
#   * a black hole for TCP to the public address in either direction: no port
#     forward, no hairpin, DROP rather than REJECT so the dialler sees the
#     field's timeout and not an instant refusal;
#   * no route between the two inside segments. The only address either node
#     has for the other is the shared public one. That is the field pair --
#     `laptop' is inside a docker bridge on a LAN machine (10.16.8.2, which
#     `router' cannot reach) and `router' advertises its own upstream address
#     (192.168.0.2, which `laptop' cannot reach) -- and it is why "advertise
#     your LAN address" does not help them.
#
# The measured asymmetry of the field NAT is `laptop -> router' UDP 10/10
# packets at 5.7 ms while TCP times out. The lab enforces that asymmetry with
# explicit rules rather than reproducing one vendor's quirk: what is under test
# is tinc's reaction to it, not the NAT.
#
# Both nodes are invited by the relay. They are then left to exchange keys over
# the graph once (defect C's REQ_PUBKEY path, which persists the key but not the
# accept mask) and both daemons are restarted. That is the field pair's state
# and it matters: with the key already on disk no REQ_PUBKEY/ANS_PUBKEY round
# trip ever happens again, so stream AC's accept-mask propagation never fires
# and each node still believes the other is plain-only. Without that restart the
# lab would quietly be testing defect C's path instead of defect E's.
#
# --expect-defect asserts the broken behaviour (and is what the pre-fix image
# must still show):
#
#   nodea log   Trying to connect to nodeb (<public> port 6552) via plain
#               Timeout while connecting to nodeb (<public> port 6552)
#               ERROR Could not set up a meta connection to nodeb   [for ever]
#   dump nodes  nodeb ... nexthop relay via nodeb distance 2 ... transports plain
#               i.e. the meta path is relayed abroad while the DATA path (via)
#               is already direct.
#
# Default mode asserts the fix: the pair ends up at distance 1 with each other
# as nexthop, over the `sf' (single-flow UDP) carrier, with the relay still
# running -- and the ERROR loop is gone.
#
# --expect-relayed is the negative control for the new knob: it asserts only
# that the pair is still relayed and its data path still direct, without saying
# anything about the accept mask. Run it with SET_OPTS='UdpMetaFallback no',
# which must put the pair back in the half-state on a FIXED build:
#
#   SET_OPTS='UdpMetaFallback no' same-nat-meta-test.sh <img> --expect-relayed
#
# Usage: [LAB=prefix] [SUBNET=10.34.9] [SETTLE=90] [LOG_LEVEL=1] \
#        [SET_OPTS='Key value'] \
#            testing/transports/same-nat-meta-test.sh [image] [--expect-defect]
#   The image is the first argument, else tincstack/core:$TINCSTACK_TAG -- the
#   same selector every other proof here takes, because a stale image silently
#   testing the wrong build has burned this project before.
set -e

EXPECT=fixed
IMG=
for arg in "$@"; do
	case $arg in
	--expect-defect) EXPECT=defect ;;
	--expect-fixed) EXPECT=fixed ;;
	--expect-relayed) EXPECT=relayed ;;
	-*) echo "unknown option $arg" >&2; exit 64 ;;
	*) IMG=$arg ;;
	esac
done
IMG=${IMG:-tincstack/core:${TINCSTACK_TAG:-dev}}
PROBE_IMG=${PROBE_IMG:-alpine}

DEFAULT_LAB=wsenat; DEFAULT_SUBNET=10.34.9
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"

NET_OUT=$LAB-out
NET_A=$LAB-ina
NET_B=$LAB-inb
NETNAME=tincstack
YAML=/etc/tincstack/tinc.yaml
OUT_CIDR=$SUBNET.0/26
A_CIDR=$SUBNET.64/26
B_CIDR=$SUBNET.128/26
R_IP=$SUBNET.10          # relay, on the public side
PUB=$SUBNET.20           # the NAT's one public address
GW_A=$SUBNET.66          # the NAT's address on nodea's segment (.65 is the docker bridge)
GW_B=$SUBNET.130        # the NAT's address on nodeb's segment (.129 is the docker bridge)
A_IP=$SUBNET.70
B_IP=$SUBNET.134
A_PORT=6551
B_PORT=6552
A_PROBE=7551
B_PROBE=7552
SETTLE=${SETTLE:-90}
LOG_LEVEL=${LOG_LEVEL:-1}   # the default an operator runs; the ERROR must be visible there

tnc() { # tnc <suffix> <tinc args...>
	tnc_c=$1; shift
	docker exec "$LAB-$tnc_c" tinc -n "$NETNAME" -c "$YAML" "$@"
}
log() { cat "/tmp/$LAB-$1/tincd.log"; }
# NB: `<producer> | grep -q PATTERN` is a trap under `set -o pipefail` -- grep
# leaves on the first match, the producer dies of SIGPIPE, the pipeline fails
# even though the pattern WAS there. Everything below uses `grep -c >/dev/null`.
has() { grep -c "$2" "/tmp/$LAB-$1/tincd.log" >/dev/null; }
count() { grep -c "$2" "/tmp/$LAB-$1/tincd.log" 2>/dev/null || true; }
fail=0
note() { echo "MISS: $*"; fail=1; }
step() { echo; echo "== $*"; }

cleanup() {
	docker rm -f "$LAB-r" "$LAB-a" "$LAB-b" "$LAB-gw" "$LAB-probe" >/dev/null 2>&1 || true
	docker network rm "$NET_A" "$NET_B" "$NET_OUT" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
	echo "FAIL: image $IMG does not exist; build it or set TINCSTACK_TAG" >&2
	exit 1
fi
echo "image: $IMG ($(docker run --rm "$IMG" tincd --version | head -n1))"
docker image inspect "$PROBE_IMG" >/dev/null 2>&1 || docker pull "$PROBE_IMG" >/dev/null

# Two bridges and a container routing between them. Docker 28+ installs a
# `! -i br-X -o br-X -j DROP' rule per bridge, which black-holes exactly the
# traffic this lab is made of (a LAN host reaching the gateway's public
# address), so both networks ask for the unprotected gateway mode; on an older
# daemon the option does not exist and is not needed. The relaxation lives and
# dies with these two throwaway networks.
mknet() { # mknet <name> <cidr>
	docker network create --subnet "$2" \
		--opt com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected "$1" >/dev/null 2>&1 \
		|| docker network create --subnet "$2" "$1" >/dev/null
}
mknet "$NET_OUT" "$OUT_CIDR"
mknet "$NET_A" "$A_CIDR"
mknet "$NET_B" "$B_CIDR"
for n in r a b; do rm -rf "/tmp/$LAB-$n"; mkdir -p "/tmp/$LAB-$n"; done

run_node() { # run_node <suffix> <network> <ip>
	docker run -d --name "$LAB-$1" --network "$2" --ip "$3" \
		--cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun \
		-v "/tmp/$LAB-$1:/etc/tincstack" "$IMG" sleep infinity >/dev/null
}
start_tincd() { docker exec -d "$LAB-$1" sh -c "tincd -n $NETNAME -c $YAML -D -d$LOG_LEVEL >>/etc/tincstack/tincd.log 2>&1"; }
wait_ready() {
	i=0
	while [ "$i" -lt 30 ]; do
		tnc "$1" pid >/dev/null 2>&1 && return 0
		i=$(( i + 1 )); sleep 1
	done
	echo "FAIL: $LAB-$1 did not open its control socket" >&2
	log "$1" >&2 || true
	exit 1
}

step "the NAT gateway: UDP hairpins, TCP to the public address does not"
docker run -d --name "$LAB-gw" --network "$NET_OUT" --ip "$PUB" \
	--cap-add NET_ADMIN --cap-add NET_RAW --sysctl net.ipv4.ip_forward=1 \
	"$IMG" sleep infinity >/dev/null
docker network connect --ip "$GW_A" "$NET_A" "$LAB-gw"
docker network connect --ip "$GW_B" "$NET_B" "$LAB-gw"
# The interface names depend on the order docker attached the networks, so they
# are looked up by address instead of assumed to be eth0/eth1/eth2.
gwsh() { docker exec "$LAB-gw" sh -c "$1"; }
gwif() { gwsh "ip -o -4 addr show | awk '\$4 ~ /^$1\\// {print \$2}'"; }
OUT_IF=$(gwif "$PUB"); A_IF=$(gwif "$GW_A"); B_IF=$(gwif "$GW_B")
[ -n "$OUT_IF" ] && [ -n "$A_IF" ] && [ -n "$B_IF" ] \
	|| { echo "FAIL: could not find the gateway interfaces" >&2; exit 1; }
echo "   out=$OUT_IF ($PUB)  nodea=$A_IF ($GW_A)  nodeb=$B_IF ($GW_B)"
gwsh "
set -e
# 1. LAN -> world. SNAT (not MASQUERADE) to keep the source port where it is
#    free, so a node's advertised Port is also its port on the public side --
#    a port-preserving cone NAT, which is what most home routers do for UDP.
iptables -t nat -A POSTROUTING -o $OUT_IF -s $A_CIDR -j SNAT --to-source $PUB
iptables -t nat -A POSTROUTING -o $OUT_IF -s $B_CIDR -j SNAT --to-source $PUB
# 2. UDP port forwards for the two nodes and the two probe ports. PREROUTING
#    catches packets from BOTH sides, so this is also the hairpin half.
iptables -t nat -A PREROUTING -p udp --dport $A_PORT  -j DNAT --to-destination $A_IP:$A_PORT
iptables -t nat -A PREROUTING -p udp --dport $B_PORT  -j DNAT --to-destination $B_IP:$B_PORT
iptables -t nat -A PREROUTING -p udp --dport $A_PROBE -j DNAT --to-destination $A_IP:$A_PROBE
iptables -t nat -A PREROUTING -p udp --dport $B_PROBE -j DNAT --to-destination $B_IP:$B_PROBE
# 3. the other hairpin half: a peer reached through the public address must
#    answer through the gateway, not straight back at a source address the
#    sender never used. Only for traffic that came from the other segment --
#    the relay's own packets must keep their real source address.
iptables -t nat -A POSTROUTING -o $B_IF -s $A_CIDR -p udp -m conntrack --ctorigdst $PUB -j SNAT --to-source $GW_B
iptables -t nat -A POSTROUTING -o $A_IF -s $B_CIDR -p udp -m conntrack --ctorigdst $PUB -j SNAT --to-source $GW_A
# 4. the two nodes sit in separate segments and the gateway does not route
#    between them: the ONLY address either node has for the other is the
#    shared public one. That is the field pair -- a node in a docker bridge on
#    a LAN machine, and a gateway node whose own \"local\" address is its
#    upstream side -- and it is what makes \"just advertise your LAN address\"
#    useless for them. Hairpin (already DNATed, original destination = the
#    public address) is the exception.
iptables -A FORWARD -i $A_IF -o $B_IF -m conntrack --ctorigdst $PUB -j ACCEPT
iptables -A FORWARD -i $B_IF -o $A_IF -m conntrack --ctorigdst $PUB -j ACCEPT
iptables -A FORWARD -i $A_IF -o $B_IF -j DROP
iptables -A FORWARD -i $B_IF -o $A_IF -j DROP
# 5. TCP to the public address is a black hole in both directions: no port
#    forward from outside, no hairpin from inside. DROP, not REJECT, so the
#    dialler sees the field's timeout rather than an instant refusal.
iptables -A INPUT   -p tcp -d $PUB -m multiport --dports $A_PORT,$B_PORT,$A_PROBE,$B_PROBE -j DROP
iptables -A FORWARD -p tcp -d $PUB -j DROP
"

step "relay founds the network on the public side"
run_node r "$NET_OUT" "$R_IP"
docker exec "$LAB-r" sh -c "install -m600 /dev/null $YAML && tinc -n $NETNAME -c $YAML set Name relay && tinc -n $NETNAME -c $YAML set Port 655"
start_tincd r
wait_ready r
tnc r set relay.Address "$R_IP"

inv_a=$(tnc r invite nodea | tr -d '\r')
inv_b=$(tnc r invite nodeb | tr -d '\r')
echo "   nodea: $inv_a"
echo "   nodeb: $inv_b"

step "both nodes join from behind the NAT"
run_node a "$NET_A" "$A_IP"
run_node b "$NET_B" "$B_IP"
docker exec "$LAB-a" ip route replace default via "$GW_A"
docker exec "$LAB-b" ip route replace default via "$GW_B"
tnc a join "$inv_a" >/dev/null
tnc b join "$inv_b" >/dev/null
tnc a set Port "$A_PORT" >/dev/null
tnc b set Port "$B_PORT" >/dev/null
# SET_OPTS is one `Key value' pair applied to both nodes before they start; it
# exists so the negative control can turn the new fallback off without a
# second copy of this lab.
if [ -n "${SET_OPTS:-}" ]; then
	# shellcheck disable=SC2086  # deliberate: SET_OPTS is "Key value"
	tnc a set $SET_OPTS >/dev/null
	# shellcheck disable=SC2086
	tnc b set $SET_OPTS >/dev/null
	echo "   both nodes: $SET_OPTS"
fi

start_tincd a; wait_ready a
start_tincd b; wait_ready b

step "let each node persist the other's Ed25519 key, then restart both"
# The field pair already held each other's keys, and that is exactly why stream
# AC's accept-mask propagation never fires for them: the mask rides on
# ANS_PUBKEY, which only a key-less node ever asks for. Reproducing that state
# by letting the pair do one REQ_PUBKEY round trip (defect C's path -- it
# persists the key but not the mask) and then restarting both daemons is more
# faithful than hand-seeding a key, and it is how the field pair got there.
have_key=0
i=0
while [ "$i" -lt 60 ]; do
	if tnc a get nodeb.Ed25519PublicKey >/dev/null 2>&1 && tnc b get nodea.Ed25519PublicKey >/dev/null 2>&1; then
		have_key=1; break
	fi
	i=$(( i + 2 )); sleep 2
done
[ "$have_key" = 1 ] || { echo "FAIL: the pair never exchanged keys over the graph" >&2; log a >&2; exit 1; }
echo "   both keys persisted after ${i}s; restarting the daemons with the logs truncated"
for n in a b; do
	tnc "$n" stop >/dev/null 2>&1 || true
done
i=0
while [ "$i" -lt 20 ]; do
	tnc a pid >/dev/null 2>&1 || tnc b pid >/dev/null 2>&1 || break
	i=$(( i + 1 )); sleep 1
done
sleep 2
for n in a b; do
	: > "/tmp/$LAB-$n/tincd.log"
	start_tincd "$n"
	wait_ready "$n"
done

step "preconditions (assert, never assume)"
# P1: the lab's NAT really is TCP-deaf and UDP-hairpinning. Proven without
#     tinc, so that a tinc failure can never be confused with a broken lab.
tcp_probe() { # tcp_probe <suffix> <ip> <port> -> 0 when the connect succeeds
	docker exec "$LAB-$1" timeout 6 bash -c "exec 3<>/dev/tcp/$2/$3" >/dev/null 2>&1
}
if tcp_probe a "$R_IP" 655; then
	echo "   TCP nodea -> relay:655 connects (the lab is not simply broken)"
else
	echo "FAIL: nodea cannot even reach the relay over TCP; the lab is broken" >&2
	exit 1
fi
if tcp_probe a "$PUB" "$B_PORT"; then
	echo "FAIL: TCP hairpin to $PUB:$B_PORT works; this NAT does not reproduce the field" >&2
	exit 1
fi
echo "   TCP nodea -> $PUB:$B_PORT times out (no forward, no hairpin)"
# udp_probe <dst> <marker>: send three datagrams from nodea's namespace to
# <dst>:$B_PROBE and report whether a listener in nodeb's namespace saw them.
udp_probe() {
	docker rm -f "$LAB-probe" >/dev/null 2>&1 || true
	docker run -d --name "$LAB-probe" --network "container:$LAB-b" "$PROBE_IMG" \
		sh -c "nc -u -l -p $B_PROBE" >/dev/null
	sleep 1
	for up_i in 1 2 3; do
		docker run --rm --network "container:$LAB-a" "$PROBE_IMG" \
			sh -c "echo $2-$up_i | nc -u -w1 $1 $B_PROBE" >/dev/null 2>&1 || true
		sleep 1
	done
	up_out=$(docker logs "$LAB-probe" 2>&1 || true)
	docker rm -f "$LAB-probe" >/dev/null 2>&1 || true
	printf '%s\n' "$up_out" | grep -c "$2" >/dev/null
}
if udp_probe "$PUB" hairpin; then
	echo "   UDP nodea -> $PUB:$B_PROBE reaches nodeb (hairpin works)"
else
	echo "FAIL: UDP hairpin does not work in this lab; the defect's premise is absent" >&2
	exit 1
fi
if udp_probe "$B_IP" lanpath; then
	echo "FAIL: nodea can reach nodeb's private address directly; that is not the field topology" >&2
	exit 1
fi
if tcp_probe a "$B_IP" "$B_PORT"; then
	echo "FAIL: nodea can reach nodeb's private address over TCP; that is not the field topology" >&2
	exit 1
fi
echo "   neither UDP nor TCP reaches nodeb's private address $B_IP (no LAN short cut)"

# P2: both nodes are on the graph through the relay, and know each other.
wait_for() { # wait_for <seconds> <suffix> <tinc args...> -- until the output matches $PAT
	wf_deadline=$(( $(date +%s) + $1 )); shift
	wf_n=$1; shift
	while :; do
		if docker exec "$LAB-$wf_n" tinc -n "$NETNAME" -c "$YAML" "$@" 2>/dev/null | grep -c "$PAT" >/dev/null; then
			return 0
		fi
		[ "$(date +%s)" -ge "$wf_deadline" ] && return 1
		sleep 2
	done
}
PAT='^relay '
wait_for 40 a dump connections || { echo "FAIL: nodea never connected to the relay" >&2; log a >&2; exit 1; }
wait_for 40 b dump connections || { echo "FAIL: nodeb never connected to the relay" >&2; log b >&2; exit 1; }
PAT='^nodeb '
wait_for 40 a dump nodes || { echo "FAIL: nodea never learned nodeb over the graph" >&2; exit 1; }
echo "   both nodes are on the relay's graph and see each other"

# P3: the key is already known on both sides, so no ANS_PUBKEY will happen.
for n in a b; do
	other=nodea; [ "$n" = a ] && other=nodeb
	tnc "$n" get "$other.Ed25519PublicKey" >/dev/null 2>&1 \
		|| { echo "FAIL: $n does not have $other's key; the seeding did not take" >&2; exit 1; }
done
echo "   both nodes already hold the other's Ed25519 key (no REQ_PUBKEY will fire)"

step "traffic over the tunnel, which is what confirms the direct UDP path"
a_vpn=$(tnc a get nodea.Subnet | head -n1 | tr -d '\r'); a_vpn=${a_vpn%%/*}
b_vpn=$(tnc b get nodeb.Subnet | head -n1 | tr -d '\r'); b_vpn=${b_vpn%%/*}
echo "   nodea=$a_vpn nodeb=$b_vpn"
docker exec "$LAB-a" ping -c 3 -W 2 "$b_vpn" || note "nodea cannot reach nodeb over the tunnel at all"

step "settling for ${SETTLE}s with the relay UP the whole time"
# A two-node lab does not reproduce a mesh-dependent defect (stream AD learned
# that the hard way): the relay stays up, so nothing about the pair's state
# depends on losing their only other edge.
s=0
while [ "$s" -lt "$SETTLE" ]; do
	docker exec "$LAB-a" ping -c 1 -W 1 "$b_vpn" >/dev/null 2>&1 || true
	sleep 5
	s=$(( s + 5 ))
done

for n in a b; do
	echo "----- $LAB-$n dump nodes -----"; tnc "$n" dump nodes
	echo "----- $LAB-$n dump connections -----"; tnc "$n" dump connections
done

peer_line() { tnc "$1" dump nodes | grep "^$2 " || true; }
carrier() { tnc "$1" dump connections 2>/dev/null | awk -v n="$2" '$1 == n { print $13 }' | head -n1; }

if [ "$EXPECT" = relayed ]; then
	echo
	echo "===== asserting that the pair is STILL RELAYED (negative control) ====="
	for n in a b; do
		other=nodea; [ "$n" = a ] && other=nodeb
		line=$(peer_line "$n" "$other")
		case $line in
		*"nexthop relay"*"distance 2"*) echo "   $n: the META path to $other is relayed, as asked" ;;
		*) note "$n reached $other anyway: $line" ;;
		esac
		case $line in
		*"via $other"*) echo "   $n: the DATA path to $other is still direct" ;;
		*) note "$n lost its direct UDP data path to $other: $line" ;;
		esac
		got=$(carrier "$n" "$other")
		[ -z "$got" ] || note "$n has a meta connection to $other on '$got'"
	done
	if [ "$fail" = 0 ]; then
		echo "PASS(control): with the UDP meta fallback off the pair stays in the half-state"
		exit 0
	fi
	echo "FAIL: the control did not hold"
	exit 1
fi

if [ "$EXPECT" = defect ]; then
	echo
	echo "===== asserting the DEFECT (pre-fix behaviour) ====="
	for n in a b; do
		other=nodea; [ "$n" = a ] && other=nodeb
		echo "----- $LAB-$n: the dial loop -----"
		grep -E "Trying to connect to $other|Timeout while connecting to $other|Could not set up a meta connection to $other" \
			"/tmp/$LAB-$n/tincd.log" | tail -6 || true
		c=$(count "$n" "Could not set up a meta connection to $other")
		[ "${c:-0}" -ge 2 ] || note "$n gave up on $other only $c time(s); the endless loop did not reproduce"
		has "$n" "Timeout while connecting to $other" || note "$n never timed out dialling $other"
		line=$(peer_line "$n" "$other")
		case $line in
		*"nexthop relay"*"distance 2"*) echo "   $n: the META path to $other is relayed (distance 2 via relay)" ;;
		*) note "$n does not see $other at distance 2 via the relay: $line" ;;
		esac
		case $line in
		*"via $other"*) echo "   $n: the DATA path to $other is already DIRECT (via $other) -- the half-state" ;;
		*) note "$n has no direct UDP data path to $other, so this is not defect E: $line" ;;
		esac
		case $line in
		*"transports plain "*|*"transports plain") echo "   $n: still believes $other is plain-only (defect E point 3)" ;;
		*) note "$n already knows $other's accept mask; the key-seeding did not hold: $line" ;;
		esac
	done
	if [ "$fail" = 0 ]; then
		echo "PASS(repro): the pair's data path is direct, its meta path is relayed for ever, and both log ERRORs"
		exit 0
	fi
	echo "FAIL: the defect did not reproduce"
	exit 1
fi

echo
echo "===== asserting the FIX ====="
for n in a b; do
	other=nodea; [ "$n" = a ] && other=nodeb
	line=$(peer_line "$n" "$other")
	case $line in
	*"nexthop $other"*"distance 1"*) echo "   $n: $other is DIRECT (distance 1, nexthop $other)" ;;
	*) note "$n does not see $other at distance 1: $line" ;;
	esac
	case $line in
	*"transports plain,sf"*) echo "   $n: knows $other's real accept mask" ;;
	*) note "$n still assumes $other is plain-only: $line" ;;
	esac
	got=$(carrier "$n" "$other")
	case $got in
	sf|obfs) echo "   $n: the meta connection to $other rides the $got carrier" ;;
	*) note "$n's meta connection to $other is on '${got:-none}', not a UDP carrier" ;;
	esac
done

step "the dial loop must be quiet at -d$LOG_LEVEL"
for n in a b; do
	other=nodea; [ "$n" = a ] && other=nodeb
	c=$(count "$n" "ERROR.*Could not set up a meta connection to $other")
	echo "   $LAB-$n: $c ERROR line(s) about $other"
	[ "${c:-0}" -le 3 ] || note "$n logged $c ERRORs for $other; the loop is still loud"
done

step "the pair keeps its link when the relay goes away"
docker stop "$LAB-r" >/dev/null
sleep 5
docker exec "$LAB-a" ping -c 3 -W 2 "$b_vpn" || note "nodea cannot reach nodeb without the relay"
docker exec "$LAB-b" ping -c 3 -W 2 "$a_vpn" || note "nodeb cannot reach nodea without the relay"
for n in a b; do
	other=nodea; [ "$n" = a ] && other=nodeb
	line=$(peer_line "$n" "$other")
	case $line in
	*"distance 1"*) : ;;
	*) note "$n lost $other when the relay stopped: $line" ;;
	esac
done

if [ "$fail" = 0 ]; then
	echo "PASS: two nodes behind one NAT peer directly over a UDP carrier, with no ERROR loop"
	exit 0
fi
echo "FAIL"
exit 1

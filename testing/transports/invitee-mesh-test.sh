#!/bin/sh
# invitee-mesh-test.sh -- defects C and D: two nodes invited by the same third
# node must peer DIRECTLY, not stay relayed through their inviter forever.
#
# Topology (the three-host stand of 2026-09-16, in three containers):
#
#     founder   public, Port 655, issues both invitations
#        |  \
#     leaf1    leaf2     each joined with `tinc join', neither was ever given
#                        a host record for the other
#
# Both leaves learn each other over the meta graph and both try a direct meta
# connection within seconds. What upstream tinc 1.1 does, and what this script
# asserts in --expect-defect mode:
#
#   acceptor   Cannot open config file <confbase>/hosts/<peer>: No such file...
#              Peer <ip> port <p> had unknown identity (<peer>)
#   dialler    Timeout from <peer> (...) during authentication
#              Could not set up a meta connection to <peer>   [on every retry]
#   result     `dump nodes' on both leaves: nexthop founder ... distance 2
#              ... transports plain
#
# Default mode asserts the fixed behaviour instead: both leaves reach
# `distance 1' with the other leaf as its own nexthop, the peer's real accept
# mask is known (defect D), the tunnel carries traffic leaf-to-leaf with the
# founder STOPPED, and neither leaf logs the ERROR loop.
#
# Usage: [LAB=prefix] [SUBNET=10.33.9] testing/transports/invitee-mesh-test.sh \
#            [image] [--expect-defect]
#   The image is the first argument, else tincstack/core:$TINCSTACK_TAG, the
#   same selector every other proof here takes -- a stale image silently
#   testing the wrong build has burned this project before.
#   LAB (default wsacim) prefixes every container/network name and the /tmp
#   data directories; a non-default LAB also gets its own /24 (see lab-env.sh).
set -e

EXPECT=fixed
IMG=
for arg in "$@"; do
	case $arg in
	--expect-defect) EXPECT=defect ;;
	--expect-fixed) EXPECT=fixed ;;
	-*) echo "unknown option $arg" >&2; exit 64 ;;
	*) IMG=$arg ;;
	esac
done
IMG=${IMG:-tincstack/core:${TINCSTACK_TAG:-dev}}

DEFAULT_LAB=wsacim; DEFAULT_SUBNET=10.33.9
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"
NET=$LAB
NETNAME=tincstack
F_IP=$SUBNET.10
L1_IP=$SUBNET.11
L2_IP=$SUBNET.12
YAML=/etc/tincstack/tinc.yaml
# tnc <container suffix> <tinc args...> -- the CLI inside one node container.
# A function, not a `T="tinc -n ..."' string, so nothing depends on word
# splitting an unquoted variable (shellcheck runs at full severity here).
tnc() {
	tnc_c=$1; shift
	docker exec "$LAB-$tnc_c" tinc -n "$NETNAME" -c "$YAML" "$@"
}
# Seconds to wait for the pair to settle. The AutoConnect backoff is
# 5/10/15/20/25/30 s, so a fix that needs one or two of those rounds still fits;
# a pair that has not peered by then never will.
SETTLE=${SETTLE:-45}

cleanup() {
	docker rm -f "$LAB-f" "$LAB-l1" "$LAB-l2" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
	echo "FAIL: image $IMG does not exist; build it or set TINCSTACK_TAG" >&2
	exit 1
fi
echo "image: $IMG ($(docker run --rm "$IMG" tincd --version | head -n1))"

for n in f l1 l2; do rm -rf "/tmp/$LAB-$n"; mkdir -p "/tmp/$LAB-$n"; done
run_node() { # run_node <suffix> <ip>
	docker run -d --name "$LAB-$1" --network "$NET" --ip "$2" \
		--cap-add NET_ADMIN --device /dev/net/tun \
		-v "/tmp/$LAB-$1:/etc/tincstack" "$IMG" sleep infinity >/dev/null
}
# The daemon's log goes to a file in the bind mount, not to the container's
# stdout, because the daemon is started with `docker exec -d' (the container
# itself is a sleeper, so `tinc join' can run before the first tincd start --
# exactly what the node image's entrypoint does).
start_tincd() { docker exec -d "$LAB-$1" sh -c "tincd -n $NETNAME -c $YAML -D -d${LOG_LEVEL:-3} >>/etc/tincstack/tincd.log 2>&1"; }
wait_ready() {
	i=0
	while [ "$i" -lt 30 ]; do
		tnc "$1" pid >/dev/null 2>&1 && return 0
		i=$(( i + 1 )); sleep 1
	done
	echo "FAIL: $LAB-$1 did not open its control socket" >&2
	cat "/tmp/$LAB-$1/tincd.log" >&2 || true
	exit 1
}

echo "== founder: empty config, materialised by the daemon"
run_node f "$F_IP"
docker exec "$LAB-f" sh -c "install -m600 /dev/null $YAML && tinc -n $NETNAME -c $YAML set Name founder && tinc -n $NETNAME -c $YAML set Port 655"
start_tincd f
wait_ready f
tnc f set founder.Address "$F_IP"

echo "== founder invites both leaves"
inv1=$(tnc f invite leaf1)
inv2=$(tnc f invite leaf2)
echo "   leaf1: $inv1"
echo "   leaf2: $inv2"

run_node l1 "$L1_IP"
run_node l2 "$L2_IP"
tnc l1 join "$inv1" >/dev/null
start_tincd l1
wait_ready l1
sleep 5
tnc l2 join "$inv2" >/dev/null
start_tincd l2
wait_ready l2

echo "== neither leaf has a host record for the other (the whole point)"
for n in l1 l2; do
	other=leaf1; [ "$n" = l1 ] && other=leaf2
	if tnc "$n" get "$other.Ed25519PublicKey" >/dev/null 2>&1; then
		echo "FAIL: $n already knows $other before they ever talked" >&2
		exit 1
	fi
done
echo "   ok"

echo "== settling for ${SETTLE}s"
sleep "$SETTLE"

l1_ip=$(tnc l1 get leaf1.Subnet | head -n1); l1_ip=${l1_ip%%/*}
l2_ip=$(tnc l2 get leaf2.Subnet | head -n1); l2_ip=${l2_ip%%/*}
echo "   tunnel addresses: leaf1=$l1_ip leaf2=$l2_ip"

for n in l1 l2; do
	echo "----- $LAB-$n dump nodes -----"
	tnc "$n" dump nodes
done
echo "----- $LAB-l1 dump edges -----"
tnc l1 dump edges

# peer_line <suffix> <peer name>: that peer's `dump nodes' line.
peer_line() { tnc "$1" dump nodes | grep "^$2 " || true; }

fail=0
note() { echo "MISS: $*"; fail=1; }
# NB: `<producer> | grep -q PATTERN` is a trap in a `set -o pipefail` script --
# grep -q leaves on the first match, the producer dies of SIGPIPE and the
# pipeline exits non-zero even though the pattern WAS found. Every presence
# test below uses `grep -c ... >/dev/null`, which reads to EOF.
has() { grep -c "$2" "/tmp/$LAB-$1/tincd.log" >/dev/null; }

if [ "$EXPECT" = defect ]; then
	echo "===== asserting the DEFECT (defect C, pre-fix behaviour) ====="
	for n in l1 l2; do
		other=leaf1; [ "$n" = l1 ] && other=leaf2
		echo "----- $LAB-$n: the two error lines -----"
		grep -E "had unknown identity|Cannot open config file .*hosts/$other|Timeout from $other .* during authentication|Could not set up a meta connection to $other" \
			"/tmp/$LAB-$n/tincd.log" | head -8 || true
		has "$n" "hosts/$other: No such file or directory" \
			|| note "$n never logged the missing host record for $other"
		has "$n" "Could not set up a meta connection to $other" \
			|| note "$n never gave up dialling $other"
		line=$(peer_line "$n" "$other")
		case $line in
		*"nexthop founder"*"distance 2"*) echo "   $n: $other is relayed (distance 2 via founder) as expected" ;;
		*) note "$n does not see $other at distance 2 via founder: $line" ;;
		esac
	done
	if [ "$fail" = 0 ]; then
		echo "PASS(repro): both leaves are permanently relayed through their inviter"
		exit 0
	fi
	echo "FAIL: the defect did not reproduce"
	exit 1
fi

echo "===== asserting the FIX ====="
for n in l1 l2; do
	other=leaf1; [ "$n" = l1 ] && other=leaf2
	line=$(peer_line "$n" "$other")
	case $line in
	*"nexthop $other"*"distance 1"*) echo "   $n: $other is DIRECT (distance 1, nexthop $other)" ;;
	*) note "$n does not see $other at distance 1: $line" ;;
	esac
	# Defect D: the peer's accept mask must have come over the graph, not be
	# the plain-only fallback.
	case $line in
	*"transports plain,sf"*) echo "   $n: knows $other's real accept mask" ;;
	*"transports plain "*|*"transports plain") note "$n still assumes $other is plain-only (defect D): $line" ;;
	*) note "$n: no transports field for $other: $line" ;;
	esac
	# The ERROR loop must be gone.
	if has "$n" "had unknown identity"; then note "$n still logs \`unknown identity'"; fi
	if has "$n" "Could not set up a meta connection to $other"; then note "$n still gives up dialling $other"; fi
	if has "$n" "Timeout from $other .* during authentication"; then note "$n still dials $other into an authentication timeout"; fi
done

echo "== leaf-to-leaf traffic WITH THE FOUNDER STOPPED"
docker stop "$LAB-f" >/dev/null
sleep 3
docker exec "$LAB-l1" ping -c 3 -W 2 "$l2_ip" || note "leaf1 cannot reach leaf2 without the founder"
docker exec "$LAB-l2" ping -c 3 -W 2 "$l1_ip" || note "leaf2 cannot reach leaf1 without the founder"
for n in l1 l2; do
	other=leaf1; [ "$n" = l1 ] && other=leaf2
	line=$(peer_line "$n" "$other")
	case $line in
	*"distance 1"*) : ;;
	*) note "$n lost $other when the founder went away: $line" ;;
	esac
done

echo "== ERROR lines in the leaf logs (should be none of the defect's)"
for n in l1 l2; do
	printf '   %s: ' "$LAB-$n"
	grep -c ERROR "/tmp/$LAB-$n/tincd.log" || true
	grep ERROR "/tmp/$LAB-$n/tincd.log" | sort | uniq -c | head -5 || true
done

if [ "$fail" = 0 ]; then
	echo "PASS: two invitees of the same node peer directly, with the founder stopped"
	exit 0
fi
echo "FAIL"
exit 1

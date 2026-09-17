#!/bin/sh
# obfs-restart-test.sh -- a peer that restarts must still be able to dial obfs.
#
# The defect (found 2026-09-17 while re-testing stream AD's fix on the merged
# tree, and the SECOND cause of "the obfs dial hangs in the field"):
#
#   keyset_build() starts the sender's counter at a RANDOM 48-bit value, and
#   the bootstrap keyset is derived from the two nodes' public keys, so it
#   outlives both daemons. The acceptor's replay window keeps the high-water
#   mark of the previous session; a peer that restarts draws a fresh random
#   start, and when it lands below that mark -- measured 1.7e14 of 2.8e14, i.e.
#   three restarts in five -- EVERY frame of its dial is "too old to prove
#   non-replay" and is dropped. The drop was silent at every debug level:
#
#     acceptor   Cold-classified an obfs datagram from 10.62.7.11 port 656 as nodeb
#                (and then nothing at all)
#     dialler    Dialling nodea (...) via obfuscated single-flow UDP
#                Timeout from nodea (...) during authentication
#                Carrier obfs failed for nodea, falling back to plain
#
#   Measured before the fix: obfs re-established after 1 of 6 restarts.
#   After: 6 of 6, with the acceptor logging
#   "Restarting the obfs replay window for nodeb at counter ...".
#
# WHY NO EXISTING TEST CAUGHT IT. Every obfs lab dials from containers that
# have never spoken obfs before, so the window is unstarted and the first dial
# always works. carrier-switch-test.sh and obfs-confirmed-peer-test.sh switch a
# RUNNING node, which also works the first time; obfs-confirmed-peer-test.sh
# restarts the dialler only on a retry, which is why it looked "flaky" (1 run
# in 4 for its author, 3 of 3 for the reviewer) instead of broken. Flakiness
# that tracks a coin flip is a defect with a probability attached, not noise.
#
#   sh testing/transports/obfs-restart-test.sh [node-image] [--expect-defect]
#
# Default asserts the fix: the first switch reaches obfs AND every restart
# re-establishes it. --expect-defect asserts the pre-fix behaviour and needs at
# least one restart to fail; with N=6 a broken build passes it by luck with
# probability 0.38^6 ~ 0.3%, which is the one number to remember before
# treating a green --expect-defect run as proof of anything.
#
# Unlike its neighbours this harness drives the NODE image (it needs the
# entrypoint's invite/join flow), so the argument is a node image, not a core.
set -u

IMG=${1:-tincstack/node:${TINCSTACK_TAG:-dev}}
MODE=${2:-}
LAB=${LAB:-obre}
N=${N:-6}
SUBNET=${SUBNET:-10.63.9.0/24}
WAIT=${WAIT:-60}
A_IP=$(echo "$SUBNET" | sed 's|0/24|10|')
B_IP=$(echo "$SUBNET" | sed 's|0/24|11|')

say() { echo "  $*"; }
fail=0
miss() { echo "  MISS: $*"; fail=1; }

cleanup() {
	[ -n "${KEEP:-}" ] && return
	docker rm -f "$LAB-a" "$LAB-b" >/dev/null 2>&1
	docker network rm "$LAB-net" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

echo "lab: LAB=$LAB IMG=$IMG SUBNET=$SUBNET restarts=$N"
cleanup
docker network create --subnet "$SUBNET" "$LAB-net" >/dev/null

docker run -d --name "$LAB-a" --network "$LAB-net" --ip "$A_IP" \
	--cap-add NET_ADMIN --device /dev/net/tun \
	-e NODE_NAME=nodea -e PUBLIC_ADDRESS="$A_IP" -e PORT=655 -e LOG_LEVEL=5 "$IMG" >/dev/null

i=0
while [ $i -lt 30 ]; do
	docker exec "$LAB-a" tincstack-cli dump nodes >/dev/null 2>&1 && break
	i=$(( i + 1 ))
	sleep 1
done

INV=$(docker exec "$LAB-a" tincstack-cli invite nodeb 2>&1 | tail -1)
case "$INV" in
*/*) : ;;
*) echo "FAIL: no invitation from the founder: $INV"; exit 1 ;;
esac

docker run -d --name "$LAB-b" --network "$LAB-net" --ip "$B_IP" \
	--cap-add NET_ADMIN --device /dev/net/tun \
	-e NODE_NAME=nodeb -e PORT=656 -e INVITE="$INV" -e LOG_LEVEL=5 "$IMG" >/dev/null

i=0
while [ $i -lt 30 ]; do
	docker exec "$LAB-b" tincstack-cli dump nodes 2>/dev/null | grep -c nodea >/dev/null 2>&1 && break
	i=$(( i + 1 ))
	sleep 1
done
sleep 5

# An obfs/sf link has no socket of its own -- it rides the shared UDP socket --
# so `socket' is -1 by design and `status' is what says it is activated.
up() {
	docker exec "$LAB-b" tincstack-cli dump connections 2>/dev/null |
		awk '/^nodea /{for(i=1;i<=NF;i++){if($i=="status")st=$(i+1); if($i=="transport")t=$(i+1)}; if(st != "0" && t=="obfs") print "yes"}' |
		head -1
}

waitup() {
	j=0
	while [ "$j" -lt "$WAIT" ]; do
		[ "$(up)" = yes ] && { echo yes; return; }
		j=$(( j + 3 ))
		sleep 3
	done
	echo no
}

accepts() { docker logs "$LAB-a" 2>&1 | grep -c "obfuscated single-flow UDP"; }
epochs() { docker logs "$LAB-a" 2>&1 | grep -c "Restarting the obfs replay window"; }

echo "== 1. switch the running dialler to obfs"
docker exec "$LAB-b" tincstack-cli set PreferredTransports obfs >/dev/null 2>&1
docker exec "$LAB-b" tincstack-cli reload >/dev/null 2>&1
docker exec "$LAB-b" tincstack-cli disconnect nodea >/dev/null 2>&1
first=$(waitup)
say "first obfs link: $first"
[ "$first" = yes ] || miss "the first switch to obfs did not come up at all (unrelated to this defect -- see obfs-confirmed-peer-test.sh)"

echo "== 2. restart the dialler $N times; every restart must get obfs back"
ok=0
acc0=$(accepts)
i=0
while [ "$i" -lt "$N" ]; do
	i=$(( i + 1 ))
	docker restart "$LAB-b" >/dev/null
	r=$(waitup)
	acc=$(accepts)
	say "restart $i: obfs=$r (acceptor accepted +$(( acc - acc0 )) single-flow session(s))"
	acc0=$acc
	[ "$r" = yes ] && ok=$(( ok + 1 ))
	sleep 2
done
say "obfs re-established after $ok of $N restarts; the acceptor restarted its replay window $(epochs) time(s)"

echo "== 3. verdict"

if [ "$MODE" = "--expect-defect" ]; then
	if [ "$ok" -lt "$N" ]; then
		echo
		echo "PASS(repro): a restarted peer cannot dial obfs ($ok of $N restarts recovered)"
		exit 0
	fi

	echo
	echo "FAIL: every restart recovered, so this build does not have the defect"
	exit 1
fi

[ "$ok" -eq "$N" ] || miss "only $ok of $N restarts got obfs back"
[ "$(epochs)" -ge 1 ] || miss "the acceptor never restarted its replay window, so this run did not exercise the fix"

echo

if [ "$fail" -eq 0 ]; then
	echo "PASS: a peer that restarts can still dial obfs ($ok of $N restarts)"
	exit 0
fi

echo "FAIL: see MISS lines above"
exit 1

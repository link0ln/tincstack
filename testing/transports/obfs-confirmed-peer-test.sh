#!/bin/sh
# obfs-confirmed-peer-test.sh -- an ALREADY-RUNNING network cannot turn covert.
#
# The defect (stream AD, seen on the real stand on 2026-09-17, `laptop' behind
# a NAT dialling the public VPS `euvds'):
#
#   dialler   Dialling euvds (...) via obfuscated single-flow UDP
#             Timeout from euvds (...) during authentication
#             Dial to euvds ... via obfs abandoned before the connection
#               was activated
#   acceptor  Received UDP packet from laptop (...) with unknown source
#               and/or destination ID            [-d5, at the same seconds]
#
# The sealed obfs handshake frames ARRIVE. The acceptor does not claim them:
# obfs_udp_try()'s cold-start branch skipped the keyed check because
#
#     node_t *known = lookup_node_udp(&addr);
#     if(known && known->status.udp_confirmed) return false;
#
# and the dialler's source address was already bound to a node whose UDP path
# was confirmed -- i.e. the normal state of any pair that has been carrying
# traffic. The frames fell through to process_sptps_udp(), which found random
# bytes where a node id should be, and dropped them. obfs was therefore
# unusable in exactly the scenario it exists for: a working network switching
# to a covert carrier under censorship. A lab that dials obfs from cold
# containers never sees it.
#
# WHY carrier-switch-test.sh PASSES AND THIS DOES NOT -- the difference, made
# explicit below and asserted, is the ACCEPTOR's view of the dialler at the
# moment of the switch:
#
#   * carrier-switch-test.sh has TWO nodes. `tinc disconnect nodea' removes
#     the only edge to the dialler, so on the acceptor the dialler becomes
#     UNREACHABLE and graph.c clears `udp_confirmed' (graph.c, the
#     reachability-change block). The guard above then does not fire and the
#     keyed check runs. The test passes on a broken daemon.
#   * a real network has more than two nodes. Here a third node (nodec) keeps
#     the dialler reachable through the mesh, so nothing on the acceptor ever
#     clears `udp_confirmed', the guard fires, and every obfs frame is
#     dropped. PART 2 asserts that the acceptor still reports `udp_confirmed'
#     for the dialler while the obfs dial is in flight -- that is the one
#     precondition the two-node test destroys.
#
#   PART 3 is the control: stop the third node, repeat the identical switch,
#   and the dialler reaches obfs even on a pre-fix build -- proving the
#   failure is the acceptor's stale `udp_confirmed', not obfs itself.
#
# Topology (three containers on one docker /24, no NAT -- the NAT in the field
# report is incidental; what matters is that the source address is known):
#
#     nodea   founder, Port 655, the ACCEPTOR, runs at -d5 so the
#      | \    "unknown source and/or destination ID" line is visible
#      |  \
#   nodeb   nodec    both invited by nodea, both peer directly (stream AC)
#     ^
#     the DIALLER: switched to obfs at runtime with
#         tinc set PreferredTransports obfs && tinc reload
#         tinc disconnect nodea            (the sequence stream AA fixed)
#
# THE NEIGHBOURING CARRIERS. The same hazard was checked, not reasoned about:
# CARRIER=sf and CARRIER=quic run this identical scenario over the other two
# UDP carriers in transport_udp_dispatch(). Both pass on a PRE-FIX image, so
# neither is shadowed by a confirmed plain peer -- transport_classify_udp()
# claims an sf frame on its magic prefix and a quic packet on its version word
# or a live connection id, and neither ever looks the source address up. Only
# obfs, whose frames are indistinguishable from random by design, had to
# consult the node table at all, and only it got the consultation wrong.
#
# Exit 0 = the assertions of the selected mode held.
# Usage: [LAB=prefix] [SUBNET=10.48.9] [WAIT=90] [CARRIER=obfs|sf|quic] \
#            testing/transports/obfs-confirmed-peer-test.sh \
#            [core image] [--expect-defect]
#   The image is the first argument, else tincstack/core:$TINCSTACK_TAG -- the
#   same explicit selector every other proof here takes, because a run that
#   silently tested a months-old image has burned this project before.
#   LAB (default wsadocp) prefixes every container/network name and the /tmp
#   data directories; a non-default LAB also gets its own /24 (see lab-env.sh).
#   KEEP=1 leaves /tmp/<LAB>-{a,b,c}/tincd.log behind for a post-mortem.
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

DEFAULT_LAB=wsadocp; DEFAULT_SUBNET=10.48.9
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"
NET=$LAB
NETNAME=tincstack
WAIT=${WAIT:-90}
# Which UDP carrier the running dialler is switched to. obfs is the one the
# defect is about; sf and quic are here so the neighbours in the same
# dispatcher are measured rather than argued about.
CARRIER=${CARRIER:-obfs}
case $CARRIER in
obfs|sf|quic) ;;
*) echo "CARRIER must be obfs, sf or quic (got '$CARRIER')" >&2; exit 2 ;;
esac
if [ "$EXPECT" = defect ] && [ "$CARRIER" != obfs ]; then
	echo "--expect-defect only describes the obfs guard; CARRIER=$CARRIER has no such guard" >&2
	exit 2
fi
YAML=/etc/tincstack/tinc.yaml
A_IP=$SUBNET.10
B_IP=$SUBNET.11
C_IP=$SUBNET.12

fail=0
miss() { echo "  MISS: $*"; fail=1; }
note() { echo "  $*"; }
step() { printf '\n== %s\n' "$*"; }

# shellcheck disable=SC2329  # invoked from the EXIT trap below
cleanup() {
	docker rm -f "$LAB-a" "$LAB-b" "$LAB-c" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	# KEEP=1 leaves the three data directories (and the daemon logs in them)
	# behind for a post-mortem; the next run wipes them anyway.
	[ -n "${KEEP:-}" ] || rm -rf "/tmp/$LAB-a" "/tmp/$LAB-b" "/tmp/$LAB-c"
}
trap cleanup EXIT
cleanup

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
	echo "FAIL: image $IMG does not exist; build it or set TINCSTACK_TAG" >&2
	exit 1
fi
echo "image: $IMG ($(docker run --rm "$IMG" tincd --version | head -n1))"
echo "mode:  carrier $CARRIER, expecting the $EXPECT behaviour"

docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null
for n in a b c; do rm -rf "/tmp/$LAB-$n"; mkdir -p "/tmp/$LAB-$n"; done

# tnc <suffix> <args...>: the CLI inside one node container. A function, not an
# unquoted command string, so nothing depends on word splitting.
tnc() {
	tnc_c=$1; shift
	docker exec "$LAB-$tnc_c" tinc -n "$NETNAME" -c "$YAML" "$@"
}
logf() { echo "/tmp/$LAB-$1/tincd.log"; }
# count <suffix> <ere>: how many lines of that node's log match. Counting is
# deliberate: `producer | grep -q' is a trap under `set -o pipefail' -- grep
# leaves on the first match and the producer dies of SIGPIPE, so a pattern that
# WAS there reads as absent. grep -c reads to EOF.
count() {
	count_n=$(grep -cE "$2" "$(logf "$1")" 2>/dev/null) || count_n=0
	[ -n "$count_n" ] || count_n=0
	printf '%s\n' "$count_n"
}

# The container is a sleeper; the daemon is started with `docker exec -d' into
# a log file in the bind mount, so `tinc join' can run before the first tincd
# and each node can have its own debug level.
run_node() { # run_node <suffix> <ip>
	docker run -d --name "$LAB-$1" --network "$NET" --ip "$2" \
		--cap-add NET_ADMIN --device /dev/net/tun \
		-v "/tmp/$LAB-$1:/etc/tincstack" "$IMG" sleep infinity >/dev/null
}
start_tincd() { # start_tincd <suffix> <debug level>
	docker exec -d "$LAB-$1" sh -c \
		"tincd -n $NETNAME -c $YAML -D -d$2 >>/etc/tincstack/tincd.log 2>&1"
}
wait_ready() { # wait_ready <suffix>
	deadline=$(( $(date +%s) + WAIT ))
	until tnc "$1" pid >/dev/null 2>&1; do
		if [ "$(date +%s)" -ge "$deadline" ]; then
			echo "FAIL: $LAB-$1 did not open its control socket within ${WAIT}s" >&2
			tail -40 "$(logf "$1")" >&2 2>/dev/null || true
			exit 1
		fi
		sleep 1
	done
}

# carrier <suffix> <peer>: the `transport' column of `dump connections'.
# Layout: <node> at <host> port <p> options <o> socket <s> status <x> transport <c>
carrier() {
	tnc "$1" dump connections 2>/dev/null | awk -v n="$2" '$1 == n { print $13 }' | head -n1
}
wait_carrier() { # wait_carrier <suffix> <peer> <carrier>
	deadline=$(( $(date +%s) + WAIT ))
	while :; do
		got=$(carrier "$1" "$2" || true)
		[ "$got" = "$3" ] && return 0
		if [ "$(date +%s)" -ge "$deadline" ]; then
			note "got '${got:-none}' instead of '$3' after ${WAIT}s"
			return 1
		fi
		sleep 1
	done
}
# confirmed <suffix> <peer>: that node reports the peer's UDP path confirmed.
confirmed() { tnc "$1" info "$2" 2>/dev/null | grep -c '^Status:.*udp_confirmed' >/dev/null; }
# wait_confirmed <suffix> <peer> <peer tunnel ip>: drive traffic until it is.
wait_confirmed() {
	deadline=$(( $(date +%s) + WAIT ))
	while :; do
		docker exec "$LAB-$1" ping -c2 -W2 "$3" >/dev/null 2>&1 || true
		confirmed "$1" "$2" && return 0
		if [ "$(date +%s)" -ge "$deadline" ]; then
			tnc "$1" info "$2" || true
			return 1
		fi
		sleep 2
	done
}
wait_ping() { # wait_ping <suffix> <ip>
	deadline=$(( $(date +%s) + WAIT ))
	while :; do
		out=$(docker exec "$LAB-$1" ping -c3 -W2 "$2" 2>&1 | tail -2)
		printf '%s\n' "$out" | grep -c ' 0% packet loss' >/dev/null && return 0
		if [ "$(date +%s)" -ge "$deadline" ]; then
			printf '%s\n' "$out"
			return 1
		fi
		sleep 2
	done
}
# distance <suffix> <peer>: the `distance' field of `dump nodes'.
distance() {
	tnc "$1" dump nodes 2>/dev/null \
		| awk -v n="$2" '$1 == n { for(i = 1; i < NF; i++) if($i == "distance") print $(i + 1) }' \
		| head -n1
}
wait_distance() { # wait_distance <suffix> <peer> <distance>
	deadline=$(( $(date +%s) + WAIT ))
	while :; do
		[ "$(distance "$1" "$2" || true)" = "$3" ] && return 0
		if [ "$(date +%s)" -ge "$deadline" ]; then
			note "$LAB-$1 sees $2 at distance '$(distance "$1" "$2" || true)', not $3"
			return 1
		fi
		sleep 2
	done
}
# prefer <suffix> <carrier>: the operator's dial order, `plain' last as the
# universal fallback (writing it twice would be a duplicate line).
prefer() {
	tnc "$1" set PreferredTransports "$2" >/dev/null
	[ "$2" = plain ] || tnc "$1" add PreferredTransports plain >/dev/null
}

step "1. a three-node network on plain, carrying traffic"
run_node a "$A_IP"
docker exec "$LAB-a" sh -c \
	"install -m600 /dev/null $YAML && tinc -n $NETNAME -c $YAML set Name nodea && tinc -n $NETNAME -c $YAML set Port 655"
# -d5 on the acceptor: "Received UDP packet ... with unknown source and/or
# destination ID" is logged at DEBUG_TRAFFIC and is the field evidence.
start_tincd a 5
wait_ready a
tnc a set nodea.Address "$A_IP" >/dev/null

inv_b=$(tnc a invite nodeb | tr -d '\r')
inv_c=$(tnc a invite nodec | tr -d '\r')
note "invitations: $inv_b / $inv_c"

run_node b "$B_IP"
run_node c "$C_IP"
tnc b join "$inv_b" >/dev/null
tnc c join "$inv_c" >/dev/null
# Fixed listening ports. An invitee defaults to an ephemeral one, which changes
# on every restart -- and PART 3 restarts the dialler, so the acceptor's cached
# UDP address for it would be stale and the UDP path would need a full
# discovery round to reconfirm.
tnc b set Port 656 >/dev/null
tnc c set Port 657 >/dev/null
start_tincd b 3
start_tincd c 2
wait_ready b
wait_ready c

a_vpn=$(tnc b get nodea.Subnet | head -n1 | tr -d '\r'); a_vpn=${a_vpn%%/*}
b_vpn=$(tnc a get nodeb.Subnet | head -n1 | tr -d '\r'); b_vpn=${b_vpn%%/*}
note "tunnel addresses: nodea=$a_vpn nodeb=$b_vpn"

accept=$(sed -n 's/.*Transports accept=\([^ ]*\).*/\1/p' "$(logf b)" | tail -n1)
note "the dialler's build accepts: ${accept:-unknown}"
case ",$accept," in
*",$CARRIER,"*) : ;;
*)
	echo "SKIP: this build has no $CARRIER carrier (accept=${accept:-unknown}); nothing to prove" >&2
	exit 0
	;;
esac

wait_carrier b nodea plain || miss "the dialler did not come up on the default carrier (plain)"
wait_ping b "$a_vpn" || miss "the tunnel does not carry traffic on plain"
note "baseline: nodeb -> nodea on $(carrier b nodea), tunnel clean"

step "2. the acceptor confirms the dialler's UDP path, and a third node keeps it reachable"
wait_confirmed b nodea "$a_vpn" || miss "the dialler never confirmed nodea's UDP path"
wait_confirmed a nodeb "$b_vpn" || miss "the ACCEPTOR never confirmed nodeb's UDP path -- this test cannot reproduce anything without it"
note "acceptor's view of the dialler: $(tnc a info nodeb | grep '^Status:' || true)"
# nodeb <-> nodec direct (stream AC). Without this edge the acceptor loses the
# dialler on `disconnect' and clears udp_confirmed, which is precisely the
# two-node case carrier-switch-test.sh already covers.
wait_distance b nodec 1 || miss "the two invitees did not peer directly, so the mesh cannot keep nodeb reachable"
wait_distance c nodea 1 || miss "nodec is not directly connected to nodea"
note "mesh: nodeb-nodec distance $(distance b nodec), nodec-nodea distance $(distance c nodea)"

step "3. switch the RUNNING dialler to $CARRIER (set + reload + disconnect)"
# THE DIFFERENCE from the two-node test: the acceptor must still hold
# udp_confirmed for the dialler while the dial is in flight. That is the
# precondition, not the result, so a run that loses it proves nothing and is
# retried rather than reported either way. It can be lost honestly: the mesh
# reconverges around the edge `disconnect' just deleted, and if the acceptor
# sees nodeb go unreachable for even one tick, graph.c clears udp_confirmed
# and the run has degenerated into the case carrier-switch-test.sh covers.
# Measured: 1 of 4 runs (CARRIER=quic) lost it this way.
still=0
attempt=0
got_carrier=0
unk_new=0
tmo_new=0
while [ "$attempt" -lt 3 ]; do
	attempt=$(( attempt + 1 ))

	if [ "$attempt" -gt 1 ]; then
		# Restart the dialler rather than just disconnecting it: the restart
		# resets retry_outgoing()'s backoff, which the failed attempt has
		# already grown, and gives the next attempt the same clean starting
		# point as the first. Rebuilding the plain path after a single-flow
		# link has been up is the slow direction (see PART 4), so this step
		# gets three times the usual patience -- it is setup, not a result.
		note "attempt $attempt: restarting the dialler on plain and reconfirming first"
		prefer b plain
		tnc b reload >/dev/null
		docker restart "$LAB-b" >/dev/null
		start_tincd b 3
		wait_ready b
		attempt_wait=$WAIT
		WAIT=$(( WAIT * 3 ))
		wait_carrier b nodea plain || miss "attempt $attempt: the dialler did not come back up on plain"
		wait_confirmed a nodeb "$b_vpn" || miss "attempt $attempt: the acceptor did not reconfirm nodeb's UDP path"
		wait_distance b nodec 1 || miss "attempt $attempt: nodeb and nodec are no longer direct"
		WAIT=$attempt_wait
	fi

	# Let the previous step's teardown finish writing before the baseline is
	# taken; a frame dropped while the OLD link was being torn down is not a
	# frame dropped by the dial that follows, and sampling in the same second
	# attributed one to the other (measured).
	sleep 3
	unk_before=$(count a 'unknown source and/or destination ID')
	tmo_before=$(count b 'Timeout from nodea .* during authentication')
	note "before the switch: acceptor 'unknown source and/or destination ID' x$unk_before, dialler auth timeouts x$tmo_before"

	prefer b "$CARRIER"
	tnc b reload >/dev/null
	tnc b disconnect nodea >/dev/null

	# Sample the acceptor's view from the instant of the disconnect onwards.
	still=0
	i=0
	while [ "$i" -lt 6 ]; do
		confirmed a nodeb && still=$(( still + 1 ))
		i=$(( i + 1 ))
		sleep 1
	done
	note "acceptor still reports udp_confirmed for nodeb in $still of 6 samples during the dial"

	got_carrier=0
	wait_carrier b nodea "$CARRIER" && got_carrier=1
	note "the dialler's link to nodea is on '$(carrier b nodea || echo none)'"

	unk_new=$(( $(count a 'unknown source and/or destination ID') - unk_before ))
	tmo_new=$(( $(count b 'Timeout from nodea .* during authentication') - tmo_before ))

	[ "$still" -eq 6 ] && break
	note "the acceptor lost udp_confirmed for nodeb mid-dial: this attempt proves nothing, retrying"
done
[ "$still" -eq 6 ] || miss "the acceptor lost udp_confirmed for nodeb in all $attempt attempts, so this run never left the two-node case"

note "during the switch: acceptor dropped $unk_new datagram(s) as 'unknown source and/or destination ID', dialler hit $tmo_new auth timeout(s)"
if [ "$unk_new" -gt 0 ]; then
	echo "  ----- acceptor, the dropped frames -----"
	grep -E 'unknown source and/or destination ID' "$(logf a)" | tail -5
fi
echo "  ----- dialler, the $CARRIER dial -----"
grep -E "via $CARRIER|obfuscated single-flow|during authentication|Carrier $CARRIER" "$(logf b)" | tail -8 || true

step "4. control: without the third node the SAME switch works, even on a pre-fix build"
# Remove nodec and RESTART the dialler, whose configuration already prefers
# $CARRIER. The restart drops the meta connection and nodec is gone, so on the
# acceptor nodeb has no path left at all: it becomes unreachable, graph.c
# clears udp_confirmed, and the keyed check runs. This is the two-node case
# carrier-switch-test.sh covers, reached here on the same daemons seconds
# after PART 3 -- the only thing that changed is the acceptor's view of the
# dialler. A pre-fix build reaches $CARRIER here and fails PART 3; that
# difference is the whole finding.
#
# Deliberately no $CARRIER -> plain -> $CARRIER dance: tearing an obfs link
# down and rebuilding it on the same running pair took over three minutes to
# reconverge in one measured run (the acceptor kept sealing data to a peer
# that had restarted, and the dialler logged "Got ADD_EDGE from nodea for
# ourself which does not match existing entry"). That is worth a look of its
# own -- see PLAN.md, Known Issues -- but it is not what this proof is about,
# and waiting it out would make the control flaky for an unrelated reason.
docker rm -f "$LAB-c" >/dev/null 2>&1 || true
docker restart "$LAB-b" >/dev/null
start_tincd b 3
wait_ready b

unk_ctl_before=$(count a 'unknown source and/or destination ID')
ctl_carrier=0
wait_carrier b nodea "$CARRIER" && ctl_carrier=1
unk_ctl_new=$(( $(count a 'unknown source and/or destination ID') - unk_ctl_before ))
note "control: link on '$(carrier b nodea || echo none)', $unk_ctl_new new dropped datagram(s)"
[ "$ctl_carrier" = 1 ] || miss "control: $CARRIER did not come up even with the dialler unreachable -- the lab itself is broken, not the guard"

step "5. verdict"
if [ "$EXPECT" = defect ]; then
	[ "$got_carrier" = 0 ] || miss "the defect did not reproduce: obfs came up despite the acceptor holding udp_confirmed"
	[ "$unk_new" -gt 0 ] || miss "the acceptor never logged 'unknown source and/or destination ID', so the frames were not silently dropped there"
	[ "$tmo_new" -gt 0 ] || miss "the dialler never timed out in authentication"
	if [ "$fail" = 0 ]; then
		echo "PASS(repro): a peer whose UDP path the acceptor has confirmed cannot be dialled over obfs;"
		echo "             the sealed frames arrive and are dropped as 'unknown source and/or destination ID'."
		exit 0
	fi
	echo "FAIL: the defect did not reproduce as described"
	exit 1
fi

[ "$got_carrier" = 1 ] || miss "the dialler did not reach $CARRIER against a peer that has its UDP path confirmed"
[ "$unk_new" = 0 ] || miss "the acceptor still dropped $unk_new frame(s) as 'unknown source and/or destination ID'"
[ "$tmo_new" = 0 ] || miss "the $CARRIER dial still ran into $tmo_new authentication timeout(s)"
wait_ping b "$a_vpn" || miss "the $CARRIER link does not carry traffic"

echo
if [ "$fail" -ne 0 ]; then
	echo "FAIL: see MISS lines above"
	exit 1
fi
echo "PASS: a running network with a confirmed UDP path can be switched to $CARRIER"

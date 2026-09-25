#!/bin/sh
# quic-loss-test.sh -- the quic carrier's streams under packet loss.
#
# ngtcp2 retransmits stream data from the pointers it was given until the
# peer acknowledges them; a send buffer that moves under it sends shifted or
# freed bytes. Until 2026-09-26 the meta stream's buffer memmove()d on every
# acknowledgment and realloc()ed on growth, and the listener's QPACK decoder
# stream -- which any HTTP/3 client makes grow -- realloc()ed too.
#
#   (meta)  founder + leaf, TCPOnly on both, so every tunnel packet rides the
#           meta stream (an HTTP/3 request body); netem LOSS and +10 ms on
#           both ends; COUNT pings of 1200 B. Pass: >= MIN_PCT% answered,
#           the link still answers after the loss is lifted, still on the
#           carrier, and the leaf dialled only once. Before the fix: 0/2000
#           and a dead link (quic); https under the same loss: 2000/2000.
#   (qpack) the founder alone; an aioquic client (quic_qpack_load.py, its
#           encoder on the listener's 4096-byte dynamic table) sends CONNS
#           connections of REQS requests each through netem LOSS on both
#           ends, so the listener's decoder stream grows while its earlier
#           bytes are being retransmitted. Pass: tincd still runs and, for an
#           image built with -Db_sanitize=address (ASAN_OPTIONS log_path
#           /tmp/asan), no AddressSanitizer report; at least one request of
#           each connection was answered.
#
# Everything runs in throwaway containers; nothing is installed on the host.
# Run under the lab lock: flock /tmp/tincstack-lab.lock <this script>.
#
# Usage: [ONLY="meta qpack"] [CARRIER=quic] [LOSS=10%] [COUNT=2000] [MIN_PCT=99]
#        [CONNS=20] [REQS=40] [LAB=wsqloss] [SUBNET=10.47.30]
#        testing/transports/quic-loss-test.sh [image]
#   The image defaults to tincstack/core:${TINCSTACK_TAG:-dev}; PROBER_IMAGE
#   (aioquic + tc) to tincstack/fp-prober:ww-f.
# shellcheck disable=SC2329  # the sections are invoked by name from $ONLY
set -u

IMG=${1:-tincstack/core:${TINCSTACK_TAG:-dev}}
PROBER=${PROBER_IMAGE:-tincstack/fp-prober:ww-f}
CARRIER=${CARRIER:-quic}
LOSS=${LOSS:-10%}
COUNT=${COUNT:-2000}
MIN_PCT=${MIN_PCT:-99}
CONNS=${CONNS:-20}
REQS=${REQS:-40}
DEFAULT_LAB=wsqloss; DEFAULT_SUBNET=10.47.30
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"
NET=${LAB}net
Y=/c/tinc.yaml
HERE=$(cd "$(dirname "$0")" && pwd)

fail=0
ok() { echo "  ok: $1"; }
bad() { echo "  FAIL: $1"; fail=1; }

cleanup() {
	docker rm -f "$LAB-f" "$LAB-l" "$LAB-p" >/dev/null 2>&1
	docker network rm "$NET" >/dev/null 2>&1
}
cleanup
trap cleanup EXIT
docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null || exit 2

t() { # node, tinc args...
	n=$1; shift
	docker exec "$LAB-$n" tinc -n lab -c "$Y" "$@"
}

node() { # name, last octet
	docker run -d --name "$LAB-$1" --network "$NET" --ip "$SUBNET.$2" --cap-add NET_ADMIN --device /dev/net/tun \
		"$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
}

start() { # node
	docker exec -d "$LAB-$1" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
}

founder() { # extra "key value" settings...
	node f 10
	docker exec "$LAB-f" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
	for kv in "$@"; do
		# shellcheck disable=SC2086  # "key value" splits on purpose
		t f set $kv
	done
	start f
	for _ in $(seq 20); do t f pid >/dev/null 2>&1 && break; sleep 1; done
	t f set founder.Address "$SUBNET.10"
}

netem() { # container, on|off
	if [ "$2" = on ]; then
		docker exec "$1" tc qdisc add dev eth0 root netem loss "$LOSS" delay 10ms
	else
		docker exec "$1" tc qdisc del dev eth0 root
	fi
}

asan_check() { # node
	if docker exec "$LAB-$1" sh -c 'cat /tmp/asan.* 2>/dev/null' | grep -q AddressSanitizer; then
		bad "$1: AddressSanitizer report"
		docker exec "$LAB-$1" sh -c 'cat /tmp/asan.*' | grep -E "ERROR|READ|WRITE|#[0-9] " | head -20
	else
		ok "$1: no AddressSanitizer report"
	fi
}

sec_meta() {
	echo "== meta: $CARRIER, TCPOnly, loss $LOSS + 10 ms both ways, $COUNT pings of 1200 B"
	founder "TCPOnly yes"
	node l 11
	inv=$(t f invite leaf)
	t l join "$inv" >/dev/null 2>&1
	t l set PreferredTransports "$CARRIER"
	t l set TCPOnly yes
	start l

	for _ in $(seq 30); do
		t l dump connections 2>/dev/null | grep -q "^founder .*transport $CARRIER" && break
		sleep 1
	done

	if ! t l dump connections 2>/dev/null | grep -q "^founder .*transport $CARRIER"; then
		bad "the leaf is not connected over $CARRIER"
		return
	fi

	fip=$(docker exec "$LAB-f" ip -4 -br addr show lab | awk '{print $3}' | cut -d/ -f1)
	docker exec "$LAB-l" ping -c3 -W2 "$fip" >/dev/null || { bad "no ping before the loss"; return; }

	netem "$LAB-f" on
	netem "$LAB-l" on
	out=$(docker exec "$LAB-l" ping -q -c"$COUNT" -i0.02 -s1200 -W1 "$fip" | tail -2)
	netem "$LAB-f" off
	netem "$LAB-l" off
	echo "$out" | sed 's/^/    /'
	got=$(echo "$out" | sed -n 's/.* \([0-9]*\) received.*/\1/p')

	if [ "${got:-0}" -ge $((COUNT * MIN_PCT / 100)) ]; then
		ok "$got/$COUNT answered under $LOSS loss (>= $MIN_PCT%)"
	else
		bad "${got:-0}/$COUNT answered under $LOSS loss (< $MIN_PCT%)"
	fi

	sleep 3

	if docker exec "$LAB-l" ping -c3 -W2 "$fip" >/dev/null; then
		ok "the link answers after the loss"
	else
		bad "the link is dead after the loss"
	fi

	if t l dump connections 2>/dev/null | grep -q "^founder .*transport $CARRIER"; then
		ok "still on $CARRIER"
	else
		bad "no longer on $CARRIER"
	fi

	dials=$(docker exec "$LAB-l" grep -c "Dialling founder" /tmp/tincd.log)
	if [ "$dials" -le 1 ]; then
		ok "the leaf dialled once"
	else
		bad "the leaf dialled $dials times"
	fi

	asan_check f
	asan_check l
	cleanup_nodes
}

sec_qpack() {
	echo "== qpack: $CONNS connections x $REQS requests with a dynamic table, loss $LOSS + 10 ms both ways"
	founder
	docker run -d --name "$LAB-p" --network "$NET" --ip "$SUBNET.20" --cap-add NET_ADMIN \
		-v "$HERE/quic_qpack_load.py:/load.py:ro" "$PROBER" sleep infinity >/dev/null
	netem "$LAB-f" on
	netem "$LAB-p" on
	out=$(docker exec "$LAB-p" python3 /load.py "$SUBNET.10" 443 "$CONNS" "$REQS" 2>&1)
	netem "$LAB-f" off
	netem "$LAB-p" off
	echo "$out" | sed 's/^/    /' | head -"$((CONNS + 5))"

	if echo "$out" | grep -q "answered 0/" || ! echo "$out" | grep -q "answered"; then
		bad "a connection got no answer"
	else
		ok "every connection was answered"
	fi

	if t f pid >/dev/null 2>&1; then
		ok "tincd still runs"
	else
		bad "tincd died"
		docker exec "$LAB-f" tail -20 /tmp/tincd.log
	fi

	asan_check f
	cleanup_nodes
}

cleanup_nodes() {
	docker rm -f "$LAB-f" "$LAB-l" "$LAB-p" >/dev/null 2>&1
}

echo "image $IMG, lab $LAB on $SUBNET.0/24"
for s in ${ONLY:-meta qpack}; do
	"sec_$s"
done

[ "$fail" = 0 ] && echo "PASS" || echo "FAIL"
exit "$fail"

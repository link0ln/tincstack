#!/usr/bin/env bash
# The quic dialler's second flight on a slow client, next to curl on the same
# budget (PLAN.md, "The second flight on a slow client (Android emulator)").
#
# On the Android emulator (~25 ms per server datagram) our dialler's Finished
# mostly left without an Initial: a 50-byte Handshake-only datagram, then the
# Finished unpadded -- where on a fast client it is curl's 1200-byte
# Initial+Handshake datagram. Whether OpenSSL (curl) does the same when it is
# that slow was never measured, because there is no curl on the phone. Here
# both run on Linux under the same CPU quota (docker --cpus) against one
# founder, DIALS connections each, and quic_initial.py (as an observer, no
# keys) prints, per connection, the packet types of the client's datagrams
# up to the first one that carries a Handshake packet.
#
# It reports; it does not pass or fail.
#
# Usage: flock /tmp/tincstack-lab.lock testing/fingerprint/slow-client-flight.sh [outdir]
#   env: CORE_IMAGE, CPUS (default "0.03 1"), DIALS (default 6)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
PY="${PYTHON_IMAGE:-python:3.12-slim}"
PFX=wwfs
NET=${PFX}net
SUBNET=10.49.68
F_IP=$SUBNET.10
L_IP=$SUBNET.11
C_IP=$SUBNET.12
Y=/c/tinc.yaml
CPUS=${CPUS:-0.03 1}
DIALS=${DIALS:-6}
OUT=${1:-$HERE/results/$(date +%Y%m%d-%H%M%S)-slow-client}
RUN="$HERE/run-slow-client"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
cleanup() {
	docker rm -f "$PFX-f" "$PFX-l" "$PFX-cap" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup
[[ -n ${KEEP:-} ]] || trap 'cleanup; docker run --rm -v "$HERE:/h" "$TOOLS" rm -rf /h/run-slow-client >/dev/null 2>&1' EXIT
mkdir -p "$RUN" "$OUT"
t() { local n=$1; shift; docker exec "$PFX-$n" tinc -n lab -c "$Y" "$@"; }

docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null || exit 2
docker run -d --name "$PFX-f" --network "$NET" --ip "$F_IP" --cap-add NET_ADMIN --device /dev/net/tun \
	"$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
docker exec "$PFX-f" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
docker exec -d "$PFX-f" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
for _ in $(seq 20); do t f pid >/dev/null 2>&1 && break; sleep 1; done
t f set founder.Address "$F_IP"

: > "$OUT/slow-client.txt"
idx=0
for cpu in $CPUS; do
	idx=$(( idx + 1 ))
	log "=== CPU quota $cpu ==="
	docker rm -f "$PFX-l" "$PFX-cap" >/dev/null 2>&1
	docker run -d --name "$PFX-l" --network "$NET" --ip "$L_IP" --cpus "$cpu" --cap-add NET_ADMIN \
		--device /dev/net/tun "$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
	t l join "$(t f invite "leaf$idx")" >/dev/null 2>&1
	t l set PreferredTransports quic
	docker run -d --name "$PFX-cap" --network "container:$PFX-f" -v "$RUN:/r" "$TOOLS" \
		tcpdump -i eth0 -U -w "/r/c-$cpu.pcap" udp port 443 >/dev/null
	sleep 2
	for i in $(seq "$DIALS"); do
		docker exec -d "$PFX-l" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
		for _ in $(seq 60); do t l dump connections 2>/dev/null | grep -q "^founder .*transport quic" && break; sleep 1; done
		t l stop >/dev/null 2>&1
		sleep 2
		docker run --rm --network "$NET" --ip "$C_IP" --cpus "$cpu" "$TOOLS" \
			curl -sk -m 30 -o /dev/null --http3-only "https://$F_IP/" || true
		log "dial $i done"
	done
	sleep 1
	docker stop -t 2 "$PFX-cap" >/dev/null
	docker run --rm -v "$HERE/../transports:/p:ro" -v "$RUN:/r" "$PY" python3 -B /p/quic_initial.py "/r/c-$cpu.pcap" \
		> "$RUN/dg-$cpu.txt"
	{
		echo "== CPU quota $cpu: client datagrams up to the first with a Handshake packet, per connection =="
		echo "   (udp length:packet types:Length fields; a fast client sends ... 1200:IHS or IH as the Finished)"
		awk -F'\t' -v l="$L_IP" -v c="$C_IP" '
			{ k = $1 ":" $7; who = ($1 == l ? "ours" : ($1 == c ? "curl" : $1)) }
			done[k] { next }
			{ seq[k] = seq[k] " " $2 ":" $3 ":" $4; w[k] = who; if(!(k in ord)) ord[k] = ++n }
			$3 ~ /H/ { done[k] = 1; fin[k] = $3 ($3 ~ /^I/ ? "(with Initial)" : "(NO Initial)") }
			END { for(k in ord) printf "%d\t%s\t%s\t%s\n", ord[k], w[k], fin[k], seq[k] }' "$RUN/dg-$cpu.txt" |
			sort -n | cut -f2-
		echo "-- tally: who, first Handshake-carrying datagram --"
		awk -F'\t' -v l="$L_IP" -v c="$C_IP" '
			{ k = $1 ":" $7 } done[k] { next }
			$3 ~ /H/ { done[k] = 1; print ($1 == l ? "ours" : "curl"), ($3 ~ /^I/ ? "Initial+Handshake" : "Handshake-only") }' \
			"$RUN/dg-$cpu.txt" | sort | uniq -c
		echo "-- tally: who, Initial-only datagrams before the first Handshake-carrying one --"
		awk -F'\t' -v l="$L_IP" '
			{ k = $1 ":" $7 } done[k] { next }
			$3 ~ /H/ { done[k] = 1; print ($1 == l ? "ours" : "curl"), n[k] + 0, "Initial-only datagrams"; next }
			{ n[k]++ }' "$RUN/dg-$cpu.txt" | sort | uniq -c
		echo
	} >> "$OUT/slow-client.txt"
done
cat "$OUT/slow-client.txt"
log "results in $OUT"

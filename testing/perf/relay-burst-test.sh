#!/usr/bin/env bash
# Does a relay lose packets when it forwards UDP bursts onto an https link?
#
#   sender --(UDP, SPTPS)--> relay --(https carrier)--> receiver
#
# The relay reads its UDP socket with recvmmsg(), up to 64 packets per call,
# and forwards every one of them to the receiver in the same event-loop pass.
# The receiver's link is TCP (https): each packet is appended to that
# connection's outbuf, and random_early_drop() discards packets once more
# than maxoutbufsize / 2 bytes are pending there. A carrier that writes only
# from the event loop lets a whole batch pile up before the first byte leaves;
# one that writes on every append keeps the queue short but splits every
# packet into two TLS records. This is the production shape of a phone on the
# https carrier downloading through ruvds2 from the quic-connected exit.
#
# Each core image in CORES gets the same lab, one after another, REPEATS
# times interleaved: a UDP load at RATE (receiver-side loss is the finding)
# and a TCP load (achieved rate). Sender and receiver share no network, so
# the relay is the only path; the script checks that the receiver's link is
# https and that the sender reaches the relay over UDP.
#
# On a LAN nothing is a bottleneck and every loss is the daemon's own; the
# phone's link is not a LAN. DELAY and LIMIT put netem on the relay <->
# receiver leg (DELAY each way, LIMIT on the relay's side towards the
# receiver), so the relay's https queue backs up the way it does in the field
# and a drop costs the inner TCP what it costs on a real RTT.
#
# Usage: flock /tmp/tincstack-lab.lock testing/perf/relay-burst-test.sh [outdir]
#   env: CORES (space-separated name=image, default the dev image),
#        RATE (UDP offered, default 300M), DGRAM (UDP payload, 1300),
#        SECONDS_RUN (10), REPEATS (3), TOOLS_IMAGE (iperf3; nicolaka/netshoot),
#        DELAY (netem delay each way on relay <-> receiver, e.g. 20ms),
#        LIMIT (netem rate relay -> receiver, e.g. 50mbit)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORES=${CORES:-dev=tincstack/core:${TINCSTACK_TAG:-dev}}
TOOLS=${TOOLS_IMAGE:-nicolaka/netshoot}
RATE=${RATE:-300M}
DGRAM=${DGRAM:-1300}
SECONDS_RUN=${SECONDS_RUN:-10}
REPEATS=${REPEATS:-3}
PFX=wwrb
N1=10.49.71
N2=10.49.72
Y=/c/tinc.yaml
OUT=${1:-$HERE/results/$(date +%Y%m%d-%H%M%S)-relay-burst}

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
cleanup() {
	docker rm -f "$PFX-r" "$PFX-s" "$PFX-d" "$PFX-is" "$PFX-id" >/dev/null 2>&1 || true
	docker network rm "${PFX}1" "${PFX}2" >/dev/null 2>&1 || true
}
trap cleanup EXIT
t() { local n=$1; shift; docker exec "$PFX-$n" tinc -n lab -c "$Y" "$@"; }
mkdir -p "$OUT"

# <image>: relay on both networks, sender on 1, receiver on 2; prints nothing, fails if the paths are wrong
lab_up() {
	cleanup
	docker network create --internal --subnet "$N1.0/24" "${PFX}1" >/dev/null || return 1
	docker network create --internal --subnet "$N2.0/24" "${PFX}2" >/dev/null || return 1
	docker run -d --name "$PFX-r" --network "${PFX}1" --ip "$N1.10" --cap-add NET_ADMIN --device /dev/net/tun \
		"$1" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
	docker network connect --ip "$N2.10" "${PFX}2" "$PFX-r"
	if [[ -n ${DELAY:-}${LIMIT:-} ]]; then
		local rif
		rif=$(docker exec "$PFX-r" ip -o -4 addr show | awk -v ip="$N2.10/" 'index($4, ip) == 1 {print $2}')
		# shellcheck disable=SC2086  # deliberate word split into netem arguments
		docker exec "$PFX-r" tc qdisc add dev "$rif" root netem ${DELAY:+delay $DELAY} ${LIMIT:+rate $LIMIT} limit 1000 || return 1
	fi
	docker run -d --name "$PFX-s" --network "${PFX}1" --ip "$N1.11" --cap-add NET_ADMIN --device /dev/net/tun \
		"$1" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
	docker run -d --name "$PFX-d" --network "${PFX}2" --ip "$N2.11" --cap-add NET_ADMIN --device /dev/net/tun \
		"$1" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
	if [[ -n ${DELAY:-} ]]; then
		docker exec "$PFX-d" tc qdisc add dev eth0 root netem delay "$DELAY" limit 1000 || return 1
	fi
	docker exec "$PFX-r" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name relay && tinc -n lab -c $Y set Port 655"
	docker exec -d "$PFX-r" sh -c "tincd -n lab -c $Y -D -d1 >>/tmp/tincd.log 2>&1"
	for _ in $(seq 20); do t r pid >/dev/null 2>&1 && break; sleep 1; done
	# Each invitation carries the relay's address on the invitee's own network.
	t r set relay.Address "$N1.10"
	t s join "$(t r invite sender)" >/dev/null 2>&1 || return 1
	t r set relay.Address "$N2.10"
	t d join "$(t r invite receiver)" >/dev/null 2>&1 || return 1
	t d set PreferredTransports https
	docker exec -d "$PFX-s" sh -c "tincd -n lab -c $Y -D -d1 >>/tmp/tincd.log 2>&1"
	docker exec -d "$PFX-d" sh -c "tincd -n lab -c $Y -D -d1 >>/tmp/tincd.log 2>&1"
	dv=""
	for _ in $(seq 60); do
		dv=$(docker exec "$PFX-d" ip -4 -br addr show lab 2>/dev/null | awk '{print $3}' | cut -d/ -f1)
		[[ -n $dv ]] && docker exec "$PFX-s" ping -c1 -W1 "$dv" >/dev/null 2>&1 && break
		sleep 0.5
	done
	[[ -n $dv ]] || return 1
	# Warm up until the sender has its SPTPS key with the receiver and a UDP path to the relay.
	for _ in $(seq 30); do
		docker exec "$PFX-s" ping -c3 -i0.2 -W1 "$dv" >/dev/null 2>&1
		t s info relay 2>/dev/null | grep -q udp_confirmed && break
		sleep 1
	done
	link=$(t d dump connections 2>/dev/null | awk '/^relay /{for(i=1;i<=NF;i++) if($i=="transport") print $(i+1)}')
	up=$(t s info relay 2>/dev/null | grep -c udp_confirmed)
	log "receiver link: ${link:-none}; sender->relay udp_confirmed: $up; receiver tunnel IP $dv"
	[[ $link == https && $up == 1 ]] || return 1
	docker run -d --name "$PFX-id" --network "container:$PFX-d" "$TOOLS" iperf3 -s >/dev/null
	sleep 1
}

# <name> <repeat>: one UDP and one TCP load; appends CSV rows
measure() {
	local j
	j=$(docker run --rm --name "$PFX-is" --network "container:$PFX-s" "$TOOLS" \
		iperf3 -c "$dv" -u -b "$RATE" -l "$DGRAM" -t "$SECONDS_RUN" -J 2>/dev/null)
	printf '%s' "$j" | python3 -c '
import json, sys
d = json.load(sys.stdin)["end"]["sum"]
print("%s,%s,udp,%s,%.1f,%.2f" % (sys.argv[1], sys.argv[2], sys.argv[3], d["bits_per_second"] / 1e6, d.get("lost_percent", 0.0)))
' "$1" "$2" "$RATE" >> "$OUT/relay-burst.csv" || echo "$1,$2,udp,$RATE,fail,fail" >> "$OUT/relay-burst.csv"
	sleep 1
	j=$(docker run --rm --name "$PFX-is" --network "container:$PFX-s" "$TOOLS" \
		iperf3 -c "$dv" -t "$SECONDS_RUN" -J 2>/dev/null)
	printf '%s' "$j" | python3 -c '
import json, sys
e = json.load(sys.stdin)["end"]
print("%s,%s,tcp,-,%.1f,%d" % (sys.argv[1], sys.argv[2], e["sum_received"]["bits_per_second"] / 1e6, e["sum_sent"].get("retransmits", 0)))
' "$1" "$2" >> "$OUT/relay-burst.csv" || echo "$1,$2,tcp,-,fail,fail" >> "$OUT/relay-burst.csv"
}

echo "core,repeat,load,offered,mbits,loss_pct_or_retransmits" > "$OUT/relay-burst.csv"
echo "relay <-> receiver: delay ${DELAY:-none} each way, rate ${LIMIT:-unlimited}; UDP offered $RATE; ${SECONDS_RUN} s per load" > "$OUT/conditions.txt"
: > "$OUT/images.txt"
for c in $CORES; do
	echo "${c%%=*} ${c#*=} $(docker image inspect "${c#*=}" --format '{{.Id}}')" >> "$OUT/images.txt"
done
for i in $(seq "$REPEATS"); do
	for c in $CORES; do
		name=${c%%=*} img=${c#*=}
		log "=== $name ($img), repeat $i ==="
		if ! lab_up "$img"; then
			log "lab did not come up for $name"
			echo "$name,$i,lab,-,fail,fail" >> "$OUT/relay-burst.csv"
			continue
		fi
		measure "$name" "$i"
		t r info receiver 2>/dev/null | grep -E 'Status|Reachability' | sed "s|^|$name $i relay->receiver |" >> "$OUT/paths.txt"
		t s info receiver 2>/dev/null | grep -E 'Status|Reachability' | sed "s|^|$name $i sender->receiver |" >> "$OUT/paths.txt"
	done
done
cleanup
# The summary: per core and load, the median over the repeats.
python3 - "$OUT/relay-burst.csv" <<-'PYEOF' | tee "$OUT/relay-burst.report.txt"
	import csv, statistics, sys
	rows = [r for r in csv.DictReader(open(sys.argv[1])) if r["mbits"] != "fail"]
	keys = sorted({(r["core"], r["load"]) for r in rows}, key=lambda k: (k[1], k[0]))
	print("core        load  n  Mbit/s (median, all)                 loss % (udp) / retransmits (tcp), median")
	for core, load in keys:
	    rs = [r for r in rows if r["core"] == core and r["load"] == load]
	    mb = [float(r["mbits"]) for r in rs]
	    x = [float(r["loss_pct_or_retransmits"]) for r in rs]
	    print("%-11s %-4s %2d  %7.1f  %-28s %8.2f" % (core, load, len(rs), statistics.median(mb),
	          " ".join("%.1f" % v for v in mb), statistics.median(x)))
PYEOF
cat "$OUT/conditions.txt" >> "$OUT/relay-burst.report.txt"
log "results in $OUT"

#!/usr/bin/env bash
# obfs wire audit: does the obfs carrier look like uniformly random UDP?
#
# obfs claims no protocol, so the reference is noise: every byte position
# uniform, sizes that do not repeat, no timing a classifier can key on,
# nothing answered to a probe. This lab captures a founder and a leaf on
# obfs and measures that, once with the shipped defaults (no junk, no header
# junk, no magic) and once shaped (junk datagrams, handshake/transport header
# junk), each through:
#
#   handshake  the leaf's first dial
#   ping       56- and 1000-byte pings, 20 each, then 2x2000 flood pings (the
#              bulk sample for per-position byte statistics)
#   idle       IDLE seconds with nothing in the tunnel (PingInterval,
#              PMTU re-probes, obfs rekeys every KeyExpire=REKEY seconds)
#   restarts   RESTARTS leaf restarts, each a fresh obfs handshake
#   probes     a stranger sends random, zero, tinc-looking and replayed
#              datagrams to UDP 655 and opens TCP 655: what answers?
#
# The captures stay in the run directory (not committed); obfs_stats.py
# reduces them to the numbers in the summary. It reports; it does not pass
# or fail.
#
# Usage: flock /tmp/tincstack-lab.lock testing/fingerprint/obfs-audit.sh [outdir]
#   env: CORE_IMAGE, IDLE (default 150), RESTARTS (default 6), REKEY (default 30),
#        CONFIGS (default "default shaped")
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
PROBER="${PROBER_IMAGE:-tincstack/fp-prober:ww-f}"
PFX=wwfo
NET=${PFX}net
SUBNET=10.49.66
F_IP=$SUBNET.10
L_IP=$SUBNET.11
P_IP=$SUBNET.20
Y=/c/tinc.yaml
IDLE=${IDLE:-150}
RESTARTS=${RESTARTS:-6}
REKEY=${REKEY:-30}
CONFIGS=${CONFIGS:-default shaped}
OUT=${1:-$HERE/results/$(date +%Y%m%d-%H%M%S)-obfs}
RUN="$HERE/run-obfs-audit"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
cleanup() {
	docker rm -f "$PFX-f" "$PFX-l" "$PFX-p" "$PFX-cap" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup
[[ -n ${KEEP:-} ]] || trap 'cleanup; docker run --rm -v "$HERE:/h" "$TOOLS" rm -rf /h/run-obfs-audit >/dev/null 2>&1' EXIT
docker run --rm -v "$HERE:/h" "$TOOLS" rm -rf /h/run-obfs-audit >/dev/null 2>&1 || true
mkdir -p "$RUN" "$OUT"

t() { local n=$1; shift; docker exec "$PFX-$n" tinc -n lab -c "$Y" "$@"; }
mark() { printf '%s\t%s\t%s\n' "$1" "$2" "$(date +%s.%N)" >> "$RUN/phases.tsv"; }
on_obfs() { t l dump connections 2>/dev/null | grep -q "^founder .*transport obfs"; }
start_leaf() { docker exec -d "$PFX-l" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"; }
wait_obfs() {
	for _ in $(seq 60); do on_obfs && return 0; sleep 1; done
	return 1
}

lab() { # <config>
	local cfg=$1 fv
	cleanup
	docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null || exit 2
	for n in f:$F_IP l:$L_IP; do
		docker run -d --name "$PFX-${n%%:*}" --network "$NET" --ip "${n#*:}" --cap-add NET_ADMIN \
			--device /dev/net/tun "$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
	done
	docker run -d --name "$PFX-p" --network "$NET" --ip "$P_IP" -v "$HERE:/h:ro" "$PROBER" sleep infinity >/dev/null
	docker exec "$PFX-f" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
	t f set KeyExpire "$REKEY"
	if [[ $cfg == shaped ]]; then
		t f set ObfsJunkPacketCount 4
		t f set ObfsJunkPacketMinSize 40
		t f set ObfsJunkPacketMaxSize 200
		t f set ObfsInitHeaderJunkSize 64
		t f set ObfsTransportHeaderJunkSize 16
	fi
	docker exec -d "$PFX-f" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
	for _ in $(seq 20); do t f pid >/dev/null 2>&1 && break; sleep 1; done
	t f set founder.Address "$F_IP"
	t l join "$(t f invite leaf)" >/dev/null 2>&1
	t l set PreferredTransports obfs
	t l set KeyExpire "$REKEY"
	docker run -d --name "$PFX-cap" --network "container:$PFX-f" -v "$RUN:/r" "$TOOLS" \
		tcpdump -i eth0 -U -w "/r/$cfg.pcap" 'udp or tcp port 655' >/dev/null
	sleep 2

	: > "$RUN/phases.tsv"
	mark "$cfg" handshake
	start_leaf
	wait_obfs || log "$cfg: the leaf did not reach obfs: $(t l dump connections 2>&1 | grep founder)"
	fv=$(docker exec "$PFX-f" ip -4 -br addr show lab | awk '{print $3}' | cut -d/ -f1)
	for _ in $(seq 20); do docker exec "$PFX-l" ping -c1 -W1 "$fv" >/dev/null 2>&1 && break; done
	mark "$cfg" ping
	docker exec "$PFX-l" ping -c20 -i0.2 -s56 "$fv" > "$RUN/$cfg-ping.txt" 2>&1
	docker exec "$PFX-l" ping -c20 -i0.2 -s1000 "$fv" >> "$RUN/$cfg-ping.txt" 2>&1
	mark "$cfg" bulk
	docker exec "$PFX-l" ping -f -c2000 -s1000 "$fv" >> "$RUN/$cfg-ping.txt" 2>&1
	docker exec "$PFX-l" ping -f -c2000 -s64 "$fv" >> "$RUN/$cfg-ping.txt" 2>&1
	mark "$cfg" idle
	sleep "$IDLE"
	for i in $(seq "$RESTARTS"); do
		t l stop >/dev/null 2>&1
		sleep 3
		mark "$cfg" "restart$i"
		start_leaf
		wait_obfs || log "$cfg: restart $i did not reach obfs"
		sleep 5
	done
	mark "$cfg" probes
	docker exec -i "$PFX-p" python3 - "$F_IP" > "$RUN/$cfg-probes.txt" 2>&1 <<-'EOF'
		import os, socket, sys
		host = sys.argv[1]
		def udp(name, payload):
		    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.5)
		    s.sendto(payload, (host, 655)); got = []
		    try:
		        while True: got.append(len(s.recvfrom(65535)[0]))
		    except socket.timeout: pass
		    print("udp %-22s %s" % (name, got or "silence")); s.close()
		for n in (1, 16, 40, 100, 200, 600, 1200, 1400):
		    udp("random-%d" % n, os.urandom(n))
		udp("zeros-100", bytes(100))
		udp("sptps-shaped-100", bytes(6) + os.urandom(94))   # direct datagram: dst id 0
		udp("obfs-shaped-100", os.urandom(8) + (90).to_bytes(2, "big") + os.urandom(90))
		def tcp(name, payload):
		    s = socket.create_connection((host, 655), timeout=3); got = b""
		    try:
		        if payload: s.sendall(payload)
		        got = s.recv(4096)
		    except (socket.timeout, OSError) as e: got = ("<%s>" % type(e).__name__).encode()
		    print("tcp %-22s %r" % (name, got[:60])); s.close()
		tcp("silent", b"")
		tcp("tinc-id", b"0 prober 17.7\n")
		tcp("http-get", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	EOF
	# replay: the leaf's first datagrams of its last handshake, sent again by
	# the stranger (an active prober that recorded the flow) -- one by one,
	# 6 s apart (the bootstrap window may restart once per 5 s)
	mark "$cfg" replay
	last=$(awk -F'\t' '$2 ~ /^restart/ { t = $3 } END { print t }' "$RUN/phases.tsv")
	docker run --rm -v "$RUN:/r" "$TOOLS" tshark -r "/r/$cfg.pcap" -Y "ip.src == $L_IP && udp && frame.time_epoch > $last" \
		-T fields -e udp.payload 2>/dev/null | head -6 > "$RUN/$cfg-replay.hex"
	docker exec -i "$PFX-p" python3 -c '
import socket, sys, time
host = sys.argv[1]
for i, h in enumerate(l.strip() for l in sys.stdin):
    if not h:
        continue
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    s.sendto(bytes.fromhex(h), (host, 655)); got = []
    try:
        while True: got.append(len(s.recvfrom(65535)[0]))
    except socket.timeout: pass
    print("udp replay-%d-%dB %s" % (i + 1, len(h) // 2, got or "silence")); s.close(); time.sleep(6)
' "$F_IP" < "$RUN/$cfg-replay.hex" >> "$RUN/$cfg-probes.txt" 2>&1
	mark "$cfg" end
	sleep 1
	docker stop -t 2 "$PFX-cap" >/dev/null
	cp "$RUN/phases.tsv" "$RUN/$cfg-phases.tsv"
	docker exec "$PFX-f" grep -cE 'obfs junk datagram|Cold-classified' /tmp/tincd.log > "$RUN/$cfg-founder-log-counts.txt" 2>&1 || true
	t l dump connections > "$RUN/$cfg-connections.txt" 2>&1 || true
}

for cfg in $CONFIGS; do
	log "=== obfs, $cfg configuration ==="
	lab "$cfg"
	docker run --rm -v "$RUN:/r" "$TOOLS" tshark -r "/r/$cfg.pcap" -Y udp -T fields \
		-e frame.time_epoch -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e udp.length -e udp.payload \
		> "$RUN/$cfg-udp.tsv" 2>/dev/null
	docker run --rm -v "$HERE:/h:ro" -v "$RUN:/r" "$PROBER" python3 /h/obfs_stats.py \
		"/r/$cfg-udp.tsv" "/r/$cfg-phases.tsv" "$F_IP" "$L_IP" > "$OUT/obfs-$cfg.txt"
	{ echo "--- probes (a stranger at $P_IP) ---"; cat "$RUN/$cfg-probes.txt"
	  echo "--- leaf's connection at the end ---"; cat "$RUN/$cfg-connections.txt"
	  echo "--- ping summary ---"; grep -E 'packets transmitted|rtt' "$RUN/$cfg-ping.txt"; } >> "$OUT/obfs-$cfg.txt"
	cat "$OUT/obfs-$cfg.txt"
done
docker image inspect "$IMG" --format "image $IMG {{.Id}}" > "$OUT/obfs-setup.txt"
log "results in $OUT"

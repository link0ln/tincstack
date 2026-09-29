#!/usr/bin/env bash
# T1c: can an observer link our sessions to a node across sessions?
#
# The handshakes are curl's and nginx's; a censor that cannot block the
# protocol can still follow one user from address to address if every
# session of that user carries a size, gap or length nobody else's does.
# Two leaves with names of different length ("leaf", 4 characters, and
# "leafwithaverylongname01", 23) dial the founder SESSIONS times each over
# every carrier in CARRIERS, interleaved. Each session is its own capture:
# the dial, five pings of known sizes (64..1200 B), then IDLE seconds of
# nothing, then the leaf's daemon stops. Reference: two identical curl
# clients (two "users") fetch the nginx page SESSIONS times each over
# HTTP/1.1+TLS and over HTTP/3, from their own addresses.
#
# linkability.py reduces the captures (SameSizes, SameGaps,
# LengthTracksPayload); see its docstring for what each one means. It
# reports; it does not pass or fail.
#
# Usage: flock /tmp/tincstack-lab.lock testing/fingerprint/linkability-audit.sh [outdir]
#   env: CORE_IMAGE, NGINX_IMAGE, TOOLS_IMAGE, PROBER_IMAGE,
#        CARRIERS (default "https quic obfs"), SESSIONS (6), IDLE (65), K (24),
#        KEEP=1, KEEP_PCAP=1 (copy the captures to outdir)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
NGINX="${NGINX_IMAGE:-tincstack/nginx-deb13:dev}"
PROBER="${PROBER_IMAGE:-tincstack/fp-prober:ww-n2}"
PFX=wwlk
NET=${PFX}net
SUBNET=10.49.74
F_IP=$SUBNET.10
N_IP=$SUBNET.13
Y=/c/tinc.yaml
CARRIERS=${CARRIERS:-https quic obfs}
SESSIONS=${SESSIONS:-6}
IDLE=${IDLE:-65}
K=${K:-24}
OUT=${1:-$HERE/results/$(date +%Y%m%d-%H%M%S)-linkability}
RUN="$HERE/run-linkability"
# node key: container suffix, tinc name, address
NODES="a:leaf:$SUBNET.11 b:leafwithaverylongname01:$SUBNET.12"
USERS="u:$SUBNET.20 v:$SUBNET.21"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
cleanup() {
	docker rm -f "$PFX-f" "$PFX-a" "$PFX-b" "$PFX-n" "$PFX-u" "$PFX-v" "$PFX-cap" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup
[[ -n ${KEEP:-} ]] || trap 'cleanup; docker run --rm -v "$HERE:/h" "$TOOLS" rm -rf /h/run-linkability >/dev/null 2>&1' EXIT
docker run --rm -v "$HERE:/h" "$TOOLS" rm -rf /h/run-linkability >/dev/null 2>&1 || true
mkdir -p "$RUN/n/html" "$RUN/s" "$OUT"
printf 'name\tkind\tnode\tnode_ip\tserver_ip\tport\tt_start\tt_idle\tt_stop\tpings...\n' > "$RUN/sessions.tsv"
t() { local n=$1; shift; docker exec "$PFX-$n" tinc -n lab -c "$Y" "$@"; }
now() { date +%s.%N; }

cap_start() { # <netns container> <host> <name>
	docker rm -f "$PFX-cap" >/dev/null 2>&1
	docker run -d --name "$PFX-cap" --network "container:$PFX-$1" -v "$RUN:/r" "$TOOLS" \
		tcpdump -i eth0 -U -w "/r/s/$3.pcap" host "$2" >/dev/null
	sleep 1.5
}
cap_stop() { sleep 1; docker stop -t 2 "$PFX-cap" >/dev/null; }

# ---- lab ----------------------------------------------------------------------------------------------
docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null || exit 2
docker run -d --name "$PFX-f" --network "$NET" --ip "$F_IP" --cap-add NET_ADMIN --device /dev/net/tun \
	"$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
for n in $NODES; do
	IFS=: read -r s _ ip <<< "$n"
	docker run -d --name "$PFX-$s" --network "$NET" --ip "$ip" --cap-add NET_ADMIN --device /dev/net/tun \
		"$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
done
docker exec "$PFX-f" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
docker exec -d "$PFX-f" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
for _ in $(seq 20); do t f pid >/dev/null 2>&1 && break; sleep 1; done
t f set founder.Address "$F_IP"
for n in $NODES; do
	IFS=: read -r s name _ <<< "$n"
	t "$s" join "$(t f invite "$name")" >/dev/null 2>&1 || { log "join $name failed"; exit 2; }
done
for _ in $(seq 20); do docker exec "$PFX-f" grep -q '^      tls_key: |' "$Y" && break; sleep 1; done
fv=$(docker exec "$PFX-f" ip -4 -br addr show lab | awk '{print $3}' | cut -d/ -f1)

# The reference web server wears the founder's certificate, as in carrier-traffic-audit.sh.
pem() {
	docker exec "$PFX-f" sh -c "awk '/^      $1: \\|/{f=1;next} f&&/^      [a-z_]+:/{f=0} f' $Y | sed 's/^        //' | sed -n '/BEGIN $2/,/END $2/p'"
}
pem tls_cert CERTIFICATE > "$RUN/n/cert.pem"
pem tls_key "PRIVATE KEY" > "$RUN/n/key.pem"
chmod 644 "$RUN/n/"*.pem
cat > "$RUN/n/default.conf" <<-'EOF'
	server {
	    listen 443 quic reuseport;
	    listen 443 ssl;
	    ssl_certificate     /n/cert.pem;
	    ssl_certificate_key /n/key.pem;
	    location / { root /usr/share/nginx/html; }
	}
EOF
docker run -d --name "$PFX-n" --network "$NET" --ip "$N_IP" -v "$RUN/n:/n:ro" \
	-v "$RUN/n/default.conf:/etc/nginx/conf.d/default.conf:ro" "$NGINX" >/dev/null
for u in $USERS; do
	docker run -d --name "$PFX-${u%%:*}" --network "$NET" --ip "${u#*:}" "$TOOLS" sleep infinity >/dev/null
done
sleep 2

# ---- ours ---------------------------------------------------------------------------------------------
for i in $(seq "$SESSIONS"); do
	for carrier in $CARRIERS; do
		case $carrier in obfs) port=655 ;; *) port=443 ;; esac
		for n in $NODES; do
			IFS=: read -r s name ip <<< "$n"
			sess="$carrier-$s-$i"
			log "=== $sess ($name over $carrier) ==="
			t "$s" set PreferredTransports "$carrier" 2>/dev/null
			cap_start f "$ip" "$sess"
			t0=$(now)
			docker exec -d "$PFX-$s" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
			for _ in $(seq 60); do
				t "$s" dump connections 2>/dev/null | grep -q "^founder .*transport $carrier" &&
					docker exec "$PFX-$s" ping -c1 -W1 "$fv" >/dev/null 2>&1 && break
				sleep 0.5
			done
			got=$(t "$s" dump connections 2>/dev/null | awk '/^founder /{for(i=1;i<=NF;i++) if($i=="transport") print $(i+1)}')
			[[ $got == "$carrier" ]] || log "$sess: link is '${got:-none}', not $carrier"
			pings=()
			for size in 64 300 600 900 1200; do
				pings+=("$size@$(now)")
				docker exec "$PFX-$s" ping -c1 -W1 -s "$size" "$fv" >/dev/null 2>&1
				sleep 0.4
			done
			ti=$(now)
			sleep "$IDLE"
			t1=$(now)
			t "$s" stop >/dev/null 2>&1
			sleep 2
			cap_stop
			{
				printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$sess" "$carrier" "$name" "$ip" "$F_IP" "$port" "$t0" "$ti" "$t1"
				printf '\t%s' "${pings[@]}"
				printf '\t%s\n' "link=${got:-none}"
			} >> "$RUN/sessions.tsv"
		done
	done
done

# ---- reference: two identical curl users, h1 and h3 ----------------------------------------------------
for i in $(seq "$SESSIONS"); do
	for v in h1:--http1.1 h3:--http3-only; do
		for u in $USERS; do
			us=${u%%:*} ip=${u#*:} sess="ref-${v%%:*}-$us-$i"
			cap_start n "$ip" "$sess"
			t0=$(now)
			docker exec "$PFX-$us" curl -sk -m 20 "${v#*:}" -o /dev/null "https://$N_IP/" || log "$sess: curl failed"
			t1=$(now)
			cap_stop
			printf '%s\tref-%s\tuser-%s\t%s\t%s\t443\t%s\t%s\t%s\n' "$sess" "${v%%:*}" "$us" "$ip" "$N_IP" "$t0" "$t1" "$t1" >> "$RUN/sessions.tsv"
		done
	done
done

# ---- judge --------------------------------------------------------------------------------------------
for p in "$RUN"/s/*.pcap; do
	b=$(basename "$p" .pcap)
	docker run --rm -v "$RUN:/r" "$TOOLS" tshark -r "/r/s/$b.pcap" -T fields -E occurrence=a -E aggregator=, \
		-e frame.time_epoch -e ip.src -e ip.dst -e udp.length -e tls.record.content_type -e tls.record.length \
		-e tcp.port -e udp.port > "$RUN/s/$b.tsv" 2>/dev/null
done
docker run --rm -v "$HERE:/h:ro" -v "$RUN:/r" "$PROBER" python3 /h/linkability.py --k "$K" \
	--json /r/linkability.json /r/sessions.tsv /r/s > "$RUN/linkability.txt"
{
	echo "== cross-session linkability: $(date -u +%FT%TZ) =="
	echo "core $IMG $(docker image inspect "$IMG" --format '{{.Id}}')"
	echo "sessions per node and carrier: $SESSIONS; idle ${IDLE}s; first $K units compared"
	echo; cat "$RUN/linkability.txt"
	echo; echo "--- links as dialled ---"; awk -F'\t' 'NR > 1 && $2 !~ /^ref-/ {print $1, $3, $NF}' "$RUN/sessions.tsv"
} > "$OUT/linkability.report.txt"
cp "$RUN/sessions.tsv" "$RUN/linkability.json" "$OUT/"
[[ -n ${KEEP_PCAP:-} ]] && cp "$RUN"/s/*.pcap "$OUT/"
cat "$OUT/linkability.report.txt"
log "results in $OUT"

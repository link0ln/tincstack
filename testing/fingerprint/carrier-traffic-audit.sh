#!/usr/bin/env bash
# After the handshake: what do the https and quic carriers look like in use?
#
# The handshakes are audited elsewhere (quic-wire-test.sh,
# quic-listener-wire-test.sh, run.sh). This lab looks at everything after
# them -- TLS record sizes, QUIC datagram sizes, what an idle tunnel sends
# and when -- next to what curl and Debian 13's nginx produce for a
# comparable download and upload:
#
#   ours       founder <- leaf over `https`, then over `quic`; inside the
#              tunnel a plain HTTP download of SIZE bytes (founder -> leaf),
#              an upload of SIZE bytes (leaf -> founder), 20 pings at 1 s,
#              then IDLE seconds of nothing
#   reference  curl (fp-tools) against nginx 1.26.3 with the founder's
#              certificate: the same download and upload over HTTP/1.1+TLS
#              and HTTP/3; and a connection left idle for IDLE seconds after
#              one GET (openssl s_client over TCP; aioquic over QUIC), to see
#              what nginx sends and when it closes
#
# carrier_stats.py reduces the captures; the pcaps stay in the run directory.
# It reports; it does not pass or fail.
#
# Usage: flock /tmp/tincstack-lab.lock testing/fingerprint/carrier-traffic-audit.sh [outdir]
#   env: CORE_IMAGE, NGINX_IMAGE, IDLE (default 200), SIZE (default 20971520), CARRIERS
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
NGINX="${NGINX_IMAGE:-tincstack/nginx-deb13:dev}"
PROBER="${PROBER_IMAGE:-tincstack/fp-prober:ww-f}"
PFX=wwft
NET=${PFX}net
SUBNET=10.49.67
F_IP=$SUBNET.10
L_IP=$SUBNET.11
N_IP=$SUBNET.12
C_IP=$SUBNET.20
Y=/c/tinc.yaml
IDLE=${IDLE:-200}
SIZE=${SIZE:-20971520}
CARRIERS=${CARRIERS:-https quic}
OUT=${1:-$HERE/results/$(date +%Y%m%d-%H%M%S)-carrier-traffic}
RUN="$HERE/run-carrier-traffic"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
cleanup() {
	docker rm -f "$PFX-f" "$PFX-l" "$PFX-n" "$PFX-c" "$PFX-fs" "$PFX-lc" "$PFX-capf" "$PFX-capn" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup
[[ -n ${KEEP:-} ]] || trap 'cleanup; docker run --rm -v "$HERE:/h" "$TOOLS" rm -rf /h/run-carrier-traffic >/dev/null 2>&1' EXIT
docker run --rm -v "$HERE:/h" "$TOOLS" rm -rf /h/run-carrier-traffic >/dev/null 2>&1 || true
mkdir -p "$RUN/n/html" "$OUT"
: > "$RUN/phases.tsv"
mark() { printf '%s\t%s\n' "$1" "$(date +%s.%N)" >> "$RUN/phases.tsv"; }

docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null || exit 2
for n in f:$F_IP l:$L_IP; do
	docker run -d --name "$PFX-${n%%:*}" --network "$NET" --ip "${n#*:}" --cap-add NET_ADMIN \
		--device /dev/net/tun "$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
done
t() { local n=$1; shift; docker exec "$PFX-$n" tinc -n lab -c "$Y" "$@"; }
docker exec "$PFX-f" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
docker exec -d "$PFX-f" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
for _ in $(seq 20); do t f pid >/dev/null 2>&1 && break; sleep 1; done
t f set founder.Address "$F_IP"
t l join "$(t f invite leaf)" >/dev/null 2>&1
for _ in $(seq 20); do docker exec "$PFX-f" grep -q '^      tls_key: |' "$Y" && break; sleep 1; done
pem() {
	docker exec "$PFX-f" sh -c "awk '/^      $1: \\|/{f=1;next} f&&/^      [a-z_]+:/{f=0} f' $Y | sed 's/^        //' | sed -n '/BEGIN $2/,/END $2/p'"
}
pem tls_cert CERTIFICATE > "$RUN/n/cert.pem"
pem tls_key "PRIVATE KEY" > "$RUN/n/key.pem"
chmod 644 "$RUN/n/"*.pem
head -c "$SIZE" /dev/urandom > "$RUN/n/html/big"
chmod -R a+rX "$RUN/n"
cat > "$RUN/n/default.conf" <<-'EOF'
	server {
	    listen 443 quic reuseport;
	    listen 443 ssl;
	    ssl_certificate     /n/cert.pem;
	    ssl_certificate_key /n/key.pem;
	    client_max_body_size 100m;
	    location / { root /n/html; }
	    location /up/ { root /tmp; dav_methods PUT; create_full_put_path on; client_body_temp_path /tmp/body; }
	}
EOF
docker run -d --name "$PFX-n" --network "$NET" --ip "$N_IP" -v "$RUN/n:/n:ro" \
	-v "$RUN/n/default.conf:/etc/nginx/conf.d/default.conf:ro" "$NGINX" >/dev/null
docker run -d --name "$PFX-c" --network "$NET" --ip "$C_IP" -v "$HERE:/h:ro" "$PROBER" sleep infinity >/dev/null
for x in f n; do
	docker run -d --name "$PFX-cap$x" --network "container:$PFX-$x" -v "$RUN:/r" "$TOOLS" \
		tcpdump -i eth0 -U -w "/r/$x.pcap" 'port 443 or port 655' >/dev/null
done
sleep 2

# ---- ours ------------------------------------------------------------------------------------------
for carrier in $CARRIERS; do
	log "=== ours over $carrier ==="
	t l set PreferredTransports "$carrier"
	mark "$carrier-handshake"
	docker exec -d "$PFX-l" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
	for _ in $(seq 40); do t l dump connections 2>/dev/null | grep -q "^founder .*transport $carrier" && break; sleep 1; done
	t l dump connections 2>&1 | grep '^founder' > "$RUN/$carrier-connection.txt"
	fv=$(docker exec "$PFX-f" ip -4 -br addr show lab | awk '{print $3}' | cut -d/ -f1)
	for _ in $(seq 20); do docker exec "$PFX-l" ping -c1 -W1 "$fv" >/dev/null 2>&1 && break; done
	t l info founder 2>&1 | grep -E 'PMTU|Status' >> "$RUN/$carrier-connection.txt"
	docker rm -f "$PFX-fs" "$PFX-lc" >/dev/null 2>&1
	docker run -d --name "$PFX-fs" --network "container:$PFX-f" -v "$HERE:/h:ro" "$PROBER" \
		python3 /h/bulk_server.py "$fv" 8000 "$SIZE" >/dev/null
	docker run -d --name "$PFX-lc" --network "container:$PFX-l" "$TOOLS" sleep infinity >/dev/null
	sleep 2
	mark "$carrier-down"
	docker exec "$PFX-lc" curl -s -m 300 -o /dev/null -w "$carrier down %{http_code} %{size_download} B %{time_total} s\n" \
		"http://$fv:8000/big" >> "$RUN/transfers.txt"
	mark "$carrier-up"
	docker exec "$PFX-lc" sh -c "head -c $SIZE /dev/urandom > /tmp/up && curl -s -m 300 -o /dev/null -X POST --data-binary @/tmp/up \
		-w '$carrier up %{http_code} %{size_upload} B %{time_total} s\n' http://$fv:8000/up" >> "$RUN/transfers.txt"
	mark "$carrier-ping"
	docker exec "$PFX-l" ping -c20 -i1 "$fv" > "$RUN/$carrier-ping.txt" 2>&1
	mark "$carrier-idle"
	sleep "$IDLE"
	mark "$carrier-stop"
	t l stop >/dev/null 2>&1
	sleep 3
done

# ---- reference: curl and nginx -----------------------------------------------------------------------
log "=== reference: curl and nginx ==="
docker run --rm -v "$RUN:/r" "$TOOLS" sh -c "head -c $SIZE /dev/urandom > /r/up"
for v in h1:--http1.1 h3:--http3-only; do
	name=${v%%:*}; opt=${v#*:}
	mark "ref-$name-down"
	docker run --rm --network "$NET" "$TOOLS" curl -sk -m 300 "$opt" -o /dev/null \
		-w "ref-$name down %{http_code} %{size_download} B %{time_total} s\n" "https://$N_IP/big" >> "$RUN/transfers.txt"
	mark "ref-$name-up"
	docker run --rm --network "$NET" -v "$RUN:/r:ro" "$TOOLS" curl -sk -m 300 "$opt" -o /dev/null \
		-T /r/up -w "ref-$name up %{http_code} %{size_upload} B %{time_total} s\n" "https://$N_IP/up/$name" >> "$RUN/transfers.txt"
done
mark "ref-h1-idle"
docker run --rm --network "$NET" "$TOOLS" sh -c "(printf 'GET / HTTP/1.1\r\nHost: x\r\n\r\n'; sleep $IDLE) | \
	timeout $(( IDLE + 5 )) openssl s_client -quiet -connect $N_IP:443 >/dev/null 2>&1" || true
mark "ref-h3-idle"
docker exec "$PFX-c" python3 -c "
import asyncio, ssl
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration
async def main():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE, idle_timeout=$IDLE + 60)
    async with connect('$N_IP', 443, configuration=cfg) as p:
        h = H3Connection(p._quic); sid = p._quic.get_next_available_stream_id()
        h.send_headers(sid, [(b':method', b'GET'), (b':scheme', b'https'), (b':authority', b'x'), (b':path', b'/')], end_stream=True)
        p.transmit(); await asyncio.sleep($IDLE)
asyncio.run(main())" >/dev/null 2>&1 || true
mark "ref-end"
sleep 1
docker stop -t 2 "$PFX-capf" "$PFX-capn" >/dev/null

for x in f n; do
	docker run --rm -v "$RUN:/r" "$TOOLS" tshark -r "/r/$x.pcap" -T fields -E occurrence=a -E aggregator=, \
		-e frame.time_epoch -e ip.src -e ip.dst -e ip.proto -e udp.length -e tcp.len -e tls.record.content_type \
		-e tls.record.length -e quic.header_form -e tcp.flags.fin -e tcp.flags.reset -e tcp.port -e udp.port \
		> "$RUN/$x.tsv" 2>/dev/null
done
docker run --rm -v "$HERE:/h:ro" -v "$RUN:/r" "$PROBER" python3 /h/carrier_stats.py \
	/r/phases.tsv /r/f.tsv /r/n.tsv "$F_IP" "$L_IP" "$N_IP" > "$OUT/carrier-traffic.txt"
{ echo "--- transfers ---"; cat "$RUN/transfers.txt"; for c in $CARRIERS; do echo "--- $c link ---"; cat "$RUN/$c-connection.txt"; done
  docker image inspect "$IMG" --format "image $IMG {{.Id}}"; } >> "$OUT/carrier-traffic.txt"
cat "$OUT/carrier-traffic.txt"
log "results in $OUT"

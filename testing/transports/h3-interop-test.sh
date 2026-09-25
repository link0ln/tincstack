#!/usr/bin/env bash
# The quic carrier is HTTP/3, proven against real HTTP/3 implementations.
#
# Until 2026-09-23 the carrier said `h3' in ALPN and then spoke raw tinc on
# stream 0: it allowed no unidirectional streams (a one-field rule in the
# publicly decryptable Initial), never opened a control stream, and a real
# HTTP/3 client got nothing back (testing/fingerprint: `curl --http3-only'
# timed out). Now the tinc session is one HTTP/3 request (h3.c,
# docs/transports.md §9.4), and this lab checks it with other people's code:
#
#   * curl (ngtcp2 + nghttp3) and Chromium get the decoy page over HTTP/3
#     from a tinc node -- our HEADERS/QPACK/DATA decode in two stacks;
#   * with their TLS keys, tshark sees our server open its control stream and
#     send SETTINGS, as every HTTP/3 server does;
#   * our dialler, pointed at nginx, sends a request nginx parses and logs
#     (method, path, user agent), recognises the answer as a web server's and
#     falls back;
#   * two tinc nodes still build a tunnel over the carrier, and the dialler's
#     Initial announces what curl's does (100 bidi / 100 uni streams, an empty
#     source connection id);
#   * with HttpsDecoyUpstream the HTTP/3 decoy relays the upstream's answer
#     (decoy_upstream.py), as the TCP one does.
#
# Usage: [CORE_IMAGE=...] testing/transports/h3-interop-test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
NGINX="${NGINX_IMAGE:-nginx:1.27}"
PY="${PYTHON_IMAGE:-python:3.12-slim}"
RUN="$HERE/run-h3"
PFX=h3i
NET=${PFX}net
SUBNET=10.47.6
F_IP=$SUBNET.10
L_IP=$SUBNET.11
N_IP=$SUBNET.12
UP_IP=$SUBNET.20
NETNAME=lab
YAML=/c/tinc.yaml
FAILED=0

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

cleanup() {
	docker rm -f "$PFX-f" "$PFX-l" "$PFX-n" "$PFX-cap" "$PFX-up" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	docker run --rm -v "$RUN:/r" "$IMG" sh -c 'rm -rf /r/*' >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
[[ -n ${KEEP:-} ]] || trap cleanup EXIT
cleanup
mkdir -p "$RUN/f" "$RUN/l" "$RUN/n" "$RUN/cap"
chmod 777 "$RUN/cap"
# --internal: nothing here needs the Internet, and Chromium would otherwise
# phone home (measured: www.google.com, redirector.gvt1.com from the lab).
docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null

if ! docker image inspect "$TOOLS" >/dev/null 2>&1; then
	docker build -q --build-arg http_proxy="${HTTP_PROXY:-}" --build-arg https_proxy="${HTTP_PROXY:-}" \
		-t "$TOOLS" "$ROOT/testing/fingerprint" >/dev/null
fi

tnc() { local n=$1; shift; docker exec "$PFX-$n" tinc -n "$NETNAME" -c "$YAML" "$@"; }
node() {
	docker run -d --name "$PFX-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN --device /dev/net/tun \
		-v "$RUN/$1:/c" "$IMG" sleep infinity >/dev/null
}
start() { docker exec -d "$PFX-$1" sh -c "tincd -n $NETNAME -c $YAML -D -d3 >>/c/tincd.log 2>&1"; }
stop() { tnc "$1" stop >/dev/null 2>&1 || true; sleep 1; }
ready() {
	for _ in $(seq 30); do tnc "$1" pid >/dev/null 2>&1 && return 0; sleep 1; done
	log "node $1 never came up"; tail -20 "$RUN/$1/tincd.log" >&2; exit 1
}
logged() { grep -q -- "$2" "$RUN/$1/tincd.log"; }
tools() { docker run --rm --network "$NET" -v "$RUN/cap:/cap" "$TOOLS" bash -c "$1" 2>&1; }
pcap() { docker run --rm -v "$RUN/cap:/cap" "$TOOLS" tshark -r /cap/f.pcap -o tls.keylog_file:/cap/keys "${@}" 2>/dev/null; }

# ---- a founder and a leaf -------------------------------------------------------------
node f "$F_IP"
docker exec "$PFX-f" sh -c "install -m600 /dev/null $YAML && tinc -n $NETNAME -c $YAML set Name founder && tinc -n $NETNAME -c $YAML set Port 655"
start f
ready f
tnc f set founder.Address "$F_IP"
inv=$(tnc f invite leaf)
node l "$L_IP"
tnc l join "$inv" >/dev/null 2>&1

docker run -d --name "$PFX-cap" --network "container:$PFX-f" --cap-add NET_ADMIN --cap-add NET_RAW \
	-v "$RUN/cap:/cap" "$TOOLS" tcpdump -U --immediate-mode -i any -s 0 -w /cap/f.pcap 'udp port 443' >/dev/null
sleep 2

tnc l set PreferredTransports quic
start l
ready l
for _ in $(seq 40); do
	tnc l dump connections 2>/dev/null | grep -q "^founder .*transport quic" && break
	sleep 1
done
if tnc l dump connections 2>/dev/null | grep -q "^founder .*transport quic"; then
	ok "two tinc nodes connect over the HTTP/3 carrier"
else
	bad "two tinc nodes connect over the HTTP/3 carrier"
	tail -15 "$RUN/l/tincd.log" >&2
fi
f_vpn=$(tnc f get Subnet 2>/dev/null | head -1 | cut -d/ -f1)
if [[ -n $f_vpn ]] && docker exec "$PFX-l" ping -c 3 -W 2 "$f_vpn" >/dev/null 2>&1; then
	ok "... and the tunnel carries traffic ($f_vpn)"
else
	bad "... and the tunnel carries traffic (${f_vpn:-no subnet})"
fi

# ---- real HTTP/3 clients against the tinc node -------------------------------------------
tools "SSLKEYLOGFILE=/cap/keys curl -sS -k -m 8 -i --http3-only https://$F_IP/" > "$RUN/curl.txt" || true
if head -1 "$RUN/curl.txt" | grep -q "^HTTP/3 200" && grep -q "<title>" "$RUN/curl.txt"; then
	ok "curl --http3-only gets the decoy page over HTTP/3"
else
	bad "curl --http3-only gets the decoy page over HTTP/3"
	head -5 "$RUN/curl.txt" >&2
fi

h3_before=$(grep -c "serving the decoy to an HTTP/3 request" "$RUN/f/tincd.log" || true)
# Chromium ignores --ignore-certificate-errors for QUIC (measured: it failed
# the QUIC handshake with CERTIFICATE_VERIFY_FAILED and quietly loaded the
# page over the TCP front); trusting the certificate's key by hash works.
awk '/^      tls_cert: \|/{f=1;next} f&&/^        /{sub(/^        /,"");print;next} f{exit}' "$RUN/f/tinc.yaml" > "$RUN/cap/f.pem"
spki=$(docker run --rm -v "$RUN/cap:/cap" "$TOOLS" sh -c \
	'openssl x509 -in /cap/f.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64')
tools "chromium --headless=new --no-sandbox --disable-gpu --ignore-certificate-errors-spki-list=$spki \
	--ssl-key-log-file=/cap/keys \
	--user-data-dir=/tmp/c --enable-quic --origin-to-force-quic-on=$F_IP:443 --dump-dom https://$F_IP/ 2>/dev/null" > "$RUN/chrome.txt" || true
h3_after=$(grep -c "serving the decoy to an HTTP/3 request" "$RUN/f/tincd.log" || true)
if grep -q "<title>" "$RUN/chrome.txt" && ((h3_after > h3_before)); then
	ok "Chromium loads the decoy page over QUIC ($((h3_after - h3_before)) HTTP/3 request(s) answered)"
else
	bad "Chromium loads the decoy page over QUIC"
	head -5 "$RUN/chrome.txt" >&2
fi

sleep 1
docker rm -f "$PFX-cap" >/dev/null
sleep 1
settings=$(pcap -Y "ip.src == $F_IP && http3.frame_type == 4" -T fields -e udp.dstport | sort -u | wc -l)
if [[ $settings -ge 2 ]]; then
	ok "our server sends SETTINGS on its control stream (decrypted, $settings client flows)"
else
	bad "our server sends SETTINGS on its control stream (decrypted: $settings flows)"
fi

# The leaf's Initial, which anyone can decrypt.
params=$(pcap -Y "ip.src == $L_IP && quic.long.packet_type == 0" -V | grep -E "Parameter: (initial_max_streams_(bidi|uni)|initial_source_connection_id)" | sort -u)
if grep -q "initial_max_streams_uni (len=2) 100" <<<"$params" && grep -q "initial_max_streams_bidi (len=2) 100" <<<"$params" &&
		grep -q "initial_source_connection_id (len=0)" <<<"$params"; then
	ok "the dialler's Initial announces 100/100 streams and an empty source connection id, as curl's does"
else
	bad "the dialler's Initial announces 100/100 streams and an empty source connection id: $params"
fi

# ---- our dialler against nginx -----------------------------------------------------------
docker run --rm -v "$RUN/n:/n" "$TOOLS" sh -c '
	cd /n && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
		-subj /CN=web.lab.test -keyout key.pem -out cert.pem 2>/dev/null && chmod 644 key.pem cert.pem'
cat > "$RUN/n/default.conf" <<-'EOF'
	log_format h3 '$request "$http_user_agent" $status';
	server {
	    listen 443 quic reuseport;
	    listen 443 ssl;
	    ssl_certificate     /n/cert.pem;
	    ssl_certificate_key /n/key.pem;
	    access_log /n/access.log h3;
	    location / { root /usr/share/nginx/html; }
	}
EOF
docker run -d --name "$PFX-n" --network "$NET" --ip "$N_IP" -v "$RUN/n:/n" \
	-v "$RUN/n/default.conf:/etc/nginx/conf.d/default.conf:ro" "$NGINX" >/dev/null
sleep 2

stop l
key=$(docker exec "$PFX-f" sh -c "grep -m1 Ed25519PublicKey $YAML" | sed 's/^ *//')
# webby: nginx, dialled like a tinc peer (any key will do; it never gets that far).
# `#' delimits: the base64 key may contain `/'.
docker exec "$PFX-l" sh -c "
	sed -i 's#^\(    hosts:\)\$#\1\n      webby: |\n        Address = $N_IP\n        QuicPort = 443\n        Transports = quic\n        $key#' $YAML"
tnc l add ConnectTo webby >/dev/null 2>&1 || true
: > "$RUN/l/tincd.log"
start l
ready l
for _ in $(seq 20); do
	logged l "answered like a web server" && break
	sleep 1
done

if [[ -s $RUN/n/access.log ]] && grep -q '^POST / HTTP/3.0 "Mozilla/5.0 .*Chrome/' "$RUN/n/access.log"; then
	ok "nginx parses our request: $(head -1 "$RUN/n/access.log" | cut -c1-60)..."
else
	bad "nginx parses our request: $(cat "$RUN/n/access.log" 2>/dev/null | head -2)"
	docker logs "$PFX-n" 2>&1 | tail -5 >&2
fi
if logged l "webby .*answered like a web server"; then
	ok "our dialler recognises a web server's answer and gives up on it"
else
	bad "our dialler recognises a web server's answer and gives up on it"
	grep -i "webby\|quic" "$RUN/l/tincd.log" | tail -8 >&2
fi

# ---- the HTTP/3 decoy relays HttpsDecoyUpstream, as the TCP one does ---------------------------
docker run -d --name "$PFX-up" --network "$NET" --ip "$UP_IP" -v "$HERE:/h:ro" \
	"$PY" python3 /h/decoy_upstream.py /tmp/requests.txt >/dev/null
tnc f set HttpsDecoyUpstream "$UP_IP:80"
tnc f reload >/dev/null 2>&1 || true
sleep 2
tools "curl -sS -k -m 8 -i --http3-only https://$F_IP/" > "$RUN/curl-up.txt" || true
if head -1 "$RUN/curl-up.txt" | grep -q "^HTTP/3 200" && grep -qi "^x-up: 1" "$RUN/curl-up.txt" &&
		grep -q "upstream page" "$RUN/curl-up.txt"; then
	ok "with HttpsDecoyUpstream, curl --http3-only gets the upstream's page"
else
	bad "with HttpsDecoyUpstream, curl --http3-only gets the upstream's page"
	head -12 "$RUN/curl-up.txt" >&2
fi

if [[ $FAILED -eq 0 ]]; then
	log "h3 interop: all checks passed"
else
	log "h3 interop: FAILURES above"
fi
exit "$FAILED"

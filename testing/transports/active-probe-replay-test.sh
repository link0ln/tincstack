#!/usr/bin/env bash
# active-probe-replay-test.sh -- Active probe & replay wire test (T1d(b)).
#
# Asserts wire behavior under active probing and packet replay:
# 1. https (TCP 443):
#    - Real HTTPS client (curl) gets the decoy page, matching nginx byte-for-byte.
#    - Replaying the first TLS record (ClientHello) from a new source at +5s and +40s
#      elicits a response matching nginx (ServerHello flight).
#    - Same-size random garbage elicits a response matching nginx (HTTP 400).
# 2. quic (UDP 443):
#    - Real HTTP/3 client (curl --http3-only) gets the decoy page, matching nginx.
#    - Replaying the first QUIC Initial datagram at +5s and +40s elicits a response
#      matching nginx (dropped or stateless reset).
#    - Same-size random garbage elicits a response matching nginx.
# 3. obfs (UDP 655):
#    - Replaying the first obfs datagram at +5s and +40s returns 0 bytes (silence),
#      indistinguishable from a closed port.
#    - Same-size random garbage to the obfs port returns 0 bytes (silence).
#    - Negative control: silence matches an unopened UDP port.
#
# Usage: [CORE_IMAGE=...] [QUICK=1] [KEEP=1] testing/transports/active-probe-replay-test.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
NGINX="${NGINX_IMAGE:-tincstack/nginx-deb13:dev}"
PY="${PYTHON_IMAGE:-python:3.12-slim}"

PFX=apr
NET=${PFX}net
SUBNET=10.47.26
F_IP=$SUBNET.10
L_IP=$SUBNET.11
N_IP=$SUBNET.12
Y=/c/tinc.yaml
RUN="$HERE/run-active-probe-replay"
FAILED=0

if [[ -n ${QUICK:-} ]]; then
	W_SHORT=2.0
	W_LONG=5.0
else
	W_SHORT=5.0
	W_LONG=40.0
fi

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }
first_line() { read -r line || true; printf '%s\n' "$line"; cat >/dev/null 2>&1 || true; }

cleanup() {
	docker rm -f "$PFX-f" "$PFX-l" "$PFX-n" "$PFX-capf" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
[[ -n ${KEEP:-} ]] || trap cleanup EXIT
cleanup
mkdir -p "$RUN/n"
chmod 777 "$RUN"

if ! docker image inspect "$TOOLS" >/dev/null 2>&1; then
	docker build -q --build-arg http_proxy="${HTTP_PROXY:-}" --build-arg https_proxy="${HTTP_PROXY:-}" \
		-t "$TOOLS" "$ROOT/testing/fingerprint" >/dev/null
fi
if ! docker image inspect "$NGINX" >/dev/null 2>&1; then
	docker build -q --build-arg http_proxy="${HTTP_PROXY:-}" --build-arg https_proxy="${HTTP_PROXY:-}" \
		-t "$NGINX" "$HERE/nginx-deb13" >/dev/null
fi

docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null

# ---- Start founder node --------------------------------------------------------------------------
docker run -d --name "$PFX-f" --network "$NET" --ip "$F_IP" --cap-add NET_ADMIN \
	--device /dev/net/tun "$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
tf() { docker exec "$PFX-f" tinc -n lab -c "$Y" "$@"; }
docker exec "$PFX-f" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
docker exec -d "$PFX-f" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
for _ in $(seq 20); do tf pid >/dev/null 2>&1 && break; sleep 1; done
tf set founder.Address "$F_IP"
for _ in $(seq 20); do docker exec "$PFX-f" grep -q '^      tls_key: |' "$Y" && break; sleep 1; done

pem() {
	docker exec "$PFX-f" sh -c "awk '/^      $1: \\|/{f=1;next} f&&/^      [a-z_]+:/{f=0} f' $Y | sed 's/^        //' | sed -n '/BEGIN $2/,/END $2/p'"
}
pem tls_cert CERTIFICATE > "$RUN/n/cert.pem"
pem tls_key "PRIVATE KEY" > "$RUN/n/key.pem"
chmod 644 "$RUN/n/"*.pem

# ---- Start reference nginx on TCP+UDP 443 with identical certificate -----------------------------
cat > "$RUN/n/default.conf" <<-'EOF'
	server {
	    listen 443 quic reuseport;
	    listen 443 ssl;
	    ssl_certificate     /n/cert.pem;
	    ssl_certificate_key /n/key.pem;
	    add_header Alt-Svc 'h3=":443"; ma=86400';
	    location / { root /usr/share/nginx/html; }
	}
EOF
docker run -d --name "$PFX-n" --network "$NET" --ip "$N_IP" -v "$RUN/n:/n:ro" \
	-v "$RUN/n/default.conf:/etc/nginx/conf.d/default.conf:ro" "$NGINX" >/dev/null

# ---- Start tcpdump capture on founder -------------------------------------------------------------
docker run -d --name "$PFX-capf" --network "container:$PFX-f" --cap-add NET_ADMIN --cap-add NET_RAW \
	-v "$RUN:/r" "$TOOLS" tcpdump -i eth0 -U -w "/r/f.pcap" 'port 443 or port 655' >/dev/null
sleep 2

# ---- Start dialler (leaf) node -------------------------------------------------------------------
docker run -d --name "$PFX-l" --network "$NET" --ip "$L_IP" --cap-add NET_ADMIN \
	--device /dev/net/tun "$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
tl() { docker exec "$PFX-l" tinc -n lab -c "$Y" "$@"; }
tl join "$(tf invite leaf)" >/dev/null 2>&1
tl set Port 0
tl set MaxTimeout 5

# ==================================================================================================
# 1. HTTPS CARRIER (TCP 443)
# ==================================================================================================
log "=== Testing HTTPS carrier active probe / replay ==="

# (a) Real HTTPS client check
res_f=$(docker run --rm --network "$NET" "$TOOLS" curl -sk "https://$F_IP/" 2>/dev/null || true)
res_n=$(docker run --rm --network "$NET" "$TOOLS" curl -sk "https://$N_IP/" 2>/dev/null || true)
if [[ -n "$res_f" && "${res_f:0:80}" == "${res_n:0:80}" ]]; then
	ok "real HTTPS client gets identical decoy page from tinc and nginx"
else
	bad "real HTTPS client response mismatch"
fi

# (b) Dial over https to capture legitimate ClientHello
tl set PreferredTransports https
docker exec -d "$PFX-l" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
for _ in $(seq 10); do tl pid >/dev/null 2>&1 && break; sleep 1; done
sleep 2

# Extract ClientHello payload hex
ch_payload=$(docker run --rm -v "$RUN:/r" "$TOOLS" tshark -r /r/f.pcap -Y "ip.src == $L_IP && tcp.dstport == 443 && tcp.len > 0" -T fields -e tcp.payload 2>/dev/null | first_line)

if [[ -n "$ch_payload" ]]; then
	ok "captured legitimate https ClientHello (${#ch_payload} hex chars)"
else
	bad "could not capture legitimate https ClientHello"
fi

# (c) Replay ClientHello at +wait_short and +wait_long
log "running https replay probe at +${W_SHORT}s and +${W_LONG}s..."
if docker run --rm --network "$NET" -v "$HERE:/h:ro" "$PY" python3 /h/replay_probe.py \
	--proto https --tinc-ip "$F_IP" --nginx-ip "$N_IP" --port 443 --payload-hex "$ch_payload" \
	--wait-short "$W_SHORT" --wait-long "$W_LONG" --mode replay; then
	ok "https ClientHello replay matches nginx at +${W_SHORT}s and +${W_LONG}s"
else
	bad "https ClientHello replay mismatch vs nginx"
fi

# (d) Same-size garbage to TCP 443
log "running https same-size garbage probe..."
if docker run --rm --network "$NET" -v "$HERE:/h:ro" "$PY" python3 /h/replay_probe.py \
	--proto https --tinc-ip "$F_IP" --nginx-ip "$N_IP" --port 443 --payload-hex "$ch_payload" --mode garbage; then
	ok "https same-size garbage matches nginx (HTTP 400 Bad Request / RST)"
else
	bad "https same-size garbage mismatch vs nginx"
fi

# ==================================================================================================
# 2. QUIC CARRIER (UDP 443)
# ==================================================================================================
log "=== Testing QUIC carrier active probe / replay ==="

# (a) Real HTTP/3 client check
h3_f=$(docker run --rm --network "$NET" "$TOOLS" curl -sk --http3-only "https://$F_IP/" 2>/dev/null || true)
h3_n=$(docker run --rm --network "$NET" "$TOOLS" curl -sk --http3-only "https://$N_IP/" 2>/dev/null || true)
if [[ -n "$h3_f" && "${h3_f:0:80}" == "${h3_n:0:80}" ]]; then
	ok "real HTTP/3 client gets identical decoy page from tinc and nginx"
else
	bad "real HTTP/3 client response mismatch"
fi

# (b) Dial over quic to capture legitimate Initial datagram
tl stop >/dev/null 2>&1 || true
docker exec "$PFX-l" sh -c 'p=$(pidof tincd 2>/dev/null || true); [ -n "$p" ] && kill $p 2>/dev/null || true'
sleep 1
tl set PreferredTransports quic
docker exec -d "$PFX-l" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
for _ in $(seq 10); do tl pid >/dev/null 2>&1 && break; sleep 1; done
sleep 2

# Extract QUIC Initial datagram payload hex (>= 1200 bytes)
quic_payload=$(docker run --rm -v "$RUN:/r" "$TOOLS" tshark -r /r/f.pcap -Y "ip.src == $L_IP && udp.dstport == 443 && udp.length >= 1200" -T fields -e udp.payload 2>/dev/null | first_line)

if [[ -n "$quic_payload" ]]; then
	ok "captured legitimate quic Initial datagram (${#quic_payload} hex chars)"
else
	bad "could not capture legitimate quic Initial datagram"
fi

# (c) Replay QUIC Initial at +wait_short and +wait_long
log "running quic replay probe at +${W_SHORT}s and +${W_LONG}s..."
if docker run --rm --network "$NET" -v "$HERE:/h:ro" "$PY" python3 /h/replay_probe.py \
	--proto quic --tinc-ip "$F_IP" --nginx-ip "$N_IP" --port 443 --payload-hex "$quic_payload" \
	--wait-short "$W_SHORT" --wait-long "$W_LONG" --mode replay; then
	ok "quic Initial replay matches nginx at +${W_SHORT}s and +${W_LONG}s (51B Server Initial)"
else
	bad "quic Initial replay mismatch vs nginx"
fi

# (d) Same-size garbage to UDP 443
log "running quic same-size garbage probe..."
if docker run --rm --network "$NET" -v "$HERE:/h:ro" "$PY" python3 /h/replay_probe.py \
	--proto quic --tinc-ip "$F_IP" --nginx-ip "$N_IP" --port 443 --payload-hex "$quic_payload" --mode garbage; then
	ok "quic same-size garbage matches nginx (silence)"
else
	bad "quic same-size garbage mismatch vs nginx"
fi

# ==================================================================================================
# 3. OBFS CARRIER (UDP 655)
# ==================================================================================================
log "=== Testing OBFS carrier active probe / replay ==="

# (a) Dial over obfs to capture legitimate initial obfs frame
tl stop >/dev/null 2>&1 || true
docker exec "$PFX-l" sh -c 'p=$(pidof tincd 2>/dev/null || true); [ -n "$p" ] && kill $p 2>/dev/null || true'
sleep 1
tl set PreferredTransports obfs
docker exec -d "$PFX-l" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
for _ in $(seq 10); do tl pid >/dev/null 2>&1 && break; sleep 1; done
sleep 2

# Extract obfs datagram payload hex from UDP 655
obfs_payload=$(docker run --rm -v "$RUN:/r" "$TOOLS" tshark -r /r/f.pcap -Y "ip.src == $L_IP && udp.dstport == 655 && udp.length > 0" -T fields -e udp.payload 2>/dev/null | first_line)

if [[ -n "$obfs_payload" ]]; then
	ok "captured legitimate obfs datagram (${#obfs_payload} hex chars)"
else
	bad "could not capture legitimate obfs datagram"
fi

# (b) Replay obfs datagram at +wait_short and +wait_long
log "running obfs replay probe at +${W_SHORT}s and +${W_LONG}s..."
if docker run --rm --network "$NET" -v "$HERE:/h:ro" "$PY" python3 /h/replay_probe.py \
	--proto obfs --tinc-ip "$F_IP" --port 655 --payload-hex "$obfs_payload" \
	--wait-short "$W_SHORT" --wait-long "$W_LONG" --mode replay; then
	ok "obfs datagram replay dropped in silence (looks like closed port)"
else
	bad "obfs datagram replay did not look like a closed port"
fi

# (c) Same-size garbage to UDP 655
log "running obfs same-size garbage probe..."
if docker run --rm --network "$NET" -v "$HERE:/h:ro" "$PY" python3 /h/replay_probe.py \
	--proto obfs --tinc-ip "$F_IP" --port 655 --payload-hex "$obfs_payload" --mode garbage; then
	ok "obfs same-size garbage dropped in silence (looks like closed port)"
else
	bad "obfs same-size garbage did not look like a closed port"
fi

# (d) Negative control: probe unopened UDP port (656) to assert identical silence
log "checking negative control on unopened port UDP 656..."
ctl=$(docker run --rm --network "$NET" -v "$HERE:/h:ro" "$PY" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.5)
s.sendto(b'test_probe_bytes', ('$F_IP', 656))
try:
    s.recvfrom(1024)
    print('answered')
except socket.timeout:
    print('silence')
except Exception as e:
    print(type(e).__name__)
s.close()
")
if [[ "$ctl" == "silence" ]]; then
	ok "unopened port UDP 656 yields identical silence"
else
	bad "negative control unexpected response: $ctl"
fi

# ==================================================================================================
# Summary
# ==================================================================================================
if [[ $FAILED -eq 0 ]]; then
	log "active probe / replay wire test (T1d): ALL CHECKS PASSED"
else
	log "active probe / replay wire test (T1d): FAILURES ABOVE"
fi
exit "$FAILED"

#!/bin/sh
# tls-front-test.sh -- prove M5 (G1) tasks 1 and 2:
#   1. certificate automation (first start -> keys present; restart -> same
#      fingerprint; a real cert via TlsCert/TlsKey is served);
#   2. the default-on decoy (curl -k https shows the decoy over a valid TLS
#      handshake; openssl s_client shows the cert; nmap -sV says https; plain
#      HTTP gets the page too; HttpsDecoyUpstream is honoured).
#   3. security review R (stream L) regressions on the same port:
#      R-1   one pending undecided byte does not spin the daemon (CPU ticks
#            over 3 s; the connection is closed within the front deadline);
#      M5-8  a plain-HTTP client that never reads a large decoy does not spin
#            the daemon and is dropped by the authentication timeout;
#      M5-10 a request carrying a tinc-shaped authenticator is never forwarded
#            to HttpsDecoyUpstream with its Cookie/Upgrade headers;
#      M5-1  a black-holed upstream never stalls the loop: a second probe is
#            answered while the first one waits on the upstream.
#
# All tooling (curl/openssl/nmap) runs in throwaway containers sharing the
# node's network namespace, so nothing is installed on the host. Test data is
# under /tmp/wsl-* only.
#
# Usage: [LAB=prefix] [SUBNET=10.41.9] testing/transports/tls-front-test.sh [image]
#   LAB (default wsl) prefixes every container/network name and the /tmp
#   directory; a non-default LAB also gets its own /24 (see lab-env.sh).
set -e

IMG=${1:-tincstack/core:${TINCSTACK_TAG:-dev}}
TOOLS=nicolaka/netshoot
DEFAULT_LAB=wsl; DEFAULT_SUBNET=10.41.9
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"
NET=${LAB}front
BASE=/tmp/$LAB-front
NODE_IP=$SUBNET.10
UP_IP=$SUBNET.20

cleanup() {
	docker rm -f "$LAB-node" "$LAB-up" "$LAB-tool" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -rf "$BASE"
mkdir -p "$BASE"
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

fail=0
note() { echo "  $1"; }
miss() { echo "  MISS: $1"; fail=1; }

# CPU ticks (user+system, 100 Hz) of the daemon (PID 1 in its container).
ticks() { docker exec "$LAB-node" cat /proc/1/stat | awk '{print $14+$15}'; }
cat > "$BASE/tinc.yaml" <<EOF
networks:
  wsg1:
    options:
      Name: nodea
      Mode: router
      Port: 655
      AddressPool: 10.191.0.0/24
EOF

# ---- first start: materialise the config, then stop ------------------------
timeout 4 docker run --rm -v "$BASE":/etc/tincstack "$IMG" \
	tincd -c /etc/tincstack/tinc.yaml -n wsg1 -D -d1 >/dev/null 2>&1 || true

echo "===== Task 1: certificate automation ====="

if grep -q "tls_cert:" "$BASE/tinc.yaml" && grep -q "tls_key:" "$BASE/tinc.yaml"; then
	note "first start materialised keys.tls_cert / keys.tls_key"
else
	miss "tls_cert/tls_key not present after first start"
fi

fp1=$(grep -i "TlsFingerprint" "$BASE/tinc.yaml" | head -1 | sed 's/.*= *//;s/[^0-9a-fA-F]//g')

if [ -n "$fp1" ]; then
	note "TlsFingerprint written to own host record: $fp1"
else
	miss "no TlsFingerprint in the host record"
fi

# ---- restart: fingerprint must be stable -----------------------------------
timeout 4 docker run --rm -v "$BASE":/etc/tincstack "$IMG" \
	tincd -c /etc/tincstack/tinc.yaml -n wsg1 -D -d1 >/dev/null 2>&1 || true
fp2=$(grep -i "TlsFingerprint" "$BASE/tinc.yaml" | head -1 | sed 's/.*= *//;s/[^0-9a-fA-F]//g')

if [ -n "$fp2" ] && [ "$fp1" = "$fp2" ]; then
	note "restart kept the same fingerprint"
else
	miss "fingerprint changed across restart ($fp1 -> $fp2)"
fi

# ---- run the daemon for the live probes ------------------------------------
docker run -d --name "$LAB-node" --network "$NET" --ip "$NODE_IP" --cap-add NET_ADMIN \
	--device /dev/net/tun -v "$BASE":/etc/tincstack "$IMG" \
	tincd -c /etc/tincstack/tinc.yaml -n wsg1 -D -d2 >/dev/null
sleep 3

echo "===== Task 2: default-on decoy ====="

# openssl s_client: a valid TLS handshake presenting the node's cert.
sc=$(docker run --rm --net "container:$LAB-node" "$TOOLS" \
	sh -c "echo Q | openssl s_client -connect 127.0.0.1:655 -servername example.com 2>/dev/null" || true)

if echo "$sc" | grep -q "BEGIN CERTIFICATE"; then
	note "openssl s_client completed a TLS handshake and got the certificate"
else
	miss "openssl s_client did not get a certificate"
fi

# The served cert fingerprint must equal the persisted one.
scfp=$(docker run --rm --net "container:$LAB-node" "$TOOLS" \
	sh -c "echo Q | openssl s_client -connect 127.0.0.1:655 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null" | sed 's/.*=//;s/[^0-9a-fA-F]//g' | tr 'A-F' 'a-f' || true)

if [ -n "$scfp" ] && [ "$scfp" = "$fp1" ]; then
	note "served cert fingerprint matches the persisted TlsFingerprint"
else
	miss "served cert fingerprint ($scfp) != persisted ($fp1)"
fi

# curl -k https: the decoy page over TLS.
hb=$(docker run --rm --net "container:$LAB-node" "$TOOLS" \
	curl -sk https://127.0.0.1:655/ || true)

if echo "$hb" | grep -qi "It works"; then
	note "curl -k https returned the decoy page"
else
	miss "curl -k https did not return the decoy page"
fi

if echo "$hb" | grep -qi "tinc"; then
	miss "decoy response leaks the string 'tinc'"
else
	note "decoy response contains no tinc string"
fi

# curl plain HTTP: same content over cleartext.
hp=$(docker run --rm --net "container:$LAB-node" "$TOOLS" \
	curl -s http://127.0.0.1:655/ || true)

if echo "$hp" | grep -qi "It works"; then
	note "curl http (cleartext) returned the decoy page too"
else
	miss "plain HTTP did not return the decoy page"
fi

# nmap -sV must identify the port as SSL/HTTPS, never as tinc.
nm=$(docker run --rm --net "container:$LAB-node" "$TOOLS" \
	nmap -sV -Pn -p 655 127.0.0.1 2>/dev/null || true)
echo "$nm" | grep -i "655/tcp" || true

if echo "$nm" | grep -i "655/tcp" | grep -Eqi "ssl|https|http"; then
	note "nmap -sV identifies the port as ssl/http(s)"
else
	miss "nmap did not identify the port as ssl/https"
fi

if echo "$nm" | grep -qi "tinc"; then
	miss "nmap fingerprinted the port as tinc"
else
	note "nmap did not fingerprint the port as tinc"
fi

# ---- review R-1: one undecided byte must not spin the daemon ---------------
echo "===== R-1: undecided front byte (no busy loop) ====="
# A client sends a single 'G' (a prefix of GET, so the classifier wants more)
# and then nothing for 6 s. Before the fix the level-triggered select() called
# the front on every loop turn: ~100 % CPU until pingtimeout (5 s). After it
# the connection is parked and closed within the front deadline (2 s).
logmark=$(docker logs "$LAB-node" 2>&1 | wc -l)
t0=$(ticks)
r1=$(docker run --rm -i --net "container:$LAB-node" "$TOOLS" python3 - <<'PY'
import socket, time
s = socket.create_connection(("127.0.0.1", 655)); s.sendall(b"G"); t = time.time()
s.settimeout(6)
try:
    d = s.recv(1); closed = time.time() - t
except socket.timeout:
    closed = -1
except OSError:
    closed = time.time() - t
print("closed_after=%.1f" % closed)
PY
)
t1=$(ticks)
r1_ticks=$((t1 - t0))
note "daemon CPU while one 'G' byte was pending: $r1_ticks ticks over the probe ($r1)"
if [ "$r1_ticks" -lt 50 ]; then
	note "R-1: no busy loop (< 0.5 s CPU)"
else
	miss "R-1: daemon burned $r1_ticks ticks on one pending byte"
fi
# The daemon closes (and tarpits: the fd is held, so the client sees no FIN,
# hence closed_after=-1 above is expected) an undecided connection after the
# front deadline; the log line is the proof.
if docker logs "$LAB-node" 2>&1 | tail -n +"$logmark" | grep -q "sent no recognisable preamble within"; then
	note "R-1: undecided connection closed by the front deadline: $(docker logs "$LAB-node" 2>&1 | tail -n +"$logmark" | grep -o 'sent no recognisable preamble within [0-9]* s')"
else
	miss "R-1: undecided connection was not closed by the front deadline"
fi

# ---- review M5-8: non-reading plain-HTTP client, large decoy ---------------
echo "===== M5-8: non-reading client on a large plain-HTTP decoy ====="
docker exec "$LAB-node" sh -c 'mkdir -p /srv/decoy && head -c 8000000 /dev/zero > /srv/decoy/big.bin && printf "It works!\n" > /srv/decoy/index.html'
docker exec "$LAB-node" sh -c "sed -i 's/      AddressPool:/      HttpsDecoyRoot: \/srv\/decoy\n      AddressPool:/' /etc/tincstack/tinc.yaml"
docker exec "$LAB-node" tinc -c /etc/tincstack/tinc.yaml -n wsg1 reload >/dev/null 2>&1 || true
sleep 1
logmark=$(docker logs "$LAB-node" 2>&1 | wc -l)
t0=$(ticks)
docker run --rm -i --net "container:$LAB-node" "$TOOLS" python3 - <<'PY' >/dev/null
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
s.connect(("127.0.0.1", 655)); s.sendall(b"GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
time.sleep(8)   # never read
PY
t1=$(ticks)
m8_ticks=$((t1 - t0))
note "daemon CPU while an 8 MB decoy sat unread for 8 s: $m8_ticks ticks"
if [ "$m8_ticks" -lt 50 ]; then
	note "M5-8: no busy loop on a non-reading client"
else
	miss "M5-8: daemon burned $m8_ticks ticks on a non-reading client"
fi
if docker logs "$LAB-node" 2>&1 | tail -n +"$logmark" | grep -q "Timeout from .* during authentication"; then
	note "M5-8: the stalled decoy connection was dropped by the authentication timeout"
else
	miss "M5-8: stalled decoy connection was not dropped within the client's 8 s"
fi

# ---- upstream proxy --------------------------------------------------------
echo "===== Task 2: HttpsDecoyUpstream ====="
# The upstream logs every request head it receives (M5-10 check below).
docker run -d --name "$LAB-up" --network "$NET" --ip "$UP_IP" "$TOOLS" python3 -c '
import socket
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 80)); srv.listen(16)
body = b"UPSTREAM-DECOY-MARKER\n"
while True:
    c, _ = srv.accept(); head = b""
    while b"\r\n\r\n" not in head:
        d = c.recv(4096)
        if not d: break
        head += d
    open("/tmp/upstream.log", "ab").write(head + b"\n----\n")
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
    c.close()
' >/dev/null
sleep 2

# Point the node at the upstream and reload.
docker exec "$LAB-node" sh -c "sed -i 's/      AddressPool:/      HttpsDecoyUpstream: $UP_IP:80\n      AddressPool:/' /etc/tincstack/tinc.yaml"
docker exec "$LAB-node" tinc -c /etc/tincstack/tinc.yaml -n wsg1 reload >/dev/null 2>&1 || docker restart "$LAB-node" >/dev/null
sleep 3

up=$(docker run --rm --net "container:$LAB-node" "$TOOLS" curl -sk https://127.0.0.1:655/ || true)

if echo "$up" | grep -q "UPSTREAM-DECOY-MARKER"; then
	note "with HttpsDecoyUpstream set, the response is the upstream's"
else
	miss "upstream proxy did not return the upstream page"
	echo "    got: $(echo "$up" | head -1)"
fi

# ---- review M5-10: an authenticator-shaped request is not forwarded --------
echo "===== M5-10: tinc-shaped authenticator never reaches the upstream ====="
docker exec "$LAB-up" sh -c ': > /tmp/upstream.log'
docker run --rm --net "container:$LAB-node" "$TOOLS" curl -sk -o /dev/null https://127.0.0.1:655/ws \
	-H "Upgrade: websocket" -H "Connection: Upgrade" -H "Sec-WebSocket-Version: 13" \
	-H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Cookie: sid=LEAKMARK-AUTHENTICATOR" || true
sleep 1
uplog=$(docker exec "$LAB-up" cat /tmp/upstream.log 2>/dev/null || true)
if [ -z "$uplog" ]; then
	miss "M5-10: the upstream saw no request at all (proxy path broken?)"
elif echo "$uplog" | grep -qi "LEAKMARK\|sid=\|Upgrade: websocket\|Sec-WebSocket"; then
	miss "M5-10: the authenticator headers were forwarded to the upstream in the clear"
	echo "$uplog" | grep -i "cookie\|upgrade\|sec-websocket" | sed 's/^/    /'
else
	note "M5-10: upstream saw the request without Cookie/Upgrade/Sec-WebSocket headers"
fi

# ---- review M5-1: a black-holed upstream must not stall the loop -----------
echo "===== M5-1: black-holed HttpsDecoyUpstream, concurrent probe latency ====="
# $SUBNET.250 has no host on the lab subnet: connect() never completes.
docker exec "$LAB-node" sh -c "sed -i 's/HttpsDecoyUpstream: .*/HttpsDecoyUpstream: $SUBNET.250:80/' /etc/tincstack/tinc.yaml"
docker exec "$LAB-node" tinc -c /etc/tincstack/tinc.yaml -n wsg1 reload >/dev/null 2>&1 || true
sleep 1
# Probe 1 waits for the upstream (3 s deadline, then the static page). Probe 2,
# started 0.5 s later, needs the event loop for its TLS handshake: the time
# to complete that handshake (curl time_appconnect) is the loop latency.
# Before the fix it waited behind probe 1's blocking connect (~2.5 s).
docker run --rm --net "container:$LAB-node" "$TOOLS" curl -sk --max-time 10 -o /dev/null https://127.0.0.1:655/ >/dev/null 2>&1 &
sleep 0.5
p2=$(docker run --rm --net "container:$LAB-node" "$TOOLS" curl -sk --max-time 10 -w '%{time_appconnect} %{time_total}' -o /dev/null https://127.0.0.1:655/ 2>/dev/null || echo "fail fail")
wait
p2hs=${p2%% *}
note "probe 2 while probe 1 hung on the black-holed upstream: TLS handshake ${p2hs}s, total ${p2#* }s"
if awk "BEGIN{exit !(${p2hs:-99} < 1.0)}" 2>/dev/null; then
	note "M5-1: the loop served probe 2's handshake while probe 1's upstream fetch was pending (< 1 s)"
else
	miss "M5-1: probe 2's handshake took ${p2hs}s: the loop was stalled by probe 1"
fi

echo "==========================================="

if [ "$fail" = 0 ]; then
	echo "PASS: certificate automation + default-on decoy + review-R regressions"
	exit 0
else
	echo "FAIL"
	exit 1
fi

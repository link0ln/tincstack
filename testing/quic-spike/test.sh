#!/bin/sh
# test.sh -- runs INSIDE the spike container (see run.sh).
#
# Generates a self-signed EC P-256 certificate (the format G1 stores in the
# node YAML), runs the server and the client over loopback under tcpdump,
# then a second pair with a wrong pin to prove pinning rejects, and prints
# one PASS/FAIL line per primitive. Exit status is non-zero on any FAIL.
# Logs and the capture go to $OUT (mounted by run.sh).
set -u

OUT=${OUT:-/out}
PORT=${PORT:-4433}
ALPN=${ALPN:-h3}
SNI=${SNI:-cdn.example.net}
mkdir -p "$OUT"
cd /tmp || exit 1

fail=0
verdict() {   # verdict <ok:0|1> <name> <detail>
	if [ "$1" -eq 0 ]; then echo "PASS $2 -- $3"; else echo "FAIL $2 -- $3"; fail=1; fi
}

echo "== certificate"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout key.pem -out cert.pem -days 30 -subj "/CN=$SNI" 2>/dev/null || exit 1
PIN=$(openssl x509 -in cert.pem -noout -fingerprint -sha256 | cut -d= -f2)
echo "self-signed EC P-256, sha256 fingerprint $PIN"
head -1 key.pem

echo "== session 1: correct pin (tcpdump on lo)"
# --immediate-mode: the whole session takes well under the 1 s TPACKET_V3
# block timeout, so without it the capture is still in the kernel ring when
# tcpdump is stopped and the file ends up empty.
tcpdump -Z root --immediate-mode -i lo -w "$OUT/spike.pcap" "udp port $PORT" 2>"$OUT/tcpdump.err" &
TCPD=$!
sleep 1
/spike/spike-server 127.0.0.1 "$PORT" cert.pem key.pem "$ALPN" 2>"$OUT/server.log" &
SRV=$!
sleep 0.3
/spike/spike-client 127.0.0.1 "$PORT" "$PIN" "$ALPN" "$SNI" 2>"$OUT/client.log"
CRC=$?
wait $SRV
SRC=$?
sleep 1.5
kill $TCPD 2>/dev/null
wait $TCPD 2>/dev/null

echo "== session 2: wrong pin (must be rejected)"
BADPIN=0000000000000000000000000000000000000000000000000000000000000000
/spike/spike-server 127.0.0.1 "$PORT" cert.pem key.pem "$ALPN" 2>"$OUT/server-badpin.log" &
SRV=$!
sleep 0.3
/spike/spike-client 127.0.0.1 "$PORT" "$BADPIN" "$ALPN" "$SNI" 2>"$OUT/client-badpin.log"
BRC=$?
wait $SRV
BSRC=$?

echo "== client log (session 1)"
cat "$OUT/client.log"
echo "== server log (session 1)"
cat "$OUT/server.log"
echo "== client log (session 2, wrong pin)"
cat "$OUT/client-badpin.log"
echo "== server log (session 2, wrong pin)"
cat "$OUT/server-badpin.log"
echo "== capture (session 1)"
python3 /spike/pcap_first.py "$OUT/spike.pcap" | tee "$OUT/pcap.txt"

echo "== results"
has() { grep -q -- "$2" "$1"; }

client_res() {  # client_res <name> -> 0 if RESULT PASS <name> in client.log
	grep -q "^RESULT PASS $1\b" "$OUT/client.log"
}

# (a) handshake with PEM cert/key, client pins by sha256
client_res handshake && has "$OUT/server.log" "server HANDSHAKE ok" && has "$OUT/client.log" "PIN ok"
verdict $? handshake "TLS 1.3 in QUIC v1, server cert from PEM, client verified by SHA-256 pin: $(grep -o 'PIN ok sha256=[0-9a-f]*' "$OUT/client.log" | head -1)"

# pin mismatch must fail the handshake
[ "$BRC" -ne 0 ] && has "$OUT/client-badpin.log" "PIN mismatch" && ! has "$OUT/server-badpin.log" "server HANDSHAKE ok"
verdict $? pin-mismatch-rejected "wrong pin: client exit=$BRC ($(grep -o 'HANDSHAKE failed.*' "$OUT/client-badpin.log" | head -1)); server never reached handshake ok ($(grep -o 'CLOSED by peer.*' "$OUT/server-badpin.log" | head -1))"

# (b) datagrams both ways
client_res datagram && has "$OUT/server.log" "server DATAGRAM recv"
verdict $? datagram "$(grep -o 'ROUND round1 .*' "$OUT/client.log")"

# (c) one bidirectional stream both ways
client_res stream && has "$OUT/server.log" "server STREAM recv"
verdict $? stream "$(grep -o 'STREAM opened id=[0-9]*' "$OUT/client.log"); $(grep -o 'server STREAM recv.*' "$OUT/server.log" | head -1)"

# (d1) NAT rebind: server must validate the client's NEW port
NEWPORT=$(grep -o 'REBIND nat-rebind: local port [0-9]* -> [0-9.]*:[0-9]*' "$OUT/client.log" | sed 's/.*://')
client_res rebind && [ -n "$NEWPORT" ] && has "$OUT/server.log" "PATH_VALIDATION success remote=127.0.0.1:$NEWPORT"
verdict $? rebind "$(grep -o 'REBIND nat-rebind.*' "$OUT/client.log"); server: $(grep -o "PATH_VALIDATION success remote=127.0.0.1:$NEWPORT" "$OUT/server.log" | head -1); $(grep -o 'ROUND after-rebind.*' "$OUT/client.log")"

# (d2) explicit migration with a new connection id
MPORT=$(grep -o 'REBIND migrate: local port [0-9]* -> [0-9.]*:[0-9]*' "$OUT/client.log" | sed 's/.*://')
client_res migrate && [ -n "$MPORT" ] && has "$OUT/server.log" "PATH_VALIDATION success remote=127.0.0.1:$MPORT"
verdict $? migrate "$(grep -o 'REBIND migrate.*' "$OUT/client.log"); $(grep -o 'ROUND after-migrate.*' "$OUT/client.log")"

# (e) ALPN / SNI visible on both sides
has "$OUT/server.log" "HANDSHAKE ok alpn=$ALPN sni=$SNI" && has "$OUT/client.log" "HANDSHAKE ok alpn=$ALPN"
verdict $? alpn-sni "$(grep -o 'server HANDSHAKE ok.*' "$OUT/server.log")"

# close + clean exit of both processes
client_res close && [ "$CRC" -eq 0 ] && [ "$SRC" -eq 0 ] && has "$OUT/server.log" "CLOSED by peer"
verdict $? close "client exit=$CRC server exit=$SRC ($(grep -o 'server CLOSED by peer.*' "$OUT/server.log"))"

# classifier bytes: first packet on the wire is a long header with the fixed
# bit set and version 0x00000001
FIRST=$(grep '^pkt   1 ' "$OUT/pcap.txt")
echo "$FIRST" | grep -q 'form=long fixed=1 type=Initial version=0x00000001'
verdict $? classifier "wire: $FIRST"

[ "$fail" -eq 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit $fail

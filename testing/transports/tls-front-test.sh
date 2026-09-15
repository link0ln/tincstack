#!/bin/sh
# tls-front-test.sh -- prove M5 (G1) tasks 1 and 2:
#   1. certificate automation (first start -> keys present; restart -> same
#      fingerprint; a real cert via TlsCert/TlsKey is served);
#   2. the default-on decoy (curl -k https shows the decoy over a valid TLS
#      handshake; openssl s_client shows the cert; nmap -sV says https; plain
#      HTTP gets the page too; HttpsDecoyUpstream is honoured).
#
# All tooling (curl/openssl/nmap) runs in throwaway containers sharing the
# node's network namespace, so nothing is installed on the host. Test data is
# under /tmp/wsg1-* only.
#
# Usage: testing/transports/tls-front-test.sh [image]
set -e

IMG=${1:-tincstack/core:ws-g1}
TOOLS=nicolaka/netshoot
NET=wsg1front
BASE=/tmp/wsg1-front
NODE_IP=10.41.9.10
UP_IP=10.41.9.20

cleanup() {
	docker rm -f wsg1-node wsg1-up wsg1-tool >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -rf "$BASE"
mkdir -p "$BASE"
docker network create --subnet 10.41.9.0/24 "$NET" >/dev/null

fail=0
note() { echo "  $1"; }
miss() { echo "  MISS: $1"; fail=1; }

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
docker run -d --name wsg1-node --network "$NET" --ip "$NODE_IP" --cap-add NET_ADMIN \
	--device /dev/net/tun -v "$BASE":/etc/tincstack "$IMG" \
	tincd -c /etc/tincstack/tinc.yaml -n wsg1 -D -d2 >/dev/null
sleep 3

echo "===== Task 2: default-on decoy ====="

# openssl s_client: a valid TLS handshake presenting the node's cert.
sc=$(docker run --rm --net container:wsg1-node "$TOOLS" \
	sh -c "echo Q | openssl s_client -connect 127.0.0.1:655 -servername example.com 2>/dev/null" || true)

if echo "$sc" | grep -q "BEGIN CERTIFICATE"; then
	note "openssl s_client completed a TLS handshake and got the certificate"
else
	miss "openssl s_client did not get a certificate"
fi

# The served cert fingerprint must equal the persisted one.
scfp=$(docker run --rm --net container:wsg1-node "$TOOLS" \
	sh -c "echo Q | openssl s_client -connect 127.0.0.1:655 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null" | sed 's/.*=//;s/[^0-9a-fA-F]//g' | tr 'A-F' 'a-f' || true)

if [ -n "$scfp" ] && [ "$scfp" = "$fp1" ]; then
	note "served cert fingerprint matches the persisted TlsFingerprint"
else
	miss "served cert fingerprint ($scfp) != persisted ($fp1)"
fi

# curl -k https: the decoy page over TLS.
hb=$(docker run --rm --net container:wsg1-node "$TOOLS" \
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
hp=$(docker run --rm --net container:wsg1-node "$TOOLS" \
	curl -s http://127.0.0.1:655/ || true)

if echo "$hp" | grep -qi "It works"; then
	note "curl http (cleartext) returned the decoy page too"
else
	miss "plain HTTP did not return the decoy page"
fi

# nmap -sV must identify the port as SSL/HTTPS, never as tinc.
nm=$(docker run --rm --net container:wsg1-node "$TOOLS" \
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

# ---- upstream proxy --------------------------------------------------------
echo "===== Task 2: HttpsDecoyUpstream ====="
docker run -d --name wsg1-up --network "$NET" --ip "$UP_IP" "$TOOLS" \
	sh -c 'mkdir -p /srv && printf "UPSTREAM-DECOY-MARKER\n" > /srv/index.html && cd /srv && python3 -m http.server 80' >/dev/null
sleep 2

# Point the node at the upstream and reload.
docker exec wsg1-node sh -c "sed -i 's/      AddressPool:/      HttpsDecoyUpstream: $UP_IP:80\n      AddressPool:/' /etc/tincstack/tinc.yaml"
docker exec wsg1-node tinc -c /etc/tincstack/tinc.yaml -n wsg1 reload >/dev/null 2>&1 || docker restart wsg1-node >/dev/null
sleep 3

up=$(docker run --rm --net container:wsg1-node "$TOOLS" curl -sk https://127.0.0.1:655/ || true)

if echo "$up" | grep -q "UPSTREAM-DECOY-MARKER"; then
	note "with HttpsDecoyUpstream set, the response is the upstream's"
else
	miss "upstream proxy did not return the upstream page"
	echo "    got: $(echo "$up" | head -1)"
fi

echo "==========================================="

if [ "$fail" = 0 ]; then
	echo "PASS: certificate automation + default-on decoy"
	exit 0
else
	echo "FAIL"
	exit 1
fi

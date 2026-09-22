#!/usr/bin/env bash
# A peer that renews its certificate must not lock everyone out of https/quic.
#
# Peers pin a node's front certificate by SHA-256 (TlsFingerprint). `tinc cert
# renew` replaces that certificate every couple of months, so a pin that never
# moves turns every renewal into an outage of the https and quic carriers --
# and since the Linux image can renew on a timer, an unattended one. The rule
# now (https.c verify_server_cert, transport_quic_tls.c verify_pin):
#
#   * a certificate that differs from the pin is let through only when a
#     publicly trusted CA issued it for the name that was dialled (SNI) --
#     which a renewal always is and an attacker on path is not;
#   * any certificate -- first contact or moved -- is pinned only after SPTPS
#     inside that very session has authenticated the peer, and the pin
#     replaces the old one rather than being appended after it.
#
# Per carrier (https, then quic), node A dials node B by name (nodeb.lab.test)
# with no fallback: B accepts only that carrier and refuses cleartext meta.
#   1. B holds the wrong Ed25519 key in A's record: TLS completes, SPTPS fails
#      -> no pin is written (review M5-7; before the fix quic pinned here)
#   2. first contact with the right key -> connected, exactly one pin = leaf1
#   3. B renews: new key, new certificate from the same CA for the same name
#      -> A reconnects, re-pins: exactly one pin = leaf2
#   4. B switches to a self-signed certificate for the same name -> refused,
#      pin unchanged
#   5. B presents a CA certificate for another name -> refused, pin unchanged
#
# The "public CA" is a throwaway CA A trusts through SSL_CERT_FILE, which both
# OpenSSL (https) and our GnuTLS glue (quic) honour. Nothing leaves the host.
#
# Usage: [CORE_IMAGE=...] [ONLY="https quic"] testing/transports/cert-repin-test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
RUN="$HERE/run-repin"
PFX=repin
NET=${PFX}net
SUBNET=10.47.3
A_IP=$SUBNET.10
B_IP=$SUBNET.11
NAME=nodeb.lab.test
FAILED=0

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

cleanup() {
	docker rm -f "$PFX-a" "$PFX-b" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	docker run --rm -v "$RUN:/r" "$IMG" sh -c 'rm -rf /r/*' >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$RUN/pki"
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

# ---- PKI: one CA, four certificates -----------------------------------------
docker run --rm -v "$RUN/pki:/p" -e NAME="$NAME" "$IMG" sh -c '
	set -e
	cd /p
	key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
	key ca.key
	openssl req -x509 -new -key ca.key -days 30 -subj "/CN=Repin Lab Root" \
		-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
		-out ca.pem 2>/dev/null
	leaf() { # name file host
		key "$1.key"
		openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null
		printf "subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n" "$2" > "$1.ext"
		openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 20 \
			-extfile "$1.ext" -out "$1.pem" 2>/dev/null
	}
	leaf leaf1 "$NAME"
	leaf leaf2 "$NAME"
	leaf other other.lab.test
	key self.key
	openssl req -x509 -new -key self.key -days 20 -subj "/CN=$NAME" \
		-addext "subjectAltName=DNS:$NAME" -out self.pem 2>/dev/null
	for c in leaf1 leaf2 other self; do
		printf "%s " "$c"; openssl x509 -in "$c.pem" -outform DER | sha256sum | cut -d" " -f1
	done > fps
	chmod -R a+rX /p
'
fp() { awk -v c="$1" '$1 == c { print $2 }' "$RUN/pki/fps"; }

# ---- node configs ------------------------------------------------------------
materialise() { # dir name
	mkdir -p "$RUN/$1"
	printf 'networks:\n  lab:\n    options:\n      Name: %s\n      Mode: router\n      Port: 655\n      PingTimeout: 3\n      MaxTimeout: 3\n      AddressPool: 10.198.0.0/24\n' "$2" > "$RUN/$1/tinc.yaml"
	timeout 4 docker run --rm -v "$RUN/$1:/c" "$IMG" tincd -c /c/tinc.yaml -n lab -D -d1 >/dev/null 2>&1 || true
	docker run --rm -v "$RUN/$1:/c" "$IMG" chmod -R a+rwX /c
}
materialise a nodea
materialise b nodeb
materialise x nodex             # only for its public key: the "wrong key" case
cp "$RUN/pki/ca.pem" "$RUN/a/ca.pem"

# configure <carrier> <b-key-from: b|x>
#   A: prefers only <carrier>, knows B by name with B's (or X's) Ed25519 key and
#   no TlsFingerprint. B: accepts only <carrier>, no cleartext meta, serves the
#   certificate in /c/cur.pem.
configure() {
	python3 - "$RUN" "$1" "$2" <<-'PY'
		import re, sys
		run, carrier, keyfrom = sys.argv[1:]

		def host_block(path, name):
		    s = open(path).read()
		    m = re.search(r'^      %s: \|\n((?:(?:        .*)?\n)+)' % name, s, re.M)
		    return [l[8:] for l in m.group(1).splitlines() if l.strip()]

		def set_options(path, extra):
		    s = open(path).read()
		    # tincd rewrites flow lists as block lists when it saves the file, so
		    # drop a key together with any "- item" lines under it
		    s = re.sub(r'\n      (PreferredTransports|Transports|AllowPlainMeta|ConnectTo|TlsCert|TlsKey):.*(\n        - .*)*', '', s)
		    s = s.replace('    options:\n', '    options:\n' + ''.join('      %s\n' % e for e in extra), 1)
		    open(path, 'w').write(s)

		def set_host(path, name, lines):
		    s = open(path).read()
		    s = re.sub(r'^      %s: \|\n(?:(?:        .*)?\n)+' % name, '', s, flags=re.M)
		    s = s.replace('    hosts:\n', '    hosts:\n      %s: |\n' % name + ''.join('        %s\n' % l for l in lines), 1)
		    open(path, 'w').write(s)

		a, b, x = ('%s/%s/tinc.yaml' % (run, d) for d in 'abx')
		key = [l for l in host_block(b if keyfrom == 'b' else x, 'nodeb' if keyfrom == 'b' else 'nodex')
		       if l.startswith('Ed25519PublicKey')]
		set_host(a, 'nodeb', ['Address = nodeb.lab.test', 'Port = 655', 'Transports = %s' % carrier, 'Subnet = 10.198.0.2/32'] + key)
		set_host(b, 'nodea', [l for l in host_block(a, 'nodea') if l.startswith('Ed25519PublicKey')] +
		         ['Subnet = 10.198.0.1/32'])
		set_options(a, ['PreferredTransports: [%s]' % carrier, 'ConnectTo: [nodeb]'])
		set_options(b, ['Transports: [%s]' % carrier, 'AllowPlainMeta: no',
		                'TlsCert: /c/cur.pem', 'TlsKey: /c/cur.key'])
	PY
}

serve() { # <cert> -- what B presents from now on (applied by restarting B)
	cp "$RUN/pki/$1.pem" "$RUN/b/cur.pem"
	cp "$RUN/pki/$1.key" "$RUN/b/cur.key"
	chmod 644 "$RUN/b/cur.pem" "$RUN/b/cur.key"
}

start_b() {
	docker rm -f "$PFX-b" >/dev/null 2>&1 || true
	docker run -d --name "$PFX-b" --network "$NET" --ip "$B_IP" --cap-add NET_ADMIN --device /dev/net/tun \
		-v "$RUN/b:/c" "$IMG" tincd -c /c/tinc.yaml -n lab -D -d3 >/dev/null
}

start_a() {
	docker rm -f "$PFX-a" >/dev/null 2>&1 || true
	docker run -d --name "$PFX-a" --network "$NET" --ip "$A_IP" --cap-add NET_ADMIN --device /dev/net/tun \
		--add-host "$NAME:$B_IP" -e SSL_CERT_FILE=/c/ca.pem \
		-v "$RUN/a:/c" "$IMG" tincd -c /c/tinc.yaml -n lab -D -d3 >/dev/null
}

# pins -> the TlsFingerprint values in A's record for B, one per line
pins() {
	python3 - "$RUN/a/tinc.yaml" <<-'PY'
		import re, sys
		s = open(sys.argv[1]).read()
		m = re.search(r'^      nodeb: \|\n((?:(?:        .*)?\n)+)', s, re.M)
		for l in (m.group(1).splitlines() if m else []):
		    l = l.strip()
		    if l.lower().startswith('tlsfingerprint'):
		        print(l.split('=', 1)[1].strip())
	PY
}

wait_log() { # <container> <pattern> <seconds>
	local deadline=$((SECONDS + $3))
	while ((SECONDS < deadline)); do
		docker logs "$1" 2>&1 | grep -q -- "$2" && return 0
		sleep 1
	done
	return 1
}

connected() { # A has an activated meta connection to B
	docker exec "$PFX-a" tinc -c /c/tinc.yaml -n lab dump reachable nodes 2>/dev/null | grep -q '^nodeb '
}

wait_connected() { # <seconds>
	local deadline=$((SECONDS + $1))
	while ((SECONDS < deadline)); do
		connected && return 0
		sleep 1
	done
	return 1
}

expect_pins() { # <label> <expected fp or "none">
	local got n
	got="$(pins)"
	n=$(printf '%s' "$got" | grep -c . || true)
	if [[ $2 == none && $n -eq 0 ]] || [[ $2 != none && $n -eq 1 && $got == "$2" ]]; then
		ok "$1"
	else
		bad "$1 (want ${2}, A's record has $n pin(s): ${got//$'\n'/ })"
	fi
}

run_carrier() {
	local c=$1
	log "==== carrier: $c"

	# -- 1. the wrong key: TLS completes, SPTPS does not ---------------------
	configure "$c" x
	serve leaf1
	start_b
	start_a
	if wait_log "$PFX-a" "Peer nodeb had unknown identity\|Error while processing\|Invalid KEX\|signature\|Timeout from nodeb\|failed to verify\|Closing connection with nodeb" 25; then :; fi
	sleep 6
	if connected; then
		bad "$c: a peer holding the wrong key must not connect"
	else
		ok "$c: a peer holding the wrong key does not connect"
	fi
	expect_pins "$c: ... and no pin is written for it (M5-7)" none

	# -- 2. first contact -----------------------------------------------------
	docker rm -f "$PFX-a" >/dev/null
	configure "$c" b
	start_b
	start_a
	if wait_connected 40; then
		ok "$c: first contact connects"
	else
		bad "$c: first contact connects"
		docker logs "$PFX-a" 2>&1 | grep -iE "$c|pin|certificate|refus" | tail -8 >&2
	fi
	sleep 2
	expect_pins "$c: first contact pins leaf1, once" "$(fp leaf1)"

	# -- 3. renewal -----------------------------------------------------------
	serve leaf2
	start_b
	if wait_log "$PFX-a" "presents a new certificate ($(fp leaf2)" 60 && wait_connected 40; then
		ok "$c: after a renewal (new key, same CA, same name) A reconnects"
	else
		bad "$c: after a renewal A reconnects"
		docker logs "$PFX-a" 2>&1 | grep -iE "$c|pin|certificate|refus" | tail -8 >&2
	fi
	wait_log "$PFX-a" "pinning TlsFingerprint $(fp leaf2)" 20 || true
	expect_pins "$c: ... and replaces the pin with leaf2, leaving one" "$(fp leaf2)"

	# -- 4. a self-signed replacement is refused ------------------------------
	serve self
	start_b
	if wait_log "$PFX-a" "is not one a CA issued for $NAME" 60; then
		ok "$c: a self-signed replacement is refused"
		docker logs "$PFX-a" 2>&1 | grep -o "does not match the pinned.*refusing" | tail -1 | cut -c1-170 >&2
	else
		bad "$c: a self-signed replacement is refused"
	fi
	sleep 3
	if connected; then
		bad "$c: ... A must not be connected to it"
	else
		ok "$c: ... A stays disconnected"
	fi
	expect_pins "$c: ... and the pin is still leaf2" "$(fp leaf2)"

	# -- 5. a CA certificate for another name is refused ----------------------
	docker rm -f "$PFX-a" >/dev/null
	serve other
	start_b
	start_a
	if wait_log "$PFX-a" "is not one a CA issued for $NAME" 60; then
		ok "$c: a CA certificate for another name is refused"
	else
		bad "$c: a CA certificate for another name is refused"
	fi
	expect_pins "$c: ... and the pin is still leaf2" "$(fp leaf2)"

	docker rm -f "$PFX-a" "$PFX-b" >/dev/null
	# the next carrier starts from an unpinned record again
	python3 - "$RUN/a/tinc.yaml" <<-'PY'
		import re, sys
		p = sys.argv[1]; s = open(p).read()
		open(p, 'w').write(re.sub(r'\n        TlsFingerprint = .*', '', s))
	PY
}

for c in ${ONLY:-https quic}; do
	run_carrier "$c"
done

if [ "$FAILED" -eq 0 ]; then
	log "certificate re-pinning: all checks passed"
else
	log "certificate re-pinning: FAILURES above"
fi
exit "$FAILED"

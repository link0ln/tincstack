#!/usr/bin/env bash
# Wire-fingerprint audit: does each carrier look like the protocol it declares?
#
# Owner's standing rule (PLAN.md, 2026-09-23): `https` must look like HTTPS,
# `quic` like QUIC, failure paths included. This lab measures that instead of
# asserting it. One server certificate, two servers, three clients, one
# dissector:
#
#   servers  B = our tincd (https front + quic on the tinc port)
#            N = nginx (official image, TLS + HTTP/3 on 443) -- the reference
#   clients  A = our tincd dialling B (https, then quic)
#            curl (OpenSSL 3.5, h2 / --http3-only) and Chromium (headless)
#            against both servers
#   captures tcpdump in B's and N's network namespaces
#   dissector tshark 4.4: JA4 / JA4_r / JA3 of every ClientHello (QUIC
#            Initials are decrypted by tshark on its own), JA3S of every
#            ServerHello, ALPN, SNI, source ports, ClientHello frame sizes and
#            the QUIC transport parameters every client sends
#
# It reports; it does not pass or fail -- the deltas go to PLAN.md with this
# run's report as the proof. Everything stays on this host.
#
# Usage: [CORE_IMAGE=...] testing/fingerprint/run.sh
# Output: testing/fingerprint/results/<run-id>/{report.txt,probes.txt,*.pcap};
# results/2026-09-23/ is the committed first run (PLAN.md cites it).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
NGINX="${NGINX_IMAGE:-nginx:1.27}"
RUN="$HERE/run"
OUT="$HERE/results/$(date +%Y%m%d-%H%M%S)"
PFX=fp
NET=${PFX}net
SUBNET=10.47.4
A_IP=$SUBNET.10
B_IP=$SUBNET.11
N_IP=$SUBNET.12
NAME=nodeb.lab.test

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

cleanup() {
	docker rm -f "$PFX-a" "$PFX-b" "$PFX-n" "$PFX-capb" "$PFX-capn" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	docker run --rm -v "$RUN:/r" "$IMG" sh -c 'rm -rf /r/*' >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$RUN/pki" "$OUT"
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

if ! docker image inspect "$TOOLS" >/dev/null 2>&1; then
	log "building $TOOLS"
	docker build -q --build-arg http_proxy="${HTTP_PROXY:-}" --build-arg https_proxy="${HTTP_PROXY:-}" \
		-t "$TOOLS" "$HERE" >/dev/null
fi

# ---- one certificate for both servers, from a throwaway CA -------------------
docker run --rm -v "$RUN/pki:/p" -e NAME="$NAME" "$IMG" sh -c '
	set -e; cd /p
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key 2>/dev/null
	openssl req -x509 -new -key ca.key -days 30 -subj "/CN=Fingerprint Lab Root" \
		-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -out ca.pem 2>/dev/null
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key 2>/dev/null
	openssl req -new -key leaf.key -subj "/CN=$NAME" -out leaf.csr 2>/dev/null
	printf "subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n" "$NAME" > leaf.ext
	openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 20 -extfile leaf.ext -out leaf.pem 2>/dev/null
	cat leaf.pem ca.pem > chain.pem
	chmod -R a+rX /p'

# ---- tinc nodes ----------------------------------------------------------------
materialise() { # dir name
	mkdir -p "$RUN/$1"
	printf 'networks:\n  lab:\n    options:\n      Name: %s\n      Mode: router\n      Port: 655\n      PingTimeout: 3\n      MaxTimeout: 3\n      AddressPool: 10.198.0.0/24\n' "$2" > "$RUN/$1/tinc.yaml"
	timeout 4 docker run --rm -v "$RUN/$1:/c" "$IMG" tincd -c /c/tinc.yaml -n lab -D -d1 >/dev/null 2>&1 || true
	docker run --rm -v "$RUN/$1:/c" "$IMG" chmod -R a+rwX /c
}
materialise a nodea
materialise b nodeb
cp "$RUN/pki/leaf.pem" "$RUN/pki/leaf.key" "$RUN/b/"
chmod 644 "$RUN/b/leaf.pem" "$RUN/b/leaf.key"

configure() { # <carrier A prefers>
	python3 - "$RUN" "$1" <<-'PY'
		import re, sys
		run, carrier = sys.argv[1:]

		def host_block(path, name):
		    s = open(path).read()
		    m = re.search(r'^      %s: \|\n((?:(?:        .*)?\n)+)' % name, s, re.M)
		    return [l[8:] for l in m.group(1).splitlines() if l.strip()]

		def set_options(path, extra):
		    s = open(path).read()
		    s = re.sub(r'\n      (PreferredTransports|Transports|AllowPlainMeta|ConnectTo|TlsCert|TlsKey):.*(\n        - .*)*', '', s)
		    s = s.replace('    options:\n', '    options:\n' + ''.join('      %s\n' % e for e in extra), 1)
		    open(path, 'w').write(s)

		def set_host(path, name, lines):
		    s = open(path).read()
		    s = re.sub(r'^      %s: \|\n(?:(?:        .*)?\n)+' % name, '', s, flags=re.M)
		    s = s.replace('    hosts:\n', '    hosts:\n      %s: |\n' % name + ''.join('        %s\n' % l for l in lines), 1)
		    open(path, 'w').write(s)

		a, b = ('%s/%s/tinc.yaml' % (run, d) for d in 'ab')
		ed = lambda path, n: [l for l in host_block(path, n) if l.startswith('Ed25519PublicKey')]
		set_host(a, 'nodeb', ['Address = nodeb.lab.test', 'Port = 655', 'Transports = https, quic',
		                      'Subnet = 10.198.0.2/32'] + ed(b, 'nodeb'))
		set_host(b, 'nodea', ed(a, 'nodea') + ['Subnet = 10.198.0.1/32'])
		set_options(a, ['PreferredTransports: [%s]' % carrier, 'ConnectTo: [nodeb]'])
		set_options(b, ['Transports: [https, quic]', 'AllowPlainMeta: no',
		                'TlsCert: /c/leaf.pem', 'TlsKey: /c/leaf.key'])
	PY
}
configure https

docker run -d --name "$PFX-b" --network "$NET" --ip "$B_IP" --cap-add NET_ADMIN --device /dev/net/tun \
	-v "$RUN/b:/c" "$IMG" tincd -c /c/tinc.yaml -n lab -D -d2 >/dev/null

# ---- nginx, the reference server -----------------------------------------------
mkdir -p "$RUN/n"
cp "$RUN/pki/chain.pem" "$RUN/pki/leaf.key" "$RUN/n/"
chmod 644 "$RUN/n/"*
cat > "$RUN/n/default.conf" <<-EOF
	server {
	    listen 443 ssl;
	    listen 443 quic reuseport;
	    http2 on;
	    server_name $NAME;
	    ssl_certificate     /etc/nginx/tls/chain.pem;
	    ssl_certificate_key /etc/nginx/tls/leaf.key;
	    ssl_protocols TLSv1.2 TLSv1.3;
	    add_header Alt-Svc 'h3=":443"; ma=86400';
	    location / { root /usr/share/nginx/html; }
	}
EOF
docker run -d --name "$PFX-n" --network "$NET" --ip "$N_IP" \
	-v "$RUN/n:/etc/nginx/tls:ro" -v "$RUN/n/default.conf:/etc/nginx/conf.d/default.conf:ro" "$NGINX" >/dev/null

# ---- captures ------------------------------------------------------------------
for s in b n; do
	docker run -d --name "$PFX-cap$s" --network "container:$PFX-$s" --cap-add NET_ADMIN --cap-add NET_RAW \
		-v "$OUT:/out" "$TOOLS" tcpdump -U -i any -s 0 -w "/out/$s.pcap" 'tcp or udp' >/dev/null
done
sleep 3

# ---- clients -------------------------------------------------------------------
tools() { # run a reference client on the lab network, as a separate source IP each time
	docker run --rm --network "$NET" --add-host "$NAME:$1" "$TOOLS" sh -c "$2" 2>&1 | tail -c 600
}
chrome() { # <server ip> <url> [extra flags]
	tools "$1" "chromium --headless=new --no-sandbox --disable-gpu --ignore-certificate-errors \
		--user-data-dir=/tmp/c --host-resolver-rules='MAP $NAME $1' ${3:-} --dump-dom '$2' >/dev/null 2>&1; echo chromium done"
}

log "A (tincd) dials B via https"
docker run -d --name "$PFX-a" --network "$NET" --ip "$A_IP" --cap-add NET_ADMIN --device /dev/net/tun \
	--add-host "$NAME:$B_IP" -v "$RUN/a:/c" "$IMG" tincd -c /c/tinc.yaml -n lab -D -d2 >/dev/null
sleep 8
docker rm -f "$PFX-a" >/dev/null

log "A (tincd) dials B via quic"
configure quic
docker run -d --name "$PFX-a" --network "$NET" --ip "$A_IP" --cap-add NET_ADMIN --device /dev/net/tun \
	--add-host "$NAME:$B_IP" -v "$RUN/a:/c" "$IMG" tincd -c /c/tinc.yaml -n lab -D -d2 >/dev/null
sleep 8
docker logs "$PFX-a" 2>&1 | grep -E "activated|via (https|quic)" | tail -3 > "$OUT/a-log.txt" || true
docker rm -f "$PFX-a" >/dev/null

log "curl: TLS and HTTP/3 against B and N"
{
	echo "== curl -> B https =="; tools "$B_IP" "curl -sk -m 5 -i https://$NAME:655/ | head -12"
	echo "== curl -> N https =="; tools "$N_IP" "curl -sk -m 5 -i https://$NAME/ | head -12"
	echo "== curl -> B garbage over TLS =="; tools "$B_IP" "printf 'XYZZY\r\n\r\n' | openssl s_client -quiet -connect $NAME:655 -servername $NAME 2>/dev/null | head -5"
	echo "== curl -> N garbage over TLS =="; tools "$N_IP" "printf 'XYZZY\r\n\r\n' | openssl s_client -quiet -connect $NAME:443 -servername $NAME 2>/dev/null | head -5"
	echo "== curl -> B http3 =="; tools "$B_IP" "curl -sSk -m 5 -i --http3-only https://$NAME:655/ 2>&1 | head -12"
	echo "== curl -> N http3 =="; tools "$N_IP" "curl -sSk -m 5 -i --http3-only https://$NAME/ 2>&1 | head -12"
} > "$OUT/probes.txt" 2>&1

log "chromium: TLS and QUIC against B and N"
chrome "$B_IP" "https://$NAME:655/" >/dev/null
chrome "$N_IP" "https://$NAME/" >/dev/null
chrome "$B_IP" "https://$NAME:655/" "--enable-quic --origin-to-force-quic-on=$NAME:655" >/dev/null
chrome "$N_IP" "https://$NAME/" "--enable-quic --origin-to-force-quic-on=$NAME:443" >/dev/null
sleep 2
docker rm -f "$PFX-capb" "$PFX-capn" >/dev/null

# ---- dissect -------------------------------------------------------------------
log "dissecting"
docker run --rm -v "$OUT:/out" -e A_IP="$A_IP" "$TOOLS" sh -c '
	cd /out
	F="ip.src udp.srcport tcp.srcport tls.handshake.extensions_server_name tls.handshake.extensions_alpn_str tls.handshake.ja4 tls.handshake.ja3 frame.len"
	fields() { for f in $F; do printf -- "-e %s " "$f"; done; }
	for s in b n; do
		echo "######## server $s: ClientHellos (src, sport, SNI, ALPN, JA4, JA3, frame bytes)"
		tshark -r $s.pcap -Y "tls.handshake.type == 1" -T fields -E separator=" | " $(fields) 2>/dev/null
		echo "######## server $s: ClientHello JA4_r (raw)"
		tshark -r $s.pcap -Y "tls.handshake.type == 1" -T fields -e ip.src -e udp.srcport -e tls.handshake.ja4_r 2>/dev/null
		echo "######## server $s: ServerHellos (dst, JA3S, cipher, frame bytes)"
		tshark -r $s.pcap -Y "tls.handshake.type == 2" -T fields -E separator=" | " -e ip.dst -e udp.dstport -e tls.handshake.ja3s -e tls.handshake.ciphersuite -e frame.len 2>/dev/null
		echo "######## server $s: QUIC transport parameters sent by clients"
		tshark -r $s.pcap -Y "tls.handshake.type == 1 && quic" -V 2>/dev/null | grep -E "^\s+(Parameter: |Internet Protocol Version 4, Src)" | sed "s/^ *//"
	done' > "$OUT/report.txt"
cat "$OUT/a-log.txt" >> "$OUT/report.txt"
log "report: $OUT/report.txt (+ probes.txt, b.pcap, n.pcap)"

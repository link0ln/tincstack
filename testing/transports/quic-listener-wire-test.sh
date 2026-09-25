#!/usr/bin/env bash
# The quic listener next to the web server it claims to be.
#
# Our listener answers HTTP/3 on UDP 443 with a decoy for anyone who is not a
# tinc peer, so it must be indistinguishable from nginx there, failure paths
# included. The reference is Debian 13's own nginx package (1.26.3 on OpenSSL
# 3.5, testing/transports/nginx-deb13): the same TLS stack as ours, so both
# answer curl's X25519MLKEM768 share, and the same default page as our
# decoy. It gets the founder's own certificate and key, so certificate sizes
# do not differ. curl --http3-only with a key log dials both, raw probes
# (quic_probe.py) poke both, and each check compares the two:
#
#   * answers to one-datagram probes: Version Negotiation for an unknown
#     version, stateless reset for an unknown connection, silence for junk;
#   * the refusal of a wrong ALPN: its CONNECTION_CLOSE sits in an Initial
#     packet, readable by anyone;
#   * the server's connection id length, in every long header in the clear;
#   * its handshake flight: datagram sizes, packets, Length fields, frames
#     (CRYPTO framing, where the PADDING goes, any 1-RTT packet in it);
#   * its transport parameters: set, order, values (connection ids and the
#     reset token by name only);
#   * its first 1-RTT datagram (tickets, HANDSHAKE_DONE, NEW_CONNECTION_ID,
#     HTTP/3 streams), its session tickets, its HTTP/3 SETTINGS;
#   * its HTTP/3 answers to GET /, GET /nope, HEAD /, POST /, DELETE /.
#
# Every difference is a FAIL. Written on 2026-09-25 as the acceptance test
# for making the listener nginx's, when most checks failed; all of them pass
# since 2026-09-26 (core/tincd/PATCHES.md), so it is a regression test now
# (PLAN.md, "The listener's QUIC side vs nginx").
#
# Usage: [CORE_IMAGE=...] [NGINX_IMAGE=...] [KEEP=1] testing/transports/quic-listener-wire-test.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
NGINX="${NGINX_IMAGE:-tincstack/nginx-deb13:dev}"
PY="${PYTHON_IMAGE:-python:3.12-slim}"
PFX=qlw
NET=${PFX}net
SUBNET=10.47.20
F_IP=$SUBNET.10
N_IP=$SUBNET.11
Y=/c/tinc.yaml
RUN="$HERE/run-quic-listener-wire"
FAILED=0

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

cleanup() {
	docker rm -f "$PFX-f" "$PFX-n" "$PFX-capf" "$PFX-capn" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup
[[ -n ${KEEP:-} ]] || trap cleanup EXIT
docker run --rm -v "$HERE:/h" "$TOOLS" sh -c 'rm -rf /h/run-quic-listener-wire' >/dev/null 2>&1 || true
mkdir -p "$RUN/n"
if [[ -z ${NGINX_IMAGE:-} ]]; then
	proxy=${http_proxy:-${HTTP_PROXY:-}}
	docker build -q ${proxy:+--build-arg http_proxy="$proxy" --build-arg https_proxy="$proxy"} \
		-t "$NGINX" "$HERE/nginx-deb13" >/dev/null || { log "cannot build $NGINX"; exit 2; }
fi

# ---- the founder and nginx with the founder's certificate ------------------------------------------
docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null
docker run -d --name "$PFX-f" --network "$NET" --ip "$F_IP" --cap-add NET_ADMIN --device /dev/net/tun \
	"$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
t() { docker exec "$PFX-f" tinc -n lab -c "$Y" "$@"; }
docker exec "$PFX-f" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
docker exec -d "$PFX-f" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
for _ in $(seq 20); do t pid >/dev/null 2>&1 && break; sleep 1; done
t set founder.Address "$F_IP"
for _ in $(seq 20); do docker exec "$PFX-f" grep -q '^      tls_key: |' "$Y" && break; sleep 1; done
pem() { # <yaml key> <PEM label>: that block of the founder's keys section
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
docker run -d --name "$PFX-n" --network "$NET" --ip "$N_IP" -v "$RUN/n:/n" \
	-v "$RUN/n/default.conf:/etc/nginx/conf.d/default.conf:ro" "$NGINX" >/dev/null
for x in f n; do
	docker run -d --name "$PFX-cap$x" --network "container:$PFX-$x" -v "$RUN:/r" "$TOOLS" \
		tcpdump -i eth0 -U -w "/r/$x.pcap" udp port 443 >/dev/null
done
sleep 2

# ---- traffic: curl, a wrong ALPN, raw probes ------------------------------------------------------
docker run --rm --network "$NET" -v "$RUN:/r" "$TOOLS" sh -c "
	for x in f:$F_IP n:$N_IP; do
		ip=\${x#*:}; n=\${x%%:*}
		SSLKEYLOGFILE=/r/keys curl -sk -m 8 -o /dev/null --http3-only https://\$ip/
		for r in 'GET /' 'GET /nope' 'HEAD /' 'POST /' 'DELETE /'; do
			m=\${r% *}; p=\${r#* }
			if [ \$m = HEAD ]; then o=-I; else o=\"-X \$m\"; fi
			[ \$m = POST ] && o=\"\$o -d x\"
			# one retry for a lost exchange (seen once against nginx in 25 POSTs)
			for try in 1 2; do
				a=\$(curl -sk -m 5 --http3-only \$o -o /dev/null -D /r/h -w '%{http_code} %{size_download} B' https://\$ip\$p 2>/dev/null)
				case \$a in 000*) ;; *) break ;; esac
			done
			printf '%s\t%s [%s]\n' \"\$r\" \"\$a\" \"\$(tr -d '\r' < /r/h | sed -n 's/^\\([a-z-]*\\):.*/\\1/p' | paste -sd, -)\" >> /r/answers-\$n.txt
			rm -f /r/h
		done
		timeout 8 openssl s_client -quic -alpn hq-interop -servername example.com -connect \$ip:443 </dev/null >/dev/null 2>&1
	done" 2>/dev/null
for x in f n; do
	ip=$F_IP; [[ $x == n ]] && ip=$N_IP
	docker run --rm --network "$NET" -v "$HERE:/p:ro" "$PY" python3 /p/quic_probe.py "$ip" > "$RUN/probes-$x.txt"
done
sleep 1
docker stop -t 2 "$PFX-capf" "$PFX-capn" >/dev/null

TS() { local x=$1; shift; docker run --rm -v "$RUN:/r" "$TOOLS" tshark -r "/r/$x.pcap" -o tls.keylog_file:/r/keys "$@" 2>/dev/null; }
compare() { # <what> <ours> <nginx's>
	printf '%s\nlistener\n%s\nnginx\n%s\n\n' "$1" "$2" "$3" >> "$RUN/compare.txt"
	if [[ -n $3 && $2 == "$3" ]]; then
		ok "$1 is nginx's: $(head -c 160 <<<"$2" | tr '\n\t' '; ')"
	else
		bad "$1 differs"
		diff <(echo "$2") <(echo "$3") | sed 's/^/     /' >&2 || true
	fi
}

# ---- one-datagram probes ----------------------------------------------------------------------------
compare "the answers to one-datagram probes" "$(cat "$RUN/probes-f.txt")" "$(cat "$RUN/probes-n.txt")"

# ---- a wrong ALPN: the Initial-level CONNECTION_CLOSE ------------------------------------------------
alpn() { # the server's Initial CONNECTION_CLOSE to the connection that offered hq-interop
	TS "$1" -Y "quic.cc.error_code && udp.srcport == 443" -T fields -e udp.length -e quic.cc.error_code \
		-e quic.cc.frame_type -e quic.cc.reason_phrase | head -1
}
compare "the CONNECTION_CLOSE for a wrong ALPN (udp length, error, frame type, reason)" "$(alpn f)" "$(alpn n)"

# ---- the handshake of curl's first connection --------------------------------------------------------
first() { # the first connection to 443 in the capture: its client port
	TS "$1" -Y "udp.dstport == 443 && quic.long.packet_type == 0" -T fields -e udp.srcport | head -1
}
cf=$(first f); cn=$(first n)
compare "the server's connection id length" \
	"$(TS f -Y "udp.srcport == 443 && udp.dstport == $cf && quic.long.packet_type" -T fields -e quic.scil | head -1)" \
	"$(TS n -Y "udp.srcport == 443 && udp.dstport == $cn && quic.long.packet_type" -T fields -e quic.scil | head -1)"
flight() { # <x> <client port>: the server's datagrams before its first short-header one
	TS "$1" -Y "udp.srcport == 443 && udp.dstport == $2" -T fields -e udp.length -e quic.long.packet_type \
		-e quic.length -e quic.frame_type | awk -F'\t' '$2 == "" { exit } { print }' | head -3 |
		sed 's/0x00000000000000//g'
}
compare "the server's handshake flight (udp length, packets, Lengths, frames)" "$(flight f "$cf")" "$(flight n "$cn")"

params() { # <x> <client port>: the server's transport parameters, ids and token by name only
	TS "$1" -Y "tls.handshake.type == 8 && udp.dstport == $2" -V | grep -E '^ +Parameter: ' | sed 's/^ *//' |
		sed -E 's/^(Parameter: (original_destination_connection_id|initial_source_connection_id|retry_source_connection_id|stateless_reset_token)) .*/\1/'
}
compare "the server's transport parameters" "$(params f "$cf")" "$(params n "$cn")"

onertt() { # <x> <client port>: frames of the server's first two 1-RTT datagrams
	TS "$1" -Y "udp.srcport == 443 && udp.dstport == $2 && !quic.long.packet_type" -T fields -e udp.length \
		-e quic.frame_type | head -2 | sed 's/0x00000000000000//g'
}
compare "the server's first 1-RTT datagrams (udp length, frames)" "$(onertt f "$cf")" "$(onertt n "$cn")"

tickets() {
	TS "$1" -Y "tls.handshake.type == 4 && udp.dstport == $2" -T fields -e tls.handshake.session_ticket_lifetime_hint \
		-e tls.handshake.session_ticket_length | head -1
}
compare "the session tickets (lifetime, length)" "$(tickets f "$cf")" "$(tickets n "$cn")"

settings() {
	TS "$1" -Y "http3.settings && udp.srcport == 443 && udp.dstport == $2" -V |
		grep -E '^ +Settings (Identifier|Value)' | sed 's/^ *//' | paste -sd' ' | sed 's/ Settings Identifier/\nSettings Identifier/g'
}
compare "the HTTP/3 SETTINGS" "$(settings f "$cf")" "$(settings n "$cn")"

# ---- HTTP/3 answers -----------------------------------------------------------------------------------
compare "the HTTP/3 answers (status, body size, header names)" "$(cat "$RUN/answers-f.txt")" "$(cat "$RUN/answers-n.txt")"

if [[ $FAILED -eq 0 ]]; then
	log "quic listener wire: all checks passed"
else
	log "quic listener wire: FAILURES above ($RUN/compare.txt)"
fi
exit "$FAILED"

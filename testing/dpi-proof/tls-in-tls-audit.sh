#!/usr/bin/env bash
# T1a: does the TLS-in-TLS burst model catch our carriers carrying a browser's HTTPS?
#
# The handshakes are byte-equal to curl/nginx (testing/fingerprint); this lab
# looks at what comes after them. A user behind the tunnel opens HTTPS sites,
# so the tunnel carries inner TLS handshakes, and nDPI (>= 4.12) looks for
# the byte shape of a TLS handshake inside TLS and inside unknown flows
# (Xue et al., USENIX Security 2024). Scenarios, each its own capture:
#
#   direct   negative control: curl and Chromium open HTTPS to a web server
#            straight, no tunnel -- plain TLS must not be flagged
#   keepalive  negative control for the whole-flow scoring: one long HTTPS
#            connection, KEEPALIVE requests with a browser-sized header for
#            objects of web-like sizes (log-uniform 200 B .. 100 KB) -- how
#            often plain TLS falls under a threshold by chance
#   kasmall, kah2, h2page  more plain HTTPS of the same objects, so that the
#            reference is a population and not one request size: curl
#            keep-alive with its own small header; curl over HTTP/2 on one
#            connection; CHROME Chromium loads of a page that pulls every
#            object over HTTP/2 (port 8444, h2 on; the carriers' workload
#            stays on 8443, HTTP/1.1, comparable across cores)
#   proxy    the same clients through a per-connection TLS tunnel
#            (tls_forward.py, the trojan/VLESS shape) as a 2026 server runs
#            it: the web-sized chain, OpenSSL's default groups, two tickets
#   proxy0   the same tunnel as nDPI's own sample captures look: a small
#            ECDSA certificate, P-256, no tickets -- the positive control:
#            nDPI 6.0 must flag it, or the arbiter proves nothing
#   <carrier> for each of CARRIERS: the leaf dials the founder over it; as
#            soon as the tunnel pings, the same clients browse through it
#            ("early", inside nDPI's packet window), then pings for the
#            overhead calibration, a 4 MiB HTTPS download, and the clients
#            again ("late")
#
# The web server is nginx 1.26.3 with a web-sized chain (RSA-2048 leaf +
# RSA-2048 intermediate): a toy certificate would shrink the server's burst
# and flatter us.
#
# Two judges read every capture: upstream nDPI 6.0's ndpiReader (the arbiter;
# its own proxy captures are checked first) and tls_in_tls.py, which scores
# the same model with a margin, as nDPI runs it and over the whole flow. The
# offloads are off on both nodes, so the capture sees the packets as sent.
# It reports; it does not pass or fail.
#
# Usage: flock /tmp/tincstack-lab.lock testing/dpi-proof/tls-in-tls-audit.sh [outdir]
#   env: CORE_IMAGE, NGINX_IMAGE, TOOLS_IMAGE, PROBER_IMAGE, NDPI_IMAGE,
#        CARRIERS (default "https obfs quic"), ROUNDS (curl per phase, 10),
#        CHROME (Chromium per phase, 4), KEEPALIVE (requests, 80),
#        LIMITS (default 25,255), KEEP=1, KEEP_PCAP=1 (copy the captures to outdir)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
NGINX="${NGINX_IMAGE:-tincstack/nginx-deb13:dev}"
PROBER="${PROBER_IMAGE:-tincstack/fp-prober:ww-n2}"
NDPI="${NDPI_IMAGE:-tincstack/ndpi:6.0}"
PFX=wwti
NET=${PFX}net
SUBNET=10.49.69
F_IP=$SUBNET.10
L_IP=$SUBNET.11
Y=/c/tinc.yaml
CARRIERS=${CARRIERS:-https obfs quic}
ROUNDS=${ROUNDS:-10}
CHROME=${CHROME:-4}
KEEPALIVE=${KEEPALIVE:-80}
LIMITS=${LIMITS:-25,255}
OUT=${1:-$HERE/results/$(date +%Y%m%d-%H%M%S)-tls-in-tls}
RUN="$HERE/run-tls-in-tls"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
cleanup() {
	docker rm -f "$PFX-f" "$PFX-l" "$PFX-n" "$PFX-fp" "$PFX-fp0" "$PFX-lc" "$PFX-lp" "$PFX-lp0" "$PFX-cap" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup
[[ -n ${KEEP:-} ]] || trap 'cleanup; docker run --rm -v "$HERE:/h" "$TOOLS" rm -rf /h/run-tls-in-tls >/dev/null 2>&1' EXIT
docker run --rm -v "$HERE:/h" "$TOOLS" rm -rf /h/run-tls-in-tls >/dev/null 2>&1 || true
mkdir -p "$RUN/n/html" "$OUT"
: > "$RUN/phases.tsv"
mark() { printf '%s\t%s\n' "$1" "$(date +%s.%N)" >> "$RUN/phases.tsv"; }
t() { local n=$1; shift; docker exec "$PFX-$n" tinc -n lab -c "$Y" "$@"; }

cap_start() { # <name>
	docker rm -f "$PFX-cap" >/dev/null 2>&1
	docker run -d --name "$PFX-cap" --network "container:$PFX-f" -v "$RUN:/r" "$TOOLS" \
		tcpdump -i eth0 -U -w "/r/$1.pcap" ip >/dev/null
	sleep 2
}
cap_stop() { sleep 1; docker stop -t 3 "$PFX-cap" >/dev/null; }

# <host> <port>: ROUNDS curl GETs and CHROME Chromium page loads, each a new TLS connection
browse() {
	local ok=0 _
	for _ in $(seq "$ROUNDS"); do
		docker exec "$PFX-lc" curl -sk -m 20 -o /dev/null -w '%{http_code}\n' "https://$1:$2/" | grep -q 200 && ok=$((ok + 1))
		sleep 0.3
	done
	for _ in $(seq "$CHROME"); do
		docker exec "$PFX-lc" sh -c "rm -rf /tmp/chr; timeout 30 chromium --headless=new --no-sandbox --disable-gpu \
			--ignore-certificate-errors --user-data-dir=/tmp/chr --dump-dom https://$1:$2/" 2>/dev/null | grep -q tincstack-inner && ok=$((ok + 1))
		sleep 0.3
	done
	echo "$ok/$((ROUNDS + CHROME))"
}

# ---- lab ----------------------------------------------------------------------------------------------
docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null || exit 2
for n in f:$F_IP l:$L_IP; do
	docker run -d --name "$PFX-${n%%:*}" --network "$NET" --ip "${n#*:}" --cap-add NET_ADMIN \
		--device /dev/net/tun "$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
	docker run --rm --network "container:$PFX-${n%%:*}" --cap-add NET_ADMIN --entrypoint ethtool "$NDPI" \
		-K eth0 tso off gso off gro off >/dev/null 2>&1 || log "ethtool failed on $n"
done
docker exec "$PFX-f" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
docker exec -d "$PFX-f" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
for _ in $(seq 20); do t f pid >/dev/null 2>&1 && break; sleep 1; done
t f set founder.Address "$F_IP"
t l join "$(t f invite leaf)" >/dev/null 2>&1

# The inner web site: a CA, an intermediate and a leaf, all RSA; nginx sends leaf + intermediate.
docker run --rm -v "$RUN/n:/n" -w /n "$TOOLS" sh -c '
	openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.pem -days 3650 -subj "/C=US/O=Example Trust/CN=Example Root CA" 2>/dev/null
	openssl req -newkey rsa:2048 -nodes -keyout int.key -out int.csr -subj "/C=US/O=Example Trust/CN=Example TLS RSA CA 2026" 2>/dev/null
	printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" > int.ext
	openssl x509 -req -in int.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1825 -extfile int.ext -out int.pem 2>/dev/null
	openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj "/CN=www.example.com" 2>/dev/null
	printf "subjectAltName=DNS:www.example.com,DNS:example.com\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n" > leaf.ext
	openssl x509 -req -in leaf.csr -CA int.pem -CAkey int.key -CAcreateserial -days 90 -extfile leaf.ext -out leaf.pem 2>/dev/null
	cat leaf.pem int.pem > chain.pem
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout small.key -out small.pem -days 90 -subj "/CN=www.example.com" 2>/dev/null
	chmod 644 *.pem *.key'
chain=$(docker run --rm -v "$RUN/n:/n" "$TOOLS" sh -c 'for c in leaf int; do openssl x509 -in /n/$c.pem -outform der | wc -c; done' | awk '{s += $1} END {print s}')
{ printf '<!DOCTYPE html><html><head><title>tincstack-inner</title></head><body>'; head -c 3000 /dev/urandom | base64 -w 100; printf '</body></html>\n'; } > "$RUN/n/html/index.html"
head -c 4194304 /dev/urandom > "$RUN/n/html/big"
mkdir -p "$RUN/n/html/o"
awk -v n="$KEEPALIVE" 'BEGIN { srand(7); for (i = 1; i <= n; i++) printf "%d %d\n", i, int(exp(log(200) + rand() * (log(100000) - log(200)))) }' |
	while read -r i sz; do head -c "$sz" /dev/urandom > "$RUN/n/html/o/$i"; done
chmod -R a+rX "$RUN/n"
{ printf '<!DOCTYPE html><html><head><title>tincstack-inner</title></head><body>'; seq -f '<img src="/o/%g">' "$KEEPALIVE"; printf '</body></html>\n'; } > "$RUN/n/html/h2.html"
cat > "$RUN/n/default.conf" <<-'EOF'
	server {
	    listen 8443 ssl;
	    ssl_certificate     /n/chain.pem;
	    ssl_certificate_key /n/leaf.key;
	    location / { root /n/html; }
	}
	server {
	    listen 8444 ssl;
	    http2 on;
	    ssl_certificate     /n/chain.pem;
	    ssl_certificate_key /n/leaf.key;
	    location / { root /n/html; }
	}
EOF
docker run -d --name "$PFX-n" --network "container:$PFX-f" -v "$RUN/n:/n:ro" \
	-v "$RUN/n/default.conf:/etc/nginx/conf.d/default.conf:ro" "$NGINX" >/dev/null
docker run -d --name "$PFX-fp" --network "container:$PFX-f" -v "$HERE:/h:ro" -v "$RUN/n:/n:ro" "$PROBER" \
	python3 /h/tls_forward.py server 9443 /n/chain.pem /n/leaf.key 127.0.0.1 8443 >/dev/null
docker run -d --name "$PFX-fp0" --network "container:$PFX-f" -v "$HERE:/h:ro" -v "$RUN/n:/n:ro" "$PROBER" \
	python3 /h/tls_forward.py server 9444 /n/small.pem /n/small.key 127.0.0.1 8443 0 prime256v1 >/dev/null
docker run -d --name "$PFX-lc" --network "container:$PFX-l" "$TOOLS" sleep infinity >/dev/null
docker run -d --name "$PFX-lp" --network "container:$PFX-l" -v "$HERE:/h:ro" "$PROBER" \
	python3 /h/tls_forward.py client 18443 "$F_IP" 9443 >/dev/null
docker run -d --name "$PFX-lp0" --network "container:$PFX-l" -v "$HERE:/h:ro" "$PROBER" \
	python3 /h/tls_forward.py client 18444 "$F_IP" 9444 prime256v1 >/dev/null
sleep 2

# ---- controls -----------------------------------------------------------------------------------------
log "=== direct: HTTPS straight to the web server ==="
cap_start direct; mark direct
echo "direct $(browse "$F_IP" 8443)" >> "$RUN/browse.txt"
cap_stop
log "=== keepalive: one long HTTPS connection ==="
cap_start keepalive; mark keepalive
# One curl, many URLs: HTTP/1.1 keep-alive on one connection. The header is a
# browser's size (Chromium's UA, Accept*, a 300-byte cookie).
docker exec "$PFX-lc" sh -c "curl -sk -m 120 --http1.1 -w '%{http_code}\n' \
	-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36' \
	-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
	-H 'Accept-Language: en-US,en;q=0.9' -H 'Cookie: session=$(head -c 225 /dev/urandom | base64 -w0)' \
	$(seq -f "-o /dev/null https://$F_IP:8443/o/%g" "$KEEPALIVE" | tr '\n' ' ')" | grep -c 200 | sed 's|^|keepalive |; s|$|/'"$KEEPALIVE"'|' >> "$RUN/browse.txt"
cap_stop
log "=== kasmall / kah2 / h2page: more plain HTTPS, the rest of the reference ==="
cap_start kasmall; mark kasmall
docker exec "$PFX-lc" sh -c "curl -sk -m 120 --http1.1 -w '%{http_code}\n' \
	$(seq -f "-o /dev/null https://$F_IP:8443/o/%g" "$KEEPALIVE" | tr '\n' ' ')" | grep -c 200 | sed 's|^|kasmall |; s|$|/'"$KEEPALIVE"'|' >> "$RUN/browse.txt"
cap_stop
cap_start kah2; mark kah2
docker exec "$PFX-lc" sh -c "curl -sk -m 120 --http2 -w '%{http_code}\n' \
	-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36' \
	-H 'Accept-Language: en-US,en;q=0.9' -H 'Cookie: session=$(head -c 225 /dev/urandom | base64 -w0)' \
	$(seq -f "-o /dev/null https://$F_IP:8444/o/%g" "$KEEPALIVE" | tr '\n' ' ')" | grep -c 200 | sed 's|^|kah2 |; s|$|/'"$KEEPALIVE"'|' >> "$RUN/browse.txt"
cap_stop
cap_start h2page; mark h2page
ok=0
for _ in $(seq "$CHROME"); do
	docker exec "$PFX-lc" sh -c "rm -rf /tmp/chr; timeout 60 chromium --headless=new --no-sandbox --disable-gpu \
		--ignore-certificate-errors --user-data-dir=/tmp/chr --dump-dom https://$F_IP:8444/h2.html" 2>/dev/null | grep -q tincstack-inner && ok=$((ok + 1))
	sleep 0.3
done
echo "h2page $ok/$CHROME" >> "$RUN/browse.txt"
cap_stop
log "=== proxy / proxy0: HTTPS through a per-connection TLS tunnel, with and without tickets ==="
cap_start proxy; mark proxy
echo "proxy $(browse 127.0.0.1 18443)" >> "$RUN/browse.txt"
cap_stop
cap_start proxy0; mark proxy0
echo "proxy0 $(browse 127.0.0.1 18444)" >> "$RUN/browse.txt"
cap_stop

# ---- ours ---------------------------------------------------------------------------------------------
for carrier in $CARRIERS; do
	log "=== ours over $carrier ==="
	t l set PreferredTransports "$carrier"
	cap_start "$carrier"; mark "$carrier-dial"
	docker exec -d "$PFX-l" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
	fv=""
	for _ in $(seq 40); do
		fv=$(docker exec "$PFX-f" ip -4 -br addr show lab 2>/dev/null | awk '{print $3}' | cut -d/ -f1)
		[[ -n $fv ]] && docker exec "$PFX-l" ping -c1 -W1 "$fv" >/dev/null 2>&1 && break
		sleep 0.5
	done
	mark "$carrier-early"
	echo "$carrier-early $(browse "$fv" 8443)" >> "$RUN/browse.txt"
	t l dump connections 2>&1 | grep '^founder' > "$RUN/$carrier-connection.txt"
	t l info founder 2>&1 | grep -E 'PMTU|Status' >> "$RUN/$carrier-connection.txt"
	mark "$carrier-calib"
	docker exec "$PFX-l" ping -q -c20 -i0.2 -s100 "$fv" > "$RUN/$carrier-ping.txt" 2>&1
	mark "$carrier-calib-end"
	mark "$carrier-bulk"
	docker exec "$PFX-lc" curl -sk -m 120 -o /dev/null -w "$carrier bulk %{http_code} %{size_download} B %{time_total} s\n" \
		"https://$fv:8443/big" >> "$RUN/browse.txt"
	mark "$carrier-late"
	echo "$carrier-late $(browse "$fv" 8443)" >> "$RUN/browse.txt"
	mark "$carrier-stop"
	t l stop >/dev/null 2>&1
	sleep 2
	cap_stop
done

# ---- judges -------------------------------------------------------------------------------------------
log "=== arbiter self-check: nDPI's own proxy captures ==="
IFS=, read -ra LIM <<< "$LIMITS"
# The heuristic's own window is max_packets_extra_dissection, but nDPI stops
# looking at a flow after packets_limit_per_flow (32) packets and ndpiReader
# after 24 UDP / 80 TCP packets: with the stock limits (N <= 25) the arbiter is
# what a default nDPI deployment sees; above that every budget is raised to N.
cfg() {
	echo "--cfg=tls,dpi.heuristics,0x07 --cfg=tls,dpi.heuristics.max_packets_extra_dissection,$1"
	[[ $1 -gt 25 ]] && echo "--cfg=packets_limit_per_flow,$1 -U $1 -T $1"
}
selfcheck=0
for s in trojan-tcp-tls vmess-tcp-tls shadowsocks-tcp; do
	# shellcheck disable=SC2046
	n=$(docker run --rm "$NDPI" -i "/samples/tls_heur__$s.pcapng" -q -v 2 $(cfg 25) 2>&1 | grep -c 'Obfuscated TLS')
	echo "arbiter self-check $s: $n flow(s) flagged" >> "$RUN/arbiter.txt"
	[[ $n -ge 1 ]] || selfcheck=1
done
REFS="keepalive kasmall kah2 h2page"
scen="direct $REFS proxy proxy0 $CARRIERS"
for s in $scen; do
	for n in "${LIM[@]}"; do
		# shellcheck disable=SC2046
		docker run --rm -v "$RUN:/r:ro" "$NDPI" -i "/r/$s.pcap" -q -v 2 $(cfg "$n") > "$RUN/$s.ndpi$n.txt" 2>&1
	done
done
py() { docker run --rm -v "$HERE:/h:ro" -v "$RUN:/r" -w /r "$PROBER" python3 /h/tls_in_tls.py "$@"; }
at() { awk -v n="$1" '$1 == n {print $2}' "$RUN/phases.tsv"; }
specs="direct:tcp/8443 keepalive:tcp/8443 kasmall:tcp/8443 kah2:tcp/8444 h2page:tcp/8444 proxy:tcp/9443 proxy0:tcp/9444"
for s in direct proxy proxy0; do py score --limits "$LIMITS" --phases /r/phases.tsv --json "/r/$s.json" "/r/$s.pcap" > "$RUN/$s.score.txt"; done
# The plain-HTTPS reference also runs under the tuned scoring of the https
# carrier (its measured overhead), below, so the two compare like for like.
for c in $CARRIERS; do
	ov=$(py calibrate "/r/$c.pcap" "$(at "$c-calib")" "$(at "$c-calib-end")" 128 2>>"$RUN/calibrate.txt")
	echo "$c overhead $ov B per packet" >> "$RUN/calibrate.txt"
	[[ $ov =~ ^[0-9]+$ ]] || ov=24
	py score --limits "$LIMITS" --overhead "$ov:$ov" --phases /r/phases.tsv --json "/r/$c.json" "/r/$c.pcap" > "$RUN/$c.score.txt"
	[[ $c == https ]] && ka_ov=$ov
	case $c in https) specs+=" https:tcp/443" ;; quic) specs+=" quic:udp/443" ;; *) specs+=" $c:udp/655" ;; esac
done
for s in $REFS; do
	py score --limits "$LIMITS" --overhead "${ka_ov:-24}:${ka_ov:-24}" --phases /r/phases.tsv --json "/r/$s.json" \
		"/r/$s.pcap" > "$RUN/$s.score.txt"
done
# shellcheck disable=SC2086
py report --json /r/summary.json --reference "${REFS// /,}" /r $specs > "$RUN/report.txt"

{
	echo "== TLS-in-TLS burst model: $(date -u +%FT%TZ) =="
	echo "core $IMG $(docker image inspect "$IMG" --format '{{.Id}}')"
	echo "arbiter $NDPI nDPI $(docker run --rm --entrypoint cat "$NDPI" /ndpi-ref) (tag 6.0), --cfg=tls,dpi.heuristics,0x07, max_packets_extra_dissection $LIMITS (above 25 also packets_limit_per_flow and -U/-T)"
	echo "inner site: nginx $(docker run --rm --entrypoint nginx "$NGINX" -v 2>&1 | cut -d/ -f2), chain leaf+intermediate ${chain:-?} B DER"
	[[ $selfcheck == 0 ]] && echo "arbiter self-check: PASS" || echo "arbiter self-check: FAIL -- the arbiter flags nothing, every verdict below is void"
	echo; cat "$RUN/report.txt"
	echo; echo "--- browse (successful page loads) ---"; cat "$RUN/browse.txt"
	echo "--- overhead calibration (ping -s100, inner IP 128 B) ---"; cat "$RUN/calibrate.txt"
	for c in $CARRIERS; do echo "$c ping $(grep -o 'rtt.*' "$RUN/$c-ping.txt")"; done
	for c in $CARRIERS; do echo "--- $c link ---"; cat "$RUN/$c-connection.txt"; done
	echo "--- arbiter ---"; cat "$RUN/arbiter.txt"
	for s in $scen; do
		for n in "${LIM[@]}"; do
			echo "--- $s: flows ndpiReader flags (max_packets $n) ---"
			grep -E '^\s+[0-9]+\s+(TCP|UDP) ' "$RUN/$s.ndpi$n.txt" | grep 'Obfuscated' | sed -E 's/\]\[/] [/g' | cut -c1-240 || true
		done
	done
} > "$OUT/tls-in-tls.report.txt"
# *.report.txt: the only text files a committed results/ tree keeps (.gitignore)
for f in "$RUN"/*.score.txt "$RUN"/*.ndpi*.txt; do cp "$f" "$OUT/$(basename "${f%.txt}").report.txt"; done
cp "$RUN"/*.json "$RUN/phases.tsv" "$OUT/"
[[ -n ${KEEP_PCAP:-} ]] && cp "$RUN"/*.pcap "$OUT/"
cat "$OUT/tls-in-tls.report.txt"
log "results in $OUT"

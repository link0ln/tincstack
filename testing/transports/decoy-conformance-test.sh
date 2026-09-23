#!/usr/bin/env bash
# The https front answers like nginx -- the same probe, the same answer.
#
# The fingerprint audit (2026-09-23) found a decoy no web server resembles:
# 200 with the same page for every path and for garbage, no Date header,
# silence for plain bytes on the TLS port, a bare FIN without close_notify,
# and a connection that never closes when the client says nothing (tinc's
# tarpit). This lab puts our node next to nginx 1.27 (`server_tokens off`,
# HTTP/1.1 -- nginx's own default, `http2` off) and sends both the same
# probes:
#
#   * status and header names, in order, for GET / (keep-alive and close),
#     HEAD, an unknown path, POST, garbage, HTTP/1.1 without Host, HTTP/1.0;
#   * the welcome page and the error pages byte for byte (200, 404, 405, 400);
#   * two requests on one kept-alive connection;
#   * plain HTTP and a tinc ID line on the TLS port: nginx's 400 pages;
#   * a non-ASCII first byte: closed without an answer by both;
#   * 30 connections at once from one address: every one answered;
#   * after `Connection: close', close_notify before the FIN;
#   * a client that sends nothing is closed after ~60 s by both.
#
# Usage: [CORE_IMAGE=...] [QUICK=1 skips the 60 s timing case] testing/transports/decoy-conformance-test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
NGINX="${NGINX_IMAGE:-nginx:1.27}"
RUN="$HERE/run-decoy"
PFX=dcf
NET=${PFX}net
SUBNET=10.47.9
F_IP=$SUBNET.10
N_IP=$SUBNET.12
FAILED=0

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

cleanup() {
	docker rm -f "$PFX-f" "$PFX-n" "$PFX-capf" "$PFX-capn" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	docker run --rm -v "$RUN:/r" "$IMG" sh -c 'rm -rf /r/*' >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
[[ -n ${KEEP:-} ]] || trap cleanup EXIT
cleanup
mkdir -p "$RUN/f" "$RUN/n" "$RUN/cap" "$RUN/out"
chmod 777 "$RUN/cap" "$RUN/out"
docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null

if ! docker image inspect "$TOOLS" >/dev/null 2>&1; then
	docker build -q --build-arg http_proxy="${HTTP_PROXY:-}" --build-arg https_proxy="${HTTP_PROXY:-}" \
		-t "$TOOLS" "$ROOT/testing/fingerprint" >/dev/null
fi

# ---- the two servers ------------------------------------------------------------------------
docker run -d --name "$PFX-f" --network "$NET" --ip "$F_IP" --cap-add NET_ADMIN --device /dev/net/tun \
	-v "$RUN/f:/c" "$IMG" sleep infinity >/dev/null
docker exec "$PFX-f" sh -c 'install -m600 /dev/null /c/tinc.yaml && tinc -n lab -c /c/tinc.yaml set Name founder && tinc -n lab -c /c/tinc.yaml set Port 655'
docker exec -d "$PFX-f" sh -c 'tincd -n lab -c /c/tinc.yaml -D -d3 >>/c/tincd.log 2>&1'

docker run --rm -v "$RUN/n:/n" "$TOOLS" sh -c 'cd /n && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
	-nodes -days 1 -subj /CN=web.lab.test -keyout key.pem -out cert.pem 2>/dev/null && chmod 644 key.pem cert.pem'
cat > "$RUN/n/default.conf" <<-'EOF'
	server_tokens off;
	server {
	    listen 443 ssl;
	    ssl_certificate     /n/cert.pem;
	    ssl_certificate_key /n/key.pem;
	    location / { root /usr/share/nginx/html; }
	}
EOF
docker run -d --name "$PFX-n" --network "$NET" --ip "$N_IP" -v "$RUN/n:/n" \
	-v "$RUN/n/default.conf:/etc/nginx/conf.d/default.conf:ro" "$NGINX" >/dev/null
sleep 4

for s in f n; do
	docker run -d --name "$PFX-cap$s" --network "container:$PFX-$s" --cap-add NET_ADMIN --cap-add NET_RAW \
		-v "$RUN/cap:/cap" "$TOOLS" tcpdump -U --immediate-mode -i any -s 0 -w "/cap/$s.pcap" 'tcp port 443' >/dev/null
done
sleep 2

# ---- probes, the same script against each ----------------------------------------------------
cat > "$RUN/out/probe.sh" <<'EOF'
#!/usr/bin/env bash
# probe.sh <ip> <outdir>: one file per probe with the raw bytes the server sent
H=$1 O=$2
tls() { # <name> <bytes...>: send over TLS, keep the whole answer
	printf "$2" | timeout 8 openssl s_client -quiet -connect "$H:443" -servername web.lab.test \
		-keylogfile "$O/keys" 2>/dev/null > "$O/$1" || true
}
tcp() { # <name> <bytes>: send over plain TCP to the TLS port
	timeout 8 bash -c "exec 3<>/dev/tcp/$H/443; printf '$2' >&3; cat <&3" > "$O/$1" 2>/dev/null || true
}
tls get       'GET / HTTP/1.1\r\nHost: web.lab.test\r\n\r\n'
tls get_close 'GET / HTTP/1.1\r\nHost: web.lab.test\r\nConnection: close\r\n\r\n'
tls head      'HEAD / HTTP/1.1\r\nHost: web.lab.test\r\nConnection: close\r\n\r\n'
tls nope      'GET /nope HTTP/1.1\r\nHost: web.lab.test\r\nConnection: close\r\n\r\n'
tls post      'POST / HTTP/1.1\r\nHost: web.lab.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
tls garbage   'XYZZY\r\n\r\n'
tls nohost    'GET / HTTP/1.1\r\n\r\n'
tls http10    'GET / HTTP/1.0\r\n\r\n'
tls twice     'GET /nope HTTP/1.1\r\nHost: web.lab.test\r\n\r\nGET /nope HTTP/1.1\r\nHost: web.lab.test\r\nConnection: close\r\n\r\n'
tcp plain     'GET / HTTP/1.1\r\nHost: web.lab.test\r\n\r\n'
tcp tincid    '0 prober 17.7\n'
tcp highbyte  '\x80\x01\x02\x03 hello\r\n\r\n'
# 30 connections at once from one address: tinc's MaxConnectionBurst (10/s)
# used to tarpit the rest -- sockets that never answer.
for i in $(seq 30); do tcp "burst.$i" 'GET / HTTP/1.1\r\nHost: web.lab.test\r\n\r\n' & done
wait
EOF
chmod +x "$RUN/out/probe.sh"
for s in f n; do
	ip=$F_IP; [[ $s == n ]] && ip=$N_IP
	mkdir -p "$RUN/out/$s"; chmod 777 "$RUN/out/$s"
	docker run --rm --network "$NET" -v "$RUN/out:/o" "$TOOLS" /o/probe.sh "$ip" "/o/$s"
done

status() { head -1 "$1" | tr -d '\r'; }
names() { awk 'NR>1 && /^\r?$/ {exit} NR>1 {sub(/:.*/,""); print}' "$1" | tr '\n' ' '; }
body() { awk 'b {print} /^\r?$/ {b=1}' "$1"; }
count() { grep -c "^HTTP/1.1 " "$1" || true; }

for p in get get_close head nope post garbage nohost http10; do
	fs=$(status "$RUN/out/f/$p"); ns=$(status "$RUN/out/n/$p")
	fn=$(names "$RUN/out/f/$p"); nn=$(names "$RUN/out/n/$p")
	if [[ -n $ns && $fs == "$ns" && $fn == "$nn" ]]; then
		ok "$p: $fs, headers $fn"
	else
		bad "$p: ours '$fs' [$fn] vs nginx '$ns' [$nn]"
	fi
done

for p in get_close nope post garbage; do
	if [[ -s $RUN/out/n/$p ]] && cmp -s <(body "$RUN/out/f/$p") <(body "$RUN/out/n/$p"); then
		ok "$p: the page is nginx's, byte for byte"
	else
		bad "$p: the page differs from nginx's"
		diff <(body "$RUN/out/f/$p") <(body "$RUN/out/n/$p") | head -6 >&2 || true
	fi
done

if [[ $(count "$RUN/out/f/twice") == 2 && $(count "$RUN/out/n/twice") == 2 ]]; then
	ok "keep-alive: two requests on one connection, two answers (as nginx)"
else
	bad "keep-alive: ours $(count "$RUN/out/f/twice") answers, nginx $(count "$RUN/out/n/twice")"
fi

# The built-in page carries the stock nginx:1.27.5 file's dates, not the
# daemon's start time (which would change on every restart).
lm=$({ grep -i "^Last-Modified:\|^ETag:" "$RUN/out/f/get_close" || true; } | tr -d '\r' | tr '\n' ' ')
if [[ $lm == 'Last-Modified: Wed, 16 Apr 2025 12:01:11 GMT ETag: "67ff9c07-267" ' ]]; then
	ok "the built-in page has the stock nginx file's Last-Modified and ETag"
else
	bad "the built-in page's Last-Modified/ETag: $lm"
fi

for p in plain tincid; do
	fs=$(status "$RUN/out/f/$p"); ns=$(status "$RUN/out/n/$p")
	if [[ -n $ns && $fs == "$ns" ]] && cmp -s <(body "$RUN/out/f/$p") <(body "$RUN/out/n/$p"); then
		ok "$p on the TLS port: $fs with nginx's page"
	else
		bad "$p on the TLS port: ours '$fs' vs nginx '$ns'"
	fi
done

if [[ ! -s $RUN/out/f/highbyte && ! -s $RUN/out/n/highbyte ]]; then
	ok "a non-ASCII first byte: closed without an answer by both"
else
	bad "a non-ASCII first byte: ours $(wc -c <"$RUN/out/f/highbyte") bytes, nginx $(wc -c <"$RUN/out/n/highbyte")"
fi

fb=$(cat "$RUN"/out/f/burst.* | grep -c "^HTTP/1.1 400 " || true)
nb=$(cat "$RUN"/out/n/burst.* | grep -c "^HTTP/1.1 400 " || true)
if [[ $fb == 30 && $nb == 30 ]]; then
	ok "30 simultaneous connections from one address: all 30 answered (as nginx)"
else
	bad "30 simultaneous connections from one address: ours answered $fb, nginx $nb"
fi

# ---- the silent client --------------------------------------------------------------------------
if [[ -z ${QUICK:-} ]]; then
	for s in f n; do
		ip=$F_IP; [[ $s == n ]] && ip=$N_IP
		docker run --rm --network "$NET" "$TOOLS" bash -c \
			"s=\$(date +%s); exec 3<>/dev/tcp/$ip/443; timeout 100 cat <&3 >/dev/null; echo \$((\$(date +%s)-s))" > "$RUN/out/silent-$s" &
	done
	wait
	fsil=$(cat "$RUN/out/silent-f"); nsil=$(cat "$RUN/out/silent-n")
	if ((fsil >= 55 && fsil <= 70 && nsil >= 55 && nsil <= 70)); then
		ok "a silent client is closed after ${fsil} s (nginx: ${nsil} s)"
	else
		bad "a silent client is closed after ${fsil} s (nginx: ${nsil} s)"
	fi
fi

# ---- close_notify before FIN -------------------------------------------------------------------
# SIGTERM, not rm -f: tcpdump says what it captured and dropped.
docker stop -t 5 "$PFX-capf" "$PFX-capn" >/dev/null
for s in f n; do docker logs "$PFX-cap$s" 2>&1 | grep -E "captured|dropped" | tr '\n' ' ' >"$RUN/out/tcpdump-$s"; done
for s in f n; do
	ip=$F_IP; [[ $s == n ]] && ip=$N_IP
	docker run --rm -v "$RUN/cap:/cap" -v "$RUN/out:/o" "$TOOLS" tshark -r "/cap/$s.pcap" -o "tls.keylog_file:/o/$s/keys" \
		-Y "ip.src == $ip && (tls.alert_message.desc == 0 || tcp.flags.fin == 1)" -T fields -e tcp.stream -e tls.alert_message.desc -e tcp.flags.fin \
		2>/dev/null > "$RUN/out/close-$s" || true
done
# Streams where the server sent close_notify before (or with) its FIN, versus streams with a FIN at all.
cn() { awk '$2=="0" && !($1 in fin) {cn[$1]=1} $NF=="True" && !($1 in fin) {fin[$1]=1; if ($1 in cn) n++} END {print n+0 "/" length(fin)}' "$1"; }
fcn=$(cn "$RUN/out/close-f"); ncn=$(cn "$RUN/out/close-n")
if [[ ${fcn%/*} -ge 5 && ${ncn%/*} -ge 5 ]]; then
	ok "close_notify before the FIN (ours $fcn TLS closes, nginx $ncn)"
else
	bad "close_notify before the FIN (ours $fcn TLS closes, nginx $ncn)"
fi

if [[ $FAILED -eq 0 ]]; then
	log "decoy conformance: all checks passed"
else
	log "decoy conformance: FAILURES above"
fi
exit "$FAILED"

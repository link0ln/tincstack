#!/usr/bin/env bash
# The https front answers like nginx -- the same probe, the same answer.
#
# The decoy is Debian 13's nginx 1.26.3 (the owner's persona, 2026-09-26):
# Debian's own nginx.conf (`server_tokens off', `gzip on'), its stock page,
# and a site that also serves HTTP/3 on 443 and says so the usual way,
# `add_header Alt-Svc 'h3=":443"; ma=86400'' -- the tinc node serves quic on
# 443 too. The reference image is testing/transports/nginx-deb13 (OpenSSL
# 3.5, like ours). Three pairs, each probed with the same bytes:
#
#   f / n   a default node (the built-in page) / nginx with the stock root
#   g / m   a node with HttpsDecoyRoot / nginx with `root' on the same files
#   h / p   a node with HttpsDecoyUpstream / nginx with proxy_pass, both in
#           front of the same upstream (decoy_upstream.py)
#
# Each answer must equal nginx's byte for byte, with only the Date value and
# a multipart boundary's counter masked: status line, header names, values
# and order, error pages, bodies (gzip and chunk framing included).
#
#   * the page, HEAD, 404, 405, 400 (garbage, no Host, duplicate Host, a
#     bad path), 505, 414, 400 "Request Header Or Cookie Too Large",
#     absolute-form, HTTP/1.0 keep-alive, HTTP/0.9;
#   * Accept-Encoding: gzip (page, 404, HEAD, HTTP/1.0, q=0, Via);
#   * If-Modified-Since / If-None-Match -> 304, If-Match /
#     If-Unmodified-Since -> 412;
#   * Range -> 206 (one range, suffix, multipart), 416, If-Range;
#   * a directory without its slash -> 301, one without index -> 403;
#   * through a reverse proxy: nginx's Server/Date, the upstream's headers,
#     keep-alive, bodies without a length and chunked ones re-framed, and
#     the request the upstream receives (Cookie aside: never forwarded);
#   * keep-alive (two requests on one connection), plain HTTP and a tinc ID
#     line on the TLS port, a non-ASCII first byte, a 30-connection burst,
#     close_notify before the FIN;
#   * the session tickets (TLS 1.3 and 1.2): message length and lifetime;
#   * timing (not with QUICK=1): a silent client is closed after ~60 s, an
#     idle kept-alive connection after ~75 s, by both.
#
# Usage: [CORE_IMAGE=...] [NGINX_IMAGE=...] [QUICK=1] [KEEP=1] testing/transports/decoy-conformance-test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
NGINX="${NGINX_IMAGE:-tincstack/nginx-deb13:dev}"
PY="${PYTHON_IMAGE:-python:3.12-slim}"
RUN="$HERE/run-decoy"
PFX=dcf
NET=${PFX}net
SUBNET=10.47.9
F_IP=$SUBNET.10
G_IP=$SUBNET.11
H_IP=$SUBNET.13
N_IP=$SUBNET.12
M_IP=$SUBNET.14
P_IP=$SUBNET.15
UP_IP=$SUBNET.20
Y=/c/tinc.yaml
FAILED=0

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

CONTAINERS="$PFX-f $PFX-g $PFX-h $PFX-n $PFX-m $PFX-p $PFX-up $PFX-capf $PFX-capn"
cleanup() {
	# shellcheck disable=SC2086
	docker rm -f $CONTAINERS >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	docker run --rm -v "$RUN:/r" "$IMG" sh -c 'rm -rf /r/*' >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
[[ -n ${KEEP:-} ]] || trap cleanup EXIT
cleanup
mkdir -p "$RUN/n" "$RUN/site/dir" "$RUN/site/emptydir" "$RUN/cap" "$RUN/out"
chmod 777 "$RUN/cap" "$RUN/out" "$RUN/n"
docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null

if ! docker image inspect "$TOOLS" >/dev/null 2>&1; then
	docker build -q --build-arg http_proxy="${HTTP_PROXY:-}" --build-arg https_proxy="${HTTP_PROXY:-}" \
		-t "$TOOLS" "$ROOT/testing/fingerprint" >/dev/null
fi
if ! docker image inspect "$NGINX" >/dev/null 2>&1; then
	docker build -q --build-arg http_proxy="${HTTP_PROXY:-}" --build-arg https_proxy="${HTTP_PROXY:-}" \
		-t "$NGINX" "$HERE/nginx-deb13" >/dev/null
fi

# A small site for the HttpsDecoyRoot pair: a directory with an index, one
# without, a stylesheet (not gzipped: gzip_types is text/html) and a page
# (gzipped). One fixed mtime, so both servers see the same dates.
printf 'hello\n' > "$RUN/site/dir/index.html"
printf 'a.css{color:red}\n' > "$RUN/site/a.css"
printf '<html><body><p>%s</p></body></html>\n' "$(printf 'lorem ipsum %.0s' $(seq 40))" > "$RUN/site/page.html"
touch -d '2025-03-01 10:00:00 UTC' "$RUN/site/dir/index.html" "$RUN/site/a.css" "$RUN/site/page.html"
chmod -R a+rX "$RUN/site"

# ---- the upstream, the three nodes, the three nginx ---------------------------------------------
docker run -d --name "$PFX-up" --network "$NET" --ip "$UP_IP" -v "$HERE:/h:ro" -v "$RUN/out:/o" \
	"$PY" python3 /h/decoy_upstream.py /o/upstream-requests.txt >/dev/null

node() { # <name> <ip> [tinc set arguments...]
	local name=$1 ip=$2
	shift 2
	docker run -d --name "$PFX-$name" --network "$NET" --ip "$ip" --cap-add NET_ADMIN --device /dev/net/tun \
		-v "$RUN/site:/srv:ro" "$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
	docker exec "$PFX-$name" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
	if [[ $# -gt 0 ]]; then
		docker exec "$PFX-$name" tinc -n lab -c "$Y" set "$@"
	fi
	docker exec -d "$PFX-$name" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
}
node f "$F_IP"
node g "$G_IP" HttpsDecoyRoot /srv
node h "$H_IP" HttpsDecoyUpstream "$UP_IP:80"

docker run --rm -v "$RUN/n:/n" "$TOOLS" sh -c 'cd /n && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
	-nodes -days 1 -subj /CN=web.lab.test -keyout key.pem -out cert.pem 2>/dev/null && chmod 644 key.pem cert.pem'
site() { # <location block>: Debian's nginx.conf plus a site that serves h3 on 443
	cat <<-EOF
		server {
		    listen 443 quic reuseport;
		    listen 443 ssl;
		    ssl_certificate     /n/cert.pem;
		    ssl_certificate_key /n/key.pem;
		    add_header Alt-Svc 'h3=":443"; ma=86400';
		    $1
		}
	EOF
}
site 'location / { root /usr/share/nginx/html; }' > "$RUN/n/stock.conf"
site 'root /srv;' > "$RUN/n/root.conf"
site "location / { proxy_pass http://$UP_IP:80; }" > "$RUN/n/proxy.conf"
nginx() { # <name> <ip> <conf>
	docker run -d --name "$PFX-$1" --network "$NET" --ip "$2" -v "$RUN/n:/n:ro" -v "$RUN/site:/srv:ro" \
		-v "$RUN/n/$3:/etc/nginx/conf.d/default.conf:ro" "$NGINX" >/dev/null
}
nginx n "$N_IP" stock.conf
nginx m "$M_IP" root.conf
nginx p "$P_IP" proxy.conf
sleep 5

for s in f n; do
	docker run -d --name "$PFX-cap$s" --network "container:$PFX-$s" --cap-add NET_ADMIN --cap-add NET_RAW \
		-v "$RUN/cap:/cap" "$TOOLS" tcpdump -U --immediate-mode -i any -s 0 -w "/cap/$s.pcap" 'tcp port 443' >/dev/null
done
sleep 2

# ---- probes, the same script against each ----------------------------------------------------
cat > "$RUN/out/probe.sh" <<'EOF'
#!/usr/bin/env bash
# probe.sh <set> <ip> <outdir>: one file per probe with the raw bytes the server sent
S=$1 H=$2 O=$3
tls() { # <name> <bytes...>: send over TLS, keep the whole answer
	printf '%b' "$2" | timeout 8 openssl s_client -quiet -connect "$H:443" -servername web.lab.test \
		-keylogfile "$O/keys" 2>/dev/null > "$O/$1" || true
}
tls12() { # <name> <bytes...>: the same over TLS 1.2 (its ticket travels in the clear)
	printf '%b' "$2" | timeout 8 openssl s_client -tls1_2 -quiet -connect "$H:443" -servername web.lab.test \
		-keylogfile "$O/keys" 2>/dev/null > "$O/$1" || true
}
tcp() { # <name> <bytes>: send over plain TCP to the TLS port
	timeout 8 bash -c "exec 3<>/dev/tcp/$H/443; printf '%b' '$2' >&3; cat <&3" > "$O/$1" 2>/dev/null || true
}
C='Host: web.lab.test\r\nConnection: close\r\n'
LM='Wed, 05 Feb 2025 11:07:30 GMT'
case $S in
stock)
	tls get        'GET / HTTP/1.1\r\nHost: web.lab.test\r\n\r\n'
	tls get_close  "GET / HTTP/1.1\r\n$C\r\n"
	tls head       "HEAD / HTTP/1.1\r\n$C\r\n"
	tls nope       "GET /nope HTTP/1.1\r\n$C\r\n"
	tls post       "POST / HTTP/1.1\r\n${C}Content-Length: 0\r\n\r\n"
	tls postnope   "POST /nope HTTP/1.1\r\n${C}Content-Length: 0\r\n\r\n"
	tls delete     "DELETE /nope HTTP/1.1\r\n$C\r\n"
	tls garbage    'XYZZY\r\n\r\n'
	tls nohost     'GET / HTTP/1.1\r\n\r\n'
	tls twohosts   'GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\nConnection: close\r\n\r\n'
	tls dotdot     "GET /../index.html HTTP/1.1\r\n$C\r\n"
	tls spellings  "GET //./a/../%69ndex.html?x=1 HTTP/1.1\r\n$C\r\n"
	tls idxslash   "GET /index.html/ HTTP/1.1\r\n$C\r\n"
	tls absolute   "GET https://web.lab.test/ HTTP/1.1\r\n$C\r\n"
	tls http10     'GET / HTTP/1.0\r\n\r\n'
	tls http10ka   'GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n'
	tls http09     'GET /\r\n'
	tls http2      "GET / HTTP/2.0\r\n$C\r\n"
	tls longline   "GET /$(head -c 9000 /dev/zero | tr '\0' a) HTTP/1.1\r\n$C\r\n"
	tls longhdr    "GET / HTTP/1.1\r\n${C}X-A: $(head -c 9000 /dev/zero | tr '\0' a)\r\n\r\n"
	tls twice      "GET /nope HTTP/1.1\r\nHost: web.lab.test\r\n\r\nGET /nope HTTP/1.1\r\n$C\r\n"
	tls gzip       "GET / HTTP/1.1\r\n${C}Accept-Encoding: gzip, deflate, br, zstd\r\n\r\n"
	tls gzip404    "GET /nope HTTP/1.1\r\n${C}Accept-Encoding: gzip\r\n\r\n"
	tls gziphead   "HEAD / HTTP/1.1\r\n${C}Accept-Encoding: gzip\r\n\r\n"
	tls gzip10     'GET / HTTP/1.0\r\nAccept-Encoding: gzip\r\n\r\n'
	tls gzipq0     "GET / HTTP/1.1\r\n${C}Accept-Encoding: gzip;q=0\r\n\r\n"
	tls gzipvia    "GET / HTTP/1.1\r\n${C}Accept-Encoding: gzip\r\nVia: 1.1 proxy\r\n\r\n"
	tls gzipka     "GET / HTTP/1.1\r\nHost: web.lab.test\r\nAccept-Encoding: gzip\r\n\r\nGET /nope HTTP/1.1\r\n${C}Accept-Encoding: gzip\r\n\r\n"
	tls ims        "GET / HTTP/1.1\r\n${C}If-Modified-Since: $LM\r\n\r\n"
	tls ims_other  "GET / HTTP/1.1\r\n${C}If-Modified-Since: Thu, 06 Feb 2025 11:07:30 GMT\r\n\r\n"
	tls ims_gzip   "GET / HTTP/1.1\r\n${C}Accept-Encoding: gzip\r\nIf-Modified-Since: $LM\r\n\r\n"
	tls inm        "GET / HTTP/1.1\r\n${C}If-None-Match: \"x\", W/\"67a34672-267\"\r\n\r\n"
	tls inm_other  "GET / HTTP/1.1\r\n${C}If-None-Match: \"x\"\r\nIf-Modified-Since: $LM\r\n\r\n"
	tls ifmatch    "GET / HTTP/1.1\r\n${C}If-Match: \"x\"\r\n\r\n"
	tls ius        "GET / HTTP/1.1\r\n${C}If-Unmodified-Since: Tue, 04 Feb 2025 11:07:30 GMT\r\n\r\n"
	tls range      "GET / HTTP/1.1\r\n${C}Range: bytes=0-99\r\n\r\n"
	tls suffix     "GET / HTTP/1.1\r\n${C}Range: bytes=-100\r\n\r\n"
	tls multi      "GET / HTTP/1.1\r\n${C}Range: bytes=0-9,20-29\r\n\r\n"
	tls r416       "GET / HTTP/1.1\r\n${C}Range: bytes=1000-2000\r\n\r\n"
	tls rsyntax    "GET / HTTP/1.1\r\n${C}Range: bytes=abc\r\n\r\n"
	tls rhead      "HEAD / HTTP/1.1\r\n${C}Range: bytes=0-99\r\n\r\n"
	tls rgzip      "GET / HTTP/1.1\r\n${C}Accept-Encoding: gzip\r\nRange: bytes=0-99\r\n\r\n"
	tls ifrange    "GET / HTTP/1.1\r\n${C}Range: bytes=0-9\r\nIf-Range: \"67a34672-267\"\r\n\r\n"
	tls ifrange_no "GET / HTTP/1.1\r\n${C}Range: bytes=0-9\r\nIf-Range: \"x\"\r\n\r\n"
	tls r416ka     'GET / HTTP/1.1\r\nHost: web.lab.test\r\nRange: bytes=1000-\r\n\r\n'
	tls12 get12    "GET / HTTP/1.1\r\n$C\r\n"
	tcp plain      'GET / HTTP/1.1\r\nHost: web.lab.test\r\n\r\n'
	tcp tincid     '0 prober 17.7\n'
	tcp highbyte   '\x80\x01\x02\x03 hello\r\n\r\n'
	# 30 connections at once from one address: tinc's MaxConnectionBurst (10/s)
	# used to tarpit the rest -- sockets that never answer.
	for i in $(seq 30); do tcp "burst.$i" 'GET / HTTP/1.1\r\nHost: web.lab.test\r\n\r\n' & done
	wait
	;;
root)
	tls dir        "GET /dir HTTP/1.1\r\n$C\r\n"
	tls dirquery   "GET /dir?a=1 HTTP/1.1\r\n$C\r\n"
	tls dirhead    "HEAD /dir HTTP/1.1\r\n$C\r\n"
	tls dir10      'GET /dir HTTP/1.0\r\n\r\n'
	tls dirslash   "GET /dir/ HTTP/1.1\r\n$C\r\n"
	tls empty      "GET /emptydir/ HTTP/1.1\r\n$C\r\n"
	tls nodir      "GET /nodir/ HTTP/1.1\r\n$C\r\n"
	tls css        "GET /a.css HTTP/1.1\r\n${C}Accept-Encoding: gzip\r\n\r\n"
	tls page       "GET /page.html HTTP/1.1\r\n${C}Accept-Encoding: gzip\r\n\r\n"
	tls rootidx    "GET / HTTP/1.1\r\n$C\r\n"
	;;
proxy)
	tls get        "GET / HTTP/1.1\r\n${C}User-Agent: probe/1\r\nAccept: */*\r\nCookie: c=d\r\n\r\n"
	tls gzip       "GET / HTTP/1.1\r\n${C}Accept-Encoding: gzip\r\n\r\n"
	tls twice      "GET / HTTP/1.1\r\nHost: web.lab.test\r\n\r\nGET /missing HTTP/1.1\r\n$C\r\n"
	tls nolen      "GET /nolen HTTP/1.1\r\n$C\r\n"
	tls nolen_ka   "GET /nolen HTTP/1.1\r\nHost: web.lab.test\r\n\r\nGET /missing HTTP/1.1\r\n$C\r\n"
	tls chunked    "GET /chunked HTTP/1.1\r\n$C\r\n"
	tls missing    "GET /missing HTTP/1.1\r\n$C\r\n"
	tls moved      "GET /moved HTTP/1.1\r\n$C\r\n"
	tls post       "POST /p HTTP/1.1\r\n${C}Content-Length: 3\r\n\r\nabc"
	tls head       "HEAD / HTTP/1.1\r\n$C\r\n"
	tls http10     'GET / HTTP/1.0\r\n\r\n'
	tls nolen10    'GET /nolen HTTP/1.0\r\n\r\n'
	tls garbage    'XYZZY\r\n\r\n'
	;;
esac
EOF
chmod +x "$RUN/out/probe.sh"
probe() { # <set> <ours> <ip> <nginx> <ip>
	mkdir -p "$RUN/out/$2" "$RUN/out/$4"
	chmod 777 "$RUN/out/$2" "$RUN/out/$4"
	docker run --rm --network "$NET" -v "$RUN/out:/o" "$TOOLS" /o/probe.sh "$1" "$3" "/o/$2"
	# the upstream's log tells which proxy forwarded what
	[[ $1 == proxy ]] && cp "$RUN/out/upstream-requests.txt" "$RUN/out/upstream-$2.txt" 2>/dev/null && : > "$RUN/out/upstream-requests.txt"
	docker run --rm --network "$NET" -v "$RUN/out:/o" "$TOOLS" /o/probe.sh "$1" "$5" "/o/$4"
	[[ $1 == proxy ]] && cp "$RUN/out/upstream-requests.txt" "$RUN/out/upstream-$4.txt" 2>/dev/null
	return 0
}
probe stock f "$F_IP" n "$N_IP"
probe root g "$G_IP" m "$M_IP"
probe proxy h "$H_IP" p "$P_IP"

# An answer with what legitimately differs between two servers masked: the
# Date value, a multipart boundary (nginx's counter) and the server's own
# address in a redirect to a request without Host (HTTP/1.0).
norm() {
	sed -E -e 's/^Date: .*/Date: -/; s/boundary=[0-9]+/boundary=N/; s/^--[0-9]+(--)?\r$/--N\1\r/' \
		-e "s#^Location: https://${SUBNET//./\\.}\\.[0-9]+/#Location: https://SERVER/#" "$1"
}
same() { # <label> <ours> <nginx>
	if [[ -s $3 ]] && cmp -s <(norm "$2") <(norm "$3"); then
		ok "$1: $(head -1 "$3" | tr -d '\r' | cut -c1-60), byte for byte"
	else
		bad "$1: ours '$(head -1 "$2" | tr -d '\r' | cut -c1-60)' vs nginx '$(head -1 "$3" | tr -d '\r' | cut -c1-60)'"
		diff <(norm "$2" | cat -A | cut -c1-150) <(norm "$3" | cat -A | cut -c1-150) | head -8 >&2 || true
	fi
}
for f in "$RUN"/out/n/*; do
	p=$(basename "$f")
	case $p in keys|burst.*|highbyte) continue ;; esac
	same "$p" "$RUN/out/f/$p" "$f"
done
for f in "$RUN"/out/m/*; do
	p=$(basename "$f"); [[ $p == keys ]] && continue
	same "root: $p" "$RUN/out/g/$p" "$f"
done
for f in "$RUN"/out/p/*; do
	p=$(basename "$f"); [[ $p == keys ]] && continue
	same "proxy: $p" "$RUN/out/h/$p" "$f"
done

# What the upstream received: the same request heads (Cookie aside -- the
# decoy never forwards it, review M5-10).
fwd() { grep -v -i '^cookie:' "$1" | tr -d '\r'; }
if [[ -s $RUN/out/upstream-p.txt ]] && cmp -s <(fwd "$RUN/out/upstream-h.txt") <(fwd "$RUN/out/upstream-p.txt"); then
	ok "proxy: the upstream received the same requests from both ($(grep -c '^=====' "$RUN/out/upstream-p.txt"))"
else
	bad "proxy: the upstream received different requests"
	diff <(fwd "$RUN/out/upstream-h.txt") <(fwd "$RUN/out/upstream-p.txt") | head -10 >&2 || true
fi

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

# ---- timing: a silent client, an idle kept-alive connection ---------------------------------------
if [[ -z ${QUICK:-} ]]; then
	for s in f n; do
		ip=$F_IP; [[ $s == n ]] && ip=$N_IP
		docker run --rm --network "$NET" "$TOOLS" bash -c \
			"s=\$(date +%s); exec 3<>/dev/tcp/$ip/443; timeout 100 cat <&3 >/dev/null; echo \$((\$(date +%s)-s))" > "$RUN/out/silent-$s" &
		# one kept-alive request, then silence: seconds from the answer to the server's close
		docker run --rm --network "$NET" "$TOOLS" bash -c \
			"(printf 'GET /nope HTTP/1.1\r\nHost: web.lab.test\r\n\r\n'; sleep 110) |
			 timeout 105 openssl s_client -quiet -connect $ip:443 -servername web.lab.test 2>/dev/null |
			 { head -1 >/dev/null; s=\$(date +%s); cat >/dev/null; echo \$((\$(date +%s)-s)); }" > "$RUN/out/idle-$s" &
	done
	wait
	fsil=$(cat "$RUN/out/silent-f"); nsil=$(cat "$RUN/out/silent-n")
	if ((fsil >= 55 && fsil <= 70 && nsil >= 55 && nsil <= 70)); then
		ok "a silent client is closed after ${fsil} s (nginx: ${nsil} s)"
	else
		bad "a silent client is closed after ${fsil} s (nginx: ${nsil} s)"
	fi
	fidle=$(cat "$RUN/out/idle-f"); nidle=$(cat "$RUN/out/idle-n")
	if ((fidle >= 72 && fidle <= 80 && nidle >= 72 && nidle <= 80)); then
		ok "an idle kept-alive connection is closed after ${fidle} s (nginx: ${nidle} s)"
	else
		bad "an idle kept-alive connection is closed after ${fidle} s (nginx: ${nidle} s)"
	fi
fi

# ---- from the captures: close_notify before FIN, session tickets --------------------------------
# SIGTERM, not rm -f: tcpdump says what it captured and dropped.
docker stop -t 5 "$PFX-capf" "$PFX-capn" >/dev/null
for s in f n; do
	ip=$F_IP; [[ $s == n ]] && ip=$N_IP
	docker run --rm -v "$RUN/cap:/cap" -v "$RUN/out:/o" "$TOOLS" tshark -r "/cap/$s.pcap" -o "tls.keylog_file:/o/$s/keys" \
		-Y "ip.src == $ip && (tls.alert_message.desc == 0 || tcp.flags.fin == 1)" -T fields -e tcp.stream -e tls.alert_message.desc -e tcp.flags.fin \
		2>/dev/null > "$RUN/out/close-$s" || true
	docker run --rm -v "$RUN/cap:/cap" -v "$RUN/out:/o" "$TOOLS" tshark -r "/cap/$s.pcap" -o "tls.keylog_file:/o/$s/keys" \
		-Y "ip.src == $ip && tls.handshake.type == 4" -T fields -e tls.handshake.length \
		-e tls.handshake.session_ticket_lifetime_hint 2>/dev/null |
		awk -F'\t' '{n = split($1, l, ","); split($2, t, ","); for (i = 1; i <= n; i++) print l[i], t[i]}' |
		sort | uniq -c | sort -rn > "$RUN/out/tickets-$s" || true
done
# Streams where the server sent close_notify before (or with) its FIN, versus streams with a FIN at all.
cn() { awk '$2=="0" && !($1 in fin) {cn[$1]=1} $NF=="True" && !($1 in fin) {fin[$1]=1; if ($1 in cn) n++} END {print n+0 "/" length(fin)}' "$1"; }
fcn=$(cn "$RUN/out/close-f"); ncn=$(cn "$RUN/out/close-n")
if [[ ${fcn%/*} -ge 5 && ${ncn%/*} -ge 5 ]]; then
	ok "close_notify before the FIN (ours $fcn TLS closes, nginx $ncn)"
else
	bad "close_notify before the FIN (ours $fcn TLS closes, nginx $ncn)"
fi
# NewSessionTicket message lengths, the most common first (the lifetime,
# nonce and ticket inside are the server's; the length shows what the
# ticket carries).
ft=$(awk '{printf "%s%s B/%ss", (NR > 1 ? ", " : ""), $2, $3}' "$RUN/out/tickets-f")
nt=$(awk '{printf "%s%s B/%ss", (NR > 1 ? ", " : ""), $2, $3}' "$RUN/out/tickets-n")
if [[ -n $nt ]] && cmp -s <(awk '{print $2, $3}' "$RUN/out/tickets-f") <(awk '{print $2, $3}' "$RUN/out/tickets-n"); then
	ok "session tickets (TLS 1.3 and 1.2; length/lifetime): $ft, as nginx's"
else
	bad "session tickets (length/lifetime): ours ${ft:-none}, nginx ${nt:-none}"
fi

if [[ $FAILED -eq 0 ]]; then
	log "decoy conformance: all checks passed"
else
	log "decoy conformance: FAILURES above"
fi
exit "$FAILED"

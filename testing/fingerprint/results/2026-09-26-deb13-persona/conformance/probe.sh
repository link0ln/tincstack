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

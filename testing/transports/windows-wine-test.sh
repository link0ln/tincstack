#!/usr/bin/env bash
# The Windows core speaks the TLS carriers, with the Linux build's wire image.
#
# Until 2026-09-23 tincd.exe was a libgcrypt build without `https' or `quic'.
# Now it links OpenSSL 3.5 and ngtcp2 statically (core/Dockerfile.build-win).
# This lab runs the real tincd.exe / tinc.exe under Wine, in Docker, against
# the Linux core -- no Windows machine, and nothing on the host:
#
#   Windows as the server (founder), a Linux leaf dialling it:
#     * the leaf connects over `https' and over `quic';
#     * curl gets the decoy page over TLS and over HTTP/3, and a plain HTTP
#       request on 443 gets nginx's 400 -- the Windows front answers like the
#       Linux one;
#     * its ServerHellos carry the Linux build's JA3S;
#     * another process cannot bind its ports with SO_REUSEADDR (Wine models
#       that for UDP only, see below).
#   Windows as the dialler, a Linux founder:
#     * it connects over `https' and over `quic';
#     * its ClientHellos are the Linux dialler's, extension for extension
#       (JA4_r) and byte count, dialling the same founder the same way --
#       and the Linux dialler's are curl's (testing/fingerprint);
#     * a dial that hangs (the founder drops TCP 443) does not stall the
#       daemon: its own front still answers (the dial socket used to stay
#       blocking on Windows, where mingw has no O_NONBLOCK).
#
# Not covered here (Wine has no Wintun): the tunnel device. The Windows node
# runs with `DeviceType = dummy', so what is proven is the carrier, the TLS
# stack and SPTPS over it (the link activates), not packets through Wintun.
#
# Usage: [CORE_IMAGE=...] [WIN_CORE_IMAGE=...] [WINE_IMAGE=...] testing/transports/windows-wine-test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
WINCORE="${WIN_CORE_IMAGE:-tincstack/core-win:${TINCSTACK_TAG:-dev}}"
WINE="${WINE_IMAGE:-tincstack/win-exe:dev}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
RUN="$HERE/run-wine"
PFX=wwt
NET=${PFX}net
SUBNET=10.47.13
L_IP=$SUBNET.10        # Linux leaf (part 1)
W_IP=$SUBNET.11        # Windows founder (part 1)
F_IP=$SUBNET.12        # Linux founder (part 2)
D_IP=$SUBNET.13        # Windows dialler (part 2)
C_IP=$SUBNET.14        # Linux dialler, the control (part 2)
YAML=/c/tinc.yaml
WYAML='Z:\c\tinc.yaml'
FAILED=0

# The Linux build's ServerHello to curl (testing/fingerprint/results/2026-09-23-deb13)
JA3S_CURL=15af977ce25de452b96affa2addb1036

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

cleanup() {
	docker rm -f "$PFX-w" "$PFX-l" "$PFX-f" "$PFX-d" "$PFX-c" "$PFX-capw" "$PFX-capf" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	docker run --rm -v "$RUN:/r" "$IMG" sh -c 'rm -rf /r/*' >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
[[ -n ${KEEP:-} ]] || trap cleanup EXIT
cleanup
mkdir -p "$RUN/bin" "$RUN/w" "$RUN/l" "$RUN/f" "$RUN/d" "$RUN/c" "$RUN/cap"
chmod 777 "$RUN/cap"
docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null

if ! docker image inspect "$TOOLS" >/dev/null 2>&1; then
	docker build -q --build-arg http_proxy="${HTTP_PROXY:-}" --build-arg https_proxy="${HTTP_PROXY:-}" \
		-t "$TOOLS" "$ROOT/testing/fingerprint" >/dev/null
fi
docker run --rm -v "$RUN/bin:/out" "$WINCORE" >/dev/null

# ---- helpers ----------------------------------------------------------------------------------
linux() { # <name> <ip>
	docker run -d --name "$PFX-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN --device /dev/net/tun \
		-v "$RUN/$1:/c" "$IMG" sleep infinity >/dev/null
}
windows() { # <name> <ip>: a Wine container with the Windows binaries under /b
	docker run -d --name "$PFX-$1" --network "$NET" --ip "$2" --entrypoint sleep -e WINEDEBUG=-all \
		-v "$RUN/bin:/b:ro" -v "$RUN/$1:/c" "$WINE" infinity >/dev/null
}
lt() { local n=$1; shift; docker exec "$PFX-$n" tinc -n lab -c "$YAML" "$@"; }
wt() { local n=$1; shift; docker exec "$PFX-$n" wine /b/tinc.exe -n lab -c "$WYAML" "$@" 2>/dev/null | tr -d '\r'; }
lstart() { docker exec -d "$PFX-$1" sh -c "tincd -n lab -c $YAML -D -d3 >>/c/tincd.log 2>&1"; }
wstart() { docker exec -d "$PFX-$1" sh -c "wine /b/tincd.exe -n lab -c '$WYAML' -D -d3 >>/c/tincd.log 2>&1"; }
lstop() { lt "$1" stop >/dev/null 2>&1 || true; sleep 1; }
wstop() { docker exec "$PFX-$1" wineserver -k >/dev/null 2>&1 || true; sleep 1; }
until_up() { # <log file>
	for _ in $(seq 40); do grep -q "Ready" "$1" 2>/dev/null && return 0; sleep 1; done
	log "never came up: $1"; tail -20 "$1" >&2; exit 1
}
capture() { # <name> <target container>
	docker run -d --name "$PFX-$1" --network "container:$PFX-$2" --cap-add NET_ADMIN --cap-add NET_RAW \
		-v "$RUN/cap:/cap" "$TOOLS" tcpdump -U --immediate-mode -i any -s 0 -w "/cap/$1.pcap" 'port 443' >/dev/null
	sleep 2
}
connected() { # <linux node> <peer> <transport>
	for _ in $(seq 40); do
		lt "$1" dump connections 2>/dev/null | grep -q "^$2 .*transport $3" && return 0
		sleep 1
	done
	return 1
}
tools() { docker run --rm --network "$NET" -v "$RUN/cap:/cap" "$TOOLS" bash -c "$1" 2>&1; }

# ==== part 1: Windows is the server ============================================================
windows w "$W_IP"
docker exec "$PFX-w" sh -c "touch $YAML"
wt w set Name wfounder >/dev/null
wt w set Port 655 >/dev/null
wt w set DeviceType dummy >/dev/null
wstart w
until_up "$RUN/w/tincd.log"
if grep -q "QUIC carrier ready (ngtcp2 .*OpenSSL 3.5" "$RUN/w/tincd.log" && grep -q "https: listening on 0.0.0.0 port 443" "$RUN/w/tincd.log"; then
	ok "tincd.exe listens with https and quic on 443 ($(grep -o 'OpenSSL 3\.5\.[0-9]*' "$RUN/w/tincd.log" | head -1), static)"
else
	bad "tincd.exe listens with https and quic on 443"
	grep -iE "quic|https|tls" "$RUN/w/tincd.log" | head -5 >&2
fi

# Nobody else may bind the ports it listens on. Windows lets a later socket
# with SO_REUSEADDR bind a port another process holds unless the holder set
# SO_EXCLUSIVEADDRUSE; tincd.exe used to set SO_REUSEADDR itself (upstream
# tinc). Wine models this for UDP -- a SO_REUSEADDR holder's port is taken --
# but refuses the second TCP listener as Linux does, so here the tinc UDP port
# is the case that tells builds apart; TCP needs real Windows.
cp "$HERE/win-bind-probe.py" "$RUN/w/"
bindprobe() { docker exec "$PFX-w" wine 'C:\Python312\python.exe' 'Z:\c\win-bind-probe.py' "$1" "$2" 2>/dev/null | tr -d '\r' | tail -1; }
if [[ $(bindprobe udp 6553) == TAKEN ]]; then
	for pp in udp:655 tcp:655 udp:443 tcp:443; do
		r=$(bindprobe "${pp%%:*}" "${pp#*:}")
		if [[ $r == REFUSED* ]]; then
			ok "a second Windows process cannot bind tincd.exe's ${pp%%:*} ${pp#*:} with SO_REUSEADDR ($r)"
		else
			bad "a second Windows process cannot bind tincd.exe's ${pp%%:*} ${pp#*:} with SO_REUSEADDR (got '$r')"
		fi
	done
else
	bad "the bind probe runs and can bind a free port (got '$(bindprobe udp 6553)')"
fi

wt w set wfounder.Address "$W_IP" >/dev/null
inv=$(wt w invite leaf | grep -m1 "^$W_IP")
linux l "$L_IP"
lt l join "$inv" >/dev/null 2>&1
capture capw w

for tr in https quic; do
	lt l set PreferredTransports "$tr"
	lstart l
	if connected l wfounder "$tr"; then
		ok "a Linux leaf connects to the Windows node over $tr"
	else
		bad "a Linux leaf connects to the Windows node over $tr"
		grep -iE "$tr|carrier" "$RUN/l/tincd.log" | tail -5 >&2
	fi
	lstop l
done

tools "curl -sk -m 8 -i https://$W_IP/" > "$RUN/curl-tls.txt" || true
tools "curl -sk -m 8 -i --http3-only https://$W_IP/" > "$RUN/curl-h3.txt" || true
tools "exec 3<>/dev/tcp/$W_IP/443; printf 'GET / HTTP/1.1\r\nHost: x\r\n\r\n' >&3; timeout 5 cat <&3 | head -1" > "$RUN/plain.txt" || true
if head -1 "$RUN/curl-tls.txt" | grep -q "^HTTP/1.1 200" && grep -q "Welcome to nginx" "$RUN/curl-tls.txt"; then
	ok "curl gets the decoy page from the Windows node over TLS"
else
	bad "curl gets the decoy page from the Windows node over TLS: $(head -1 "$RUN/curl-tls.txt")"
fi
if head -1 "$RUN/curl-h3.txt" | grep -q "^HTTP/3 200" && grep -q "Welcome to nginx" "$RUN/curl-h3.txt"; then
	ok "curl --http3-only gets the decoy page from the Windows node"
else
	bad "curl --http3-only gets the decoy page from the Windows node: $(head -1 "$RUN/curl-h3.txt")"
fi
if tr -d '\r' < "$RUN/plain.txt" | grep -q "^HTTP/1.1 400 Bad Request"; then
	ok "plain HTTP on the Windows node's 443 gets nginx's 400"
else
	bad "plain HTTP on the Windows node's 443 gets nginx's 400: '$(cat "$RUN/plain.txt")'"
fi
docker stop -t 3 "$PFX-capw" >/dev/null
jas=$(docker run --rm -v "$RUN/cap:/cap" "$TOOLS" tshark -r /cap/capw.pcap -Y "tls.handshake.type == 2 && ip.src == $W_IP" \
	-T fields -e tls.handshake.ja3s 2>/dev/null | sort -u | tr '\n' ' ')
if [[ $jas == "$JA3S_CURL " ]]; then
	ok "every ServerHello from the Windows node has the Linux build's JA3S ($JA3S_CURL, TLS and QUIC)"
else
	bad "ServerHello JA3S from the Windows node: $jas"
fi
wstop w

# ==== part 2: Windows is the dialler ===========================================================
linux f "$F_IP"
docker exec "$PFX-f" sh -c "install -m600 /dev/null $YAML && tinc -n lab -c $YAML set Name founder && tinc -n lab -c $YAML set Port 655"
lstart f
until_up "$RUN/f/tincd.log"
lt f set founder.Address "$F_IP"
inv=$(lt f invite wleaf)
windows d "$D_IP"
docker exec "$PFX-d" sh -c "touch $YAML"
wt d join "$inv" >/dev/null || true
wt d set DeviceType dummy >/dev/null
inv=$(lt f invite lleaf)
linux c "$C_IP"
lt c join "$inv" >/dev/null 2>&1
capture capf f

for tr in https quic; do
	wt d set PreferredTransports "$tr" >/dev/null
	wstart d
	if connected f wleaf "$tr"; then
		ok "the Windows node connects to a Linux founder over $tr"
	else
		bad "the Windows node connects to a Linux founder over $tr"
		grep -iE "$tr|carrier|error" "$RUN/d/tincd.log" | tail -6 >&2
	fi
	wstop d
	lt c set PreferredTransports "$tr"
	lstart c
	connected f lleaf "$tr" || bad "control: the Linux leaf connects over $tr"
	lstop c
done
# curl dialling the same founder by IP: the reference both must equal.
tools "curl -sk -m 8 -o /dev/null https://$F_IP/; curl -sk -m 8 -o /dev/null --http3-only https://$F_IP/" >/dev/null || true
docker stop -t 3 "$PFX-capf" >/dev/null

hellos() { # <src ip> <ja4 prefix>
	docker run --rm -v "$RUN/cap:/cap" "$TOOLS" tshark -r /cap/capf.pcap -Y "tls.handshake.type == 1 && ip.src == $1" \
		-T fields -e tls.handshake.ja4_r -e frame.len -e tls.quic.parameter.type 2>/dev/null | grep "^$2" | sort -u
}
curl_hellos() { # <ja4 prefix>: ClientHellos from neither node -- curl's
	docker run --rm -v "$RUN/cap:/cap" "$TOOLS" tshark -r /cap/capf.pcap \
		-Y "tls.handshake.type == 1 && ip.src != $D_IP && ip.src != $C_IP && ip.src != $F_IP" \
		-T fields -e tls.handshake.ja4_r -e frame.len -e tls.quic.parameter.type 2>/dev/null | grep "^$1" | sort -u
}
for p in t13:https q13:quic; do
	w=$(hellos "$D_IP" "${p%%:*}"); l=$(hellos "$C_IP" "${p%%:*}"); k=$(curl_hellos "${p%%:*}")
	printf 'windows %s\n%s\nlinux %s\n%s\ncurl %s\n%s\n' "${p#*:}" "$w" "${p#*:}" "$l" "${p#*:}" "$k" >> "$RUN/clienthellos.txt"
	if [[ -n $k && $(cut -f1 <<<"$k") == "$(cut -f1 <<<"$l")" && $(cut -f3 <<<"$k") == "$(cut -f3 <<<"$l")" ]]; then
		ok "dialling an IP, the Linux ${p#*:} ClientHello has curl's extensions ($(cut -c1-10 <<<"$k"); curl $(cut -f2 <<<"$k") bytes, ours $(cut -f2 <<<"$l"))$(tp=$(cut -f3 <<<"$k"); [[ -z $tp ]] || echo " and transport parameters $tp")"
	else
		bad "dialling an IP, the Linux ${p#*:} ClientHello has curl's extensions"
		diff <(tr ',_\t' '\n' <<<"$l") <(tr ',_\t' '\n' <<<"$k") | head -8 >&2 || true
	fi
	if [[ -n $w && $w == "$l" ]]; then
		ok "the Windows ${p#*:} ClientHello is the Linux one: $(cut -c1-10 <<<"$w"), $(cut -f2 <<<"$w") bytes, same extensions$(tp=$(cut -f3 <<<"$w"); [[ -z $tp ]] || echo ", transport parameters $tp")"
	else
		bad "the Windows ${p#*:} ClientHello differs from the Linux one"
		diff <(tr ',_\t' '\n' <<<"$w") <(tr ',_\t' '\n' <<<"$l") | head -8 >&2 || true
	fi
done

# The datagram with the client's Finished (Initial padded to fill it, Handshake, 1-RTT ACK, the
# connection ID the server issued) is the Linux dialler's, which quic-wire-test.sh holds to curl's.
python3 -B "$HERE/quic_initial.py" "$RUN/cap/capf.pcap" > "$RUN/datagrams.txt" 2>/dev/null
second() { # <client ip>: udp length, packets, Lengths, Initial frames, DCID moved or kept
	awk -F'\t' -v ip="$1" '$1 != ip { next }
		$3 ~ /^IH/ { printf "%s\t%s\t%s\t%s\t%s\n", $2, $3, $4, $5, ($6 != prev[$7] ? "moved" : "kept"); exit }
		{ prev[$7] = $6 }' "$RUN/datagrams.txt"
}
s_plat=$(second "$D_IP"); s_lin=$(second "$C_IP")
if [[ -n $s_lin && $s_plat == "$s_lin" ]]; then
	ok "the Windows quic second flight is the Linux one: $(awk -F'\t' '{printf "%s B of %s, Lengths %s, Initial %s, dcid %s", $1, $2, $3, $4, $5}' <<<"$s_plat")"
else
	bad "the Windows quic second flight differs from the Linux one: windows '$s_plat', linux '$s_lin'"
fi

# ---- a hanging dial must not stall the daemon ----------------------------------------------------
docker exec "$PFX-f" iptables -A INPUT -p tcp --dport 443 -j DROP
wt d set PreferredTransports https >/dev/null
: > "$RUN/d/tincd.log"
wstart d
until_up "$RUN/d/tincd.log"
for _ in $(seq 15); do grep -q "Dialling founder .* via https" "$RUN/d/tincd.log" && break; sleep 1; done
sleep 2
# A joined node listens on a random port; its front there takes TLS too.
dport=$(grep -m1 -o "Listening on 0.0.0.0 port [0-9]*" "$RUN/d/tincd.log" | grep -o "[0-9]*$")
t0=$(date +%s%N)
tools "curl -sSk -m 10 -o /dev/null -w '%{http_code}' https://$D_IP:$dport/" > "$RUN/stall.txt" || true
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
if [[ $(cat "$RUN/stall.txt") == 200 ]] && ((ms < 5000)); then
	ok "while its https dial hangs, the Windows node's own front answers (${ms} ms)"
else
	bad "while its https dial hangs, the Windows node's own front answers (got '$(cat "$RUN/stall.txt")' after ${ms} ms)"
fi
wstop d

if [[ $FAILED -eq 0 ]]; then
	log "windows (wine): all checks passed"
else
	log "windows (wine): FAILURES above"
fi
exit "$FAILED"

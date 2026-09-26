#!/usr/bin/env bash
# The quic dialler's handshake flights are curl's.
#
# curl 8.14 on Debian 13 speaks QUIC through OpenSSL 3.5's own stack; our
# dialler runs ngtcp2. Its Initial -- which anyone can decrypt, its keys come
# from the destination connection id on the wire -- used to give that away:
# ngtcp2's transport parameters (another set and order, version_information,
# max_datagram_frame_size), 1-byte packet numbers, 4-byte Length fields, and
# the ClientHello cut into a dozen shuffled CRYPTO frames between PINGs and
# PADDING. core/ngtcp2/tincstack-wire.patch makes ngtcp2 write it as OpenSSL
# does. Here a founder, a leaf dialling it over quic and curl --http3-only
# dialling the same founder by IP are captured side by side:
#
#   * the leaf's transport parameters are curl's: set, order and values;
#   * its ClientHello is curl's: JA4_r and length;
#   * its two Initial packets are curl's: sizes, packet-number length, Length
#     field, frames, CRYPTO offsets and lengths, PADDING;
#   * the datagram with its Finished is curl's: OpenSSL pads the Initial in
#     front of the Handshake packet, not the 1-RTT packet after it, and has
#     moved to the connection ID the server issued -- Length fields and
#     Destination Connection ID are in the clear;
#   * the link is on quic and the tunnel carries 1400-byte pings both ways
#     (the dialler takes and sends 1200-byte packets at most, as curl does, so
#     tinc's path MTU on quic is smaller: printed).
#
# Usage: [CORE_IMAGE=...] [KEEP=1] testing/transports/quic-wire-test.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
PFX=qwt
NET=${PFX}net
SUBNET=10.47.18
F_IP=$SUBNET.10
L_IP=$SUBNET.11
Y=/c/tinc.yaml
RUN="$HERE/run-quic-wire"
FAILED=0

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

cleanup() {
	docker rm -f "$PFX-f" "$PFX-l" "$PFX-cap" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup
[[ -n ${KEEP:-} ]] || trap cleanup EXIT
docker run --rm -v "$HERE:/h" "$TOOLS" sh -c 'rm -rf /h/run-quic-wire' >/dev/null 2>&1 || true
mkdir -p "$RUN"

t() { local n=$1; shift; docker exec "$PFX-$n" tinc -n lab -c "$Y" "$@"; }
node() { # <name> <ip>
	docker run -d --name "$PFX-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN --device /dev/net/tun \
		"$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
}
tshark() { docker run --rm -v "$RUN:/r" "$TOOLS" tshark -r /r/c.pcap "$@" 2>/dev/null; }

docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null
node f "$F_IP"
node l "$L_IP"
docker exec "$PFX-f" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
docker exec -d "$PFX-f" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
for _ in $(seq 20); do t f pid >/dev/null 2>&1 && break; sleep 1; done
t f set founder.Address "$F_IP"
inv=$(t f invite leaf)
t l join "$inv" >/dev/null 2>&1
t l set PreferredTransports quic
docker run -d --name "$PFX-cap" --network "container:$PFX-f" -v "$RUN:/r" "$TOOLS" \
	tcpdump -i eth0 -U -w /r/c.pcap udp port 443 >/dev/null
sleep 2

docker exec -d "$PFX-l" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
for _ in $(seq 30); do t l dump connections 2>/dev/null | grep -q "^founder .*transport " && break; sleep 1; done
if t l dump connections 2>/dev/null | grep -q "^founder .*transport quic"; then
	ok "the leaf is on quic"
else
	bad "the leaf is on quic: $(t l dump connections 2>/dev/null | grep '^founder')"
fi
docker run --rm --network "$NET" "$TOOLS" curl -sk -m 8 -o /dev/null --http3-only "https://$F_IP/" || true
sleep 1
docker stop -t 2 "$PFX-cap" >/dev/null
# curl ran in a throwaway container: the reference is every client that is neither node.

# ---- transport parameters, ClientHello -------------------------------------------------------------
params() { # <display filter>: the transport parameters with their values, one per line
	tshark -Y "tls.handshake.type == 1 && $1" -V | grep -E '^ +Parameter: ' | sed 's/^ *//'
}
ours=$(params "ip.src == $L_IP")
curls=$(params "ip.src != $L_IP && ip.src != $F_IP")
printf 'leaf\n%s\ncurl\n%s\n' "$ours" "$curls" > "$RUN/transport-parameters.txt"
if [[ -n $ours && $ours == "$curls" ]]; then
	ok "transport parameters are curl's: $(grep -o '^Parameter: [a-z_]*' <<<"$ours" | cut -d' ' -f2 | paste -sd,)"
else
	bad "transport parameters differ from curl's"
	diff <(echo "$ours") <(echo "$curls") >&2 || true
fi

hello() { tshark -Y "tls.handshake.type == 1 && quic && $1" -T fields -e tls.handshake.ja4_r -e tls.handshake.length | sort -u; }
h_ours=$(hello "ip.src == $L_IP")
h_curl=$(hello "ip.src != $L_IP && ip.src != $F_IP")
if [[ -n $h_ours && $h_ours == "$h_curl" ]]; then
	ok "the ClientHello is curl's: $(cut -c1-40 <<<"$h_ours")..., $(cut -f2 <<<"$h_ours") bytes"
else
	bad "the ClientHello differs: ours '$h_ours', curl '$h_curl'"
fi

# ---- the first flight: two Initial packets ----------------------------------------------------------
LAYOUT=(-e udp.length -e quic.packet_number_length -e quic.length -e quic.frame_type
	-e quic.crypto.offset -e quic.crypto.length -e quic.padding_length)
flight() { tshark -Y "quic.long.packet_type == 0 && $1" -T fields "${LAYOUT[@]}" | head -2; }
f_ours=$(flight "ip.src == $L_IP")
f_curl=$(flight "ip.src != $L_IP && ip.src != $F_IP")
printf 'leaf\n%s\ncurl\n%s\n' "$f_ours" "$f_curl" > "$RUN/first-flight.txt"
if [[ -n $f_ours && $f_ours == "$f_curl" ]]; then
	ok "the first flight is curl's: $(awk -F'\t' '{printf "%s%s B (Length %s, CRYPTO %s+%s, PADDING %s)", (NR > 1 ? "; " : ""), $1, $3, $5, $6, ($7 == "" ? 0 : $7)}' <<<"$f_ours")"
else
	bad "the first flight differs (udp length, pn length, Length, frames, crypto offset, crypto length, padding)"
	diff <(echo "$f_ours") <(echo "$f_curl") >&2 || true
fi

# ---- the second flight: Initial + Handshake (+ 1-RTT) in one datagram ------------------------------
# The client's first datagram carrying both an Initial and a Handshake packet. In the clear: its
# UDP length, its packets, their Length fields and Destination Connection ID; readable by anyone:
# the Initial's frames. OpenSSL pads the Initial so that the datagram is full (stock ngtcp2 pads
# the 1-RTT packet after it: Initial Length 25 instead of 1051) and has already moved to the
# connection ID the server issued in its first 1-RTT packet (stock ngtcp2 keeps the original).
# tshark loses a connection across that move without the TLS secrets; quic_initial.py keys the
# Initials by the client's first DCID, as an observer does.
python3 -B "$HERE/quic_initial.py" "$RUN/c.pcap" > "$RUN/datagrams.txt"
second() { # <client ip>: udp length, packets, Lengths, Initial frames, DCID moved or kept
	awk -F'\t' -v ip="$1" '$1 != ip { next }
		$3 ~ /^IH/ { printf "%s\t%s\t%s\t%s\t%s\n", $2, $3, $4, $5, ($6 != prev[$7] ? "moved" : "kept"); exit }
		{ prev[$7] = $6 }' "$RUN/datagrams.txt"
}
s_ours=$(second "$L_IP")
s_curl=$(second "$(awk -F'\t' -v l="$L_IP" '$1 != l { print $1; exit }' "$RUN/datagrams.txt")")
printf 'leaf\n%s\ncurl\n%s\n' "$s_ours" "$s_curl" > "$RUN/second-flight.txt"
if [[ -n $s_ours && $s_ours == "$s_curl" ]]; then
	ok "the second flight is curl's: $(awk -F'\t' '{printf "%s B of %s, Lengths %s, Initial %s, destination connection id %s", $1, $2, $3, $4, $5}' <<<"$s_ours")"
else
	bad "the second flight differs (udp length, packets, Lengths, Initial frames, dcid): ours '$s_ours', curl '$s_curl'"
fi

# The client's first short-header-only datagrams (its HTTP/3 streams, the request): printed, not
# compared -- our request carries the authenticator (docs/transports.md §9.4), curl's GET does not.
onertt() { awk -F'\t' -v ip="$1" '$1 == ip && $3 == "S" { printf "%s%s", (n++ ? "/" : ""), $2; if (n == 4) exit }' "$RUN/datagrams.txt"; }
log "  the client's first 1-RTT datagrams (udp length): leaf $(onertt "$L_IP"), curl $(onertt "$(awk -F'\t' -v l="$L_IP" '$1 != l { print $1; exit }' "$RUN/datagrams.txt")")"

# ---- the tunnel ----------------------------------------------------------------------------------
lab_ip() { docker exec "$PFX-$1" ip -4 -br addr show lab | awk '{print $3}' | cut -d/ -f1; }
fv=$(lab_ip f)
lv=$(lab_ip l)
for _ in $(seq 20); do docker exec "$PFX-l" ping -c1 -W1 "$fv" >/dev/null 2>&1 && break; done
pings=0
for s in 56 1400; do
	docker exec "$PFX-l" ping -c3 -W2 -s "$s" "$fv" >/dev/null 2>&1 || docker exec "$PFX-l" ping -c3 -W2 -s "$s" "$fv" >/dev/null 2>&1 || pings=1
	docker exec "$PFX-f" ping -c3 -W2 -s "$s" "$lv" >/dev/null 2>&1 || docker exec "$PFX-f" ping -c3 -W2 -s "$s" "$lv" >/dev/null 2>&1 || pings=1
done
info=$(t l info founder)
if [[ $pings -eq 0 ]] && grep -q "udp_confirmed" <<<"$info"; then
	ok "the tunnel carries 56- and 1400-byte pings both ways, datagrams confirmed; $(grep -o 'PMTU: *[0-9]*' <<<"$info" | tr -s ' ')"
else
	bad "the tunnel over quic: pings $([[ $pings -eq 0 ]] && echo ok || echo lost), $(grep -E 'Status|Reach' <<<"$info" | tr -s ' ' | paste -sd';')"
fi

if [[ $FAILED -eq 0 ]]; then
	log "quic wire: all checks passed"
else
	log "quic wire: FAILURES above"
fi
exit "$FAILED"

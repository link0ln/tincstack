#!/usr/bin/env bash
# The https and quic fronts live on 443, not on tinc's port -- and the quic
# client sends from an ephemeral port like every QUIC client.
#
# The wire-fingerprint audit (testing/fingerprint, 2026-09-23) found TLS and
# QUIC on 655, tinc's IANA port, and our quic dial sending *from* the tinc
# port. Now (docs/transports.md §3.1):
#
#   * a node that accepts inbound connections (Port is not 0) also listens on
#     TCP 443 (HttpsPort) and UDP 443 (QuicPort) by default, TLS-only and
#     QUIC-only -- plain and obfs stay on the tinc port;
#   * it writes HttpsPort/QuicPort into its own host record, so an invitation
#     tells the invitee where to dial;
#   * the quic dial uses a fresh socket on an ephemeral port;
#   * a node that cannot bind 443 says so, advertises nothing, and peers keep
#     reaching the fronts on the tinc port.
#
# Founder F and leaf L, joined by a real `tinc invite' / `tinc join'. L is a
# listening node too (Port 655), so a dial from its listening socket would
# show up as source port 655 or 443.
#
# Usage: [CORE_IMAGE=...] testing/transports/front-port-test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
RUN="$HERE/run-frontport"
PFX=fport
NET=${PFX}net
SUBNET=10.47.5
F_IP=$SUBNET.10
L_IP=$SUBNET.11
P_IP=$SUBNET.12
NETNAME=lab
YAML=/c/tinc.yaml
FAILED=0

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

cleanup() {
	docker rm -f "$PFX-f" "$PFX-l" "$PFX-cap" "$PFX-occ" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	docker run --rm -v "$RUN:/r" "$IMG" sh -c 'rm -rf /r/*' >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
mkdir -p "$RUN/f" "$RUN/l" "$RUN/cap"
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

if ! docker image inspect "$TOOLS" >/dev/null 2>&1; then
	docker build -q --build-arg http_proxy="${HTTP_PROXY:-}" --build-arg https_proxy="${HTTP_PROXY:-}" \
		-t "$TOOLS" "$ROOT/testing/fingerprint" >/dev/null
fi

tnc() { local n=$1; shift; docker exec "$PFX-$n" tinc -n "$NETNAME" -c "$YAML" "$@"; }
node() { # <f|l> <ip>: a sleeper; tincd is started with docker exec
	docker run -d --name "$PFX-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN --device /dev/net/tun \
		-v "$RUN/$1:/c" "$IMG" sleep infinity >/dev/null
}
start() { docker exec -d "$PFX-$1" sh -c "tincd -n $NETNAME -c $YAML -D -d3 >>/c/tincd.log 2>&1"; }
stop() { tnc "$1" stop >/dev/null 2>&1 || true; sleep 1; }
ready() {
	for _ in $(seq 30); do tnc "$1" pid >/dev/null 2>&1 && return 0; sleep 1; done
	log "node $1 never came up"; tail -20 "$RUN/$1/tincd.log" >&2; exit 1
}
logged() { grep -q -- "$2" "$RUN/$1/tincd.log"; }
connected() { tnc l dump connections 2>/dev/null | grep -q "^founder .*transport $1"; }
wait_connected() { for _ in $(seq "$2"); do connected "$1" && return 0; sleep 1; done; return 1; }
probe() { docker run --rm --network "$NET" --ip "$P_IP" "$TOOLS" bash -c "$1"; }
pcap() { docker run --rm -v "$RUN/cap:/cap" "$TOOLS" tshark -r /cap/f.pcap -Y "$1" -T fields "${@:2}" 2>/dev/null; }

# ---- the founder -----------------------------------------------------------------
node f "$F_IP"
docker exec "$PFX-f" sh -c "install -m600 /dev/null $YAML && tinc -n $NETNAME -c $YAML set Name founder && tinc -n $NETNAME -c $YAML set Port 655"
start f
ready f
sleep 2

if logged f "listening on .*port 443 (HttpsPort)" && logged f "listening on .*port 443 (QuicPort)"; then
	ok "a listening node opens the https and quic fronts on 443 by default"
else
	bad "a listening node opens the https and quic fronts on 443 by default"
	grep -iE "443|front|listening" "$RUN/f/tincd.log" | head >&2
fi

if [[ $(tnc f get founder.HttpsPort 2>/dev/null) == 443 && $(tnc f get founder.QuicPort 2>/dev/null) == 443 ]]; then
	ok "... and advertises them in its own host record"
else
	bad "... and advertises them in its own host record (HttpsPort=$(tnc f get founder.HttpsPort 2>&1) QuicPort=$(tnc f get founder.QuicPort 2>&1))"
fi

# ---- a leaf, joined by invitation ----------------------------------------------------
tnc f set founder.Address "$F_IP"
inv=$(tnc f invite leaf)
node l "$L_IP"
tnc l join "$inv" >/dev/null 2>&1

# Capture from here: `tinc join' itself is cleartext tinc on the tinc port
# (PLAN.md, known), and is not what is being measured.
docker run -d --name "$PFX-cap" --network "container:$PFX-f" --cap-add NET_ADMIN --cap-add NET_RAW \
	-v "$RUN/cap:/cap" "$TOOLS" tcpdump -U -i any -s 0 -w /cap/f.pcap 'tcp or udp' >/dev/null
sleep 2

if [[ $(tnc l get founder.HttpsPort 2>/dev/null) == 443 && $(tnc l get founder.QuicPort 2>/dev/null) == 443 ]]; then
	ok "the invitation carries the front ports to the invitee"
else
	bad "the invitation carries the front ports to the invitee"
fi

# A listening leaf, so that a dial from its listening socket would be visible.
tnc l set Port 655
tnc l set PreferredTransports https
start l
ready l

if wait_connected https 40; then
	ok "the leaf connects via https"
else
	bad "the leaf connects via https"
	tail -15 "$RUN/l/tincd.log" >&2
fi

stop l
tnc l set PreferredTransports quic
start l
ready l

if wait_connected quic 40; then
	ok "the leaf connects via quic"
else
	bad "the leaf connects via quic"
	tail -15 "$RUN/l/tincd.log" >&2
fi

# ---- a prober on the fronts -------------------------------------------------------------
probe "curl -sk -m 5 -o /dev/null -w '%{http_code}' https://$F_IP/" > "$RUN/tls-probe" || true
if [[ $(cat "$RUN/tls-probe") == 200 ]]; then
	ok "TLS on TCP 443 reaches the https front (decoy answers)"
else
	bad "TLS on TCP 443 reaches the https front (got '$(cat "$RUN/tls-probe")')"
fi

probe "exec 3<>/dev/tcp/$F_IP/443; printf '0 prober 17.7\n' >&3; timeout 3 cat <&3 | wc -c" > "$RUN/tinc-probe" 2>/dev/null || true
if [[ $(tr -d ' \n' < "$RUN/tinc-probe") == 0 ]]; then
	ok "a tinc ID line on TCP 443 gets no answer"
else
	bad "a tinc ID line on TCP 443 gets no answer (got $(cat "$RUN/tinc-probe") bytes)"
fi

probe "head -c 120 /dev/urandom > /dev/udp/$F_IP/443; sleep 2" || true
sleep 2
docker rm -f "$PFX-cap" >/dev/null
sleep 1

# ---- what the capture says --------------------------------------------------------------
tcp_dports=$(pcap "ip.src == $L_IP && tcp.flags.syn == 1 && tcp.flags.ack == 0" -e tcp.dstport | sort -u | tr '\n' ' ')
if [[ $tcp_dports == "443 " ]]; then
	ok "the https dial went to TCP 443 (and nowhere else)"
else
	bad "the https dial went to TCP 443 (and nowhere else): dports '$tcp_dports'"
fi

quic_flows=$(pcap "ip.src == $L_IP && quic" -e udp.srcport -e udp.dstport | sort -u)
quic_dports=$(awk '{print $2}' <<<"$quic_flows" | sort -u | tr '\n' ' ')
quic_sports=$(awk '{print $1}' <<<"$quic_flows" | sort -u | tr '\n' ' ')
if [[ $quic_dports == "443 " ]]; then
	ok "the quic dial went to UDP 443"
else
	bad "the quic dial went to UDP 443: dports '$quic_dports'"
fi
if [[ -n $quic_sports && ! " $quic_sports " =~ \ (655|443)\  ]]; then
	ok "... from an ephemeral source port ($quic_sports)"
else
	bad "... from an ephemeral source port: sports '$quic_sports'"
fi

udp_answers=$(pcap "ip.dst == $P_IP && udp" -e udp.srcport | wc -l)
if [[ $udp_answers == 0 ]]; then
	ok "random bytes on UDP 443 get no answer"
else
	bad "random bytes on UDP 443 get no answer ($udp_answers datagrams back)"
fi

# ---- a peer that knows no front port still gets in, on the tinc port ---------------------
stop l
tnc l set founder.HttpsPort "" >/dev/null 2>&1 || true
docker exec "$PFX-l" sh -c "sed -i '/HttpsPort = /d; /QuicPort = /d' $YAML"
tnc l set PreferredTransports https
start l
ready l
if wait_connected https 40; then
	ok "without an advertised HttpsPort the https dial still gets in on the tinc port"
else
	bad "without an advertised HttpsPort the https dial still gets in on the tinc port"
fi
stop l

# ---- a founder that cannot have 443 ----------------------------------------------------
# What a non-root Linux node sees: no CAP_NET_BIND_SERVICE, privileged ports
# below 1024.
stop f
docker rm -f "$PFX-f" >/dev/null
tnc_f2() { docker exec "$PFX-f" tinc -n "$NETNAME" -c "$YAML" "$@"; }
docker run -d --name "$PFX-f" --network "$NET" --ip "$F_IP" --cap-add NET_ADMIN --device /dev/net/tun \
	--cap-drop NET_BIND_SERVICE --sysctl net.ipv4.ip_unprivileged_port_start=1024 \
	-v "$RUN/f:/c" "$IMG" sleep infinity >/dev/null
tnc_f2 set Port 6550
: > "$RUN/f/tincd.log"
start f
ready f
sleep 2
if logged f "could not listen on TCP port 443 (the default)" && logged f "could not listen on UDP port 443 (the default)"; then
	ok "a node that cannot bind 443 says so"
else
	bad "a node that cannot bind 443 says so"
	grep -iE "443|listen" "$RUN/f/tincd.log" | head >&2
fi
if ! tnc f get founder.HttpsPort >/dev/null 2>&1 && ! tnc f get founder.QuicPort >/dev/null 2>&1; then
	ok "... and stops advertising the front ports"
else
	bad "... and stops advertising the front ports ($(tnc f get founder.HttpsPort 2>&1) / $(tnc f get founder.QuicPort 2>&1))"
fi

# ---- UDP 443 taken by another QUIC server -------------------------------------------
# openssl s_server sets SO_REUSEADDR, as nginx and most servers do. So did the
# socket tincd opened for the quic front, and on Linux two UDP sockets that both
# set it share the port: the kernel hands each datagram to one of them. The
# front must fail to bind instead of silently taking part of the other
# server's traffic.
stop f
docker rm -f "$PFX-f" >/dev/null
node f "$F_IP"
docker run -d --name "$PFX-occ" --network "container:$PFX-f" "$TOOLS" bash -c \
	"cd /tmp && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=o -keyout k -out c 2>/dev/null
	 sleep infinity | openssl s_server -dtls1_2 -accept 443 -key k -cert c >/dev/null 2>&1" >/dev/null
for _ in $(seq 10); do
	docker exec "$PFX-f" sh -c 'cat /proc/net/udp /proc/net/udp6' | grep -q ':01BB ' && break
	sleep 1
done
if ! docker exec "$PFX-f" sh -c 'cat /proc/net/udp /proc/net/udp6' | grep -q ':01BB '; then
	bad "the occupier holds UDP 443 (lab setup)"
fi
tnc f set Port 655
: > "$RUN/f/tincd.log"
start f
ready f
sleep 2
if logged f "could not listen on UDP port 443" && ! logged f "listening on .*port 443 (QuicPort)"; then
	ok "a quic front does not share UDP 443 with another server"
else
	bad "a quic front does not share UDP 443 with another server"
	grep -iE "443|quic" "$RUN/f/tincd.log" | head >&2
fi
if [[ $(tnc f get founder.HttpsPort 2>/dev/null) == 443 ]] && ! tnc f get founder.QuicPort >/dev/null 2>&1; then
	ok "... and advertises only the https front"
else
	bad "... and advertises only the https front ($(tnc f get founder.HttpsPort 2>&1) / $(tnc f get founder.QuicPort 2>&1))"
fi

if [[ $FAILED -eq 0 ]]; then
	log "front ports: all checks passed"
else
	log "front ports: FAILURES above"
fi
exit "$FAILED"

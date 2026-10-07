#!/bin/sh
# dns-refresh-test.sh -- a DNS name in Address is watched and followed.
#
# The owner request (2026-10-07, plan block "DNS names for node addresses"):
# a node whose host record says `Address = <dns name>` must be re-dialled
# when the name's A record moves, and the last address the name resolved to
# must survive the resolver being down.
#
# Lab shape: two tinc nodes on one docker network plus a dnsmasq. The dialler
# (nodea) knows nodeb ONLY by name b.tinc.lab; dnsmasq answers from a hosts
# file the test rewrites on the fly. The interval is set to 5 s so the whole
# proof runs in minutes.
#
#   PART 1  name resolves to .12 -- the pair connects, nodea's connection
#           sits on .12, dnsrefresh.state persists b.tinc.lab -> .12.
#   PART 2  the A record flips to .13 (nodeb also answers there) -- within
#           interval + settle, nodea drops the .12 session and the live
#           connection is on .13 (owner's rule: two servers with one
#           identity must not coexist).
#   PART 3  the record and the resolver both go away (dnsmasq is stopped),
#           nodea restarts -- it must come back to .12/.13 from the
#           persisted last-good address, without any DNS.
#   CONTROL `DnsRefreshInterval = 0' -- a flip does nothing; the .12 session
#           stays until the link dies on its own.
#
# Usage: [CORE_IMAGE=tincstack/core:tag] sh testing/transports/dns-refresh-test.sh
#        DNS_IMAGE=<image with dnsmasq> to reuse a prebuilt resolver image.
set -eu

# shellcheck source=testing/transports/lab-env.sh
DEFAULT_LAB=wsdns; DEFAULT_SUBNET=10.33.13
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"

NET=$LAB
NETNAME=tincstack
YAML=/etc/tincstack/tinc.yaml
YAML_DIR=/etc/tincstack
INTERVAL=${INTERVAL:-5}
SETTLE=${SETTLE:-25}

A_IP=$SUBNET.10
B1_IP=$SUBNET.12          # nodeb's first address (A record target)
B2_IP=$SUBNET.13          # nodeb's second address (after the flip)
DNS_IP=$SUBNET.9
NAME=b.tinc.lab

cleanup() {
	if [ "${KEEP:-0}" = 1 ]; then
		echo "KEEP=1: containers and /tmp/$LAB-* left for inspection" >&2
		return
	fi
	docker rm -f "$LAB-a" "$LAB-b" "$LAB-b2" "$LAB-dns" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "/tmp/$LAB-a" "/tmp/$LAB-b" "/tmp/$LAB-b2" "/tmp/$LAB-dns" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

IMG=${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
	echo "FAIL: image $IMG does not exist; build it or set TINCSTACK_TAG" >&2
	exit 1
fi
echo "image: $IMG ($(docker run --rm "$IMG" tincd --version | head -n1))"

# ── the resolver ─────────────────────────────────────────────────────────
# dnsmasq from the debian:12-slim base (built locally; no registry pull).
DNS_IMAGE=${DNS_IMAGE:-tincstack/dnsmasq:dev}
if ! docker image inspect "$DNS_IMAGE" >/dev/null 2>&1; then
	# stdin build: no context directory is needed, and this keeps the lab
	# self-contained (debian:12-slim is a local image; no registry pull).
	docker build -q -t "$DNS_IMAGE" - <<'BUILD' >/dev/null
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends dnsmasq-base \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["dnsmasq", "--no-daemon", "--log-facility=-", "-q"]
BUILD
fi

rm -rf "/tmp/$LAB-dns"; mkdir -p "/tmp/$LAB-dns"
: > "/tmp/$LAB-dns/hosts"
set_host() { # set_host <ip> -- point $NAME at an ip (or remove it)
	# addn-hosts format is "IP name" (hosts(5)); the dnsmasq.conf
	# address=/name/ip syntax is NOT read from addn-hosts files.
	printf '%s %s\n' "$1" "$NAME" > "/tmp/$LAB-dns/hosts"
	# kill is a shell builtin, not a binary: docker exec needs a shell to
	# run it in, or the HUP never reaches dnsmasq and the flip is not read.
	docker exec "$LAB-dns" sh -c 'kill -HUP 1' 2>/dev/null || true
}
docker run -d --name "$LAB-dns" --network "$NET" --ip "$DNS_IP" \
	--mount type=bind,source="/tmp/$LAB-dns/hosts",target=/etc/dnsmasq.more,readonly \
	--dns 127.0.0.1 \
	"$DNS_IMAGE" --conf-file=/dev/null --no-resolv \
	--addn-hosts=/etc/dnsmasq.more --server=/tinc.lab/ \
	--listen-address="$DNS_IP" >/dev/null

set_host "$B1_IP"

# ── the nodes ────────────────────────────────────────────────────────────
run_node() { # run_node <suffix> <ip> <extra ip>
	docker run -d --name "$LAB-$1" --network "$NET" --ip "$2" \
		${3:+--network "$NET" } \
		--cap-add NET_ADMIN --device /dev/net/tun \
		--dns "$DNS_IP" \
		-v "/tmp/$LAB-$1:/etc/tincstack" "$IMG" sleep infinity >/dev/null
}

for n in a b; do rm -rf "/tmp/$LAB-$n"; mkdir -p "/tmp/$LAB-$n"; done
run_node a "$A_IP"
# nodeb starts at B1_IP; PART 2 migrates it wholesale to B2_IP (see
# move_nodeb) -- the old address dies with the old container, which is the
# realistic "we moved the server" shape.
run_node b "$B1_IP"
sleep 1
# dnsmasq resolves the name for nodea; give the resolver container a second
# so its socket is up before any lookup.
sleep 1

tnc() {
	tnc_c=$1; shift
	docker exec "$LAB-$tnc_c" tinc -n "$NETNAME" -c "$YAML" "$@"
}

start_tincd() { docker exec -d "$LAB-$1" sh -c "tincd -n $NETNAME -c $YAML -D -d${LOG_LEVEL:-3} >>/etc/tincstack/tincd.log 2>&1"; }
# A clean stop that works even when the pid file is gone (PART 3 restarts
# after a resolver outage): ask the daemon politely, then make sure it is
# gone before the next start -- a leftover holding /dev/net/tun fails the
# restart with "Device or resource busy". No pgrep/pkill: the node image is
# debian-slim and has no procps; walk /proc instead.
tincd_alive() { # tincd_alive <suffix>: 0 when a tincd process exists
	docker exec "$LAB-$1" sh -c '
	for d in /proc/[0-9]*; do
		readlink "$d/exe" 2>/dev/null | grep -q tincd && exit 0
	done
	exit 1' >/dev/null 2>&1
}
stop_node() {
	docker exec "$LAB-$1" tinc -n "$NETNAME" -c "$YAML" stop >/dev/null 2>&1 || true
	i=0
	while [ "$i" -lt 15 ]; do
		tincd_alive "$1" || return 0
		i=$(( i + 1 )); sleep 1
	done
	docker exec "$LAB-$1" sh -c '
	for d in /proc/[0-9]*; do
		readlink "$d/exe" 2>/dev/null | grep -q tincd && kill "${d#/proc/}" 2>/dev/null
	done' >/dev/null 2>&1 || true
	sleep 2
}
wait_ready() {
	i=0
	while [ "$i" -lt 30 ]; do
		tnc "$1" pid >/dev/null 2>&1 && return 0
		i=$(( i + 1 )); sleep 1
	done
	echo "FAIL: $LAB-$1 did not open its control socket" >&2
	cat "/tmp/$LAB-$1/tincd.log" >&2 || true
	exit 1
}

echo "== nodea: founder; nodeb joins by invitation, then nodea knows it by name"
docker exec "$LAB-a" sh -c "install -m600 /dev/null $YAML && tinc -n $NETNAME -c $YAML set Name nodea && tinc -n $NETNAME -c $YAML set Port 655 && tinc -n $NETNAME -c $YAML set DnsRefreshInterval $INTERVAL"
start_tincd a
wait_ready a
tnc a set nodea.Address "$A_IP"

# nodea hands nodeb its record by invitation (join on a blank nodeb; a node
# that already has a network refuses to join).
inv=$(tnc a invite nodeb)
docker exec "$LAB-b" sh -c "install -m600 /dev/null $YAML"
tnc b join "$inv" >/dev/null
start_tincd b
wait_ready b
# What matters is nodea's view: nodeb is known by the DNS name, not an IP.
tnc a set nodeb.Address "$NAME"

echo "== PART 1: the name resolves to $B1_IP; expecting a session on it"
sleep "$SETTLE"

fail=0
note() { echo "MISS: $*"; fail=1; }
alog() { grep -c "$1" "/tmp/$LAB-a/tincd.log" >/dev/null; }

conn_ip() { # the address nodea's live meta connection to nodeb is on
	# `dump nodes' prints "<name> id <id> at <host> port <port> cipher ..."
	# so the host is field 5. MYSELF lines and unreachable hosts are skipped
	# by matching the name exactly.
	tnc a dump nodes 2>/dev/null | awk '$1 == "nodeb" && $4 == "at" {print $5}' | head -n1
}

c1=$(conn_ip)
echo "   connection to nodeb on: ${c1:-none}"
[ "$c1" = "$B1_IP" ] || note "PART 1: connection is on '$c1', expected $B1_IP"
docker exec "$LAB-a" sh -c "grep -q 'nodeb $NAME' $YAML_DIR/$NETNAME/cache/dnsrefresh.state" \
	|| note "PART 1: dnsrefresh.state does not hold 'nodeb $NAME'"

# move_nodeb <new ip> -- a real migration: the old address leaves the old
# container and lands on a fresh one running the SAME identity (keys and
# config move with the volume), which is exactly the "two servers, one
# identity" the owner wants prevented: while both live, nodea must follow
# DNS, not the address it first reached.
move_nodeb() {
	docker rm -f "$LAB-b2" >/dev/null 2>&1 || true
	rm -rf "/tmp/$LAB-b2"
	cp -a "/tmp/$LAB-b" "/tmp/$LAB-b2"
	docker run -d --name "$LAB-b2" --network "$NET" --ip "$1" \
		--cap-add NET_ADMIN --device /dev/net/tun \
		--dns "$DNS_IP" \
		-v "/tmp/$LAB-b2:/etc/tincstack" "$IMG" sleep infinity >/dev/null
	# Wipe the old container's config so it can no longer claim the
	# identity if anything still dials the old address.
	docker rm -f "$LAB-b" >/dev/null 2>&1 || true
	docker exec "$LAB-b2" sh -c "rm -f /etc/tincstack/tincstack/run/* 2>/dev/null; tincd -n $NETNAME -c $YAML -k" >/dev/null 2>&1 || true
	docker exec -d "$LAB-b2" sh -c "tincd -n $NETNAME -c $YAML -D -d${LOG_LEVEL:-3} >>/etc/tincstack/tincd.log 2>&1"
}

echo "== PART 2: flip the A record to $B2_IP (the server moved); expecting a re-dial"
set_host "$B2_IP"
move_nodeb "$B2_IP"
sleep $(( INTERVAL * 2 + SETTLE ))

c2=$(conn_ip)
echo "   connection to nodeb on: ${c2:-none}"
[ "$c2" = "$B2_IP" ] || note "PART 2: connection is on '$c2', expected $B2_IP"
alog "dnsrefresh: nodeb moved" || note "PART 2: no 'moved' line in nodea's log"
docker exec "$LAB-a" sh -c "grep -q '$B2_IP' $YAML_DIR/$NETNAME/cache/dnsrefresh.state" \
	|| note "PART 2: dnsrefresh.state was not updated to $B2_IP"

echo "== PART 3: kill the resolver, restart nodea; last-good must carry it"
docker stop "$LAB-dns" >/dev/null
stop_node a
rm -f "/tmp/$LAB-a/tincd.log"
start_tincd a
wait_ready a
sleep "$SETTLE"

c3=$(conn_ip)
echo "   connection to nodeb on: ${c3:-none} (resolver down)"
[ "$c3" = "$B2_IP" ] || note "PART 3: connection is on '$c3', expected $B2_IP (persisted)"

echo "== CONTROL: DnsRefreshInterval = 0 -- a flip must do nothing"
docker start "$LAB-dns" >/dev/null
sleep 2
stop_node a
docker exec "$LAB-a" tinc -n "$NETNAME" -c "$YAML" set DnsRefreshInterval 0
rm -f "/tmp/$LAB-a/tincd.log"
start_tincd a
wait_ready a
sleep "$SETTLE"
c4a=$(conn_ip)
set_host "$B1_IP"
sleep $(( INTERVAL * 4 + SETTLE ))
c4b=$(conn_ip)
echo "   before flip: $c4a, after flip: $c4b (expect no change)"
[ "$c4a" = "$c4b" ] || note "CONTROL: connection moved $c4a -> $c4b with the watcher off"

echo
if [ "$fail" -eq 0 ]; then
	echo "PASS: dns follow, last-good persistence, and the disabled control all held"
else
	echo "FAIL: $fail miss(es) above"
fi
exit "$fail"

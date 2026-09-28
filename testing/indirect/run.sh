#!/usr/bin/env bash
# IndirectData proof: a node that sets IndirectData is contacted by its meta
# neighbours only. Topology, as ruvds2/euvds in production (PLAN.md, "euvds
# talks to ruvds2 only"):
#
#   client --ConnectTo--> relay --ConnectTo--> exit (IndirectData: yes)
#
# client runs the default AutoConnect: yes, so it would dial exit on its own
# as soon as it learns of it. Asserted after a settle period that spans several
# AutoConnect rounds:
#   - client pings exit's VPN address (the data goes through relay);
#   - not one packet from client to exit's LAN address, counted by iptables in
#     both containers from tinc-up on (before the daemons dial anything);
#   - client never logs "Autoconnecting to exit";
#   - exit's own edge carries OPTION_DECLARED_INDIRECT (0x10), relay's edge to
#     exit does not (the bit is never merged from the peer's ACK).
# Exit 0 = pass. Run it against the previous image to see it discriminate:
#   CORE_IMAGE=tincstack/core:40c0745 testing/indirect/run.sh   # v0.5.0: FAIL
#
# Mixed deployment (production: ruvds2 still on v0.5.0, euvds and clients new):
#   RELAY_IMAGE=tincstack/core:40c0745 testing/indirect/run.sh      # PASS
#
# Usage: [CORE_IMAGE=tincstack/core:dev] [RELAY_IMAGE=...] [LAB=wind] [SETTLE=45] testing/indirect/run.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CORE_IMAGE="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
SETTLE="${SETTLE:-45}"
NET=ind
DEFAULT_LAB=wind; DEFAULT_SUBNET=172.31.78
# shellcheck source=testing/transports/lab-env.sh
. "$HERE/../transports/lab-env.sh"
export IND_PROJECT="$LAB-indirect" IND_SUBNET="$SUBNET"
if [ "$LAB" = "$DEFAULT_LAB" ]; then IND_RUN=run; else IND_RUN="run-$LAB"; fi
export IND_RUN
RUN="$HERE/$IND_RUN"
compose() { docker compose -f "$HERE/compose.yml" "$@"; }
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

cleanup() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    docker run --rm -v "$HERE:/mnt" "$CORE_IMAGE" rm -rf "/mnt/$IND_RUN" >/dev/null 2>&1 || true
    rm -rf "$RUN" 2>/dev/null || true
}
cleanup
trap cleanup EXIT
mkdir -p "$RUN"

if ! docker image inspect "$CORE_IMAGE" >/dev/null 2>&1; then
    log "indirect: FAIL ($CORE_IMAGE does not exist)"; exit 1
fi

RELAY="$SUBNET.11" EXIT="$SUBNET.12" CLIENT="$SUBNET.13"

# gen NAME LAN_IP VPN_IP "extra tinc-up line" [option lines...]
gen() {
    local name="$1" lan="$2" vpn="$3" up="$4"; shift 4
    local tmp="$RUN/keys-$name" d="$RUN/$name"
    mkdir -p "$tmp/hosts" "$d/$NET"
    printf 'Name = %s\n' "$name" > "$tmp/tinc.conf"
    docker run --rm -v "$tmp:/k" "$CORE_IMAGE" \
        sh -c "tinc -c /k generate-keys && chown -R $(id -u):$(id -g) /k" >/dev/null 2>&1
    { printf 'Address = %s\nPort = 655\nSubnet = %s/32\n' "$lan" "$vpn"; cat "$tmp/hosts/$name"; } > "$RUN/host-$name.txt"
    {
        echo "networks:"
        echo "  $NET:"
        echo "    options:"
        echo "      Name: $name"
        echo "      Mode: router"
        echo "      Port: 655"
        echo "      AddressFamily: ipv4"
        for l in "$@"; do echo "      $l"; done
        echo "    keys:"
        echo "      ed25519_priv: |"; sed 's/^/        /' "$tmp/ed25519_key.priv"
        echo "      rsa_priv: |"; sed 's/^/        /' "$tmp/rsa_key.priv"
        echo "    scripts:"
        echo "      tinc-up: |"
        echo "        #!/bin/sh"
        # shellcheck disable=SC2016  # $INTERFACE is expanded by tincd, not here
        echo '        ip link set "$INTERFACE" up'
        echo "        ip addr add $vpn/24 dev \"\$INTERFACE\""
        [ -n "$up" ] && echo "        $up"
    } > "$d/tinc.yaml"
    rm -rf "$tmp"
}
# The counters go in from tinc-up: the device is set up before any dial.
gen relay "$RELAY" 10.78.0.1 "" "ConnectTo: [exit]"
gen exit "$EXIT" 10.78.0.2 "iptables -A INPUT -s $CLIENT" "IndirectData: yes" "AutoConnect: no"
gen client "$CLIENT" 10.78.0.3 "iptables -A OUTPUT -d $EXIT" "ConnectTo: [relay]" "AutoConnect: yes"
hosts() { # hosts NODE PEERS...
    local n="$1"; shift
    { echo "    hosts:"; for m in "$@"; do echo "      $m: |"; sed 's/^/        /' "$RUN/host-$m.txt"; done; } >> "$RUN/$n/tinc.yaml"
}
hosts relay relay exit client
hosts exit exit relay
hosts client client relay   # exit's key and address only ever come from the mesh
rm -f "$RUN"/host-*.txt

if ! compose up -d >/dev/null 2>"$RUN/compose-up.err"; then
    sed 's/^/indirect: /' "$RUN/compose-up.err" >&2; compose logs; exit 1
fi
ok=1
reach=0
for _ in $(seq 1 40); do
    if compose exec -T client ping -c 1 -W 1 10.78.0.2 >/dev/null 2>&1; then reach=1; break; fi
    sleep 1
done
[ "$reach" -eq 1 ] || { log "indirect: FAIL (client never reached exit's VPN address through relay)"; ok=0; }
log "indirect: settling ${SETTLE}s (several AutoConnect rounds)"
sleep "$SETTLE"
compose exec -T client ping -c 5 -i 0.3 -W 2 10.78.0.2 >"$RUN/ping.txt" 2>&1 || true
if ! grep -c " 0% packet loss" "$RUN/ping.txt" >/dev/null; then log "indirect: FAIL (client -> exit ping after settle)"; cat "$RUN/ping.txt" >&2; ok=0; fi

sent=$(compose exec -T client iptables -nvxL OUTPUT | awk -v d="$EXIT" '$0 ~ d {print $1; exit}')
got=$(compose exec -T exit iptables -nvxL INPUT | awk -v s="$CLIENT" '$0 ~ s {print $1; exit}')
log "indirect: packets client->exit LAN address: sent $sent, received $got"
[ "${sent:-x}" = 0 ] || { log "indirect: FAIL (client sent ${sent:-?} packets straight to exit)"; ok=0; }
[ "${got:-x}" = 0 ] || { log "indirect: FAIL (exit received ${got:-?} packets from client)"; ok=0; }

dials=$(compose logs --no-log-prefix client | grep -c "Autoconnecting to exit" || true)
[ "$dials" = 0 ] || { log "indirect: FAIL (client autoconnected to exit $dials times)"; ok=0; }

edges=$(compose exec -T client tinc -c /etc/tincstack/tinc.yaml dump edges)
printf '%s\n' "$edges" | sed 's/^/indirect: edge: /' >&2
own=$(printf '%s\n' "$edges" | awk '$1=="exit" && $3=="relay" {for(i=1;i<NF;i++) if($i=="options") print $(i+1)}')
theirs=$(printf '%s\n' "$edges" | awk '$1=="relay" && $3=="exit" {for(i=1;i<NF;i++) if($i=="options") print $(i+1)}')
if [ -z "$own" ] || [ $(( 0x$own & 0x10 )) -eq 0 ]; then log "indirect: FAIL (exit's own edge lacks 0x10: '${own}')"; ok=0; fi
if [ -z "$theirs" ] || [ $(( 0x$theirs & 0x1 )) -eq 0 ]; then
    log "indirect: FAIL (relay's edge to exit must be INDIRECT: '${theirs}')"; ok=0
elif [ "${RELAY_IMAGE:-$CORE_IMAGE}" = "$CORE_IMAGE" ] && [ $(( 0x$theirs & 0x10 )) -ne 0 ]; then
    # an older relay merges the bit from exit's ACK; that only stops new
    # clients from AutoConnecting to the relay, which they ConnectTo anyway
    log "indirect: FAIL (relay's edge to exit carries exit's 0x10: '${theirs}')"; ok=0
fi

if [ "$ok" -eq 1 ]; then
    log "indirect: PASS (client reaches exit via relay only, no dial, no packet; $CORE_IMAGE)"
else
    compose logs --no-log-prefix client | grep -E "Autoconnect|exit" | tail -20 >&2 || true
    log "indirect: FAIL ($CORE_IMAGE)"; exit 1
fi

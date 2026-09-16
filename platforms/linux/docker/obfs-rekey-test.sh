#!/bin/bash
# obfs-rekey-test.sh -- proof that the obfs per-link session key actually
# ROTATES, on the same two-project lab as two-nodes.sh (<LAB>-a founding,
# <LAB>-b invitee). docs/transports.md claims the key is "re-derived
# periodically (aligned with KeyExpire)"; nothing proved it, and the first
# implementation only rotated when BOTH peers happened to run their own timer:
# an offer from the peer was left unanswered once we had acked the previous
# round, so the effective period was the LARGER of the two KeyExpire values
# (measured: A KeyExpire 10 s, B 3600 s -> one session key in 80 s, eight
# offers ignored).
#
#   1. b joins a over the default (plain) carrier and the tunnel works;
#   2. both nodes are switched to the obfs carrier and restarted;
#   3. SYMMETRIC: both KeyExpire = REKEY (default 10 s). Over WINDOW seconds of
#      1 Hz ping both sides must log several "obfs session key established"
#      and lose no packet -- the sender keeps the current key until the new one
#      is acked, so rotation must never cost traffic;
#   4. ASYMMETRIC: a keeps KeyExpire = REKEY, b is set to 3600. a alone drives
#      the rotation, so both sides must still rotate more than once. This is
#      the regression test for the unanswered-offer defect.
#
# Exit 0 = every step held. Everything it creates is removed on exit unless
# KEEP=1. Tunables: LAB (project prefix, default wsrk), TINCSTACK_TAG (image
# tag, default dev), WAIT (seconds per wait, default 60), REKEY (KeyExpire of
# the driving node, default 10), WINDOW (seconds of traffic per phase,
# default 80).
set -euo pipefail
cd "$(dirname "$0")"

LAB=${LAB:-wsrk}
WAIT=${WAIT:-60}
REKEY=${REKEY:-10}
WINDOW=${WINDOW:-80}
A=$LAB-a
B=$LAB-b
export COMPOSE_FILE=docker-compose.yml:compose.lab.yml
export TINCSTACK_LAB_NET=$LAB-lab
export TINCSTACK_TAG=${TINCSTACK_TAG:-dev}

# The rotation is logged at DEBUG under DEBUG_CONNECTIONS, so the nodes run at
# -d3; a rotation that converges logs exactly one line per side per round.
LOG_LEVEL=3
export LOG_LEVEL

fail=0
step() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
miss() { printf '   MISS: %s\n' "$*"; fail=1; }

cleanup() {
    if [[ ${KEEP:-0} == 1 ]]; then
        echo "KEEP=1: leaving $A, $B and network $TINCSTACK_LAB_NET in place"
        return
    fi
    step "cleanup"
    docker compose -p "$A" down -v --remove-orphans >/dev/null 2>&1 || true
    docker compose -p "$B" down -v --remove-orphans >/dev/null 2>&1 || true
    docker network rm "$TINCSTACK_LAB_NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup >/dev/null 2>&1 || true

node() { docker compose -p "$1" exec -T node "${@:2}"; }
cli() { node "$1" tincstack-cli "${@:2}"; }
logs() { docker compose -p "$1" logs --no-log-prefix node 2>/dev/null; }
rekeys() { logs "$1" | grep -c 'obfs session key established' || true; }

wait_ready() {
    local deadline=$(( SECONDS + WAIT ))
    until logs "$1" | grep -q ' Ready$' && node "$1" tincstack-cli pid >/dev/null 2>&1; do
        if (( SECONDS >= deadline )); then
            echo "FAIL: $1 not ready within ${WAIT}s; log follows" >&2
            logs "$1" >&2 || true
            return 1
        fi
        sleep 1
    done
}

docker network inspect "$TINCSTACK_LAB_NET" >/dev/null 2>&1 \
    || docker network create "$TINCSTACK_LAB_NET" >/dev/null

step "1: founding node and join"
COMPOSE_PROJECT_NAME=$A NODE_NAME=node_a PUBLIC_ADDRESS=$A-node-1 PORT=655 \
    docker compose up -d --build --quiet-pull >/dev/null
wait_ready "$A"
invitation=$(COMPOSE_PROJECT_NAME=$A ./invite.sh node_b)
COMPOSE_PROJECT_NAME=$B PORT=656 INVITE=$invitation docker compose up -d >/dev/null
wait_ready "$B"

a_ip=$(cli "$A" get node_a.Subnet | head -n1); a_ip=${a_ip%%/*}
b_ip=$(cli "$B" get node_b.Subnet | head -n1); b_ip=${b_ip%%/*}
if node "$B" ping -c 2 -W 2 "$a_ip" >/dev/null 2>&1; then
    note "plain tunnel up ($a_ip <-> $b_ip)"
else
    miss "the plain tunnel did not come up; the rest of the test is meaningless"
    exit 1
fi

step "2: switch both nodes to the obfs carrier"
for p in "$A" "$B"; do
    cli "$p" set Transports "plain, obfs" >/dev/null
    cli "$p" set PreferredTransports obfs >/dev/null
done

# phase <label> <KeyExpire of a> <KeyExpire of b>
phase() {
    local label=$1 ke_a=$2 ke_b=$3
    step "$label: KeyExpire a=$ke_a b=$ke_b, ${WINDOW}s of traffic"
    cli "$A" set KeyExpire "$ke_a" >/dev/null
    cli "$B" set KeyExpire "$ke_b" >/dev/null
    # A restart (not a reload) so the carrier and the timers are re-read from
    # a known state, and the log counters below start from zero.
    docker compose -p "$A" restart node >/dev/null
    docker compose -p "$B" restart node >/dev/null
    wait_ready "$A"
    wait_ready "$B"

    local out
    out=$(node "$B" ping -c "$WINDOW" -i 1 -W 2 "$a_ip" 2>&1 || true)
    local loss
    loss=$(printf '%s\n' "$out" | grep -o '[0-9]*% packet loss' | tail -1)
    local ra rb
    ra=$(rekeys "$A"); rb=$(rekeys "$B")
    note "session keys established: a=$ra b=$rb ; $loss"

    [[ $loss == "0% packet loss" ]] || miss "$label: rotation cost traffic ($loss)"
    (( ra > 1 )) || miss "$label: a rotated $ra time(s) in ${WINDOW}s (want > 1)"
    (( rb > 1 )) || miss "$label: b rotated $rb time(s) in ${WINDOW}s (want > 1)"

    for p in "$A" "$B"; do
        if cli "$p" dump connections 2>/dev/null | grep -q 'transport obfs'; then
            note "$p: still on the obfs carrier"
        else
            miss "$label: $p is not on the obfs carrier any more"
        fi
    done
}

phase "3 symmetric" "$REKEY" "$REKEY"
phase "4 asymmetric (a drives, b at 3600)" "$REKEY" 3600

echo
if (( fail )); then
    echo "FAIL: the obfs session key does not rotate as documented"
    exit 1
fi
echo "PASS: obfs session key rotates on both sides, symmetric and one-sided, without losing a packet"

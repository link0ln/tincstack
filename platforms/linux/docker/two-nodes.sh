#!/usr/bin/env bash
# two-nodes.sh -- PLAN.md M6 proof (b), one command, non-interactive:
# two compose projects (<LAB>-a founding, <LAB>-b invitee) on one docker
# network; invite on a, join on b, ping across the tunnel. Exit 0 = the tunnel
# carries traffic both ways. Everything it creates is removed on exit unless
# KEEP=1. Tunables: LAB (project prefix, default wsc), TINCSTACK_TAG (image
# tag, default dev), WAIT (seconds per readiness wait, default 60).
# Bash only (pipefail, [[ ]], arithmetic): `sh two-nodes.sh` would die on
# `set -o pipefail` with dash's "Illegal option", so fail with a clear message
# first. Run it directly or as `bash two-nodes.sh`.
if [ -z "${BASH_VERSION:-}" ]; then
    echo "two-nodes.sh: this script needs bash; run it directly or with 'bash two-nodes.sh' (not 'sh')" >&2
    exit 2
fi
set -euo pipefail
cd "$(dirname "$0")"

LAB=${LAB:-wsc}
WAIT=${WAIT:-60}
A=$LAB-a
B=$LAB-b
export COMPOSE_FILE=docker-compose.yml:compose.lab.yml
export TINCSTACK_LAB_NET=$LAB-lab
export TINCSTACK_TAG=${TINCSTACK_TAG:-dev}

step() { printf '\n== %s\n' "$*"; }
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

# wait_ready <project>: the daemon logged Ready and answers on its control socket.
wait_ready() {
    local deadline=$(( SECONDS + WAIT ))
    until docker compose -p "$1" logs --no-log-prefix node 2>/dev/null | grep -q ' Ready$' \
          && docker compose -p "$1" exec -T node tincstack-cli pid >/dev/null 2>&1; do
        if (( SECONDS >= deadline )); then
            echo "FAIL: $1 not ready within ${WAIT}s; log follows" >&2
            docker compose -p "$1" logs --no-log-prefix node >&2 || true
            return 1
        fi
        sleep 1
    done
}

docker network inspect "$TINCSTACK_LAB_NET" >/dev/null 2>&1 || docker network create "$TINCSTACK_LAB_NET" >/dev/null

step "a: founding node (NODE_NAME=node_a PUBLIC_ADDRESS=$A-node-1 PORT=655)"
COMPOSE_PROJECT_NAME=$A NODE_NAME=node_a PUBLIC_ADDRESS=$A-node-1 PORT=655 \
    docker compose up -d --build --quiet-pull
wait_ready "$A"
docker compose -p "$A" logs --no-log-prefix node | grep -E 'Materialised|Ready|Address ='

step "a: invite node_b"
invitation=$(COMPOSE_PROJECT_NAME=$A ./invite.sh node_b)
echo "invitation: $invitation"
case $invitation in
    "$A-node-1:655/"*) ;;
    *) echo "FAIL: invitation does not carry PUBLIC_ADDRESS:PORT" >&2; exit 1 ;;
esac

step "b: join (PORT=656)"
COMPOSE_PROJECT_NAME=$B PORT=656 INVITE=$invitation docker compose up -d
if ! wait_ready "$B"; then
    echo "FAIL: b did not come up after join; inviter-side log (a) follows" >&2
    docker compose -p "$A" logs --no-log-prefix --since 5m node | grep -vE 'localhost port unix' >&2 || true
    exit 1
fi
docker compose -p "$B" logs --no-log-prefix node | grep -E 'entrypoint|Materialised|Ready|Connect' || true

step "interfaces: addressed by the daemon's built-in tinc-up, no script in the image"
for p in "$A" "$B"; do
    docker compose -p "$p" logs --no-log-prefix node | grep -E 'built-in tinc-up' || {
        echo "FAIL: $p did not log the built-in interface setup" >&2; exit 1; }
    docker compose -p "$p" exec -T node ip -br addr show dev tincstack
    docker compose -p "$p" exec -T node test ! -e /etc/tincstack/tincstack/tinc-up || {
        echo "FAIL: $p has a tinc-up script in its runtime dir" >&2; exit 1; }
done

step "tunnel: b -> a and a -> b"
a_ip=$(docker compose -p "$A" exec -T node tincstack-cli get node_a.Subnet | head -n1)
b_ip=$(docker compose -p "$B" exec -T node tincstack-cli get node_b.Subnet | head -n1)
a_ip=${a_ip%%/*}
b_ip=${b_ip%%/*}
echo "a=$a_ip b=$b_ip"
docker compose -p "$B" exec -T node ping -c 3 -W 2 "$a_ip"
docker compose -p "$A" exec -T node ping -c 3 -W 2 "$b_ip"

step "inviter learned the invitee (hosts.node_b in a's tinc.yaml)"
docker compose -p "$A" exec -T node tincstack-cli get node_b.Ed25519PublicKey

echo
echo "PASS: two-node tunnel up"

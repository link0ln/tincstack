#!/bin/bash
# reload-test.sh -- proof that `tinc reload' in YAML mode no longer bounces
# every meta connection (PLAN.md "Known Issues", observed by stream S).
#
# The stock check in reload_configuration() (net.c) stats
# <confbase>/hosts/<peer> and closes the link when the file is newer than the
# last check. In YAML mode that tree does not exist -- config_fopen()
# materialises the host record as text on every read -- so the stat failed and
# EVERY peer looked changed on EVERY reload. This lab asserts the content
# comparison that replaced it:
#
#   1. b joins a (the two-project lab of two-nodes.sh: <LAB>-a founding,
#      <LAB>-b invitee) and is switched to PreferredTransports [https, plain],
#      so the link runs on a covert carrier;
#   2. three no-op `tinc reload' plus one `tinc set' + reload on b, with a
#      tunnel ping running throughout: no "has been changed", no "Closing
#      connection", the same socket on both ends, 0 % packet loss, and the
#      carrier is still https (stream N's rule, review row L-2);
#   3. a real change to a peer's host record (an extra `Address' line for
#      node_a) followed by a reload DOES terminate that one connection, which
#      then comes back -- again on https, with the tunnel carrying traffic.
#
# Exit 0 = every step held. Everything it creates is removed on exit unless
# KEEP=1. Tunables: LAB (project prefix, default wsp), TINCSTACK_TAG (image
# tag, default dev), WAIT (seconds per wait, default 60).
# Bash only (pipefail, [[ ]], arithmetic); run it directly or as `bash ...'.
if [ -z "${BASH_VERSION:-}" ]; then
    echo "reload-test.sh: this script needs bash; run it directly or with 'bash reload-test.sh' (not 'sh')" >&2
    exit 2
fi
set -euo pipefail
cd "$(dirname "$0")"

LAB=${LAB:-wsp}
WAIT=${WAIT:-60}
A=$LAB-a
B=$LAB-b
export COMPOSE_FILE=docker-compose.yml:compose.lab.yml
export TINCSTACK_LAB_NET=$LAB-lab
export TINCSTACK_TAG=${TINCSTACK_TAG:-dev}

PINGLOG=$(mktemp)
fail=0

step() { printf '\n== %s\n' "$*"; }
miss() { echo "  MISS: $*" >&2; fail=1; }
note() { echo "  $*"; }

cleanup() {
    rm -f "$PINGLOG"
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

node() { docker compose -p "$1" exec -T node "${@:2}"; }
logs() { docker compose -p "$1" logs --no-log-prefix node 2>/dev/null; }

# count <project> <grep -E pattern>
count() { logs "$1" | grep -cE "$2" || true; }

# conn <project> <peer> <field>: a column of `dump connections' for one peer.
# Line layout: <node> at <host> port <p> options <o> socket <s> status <x> transport <c>
conn() { node "$1" tincstack-cli dump connections | awk -v n="$2" '$1 == n { print $'"$3"' }' | head -n1; }
conn_socket()    { conn "$1" "$2" 9; }
conn_transport() { conn "$1" "$2" 13; }

# wait_ready <project>
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

# wait_carrier <project> <peer> <carrier>
wait_carrier() {
    local deadline=$(( SECONDS + WAIT )) got=
    until got=$(conn_transport "$1" "$2" 2>/dev/null || true); [[ $got == "$3" ]]; do
        if (( SECONDS >= deadline )); then
            echo "FAIL: $1 did not reach carrier $3 for $2 within ${WAIT}s (got '${got:-none}')" >&2
            node "$1" tincstack-cli dump connections >&2 || true
            logs "$1" | tail -n 40 >&2 || true
            return 1
        fi
        sleep 1
    done
}

docker network inspect "$TINCSTACK_LAB_NET" >/dev/null 2>&1 || docker network create "$TINCSTACK_LAB_NET" >/dev/null

step "a: founding node"
COMPOSE_PROJECT_NAME=$A NODE_NAME=node_a PUBLIC_ADDRESS=$A-node-1 PORT=655 \
    docker compose up -d --build --quiet-pull
wait_ready "$A"

step "b: join"
invitation=$(COMPOSE_PROJECT_NAME=$A ./invite.sh node_b)
COMPOSE_PROJECT_NAME=$B PORT=656 INVITE=$invitation docker compose up -d
wait_ready "$B"

a_ip=$(node "$A" tincstack-cli get node_a.Subnet | head -n1); a_ip=${a_ip%%/*}
node "$B" ping -c 2 -W 2 "$a_ip" >/dev/null && note "tunnel b -> a ok ($a_ip)"

step "1. b prefers the https carrier (so the reload cases also prove the carrier is kept)"
node "$B" tincstack-cli set PreferredTransports https
node "$B" tincstack-cli add PreferredTransports plain
docker compose -p "$B" restart node >/dev/null
wait_ready "$B"
wait_carrier "$B" node_a https
wait_carrier "$A" node_b https
note "carrier: b->node_a $(conn_transport "$B" node_a), a->node_b $(conn_transport "$A" node_b)"
# The first https dial pins a's TlsFingerprint into b's host record for node_a
# (review M5-7): a write the daemon makes itself, which must not read as an
# operator edit on the next reload either. Wait for it before the baseline.
deadline=$(( SECONDS + WAIT ))
until node "$B" tincstack-cli get node_a.TlsFingerprint >/dev/null 2>&1; do
    (( SECONDS < deadline )) || { miss "b never pinned node_a's TlsFingerprint"; break; }
    sleep 1
done

step "2. three no-op reloads and one \`tinc set' + reload on b, tunnel ping running"
b_changed0=$(count "$B" 'has been changed')
b_closing0=$(count "$B" 'Closing connection with node_a')
a_closing0=$(count "$A" 'Closing connection with node_b')
b_sock0=$(conn_socket "$B" node_a)
a_sock0=$(conn_socket "$A" node_b)
note "before: b closes(node_a)=$b_closing0 changed=$b_changed0 socket=$b_sock0; a closes(node_b)=$a_closing0 socket=$a_sock0"

node "$B" ping -c 30 -i 0.5 -W 2 "$a_ip" > "$PINGLOG" 2>&1 &
ping_pid=$!

for i in 1 2 3; do
    node "$B" tincstack-cli reload
    note "reload $i sent"
    sleep 2
done
node "$B" tincstack-cli set PingInterval 30
node "$B" tincstack-cli reload
note "reload 4 sent (after \`tinc set PingInterval 30')"
sleep 2

wait "$ping_pid" || miss "tunnel ping b -> a failed during the reloads"
loss=$(sed -n 's/.*, \([0-9]*\)% packet loss.*/\1/p' "$PINGLOG" | head -n1)
note "tunnel ping during 4 reloads: ${loss:-?}% packet loss"
[[ ${loss:-100} == 0 ]] || miss "tunnel lost packets during the reloads (${loss:-?}%)"

b_changed1=$(count "$B" 'has been changed')
b_closing1=$(count "$B" 'Closing connection with node_a')
a_closing1=$(count "$A" 'Closing connection with node_b')
b_sock1=$(conn_socket "$B" node_a)
a_sock1=$(conn_socket "$A" node_b)
note "after:  b closes(node_a)=$b_closing1 changed=$b_changed1 socket=$b_sock1; a closes(node_b)=$a_closing1 socket=$a_sock1"

(( b_changed1 == b_changed0 )) || miss "b logged $(( b_changed1 - b_changed0 ))x 'has been changed' on a no-op reload"
(( b_closing1 == b_closing0 )) || miss "b closed the link to node_a $(( b_closing1 - b_closing0 ))x on a no-op reload"
(( a_closing1 == a_closing0 )) || miss "a closed the link to node_b $(( a_closing1 - a_closing0 ))x while b reloaded"
[[ -n $b_sock1 && $b_sock1 == "$b_sock0" ]] || miss "b's connection to node_a was re-established (socket $b_sock0 -> ${b_sock1:-none})"
[[ -n $a_sock1 && $a_sock1 == "$a_sock0" ]] || miss "a's connection to node_b was re-established (socket $a_sock0 -> ${a_sock1:-none})"
[[ $(conn_transport "$B" node_a) == https ]] || miss "b's carrier is no longer https"
[[ $(conn_transport "$A" node_b) == https ]] || miss "a's carrier is no longer https"
(( fail )) || note "PASS: four reloads, links untouched, carrier kept"

step "3. a real change to node_a's host record still terminates that connection"
# A second, equally valid address for a (its lab-network IP) -- a genuine
# change of the record's content that does not break the re-dial.
a_addr=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$TINCSTACK_LAB_NET\").IPAddress}}" "$A-node-1")
note "adding node_a.Address = $a_addr 655 on b"
node "$B" tincstack-cli add node_a.Address "$a_addr" 655
node "$B" tincstack-cli reload

deadline=$(( SECONDS + WAIT ))
until (( $(count "$B" 'Host config file of node_a has been changed') > 0 )); do
    (( SECONDS < deadline )) || { miss "b did not notice the changed host record of node_a"; break; }
    sleep 1
done
logs "$B" | grep -E 'Host config file of node_a has been changed' | tail -n1 || true
(( $(count "$B" 'Closing connection with node_a') > b_closing1 )) || miss "b did not close the connection to node_a after a real change"

wait_carrier "$B" node_a https
wait_carrier "$A" node_b https
b_sock2=$(conn_socket "$B" node_a)
note "reconnected: b socket $b_sock1 -> $b_sock2, carrier $(conn_transport "$B" node_a) (a: $(conn_transport "$A" node_b))"
[[ $b_sock2 != "$b_sock1" ]] || note "(the re-dial reused socket $b_sock2)"
node "$B" ping -c 3 -W 2 "$a_ip" >/dev/null || miss "tunnel b -> a broken after the real change"
n=$(count "$B" 'Host config file of .* has been changed')
(( n == 1 )) || miss "expected exactly one 'has been changed' over the whole run, got $n"

echo
if (( fail )); then
    echo "FAIL: see MISS lines above"
    exit 1
fi
echo "PASS: no-op reloads keep every meta connection and its carrier; a real host-record change still bounces that one link"

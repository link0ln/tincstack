#!/bin/bash
# yaml-scripts.sh -- proof that the `scripts:` stanza of docs/config-schema.md
# is implemented by the daemon (PLAN.md "Found during M9", stream S), on the
# same two-project lab as two-nodes.sh (<LAB>-a founding, <LAB>-b invitee):
#
#   1. b joins a; both interfaces come up through the built-in tinc-up (no
#      scripts.tinc-up given, autoif.c is used);
#   2. a `scripts.host-up` is added to b's tinc.yaml and `tinc reload` is sent:
#      the daemon writes <runtime dir>/host-up (0700) without a restart;
#   3. a is restarted, so node_a goes down and up again on b: the script runs
#      and leaves its marker file;
#   4. a hand-made side file (tinc-down) is left alone across a reload and
#      reported once;
#   5. the `scripts.host-up` key is deleted and b is reloaded: the file is gone,
#      the side file is still there.
#
# Exit 0 = every step held. Everything it creates is removed on exit unless
# KEEP=1. Tunables: LAB (project prefix, default wss), TINCSTACK_TAG (image
# tag, default dev), WAIT (seconds per wait, default 60).
set -euo pipefail
cd "$(dirname "$0")"

LAB=${LAB:-wss}
WAIT=${WAIT:-60}
A=$LAB-a
B=$LAB-b
export COMPOSE_FILE=docker-compose.yml:compose.lab.yml
export TINCSTACK_LAB_NET=$LAB-lab
export TINCSTACK_TAG=${TINCSTACK_TAG:-dev}
RUNDIR=/etc/tincstack/tincstack        # the daemon's runtime dir (NETNAME=tincstack)

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

node() { docker compose -p "$1" exec -T node "${@:2}"; }
logs() { docker compose -p "$1" logs --no-log-prefix node 2>/dev/null; }

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

# wait_log <project> <grep -E pattern> [min count]
wait_log() {
    local deadline=$(( SECONDS + WAIT )) want=${3:-1}
    until (( $(logs "$1" | grep -cE "$2") >= want )); do
        if (( SECONDS >= deadline )); then
            echo "FAIL: $1 did not log /$2/ (x$want) within ${WAIT}s; log follows" >&2
            logs "$1" >&2 || true
            return 1
        fi
        sleep 1
    done
    logs "$1" | grep -E "$2" | tail -n "$want"
}

# wait_file <project> <path>
wait_file() {
    local deadline=$(( SECONDS + WAIT ))
    until node "$1" test -e "$2"; do
        if (( SECONDS >= deadline )); then
            echo "FAIL: $2 did not appear on $1 within ${WAIT}s; log follows" >&2
            logs "$1" >&2 || true
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

step "1. both interfaces via the built-in tinc-up (no scripts.tinc-up in either YAML)"
for p in "$A" "$B"; do
    wait_log "$p" 'built-in tinc-up'
    node "$p" test ! -e $RUNDIR/tinc-up || { echo "FAIL: $p has a tinc-up in $RUNDIR" >&2; exit 1; }
done
a_ip=$(node "$A" tincstack-cli get node_a.Subnet | head -n1); a_ip=${a_ip%%/*}
node "$B" ping -c 2 -W 2 "$a_ip" >/dev/null && echo "tunnel b -> a ok ($a_ip)"

step "2. add scripts.host-up to b's tinc.yaml, reload"
node "$B" test ! -e $RUNDIR/host-up
# shellcheck disable=SC2016  # $NODE/$REMOTEADDRESS are for the daemon's script env
node "$B" sh -c 'cat >> /etc/tincstack/tinc.yaml <<'"'"'YAML'"'"'
    scripts:
      host-up: |
        #!/bin/sh
        # marker: which peer came up and from where
        echo "$NODE $REMOTEADDRESS" > "/etc/tincstack/marker-$NODE"
YAML'
node "$B" tincstack-cli reload
wait_log "$B" "Wrote script \`host-up'"
mode=$(node "$B" stat -c '%a %U' $RUNDIR/host-up)
echo "host-up: mode $mode"
[[ $mode == "700 root" ]] || { echo "FAIL: host-up is not 0700" >&2; exit 1; }
node "$B" test ! -e $RUNDIR/host-up.tmp || { echo "FAIL: temp file left behind" >&2; exit 1; }
node "$B" test ! -e /etc/tincstack/marker-node_a || { echo "FAIL: marker exists before any host-up event" >&2; exit 1; }

step "3. restart a: node_a comes back up on b, host-up runs, marker appears"
docker compose -p "$A" restart node >/dev/null
wait_ready "$A"
wait_file "$B" /etc/tincstack/marker-node_a
echo "marker: $(node "$B" cat /etc/tincstack/marker-node_a)"
# ("Executing script host-up" is a DEBUG_STATUS line; the node runs at -d1, so
# the marker file is the evidence, not the log.)

step "4. a hand-made side file is left alone and reported once"
node "$B" sh -c "printf '#!/bin/sh\nexit 0\n' > $RUNDIR/tinc-down && chmod 700 $RUNDIR/tinc-down"
node "$B" tincstack-cli reload
wait_log "$B" "Script \`$RUNDIR/tinc-down' is a side file"
node "$B" tincstack-cli reload
sleep 2
n=$(logs "$B" | grep -c 'is a side file' || true)
(( n == 1 )) || { echo "FAIL: side file reported $n times, expected once" >&2; exit 1; }
node "$B" test -x $RUNDIR/tinc-down || { echo "FAIL: side file tinc-down was removed" >&2; exit 1; }
# a reload with unchanged content does not rewrite the file
wrote=$(logs "$B" | grep -c "Wrote script \`host-up'" || true)
(( wrote == 1 )) || { echo "FAIL: host-up rewritten on reload without a change ($wrote writes)" >&2; exit 1; }

step "5. delete the scripts.host-up key, reload: the file is removed, the side file stays"
node "$B" sh -c "awk '/^    scripts:/{skip=1; next} skip && (/^    [^ ]/ || /^[^ ]/){skip=0} !skip{print}' /etc/tincstack/tinc.yaml > /etc/tincstack/tinc.yaml.new && mv /etc/tincstack/tinc.yaml.new /etc/tincstack/tinc.yaml && chmod 600 /etc/tincstack/tinc.yaml"
if node "$B" grep -q '^    scripts:' /etc/tincstack/tinc.yaml; then echo "FAIL: scripts block still in the YAML" >&2; exit 1; fi
node "$B" tincstack-cli reload
wait_log "$B" "Removed script \`$RUNDIR/host-up'"
node "$B" test ! -e $RUNDIR/host-up || { echo "FAIL: host-up still on disk" >&2; exit 1; }
node "$B" test -x $RUNDIR/tinc-down || { echo "FAIL: side file tinc-down was removed" >&2; exit 1; }
node "$B" tincstack-cli pid >/dev/null

step "6. tinc set/get/del scripts.<name> (@file), daemon picks it up without an explicit reload"
# The CLI writes into networks.<net>.scripts.<name> under the writers' lock and
# asks the running daemon to reload, so no `tincstack-cli reload' here.
# shellcheck disable=SC2016  # $NODE is for the daemon's script env, not this shell
node "$B" sh -c 'cat > /tmp/host-up.new <<'"'"'SH'"'"'
#!/bin/sh
# set by `tinc set scripts.host-up @file`
echo "$NODE via-cli" > "/etc/tincstack/marker2-$NODE"
SH'
node "$B" tincstack-cli set scripts.host-up @/tmp/host-up.new
wait_log "$B" "Wrote script \`host-up'" 2
mode=$(node "$B" stat -c '%a %U' $RUNDIR/host-up)
[[ $mode == "700 root" ]] || { echo "FAIL: host-up from the CLI is not 0700 ($mode)" >&2; exit 1; }
# get prints exactly what set wrote (the YAML block scalar is chomped and get
# adds the newline back, so this is a byte-for-byte round trip of the file)
node "$B" sh -c 'tinc -n tincstack -c /etc/tincstack/tinc.yaml get scripts.host-up > /tmp/host-up.get \
    && diff -u /tmp/host-up.new /tmp/host-up.get' \
    || { echo "FAIL: get scripts.host-up did not return what set wrote" >&2; exit 1; }
# an inline body is refused, with the @file hint
if err=$(node "$B" tincstack-cli set scripts.host-up '#!/bin/sh' 2>&1); then
    echo "FAIL: an inline script body was accepted" >&2; exit 1
fi
[[ $err == *"read from a file"* ]] || { echo "FAIL: no @file hint in: $err" >&2; exit 1; }
# the script the CLI installed really runs: restart a so node_a comes up again
docker compose -p "$A" restart node >/dev/null
wait_ready "$A"
wait_file "$B" /etc/tincstack/marker2-node_a
echo "marker2: $(node "$B" cat /etc/tincstack/marker2-node_a)"
# del removes the key and the daemon removes the file, again without a reload
node "$B" tincstack-cli del scripts.host-up
wait_log "$B" "Removed script \`$RUNDIR/host-up'" 2
node "$B" test ! -e $RUNDIR/host-up || { echo "FAIL: host-up still on disk after del" >&2; exit 1; }
if node "$B" grep -q 'host-up' /etc/tincstack/tinc.yaml; then echo "FAIL: scripts.host-up still in the YAML" >&2; exit 1; fi
if node "$B" tincstack-cli del scripts.host-up 2>/dev/null; then echo "FAIL: deleting a missing script succeeded" >&2; exit 1; fi
node "$B" test -x $RUNDIR/tinc-down || { echo "FAIL: side file tinc-down was removed" >&2; exit 1; }
node "$B" tincstack-cli pid >/dev/null

echo
echo "PASS: scripts stanza materialised on reload, ran on host-up, removed on key deletion,"
echo "      tinc set/get/del scripts.<name> edits the YAML and the daemon follows"

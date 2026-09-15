#!/bin/bash
# tincstack Linux entrypoint -- a zero-config node.
#
# The daemon configures itself (PLAN.md M1): started against an empty or absent
# tinc.yaml it materialises the network stanza, Name, Mode, Port, AddressPool,
# its own Subnet and the key pairs, then answers `tinc invite`. This script
# therefore never writes configuration text. It only maps the few deploy-time
# choices from the environment into the daemon-owned file and supervises tincd:
#
#   NETNAME         network name (default tincstack)             -> tincd -n
#   NODE_NAME       this node's name; only honoured on the first start (the
#                   daemon derives one from the hostname when unset)
#   PUBLIC_ADDRESS  address[:port] peers reach this node at      -> own host
#                   record `Address`; with it set `tinc invite` neither phones
#                   home nor guesses (PLAN.md Known Issues)
#   PORT            listen port; unset = the daemon's rule (655 for a founding
#                   node, ephemeral for an invitee)
#   INVITE          invitation string: `tinc join` on the first start only
#                   (CONNECT_TO is accepted as an alias)
#   LOG_LEVEL       tincd -d level (default 1)
#
# Values are written with tincstack-yaml, a temporary bridge to be replaced by
# `tinc set` once the CLI is YAML-aware (stream A, M2).
set -euo pipefail

CONFIG_DIR=${TINCSTACK_CONFIG_DIR:-/etc/tincstack}
NETNAME=${NETNAME:-tincstack}
NODE_NAME=${NODE_NAME:-}
PUBLIC_ADDRESS=${PUBLIC_ADDRESS:-}
PORT=${PORT:-}
INVITE=${INVITE:-${CONNECT_TO:-}}
LOG_LEVEL=${LOG_LEVEL:-1}

YAML=$CONFIG_DIR/tinc.yaml
RUNDIR=$CONFIG_DIR/$NETNAME          # the daemon's runtime dir in YAML mode
READY_TIMEOUT=${READY_TIMEOUT:-60}   # seconds to wait for the control socket

log() { printf 'entrypoint: %s\n' "$*" >&2; }
cli() { tinc -n "$NETNAME" -c "$YAML" "$@"; }

if [[ ! -e /dev/net/tun ]]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

mkdir -p "$RUNDIR"   # the CLI re-chmods it to 0755 anyway; secrets are in tinc.yaml (0600)

fresh=0
[[ -s $YAML ]] || fresh=1

# --- first start with an invitation: let the CLI join --------------------
if [[ -n $INVITE ]]; then
    if (( fresh )); then
        log "first start with INVITE: joining"
        if ! cli join "$INVITE"; then
            log "join failed; nothing was kept, fix the invitation and restart"
            # Drop exactly what a failed join leaves behind so the retry is clean.
            rm -rf "$RUNDIR/tinc.conf" "$RUNDIR/hosts" "$RUNDIR/ed25519_key.priv" \
                   "$RUNDIR/rsa_key.priv" "$RUNDIR/invitation-data" "$RUNDIR/tinc-up.invitation"
            sleep 10   # keep `restart: unless-stopped` from hot-looping
            exit 1
        fi
    else
        log "INVITE ignored: $YAML already exists, this node has an identity"
    fi
fi

# --- interface addressing: REMOVABLE once the core sets the tun address itself
# (stream A adds a built-in default). Installed on every start so an image
# update reaches existing volumes; overrides whatever a join wrote there.
install -m 0755 /usr/local/lib/tincstack/tinc-up "$RUNDIR/tinc-up"

# --- deploy-time choices known before the daemon starts --------------------
if [[ -n $NODE_NAME ]]; then
    current=$(tincstack-yaml get "$YAML" "$NETNAME" Name || true)
    if [[ -z $current ]]; then
        tincstack-yaml set "$YAML" "$NETNAME" Name "$NODE_NAME"
        log "Name=$NODE_NAME"
    elif [[ $current != "$NODE_NAME" ]]; then
        log "NODE_NAME=$NODE_NAME ignored: node is already '$current' (renaming would orphan its keys and host record)"
    fi
fi

if [[ -n $PORT ]]; then
    tincstack-yaml set "$YAML" "$NETNAME" Port "$PORT"
fi

# --- run the daemon; it materialises anything still missing ---------------
export TINCSTACK_CONFIG=$YAML   # read by tinc-up
tincd -n "$NETNAME" -c "$YAML" -D -d"$LOG_LEVEL" &
daemon=$!
trap 'kill -TERM "$daemon" 2>/dev/null || true' TERM INT

deadline=$(( SECONDS + READY_TIMEOUT ))
until cli pid >/dev/null 2>&1; do
    if ! kill -0 "$daemon" 2>/dev/null; then
        wait "$daemon" || rc=$?
        log "tincd exited before becoming ready (rc=${rc:-0})"
        exit "${rc:-1}"
    fi
    if (( SECONDS >= deadline )); then
        log "tincd did not open its control socket within ${READY_TIMEOUT}s"
        kill -TERM "$daemon" 2>/dev/null || true
        exit 1
    fi
    sleep 0.5
done

# --- choices that need the materialised identity ---------------------------
# Own host record `Address`: the CLI reads it from the file on every invite,
# the daemon itself does not use it, so a post-start edit is exactly enough.
if [[ -n $PUBLIC_ADDRESS ]]; then
    name=$(tincstack-yaml get "$YAML" "$NETNAME" Name)
    case $PUBLIC_ADDRESS in
        \[*\]:*) address="${PUBLIC_ADDRESS%%\]:*}"; address="${address#\[} ${PUBLIC_ADDRESS##*\]:}" ;;   # [v6]:port
        *:*:*)   address=$PUBLIC_ADDRESS ;;                                                                # bare v6
        *:*)     address="${PUBLIC_ADDRESS%%:*} ${PUBLIC_ADDRESS##*:}" ;;                                  # host:port
        *)       address=$PUBLIC_ADDRESS ;;
    esac
    tincstack-yaml host-set "$YAML" "$NETNAME" "$name" Address "$address"
    log "hosts.$name Address = $address"
fi

rc=0
while kill -0 "$daemon" 2>/dev/null; do
    wait "$daemon" && rc=0 || rc=$?
done
exit "$rc"

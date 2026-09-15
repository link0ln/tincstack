#!/bin/bash
# tincstack Linux entrypoint -- a zero-config node.
#
# The daemon configures itself (PLAN.md M1): started against an empty or absent
# tinc.yaml it materialises the network stanza, Name, Mode, Port, AddressPool,
# its own Subnet and the key pairs, then answers `tinc invite`; it also gives
# the tun interface its address (built-in tinc-up, core/tincd/src/autoif.c).
# This script therefore never writes configuration text. It only maps the few
# deploy-time choices from the environment into the daemon-owned file with the
# YAML-aware CLI (`tinc -c tinc.yaml set`) and supervises tincd:
#
#   NETNAME         network name (default tincstack)             -> tincd -n
#   NODE_NAME       this node's name; only honoured on the first start (the
#                   daemon derives one from the hostname when unset)
#   PUBLIC_ADDRESS  address[:port] peers reach this node at      -> own host
#                   record `Address`; with it set `tinc invite` neither phones
#                   home nor guesses (PLAN.md Known Issues)
#   PORT            listen port; unset = the daemon's rule (655 for a founding
#                   node, ephemeral for an invitee). Stored in the node's own
#                   host record and passed as `tincd -o Port=`: see below.
#   INVITE          invitation string: `tinc join` on the first start only
#                   (CONNECT_TO is accepted as an alias)
#   LOG_LEVEL       tincd -d level (default 1)
#
# PORT: tinc's variable table marks Port host-only, so `tinc set Port` stores
# it in hosts.<Name> while the daemon materialises options.Port with its own
# default; with both present the daemon picks one by line number (conf.c
# config_compare), i.e. arbitrarily (verified: a joined node with `Port = 656`
# in its host record listened on an ephemeral port). Until the core lets
# `tinc set` target options.Port, the same value is therefore also passed as
# a command-line option, which tincd ranks above every file entry (same
# config_compare) -- a documented tincd feature, not a template. The host
# record copy is what `tinc invite` reads (before options), so invitations
# carry the right port; options.Port keeps the materialised default.
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
# A failed join undoes its own writes (the same invitation can be retried).
if [[ -n $INVITE ]]; then
    if (( fresh )); then
        log "first start with INVITE: joining"
        if ! cli join "$INVITE"; then
            log "join failed; nothing was kept, fix the invitation and restart"
            sleep 10   # keep `restart: unless-stopped` from hot-looping
            exit 1
        fi
    else
        log "INVITE ignored: $YAML already exists, this node has an identity"
    fi
fi

# `tinc set` edits a document: it refuses an absent file, while an empty one is
# a valid empty document the daemon materialises into. Not a template.
[[ -e $YAML ]] || install -m 0600 /dev/null "$YAML"

# Images before the core's built-in interface addressing installed a stopgap
# tinc-up into the runtime dir; a leftover one would shadow the built-in.
if [[ -f $RUNDIR/tinc-up ]] && grep -q 'TEMPORARY, REMOVABLE' "$RUNDIR/tinc-up"; then
    rm -f "$RUNDIR/tinc-up"
    log "removed the stopgap tinc-up; the daemon addresses $NETNAME itself"
fi

# --- deploy-time choices --------------------------------------------------
# Name is a server option (options.Name). Port and Address are host
# variables: `tinc set <Name>.<Var>` puts them into hosts.<Name>, so they
# need the name.
name=$(cli get Name 2>/dev/null || true)

if [[ -n $NODE_NAME ]]; then
    if [[ -z $name ]]; then
        cli set Name "$NODE_NAME"
        name=$NODE_NAME
        log "Name=$NODE_NAME"
    elif [[ $name != "$NODE_NAME" ]]; then
        log "NODE_NAME=$NODE_NAME ignored: node is already '$name' (renaming would orphan its keys and host record)"
    fi
fi

address=
if [[ -n $PUBLIC_ADDRESS ]]; then
    case $PUBLIC_ADDRESS in
        \[*\]:*) address="${PUBLIC_ADDRESS%%\]:*}"; address="${address#\[} ${PUBLIC_ADDRESS##*\]:}" ;;   # [v6]:port
        *:*:*)   address=$PUBLIC_ADDRESS ;;                                                                # bare v6
        *:*)     address="${PUBLIC_ADDRESS%%:*} ${PUBLIC_ADDRESS##*:}" ;;                                  # host:port
        *)       address=$PUBLIC_ADDRESS ;;
    esac
fi

# Own host record: `Port` and `Address` are what `tinc invite` reads; the
# daemon itself takes the port from -o Port= (see PORT above). Set before the
# start when the name is known, right after `Ready` otherwise (the running
# daemon is asked to reload by the CLI; nothing here needs that).
set_host_vars() {
    if [[ -n $PORT ]]; then
        cli set "$name.Port" "$PORT"
        log "hosts.$name Port = $PORT"
    fi
    if [[ -n $address ]]; then
        # shellcheck disable=SC2086  # "host port" are two CLI arguments
        cli set "$name.Address" $address
        log "hosts.$name Address = $address"
    fi
}

[[ -z $name ]] || set_host_vars

# --- run the daemon; it materialises anything still missing ---------------
daemon_opts=()
[[ -z $PORT ]] || daemon_opts+=(-o "Port=$PORT")

tincd -n "$NETNAME" -c "$YAML" -D -d"$LOG_LEVEL" "${daemon_opts[@]}" &
daemon=$!
trap 'kill -TERM "$daemon" 2>/dev/null || true' TERM INT

deadline=$(( SECONDS + READY_TIMEOUT ))
until cli pid >/dev/null 2>&1; do
    if ! kill -0 "$daemon" 2>/dev/null; then
        rc=0
        wait "$daemon" || rc=$?
        log "tincd exited before becoming ready (rc=$rc)"
        exit "$(( rc == 0 ? 1 : rc ))"
    fi
    if (( SECONDS >= deadline )); then
        log "tincd did not open its control socket within ${READY_TIMEOUT}s"
        kill -TERM "$daemon" 2>/dev/null || true
        exit 1
    fi
    sleep 0.5
done

# --- choices that needed the materialised identity -------------------------
if [[ -z $name ]]; then
    name=$(cli get Name)
    log "daemon chose Name=$name"
    set_host_vars
fi

rc=0
while kill -0 "$daemon" 2>/dev/null; do
    wait "$daemon" && rc=0 || rc=$?
done
exit "$rc"

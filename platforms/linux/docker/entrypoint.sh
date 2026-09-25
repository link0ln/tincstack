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
#                   node, ephemeral for an invitee). Stored as options.Port,
#                   which the daemon and `tinc invite` both rank first.
#   FRONT_PORT      port of the https (TCP) and quic (UDP) fronts, the port
#                   compose publishes for them; unset = the daemon's default,
#                   443. Stored as options.HttpsPort and options.QuicPort. A
#                   listening node advertises it in its own host record, so it
#                   must be the port peers reach from outside, unless:
#   FRONT_PORT_PUBLIC  the port peers reach the fronts on when a router
#                   forwards another external port to FRONT_PORT. Stored as
#                   options.HttpsPortPublic and options.QuicPortPublic; the
#                   node then advertises this one and still listens on
#                   FRONT_PORT. Like FRONT_PORT, unsetting it later does not
#                   remove the option (`tincstack-cli del HttpsPortPublic`).
#   INVITE         invitation string: `tinc join` on the first start only
#                   (CONNECT_TO is accepted as an alias)
#   LOG_LEVEL       tincd -d level (default 1)
#   CERT_RENEW      1 (default): check periodically whether the ACME certificate
#                   for the https/quic front needs renewing (peers re-pin a
#                   renewed certificate after SPTPS on their own). 0: off
#   CERT_RENEW_INTERVAL  seconds between those checks (default 43200 = 12 h)
#
# PORT: `Port` is a server variable in this core (options.Port, the place
# zeroconf and join write it); the daemon and `tinc invite` rank it above a
# Port line in the host record, so one `tinc set Port` is enough and nothing
# is passed on the command line.
set -euo pipefail

CONFIG_DIR=${TINCSTACK_CONFIG_DIR:-/etc/tincstack}
NETNAME=${NETNAME:-tincstack}
NODE_NAME=${NODE_NAME:-}
PUBLIC_ADDRESS=${PUBLIC_ADDRESS:-}
PORT=${PORT:-}
FRONT_PORT=${FRONT_PORT:-}
FRONT_PORT_PUBLIC=${FRONT_PORT_PUBLIC:-}
INVITE=${INVITE:-${CONNECT_TO:-}}
LOG_LEVEL=${LOG_LEVEL:-1}
CERT_RENEW=${CERT_RENEW:-1}
CERT_RENEW_INTERVAL=${CERT_RENEW_INTERVAL:-43200}

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
# Name and Port are server options (options.Name, options.Port). Address is a
# host variable: `tinc set <Name>.Address` puts it into hosts.<Name>, so it
# needs the name.
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

if [[ -n $PORT ]]; then
    cli set Port "$PORT"
    log "options.Port = $PORT"
fi

if [[ -n $FRONT_PORT ]]; then
    cli set HttpsPort "$FRONT_PORT"
    cli set QuicPort "$FRONT_PORT"
    log "options.HttpsPort = options.QuicPort = $FRONT_PORT"
fi

if [[ -n $FRONT_PORT_PUBLIC ]]; then
    cli set HttpsPortPublic "$FRONT_PORT_PUBLIC"
    cli set QuicPortPublic "$FRONT_PORT_PUBLIC"
    log "options.HttpsPortPublic = options.QuicPortPublic = $FRONT_PORT_PUBLIC"
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

# Own host record: `Address` is what `tinc invite` reads. Set before the
# start when the name is known, right after `Ready` otherwise (the running
# daemon is asked to reload by the CLI; nothing here needs that).
set_host_vars() {
    if [[ -n $address ]]; then
        # shellcheck disable=SC2086  # "host port" are two CLI arguments
        cli set "$name.Address" $address
        log "hosts.$name Address = $address"
    fi
}

[[ -z $name ]] || set_host_vars

# --- run the daemon; it materialises anything still missing ---------------
tincd -n "$NETNAME" -c "$YAML" -D -d"$LOG_LEVEL" &
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

# --- keep the certificate alive -------------------------------------------
# `tinc cert` issues and renews, but nothing runs it: a certificate obtained
# once simply expires ~90 days later, and the https front then presents an
# expired certificate -- which is more remarkable to an observer than the
# self-signed one it replaced. So the node renews itself.
#
# `cert renew` is a no-op while more than AcmeRenewDays remain (it reads the
# stored certificate and returns), so this costs one config read per interval
# until the week it matters. It runs only when ACME is actually configured;
# without CertDomain and CloudflareToken there is nothing to renew.
#
# The first check runs a minute after start, not one interval after it: a node
# restarted more often than CERT_RENEW_INTERVAL would otherwise never check.
renew_loop() {
    local domain token out delay=$(( CERT_RENEW_INTERVAL < 60 ? CERT_RENEW_INTERVAL : 60 ))
    while sleep "$delay"; do
        delay=$CERT_RENEW_INTERVAL
        domain=$(cli get CertDomain 2>/dev/null || true)
        token=$(cli get CloudflareToken 2>/dev/null || true)   # never logged
        [[ -n $domain && -n $token ]] || continue
        if out=$(cli cert renew 2>&1); then
            # The no-op case is the common one; only say something when the
            # certificate actually changed.
            [[ $out == *"nothing to do"* ]] || log "cert renew: ${out//$'\n'/ }"
        else
            log "cert renew failed: ${out//$'\n'/ }"
        fi
    done
}

if [[ $CERT_RENEW != 0 ]]; then
    renew_loop &
    renewer=$!
    trap 'kill -TERM "$daemon" "$renewer" 2>/dev/null || true' TERM INT
fi

rc=0
while kill -0 "$daemon" 2>/dev/null; do
    wait "$daemon" && rc=0 || rc=$?
done
[[ -z ${renewer:-} ]] || kill -TERM "$renewer" 2>/dev/null || true
exit "$rc"

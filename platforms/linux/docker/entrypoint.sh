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
#                   FRONT_PORT. Unsetting it clears the stored public port.
#   OBFS_PORT       UDP port for the obfuscated carrier (default: tinc UDP port);
#                   stored as options.ObfsPort and advertised in the host record.
#   OBFS_PORT_PUBLIC  public port peers reach OBFS_PORT on through a port forward;
#                   stored as options.ObfsPortPublic.
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
OBFS_PORT=${OBFS_PORT:-}
OBFS_PORT_PUBLIC=${OBFS_PORT_PUBLIC:-}
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

ENV_STATE=$RUNDIR/.entrypoint-env

env_state_has() {
    [[ -f $ENV_STATE ]] && grep -qxF "$1" "$ENV_STATE"
}

env_state_add() {
    if ! env_state_has "$1"; then
        printf '%s\n' "$1" >>"$ENV_STATE"
    fi
}

env_state_del() {
    [[ -f $ENV_STATE ]] || return 0
    local tmp=$ENV_STATE.tmp
    grep -vxF "$1" "$ENV_STATE" >"$tmp" || true
    mv -f "$tmp" "$ENV_STATE"
}

valid_port() {
    local p=$1
    [[ $p =~ ^[0-9]+$ ]] && (( 10#$p >= 1 && 10#$p <= 65535 ))
}

valid_port_or_zero() {
    local p=$1
    [[ $p =~ ^[0-9]+$ ]] && (( 10#$p >= 0 && 10#$p <= 65535 ))
}

if [[ -n $PORT ]]; then
    if ! valid_port_or_zero "$PORT"; then
        log "invalid PORT '$PORT': expected integer 0..65535"
        exit 1
    fi
    cli set Port "$PORT"
    env_state_add PORT
    log "options.Port = $PORT"
elif (( ! fresh )) && env_state_has PORT; then
    cur_port=$(cli get Port 2>/dev/null || true)
    cur_ct=$(cli get ConnectTo 2>/dev/null || true)
    default_port=655
    [[ -z $cur_ct ]] || default_port=0
    if [[ -n $cur_port && $cur_port != "$default_port" ]]; then
        cli set Port "$default_port"
        log "PORT unset: reset options.Port from $cur_port to $default_port"
    fi
    env_state_del PORT
fi

if [[ -n $FRONT_PORT ]]; then
    if ! valid_port_or_zero "$FRONT_PORT"; then
        log "invalid FRONT_PORT '$FRONT_PORT': expected integer 0..65535"
        exit 1
    fi
    cli set HttpsPort "$FRONT_PORT"
    cli set QuicPort "$FRONT_PORT"
    env_state_add FRONT_PORT
    log "options.HttpsPort = options.QuicPort = $FRONT_PORT"
elif (( ! fresh )) && env_state_has FRONT_PORT; then
    if [[ -n $(cli get HttpsPort 2>/dev/null || true) || -n $(cli get QuicPort 2>/dev/null || true) ]]; then
        cli del HttpsPort >/dev/null 2>&1 || true
        cli del QuicPort >/dev/null 2>&1 || true
        log "FRONT_PORT unset: cleared env-managed options.HttpsPort / options.QuicPort"
    fi
    env_state_del FRONT_PORT
fi

if [[ -n $FRONT_PORT_PUBLIC ]]; then
    if ! valid_port "$FRONT_PORT_PUBLIC"; then
        log "invalid FRONT_PORT_PUBLIC '$FRONT_PORT_PUBLIC': expected integer 1..65535"
        exit 1
    fi
    cli set HttpsPortPublic "$FRONT_PORT_PUBLIC"
    cli set QuicPortPublic "$FRONT_PORT_PUBLIC"
    env_state_add FRONT_PORT_PUBLIC
    log "options.HttpsPortPublic = options.QuicPortPublic = $FRONT_PORT_PUBLIC"
elif (( ! fresh )) && env_state_has FRONT_PORT_PUBLIC; then
    if [[ -n $(cli get HttpsPortPublic 2>/dev/null || true) || -n $(cli get QuicPortPublic 2>/dev/null || true) ]]; then
        cli del HttpsPortPublic >/dev/null 2>&1 || true
        cli del QuicPortPublic >/dev/null 2>&1 || true
        log "FRONT_PORT_PUBLIC unset: cleared env-managed options.HttpsPortPublic / options.QuicPortPublic"
    fi
    env_state_del FRONT_PORT_PUBLIC
fi

if [[ -n $OBFS_PORT ]]; then
    if ! valid_port_or_zero "$OBFS_PORT"; then
        log "invalid OBFS_PORT '$OBFS_PORT': expected integer 0..65535"
        exit 1
    fi
    cli set ObfsPort "$OBFS_PORT"
    env_state_add OBFS_PORT
    log "options.ObfsPort = $OBFS_PORT (ensure UDP port $OBFS_PORT is published on the host, e.g. via compose.obfs.yml)"
elif (( ! fresh )) && env_state_has OBFS_PORT; then
    if [[ -n $(cli get ObfsPort 2>/dev/null || true) ]]; then
        cli del ObfsPort >/dev/null 2>&1 || true
        log "OBFS_PORT unset: cleared env-managed options.ObfsPort"
    fi
    env_state_del OBFS_PORT
fi

if [[ -n $OBFS_PORT_PUBLIC ]]; then
    if ! valid_port "$OBFS_PORT_PUBLIC"; then
        log "invalid OBFS_PORT_PUBLIC '$OBFS_PORT_PUBLIC': expected integer 1..65535"
        exit 1
    fi
    cli set ObfsPortPublic "$OBFS_PORT_PUBLIC"
    env_state_add OBFS_PORT_PUBLIC
    log "options.ObfsPortPublic = $OBFS_PORT_PUBLIC"
elif (( ! fresh )) && env_state_has OBFS_PORT_PUBLIC; then
    if [[ -n $(cli get ObfsPortPublic 2>/dev/null || true) ]]; then
        cli del ObfsPortPublic >/dev/null 2>&1 || true
        log "OBFS_PORT_PUBLIC unset: cleared env-managed options.ObfsPortPublic"
    fi
    env_state_del OBFS_PORT_PUBLIC
fi

address_args=()
if [[ -n $PUBLIC_ADDRESS ]]; then
    addr_host=
    addr_port=
    case $PUBLIC_ADDRESS in
        \[*\]:*)
            addr_host=${PUBLIC_ADDRESS%%\]:*}
            addr_host=${addr_host#\[}
            addr_port=${PUBLIC_ADDRESS##*\]:}
            if [[ -z $addr_host || -z $addr_port ]] || ! valid_port "$addr_port"; then
                log "invalid PUBLIC_ADDRESS '$PUBLIC_ADDRESS': expected [ipv6]:port with port 1..65535"
                exit 1
            fi
            address_args=("$addr_host" "$addr_port")
            ;;
        \[*\])
            addr_host=${PUBLIC_ADDRESS#\[}
            addr_host=${addr_host%\]}
            if [[ -z $addr_host ]]; then
                log "invalid PUBLIC_ADDRESS '$PUBLIC_ADDRESS': empty bracketed address"
                exit 1
            fi
            address_args=("$addr_host")
            ;;
        *\[* | *\]*)
            log "invalid PUBLIC_ADDRESS '$PUBLIC_ADDRESS': unmatched brackets"
            exit 1
            ;;
        *:*:*)
            address_args=("$PUBLIC_ADDRESS")
            ;;
        *:*)
            addr_host=${PUBLIC_ADDRESS%%:*}
            addr_port=${PUBLIC_ADDRESS##*:}
            if [[ -z $addr_host || -z $addr_port ]] || ! valid_port "$addr_port"; then
                log "invalid PUBLIC_ADDRESS '$PUBLIC_ADDRESS': expected host:port with non-empty host and port 1..65535"
                exit 1
            fi
            address_args=("$addr_host" "$addr_port")
            ;;
        *)
            address_args=("$PUBLIC_ADDRESS")
            ;;
    esac
    if [[ ${address_args[0]} == -* || ${address_args[0]} == *[[:space:]]* ]]; then
        log "invalid PUBLIC_ADDRESS '$PUBLIC_ADDRESS': malformed host '${address_args[0]}'"
        exit 1
    fi
fi

# Own host record: `Address` is what `tinc invite` reads. Set before the
# start when the name is known, right after `Ready` otherwise (the running
# daemon is asked to reload by the CLI; nothing here needs that).
set_host_vars() {
    if (( ${#address_args[@]} > 0 )); then
        cli set "$name.Address" "${address_args[@]}"
        env_state_add PUBLIC_ADDRESS
        log "hosts.$name Address = ${address_args[*]}"
    elif (( ! fresh )) && env_state_has PUBLIC_ADDRESS; then
        if [[ -n $(cli get "$name.Address" 2>/dev/null || true) ]]; then
            cli del "$name.Address" >/dev/null 2>&1 || true
            log "PUBLIC_ADDRESS unset: cleared env-managed hosts.$name Address"
        fi
        env_state_del PUBLIC_ADDRESS
    fi
}

[[ -z $name ]] || set_host_vars

# --- run the daemon; it materialises anything still missing ---------------
sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608 >/dev/null 2>&1 || true
tincd -n "$NETNAME" -c "$YAML" -D -d"$LOG_LEVEL" &
daemon=$!
trap 'kill -TERM "$daemon" 2>/dev/null || true' TERM INT
trap 'kill -HUP "$daemon" 2>/dev/null || true' HUP

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
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$daemon" 2>/dev/null || break
            sleep 0.5
        done
        if kill -0 "$daemon" 2>/dev/null; then
            kill -KILL "$daemon" 2>/dev/null || true
        fi
        wait "$daemon" 2>/dev/null || true
        exit 1
    fi
    sleep 0.5
done

# Raise TUN txqueuelen and sch_fq per-flow packet limit on the TUN device
# (default txqueuelen 500 and fq flow_limit 100p drop bursts under BBR pacing).
iface=$(cli get Interface 2>/dev/null || true)
iface=${iface:-$NETNAME}
ip link set "$iface" txqueuelen 4000 2>/dev/null || true
if command -v tc >/dev/null 2>&1; then
    tc qdisc replace dev "$iface" root fq flow_limit 2000 2>/dev/null || true
fi

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
    local domain token out rc_renew sleep_pid="" renew_pid="" out_file=""
    local delay=$(( CERT_RENEW_INTERVAL < 60 ? CERT_RENEW_INTERVAL : 60 ))
    trap '
        [[ -z $sleep_pid ]] || kill -TERM "$sleep_pid" 2>/dev/null || true
        [[ -z $renew_pid ]] || kill -TERM "$renew_pid" 2>/dev/null || true
        [[ -z $sleep_pid ]] || wait "$sleep_pid" 2>/dev/null || true
        [[ -z $renew_pid ]] || wait "$renew_pid" 2>/dev/null || true
        [[ -z $out_file ]] || rm -f "$out_file"
        exit 0
    ' TERM INT
    while true; do
        sleep "$delay" &
        sleep_pid=$!
        wait "$sleep_pid" || break
        sleep_pid=""
        kill -0 "$daemon" 2>/dev/null || break
        delay=$CERT_RENEW_INTERVAL
        domain=$(cli get CertDomain 2>/dev/null || true)
        token=$(cli get CloudflareToken 2>/dev/null || true)   # never logged
        [[ -n $domain && -n $token ]] || continue
        out_file=$(mktemp "${TMPDIR:-/tmp}/tincstack-renew.XXXXXX")
        cli cert renew >"$out_file" 2>&1 &
        renew_pid=$!
        rc_renew=0
        wait "$renew_pid" || rc_renew=$?
        renew_pid=""
        out=$(cat "$out_file" 2>/dev/null || true)
        rm -f "$out_file"
        out_file=""
        if (( rc_renew == 0 )); then
            # The no-op case is the common one; only say something when the
            # certificate actually changed.
            [[ $out == *"nothing to do"* ]] || log "cert renew: ${out//$'\n'/ }"
        else
            log "cert renew failed: ${out//$'\n'/ }"
        fi
    done
}

if [[ ! $CERT_RENEW_INTERVAL =~ ^-?[0-9]+$ ]]; then
    log "invalid CERT_RENEW_INTERVAL '$CERT_RENEW_INTERVAL': expected integer seconds"
    exit 1
fi

if [[ $CERT_RENEW != 0 ]]; then
    if (( 10#$CERT_RENEW_INTERVAL > 0 )); then
        renew_loop &
        renewer=$!
        trap 'kill -TERM "$daemon" "$renewer" 2>/dev/null || true' TERM INT
    else
        log "CERT_RENEW_INTERVAL=$CERT_RENEW_INTERVAL <= 0: background certificate renewal disabled"
    fi
fi

rc=0
while kill -0 "$daemon" 2>/dev/null; do
    wait "$daemon" && rc=0 || rc=$?
done
if [[ -n ${renewer:-} ]]; then
    kill -TERM "$renewer" 2>/dev/null || true
    wait "$renewer" 2>/dev/null || true
fi
exit "$rc"

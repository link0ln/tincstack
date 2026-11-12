#!/bin/bash
# join.sh <invitation> -- bring this project's node up as a member of an
# existing mesh. Same as `INVITE=<invitation> docker compose up -d`: the
# entrypoint runs `tinc join` on the first start only; a node that already has
# an identity in its data volume ignores the invitation.
#
# With PORT unset the node only dials out (the daemon gives it Port 0 and no
# front), so no host port is published for it: compose.leaf.yml is added to
# COMPOSE_FILE, for this run and in .env for every later `docker compose up`.
# Set PORT (environment or .env) for an invitee that others should dial; it
# then publishes PORT and FRONT_PORT like a founding node.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <invitation-string>" >&2
    exit 64
fi

cd "$(dirname "$0")"

# The value compose would use: the environment first, then .env (stripping CR,
# optional `export`, surrounding quotes, inline `#` comments, and whitespace).
dotenv() {
    local key=$1 line rest val=""
    [[ -f .env ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        line=${line#"${line%%[![:space:]]*}"}
        [[ -z $line || $line == \#* ]] && continue
        if [[ $line == export[[:space:]]* ]]; then
            line=${line#export}
            line=${line#"${line%%[![:space:]]*}"}
        fi
        [[ $line == "$key"* ]] || continue
        rest=${line#"$key"}
        rest=${rest#"${rest%%[![:space:]]*}"}
        [[ $rest == =* ]] || continue
        rest=${rest#=}
        rest=${rest#"${rest%%[![:space:]]*}"}
        if [[ $rest == \"* ]]; then
            rest=${rest#\"}
            val=${rest%%\"*}
        elif [[ $rest == \'* ]]; then
            rest=${rest#\'}
            val=${rest%%\'*}
        else
            val=${rest%%#*}
            val=${val%"${val##*[![:space:]]}"}
        fi
    done < .env
    printf '%s' "$val"
}
valid_port_or_zero() {
    local p=$1
    [[ $p =~ ^[0-9]+$ ]] && (( 10#$p >= 0 && 10#$p <= 65535 ))
}

# Insert `overlay` into a colon-separated COMPOSE_FILE list BEFORE transport
# port overlays (such as compose.obfs.yml), so `!reset` / `!override` on base
# ports never wipes dedicated transport overlays that come after it.
insert_overlay() {
    local list=$1 overlay=$2 drop=${3:-}
    local -a parts=() out=()
    local item inserted=0
    IFS=':' read -r -a parts <<< "$list"
    for item in "${parts[@]}"; do
        [[ -z $item || $item == "$overlay" ]] && continue
        [[ -n $drop && $item == "$drop" ]] && continue
        if (( ! inserted )) && [[ $item == *compose.obfs.yml ]]; then
            out+=("$overlay")
            inserted=1
        fi
        out+=("$item")
    done
    if (( ! inserted )); then
        out+=("$overlay")
    fi
    local IFS=':'
    printf '%s' "${out[*]}"
}

port=${PORT-$(dotenv PORT)}
front_port=${FRONT_PORT-$(dotenv FRONT_PORT)}
obfs_port=${OBFS_PORT-$(dotenv OBFS_PORT)}

for pair in "PORT:$port" "FRONT_PORT:$front_port" "OBFS_PORT:$obfs_port"; do
    k=${pair%%:*}
    v=${pair#*:}
    if [[ -n $v ]] && ! valid_port_or_zero "$v"; then
        echo "join.sh: invalid $k='$v' (expected integer 0..65535)" >&2
        exit 64
    fi
done

had_env=0
env_backup=""
cleanup_backup() {
    [[ -z $env_backup ]] || rm -f "$env_backup"
}
trap cleanup_backup EXIT

write_compose_env() {
    local target_files=$1
    if [[ -f .env ]]; then
        had_env=1
        env_backup=$(mktemp .env.bak.XXXXXX)
        cp -p .env "$env_backup"
        (
            umask 077
            rm -f .env.tmp
            grep -Ev '^[[:space:]]*(export[[:space:]]+)?COMPOSE_FILE[[:space:]]*=' .env > .env.tmp || true
            chmod --reference=.env .env.tmp 2>/dev/null || chmod 0600 .env.tmp
            if [[ -s .env.tmp && -n "$(tail -c 1 .env.tmp)" ]]; then
                printf '\n' >> .env.tmp
            fi
            printf 'COMPOSE_FILE=%s\n' "$target_files" >> .env.tmp
            mv -f .env.tmp .env
        )
    else
        had_env=0
        (
            umask 077
            printf 'COMPOSE_FILE=%s\n' "$target_files" > .env.tmp
            chmod 0600 .env.tmp
            mv -f .env.tmp .env
        )
    fi
}

rollback_compose_env() {
    if (( had_env )) && [[ -n $env_backup && -f $env_backup ]]; then
        mv -f "$env_backup" .env
        env_backup=""
    elif (( ! had_env )); then
        rm -f .env
    fi
}

updated_env=0
if [[ -z $port || $port == 0 ]]; then
    files=${COMPOSE_FILE:-$(dotenv COMPOSE_FILE)}
    files=${files:-docker-compose.yml}
    files=$(insert_overlay "$files" "compose.leaf.yml" "compose.nofront.yml")
    write_compose_env "$files"
    updated_env=1
    echo "join.sh: PORT unset/0, this node only dials out: no base host ports published (COMPOSE_FILE=$files, kept in .env)" >&2
    if [[ -n ${COMPOSE_FILE:-} && ${COMPOSE_FILE} != "$files" ]]; then
        echo "join.sh: COMPOSE_FILE is exported in this shell and overrides .env; update COMPOSE_FILE=$files for later runs" >&2
    fi
    export COMPOSE_FILE=$files
elif [[ $front_port == 0 ]]; then
    files=${COMPOSE_FILE:-$(dotenv COMPOSE_FILE)}
    files=${files:-docker-compose.yml}
    files=$(insert_overlay "$files" "compose.nofront.yml" "compose.leaf.yml")
    write_compose_env "$files"
    updated_env=1
    echo "join.sh: FRONT_PORT=0 with PORT=$port: front ports disabled (COMPOSE_FILE=$files, kept in .env)" >&2
    if [[ -n ${COMPOSE_FILE:-} && ${COMPOSE_FILE} != "$files" ]]; then
        echo "join.sh: COMPOSE_FILE is exported in this shell and overrides .env; update COMPOSE_FILE=$files for later runs" >&2
    fi
    export COMPOSE_FILE=$files
fi

rc=0
INVITE=$1 docker compose up -d || rc=$?
if (( rc != 0 )); then
    if (( updated_env )); then
        rollback_compose_env
    fi
    exit "$rc"
fi

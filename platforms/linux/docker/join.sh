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
port=${PORT-$(dotenv PORT)}

if [[ -z $port || $port == 0 ]]; then
    files=${COMPOSE_FILE:-$(dotenv COMPOSE_FILE)}
    files=${files:-docker-compose.yml}
    case ":$files:" in
        *:compose.leaf.yml:*) ;;
        *) files=$files:compose.leaf.yml ;;
    esac
    if [[ -f .env ]]; then
        (
            umask 077
            rm -f .env.tmp
            grep -Ev '^[[:space:]]*(export[[:space:]]+)?COMPOSE_FILE[[:space:]]*=' .env > .env.tmp || true
            chmod --reference=.env .env.tmp 2>/dev/null || chmod 0600 .env.tmp
            if [[ -s .env.tmp && -n "$(tail -c 1 .env.tmp)" ]]; then
                printf '\n' >> .env.tmp
            fi
            printf 'COMPOSE_FILE=%s\n' "$files" >> .env.tmp
            mv -f .env.tmp .env
        )
    else
        (
            umask 077
            printf 'COMPOSE_FILE=%s\n' "$files" > .env.tmp
            chmod 0600 .env.tmp
            mv -f .env.tmp .env
        )
    fi
    echo "join.sh: PORT unset, this node only dials out: no host ports published (COMPOSE_FILE=$files, kept in .env)" >&2
    if [[ -n ${COMPOSE_FILE:-} && ${COMPOSE_FILE} != "$files" ]]; then
        echo "join.sh: COMPOSE_FILE is exported in this shell and overrides .env; add :compose.leaf.yml to it for later runs" >&2
    fi
    export COMPOSE_FILE=$files
fi

INVITE=$1 exec docker compose up -d

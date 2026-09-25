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

# The value compose would use: the environment first, then .env.
dotenv() { [[ ! -f .env ]] || sed -n "s/^$1=//p" .env | tail -n 1; }
port=${PORT-$(dotenv PORT)}

if [[ -z $port ]]; then
    files=${COMPOSE_FILE:-$(dotenv COMPOSE_FILE)}
    files=${files:-docker-compose.yml}
    case ":$files:" in
        *:compose.leaf.yml:*) ;;
        *) files=$files:compose.leaf.yml ;;
    esac
    if [[ -f .env ]] && grep -q '^COMPOSE_FILE=' .env; then
        sed -i "s|^COMPOSE_FILE=.*|COMPOSE_FILE=$files|" .env
    else
        [[ ! -s .env || -z $(tail -c 1 .env) ]] || echo >> .env
        printf 'COMPOSE_FILE=%s\n' "$files" >> .env
    fi
    echo "join.sh: PORT unset, this node only dials out: no host ports published (COMPOSE_FILE=$files, kept in .env)" >&2
    if [[ -n ${COMPOSE_FILE:-} && ${COMPOSE_FILE} != "$files" ]]; then
        echo "join.sh: COMPOSE_FILE is exported in this shell and overrides .env; add :compose.leaf.yml to it for later runs" >&2
    fi
    export COMPOSE_FILE=$files
fi

INVITE=$1 exec docker compose up -d

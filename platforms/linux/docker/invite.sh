#!/bin/bash
# invite.sh <name> -- issue a one-line invitation for a new node from this
# project's running node. Prints the invitation on stdout; hand it to the other
# host's join.sh. Honours COMPOSE_PROJECT_NAME / COMPOSE_FILE / -p like compose.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <new-node-name>" >&2
    exit 64
fi

cd "$(dirname "$0")"
exec docker compose exec -T node tincstack-cli invite "$1"

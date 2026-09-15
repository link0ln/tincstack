#!/bin/bash
# join.sh <invitation> -- bring this project's node up as a member of an
# existing mesh. Same as `INVITE=<invitation> docker compose up -d`: the
# entrypoint runs `tinc join` on the first start only; a node that already has
# an identity in its data volume ignores the invitation.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <invitation-string>" >&2
    exit 64
fi

cd "$(dirname "$0")"
INVITE=$1 exec docker compose up -d

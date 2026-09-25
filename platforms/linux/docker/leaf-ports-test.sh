#!/usr/bin/env bash
# leaf-ports-test.sh -- an invitee that only dials out publishes no host port.
#
# docker-compose.yml publishes PORT (655) and FRONT_PORT (443) tcp+udp. Until
# compose.leaf.yml, an invitee published them too, although it listens on
# neither: `compose up' then failed on any host where a web server holds 443.
# Now join.sh adds compose.leaf.yml when PORT is unset and keeps it in .env.
#
#   * the host port the invitee would have published is held by another
#     container (the web server);
#   * control: a plain `INVITE=... docker compose up' of the invitee fails on
#     it ("port is already allocated") -- the defect;
#   * join.sh brings the same invitee up, with no published port, and it
#     reaches the founder;
#   * a later plain `docker compose up -d' keeps it that way (.env);
#   * the founder still publishes PORT and FRONT_PORT.
#
# The compose files are run from a copy of this directory, so the .env that
# join.sh writes never touches the checkout. Images: tincstack/core at
# TINCSTACK_TAG must exist; tincstack/node at that tag is (re)built from it.
# Host ports used: 26655, 28443, 28444 (PORT_BASE shifts them).
#
# Usage: [TINCSTACK_TAG=dev] [LAB=wwl] platforms/linux/docker/leaf-ports-test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB=${LAB:-wwl}
WAIT=${WAIT:-60}
export TINCSTACK_TAG=${TINCSTACK_TAG:-dev}
BASE=${PORT_BASE:-0}
F_PORT=$((26655 + BASE))       # founder: tinc port
F_FRONT=$((28444 + BASE))      # founder: fronts
WEB=$((28443 + BASE))          # the "web server" on the invitee's host
NET=$LAB-lab
T=
FAILED=0

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

# By label, so that it also clears what a killed earlier run left behind.
cleanup() {
	local p ids
	for p in a b c; do
		ids=$(docker ps -aq --filter "label=com.docker.compose.project=$LAB-$p")
		# shellcheck disable=SC2086  # one id per word
		[[ -z $ids ]] || docker rm -f $ids >/dev/null 2>&1 || true
		docker volume rm "$LAB-${p}_data" >/dev/null 2>&1 || true
	done
	docker rm -f "$LAB-web" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	[[ -z $T ]] || rm -rf "$T"
}
trap cleanup EXIT
cleanup
T=$(mktemp -d)

cp "$HERE/docker-compose.yml" "$HERE/compose.leaf.yml" "$HERE/join.sh" "$HERE/invite.sh" "$T/"
# The same lab bridge for every project, ports untouched (compose.lab.yml
# would reset them, which is what is being tested).
cat > "$T/compose.net.yml" <<EOF
services:
  node:
    networks: [lab]
networks:
  lab:
    name: $NET
    external: true
EOF
docker network create "$NET" >/dev/null

# The node image from this checkout's entrypoint on top of the given core.
docker build -q --build-arg CORE_IMAGE="tincstack/core:$TINCSTACK_TAG" -t "tincstack/node:$TINCSTACK_TAG" "$HERE" >/dev/null

published() { # <project>: the node container's published host ports, sorted
	docker port "$(cd "$T" && docker compose -p "$1" ps -q node)" 2>/dev/null | sed 's/.*://' | sort -u | tr '\n' ' '
}
ready() { # <project>
	local deadline=$((SECONDS + WAIT))
	until (cd "$T" && docker compose -p "$1" exec -T node tincstack-cli pid) >/dev/null 2>&1; do
		((SECONDS < deadline)) || { log "$1 never came up"; (cd "$T" && docker compose -p "$1" logs --no-log-prefix node | tail -20) >&2; return 1; }
		sleep 1
	done
}

# ---- the founder publishes as before ------------------------------------------------------
(cd "$T" && COMPOSE_FILE=docker-compose.yml:compose.net.yml COMPOSE_PROJECT_NAME=$LAB-a NODE_NAME=node_a \
	PUBLIC_ADDRESS=$LAB-a-node-1 PORT=$F_PORT FRONT_PORT=$F_FRONT docker compose up -d --quiet-pull) >&2
ready "$LAB-a"
got=$(published "$LAB-a")
if [[ $got == "$F_PORT $F_FRONT " ]]; then
	ok "the founder publishes PORT and FRONT_PORT ($got)"
else
	bad "the founder publishes PORT and FRONT_PORT (got '$got')"
fi

# ---- a web server holds the invitee's front port on the host ------------------------------
docker run -d --name "$LAB-web" -p "$WEB:80/tcp" -p "$WEB:80/udp" "tincstack/core:$TINCSTACK_TAG" sleep infinity >/dev/null

# Control: what an invitee did before compose.leaf.yml. (PORT is only given a
# free host port here so that the web server's port is the one in the way;
# the default 655 was published for an invitee just the same.)
inv=$(cd "$T" && COMPOSE_FILE=docker-compose.yml:compose.net.yml COMPOSE_PROJECT_NAME=$LAB-a ./invite.sh node_c)
if (cd "$T" && COMPOSE_FILE=docker-compose.yml:compose.net.yml COMPOSE_PROJECT_NAME=$LAB-c FRONT_PORT=$WEB \
	PORT=$((F_PORT + 1)) INVITE=$inv docker compose up -d) > "$T/control.log" 2>&1; then
	bad "control: an invitee publishing FRONT_PORT fails on the taken host port (it came up)"
elif grep -qiE ":$WEB.*(already allocated|address already in use)" "$T/control.log"; then
	ok "control: an invitee publishing FRONT_PORT fails on the taken host port ($(grep -oiE "[^ ]*:$WEB.*(already allocated|address already in use)" "$T/control.log" | head -1))"
else
	bad "control: an invitee publishing FRONT_PORT fails on the taken host port (other error)"
	tail -5 "$T/control.log" >&2
fi

# ---- join.sh: the same invitee, no published port -----------------------------------------
inv=$(cd "$T" && COMPOSE_FILE=docker-compose.yml:compose.net.yml COMPOSE_PROJECT_NAME=$LAB-a ./invite.sh node_b)
if (cd "$T" && env -u PORT COMPOSE_FILE=docker-compose.yml:compose.net.yml COMPOSE_PROJECT_NAME="$LAB-b" FRONT_PORT="$WEB" \
	./join.sh "$inv") > "$T/join.log" 2>&1 && ready "$LAB-b"; then
	ok "join.sh brings the invitee up although the host port is taken"
else
	bad "join.sh brings the invitee up although the host port is taken"
	tail -8 "$T/join.log" >&2
fi
got=$(published "$LAB-b")
if [[ -z $got ]]; then
	ok "... and publishes no host port"
else
	bad "... and publishes no host port (got '$got')"
fi
if grep -qx "COMPOSE_FILE=docker-compose.yml:compose.net.yml:compose.leaf.yml" "$T/.env" 2>/dev/null; then
	ok "... and keeps compose.leaf.yml in .env"
else
	bad "... and keeps compose.leaf.yml in .env ($(cat "$T/.env" 2>&1))"
fi
for _ in $(seq "$WAIT"); do
	(cd "$T" && docker compose -p "$LAB-b" exec -T node tincstack-cli dump connections) 2>/dev/null | grep -q "^node_a " && break
	sleep 1
done
if (cd "$T" && docker compose -p "$LAB-b" exec -T node tincstack-cli dump connections) 2>/dev/null | grep -q "^node_a "; then
	ok "... and reaches the founder"
else
	bad "... and reaches the founder"
fi

# ---- a later plain `docker compose up' reads .env ---------------------------------------------
(cd "$T" && env -u COMPOSE_FILE -u PORT COMPOSE_PROJECT_NAME="$LAB-b" FRONT_PORT="$WEB" docker compose up -d --force-recreate) > "$T/up2.log" 2>&1 || true
if ready "$LAB-b" && [[ -z $(published "$LAB-b") ]]; then
	ok "a later plain 'docker compose up -d' keeps the invitee unpublished"
else
	bad "a later plain 'docker compose up -d' keeps the invitee unpublished ($(published "$LAB-b"))"
	tail -5 "$T/up2.log" >&2
fi

if [[ $FAILED -eq 0 ]]; then
	log "leaf ports: all checks passed"
else
	log "leaf ports: FAILURES above"
fi
exit "$FAILED"

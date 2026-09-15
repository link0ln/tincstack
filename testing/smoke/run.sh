#!/usr/bin/env bash
# Two-node docker compose smoke test (used by `make check`).
# Generates keys + explicit tinc.yaml files for node1/node2 at run time (under
# ./run/, git-ignored), brings both up with the core image in YAML mode and
# asserts a ping across the tunnel in both directions. Exit 0 = pass.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CORE_IMAGE="${CORE_IMAGE:-tincstack/core:${WSF_TAG:-ws-f}}"
NET=smoke
RUN="$HERE/run"
compose() { docker compose -f "$HERE/compose.yml" "$@"; }
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

cleanup() { compose down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$RUN"; }
cleanup
trap cleanup EXIT
mkdir -p "$RUN"

# gen NAME LAN_IP VPN_IP [extra option lines]
gen() {
    local name="$1" lan="$2" vpn="$3"; shift 3
    local tmp="$RUN/keys-$name" d="$RUN/$name"
    mkdir -p "$tmp/hosts" "$d/$NET"
    printf 'Name = %s\n' "$name" > "$tmp/tinc.conf"
    docker run --rm -v "$tmp:/k" "$CORE_IMAGE" tinc -c /k generate-keys >/dev/null 2>&1
    # host record: Address/Port/Subnet + the public keys tinc appended
    { printf 'Address = %s\nPort = 655\nSubnet = %s/32\n' "$lan" "$vpn"; cat "$tmp/hosts/$name"; } > "$RUN/host-$name.txt"
    {
        echo "networks:"
        echo "  $NET:"
        echo "    options:"
        echo "      Name: $name"
        echo "      Mode: router"
        echo "      Port: 655"
        echo "      AddressFamily: ipv4"
        echo "      UDPDiscoveryBurst: 5"
        for l in "$@"; do echo "      $l"; done
        echo "    keys:"
        echo "      ed25519_priv: |"; sed 's/^/        /' "$tmp/ed25519_key.priv"
        echo "      rsa_priv: |"; sed 's/^/        /' "$tmp/rsa_key.priv"
    } > "$d/tinc.yaml"
    # tinc-up lives next to the YAML as <dir>/<netname>/tinc-up (the daemon's
    # side-file directory in YAML mode; the schema's scripts: stanza is not
    # implemented by yamlconf.c yet — see PLAN.md "Found during M9").
    # shellcheck disable=SC2016  # $INTERFACE is expanded by tincd, not here
    printf '#!/bin/sh\nip link set "$INTERFACE" up\nip addr add %s/24 dev "$INTERFACE"\n' "$vpn" > "$d/$NET/tinc-up"
    chmod +x "$d/$NET/tinc-up"
    rm -rf "$tmp"
}
gen node1 172.31.77.11 10.79.0.1
gen node2 172.31.77.12 10.79.0.2 "ConnectTo: [node1]"
for n in node1 node2; do
    { echo "    hosts:"
      for m in node1 node2; do echo "      $m: |"; sed 's/^/        /' "$RUN/host-$m.txt"; done
    } >> "$RUN/$n/tinc.yaml"
done
rm -f "$RUN"/host-*.txt

compose up -d >/dev/null 2>&1 || { compose logs; exit 1; }
ok=0
for _ in $(seq 1 30); do
    if compose exec -T node1 ping -c 1 -W 1 10.79.0.2 >/dev/null 2>&1 \
       && compose exec -T node2 ping -c 1 -W 1 10.79.0.1 >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
done
compose exec -T node1 ping -c 3 -W 2 10.79.0.2 || true
compose exec -T node2 tinc -c /etc/tincstack/tinc.yaml info node1 || true
if [ "$ok" -eq 1 ]; then
    log "smoke: PASS (cross-node ping both ways, YAML mode, $CORE_IMAGE)"
else
    log "smoke: FAIL"; compose logs; exit 1
fi

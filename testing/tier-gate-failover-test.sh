#!/usr/bin/env bash
# tier-gate-failover-test.sh -- Authoritative TierGate priority admission,
# <=10s blackhole failover, BGP-style anti-flap dampening, and make-before-break
# failback end-to-end verification in Docker.
#
# Topology (mirrors production router -> ruvds3 -> euvds):
#   ruvds3 (172.30.97.11, VPN 10.197.0.1, ConnectTo: euvds, PeerTier=2 on euvds)
#   euvds  (172.30.97.12, VPN 10.197.0.2, TierGate: yes, TierHoldBase: 20, IndirectData: yes)
#   client (172.30.97.13, VPN 10.197.0.3, ConnectTo: ruvds3, FallbackConnectTo: euvds)
#   probe1 (172.30.97.14, VPN 10.197.0.4, ConnectTo: euvds -> tier=1 probe for rejection check)
set -euo pipefail

IMG=${1:-${CORE_IMAGE:-tincstack/core:${WSF_TAG:-ws-f}}}
PFX=tgtest
NET=${PFX}net
SUBNET=${SUBNET:-10.42.97}
BASE=/tmp/${PFX}

RUVDS_IP=$SUBNET.11
EUVDS_IP=$SUBNET.12
CLIENT_IP=$SUBNET.13
PROBE_IP=$SUBNET.14

RUVDS_VPN=10.197.0.1
EUVDS_VPN=10.197.0.2
CLIENT_VPN=10.197.0.3
PROBE_VPN=10.197.0.4

BG_PING_PID=""

cleanup() {
	if [ -n "$BG_PING_PID" ]; then
		kill "$BG_PING_PID" >/dev/null 2>&1 || true
		wait "$BG_PING_PID" 2>/dev/null || true
	fi
	docker rm -f "$PFX-ruvds3" "$PFX-euvds" "$PFX-client" "$PFX-probe1" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	if docker image inspect "$IMG" >/dev/null 2>&1; then
		docker run --rm -v /tmp:/hosttmp "$IMG" rm -rf "/hosttmp/${PFX}-ruvds3" "/hosttmp/${PFX}-euvds" "/hosttmp/${PFX}-client" "/hosttmp/${PFX}-probe1" >/dev/null 2>&1 || true
	fi
	rm -rf "$BASE-ruvds3" "$BASE-euvds" "$BASE-client" "$BASE-probe1" "$BASE-bg-ping.log" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

mkdir -p "$BASE-ruvds3" "$BASE-euvds" "$BASE-client" "$BASE-probe1"
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

fail=0
pass_count=0
note() { printf '  [PASS] %s\n' "$1"; pass_count=$((pass_count + 1)); }
miss() { printf '  [FAIL] %s\n' "$1"; fail=1; }

write_base_yaml() {
	local dir="$1" name="$2" extra="$3"
	cat > "$dir/tinc.yaml" <<EOF
networks:
  tg:
    options:
      Name: $name
      Mode: router
      Port: 655
      HttpsPort: 0
      QuicPort: 0
      AutoConnect: no
      PingInterval: 5
      PingTimeout: 3
      MaxTimeout: 5
      AddressFamily: ipv4
      AddressPool: 10.197.0.0/24
      PreferredTransports: [obfs, plain]
$extra
EOF
}

write_base_yaml "$BASE-ruvds3" "ruvds3" "      ConnectTo: euvds"
write_base_yaml "$BASE-euvds" "euvds" "      TierGate: yes
      TierHoldBase: 20
      IndirectData: yes"
write_base_yaml "$BASE-client" "client" "      ConnectTo: ruvds3
      FallbackConnectTo: euvds"
write_base_yaml "$BASE-probe1" "probe1" "      ConnectTo: euvds"

for d in ruvds3 euvds client probe1; do
	timeout 4 docker run --rm -v "$BASE-$d":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n tg -D -d1 >/dev/null 2>&1 || true
done

python3 - "$BASE" "$RUVDS_IP" "$EUVDS_IP" "$CLIENT_IP" "$PROBE_IP" \
	"$RUVDS_VPN" "$EUVDS_VPN" "$CLIENT_VPN" "$PROBE_VPN" <<'PYEOF'
import re
import sys

base, r_ip, e_ip, c_ip, p_ip, r_vpn, e_vpn, c_vpn, p_vpn = sys.argv[1:10]
nodes = {
    "ruvds3": (f"{base}-ruvds3/tinc.yaml", r_ip, r_vpn),
    "euvds": (f"{base}-euvds/tinc.yaml", e_ip, e_vpn),
    "client": (f"{base}-client/tinc.yaml", c_ip, c_vpn),
    "probe1": (f"{base}-probe1/tinc.yaml", p_ip, p_vpn),
}

def extract_host(path: str, name: str) -> list[str]:
    text = open(path, encoding="utf-8").read()
    m = re.search(r"^      %s: \|\n((?:        .*\n)+)" % re.escape(name), text, re.M)
    if not m:
        raise RuntimeError(f"missing host block {name} in {path}")
    return [line[8:] for line in m.group(1).splitlines() if line.strip()]

records: dict[str, list[str]] = {}
for name, (path, ip, vpn) in nodes.items():
    lines = [
        f"Address = {ip}",
        "Port = 655",
        f"Subnet = {vpn}/32",
    ] + [l for l in extract_host(path, name) if not l.startswith(("Address", "Port", "Subnet"))]
    records[name] = lines

    text = open(path, encoding="utf-8").read()
    text = re.sub(
        r"(      %s: \|\n(?:        .*\n)*?        Subnet = )[^\n]+" % re.escape(name),
        lambda m: m.group(1) + f"{vpn}/32",
        text,
    )
    script = (
        "    scripts:\n"
        "      tinc-up: |\n"
        "        #!/bin/sh\n"
        "        ip link set \"$INTERFACE\" up\n"
        f"        ip addr add {vpn}/24 dev \"$INTERFACE\"\n"
    )
    open(path, "w", encoding="utf-8").write(text + script)

def inject(path: str, peer: str, lines: list[str], extra: list[str] | None = None) -> None:
    text = open(path, encoding="utf-8").read()
    block = "".join(f"        {l}\n" for l in (lines + (extra or [])))
    text = text.replace("    hosts:\n", f"    hosts:\n      {peer}: |\n{block}", 1)
    open(path, "w", encoding="utf-8").write(text)

# ruvds3 <-> euvds, client, probe1
inject(nodes["ruvds3"][0], "euvds", records["euvds"])
inject(nodes["ruvds3"][0], "client", records["client"])

# euvds knows ruvds3 (PeerTier = 2), client (default tier 1), and probe1 (default tier 1)
inject(nodes["euvds"][0], "ruvds3", records["ruvds3"], ["PeerTier = 2"])
inject(nodes["euvds"][0], "client", records["client"])
inject(nodes["euvds"][0], "probe1", records["probe1"])

# client knows ruvds3 (ConnectTo) and euvds (FallbackConnectTo + IndirectData)
inject(nodes["client"][0], "ruvds3", records["ruvds3"])
inject(nodes["client"][0], "euvds", records["euvds"])

# probe1 only knows euvds (used to prove tier-1 direct dial refusal while ruvds3 is healthy)
inject(nodes["probe1"][0], "euvds", records["euvds"])
PYEOF

start_node() {
	local role="$1" ip="$2"
	docker run -d --name "${PFX}-${role}" --network "$NET" --ip "$ip" \
		--cap-add NET_ADMIN --device /dev/net/tun \
		-v "${BASE}-${role}":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n tg -D -d2 >/dev/null
}

doc_json() {
	docker exec "${PFX}-$1" tinc -c /etc/tincstack/tinc.yaml -n tg doctor --json 2>/dev/null || echo "{}"
}

json_field() {
	python3 -c 'import json,sys; d=json.loads(sys.argv[1] or "{}"); k=sys.argv[2]; print(d.get(k, ""))' "$1" "$2" 2>/dev/null || true
}

peer_field() {
	python3 -c 'import json,sys
d=json.loads(sys.argv[1] or "{}")
for p in d.get("peers") or []:
    if p.get("name")==sys.argv[2]:
        print(p.get(sys.argv[3], ""))
        break' "$1" "$2" "$3" 2>/dev/null || true
}

echo "===== Test 1: Normal Tier-2 Admission & Direct Tier-1 Refusal ====="
start_node euvds "$EUVDS_IP"
start_node ruvds3 "$RUVDS_IP"
start_node client "$CLIENT_IP"

up=0
for _ in $(seq 1 20); do
	if docker exec "$PFX-client" ping -c1 -W1 "$EUVDS_VPN" >/dev/null 2>&1; then
		up=1
		break
	fi
	sleep 1
done

if [ "$up" -eq 1 ]; then
	note "Baseline mesh converged: client reaches euvds ($EUVDS_VPN)"
else
	miss "Baseline mesh failed to converge within 20s"
fi

c_nodes=$(docker exec "$PFX-client" tinc -c /etc/tincstack/tinc.yaml -n tg dump nodes 2>/dev/null || true)
e_conns=$(docker exec "$PFX-euvds" tinc -c /etc/tincstack/tinc.yaml -n tg dump connections 2>/dev/null || true)
e_doc=$(doc_json euvds)

if echo "$c_nodes" | grep "^euvds " | grep -Eq "nexthop ruvds3 .*distance 2" && ! echo "$e_conns" | grep -q "^client "; then
	note "Traffic forces client -> ruvds3 -> euvds (distance=2, no direct client<->euvds link)"
else
	miss "Unexpected baseline routing: client_euvds=$(echo "$c_nodes" | grep "^euvds " || true); e_conns=$e_conns"
fi

if [ "$(json_field "$e_doc" tier_gate)" = "True" ] && [ "$(json_field "$e_doc" active_tier)" = "2" ] && [ "$(json_field "$e_doc" tier_state)" = "normal" ]; then
	note "euvds doctor reports tier_gate=true active_tier=2 state=normal"
else
	miss "euvds doctor state unexpected: $e_doc"
fi

# Start transient Tier-1 probe attempting direct ConnectTo euvds while ruvds3 is healthy
start_node probe1 "$PROBE_IP"
rej_ok=0
for _ in $(seq 1 10); do
	sleep 1
	e_doc=$(doc_json euvds)
	rej=$(json_field "$e_doc" tier_rejects)
	if [ "${rej:-0}" -ge 1 ]; then
		rej_ok=1
		break
	fi
done
p_conns=$(docker exec "$PFX-probe1" tinc -c /etc/tincstack/tinc.yaml -n tg dump connections 2>/dev/null || true)
docker rm -f "$PFX-probe1" >/dev/null 2>&1 || true

if [ "$rej_ok" -eq 1 ] && ! echo "$p_conns" | grep -q "edges"; then
	note "TierGate refused Tier-1 direct connection (tier_rejects=$rej) while ruvds3 healthy"
else
	miss "TierGate did not refuse Tier-1 direct peer (rej=$rej_ok, p_conns=$p_conns)"
fi

echo "===== Test 2: <=10s Blackhole Failover on ruvds3 Outage ====="
t0=$(date +%s)
docker exec "$PFX-ruvds3" sh -c 'iptables -I INPUT -j DROP && iptables -I OUTPUT -j DROP'

fo_sec=-1
for _ in $(seq 1 30); do
	sleep 0.5
	c_conns=$(docker exec "$PFX-client" tinc -c /etc/tincstack/tinc.yaml -n tg dump connections 2>/dev/null || true)
	if echo "$c_conns" | grep -q "^euvds " && docker exec "$PFX-client" ping -c1 -W1 "$EUVDS_VPN" >/dev/null 2>&1; then
		t1=$(date +%s)
		fo_sec=$((t1 - t0))
		break
	fi
done

if [ "$fo_sec" -ge 0 ] && [ "$fo_sec" -le 10 ]; then
	note "Blackhole failover to direct euvds succeeded in ${fo_sec}s (<= 10s SLA)"
else
	miss "Blackhole failover exceeded 10s or failed (fo_sec=$fo_sec)"
fi

e_doc=$(doc_json euvds)
if [ "$(json_field "$e_doc" active_tier)" = "1" ] && [ "$(json_field "$e_doc" tier_state)" = "fallback" ]; then
	note "euvds dropped active_tier=1 state=fallback and admitted client"
else
	miss "euvds fallback doctor unexpected: $e_doc"
fi

echo "===== Test 3: Anti-Flap Dampening (12s UP / 12s DOWN -> 0% bounce/loss) ====="
docker exec "$PFX-client" ping -i 1 "$EUVDS_VPN" > "$BASE-bg-ping.log" 2>&1 &
BG_PING_PID=$!
sleep 2

# Flap #1 UP for 12s (< TierHoldBase=20s)
docker exec "$PFX-ruvds3" iptables -F
sleep 12

e_doc=$(doc_json euvds)
c_conns=$(docker exec "$PFX-client" tinc -c /etc/tincstack/tinc.yaml -n tg dump connections 2>/dev/null || true)
if [ "$(json_field "$e_doc" tier_state)" = "probation" ] && [ "$(json_field "$e_doc" active_tier)" = "1" ] &&
   [ "$(peer_field "$e_doc" ruvds3 tier_quarantined)" = "True" ] && echo "$c_conns" | grep -q "^euvds "; then
	note "Flap #1: ruvds3 quarantined in probation, active_tier stayed 1, client kept direct euvds"
else
	miss "Flap #1 violated anti-flap hold: e_doc=$e_doc c_conns=$c_conns"
fi

# Flap #2 DOWN for 12s
docker exec "$PFX-ruvds3" sh -c 'iptables -I INPUT -j DROP && iptables -I OUTPUT -j DROP'
sleep 12

echo "===== Test 4: Sustained Recovery -> Probation Clear -> Make-Before-Break Failback ====="
docker exec "$PFX-ruvds3" iptables -F

fb_ok=0
for _ in $(seq 1 200); do
	e_doc=$(doc_json euvds)
	c_conns=$(docker exec "$PFX-client" tinc -c /etc/tincstack/tinc.yaml -n tg dump connections 2>/dev/null || true)
	c_nodes=$(docker exec "$PFX-client" tinc -c /etc/tincstack/tinc.yaml -n tg dump nodes 2>/dev/null || true)
	if [ "$(json_field "$e_doc" active_tier)" = "2" ] &&
	   [ "$(json_field "$e_doc" tier_state)" = "normal" ] &&
	   ! echo "$c_conns" | grep -q "^euvds " &&
	   echo "$c_nodes" | grep "^euvds " | grep -Eq "nexthop ruvds3 .*distance 2"; then
		fb_ok=1
		break
	fi
	sleep 1
done

sleep 3
docker exec "$PFX-client" sh -c 'for p in $(pidof ping 2>/dev/null); do kill -INT "$p" 2>/dev/null || true; done'
wait "$BG_PING_PID" 2>/dev/null || true
BG_PING_PID=""

if [ "$fb_ok" -eq 1 ]; then
	note "Probation cleared after sustained stability; client failed back to ruvds3->euvds (tier_redirects=$(json_field "$e_doc" tier_redirects))"
else
	miss "Client did not fail back cleanly within 200s: e_doc=$e_doc"
fi

# Check 0% packet loss during flap & failback ping window
ping_stats=$(grep "packet loss" "$BASE-bg-ping.log" || true)
if echo "$ping_stats" | grep -q ", 0% packet loss"; then
	note "Continuous client->euvds ping across flap + failback achieved 0% packet loss ($ping_stats)"
else
	miss "Unexpected packet loss across flap + failback: $ping_stats"
	cat "$BASE-bg-ping.log" || true
fi

printf '==================================================================\n'
printf 'Summary: %d passed, fail=%d\n' "$pass_count" "$fail"
exit "$fail"

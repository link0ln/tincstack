#!/bin/sh
# ping-interval-test.sh -- proof that the dead-peer detection window
# (PingInterval / PingTimeout) is configurable from tinc.yaml, applies on a
# reload, and no longer substitutes values in silence.
#
# Why this exists: a field measurement (PLAN.md, defect G in the field) showed
# failover taking 21/45/46 s on a stand running the defaults. That is not a
# defect -- it is PingInterval 60 + PingTimeout 5, the window a peer's death is
# detected in, uniformly distributed because the death is uncorrelated with the
# ping cadence. The window is the knob a deployment turns, so it has to be
# reachable from the YAML, take effect without a restart, and say something
# when it refuses what it was given.
#
# PART 1  defaults: nodea links to nodeb, nodeb is FROZEN (docker pause -- the
#         kernel still ACKs, the daemon never answers, which is what a silently
#         dead peer looks like), and nodea takes the long way round: the link
#         is closed well after 30 s (expected 60-70).
# PART 2  `tinc set PingInterval 10' + `tinc set PingTimeout 3' + `tinc reload'
#         on the SAME running daemon: it logs the window change, and the next
#         freeze is detected within 20 s -- no restart.
# PART 3  a node that starts with PingInterval: 10 / PingTimeout: 3 in its YAML
#         options detects the freeze within 20 s (the startup path, not reload).
# PART 4  the substitutions are loud: `PingInterval: 0' (which reads like "stop
#         pinging" and means once a day), a PingTimeout above PingInterval, and
#         a PingInterval below the default PingTimeout each name what was asked
#         for and what is used. A healthy node logs none of it.
#
# Everything runs in containers; nothing is installed on the host.
#
# Usage: [LAB=prefix] [SUBNET=10.38.95] testing/config/ping-interval-test.sh [image]
#   The image is the first argument, else tincstack/core:$TINCSTACK_TAG, else
#   tincstack/core:dev. LAB (default wspi) prefixes the containers, the docker
#   network (<LAB>ping) and the /tmp data directories; a non-default LAB also
#   gets its own /24 (lab-env.sh), so two runs can share a host.
set -e

IMG=${1:-tincstack/core:${TINCSTACK_TAG:-dev}}
DEFAULT_LAB=wspi; DEFAULT_SUBNET=10.38.95
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/../transports/lab-env.sh"
NET=${LAB}ping
BASE=/tmp/$LAB-ping
NETNAME=wsz
WAIT=120

A_IP=$SUBNET.10
B_IP=$SUBNET.12
A_VPN=10.186.0.1
B_VPN=10.186.0.3

# What each part allows. SLOW_MIN: under the defaults the window is
# 60..65 s from the last meta traffic, so anything under 30 s would mean the
# defaults are not what this claims. FAST_MAX: PingInterval 10 + PingTimeout 3
# is a 10..13 s window; 20 s leaves room for the one-second tick and a loaded
# host without letting a 60 s default pass as a 10 s one.
SLOW_MIN=30
SLOW_LIMIT=100
FAST_MAX=20

fail=0
miss() { echo "FAIL: $*"; fail=1; }
note() { echo "ok:   $*"; }

cleanup() {
	docker unpause "$LAB-b" >/dev/null 2>&1 || true
	docker rm -f "$LAB-a" "$LAB-b" "$LAB-c" >/dev/null 2>&1 || true
}
# shellcheck disable=SC2329  # invoked from the EXIT trap below
cleanup_exit() {
	cleanup
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$BASE"-a "$BASE"-b "$BASE"-c
}
trap cleanup_exit EXIT
cleanup
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

# --- config generator -------------------------------------------------------
# $1 dir  $2 name  $3 extra option lines (already indented 6 spaces)
gen() {
	rm -rf "$1"; mkdir -p "$1"
	{
		echo "networks:"
		echo "  $NETNAME:"
		echo "    options:"
		echo "      Name: $2"
		echo "      Mode: router"
		echo "      Port: 655"
		echo "      AddressPool: 10.186.0.0/24"
		printf '%s\n' "$3"
	} > "$1/tinc.yaml"
}

# One short run per node so the daemon materialises its own keys and host block.
materialise() {
	for d in "$@"; do
		timeout 5 docker run --rm -v "$BASE-$d":/etc/tincstack "$IMG" \
			tincd -c /etc/tincstack/tinc.yaml -n "$NETNAME" -D -d1 >/dev/null 2>&1 || true
	done
}

# Cross-inject host records so each node knows the other's key, VPN subnet and
# dial address (same helper as the transport proofs).
crossinject() {
	python3 - "$BASE" "$A_IP" "$B_IP" "$A_VPN" "$B_VPN" <<'PYEOF'
import re, sys
base, aip, bip, avpn, bvpn = sys.argv[1:6]
names = {'a': 'nodea', 'b': 'nodeb'}
vpn = {'a': avpn, 'b': bvpn}
ip = {'a': aip, 'b': bip}
paths = {k: '%s-%s/tinc.yaml' % (base, k) for k in names}

def block(path, name):
    s = open(path).read()
    m = re.search(r'^      %s: \|\n((?:(?:        .*)?\n)+)' % re.escape(name), s, re.M)
    lines = [l[8:] for l in m.group(1).split('\n') if l.startswith('        ')]
    return [l for l in lines if l.strip()]

def setsubnet(lines, subnetip):
    return [re.sub(r'Subnet = .*', 'Subnet = %s/32' % subnetip, l) for l in lines]

blocks = {k: setsubnet(block(paths[k], names[k]), vpn[k]) for k in names}

for k in names:
    s = open(paths[k]).read()
    s = re.sub(r'(%s: \|\n(?:        .*\n)*?        Subnet = )[^\n]*' % names[k],
               lambda m: m.group(1) + '%s/32' % vpn[k], s)
    open(paths[k], 'w').write(s)

def indent(lines): return ''.join('        ' + l + '\n' for l in lines)

def inject(path, name, extra):
    s = open(path).read()
    if '      %s: |' % name in s:
        return
    s = s.replace('    hosts:\n', '    hosts:\n      %s: |\n' % name + indent(extra), 1)
    open(path, 'w').write(s)

for k in names:
    for j in names:
        if j == k:
            continue
        rec = ['Address = ' + ip[j], 'Port = 655'] + [l for l in blocks[j] if not l.startswith(('Address', 'Port'))]
        inject(paths[k], names[j], rec)
print("configs merged")
PYEOF
}

start() { # letter ip
	docker run -d --name "$LAB-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN \
		--device /dev/net/tun -v "$BASE-$1":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n "$NETNAME" -D -d2 >/dev/null
}
logs() { docker logs "$LAB-$1" 2>&1; }
cli() { l=$1; shift; docker exec "$LAB-$l" tinc -c /etc/tincstack/tinc.yaml -n "$NETNAME" "$@" 2>&1 || true; }
setvpn() { # letter vpnip
	docker exec "$LAB-$1" ip addr add "$2/24" dev "$NETNAME" >/dev/null 2>&1 || true
	docker exec "$LAB-$1" ip link set "$NETNAME" up >/dev/null 2>&1 || true
}
activated() { logs "$1" | grep -q ' activated'; }

wait_link() { # a-letter a-vpn b-letter b-vpn
	deadline=$(( $(date +%s) + WAIT ))
	while :; do
		setvpn "$1" "$2"; setvpn "$3" "$4"
		if activated "$1" && activated "$3" \
		   && docker exec "$LAB-$1" ping -c1 -W1 "$4" >/dev/null 2>&1 \
		   && docker exec "$LAB-$3" ping -c1 -W1 "$2" >/dev/null 2>&1; then
			return 0
		fi
		if [ "$(date +%s)" -ge "$deadline" ]; then
			echo "TIMEOUT: link $1<->$3 not ready within ${WAIT}s; logs follow"
			logs "$1" | tail -20; logs "$3" | tail -20
			return 1
		fi
		sleep 1
	done
}

# How many times $1 has closed its connection with $2 so far.
closes() { logs "$1" | grep -c "Closing connection with $2" || true; }

# freeze_and_time <letter> <peer> <limit seconds>
# Freezes nodeb, prints the seconds until <letter> closed the link with <peer>,
# or -1 when it did not within the limit. The clock starts at the freeze, which
# is the earliest moment the peer can be called dead; the window itself is
# measured from the last meta traffic, so the freeze happens right after the
# link is healthy and the two are within a second of each other.
freeze_and_time() {
	before=$(closes "$1" "$2")
	t0=$(date +%s)
	docker pause "$LAB-b" >/dev/null
	while :; do
		el=$(( $(date +%s) - t0 ))
		if [ "$(closes "$1" "$2")" -gt "$before" ]; then
			echo "$el"
			return 0
		fi
		if [ "$el" -ge "$3" ]; then
			echo "-1"
			return 0
		fi
		sleep 1
	done
}

# The line the ping timeout logs, e.g. "nodeb (...) didn't respond to PING in 5 seconds".
ping_line() { logs "$1" | grep "didn't respond to PING" | tail -1 || true; }
ping_secs() { ping_line "$1" | sed -n "s/.*didn't respond to PING in \([0-9]*\) seconds.*/\1/p"; }

######################## PART 1: the default window #########################
echo "===== PART 1: defaults (PingInterval 60, PingTimeout 5): a frozen peer is noticed slowly ====="

gen "$BASE-b" nodeb ""
gen "$BASE-a" nodea "      ConnectTo: [nodeb]"
materialise b a
crossinject
start b "$B_IP"; start a "$A_IP"
wait_link a "$A_VPN" b "$B_VPN" || miss "default: the link nodea<->nodeb did not come up"

if logs a | grep -q 'out of range'; then
	miss "a logged a range complaint although nothing was configured: $(logs a | grep 'out of range' | tail -1)"
else
	note "a logged no range complaint at the defaults"
fi

slow=$(freeze_and_time a nodeb "$SLOW_LIMIT")
echo "a noticed the frozen nodeb after ${slow}s (default window)"
if [ "$slow" = "-1" ]; then
	miss "default: a never closed the link to the frozen nodeb within ${SLOW_LIMIT}s"
elif [ "$slow" -lt "$SLOW_MIN" ]; then
	miss "default: detection took only ${slow}s, which is not a 60+5 window -- the defaults are not what they claim"
else
	note "default detection ${slow}s (>= ${SLOW_MIN}s), ping timeout line: $(ping_line a)"
fi

######## PART 2: shortening the window on the running daemon (reload) #######
echo
echo "===== PART 2: \`tinc set PingInterval 10 / PingTimeout 3' + reload, no restart ====="
docker unpause "$LAB-b" >/dev/null
wait_link a "$A_VPN" b "$B_VPN" || miss "reload: the link did not come back after unfreezing nodeb"

# `tinc set' saves the YAML and asks the running daemon to reload by itself
# (docs/config-schema.md, "Editing a script from the CLI" -- the same path for
# options), so each of these two edits is already a reload; the explicit one
# below is the no-op that proves nothing is logged when nothing changed. The
# two values therefore move in separate lines, which is what is asserted.
cli a set PingInterval 10 >/dev/null
cli a set PingTimeout 3 >/dev/null
cli a reload >/dev/null
sleep 2
changed=$(logs a | grep 'Dead-peer detection window changed on reload' || true)
printf '%s\n' "${changed:-<nothing logged>}" | sed 's/^/a: /'
if printf '%s' "$changed" | grep -q 'PingInterval 60 -> 10' \
   && printf '%s' "$changed" | grep -q 'PingTimeout 5 -> 3'; then
	note "the daemon logged both halves of the new window without a restart"
else
	miss "the daemon did not log the window change on reload"
fi

# Wait until the link is quiet and healthy again, then freeze.
wait_link a "$A_VPN" b "$B_VPN" || miss "reload: the link was not healthy before the second freeze"
fast=$(freeze_and_time a nodeb "$FAST_MAX")
echo "a noticed the frozen nodeb after ${fast}s (window set by reload)"
if [ "$fast" = "-1" ]; then
	miss "reload: PingInterval 10 was accepted but detection still took more than ${FAST_MAX}s -- the reload did not apply it"
else
	note "detection after reload: ${fast}s (<= ${FAST_MAX}s), ping timeout line: $(ping_line a)"
	secs=$(ping_secs a)
	if [ -n "$secs" ] && [ "$secs" -le 5 ]; then
		note "the PING went unanswered for ${secs}s, i.e. the new PingTimeout, not the old 5"
	fi
fi
docker unpause "$LAB-b" >/dev/null
cleanup

##################### PART 3: configured at startup #########################
echo
echo "===== PART 3: PingInterval: 10 / PingTimeout: 3 in the YAML at startup ====="
gen "$BASE-b" nodeb ""
gen "$BASE-a" nodea "      ConnectTo: [nodeb]
      PingInterval: 10
      PingTimeout: 3"
materialise b a
crossinject
start b "$B_IP"; start a "$A_IP"
wait_link a "$A_VPN" b "$B_VPN" || miss "startup: the link nodea<->nodeb did not come up"

boot=$(freeze_and_time a nodeb "$FAST_MAX")
echo "a noticed the frozen nodeb after ${boot}s (window set in the YAML at startup)"
if [ "$boot" = "-1" ]; then
	miss "startup: PingInterval: 10 in the YAML did not shorten the window (no close within ${FAST_MAX}s)"
else
	note "startup detection ${boot}s (<= ${FAST_MAX}s), ping timeout line: $(ping_line a)"
fi
docker unpause "$LAB-b" >/dev/null
cleanup

################## PART 4: the substitutions are not silent #################
echo
echo "===== PART 4: out-of-range values say what they do ====="

# A single node, no peers: it only has to start, log and be killed.
solo() { # extra option lines -> its log
	rm -rf "$BASE-c"
	gen "$BASE-c" nodec "$1"
	timeout 6 docker run --rm --name "$LAB-c" -v "$BASE-c":/etc/tincstack "$IMG" \
		tincd -c /etc/tincstack/tinc.yaml -n "$NETNAME" -D -d1 2>&1 || true
}

zero=$(solo "      PingInterval: 0")
echo "$zero" | grep 'PingInterval' || true
case $zero in
	*"PingInterval 0 is out of range"*"86400"*)
		note "\`PingInterval: 0' says it means once a day instead of silently meaning it" ;;
	*) miss "\`PingInterval: 0' did not warn about the 86400 s substitution" ;;
esac

overshoot=$(solo "      PingInterval: 10
      PingTimeout: 99")
echo "$overshoot" | grep 'PingTimeout' || true
case $overshoot in
	*"PingTimeout 99 is out of range (1..PingInterval = 10), using 10 seconds"*)
		note "a PingTimeout above PingInterval names both values" ;;
	*) miss "PingTimeout 99 with PingInterval 10 did not warn" ;;
esac

squeezed=$(solo "      PingInterval: 2")
echo "$squeezed" | grep 'PingTimeout' || true
case $squeezed in
	*"default PingTimeout of 5 seconds is longer than PingInterval 2, using 2 seconds"*)
		note "an interval below the default timeout says which timeout is actually used" ;;
	*) miss "PingInterval 2 did not warn that the default PingTimeout no longer fits" ;;
esac

healthy=$(solo "      PingInterval: 10
      PingTimeout: 3")
case $healthy in
	*"out of range"*|*"is longer than PingInterval"*)
		miss "a valid PingInterval/PingTimeout pair still complained: $(echo "$healthy" | grep -i ping | tail -1)" ;;
	*) note "a valid pair logs nothing" ;;
esac

echo
if [ "$fail" = 0 ]; then
	echo "PASS: the dead-peer window is set from the YAML at startup and on reload, and bad values are loud ($IMG)"
else
	echo "FAIL: see the lines above ($IMG)"
fi
exit "$fail"

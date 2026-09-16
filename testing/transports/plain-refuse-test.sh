#!/bin/sh
# plain-refuse-test.sh -- prove the `AllowPlainMeta' option (stream Z).
#
# PLAN.md's Known Issues entry "a node cannot refuse cleartext tinc on its
# listening port" is the thing this proves fixed. The reproduction it names is
# exactly PART 1 here: a third party that can reach the port and knows (or
# guesses) any member name opens an unwrapped tinc meta connection and the node
# answers with its own ID line -- a probe, not a man-in-the-middle, is enough
# to fingerprint the node as tinc.
#
# PART 1  BEFORE / default (no AllowPlainMeta line anywhere):
#   * two nodes link over the plain carrier and ping both ways;
#   * a raw TCP probe from a third address that sends the tinc ID line
#     "0 nodea 17.7" to nodeb's port gets nodeb's ID line back;
#   * nodeb's accept list, as it logs it, contains `plain'.
# PART 2  AFTER, nodeb with `AllowPlainMeta: no':
#   * nodeb logs the accept list WITHOUT `plain';
#   * the same raw probe gets NOTHING back (the socket is tarpitted, exactly
#     like an unrecognised preamble, so the refusal is not itself a signal),
#     and nodeb logs the refusal naming the reason;
#   * an obfs connection from nodea to the SAME node still comes up and
#     carries traffic both ways -- refusing plain does not refuse the node;
#   * `tinc dump nodes' on the refusing node still works (the control
#     connection is a UNIX socket and never reaches the TCP front).
# PART 3  reload: `tinc set AllowPlainMeta yes' + `tinc reload' on the running
#   refusing node makes the same probe answer again, without a restart --
#   AllowPlainMeta is re-read like its neighbours Transports/SingleFlow.
#
# Everything runs in containers; nothing is installed on the host. No fixed
# sleeps for readiness: every link wait polls until both daemons logged
# "activated" and a ping succeeds, with a deadline.
#
# Usage: [LAB=prefix] [SUBNET=10.37.94] testing/transports/plain-refuse-test.sh [image]
#   The image is the first argument, else tincstack/core:$TINCSTACK_TAG, else
#   tincstack/core:dev -- the same selector every other proof here takes.
#   LAB (default wspr) prefixes the containers, the docker network
#   (<LAB>plain) and the /tmp data directories; a non-default LAB also gets its
#   own /24 (lab-env.sh), so two runs can share a host.
set -e

IMG=${1:-tincstack/core:${TINCSTACK_TAG:-dev}}
PROBE_IMG=nicolaka/netshoot
DEFAULT_LAB=wspr; DEFAULT_SUBNET=10.37.94
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"
NET=${LAB}plain
BASE=/tmp/$LAB-plain
NETNAME=wsz
WAIT=120

A_IP=$SUBNET.10
B_IP=$SUBNET.12
P_IP=$SUBNET.50
J_IP=$SUBNET.51
A_VPN=10.184.0.1
B_VPN=10.184.0.3

fail=0
miss() { echo "FAIL: $*"; fail=1; }
note() { echo "ok:   $*"; }

cleanup() {
	docker rm -f "$LAB-a" "$LAB-b" "$LAB-probe" "$LAB-join" >/dev/null 2>&1 || true
}
# shellcheck disable=SC2329  # invoked from the EXIT trap below
cleanup_exit() {
	cleanup
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$BASE"-a "$BASE"-b "$BASE"-j
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
		echo "      AddressPool: 10.184.0.0/24"
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
# dial address.
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
# The node's own effective accept list, as transport_read_config() logs it.
acceptlist() { logs "$1" | grep 'Transports accept=' | tail -1; }
# Just the accept= field of it. NB: matching `*plain*' against the whole line
# is wrong -- the same line ends in `prefer=plain'.
acceptmask() { acceptlist "$1" | sed -n 's/.*accept=\([^ ]*\).*/\1/p'; }
accepts_plain() { acceptmask "$1" | tr ',' '\n' | grep -qx plain; }

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

# The whole point of the test: an unwrapped tinc meta connection from a third
# address. Sends the tinc ID line and prints whatever comes back (nothing, if
# the node refuses and tarpits). $1 = target ip, $2 = the ID line to send.
probe() {
	docker rm -f "$LAB-probe" >/dev/null 2>&1 || true
	docker run --rm --name "$LAB-probe" --network "$NET" --ip "$P_IP" "$PROBE_IMG" \
		python3 -c "
import socket
s = socket.create_connection(('$1', 655), 10)
s.settimeout(8)
s.sendall(b'$2\n')
try:
    d = s.recv(256)
except Exception:
    d = b''
s.close()
print('PROBE-REPLY<' + d.decode('utf-8', 'replace').split('\n')[0].strip() + '>')
" 2>&1 || true
}

# `tinc join' from a fresh node against nodeb. This is the documented cost of
# AllowPlainMeta = no, not an accident: invitation.c opens a raw TCP socket and
# sends "0 ?<key> ..." in cleartext (the invitee holds no key material yet), so
# the front classifies it TCP_CLASS_TINC and refuses it like any other
# cleartext meta connection. Asserted in BOTH directions below so the trade-off
# cannot change silently -- if a future change makes join work over a wrapped
# carrier, this is the assertion to update, deliberately.
try_join() {
	rm -rf "$BASE-j"; mkdir -p "$BASE-j"
	inv=$(cli b invite "joiner$1" | tail -1)
	docker rm -f "$LAB-join" >/dev/null 2>&1 || true
	docker run --rm --name "$LAB-join" --network "$NET" --ip "$J_IP" \
		-v "$BASE-j":/etc/tincstack "$IMG" \
		tinc -c /etc/tincstack/tinc.yaml -n "$NETNAME" join "$inv" 2>&1 | tail -3
}

OBFS_OPTS="      ObfsJunkPacketCount: 4
      ObfsJunkPacketMinSize: 100
      ObfsJunkPacketMaxSize: 200"

######################## PART 1: default, plain accepted ####################
echo "===== PART 1: default (no AllowPlainMeta): plain is accepted ====="

gen "$BASE-b" nodeb ""
gen "$BASE-a" nodea "      ConnectTo: [nodeb]"
materialise b a
crossinject
start b "$B_IP"; start a "$A_IP"
wait_link a "$A_VPN" b "$B_VPN" || miss "default: plain link nodea<->nodeb did not come up"

accept_before=$(acceptlist b)
echo "b: $accept_before"
if accepts_plain b; then
	note "default accept list contains plain ($(acceptmask b))"
else
	miss "default accept list has no plain: $accept_before"
fi

rep_before=$(probe "$B_IP" "0 nodea 17.7")
echo "probe -> nodeb: $rep_before"
case $rep_before in
	*"PROBE-REPLY<0 nodeb"*) note "default: the cleartext probe gets nodeb's tinc ID line back (the fingerprint PLAN.md described)" ;;
	*) miss "default: expected nodeb's ID line, got: $rep_before" ;;
esac

################### PART 2: AllowPlainMeta: no on the listener ##############
echo
echo "===== PART 2: nodeb AllowPlainMeta: no -- plain refused, obfs still works ====="
cleanup
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null 2>&1 || true

gen "$BASE-b" nodeb "      AllowPlainMeta: no
$OBFS_OPTS"
gen "$BASE-a" nodea "      PreferredTransports: [obfs, plain]
      ConnectTo: [nodeb]
$OBFS_OPTS"
materialise b a
crossinject
start b "$B_IP"; start a "$A_IP"
wait_link a "$A_VPN" b "$B_VPN" || miss "AllowPlainMeta=no: the obfs link nodea<->nodeb did not come up"

accept_after=$(acceptlist b)
echo "b: $accept_after"
if [ -z "$accept_after" ]; then
	miss "b never logged its accept list"
elif accepts_plain b; then
	miss "AllowPlainMeta=no but the accept list still has plain: $accept_after"
else
	note "accept list no longer contains plain ($(acceptmask b))"
fi

if logs b | grep -q 'AllowPlainMeta = no'; then
	note "b warned about the consequence at startup: $(logs b | grep 'AllowPlainMeta = no' | tail -1)"
else
	miss "b did not log the AllowPlainMeta warning"
fi

# The link that DOES work: obfs, carrying real traffic both ways.
obfs_ping=$(docker exec "$LAB-a" ping -c4 -W2 "$B_VPN" 2>&1 | tail -2)
echo "$obfs_ping"
case $obfs_ping in
	*" 0% packet loss"*) note "obfs link to the refusing node passes traffic (0% loss)" ;;
	*) miss "obfs link to the refusing node lost packets" ;;
esac
if logs a | grep -q 'Connection with nodeb.*activated'; then
	note "a: $(logs a | grep 'activated' | tail -1)"
fi

# The probe that must now get nothing.
rep_after=$(probe "$B_IP" "0 nodea 17.7")
echo "probe -> nodeb: $rep_after"
case $rep_after in
	"PROBE-REPLY<>") note "the cleartext probe gets NO answer: the node no longer identifies itself as tinc" ;;
	*) miss "AllowPlainMeta=no but the probe still got: $rep_after" ;;
esac

refusal=$(logs b | grep 'refusing cleartext tinc meta connection' | tail -1 || true)
if [ -n "$refusal" ]; then
	note "b logged the reason: $refusal"
else
	miss "b did not log a refusal line for the cleartext probe"
fi

# The dialler's view of the peer: `dump nodes' prints transport_node_mask(),
# which ack_h() fills from the ACK. It used to OR `plain' back in, so a peer
# that refuses plain was still dialled on plain for a refusal.
peerview=$(cli a dump nodes | grep '^nodeb ' | sed -n 's/.* transports \([^ ]*\).*/\1/p')
echo "a's view of nodeb's accept list: ${peerview:-<none>}"
if [ -z "$peerview" ]; then
	miss "a never learned nodeb's accept list"
elif printf '%s\n' "$peerview" | tr ',' '\n' | grep -qx plain; then
	miss "a still believes nodeb accepts plain: $peerview"
else
	note "a learned from the ACK that nodeb does not accept plain ($peerview)"
fi

# The local control connection must be untouched.
dump=$(cli b dump nodes)
echo "$dump"
case $dump in
	*nodeb*) note "\`tinc dump nodes' still works on the refusing node" ;;
	*) miss "the CLI stopped working on the refusing node: $dump" ;;
esac

# The documented cost: `tinc join' against this node cannot work.
join_refused=$(try_join 1)
echo "tinc join -> nodeb: $join_refused"
case $join_refused in
	*"Could not connect to inviter"*) note "the documented trade-off holds: \`tinc join' against a node that refuses plain fails (invitations are cleartext by construction)" ;;
	*) miss "expected \`tinc join' to fail against a plain-refusing node, got: $join_refused" ;;
esac

######################## PART 3: reload puts it back ########################
echo
echo "===== PART 3: \`tinc set AllowPlainMeta yes' + reload, no restart ====="
cli b set AllowPlainMeta yes >/dev/null
cli b reload >/dev/null
# Poll for the reload to have been applied (the daemon re-logs its accept list).
deadline=$(( $(date +%s) + 30 ))
while :; do
	accepts_plain b && break
	[ "$(date +%s)" -ge "$deadline" ] && break
	sleep 1
done
accept_reload=$(acceptlist b)
echo "b: $accept_reload"
if accepts_plain b; then
	note "after reload the accept list contains plain again ($(acceptmask b))"
else
	miss "reload did not re-read AllowPlainMeta: $accept_reload"
fi

rep_reload=$(probe "$B_IP" "0 nodea 17.7")
echo "probe -> nodeb: $rep_reload"
case $rep_reload in
	*"PROBE-REPLY<0 nodeb"*) note "the probe is answered again without restarting the daemon" ;;
	*) miss "after reload the probe still got: $rep_reload" ;;
esac

join_ok=$(try_join 2)
echo "tinc join -> nodeb: $join_ok"
case $join_ok in
	*"Invitation successfully accepted"*|*"Configuration stored in"*)
		note "and \`tinc join' works again on the same running daemon" ;;
	*) miss "after reload \`tinc join' still failed: $join_ok" ;;
esac

echo
if [ "$fail" = 0 ]; then
	echo "PASS: AllowPlainMeta refuses inbound cleartext tinc, keeps obfs, the CLI and reload ($IMG)"
else
	echo "FAIL: see the lines above ($IMG)"
fi
exit "$fail"

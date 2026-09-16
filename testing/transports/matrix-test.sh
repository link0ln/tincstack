#!/bin/sh
# matrix-test.sh -- prove outbound carrier selection and fallback.
#
# Two docker nodes. The dialling node's PreferredTransports puts the `test'
# stub carrier (compiled only with -Dtransport_test=true) ahead of `plain'.
# The test carrier's dial always fails, so the selector must fall back to
# `plain' and the tunnel must still come up. This exercises the real
# (preference x accept) walk with a carrier whose failure is deterministic.
#
# Requires an image built with -Dtransport_test=true. Build it with:
#   sed 's/-Dbuildtype=release/-Dbuildtype=release -Dtransport_test=true/' \
#       core/Dockerfile.build > /tmp/Dockerfile.test
#   docker build -f /tmp/Dockerfile.test -t tincstack/core:ws-b-test core/
#
# Usage: [LAB=prefix] [SUBNET=10.30.9] testing/transports/matrix-test.sh [image]
#   LAB (default wsbmtx) prefixes every container/network name and the /tmp
#   directories; a non-default LAB also gets its own /24 (see lab-env.sh).
#   The image is the first argument, else tincstack/core:$TINCSTACK_TAG, the
#   same selector every other proof takes. Silently defaulting to the stream
#   image this test was written against means a house-style invocation tests
#   a months-old core and reports its state as today's (measured: a run with
#   TINCSTACK_TAG set but no argument tested tincstack/core:ws-o and failed
#   PART 8, which the current core passes).
set -e

IMG=${1:-tincstack/core:${TINCSTACK_TAG:-dev-test}}
DEFAULT_LAB=wsbmtx; DEFAULT_SUBNET=10.30.9
# shellcheck source=testing/transports/lab-env.sh
. "$(dirname "$0")/lab-env.sh"
NET=$LAB
A_IP=$SUBNET.10
B_IP=$SUBNET.11
DA=/tmp/$LAB-a
DB=/tmp/$LAB-b

cleanup() {
	docker rm -f "$LAB-a" "$LAB-b" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

rm -rf "$DA" "$DB"
mkdir -p "$DA" "$DB"

cat > "$DA/tinc.yaml" <<EOF
networks:
  wsb:
    options:
      Name: nodea
      Mode: router
      Port: 655
      AddressPool: 10.180.0.0/24
EOF

cat > "$DB/tinc.yaml" <<EOF
networks:
  wsb:
    options:
      Name: nodeb
      Mode: router
      Port: 0
      AddressPool: 10.180.0.0/24
      PreferredTransports: [test, plain]
      ConnectTo: [nodea]
EOF

# Materialise keys / host records.
timeout 3 docker run --rm -v "$DA":/etc/tincstack "$IMG" tincd -c /etc/tincstack/tinc.yaml -n wsb -D -d1 >/dev/null 2>&1 || true
timeout 3 docker run --rm -v "$DB":/etc/tincstack "$IMG" tincd -c /etc/tincstack/tinc.yaml -n wsb -D -d1 >/dev/null 2>&1 || true

# Cross-inject host records; nodea advertises that it also accepts `test'.
python3 - "$A_IP" "$DA" "$DB" <<'PYEOF'
import re, sys
aip, da, db = sys.argv[1], sys.argv[2], sys.argv[3]
def block(path, name):
    s = open(path).read()
    m = re.search(r'^      %s: \|\n((?:(?:        .*)?\n)+)' % re.escape(name), s, re.M)
    body = m.group(1)
    lines = [l[8:] for l in body.split('\n') if l.startswith('        ')]
    return [l for l in lines if l.strip()]
def indent(lines): return ''.join('        ' + l + '\n' for l in lines)
a = block(da + '/tinc.yaml', 'nodea')
b = block(db + '/tinc.yaml', 'nodeb')
# advertise test in nodea's record so nodeb considers it
a = [l for l in a if not l.startswith('Transports')] + ['Transports = plain, sf, test']
nodea = ['Address = ' + aip, 'Port = 655'] + [l for l in a if not l.startswith(('Address','Port'))]
sa = open(da + '/tinc.yaml').read().replace('    hosts:\n', '    hosts:\n      nodeb: |\n' + indent(b), 1)
open(da + '/tinc.yaml', 'w').write(sa)
sb = open(db + '/tinc.yaml').read().replace('    hosts:\n', '    hosts:\n      nodea: |\n' + indent(nodea), 1)
open(db + '/tinc.yaml', 'w').write(sb)
print("merged")
PYEOF

docker run -d --name "$LAB-a" --network "$NET" --ip "$A_IP" --cap-add NET_ADMIN --device /dev/net/tun -v "$DA":/etc/tincstack "$IMG" tincd -c /etc/tincstack/tinc.yaml -n wsb -D -d3 >/dev/null
docker run -d --name "$LAB-b" --network "$NET" --ip "$B_IP" --cap-add NET_ADMIN --device /dev/net/tun -v "$DB":/etc/tincstack "$IMG" tincd -c /etc/tincstack/tinc.yaml -n wsb -D -d3 >/dev/null
sleep 7

log=$(docker logs "$LAB-b" 2>&1)
echo "----- node B relevant log -----"
echo "$log" | grep -iE "via test|simulated dial|falling back|via plain|activated" || true
echo "-------------------------------"

fail=0
echo "$log" | grep -q "via test" || { echo "MISS: node B did not try the test carrier first"; fail=1; }
echo "$log" | grep -qi "falling back to plain" || { echo "MISS: no fallback to plain logged"; fail=1; }
echo "$log" | grep -q "activated" || { echo "MISS: connection never activated"; fail=1; }

if [ "$fail" = 0 ]; then
	echo "PASS: test carrier tried, fell back to plain, tunnel came up"
	exit 0
else
	echo "FAIL"
	exit 1
fi

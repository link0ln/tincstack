#!/usr/bin/env bash
# T1e -- junk-packet DoS-cost test.
#
# A censor (or anyone) can send unauthenticated datagrams at a node's UDP port.
# For obfs/DirectSeal the cold-start classifier (obfs_udp_try) has to decide,
# with a keyed check, whether such a datagram belongs to any peer it knows --
# so the worry is an O(N)-per-packet handler: one keyed derivation per known
# peer per junk datagram would let a flood cost the daemon N x rate CPU and
# starve everything else (a DoS lever, a Salamander-style listener is O(N)
# per junk datagram). tincstack caps that scan at a per-second budget
# (OBFS_SCAN_PER_SEC..OBFS_SCAN_MAX in obfs.c) with a round-robin cursor, so the
# keyed work is bounded per wall-second regardless of how hard the flood comes.
#
# This test measures the daemon's CPU while it is flooded with unauthenticated
# junk, as a function of two dimensions, and asserts the bound holds:
#
#   * vs FLOOD RATE at a fixed peer count -- the DoS lever. A rate-independent
#     per-second CPU means an attacker cannot raise our cost by flooding
#     harder. This is the property that matters.
#   * vs PEER COUNT N at a fixed rate -- bounded (capped) growth, not the
#     linear-per-packet blow-up an O(N) handler would show.
#
# Metric: the tincd process's utime+stime (jiffies from /proc/<pid>/stat,
# fields 14+15) over the flood window, minus an equal idle window, converted to
# CPU-microseconds and divided by the packets the attacker actually sent -->
# CPU us per junk packet. Reported per (build, N, rate), median over REPEATS.
#
# Positive control (so "flat" is not "the meter is broken"): a deliberately
# O(N)-per-packet build is compiled from a COPY of core/ with the scan's
# per-second budget neutered (every junk packet scans the whole node tree). It
# must show CPU rising with N and with rate; the shipped build must not. The
# shipped source is never touched.
#
# The victim knows N peers by carrying N host records with well-formed Ed25519
# public keys (43-char tinc base64 of 32 random bytes -- ecdsa_set_base64_public
# _key validates length only, and obfs_derive_base hashes the base64 text, so a
# random-but-well-formed key exercises the full per-peer derivation the scan
# runs). The peers are never live: the junk comes from an unknown source
# address, which is exactly the cold-start path the scan defends.
#
# Host hygiene: everything runs in throwaway containers; nothing is installed on
# the host and the shipped tree is not modified.
#
# Usage: flock /tmp/tincstack-lab.lock testing/perf/junk-cost-test.sh [outdir]
#   env: CORE_IMAGE  (shipped build to test; default tincstack/core:${TINCSTACK_TAG:-dev})
#        CONTROL     (1 = also build+run the O(N) positive control; default 1)
#        NLIST       (peer counts; default "1 4 16 64")
#        RATELIST    (attacker send rates in pps; default "auto" = one max-rate run;
#                     e.g. "20000 80000" pins the loop to those rates)
#        DURATION    (flood seconds per measurement; default 8)
#        REPEATS     (default 3)
#        PYTHON_IMAGE(default python:3.12-slim), KEEP (keep containers)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
CONTROL="${CONTROL:-1}"
NLIST="${NLIST:-1 4 16 64}"
# A sub-saturation numeric rate (O(N) shows unmasked) plus a max-rate run (the
# DoS lever: at saturation the O(N) build pegs the core while the shipped one
# does not). "auto" alone still works -- the meter is then proven via CPU.
RATELIST="${RATELIST:-15000 auto}"
DURATION="${DURATION:-8}"
REPEATS="${REPEATS:-3}"
PY="${PYTHON_IMAGE:-python:3.12-slim}"
CONTROL_IMG="tincstack/core-junk-on:t1e"
PFX=jc
NET=${PFX}net
SUBNET=10.51.3
V_IP=$SUBNET.10
Y=/c/tinc.yaml
PORT=655
OUT=${1:-$HERE/results/$(date +%Y%m%d-%H%M%S)-junk-cost}
FAILED=0
# Docker -v needs an absolute source path; make OUT absolute up front so the
# flood container can mount it wherever the caller pointed us.
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

cleanup() {
	docker rm -f "$PFX-v" "$PFX-a" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
[[ -n ${KEEP:-} ]] || trap cleanup EXIT
mkdir -p "$OUT"

# ---- the O(N) positive control image: a copy of core/ with the budget removed ----
build_control() {
	local tmp
	tmp="$(mktemp -d)"
	cp -a "$ROOT/core/." "$tmp/"
	# Neuter the per-second scan budget: force a full node-tree scan on EVERY
	# junk datagram. Anchored insertion before the round-robin loop, so it
	# overrides whatever the per-second gate set. Shipped tree is untouched.
	python3 - "$tmp/tincd/src/obfs.c" <<-'PYEOF'
		import sys
		p = sys.argv[1]
		s = open(p).read()
		anchor = "\t/* Round-robin from the persistent cursor, wrapping once. */\n"
		if anchor not in s:
		    sys.exit("anchor not found in obfs.c -- control patch needs updating")
		inject = ("\tscan_budget = (int)total; scan_cursor = 0; "
		          "/* T1e CONTROL: per-packet O(N) scan, no budget */\n")
		s = s.replace(anchor, inject + anchor, 1)
		open(p, "w").write(s)
	PYEOF
	log "building the O(N) positive-control image ($CONTROL_IMG) from a patched copy"
	docker build -q -f "$tmp/Dockerfile.build" -t "$CONTROL_IMG" "$tmp" >/dev/null || {
		rm -rf "$tmp"
		return 1
	}
	rm -rf "$tmp"
}

# ---- the flood generator (python stdlib, throwaway container) --------------------
# Sends UDP junk to the victim for <duration> s (optionally rate-limited), each
# datagram >= OBFS_MIN_FRAME with a first byte < 0x40 so the classifier routes
# it to the obfs keyed check (not SF, not a QUIC long/short header). Prints the
# packet count it actually sent on stdout.
cat > "$OUT/flood.py" <<'PYEOF'
import os, socket, sys, time
host, port, dur = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
rate = float(sys.argv[4])  # pps; 0 = as fast as possible
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((host, port))
payload = bytearray(os.urandom(1300))
payload[0] &= 0x3f  # not 0x40+ (QUIC short) and not 0xc0+ (QUIC long); not SF magic
sent = 0
end = time.monotonic() + dur
if rate > 0:
    interval = 1.0 / rate
    nxt = time.monotonic()
    while time.monotonic() < end:
        try:
            s.send(payload); sent += 1
        except OSError:
            pass
        nxt += interval
        d = nxt - time.monotonic()
        if d > 0:
            time.sleep(d)
else:
    # max rate; refresh a few bytes occasionally so it is not one cached frame
    while time.monotonic() < end:
        for _ in range(2000):
            try:
                s.send(payload); sent += 1
            except OSError:
                pass
        if time.monotonic() >= end:
            break
print(sent)
PYEOF

# tincd CPU jiffies (utime+stime) of the victim's daemon
cpu_jiffies() { # -> integer
	docker exec "$PFX-v" sh -c 'p=$(cat /tmp/tincd.pid); awk "{print \$14+\$15}" /proc/$p/stat' 2>/dev/null || echo 0
}
CLK=$(docker run --rm "$IMG" getconf CLK_TCK 2>/dev/null || echo 100)

# Bring the victim up with N well-formed host records, obfs in the accept mask.
victim_up() { # <image> <N>
	local img=$1 n=$2
	docker rm -f "$PFX-v" >/dev/null 2>&1 || true
	docker run -d --name "$PFX-v" --network "$NET" --ip "$V_IP" --cap-add NET_ADMIN --device /dev/net/tun \
		"$img" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
	docker exec "$PFX-v" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder >/dev/null && tinc -n lab -c $Y set Port $PORT >/dev/null"
	# N host records, each a well-formed random Ed25519 pubkey, added offline
	# so load_all_nodes() puts them in the node tree at startup.
	docker exec "$PFX-v" sh -c '
		n='"$n"'; Y='"$Y"'
		i=1
		while [ "$i" -le "$n" ]; do
			pk=$(head -c32 /dev/urandom | base64 | tr -d "=" | cut -c1-43)
			tinc -n lab -c "$Y" set "peer$i.Ed25519PublicKey" "$pk" >/dev/null
			i=$((i+1))
		done'
	docker exec -d "$PFX-v" sh -c "tincd -n lab -c $Y -D -d0 >/tmp/tincd.log 2>&1 & echo \$! >/tmp/tincd.pid"
	local seen=0 t
	for _ in $(seq 30); do
		t=$(docker exec "$PFX-v" sh -c 'cat /tmp/tincd.pid 2>/dev/null && ls /proc/$(cat /tmp/tincd.pid 2>/dev/null)/stat 2>/dev/null' 2>/dev/null)
		[[ -n $t ]] && seen=$(docker exec "$PFX-v" tinc -n lab -c "$Y" dump nodes 2>/dev/null | grep -c '^peer') && break
		sleep 0.5
	done
	log "victim up: node tree has founder + $seen peers (asked for $n)"
	[[ $seen -eq $n ]]
}

# One measurement: idle window, then flood window; append a CSV row with
# CPU-us/packet (flood minus idle, normalised by packets sent).
measure() { # <build> <N> <rate> <repeat>
	local build=$1 n=$2 rate=$3 rep=$4
	local pps=$rate
	[[ $rate == auto ]] && pps=0
	local c0 c1 cidle pkts flood_j idle_j us_pkt
	c0=$(cpu_jiffies)
	sleep "$DURATION"
	cidle=$(cpu_jiffies)
	idle_j=$((cidle - c0))
	c0=$(cpu_jiffies)
	pkts=$(docker run --rm --network "$NET" -v "$OUT:/o" "$PY" python3 /o/flood.py "$V_IP" "$PORT" "$DURATION" "$pps" 2>/dev/null)
	c1=$(cpu_jiffies)
	flood_j=$((c1 - c0))
	[[ -z $pkts || $pkts -eq 0 ]] && { echo "$build,$n,$rate,$rep,fail,fail,fail" >> "$OUT/junk-cost.csv"; return; }
	# CPU us attributable to the flood = (flood - idle) jiffies -> us, / packets
	us_pkt=$(python3 -c "print('%.4f' % (max(0,($flood_j-$idle_j))*1e6/$CLK/$pkts))")
	local flood_cpu_pct
	flood_cpu_pct=$(python3 -c "print('%.1f' % ($flood_j*100.0/$CLK/$DURATION))")
	echo "$build,$n,$rate,$rep,$pkts,$us_pkt,$flood_cpu_pct" >> "$OUT/junk-cost.csv"
	log "$build N=$n rate=$rate rep=$rep: $pkts pkts, ${us_pkt} us/pkt, flood CPU ${flood_cpu_pct}% (idle ${idle_j}j over ${DURATION}s)"
}

# ---- run ------------------------------------------------------------------------
cleanup
docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null
docker image inspect "$PY" >/dev/null 2>&1 || docker pull -q "$PY" >/dev/null 2>&1 || true

BUILDS="shipped=$IMG"
if [[ $CONTROL == 1 ]]; then
	if build_control; then
		BUILDS="$BUILDS controlON=$CONTROL_IMG"
	else
		log "control build failed; running shipped only"
	fi
fi

echo "build,N,rate,repeat,packets,cpu_us_per_pkt,flood_cpu_pct" > "$OUT/junk-cost.csv"
{
	echo "victim $IMG; junk 1300 B to udp/$PORT, first byte < 0x40 (-> obfs keyed check)"
	echo "N peers = well-formed random Ed25519 host records; duration ${DURATION}s x ${REPEATS}; CLK_TCK=$CLK"
	echo "rates: $RATELIST (auto = one max-rate run); builds: $BUILDS"
} > "$OUT/conditions.txt"
for b in $BUILDS; do echo "${b%%=*} ${b#*=} $(docker image inspect "${b#*=}" --format '{{.Id}}' 2>/dev/null)" >> "$OUT/images.txt"; done

for b in $BUILDS; do
	bname=${b%%=*} bimg=${b#*=}
	for n in $NLIST; do
		for rate in $RATELIST; do
			for r in $(seq "$REPEATS"); do
				if ! victim_up "$bimg" "$n"; then
					log "victim did not come up ($bname N=$n)"
					echo "$bname,$n,$rate,$r,fail,fail,fail" >> "$OUT/junk-cost.csv"
					continue
				fi
				measure "$bname" "$n" "$rate" "$r"
				docker rm -f "$PFX-v" >/dev/null 2>&1 || true
			done
		done
	done
done
cleanup

# ---- report & assertions --------------------------------------------------------
python3 - "$OUT/junk-cost.csv" "$OUT" <<'PYEOF' | tee "$OUT/junk-cost.report.txt"
import csv, statistics, sys
rows = [r for r in csv.DictReader(open(sys.argv[1])) if r["cpu_us_per_pkt"] != "fail"]
def med(build, n, rate, field):
    xs = [float(r[field]) for r in rows if r["build"]==build and r["N"]==str(n) and r["rate"]==rate]
    return statistics.median(xs) if xs else None
builds = sorted({r["build"] for r in rows})
Ns = sorted({int(r["N"]) for r in rows})
rates = sorted({r["rate"] for r in rows}, key=lambda x: (x=="auto", x))
print("CPU microseconds per junk packet (median over repeats), and flood-window CPU %%:")
print()
hdr = "build       rate       " + "".join("N=%-10d" % n for n in Ns)
print(hdr)
for b in builds:
    for rate in rates:
        cells=[]
        for n in Ns:
            u = med(b,n,rate,"cpu_us_per_pkt"); c = med(b,n,rate,"flood_cpu_pct")
            cells.append("-" if u is None else "%.2fus/%.0f%%" % (u,c))
        print("%-11s %-10s " % (b, rate) + "".join("%-12s" % c for c in cells))
print()

# Save the medians for the shell to assert on: build rate N us/pkt cpu%
with open(sys.argv[2]+"/medians.txt","w") as f:
    for b in builds:
        for rate in rates:
            for n in Ns:
                u=med(b,n,rate,"cpu_us_per_pkt"); c=med(b,n,rate,"flood_cpu_pct")
                if u is not None:
                    f.write("%s %s %d %.4f %.1f\n"%(b,rate,n,u,c if c is not None else 0))
PYEOF

# Assertions, read from the medians the report wrote (build rate N us/pkt cpu%).
# A max-rate ("auto") flood SATURATES one core, so the kernel drops junk before
# tincd sees it and an O(N) handler shows up as CPU pegged near 100% with only a
# modest per-packet rise, not a clean Nx per-packet blow-up. A sub-saturation
# NUMERIC rate has no drops, so there the O(N) cost per packet shows unmasked.
# So: assert the shipped per-packet cost is bounded in N at every rate; prove
# the meter with the control at a sub-saturation rate (per-packet rises) and/or
# at auto (CPU saturates). A run with only auto still proves it via CPU.
med()  { awk -v b="$1" -v r="$2" -v n="$3" '$1==b&&$2==r&&$3==n{print $4}' "$OUT/medians.txt"; }
medc() { awk -v b="$1" -v r="$2" -v n="$3" '$1==b&&$2==r&&$3==n{print $5}' "$OUT/medians.txt"; }
maxN=$(echo "$NLIST" | tr ' ' '\n' | sort -n | tail -1)
minN=$(echo "$NLIST" | tr ' ' '\n' | sort -n | head -1)
gt() { python3 -c "import sys; sys.exit(0 if float('${1:-0}') $2 float('${3:-0}') else 1)"; }

for rate in $RATELIST; do
	slo=$(med shipped "$rate" "$minN"); shi=$(med shipped "$rate" "$maxN")
	[[ -z $slo || -z $shi ]] && continue
	if gt "$shi" '<=' "$(python3 -c "print(3*$slo+0.5)")"; then
		ok "shipped bounded in N at rate=$rate: N=$minN ${slo}us/pkt -> N=$maxN ${shi}us/pkt (<= 3x)"
	else
		bad "shipped grows with N at rate=$rate: N=$minN ${slo}us/pkt -> N=$maxN ${shi}us/pkt (> 3x): possible O(N) lever"
	fi
done

# Positive control: prove the meter is not simply blind.
if awk '$1=="controlON"' "$OUT/medians.txt" | grep -q .; then
	proven=0
	for rate in $RATELIST; do
		clo=$(med controlON "$rate" "$minN"); chi=$(med controlON "$rate" "$maxN")
		[[ -z $clo || -z $chi ]] && continue
		if [[ $rate == auto ]]; then
			# Saturating flood: the O(N) build should peg the core near 100%
			# while the shipped build (same rate) does not, and per-packet cost
			# still rises. Signal = CPU saturation gap.
			cchi=$(medc controlON auto "$maxN"); cclo=$(medc controlON auto "$minN")
			schi=$(medc shipped auto "$maxN")
			if gt "$cchi" '>=' 90 && gt "$(python3 -c "print($cchi-$schi)")" '>=' 15; then
				ok "control (O(N)) saturates the core at auto: N=$maxN CPU ${cchi}% vs shipped ${schi}%, per-pkt ${clo}->${chi}us (meter works)"
				proven=1
			else
				log "control at auto: N=$minN->$maxN ${clo}->${chi}us, CPU ${cclo}%->${cchi}% (informational; saturation masks per-pkt)"
			fi
		else
			# Sub-saturation: the O(N) per-packet cost shows unmasked.
			if gt "$chi" '>' "$(python3 -c "print(2*$clo)")"; then
				ok "control (O(N)) rises with N at rate=$rate: N=$minN ${clo}us/pkt -> N=$maxN ${chi}us/pkt (> 2x, meter works)"
				proven=1
			else
				bad "control (O(N)) did NOT rise with N at sub-saturation rate=$rate ($clo -> $chi): meter suspect, distrust the shipped PASS"
			fi
		fi
	done
	[[ $proven -eq 1 ]] || bad "the O(N) control never showed a rise at any rate: the meter is unproven, so the shipped PASS is not trustworthy"
else
	log "no control build ran; shipped result is unguarded (set CONTROL=1)"
fi

cat "$OUT/conditions.txt" >> "$OUT/junk-cost.report.txt"
log "results in $OUT"
if [[ $FAILED -eq 0 ]]; then log "junk-cost: all checks passed"; else log "junk-cost: FAILURES above"; fi
exit "$FAILED"

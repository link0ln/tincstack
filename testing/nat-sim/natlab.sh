#!/usr/bin/env bash
# tincstack NAT lab — runs INSIDE the privileged lab container
# (tincstack/natlab). Builds the topology from network namespaces + veth pairs,
# applies NAT profiles on the gateway namespaces, runs tincd (core or upstream
# baseline binaries) in the node namespaces and judges the outcome.
# Driven from the host by testing/nat-sim/lab.sh; see README.md.
#
#   natlab validate-nat
#   natlab scenario A_TYPE B_TYPE [opts]
#   natlab matrix [--quick] [opts]
#   natlab laptop [opts]
#   natlab glare [opts]            (--image-b IMG: nodeb runs the other binary)
#
# opts: --image core|baseline|both  --image-b core|baseline  --out DIR  --rtt MS
#       --wait S  --recover S
#       --pause S  --cgnat-udp-timeout S  --cgnat-udp-stream-timeout S
set -euo pipefail

CORE_TINCD=/usr/local/sbin/tincd;      CORE_TINC=/usr/local/sbin/tinc
BASE_TINCD=/opt/baseline/sbin/tincd;   BASE_TINC=/opt/baseline/sbin/tinc
LAB=/lab; RUN=$LAB/run; NODES=$LAB/nodes; LOGS=$LAB/logs

# Address plan (RFC 6598 100.64/10 plays "the internet")
RELAY_IP=100.64.0.10; GWA_EXT=100.64.0.2; GWB_EXT=100.64.0.3; GWL2_EXT=100.64.0.4
PROBE_IP1=100.64.0.20; PROBE_IP2=100.64.0.21
GWA_INT=192.168.110.254; NODEA_IP=192.168.110.5
GWB_INT=192.168.120.254; NODEB_IP=192.168.120.5
GWL1_INT=192.168.130.254; NODEL_IP=192.168.130.5
GWL2_INT=10.200.0.254; GWL1_EXT=10.200.0.2
VPN_RELAY=10.77.0.1; VPN_A=10.77.0.2; VPN_B=10.77.0.3; VPN_L=10.77.0.4
TINC_PORT=655
MAP_A=40655; MAP_B=41655            # static external ports of the cone profiles

IMAGE_SEL=""; IMAGE_B=""; OUT=/lab/results; RTT=0; WAIT=90; RECOVER=60; PAUSE=70; QUICK=0
CGNAT_UDP_TO=10; CGNAT_UDP_STO=30

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { log "ERROR: $*"; exit 2; }

parse_opts() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --image) IMAGE_SEL="$2"; shift 2 ;;
            --image-b) IMAGE_B="$2"; shift 2 ;;
            --out) OUT="$2"; shift 2 ;;
            --rtt) RTT="$2"; shift 2 ;;
            --wait) WAIT="$2"; shift 2 ;;
            --recover) RECOVER="$2"; shift 2 ;;
            --pause) PAUSE="$2"; shift 2 ;;
            --cgnat-udp-timeout) CGNAT_UDP_TO="$2"; shift 2 ;;
            --cgnat-udp-stream-timeout) CGNAT_UDP_STO="$2"; shift 2 ;;
            --quick) QUICK=1; shift ;;
            *) die "unknown option $1" ;;
        esac
    done
}

# ---------------------------------------------------------------- netns topology
ns() { ip netns exec "$@"; }
ns_add() { for n in "$@"; do ip netns add "$n"; ns "$n" ip link set lo up; done; }

# veth NS1 IF1 IP1/PL NS2 IF2 IP2/PL  (NS "root" = the container namespace)
veth() {
    local n1="$1" i1="$2" a1="$3" n2="$4" i2="$5" a2="$6"
    # create under unique temporary names (the container root ns already owns
    # an eth0), then move+rename each end into its namespace
    ip link add "v$$a" type veth peer name "v$$b"
    if [ "$n1" = root ]; then ip link set "v$$a" name "$i1"; else ip link set "v$$a" netns "$n1" name "$i1"; fi
    if [ "$n2" = root ]; then ip link set "v$$b" name "$i2"; else ip link set "v$$b" netns "$n2" name "$i2"; fi
    _cfg() { if [ "$1" = root ]; then ip addr add "$3" dev "$2"; ip link set "$2" up;
             else ns "$1" ip addr add "$3" dev "$2"; ns "$1" ip link set "$2" up; fi; }
    [ "$a1" = - ] || _cfg "$n1" "$i1" "$a1"
    [ "$a2" = - ] || _cfg "$n2" "$i2" "$a2"
}
# attach NS IF IP/PL -> veth from NS to the "internet" bridge br0 (root ns)
attach() {
    local pif="br-$1"
    veth "$1" "$2" "$3" root "$pif" -
    ip link set "$pif" master br0 up
}

teardown() {
    pkill -x tincd 2>/dev/null || true
    pkill -f "udpprobe server" 2>/dev/null || true
    pkill -x ping 2>/dev/null || true
    sleep 0.3
    for n in $(ip netns list 2>/dev/null | awk '{print $1}'); do ip netns del "$n" 2>/dev/null || true; done
    ip link del br0 2>/dev/null || true
    rm -rf "$RUN" "$NODES" "$LOGS"
    mkdir -p "$RUN" "$NODES" "$LOGS"
}

internet_up() {
    ip link add br0 type bridge
    ip link set br0 up
    # Keep the in-container bridge purely L2 (per-netns sysctl; absent if the
    # br_netfilter module is not loaded, in which case it is already L2-only).
    sysctl -qw net.bridge.bridge-nf-call-iptables=0 2>/dev/null || true
    ns_add relay
    attach relay eth0 "$RELAY_IP/24"
}
# gw_up NAME EXT_IF_ADDR INT_IF_ADDR NODE NODE_ADDR  (all ext on br0)
gw_up() {
    ns_add "$1" "$4"
    attach "$1" ext "$2/24"
    veth "$1" int "$3/24" "$4" eth0 "$5/24"
    ns "$4" ip route add default via "$3"
}
gw_nat() { # ns type ext_ip int_ip [extra natprofile args]
    local name="$1" type="$2" ext="$3" int="$4"; shift 4
    ns "$name" natprofile "$type" --ext-ip "$ext" --int-ip "$int" --rtt-ms "$RTT" "$@"
}

# ---------------------------------------------------------------- tinc
tincd_bin() { case "$1" in core) echo "$CORE_TINCD" ;; baseline) echo "$BASE_TINCD" ;; *) die "bad image $1" ;; esac; }
tinc_bin()  { case "$1" in core) echo "$CORE_TINC" ;; baseline) echo "$BASE_TINC" ;; *) die "bad image $1" ;; esac; }

# write_node NAME VPN_IP [extra tinc.conf lines...]
write_node() {
    local name="$1" vpnip="$2"; shift 2
    local d="$NODES/$name"
    mkdir -p "$d/hosts"
    {
        echo "Name = $name"
        echo "Mode = router"
        echo "Port = $TINC_PORT"
        echo "AddressFamily = ipv4"
        echo "PingInterval = 10"
        echo "PingTimeout = 5"
        for l in "$@"; do echo "$l"; done
    } > "$d/tinc.conf"
    printf 'Subnet = %s/32\n' "$vpnip" > "$d/hosts/$name"
    if [ "$name" = relay ]; then
        printf 'Address = %s\nPort = %s\n' "$RELAY_IP" "$TINC_PORT" >> "$d/hosts/$name"
    fi
    # shellcheck disable=SC2016  # $INTERFACE is expanded by tincd, not here
    printf '#!/bin/sh\nip link set "$INTERFACE" up\nip addr add %s/24 dev "$INTERFACE"\n' "$vpnip" > "$d/tinc-up"
    chmod +x "$d/tinc-up"
    # Keys: generated by the core CLI in classic mode (format identical for both
    # daemons); they exist only inside this container and never reach results/.
    "$CORE_TINC" -c "$d" generate-keys >/dev/null 2>&1
}
share_hosts() {
    local n m
    for n in "$NODES"/*; do
        for m in "$NODES"/*; do
            [ "$n" = "$m" ] || cp "$m/hosts/$(basename "$m")" "$n/hosts/"
        done
    done
}
CUR_IMG=core
# Per-node image override (mixed pairs): NODE_IMG_<name>=core|baseline wins
# over CUR_IMG for that node only; used by `glare --image-b`.
node_img() { local v="NODE_IMG_$1"; echo "${!v:-$CUR_IMG}"; }
tinc_start() { # NAME  -> starts tincd in netns NAME, pid in $RUN/NAME.pid
    local name="$1"
    # exec so that $! is the `ip netns exec` process, which execs tincd itself:
    # SIGSTOP/SIGCONT and kill -0 must hit the daemon, not a wrapper subshell.
    ( exec ip netns exec "$name" "$(tincd_bin "$(node_img "$name")")" -D -d5 -c "$NODES/$name" --pidfile "$RUN/$name.pid" \
        >> "$LOGS/$name.log" 2>&1 ) &
    echo $! > "$RUN/$name.ospid"
}
tinc_pid() { cat "$RUN/$1.ospid"; }
tinc_stop() { local p; p="$(tinc_pid "$1")"; kill -TERM "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; }
tincctl() { "$(tinc_bin "$(node_img "$1")")" -c "$NODES/$1" --pidfile "$RUN/$1.pid" "${@:2}"; }
reach() { tincctl "$1" info "$2" 2>/dev/null | awk -F': *' '/^Reachability:/{print $2}'; }

# wait_direct NODE PEER MAXS -> prints seconds taken, exit 1 on timeout
wait_direct() {
    local t0 t r
    t0=$(date +%s)
    while :; do
        r="$(reach "$1" "$2" || true)"
        t=$(( $(date +%s) - t0 ))
        if [ "$r" = "directly with UDP" ]; then echo "$t"; return 0; fi
        [ "$t" -ge "$3" ] && { echo "$t"; return 1; }
        sleep 2
    done
}
ping_ok() { ns "$1" ping -c 3 -W 2 -i 0.5 "$2" >/dev/null 2>&1; }
# wait_recover NODE PEER PEER_VPN_IP MAXS -> seconds until `info` says direct
# UDP *and* a ping over the tunnel is answered (a stale "directly with UDP"
# from before a peer restart / sleep does not count: the SPTPS session must be
# usable again). Exit 1 on timeout.
wait_recover() {
    local t0 t r
    t0=$(date +%s)
    while :; do
        r="$(reach "$1" "$2" || true)"
        t=$(( $(date +%s) - t0 ))
        if [ "$r" = "directly with UDP" ] && ns "$1" ping -c 1 -W 1 "$3" >/dev/null 2>&1; then echo "$t"; return 0; fi
        [ "$t" -ge "$4" ] && { echo "$t"; return 1; }
        sleep 2
    done
}
bg_ping() { ns "$1" ping -i 1 "$2" >/dev/null 2>&1 & }

save_state() { # dir node...
    local d="$1"; mkdir -p "$d"
    for n in "${@:2}"; do
        cp "$LOGS/$n.log" "$d/$n.log" 2>/dev/null || true
        { tincctl "$n" dump nodes; echo; tincctl "$n" dump edges; } > "$d/$n.dump.txt" 2>&1 || true
    done
}
save_gw() { # dir gw...
    for g in "${@:2}"; do
        { ns "$g" iptables -S; echo; ns "$g" iptables -t nat -S; echo;
          ns "$g" conntrack -L 2>/dev/null || true; } > "$1/gw-$g.txt" 2>&1 || true
    done
}

# ---------------------------------------------------------------- validate-nat
# Prove each NAT profile with the udpprobe classifier before trusting any tinc
# result: the classification must equal the declared profile.
validate_nat() {
    local d="$OUT/validate-nat"; mkdir -p "$d"
    teardown; internet_up
    ns_add probe
    attach probe eth0 "$PROBE_IP1/24"
    ns probe ip addr add "$PROBE_IP2/24" dev eth0
    ns probe udpprobe server --ip1 "$PROBE_IP1" --ip2 "$PROBE_IP2" > "$d/probe-server.log" 2>&1 &
    gw_up gwa "$GWA_EXT" "$GWA_INT" client "$NODEA_IP"
    sleep 0.5
    local fail=0 t sport=4000 out rc
    : > "$d/udpprobe.jsonl"
    for t in fullcone restricted portrestricted masq symmetric udpblock; do
        sport=$((sport + 1))   # fresh inside port per profile: no conntrack carry-over
        local extra=()
        case "$t" in
            fullcone|restricted|portrestricted)
                gw_nat gwa "$t" "$GWA_EXT" "$GWA_INT" --inside "$NODEA_IP" --map "$MAP_A:$sport" >> "$d/gw.log"
                extra=(--expect-ext-port "$MAP_A") ;;
            *)  gw_nat gwa "$t" "$GWA_EXT" "$GWA_INT" >> "$d/gw.log" ;;
        esac
        rc=0
        out="$(ns client udpprobe client --sport "$sport" --server "$PROBE_IP1" --server2 "$PROBE_IP2" --expect "$t" "${extra[@]}")" || rc=$?
        echo "$t: $out" | tee -a "$d/udpprobe.jsonl"
        if [ "$rc" -ne 0 ]; then log "NAT profile $t: emulation does NOT behave as declared"; fail=1; fi
    done
    teardown
    if [ "$fail" -eq 0 ]; then log "validate-nat: all 6 profiles behave as declared"; else log "validate-nat: FAILED"; fi
    cp "$d/udpprobe.jsonl" "$OUT/validate-nat.jsonl" 2>/dev/null || true
    return "$fail"
}

# ---------------------------------------------------------------- pair scenario
# Which pairs can hole-punch at all (RFC 5128 §3.3 logic, tinc does no port
# prediction): an address-and-port-dependent *mapping* (symmetric, and masq as
# measured on this kernel) cannot meet an address-and-port-dependent *filter*
# (portrestricted, symmetric, masq); every other pair can. udpblock pairs must
# still carry traffic over TCP.
expect_direct() { # a b -> yes|no|tcp
    case "$1/$2" in
        *udpblock*) echo tcp ;;
        symmetric/symmetric|symmetric/masq|masq/symmetric|masq/masq) echo no ;;
        symmetric/portrestricted|portrestricted/symmetric|masq/portrestricted|portrestricted/masq) echo no ;;
        *) echo yes ;;
    esac
}
profile_args() { # type inside_ip map_ext
    case "$1" in
        fullcone|restricted|portrestricted) echo "--inside $2 --map $3:$TINC_PORT" ;;
        *) echo "" ;;
    esac
}

scenario_run() { # A_TYPE B_TYPE IMAGE OUTDIR -> 0 pass / 1 fail
    local ta="$1" tb="$2" img="$3" d="$4"
    CUR_IMG="$img"; mkdir -p "$d"
    teardown; internet_up
    write_node relay "$VPN_RELAY"
    write_node nodea "$VPN_A" "ConnectTo = relay" "UDPDiscoveryBurst = 5"
    write_node nodeb "$VPN_B" "ConnectTo = relay" "UDPDiscoveryBurst = 5"
    share_hosts
    gw_up gwa "$GWA_EXT" "$GWA_INT" nodea "$NODEA_IP"
    gw_up gwb "$GWB_EXT" "$GWB_INT" nodeb "$NODEB_IP"
    # shellcheck disable=SC2046
    gw_nat gwa "$ta" "$GWA_EXT" "$GWA_INT" $(profile_args "$ta" "$NODEA_IP" "$MAP_A") > "$d/gw-setup.txt"
    # shellcheck disable=SC2046
    gw_nat gwb "$tb" "$GWB_EXT" "$GWB_INT" $(profile_args "$tb" "$NODEB_IP" "$MAP_B") >> "$d/gw-setup.txt"
    tinc_start relay; sleep 1
    tinc_start nodea; tinc_start nodeb
    sleep 2
    # Traffic is driven from A only. Pinging from both sides at once makes both
    # nodes send REQ_KEY simultaneously, which tinc 1.1 (upstream and core)
    # cannot resolve without a 10/30 s cooldown round (see `natlab glare` and
    # PLAN.md "Found during M9"); that would measure the glare, not the NAT.
    bg_ping nodea "$VPN_B"
    local t_ab t_ba ok_ab=1 ok_ba=1 r_ab r_ba
    t_ab="$(wait_direct nodea nodeb "$WAIT")" || ok_ab=0
    t_ba="$(wait_direct nodeb nodea "$((WAIT > t_ab ? WAIT - t_ab : 5))")" || ok_ba=0
    r_ab="$(reach nodea nodeb || true)"; r_ba="$(reach nodeb nodea || true)"
    local ping=1; ping_ok nodea "$VPN_B" && ping_ok nodeb "$VPN_A" || ping=0
    local exp verdict direct=0
    exp="$(expect_direct "$ta" "$tb")"
    [ "$ok_ab" -eq 1 ] && [ "$ok_ba" -eq 1 ] && direct=1
    case "$exp" in
        yes) if [ "$direct" -eq 1 ] && [ "$ping" -eq 1 ]; then verdict=PASS; else verdict=FAIL; fi ;;
        no)  if [ "$ping" -eq 1 ]; then verdict=PASS; else verdict=FAIL; fi ;;   # relay path must carry traffic
        tcp) if [ "$ping" -eq 1 ] && [ "$direct" -eq 0 ]; then verdict=PASS; else verdict=FAIL; fi ;;
    esac
    tincctl nodea info nodeb > "$d/nodea.info.txt" 2>&1 || true
    tincctl nodeb info nodea > "$d/nodeb.info.txt" 2>&1 || true
    save_state "$d" relay nodea nodeb
    save_gw "$d" gwa gwb
    printf '{"a":"%s","b":"%s","image":"%s","rtt_ms":%s,"expected":"%s","direct_ab":%s,"direct_ba":%s,"t_ab":%s,"t_ba":%s,"reach_ab":"%s","reach_ba":"%s","ping":%s,"verdict":"%s"}\n' \
        "$ta" "$tb" "$img" "$RTT" "$exp" "$ok_ab" "$ok_ba" "$t_ab" "$t_ba" "$r_ab" "$r_ba" "$ping" "$verdict" > "$d/result.json"
    log "scenario $ta x $tb [$img]: $verdict (expected=$exp direct a->b=$ok_ab/${t_ab}s b->a=$ok_ba/${t_ba}s ping=$ping reach=[$r_ab | $r_ba])"
    teardown
    [ "$verdict" = PASS ]
}

scenario() {
    local ta="$1" tb="$2"; shift 2; parse_opts "$@"
    scenario_run "$ta" "$tb" "${IMAGE_SEL:-core}" "$OUT/pair-$ta-$tb/${IMAGE_SEL:-core}"
}

MATRIX_TYPES=(fullcone restricted portrestricted masq symmetric)
matrix() {
    parse_opts "$@"
    local imgs fail=0 a b i p
    case "${IMAGE_SEL:-both}" in both) imgs="core baseline" ;; *) imgs="$IMAGE_SEL" ;; esac
    mkdir -p "$OUT"
    local pairs=()
    if [ "$QUICK" -eq 1 ]; then
        pairs=(fullcone/fullcone portrestricted/portrestricted masq/restricted symmetric/symmetric udpblock/portrestricted)
    else
        for a in "${MATRIX_TYPES[@]}"; do for b in "${MATRIX_TYPES[@]}"; do pairs+=("$a/$b"); done; done
        pairs+=(udpblock/fullcone udpblock/portrestricted udpblock/udpblock)
    fi
    for i in $imgs; do
        for p in "${pairs[@]}"; do
            a="${p%/*}"; b="${p#*/}"
            scenario_run "$a" "$b" "$i" "$OUT/pair-$a-$b/$i" || fail=1
        done
    done
    summarize
    return "$fail"
}

summarize() {
    local f
    {
        echo "# NAT lab summary — $(date -u +%Y-%m-%dT%H:%MZ)"
        echo
        echo "Cell = seconds until \`tinc info <peer>\` reported *directly with UDP* on that side; \`-\` = never within the wait. \`expected\` = yes (direct UDP must come up), no (pair cannot hole-punch: traffic must still flow via the relay), tcp (UDP blocked: meta/TCP path must carry traffic)."
        echo
        echo "| A x B | image | expected | direct a->b | direct b->a | ping | verdict |"
        echo "|---|---|---|---|---|---|---|"
        for f in "$OUT"/pair-*/*/result.json; do
            [ -f "$f" ] || continue
            python3 - "$f" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
da=f"{r['t_ab']}s" if r['direct_ab'] else "-"
db=f"{r['t_ba']}s" if r['direct_ba'] else "-"
print(f"| {r['a']} x {r['b']} | {r['image']} | {r['expected']} | {da} | {db} | {'ok' if r['ping'] else 'FAIL'} | {r['verdict']} |")
PY
        done
        if [ -f "$OUT/laptop/summary.md" ]; then echo; cat "$OUT/laptop/summary.md"; fi
        if [ -f "$OUT/glare/summary.md" ]; then echo; cat "$OUT/glare/summary.md"; fi
        if [ -f "$OUT/validate-nat/udpprobe.jsonl" ]; then
            echo; echo "## NAT emulation self-check (udpprobe)"; echo; echo '```'
            cat "$OUT/validate-nat/udpprobe.jsonl"; echo '```'
        fi
    } > "$OUT/summary.md"
    cat "$OUT/summary.md"
}

# ---------------------------------------------------------------- laptop regression
# L behind two-tier CGNAT (home router masq -> carrier masq with short conntrack
# windows), P (= nodeb) behind restricted-cone, R public.
laptop_run() { # IMAGE OUTDIR -> 0 pass
    local img="$1" d="$2"
    CUR_IMG="$img"; mkdir -p "$d"
    teardown; internet_up
    write_node relay "$VPN_RELAY"
    write_node nodeb "$VPN_B" "ConnectTo = relay" "UDPDiscoveryBurst = 5"
    write_node nodel "$VPN_L" "ConnectTo = relay" "UDPDiscoveryBurst = 5" "UDPRebindOnWake = yes"
    share_hosts
    gw_up gwb "$GWB_EXT" "$GWB_INT" nodeb "$NODEB_IP"
    # carrier tier: ext on br0, int towards the home router
    ns_add gwl2 gwl1 nodel
    attach gwl2 ext "$GWL2_EXT/24"
    veth gwl2 int "$GWL2_INT/24" gwl1 ext "$GWL1_EXT/24"
    ns gwl1 ip route add default via "$GWL2_INT"
    veth gwl1 int "$GWL1_INT/24" nodel eth0 "$NODEL_IP/24"
    ns nodel ip route add default via "$GWL1_INT"
    gw_nat gwb restricted "$GWB_EXT" "$GWB_INT" --inside "$NODEB_IP" --map "$MAP_B:$TINC_PORT" > "$d/gw-setup.txt"
    gw_nat gwl1 masq "$GWL1_EXT" "$GWL1_INT" >> "$d/gw-setup.txt"
    gw_nat gwl2 masq "$GWL2_EXT" "$GWL2_INT" --udp-timeout "$CGNAT_UDP_TO" --udp-stream-timeout "$CGNAT_UDP_STO" >> "$d/gw-setup.txt"
    tinc_start relay; sleep 1
    tinc_start nodeb; tinc_start nodel
    sleep 2
    bg_ping nodel "$VPN_B"      # the laptop drives traffic; P only answers

    local res=() overall=PASS t ok
    stage_result() { # name ok seconds note
        res+=("$1|$2|$3|$4")
        log "laptop [$img] stage $1: $([ "$2" -eq 1 ] && echo ok || echo FAIL) (${3}s) $4"
        [ "$2" -eq 1 ] || overall=FAIL
    }
    # stage 0: precondition — direct UDP up both ways
    ok=1; t="$(wait_recover nodel nodeb "$VPN_B" "$WAIT")" || ok=0
    [ "$ok" -eq 1 ] && { wait_direct nodeb nodel 30 >/dev/null || ok=0; }
    stage_result setup "$ok" "$t" "direct L<->P through 2-tier CGNAT / restricted-cone"
    if [ "$ok" -eq 0 ]; then
        overall=SETUP-FAIL
    else
        echo "=== stage a: peer restart $(date +%T) ===" >> "$LOGS/nodel.log"
        # stage a: peer P restarts its tincd (same config)
        tinc_stop nodeb; sleep 1; tinc_start nodeb
        ok=1; t="$(wait_recover nodel nodeb "$VPN_B" "$RECOVER")" || ok=0
        stage_result peer-restart "$ok" "$t" "P's tincd restarted; L must re-establish direct UDP"

        # stage b: simulated sleep/resume of L: the process is frozen with
        # SIGSTOP for PAUSE seconds; tincd's 1-second timer then sees a gap
        # > 2*UDPDiscoveryTimeout (60 s) and takes its wake-from-sleep path
        # ("Awaking from dead"), which is where UDPRebindOnWake hooks in.
        echo "=== stage b: SIGSTOP ${PAUSE}s $(date +%T) ===" >> "$LOGS/nodel.log"
        kill -STOP "$(tinc_pid nodel)"; sleep "$PAUSE"; kill -CONT "$(tinc_pid nodel)"
        ok=1; t="$(wait_recover nodel nodeb "$VPN_B" "$RECOVER")" || ok=0
        stage_result sleep-resume "$ok" "$t" "L frozen ${PAUSE}s (SIGSTOP/SIGCONT), then resumed"

        # stage c: sleep again; while asleep L's NAT mapping goes bad: the
        # carrier tier's conntrack is flushed and, because the kernel cannot
        # emulate a mapping that *stays* filtered, the home tier black-holes
        # every inbound datagram to L's old inside socket (post-de-NAT
        # dst = L:oldport). That is the field symptom of the "stuck mapping":
        # the old socket never receives again, a fresh socket (=> fresh
        # mapping) punches through immediately. Only UDPRebindOnWake gives
        # tincd a fresh socket without a process restart.
        local oldport newport
        oldport="$(ns nodel ss -Hunl | awk '{print $4}' | grep -oE '[0-9]+$' | head -1 || true)"
        ns gwl2 conntrack -L > "$d/gwl2-conntrack-before-stage-c.txt" 2>/dev/null || true
        echo "=== stage c: SIGSTOP ${PAUSE}s + mapping dropped (L inside port ${oldport:-?}) $(date +%T) ===" >> "$LOGS/nodel.log"
        kill -STOP "$(tinc_pid nodel)"
        ns gwl2 conntrack -F >/dev/null 2>&1 || true
        ns gwl1 conntrack -F >/dev/null 2>&1 || true
        [ -n "$oldport" ] && ns gwl1 iptables -I FORWARD 1 -i ext -p udp -d "$NODEL_IP" --dport "$oldport" -j DROP
        sleep "$PAUSE"; kill -CONT "$(tinc_pid nodel)"
        ok=1; t="$(wait_recover nodel nodeb "$VPN_B" "$RECOVER")" || ok=0
        newport="$(ns nodel ss -Hunl | awk '{print $4}' | grep -oE '[0-9]+$' | head -1 || true)"
        echo "L UDP socket port before stage c: ${oldport:-?}, after: ${newport:-?}" > "$d/nodel-udp-port.txt"
        stage_result mapping-dropped "$ok" "$t" "L frozen ${PAUSE}s; NAT conntrack flushed, inbound to L's old socket (port ${oldport:-?}) black-holed; L's port after: ${newport:-?}"
    fi
    local ping=1; ping_ok nodel "$VPN_B" || ping=0
    tincctl nodel info nodeb > "$d/nodel.info.txt" 2>&1 || true
    save_state "$d" relay nodeb nodel
    save_gw "$d" gwb gwl1 gwl2
    # log signatures of the livelock the SPTPS patch removes
    local seqno reqkey awake rebound alive
    seqno="$(cat "$d"/*.log | grep -c "Invalid packet seqno" || true)"
    reqkey="$(cat "$d"/*.log | grep -c "while we already started a SPTPS session" || true)"
    awake="$(grep -c "Awaking from dead" "$d/nodel.log" || true)"
    rebound="$(grep -c "Rebound UDP socket" "$d/nodel.log" || true)"
    alive=0; kill -0 "$(tinc_pid nodel)" 2>/dev/null && alive=1
    [ "$seqno" -gt 20 ] && overall=FAIL
    [ "$reqkey" -gt 20 ] && overall=FAIL
    [ "$alive" -eq 1 ] || overall=FAIL
    {
        echo "## Laptop regression — image: $img (rtt=${RTT}ms, CGNAT udp conntrack timeouts ${CGNAT_UDP_TO}/${CGNAT_UDP_STO}s, pause=${PAUSE}s, recover budget ${RECOVER}s)"
        echo
        echo "| stage | result | seconds | note |"
        echo "|---|---|---|---|"
        local r n o s note
        for r in "${res[@]}"; do IFS='|' read -r n o s note <<<"$r"; echo "| $n | $([ "$o" -eq 1 ] && echo ok || echo FAIL) | $s | $note |"; done
        echo
        echo "- tunnel ping L->P after all stages (any path): $([ "$ping" -eq 1 ] && echo ok || echo FAIL)"
        echo "- \`Invalid packet seqno\` lines (all logs): $seqno; \`Got REQ_KEY ... already started a SPTPS session\` lines: $reqkey (livelock threshold: > 20 either)"
        echo "- L: \`Awaking from dead\` events: $awake; \`Rebound UDP socket\` events: $rebound; same tincd process throughout: $([ "$alive" -eq 1 ] && echo yes || echo NO)"
        echo "- **verdict: $overall**"
    } > "$d/summary.md"
    printf '{"image":"%s","verdict":"%s","ping":%s,"seqno_lines":%s,"reqkey_lines":%s,"awake":%s,"rebound":%s,"stages":"%s"}\n' \
        "$img" "$overall" "$ping" "$seqno" "$reqkey" "$awake" "$rebound" "${res[*]}" > "$d/result.json"
    cat "$d/summary.md"
    teardown
    [ "$overall" = PASS ]
}

laptop() {
    parse_opts "$@"
    local imgs fail=0 i d="$OUT/laptop"
    case "${IMAGE_SEL:-both}" in both) imgs="core baseline" ;; *) imgs="$IMAGE_SEL" ;; esac
    mkdir -p "$d"
    for i in $imgs; do laptop_run "$i" "$d/$i" || fail=1; done
    { for i in $imgs; do cat "$d/$i/summary.md"; echo; done; } > "$d/summary.md"
    return "$fail"
}

# ---------------------------------------------------------------- glare
# Both nodes (full-cone, public relay) start sending to each other at the same
# moment, so both send REQ_KEY at once. Measures the time until the SPTPS key
# exchange succeeds and counts the "Invalid packet seqno" / "REQ_KEY ... while
# we already started" rounds. Informative for the core-vs-baseline delta of the
# 30 s cooldown; the verdict is PASS when a key is established within --wait.
glare_run() { # IMAGE OUTDIR   (nodeb runs $IMAGE_B when set: mixed pair)
    local img="$1" d="$2" label="$1"
    CUR_IMG="$img"; mkdir -p "$d"
    # shellcheck disable=SC2034  # read through indirect expansion in node_img
    NODE_IMG_nodeb="${IMAGE_B:-$img}"
    [ -z "$IMAGE_B" ] || label="$img x $IMAGE_B"
    teardown; internet_up
    write_node relay "$VPN_RELAY"
    write_node nodea "$VPN_A" "ConnectTo = relay" "UDPDiscoveryBurst = 5"
    write_node nodeb "$VPN_B" "ConnectTo = relay" "UDPDiscoveryBurst = 5"
    share_hosts
    gw_up gwa "$GWA_EXT" "$GWA_INT" nodea "$NODEA_IP"
    gw_up gwb "$GWB_EXT" "$GWB_INT" nodeb "$NODEB_IP"
    gw_nat gwa fullcone "$GWA_EXT" "$GWA_INT" --inside "$NODEA_IP" --map "$MAP_A:$TINC_PORT" > "$d/gw-setup.txt"
    gw_nat gwb fullcone "$GWB_EXT" "$GWB_INT" --inside "$NODEB_IP" --map "$MAP_B:$TINC_PORT" >> "$d/gw-setup.txt"
    tinc_start relay; sleep 1
    tinc_start nodea; tinc_start nodeb
    sleep 3                                   # both meta connections up
    bg_ping nodea "$VPN_B"; bg_ping nodeb "$VPN_A"
    local t0 t ok=0
    t0=$(date +%s)
    while :; do
        t=$(( $(date +%s) - t0 ))
        if grep -q "SPTPS key exchange with nodeb .* successful" "$LOGS/nodea.log" 2>/dev/null; then ok=1; break; fi
        [ "$t" -ge "$WAIT" ] && break
        sleep 1
    done
    local seqno reqkey restarts
    save_state "$d" relay nodea nodeb
    seqno="$(cat "$d"/nodea.log "$d"/nodeb.log | grep -c "Invalid packet seqno" || true)"
    # glare lines: the stock "already started" message and the core's tie-break message (patch 5)
    reqkey="$(cat "$d"/nodea.log "$d"/nodeb.log | grep -c "while we already started a SPTPS session\|glare tie-break" || true)"
    restarts="$(cat "$d"/nodea.log "$d"/nodeb.log | grep -c "restarting SPTPS" || true)"
    local verdict=FAIL; [ "$ok" -eq 1 ] && verdict=PASS
    printf '{"image":"%s","verdict":"%s","t_key":%s,"seqno_lines":%s,"reqkey_lines":%s,"sptps_restarts":%s}\n' \
        "$label" "$verdict" "$t" "$seqno" "$reqkey" "$restarts" > "$d/result.json"
    unset NODE_IMG_nodeb
    log "glare [$label]: $verdict key after ${t}s, seqno-errors=$seqno glare-lines=$reqkey sptps-restarts=$restarts"
    teardown
    [ "$ok" -eq 1 ]
}
glare() {
    parse_opts "$@"
    local imgs fail=0 i d="$OUT/glare"
    case "${IMAGE_SEL:-both}" in both) imgs="core baseline" ;; *) imgs="$IMAGE_SEL" ;; esac
    local sub=""; [ -z "$IMAGE_B" ] || sub="-x-$IMAGE_B"
    mkdir -p "$d"
    for i in $imgs; do glare_run "$i" "$d/$i$sub" || fail=1; done
    {
        echo "## REQ_KEY glare (both sides initiate at once; full-cone x full-cone)"
        echo
        echo "| image | key established after | \`Invalid packet seqno\` | glare lines | SPTPS restarts | verdict |"
        echo "|---|---|---|---|---|---|"
        for i in $imgs; do
            python3 - "$d/$i$sub/result.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
print(f"| {r['image']} | {r['t_key']}s | {r['seqno_lines']} | {r['reqkey_lines']} | {r['sptps_restarts']} | {r['verdict']} |")
PY
        done
    } > "$d/summary.md"
    cat "$d/summary.md"
    return "$fail"
}

# ---------------------------------------------------------------- main
mkdir -p "$RUN" "$NODES" "$LOGS"
# Both binaries must actually run (a baseline CLI missing a shared library once
# made every `info` poll fail and turned a working tunnel into SETUP-FAIL).
for b in "$CORE_TINCD" "$CORE_TINC" "$BASE_TINCD" "$BASE_TINC"; do
    "$b" --version >/dev/null 2>&1 || die "$b does not run: $("$b" --version 2>&1 | head -1)"
done
cmd="${1:-}"; shift || true
case "$cmd" in
    validate-nat) parse_opts "$@"; validate_nat ;;
    scenario) scenario "$@" ;;
    matrix) matrix "$@" ;;
    laptop) laptop "$@" ;;
    glare) glare "$@" ;;
    summarize) parse_opts "$@"; summarize ;;
    shell) exec bash ;;
    *) sed -n '2,16p' "$0"; exit 2 ;;
esac

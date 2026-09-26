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
#   natlab mesh [opts]             relay + N NATed nodes, every pair pings
#                                  (--nodes "t1 t2 ...", --relay-down S)
#   natlab rekey A_TYPE B_TYPE     direct pair under frequent SPTPS rekeys
#                                  (--keyexpire S, --duration S)
#   natlab portmap                 NAT port-allocation map (nattrav, no tinc)
#   natlab punch A_TYPE B_TYPE     hole-punch strategies (nattrav, no tinc;
#                                  --trials N, --strategies "first second ...",
#                                  --spray N: also send to N ports around the
#                                  peer's advertised port, --sync: both sides
#                                  start on the rendezvous' GO, --rtt MS)
#
# opts: --image core|baseline|both  --image-b core|baseline  --out DIR  --rtt MS
#       --wait S  --recover S  --expect clean|defect|any  --clean-max S
#       --pause S  --cgnat-udp-timeout S  --cgnat-udp-stream-timeout S
#       --transport CARRIER (PreferredTransports of the NATed nodes, e.g. quic)
#       --pairs "a/b c/d" (matrix subset)
#       --capture (scenario/matrix: pcap of the A<->B datagrams on gwa's
#       external side + the dpi-proof fingerprint report, peer.report.txt)
#       --ipv6 both|a|b (scenario/matrix: that side also gets global IPv6 behind a
#       stateful, non-translating firewall; the relay is dual-stack)
# Type `cgnat' (scenario/matrix/mesh/punch) = two tiers of stock MASQUERADE,
# the carrier tier with the short --cgnat-udp-* conntrack windows.
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
# glare grading: what a run must look like, and how fast "clean" has to be.
EXPECT=""; CLEAN_MAX=10
CGNAT_UDP_TO=10; CGNAT_UDP_STO=30
TRANSPORT=""; PAIRS=""; NODE_CONF=""; IPV6=""; CAPTURE=0; SPRAY=0; SYNC=""; MESH_NODES="fullcone restricted portrestricted masq symmetric"
RELAY_DOWN=0; KEYEXPIRE=20; DURATION=120; TRIALS=5; STRATEGIES="first second burn burn-keep"

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
            --expect) EXPECT="$2"; shift 2 ;;
            --clean-max) CLEAN_MAX="$2"; shift 2 ;;
            --recover) RECOVER="$2"; shift 2 ;;
            --pause) PAUSE="$2"; shift 2 ;;
            --cgnat-udp-timeout) CGNAT_UDP_TO="$2"; shift 2 ;;
            --cgnat-udp-stream-timeout) CGNAT_UDP_STO="$2"; shift 2 ;;
            --quick) QUICK=1; shift ;;
            --transport) TRANSPORT="$2"; shift 2 ;;
            --pairs) PAIRS="$2"; shift 2 ;;
            --nodes) MESH_NODES="$2"; shift 2 ;;
            --relay-down) RELAY_DOWN="$2"; shift 2 ;;
            --keyexpire) KEYEXPIRE="$2"; shift 2 ;;
            --duration) DURATION="$2"; shift 2 ;;
            --trials) TRIALS="$2"; shift 2 ;;
            --strategies) STRATEGIES="$2"; shift 2 ;;
            --node-conf) NODE_CONF="$2"; shift 2 ;;
            --ipv6) IPV6="$2"; shift 2 ;;
            --capture) CAPTURE=1; shift ;;
            --spray) SPRAY="$2"; shift 2 ;;
            --sync) SYNC=1; shift ;;
            *) die "unknown option $1" ;;
        esac
    done
}

# ---------------------------------------------------------------- netns topology
ns() { ip netns exec "$@"; }
ns_add() { local n; for n in "$@"; do ip netns add "$n"; ns "$n" ip link set lo up; done; }

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
    local n
    pkill -x tincd 2>/dev/null || true
    pkill -f "udpprobe server" 2>/dev/null || true
    pkill -f "nattrav server" 2>/dev/null || true
    pkill -x ping 2>/dev/null || true
    pkill -x tcpdump 2>/dev/null || true
    sleep 0.3
    for n in $(ip netns list 2>/dev/null | awk '{print $1}'); do ip netns del "$n" 2>/dev/null || true; done
    ip link del br0 2>/dev/null || true
    # netns teardown is asynchronous in the kernel: the root-side veth ends
    # (br-*) linger for a moment, and a quick re-setup then fails with
    # "RTNETLINK answers: File exists" (seen in back-to-back portmap trials)
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        ip -o link show 2>/dev/null | grep -q ': br-' || break
        sleep 0.5
    done
    # still there (a process kept a namespace alive, or a veth() failed
    # half-way and left its temporary name behind): remove them by hand,
    # otherwise every later scenario of the run fails with "File exists"
    local l
    for l in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(br-|v[0-9]+[ab]$)'); do
        ip link del "$l" 2>/dev/null || true
    done
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
    if [ -n "$IPV6" ]; then ns relay ip -6 addr add "$RELAY_IP6/64" dev eth0 nodad; fi
}
# IPv6 "internet" 2001:db8::/64 on br0; site L (a|b) gets 2001:db8:L::/64 behind
# its gateway, routed (no translation) with a stateful firewall: outbound open,
# inbound only for conntrack ESTABLISHED/RELATED -- what a home router does for
# IPv6. IPv4 keeps whatever NAT profile the site has.
RELAY_IP6=2001:db8::10
v6_site() { # GW NODE L EXT_HOST_ID
    local gw="$1" node="$2" l="$3" id="$4"
    ns "$gw" sysctl -qw net.ipv6.conf.all.forwarding=1
    ns "$gw" ip -6 addr add "2001:db8::$id/64" dev ext nodad
    ns "$gw" ip -6 addr add "2001:db8:$l::1/64" dev int nodad
    ns "$node" ip -6 addr add "2001:db8:$l::5/64" dev eth0 nodad
    ns "$node" ip -6 route add default via "2001:db8:$l::1"
    ns "$gw" ip6tables -P FORWARD DROP
    ns "$gw" ip6tables -A FORWARD -i int -o ext -j ACCEPT
    ns "$gw" ip6tables -A FORWARD -i ext -o int -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ns relay ip -6 route add "2001:db8:$l::/64" via "2001:db8::$id"
}
v6_up() { # after side_up of both sites
    [ -n "$IPV6" ] || return 0
    case "$IPV6" in both|a) v6_site gwa nodea a 2 ;; esac
    case "$IPV6" in both|b) v6_site gwb nodeb b 3 ;; esac
    if [ "$IPV6" = both ]; then
        ns gwa ip -6 route add 2001:db8:b::/64 via 2001:db8::3
        ns gwb ip -6 route add 2001:db8:a::/64 via 2001:db8::2
    fi
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
        if [ -n "$IPV6" ]; then echo "AddressFamily = any"; else echo "AddressFamily = ipv4"; fi
        echo "PingInterval = 10"
        echo "PingTimeout = 5"
        for l in "$@"; do echo "$l"; done
    } > "$d/tinc.conf"
    printf 'Subnet = %s/32\n' "$vpnip" > "$d/hosts/$name"
    if [ "$name" = relay ]; then
        # dual-stack relay: the IPv6 address first, as a resolver would order it
        if [ -n "$IPV6" ]; then printf 'Address = %s\n' "$RELAY_IP6" >> "$d/hosts/$name"; fi
        printf 'Address = %s\nPort = %s\n' "$RELAY_IP" "$TINC_PORT" >> "$d/hosts/$name"
        # --transport: a first dial only tries carriers the peer's host record
        # advertises (docs/transports.md §2), and the fronts listen on 443
        if [ -n "$TRANSPORT" ]; then
            printf 'Transports = plain, sf, obfs, https, quic\nHttpsPort = 443\nQuicPort = 443\n' >> "$d/hosts/$name"
        fi
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
    local d="$1" n; mkdir -p "$d"
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
    for t in fullcone restricted portrestricted masq masqfw symmetric udpblock; do
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
    if [ "$fail" -eq 0 ]; then log "validate-nat: all 7 profiles behave as declared"; else log "validate-nat: FAILED"; fi
    cp "$d/udpprobe.jsonl" "$OUT/validate-nat.jsonl" 2>/dev/null || true
    return "$fail"
}

# ---------------------------------------------------------------- pair scenario
# Which pairs can hole-punch at all (RFC 5128 §3.3 logic, tinc does no port
# prediction): an address-and-port-dependent *mapping* (symmetric, and masq as
# measured on this kernel) cannot meet an address-and-port-dependent *filter*
# (portrestricted, symmetric, masq); every other pair can. udpblock pairs must
# still carry traffic over TCP.
# the class a profile is judged as: cgnat = two masq tiers; masqfw measures
# as EIM + APDF (port-restricted cone) once the gateway's INPUT is closed
nat_class() { case "$1" in cgnat) echo masq ;; masqfw) echo portrestricted ;; *) echo "$1" ;; esac; }
expect_direct() { # a b -> yes|no|tcp
    case "$(nat_class "$1")/$(nat_class "$2")" in
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
# PreferredTransports line for the NATed nodes when --transport is given. The
# relay accepts every compiled carrier by default, so only the dialler changes.
# Printed as one word (no spaces) so it survives the unquoted $(...) at the
# call sites; tincd's list parser takes commas.
transport_conf() {
    [ -z "$TRANSPORT" ] || printf 'PreferredTransports=%s,plain\n' "$TRANSPORT"
    # --node-conf "Key=Value Key=Value": extra lines for the NATed nodes
    [ -z "$NODE_CONF" ] || printf '%s\n' "$NODE_CONF"
}
# side_up GW NODE TYPE EXT_IP INT_IP NODE_IP MAP CGNET
#   One NATed site on br0. TYPE cgnat = two tiers of stock MASQUERADE: the home
#   router GW (int INT_IP) behind the carrier GW"2" (ext EXT_IP, int CGNET.254,
#   short --cgnat-udp-* conntrack windows); otherwise one gateway of TYPE.
side_up() {
    local gw="$1" node="$2" t="$3" ext="$4" int="$5" nip="$6" map="$7" cg="$8"
    if [ "$t" = cgnat ]; then
        ns_add "${gw}2" "$gw" "$node"
        attach "${gw}2" ext "$ext/24"
        veth "${gw}2" int "$cg.254/24" "$gw" ext "$cg.2/24"
        ns "$gw" ip route add default via "$cg.254"
        veth "$gw" int "$int/24" "$node" eth0 "$nip/24"
        ns "$node" ip route add default via "$int"
        gw_nat "$gw" masq "$cg.2" "$int"
        gw_nat "${gw}2" masq "$ext" "$cg.254" --udp-timeout "$CGNAT_UDP_TO" --udp-stream-timeout "$CGNAT_UDP_STO"
    else
        gw_up "$gw" "$ext" "$int" "$node" "$nip"
        # shellcheck disable=SC2046
        gw_nat "$gw" "$t" "$ext" "$int" $(profile_args "$t" "$nip" "$map")
    fi
}
# the carrier each meta connection of NODE runs on ("peer:carrier ...")
meta_carriers() {
    tincctl "$1" dump connections 2>/dev/null \
        | awk '{c=""; for(i=1;i<NF;i++) if($i=="transport") c=$(i+1); printf "%s:%s ", $1, (c==""?"?":c)}'
}

scenario_run() { # A_TYPE B_TYPE IMAGE OUTDIR -> 0 pass / 1 fail
    local ta="$1" tb="$2" img="$3" d="$4"
    CUR_IMG="$img"; mkdir -p "$d"
    teardown; internet_up
    write_node relay "$VPN_RELAY"
    # shellcheck disable=SC2046  # transport_conf prints zero or one line
    write_node nodea "$VPN_A" "ConnectTo = relay" "UDPDiscoveryBurst = 5" $(transport_conf)
    # shellcheck disable=SC2046
    write_node nodeb "$VPN_B" "ConnectTo = relay" "UDPDiscoveryBurst = 5" $(transport_conf)
    share_hosts
    side_up gwa nodea "$ta" "$GWA_EXT" "$GWA_INT" "$NODEA_IP" "$MAP_A" 10.201.0 > "$d/gw-setup.txt"
    side_up gwb nodeb "$tb" "$GWB_EXT" "$GWB_INT" "$NODEB_IP" "$MAP_B" 10.202.0 >> "$d/gw-setup.txt"
    v6_up
    local cap_pid=""
    if [ "$CAPTURE" -eq 1 ]; then
        # only what crosses between the two sites directly: what an on-path
        # observer between A's and B's networks sees of the peer-to-peer path
        # exec: $! must be tcpdump itself (a backgrounded `ns' function is a
        # subshell; killing it left tcpdump holding gwa's namespace alive)
        ( exec ip netns exec gwa tcpdump -i ext -U -s 0 -w "$d/peer.pcap" "udp and host $GWB_EXT" > /dev/null 2>&1 ) &
        cap_pid=$!
    fi
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
    # https links are TCP-only by design (https.c become_established), and so
    # is TCPOnly: no direct UDP is attempted, traffic must flow over the meta
    # path -- graded like udpblock
    case " $TRANSPORT $NODE_CONF " in *" https "*|*TCPOnly=yes*) exp=tcp ;; esac
    [ "$ok_ab" -eq 1 ] && [ "$ok_ba" -eq 1 ] && direct=1
    case "$exp" in
        yes) if [ "$direct" -eq 1 ] && [ "$ping" -eq 1 ]; then verdict=PASS; else verdict=FAIL; fi ;;
        no)  if [ "$ping" -eq 1 ]; then verdict=PASS; else verdict=FAIL; fi ;;   # relay path must carry traffic
        tcp) if [ "$ping" -eq 1 ] && [ "$direct" -eq 0 ]; then verdict=PASS; else verdict=FAIL; fi ;;
    esac
    tincctl nodea info nodeb > "$d/nodea.info.txt" 2>&1 || true
    tincctl nodeb info nodea > "$d/nodeb.info.txt" 2>&1 || true
    local meta_a meta_b
    meta_a="$(meta_carriers nodea)"; meta_b="$(meta_carriers nodeb)"
    if [ -n "$cap_pid" ]; then
        # 20 s more of steady-state traffic: a carrier link that comes up
        # after the direct path (AutoConnect, UdpMetaFallback) shows up too
        sleep 20
        meta_a="$(meta_carriers nodea)"; meta_b="$(meta_carriers nodeb)"
        kill "$cap_pid" 2>/dev/null || true; wait "$cap_pid" 2>/dev/null || true
        dpi-fingerprint "$d/peer.pcap" --port 0 > "$d/peer.report.txt" 2>&1 || true
        rm -f "$d/peer.pcap"
    fi
    save_state "$d" relay nodea nodeb
    save_gw "$d" gwa gwb
    if [ "$ta" = cgnat ]; then save_gw "$d" gwa2; fi
    if [ "$tb" = cgnat ]; then save_gw "$d" gwb2; fi
    printf '{"a":"%s","b":"%s","image":"%s","transport":"%s","meta_a":"%s","meta_b":"%s","rtt_ms":%s,"expected":"%s","direct_ab":%s,"direct_ba":%s,"t_ab":%s,"t_ba":%s,"reach_ab":"%s","reach_ba":"%s","ping":%s,"verdict":"%s"}\n' \
        "$ta" "$tb" "$img" "${TRANSPORT:-plain}${IPV6:+ +v6$IPV6}" "${meta_a% }" "${meta_b% }" "$RTT" "$exp" "$ok_ab" "$ok_ba" "$t_ab" "$t_ba" "$r_ab" "$r_ba" "$ping" "$verdict" > "$d/result.json"
    log "scenario $ta x $tb [$img${TRANSPORT:+/$TRANSPORT}]: $verdict (expected=$exp direct a->b=$ok_ab/${t_ab}s b->a=$ok_ba/${t_ba}s ping=$ping reach=[$r_ab | $r_ba])"
    teardown
    [ "$verdict" = PASS ]
}

scenario() {
    local ta="$1" tb="$2"; shift 2; parse_opts "$@"
    scenario_run "$ta" "$tb" "${IMAGE_SEL:-core}" "$OUT/pair-$ta-$tb/${IMAGE_SEL:-core}${TRANSPORT:+-$TRANSPORT}${IPV6:+-v6$IPV6}"
}

MATRIX_TYPES=(fullcone restricted portrestricted masq symmetric)
matrix() {
    parse_opts "$@"
    local imgs fail=0 a b i p
    case "${IMAGE_SEL:-both}" in both) imgs="core baseline" ;; *) imgs="$IMAGE_SEL" ;; esac
    mkdir -p "$OUT"
    local pairs=()
    if [ -n "$PAIRS" ]; then
        read -r -a pairs <<<"$PAIRS"
    elif [ "$QUICK" -eq 1 ]; then
        pairs=(fullcone/fullcone portrestricted/portrestricted masq/restricted symmetric/symmetric udpblock/portrestricted)
    else
        for a in "${MATRIX_TYPES[@]}"; do for b in "${MATRIX_TYPES[@]}"; do pairs+=("$a/$b"); done; done
        pairs+=(udpblock/fullcone udpblock/portrestricted udpblock/udpblock)
    fi
    for i in $imgs; do
        for p in "${pairs[@]}"; do
            a="${p%/*}"; b="${p#*/}"
            scenario_run "$a" "$b" "$i" "$OUT/pair-$a-$b/$i${TRANSPORT:+-$TRANSPORT}${IPV6:+-v6$IPV6}" || fail=1
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
        echo "| A x B | image | carrier | expected | direct a->b | direct b->a | ping | verdict |"
        echo "|---|---|---|---|---|---|---|---|"
        for f in "$OUT"/pair-*/*/result.json; do
            [ -f "$f" ] || continue
            python3 - "$f" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
da=f"{r['t_ab']}s" if r['direct_ab'] else "-"
db=f"{r['t_ba']}s" if r['direct_ba'] else "-"
print(f"| {r['a']} x {r['b']} | {r['image']} | {r.get('transport','plain')} | {r['expected']} | {da} | {db} | {'ok' if r['ping'] else 'FAIL'} | {r['verdict']} |")
PY
        done
        if [ -f "$OUT/laptop/summary.md" ]; then echo; cat "$OUT/laptop/summary.md"; fi
        if [ -f "$OUT/glare/summary.md" ]; then echo; cat "$OUT/glare/summary.md"; fi
        for f in mesh rekey portmap punch; do
            if [ -f "$OUT/$f/summary.md" ]; then echo; cat "$OUT/$f/summary.md"; fi
        done
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
# What a glare run is supposed to look like, per image. The point of the
# baseline arm is to SHOW the defect the tie-break fixes, so it is asserted to
# be bad rather than required to clear the core's bar -- grading both by the
# core's rule made a correct control turn the arm red (PLAN.md, 2026-09-18).
# Measured at --rtt 50: core 1 s with 0 restarts and 0 seqno errors (4 of 4),
# baseline 12-90 s with 1-14 SPTPS restarts.
# A mixed pair is NOT graded by default: which side keeps its session depends on
# the node names (the tie-break is lexicographic), so `core x baseline' is clean
# while `baseline x core' pays a stock 10 s timer. Assert one with --expect.
glare_expect() { # label -> clean|defect|any
    if [ -n "$EXPECT" ]; then printf '%s\n' "$EXPECT"; return; fi
    if [ -n "$IMAGE_B" ]; then echo any; return; fi

    case "$1" in
        core) echo clean ;;
        baseline) echo defect ;;
        *) echo any ;;
    esac
}

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
    local expect verdict why rc
    expect="$(glare_expect "$img")"

    case "$expect" in
        clean)
            # The patched binary must win the tie-break: one key, at once, with
            # nothing torn down on the way.
            if [ "$ok" -eq 1 ] && [ "$t" -le "$CLEAN_MAX" ] && [ "$restarts" -eq 0 ] && [ "$seqno" -eq 0 ]; then
                verdict=PASS; rc=0
                why="key in ${t}s (limit ${CLEAN_MAX}s), no SPTPS restart, no seqno error"
            else
                verdict=FAIL; rc=1
                why="expected a clean tie-break (key within ${CLEAN_MAX}s, 0 restarts, 0 seqno errors), got ${t}s / $restarts / $seqno"
                [ "$ok" -eq 1 ] || why="$why, and no key at all within ${WAIT}s"
            fi
            ;;
        defect)
            # The unpatched control must SHOW the defect. Requiring it to pass
            # the core's bar made a correct control fail the arm (PLAN.md).
            if [ "$reqkey" -eq 0 ]; then
                verdict=INCONCLUSIVE; rc=2
                why="the two sides never collided (0 glare lines), so this run says nothing about the defect; --rtt 50 makes the collision near-certain"
            elif [ "$ok" -eq 0 ] || [ "$restarts" -ge 1 ] || [ "$seqno" -ge 1 ]; then
                verdict=PASS; rc=0
                why="the defect reproduced: $restarts SPTPS restart(s), $seqno seqno error(s), key after ${t}s"
            else
                verdict=FAIL; rc=1
                why="this binary recovered from a real glare with no restart and no seqno error, so it does not show the defect the control exists to show"
            fi
            ;;
        *)
            if [ "$ok" -eq 1 ]; then verdict=PASS; rc=0; else verdict=FAIL; rc=1; fi
            why="no expectation for this pair, graded only on whether a key was established within ${WAIT}s"
            ;;
    esac

    printf '{"image":"%s","expected":"%s","verdict":"%s","t_key":%s,"seqno_lines":%s,"reqkey_lines":%s,"sptps_restarts":%s,"why":"%s"}\n' \
        "$label" "$expect" "$verdict" "$t" "$seqno" "$reqkey" "$restarts" "$why" > "$d/result.json"
    unset NODE_IMG_nodeb
    log "glare [$label]: $verdict (expected $expect) key after ${t}s, seqno-errors=$seqno glare-lines=$reqkey sptps-restarts=$restarts -- $why"
    teardown
    return "$rc"
}
glare() {
    parse_opts "$@"
    local imgs worst=0 rc i d="$OUT/glare" jsons=()
    case "${IMAGE_SEL:-both}" in both) imgs="core baseline" ;; *) imgs="$IMAGE_SEL" ;; esac
    local sub=""; [ -z "$IMAGE_B" ] || sub="-x-$IMAGE_B"
    mkdir -p "$d"

    for i in $imgs; do
        rc=0; glare_run "$i" "$d/$i$sub" || rc=$?

        # INCONCLUSIVE means the collision this scenario is built to provoke did
        # not happen, so the run measured nothing. One retry: a red arm should
        # mean a changed binary, not an unlucky lab.
        if [ "$rc" -eq 2 ]; then
            log "glare [$i]: the first attempt did not collide, retrying once"
            rc=0; glare_run "$i" "$d/$i$sub-retry" || rc=$?
            jsons+=("$d/$i$sub-retry/result.json")
        else
            jsons+=("$d/$i$sub/result.json")
        fi

        [ "$rc" -le "$worst" ] || worst=$rc
    done

    {
        echo "## REQ_KEY glare (both sides initiate at once; full-cone x full-cone)"
        echo
        echo "Each image is graded against what it is SUPPOSED to do: \`clean\` = the"
        echo "tie-break holds (key within ${CLEAN_MAX}s, no SPTPS restart, no seqno error),"
        echo "\`defect\` = the unpatched control still demonstrates the glare it is there"
        echo "to demonstrate. A control that recovers cleanly fails this table, and so"
        echo "does a patched binary that does not."
        echo
        echo "| image | expected | key established after | \`Invalid packet seqno\` | glare lines | SPTPS restarts | verdict |"
        echo "|---|---|---|---|---|---|---|"
        for j in "${jsons[@]}"; do
            python3 - "$j" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
print(f"| {r['image']} | {r.get('expected','any')} | {r['t_key']}s | {r['seqno_lines']} | {r['reqkey_lines']} | {r['sptps_restarts']} | {r['verdict']} |")
PY
        done
        echo
        for j in "${jsons[@]}"; do
            python3 - "$j" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
print(f"- {r['image']}: {r['verdict']} -- {r.get('why','')}")
PY
        done
    } > "$d/summary.md"
    cat "$d/summary.md"
    return "$worst"
}

# ---------------------------------------------------------------- mesh
# relay + one NATed node per type in --nodes; every node pings every other node
# (both directions: a mesh has no polite initiator). Per pair: seconds until
# both sides report direct UDP; the share of pairs that went direct against the
# pair table; the relay's traffic in a 20 s steady-state window. With
# --relay-down S the relay's tincd is then stopped for S seconds while one
# direct and one relayed pair ping at 5 pps, and the outage each saw is taken
# from `ping -D' timestamps.
mesh_run() { # IMAGE OUTDIR
    local img="$1" d="$2"
    CUR_IMG="$img"; mkdir -p "$d"
    teardown; internet_up
    local types=() i j n t0 t r key left
    read -r -a types <<<"$MESH_NODES"
    n=${#types[@]}
    write_node relay "$VPN_RELAY"
    for ((i = 1; i <= n; i++)); do
        # shellcheck disable=SC2046  # transport_conf prints zero or one word
        write_node "m$i" "10.77.0.$((10 + i))" "ConnectTo = relay" "UDPDiscoveryBurst = 5" $(transport_conf)
    done
    share_hosts
    : > "$d/gw-setup.txt"
    for ((i = 1; i <= n; i++)); do
        side_up "g$i" "m$i" "${types[i - 1]}" "100.64.0.$((30 + i))" "192.168.$((140 + i)).254" \
            "192.168.$((140 + i)).5" "$((42000 + i))" "10.$((210 + i)).0" >> "$d/gw-setup.txt"
    done
    tinc_start relay; sleep 1
    for ((i = 1; i <= n; i++)); do tinc_start "m$i"; done
    sleep 2
    for ((i = 1; i <= n; i++)); do
        for ((j = 1; j <= n; j++)); do
            [ "$i" -eq "$j" ] || bg_ping "m$i" "10.77.0.$((10 + j))"
        done
    done
    declare -A tdir=()
    t0=$(date +%s)
    while :; do
        t=$(( $(date +%s) - t0 )); left=0
        for ((i = 1; i <= n; i++)); do
            for ((j = 1; j <= n; j++)); do
                [ "$i" -ne "$j" ] || continue
                key="$i-$j"
                [ -z "${tdir[$key]:-}" ] || continue
                r="$(reach "m$i" "m$j" || true)"
                if [ "$r" = "directly with UDP" ]; then tdir[$key]=$t; else left=$((left + 1)); fi
            done
        done
        [ "$left" -eq 0 ] && break
        [ "$t" -ge "$WAIT" ] && break
        sleep 2
    done
    # steady-state relay load: every ordered pair keeps pinging at 1 pps
    local rx0 tx0 rp0 tp0 rx1 tx1 rp1 tp1 st=/sys/class/net/eth0/statistics
    rx0=$(ns relay cat $st/rx_bytes); tx0=$(ns relay cat $st/tx_bytes)
    rp0=$(ns relay cat $st/rx_packets); tp0=$(ns relay cat $st/tx_packets)
    sleep 20
    rx1=$(ns relay cat $st/rx_bytes); tx1=$(ns relay cat $st/tx_bytes)
    rp1=$(ns relay cat $st/rx_packets); tp1=$(ns relay cat $st/tx_packets)
    : > "$d/pairs.txt"
    # which meta connections exist now (AutoConnect + UdpMetaFallback may have
    # added direct `sf' links between NATed nodes; those survive a relay loss)
    : > "$d/meta.txt"
    for ((i = 1; i <= n; i++)); do echo "m$i(${types[i - 1]}): $(meta_carriers "m$i")" >> "$d/meta.txt"; done
    local pd="" pr=""
    for ((i = 1; i <= n; i++)); do
        for ((j = i + 1; j <= n; j++)); do
            local e now_ij now_ji
            e="$(expect_direct "${types[i - 1]}" "${types[j - 1]}")"
            now_ij="$(reach "m$i" "m$j" || true)"; now_ji="$(reach "m$j" "m$i" || true)"
            echo "${types[i - 1]} ${types[j - 1]} $e ${tdir[$i-$j]:--} ${tdir[$j-$i]:--} $i $j ${now_ij// /_} ${now_ji// /_}" >> "$d/pairs.txt"
            if [ -z "$pd" ] && [ -n "${tdir[$i-$j]:-}" ] && [ -n "${tdir[$j-$i]:-}" ]; then pd="$i $j"; fi
            if [ -z "$pr" ] && [ -z "${tdir[$i-$j]:-}" ]; then pr="$i $j"; fi
        done
    done
    local down_json="null"
    if [ "$RELAY_DOWN" -gt 0 ]; then
        local a b pa pb t_stop t_start
        read -r a b <<<"${pd:-1 2}"
        ns "m$a" ping -D -i 0.2 -W 1 "10.77.0.$((10 + b))" > "$d/ping-direct.txt" 2>&1 & pa=$!
        read -r a b <<<"${pr:-1 2}"
        ns "m$a" ping -D -i 0.2 -W 1 "10.77.0.$((10 + b))" > "$d/ping-relayed.txt" 2>&1 & pb=$!
        echo "direct-pair ${pd:-none} relayed-pair ${pr:-none}" > "$d/relay-down-pairs.txt"
        sleep 5
        for ((i = 1; i <= n; i++)); do echo "=== relay stopped $(date +%T) ===" >> "$LOGS/m$i.log"; done
        t_stop=$(date +%s.%N)
        tinc_stop relay
        sleep "$RELAY_DOWN"
        t_start=$(date +%s.%N)
        tinc_start relay
        for ((i = 1; i <= n; i++)); do echo "=== relay started $(date +%T) ===" >> "$LOGS/m$i.log"; done
        sleep "$RECOVER"
        kill "$pa" "$pb" 2>/dev/null || true
        wait "$pa" "$pb" 2>/dev/null || true
        down_json="$(python3 - "$d" "$t_stop" "$t_start" <<'PY'
import json, re, sys
d, t_stop, t_start = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
out = {}
for k in ("direct", "relayed"):
    ts = []
    for line in open(f"{d}/ping-{k}.txt"):
        m = re.match(r"\[(\d+\.\d+)\] \d+ bytes from", line)
        if m:
            ts.append(float(m.group(1)))
    during = [t for t in ts if t_stop < t < t_start]
    after = [t for t in ts if t >= t_start]
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    out[k] = {"replies": len(ts), "replies_while_relay_down": len(during),
              "max_gap_s": round(max(gaps), 1) if gaps else None,
              "first_reply_after_restart_s": round(after[0] - t_start, 1) if after else None}
print(json.dumps(out))
PY
)"
    fi
    for ((i = 1; i <= n; i++)); do save_state "$d" "m$i"; done
    save_state "$d" relay
    python3 - "$d" "$img" "${TRANSPORT:-plain}" "$WAIT" "$rx0" "$rx1" "$tx0" "$tx1" "$rp0" "$rp1" "$tp0" "$tp1" "$down_json" "$RELAY_DOWN" <<'PY'
import json, sys
d, img, tr, wait = sys.argv[1:5]
rx0, rx1, tx0, tx1, rp0, rp1, tp0, tp1 = map(int, sys.argv[5:13])
down = json.loads(sys.argv[13]); rdown = int(sys.argv[14])
rows = []
for line in open(f"{d}/pairs.txt"):
    a, b, e, tij, tji, i, j, nij, nji = line.split()
    both = tij != "-" and tji != "-"
    rows.append({"a": a, "b": b, "expected": e, "t_ab": tij, "t_ba": tji, "direct": both,
                 "now_ab": nij.replace("_", " "), "now_ba": nji.replace("_", " ")})
exp_yes = [r for r in rows if r["expected"] == "yes"]
res = {"image": img, "transport": tr, "wait": int(wait), "pairs": rows,
       "direct_pairs": sum(r["direct"] for r in rows), "total_pairs": len(rows),
       "expected_direct": len(exp_yes), "expected_direct_ok": sum(r["direct"] for r in exp_yes),
       "unexpected_direct": sum(r["direct"] for r in rows if r["expected"] != "yes"),
       "time_to_all_expected_s": max([max(int(r["t_ab"]), int(r["t_ba"])) for r in exp_yes if r["direct"]] or [0]),
       "relay_rx_Bps": round((rx1 - rx0) / 20), "relay_tx_Bps": round((tx1 - tx0) / 20),
       "relay_rx_pps": round((rp1 - rp0) / 20, 1), "relay_tx_pps": round((tp1 - tp0) / 20, 1),
       "relay_down_s": rdown, "relay_down": down}
json.dump(res, open(f"{d}/result.json", "w"))
with open(f"{d}/summary.md", "w") as f:
    f.write(f"### mesh — image {img}, carrier {tr}, {len(rows)} pairs, wait {wait}s\n\n")
    f.write("| A x B | expected | direct a->b | direct b->a | direct both | state at end (a / b) |\n|---|---|---|---|---|---|\n")
    for r in rows:
        f.write(f"| {r['a']} x {r['b']} | {r['expected']} | {r['t_ab'] if r['t_ab'] == '-' else r['t_ab'] + 's'} | "
                f"{r['t_ba'] if r['t_ba'] == '-' else r['t_ba'] + 's'} | {'yes' if r['direct'] else 'no'} | {r['now_ab']} / {r['now_ba']} |\n")
    f.write(f"\n- direct: **{res['direct_pairs']}/{res['total_pairs']}** pairs "
            f"({res['expected_direct_ok']}/{res['expected_direct']} of the pairs the table calls traversable, "
            f"{res['unexpected_direct']} beyond it); all traversable pairs direct after {res['time_to_all_expected_s']} s\n")
    f.write(f"- relay load, steady state (every ordered pair pings at 1 pps): rx {res['relay_rx_pps']} pkt/s "
            f"{res['relay_rx_Bps']} B/s, tx {res['relay_tx_pps']} pkt/s {res['relay_tx_Bps']} B/s\n")
    f.write("- meta connections at the end of the wait (node(type): peer:carrier ...): "
            + "; ".join(l.strip() for l in open(f"{d}/meta.txt")) + "\n")
    if down:
        for k, v in down.items():
            f.write(f"- relay tincd down {rdown} s, {k} pair (5 pps): replies while down {v['replies_while_relay_down']}, "
                    f"longest gap {v['max_gap_s']} s, first reply {v['first_reply_after_restart_s']} s after the relay restarted\n")
print(open(f"{d}/summary.md").read())
PY
    teardown
}

mesh() {
    parse_opts "$@"
    local imgs i d="$OUT/mesh" sub=""
    case "${IMAGE_SEL:-both}" in both) imgs="core baseline" ;; *) imgs="$IMAGE_SEL" ;; esac
    [ -z "$TRANSPORT" ] || sub="-$TRANSPORT"
    [ "$RELAY_DOWN" -eq 0 ] || sub="$sub-relaydown$RELAY_DOWN"
    if [ -n "$NODE_CONF" ]; then sub="$sub-$(printf '%s' "$NODE_CONF" | tr ' =' '_-')"; fi
    mkdir -p "$d"
    for i in $imgs; do mesh_run "$i" "$d/$i$sub"; done
    { for f in "$d"/*/summary.md; do cat "$f"; echo; done; } > "$d/summary.md"
}

# ---------------------------------------------------------------- rekey
# A direct pair under frequent SPTPS rekeys (KeyExpire on every node). Every
# rekey's handshake records travel as ANS_KEY through the relay, which appends
# the sender's reflexive UDP address; ans_key_h() applies it with
# update_node_udp(), which clears udp_confirmed and the PMTU state even when
# the address did not change. Counts, after the pair first went direct, how
# often that happened and how many data packets went via the relay instead.
rekey_run() { # A B IMAGE OUTDIR
    local ta="$1" tb="$2" img="$3" d="$4"
    CUR_IMG="$img"; mkdir -p "$d"
    teardown; internet_up
    write_node relay "$VPN_RELAY" "KeyExpire = $KEYEXPIRE"
    # shellcheck disable=SC2046  # --node-conf words, one tinc.conf line each
    write_node nodea "$VPN_A" "ConnectTo = relay" "UDPDiscoveryBurst = 5" "KeyExpire = $KEYEXPIRE" $(transport_conf)
    # shellcheck disable=SC2046
    write_node nodeb "$VPN_B" "ConnectTo = relay" "UDPDiscoveryBurst = 5" "KeyExpire = $KEYEXPIRE" $(transport_conf)
    share_hosts
    side_up gwa nodea "$ta" "$GWA_EXT" "$GWA_INT" "$NODEA_IP" "$MAP_A" 10.201.0 > "$d/gw-setup.txt"
    side_up gwb nodeb "$tb" "$GWB_EXT" "$GWB_INT" "$NODEB_IP" "$MAP_B" 10.202.0 >> "$d/gw-setup.txt"
    tinc_start relay; sleep 1
    tinc_start nodea; tinc_start nodeb
    sleep 2
    local t_up ok=1 la lb
    ns nodea ping -D -i 0.2 -W 1 "$VPN_B" > "$d/ping.txt" 2>&1 &
    local pp=$!
    t_up="$(wait_direct nodea nodeb "$WAIT")" || ok=0
    wait_direct nodeb nodea 30 >/dev/null || ok=0
    la=$(wc -l < "$LOGS/nodea.log"); lb=$(wc -l < "$LOGS/nodeb.log")
    local t_mark; t_mark=$(date +%s.%N)
    sleep "$DURATION"
    kill "$pp" 2>/dev/null || true; wait "$pp" 2>/dev/null || true
    # a direct meta connection nodea<->nodeb (UdpMetaFallback `sf') carries
    # the rekey handshake itself, so the relay never appends an address
    echo "nodea: $(meta_carriers nodea)" > "$d/meta.txt"
    save_state "$d" relay nodea nodeb
    tail -n +"$((la + 1))" "$d/nodea.log" > "$d/nodea.window.txt"
    tail -n +"$((lb + 1))" "$d/nodeb.log" > "$d/nodeb.window.txt"
    python3 - "$d" "$ta" "$tb" "$img" "$KEYEXPIRE" "$DURATION" "$ok" "$t_up" "$t_mark" "${NODE_CONF:--}" <<'PY'
import json, re, sys
d, ta, tb, img, ke, dur, ok, t_up, t_mark, nc = sys.argv[1:11]
t_mark = float(t_mark)
def cnt(f, pat):
    return sum(1 for l in open(f) if re.search(pat, l))
wa, wb = f"{d}/nodea.window.txt", f"{d}/nodeb.window.txt"
res = {"a": ta, "b": tb, "image": img, "node_conf": nc, "keyexpire": int(ke), "window_s": int(dur), "direct_before_window": ok == "1",
       "t_direct_s": int(t_up),
       "rekeys_a": cnt(wa, r"Expiring symmetric keys"),
       "addr_updates_a": cnt(wa, r"UDP address of nodeb set to"),
       "addr_updates_b": cnt(wb, r"UDP address of nodea set to"),
       "reflexive_applied_a": cnt(wa, r"Using reflexive UDP address from nodeb"),
       "a_to_b_via_nodeb": cnt(wa, r"to nodeb \(.*\) via nodeb \("),
       "a_to_b_via_relay": cnt(wa, r"to nodeb \(.*\) via relay \("),
       "a_to_b_tcp": cnt(wa, r"to nodeb \(.*\) via relay \(.*\) \(TCP\)")}
ts = []
for line in open(f"{d}/ping.txt"):
    m = re.match(r"\[(\d+\.\d+)\] \d+ bytes from", line)
    if m and float(m.group(1)) >= t_mark:
        ts.append(float(m.group(1)))
gaps = [b - a for a, b in zip(ts, ts[1:])]
res["ping_replies"] = len(ts)
res["ping_expected"] = int(int(dur) / 0.2)
res["ping_max_gap_s"] = round(max(gaps), 2) if gaps else None
tot = res["a_to_b_via_nodeb"] + res["a_to_b_via_relay"]
res["relayed_share"] = round(res["a_to_b_via_relay"] / tot, 3) if tot else None
json.dump(res, open(f"{d}/result.json", "w"))
print(json.dumps(res))
PY
    teardown
}

rekey() {
    local ta="$1" tb="$2"; shift 2; parse_opts "$@"
    local imgs i d="$OUT/rekey" sub=""
    case "${IMAGE_SEL:-both}" in both) imgs="core baseline" ;; *) imgs="$IMAGE_SEL" ;; esac
    if [ -n "$NODE_CONF" ]; then sub="-$(printf '%s' "$NODE_CONF" | tr ' =' '_-')"; fi
    mkdir -p "$d"
    for i in $imgs; do rekey_run "$ta" "$tb" "$i" "$d/$ta-$tb-$i-ke$KEYEXPIRE$sub"; done
    {
        echo "### SPTPS rekey on a direct pair (KeyExpire on every node; counted over a window after the pair went direct)"
        echo
        echo "| A x B | image (extra config) | KeyExpire | window | rekeys (A) | A: peer UDP address reset | B: peer UDP address reset | A->B packets via relay / direct | relayed share | ping replies / sent | longest ping gap |"
        echo "|---|---|---|---|---|---|---|---|---|---|---|"
        for f in "$d"/*/result.json; do
            python3 - "$f" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print(f"| {r['a']} x {r['b']} | {r['image']}{'' if r.get('node_conf', '-') == '-' else ' (' + r['node_conf'] + ')'} | {r['keyexpire']} s | {r['window_s']} s | {r['rekeys_a']} | {r['addr_updates_a']} | {r['addr_updates_b']} | "
      f"{r['a_to_b_via_relay']} / {r['a_to_b_via_nodeb']} | {r['relayed_share']} | {r['ping_replies']} / {r['ping_expected']} | {r['ping_max_gap_s']} s |")
PY
        done
    } > "$d/summary.md"
    cat "$d/summary.md"
}

# ---------------------------------------------------------------- portmap / punch
# Both run nattrav (stdlib python) instead of tincd: they measure what a NAT
# does and what a hole puncher could do with it, so a technique is proven here
# before the daemon changes. Reflectors: $PROBE_IP1..3 on ports 3478/3479.
PROBE_IP3=100.64.0.22
reflector_up() {
    ns_add probe
    attach probe eth0 "$PROBE_IP1/24"
    ns probe ip addr add "$PROBE_IP2/24" dev eth0
    ns probe ip addr add "$PROBE_IP3/24" dev eth0
    ns probe nattrav server --bind "$PROBE_IP1:3478" --bind "$PROBE_IP1:3479" \
        --bind "$PROBE_IP2:3478" --bind "$PROBE_IP2:3479" \
        --bind "$PROBE_IP3:3478" --bind "$PROBE_IP3:3479" >> "$1" 2>&1 &
    sleep 0.3
}

portmap() {
    parse_opts "$@"
    local d="$OUT/portmap" t k out
    mkdir -p "$d"
    : > "$d/portmap.jsonl"
    local i1="$PROBE_IP1" i2="$PROBE_IP2" i3="$PROBE_IP3"
    # A: no unsolicited inbound at all -- five destinations in order.
    local seq_a=("$i1:3478" "$i1:3479" "$i2:3478" "$i2:3479" "$i3:3478")
    # P: after the first destination, two OTHER reflector sockets send us an
    # unsolicited datagram (what a peer's early hole-punch probe is); then new
    # destinations, poked and not poked, in a mixed order.
    local seq_p=("$i1:3478" "poke=$i1:3478>$i2:3478" "poke=$i1:3478>$i1:3479" "$i3:3478" "$i2:3478" "$i1:3479" "$i3:3479")
    for t in masq masqfw cgnat symmetric; do
        for k in 1 2; do
            teardown; internet_up
            reflector_up "$d/server.log"
            side_up gwa client "$t" "$GWA_EXT" "$GWA_INT" "$NODEA_IP" "$MAP_A" 10.201.0 >> "$d/gw-setup.txt"
            sleep 0.3
            local dst=() x sp
            for x in "${seq_a[@]}"; do dst+=(--dst "$x"); done
            out="$(ns client nattrav portmap --sport 655 "${dst[@]}")"
            echo "{\"type\":\"$t\",\"trial\":$k,\"seq\":\"A-nopoke-sport655\",\"r\":$out}" >> "$d/portmap.jsonl"
            for sp in 656 4004; do
                dst=()
                for x in "${seq_p[@]}"; do dst+=(--dst "$x"); done
                out="$(ns client nattrav portmap --sport "$sp" "${dst[@]}")"
                echo "{\"type\":\"$t\",\"trial\":$k,\"seq\":\"P-poked-sport$sp\",\"r\":$out}" >> "$d/portmap.jsonl"
            done
            # C: a throwaway first datagram, then the "relay"; what does a new
            # destination get once the unanswered burn mapping has expired?
            # (home tier: unreplied UDP conntrack timeout 5 s for this sequence)
            if [ "$t" = masq ] || [ "$t" = masqfw ]; then
                gw_nat gwa "$t" "$GWA_EXT" "$GWA_INT" --udp-timeout 5 >> "$d/gw-setup.txt"
                out="$(ns client nattrav portmap --sport 657 --dst "burn=$i3:9" --dst "$i1:3478" \
                    --dst "$i2:3478" --dst sleep=10 --dst "$i3:3479" --dst "$i2:3479")"
                echo "{\"type\":\"$t\",\"trial\":$k,\"seq\":\"C-burn-then-expire\",\"r\":$out}" >> "$d/portmap.jsonl"
            fi
            if [ "$k" -eq 1 ]; then save_gw "$d" gwa; mv "$d/gw-gwa.txt" "$d/gw-gwa-$t.txt"; fi
        done
    done
    teardown
    python3 - "$d" <<'PY' > "$d/summary.md"
import json, sys
d = sys.argv[1]
print("### NAT port allocation (nattrav portmap; one inside socket, destinations in order)\n")
print("A: ip1:3478, ip1:3479, ip2:3478, ip2:3479, ip3:3478 -- nothing unsolicited. "
      "P: ip1:3478, then ip2:3478 and ip1:3479 each send one unsolicited datagram to the mapping (`poke`), "
      "then ip3:3478, ip2:3478 (poked), ip1:3479 (poked), ip3:3479. "
      "C (masq/masqfw, unreplied UDP timeout 5 s): a burn datagram nobody answers, ip1:3478, ip2:3478, "
      "10 s with the answered flows kept alive, ip3:3479, ip2:3479.\n")
print("| NAT | trial | sequence | external port per destination (poke: arrived?) | first keeps source port | later destinations share one port |")
print("|---|---|---|---|---|---|")
for line in open(f"{d}/portmap.jsonl"):
    j = json.loads(line); r = j["r"]
    cells = []
    for o in r["obs"]:
        if o["dst"].startswith("poke="):
            cells.append("poke:" + ("in" if o.get("poke_arrived") else "dropped"))
        elif o["dst"].startswith("burn="):
            cells.append("burn")
        else:
            cells.append(f"{o['dst'].split(':')[0].split('.')[-1]}:{o['dst'].split(':')[1]}->{o['port']}")
    print(f"| {j['type']} | {j['trial']} | {j['seq']} | {', '.join(cells)} | {r['first_preserved']} | {r['rest_shared']} |")
PY
    cat "$d/summary.md"
}

punch_pair() { # A B -> appends to $OUT/punch/punch.jsonl
    local ta="$1" tb="$2" d="$OUT/punch/$1-$2" s k ra rb pa pb label
    mkdir -p "$d"
    for s in $STRATEGIES; do
        label="$s"; [ "$SPRAY" -eq 0 ] || label="$label+spray$SPRAY"
        [ -z "$SYNC" ] || label="$label+sync"
        [ "$RTT" = 0 ] || label="$label+rtt$RTT"
        for ((k = 1; k <= TRIALS; k++)); do
            teardown; internet_up
            reflector_up "$d/server.log"
            side_up gwa nodea "$ta" "$GWA_EXT" "$GWA_INT" "$NODEA_IP" "$MAP_A" 10.201.0 > /dev/null
            side_up gwb nodeb "$tb" "$GWB_EXT" "$GWB_INT" "$NODEB_IP" "$MAP_B" 10.202.0 > /dev/null
            sleep 0.3
            ns nodea nattrav punch --name "a$k$s" --peer "b$k$s" --sport "$TINC_PORT" --rdv "$PROBE_IP1:3478" \
                --second "$PROBE_IP1:3479" --burn "$PROBE_IP3:9" --strategy "$s" --spray "$SPRAY" ${SYNC:+--sync} > "$d/a.json" 2>&1 & pa=$!
            ns nodeb nattrav punch --name "b$k$s" --peer "a$k$s" --sport "$TINC_PORT" --rdv "$PROBE_IP1:3478" \
                --second "$PROBE_IP1:3479" --burn "$PROBE_IP3:9" --strategy "$s" --spray "$SPRAY" ${SYNC:+--sync} > "$d/b.json" 2>&1 & pb=$!
            wait "$pa" || true; wait "$pb" || true
            ra="$(tail -1 "$d/a.json")"; rb="$(tail -1 "$d/b.json")"
            echo "{\"a\":\"$ta\",\"b\":\"$tb\",\"strategy\":\"$label\",\"trial\":$k,\"ra\":${ra:-null},\"rb\":${rb:-null}}" >> "$OUT/punch/punch.jsonl"
            if [ "$k" -eq 1 ]; then
                save_gw "$d" gwa gwb
                mv "$d/gw-gwa.txt" "$d/$label-gw-gwa.txt"; mv "$d/gw-gwb.txt" "$d/$label-gw-gwb.txt"
            fi
        done
    done
}

punch() {
    local pairs=() p
    while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do pairs+=("$1"); shift; done
    parse_opts "$@"
    [ "${#pairs[@]}" -gt 0 ] || pairs=(masq/masq masqfw/masqfw masq/portrestricted masqfw/portrestricted masq/symmetric cgnat/cgnat symmetric/symmetric restricted/masq)
    mkdir -p "$OUT/punch"
    touch "$OUT/punch/punch.jsonl"      # appended: several runs share one table
    for p in "${pairs[@]}"; do punch_pair "${p%/*}" "${p#*/}"; done
    teardown
    python3 - "$OUT/punch/punch.jsonl" <<'PY' > "$OUT/punch/summary.md"
import json, sys, collections
agg = collections.OrderedDict()
for line in open(sys.argv[1]):
    j = json.loads(line)
    key = (j["a"], j["b"], j["strategy"])
    a, b = j["ra"] or {}, j["rb"] or {}
    both = bool(a.get("ok")) and bool(b.get("ok"))
    t = max((a.get("first_contact") or {}).get("t", 99), (b.get("first_contact") or {}).get("t", 99)) if both else None
    g = agg.setdefault(key, {"n": 0, "ok": 0, "t": [], "adv": set()})
    g["n"] += 1; g["ok"] += both
    if t is not None:
        g["t"].append(t)
    g["adv"].add(f"{(a.get('advertised') or ['?', '?'])[1]}/{(b.get('advertised') or ['?', '?'])[1]}")
print("### Hole punch without tinc (nattrav punch; both sides send every 100 ms for 8 s to the address the other advertised)\n")
print("strategy: `first` = advertise what the rendezvous (first destination) saw -- what tinc's UDP_INFO/ANS_KEY carry today; "
      "`second` = advertise what a second reflector port on the same host saw; `burn` = one throwaway datagram before the rendezvous, advertise the rendezvous' view; "
      "`+sprayN` = also send to N ports around the advertised one; `+sync` = neither side sends to the other before the rendezvous says GO to both at once; "
      "`+rttN` = netem on every gateway's external interface.\n")
print("| A x B | strategy | bidirectional contact | median time to contact | advertised ports (a/b, per trial) |")
print("|---|---|---|---|---|")
for (a, b, s), g in agg.items():
    ts = sorted(g["t"])
    med = f"{ts[len(ts)//2]:.2f} s" if ts else "-"
    print(f"| {a} x {b} | {s} | {g['ok']}/{g['n']} | {med} | {' '.join(sorted(g['adv']))} |")
PY
    cat "$OUT/punch/summary.md"
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
    mesh) mesh "$@" ;;
    rekey) rekey "$@" ;;
    portmap) portmap "$@" ;;
    punch) punch "$@" ;;
    summarize) parse_opts "$@"; summarize ;;
    shell) exec bash ;;
    *) sed -n '2,16p' "$0"; exit 2 ;;
esac

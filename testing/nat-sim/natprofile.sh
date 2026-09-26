#!/usr/bin/env bash
# Apply one NAT profile on a dual-homed gateway container (runs INSIDE the
# gateway). Interfaces are found from the IPs they carry.
#
#   natprofile <type> --ext-ip A.B.C.D --int-ip A.B.C.D --inside A.B.C.D \
#              [--map EXTPORT:INTPORT] [--udp-timeout S] [--udp-stream-timeout S] \
#              [--rtt-ms N]
#
# Types (RFC 3489 / RFC 4787 vocabulary; see README "How each NAT type is
# emulated" for the exact netfilter semantics and their limits):
#   fullcone        EIM + endpoint-independent filtering. Static SNAT/DNAT pair for
#                   the inside host's declared UDP port (--map), external port !=
#                   internal port. Anyone may send to the mapping.
#   restricted      EIM + address-dependent filtering. Same static pair; inbound
#                   allowed only from IPs the inside host has sent UDP to (xt_recent
#                   list keyed on destination address, refreshed on every outbound
#                   datagram, 300 s lifetime).
#   portrestricted  EIM + address-and-port-dependent filtering. Same static pair;
#                   inbound only for conntrack ESTABLISHED tuples (exact ip:port).
#   masq            Stock Linux MASQUERADE, dynamic (works for any inside port,
#                   needed for a node that rebinds its UDP port at run time).
#                   The gateway's INPUT chain is open, so an unsolicited datagram
#                   to its external address creates a local conntrack entry.
#                   udpprobe measures "first destination keeps the source port,
#                   every further destination shares one other port"
#                   (EIM-after-first) with address-and-port-dependent filtering;
#                   2026-09-26 (stream N): that remapping follows the unsolicited
#                   inbound entries, see README "masq vs masqfw".
#   masqfw          masq plus the router's own firewall: new inbound on the
#                   external interface is dropped in INPUT (as OpenWrt and CPE
#                   firewalls do). Measured on 6.8: EIM + APDF, port-preserving;
#                   see README "masq vs masqfw".
#   symmetric       APDM + APDF: MASQUERADE --random-fully (fresh external port per
#                   destination tuple) + inbound only for ESTABLISHED tuples.
#   udpblock        Drops every UDP datagram both ways; TCP is MASQUERADEd
#                   normally. Models a network where only the TCP meta path works.
#
# Options:
#   --udp-timeout S          nf_conntrack_udp_timeout (unreplied window)
#   --udp-stream-timeout S   nf_conntrack_udp_timeout_stream (replied window)
#   --rtt-ms N               netem delay N/2 ms on the external interface (both
#                            directions on that interface => N ms RTT added)
set -euo pipefail

TYPE="${1:-}"
[ -n "$TYPE" ] || { echo "usage: natprofile <type> ..." >&2; exit 2; }
shift
EXT_IP=""; INT_IP=""; INSIDE=""; MAP=""; UDP_TO=""; UDP_STO=""; RTT_MS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --ext-ip) EXT_IP="$2"; shift 2 ;;
        --int-ip) INT_IP="$2"; shift 2 ;;
        --inside) INSIDE="$2"; shift 2 ;;
        --map) MAP="$2"; shift 2 ;;
        --udp-timeout) UDP_TO="$2"; shift 2 ;;
        --udp-stream-timeout) UDP_STO="$2"; shift 2 ;;
        --rtt-ms) RTT_MS="$2"; shift 2 ;;
        *) echo "natprofile: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -n "$EXT_IP" ] && [ -n "$INT_IP" ] || { echo "natprofile: --ext-ip and --int-ip required" >&2; exit 2; }

iface_of() { ip -o -4 addr show | awk -v ip="$1" '$4 ~ "^"ip"/" {print $2; exit}'; }
EXT="$(iface_of "$EXT_IP")"
INT="$(iface_of "$INT_IP")"
[ -n "$EXT" ] && [ -n "$INT" ] || { echo "natprofile: cannot find interfaces for $EXT_IP / $INT_IP" >&2; exit 2; }

EXTPORT=""; INTPORT=""
if [ -n "$MAP" ]; then
    EXTPORT="${MAP%%:*}"; INTPORT="${MAP##*:}"
fi
need_map() {
    [ -n "$EXTPORT" ] && [ -n "$INSIDE" ] || {
        echo "natprofile: $TYPE needs --inside and --map EXTPORT:INTPORT" >&2; exit 2; }
}

sysctl -qw net.ipv4.ip_forward=1
# Ensure conntrack sysctls exist (loads nf_conntrack) before tuning them.
iptables -t nat -L -n >/dev/null
[ -n "$UDP_TO" ] && sysctl -qw "net.netfilter.nf_conntrack_udp_timeout=$UDP_TO"
[ -n "$UDP_STO" ] && sysctl -qw "net.netfilter.nf_conntrack_udp_timeout_stream=$UDP_STO"

iptables -t nat -F
iptables -F FORWARD
iptables -F INPUT
iptables -P FORWARD DROP
conntrack -F 2>/dev/null || true
tc qdisc del dev "$EXT" root 2>/dev/null || true
if [ -n "$RTT_MS" ] && [ "$RTT_MS" -gt 0 ]; then
    tc qdisc add dev "$EXT" root netem delay "$((RTT_MS / 2))ms"
fi

# Common: outbound from LAN always allowed; inbound replies always allowed.
iptables -A FORWARD -i "$INT" -o "$EXT" -j ACCEPT
iptables -A FORWARD -i "$EXT" -o "$INT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

static_pair() {
    iptables -t nat -A PREROUTING -i "$EXT" -p udp --dport "$EXTPORT" \
        -j DNAT --to-destination "$INSIDE:$INTPORT"
    iptables -t nat -A POSTROUTING -o "$EXT" -p udp -s "$INSIDE" --sport "$INTPORT" \
        -j SNAT --to-source "$EXT_IP:$EXTPORT"
}

case "$TYPE" in
    fullcone)
        need_map
        static_pair
        iptables -t nat -A POSTROUTING -o "$EXT" -j MASQUERADE
        iptables -A FORWARD -i "$EXT" -o "$INT" -p udp -d "$INSIDE" --dport "$INTPORT" -j ACCEPT
        ;;
    restricted)
        need_map
        static_pair
        iptables -t nat -A POSTROUTING -o "$EXT" -j MASQUERADE
        # Record every destination the inside host sends UDP to (refreshes TTL).
        iptables -I FORWARD 1 -i "$INT" -o "$EXT" -p udp -s "$INSIDE" \
            -m recent --name wsf_allow --rdest --set -j ACCEPT
        iptables -A FORWARD -i "$EXT" -o "$INT" -p udp -d "$INSIDE" --dport "$INTPORT" \
            -m recent --name wsf_allow --rsource --rcheck --seconds 300 -j ACCEPT
        ;;
    portrestricted)
        need_map
        static_pair
        iptables -t nat -A POSTROUTING -o "$EXT" -j MASQUERADE
        ;;
    masq)
        iptables -t nat -A POSTROUTING -o "$EXT" -j MASQUERADE
        ;;
    masqfw)
        # masq as a real router runs it: the gateway's own INPUT chain drops
        # new inbound connections on the WAN side (OpenWrt's `wan' zone input
        # REJECT, every CPE firewall). An unsolicited datagram is then dropped
        # before conntrack confirms it, so it leaves no local conntrack entry
        # behind -- in plain `masq' (INPUT open) such an entry claims the
        # external port and pushes later outbound flows onto another one.
        iptables -t nat -A POSTROUTING -o "$EXT" -j MASQUERADE
        iptables -F INPUT
        iptables -A INPUT -i "$EXT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -i "$EXT" -j DROP
        ;;
    symmetric)
        iptables -t nat -A POSTROUTING -o "$EXT" -j MASQUERADE --random-fully
        ;;
    udpblock)
        iptables -t nat -A POSTROUTING -o "$EXT" -j MASQUERADE
        iptables -I FORWARD 1 -p udp -j DROP
        ;;
    *)
        echo "natprofile: unknown type $TYPE" >&2; exit 2 ;;
esac

# Everything else from outside is dropped (chain policy), logged count only.
iptables -A FORWARD -i "$EXT" -o "$INT" -j DROP

echo "natprofile: $TYPE ext=$EXT($EXT_IP) int=$INT($INT_IP) inside=${INSIDE:-any} map=${MAP:-dyn} udp_to=${UDP_TO:-default}/${UDP_STO:-default} rtt=${RTT_MS:-0}ms"

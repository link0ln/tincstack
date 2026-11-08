/*
    net_packet.c -- Handles in- and outgoing VPN packets
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2022 Guus Sliepen <guus@tinc-vpn.org>
                  2010      Timothy Redaelli <timothy@redaelli.eu>
                  2010      Brandon Black <blblack@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"

#ifdef HAVE_ZLIB
#define ZLIB_CONST
#include <zlib.h>

#endif

#ifdef HAVE_LZO
#include LZO1X_H
#endif

#ifdef HAVE_LZ4
#include <lz4.h>
#endif

#include "address_cache.h"
#include "cipher.h"
#include "conf.h"
#include "connection.h"
#include "compression.h"
#include "crypto.h"
#include "digest.h"
#include "device.h"
#include "ethernet.h"
#include "graph.h"
#include "ipv4.h"
#include "ipv6.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "random.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"
#include "transport_quic.h"
#include "obfs.h"

/* The minimum size of a probe is 14 bytes, but since we normally use CBC mode
   encryption, we can add a few extra random bytes without increasing the
   resulting packet size. */
#define MIN_PROBE_SIZE 18

int keylifetime = 0;
#ifdef HAVE_LZO
static char lzo_wrkmem[LZO1X_999_MEM_COMPRESS > LZO1X_1_MEM_COMPRESS ? LZO1X_999_MEM_COMPRESS : LZO1X_1_MEM_COMPRESS];
#endif

#ifdef HAVE_LZ4

#ifdef HAVE_LZ4_BUILTIN
static LZ4_stream_t lz4_stream;
#else
static void *lz4_state = NULL;
#endif // HAVE_LZ4_BUILTIN

#endif // HAVE_LZ4

static void send_udppacket(node_t *, vpn_packet_t *);
static void try_udp(node_t *n, bool has_data);
static void try_mtu(node_t *n);
static void send_udp_probe_packet(node_t *n, size_t len);

unsigned replaywin = 1024;
int multipath_current_rx_uplink = -1;
static const vpn_packet_t *multipath_current_tx_pkt = NULL;
static const sockaddr_t *current_udp_rx_addr = NULL;
static int current_udp_rx_sock = -1;
static int current_udp_rx_len = 0;
static bool current_udp_rx_direct = false;
static sockaddr_t current_probe_reply_addr;
static int current_probe_reply_sock = -1;
static const node_t *current_probe_reply_node = NULL;
static bool force_node_address = false;
bool localdiscovery = true;
bool low_power_mode = false;
bool udp_discovery = true;
int udp_discovery_keepalive_interval = 10;
int udp_discovery_interval = 2;
int udp_discovery_timeout = 30;
/* Number of UDP probe packets to send back-to-back while a node is reachable
   but UDP is not yet confirmed. A single probe every interval easily misses
   the short inbound filtering window of restricted-cone / CGNAT firewalls at
   high RTT. Sending a small burst (and doing so on both ends, triggered by the
   relayed UDP_INFO so the bursts roughly coincide) dramatically raises the
   odds the packets cross each other's NAT in the open window — this is the same
   trick a manual UDP hole-puncher uses. Once UDP is confirmed we fall back to a
   single keepalive probe, so the burst only costs traffic during hole punching. */
int udp_discovery_burst = 5;
char *address_pool = NULL;

#define MAX_SEQNO 1073741824

/* The datagram path to a direct neighbour is its meta connection's carrier
   (quic: DATAGRAM frames in the same QUIC connection). That path is alive
   exactly as long as the connection is, and the carrier keeps it alive and
   knows its own ceiling; so once UDP is confirmed and the MTU fixed over it,
   tinc's own keepalive and PMTU re-probing only add packets an idle HTTP/3
   client never sends (a burst every ~2.5 s, measured: docs/transports.md
   §9). With plain/sf/obfs this is always false. */
static bool carrier_datagram_path(const node_t *n) {
	return n->connection && n->connection->transport && n->connection->transport->send_datagram;
}

static void try_fix_mtu(node_t *n) {
	if(n->mtuprobes < 0) {
		return;
	}

	if(n->mtuprobes == 20 || n->minmtu >= n->maxmtu) {
		if(n->minmtu < MINMTU) {
			if(!carrier_datagram_path(n)) {
				logger(DEBUG_TRAFFIC, LOG_INFO, "UDP path to %s (%s) passed keepalive (%d bytes) but failed all PMTU >= %d probes; keeping traffic on meta connection",
				       n->name, n->hostname, n->minmtu, MINMTU);
				n->mtuprobes = 0;
				n->maxmtu = MTU;
				n->mtu = MTU;
				return;
			}

			n->minmtu = MINMTU;
		}

		if(n->minmtu > n->maxmtu) {
			n->minmtu = n->maxmtu;
		} else {
			n->maxmtu = n->minmtu;
		}

		n->mtu = n->minmtu;
		logger(DEBUG_TRAFFIC, LOG_INFO, "Fixing MTU of %s (%s) to %d after %d probes", n->name, n->hostname, n->mtu, n->mtuprobes);
		n->mtuprobes = -1;
		n->last_large_udp_rx = now.tv_sec;
	}
}

static void reduce_mtu(node_t *n, int mtu) {
	if(mtu < MINMTU) {
		mtu = MINMTU;
	}

	if(n->maxmtu > mtu) {
		n->maxmtu = mtu;
	}

	if(n->mtu > mtu) {
		n->mtu = mtu;
	}

	try_fix_mtu(n);
}

/* DirectSeal (obfs.h): may we probe `n' over the plain UDP socket at all?
   Not while we seal and do not yet know whether it reads sealed datagrams
   (asked over the graph; the answer takes one relay round trip, about as long
   as the SPTPS handshake that has to finish before the first probe anyway),
   and never when it cannot read them. A node that does not seal waits for
   the same answer for at most DSEAL_UNKNOWN_HOLD seconds -- the peer may be
   one that wants its direct path sealed -- and then probes as upstream does.
   A carrier datagram path or an obfs link is sealed or carried anyway. */
#define DSEAL_UNKNOWN_HOLD 3

/* Set while send_carrier_beacon() sends: the probe goes out of the plain UDP
   data socket even though the peer's meta connection carries datagrams. */
static bool carrier_beacon_raw;

static bool direct_seal_permits(node_t *n, bool probing) {
	if(carrier_datagram_path(n) ||
	                (n->connection && n->connection->transport && n->connection->transport->id == TRANSPORT_OBFS)) {
		return true;
	}

	dseal_verdict_t dv = dseal_verdict(n);

	switch(dv) {
	case DSEAL_SEND_HOLD:
		send_req_dseal(n);
		dseal_log_hold(n, dv);
		return false;

	case DSEAL_SEND_BLOCK:
		dseal_log_hold(n, dv);
		return false;

	case DSEAL_SEND_PLAIN_UNKNOWN:
		if(!probing) {
			return true;
		}

		send_req_dseal(n);
		return !(n->last_req_transports && now.tv_sec - n->last_req_transports < DSEAL_UNKNOWN_HOLD);

	case DSEAL_SEND_PLAIN:
	case DSEAL_SEND_SEAL:
		return true;
	}

	return true;
}

static void udp_probe_timeout_handler(void *data) {
	node_t *n = data;

	if(!n->status.udp_confirmed || carrier_datagram_path(n)) {
		return;
	}

	logger(DEBUG_TRAFFIC, LOG_INFO, "Too much time has elapsed since last UDP ping response from %s (%s), stopping UDP communication", n->name, n->hostname);
	n->status.udp_confirmed = false;
	n->status.udp_addr_confirmed = false;
	n->last_lan_udp_rx = 0;
	n->udp_ping_rtt = -1;
	n->maxrecentlen = 0;
	n->mtuprobes = 0;
	n->minmtu = 0;
	n->maxmtu = MTU;
}

static void send_udp_probe_reply(node_t *n, vpn_packet_t *packet, length_t len) {
	if(!n->status.sptps && !n->status.validkey) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Trying to send UDP probe reply to %s (%s) but we don't have his key yet", n->name, n->hostname);
		return;
	}

	/* Type 2 probe replies were introduced in protocol 17.3 */
	if((n->options >> 24) >= 3) {
		DATA(packet)[0] = 2;
		uint16_t len16 = htons(len);
		memcpy(DATA(packet) + 1, &len16, 2);
		packet->len = MIN_PROBE_SIZE;
		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending type 2 probe reply length %u to %s (%s)", len, n->name, n->hostname);

	} else {
		/* Legacy protocol: n won't understand type 2 probe replies. */
		DATA(packet)[0] = 1;
		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending type 1 probe reply length %u to %s (%s)", len, n->name, n->hostname);
	}

	/* Temporarily set udp_confirmed, so that the reply is sent
	   back exactly the way it came in. */

	bool udp_confirmed = n->status.udp_confirmed;
	n->status.udp_confirmed = true;
	send_udppacket(n, packet);
	n->status.udp_confirmed = udp_confirmed;
	current_probe_reply_node = NULL;
	current_probe_reply_sock = -1;
}

static void udp_probe_h(node_t *n, vpn_packet_t *packet, length_t len) {
	if(n->status.no_direct || node_is_no_direct(n->name)) {
		if(n->last_no_direct_sent != now.tv_sec) {
			n->last_no_direct_sent = now.tv_sec;
			send_no_direct_signal(n, true);
		}

		return;
	}

	if(!DATA(packet)[0]) {
		if(n->remote_no_direct) {
			n->remote_no_direct = false;
			graph();
		}

		logger(DEBUG_TRAFFIC, LOG_INFO, "Got UDP probe request %d from %s (%s)", packet->len, n->name, n->hostname);

		if(direct_seal_permits(n, false)) {
			n->last_udp_rx = now.tv_sec;
		}

		send_udp_probe_reply(n, packet, len);
		return;
	}

	/* A reply that arrived in the clear from a peer we do not send direct
	   datagrams to (DirectSeal: it cannot read them, or we do not know yet)
	   must not confirm a path we would then have to use in the clear. */
	if(!direct_seal_permits(n, false)) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Ignoring UDP probe reply from %s (%s): no direct UDP to it (DirectSeal)", n->name, n->hostname);
		return;
	}

	if(DATA(packet)[0] == 2) {
		// It's a type 2 probe reply, use the length field inside the packet
		uint16_t len16;
		memcpy(&len16, DATA(packet) + 1, 2);
		len = ntohs(len16);
	}

	if(n->status.ping_sent) {  // a probe in flight
		gettimeofday(&now, NULL);
		struct timeval rtt;
		timersub(&now, &n->udp_ping_sent, &rtt);
		n->udp_ping_rtt = (int)(rtt.tv_sec * 1000000 + rtt.tv_usec);
		n->status.ping_sent = false;
		multipath_update_udp_rtt(n, &n->address, (uint32_t)MAX(n->udp_ping_rtt, 1));
		logger(DEBUG_TRAFFIC, LOG_INFO, "Got type %d UDP probe reply %d from %s (%s) rtt=%d.%03d", DATA(packet)[0], len, n->name, n->hostname, n->udp_ping_rtt / 1000, n->udp_ping_rtt % 1000);

		int rtt_ms = n->udp_ping_rtt / 1000;

		if(rtt_ms < 1) {
			rtt_ms = 1;
		}

		if(n->smoothed_rtt_ms <= 0 || rtt_ms < n->smoothed_rtt_ms) {
			n->smoothed_rtt_ms = rtt_ms;
		} else {
			n->smoothed_rtt_ms = (n->smoothed_rtt_ms * 3 + rtt_ms) / 4;
		}

		if(n->connection && n->connection->edge && !n->connection->status.custom_weight) {
			edge_t *e = n->connection->edge;
			int new_weight = n->smoothed_rtt_ms;

			if(low_power_mode || myself->status.no_direct) {
				new_weight += 1000;
			}

			if(n->connection->options & OPTION_TCPONLY) {
				new_weight += 500;
			} else if(n->connection->transport && n->connection->transport->send_datagram) {
				new_weight += 250;
			}

			int diff = new_weight > e->weight ? new_weight - e->weight : e->weight - new_weight;
			time_t cooldown = (new_weight < e->weight) ? 5 : 60;

			if(diff >= 20 && diff * 2 >= e->weight &&
			                (!e->weight_rtt_calibrated || now.tv_sec - e->last_weight_update >= cooldown)) {
				logger(DEBUG_PROTOCOL, LOG_INFO, "Calibrating edge weight to %s from %d to %d (UDP RTT %d.%03d ms)",
				       n->name, e->weight, new_weight, n->udp_ping_rtt / 1000, n->udp_ping_rtt % 1000);
				splay_node_t *snode = splay_unlink(&edge_weight_tree, e);
				e->weight = new_weight;
				splay_insert_node(&edge_weight_tree, snode);
				e->weight_rtt_calibrated = true;
				e->last_weight_update = now.tv_sec;

				if(!tunnelserver) {
					send_add_edge(everyone, e);
				}

				graph();
			}
		}
	} else {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Got type %d UDP probe reply %d from %s (%s)", DATA(packet)[0], len, n->name, n->hostname);
	}

	n->udp_ping_unanswered = 0;
	n->last_udp_rx = now.tv_sec;

	if(len >= MINMTU) {
		n->last_large_udp_rx = now.tv_sec;
	}

	/* It's a valid reply: now we know bidirectional communication
	   is possible using the address and socket that the reply
	   packet used. */
	bool was_unconfirmed = !n->status.udp_confirmed;

	if(!n->status.udp_confirmed) {
		n->status.udp_confirmed = true;
		n->punch_go = (struct timeval) {
			0, 0
		};
		n->punch_backoff_until = 0;
		n->punch_unanswered = 0;
		timeout_del(&n->punch_timer);

		if(!n->address_cache) {
			n->address_cache = open_address_cache(n);
		}

		if(n->connection && n->connection->edge) {
			reset_address_cache(n->address_cache);
			add_recent_address(n->address_cache, &n->connection->edge->address);
		}
	}

	// Reset the UDP ping timer.

	if(udp_discovery) {
		timeout_del(&n->udp_ping_timeout);
		timeout_add(&n->udp_ping_timeout, &udp_probe_timeout_handler, n, &(struct timeval) {
			udp_discovery_timeout, 0
		});
	}

	if(len > n->maxmtu) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Increase in PMTU to %s (%s) detected, restarting PMTU discovery", n->name, n->hostname);
		n->minmtu = len;
		n->maxmtu = MTU;
		/* Set mtuprobes to 1 so that try_mtu() doesn't reset maxmtu */
		n->mtuprobes = 1;
		return;
	} else if(n->mtuprobes < 0 && len == n->maxmtu) {
		/* We got a maxmtu sized packet, confirming the PMTU is still valid. */
		n->mtuprobes = -1;
		n->mtu_ping_sent = now;
	}

	/* If applicable, raise the minimum supported MTU */

	if(n->minmtu < len) {
		n->minmtu = len;

		if(n->mtu < n->minmtu) {
			n->mtu = n->minmtu;
		}

		try_fix_mtu(n);
	}

	if(was_unconfirmed) {
		try_mtu(n);
	}
}

static length_t compress_packet_lz4(uint8_t *dest, length_t dest_len, const uint8_t *source, length_t len) {
#ifdef HAVE_LZ4
#ifdef HAVE_LZ4_BUILTIN
	return LZ4_compress_fast_extState(&lz4_stream, (const char *) source, (char *) dest, len, dest_len, 0);
#else

	/* @FIXME: Put this in a better place, and free() it too. */
	if(lz4_state == NULL) {
		lz4_state = xmalloc(LZ4_sizeofState());
	}

	return LZ4_compress_fast_extState(lz4_state, (const char *) source, (char *) dest, len, dest_len, 0);
#endif /* HAVE_LZ4_BUILTIN */
#endif /* HAVE_LZ4 */
	return 0;
}

static length_t compress_packet_lzo(uint8_t *dest, length_t dest_len, const uint8_t *source, length_t len, compression_level_t level) {
#ifdef HAVE_LZO
	lzo_uint lzolen = dest_len;
	int result;

	if(level == COMPRESS_LZO_HI) {
		result = lzo1x_999_compress(source, len, dest, &lzolen, lzo_wrkmem);
	} else { // level == COMPRESS_LZO_LO
		result = lzo1x_1_compress(source, len, dest, &lzolen, lzo_wrkmem);
	}

	if(result == LZO_E_OK) {
		return lzolen;
	}

#endif /* HAVE_LZO */

	return 0;
}

static length_t compress_packet_zlib(uint8_t *dest, length_t dest_len, const uint8_t *source, length_t len, compression_level_t level) {
#ifdef HAVE_ZLIB
	unsigned long result_len = dest_len;

	if(compress2(dest, &result_len, source, len, level) == Z_OK) {
		return result_len;
	}

#endif /* HAVE_ZLIB */

	return 0;
}

static length_t compress_packet(uint8_t *dest, length_t dest_len, const uint8_t *source, length_t len, compression_level_t level) {
	switch(level) {

	case COMPRESS_LZ4:
		return compress_packet_lz4(dest, dest_len, source, len);

	case COMPRESS_LZO_HI:
	case COMPRESS_LZO_LO:
		return compress_packet_lzo(dest, dest_len, source, len, level);

	case COMPRESS_ZLIB_9:
	case COMPRESS_ZLIB_8:
	case COMPRESS_ZLIB_7:
	case COMPRESS_ZLIB_6:
	case COMPRESS_ZLIB_5:
	case COMPRESS_ZLIB_4:
	case COMPRESS_ZLIB_3:
	case COMPRESS_ZLIB_2:
	case COMPRESS_ZLIB_1: {
		return compress_packet_zlib(dest, dest_len, source, len, level);
	}

	case COMPRESS_NONE:
		if(dest_len >= len) {
			memcpy(dest, source, len);
			return len;
		} else {
			return 0;
		}

	default:
		return 0;
	}
}

static length_t uncompress_packet(uint8_t *dest, length_t dest_len, const uint8_t *source, length_t len, compression_level_t level) {
	switch(level) {
#ifdef HAVE_LZ4

	case COMPRESS_LZ4:

		return LZ4_decompress_safe((char *)source, (char *) dest, len, dest_len);

#endif
#ifdef HAVE_LZO

	case COMPRESS_LZO_HI:
	case COMPRESS_LZO_LO: {
		lzo_uint lzo_len = dest_len;

		if(lzo1x_decompress_safe(source, len, dest, &lzo_len, NULL) == LZO_E_OK) {
			return lzo_len;
		} else {
			return 0;
		}
	}

#endif
#ifdef HAVE_ZLIB

	case COMPRESS_ZLIB_9:
	case COMPRESS_ZLIB_8:
	case COMPRESS_ZLIB_7:
	case COMPRESS_ZLIB_6:
	case COMPRESS_ZLIB_5:
	case COMPRESS_ZLIB_4:
	case COMPRESS_ZLIB_3:
	case COMPRESS_ZLIB_2:
	case COMPRESS_ZLIB_1: {
		static z_stream stream;

		if(stream.next_in) {
			inflateReset(&stream);
		} else {
			inflateInit(&stream);
		}

		stream.next_in = source;
		stream.avail_in = len;
		stream.next_out = dest;
		stream.avail_out = dest_len;
		stream.total_out = 0;

		if(inflate(&stream, Z_FINISH) == Z_STREAM_END) {
			return stream.total_out;
		} else {
			return 0;
		}
	}

#endif

	case COMPRESS_NONE:
		if(dest_len >= len) {
			memcpy(dest, source, len);
			return len;
		} else {
			return 0;
		}

	default:
		return 0;
	}
}

/* VPN packet I/O */

static void receive_packet(node_t *n, vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Received packet of %d bytes from %s (%s)",
	       packet->len, n->name, n->hostname);

	n->in_packets++;
	n->in_bytes += packet->len;

	route(n, packet);
}

static bool try_mac(node_t *n, const vpn_packet_t *inpkt) {
	if(n->status.sptps) {
		return sptps_verify_datagram(&n->sptps, DATA(inpkt), inpkt->len);
	}

#ifdef DISABLE_LEGACY
	return false;
#else

	if(!n->status.validkey_in || !digest_active(n->indigest) || (size_t)inpkt->len < sizeof(seqno_t) + digest_length(n->indigest)) {
		return false;
	}

	return digest_verify(n->indigest, inpkt->data, inpkt->len - digest_length(n->indigest), inpkt->data + inpkt->len - digest_length(n->indigest));
#endif
}

/* Update `n`'s UDP endpoint (`n->sock`, `n->address`, `n->last_lan_udp_rx`) as
   soon as an incoming direct UDP datagram has been cryptographically verified,
   BEFORE `udp_probe_h()` runs so that:
   1. A probe reply (`send_udp_probe_reply`) is sent back to the exact address
      the probe request arrived from (e.g. a LocalDiscovery LAN IP) instead of
      a stale WAN address;
   2. A probe reply that sets `n->status.udp_confirmed = true` inside
      `udp_probe_h()` does not immediately get `udp_confirmed` reset to `false`
      by a post-`receive_udppacket()` call to `update_node_udp()`;
   3. A slower NAT-hairpinned packet arriving from a public WAN IP milliseconds
      after a direct private-LAN packet does not overwrite the active LAN path. */
static void apply_incoming_udp_endpoint(node_t *n, bool is_probe_req) {
	if(!n || !current_udp_rx_addr || current_udp_rx_sock < 0) {
		return;
	}

	const sockaddr_t *addr = current_udp_rx_addr;
	int sock_idx = current_udp_rx_sock;
	int pkt_len = current_udp_rx_len;
	current_udp_rx_addr = NULL;
	current_udp_rx_sock = -1;
	current_udp_rx_len = 0;

	if(!direct_seal_permits(n, false)) {
		return;
	}

	/* If an unconfirmed probe request arrives from a different address while we
	   already have a confirmed UDP path to `n`, do not tear down `n->address`
	   (`update_node_udp` resets `udp_confirmed = false`) until 2-way reachability
	   on the new address is proven by a probe reply or data packet. Record the
	   source endpoint so `send_udp_probe_reply()` answers back to `addr`. */
	if(is_probe_req && n->status.udp_confirmed && sockaddrcmp(addr, &n->address)) {
		current_probe_reply_addr = *addr;
		current_probe_reply_sock = sock_idx;
		current_probe_reply_node = n;
		multipath_record_udp_rx(n, multipath_current_rx_uplink, sock_idx, addr, pkt_len);
		return;
	}

	bool addr_is_lan = sockaddr_is_private_lan(addr);

	if(addr_is_lan) {
		n->last_lan_udp_rx = now.tv_sec;
	} else if(node_has_active_lan_udp(n) && (now.tv_sec - n->last_lan_udp_rx <= udp_discovery_interval + 1)) {
		return;
	}

	n->sock = sock_idx;
	multipath_record_udp_rx(n, multipath_current_rx_uplink, sock_idx, addr, pkt_len);

	if(sockaddrcmp(addr, &n->address)) {
		bool upgrade_to_lan = addr_is_lan && !sockaddr_is_private_lan(&n->address);

		if(multipath_mode == MULTIPATH_OFF || !n->status.udp_confirmed || upgrade_to_lan || (now.tv_sec - n->last_udp_rx > pinginterval)) {
			update_node_udp(n, addr);
		}
	}

	n->status.udp_addr_confirmed = true;
}

static bool receive_udppacket(node_t *n, vpn_packet_t *inpkt) {
	if(n->status.sptps) {
		if(!n->sptps.state) {
			if(!n->status.waitingforkey) {
				logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got packet from %s (%s) but we haven't exchanged keys yet", n->name, n->hostname);
				send_req_key(n);
			} else {
				logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got packet from %s (%s) but he hasn't got our key yet", n->name, n->hostname);
			}

			return false;
		}

		n->status.udppacket = true;
		bool result = sptps_receive_data(&n->sptps, DATA(inpkt), inpkt->len);
		n->status.udppacket = false;

		if(!result) {
			/* Uh-oh. It might be that the tunnel is stuck in some corrupted state,
			   so let's restart SPTPS in case that helps. But don't do that too often
			   to prevent storms, and because that would make life a little too easy
			   for external attackers trying to DoS us. The cooldown is generous
			   (30s) because after a reset, stale UDP packets from the previous
			   session keep arriving for a while; we want the TCP-relayed handshake
			   to finish in peace before considering another reset. */
			if(n->sptps.state == SPTPS_SECONDARY_KEX && n->last_req_key < now.tv_sec - 30 &&
			                (!n->status.validkey || now.tv_sec - n->last_udp_rx > 5)) {
				logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to decode raw UDP packet from %s (%s), restarting SPTPS", n->name, n->hostname);
				send_req_key(n);
			}

			return false;
		}

		return true;
	}

#ifdef DISABLE_LEGACY
	return false;
#else
	vpn_packet_t pkt1, pkt2;
	vpn_packet_t *pkt[] = { &pkt1, &pkt2, &pkt1, &pkt2 };
	int nextpkt = 0;
	size_t outlen;
	pkt1.offset = DEFAULT_PACKET_OFFSET;
	pkt2.offset = DEFAULT_PACKET_OFFSET;

	if(!n->status.validkey_in) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got packet from %s (%s) but he hasn't got our key yet", n->name, n->hostname);
		return false;
	}

	/* Check packet length */

	if((size_t)inpkt->len < sizeof(seqno_t) + digest_length(n->indigest)) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got too short packet from %s (%s)",
		       n->name, n->hostname);
		return false;
	}

	/* It's a legacy UDP packet, the data starts after the seqno */

	inpkt->offset += sizeof(seqno_t);

	/* Check the message authentication code */

	if(digest_active(n->indigest)) {
		inpkt->len -= digest_length(n->indigest);

		if(!digest_verify(n->indigest, SEQNO(inpkt), inpkt->len, SEQNO(inpkt) + inpkt->len)) {
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got unauthenticated packet from %s (%s)", n->name, n->hostname);
			return false;
		}
	}

	/* Decrypt the packet */

	if(cipher_active(n->incipher)) {
		vpn_packet_t *outpkt = pkt[nextpkt++];
		outlen = MAXSIZE;

		if(!cipher_decrypt(n->incipher, SEQNO(inpkt), inpkt->len, SEQNO(outpkt), &outlen, true)) {
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Error decrypting packet from %s (%s)", n->name, n->hostname);
			return false;
		}

		outpkt->len = outlen;
		inpkt = outpkt;
	}

	/* Check the sequence number */

	seqno_t seqno;
	memcpy(&seqno, SEQNO(inpkt), sizeof(seqno));
	seqno = ntohl(seqno);
	inpkt->len -= sizeof(seqno);

	if(replaywin) {
		if(seqno != n->received_seqno + 1) {
			if(seqno >= n->received_seqno + replaywin * 8) {
				if(n->farfuture++ < replaywin >> 2) {
					logger(DEBUG_TRAFFIC, LOG_WARNING, "Packet from %s (%s) is %d seqs in the future, dropped (%u)",
					       n->name, n->hostname, seqno - n->received_seqno - 1, n->farfuture);
					return false;
				}

				logger(DEBUG_TRAFFIC, LOG_WARNING, "Lost %d packets from %s (%s)",
				       seqno - n->received_seqno - 1, n->name, n->hostname);
				memset(n->late, 0, replaywin);
			} else if(seqno <= n->received_seqno) {
				if((n->received_seqno >= replaywin * 8 && seqno <= n->received_seqno - replaywin * 8) || !(n->late[(seqno / 8) % replaywin] & (1 << seqno % 8))) {
					logger(DEBUG_TRAFFIC, LOG_WARNING, "Got late or replayed packet from %s (%s), seqno %d, last received %d",
					       n->name, n->hostname, seqno, n->received_seqno);
					return false;
				}
			} else {
				for(seqno_t i = n->received_seqno + 1; i < seqno; i++) {
					n->late[(i / 8) % replaywin] |= 1 << i % 8;
				}
			}
		}

		n->farfuture = 0;
		n->late[(seqno / 8) % replaywin] &= ~(1 << seqno % 8);
	}

	if(seqno > n->received_seqno) {
		n->received_seqno = seqno;
	}

	n->received++;

	if(n->received_seqno > MAX_SEQNO) {
		regenerate_key();
	}

	/* Decompress the packet */

	length_t origlen = inpkt->len;

	if(n->incompression != COMPRESS_NONE) {
		vpn_packet_t *outpkt = pkt[nextpkt++];
		outpkt->len = uncompress_packet(DATA(outpkt), MAXSIZE - outpkt->offset, DATA(inpkt), inpkt->len, n->incompression);

		if(!outpkt->len) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while uncompressing packet from %s (%s)",
			       n->name, n->hostname);
			return false;
		}

		inpkt = outpkt;

		if(origlen > MTU / 64 + 20) {
			origlen -= MTU / 64 + 20;
		} else {
			origlen = 0;
		}
	}

	if(inpkt->len > n->maxrecentlen) {
		n->maxrecentlen = inpkt->len;
	}

	inpkt->priority = 0;
	bool is_probe = !DATA(inpkt)[12] && !DATA(inpkt)[13];
	apply_incoming_udp_endpoint(n, is_probe && !DATA(inpkt)[0]);

	if(is_probe) {
		udp_probe_h(n, inpkt, origlen);
	} else {
		receive_packet(n, inpkt);
	}

	return true;
#endif
}

void receive_tcppacket(connection_t *c, const char *buffer, size_t len) {
	if(c && c->status.active) {
		c->post_activate_verified = true;
	}

	vpn_packet_t outpkt;
	outpkt.offset = DEFAULT_PACKET_OFFSET;

	if(len > sizeof(outpkt.data) - outpkt.offset) {
		return;
	}

	outpkt.len = len;

	if(c->options & OPTION_TCPONLY) {
		outpkt.priority = 0;
	} else {
		outpkt.priority = -1;
	}

	/* If a direct neighbour sends us a small packet (< MINMTU) over TCP
	   while we still think its PMTU is >= len, and we have heard no UDP from
	   it for at least udp_discovery_interval seconds, the neighbour has
	   already demoted its own minmtu to 0 and fallen back to TCP. Reset our
	   minmtu to 0 immediately so our replies also use TCP instead of going
	   into a dead UDP blackhole, and arm try_mtu() to re-verify when UDP recovers. */
	if(c->node && c->node->status.udp_confirmed && !carrier_datagram_path(c->node) &&
	                len < MINMTU && c->node->minmtu >= (int)len &&
	                now.tv_sec - c->node->last_udp_rx >= udp_discovery_interval) {
		c->node->minmtu = 0;

		if(c->node->mtuprobes < 0) {
			c->node->mtuprobes = 0;
		}
	}

	memcpy(DATA(&outpkt), buffer, len);

	receive_packet(c->node, &outpkt);
}

bool receive_tcppacket_sptps(connection_t *c, const char *data, size_t len) {
	if(c && c->status.active) {
		c->post_activate_verified = true;
	}

	if(len < sizeof(node_id_t) + sizeof(node_id_t)) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Got too short TCP SPTPS packet from %s (%s)", c->name, c->hostname);
		return false;
	}

	node_t *to = lookup_node_id((node_id_t *)data);
	data += sizeof(node_id_t);
	len -= sizeof(node_id_t);

	if(!to) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Got TCP SPTPS packet from %s (%s) with unknown destination ID", c->name, c->hostname);
		return true;
	}

	node_t *from = lookup_node_id((node_id_t *)data);
	data += sizeof(node_id_t);
	len -= sizeof(node_id_t);

	if(!from) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Got TCP SPTPS packet from %s (%s) with unknown source ID", c->name, c->hostname);
		return true;
	}

	if(!to->status.reachable) {
		/* This can happen in the form of a race condition
		   if the node just became unreachable. */
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Cannot relay TCP packet from %s (%s) because the destination, %s (%s), is unreachable", from->name, from->hostname, to->name, to->hostname);
		return true;
	}

	/* Help the sender reach us over UDP.
	   Note that we only do this if we're the destination or the static relay;
	   otherwise every hop would initiate its own UDP info message, resulting in elevated chatter. */
	if(to == myself || (to->via == myself && to->nexthop == to)) {
		send_udp_info(myself, from);
	}

	/* If we're not the final recipient, relay the packet.

	   Relaying needs no key of our own with the destination: the record is
	   end-to-end SPTPS between `from' and `to', and send_sptps_data() only
	   uses node ids and the path to `to' (the UDP twin in process_sptps_udp()
	   has never checked a key). The old `to->status.validkey' gate dropped
	   every packet for a TCP-only neighbour, because try_tx_sptps() never
	   starts SPTPS with one -- i.e. two nodes that both reach this node over
	   the https carrier (TCPONLY|INDIRECT links) could not exchange any data
	   (docs/nat.md §5.2, testing/nat-sim `matrix --transport https`). */

	if(to != myself) {
		size_t origlen = len > SPTPS_DATAGRAM_OVERHEAD ? len - SPTPS_DATAGRAM_OVERHEAD : 0;
		node_t *relay = (to->via != myself && origlen <= to->via->minmtu) ? to->via : to->nexthop;

		if(!relay || relay == myself || relay == c->node || relay == from) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Routing loop relaying TCP SPTPS packet from %s to %s via %s!", from->name, to->name, relay ? relay->name : "(null)");
			return true;
		}

		send_sptps_data(to, from, 0, data, len);
		try_tx(to, true);
		return true;
	}

	/* The packet is for us */

	if(!sptps_receive_data(&from->sptps, data, len)) {
		/* Uh-oh. It might be that the tunnel is stuck in some corrupted state,
		   so let's restart SPTPS in case that helps. But don't do that too often
		   to prevent storms. Cooldown raised to 30s for the same reason as in
		   receive_udppacket: give the in-progress handshake time to finish. */
		if(from->sptps.state == SPTPS_SECONDARY_KEX && from->last_req_key < now.tv_sec - 30 &&
		                (!from->status.validkey || now.tv_sec - from->last_udp_rx > 5)) {
			logger(DEBUG_PROTOCOL, LOG_ERR, "Failed to decode raw TCP packet from %s (%s), restarting SPTPS", from->name, from->hostname);
			send_req_key(from);
		}

		return true;
	}

	send_mtu_info(myself, from, MTU);
	return true;
}

static void send_sptps_packet(node_t *n, vpn_packet_t *origpkt) {
	if(!n->status.validkey && !n->connection) {
		return;
	}

	uint8_t type = 0;
	int offset = 0;

	if(!(DATA(origpkt)[12] | DATA(origpkt)[13])) {
		if(n->sptps.outstate) {
			sptps_send_record(&n->sptps, PKT_PROBE, DATA(origpkt), origpkt->len);
		}

		return;
	}

	if(routing_mode == RMODE_ROUTER) {
		offset = 14;
	} else {
		type = PKT_MAC;
	}

	if(origpkt->len < offset) {
		return;
	}

	if(origpkt->len > 14 &&
	                (routing_mode == RMODE_ROUTER ||
	                 (DATA(origpkt)[12] == 0x08 && DATA(origpkt)[13] == 0x00) ||
	                 (DATA(origpkt)[12] == 0x86 && DATA(origpkt)[13] == 0xdd)) &&
	                is_tls_client_hello((const uint8_t *)DATA(origpkt) + 14, origpkt->len - 14)) {
		node_t *hop = (n->connection) ? n : (n->nexthop ? n->nexthop : n);
		if(hop && hop->connection) {
			https_pad_next_burst(hop->connection, 1350, 1650);
		}
		obfs_pad_next_burst(hop ? hop : n);
		if(n != hop) {
			obfs_pad_next_burst(n);
		}
	}

	vpn_packet_t outpkt;

	if(n->outcompression != COMPRESS_NONE) {
		outpkt.offset = 0;
		length_t len = compress_packet(DATA(&outpkt) + offset, MAXSIZE - offset, DATA(origpkt) + offset, origpkt->len - offset, n->outcompression);

		if(!len) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while compressing packet to %s (%s)", n->name, n->hostname);
		} else if(len < origpkt->len - offset) {
			outpkt.len = len + offset;
			origpkt = &outpkt;
			type |= PKT_COMPRESSED;
		}
	}

	/* If we have a direct metaconnection to n, and we can't use UDP, then
	   don't bother with SPTPS and just use a "plaintext" PACKET message.
	   We don't really care about end-to-end security since we're not
	   sending the message through any intermediate nodes.
	   Exception: in MULTIPATH_REDUNDANT mode with multiple connections and
	   a valid SPTPS key, use SPTPS records so the receiver deduplicates copies
	   by SPTPS sequence number. */
	if(n->connection && origpkt->len - offset > n->minmtu &&
	   !(multipath_mode == MULTIPATH_REDUNDANT && n->status.validkey && n->connections.count > 1)) {
		connection_t *conns[2] = {NULL, NULL};
		int nconns = multipath_select_connections(n, origpkt, conns);
		send_tcppacket(nconns > 0 ? conns[0] : n->connection, origpkt);
	} else {
		if(origpkt->len >= MINMTU && n->status.udp_confirmed && !carrier_datagram_path(n) &&
		                n->mtuprobes == -1 &&
		                now.tv_sec - n->last_large_udp_rx >= udp_discovery_keepalive_interval &&
		                now.tv_sec - n->mtu_ping_sent.tv_sec >= udp_discovery_keepalive_interval) {
			n->mtuprobes = -2;
			n->mtu_ping_sent = now;
			send_udp_probe_packet(n, n->maxmtu);
		}

		multipath_current_tx_pkt = origpkt;
		sptps_send_record(&n->sptps, type, DATA(origpkt) + offset, origpkt->len - offset);
		multipath_current_tx_pkt = NULL;
	}
}

static void adapt_socket(const sockaddr_t *sa, size_t *sock) {
	/* Make sure we have a suitable socket for the chosen address */
	if(listen_socket[*sock].sa.sa.sa_family != sa->sa.sa_family) {
		for(int i = 0; i < listen_sockets; i++) {
			if(listen_socket[i].sa.sa.sa_family == sa->sa.sa_family) {
				*sock = i;
				break;
			}
		}
	}
}

bool node_tcponly(const node_t *n) {
	return ((myself->options | n->options | (n->connection ? n->connection->options : 0)) & OPTION_TCPONLY) != 0;
}

static bool sockaddr_is_unicast_ip(const sockaddr_t *sa) {
	if(!sa) {
		return false;
	}

	if(sa->sa.sa_family == AF_INET) {
		uint32_t ip = ntohl(sa->in.sin_addr.s_addr);
		return ip != 0 && (ip >> 24) != 127;
	}

	if(sa->sa.sa_family == AF_INET6) {
		return !IN6_IS_ADDR_UNSPECIFIED(&sa->in6.sin6_addr) && !IN6_IS_ADDR_LOOPBACK(&sa->in6.sin6_addr);
	}

	return false;
}

bool sockaddr_is_private_lan(const sockaddr_t *sa) {
	if(!sockaddr_is_unicast_ip(sa)) {
		return false;
	}

	if(sa->sa.sa_family == AF_INET) {
		const ipv4_t *dst = (const ipv4_t *)&sa->in.sin_addr;
		subnet_t *s = lookup_subnet_ipv4(dst);

		if(s && s->net.ipv4.prefixlength == 32) {
			return false;
		}

		uint32_t ip = ntohl(sa->in.sin_addr.s_addr);
		return ((ip & 0xff000000u) == 0x0a000000u) || /* 10.0.0.0/8 */
		       ((ip & 0xfff00000u) == 0xac100000u) || /* 172.16.0.0/12 */
		       ((ip & 0xffff0000u) == 0xc0a80000u) || /* 192.168.0.0/16 */
		       ((ip & 0xffff0000u) == 0xa9fe0000u);   /* 169.254.0.0/16 */
	}

	if(sa->sa.sa_family == AF_INET6) {
		const ipv6_t *dst = (const ipv6_t *)&sa->in6.sin6_addr;
		subnet_t *s = lookup_subnet_ipv6(dst);

		if(s && s->net.ipv6.prefixlength == 128) {
			return false;
		}

		const uint8_t *b = sa->in6.sin6_addr.s6_addr;
		return (b[0] == 0xfe && (b[1] & 0xc0) == 0x80 && sa->in6.sin6_scope_id != 0) || /* fe80::/10 (scoped) */
		       ((b[0] & 0xfe) == 0xfc);                                                  /* fc00::/7 */
	}

	return false;
}

bool node_has_active_lan_udp(const node_t *n) {
	return n && n->status.udp_confirmed && sockaddr_is_private_lan(&n->address) &&
	       n->last_lan_udp_rx && (now.tv_sec - n->last_lan_udp_rx < udp_discovery_keepalive_interval * 2);
}

/* Returns true when `sa` has the same public WAN IP that a remote peer sees
   for `myself` (`e->reverse->address`) while our local socket address for that
   edge is on a private LAN (or wildcard), meaning `sa` is our own NAT router's
   public WAN IP (a hairpin NAT reflection). */
bool sockaddr_is_my_nat_wan_ip(const sockaddr_t *sa) {
	if(!myself || !sockaddr_is_unicast_ip(sa) || sockaddr_is_private_lan(sa)) {
		return false;
	}

	for splay_each(edge_t, e, &myself->edge_tree) {
		if(!e->reverse || !sockaddr_is_unicast_ip(&e->reverse->address) ||
		                sockaddr_is_private_lan(&e->reverse->address) ||
		                e->reverse->address.sa.sa_family != sa->sa.sa_family) {
			continue;
		}

		if(sockaddr_is_unicast_ip(&e->local_address) && !sockaddr_is_private_lan(&e->local_address) &&
		                e->local_address.sa.sa_family == sa->sa.sa_family) {
			if(sa->sa.sa_family == AF_INET &&
			                e->local_address.in.sin_addr.s_addr == e->reverse->address.in.sin_addr.s_addr) {
				continue;
			}

			if(sa->sa.sa_family == AF_INET6 &&
			                !memcmp(&e->local_address.in6.sin6_addr, &e->reverse->address.in6.sin6_addr, sizeof(struct in6_addr))) {
				continue;
			}
		}

		if(sa->sa.sa_family == AF_INET) {
			if(sa->in.sin_addr.s_addr == e->reverse->address.in.sin_addr.s_addr) {
				return true;
			}
		} else if(sa->sa.sa_family == AF_INET6) {
			if(!memcmp(&sa->in6.sin6_addr, &e->reverse->address.in6.sin6_addr, sizeof(struct in6_addr))) {
				return true;
			}
		}
	}

	return false;
}

static bool node_shares_my_wan_ip(const node_t *n) {
	if(!n || !myself || n == myself) {
		return false;
	}

	if(sockaddr_is_my_nat_wan_ip(&n->address)) {
		return true;
	}

	for splay_each(edge_t, e, &n->edge_tree) {
		if(e->reverse && sockaddr_is_my_nat_wan_ip(&e->reverse->address)) {
			return true;
		}
	}

	return false;
}

static bool sockaddr_same_lan_as_myself(const sockaddr_t *sa) {
	if(!myself || !sockaddr_is_private_lan(sa)) {
		return false;
	}

	for splay_each(edge_t, e, &myself->edge_tree) {
		const sockaddr_t *my_sa = NULL;

		if(sockaddr_is_unicast_ip(&e->local_address)) {
			my_sa = &e->local_address;
		} else if(e->reverse && sockaddr_is_private_lan(&e->reverse->address)) {
			my_sa = &e->reverse->address;
		}

		if(!my_sa || my_sa->sa.sa_family != sa->sa.sa_family) {
			continue;
		}

		if(sa->sa.sa_family == AF_INET) {
			uint32_t a = ntohl(sa->in.sin_addr.s_addr);
			uint32_t b = ntohl(my_sa->in.sin_addr.s_addr);

			if((a & 0xffffff00u) == (b & 0xffffff00u)) {
				return true;
			}
		} else if(sa->sa.sa_family == AF_INET6) {
			if(!memcmp(&sa->in6.sin6_addr, &my_sa->in6.sin6_addr, 8)) {
				return true;
			}
		}
	}

	return false;
}

static const sockaddr_t *edge_usable_local_addr(const edge_t *e) {
	if(!e) {
		return NULL;
	}

	if(sockaddr_is_unicast_ip(&e->local_address) && !address_routes_via_vpn(&e->local_address)) {
		return &e->local_address;
	}

	/* Fallback when e->local_address is 0.0.0.0 (e.g. an older peer over a
	   UDP carrier) and its neighbour saw it on a private LAN address. */
	if(e->reverse && sockaddr_is_private_lan(&e->reverse->address) && !address_routes_via_vpn(&e->reverse->address)) {
		return &e->reverse->address;
	}

	return NULL;
}

bool node_best_lan_address(const node_t *n, sockaddr_t *out) {
	if(!n || !out) {
		return false;
	}

	for splay_each(edge_t, e, &n->edge_tree) {
		const sockaddr_t *cand = edge_usable_local_addr(e);

		if(cand && sockaddr_same_lan_as_myself(cand)) {
			*out = *cand;
			return true;
		}
	}

	if(sockaddr_is_private_lan(&n->address) && !address_routes_via_vpn(&n->address)) {
		*out = n->address;
		return true;
	}

	for splay_each(edge_t, e, &n->edge_tree) {
		const sockaddr_t *cand = edge_usable_local_addr(e);

		if(cand && sockaddr_is_private_lan(cand)) {
			*out = *cand;
			return true;
		}
	}

	return false;
}

bool node_shares_local_lan(const node_t *n) {
	if(!n || !myself || n == myself) {
		return false;
	}

	const uint32_t udp_carriers = TRANSPORT_BIT(TRANSPORT_PLAIN) |
	                              TRANSPORT_BIT(TRANSPORT_SF) |
	                              TRANSPORT_BIT(TRANSPORT_OBFS) |
	                              TRANSPORT_BIT(TRANSPORT_QUIC);

	if(n->transports && !(n->transports & udp_carriers)) {
		return false;
	}

	bool same_wan = node_shares_my_wan_ip(n);

	for splay_each(edge_t, e, &n->edge_tree) {
		const sockaddr_t *cand = edge_usable_local_addr(e);

		if(cand && (sockaddr_same_lan_as_myself(cand) ||
		                (same_wan && sockaddr_is_private_lan(cand)))) {
			return true;
		}
	}

	return false;
}

static void choose_local_address(const node_t *n, const sockaddr_t **sa, size_t *sock);

static void choose_udp_address(const node_t *n, const sockaddr_t **sa, size_t *sock) {
	if(force_node_address) {
		if(n->address.sa.sa_family == AF_UNSPEC || n->address.sa.sa_family == AF_UNKNOWN ||
		                address_routes_via_vpn(&n->address) || sockaddr_is_my_nat_wan_ip(&n->address)) {
			*sa = NULL;
			return;
		}

		*sa = &n->address;
		*sock = n->sock;
		adapt_socket(*sa, sock);
		return;
	}

	if(current_probe_reply_node == n && current_probe_reply_sock >= 0 &&
	                !address_routes_via_vpn(&current_probe_reply_addr) &&
	                !sockaddr_is_my_nat_wan_ip(&current_probe_reply_addr)) {
		*sa = &current_probe_reply_addr;
		*sock = (size_t)current_probe_reply_sock;
		adapt_socket(*sa, sock);
		return;
	}

	if(n->connection && n->connection->transport &&
	                (n->connection->transport->caps & (TRANSPORT_CAP_SINGLE_FLOW | TRANSPORT_CAP_DATA_UDP)) == (TRANSPORT_CAP_SINGLE_FLOW | TRANSPORT_CAP_DATA_UDP)) {
		*sa = &n->connection->address;
		*sock = n->sock;
		adapt_socket(*sa, sock);
		return;
	}

	/* Latest guess */
	*sa = &n->address;
	*sock = n->sock;

	/* If the UDP address is confirmed, use it, unless OS routing changed
	   so that this address now routes back into our own VPN interface. */
	if(n->status.udp_confirmed) {
		if(n->last_vpn_route_check != now.tv_sec) {
			node_t *mut_n = (node_t *)n;
			mut_n->last_vpn_route_check = now.tv_sec;

			if((*sa)->sa.sa_family == AF_UNSPEC || (*sa)->sa.sa_family == AF_UNKNOWN ||
			                address_routes_via_vpn(*sa) || sockaddr_is_my_nat_wan_ip(*sa)) {
				*sa = NULL;

				if(!carrier_datagram_path(n)) {
					logger(DEBUG_TRAFFIC, LOG_INFO, "Confirmed UDP address of %s (%s) now routes via VPN or self WAN IP, stopping direct UDP communication", n->name, n->hostname);
					mut_n->status.udp_confirmed = false;
					mut_n->status.udp_addr_confirmed = false;
					mut_n->last_lan_udp_rx = 0;
					mut_n->udp_ping_rtt = -1;
					mut_n->maxrecentlen = 0;
					mut_n->mtuprobes = 0;
					mut_n->minmtu = 0;
					mut_n->maxmtu = MTU;
				}

				return;
			}
		}

		return;
	}

	/* If we have already received direct UDP from this peer on a private LAN
	   address, keep probing that LAN address instead of rotating 2 out of 3
	   probes to a remote relay's WAN view (`e->reverse->address`). */
	if(sockaddr_is_private_lan(*sa) && n->last_lan_udp_rx &&
	                (now.tv_sec - n->last_lan_udp_rx < udp_discovery_keepalive_interval * 2) &&
	                !address_routes_via_vpn(*sa)) {
		adapt_socket(*sa, sock);
		return;
	}

	/* Send the first two of every three unconfirmed probes to n->address
	   (the peer's reflexive UDP address discovered via ANS_KEY / UDP_INFO /
	   coordinated hole punch), and the third to an edge address. */

	node_t *mut_n = (node_t *)n;

	if((mut_n->udp_probe_seq++ % 3) != 2) {
		if((*sa)->sa.sa_family != AF_UNSPEC && (*sa)->sa.sa_family != AF_UNKNOWN &&
		                !address_routes_via_vpn(*sa) && !sockaddr_is_my_nat_wan_ip(*sa)) {
			adapt_socket(*sa, sock);
			return;
		}
	}

	/* Otherwise, address are found in edges to this node.
	   So we pick a random edge and a random socket. */

	unsigned int i = 0;
	unsigned int j = prng(n->edge_tree.count);
	edge_t *candidate = NULL;

	for splay_each(edge_t, e, &n->edge_tree) {
		if(i++ == j) {
			if(e->reverse && !address_routes_via_vpn(&e->reverse->address) &&
			                !sockaddr_is_my_nat_wan_ip(&e->reverse->address)) {
				candidate = e->reverse;
			}

			break;
		}
	}

	if(!candidate) {
		for splay_each(edge_t, e, &n->edge_tree) {
			if(e->reverse && !address_routes_via_vpn(&e->reverse->address) &&
			                !sockaddr_is_my_nat_wan_ip(&e->reverse->address)) {
				candidate = e->reverse;
				break;
			}
		}
	}

	if(candidate) {
		*sa = &candidate->address;
		*sock = prng(listen_sockets);
	} else {
		choose_local_address(n, sa, sock);
		return;
	}

	if(!*sa || (*sa)->sa.sa_family == AF_UNSPEC || (*sa)->sa.sa_family == AF_UNKNOWN ||
	                address_routes_via_vpn(*sa) || sockaddr_is_my_nat_wan_ip(*sa)) {
		choose_local_address(n, sa, sock);
		return;
	}

	adapt_socket(*sa, sock);
}

static void choose_local_address(const node_t *n, const sockaddr_t **sa, size_t *sock) {
	*sa = NULL;

	if(!n || !n->edge_tree.count) {
		return;
	}

	/* First preference: an edge whose local address (or private-LAN reverse
	   address) is on the same /24 (IPv4) or /64 (IPv6) local LAN as myself. */
	for splay_each(edge_t, e, &n->edge_tree) {
		const sockaddr_t *cand = edge_usable_local_addr(e);

		if(cand && sockaddr_same_lan_as_myself(cand)) {
			*sa = cand;
			*sock = prng(listen_sockets);
			adapt_socket(*sa, sock);
			return;
		}
	}

	/* Second preference: pick a random edge with a valid unicast local address,
	   falling back to a full scan if the random edge had 0.0.0.0 / none. */
	unsigned int i = 0;
	unsigned int j = prng(n->edge_tree.count);
	const sockaddr_t *chosen = NULL;

	for splay_each(edge_t, e, &n->edge_tree) {
		if(i++ == j) {
			chosen = edge_usable_local_addr(e);
			break;
		}
	}

	if(!chosen) {
		for splay_each(edge_t, e, &n->edge_tree) {
			chosen = edge_usable_local_addr(e);

			if(chosen) {
				break;
			}
		}
	}

	if(chosen) {
		*sa = chosen;
		*sock = prng(listen_sockets);
		adapt_socket(*sa, sock);
	}
}

static void send_udppacket(node_t *n, vpn_packet_t *origpkt) {
	if(!n->status.reachable) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Trying to send UDP packet to unreachable node %s (%s)", n->name, n->hostname);
		return;
	}

	if(n->status.sptps) {
		send_sptps_packet(n, origpkt);
		return;
	}

#ifdef DISABLE_LEGACY
	return;
#else
	vpn_packet_t pkt1, pkt2;
	vpn_packet_t *pkt[] = { &pkt1, &pkt2, &pkt1, &pkt2 };
	vpn_packet_t *inpkt = origpkt;
	int nextpkt = 0;
	vpn_packet_t *outpkt;
	int origlen = origpkt->len;
	size_t outlen;
	int origpriority = origpkt->priority;

	pkt1.offset = DEFAULT_PACKET_OFFSET;
	pkt2.offset = DEFAULT_PACKET_OFFSET;

	/* Make sure we have a valid key */

	if(!n->status.validkey) {
		logger(DEBUG_TRAFFIC, LOG_INFO,
		       "No valid key known yet for %s (%s), forwarding via TCP",
		       n->name, n->hostname);
		send_tcppacket(n->nexthop->connection, origpkt);
		return;
	}

	/* DirectSeal (obfs.h): a legacy (tinc 1.0 protocol) peer cannot read a
	   sealed datagram, so a sealing node sends it none; probes are not sent
	   at all (try_udp), data goes inside the meta connection. */
	if(dseal_self_wants()) {
		if(DATA(origpkt)[12] | DATA(origpkt)[13]) {
			send_tcppacket(n->nexthop->connection, origpkt);
		}

		return;
	}

	if(n->options & OPTION_PMTU_DISCOVERY && inpkt->len > n->minmtu && (DATA(inpkt)[12] | DATA(inpkt)[13])) {
		logger(DEBUG_TRAFFIC, LOG_INFO,
		       "Packet for %s (%s) larger than minimum MTU, forwarding via %s",
		       n->name, n->hostname, n != n->nexthop ? n->nexthop->name : "TCP");

		if(n != n->nexthop) {
			send_packet(n->nexthop, origpkt);
		} else {
			send_tcppacket(n->nexthop->connection, origpkt);
		}

		return;
	}

	/* Compress the packet */

	if(n->outcompression != COMPRESS_NONE) {
		outpkt = pkt[nextpkt++];
		outpkt->len = compress_packet(DATA(outpkt), MAXSIZE - outpkt->offset, DATA(inpkt), inpkt->len, n->outcompression);

		if(!outpkt->len) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while compressing packet to %s (%s)",
			       n->name, n->hostname);
			return;
		}

		inpkt = outpkt;
	}

	/* Add sequence number */

	seqno_t seqno = htonl(++(n->sent_seqno));
	memcpy(SEQNO(inpkt), &seqno, sizeof(seqno));
	inpkt->len += sizeof(seqno);

	/* Encrypt the packet */

	if(cipher_active(n->outcipher)) {
		outpkt = pkt[nextpkt++];
		outlen = MAXSIZE;

		if(!cipher_encrypt(n->outcipher, SEQNO(inpkt), inpkt->len, SEQNO(outpkt), &outlen, true)) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while encrypting packet to %s (%s)", n->name, n->hostname);
			goto end;
		}

		outpkt->len = outlen;
		inpkt = outpkt;
	}

	/* Add the message authentication code */

	if(digest_active(n->outdigest)) {
		if(!digest_create(n->outdigest, SEQNO(inpkt), inpkt->len, SEQNO(inpkt) + inpkt->len)) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while encrypting packet to %s (%s)", n->name, n->hostname);
			goto end;
		}

		inpkt->len += digest_length(n->outdigest);
	}

	/* Send the packet */

	const sockaddr_t *sa = NULL;
	size_t sock;

	if(n->status.send_locally) {
		choose_local_address(n, &sa, &sock);
	}

	if(!sa) {
		choose_udp_address(n, &sa, &sock);
	}

	if(!sa) {
		goto end;
	}

	if(priorityinheritance && origpriority != listen_socket[sock].priority) {
		listen_socket[sock].priority = origpriority;

		switch(sa->sa.sa_family) {
#if defined(IP_TOS)

		case AF_INET:
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Setting IPv4 outgoing packet priority to %d", origpriority);

			if(setsockopt(listen_socket[sock].udp.fd, IPPROTO_IP, IP_TOS, (void *)&origpriority, sizeof(origpriority))) { /* SO_PRIORITY doesn't seem to work */
				logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "setsockopt", sockstrerror(sockerrno));
			}

			break;
#endif
#if defined(IPV6_TCLASS)

		case AF_INET6:
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Setting IPv6 outgoing packet priority to %d", origpriority);

			if(setsockopt(listen_socket[sock].udp.fd, IPPROTO_IPV6, IPV6_TCLASS, (void *)&origpriority, sizeof(origpriority))) { /* SO_PRIORITY doesn't seem to work */
				logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "setsockopt", sockstrerror(sockerrno));
			}

			break;
#endif

		default:
			break;
		}
	}

	if(sendto(listen_socket[sock].udp.fd, (void *)SEQNO(inpkt), inpkt->len, 0, &sa->sa, SALEN(sa->sa)) < 0 && !sockwouldblock(sockerrno)) {
		if(sockmsgsize(sockerrno)) {
			reduce_mtu(n, origlen - 1);
		} else {
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending packet to %s (%s): %s", n->name, n->hostname, sockstrerror(sockerrno));
		}
	}

end:
	origpkt->len = origlen;
#endif
}

/* The meta-connection half of send_sptps_data(): the record goes to the next
   hop inside the meta connection (SPTPS_PACKET, or REQ_KEY/ANS_KEY for older
   hops and handshakes). */
static bool send_sptps_data_meta(node_t *to, node_t *from, int type, const void *data, size_t len) {
	if(!to || !to->nexthop) {
		return false;
	}

	connection_t *conns[2] = {NULL, NULL};
	int nconns = (type == SPTPS_HANDSHAKE) ? 0 : multipath_select_connections(to->nexthop, multipath_current_tx_pkt, conns);

	if(nconns <= 0) {
		conns[0] = to->nexthop->connection;
		nconns = conns[0] ? 1 : 0;
	}

	connection_t *hdr_c = to->nexthop->connection ? to->nexthop->connection : (nconns > 0 ? conns[0] : NULL);

	if(!hdr_c) {
		return false;
	}

	if(type != SPTPS_HANDSHAKE && (hdr_c->options >> 24) >= 7) {
		const size_t buflen = len + sizeof(to->id) + sizeof(from->id);
		uint8_t *buf = alloca(buflen);
		uint8_t *buf_ptr = buf;
		memcpy(buf_ptr, &to->id, sizeof(to->id));
		buf_ptr += sizeof(to->id);
		memcpy(buf_ptr, &from->id, sizeof(from->id));
		buf_ptr += sizeof(from->id);
		memcpy(buf_ptr, data, len);
		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending packet from %s (%s) to %s (%s) via %s (%s) (TCP)", from->name, from->hostname, to->name, to->hostname, to->nexthop->name, to->nexthop->hostname);
		bool ok = false;

		for(int i = 0; i < nconns; i++) {
			if(conns[i] && send_sptps_tcppacket(conns[i], buf, buflen)) {
				ok = true;
			}
		}

		return ok;
	}

	char *buf = alloca(B64_SIZE(len));
	b64encode_tinc(data, buf, len);

	/* If this is a handshake packet, use ANS_KEY instead of REQ_KEY, for two reasons:
	    - We don't want intermediate nodes to switch to UDP to relay these packets;
	    - ANS_KEY allows us to learn the reflexive UDP address. */
	if(type == SPTPS_HANDSHAKE) {
		to->incompression = myself->incompression;
		return send_request(to->nexthop->connection, "%d %s %s %s -1 -1 -1 %d", ANS_KEY, from->name, to->name, buf, to->incompression);
	} else {
		bool ok = false;

		for(int i = 0; i < nconns; i++) {
			if(!conns[i]) {
				continue;
			}

			if(random_early_drop(conns[i])) {
				ok = true;
				continue;
			}

			if(send_request(conns[i], "%d %s %s %d %s", REQ_KEY, from->name, to->name, SPTPS_PACKET, buf)) {
				ok = true;
			}
		}

		return ok;
	}
}

/* DirectSeal refused a direct datagram to `relay' (HOLD: we do not know yet
   whether it reads sealed datagrams; BLOCK: it cannot). A probe is simply not
   sent (we are not probing that path); a record goes inside the meta
   connection instead. */
static bool send_sptps_data_held(node_t *relay, dseal_verdict_t dv, node_t *to, node_t *from, int type, const void *data, size_t len) {
	if(dv == DSEAL_SEND_HOLD) {
		send_req_dseal(relay);
	}

	dseal_log_hold(relay, dv);

	if(type == PKT_PROBE) {
		return true;
	}

	return send_sptps_data_meta(to, from, type, data, len);
}

static bool handle_udp_send_error(node_t *relay, node_t *to, node_t *from, int type, const void *data, size_t len) {
	if(!relay->status.send_locally) {
		if(relay->status.udp_confirmed && !carrier_datagram_path(relay)) {
			timeout_del(&relay->udp_ping_timeout);
			udp_probe_timeout_handler(relay);
		}

		if(type != PKT_PROBE) {
			return send_sptps_data_meta(to, from, type, data, len);
		}
	}

	return false;
}

static bool direct_udp_is_degraded(const node_t *n) {
	if(!n || n == myself || n->connection || !n->status.udp_confirmed || carrier_datagram_path(n)) {
		return false;
	}

	if(!n->nexthop || n->nexthop == n || n->nexthop == myself || !n->nexthop->status.reachable) {
		return false;
	}

	if(directonly) {
		return false;
	}

	if(n->udp_ping_unanswered >= 2 && (now.tv_sec - n->last_udp_rx >= udp_discovery_interval * 2)) {
		return true;
	}

	if(n->smoothed_rtt_ms > 0 && n->distance == 2 && n->prevedge &&
	                n->prevedge->weight_rtt_calibrated && n->nexthop->smoothed_rtt_ms > 0) {
		int peer_relay_rtt = n->prevedge->weight >= 1000 ? n->prevedge->weight - 1000 : n->prevedge->weight;
		int relay_rtt = n->nexthop->smoothed_rtt_ms + MAX(peer_relay_rtt, 1);

		if(n->smoothed_rtt_ms > relay_rtt + 100 && n->smoothed_rtt_ms > relay_rtt * 2) {
			return true;
		}
	}

	return false;
}

bool send_sptps_data(node_t *to, node_t *from, int type, const void *data, size_t len) {
	size_t origlen = len - SPTPS_DATAGRAM_OVERHEAD;
	node_t *relay = (to->via != myself && (type == PKT_PROBE || origlen <= to->via->minmtu)) ? to->via : to->nexthop;

	if(from == myself && relay == to && type != PKT_PROBE && type != SPTPS_HANDSHAKE && direct_udp_is_degraded(to)) {
		relay = to->nexthop;
	}

	bool direct = from == myself && to == relay;
	bool relay_supported = (relay->options >> 24) >= 4;
	bool tcponly = node_tcponly(relay);

	/* Send it via TCP if it is a handshake packet, TCPOnly is in use, this is a relay packet that the other node cannot understand, or this packet is larger than the MTU. */

	if(type == SPTPS_HANDSHAKE || tcponly || (!direct && !relay_supported) || (type != PKT_PROBE && origlen > relay->minmtu)) {
		if(type == PKT_PROBE) {
			return true;
		}

		if(from != myself && type != SPTPS_HANDSHAKE && origlen > relay->minmtu && relay->minmtu >= MINMTU) {
			send_mtu_info(to, from, relay->minmtu);
		}

		return send_sptps_data_meta(to, from, type, data, len);
	}

	size_t overhead = 0;

	if(relay_supported) {
		overhead += sizeof(to->id) + sizeof(from->id);
	}

	char *buf = alloca(len + overhead);
	char *buf_ptr = buf;

	if(relay_supported) {
		if(direct) {
			/* Inform the recipient that this packet was sent directly. */
			node_id_t nullid = {0};
			memcpy(buf_ptr, &nullid, sizeof(nullid));
			buf_ptr += sizeof(nullid);
		} else {
			memcpy(buf_ptr, &to->id, sizeof(to->id));
			buf_ptr += sizeof(to->id);
		}

		memcpy(buf_ptr, &from->id, sizeof(from->id));
		buf_ptr += sizeof(from->id);

	}

	/* TODO: if this copy turns out to be a performance concern, change sptps_send_record() to add some "pre-padding" to the buffer and use that instead */
	memcpy(buf_ptr, data, len);
	buf_ptr += len;

	const sockaddr_t *sa = NULL;
	size_t sock;

	if(relay->status.send_locally) {
		choose_local_address(relay, &sa, &sock);
	}

	if(!sa) {
		choose_udp_address(relay, &sa, &sock);
	}

	if(!sa && !( !carrier_beacon_raw && relay->connection && relay->connection->transport && relay->connection->transport->send_datagram )) {
		if(type == PKT_PROBE) {
			return true;
		}

		return send_sptps_data_meta(to, from, type, data, len);
	}

	logger(DEBUG_TRAFFIC, LOG_INFO, "Sending packet from %s (%s) to %s (%s) via %s (%s) (UDP)", from->name, from->hostname, to->name, to->hostname, relay->name, relay->hostname);

	/* quic carrier (any carrier with a send_datagram hook): if the next hop's
	   meta connection runs on such a carrier, the SPTPS datagram rides that
	   flow (a QUIC DATAGRAM frame) instead of the plain socket, byte-for-byte
	   the same record. Per hop, like obfs, so a relay never double-wraps. A
	   `false' return means it does not fit the carrier's datagram ceiling:
	   treated exactly like EMSGSIZE so tinc's MTU discovery converges. With
	   plain/sf/obfs the hook is NULL and this is byte-identical to before. */
	if(!carrier_beacon_raw && relay->connection && relay->connection->transport && relay->connection->transport->send_datagram) {
		connection_t *conns[2] = {NULL, NULL};
		int nconns = multipath_select_connections(relay, multipath_current_tx_pkt, conns);

		if(nconns <= 0) {
			conns[0] = relay->connection;
			nconns = 1;
		}

		bool sent_any = false;

		for(int i = 0; i < nconns; i++) {
			connection_t * target_c = conns[i];

			if(target_c && target_c->transport && target_c->transport->send_datagram) {
				size_t excess = 0;

				if(!target_c->transport->send_datagram(target_c, buf, (size_t)(buf_ptr - buf), &excess)) {
					reduce_mtu(relay, (int)origlen - (int)(excess ? excess : 1));
				} else {
					sent_any = true;
				}
			}
		}

		if(!sent_any && type != PKT_PROBE) {
			return send_sptps_data_meta(to, from, type, data, len);
		}

		return true;
	}

	if(type == PKT_PROBE) {
		multipath_probe_node_paths(relay, buf, (size_t)(buf_ptr - buf));
	}

	/* DirectSeal (obfs.h) decides for every obfs link but the obfs carrier's
	   own. An active obfs link to `relay' is not only the carrier's: the cold
	   path activates one as soon as the peer's first sealed datagram arrives,
	   and it outlives the reason it was activated for. Sending on it
	   regardless of the verdict did two things (2026-09-29):
	   - HOLD/BLOCK: a peer that seals towards us (because we seal) reads
	     sealed datagrams only if its own Transports accept obfs, so a node
	     that had just logged "Not sending UDP to X directly" answered X's
	     probes with sealed datagrams X drops, in every coordinated punch round
	     (mixed-version-test.sh, a leaf with `Transports: plain, sf');
	   - PLAIN: a peer that sealed, got a direct-seal session key and then
	     restarted without sealing got our datagrams under a session key it no
	     longer has; nothing it sends is sealed, so nothing renegotiates, and
	     the direct path stayed dead (carrier-switch-test.sh's `plain -> quic'
	     setup step, 1 run in 3).
	   The obfs carrier's own meta link is exempt: its peer reads obfs by
	   definition, and while the link comes up its capability may not be known
	   yet. A SEAL verdict seals below, through obfs_seal_send. */
	bool obfs_carrier = relay->connection && relay->connection->transport && relay->connection->transport->id == TRANSPORT_OBFS;
	dseal_verdict_t dv = dseal_verdict(relay);

	if(!obfs_carrier && (dv == DSEAL_SEND_HOLD || dv == DSEAL_SEND_BLOCK)) {
		return send_sptps_data_held(relay, dv, to, from, type, data, len);
	}

	/* Multipath UDP scheduler: if multiple confirmed UDP paths or bound uplinks
	   are active for `relay`, dispatch across the selected path(s) (1 for
	   failover/flowhash/split, 2 for redundant). */
	node_path_t *mp_paths[2] = {NULL, NULL};
	int npaths = (direct && type != PKT_PROBE && !relay->status.send_locally) ?
	             multipath_select_udp_paths(relay, multipath_current_tx_pkt, mp_paths) : 0;

	if(npaths > 0) {
		size_t pkt_bytes = (size_t)(buf_ptr - buf);
		bool any_ok = false;

		for(int i = 0; i < npaths; i++) {
			node_path_t *p = mp_paths[i];
			const sockaddr_t *psa = &p->addr;
			size_t psock = (p->sock_idx >= 0 && p->sock_idx < listen_sockets) ? (size_t)p->sock_idx : sock;
			int pfd = multipath_get_udp_fd(p->uplink_idx, psa->sa.sa_family, (int)psock);

			p->last_tx = now.tv_sec;
			p->tx_packets++;
			p->tx_bytes += pkt_bytes;

			if(p->uplink_idx >= 0 && p->uplink_idx < MAX_UPLINKS) {
				multipath_uplinks[p->uplink_idx].tx_packets++;
				multipath_uplinks[p->uplink_idx].tx_bytes += pkt_bytes;
			}

			size_t mp_excess = 0;
			obfs_send_t mp_wrapped = obfs_carrier ? obfs_wrap_send_fd(pfd, psock, psa, buf, pkt_bytes, relay, &mp_excess) : OBFS_SEND_PLAIN;

			if(mp_wrapped == OBFS_SEND_OK) {
				any_ok = true;
				continue;
			} else if(mp_wrapped == OBFS_SEND_TOOBIG) {
				reduce_mtu(relay, (int)origlen - (int)(mp_excess ? mp_excess : 1));
				any_ok = true;
				continue;
			} else if(mp_wrapped == OBFS_SEND_ERR) {
				continue;
			}

			if(dv == DSEAL_SEND_SEAL) {
				obfs_send_t mp_sealed = obfs_seal_send_fd(pfd, psock, psa, buf, pkt_bytes, relay, &mp_excess);

				if(mp_sealed == OBFS_SEND_OK) {
					any_ok = true;
				} else if(mp_sealed == OBFS_SEND_TOOBIG) {
					reduce_mtu(relay, (int)origlen - (int)(mp_excess ? mp_excess : 1));
					any_ok = true;
				}

				continue;
			}

			if(sendto(pfd, buf, pkt_bytes, 0, &psa->sa, SALEN(psa->sa)) < 0 && !sockwouldblock(sockerrno)) {
				if(sockmsgsize(sockerrno)) {
					reduce_mtu(relay, (int)origlen - 1);
					any_ok = true;
				} else if(sendto(pfd, buf, pkt_bytes, 0, &psa->sa, SALEN(psa->sa)) >= 0 || sockwouldblock(sockerrno)) {
					any_ok = true;
				}
			} else {
				any_ok = true;
			}
		}

		if(!any_ok) {
			return handle_udp_send_error(relay, to, from, type, data, len);
		}

		return true;
	}

	/* obfs carrier: if the next hop is an obfs link, seal this SPTPS datagram
	   before it goes on the wire. The relay strips the seal on receive and this
	   re-applies it per hop, so a relayed record is never double-wrapped. When
	   the hop is not an obfs link the datagram is sent unchanged below. */
	size_t obfs_excess = 0;
	obfs_send_t wrapped = obfs_carrier ? obfs_wrap_send(sock, sa, buf, (size_t)(buf_ptr - buf), relay, &obfs_excess) : OBFS_SEND_PLAIN;

	switch(wrapped) {
	case OBFS_SEND_OK:
		return true;

	case OBFS_SEND_TOOBIG:

		/* The seal does not fit the path. Same contract as the quic carrier
		   above and as EMSGSIZE on the plain socket below -- except that obfs
		   knows exactly how many bytes were over, so the packet size drops by
		   precisely that much and PMTU discovery converges in one step. Before
		   this, obfs swallowed the EMSGSIZE and every oversized probe was lost
		   silently, so discovery never converged and the carrier looked hung. */
		reduce_mtu(relay, (int)origlen - (int)(obfs_excess ? obfs_excess : 1));
		return true;

	case OBFS_SEND_ERR:
		return handle_udp_send_error(relay, to, from, type, data, len);

	case OBFS_SEND_PLAIN:
		break;
	}

	/* DirectSeal (obfs.h): a node that runs a masking carrier seals its
	   direct datagrams -- probes, replies and data alike -- with the peer's
	   obfs link, and sends none at all to a peer that could not read them.
	   Between two nodes that do not seal, this is upstream tinc's wire. */
	if(dv == DSEAL_SEND_SEAL) {
		obfs_send_t sealed = obfs_seal_send(sock, sa, buf, (size_t)(buf_ptr - buf), relay, &obfs_excess);

		if(sealed == OBFS_SEND_TOOBIG) {
			reduce_mtu(relay, (int)origlen - (int)(obfs_excess ? obfs_excess : 1));
		} else if(sealed == OBFS_SEND_ERR) {
			return handle_udp_send_error(relay, to, from, type, data, len);
		}

		return true;
	}

	if(dv == DSEAL_SEND_HOLD || dv == DSEAL_SEND_BLOCK) {
		/* only the obfs carrier's own link gets here, when it is not up */
		return send_sptps_data_held(relay, dv, to, from, type, data, len);
	}

	if(sendto(listen_socket[sock].udp.fd, buf, buf_ptr - buf, 0, &sa->sa, SALEN(sa->sa)) < 0 && !sockwouldblock(sockerrno)) {
		if(sockmsgsize(sockerrno)) {
			reduce_mtu(relay, (int)origlen - 1);
		} else if(sendto(listen_socket[sock].udp.fd, buf, buf_ptr - buf, 0, &sa->sa, SALEN(sa->sa)) < 0 && !sockwouldblock(sockerrno)) {
			if(sockmsgsize(sockerrno)) {
				reduce_mtu(relay, (int)origlen - 1);
			} else {
				logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending UDP SPTPS packet to %s (%s): %s", relay->name, relay->hostname, sockstrerror(sockerrno));
				return handle_udp_send_error(relay, to, from, type, data, len);
			}
		}
	}

	return true;
}

bool receive_sptps_record(void *handle, uint8_t type, const void *data, uint16_t len) {
	node_t *from = handle;

	if(from->status.udppacket) {
		bool is_probe_req = (type == PKT_PROBE && len >= 1 && ((const uint8_t *)data)[0] == 0);
		apply_incoming_udp_endpoint(from, is_probe_req);
	}

	if(type == SPTPS_HANDSHAKE) {
		from->last_req_key = now.tv_sec;

		if(!from->status.validkey) {
			from->status.validkey = true;
			from->status.waitingforkey = false;
			/* Whatever the route did while this exchange was in flight, it
			   completed. The mark must not outlive the exchange it describes
			   (it is also visible in `dump nodes'). */
			from->status.sptps_route_stale = false;
			logger(DEBUG_META, LOG_INFO, "SPTPS key exchange with %s (%s) successful", from->name, from->hostname);

			if(from->sptps.initiator && !(from->connection && node_tcponly(from))) {
				try_udp(from, false);
			}
		}

		return true;
	}

	if(len > MTU) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Packet from %s (%s) larger than maximum supported size (%d > %d)", from->name, from->hostname, len, MTU);
		return false;
	}

	vpn_packet_t inpkt;
	inpkt.offset = DEFAULT_PACKET_OFFSET;
	inpkt.priority = 0;

	if(type == PKT_PROBE) {
		if(!from->status.udppacket || !current_udp_rx_direct) {
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Ignoring SPTPS PROBE packet from %s (%s) received via relay/TCP", from->name, from->hostname);
			return true;
		}

		inpkt.len = len;
		memcpy(DATA(&inpkt), data, len);

		if(inpkt.len > from->maxrecentlen) {
			from->maxrecentlen = inpkt.len;
		}

		udp_probe_h(from, &inpkt, len);
		return true;
	}

	if(type & ~(PKT_COMPRESSED | PKT_MAC)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unexpected SPTPS record type %d len %d from %s (%s)", type, len, from->name, from->hostname);
		return false;
	}

	/* Check if we have the headers we need */
	if(routing_mode != RMODE_ROUTER && !(type & PKT_MAC)) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Received packet from %s (%s) without MAC header (maybe Mode is not set correctly)", from->name, from->hostname);
		return false;
	} else if(routing_mode == RMODE_ROUTER && (type & PKT_MAC)) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Received packet from %s (%s) with MAC header (maybe Mode is not set correctly)", from->name, from->hostname);
	}

	int offset = (type & PKT_MAC) ? 0 : 14;

	if(type & PKT_COMPRESSED) {
		length_t ulen = uncompress_packet(DATA(&inpkt) + offset, MAXSIZE - inpkt.offset, (const uint8_t *)data, len, from->incompression);

		if(!ulen) {
			return false;
		} else {
			inpkt.len = ulen + offset;
		}

		if(inpkt.len > MAXSIZE) {
			abort();
		}
	} else {
		memcpy(DATA(&inpkt) + offset, data, len);
		inpkt.len = len + offset;
	}

	/* Generate the Ethernet packet type if necessary */
	if(offset) {
		switch(DATA(&inpkt)[14] >> 4) {
		case 4:
			DATA(&inpkt)[12] = 0x08;
			DATA(&inpkt)[13] = 0x00;
			break;

		case 6:
			DATA(&inpkt)[12] = 0x86;
			DATA(&inpkt)[13] = 0xDD;
			break;

		default:
			logger(DEBUG_TRAFFIC, LOG_ERR,
			       "Unknown IP version %d while reading packet from %s (%s)",
			       DATA(&inpkt)[14] >> 4, from->name, from->hostname);
			return false;
		}
	}

	if(from->status.udppacket && current_udp_rx_direct) {
		from->udp_ping_unanswered = 0;
		from->last_udp_rx = now.tv_sec;

		if(len >= MINMTU) {
			from->last_large_udp_rx = now.tv_sec;
		}

		if(len > from->maxrecentlen) {
			from->maxrecentlen = len;
		}
	}

	receive_packet(from, &inpkt);
	return true;
}

// This function tries to get SPTPS keys, if they aren't already known.
// This function makes no guarantees - it is up to the caller to check the node's state to figure out if the keys are available.
static void try_sptps(node_t *n) {
	if(n->status.validkey) {
		return;
	}

	logger(DEBUG_TRAFFIC, LOG_INFO, "No valid key known yet for %s (%s)", n->name, n->hostname);

	/* 30s instead of 10s: under high RTT or congested TCP relay paths, the
	   SPTPS handshake genuinely needs more than 10s. Resetting again too early
	   tears down an in-progress handshake and feeds the stale-packet livelock
	   described in sptps.c.
	   Jitter ±20% (patch 5): when two nodes arm this timer in the same instant
	   (the REQ_KEY-glare case) a fixed cooldown makes them retry in the same
	   second and collide again. A small random spread decorrelates the two
	   sides' retries so recovery converges even if the deterministic tie-break
	   in protocol_key.c did not apply (e.g. one peer is unpatched). */
	if(!n->status.waitingforkey) {
		send_req_key(n);
	} else if(n->status.sptps_route_stale) {
		/* The route this exchange went out over is gone (graph.c). Waiting out
		   the cooldown would only be waiting for an answer to records that
		   cannot arrive. Restart now, over the route we have. */
		logger(DEBUG_ALWAYS, LOG_DEBUG, "The route to %s changed under our pending key exchange, restarting SPTPS over the new one", n->name);
		n->status.sptps_route_stale = false;
		sptps_stop(&n->sptps);
		n->status.waitingforkey = false;
		send_req_key(n);
	} else {
		int cooldown = 30 + (int)prng(13) - 6;   /* 24..36s */

		if(n->last_req_key + cooldown < now.tv_sec) {
			logger(DEBUG_ALWAYS, LOG_DEBUG, "No key from %s after %d seconds, restarting SPTPS", n->name, cooldown);
			sptps_stop(&n->sptps);
			n->status.waitingforkey = false;
			send_req_key(n);
		}
	}

	return;
}

static void send_udp_probe_packet(node_t *n, size_t len) {
	vpn_packet_t packet;

	if(len > sizeof(packet.data)) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Truncating probe length %lu to %s (%s)", (unsigned long)len, n->name, n->hostname);
		len = sizeof(packet.data);
	}

	len = MAX(len, MIN_PROBE_SIZE);
	packet.offset = DEFAULT_PACKET_OFFSET;
	memset(DATA(&packet), 0, 14);
	randomize(DATA(&packet) + 14, len - 14);
	packet.len = len;
	packet.priority = 0;

	logger(DEBUG_TRAFFIC, LOG_INFO, "Sending UDP probe length %lu to %s (%s)", (unsigned long)len, n->name, n->hostname);

	send_udppacket(n, &packet);
}

// This function tries to establish a UDP tunnel to a node so that packets can be sent.
// If a tunnel is already established, it makes sure it stays up.
// This function makes no guarantees - it is up to the caller to check the node's state to figure out if UDP is usable.
/* A neighbour reached over a datagram carrier (quic) sees our QUIC socket,
   not our UDP data socket, and since the carrier's records no longer move
   n->address (process_sptps_udp) it would know no mapping of the data socket
   at all -- yet it is the one that tells other peers where to punch
   (UDP_INFO, the ANS_KEY hint). So while we try UDP to a node behind it, send it one
   probe from the data socket every udp_discovery_keepalive_interval: sealed
   like any direct datagram (DirectSeal), never in the clear to a peer that
   cannot read it, and answered over the carrier. It also keeps our NAT's
   mapping for the data socket alive. */
static void send_carrier_beacon(node_t *n) {
	if(!n->status.validkey || !n->status.sptps || (n->options >> 24) < 4 ||
	                node_tcponly(n)) {
		return;
	}

	if(n->carrier_beacon_sent && now.tv_sec - n->carrier_beacon_sent < udp_discovery_keepalive_interval) {
		return;
	}

	dseal_verdict_t dv = dseal_verdict(n);

	if(dv == DSEAL_SEND_HOLD || dv == DSEAL_SEND_BLOCK) {
		return;
	}

	n->carrier_beacon_sent = now.tv_sec;
	carrier_beacon_raw = true;
	send_udp_probe_packet(n, MIN_PROBE_SIZE);
	carrier_beacon_raw = false;
}

void maybe_send_carrier_beacon(node_t *n) {
	if(n && n->nexthop && n->nexthop != n && n->nexthop != myself && carrier_datagram_path(n->nexthop)) {
		send_carrier_beacon(n->nexthop);
	}
}

static bool has_confirmed_udp_addr(const node_t *n) {
	return n->status.udp_confirmed && (!carrier_datagram_path(n) || n->status.udp_addr_confirmed || (n->connection && n->connection->outgoing && n->has_config_address));
}

/* ---- coordinated hole punch (stream N2) ------------------------------------

   tinc used to probe a peer it has no direct path to as soon as it had a key,
   every 2 s, for as long as there was traffic. Behind a NAT that creates an
   entry for an unsolicited inbound datagram (Linux MASQUERADE with its input
   open, a CGN tier built the same way), the first probe to arrive before the
   peer's own outgoing one takes the port the peer then needs, and probing
   every 2 s keeps that entry alive for ever (docs/nat.md §3.2, §9). So for a
   peer that speaks this (DSEAL_PUNCH in its capability token) and that we
   reach through a relay:

   - nobody probes it unsolicited: we ask for a round with
     `REQ_KEY <me> <peer> 98 0 - -' through the meta graph;
   - the relay whose meta neighbours both ends are answers instead of
     forwarding, once it has confirmed both ends' UDP addresses (until then
     it stays silent and the asker retries): `98 2 <addr> <port>' to both
     ends at the same instant, each carrying the other end's UDP address as
     the relay sees it. An older relay forwards the request, and
     the far end answers `98 1 - -' itself and starts after half the meta
     path's weighted distance, so both first probes leave about together;
   - a GO starts a PUNCH_ROUND-second round of the usual probe bursts; a
     round that ends without a confirmed path is followed by PUNCH_BACKOFF
     seconds without a single probe to that peer -- longer than the 30 s a
     Linux conntrack entry for unreplied UDP lives -- so that entries left
     by the failed round expire before the next one.

   Peers without the capability (upstream, older tincstack) and direct meta
   neighbours are probed exactly as before. */
#define PUNCH_ROUND 8
#define PUNCH_BACKOFF 35
#define PUNCH_REQ_RETRY 2
#define PUNCH_MAX_UNANSWERED 5
#define PUNCH_MAX_DELAY_MS 1000

static bool punch_coordinated(const node_t *n) {
	if(n->status.no_direct || n->remote_no_direct) {
		return false;
	}

	node_t *via = (n->via == myself) ? n->nexthop : n->via;
	return via == n && !node_tcponly(n) &&
	       (n->dseal & DSEAL_KNOWN) && (n->dseal & DSEAL_PUNCH) && !n->connection &&
	       n->nexthop && n->nexthop != n && n->nexthop->connection;
}

static void punch_timer_handler(void *data) {
	node_t *n = data;
	timeout_del(&n->punch_timer);

	if(!n->status.reachable || n->status.udp_confirmed || n->status.no_direct || n->remote_no_direct) {
		return;
	}

	/* The round starts now: the first burst goes out at once. */
	n->udp_ping_sent = (struct timeval) {
		0, 0
	};
	try_udp(n, false);
}

static void punch_start(node_t *n, int delay_ms, const sockaddr_t *sa, const char *why) {
	node_t *via = (n->via == myself) ? n->nexthop : n->via;

	if(!n->status.reachable || n->status.udp_confirmed || via != n || node_tcponly(n) || n->status.no_direct || n->remote_no_direct) {
		return;
	}

	if(timerisset(&n->punch_go)) {
		struct timeval end;
		timeradd(&n->punch_go, &((struct timeval) {
			PUNCH_ROUND, 0
		}), &end);

		if(timercmp(&now, &end, <)) {
			return; /* a round is on already (both ends asked, or a duplicate) */
		}
	}

	if(sa && sa->sa.sa_family != AF_UNKNOWN) {
		uint16_t new_port = 0;
		uint16_t prev_port = 0;
		bool same_ip = false;

		if(sa->sa.sa_family == AF_INET) {
			new_port = ntohs(sa->in.sin_port);

			if(n->address.sa.sa_family == AF_INET &&
			                n->address.in.sin_addr.s_addr == sa->in.sin_addr.s_addr) {
				prev_port = ntohs(n->address.in.sin_port);
				same_ip = true;
			}
		} else if(sa->sa.sa_family == AF_INET6) {
			new_port = ntohs(sa->in6.sin6_port);

			if(n->address.sa.sa_family == AF_INET6 &&
			                !memcmp(&n->address.in6.sin6_addr, &sa->in6.sin6_addr, sizeof(sa->in6.sin6_addr))) {
				prev_port = ntohs(n->address.in6.sin6_port);
				same_ip = true;
			}
		}

		if(same_ip && prev_port >= 1024 && new_port >= 1024 && prev_port != new_port) {
			int diff = (int)new_port - (int)prev_port;

			if(diff != 0 && diff >= -16 && diff <= 16) {
				n->nat_port_delta = (int16_t)diff;
			}
		}

		if(new_port >= 1024) {
			n->punch_base_port = new_port;
		}

		if(sockaddrcmp(sa, &n->address)) {
			update_node_udp(n, sa);
		}
	}

	n->udp_probe_seq = 0;

	if(delay_ms < 0) {
		delay_ms = 0;
	} else if(delay_ms > PUNCH_MAX_DELAY_MS) {
		delay_ms = PUNCH_MAX_DELAY_MS;
	}

	struct timeval d = {delay_ms / 1000, (delay_ms % 1000) * 1000};
	timeradd(&now, &d, &n->punch_go);
	n->punch_backoff_until = 0;
	n->punch_unanswered = 0;
	logger(DEBUG_CONNECTIONS, LOG_INFO, "Coordinated hole punch with %s (%s): %s, first probes in %d ms", n->name, n->hostname, why, delay_ms);
	timeout_del(&n->punch_timer);
	timeout_add(&n->punch_timer, punch_timer_handler, n, &d);
}

/* May try_udp() probe `n' (not confirmed, coordinated) now? */
static bool punch_may_probe(node_t *n) {
	if(timerisset(&n->punch_go)) {
		if(timercmp(&now, &n->punch_go, <)) {
			return false; /* the round starts later */
		}

		struct timeval end;
		timeradd(&n->punch_go, &((struct timeval) {
			PUNCH_ROUND, 0
		}), &end);

		if(timercmp(&now, &end, <)) {
			return true;
		}

		n->punch_go = (struct timeval) {
			0, 0
		};
		n->punch_backoff_until = now.tv_sec + PUNCH_BACKOFF;
		n->status.ping_sent = false;
		logger(DEBUG_CONNECTIONS, LOG_INFO, "No direct UDP path to %s (%s) after a coordinated %d s round; no probes to it for %d s, so that NAT entries the round left expire",
		       n->name, n->hostname, PUNCH_ROUND, PUNCH_BACKOFF);
		return false;
	}

	if(now.tv_sec < n->punch_backoff_until || !n->status.validkey) {
		return false;
	}

	if(n->punch_req_sent && now.tv_sec - n->punch_req_sent < PUNCH_REQ_RETRY) {
		return false;
	}

	if(n->punch_unanswered >= PUNCH_MAX_UNANSWERED) {
		/* It advertised the capability but nothing answers: do not stay
		   relayed for that, run a round on our own. */
		logger(DEBUG_CONNECTIONS, LOG_INFO, "No answer from %s (%s) to %d coordinated hole-punch requests; probing it on our own this round",
		       n->name, n->hostname, PUNCH_MAX_UNANSWERED);
		punch_start(n, 0, NULL, "no answer, uncoordinated round");
		return false;
	}

	n->punch_req_sent = now.tv_sec;
	n->punch_unanswered++;
	logger(DEBUG_PROTOCOL, LOG_INFO, "Asking for a coordinated hole punch with %s (%s) via %s", n->name, n->hostname, n->nexthop->name);
	send_request(n->nexthop->connection, "%d %s %s %d %d - -", REQ_KEY, myself->name, n->name, PUNCH_REQ, 0);
	return false;
}

/* Tell `b' to start punching towards `a' now, with `a''s UDP address as we
   see it (the relay's view; only if we confirmed it). */
static bool punch_send_go(node_t *a, node_t *b) {
	char *addr = NULL, *port = NULL;

	if(has_confirmed_udp_addr(a) && a->address.sa.sa_family != AF_UNSPEC && a->address.sa.sa_family != AF_UNKNOWN) {
		sockaddr2str(&a->address, &addr, &port);
	}

	bool ok = send_request(b->connection, "%d %s %s %d %d %s %s", REQ_KEY, a->name, b->name, PUNCH_REQ, 2, addr ? addr : "-", port ? port : "-");
	free(addr);
	free(port);
	return ok;
}

void send_no_direct_signal(node_t *to, bool no_direct) {
	if(!to || to == myself || !myself || !to->status.reachable || !to->nexthop || !to->nexthop->connection) {
		return;
	}

	int flag = no_direct ? PUNCH_NO_DIRECT : PUNCH_ALLOW_DIRECT;
	send_request(to->nexthop->connection, "%d %s %s %d %d - -", REQ_KEY, myself->name, to->name, PUNCH_REQ, flag);

	if(!no_direct && !to->connection && to->status.validkey) {
		try_udp(to, false);
	}
}

bool punch_h(node_t *from, node_t *to, const char *request) {
	int flag = -1;
	char addr[MAX_STRING_SIZE] = "";
	char port[MAX_STRING_SIZE] = "";

	if(sscanf(request, "%*d %*s %*s %*d %d " MAX_STRING " " MAX_STRING, &flag, addr, port) < 1 || flag < 0 || flag > 4) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "PUNCH_REQ", from->name, from->hostname);
		return true;
	}

	if(to != myself) {
		/* The rendezvous: both ends are our meta neighbours, so both hear
		   "go" from us at the same instant. */
		if(flag == 0 && !low_power_mode && !from->status.no_direct && !to->status.no_direct && !from->remote_no_direct && !to->remote_no_direct &&
		                from->connection && to->connection && from->connection->edge && to->connection->edge) {
			/* Only with both ends' real UDP addresses: a GO without them
			   sends each end at its edge guess (the TCP address, port 655),
			   which a port-changing NAT never maps, and the round is spent
			   there (lab: masq x portrestricted, 10 s -> 45 s). Stay silent
			   until we have confirmed both; the asker retries every
			   PUNCH_REQ_RETRY s and runs a round on its own after
			   PUNCH_MAX_UNANSWERED requests (a relay that never has UDP to
			   them, e.g. TCP-only links). */
			if(!has_confirmed_udp_addr(from) || !has_confirmed_udp_addr(to)) {
				logger(DEBUG_PROTOCOL, LOG_INFO, "Coordinated hole punch between %s and %s: not yet, no confirmed UDP address of %s", from->name, to->name,
				       !has_confirmed_udp_addr(from) ? from->name : to->name);
				return true;
			}

			logger(DEBUG_CONNECTIONS, LOG_INFO, "Coordinated hole punch between %s and %s: telling both to start", from->name, to->name);
			punch_send_go(from, to);
			punch_send_go(to, from);
			return true;
		}

		if(!to->nexthop || !to->nexthop->connection) {
			return true;
		}

		return send_request(to->nexthop->connection, "%s", request);
	}

	if(flag == PUNCH_NO_DIRECT) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Peer %s (%s) signaled NoDirect (relay-only); suppressing direct connections and UDP probes to it", from->name, from->hostname);
		bool changed = !from->remote_no_direct;
		from->remote_no_direct = true;

		for list_each(outgoing_t, outgoing, &outgoing_list) {
			if(outgoing->node == from) {
				timeout_del(&outgoing->ev);
			}
		}

		if(from->status.udp_confirmed || from->status.udp_addr_confirmed) {
			from->status.udp_confirmed = false;
			from->status.udp_addr_confirmed = false;
			from->udp_ping_rtt = -1;
			from->maxrecentlen = 0;
			from->mtuprobes = 0;
			from->minmtu = 0;
			from->maxmtu = MTU;
			timeout_del(&from->udp_ping_timeout);
			changed = true;
		}

		timeout_del(&from->punch_timer);
		from->punch_go = (struct timeval) {0, 0};
		from->last_lan_udp_rx = 0;
		memset(from->paths, 0, sizeof(from->paths));

		if(changed) {
			graph();
		}

		return true;
	}

	if(flag == PUNCH_ALLOW_DIRECT) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Peer %s (%s) re-enabled direct connections; resuming direct discovery", from->name, from->hostname);
		bool changed = from->remote_no_direct;
		from->remote_no_direct = false;
		from->punch_backoff_until = 0;
		from->punch_unanswered = 0;
		from->punch_req_sent = 0;

		if(changed) {
			graph();
		}

		if(!from->status.no_direct && !node_is_no_direct(from->name) && !from->connection) {
			for list_each(outgoing_t, outgoing, &outgoing_list) {
				if(outgoing->node == from && !outgoing->ev.cb) {
					setup_outgoing_connection(outgoing, false);
					break;
				}
			}
		}

		if(from->status.reachable && !from->connection && from->status.validkey) {
			try_udp(from, false);
		}

		return true;
	}

	if(from->status.no_direct || node_is_no_direct(from->name)) {
		if(from->last_no_direct_sent != now.tv_sec) {
			from->last_no_direct_sent = now.tv_sec;
			send_no_direct_signal(from, true);
		}

		return true;
	}

	if((flag == 0 || flag == 1) && from->remote_no_direct) {
		from->remote_no_direct = false;
		graph();
	}

	if(from->remote_no_direct) {
		return true;
	}

	if(!punch_coordinated(from)) {
		/* Not a peer we coordinate with (a meta neighbour now, or its token
		   changed): it asked, so still answer, and probe as usual. */
		if(flag == 0 && from->nexthop && from->nexthop->connection) {
			send_request(from->nexthop->connection, "%d %s %s %d %d - -", REQ_KEY, myself->name, from->name, PUNCH_REQ, 1);
		}

		return true;
	}

	if(flag == 0) {
		/* The relay forwarded the request instead of answering it (an older
		   build): answer the peer ourselves and start once our answer has
		   crossed the meta path, estimated as half its weighted distance. */
		send_request(from->nexthop->connection, "%d %s %s %d %d - -", REQ_KEY, myself->name, from->name, PUNCH_REQ, 1);
		punch_start(from, from->weighted_distance / 2, NULL, "the peer asked through an older relay");
		return true;
	}

	sockaddr_t sa = {0};
	bool have = *addr && *port && strcmp(addr, "-") && strcmp(port, "-");

	if(have) {
		sa = str2sockaddr(addr, port);

		if(sa.sa.sa_family == AF_UNSPEC || sa.sa.sa_family == AF_UNKNOWN ||
		                !sockaddr_is_unicast_ip(&sa) || address_routes_via_vpn(&sa) ||
		                from->nexthop == from) {
			have = false;
		} else if(sockaddr_is_my_nat_wan_ip(&sa)) {
			if(!node_best_lan_address(from, &sa)) {
				have = false;
			}
		}
	}

	punch_start(from, 0, have ? &sa : NULL, flag == 2 ? "the relay says go" : "the peer says go");
	return true;
}

static void try_udp(node_t *n, bool has_data) {
	node_t *via = (n->via == myself) ? n->nexthop : n->via;

	if(!udp_discovery || via != n || node_tcponly(n) || n->status.no_direct || n->remote_no_direct) {
		return;
	}

	if(n->status.sptps && (!n->status.validkey || !n->sptps.outstate)) {
		return;
	}

	/* Punching towards a node we reach through a quic neighbour: that
	   neighbour is the one that tells it where our data socket is, so it has
	   to have seen that socket (send_carrier_beacon). Nothing is sent to a
	   quic neighbour that relays for nobody: between two quic nodes the wire
	   stays QUIC only. */
	if(n->nexthop && n->nexthop != n && n->nexthop != myself && carrier_datagram_path(n->nexthop)) {
		send_carrier_beacon(n->nexthop);
	}

	if(n->status.udp_confirmed && carrier_datagram_path(n)) {
		return;
	}

	if(!direct_seal_permits(n, true)) {
		return;
	}

	/* Send gratuitous probe replies to 1.1 nodes. */

	if((n->options >> 24) >= 3 && n->status.udp_confirmed) {
		struct timeval ping_tx_elapsed;
		timersub(&now, &n->udp_reply_sent, &ping_tx_elapsed);

		if(ping_tx_elapsed.tv_sec >= udp_discovery_keepalive_interval - 1) {
			n->udp_reply_sent = now;

			if(n->maxrecentlen) {
				vpn_packet_t pkt;
				pkt.len = n->maxrecentlen;
				pkt.offset = DEFAULT_PACKET_OFFSET;
				memset(DATA(&pkt), 0, 14);
				randomize(DATA(&pkt) + 14, MIN_PROBE_SIZE - 14);
				send_udp_probe_reply(n, &pkt, pkt.len);
				n->maxrecentlen = 0;
			}
		}
	}

	/* Coordinated hole punch: no unsolicited probe outside a round, except a
	   rate-limited LocalDiscovery probe when the peer shares our local LAN. */
	if(!n->status.udp_confirmed && punch_coordinated(n) && !punch_may_probe(n)) {
		if(localdiscovery && n->prevedge && now.tv_sec >= n->punch_backoff_until && node_shares_local_lan(n)) {
			struct timeval ldisc_elapsed;
			timersub(&now, &n->udp_ping_sent, &ldisc_elapsed);

			if(ldisc_elapsed.tv_sec >= udp_discovery_interval) {
				gettimeofday(&now, NULL);
				n->udp_ping_sent = now;
				n->status.ping_sent = true;
				dseal_note_probe(n);
				n->status.send_locally = true;
				send_udp_probe_packet(n, MIN_PROBE_SIZE);
				n->status.send_locally = false;
			}
		}

		return;
	}

	/* Probe request */

	struct timeval ping_tx_elapsed;
	timersub(&now, &n->udp_ping_sent, &ping_tx_elapsed);

	bool rx_silent = has_data && (now.tv_sec - n->last_udp_rx >= udp_discovery_interval);
	int keepalive_interval = low_power_mode ? MAX(udp_discovery_keepalive_interval, 25) : udp_discovery_keepalive_interval;
	int interval = n->status.udp_confirmed
	               ? ((n->status.ping_sent || rx_silent) ? udp_discovery_interval : keepalive_interval)
	               : udp_discovery_interval;

	if(ping_tx_elapsed.tv_sec >= interval) {
		if(n->status.udp_confirmed && n->status.ping_sent) {
			n->udp_ping_unanswered++;

			if(n->udp_ping_unanswered >= 3) {
				n->status.ping_sent = false;
				n->udp_ping_unanswered = 0;
				timeout_del(&n->udp_ping_timeout);
				udp_probe_timeout_handler(n);
				return;
			}
		} else {
			n->udp_ping_unanswered = 0;
		}

		gettimeofday(&now, NULL);
		n->udp_ping_sent = now; // a probe in flight
		n->status.ping_sent = true;

		/* While UDP is not yet confirmed, send a short burst of probes instead
		   of a single one. choose_udp_address() rotates the destination across
		   the reflexive address and known edges on every call, so a burst also
		   covers several candidate paths at once. This is the core of the
		   hole-punching improvement: a burst is far more likely to traverse the
		   brief inbound window a restricted-cone / CGNAT firewall opens. Once
		   confirmed we send exactly one keepalive probe. */
		int burst = n->status.udp_confirmed ? 1 : udp_discovery_burst;

		if(!n->status.udp_confirmed) {
			dseal_note_probe(n);
		}

		if(localdiscovery && !n->status.udp_confirmed && n->prevedge) {
			n->status.send_locally = true;
			send_udp_probe_packet(n, MIN_PROBE_SIZE);
			n->status.send_locally = false;
		}

		for(int i = 0; i < burst; i++) {
			send_udp_probe_packet(n, MIN_PROBE_SIZE);
		}

		if(!n->status.udp_confirmed && timerisset(&n->punch_go) &&
		                n->punch_base_port >= 1024 && n->nat_port_delta != 0 &&
		                !sockaddr_is_private_lan(&n->address)) {
			int pred_port = (int)n->punch_base_port + n->nat_port_delta;

			if(pred_port >= 1024 && pred_port <= 65535) {
				char port_str[16];
				snprintf(port_str, sizeof(port_str), "%d", pred_port);
				sockaddr_t saved_addr = n->address;
				sockaddr_setport(&n->address, port_str);
				force_node_address = true;
				send_udp_probe_packet(n, MIN_PROBE_SIZE);
				force_node_address = false;
				n->address = saved_addr;
			}
		}
	}
}

static length_t choose_initial_maxmtu(node_t *n) {
#ifdef IP_MTU

	int sock = -1;

	const sockaddr_t *sa = NULL;
	size_t sockindex;
	choose_udp_address(n, &sa, &sockindex);

	if(!sa) {
		return MTU;
	}

	sock = socket(sa->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

	if(sock < 0) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Creating MTU assessment socket for %s (%s) failed: %s", n->name, n->hostname, sockstrerror(sockerrno));
		return MTU;
	}

	if(connect(sock, &sa->sa, SALEN(sa->sa))) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Connecting MTU assessment socket for %s (%s) failed: %s", n->name, n->hostname, sockstrerror(sockerrno));
		closesocket(sock);
		return MTU;
	}

	int ip_mtu;
	socklen_t ip_mtu_len = sizeof(ip_mtu);

	if(getsockopt(sock, IPPROTO_IP, IP_MTU, (void *)&ip_mtu, &ip_mtu_len)) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "getsockopt(IP_MTU) on %s (%s) failed: %s", n->name, n->hostname, sockstrerror(sockerrno));
		closesocket(sock);
		return MTU;
	}

	closesocket(sock);

	if(ip_mtu < MINMTU) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "getsockopt(IP_MTU) on %s (%s) returned absurdly small value: %d", n->name, n->hostname, ip_mtu);
		return MTU;
	}

	/* getsockopt(IP_MTU) returns the MTU of the physical interface.
	   We need to remove various overheads to get to the tinc MTU. */
	length_t mtu = ip_mtu;
	mtu -= (sa->sa.sa_family == AF_INET6) ? sizeof(struct ip6_hdr) : sizeof(struct ip);
	mtu -= 8; /* UDP */

	if(n->status.sptps) {
		mtu -= SPTPS_DATAGRAM_OVERHEAD;

		if((n->options >> 24) >= 4) {
			mtu -= sizeof(node_id_t) + sizeof(node_id_t);
		}

#ifndef DISABLE_LEGACY
	} else {
		mtu -= digest_length(n->outdigest);

		/* Now it's tricky. We use CBC mode, so the length of the
		   encrypted payload must be a multiple of the blocksize. The
		   sequence number is also part of the encrypted payload, so we
		   must account for it after correcting for the blocksize.
		   Furthermore, the padding in the last block must be at least
		   1 byte. */

		length_t blocksize = cipher_blocksize(n->outcipher);

		if(blocksize > 1) {
			mtu /= blocksize;
			mtu *= blocksize;
			mtu--;
		}

		mtu -= 4; // seqno
#endif
	}

	if(mtu > MTU) {
		return MTU;
	}

	logger(DEBUG_TRAFFIC, LOG_INFO, "Using system-provided maximum tinc MTU for %s (%s): %hd", n->name, n->hostname, mtu);
	return mtu;

#else
	(void)n;
	return MTU;
#endif
}

/* This function tries to determines the MTU of a node.
   By calling this function repeatedly, n->minmtu will be progressively
   increased, and at some point, n->mtu will be fixed to n->minmtu.  If the MTU
   is already fixed, this function checks if it can be increased.
*/

static void try_mtu(node_t *n) {
	if(!(n->options & OPTION_PMTU_DISCOVERY)) {
		return;
	}

	if(udp_discovery && !n->status.udp_confirmed) {
		n->maxrecentlen = 0;
		n->mtuprobes = 0;
		n->minmtu = 0;
		n->maxmtu = MTU;
		return;
	}

	/* mtuprobes == 0..19: initial discovery, send bursts with 1 second interval, mtuprobes++
	   mtuprobes ==    20: fix MTU, and go to -1
	   mtuprobes ==    -1: send one maxmtu and one maxmtu+1 probe every pinginterval
	   mtuprobes ==-2..-3: send one maxmtu probe every second
	   mtuprobes ==    -4: maxmtu no longer valid, reset minmtu and maxmtu and go to 0 */

	if(n->mtuprobes < 0 && carrier_datagram_path(n)) {
		return; /* fixed; a smaller carrier ceiling comes back as reduce_mtu() */
	}

	struct timeval elapsed;
	timersub(&now, &n->mtu_ping_sent, &elapsed);

	if(n->mtuprobes >= 0) {
		if(n->mtuprobes != 0 && elapsed.tv_sec == 0 && elapsed.tv_usec < 333333) {
			return;
		}
	} else {
		if(n->mtuprobes < -1) {
			if(elapsed.tv_sec < 1) {
				return;
			}
		} else {
			if(elapsed.tv_sec < pinginterval) {
				return;
			}
		}
	}

	n->mtu_ping_sent = now;

	try_fix_mtu(n);

	if(n->mtuprobes < -3) {
		/* We lost three MTU probes, restart discovery */
		logger(DEBUG_TRAFFIC, LOG_INFO, "Decrease in PMTU to %s (%s) detected, restarting PMTU discovery", n->name, n->hostname);
		n->mtuprobes = 0;
		n->minmtu = 0;
	}

	if(n->mtuprobes < 0) {
		/* After the initial discovery, we only send one maxmtu and one
		   maxmtu+1 probe to detect PMTU increases. */
		send_udp_probe_packet(n, n->maxmtu);

		if(n->mtuprobes == -1 && n->maxmtu + 1 < MTU) {
			send_udp_probe_packet(n, n->maxmtu + 1);
		}

		n->mtuprobes--;
	} else {
		/* Before initial discovery begins, set maxmtu to the most likely value.
		   If it's underestimated, we will correct it after initial discovery. */
		if(n->mtuprobes == 0) {
			n->maxmtu = choose_initial_maxmtu(n);
		}

		for(;;) {
			/* Decreasing the number of probes per cycle might make the algorithm react faster to lost packets,
			   but it will typically increase convergence time in the no-loss case. */
			const length_t probes_per_cycle = 8;

			/* This magic value was determined using math simulations.
			   It will result in a 1329-byte first probe, followed (if there was a reply) by a 1407-byte probe.
			   Since 1407 is just below the range of tinc MTUs over typical networks,
			   this fine-tuning allows tinc to cover a lot of ground very quickly.
			   This fine-tuning is only valid for maxmtu = MTU; if maxmtu is smaller,
			   then it's better to use a multiplier of 1. Indeed, this leads to an interesting scenario
			   if choose_initial_maxmtu() returns the actual MTU value - it will get confirmed with one single probe. */
			const float multiplier = (n->maxmtu == MTU) ? 0.97f : 1.0f;

			const float cycle_position = (float) probes_per_cycle - (float)(n->mtuprobes % probes_per_cycle) - 1.0f;
			const length_t minmtu = MAX(n->minmtu, MINMTU);
			const float interval = (float)(n->maxmtu - minmtu);

			length_t offset = 0;

			/* powf can be underflowed if n->maxmtu is less than 512 due to the minmtu MAX bound */
			if(interval > 0) {
				/* The core of the discovery algorithm is this exponential.
				        It produces very large probes early in the cycle, and then it very quickly decreases the probe size.
				        This reflects the fact that in the most difficult cases, we don't get any feedback for probes that
				        are too large, and therefore we need to concentrate on small offsets so that we can quickly converge
				        on the precise MTU as we are approaching it.
				        The last probe of the cycle is always 1 byte in size - this is to make sure we'll get at least one
				        reply per cycle so that we can make progress. */
				offset = lrintf(powf(interval, multiplier * cycle_position / (float)(probes_per_cycle - 1)));
			}

			length_t maxmtu = n->maxmtu;
			send_udp_probe_packet(n, minmtu + offset);

			/* If maxmtu changed, it means the probe was rejected by the system because it was too large.
			   In that case, we recalculate with the new maxmtu and try again. */
			if(n->mtuprobes < 0 || maxmtu == n->maxmtu) {
				break;
			}
		}

		/* Bridge the gap between probe 0 (~1345) and probe 1 (~891) on tunnel/LTE
		   paths by testing the standard 1280-byte IPv6/tunnel floor during cycle 1. */
		if(n->mtuprobes == 1 && n->minmtu < 1280 && n->maxmtu >= 1280) {
			send_udp_probe_packet(n, 1280);
		}

		if(n->mtuprobes >= 0) {
			n->mtuprobes++;
		}
	}
}

/* These functions try to establish a tunnel to a node (or its relay) so that
   packets can be sent (e.g. exchange keys).
   If a tunnel is already established, it tries to improve it (e.g. by trying
   to establish a UDP tunnel instead of TCP).  This function makes no
   guarantees - it is up to the caller to check the node's state to figure out
   if TCP and/or UDP is usable.  By calling this function repeatedly, the
   tunnel is gradually improved until we hit the wall imposed by the underlying
   network environment.  It is recommended to call this function every time a
   packet is sent (or intended to be sent) to a node, so that the tunnel keeps
   improving as packets flow, and then gracefully downgrades itself as it goes
   idle.
*/

static void try_tx_sptps(node_t *n, bool mtu) {
	/* If n is a TCP-only neighbor, we'll only use "cleartext" PACKET
	   messages anyway, so there's no need for SPTPS at all. */

	if(n->connection && node_tcponly(n)) {
		if(multipath_mode == MULTIPATH_REDUNDANT && n->connections.count > 1) {
			try_sptps(n);
		}

		return;
	}

	/* Otherwise, try to do SPTPS authentication with n if necessary. */

	try_sptps(n);

	/* Do we need to statically relay packets? */

	node_t *via = (n->via == myself) ? n->nexthop : n->via;

	/* If we do have a static relay, try everything with that one instead, if it supports relaying. */

	if(via != n) {
		if((via->options >> 24) < 4) {
			return;
		}

		try_tx(via, mtu);
		return;
	}

	/* Otherwise, try to establish UDP connectivity. */

	try_udp(n, mtu);

	if(mtu) {
		try_mtu(n);
	}

	/* If we don't have UDP connectivity (yet), we need to use a dynamic relay (nexthop)
	   while we try to establish direct connectivity. */

	if(!n->status.udp_confirmed && n != n->nexthop && (n->nexthop->options >> 24) >= 4) {
		try_tx(n->nexthop, mtu);
	}
}

static void try_tx_legacy(node_t *n, bool mtu) {
	/* Does he have our key? If not, send one. */

	if(!n->status.validkey_in) {
		send_ans_key(n);
	}

	/* Check if we already have a key, or request one. */

	if(!n->status.validkey) {
		if(n->last_req_key + 10 <= now.tv_sec) {
			send_req_key(n);
			n->last_req_key = now.tv_sec;
		}

		return;
	}

	try_udp(n, mtu);

	if(mtu) {
		try_mtu(n);
	}
}

void try_tx(node_t *n, bool mtu) {
	if(!n->status.reachable) {
		return;
	}

	if(n->status.sptps) {
		try_tx_sptps(n, mtu);
	} else {
		try_tx_legacy(n, mtu);
	}
}

void send_packet(node_t *n, vpn_packet_t *packet) {
	// If it's for myself, write it to the tun/tap device.

	if(n == myself) {
		if(overwrite_mac) {
			memcpy(DATA(packet), mymac.x, ETH_ALEN);
			// Use an arbitrary fake source address.
			memcpy(DATA(packet) + ETH_ALEN, DATA(packet), ETH_ALEN);
			DATA(packet)[ETH_ALEN * 2 - 1] ^= 0xFF;
		}

		n->out_packets++;
		n->out_bytes += packet->len;
		devops.write(packet);
		return;
	}

	logger(DEBUG_TRAFFIC, LOG_ERR, "Sending packet of %d bytes to %s (%s)", packet->len, n->name, n->hostname);

	// If the node is not reachable, drop it.

	if(!n->status.reachable) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Node %s (%s) is not reachable", n->name, n->hostname);
		return;
	}

	// Keep track of packet statistics.

	n->out_packets++;
	n->out_bytes += packet->len;

	// Check if it should be sent as an SPTPS packet.

	if(n->status.sptps) {
		send_sptps_packet(n, packet);
		try_tx(n, true);
		return;
	}

	// Determine which node to actually send it to.

	node_t *via = (packet->priority == -1 || n->via == myself) ? n->nexthop : n->via;

	if(via != n) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending packet to %s via %s (%s)", n->name, via->name, n->via->hostname);
	}

	// Try to send via UDP, unless TCP is forced.

	if(packet->priority == -1 || node_tcponly(via)) {
		connection_t *conns[2] = {NULL, NULL};
		int nconns = multipath_select_connections(via, packet, conns);
		connection_t *target_c = nconns > 0 ? conns[0] : via->connection;

		if(!send_tcppacket(target_c, packet)) {
			terminate_connection(target_c, true);
		}

		return;
	}

	send_udppacket(via, packet);
	try_tx(via, true);
}

void broadcast_packet(const node_t *from, vpn_packet_t *packet) {
	// Always give ourself a copy of the packet.
	if(from != myself) {
		send_packet(myself, packet);
	}

	// In TunnelServer mode, do not forward broadcast packets.
	// The MST might not be valid and create loops.
	if(tunnelserver || broadcast_mode == BMODE_NONE) {
		return;
	}

	logger(DEBUG_TRAFFIC, LOG_INFO, "Broadcasting packet of %d bytes from %s (%s)",
	       packet->len, from->name, from->hostname);

	switch(broadcast_mode) {
	// In MST mode, broadcast packets travel via the Minimum Spanning Tree.
	// This guarantees all nodes receive the broadcast packet, and
	// usually distributes the sending of broadcast packets over all nodes.
	case BMODE_MST: {
		int count = connection_list.count;

		if(count > 0) {
			node_t **targets = alloca((size_t)count * sizeof(node_t *));
			int ntargets = 0;
			connection_t *skip_c = from->nexthop ? from->nexthop->connection : NULL;

			for list_each(connection_t, c, &connection_list) {
				if(c->edge && c->status.mst && c != skip_c && c->node && ntargets < count) {
					targets[ntargets++] = c->node;
				}
			}

			for(int i = 0; i < ntargets; i++) {
				if(targets[i]->status.reachable) {
					send_packet(targets[i], packet);
				}
			}
		}

		break;
	}

	// In direct mode, we send copies to each node we know of.
	// However, this only reaches nodes that can be reached in a single hop.
	// We don't have enough information to forward broadcast packets in this case.
	case BMODE_DIRECT:
		if(from != myself) {
			break;
		}

		for splay_each(node_t, n, &node_tree)
			if(n->status.reachable && n != myself && ((n->via == myself && n->nexthop == n) || n->via == n)) {
				send_packet(n, packet);
			}

		break;

	case BMODE_NONE:
	default:
		break;
	}
}

/* We got a packet from some IP address, but we don't know who sent it.  Try to
   verify the message authentication code against all active session keys.
   Since this is actually an expensive operation, we only do a full check once
   a minute, the rest of the time we only check against nodes for which we know
   an IP address that matches the one from the packet.  */

static node_t *try_harder(const sockaddr_t *from, const vpn_packet_t *pkt) {
	node_t *match = NULL;
	bool hard = false;
	static time_t last_hard_try = 0;

	for splay_each(node_t, n, &node_tree) {
		if(!n->status.reachable || n == myself) {
			continue;
		}

		if(!n->status.validkey_in && !(n->status.sptps && n->sptps.instate)) {
			continue;
		}

		bool soft = false;

		for splay_each(edge_t, e, &n->edge_tree) {
			if(!e->reverse) {
				continue;
			}

			if(!sockaddrcmp_noport(from, &e->reverse->address)) {
				soft = true;
				break;
			}
		}

		if(!soft) {
			if(last_hard_try == now.tv_sec) {
				continue;
			}

			hard = true;
		}

		if(!try_mac(n, pkt)) {
			continue;
		}

		match = n;
		break;
	}

	if(hard) {
		last_hard_try = now.tv_sec;
	}

	return match;
}

/* Would process_sptps_udp() below recognise this datagram as ordinary data
   from `n', the node the source address is bound to?

   The obfs carrier asks before it decides to leave a datagram from an
   already-confirmed plain peer alone. It used to skip its keyed check for
   every such peer, which made obfs undialable on any network that was already
   carrying traffic -- the only networks that ever need it (stream AD). This
   is the cheap half of "let the SPTPS path try first": it runs exactly the
   identification process_sptps_udp() runs, and nothing else.

   A relay-capable peer (protocol option version >= 4, which is every build
   that can speak obfs at all) prefixes each data datagram with a destination
   and a source node id -- all-zero destination for a direct one. An obfs
   frame starts with its whitened nonce instead, so the destination id is
   random: it is neither zero nor a node we know, and the datagram falls
   through to the keyed check instead of being dropped. The residual is one
   frame in 2^48 whose first six bytes happen to be zero; that frame is
   dropped and the handshake retries.

   A peer that is not relay-capable has no such header, so every datagram from
   it is "direct" and nothing here can tell obfs from data. That is safe
   rather than lucky: such a build has no obfs carrier either, and the address
   we looked up is that very node's. */
bool sptps_udp_addresses_known_nodes(const node_t *n, const uint8_t *buf, size_t len) {
	if(!n->status.sptps || (n->options >> 24) < 4) {
		return true;
	}

	if(len < 2 * sizeof(node_id_t)) {
		return false;
	}

	node_id_t nullid = {0};
	node_id_t dst, src;
	memcpy(&dst, buf, sizeof(dst));
	memcpy(&src, buf + sizeof(dst), sizeof(src));

	if(!memcmp(&dst, &nullid, sizeof(nullid))) {
		return true; /* a direct datagram addressed to us */
	}

	return lookup_node_id(&src) && lookup_node_id(&dst);
}

/* The SPTPS / legacy UDP data path, split out so the obfs carrier can
   re-inject a datagram it just unsealed without going back through the carrier
   dispatcher (which would try to classify the inner bytes again). */
/* `via_carrier': the record arrived inside a carrier flow (a QUIC DATAGRAM
   frame), so `addr' is that flow's remote -- the peer's QUIC socket as its
   NAT maps it -- and says nothing about where its UDP data socket is. Such a
   record must not move n->address: a relay that did so handed the QUIC flow
   out as the node's UDP address (UDP_INFO, the ANS_KEY hint), and every pair
   behind a port-changing NAT punched at the wrong port (stream N,
   docs/nat.md §5.1). The node's data-socket mapping reaches the relay from
   the node's carrier beacons instead (send_carrier_beacon).
   `carrier_node' (non-NULL only with via_carrier) is the node at the other
   end of the carrier's authenticated meta connection: the sender of the
   record, whatever its address. Looking the sender up by address no longer
   works once the flow is not n->address, and a relayed record (non-zero
   destination id) has no other way to be attributed. */
static void process_sptps_udp(listen_socket_t *ls, vpn_packet_t *pkt, sockaddr_t *addr, bool via_carrier, node_t *carrier_node) {
	char *hostname;
	node_id_t nullid = {0};
	node_t *from, *to;
	bool direct = false;

	sockaddrunmap(addr); /* Some braindead IPv6 implementations do stupid things. */

	// Try to figure out who sent this packet.

	node_t *n = via_carrier ? carrier_node : lookup_node_udp(addr);

	if(via_carrier && !n) {
		return;         // the carrier's connection is not authenticated yet
	}

	if(n && !via_carrier && !n->status.udp_confirmed) {
		n = NULL;        // Don't believe it if we don't have confirmation yet.
	}

	/* If this datagram was just unsealed and replay-checked by obfs_accept(),
	   carrier_node is the authenticated sender node even when its NAT mapping
	   just changed (so lookup_node_udp(addr) missed) and even when the inner
	   record is a relayed packet (DSTID != 0, which sptps_verify_datagram
	   cannot verify because it is encrypted end-to-end for the destination). */
	if(!n && !via_carrier && carrier_node) {
		n = carrier_node;
	}

	if(!n) {
		// It might be from a 1.1 node, which might have a source ID in the packet.
		pkt->offset = 2 * sizeof(node_id_t);

		if(pkt->len >= pkt->offset) {
			from = lookup_node_id(SRCID(pkt));

			if(from && from->status.sptps &&
			                (!memcmp(DSTID(pkt), &nullid, sizeof(nullid)) || !memcmp(DSTID(pkt), &myself->id, sizeof(myself->id)))) {
				if(sptps_verify_datagram(&from->sptps, DATA(pkt), pkt->len - 2 * sizeof(node_id_t))) {
					if(!memcmp(DSTID(pkt), &nullid, sizeof(nullid))) {
						n = from;
					} else {
						n = (from->via && from->via != myself) ? from->via : (from->nexthop ? from->nexthop : from);
					}
				} else {
					goto skip_harder;
				}
			}
		}
	}

	if(!n) {
		pkt->offset = 0;
		n = try_harder(addr, pkt);
	}

skip_harder:

	if(!n) {
		if(debug_level >= DEBUG_TRAFFIC) {
			hostname = sockaddr2hostname(addr);
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Received UDP packet from unknown source %s", hostname);
			free(hostname);
		}

		return;
	}

	pkt->offset = 0;

	if(n->status.sptps) {
		bool relay_enabled = (n->options >> 24) >= 4;

		if(relay_enabled) {
			pkt->offset = 2 * sizeof(node_id_t);

			if(pkt->offset > pkt->len) {
				logger(DEBUG_TRAFFIC, LOG_WARNING, "Got too short packet from %s (%s)", n->name, n->hostname);
				return;
			}

			pkt->len -= pkt->offset;
		}

		if(!relay_enabled || !memcmp(DSTID(pkt), &nullid, sizeof(nullid))) {
			if(n->status.no_direct || node_is_no_direct(n->name)) {
				if(n->last_no_direct_sent != now.tv_sec) {
					n->last_no_direct_sent = now.tv_sec;
					send_no_direct_signal(n, true);
				}

				return;
			}

			direct = true;
			from = n;
			to = myself;
		} else {
			from = lookup_node_id(SRCID(pkt));
			to = lookup_node_id(DSTID(pkt));
		}

		if(!from || !to) {
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Received UDP packet from %s (%s) with unknown source and/or destination ID", n->name, n->hostname);
			return;
		}

		if(!to->status.reachable) {
			/* This can happen in the form of a race condition
			   if the node just became unreachable. */
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Cannot relay packet from %s (%s) because the destination, %s (%s), is unreachable", from->name, from->hostname, to->name, to->hostname);
			return;
		}

		/* The packet is supposed to come from the originator or its static relay
		   (i.e. with no dynamic relays in between).
		   If it did not, "help" the static relay by sending it UDP info.
		   Note that we only do this if we're the destination or the static relay;
		   otherwise every hop would initiate its own UDP info message, resulting in elevated chatter. */

		if(n != from->via && (to == myself || (to->via == myself && to->nexthop == to))) {
			send_udp_info(myself, from);
		}

		/* If we're not the final recipient, relay the packet. */

		if(to != myself) {
			size_t origlen = pkt->len > SPTPS_DATAGRAM_OVERHEAD ? pkt->len - SPTPS_DATAGRAM_OVERHEAD : 0;
			node_t *relay = (to->via != myself && origlen <= to->via->minmtu) ? to->via : to->nexthop;

			if(!relay || relay == myself || relay == n || relay == from) {
				logger(DEBUG_TRAFFIC, LOG_ERR, "Routing loop relaying UDP SPTPS packet from %s to %s via %s!", from->name, to->name, relay ? relay->name : "(null)");
				return;
			}

			if(carrier_node && !via_carrier) {
				n->sock = ls - listen_socket;

				if(sockaddrcmp(addr, &n->address)) {
					update_node_udp(n, addr);
				}

				n->status.udp_addr_confirmed = true;
			}

			n->last_udp_rx = now.tv_sec;
			n->udp_ping_unanswered = 0;

			send_sptps_data(to, from, 0, DATA(pkt), pkt->len);
			try_tx(to, true);
			return;
		}
	} else {
		direct = true;
		from = n;
	}

	if(direct && !via_carrier) {
		current_udp_rx_addr = addr;
		current_udp_rx_sock = (int)(ls - listen_socket);
		current_udp_rx_len = pkt->len;
	} else {
		current_udp_rx_addr = NULL;
		current_udp_rx_sock = -1;
		current_udp_rx_len = 0;
	}

	current_udp_rx_direct = direct;
	bool rx_ok = receive_udppacket(from, pkt);
	current_udp_rx_direct = false;
	current_udp_rx_addr = NULL;
	current_udp_rx_sock = -1;
	current_udp_rx_len = 0;

	if(!rx_ok) {
		return;
	}

	if(!direct || via_carrier) {
		n->sock = ls - listen_socket;
	}

	/* If the packet went through a relay, help the sender find the appropriate MTU
	   through the relay path. */

	if(!direct) {
		if(n != from) {
			n->last_udp_rx = now.tv_sec;
			n->udp_ping_unanswered = 0;
		}

		send_mtu_info(myself, from, MTU);
	}
}

static void handle_incoming_vpn_packet(listen_socket_t *ls, vpn_packet_t *pkt, sockaddr_t *addr) {
	sockaddrunmap(addr);

	if(sockaddr_is_my_nat_wan_ip(addr)) {
		return;
	}

	/* First give the carriers a chance to claim this datagram (single-flow
	   meta frames, QUIC, obfs). Anything they do not claim is an ordinary
	   SPTPS / legacy data packet and is handled by process_sptps_udp() exactly
	   as before. The classifier keys on a reserved prefix (or, for obfs, a
	   keyed check), so a real data packet is never mis-claimed (see
	   docs/transports.md). */
	if(transport_udp_dispatch(ls, pkt->data, pkt->len, addr)) {
		return;
	}

	process_sptps_udp(ls, pkt, addr, false, NULL);
}

void handle_incoming_vpn_packet_uplink(int uplink_idx, listen_socket_t *ls, vpn_packet_t *pkt, sockaddr_t *addr) {
	int prev = multipath_current_rx_uplink;
	multipath_current_rx_uplink = uplink_idx;
	handle_incoming_vpn_packet(ls, pkt, addr);
	multipath_current_rx_uplink = prev;
}

/* Re-inject an inner SPTPS datagram that the obfs carrier just unsealed. It
   goes straight to the data path, bypassing carrier dispatch. */
void handle_incoming_vpn_packet_decap(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr, node_t *from) {
	if(len > MAXSIZE) {
		return;
	}

	vpn_packet_t pkt;
	pkt.offset = 0;
	pkt.priority = 0;
	memcpy(pkt.data, buf, len);
	pkt.len = len;

	sockaddr_t a = *addr;
	process_sptps_udp(ls, &pkt, &a, false, from);
}

/* A record a carrier delivered inside its own flow (quic's DATAGRAM frames):
   the data path, but `addr' is the carrier flow's (see process_sptps_udp). */
void handle_incoming_carrier_datagram(listen_socket_t *ls, const uint8_t *buf, size_t len, const sockaddr_t *addr, node_t *from) {
	if(len > MAXSIZE) {
		return;
	}

	vpn_packet_t pkt;
	pkt.offset = 0;
	pkt.priority = 0;
	memcpy(pkt.data, buf, len);
	pkt.len = len;

	sockaddr_t a = *addr;
	process_sptps_udp(ls, &pkt, &a, true, from);
}

void handle_incoming_vpn_data(void *data, int flags) {
	(void)data;
	(void)flags;
	listen_socket_t *ls = data;

#ifdef HAVE_RECVMMSG
#define MAX_MSG 64
	static ssize_t num = MAX_MSG;
	static vpn_packet_t pkt[MAX_MSG];
	static sockaddr_t addr[MAX_MSG];
	static struct mmsghdr msg[MAX_MSG];
	static struct iovec iov[MAX_MSG];

	for(int i = 0; i < num; i++) {
		pkt[i].offset = 0;

		iov[i] = (struct iovec) {
			.iov_base = DATA(&pkt[i]),
			.iov_len = MAXSIZE,
		};

		msg[i].msg_hdr = (struct msghdr) {
			.msg_name = &addr[i].sa,
			.msg_namelen = sizeof(addr)[i],
			.msg_iov = &iov[i],
			.msg_iovlen = 1,
		};
	}

	num = recvmmsg(ls->udp.fd, msg, MAX_MSG, MSG_DONTWAIT, NULL);

	if(num < 0) {
		num = MAX_MSG;

		if(!sockwouldblock(sockerrno)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Receiving packet failed: %s", sockstrerror(sockerrno));
		}

		return;
	}

	quic_batch_begin();

	for(int i = 0; i < num; i++) {
		pkt[i].len = msg[i].msg_len;

		if(pkt[i].len <= 0 || pkt[i].len > MAXSIZE) {
			continue;
		}

		handle_incoming_vpn_packet(ls, &pkt[i], &addr[i]);
	}

	quic_batch_end();

#else
	vpn_packet_t pkt;
	sockaddr_t addr = {0};
	socklen_t addrlen = sizeof(addr);

	pkt.offset = 0;
	ssize_t len = recvfrom(ls->udp.fd, (void *)DATA(&pkt), MAXSIZE, 0, &addr.sa, &addrlen);

	if(len <= 0 || (size_t)len > MAXSIZE) {
		if(!sockwouldblock(sockerrno)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Receiving packet failed: %s", sockstrerror(sockerrno));
		}

		return;
	}

	pkt.len = len;

	handle_incoming_vpn_packet(ls, &pkt, &addr);

#endif
}

void handle_device_data(void *data, int flags) {
	(void)data;
	(void)flags;
	vpn_packet_t packet;
	static int errors = 0;

	quic_batch_begin();

	for(int i = 0; i < 64; i++) {
		errno = 0;
		packet.offset = DEFAULT_PACKET_OFFSET;
		packet.priority = 0;

		if(devops.read(&packet)) {
			errors = 0;
			myself->in_packets++;
			myself->in_bytes += packet.len;
			route(myself, &packet);
#ifdef HAVE_LINUX
			if(devops.read != os_devops.read) {
				break;
			}
#else
			break;
#endif
		} else {
			if(errno == EAGAIN || errno == EINTR) {
				break;
			}

			sleep_millis(errors * 50);
			errors++;

			if(errors > 10) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Too many errors from %s, exiting!", device);
				event_exit();
			}

			break;
		}
	}

	quic_batch_end();
}

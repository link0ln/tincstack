/*
    multipath.c -- Hybrid Application-Level Multipath & Multi-WAN engine.

    Implements:
      - Multi-interface / multi-gateway uplink management (Linux, Android, Windows)
      - Cross-platform socket binding:
          * Linux:   SO_BINDTODEVICE, SO_MARK, source IP bind, AF_NETLINK route/link watcher
          * Android: android_setsocknetwork() via libandroid.so dlsym + source IP bind
          * Windows: IP_UNICAST_IF / IPV6_UNICAST_IF + source IP bind
      - Multi-connection pool per node_t (n->connections) with 0-ms make-before-break
        failover (transferring edge_t to a surviving connection without graph() churn
        or SPTPS reset)
      - Per-node multi-path UDP table (n->paths[MAX_NODE_PATHS])
      - Packet schedulers: failover, flowhash (5-tuple inner packet hash),
        redundant (2x duplication, deduplicated by SPTPS seqno bitmap), and
        split (burst-boundary rotation against statistical DPI)
      - Post-handshake QUIC path migration trigger on uplink state change
*/

#include "system.h"

#include <stddef.h>

#ifdef HAVE_LINUX
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#if defined(__ANDROID__) || defined(HAVE_ANDROID)
#include <dlfcn.h>
#endif

#include "address_cache.h"
#include "autoif.h"
#include "conf.h"
#include "connection.h"
#include "control_common.h"
#include "edge.h"
#include "ethernet.h"
#include "graph.h"
#include "ipv4.h"
#include "ipv6.h"
#include "logger.h"
#include "multipath.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "obfs.h"
#include "protocol.h"
#include "route.h"
#define TINC_TRANSPORT_DAEMON
#include "transport.h"
#include "transport_quic.h"
#include "utils.h"
#include "xalloc.h"

multipath_mode_t multipath_mode = MULTIPATH_FAILOVER;
int multipath_target_connections = 1;
uint32_t multipath_tcp_max_pacing_rate = 0;
bool multipath_tcp_auto_pacing = true;
multipath_uplink_t multipath_uplinks[MAX_UPLINKS];
int multipath_uplink_count = 0;

/* Set while processing an inbound packet from a dedicated uplink UDP socket */
extern int multipath_current_rx_uplink;

static timeout_t multipath_timer;
static bool multipath_initialized = false;

static bool connection_ping_overdue(const connection_t *c) {
	return c && c->status.pinged && (now.tv_sec - c->last_ping_time > 5);
}

typedef struct mp_tcp_diag_t {
	bool valid;
	uint32_t rtt_us;
	uint32_t min_rtt_us;
	uint32_t snd_cwnd;
	uint32_t total_retrans;
	uint32_t segs_out;
	uint64_t pacing_bps;
} mp_tcp_diag_t;

static bool connection_is_loopback(const connection_t *c) {
	if(!c) {
		return false;
	}

	if(c->address.sa.sa_family == AF_INET) {
		return (ntohl(c->address.in.sin_addr.s_addr) >> 24) == 127U;
	}

	if(c->address.sa.sa_family == AF_INET6) {
		return IN6_IS_ADDR_LOOPBACK(&c->address.in6.sin6_addr) ||
		       (IN6_IS_ADDR_V4MAPPED(&c->address.in6.sin6_addr) &&
		        c->address.in6.sin6_addr.s6_addr[12] == 127U);
	}

	return false;
}

static bool connection_has_wan_rtt(const connection_t *c) {
	return c && !connection_is_loopback(c) && c->tcp_min_rtt_us >= 1000;
}

static bool connection_check_policed(connection_t *c, uint64_t best_pacing_bps) {
	if(!connection_has_wan_rtt(c)) {
		return false;
	}

	/* Condition A: standalone TSPU ~0.5-3.5 Mbps policer */
	uint64_t policed_pacing_ceil = (c->applied_pacing_rate > 0 &&
	                                (uint64_t)c->applied_pacing_rate * 4ULL < 4000000ULL)
	                               ? (uint64_t)c->applied_pacing_rate * 4ULL
	                               : 4000000ULL;

	if(c->tcp_segs_out >= 80 &&
	                ((c->tcp_segs_out >= 150 && (uint64_t)c->tcp_total_retrans * 40ULL > (uint64_t)c->tcp_segs_out) ||
	                 (c->tcp_segs_out < 150 && (uint64_t)c->tcp_total_retrans * 28ULL > (uint64_t)c->tcp_segs_out)) &&
	                c->tcp_cwnd > 0 && c->tcp_cwnd <= 32 &&
	                c->tcp_pacing_bps > 0 && c->tcp_pacing_bps < policed_pacing_ceil) {
		bool newly = !c->tcp_degraded;
		c->tcp_degraded = true;

		if(newly && best_pacing_bps < 12000000ULL) {
			multipath_handle_conn_degraded(c->node, c);
		}

		return true;
	}

	/* Condition B: relative ECMP throttling vs proven fast sibling */
	if(best_pacing_bps >= 15000000ULL && c->tcp_segs_out >= 300 &&
	                (uint64_t)c->tcp_total_retrans * 33ULL > (uint64_t)c->tcp_segs_out &&
	                c->tcp_cwnd > 0 && c->tcp_cwnd <= 75 &&
	                c->tcp_pacing_bps > 0 && c->tcp_pacing_bps < 12000000ULL &&
	                c->tcp_pacing_bps * 4ULL < best_pacing_bps) {
		c->tcp_degraded = true;
		return true;
	}

	/* Condition C: BBRv1 lt_bw / low-cwnd lockup (< 3 Mbps, cwnd <= 28) vs proven >= 12 Mbps sibling */
	if(best_pacing_bps >= 12000000ULL && c->tcp_segs_out >= 800 &&
	                (c->tcp_total_retrans >= 8 || (uint64_t)c->tcp_total_retrans * 200ULL > (uint64_t)c->tcp_segs_out) &&
	                c->tcp_cwnd > 0 && c->tcp_cwnd <= 28 &&
	                c->tcp_pacing_bps > 0 && c->tcp_pacing_bps < 3000000ULL &&
	                c->tcp_pacing_bps * 4ULL < best_pacing_bps) {
		c->tcp_degraded = true;
		return true;
	}

	/* Condition D: high-loss (> 12%) ECMP tuple lagging healthy sibling (effective under TcpMaxPacingRate too) */
	if(best_pacing_bps >= 8000000ULL && c->tcp_segs_out >= 400 &&
	                (uint64_t)c->tcp_total_retrans * 25ULL > (uint64_t)c->tcp_segs_out * 3ULL &&
	                c->tcp_pacing_bps > 0 && c->tcp_pacing_bps * 3ULL < best_pacing_bps * 2ULL) {
		c->tcp_degraded = true;
		return true;
	}

	return false;
}

static bool query_connection_tcp_diag(connection_t *c, mp_tcp_diag_t *out) {
	if(out) {
		memset(out, 0, sizeof(*out));
	}

	if(!c || !c->status.active) {
		return false;
	}

	if(c->transport && c->transport->id == TRANSPORT_QUIC) {
		uint32_t rtt_us = 0, min_rtt_us = 0, cwnd = 0, lost = 0, sent = 0;
		uint64_t pbps = 0;

		if(!quic_get_conn_diag(c, &rtt_us, &min_rtt_us, &cwnd, &pbps, &lost, &sent)) {
			return false;
		}

		if(out) {
			out->valid = true;
			out->rtt_us = rtt_us;
			out->min_rtt_us = min_rtt_us;
			out->snd_cwnd = cwnd;
			out->pacing_bps = pbps;
			out->total_retrans = lost;
			out->segs_out = sent;
		}

		return true;
	}

#if defined(HAVE_LINUX) && defined(TCP_INFO)

	if(c->socket < 0) {
		return false;
	}

	if(c->address.sa.sa_family != AF_INET && c->address.sa.sa_family != AF_INET6) {
		return false;
	}

	if(c->transport && (c->transport->id == TRANSPORT_SF ||
	                    c->transport->id == TRANSPORT_OBFS)) {
		return false;
	}

	struct linux_tcp_info_minrtt {
		uint8_t  tcpi_u8[8];
		uint32_t tcpi_u32_a[24];
		uint64_t tcpi_u64_a[4];
		uint32_t tcpi_segs_out;
		uint32_t tcpi_segs_in;
		uint32_t tcpi_notsent_bytes;
		uint32_t tcpi_min_rtt;
	};

	_Static_assert(offsetof(struct linux_tcp_info_minrtt, tcpi_u32_a) + 15 * sizeof(uint32_t) == 68,
	               "tcpi_rtt offset mismatch");
	_Static_assert(offsetof(struct linux_tcp_info_minrtt, tcpi_u32_a) + 18 * sizeof(uint32_t) == 80,
	               "tcpi_snd_cwnd offset mismatch");
	_Static_assert(offsetof(struct linux_tcp_info_minrtt, tcpi_u32_a) + 23 * sizeof(uint32_t) == 100,
	               "tcpi_total_retrans offset mismatch");
	_Static_assert(offsetof(struct linux_tcp_info_minrtt, tcpi_u64_a) == 104,
	               "tcpi_pacing_rate offset mismatch");
	_Static_assert(offsetof(struct linux_tcp_info_minrtt, tcpi_segs_out) == 136,
	               "tcpi_segs_out offset mismatch");
	_Static_assert(offsetof(struct linux_tcp_info_minrtt, tcpi_min_rtt) == 148,
	               "linux_tcp_info_minrtt offset mismatch");

	struct linux_tcp_info_minrtt ti;
	socklen_t optlen = sizeof(ti);
	memset(&ti, 0, sizeof(ti));

	if(getsockopt(c->socket, IPPROTO_TCP, TCP_INFO, &ti, &optlen) != 0) {
		return false;
	}

	if(out) {
		if((size_t)optlen >= offsetof(struct linux_tcp_info_minrtt, tcpi_u64_a)) {
			out->valid = true;
			out->rtt_us = ti.tcpi_u32_a[15];
			out->snd_cwnd = ti.tcpi_u32_a[18];
			out->total_retrans = ti.tcpi_u32_a[23];
		}

		if((size_t)optlen >= offsetof(struct linux_tcp_info_minrtt, tcpi_segs_out)) {
			out->pacing_bps = ti.tcpi_u64_a[0] <= (UINT64_MAX / 8U) ? ti.tcpi_u64_a[0] * 8U : UINT64_MAX;
		}

		if((size_t)optlen >= offsetof(struct linux_tcp_info_minrtt, tcpi_segs_in)) {
			out->segs_out = ti.tcpi_segs_out;
		}

		if((size_t)optlen >= sizeof(ti) && ti.tcpi_min_rtt > 0 && ti.tcpi_min_rtt < 10000000U) {
			out->min_rtt_us = ti.tcpi_min_rtt;
		}
	}

	return out ? out->valid : true;
#else
	return false;
#endif
}

static void refresh_connection_tcp_health(connection_t *c, bool sample_window) {
	if(!c) {
		return;
	}

	mp_tcp_diag_t td;

	if(!query_connection_tcp_diag(c, &td)) {
		(void)sample_window;
		return;
	}

	c->tcp_diag_at = now.tv_sec;

	if(td.min_rtt_us > 0) {
		c->tcp_min_rtt_us = td.min_rtt_us;
	}

	c->tcp_rtt_us = td.rtt_us;
	c->tcp_cwnd = td.snd_cwnd;
	c->tcp_pacing_bps = td.pacing_bps;
	c->tcp_segs_out = td.segs_out;
	c->tcp_total_retrans = td.total_retrans;

	bool standalone_policed = connection_check_policed(c, 0);

	if(!sample_window) {
		return;
	}

	bool win_policed = false;
	bool win_healthy_fast = false;

	if(c->tcp_prev_segs_out > 0 && td.segs_out >= c->tcp_prev_segs_out &&
	                td.total_retrans >= c->tcp_prev_retrans) {
		uint32_t d_segs = td.segs_out - c->tcp_prev_segs_out;
		uint32_t d_ret = td.total_retrans - c->tcp_prev_retrans;
		uint64_t cap_bps = (uint64_t)c->applied_pacing_rate * 8ULL;

		if(cap_bps > 0) {
			uint64_t bad_pacing_ceil = cap_bps / 2ULL < 8000000ULL ? cap_bps / 2ULL : 8000000ULL;
			win_policed = (d_segs >= 40 && (uint64_t)d_ret * 10ULL > (uint64_t)d_segs &&
			               td.snd_cwnd > 0 && td.snd_cwnd <= 32 &&
			               td.pacing_bps > 0 && td.pacing_bps < bad_pacing_ceil);
			win_healthy_fast = (d_segs >= 50 && (uint64_t)d_ret * 12ULL <= (uint64_t)d_segs &&
			                    td.snd_cwnd >= 28 && td.pacing_bps * 4ULL >= cap_bps * 3ULL);
		} else {
			win_policed = (d_segs >= 40 && (uint64_t)d_ret * 16ULL > (uint64_t)d_segs &&
			               td.snd_cwnd > 0 && td.snd_cwnd <= 40 &&
			               td.pacing_bps > 0 && td.pacing_bps < 8000000ULL);
			win_healthy_fast = (d_segs >= 50 && (uint64_t)d_ret * 50ULL <= (uint64_t)d_segs &&
			                    td.snd_cwnd >= 80 && td.pacing_bps >= 15000000ULL);
		}
	}

	c->tcp_prev_segs_out = td.segs_out;
	c->tcp_prev_retrans = td.total_retrans;

	if(win_policed) {
		if(c->tcp_bad_windows < 10) {
			c->tcp_bad_windows++;
		}

		if(c->tcp_bad_windows >= 2) {
			bool newly = !c->tcp_degraded;
			c->tcp_degraded = true;

			if(newly) {
				multipath_handle_conn_degraded(c->node, c);
			}
		}
	} else if(!standalone_policed &&
	                (win_healthy_fast || (td.snd_cwnd >= 100 && td.pacing_bps >= 20000000ULL))) {
		c->tcp_bad_windows = 0;
		c->tcp_degraded = false;
	}
}

static void refresh_connection_tcp_min_rtt(connection_t *c) {
	refresh_connection_tcp_health(c, false);
}

static bool connection_is_wan_degraded(connection_t *c, uint32_t best_rtt, uint64_t best_pacing_bps, uint32_t rtt_tol_us) {
	if(!c || connection_is_loopback(c) || best_rtt < 1000 || best_rtt == UINT32_MAX) {
		return false;
	}

	(void)connection_check_policed(c, best_pacing_bps);

	uint32_t eff_tol = (best_rtt < 10000 && rtt_tol_us > 15000) ? 15000 : rtt_tol_us;

	if(connection_has_wan_rtt(c) && c->tcp_min_rtt_us > best_rtt + eff_tol &&
	                (uint64_t)c->tcp_min_rtt_us * 2ULL > (uint64_t)best_rtt * 3ULL) {
		return true;
	}

	size_t qbytes = (c->outbuf.len > c->outbuf.offset ? c->outbuf.len - c->outbuf.offset : 0) + c->transport_outbuf_len;

	if(qbytes > 2097152 && c->tcp_rtt_us > best_rtt * 4 && c->tcp_rtt_us > best_rtt + 150000) {
		c->tcp_degraded = true;
	}

	return c->tcp_degraded;
}

#ifdef HAVE_LINUX
static int netlink_fd = -1;
static io_t netlink_io;
#endif

#if defined(__ANDROID__) || defined(HAVE_ANDROID)
typedef int (*android_setsocknetwork_fn)(uint64_t network, int fd);
static android_setsocknetwork_fn p_android_setsocknetwork = NULL;
static bool android_sym_resolved = false;

static android_setsocknetwork_fn resolve_android_setsocknetwork(void) {
	if(!android_sym_resolved) {
		android_sym_resolved = true;
		void *lib = dlopen("libandroid.so", RTLD_LAZY | RTLD_LOCAL);

		if(lib) {
			p_android_setsocknetwork = (android_setsocknetwork_fn)dlsym(lib, "android_setsocknetwork");
		}
	}

	return p_android_setsocknetwork;
}
#endif

const char *multipath_mode_name(multipath_mode_t mode) {
	switch(mode) {
	case MULTIPATH_OFF:
		return "off";

	case MULTIPATH_FAILOVER:
		return "failover";

	case MULTIPATH_FLOWHASH:
		return "flowhash";

	case MULTIPATH_REDUNDANT:
		return "redundant";

	case MULTIPATH_SPLIT:
		return "split";

	default:
		return "failover";
	}
}

bool multipath_parse_mode(const char *str, multipath_mode_t *out) {
	if(!str || !out) {
		return false;
	}

	if(!strcasecmp(str, "off") || !strcasecmp(str, "no") || !strcasecmp(str, "false") || !strcmp(str, "0")) {
		*out = MULTIPATH_OFF;
		return true;
	}

	if(!strcasecmp(str, "failover") || !strcasecmp(str, "backup") || !strcasecmp(str, "auto")) {
		*out = MULTIPATH_FAILOVER;
		return true;
	}

	if(!strcasecmp(str, "flowhash") || !strcasecmp(str, "ecmp") || !strcasecmp(str, "hash") || !strcasecmp(str, "stripe")) {
		*out = MULTIPATH_FLOWHASH;
		return true;
	}

	if(!strcasecmp(str, "redundant") || !strcasecmp(str, "dup") || !strcasecmp(str, "duplicate")) {
		*out = MULTIPATH_REDUNDANT;
		return true;
	}

	if(!strcasecmp(str, "split") || !strcasecmp(str, "strip") || !strcasecmp(str, "stealth") || !strcasecmp(str, "burst")) {
		*out = MULTIPATH_SPLIT;
		return true;
	}

	return false;
}

/* ---- Dedicated per-uplink UDP sockets ------------------------------------ */

static void handle_uplink_udp_v4(void *data, int flags) {
	(void)flags;
	int idx = (int)(intptr_t)data;

	if(idx < 0 || idx >= MAX_UPLINKS || !multipath_uplinks[idx].in_use || multipath_uplinks[idx].udp_fd_v4 < 0) {
		return;
	}

	vpn_packet_t pkt;

	quic_batch_begin();

	for(int batch = 0; batch < 64; batch++) {
		if(!multipath_uplinks[idx].in_use || multipath_uplinks[idx].udp_fd_v4 < 0) {
			break;
		}

		sockaddr_t addr = {0};
		socklen_t addrlen = sizeof(addr);
		pkt.offset = 0;

		ssize_t len = recvfrom(multipath_uplinks[idx].udp_fd_v4, (void *)DATA(&pkt), MAXSIZE, 0, &addr.sa, &addrlen);

		if(len <= 0 || (size_t)len > MAXSIZE) {
			if(len < 0 && !sockwouldblock(sockerrno)) {
				logger(DEBUG_TRAFFIC, LOG_WARNING, "multipath: recvfrom IPv4 on uplink %s failed: %s",
				       multipath_uplinks[idx].name, sockstrerror(sockerrno));
			}

			break;
		}

		pkt.len = (size_t)len;
		multipath_uplinks[idx].rx_packets++;
		multipath_uplinks[idx].rx_bytes += (uint64_t)len;

		listen_socket_t u_ls;
		memset(&u_ls, 0, sizeof(u_ls));
		u_ls.sa.sa.sa_family = AF_INET;
		u_ls.tcp.fd = -1;

		for(int i = 0; i < listen_sockets; i++) {
			if(listen_socket[i].sa.sa.sa_family == AF_INET) {
				u_ls = listen_socket[i];
				break;
			}
		}

		u_ls.udp.fd = multipath_uplinks[idx].udp_fd_v4;
		handle_incoming_vpn_packet_uplink(idx, &u_ls, &pkt, &addr);
	}

	quic_batch_end();
}

static void handle_uplink_udp_v6(void *data, int flags) {
	(void)flags;
	int idx = (int)(intptr_t)data;

	if(idx < 0 || idx >= MAX_UPLINKS || !multipath_uplinks[idx].in_use || multipath_uplinks[idx].udp_fd_v6 < 0) {
		return;
	}

	vpn_packet_t pkt;

	quic_batch_begin();

	for(int batch = 0; batch < 64; batch++) {
		if(!multipath_uplinks[idx].in_use || multipath_uplinks[idx].udp_fd_v6 < 0) {
			break;
		}

		sockaddr_t addr = {0};
		socklen_t addrlen = sizeof(addr);
		pkt.offset = 0;

		ssize_t len = recvfrom(multipath_uplinks[idx].udp_fd_v6, (void *)DATA(&pkt), MAXSIZE, 0, &addr.sa, &addrlen);

		if(len <= 0 || (size_t)len > MAXSIZE) {
			if(len < 0 && !sockwouldblock(sockerrno)) {
				logger(DEBUG_TRAFFIC, LOG_WARNING, "multipath: recvfrom IPv6 on uplink %s failed: %s",
				       multipath_uplinks[idx].name, sockstrerror(sockerrno));
			}

			break;
		}

		pkt.len = (size_t)len;
		multipath_uplinks[idx].rx_packets++;
		multipath_uplinks[idx].rx_bytes += (uint64_t)len;

		listen_socket_t u_ls;
		memset(&u_ls, 0, sizeof(u_ls));
		u_ls.sa.sa.sa_family = AF_INET6;
		u_ls.tcp.fd = -1;

		for(int i = 0; i < listen_sockets; i++) {
			if(listen_socket[i].sa.sa.sa_family == AF_INET6) {
				u_ls = listen_socket[i];
				break;
			}
		}

		u_ls.udp.fd = multipath_uplinks[idx].udp_fd_v6;
		handle_incoming_vpn_packet_uplink(idx, &u_ls, &pkt, &addr);
	}

	quic_batch_end();
}

static void close_uplink_sockets(multipath_uplink_t *u) {
	if(u->udp_fd_v4 >= 0) {
		if(u->io_v4.cb) {
			io_del(&u->io_v4);
		}

		closesocket(u->udp_fd_v4);
		u->udp_fd_v4 = -1;
	}

	if(u->udp_fd_v6 >= 0) {
		if(u->io_v6.cb) {
			io_del(&u->io_v6);
		}

		closesocket(u->udp_fd_v6);
		u->udp_fd_v6 = -1;
	}
}

static void set_uplink_udp_buffer(int fd, int optname, int size) {
	if(size <= 0) {
		return;
	}

#if defined(SOL_SOCKET) && defined(SO_RCVBUFFORCE) && defined(SO_SNDBUFFORCE)
	int force_opt = (optname == SO_RCVBUF) ? SO_RCVBUFFORCE : ((optname == SO_SNDBUF) ? SO_SNDBUFFORCE : 0);

	if(force_opt && !setsockopt(fd, SOL_SOCKET, force_opt, (const void *)&size, sizeof(size))) {
		return;
	}
#endif

	setsockopt(fd, SOL_SOCKET, optname, (const void *)&size, sizeof(size));
}

static int open_uplink_udp_socket(int idx, int af) {
	int fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);

	if(fd < 0) {
		return -1;
	}

#ifdef FD_CLOEXEC
	fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif

#ifdef O_NONBLOCK
	{
		int flags = fcntl(fd, F_GETFL);

		if(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
			closesocket(fd);
			return -1;
		}
	}
#elif defined(HAVE_WINDOWS) || defined(WIN32)
	{
		unsigned long arg = 1;

		if(ioctlsocket(fd, FIONBIO, &arg) != 0) {
			closesocket(fd);
			return -1;
		}

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
		BOOL new_behavior = FALSE;
		DWORD bytes_returned = 0;
		WSAIoctl(fd, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior), NULL, 0, &bytes_returned, NULL, NULL);
	}
#endif

	int bcast = 1;
	setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (const void *)&bcast, sizeof(bcast));
	set_uplink_udp_buffer(fd, SO_RCVBUF, udp_rcvbuf);
	set_uplink_udp_buffer(fd, SO_SNDBUF, udp_sndbuf);

#if defined(IPV6_V6ONLY)
	if(af == AF_INET6) {
		int option = 1;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *)&option, sizeof(option));
	}
#endif

	if(myself && (myself->options & OPTION_PMTU_DISCOVERY)) {
		if(af == AF_INET) {
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
			int pmtu = IP_PMTUDISC_DO;
			setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, (const void *)&pmtu, sizeof(pmtu));
#elif defined(IP_DONTFRAGMENT)
			int df = 1;
			setsockopt(fd, IPPROTO_IP, IP_DONTFRAGMENT, (const void *)&df, sizeof(df));
#elif defined(IP_DONTFRAG)
			int df = 1;
			setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, (const void *)&df, sizeof(df));
#endif
		} else if(af == AF_INET6) {
#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
			int pmtu6 = IPV6_PMTUDISC_DO;
			setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, (const void *)&pmtu6, sizeof(pmtu6));
#elif defined(IPV6_DONTFRAG)
			int df6 = 1;
			setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, (const void *)&df6, sizeof(df6));
#endif
		}
	}

	if(!multipath_bind_socket(fd, af, idx)) {
		closesocket(fd);
		return -1;
	}

	/* If multipath_bind_socket did not bind a specific local IP, bind ephemeral port */
	multipath_uplink_t *u = &multipath_uplinks[idx];

	if((af == AF_INET && !u->have_v4) || (af == AF_INET6 && !u->have_v6)) {
		sockaddr_t any = {0};

		if(af == AF_INET) {
			any.in.sin_family = AF_INET;
			any.in.sin_addr.s_addr = INADDR_ANY;
			any.in.sin_port = 0;
		} else {
			any.in6.sin6_family = AF_INET6;
			any.in6.sin6_port = 0;
		}

		if(bind(fd, &any.sa, SALEN(any.sa)) < 0) {
			closesocket(fd);
			return -1;
		}
	}

	return fd;
}

static void ensure_uplink_sockets(int idx) {
	if(!multipath_initialized || idx < 0 || idx >= MAX_UPLINKS) {
		return;
	}

	multipath_uplink_t *u = &multipath_uplinks[idx];

	if(!u->in_use || !u->is_up) {
		close_uplink_sockets(u);
		return;
	}

	if(u->udp_fd_v4 < 0 && (!u->have_v6 || u->have_v4)) {
		u->udp_fd_v4 = open_uplink_udp_socket(idx, AF_INET);

		if(u->udp_fd_v4 >= 0) {
			io_add(&u->io_v4, handle_uplink_udp_v4, (void *)(intptr_t)idx, u->udp_fd_v4, IO_READ);
		}
	}

	if(u->udp_fd_v6 < 0 && u->have_v6) {
		u->udp_fd_v6 = open_uplink_udp_socket(idx, AF_INET6);

		if(u->udp_fd_v6 >= 0) {
			io_add(&u->io_v6, handle_uplink_udp_v6, (void *)(intptr_t)idx, u->udp_fd_v6, IO_READ);
		}
	}
}

/* ---- Cross-Platform Socket Binding --------------------------------------- */

bool multipath_bind_socket(int fd, int af, int uplink_idx) {
	if(fd < 0 || uplink_idx < 0 || uplink_idx >= MAX_UPLINKS) {
		return true;
	}

	multipath_uplink_t *u = &multipath_uplinks[uplink_idx];

	if(!u->in_use) {
		return true;
	}

#if defined(__ANDROID__) || defined(HAVE_ANDROID)
	if(u->net_handle != 0) {
		android_setsocknetwork_fn fn = resolve_android_setsocknetwork();

		if(!fn) {
			logger(DEBUG_CONNECTIONS, LOG_WARNING,
			       "multipath: android_setsocknetwork unavailable on %s (handle=%"PRIu64")",
			       u->name, u->net_handle);
			return false;
		}

		if(fn(u->net_handle, fd) != 0) {
			logger(DEBUG_CONNECTIONS, LOG_WARNING,
			       "multipath: android_setsocknetwork(%"PRIu64") on %s failed: %s",
			       u->net_handle, u->name, strerror(errno));
			return false;
		}
	}
#endif

#if defined(SO_MARK)
	if(u->fwmark != 0) {
		if(setsockopt(fd, SOL_SOCKET, SO_MARK, (const void *)&u->fwmark, sizeof(u->fwmark)) < 0) {
			logger(DEBUG_CONNECTIONS, LOG_WARNING,
			       "multipath: SO_MARK(%d) on uplink %s failed: %s",
			       u->fwmark, u->name, sockstrerror(sockerrno));
		}
	}
#endif

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	/* Bind to interface name if it does not look like a numeric IP literal */
	if(u->name[0] && !strchr(u->name, '.') && !strchr(u->name, ':')) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, u->name, IFNAMSIZ - 1);

		if(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (const void *)&ifr, sizeof(ifr)) < 0) {
			/* On Android unprivileged VPN sockets or inside restricted containers,
			   SO_BINDTODEVICE may return EPERM if net_handle or source IP is used instead. */
			logger(DEBUG_CONNECTIONS, LOG_DEBUG,
			       "multipath: SO_BINDTODEVICE(%s) skipped: %s",
			       u->name, sockstrerror(sockerrno));
		}
	}
#endif

#ifdef HAVE_WINDOWS
	if(u->ifindex > 0) {
		if(af == AF_INET) {
			DWORD idx_net = htonl(u->ifindex);
			setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, (const char *)&idx_net, sizeof(idx_net));
		} else if(af == AF_INET6) {
			DWORD idx_host = u->ifindex;
			setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, (const char *)&idx_host, sizeof(idx_host));
		}
	}
#endif

	if(af == AF_INET && u->have_v4) {
		sockaddr_t bind_sa = u->local_v4;
		bind_sa.in.sin_port = 0;

		if(bind(fd, &bind_sa.sa, SALEN(bind_sa.sa)) < 0) {
			logger(DEBUG_CONNECTIONS, LOG_WARNING,
			       "multipath: bind IPv4 on uplink %s failed: %s",
			       u->name, sockstrerror(sockerrno));
			return false;
		}
	} else if(af == AF_INET6 && u->have_v6) {
		sockaddr_t bind_sa = u->local_v6;
		bind_sa.in6.sin6_port = 0;

		if(bind(fd, &bind_sa.sa, SALEN(bind_sa.sa)) < 0) {
			logger(DEBUG_CONNECTIONS, LOG_WARNING,
			       "multipath: bind IPv6 on uplink %s failed: %s",
			       u->name, sockstrerror(sockerrno));
			return false;
		}
	}

	return true;
}

int multipath_get_udp_fd(int uplink_idx, int af, int fallback_sock_idx) {
	if(uplink_idx >= 0 && uplink_idx < MAX_UPLINKS && multipath_uplinks[uplink_idx].in_use && multipath_uplinks[uplink_idx].is_up) {
		ensure_uplink_sockets(uplink_idx);

		if(af == AF_INET && multipath_uplinks[uplink_idx].udp_fd_v4 >= 0) {
			return multipath_uplinks[uplink_idx].udp_fd_v4;
		}

		if(af == AF_INET6) {
			if(multipath_uplinks[uplink_idx].udp_fd_v6 < 0 && multipath_initialized &&
			                (!multipath_uplinks[uplink_idx].have_v4 || multipath_uplinks[uplink_idx].have_v6)) {
				multipath_uplinks[uplink_idx].udp_fd_v6 = open_uplink_udp_socket(uplink_idx, AF_INET6);

				if(multipath_uplinks[uplink_idx].udp_fd_v6 >= 0) {
					io_add(&multipath_uplinks[uplink_idx].io_v6, handle_uplink_udp_v6,
					       (void *)(intptr_t)uplink_idx, multipath_uplinks[uplink_idx].udp_fd_v6, IO_READ);
				}
			}

			if(multipath_uplinks[uplink_idx].udp_fd_v6 >= 0) {
				return multipath_uplinks[uplink_idx].udp_fd_v6;
			}
		}
	}

	if(fallback_sock_idx < 0) {
		return -1;
	}

	if(fallback_sock_idx < listen_sockets) {
		return listen_socket[fallback_sock_idx].udp.fd;
	}

	for(int i = 0; i < listen_sockets; i++) {
		if(listen_socket[i].sa.sa.sa_family == af) {
			return listen_socket[i].udp.fd;
		}
	}

	return listen_sockets > 0 ? listen_socket[0].udp.fd : -1;
}

bool multipath_owns_udp_fd(int fd) {
	if(fd < 0) {
		return false;
	}

	for(int i = 0; i < MAX_UPLINKS; i++) {
		if(multipath_uplinks[i].in_use &&
		                (multipath_uplinks[i].udp_fd_v4 == fd || multipath_uplinks[i].udp_fd_v6 == fd)) {
			return true;
		}
	}

	return false;
}

bool multipath_uplink_is_healthy(int uplink_idx) {
	if(uplink_idx < 0 || uplink_idx >= MAX_UPLINKS) {
		return true;
	}

	return multipath_uplinks[uplink_idx].in_use && multipath_uplinks[uplink_idx].is_up;
}

/* ---- Uplink Registry Management ------------------------------------------ */

static void parse_ip_into_uplink(multipath_uplink_t *u, const char *ip_str) {
	if(!ip_str || !*ip_str || !strcmp(ip_str, "-") || !strcmp(ip_str, "auto")) {
		return;
	}

	struct in_addr v4;
	struct in6_addr v6;

	if(inet_pton(AF_INET, ip_str, &v4) == 1) {
		memset(&u->local_v4, 0, sizeof(u->local_v4));
		u->local_v4.in.sin_family = AF_INET;
		u->local_v4.in.sin_addr = v4;
		u->have_v4 = true;
	} else if(inet_pton(AF_INET6, ip_str, &v6) == 1) {
		memset(&u->local_v6, 0, sizeof(u->local_v6));
		u->local_v6.in6.sin6_family = AF_INET6;
		u->local_v6.in6.sin6_addr = v6;
		u->have_v6 = true;
	}
}

int multipath_upsert_uplink(const char *name, const char *local_ip, int weight,
                            bool is_backup, int mark, uint64_t net_handle, bool is_up) {
	if(!name || !*name) {
		return -1;
	}

	int slot = -1;

	for(int i = 0; i < MAX_UPLINKS; i++) {
		if(multipath_uplinks[i].in_use && !strcasecmp(multipath_uplinks[i].name, name)) {
			slot = i;
			break;
		}

		if(!multipath_uplinks[i].in_use && slot < 0) {
			slot = i;
		}
	}

	if(slot < 0) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "multipath: MAX_UPLINKS (%d) reached, cannot add %s", MAX_UPLINKS, name);
		return -1;
	}

	multipath_uplink_t *u = &multipath_uplinks[slot];
	bool was_in_use = u->in_use;
	bool old_up = u->is_up;

	if(!was_in_use) {
		memset(u, 0, sizeof(*u));
		u->udp_fd_v4 = -1;
		u->udp_fd_v6 = -1;
		strncpy(u->name, name, sizeof(u->name) - 1);
		u->in_use = true;
		multipath_uplink_count++;
	} else {
		/* Re-bind UDP sockets if IP or state changed */
		close_uplink_sockets(u);
	}

	u->weight = weight > 0 ? CLAMP(weight, 1, 100) : 100;
	u->is_backup = is_backup;
	u->fwmark = mark;
	u->net_handle = net_handle;
	u->is_up = is_up;

#if defined(HAVE_NET_IF_H) && !defined(HAVE_WINDOWS)
	u->ifindex = if_nametoindex(u->name);
#endif

	/* Reset cached local source IPs before re-parsing name / local_ip */
	u->have_v4 = false;
	u->have_v6 = false;
	memset(&u->local_v4, 0, sizeof(u->local_v4));
	memset(&u->local_v6, 0, sizeof(u->local_v6));

	/* If name itself is an IP literal, parse it as local_ip as well */
	parse_ip_into_uplink(u, name);

	if(local_ip && *local_ip) {
		parse_ip_into_uplink(u, local_ip);
	}

	ensure_uplink_sockets(slot);

	logger(DEBUG_CONNECTIONS, LOG_INFO,
	       "multipath: uplink[%d] '%s' (%s, weight=%d, mark=0x%x, handle=%"PRIu64") is %s",
	       slot, u->name, u->is_backup ? "backup" : "primary", u->weight,
	       u->fwmark, u->net_handle, u->is_up ? "UP" : "DOWN");

	if(multipath_initialized && (!was_in_use || old_up != is_up)) {
		multipath_maintain();
	}

	return slot;
}

bool multipath_remove_uplink(const char *name) {
	if(!name || !*name) {
		return false;
	}

	for(int i = 0; i < MAX_UPLINKS; i++) {
		if(multipath_uplinks[i].in_use && !strcasecmp(multipath_uplinks[i].name, name)) {
			close_uplink_sockets(&multipath_uplinks[i]);
			memset(&multipath_uplinks[i], 0, sizeof(multipath_uplinks[i]));
			multipath_uplinks[i].udp_fd_v4 = -1;
			multipath_uplinks[i].udp_fd_v6 = -1;

			if(multipath_uplink_count > 0) {
				multipath_uplink_count--;
			}

			for splay_each(node_t, n, &node_tree) {
				for(int j = 0; j < MAX_NODE_PATHS; j++) {
					if(n->paths[j].uplink_idx == i) {
						n->paths[j].active = false;
						n->paths[j].confirmed = false;
					}
				}
			}

			/* Close any connections still bound to this removed uplink */
			bool found_dead;

			do {
				found_dead = false;

				for list_each(connection_t, c, &connection_list) {
					if(!c->status.control && c->uplink_idx == i) {
						terminate_connection(c, c->edge);
						found_dead = true;
						break;
					}
				}
			} while(found_dead);

			if(multipath_initialized) {
				multipath_maintain();
			}

			return true;
		}
	}

	return false;
}

static bool connection_is_dialling_node(const connection_t *c, const node_t *n) {
	if(!c || !n || c->status.control || c->status.web_front || c->status.active) {
		return false;
	}

	return (c->node == n) || (c->name && !strcmp(c->name, n->name));
}

/* Pick the best uplink for a new outgoing connection to node `n` so parallel
   connections spread across distinct active uplinks. */
int multipath_pick_next_uplink(const node_t *n) {
	if(multipath_uplink_count <= 0) {
		return -1;
	}

	int best_idx = -1;
	int best_score = INT_MAX;

	for(int i = 0; i < MAX_UPLINKS; i++) {
		multipath_uplink_t *u = &multipath_uplinks[i];

		if(!u->in_use || !u->is_up) {
			continue;
		}

		int used = 0;

		if(n) {
			for list_each(connection_t, c, &n->connections) {
				if(c->status.active && c->uplink_idx == i) {
					used++;
				}
			}

			for list_each(connection_t, c, &connection_list) {
				if(connection_is_dialling_node(c, n) && c->uplink_idx == i) {
					used++;
				}
			}
		}

		/* Prefer unused primary uplinks (score 0), then unused backup uplinks
		   (score 1, so standby make-before-break connections are pre-warmed on
		   the backup uplink), before placing a second connection on the same
		   uplink (score >= 10). */
		int score = used * 10 + (u->is_backup ? 1 : 0);

		if(score < best_score) {
			best_score = score;
			best_idx = i;
		}
	}

	return best_idx;
}

int multipath_get_tx_uplink(const node_t *n) {
	if(multipath_mode == MULTIPATH_OFF || multipath_uplink_count <= 0) {
		return -1;
	}

	if(n && n->connection && n->connection->uplink_idx >= 0 &&
	                multipath_uplink_is_healthy(n->connection->uplink_idx)) {
		return n->connection->uplink_idx;
	}

	return multipath_pick_next_uplink(n);
}

/* ---- Configuration Parsing ----------------------------------------------- */

static void parse_multipath_interface_line(const char *val) {
	if(!val || !*val) {
		return;
	}

	char *copy = xstrdup(val);

	/* Support compact colon-delimited syntax: ifname:ip[:weight[:backup[:mark]]] */
	if(strchr(copy, ':') && !strpbrk(copy, " \t=")) {
		char *saveptr = NULL;
		char *ifname = strtok_r(copy, ":", &saveptr);
		char *ip_tok = strtok_r(NULL, ":", &saveptr);
		char *w_tok = strtok_r(NULL, ":", &saveptr);
		char *b_tok = strtok_r(NULL, ":", &saveptr);
		char *m_tok = strtok_r(NULL, ":", &saveptr);

		if(ifname && *ifname) {
			int weight = w_tok ? atoi(w_tok) : 100;
			bool is_backup = b_tok ? (!strcasecmp(b_tok, "1") || !strcasecmp(b_tok, "backup") || !strcasecmp(b_tok, "yes")) : false;
			int mark = m_tok ? (int)strtol(m_tok, NULL, 0) : 0;
			multipath_upsert_uplink(ifname, ip_tok, weight, is_backup, mark, 0, true);
		}

		free(copy);
		return;
	}

	char *saveptr = NULL;
	char *tok = strtok_r(copy, " \t,", &saveptr);

	if(!tok) {
		free(copy);
		return;
	}

	const char *ifname = tok;
	const char *local_ip = NULL;
	int weight = 100;
	bool is_backup = false;
	int mark = 0;
	uint64_t net_handle = 0;

	while((tok = strtok_r(NULL, " \t,", &saveptr)) != NULL) {
		if(!strcasecmp(tok, "backup") || !strcasecmp(tok, "standby")) {
			is_backup = true;
		} else if(!strcasecmp(tok, "primary")) {
			is_backup = false;
		} else if(!strncasecmp(tok, "weight=", 7)) {
			weight = atoi(tok + 7);
		} else if(!strncasecmp(tok, "mark=", 5)) {
			mark = (int)strtol(tok + 5, NULL, 0);
		} else if(!strncasecmp(tok, "ip=", 3)) {
			local_ip = tok + 3;
		} else if(!strncasecmp(tok, "handle=", 7)) {
			net_handle = strtoull(tok + 7, NULL, 0);
		}
	}

	multipath_upsert_uplink(ifname, local_ip, weight, is_backup, mark, net_handle, true);
	free(copy);
}

void multipath_read_config(void) {
	multipath_mode = MULTIPATH_FAILOVER;
	multipath_target_connections = 1;
	multipath_tcp_max_pacing_rate = 0;

	int pacing_Bps = 0;

	if(get_config_int(lookup_config(&config_tree, "TcpMaxPacingRate"), &pacing_Bps) && pacing_Bps > 0) {
		multipath_tcp_max_pacing_rate = (uint32_t)pacing_Bps;
	}

	multipath_tcp_auto_pacing = (multipath_tcp_max_pacing_rate == 0);
	get_config_bool(lookup_config(&config_tree, "TcpAutoPacing"), &multipath_tcp_auto_pacing);

	char *mode_str = NULL;

	if(get_config_string(lookup_config(&config_tree, "MultipathMode"), &mode_str)) {
		multipath_mode_t m;

		if(multipath_parse_mode(mode_str, &m)) {
			multipath_mode = m;
		} else {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Unknown MultipathMode '%s', defaulting to failover", mode_str);
			multipath_mode = MULTIPATH_FAILOVER;
		}

		free(mode_str);
	}

	int conns = 1;

	if(get_config_int(lookup_config(&config_tree, "MultipathConnections"), &conns)) {
		multipath_target_connections = CLAMP(conns, 1, MAX_MULTIPATH_CONNECTIONS);
	}

	for(config_t *cfg = lookup_config(&config_tree, "MultipathInterface");
	    cfg;
	    cfg = lookup_config_next(&config_tree, cfg)) {
		char *val = NULL;

		if(get_config_string(cfg, &val) && val) {
			parse_multipath_interface_line(val);
			free(val);
		}
	}

	/* If multiple uplinks were configured and MultipathConnections was not
	   explicitly set > 1, automatically allow at least 2 parallel connections
	   so make-before-break across uplinks is active out of the box. */
	if(multipath_uplink_count > 1 && multipath_target_connections < 2 && multipath_mode != MULTIPATH_OFF) {
		multipath_target_connections = MIN(multipath_uplink_count, MAX_MULTIPATH_CONNECTIONS);
	}
}

/* ---- Linux Netlink Route & Link Monitor ---------------------------------- */

#ifdef HAVE_LINUX
static void handle_netlink_event(void *data, int flags) {
	(void)data;
	(void)flags;

	if(netlink_fd < 0) {
		return;
	}

	uint8_t buf[8192];
	bool route_or_link_changed = false;

	while(true) {
		ssize_t len = recv(netlink_fd, buf, sizeof(buf), MSG_DONTWAIT);

		if(len <= 0) {
			break;
		}

		for(struct nlmsghdr *nh = (struct nlmsghdr *)buf; len >= (ssize_t)sizeof(*nh) && NLMSG_OK(nh, (size_t)len); nh = NLMSG_NEXT(nh, len)) {
			if(nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR) {
				break;
			}

			if(nh->nlmsg_type == RTM_NEWLINK || nh->nlmsg_type == RTM_DELLINK) {
				struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
				bool is_up = (nh->nlmsg_type == RTM_NEWLINK) &&
				             ((ifi->ifi_flags & IFF_UP) != 0) &&
				             ((ifi->ifi_flags & IFF_RUNNING) != 0);

				for(int i = 0; i < MAX_UPLINKS; i++) {
					multipath_uplink_t *u = &multipath_uplinks[i];

					if(!u->in_use) {
						continue;
					}

					if(u->ifindex == 0) {
						u->ifindex = if_nametoindex(u->name);
					}

					if(u->ifindex != 0 && (int)u->ifindex == ifi->ifi_index) {
						if(u->is_up != is_up) {
							u->is_up = is_up;
							route_or_link_changed = true;
							logger(DEBUG_CONNECTIONS, LOG_NOTICE,
							       "multipath: Netlink detected interface %s (idx %d) is now %s",
							       u->name, ifi->ifi_index, is_up ? "UP" : "DOWN");
							ensure_uplink_sockets(i);
						}
					}
				}
			} else if(nh->nlmsg_type == RTM_NEWROUTE || nh->nlmsg_type == RTM_DELROUTE ||
			          nh->nlmsg_type == RTM_NEWADDR || nh->nlmsg_type == RTM_DELADDR) {
				route_or_link_changed = true;
			}
		}
	}

	if(route_or_link_changed && multipath_mode != MULTIPATH_OFF) {
		for(int i = 0; i < MAX_UPLINKS; i++) {
			if(multipath_uplinks[i].in_use && multipath_uplinks[i].is_up) {
				ensure_uplink_sockets(i);
			}
		}

		multipath_maintain();
	}
}

static void init_netlink_watcher(void) {
	netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if(netlink_fd < 0) {
		return;
	}

#ifdef FD_CLOEXEC
	fcntl(netlink_fd, F_SETFD, FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
	int flags = fcntl(netlink_fd, F_GETFL);
	fcntl(netlink_fd, F_SETFL, flags | O_NONBLOCK);
#endif

	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE,
	};

	if(bind(netlink_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(netlink_fd);
		netlink_fd = -1;
		return;
	}

	io_add(&netlink_io, handle_netlink_event, NULL, netlink_fd, IO_READ);
}

static void exit_netlink_watcher(void) {
	if(netlink_fd >= 0) {
		io_del(&netlink_io);
		close(netlink_fd);
		netlink_fd = -1;
	}
}
#endif /* HAVE_LINUX */

/* ---- Adaptive Per-Node & Per-Socket TCP Pacing (SO_MAX_PACING_RATE) ------ */

uint32_t multipath_calc_socket_pacing_rate(uint32_t node_budget_Bps, int pool_conns, int active_tx_conns) {
	if(node_budget_Bps == 0) {
		return 0;
	}

	uint32_t floor_rate = node_budget_Bps / MAX_MULTIPATH_CONNECTIONS;

	if(floor_rate < 64000U) {
		floor_rate = node_budget_Bps < 64000U ? node_budget_Bps : 64000U;
	}

	if(pool_conns <= 1) {
		return node_budget_Bps;
	}

	if(active_tx_conns <= 1) {
		uint32_t single = (uint32_t)(((uint64_t)node_budget_Bps * 2ULL) / 3ULL);
		return single >= floor_rate ? single : floor_rate;
	}

	uint32_t share = node_budget_Bps / (uint32_t)active_tx_conns;
	return share >= floor_rate ? share : floor_rate;
}

static bool connection_has_tcp_socket(const connection_t *c) {
	if(!c || c->socket < 0) {
		return false;
	}

	if(c->address.sa.sa_family != AF_INET && c->address.sa.sa_family != AF_INET6) {
		return false;
	}

	if(c->transport && (c->transport->id == TRANSPORT_SF ||
	                    c->transport->id == TRANSPORT_OBFS ||
	                    c->transport->id == TRANSPORT_QUIC)) {
		return false;
	}

	return true;
}

static void apply_one_conn_pacing(connection_t *c, uint32_t target) {
	if(!c) {
		return;
	}

	c->target_pacing_rate = target;

	if(target == c->applied_pacing_rate) {
		return;
	}

	if(!connection_has_tcp_socket(c)) {
		return;
	}

#if defined(SOL_SOCKET) && defined(SO_MAX_PACING_RATE)
	uint32_t opt = target ? target : UINT32_MAX;

	if(setsockopt(c->socket, SOL_SOCKET, SO_MAX_PACING_RATE, &opt, sizeof(opt)) == 0) {
		c->applied_pacing_rate = target;
	}
#else
	c->applied_pacing_rate = target;
#endif
}

/* Ignore light background streams below MAX(budget/8, 64 KB/s) as heavy TX
   and subtract only their measured bytes from remaining pacing headroom. */

static void conn_record_tx_bytes(connection_t *c, time_t cur_sec, size_t tx_bytes) {
	if(!c || tx_bytes == 0) {
		return;
	}

	if(c->last_tx_sec != cur_sec) {
		if(!c->tcp_degraded && c->cur_tx_bytes >= 200000U) {
			if(c->cur_tx_bytes > c->peak_tx_Bps || (c->peak_tx_at > 0 && cur_sec > c->peak_tx_at + 60)) {
				c->peak_tx_Bps = c->cur_tx_bytes;
				c->peak_tx_at = c->last_tx_sec > 0 ? c->last_tx_sec : cur_sec;
			}
		}

		if(c->last_tx_sec > 0 && cur_sec > c->last_tx_sec && cur_sec - c->last_tx_sec == 1) {
			c->prev_tx_bytes = c->cur_tx_bytes;
			c->prev_tx_sec = c->last_tx_sec;
		} else {
			c->prev_tx_bytes = 0;
			c->prev_tx_sec = 0;
		}

		c->cur_tx_bytes = 0;
		c->last_tx_sec = cur_sec;
	}

	if(tx_bytes >= (size_t)UINT32_MAX || c->cur_tx_bytes > UINT32_MAX - (uint32_t)tx_bytes) {
		c->cur_tx_bytes = UINT32_MAX;
	} else {
		c->cur_tx_bytes += (uint32_t)tx_bytes;
	}

	if(!c->tcp_degraded && c->cur_tx_bytes >= 200000U && c->cur_tx_bytes > c->peak_tx_Bps) {
		c->peak_tx_Bps = c->cur_tx_bytes;
		c->peak_tx_at = cur_sec;
	}

	if(c->node && c == c->node->auto_pacing_canary && c->cur_tx_bytes >= 65536U) {
		c->node->auto_pacing_canary_tested = true;
	}
}

static uint32_t conn_recent_tx_Bps(const connection_t *c, time_t cur_sec) {
	if(!c || !c->status.active) {
		return 0;
	}

	if(c->last_tx_sec == cur_sec) {
		uint32_t prev = (c->prev_tx_sec > 0 && cur_sec > c->prev_tx_sec && cur_sec - c->prev_tx_sec == 1)
		                ? c->prev_tx_bytes
		                : 0;
		return c->cur_tx_bytes >= prev ? c->cur_tx_bytes : prev;
	}

	if(c->last_tx_sec > 0 && cur_sec > c->last_tx_sec && cur_sec - c->last_tx_sec == 1) {
		return c->cur_tx_bytes;
	}

	return 0;
}

static bool conn_is_heavy_tx(const connection_t *c, time_t cur_sec, uint32_t heavy_thresh) {
	if(!c || !c->status.active) {
		return false;
	}

	size_t qbytes = (c->outbuf.len > c->outbuf.offset ? c->outbuf.len - c->outbuf.offset : 0) +
	                c->transport_outbuf_len;

	return conn_recent_tx_Bps(c, cur_sec) >= heavy_thresh || qbytes >= 32768U;
}

static uint32_t clamp_rate_u32(uint64_t val, uint32_t lo, uint32_t hi) {
	if(val < (uint64_t)lo) {
		return lo;
	}

	if(val > (uint64_t)hi) {
		return hi;
	}

	return (uint32_t)val;
}

static uint32_t node_manual_pacing_cap(const node_t *n) {
	if(!n) {
		return multipath_tcp_max_pacing_rate;
	}

	return n->tcp_max_pacing_rate ? n->tcp_max_pacing_rate : multipath_tcp_max_pacing_rate;
}

bool multipath_node_auto_pacing_enabled(const node_t *n) {
	if(!n) {
		return multipath_tcp_auto_pacing;
	}

	if(n->tcp_auto_pacing_override > 0) {
		return true;
	}

	if(n->tcp_auto_pacing_override < 0) {
		return false;
	}

	if(n->tcp_max_pacing_rate > 0) {
		return false;
	}

	return multipath_tcp_auto_pacing;
}

bool multipath_node_has_datagram_carrier(const node_t *n) {
	if(!n) {
		return false;
	}

	if(n->connection && n->connection->transport && n->connection->transport->send_datagram) {
		return true;
	}

	for list_each(connection_t, c, &n->connections) {
		if(c && c->status.active && c->transport && c->transport->send_datagram) {
			return true;
		}
	}

	return false;
}

static uint32_t node_effective_pacing_budget(const node_t *n) {
	uint32_t manual_cap = node_manual_pacing_cap(n);
	uint32_t auto_cap = (n && multipath_node_auto_pacing_enabled(n)) ? n->auto_pacing_budget_Bps : 0;

	if(manual_cap > 0 && auto_cap > 0) {
		return manual_cap < auto_cap ? manual_cap : auto_cap;
	}

	return manual_cap ? manual_cap : auto_cap;
}

void multipath_handle_conn_degraded(node_t *n, connection_t *c) {
	if(!n || !c || c->status.control || !multipath_node_auto_pacing_enabled(n)) {
		return;
	}

	if(!connection_has_wan_rtt(c)) {
		return;
	}

	if(c->transport && (c->transport->id == TRANSPORT_SF ||
	                    c->transport->id == TRANSPORT_OBFS ||
	                    c->transport->id == TRANSPORT_QUIC)) {
		return;
	}

	time_t cur_sec = now.tv_sec > 0 ? now.tv_sec : 1;

	/* Canary leg hit the policer: do not penalize healthy sibling budget, just abort probe. */
	if(c == n->auto_pacing_canary || c->is_canary) {
		c->is_canary = false;

		if(n->auto_pacing_canary == c) {
			n->auto_pacing_canary = NULL;
		}

		n->auto_pacing_canary_started_at = 0;
		n->auto_pacing_canary_tested = false;
		n->auto_pacing_next_probe_at = cur_sec + 1200;
		logger(DEBUG_CONNECTIONS, LOG_NOTICE,
		       "multipath: TcpAutoPacing canary leg to %s hit policer -> keeping ceiling ~%.2f Mbps, cooldown 20m",
		       n->name, (double)n->auto_pacing_budget_Bps * 8.0 / 1000000.0);
		multipath_apply_node_tcp_pacing(n, NULL, 0);
		return;
	}

	/* Debounce simultaneous multi-leg loss bursts within 15s. */
	if(n->auto_pacing_last_backoff_at > 0 && cur_sec >= n->auto_pacing_last_backoff_at &&
	                cur_sec - n->auto_pacing_last_backoff_at < 15) {
		return;
	}

	uint32_t recent = conn_recent_tx_Bps(c, cur_sec);
	uint32_t trigger_rate = c->peak_tx_Bps > recent ? c->peak_tx_Bps : recent;

	if(trigger_rate < 1250000U) {
		return;
	}

	if(c->applied_pacing_rate > 0 && trigger_rate > c->applied_pacing_rate) {
		trigger_rate = c->applied_pacing_rate;
	}

	uint32_t safe_leg = (uint32_t)(((uint64_t)trigger_rate * 85ULL) / 100ULL);
	int pool_n = (int)n->connections.count;

	if(multipath_mode != MULTIPATH_OFF && multipath_target_connections > pool_n) {
		pool_n = multipath_target_connections;
	}

	uint32_t cand_budget = (pool_n <= 1)
	                       ? safe_leg
	                       : (uint32_t)(((uint64_t)safe_leg * 3ULL) / 2ULL);
	uint32_t manual_cap = node_manual_pacing_cap(n);
	uint32_t ceiling = manual_cap > 0 ? manual_cap : 250000000U;
	uint32_t floor_Bps = ceiling < 1500000U ? ceiling : 1500000U;
	cand_budget = clamp_rate_u32(cand_budget, floor_Bps, ceiling);

	if(n->auto_pacing_budget_Bps == 0 || cand_budget < n->auto_pacing_budget_Bps) {
		n->auto_pacing_policer_Bps = trigger_rate;
		n->auto_pacing_budget_Bps = cand_budget;
		n->auto_pacing_last_backoff_at = cur_sec;
		n->auto_pacing_next_probe_at = cur_sec + 900;

		if(n->auto_pacing_canary) {
			n->auto_pacing_canary->is_canary = false;
			n->auto_pacing_canary = NULL;
		}

		n->auto_pacing_canary_started_at = 0;
		n->auto_pacing_canary_tested = false;
		logger(DEBUG_CONNECTIONS, LOG_NOTICE,
		       "multipath: TcpAutoPacing %s throttled around %.2f Mbps -> backoff budget %.2f Mbps (per-leg %.2f Mbps)",
		       n->name, (double)trigger_rate * 8.0 / 1000000.0,
		       (double)cand_budget * 8.0 / 1000000.0,
		       (double)safe_leg * 8.0 / 1000000.0);
		multipath_apply_node_tcp_pacing(n, NULL, 0);
	}
}

void multipath_step_auto_pacing(node_t *n) {
	if(!n || !multipath_node_auto_pacing_enabled(n)) {
		if(n && n->auto_pacing_canary) {
			n->auto_pacing_canary->is_canary = false;
			n->auto_pacing_canary = NULL;
		}

		return;
	}

	if(n->auto_pacing_budget_Bps == 0) {
		return;
	}

	time_t cur_sec = now.tv_sec > 0 ? now.tv_sec : 1;
	uint32_t manual_cap = node_manual_pacing_cap(n);

	/* Finish active 30s canary probe if running */
	if(n->auto_pacing_canary) {
		connection_t *can = n->auto_pacing_canary;
		bool still_live = false;

		for list_each(connection_t, item, &n->connections) {
			if(item == can && item->status.active) {
				still_live = true;
				break;
			}
		}

		if(!still_live) {
			can->is_canary = false;
			n->auto_pacing_canary = NULL;
			n->auto_pacing_canary_started_at = 0;
			n->auto_pacing_canary_tested = false;
			n->auto_pacing_next_probe_at = cur_sec + 300;
			return;
		}

		if(can->tcp_degraded) {
			multipath_handle_conn_degraded(n, can);
			return;
		}

		if(cur_sec >= n->auto_pacing_canary_started_at + 30) {
			uint32_t min_load = n->auto_pacing_budget_Bps / 16U;

			if(min_load < 65536U) {
				min_load = 65536U;
			}

			if(conn_recent_tx_Bps(can, cur_sec) >= min_load || can->peak_tx_at >= n->auto_pacing_canary_started_at) {
				n->auto_pacing_canary_tested = true;
			}

			can->is_canary = false;
			n->auto_pacing_canary = NULL;
			n->auto_pacing_canary_started_at = 0;

			if(n->auto_pacing_canary_tested) {
				uint64_t next_b = ((uint64_t)n->auto_pacing_budget_Bps * 110ULL) / 100ULL;

				if(manual_cap > 0 && next_b >= manual_cap) {
					n->auto_pacing_budget_Bps = manual_cap;
					n->auto_pacing_next_probe_at = 0;
				} else if(manual_cap == 0 && n->auto_pacing_policer_Bps > 0 &&
				                next_b > (uint64_t)n->auto_pacing_policer_Bps * 3ULL) {
					n->auto_pacing_budget_Bps = 0;
					n->auto_pacing_policer_Bps = 0;
					n->auto_pacing_next_probe_at = 0;
				} else {
					n->auto_pacing_budget_Bps = (uint32_t)(next_b < 250000000ULL ? next_b : 250000000ULL);
					n->auto_pacing_next_probe_at = cur_sec + 900;
				}

				logger(DEBUG_CONNECTIONS, LOG_INFO,
				       "multipath: TcpAutoPacing canary to %s passed -> raised budget to %.2f Mbps",
				       n->name, (double)n->auto_pacing_budget_Bps * 8.0 / 1000000.0);
			} else {
				/* Link was idle during canary window; retry in 5 min instead of promoting blindly. */
				n->auto_pacing_next_probe_at = cur_sec + 300;
			}

			n->auto_pacing_canary_tested = false;
			multipath_apply_node_tcp_pacing(n, NULL, 0);
		}

		return;
	}

	/* Trigger new +10% canary probe on ONE secondary TCP leg */
	if(n->auto_pacing_next_probe_at > 0 && cur_sec >= n->auto_pacing_next_probe_at &&
	                (manual_cap == 0 || n->auto_pacing_budget_Bps < manual_cap)) {
		connection_t *cand = NULL;

		for list_each(connection_t, c, &n->connections) {
			if(c != n->connection && c->status.active && !c->tcp_degraded &&
			                multipath_uplink_is_healthy(c->uplink_idx) &&
			                (!c->transport || (c->transport->id != TRANSPORT_QUIC &&
			                                   c->transport->id != TRANSPORT_OBFS &&
			                                   c->transport->id != TRANSPORT_SF))) {
				cand = c;
				break;
			}
		}

		if(cand) {
			cand->is_canary = true;
			n->auto_pacing_canary = cand;
			n->auto_pacing_canary_started_at = cur_sec;
			n->auto_pacing_canary_tested = false;
			multipath_apply_node_tcp_pacing(n, NULL, 0);
		} else {
			n->auto_pacing_next_probe_at = cur_sec + 300;
		}
	}
}

void multipath_apply_node_tcp_pacing(node_t *n, connection_t *tx_conn, size_t tx_bytes) {
	if(!n) {
		return;
	}

	uint32_t budget = node_effective_pacing_budget(n);
	uint32_t manual_cap = node_manual_pacing_cap(n);
	time_t cur_sec = now.tv_sec > 0 ? now.tv_sec : 1;

	if(tx_conn && tx_bytes > 0) {
		conn_record_tx_bytes(tx_conn, cur_sec, tx_bytes);
	}

	if(budget == 0) {
		if(tx_conn && tx_conn->applied_pacing_rate == 0 && tx_conn->target_pacing_rate == 0) {
			return;
		}

		bool saw_p = false;

		for list_each(connection_t, c, &n->connections) {
			if(c == n->connection) {
				saw_p = true;
			}

			apply_one_conn_pacing(c, 0);
		}

		if(n->connection && !saw_p) {
			apply_one_conn_pacing(n->connection, 0);
		}

		return;
	}

	uint32_t floor_rate = budget / MAX_MULTIPATH_CONNECTIONS;

	if(floor_rate < 64000U) {
		floor_rate = budget < 64000U ? budget : 64000U;
	}

	uint32_t heavy_thresh = budget / 8U;

	if(heavy_thresh < 65536U) {
		heavy_thresh = 65536U;
	}

	int pool_conns = 0;
	int heavy_cnt = 0;
	uint64_t light_used = 0;
	bool saw_primary = false;

	for list_each(connection_t, c, &n->connections) {
		if(c == n->connection) {
			saw_primary = true;
		}

		if(!c->status.active) {
			continue;
		}

		pool_conns++;

		if(conn_is_heavy_tx(c, cur_sec, heavy_thresh)) {
			heavy_cnt++;

			if(c == n->auto_pacing_canary) {
				n->auto_pacing_canary_tested = true;
			}
		} else {
			light_used += conn_recent_tx_Bps(c, cur_sec);
		}
	}

	if(n->connection && !saw_primary && n->connection->status.active) {
		pool_conns++;

		if(conn_is_heavy_tx(n->connection, cur_sec, heavy_thresh)) {
			heavy_cnt++;
		} else {
			light_used += conn_recent_tx_Bps(n->connection, cur_sec);
		}
	}

	int effective_pool = (multipath_mode != MULTIPATH_OFF && multipath_target_connections > pool_conns)
	                     ? multipath_target_connections
	                     : pool_conns;
	uint32_t single_cap = (effective_pool <= 1)
	                      ? budget
	                      : clamp_rate_u32(((uint64_t)budget * 2ULL) / 3ULL, floor_rate, budget);

	uint32_t heavy_target = single_cap;
	uint32_t light_target = single_cap;

	if(heavy_cnt >= 1) {
		int denom_pool = effective_pool > heavy_cnt ? effective_pool : heavy_cnt;
		uint64_t min_heavy_pool = ((uint64_t)budget * (uint64_t)heavy_cnt) / (uint64_t)denom_pool;
		uint64_t rem_pool = (uint64_t)budget > light_used ? ((uint64_t)budget - light_used) : 0ULL;
		uint64_t heavy_pool = rem_pool >= min_heavy_pool ? rem_pool : min_heavy_pool;
		heavy_target = clamp_rate_u32(heavy_pool / (uint64_t)heavy_cnt, floor_rate, single_cap);

		uint32_t denom = (uint32_t)(heavy_cnt < 2 ? 3 : (heavy_cnt + 1));
		light_target = clamp_rate_u32((uint64_t)budget / (uint64_t)denom, floor_rate, single_cap);
	}

	for list_each(connection_t, c, &n->connections) {
		uint32_t t = conn_is_heavy_tx(c, cur_sec, heavy_thresh) ? heavy_target : light_target;

		if(c == n->auto_pacing_canary && c->is_canary) {
			uint32_t hard_hi = manual_cap > 0 ? manual_cap : 250000000U;
			t = clamp_rate_u32(((uint64_t)t * 110ULL) / 100ULL, floor_rate, hard_hi);
		}

		apply_one_conn_pacing(c, t);
	}

	if(n->connection && !saw_primary) {
		uint32_t t = conn_is_heavy_tx(n->connection, cur_sec, heavy_thresh) ? heavy_target : light_target;
		apply_one_conn_pacing(n->connection, t);
	}
}

/* ---- Multi-Connection Pool & Make-Before-Break Failover ------------------ */

void multipath_node_add_connection(node_t *n, connection_t *c) {
	if(!n || !c) {
		return;
	}

	bool used[MAX_MULTIPATH_CONNECTIONS];
	memset(used, 0, sizeof(used));

	for list_each(connection_t, existing, &n->connections) {
		if(existing == c) {
			return;
		}

		if(existing->relay_slot < MAX_MULTIPATH_CONNECTIONS) {
			used[existing->relay_slot] = true;
		}
	}

	uint32_t chosen_slot = MAX_MULTIPATH_CONNECTIONS;

	for(uint32_t s = 0; s < MAX_MULTIPATH_CONNECTIONS; s++) {
		if(!used[s]) {
			chosen_slot = s;
			break;
		}
	}

	if(chosen_slot >= MAX_MULTIPATH_CONNECTIONS) {
		chosen_slot = (n->next_relay_slot++) % MAX_MULTIPATH_CONNECTIONS;
	}

	c->relay_slot = chosen_slot;

	uint8_t needed_hwm = (uint8_t)((chosen_slot % MAX_MULTIPATH_CONNECTIONS) + 1);

	if(needed_hwm > n->mp_slot_hwm) {
		n->mp_slot_hwm = needed_hwm;
	}

	list_insert_tail(&n->connections, c);
	multipath_apply_node_tcp_pacing(n, NULL, 0);
}

void multipath_node_del_connection(node_t *n, connection_t *c) {
	if(!n || !c) {
		return;
	}

	if(n->auto_pacing_canary == c) {
		n->auto_pacing_canary = NULL;
	}

	c->is_canary = false;

	list_delete(&n->connections, c);

	if(n->connections.count == 0) {
		n->mp_slot_hwm = 0;
		n->next_relay_slot = 0;
	}
}

void multipath_record_dial_result(node_t *n, connection_t *c, bool ok) {
	if(!n || !c || !c->transport) {
		return;
	}

	transport_id_t id = c->transport->id;

	if(id >= TRANSPORT_TEST) {
		return;
	}

	if(ok) {
		n->mp_carrier_failures[id] = 0;
		n->mp_carrier_backoff_until[id] = 0;
		return;
	}

	uint8_t fails = n->mp_carrier_failures[id] < 6 ? ++n->mp_carrier_failures[id] : 6;
	time_t delay = 15;

	for(uint8_t i = 1; i < fails && delay < 300; i++) {
		delay *= 2;
	}

	if(delay > 300) {
		delay = 300;
	}

	time_t cur_sec = now.tv_sec > 0 ? now.tv_sec : 1;
	n->mp_carrier_backoff_until[id] = cur_sec + delay;
	logger(DEBUG_CONNECTIONS, LOG_INFO,
	       "multipath: carrier %s secondary dial to %s failed (%u in a row); backoff %lds",
	       c->transport->name, n->name ? n->name : "peer", fails, (long)delay);
}

static uint16_t extract_sockaddr_port(const sockaddr_t *sa) {
	if(sa->sa.sa_family == AF_INET) {
		return sa->in.sin_port;
	}

	if(sa->sa.sa_family == AF_INET6) {
		return sa->in6.sin6_port;
	}

	return 0;
}

static void set_sockaddr_port_net(sockaddr_t *sa, uint16_t net_port) {
	if(sa->sa.sa_family == AF_INET) {
		sa->in.sin_port = net_port;
	} else if(sa->sa.sa_family == AF_INET6) {
		sa->in6.sin6_port = net_port;
	}
}

static void multipath_transfer_edge(connection_t *from, connection_t *to) {
	if(!from || !to || !from->edge) {
		return;
	}

	edge_t *e = from->edge;
	bool from_is_single_flow_udp = from->transport &&
	                               (from->transport->caps & (TRANSPORT_CAP_SINGLE_FLOW | TRANSPORT_CAP_DATA_UDP)) == (TRANSPORT_CAP_SINGLE_FLOW | TRANSPORT_CAP_DATA_UDP);
	bool to_is_single_flow_udp = to->transport &&
	                             (to->transport->caps & (TRANSPORT_CAP_SINGLE_FLOW | TRANSPORT_CAP_DATA_UDP)) == (TRANSPORT_CAP_SINGLE_FLOW | TRANSPORT_CAP_DATA_UDP);

	uint16_t listen_port = !from_is_single_flow_udp ? extract_sockaddr_port(&e->address) : 0;

	if(!listen_port) {
		listen_port = extract_sockaddr_port(&to->base_address);
	}

	if(!listen_port && e->to && e->to->address_cache && e->to->address_cache->data.used > 0) {
		listen_port = extract_sockaddr_port(&e->to->address_cache->data.address[0]);
	}

	to->edge = e;
	e->connection = to;
	e->options = to->options;

	if(&e->address != &to->address) {
		sockaddrfree(&e->address);
		sockaddrcpy(&e->address, &to->address);
	}

	if(!to_is_single_flow_udp && listen_port) {
		set_sockaddr_port_net(&e->address, listen_port);
	}

	sockaddr_t local_sa = {0};

	if(transport_local_address(to, &local_sa)) {
		if(!to_is_single_flow_udp) {
			sockaddr_setport(&local_sa, myport.udp);
		}

		sockaddrfree(&e->local_address);
		sockaddrcpy(&e->local_address, &local_sa);
		sockaddrfree(&local_sa);
	}

	if(e->to && e->from) {
		e->reverse = lookup_edge(e->to, e->from);

		if(e->reverse) {
			e->reverse->reverse = e;
		}
	}

	if(e->to) {
		node_t *n = e->to;

		if(n->connection == from) {
			from->status.multipath_sub = true;
			to->status.multipath_sub = false;
			n->connection = to;
		}

		if(n->prevedge == e) {
			n->options = e->options;

			if(to->options & OPTION_TCPONLY) {
				n->options |= OPTION_TCPONLY;
			}

			bool indirect = (myself ? myself->status.indirect : false) || (e->options & OPTION_INDIRECT) ||
			                n->status.no_direct || n->remote_no_direct;
			n->status.indirect = indirect;
			n->via = indirect ? (myself ? myself->via : n) : n;
		}

		bool from_dgram = from->transport && from->transport->send_datagram != NULL;
		bool to_dgram = to->transport && to->transport->send_datagram != NULL;

		if(from_dgram != to_dgram) {
			timeout_del(&n->udp_ping_timeout);
			n->status.udp_confirmed = false;

			if(from_dgram) {
				n->status.udp_addr_confirmed = false;
			}

			n->status.ping_sent = false;
			n->udp_ping_sent = (struct timeval) {0, 0};
			n->mtuprobes = 0;
			n->minmtu = 0;
			n->maxmtu = MTU;
			n->mtu = MTU;
		} else if((to->options & OPTION_TCPONLY) && n->status.udp_confirmed) {
			timeout_del(&n->udp_ping_timeout);
			n->status.udp_confirmed = false;
			n->status.udp_addr_confirmed = false;
			n->minmtu = 0;
			n->maxmtu = MTU;
			n->mtu = MTU;
		}
	}

	from->edge = NULL;

	if(myself && e->from == myself && !tunnelserver) {
		send_add_edge(everyone, e);
	}

	if(myself) {
		graph();
	}
}

/* Called in ack_h() when a new connection `c` to `n` completes authentication
   while `n->connection` already exists.
   Returns true if `c` is accepted into `n->connections` without terminating
   `n->connection` (zero-drop parallel connection / make-before-break). */
bool multipath_accept_secondary(node_t *n, connection_t *c) {
	if(!n || !c || !n->connection || n->connection == c) {
		return false;
	}

	if(c->transport && (c->transport->id == TRANSPORT_SF || c->transport->id == TRANSPORT_OBFS)) {
		return false;
	}

	multipath_node_add_connection(n, n->connection);

	/* If n->connections already reached the cap, check if the oldest secondary
	   or the primary is stale (e.g. missed keepalive or on a DOWN uplink). */
	int max_conns = MIN(MAX(multipath_target_connections + 2, 4), MAX_MULTIPATH_CONNECTIONS * 2);

	if((int)n->connections.count >= max_conns) {
		connection_t *victim = NULL;

		for list_each(connection_t, cand, &n->connections) {
			if(cand == n->connection) {
				continue;
			}

			if(!multipath_uplink_is_healthy(cand->uplink_idx) || connection_ping_overdue(cand)) {
				victim = cand;
				break;
			}

			if(!victim) {
				victim = cand;
			}
		}

		if(victim) {
			multipath_node_del_connection(n, victim);
			victim->status.multipath_sub = false;
			victim->edge = NULL;
			terminate_connection(victim, false);
		}
	}

	c->node = n;
	c->status.multipath_sub = true;
	c->edge = NULL;
	refresh_connection_tcp_min_rtt(c);
	multipath_node_add_connection(n, c);

	/* If the existing primary connection is on a downed uplink or waiting on
	   a ping timeout while `c` is fresh and healthy, seamlessly promote `c`
	   to primary right now! */
	connection_t *old_primary = n->connection;
	bool old_unhealthy = !multipath_uplink_is_healthy(old_primary->uplink_idx) ||
	                     connection_ping_overdue(old_primary);

	if(old_unhealthy && old_primary->edge) {
		old_primary->status.multipath_sub = true;
		c->status.multipath_sub = false;
		n->connection = c;

		if(old_primary->outgoing && old_primary->outgoing->timeout != -1 && !c->outgoing) {
			c->outgoing = old_primary->outgoing;
			old_primary->outgoing = NULL;
		}

		multipath_transfer_edge(old_primary, c);

		logger(DEBUG_CONNECTIONS, LOG_NOTICE,
		       "multipath: seamlessly promoted new connection with %s (%s) to primary (0-ms handover)",
		       c->name, c->hostname);
	} else {
		logger(DEBUG_CONNECTIONS, LOG_NOTICE,
		       "multipath: added parallel connection #%u with %s (%s, uplink=%d, mode=%s)",
		       n->connections.count, c->name, c->hostname, c->uplink_idx,
		       multipath_mode_name(multipath_mode));
	}

	return true;
}

/* Called in terminate_connection() when `dying == n->connection` is about to be
   closed. If another authenticated connection exists in `n->connections`,
   promotes it to `n->connection` and transfers `dying->edge` so the VPN graph
   and SPTPS session experience 0-ms interruption! */
bool multipath_promote_survivor(node_t *n, connection_t *dying) {
	if(!n || !dying) {
		return false;
	}

	multipath_node_del_connection(n, dying);

	if(n->connection != dying) {
		if(n->connection && n->connections.count == 1 &&
		                (n->connection->sptps.state || n->connection->status.encryptout)) {
			send_request(n->connection, "%d solo", PING);
		}

		return false;
	}

	connection_t *survivor = NULL;

	/* Prefer a survivor on a healthy primary uplink that is not waiting on a ping */
	for(int pass = 0; pass < 2 && !survivor; pass++) {
		for list_each(connection_t, cand, &n->connections) {
			if(cand == dying || !cand->status.active) {
				continue;
			}

			if(pass == 0 && (!multipath_uplink_is_healthy(cand->uplink_idx) || connection_ping_overdue(cand))) {
				continue;
			}

			survivor = cand;
			break;
		}
	}

	if(!survivor) {
		return false;
	}

	/* Do NOT transfer outgoing_t if it is being intentionally torn down
	   (timeout == -1, e.g. dnsrefresh_apply or removed ConnectTo on reload). */
	if(dying->outgoing && dying->outgoing->timeout != -1 && !survivor->outgoing) {
		survivor->outgoing = dying->outgoing;
		dying->outgoing = NULL;
	}

	survivor->status.multipath_sub = false;
	n->connection = survivor;

	if(dying->edge) {
		multipath_transfer_edge(dying, survivor);
	}

	if(n->connections.count == 1 && (survivor->sptps.state || survivor->status.encryptout)) {
		send_request(survivor, "%d solo", PING);
	}

	logger(DEBUG_CONNECTIONS, LOG_NOTICE,
	       "multipath: primary connection to %s failed; promoted standby connection (%s, uplink=%d) in 0 ms without route flap",
	       n->name, survivor->hostname, survivor->uplink_idx);

	return true;
}

void multipath_peer_promoted_solo(connection_t *c) {
	if(!c || !c->node) {
		return;
	}

	node_t *n = c->node;

	if(n->connection && n->connection != c) {
		connection_t *old = n->connection;

		if(old->outgoing && old->outgoing->timeout != -1 && !c->outgoing) {
			c->outgoing = old->outgoing;
			old->outgoing = NULL;
		}

		old->status.multipath_sub = true;
		c->status.multipath_sub = false;
		n->connection = c;

		if(old->edge) {
			multipath_transfer_edge(old, c);
		}
	}

	bool found_stale;

	do {
		found_stale = false;

		for list_each(connection_t, other, &n->connections) {
			if(other != c) {
				multipath_node_del_connection(n, other);
				other->edge = NULL;
				other->status.multipath_sub = false;
				terminate_connection(other, false);
				found_stale = true;
				break;
			}
		}
	} while(found_stale);
}

/* ---- Per-Node UDP Path Tracking & Probing -------------------------------- */

void multipath_record_udp_rx(node_t *n, int uplink_idx, int sock_idx,
                             const sockaddr_t *addr, size_t len) {
	if(!n || !addr || n == myself ||
	                (addr->sa.sa_family != AF_INET && addr->sa.sa_family != AF_INET6)) {
		return;
	}

	sockaddr_t clean = *addr;
	sockaddrunmap(&clean);

	int match_idx = -1;
	int free_idx = -1;
	int oldest_idx = 0;
	time_t oldest_rx = INT_MAX;

	for(int i = 0; i < MAX_NODE_PATHS; i++) {
		node_path_t *p = &n->paths[i];

		if(p->active) {
			if(p->uplink_idx == uplink_idx && !sockaddrcmp(&p->addr, &clean)) {
				match_idx = i;
				break;
			}

			if(p->last_rx < oldest_rx) {
				oldest_rx = p->last_rx;
				oldest_idx = i;
			}
		} else if(free_idx < 0) {
			free_idx = i;
		}
	}

	int idx = match_idx >= 0 ? match_idx : (free_idx >= 0 ? free_idx : oldest_idx);
	node_path_t *p = &n->paths[idx];

	if(match_idx < 0) {
		sockaddrfree(&p->addr);
		memset(p, 0, sizeof(*p));
		p->active = true;
		p->uplink_idx = uplink_idx;
		p->sock_idx = sock_idx >= 0 ? sock_idx : (int)n->sock;
		sockaddrcpy(&p->addr, &clean);
		p->srtt_us = n->udp_ping_rtt > 0 ? (uint32_t)n->udp_ping_rtt : 50000;
	}

	p->confirmed = true;
	p->last_rx = now.tv_sec;
	p->rx_packets++;
	p->rx_bytes += (uint64_t)len;
}

void multipath_update_udp_rtt(node_t *n, const sockaddr_t *addr, uint32_t rtt_us) {
	if(!n || !addr || rtt_us == 0 ||
	                (addr->sa.sa_family != AF_INET && addr->sa.sa_family != AF_INET6)) {
		return;
	}

	sockaddr_t clean = *addr;
	sockaddrunmap(&clean);

	for(int i = 0; i < MAX_NODE_PATHS; i++) {
		node_path_t *p = &n->paths[i];

		if(p->active && !sockaddrcmp(&p->addr, &clean)) {
			if(p->srtt_us == 0) {
				p->srtt_us = rtt_us;
			} else {
				/* EWMA: 7/8 old + 1/8 new */
				p->srtt_us = (uint32_t)(((uint64_t)p->srtt_us * 7 + rtt_us) / 8);
			}
		}
	}
}

void multipath_probe_node_paths(node_t *n, const void *probe_payload, size_t payload_len) {
	if(!n || n->status.no_direct || n->remote_no_direct || !probe_payload || !payload_len ||
	                !n->status.sptps || !n->sptps.outstate || multipath_mode == MULTIPATH_OFF) {
		return;
	}

	/* Collect distinct resolved remote UDP endpoints for `n` (primary n->address
	   plus any confirmed secondary n->paths[i].addr). */
	const sockaddr_t *dsts[MAX_NODE_PATHS + 1];
	size_t dst_socks[MAX_NODE_PATHS + 1];
	int dst_uplinks[MAX_NODE_PATHS + 1];
	int ndsts = 0;

	if(n->address.sa.sa_family == AF_INET || n->address.sa.sa_family == AF_INET6) {
		dsts[ndsts] = &n->address;
		dst_socks[ndsts] = n->sock;
		dst_uplinks[ndsts] = -1;
		ndsts++;
	}

	for(int i = 0; i < MAX_NODE_PATHS && ndsts < MAX_NODE_PATHS + 1; i++) {
		const node_path_t *p = &n->paths[i];

		if(!p->active || (p->addr.sa.sa_family != AF_INET && p->addr.sa.sa_family != AF_INET6)) {
			continue;
		}

		bool seen = false;

		for(int j = 0; j < ndsts; j++) {
			if(!sockaddrcmp(&p->addr, dsts[j])) {
				seen = true;
				break;
			}
		}

		if(!seen) {
			dsts[ndsts] = &p->addr;
			dst_socks[ndsts] = p->sock_idx >= 0 ? (size_t)p->sock_idx : n->sock;
			dst_uplinks[ndsts] = p->uplink_idx;
			ndsts++;
		}
	}

	if(ndsts <= 0) {
		return;
	}

	/* When dedicated uplinks are configured, encode a fresh SPTPS probe record
	   (unique seqno + standard obfs/DirectSeal pipeline) per (uplink, remote_addr). */
	if(multipath_uplink_count > 0) {
		for(int u = 0; u < MAX_UPLINKS; u++) {
			if(!multipath_uplinks[u].in_use || !multipath_uplinks[u].is_up) {
				continue;
			}

			for(int d = 0; d < ndsts; d++) {
				send_sptps_probe_on_path(n, u, dst_socks[d], dsts[d], probe_payload, payload_len);
			}
		}
	} else {
		/* No dedicated local uplinks, but peer may have multiple confirmed remote
		   addresses in n->paths: probe alternate addresses beyond dsts[0] (&n->address). */
		for(int d = 0; d < ndsts; d++) {
			if((n->address.sa.sa_family == AF_INET || n->address.sa.sa_family == AF_INET6) &&
			                !sockaddrcmp(dsts[d], &n->address)) {
				continue;
			}

			send_sptps_probe_on_path(n, dst_uplinks[d], dst_socks[d], dsts[d], probe_payload, payload_len);
		}
	}
}

/* ---- 5-Tuple Inner Packet Flow Hash (Zero Intra-Flow Reordering) --------- */

uint32_t multipath_flow_hash(const vpn_packet_t *pkt) {
	if(!pkt || pkt->len < 14) {
		return 0;
	}

	const uint8_t *p = DATA(pkt);
	size_t len = pkt->len;

	/* vpn_packet_t always begins with a 14-byte Ethernet / pseudo-Ethernet
	   header in both RMODE_ROUTER and RMODE_SWITCH / RMODE_HUB. */
	const size_t l2_off = 14;
	uint16_t ether_type = ((uint16_t)p[12] << 8) | p[13];
	p += l2_off;
	len -= l2_off;

	/* 802.1Q VLAN tag */
	if(ether_type == 0x8100 && len >= 4) {
		p += 4;
		len -= 4;
	}

	/* FNV-1a 32-bit basis */
	uint32_t hash = 2166136261u;

#define FNV_MIX_BYTE(b) do { hash ^= (uint8_t)(b); hash *= 16777619u; } while(0)
#define FNV_MIX_BUF(buf, n) do { \
	const uint8_t *_b = (const uint8_t *)(buf); \
	for(size_t _i = 0; _i < (size_t)(n); _i++) { FNV_MIX_BYTE(_b[_i]); } \
} while(0)

	uint8_t ip_ver = len > 0 ? (p[0] >> 4) : 0;

	if(ip_ver == 4 && len >= 20) {
		uint8_t ihl = (p[0] & 0x0f) * 4;
		uint8_t proto = p[9];
		FNV_MIX_BYTE(proto);
		FNV_MIX_BUF(p + 12, 8); /* src_ip (4B) + dst_ip (4B) */

		if(ihl >= 20 && len >= (size_t)ihl + 4 && (proto == 6 || proto == 17 || proto == 132)) {
			FNV_MIX_BUF(p + ihl, 4); /* src_port (2B) + dst_port (2B) */
		}
	} else if(ip_ver == 6 && len >= 40) {
		/* Mix IPv6 flow label (20 bits) + next header + src_ip6 (16B) + dst_ip6 (16B) */
		FNV_MIX_BYTE(p[1] & 0x0f);
		FNV_MIX_BYTE(p[2]);
		FNV_MIX_BYTE(p[3]);
		uint8_t nh = p[6];
		FNV_MIX_BYTE(nh);
		FNV_MIX_BUF(p + 8, 32);

		if(len >= 44 && (nh == 6 || nh == 17 || nh == 132)) {
			FNV_MIX_BUF(p + 40, 4);
		}
	} else {
		/* Non-IP frame (ARP, etc.): hash first up to 32 bytes */
		size_t mix_len = len < 32 ? len : 32;
		FNV_MIX_BUF(p, mix_len);
	}

#undef FNV_MIX_BUF
#undef FNV_MIX_BYTE

	/* Final avalanche */
	hash ^= hash >> 16;
	hash *= 0x85ebca6bu;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35u;
	hash ^= hash >> 16;

	return hash;
}

/* ---- Multipath Packet Schedulers ----------------------------------------- */

#define SPLIT_BURST_PACKETS 16

static bool connection_is_usable(const connection_t *c, bool allow_backup) {
	if(!c || !c->status.active) {
		return false;
	}

	if(c->uplink_idx >= 0 && c->uplink_idx < MAX_UPLINKS) {
		const multipath_uplink_t *u = &multipath_uplinks[c->uplink_idx];

		if(!u->in_use || !u->is_up) {
			return false;
		}

		if(!allow_backup && u->is_backup) {
			return false;
		}
	}

	return true;
}

static int finish_select_connections(node_t *n, connection_t *out[2], int count) {
	if(count >= 1 && out[0]) {
		multipath_apply_node_tcp_pacing(n, out[0], 0);
	}

	if(count >= 2 && out[1] && out[1] != out[0]) {
		multipath_apply_node_tcp_pacing(n, out[1], 0);
	}

	return count;
}

bool multipath_pkt_is_latency_sensitive(const vpn_packet_t *pkt) {
	if(!pkt || pkt->len < 14) {
		return false;
	}

	const uint8_t *p = DATA(pkt);
	size_t len = pkt->len;
	uint16_t eth = ((uint16_t)p[12] << 8) | p[13];
	p += 14;
	len -= 14;

	if(eth == 0x8100 && len >= 4) {
		eth = ((uint16_t)p[2] << 8) | p[3];
		p += 4;
		len -= 4;
	}

	if(eth == 0x0800 && len >= 20 && (p[0] >> 4) == 4) {
		uint8_t proto = p[9];

		if(proto == 17 || proto == 1) {
			return true;
		}

		if(proto == 6) {
			return pkt->len <= 320;
		}

		return false;
	}

	if(eth == 0x86dd && len >= 40 && (p[0] >> 4) == 6) {
		uint8_t nh = p[6];

		if(nh == 17 || nh == 58) {
			return true;
		}

		if(nh == 6) {
			return pkt->len <= 340;
		}

		return false;
	}

	return true;
}

uint8_t multipath_conn_health_score(const node_t *n, const connection_t *c, uint32_t best_rtt_us) {
	(void)n;

	if(!c || !c->status.active || !multipath_uplink_is_healthy(c->uplink_idx)) {
		return 0;
	}

	int score = 100;

	if(connection_has_wan_rtt(c) && best_rtt_us >= 1000 && best_rtt_us < UINT32_MAX &&
	                c->tcp_min_rtt_us > best_rtt_us) {
		uint32_t delta_ms = (c->tcp_min_rtt_us - best_rtt_us) / 1000U;
		int rtt_pen = (int)(delta_ms / 2U);

		if(rtt_pen > 35) {
			rtt_pen = 35;
		}

		score -= rtt_pen;
	}

	if(c->tcp_degraded) {
		score -= 55;
	} else if(c->tcp_segs_out >= 100 && c->tcp_total_retrans > 0) {
		uint64_t loss_pct = ((uint64_t)c->tcp_total_retrans * 100ULL) / (uint64_t)c->tcp_segs_out;

		if(loss_pct >= 12) {
			score -= 40;
		} else if(loss_pct >= 5) {
			score -= 25;
		} else if(loss_pct >= 2) {
			score -= 10;
		}
	}

	size_t qbytes = (c->outbuf.len > c->outbuf.offset ? c->outbuf.len - c->outbuf.offset : 0) +
	                c->transport_outbuf_len;

	if(qbytes > 1048576U) {
		score -= 25;
	} else if(qbytes > 262144U) {
		score -= 10;
	}

	if(connection_ping_overdue(c)) {
		score -= 30;
	}

	if(c->transport && c->transport->send_datagram) {
		score += 5;
	}

	return (uint8_t)CLAMP(score, 1, 100);
}

uint8_t multipath_udp_path_score(const node_t *n, const node_path_t *p, uint32_t best_rtt_us) {
	if(!p || !p->active || !p->confirmed || !multipath_uplink_is_healthy(p->uplink_idx)) {
		return 0;
	}

	if(now.tv_sec - p->last_rx > pingtimeout * 2 + 15) {
		return 0;
	}

	int score = 100;
	uint32_t srtt = p->srtt_us ? p->srtt_us : (n && n->udp_ping_rtt > 0 ? (uint32_t)n->udp_ping_rtt : 50000U);

	if(best_rtt_us >= 1000 && best_rtt_us < UINT32_MAX && srtt > best_rtt_us) {
		int pen = (int)((srtt - best_rtt_us) / 2000U);

		if(pen > 35) {
			pen = 35;
		}

		score -= pen;
	}

	if(n && n->udp_ping_unanswered >= 2) {
		int upen = n->udp_ping_unanswered * 15;

		if(upen > 45) {
			upen = 45;
		}

		score -= upen;
	}

	score += 5;
	return (uint8_t)CLAMP(score, 1, 100);
}

int multipath_select_connections(node_t *n, const vpn_packet_t *pkt, connection_t *out[2]) {
	out[0] = NULL;
	out[1] = NULL;

	if(!n) {
		return 0;
	}

	if(multipath_mode == MULTIPATH_OFF || n->connections.count <= 1) {
		if(n->connection) {
			n->connection->health_score = multipath_conn_health_score(n, n->connection, n->connection->tcp_min_rtt_us);
			out[0] = n->connection;
			return finish_select_connections(n, out, 1);
		}

		return 0;
	}

	connection_t *usable[MAX_MULTIPATH_CONNECTIONS * 2] = {0};
	int nusable = 0;

	/* First collect active non-backup connections; if none, allow backup uplinks */
	for(int pass = 0; pass < 2 && nusable == 0; pass++) {
		bool allow_backup = (pass == 1);

		for list_each(connection_t, c, &n->connections) {
			if(!connection_is_usable(c, allow_backup)) {
				continue;
			}

			if(pass == 0 && connection_ping_overdue(c)) {
				continue;
			}

			if(c->tcp_diag_at != now.tv_sec) {
				refresh_connection_tcp_health(c, false);
			}

			if(nusable < (int)(sizeof(usable) / sizeof(usable[0]))) {
				usable[nusable++] = c;
			}
		}
	}

	if(nusable == 0) {
		if(n->connection) {
			out[0] = n->connection;
			return finish_select_connections(n, out, 1);
		}

		return 0;
	}

	uint32_t best_rtt = UINT32_MAX;
	uint64_t best_pacing_bps = 0;
	int wan_rtt_cnt = 0;
	bool has_dgram = false;
	bool has_stream = false;

	for(int i = 0; i < nusable; i++) {
		if(usable[i]->transport && usable[i]->transport->send_datagram) {
			has_dgram = true;
		} else {
			has_stream = true;
		}

		if(nusable > 1) {
			if(connection_has_wan_rtt(usable[i])) {
				wan_rtt_cnt++;

				if(usable[i]->tcp_min_rtt_us < best_rtt) {
					best_rtt = usable[i]->tcp_min_rtt_us;
				}
			}

			if(usable[i]->tcp_pacing_bps > best_pacing_bps) {
				best_pacing_bps = usable[i]->tcp_pacing_bps;
			}
		}
	}

	/* Only compare WAN TCP paths when at least 2 non-loopback legs report >= 1 ms min_rtt;
	   loopback proxy sockets stay untouched. */
	bool has_wan = (wan_rtt_cnt >= 2 && best_rtt >= 1000 && best_rtt < UINT32_MAX);

	connection_t *healthy[MAX_MULTIPATH_CONNECTIONS * 2] = {0};
	int nhealthy = 0;

	for(int i = 0; i < nusable; i++) {
		bool deg = has_wan && connection_is_wan_degraded(usable[i], best_rtt, best_pacing_bps, 30000);
		usable[i]->health_score = multipath_conn_health_score(n, usable[i], best_rtt);

		if(!deg) {
			healthy[nhealthy++] = usable[i];
		}
	}

	if(nhealthy == 0) {
		for(int i = 0; i < nusable; i++) {
			healthy[nhealthy++] = usable[i];
		}
	}

	/* Heterogeneous specialization: in parallel pools mixing datagram (quic)
	   and stream (https) legs, steer latency-sensitive / UDP / small packets
	   onto the healthiest datagram leg to avoid TCP head-of-line blocking. */
	if(has_dgram && has_stream && pkt && multipath_pkt_is_latency_sensitive(pkt) &&
	                multipath_mode != MULTIPATH_REDUNDANT && pkt->len <= 1119) {
		connection_t *best_dg = NULL;

		for(int i = 0; i < nhealthy; i++) {
			if(healthy[i]->transport && healthy[i]->transport->send_datagram &&
			                healthy[i]->health_score >= 50 &&
			                (!best_dg || healthy[i]->health_score > best_dg->health_score)) {
				best_dg = healthy[i];
			}
		}

		if(best_dg) {
			out[0] = best_dg;
			return finish_select_connections(n, out, 1);
		}
	}

	if(nusable == 1 || multipath_mode == MULTIPATH_FAILOVER) {
		connection_t *best = healthy[0];

		for(int i = 1; i < nhealthy; i++) {
			if(healthy[i]->health_score > best->health_score) {
				best = healthy[i];
			}
		}

		out[0] = best;
		return finish_select_connections(n, out, 1);
	}

	switch(multipath_mode) {
	case MULTIPATH_REDUNDANT:
		out[0] = healthy[0];
		out[1] = nhealthy >= 2 ? healthy[1] : (usable[0] != healthy[0] ? usable[0] : usable[1]);
		return finish_select_connections(n, out, 2);

	case MULTIPATH_FLOWHASH: {
		uint32_t h;

		if(pkt) {
			h = multipath_flow_hash(pkt);
		} else if(multipath_current_flow_hash & 0x80000000u) {
			h = multipath_current_flow_hash & 0x7fffffffu;
		} else if(multipath_current_flow_hash) {
			h = multipath_current_flow_hash;
		} else {
			h = n->mp_rr_cursor++;
		}

		/* Consistent fixed-slot mapping: a degraded or closed slot never shifts
		   healthy flows onto different sockets, preventing intra-flow TCP reordering. */
		connection_t *slots[MAX_MULTIPATH_CONNECTIONS];
		bool slot_ok[MAX_MULTIPATH_CONNECTIONS];
		memset(slots, 0, sizeof(slots));
		memset(slot_ok, 0, sizeof(slot_ok));

		uint32_t max_slot_plus1 = 1;

		for(int i = 0; i < nusable; i++) {
			connection_t *c = usable[i];
			uint32_t s = c->relay_slot % MAX_MULTIPATH_CONNECTIONS;
			bool ok = !(has_wan && connection_is_wan_degraded(c, best_rtt, best_pacing_bps, 30000));

			if(!slots[s] || (!slot_ok[s] && ok)) {
				slots[s] = c;
				slot_ok[s] = ok;
			}

			if(s + 1 > max_slot_plus1) {
				max_slot_plus1 = s + 1;
			}
		}

		if(max_slot_plus1 > n->mp_slot_hwm) {
			n->mp_slot_hwm = (uint8_t)max_slot_plus1;
		}

		uint32_t width = n->mp_slot_hwm >= 2 ? n->mp_slot_hwm :
		                 (max_slot_plus1 >= 2 ? max_slot_plus1 : (uint32_t)MAX_MULTIPATH_CONNECTIONS);

		if(width > MAX_MULTIPATH_CONNECTIONS) {
			width = MAX_MULTIPATH_CONNECTIONS;
		}

		uint32_t idx = h % width;

		if(slots[idx] && slot_ok[idx]) {
			out[0] = slots[idx];
			return finish_select_connections(n, out, 1);
		}

		uint32_t alt_base = h / width;

		for(uint32_t step = 0; step < width; step++) {
			uint32_t alt = (alt_base + step) % width;

			if(slots[alt] && slot_ok[alt]) {
				out[0] = slots[alt];
				return finish_select_connections(n, out, 1);
			}
		}

		out[0] = slots[idx] ? slots[idx] : healthy[0];
		return finish_select_connections(n, out, 1);
	}

	case MULTIPATH_SPLIT: {
		if(++n->mp_burst_pkts >= SPLIT_BURST_PACKETS) {
			n->mp_burst_pkts = 0;
			n->mp_rr_cursor++;
		}

		out[0] = healthy[n->mp_rr_cursor % (uint32_t)nhealthy];
		return finish_select_connections(n, out, 1);
	}

	case MULTIPATH_OFF:
	case MULTIPATH_FAILOVER:
	default:
		out[0] = healthy[0];
		return finish_select_connections(n, out, 1);
	}
}

static bool udp_path_is_usable(const node_path_t *p, bool allow_backup) {
	if(!p || !p->active || !p->confirmed) {
		return false;
	}

	if(now.tv_sec - p->last_rx > pingtimeout * 2 + 15) {
		return false;
	}

	if(p->uplink_idx >= 0 && p->uplink_idx < MAX_UPLINKS) {
		const multipath_uplink_t *u = &multipath_uplinks[p->uplink_idx];

		if(!u->in_use || !u->is_up) {
			return false;
		}

		if(!allow_backup && u->is_backup) {
			return false;
		}
	}

	return true;
}

int multipath_select_udp_paths(node_t *n, const vpn_packet_t *pkt, node_path_t *out[2]) {
	out[0] = NULL;
	out[1] = NULL;

	if(!n || n->status.no_direct || multipath_mode == MULTIPATH_OFF) {
		return 0;
	}

	node_path_t *cands[MAX_NODE_PATHS];
	int ncands = 0;

	for(int pass = 0; pass < 2 && ncands == 0; pass++) {
		bool allow_backup = (pass == 1);

		for(int i = 0; i < MAX_NODE_PATHS; i++) {
			if(udp_path_is_usable(&n->paths[i], allow_backup)) {
				cands[ncands++] = &n->paths[i];
			}
		}
	}

	/* Sort candidates by lowest srtt_us */
	for(int i = 0; i < ncands - 1; i++) {
		for(int j = i + 1; j < ncands; j++) {
			uint32_t rtt_i = cands[i]->srtt_us ? cands[i]->srtt_us : 50000;
			uint32_t rtt_j = cands[j]->srtt_us ? cands[j]->srtt_us : 50000;

			if(rtt_j < rtt_i) {
				node_path_t *tmp = cands[i];
				cands[i] = cands[j];
				cands[j] = tmp;
			}
		}
	}

	if(ncands == 0) {
		return 0;
	}

	if(ncands == 1 || multipath_mode == MULTIPATH_FAILOVER) {
		out[0] = cands[0];
		return 1;
	}

	switch(multipath_mode) {
	case MULTIPATH_REDUNDANT:
		out[0] = cands[0];
		out[1] = cands[1];
		return 2;

	case MULTIPATH_FLOWHASH: {
		uint32_t h;

		if(pkt) {
			h = multipath_flow_hash(pkt);
		} else if(multipath_current_flow_hash & 0x80000000u) {
			h = multipath_current_flow_hash & 0x7fffffffu;
		} else if(multipath_current_flow_hash) {
			h = multipath_current_flow_hash;
		} else {
			h = n->mp_rr_cursor++;
		}

		out[0] = cands[h % (uint32_t)ncands];
		return 1;
	}

	case MULTIPATH_SPLIT: {
		if(++n->mp_burst_pkts >= SPLIT_BURST_PACKETS) {
			n->mp_burst_pkts = 0;
			n->mp_rr_cursor++;
		}

		out[0] = cands[n->mp_rr_cursor % (uint32_t)ncands];
		return 1;
	}

	case MULTIPATH_OFF:
	case MULTIPATH_FAILOVER:
	default:
		out[0] = cands[0];
		return 1;
	}
}

/* ---- Periodic Maintenance: Parallel Connections & Path Health ------------ */

/* Count how many active + in-progress connections exist to `n`. */
static int count_node_live_or_dialling(const node_t *n) {
	int count = 0;

	for list_each(connection_t, c, &n->connections) {
		if(c->status.active && multipath_uplink_is_healthy(c->uplink_idx)) {
			count++;
		}
	}

	for list_each(connection_t, c, &connection_list) {
		if(connection_is_dialling_node(c, n) && multipath_uplink_is_healthy(c->uplink_idx)) {
			count++;
		}
	}

	return count;
}

static bool sockaddr_has_valid_family(const sockaddr_t *sa) {
	return sa && sa->sa.sa_family != AF_UNSPEC && sa->sa.sa_family != AF_UNKNOWN && sa->sa.sa_family != 0;
}

static const transport_t *pick_secondary_transport(outgoing_t *outgoing) {
	node_t *n = outgoing->node;
	transport_id_t cands[TRANSPORT_MAX];
	int ncands = transport_pool_candidates(n, cands);

	if(ncands <= 0) {
		return n->connection->transport ? n->connection->transport : transport_current(outgoing);
	}

	time_t cur_sec = now.tv_sec > 0 ? now.tv_sec : 1;
	transport_id_t best_id = cands[0];
	int best_count = INT_MAX;
	bool found_ready = false;

	for(int i = 0; i < ncands; i++) {
		transport_id_t id = cands[i];

		if(n->mp_carrier_backoff_until[id] > cur_sec) {
			continue;
		}

		int cnt = 0;

		for list_each(connection_t, existing, &n->connections) {
			transport_id_t eid = existing->transport ? existing->transport->id : TRANSPORT_PLAIN;

			if(existing->status.active && eid == id) {
				cnt++;
			}
		}

		for list_each(connection_t, existing, &connection_list) {
			if(connection_is_dialling_node(existing, n)) {
				transport_id_t eid = existing->transport ? existing->transport->id : TRANSPORT_PLAIN;

				if(eid == id) {
					cnt++;
				}
			}
		}

		if(!found_ready || cnt < best_count) {
			best_count = cnt;
			best_id = id;
			found_ready = true;
		}
	}

	if(!found_ready) {
		return n->connection->transport ? n->connection->transport : transport_current(outgoing);
	}

	const transport_t *picked = transport_get(best_id);
	return picked ? picked : transport_current(outgoing);
}

/* Open a secondary parallel carrier connection to `outgoing->node` without
   disturbing the primary `n->connection`. */
static void dial_secondary_connection(outgoing_t *outgoing) {
	node_t *n = outgoing->node;

	if(!n || !n->connection || !n->address_cache) {
		return;
	}

	const transport_t *t = pick_secondary_transport(outgoing);

	if(!t || !t->dial) {
		return;
	}

	/* Single-flow UDP (`sf` / `obfs`) demuxes incoming frames by peer source
	   address / per-node link state and uses multipath at the UDP datagram
	   layer; only TCP-based (`plain`, `sftcp`, `https`) and `quic`
	   (Connection ID demuxed) open multiple parallel meta connections. */
	if(t->id == TRANSPORT_SF || t->id == TRANSPORT_OBFS) {
		return;
	}

	sockaddr_t target_sa = {0};
	bool have_target = false;
	sockaddr_t first_valid_sa = {0};
	bool have_first_valid = false;

	reset_address_cache(n->address_cache);

	const sockaddr_t *cand;

	while((cand = get_recent_address(n->address_cache)) != NULL) {
		if(!sockaddr_has_valid_family(cand) || address_routes_via_vpn(cand)) {
			continue;
		}

		if(!have_first_valid) {
			memcpy(&first_valid_sa, cand, SALEN(cand->sa));
			have_first_valid = true;
		}

		bool already_used = false;

		for list_each(connection_t, existing, &n->connections) {
			transport_id_t eid = existing->transport ? existing->transport->id : TRANSPORT_PLAIN;

			if(eid != t->id) {
				continue;
			}

			if((sockaddr_has_valid_family(&existing->base_address) && !sockaddrcmp_noport(cand, &existing->base_address)) ||
			                (sockaddr_has_valid_family(&existing->address) && !sockaddrcmp_noport(cand, &existing->address))) {
				already_used = true;
				break;
			}
		}

		if(!already_used) {
			memcpy(&target_sa, cand, SALEN(cand->sa));
			have_target = true;
			break;
		}
	}

	reset_address_cache(n->address_cache);

	if(!have_target && have_first_valid) {
		target_sa = first_valid_sa;
		have_target = true;
	}

	if(!have_target) {
		for list_each(connection_t, existing, &n->connections) {
			if(sockaddr_has_valid_family(&existing->base_address) && !address_routes_via_vpn(&existing->base_address)) {
				memcpy(&target_sa, &existing->base_address, SALEN(existing->base_address.sa));
				have_target = true;
				break;
			}
		}
	}

	if(!have_target && sockaddr_has_valid_family(&n->connection->base_address) &&
	                !address_routes_via_vpn(&n->connection->base_address)) {
		memcpy(&target_sa, &n->connection->base_address, SALEN(n->connection->base_address.sa));
		have_target = true;
	}

	if(!have_target && n->connection->edge &&
	                sockaddr_has_valid_family(&n->connection->edge->address) &&
	                !address_routes_via_vpn(&n->connection->edge->address)) {
		memcpy(&target_sa, &n->connection->edge->address, SALEN(n->connection->edge->address.sa));
		have_target = true;
	}

	if(!have_target && sockaddr_has_valid_family(&n->connection->address) &&
	                !address_routes_via_vpn(&n->connection->address)) {
		memcpy(&target_sa, &n->connection->address, SALEN(n->connection->address.sa));
		have_target = true;
	}

	if(!have_target) {
		return;
	}

	connection_t *c = new_connection();
	c->outgoing = NULL; /* Primary connection owns `outgoing`; secondary is self-contained */
	memcpy(&c->address, &target_sa, SALEN(target_sa.sa));
	memcpy(&c->base_address, &target_sa, SALEN(target_sa.sa));
	c->hostname = sockaddr2hostname(&c->address);
	c->name = xstrdup(n->name);
	c->outmaclength = myself->connection->outmaclength;
	c->last_ping_time = now.tv_sec;
	c->transport = t;
	c->uplink_idx = multipath_pick_next_uplink(n);
	c->status.multipath_sub = true;
	c->status.we_dialled = true;
	connection_snapshot_host_config(c);

	logger(DEBUG_CONNECTIONS, LOG_INFO,
	       "multipath: dialling parallel connection to %s (%s) via %s (uplink=%d)",
	       n->name, c->hostname, t->name, c->uplink_idx);

	if(!t->dial(c)) {
		multipath_record_dial_result(n, c, false);
		free_connection(c);
	}
}

static void multipath_swap_primary(node_t *n, connection_t *new_primary) {
	connection_t *old_c = n->connection;

	if(old_c->outgoing && old_c->outgoing->timeout != -1 && !new_primary->outgoing) {
		new_primary->outgoing = old_c->outgoing;
		old_c->outgoing = NULL;
	}

	old_c->status.multipath_sub = true;
	new_primary->status.multipath_sub = false;
	n->connection = new_primary;

	if(old_c->edge) {
		multipath_transfer_edge(old_c, new_primary);
	}
}

static connection_t *multipath_best_wan_conn(node_t *n, uint32_t rtt_tol_us, bool sample_window,
                uint32_t *best_rtt_out, uint64_t *best_pacing_out, int *active_out) {
	uint32_t best_rtt = UINT32_MAX;
	uint64_t best_pacing = 0;
	int active_cnt = 0;
	int wan_rtt_cnt = 0;

	for list_each(connection_t, c, &n->connections) {
		if(!c->status.active || !multipath_uplink_is_healthy(c->uplink_idx)) {
			continue;
		}

		active_cnt++;
		refresh_connection_tcp_health(c, sample_window);

		if(connection_has_wan_rtt(c)) {
			wan_rtt_cnt++;

			if(c->tcp_min_rtt_us < best_rtt) {
				best_rtt = c->tcp_min_rtt_us;
			}
		}

		if(c->tcp_pacing_bps > best_pacing) {
			best_pacing = c->tcp_pacing_bps;
		}
	}

	*best_rtt_out = best_rtt;
	*best_pacing_out = best_pacing;
	*active_out = active_cnt;

	if(wan_rtt_cnt < 2 || best_rtt < 1000 || best_rtt == UINT32_MAX) {
		return NULL;
	}

	connection_t *best_cand = NULL;

	for list_each(connection_t, c, &n->connections) {
		if(!c->status.active || !multipath_uplink_is_healthy(c->uplink_idx)) {
			continue;
		}

		if(connection_is_wan_degraded(c, best_rtt, best_pacing, rtt_tol_us)) {
			continue;
		}

		bool c_wan = connection_has_wan_rtt(c);
		bool best_wan = best_cand ? connection_has_wan_rtt(best_cand) : false;

		if(!best_cand ||
		                (c_wan && !best_wan) ||
		                (c_wan && best_wan && c->tcp_min_rtt_us < best_cand->tcp_min_rtt_us) ||
		                (c->tcp_min_rtt_us == best_cand->tcp_min_rtt_us && c->tcp_pacing_bps > best_cand->tcp_pacing_bps)) {
			best_cand = c;
		}
	}

	return best_cand;
}

void multipath_maintain(void) {
	if(!multipath_initialized || multipath_mode == MULTIPATH_OFF) {
		return;
	}

	for(int i = 0; i < MAX_UPLINKS; i++) {
		if(multipath_uplinks[i].in_use && multipath_uplinks[i].is_up) {
			ensure_uplink_sockets(i);
		}
	}

	for splay_each(node_t, n, &node_tree) {
		if(n != myself) {
			multipath_apply_node_tcp_pacing(n, NULL, 0);
			multipath_step_auto_pacing(n);
		}
	}

#ifdef HAVE_LINUX
	static time_t last_route_verify = 0;

	if(now.tv_sec - last_route_verify >= 30) {
		last_route_verify = now.tv_sec;
		autoif_ensure_routes();
	}
#endif

	/* If the primary connection of any node is sitting on a DOWN uplink while a
	   healthy secondary connection is ready in n->connections, swap them now! */
	for splay_each(node_t, n, &node_tree) {
		if(!n->connection || n->connections.count <= 1) {
			continue;
		}

		if(!multipath_uplink_is_healthy(n->connection->uplink_idx)) {
			for list_each(connection_t, cand, &n->connections) {
				if(cand != n->connection && cand->status.active && multipath_uplink_is_healthy(cand->uplink_idx)) {
					multipath_swap_primary(n, cand);
					logger(DEBUG_CONNECTIONS, LOG_NOTICE,
					       "multipath: switched primary connection of %s to healthy uplink %d",
					       n->name, cand->uplink_idx);
					break;
				}
			}
		}
	}

	static time_t last_ecmp_recycle = 0;

	for splay_each(node_t, n, &node_tree) {
		if(!n->connection || n->connections.count < 2) {
			continue;
		}

		uint32_t best_rtt = UINT32_MAX;
		uint64_t best_pacing = 0;
		int active_cnt = 0;
		connection_t *best_cand = multipath_best_wan_conn(n, 30000, true, &best_rtt, &best_pacing, &active_cnt);

		if(best_rtt < 1000 || best_rtt == UINT32_MAX) {
			continue;
		}

		/* If primary connection landed on a congested/throttled ECMP leg, promote best_cand */
		if(best_cand && best_cand != n->connection &&
		                connection_is_wan_degraded(n->connection, best_rtt, best_pacing, 30000)) {
			connection_t *old_c = n->connection;
			multipath_swap_primary(n, best_cand);
			logger(DEBUG_CONNECTIONS, LOG_NOTICE,
			       "multipath: promoted healthier ECMP connection for %s (%.1f ms cwnd=%u vs %.1f ms cwnd=%u)",
			       n->name, best_cand->tcp_min_rtt_us / 1000.0, best_cand->tcp_cwnd,
			       old_c->tcp_min_rtt_us / 1000.0, old_c->tcp_cwnd);
		}

		/* Recycle at most 1 genuinely collapsed/skewed ECMP secondary connection per cooldown
		   (30s when all legs are degraded and best_cand == NULL, 60s otherwise). */
		bool we_maintain_pool = false;

		for list_each(outgoing_t, og, &outgoing_list) {
			if(og->node == n) {
				we_maintain_pool = true;
				break;
			}
		}

		bool has_policed_sub = false;

		for list_each(connection_t, cand, &n->connections) {
			if(cand != n->connection && cand->status.active && cand->tcp_degraded) {
				has_policed_sub = true;
				break;
			}
		}

		time_t recycle_cooldown = (!best_cand || has_policed_sub) ? 20 : 60;

		if(we_maintain_pool && now.tv_sec - last_ecmp_recycle >= recycle_cooldown) {
			connection_t *worst = NULL;

			for list_each(connection_t, cand, &n->connections) {
				if(cand == n->connection || !cand->status.active) {
					continue;
				}

				bool cand_bad = best_cand
				                ? connection_is_wan_degraded(cand, best_rtt, best_pacing, 30000)
				                : (cand->tcp_degraded || connection_is_wan_degraded(cand, best_rtt, best_pacing, 30000));
				time_t min_age = cand->tcp_degraded ? 20 : 45;

				if(cand->activated_at > 0 && now.tv_sec - cand->activated_at >= min_age && cand_bad) {
					if(!worst ||
					                (cand->tcp_degraded && !worst->tcp_degraded) ||
					                cand->tcp_min_rtt_us > worst->tcp_min_rtt_us ||
					                (cand->tcp_min_rtt_us == worst->tcp_min_rtt_us && cand->tcp_pacing_bps < worst->tcp_pacing_bps)) {
						worst = cand;
					}
				}
			}

			if(worst) {
				last_ecmp_recycle = now.tv_sec;
				logger(DEBUG_CONNECTIONS, LOG_NOTICE,
				       "multipath: recycling degraded ECMP connection to %s (%s, %.1f ms vs best %.1f ms, cwnd=%u, pacing=%.2f Mbps)",
				       n->name, worst->hostname ? worst->hostname : "?",
				       worst->tcp_min_rtt_us / 1000.0, best_rtt / 1000.0,
				       worst->tcp_cwnd, worst->tcp_pacing_bps / 1000000.0);
				multipath_node_del_connection(n, worst);
				worst->status.multipath_sub = false;
				worst->status.no_tarpit = true;
				worst->edge = NULL;
				terminate_connection(worst, false);
			}
		}
	}

	/* Maintain up to `multipath_target_connections` parallel connections for each
	   ConnectTo peer. */
	if(multipath_target_connections > 1) {
		for list_each(outgoing_t, outgoing, &outgoing_list) {
			node_t *n = outgoing->node;

			if(!n || !n->connection || !n->status.reachable || n->status.no_direct || node_is_no_direct(n->name)) {
				continue;
			}

			int have = count_node_live_or_dialling(n);

			if(have < multipath_target_connections) {
				dial_secondary_connection(outgoing);
			}
		}
	}
}

static void multipath_timer_cb(void *data) {
	(void)data;
	multipath_maintain();
	struct timeval tv = { 5, 0 };
	timeout_set(&multipath_timer, &tv);
}

void multipath_init(void) {
	if(multipath_initialized) {
		return;
	}

	multipath_initialized = true;

	for(int i = 0; i < MAX_UPLINKS; i++) {
		if(multipath_uplinks[i].in_use) {
			ensure_uplink_sockets(i);
		}
	}

#ifdef HAVE_LINUX
	init_netlink_watcher();
#endif

	struct timeval tv = { 5, 0 };
	timeout_add(&multipath_timer, multipath_timer_cb, NULL, &tv);
}

void multipath_exit(void) {
	if(!multipath_initialized) {
		return;
	}

	multipath_initialized = false;
	timeout_del(&multipath_timer);

#ifdef HAVE_LINUX
	exit_netlink_watcher();
#endif

	for(int i = 0; i < MAX_UPLINKS; i++) {
		if(multipath_uplinks[i].in_use) {
			close_uplink_sockets(&multipath_uplinks[i]);
			multipath_uplinks[i].in_use = false;
		}
	}

	multipath_uplink_count = 0;
}

/* ---- Control Socket Handler (REQ_MULTIPATH) ------------------------------
   Format:
     CONTROL REQ_MULTIPATH status
     CONTROL REQ_MULTIPATH detail
     CONTROL REQ_MULTIPATH recycle [peer|all] [slow|all]
     CONTROL REQ_MULTIPATH mode <off|failover|flowhash|redundant|split> [connections]
     CONTROL REQ_MULTIPATH uplink add <name> <ip|-> <weight> <backup:0|1> <mark> <net_handle> <up:0|1>
     CONTROL REQ_MULTIPATH uplink del <name>
*/

static void node_primary_ipv4_str(node_t *n, char *buf, size_t len) {
	if(!buf || len == 0) {
		return;
	}

	snprintf(buf, len, "-");

	if(!n) {
		return;
	}

	const subnet_t *best = NULL;

	for splay_each(subnet_t, s, &n->subnet_tree) {
		if(s->type != SUBNET_IPV4) {
			continue;
		}

		if(!best || s->net.ipv4.prefixlength > best->net.ipv4.prefixlength) {
			best = s;
		}
	}

	if(!best) {
		return;
	}

	char netstr[MAXNETSTR];

	if(!net2str(netstr, sizeof(netstr), best)) {
		return;
	}

	char *slash = strchr(netstr, '/');

	if(slash) {
		*slash = '\0';
	}

	char *hash = strchr(netstr, '#');

	if(hash) {
		*hash = '\0';
	}

	if(netstr[0]) {
		snprintf(buf, len, "%s", netstr);
	}
}

static void format_endpoint_token(const sockaddr_t *sa, char *buf, size_t len) {
	if(!buf || len == 0) {
		return;
	}

	snprintf(buf, len, "-");

	if(!sa || (sa->sa.sa_family != AF_INET && sa->sa.sa_family != AF_INET6)) {
		return;
	}

	char *addr = NULL;
	char *port = NULL;
	sockaddr2str(sa, &addr, &port);

	if(addr && port && addr[0]) {
		if(strchr(addr, ':') && addr[0] != '[') {
			snprintf(buf, len, "[%s]:%s", addr, port);
		} else {
			snprintf(buf, len, "%s:%s", addr, port);
		}

		for(size_t i = 0; buf[i]; i++) {
			if(buf[i] == ' ' || buf[i] == '\t') {
				buf[i] = '_';
			}
		}
	}

	free(addr);
	free(port);
}

static void format_node_pref_transports(const node_t *n, char *buf, size_t len) {
	if(!buf || len == 0) {
		return;
	}

	if(!n || n->pref_transports_count == 0) {
		snprintf(buf, len, "-");
		return;
	}

	size_t off = 0;
	buf[0] = '\0';

	for(uint8_t i = 0; i < n->pref_transports_count && i < 8; i++) {
		const char *tname = transport_name((transport_id_t)n->pref_transports[i]);
		int wrote = snprintf(buf + off, len - off, "%s%s", i > 0 ? "," : "", tname ? tname : "?");

		if(wrote < 0 || (size_t)wrote >= len - off) {
			break;
		}

		off += (size_t)wrote;
	}

	if(!buf[0]) {
		snprintf(buf, len, "-");
	}
}

static void emit_conn_detail(connection_t *ctl, const node_t *n, connection_t *conn, time_t now_sec) {
	mp_tcp_diag_t td;
	bool has_tcp = query_connection_tcp_diag(conn, &td);
	uint32_t min_rtt_us = td.min_rtt_us ? td.min_rtt_us : conn->tcp_min_rtt_us;
	double rtt_ms = (has_tcp && td.rtt_us > 0) ? (double)td.rtt_us / 1000.0 : -1.0;
	double min_rtt_ms = min_rtt_us > 0 ? (double)min_rtt_us / 1000.0 : -1.0;
	double pacing_mbps = (has_tcp && td.pacing_bps > 0) ? (double)td.pacing_bps / 1000000.0 : -1.0;
	long age_s = (conn->activated_at > 0 && now_sec >= conn->activated_at) ? (long)(now_sec - conn->activated_at) : -1;
	long last_ping_s = (conn->last_ping_time > 0 && now_sec >= conn->last_ping_time) ? (long)(now_sec - conn->last_ping_time) : -1;
	unsigned long outbuf = (conn->outbuf.len > conn->outbuf.offset) ? (unsigned long)(conn->outbuf.len - conn->outbuf.offset) : 0;
	unsigned long txbuf = (unsigned long)conn->transport_outbuf_len;
	const char *carrier = (conn->transport && conn->transport->name) ? conn->transport->name : "plain";
	const char *dir = (conn->outgoing || conn->status.we_dialled) ? "out" : "in";
	const char *role = (conn == n->connection) ? "primary" : "sub";
	double pacing_cap_mbps = conn->applied_pacing_rate > 0
	                         ? (double)conn->applied_pacing_rate * 8.0 / 1000000.0
	                         : (conn->target_pacing_rate > 0 ? (double)conn->target_pacing_rate * 8.0 / 1000000.0 : 0.0);
	char ep[160];

	uint32_t best_rtt = UINT32_MAX;

	for list_each(connection_t, item, &n->connections) {
		if(item->status.active && connection_has_wan_rtt(item) && item->tcp_min_rtt_us < best_rtt) {
			best_rtt = item->tcp_min_rtt_us;
		}
	}

	conn->health_score = multipath_conn_health_score(n, conn, best_rtt);
	format_endpoint_token(&conn->address, ep, sizeof(ep));
	send_request(ctl,
	             "%d %d 1 conn peer=%s role=%s dir=%s fd=%d active=%d verified=%d uplink=%d carrier=%s ep=%s age_s=%ld last_ping_s=%ld outbuf=%lu txbuf=%lu rtt_ms=%.1f min_rtt_ms=%.1f cwnd=%u retrans=%u segs_out=%u pacing_mbps=%.2f pacing_cap_mbps=%.2f slot=%u degraded=%d score=%u canary=%d",
	             CONTROL, REQ_MULTIPATH,
	             n->name, role, dir, conn->socket,
	             conn->status.active ? 1 : 0,
	             conn->post_activate_verified ? 1 : 0,
	             conn->uplink_idx, carrier, ep,
	             age_s, last_ping_s, outbuf, txbuf,
	             rtt_ms, min_rtt_ms,
	             td.snd_cwnd, td.total_retrans, td.segs_out, pacing_mbps, pacing_cap_mbps,
	             conn->relay_slot, conn->tcp_degraded ? 1 : 0,
	             (unsigned int)conn->health_score, conn->is_canary ? 1 : 0);
}

static void recycle_node_conns(connection_t *ctl, node_t *n, bool all_secondary, int *promoted_out, int *recycled_out) {
	if(!n || !n->connection || n->connections.count < 2) {
		return;
	}

	uint32_t best_rtt = UINT32_MAX;
	uint64_t best_pacing = 0;
	int active_cnt = 0;
	connection_t *best_cand = multipath_best_wan_conn(n, 25000, false, &best_rtt, &best_pacing, &active_cnt);

	if(!multipath_uplink_is_healthy(n->connection->uplink_idx) && !best_cand) {
		for list_each(connection_t, cand, &n->connections) {
			if(cand != n->connection && cand->status.active && multipath_uplink_is_healthy(cand->uplink_idx)) {
				best_cand = cand;
				break;
			}
		}
	}

	if(best_cand && best_cand != n->connection &&
	                (!multipath_uplink_is_healthy(n->connection->uplink_idx) ||
	                 connection_is_wan_degraded(n->connection, best_rtt, best_pacing, 25000))) {
		connection_t *old_c = n->connection;
		double old_ms = old_c->tcp_min_rtt_us > 0 ? (double)old_c->tcp_min_rtt_us / 1000.0 : -1.0;
		double new_ms = best_cand->tcp_min_rtt_us > 0 ? (double)best_cand->tcp_min_rtt_us / 1000.0 : -1.0;

		multipath_swap_primary(n, best_cand);
		logger(DEBUG_CONNECTIONS, LOG_NOTICE,
		       "multipath: operator recycle promoted %s primary (%.1f ms -> %.1f ms, cwnd=%u)",
		       n->name, old_ms, new_ms, best_cand->tcp_cwnd);
		send_request(ctl, "%d %d 1 promoted peer=%s old_ms=%.1f new_ms=%.1f",
		             CONTROL, REQ_MULTIPATH, n->name, old_ms, new_ms);
		(*promoted_out)++;
	}

	connection_t *victims[MAX_MULTIPATH_CONNECTIONS * 2];
	int nvictims = 0;

	for list_each(connection_t, cand, &n->connections) {
		if(cand == n->connection) {
			continue;
		}

		bool wan_ready = (best_rtt >= 1000 && best_rtt != UINT32_MAX);
		bool slow = !cand->status.active ||
		            !multipath_uplink_is_healthy(cand->uplink_idx) ||
		            cand->tcp_degraded ||
		            (wan_ready && connection_is_wan_degraded(cand, best_rtt, best_pacing, 25000));

		if((all_secondary || slow) && nvictims < MAX_MULTIPATH_CONNECTIONS * 2) {
			victims[nvictims++] = cand;
		}
	}

	for(int i = 0; i < nvictims; i++) {
		connection_t *victim = victims[i];
		char ep[160];
		double v_ms = victim->tcp_min_rtt_us > 0 ? (double)victim->tcp_min_rtt_us / 1000.0 : -1.0;
		double b_ms = best_rtt != UINT32_MAX ? (double)best_rtt / 1000.0 : -1.0;

		format_endpoint_token(&victim->address, ep, sizeof(ep));
		logger(DEBUG_CONNECTIONS, LOG_NOTICE,
		       "multipath: operator recycling connection to %s (%s, %.1f ms vs best %.1f ms, cwnd=%u, pacing=%.2f Mbps)",
		       n->name, ep, v_ms, b_ms, victim->tcp_cwnd, victim->tcp_pacing_bps / 1000000.0);
		send_request(ctl, "%d %d 1 recycled peer=%s role=sub ep=%s min_rtt_ms=%.1f best_ms=%.1f",
		             CONTROL, REQ_MULTIPATH, n->name, ep, v_ms, b_ms);
		multipath_node_del_connection(n, victim);
		victim->status.multipath_sub = false;
		victim->status.no_tarpit = true;
		victim->edge = NULL;
		terminate_connection(victim, false);
		(*recycled_out)++;
	}
}

bool control_multipath_h(connection_t *c, const char *request) {
	char subcmd[64] = "";

	if(sscanf(request, "%*d %*d %63s", subcmd) != 1) {
		return send_request(c, "%d %d -1", CONTROL, REQ_MULTIPATH);
	}

	if(!strcasecmp(subcmd, "status")) {
		send_request(c, "%d %d 0 mode=%s target_conns=%d uplinks=%d",
		             CONTROL, REQ_MULTIPATH,
		             multipath_mode_name(multipath_mode),
		             multipath_target_connections,
		             multipath_uplink_count);

		for(int i = 0; i < MAX_UPLINKS; i++) {
			multipath_uplink_t *u = &multipath_uplinks[i];

			if(!u->in_use) {
				continue;
			}

			send_request(c, "%d %d 1 uplink %d %s %s %d %d 0x%x %llu %llu %llu",
			             CONTROL, REQ_MULTIPATH, i, u->name,
			             u->is_up ? "UP" : "DOWN",
			             u->weight, u->is_backup ? 1 : 0, u->fwmark,
			             (unsigned long long)u->net_handle,
			             (unsigned long long)u->tx_packets,
			             (unsigned long long)u->rx_packets);
		}

		for splay_each(node_t, n, &node_tree) {
			if(n == myself || (!n->connection && !n->connections.count)) {
				continue;
			}

			int active_paths = 0;

			for(int i = 0; i < MAX_NODE_PATHS; i++) {
				if(n->paths[i].active && n->paths[i].confirmed) {
					active_paths++;
				}
			}

			send_request(c, "%d %d 1 node %s conns=%u udp_paths=%d primary_uplink=%d",
			             CONTROL, REQ_MULTIPATH, n->name,
			             n->connections.count, active_paths,
			             n->connection ? n->connection->uplink_idx : -1);
		}

		return send_request(c, "%d %d 2", CONTROL, REQ_MULTIPATH);
	}

	if(!strcasecmp(subcmd, "detail")) {
		char self_ip[64];
		node_primary_ipv4_str(myself, self_ip, sizeof(self_ip));
		send_request(c, "%d %d 0 summary name=%s vpn_ip=%s mode=%s target_conns=%d uplinks=%d maxoutbuf=%d",
		             CONTROL, REQ_MULTIPATH,
		             (myself && myself->name) ? myself->name : "-",
		             self_ip,
		             multipath_mode_name(multipath_mode),
		             multipath_target_connections,
		             multipath_uplink_count,
		             maxoutbufsize);

		for(int i = 0; i < MAX_UPLINKS; i++) {
			multipath_uplink_t *u = &multipath_uplinks[i];

			if(!u->in_use) {
				continue;
			}

			send_request(c, "%d %d 1 uplink idx=%d name=%s state=%s weight=%d backup=%d mark=0x%x handle=%llu tx=%llu rx=%llu",
			             CONTROL, REQ_MULTIPATH, i, u->name,
			             u->is_up ? "UP" : "DOWN",
			             u->weight, u->is_backup ? 1 : 0, u->fwmark,
			             (unsigned long long)u->net_handle,
			             (unsigned long long)u->tx_packets,
			             (unsigned long long)u->rx_packets);
		}

		for splay_each(node_t, n, &node_tree) {
			if(n == myself) {
				continue;
			}

			int active_paths = 0;

			for(int i = 0; i < MAX_NODE_PATHS; i++) {
				if(n->paths[i].active && n->paths[i].confirmed) {
					active_paths++;
				}
			}

			int nconns = n->connections.count ? (int)n->connections.count : (n->connection ? 1 : 0);
			bool has_primary_in_list = false;

			if(n->connection && n->connections.count) {
				for list_each(connection_t, cand, &n->connections) {
					if(cand == n->connection) {
						has_primary_in_list = true;
						break;
					}
				}

				if(!has_primary_in_list) {
					nconns++;
				}
			}

			char vpn_ip[64];
			char prefb[128];
			char udp_ep[160];
			node_primary_ipv4_str(n, vpn_ip, sizeof(vpn_ip));
			format_node_pref_transports(n, prefb, sizeof(prefb));
			format_endpoint_token(&n->address, udp_ep, sizeof(udp_ep));

			double udp_rtt_ms = (n->status.udp_confirmed && n->udp_ping_rtt >= 0)
			                    ? (double)n->udp_ping_rtt / 1000.0
			                    : -1.0;

			send_request(c,
			             "%d %d 1 node name=%s reachable=%d direct=%d via=%s nexthop=%s vpn_ip=%s conns=%d udp_ok=%d udp_rtt_ms=%.3f udp_paths=%d udp_unans=%d udp_ep=%s mtu=%d minmtu=%d maxmtu=%d tcponly=%d no_direct=%d pref=%s tx_seq=%u rx_seq=%u rx_ok=%u in_pkts=%llu out_pkts=%llu in_bytes=%llu out_bytes=%llu primary_uplink=%d tcp_pacing_Bps=%u auto_pacing=%d auto_budget_Bps=%u policer_Bps=%u",
			             CONTROL, REQ_MULTIPATH,
			             n->name,
			             n->status.reachable ? 1 : 0,
			             (n->connection != NULL || n->connections.count > 0) ? 1 : 0,
			             (n->via && n->via->name) ? n->via->name : "-",
			             (n->nexthop && n->nexthop->name) ? n->nexthop->name : "-",
			             vpn_ip,
			             nconns,
			             n->status.udp_confirmed ? 1 : 0,
			             udp_rtt_ms,
			             active_paths,
			             n->udp_ping_unanswered,
			             udp_ep,
			             (int)n->mtu,
			             (int)n->minmtu,
			             (int)n->maxmtu,
			             node_tcponly(n) ? 1 : 0,
			             (n->status.no_direct || n->remote_no_direct || node_is_no_direct(n->name)) ? 1 : 0,
			             prefb,
			             n->sent_seqno,
			             n->received_seqno,
			             n->received,
			             (unsigned long long)n->in_packets,
			             (unsigned long long)n->out_packets,
			             (unsigned long long)n->in_bytes,
			             (unsigned long long)n->out_bytes,
			             n->connection ? n->connection->uplink_idx : -1,
			             node_effective_pacing_budget(n),
			             multipath_node_auto_pacing_enabled(n) ? 1 : 0,
			             n->auto_pacing_budget_Bps,
			             n->auto_pacing_policer_Bps);

			bool emitted_primary = false;

			for list_each(connection_t, conn, &n->connections) {
				if(conn == n->connection) {
					emitted_primary = true;
				}

				emit_conn_detail(c, n, conn, now.tv_sec);
			}

			if(n->connection && !emitted_primary) {
				emit_conn_detail(c, n, n->connection, now.tv_sec);
			}
		}

		return send_request(c, "%d %d 2", CONTROL, REQ_MULTIPATH);
	}

	if(!strcasecmp(subcmd, "recycle")) {
		char arg1[128] = "all";
		char arg2[64] = "slow";
		int parsed = sscanf(request, "%*d %*d %*s %127s %63s", arg1, arg2);
		bool target_all_peers = true;
		bool all_secondary = false;
		node_t *target_node = NULL;

		if(parsed >= 1) {
			if(!strcasecmp(arg1, "slow")) {
				target_all_peers = true;
				all_secondary = false;
			} else if(!strcasecmp(arg1, "all")) {
				target_all_peers = true;
				all_secondary = (parsed >= 2 && !strcasecmp(arg2, "all"));
			} else {
				target_all_peers = false;
				target_node = lookup_node(arg1);

				if(!target_node || target_node == myself) {
					return send_request(c, "%d %d -2", CONTROL, REQ_MULTIPATH);
				}

				if(parsed >= 2 && (!strcasecmp(arg2, "all") || !strcasecmp(arg2, "force"))) {
					all_secondary = true;
				}
			}
		}

		int promoted = 0;
		int recycled = 0;

		if(target_all_peers) {
			for splay_each(node_t, n, &node_tree) {
				if(n == myself) {
					continue;
				}

				recycle_node_conns(c, n, all_secondary, &promoted, &recycled);
			}
		} else {
			recycle_node_conns(c, target_node, all_secondary, &promoted, &recycled);
		}

		if(recycled > 0) {
			multipath_maintain();
		}

		send_request(c, "%d %d 0 promoted=%d recycled=%d",
		             CONTROL, REQ_MULTIPATH, promoted, recycled);
		return send_request(c, "%d %d 2", CONTROL, REQ_MULTIPATH);
	}

	if(!strcasecmp(subcmd, "mode")) {
		char mstr[64] = "";
		int conns = multipath_target_connections;

		if(sscanf(request, "%*d %*d %*s %63s %d", mstr, &conns) < 1) {
			return send_request(c, "%d %d -1", CONTROL, REQ_MULTIPATH);
		}

		multipath_mode_t m;

		if(!multipath_parse_mode(mstr, &m)) {
			return send_request(c, "%d %d -1", CONTROL, REQ_MULTIPATH);
		}

		multipath_mode = m;
		multipath_target_connections = CLAMP(conns, 1, MAX_MULTIPATH_CONNECTIONS);
		multipath_maintain();
		return send_request(c, "%d %d 0", CONTROL, REQ_MULTIPATH);
	}

	if(!strcasecmp(subcmd, "uplink")) {
		char action[32] = "";
		char name[64] = "";
		char ip[128] = "-";
		int weight = 100;
		int backup = 0;
		int mark = 0;
		unsigned long long handle = 0;
		int up = 1;

		int parsed = sscanf(request, "%*d %*d %*s %31s %63s %127s %d %d %i %llu %d",
		                    action, name, ip, &weight, &backup, &mark, &handle, &up);

		if(parsed < 2) {
			return send_request(c, "%d %d -1", CONTROL, REQ_MULTIPATH);
		}

		if(!strcasecmp(action, "del") || !strcasecmp(action, "remove")) {
			bool ok = multipath_remove_uplink(name);
			return send_request(c, "%d %d %d", CONTROL, REQ_MULTIPATH, ok ? 0 : -1);
		}

		if(!strcasecmp(action, "add") || !strcasecmp(action, "set") || !strcasecmp(action, "update")) {
			int idx = multipath_upsert_uplink(name, ip, weight, backup != 0, mark, (uint64_t)handle, up != 0);
			return send_request(c, "%d %d %d", CONTROL, REQ_MULTIPATH, idx >= 0 ? 0 : -1);
		}
	}

	if(!strcasecmp(subcmd, "pacing")) {
		char target[128] = "all";
		char val[64] = "";
		int parsed = sscanf(request, "%*d %*d %*s %127s %63s", target, val);

		if(parsed < 1) {
			return send_request(c, "%d %d -1", CONTROL, REQ_MULTIPATH);
		}

		node_t *single = strcasecmp(target, "all") ? lookup_node(target) : NULL;

		if(strcasecmp(target, "all") && (!single || single == myself)) {
			return send_request(c, "%d %d -2", CONTROL, REQ_MULTIPATH);
		}

		if(parsed >= 2) {
			if(!strcasecmp(val, "auto")) {
				if(single) {
					single->tcp_auto_pacing_override = 1;
				} else {
					multipath_tcp_auto_pacing = true;
				}
			} else if(!strcasecmp(val, "off")) {
				if(single) {
					single->tcp_auto_pacing_override = -1;
					single->auto_pacing_budget_Bps = 0;
				} else {
					multipath_tcp_auto_pacing = false;

					for splay_each(node_t, n, &node_tree) {
						n->auto_pacing_budget_Bps = 0;
					}
				}
			} else if(!strcasecmp(val, "reset")) {
				for splay_each(node_t, n, &node_tree) {
					if(single && n != single) {
						continue;
					}

					n->auto_pacing_budget_Bps = 0;
					n->auto_pacing_policer_Bps = 0;
					n->auto_pacing_next_probe_at = 0;
				}
			} else {
				unsigned long bps = strtoul(val, NULL, 10);

				if(single) {
					single->tcp_max_pacing_rate = (uint32_t)bps;
					single->auto_pacing_budget_Bps = 0;
				} else {
					multipath_tcp_max_pacing_rate = (uint32_t)bps;
					multipath_tcp_auto_pacing = (bps == 0);
				}
			}

			for splay_each(node_t, n, &node_tree) {
				if(n != myself && (!single || n == single)) {
					multipath_apply_node_tcp_pacing(n, NULL, 0);
				}
			}
		}

		for splay_each(node_t, n, &node_tree) {
			if(n == myself || (single && n != single)) {
				continue;
			}

			send_request(c, "%d %d 1 pacing peer=%s auto=%d effective_Bps=%u manual_Bps=%u auto_budget_Bps=%u policer_Bps=%u",
			             CONTROL, REQ_MULTIPATH, n->name,
			             multipath_node_auto_pacing_enabled(n) ? 1 : 0,
			             node_effective_pacing_budget(n),
			             node_manual_pacing_cap(n),
			             n->auto_pacing_budget_Bps,
			             n->auto_pacing_policer_Bps);
		}

		return send_request(c, "%d %d 2", CONTROL, REQ_MULTIPATH);
	}

	return send_request(c, "%d %d -1", CONTROL, REQ_MULTIPATH);
}

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

#ifdef HAVE_LINUX
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#if defined(__ANDROID__) || defined(HAVE_ANDROID)
#include <dlfcn.h>
#endif

#include "address_cache.h"
#include "conf.h"
#include "connection.h"
#include "control_common.h"
#include "edge.h"
#include "ethernet.h"
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
#include "utils.h"
#include "xalloc.h"

multipath_mode_t multipath_mode = MULTIPATH_FAILOVER;
int multipath_target_connections = 1;
multipath_uplink_t multipath_uplinks[MAX_UPLINKS];
int multipath_uplink_count = 0;

/* Set while processing an inbound packet from a dedicated uplink UDP socket */
extern int multipath_current_rx_uplink;

static timeout_t multipath_timer;
static bool multipath_initialized = false;

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
	sockaddr_t addr = {0};
	socklen_t addrlen = sizeof(addr);
	pkt.offset = 0;

	ssize_t len = recvfrom(multipath_uplinks[idx].udp_fd_v4, (void *)DATA(&pkt), MAXSIZE, 0, &addr.sa, &addrlen);

	if(len <= 0 || (size_t)len > MAXSIZE) {
		return;
	}

	pkt.len = (size_t)len;
	multipath_uplinks[idx].rx_packets++;
	multipath_uplinks[idx].rx_bytes += (uint64_t)len;

	listen_socket_t *ls = listen_sockets > 0 ? &listen_socket[0] : NULL;

	for(int i = 0; i < listen_sockets; i++) {
		if(listen_socket[i].sa.sa.sa_family == AF_INET) {
			ls = &listen_socket[i];
			break;
		}
	}

	if(ls) {
		handle_incoming_vpn_packet_uplink(idx, ls, &pkt, &addr);
	}
}

static void handle_uplink_udp_v6(void *data, int flags) {
	(void)flags;
	int idx = (int)(intptr_t)data;

	if(idx < 0 || idx >= MAX_UPLINKS || !multipath_uplinks[idx].in_use || multipath_uplinks[idx].udp_fd_v6 < 0) {
		return;
	}

	vpn_packet_t pkt;
	sockaddr_t addr = {0};
	socklen_t addrlen = sizeof(addr);
	pkt.offset = 0;

	ssize_t len = recvfrom(multipath_uplinks[idx].udp_fd_v6, (void *)DATA(&pkt), MAXSIZE, 0, &addr.sa, &addrlen);

	if(len <= 0 || (size_t)len > MAXSIZE) {
		return;
	}

	pkt.len = (size_t)len;
	multipath_uplinks[idx].rx_packets++;
	multipath_uplinks[idx].rx_bytes += (uint64_t)len;

	listen_socket_t *ls = listen_sockets > 0 ? &listen_socket[0] : NULL;

	for(int i = 0; i < listen_sockets; i++) {
		if(listen_socket[i].sa.sa.sa_family == AF_INET6) {
			ls = &listen_socket[i];
			break;
		}
	}

	if(ls) {
		handle_incoming_vpn_packet_uplink(idx, ls, &pkt, &addr);
	}
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

static int open_uplink_udp_socket(int idx, int af) {
	int fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);

	if(fd < 0) {
		return -1;
	}

#ifdef FD_CLOEXEC
	fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif

#ifdef O_NONBLOCK
	int flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#elif defined(HAVE_WINDOWS)
	unsigned long arg = 1;
	ioctlsocket(fd, FIONBIO, &arg);
#endif

#if defined(IPV6_V6ONLY)
	if(af == AF_INET6) {
		int option = 1;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof(option));
	}
#endif

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

		if(fn) {
			if(fn(u->net_handle, fd) != 0) {
				logger(DEBUG_CONNECTIONS, LOG_WARNING,
				       "multipath: android_setsocknetwork(%"PRIu64") on %s failed: %s",
				       u->net_handle, u->name, strerror(errno));
			}
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

		if(af == AF_INET6 && multipath_uplinks[uplink_idx].udp_fd_v6 >= 0) {
			return multipath_uplinks[uplink_idx].udp_fd_v6;
		}
	}

	if(fallback_sock_idx >= 0 && fallback_sock_idx < listen_sockets) {
		return listen_socket[fallback_sock_idx].udp.fd;
	}

	return listen_sockets > 0 ? listen_socket[0].udp.fd : -1;
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

			if(multipath_initialized) {
				multipath_maintain();
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

			return true;
		}
	}

	return false;
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
				if(c->uplink_idx == i) {
					used++;
				}
			}

			for list_each(connection_t, c, &connection_list) {
				if(c->status.connecting && c->name && !strcmp(c->name, n->name) && c->uplink_idx == i) {
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

		for(struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (unsigned int)len); nh = NLMSG_NEXT(nh, len)) {
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

/* ---- Multi-Connection Pool & Make-Before-Break Failover ------------------ */

void multipath_node_add_connection(node_t *n, connection_t *c) {
	if(!n || !c) {
		return;
	}

	for list_each(connection_t, existing, &n->connections) {
		if(existing == c) {
			return;
		}
	}

	list_insert_tail(&n->connections, c);
}

void multipath_node_del_connection(node_t *n, connection_t *c) {
	if(!n || !c) {
		return;
	}

	list_delete(&n->connections, c);
}

/* Called in ack_h() when a new connection `c` to `n` completes authentication
   while `n->connection` already exists.
   Returns true if `c` is accepted into `n->connections` without terminating
   `n->connection` (zero-drop parallel connection / make-before-break). */
bool multipath_accept_secondary(node_t *n, connection_t *c) {
	if(!n || !c || !n->connection || n->connection == c) {
		return false;
	}

	if(multipath_mode == MULTIPATH_OFF) {
		return false;
	}

	multipath_node_add_connection(n, n->connection);

	/* If n->connections already reached the cap, check if the oldest secondary
	   or the primary is stale (e.g. missed keepalive or on a DOWN uplink). */
	int max_conns = MAX(multipath_target_connections, 2);

	if((int)n->connections.count >= max_conns) {
		connection_t *victim = NULL;

		for list_each(connection_t, cand, &n->connections) {
			if(cand == n->connection) {
				continue;
			}

			if(!multipath_uplink_is_healthy(cand->uplink_idx) || cand->status.pinged) {
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
	multipath_node_add_connection(n, c);

	/* If the existing primary connection is on a downed uplink or waiting on
	   a ping timeout while `c` is fresh and healthy, seamlessly promote `c`
	   to primary right now without deleting the edge or running graph()! */
	connection_t *old_primary = n->connection;
	bool old_unhealthy = !multipath_uplink_is_healthy(old_primary->uplink_idx) ||
	                     old_primary->status.pinged;

	if(old_unhealthy && old_primary->edge) {
		c->edge = old_primary->edge;
		c->edge->connection = c;
		c->edge->address = c->address;
		old_primary->edge = NULL;
		old_primary->status.multipath_sub = true;
		c->status.multipath_sub = false;
		n->connection = c;

		if(old_primary->outgoing && !c->outgoing) {
			c->outgoing = old_primary->outgoing;
			old_primary->outgoing = NULL;
		}

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

			if(pass == 0 && (!multipath_uplink_is_healthy(cand->uplink_idx) || cand->status.pinged)) {
				continue;
			}

			survivor = cand;
			break;
		}
	}

	if(!survivor) {
		return false;
	}

	if(dying->edge) {
		survivor->edge = dying->edge;
		survivor->edge->connection = survivor;
		survivor->edge->address = survivor->address;
		dying->edge = NULL;
	}

	if(dying->outgoing && !survivor->outgoing) {
		survivor->outgoing = dying->outgoing;
		dying->outgoing = NULL;
	}

	survivor->status.multipath_sub = false;
	n->connection = survivor;

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

		if(old->edge) {
			c->edge = old->edge;
			c->edge->connection = c;
			c->edge->address = c->address;
			old->edge = NULL;
		}

		if(old->outgoing && !c->outgoing) {
			c->outgoing = old->outgoing;
			old->outgoing = NULL;
		}

		old->status.multipath_sub = true;
		c->status.multipath_sub = false;
		n->connection = c;
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
	if(!n || !addr || n == myself) {
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
		memset(p, 0, sizeof(*p));
		p->active = true;
		p->uplink_idx = uplink_idx;
		p->sock_idx = sock_idx >= 0 ? sock_idx : (int)n->sock;
		p->addr = clean;
		p->srtt_us = n->udp_ping_rtt > 0 ? (uint32_t)n->udp_ping_rtt : 50000;
	}

	p->confirmed = true;
	p->last_rx = now.tv_sec;
	p->rx_packets++;
	p->rx_bytes += (uint64_t)len;
}

void multipath_update_udp_rtt(node_t *n, const sockaddr_t *addr, uint32_t rtt_us) {
	if(!n || !addr || rtt_us == 0) {
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
				p->srtt_us = (p->srtt_us * 7 + rtt_us) / 8;
			}
		}
	}
}

void multipath_probe_node_paths(node_t *n, const void *probe_pkt, size_t len) {
	if(!n || n->status.no_direct || !probe_pkt || !len || multipath_mode == MULTIPATH_OFF || multipath_uplink_count <= 0) {
		return;
	}

	const sockaddr_t *dst = &n->address;

	if(dst->sa.sa_family != AF_INET && dst->sa.sa_family != AF_INET6) {
		return;
	}

	for(int u = 0; u < MAX_UPLINKS; u++) {
		if(!multipath_uplinks[u].in_use || !multipath_uplinks[u].is_up) {
			continue;
		}

		int fd = multipath_get_udp_fd(u, dst->sa.sa_family, n->sock);

		if(fd < 0) {
			continue;
		}

		size_t excess = 0;

		if(obfs_wrap_send_fd(fd, n->sock, dst, probe_pkt, len, n, &excess) != OBFS_SEND_PLAIN) {
			continue;
		}

		dseal_verdict_t dv = dseal_verdict(n);

		if(dv == DSEAL_SEND_SEAL) {
			obfs_seal_send_fd(fd, n->sock, dst, probe_pkt, len, n, &excess);
			continue;
		} else if(dv == DSEAL_SEND_HOLD || dv == DSEAL_SEND_BLOCK) {
			continue;
		}

		sendto(fd, probe_pkt, len, 0, &dst->sa, SALEN(dst->sa));
	}
}

/* ---- 5-Tuple Inner Packet Flow Hash (Zero Intra-Flow Reordering) --------- */

uint32_t multipath_flow_hash(const vpn_packet_t *pkt) {
	if(!pkt || pkt->len < 14) {
		return 0;
	}

	const uint8_t *p = DATA(pkt);
	size_t len = pkt->len;

	/* Skip Ethernet header if present (Switch/Hub mode or TAP) */
	uint16_t ether_type = 0;

	if(routing_mode != RMODE_ROUTER && len >= sizeof(struct ether_header)) {
		ether_type = ((uint16_t)p[12] << 8) | p[13];
		p += sizeof(struct ether_header);
		len -= sizeof(struct ether_header);

		/* 802.1Q VLAN tag */
		if(ether_type == 0x8100 && len >= 4) {
			ether_type = ((uint16_t)p[2] << 8) | p[3];
			p += 4;
			len -= 4;
		}
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

int multipath_select_connections(node_t *n, const vpn_packet_t *pkt, connection_t *out[2]) {
	out[0] = NULL;
	out[1] = NULL;

	if(!n) {
		return 0;
	}

	if(multipath_mode == MULTIPATH_OFF || n->connections.count <= 1) {
		if(n->connection) {
			out[0] = n->connection;
			return 1;
		}

		return 0;
	}

	connection_t *cands[MAX_MULTIPATH_CONNECTIONS * 2];
	int ncands = 0;

	/* First collect healthy non-backup connections; if none, allow backup uplinks */
	for(int pass = 0; pass < 2 && ncands == 0; pass++) {
		bool allow_backup = (pass == 1);

		for list_each(connection_t, c, &n->connections) {
			if(!connection_is_usable(c, allow_backup)) {
				continue;
			}

			if(pass == 0 && c->status.pinged) {
				continue;
			}

			if(ncands < (int)(sizeof(cands) / sizeof(cands[0]))) {
				cands[ncands++] = c;
			}
		}
	}

	if(ncands == 0) {
		if(n->connection) {
			out[0] = n->connection;
			return 1;
		}

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
		uint32_t h = pkt ? multipath_flow_hash(pkt) : n->mp_rr_cursor++;
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
		uint32_t h = pkt ? multipath_flow_hash(pkt) : n->mp_rr_cursor++;
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
		if(c->status.connecting && c->name && !strcmp(c->name, n->name)) {
			count++;
		}
	}

	return count;
}

/* Open a secondary parallel carrier connection to `outgoing->node` without
   disturbing the primary `n->connection`. */
static void dial_secondary_connection(outgoing_t *outgoing) {
	node_t *n = outgoing->node;

	if(!n || !n->connection || !n->address_cache) {
		return;
	}

	const transport_t *t = n->connection->transport ? n->connection->transport : transport_current(outgoing);

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

	const sockaddr_t *sa = NULL;

	for(int attempt = 0; attempt < 8; attempt++) {
		const sockaddr_t *cand = get_recent_address(n->address_cache);

		if(!cand) {
			break;
		}

		bool already_used = false;

		for list_each(connection_t, existing, &n->connections) {
			if(!sockaddrcmp_noport(cand, &existing->base_address) ||
			                !sockaddrcmp_noport(cand, &existing->address)) {
				already_used = true;
				break;
			}
		}

		if(!already_used) {
			sa = cand;
			break;
		}
	}

	if(!sa) {
		reset_address_cache(n->address_cache);
		sa = &n->connection->base_address;
	}

	if(!sa->sa.sa_family) {
		sa = &n->connection->address;
	}

	if(!sa->sa.sa_family) {
		return;
	}

	connection_t *c = new_connection();
	c->outgoing = NULL; /* Primary connection owns `outgoing`; secondary is self-contained */
	memcpy(&c->address, sa, SALEN(sa->sa));
	memcpy(&c->base_address, sa, SALEN(sa->sa));
	c->hostname = sockaddr2hostname(&c->address);
	c->name = xstrdup(n->name);
	c->outmaclength = myself->connection->outmaclength;
	c->last_ping_time = now.tv_sec;
	c->transport = t;
	c->uplink_idx = multipath_pick_next_uplink(n);
	c->status.multipath_sub = true;

	logger(DEBUG_CONNECTIONS, LOG_INFO,
	       "multipath: dialling parallel connection to %s (%s) via %s (uplink=%d)",
	       n->name, c->hostname, t->name, c->uplink_idx);

	if(!t->dial(c)) {
		free_connection(c);
	}
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

	/* If the primary connection of any node is sitting on a DOWN uplink while a
	   healthy secondary connection is ready in n->connections, swap them now! */
	for splay_each(node_t, n, &node_tree) {
		if(!n->connection || n->connections.count <= 1) {
			continue;
		}

		if(!multipath_uplink_is_healthy(n->connection->uplink_idx)) {
			for list_each(connection_t, cand, &n->connections) {
				if(cand != n->connection && cand->status.active && multipath_uplink_is_healthy(cand->uplink_idx)) {
					if(n->connection->edge) {
						cand->edge = n->connection->edge;
						cand->edge->connection = cand;
						cand->edge->address = cand->address;
						n->connection->edge = NULL;
					}

					if(n->connection->outgoing && !cand->outgoing) {
						cand->outgoing = n->connection->outgoing;
						n->connection->outgoing = NULL;
					}

					n->connection->status.multipath_sub = true;
					cand->status.multipath_sub = false;
					n->connection = cand;
					logger(DEBUG_CONNECTIONS, LOG_NOTICE,
					       "multipath: switched primary connection of %s to healthy uplink %d",
					       n->name, cand->uplink_idx);
					break;
				}
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
     CONTROL REQ_MULTIPATH mode <off|failover|flowhash|redundant|split> [connections]
     CONTROL REQ_MULTIPATH uplink add <name> <ip|-> <weight> <backup:0|1> <mark> <net_handle> <up:0|1>
     CONTROL REQ_MULTIPATH uplink del <name>
*/

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

	return send_request(c, "%d %d -1", CONTROL, REQ_MULTIPATH);
}

#ifndef TINC_MULTIPATH_H
#define TINC_MULTIPATH_H

/*
    multipath.h -- Hybrid Application-Level Multipath & Multi-WAN engine.

    Provides application-layer multipath scheduling, parallel connection
    pooling, make-before-break 0-ms failover, multi-interface/multi-gateway
    socket binding (Linux SO_BINDTODEVICE/SO_MARK + Netlink, Android
    android_setsocknetwork Wi-Fi + Cellular, Windows IP_UNICAST_IF), and
    post-handshake QUIC path migration without any wire-level protocol
    demasking (School A wire rules preserved 100%).
*/

#include "system.h"
#include "event.h"
#include "list.h"
#include "net.h"

struct node_t;
struct connection_t;
struct vpn_packet_t;

#define MAX_UPLINKS               8
#define MAX_NODE_PATHS            4
#define MAX_MULTIPATH_CONNECTIONS 4

typedef enum multipath_mode_t {
	MULTIPATH_OFF = 0,       /* Single connection, single path (legacy) */
	MULTIPATH_FAILOVER = 1,  /* Make-before-break 0-ms failover (default) */
	MULTIPATH_FLOWHASH = 2,  /* 5-tuple inner flow hash across active paths/connections */
	MULTIPATH_REDUNDANT = 3, /* Duplicate packets across top 2 paths/connections (SPTPS deduplicates) */
	MULTIPATH_SPLIT = 4,     /* Burst-boundary rotational splitting across paths/connections (anti-DPI) */
} multipath_mode_t;

/* Local physical/logical uplink (WAN interface, gateway, or Android Network handle). */
typedef struct multipath_uplink_t {
	bool in_use;
	char name[64];           /* Interface name (e.g. wlan0, rmnet_data0, eth0) or label */
	sockaddr_t local_v4;     /* Optional local IPv4 address for source bind */
	bool have_v4;
	sockaddr_t local_v6;     /* Optional local IPv6 address for source bind */
	bool have_v6;
	uint32_t ifindex;        /* OS interface index (if_nametoindex) */
	int fwmark;              /* Optional per-uplink Linux fwmark (policy routing table) */
	uint64_t net_handle;     /* Android Network.getNetworkHandle() for android_setsocknetwork() */
	int weight;              /* Relative scheduling weight (1..100, default 100) */
	bool is_backup;          /* Standby/backup uplink (used only when primary uplinks degrade/fail) */
	bool is_up;              /* Link + address + route operational state */

	/* Dedicated non-blocking UDP sockets bound to this uplink so UDP/obfs/dseal
	   traffic can traverse multiple WAN interfaces simultaneously regardless of
	   the OS default route. */
	int udp_fd_v4;
	int udp_fd_v6;
	io_t io_v4;
	io_t io_v6;

	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t rx_packets;
	uint64_t rx_bytes;
} multipath_uplink_t;

/* Per-node UDP data path entry (stored in node_t->paths[MAX_NODE_PATHS]). */
typedef struct node_path_t {
	bool active;
	bool confirmed;
	int uplink_idx;          /* -1 for default listen_socket, or 0..MAX_UPLINKS-1 */
	int sock_idx;            /* Fallback index into listen_socket[] */
	sockaddr_t addr;         /* Remote peer UDP address on this path */
	uint32_t srtt_us;        /* Smoothed RTT in microseconds (0 = unknown) */
	time_t last_rx;          /* Last time a valid packet arrived on this path */
	time_t last_tx;          /* Last time we transmitted on this path */
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t rx_packets;
	uint64_t rx_bytes;
} node_path_t;

extern multipath_mode_t multipath_mode;
extern int multipath_target_connections;
extern multipath_uplink_t multipath_uplinks[MAX_UPLINKS];
extern int multipath_uplink_count;

/* Lifecycle & configuration */
void multipath_read_config(void);
void multipath_init(void);
void multipath_exit(void);
const char *multipath_mode_name(multipath_mode_t mode);
bool multipath_parse_mode(const char *str, multipath_mode_t *out);

/* Uplink management & cross-platform socket binding */
int multipath_upsert_uplink(const char *name, const char *local_ip, int weight,
                            bool is_backup, int mark, uint64_t net_handle, bool is_up);
bool multipath_remove_uplink(const char *name);
int multipath_pick_next_uplink(const struct node_t *n);
int multipath_get_tx_uplink(const struct node_t *n);
bool multipath_bind_socket(int fd, int af, int uplink_idx);
int multipath_get_udp_fd(int uplink_idx, int af, int fallback_sock_idx);
bool multipath_owns_udp_fd(int fd);
bool multipath_uplink_is_healthy(int uplink_idx);

/* Multi-connection pool & make-before-break failover */
bool multipath_accept_secondary(struct node_t *n, struct connection_t *c);
bool multipath_promote_survivor(struct node_t *n, struct connection_t *dying);
void multipath_peer_promoted_solo(struct connection_t *c);
void multipath_node_add_connection(struct node_t *n, struct connection_t *c);
void multipath_node_del_connection(struct node_t *n, struct connection_t *c);
void multipath_maintain(void);

/* Per-node UDP path tracking & probing */
void multipath_record_udp_rx(struct node_t *n, int uplink_idx, int sock_idx,
                             const sockaddr_t *addr, size_t len);
void multipath_update_udp_rtt(struct node_t *n, const sockaddr_t *addr, uint32_t rtt_us);
void multipath_probe_node_paths(struct node_t *n, const void *probe_payload, size_t payload_len);
bool send_sptps_probe_on_path(struct node_t *n, int uplink_idx, size_t sock_idx,
                              const sockaddr_t *dst, const void *probe_payload, size_t payload_len);

/* Packet schedulers (returns number of selected connections/paths: 0, 1, or 2) */
uint32_t multipath_flow_hash(const struct vpn_packet_t *pkt);
int multipath_select_connections(struct node_t *n, const struct vpn_packet_t *pkt,
                                 struct connection_t *out[2]);
int multipath_select_udp_paths(struct node_t *n, const struct vpn_packet_t *pkt,
                               node_path_t *out[2]);

/* Control socket handler (REQ_MULTIPATH) */
bool control_multipath_h(struct connection_t *c, const char *request);

#endif /* TINC_MULTIPATH_H */

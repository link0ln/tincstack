/*
    diag.c -- In-tunnel diagnostic probes (ICMP ping/traceroute/PMTU) and
              user-space TCP-to-localhost bridge for the Diagnostic Web Panel.
*/

#include "system.h"

#include "conf.h"
#include "connection.h"
#include "control_common.h"
#include "diag.h"
#include "ethernet.h"
#include "event.h"
#include "ipv4.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "node.h"
#include "protocol.h"
#include "route.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

#define DIAG_TH_FIN  0x01
#define DIAG_TH_SYN  0x02
#define DIAG_TH_RST  0x04
#define DIAG_TH_PUSH 0x08
#define DIAG_TH_ACK  0x10

#define MAX_DIAG_TCP_CONNS 16
#define MAX_DIAG_PING_REQS 32
#define DIAG_TCP_MSS       1160
#define DIAG_TCP_INFLIGHT  16384
#define DIAG_TCP_TX_CAP    65536
#define DIAG_TCP_RX_CAP    16384
#define DIAG_TCP_IDLE_S    30
#define DIAG_TCP_RTO_US    300000L

typedef struct diag_ping_req_t {
	connection_t *c;
	uint16_t seq;
	uint8_t ttl;
	uint16_t size;
	char dst_str[64];
	struct timeval sent_tv;
	timeout_t timer;
	struct diag_ping_req_t *next;
} diag_ping_req_t;

typedef struct diag_tcp_conn_t {
	bool active;
	ipv4_t peer_ip;
	ipv4_t my_ip;
	uint16_t peer_port;
	uint16_t my_port;

	int fd;
	io_t io;
	bool local_connected;
	bool local_eof;

	uint32_t irs;
	uint32_t rcv_nxt;
	uint32_t iss;
	uint32_t tx_una_seq;
	uint32_t peer_wnd;
	bool syn_acked;
	bool fin_sent;
	bool fin_acked;
	bool peer_fin;

	time_t last_activity;
	struct timeval last_tx_tv;
	int rto_count;

	size_t rx_off;
	size_t rx_len;
	uint8_t rx_buf[DIAG_TCP_RX_CAP];

	size_t tx_sent_offset;
	size_t tx_len;
	uint8_t tx_buf[DIAG_TCP_TX_CAP];
} diag_tcp_conn_t;

static int diag_port = 0;
static bool diag_port_runtime_set = false;
static uint16_t diag_ping_seq = 1;
static uint16_t diag_ip_id = 1;
static diag_ping_req_t *ping_reqs = NULL;
static diag_tcp_conn_t *tcp_conns[MAX_DIAG_TCP_CONNS] = {0};
static timeout_t tcp_retransmit_timer;

/* ---- Checksum helpers ---------------------------------------------------- */

static uint16_t diag_inet_checksum(const void *vdata, size_t len, uint16_t prevsum) {
	const uint8_t *data = vdata;
	uint16_t word;
	uint32_t checksum = prevsum ^ 0xFFFF;

	while(len >= 2) {
		memcpy(&word, data, sizeof(word));
		checksum += word;
		data += 2;
		len -= 2;
	}

	if(len) {
		checksum += *data;
	}

	while(checksum >> 16) {
		checksum = (checksum & 0xFFFF) + (checksum >> 16);
	}

	return (uint16_t)~checksum;
}

static uint16_t diag_tcp_checksum(ipv4_t src, ipv4_t dst, const void *tcp_data, size_t tcp_len) {
	struct {
		ipv4_t src;
		ipv4_t dst;
		uint8_t zero;
		uint8_t proto;
		uint16_t len;
	} pseudo;

	pseudo.src = src;
	pseudo.dst = dst;
	pseudo.zero = 0;
	pseudo.proto = IPPROTO_TCP;
	pseudo.len = htons((uint16_t)tcp_len);

	uint16_t csum = diag_inet_checksum(&pseudo, sizeof(pseudo), 0xFFFF);
	return diag_inet_checksum(tcp_data, tcp_len, csum);
}

/* ---- Own VPN IPv4 lookup ------------------------------------------------- */

bool diag_my_ipv4(ipv4_t *out) {
	if(!myself) {
		return false;
	}

	/* First preference: a /32 host subnet owned by myself. */
	for splay_each(subnet_t, s, &myself->subnet_tree) {
		if(s->type == SUBNET_IPV4 && s->net.ipv4.prefixlength == 32) {
			*out = s->net.ipv4.address;
			return true;
		}
	}

	/* Fallback: any non-zero IPv4 subnet owned by myself. */
	for splay_each(subnet_t, s, &myself->subnet_tree) {
		if(s->type == SUBNET_IPV4 &&
		                (s->net.ipv4.address.x[0] || s->net.ipv4.address.x[1] ||
		                 s->net.ipv4.address.x[2] || s->net.ipv4.address.x[3])) {
			*out = s->net.ipv4.address;
			return true;
		}
	}

	return false;
}

bool diag_is_probe_ipv4(const vpn_packet_t *packet) {
	const size_t eth_sz = sizeof(struct ether_header);

	if(packet->len < eth_sz + 20 + 8) {
		return false;
	}

	const uint8_t *d = DATA(packet);

	if(d[12] != 0x08 || d[13] != 0x00) {
		return false;
	}

	uint8_t ihl = (d[eth_sz] & 0x0f) * 4;

	if(ihl < 20 || packet->len < eth_sz + ihl + 8) {
		return false;
	}

	if(d[eth_sz + 9] != IPPROTO_ICMP) {
		return false;
	}

	const uint8_t *icmp_ptr = d + eth_sz + ihl;

	if(icmp_ptr[0] != ICMP_ECHO) {
		return false;
	}

	uint16_t id_net;
	memcpy(&id_net, icmp_ptr + 4, sizeof(id_net));
	return ntohs(id_net) == DIAG_ICMP_ID;
}

/* ---- TCP bridge to 127.0.0.1:<diag_port> --------------------------------- */

static void diag_tcp_conn_close(diag_tcp_conn_t *c) {
	if(!c) {
		return;
	}

	for(int i = 0; i < MAX_DIAG_TCP_CONNS; i++) {
		if(tcp_conns[i] == c) {
			tcp_conns[i] = NULL;
		}
	}

	if(c->io.cb) {
		io_del(&c->io);
	}

	if(c->fd >= 0) {
		closesocket(c->fd);
		c->fd = -1;
	}

	free(c);
}

static void diag_tcp_close_all(void) {
	for(int i = 0; i < MAX_DIAG_TCP_CONNS; i++) {
		if(tcp_conns[i]) {
			diag_tcp_conn_close(tcp_conns[i]);
		}
	}

	timeout_del(&tcp_retransmit_timer);
}

static void diag_tcp_send_segment(ipv4_t src_ip, ipv4_t dst_ip,
                                  uint16_t sport, uint16_t dport,
                                  uint32_t seq, uint32_t ack,
                                  uint8_t flags, uint16_t win,
                                  const uint8_t *payload, size_t payload_len,
                                  bool include_mss) {
	vpn_packet_t pkt;
	memset(&pkt, 0, sizeof(pkt));
	pkt.offset = DEFAULT_PACKET_OFFSET;
	pkt.priority = 0;

	const size_t eth_sz = sizeof(struct ether_header);
	const size_t opt_len = include_mss ? 4 : 0;
	const size_t tcp_hdr_len = 20 + opt_len;
	const size_t tcp_total = tcp_hdr_len + payload_len;
	const size_t ip_total = 20 + tcp_total;

	if(eth_sz + ip_total > MAXSIZE - pkt.offset) {
		return;
	}

	uint8_t *d = DATA(&pkt);
	memset(d, 0, eth_sz);
	d[12] = 0x08;
	d[13] = 0x00;

	/* IPv4 header */
	uint8_t *ip = d + eth_sz;
	ip[0] = 0x45;
	ip[1] = 0;
	uint16_t ip_len_net = htons((uint16_t)ip_total);
	memcpy(ip + 2, &ip_len_net, 2);
	uint16_t id_net = htons(++diag_ip_id);
	memcpy(ip + 4, &id_net, 2);
	ip[6] = 0x40; /* DF */
	ip[7] = 0x00;
	ip[8] = 64;   /* TTL */
	ip[9] = IPPROTO_TCP;
	ip[10] = 0;
	ip[11] = 0;
	memcpy(ip + 12, &src_ip, 4);
	memcpy(ip + 16, &dst_ip, 4);
	uint16_t ip_csum = diag_inet_checksum(ip, 20, 0xFFFF);
	memcpy(ip + 10, &ip_csum, 2);

	/* TCP header */
	uint8_t *tcp = ip + 20;
	uint16_t sport_net = htons(sport);
	uint16_t dport_net = htons(dport);
	uint32_t seq_net = htonl(seq);
	uint32_t ack_net = htonl(ack);
	uint16_t win_net = htons(win);

	memcpy(tcp + 0, &sport_net, 2);
	memcpy(tcp + 2, &dport_net, 2);
	memcpy(tcp + 4, &seq_net, 4);
	memcpy(tcp + 8, &ack_net, 4);
	tcp[12] = (uint8_t)((tcp_hdr_len / 4) << 4);
	tcp[13] = flags;
	memcpy(tcp + 14, &win_net, 2);
	memset(tcp + 16, 0, 4); /* checksum + urgent pointer */

	if(include_mss) {
		tcp[20] = 2; /* Kind: MSS */
		tcp[21] = 4; /* Length: 4 */
		uint16_t mss_net = htons(DIAG_TCP_MSS);
		memcpy(tcp + 22, &mss_net, 2);
	}

	if(payload_len > 0 && payload) {
		memcpy(tcp + tcp_hdr_len, payload, payload_len);
	}

	uint16_t tcp_csum = diag_tcp_checksum(src_ip, dst_ip, tcp, tcp_total);
	memcpy(tcp + 16, &tcp_csum, 2);

	pkt.len = (length_t)(eth_sz + ip_total);
	route(myself, &pkt);
}

static void diag_tcp_update_io(diag_tcp_conn_t *c) {
	if(!c || c->fd < 0 || !c->io.cb) {
		return;
	}

	int flags = 0;

	if(!c->local_connected) {
		flags = IO_READ | IO_WRITE;
	} else {
		if(c->rx_off < c->rx_len) {
			flags |= IO_WRITE;
		}

		if(!c->local_eof && c->tx_len < sizeof(c->tx_buf)) {
			flags |= IO_READ;
		}
	}

	io_set(&c->io, flags);
}

static void diag_tcp_flush_rx(diag_tcp_conn_t *c) {
	if(!c || !c->local_connected || c->fd < 0) {
		return;
	}

	int loops = 0;

	while(c->rx_off < c->rx_len && loops++ < 8) {
		ssize_t n = send(c->fd, (const char *)(c->rx_buf + c->rx_off), c->rx_len - c->rx_off, 0);

		if(n > 0) {
			c->rx_off += (size_t)n;
			continue;
		}

		if(n < 0 && sockwouldblock(sockerrno)) {
			break;
		}

		/* Local socket write error */
		c->local_eof = true;
		break;
	}

	if(c->rx_off == c->rx_len) {
		c->rx_off = 0;
		c->rx_len = 0;

		if(c->peer_fin && c->fd >= 0) {
#ifdef HAVE_WINDOWS
			shutdown(c->fd, SD_SEND);
#else
			shutdown(c->fd, SHUT_WR);
#endif
		}
	}
}

static void diag_tcp_read_local(diag_tcp_conn_t *c) {
	if(!c || !c->local_connected || c->local_eof || c->fd < 0) {
		return;
	}

	int loops = 0;

	while(c->tx_len < sizeof(c->tx_buf) && loops++ < 8) {
		ssize_t n = recv(c->fd, (char *)(c->tx_buf + c->tx_len), sizeof(c->tx_buf) - c->tx_len, 0);

		if(n > 0) {
			c->tx_len += (size_t)n;
			c->last_activity = now.tv_sec;
			continue;
		}

		if(n < 0 && sockwouldblock(sockerrno)) {
			break;
		}

		c->local_eof = true;
		break;
	}
}

static void diag_tcp_pump_tx(diag_tcp_conn_t *c, size_t max_segments) {
	if(!c || !c->syn_acked) {
		return;
	}

	size_t sent_segs = 0;
	size_t max_inflight = MIN((size_t)c->peer_wnd, (size_t)DIAG_TCP_INFLIGHT);

	if(max_inflight < DIAG_TCP_MSS) {
		max_inflight = DIAG_TCP_MSS;
	}

	while(c->tx_sent_offset < c->tx_len && c->tx_sent_offset < max_inflight) {
		if(max_segments > 0 && sent_segs >= max_segments) {
			break;
		}

		size_t rem = c->tx_len - c->tx_sent_offset;
		size_t chunk = rem > DIAG_TCP_MSS ? DIAG_TCP_MSS : rem;
		uint32_t seq = c->tx_una_seq + (uint32_t)c->tx_sent_offset;

		diag_tcp_send_segment(c->my_ip, c->peer_ip, c->my_port, c->peer_port,
		                      seq, c->rcv_nxt, DIAG_TH_PUSH | DIAG_TH_ACK, 65535,
		                      c->tx_buf + c->tx_sent_offset, chunk, false);

		c->tx_sent_offset += chunk;
		c->last_tx_tv = now;
		sent_segs++;
	}

	if(c->local_eof && c->tx_sent_offset == c->tx_len && !c->fin_sent && !c->fin_acked) {
		uint32_t seq = c->tx_una_seq + (uint32_t)c->tx_sent_offset;
		diag_tcp_send_segment(c->my_ip, c->peer_ip, c->my_port, c->peer_port,
		                      seq, c->rcv_nxt, DIAG_TH_FIN | DIAG_TH_ACK, 65535,
		                      NULL, 0, false);
		c->fin_sent = true;
		c->last_tx_tv = now;
	}
}

static void diag_tcp_io_cb(void *data, int flags) {
	diag_tcp_conn_t *c = data;

	if(!c || !c->active) {
		return;
	}

	if(!c->local_connected) {
		int err = 0;
		socklen_t len = sizeof(err);

		if(getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *)&err, &len) || err) {
			uint32_t rst_seq = c->syn_acked ? c->tx_una_seq : (c->iss + 1);
			diag_tcp_send_segment(c->my_ip, c->peer_ip, c->my_port, c->peer_port,
			                      rst_seq, c->rcv_nxt, DIAG_TH_RST | DIAG_TH_ACK, 0,
			                      NULL, 0, false);
			diag_tcp_conn_close(c);
			return;
		}

		c->local_connected = true;
	}

	if(flags & IO_WRITE) {
		diag_tcp_flush_rx(c);
	}

	if(flags & IO_READ) {
		diag_tcp_read_local(c);
	}

	diag_tcp_pump_tx(c, 8);

	if(c->fin_acked && c->peer_fin) {
		diag_tcp_conn_close(c);
		return;
	}

	diag_tcp_update_io(c);
}

static void diag_tcp_timer_cb(void *data) {
	(void)data;
	bool any_active = false;

	for(int i = 0; i < MAX_DIAG_TCP_CONNS; i++) {
		diag_tcp_conn_t *c = tcp_conns[i];

		if(!c) {
			continue;
		}

		if(now.tv_sec - c->last_activity > DIAG_TCP_IDLE_S || c->rto_count > 10) {
			diag_tcp_conn_close(c);
			continue;
		}

		any_active = true;
		long elapsed_us = (now.tv_sec - c->last_tx_tv.tv_sec) * 1000000L +
		                  (now.tv_usec - c->last_tx_tv.tv_usec);

		if(!c->syn_acked) {
			if(elapsed_us >= DIAG_TCP_RTO_US) {
				c->rto_count++;
				c->last_tx_tv = now;
				diag_tcp_send_segment(c->my_ip, c->peer_ip, c->my_port, c->peer_port,
				                      c->iss, c->rcv_nxt, DIAG_TH_SYN | DIAG_TH_ACK, 65535,
				                      NULL, 0, true);
			}
		} else if((c->tx_len > 0 || (c->fin_sent && !c->fin_acked)) && elapsed_us >= DIAG_TCP_RTO_US) {
			c->rto_count++;
			c->tx_sent_offset = 0;
			c->fin_sent = false;
			diag_tcp_pump_tx(c, 4);
		}
	}

	if(any_active) {
		timeout_set(&tcp_retransmit_timer, &(struct timeval) {
			0, 200000
		});
	}
}

static void diag_ensure_tcp_timer(void) {
	if(!tcp_retransmit_timer.cb) {
		timeout_add(&tcp_retransmit_timer, diag_tcp_timer_cb, NULL, &(struct timeval) {
			0, 200000
		});
	}
}

static void diag_handle_tcp_packet(const uint8_t *ip, const uint8_t *tcp, size_t tcp_total_len) {
	if(tcp_total_len < 20) {
		return;
	}

	ipv4_t peer_ip, my_ip;
	memcpy(&peer_ip, ip + 12, 4);
	memcpy(&my_ip, ip + 16, 4);

	uint16_t sport_net, dport_net, win_net;
	uint32_t seq_net, ack_net;
	memcpy(&sport_net, tcp + 0, 2);
	memcpy(&dport_net, tcp + 2, 2);
	memcpy(&seq_net, tcp + 4, 4);
	memcpy(&ack_net, tcp + 8, 4);
	memcpy(&win_net, tcp + 14, 2);

	uint16_t sport = ntohs(sport_net);
	uint16_t dport = ntohs(dport_net);
	uint32_t seq = ntohl(seq_net);
	uint32_t ack = ntohl(ack_net);
	uint16_t win = ntohs(win_net);
	uint8_t th_off = (tcp[12] >> 4) * 4;
	uint8_t flags = tcp[13];

	if(th_off < 20 || tcp_total_len < th_off) {
		return;
	}

	const uint8_t *payload = tcp + th_off;
	size_t payload_len = tcp_total_len - th_off;

	diag_tcp_conn_t *c = NULL;

	for(int i = 0; i < MAX_DIAG_TCP_CONNS; i++) {
		diag_tcp_conn_t *cand = tcp_conns[i];

		if(cand && cand->peer_port == sport && cand->my_port == dport &&
		                !memcmp(&cand->peer_ip, &peer_ip, 4)) {
			c = cand;
			break;
		}
	}

	if((flags & DIAG_TH_SYN) && !(flags & DIAG_TH_ACK)) {
		if(c) {
			if(!c->syn_acked && seq == c->irs) {
				diag_tcp_send_segment(c->my_ip, c->peer_ip, c->my_port, c->peer_port,
				                      c->iss, c->rcv_nxt, DIAG_TH_SYN | DIAG_TH_ACK, 65535,
				                      NULL, 0, true);
				return;
			}

			diag_tcp_conn_close(c);
			c = NULL;
		}

		/* Find a free slot or evict the oldest connection */
		int slot = -1;
		time_t oldest_time = now.tv_sec + 1;
		int oldest_slot = 0;

		for(int i = 0; i < MAX_DIAG_TCP_CONNS; i++) {
			if(!tcp_conns[i]) {
				slot = i;
				break;
			}

			if(tcp_conns[i]->last_activity < oldest_time) {
				oldest_time = tcp_conns[i]->last_activity;
				oldest_slot = i;
			}
		}

		if(slot < 0) {
			diag_tcp_conn_close(tcp_conns[oldest_slot]);
			slot = oldest_slot;
		}

		int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if(fd < 0) {
			diag_tcp_send_segment(my_ip, peer_ip, dport, sport, 0, seq + 1,
			                      DIAG_TH_RST | DIAG_TH_ACK, 0, NULL, 0, false);
			return;
		}

#ifdef FD_CLOEXEC
		fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
		{
			int fl = fcntl(fd, F_GETFL);
			fcntl(fd, F_SETFL, fl | O_NONBLOCK);
		}
#elif defined(HAVE_WINDOWS)
		{
			unsigned long arg = 1;
			ioctlsocket(fd, FIONBIO, &arg);
		}
#endif
		int one = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const void *)&one, sizeof(one));

		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(0x7f000001);
		sin.sin_port = htons(dport);

		bool connected_now = false;

		if(connect(fd, (struct sockaddr *)&sin, sizeof(sin)) == 0) {
			connected_now = true;
		} else if(!sockinprogress(sockerrno)) {
			closesocket(fd);
			diag_tcp_send_segment(my_ip, peer_ip, dport, sport, 0, seq + 1,
			                      DIAG_TH_RST | DIAG_TH_ACK, 0, NULL, 0, false);
			return;
		}

		c = xzalloc(sizeof(*c));
		c->active = true;
		c->peer_ip = peer_ip;
		c->my_ip = my_ip;
		c->peer_port = sport;
		c->my_port = dport;
		c->fd = fd;
		c->local_connected = connected_now;
		c->irs = seq;
		c->rcv_nxt = seq + 1;
		c->iss = ((uint32_t)now.tv_sec << 16) ^ (uint32_t)now.tv_usec ^ ((uint32_t)sport << 8) ^ 0x5a3c96e1U;
		c->tx_una_seq = c->iss + 1;
		c->peer_wnd = win > 1460 ? win : 16384;
		c->last_activity = now.tv_sec;
		c->last_tx_tv = now;

		tcp_conns[slot] = c;
		io_add(&c->io, diag_tcp_io_cb, c, fd, connected_now ? IO_READ : (IO_READ | IO_WRITE));
		diag_ensure_tcp_timer();

		diag_tcp_send_segment(c->my_ip, c->peer_ip, c->my_port, c->peer_port,
		                      c->iss, c->rcv_nxt, DIAG_TH_SYN | DIAG_TH_ACK, 65535,
		                      NULL, 0, true);
		return;
	}

	if(!c) {
		if(!(flags & DIAG_TH_RST)) {
			uint32_t rst_seq = (flags & DIAG_TH_ACK) ? ack : 0;
			uint32_t rst_ack = seq + (uint32_t)payload_len + ((flags & DIAG_TH_FIN) ? 1 : 0);
			diag_tcp_send_segment(my_ip, peer_ip, dport, sport, rst_seq, rst_ack,
			                      DIAG_TH_RST | DIAG_TH_ACK, 0, NULL, 0, false);
		}

		return;
	}

	if(flags & DIAG_TH_RST) {
		diag_tcp_conn_close(c);
		return;
	}

	c->last_activity = now.tv_sec;
	c->peer_wnd = win >= 1460 ? win : 4096;

	if(flags & DIAG_TH_ACK) {
		if(!c->syn_acked) {
			if((int32_t)(ack - (c->iss + 1)) >= 0) {
				c->syn_acked = true;
				c->rto_count = 0;
			}
		}

		if(c->syn_acked) {
			int32_t acked = (int32_t)(ack - c->tx_una_seq);

			if(acked > 0) {
				c->rto_count = 0;
				size_t drop = (size_t)acked <= c->tx_len ? (size_t)acked : c->tx_len;

				if(drop > 0) {
					memmove(c->tx_buf, c->tx_buf + drop, c->tx_len - drop);
					c->tx_len -= drop;
					c->tx_una_seq += (uint32_t)drop;
					c->tx_sent_offset = (c->tx_sent_offset > drop) ? (c->tx_sent_offset - drop) : 0;
					c->last_tx_tv = now;
				}

				if(c->fin_sent && ack == c->tx_una_seq + 1) {
					c->fin_acked = true;
					c->fin_sent = false;
					c->tx_una_seq++;
				}
			}
		}
	}

	bool send_ack = false;

	if(payload_len > 0) {
		int32_t offset = (int32_t)(c->rcv_nxt - seq);

		if(offset >= 0 && (size_t)offset < payload_len) {
			const uint8_t *new_data = payload + offset;
			size_t new_len = payload_len - (size_t)offset;

			if(c->rx_off > 0 && c->rx_off == c->rx_len) {
				c->rx_off = 0;
				c->rx_len = 0;
			} else if(c->rx_off >= 4096) {
				memmove(c->rx_buf, c->rx_buf + c->rx_off, c->rx_len - c->rx_off);
				c->rx_len -= c->rx_off;
				c->rx_off = 0;
			}

			size_t avail = sizeof(c->rx_buf) - c->rx_len;
			size_t take = new_len <= avail ? new_len : avail;

			if(take > 0) {
				memcpy(c->rx_buf + c->rx_len, new_data, take);
				c->rx_len += take;
				c->rcv_nxt += (uint32_t)take;
				diag_tcp_flush_rx(c);
			}
		}

		send_ack = true;
	}

	if(flags & DIAG_TH_FIN) {
		if(seq + (uint32_t)payload_len == c->rcv_nxt && !c->peer_fin) {
			c->peer_fin = true;
			c->rcv_nxt++;
			send_ack = true;
			diag_tcp_flush_rx(c);
		}
	}

	diag_tcp_read_local(c);

	size_t prev_sent = c->tx_sent_offset;
	bool prev_fin = c->fin_sent;
	diag_tcp_pump_tx(c, 8);

	if(send_ack && c->tx_sent_offset == prev_sent && c->fin_sent == prev_fin) {
		uint32_t cur_seq = c->tx_una_seq + (uint32_t)c->tx_sent_offset + (c->fin_sent ? 1 : 0);
		diag_tcp_send_segment(c->my_ip, c->peer_ip, c->my_port, c->peer_port,
		                      cur_seq, c->rcv_nxt, DIAG_TH_ACK, 65535,
		                      NULL, 0, false);
	}

	if(c->fin_acked && c->peer_fin) {
		diag_tcp_conn_close(c);
		return;
	}

	diag_tcp_update_io(c);
}

/* ---- In-tunnel ICMP probe handling --------------------------------------- */

static void diag_free_ping_req(diag_ping_req_t *target) {
	diag_ping_req_t **pp = &ping_reqs;

	while(*pp) {
		if(*pp == target) {
			*pp = target->next;
			timeout_del(&target->timer);
			free(target);
			return;
		}

		pp = &(*pp)->next;
	}
}

static void diag_ping_timeout_cb(void *data) {
	diag_ping_req_t *req = data;

	if(!req) {
		return;
	}

	if(req->c) {
		send_request(req->c, "%d %d 1 %s - -1 -1 -1 %d 0",
		             CONTROL, REQ_DIAG_PING, req->dst_str, (int)req->ttl);
	}

	diag_free_ping_req(req);
}

void diag_cleanup_connection(connection_t *c) {
	if(!c) {
		return;
	}

	diag_ping_req_t *cur = ping_reqs;

	while(cur) {
		diag_ping_req_t *next = cur->next;

		if(cur->c == c) {
			diag_free_ping_req(cur);
		}

		cur = next;
	}
}

bool diag_intercept_ipv4(node_t *source, vpn_packet_t *packet) {
	const size_t eth_sz = sizeof(struct ether_header);

	if(packet->len < eth_sz + 20) {
		return false;
	}

	uint8_t *d = DATA(packet);
	uint8_t proto = d[eth_sz + 9];

	/* Fast path: immediately ignore normal traffic when neither ICMP nor the
	   configured diagnostic TCP bridge port applies. */
	if(proto != IPPROTO_ICMP && (proto != IPPROTO_TCP || diag_port <= 0 || source == myself)) {
		return false;
	}

	if(d[12] != 0x08 || d[13] != 0x00) {
		return false;
	}

	uint8_t *ip = d + eth_sz;
	uint8_t ihl = (ip[0] & 0x0f) * 4;

	if((ip[0] >> 4) != 4 || ihl < 20 || packet->len < eth_sz + ihl) {
		return false;
	}

	if(proto == IPPROTO_ICMP) {
		if(packet->len < eth_sz + ihl + 8) {
			return false;
		}

		uint8_t *icmp_ptr = ip + ihl;
		size_t icmp_len = packet->len - eth_sz - ihl;
		uint8_t icmp_type = icmp_ptr[0];
		uint8_t icmp_code = icmp_ptr[1];

		/* 1. Incoming Echo Request addressed to us */
		if(icmp_type == ICMP_ECHO && icmp_code == 0 && source != myself) {
			ipv4_t my_ip;

			if(!diag_my_ipv4(&my_ip) || memcmp(ip + 16, &my_ip, 4) != 0) {
				return false;
			}

			uint16_t id_net;
			memcpy(&id_net, icmp_ptr + 4, 2);
			bool is_diag_probe = (ntohs(id_net) == DIAG_ICMP_ID);

#ifndef __ANDROID__
			if(!is_diag_probe) {
				return false;
			}
#endif
			/* Swap Ethernet MACs */
			uint8_t tmp_mac[6];
			memcpy(tmp_mac, d, 6);
			memcpy(d, d + 6, 6);
			memcpy(d + 6, tmp_mac, 6);

			/* Swap IPv4 src and dst */
			uint8_t tmp_ip[4];
			memcpy(tmp_ip, ip + 12, 4);
			memcpy(ip + 12, ip + 16, 4);
			memcpy(ip + 16, tmp_ip, 4);

			ip[8] = 64; /* reset TTL */
			ip[10] = 0;
			ip[11] = 0;
			uint16_t ip_csum = diag_inet_checksum(ip, ihl, 0xFFFF);
			memcpy(ip + 10, &ip_csum, 2);

			/* Echo Reply */
			icmp_ptr[0] = ICMP_ECHOREPLY;
			icmp_ptr[1] = 0;
			icmp_ptr[2] = 0;
			icmp_ptr[3] = 0;
			uint16_t icmp_csum = diag_inet_checksum(icmp_ptr, icmp_len, 0xFFFF);
			memcpy(icmp_ptr + 2, &icmp_csum, 2);

			route(myself, packet);
			return true;
		}

		/* 2. Incoming Echo Reply / Destination Unreachable / Time Exceeded */
		if((icmp_type == ICMP_ECHOREPLY || icmp_type == ICMP_DEST_UNREACH || icmp_type == ICMP_TIME_EXCEEDED) && ping_reqs) {
			uint16_t id = 0, seq = 0, next_mtu = 0;

			if(icmp_type == ICMP_ECHOREPLY) {
				uint16_t id_net, seq_net;
				memcpy(&id_net, icmp_ptr + 4, 2);
				memcpy(&seq_net, icmp_ptr + 6, 2);
				id = ntohs(id_net);
				seq = ntohs(seq_net);
			} else {
				if(icmp_type == ICMP_DEST_UNREACH && icmp_code == ICMP_FRAG_NEEDED) {
					uint16_t mtu_net;
					memcpy(&mtu_net, icmp_ptr + 6, 2);
					next_mtu = ntohs(mtu_net);
				}

				if(icmp_len >= 8 + 20 + 8) {
					const uint8_t *inner_ip = icmp_ptr + 8;
					uint8_t inner_ihl = (inner_ip[0] & 0x0f) * 4;

					if(inner_ihl >= 20 && icmp_len >= (size_t)(8 + inner_ihl + 8) && inner_ip[9] == IPPROTO_ICMP) {
						const uint8_t *inner_icmp = inner_ip + inner_ihl;
						uint16_t id_net, seq_net;
						memcpy(&id_net, inner_icmp + 4, 2);
						memcpy(&seq_net, inner_icmp + 6, 2);
						id = ntohs(id_net);
						seq = ntohs(seq_net);
					}
				}
			}

			if(id == DIAG_ICMP_ID) {
				for(diag_ping_req_t *req = ping_reqs; req; req = req->next) {
					if(req->seq == seq) {
						long rtt_us = (now.tv_sec - req->sent_tv.tv_sec) * 1000000L +
						              (now.tv_usec - req->sent_tv.tv_usec);

						if(rtt_us < 0) {
							rtt_us = 0;
						}

						ipv4_t src_ip;
						memcpy(&src_ip, ip + 12, 4);
						char src_ip_str[32];
						snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
						         src_ip.x[0], src_ip.x[1], src_ip.x[2], src_ip.x[3]);

						subnet_t *sub = lookup_subnet_ipv4(&src_ip);
						const char *nname = (sub && sub->owner && sub->owner->name) ? sub->owner->name :
						                    (source && source->name ? source->name : "-");

						send_request(req->c, "%d %d 0 %s %s %d %d %ld %d %d",
						             CONTROL, REQ_DIAG_PING, src_ip_str, nname,
						             (int)icmp_type, (int)icmp_code, rtt_us,
						             (int)ip[8], (int)next_mtu);
						diag_free_ping_req(req);
						return true;
					}
				}
			}
		}

		return false;
	}

	if(proto == IPPROTO_TCP && diag_port > 0 && source != myself) {
		ipv4_t my_ip;

		if(!diag_my_ipv4(&my_ip) || memcmp(ip + 16, &my_ip, 4) != 0) {
			return false;
		}

		uint16_t ip_off_net, ip_len_net;
		memcpy(&ip_len_net, ip + 2, 2);
		memcpy(&ip_off_net, ip + 6, 2);
		uint16_t ip_off = ntohs(ip_off_net);
		uint16_t ip_total = ntohs(ip_len_net);

		if((ip_off & (IP_MF | IP_OFFMASK)) != 0) {
			return false;
		}

		if(ip_total < ihl + 20 || eth_sz + ip_total > packet->len) {
			return false;
		}

		const uint8_t *tcp = ip + ihl;
		uint16_t dport_net;
		memcpy(&dport_net, tcp + 2, 2);

		if(ntohs(dport_net) != (uint16_t)diag_port) {
			return false;
		}

		diag_handle_tcp_packet(ip, tcp, ip_total - ihl);
		return true;
	}

	return false;
}

/* ---- Control & lifecycle ------------------------------------------------- */

void diag_set_port(int port, bool from_runtime) {
	if(port < 0 || port > 65535) {
		port = 0;
	}

	if(port != diag_port) {
		diag_tcp_close_all();
		diag_port = port;
		logger(DEBUG_ALWAYS, LOG_NOTICE, "Diagnostic bridge port set to %d", diag_port);
	}

	if(from_runtime) {
		diag_port_runtime_set = true;
	}
}

int diag_get_port(void) {
	return diag_port;
}

void diag_init(void) {
	int port = 0;

	if(get_config_int(lookup_config(&config_tree, "DiagPort"), &port)) {
		diag_set_port(port, false);
		diag_port_runtime_set = false;
	}
}

void diag_reload(void) {
	int port = 0;

	if(get_config_int(lookup_config(&config_tree, "DiagPort"), &port)) {
		diag_set_port(port, false);
		diag_port_runtime_set = false;
	} else if(!diag_port_runtime_set) {
		diag_set_port(0, false);
	}
}

void diag_exit(void) {
	diag_tcp_close_all();

	while(ping_reqs) {
		diag_free_ping_req(ping_reqs);
	}

	diag_port = 0;
	diag_port_runtime_set = false;
}

bool control_diag_port_h(connection_t *c, const char *request) {
	int port = -1;

	if(sscanf(request, "%*d %*d %d", &port) == 1 && port >= 0 && port <= 65535) {
		diag_set_port(port, true);
	}

	return send_request(c, "%d %d 0 %d", CONTROL, REQ_DIAG_PORT, diag_port);
}

bool control_diag_ping_h(connection_t *c, const char *request) {
	char dst_str[64] = {0};
	int size = 56;
	int ttl = 64;
	int df = 0;
	int timeout_ms = 2000;

	int n = sscanf(request, "%*d %*d %63s %d %d %d %d", dst_str, &size, &ttl, &df, &timeout_ms);

	if(n < 1) {
		return send_request(c, "%d %d -1 - - -1 -1 -1 0 0", CONTROL, REQ_DIAG_PING);
	}

	unsigned int b0, b1, b2, b3;

	if(sscanf(dst_str, "%u.%u.%u.%u", &b0, &b1, &b2, &b3) != 4 ||
	                b0 > 255 || b1 > 255 || b2 > 255 || b3 > 255) {
		return send_request(c, "%d %d -2 %s - -1 -1 -1 0 0", CONTROL, REQ_DIAG_PING, dst_str);
	}

	ipv4_t dst_ip = {{(uint8_t)b0, (uint8_t)b1, (uint8_t)b2, (uint8_t)b3}};
	ipv4_t my_ip;

	if(!diag_my_ipv4(&my_ip)) {
		return send_request(c, "%d %d -3 %s - -1 -1 -1 0 0", CONTROL, REQ_DIAG_PING, dst_str);
	}

	size = CLAMP(size, 0, 1472);
	ttl = CLAMP(ttl, 1, 255);
	timeout_ms = CLAMP(timeout_ms, 100, 10000);

	/* Cap in-flight ping requests so ping_reqs stays O(1) */
	int pending_count = 0;
	diag_ping_req_t *oldest = NULL;

	for(diag_ping_req_t *it = ping_reqs; it; it = it->next) {
		pending_count++;
		oldest = it;
	}

	if(pending_count >= MAX_DIAG_PING_REQS && oldest) {
		diag_ping_timeout_cb(oldest);
	}

	uint16_t seq = ++diag_ping_seq;

	/* Register pending request BEFORE route() in case route_ipv4_unreachable()
	   fires synchronously on this very call (e.g. local ICMP_FRAG_NEEDED). */
	diag_ping_req_t *req = xzalloc(sizeof(*req));
	req->c = c;
	req->seq = seq;
	req->ttl = (uint8_t)ttl;
	req->size = (uint16_t)size;
	snprintf(req->dst_str, sizeof(req->dst_str), "%s", dst_str);
	gettimeofday(&now, NULL);
	req->sent_tv = now;
	req->next = ping_reqs;
	ping_reqs = req;

	timeout_add(&req->timer, diag_ping_timeout_cb, req, &(struct timeval) {
		timeout_ms / 1000, (timeout_ms % 1000) * 1000
	});

	/* Build and inject Ethernet + IPv4 + ICMP Echo Request packet */
	vpn_packet_t pkt;
	memset(&pkt, 0, sizeof(pkt));
	pkt.offset = DEFAULT_PACKET_OFFSET;
	pkt.priority = 0;

	const size_t eth_sz = sizeof(struct ether_header);
	const size_t icmp_total = 8 + (size_t)size;
	const size_t ip_total = 20 + icmp_total;

	uint8_t *d = DATA(&pkt);
	memset(d, 0, eth_sz);
	d[12] = 0x08;
	d[13] = 0x00;

	uint8_t *ip = d + eth_sz;
	ip[0] = 0x45;
	ip[1] = 0;
	uint16_t ip_len_net = htons((uint16_t)ip_total);
	memcpy(ip + 2, &ip_len_net, 2);
	uint16_t id_net = htons(++diag_ip_id);
	memcpy(ip + 4, &id_net, 2);
	ip[6] = df ? 0x40 : 0x00;
	ip[7] = 0x00;
	ip[8] = (uint8_t)ttl;
	ip[9] = IPPROTO_ICMP;
	ip[10] = 0;
	ip[11] = 0;
	memcpy(ip + 12, &my_ip, 4);
	memcpy(ip + 16, &dst_ip, 4);
	uint16_t ip_csum = diag_inet_checksum(ip, 20, 0xFFFF);
	memcpy(ip + 10, &ip_csum, 2);

	uint8_t *icmp_ptr = ip + 20;
	icmp_ptr[0] = ICMP_ECHO;
	icmp_ptr[1] = 0;
	icmp_ptr[2] = 0;
	icmp_ptr[3] = 0;
	uint16_t icmp_id_net = htons(DIAG_ICMP_ID);
	uint16_t icmp_seq_net = htons(seq);
	memcpy(icmp_ptr + 4, &icmp_id_net, 2);
	memcpy(icmp_ptr + 6, &icmp_seq_net, 2);

	for(int i = 0; i < size; i++) {
		icmp_ptr[8 + i] = (uint8_t)(0x20 + (i & 0x3f));
	}

	uint16_t icmp_csum = diag_inet_checksum(icmp_ptr, icmp_total, 0xFFFF);
	memcpy(icmp_ptr + 2, &icmp_csum, 2);

	pkt.len = (length_t)(eth_sz + ip_total);
	route(myself, &pkt);

	return true;
}

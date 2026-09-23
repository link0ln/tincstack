/*
    net_socket.c -- Handle various kinds of sockets.
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2018 Guus Sliepen <guus@tinc-vpn.org>
                  2006      Scott Lamb <slamb@slamb.org>
                  2009      Florian Forster <octo@verplant.org>

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

#include "address_cache.h"
#include "conf.h"
#include "connection.h"
#include "crypto.h"
#include "list.h"
#include "logger.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

#define TINC_TRANSPORT_DAEMON
#include "transport.h"

int addressfamily = AF_UNSPEC;
int maxtimeout = 900;
int seconds_till_retry = 5;
int udp_rcvbuf = 1024 * 1024;
int udp_sndbuf = 1024 * 1024;
bool udp_rcvbuf_warnings;
bool udp_sndbuf_warnings;
int max_connection_burst = 10;
int fwmark;

listen_socket_t listen_socket[MAXSOCKETS];
int listen_sockets;
#ifndef HAVE_WINDOWS
io_t unix_socket;
#endif

static void free_outgoing(outgoing_t *outgoing) {
	timeout_del(&outgoing->ev);
	free(outgoing);
}

list_t outgoing_list = {
	.head = NULL,
	.tail = NULL,
	.count = 0,
	.delete = (list_action_t)free_outgoing,
};

/* Setup sockets */

static void configure_tcp(connection_t *c) {
	int option;

#ifdef O_NONBLOCK
	int flags = fcntl(c->socket, F_GETFL);

	if(fcntl(c->socket, F_SETFL, flags | O_NONBLOCK) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "fcntl for %s fd %d: %s", c->hostname, c->socket, strerror(errno));
	}

#elif defined(WIN32)
	unsigned long arg = 1;

	if(ioctlsocket(c->socket, FIONBIO, &arg) != 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "ioctlsocket for %s fd %d: %s", c->hostname, c->socket, sockstrerror(sockerrno));
	}

#endif

#if defined(TCP_NODELAY)
	option = 1;
	setsockopt(c->socket, IPPROTO_TCP, TCP_NODELAY, (void *)&option, sizeof(option));
#endif

#if defined(IP_TOS) && defined(IPTOS_LOWDELAY)
	option = IPTOS_LOWDELAY;
	setsockopt(c->socket, IPPROTO_IP, IP_TOS, (void *)&option, sizeof(option));
#endif

#if defined(IPV6_TCLASS) && defined(IPTOS_LOWDELAY)
	option = IPTOS_LOWDELAY;
	setsockopt(c->socket, IPPROTO_IPV6, IPV6_TCLASS, (void *)&option, sizeof(option));
#endif

#if defined(SO_MARK)

	if(fwmark) {
		setsockopt(c->socket, SOL_SOCKET, SO_MARK, (void *)&fwmark, sizeof(fwmark));
	}

#endif
}

static bool bind_to_interface(int sd) {
	char *iface;

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	struct ifreq ifr;
	int status;
#endif /* defined(SOL_SOCKET) && defined(SO_BINDTODEVICE) */

	if(!get_config_string(lookup_config(&config_tree, "BindToInterface"), &iface)) {
		return true;
	}

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;

	status = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr));

	if(status) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't bind to interface %s: %s", iface,
		       sockstrerror(sockerrno));
		return false;
	}

#else /* if !defined(SOL_SOCKET) || !defined(SO_BINDTODEVICE) */
	(void)sd;
	logger(DEBUG_ALWAYS, LOG_WARNING, "%s not supported on this platform", "BindToInterface");
#endif

	return true;
}

static bool bind_to_address(connection_t *c) {
	int s = -1;

	for(int i = 0; i < listen_sockets && listen_socket[i].bindto; i++) {
		if(listen_socket[i].sa.sa.sa_family != c->address.sa.sa_family) {
			continue;
		}

		if(s >= 0) {
			return false;
		}

		s = i;
	}

	if(s < 0) {
		return false;
	}

	sockaddr_t sa = listen_socket[s].sa;

	if(sa.sa.sa_family == AF_INET) {
		sa.in.sin_port = 0;
	} else if(sa.sa.sa_family == AF_INET6) {
		sa.in6.sin6_port = 0;
	}

	if(bind(c->socket, &sa.sa, SALEN(sa.sa))) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Can't bind outgoing socket: %s", sockstrerror(sockerrno));
		return false;
	}

	return true;
}

static bool try_bind(int nfd, const sockaddr_t *sa, const char *type) {
	if(!bind(nfd, &sa->sa, SALEN(sa->sa))) {
		return true;
	}

	closesocket(nfd);
	char *addrstr = sockaddr2hostname(sa);
	logger(DEBUG_ALWAYS, LOG_ERR, "Can't bind to %s/%s: %s", addrstr, type, sockstrerror(sockerrno));
	free(addrstr);
	return false;
}

int setup_listen_socket(const sockaddr_t *sa) {
	int nfd;
	int option;
	char *iface;

	nfd = socket(sa->sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

	if(nfd < 0) {
		logger(DEBUG_STATUS, LOG_ERR, "Creating metasocket failed: %s", sockstrerror(sockerrno));
		return -1;
	}

#ifdef FD_CLOEXEC
	fcntl(nfd, F_SETFD, FD_CLOEXEC);
#endif

	/* Optimize TCP settings */

	option = 1;
	setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (void *)&option, sizeof(option));

#if defined(IPV6_V6ONLY)

	if(sa->sa.sa_family == AF_INET6) {
		setsockopt(nfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof(option));
	}

#else
#warning IPV6_V6ONLY not defined
#endif

#if defined(SO_MARK)

	if(fwmark) {
		setsockopt(nfd, SOL_SOCKET, SO_MARK, (void *)&fwmark, sizeof(fwmark));
	}

#endif

	if(get_config_string
	                (lookup_config(&config_tree, "BindToInterface"), &iface)) {
#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, iface, IFNAMSIZ);
		ifr.ifr_name[IFNAMSIZ - 1] = 0;

		if(setsockopt(nfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr))) {
			closesocket(nfd);
			logger(DEBUG_ALWAYS, LOG_ERR, "Can't bind to interface %s: %s", iface,
			       sockstrerror(sockerrno));
			return -1;
		}

#else
		logger(DEBUG_ALWAYS, LOG_WARNING, "%s not supported on this platform", "BindToInterface");
#endif
	}

	if(!try_bind(nfd, sa, "tcp")) {
		return -1;
	}

	if(listen(nfd, 3)) {
		closesocket(nfd);
		logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "listen", sockstrerror(sockerrno));
		return -1;
	}

	return nfd;
}

static void set_udp_buffer(int nfd, int type, const char *name, int size, bool warnings) {
	if(!size) {
		return;
	}

	if(setsockopt(nfd, SOL_SOCKET, type, (void *)&size, sizeof(size))) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Can't set UDP %s to %i: %s", name, size, sockstrerror(sockerrno));
		return;
	}

	if(!warnings) {
		return;
	}

	// The system may cap the requested buffer size.
	// Read back the value and check if it is now as requested.
	int actual = -1;
	socklen_t optlen = sizeof(actual);

	if(getsockopt(nfd, SOL_SOCKET, type, (void *)&actual, &optlen)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Can't read back UDP %s: %s", name, sockstrerror(sockerrno));
	} else if(optlen != sizeof(actual)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Can't read back UDP %s: unexpected returned optlen %d", name, (int)optlen);
	} else if(actual < size) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Can't set UDP %s to %i, the system set it to %i instead", name, size, actual);
	}
}

int setup_vpn_in_socket(const sockaddr_t *sa) {
	return setup_udp_socket(sa, true);
}

/* shared = false: no SO_REUSEADDR. On Linux two UDP sockets that both set it
   share the port, and the kernel splits the datagrams between them -- a front
   on 443 would silently take part of another QUIC server's traffic instead of
   failing to bind. */
int setup_udp_socket(const sockaddr_t *sa, bool shared) {
	int nfd;
	int option;

	nfd = socket(sa->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

	if(nfd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Creating UDP socket failed: %s", sockstrerror(sockerrno));
		return -1;
	}

#ifdef FD_CLOEXEC
	fcntl(nfd, F_SETFD, FD_CLOEXEC);
#endif

#ifdef O_NONBLOCK
	{
		int flags = fcntl(nfd, F_GETFL);

		if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			closesocket(nfd);
			logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "fcntl",
			       strerror(errno));
			return -1;
		}
	}
#elif defined(WIN32)
	{
		unsigned long arg = 1;

		if(ioctlsocket(nfd, FIONBIO, &arg) != 0) {
			closesocket(nfd);
			logger(DEBUG_ALWAYS, LOG_ERR, "Call to `%s' failed: %s", "ioctlsocket", sockstrerror(sockerrno));
			return -1;
		}
	}
#endif

	option = 1;

	if(shared) {
		setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (void *)&option, sizeof(option));
	}

	setsockopt(nfd, SOL_SOCKET, SO_BROADCAST, (void *)&option, sizeof(option));

	set_udp_buffer(nfd, SO_RCVBUF, "SO_RCVBUF", udp_rcvbuf, udp_rcvbuf_warnings);
	set_udp_buffer(nfd, SO_SNDBUF, "SO_SNDBUF", udp_sndbuf, udp_sndbuf_warnings);

#if defined(IPV6_V6ONLY)

	if(sa->sa.sa_family == AF_INET6) {
		setsockopt(nfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof(option));
	}

#endif

#if defined(IP_DONTFRAG) && !defined(IP_DONTFRAGMENT)
#define IP_DONTFRAGMENT IP_DONTFRAG
#endif

#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)

	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = IP_PMTUDISC_DO;
		setsockopt(nfd, IPPROTO_IP, IP_MTU_DISCOVER, (void *)&option, sizeof(option));
	}

#elif defined(IP_DONTFRAGMENT)

	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = 1;
		setsockopt(nfd, IPPROTO_IP, IP_DONTFRAGMENT, (void *)&option, sizeof(option));
	}

#endif

#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)

	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = IPV6_PMTUDISC_DO;
		setsockopt(nfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, (void *)&option, sizeof(option));
	}

#elif defined(IPV6_DONTFRAG)

	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = 1;
		setsockopt(nfd, IPPROTO_IPV6, IPV6_DONTFRAG, (void *)&option, sizeof(option));
	}

#endif

#if defined(SO_MARK)

	if(fwmark) {
		setsockopt(nfd, SOL_SOCKET, SO_MARK, (void *)&fwmark, sizeof(fwmark));
	}

#endif

	if(!bind_to_interface(nfd)) {
		closesocket(nfd);
		return -1;
	}

	if(!try_bind(nfd, sa, "udp")) {
		return -1;
	}

	return nfd;
} /* int setup_udp_socket */

/* Rebind every UDP listening socket to a fresh OS-assigned source port.

   Rationale: behind a (CG)NAT, the external UDP mapping for our fixed source
   port can get stuck in a "bad" state — e.g. after the laptop resumes from
   sleep or roams networks, the carrier NAT may keep filtering inbound packets
   on the old mapping, so hole punching to that endpoint never succeeds again.
   A manual hole-puncher works around this by opening a brand new socket (new
   source port => fresh, often unfiltered mapping). This does the same inside
   tinc: close each UDP socket and reopen it on port 0, letting the OS pick a
   new ephemeral port. reflexive discovery (UDP_INFO) then re-advertises the
   new external address to peers automatically.

   Only meaningful for nodes that don't need a stable inbound port (i.e. nodes
   behind NAT that reach others via ConnectTo); a node with a public IP that
   peers dial by a fixed port must NOT call this. It is therefore gated by the
   UDPRebindOnWake option and only triggered on the wake-from-sleep path. */
void rebind_udp_sockets(void) {
	for(int i = 0; i < listen_sockets; i++) {
		listen_socket_t *sock = &listen_socket[i];

		/* Drop the old socket out of the event loop and close it. */
		io_del(&sock->udp);

		if(sock->udp.fd >= 0) {
			closesocket(sock->udp.fd);
		}

		/* Reuse the bound address family/host but request a fresh port (0). */
		sockaddr_t sa = sock->sa;

		if(sa.sa.sa_family == AF_INET) {
			sa.in.sin_port = 0;
		} else if(sa.sa.sa_family == AF_INET6) {
			sa.in6.sin6_port = 0;
		}

		int udp_fd = setup_vpn_in_socket(&sa);

		if(udp_fd < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not rebind UDP socket %d to a fresh port", i);
			continue;
		}

		io_add(&sock->udp, handle_incoming_vpn_data, sock, udp_fd, IO_READ);
		logger(DEBUG_ALWAYS, LOG_INFO, "Rebound UDP socket %d to a fresh source port", i);
	}
}

static void retry_outgoing_handler(void *data) {
	setup_outgoing_connection(data, true);
}

void retry_outgoing(outgoing_t *outgoing) {
	outgoing->timeout += 5;

	if(outgoing->timeout > maxtimeout) {
		outgoing->timeout = maxtimeout;
	}

	/* Defect C, third symptom: get_recent_address() consumes its candidate
	   list once -- the persisted cache, then the addresses the meta graph
	   advertises for the node, then its Address statements -- and rewinds only
	   when a connection actually came up (pong_h) or when the carrier walk
	   moves on. A peer we know only from the graph has no Address statement,
	   so after the single graph-derived candidate is spent every later retry
	   logs "Could not set up a meta connection to X" without opening a socket,
	   and the pair never recovers however long the backoff runs. Rewind here:
	   the backoff just extended above is what bounds the attempt rate, so this
	   costs one re-walk of a handful of addresses per retry, not a storm.
	   Upstream 1.1pre18 has the same gap (measured). */
	if(outgoing->node && outgoing->node->address_cache) {
		reset_address_cache(outgoing->node->address_cache);
	}

	/* Defect E: the UDP fallback is spent once per cycle, and a new cycle
	   starts here. */
	outgoing->udp_fallback_used = false;

	timeout_add(&outgoing->ev, retry_outgoing_handler, outgoing, &(struct timeval) {
		outgoing->timeout, jitter()
	});

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Trying to re-establish outgoing connection in %d seconds", outgoing->timeout);
}

void finish_connecting(connection_t *c) {
	logger(DEBUG_CONNECTIONS, LOG_INFO, "Connected to %s (%s)", c->name, c->hostname);

	c->last_ping_time = now.tv_sec;
	c->status.connecting = false;

	send_id(c);
}

static void do_outgoing_pipe(connection_t *c, const char *command) {
#ifndef HAVE_WINDOWS
	int fd[2];

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not create socketpair: %s", sockstrerror(sockerrno));
		return;
	}

	if(fork()) {
		c->socket = fd[0];
		close(fd[1]);
		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Using proxy %s", command);
		return;
	}

	close(0);
	close(1);
	close(fd[0]);
	dup2(fd[1], 0);
	dup2(fd[1], 1);
	close(fd[1]);

	// Other filedescriptors should be closed automatically by CLOEXEC

	char *host = NULL;
	char *port = NULL;

	sockaddr2str(&c->address, &host, &port);
	setenv("REMOTEADDRESS", host, true);
	setenv("REMOTEPORT", port, true);
	setenv("NAME", myself->name, true);

	if(c->name) {
		setenv("NODE", c->name, true);
	}

	if(netname) {
		setenv("NETNAME", netname, true);
	}

	int result = system(command);

	if(result < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not execute %s: %s", command, strerror(errno));
	} else if(result) {
		logger(DEBUG_ALWAYS, LOG_ERR, "%s exited with non-zero status %d", command, result);
	}

	exit(result);
#else
	(void)c;
	(void)command;
	logger(DEBUG_ALWAYS, LOG_ERR, "Proxy type exec not supported on this platform!");
	return;
#endif
}

static void handle_meta_write(connection_t *c) {
	if(c->outbuf.len <= c->outbuf.offset) {
		return;
	}

	ssize_t outlen = send(c->socket, c->outbuf.data + c->outbuf.offset, c->outbuf.len - c->outbuf.offset, 0);

	if(outlen <= 0) {
		if(outlen == 0 || sockwouldblock(sockerrno)) {
			logger(DEBUG_META, LOG_DEBUG, "Sending %d bytes to %s (%s) would block", c->outbuf.len - c->outbuf.offset, c->name, c->hostname);
			return;
		} else if(sockerrno == EPIPE) {
			logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection closed by %s (%s)", c->name, c->hostname);
		} else {
			logger(DEBUG_CONNECTIONS, LOG_ERR, "Could not send %d bytes of data to %s (%s): %s", c->outbuf.len - c->outbuf.offset, c->name, c->hostname, sockstrerror(sockerrno));
		}

		terminate_connection(c, c->edge);
		return;
	}

	buffer_read(&c->outbuf, outlen);

	if(!c->outbuf.len) {
		io_set(&c->io, IO_READ);
	}
}

static void handle_meta_io(void *data, int flags) {
	connection_t *c = data;

	if(c->status.connecting) {
		/*
		   The event loop does not protect against spurious events. Verify that we are actually connected
		   by issuing an empty send() call.

		   Note that the behavior of send() on potentially unconnected sockets differ between platforms:
		   +------------+-----------+-------------+-----------+
		   |   Event    |   POSIX   |    Linux    |  Windows  |
		   +------------+-----------+-------------+-----------+
		   | Spurious   | ENOTCONN  | EWOULDBLOCK | ENOTCONN  |
		   | Failed     | ENOTCONN  | (cause)     | ENOTCONN  |
		   | Successful | (success) | (success)   | (success) |
		   +------------+-----------+-------------+-----------+
		*/
		if(send(c->socket, NULL, 0, 0) != 0) {
			if(sockwouldblock(sockerrno)) {
				return;
			}

			int socket_error;

			if(!socknotconn(sockerrno)) {
				socket_error = sockerrno;
			} else {
				socklen_t len = sizeof(socket_error);
				getsockopt(c->socket, SOL_SOCKET, SO_ERROR, (void *)&socket_error, &len);
			}

			if(socket_error) {
				logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Error while connecting to %s (%s): %s", c->name, c->hostname, sockstrerror(socket_error));
				terminate_connection(c, false);
			}

			return;
		}

		c->status.connecting = false;
		finish_connecting(c);
	}

	if(flags & IO_WRITE) {
		handle_meta_write(c);
	} else {
		/* An inbound TCP connection is classified by the front before its
		   bytes are treated as tinc meta traffic. Until it is classified we
		   only peek; a client that never sends a recognisable preamble is
		   reaped by the authentication timeout, so it cannot hold the slot
		   forever. */
		if(c->status.front_pending && !transport_front_dispatch(c)) {
			return;
		}

		handle_meta_connection_data(c);
	}
}

/* The plain carrier's dial hook: open a TCP meta connection (optionally
   through a proxy), exactly as upstream tinc always did. `c' already has
   address, hostname and name filled in. On success the connection is
   registered and returned to the event loop; on failure it returns false and
   leaves `c' for the caller to free. */
bool transport_plain_dial(connection_t *c) {
	struct addrinfo *proxyai = NULL;
	int result;

	if(!proxytype) {
		c->socket = socket(c->address.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
		configure_tcp(c);
	} else if(proxytype == PROXY_EXEC) {
		do_outgoing_pipe(c, proxyhost);
	} else {
		proxyai = str2addrinfo(proxyhost, proxyport, SOCK_STREAM);

		if(!proxyai) {
			return false;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Using proxy at %s port %s", proxyhost, proxyport);
		c->socket = socket(proxyai->ai_family, SOCK_STREAM, IPPROTO_TCP);
		configure_tcp(c);
	}

	if(c->socket == -1) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Creating socket for %s failed: %s", c->hostname, sockstrerror(sockerrno));

		if(proxyai) {
			freeaddrinfo(proxyai);
		}

		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(c->socket, F_SETFD, FD_CLOEXEC);
#endif

	if(proxytype != PROXY_EXEC) {
#if defined(IPV6_V6ONLY)
		int option = 1;

		if(c->address.sa.sa_family == AF_INET6) {
			setsockopt(c->socket, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof(option));
		}

#endif

		bind_to_interface(c->socket);
		bind_to_address(c);
	}

	/* Connect */

	if(!proxytype) {
		result = connect(c->socket, &c->address.sa, SALEN(c->address.sa));
	} else if(proxytype == PROXY_EXEC) {
		result = 0;
	} else {
		if(!proxyai) {
			abort();
		}

		result = connect(c->socket, proxyai->ai_addr, proxyai->ai_addrlen);
		freeaddrinfo(proxyai);
	}

	if(result == -1 && !sockinprogress(sockerrno)) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Could not connect to %s (%s): %s", c->name, c->hostname, sockstrerror(sockerrno));
		return false;
	}

	/* Now that there is a working socket, register this connection. */

	c->status.connecting = true;

	connection_add(c);

	io_add(&c->io, handle_meta_io, c, c->socket, IO_READ | IO_WRITE);

	return true;
}

/* Defect E, first symptom. A dial to an address that has never once worked
   repeated "Could not set up a meta connection to X" at LOG_ERR on every
   backoff round, for ever, at the default -d1. Measured on the four-node stand
   and reproduced in testing/transports/same-nat-meta-test.sh: two nodes behind
   one NAT whose TCP hairpin does not work log it until one of them is
   restarted. The backoff does widen (5, 10, 15 ... MaxTimeout, contrary to the
   first field write-up), so the steady rate is one line per peer per 15 min --
   but it is still an ERROR, for ever, for a condition the operator can do
   nothing about, and it is what makes a node with a handful of unreachable
   peers look broken.

   So: the first OUTGOING_LOUD_FAILURES give-ups are as loud as before, then
   one line says where the rest went, and the rest go to -d3. Nothing is
   *stopped*: the dial keeps happening on the same backoff, because a NAT
   mapping or a route can start working at any time, and `failures' is reset
   the moment a connection to this peer activates -- so a peer that goes away
   and comes back is loud again. */
#define OUTGOING_LOUD_FAILURES 3

static void log_outgoing_failure(outgoing_t *outgoing) {
	const char *name = outgoing->node->name;

	if(outgoing->failures < OUTGOING_LOUD_FAILURES) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Could not set up a meta connection to %s", name);
	} else if(outgoing->failures == OUTGOING_LOUD_FAILURES) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Could not set up a meta connection to %s (%d times in a row; further attempts are logged at -d3 until one succeeds)", name, outgoing->failures + 1);
	} else {
		logger(DEBUG_PROTOCOL, LOG_DEBUG, "Could not set up a meta connection to %s (%d times in a row)", name, outgoing->failures + 1);
	}

	if(outgoing->failures < INT_MAX) {
		outgoing->failures++;
	}
}

bool do_outgoing_connection(outgoing_t *outgoing) {
	const sockaddr_t *sa;
	sockaddr_t udpsa;
	const transport_t *t;
	bool fallback;

begin:
	sa = get_recent_address(outgoing->node->address_cache);
	t = NULL;
	fallback = false;

	if(!sa) {
		/* Defect E, second symptom. Every address the graph and the config
		   know for this peer has just refused a meta connection -- but the
		   DATA path to it may be a confirmed direct UDP flow (a NAT that
		   hairpins UDP and not TCP is exactly that shape). Dial the meta
		   connection over that flow with the single-flow carrier, which is
		   the same path the packets already take. SPTPS and the ID exchange
		   are untouched; the acceptor still enforces its own accept list. */
		if(transport_udp_meta_fallback(outgoing, &udpsa)) {
			sa = &udpsa;
			t = transport_get(TRANSPORT_SF);
			fallback = true;
		} else {
			log_outgoing_failure(outgoing);
			retry_outgoing(outgoing);
			return false;
		}
	}

	if(!t) {
		t = transport_current(outgoing);
	}

	connection_t *c = new_connection();
	c->outgoing = outgoing;
	memcpy(&c->address, sa, SALEN(sa->sa));
	c->hostname = sockaddr2hostname(&c->address);
	c->name = xstrdup(outgoing->node->name);
	c->outmaclength = myself->connection->outmaclength;
	c->last_ping_time = now.tv_sec;
	c->transport = t;

	if(fallback) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "No address of %s accepts a meta connection, but its UDP data path is direct: dialling %s (%s) via %s", outgoing->node->name, outgoing->node->name, c->hostname, t->name);
	} else {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Trying to connect to %s (%s) via %s", outgoing->node->name, c->hostname, t->name);
	}

	if(!t->dial || !t->dial(c)) {
		free_connection(c);

		/* This carrier did not even get a socket up. Fall back to the next
		   carrier in the preference list, retrying the same set of addresses
		   from the top. The UDP fallback is not part of that walk: it is an
		   address of last resort, already spent for this cycle. */
		if(!fallback && transport_next_candidate(outgoing)) {
			reset_address_cache(outgoing->node->address_cache);
		}

		goto begin;
	}

	return true;
}

void setup_outgoing_connection(outgoing_t *outgoing, bool verbose) {
	(void)verbose;
	timeout_del(&outgoing->ev);

	node_t *n = outgoing->node;

	if(!n->address_cache) {
		n->address_cache = open_address_cache(n);
	}

	/* Defect C: a meta connection to a peer whose Ed25519 key we do not have
	   cannot authenticate -- id_h() has nothing to hand to sptps_start() -- so
	   dialling one is provably wasted, and it is what produced the
	   "Timeout ... during authentication" the field report shows. For a node
	   we met only over the graph (both invited by the same third node) neither
	   side has a host record, and upstream only fetches the key when *traffic*
	   needs it, i.e. long after the meta connection gave up. Ask for it over
	   the graph and come back on the normal backoff instead of dialling into a
	   refusal; the answer takes one relay round trip, so the next attempt has
	   it. send_req_pubkey() returns false when there is nobody to ask (no
	   nexthop, or the key is already known), and then we dial as before.

	   Bounded on purpose: only while the backoff is still short (at most the
	   5/10/15/20/25 s rounds, ~75 s). If the key still has not arrived by
	   then something else is wrong and we go back to dialling anyway rather
	   than stalling this outgoing_t silently. */
	if(outgoing->timeout < 30 && !node_read_ecdsa_public_key(n) && send_req_pubkey(n)) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Deferring the dial to %s until its Ed25519 key arrives over the graph", n->name);
		retry_outgoing(outgoing);
		return;
	}

	/* Defect E, point 3. A peer whose key we already have never answers an
	   ANS_PUBKEY, so stream AC's accept-mask propagation never reaches it and
	   we would keep assuming it is plain-only -- which is exactly the pair
	   that needs a non-plain carrier. Ask over the graph; the answer takes one
	   relay round trip, so the carrier walk of the next cycle has it.
	   send_req_transports() is a no-op once the list is known and is rate
	   limited per node. */
	send_req_transports(n);

	/* Defect E, second symptom. The UDP meta fallback can only fire if the
	   data path to this peer has been confirmed direct, and that confirmation
	   is normally driven by *traffic*: a pair that has nothing to say to each
	   other would stay relayed for ever with no way out. try_tx() is what
	   traffic would call; it rate-limits itself (try_sptps/try_udp) and the
	   growing reconnect backoff bounds it further.

	   Only for a peer we have ALREADY failed to dial at least once, which is
	   the whole population this fix is for. Kicking it on the first dial too
	   was measured to be actively harmful: it confirms the UDP path of a peer
	   that is about to connect normally, and a node whose *confirmed* path is
	   then black-holed takes udp_discovery_timeout to fall back to the relay,
	   where a node that never confirmed it notices in one sf retransmission
	   round. testing/transports/singleflow-test.sh PART 2 (sever a fresh
	   A<->B link, require the relayed path within ~40 s) went from 3/3 to 1/3
	   because of it. */
	if(udp_meta_fallback && outgoing->failures && n->status.reachable && !n->status.udp_confirmed) {
		try_tx(n, true);
	}

	if(n->connection && !transport_outranks_connection(outgoing, n->connection)) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Already connected to %s", n->name);
		return;
	}

	if(n->connection) {
		/* The peer dialled us on a carrier we rank below the one we would
		   dial (review row L-2 residual, docs/transports.md §2). Dial ours
		   anyway: its link stays up and carries traffic until ours activates,
		   at which point ack_h() keeps the newer connection and drops the
		   old one, so the pair is never left with zero connections. */
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Connected to %s over %s, which we rank below %s: dialling %s as well",
		       n->name, n->connection->transport ? n->connection->transport->name : "plain",
		       transport_current(outgoing)->name, transport_current(outgoing)->name);

		/* Only one connection may own the outgoing_t: if ack_h() parked it on
		   the peer's inbound link, hand it to the dial we are about to make. */
		if(n->connection->outgoing == outgoing) {
			n->connection->outgoing = NULL;
		}
	}

	do_outgoing_connection(outgoing);
}

static bool check_tarpit(const sockaddr_t *sa, int fd) {
	// Check if we get many connections from the same host

	static sockaddr_t prev_sa;

	if(!sockaddrcmp_noport(sa, &prev_sa)) {
		static time_t samehost_burst;
		static time_t samehost_burst_time;

		if(now.tv_sec - samehost_burst_time > samehost_burst) {
			samehost_burst = 0;
		} else {
			samehost_burst -= now.tv_sec - samehost_burst_time;
		}

		samehost_burst_time = now.tv_sec;
		samehost_burst++;

		if(samehost_burst > max_connection_burst) {
			tarpit(fd);
			return true;
		}
	}

	prev_sa = *sa;

	// Check if we get many connections from different hosts

	static time_t connection_burst;
	static time_t connection_burst_time;

	if(now.tv_sec - connection_burst_time > connection_burst) {
		connection_burst = 0;
	} else {
		connection_burst -= now.tv_sec - connection_burst_time;
	}

	connection_burst_time = now.tv_sec;
	connection_burst++;

	if(connection_burst >= max_connection_burst) {
		connection_burst = max_connection_burst;
		tarpit(fd);
		return true;
	}

	return false;
}

/*
  accept a new tcp connect and create a
  new connection
*/
static void accept_meta_connection(listen_socket_t *l, bool tls_only) {
	connection_t *c;
	sockaddr_t sa;
	int fd;
	socklen_t len = sizeof(sa);

	fd = accept(l->tcp.fd, &sa.sa, &len);

	if(fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Accepting a new connection failed: %s", sockstrerror(sockerrno));
		return;
	}

	sockaddrunmap(&sa);

	if(!is_local_connection(&sa) && check_tarpit(&sa, fd)) {
		return;
	}

	// Accept the new connection

	c = new_connection();
	c->name = xstrdup("<unknown>");
	c->outmaclength = myself->connection->outmaclength;

	c->address = sa;
	c->hostname = sockaddr2hostname(&sa);
	c->socket = fd;
	c->last_ping_time = now.tv_sec;
	c->status.front_pending = true;
	c->status.front_tls_only = tls_only;

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection from %s", c->hostname);

	io_add(&c->io, handle_meta_io, c, c->socket, IO_READ);

	configure_tcp(c);

	connection_add(c);

	c->allow_request = ID;
}

void handle_new_meta_connection(void *data, int flags) {
	(void)flags;
	accept_meta_connection(data, false);
}

/* The HttpsPort listener (https.c): same front, but only a TLS ClientHello
   gets anywhere (transport_front_dispatch). */
void handle_new_front_connection(void *data, int flags) {
	(void)flags;
	accept_meta_connection(data, true);
}

#ifndef HAVE_WINDOWS
/*
  accept a new UNIX socket connection
*/
void handle_new_unix_connection(void *data, int flags) {
	(void)flags;
	io_t *io = data;
	connection_t *c;
	sockaddr_t sa;
	int fd;
	socklen_t len = sizeof(sa);

	fd = accept(io->fd, &sa.sa, &len);

	if(fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Accepting a new connection failed: %s", sockstrerror(sockerrno));
		return;
	}

	sockaddrunmap(&sa);

	c = new_connection();
	c->name = xstrdup("<control>");
	c->address = sa;
	c->hostname = xstrdup("localhost port unix");
	c->socket = fd;
	c->last_ping_time = now.tv_sec;

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection from %s", c->hostname);

	io_add(&c->io, handle_meta_io, c, c->socket, IO_READ);

	connection_add(c);

	c->allow_request = ID;
}
#endif

void try_outgoing_connections(void) {
	/* If there is no outgoing list yet, create one. Otherwise, mark all outgoings as deleted. */

	for list_each(outgoing_t, outgoing, &outgoing_list) {
		outgoing->timeout = -1;
	}

	/* Make sure there is one outgoing_t in the list for each ConnectTo. */

	for(config_t *cfg = lookup_config(&config_tree, "ConnectTo"); cfg; cfg = lookup_config_next(&config_tree, cfg)) {
		char *name;
		get_config_string(cfg, &name);

		if(!check_id(name)) {
			logger(DEBUG_ALWAYS, LOG_ERR,
			       "Invalid name for outgoing connection in %s line %d",
			       cfg->file, cfg->line);
			free(name);
			continue;
		}

		if(!strcmp(name, myself->name)) {
			free(name);
			continue;
		}

		bool found = false;

		for list_each(outgoing_t, outgoing, &outgoing_list) {
			if(!strcmp(outgoing->node->name, name)) {
				found = true;
				outgoing->timeout = 0;
				break;
			}
		}

		if(!found) {
			outgoing_t *outgoing = xzalloc(sizeof(*outgoing));
			node_t *n = lookup_node(name);

			if(!n) {
				n = new_node(name);
				node_add(n);
			}

			outgoing->node = n;
			list_insert_tail(&outgoing_list, outgoing);
			setup_outgoing_connection(outgoing, true);
		}

		free(name);
	}

	/* Terminate any connections whose outgoing_t is to be deleted. */

	for list_each(connection_t, c, &connection_list) {
		if(c->outgoing && c->outgoing->timeout == -1) {
			c->outgoing = NULL;
			logger(DEBUG_CONNECTIONS, LOG_INFO, "No more outgoing connection to %s", c->name);
			terminate_connection(c, c->edge);
		}
	}

	/* Delete outgoing_ts for which there is no ConnectTo. */

	for list_each(outgoing_t, outgoing, &outgoing_list)
		if(outgoing->timeout == -1) {
			list_delete_node(&outgoing_list, node);
		}
}

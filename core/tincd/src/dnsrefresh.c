/*
    dnsrefresh.c -- Watch Address = <hostname> entries and follow DNS changes

    A host record may name a peer by DNS name. The dial path already resolves
    such names (address_cache.c walks Address statements through
    str2addrinfo), but nothing re-checks a name while a link is up: a peer
    that moves to a new server keeps its old session until the link dies on
    its own. This file adds the standing watcher:

      - a worker thread resolves names off the event loop (getaddrinfo
        blocks; the daemon is single-threaded),
      - results come back over a socketpair the event loop watches,
      - the last address a name resolved to is persisted per node and is
        only ever replaced by a live DNS answer -- a dead resolver never
        erases the last working address,
      - when a fresh answer no longer lists the address a live meta
        connection is using, that connection is torn down (the normal
        terminate_connection path) and re-dialled to what DNS now returns,
        so two servers with one identity do not coexist.

    Trust is unchanged: SPTPS/Ed25519 still authenticates the peer and
    https/quic still pin TlsFingerprint, so a poisoned record can only
    cause a failed dial, never an impersonation.
*/

#include "system.h"
#include "net.h"

#include <pthread.h>

#include "conf.h"
#include "connection.h"
#include "address_cache.h"
#include "dnsrefresh.h"
#include "logger.h"
#include "names.h"
#include "netutl.h"
#include "node.h"
#include "utils.h"
#include "xalloc.h"

#ifdef HAVE_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#endif

int dnsrefresh_interval = 600;

/* The watch list is built by the event-loop thread and consumed by the
   worker; ownership follows the job: the loop frees what it queued, the
   worker frees what it produced. */

typedef struct dnsrefresh_job_t {
	char *node_name;                         /* tinc node the Address belongs to */
	char *hostname;                          /* the DNS name in the Address statement */
	char *port;                              /* port from the Address statement / Port option */
	sockaddr_t last_good;                    /* last live answer, persisted (sa_family 0 = none) */
	bool has_last_good;
	sockaddr_t *addrs;                       /* all addresses from latest resolution */
	size_t naddrs;
	struct dnsrefresh_job_t *next;
} dnsrefresh_job_t;

typedef struct dnsrefresh_result_t {
	char *node_name;
	char *hostname;
	sockaddr_t addr;                         /* first address of the answer (priority order) */
	sockaddr_t *addrs;                       /* all addresses returned by getaddrinfo */
	size_t naddrs;
	int gai_err;                             /* getaddrinfo error code when !ok */
	bool ok;                                 /* false = the name did not resolve */
	struct dnsrefresh_result_t *next;
} dnsrefresh_result_t;

static void dnsrefresh_free_job_list(dnsrefresh_job_t *list) {
	while(list) {
		dnsrefresh_job_t *next = list->next;
		free(list->node_name);
		free(list->hostname);
		free(list->port);
		free(list->addrs);
		free(list);
		list = next;
	}
}

static void dnsrefresh_free_result_list(dnsrefresh_result_t *list) {
	while(list) {
		dnsrefresh_result_t *next = list->next;
		free(list->node_name);
		free(list->hostname);
		free(list->addrs);
		free(list);
		list = next;
	}
}

/* Shared between the event loop and the worker. All fields except the
   queues are written only from the event loop; the queues use the mutex. */

static struct {
	bool started;
	pthread_t thread;
	pthread_mutex_t mutex;
	pthread_cond_t work;                   /* signalled when a batch is queued or stop is set */
	int notify_write_fd;                     /* event loop owns notify_read_fd via io_t */
	dnsrefresh_job_t *pending;               /* loop -> worker: resolve these */
	dnsrefresh_result_t *pending_done;       /* worker -> loop: answers to apply */
	bool stop;
#ifdef HAVE_WINDOWS
	HANDLE wake_event;                       /* not used for IO, kept for symmetry */
#endif
} dnsrefresh = {0};

static io_t dnsrefresh_io;

/* socketpair for POSIX, UDP loopback socketpair stand-in on Windows (a real
   socketpair does not exist there; an AF_INET/UDP pair on 127.0.0.1 gives
   the same wake-the-loop semantics and works with the select backend). */

static int dnsrefresh_pair[2] = {-1, -1};

#ifdef HAVE_WINDOWS
static bool dnsrefresh_make_pair(void) {
	struct sockaddr_in inaddr, peeraddr;
	SOCKET sock = INVALID_SOCKET;
	SOCKET peer = INVALID_SOCKET;
	int sock_size = sizeof(inaddr);
	int peer_size = sizeof(peeraddr);

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	if(sock == INVALID_SOCKET) {
		return false;
	}

	memset(&inaddr, 0, sizeof(inaddr));
	inaddr.sin_family = AF_INET;
	inaddr.sin_addr.s_addr = htonl(0x7f000001);

	if(bind(sock, (struct sockaddr *)&inaddr, sizeof(inaddr)) == SOCKET_ERROR) {
		closesocket(sock);
		return false;
	}

	getsockname(sock, (struct sockaddr *)&inaddr, &sock_size);

	peer = socket(AF_INET, SOCK_DGRAM, 0);

	if(peer == INVALID_SOCKET) {
		closesocket(sock);
		return false;
	}

	memset(&peeraddr, 0, sizeof(peeraddr));
	peeraddr.sin_family = AF_INET;
	peeraddr.sin_addr.s_addr = htonl(0x7f000001);

	if(bind(peer, (struct sockaddr *)&peeraddr, sizeof(peeraddr)) == SOCKET_ERROR) {
		closesocket(sock);
		closesocket(peer);
		return false;
	}

	getsockname(peer, (struct sockaddr *)&peeraddr, &peer_size);

	if(connect(peer, (struct sockaddr *)&inaddr, sock_size) == SOCKET_ERROR ||
	                connect(sock, (struct sockaddr *)&peeraddr, peer_size) == SOCKET_ERROR) {
		closesocket(sock);
		closesocket(peer);
		return false;
	}

	/* Datagram: nothing is ever buffered; wake bytes are drained below. */
	u_long nb = 1;
	ioctlsocket(sock, FIONBIO, &nb);
	nb = 1;
	ioctlsocket(peer, FIONBIO, &nb);

	dnsrefresh_pair[0] = (int)sock;
	dnsrefresh_pair[1] = (int)peer;
	return true;
}
#else
static bool dnsrefresh_make_pair(void) {
	if(socketpair(AF_UNIX, SOCK_DGRAM, 0, dnsrefresh_pair)) {
		return false;
	}

	/* Both ends non-blocking: the event loop's drain loop must see EAGAIN
	   when the wake bytes are exhausted, never block on an empty channel
	   (a blocking read here froze the whole daemon after the first wake). */
	for(int i = 0; i < 2; i++) {
		int flags = fcntl(dnsrefresh_pair[i], F_GETFL, 0);

		if(flags < 0 || fcntl(dnsrefresh_pair[i], F_SETFL, flags | O_NONBLOCK) < 0) {
			closesocket(dnsrefresh_pair[0]);
			closesocket(dnsrefresh_pair[1]);
			dnsrefresh_pair[0] = dnsrefresh_pair[1] = -1;
			return false;
		}
	}

	return true;
}
#endif

/* Persisted state: one line per watched name, next to the address cache.
   Format: "<node> <hostname> <ip> <port>\n" -- sockaddr2str gives
   "ip port". The port is whatever the Address statement carried (default
   655); it is part of the last-good endpoint. */

static void dnsrefresh_state_path(char *buf, size_t len) {
	snprintf(buf, len, "%s" SLASH "cache" SLASH "dnsrefresh.state", confbase);
}

static void dnsrefresh_load_state(dnsrefresh_job_t **jobs) {
	char path[PATH_MAX];
	dnsrefresh_state_path(path, sizeof(path));
	FILE *fp = fopen(path, "r");

	if(!fp) {
		return;
	}

	char line[512];

	while(fgets(line, sizeof(line), fp)) {
		char node_name[128], hostname[256], addrstr[128], portstr[16];

		if(sscanf(line, " %127s %255s %127s %15s", node_name, hostname, addrstr, portstr) != 4) {
			continue;
		}

		/* Re-attach to a live job further down; load_all_nodes() has run by
		   then, so the record only has to survive until the rebuild. The
		   PORT is the 4th column and must come back too: a job with a
		   NULL port crashed queue_batch's xstrdup (the lab's PART 3
		   startup segfault, 2026-10-07). */
		dnsrefresh_job_t *job = xzalloc(sizeof(*job));
		job->node_name = xstrdup(node_name);
		job->hostname = xstrdup(hostname);
		job->port = xstrdup(portstr);
		sockaddr_t sa = str2sockaddr(addrstr, portstr);

		if(sa.sa.sa_family != AF_UNKNOWN) {
			job->last_good = sa;
			job->has_last_good = true;
		}

		job->next = *jobs;
		*jobs = job;
	}

	fclose(fp);
}

static void dnsrefresh_save_state(dnsrefresh_job_t *jobs) {
	char path[PATH_MAX];
	dnsrefresh_state_path(path, sizeof(path));
	char tmp[PATH_MAX + 8];
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	FILE *fp = fopen(tmp, "w");

	if(!fp) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Could not open %s for writing: %s", tmp, strerror(errno));
		return;
	}

	for(dnsrefresh_job_t *j = jobs; j; j = j->next) {
		if(!j->has_last_good) {
			continue;
		}

		char *addrstr = NULL;
		char *portstr = NULL;
		sockaddr2str(&j->last_good, &addrstr, &portstr);

		if(addrstr && portstr) {
			fprintf(fp, "%s %s %s %s\n", j->node_name, j->hostname, addrstr, portstr);
		}

		free(addrstr);
		free(portstr);
	}

	fclose(fp);

	if(rename(tmp, path)) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Could not rename %s: %s", tmp, strerror(errno));
	}
}

/* ── worker thread ─────────────────────────────────────────────────────── */

/* Numeric-only guard: the name came out of a config file, and an Address
   statement is allowed to be a literal IP -- those are not watched, but a
   cheap parse here catches a stray one without a resolver round trip. */

static bool dnsrefresh_is_name(const char *s) {
	struct addrinfo hint = {0};
	struct addrinfo *ai = NULL;
	hint.ai_flags = AI_NUMERICHOST;
	hint.ai_socktype = SOCK_STREAM;
	int err = getaddrinfo(s, NULL, &hint, &ai);

	if(!err && ai) {
		freeaddrinfo(ai);
		return false;
	}

	return true;
}

static void *dnsrefresh_thread(void *arg) {
	(void)arg;

	pthread_mutex_lock(&dnsrefresh.mutex);

	while(!dnsrefresh.stop) {
		/* Wait for the timer to queue a batch (or for shutdown). Without
		   this wait the loop span on an empty queue: a full core of spin
		   and a wake byte per iteration. */
		while(!dnsrefresh.stop && !dnsrefresh.pending) {
			pthread_cond_wait(&dnsrefresh.work, &dnsrefresh.mutex);
		}

		if(dnsrefresh.stop) {
			break;
		}

		dnsrefresh_job_t *batch = dnsrefresh.pending;
		dnsrefresh.pending = NULL;
		pthread_mutex_unlock(&dnsrefresh.mutex);

		dnsrefresh_result_t *results = NULL;

		for(dnsrefresh_job_t *j = batch; j; j = j->next) {
			dnsrefresh_result_t *r = xzalloc(sizeof(*r));
			r->node_name = xstrdup(j->node_name);
			r->hostname = xstrdup(j->hostname);

			if(!dnsrefresh_is_name(j->hostname)) {
				/* A literal IP is its own answer; report ok so the loop
				   side never worries about it again (it is skipped when
				   the watch list is rebuilt, so this is defensive). */
				sockaddr_t sa = str2sockaddr(j->hostname, j->port ? j->port : "655");

				if(sa.sa.sa_family != AF_UNKNOWN) {
					r->addr = sa;
					r->addrs = xmalloc(sizeof(sockaddr_t));
					r->addrs[0] = sa;
					r->naddrs = 1;
					r->ok = true;
				} else {
					r->ok = false;
				}
			} else {
				struct addrinfo hint = {0};
				struct addrinfo *ai = NULL;
				hint.ai_socktype = SOCK_STREAM;
				/* Resolve WITH the port: a port-0 sockaddr cannot be
				   dialled, and the last-good endpoint must carry the
				   port the Address statement names (default 655). */
				int err = getaddrinfo(j->hostname, j->port ? j->port : "655", &hint, &ai);

				if(!err && ai) {
					/* The resolver's first answer, in its priority order, plus all
					   returned records so multi-A/AAAA names do not flap. */
					memcpy(&r->addr, ai->ai_addr, ai->ai_addrlen);
					size_t count = 0;
					for(struct addrinfo *aip = ai; aip; aip = aip->ai_next) {
						if(aip->ai_addr && aip->ai_addrlen <= sizeof(sockaddr_t)) {
							count++;
						}
					}
					if(count > 0) {
						r->addrs = xzalloc(count * sizeof(sockaddr_t));
						for(struct addrinfo *aip = ai; aip; aip = aip->ai_next) {
							if(aip->ai_addr && aip->ai_addrlen <= sizeof(sockaddr_t)) {
								memcpy(&r->addrs[r->naddrs++], aip->ai_addr, aip->ai_addrlen);
							}
						}
					}
					r->ok = true;
					freeaddrinfo(ai);
				} else {
					r->ok = false;
					r->gai_err = err;
					if(ai) {
						freeaddrinfo(ai);
					}
				}
			}

			r->next = results;
			results = r;
		}

		/* Free the batch; results cross the boundary and are freed by the
		   event loop. */
		dnsrefresh_free_job_list(batch);

		/* Publish the results under the mutex FIRST, then wake the loop.
		   The old order (wake, then publish) raced: the loop drained the
		   wake byte, took an empty list and went back to sleep, and the
		   results -- appended a moment later -- were freed as stale by the
		   next tick without ever being applied. */
		pthread_mutex_lock(&dnsrefresh.mutex);

		/* Append to the done list the loop drains. */
		if(!dnsrefresh.pending_done) {
			dnsrefresh.pending_done = results;
		} else {
			dnsrefresh_result_t *t = dnsrefresh.pending_done;

			while(t->next) {
				t = t->next;
			}

			t->next = results;
		}

		pthread_mutex_unlock(&dnsrefresh.mutex);

		if(send(dnsrefresh_pair[1], "R", 1, 0) < 0 && !sockwouldblock(sockerrno)) {
			/* Loop gone; it will reap us at shutdown. The results stay
			   on the done list; nothing leaks per tick. */
		}

		pthread_mutex_lock(&dnsrefresh.mutex);
	}

	pthread_mutex_unlock(&dnsrefresh.mutex);
	return NULL;
}

/* ── event-loop side ───────────────────────────────────────────────────── */

/* The live watch list, owned by the event loop. Rebuilt from the host
   records on start and on every reload. */

static dnsrefresh_job_t *dnsrefresh_jobs = NULL;

static void dnsrefresh_free_jobs(void) {
	dnsrefresh_free_job_list(dnsrefresh_jobs);
	dnsrefresh_jobs = NULL;
}

static bool dnsrefresh_job_match(const dnsrefresh_job_t *j, const char *node_name, const char *hostname) {
	return !strcmp(j->node_name, node_name) && !strcmp(j->hostname, hostname);
}

/* Collect every Address statement of every node's host record that is a
   DNS name. In YAML mode the host text comes from the YAML store; in
   classic mode from hosts/<name>. */

static void dnsrefresh_rebuild(void) {
	dnsrefresh_job_t *old_jobs = dnsrefresh_jobs;
	dnsrefresh_jobs = NULL;

	/* Also load persisted last-good endpoints from disk in case this is the
	   first rebuild since startup. */
	dnsrefresh_job_t *saved_disk = NULL;
	dnsrefresh_load_state(&saved_disk);

	for splay_each(node_t, n, &node_tree) {
		if(n == myself) {
			continue;
		}

		splay_tree_t *config = create_configuration();
		read_host_config(config, n->name, false);
		config_t *cfg = lookup_config(config, "Address");

		while(cfg) {
			char *address = NULL;
			get_config_string(cfg, &address);

			if(address && *address) {
				char *space = strchr(address, ' ');
				char *port = NULL;

				if(space) {
					port = xstrdup(space + 1);
					*space = 0;
				}

				if(!port) {
					/* No port in the Address statement: the host record's
					   Port option, else tinc's default. */
					char *p = NULL;
					get_config_string(lookup_config(config, "Port"), &p);

					if(p && *p) {
						port = p;
					} else {
						free(p);
					}
				}

				if(dnsrefresh_is_name(address)) {
					/* Skip duplicates (same node+name). */
					bool dup = false;

					for(dnsrefresh_job_t *j = dnsrefresh_jobs; j; j = j->next) {
						if(dnsrefresh_job_match(j, n->name, address)) {
							dup = true;
							break;
						}
					}

					if(!dup) {
						dnsrefresh_job_t *job = xzalloc(sizeof(*job));
						job->node_name = xstrdup(n->name);
						job->hostname = xstrdup(address);
						job->port = xstrdup(port ? port : "655");

						for(dnsrefresh_job_t *oj = old_jobs; oj; oj = oj->next) {
							if(dnsrefresh_job_match(oj, n->name, address)) {
								job->last_good = oj->last_good;
								job->has_last_good = oj->has_last_good;
								if(oj->addrs && oj->naddrs > 0) {
									job->addrs = xmalloc(oj->naddrs * sizeof(sockaddr_t));
									memcpy(job->addrs, oj->addrs, oj->naddrs * sizeof(sockaddr_t));
									job->naddrs = oj->naddrs;
								}
								break;
							}
						}

						if(!job->has_last_good) {
							for(dnsrefresh_job_t *sj = saved_disk; sj; sj = sj->next) {
								if(dnsrefresh_job_match(sj, n->name, address) && sj->has_last_good) {
									job->last_good = sj->last_good;
									job->has_last_good = true;
									break;
								}
							}
						}

						job->next = dnsrefresh_jobs;
						dnsrefresh_jobs = job;
					}
				}

				free(port);
			}

			free(address);
			cfg = lookup_config_next(config, cfg);
		}

		exit_configuration(config);
	}

	dnsrefresh_free_job_list(old_jobs);
	dnsrefresh_free_job_list(saved_disk);
}

static void dnsrefresh_queue_batch(void) {
	if(!dnsrefresh.started || dnsrefresh_interval <= 0) {
		return;
	}

	dnsrefresh_job_t *copy = NULL;

	for(dnsrefresh_job_t *j = dnsrefresh_jobs; j; j = j->next) {
		dnsrefresh_job_t *c = xzalloc(sizeof(*c));
		c->node_name = xstrdup(j->node_name);
		c->hostname = xstrdup(j->hostname);
		/* Defensive: a job with no port (should not exist after the
		   load_state fix) still must not crash the strdup. */
		c->port = xstrdup(j->port ? j->port : "655");
		c->next = copy;
		copy = c;
	}

	pthread_mutex_lock(&dnsrefresh.mutex);
	dnsrefresh_result_t *stale = dnsrefresh.pending_done;
	dnsrefresh_job_t *old_pending = dnsrefresh.pending;
	dnsrefresh.pending_done = NULL;
	dnsrefresh.pending = copy;
	pthread_cond_signal(&dnsrefresh.work);
	pthread_mutex_unlock(&dnsrefresh.mutex);

	dnsrefresh_free_job_list(old_pending);
	dnsrefresh_free_result_list(stale);
}

static bool dnsrefresh_ip_equal(const sockaddr_t *a, const sockaddr_t *b) {
	if(a->sa.sa_family != b->sa.sa_family) {
		return false;
	}

	if(a->sa.sa_family == AF_INET) {
		return a->in.sin_addr.s_addr == b->in.sin_addr.s_addr;
	}

	if(a->sa.sa_family == AF_INET6) {
		return !memcmp(&a->in6.sin6_addr, &b->in6.sin6_addr, sizeof(struct in6_addr));
	}

	return false;
}

/* Does the fresh answer still list the address a live connection is on? */

static bool dnsrefresh_answer_lists(const dnsrefresh_result_t *r, const sockaddr_t *sa) {
	/* The live endpoint's PORT is not comparable: an accepted connection sits
	   on the peer's ephemeral source port, and a carrier connection may use
	   HttpsPort/QuicPort/ObfsPort, while the resolved address carries the
	   service port. Compare address family + IP across all returned records. */
	if(!r->ok) {
		return false;
	}

	if(r->addrs && r->naddrs > 0) {
		for(size_t i = 0; i < r->naddrs; i++) {
			if(dnsrefresh_ip_equal(&r->addrs[i], sa)) {
				return true;
			}
		}
		return false;
	}

	return dnsrefresh_ip_equal(&r->addr, sa);
}

static bool dnsrefresh_job_lists(const dnsrefresh_job_t *j, const sockaddr_t *sa) {
	if(j->addrs && j->naddrs > 0) {
		for(size_t i = 0; i < j->naddrs; i++) {
			if(dnsrefresh_ip_equal(&j->addrs[i], sa)) {
				return true;
			}
		}
		return false;
	}

	if(j->has_last_good) {
		return dnsrefresh_ip_equal(&j->last_good, sa);
	}

	return false;
}

static void dnsrefresh_apply(dnsrefresh_result_t *r) {
	/* Find the live job to update last_good. */
	dnsrefresh_job_t *job = NULL;

	for(dnsrefresh_job_t *j = dnsrefresh_jobs; j; j = j->next) {
		if(dnsrefresh_job_match(j, r->node_name, r->hostname)) {
			job = j;
			break;
		}
	}

	if(!job) {
		return;
	}

	if(r->ok) {
		free(job->addrs);
		job->addrs = NULL;
		job->naddrs = 0;
		if(r->addrs && r->naddrs > 0) {
			job->addrs = xmalloc(r->naddrs * sizeof(sockaddr_t));
			memcpy(job->addrs, r->addrs, r->naddrs * sizeof(sockaddr_t));
			job->naddrs = r->naddrs;
		}

		bool changed = !job->has_last_good || !dnsrefresh_answer_lists(r, &job->last_good);

		if(changed) {
			char old[128] = "(none)";
			char *addrstr = NULL;
			char *portstr = NULL;
			sockaddr2str(&r->addr, &addrstr, &portstr);

			if(job->has_last_good) {
				char *oa = NULL;
				char *op = NULL;
				sockaddr2str(&job->last_good, &oa, &op);

				if(oa) {
					snprintf(old, sizeof(old), "%s", oa);
					free(oa);
				}

				free(op);
			}

			logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Address of %s (%s) changed in DNS: %s -> %s; following",
			       r->node_name, r->hostname, old, addrstr ? addrstr : "?");
			free(addrstr);
			free(portstr);

			job->last_good = r->addr;
			job->has_last_good = true;
			dnsrefresh_save_state(dnsrefresh_jobs);
		}
	} else {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "dnsrefresh: %s (%s) did not resolve (%s); keeping the last-known address",
		       r->node_name, r->hostname, r->gai_err ? gai_strerror(r->gai_err) : "empty answer");
	}

	/* The owner's rule: when DNS no longer lists the address a live meta
	   connection is using, drop that connection so the re-dial goes to the
	   address DNS now returns. Only the direct connection to that node is
	   touched; relayed paths are the graph's business. */
	node_t *n = lookup_node(r->node_name);

	if(!n || !n->connection || !r->ok) {
		return;
	}

	sockaddr_t *live = &n->connection->address;

	/* Check if ANY watched DNS name for this node still lists the live IP. */
	bool any_job_lists = dnsrefresh_answer_lists(r, live);
	if(!any_job_lists) {
		for(dnsrefresh_job_t *j = dnsrefresh_jobs; j; j = j->next) {
			if(j != job && !strcmp(j->node_name, r->node_name) && dnsrefresh_job_lists(j, live)) {
				any_job_lists = true;
				break;
			}
		}
	}

	if(!any_job_lists) {
		char *old = NULL;
		char *oldp = NULL;
		char *new = NULL;
		char *newp = NULL;
		sockaddr2str(live, &old, &oldp);
		sockaddr2str(&r->addr, &new, &newp);
		logger(DEBUG_CONNECTIONS, LOG_NOTICE, "dnsrefresh: %s moved from %s to %s in DNS; reconnecting", r->node_name, old ? old : "?", new ? new : "?");
		free(old);
		free(oldp);
		free(new);
		free(newp);

		/* Only a connection WE dialled to the watched name is ours to move:
		   an accepted connection's address is the peer's own source address
		   (ephemeral port, its routing choice), and enforcing the record on
		   it would flap the link every interval while the peer keeps
		   dialling us from the address it still holds. When that address
		   dies for real, the accepted connection dies with it (dead-peer
		   detection) and the re-dial goes to what DNS now returns. */
		if(!n->connection->outgoing) {
			return;
		}

		if(n->address_cache) {
			/* The old address must leave the candidate list entirely -- by
			   IP, the cached spellings carry ephemeral ports -- or the
			   re-dial walks straight back to it while the peer still
			   answers there. */
			drop_address_ip(n->address_cache, live);
			reset_address_cache(n->address_cache);
		}

		terminate_connection(n->connection, true);
	}
}

static void dnsrefresh_handle_results(void) {
	pthread_mutex_lock(&dnsrefresh.mutex);
	dnsrefresh_result_t *results = dnsrefresh.pending_done;
	dnsrefresh.pending_done = NULL;
	pthread_mutex_unlock(&dnsrefresh.mutex);

	/* First pass: update job->addrs for all results in the batch so
	   multi-Address nodes have complete state before checking connections. */
	for(dnsrefresh_result_t *r = results; r; r = r->next) {
		if(!r->ok) {
			continue;
		}
		for(dnsrefresh_job_t *j = dnsrefresh_jobs; j; j = j->next) {
			if(dnsrefresh_job_match(j, r->node_name, r->hostname)) {
				free(j->addrs);
				j->addrs = NULL;
				j->naddrs = 0;
				if(r->addrs && r->naddrs > 0) {
					j->addrs = xmalloc(r->naddrs * sizeof(sockaddr_t));
					memcpy(j->addrs, r->addrs, r->naddrs * sizeof(sockaddr_t));
					j->naddrs = r->naddrs;
				}
				break;
			}
		}
	}

	while(results) {
		dnsrefresh_result_t *next = results->next;
		dnsrefresh_apply(results);
		free(results->node_name);
		free(results->hostname);
		free(results->addrs);
		free(results);
		results = next;
	}
}

static void dnsrefresh_io_cb(void *data, int flags) {
	(void)data;
	(void)flags;
	char buf[64];

	/* Drain the wake byte(s); datagram socketpair cannot buffer much. */
	while(recv(dnsrefresh_pair[0], buf, sizeof(buf), 0) > 0) {
	}

	dnsrefresh_handle_results();
}

static timeout_t dnsrefresh_timer;

static void dnsrefresh_timer_cb(void *data) {
	(void)data;

	if(dnsrefresh_interval <= 0) {
		return;
	}

	dnsrefresh_rebuild();
	dnsrefresh_queue_batch();

	timeout_set(&dnsrefresh_timer, &(struct timeval) {
		dnsrefresh_interval, jitter()
	});
}

void dnsrefresh_init(void) {
	if(dnsrefresh.started || dnsrefresh_interval <= 0) {
		return;
	}

	if(!dnsrefresh_make_pair()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "dnsrefresh: could not create the wake channel; DNS polling is off");
		return;
	}

	dnsrefresh.stop = false;
	pthread_mutex_init(&dnsrefresh.mutex, NULL);
	pthread_cond_init(&dnsrefresh.work, NULL);

	if(pthread_create(&dnsrefresh.thread, NULL, dnsrefresh_thread, NULL)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "dnsrefresh: could not start the resolver thread; DNS polling is off");
		closesocket(dnsrefresh_pair[0]);
		closesocket(dnsrefresh_pair[1]);
		dnsrefresh_pair[0] = dnsrefresh_pair[1] = -1;
		pthread_mutex_destroy(&dnsrefresh.mutex);
		pthread_cond_destroy(&dnsrefresh.work);
		return;
	}

	dnsrefresh.started = true;
	io_add(&dnsrefresh_io, dnsrefresh_io_cb, NULL, dnsrefresh_pair[0], IO_READ);

	dnsrefresh_rebuild();
	dnsrefresh_queue_batch();

	timeout_add(&dnsrefresh_timer, dnsrefresh_timer_cb, &dnsrefresh_timer, &(struct timeval) {
		dnsrefresh_interval, jitter()
	});

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "dnsrefresh: watching host records every %d s", dnsrefresh_interval);
}

void dnsrefresh_exit(void) {
	if(!dnsrefresh.started) {
		return;
	}

	timeout_del(&dnsrefresh_timer);
	io_del(&dnsrefresh_io);

	pthread_mutex_lock(&dnsrefresh.mutex);
	dnsrefresh.stop = true;
	pthread_cond_signal(&dnsrefresh.work);
	pthread_mutex_unlock(&dnsrefresh.mutex);

	if(send(dnsrefresh_pair[1], "S", 1, 0) < 0 && !sockwouldblock(sockerrno)) {
		/* The loop is gone; pthread_join below still reaps the thread. */
	}

	pthread_join(dnsrefresh.thread, NULL);

	dnsrefresh_free_job_list(dnsrefresh.pending);
	dnsrefresh.pending = NULL;
	dnsrefresh_free_result_list(dnsrefresh.pending_done);
	dnsrefresh.pending_done = NULL;

	closesocket(dnsrefresh_pair[0]);
	closesocket(dnsrefresh_pair[1]);
	dnsrefresh_pair[0] = dnsrefresh_pair[1] = -1;
	pthread_mutex_destroy(&dnsrefresh.mutex);
	pthread_cond_destroy(&dnsrefresh.work);
	dnsrefresh_free_jobs();
	dnsrefresh.started = false;
}

/* Re-read the interval after a reload; a zero disables (timer stops). */

void dnsrefresh_reload(void) {
	if(!dnsrefresh.started) {
		/* Could have been enabled by the reload. */
		if(dnsrefresh_interval > 0) {
			dnsrefresh_init();
		}

		return;
	}

	if(dnsrefresh_interval <= 0) {
		/* Disabled by reload: keep the thread but stop the timer. */
		timeout_del(&dnsrefresh_timer);
		logger(DEBUG_CONNECTIONS, LOG_NOTICE, "dnsrefresh: disabled (DnsRefreshInterval = 0)");
		return;
	}

	timeout_set(&dnsrefresh_timer, &(struct timeval) {
		dnsrefresh_interval, jitter()
	});

	dnsrefresh_rebuild();
	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "dnsrefresh: interval is now %d s", dnsrefresh_interval);
}

/* The dial walk can call this to offer a last-good address for a watched
   name (D2): below the live cache, above re-reading Address. */

const sockaddr_t *dnsrefresh_last_good(const char *node_name, const char *hostname) {
	for(dnsrefresh_job_t *j = dnsrefresh_jobs; j; j = j->next) {
		if(dnsrefresh_job_match(j, node_name, hostname) && j->has_last_good) {
			return &j->last_good;
		}
	}

	return NULL;
}

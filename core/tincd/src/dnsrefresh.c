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
	struct dnsrefresh_job_t *next;
} dnsrefresh_job_t;

typedef struct dnsrefresh_result_t {
	char *node_name;
	char *hostname;
	sockaddr_t addr;                         /* first address of the answer (priority order) */
	bool ok;                                 /* false = the name did not resolve */
	struct dnsrefresh_result_t *next;
} dnsrefresh_result_t;

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
	struct sockaddr_in inaddr;
	SOCKET sock = INVALID_SOCKET;
	SOCKET peer = INVALID_SOCKET;
	int sock_size = sizeof(inaddr);

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

	if(connect(peer, (struct sockaddr *)&inaddr, sock_size) == SOCKET_ERROR) {
		closesocket(sock);
		closesocket(peer);
		return false;
	}

	/* Datagram: nothing is ever buffered; wake bytes are drained below. */
	u_long nb = 1;
	ioctlsocket(sock, FIONBIO, &nb);

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
			close(dnsrefresh_pair[0]);
			close(dnsrefresh_pair[1]);
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
					/* The resolver's first answer, in its priority order. */
					memcpy(&r->addr, ai->ai_addr, ai->ai_addrlen);
					r->ok = true;
					freeaddrinfo(ai);
				} else {
					r->ok = false;
					logger(DEBUG_CONNECTIONS, LOG_DEBUG, "dnsrefresh: %s did not resolve: %s", j->hostname,
					       err ? gai_strerror(err) : "empty answer");
				}
			}

			r->next = results;
			results = r;
		}

		/* Free the batch; results cross the boundary and are freed by the
		   event loop. */
		while(batch) {
			dnsrefresh_job_t *next = batch->next;
			free(batch->node_name);
			free(batch->hostname);
			free(batch->port);
			free(batch);
			batch = next;
		}

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

		if(write(dnsrefresh_pair[1], "R", 1) < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			/* Loop gone; it will reap us at shutdown. The results stay
			   on the done list; nothing leaks per tick. */
		}
	}

	pthread_mutex_unlock(&dnsrefresh.mutex);
	return NULL;
}

/* ── event-loop side ───────────────────────────────────────────────────── */

/* The live watch list, owned by the event loop. Rebuilt from the host
   records on start and on every reload. */

static dnsrefresh_job_t *dnsrefresh_jobs = NULL;

static void dnsrefresh_free_jobs(void) {
	while(dnsrefresh_jobs) {
		dnsrefresh_job_t *next = dnsrefresh_jobs->next;
		free(dnsrefresh_jobs->node_name);
		free(dnsrefresh_jobs->hostname);
		free(dnsrefresh_jobs->port);
		free(dnsrefresh_jobs);
		dnsrefresh_jobs = next;
	}
}

static bool dnsrefresh_job_match(const dnsrefresh_job_t *j, const char *node_name, const char *hostname) {
	return !strcmp(j->node_name, node_name) && !strcmp(j->hostname, hostname);
}

/* Collect every Address statement of every node's host record that is a
   DNS name. In YAML mode the host text comes from the YAML store; in
   classic mode from hosts/<name>. */

static void dnsrefresh_rebuild(void) {
	dnsrefresh_free_jobs();

	/* Reload persisted last-good endpoints first: a job found again below
	   re-attaches to its saved address. */
	dnsrefresh_load_state(&dnsrefresh_jobs);

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
	dnsrefresh.pending_done = NULL;
	dnsrefresh.pending = copy;
	pthread_cond_signal(&dnsrefresh.work);
	pthread_mutex_unlock(&dnsrefresh.mutex);

	while(stale) {
		dnsrefresh_result_t *next = stale->next;
		free(stale->node_name);
		free(stale->hostname);
		free(stale);
		stale = next;
	}
}

/* Does the fresh answer still list the address a live connection is on? */

static bool dnsrefresh_answer_lists(const dnsrefresh_result_t *r, const sockaddr_t *sa) {
	/* The result carries only the first address (the one we follow). The
	   live endpoint's PORT is not comparable: an accepted connection sits
	   on the peer's ephemeral source port, while the resolved address
	   carries the service port. Compare address family + IP only; the
	   service port rides along in the resolved sockaddr for the re-dial. */
	if(!r->ok || r->addr.sa.sa_family != sa->sa.sa_family) {
		return false;
	}

	if(r->addr.sa.sa_family == AF_INET) {
		return r->addr.in.sin_addr.s_addr == sa->in.sin_addr.s_addr;
	}

	if(r->addr.sa.sa_family == AF_INET6) {
		return !memcmp(&r->addr.in6.sin6_addr, &sa->in6.sin6_addr, sizeof(struct in6_addr));
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
		bool changed = !job->has_last_good || sockaddrcmp(&job->last_good, &r->addr);

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
		logger(DEBUG_CONNECTIONS, LOG_INFO, "dnsrefresh: %s (%s) did not resolve; keeping the last-known address", r->node_name, r->hostname);
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

	if(!dnsrefresh_answer_lists(r, live)) {
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

	while(results) {
		dnsrefresh_result_t *next = results->next;
		dnsrefresh_apply(results);
		free(results->node_name);
		free(results->hostname);
		free(results);
		results = next;
	}
}

static void dnsrefresh_io_cb(void *data, int flags) {
	(void)data;
	(void)flags;
	char buf[64];

	/* Drain the wake byte(s); datagram socketpair cannot buffer much. */
	while(read(dnsrefresh_pair[0], buf, sizeof(buf)) > 0) {
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

	pthread_mutex_init(&dnsrefresh.mutex, NULL);
	pthread_cond_init(&dnsrefresh.work, NULL);

	if(pthread_create(&dnsrefresh.thread, NULL, dnsrefresh_thread, NULL)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "dnsrefresh: could not start the resolver thread; DNS polling is off");
		close(dnsrefresh_pair[0]);
		close(dnsrefresh_pair[1]);
		dnsrefresh_pair[0] = dnsrefresh_pair[1] = -1;
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

	if(write(dnsrefresh_pair[1], "S", 1) < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		/* The loop is gone; pthread_join below still reaps the thread. */
	}

	pthread_join(dnsrefresh.thread, NULL);

	close(dnsrefresh_pair[0]);
	close(dnsrefresh_pair[1]);
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

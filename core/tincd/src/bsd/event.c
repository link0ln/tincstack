/*
    event.c -- kqueue support for the BSD family
    Copyright (C) 2012-2022 Guus Sliepen <guus@tinc-vpn.org>

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

#include "../system.h"

#include <sys/event.h>

#include "../event.h"
#include "../utils.h"
#include "../net.h"

static bool running = false;
static int kq = 0;

static inline void event_init(void) {
	if(!kq) {
		kq = kqueue();

		if(kq == -1) {
			logger(DEBUG_ALWAYS, LOG_EMERG, "Could not initialize kqueue: %s", strerror(errno));
			abort();
		}
	}
}

static void event_deinit(void) {
	if(kq) {
		close(kq);
		kq = 0;
	}
}

void io_add(io_t *io, io_cb_t cb, void *data, int fd, int flags) {
	if(io->cb) {
		return;
	}

	io->fd = fd;
	io->flags = 0;
	io->cb = cb;
	io->data = data;
	io->node.data = io;

	io_set(io, flags);
}

void io_set(io_t *io, int flags) {
	event_init();

	int prev_flags = io->flags;

	if(flags == prev_flags) {
		return;
	}

	io->flags = flags;

	if(io->fd == -1) {
		return;
	}

	struct kevent change[2];
	struct kevent result[2];
	int nchanges = 0;

	if((flags & IO_READ) != (prev_flags & IO_READ)) {
		EV_SET(&change[nchanges++], io->fd, EVFILT_READ,
		       EV_RECEIPT | ((flags & IO_READ) ? (EV_ADD | EV_ENABLE) : EV_DELETE),
		       0, 0, io);
	}

	if((flags & IO_WRITE) != (prev_flags & IO_WRITE)) {
		EV_SET(&change[nchanges++], io->fd, EVFILT_WRITE,
		       EV_RECEIPT | ((flags & IO_WRITE) ? (EV_ADD | EV_ENABLE) : EV_DELETE),
		       0, 0, io);
	}

	if(nchanges > 0) {
		if(kevent(kq, change, nchanges, result, nchanges, NULL) < 0) {
			logger(DEBUG_ALWAYS, LOG_EMERG, "kevent failed: %s", strerror(errno));
			abort();
		}

		for(int i = 0; i < nchanges; i++) {
			int err = (result[i].flags & EV_ERROR) ? (int)result[i].data : 0;

			if(err && err != ENOENT) {
				logger(DEBUG_ALWAYS, LOG_EMERG, "kevent filter %d error: %s",
				       (int)result[i].filter, strerror(err));
				abort();
			}
		}
	}

	if(!flags) {
		io_tree.generation++;
	}
}

void io_del(io_t *io) {
	if(io->cb) {
		io_set(io, 0);
		io->cb = NULL;
	}
}

bool event_loop(void) {
	event_init();
	running = true;

	while(running) {
		struct timeval diff;
		struct timeval *tv = timeout_execute(&diff);

		if(!running) {
			break;
		}

		struct kevent events[MAX_EVENTS_PER_LOOP];
		struct timespec ts;
		const struct timespec *tsp = NULL;

		if(tv) {
			if(tv->tv_sec < 0 || (tv->tv_sec == 0 && tv->tv_usec <= 0)) {
				ts.tv_sec = 0;
				ts.tv_nsec = 0;
			} else {
				ts.tv_sec = tv->tv_sec;
				ts.tv_nsec = tv->tv_usec * 1000;
			}

			tsp = &ts;
		}

		int n = kevent(kq, NULL, 0, events, MAX_EVENTS_PER_LOOP, tsp);

		if(n < 0) {
			if(sockwouldblock(sockerrno)) {
				continue;
			} else {
				return false;
			}
		}

		if(!n) {
			continue;
		}

		gettimeofday(&now, NULL);

		unsigned int curgen = io_tree.generation;

		for(int i = 0; i < n; i++) {
			const struct kevent *evt = &events[i];
			io_t *io = evt->udata;

			if(!io || !io->cb || io->flags == 0) {
				continue;
			}

			if(evt->filter == EVFILT_WRITE && (io->flags & IO_WRITE)) {
				io->cb(io->data, IO_WRITE);
			} else if(evt->filter == EVFILT_READ && (io->flags & IO_READ)) {
				io->cb(io->data, IO_READ);
			} else if((evt->flags & EV_EOF) && (io->flags & IO_READ)) {
				io->cb(io->data, IO_READ);
			} else if((evt->flags & EV_EOF) && (io->flags & IO_WRITE)) {
				io->cb(io->data, IO_WRITE);
			} else {
				continue;
			}

			if(!running || curgen != io_tree.generation) {
				break;
			}
		}
	}

	event_deinit();
	return true;
}

void event_exit(void) {
	running = false;
}

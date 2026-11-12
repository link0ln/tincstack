/*
    event.c -- epoll support for Linux
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

#include <sys/epoll.h>
#include <sys/syscall.h>

#include "../event.h"
#include "../utils.h"
#include "../net.h"

static bool running = false;
static int epollset = 0;

/* NOTE: 1024 limit is only used on ancient (pre 2.6.27) kernels.
   Decent kernels will ignore this value making it unlimited.
   epoll_create1 might be better, but these kernels would not be supported
   in that case. */
static inline void event_init(void) {
	if(!epollset) {
		epollset = epoll_create(1024);

		if(epollset == -1) {
			logger(DEBUG_ALWAYS, LOG_EMERG, "Could not initialize epoll: %s", strerror(errno));
			abort();
		}
	}
}

static void event_deinit(void) {
	if(epollset) {
		close(epollset);
		epollset = 0;
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

	if(flags == io->flags) {
		return;
	}

	io->flags = flags;

	if(io->fd == -1) {
		return;
	}

	epoll_ctl(epollset, EPOLL_CTL_DEL, io->fd, NULL);

	struct epoll_event ev = {
		.events = 0,
		.data.ptr = io,
	};

	if(flags & IO_READ) {
		ev.events |= EPOLLIN;
	}

	if(flags & IO_WRITE) {
		ev.events |= EPOLLOUT;
	}

	if(ev.events == 0) {
		io_tree.generation++;
		return;
	}

	if(epoll_ctl(epollset, EPOLL_CTL_ADD, io->fd, &ev) < 0) {
		logger(DEBUG_ALWAYS, LOG_EMERG, "epoll_ctl failed: %s", strerror(errno));
		abort();
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

		struct epoll_event events[MAX_EVENTS_PER_LOOP];
		int n = -1;
#if defined(__NR_epoll_pwait2) && !defined(__ANDROID__)
		static bool have_pwait2 = true;

		if(have_pwait2) {
			struct timespec ts;

			if(tv) {
				ts.tv_sec = tv->tv_sec;
				ts.tv_nsec = tv->tv_usec * 1000;
			}

			n = epoll_pwait2(epollset, events, MAX_EVENTS_PER_LOOP, tv ? &ts : NULL, NULL);

			if(n < 0 && errno == ENOSYS) {
				have_pwait2 = false;
			}
		}

		if(!have_pwait2)
#endif
		{
			/* Round up. Truncated, a timer less than a millisecond away became
			   epoll_wait(0) and the loop spun until it was due; the quic carrier
			   arms ngtcp2's microsecond timers on every packet, so at 1 Mbit/s
			   that spin was 15 % of a core (windows/event.c adds 1 for the same
			   reason). */
			int64_t timeout = -1;

			if(tv) {
				if(tv->tv_sec < 0 || (tv->tv_sec == 0 && tv->tv_usec <= 0)) {
					timeout = 0;
				} else if((int64_t)tv->tv_sec > INT_MAX / 1000 - 2) {
					timeout = INT_MAX;
				} else {
					timeout = ((int64_t)tv->tv_sec * 1000) + ((tv->tv_usec + 999) / 1000);

					if(timeout > INT_MAX) {
						timeout = INT_MAX;
					}
				}
			}

			n = epoll_wait(epollset, events, MAX_EVENTS_PER_LOOP, (int)timeout);
		}

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
			io_t *io = events[i].data.ptr;
			uint32_t revents = events[i].events;

			if(!io || !io->cb || io->flags == 0) {
				if(io && io->fd != -1) {
					epoll_ctl(epollset, EPOLL_CTL_DEL, io->fd, NULL);
				}

				continue;
			}

			if((revents & EPOLLOUT) && (io->flags & IO_WRITE)) {
				io->cb(io->data, IO_WRITE);
			}

			if(!running || curgen != io_tree.generation) {
				break;
			}

			if((revents & (EPOLLIN | EPOLLERR | EPOLLHUP)) && (io->flags & IO_READ)) {
				io->cb(io->data, IO_READ);
			} else if((revents & (EPOLLERR | EPOLLHUP)) && !(revents & EPOLLOUT)) {
				if(io->flags & IO_WRITE) {
					io->cb(io->data, IO_WRITE);
				} else if(io->fd != -1) {
					epoll_ctl(epollset, EPOLL_CTL_DEL, io->fd, NULL);
				}
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

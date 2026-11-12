/*
    event.c -- I/O, timeout, and event handling
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

#include "system.h"

#include "event.h"

struct timeval now;

static int io_compare(const io_t *a, const io_t *b) {
#ifndef HAVE_WINDOWS
	return a->fd - b->fd;
#else

	if(a->event < b->event) {
		return -1;
	}

	if(a->event > b->event) {
		return 1;
	}

	return 0;
#endif
}

static int timeout_compare(const timeout_t *a, const timeout_t *b) {
	struct timeval diff;
	timersub(&a->tv, &b->tv, &diff);

	if(diff.tv_sec < 0) {
		return -1;
	}

	if(diff.tv_sec > 0) {
		return 1;
	}

	if(diff.tv_usec < 0) {
		return -1;
	}

	if(diff.tv_usec > 0) {
		return 1;
	}

	uintptr_t ap = (uintptr_t)a;
	uintptr_t bp = (uintptr_t)b;

	if(ap < bp) {
		return -1;
	}

	if(ap > bp) {
		return 1;
	}

	return 0;
}

splay_tree_t io_tree = {.compare = (splay_compare_t)io_compare};
splay_tree_t timeout_tree = {.compare = (splay_compare_t)timeout_compare};
static splay_tree_t deferred_timeout_tree = {.compare = (splay_compare_t)timeout_compare};
static timeout_t *current_executing_timeout = NULL;
static timeout_cb_t current_executing_cb = NULL;
static bool in_timeout_execute = false;
static struct timeval exec_mono_cutoff = {0, 0};

/* Monotonic clock used strictly for internal timeout_t deadlines so wall-clock
   NTP adjustments cannot freeze or prematurely fire event-loop timers, while
   keeping global `now` as UNIX epoch wall-clock for protocol authentication. */
static void event_monotonic_now(struct timeval *out) {
#ifdef HAVE_WINDOWS
	static LARGE_INTEGER freq = {0};
	LARGE_INTEGER cnt;

	if(freq.QuadPart == 0) {
		QueryPerformanceFrequency(&freq);
	}

	if(freq.QuadPart > 0 && QueryPerformanceCounter(&cnt)) {
		out->tv_sec = (long)(cnt.QuadPart / freq.QuadPart) + 1;
		out->tv_usec = (long)(((cnt.QuadPart % freq.QuadPart) * 1000000LL) / freq.QuadPart);
		return;
	}

	ULONGLONG ms = GetTickCount64();
	out->tv_sec = (long)(ms / 1000ULL) + 1;
	out->tv_usec = (long)((ms % 1000ULL) * 1000ULL);
#elif defined(CLOCK_MONOTONIC)
	struct timespec ts;

	if(clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
		out->tv_sec = ts.tv_sec + 1;
		out->tv_usec = (suseconds_t)(ts.tv_nsec / 1000L);
		return;
	}

	gettimeofday(out, NULL);
#else
	gettimeofday(out, NULL);
#endif
}

static void timeout_unlink_any(timeout_t *timeout) {
	if(deferred_timeout_tree.head && splay_search(&deferred_timeout_tree, timeout) == timeout) {
		splay_unlink_node(&deferred_timeout_tree, &timeout->node);
	} else {
		splay_unlink_node(&timeout_tree, &timeout->node);
	}
}

void timeout_add(timeout_t *timeout, timeout_cb_t cb, void *data, const struct timeval *tv) {
	if(timerisset(&timeout->tv)) {
		timeout_unlink_any(timeout);
		timeout->tv = (struct timeval) {
			0, 0
		};
	}

	timeout->cb = cb;
	timeout->data = data;
	timeout->node.data = timeout;

	timeout_set(timeout, tv);
}

void timeout_set(timeout_t *timeout, const struct timeval *tv) {
	if(timerisset(&timeout->tv)) {
		timeout_unlink_any(timeout);
		timeout->tv = (struct timeval) {
			0, 0
		};
	}

	if(!timeout->cb && timeout == current_executing_timeout && current_executing_cb) {
		timeout->cb = current_executing_cb;
		timeout->node.data = timeout;
	}

	if(!timeout->cb) {
		return;
	}

	if(!now.tv_sec) {
		gettimeofday(&now, NULL);
	}

	struct timeval mono_now;
	event_monotonic_now(&mono_now);

	struct timeval delta = tv ? *tv : (struct timeval) {
		0, 0
	};

	if(delta.tv_sec < 0 || (delta.tv_sec == 0 && delta.tv_usec < 0)) {
		delta = (struct timeval) {
			0, 0
		};
	}

	timeradd(&mono_now, &delta, &timeout->tv);

	splay_tree_t *target_tree = &timeout_tree;

	if(in_timeout_execute && !timercmp(&timeout->tv, &exec_mono_cutoff, >)) {
		target_tree = &deferred_timeout_tree;
	}

	if(!splay_insert_node(target_tree, &timeout->node)) {
		abort();
	}
}

void timeout_del(timeout_t *timeout) {
	if(current_executing_timeout == timeout) {
		current_executing_timeout = NULL;
		current_executing_cb = NULL;
	}

	if(!timeout->cb) {
		return;
	}

	if(timerisset(&timeout->tv)) {
		timeout_unlink_any(timeout);
	}

	timeout->cb = 0;
	timeout->tv = (struct timeval) {
		0, 0
	};
}

struct timeval *timeout_execute(struct timeval *diff) {
	gettimeofday(&now, NULL);

	struct timeval mono_now;
	event_monotonic_now(&mono_now);
	exec_mono_cutoff = mono_now;
	in_timeout_execute = true;

	struct timeval *tv = NULL;

	while(timeout_tree.head) {
		timeout_t *timeout = timeout_tree.head->data;
		timersub(&timeout->tv, &exec_mono_cutoff, diff);

		if(diff->tv_sec < 0 || (diff->tv_sec == 0 && diff->tv_usec <= 0)) {
			timeout_cb_t cb = timeout->cb;
			void *data = timeout->data;

			/* Unlink BEFORE invoking cb() so any timeout_set()/timeout_add()
			   inside cb() -- including {0, 0} or identical deadlines -- stays
			   armed and is never deleted after cb() returns. */
			splay_unlink_node(&timeout_tree, &timeout->node);
			timeout->cb = 0;
			timeout->tv = (struct timeval) {
				0, 0
			};

			current_executing_timeout = timeout;
			current_executing_cb = cb;

			if(cb) {
				cb(data);
			}

			if(current_executing_timeout == timeout) {
				current_executing_timeout = NULL;
				current_executing_cb = NULL;
			}
		} else {
			break;
		}
	}

	in_timeout_execute = false;

	while(deferred_timeout_tree.head) {
		timeout_t *t = deferred_timeout_tree.head->data;
		splay_unlink_node(&deferred_timeout_tree, &t->node);

		if(!splay_insert_node(&timeout_tree, &t->node)) {
			abort();
		}
	}

	if(timeout_tree.head) {
		timeout_t *next = timeout_tree.head->data;
		event_monotonic_now(&mono_now);
		timersub(&next->tv, &mono_now, diff);

		if(diff->tv_sec < 0 || (diff->tv_sec == 0 && diff->tv_usec < 0)) {
			*diff = (struct timeval) {
				0, 0
			};
		}

		tv = diff;
	}

	return tv;
}

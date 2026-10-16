/*
    event.c -- event support for Windows
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

#include <assert.h>

#include "../event.h"
#include "../logger.h"
#include "../utils.h"
#include "../net.h"

static bool running = false;
static DWORD event_count = 0;

static const long READ_EVENTS = FD_READ | FD_ACCEPT | FD_CLOSE;
static const long WRITE_EVENTS = FD_WRITE | FD_CONNECT;

void io_add(io_t *io, io_cb_t cb, void *data, int fd, int flags) {
	if(io->cb) {
		return;
	}

	io->fd = fd;

	if(io->fd != -1) {
		io->event = WSACreateEvent();

		if(io->event == WSA_INVALID_EVENT) {
			logger(DEBUG_ALWAYS, LOG_ERR, "WSACreateEvent failed: %s", winerror(WSAGetLastError()));
			return;
		}
	}

	event_count++;

	io->cb = cb;
	io->data = data;
	io->node.data = io;

	io_set(io, flags);

	if(!splay_insert_node(&io_tree, &io->node)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Duplicate io_t node in io_tree (fd=%d)", fd);
		if(io->fd != -1 && io->event != WSA_INVALID_EVENT) {
			WSACloseEvent(io->event);
		}
		event_count--;
		io->cb = NULL;
	}
}

void io_add_event(io_t *io, io_cb_t cb, void *data, WSAEVENT event) {
	io->event = event;
	io_add(io, cb, data, -1, 0);
}

void io_set(io_t *io, int flags) {
	if(flags == io->flags) {
		return;
	}

	io->flags = flags;

	if(io->fd == -1) {
		return;
	}

	long events = 0;

	if(flags & IO_WRITE) {
		events |= WRITE_EVENTS;
	}

	if(flags & IO_READ) {
		events |= READ_EVENTS;
	}

	if(WSAEventSelect(io->fd, io->event, events) != 0) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "WSAEventSelect failed on fd %d: %s", io->fd, winerror(WSAGetLastError()));
	}
}

void io_del(io_t *io) {
	if(!io->cb) {
		return;
	}

	io_set(io, 0);

	if(io->fd != -1 && WSACloseEvent(io->event) == FALSE) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "WSACloseEvent failed on fd %d: %s", io->fd, winerror(WSAGetLastError()));
	}

	if(event_count > 0) {
		event_count--;
	}

	splay_unlink_node(&io_tree, &io->node);
	io->cb = NULL;
}

bool event_loop(void) {
	running = true;

	assert(WSA_WAIT_EVENT_0 == 0);

	while(running) {
		struct timeval diff;
		struct timeval *tv = timeout_execute(&diff);

		if(!running) {
			break;
		}

		DWORD timeout_ms = tv ? (DWORD)(tv->tv_sec * 1000 + tv->tv_usec / 1000 + 1) : WSA_INFINITE;

		if(!event_count) {
			Sleep(timeout_ms);
			continue;
		}

		/*
		   For some reason, Microsoft decided to make the FD_WRITE event edge-triggered instead of level-triggered,
		   which is the opposite of what select() does. In practice, that means that if a FD_WRITE event triggers,
		   it will never trigger again until a send() returns EWOULDBLOCK. Since the semantics of this event loop
		   is that write events are level-triggered (i.e. they continue firing until the socket is full), we need
		   to emulate these semantics by making sure we fire each IO_WRITE that is still writeable.

		   Note that technically FD_CLOSE has the same problem, but it's okay because user code does not rely on
		   this event being fired again if ignored.
		*/
		unsigned int curgen = io_tree.generation;
		bool ran_write = false;

		for splay_each(io_t, io, &io_tree) {
			if((io->flags & IO_WRITE) && io->fd != -1 && send(io->fd, NULL, 0, 0) == 0) {
				ran_write = true;
				io->cb(io->data, IO_WRITE);

				if(!running || curgen != io_tree.generation) {
					break;
				}
			}
		}

		if(!running) {
			break;
		}

		if(ran_write) {
			tv = timeout_execute(&diff);

			if(!running) {
				break;
			}

			timeout_ms = tv ? (DWORD)(tv->tv_sec * 1000 + tv->tv_usec / 1000 + 1) : WSA_INFINITE;
		}

		WSAEVENT events[WSA_MAXIMUM_WAIT_EVENTS];
		io_t *io_map[WSA_MAXIMUM_WAIT_EVENTS];
		DWORD event_index = 0;

		for splay_each(io_t, io, &io_tree) {
			if(event_index >= WSA_MAXIMUM_WAIT_EVENTS) {
				break;
			}

			events[event_index] = io->event;
			io_map[event_index] = io;
			event_index++;
		}

		if(event_count > WSA_MAXIMUM_WAIT_EVENTS && timeout_ms > 50) {
			timeout_ms = 50;
		}

		/*
		 * If the generation number changes due to event addition
		 * or removal by a callback we restart the loop.
		 */
		curgen = io_tree.generation;

		for(DWORD event_offset = 0; event_offset < event_index && running;) {
			DWORD result = WSAWaitForMultipleEvents(event_index - event_offset, &events[event_offset], FALSE, timeout_ms, FALSE);

			if(result == WSA_WAIT_TIMEOUT) {
				break;
			}

			if(result == WSA_WAIT_FAILED || result >= event_index - event_offset) {
				logger(DEBUG_ALWAYS, LOG_WARNING, "WSAWaitForMultipleEvents failed: %s", winerror(WSAGetLastError()));
				break;
			}

			/* Look up io in the map by index. */
			DWORD fired_index = result + event_offset;
			io_t *io = io_map[fired_index];

			if(io->fd == -1) {
				io->cb(io->data, 0);

				if(!running || curgen != io_tree.generation) {
					break;
				}
			} else {
				WSANETWORKEVENTS network_events;

				if(WSAEnumNetworkEvents(io->fd, io->event, &network_events) != 0) {
					logger(DEBUG_ALWAYS, LOG_WARNING, "WSAEnumNetworkEvents failed on fd %d: %s", io->fd, winerror(WSAGetLastError()));
					event_offset = fired_index + 1;
					timeout_ms = 0;
					continue;
				}

				if((network_events.lNetworkEvents & READ_EVENTS) && (io->flags & IO_READ)) {
					io->cb(io->data, IO_READ);

					if(!running || curgen != io_tree.generation) {
						break;
					}
				}

				if((network_events.lNetworkEvents & WRITE_EVENTS) && (io->flags & IO_WRITE)) {
					io->cb(io->data, IO_WRITE);

					if(!running || curgen != io_tree.generation) {
						break;
					}
				}
			}

			/* Continue checking the rest of the events. */
			event_offset = fired_index + 1;

			/* Just poll the next time through. */
			timeout_ms = 0;
		}
	}

	return true;
}

void event_exit(void) {
	running = false;
}

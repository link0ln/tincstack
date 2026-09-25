/*
    quic_txq.c -- the send queue of one QUIC stream, whose bytes never move
                  (quic_txq.h).

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
*/

#include "system.h"

#include "quic_txq.h"
#include "xalloc.h"

struct quic_txq_chunk_t {
	quic_txq_chunk_t *next;
	size_t len;             /* bytes written; only ever grows */
	size_t cap;
	uint8_t data[];
};

void quic_txq_append(quic_txq_t *q, const void *data, size_t len) {
	const uint8_t *p = data;

	while(len) {
		quic_txq_chunk_t *t = q->tail;

		if(!t || t->len == t->cap) {
			size_t cap = len > QUIC_TXQ_CHUNK ? len : QUIC_TXQ_CHUNK;
			quic_txq_chunk_t *n = xmalloc(sizeof(*n) + cap);
			n->next = NULL;
			n->len = 0;
			n->cap = cap;

			if(t) {
				t->next = n;
			} else {
				q->head = n;
				q->base = q->end;
			}

			q->tail = t = n;
		}

		/* Only the free tail of the last chunk is written: bytes before it
		   may be in ngtcp2's hands. */
		size_t take = t->cap - t->len < len ? t->cap - t->len : len;
		memcpy(t->data + t->len, p, take);
		t->len += take;
		q->end += take;
		p += take;
		len -= take;
	}
}

size_t quic_txq_pending(quic_txq_t *q, quic_txq_vec_t *vec, size_t nvec, size_t max) {
	if(q->sent >= q->end || !nvec || !max) {
		return 0;
	}

	quic_txq_chunk_t *c = q->cur;
	uint64_t cbase = q->cur_base;

	if(!c || cbase > q->sent) {
		c = q->head;
		cbase = q->base;
	}

	while(c && cbase + c->len <= q->sent) {
		cbase += c->len;
		c = c->next;
	}

	q->cur = c;
	q->cur_base = cbase;

	size_t n = 0;
	size_t off = (size_t)(q->sent - cbase);

	for(; c && n < nvec && max; c = c->next, off = 0) {
		size_t l = c->len - off;

		if(!l) {
			continue;
		}

		if(l > max) {
			l = max;
		}

		vec[n].base = c->data + off;
		vec[n].len = l;
		max -= l;
		n++;
	}

	return n;
}

void quic_txq_sent(quic_txq_t *q, size_t n) {
	q->sent += n;

	if(q->sent > q->end) {
		q->sent = q->end;
	}
}

void quic_txq_ack(quic_txq_t *q, uint64_t offset) {
	if(offset > q->end) {
		offset = q->end;
	}

	if(offset <= q->acked) {
		return;
	}

	q->acked = offset;

	/* A last chunk that is wholly acknowledged goes too: nothing of it can
	   be in flight, and the next append starts a new one. */
	while(q->head && q->base + q->head->len <= q->acked) {
		quic_txq_chunk_t *c = q->head;
		q->base += c->len;
		q->head = c->next;

		if(q->cur == c) {
			q->cur = NULL;
		}

		if(q->tail == c) {
			q->tail = NULL;
		}

		free(c);
	}

	if(q->sent < q->acked) {
		q->sent = q->acked;     /* not expected: ngtcp2 acknowledges only what it took */
	}
}

void quic_txq_free(quic_txq_t *q) {
	while(q->head) {
		quic_txq_chunk_t *c = q->head;
		q->head = c->next;
		free(c);
	}

	memset(q, 0, sizeof(*q));
}

size_t quic_txq_chunks(const quic_txq_t *q) {
	size_t n = 0;

	for(quic_txq_chunk_t *c = q->head; c; c = c->next) {
		n++;
	}

	return n;
}

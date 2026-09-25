#ifndef TINC_QUIC_TXQ_H
#define TINC_QUIC_TXQ_H

/*
    quic_txq.h -- the send queue of one QUIC stream, whose bytes never move.

    ngtcp2 does not copy stream data: ngtcp2_conn_writev_stream() keeps
    pointers to what it was given and retransmits from them until
    acked_stream_data_offset says the peer has it. A buffer that is
    realloc()ed or memmove()d while bytes in it are in flight makes a lost
    packet's retransmission read freed or shifted memory -- and send it.

    A quic_txq_t is a list of fixed chunks. Appending fills the last chunk's
    free tail or adds a chunk; a byte, once written, stays at its address
    until the acknowledged prefix covers its whole chunk, which is then
    freed. Nothing else ever moves or frees it (except quic_txq_free()).

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

#define QUIC_TXQ_CHUNK 4096     /* the smallest chunk; a larger append gets its own size */

typedef struct quic_txq_chunk_t quic_txq_chunk_t;

typedef struct quic_txq_t {
	quic_txq_chunk_t *head, *tail;
	uint64_t base;          /* stream offset of head's first byte */
	uint64_t end;           /* stream offset just past the last byte appended */
	uint64_t sent;          /* stream offset handed to ngtcp2 so far */
	uint64_t acked;         /* acknowledged prefix */
	quic_txq_chunk_t *cur;  /* the chunk holding `sent' (a cache; NULL: search) */
	uint64_t cur_base;
} quic_txq_t;

/* One piece of pending data; the layout of ngtcp2_vec. */
typedef struct quic_txq_vec_t {
	uint8_t *base;
	size_t len;
} quic_txq_vec_t;

void quic_txq_append(quic_txq_t *q, const void *data, size_t len);

/* Bytes appended and not yet handed out. */
static inline uint64_t quic_txq_unsent(const quic_txq_t *q) {
	return q->end - q->sent;
}

/* Up to `nvec' pieces of what follows `sent', at most `max' bytes in all.
   Returns the number of pieces. The pointers stay valid until the bytes
   are acknowledged. */
size_t quic_txq_pending(quic_txq_t *q, quic_txq_vec_t *vec, size_t nvec, size_t max);

/* ngtcp2 took `n' more bytes. */
void quic_txq_sent(quic_txq_t *q, size_t n);

/* The peer has everything below `offset' (acked_stream_data_offset's
   offset + datalen): free the chunks it covers entirely. */
void quic_txq_ack(quic_txq_t *q, uint64_t offset);

void quic_txq_free(quic_txq_t *q);

/* Chunks currently held (for tests). */
size_t quic_txq_chunks(const quic_txq_t *q);

#endif /* TINC_QUIC_TXQ_H */

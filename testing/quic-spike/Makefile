# Built inside the ws-q image (core/Dockerfile.build-quic, target build),
# where pkg-config resolves ngtcp2 and its GnuTLS backend.
PKGS = libngtcp2 libngtcp2_crypto_gnutls gnutls
CFLAGS ?= -O2 -g -Wall -Wextra -std=gnu11
CFLAGS += $(shell pkg-config --cflags $(PKGS))
LDLIBS += $(shell pkg-config --libs $(PKGS))

all: spike-server spike-client

spike-server: server.o common.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

spike-client: client.o common.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

server.o client.o common.o: common.h

clean:
	rm -f *.o spike-server spike-client

.PHONY: all clean

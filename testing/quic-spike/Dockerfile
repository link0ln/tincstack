# Stream-Q spike image: the ws-q build stage (ngtcp2 + GnuTLS present) plus
# tcpdump and openssl, with the spike compiled in. Built by run.sh.
ARG BASE=tincstack/core:ws-q-build
FROM ${BASE}
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump openssl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /spike
COPY Makefile common.h common.c server.c client.c test.sh pcap_first.py /spike/
RUN make && chmod +x test.sh

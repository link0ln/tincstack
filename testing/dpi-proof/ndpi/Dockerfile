# Upstream nDPI's ndpiReader, the arbiter for the TLS-in-TLS oracle
# (testing/dpi-proof/tls-in-tls-audit.sh). Built from source at a pinned
# release commit (tag 6.0); nothing is installed on the host. nDPI is
# LGPL-3.0 and is only run here, never linked into tincstack.
#
# /samples holds nDPI's own TLS-heuristic test captures (proxies it flags),
# the arbiter's positive control on every run. ethtool is here so the lab can
# turn segmentation offloads off in a container's network namespace.
FROM debian:trixie-slim AS build
ARG NDPI_REF=1a5293396337f9a72dfee1fa070b2c4b0a0a3aaf
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates git build-essential autoconf automake libtool pkg-config \
      libpcap-dev libjson-c-dev \
 && rm -rf /var/lib/apt/lists/*
RUN git init /src && cd /src \
 && git remote add origin https://github.com/ntop/nDPI \
 && git fetch -q --depth 1 origin "$NDPI_REF" && git checkout -q FETCH_HEAD \
 && ./autogen.sh >/dev/null && ./configure --prefix=/opt/ndpi >/dev/null \
 && make -j"$(nproc)" >/dev/null && cp example/ndpiReader /usr/local/bin/ \
 && git rev-parse HEAD > /ndpi-ref \
 && mkdir /samples && cp tests/cfgs/default/pcap/tls_heur__*.pcapng /samples/

FROM debian:trixie-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libpcap0.8t64 libjson-c5 ethtool \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/ndpiReader /usr/local/bin/ndpiReader
COPY --from=build /ndpi-ref /ndpi-ref
COPY --from=build /samples /samples
ENTRYPOINT ["ndpiReader"]

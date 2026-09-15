# Upstream tinc 1.1pre18 (unpatched) built from the release tarball with
# autotools. Used as the comparison baseline for the NAT lab: same runtime
# packages as core/Dockerfile.build so the two images differ only in tincd.
#
# Build context must contain tinc-1.1pre18.tar.gz (testing/baseline/build.sh
# copies it in from TINC_TARBALL, default
# /opt/gitrepo/vpn-experiments/tinc-1.1pre18.tar.gz).
FROM debian:12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config \
        libssl-dev zlib1g-dev liblzo2-dev liblz4-dev \
        libncurses-dev libreadline-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ADD tinc-1.1pre18.tar.gz /src/
RUN cd tinc-1.1pre18 \
    && ./configure --prefix=/usr/local --localstatedir=/var \
         --disable-miniupnpc --disable-systemd \
    && make -j"$(nproc)" \
    && make DESTDIR=/install install

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 zlib1g liblzo2-2 liblz4-1 libncursesw6 libreadline8 \
        iproute2 iputils-ping iptables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /install/usr/local/ /usr/local/
RUN ldconfig

# Reference clients and the dissector for the wire-fingerprint audit
# (testing/fingerprint/run.sh). Debian trixie: Wireshark 4.4 (JA3/JA4 fields),
# curl built with ngtcp2 (--http3), Chromium.
FROM debian:trixie-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      tshark tcpdump curl chromium ca-certificates openssl procps \
 && rm -rf /var/lib/apt/lists/*

# Lab image for testing/nat-sim and testing/dpi-proof.
# = the core image (tincd under test at /usr/local/sbin) + the upstream baseline
#   binaries at /opt/baseline/sbin + netns/netfilter/capture tooling.
# The whole lab runs inside ONE privileged container using network namespaces
# and veth pairs, so it never depends on the host's Docker networking or
# firewall (Docker 28+/Cilium hosts drop bridged cross-network traffic).
ARG CORE_IMAGE=tincstack/core:ws-f
ARG BASELINE_IMAGE=tincstack/baseline:ws-f
# hadolint ignore=DL3006
FROM ${BASELINE_IMAGE} AS baseline
# hadolint ignore=DL3006
FROM ${CORE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables conntrack tcpdump python3 iproute2 procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=baseline /usr/local/sbin/tincd /opt/baseline/sbin/tincd
COPY --from=baseline /usr/local/sbin/tinc /opt/baseline/sbin/tinc
COPY nat-sim/natprofile.sh /usr/local/bin/natprofile
COPY nat-sim/udpprobe.py /usr/local/bin/udpprobe
COPY nat-sim/natlab.sh /usr/local/bin/natlab
COPY dpi-proof/capture.sh /usr/local/bin/dpi-capture
COPY dpi-proof/fingerprint.py /usr/local/bin/dpi-fingerprint
COPY dpi-proof/compare.py /usr/local/bin/dpi-compare
RUN chmod +x /usr/local/bin/natprofile /usr/local/bin/udpprobe /usr/local/bin/natlab \
        /usr/local/bin/dpi-capture /usr/local/bin/dpi-fingerprint /usr/local/bin/dpi-compare
CMD ["natlab"]

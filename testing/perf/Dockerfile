# Bench image: the NAT-lab image (tincd under test at /usr/local/sbin plus the
# upstream baseline at /opt/baseline/sbin) with iperf3 added. Both daemons live
# in one image on purpose -- the comparison must differ in the binary and in
# nothing else: same kernel, same container, same OpenSSL, same config files.
ARG LAB_IMAGE=tincstack/natlab:sf5glare
ARG BASELINE_O3_IMAGE=tincstack/baseline:o3
# hadolint ignore=DL3006
FROM ${BASELINE_O3_IMAGE} AS baseline_o3
# hadolint ignore=DL3006
FROM ${LAB_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
        iperf3 \
    && rm -rf /var/lib/apt/lists/*
# Upstream again, this time compiled the way our own core is (-O3), so that the
# comparison can separate "different code" from "different compiler flags":
# the lab baseline is autotools' default -g -O2, ours is meson release -O3.
COPY --from=baseline_o3 /usr/local/sbin/tincd /opt/baseline-o3/sbin/tincd

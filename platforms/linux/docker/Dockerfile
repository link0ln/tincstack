# tincstack Linux node image: the core image plus the zero-config entrypoint.
#
# docker compose builds core/ first and hands it over as the named build context
# `core` (see docker-compose.yml). By hand:
#   docker build -f core/Dockerfile.build -t tincstack/core:dev core/
#   docker build --build-arg CORE_IMAGE=tincstack/core:dev -t tincstack/node:dev platforms/linux/docker
ARG CORE_IMAGE=core
FROM ${CORE_IMAGE}

# python3 serves only tincstack-yaml, the temporary env->YAML bridge that
# `tinc set` replaces once it is YAML-aware (PLAN.md M2). Drop it with the helper.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-minimal \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 entrypoint.sh   /usr/local/bin/tincstack-entrypoint
COPY --chmod=0755 tincstack-yaml  /usr/local/bin/tincstack-yaml
COPY --chmod=0755 tincstack-cli   /usr/local/bin/tincstack-cli
COPY --chmod=0755 tinc-up         /usr/local/lib/tincstack/tinc-up

# Identity and runtime state live here: the daemon-owned tinc.yaml (keys inside)
# and <netname>/ (cache, invitations, control socket fallback). Always a volume.
VOLUME /etc/tincstack

ENTRYPOINT ["/usr/local/bin/tincstack-entrypoint"]

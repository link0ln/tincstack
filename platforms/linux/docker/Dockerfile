# tincstack Linux node image: the core image plus the zero-config entrypoint.
#
# docker compose builds core/ first and hands it over as the named build context
# `core` (see docker-compose.yml). By hand:
#   docker build -f core/Dockerfile.build -t tincstack/core:dev core/
#   docker build --build-arg CORE_IMAGE=tincstack/core:dev -t tincstack/node:dev platforms/linux/docker
ARG CORE_IMAGE=core
FROM ${CORE_IMAGE}

# Nothing beyond the core: the entrypoint maps env -> YAML with the core's own
# YAML-aware `tinc set`, and the daemon addresses the tun interface itself.
COPY --chmod=0755 entrypoint.sh   /usr/local/bin/tincstack-entrypoint
COPY --chmod=0755 tincstack-cli   /usr/local/bin/tincstack-cli

# Identity and runtime state live here: the daemon-owned tinc.yaml (keys inside)
# and <netname>/ (cache, invitations, control socket fallback). Always a volume.
VOLUME /etc/tincstack

ENTRYPOINT ["/usr/local/bin/tincstack-entrypoint"]

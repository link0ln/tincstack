# The reference web server for the QUIC listener: Debian 13's own nginx
# package (1.26.3, OpenSSL 3.5 -- the TLS stack our core links, so both pick
# X25519MLKEM768 for curl), default site removed; tests mount their config.
FROM debian:trixie-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nginx \
 && rm -rf /var/lib/apt/lists/* /etc/nginx/sites-enabled/default
CMD ["nginx", "-g", "daemon off;"]

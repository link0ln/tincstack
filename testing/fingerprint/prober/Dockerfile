# Probers for the 2026-09-26 wire audit (testing/fingerprint/post405-timing.sh
# and friends): an HTTP/3 client that can pause between a request's HEADERS
# and its DATA (aioquic), and tc for netem on the prober's own interface.
# Nothing here is a reference client; curl and Chromium stay in fp-tools.
FROM python:3.12-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir aioquic==1.2.0

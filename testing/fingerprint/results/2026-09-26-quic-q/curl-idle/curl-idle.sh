#!/usr/bin/env bash
# curl-idle.sh <outdir> [idle s]: what an HTTP/3 connection does while curl
# waits on an answer that does not come: curl --http3-only against Debian 13's
# nginx proxying to an upstream that accepts and never answers. Capture on
# the nginx side, UDP 443 only.
set -uo pipefail
OUT=$1 IDLE=${2:-150}
PFX=wsqcurl NET=wsqcurlnet SUBNET=10.47.32
TOOLS=tincstack/fp-tools:dev NGINX=tincstack/nginx-deb13:dev PROBER=tincstack/fp-prober:ww-f
mkdir -p "$OUT/n"
cleanup() { docker rm -f $PFX-n $PFX-u $PFX-cap $PFX-c >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; trap cleanup EXIT
docker network create --internal --subnet "$SUBNET.0/24" $NET >/dev/null
docker run --rm -v "$OUT/n:/n" $TOOLS sh -c 'openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=x -keyout /n/key.pem -out /n/cert.pem 2>/dev/null; chmod 644 /n/*.pem'
printf '%s\n' 'server {' '    listen 443 quic reuseport;' '    listen 443 ssl;' \
	'    ssl_certificate /n/cert.pem;' '    ssl_certificate_key /n/key.pem;' \
	"    location / { proxy_pass http://$SUBNET.13:8080; proxy_read_timeout 600s; }" '}' > "$OUT/n/default.conf"
docker run -d --name $PFX-u --network $NET --ip $SUBNET.13 $PROBER \
	python3 -c 'import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0",8080)); s.listen(8)
c=[]
while True: c.append(s.accept()[0])' >/dev/null
docker run -d --name $PFX-n --network $NET --ip $SUBNET.12 -v "$OUT/n:/n:ro" \
	-v "$OUT/n/default.conf:/etc/nginx/conf.d/default.conf:ro" $NGINX >/dev/null
docker run -d --name $PFX-cap --network container:$PFX-n -v "$OUT:/o" $TOOLS \
	tcpdump -i eth0 -U -w /o/n.pcap udp port 443 >/dev/null
sleep 3
date +%s.%N > "$OUT/start.txt"
docker run --rm --name $PFX-c --network $NET --ip $SUBNET.20 $TOOLS \
	curl -sk --http3-only -m "$IDLE" -o /dev/null -w 'curl %{http_code} %{time_total}\n' "https://$SUBNET.12/stall" > "$OUT/curl.txt" 2>&1
date +%s.%N > "$OUT/end.txt"
sleep 2
docker stop -t 2 $PFX-cap >/dev/null
docker run --rm -v "$OUT:/o" $TOOLS sh -c "tcpdump -n -tt -r /o/n.pcap 2>/dev/null" > "$OUT/n.txt"
st=$(cat "$OUT/start.txt")
awk -v st="$st" '{d=($3 ~ /^10\.47\.32\.20\./) ? "c>n" : "n>c"; printf "%8.3f %s %s\n", $1-st, d, $NF}' "$OUT/n.txt" > "$OUT/timeline.txt"
wc -l < "$OUT/n.txt"
cat "$OUT/curl.txt"

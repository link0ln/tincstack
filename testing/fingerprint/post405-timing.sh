#!/usr/bin/env bash
# POST-405 timing: does our listener answer a non-tinc POST later than nginx?
#
# A tinc dialler's request is a POST whose body is the authenticator, so the
# quic listener (and, in principle, the TLS front) cannot answer a POST until
# it has seen enough of the body to tell a peer from anyone else. nginx
# answers a POST to a static file with 405 as soon as the head is whole
# (PLAN.md, "A POST's 405 comes after its body"). The owner asked for the
# size of that difference on a real path before deciding anything.
#
# One founder (our listener, TCP and UDP 443), Debian 13's nginx 1.26.3 with
# the founder's own certificate and key, and a prober container with tc netem
# on its own egress (the whole RTT as one-way delay, so the servers' side is
# untouched). post_probe.py opens a fresh connection per probe and times the
# answer from the head and from the body:
#   get, post-now, post-pause (1 s between head and body), post-nobody
#   (head only), post-authver (a body that starts like an authenticator)
# over h3 (aioquic) and h1 (HTTP/1.1 over TLS, stdlib ssl), for RTT 20, 80,
# 200 ms x jitter 0, 10 ms. post405_summary.py turns that into per-probe and
# statistical distinguishability. netem runs with `rate 10gbit` so jitter
# does not reorder packets (without a rate every packet draws its own delay
# and a 10 ms jitter reorders the prober's flights, which QUIC loss recovery
# answers with PTOs -- the first run, results/2026-09-26-audit/post405,
# measured that artefact: nginx's median at 200+-10 ms was 600 ms).
#
# It reports; it does not pass or fail.
#
# Usage: flock /tmp/tincstack-lab.lock testing/fingerprint/post405-timing.sh [outdir]
#   env: CORE_IMAGE, NGINX_IMAGE, N (probes per cell, default 12), RTTS, JITTERS
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
NGINX="${NGINX_IMAGE:-tincstack/nginx-deb13:dev}"
PROBER="${PROBER_IMAGE:-tincstack/fp-prober:ww-f}"
PFX=wwfp
NET=${PFX}net
SUBNET=10.49.65
F_IP=$SUBNET.10
N_IP=$SUBNET.11
P_IP=$SUBNET.20
Y=/c/tinc.yaml
N=${N:-12}
RTTS=${RTTS:-20 80 200}
JITTERS=${JITTERS:-0 10}
OUT=${1:-$HERE/results/$(date +%Y%m%d-%H%M%S)-post405}
RUN="$HERE/run-post405"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
cleanup() {
	docker rm -f "$PFX-f" "$PFX-n" "$PFX-p" "$PFX-cap" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$RUN"
}
cleanup
[[ -n ${KEEP:-} ]] || trap cleanup EXIT
mkdir -p "$RUN/n" "$OUT"
if ! docker image inspect "$PROBER" >/dev/null 2>&1; then
	proxy=${http_proxy:-${HTTP_PROXY:-}}
	docker build -q ${proxy:+--build-arg http_proxy="$proxy" --build-arg https_proxy="$proxy"} \
		-t "$PROBER" "$HERE/prober" >/dev/null || { log "cannot build $PROBER"; exit 2; }
fi

docker network create --internal --subnet "$SUBNET.0/24" "$NET" >/dev/null || exit 2
docker run -d --name "$PFX-f" --network "$NET" --ip "$F_IP" --cap-add NET_ADMIN --device /dev/net/tun \
	"$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
t() { docker exec "$PFX-f" tinc -n lab -c "$Y" "$@"; }
docker exec "$PFX-f" sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
docker exec -d "$PFX-f" sh -c "tincd -n lab -c $Y -D -d3 >>/tmp/tincd.log 2>&1"
for _ in $(seq 20); do t pid >/dev/null 2>&1 && break; sleep 1; done
t set founder.Address "$F_IP"
for _ in $(seq 20); do docker exec "$PFX-f" grep -q '^      tls_key: |' "$Y" && break; sleep 1; done
pem() { # <yaml key> <PEM label>: that block of the founder's keys section
	docker exec "$PFX-f" sh -c "awk '/^      $1: \\|/{f=1;next} f&&/^      [a-z_]+:/{f=0} f' $Y | sed 's/^        //' | sed -n '/BEGIN $2/,/END $2/p'"
}
pem tls_cert CERTIFICATE > "$RUN/n/cert.pem"
pem tls_key "PRIVATE KEY" > "$RUN/n/key.pem"
chmod 644 "$RUN/n/"*.pem
cat > "$RUN/n/default.conf" <<-'EOF'
	server {
	    listen 443 quic reuseport;
	    listen 443 ssl;
	    ssl_certificate     /n/cert.pem;
	    ssl_certificate_key /n/key.pem;
	    location / { root /usr/share/nginx/html; }
	}
EOF
docker run -d --name "$PFX-n" --network "$NET" --ip "$N_IP" -v "$RUN/n:/n:ro" \
	-v "$RUN/n/default.conf:/etc/nginx/conf.d/default.conf:ro" "$NGINX" >/dev/null
docker run -d --name "$PFX-p" --network "$NET" --ip "$P_IP" --cap-add NET_ADMIN -v "$HERE:/h:ro" \
	"$PROBER" sleep infinity >/dev/null
sleep 3

probe() { docker exec "$PFX-p" python3 /h/post_probe.py "$@"; }
{
	printf 'image\t%s\t%s\n' "$IMG" "$(docker image inspect "$IMG" --format '{{.Id}}')"
	printf 'nginx\t%s\t%s\n' "$NGINX" "$(docker exec "$PFX-n" nginx -v 2>&1)"
	printf 'prober\t%s\n' "$(probe h3 "$F_IP" get 1 2>&1 | head -1)"
} > "$OUT/setup.txt"

RAW="$OUT/raw.tsv"
printf 'rtt\tjitter\tserver\tproto\tmode\tstatus\tt_head\tt_body\n' > "$RAW"
for rtt in $RTTS; do
	for jit in $JITTERS; do
		if [[ $jit == 0 ]]; then
			docker exec "$PFX-p" tc qdisc replace dev eth0 root netem delay "${rtt}ms" rate 10gbit
		else
			docker exec "$PFX-p" tc qdisc replace dev eth0 root netem delay "${rtt}ms" "${jit}ms" rate 10gbit
		fi
		log "netem: RTT $rtt ms, jitter $jit ms"
		for srv in f:$F_IP n:$N_IP; do
			name=${srv%%:*}; ip=${srv#*:}
			[[ $name == f ]] && name=listener || name=nginx
			for proto in h3 h1; do
				for mode in get post-now post-pause post-authver; do
					probe "$proto" "$ip" "$mode" "$N" 1000 5000
				done
				probe "$proto" "$ip" post-nobody $(( N / 2 )) 1000 3000
			done | awk -v r="$rtt" -v j="$jit" -v s="$name" '{ print r "\t" j "\t" s "\t" $0 }' >> "$RAW"
		done
	done
done
docker exec "$PFX-p" tc qdisc del dev eth0 root 2>/dev/null || true

# What happens to a head-only POST in the end (no netem): nginx answers at
# once; ours waits for a body -- until when?
log "a head-only POST, waited out for 70 s"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
docker run -d --name "$PFX-cap" --network "container:$PFX-p" -v "$RUN:/r" "$TOOLS" \
	tcpdump -i eth0 -U -w /r/nobody.pcap port 443 >/dev/null
sleep 2
for srv in f:$F_IP n:$N_IP; do
	name=${srv%%:*}; ip=${srv#*:}
	[[ $name == f ]] && name=listener || name=nginx
	for proto in h3 h1; do
		printf '%s\t%s\n' "$name" "$(probe "$proto" "$ip" post-nobody 1 1000 70000)"
	done
done > "$OUT/nobody-70s.txt"
docker stop -t 2 "$PFX-cap" >/dev/null
# what each server sent the head-only prober, and when (s after its first packet on that 5-tuple)
docker run --rm -v "$RUN:/r" "$TOOLS" tshark -r /r/nobody.pcap -Y "ip.src == $F_IP || ip.src == $N_IP" -T fields \
	-e frame.time_epoch -e ip.src -e _ws.col.Protocol -e frame.len -e tcp.flags.fin -e tcp.flags.reset 2>/dev/null |
	awk -F'\t' -v f="$F_IP" '{ k = $2 "/" $3; if(!(k in t0)) t0[k] = $1
		printf "%s %s +%.1fs %sB%s%s\n", ($2 == f ? "listener" : "nginx"), $3, $1 - t0[k], $4, ($5 == 1 ? " FIN" : ""), ($6 == 1 ? " RST" : "") }' \
	> "$OUT/nobody-70s-server-packets.txt"
docker exec "$PFX-f" grep -c 'quic: serving the decoy' /tmp/tincd.log > "$OUT/listener-decoy-count.txt" 2>&1 || true

docker run --rm -v "$HERE:/h:ro" -v "$OUT:/o" "$PROBER" python3 /h/post405_summary.py /o/raw.tsv > "$OUT/summary.txt"
cat "$OUT/summary.txt" "$OUT/nobody-70s.txt"
log "results in $OUT"

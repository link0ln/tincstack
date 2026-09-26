#!/usr/bin/env bash
# idle-dbg.sh <image> <outdir> [idle s]: a quic link left idle, tincd -d5 on
# both ends and a capture of the founder's UDP; what the idle link sends and why.
set -uo pipefail
IMG=$1 OUT=$2 IDLE=${3:-90}
PFX=wsqidle NET=wsqidlenet SUBNET=10.47.31 Y=/c/tinc.yaml
mkdir -p "$OUT"
t() { local n=$1; shift; docker exec "$PFX-$n" tinc -n lab -c "$Y" "$@"; }
cleanup() { docker rm -f $PFX-f $PFX-l $PFX-cap >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
cleanup; trap cleanup EXIT
docker network create --internal --subnet "$SUBNET.0/24" $NET >/dev/null
for n in f:10 l:11; do
	docker run -d --name "$PFX-${n%%:*}" --network $NET --ip "$SUBNET.${n#*:}" --cap-add NET_ADMIN --device /dev/net/tun \
		"$IMG" sh -c 'mkdir -p /c; exec sleep infinity' >/dev/null
done
docker exec $PFX-f sh -c "install -m600 /dev/null $Y && tinc -n lab -c $Y set Name founder && tinc -n lab -c $Y set Port 655"
docker exec -d $PFX-f sh -c "tincd -n lab -c $Y -D -d5 >>/tmp/tincd.log 2>&1"
for _ in $(seq 20); do t f pid >/dev/null 2>&1 && break; sleep 1; done
t f set founder.Address "$SUBNET.10"
t l join "$(t f invite leaf)" >/dev/null 2>&1
t l set PreferredTransports quic
docker run -d --name $PFX-cap --network container:$PFX-f --cap-add NET_ADMIN --cap-add NET_RAW -v "$OUT:/o" \
	nicolaka/netshoot tcpdump -U -n -i eth0 -w /o/f.pcap udp >/dev/null
docker exec -d $PFX-l sh -c "tincd -n lab -c $Y -D -d5 >>/tmp/tincd.log 2>&1"
for _ in $(seq 30); do t l dump connections 2>/dev/null | grep -q "^founder .*transport quic" && break; sleep 1; done
fip=$(docker exec $PFX-f ip -4 -br addr show lab | awk '{print $3}' | cut -d/ -f1)
docker exec $PFX-l ping -c3 -W2 "$fip" | tail -1
sleep 5
start=$(date +%s.%N)
echo "idle start $start" > "$OUT/idle.txt"
sleep "$IDLE"
echo "idle end $(date +%s.%N)" >> "$OUT/idle.txt"
t l info founder > "$OUT/info-leaf.txt" 2>&1
docker stop -t 3 $PFX-cap >/dev/null
for n in f l; do docker exec $PFX-$n cat /tmp/tincd.log > "$OUT/tincd-$n.log"; done
docker run --rm -v "$OUT:/o" nicolaka/netshoot sh -c "tcpdump -n -tt -r /o/f.pcap 2>/dev/null" > "$OUT/f.txt"
awk -v s="$start" '$1 >= s' "$OUT/f.txt" | wc -l

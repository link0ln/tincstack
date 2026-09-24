#!/usr/bin/env bash
# The Android core speaks the TLS carriers, with the Linux build's wire image.
#
# Until 2026-09-24 the Android core linked LibreSSL's libcrypto alone: no
# `https', no `quic', and the default build did not even compile (the APK was
# built --crypto nolegacy). Now platforms/android/native/build-core.sh links
# OpenSSL 3.5, zstd and ngtcp2 statically, as the Windows and Linux builds do.
# This lab runs the real NDK binaries (libtincd.so / libtinc.so, x86_64) on
# the headless Android emulator in Docker (platforms/android/docker) against
# Linux nodes -- nothing on the host but /dev/kvm:
#
#   the Android node dials a Linux founder:
#     * it connects over `https' and over `quic';
#     * its ClientHellos are the Linux dialler's, dialling the same founder
#       the same way: extension for extension (JA4_r), handshake length, and
#       for QUIC the transport parameters in order -- and their JA4_r is curl's.
#
# Compared by TLS handshake length, not frame length: the emulator's
# user-mode NAT (slirp) terminates the guest's TCP and re-sends it in its
# own segments (1460 + 91 bytes here), which is the emulator's doing, not the
# phone's. The QUIC transport parameters are ngtcp2's, not curl's (curl 8.14
# on Debian 13 runs OpenSSL's own QUIC stack): printed, not required --
# PLAN.md Known Issues.
#
# Not covered here: the VpnService data path (this runs the daemon as root
# with `DeviceType = dummy'; platforms/android/docker/join-on-emulator.sh
# with TRANSPORT=https|quic drives the app for that), and a phone as a
# server (a joined node listens on no front).
#
# Usage: [CORE_IMAGE=...] [ANDROID_CORE=<dir with libtincd.so libtinc.so>] testing/transports/android-emulator-test.sh
#   ANDROID_CORE defaults to platforms/android/app/build/core/jniLibs/x86_64
#   (what `./gradlew -PtincAbis=x86_64 assembleDebug' leaves there).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMG="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-dev}}"
TOOLS="${TOOLS_IMAGE:-tincstack/fp-tools:dev}"
ACORE="${ANDROID_CORE:-$ROOT/platforms/android/app/build/core/jniLibs/x86_64}"
RUN="$HERE/run-android"
PFX=aet
NET=${PFX}net
SUBNET=10.47.14
F_IP=$SUBNET.12        # Linux founder
C_IP=$SUBNET.14        # Linux dialler, the control
YAML=/c/tinc.yaml
AD=/data/local/tmp/tinclab  # the Android node's directory
FAILED=0
export NAME=$PFX-emu

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS $1"; }
bad() { log "FAIL $1"; FAILED=1; }

[[ -f $ACORE/libtincd.so && -f $ACORE/libtinc.so ]] || { log "no libtincd.so/libtinc.so in $ACORE"; exit 1; }

cleanup() {
	docker rm -f "$PFX-f" "$PFX-c" "$PFX-capf" "$NAME" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	docker run --rm -v "$RUN:/r" "$IMG" sh -c 'rm -rf /r/*' >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
[[ -n ${KEEP:-} ]] || trap cleanup EXIT
cleanup
mkdir -p "$RUN/f" "$RUN/c" "$RUN/cap"
chmod 777 "$RUN/cap"
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

if ! docker image inspect "$TOOLS" >/dev/null 2>&1; then
	docker build -q --build-arg http_proxy="${HTTP_PROXY:-}" --build-arg https_proxy="${HTTP_PROXY:-}" \
		-t "$TOOLS" "$ROOT/testing/fingerprint" >/dev/null
fi

# ---- helpers ----------------------------------------------------------------------------------
linux() { # <name> <ip>
	docker run -d --name "$PFX-$1" --network "$NET" --ip "$2" --cap-add NET_ADMIN --device /dev/net/tun \
		-v "$RUN/$1:/c" "$IMG" sleep infinity >/dev/null
}
lt() { local n=$1; shift; docker exec "$PFX-$n" tinc -n lab -c "$YAML" "$@"; }
lstart() { docker exec -d "$PFX-$1" sh -c "tincd -n lab -c $YAML -D -d3 >>/c/tincd.log 2>&1"; }
lstop() { lt "$1" stop >/dev/null 2>&1 || true; sleep 1; }
ash() { docker exec "$NAME" adb shell "su 0 sh -c '$1'" | tr -d '\r'; }
at() { ash "$AD/tinc -n lab -c $AD/tinc.yaml --pidfile $AD/pid $*"; }
astart() { # detached: an `adb shell' with a child still running never returns
	docker exec -d "$NAME" adb shell "su 0 sh -c 'cd $AD && exec ./tincd -n lab -c $AD/tinc.yaml --pidfile $AD/pid --logfile $AD/tincd.log -D -d3 >/dev/null 2>&1'"
}
astop() { ash "kill \$(cat $AD/pid | cut -d\" \" -f1) 2>/dev/null; sleep 1; rm -f $AD/pid"; }
until_up() { # <log file>
	for _ in $(seq 40); do grep -q "Ready" "$1" 2>/dev/null && return 0; sleep 1; done
	log "never came up: $1"; tail -20 "$1" >&2; exit 1
}
capture() { # <name> <target container>
	docker run -d --name "$PFX-$1" --network "container:$PFX-$2" --cap-add NET_ADMIN --cap-add NET_RAW \
		-v "$RUN/cap:/cap" "$TOOLS" tcpdump -U --immediate-mode -i any -s 0 -w "/cap/$1.pcap" 'port 443' >/dev/null
	sleep 2
}
connected() { # <linux node> <peer> <transport>
	for _ in $(seq 40); do
		lt "$1" dump connections 2>/dev/null | grep -q "^$2 .*transport $3" && return 0
		sleep 1
	done
	return 1
}
tools() { docker run --rm --network "$NET" -v "$RUN/cap:/cap" "$TOOLS" bash -c "$1" 2>&1; }

# ---- the emulator, with the core pushed in -------------------------------------------------------
NET=$NET "$ROOT/platforms/android/docker/emulator.sh" up >&2
A_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$NAME")
docker cp "$ACORE/libtincd.so" "$NAME:/tmp/tincd"
docker cp "$ACORE/libtinc.so" "$NAME:/tmp/tinc"
docker exec "$NAME" adb push /tmp/tincd /tmp/tinc /data/local/tmp/ >/dev/null 2>&1
ash "rm -rf $AD && mkdir -p $AD && mv /data/local/tmp/tincd /data/local/tmp/tinc $AD/ && chmod 755 $AD/tincd $AD/tinc && touch $AD/tinc.yaml && chmod 600 $AD/tinc.yaml"
ver=$(ash "$AD/tincd --version" | head -2 | tr '\n' ' ')
log "android $(docker exec "$NAME" adb shell getprop ro.build.version.release | tr -d '\r') (API $(docker exec "$NAME" adb shell getprop ro.build.version.sdk | tr -d '\r')), guest NAT source $A_IP: $ver"
case $ver in *openssl*) ;; *) bad "the Android core is not an OpenSSL build: $ver" ;; esac

# ---- the founder, the Android node, the control --------------------------------------------------
linux f "$F_IP"
docker exec "$PFX-f" sh -c "install -m600 /dev/null $YAML && tinc -n lab -c $YAML set Name founder && tinc -n lab -c $YAML set Port 655"
lstart f
until_up "$RUN/f/tincd.log"
lt f set founder.Address "$F_IP"
inv=$(lt f invite aleaf)
at "join $inv" >/dev/null 2>&1 || true
at "set DeviceType dummy" >/dev/null
inv=$(lt f invite lleaf)
linux c "$C_IP"
lt c join "$inv" >/dev/null 2>&1
capture capf f

for tr in https quic; do
	at "set PreferredTransports $tr" >/dev/null
	astart
	if connected f aleaf "$tr"; then
		ok "the Android node connects to a Linux founder over $tr"
	else
		bad "the Android node connects to a Linux founder over $tr"
		ash "grep -iE \"$tr|carrier|error\" $AD/tincd.log | tail -6" >&2 || true
	fi
	astart_log=$(ash "grep -m1 -o \"QUIC carrier ready.*\" $AD/tincd.log" || true)
	astop
	lt c set PreferredTransports "$tr"
	lstart c
	connected f lleaf "$tr" || bad "control: the Linux leaf connects over $tr"
	lstop c
done
[[ -n $astart_log ]] && log "android: $astart_log"
# curl dialling the same founder by IP: the reference both must equal.
tools "curl -sk -m 8 -o /dev/null https://$F_IP/; curl -sk -m 8 -o /dev/null --http3-only https://$F_IP/" >/dev/null || true
docker stop -t 3 "$PFX-capf" >/dev/null

FIELDS=(-e tls.handshake.ja4_r -e tls.handshake.length -e tls.quic.parameter.type)
hellos() { # <src ip> <ja4 prefix>: JA4_r, handshake length, QUIC transport parameter types
	docker run --rm -v "$RUN/cap:/cap" "$TOOLS" tshark -r /cap/capf.pcap -Y "tls.handshake.type == 1 && ip.src == $1" \
		-T fields "${FIELDS[@]}" 2>/dev/null | grep "^$2" | sort -u
}
curl_hellos() { # <ja4 prefix>: ClientHellos from neither node -- curl's
	docker run --rm -v "$RUN/cap:/cap" "$TOOLS" tshark -r /cap/capf.pcap \
		-Y "tls.handshake.type == 1 && ip.src != $A_IP && ip.src != $C_IP && ip.src != $F_IP" \
		-T fields "${FIELDS[@]}" 2>/dev/null | grep "^$1" | sort -u
}
for p in t13:https q13:quic; do
	a=$(hellos "$A_IP" "${p%%:*}"); l=$(hellos "$C_IP" "${p%%:*}"); k=$(curl_hellos "${p%%:*}")
	printf 'android %s\n%s\nlinux %s\n%s\ncurl %s\n%s\n' "${p#*:}" "$a" "${p#*:}" "$l" "${p#*:}" "$k" >> "$RUN/clienthellos.txt"
	if [[ -n $k && $(cut -f1 <<<"$k") == "$(cut -f1 <<<"$l")" ]]; then
		ok "dialling an IP, the Linux ${p#*:} ClientHello has curl's extensions ($(cut -c1-10 <<<"$k"); handshake: curl $(cut -f2 <<<"$k") bytes, ours $(cut -f2 <<<"$l"))"
		[[ -z $(cut -f3 <<<"$k") ]] || log "     QUIC transport parameters: curl $(cut -f3 <<<"$k"), ours $(cut -f3 <<<"$l")"
	else
		bad "dialling an IP, the Linux ${p#*:} ClientHello has curl's extensions"
		diff <(tr ',_\t' '\n' <<<"$l") <(tr ',_\t' '\n' <<<"$k") | head -8 >&2 || true
	fi
	if [[ -n $a && $a == "$l" ]]; then
		ok "the Android ${p#*:} ClientHello is the Linux one: $(cut -c1-10 <<<"$a"), $(cut -f2 <<<"$a")-byte handshake, same extensions$(tp=$(cut -f3 <<<"$a"); [[ -z $tp ]] || echo ", transport parameters $tp")"
	else
		bad "the Android ${p#*:} ClientHello differs from the Linux one"
		diff <(tr ',_\t' '\n' <<<"$a") <(tr ',_\t' '\n' <<<"$l") | head -8 >&2 || true
	fi
done

if [[ $FAILED -eq 0 ]]; then
	log "android (emulator): all checks passed"
else
	log "android (emulator): FAILURES above"
fi
exit "$FAILED"

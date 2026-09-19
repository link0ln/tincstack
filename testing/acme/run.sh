#!/usr/bin/env bash
# Proof for `tinc cert`: issue a real certificate from a real ACME server over a
# DNS-01 challenge, with a stand-in Cloudflare API, and then walk the error
# taxonomy. Nothing leaves the host and no Cloudflare account is involved.
#
# Usage: [CORE_IMAGE=tincstack/core:tag] testing/acme/run.sh
# Exit 0 = every case behaved as documented.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CORE_IMAGE="${CORE_IMAGE:-tincstack/core:${TINCSTACK_TAG:-${WSF_TAG:-dev}}}"
export ACME_PROJECT="${ACME_PROJECT:-tincstack-acme}"
export ACME_ZONE="${ACME_ZONE:-example.test}"
DOMAIN="node.$ACME_ZONE"
RUN="$HERE/run"
FAILED=0

compose() { docker compose -f "$HERE/compose.yml" "$@"; }
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

# shellcheck disable=SC2329  # invoked from the EXIT trap below
cleanup() {
	compose down -v --remove-orphans >/dev/null 2>&1 || true
	# tincd writes as root inside the container; remove through a container so
	# that a non-root caller can still clean its own run directory.
	docker run --rm -v "$RUN:/run/acme" "$CORE_IMAGE" sh -c 'rm -rf /run/acme/*' >/dev/null 2>&1 || true
	rm -rf "$RUN" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$RUN"; mkdir -p "$RUN/certs"

# ---- trust anchors -------------------------------------------------------
# Pebble serves a fixed test certificate; its CA ships in the image.
log "extracting the Pebble test CA"
CID=$(docker create ghcr.io/letsencrypt/pebble:latest)
docker cp "$CID:/test/certs/pebble.minica.pem" "$RUN/certs/pebble.minica.pem" >/dev/null
docker rm -f "$CID" >/dev/null

log "minting a CA and a server certificate for the Cloudflare mock"
cat > "$RUN/certs/leaf.ext" <<EOF
subjectAltName=DNS:mock-cf
basicConstraints=CA:FALSE
extendedKeyUsage=serverAuth
EOF
docker run --rm -v "$RUN/certs:/certs" --entrypoint sh alpine/openssl -ec '
  cd /certs
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=mock-cf test CA" \
      -addext "basicConstraints=critical,CA:TRUE" -keyout ca.key -out ca.pem
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=mock-cf" \
      -keyout mock-cf.key -out mock-cf.csr
  openssl x509 -req -in mock-cf.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
      -days 2 -extfile leaf.ext -out mock-cf.pem
  chmod 0644 mock-cf.key
' >/dev/null 2>&1
cat "$RUN/certs/ca.pem" "$RUN/certs/pebble.minica.pem" > "$RUN/certs/bundle.pem"

# ---- lab -----------------------------------------------------------------
log "starting pebble, challtestsrv and the Cloudflare mock"
compose up -d >/dev/null

# Both servers are up when their ports accept a connection from inside the lab.
ready=0
for _ in $(seq 90); do
	if compose exec -T mock-cf python3 -c '
import socket,sys
for hp in (("pebble",14000),("mock-cf",4443)):
    s=socket.socket(); s.settimeout(1)
    try: s.connect(hp)
    except OSError: sys.exit(1)
    s.close()
' >/dev/null 2>&1; then ready=1; break; fi
	sleep 1
done
[ "$ready" = 1 ] || { log "FAIL: pebble or mock-cf never came up"; compose logs --tail=40; exit 1; }

# ---- config generator ----------------------------------------------------
# One network "t" per case, each with its own file so a failed case cannot
# leave state behind for the next one.
write_conf() {   # write_conf <file> <token> [domain]
	cat > "$RUN/$1" <<EOF
networks:
  t:
    options:
      Name: n1
      CertDomain: ${3:-$DOMAIN}
      CloudflareToken: $2
      CloudflareApi: https://mock-cf:4443/client/v4
      AcmeDirectory: https://pebble:14000/dir
      AcmeCaFile: /run/acme/certs/bundle.pem
      AcmeContact: mailto:nobody@example.test
      AcmePropagation: 1
      AcmePollTimeout: 45
      AcmeRenewDays: 1
    hosts:
      n1: |
        Port = 655
EOF
}

run_cert() {   # run_cert <file> <subcommand...>
	local f="$1"; shift
	# </dev/null: `compose exec` reads stdin, and without this the loop below
	# feeds it the rest of the case list instead of the shell.
	compose exec -T node tinc -c "/run/acme/$f" -n t cert "$@" 2>&1 </dev/null
}

check() {   # check <name> <expected-substring> <output>
	if printf '%s' "$3" | grep -qF -- "$2"; then
		log "PASS $1"
	else
		log "FAIL $1: expected to see '$2'"
		printf '%s\n' "$3" | sed 's/^/      | /' >&2
		FAILED=1
	fi
}

# ---- 1. the happy path ---------------------------------------------------
log "case: a working token issues a certificate"
write_conf good.yaml tok-good-000000000000000000
out=$(run_cert good.yaml issue || true)
check "issue succeeds" "Stored the certificate for $DOMAIN" "$out"
check "issue reports the new pin" "New TlsFingerprint:" "$out"

status=$(run_cert good.yaml status || true)
check "status names the domain" "Valid for      $DOMAIN" "$status"
check "status shows a CA issuer" "Pebble" "$status"
check "status no longer says self-signed" "Kind           issued by a CA" "$status"

# The fingerprint in the host record must be the one of the certificate that
# was just stored: peers pin this, and a stale pin locks them out.
fp=$(printf '%s' "$status" | awk '/^Fingerprint/{print $2}')
if grep -q "TlsFingerprint = $fp" "$RUN/good.yaml"; then
	log "PASS host record carries the new fingerprint"
else
	log "FAIL host record fingerprint does not match the stored certificate"
	grep -n "TlsFingerprint" "$RUN/good.yaml" >&2 || echo "      | (no TlsFingerprint line at all)" >&2
	FAILED=1
fi

# The account key is kept, so a second run reuses the ACME account.
if grep -q "acme_account" "$RUN/good.yaml"; then
	log "PASS the ACME account key was stored"
else
	log "FAIL the ACME account key was not stored"
	FAILED=1
fi

# AcmeRenewDays is 1 above, and the CA issues for longer than that, so a renew
# straight after an issue has nothing to do. --force must still reissue.
out=$(run_cert good.yaml renew || true)
check "renew is a no-op on a fresh certificate" "nothing to do" "$out"

out=$(run_cert good.yaml renew --force || true)
check "renew --force reissues anyway" "Stored the certificate for $DOMAIN" "$out"

if run_cert good.yaml check >/dev/null 2>&1; then
	log "PASS check passes with a good token"
else
	log "FAIL check rejected a token that works"
	FAILED=1
fi

# ---- 2. the error taxonomy ----------------------------------------------
# name:token:expected code:expected phrase
cases="
bad token:tok-bad-000000000000000000:cloudflare-token:Invalid API Token
inactive token:tok-inactive-000000000000:cloudflare-token:is not active
insufficient rights:tok-noperm-000000000000:cloudflare-permission:Zone:DNS:Edit
rights for another zone:tok-otherzone-00000000:cloudflare-zone:other.test
no zones at all:tok-nozone-000000000000:cloudflare-zone:no zones at all
rate limited:tok-ratelimit-0000000000:cloudflare-api:rate-limiting
"
i=0
while IFS=: read -r name token code phrase rest; do
	[ -n "${name:-}" ] || continue
	i=$((i + 1))
	# "Zone:DNS:Edit" contains colons; glue the remainder back on.
	[ -n "${rest:-}" ] && phrase="$phrase:$rest"
	write_conf "case$i.yaml" "$token"
	out=$(run_cert "case$i.yaml" issue || true)
	check "$name -> $code" "FAILED ($code)" "$out"
	check "$name explains why" "$phrase" "$out"
done <<EOF
$cases
EOF

# A record that is accepted but never published: the CA cannot validate it.
log "case: the TXT record never appears in DNS"
write_conf silent.yaml tok-silent-000000000000000000
out=$(run_cert silent.yaml issue || true)
check "silent zone -> acme-challenge" "FAILED (acme-challenge)" "$out"

# A domain the token's zone does not cover, with a token that works otherwise.
log "case: CertDomain outside the token's zone"
write_conf outside.yaml tok-good-000000000000000000 "node.elsewhere.test"
out=$(run_cert outside.yaml issue || true)
check "domain outside the zone -> cloudflare-zone" "FAILED (cloudflare-zone)" "$out"
check "it names the zones the token can see" "$ACME_ZONE" "$out"

# ---- 3. a running daemon picks up the new certificate --------------------
# The https front used to read the certificate only at carrier init, so a
# certificate swapped in while the daemon ran was served only after a restart
# (PLAN.md Known Issues, M5). `tinc cert issue` asks for a reload; this proves
# the reload actually re-reads it.
log "case: the running daemon serves the new certificate after a reload"
compose exec -T node sh -ec '
	mkdir -p /run/acme/keys/hosts
	printf "Name = n1\n" > /run/acme/keys/tinc.conf
	tinc -c /run/acme/keys generate-keys >/dev/null 2>&1
	chmod -R a+rX /run/acme/keys
' </dev/null

{
	echo "networks:"
	echo "  t:"
	echo "    options:"
	echo "      Name: n1"
	echo "      Mode: router"
	echo "      Port: 0"
	echo "      DeviceType: dummy"
	echo "      Transports: [plain, https]"
	echo "      CertDomain: $DOMAIN"
	echo "      CloudflareToken: tok-good-000000000000000000"
	echo "      CloudflareApi: https://mock-cf:4443/client/v4"
	echo "      AcmeDirectory: https://pebble:14000/dir"
	echo "      AcmeCaFile: /run/acme/certs/bundle.pem"
	echo "      AcmePropagation: 1"
	echo "      AcmePollTimeout: 45"
	echo "    keys:"
	echo "      ed25519_priv: |"; sed 's/^/        /' "$RUN/keys/ed25519_key.priv"
	echo "      rsa_priv: |"; sed 's/^/        /' "$RUN/keys/rsa_key.priv"
	echo "    hosts:"
	echo "      n1: |"; sed 's/^/        /' "$RUN/keys/hosts/n1"
} > "$RUN/hot.yaml"

compose exec -d node tincd -c /run/acme/hot.yaml -n t -D -d2 --logfile=/run/acme/hot.log
started=0
for _ in $(seq 30); do
	if grep -q "TLS certificate ready" "$RUN/hot.log" 2>/dev/null; then started=1; break; fi
	sleep 1
done

if [ "$started" != 1 ]; then
	log "FAIL the daemon never brought the TLS front up"
	[ -f "$RUN/hot.log" ] && sed 's/^/      | /' "$RUN/hot.log" >&2
	FAILED=1
else
	before=$(grep "TLS certificate ready" "$RUN/hot.log" | tail -1 | awk '{print $NF}')
	out=$(run_cert hot.yaml issue || true)
	check "issue against a running daemon succeeds" "Stored the certificate" "$out"
	check "issue asks the daemon to reload" "reload its configuration" "$out"

	after=""
	for _ in $(seq 20); do
		after=$(grep "TLS certificate ready" "$RUN/hot.log" | tail -1 | awk '{print $NF}')
		[ -n "$after" ] && [ "$after" != "$before" ] && break
		sleep 1
	done

	want=$(run_cert hot.yaml status | awk '/^Fingerprint/{print $2}')
	if [ -n "$after" ] && [ "$after" != "$before" ] && [ "$after" = "$want" ]; then
		log "PASS the running daemon reloaded the new certificate (${before:0:12}… -> ${after:0:12}…)"
	else
		log "FAIL the running daemon did not pick up the new certificate"
		log "     before=$before after=$after stored=$want"
		FAILED=1
	fi
fi

# shellcheck disable=SC2016  # the $() runs inside the container, not here
compose exec -T node sh -c 'kill "$(cat /run/acme/*/t/pid 2>/dev/null | head -1)" 2>/dev/null; true' </dev/null || true

if [ "$FAILED" = 0 ]; then
	log "testing/acme/run.sh: OK"
else
	log "testing/acme/run.sh: FAILED"
fi
exit "$FAILED"

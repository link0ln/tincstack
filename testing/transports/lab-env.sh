#!/bin/sh
# lab-env.sh -- sourced by the transport proofs; derives the per-run names so
# two runs of one script (or of two scripts) can share a host without killing
# each other's containers or fighting over one docker subnet.
#
#   LAB      prefix of every container and network name and of the /tmp data
#            directory. Default: the script's historical prefix (DEFAULT_LAB),
#            so the names the READMEs document stay valid.
#   SUBNET   the lab /24 without its last octet. Default: DEFAULT_SUBNET for
#            the default LAB; any other LAB gets a LAB-derived third octet
#            (20..219) so a concurrent run never asks docker for a subnet that
#            is already in use. Override explicitly on a collision.
#
# The caller sets DEFAULT_LAB and DEFAULT_SUBNET, then sources this file:
#   DEFAULT_LAB=wsbsf; DEFAULT_SUBNET=10.31.9; . "$(dirname "$0")/lab-env.sh"
LAB=${LAB:-$DEFAULT_LAB}
if [ -z "${SUBNET:-}" ]; then
	if [ "$LAB" = "$DEFAULT_LAB" ]; then
		SUBNET=$DEFAULT_SUBNET
	else
		SUBNET=${DEFAULT_SUBNET%.*}.$(( $(printf %s "$LAB" | cksum | cut -d' ' -f1) % 200 + 20 ))
	fi
fi
case $LAB in
	*[!a-z0-9]*|'') echo "LAB must be lowercase letters and digits only (got '$LAB')" >&2; exit 2 ;;
esac
echo "lab: LAB=$LAB SUBNET=$SUBNET.0/24" >&2

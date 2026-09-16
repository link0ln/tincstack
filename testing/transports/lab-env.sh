#!/bin/sh
# lab-env.sh -- sourced by the transport proofs; derives the per-run names so
# two runs of one script (or of two scripts) can share a host without killing
# each other's containers or fighting over one docker subnet.
#
#   LAB      prefix of every container and network name and of the /tmp data
#            directory. Default: the script's historical prefix (DEFAULT_LAB),
#            so the names the READMEs document stay valid.
#   SUBNET   the lab /24 without its last octet. The first candidate is
#            DEFAULT_SUBNET for the default LAB and a LAB-derived third octet
#            (20..219) for any other; if a docker network that is not this
#            lab's own already holds that /24, the lowest free octet in
#            20..219 is taken instead. The derivation has only 200 values, so
#            two non-default LABs can hash to the same one (`wsu1` and `wso`
#            do) -- that is what the retry is for. Set SUBNET to pin one.
#
# The retry reads the docker network list; it is not a lock. Two labs started
# within the same second can both see the same /24 free and the loser gets
# docker's "Pool overlaps with other one on this address space". Stagger the
# starts, or set SUBNET, if that matters.
#
# The caller sets DEFAULT_LAB and DEFAULT_SUBNET, then sources this file:
#   DEFAULT_LAB=wsbsf; DEFAULT_SUBNET=10.31.9; . "$(dirname "$0")/lab-env.sh"
LAB=${LAB:-$DEFAULT_LAB}
case $LAB in
	*[!a-z0-9]*|'') echo "LAB must be lowercase letters and digits only (got '$LAB')" >&2; exit 2 ;;
esac

if [ -z "${SUBNET:-}" ]; then
	# The /24s docker already has, as bare "a.b.c" prefixes, so a candidate can
	# be tested against them. One docker call, not one per candidate. A host
	# with no reachable docker daemon yields an empty list, i.e. the historical
	# behaviour of taking the first candidate unconditionally.
	#
	# This lab's own networks do not count as a collision: every proof here
	# names its network after LAB (<LAB>, <LAB>obfs, <LAB>front, <LAB>-lab,
	# <LAB>-smoke, <LAB>-a_default ...), and a leftover one from a run that was
	# killed before its cleanup trap is about to be removed by the caller
	# anyway -- counting it would move the lab off its documented /24 for no
	# reason. The test is therefore "name starts with LAB", with one exception:
	# a digit right after the prefix means a DIFFERENT lab whose name merely
	# starts with ours (wso vs wso1obfs), so that one does count. Two labs
	# where one name is an alphabetic prefix of the other are not distinguished
	# and fall back to the old behaviour: docker refuses the overlapping pool.
	lab_env_taken=$(docker network ls -q 2>/dev/null \
		| xargs -r docker network inspect \
			--format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null \
		| awk -v self="$LAB" '
			index($1, self) == 1 && substr($1, length(self) + 1, 1) !~ /^[0-9]$/ { next }
			{ for(i = 2; i <= NF; i++) if(sub(/\.[0-9]+\/[0-9]+$/, "", $i)) { print $i } }')

	lab_env_free() { # prefix -> 0 when no other lab holds that /24
		printf '%s\n' "$lab_env_taken" | grep -qx "$1" && return 1
		return 0
	}

	lab_env_base=${DEFAULT_SUBNET%.*}
	if [ "$LAB" = "$DEFAULT_LAB" ]; then
		lab_env_first=$DEFAULT_SUBNET
	else
		lab_env_first=$lab_env_base.$(( $(printf %s "$LAB" | cksum | cut -d' ' -f1) % 200 + 20 ))
	fi

	SUBNET=$lab_env_first
	if ! lab_env_free "$SUBNET"; then
		lab_env_n=20
		while [ "$lab_env_n" -le 219 ]; do
			SUBNET=$lab_env_base.$lab_env_n
			lab_env_free "$SUBNET" && break
			lab_env_n=$(( lab_env_n + 1 ))
		done
		if [ "$lab_env_n" -gt 219 ]; then
			echo "lab-env: every /24 in $lab_env_base.20-219 is in use; set SUBNET explicitly" >&2
			exit 2
		fi
		echo "lab: $lab_env_first.0/24 is held by another lab, taking $SUBNET.0/24" >&2
	fi
fi
echo "lab: LAB=$LAB SUBNET=$SUBNET.0/24" >&2

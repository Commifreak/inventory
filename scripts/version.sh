#!/bin/sh
# Prints the version of builds that are not releases: the newest release tag
# (vX.Y.Z) with the patch number increased plus a pre-release suffix, e.g.
# 0.2.1-edge.202611181200 after v0.2.0. Such versions sort above the last
# release and below every following one (0.2.1, 0.3.0, ...), so agents update
# in the right direction when a server switches between :edge and :latest.
#
# Usage: scripts/version.sh [suffix]      (default suffix: dev)
#   REQUIRE_TAG=1  fail if no release tag is found (CI: a shallow clone
#                  without tags would produce versions below every release)
set -eu
suffix="${1:-dev}"
last=$(git tag --list 'v*' 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n1 || true)
if [ -z "$last" ]; then
	if [ -n "${REQUIRE_TAG:-}" ]; then
		echo "no release tag vX.Y.Z found (fetch tags: actions/checkout with fetch-depth: 0)" >&2
		exit 1
	fi
	last=0.0.0
fi
major=${last%%.*}
rest=${last#*.}
minor=${rest%%.*}
patch=${rest#*.}
echo "${major}.${minor}.$((patch + 1))-${suffix}"

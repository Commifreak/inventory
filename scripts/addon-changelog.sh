#!/bin/sh
# Prints the Home Assistant add-on changelog entry for a release: the titles
# of the changes since the previous release that touch the agent or the
# add-on image. Every change is a squash-merged pull request, i.e. one commit
# on main whose subject is the PR title ("Title (#12)").
#
# Usage: scripts/addon-changelog.sh <version> [owner/repo]   (e.g. 0.3.1)
set -eu
version="$1"
repo="${2:-Commifreak/inventory}"
paths='^(internal/agent/|internal/protocol/|cmd/inventory-agent/|ha-addon/)'

prev=$(git tag --list 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sed 's/^v//' |
	sort -t. -k1,1n -k2,2n -k3,3n | awk -v v="$version" '$0 == v { print p; exit } { p = $0 }')

echo "## ${version}"
echo
if [ -z "$prev" ]; then
	echo "- First release."
else
	found=0
	for h in $(git log --first-parent --format=%H "v${prev}..v${version}"); do
		if git diff-tree --no-commit-id --name-only -r "$h" | grep -qE "$paths"; then
			git log -1 --format='- %s' "$h" |
				sed -E "s|\(#([0-9]+)\)|([#\1](https://github.com/${repo}/pull/\1))|"
			found=1
		fi
	done
	[ "$found" = 1 ] || echo "- No changes to the agent; this release only changes the Inventory server."
fi
echo
echo "Release notes: https://github.com/${repo}/releases/tag/v${version}"

#!/bin/sh
# Fails unless every Go module in modules.txt is compiled into the caddy
# binary on PATH. Usage: verify-modules.sh [modules.txt]
set -eu

list="${1:-/etc/caddy/cpm-modules.txt}"
packages="$(caddy list-modules --packages --skip-standard)"
status=0

for entry in $(grep -Ev '^[[:space:]]*(#|$)' "$list"); do
	pkg="${entry%@*}"
	ids="$(printf '%s\n' "$packages" | awk -v p="$pkg" '$2 == p || index($2, p "/") == 1 { print $1 }')"
	if [ -z "$ids" ]; then
		echo "MISSING: $pkg provides no Caddy modules" >&2
		status=1
	else
		echo "ok: $pkg -> $(echo $ids)"
	fi
done

exit "$status"

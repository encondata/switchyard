#!/bin/sh
# Starts Caddy as uid 1000 (gid 0), the same user CPM runs as, so CPM can
# read certificate files from Caddy's data folder for the cert status page.
# The binary has cap_net_bind_service, so it can still bind ports 80/443.
set -eu

CADDY_UID=1000
CADDY_GID=0

# Volumes created by an earlier root-run Caddy keep root-owned files; fix
# ownership once, while we're still root.
for d in /data /config /run/caddy /var/log/caddy; do
	mkdir -p "$d"
	if [ "$(stat -c %u "$d")" != "$CADDY_UID" ] || [ -n "$(find "$d" ! -user "$CADDY_UID" -print -quit 2>/dev/null)" ]; then
		chown -R "$CADDY_UID:$CADDY_GID" "$d"
	fi
done
rm -f /run/caddy/admin.sock

if [ "$#" -gt 0 ]; then
	exec su-exec "$CADDY_UID:$CADDY_GID" "$@"
fi

# No command: run the last config CPM applied, or the bootstrap config on a
# fresh install.
config=/etc/caddy/bootstrap.json
if [ -s /etc/caddy/cpm/caddy.json ]; then
	config=/etc/caddy/cpm/caddy.json
fi
echo "cpm-caddy: starting with $config"
exec su-exec "$CADDY_UID:$CADDY_GID" caddy run --config "$config"

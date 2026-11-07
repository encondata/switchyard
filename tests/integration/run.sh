#!/bin/sh
# Starts Caddy + CPM + Pebble + a test backend in Docker, runs the
# integration tests against them, and tears everything down.
#   tests/integration/run.sh
set -eu
cd "$(dirname "$0")"
here=$(pwd)
project=cpm-integration
compose="docker compose -p $project -f ../../compose.yaml -f compose.yaml --profile demo"

# Pebble's test root, so Caddy trusts the Pebble ACME server.
cid=$(docker create ghcr.io/letsencrypt/pebble:2.10.1@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199)
docker cp "$cid:/test/certs/pebble.minica.pem" "$here/pebble.minica.pem"
docker rm "$cid" >/dev/null
export PEBBLE_ROOT_PEM="$here/pebble.minica.pem"

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		echo "--- logs (failure) ---"
		$compose logs --no-color --tail 80 caddy cpm pebble || true
	fi
	$compose down -v >/dev/null 2>&1 || true
	rm -f "$here/pebble.minica.pem"
	exit "$status"
}
trap cleanup EXIT

$compose up -d --build --wait
CPM_INTEGRATION=1 CPM_URL=http://127.0.0.1:28080 CADDY_HTTP=127.0.0.1:28000 CADDY_HTTPS=127.0.0.1:28443 \
	go test -count=1 -v ./...

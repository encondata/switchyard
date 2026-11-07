# CaddyProxyManager (CPM)

A web UI for managing a Caddy reverse proxy, replacing Nginx Proxy Manager.
CPM keeps hosts, certificates, folders and access rules in its own database
and builds one complete Caddy JSON config from it, applied through Caddy's
admin API.

Spec and decisions: Harbor Master wiki, `CaddyProxyManager/Design`.
Work tracking: Harbor Master project `CPM`.

## Layout

| Path | What |
|---|---|
| `cmd/cpm` | Server entry point (API + embedded web UI) |
| `internal/server` | HTTP routing, API handlers, static UI serving |
| `internal/compiler` | Database state → Caddy JSON config (CPM-5) |
| `internal/ingest` | Access-log ingester with GeoIP tagging (CPM-22) |
| `web` | React + TypeScript frontend (Vite); `web/dist` is embedded in the binary |
| `caddy` | Custom Caddy image: `Dockerfile` (pinned Caddy, xcaddy, base images) and `modules.txt` (pinned plugins) |

## Custom Caddy image

`caddy/Dockerfile` builds Caddy with `xcaddy` from the plugins listed in
`caddy/modules.txt`. To add a plugin (GeoIP, rate limiting, CrowdSec, l4),
uncomment its line there and pin a version. The build fails if any listed
plugin is missing from `caddy list-modules`.

`make caddy` builds `cpm-caddy:dev` locally. On every push to `main` that
touches `caddy/`, the **Caddy image** workflow tests the image and publishes
it for amd64 and arm64 as `ghcr.io/encondata/cpm-caddy`, tagged `latest`,
the Caddy version (e.g. `v2.11.9`), and `<caddy version>-<git sha>`.

## Run it locally with Docker

```bash
docker compose up -d --build
```

- CPM UI: `http://<host>:8080` (listens on 0.0.0.0)
- Caddy: ports 80 and 443 on 0.0.0.0. With no hosts configured yet, it
  answers 404 "No site is configured for this address."
- First sign-in: **admin / 123456**. You must choose a new password before
  anything else works.

Caddy starts from `caddy/bootstrap.json`, which puts its admin API on the
unix socket `/run/caddy/admin.sock` (shared with CPM through a volume) and
nothing else. To start over with a fresh database (and the default admin
again): `docker compose down && docker volume rm cpm_cpm-data`.

## Requirements

- Go (version in `go.mod`)
- Node 22
- `golangci-lint` v2 (`brew install golangci-lint`)

## Common tasks

```bash
make ui       # build the frontend into web/dist
make build    # build bin/cpm with the UI embedded
make run      # run the server on :8080
make test     # go test -race ./...
make lint     # golangci-lint, oxlint, prettier check, tsc
make fmt      # format Go and frontend code
```

For UI work with hot reload, run `make run` in one terminal and
`cd web && npm run dev` in another; Vite proxies `/api` to `:8080`.

CI (`.github/workflows/ci.yml`) runs on every push: it lints and builds the
frontend, then lints, tests and builds the Go binary with the UI embedded,
and smoke-tests it.

# CPM's custom Caddy build. Every version is pinned here or in modules.txt.
# Build from the repo root:  docker build -t cpm-caddy caddy/

ARG GO_IMAGE=golang:1.27.3-alpine3.24@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18
ARG CADDY_IMAGE=caddy:2.11.9-alpine@sha256:0bbb055bda6793c999bde78b1b5ce3e89f829fb031af2cf50056ea1246559fee

FROM ${GO_IMAGE} AS build
ARG CADDY_VERSION=v2.11.9
ARG XCADDY_VERSION=v0.4.7

RUN apk add --no-cache git
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}

WORKDIR /src
COPY modules.txt .
RUN set -eu; \
    args=""; \
    for m in $(grep -Ev '^[[:space:]]*(#|$)' modules.txt); do args="$args --with $m"; done; \
    echo "xcaddy build ${CADDY_VERSION}${args}"; \
    CGO_ENABLED=0 xcaddy build "${CADDY_VERSION}" ${args} --output /out/caddy; \
    /out/caddy version

# The official image supplies the user, dirs (/config, /data), CA certs and
# default env; we swap in our binary.
FROM ${CADDY_IMAGE}
COPY --from=build /out/caddy /usr/bin/caddy
COPY modules.txt /etc/caddy/cpm-modules.txt
COPY verify-modules.sh /usr/local/bin/cpm-verify-modules
RUN caddy version && cpm-verify-modules

LABEL org.opencontainers.image.title="cpm-caddy" \
      org.opencontainers.image.description="Caddy built for CaddyProxyManager" \
      org.opencontainers.image.source="https://github.com/encondata/caddyproxymanager"

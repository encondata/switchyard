# CPM server image: React UI built and embedded into a static Go binary.
# Build from the repo root:  docker build -t cpm .

FROM node:22.23.4-alpine3.24@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202 AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.27.3-alpine3.24@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cpm ./cmd/cpm

FROM alpine:3.24@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -H -u 1000 -G root cpm \
    && mkdir -p /data /caddy-applied && chown cpm:root /data /caddy-applied
COPY --from=build /out/cpm /usr/local/bin/cpm

# Runs as uid 1000 in group root (gid 0): the group gives it access to
# Caddy's admin socket (mode 0660, owned root:root) without being root.
USER 1000:0
ENV CPM_LISTEN=0.0.0.0:8080 \
    CPM_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD wget -qO- http://127.0.0.1:8080/api/health >/dev/null || exit 1
ENTRYPOINT ["cpm"]

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Go and golangci-lint run locally when installed, otherwise in Docker
# (same versions as CI), so a Mac without Go can still build and test.
DOCKER_GO := docker run --rm -v "$(CURDIR)":/src -w /src \
	-v switchyard-gomod:/go/pkg/mod -v switchyard-gocache:/root/.cache/go-build
HOST_OS := $(shell uname -s | tr A-Z a-z)
HOST_ARCH := $(shell uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')

ifeq ($(shell command -v go 2>/dev/null),)
GO_BUILD := $(DOCKER_GO) -e CGO_ENABLED=0 -e GOOS=$(HOST_OS) -e GOARCH=$(HOST_ARCH) golang:1.27.3 go
GO_TEST := $(DOCKER_GO) golang:1.27.3 go
else
GO_BUILD := go
GO_TEST := go
endif

ifeq ($(shell command -v golangci-lint 2>/dev/null),)
GOLANGCI := $(DOCKER_GO) -v switchyard-lintcache:/root/.cache/golangci-lint golangci/golangci-lint:v2.15.0 golangci-lint
else
GOLANGCI := golangci-lint
endif

.PHONY: all ui build run test lint fmt caddy check clean

all: ui build

## ui: install frontend deps and build web/dist (embedded into the binary)
ui:
	cd web && npm ci && npm run build && touch dist/.gitkeep

## build: build the cpm binary into bin/
build:
	CGO_ENABLED=0 $(GO_BUILD) build -trimpath -ldflags '$(LDFLAGS)' -o bin/cpm ./cmd/cpm

## run: run the server on :8080 (use `cd web && npm run dev` for UI hot reload)
run:
	$(GO_BUILD) run ./cmd/cpm

## test: Go tests with the race detector
test:
	$(GO_TEST) test -race ./...

## lint: Go and frontend linters, plus format checks
lint:
	$(GOLANGCI) run
	cd web && npm run lint && npm run format:check && npm run typecheck

## fmt: format Go and frontend code
fmt:
	$(GOLANGCI) fmt
	cd web && npm run format

## caddy: build the custom Caddy image (switchyard-caddy:dev) and verify its modules
caddy:
	docker build -t switchyard-caddy:dev caddy/
	docker run --rm switchyard-caddy:dev cpm-verify-modules

## check: everything CI runs
check: lint test

clean:
	rm -rf bin
	find web/dist -mindepth 1 ! -name .gitkeep -delete

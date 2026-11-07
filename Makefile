VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all ui build run test lint fmt caddy check clean

all: ui build

## ui: install frontend deps and build web/dist (embedded into the binary)
ui:
	cd web && npm ci && npm run build && touch dist/.gitkeep

## build: build the cpm binary into bin/
build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/cpm ./cmd/cpm

## run: run the server on :8080 (use `cd web && npm run dev` for UI hot reload)
run:
	go run ./cmd/cpm

## test: Go tests with the race detector
test:
	go test -race ./...

## lint: Go and frontend linters, plus format checks
lint:
	golangci-lint run
	cd web && npm run lint && npm run format:check && npm run typecheck

## fmt: format Go and frontend code
fmt:
	golangci-lint fmt
	cd web && npm run format

## caddy: build the custom Caddy image (cpm-caddy:dev) and verify its modules
caddy:
	docker build -t cpm-caddy:dev caddy/
	docker run --rm cpm-caddy:dev cpm-verify-modules

## check: everything CI runs
check: lint test

clean:
	rm -rf bin
	find web/dist -mindepth 1 ! -name .gitkeep -delete

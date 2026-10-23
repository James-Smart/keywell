VERSION := $(shell git describe --always --dirty)

.PHONY: build test run

# A static binary, ./latch, that reports the git version.
build:
	CGO_ENABLED=0 go build -ldflags "-X main.Version=$(VERSION)" -o latch ./cmd/latch

test:
	go test ./...

# Serve the development install made by the README's quickstart.
run:
	go run ./cmd/latch serve --config ./dev-data/latch.yaml

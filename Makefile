VERSION := $(shell git describe --always --dirty)

.PHONY: build docker test run authentik-up authentik-down test-authentik

# A static binary, ./latch, that reports the git version.
build:
	CGO_ENABLED=0 go build -ldflags "-X main.Version=$(VERSION)" -o latch ./cmd/latch

# The container image, tagged latch:<version>.
docker:
	docker build --build-arg VERSION=$(VERSION) -t latch:$(VERSION) .

test:
	go test ./...

# Serve the development install made by the README's quickstart.
run:
	go run ./cmd/latch serve --config ./dev-data/latch.yaml

# The Authentik 2026.8 dev stack the importer tests read from.
authentik-up:
	dev/authentik/up.sh

authentik-down:
	dev/authentik/down.sh

test-authentik:
	LATCH_TEST_AUTHENTIK_DSN=$$(dev/authentik/dsn.sh) go test -count=1 -run Authentik ./internal/authentik/... ./internal/importer/...

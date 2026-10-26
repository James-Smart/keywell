VERSION := $(shell git describe --always --dirty)

.PHONY: build docker test run authentik-up authentik-down test-authentik

# A static binary, ./keywell, that reports the git version.
build:
	CGO_ENABLED=0 go build -ldflags "-X main.Version=$(VERSION)" -o keywell ./cmd/keywell

# The container image, tagged keywell:<version>.
docker:
	docker build --build-arg VERSION=$(VERSION) -t keywell:$(VERSION) .

test:
	go test ./...

# Serve the development instance made in the README's Development section.
run:
	go run ./cmd/keywell serve --config ./dev-data/keywell.yaml

# The Authentik 2026.8 dev stack the importer tests read from.
authentik-up:
	dev/authentik/up.sh

authentik-down:
	dev/authentik/down.sh

test-authentik:
	KEYWELL_TEST_AUTHENTIK_DSN=$$(dev/authentik/dsn.sh) go test -count=1 -run Authentik ./internal/authentik/... ./internal/importer/...

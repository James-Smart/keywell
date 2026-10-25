# Authentik dev stack

A real Authentik 2026.8.5 with a known set of users, groups, apps and two-step devices. The importer tests read from it (see "Dev stack fixture" in the import plan for every seeded row).

Nothing here is used in production. Needs Docker with Compose and `openssl`.

## Start

    make authentik-up

The first run writes `dev/authentik/.env` (random database password, secret key and `akadmin` password; it is git-ignored), starts the stack, waits for Authentik to finish migrating (a few minutes), and seeds it with `seed.py`. It ends with:

    export LATCH_TEST_AUTHENTIK_DSN=postgres://...

Running it again is safe: the seed changes nothing that is already there.

## Test against it

    make test-authentik

This fills in `LATCH_TEST_AUTHENTIK_DSN` from `.env` and runs the tests whose names contain `Authentik`. Plain `go test ./...` skips them.

## Reseed from scratch

    make authentik-down authentik-up

`authentik-down` deletes the database volume and `data/`, `certs/` and `custom-templates/`. It keeps `.env`.

## Authentik's UI

Port 9700 on this machine's LAN address, or `http://localhost:9700`. Sign in as `akadmin` with `AUTHENTIK_BOOTSTRAP_PASSWORD` from `.env`.

Postgres is on `127.0.0.1:55432` (database and user `authentik`; `dev/authentik/dsn.sh` prints the DSN).

#!/bin/sh
# Print the DSN of the Authentik dev stack's Postgres.
set -eu
cd "$(dirname "$0")"
pw=$(sed -n 's/^PG_PASS=//p' .env)
echo "postgres://authentik:${pw}@127.0.0.1:55432/authentik?sslmode=disable"

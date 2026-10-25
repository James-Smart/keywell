#!/bin/sh
# Stop the Authentik dev stack and delete its data. Keeps .env.
set -eu
cd "$(dirname "$0")"
if [ -f .env ]; then
	docker compose down -v
fi
rm -rf data certs custom-templates

#!/bin/sh
# Start the Authentik dev stack and seed it. Safe to run again.
set -eu
cd "$(dirname "$0")"

if [ ! -f .env ]; then
	umask 077
	{
		echo "PG_PASS=$(openssl rand -hex 24)"
		echo "AUTHENTIK_SECRET_KEY=$(openssl rand -hex 32)"
		echo "AUTHENTIK_BOOTSTRAP_PASSWORD=$(openssl rand -hex 16)"
		echo "AUTHENTIK_BOOTSTRAP_EMAIL=akadmin@example.org"
	} > .env
	echo "wrote dev/authentik/.env"
fi

mkdir -p data certs custom-templates
docker compose up -d

echo "waiting for Authentik to finish migrating (first start takes a few minutes)..."
i=0
while :; do
	n=$(docker compose exec -T postgresql psql -U authentik -d authentik -Atc \
		"select count(*) from authentik_flows_flow where slug='default-provider-authorization-implicit-consent'" 2>/dev/null || true)
	[ "$n" = "1" ] && break
	i=$((i + 1))
	if [ "$i" -ge 100 ]; then
		echo "timed out after 5 minutes waiting for the default flows" >&2
		exit 1
	fi
	sleep 3
done

# The flow can exist before the server container can run a shell; wait for it.
i=0
until docker compose exec -T server ak shell -c "print('ready')" >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -ge 40 ]; then
		echo "timed out waiting for ak shell" >&2
		exit 1
	fi
	sleep 3
done

docker compose exec -T server ak shell -c "$(cat seed.py)"

echo "Authentik UI: http://localhost:9700 (user akadmin, password in dev/authentik/.env)"
echo "export LATCH_TEST_AUTHENTIK_DSN=$(./dsn.sh)"

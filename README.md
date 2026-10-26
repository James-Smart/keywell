# Latch

Latch is a small identity provider for a makerspace, built to replace Authentik.
It is one Go binary with an embedded SQLite database and no other services to run.
Members sign in once, on a page with the space's branding, and that sign-in works for MediaWiki and the space's other apps through OpenID Connect.

## Quickstart

You need Go 1.27. From a checkout:

```sh
go run ./cmd/latch init --data-dir ./dev-data --public-url http://localhost:8080 \
  --admin-email you@example.org --admin-password 'correct horse battery staple' \
  --config ./dev-data/latch.yaml
go run ./cmd/latch serve --config ./dev-data/latch.yaml
```

`init` writes the config file, creates the database and a token signing key, and makes `you@example.org` an admin. Leave out `--admin-password` to be asked for it instead.

Then open <http://localhost:8080> and sign in. The Admin group requires two-step sign in, so you will be asked to set it up with an authenticator app first. You do not need an email server to try it.

`make run` runs the `serve` command above, `make build` builds a static `./latch` binary, and `make test` runs the tests.

For a real installation, set `--public-url` to the HTTPS address members will use (for example `https://login.example.org`) and put Latch behind a reverse proxy that terminates TLS. `GET /healthz` answers `{"status":"ok","version":"..."}` for health checks.

Then list the proxy's address in `trusted_proxies` (for example `127.0.0.1/32` when it runs on the same host, or `172.16.0.0/12` for Docker's default networks). Latch believes `X-Forwarded-For` and `X-Forwarded-Proto` only from those addresses. If the proxy is missing from the list, every member appears to come from the proxy's address, so the sign-in limit of 50 failures per address per 15 minutes is shared by everyone: a few people mistyping their passwords lock the whole space out. Latch logs a warning, `ignoring X-Forwarded-For from untrusted peer ...`, when it sees forwarded headers from an address it does not trust.

## Configuration

`latch.example.yaml` lists every setting with a short note. `latch init` writes your config file from it. Any setting can also be set with an environment variable: `LATCH_` plus the key path in capitals, for example `LATCH_SMTP_HOST`.

Keep `encryption_key` safe and backed up with the database. It encrypts the two-step sign-in secrets and the signing keys, and without it they cannot be read.

Latch refuses to start if:

- `password.min_length` is below 10. The built-in list of common passwords only covers passwords of 10 or more characters.
- Any duration is 0 or negative.
- `tokens.access` or `tokens.id` is longer than 24h. A retired signing key keeps verifying tokens for only 24 hours.
- `tokens.refresh_absolute` is shorter than `tokens.refresh`.
- A `trusted_proxies` entry is not a CIDR range (`10.0.0.0/8`) or an IP address.
- `metrics.listen` is set but is not `host:port`, or uses port 0.

## Metrics

Latch can serve Prometheus metrics. Set `metrics.listen` (or `LATCH_METRICS_LISTEN`) to a `host:port` such as `127.0.0.1:9100`. It is off when empty. Metrics are served at `/metrics` on that address only.

The listener is separate on purpose. `/metrics` is never on the public listener, so a reverse proxy in front of Latch cannot expose it by accident. Bind it to a private address and let only your Prometheus server reach it.

There are four metric families:

- `latch_build_info`: the running version.
- `latch_http_requests_total`: requests answered, by status class (`1xx` to `5xx`).
- `latch_logins_total`: sign-ins, by result (`success`, `failure`, `second_step_failure`). A correct password that still needs a second step counts only once that step is done.
- `latch_tokens_issued_total`: tokens issued to apps, by grant (`authorization_code`, `refresh_token`, `client_credentials`).

To scrape it, add this to Prometheus:

```yaml
scrape_configs: [{job_name: latch, static_configs: [{targets: ['127.0.0.1:9100']}]}]
```

## Running Latch for real

### Docker

`deploy/docker-compose.yml` runs Latch from a small image with no shell. The data lives in a named volume, `latch-data`, mounted at `/var/lib/latch`. Build the image, then make the config and database once:

```sh
docker compose -f deploy/docker-compose.yml build
docker compose -f deploy/docker-compose.yml run --rm latch init --config /var/lib/latch/latch.yaml \
  --data-dir /var/lib/latch --public-url https://login.example.org --admin-email you@example.org
docker compose -f deploy/docker-compose.yml up -d
```

`init` asks for the first admin's password. The port is published on `127.0.0.1:8080` only, so point your reverse proxy there. Because the image has no shell to edit the config file with, set SMTP and other settings with `LATCH_` variables in the compose file's `environment:` section (see the comments there).

### systemd

```sh
sudo useradd --system --home-dir /var/lib/latch --shell /usr/sbin/nologin latch
make build
sudo install -m 0755 latch /usr/local/bin/latch
sudo install -d -o root -g latch -m 0750 /etc/latch
sudo install -d -o latch -g latch -m 0750 /var/lib/latch
sudo latch init --config /etc/latch/latch.yaml --data-dir /var/lib/latch \
  --public-url https://login.example.org --admin-email you@example.org
sudo chown root:latch /etc/latch/latch.yaml
sudo chmod 0640 /etc/latch/latch.yaml
sudo chown -R latch:latch /var/lib/latch
sudo cp deploy/latch.service /etc/systemd/system/latch.service
sudo systemctl daemon-reload
sudo systemctl enable --now latch
```

The config file holds `encryption_key` and the SMTP password, so only root and the `latch` group can read it.

### Backups

A backup is the database, `data_dir/icons` (the admin's decisions about app icons) and the config file. The config's `encryption_key` is needed to read two-step sign-in secrets and signing keys from any backup. Without it, a copy of the database cannot restore those, so keep the key somewhere separate from the database backups too.

You can back up the database while Latch runs:

```sh
sqlite3 /var/lib/latch/latch.db ".backup '/backups/latch.db'"
```

Under Docker, use a throwaway container with the volume mounted read-write (SQLite needs to write to its lock files, even to read), and copy the config and icons as well:

```sh
mkdir -p backups
docker run --rm -v latch-data:/var/lib/latch -v "$PWD/backups:/backups" alpine sh -c '
  apk add --no-cache sqlite >/dev/null &&
  sqlite3 /var/lib/latch/latch.db ".backup /backups/latch.db" &&
  cp /var/lib/latch/latch.yaml /backups/ &&
  if [ -d /var/lib/latch/icons ]; then cp -r /var/lib/latch/icons /backups/; fi'
```

The volume's name is prefixed with the compose project name (the directory name, `deploy_latch-data` by default); `docker volume ls` shows it. Or stop Latch and copy `latch.db` along with the other files.

## Connecting MediaWiki

Install the [PluggableAuth](https://www.mediawiki.org/wiki/Extension:PluggableAuth) and [OpenID Connect](https://www.mediawiki.org/wiki/Extension:OpenID_Connect) extensions. Register the wiki in Latch as a confidential application with the redirect URI `https://wiki.example.org/index.php/Special:PluggableAuthLogin` (use your wiki's own address). Then add this to `LocalSettings.php`. The app's page in Latch has a Setup details panel with this snippet already filled in, apart from the secret.

The snippet:

```php
wfLoadExtension( 'PluggableAuth' );
wfLoadExtension( 'OpenIDConnect' );

$wgPluggableAuth_Config['Latch'] = [
    'plugin' => 'OpenIDConnect',
    'data' => [
        'providerURL' => 'https://login.example.org',
        'clientID' => '…',
        'clientsecret' => '…',
        'scope' => [ 'openid', 'profile', 'email', 'groups' ],
    ],
];
```

`providerURL` is Latch's `public_url`, with no trailing slash. The wiki takes the account name from `preferred_username`, along with `email` and `name`.

If the wiki's accounts came from Authentik, they are linked to Authentik's address, which changes when you switch. Set `$wgOpenIDConnect_MigrateUsersByEmail = true;` for the first sign-ins after the switch so existing accounts are matched by email.

## Connecting your own app

Any OpenID Connect client library will work. Point it at the discovery document:

```
https://login.example.org/.well-known/openid-configuration
```

- Grants: `authorization_code`, `refresh_token`, and `client_credentials` (for confidential apps that act as a service account).
- PKCE with `S256`. Public clients such as browser apps must use it; confidential clients may.
- Browser apps can call the token, userinfo and revocation endpoints directly: Latch allows cross-origin requests (CORS) from the origin of any registered redirect URI, without cookies. Discovery and the keys are readable from any origin.
- Client authentication: `client_secret_basic`, `client_secret_post`, or `none` for public clients.
- Scopes: `openid`, `profile`, `email`, `groups`, `offline_access`. The `groups` claim is a list of group names.
- ID tokens are signed with RS256. The public keys are at `/.well-known/jwks.json`.
- To sign a member out, send their browser to the `end_session_endpoint` (`/oauth/logout`) with `id_token_hint`, and `post_logout_redirect_uri` if you registered one.

To register an app, open Admin pages, then Applications, then Add application. Say whether the app keeps a secret, list the addresses it signs members back to, and choose which groups may use it. For an app that keeps a secret, copy the secret when it is shown. It is shown once; if you lose it, regenerate it from the app's page.

## Admin pages

Admins manage Latch at `/admin` (there is a link on the member home page). You need to be in a group that has admin access. If any of your groups requires two-step sign in, you need to have set it up, and Latch asks for your code when you sign in. This is checked again on every admin page: if you join such a group, or one of your groups starts requiring it, after you signed in, the next admin page sends you to set up two-step sign in first. The `Admin` group that `latch init` makes has admin access and requires two-step sign in.

The sidebar has these entries:

- **Members**: add, find and edit members; send an invitation or reset email, set a password, clear two-step sign in, sign someone out everywhere, or disable or delete an account.
- **Groups**: make groups, choose which give admin access or require two-step sign in, and add or remove members.
- **Applications**: register apps, choose which groups may use them, show them on the members' home page, and see the details to set each one up.
- **Service accounts**: accounts for scripts and devices, with the API tokens they use.
- **Settings**: the space's branding, a button to test the email settings, and the signing keys.
- **Audit log**: who changed what and when, and sign-in activity.

## Admin API

Most of what you can do on the admin pages you can also do over HTTP, for scripts. Three things are on the admin pages only: sending a test email, making a new signing key (also `latch rotate-keys`), and uploading an app's icon (over HTTP, set `icon_url` to an `https://` address instead). Open Admin pages, then Service accounts, and add a service account. On its page, make a token, choosing Read only or Full admin. Copy the token when it is shown. It starts with `latch_` and is shown once.

Send the token as a bearer token:

```sh
curl -H "Authorization: Bearer latch_…" https://login.example.org/api/v1/me
```

A read-only token can only make `GET` requests. A full admin token can change things too. Requests and answers are JSON, and each token may make 600 requests a minute. The OpenAPI document at `/api/v1/openapi.json` lists every route.

## Commands

Every command except `version` takes `--config PATH` (default `./latch.yaml`). Run `latch <command> -h` to see its flags.

| Command | What it does |
|---|---|
| `latch init --public-url URL [--data-dir DIR] [--admin-email EMAIL]` | Writes a config file, sets up the database and a signing key, and adds the first admin. |
| `latch serve` | Runs the web server. |
| `latch create-admin --email EMAIL` | Adds someone to the Admin group, creating their account if they don't have one. |
| `latch reset-password EMAIL` | Prints a link the member can use once, within an hour, to choose a new password. |
| `latch rotate-keys [--retire-after 90d]` | Makes a new token signing key and retires older keys that were replaced more than `--retire-after` ago. A running server picks up the change within 5 minutes. |
| `latch import-authentik --from DSN [--dry-run] [--drop-key KEY]...` | Copies members, groups and apps from an Authentik database, with their passwords, two-step sign in and recovery codes. `--dry-run` shows what would be copied and saves nothing. Rerun it as often as you like. Put the database password in the `PGPASSWORD` environment variable instead of in `--from` if you prefer. |
| `latch version` | Prints the version. |

## Status

Sign-in, password reset, two-step sign in, the member home page, the OpenID Connect endpoints, the commands above, the admin pages, the admin API and the Authentik importer work. To move from Authentik to Latch, follow `docs/cutover.md`.

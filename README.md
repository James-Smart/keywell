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

## Connecting MediaWiki

Install the [PluggableAuth](https://www.mediawiki.org/wiki/Extension:PluggableAuth) and [OpenID Connect](https://www.mediawiki.org/wiki/Extension:OpenID_Connect) extensions. Register the wiki in Latch as a confidential application with the redirect URI `https://wiki.example.org/index.php/Special:PluggableAuthLogin` (use your wiki's own address). Then add this to `LocalSettings.php`:

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

Applications will be registered in the admin UI, which is not built yet (see Status).

## Commands

Every command except `version` takes `--config PATH` (default `./latch.yaml`). Run `latch <command> -h` to see its flags.

| Command | What it does |
|---|---|
| `latch init --public-url URL [--data-dir DIR] [--admin-email EMAIL]` | Writes a config file, sets up the database and a signing key, and adds the first admin. |
| `latch serve` | Runs the web server. |
| `latch create-admin --email EMAIL` | Adds someone to the Admin group, creating their account if they don't have one. |
| `latch reset-password EMAIL` | Prints a link the member can use once, within an hour, to choose a new password. |
| `latch rotate-keys [--retire-after 90d]` | Makes a new token signing key and retires older keys that were replaced more than `--retire-after` ago. A running server picks up the change within 5 minutes. |
| `latch version` | Prints the version. |

## Status

Sign-in, password reset, two-step sign in, the member home page, the OpenID Connect endpoints and the commands above work. The admin UI, the admin API and the Authentik importer are being built next.

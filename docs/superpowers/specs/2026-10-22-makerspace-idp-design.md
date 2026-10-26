# Latch: a lightweight identity provider for a makerspace

**Status:** design, awaiting approval
**Date:** 2026-10-22
**Name:** Keywell. Renamed on 2026-10-26 from the placeholder Latch, which this document and the plans written before then still use.

## 1. Intent

Replace Authentik at a makerspace of roughly 120 members. Authentik works
but its admin UI confuses the volunteer team and it consumes resources out
of proportion to the job. Latch is a single Go binary with an embedded
SQLite database that does the handful of things the space actually needs,
with an admin UI a volunteer can use without training.

Success means:

- MediaWiki and the space's custom apps log in through Latch exactly as
  they do through Authentik today, with no member-visible change beyond
  the look of the login page.
- Every member's existing password and TOTP enrolment keeps working after
  cutover. No forced resets.
- A volunteer can onboard a new member (create, group, invite email) in
  under a minute with no instruction.
- It idles at a small fraction of Authentik's memory footprint and runs as
  one process with no external services.

## 2. Goals, non-goals, anti-goals

### Goals (v1)

- Manage members (users) and groups through a simple web UI.
- Act as an OpenID Connect provider for confidential clients (MediaWiki,
  server-side apps) and public clients (browser SPAs via PKCE).
- Branded login, logout, password reset and set-password pages: logo,
  colours, space name, support contact.
- Password reset and invite emails over SMTP.
- Optional TOTP second factor, enrolable by members, clearable by admins,
  requirable per group.
- Member home page with app tiles filtered by group, plus change password.
- Service accounts: non-human identities with group membership, holding API
  tokens for the admin API and usable as the identity for machine-to-machine
  OAuth2 (client credentials).
- Audit log of admin changes.
- One-shot, re-runnable importer from a live Authentik Postgres database:
  users, groups, memberships, password hashes, attributes, TOTP devices,
  OAuth2 providers and applications.

### Non-goals (explicitly later or never)

- WebAuthn / passkeys (planned phase 2; see §12).
- SAML, LDAP, RADIUS, forward-auth proxy.
- Social login or federating to upstream identity providers.
- Member self-registration.
- Multi-tenancy, flows/stages/policies engines, per-app claim mapping UIs.
- Postgres or MySQL backends.
- Horizontal scaling. One instance is the design.

### Anti-goals (would make this a failure even if it works)

- An admin UI that needs a glossary. If a screen needs "provider",
  "flow", "stage" or "binding" to explain itself, it is wrong.
- A cutover that forces members to reset passwords or re-enrol 2FA.
- Memory footprint comparable to Authentik's.
- Any dependency on an external service to start or to log someone in.

## 3. Constraints and decisions already made

| Decision | Choice | Whose |
|---|---|---|
| Language | Go, latest stable | Claude's call, accepted by James |
| Database | SQLite, single file, embedded driver (no cgo required) | Claude's call, accepted |
| Deployment | Single static binary; templates and assets embedded; Dockerfile and systemd unit provided | James |
| TLS | Terminated by an existing reverse proxy; Latch speaks plain HTTP and trusts `X-Forwarded-*` from configured proxies | Claude's call |
| Login identifier | Email address | James |
| Branding | Logo, primary colour, space name, support contact line, from config | James |
| Member home | App tiles filtered by group, plus change password | James |
| Members editing own profile | Password only; name and email are admin-edited | Claude's call |
| 2FA | TOTP in v1, passkeys later | James |
| Framework | No PocketBase or similar; plain Go with small libraries | James, after discussion |
| Secrets at rest | Client secrets stored hashed where possible, otherwise encrypted with a key from config | Claude's call |

Not a Go web framework. Standard library `net/http` with a small router if
desired, `html/template`, `net/smtp` or a thin mail library. A well-tested
OIDC provider library is acceptable (for example `zitadel/oidc`) if it does
not dictate storage or UI; the builder decides.

## 4. Domain model

All IDs are UUIDv4 strings unless stated. Timestamps are UTC RFC 3339.

**User**

- `id`, `type` ∈ {`member`, `service`}, `email` (unique, case-insensitive;
  required for members, optional for service accounts), `username` (unique,
  optional, used for `preferred_username`; required for service accounts),
  `name`
- `password_hash` (native: argon2id in PHC string format) or
  `legacy_password_hash` (Django format, see §9) — exactly one may be set;
  neither means "no password, must use reset link"
- `is_active` (disabled users cannot log in or obtain tokens; existing
  sessions and refresh tokens are revoked on disable)
- `is_admin` is **not** a column: admin rights come from membership of the
  group whose `is_admin` flag is set (see Group)
- `metadata`: JSON object, free-form, default `{}`
- `totp_secret` (encrypted at rest), `totp_confirmed_at`, `recovery_codes`
  (hashed, up to 10)
- `authentik_pk`, `authentik_uuid`, `authentik_uid` (nullable; set by the
  importer, see §9 and §6.4)
- `last_login_at`, `created_at`, `updated_at`

**Group**

- `id`, `name` (unique), `description`
- `is_admin`: members of any group with this flag may use the admin UI and
  API. Exactly one such group exists after first run (`Admin`); admins may
  flag others.
- `require_totp`: members of this group must have TOTP enrolled; they are
  forced through enrolment on next login (never locked out: a member with no
  enrolment completes it with their password alone, once)
- `metadata`: JSON object, default `{}`, exposed in tokens as described in §6.3
- `authentik_uuid` (nullable)

**Membership**: `user_id`, `group_id`. Flat; no nesting. Authentik parent
groups are flattened on import (a member of a child is also made a member of
each ancestor).

**Application** (an OIDC client plus its tile)

- `id`, `name`, `slug` (unique, URL-safe)
- `client_id` (unique), `client_secret_hash` (null for public clients),
  `client_type` ∈ {`confidential`, `public`}
- `redirect_uris`: list of exact-match URIs. Loopback (`http://127.0.0.1:*`,
  `http://localhost:*`) matches any port per RFC 8252.
- `post_logout_redirect_uris`: list
- `allowed_group_ids`: empty means any active user may sign in; otherwise
  the user must be in at least one listed group. Also controls tile visibility.
- `subject_mode` ∈ {`id`, `email`, `username`, `authentik_uuid`,
  `authentik_uid`}; default `id`. See §6.4.
- `access_token_ttl`, `refresh_token_ttl`, `id_token_ttl` (durations; defaults
  in §6.2)
- Tile fields: `launch_url` (nullable; no tile if null), `icon_url` or
  uploaded icon, `description`, `show_tile` bool
- `service_account_id` (nullable): when set, the `client_credentials` grant is
  enabled for this application and tokens it mints carry that service account
  as `sub` (§6.5). Confidential clients only.
- `authentik_provider_pk` (nullable)

**Session**: server-side, cookie-referenced. `id`, `user_id`, `created_at`,
`last_seen_at`, `expires_at`, `totp_passed` bool, `ip`, `user_agent`.

**AuthorizationCode**, **RefreshToken**, **AccessToken** (if opaque) as the
OIDC library or implementation needs. Refresh tokens are stored hashed,
rotate on use, and are revoked when the user is disabled, deleted, or
changes password, or when the admin clicks "sign out everywhere".

**Service account** is a User with `type = service`. It has no password, no
TOTP, cannot use the login pages, has a username and display name, belongs to
groups like any member, carries `metadata`, and appears in tokens exactly as a
member would (so apps authorize it by group). It owns zero or more API tokens.
An Application may name a service account as its machine identity (§6.5).

**ApiToken**: `id`, `service_account_id`, `label`, `token_hash`, `scope` ∈
{`admin`, `read`}, `created_by_user_id`, `created_at`, `last_used_at`,
`expires_at` (nullable). Shown once at creation. `read` tokens may only call
`GET` endpoints. A token's admin rights do not depend on the service account's
groups; they come from `scope` alone, so a door controller can be in
`Members` for app access and hold a `read` token for lookups without being an
admin.

**PasswordResetToken**: `token_hash`, `user_id`, `expires_at`, `used_at`,
`purpose` ∈ {`reset`, `invite`}.

**AuditEvent**: `id`, `at`, `actor_type` ∈ {`user`, `service_account`, `system`,
`importer`}, `actor_id`, `action` (e.g. `user.create`, `group.member.add`,
`app.secret.rotate`, `user.totp.clear`, `login.success`, `login.failure`),
`target_type`, `target_id`, `summary` (human sentence), `detail` (JSON).

**SigningKey**: RSA 2048 or EC P-256 (builder's choice; must be supported by
MediaWiki's OpenID Connect extension, RS256 is the safe default). `kid`,
private key encrypted at rest, `created_at`, `retired_at`. JWKS publishes all
non-expired keys; a `rotate-keys` subcommand creates a new active key and
keeps the old one published for the longest configured token TTL.

## 5. Member-facing pages

All member-facing pages share one branded frame: logo and space name in a
coloured header bar, support contact line in the footer, primary colour on
buttons and links. Mobile-friendly. No JavaScript required for login, reset
or logout; progressive enhancement only.

| Route | Purpose |
|---|---|
| `GET /login` | Email + password. When reached via an OIDC request, shows "to continue to *App name*". Link to forgotten password. |
| `POST /login` | Verifies credentials, upgrades legacy hash (§9), creates session. If TOTP enrolled, redirects to `/login/totp`. If a group requires TOTP and none enrolled, redirects to enrolment. |
| `GET/POST /login/totp` | Six-digit code or recovery code. |
| `GET /logout`, `POST /logout` | Ends session. GET shows confirm button (prevents CSRF logout); POST from the member home or RP-initiated logout (§6) acts directly. |
| `GET/POST /reset` | Enter email. Always responds "if that address exists we've emailed it" regardless of existence. |
| `GET/POST /reset/{token}` | Choose new password. Used for both reset and invite; copy differs by purpose. Invalidates all sessions and refresh tokens on success. |
| `GET /` | Member home: greeting, app tiles (apps with `show_tile`, a launch URL, and group access), links to change password and manage 2FA, sign out. Redirects to `/login` if no session. |
| `GET/POST /account/password` | Change password (requires current password). |
| `GET/POST /account/totp` | Enrol: shows QR and manual key, confirms with a code, then shows recovery codes once. Disable: requires current password and a code. |
| `GET /healthz` | Liveness, unauthenticated, returns version. |

Password rules: minimum 10 characters, no composition rules, reject the
top-10k common passwords list embedded in the binary. Builder may raise the
minimum.

Login throttling: per-account and per-IP sliding windows (defaults 10 per
account per 15 minutes, 50 per IP per 15 minutes). Failures after the limit
return the same page with a generic "try again later" message. Reset request
throttled per account (3 per hour) and per IP.

## 6. OpenID Connect provider

### 6.1 Endpoints

Issuer is `public_url` from config, exactly, with no trailing slash.

| Route | Notes |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery |
| `GET /.well-known/jwks.json` | Public keys |
| `GET /oauth/authorize` | Authorization code flow only. `response_type=code`. PKCE (`S256`) required for public clients, accepted for confidential. `nonce` honoured. `prompt=login` and `prompt=none` honoured. `max_age` honoured via session `last_login_at`. |
| `POST /oauth/token` | Grants: `authorization_code`, `refresh_token`. Client auth: `client_secret_basic`, `client_secret_post`, or `none` (public). Refresh tokens rotate. |
| `GET/POST /oauth/userinfo` | Bearer access token. |
| `POST /oauth/revoke` | RFC 7009 for refresh tokens. |
| `POST /oauth/introspect` | RFC 7662, client-authenticated. Useful for the custom apps. |
| `GET /oauth/logout` | RP-initiated logout (OIDC RP-Initiated Logout 1.0): accepts `id_token_hint`, `post_logout_redirect_uri` (must be registered), `state`. Ends the Latch session and redirects. Without a valid redirect, shows the branded "you're signed out" page. |

No implicit or hybrid flows. No device flow. `client_credentials` is
available only to applications with a machine identity (§6.5).

Access tokens are JWTs signed RS256 with the active key so apps can verify
locally, matching what Authentik issues; also accepted at `/oauth/userinfo`.
Opaque access tokens are not an option (Claude's call, after builder review:
custom apps may already verify Authentik JWTs locally).

Consent screen: none. Apps are first-party; the admin's "allowed groups"
setting is the authorization. If the user is not in an allowed group, show
a branded "you don't have access to *App*" page with a sign-out link, not an
OAuth error redirect.

### 6.2 Default lifetimes

| Token | Default |
|---|---|
| Authorization code | 60 seconds, single use |
| Access token | 1 hour |
| ID token | 1 hour |
| Refresh token | 30 days, sliding on use, absolute cap 90 days |
| Browser session | 14 days idle, 30 days absolute; "remember me" is not a checkbox, these are the only settings |

All configurable globally; access/refresh/ID also per application.

### 6.3 Scopes and claims

Scopes: `openid`, `profile`, `email`, `groups`, `offline_access`. Unknown
scopes are ignored. `offline_access` is required for a refresh token to be
issued **only if** `require_offline_access_for_refresh` is true in config;
default false so MediaWiki, which does not request it, still refreshes.

| Claim | Scope | Source |
|---|---|---|
| `sub` | always | per application `subject_mode` (§6.4) |
| `email`, `email_verified` | `email` | user; `email_verified` is `true` (admins create accounts) |
| `name`, `preferred_username` | `profile` | user `name`, user `username` (falls back to email local part if username null) |
| `groups` | `groups` | array of group **names** the user belongs to |
| `metadata` | `profile` | user's metadata object, verbatim |
| `group_metadata` | `groups` | object keyed by group name → that group's metadata object, for the user's groups only |
| `is_admin` | `groups` | bool, convenience |
| `updated_at` | `profile` | user `updated_at` as Unix time |

ID tokens and userinfo both include these; access tokens include `sub`,
`email`, `groups`, `scope`, `client_id`, `exp`, `iat`, `iss`, `aud`.

A note on MediaWiki: the OpenID Connect extension reads `sub`, `email`,
`preferred_username` and `name`, and can map `groups` to wiki groups via its
`global_roles`/`groups` properties. No extra claim mapping is needed.

### 6.4 Subject identifiers and Authentik compatibility

Apps that keyed user records on Authentik's `sub` break if `sub` changes.
Authentik computes `sub` per provider from its `sub_mode`:

| Authentik `sub_mode` | Latch `subject_mode` | Value |
|---|---|---|
| `hashed_user_id` (default) | `authentik_uid` | SHA-256 hex of `"{user.pk}-{SECRET_KEY}"`. The importer computes and stores this per user when given Authentik's `SECRET_KEY`; without it the mode falls back to `id` with a warning. |
| `user_id` | `authentik_uid` variant | integer pk as string; importer stores `authentik_pk`, mode `authentik_pk` is a sixth allowed value |
| `user_uuid` | `authentik_uuid` | Authentik user UUID |
| `user_email` | `email` | current email |
| `user_username` | `username` | current username |
| `user_upn` | `email` | best effort; warn |

Users created after cutover have no Authentik values; for them any
Authentik-derived mode falls back to `id`. The admin UI shows the subject
mode on the application page with a one-line explanation and a warning
triangle when it is Authentik-derived, so it can be switched to `id` once
apps have migrated their user tables.

MediaWiki note for cutover: the issuer URL changes, and the OpenID Connect
extension keys accounts on `(issuer, sub)`. Enable its
`MigrateUsersByEmail` (or by username) option for the first logins after
cutover, or update the `openid_connect` table's issuer column during the
maintenance window. Put this in the cutover runbook (§11).

### 6.5 Machine-to-machine (client credentials)

A confidential application with a `service_account_id` may call
`POST /oauth/token` with `grant_type=client_credentials` and its client
secret. The response is an access token (no ID token, no refresh token) whose
`sub` is the service account per the application's `subject_mode`, with
`groups`, `metadata`, `email` (if set), `preferred_username` and
`client_id` claims. Default lifetime is the application's access-token TTL.
`/oauth/userinfo` and `/oauth/introspect` accept these tokens. The admin UI
shows the toggle as "Allow this app to sign in by itself (machine to machine)"
with a service-account picker.

## 7. Admin UI

Served under `/admin`. Requires a session for a user in an `is_admin` group
and TOTP passed if that group requires it. Left sidebar: Members, Groups,
Applications, Service accounts, Settings, Audit log. Same branded header as member pages with
an "Admin" label.

**Members list.** Search (name, email, username), filter (All / Active /
Invited / Disabled / No 2FA / Admins), columns: name, email, groups as
chips, status, last login. Paginated at 50. "Add member" button.

Members list shows `type = member` only; service accounts have their own
screen. Status is derived: *Disabled* (`!is_active`), *Invited* (no password set,
unexpired invite token exists), *Needs password* (no password set, no
token), *Active*.

**Add member.** Name, email, optional username, group checkboxes, metadata
(collapsed by default; empty `{}`), and a choice: *Send invite email* (default)
or *Set a password now*. Invite emails carry a set-password link valid 7 days.

**Edit member.** As mocked: name, email, username, group checkboxes, metadata
editor (textarea, validated as a JSON object on save), actions: send password
reset, set password manually, clear 2FA (confirm), disable/enable, sign out
everywhere, delete (confirm by typing email; deletes memberships, sessions,
tokens; audit event retained). Shows last login, created date, 2FA status,
Authentik import origin if any.

**Service accounts.** Sidebar entry. List: name, username, groups, token
count, last used. Create/edit: name, username, description, groups
checkboxes, metadata. Tokens panel: list (label, scope, created, last used,
expiry), create (label, scope, optional expiry; secret shown once), revoke.
Delete confirms and revokes all tokens.

**Groups.** List with member counts. Create/edit: name, description, admin
flag, require-2FA flag, metadata. Members tab with add-by-search and remove.
Deleting a group that is the last `is_admin` group is refused.

**Applications.** List with tile preview, client type, allowed groups. Edit:
name, slug, client type, redirect URIs (one per line), post-logout redirect
URIs, allowed groups, subject mode, token lifetimes (advanced, collapsed),
tile: show on home, launch URL, description, icon. "Regenerate secret" shows
the new secret once. A "Setup details" panel shows issuer, discovery URL,
client ID, and copy-paste snippets for MediaWiki's `LocalSettings.php` and a
generic OIDC client.

**Settings.** Branding preview (read-only, values come from config; page
explains where to change them). SMTP test: send a test email to the current
admin. Signing keys: list, rotate. Import status: last import run summary.

**Audit log.** Reverse-chronological, filter by actor, action, target;
30-day default view, searchable further back. Login failures are logged but
collapsed into one line per account per hour.

Error pages, empty states and confirmation dialogs use plain language.
Destructive buttons are red and confirm.

## 8. Admin REST API

Base `/api/v1`. `Authorization: Bearer <api token>` where the token belongs
to a service account (§4). JSON in and out. Errors are
`{"error": "code", "message": "human text"}`. All writes emit audit events
with `actor_type=service_account` and the token's id in `detail`. Tokens with
`scope = read` get `403` on anything but `GET`.

| Method, path | Purpose |
|---|---|
| `GET /users?q=&group=&status=&page=` | list |
| `POST /users` | create; body as Add member; `"invite": true` sends email |
| `GET/PATCH/DELETE /users/{id}` | id may also be `email:alex@example.org` |
| `POST /users/{id}/reset-email` | send reset link |
| `POST /users/{id}/password` | set password `{"password": "..."}` |
| `POST /users/{id}/totp/clear` | |
| `POST /users/{id}/sessions/revoke` | sign out everywhere |
| `PUT /users/{id}/groups` | replace full membership list `{"groups": ["Members","Laser"]}` by name or id |
| `POST/DELETE /users/{id}/groups/{group}` | add or remove one |
| `GET/POST /groups`, `GET/PATCH/DELETE /groups/{id}` | |
| `GET /groups/{id}/members` | |
| `GET/POST /apps`, `GET/PATCH/DELETE /apps/{id}` | |
| `POST /apps/{id}/rotate-secret` | returns secret once |
| `GET /audit?since=&actor=&action=&target=&page=` | |
| `GET/POST /service-accounts`, `GET/PATCH/DELETE /service-accounts/{id}` | |
| `GET/POST /service-accounts/{id}/tokens`, `DELETE /service-accounts/{id}/tokens/{tid}` | create returns secret once |
| `GET /me` | the calling service account and token scope |

The first service account and token are created from the Service accounts
screen by an admin; there is no bootstrap token in config. Rate limit 600 requests per minute
per token. OpenAPI 3 document served at `/api/v1/openapi.json`.

## 9. Password hash compatibility

Imported users carry a Django-format hash in `legacy_password_hash`. On
successful login the password is re-hashed with argon2id into
`password_hash` and the legacy field cleared. Formats to support, all
verified with constant-time comparison:

| Prefix | Format |
|---|---|
| `argon2$argon2id$v=19$m=…,t=…,p=…$<salt b64 nopad>$<hash b64 nopad>` | Authentik default since 2022 |
| `argon2$argon2i$…` | older Django |
| `pbkdf2_sha256$<iterations>$<salt>$<hash b64>` | Django default; common for old accounts |
| `pbkdf2_sha1$…` | rare |
| `scrypt$<n>$<salt>$<r>$<p>$<hash b64>` | rare |
| `bcrypt_sha256$<bcrypt string>` | bcrypt of sha256(password) hex |
| `!…` or empty | unusable; user is *Needs password*; importer counts these |

Native format: argon2id, PHC string, parameters at least m=64 MiB, t=3, p=4,
tuned so verification is under 100 ms on the target host. Builder may pick
exact values.

## 10. Importer

`latch import-authentik --from "postgres://…" [--secret-key …] [--dry-run]`

Connects directly to Authentik's Postgres. Read-only. Idempotent: matches
users on `authentik_uuid`, then email; groups on `authentik_uuid`, then
name; applications on `authentik_provider_pk`, then `client_id`. Existing
Latch records are updated, never duplicated. Fields an admin has changed in
Latch since the last run are overwritten by the import (document this; the
tool is for the migration window). Password hashes are only overwritten if
the user still has a legacy hash (never clobber a native hash from a
post-import login).

The target is the latest Authentik release as of October 2026 (the 2026.x
line, which is what James runs). The importer supports that schema only;
no code paths for older layouts. Table and column names below are from
memory of the current schema and must be verified by the builder against a
dump of the live database (`\d` in psql); Authentik renames columns between
releases. The importer should fail loudly
with the table/column name when a query fails.

**Users**: `authentik_core_user` → `email`, `username`, `name`, `password`
(legacy hash), `is_active`, `attributes` (jsonb → metadata), `uuid`,
`id` (pk), `last_login`, `date_joined`. Skip rows where `type` is a service
account (`service_account`, `internal_service_account`); James has none in
use today, and Authentik's own internal accounts must not be imported. Users with empty
email are skipped and listed in the report. Duplicate emails
(case-insensitive) are reported and the dry run fails until resolved.

**Groups**: `authentik_core_group` → `name`, `attributes` → metadata,
`group_uuid`, `is_superuser` → `is_admin`, `parent_id` (flattened).
Memberships: `authentik_core_user_ak_groups`. Authentik's MFA enforcement
lives in flows and policies and is not imported; the importer sets
`require_totp` on every imported `is_admin` group and nothing else (Claude's
call). Admins adjust in the Groups screen.

**Attribute filtering**: user and group `attributes` keys with the prefix
`goauthentik.io/` are dropped on import (they are Authentik internals). The
report lists every distinct remaining top-level key with a count so an admin
can review what will reach apps as `metadata` before cutover. `--drop-key`
may be repeated to exclude further keys (Claude's call).

**TOTP**: `authentik_stages_authenticator_totp_totpdevice` where
`confirmed = true` → `key` (hex, decode to raw secret, store encrypted),
`digits` (expect 6; warn otherwise). One device per user; if several, take
most recently used and report. Recovery codes:
`authentik_stages_authenticator_static_statictoken` joined to its device;
import unused tokens as recovery codes (hash them).

**Applications**: `authentik_core_application` joined to
`authentik_core_provider` and `authentik_providers_oauth2_oauth2provider`
→ `name`, `slug`, `meta_launch_url` → launch URL, `meta_icon` → icon URL,
`meta_description`, `client_id`, `client_secret` (hash on import; confidential
only), `client_type`, `redirect_uris` (newer Authentik: JSON list of
`{matching_mode, url}`; older: newline-separated text, possibly regex — strict
entries imported as-is, regex entries reported for manual entry),
`sub_mode` → subject mode per §6.4, `access_token_validity` and
`refresh_token_validity` (Authentik duration strings like `hours=1`, parse the
common forms). Allowed groups: group bindings in
`authentik_policies_policybinding` where `target_id` is the application's
`pbm_uuid` and `group_id` is set; policy-based bindings are reported for
manual review. Applications with a non-OAuth2 provider (SAML, proxy, LDAP)
are listed in the report and skipped.

**Report**: printed and stored (Settings → Import status): counts created,
updated, skipped, warnings, each with the reason. Dry run produces the same
report without writing.

**Secret key**: when `--secret-key` (or `LATCH_AUTHENTIK_SECRET_KEY`) is
given, compute `authentik_uid` per user. Authentik exposes this value as
`AUTHENTIK_SECRET_KEY` in its `.env`.

## 11. Configuration and operations

Config file `latch.yaml` (path from `--config`, default `./latch.yaml`),
every key overridable by `LATCH_` environment variables. Keys:

```yaml
public_url: https://login.example.org      # issuer; no trailing slash
listen: 0.0.0.0:8080
data_dir: /var/lib/latch                   # latch.db, uploaded icons
trusted_proxies: [10.0.0.0/8]              # for X-Forwarded-For/Proto
encryption_key: <32 bytes base64>          # at-rest encryption of TOTP secrets, signing keys; generated by `latch init`
branding:
  name: Hackspace Name
  logo: /var/lib/latch/logo.png            # or URL; served at /static/logo
  primary_color: "#2c6e49"
  support_text: "Need help? Email membership@hackspace.example"
smtp:
  host: smtp.example.org
  port: 587
  username: …
  password: …
  from: "Hackspace Login <login@hackspace.example>"
  tls: starttls                             # starttls | tls | none
sessions:
  idle: 336h
  absolute: 720h
tokens:
  access: 1h
  id: 1h
  refresh: 720h
  refresh_absolute: 2160h
  require_offline_access_for_refresh: false
password:
  min_length: 10
log:
  level: info
  format: json                              # json | text
```

Subcommands:

- `latch init` — writes a config skeleton with a fresh encryption key, creates
  the database, creates the `Admin` group and prompts for the first admin's
  email and password (or takes `--admin-email`, `--admin-password`).
- `latch serve` — runs migrations, starts HTTP.
- `latch import-authentik` — §10.
- `latch rotate-keys`, `latch create-admin`, `latch reset-password <email>`
  (prints a one-time link; break-glass when SMTP is down).
- `latch version`.

Build order (Claude's call, for the plan): importer, legacy hash
verification, OIDC provider and login pages first, since they carry the
cutover risk and can be exercised against the real export early; admin UI,
API and audit log after. Latch runs alongside Authentik on its own hostname
during the parallel period; admins are told not to edit members in Latch
until the final import because the importer overwrites (§10).

Logging: structured, one line per request at info, no passwords, tokens or
codes ever logged. Prometheus metrics at `/metrics` behind the trusted-proxy
check or a config flag; keep it minimal (requests, logins, token issuance).

Backups: the SQLite file in WAL mode. Document `sqlite3 latch.db ".backup"`
or stopping the service and copying the file. Icons live in `data_dir`.

Deliverables also include a `Dockerfile` (distroless or alpine, non-root,
volume at `/var/lib/latch`), a `docker-compose.yml` example, a systemd unit,
and a `docs/cutover.md` runbook covering: dry-run import a week ahead,
reconcile warnings, final import, switch MediaWiki's issuer with migrate-by-
email on, switch each custom app's issuer, verify a login per app, turn
Authentik off, remove migrate-by-email later.

## 12. Phase 2 candidates (not in v1)

- WebAuthn/passkeys as a second factor and as passwordless. Credentials
  import from Authentik only if the hostname is unchanged.
- Per-application claim toggles (hide metadata from an app).
- Member self-service edit of name with admin approval.
- Webhooks on user events for the automation James plans.
- LDAP read-only interface if a future tool needs it.

## 13. Left to the builder

- Router, OIDC library, SQLite driver, migration tool, template structure,
  CSS approach (no build step preferred; a small hand-written stylesheet or
  classless CSS is fine).
- Exact argon2id parameters, exact table schemas, index choices.
- Test strategy, but: there must be an end-to-end test that runs a real OIDC
  client (library or `oauth2` package) against the server for both client
  types plus client credentials, a test for every legacy hash format with
  known vectors, and importer tests as follows.
- **Importer development against a real Authentik.** No production dump is
  available during development (James's decision). The builder stands up the
  latest Authentik with its official docker-compose in a `dev/authentik/`
  directory, seeds it through Authentik's API with a script (members with
  passwords, a child group under a parent, a confirmed TOTP device with
  static recovery tokens, a confidential and a public OAuth2 provider with
  applications and a group binding, one service account to be skipped), and
  the importer test suite runs against that Postgres. Schema facts in §10
  are verified there, and the seed script doubles as the fixture generator.
  The seeded hashes must include at least one argon2 and one pbkdf2_sha256
  entry (set via Authentik's API or SQL).
- Icon upload limits and formats.
- Internal package layout.
- Whether access tokens are JWT or opaque (see §6.1).
- Pagination style in the API (page/size or cursor).
- Copy for emails and pages, within the plain-language rule.

## 14. Open questions resolved during brainstorming

Kept for the record; none remain open.

- PocketBase as a base: rejected, it would still need the OIDC provider,
  volunteer UI, login pages and legacy-hash handling built on top.
- Member profile self-edit: password only.
- 2FA scope: TOTP now, passkeys later.
- Authentik provider import: yes, so client credentials survive cutover.
- Member home: app tiles.

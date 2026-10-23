# Latch core: decisions made during implementation

Companion to `2026-10-22-latch-core.md`. These are the calls made while executing the plan, where the plan was silent, ambiguous, or wrong. Each says what was decided, why, and what it costs if wrong. The spec stays the binding authority; where a decision departs from the plan text, the spec or a review finding is the reason.

## Changes to what the plan said

- **Common-password list.** The plan named SecLists' top-10k list. It does not contain `password1234` and only 51 of its entries reach the 10-character minimum. Latch embeds the NCSC 100k list filtered to entries of 10+ characters (about 9,100 entries, about 106 KB). Costs about 100 KB of binary size.
- **Timestamps.** Stored as fixed-width UTC (`2006-01-02T15:04:05.000000000Z`) so string comparison in SQL orders correctly. RFC 3339 with variable-width fractions could mis-order expiries by under a second.
- **Key retirement.** `RetireOlderThan(d)` measures a key's age from when it was superseded, not from when it was created. The plan's "rotate, then retire keys older than 90 days" would otherwise drop the just-replaced key from the JWKS at once and break every app that checks tokens locally.
- **Retired-key grace.** A retired key still verifies tokens inside Latch for 24 hours, then stops. Retiring a key is also how an operator revokes a compromised one. Access and ID token lifetimes are capped at 24 hours in config to match.
- **Key reload.** `serve` reloads signing keys every 5 minutes, so `latch rotate-keys` run as a separate process takes effect without a restart.
- **Sign-in loop.** When authorize sends a member to sign in, the return address drops `prompt=login` and `max_age`. Keeping them verbatim, as the plan said, sent the member back to the sign-in page forever. Apps can still check `auth_time`.
- **Email subject mode.** `sub` is the stored email exactly as Authentik issued it, not lower-cased. Lower-casing would have changed `sub` for imported members with capital letters in their address.
- **Client-credentials tokens.** Always carry `groups`, `metadata`, `preferred_username` and `email` (if set), regardless of scope, as spec §6.5 says. The plan had scoped them like member tokens.
- **App-initiated logout.** With a signed-in browser and no matching `id_token_hint`, `/oauth/logout` now sends the member to the "Sign out?" confirmation page instead of signing them out. OIDC RP-Initiated Logout §2 requires asking. Costs one extra click for apps that omit the hint.
- **Config hardening.** Unknown config keys are refused. `password.min_length` must be at least 10; all durations positive; access and ID tokens at most 24 hours; `trusted_proxies` entries must parse. `init` now writes `trusted_proxies: []`.

## Security calls beyond the plan

- **Throttling counts failures only.** A successful sign-in gives back its place in both the per-account and per-IP limits. The space sits behind one NAT address, so 50 successful sign-ins in 15 minutes at an event is realistic. Reserve-then-refund keeps concurrent bursts inside the limit.
- **Second factor.** A session stays incomplete until TOTP is done when the member is enrolled **or** a group requires it, so nobody can skip enrolment. Wrong codes are capped at 5 per session and 10 per account per 15 minutes. Each code is accepted only once (RFC 6238 §5.2). Password change and turning TOTP off draw on the sign-in limit.
- **Reset emails** are sent in the background so response time does not reveal whether an address has an account.
- **Concurrent password hashing** is limited to a few at a time, and stored hashes with extreme cost parameters are refused. Without this, 50 parallel failed sign-ins grew memory by about 2 GB.
- **Service accounts** cannot sign in, receive reset emails, or be targeted by `reset-password` or `create-admin`.
- **Session IDs** are stored hashed; only the cookie holds the raw value. A copied database backup does not hand over live sessions.
- **Refresh rotation** is atomic. Presenting a revoked refresh token revokes the whole family. `/oauth/revoke` also revokes the whole family.
- **Wrong-client code exchange** gets exactly the same error as an unknown code.
- **CORS.** Discovery and JWKS allow any origin. Token, userinfo and revoke allow an origin only when it matches the origin of a registered redirect URI, and never with credentials.
- **Introspection** is open to any confidential client, per the RFC 7662 resource-server model.
- **Forwarded headers** from a peer not in `trusted_proxies` are ignored and logged once, so a misconfigured proxy is visible instead of silently turning per-IP limits into a global lockout.

## Smaller accepted choices

- Access tokens carry a private `latch_uid` claim so userinfo and introspection can reload the member.
- Turning TOTP off accepts a recovery code, so a member who lost their phone is not stuck.
- `latch init` comments out `branding.logo`; admin commands refuse a missing database; `init` refuses to run over an existing database.
- The argon2 timing test is skipped under the race detector, which triples hashing time.

## Not done here, deliberately

- **No way to register an application yet.** The admin plan delivers it. Until then, apps must be inserted into SQLite by hand.
- Admin UI, admin API, Authentik importer, Dockerfile, systemd unit, `/metrics`, cutover runbook: sibling plans.

## Carry into the admin plan

- Create invited members with `IsActive = true`; a reset link for an inactive account shows "expired".
- Record a `user.invite` audit event with the admin as actor; `SendReset` records the invitee.
- Clearing a member's TOTP must also delete their `totp_enrolments` rows.
- Cap per-application access, ID and refresh token lifetimes; access and ID at 24 hours.
- Validate `client_type` and `subject_mode` on input; an unknown subject mode silently becomes `id`.
- `store.DeleteOtherSessions` exists and can be reused for "sign out everywhere".

## Carry into the importer plan

- Store `users.email` byte-for-byte as Authentik's `user.email`, or email-mode `sub` values change.
- Seed `users.totp_last_step` from Authentik's `last_t`.
- Bound scrypt `p` (128·r·p), PBKDF2 output length and bcrypt cost in legacy hash parsing.
- An imported account on `pbkdf2_sha256` with 870,000 iterations verifies in about 0.8 s, which is distinguishable from the 0.1 s dummy hash until first sign-in.

## Small follow-ups

- Accept a config file containing only `---`; it currently fails with EOF.
- Give the hashing-slot wait a 10-second deadline so overload shows the throttled page instead of a proxy timeout.
- Add `MaxBytesReader` to form posts.
- Recover panics in the background jobs so one cannot crash `serve`.
- Revoked refresh tokens are pruned after 24 hours; after that, revoking with that stale token no longer ends the family.

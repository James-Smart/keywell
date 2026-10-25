# Latch Import and Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the makerspace from Authentik to Latch without anyone resetting a password or re-enrolling two-step sign in. To do that, add:
- a re-runnable `latch import-authentik` command;
- the operations pieces a real installation needs: `/metrics`, a Dockerfile, a compose example, a systemd unit, backups documentation and a cutover runbook.

**Architecture:**
- A new `internal/authentik` package reads Authentik 2026.8's Postgres into a plain `Snapshot`. It reads inside one read-only, repeatable-read transaction.
- A new `internal/importer` package maps a snapshot onto Latch inside one SQLite transaction. It uses the existing store methods through a transaction-bound `Store`. A dry run runs exactly the same code and rolls back, so its report is the real one.
- Imported applications pass the same validation as hand-made ones, through `admin.CheckApp`.
- Tests run against a real Authentik that `dev/authentik/` stands up and seeds.
- Metrics are served on a separate listener that is off by default.

**Tech Stack:**
- As before: Go 1.27.1, stdlib `net/http`, `modernc.org/sqlite`.
- One new dependency: `github.com/jackc/pgx/v5`. It is pure Go and used only to read Authentik's Postgres.
- The dev stack uses Docker Compose with `ghcr.io/goauthentik/server:2026.8.5` and `postgres:16-alpine`.
- The release image is built on `golang:1.27` and runs on `gcr.io/distroless/static-debian13:nonroot`.

**Spec:** `docs/superpowers/specs/2026-10-22-makerspace-idp-design.md`. The relevant sections are:
- §9: legacy hashes;
- §10: importer;
- §11: configuration and operations, `/metrics`, backups and deliverables;
- §13: importer development against a real Authentik.

Also read both decisions docs, `docs/superpowers/plans/2026-10-22-latch-core-decisions.md` and `docs/superpowers/plans/2026-10-23-latch-admin-decisions.md`. Their "Carry into the importer plan" items are requirements of this plan.

**Not in this plan:**
- Passkeys and webhooks.
- Any Authentik version other than 2026.8.
- The core decisions doc's remaining small follow-ups, and the admin plan's parked polish.
- **Sign-in timing.** A member imported on `pbkdf2_sha256` (1,000,000 iterations in 2026.8) takes about a second to check, until their first sign-in upgrades the hash. That timing tells an attacker the account exists. The core decisions doc records this as accepted, and it stays accepted.

## Verified Authentik 2026.8 schema

The spec warns that its §10 table and column names are from memory. The names below were checked against a running `ghcr.io/goauthentik/server:2026.8.4` on 2026-10-25. 2026.8.5 is a patch release of the same line. Where this section and spec §10 disagree, this section wins.

| What | Where it is in 2026.8 |
|---|---|
| Users | `authentik_core_user`: `id` (int pk), `uuid`, `username`, `name`, `email` (`''` when none), `password`, `is_active`, `attributes` (jsonb), `type` (`internal`, `external`, `service_account` or `internal_service_account`), `path`, `last_login`, `date_joined` |
| Groups | `authentik_core_group`: `group_uuid`, `name`, `attributes`, `is_superuser`. **There is no `parent_id`.** |
| Group parents | `authentik_core_groupparentage(child_id, parent_id)`. A group can have **several parents**. |
| Memberships | `authentik_core_user_groups(user_id → user.id, group_id → group.group_uuid)`. The spec's `authentik_core_user_ak_groups` does not exist. |
| Hashed user ID (`sub_mode = hashed_user_id`) | `sha256("<user.id>-<install_id>")` as lower-case hex. `install_id` comes from `SELECT id FROM authentik_install_id ORDER BY id LIMIT 1`. **It is not `SECRET_KEY`.** This was checked in Authentik's code (`User.uid` → `get_unique_identifier()` → `get_install_id()`) and against a value Authentik returned. |
| Default password hash | `pbkdf2_sha256$1000000$…`, the Django default. `argon2$argon2id$…` appears only on accounts hashed by older setups. |
| Applications | `authentik_core_application`: `policybindingmodel_ptr_id` (uuid, what bindings target), `name`, `slug` (may contain capitals and `_`), `meta_launch_url`, `meta_icon`, `meta_description`, `meta_hide`, `provider_id`. Joined to `authentik_policies_policybindingmodel(pbm_uuid, policy_engine_mode)`, where the mode is `any` or `all`. |
| Providers | `authentik_core_provider(id, name)`. OAuth2 providers are in `authentik_providers_oauth2_oauth2provider(provider_ptr_id, client_type, client_id, client_secret, sub_mode, access_token_validity, refresh_token_validity, _redirect_uris, grant_types)`. `client_secret` is plaintext. `grant_types` is `text[]`. |
| Redirect URIs | `_redirect_uris` is jsonb: a list of `{"url", "matching_mode": "strict" or "regex", "redirect_uri_type": "authorization" or "logout"}` |
| Durations | Text like `hours=1;minutes=30`. The keys are `microseconds`, `milliseconds`, `seconds`, `minutes`, `hours`, `days` and `weeks`, case-insensitive. Values are floats. Unknown keys are ignored. |
| Bindings | `authentik_policies_policybinding(target_id, group_id, user_id, policy_id, enabled, negate, order)` |
| TOTP | `authentik_stages_authenticator_totp_totpdevice(id, user_id, name, confirmed, key, step, t0, digits, last_t, created, last_used)`. `key` is hex. |
| Recovery codes | `authentik_stages_authenticator_static_staticdevice(id, user_id, confirmed)` and `authentik_stages_authenticator_static_statictoken(device_id, token)`. Tokens are plaintext and case-sensitive. They are 12 characters from `[A-Za-z0-9]` by default (the stage allows up to 100). Authentik deletes a token once it is used, so every row is unused. |
| Claim mappings | `authentik_core_provider_property_mappings(provider_id, propertymapping_id)` joined to `authentik_core_propertymapping(pm_uuid, name, managed)`. The built-in profile scope (`managed = 'goauthentik.io/providers/oauth2/scope-profile'`) sends `groups`. |
| Built-in rows | `AnonymousUser` (type `internal`, no email, `!` password) and `ak-outpost-…` (`internal_service_account`) exist on every install. So do the groups `authentik Admins` (superuser), `authentik Read-only` and `authentik Agent-Users`. |

## Rulings made while writing this plan

These depart from the spec or settle what it left open. Each says why, and what it costs if wrong.

1. **No `--secret-key`.**
   - Authentik 2026.8 hashes user IDs with the install ID, which the importer reads from the same database. Spec §10's `--secret-key` and `LATCH_AUTHENTIK_SECRET_KEY` are therefore not built.
   - `hashed_user_id` always maps to `authentik_uid`, computed for every member.
   - Cost if wrong: none for 2026.8. A multi-tenant Authentik (`tenants.enabled`) uses a tenant UUID instead, but the space doesn't run one.
2. **One transaction; the dry run is a rollback.**
   - The whole import, including the report, runs in one SQLite transaction. A dry run rolls it back, and so does an import with blocking problems.
   - A failure partway leaves Latch untouched.
   - Cost: a running `latch serve` waits for the write lock for the length of the import, which is well under the 5-second busy timeout for 120 members.
3. **Members who already use Latch keep their Latch credentials.** A member "uses Latch" when they have a native password hash, because they signed in or a password was set in Latch.
   - For these members, re-imports never touch the password, TOTP or recovery codes.
   - For everyone else, all three mirror Authentik on every run.
   - This extends the spec's "never clobber a native hash" rule to TOTP. Cost: a member who signs in to Latch during the parallel period and then re-enrols TOTP in Authentik keeps their older Latch TOTP.
4. **The importer manages only imported groups.**
   - It adds and removes memberships in groups that carry an `authentik_uuid`.
   - It never touches memberships of Latch-only groups. For example, the `Admin` group that `latch init` made keeps its members.
   - It never turns `is_admin` off on a group; it reports instead.
   - It sets `require_totp` to the Authentik group's `is_superuser` on every run.
   - Cost: an Authentik demotion has to be repeated by hand in Latch.
5. **Empty, unused groups are skipped and listed.** These are groups with no imported members (directly or through child groups) that no imported app uses. This keeps Authentik's built-in `authentik Read-only` and `authentik Agent-Users` out. Cost: an empty group James wanted must be re-created by hand.
6. **Access rules Latch can't express never widen access.**
   - These rules are:
     - a policy binding;
     - a user binding;
     - a negated binding;
     - `all` mode with two or more group bindings.
   - An app with any of them is imported open only to the imported admin groups, with a warning.
   - An app with no enabled bindings is open to every active member, as it was in Authentik.
   - Cost: such an app is admin-only until a volunteer picks its groups.
7. **Imported recovery codes keep Authentik's format.**
   - Each is stored as `secrets.HashToken(token)`, exactly as typed, case-sensitive.
   - The TOTP step accepts a code that isn't in Latch's `xxxxx-xxxxx` format when it is 7 to 100 letters and digits.
   - Cost: none. These codes only work for the member whose codes they are, under the existing TOTP limits.
8. **Metrics have their own listener.** `/metrics` is served only on `metrics.listen` (for example `127.0.0.1:9100`), which is off when empty, and never on the public listener. That way a reverse proxy can't expose it by accident. This is how the plan meets spec §11's "behind the trusted-proxy check or a config flag".
9. **Usernames stay unique by exact case.** The importer warns when two imported usernames differ only in case. It blocks only when an Authentik username exactly matches a different Latch account. Cost: no migration now. A future case-insensitive index would need those collisions fixed first.
10. **The dev stack is seeded through Authentik's own models.** It runs `ak shell` rather than the REST API, because the API can't set a TOTP key, static tokens or an argon2 hash. Cost: values the API would refuse could be seeded. The seed uses only realistic values.
11. **The importer writes one audit event per run**, `import.run` with actor type `importer`, after commit. Per-record detail is in the stored report.

## Global Constraints

- Everything in the earlier plans' Global Constraints still holds:
  - module `latch`, Go 1.27, no cgo, plain-language copy;
  - never log passwords, tokens, secrets or codes.
- **Nothing secret leaves the importer.** The importer never prints, logs or stores any of these:
  - a password hash;
  - a TOTP key;
  - a static token;
  - a client secret;
  - the password in the `--from` connection string.
- Reports, the `import_runs` table and error messages name the source as `host:port/dbname` (`authentik.Source`).
- **The importer only reads from Authentik.** It connects with `default_transaction_read_only=on` and reads everything in one `REPEATABLE READ READ ONLY` transaction.
- When a query fails, the error names the table it was reading (spec §10: "fail loudly with the table/column name").
- The importer supports only the Authentik 2026.8 schema in "Verified Authentik 2026.8 schema" above. There are no code paths for older layouts.
- **Inside the import transaction, use only the transaction's `Store`.** `db.Open` uses one connection, so any call on the outer `Store` inside `InTx` waits forever. The audit event is recorded after commit.
- **Report copy appears on the Settings page.** It follows the admin plan's rule: the words "provider", "flow", "stage" and "binding" never appear in it. Say "signs in with SAML", "an access rule" or "a policy" instead.
- **Overwrite rules (spec §10).** Authentik's values replace Latch's for every imported field on every run. The only exceptions are Rulings 3, 4, 6 and 7, and these two:
  - an app keeps its Latch service account;
  - an app keeps an uploaded `/icons/…` icon when Authentik has no usable icon.
- **Matching (spec §10):**
  - users on `authentik_uuid`, then email (case-insensitive);
  - groups on `authentik_uuid`, then exact name;
  - apps on `authentik_provider_pk`, then `client_id`.
  - Existing records are updated, never duplicated.
- **Email is stored exactly as Authentik has it.** `Alex.Smith@Example.org` stays in that case, so `sub` values in email mode do not change (core decisions).
- `go test ./...` stays hermetic and passes with no Docker running. Tests that need the dev stack skip unless `LATCH_TEST_AUTHENTIK_DSN` is set.

## Review Focus

These inputs are implied by the spec but no happy-path test exercises them. Each one is pinned by a test in the task named.

1. **Latch's own first admin also exists in Authentik**, with the same email in any case. They are matched, not duplicated. They keep:
   - their native password;
   - their Latch TOTP and recovery codes;
   - their membership of the Latch `Admin` group.

   They gain their Authentik groups and Authentik IDs. Pinned in Task 5 (groups) and Task 6 (credentials).
2. **Re-running after members have used Latch.**
   - The second run adds nothing.
   - Native hashes and Latch-enrolled TOTP stay as they are.
   - A member removed from an Authentik group loses only that membership.

   Pinned in Task 5 and Task 6.
3. **Authentik access rules Latch can't express** never open an app wider than Authentik did (Ruling 6). Pinned in Task 7.
4. **Conflicts stop the import, with nothing written, even without `--dry-run`.** The report names both records. The conflicts are:
   - two importable members whose emails differ only in case;
   - an Authentik member whose email, or exact username, belongs to a different Latch account;
   - a Latch group with the same name that is already linked to a different Authentik group.

   Pinned in Task 5.
5. **A failure partway, and a dry run, leave Latch exactly as it was.** No rows are added, changed or removed. Pinned in Task 5.

---

## Shared interfaces

Later tasks use these exact names. Task numbers say where each is defined.

```go
// internal/authentik (Task 2)
type Snapshot struct {
    InstallID    string            // authentik_install_id.id
    Users        []User            // every row of authentik_core_user
    Groups       []Group
    Memberships  []Membership      // direct memberships only
    Parents      []Parentage
    TOTPDevices  []TOTPDevice      // confirmed and unconfirmed
    StaticTokens []StaticToken     // tokens of confirmed static devices only
    Applications []Application
    Providers    []OAuth2Provider  // OAuth2/OpenID providers only
    Bindings     []Binding         // bindings whose target is an application
    Mappings     []ProviderMapping // claim mappings attached to OAuth2 providers
}
type User struct {
    PK                    int64
    UUID                  string
    Username, Name, Email string         // Email "" when Authentik has none
    Password              string         // Django hash, "!…" or ""
    IsActive              bool
    Type                  string         // internal | external | service_account | internal_service_account
    Attributes            map[string]any // never nil
    LastLogin             *time.Time
    DateJoined            time.Time
}
type Group struct {
    UUID, Name  string
    IsSuperuser bool
    Attributes  map[string]any // never nil
}
type Membership struct { UserPK int64; GroupUUID string }
type Parentage struct { ChildUUID, ParentUUID string }
type TOTPDevice struct {
    UserPK       int64
    Name, KeyHex string
    Confirmed    bool
    Step, Digits int
    T0, LastT    int64
    Created      time.Time
    LastUsed     *time.Time
}
type StaticToken struct { UserPK int64; Token string }
type Application struct {
    UUID                                     string // policybindingmodel_ptr_id
    Name, Slug, LaunchURL, Icon, Description string
    Hide                                     bool
    ProviderPK                               *int64 // nil: the application has none
    EngineMode                               string // "any" | "all"
}
type OAuth2Provider struct {
    PK                                        int64
    Name, ClientType, ClientID, ClientSecret  string
    SubMode                                   string
    AccessTokenValidity, RefreshTokenValidity string // e.g. "hours=1"
    RedirectURIs                              []RedirectURI
    GrantTypes                                []string
}
type RedirectURI struct{ URL, MatchingMode, Type string } // strict|regex; authorization|logout
type Binding struct {
    TargetUUID      string
    GroupUUID       string // "" unless a group binding
    UserPK          *int64 // nil unless a user binding
    PolicyUUID      string // "" unless a policy binding
    Enabled, Negate bool
}
type ProviderMapping struct{ ProviderPK int64; Name, Managed string } // Managed "" for one an admin wrote
const ManagedProfileScope = "goauthentik.io/providers/oauth2/scope-profile"

func Read(ctx context.Context, dsn string) (*Snapshot, error)
func Source(dsn string) string                      // "host:port/dbname"; never user or password
func ParseValidity(s string) (time.Duration, error) // Authentik duration text
func HashedUserID(pk int64, installID string) string // hex sha256 of "<pk>-<installID>"

// internal/store (Task 3)
func (s *Store) InTx(ctx context.Context, fn func(tx *Store) error) error
func (s *Store) AllUsers(ctx context.Context) ([]model.User, error) // members and service accounts, oldest first
func (s *Store) SetLegacyPassword(ctx context.Context, userID, hash string) (bool, error)
func (s *Store) ImportTOTP(ctx context.Context, userID string, secretEnc []byte, confirmedAt time.Time,
    lastStep int64, codeHashes []string) error
type ImportRun struct {
    ID                    string
    StartedAt, FinishedAt time.Time
    Source                string // authentik.Source(dsn)
    Report                string // importer.Report as JSON
}
func (s *Store) InsertImportRun(ctx context.Context, r *ImportRun) error
func (s *Store) LastImportRun(ctx context.Context) (*ImportRun, error) // ErrNotFound when none
// UpdateGroup also writes AuthentikUUID.

// internal/password (Task 4)
func CheckStored(encoded string) error // nil when Verify can check encoded; computes no hash

// internal/admin (Task 7)
func (s *Service) CheckApp(ctx context.Context, app *model.Application) error // *ValidationError when invalid
func SlugFromName(name string) string // the existing slugFromName, exported

// internal/importer (Tasks 5-8)
type Deps struct {
    Store *store.Store
    Enc   *secrets.Encryptor
    Cfg   *config.Config   // token lifetime caps
    Audit *audit.Recorder  // nil: no audit event
    Now   func() time.Time // nil: time.Now
}
type Options struct {
    DryRun   bool
    DropKeys []string // metadata keys to leave out besides "goauthentik.io/…"
    Source   string   // authentik.Source(dsn), for the report
}
var ErrBlocked = errors.New("importer: problems must be fixed before importing")
func Run(ctx context.Context, d Deps, snap *authentik.Snapshot, opts Options) (*Report, error)
type Report struct {
    Source                  string     `json:"source"`
    DryRun                  bool       `json:"dry_run"`
    StartedAt               time.Time  `json:"started_at"`
    FinishedAt              time.Time  `json:"finished_at"`
    Members                 Counts     `json:"members"`
    Groups                  Counts     `json:"groups"`
    Apps                    Counts     `json:"apps"`
    LeftOut                 int        `json:"left_out"`                   // service accounts and Authentik's own accounts
    KeptLatchCredentials    int        `json:"kept_latch_credentials"`     // Ruling 3
    NoPassword              int        `json:"no_password"`
    TOTP                    int        `json:"totp"`
    RecoveryCodes           int        `json:"recovery_codes"`
    MemberKeys              []KeyCount `json:"member_keys"`
    GroupKeys               []KeyCount `json:"group_keys"`
    Items                   []Item     `json:"items"`
    Blocking                []string   `json:"blocking"`
}
type Counts struct{ Added, Updated, Skipped int } // json: added, updated, skipped
type KeyCount struct{ Key string; Count int }     // json: key, count
type Item struct {
    Kind    string // "member", "group" or "app"
    Name    string // email for members (username when there is none); name otherwise
    Skipped bool   // false: imported, with a warning
    Reason  string // a full sentence
}
func (r *Report) WriteText(w io.Writer) error
func (r *Report) Summary() string

// internal/audit (Task 8)
const ImportRun = "import.run"

// internal/metrics (Task 9)
func New(version string) *Registry
func (m *Registry) CountRequest(status int)
func (m *Registry) ObserveAudit(e model.AuditEvent)
func (m *Registry) Handler() http.Handler
// audit: func (r *Recorder) WithObserver(f func(model.AuditEvent)) *Recorder
// config: Config.Metrics MetricsConfig{Listen string} (yaml metrics.listen, env LATCH_METRICS_LISTEN)
// web: Deps.Metrics *metrics.Registry (nil: requests are not counted)
```

## Dev stack fixture

Task 1 seeds these values. The reader test (Task 2) and the end-to-end test (Task 8) assert them. Passwords are set through Django's `make_password` with the hasher named.

**Groups**
- `Members`, with attributes `{"door": "yes", "goauthentik.io/internal": true}`.
- `Laser`, child of `Members`, with attributes `{"induction": "2024"}`.
- `Trustees`, child of `Members`, superuser.
- The built-in groups stay as Authentik made them.

**Members**

| Username | Email | Name | Type, state | Password (hasher) | Groups |
|---|---|---|---|---|---|
| `alex` | `Alex.Smith@Example.org` | Alex Smith | internal, active | `alex correct horse 1` (default pbkdf2_sha256) | Laser |
| `sam` | `sam@example.org` | Sam Jones | internal, active | `sam correct horse 2` (`argon2`) | Trustees |
| `jo` | `jo@example.org` | *(empty)* | internal, active | unusable (`set_unusable_password`) | Members |
| `pat` | `pat@example.org` | Pat Inactive | internal, **inactive** | `pat correct horse 3` (default) | Members |
| `kim` | `kim@example.org` | Kim External | **external**, active | `kim correct horse 4` (`scrypt`) | none |
| `nomail` | *(empty)* | No Mail | internal, active | `nomail correct horse 5` | Members |
| `door-bot` | *(empty)* | door-bot | **service_account** | none | none |

`alex` has these attributes: `{"member_number": 42, "goauthentik.io/user/sources": []}`. The bootstrap admin `akadmin` (email `akadmin@example.org`, group `authentik Admins`) also exists.

**Two-step**
- `alex` has two **confirmed** TOTP devices:
  - `Old phone`: key hex `3132333435363738393031323334353637383931`, `last_used` 2025-01-01T00:00:00Z;
  - `Phone`: key hex `3132333435363738393031323334353637383930` (the RFC 6238 SHA-1 test key, base32 `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`), `last_used` 2026-10-01T00:00:00Z, `last_t` 1000. Both have step 30, t0 0 and 6 digits.
- `alex` also has an **unconfirmed** device, `Tablet`.
- `alex` has a confirmed static device with tokens `RecoveryAAA1`, `RecoveryBBB2` and `RecoveryCCC3`.
- `pat` has one confirmed TOTP device, `Pat phone`, with 8 digits.

**Applications**

| Application | Slug | Its provider | Launch, icon | Access |
|---|---|---|---|---|
| Wiki | `wiki` | OAuth2 `wiki`: confidential, `client_id` `wiki-client-id`, secret `wiki-client-secret-0123456789`, `sub_mode` `hashed_user_id`, access `hours=2`, refresh `days=30`. Redirect URIs: strict authorization `https://wiki.example.org/index.php/Special:PluggableAuthLogin`, regex authorization `https://.*\.example\.org/cb`, strict logout `https://wiki.example.org/`. Claim mappings: the built-in openid, email and profile scopes, plus a custom scope mapping `Wiki extra claims` (scope `wiki`). | `https://wiki.example.org/`, icon `/media/public/application-icons/wiki.png`, description `The makerspace wiki` | group binding: Members |
| Door Booking | `Door_Booking` | OAuth2 `door-app`: public, `client_id` `door-app-client-id`, `sub_mode` `user_email`, access `minutes=5`, refresh `weeks=20`. Redirect: strict authorization `https://door.example.org/callback`. | `https://door.example.org/`, icon `https://door.example.org/icon.png` | none |
| Tool Booking | `tools` | OAuth2 `tools`: confidential, `client_id` `tools-client-id`, secret `tools-client-secret-0123456789`, `sub_mode` `user_uuid`, access `hours=36`, refresh `days=30`, `grant_types` `{authorization_code,client_credentials}`. Redirect: strict authorization `https://tools.example.org/oauth/callback`. | `https://tools.example.org/`, no icon | group binding: Laser; policy binding: expression policy `Weekdays only` (`return True`) |
| Grafana | `grafana` | SAML `grafana-saml`, ACS `https://grafana.example.org/saml/acs` | none | none |
| Printer | `printer` | none | none | none |

There is also an OAuth2 provider `orphan` with no application: confidential, `client_id` `orphan-client-id`, strict redirect `https://orphan.example.org/cb`.

---

### Task 1: Authentik dev stack and seed

**Files:**
- Create:
  - `dev/authentik/docker-compose.yml`
  - `dev/authentik/up.sh`
  - `dev/authentik/down.sh`
  - `dev/authentik/dsn.sh`
  - `dev/authentik/seed.py`
  - `dev/authentik/README.md`
- Modify: `.gitignore`, `Makefile`

**Interfaces:**
- Produces:
  - a seeded Authentik 2026.8.5 whose Postgres listens on `127.0.0.1:55432`;
  - `dev/authentik/dsn.sh`, which prints the DSN;
  - `make authentik-up`, `make authentik-down` and `make test-authentik`.

- [ ] **Step 1: Write the compose file.**
  - Start from Authentik's official `https://goauthentik.io/docker-compose.yml` and pin `AUTHENTIK_TAG` to `2026.8.5`.
  - Publish Postgres as `127.0.0.1:55432:5432`.
  - Publish Authentik's HTTP as `0.0.0.0:9700:9000`, so it can be opened from another machine on the LAN, and drop the 9443 mapping.
  - Give the worker no Docker socket mount and no `user: root`.
  - Name the compose project `latch-authentik-dev`.

- [ ] **Step 2: Write `up.sh`, `down.sh` and `dsn.sh` (POSIX sh, `set -eu`, runnable from any directory).**
  - `up.sh`, on first run, writes `dev/authentik/.env` with `PG_PASS` and `AUTHENTIK_SECRET_KEY` from `openssl rand -hex`, and `AUTHENTIK_BOOTSTRAP_PASSWORD`/`_EMAIL` (`akadmin@example.org`). Then it:
    - runs `docker compose up -d`;
    - waits, for up to 5 minutes, until the flow `default-provider-authorization-implicit-consent` exists (the worker creates it);
    - pipes `seed.py` into `docker compose exec -T server ak shell -c "$(cat seed.py)"`;
    - prints `export LATCH_TEST_AUTHENTIK_DSN=…`.
  - `down.sh` runs `docker compose down -v` and removes `data/`, `certs/` and `custom-templates/`. It keeps `.env`.
  - `dsn.sh` prints `postgres://authentik:$PG_PASS@127.0.0.1:55432/authentik?sslmode=disable` from `.env`.

- [ ] **Step 3: Write `seed.py`, which creates every row in "Dev stack fixture" with Authentik's Django models.**
  - Use `update_or_create` on natural keys, so running it twice changes nothing.
  - Set each password with `make_password(pw, hasher=…)` as the table says, or `set_unusable_password()`.
  - Set TOTP keys, `last_t`, `last_used` and static tokens directly on the device models.
  - Look up the default flows by slug.
  - End by printing one line per kind of object created.

- [ ] **Step 4: Ignore and wire up.**
  - `.gitignore` gains `dev/authentik/.env`, `dev/authentik/data/`, `dev/authentik/certs/` and `dev/authentik/custom-templates/`.
  - `Makefile` gains these targets:
    - `authentik-up` (runs `up.sh`);
    - `authentik-down` (runs `down.sh`);
    - `test-authentik`, which runs `LATCH_TEST_AUTHENTIK_DSN=$$(dev/authentik/dsn.sh) go test -count=1 -run Authentik ./internal/authentik ./internal/importer`.
  - `README.md` in `dev/authentik/` says what the stack is for, how to start, reseed (`make authentik-down authentik-up`) and stop it, and where Authentik's UI is: port 9700 on the machine's LAN address or on localhost, signing in as `akadmin` with the generated bootstrap password in `.env`.

- [ ] **Step 5: Verify.**
  - Run `make authentik-up`. It should end with the export line.
  - Then run these through `docker compose -p latch-authentik-dev exec -T postgresql psql -U authentik -d authentik -Atc`. Expected output:
    - `select username, type, is_active from authentik_core_user order by username` lists the seven fixture users plus `AnonymousUser`, `ak-outpost-…` and `akadmin`.
    - `select split_part(password,'$',1) from authentik_core_user where username in ('alex','sam','kim') order by username` prints `pbkdf2_sha256`, `scrypt`, `argon2` (in alex, kim, sam order).
    - `select count(*) from authentik_stages_authenticator_static_statictoken` prints `3`.
  - Run `up.sh` again: the seed reports nothing new and the counts are unchanged.

- [ ] **Step 6: Commit** with the message `dev: Authentik 2026.8 dev stack with a seeded fixture for importer tests`.

### Task 2: Read an Authentik database

**Files:**
- Create:
  - `internal/authentik/authentik.go`: the types, `Source`, `ParseValidity`, `HashedUserID`
  - `internal/authentik/read.go`
  - `internal/authentik/authentik_test.go`
  - `internal/authentik/read_test.go`
- Modify: `go.mod`, `go.sum` (`go get github.com/jackc/pgx/v5@latest`)

**Interfaces:**
- Consumes: the Task 1 stack, in tests only.
- Produces: everything listed under `internal/authentik` in Shared interfaces.

- [ ] **Step 1: Write failing unit tests in `authentik_test.go`.**
  - `TestParseValidity`, as a table:

    | Input | Result |
    |---|---|
    | `hours=1` | 1h |
    | `minutes=5` | 5m |
    | `days=30` | 720h |
    | `weeks=20` | 3360h |
    | `hours=1;minutes=30` | 90m |
    | `HOURS=2` | 2h |
    | `seconds=1.5` | 1.5s |
    | `hours=1;bogus=3` | 1h |
    | `""` | error |
    | `hours` | error |
    | `bogus=1` | error ("no valid keys") |
    | `hours=x` | error |
    | `hours=-1` | error |

  - `TestHashedUserID`: `HashedUserID(6, "c8b87056-95de-45d3-aed6-2c27cb4271ec")` is `9ddc5c9119d9167a4f7d5c6516bfaa6da909f0c1b69a107562f7951b1dac8051` (a value Authentik itself returned).
  - `TestSource`, as a table:

    | DSN | Result |
    |---|---|
    | `postgres://authentik:s3cret@db.internal:5432/authentik?sslmode=disable` | `db.internal:5432/authentik` |
    | `postgres://u:p@localhost/ak` | `localhost:5432/ak` |
    | `host=db user=u password=p dbname=ak` | `db:5432/ak` |
    | `::not a dsn::` | `an Authentik database` |

    No result contains a password.

- [ ] **Step 2: Run** `go test ./internal/authentik -run 'ParseValidity|HashedUserID|Source'`. Expected: FAIL (undefined).

- [ ] **Step 3: Implement the types and the three helpers in `authentik.go`.**
  - `ParseValidity` follows Authentik's `timedelta_from_string`, as the schema table describes. It also refuses a negative total.
  - `Source` uses `pgx.ParseConfig`.

- [ ] **Step 4: Write failing read tests in `read_test.go`.** They skip with `t.Skip("set LATCH_TEST_AUTHENTIK_DSN (make authentik-up) to run")` when the variable is empty.
  - `TestReadAuthentikFixture` reads the seeded stack and asserts:
    - `InstallID` is a UUID;
    - `alex` has email `Alex.Smith@Example.org`, a `pbkdf2_sha256$1000000$` password and `Attributes["member_number"] == float64(42)`;
    - `door-bot` has type `service_account`;
    - `Laser` has `Members` among its `Parents`;
    - `alex` has 3 TOTP devices, of which 2 are confirmed, and `Phone` has `KeyHex` `3132…3930`, `LastT` 1000 and a non-nil `LastUsed`;
    - `StaticTokens` holds exactly alex's three tokens;
    - Wiki's provider has 3 `RedirectURIs`, one of each `MatchingMode`/`Type` combination seeded, and `AccessTokenValidity` `hours=2`;
    - Tool Booking's bindings include one with a `GroupUUID` and one with a `PolicyUUID`;
    - Grafana has a `ProviderPK` but no matching entry in `Providers`;
    - Printer has a nil `ProviderPK`;
    - `orphan` is in `Providers`;
    - `Mappings` for Wiki's provider include `ManagedProfileScope` and one entry with `Managed == ""` named `Wiki extra claims`.
  - `TestReadAuthentikIsReadOnly`: the connection `Read` opens refuses `INSERT INTO authentik_core_group …`. Test this through an unexported `connect(ctx, dsn)` that `Read` uses.
  - `TestReadAuthentikErrorsHideThePassword`: `Read` with `postgres://authentik:hunter2-secret@127.0.0.1:1/authentik` returns an error whose text does not contain `hunter2-secret`. This test needs no stack, so it does not skip.

- [ ] **Step 5: Run** `make test-authentik` with the stack up, then `go test ./internal/authentik` without the variable set. Expected: FAIL, then the stack tests skip.

- [ ] **Step 6: Implement `Read` and `connect` in `read.go`.**
  - `connect` sets `RuntimeParams["default_transaction_read_only"] = "on"` and opens one `pgx.Conn`. `Read` then begins `pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}`.
  - Use one query per slice, with the table and column names from the schema table. Wrap each error as `fmt.Errorf("authentik: read %s: %w", table, err)`.
  - Rebuild any connect error from `Source(dsn)` and the driver's error, then check the password string is absent before returning it. If it is present, return only `authentik: connect to <source> failed`.
  - Decode jsonb into `map[string]any` and leave none nil.

- [ ] **Step 7: Run** `make test-authentik` and `go test ./internal/authentik`. Expected: PASS, and SKIP for the stack tests in the second run.

- [ ] **Step 8: Commit** with the message `feat(authentik): read an Authentik 2026.8 database into a snapshot`.

### Task 3: Store support for importing

**Files:**
- Create:
  - `internal/db/migrations/0005_import.sql`
  - `internal/store/import_runs.go`
  - `internal/store/tx_test.go`
  - `internal/store/import_runs_test.go`
- Modify:
  - `internal/store/store.go`
  - `internal/store/users.go`
  - `internal/store/groups.go`
  - `internal/store/apps.go`
  - `internal/store/totp_enrol.go`
  - `internal/store/users_test.go`
  - `internal/store/groups_admin_test.go`

**Interfaces:**
- Produces: everything listed under `internal/store` in Shared interfaces.

- [ ] **Step 1: Write failing tests.**
  - `TestInTxCommits`: users and groups created inside `InTx` are visible after it returns nil.
  - `TestInTxRollsBack`: `InTx` whose `fn` returns an error leaves none of these behind: a user, a group, an application with allowed groups (`CreateApplication` opens its own transaction), recovery codes (`ReplaceRecoveryCodes`) or a cleared TOTP (`ClearTOTP`). The error is returned unchanged (`errors.Is`).
  - `TestInTxMethodsUseTheTransaction`: inside `InTx` on a `db.Open` store, which has a single connection, under a 5-second `context.WithTimeout`, every method listed in Shared interfaces and `CreateApplication`, `UpdateApplication`, `ReplaceUserGroups` and `ClearTOTP` complete without timing out.
  - `TestSetLegacyPassword`: it sets the hash and returns true for a user with no native hash. It returns false and leaves the row alone for a user with a native hash, and returns false for an unknown ID.
  - `TestImportTOTP`: afterwards, `TOTPEnrolled()`, `TOTPConfirmedAt` and `CountUnusedRecoveryCodes` are 3, and `ClaimTOTPStep(…, lastStep)` returns false while `lastStep+1` returns true. A second `ImportTOTP` replaces the codes rather than adding to them.
  - `TestAllUsers`: it returns members and service accounts, oldest first.
  - `TestUpdateGroupWritesAuthentikUUID`.
  - `TestImportRuns`: `LastImportRun` returns `ErrNotFound` on an empty database, then returns the later of two inserted runs by `FinishedAt`, with every field round-tripped.

- [ ] **Step 2: Run** `go test ./internal/store`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `Store` holds a small `dbtx` interface (`ExecContext`, `QueryContext`, `QueryRowContext`) plus the `*sql.DB`, and records whether it is bound to a transaction.
  - A private `withTx(ctx, func(*sql.Tx) error) error` replaces the six `s.db.BeginTx` sites. In a bound store it runs inside the existing transaction; otherwise it begins and commits its own.
  - `InTx` on a bound store just calls `fn(s)`.
  - Migration `0005_import.sql` creates:

    ```sql
    CREATE TABLE import_runs (
        id TEXT PRIMARY KEY,
        started_at TEXT NOT NULL,
        finished_at TEXT NOT NULL,
        source TEXT NOT NULL,
        report TEXT NOT NULL
    );
    CREATE INDEX import_runs_finished_idx ON import_runs(finished_at);
    ```

  - `SetLegacyPassword` is one `UPDATE … WHERE id=? AND password_hash=''`.
  - `ImportTOTP` sets `totp_secret_enc`, `totp_confirmed_at` and `totp_last_step` and replaces the recovery codes, in one `withTx`.

- [ ] **Step 4: Run** `go test ./internal/store ./...`. Expected: PASS. The other packages are unaffected.

- [ ] **Step 5: Commit** with the message `feat(store): transactions spanning store calls, import runs, legacy password and TOTP import`.

### Task 4: Imported credentials verify safely

**Files:**
- Modify:
  - `internal/password/legacy.go`
  - `internal/password/password.go`
  - `internal/password/password_test.go`
  - `internal/web/totp.go`
  - `internal/web/totp_test.go`

**Interfaces:**
- Produces: `password.CheckStored`.
- Changes: the TOTP step and turning TOTP off (both go through `checkCode`) accept imported recovery codes (Ruling 7).

- [ ] **Step 1: Write failing tests.**
  - `TestCheckStored`:
    - nil for a native hash and for each supported Django format (reuse the vectors in `password_test.go`);
    - `ErrUnusable` for `""` and `"!abc"`;
    - `ErrUnsupported` for `md5$abc$def` and `bcrypt$2b$12$…`;
    - an error that is neither of those for `pbkdf2_sha256$abc$salt$hash`.
  - `TestLegacyCeilings`: each of these is refused by `CheckStored` and by `Verify` with a malformed error, and `Verify` returns in under 50 ms:
    - scrypt with N·r·p above `1<<22` (for example N=16384, r=8, p=64);
    - pbkdf2_sha256 whose decoded hash is longer than 64 bytes;
    - bcrypt_sha256 with cost 15.
  - `TestImportedRecoveryCode` (web): the member has TOTP and `ReplaceRecoveryCodes([HashToken("RecoveryAAA1")])`. At the TOTP step:
    - `RecoveryAAA1` signs them in;
    - `recoveryaaa1` is refused;
    - reusing `RecoveryAAA1` on a new sign-in is refused;
    - a Latch-format code and a current 6-digit code still work.

    Turning TOTP off on the account page also accepts an imported code.

- [ ] **Step 2: Run** `go test ./internal/password ./internal/web -run 'CheckStored|Ceilings|ImportedRecovery'`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - Split each legacy verifier into parse-and-check, then compute, so `CheckStored` and `Verify` share the parsing and the ceilings.
  - Add the ceilings:
    - `maxScryptWork = 1 << 22` for N·r·p, checked without overflow. It replaces the 128·N·r check, which it implies.
    - `maxPBKDF2Len = 64` bytes.
    - `maxBcryptCost = 14`, read with `bcrypt.Cost`.
  - In `checkCode`, add a second branch after the Latch-format one. When `strings.TrimSpace(code)` matches `^[A-Za-z0-9]{7,100}$`, consume `secrets.HashToken` of it, exactly as typed. Otherwise fall through to TOTP.

- [ ] **Step 4: Run** `go test ./internal/password ./internal/web`. Expected: PASS.

- [ ] **Step 5: Commit** with the message `feat: bound legacy hash costs, check stored hashes without hashing, accept imported recovery codes`.

### Task 5: Import members and groups

**Files:**
- Create:
  - `internal/importer/importer.go` (`Run`, `Deps`, `Options`, the transaction)
  - `internal/importer/report.go`
  - `internal/importer/groups.go`
  - `internal/importer/members.go`
  - `internal/importer/fixture_test.go`: snapshot builders, in `package importer` and exported, so `package importer_test` files can use them too
  - `internal/importer/members_test.go`
  - `internal/importer/report_test.go`

**Interfaces:**
- Consumes: `authentik.Snapshot` (Task 2); `store.InTx`, `AllUsers`, `SetLegacyPassword` and the `UpdateGroup` change (Task 3).
- Produces: `importer.Run`, `Deps`, `Options`, `ErrBlocked`, `Report`, `Counts`, `KeyCount`, `Item`, `WriteText` and `Summary`.
  - Members are created with their legacy hash set: either `CheckStored` passes or the hash is stored empty.
  - TOTP is left to Task 6 and applications to Task 7. Leave a call site for each in `Run`'s sequence, where they plug in.

- [ ] **Step 1: Write failing tests.** These use `storetest.OpenTest` and snapshots built in Go.
  - Tests that use `testenv` belong in `package importer_test`. `testenv` imports `web`, which imports `importer` once Task 8 is done, so an internal test that imports it would be an import cycle.
  - **`TestImportMembers`**:
    - Members are created with these values:
      - the exact email;
      - the name, or the username when the name is blank;
      - the username;
      - `IsActive`;
      - metadata with `goauthentik.io/…` keys and `Options.DropKeys` removed;
      - `AuthentikPK`, `AuthentikUUID` and `AuthentikUID = HashedUserID(pk, InstallID)`;
      - `CreatedAt = DateJoined`;
      - `LastLoginAt`.
    - These are left out, counted in `LeftOut` and not listed: types `service_account` and `internal_service_account`, and the user `AnonymousUser`.
    - A member with no email is skipped with the reason `Has no email address, which Latch needs to sign them in.`
    - `Report.Members` counts them.
  - **`TestImportGroupsAndMemberships`**:
    - A member of a grandchild group is also made a member of its parent and its grandparent.
    - A group with two parents gets both.
    - A parent cycle (A→B→A) terminates.
    - `is_superuser` sets `IsAdmin` and `RequireTOTP`.
    - A group with no members and no app using it is skipped with the reason `Has no members and no app uses it.`
    - A Latch group with the same name and no Authentik ID is adopted: it is matched and gains `AuthentikUUID`.
  - **`TestImportIsIdempotent`**:
    - The second `Run` on the same snapshot reports 0 added and every record updated. Row counts in `users`, `groups`, `memberships` and `applications` are unchanged.
    - When the snapshot drops a membership, only that membership goes.
    - When the snapshot renames a group, the Latch group is renamed rather than a new one added.
  - **`TestImportKeepsLatchOnlyState`** (Review Focus 1 and 2):
    - The Latch admin, in the `Admin` group (no Authentik ID), also appears in the snapshot with the same email in upper case. They are matched, not added. They are still in `Admin`, and they gain their Authentik groups.
    - An imported group the snapshot no longer marks `is_superuser` keeps `IsAdmin`, with the warning `Isn't an admin group in Authentik any more. Latch leaves admin access on; untick it on the group's page if that's right.`
    - A previously imported member missing from the snapshot is left alone, with the warning `Is no longer in Authentik. Latch has left them as they are.`
  - **`TestImportDisablesAndSignsOut`**: a member who has a session and a refresh token in Latch and is inactive in the snapshot ends up disabled, with both gone.
  - **`TestImportBlocksConflicts`** (Review Focus 4). `Run` returns `ErrBlocked` and a report whose `Blocking` names both records, and every table's row count is unchanged. Each case is separate, each also with `DryRun: false`:
    - two snapshot members `a@x.org` and `A@X.org`;
    - a snapshot member matched by UUID whose email belongs to another Latch account;
    - a snapshot username exactly equal to a different Latch account's;
    - a snapshot group whose name matches a Latch group linked to a different `authentik_uuid`.

    Separately, two usernames that differ only in case give a warning, not a block.
  - **`TestDryRunWritesNothing`** (Review Focus 5): a dry run returns the same report, apart from `DryRun`, as the real run that follows it. Before the real run, every table's row count and every `updated_at` are unchanged.
  - **`TestFailurePartwayLeavesNothing`** (Review Focus 5): the unexported hook `testHookAfterMembers func() error`, set from an internal test, returns an error. `Run` returns it and the database is unchanged.
  - **`TestReportText`** (`report_test.go`): `WriteText` for a fixed report prints the exact text below, and a blocked report starts with `Nothing was imported from …`. `Summary()` is `6 members added, 0 updated, 1 skipped; 4 groups added, 0 updated, 2 skipped; 3 apps added, 0 updated, 3 skipped`.

    ```
    Dry run of an import from db.internal:5432/authentik. Nothing was saved.
    Members: 6 added, 0 updated, 1 skipped
    Groups: 4 added, 0 updated, 2 skipped
    Apps: 3 added, 0 updated, 3 skipped
    Left out 3 service accounts and Authentik's own accounts.
    Two-step sign in carried over for 1 member, with 3 recovery codes.
    1 member has no usable password and will need a reset link.

    Metadata apps will see for members:
      member_number (1 member)
    Metadata apps will see for groups:
      door (1 group)
      induction (1 group)

    Skipped:
      member nomail: Has no email address, which Latch needs to sign them in.
    Warnings:
      app Wiki: Return address https://.*\.example\.org/cb is a pattern. Add the real addresses on the app's page.
    ```

    Sentence lines whose count is 0 are left out. The three count lines always print. A real run starts `Imported from <source>.` and a blocked one `Nothing was imported from <source>. Fix these first:` followed by the `Blocking` lines.

- [ ] **Step 2: Run** `go test ./internal/importer`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - **`Run`:**
    - It sets `StartedAt`, then does everything inside `d.Store.InTx`, on the transaction's store only:
      - load Latch's users, groups and applications;
      - plan the members and groups;
      - collect blocking problems, and if there are any, return the sentinel that rolls back;
      - write the groups;
      - write the members;
      - write the memberships;
      - write credentials (Task 6);
      - write applications (Task 7);
      - unless `DryRun`, insert the import run.
    - `DryRun` rolls back with a private sentinel. `Run` maps that sentinel to a nil error.
    - After commit, and only for a real run, it records the audit event (Task 8 adds the event).
  - **Members:**
    - Match on UUID, then email.
    - Overwrite the name, email, username, `IsActive`, metadata and Authentik IDs.
    - Set `LastLoginAt` through `TouchLastLogin` only when Authentik's is later.
    - On an active-to-inactive change, call `DeleteSessionsForUser` and `RevokeRefreshTokensForUser`.
    - A username containing whitespace is imported without the username, with a warning.
  - **Groups:**
    - Match on UUID, then name.
    - Flatten ancestors with a visited set.
    - Apply Rulings 4 and 5.
    - Membership changes touch only groups that have an `AuthentikUUID`.
  - **Metadata keys:** count the top-level keys left after filtering, per member and per group, sorted by key.
  - **Ordering:** the report lists Items in snapshot order within each kind, members first, then groups, then apps.

- [ ] **Step 4: Run** `go test ./internal/importer ./...`. Expected: PASS.

- [ ] **Step 5: Commit** with the message `feat(importer): import Authentik members, groups and memberships in one transaction`.

### Task 6: Import passwords, two-step and recovery codes

**Files:**
- Create:
  - `internal/importer/credentials.go`
  - `internal/importer/credentials_test.go`
- Modify: `internal/importer/importer.go` (plug in at the credentials call site)

**Interfaces:**
- Consumes:
  - `store.SetLegacyPassword` and `store.ImportTOTP`, plus the existing `ClearTOTP` (Task 3);
  - `password.CheckStored` (Task 4);
  - `totp.SecretFromHex`;
  - `secrets.HashToken`;
  - `Deps.Enc.Seal`.
- Produces: `Report.TOTP`, `RecoveryCodes`, `NoPassword` and `KeptLatchCredentials`.

- [ ] **Step 1: Write failing tests.**
  - **`TestImportPasswords`**:
    - A pbkdf2_sha256 hash is stored as the legacy hash. So is an argon2 hash.
    - `"!x"` is stored as `""` and counted in `NoPassword`.
    - `md5$…` is stored as `""`, counted, and warned with `Has a password Latch can't check. They'll need a reset link.`
    - A member who already has a native hash keeps it and their legacy hash stays empty. This includes the Latch admin from Task 5's test (Review Focus 1).
  - **`TestImportedMemberSignsIn`**: an imported member whose legacy hash is the Django test vector `pbkdf2_sha256$870000$…` (reuse the one in `password_test.go`) signs in through `testenv` with its password. Afterwards their `PasswordHash` is native and `LegacyPasswordHash` is empty.
  - **`TestImportTOTP`**:
    - The confirmed device with the latest `LastUsed` wins. A device with a nil `LastUsed` sorts last. Ties go to the latest `Created`.
    - Two confirmed devices give the warning `Had 2 authenticator apps in Authentik. Latch kept the one used most recently ("Phone").`
    - Unconfirmed devices are ignored.
    - The sealed secret opens to `totp.SecretFromHex(KeyHex)`.
    - `totp_last_step` is `LastT`, so `ClaimTOTPStep(LastT)` is false.
    - `TOTPConfirmedAt` is the device's `Created`.
    - Recovery codes are the user's static tokens, hashed with `secrets.HashToken`.
    - `Report.TOTP` and `RecoveryCodes` count them.
  - **`TestImportTOTPUnsupported`**: a device with 8 digits, step 60 or a non-zero t0 is not imported, with the warning `Used a kind of two-step code Latch doesn't support. They'll set up two-step sign in again.` A bad hex key gets the same warning.
  - **`TestImportTOTPMirrorsAuthentik`**: a member without a native hash who has TOTP in Latch, but no confirmed device in the snapshot, has it cleared.
  - **`TestImportKeepsLatchCredentials`** (Ruling 3, Review Focus 2): a member with a native hash, their own Latch TOTP and recovery codes keeps all three, whatever the snapshot says. `KeptLatchCredentials` counts them.

- [ ] **Step 2: Run** `go test ./internal/importer -run 'Passwords|SignsIn|TOTP|LatchCredentials'`. Expected: FAIL.

- [ ] **Step 3: Implement `importCredentials(ctx, tx, …)`, applied to each imported member after the memberships are written.**
  - Skip members with a native hash entirely, and count them.
  - Otherwise, set the legacy hash, or `""` when `CheckStored` refuses it.
  - Choose the TOTP device among the confirmed devices with step 30, t0 0 and 6 digits. When there are none, warn if some confirmed device exists, then clear any Latch TOTP.
  - Import with `ImportTOTP`.
  - Keep recovery codes only with an imported TOTP.

- [ ] **Step 4: Run** `go test ./internal/importer ./...`. Expected: PASS.

- [ ] **Step 5: Commit** with the message `feat(importer): carry over legacy passwords, TOTP devices and recovery codes`.

### Task 7: Import applications

**Files:**
- Create:
  - `internal/importer/apps.go`
  - `internal/importer/access.go`
  - `internal/importer/apps_test.go`
- Modify:
  - `internal/admin/apps.go` (add `CheckApp`; export `SlugFromName`)
  - `internal/admin/apps_test.go`
  - `internal/importer/importer.go`

**Interfaces:**
- Consumes: `authentik.ParseValidity`, `authentik.ManagedProfileScope`, `admin.New(admin.Deps{Cfg, Store: tx})`, `admin.CheckApp`, `admin.SlugFromName`.
- Produces: `Report.Apps` and the app items.

- [ ] **Step 1: Write failing tests.**
  - **`TestCheckApp`** (admin):
    - It returns nil for a valid app and tidies it in place, as `validateApp` does.
    - It returns a `*ValidationError` with a `slug` field for a slug taken by another app.
    - An app's own slug is not "taken" when `app.ID` is set.
  - **`TestImportApps`**, using a snapshot built from the Dev stack fixture's application rows. Expected results:
    - **Wiki:**
      - confidential, with `ClientID` `wiki-client-id`;
      - `ClientSecretHash` equal to `secrets.HashToken("wiki-client-secret-0123456789")`;
      - `SubjectMode` `authentik_uid`;
      - `RedirectURIs` holding only the strict authorization address, and `PostLogoutRedirectURIs` `["https://wiki.example.org/"]`;
      - access and ID TTL 2h, refresh 720h;
      - `LaunchURL` set, `ShowTile` true, `IconURL` `""`;
      - `AllowedGroupIDs` set to Members.
    - **Wiki's warnings:**
      - `Return address https://.*\.example\.org/cb is a pattern. Add the real addresses on the app's page.`
      - `Its icon is stored in Authentik. Upload it on the app's page.`
      - `Authentik sent extra details through "Wiki extra claims", which Latch doesn't send.`
      - `Authentik sent group names to it with "profile". Latch sends them only when an app asks for "groups", so add groups to its scopes if it uses them.`
    - **Door Booking:**
      - slug `door-booking`, with the warning `Its short name changed from Door_Booking to door-booking.`;
      - public, with `ClientSecretHash` `""`;
      - `SubjectMode` `email`;
      - access 5m;
      - refresh capped at `Cfg.Tokens.RefreshAbsolute`, with the warning `Authentik kept sign-ins for 3360h; Latch's limit is 2160h, so it uses that.`;
      - icon kept;
      - `AllowedGroupIDs` empty.
    - **Tool Booking:**
      - `SubjectMode` `authentik_uuid`;
      - access capped at 24h, with a warning of the same form;
      - `AllowedGroupIDs` set to the imported admin groups, with the warning `Authentik limited who could use it with a policy. Only admins can use it until you choose its groups on the app's page.`;
      - also the warning `Authentik let it sign in by itself. To allow that in Latch, choose a service account on the app's page.`
    - **Skipped:**
      - Grafana: `Signs in with something other than OpenID Connect, which is all Latch supports.`
      - Printer: `Has nothing to sign in with in Authentik.`
      - `orphan`, listed under its own name: `Isn't used by any application in Authentik.`
  - **`TestImportAppAccess`** (Review Focus 3), as a table over each app's bindings:

    | Bindings | Allowed groups and warning |
    |---|---|
    | none | open, no warning |
    | only disabled ones | open |
    | one group | that group |
    | two groups, mode `any` | both |
    | two groups, mode `all` | admin groups, warning "with several groups that all had to match" |
    | negated group | admin groups, warning "with a rule that left people out" |
    | user binding | admin groups, warning "with a named person" |
    | policy | admin groups, warning "with a policy" |

    In no case is an app open to a member who couldn't use it in Authentik.
  - **`TestImportAppsUpdate`**:
    - A second run updates rather than adds.
    - An app matched by `client_id` gains `AuthentikProviderPK`.
    - A Latch-set `ServiceAccountID` survives.
    - An uploaded `/icons/x.png` survives when Authentik has no usable icon.
    - An app that fails `CheckApp` is skipped with its field messages joined by spaces. For example, a 21st strict redirect gives `Add at most 20 addresses.`

- [ ] **Step 2: Run** `go test ./internal/admin ./internal/importer -run 'CheckApp|Apps|AppAccess'`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - **`CheckApp`** wraps `validateApp(ctx, p, app, app.ID)` and `p.err()`.
  - **Map each Authentik application whose provider is in `Snapshot.Providers`:**
    - the slug through `SlugFromName`;
    - redirect URIs by type: strict ones kept, patterns warned;
    - subject modes by the spec §6.4 table. `user_upn` becomes `email` with the warning `Identified people by UPN in Authentik. Latch uses their email address instead.`;
    - lifetimes through `ParseValidity`, capped to [1m, 24h] for access and ID (ID = access) and [1m, `RefreshAbsolute`] for refresh. A value that won't parse becomes 0 (the default), with a warning.
  - **Launch URL and tile:**
    - The launch URL is kept only if it is an absolute http(s) address. `blank://blank` silently means none.
    - `ShowTile = LaunchURL != "" && !Hide`.
  - **Icon:** kept only if it is `https://`. Otherwise keep an existing `/icons/` icon; failing that, warn.
  - **Access:** decided in `access.go` per Ruling 6.
  - **Validate and write:** match per Global Constraints, run `CheckApp`, then call `CreateApplication` or `UpdateApplication` on the transaction's store.

- [ ] **Step 4: Run** `go test ./internal/admin ./internal/importer ./...`. Expected: PASS.

- [ ] **Step 5: Commit** with the message `feat(importer): import OpenID Connect apps through the admin checks, never widening access`.

### Task 8: The import command, import status and end-to-end tests

**Files:**
- Create:
  - `cmd/latch/import.go`
  - `cmd/latch/import_test.go`
  - `internal/importer/authentik_test.go` (stack-gated end-to-end)
- Modify:
  - `cmd/latch/main.go` (usage, command table)
  - `internal/audit/audit.go`
  - `internal/importer/importer.go` (audit after commit)
  - `internal/web/admin_settings.go`
  - `internal/web/templates/admin_settings.html`
  - `internal/web/admin_test.go`, or the existing settings test file
  - `README.md` (Commands table, Status)

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `latch import-authentik --from DSN [--dry-run] [--drop-key KEY]... [--config PATH]`;
  - `audit.ImportRun`;
  - the Settings section "Import from Authentik".

- [ ] **Step 1: Write failing tests.**
  - **`TestImportCommand`** (`cmd/latch`). The command reads through a package variable `readAuthentik = authentik.Read`, which the test replaces, so no Postgres is needed.
    - On an `initInstall` installation, `--dry-run` prints the report to stdout, exits 0 and stores no `import_runs` row.
    - A real run exits 0, stores one row, and records one `import.run` audit event with actor type `importer` and summary `Imported from Authentik: <Summary()>`.
    - A blocked snapshot exits 1 and prints the Blocking lines.
    - Leaving out `--from` exits 2 with `latch import-authentik: --from is required`.
    - `--drop-key member_number --drop-key door` removes both keys.
    - Neither stdout, stderr nor the stored report contains `s3cret`, the password in the `--from` DSN the test passes.
  - **`TestSettingsImportStatus`**:
    - With no run, the Settings page says `Nothing has been imported from Authentik yet.`
    - After `InsertImportRun`, it shows the run's date and source, the three count lines from the report, and a `<details>` listing each skipped item and warning.
  - **`TestImportAuthentikEndToEnd`** (stack-gated, `internal/importer/authentik_test.go`). It reads the Dev stack fixture and runs the import into a `testenv` installation. Then it checks:
    - **The report:**
      - Members 6 added and 1 skipped (`nomail`), `LeftOut` 3;
      - Groups 4 added and 2 skipped;
      - Apps 3 added and 3 skipped;
      - `NoPassword` 1 (`jo`), `TOTP` 1, `RecoveryCodes` 3.
    - **A sign-in through the browser flow:**
      - `alex` signs in with `alex correct horse 1` and a code computed from `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` at the test clock;
      - he completes Wiki's authorization-code flow with secret `wiki-client-secret-0123456789`;
      - the ID token's `sub` is `authentik.HashedUserID(alexPK, snap.InstallID)`;
      - his stored hash is now native.
    - **Other members and the re-run:**
      - `sam`'s argon2 password and `kim`'s scrypt password sign them in;
      - `RecoveryBBB2` works at `alex`'s TOTP step;
      - a second `Run` adds nothing.

- [ ] **Step 2: Run** `go test ./cmd/latch ./internal/web -run 'ImportCommand|ImportStatus'` and `make test-authentik`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - **The command** loads the install (`openInstall`), builds the encryptor and `audit.New(st, cliLogger(stderr))`, reads the snapshot, runs, and prints `WriteText` to stdout.
    - It exits 1 on `ErrBlocked` or any error, which goes through `fail`.
    - `--drop-key` is a repeatable `flag.Value`.
    - The usage line in `main.go` is `import-authentik  copy members, groups and apps from an Authentik database`.
  - **The Settings section** comes after Signing keys and is headed `Import from Authentik`.
    - It decodes `LastImportRun().Report` into `importer.Report`.
    - It says when the import ran and from where, then shows the three count lines.
    - Then a `<details>` with the summary `What was skipped or needs a look (N)` lists the items as `<li>` elements. The page shows a red "skipped" or plain "warning" label beside each item.
  - **README** gains the command in the Commands table. Its Status says the importer is done and points to `docs/cutover.md`.

- [ ] **Step 4: Run** `go test ./...` and `make test-authentik`. Expected: PASS.

- [ ] **Step 5: Commit** with the message `feat: latch import-authentik, import status on Settings, end-to-end import test against Authentik`.

### Task 9: Metrics

**Files:**
- Create:
  - `internal/metrics/metrics.go`
  - `internal/metrics/metrics_test.go`
- Modify:
  - `internal/config/config.go`
  - `internal/config/example.yaml`
  - `latch.example.yaml` (keep the copy identical)
  - `internal/config/config_test.go`
  - `internal/audit/audit.go`
  - `internal/web/server.go` and `internal/web/middleware.go` (`Deps.Metrics`, counted in `requestLog`)
  - `cmd/latch/main.go` (second listener)
  - `cmd/latch/jobs_test.go`
  - `README.md` (Metrics section)

**Interfaces:**
- Produces: `internal/metrics` as in Shared interfaces, `Recorder.WithObserver`, `config.MetricsConfig`, `web.Deps.Metrics`.

- [ ] **Step 1: Write failing tests.**
  - **`TestMetricsText`**. A fresh `New("v1")` serves the text below, with `Content-Type: text/plain; version=0.0.4; charset=utf-8`. Every series is present from the start at 0, in this order.

    ```
    # HELP latch_build_info The running version of Latch.
    # TYPE latch_build_info gauge
    latch_build_info{version="v1"} 1
    # HELP latch_http_requests_total Requests answered, by status class.
    # TYPE latch_http_requests_total counter
    latch_http_requests_total{code="1xx"} 0
    latch_http_requests_total{code="2xx"} 0
    latch_http_requests_total{code="3xx"} 0
    latch_http_requests_total{code="4xx"} 0
    latch_http_requests_total{code="5xx"} 0
    # HELP latch_logins_total Sign-ins, by result.
    # TYPE latch_logins_total counter
    latch_logins_total{result="success"} 0
    latch_logins_total{result="failure"} 0
    latch_logins_total{result="second_step_failure"} 0
    # HELP latch_tokens_issued_total Tokens issued to apps, by grant.
    # TYPE latch_tokens_issued_total counter
    latch_tokens_issued_total{grant="authorization_code"} 0
    latch_tokens_issued_total{grant="refresh_token"} 0
    latch_tokens_issued_total{grant="client_credentials"} 0
    ```

  - **`TestObserveAudit`**:
    - `login.success` counts as a success, except when `Detail["second_factor"] == "pending"`, which counts nothing.
    - `login.failure` counts as a failure, and `login.totp_failure` as `second_step_failure`.
    - `oidc.token.issued` counts under `Detail["grant"]`. An unknown grant counts nothing.
    - Other actions count nothing.
    - `CountRequest(302)` raises `3xx`. A status of 0 counts as `2xx`.
  - **Config tests:**
    - `metrics.listen` defaults to `""` and `LATCH_METRICS_LISTEN` sets it.
    - `127.0.0.1:9100` and `:9100` are valid.
    - `localhost` and `127.0.0.1:x` are refused with `metrics.listen must be host:port, got …`.
  - **`TestServeMetricsListener`** (`cmd/latch`). With `metrics.listen` on a free local port:
    - `GET /metrics` there answers 200 with `latch_build_info`;
    - a sign-in failure against the main listener raises `latch_logins_total{result="failure"}` to 1;
    - `GET /metrics` on the main listener is 404, or the member home redirect, never the metrics;
    - when `metrics.listen` is empty, nothing extra listens.

- [ ] **Step 2: Run** `go test ./internal/metrics ./internal/config ./cmd/latch -run 'Metrics|ObserveAudit|ServeMetrics'`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - **Counters:** use `sync/atomic` and hand-written exposition text. Do not add a Prometheus dependency.
  - **`WithObserver`:** `Record` calls the observer after the insert attempt, whether or not the insert succeeded.
  - **`serve`:**
    - It builds the registry with `Version` and attaches it to the recorder and to `web.Deps`.
    - When `cfg.Metrics.Listen != ""`, it starts a second `http.Server` whose mux serves only `GET /metrics`, with the same timeouts.
    - It shuts that server down alongside the main one, and a listen failure on it fails `serve`.
  - **`example.yaml`** gets this entry:

    ```yaml
    metrics:
      listen: ""                                # host:port to serve Prometheus metrics at /metrics, e.g. 127.0.0.1:9100; empty = off
    ```

  - **README** gains a Metrics section: the setting, the four metric families, and why the metrics listener is separate (Ruling 8).

- [ ] **Step 4: Run** `go test ./...`. Expected: PASS.

- [ ] **Step 5: Commit** with the message `feat: Prometheus metrics on an optional separate listener`.

### Task 10: Dockerfile, compose example, systemd unit, backups

**Files:**
- Create:
  - `Dockerfile`
  - `.dockerignore`
  - `deploy/docker-compose.yml`
  - `deploy/latch.service`
- Modify: `Makefile` (`docker` target), `README.md`

**Interfaces:**
- Produces: the `latch:<version>` image and the files above.

- [ ] **Step 1: Write the `Dockerfile`.**
  - The build stage is `golang:1.27`. It runs `go mod download` with only `go.mod` and `go.sum` copied, then builds with `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}"`, where `ARG VERSION=dev`. It also makes an empty `/out/data`.
  - The runtime stage is `gcr.io/distroless/static-debian13:nonroot`. If that tag doesn't exist, use `static-debian12:nonroot` and say so in the report. It holds `/latch` and the empty directory copied to `/var/lib/latch` with `--chown=65532:65532`.
  - It declares `VOLUME /var/lib/latch` and `EXPOSE 8080`, with `ENTRYPOINT ["/latch"]` and `CMD ["serve", "--config", "/var/lib/latch/latch.yaml"]`.
  - `.dockerignore` excludes:
    - `.git`
    - `.claude`
    - `.superpowers`
    - `dev-data`
    - `dev/authentik/.env`
    - `dev/authentik/data`
    - `/latch`
    - `*.db`

- [ ] **Step 2: Write `deploy/docker-compose.yml`.**
  - One `latch` service with `build: ..` and `image: latch:local`, `restart: unless-stopped`.
  - Ports `127.0.0.1:8080:8080`, the named volume `latch-data:/var/lib/latch`, and `environment: LATCH_TRUSTED_PROXIES: "172.16.0.0/12"`.
  - Comments say how to set SMTP and other settings through `LATCH_…` variables, since the image has no shell for editing the config.

- [ ] **Step 3: Write `deploy/latch.service`.**
  - `User=latch`, `Group=latch`, `ExecStart=/usr/local/bin/latch serve --config /etc/latch/latch.yaml`, `Restart=on-failure`.
  - `StateDirectory=latch` with `StateDirectoryMode=0750`.
  - Hardening:
    - `NoNewPrivileges`
    - `ProtectSystem=strict`
    - `ProtectHome`
    - `PrivateTmp`
    - `PrivateDevices`
    - `ProtectKernelTunables`
    - `ProtectKernelModules`
    - `ProtectControlGroups`
    - `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`
    - `RestrictNamespaces`
    - `LockPersonality`
    - `MemoryDenyWriteExecute`
    - `RestrictRealtime`
    - `SystemCallArchitectures=native`
    - an empty `CapabilityBoundingSet=`
  - `WantedBy=multi-user.target`.

- [ ] **Step 4: Add to `README.md` a section "Running Latch for real", with three parts.**
  - **Docker:** `docker compose -f deploy/docker-compose.yml build`, then:

    ```sh
    docker compose -f deploy/docker-compose.yml run --rm latch init --config /var/lib/latch/latch.yaml \
      --data-dir /var/lib/latch --public-url https://login.example.org --admin-email you@example.org
    ```

    Then `up -d`.
  - **systemd:**
    - create the `latch` system user;
    - install the binary from `make build`;
    - run `sudo latch init --config /etc/latch/latch.yaml --data-dir /var/lib/latch …`;
    - `chown root:latch` the config, with mode `0640`;
    - `chown -R latch:latch /var/lib/latch`;
    - enable the unit.
  - **Backups:**
    - `sqlite3 /var/lib/latch/latch.db ".backup '/backups/latch.db'"` while Latch runs. For Docker, use a throwaway `alpine` container with the volume mounted read-write and `apk add sqlite`. Or stop Latch and copy `latch.db`.
    - Back up `data_dir/icons` too (admin decisions), and the config file. Its `encryption_key` is needed to read two-step secrets and signing keys in any backup.

  Add a `docker` target to `Makefile` that runs `docker build --build-arg VERSION=$(VERSION) -t latch:$(VERSION) .`.

- [ ] **Step 5: Verify.**
  - `make docker` succeeds. Then:
    - `docker run --rm latch:<v> version` prints `latch <v>`.
    - `docker image inspect -f '{{.Config.User}}' latch:<v>` prints `65532` or `nonroot`.
    - The README's Docker steps work end to end, with `--public-url http://localhost:8080` and a scratch compose project name. `curl -s http://127.0.0.1:8080/healthz` answers `{"status":"ok",…}`. Clean up the project and its volume afterwards.
  - `systemd-analyze verify deploy/latch.service` reports nothing except, at most, the missing `/usr/local/bin/latch`.
  - Report the image size.

- [ ] **Step 6: Commit** with the message `ops: Dockerfile, compose example, systemd unit, production and backup docs`.

### Task 11: Cutover runbook

**Files:**
- Create: `docs/cutover.md`
- Modify: `README.md` (link it from Status and the Commands row)

**Interfaces:**
- Consumes: the command, report wording and Settings section (Task 8), and the deploy files (Task 10).

- [ ] **Step 1: Write `docs/cutover.md`.** It is plain-language, for the volunteer doing the move, and uses numbered steps under these headings, in order:
  1. **What changes for members.** The login page looks different and nothing else does: passwords and authenticator apps carry over. Members flagged "no usable password" get a reset link.
  2. **A week before.**
     - Install Latch on its own hostname (README "Running Latch for real").
     - Take a copy of Authentik's database with `docker compose exec -T postgresql pg_dump -U authentik -d authentik -Fc > authentik.dump`, run from Authentik's directory.
     - Restore the copy into a throwaway Postgres, e.g. `docker run -d --name ak-copy -e POSTGRES_PASSWORD=… -p 127.0.0.1:55433:5432 postgres:16-alpine`, then `pg_restore`.
     - Run `latch import-authentik --dry-run --from postgres://postgres@127.0.0.1:55433/authentik`, with the password in `PGPASSWORD` rather than in the address.
     - A direct connection to the live database also works, read-only, but needs its port published. Say so as the alternative.
  3. **Reading the report.** One short entry per skipped item and warning reason from Tasks 5 to 7, each saying what to do: in Authentik before the final import, or on the Latch page afterwards. It covers:
     - the `--drop-key` advice for metadata that apps shouldn't see;
     - the "Must fix first" list;
     - the `groups` scope note for apps that read group names.
  4. **Until the switch.**
     - Make changes in Authentik, not Latch. Each import replaces Latch's copy of imported members, groups and apps (spec §10).
     - Don't rotate app secrets in Latch.
     - Re-run the dry run whenever you like.
  5. **Switch day.**
     - Announce a short window and stop changes in Authentik.
     - Take a fresh dump and restore it.
     - Run the import without `--dry-run`.
     - Check Settings → Import from Authentik.
     - **MediaWiki:**
       - set `providerURL` to Latch's issuer;
       - either turn on the OpenID Connect extension's migrate-by-email option, or update the issuer stored in its `openid_connect` table during the window;
       - give the exact setting and table names after checking the extension's current documentation at mediawiki.org, and quote the doc version checked;
       - add `groups` to its scopes if it maps groups.
     - **Each custom app:** issuer, discovery URL (`<public_url>/.well-known/openid-configuration`), JWKS URL and the same client ID and secret. Its user IDs (`sub`) don't change, because the importer kept each app's subject mode.
     - Sign in to each app once to check it.
     - Turn Authentik off, keeping its last dump.
  6. **If something goes wrong.**
     - Point the apps back at Authentik, which still has everything. Members who changed their password in Latch since the switch use their old one there.
     - Re-importing is safe at any time.
  7. **A few weeks later.**
     - Turn off migrate-by-email.
     - Once an app no longer depends on Authentik user IDs, consider switching its subject mode to Latch's own IDs (the warning triangle on the app page).
     - Delete the throwaway Postgres and the dumps.

- [ ] **Step 2: Check it.** Every command in the runbook either runs against the dev stack, with addresses swapped, or is quoted from the README. Every report reason quoted matches the code exactly: `grep` each one in `internal/importer`. Fix any drift.

- [ ] **Step 3: Commit** with the message `docs: Authentik to Latch cutover runbook`.

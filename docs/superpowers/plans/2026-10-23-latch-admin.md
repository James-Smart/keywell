# Latch Admin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give volunteers a web admin area for members, groups, applications, service accounts, settings and the audit log, and give automation a bearer-token REST API over the same operations, so nobody has to touch SQLite to run Latch.

**Architecture:** A new `internal/admin` package is the only place admin writes happen. It validates input, writes through `store`, sends emails through the web server's existing `SendReset`, and records one audit event per change. The admin pages are handlers and templates in `internal/web`, so they share the branded `Renderer`. The REST API is a new `internal/api` package. Both sit thinly over `admin` and read straight from `store`. `web.New` builds the admin service and mounts the API at `/api/`, outside the session middleware.

**Tech Stack:** As the core plan: Go 1.27.1, stdlib `net/http` and `html/template`, `modernc.org/sqlite`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-22-makerspace-idp-design.md`. The relevant sections are:
- §4: ApiToken and service accounts.
- §6.4: how the subject mode is shown.
- §6.5: the machine-to-machine toggle.
- §7: admin UI.
- §8: admin REST API.

Also read `docs/superpowers/plans/2026-10-22-latch-core-decisions.md`. Its "Carry into the admin plan" items are requirements of this plan.

**Not in this plan:**
- **Import status on Settings.** The importer plan adds it, together with its `import_runs` table.
- **Operations files.** `/metrics`, the Dockerfile, the systemd unit and the cutover runbook belong to the importer plan.
- **Small follow-ups.** Of the core decisions doc's small follow-ups, only request body limits are done here (Task 6).

## Global Constraints

- Everything in the core plan's Global Constraints still holds:
  - module `latch`, Go 1.27, no cgo;
  - never log passwords, tokens, secrets or codes;
  - plain-language copy;
  - the words "provider", "flow", "stage" and "binding" never appear in UI copy. Code snippets an admin pastes verbatim, such as MediaWiki's `providerURL`, are exempt.
- Admin pages live under `/admin`. The sidebar lists, in this order: Members, Groups, Applications, Service accounts, Settings, Audit log (§7).
- Admin access needs both of these, checked on every request (§7):
  - a complete session, meaning the second step has passed whenever a group requires it (`session.RequireUser` already enforces this);
  - membership of any group with `is_admin`.
- Admin pages work without JavaScript, like the member pages. Confirmations are inline `<details>` disclosures, not dialogs.
- Destructive buttons are red and confirm (§7):
  - deleting a member confirms by typing their email;
  - deleting a group, application or service account confirms by typing its name.
- The members list shows members only (`type = member`), 50 per page, with search over name, email and username (§7).
- Deleting the last `is_admin` group is refused (§7). Removing `is_admin` from it is refused too, because it causes the same lockout.
- Invite links last 7 days (`web.InviteTokenTTL`). Reset links last 1 hour (`web.ResetTokenTTL`).
- Client secrets and API tokens are shown once, in the response to the request that made them. They are stored only as `secrets.HashToken(...)` (§4, §8).
- Per-application token lifetimes (core decisions). Empty means the global default.
  - Access and ID tokens: 1 minute to 24 hours.
  - Refresh tokens: 1 minute to `tokens.refresh_absolute`.
- Admin API rules (§8):
  - base path `/api/v1`, authenticated with `Authorization: Bearer <token>`;
  - JSON in and out; errors are `{"error": "code", "message": "human text"}`;
  - `read` tokens get 403 on anything but `GET`;
  - 600 requests per minute per token;
  - an OpenAPI 3 document at `/api/v1/openapi.json`;
  - no bootstrap token in config.
- Every admin write records an audit event, with the acting admin or service account as the actor. API writes have `actor_type = service_account` and the token's ID in `detail.token_id` (§8).
- All admin writes go through `internal/admin`. Handlers in `web` and `api` may read through `store` directly but never write through it.

## Review Focus

These are inputs the spec implies but no happy-path test covers. Each one has a pinned test in the task that owns the code.

1. **An email that differs only in case** from an existing one (`ALEX@example.org` when `alex@example.org` exists) gets the field message "Another member already uses that email address.", never a 500. Pinned in Task 3 and Task 7.
2. **Bad metadata.** Metadata text that is valid JSON but not an object (`[1,2]`, `"x"`, `null`, `42`), or not JSON at all, gets a field message. Nothing is saved, and the form keeps what was typed. Pinned in Task 3 and Task 7.
3. **An admin locking themselves, or everyone, out.** Each of these gets a plain refusal, and nothing changes. Pinned in Tasks 3, 4, 7 and 8.
   - unticking their own last admin group;
   - disabling or deleting their own account;
   - deleting the last admin group, or removing admin access from it.
4. **API calls that must fail cleanly** get a JSON 401 or 403 in the error shape, never HTML and never a 500. Pinned in Task 13.
   - a token that is expired or revoked;
   - a token whose service account was deleted;
   - a `read` token on a write.
5. **Messy return addresses.** Redirect URI text with CRLF line endings, blank lines, surrounding spaces or duplicates is cleaned up: trimmed, blanks dropped, duplicates removed. A relative address, an address with a `#fragment`, or a `javascript:` address gets a field message naming the line. Pinned in Task 5 and Task 9.

---

## Shared interfaces

Later tasks use these exact names. Task numbers say where each is defined.

```go
// internal/model (Task 1)
type UserStatus string // derived, never stored
const (
    UserStatusActive        UserStatus = "active"
    UserStatusInvited       UserStatus = "invited"        // no password, an unused unexpired invite link exists
    UserStatusNeedsPassword UserStatus = "needs_password" // no password, no such link
    UserStatusDisabled      UserStatus = "disabled"       // !IsActive, whatever else is true
)
// User gains: Description string  // service accounts; "" for members

type APITokenScope string
const (
    APITokenScopeAdmin APITokenScope = "admin"
    APITokenScopeRead  APITokenScope = "read"
)
type APIToken struct {
    ID, ServiceAccountID, Label string
    TokenHash       string // secrets.HashToken(raw)
    Scope           APITokenScope
    CreatedByUserID string // the admin or service account that made it
    CreatedAt       time.Time
    LastUsedAt      *time.Time
    ExpiresAt       *time.Time // nil = never
}

// internal/store (Tasks 1-2)
var ErrLastAdminGroup = errors.New("store: last admin group")
type UserFilter struct {
    Type    model.UserType // "" = members and service accounts
    Query   string         // case-insensitive substring of name, email or username
    Status  string         // "", "active", "invited", "needs_password", "disabled", "no_2fa", "admins"
    GroupID string         // only members of this group
    Page    int            // 1-based; < 1 means 1
    PerPage int            // 0 means 50; capped at 500
}
type UserRow struct {
    model.User
    Status        model.UserStatus
    Groups        []model.Group // ordered by name
    IsAdmin       bool          // in any group with IsAdmin
    TokenCount    int           // API tokens it holds (service accounts)
    TokenLastUsed *time.Time    // latest LastUsedAt among them
}
type UserPage struct{ Rows []UserRow; Total, Page, PerPage int }
func (s *Store) ListUsers(ctx context.Context, f UserFilter) (UserPage, error)
func (s *Store) GetUserStatus(ctx context.Context, u *model.User) (model.UserStatus, error)
func (s *Store) DeleteUser(ctx context.Context, id string) error // ErrNotFound
func (s *Store) CreateAPIToken(ctx context.Context, t *model.APIToken) error // fills ID, CreatedAt
func (s *Store) ListAPITokens(ctx context.Context, serviceAccountID string) ([]model.APIToken, error) // newest first
func (s *Store) GetAPITokenByHash(ctx context.Context, tokenHash string) (*model.APIToken, error)
func (s *Store) TouchAPIToken(ctx context.Context, id string, at time.Time) error
func (s *Store) DeleteAPIToken(ctx context.Context, serviceAccountID, id string) error // ErrNotFound unless it is that account's
type GroupRow struct{ model.Group; MemberCount int }
func (s *Store) ListGroupsWithCounts(ctx context.Context) ([]GroupRow, error)
func (s *Store) UpdateGroup(ctx context.Context, g *model.Group) error // ErrNotFound, ErrConflict, ErrLastAdminGroup
func (s *Store) DeleteGroup(ctx context.Context, id string) error      // ErrNotFound, ErrLastAdminGroup
func (s *Store) ReplaceUserGroups(ctx context.Context, userID string, groupIDs []string) error
func (s *Store) DeleteApplication(ctx context.Context, id string) error // ErrNotFound
type AuditFilter struct {
    Since, Until          time.Time // zero = unbounded; Since inclusive, Until exclusive
    ActorID, TargetID     string    // exact
    Actions               []string  // action prefixes, OR-ed: "user." matches user.create, "logout" matches logout
    Query                 string    // case-insensitive substring of summary
    CollapseLoginFailures bool      // one row per target and clock hour for login.failure, with Count
    Page, PerPage         int       // as UserFilter
}
type AuditRow struct{ model.AuditEvent; Count int } // Count is 1 except for collapsed rows
type AuditPage struct{ Rows []AuditRow; Total, Page, PerPage int }
func (s *Store) ListAuditEvents(ctx context.Context, f AuditFilter) (AuditPage, error)

// internal/audit (Task 3): action names added beside the existing ones
UserCreate = "user.create"; UserInvite = "user.invite"; UserUpdate = "user.update"
UserDisable = "user.disable"; UserEnable = "user.enable"; UserDelete = "user.delete"
UserPasswordSet = "user.password.set"; UserResetSent = "user.password.reset_sent"
UserTOTPClear = "user.totp.clear"; UserSessionsRevoke = "user.sessions.revoke"
GroupCreate = "group.create"; GroupUpdate = "group.update"; GroupDelete = "group.delete"
GroupMemberAdd = "group.member.add"; GroupMemberRemove = "group.member.remove"
AppCreate = "app.create"; AppUpdate = "app.update"; AppDelete = "app.delete"; AppSecretRotate = "app.secret.rotate"
ServiceAccountCreate = "service_account.create"; ServiceAccountUpdate = "service_account.update"
ServiceAccountDelete = "service_account.delete"
APITokenCreate = "api_token.create"; APITokenRevoke = "api_token.revoke"
SMTPTest = "settings.smtp_test"
```

**Audit event conventions:**
- `target_type` is one of `user`, `group`, `application`, `service_account`, `api_token`, `signing_key`.
- `group.member.*` events target the user, with `detail.group_id` and `detail.group_name`.
- Update events carry `detail.changed`, which maps each changed field to `{"from": old, "to": new}`. The exception is `metadata`, which maps to `{}` so its values are never copied into the log.
- Delete events copy the identifying fields of the target into `detail` (email and name; slug and client_id), because the row is gone.
- `summary` is a sentence naming the target, for example "Added Alex Rivera to Laser".

```go
// internal/admin (Tasks 3-5)
type Notifier interface { // satisfied by *web.Server
    SendReset(ctx context.Context, user *model.User, purpose model.ResetPurpose) error
}
type Keys interface { // satisfied by *oidc.KeyManager
    RotateAs(ctx context.Context, actorType model.ActorType, actorID string) (newKID string, err error)
    RetireOlderThan(ctx context.Context, d time.Duration) (int, error)
    ActiveKID() string
}
type Deps struct {
    Cfg          *config.Config
    Store        *store.Store
    Audit        *audit.Recorder
    Mailer       mail.Mailer
    Notifier     Notifier
    Keys         Keys
    HashPassword func(ctx context.Context, pw string) (string, error) // nil = password.HashCtx
    Now          func() time.Time                                     // nil = time.Now
}
type Service struct{ /* d Deps */ }
func New(d Deps) *Service

type Actor struct {
    Type    model.ActorType // model.ActorUser (an admin in the UI) or model.ActorServiceAccount (an API token)
    ID      string
    TokenID string // the API token used; recorded as detail["token_id"] when set
}
type ValidationError struct{ Fields map[string]string } // field name -> message shown beside it
type RefusedError struct{ Message string }             // cannot be done as asked; Message is shown as is
type EmailError struct{ Err error }                    // the change was made, its email was not sent
var ErrBadToken = errors.New("admin: unknown, expired or revoked API token")
// Missing records: errors.Is(err, store.ErrNotFound). Methods that take a member, service account,
// group or app ID return store.ErrNotFound when the ID is of the wrong kind.
const KeyRetireAfter = 90 * 24 * time.Hour
func ParseMetadata(raw string) (map[string]any, *ValidationError) // "" -> {}; must be a JSON object of at most 8192 bytes

type NewMember struct {
    Name, Email, Username string
    GroupIDs []string
    Metadata map[string]any // nil = {}
    Invite   bool           // email an invitation
    Password string         // used when !Invite; "" leaves the member Needs password
}
type MemberPatch struct { // nil fields are left alone
    Name, Email, Username *string
    GroupIDs *[]string
    Metadata *map[string]any
    IsActive *bool
}
func (s *Service) CreateMember(ctx context.Context, a Actor, in NewMember) (*model.User, error) // invite failure: the user AND *EmailError
func (s *Service) UpdateMember(ctx context.Context, a Actor, id string, p MemberPatch) (*model.User, error)
func (s *Service) DeleteMember(ctx context.Context, a Actor, id string) error
func (s *Service) SendPasswordEmail(ctx context.Context, a Actor, id string) (model.ResetPurpose, error) // invite if no password, else reset
func (s *Service) SetMemberPassword(ctx context.Context, a Actor, id, password string) error
func (s *Service) ClearMemberTOTP(ctx context.Context, a Actor, id string) error
func (s *Service) SignOutEverywhere(ctx context.Context, a Actor, id string) error
func (s *Service) ResolveMember(ctx context.Context, ref string) (*model.User, error) // ID or "email:<address>"
func (s *Service) ResolveGroups(ctx context.Context, refs []string) ([]string, error) // names or IDs -> IDs

type GroupInput struct { Name, Description string; IsAdmin, RequireTOTP bool; Metadata map[string]any }
type GroupPatch struct { Name, Description *string; IsAdmin, RequireTOTP *bool; Metadata *map[string]any }
func (s *Service) CreateGroup(ctx context.Context, a Actor, in GroupInput) (*model.Group, error)
func (s *Service) UpdateGroup(ctx context.Context, a Actor, id string, p GroupPatch) (*model.Group, error)
func (s *Service) DeleteGroup(ctx context.Context, a Actor, id string) error
func (s *Service) AddToGroup(ctx context.Context, a Actor, userID, groupID string) error      // members and service accounts
func (s *Service) RemoveFromGroup(ctx context.Context, a Actor, userID, groupID string) error
func (s *Service) ResolveGroup(ctx context.Context, ref string) (*model.Group, error) // ID or "name:<name>"

type ServiceAccountInput struct { Name, Username, Description string; GroupIDs []string; Metadata map[string]any }
type ServiceAccountPatch struct { Name, Username, Description *string; GroupIDs *[]string; Metadata *map[string]any }
func (s *Service) CreateServiceAccount(ctx context.Context, a Actor, in ServiceAccountInput) (*model.User, error)
func (s *Service) UpdateServiceAccount(ctx context.Context, a Actor, id string, p ServiceAccountPatch) (*model.User, error)
func (s *Service) DeleteServiceAccount(ctx context.Context, a Actor, id string) error
func (s *Service) ResolveServiceAccount(ctx context.Context, ref string) (*model.User, error) // ID or "username:<name>"
type NewToken struct { Label string; Scope model.APITokenScope; ExpiresAt *time.Time }
func (s *Service) CreateToken(ctx context.Context, a Actor, serviceAccountID string, in NewToken) (*model.APIToken, string, error) // raw token once
func (s *Service) RevokeToken(ctx context.Context, a Actor, serviceAccountID, tokenID string) error
type Caller struct { Account *model.User; Token *model.APIToken }
func (c *Caller) Actor() Actor // {ActorServiceAccount, Account.ID, Token.ID}
func (s *Service) AuthenticateToken(ctx context.Context, raw string) (*Caller, error) // ErrBadToken

type AppInput struct {
    Name, Slug                           string // Slug "" = made from Name
    ClientType                           model.ClientType
    RedirectURIs, PostLogoutRedirectURIs []string
    AllowedGroupIDs                      []string
    SubjectMode                          model.SubjectMode // "" = id
    AccessTokenTTL, IDTokenTTL, RefreshTokenTTL time.Duration // 0 = global default
    LaunchURL, IconURL, Description      string
    ShowTile                             bool
    ServiceAccountID                     string // "" = no machine-to-machine sign-in
}
type AppPatch struct { /* every AppInput field as a pointer; nil = unchanged */ }
func (s *Service) CreateApp(ctx context.Context, a Actor, in AppInput) (app *model.Application, secret string, err error)       // secret "" for public apps
func (s *Service) UpdateApp(ctx context.Context, a Actor, id string, p AppPatch) (app *model.Application, secret string, err error) // secret set only when it became confidential
func (s *Service) DeleteApp(ctx context.Context, a Actor, id string) error
func (s *Service) RotateAppSecret(ctx context.Context, a Actor, id string) (string, error)
func (s *Service) ResolveApp(ctx context.Context, ref string) (*model.Application, error) // ID or "slug:<slug>"

func (s *Service) SendTestEmail(ctx context.Context, a Actor, to *model.User) error
func (s *Service) RotateKeys(ctx context.Context, a Actor) (newKID string, retired int, err error) // RotateAs, then RetireOlderThan(KeyRetireAfter)
```

```go
// internal/web (Task 6)
type Page struct {
    Title         string
    Error, Notice string
    Data          any
    Section       string // admin sidebar entry: "members", "groups", "apps", "service-accounts", "settings", "audit"; "" on member pages
}
// Deps gains: Keys admin.Keys  // *oidc.KeyManager, for Settings
// Template funcs: ago(*time.Time) string, date(time.Time) string, datetime(time.Time) string, prettyJSON(map[string]any) string

// internal/api (Task 13)
type Deps struct {
    Admin *admin.Service
    Store *store.Store
    Log   *slog.Logger
    Now   func() time.Time // nil = time.Now; also the rate limiter's clock
}
func New(d Deps) http.Handler // serves every path under /api/

// internal/testenv (Tasks 6, 10, 13)
func (e *Env) AdminClient(t *testing.T) (*http.Client, *model.User) // admin@example.org in group "Admin" (IsAdmin, no second step), signed in
func (e *Env) Page(t *testing.T, c *http.Client, path string) (*http.Response, string)                    // GET; body closed, returned as text
func (e *Env) Submit(t *testing.T, c *http.Client, path string, form url.Values) (*http.Response, string) // POST form
func (e *Env) SubmitMultipart(t *testing.T, c *http.Client, path string, form url.Values, file, filename string, content []byte) (*http.Response, string)
func (e *Env) APIToken(t *testing.T, username string, scope model.APITokenScope) (raw string, account *model.User)
func (e *Env) API(t *testing.T, token, method, path string, body any) (map[string]any, *http.Response) // body JSON-encoded unless nil; result nil when empty
```

**API JSON.** Times are RFC 3339 UTC, and unset times are `null`. Lifetimes are whole seconds, with `null` meaning the global default. Groups appear as names on output and are accepted as names or IDs on input.

| Kind | Fields |
|---|---|
| user | `id, email, username, name, status, is_active, is_admin, groups, metadata, totp_enrolled, imported_from_authentik, last_login_at, created_at, updated_at` |
| group | `id, name, description, is_admin, require_totp, metadata, member_count, created_at, updated_at` |
| app | `id, name, slug, client_id, client_type, redirect_uris, post_logout_redirect_uris, allowed_groups, subject_mode, access_token_ttl, id_token_ttl, refresh_token_ttl, launch_url, icon_url, description, show_tile, service_account_id, created_at, updated_at`; plus `client_secret` only in the response that made it |
| service account | `id, name, username, description, groups, metadata, token_count, last_used_at, created_at, updated_at` |
| token | `id, label, scope, created_by, created_at, last_used_at, expires_at`; plus `token` only in the create response |
| audit event | `id, at, actor_type, actor_id, action, target_type, target_id, summary, detail` |
| list | `{"items": [...], "page": 1, "per_page": 50, "total": 123}`. `per_page` defaults to 50, maximum 200. |

**API errors:**

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_json` | the body is not a JSON object of the documented fields (unknown fields are refused) |
| 401 | `unauthorized` | the token is missing, unknown, expired or revoked; also sends `WWW-Authenticate: Bearer` |
| 403 | `forbidden` | a `read` token on a non-GET request |
| 404 | `not_found` | no such route or record |
| 409 | `refused` | `*admin.RefusedError`; `message` is its Message |
| 413 | `too_large` | the body is over 1 MiB |
| 422 | `invalid` | `*admin.ValidationError`; adds `"fields": {field: message}` |
| 429 | `rate_limited` | over 600 requests per minute; also sends `Retry-After: 60` |
| 502 | `email_failed` | the reset email could not be sent |
| 500 | `internal` | anything else; logged, with a generic message |

---

### Task 1: Schema, model, member listing and API tokens in the store

**Files:**
- Create: `internal/db/migrations/0004_admin.sql`, `internal/store/users_list.go`, `internal/store/users_list_test.go`, `internal/store/api_tokens.go`, `internal/store/api_tokens_test.go`
- Modify: `internal/model/model.go`, `internal/store/users.go` (description column, `DeleteUser`, `ClearTOTP`), `internal/store/users_test.go`, `internal/store/totp_enrol_test.go`, `internal/db/db_test.go` (expected migration list gains `0004_admin.sql`)

**Interfaces:**
- Consumes: the existing store helpers (`formatTime`, `parseNullTime`, `wrapWrite`, `oneRow`, `scanUser`).
- Produces:
  - model `UserStatus`, `APIToken`, `APITokenScope` and `User.Description`;
  - store `ListUsers`, `GetUserStatus`, `DeleteUser` and the API-token methods (Shared interfaces);
  - `ClearTOTP` also deletes the `totp_enrolments` rows of the user's sessions, in the same transaction (core decisions carry-forward).

Migration, exactly:

```sql
ALTER TABLE users ADD COLUMN description TEXT NOT NULL DEFAULT '';

CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    service_account_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL CHECK (scope IN ('admin','read')),
    created_by_user_id TEXT NOT NULL DEFAULT '', -- no foreign key: the token outlives its creator
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    expires_at TEXT
);
CREATE INDEX api_tokens_account_idx ON api_tokens(service_account_id);
CREATE INDEX audit_events_actor_idx ON audit_events(actor_id);
CREATE INDEX audit_events_target_idx ON audit_events(target_id);
```

One SQL `CASE` expression computes the status for both `ListUsers` and `GetUserStatus`, checking in this order:
1. `disabled` when `is_active = 0`.
2. `active` for every service account.
3. For members with neither password hash: `invited` when an unused, unexpired invite token exists, else `needs_password`.
4. `active` otherwise.

The two extra status filters are:
- `no_2fa`: `totp_confirmed_at IS NULL`.
- `admins`: a member of a group with `is_admin`.

The search uses `LIKE … ESCAPE '\'`, with `\`, `%` and `_` in the query escaped. Rows are ordered by `name COLLATE NOCASE, email COLLATE NOCASE, id`. Groups for the returned rows are loaded in one query.

- [ ] **Step 1: Tests**

```go
// users_test.go
func TestUserDescriptionRoundTrip(t)   // service user Description "Door controller" survives CreateUser/GetUser; UpdateUser changes it
func TestDeleteUserCascades(t)         // user with membership, session, refresh token, reset token, recovery code; service account with a token and an app naming it:
                                       // after DeleteUser rows are gone, the app's ServiceAccountID is "", audit_events untouched; second call ErrNotFound
// totp_enrol_test.go
func TestClearTOTPDeletesEnrolments(t) // PutTOTPEnrolment on the user's session; ClearTOTP; GetTOTPEnrolment -> ErrNotFound
// users_list_test.go
func TestListUsersStatus(t)            // active (password); invited (no password, invite expiring tomorrow); needs_password (no password, invite expired yesterday);
                                       // disabled (has password, IsActive false); service account -> "active"
func TestGetUserStatusMatchesList(t)   // same five users, GetUserStatus equals each row's Status
func TestListUsersFilters(t)           // Type member excludes the service account; each Status value; "no_2fa" excludes an enrolled member;
                                       // "admins" only members of an IsAdmin group; GroupID
func TestListUsersQuery(t)             // "ALEX" matches name "Alex Rivera", email "alex@example.org" and username "alexr" (3 users);
                                       // "50%" matches "50% Club" not "500 Club"; "a_b" matches "a_b" not "axb"
func TestListUsersPaging(t)            // 120 members: PerPage 0 -> 50 rows, Total 120, PerPage 50; Page 3 -> 20 rows; Page 9 -> 0 rows, Total 120;
                                       // first row by case-insensitive name; PerPage 1000 -> PerPage 500
func TestListUsersGroupsAndTokens(t)   // row.Groups names sorted; IsAdmin set for a member of an admin group;
                                       // service account with 2 tokens (one used yesterday, one an hour ago) -> TokenCount 2, TokenLastUsed an hour ago
// api_tokens_test.go
func TestAPITokenLifecycle(t)          // Create fills ID, CreatedAt; GetAPITokenByHash returns it (Scope, Label, CreatedByUserID, ExpiresAt);
                                       // TouchAPIToken sets LastUsedAt; ListAPITokens newest first;
                                       // DeleteAPIToken(otherAccount, id) -> ErrNotFound and the token remains; DeleteAPIToken(owner, id) -> gone
func TestAPITokenHashUnique(t)         // second token with the same hash -> ErrConflict
```

- [ ] **Step 2: Run** `go test ./internal/store/ ./internal/db/` and expect it to FAIL with undefined `ListUsers`, `APIToken` and the like.
- [ ] **Step 3: Implement** the migration, the model additions, `users_list.go` (`ListUsers`, `GetUserStatus`), `api_tokens.go`, and in `users.go`: `description` in `userCols`/`CreateUser`/`UpdateUser`, `DeleteUser`, and `ClearTOTP` deleting enrolments.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(store): member listing with derived status, API tokens, user description`

---

### Task 2: Store: groups, application delete, audit queries

**Files:**
- Create: `internal/store/groups_admin_test.go`, `internal/store/audit_test.go`
- Modify: `internal/store/groups.go`, `internal/store/apps.go`, `internal/store/audit.go`, `internal/store/apps_test.go`

**Interfaces:**
- Consumes: Task 1.
- Produces: `ListGroupsWithCounts`, `UpdateGroup`, `DeleteGroup`, `ReplaceUserGroups`, `DeleteApplication`, `ListAuditEvents` and `ErrLastAdminGroup` (Shared interfaces).

Both last-admin-group guards are single statements, so two admins acting at once cannot both get through:
- **Delete:** `DELETE FROM groups WHERE id=? AND (is_admin=0 OR (SELECT COUNT(*) FROM groups WHERE is_admin=1) > 1)`.
- **Update:** the `UPDATE` carries the same condition whenever it would set `is_admin = 0`.

When no row changes, the store reads the row back. It returns `ErrNotFound` if the row is gone and `ErrLastAdminGroup` if it is still there.

`ReplaceUserGroups` runs in one transaction. An unknown group ID fails the foreign key, and the previous memberships stay.

`ListAuditEvents` with `CollapseLoginFailures` returns, newest first, the union of:
- the non-`login.failure` rows;
- one row per `(target_id, substr(at, 1, 13))` group of `login.failure` rows. That row carries the newest event's columns and `COUNT(*)` as `Count`.

`Total` counts rows after collapsing.

- [ ] **Step 1: Tests**

```go
// groups_admin_test.go
func TestUpdateGroup(t)            // name, description, flags, metadata persisted; renaming onto an existing name -> ErrConflict
func TestLastAdminGroupGuards(t)   // only "Admin" has IsAdmin: UpdateGroup with IsAdmin false -> ErrLastAdminGroup and row unchanged; DeleteGroup -> ErrLastAdminGroup;
                                   // after a second admin group exists both succeed; DeleteGroup(unknown) -> ErrNotFound
func TestDeleteGroupCascades(t)    // memberships and application_groups rows for it are gone
func TestListGroupsWithCounts(t)   // counts include service accounts; ordered by name; a group with no members has 0
func TestReplaceUserGroups(t)      // {A,B} -> {B,C}; -> {} leaves none; {B, "no-such-id"} -> error and memberships still {}
// apps_test.go
func TestDeleteApplication(t)      // its auth codes, refresh tokens and application_groups rows are gone; second call ErrNotFound
// audit_test.go
func TestListAuditEvents(t)        // Since/Until bounds; ActorID; TargetID; Actions ["user.", "logout"] keeps user.create and logout, drops login.success;
                                   // Query "laser" matches summary "Added Alex to Laser"; newest first; PerPage 2 pages through with Total
func TestListAuditEventsCollapsesLoginFailures(t)
                                   // login.failure: 4 for user X between 10:00 and 10:59, 1 for X at 11:05, 3 with target "" at 10:xx; plus 1 user.update
                                   // Collapse on -> 4 rows: X 10h Count 4 (at = latest of the four), X 11h Count 1, "" 10h Count 3, user.update Count 1; Total 4
                                   // Collapse off -> 9 rows, all Count 1
```

- [ ] **Step 2: Run** `go test ./internal/store/` and expect it to FAIL.
- [ ] **Step 3: Implement** the methods above.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(store): group update and delete with last-admin guard, app delete, audit queries`

---

### Task 3: Admin service: core and members

**Files:**
- Create: `internal/admin/admin.go` (`Deps`, `Service`, `Actor`, error types, `ParseMetadata`, shared validation, audit helper), `internal/admin/members.go`, `internal/admin/admin_test.go` (helper `newService(t) (*admin.Service, *store.Store, *fakeNotifier)` plus fakes), `internal/admin/members_test.go`
- Modify: `internal/audit/audit.go` (action names from Shared interfaces)

**Interfaces:**
- Consumes:
  - store: Tasks 1-2, plus `CreateUser`, `UpdateUser`, `SetPassword`, `ClearTOTP`, `DeleteSessionsForUser`, `RevokeRefreshTokensForUser`;
  - `password.CheckPolicy`;
  - `audit.Recorder.Record`.
- Produces: the member half of the admin service (Shared interfaces). All tests are external (`package admin_test`) and use `storetest.OpenTestDB`, so they can read `audit_events` through `store.ListAuditEvents`.

**Rules:**

| Field | Rule and message |
|---|---|
| Name | trimmed, 1–200 characters: "Enter a name." |
| Email (members) | trimmed, at most 254 characters, exactly one `@` with text on both sides, no spaces: "Enter an email address, like alex@example.org." Taken by another user, ignoring case: "Another member already uses that email address." |
| Username | optional for members, trimmed, at most 150 characters, no spaces: "Usernames can't contain spaces." Taken: "That username is taken." |
| Password | `password.CheckPolicy(pw, cfg.Password.MinLength)` errors use the member pages' copy: "Use at least %d characters." and "That password is too common. Pick something less guessable." |
| Metadata | must be a JSON object: `Metadata must be a JSON object, like {"member_number": 42}.` Over 8192 bytes: "Metadata is too long. Keep it under 8 KB." |
| Group IDs | an unknown group ID: "That group no longer exists." |
| Group names | an unknown name passed to `ResolveGroups`: `No group called "Nope".` |

Uniqueness is checked before writing, so the message lands on the right field.

**Behaviour:**
- **Create.** New members are `IsActive = true` and `Type = member` (core decisions carry-forward). Create records `user.create`. An invitation also records `user.invite` with the admin as actor, and calls `Notifier.SendReset(user, invite)`, which records its own event for the invitee.
- **Send password email.** `SendPasswordEmail` records `user.invite` or `user.password.reset_sent`. On a disabled account it is refused: "This account is disabled. Enable it first."
- **Revocations.** Disabling, setting a password and signing out everywhere each delete all the member's sessions and revoke their refresh tokens.
- **Self-protection.** When the actor is the target member, three things are refused:

  | Change | Refusal |
  |---|---|
  | disable | "You can't disable your own account." |
  | delete | "You can't delete your own account." |
  | any group change that leaves them in no admin group | "You can't remove your own admin access. Ask another admin to do it." |

- **Actor in audit.** `Actor.TokenID`, when set, goes into every event's `detail.token_id`.

- [ ] **Step 1: Tests**

```go
func TestCreateMemberInvite(t)          // Invite: user active, type member, Metadata {}; notifier called once with (user, "invite");
                                        // audit has user.create and user.invite, ActorType "user", ActorID = admin's ID, TargetID = new user
func TestCreateMemberWithPassword(t)    // Invite false, Password "correct horse battery": password.Verify ok; notifier not called; status active
func TestCreateMemberValidation(t)      // table, each leaving no user behind: name "" -> Fields["name"]; email "alex" -> Fields["email"];
                                        // existing "alex@example.org", new "ALEX@example.org" -> Fields["email"] == "Another member already uses that email address." (Review Focus 1);
                                        // username taken -> Fields["username"] == "That username is taken."; Password "short" -> Fields["password"] == "Use at least 10 characters.";
                                        // 9000-byte metadata -> Fields["metadata"]; GroupIDs ["nope"] -> Fields["groups"]
func TestParseMetadata(t)               // "" -> {}; `{"a":1}` -> map; `[1,2]`, `"x"`, `null`, `42`, `{bad` -> Fields["metadata"] == `Metadata must be a JSON object, like {"member_number": 42}.` (Review Focus 2)
func TestCreateMemberInviteEmailFails(t)// notifier error -> returns non-nil user and an error that errors.As finds *EmailError; user is stored
func TestUpdateMember(t)                // patch Name and Email only: Username, groups, metadata unchanged;
                                        // audit user.update detail.changed has name and email with from/to; metadata change appears as "metadata": {}
func TestUpdateMemberGroups(t)          // GroupIDs {Members, Laser} -> {Members, Woodshop}: one group.member.remove (Laser) and one group.member.add (Woodshop), detail.group_name set
func TestDisableAndEnable(t)            // IsActive false: sessions gone, refresh tokens revoked, audit user.disable; IsActive true: user.enable
func TestSelfProtection(t)              // Review Focus 3: actor == target: disable, delete, GroupIDs without any admin group -> *RefusedError with the messages above, nothing changed;
                                        // a second admin can do each to the first
func TestDeleteMember(t)                // gone; audit user.delete with detail email and name, TargetID the old ID
func TestSendPasswordEmail(t)           // no password -> "invite" and user.invite; with password -> "reset" and user.password.reset_sent; disabled -> *RefusedError;
                                        // notifier error -> *EmailError
func TestSetMemberPassword(t)           // "short" -> Fields["password"]; good password: native hash set, LegacyPasswordHash "", sessions gone, refresh revoked;
                                        // audit user.password.set whose detail has no "password" key
func TestClearMemberTOTP(t)             // enrolled member: TOTP and recovery codes cleared; audit user.totp.clear
func TestSignOutEverywhere(t)           // sessions gone, refresh revoked, audit user.sessions.revoke
func TestMemberMethodsRejectServiceAccounts(t) // UpdateMember, DeleteMember, SendPasswordEmail, SetMemberPassword, ClearMemberTOTP, SignOutEverywhere
                                        // with a service account's ID -> store.ErrNotFound
func TestResolveMemberAndGroups(t)      // "email:ALEX@example.org" and the plain ID both find Alex; "email:nobody@x" -> ErrNotFound; a service account ID -> ErrNotFound;
                                        // ResolveGroups(["Laser", <Woodshop ID>]) -> both IDs; ["Nope"] -> Fields["groups"] == `No group called "Nope".`
func TestTokenActorInAudit(t)           // Actor{ActorServiceAccount, sa.ID, "tok-1"} creating a member -> audit ActorType "service_account", detail.token_id "tok-1"
```

- [ ] **Step 2: Run** `go test ./internal/admin/` and expect it to FAIL.
- [ ] **Step 3: Implement** `admin.go` and `members.go`, and add the audit action names.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(admin): admin service with member operations, validation and audit`

---

### Task 4: Admin service: groups, service accounts and API tokens

**Files:**
- Create: `internal/admin/groups.go`, `internal/admin/groups_test.go`, `internal/admin/service_accounts.go`, `internal/admin/service_accounts_test.go`

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: the group, service-account, token and `AuthenticateToken` parts of the admin service (Shared interfaces).

**Group rules:**
- Name trimmed, 1–100 characters: "Enter a group name." Taken: "There's already a group with that name."
- Description at most 500 characters.
- Metadata as in Task 3.
- A last-admin-group refusal reads "This is the only admin group. Make another group an admin group first."
- `RemoveFromGroup` of yourself out of your last admin group gets Task 3's own-admin-access refusal.
- `AddToGroup` for someone already in the group does nothing and records nothing.

**Service account rules:**
- Name as for members; username required ("Enter a username.") and unique; `Type = service`; no password.

**API token rules:**
- The raw token is `"latch_" + secrets.RandomToken(32)`.
- Label 1–100 characters: "Enter a label so you can tell tokens apart."
- Scope `admin` or `read`: "Choose full admin or read only."
- `ExpiresAt` must be in the future: "Choose a date in the future."
- `CreatedByUserID` is the actor's ID.
- `api_token.create` has `detail.label` and `detail.scope`, never the token.

**`AuthenticateToken` fails with `ErrBadToken` for any of these:**
- an unknown hash;
- `ExpiresAt` at or before now;
- the account missing, inactive or not a service account.

It writes `LastUsedAt` when that is nil or at least a minute old (`Deps.Now`).

- [ ] **Step 1: Tests**

```go
// groups_test.go
func TestCreateAndUpdateGroup(t)   // Fields["name"] for "" and for a taken name; flags and metadata saved; audit group.create and group.update (detail.changed)
func TestLastAdminGroupRefused(t)  // Review Focus 3: only admin group: UpdateGroup IsAdmin false and DeleteGroup -> *RefusedError with the message above; group unchanged
func TestDeleteGroup(t)            // audit group.delete with detail.name
func TestAddRemoveGroupMember(t)   // member and service account both addable; group.member.add / remove events; second add is a no-op with no event;
                                   // removing yourself from your only admin group -> *RefusedError
func TestResolveGroup(t)           // ID and "name:Laser"; "name:nope" -> ErrNotFound
// service_accounts_test.go
func TestServiceAccountLifecycle(t)// create: Type service, Description, groups, no password hash; username "" -> Fields["username"]; taken -> "That username is taken.";
                                   // update; delete; audit service_account.create/update/delete; DeleteServiceAccount(member ID) -> ErrNotFound; "username:door" resolves
func TestCreateToken(t)            // raw has prefix "latch_" and length 49; stored TokenHash == secrets.HashToken(raw); Scope read; CreatedByUserID = actor;
                                   // Label "" -> Fields["label"]; Scope "write" -> Fields["scope"]; ExpiresAt yesterday -> Fields["expires_at"];
                                   // audit api_token.create whose detail has label and scope and no value containing raw
func TestAuthenticateToken(t)      // fresh token -> Caller with Account and Token; Caller.Actor() has TokenID;
                                   // unknown, expired, revoked, and account deleted -> ErrBadToken;
                                   // LastUsedAt set on first use, unchanged 30s later, updated 61s later (Deps.Now clock)
func TestRevokeToken(t)            // another account's ID -> ErrNotFound; owner -> token gone, AuthenticateToken -> ErrBadToken; audit api_token.revoke
```

- [ ] **Step 2: Run** `go test ./internal/admin/` and expect it to FAIL.
- [ ] **Step 3: Implement** `groups.go` and `service_accounts.go`.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(admin): groups, service accounts and API tokens`

---

### Task 5: Admin service: applications and settings

**Files:**
- Create: `internal/admin/apps.go`, `internal/admin/apps_test.go`, `internal/admin/settings.go`, `internal/admin/settings_test.go`
- Modify:
  - `internal/oidc/keys.go`: add `RotateAs`; `Rotate(ctx)` becomes `RotateAs(ctx, audit.ActorSystem, "")`.
  - `internal/oidc/keys_test.go`.
  - `internal/mail/templates.go`: add `func TestEmail(b Brand) Message`.
  - `internal/mail/mail_test.go`.

**Interfaces:**
- Consumes:
  - Tasks 1-4;
  - `config.ParseDuration`;
  - `oidc.KeyManager`, which admin tests may use for real;
  - `store.ListSigningKeys`.
- Produces:
  - the application and settings parts of the admin service;
  - `func (k *KeyManager) RotateAs(ctx context.Context, actorType model.ActorType, actorID string) (string, error)`;
  - `mail.TestEmail`, whose subject is "Test email from <branding name>" and whose body says email sending works and names `PublicURL`.

**Application rules.** Field keys are the JSON and form names.

| Field | Rule and message |
|---|---|
| `name` | 1–100 characters. |
| `slug` | Blank means made from the name: lower-case it, turn each run of characters outside `a-z0-9` into `-`, trim `-`, cut to 64 characters, and use `app` if nothing is left. It must match `^[a-z0-9]+(-[a-z0-9]+)*$`: "Use lower-case letters, numbers and hyphens." Taken: "Another app already uses that short name." |
| `client_type` | `confidential` or `public`: "Choose whether the app keeps a secret." |
| `redirect_uris`, `post_logout_redirect_uris` | Each entry is trimmed. Empty entries and duplicates are dropped. At most 20 remain: "Add at most 20 addresses." Each must be absolute `http` or `https`, with a host and no user info: "Line %d isn't a full web address starting with https:// or http://." No fragment: "Line %d can't contain a # part." %d counts the submitted lines, starting at 1. |
| `allowed_groups` | Existing group IDs. |
| `subject_mode` | One of the six modes, with `""` meaning `id`: "Choose how the app identifies people." (core decisions carry-forward) |
| `access_token_ttl`, `id_token_ttl` | 0, or 1 minute to 24 hours: "Use a time between 1m and 24h, like 1h." |
| `refresh_token_ttl` | 0, or 1 minute to `tokens.refresh_absolute`: "Use a time between 1m and %s." |
| `launch_url` | Empty, or absolute `http`/`https`. |
| `icon_url` | Empty, absolute `https` only (the CSP allows only https images), or a path starting `/icons/`. |
| `service_account_id` | Only on confidential apps: "Only apps that keep a secret can sign in by themselves." Must name a service account: "Choose a service account." |

New apps get a client ID of `secrets.RandomToken(18)` (24 characters). Confidential apps get a secret of `secrets.RandomToken(32)` (43 characters), stored only as its hash.

Switching the client type:
- **Confidential → public** clears the secret hash.
- **Public → confidential** makes a secret and returns it.

`RotateAppSecret` on a public app is refused: "This app doesn't use a secret."

`RotateKeys` uses the actor, so the key event records the admin. `SendTestEmail` records `settings.smtp_test` with `detail.sent` (true or false) and returns the mailer's error.

- [ ] **Step 1: Tests**

```go
// apps_test.go
func TestCreateConfidentialApp(t)    // secret 43 chars, ClientSecretHash == HashToken(secret), ClientID 24 chars, Slug "members-wiki" from Name "Members Wiki",
                                     // SubjectMode "id"; audit app.create detail has slug and client_type, not the secret
func TestCreatePublicApp(t)          // secret "", ClientSecretHash ""
func TestAppValidation(t)            // table AppInput -> field: name ""; slug "Bad Slug!"; duplicate slug ("Another app already uses that short name.");
                                     // client_type "weird"; subject_mode "guess"; redirect "/callback", "javascript:alert(1)", "https://user:pw@a/cb" -> message contains "Line 1";
                                     // "https://a/cb#x" -> "Line 1 can't contain a # part."; 21 distinct URIs; AccessTokenTTL 25h; IDTokenTTL 25h;
                                     // RefreshTokenTTL beyond refresh_absolute; launch_url "ftp://x"; icon_url "http://x/i.png" (https only);
                                     // service account on a public app; a member's ID as service account; unknown allowed group
func TestRedirectURICleanup(t)       // Review Focus 5: ["  https://a/cb ", "", "https://a/cb", "\r", "https://b/cb"] -> stored ["https://a/cb", "https://b/cb"];
                                     // ["https://a/cb", "", "/x"] -> message "Line 3 isn't a full web address starting with https:// or http://."
func TestUpdateAppClientTypeSwitch(t)// confidential->public: hash cleared, secret ""; public->confidential: secret returned, hash matches
func TestRotateAppSecret(t)          // old secret no longer matches, new one does; public app -> *RefusedError; audit app.secret.rotate
func TestDeleteApp(t)                // gone; audit app.delete detail has name, slug, client_id
func TestResolveApp(t)               // ID and "slug:members-wiki"
// settings_test.go
func TestSendTestEmail(t)            // mail.Memory gets To = admin email, Subject contains branding name; failing mailer -> error returned; audit settings.smtp_test detail.sent
func TestRotateKeys(t)               // real KeyManager: ActiveKID changes, retired 0; audit oidc.key.rotate ActorType "user" ActorID admin
// internal/oidc/keys_test.go
func TestRotateAsRecordsActor(t)     // RotateAs(ctx, ActorUser, "u1") -> audit row actor user/u1; Rotate(ctx) still records actor_type "system"
```

- [ ] **Step 2: Run** `go test ./internal/admin/ ./internal/oidc/ ./internal/mail/` and expect it to FAIL.
- [ ] **Step 3: Implement** `apps.go`, `settings.go`, `RotateAs` and `mail.TestEmail`.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(admin): applications, signing key rotation and SMTP test`

---

### Task 6: Admin shell and Settings page

**Files:**
- Create: `internal/web/admin.go`, `internal/web/admin_settings.go`, `internal/web/templates/_admin.html`, `internal/web/templates/admin_settings.html`, `internal/web/admin_test.go`, `internal/web/render_internal_test.go`
- Modify:
  - `internal/web/render.go`: partials, template funcs, `Page.Section`.
  - `internal/web/templates/frame.html`.
  - `internal/web/static/latch.css`.
  - `internal/web/server.go`: `Deps.Keys`, building the admin service, admin routes, `limitBody`.
  - `internal/web/home.go` and `templates/home.html`: the admin link.
  - `internal/testenv/testenv.go`: pass `Keys`; add `AdminClient`, `Page`, `Submit`.
  - `cmd/latch/main.go`: pass `Keys: keys`.

**Interfaces:**
- Consumes: the admin service (Tasks 3-5).
- Produces:
  - **Template sets.** Every `templates/_*.html` file is parsed into every page's template set and is never a page itself. Template funcs (Shared interfaces):
    - `ago`: nil → "Never"; under 24h → "Today"; under 48h → "Yesterday"; under 30 days → "N days ago"; under 365 days → "N months ago" (days/30, at least 1); otherwise "N years ago".
    - `date`: "2 Jan 2006".
    - `datetime`: "2 Jan 2006 15:04 UTC".
    - `prettyJSON`: two-space indent; nil gives `{}`.
  - **Admin frame.** When `Page.Section` is set, the frame shows the admin layout:
    - the header adds an "Admin" label, the admin's email, a "Member home" link and a Sign out button (POST `/logout`);
    - `main.admin` holds `<nav class="admin-nav" aria-label="Admin">` with the six sidebar links (`/admin/members`, `/admin/groups`, `/admin/apps`, `/admin/service-accounts`, `/admin/settings`, `/admin/audit`), with `aria-current="page"` on the active one;
    - next comes `<div class="admin-main">` with the alerts and content;
    - on narrow screens the nav becomes a row above the content.
  - **Access check.** `func (s *Server) requireAdmin(next http.Handler) http.Handler` runs inside `session.RequireUser`. Anyone in no `is_admin` group gets a 403 error page, titled "Admins only", reading "You need to be in an admin group to use these pages. Ask an existing admin if you think you should be."
  - `func adminActor(r *http.Request) admin.Actor` returns `{model.ActorUser, signed-in user ID, ""}`.
  - **Admin service.** `Server.admin` is built in `web.New` from `admin.Deps{Cfg, Store, Audit, Mailer, Notifier: s, Keys: d.Keys, HashPassword: s.hashPassword, Now: d.Now}`.
  - **Result convention**, used by Tasks 7-12:
    - A successful POST redirects (303) to a page with `?notice=<key>`. The page shows `adminNotices[key]`. An unknown key shows nothing, so no request text is ever echoed back.
    - A failed POST re-renders the page directly with `Page.Error` (or field messages) and status 422 (validation), 409 (refused) or 502 (email).
    - `store.ErrNotFound` gives the 404 error page.
  - **Routes:**
    - `GET /admin` redirects (303) to `/admin/members`;
    - `GET /admin/settings`;
    - `POST /admin/settings/test-email`;
    - `POST /admin/settings/rotate-keys`.
  - **Body limit.** `limitBody` allows `maxBodyBytes = 1 << 20` on every path except `/api/`, which limits its own bodies so it can answer in JSON. A larger `Content-Length` gets a 413 error page titled "Too much data". Otherwise the body is wrapped in `http.MaxBytesReader`. This closes the core decisions' `MaxBytesReader` follow-up.
  - **Member home.** `homeData.IsAdmin` adds an "Admin pages" link (`href="/admin"`) to the home page's account links.

```go
var adminNotices = map[string]string{
    "saved":           "Changes saved.",
    "invited":         "Member added. We've emailed them an invitation.",
    "added":           "Member added.",
    "added_no_email":  "Member added, but the invitation email couldn't be sent. Check the email settings on the Settings page, then use Send invite email.",
    "invite_sent":     "Invitation emailed.",
    "reset_sent":      "Password reset email sent.",
    "password_set":    "Password set. They've been signed out everywhere.",
    "totp_cleared":    "Two-step sign in cleared.",
    "disabled":        "Account disabled. They've been signed out everywhere.",
    "enabled":         "Account enabled.",
    "signed_out":      "Signed out everywhere.",
    "deleted":         "Deleted.",
    "member_added":    "Added to the group.",
    "member_removed":  "Removed from the group.",
    "token_revoked":   "Token revoked.",
    "test_email_sent": "Test email sent. Check your inbox.",
    "key_rotated":     "New signing key in use. Apps pick it up automatically.",
}
```

**Settings page.** It has three sections:
- **Branding:** name, logo, a swatch of the colour with its hex value, and the support text. Then: "To change these, edit the branding section of Latch's config file (latch.yaml) and restart Latch."
- **Email:** SMTP host, port, from address and TLS mode, never the password. When the host is empty it says "Email isn't set up yet." A "Send a test email to <admin email>" button follows. A failed send re-renders with status 502 and the error "The test email couldn't be sent: <error text>". This is the one place a raw error is shown, because the admin needs it to fix their config.
- **Signing keys:** a table of key ID, date made, and a state. The state is "In use" for the active key, "Retired <date>" for a retired key, and "Still published" otherwise. A "Make a new signing key" button sits under the table with the note "Apps pick up the new key automatically. Older keys are retired 90 days after they're replaced."

CSS is hand-written in `latch.css`:
- the admin grid (`main.admin`, max-width 1200px, a 12rem sidebar);
- `.table-wrap` (horizontal scroll) and `table.list`;
- `.chip`, plus `.status` with dots: green for active, amber for invited or needs password, red for disabled;
- `.toolbar` and `.pagination`;
- `.button-danger` (`--danger: #b42318`) and `details.confirm`;
- `.field-error`, `textarea`, `select`, `.checks` and `.panel`;
- `.secret` (monospace, `user-select: all`).

- [ ] **Step 1: Tests**

```go
// admin_test.go
func TestAdminRequiresAdmin(t)          // no session: GET /admin -> 303 /login?next=%2Fadmin; plain member -> 403 containing "Admins only";
                                        // AdminClient -> 303 /admin/members
func TestAdminRequiresSecondStep(t)     // admin in a RequireTOTP admin group, enrolled, password step only: GET /admin/settings -> 303 to /login/totp?next=...
func TestAdminFrame(t)                  // GET /admin/settings: the six sidebar links appear in order; the Settings link has aria-current="page";
                                        // the header shows "Admin" and admin@example.org and a form posting to /logout
func TestSettingsPage(t)                // branding name, primary colour hex, "latch.yaml"; "Email isn't set up yet." with the default config;
                                        // the active key's kid next to "In use"; no SMTP password text when one is configured
func TestSettingsTestEmail(t)           // POST test-email -> 303 /admin/settings?notice=test_email_sent; Mailer.Last().To == admin email;
                                        // failing mailer (testenv.WithMailer) -> 502 page containing "couldn't be sent"
func TestSettingsRotateKeys(t)          // POST rotate-keys -> 303 ?notice=key_rotated; env.Keys.ActiveKID() changed; /.well-known/jwks.json has 2 keys
func TestAdminNoticesComeFromTable(t)   // ?notice=saved shows "Changes saved."; ?notice=%3Cb%3Ehi%3C%2Fb%3E shows no alert and the body lacks "hi"
func TestHomeLinksAdminsToAdminPages(t) // admin's home has href="/admin"; a plain member's does not
func TestRequestBodyLimit(t)            // POST /login with Content-Length 2<<20 -> 413
// render_internal_test.go
func TestTemplateFuncs(t)               // ago(nil) "Never"; now-1h "Today"; now-30h "Yesterday"; now-5d "5 days ago"; now-70d "2 months ago"; now-800d "2 years ago";
                                        // date(2026-10-03) "3 Oct 2026"; prettyJSON({"a":1}) == "{\n  \"a\": 1\n}"; prettyJSON(nil) "{}"
```

- [ ] **Step 2: Run** `go test ./internal/web/` and expect it to FAIL.
- [ ] **Step 3: Implement** the shell, the Settings page, the CSS, `limitBody`, the home link, and the testenv and `main.go` wiring.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(web): admin shell with sidebar, admin check, settings page, body limit`

---

### Task 7: Members pages

**Files:**
- Create: `internal/web/admin_members.go`, templates `admin_members.html`, `admin_member_new.html`, `admin_member.html`, `internal/web/admin_members_test.go`

**Interfaces:**
- Consumes:
  - the admin service's member methods and `ParseMetadata`;
  - `store.ListUsers`, `GetUser`, `GetUserStatus`, `ListGroups` and `ListGroupsForUser`;
  - Task 6's convention and partials.
- Produces:

  | Route | Purpose |
  |---|---|
  | `GET /admin/members` | `?q=&status=&page=` |
  | `GET /admin/members/new` | add form |
  | `POST /admin/members` | create |
  | `GET /admin/members/{id}` | edit page |
  | `POST /admin/members/{id}` | save |
  | `POST /admin/members/{id}/send-email` | |
  | `POST /admin/members/{id}/password` | |
  | `POST /admin/members/{id}/clear-totp` | |
  | `POST /admin/members/{id}/disable` | |
  | `POST /admin/members/{id}/enable` | |
  | `POST /admin/members/{id}/sign-out` | |
  | `POST /admin/members/{id}/delete` | field `confirm` |

  Form fields: `name`, `email`, `username`, `groups` (repeated group IDs), `metadata`, `setup` (`invite` or `password`), `password`.

**List page.** The copy follows the wireframe from brainstorming.
- **Toolbar:** a search box ("Search name, email or username"), a status filter and an "Add member" button.
- **Filter options:** All, Active, Invited, Needs password, Disabled, No two-step sign in, Admins. The values are the `UserFilter.Status` strings.
- **Columns:** Name (a link to the edit page), Email, Groups (chips), Status, Last login (`ago`).
- **Status labels:** "Active", "Invited, not set up", "Needs password", "Disabled".
- **Pagination:** 50 per page. Page links keep `q` and `status`. A page value that is not a number means page 1.

**Add page.** It has these fields:
- "Full name";
- "Email (used to sign in)";
- "Username (optional, for the wiki)";
- the groups as checkboxes;
- "Metadata (custom JSON, passed to apps)" inside a closed `<details>`, starting as `{}`;
- "How will they set their password?", with the choices "Email them an invitation (recommended)" (the default) or "Set a password now" plus a password field.

A successful add redirects to the edit page with `invited`, `added` or `added_no_email`.

**Edit page.**
- **Form:** the same fields and a "Save changes" button.
- **Info panel:** status, last login, created date, and two-step sign in. Two-step sign in reads "On since <date>", or "Off". When a group requires it but the member has none, it adds: "Required by <group>; they'll set it up next time they sign in".
- **Import origin:** "Imported from Authentik" when `AuthentikUUID` or `AuthentikPK` is set.
- **Actions,** each a small form:
  - "Send invite email" when there is no password, otherwise "Send password reset email";
  - "Set password manually", a `<details>` with a password field;
  - "Clear two-step sign in", shown only when enrolled, behind a confirm;
  - "Sign out everywhere";
  - "Disable account" (red, behind a confirm), or "Enable account";
  - "Delete member" (red): a `<details>` that asks "Type their email address to confirm".
- **Your own page:** disable and delete are left out, and the page says "This is your account. Change your own password from your account page." The service still refuses those actions if they are posted anyway.
- **Delete mismatch:** a typed email that does not match (trimmed, ignoring case) re-renders with 422 and "Type the email address exactly to confirm."

- [ ] **Step 1: Tests**

```go
func TestMembersList(t)                 // active "Alex Rivera" in Laser, invited "Priya Nair", disabled "Chris Dubois", service account "Door":
                                        // names, emails, a "Laser" chip, "Invited, not set up", "Disabled" shown; "Door" absent; href="/admin/members/new"
func TestMembersListSearchFilterPage(t) // ?q=priya -> Priya only; ?status=disabled -> Chris only;
                                        // 60 members with ?status=active -> 50 rows and a link containing "page=2" and "status=active"; ?page=abc -> first page
func TestAddMemberInvite(t)             // POST name, email, groups=[Laser ID], setup=invite -> 303 Location /admin/members/{id}?notice=invited;
                                        // env.WaitMail not needed (synchronous); Mailer.Last().To == email and its text contains "/reset/"; member is in Laser
func TestAddMemberSetPassword(t)        // setup=password, password "correct horse battery" -> 303 ?notice=added; env.Login with that password succeeds
func TestAddMemberErrorsKeepInput(t)    // Review Focus 1: existing alex@example.org, POST email "ALEX@example.org", name "Alex Two" -> 422,
                                        // body has "Another member already uses that email address." and value="Alex Two";
                                        // Review Focus 2: metadata "[1,2]" -> 422 "Metadata must be a JSON object" and the textarea still holds [1,2]; no user created in either case
func TestAddMemberInviteEmailFails(t)   // failing mailer -> 303 ?notice=added_no_email; following it shows that notice text
func TestEditMember(t)                  // GET shows the fields, the checked groups, metadata pretty-printed, "Off" for two-step, and "Imported from Authentik" when AuthentikUUID is set;
                                        // POST new name and no groups -> 303 ?notice=saved; store has the new name and no memberships
func TestMemberActions(t)               // send-email: no password -> invite email and ?notice=invite_sent; with password -> reset email and ?notice=reset_sent;
                                        // password "short" -> 422 containing "Use at least 10 characters."; good password -> ?notice=password_set and the member's existing session is gone;
                                        // clear-totp -> ?notice=totp_cleared and TOTPConfirmedAt nil; disable -> ?notice=disabled and sessions gone; enable -> ?notice=enabled;
                                        // sign-out -> ?notice=signed_out
func TestDeleteMemberConfirm(t)         // confirm "wrong@example.org" -> 422 "Type the email address exactly to confirm." and member remains;
                                        // confirm " ALEX@example.org " -> 303 /admin/members?notice=deleted and member gone
func TestAdminCannotLockThemselvesOut(t)// Review Focus 3: on their own page, the admin has no disable or delete form and sees "This is your account.";
                                        // POST own /disable -> 409 "You can't disable your own account."; saving with the Admin box unticked -> 409 "You can't remove your own admin access"
func TestMemberPagesRejectServiceAccounts(t) // GET and POST /admin/members/{service account ID} -> 404
```

- [ ] **Step 2: Run** `go test ./internal/web/ -run 'Member'` and expect it to FAIL.
- [ ] **Step 3: Implement** the handlers and templates.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(web): admin members list, add, edit and account actions`

---

### Task 8: Groups pages

**Files:**
- Create: `internal/web/admin_groups.go`, templates `admin_groups.html`, `admin_group.html` (new and edit), `internal/web/admin_groups_test.go`

**Interfaces:**
- Consumes: the admin service's group methods, `store.ListGroupsWithCounts`, and `store.ListUsers` (with `GroupID`, or with `Query` for the add search).
- Produces:

  | Route | Purpose |
  |---|---|
  | `GET /admin/groups` | list |
  | `GET /admin/groups/new` | add form |
  | `POST /admin/groups` | create |
  | `GET /admin/groups/{id}` | `?q=` searches for people to add |
  | `POST /admin/groups/{id}` | save |
  | `POST /admin/groups/{id}/members` | field `user_id` |
  | `POST /admin/groups/{id}/members/{uid}/remove` | |
  | `POST /admin/groups/{id}/delete` | field `confirm` |

  Form fields: `name`, `description`, `is_admin`, `require_totp`, `metadata`.

**List page.** Columns are name, description and member count. Chips show "Admin access" and "Requires two-step sign in". An "Add group" button sits above.

**Form.** It has:
- "Name" and "Description";
- the checkboxes "Members can use the admin pages" (`is_admin`) and "Members must use two-step sign in" (`require_totp`);
- metadata in a `<details>`.

A create redirects to the edit page with `?notice=saved`.

**Members section on the edit page.**
- A table of name, email, a "Service account" chip where it applies, and a Remove button.
- An "Add someone" search form (`GET ?q=`). It lists up to 20 matching members and service accounts who are not already in the group, each with an Add button.

**Delete.** Deleting is a red `<details>`: "Type the group's name to confirm". A typed name that does not match re-renders with 422 and "Type the name exactly to confirm."

- [ ] **Step 1: Tests**

```go
func TestGroupsList(t)               // "Laser" with 2 members shows 2; Admin group shows "Admin access"; a RequireTOTP group shows "Requires two-step sign in"
func TestCreateGroup(t)              // POST -> 303 /admin/groups/{id}?notice=saved; duplicate name -> 422 "There's already a group with that name."
func TestEditGroup(t)                // flags and metadata saved; metadata "null" -> 422 and nothing saved
func TestGroupMembersSection(t)      // lists a member and a service account (with "Service account"); ?q=sam lists Sam (not yet a member) with an Add form, not existing members;
                                     // POST members user_id=Sam -> 303 ?notice=member_added; remove -> ?notice=member_removed
func TestLastAdminGroupRefusedInUI(t)// Review Focus 3: only admin group: save with is_admin unticked -> 409 page with "This is the only admin group. Make another group an admin group first.";
                                     // delete with the right name -> 409 same message; group still IsAdmin
func TestDeleteGroupConfirm(t)       // wrong name -> 422 "Type the name exactly to confirm."; right -> 303 /admin/groups?notice=deleted
```

- [ ] **Step 2: Run** `go test ./internal/web/ -run 'Group'` and expect it to FAIL.
- [ ] **Step 3: Implement** the handlers and templates.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(web): admin groups pages with members and last-admin guard`

---

### Task 9: Applications pages

**Files:**
- Create: `internal/web/admin_apps.go`, templates `admin_apps.html`, `admin_app.html` (new and edit), `admin_secret.html`, `internal/web/admin_apps_test.go`

**Interfaces:**
- Consumes: the admin service's app methods, `store.ListApplications`, `store.ListGroups`, `store.ListUsers` (service accounts), and `config.ParseDuration`.
- Produces:

  | Route | Purpose |
  |---|---|
  | `GET /admin/apps` | list |
  | `GET /admin/apps/new` | add form |
  | `POST /admin/apps` | create |
  | `GET /admin/apps/{id}` | edit page |
  | `POST /admin/apps/{id}` | save |
  | `POST /admin/apps/{id}/rotate-secret` | |
  | `POST /admin/apps/{id}/delete` | field `confirm` |

  Form fields: `name`, `slug`, `client_type`, `redirect_uris` and `post_logout_redirect_uris` (textareas, split on `\n`), `allowed_groups`, `subject_mode`, `access_token_ttl`, `id_token_ttl`, `refresh_token_ttl`, `show_tile`, `launch_url`, `description`, `icon_url`, `machine` and `service_account_id`.

  Also, for Tasks 10-11:
  - `admin_secret.html` takes data `secretPage{Heading, Intro string; Items []secretItem /* Label, Value */; Example string; Back string}`.
  - `func formatTTL(d time.Duration) string` turns 0 into ""; whole days into "Nd"; else whole hours into "Nh"; else whole minutes into "Nm".

**Lifetime fields** parse with `config.ParseDuration`. Blank means 0. A value that does not parse gives the field message "Use a time like 1h or 30d."

**List page.** Each row shows a tile preview (the icon or the initial), the name, and the kind of app. Then the allowed groups as chips, or "Everyone". A "Machine to machine" chip appears when a service account is set. The kind of app reads "Keeps a secret" for confidential apps and "No secret (browser or phone app)" for public ones.

**Form sections:**
- **Basics:** "Name"; "Short name (used in links; leave blank to make one from the name)"; and "Does the app keep a secret?". The answers are "Yes: it runs on a server, like MediaWiki" (confidential, the default) or "No: it runs in the browser or on a phone" (public).
- **Addresses:** "Sign-in return addresses, one per line"; "Addresses to return to after signing out (optional)".
- **Who can sign in:** group checkboxes, with "Leave all unticked to let every active member in."
- **How the app recognises people:** a `subject_mode` select:

  | Value | Label | Help |
  |---|---|---|
  | `id` | "Latch ID (recommended)" | "A permanent ID that never changes, even if their email does." |
  | `email` | "Email address" | "Changes when their email changes." |
  | `username` | "Username" | "People without a username get their Latch ID." |
  | `authentik_uid` | "Authentik ID (Authentik's default)" | |
  | `authentik_uuid` | "Authentik UUID" | |
  | `authentik_pk` | "Authentik number" | |

  Under the select: "Changing this changes how the app recognises people, so existing accounts in the app may stop matching." When the current mode is an `authentik_*` one, also show: "⚠ This uses the identifier Authentik gave this app, so people's existing accounts in it keep working. People added after the move get their Latch ID instead. Switch to Latch ID once the app no longer needs Authentik's identifiers." (§6.4)
- **Home page tile:** "Show on members' home page", "Link to open the app", "Description" and "Icon address (https)".
- **Machine to machine:** "Allow this app to sign in by itself (machine to machine)" (§6.5) with a service-account select. When there is no service account yet, link to `/admin/service-accounts/new` instead.
- **Token lifetimes (advanced):** a closed `<details>`. Each field shows the global default as its placeholder.

**Edit-page panels:**
- **Setup details.** Issuer, discovery URL (`<issuer>/.well-known/openid-configuration`), client ID and the registered return addresses.
  - For confidential apps, a `LocalSettings.php` snippet in a `<pre>`:
    ```php
    $wgPluggableAuth_Config['<name>'] = [ 'plugin' => 'OpenIDConnect', 'data' => [
        'providerURL' => '<issuer>', 'clientID' => '<client id>',
        'clientsecret' => '(the secret you copied when you made this app)',
        'scope' => [ 'openid', 'profile', 'email', 'groups' ] ] ];
    ```
  - Generic client settings: client authentication `client_secret_basic` or `client_secret_post`, or for public apps "No secret; use PKCE with S256"; scopes.
  - For machine-to-machine apps: `curl -u '<client id>:<secret>' -d grant_type=client_credentials <issuer>/oauth/token`.
- **"Regenerate secret".** Confidential apps only, behind a confirm: "The old secret stops working straight away."
- **"Delete application".** Type the name to confirm.

**When the secret page appears.** These all answer 200 with `admin_secret.html` instead of redirecting:
- creating a confidential app;
- regenerating its secret;
- switching an app to confidential.

The page has the heading "Copy the client secret now" and the intro "You won't be able to see it again. If you lose it, regenerate it from the app's page." Its items are the client ID and the secret. Its back link goes to the app's page.

- [ ] **Step 1: Tests**

```go
func TestAppsList(t)                       // confidential app with group Laser -> "Keeps a secret" and a "Laser" chip; public app -> "No secret" and "Everyone"
func TestCreateConfidentialAppShowsSecretOnce(t) // POST -> 200 page with the client ID and a 43-char secret whose HashToken equals the stored hash;
                                           // GET /admin/apps/{id} afterwards does not contain the secret
func TestCreatePublicApp(t)                // client_type=public -> 303 /admin/apps/{id}?notice=saved
func TestAppFormErrors(t)                  // Review Focus 5: redirect_uris "https://a/cb\r\n\r\n  https://a/cb  \r\n/relative" -> 422 containing "Line 4 isn't a full web address",
                                           // the textarea keeps the input; access_token_ttl "soon" -> 422 "Use a time like 1h or 30d."; access_token_ttl "25h" -> 422 "between 1m and 24h"
func TestEditApp(t)                        // allowed_groups, subject_mode=email, access_token_ttl "2h" -> 2h stored and shown back as "2h"; blank -> 0;
                                           // show_tile, launch_url, description saved; machine=on with a service account -> ServiceAccountID set; machine off -> ""
func TestSubjectModeWarning(t)             // authentik_uid -> body contains "Switch to Latch ID once the app no longer needs Authentik's identifiers."; id -> it does not
func TestSetupDetails(t)                   // body has the issuer, "/.well-known/openid-configuration", "'clientID' => '<client id>'"; public app page has "PKCE" and no LocalSettings snippet
func TestRegenerateSecret(t)               // POST rotate-secret -> 200 with a new secret; /oauth/introspect as the app with the old secret -> 401, with the new -> 200
func TestSwitchToConfidentialShowsSecret(t)// public app saved with client_type=confidential -> 200 secret page
func TestDeleteAppConfirm(t)               // wrong name -> 422; right -> 303 /admin/apps?notice=deleted and app gone
```

- [ ] **Step 2: Run** `go test ./internal/web/ -run 'App|Secret|Subject|Setup'` and expect it to FAIL.
- [ ] **Step 3: Implement** the handlers and templates.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(web): admin applications pages with setup details and one-time secrets`

---

### Task 10: Application icons

**Files:**
- Create: `internal/web/admin_icons.go`, `internal/web/admin_icons_test.go`
- Modify:
  - `internal/web/admin_apps.go` and `templates/admin_app.html`: the edit form becomes `multipart/form-data`, with an `icon` file field and a `remove_icon` checkbox.
  - `internal/web/server.go`: `GET /icons/{name}` on the root mux, without a session lookup.
  - `internal/testenv/testenv.go`: `SubmitMultipart`.

**Interfaces:**
- Consumes: `UpdateApp` with `IconURL`; `Cfg.DataDir`.
- Produces:
  - `func (s *Server) saveIcon(appID string, data []byte) (iconURL string, problem string, err error)`. `problem` is a field message for a bad upload.
  - `func (s *Server) removeIconFile(iconURL string)`.
  - the `/icons/{name}` route.

**Rules:**
- **Where icons live.** Files go in `<data_dir>/icons/`, which is created with mode 0750.
- **File names.** A name is `<app ID>-<first 12 hex of sha256(data)>.<ext>`. The icon URL is `/icons/<name>`.
- **Accepted types.** The type is sniffed with `http.DetectContentType`: `image/png` gives `png`, `image/jpeg` gives `jpg`, `image/gif` gives `gif`, `image/webp` gives `webp`. Anything else, including SVG, gets "Use a PNG, JPEG, GIF or WebP image."
- **Size.** Over 262144 bytes gets "That image is bigger than 256 KB. Use a smaller one."
- **Saving the form.** The upload happens in the same submission as the other fields. A bad icon re-renders with 422 and saves nothing. The edit handler accepts both form encodings.
- **Cleanup.** After a successful replace or `remove_icon`, the old `/icons/` file is deleted. Deleting the app deletes its file. Cleanup failures are only logged.
- **Serving.** `GET /icons/{name}` serves only names matching `^[0-9a-f-]{36}-[0-9a-f]{12}\.(png|jpg|gif|webp)$`. The `Content-Type` comes from the extension, with `Cache-Control: public, max-age=31536000, immutable`. Anything else is 404.

- [ ] **Step 1: Tests**

```go
func TestUploadIcon(t)             // multipart save with a 1x1 PNG (image/png encoder) -> 303; IconURL matches ^/icons/<app id>-[0-9a-f]{12}\.png$;
                                   // GET it -> 200, Content-Type image/png, X-Content-Type-Options nosniff, same bytes; the member home <img> uses it
func TestIconRejected(t)           // 300 KB of PNG data -> 422 "bigger than 256 KB"; "<svg xmlns=...>" -> 422 "Use a PNG, JPEG, GIF or WebP image."; IconURL unchanged
func TestReplaceAndRemoveIcon(t)   // second upload: the first file no longer exists in data_dir/icons; remove_icon=on -> IconURL "" and file gone;
                                   // deleting the app removes its icon file
func TestIconRouteRejectsBadNames(t) // GET /icons/..%2Flatch.db, /icons/x.svg, /icons/<valid-looking name that does not exist> -> 404
```

- [ ] **Step 2: Run** `go test ./internal/web/ -run Icon` and expect it to FAIL.
- [ ] **Step 3: Implement** icon saving, serving and cleanup.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(web): upload, serve and clean up application icons`

---

### Task 11: Service accounts pages

**Files:**
- Create: `internal/web/admin_service_accounts.go`, templates `admin_service_accounts.html`, `admin_service_account.html`, `internal/web/admin_service_accounts_test.go`

**Interfaces:**
- Consumes:
  - the admin service's service-account and token methods;
  - `store.ListUsers` (`Type: service`), `store.ListAPITokens` and `store.ListApplications`;
  - `admin_secret.html` (Task 9).
- Produces:

  | Route | Purpose |
  |---|---|
  | `GET /admin/service-accounts` | list |
  | `GET /admin/service-accounts/new` | add form |
  | `POST /admin/service-accounts` | create |
  | `GET /admin/service-accounts/{id}` | edit page |
  | `POST /admin/service-accounts/{id}` | save |
  | `POST /admin/service-accounts/{id}/tokens` | fields `label`, `scope` (`admin` or `read`, default `read`), `expires_days` (`""` for never, the default, or `30`, `90`, `365`) |
  | `POST /admin/service-accounts/{id}/tokens/{tid}/revoke` | |
  | `POST /admin/service-accounts/{id}/delete` | field `confirm` |

**List page.**
- Intro: "Service accounts are for scripts and devices, like a door controller. They can't use the sign-in pages; they use API tokens, or sign in to apps by themselves."
- Columns: name, username, group chips, tokens (count), last used (`ago` of `TokenLastUsed`).

**Form.** "Name", "Username", "Description", groups and metadata.

**Edit page.**
- **Tokens table:** label; access ("Full admin" or "Read only"); made (date and creator name); last used; expires (date or "Never"). Each row has a Revoke button behind a confirm.
- **"New API token" form.**
- **Machine sign-in:** "Apps that sign in as this account", listing the apps whose `ServiceAccountID` is this account.
- **Delete:** type the name to confirm. The warning says how many tokens will stop working and which apps lose machine sign-in.

**Token created.** Creating a token answers 200 with `admin_secret.html`:
- heading "Copy the API token now";
- item "Token";
- example `curl -H "Authorization: Bearer <token>" <issuer>/api/v1/me`.

- [ ] **Step 1: Tests**

```go
func TestServiceAccountsList(t)     // "Door controller" with 2 tokens shows 2 and its group chip; a member is absent
func TestCreateServiceAccount(t)    // POST -> 303 /admin/service-accounts/{id}?notice=saved; Type service; no username -> 422 "Enter a username."
func TestCreateTokenShowsOnce(t)    // POST tokens label "Door", scope read, expires_days 30 -> 200 with a "latch_" token and the curl example;
                                    // stored ExpiresAt within a minute of now+30d; account page lists "Door" and "Read only" and never the token
func TestRevokeTokenUI(t)           // POST revoke -> 303 ?notice=token_revoked; ListAPITokens empty
func TestServiceAccountShowsApps(t) // an app with ServiceAccountID = account -> its name under "Apps that sign in as this account"
func TestDeleteServiceAccount(t)    // wrong name -> 422; right -> 303 /admin/service-accounts?notice=deleted; tokens gone; app.ServiceAccountID ""
func TestServiceAccountPagesRejectMembers(t) // /admin/service-accounts/{member ID} -> 404
```

- [ ] **Step 2: Run** `go test ./internal/web/ -run ServiceAccount` and expect it to FAIL.
- [ ] **Step 3: Implement** the handlers and templates.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(web): admin service accounts pages with API tokens`

---

### Task 12: Audit log page

**Files:**
- Create: `internal/web/admin_audit.go`, template `admin_audit.html`, `internal/web/admin_audit_test.go`
- Modify: `templates/admin_member.html`, `admin_group.html`, `admin_app.html` and `admin_service_account.html`. Each gains a "View activity" link to `/admin/audit?target=<id>&category=all`.

**Interfaces:**
- Consumes: `store.ListAuditEvents` with `CollapseLoginFailures: true`; `store.GetUser`, `GetGroup` and `GetApplication` for names.
- Produces: `GET /admin/audit?category=&action=&from=&to=&q=&actor=&target=&page=`. When `action` is set, that one action prefix replaces the category's list.

```go
var auditCategories = []struct{ Key, Label string; Actions []string }{
    {"changes", "Changes", []string{"user.", "group.", "app.", "service_account.", "api_token.", "settings.", "oidc.key."}},
    {"signins", "Sign-ins", []string{"login.", "logout", "oidc.authorize."}},
    {"tokens", "App tokens", []string{"oidc.token."}},
    {"all", "Everything", nil},
}
```

**Filters.**
- `category` defaults to `changes`.
- `from` and `to` are `YYYY-MM-DD`. `from` defaults to 30 days ago and sets `Since` (§7). `to` is inclusive, so `Until` is the day after. A bad date falls back to the default.
- `q` searches the summary.

**Table columns:**
- **When:** `datetime`.
- **Who:** the actor, linking to `?actor=<id>`. A user or service account shows their name, or their email when the name is empty. `system` shows "Latch" and `importer` shows "Importer". An ID that no longer exists shows "Deleted account".
- **What:** the summary, followed by "(N times)" when `Count > 1`, and the action name as small text linking to `?action=<action>&category=all`.
- **About:** the target's name, linking to its admin page when the target is a user, service account, group or application that still exists.

Each distinct ID on the page is looked up once. While `actor` or `target` is set, a line names whose activity is shown, with a link that clears it. Rows are paginated at 50.

- [ ] **Step 1: Tests**

```go
func TestAuditDefaultsToChangesLast30Days(t) // user.update today, oidc.token.issued today, user.create 40 days ago -> only the user.update summary is shown
func TestAuditCategoriesAndRange(t)   // ?category=signins shows a login.success and not the user.update; ?category=all&from=<60 days ago> shows the 40-day-old event
func TestAuditCollapsedFailures(t)    // 4 login.failure events for Alex within one hour -> one row containing "(4 times)"
func TestAuditNamesAndLinks(t)        // actor shown as the admin's name linking to ?actor=<id>; target member linking to /admin/members/<id>;
                                      // an actor ID with no user -> "Deleted account"; ActorSystem -> "Latch"
func TestAuditFilterByTarget(t)       // ?target=<Alex ID>&category=all shows only Alex's events; Alex's member page links there
func TestAuditFilterByAction(t)       // ?action=group.member. shows group.member.add and group.member.remove rows only; each row's action links to ?action=<action>
```

- [ ] **Step 2: Run** `go test ./internal/web/ -run Audit` and expect it to FAIL.
- [ ] **Step 3: Implement** the audit page and the "View activity" links.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(web): audit log page with categories, date range and collapsed failures`

---

### Task 13: API foundation

**Files:**
- Create: `internal/api/api.go` (`New`, `Deps`, the `routes` table, middleware), `internal/api/respond.go` (JSON writing, decoding, error mapping), `internal/api/me.go`, `internal/api/openapi.json`, `internal/api/openapi.go` (embed and serve), `internal/api/api_test.go` (`package api_test`, using testenv), `internal/api/openapi_test.go` (`package api`)
- Modify:
  - `internal/web/server.go`: `root.Handle("/api/", api.New(api.Deps{Admin: s.admin, Store, Log, Now}))`, outside the session middleware.
  - `internal/testenv/testenv.go`: `APIToken` and `API`.

**Interfaces:**
- Consumes: `admin.Service.AuthenticateToken`, `Caller.Actor`, the error types, and `ratelimit.New`.
- Produces:
  - `api.New`;
  - `GET /api/v1/me`, which returns `{"service_account": <service account>, "token": <token>}`;
  - `GET /api/v1/openapi.json`, which is public;
  - the `routes` table, `[]route{method, path string; ...}`, with paths relative to `/api/v1` (for example `/users/{id}`), so the OpenAPI test can read it;
  - `func writeError(w http.ResponseWriter, status int, code, message string)`;
  - `func (h *handler) fail(w http.ResponseWriter, r *http.Request, err error)`, which maps the admin errors to the API error table;
  - `func decode(w http.ResponseWriter, r *http.Request, v any) bool`, which uses `DisallowUnknownFields` and answers 400 `invalid_json` itself.

**Middleware order** inside `New`, outermost first:
1. Recover: a panic becomes JSON 500 `internal`.
2. Body limit: 1 MiB, answering JSON 413 `too_large`.
3. The public OpenAPI route.
4. Bearer authentication: 401 `unauthorized`, message "Send a valid API token in the Authorization header.", with `WWW-Authenticate: Bearer`.
5. Scope: a `read` token on anything but `GET` or `HEAD` gets 403 `forbidden`, message "This token can only read. Use a token with full admin access to make changes." This runs before routing.
6. Rate limit: `ratelimit.New(600, time.Minute)`, keyed by token ID, with `Deps.Now` as its clock. Over the limit gets 429 `rate_limited` with `Retry-After: 60`.
7. The router. An unknown path gets 404 `not_found`. A known path with the wrong method gets 405 `method_not_allowed`.

Every response has `Content-Type: application/json` and `Cache-Control: no-store`. Cookies are ignored.

**The OpenAPI document** is hand-written, `openapi: 3.1.0`. It contains:
- `info.title` "Latch admin API" and `info.version` "1";
- `servers: [{url: "/api/v1"}]`;
- a bearer `securitySchemes` entry used globally;
- the shared JSON shapes as `components.schemas`: `User`, `Group`, `App`, `ServiceAccount`, `Token`, `AuditEvent`, `List` and `Error`;
- one operation per route, each with a summary and its responses.

In this task it describes `/me` only. Tasks 14 and 15 extend it with each route they add.

- [ ] **Step 1: Tests**

```go
// api_test.go
func TestAPIRequiresToken(t)       // Review Focus 4: no header, "Bearer junk", expired token, revoked token, token of a deleted service account ->
                                   // 401, JSON {"error":"unauthorized",...}, WWW-Authenticate "Bearer", Content-Type application/json
func TestAPIIgnoresCookies(t)      // AdminClient's browser session cookie and no Authorization header -> 401
func TestAPIMe(t)                  // read token -> 200, service_account.username = "door", token.scope = "read", no "token" or "token_hash" key
func TestAPIReadScopeCannotWrite(t)// read token POST /api/v1/me -> 403 {"error":"forbidden"}; admin token POST /api/v1/me -> 405 {"error":"method_not_allowed"}
func TestAPIRateLimit(t)           // 600 GET /me succeed; the 601st -> 429 rate_limited with Retry-After "60"; a second token still gets 200;
                                   // env.Clock.Advance(61s) -> the first token gets 200 again
func TestAPIUnknownRoute(t)        // GET /api/v1/nope -> 404 {"error":"not_found"}
func TestAPIBodyLimit(t)           // admin token, POST with Content-Length 2<<20 -> 413 {"error":"too_large"}
func TestOpenAPIServed(t)          // no token: GET /api/v1/openapi.json -> 200, openapi starts "3.", info.title "Latch admin API"
// openapi_test.go
func TestOpenAPIMatchesRoutes(t)   // every routes entry is in paths with its lower-case method, and every path+method in the document is a route
```

- [ ] **Step 2: Run** `go test ./internal/api/` and expect it to FAIL.
- [ ] **Step 3: Implement** the package, mount it, and add the testenv helpers.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(api): admin API skeleton with bearer tokens, scopes, rate limit and OpenAPI`

---

### Task 14: API: members and groups

**Files:**
- Create: `internal/api/users.go`, `internal/api/groups.go`, `internal/api/users_test.go`, `internal/api/groups_test.go`
- Modify: `internal/api/api.go` (routes), `internal/api/openapi.json`

**Interfaces:**
- Consumes: the member and group methods, `ResolveMember`, `ResolveGroup`, `ResolveGroups`, `ParseMetadata`, `store.ListUsers` and `store.ListGroupsWithCounts`.
- Produces these routes (§8). `{id}` for a member is an ID or `email:<address>`; for a group it is an ID or `name:<name>`.

  | Method and path | Body | Response |
  |---|---|---|
  | `GET /users` | `?q=&group=&status=&page=&per_page=`; `group` is a name or ID | list of members |
  | `POST /users` | `{name, email, username, groups, metadata, invite, password}` | 201 user; adds `"invite_error"` when the invitation was not sent |
  | `GET /users/{id}` | | user |
  | `PATCH /users/{id}` | `{name, email, username, groups, metadata, is_active}`; `null` or absent leaves a field alone; `""` clears `username` | user |
  | `DELETE /users/{id}` | | 204 |
  | `POST /users/{id}/reset-email` | | `{"sent": "invite"}` or `{"sent": "reset"}`; 502 `email_failed` |
  | `POST /users/{id}/password` | `{"password"}` | 204 |
  | `POST /users/{id}/totp/clear` | | 204 |
  | `POST /users/{id}/sessions/revoke` | | 204 |
  | `PUT /users/{id}/groups` | `{"groups": [...]}` | user |
  | `POST /users/{id}/groups/{group}` | | user |
  | `DELETE /users/{id}/groups/{group}` | | user |
  | `GET /groups` | | list; every group, unpaginated |
  | `POST /groups` | `{name, description, is_admin, require_totp, metadata}` | 201 group |
  | `GET /groups/{id}` | | group |
  | `PATCH /groups/{id}` | as POST, all optional | group |
  | `DELETE /groups/{id}` | | 204 |
  | `GET /groups/{id}/members` | `?page=&per_page=` | list of `{id, type, name, email, username}` |

`metadata` is decoded as `json.RawMessage` and passed through `admin.ParseMetadata`, so a non-object gets 422 `invalid`, the same as the pages.

- [ ] **Step 1: Tests**

```go
// users_test.go
func TestAPIUsersList(t)          // ?q=priya; ?status=disabled; ?group=Laser; envelope has items, page 1, per_page 50, total; per_page=500 -> per_page 200;
                                  // the service account never appears
func TestAPICreateUser(t)         // POST {"name","email","groups":["Laser"],"invite":true} -> 201, status "invited", groups ["Laser"]; invite email sent;
                                  // audit user.create actor_type service_account with detail.token_id = the token's ID
func TestAPICreateUserErrors(t)   // duplicate email in another case -> 422 {"error":"invalid","fields":{"email":"Another member already uses that email address."}};
                                  // {"emial": "x"} -> 400 invalid_json; body "nope" -> 400 invalid_json; "metadata": [1] -> 422 fields.metadata
func TestAPIGetPatchDeleteUser(t) // GET by ID and by email:ALEX@example.org; PATCH {"name":"New"} keeps email and groups;
                                  // PATCH {"is_active":false} -> status "disabled" and the member's sessions are gone; DELETE -> 204, then GET -> 404
func TestAPIUserActions(t)        // reset-email -> {"sent":"reset"}; password "short" -> 422 fields.password; good -> 204; totp/clear -> 204; sessions/revoke -> 204
func TestAPIUserGroups(t)         // PUT {"groups":["Members","Laser"]}; POST /groups/Woodshop adds; DELETE /groups/Laser removes; PUT ["Nope"] -> 422 fields.groups
func TestAPIUserJSONHasNoSecrets(t) // no key of a user response contains "hash", "secret" or "password"
func TestAPIUsersRejectServiceAccounts(t) // GET /users/{service account ID} -> 404
// groups_test.go
func TestAPIGroups(t)             // list has member_count; POST 201; GET name:Laser; PATCH description; GET members lists both a member and a service account with "type"
func TestAPILastAdminGroup(t)     // Review Focus 3: PATCH {"is_admin":false} and DELETE on the only admin group -> 409 {"error":"refused","message":"This is the only admin group. ..."}
func TestAPIReadTokenCanList(t)   // read token: GET /users and GET /groups -> 200; POST /groups -> 403
```

- [ ] **Step 2: Run** `go test ./internal/api/` and expect it to FAIL.
- [ ] **Step 3: Implement** the handlers, their routes and their OpenAPI entries.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(api): members and groups endpoints`

---

### Task 15: API: applications, service accounts, tokens and audit

**Files:**
- Create: `internal/api/apps.go`, `internal/api/service_accounts.go`, `internal/api/audit.go`, `internal/api/apps_test.go`, `internal/api/service_accounts_test.go`, `internal/api/audit_test.go`
- Modify: `internal/api/api.go` (routes), `internal/api/openapi.json`

**Interfaces:**
- Consumes: the app, service-account and token methods, `ResolveApp`, `ResolveServiceAccount`, and `store.ListAuditEvents` (not collapsed).
- Produces these routes. `{id}` for an app is an ID or `slug:<slug>`; for a service account it is an ID or `username:<name>`.

  | Method and path | Body | Response |
  |---|---|---|
  | `GET /apps` | | list; unpaginated |
  | `POST /apps` | the app fields except `id`, `client_id` and timestamps; lifetimes in seconds | 201 app, plus `client_secret` for confidential apps |
  | `GET /apps/{id}` | | app |
  | `PATCH /apps/{id}` | as POST, all optional | app, plus `client_secret` when it became confidential |
  | `DELETE /apps/{id}` | | 204 |
  | `POST /apps/{id}/rotate-secret` | | `{"client_secret": "..."}` |
  | `GET /service-accounts` | `?q=&page=&per_page=` | list |
  | `POST /service-accounts` | `{name, username, description, groups, metadata}` | 201 |
  | `GET /service-accounts/{id}` | | service account |
  | `PATCH /service-accounts/{id}` | as POST, all optional | service account |
  | `DELETE /service-accounts/{id}` | | 204 |
  | `GET /service-accounts/{id}/tokens` | | list |
  | `POST /service-accounts/{id}/tokens` | `{label, scope, expires_at}`; `expires_at` is RFC 3339 or absent | 201 token, plus `token` |
  | `DELETE /service-accounts/{id}/tokens/{tid}` | | 204 |
  | `GET /audit` | `?since=&until=&actor=&action=&target=&q=&page=&per_page=`; `since` and `until` are RFC 3339 or `YYYY-MM-DD`; `action` is one prefix | raw events, newest first |

- [ ] **Step 1: Tests**

```go
// apps_test.go
func TestAPIApps(t)               // POST confidential -> 201 with a 43-char client_secret; GET has no client_secret; PATCH redirect_uris; GET slug:members-wiki;
                                  // rotate-secret returns a different secret; DELETE 204
func TestAPIAppValidation(t)      // access_token_ttl 90000 -> 422 fields.access_token_ttl; subject_mode "guess" -> 422 fields.subject_mode
func TestAPICreatedAppSignsIn(t)  // POST a public app with redirect_uris ["http://127.0.0.1/cb"] -> env.Authorize with PKCE and env.Exchange succeed for a member
// service_accounts_test.go
func TestAPIServiceAccounts(t)    // POST, GET username:door, PATCH description, list excludes members; DELETE -> its tokens stop working (401 on /me)
func TestAPITokens(t)             // POST {"label":"door","scope":"read"} -> 201 with "token" starting latch_ that works on /me; GET list has no "token" key;
                                  // expires_at in the past -> 422 fields.expires_at; DELETE -> 204 and the token -> 401
// audit_test.go
func TestAPIAudit(t)              // after an API create: GET /audit?action=user. returns user.create first with actor_type "service_account";
                                  // 3 login.failure events in one hour come back as 3 rows; since=<tomorrow> -> total 0
```

- [ ] **Step 2: Run** `go test ./internal/api/` and expect it to FAIL.
- [ ] **Step 3: Implement** the handlers, their routes and their OpenAPI entries.
- [ ] **Step 4: Run** `go test ./... && go vet ./...` and expect it to PASS.
- [ ] **Step 5: Commit** `feat(api): applications, service accounts, tokens and audit endpoints`

---

### Task 16: End to end, copy check, README

**Files:**
- Create: `internal/web/admin_smoke_test.go`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything above, plus `go-oidc` and `oauth2`, as in `smoke_test.go`.
- Produces: no new code. These tests exercise wiring and copy, and the README describes the new surface.

- [ ] **Step 1: Tests**

```go
func TestSmokeAdminOnboarding(t)   // the spec's one-minute onboarding, through the pages only. The admin client:
                                   //   creates group Laser;
                                   //   creates a confidential app with a tile, allowed group Laser, redirect to a test callback, and copies the secret;
                                   //   adds a member with setup=invite and Laser ticked.
                                   // Then: follow the emailed link, choose a password, sign in.
                                   // The home page shows the app tile. A go-oidc code flow with the copied secret yields an ID token whose groups claim contains "Laser".
func TestSmokeMachineToMachine(t)  // through the pages: create service account "door" in Laser; create a token; create a confidential app with machine sign-in as "door".
                                   // client_credentials at /oauth/token gives an access token whose preferred_username is "door" and whose groups contain "Laser".
                                   // GET /api/v1/me with the token answers username "door".
func TestAdminCopyAvoidsJargon(t)  // seed one of everything, then GET every admin page:
                                   //   the lists; each edit page; each new form; the secret page (from a create); settings; audit with category=all.
                                   // With <pre> and <code> contents removed, no body matches (?i)\b(provider|flow|stage|binding)s?\b.
```

- [ ] **Step 2: Run** `go test ./internal/web/ -run 'Smoke|Jargon'`. It should PASS straight away; a failure points at a wiring or copy gap in an earlier task, so fix it there.
- [ ] **Step 3: README**
  - Replace "Applications will be registered in the admin UI, which is not built yet (see Status)" with how to register an app: Admin pages → Applications → Add application, and copy the secret when it is shown.
  - In "Connecting MediaWiki", point to the app's Setup details panel for a filled-in snippet.
  - Add an "Admin pages" section: what lives under `/admin`; that it needs the Admin group and two-step sign in; and what each sidebar entry is for, one line each.
  - Add an "Admin API" section:
    - create a service account and a token on the Service accounts page;
    - `curl -H "Authorization: Bearer latch_…" https://login.example.org/api/v1/me`;
    - read-only versus full admin tokens;
    - 600 requests a minute;
    - the OpenAPI document at `/api/v1/openapi.json`.
  - Update "Status": the admin pages and the admin API work; the Authentik importer is next.
- [ ] **Step 4: Run** `go vet ./... && go test -race ./...` and expect it to PASS. Then do a manual check: `make run`, sign in as the admin, add a member with "Set a password now", and add an application. Bind the server to `0.0.0.0` for viewing from another machine.
- [ ] **Step 5: Commit** `test: admin onboarding and machine sign-in end to end; docs: admin pages and API`

---

## Self-review notes

**Spec coverage:**

| Spec section | Where |
|---|---|
| §4 ApiToken | Task 1 schema; Task 4 service; Task 11 pages; Task 15 API |
| §4 service account description | Task 1 column; Task 4; Task 11 |
| §6.4 subject mode with explanation and warning | Task 9 |
| §6.5 machine-to-machine toggle and service-account picker | Task 9; end to end in Task 16 |
| §7 sidebar and admin check | Task 6 |
| §7 Members | Task 7 |
| §7 Service accounts | Task 11 |
| §7 Groups | Task 8 |
| §7 Applications | Tasks 9 and 10 |
| §7 Settings (branding, SMTP test, keys) | Task 6 |
| §7 Audit log | Task 12 |
| §7 plain language, red confirms | Global Constraints; Task 16 copy check |
| §8 every listed endpoint | Tasks 13–15 |
| §8 errors, read scope, 600/min, OpenAPI | Task 13 |
| §8 audit with token ID | Task 3 (`Actor.TokenID`), checked in Task 14 |
| §11 uploaded icons in `data_dir` | Task 10 |

§7's import status panel goes to the importer plan.

**Core decisions carry-forwards:**
- Invited members are active, and `user.invite` names the admin: Task 3.
- `ClearTOTP` deletes `totp_enrolments`: Task 1.
- Per-app lifetime caps: Task 5.
- `client_type` and `subject_mode` are validated: Task 5.
- "Sign out everywhere" deletes all sessions, so `DeleteOtherSessions` is not needed. The admin acts on someone else, and signing yourself out everywhere is expected.
- `MaxBytesReader`: Task 6.

**Rulings made while planning:**
- **Un-flagging the last admin group** is refused like deleting it (same lockout).
- **Self-lockout.** Admins cannot disable or delete themselves, or untick their own last admin group. The CLI `create-admin` remains the break-glass.
- **Service-account disabling.** Service accounts have no disable switch in v1; delete one or revoke its tokens. `AuthenticateToken` still checks `IsActive`, so an inactive account written by a later importer is safe.
- **Admin emails are synchronous.** Invite and reset emails sent by an admin, unlike the public reset form, so a failure is shown. Address enumeration is not a concern for admins.
- **Icon URLs** must be https, because the CSP's `img-src` allows only `'self'` and `https:`. Uploads are the alternative.
- **Default audit view.** It hides app token issuance ("Changes"), which otherwise buries admin changes.
- **API lifetimes** are whole seconds under the same names as the form fields, so `fields` keys match both.

**Type consistency:**
- `ValidationError.Fields` keys are the form field names and the JSON keys alike.
- `Section` values in Task 6 match the routes in Tasks 7–12.
- `admin.Keys` is satisfied by `*oidc.KeyManager` once Task 5 adds `RotateAs`.
- `UserFilter.Status` values are the members filter values (Task 7) and the API `status` values (Task 14).

**Review Focus pins:**

| Item | Tests |
|---|---|
| 1. Email differing only in case | Task 3 `TestCreateMemberValidation`; Task 7 `TestAddMemberErrorsKeepInput` |
| 2. Bad metadata | Task 3 `TestParseMetadata`; Task 7 `TestAddMemberErrorsKeepInput` |
| 3. Locking yourself or everyone out | Task 3 `TestSelfProtection`; Task 4 `TestLastAdminGroupRefused`; Task 7 `TestAdminCannotLockThemselvesOut`; Task 8 `TestLastAdminGroupRefusedInUI`; Task 14 `TestAPILastAdminGroup` |
| 4. API calls that must fail cleanly | Task 13 `TestAPIRequiresToken` and `TestAPIReadScopeCannotWrite` |
| 5. Messy return addresses | Task 5 `TestRedirectURICleanup`; Task 9 `TestAppFormErrors` |

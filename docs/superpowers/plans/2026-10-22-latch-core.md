# Latch Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A running Latch binary that can be initialised, hold users/groups/applications in SQLite, log members in (with legacy Authentik hashes and TOTP), reset passwords by email, and act as a complete OIDC provider that MediaWiki and a PKCE SPA can authenticate against.

**Architecture:** One Go module, stdlib `net/http` with Go 1.22+ method patterns, server-side sessions in SQLite, `html/template` pages embedded in the binary. A `store` package owns all SQL; `password`, `totp`, `secrets`, `mail`, `ratelimit` are small leaf packages; `oidc` implements the provider endpoints over `store` and a `KeyManager`; `web` wires handlers, middleware and templates. The CLI in `cmd/latch` dispatches subcommands.

**Tech Stack:** Go 1.27 (installed: 1.27.1), `modernc.org/sqlite` (pure Go), `gopkg.in/yaml.v3`, `golang.org/x/crypto` (argon2, pbkdf2, bcrypt, scrypt), `github.com/go-jose/go-jose/v4` (JWS/JWK), `github.com/pquerna/otp` (TOTP + QR), `github.com/wneessen/go-mail` (SMTP). Test-only: `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`.

**Spec:** `docs/superpowers/specs/2026-10-22-makerspace-idp-design.md`

**Sibling plans (written after this one lands, they depend on these interfaces):**
- `latch-admin`: admin UI (§7), admin REST API (§8), service accounts and API tokens (§4, §6.5 toggle UI), audit log UI.
- `latch-import`: Authentik importer (§10), local Authentik dev stack (§13), Dockerfile, systemd unit, `/metrics`, `docs/cutover.md` (§11).

This plan creates the schema columns those plans need (`users.type`, `applications.service_account_id`, `authentik_*`) so they add tables, not alter them.

## Global Constraints

- Module path `latch`. Go `1.27` in `go.mod`. No cgo.
- Issuer is `public_url` exactly, no trailing slash (§6.1).
- Native password hash: argon2id PHC string, `m=65536,t=3,p=4` (§9; builder may raise, never lower).
- Legacy formats verified: `argon2$argon2id`, `argon2$argon2i`, `pbkdf2_sha256`, `pbkdf2_sha1`, `scrypt`, `bcrypt_sha256`; `!…`/empty is unusable (§9).
- Password minimum 10 characters, reject embedded top-10k list, no composition rules (§5).
- Throttles: login 10/account/15min, 50/IP/15min; reset 3/account/hour (§5).
- Lifetimes: code 60s single use; access 1h; ID 1h; refresh 30d sliding, 90d absolute; session 14d idle, 30d absolute (§6.2).
- Scopes `openid profile email groups offline_access`; claims per §6.3 table; `groups` is an array of group **names**.
- Signing: RS256, RSA 2048, `kid` per key; JWKS publishes non-retired keys (§4 SigningKey).
- Never log passwords, tokens, codes or secrets (§11).
- All member-facing pages work without JavaScript (§5). Plain-language copy; the words "provider", "flow", "stage", "binding" never appear in UI (§2 anti-goals).
- Cookie `latch_session`: HttpOnly, SameSite=Lax, Secure when `public_url` is https.
- Secrets at rest (TOTP secrets, signing private keys) encrypted with AES-256-GCM under `encryption_key` (§3, §11).

## Review Focus

Inputs the spec implies but no happy-path test covers; each has a pinned test in the owning task.

1. Email entered as `" Alex@Example.ORG "` at login must match the stored `alex@example.org` (Task 12).
2. `next` after login must be a same-site path; `next=https://evil.example` or `//evil.example` redirects to `/` (Task 12).
3. Redirect URI `https://wiki.example.org/callback/` (trailing slash) or a different port must be rejected when only `https://wiki.example.org/callback` is registered; `http://127.0.0.1:51234/cb` matches a registered `http://127.0.0.1/cb` (Task 16).
4. A refresh token for a user disabled after issuance must fail with `invalid_grant`, and the whole token family must be revoked (Task 17).
5. A reset link used twice, or after expiry, shows the branded "this link has expired" page with a link to request another, status 200, never a 500 or a raw error (Task 14).

---

## Shared interfaces

Every task's Interfaces block refers to these. Defined in Task 2 (`model`), Tasks 5–7 (`store`); later tasks must use these exact names.

```go
// internal/model/model.go
type UserType string      // "member" | "service"
type ClientType string    // "confidential" | "public"
type SubjectMode string   // "id" | "email" | "username" | "authentik_uuid" | "authentik_uid" | "authentik_pk"

type User struct {
    ID, Name            string
    Type                UserType
    Email, Username     string            // "" when unset
    PasswordHash        string            // native PHC, "" if none
    LegacyPasswordHash  string            // Django format, "" if none
    IsActive            bool
    Metadata            map[string]any    // never nil after load
    TOTPSecretEnc       []byte            // nil if not enrolled
    TOTPConfirmedAt     *time.Time
    AuthentikPK         *int64
    AuthentikUUID, AuthentikUID string
    LastLoginAt         *time.Time
    CreatedAt, UpdatedAt time.Time
}
func (u *User) HasPassword() bool   // PasswordHash != "" || LegacyPasswordHash != ""
func (u *User) TOTPEnrolled() bool  // TOTPConfirmedAt != nil

type Group struct {
    ID, Name, Description string
    IsAdmin, RequireTOTP  bool
    Metadata              map[string]any
    AuthentikUUID         string
    CreatedAt, UpdatedAt  time.Time
}

type Application struct {
    ID, Name, Slug, ClientID string
    ClientSecretHash         string   // "" for public
    ClientType               ClientType
    RedirectURIs             []string
    PostLogoutRedirectURIs   []string
    AllowedGroupIDs          []string // empty = anyone active
    SubjectMode              SubjectMode
    AccessTokenTTL, RefreshTokenTTL, IDTokenTTL time.Duration // 0 = use global default
    LaunchURL, IconURL, Description string
    ShowTile                 bool
    ServiceAccountID         string   // "" = client_credentials disabled
    AuthentikProviderPK      *int64
    CreatedAt, UpdatedAt     time.Time
}

type Session struct {
    ID, UserID       string
    CreatedAt        time.Time   // == auth_time for OIDC
    LastSeenAt, ExpiresAt time.Time
    TOTPPassed       bool
    IP, UserAgent    string
}

type AuthCode struct {
    CodeHash, ApplicationID, UserID, SessionID string
    RedirectURI, Scope, Nonce                  string
    CodeChallenge, CodeChallengeMethod         string
    AuthTime, ExpiresAt                        time.Time
    UsedAt                                     *time.Time
}

type RefreshToken struct {
    TokenHash, FamilyID, ApplicationID, UserID, Scope, Nonce string
    AuthTime, CreatedAt, ExpiresAt, AbsoluteExpiresAt        time.Time
    RevokedAt                                                *time.Time
}

type ResetPurpose string // "reset" | "invite"
type ResetToken struct {
    TokenHash, UserID string
    Purpose           ResetPurpose
    CreatedAt, ExpiresAt time.Time
    UsedAt            *time.Time
}

type SigningKey struct {
    KID, Alg          string      // Alg always "RS256"
    PrivateKeyEnc     []byte
    PublicKeyPEM      string
    CreatedAt         time.Time
    RetiredAt         *time.Time
}

type ActorType string // "user" | "service_account" | "system" | "importer"
type AuditEvent struct {
    ID        string
    At        time.Time
    ActorType ActorType
    ActorID   string
    Action, TargetType, TargetID, Summary string
    Detail    map[string]any
}
```

```go
// internal/store/store.go
var ErrNotFound = errors.New("store: not found")
var ErrConflict = errors.New("store: conflict")   // unique violation
type Store struct { db *sql.DB }
func New(db *sql.DB) *Store

// users.go
func (s *Store) CreateUser(ctx, u *model.User) error            // fills ID/timestamps if empty; ErrConflict on email/username
func (s *Store) GetUser(ctx, id string) (*model.User, error)
func (s *Store) GetUserByEmail(ctx, email string) (*model.User, error)  // trims, case-insensitive
func (s *Store) GetUserByUsername(ctx, username string) (*model.User, error)
func (s *Store) UpdateUser(ctx, u *model.User) error            // all columns except password/totp
func (s *Store) SetPassword(ctx, userID, phcHash string) error  // sets PasswordHash, clears LegacyPasswordHash
func (s *Store) SetTOTP(ctx, userID string, secretEnc []byte, confirmedAt *time.Time) error
func (s *Store) ClearTOTP(ctx, userID string) error             // also deletes recovery codes
func (s *Store) TouchLastLogin(ctx, userID string, at time.Time) error
func (s *Store) ReplaceRecoveryCodes(ctx, userID string, codeHashes []string) error
func (s *Store) ConsumeRecoveryCode(ctx, userID, codeHash string) (bool, error)
func (s *Store) CountUnusedRecoveryCodes(ctx, userID string) (int, error)

// groups.go
func (s *Store) CreateGroup(ctx, g *model.Group) error
func (s *Store) GetGroup(ctx, id string) (*model.Group, error)
func (s *Store) GetGroupByName(ctx, name string) (*model.Group, error)
func (s *Store) ListGroups(ctx) ([]model.Group, error)
func (s *Store) ListGroupsForUser(ctx, userID string) ([]model.Group, error)   // ordered by name
func (s *Store) AddMember(ctx, userID, groupID string) error                   // idempotent
func (s *Store) RemoveMember(ctx, userID, groupID string) error

// apps.go
func (s *Store) CreateApplication(ctx, a *model.Application) error
func (s *Store) GetApplication(ctx, id string) (*model.Application, error)
func (s *Store) GetApplicationByClientID(ctx, clientID string) (*model.Application, error)
func (s *Store) GetApplicationBySlug(ctx, slug string) (*model.Application, error)
func (s *Store) ListApplications(ctx) ([]model.Application, error)
func (s *Store) UpdateApplication(ctx, a *model.Application) error
func (s *Store) ListTileApplicationsForUser(ctx, userID string) ([]model.Application, error) // ShowTile && LaunchURL != "" && allowed

// sessions.go
func (s *Store) CreateSession(ctx, sess *model.Session) error
func (s *Store) GetSession(ctx, id string) (*model.Session, error)   // ErrNotFound if expired
func (s *Store) UpdateSession(ctx, sess *model.Session) error       // LastSeenAt, ExpiresAt, TOTPPassed
func (s *Store) DeleteSession(ctx, id string) error
func (s *Store) DeleteSessionsForUser(ctx, userID string) error
func (s *Store) DeleteExpiredSessions(ctx) (int64, error)

// oauth.go
func (s *Store) CreateAuthCode(ctx, c *model.AuthCode) error
func (s *Store) ConsumeAuthCode(ctx, codeHash string) (*model.AuthCode, error) // atomic: ErrNotFound if missing, used, or expired
func (s *Store) CreateRefreshToken(ctx, t *model.RefreshToken) error
func (s *Store) GetRefreshToken(ctx, tokenHash string) (*model.RefreshToken, error) // returns revoked/expired too; caller checks
func (s *Store) RevokeRefreshToken(ctx, tokenHash string) error
func (s *Store) RevokeRefreshTokenFamily(ctx, familyID string) error
func (s *Store) RevokeRefreshTokensForUser(ctx, userID string) error

// reset.go
func (s *Store) CreateResetToken(ctx, t *model.ResetToken) error
func (s *Store) ConsumeResetToken(ctx, tokenHash string) (*model.ResetToken, error) // atomic; ErrNotFound if missing/used/expired
func (s *Store) HasActiveInviteToken(ctx, userID string) (bool, error)

// keys.go
func (s *Store) InsertSigningKey(ctx, k *model.SigningKey) error
func (s *Store) ListSigningKeys(ctx) ([]model.SigningKey, error)   // newest first, includes retired
func (s *Store) RetireSigningKey(ctx, kid string, at time.Time) error

// audit.go
func (s *Store) InsertAuditEvent(ctx, e *model.AuditEvent) error
```

File map for this plan:

```
go.mod, go.sum
cmd/latch/main.go                 CLI dispatch: init, serve, create-admin, reset-password, rotate-keys, version
internal/config/config.go         Config struct, Load, Validate, defaults
internal/config/config_test.go
internal/db/db.go                 Open (WAL, foreign keys), Migrate
internal/db/migrations/0001_core.sql
internal/db/db_test.go
internal/model/model.go           structs above
internal/secrets/secrets.go       RandomToken, HashToken, Encryptor
internal/password/password.go     Hash, Verify, IsLegacy, CheckPolicy; common.txt embedded
internal/password/legacy.go       Django formats
internal/password/password_test.go
internal/store/{store,users,groups,apps,sessions,oauth,reset,keys,audit}.go (+ _test.go)
internal/store/testutil.go        OpenTest(t) *Store
internal/ratelimit/ratelimit.go
internal/totp/totp.go
internal/mail/mail.go             Mailer, Message, Memory
internal/mail/smtp.go
internal/mail/templates.go        ResetEmail, InviteEmail
internal/audit/audit.go           Recorder
internal/session/session.go       Manager, middleware, FromContext
internal/web/server.go            Deps, New(...) http.Handler, routes
internal/web/render.go            templates, Brand, render helpers
internal/web/middleware.go        RealIP, logging, security headers, CSRF
internal/web/templates/*.html     frame, login, totp, logout, reset_request, reset_sent, reset_set, reset_expired, home, account_password, account_totp, account_totp_codes, no_access, signed_out, error
internal/web/static/latch.css
internal/web/auth.go              login/logout/totp handlers
internal/web/reset.go             reset request/set, invite
internal/web/account.go           home, password change, totp enrol/disable
internal/testenv/testenv.go       shared httptest harness (importable by web_test and oidc_test)
internal/oidc/keys.go             KeyManager
internal/oidc/claims.go           Subject, BuildClaims, scope parsing
internal/oidc/provider.go         Provider, Mount, discovery, jwks
internal/oidc/authorize.go
internal/oidc/token.go            token, userinfo, introspect, revoke
internal/oidc/logout.go
internal/oidc/e2e_test.go
```

---

### Task 1: Module, config loading

**Files:**
- Create: `go.mod`, `internal/config/config.go`, `internal/config/config_test.go`, `latch.example.yaml`

**Interfaces:**
- Produces:
  ```go
  type BrandingConfig struct{ Name, Logo string; PrimaryColor string `yaml:"primary_color"`; SupportText string `yaml:"support_text"` }
  type SMTPConfig struct{ Host string; Port int; Username, Password, From, TLS string }  // TLS: starttls|tls|none
  type SessionsConfig struct{ Idle, Absolute time.Duration }
  type TokensConfig struct{ Access, ID, Refresh time.Duration; RefreshAbsolute time.Duration `yaml:"refresh_absolute"`; RequireOfflineAccessForRefresh bool `yaml:"require_offline_access_for_refresh"` }
  type PasswordConfig struct{ MinLength int `yaml:"min_length"` }
  type LogConfig struct{ Level, Format string }
  type Config struct {
      PublicURL string `yaml:"public_url"`; Listen string; DataDir string `yaml:"data_dir"`
      TrustedProxies []string `yaml:"trusted_proxies"`; EncryptionKey string `yaml:"encryption_key"`
      Branding BrandingConfig; SMTP SMTPConfig; Sessions SessionsConfig; Tokens TokensConfig; Password PasswordConfig; Log LogConfig
  }
  func Load(path string, env func(string) string) (*Config, error) // yaml then LATCH_* overrides; path "" = defaults only
  func (c *Config) Validate() error
  func (c *Config) Issuer() string            // PublicURL with trailing slash stripped
  func (c *Config) SecureCookies() bool       // strings.HasPrefix(PublicURL, "https://")
  func (c *Config) DBPath() string            // filepath.Join(DataDir, "latch.db")
  ```
  Env override key: `LATCH_` + path upper-cased with `_` between levels, e.g. `LATCH_SMTP_HOST`, `LATCH_BRANDING_PRIMARY_COLOR`, `LATCH_TOKENS_REQUIRE_OFFLINE_ACCESS_FOR_REFRESH`. Durations parse with `time.ParseDuration`, with `d` suffix supported by a helper (`30d` = 720h).

- [ ] **Step 1: `go mod init latch`, set `go 1.27`, `go get gopkg.in/yaml.v3`**

- [ ] **Step 2: Write failing tests in `config_test.go`**

```go
func TestLoadDefaults(t *testing.T)        // Load("", noEnv): Listen=="0.0.0.0:8080", Sessions.Idle==336*time.Hour, Sessions.Absolute==720*time.Hour, Tokens.Access==time.Hour, Tokens.Refresh==720*time.Hour, Tokens.RefreshAbsolute==2160*time.Hour, Password.MinLength==10, Log.Format=="json"
func TestLoadYAMLAndEnvOverride(t *testing.T) // yaml sets smtp.host=a; env LATCH_SMTP_HOST=b; result "b"; LATCH_TOKENS_ACCESS="30m" -> 30*time.Minute; LATCH_SESSIONS_IDLE="7d" -> 168h
func TestValidate(t *testing.T)            // missing public_url -> error mentioning "public_url"; public_url "https://x/" -> Issuer()=="https://x"; encryption_key not 32 bytes base64 -> error; smtp.tls "foo" -> error; branding.primary_color "red" -> error (must be #rrggbb)
```

- [ ] **Step 3: Run `go test ./internal/config/` — expect compile failure**

- [ ] **Step 4: Implement `config.go` with the signatures above; write `latch.example.yaml` matching spec §11 verbatim**

- [ ] **Step 5: `go test ./internal/config/` — PASS**

- [ ] **Step 6: Commit** `feat(config): load yaml with env overrides and validation`

---

### Task 2: Model, database open, migrations, core schema

**Files:**
- Create: `internal/model/model.go`, `internal/db/db.go`, `internal/db/migrations/0001_core.sql`, `internal/db/db_test.go`

**Interfaces:**
- Produces: all `model` types from Shared interfaces; `func db.Open(path string) (*sql.DB, error)` (driver `sqlite`, DSN `file:<path>?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)`, `SetMaxOpenConns(1)` for writes is acceptable); `func db.Migrate(ctx, *sql.DB) (applied []string, err error)` using `embed.FS` of `migrations/*.sql`, table `schema_migrations(name TEXT PRIMARY KEY, applied_at TEXT)`, each file in one transaction, sorted by filename.

- [ ] **Step 1: `go get modernc.org/sqlite`**

- [ ] **Step 2: Write failing tests**

```go
func TestMigrateFreshAndIdempotent(t *testing.T) // Open(t.TempDir()+"/x.db"); Migrate -> applied==["0001_core.sql"]; Migrate again -> applied empty; table list contains users, recovery_codes, groups, memberships, applications, application_groups, sessions, auth_codes, refresh_tokens, password_reset_tokens, signing_keys, audit_events
func TestForeignKeysOn(t *testing.T)             // PRAGMA foreign_keys returns 1
```

- [ ] **Step 3: Run — fails**

- [ ] **Step 4: Write `model.go` exactly as Shared interfaces; write `0001_core.sql`**

Schema decisions the SQL must follow: TEXT ids (UUIDv4), timestamps TEXT RFC3339 UTC, booleans INTEGER 0/1, JSON in TEXT. `users.email` has `UNIQUE` on `lower(email)` via `CREATE UNIQUE INDEX users_email_idx ON users(lower(email)) WHERE email IS NOT NULL`; `users.username` unique where not null; `users.type` CHECK in ('member','service'). `groups.name UNIQUE`. `memberships(user_id, group_id) PRIMARY KEY`, both `ON DELETE CASCADE`. `applications.client_id UNIQUE`, `slug UNIQUE`, `redirect_uris`/`post_logout_redirect_uris` JSON arrays, TTL columns INTEGER seconds nullable, `service_account_id` nullable FK users ON DELETE SET NULL. `application_groups(application_id, group_id)` PK, cascades. `sessions` FK users cascade; index on `user_id`, `expires_at`. `auth_codes.code_hash PK`, `refresh_tokens.token_hash PK` with index on `family_id`, `user_id`. `password_reset_tokens.token_hash PK`. `signing_keys.kid PK`. `audit_events.id PK`, index on `at`.

- [ ] **Step 5: Run — PASS**

- [ ] **Step 6: Commit** `feat(db): sqlite open, migration runner, core schema`

---

### Task 3: Secrets helpers

**Files:**
- Create: `internal/secrets/secrets.go`, `internal/secrets/secrets_test.go`

**Interfaces:**
- Produces:
  ```go
  func RandomToken(nbytes int) string               // crypto/rand, base64.RawURLEncoding
  func HashToken(token string) string               // hex(sha256(token))
  func NewID() string                               // UUIDv4 string, lower-case; implement with crypto/rand, no dependency
  type Encryptor struct{ aead cipher.AEAD }
  func NewEncryptor(base64Key string) (*Encryptor, error) // std base64, must decode to 32 bytes
  func (e *Encryptor) Seal(plain []byte) ([]byte, error)  // nonce||ciphertext, random 12-byte nonce
  func (e *Encryptor) Open(sealed []byte) ([]byte, error)
  func GenerateKey() string                         // 32 random bytes, std base64 — used by `latch init`
  ```

- [ ] **Step 1: Tests**: `TestRandomTokenLengthAndUniqueness` (32 bytes → 43 chars, 1000 distinct), `TestHashTokenKnown` (`HashToken("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"`), `TestEncryptorRoundTripAndTamper` (Open of flipped byte errors), `TestNewEncryptorRejectsShortKey`, `TestNewIDFormat` (regexp `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).
- [ ] **Step 2: Run — fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run — PASS**
- [ ] **Step 5: Commit** `feat(secrets): random tokens, hashing, aes-gcm encryptor`

---

### Task 4: Password hashing, legacy Django verification, policy

**Files:**
- Create: `internal/password/password.go`, `internal/password/legacy.go`, `internal/password/common.txt`, `internal/password/password_test.go`

**Interfaces:**
- Produces:
  ```go
  var ErrUnusable = errors.New("password: unusable hash")
  var ErrUnsupported = errors.New("password: unsupported hash format")
  func Hash(password string) (string, error)             // "$argon2id$v=19$m=65536,t=3,p=4$<b64 nopad salt 16B>$<b64 nopad 32B>"
  func Verify(password, encoded string) (bool, error)    // native + all legacy; (false, ErrUnusable) for ""/"!..."; (false, ErrUnsupported) unknown prefix
  func IsLegacy(encoded string) bool                      // !strings.HasPrefix(encoded, "$argon2id$")
  func CheckPolicy(password string, minLen int) error    // ErrTooShort{Min} ; ErrCommon
  ```
  Django formats (`legacy.go`), all base64 std with padding except argon2 which is raw (no padding):
  - `argon2$argon2id$v=19$m=M,t=T,p=P$SALT$HASH` and `argon2$argon2i$…` → `argon2.IDKey/Key(pw, salt, T, M, P, len(hash))`
  - `pbkdf2_sha256$ITER$SALT$HASH` → `pbkdf2.Key(pw, []byte(SALT), ITER, len(hash), sha256.New)`; `pbkdf2_sha1` likewise
  - `scrypt$N$SALT$R$P$HASH` → `scrypt.Key(pw, []byte(SALT), N, R, P, len(hash))`
  - `bcrypt_sha256$<bcrypt>` → `bcrypt.CompareHashAndPassword([]byte(bcryptPart), []byte(hex(sha256(pw))))`
  All comparisons `subtle.ConstantTimeCompare`.

- [ ] **Step 1: `go get golang.org/x/crypto`**

- [ ] **Step 2: Write failing tests** with these known-answer vectors (password `correct horse battery staple`, generated with Django/argon2-cffi/hashlib/bcrypt):

```go
var legacyVectors = []string{
 "argon2$argon2id$v=19$m=102400,t=2,p=8$dks5bVoycFF4TDNuQWJDZA$v8TF/ZYe14p3FcLHRA6jRYFGhPQeg4Ja6gSqYQa18o4",
 "argon2$argon2i$v=19$m=512,t=2,p=2$dks5bVoycFF4TDNuQWJDZA$KsO21ry6WpQq7hLLmlFyyA",
 "pbkdf2_sha256$870000$vK9mZ2pQxL3n$k/YNzDxY8WuRK/+6PjMgYNCGxD4pyHdDwQFRbvUuXCo=",
 "pbkdf2_sha1$870000$vK9mZ2pQxL3n$bBx96KNlmEfYEidEL5887jX7oR8=",
 "scrypt$16384$vK9mZ2pQxL3n$8$1$mxwMrE3lGVjXaWtNecRS7hTkxrQnybG3B5i5Jao4znB257dwfBoQiweWlMmv54syIQUTtPbr22oeIHioiv7I/Q==",
 "bcrypt_sha256$$2b$12$uq70YScYbDqF0tdvP3Yhtu.PIe3/Xobf8UlszETQiO/sTqMtfUVgq",
}
func TestLegacyVectorsVerify(t *testing.T)      // each: Verify(pw, v) == (true,nil); Verify("wrong", v) == (false,nil); IsLegacy(v)
func TestNativeRoundTrip(t *testing.T)          // h,_ := Hash(pw); strings.HasPrefix(h,"$argon2id$v=19$m=65536,t=3,p=4$"); Verify ok; wrong false; !IsLegacy(h); two Hash calls differ
func TestUnusableAndUnsupported(t *testing.T)   // Verify(pw,"") and Verify(pw,"!abc") -> ErrUnusable; Verify(pw,"md5$x$y") -> ErrUnsupported
func TestCheckPolicy(t *testing.T)              // "short" -> ErrTooShort; "password1234" -> ErrCommon (ensure it is in common.txt); "correct horse battery staple" -> nil; 10-char non-common ok
func TestVerifyUnder100ms(t *testing.T)         // native Verify < 100ms on this host (t.Skip on -short)
```

- [ ] **Step 3: Run — fails**

- [ ] **Step 4: Create `common.txt`**: download the SecLists `10k-most-common.txt` (or equivalent public list), lower-case, one per line, commit it; embed with `//go:embed common.txt`, load into a `map[string]struct{}` once via `sync.Once`. Comparison lower-cases the candidate.

- [ ] **Step 5: Implement `password.go` and `legacy.go`**

- [ ] **Step 6: Run — PASS**

- [ ] **Step 7: Commit** `feat(password): argon2id hashing, django legacy verification, policy`

---

### Task 5: Store: users and groups

**Files:**
- Create: `internal/store/store.go`, `internal/store/testutil.go`, `internal/store/users.go`, `internal/store/groups.go`, `internal/store/users_test.go`, `internal/store/groups_test.go`

**Interfaces:**
- Consumes: `db.Open`, `db.Migrate`, `model.*`, `secrets.NewID`
- Produces: `store.New`, `ErrNotFound`, `ErrConflict`, user and group methods from Shared interfaces, plus `func OpenTest(t *testing.T) *Store` (temp file DB, migrated, closed on cleanup).

- [ ] **Step 1: Tests**

```go
func TestCreateAndGetUser(t)            // Create fills ID/CreatedAt; GetUser, GetUserByEmail("  ALEX@Example.org ") both return it; Metadata round-trips {"member_number":42} (number decodes as float64 — assert via JSON equality)
func TestCreateUserDuplicateEmailCaseInsensitive(t) // second create with "Alex@example.org" -> ErrConflict
func TestServiceAccountNoEmail(t)       // Type service, Email "" , Username "door" creates fine; two service accounts with "" email both create
func TestSetPasswordClearsLegacy(t)     // user with LegacyPasswordHash; SetPassword -> PasswordHash set, Legacy ""
func TestTOTPAndRecoveryCodes(t)        // SetTOTP then ClearTOTP deletes codes; ReplaceRecoveryCodes(3) ; ConsumeRecoveryCode true then false; CountUnused 2
func TestGroupsAndMembership(t)         // CreateGroup x2; AddMember twice idempotent; ListGroupsForUser sorted by name; RemoveMember; GetGroupByName ErrNotFound
func TestDeleteUserCascadesMembership(t) // (raw DELETE) memberships gone — proves FK cascade
```

- [ ] **Step 2: Run — fails**
- [ ] **Step 3: Implement.** Email is stored as given but trimmed; lookups use `lower(email) = lower(?)` on trimmed input. Metadata marshalled with `encoding/json`; nil → `{}`.
- [ ] **Step 4: Run — PASS**
- [ ] **Step 5: Commit** `feat(store): users, groups, memberships`

---

### Task 6: Store: applications, auth codes, refresh tokens, signing keys

**Files:**
- Create: `internal/store/apps.go`, `internal/store/oauth.go`, `internal/store/keys.go`, with `_test.go` each

**Interfaces:**
- Produces: `apps`, `oauth`, `keys` methods from Shared interfaces.

- [ ] **Step 1: Tests**

```go
func TestApplicationRoundTrip(t)                 // slices and TTLs round-trip; 0 TTL stored NULL and read back 0; GetApplicationByClientID; UpdateApplication replaces AllowedGroupIDs set
func TestListTileApplicationsForUser(t)          // app A no groups+tile -> visible; app B group G, user not in G -> hidden; add member -> visible; app C ShowTile false -> hidden; app D no LaunchURL -> hidden
func TestConsumeAuthCodeOnce(t)                  // Create; Consume ok; Consume again ErrNotFound; expired code ErrNotFound
func TestRefreshTokenFamilyRevoke(t)             // two tokens same family; RevokeRefreshTokenFamily -> both RevokedAt set; RevokeRefreshTokensForUser
func TestSigningKeysOrderAndRetire(t)            // insert two with different CreatedAt; List newest first; Retire sets RetiredAt
```

- [ ] **Step 2: Run — fails**
- [ ] **Step 3: Implement.** `ConsumeAuthCode` is `UPDATE auth_codes SET used_at=? WHERE code_hash=? AND used_at IS NULL AND expires_at > ?` then check `RowsAffected()==1`, then SELECT; same pattern for `ConsumeResetToken` in Task 7.
- [ ] **Step 4: Run — PASS**
- [ ] **Step 5: Commit** `feat(store): applications, oauth artefacts, signing keys`

---

### Task 7: Store: sessions, reset tokens, audit; audit recorder

**Files:**
- Create: `internal/store/sessions.go`, `internal/store/reset.go`, `internal/store/audit.go` (+ tests), `internal/audit/audit.go`, `internal/audit/audit_test.go`

**Interfaces:**
- Produces: store methods from Shared interfaces; 
  ```go
  // internal/audit
  type Recorder struct{ store *store.Store; log *slog.Logger }
  func New(s *store.Store, log *slog.Logger) *Recorder
  func (r *Recorder) Record(ctx, e model.AuditEvent)   // fills ID/At; logs at info with action/actor/target; never returns error (logs it)
  // actor helpers
  func UserActor(userID string) (model.ActorType, string)
  const ActorSystem = model.ActorType("system")
  ```
  Action string constants in `audit`: `LoginSuccess="login.success"`, `LoginFailure="login.failure"`, `LoginTOTPFailure="login.totp_failure"`, `Logout="logout"`, `PasswordChanged="user.password.change"`, `PasswordResetRequested="user.password.reset_requested"`, `PasswordResetCompleted="user.password.reset_completed"`, `TOTPEnrolled="user.totp.enrol"`, `TOTPDisabled="user.totp.disable"`, `TokenIssued="oidc.token.issued"`, `KeyRotated="oidc.key.rotate"`.

- [ ] **Step 1: Tests**: `TestSessionExpiryHidden` (GetSession on expired → ErrNotFound; DeleteExpiredSessions returns 1), `TestDeleteSessionsForUser`, `TestConsumeResetTokenOnce`, `TestHasActiveInviteToken` (purpose invite unexpired unused → true; after consume → false; purpose reset → false), `TestAuditInsertAndRecorder` (Record fills ID and At, row exists, Detail JSON round-trips).
- [ ] **Step 2: Run — fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run — PASS**
- [ ] **Step 5: Commit** `feat(store): sessions, reset tokens, audit events; audit recorder`

---

### Task 8: Rate limiter

**Files:**
- Create: `internal/ratelimit/ratelimit.go`, `internal/ratelimit/ratelimit_test.go`

**Interfaces:**
- Produces:
  ```go
  type Limiter struct { /* mutex, map[string][]time.Time, limit int, window time.Duration, now func() time.Time */ }
  func New(limit int, window time.Duration) *Limiter
  func (l *Limiter) Allow(key string) bool     // records the attempt when allowed; sliding window
  func (l *Limiter) Reset(key string)          // clear on successful login
  ```
  Prune keys with no events inside the window on each `Allow` call for that key, plus a full sweep every 1000 calls.

- [ ] **Step 1: Tests**: `TestAllowUpToLimit` (limit 3: 3 true then false), `TestWindowSlides` (inject `now`; after window passes, allowed again), `TestResetClears`, `TestKeysIndependent`.
- [ ] **Step 2–5: fail, implement, pass, commit** `feat(ratelimit): in-memory sliding window`

---

### Task 9: TOTP and recovery codes

**Files:**
- Create: `internal/totp/totp.go`, `internal/totp/totp_test.go`

**Interfaces:**
- Produces:
  ```go
  func GenerateSecret() (string, error)                      // 20 random bytes, base32 no padding, upper-case
  func ProvisioningURI(secret, issuer, account string) string // otpauth://totp/<issuer>:<account>?secret=..&issuer=..&algorithm=SHA1&digits=6&period=30
  func QRPNG(uri string, size int) ([]byte, error)           // pquerna/otp key.Image
  func Validate(secret, code string) bool                    // totp.ValidateCustom, skew 1, digits 6, SHA1; code trimmed, spaces removed
  func GenerateRecoveryCodes(n int) ([]string, error)        // "xxxxx-xxxxx" lower-case from alphabet "abcdefghjkmnpqrstuvwxyz23456789"
  func NormalizeRecoveryCode(s string) string                // lower, strip spaces/dashes, re-insert dash after 5
  func SecretFromHex(hexKey string) (string, error)          // Authentik stores raw key as hex — for the importer plan
  ```

- [ ] **Step 1: `go get github.com/pquerna/otp`**
- [ ] **Step 2: Tests**: `TestValidateWithGeneratedCode` (`totp.GenerateCode(secret, now)` validates; ±30s validates; ±90s does not), `TestValidateIgnoresSpaces` (`"123 456"`), `TestProvisioningURIFormat` (parse URL, check params), `TestRecoveryCodesFormat` (10 codes, regexp `^[a-z2-9]{5}-[a-z2-9]{5}$`, distinct), `TestNormalizeRecoveryCode` (`"ABCDE FGHJK"` → `"abcde-fghjk"`), `TestSecretFromHex` (`"3132333435363738393031323334353637383930"` → `"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"`).
- [ ] **Step 3–6: fail, implement, pass, commit** `feat(totp): secrets, validation, recovery codes`

---

### Task 10: Mail

**Files:**
- Create: `internal/mail/mail.go`, `internal/mail/smtp.go`, `internal/mail/templates.go`, `internal/mail/mail_test.go`

**Interfaces:**
- Produces:
  ```go
  type Message struct{ To, Subject, Text, HTML string }
  type Mailer interface{ Send(ctx context.Context, m Message) error }
  type Memory struct{ mu sync.Mutex; Sent []Message }        // test double
  func (m *Memory) Send(ctx, msg Message) error
  func (m *Memory) Last() (Message, bool)
  type SMTP struct{ cfg config.SMTPConfig }
  func NewSMTP(cfg config.SMTPConfig) (*SMTP, error)
  func (s *SMTP) Send(ctx, m Message) error                  // go-mail; TLS "starttls" -> TLSMandatory, "tls" -> SSL, "none" -> NoTLS
  type Brand struct{ Name, SupportText, PublicURL string }
  func ResetEmail(b Brand, link string, expires time.Duration) Message   // subject "Reset your <Name> password"
  func InviteEmail(b Brand, link string, expires time.Duration) Message  // subject "Set up your <Name> account"
  ```
  Email bodies: plain text first, minimal HTML with the same words. Copy: reset — "Someone asked to reset the password for this address at <Name>. If that was you, use this link within <N hours>: <link>. If not, ignore this email; nothing changes." Invite — "An account has been created for you at <Name>. Choose your password here within <N days>: <link>." Both end with SupportText.

- [ ] **Step 1: `go get github.com/wneessen/go-mail`**
- [ ] **Step 2: Tests**: `TestTemplatesContainLinkAndBrand` (Text and HTML contain link and Name; HTML escapes `<` in Name), `TestSMTPSendsViaLocalServer` (start a minimal SMTP listener in-test on `127.0.0.1:0` using a goroutine that reads lines and replies 220/250/354/250/221; assert `RCPT TO:<to>` and subject seen; TLS "none"), `TestNewSMTPRejectsBadTLS`.
- [ ] **Step 3–6: fail, implement, pass, commit** `feat(mail): smtp mailer, memory double, reset and invite emails`

---

### Task 11: Session manager and web skeleton (templates, branding, middleware, healthz, serve)

**Files:**
- Create: `internal/session/session.go`, `internal/session/session_test.go`, `internal/web/server.go`, `internal/web/render.go`, `internal/web/middleware.go`, `internal/web/templates/frame.html`, `internal/web/templates/error.html`, `internal/web/static/latch.css`, `internal/testenv/testenv.go`, `internal/web/server_test.go`, `cmd/latch/main.go` (serve + version only)

**Interfaces:**
- Consumes: `config`, `store`, `secrets`
- Produces:
  ```go
  // internal/session
  const CookieName = "latch_session"
  type Manager struct{ store *store.Store; idle, absolute time.Duration; secure bool; now func() time.Time }
  func NewManager(s *store.Store, idle, absolute time.Duration, secure bool) *Manager
  func (m *Manager) Start(ctx, w http.ResponseWriter, r *http.Request, userID string, totpPassed bool) (*model.Session, error)  // creates row, sets cookie (MaxAge = absolute)
  func (m *Manager) End(ctx, w, r) error                     // deletes row, clears cookie
  func (m *Manager) Update(ctx, sess *model.Session) error   // e.g. after TOTP
  func (m *Manager) Middleware(next http.Handler) http.Handler // loads session+user into ctx if cookie valid; touches LastSeenAt at most once per minute; extends ExpiresAt = min(now+idle, CreatedAt+absolute); drops inactive users
  func FromContext(ctx) (*model.Session, *model.User, bool)
  func RequireUser(next http.Handler) http.Handler            // redirect to /login?next=<path> if none
  func RequireAdmin(...) is NOT in this plan (admin plan)

  // internal/web — the Renderer is independent of Server so the oidc package can use it too
  type Brand struct{ Name, LogoURL, PrimaryColor, SupportText string }
  type Renderer struct{ tmpl *template.Template; brand Brand; log *slog.Logger }
  func NewRenderer(cfg *config.Config, log *slog.Logger) (*Renderer, error)   // parses embedded templates once
  type Page struct{ Title string; Error, Notice string; Data any }           // Brand and User are injected by Render from cfg and session.FromContext
  func (rd *Renderer) Render(w http.ResponseWriter, r *http.Request, status int, name string, p Page)  // name without ".html"
  func (rd *Renderer) RenderError(w, r, status int, title, message string)
  func (rd *Renderer) RenderNoAccess(w, r, appName string)                    // Task 16 adds no_access.html
  type Deps struct {
      Cfg *config.Config; Store *store.Store; Sessions *session.Manager; Mailer mail.Mailer
      Audit *audit.Recorder; Enc *secrets.Encryptor; Log *slog.Logger; Renderer *Renderer
      LoginLimiterAccount, LoginLimiterIP, ResetLimiterAccount, ResetLimiterIP *ratelimit.Limiter
      OIDC interface{ Mount(*http.ServeMux) }  // the oidc.Provider (Task 16+); nil in early tests
      Version string
  }
  func New(d Deps) http.Handler
  ```
  Construction order in `main` and in `testenv`: `rend := web.NewRenderer(cfg, log)` → `prov := oidc.NewProvider(oidc.Deps{…, Renderer: rend})` → `web.New(web.Deps{…, Renderer: rend, OIDC: prov})`.

  `internal/testenv` is a normal (non-test) package so both `web` and `oidc` tests can import it; to avoid import cycles **all tests in `internal/web` and `internal/oidc` use external test packages** (`package web_test`, `package oidc_test`).
  Middleware chain (outermost first): recover→500 page; RealIP (trust `X-Forwarded-For`/`X-Forwarded-Proto` only when `RemoteAddr` is in `TrustedProxies`); request log (method, path, status, duration, ip; slog); security headers (`X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `X-Frame-Options: DENY` except `/oauth/authorize` which may be framed? No — DENY everywhere, `Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'`); CSRF via `http.CrossOriginProtection` with `AddInsecureBypassPattern("/oauth/")` and `/api/`; sessions middleware.
  Static: `GET /static/` from embedded FS with `Cache-Control: public, max-age=86400`; `GET /static/logo` serves `Branding.Logo` from disk when it is a file path, or 302 to it when it is a URL. `GET /healthz` → `{"status":"ok","version":"..."}`.
  CSS: single file, CSS variable `--primary` set inline in `frame.html` from Brand.PrimaryColor; mobile-first; max content width 420px for auth pages, 960px for home.

- [ ] **Step 1: Tests**

```go
// session_test.go
func TestStartLoadsUserAndExtends(t)     // Start; request with cookie through Middleware -> FromContext user; ExpiresAt advanced after now+2min with injected clock
func TestAbsoluteCapRespected(t)         // injected now = CreatedAt+absolute+1s -> session gone (ErrNotFound/deleted)
func TestInactiveUserDropped(t)          // IsActive=false -> no user in ctx, cookie cleared
func TestEndClearsCookie(t)
// server_test.go
func TestHealthz(t)                      // 200, JSON has version
func TestBrandingRendered(t)             // GET /login (placeholder handler in this task returns frame with "Sign in") contains Branding.Name and primary colour; Content-Security-Policy header present
func TestRealIPOnlyFromTrustedProxy(t)   // X-Forwarded-For honoured when RemoteAddr 10.0.0.1 and trusted_proxies [10.0.0.0/8]; ignored otherwise (assert via a test handler that echoes ip from ctx)
func TestCrossOriginPostRejected(t)      // POST /login with Sec-Fetch-Site: cross-site -> 403; POST /oauth/token with same header -> not 403
```
  `internal/testenv/testenv.go`: `type Env struct{ TS *httptest.Server; Store *store.Store; Mailer *mail.Memory; Cfg *config.Config; Clock *Clock; Keys *oidc.KeyManager }` (Keys field added in Task 15), `func New(t *testing.T, opts ...Option) *Env` that builds all Deps with memory mailer, `PublicURL = TS.URL` (indirection: start `httptest.NewServer` on a handler var, then build `web.New` and assign), options `WithConfig(func(*config.Config))`; helpers `(*Env).CreateUser(t, email, password string, groups ...string) *model.User`, `(*Env).CreateGroup(t, name string, isAdmin, requireTOTP bool) *model.Group`, `(*Env).CreateApp(t, a model.Application, secret string) *model.Application`, `(*Env).Client(t) *http.Client` (cookie jar, `CheckRedirect` returns `http.ErrUseLastResponse`), `(*Env).Login(t, c *http.Client, email, password string)`, `(*Env).Authorize(t, c *http.Client, app *model.Application, pkce bool) (code, verifier, state string)` (Task 16 adds), `(*Env).Exchange(...)` (Task 17 adds).

- [ ] **Step 2: Run — fails**
- [ ] **Step 3: Implement session, web skeleton, `frame.html`, `error.html`, `latch.css`; `cmd/latch/main.go` with `serve` (load config, open db, migrate, build deps, `http.Server` with timeouts `ReadHeaderTimeout 10s`, graceful shutdown on SIGINT/SIGTERM) and `version`**
- [ ] **Step 4: Run — PASS; `go build ./...`**
- [ ] **Step 5: Commit** `feat(web): session manager, branded frame, middleware, healthz, serve command`

---

### Task 12: Login and logout

**Files:**
- Create: `internal/web/auth.go`, `internal/web/auth_test.go`, templates `login.html`, `logout.html`, `signed_out.html`

**Interfaces:**
- Consumes: `password.Verify/IsLegacy/Hash`, `session.Manager`, `ratelimit`, `audit`, `store`
- Produces: routes `GET /login`, `POST /login`, `GET /logout`, `POST /logout`; helper `func safeNext(raw string) string` (returns raw only if it parses as a path starting with single `/` and no scheme/host; else `/`); `func (s *Server) afterLogin(w, r, user, sess)` which decides: TOTP enrolled → `/login/totp?next=`; any group RequireTOTP and not enrolled → `/account/totp?required=1&next=`; else redirect `next`. Login page accepts `?next=` and `?app=<slug>` (shows "to continue to *Name*"); OIDC authorize (Task 16) redirects to `/login?next=<authorize URL>&app=<slug>`.

Behaviour: trim and lower email for lookup; on any failure (unknown email, wrong password, inactive, unusable hash, limiter) re-render login with 200 and the single message "That email and password didn't match." (identical for all cases); limiter keys `acct:<lower email>` and `ip:<ip>`; limit exceeded shows "Too many attempts. Try again in a few minutes." (200). On success: if `IsLegacy` → `password.Hash` and `store.SetPassword`; `TouchLastLogin`; `limiter.Reset(acct)`; audit `LoginSuccess`; session `TOTPPassed = !user.TOTPEnrolled()`. `GET /logout` renders confirm form; `POST /logout` ends session, redirects `/logout/done` which renders `signed_out.html` ("You're signed out." + link to sign in).

- [ ] **Step 1: Tests**

```go
func TestLoginSuccessSetsCookieAndRedirects(t)       // 303 to "/" ; cookie present; user.LastLoginAt set
func TestLoginEmailNormalised(t)                     // Review Focus 1: form email " Alex@Example.ORG " logs in alex@example.org
func TestLoginLegacyHashUpgraded(t)                  // user created with pbkdf2 vector; login ok; store shows PasswordHash "$argon2id$", Legacy ""
func TestLoginWrongPasswordGenericMessage(t)         // 200, body contains "didn't match", no cookie; same body for unknown email
func TestLoginInactiveRejected(t)
func TestLoginThrottledAfter10(t)                    // 10 failures then correct password -> "Too many attempts"
func TestSafeNext(t)                                 // table: "/account" ok; "https://evil.example" -> "/"; "//evil.example" -> "/"; "/\\evil" -> "/"; "" -> "/"
func TestLoginRedirectsToNext(t)                     // Review Focus 2 via HTTP: next=https://evil.example -> Location "/"
func TestLoginShowsAppName(t)                        // ?app=wiki -> "to continue to Members Wiki"
func TestLoginWithTOTPGoesToTOTPStep(t)              // enrolled user -> 303 /login/totp?next=... and session TOTPPassed false, RequireUser pages still redirect (session incomplete)
func TestLogoutPostEndsSession(t)                    // GET /logout 200 has form; POST -> 303 /logout/done; cookie cleared; subsequent GET / -> 303 /login
```
  Note: `RequireUser` must treat a session with `TOTPPassed=false` as not logged in for every route except `/login/totp`, `/logout`, `/account/totp` when `required=1` flow (Task 13 refines this; implement the check in `session.RequireUser` now with a package-level allowlist func `session.AllowIncomplete(path) bool`).

- [ ] **Step 2–5: fail, implement, pass, commit** `feat(web): login, logout, legacy hash upgrade, throttling`

---

### Task 13: TOTP step, enrolment, disable, required-by-group

**Files:**
- Create: `internal/web/totp.go`, `internal/web/totp_test.go`, templates `login_totp.html`, `account_totp.html` (status + enrol form + disable form), `account_totp_codes.html`
- Modify: `internal/web/auth.go` (`afterLogin` already routes), `internal/session/session.go` (`AllowIncomplete`)

**Interfaces:**
- Consumes: `totp.*`, `secrets.Encryptor`, `store.SetTOTP/ClearTOTP/ReplaceRecoveryCodes/ConsumeRecoveryCode`
- Produces: routes `GET/POST /login/totp`, `GET /account/totp`, `POST /account/totp/begin`, `GET /account/totp/qr.png`, `POST /account/totp/confirm`, `POST /account/totp/disable`, `GET /account/totp/codes` (one-time display after confirm; stored in a short-lived server-side flash keyed by session: add `pending_totp_secret_enc` and `pending_codes_json` columns? No — keep enrolment state in a new table `totp_enrolments(session_id PK, secret_enc BLOB, codes_json TEXT, created_at)` via migration `0002_totp_enrolment.sql`, cleaned when consumed or session ends).

Behaviour: `/login/totp` accepts `code` (6 digits) or a recovery code (contains a dash or is 10 letters); 5 failures per session → end session, audit `LoginTOTPFailure`, redirect `/login`. Success sets `TOTPPassed`, redirects `safeNext`. Enrol: `begin` generates secret, stores in `totp_enrolments`, renders QR (`/account/totp/qr.png` serves PNG for the pending secret only), manual key, and a confirm field; `confirm` validates code → `SetTOTP(confirmedAt=now)`, generates 10 recovery codes, `ReplaceRecoveryCodes(hashes)`, shows codes once (`account_totp_codes.html`, with "I've saved these" button to `/`). Disable requires current password + a valid code; `ClearTOTP`; audit. When `required=1` (group requires TOTP, none enrolled) the page says "Your group requires two-step sign in. Set it up now." and the session is incomplete until confirmed. Issuer in provisioning URI = Branding.Name; account = user email.

- [ ] **Step 1: Tests**

```go
func TestEnrolConfirmShowsCodesOnce(t)          // begin -> page has manual key; qr.png 200 image/png; confirm with generated code -> 303 /account/totp/codes -> 10 codes in body; GET again -> 303 /account/totp (gone)
func TestLoginTOTPCodeAndRecovery(t)            // enrolled: login -> /login/totp; wrong code 200 w/ error; correct -> 303 /; new client login + recovery code works; same recovery code again fails
func TestLoginTOTPFiveFailuresEndsSession(t)
func TestRequiredByGroupForcesEnrolment(t)      // group RequireTOTP, user not enrolled: login -> 303 /account/totp?required=1; GET / -> 303 back to enrolment; after confirm, GET / -> 200
func TestDisableRequiresPasswordAndCode(t)
func TestIncompleteSessionCannotReachAccount(t) // session with TOTPPassed=false: GET /account/password -> 303 /login/totp
```

- [ ] **Step 2–5: fail, implement (incl. `0002_totp_enrolment.sql`), pass, commit** `feat(web): totp second step, enrolment, recovery codes, group requirement`

---

### Task 14: Password reset, invite links, change password

**Files:**
- Create: `internal/web/reset.go`, `internal/web/reset_test.go`, `internal/web/account.go` (password change only; home comes in Task 19), templates `reset_request.html`, `reset_sent.html`, `reset_set.html`, `reset_expired.html`, `account_password.html`

**Interfaces:**
- Consumes: `mail.ResetEmail/InviteEmail`, `store` reset methods, `password.CheckPolicy/Hash`, limiters
- Produces: routes `GET/POST /reset`, `GET/POST /reset/{token}`, `GET/POST /account/password`; package function used by the admin plan and CLI:
  ```go
  // internal/web/reset.go
  const ResetTokenTTL = 1 * time.Hour
  const InviteTokenTTL = 7 * 24 * time.Hour
  func IssueResetLink(ctx, st *store.Store, issuer string, userID string, purpose model.ResetPurpose) (link string, err error) // creates token (32 random bytes), stores hash, returns issuer+"/reset/"+token
  func (s *Server) SendReset(ctx, user *model.User, purpose model.ResetPurpose) error  // IssueResetLink + mailer + audit PasswordResetRequested
  ```

Behaviour: `POST /reset` always renders `reset_sent.html` ("If that address has an account, we've emailed a link. It lasts one hour."), even for unknown or inactive emails and when throttled (limiter `3/acct/hour`, `20/ip/hour`); sends only for active users. `GET /reset/{token}`: look up by hash **without consuming**; missing/used/expired → `reset_expired.html` 200 with link to `/reset`; else render form (copy depends on purpose: "Choose a new password" vs "Welcome to <Name>. Choose your password."). `POST /reset/{token}`: validate policy (errors rendered inline: "Use at least 10 characters." / "That password is too common. Pick something less guessable."), confirm matches, then `ConsumeResetToken` (if that fails → expired page), `SetPassword`, `DeleteSessionsForUser`, `RevokeRefreshTokensForUser`, audit `PasswordResetCompleted`, start a fresh session (TOTPPassed = !enrolled), redirect `/`. `GET/POST /account/password`: current password required; same policy; on success revoke refresh tokens, delete other sessions (keep current), audit `PasswordChanged`, notice "Password changed."

Add `store.PeekResetToken(ctx, tokenHash) (*model.ResetToken, error)` (non-consuming; ErrNotFound if missing, used or expired) to `reset.go` in store with a test.

- [ ] **Step 1: Tests**

```go
func TestResetRequestSendsMailOnlyForActiveUsers(t)   // known active -> mailer.Sent 1 with link containing "/reset/"; unknown -> 0 but same 200 page text; inactive -> 0
func TestResetLinkSetsPasswordAndLogsIn(t)            // follow link from mail; POST new password -> 303 /; cookie set; old password fails; old sessions gone; refresh tokens revoked (insert one first)
func TestResetLinkReuseAndExpiryShowExpiredPage(t)    // Review Focus 5: after use, GET -> 200 containing "expired" and href="/reset"; token with ExpiresAt past -> same; garbage token -> same
func TestResetPolicyErrorsInline(t)                   // "short" -> "at least 10"; "password1234" -> "too common"; mismatch -> "don't match"; token NOT consumed by failed attempts
func TestInviteCopy(t)                                // purpose invite page contains "Welcome to"; mail subject "Set up your"
func TestResetThrottled(t)                            // 4th request within hour -> still 200, mailer.Sent stays 3
func TestChangePassword(t)                            // wrong current -> error; ok -> notice; other session deleted, current kept
```

- [ ] **Step 2–5: fail, implement, pass, commit** `feat(web): password reset, invite links, change password`

---

### Task 15: Signing keys and JWT issuance

**Files:**
- Create: `internal/oidc/keys.go`, `internal/oidc/keys_test.go`

**Interfaces:**
- Consumes: `store` keys methods, `secrets.Encryptor`, `audit`
- Produces:
  ```go
  type KeyManager struct{ store *store.Store; enc *secrets.Encryptor; mu sync.RWMutex; active *rsa.PrivateKey; activeKID string; public []jose.JSONWebKey }
  func NewKeyManager(ctx, s *store.Store, enc *secrets.Encryptor) (*KeyManager, error) // loads keys; if none, generates one (EnsureKey)
  func (k *KeyManager) EnsureKey(ctx) error
  func (k *KeyManager) Rotate(ctx) (newKID string, err error)   // new active key; previous keys stay published (not retired); caller may retire later
  func (k *KeyManager) RetireOlderThan(ctx, d time.Duration) (int, error) // retires non-active keys older than d (used by rotate-keys CLI with 90d)
  func (k *KeyManager) JWKS() jose.JSONWebKeySet                  // all non-retired public keys, use "sig", alg RS256
  func (k *KeyManager) Sign(claims map[string]any) (string, error) // RS256 compact JWS with kid header, typ "JWT"
  func (k *KeyManager) ActiveKID() string
  ```
  Private key stored PKCS#8 DER sealed by `Encryptor`; public as PEM. `kid` = first 16 hex chars of sha256 of public DER.

- [ ] **Step 1: `go get github.com/go-jose/go-jose/v4`**
- [ ] **Step 2: Tests**: `TestEnsureKeyCreatesOnce` (two managers on same store → one key), `TestSignVerifiesAgainstJWKS` (parse with go-jose, verify with JWKS key by kid, claims round-trip), `TestRotateKeepsOldPublished` (sign before rotate; after rotate JWKS has 2 keys; old token still verifies; new token kid differs), `TestRetireOlderThan` (retired key leaves JWKS), `TestPrivateKeyEncryptedAtRest` (raw column does not contain PKCS#8 header bytes of the DER, i.e. `Open` needed).
- [ ] **Step 3–6: fail, implement, pass, commit** `feat(oidc): signing key manager, jwks, rs256 signing`

---

### Task 16: Discovery, JWKS, claims, authorize endpoint

**Files:**
- Create: `internal/oidc/provider.go`, `internal/oidc/claims.go`, `internal/oidc/authorize.go`, `internal/oidc/claims_test.go`, `internal/oidc/authorize_test.go`, template `internal/web/templates/no_access.html` ("You don't have access to <App>. Ask an admin if you think you should." + sign-out form)
- Modify: `internal/web/render.go` (add `RenderNoAccess`), `internal/testenv/testenv.go` (add `Authorize` helper)

**Interfaces:**
- Consumes: `KeyManager`, `store`, `session.FromContext`, `config`
- Produces:
  ```go
  type Renderer interface {   // satisfied by *web.Renderer
      RenderError(w http.ResponseWriter, r *http.Request, status int, title, msg string)
      RenderNoAccess(w http.ResponseWriter, r *http.Request, appName string)
  }
  type Deps struct{ Cfg *config.Config; Store *store.Store; Keys *KeyManager; Audit *audit.Recorder; Log *slog.Logger
                    Renderer Renderer; Now func() time.Time }
  type Provider struct{ d Deps; issuer string }
  func NewProvider(d Deps) *Provider
  func (p *Provider) Mount(mux *http.ServeMux)   // registers all §6.1 routes
  // claims.go
  func ParseScopes(s string) []string            // split, dedupe, keep only known scopes, always includes "openid" if present in input
  func Subject(u *model.User, app *model.Application) string   // §6.4 table; authentik_* modes fall back to u.ID when the field is empty
  func BuildClaims(u *model.User, groups []model.Group, app *model.Application, scopes []string) map[string]any // §6.3 (no iss/aud/exp — added by issuer helpers)
  func UserAllowed(u *model.User, groups []model.Group, app *model.Application) bool // IsActive && (len(AllowedGroupIDs)==0 || intersects)
  func MatchRedirectURI(registered []string, candidate string) bool // exact string match; or loopback rule: registered host 127.0.0.1/localhost/[::1] with no port matches candidate with any port, same scheme and path
  ```
  Discovery document fields: `issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, end_session_endpoint, revocation_endpoint, introspection_endpoint, response_types_supported ["code"], grant_types_supported ["authorization_code","refresh_token","client_credentials"], subject_types_supported ["public"], id_token_signing_alg_values_supported ["RS256"], scopes_supported [5], token_endpoint_auth_methods_supported ["client_secret_basic","client_secret_post","none"], code_challenge_methods_supported ["S256"], claims_supported [sub,email,email_verified,name,preferred_username,groups,metadata,group_metadata,is_admin,updated_at]`.

  Authorize algorithm: validate `client_id` → app (unknown → 400 error page "Unknown application"); validate `redirect_uri` with `MatchRedirectURI` (fail → 400 error page, **never** redirect); from here errors redirect to `redirect_uri` with `error`, `error_description`, `state`. Require `response_type=code`; public client requires `code_challenge` + `code_challenge_method=S256` (`invalid_request`); scopes via `ParseScopes`, must contain `openid` (`invalid_scope`). Session: none or `TOTPPassed=false` or `prompt=login` or (`max_age` set and `now-CreatedAt > max_age`) → if `prompt=none` redirect `error=login_required`, else redirect to `/login?next=<full authorize URL>&app=<slug>` (303). User present: `UserAllowed` false → `RenderNoAccess` (200). Else create `AuthCode` (32 random bytes, hash stored, `ExpiresAt=now+60s`, `AuthTime=session.CreatedAt`), redirect `302` to `redirect_uri?code=…&state=…` (iss param too, RFC 9207).

- [ ] **Step 1: Tests**

```go
// claims_test.go
func TestSubjectModes(t)             // table over all 6 modes incl. fallback to ID when authentik field empty
func TestBuildClaimsByScope(t)       // openid only -> just sub; +email -> email,email_verified true; +profile -> name, preferred_username (fallback to email local part), metadata, updated_at; +groups -> groups names sorted, group_metadata keyed by name, is_admin
func TestMatchRedirectURI(t)         // Review Focus 3: exact ok; trailing slash no; other port no; "http://127.0.0.1/cb" vs "http://127.0.0.1:51234/cb" yes; localhost yes; "http://127.0.0.1/cb" vs "http://127.0.0.1:51234/other" no; https loopback with port registered must still match exactly
// authorize_test.go (uses web testenv so /login works; discovery via ts.URL)
func TestDiscoveryDocument(t)        // issuer == ts.URL; endpoints under ts.URL; jwks fetch 200 with 1 key
func TestAuthorizeUnknownClientIs400Page(t)
func TestAuthorizeBadRedirectIs400NoRedirect(t)
func TestAuthorizeRedirectsToLoginThenIssuesCode(t)   // no session -> 303 /login?next=...&app=wiki; after login, GET next -> 302 to redirect_uri with code,state,iss
func TestAuthorizePublicClientRequiresPKCE(t)         // -> redirect with error=invalid_request
func TestAuthorizeGroupDenied(t)                      // user not in allowed group -> 200 page containing app name and "don't have access"
func TestAuthorizePromptNoneWithoutSession(t)         // error=login_required
func TestAuthorizeMaxAgeForcesLogin(t)
```

- [ ] **Step 2–5: fail, implement, pass, commit** `feat(oidc): discovery, jwks, claims, authorize endpoint`

---

### Task 17: Token, userinfo, introspect, revoke

**Files:**
- Create: `internal/oidc/token.go`, `internal/oidc/token_test.go`

**Interfaces:**
- Consumes: Task 16 `Provider`, `password.Verify` is **not** used for client secrets — client secrets are compared via `secrets.HashToken` equality in constant time (`ClientSecretHash = HashToken(secret)`); provide `func (p *Provider) authenticateClient(r) (*model.Application, error)` supporting basic, post, and `none` for public clients (public clients must not send a secret).
- Produces: `POST /oauth/token` (grants `authorization_code`, `refresh_token`, `client_credentials`), `GET|POST /oauth/userinfo`, `POST /oauth/introspect`, `POST /oauth/revoke`; helpers
  ```go
  func (p *Provider) issueTokens(ctx, u *model.User, app *model.Application, scopes []string, nonce string, authTime time.Time, withIDToken, withRefresh bool, familyID string) (tokenResponse, error)
  type tokenResponse struct{ AccessToken string `json:"access_token"`; TokenType string `json:"token_type"`; ExpiresIn int `json:"expires_in"`; RefreshToken string `json:"refresh_token,omitempty"`; IDToken string `json:"id_token,omitempty"`; Scope string `json:"scope"` }
  func (p *Provider) ttl(app *model.Application, kind string) time.Duration // per-app override else config
  func (p *Provider) parseAccessToken(raw string) (claims map[string]any, err error) // verify sig against KeyManager, exp, iss
  ```
  Access token claims: `iss, sub, aud=[client_id], client_id, exp, iat, jti, scope, email, groups` (+ `typ: at+jwt` header). ID token claims: `BuildClaims` + `iss, aud=client_id, exp, iat, auth_time, nonce (if any), at_hash`. Refresh token: 32 random bytes, hash stored; rotation on use: old `RevokeRefreshToken`, new token same `FamilyID`; presenting a revoked token → `RevokeRefreshTokenFamily` and `invalid_grant`. Refresh issued when `!RequireOfflineAccessForRefresh || scopes contains offline_access`, never for `client_credentials`. Refresh grant re-loads user; inactive → revoke family, `invalid_grant`. Refresh `ExpiresAt = now+Refresh`, `AbsoluteExpiresAt` inherited from family's first token (`now+RefreshAbsolute` on first issue). `client_credentials`: confidential app with `ServiceAccountID` set, else `unauthorized_client`; subject = service account user; access token only. Userinfo: bearer access token → `BuildClaims` for scopes in the token. Introspect: client-authenticated; `{"active":false}` for anything invalid; else `active, sub, client_id, scope, exp, iat, iss, username(email)`. Revoke: refresh tokens only; always 200. All token endpoint errors are JSON `{"error","error_description"}` with 400 (401 + `WWW-Authenticate: Basic` for `invalid_client`). `Cache-Control: no-store` on token responses.

- [ ] **Step 1: Tests** (drive via raw HTTP against testenv, obtaining codes through `Env.Authorize`; add `(*Env).Exchange(t, app, code, verifier, redirectURI string) (map[string]any, *http.Response)` to testenv in this task):

```go
func TestCodeExchangeConfidentialBasicAuth(t)      // id_token parses, nonce round-trips, at_hash correct, aud==client_id, auth_time present; access token verifies with JWKS; refresh present
func TestCodeExchangePublicPKCE(t)                 // verifier correct ok; wrong verifier -> invalid_grant; code reuse -> invalid_grant
func TestCodeBoundToClientAndRedirectURI(t)        // other client's secret -> invalid_grant; different redirect_uri -> invalid_grant
func TestRefreshRotatesAndDetectsReuse(t)          // refresh -> new pair; old refresh again -> invalid_grant AND new one now also invalid (family revoked)
func TestRefreshDisabledUserFails(t)               // Review Focus 4: set IsActive=false; refresh -> invalid_grant; family revoked
func TestRefreshRequiresOfflineAccessWhenConfigured(t) // cfg flag true: no scope -> no refresh_token in response
func TestClientCredentialsServiceAccount(t)        // app with ServiceAccountID in group "Doors": token has sub, groups ["Doors"], no id_token/refresh; app without -> unauthorized_client; public client -> invalid_client
func TestUserinfoAndIntrospect(t)                  // userinfo claims match scopes; introspect active true; garbage -> active false; after revoke of refresh, refresh fails
func TestPerAppTTLOverride(t)                      // app.AccessTokenTTL=5m -> expires_in 300
func TestTokenErrorsAreJSONNoStore(t)
```

- [ ] **Step 2–5: fail, implement, pass, commit** `feat(oidc): token, userinfo, introspection, revocation`

---

### Task 18: RP-initiated logout and end-to-end with a real OIDC client

**Files:**
- Create: `internal/oidc/logout.go`, `internal/oidc/logout_test.go`, `internal/oidc/e2e_test.go`

**Interfaces:**
- Consumes: everything above; test deps `github.com/coreos/go-oidc/v3/oidc`, `golang.org/x/oauth2`
- Produces: `GET|POST /oauth/logout` per §6.1: parse `id_token_hint` (verify signature, ignore exp), determine client from `aud`; `post_logout_redirect_uri` must be in that app's `PostLogoutRedirectURIs` (exact match) — if valid, end session and 302 to it with `state`; if absent or invalid, end session and render `signed_out.html`. Without `id_token_hint`, never redirect; render page. Must work with no session (idempotent).

- [ ] **Step 1: Tests**

```go
func TestRPLogoutRedirectsWhenRegistered(t)        // login via OIDC, call logout with id_token_hint + registered uri -> 302 uri?state=..; session cookie no longer valid
func TestRPLogoutUnregisteredURIRendersPage(t)
func TestRPLogoutWithoutHintRendersPage(t)
// e2e_test.go
func TestE2EConfidentialClientWithGoOIDC(t)        // oidc.NewProvider(ctx, ts.URL); oauth2.Config{ClientID, ClientSecret, RedirectURL "https://app.test/cb", Scopes openid profile email groups}; drive browser client through AuthCodeURL -> login -> capture code from Location; Exchange; provider.Verifier(&oidc.Config{ClientID}).Verify(id_token) ok; claims.groups contains "Members"; UserInfo() email matches; TokenSource refresh works
func TestE2EPublicClientPKCE(t)                    // oauth2.GenerateVerifier/S256ChallengeOption; ClientSecret ""; AuthStyleInParams
func TestE2EMediaWikiShape(t)                      // scopes "openid profile email"; id_token has preferred_username == username; no groups claim without scope
```

- [ ] **Step 2–5: fail, implement, pass, commit** `feat(oidc): rp-initiated logout; end-to-end tests with go-oidc`

---

### Task 19: Member home, CLI commands

**Files:**
- Create: `internal/web/home.go`, `internal/web/home_test.go`, template `home.html`; `cmd/latch/init.go`, `cmd/latch/admin.go` (create-admin, reset-password), `cmd/latch/keys.go` (rotate-keys), `cmd/latch/main_test.go`
- Modify: `cmd/latch/main.go` dispatch; `internal/web/server.go` route `GET /`

**Interfaces:**
- Produces: `GET /` (RequireUser): greeting "Hi <first word of Name>", tiles from `ListTileApplicationsForUser` (name, description, icon or initial letter block, link `LaunchURL`), empty state "No apps yet. Ask an admin to give you access.", links `/account/password`, `/account/totp`, logout form. CLI:
  - (`go get golang.org/x/term` for the password prompt.)
  - `latch init [--config latch.yaml] [--data-dir DIR] [--public-url URL] [--admin-email E] [--admin-password P]`: writes config skeleton (from `latch.example.yaml` with generated `encryption_key`, given values filled) unless file exists (error, no overwrite); opens/migrates DB; creates group `Admin` (`IsAdmin=true, RequireTOTP=true`) if missing; creates admin user if email given (password via flag or interactive prompt with `golang.org/x/term`); `EnsureKey`. Prints next steps.
  - `latch create-admin --email E [--password P]`: creates (or promotes existing) user into `Admin` group.
  - `latch reset-password EMAIL`: prints a one-time reset link using `web.IssueResetLink` (purpose reset).
  - `latch rotate-keys [--retire-after 90d]`: `Rotate` then `RetireOlderThan`.
  - `latch version`, `latch serve` (Task 11).
  Exit code 1 and a one-line stderr message on error; no stack traces.

- [ ] **Step 1: Tests**

```go
func TestHomeShowsTilesForUserGroups(t)   // two apps, one group-restricted; body has allowed app name and launch URL, not the other; has "Change password"
func TestHomeEmptyState(t)
func TestHomeRequiresLogin(t)             // 303 /login?next=/
// main_test.go (run subcommands in-process via func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int)
func TestInitCreatesConfigDBAdminAndKey(t) // temp dir; run init with flags; config file exists with 44-char encryption_key; users has admin in Admin group; signing_keys 1; second init -> exit 1 "already exists"
func TestResetPasswordPrintsLink(t)       // link matches ^<public_url>/reset/[A-Za-z0-9_-]{43}$ and PeekResetToken finds it
func TestRotateKeys(t)                    // 2 keys after rotate
```

- [ ] **Step 2–5: fail, implement, pass, commit** `feat: member home with app tiles; init, create-admin, reset-password, rotate-keys commands`

---

### Task 20: Wire-up, README quickstart, full verification

**Files:**
- Create: `README.md`, `Makefile` (targets `build`, `test`, `run`), `internal/web/smoke_test.go`
- Modify: `cmd/latch/main.go` if any dep is unwired

- [ ] **Step 1: Smoke test** `TestSmokeFullFlow`: init-equivalent setup in testenv → create app (confidential, tile) → member logs in → home shows tile → OIDC code flow via go-oidc → change password → old refresh revoked → logout → RP logout page. One test, exercising wiring only (each piece is unit-tested already).
- [ ] **Step 2: Run `go vet ./... && go test ./... -race`** — expect PASS, no data races.
- [ ] **Step 3: Manual run**: `go run ./cmd/latch init --data-dir ./dev-data --public-url http://localhost:8080 --admin-email you@example.org --admin-password 'correct horse battery staple' --config ./dev-data/latch.yaml` then `go run ./cmd/latch serve --config ./dev-data/latch.yaml`; `curl -s localhost:8080/.well-known/openid-configuration | head -c 200` shows issuer; browser login works (no SMTP needed). Add `dev-data/` to `.gitignore`.
- [ ] **Step 4: README**: what Latch is (3 lines), quickstart (the two commands above), config reference pointer to `latch.example.yaml`, MediaWiki `LocalSettings.php` snippet for the OpenID Connect extension (`providerURL` = issuer, `clientID`, `clientsecret`, `scope` `openid profile email groups`), status line that admin UI and importer are in progress.
- [ ] **Step 5: Commit** `docs: readme quickstart; smoke test`

---

## Self-review notes

- Spec coverage: §4 model (T2, T5–7), §5 routes (T11–14, T19; `/metrics` deferred to import/ops plan as stated), §6 all endpoints and claims (T15–18), §6.5 client_credentials grant (T17; admin toggle UI in admin plan), §9 (T4), §11 config/CLI (T1, T11, T19), §3 constraints (Global Constraints). §7, §8, §10 are the sibling plans. `audit_events` table and recorder exist here so admin plan only adds UI.
- Deferred to admin plan: `api_tokens` table, `RequireAdmin`, service-account creation UI, admin audit views. Deferred to import plan: `totp.SecretFromHex` consumer, Dockerfile, systemd, `/metrics`, runbook.
- Type consistency: `model.Application.AllowedGroupIDs` (not names) is used by `UserAllowed` and `ListTileApplicationsForUser`; `groups` claim uses names via `[]model.Group` loaded with `ListGroupsForUser`. `secrets.HashToken` is the single hashing function for codes, refresh tokens, reset tokens, recovery codes and client secrets.
- Review Focus items 1–5 are pinned in T12, T12, T16, T17, T14 respectively.

// Package authentik reads an Authentik 2026.8 database into a Snapshot.
//
// It only reads: the connection is read-only and the whole read happens in one
// repeatable-read transaction, so the Snapshot is consistent. A later importer
// maps the Snapshot onto Latch. The snapshot carries secrets (password hashes,
// TOTP keys, recovery codes, client secrets); callers must never print or log
// them.
package authentik

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ManagedProfileScope is the Managed value of Authentik's built-in profile
// scope mapping, which sends the user's groups.
const ManagedProfileScope = "goauthentik.io/providers/oauth2/scope-profile"

// Snapshot is a consistent copy of the parts of Authentik that Latch imports.
type Snapshot struct {
	InstallID    string            // authentik_install_id.id
	Users        []User            // every row of authentik_core_user
	Groups       []Group           //
	Memberships  []Membership      // direct memberships only
	Parents      []Parentage       //
	TOTPDevices  []TOTPDevice      // confirmed and unconfirmed
	StaticTokens []StaticToken     // tokens of confirmed static devices only
	Applications []Application     //
	Providers    []OAuth2Provider  // OAuth2/OpenID providers only
	Bindings     []Binding         // bindings whose target is an application
	Mappings     []ProviderMapping // claim mappings attached to OAuth2 providers
}

// User is a row of authentik_core_user.
type User struct {
	PK                    int64
	UUID                  string
	Username, Name, Email string         // Email is "" when Authentik has none
	Password              string         // Django hash, "!…" or ""
	IsActive              bool           //
	Type                  string         // internal | external | service_account | internal_service_account
	Attributes            map[string]any // never nil
	LastLogin             *time.Time     //
	DateJoined            time.Time      //
}

// Group is a row of authentik_core_group.
type Group struct {
	UUID, Name  string
	IsSuperuser bool
	Attributes  map[string]any // never nil
}

// Membership is a direct membership of a user in a group.
type Membership struct {
	UserPK    int64
	GroupUUID string
}

// Parentage says ParentUUID is a parent of ChildUUID. A group can have several.
type Parentage struct{ ChildUUID, ParentUUID string }

// TOTPDevice is an authenticator-app device. KeyHex is the secret key in hex.
type TOTPDevice struct {
	UserPK       int64
	Name, KeyHex string
	Confirmed    bool
	Step, Digits int
	T0, LastT    int64
	Created      time.Time
	LastUsed     *time.Time
}

// StaticToken is an unused recovery code, in plaintext and case-sensitive.
type StaticToken struct {
	UserPK int64
	Token  string
}

// Application is a row of authentik_core_application.
type Application struct {
	UUID                                     string // policybindingmodel_ptr_id
	Name, Slug, LaunchURL, Icon, Description string
	Hide                                     bool
	ProviderPK                               *int64 // nil: the application has none
	EngineMode                               string // "any" | "all"
}

// OAuth2Provider is an OAuth2/OpenID provider. Other kinds of provider (SAML,
// proxy, …) are not read.
type OAuth2Provider struct {
	PK                                        int64
	Name, ClientType, ClientID, ClientSecret  string
	SubMode                                   string
	AccessTokenValidity, RefreshTokenValidity string // Authentik duration text, e.g. "hours=1"
	RedirectURIs                              []RedirectURI
	GrantTypes                                []string
}

// RedirectURI is one entry of a provider's redirect URI list.
type RedirectURI struct{ URL, MatchingMode, Type string } // strict|regex; authorization|logout

// Binding attaches a group, user or policy to an application's access rules.
type Binding struct {
	TargetUUID      string
	GroupUUID       string // "" unless a group binding
	UserPK          *int64 // nil unless a user binding
	PolicyUUID      string // "" unless a policy binding
	Enabled, Negate bool
}

// ProviderMapping is a claim mapping attached to an OAuth2 provider. Managed is
// "" for a mapping an admin wrote.
type ProviderMapping struct {
	ProviderPK    int64
	Name, Managed string
}

// validityUnits are the keys Authentik's timedelta_from_string accepts, in
// nanoseconds.
var validityUnits = map[string]float64{
	"microseconds": float64(time.Microsecond),
	"milliseconds": float64(time.Millisecond),
	"seconds":      float64(time.Second),
	"minutes":      float64(time.Minute),
	"hours":        float64(time.Hour),
	"days":         24 * float64(time.Hour),
	"weeks":        7 * 24 * float64(time.Hour),
}

// ParseValidity reads Authentik duration text such as "hours=1;minutes=30".
// Keys are case-insensitive and values are floats; unknown keys are ignored,
// but at least one known key is needed and the total must not be negative.
func ParseValidity(s string) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return 0, errors.New("authentik: empty duration")
	}
	var total float64
	valid := 0
	for _, part := range strings.Split(s, ";") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return 0, fmt.Errorf("authentik: duration %q: %q is not key=value", s, part)
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, fmt.Errorf("authentik: duration %q: %q is not a number", s, value)
		}
		unit, known := validityUnits[strings.ToLower(strings.TrimSpace(key))]
		if !known {
			continue
		}
		total += n * unit
		valid++
	}
	if valid == 0 {
		return 0, fmt.Errorf("authentik: duration %q has no valid keys", s)
	}
	if total < 0 {
		return 0, fmt.Errorf("authentik: duration %q is negative", s)
	}
	if total > float64(math.MaxInt64) {
		return 0, fmt.Errorf("authentik: duration %q is too long", s)
	}
	return time.Duration(total), nil
}

// HashedUserID returns the "sub" Authentik gives a user whose provider uses the
// hashed_user_id mode: the lower-case hex SHA-256 of "<pk>-<installID>".
func HashedUserID(pk int64, installID string) string {
	sum := sha256.Sum256([]byte(strconv.FormatInt(pk, 10) + "-" + installID))
	return hex.EncodeToString(sum[:])
}

// unknownSource names a database whose DSN could not be understood.
const unknownSource = "an Authentik database"

// Source names the database a DSN points at as "host:port/dbname", for reports
// and errors. It never includes the user or password. A DSN that cannot be
// parsed gives "an Authentik database": the driver's parse error can quote the
// DSN, so it is not used.
func Source(dsn string) string {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || cfg.Host == "" {
		return unknownSource
	}
	return fmt.Sprintf("%s:%d/%s", cfg.Host, cfg.Port, cfg.Database)
}

// Package model holds the plain data types shared across Latch.
package model

import "time"

type UserType string

const (
	UserTypeMember  UserType = "member"
	UserTypeService UserType = "service"
)

type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

type SubjectMode string

const (
	SubjectModeID            SubjectMode = "id"
	SubjectModeEmail         SubjectMode = "email"
	SubjectModeUsername      SubjectMode = "username"
	SubjectModeAuthentikUUID SubjectMode = "authentik_uuid"
	SubjectModeAuthentikUID  SubjectMode = "authentik_uid"
	SubjectModeAuthentikPK   SubjectMode = "authentik_pk"
)

type User struct {
	ID, Name                    string
	Type                        UserType
	Email, Username             string // "" when unset
	PasswordHash                string // native PHC, "" if none
	LegacyPasswordHash          string // Django format, "" if none
	IsActive                    bool
	Metadata                    map[string]any // never nil after load
	TOTPSecretEnc               []byte         // nil if not enrolled
	TOTPConfirmedAt             *time.Time
	AuthentikPK                 *int64
	AuthentikUUID, AuthentikUID string
	LastLoginAt                 *time.Time
	Description                 string // service accounts; "" for members
	CreatedAt, UpdatedAt        time.Time
}

// UserStatus is a member's state, derived from their record and never stored.
type UserStatus string

const (
	UserStatusActive        UserStatus = "active"
	UserStatusInvited       UserStatus = "invited"        // no password, an unused unexpired invite link exists
	UserStatusNeedsPassword UserStatus = "needs_password" // no password, no such link
	UserStatusDisabled      UserStatus = "disabled"       // !IsActive, whatever else is true
)

type APITokenScope string

const (
	APITokenScopeAdmin APITokenScope = "admin"
	APITokenScopeRead  APITokenScope = "read"
)

// APIToken is a bearer token for the admin API, held by a service account.
type APIToken struct {
	ID, ServiceAccountID, Label string
	TokenHash                   string // secrets.HashToken(raw)
	Scope                       APITokenScope
	CreatedByUserID             string // the admin or service account that made it
	CreatedAt                   time.Time
	LastUsedAt                  *time.Time
	ExpiresAt                   *time.Time // nil = never
}

// HasPassword reports whether the user has any password hash.
func (u *User) HasPassword() bool { return u.PasswordHash != "" || u.LegacyPasswordHash != "" }

// TOTPEnrolled reports whether the user has confirmed TOTP enrolment.
func (u *User) TOTPEnrolled() bool { return u.TOTPConfirmedAt != nil }

type Group struct {
	ID, Name, Description string
	IsAdmin, RequireTOTP  bool
	Metadata              map[string]any
	AuthentikUUID         string
	CreatedAt, UpdatedAt  time.Time
}

type Application struct {
	ID, Name, Slug, ClientID                    string
	ClientSecretHash                            string // "" for public
	ClientType                                  ClientType
	RedirectURIs                                []string
	PostLogoutRedirectURIs                      []string
	AllowedGroupIDs                             []string // empty = anyone active
	SubjectMode                                 SubjectMode
	AccessTokenTTL, RefreshTokenTTL, IDTokenTTL time.Duration // 0 = use global default
	LaunchURL, IconURL, Description             string
	ShowTile                                    bool
	ServiceAccountID                            string // "" = client_credentials disabled
	AuthentikProviderPK                         *int64
	CreatedAt, UpdatedAt                        time.Time
}

type Session struct {
	ID, UserID            string
	CreatedAt             time.Time // == auth_time for OIDC
	LastSeenAt, ExpiresAt time.Time
	TOTPPassed            bool
	IP, UserAgent         string
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

type ResetPurpose string

const (
	ResetPurposeReset  ResetPurpose = "reset"
	ResetPurposeInvite ResetPurpose = "invite"
)

type ResetToken struct {
	TokenHash, UserID    string
	Purpose              ResetPurpose
	CreatedAt, ExpiresAt time.Time
	UsedAt               *time.Time
}

type SigningKey struct {
	KID, Alg      string // Alg always "RS256"
	PrivateKeyEnc []byte
	PublicKeyPEM  string
	CreatedAt     time.Time
	RetiredAt     *time.Time
}

type ActorType string

const (
	ActorUser           ActorType = "user"
	ActorServiceAccount ActorType = "service_account"
	ActorSystem         ActorType = "system"
	ActorImporter       ActorType = "importer"
)

type AuditEvent struct {
	ID                                    string
	At                                    time.Time
	ActorType                             ActorType
	ActorID                               string
	Action, TargetType, TargetID, Summary string
	Detail                                map[string]any
}

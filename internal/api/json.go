package api

import (
	"context"
	"fmt"
	"time"

	"latch/internal/model"
	"latch/internal/store"
)

// This file holds the API's JSON shapes, one type per kind of record with
// the fields of the "API JSON" table, and the functions that make them.
// Times are UTC and unset ones null; groups appear as names; lists of
// nothing are [], never null.

// serviceAccountJSON is a service account.
type serviceAccountJSON struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Username    string         `json:"username"`
	Description string         `json:"description"`
	Groups      []string       `json:"groups"`
	Metadata    map[string]any `json:"metadata"`
	TokenCount  int            `json:"token_count"`
	LastUsedAt  *time.Time     `json:"last_used_at"` // latest use of any of its tokens
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// newServiceAccountJSON makes the JSON of a service account from its row,
// which needs Groups, TokenCount and TokenLastUsed: a row of
// store.ListUsers, or one from serviceAccountRow.
func newServiceAccountJSON(row store.UserRow) serviceAccountJSON {
	return serviceAccountJSON{
		ID:          row.ID,
		Name:        row.Name,
		Username:    row.Username,
		Description: row.Description,
		Groups:      groupNames(row.Groups),
		Metadata:    metadataJSON(row.Metadata),
		TokenCount:  row.TokenCount,
		LastUsedAt:  utcOrNil(row.TokenLastUsed),
		CreatedAt:   row.CreatedAt.UTC(),
		UpdatedAt:   row.UpdatedAt.UTC(),
	}
}

// serviceAccountRow loads what the JSON of one service account shows
// beyond its record: its groups, and the count and latest use of its
// tokens. Status and IsAdmin are left unset.
func (h *handler) serviceAccountRow(ctx context.Context, u *model.User) (store.UserRow, error) {
	groups, err := h.d.Store.ListGroupsForUser(ctx, u.ID)
	if err != nil {
		return store.UserRow{}, fmt.Errorf("api: groups of service account: %w", err)
	}
	tokens, err := h.d.Store.ListAPITokens(ctx, u.ID)
	if err != nil {
		return store.UserRow{}, fmt.Errorf("api: tokens of service account: %w", err)
	}
	row := store.UserRow{User: *u, Groups: groups, TokenCount: len(tokens)}
	for _, t := range tokens {
		if t.LastUsedAt != nil && (row.TokenLastUsed == nil || t.LastUsedAt.After(*row.TokenLastUsed)) {
			row.TokenLastUsed = t.LastUsedAt
		}
	}
	return row, nil
}

// tokenJSON is an API token. The raw token is never part of it; the
// response that makes a token adds it.
type tokenJSON struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Scope      string     `json:"scope"`
	CreatedBy  string     `json:"created_by"` // ID of the admin or service account that made it
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"` // null: never
}

// newTokenJSON makes the JSON of an API token.
func newTokenJSON(t *model.APIToken) tokenJSON {
	return tokenJSON{
		ID:         t.ID,
		Label:      t.Label,
		Scope:      string(t.Scope),
		CreatedBy:  t.CreatedByUserID,
		CreatedAt:  t.CreatedAt.UTC(),
		LastUsedAt: utcOrNil(t.LastUsedAt),
		ExpiresAt:  utcOrNil(t.ExpiresAt),
	}
}

// groupNames returns the names of groups, [] for none.
func groupNames(groups []model.Group) []string {
	names := make([]string, len(groups))
	for i, g := range groups {
		names[i] = g.Name
	}
	return names
}

// metadataJSON returns m, or {} for nil.
func metadataJSON(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// userJSON is a member. It has no password hash, TOTP secret or any other
// secret.
type userJSON struct {
	ID                    string         `json:"id"`
	Email                 string         `json:"email"`
	Username              string         `json:"username"`
	Name                  string         `json:"name"`
	Status                string         `json:"status"`
	IsActive              bool           `json:"is_active"`
	IsAdmin               bool           `json:"is_admin"` // in any group with is_admin
	Groups                []string       `json:"groups"`
	Metadata              map[string]any `json:"metadata"`
	TOTPEnrolled          bool           `json:"totp_enrolled"`
	ImportedFromAuthentik bool           `json:"imported_from_authentik"`
	LastLoginAt           *time.Time     `json:"last_login_at"`
	CreatedAt             time.Time      `json:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at"`
}

// newUserJSON makes the JSON of a member from its record, status and groups.
func newUserJSON(u *model.User, status model.UserStatus, groups []model.Group) userJSON {
	admin := false
	for _, g := range groups {
		admin = admin || g.IsAdmin
	}
	return userJSON{
		ID:                    u.ID,
		Email:                 u.Email,
		Username:              u.Username,
		Name:                  u.Name,
		Status:                string(status),
		IsActive:              u.IsActive,
		IsAdmin:               admin,
		Groups:                groupNames(groups),
		Metadata:              metadataJSON(u.Metadata),
		TOTPEnrolled:          u.TOTPEnrolled(),
		ImportedFromAuthentik: u.AuthentikUUID != "" || u.AuthentikPK != nil,
		LastLoginAt:           utcOrNil(u.LastLoginAt),
		CreatedAt:             u.CreatedAt.UTC(),
		UpdatedAt:             u.UpdatedAt.UTC(),
	}
}

// groupJSON is a group.
type groupJSON struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	IsAdmin     bool           `json:"is_admin"`
	RequireTOTP bool           `json:"require_totp"`
	Metadata    map[string]any `json:"metadata"`
	MemberCount int            `json:"member_count"` // members and service accounts
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// newGroupJSON makes the JSON of a group with its number of members.
func newGroupJSON(g *model.Group, memberCount int) groupJSON {
	return groupJSON{
		ID:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		IsAdmin:     g.IsAdmin,
		RequireTOTP: g.RequireTOTP,
		Metadata:    metadataJSON(g.Metadata),
		MemberCount: memberCount,
		CreatedAt:   g.CreatedAt.UTC(),
		UpdatedAt:   g.UpdatedAt.UTC(),
	}
}

// groupMemberJSON is one line of a group's member list: a member or a
// service account.
type groupMemberJSON struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // "member" or "service_account"
	Name     string `json:"name"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

// newGroupMemberJSON makes the line of a user in a group's member list.
func newGroupMemberJSON(u *model.User) groupMemberJSON {
	kind := "member"
	if u.Type == model.UserTypeService {
		kind = "service_account"
	}
	return groupMemberJSON{ID: u.ID, Type: kind, Name: u.Name, Email: u.Email, Username: u.Username}
}

// appJSON is an application. The client secret is never part of it; the
// responses that make or replace one add it.
type appJSON struct {
	ID                     string    `json:"id"`
	Name                   string    `json:"name"`
	Slug                   string    `json:"slug"`
	ClientID               string    `json:"client_id"`
	ClientType             string    `json:"client_type"`
	RedirectURIs           []string  `json:"redirect_uris"`
	PostLogoutRedirectURIs []string  `json:"post_logout_redirect_uris"`
	AllowedGroups          []string  `json:"allowed_groups"` // group names; empty means any active member
	SubjectMode            string    `json:"subject_mode"`
	AccessTokenTTL         *int64    `json:"access_token_ttl"` // seconds; null is the global default
	IDTokenTTL             *int64    `json:"id_token_ttl"`
	RefreshTokenTTL        *int64    `json:"refresh_token_ttl"`
	LaunchURL              string    `json:"launch_url"`
	IconURL                string    `json:"icon_url"`
	Description            string    `json:"description"`
	ShowTile               bool      `json:"show_tile"`
	ServiceAccountID       *string   `json:"service_account_id"` // null when the app can't sign in by itself
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

// newAppJSON makes the JSON of an application. groupNameByID maps group IDs
// to names; an allowed group missing from it is left out.
func newAppJSON(a *model.Application, groupNameByID map[string]string) appJSON {
	allowed := make([]string, 0, len(a.AllowedGroupIDs))
	for _, id := range a.AllowedGroupIDs {
		if name, ok := groupNameByID[id]; ok {
			allowed = append(allowed, name)
		}
	}
	var serviceAccount *string
	if a.ServiceAccountID != "" {
		serviceAccount = &a.ServiceAccountID
	}
	return appJSON{
		ID:                     a.ID,
		Name:                   a.Name,
		Slug:                   a.Slug,
		ClientID:               a.ClientID,
		ClientType:             string(a.ClientType),
		RedirectURIs:           nonNil(a.RedirectURIs),
		PostLogoutRedirectURIs: nonNil(a.PostLogoutRedirectURIs),
		AllowedGroups:          allowed,
		SubjectMode:            string(a.SubjectMode),
		AccessTokenTTL:         seconds(a.AccessTokenTTL),
		IDTokenTTL:             seconds(a.IDTokenTTL),
		RefreshTokenTTL:        seconds(a.RefreshTokenTTL),
		LaunchURL:              a.LaunchURL,
		IconURL:                a.IconURL,
		Description:            a.Description,
		ShowTile:               a.ShowTile,
		ServiceAccountID:       serviceAccount,
		CreatedAt:              a.CreatedAt.UTC(),
		UpdatedAt:              a.UpdatedAt.UTC(),
	}
}

// nonNil returns s, or an empty slice for nil, so JSON shows [] not null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// seconds returns d in whole seconds, or nil for 0 (the global default).
func seconds(d time.Duration) *int64 {
	if d == 0 {
		return nil
	}
	s := int64(d / time.Second)
	return &s
}

// auditEventJSON is one audit event, as stored.
type auditEventJSON struct {
	ID         string         `json:"id"`
	At         time.Time      `json:"at"`
	ActorType  string         `json:"actor_type"`
	ActorID    string         `json:"actor_id"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Summary    string         `json:"summary"`
	Detail     map[string]any `json:"detail"`
}

// newAuditEventJSON makes the JSON of an audit event.
func newAuditEventJSON(e *model.AuditEvent) auditEventJSON {
	return auditEventJSON{
		ID:         e.ID,
		At:         e.At.UTC(),
		ActorType:  string(e.ActorType),
		ActorID:    e.ActorID,
		Action:     e.Action,
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		Summary:    e.Summary,
		Detail:     metadataJSON(e.Detail),
	}
}

// utcOrNil returns t in UTC, or nil for nil.
func utcOrNil(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

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

// utcOrNil returns t in UTC, or nil for nil.
func utcOrNil(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

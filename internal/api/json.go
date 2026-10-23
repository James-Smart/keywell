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

// utcOrNil returns t in UTC, or nil for nil.
func utcOrNil(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

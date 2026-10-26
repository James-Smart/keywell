package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"keywell/internal/model"
)

func mkService(t *testing.T, s *Store, username string) *model.User {
	t.Helper()
	u := &model.User{Name: username, Type: model.UserTypeService, Username: username, IsActive: true}
	if err := s.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAPITokenLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	acct, other := mkService(t, s, "a"), mkService(t, s, "b")
	exp := time.Now().Add(24 * time.Hour).UTC()
	t1 := &model.APIToken{ServiceAccountID: acct.ID, Label: "first", TokenHash: "h1", Scope: model.APITokenScopeAdmin,
		CreatedByUserID: "admin-1", ExpiresAt: &exp}
	if err := s.CreateAPIToken(ctx, t1); err != nil {
		t.Fatal(err)
	}
	if t1.ID == "" || t1.CreatedAt.IsZero() {
		t.Fatalf("not filled: %+v", t1)
	}
	time.Sleep(2 * time.Millisecond)
	t2 := &model.APIToken{ServiceAccountID: acct.ID, Label: "second", TokenHash: "h2", Scope: model.APITokenScopeRead}
	if err := s.CreateAPIToken(ctx, t2); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetAPITokenByHash(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != t1.ID || got.Scope != model.APITokenScopeAdmin || got.Label != "first" || got.CreatedByUserID != "admin-1" ||
		got.ServiceAccountID != acct.ID || got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) || got.LastUsedAt != nil {
		t.Fatalf("got %+v", got)
	}
	if _, err := s.GetAPITokenByHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown hash: %v", err)
	}

	used := time.Now().UTC()
	if err := s.TouchAPIToken(ctx, t1.ID, used); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAPITokenByHash(ctx, "h1")
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(used) {
		t.Fatalf("last used %v", got.LastUsedAt)
	}

	list, err := s.ListAPITokens(ctx, acct.ID)
	if err != nil || len(list) != 2 || list[0].ID != t2.ID || list[1].ID != t1.ID {
		t.Fatalf("list %+v, %v", list, err)
	}

	if err := s.DeleteAPIToken(ctx, other.ID, t1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete via other account: %v", err)
	}
	if _, err := s.GetAPITokenByHash(ctx, "h1"); err != nil {
		t.Fatalf("token removed by the wrong account: %v", err)
	}
	if err := s.DeleteAPIToken(ctx, acct.ID, t1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAPITokenByHash(ctx, "h1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token remains: %v", err)
	}
}

func TestAPITokenHashUnique(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	acct := mkService(t, s, "a")
	mk := func() error {
		return s.CreateAPIToken(ctx, &model.APIToken{ServiceAccountID: acct.ID, Label: "x", TokenHash: "same", Scope: model.APITokenScopeRead})
	}
	if err := mk(); err != nil {
		t.Fatal(err)
	}
	if err := mk(); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate hash: %v, want ErrConflict", err)
	}
}

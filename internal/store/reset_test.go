package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"keywell/internal/model"
)

func mkReset(t *testing.T, s *Store, hash, userID string, p model.ResetPurpose, exp time.Time) {
	t.Helper()
	tok := &model.ResetToken{TokenHash: hash, UserID: userID, Purpose: p, CreatedAt: time.Now().UTC(), ExpiresAt: exp}
	if err := s.CreateResetToken(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
}

func TestConsumeResetTokenOnce(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mkUser(t, s, "r@example.org")
	now := time.Now()
	mkReset(t, s, "good", u.ID, model.ResetPurposeReset, now.Add(time.Hour))
	mkReset(t, s, "old", u.ID, model.ResetPurposeReset, now.Add(-time.Minute))
	tok, err := s.ConsumeResetToken(ctx, "good")
	if err != nil {
		t.Fatal(err)
	}
	if tok.UsedAt == nil || tok.UserID != u.ID || tok.Purpose != model.ResetPurposeReset {
		t.Fatalf("token: %+v", tok)
	}
	for _, h := range []string{"good", "old", "missing"} {
		if _, err := s.ConsumeResetToken(ctx, h); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: %v", h, err)
		}
	}
}

func TestHasActiveInviteToken(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mkUser(t, s, "i@example.org")
	other := mkUser(t, s, "j@example.org")
	check := func(id string, want bool) {
		t.Helper()
		got, err := s.HasActiveInviteToken(ctx, id)
		if err != nil || got != want {
			t.Fatalf("HasActiveInviteToken(%s) = %v, %v; want %v", id, got, err, want)
		}
	}
	check(u.ID, false)
	mkReset(t, s, "inv", u.ID, model.ResetPurposeInvite, time.Now().Add(time.Hour))
	mkReset(t, s, "rst", other.ID, model.ResetPurposeReset, time.Now().Add(time.Hour))
	check(u.ID, true)
	check(other.ID, false)
	if _, err := s.ConsumeResetToken(ctx, "inv"); err != nil {
		t.Fatal(err)
	}
	check(u.ID, false)
	mkReset(t, s, "inv2", u.ID, model.ResetPurposeInvite, time.Now().Add(-time.Hour))
	check(u.ID, false)
}

// DeleteResetToken removes that one token, and is fine with one that is gone.
func TestDeleteResetToken(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mkUser(t, s, "d@example.org")
	mkReset(t, s, "first", u.ID, model.ResetPurposeInvite, time.Now().Add(time.Hour))
	mkReset(t, s, "second", u.ID, model.ResetPurposeInvite, time.Now().Add(time.Hour))
	if err := s.DeleteResetToken(ctx, "first"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PeekResetToken(ctx, "first"); !errors.Is(err, ErrNotFound) {
		t.Errorf("first still there: %v", err)
	}
	if _, err := s.PeekResetToken(ctx, "second"); err != nil {
		t.Errorf("second gone: %v", err)
	}
	if err := s.DeleteResetToken(ctx, "first"); err != nil {
		t.Errorf("deleting it again: %v", err)
	}
}

// PeekResetToken finds an unused, unexpired token without using it up.
func TestPeekResetToken(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mkUser(t, s, "p@example.org")
	now := time.Now()
	mkReset(t, s, "good", u.ID, model.ResetPurposeInvite, now.Add(time.Hour))
	mkReset(t, s, "old", u.ID, model.ResetPurposeReset, now.Add(-time.Minute))
	for range 2 {
		tok, err := s.PeekResetToken(ctx, "good")
		if err != nil {
			t.Fatal(err)
		}
		if tok.UsedAt != nil || tok.UserID != u.ID || tok.Purpose != model.ResetPurposeInvite ||
			!tok.ExpiresAt.After(now) {
			t.Fatalf("token: %+v", tok)
		}
	}
	if _, err := s.ConsumeResetToken(ctx, "good"); err != nil {
		t.Fatalf("consume after peek: %v", err)
	}
	for _, h := range []string{"good", "old", "missing"} {
		if _, err := s.PeekResetToken(ctx, h); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: %v", h, err)
		}
	}
}

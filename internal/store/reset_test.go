package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"latch/internal/model"
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
	s := OpenTest(t)
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
	s := OpenTest(t)
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

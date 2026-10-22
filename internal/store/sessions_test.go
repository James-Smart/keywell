package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"latch/internal/model"
)

func mkSession(t *testing.T, s *Store, id, userID string, exp time.Time) *model.Session {
	t.Helper()
	now := time.Now().UTC()
	sess := &model.Session{ID: id, UserID: userID, CreatedAt: now, LastSeenAt: now, ExpiresAt: exp, IP: "10.0.0.1", UserAgent: "ua"}
	if err := s.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestSessionExpiryHidden(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	u := mkUser(t, s, "sess@example.org")
	now := time.Now().UTC()
	mkSession(t, s, "live", u.ID, now.Add(time.Hour))
	mkSession(t, s, "dead", u.ID, now.Add(-time.Minute))

	got, err := s.GetSession(ctx, "live")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != u.ID || got.IP != "10.0.0.1" || got.UserAgent != "ua" || got.TOTPPassed {
		t.Fatalf("session: %+v", got)
	}
	if _, err := s.GetSession(ctx, "dead"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired get: %v", err)
	}
	got.TOTPPassed = true
	got.ExpiresAt = now.Add(2 * time.Hour)
	if err := s.UpdateSession(ctx, got); err != nil {
		t.Fatal(err)
	}
	again, err := s.GetSession(ctx, "live")
	if err != nil {
		t.Fatal(err)
	}
	if !again.TOTPPassed || !again.ExpiresAt.Equal(got.ExpiresAt) {
		t.Fatalf("update: %+v", again)
	}
	n, err := s.DeleteExpiredSessions(ctx)
	if err != nil || n != 1 {
		t.Fatalf("delete expired: %d %v", n, err)
	}
}

func TestDeleteSessionsForUser(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	a := mkUser(t, s, "a@example.org")
	b := mkUser(t, s, "b@example.org")
	exp := time.Now().Add(time.Hour)
	mkSession(t, s, "a1", a.ID, exp)
	mkSession(t, s, "a2", a.ID, exp)
	mkSession(t, s, "b1", b.ID, exp)
	if err := s.DeleteSessionsForUser(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a1", "a2"} {
		if _, err := s.GetSession(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if _, err := s.GetSession(ctx, "b1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, "b1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "b1"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

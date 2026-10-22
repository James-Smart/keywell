package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"latch/internal/model"
)

func oauthFixture(t *testing.T, s *Store) (*model.User, *model.Application) {
	t.Helper()
	u := mkUser(t, s, "o@example.org")
	a := &model.Application{Name: "A", Slug: "a", ClientID: "a"}
	if err := s.CreateApplication(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	return u, a
}

func TestConsumeAuthCodeOnce(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	u, a := oauthFixture(t, s)
	now := time.Now().UTC()
	mk := func(hash string, exp time.Time) {
		t.Helper()
		c := &model.AuthCode{CodeHash: hash, ApplicationID: a.ID, UserID: u.ID, SessionID: "s", RedirectURI: "https://x/cb",
			Scope: "openid email", Nonce: "n", CodeChallenge: "ch", CodeChallengeMethod: "S256", AuthTime: now, ExpiresAt: exp}
		if err := s.CreateAuthCode(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	mk("good", now.Add(time.Minute))
	mk("old", now.Add(-time.Minute))
	c, err := s.ConsumeAuthCode(ctx, "good")
	if err != nil {
		t.Fatal(err)
	}
	if c.UsedAt == nil || c.Scope != "openid email" || c.Nonce != "n" || c.CodeChallengeMethod != "S256" || c.UserID != u.ID {
		t.Fatalf("code: %+v", c)
	}
	if _, err := s.ConsumeAuthCode(ctx, "good"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume: %v", err)
	}
	if _, err := s.ConsumeAuthCode(ctx, "old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired consume: %v", err)
	}
	if _, err := s.ConsumeAuthCode(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing consume: %v", err)
	}
}

func TestRefreshTokenFamilyRevoke(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	u, a := oauthFixture(t, s)
	other := mkUser(t, s, "other@example.org")
	now := time.Now().UTC()
	mk := func(hash, fam, uid string) {
		t.Helper()
		rt := &model.RefreshToken{TokenHash: hash, FamilyID: fam, ApplicationID: a.ID, UserID: uid, Scope: "openid", Nonce: "n",
			AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour)}
		if err := s.CreateRefreshToken(ctx, rt); err != nil {
			t.Fatal(err)
		}
	}
	mk("t1", "f1", u.ID)
	mk("t2", "f1", u.ID)
	mk("t3", "f2", u.ID)
	mk("t4", "f3", other.ID)
	rt, err := s.GetRefreshToken(ctx, "t1")
	if err != nil || rt.RevokedAt != nil || rt.FamilyID != "f1" || rt.Scope != "openid" {
		t.Fatalf("get: %+v %v", rt, err)
	}
	if _, err := s.GetRefreshToken(ctx, "zzz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	revoked := func(h string) bool {
		t.Helper()
		rt, err := s.GetRefreshToken(ctx, h)
		if err != nil {
			t.Fatal(err)
		}
		return rt.RevokedAt != nil
	}
	if err := s.RevokeRefreshToken(ctx, "t3"); err != nil || !revoked("t3") {
		t.Fatalf("revoke single: %v", err)
	}
	first, _ := s.GetRefreshToken(ctx, "t3")
	time.Sleep(2 * time.Millisecond)
	if err := s.RevokeRefreshToken(ctx, "t3"); err != nil {
		t.Fatal(err)
	}
	again, _ := s.GetRefreshToken(ctx, "t3")
	if !again.RevokedAt.Equal(*first.RevokedAt) {
		t.Fatal("revoked_at should not be overwritten")
	}
	if err := s.RevokeRefreshTokenFamily(ctx, "f1"); err != nil {
		t.Fatal(err)
	}
	if !revoked("t1") || !revoked("t2") || revoked("t4") {
		t.Fatal("family revoke wrong")
	}
	if err := s.RevokeRefreshTokensForUser(ctx, other.ID); err != nil {
		t.Fatal(err)
	}
	if !revoked("t4") {
		t.Fatal("user revoke failed")
	}
}

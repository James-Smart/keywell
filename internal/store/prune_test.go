package store

import (
	"context"
	"slices"
	"testing"
	"time"

	"latch/internal/model"
)

// keys returns the values of the key column of table, sorted.
func keys(t *testing.T, s *Store, table, column string) []string {
	t.Helper()
	rows, err := s.db.Query(`SELECT ` + column + ` FROM ` + table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		got = append(got, k)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	return got
}

func TestDeleteSpentAuthCodes(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u, a := oauthFixture(t, s)
	now := time.Now().UTC()
	used := now.Add(-time.Second)
	for _, c := range []model.AuthCode{
		{CodeHash: "live", ExpiresAt: now.Add(time.Minute)},
		{CodeHash: "used", ExpiresAt: now.Add(time.Minute), UsedAt: &used},
		{CodeHash: "expired", ExpiresAt: now.Add(-time.Second)},
	} {
		c.ApplicationID, c.UserID, c.SessionID, c.RedirectURI, c.AuthTime = a.ID, u.ID, "s", "https://x/cb", now
		if err := s.CreateAuthCode(ctx, &c); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.DeleteSpentAuthCodes(ctx)
	if err != nil || n != 2 {
		t.Fatalf("DeleteSpentAuthCodes = %d, %v; want 2", n, err)
	}
	if got := keys(t, s, "auth_codes", "code_hash"); !slices.Equal(got, []string{"live"}) {
		t.Fatalf("codes left %v, want [live]", got)
	}
}

// A refresh token goes once past its absolute lifetime, or a day after it
// was revoked (kept that long so a replay of it still ends its family).
func TestDeleteDeadRefreshTokens(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u, a := oauthFixture(t, s)
	now := time.Now().UTC()
	longAgo, recently := now.Add(-25*time.Hour), now.Add(-time.Hour)
	for _, rt := range []model.RefreshToken{
		{TokenHash: "live", AbsoluteExpiresAt: now.Add(time.Hour)},
		{TokenHash: "absolute-expired", AbsoluteExpiresAt: now.Add(-time.Second)},
		{TokenHash: "revoked-long-ago", AbsoluteExpiresAt: now.Add(time.Hour), RevokedAt: &longAgo},
		{TokenHash: "revoked-recently", AbsoluteExpiresAt: now.Add(time.Hour), RevokedAt: &recently},
	} {
		rt.FamilyID, rt.ApplicationID, rt.UserID = "f", a.ID, u.ID
		rt.AuthTime, rt.CreatedAt, rt.ExpiresAt = now, now, rt.AbsoluteExpiresAt
		if err := s.CreateRefreshToken(ctx, &rt); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.DeleteDeadRefreshTokens(ctx)
	if err != nil || n != 2 {
		t.Fatalf("DeleteDeadRefreshTokens = %d, %v; want 2", n, err)
	}
	if got := keys(t, s, "refresh_tokens", "token_hash"); !slices.Equal(got, []string{"live", "revoked-recently"}) {
		t.Fatalf("tokens left %v, want [live revoked-recently]", got)
	}
}

func TestDeleteSpentResetTokens(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mkUser(t, s, "r@example.org")
	now := time.Now().UTC()
	mkReset(t, s, "live", u.ID, model.ResetPurposeReset, now.Add(time.Hour))
	mkReset(t, s, "used", u.ID, model.ResetPurposeInvite, now.Add(time.Hour))
	mkReset(t, s, "expired", u.ID, model.ResetPurposeReset, now.Add(-time.Second))
	if _, err := s.ConsumeResetToken(ctx, "used"); err != nil {
		t.Fatal(err)
	}
	n, err := s.DeleteSpentResetTokens(ctx)
	if err != nil || n != 2 {
		t.Fatalf("DeleteSpentResetTokens = %d, %v; want 2", n, err)
	}
	if got := keys(t, s, "password_reset_tokens", "token_hash"); !slices.Equal(got, []string{"live"}) {
		t.Fatalf("tokens left %v, want [live]", got)
	}
}

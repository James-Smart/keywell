package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"keywell/internal/model"
)

// CreateAuthCode stores a new authorization code (already hashed).
func (s *Store) CreateAuthCode(ctx context.Context, c *model.AuthCode) error {
	_, err := s.q.ExecContext(ctx, `INSERT INTO auth_codes
		(code_hash, application_id, user_id, session_id, redirect_uri, scope, nonce,
		 code_challenge, code_challenge_method, auth_time, expires_at, used_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.CodeHash, c.ApplicationID, c.UserID, c.SessionID, c.RedirectURI, c.Scope, c.Nonce,
		c.CodeChallenge, c.CodeChallengeMethod, formatTime(c.AuthTime), formatTime(c.ExpiresAt), nullTime(c.UsedAt))
	return wrapWrite("store: create auth code", err)
}

// ConsumeAuthCode atomically marks an unused, unexpired code as used and returns it.
// It returns ErrNotFound if the code is missing, already used or expired.
func (s *Store) ConsumeAuthCode(ctx context.Context, codeHash string) (*model.AuthCode, error) {
	now := formatTime(time.Now())
	res, err := s.q.ExecContext(ctx, `UPDATE auth_codes SET used_at=? WHERE code_hash=? AND used_at IS NULL AND expires_at > ?`,
		now, codeHash, now)
	if err != nil {
		return nil, fmt.Errorf("store: consume auth code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("store: consume auth code: %w", err)
	}
	if n != 1 {
		return nil, ErrNotFound
	}
	var (
		c                   model.AuthCode
		authTime, expiresAt string
		usedAt              sql.NullString
	)
	err = s.q.QueryRowContext(ctx, `SELECT code_hash, application_id, user_id, session_id, redirect_uri, scope, nonce,
		code_challenge, code_challenge_method, auth_time, expires_at, used_at FROM auth_codes WHERE code_hash=?`, codeHash).
		Scan(&c.CodeHash, &c.ApplicationID, &c.UserID, &c.SessionID, &c.RedirectURI, &c.Scope, &c.Nonce,
			&c.CodeChallenge, &c.CodeChallengeMethod, &authTime, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: read auth code: %w", err)
	}
	if c.AuthTime, err = parseTime(authTime); err != nil {
		return nil, err
	}
	if c.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return nil, err
	}
	if c.UsedAt, err = parseNullTime(usedAt); err != nil {
		return nil, err
	}
	return &c, nil
}

// CreateRefreshToken stores a new refresh token (already hashed).
func (s *Store) CreateRefreshToken(ctx context.Context, t *model.RefreshToken) error {
	_, err := s.q.ExecContext(ctx, `INSERT INTO refresh_tokens
		(token_hash, family_id, application_id, user_id, scope, nonce, auth_time, created_at,
		 expires_at, absolute_expires_at, revoked_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		t.TokenHash, t.FamilyID, t.ApplicationID, t.UserID, t.Scope, t.Nonce, formatTime(t.AuthTime),
		formatTime(t.CreatedAt), formatTime(t.ExpiresAt), formatTime(t.AbsoluteExpiresAt), nullTime(t.RevokedAt))
	return wrapWrite("store: create refresh token", err)
}

// GetRefreshToken returns the token even if revoked or expired; callers decide.
func (s *Store) GetRefreshToken(ctx context.Context, tokenHash string) (*model.RefreshToken, error) {
	var (
		t                                                 model.RefreshToken
		authTime, createdAt, expiresAt, absoluteExpiresAt string
		revokedAt                                         sql.NullString
	)
	err := s.q.QueryRowContext(ctx, `SELECT token_hash, family_id, application_id, user_id, scope, nonce,
		auth_time, created_at, expires_at, absolute_expires_at, revoked_at FROM refresh_tokens WHERE token_hash=?`, tokenHash).
		Scan(&t.TokenHash, &t.FamilyID, &t.ApplicationID, &t.UserID, &t.Scope, &t.Nonce,
			&authTime, &createdAt, &expiresAt, &absoluteExpiresAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get refresh token: %w", err)
	}
	for _, f := range []struct {
		dst *time.Time
		src string
	}{{&t.AuthTime, authTime}, {&t.CreatedAt, createdAt}, {&t.ExpiresAt, expiresAt}, {&t.AbsoluteExpiresAt, absoluteExpiresAt}} {
		if *f.dst, err = parseTime(f.src); err != nil {
			return nil, err
		}
	}
	if t.RevokedAt, err = parseNullTime(revokedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) revokeWhere(ctx context.Context, op, col, val string) error {
	_, err := s.q.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at=? WHERE `+col+`=? AND revoked_at IS NULL`,
		formatTime(time.Now()), val)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// RevokeRefreshToken revokes one token; already-revoked or unknown tokens are a no-op.
func (s *Store) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	return s.revokeWhere(ctx, "store: revoke refresh token", "token_hash", tokenHash)
}

// RevokeRefreshTokenIfActive revokes the token as of now if it is neither
// revoked nor expired, and reports whether it did. It is atomic, so of two
// concurrent calls for one token at most one returns true.
func (s *Store) RevokeRefreshTokenIfActive(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	at := formatTime(now)
	res, err := s.q.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at=?
		WHERE token_hash=? AND revoked_at IS NULL AND expires_at > ?`, at, tokenHash, at)
	if err != nil {
		return false, fmt.Errorf("store: revoke active refresh token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: revoke active refresh token: %w", err)
	}
	return n == 1, nil
}

// RevokeRefreshTokenFamily revokes every token in the family.
func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID string) error {
	return s.revokeWhere(ctx, "store: revoke refresh token family", "family_id", familyID)
}

// RevokeRefreshTokensForUser revokes every token belonging to the user.
func (s *Store) RevokeRefreshTokensForUser(ctx context.Context, userID string) error {
	return s.revokeWhere(ctx, "store: revoke user refresh tokens", "user_id", userID)
}

// DeleteSpentAuthCodes removes authorization codes that are used or
// expired, and returns how many it removed.
func (s *Store) DeleteSpentAuthCodes(ctx context.Context) (int64, error) {
	return s.deleteRows(ctx, "store: delete spent auth codes",
		`DELETE FROM auth_codes WHERE used_at IS NOT NULL OR expires_at <= ?`, formatTime(time.Now()))
}

// revokedRefreshKept is how long a revoked refresh token is kept, so that
// presenting it again still ends its family (reuse detection).
const revokedRefreshKept = 24 * time.Hour

// DeleteDeadRefreshTokens removes refresh tokens past their absolute
// lifetime, or revoked more than revokedRefreshKept ago, and returns how
// many it removed.
func (s *Store) DeleteDeadRefreshTokens(ctx context.Context) (int64, error) {
	now := time.Now()
	return s.deleteRows(ctx, "store: delete dead refresh tokens",
		`DELETE FROM refresh_tokens WHERE absolute_expires_at <= ? OR revoked_at <= ?`,
		formatTime(now), formatTime(now.Add(-revokedRefreshKept)))
}

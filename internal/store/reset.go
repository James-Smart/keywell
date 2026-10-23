package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"latch/internal/model"
)

// CreateResetToken stores a new reset or invite token (already hashed).
func (s *Store) CreateResetToken(ctx context.Context, t *model.ResetToken) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO password_reset_tokens
		(token_hash, user_id, purpose, created_at, expires_at, used_at) VALUES (?,?,?,?,?,?)`,
		t.TokenHash, t.UserID, string(t.Purpose), formatTime(t.CreatedAt), formatTime(t.ExpiresAt), nullTime(t.UsedAt))
	return wrapWrite("store: create reset token", err)
}

// ConsumeResetToken atomically marks an unused, unexpired token as used and returns it.
// It returns ErrNotFound if the token is missing, already used or expired.
func (s *Store) ConsumeResetToken(ctx context.Context, tokenHash string) (*model.ResetToken, error) {
	now := formatTime(time.Now())
	res, err := s.db.ExecContext(ctx, `UPDATE password_reset_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at > ?`,
		now, tokenHash, now)
	if err != nil {
		return nil, fmt.Errorf("store: consume reset token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("store: consume reset token: %w", err)
	}
	if n != 1 {
		return nil, ErrNotFound
	}
	return s.readResetToken(ctx, `SELECT `+resetCols+` FROM password_reset_tokens WHERE token_hash=?`, tokenHash)
}

// PeekResetToken returns an unused, unexpired token without using it up.
// It returns ErrNotFound if the token is missing, already used or expired.
func (s *Store) PeekResetToken(ctx context.Context, tokenHash string) (*model.ResetToken, error) {
	return s.readResetToken(ctx, `SELECT `+resetCols+` FROM password_reset_tokens
		WHERE token_hash=? AND used_at IS NULL AND expires_at > ?`, tokenHash, formatTime(time.Now()))
}

const resetCols = `token_hash, user_id, purpose, created_at, expires_at, used_at`

// readResetToken returns the row query selects (columns resetCols), or
// ErrNotFound when it selects none.
func (s *Store) readResetToken(ctx context.Context, query string, args ...any) (*model.ResetToken, error) {
	var (
		t                             model.ResetToken
		purpose, createdAt, expiresAt string
		usedAt                        sql.NullString
	)
	err := s.db.QueryRowContext(ctx, query, args...).
		Scan(&t.TokenHash, &t.UserID, &purpose, &createdAt, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: read reset token: %w", err)
	}
	t.Purpose = model.ResetPurpose(purpose)
	if t.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if t.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return nil, err
	}
	if t.UsedAt, err = parseNullTime(usedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

// DeleteSpentResetTokens removes reset and invite tokens that are used or
// expired, and returns how many it removed.
func (s *Store) DeleteSpentResetTokens(ctx context.Context) (int64, error) {
	return s.deleteRows(ctx, "store: delete spent reset tokens",
		`DELETE FROM password_reset_tokens WHERE used_at IS NOT NULL OR expires_at <= ?`, formatTime(time.Now()))
}

// HasActiveInviteToken reports whether the user has an unused, unexpired invite token.
func (s *Store) HasActiveInviteToken(ctx context.Context, userID string) (bool, error) {
	var ok bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM password_reset_tokens
		WHERE user_id=? AND purpose='invite' AND used_at IS NULL AND expires_at > ?)`,
		userID, formatTime(time.Now())).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("store: check invite token: %w", err)
	}
	return ok, nil
}

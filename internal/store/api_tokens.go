package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"keywell/internal/model"
	"keywell/internal/secrets"
)

const apiTokenCols = `id, service_account_id, label, token_hash, scope, created_by_user_id, created_at, last_used_at, expires_at`

func scanAPIToken(row interface{ Scan(...any) error }) (*model.APIToken, error) {
	var (
		t                     model.APIToken
		createdAt             string
		lastUsedAt, expiresAt sql.NullString
	)
	err := row.Scan(&t.ID, &t.ServiceAccountID, &t.Label, &t.TokenHash, &t.Scope, &t.CreatedByUserID,
		&createdAt, &lastUsedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan api token: %w", err)
	}
	if t.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if t.LastUsedAt, err = parseNullTime(lastUsedAt); err != nil {
		return nil, err
	}
	if t.ExpiresAt, err = parseNullTime(expiresAt); err != nil {
		return nil, err
	}
	return &t, nil
}

// CreateAPIToken inserts t (its hash already computed), filling ID and
// CreatedAt when empty. A hash already in use is ErrConflict.
func (s *Store) CreateAPIToken(ctx context.Context, t *model.APIToken) error {
	if t.ID == "" {
		t.ID = secrets.NewID()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	_, err := s.q.ExecContext(ctx, `INSERT INTO api_tokens (`+apiTokenCols+`) VALUES (?,?,?,?,?,?,?,?,?)`,
		t.ID, t.ServiceAccountID, t.Label, t.TokenHash, string(t.Scope), t.CreatedByUserID,
		formatTime(t.CreatedAt), nullTime(t.LastUsedAt), nullTime(t.ExpiresAt))
	return wrapWrite("store: create api token", err)
}

// ListAPITokens returns the service account's tokens, newest first.
func (s *Store) ListAPITokens(ctx context.Context, serviceAccountID string) ([]model.APIToken, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT `+apiTokenCols+` FROM api_tokens
		WHERE service_account_id = ? ORDER BY created_at DESC, id`, serviceAccountID)
	if err != nil {
		return nil, fmt.Errorf("store: list api tokens: %w", err)
	}
	defer rows.Close()
	var out []model.APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list api tokens: %w", err)
	}
	return out, nil
}

// GetAPITokenByHash returns the token with the given hash, even if expired;
// callers decide.
func (s *Store) GetAPITokenByHash(ctx context.Context, tokenHash string) (*model.APIToken, error) {
	return scanAPIToken(s.q.QueryRowContext(ctx, `SELECT `+apiTokenCols+` FROM api_tokens WHERE token_hash = ?`, tokenHash))
}

// TouchAPIToken records that the token was used at the given time.
func (s *Store) TouchAPIToken(ctx context.Context, id string, at time.Time) error {
	res, err := s.q.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, formatTime(at), id)
	return oneRow("store: touch api token", res, err)
}

// DeleteAPIToken revokes a token; ErrNotFound unless it belongs to that
// service account.
func (s *Store) DeleteAPIToken(ctx context.Context, serviceAccountID, id string) error {
	res, err := s.q.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ? AND service_account_id = ?`, id, serviceAccountID)
	return oneRow("store: delete api token", res, err)
}

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"keywell/internal/model"
)

// InsertSigningKey stores a signing key; ErrConflict if the kid exists.
func (s *Store) InsertSigningKey(ctx context.Context, k *model.SigningKey) error {
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	_, err := s.q.ExecContext(ctx, `INSERT INTO signing_keys (kid, alg, private_key_enc, public_key_pem, created_at, retired_at)
		VALUES (?,?,?,?,?,?)`,
		k.KID, k.Alg, k.PrivateKeyEnc, k.PublicKeyPEM, formatTime(k.CreatedAt), nullTime(k.RetiredAt))
	return wrapWrite("store: insert signing key", err)
}

// ListSigningKeys returns all keys, newest first, including retired ones.
func (s *Store) ListSigningKeys(ctx context.Context) ([]model.SigningKey, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT kid, alg, private_key_enc, public_key_pem, created_at, retired_at
		FROM signing_keys ORDER BY created_at DESC, kid`)
	if err != nil {
		return nil, fmt.Errorf("store: list signing keys: %w", err)
	}
	defer rows.Close()
	keys := []model.SigningKey{}
	for rows.Next() {
		var (
			k         model.SigningKey
			createdAt string
			retiredAt sql.NullString
		)
		if err := rows.Scan(&k.KID, &k.Alg, &k.PrivateKeyEnc, &k.PublicKeyPEM, &createdAt, &retiredAt); err != nil {
			return nil, fmt.Errorf("store: scan signing key: %w", err)
		}
		if k.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, err
		}
		if k.RetiredAt, err = parseNullTime(retiredAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list signing keys: %w", err)
	}
	return keys, nil
}

// RetireSigningKey marks the key retired at the given time.
func (s *Store) RetireSigningKey(ctx context.Context, kid string, at time.Time) error {
	res, err := s.q.ExecContext(ctx, `UPDATE signing_keys SET retired_at=? WHERE kid=?`, formatTime(at), kid)
	return oneRow("store: retire signing key", res, err)
}

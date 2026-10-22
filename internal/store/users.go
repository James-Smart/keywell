package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"latch/internal/model"
	"latch/internal/secrets"
)

const userCols = `id, name, type, COALESCE(email,''), COALESCE(username,''), password_hash,
	legacy_password_hash, is_active, metadata, totp_secret_enc, totp_confirmed_at, authentik_pk,
	COALESCE(authentik_uuid,''), COALESCE(authentik_uid,''), last_login_at, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*model.User, error) {
	var (
		u                    model.User
		active               int
		meta                 sql.NullString
		totpAt, lastLogin    sql.NullString
		pk                   sql.NullInt64
		createdAt, updatedAt string
	)
	err := row.Scan(&u.ID, &u.Name, &u.Type, &u.Email, &u.Username, &u.PasswordHash,
		&u.LegacyPasswordHash, &active, &meta, &u.TOTPSecretEnc, &totpAt, &pk,
		&u.AuthentikUUID, &u.AuthentikUID, &lastLogin, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan user: %w", err)
	}
	u.IsActive = active != 0
	if pk.Valid {
		v := pk.Int64
		u.AuthentikPK = &v
	}
	if u.Metadata, err = unmarshalMeta(meta); err != nil {
		return nil, err
	}
	if u.TOTPConfirmedAt, err = parseNullTime(totpAt); err != nil {
		return nil, err
	}
	if u.LastLoginAt, err = parseNullTime(lastLogin); err != nil {
		return nil, err
	}
	if u.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if u.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

func nullPK(pk *int64) any {
	if pk == nil {
		return nil
	}
	return *pk
}

// CreateUser inserts u, filling ID, timestamps and Type when empty.
func (s *Store) CreateUser(ctx context.Context, u *model.User) error {
	if u.ID == "" {
		u.ID = secrets.NewID()
	}
	if u.Type == "" {
		u.Type = model.UserTypeMember
	}
	u.Email = strings.TrimSpace(u.Email)
	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = now
	}
	meta, err := marshalMeta(u.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO users
		(id, name, type, email, username, password_hash, legacy_password_hash, is_active, metadata,
		 totp_secret_enc, totp_confirmed_at, authentik_pk, authentik_uuid, authentik_uid,
		 last_login_at, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.Name, string(u.Type), nullIfEmpty(u.Email), nullIfEmpty(u.Username),
		u.PasswordHash, u.LegacyPasswordHash, boolInt(u.IsActive), meta,
		u.TOTPSecretEnc, nullTime(u.TOTPConfirmedAt), nullPK(u.AuthentikPK),
		nullIfEmpty(u.AuthentikUUID), nullIfEmpty(u.AuthentikUID),
		nullTime(u.LastLoginAt), formatTime(u.CreatedAt), formatTime(u.UpdatedAt))
	return wrapWrite("store: create user", err)
}

func (s *Store) getUserWhere(ctx context.Context, where string, arg any) (*model.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE `+where, arg))
}

// GetUser returns the user with the given id.
func (s *Store) GetUser(ctx context.Context, id string) (*model.User, error) {
	return s.getUserWhere(ctx, `id = ?`, id)
}

// GetUserByEmail looks a user up by trimmed, case-insensitive email.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	return s.getUserWhere(ctx, `lower(email) = lower(?)`, strings.TrimSpace(email))
}

// GetUserByUsername looks a user up by exact username.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	return s.getUserWhere(ctx, `username = ?`, username)
}

// UpdateUser writes every column except the password and TOTP columns.
func (s *Store) UpdateUser(ctx context.Context, u *model.User) error {
	meta, err := marshalMeta(u.Metadata)
	if err != nil {
		return err
	}
	u.Email = strings.TrimSpace(u.Email)
	u.UpdatedAt = time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE users SET name=?, email=?, username=?, type=?, is_active=?,
		metadata=?, authentik_pk=?, authentik_uuid=?, authentik_uid=?, updated_at=? WHERE id=?`,
		u.Name, nullIfEmpty(u.Email), nullIfEmpty(u.Username), string(u.Type), boolInt(u.IsActive),
		meta, nullPK(u.AuthentikPK), nullIfEmpty(u.AuthentikUUID), nullIfEmpty(u.AuthentikUID),
		formatTime(u.UpdatedAt), u.ID)
	return oneRow("store: update user", res, err)
}

// oneRow converts an exec result into ErrNotFound when no row was affected.
func oneRow(op string, res sql.Result, err error) error {
	if err != nil {
		return wrapWrite(op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPassword stores a native hash and clears any legacy hash.
func (s *Store) SetPassword(ctx context.Context, userID, phcHash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash=?, legacy_password_hash='', updated_at=? WHERE id=?`,
		phcHash, formatTime(time.Now()), userID)
	return oneRow("store: set password", res, err)
}

// SetTOTP stores the sealed TOTP secret and confirmation time.
func (s *Store) SetTOTP(ctx context.Context, userID string, secretEnc []byte, confirmedAt *time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret_enc=?, totp_confirmed_at=?, updated_at=? WHERE id=?`,
		secretEnc, nullTime(confirmedAt), formatTime(time.Now()), userID)
	return oneRow("store: set totp", res, err)
}

// ClearTOTP removes TOTP enrolment and the user's recovery codes.
func (s *Store) ClearTOTP(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: clear totp: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret_enc=NULL, totp_confirmed_at=NULL, updated_at=? WHERE id=?`,
		formatTime(time.Now()), userID)
	if err := oneRow("store: clear totp", res, err); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=?`, userID); err != nil {
		return fmt.Errorf("store: clear recovery codes: %w", err)
	}
	return tx.Commit()
}

// TouchLastLogin records a successful login time.
func (s *Store) TouchLastLogin(ctx context.Context, userID string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET last_login_at=? WHERE id=?`, formatTime(at), userID)
	return oneRow("store: touch last login", res, err)
}

// ReplaceRecoveryCodes atomically swaps the user's recovery codes for codeHashes.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, codeHashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: replace recovery codes: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=?`, userID); err != nil {
		return fmt.Errorf("store: replace recovery codes: %w", err)
	}
	for _, h := range codeHashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes (id, user_id, code_hash) VALUES (?,?,?)`,
			secrets.NewID(), userID, h); err != nil {
			return wrapWrite("store: replace recovery codes", err)
		}
	}
	return tx.Commit()
}

// ConsumeRecoveryCode marks an unused code as used; it reports whether one was consumed.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID, codeHash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL`,
		formatTime(time.Now()), userID, codeHash)
	if err != nil {
		return false, fmt.Errorf("store: consume recovery code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: consume recovery code: %w", err)
	}
	return n == 1, nil
}

// CountUnusedRecoveryCodes returns how many recovery codes the user has left.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count recovery codes: %w", err)
	}
	return n, nil
}

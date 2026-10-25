package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"latch/internal/model"
	"latch/internal/secrets"
)

// ImportRun is the record of one import from Authentik.
type ImportRun struct {
	ID                    string
	StartedAt, FinishedAt time.Time
	Source                string // authentik.Source(dsn)
	Report                string // importer.Report as JSON
}

// InsertImportRun stores r, filling ID when empty.
func (s *Store) InsertImportRun(ctx context.Context, r *ImportRun) error {
	if r.ID == "" {
		r.ID = secrets.NewID()
	}
	_, err := s.q.ExecContext(ctx, `INSERT INTO import_runs (id, started_at, finished_at, source, report)
		VALUES (?,?,?,?,?)`, r.ID, formatTime(r.StartedAt), formatTime(r.FinishedAt), r.Source, r.Report)
	return wrapWrite("store: insert import run", err)
}

// LastImportRun returns the run that finished last, or ErrNotFound.
func (s *Store) LastImportRun(ctx context.Context) (*ImportRun, error) {
	var (
		r                 ImportRun
		startedAt, finish string
	)
	err := s.q.QueryRowContext(ctx, `SELECT id, started_at, finished_at, source, report FROM import_runs
		ORDER BY finished_at DESC, id DESC LIMIT 1`).Scan(&r.ID, &startedAt, &finish, &r.Source, &r.Report)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: last import run: %w", err)
	}
	if r.StartedAt, err = parseTime(startedAt); err != nil {
		return nil, err
	}
	if r.FinishedAt, err = parseTime(finish); err != nil {
		return nil, err
	}
	return &r, nil
}

// AllUsers returns every member and service account, oldest first.
func (s *Store) AllUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: all users: %w", err)
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: all users: %w", err)
	}
	return out, nil
}

// SetLegacyPassword stores an imported hash for a user with no native
// password. It reports whether it did; a user who already has a native hash,
// or no such user, is left alone.
func (s *Store) SetLegacyPassword(ctx context.Context, userID, hash string) (bool, error) {
	res, err := s.q.ExecContext(ctx, `UPDATE users SET legacy_password_hash=?, updated_at=?
		WHERE id=? AND password_hash=''`, hash, formatTime(time.Now()), userID)
	if err != nil {
		return false, fmt.Errorf("store: set legacy password: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: set legacy password: %w", err)
	}
	return n == 1, nil
}

// ImportTOTP enrols the user with an imported secret: it sets the sealed
// secret, confirmation time and last claimed step, and replaces the recovery
// codes, in one transaction. ErrNotFound if there is no such user.
func (s *Store) ImportTOTP(ctx context.Context, userID string, secretEnc []byte, confirmedAt time.Time,
	lastStep int64, codeHashes []string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret_enc=?, totp_confirmed_at=?, totp_last_step=?,
			updated_at=? WHERE id=?`, secretEnc, formatTime(confirmedAt), lastStep, formatTime(time.Now()), userID)
		if err := oneRow("store: import totp", res, err); err != nil {
			return err
		}
		return replaceRecoveryCodes(ctx, tx, userID, codeHashes)
	})
}

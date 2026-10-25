package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PutTOTPEnrolment starts (or restarts) the session's TOTP enrolment with
// the sealed secret, dropping any recovery codes stored for it.
func (s *Store) PutTOTPEnrolment(ctx context.Context, sessionID string, secretEnc []byte) error {
	_, err := s.q.ExecContext(ctx, `INSERT INTO totp_enrolments (session_id, secret_enc, codes_json, created_at)
		VALUES (?,?,NULL,?)
		ON CONFLICT(session_id) DO UPDATE SET secret_enc=excluded.secret_enc, codes_json=NULL, created_at=excluded.created_at`,
		sessionID, secretEnc, formatTime(time.Now()))
	return wrapWrite("store: put totp enrolment", err)
}

// GetTOTPEnrolment returns the session's enrolment, or ErrNotFound. Until
// it is confirmed that is the sealed pending secret and codesJSON "";
// afterwards an empty secret and the recovery codes still to show.
func (s *Store) GetTOTPEnrolment(ctx context.Context, sessionID string) (secretEnc []byte, codesJSON string, err error) {
	err = s.q.QueryRowContext(ctx, `SELECT secret_enc, COALESCE(codes_json,'') FROM totp_enrolments WHERE session_id=?`,
		sessionID).Scan(&secretEnc, &codesJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("store: get totp enrolment: %w", err)
	}
	return secretEnc, codesJSON, nil
}

// CompleteTOTPEnrolment confirms the session's enrolment in one
// transaction: secretEnc becomes the user's TOTP secret, confirmed at
// confirmedAt with the code for time step, which is claimed as by
// ClaimTOTPStep so that code cannot also sign in; codeHashes replace their
// recovery codes; and the enrolment
// keeps codesJSON, the codes to show once, while its copy of the secret is
// cleared. It returns ErrConflict when the user is already enrolled (or does
// not exist) and ErrNotFound when the session has no enrolment; either way
// nothing is written.
func (s *Store) CompleteTOTPEnrolment(ctx context.Context, userID, sessionID string, secretEnc []byte,
	confirmedAt time.Time, step int64, codeHashes []string, codesJSON string) error {
	const op = "store: complete totp enrolment"
	return s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret_enc=?, totp_confirmed_at=?, totp_last_step=?,
			updated_at=? WHERE id=? AND totp_confirmed_at IS NULL`,
			secretEnc, formatTime(confirmedAt), step, formatTime(time.Now()), userID)
		if err := oneRow(op, res, err); errors.Is(err, ErrNotFound) {
			return fmt.Errorf("%s: %w", op, ErrConflict)
		} else if err != nil {
			return err
		}
		// secret_enc is NOT NULL; an empty blob is "no secret".
		res, err = tx.ExecContext(ctx, `UPDATE totp_enrolments SET secret_enc=X'', codes_json=? WHERE session_id=?`,
			codesJSON, sessionID)
		if err := oneRow(op, res, err); err != nil {
			return err
		}
		if err := replaceRecoveryCodes(ctx, tx, userID, codeHashes); err != nil {
			return err
		}
		return nil
	})
}

// DeleteTOTPEnrolment removes the session's enrolment; none is a no-op.
func (s *Store) DeleteTOTPEnrolment(ctx context.Context, sessionID string) error {
	if _, err := s.q.ExecContext(ctx, `DELETE FROM totp_enrolments WHERE session_id=?`, sessionID); err != nil {
		return fmt.Errorf("store: delete totp enrolment: %w", err)
	}
	return nil
}

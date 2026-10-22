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
	_, err := s.db.ExecContext(ctx, `INSERT INTO totp_enrolments (session_id, secret_enc, codes_json, created_at)
		VALUES (?,?,NULL,?)
		ON CONFLICT(session_id) DO UPDATE SET secret_enc=excluded.secret_enc, codes_json=NULL, created_at=excluded.created_at`,
		sessionID, secretEnc, formatTime(time.Now()))
	return wrapWrite("store: put totp enrolment", err)
}

// GetTOTPEnrolment returns the session's sealed pending secret and the
// recovery codes JSON ("" until confirmed), or ErrNotFound.
func (s *Store) GetTOTPEnrolment(ctx context.Context, sessionID string) (secretEnc []byte, codesJSON string, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT secret_enc, COALESCE(codes_json,'') FROM totp_enrolments WHERE session_id=?`,
		sessionID).Scan(&secretEnc, &codesJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("store: get totp enrolment: %w", err)
	}
	return secretEnc, codesJSON, nil
}

// SetTOTPEnrolmentCodes stores the recovery codes to show once, or returns
// ErrNotFound when the session has no enrolment.
func (s *Store) SetTOTPEnrolmentCodes(ctx context.Context, sessionID, codesJSON string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE totp_enrolments SET codes_json=? WHERE session_id=?`, codesJSON, sessionID)
	return oneRow("store: set totp enrolment codes", res, err)
}

// DeleteTOTPEnrolment removes the session's enrolment; none is a no-op.
func (s *Store) DeleteTOTPEnrolment(ctx context.Context, sessionID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM totp_enrolments WHERE session_id=?`, sessionID); err != nil {
		return fmt.Errorf("store: delete totp enrolment: %w", err)
	}
	return nil
}

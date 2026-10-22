package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"latch/internal/model"
)

// CreateSession stores a new session.
func (s *Store) CreateSession(ctx context.Context, sess *model.Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions
		(id, user_id, created_at, last_seen_at, expires_at, totp_passed, ip, user_agent)
		VALUES (?,?,?,?,?,?,?,?)`,
		sess.ID, sess.UserID, formatTime(sess.CreatedAt), formatTime(sess.LastSeenAt), formatTime(sess.ExpiresAt),
		boolInt(sess.TOTPPassed), nullIfEmpty(sess.IP), nullIfEmpty(sess.UserAgent))
	return wrapWrite("store: create session", err)
}

// GetSession returns the session, or ErrNotFound if it is missing or expired.
func (s *Store) GetSession(ctx context.Context, id string) (*model.Session, error) {
	var (
		sess                             model.Session
		createdAt, lastSeenAt, expiresAt string
		totpPassed                       int
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, created_at, last_seen_at, expires_at, totp_passed,
		COALESCE(ip,''), COALESCE(user_agent,'') FROM sessions WHERE id=? AND expires_at > ?`,
		id, formatTime(time.Now())).
		Scan(&sess.ID, &sess.UserID, &createdAt, &lastSeenAt, &expiresAt, &totpPassed, &sess.IP, &sess.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get session: %w", err)
	}
	if sess.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if sess.LastSeenAt, err = parseTime(lastSeenAt); err != nil {
		return nil, err
	}
	if sess.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return nil, err
	}
	sess.TOTPPassed = totpPassed != 0
	return &sess, nil
}

// UpdateSession writes LastSeenAt, ExpiresAt and TOTPPassed.
func (s *Store) UpdateSession(ctx context.Context, sess *model.Session) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at=?, expires_at=?, totp_passed=? WHERE id=?`,
		formatTime(sess.LastSeenAt), formatTime(sess.ExpiresAt), boolInt(sess.TOTPPassed), sess.ID)
	if err != nil {
		return fmt.Errorf("store: update session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: update session: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchSession writes only LastSeenAt and ExpiresAt, so it cannot undo a
// concurrent change to TOTPPassed.
func (s *Store) TouchSession(ctx context.Context, id string, lastSeen, expires time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at=?, expires_at=? WHERE id=?`,
		formatTime(lastSeen), formatTime(expires), id)
	return oneRow("store: touch session", res, err)
}

// IncrementTOTPFailures counts one more wrong code at the session's TOTP
// step and returns the new total, or ErrNotFound.
func (s *Store) IncrementTOTPFailures(ctx context.Context, sessionID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `UPDATE sessions SET totp_failures = totp_failures + 1 WHERE id=?
		RETURNING totp_failures`, sessionID).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("store: count totp failure: %w", err)
	}
	return n, nil
}

// DeleteSession removes one session; a missing session is a no-op.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, id); err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}

// DeleteSessionsForUser removes every session belonging to the user.
func (s *Store) DeleteSessionsForUser(ctx context.Context, userID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return fmt.Errorf("store: delete user sessions: %w", err)
	}
	return nil
}

// DeleteExpiredSessions removes expired sessions and returns how many were removed.
func (s *Store) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, formatTime(time.Now()))
	if err != nil {
		return 0, fmt.Errorf("store: delete expired sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: delete expired sessions: %w", err)
	}
	return n, nil
}

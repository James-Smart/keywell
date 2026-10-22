// Package store is the SQLite-backed persistence layer for Latch.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	// ErrNotFound is returned when a requested row does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned on a unique constraint violation.
	ErrConflict = errors.New("store: conflict")
)

// Store wraps the database handle.
type Store struct{ db *sql.DB }

// New returns a Store using db.
func New(db *sql.DB) *Store { return &Store{db: db} }

// isUniqueViolation reports whether err is a SQLite unique constraint failure.
func isUniqueViolation(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return true
		}
	}
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// wrapWrite maps unique violations to ErrConflict and wraps other errors.
func wrapWrite(op string, err error) error {
	if err == nil {
		return nil
	}
	if isUniqueViolation(err) {
		return fmt.Errorf("%s: %w", op, ErrConflict)
	}
	return fmt.Errorf("%s: %w", op, err)
}

// timeLayout is fixed-width UTC (always 9 fractional digits) so that string
// comparison of stored timestamps orders chronologically.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("store: parse time %q: %w", s, err)
	}
	return t.UTC(), nil
}

// nullIfEmpty stores "" as NULL.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

func parseNullTime(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func marshalMeta(m map[string]any) (string, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("store: marshal metadata: %w", err)
	}
	return string(b), nil
}

func unmarshalMeta(s sql.NullString) (map[string]any, error) {
	m := map[string]any{}
	if !s.Valid || s.String == "" {
		return m, nil
	}
	if err := json.Unmarshal([]byte(s.String), &m); err != nil {
		return nil, fmt.Errorf("store: unmarshal metadata: %w", err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

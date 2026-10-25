// Package store is the SQLite-backed persistence layer for Latch.
package store

import (
	"context"
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

// dbtx is what both *sql.DB and *sql.Tx offer; every query goes through it.
type dbtx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Store wraps the database handle. A Store handed to InTx's callback is bound
// to that transaction: all of its calls run inside it.
type Store struct {
	db  *sql.DB
	q   dbtx    // db, or tx when bound
	tx  *sql.Tx // non-nil when bound to a transaction
	spN int     // savepoint counter, for unique names; bound stores only
}

// New returns a Store using db.
func New(db *sql.DB) *Store { return &Store{db: db, q: db} }

// InTx runs fn with a Store whose calls all share one transaction. It commits
// if fn returns nil and rolls back otherwise, returning fn's error unchanged.
// On a Store already bound to a transaction it just calls fn with that Store.
// Inside fn use only tx: the database has one connection, so a call on the
// outer Store would wait for the transaction forever.
func (s *Store) InTx(ctx context.Context, fn func(tx *Store) error) error {
	if s.tx != nil {
		return fn(s)
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		return fn(&Store{db: s.db, q: tx, tx: tx})
	})
}

// withTx runs fn in the Store's transaction when bound to one, else in a
// transaction of its own that commits when fn returns nil. In a bound Store
// fn runs inside a savepoint, so when it fails its partial writes are undone
// and the transaction stays usable; the caller may carry on.
func (s *Store) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	if s.tx != nil {
		s.spN++
		name := fmt.Sprintf("latch_sp_%d", s.spN)
		if _, err := s.tx.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
			return fmt.Errorf("store: savepoint: %w", err)
		}
		if err := fn(s.tx); err != nil {
			// Undo fn's writes. If the rollback itself fails the outer
			// transaction is unusable and its own rollback will follow.
			_, _ = s.tx.ExecContext(ctx, "ROLLBACK TO "+name)
			_, _ = s.tx.ExecContext(ctx, "RELEASE "+name)
			return err
		}
		if _, err := s.tx.ExecContext(ctx, "RELEASE "+name); err != nil {
			return fmt.Errorf("store: release savepoint: %w", err)
		}
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

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

// deleteRows runs a DELETE and returns how many rows it removed.
func (s *Store) deleteRows(ctx context.Context, op, query string, args ...any) (int64, error) {
	res, err := s.q.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return n, nil
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

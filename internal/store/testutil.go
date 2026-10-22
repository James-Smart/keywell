package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"latch/internal/db"
)

// OpenTest returns a Store backed by a fresh, migrated temp-file database that
// is closed when the test ends.
func OpenTest(t *testing.T) *Store {
	t.Helper()
	s, _ := OpenTestDB(t)
	return s
}

// OpenTestDB is OpenTest that also returns the database, for tests that read
// tables the store has no reader for, such as audit_events.
func OpenTestDB(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := db.Migrate(context.Background(), d); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}
	return New(d), d
}

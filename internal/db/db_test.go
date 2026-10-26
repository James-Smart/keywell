package db_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/James-Smart/keywell/internal/db"
)

func open(t *testing.T) *sql.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestMigrateFreshAndIdempotent(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	applied, err := db.Migrate(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(applied, []string{"0001_core.sql", "0002_totp_enrolment.sql", "0003_totp_last_step.sql", "0004_admin.sql", "0005_import.sql"}) {
		t.Fatalf("applied = %v", applied)
	}
	applied, err = db.Migrate(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 0 {
		t.Fatalf("second run applied %v", applied)
	}
	rows, err := d.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		have[n] = true
	}
	for _, n := range []string{"users", "recovery_codes", "groups", "memberships", "applications", "application_groups", "sessions", "auth_codes", "refresh_tokens", "password_reset_tokens", "signing_keys", "audit_events", "totp_enrolments", "schema_migrations"} {
		if !have[n] {
			t.Errorf("missing table %s", n)
		}
	}
}

func TestForeignKeysOn(t *testing.T) {
	d := open(t)
	var v int
	if err := d.QueryRow(`PRAGMA foreign_keys`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Fatalf("foreign_keys = %d", v)
	}
}

package audit_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/James-Smart/keywell/internal/audit"
	"github.com/James-Smart/keywell/internal/db"
	"github.com/James-Smart/keywell/internal/model"
	"github.com/James-Smart/keywell/internal/store"
)

func TestAuditInsertAndRecorder(t *testing.T) {
	ctx := context.Background()
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := db.Migrate(ctx, d); err != nil {
		t.Fatal(err)
	}
	r := audit.New(store.New(d), slog.New(slog.NewTextHandler(io.Discard, nil)))
	at, id := audit.UserActor("u1")
	r.Record(ctx, model.AuditEvent{ActorType: at, ActorID: id, Action: audit.LoginSuccess, TargetType: "user", TargetID: "u1",
		Detail: map[string]any{"ip": "10.0.0.1", "n": float64(2)}})
	r.Record(ctx, model.AuditEvent{ActorType: audit.ActorSystem, Action: audit.KeyRotated})

	var evID, atStr, actorType, actorID, action, detail string
	err = d.QueryRowContext(ctx, `SELECT id, at, actor_type, actor_id, action, detail FROM audit_events WHERE action=?`,
		audit.LoginSuccess).Scan(&evID, &atStr, &actorType, &actorID, &action, &detail)
	if err != nil {
		t.Fatal(err)
	}
	if evID == "" || atStr == "" || actorType != "user" || actorID != "u1" || action != "login.success" {
		t.Fatalf("row: %q %q %q %q %q", evID, atStr, actorType, actorID, action)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(detail), &m); err != nil || m["ip"] != "10.0.0.1" || m["n"] != float64(2) {
		t.Fatalf("detail: %s %v", detail, err)
	}
	if err := d.QueryRowContext(ctx, `SELECT detail FROM audit_events WHERE action=?`, audit.KeyRotated).Scan(&detail); err != nil || detail != "{}" {
		t.Fatalf("nil detail: %q %v", detail, err)
	}
}

// The observer sees every event, including ones that could not be stored,
// and the recorder it was added to is left unchanged.
func TestWithObserver(t *testing.T) {
	ctx := context.Background()
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migrate(ctx, d); err != nil {
		t.Fatal(err)
	}
	base := audit.New(store.New(d), slog.New(slog.NewTextHandler(io.Discard, nil)))
	var seen []string
	r := base.WithObserver(func(e model.AuditEvent) { seen = append(seen, e.Action) })
	r.Record(ctx, model.AuditEvent{ActorType: audit.ActorSystem, Action: audit.KeyRotated})
	base.Record(ctx, model.AuditEvent{ActorType: audit.ActorSystem, Action: audit.Logout})
	d.Close() // inserts now fail
	r.Record(ctx, model.AuditEvent{ActorType: audit.ActorSystem, Action: audit.LoginFailure})
	if len(seen) != 2 || seen[0] != audit.KeyRotated || seen[1] != audit.LoginFailure {
		t.Fatalf("observed %v", seen)
	}
}

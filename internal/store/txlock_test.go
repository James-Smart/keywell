package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/James-Smart/keywell/internal/db"
	"github.com/James-Smart/keywell/internal/model"
)

// A transaction that reads and then writes must not lose the race to
// another process (a running `keywell serve`) that commits in between: it
// takes the write lock when it begins, so the other writer waits.
func TestInTxTakesWriteLockUpFront(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "shared.db")
	da, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer da.Close()
	if _, err := db.Migrate(ctx, da); err != nil {
		t.Fatal(err)
	}
	dbB, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dbB.Close()
	a, b := New(da), New(dbB)

	bDone := make(chan error, 1)
	err = a.InTx(ctx, func(tx *Store) error {
		if _, err := tx.AllUsers(ctx); err != nil {
			return err
		}
		go func() {
			bDone <- b.CreateUser(ctx, &model.User{Name: "B", Email: "b@example.org", IsActive: true})
		}()
		select {
		case err := <-bDone:
			t.Errorf("B's write finished while A's transaction was open: %v", err)
			bDone <- err
		case <-time.After(300 * time.Millisecond):
		}
		return tx.CreateUser(ctx, &model.User{Name: "A", Email: "a@example.org", IsActive: true})
	})
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	select {
	case err := <-bDone:
		if err != nil {
			t.Fatalf("B: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("B never finished")
	}
	us, err := a.AllUsers(ctx)
	if err != nil || len(us) != 2 {
		t.Fatalf("users: %d %v", len(us), err)
	}
}

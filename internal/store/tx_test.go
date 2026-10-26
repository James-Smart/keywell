package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"keywell/internal/model"
)

func TestInTxCommits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := openTest(t)
	var uid, gid string
	err := s.InTx(ctx, func(tx *Store) error {
		u := &model.User{Name: "A", Email: "a@example.org", IsActive: true}
		g := &model.Group{Name: "G"}
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		if err := tx.CreateGroup(ctx, g); err != nil {
			return err
		}
		uid, gid = u.ID, g.ID
		return tx.AddMember(ctx, u.ID, g.ID)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUser(ctx, uid); err != nil {
		t.Fatalf("user: %v", err)
	}
	gs, err := s.ListGroupsForUser(ctx, uid)
	if err != nil || len(gs) != 1 || gs[0].ID != gid {
		t.Fatalf("groups: %+v %v", gs, err)
	}
}

func TestInTxRollsBack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := openTest(t)
	existing := mkUser(t, s, "keep@example.org")
	if err := s.ReplaceRecoveryCodes(ctx, existing.ID, []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	if err := s.SetTOTP(ctx, existing.ID, []byte("sealed"), &at); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	err := s.InTx(ctx, func(tx *Store) error {
		u := &model.User{Name: "N", Email: "n@example.org", IsActive: true}
		g := &model.Group{Name: "NG"}
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		if err := tx.CreateGroup(ctx, g); err != nil {
			return err
		}
		a := &model.Application{Name: "App", Slug: "app", ClientID: "app", AllowedGroupIDs: []string{g.ID}}
		if err := tx.CreateApplication(ctx, a); err != nil {
			return err
		}
		if err := tx.ReplaceRecoveryCodes(ctx, existing.ID, []string{"x"}); err != nil {
			return err
		}
		if err := tx.ClearTOTP(ctx, existing.ID); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if _, err := s.GetUserByEmail(ctx, "n@example.org"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("user left behind: %v", err)
	}
	if _, err := s.GetGroupByName(ctx, "NG"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("group left behind: %v", err)
	}
	if _, err := s.GetApplicationBySlug(ctx, "app"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("app left behind: %v", err)
	}
	got, err := s.GetUser(ctx, existing.ID)
	if err != nil || !got.TOTPEnrolled() {
		t.Fatalf("totp cleared despite rollback: %+v %v", got, err)
	}
	if n, err := s.CountUnusedRecoveryCodes(ctx, existing.ID); err != nil || n != 2 {
		t.Fatalf("recovery codes = %d %v, want 2", n, err)
	}
}

func TestInTxMethodsUseTheTransaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := openTest(t)
	err := s.InTx(ctx, func(tx *Store) error {
		u := &model.User{Name: "U", Email: "u@example.org", IsActive: true}
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		g := &model.Group{Name: "G"}
		if err := tx.CreateGroup(ctx, g); err != nil {
			return err
		}
		if err := tx.ReplaceUserGroups(ctx, u.ID, []string{g.ID}); err != nil {
			return err
		}
		a := &model.Application{Name: "A", Slug: "a", ClientID: "a", AllowedGroupIDs: []string{g.ID}}
		if err := tx.CreateApplication(ctx, a); err != nil {
			return err
		}
		a.Name = "A2"
		if err := tx.UpdateApplication(ctx, a); err != nil {
			return err
		}
		g.Description = "d"
		g.AuthentikUUID = "uuid-1"
		if err := tx.UpdateGroup(ctx, g); err != nil {
			return err
		}
		u.Name = "U2"
		if err := tx.UpdateUser(ctx, u); err != nil {
			return err
		}
		if ok, err := tx.SetLegacyPassword(ctx, u.ID, "legacy"); err != nil || !ok {
			return errors.Join(errors.New("SetLegacyPassword"), err)
		}
		if err := tx.ImportTOTP(ctx, u.ID, []byte("s"), time.Now(), 5, []string{"a", "b"}); err != nil {
			return err
		}
		if err := tx.ClearTOTP(ctx, u.ID); err != nil {
			return err
		}
		if _, err := tx.AllUsers(ctx); err != nil {
			return err
		}
		if _, err := tx.GetUser(ctx, u.ID); err != nil {
			return err
		}
		if _, err := tx.GetUserByEmail(ctx, "u@example.org"); err != nil {
			return err
		}
		if _, err := tx.GetGroupByName(ctx, "G"); err != nil {
			return err
		}
		if _, err := tx.ListGroups(ctx); err != nil {
			return err
		}
		if _, err := tx.ListApplications(ctx); err != nil {
			return err
		}
		if _, err := tx.GetApplicationByClientID(ctx, "a"); err != nil {
			return err
		}
		if err := tx.AddMember(ctx, u.ID, g.ID); err != nil {
			return err
		}
		if err := tx.RemoveMember(ctx, u.ID, g.ID); err != nil {
			return err
		}
		if err := tx.InsertImportRun(ctx, &ImportRun{StartedAt: time.Now(), FinishedAt: time.Now(), Source: "h:1/d", Report: "{}"}); err != nil {
			return err
		}
		if _, err := tx.LastImportRun(ctx); err != nil {
			return err
		}
		// Nested InTx joins the same transaction.
		return tx.InTx(ctx, func(inner *Store) error {
			_, err := inner.AllUsers(ctx)
			return err
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInTxFailedCallUndoesItsPartialWrites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := openTest(t)
	u := mkUser(t, s, "m@example.org")
	keep := mkGroup(t, s, "Keep")
	other := mkGroup(t, s, "Other")
	if err := s.AddMember(ctx, u.ID, keep.ID); err != nil {
		t.Fatal(err)
	}
	memberOf := func(st *Store) []string {
		t.Helper()
		gs, err := st.ListGroupsForUser(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, g := range gs {
			out = append(out, g.Name)
		}
		return out
	}
	err := s.InTx(ctx, func(tx *Store) error {
		if err := tx.ReplaceUserGroups(ctx, u.ID, []string{other.ID, "no-such-group"}); err == nil {
			t.Error("unknown group accepted")
		}
		if got := memberOf(tx); len(got) != 1 || got[0] != "Keep" {
			t.Errorf("inside tx: memberships = %v, want [Keep]", got)
		}
		a := &model.Application{Name: "A", Slug: "a", ClientID: "a", AllowedGroupIDs: []string{other.ID, "no-such-group"}}
		if err := tx.CreateApplication(ctx, a); err == nil {
			t.Error("app with unknown group accepted")
		}
		if _, err := tx.GetApplicationBySlug(ctx, "a"); !errors.Is(err, ErrNotFound) {
			t.Errorf("inside tx: app left behind: %v", err)
		}
		// The transaction is still usable and its later writes commit.
		return tx.AddMember(ctx, u.ID, other.ID)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := memberOf(s); len(got) != 2 {
		t.Fatalf("after commit: memberships = %v, want Keep and Other", got)
	}
	if _, err := s.GetApplicationBySlug(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after commit: app left behind: %v", err)
	}
}

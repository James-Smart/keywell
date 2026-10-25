package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"latch/internal/model"
)

func TestSetLegacyPassword(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	fresh := mkUser(t, s, "fresh@example.org")
	if ok, err := s.SetLegacyPassword(ctx, fresh.ID, "pbkdf2:legacy"); err != nil || !ok {
		t.Fatalf("fresh user: %v %v", ok, err)
	}
	got, _ := s.GetUser(ctx, fresh.ID)
	if got.LegacyPasswordHash != "pbkdf2:legacy" || got.PasswordHash != "" {
		t.Fatalf("got %+v", got)
	}

	native := mkUser(t, s, "native@example.org")
	if err := s.SetPassword(ctx, native.ID, "$argon2id$native"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SetLegacyPassword(ctx, native.ID, "pbkdf2:legacy"); err != nil || ok {
		t.Fatalf("native user: %v %v", ok, err)
	}
	got, _ = s.GetUser(ctx, native.ID)
	if got.LegacyPasswordHash != "" || got.PasswordHash != "$argon2id$native" {
		t.Fatalf("native row changed: %+v", got)
	}

	if ok, err := s.SetLegacyPassword(ctx, "nope", "x"); err != nil || ok {
		t.Fatalf("unknown user: %v %v", ok, err)
	}
}

func TestImportTOTP(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mkUser(t, s, "t@example.org")
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := s.ImportTOTP(ctx, u.ID, []byte("sealed"), at, 100, []string{"a", "b", "c"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.TOTPEnrolled() || got.TOTPConfirmedAt == nil || !got.TOTPConfirmedAt.Equal(at) || string(got.TOTPSecretEnc) != "sealed" {
		t.Fatalf("got %+v", got)
	}
	if n, err := s.CountUnusedRecoveryCodes(ctx, u.ID); err != nil || n != 3 {
		t.Fatalf("codes = %d %v, want 3", n, err)
	}
	if ok, err := s.ClaimTOTPStep(ctx, u.ID, 100); err != nil || ok {
		t.Fatalf("lastStep claimable: %v %v", ok, err)
	}
	if ok, err := s.ClaimTOTPStep(ctx, u.ID, 101); err != nil || !ok {
		t.Fatalf("lastStep+1 not claimable: %v %v", ok, err)
	}

	if err := s.ImportTOTP(ctx, u.ID, []byte("sealed2"), at, 200, []string{"x", "y", "z"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountUnusedRecoveryCodes(ctx, u.ID); n != 3 {
		t.Fatalf("codes = %d, want 3 (replaced, not added)", n)
	}
	if err := s.ImportTOTP(ctx, "nope", []byte("s"), at, 1, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestAllUsers(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(name string, typ model.UserType, age int) {
		t.Helper()
		u := &model.User{Name: name, Type: typ, IsActive: true, CreatedAt: base.Add(time.Duration(age) * time.Hour)}
		if typ == model.UserTypeMember {
			u.Email = name + "@example.org"
		}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	mk("third", model.UserTypeMember, 3)
	mk("first", model.UserTypeMember, 1)
	mk("svc", model.UserTypeService, 2)
	got, err := s.AllUsers(ctx)
	if err != nil || len(got) != 3 {
		t.Fatalf("got %d %v", len(got), err)
	}
	if got[0].Name != "first" || got[1].Name != "svc" || got[2].Name != "third" {
		t.Fatalf("order: %s %s %s", got[0].Name, got[1].Name, got[2].Name)
	}
}

func TestImportRuns(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.LastImportRun(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty: %v", err)
	}
	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	later := &ImportRun{StartedAt: t0, FinishedAt: t0.Add(2 * time.Hour), Source: "db:5432/authentik", Report: `{"a":1}`}
	earlier := &ImportRun{StartedAt: t0.Add(30 * time.Minute), FinishedAt: t0.Add(40 * time.Minute), Source: "other:5432/x", Report: `{}`}
	// Insert the later one first so insertion order cannot decide the answer.
	if err := s.InsertImportRun(ctx, later); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertImportRun(ctx, earlier); err != nil {
		t.Fatal(err)
	}
	if later.ID == "" || later.ID == earlier.ID {
		t.Fatalf("ids: %q %q", later.ID, earlier.ID)
	}
	got, err := s.LastImportRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != later.ID || !got.StartedAt.Equal(later.StartedAt) || !got.FinishedAt.Equal(later.FinishedAt) ||
		got.Source != later.Source || got.Report != later.Report {
		t.Fatalf("got %+v, want %+v", got, later)
	}
}

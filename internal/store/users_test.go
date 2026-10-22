package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"latch/internal/model"
)

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func TestCreateAndGetUser(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	u := &model.User{Name: "Alex", Email: "  Alex@Example.org ", Username: "alex", IsActive: true,
		Metadata: map[string]any{"member_number": 42}}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if u.ID == "" || u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() || u.Type != model.UserTypeMember {
		t.Fatalf("not filled: %+v", u)
	}
	for _, get := range []func() (*model.User, error){
		func() (*model.User, error) { return s.GetUser(ctx, u.ID) },
		func() (*model.User, error) { return s.GetUserByEmail(ctx, "  ALEX@Example.org ") },
		func() (*model.User, error) { return s.GetUserByUsername(ctx, "alex") },
	} {
		got, err := get()
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != u.ID || got.Email != "Alex@Example.org" || got.Name != "Alex" || !got.IsActive {
			t.Fatalf("got %+v", got)
		}
		if !jsonEqual(got.Metadata, map[string]any{"member_number": 42}) {
			t.Fatalf("metadata %v", got.Metadata)
		}
		if !got.CreatedAt.Equal(u.CreatedAt) {
			t.Fatalf("created %v vs %v", got.CreatedAt, u.CreatedAt)
		}
	}
	if _, err := s.GetUser(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := s.GetUserByEmail(ctx, "nobody@example.org"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestUpdateUser(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	u := &model.User{Name: "Alex", Email: "a@example.org", IsActive: true}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	pk := int64(7)
	u.Name, u.Username, u.IsActive, u.AuthentikPK, u.AuthentikUUID = "Alexa", "alexa", false, &pk, "uuid-1"
	u.Metadata = map[string]any{"k": "v"}
	if err := s.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Alexa" || got.Username != "alexa" || got.IsActive || got.AuthentikPK == nil || *got.AuthentikPK != 7 || got.AuthentikUUID != "uuid-1" {
		t.Fatalf("got %+v", got)
	}
	if err := s.UpdateUser(ctx, &model.User{ID: "missing", Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestCreateUserDuplicateEmailCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	if err := s.CreateUser(ctx, &model.User{Name: "A", Email: "alex@example.org"}); err != nil {
		t.Fatal(err)
	}
	err := s.CreateUser(ctx, &model.User{Name: "B", Email: "Alex@example.org"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}

func TestServiceAccountNoEmail(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	for _, name := range []string{"door", "printer"} {
		u := &model.User{Name: name, Type: model.UserTypeService, Username: name, IsActive: true}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	got, err := s.GetUserByUsername(ctx, "door")
	if err != nil || got.Email != "" || got.Type != model.UserTypeService {
		t.Fatalf("got %+v err %v", got, err)
	}
	err = s.CreateUser(ctx, &model.User{Name: "dup", Type: model.UserTypeService, Username: "door"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}

func TestSetPasswordClearsLegacy(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	u := &model.User{Name: "A", Email: "a@example.org", LegacyPasswordHash: "pbkdf2_sha256$1$x$y"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if got.LegacyPasswordHash == "" || !got.HasPassword() {
		t.Fatalf("legacy not stored: %+v", got)
	}
	if err := s.SetPassword(ctx, u.ID, "$argon2id$new"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetUser(ctx, u.ID)
	if got.PasswordHash != "$argon2id$new" || got.LegacyPasswordHash != "" {
		t.Fatalf("got %+v", got)
	}
	if err := s.SetPassword(ctx, "missing", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestTOTPAndRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	u := &model.User{Name: "A", Email: "a@example.org"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	if err := s.SetTOTP(ctx, u.ID, []byte("sealed"), &at); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if string(got.TOTPSecretEnc) != "sealed" || !got.TOTPEnrolled() || !got.TOTPConfirmedAt.Equal(at) {
		t.Fatalf("got %+v", got)
	}
	if err := s.ReplaceRecoveryCodes(ctx, u.ID, []string{"h1", "h2", "h3"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConsumeRecoveryCode(ctx, u.ID, "h1"); err != nil || !ok {
		t.Fatalf("first consume: %v %v", ok, err)
	}
	if ok, err := s.ConsumeRecoveryCode(ctx, u.ID, "h1"); err != nil || ok {
		t.Fatalf("second consume: %v %v", ok, err)
	}
	if ok, _ := s.ConsumeRecoveryCode(ctx, u.ID, "unknown"); ok {
		t.Fatal("unknown code consumed")
	}
	if n, err := s.CountUnusedRecoveryCodes(ctx, u.ID); err != nil || n != 2 {
		t.Fatalf("count %d %v", n, err)
	}
	if err := s.ReplaceRecoveryCodes(ctx, u.ID, []string{"n1"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountUnusedRecoveryCodes(ctx, u.ID); n != 1 {
		t.Fatalf("after replace count %d", n)
	}
	if err := s.ClearTOTP(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetUser(ctx, u.ID)
	if got.TOTPSecretEnc != nil || got.TOTPEnrolled() {
		t.Fatalf("totp not cleared: %+v", got)
	}
	if n, _ := s.CountUnusedRecoveryCodes(ctx, u.ID); n != 0 {
		t.Fatalf("codes remain: %d", n)
	}
}

func TestTouchLastLogin(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	u := &model.User{Name: "A", Email: "a@example.org"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Hour)
	if err := s.TouchLastLogin(ctx, u.ID, at); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if got.LastLoginAt == nil || !got.LastLoginAt.Equal(at) {
		t.Fatalf("last login %v want %v", got.LastLoginAt, at)
	}
}

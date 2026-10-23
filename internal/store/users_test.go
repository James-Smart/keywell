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
	s := openTest(t)
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
	s := openTest(t)
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
	s := openTest(t)
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
	s := openTest(t)
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
	s := openTest(t)
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
	s := openTest(t)
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

// Each TOTP time step can be claimed once, and only after the last one
// claimed, so a code is never accepted twice (RFC 6238 §5.2).
func TestClaimTOTPStep(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := &model.User{Name: "A", Email: "a@example.org"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		step int64
		want bool
	}{
		{100, true},  // nothing claimed yet
		{100, false}, // the same code again
		{99, false},  // an older code
		{101, true},
	} {
		if ok, err := s.ClaimTOTPStep(ctx, u.ID, c.step); ok != c.want || err != nil {
			t.Fatalf("ClaimTOTPStep(%d) = %v, %v; want %v", c.step, ok, err, c.want)
		}
	}
	// Turning TOTP off forgets the last step, for a new secret.
	if err := s.ClearTOTP(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ClaimTOTPStep(ctx, u.ID, 50); !ok || err != nil {
		t.Fatalf("ClaimTOTPStep after ClearTOTP = %v, %v; want true", ok, err)
	}
	if ok, err := s.ClaimTOTPStep(ctx, "nobody", 1000); ok || err != nil {
		t.Fatalf("ClaimTOTPStep(unknown user) = %v, %v; want false, nil", ok, err)
	}
}

func TestTouchLastLogin(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
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

func TestUserDescriptionRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := &model.User{Name: "Door", Type: model.UserTypeService, Username: "door", IsActive: true, Description: "Door controller"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUser(ctx, u.ID)
	if err != nil || got.Description != "Door controller" {
		t.Fatalf("got %+v, %v", got, err)
	}
	got.Description = "Front door"
	if err := s.UpdateUser(ctx, got); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetUser(ctx, u.ID)
	if err != nil || got.Description != "Front door" {
		t.Fatalf("after update %+v, %v", got, err)
	}
}

func TestDeleteUserCascades(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now().UTC()
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := s.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	u := mkUser(t, s, "gone@example.org")
	g := mkGroup(t, s, "g")
	if err := s.AddMember(ctx, u.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	mkSession(t, s, "sess", u.ID, now.Add(time.Hour))
	mkReset(t, s, "reset", u.ID, model.ResetPurposeReset, now.Add(time.Hour))
	if err := s.ReplaceRecoveryCodes(ctx, u.ID, []string{"c1"}); err != nil {
		t.Fatal(err)
	}
	svc := &model.User{Name: "svc", Type: model.UserTypeService, Username: "svc", IsActive: true}
	if err := s.CreateUser(ctx, svc); err != nil {
		t.Fatal(err)
	}
	app := &model.Application{Name: "App", Slug: "app", ClientID: "app", ClientType: model.ClientTypePublic,
		SubjectMode: model.SubjectModeID, ServiceAccountID: svc.ID}
	if err := s.CreateApplication(ctx, app); err != nil {
		t.Fatal(err)
	}
	rt := &model.RefreshToken{TokenHash: "rt", FamilyID: "f", ApplicationID: app.ID, UserID: u.ID,
		AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour)}
	if err := s.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatal(err)
	}
	tok := &model.APIToken{ServiceAccountID: svc.ID, Label: "t", TokenHash: "h", Scope: model.APITokenScopeRead}
	if err := s.CreateAPIToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertAuditEvent(ctx, &model.AuditEvent{ActorType: model.ActorUser, ActorID: u.ID, Action: "x", TargetID: svc.ID}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"memberships", "sessions", "refresh_tokens", "password_reset_tokens", "recovery_codes"} {
		if n := count(`SELECT COUNT(*) FROM `+tbl+` WHERE user_id = ?`, u.ID); n != 0 {
			t.Errorf("%s: %d rows remain", tbl, n)
		}
	}
	if _, err := s.GetUser(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("user remains: %v", err)
	}
	if err := s.DeleteUser(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}

	if err := s.DeleteUser(ctx, svc.ID); err != nil {
		t.Fatal(err)
	}
	if n := count(`SELECT COUNT(*) FROM api_tokens WHERE service_account_id = ?`, svc.ID); n != 0 {
		t.Errorf("api_tokens: %d rows remain", n)
	}
	got, err := s.GetApplication(ctx, app.ID)
	if err != nil || got.ServiceAccountID != "" {
		t.Fatalf("app after account delete: %+v, %v", got, err)
	}
	if n := count(`SELECT COUNT(*) FROM audit_events`); n != 1 {
		t.Errorf("audit_events: %d, want 1", n)
	}
}

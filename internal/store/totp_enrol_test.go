package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestTOTPEnrolmentLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mkUser(t, s, "enrol@example.org")
	mkSession(t, s, "sess", u.ID, time.Now().Add(time.Hour))

	if _, _, err := s.GetTOTPEnrolment(ctx, "sess"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get before put: %v", err)
	}

	if err := s.PutTOTPEnrolment(ctx, "sess", []byte("first")); err != nil {
		t.Fatal(err)
	}
	secret, codes, err := s.GetTOTPEnrolment(ctx, "sess")
	if err != nil || !bytes.Equal(secret, []byte("first")) || codes != "" {
		t.Fatalf("get: %q %q %v", secret, codes, err)
	}
	// Starting again replaces the pending secret.
	if err := s.PutTOTPEnrolment(ctx, "sess", []byte("second")); err != nil {
		t.Fatal(err)
	}

	confirmed := time.Now().UTC()
	if err := s.CompleteTOTPEnrolment(ctx, u.ID, "sess", []byte("second"), confirmed, 500,
		[]string{"h1", "h2"}, `["c1","c2"]`); err != nil {
		t.Fatal(err)
	}
	// The code that confirmed the enrolment cannot sign in afterwards.
	if ok, err := s.ClaimTOTPStep(ctx, u.ID, 500); ok || err != nil {
		t.Fatalf("claim the confirming step: %v, %v; want false", ok, err)
	}
	if ok, err := s.ClaimTOTPStep(ctx, u.ID, 501); !ok || err != nil {
		t.Fatalf("claim the next step: %v, %v; want true", ok, err)
	}
	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.TOTPSecretEnc, []byte("second")) || got.TOTPConfirmedAt == nil || !got.TOTPConfirmedAt.Equal(confirmed) {
		t.Fatalf("user after complete: secret %q confirmed %v", got.TOTPSecretEnc, got.TOTPConfirmedAt)
	}
	if n, err := s.CountUnusedRecoveryCodes(ctx, u.ID); err != nil || n != 2 {
		t.Fatalf("recovery codes: %d, %v", n, err)
	}
	// The enrolment now holds only the codes to show: never the live secret.
	secret, codes, err = s.GetTOTPEnrolment(ctx, "sess")
	if err != nil || len(secret) != 0 || codes != `["c1","c2"]` {
		t.Fatalf("enrolment after complete: %q %q %v", secret, codes, err)
	}

	// Put drops any codes still waiting.
	if err := s.PutTOTPEnrolment(ctx, "sess", []byte("third")); err != nil {
		t.Fatal(err)
	}
	if secret, codes, err := s.GetTOTPEnrolment(ctx, "sess"); err != nil || !bytes.Equal(secret, []byte("third")) || codes != "" {
		t.Fatalf("after put: %q %q %v", secret, codes, err)
	}

	if err := s.DeleteTOTPEnrolment(ctx, "sess"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GetTOTPEnrolment(ctx, "sess"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
	if err := s.DeleteTOTPEnrolment(ctx, "sess"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
}

// A second completion (a double-submitted confirm) changes nothing: the
// codes stored as hashes stay the ones kept to show.
func TestCompleteTOTPEnrolmentRefusesSecond(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mkUser(t, s, "twice@example.org")
	mkSession(t, s, "sess", u.ID, time.Now().Add(time.Hour))
	if err := s.PutTOTPEnrolment(ctx, "sess", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.CompleteTOTPEnrolment(ctx, u.ID, "sess", []byte("secret"), now, 1, []string{"a1", "a2"}, `["a"]`); err != nil {
		t.Fatal(err)
	}

	err := s.CompleteTOTPEnrolment(ctx, u.ID, "sess", []byte("other"), now.Add(time.Second), 2, []string{"b1", "b2", "b3"}, `["b"]`)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("second complete: %v, want ErrConflict", err)
	}
	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.TOTPSecretEnc, []byte("secret")) || !got.TOTPConfirmedAt.Equal(now) {
		t.Fatalf("user changed by the second complete: %q %v", got.TOTPSecretEnc, got.TOTPConfirmedAt)
	}
	if n, err := s.CountUnusedRecoveryCodes(ctx, u.ID); err != nil || n != 2 {
		t.Fatalf("recovery codes: %d, %v", n, err)
	}
	if ok, err := s.ConsumeRecoveryCode(ctx, u.ID, "a1"); !ok || err != nil {
		t.Fatalf("first set's code gone: %v %v", ok, err)
	}
	if _, codes, err := s.GetTOTPEnrolment(ctx, "sess"); err != nil || codes != `["a"]` {
		t.Fatalf("codes to show: %q %v", codes, err)
	}
}

// Without the session's enrolment nothing is written, the user included.
func TestCompleteTOTPEnrolmentNeedsEnrolment(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mkUser(t, s, "none@example.org")
	mkSession(t, s, "sess", u.ID, time.Now().Add(time.Hour))

	err := s.CompleteTOTPEnrolment(ctx, u.ID, "sess", []byte("secret"), time.Now(), 1, []string{"h"}, `["c"]`)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("complete without enrolment: %v, want ErrNotFound", err)
	}
	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TOTPEnrolled() || got.TOTPSecretEnc != nil {
		t.Fatalf("user enrolled without an enrolment: %+v", got)
	}
	if n, err := s.CountUnusedRecoveryCodes(ctx, u.ID); err != nil || n != 0 {
		t.Fatalf("recovery codes: %d, %v", n, err)
	}
}

// A pending enrolment, which may hold plaintext recovery codes, goes when
// its session does.
func TestTOTPEnrolmentEndsWithSession(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mkUser(t, s, "cascade@example.org")
	mkSession(t, s, "sess", u.ID, time.Now().Add(time.Hour))
	if err := s.PutTOTPEnrolment(ctx, "sess", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, "sess"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GetTOTPEnrolment(ctx, "sess"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("enrolment outlived its session: %v", err)
	}
}

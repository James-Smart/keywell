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
	s := OpenTest(t)
	u := mkUser(t, s, "enrol@example.org")
	mkSession(t, s, "sess", u.ID, time.Now().Add(time.Hour))

	if _, _, err := s.GetTOTPEnrolment(ctx, "sess"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get before put: %v", err)
	}
	if err := s.SetTOTPEnrolmentCodes(ctx, "sess", `["a"]`); !errors.Is(err, ErrNotFound) {
		t.Fatalf("set codes before put: %v", err)
	}

	if err := s.PutTOTPEnrolment(ctx, "sess", []byte("first")); err != nil {
		t.Fatal(err)
	}
	secret, codes, err := s.GetTOTPEnrolment(ctx, "sess")
	if err != nil || !bytes.Equal(secret, []byte("first")) || codes != "" {
		t.Fatalf("get: %q %q %v", secret, codes, err)
	}
	if err := s.SetTOTPEnrolmentCodes(ctx, "sess", `["abcde-fghjk"]`); err != nil {
		t.Fatal(err)
	}
	if _, codes, err := s.GetTOTPEnrolment(ctx, "sess"); err != nil || codes != `["abcde-fghjk"]` {
		t.Fatalf("codes: %q %v", codes, err)
	}

	// Starting again replaces the secret and drops any codes.
	if err := s.PutTOTPEnrolment(ctx, "sess", []byte("second")); err != nil {
		t.Fatal(err)
	}
	secret, codes, err = s.GetTOTPEnrolment(ctx, "sess")
	if err != nil || !bytes.Equal(secret, []byte("second")) || codes != "" {
		t.Fatalf("after second put: %q %q %v", secret, codes, err)
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

// A pending enrolment, which may hold plaintext recovery codes, goes when
// its session does.
func TestTOTPEnrolmentEndsWithSession(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
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

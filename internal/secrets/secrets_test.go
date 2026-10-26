package secrets_test

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"testing"

	"keywell/internal/secrets"
)

func TestRandomTokenLengthAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		tok := secrets.RandomToken(32)
		if len(tok) != 43 {
			t.Fatalf("len = %d, want 43", len(tok))
		}
		if seen[tok] {
			t.Fatalf("duplicate token %q", tok)
		}
		seen[tok] = true
	}
}

func TestHashTokenKnown(t *testing.T) {
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := secrets.HashToken("abc"); got != want {
		t.Fatalf("HashToken = %s, want %s", got, want)
	}
}

func TestEncryptorRoundTripAndTamper(t *testing.T) {
	enc, err := secrets.NewEncryptor(secrets.GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("totp-secret")
	sealed, err := enc.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := enc.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip = %q, want %q", got, plain)
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := enc.Open(sealed); err == nil {
		t.Fatal("Open of tampered data succeeded")
	}
	if _, err := enc.Open([]byte("short")); err == nil {
		t.Fatal("Open of short input succeeded")
	}
}

func TestNewEncryptorRejectsShortKey(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := secrets.NewEncryptor(short); err == nil {
		t.Fatal("accepted 16-byte key")
	}
	if _, err := secrets.NewEncryptor("not base64!!"); err == nil {
		t.Fatal("accepted invalid base64")
	}
}

func TestNewIDFormat(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for i := 0; i < 100; i++ {
		if id := secrets.NewID(); !re.MatchString(id) {
			t.Fatalf("bad id %q", id)
		}
	}
}

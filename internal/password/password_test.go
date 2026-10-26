package password_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"keywell/internal/password"
)

const pw = "correct horse battery staple"

// Generated with Django/argon2-cffi/hashlib/bcrypt for pw.
var legacyVectors = []string{
	"argon2$argon2id$v=19$m=102400,t=2,p=8$dks5bVoycFF4TDNuQWJDZA$v8TF/ZYe14p3FcLHRA6jRYFGhPQeg4Ja6gSqYQa18o4",
	"argon2$argon2i$v=19$m=512,t=2,p=2$dks5bVoycFF4TDNuQWJDZA$KsO21ry6WpQq7hLLmlFyyA",
	"pbkdf2_sha256$870000$vK9mZ2pQxL3n$k/YNzDxY8WuRK/+6PjMgYNCGxD4pyHdDwQFRbvUuXCo=",
	"pbkdf2_sha1$870000$vK9mZ2pQxL3n$bBx96KNlmEfYEidEL5887jX7oR8=",
	"scrypt$16384$vK9mZ2pQxL3n$8$1$mxwMrE3lGVjXaWtNecRS7hTkxrQnybG3B5i5Jao4znB257dwfBoQiweWlMmv54syIQUTtPbr22oeIHioiv7I/Q==",
	"bcrypt_sha256$$2b$12$uq70YScYbDqF0tdvP3Yhtu.PIe3/Xobf8UlszETQiO/sTqMtfUVgq",
}

func TestLegacyVectorsVerify(t *testing.T) {
	for _, v := range legacyVectors {
		t.Run(v[:20], func(t *testing.T) {
			if ok, err := password.Verify(pw, v); !ok || err != nil {
				t.Errorf("Verify(correct) = %v, %v; want true, nil", ok, err)
			}
			if ok, err := password.Verify("wrong", v); ok || err != nil {
				t.Errorf("Verify(wrong) = %v, %v; want false, nil", ok, err)
			}
			if !password.IsLegacy(v) {
				t.Error("IsLegacy = false, want true")
			}
		})
	}
}

func TestNativeRoundTrip(t *testing.T) {
	h, err := password.Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "$argon2id$v=19$m=65536,t=3,p=4$"
	if !strings.HasPrefix(h, prefix) {
		t.Fatalf("Hash = %q, want prefix %q", h, prefix)
	}
	salt, sum, ok := strings.Cut(strings.TrimPrefix(h, prefix), "$")
	if !ok {
		t.Fatalf("Hash = %q, want salt$hash after parameters", h)
	}
	if b, err := base64.RawStdEncoding.DecodeString(salt); err != nil || len(b) != 16 {
		t.Errorf("salt %q: %d bytes, err %v; want 16 bytes unpadded base64", salt, len(b), err)
	}
	if b, err := base64.RawStdEncoding.DecodeString(sum); err != nil || len(b) != 32 {
		t.Errorf("hash %q: %d bytes, err %v; want 32 bytes unpadded base64", sum, len(b), err)
	}
	if ok, err := password.Verify(pw, h); !ok || err != nil {
		t.Errorf("Verify(correct) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := password.Verify("wrong", h); ok || err != nil {
		t.Errorf("Verify(wrong) = %v, %v; want false, nil", ok, err)
	}
	if password.IsLegacy(h) {
		t.Error("IsLegacy(native) = true, want false")
	}
	h2, err := password.Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	if h == h2 {
		t.Error("two Hash calls returned the same string")
	}
}

// Verify must read the cost parameters from the stored string, so that the
// defaults can be raised without breaking existing hashes.
func TestNativeVerifyUsesEncodedParameters(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(pw), salt, 1, 8*1024, 1, 32)
	h := "$argon2id$v=19$m=8192,t=1,p=1$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(key)
	if ok, err := password.Verify(pw, h); !ok || err != nil {
		t.Errorf("Verify(correct) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := password.Verify("wrong", h); ok || err != nil {
		t.Errorf("Verify(wrong) = %v, %v; want false, nil", ok, err)
	}
}

func TestUnusableAndUnsupported(t *testing.T) {
	for _, enc := range []string{"", "!abc"} {
		if ok, err := password.Verify(pw, enc); ok || !errors.Is(err, password.ErrUnusable) {
			t.Errorf("Verify(%q) = %v, %v; want false, ErrUnusable", enc, ok, err)
		}
	}
	if ok, err := password.Verify(pw, "md5$x$y"); ok || !errors.Is(err, password.ErrUnsupported) {
		t.Errorf("Verify(md5) = %v, %v; want false, ErrUnsupported", ok, err)
	}
}

// Malformed stored hashes must fail with an error, never panic and never
// match. An empty hash part must be caught before hashing: argon2 and scrypt
// panic on a zero key length, and an empty derived key would compare equal
// to it.
var malformedHashes = []string{
	"$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$",
	"$argon2id$v=19$m=65536,t=0,p=4$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA",
	"$argon2id$v=19$m=65536,t=3,p=0$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA",
	"$argon2id$v=19$m=65536,t=3$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA",
	"$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$!!!",
	"$argon2id$v=16$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA",
	"argon2$argon2d$v=19$m=512,t=2,p=2$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA",
	"$argon2id$v=19$m=263168,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA",       // 257 MiB
	"argon2$argon2id$v=19$m=263168,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA", // 257 MiB
	"pbkdf2_sha256$870000$salt$",
	"pbkdf2_sha256$0$salt$aGFzaA==",
	"pbkdf2_sha256$870000$salt",
	"pbkdf2_sha1$abc$salt$aGFzaA==",
	"scrypt$16384$salt$8$1$",
	"scrypt$1000$salt$8$1$aGFzaA==",
	"scrypt$16384$salt$8$aGFzaA==",
	"scrypt$16384$salt$0$1$aGFzaA==",
	"scrypt$16384$salt$8$0$aGFzaA==",
	"bcrypt_sha256$$2b$12$short",
	"bcrypt_sha256$",
	"bcrypt_sha256$$2b$12$uq70YScYbDqF0tdvP3Yh!u.PIe3/Xobf8UlszETQiO/sTqMtfUVgq",
}

func TestMalformedHashesFail(t *testing.T) {
	for _, enc := range malformedHashes {
		ok, err := password.Verify(pw, enc)
		if ok || err == nil {
			t.Errorf("Verify(%q) = %v, %v; want false, error", enc, ok, err)
		}
	}
}

func TestCheckStored(t *testing.T) {
	native, err := password.Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	for _, enc := range append([]string{native}, legacyVectors...) {
		if err := password.CheckStored(enc); err != nil {
			t.Errorf("CheckStored(%.20q) = %v; want nil", enc, err)
		}
	}
	for _, enc := range []string{"", "!abc"} {
		if err := password.CheckStored(enc); !errors.Is(err, password.ErrUnusable) {
			t.Errorf("CheckStored(%q) = %v; want ErrUnusable", enc, err)
		}
	}
	for _, enc := range []string{"md5$abc$def", "bcrypt$2b$12$uq70YScYbDqF0tdvP3Yhtu.PIe3/Xobf8UlszETQiO/sTqMtfUVgq"} {
		if err := password.CheckStored(enc); !errors.Is(err, password.ErrUnsupported) {
			t.Errorf("CheckStored(%q) = %v; want ErrUnsupported", enc, err)
		}
	}
	for _, enc := range malformedHashes {
		if err := password.CheckStored(enc); err == nil {
			t.Errorf("CheckStored(%q) = nil; want an error, as Verify returns one", enc)
		}
	}
	err = password.CheckStored("pbkdf2_sha256$abc$salt$hash")
	if err == nil || errors.Is(err, password.ErrUnusable) || errors.Is(err, password.ErrUnsupported) {
		t.Errorf("CheckStored(bad pbkdf2) = %v; want a malformed error", err)
	}
}

// Legacy hashes asking for more than the ceilings are refused as malformed,
// by CheckStored and by Verify, without computing anything.
func TestLegacyCeilings(t *testing.T) {
	long := base64.StdEncoding.EncodeToString(make([]byte, 65))
	for _, c := range []struct{ name, enc string }{
		{"scrypt_work", "scrypt$16384$salt$8$64$aGFzaA=="},
		{"scrypt_memory_r", "scrypt$2$salt$2097152$1$aGFzaA=="},
		{"scrypt_memory_p", "scrypt$2$salt$1$2097152$aGFzaA=="},
		{"scrypt_work_overflow", "scrypt$1073741824$salt$1073741824$1073741824$aGFzaA=="},
		{"pbkdf2_len", "pbkdf2_sha256$1000$salt$" + long},
		{"bcrypt_cost", "bcrypt_sha256$$2b$15$uq70YScYbDqF0tdvP3Yhtu.PIe3/Xobf8UlszETQiO/sTqMtfUVgq"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := password.CheckStored(c.enc); err == nil || !strings.Contains(err.Error(), "malformed") {
				t.Errorf("CheckStored = %v; want a malformed-hash error", err)
			}
			start := time.Now()
			ok, err := password.Verify(pw, c.enc)
			if ok || err == nil || !strings.Contains(err.Error(), "malformed") {
				t.Errorf("Verify = %v, %v; want false and a malformed-hash error", ok, err)
			}
			if d := time.Since(start); d > 50*time.Millisecond {
				t.Errorf("Verify took %v; want under 50ms", d)
			}
		})
	}
}

// The scrypt ceilings hold at their edges, including for values that
// overflow a 32-bit int (run with GOARCH=386 too).
func TestScryptCeilingEdges(t *testing.T) {
	for _, c := range []struct {
		enc string
		ok  bool
	}{
		{"scrypt$2$salt$262144$4$aGFzaA==", true},                                                   // 128·r·(N+p+2) = 256 MiB exactly
		{"scrypt$2$salt$262144$5$aGFzaA==", false},                                                  // 288 MiB; N·r·p within the work ceiling
		{"scrypt$2048$salt$1$2048$aGFzaA==", true},                                                  // N·r·p = 1<<22 exactly
		{"scrypt$2048$salt$1$2049$aGFzaA==", false},                                                 // N·r·p just over; memory 2 MiB
		{"scrypt$2$salt$2097152$1$aGFzaA==", false},                                                 // memory 1.25 GiB, within the work ceiling
		{"scrypt$4294967296$salt$1$1$aGFzaA==", false},                                              // N = 1<<32
		{"scrypt$2$salt$4294967296$1$aGFzaA==", false},                                              // r = 1<<32
		{"scrypt$2$salt$1$4294967296$aGFzaA==", false},                                              // p = 1<<32
		{"scrypt$4611686018427387904$salt$4611686018427387904$4611686018427387904$aGFzaA==", false}, // 1<<62 each
		{"scrypt$2$salt$-1$1$aGFzaA==", false},
		// N·r·p = 1<<32 and 128·r·(N+p+2) = 1<<39 + 3<<23: both wrap to
		// small numbers in 32-bit arithmetic.
		{"scrypt$65536$salt$65536$1$aGFzaA==", false},
	} {
		if err := password.CheckStored(c.enc); (err == nil) != c.ok {
			t.Errorf("CheckStored(%q) = %v; want accepted %v", c.enc, err, c.ok)
		}
	}
}

// A stored hash whose cost would take over 256 MiB of memory, or an
// unreasonable time, to check is refused as malformed without hashing.
func TestCostCeilings(t *testing.T) {
	const salt, sum = "c2FsdHNhbHRzYWx0c2FsdA", "aGFzaGhhc2hoYXNoaGFzaA"
	for _, c := range []struct{ name, enc string }{
		{"argon2_m", "$argon2id$v=19$m=262145,t=1,p=1$" + salt + "$" + sum},
		{"argon2_m_django", "argon2$argon2id$v=19$m=262145,t=1,p=1$" + salt + "$" + sum},
		{"argon2_t", "$argon2id$v=19$m=8,t=17,p=1$" + salt + "$" + sum},
		{"pbkdf2_iter", "pbkdf2_sha256$10000001$salt$aGFzaA=="},
		{"scrypt_mem", "scrypt$2097152$salt$8$1$aGFzaA=="},   // 128·N·r = 2 GiB
		{"scrypt_mem_r", "scrypt$2$salt$8388608$1$aGFzaA=="}, // 128·N·r = 2 GiB
	} {
		t.Run(c.name, func(t *testing.T) {
			ok, err := password.Verify(pw, c.enc)
			if ok || err == nil || !strings.Contains(err.Error(), "malformed") {
				t.Fatalf("Verify = %v, %v; want false and a malformed-hash error", ok, err)
			}
		})
	}
	// At the memory ceiling a hash is still accepted (CheckStored hashes
	// nothing, so this costs no memory).
	for _, enc := range []string{
		"$argon2id$v=19$m=262144,t=1,p=1$" + salt + "$" + sum,
		"argon2$argon2id$v=19$m=262144,t=1,p=1$" + salt + "$" + sum,
	} {
		if err := password.CheckStored(enc); err != nil {
			t.Errorf("CheckStored(%.40q) = %v; want nil", enc, err)
		}
	}
	// At the time ceiling (and a tiny memory cost) a hash still verifies.
	salt16 := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(pw), salt16, 16, 8, 1, 32)
	h := "$argon2id$v=19$m=8,t=16,p=1$" + base64.RawStdEncoding.EncodeToString(salt16) + "$" +
		base64.RawStdEncoding.EncodeToString(key)
	if ok, err := password.Verify(pw, h); !ok || err != nil {
		t.Errorf("Verify(t=16) = %v, %v; want true, nil", ok, err)
	}
}

func TestCheckPolicy(t *testing.T) {
	const minLen = 10
	var short password.ErrTooShort
	if err := password.CheckPolicy("short", minLen); !errors.As(err, &short) || short.Min != minLen {
		t.Errorf(`CheckPolicy("short") = %v; want ErrTooShort{Min: %d}`, err, minLen)
	}
	// Nine runes but eighteen bytes: length counts runes.
	if err := password.CheckPolicy("ééééééééé", minLen); !errors.As(err, &short) {
		t.Errorf("CheckPolicy(9 runes) = %v; want ErrTooShort", err)
	}
	for _, p := range []string{"password1234", "PassWord1234"} {
		if err := password.CheckPolicy(p, minLen); !errors.Is(err, password.ErrCommon) {
			t.Errorf("CheckPolicy(%q) = %v; want ErrCommon", p, err)
		}
	}
	for _, p := range []string{pw, "zq8!vR2#mk", "éééééééééé"} {
		if err := password.CheckPolicy(p, minLen); err != nil {
			t.Errorf("CheckPolicy(%q) = %v; want nil", p, err)
		}
	}
}

func TestVerifyUnder100ms(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in -short mode")
	}
	if raceEnabled {
		t.Skip("timing test skipped under the race detector")
	}
	h, err := password.Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	// Best of three, so one scheduling hiccup on a busy host does not fail
	// the run; a consistently slow Verify still does.
	best := time.Duration(1<<63 - 1)
	for range 3 {
		start := time.Now()
		if ok, err := password.Verify(pw, h); !ok || err != nil {
			t.Fatalf("Verify = %v, %v; want true, nil", ok, err)
		}
		best = min(best, time.Since(start))
	}
	t.Logf("native Verify best of 3: %v", best)
	if best >= 100*time.Millisecond {
		t.Errorf("native Verify took %v, want < 100ms", best)
	}
}

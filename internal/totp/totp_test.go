package totp

import (
	"bytes"
	"image/png"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/pquerna/otp"
	pqtotp "github.com/pquerna/otp/totp"
)

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := pqtotp.GenerateCodeCustom(secret, at, pqtotp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestGenerateSecret(t *testing.T) {
	s, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Z2-7]{32}$`).MatchString(s) {
		t.Fatalf("unexpected secret %q", s)
	}
}

// MatchStep accepts a code from the current 30 second step or one either
// side, and returns the step the code belongs to.
func TestMatchStepWithGeneratedCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 12, 0, 10, 0, time.UTC)
	step := now.Unix() / 30
	code := codeAt(t, secret, now)
	cases := []struct {
		name  string
		shift time.Duration
		want  bool
	}{
		{"same step", 0, true},
		{"30s later", 30 * time.Second, true},
		{"30s earlier", -30 * time.Second, true},
		{"90s later", 90 * time.Second, false},
		{"90s earlier", -90 * time.Second, false},
	}
	for _, c := range cases {
		got, ok := MatchStep(secret, code, now.Add(c.shift))
		if ok != c.want {
			t.Errorf("%s: ok %v want %v", c.name, ok, c.want)
		}
		if ok && got != step {
			t.Errorf("%s: step %d want %d (the step the code was made in)", c.name, got, step)
		}
	}
}

func TestMatchStepIgnoresSpaces(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Now()
	code := codeAt(t, secret, now)
	spaced := " " + code[:3] + " " + code[3:] + " "
	if step, ok := MatchStep(secret, spaced, now); !ok || step != now.Unix()/30 {
		t.Fatalf("code with spaces: step %d ok %v", step, ok)
	}
}

func TestMatchStepRejectsGarbage(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Now()
	for _, c := range []struct{ secret, code string }{
		{secret, ""}, {secret, "abcdef"}, {secret, "12345"}, {secret, "1234567"}, {"not base32!", "123456"},
	} {
		if _, ok := MatchStep(c.secret, c.code, now); ok {
			t.Errorf("MatchStep(%q, %q) matched", c.secret, c.code)
		}
	}
}

func TestProvisioningURIFormat(t *testing.T) {
	uri := ProvisioningURI("ABCDEFGH", "Maker Space & Co", "jo@example.org")
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("bad scheme/host: %s", uri)
	}
	if got := u.Path; got != "/Maker Space & Co:jo@example.org" {
		t.Fatalf("bad label %q", got)
	}
	q := u.Query()
	want := map[string]string{
		"secret": "ABCDEFGH", "issuer": "Maker Space & Co",
		"algorithm": "SHA1", "digits": "6", "period": "30",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("param %s = %q want %q", k, q.Get(k), v)
		}
	}
}

func TestQRPNG(t *testing.T) {
	uri := ProvisioningURI("JBSWY3DPEHPK3PXP", "Keywell", "jo@example.org")
	b, err := QRPNG(uri, 200)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != 200 {
		t.Fatalf("width %d", img.Bounds().Dx())
	}
}

func TestRecoveryCodesFormat(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("got %d codes", len(codes))
	}
	re := regexp.MustCompile(`^[a-z2-9]{5}-[a-z2-9]{5}$`)
	seen := map[string]bool{}
	for _, c := range codes {
		if !re.MatchString(c) {
			t.Errorf("bad code %q", c)
		}
		if seen[c] {
			t.Errorf("duplicate %q", c)
		}
		seen[c] = true
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	for in, want := range map[string]string{
		"ABCDE FGHJK":  "abcde-fghjk",
		"abcde-fghjk":  "abcde-fghjk",
		" ABCDEFGHJK ": "abcde-fghjk",
		"abc":          "abc",
	} {
		if got := NormalizeRecoveryCode(in); got != want {
			t.Errorf("Normalize(%q) = %q want %q", in, got, want)
		}
	}
}

func TestSecretFromHex(t *testing.T) {
	got, err := SecretFromHex("3132333435363738393031323334353637383930")
	if err != nil {
		t.Fatal(err)
	}
	if got != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Fatalf("got %q", got)
	}
	if _, err := SecretFromHex("zz"); err == nil {
		t.Fatal("expected error for bad hex")
	}
}

// Package totp provides TOTP secrets, validation, provisioning QR codes and
// one-time recovery codes.
package totp

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"image/png"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	pqtotp "github.com/pquerna/otp/totp"
)

const (
	period           = 30
	recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	recoveryHalfLen  = 5
	secretBytes      = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns 20 random bytes as upper-case base32 without padding.
func GenerateSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("totp: generate secret: %w", err)
	}
	return b32.EncodeToString(b), nil
}

// SecretFromHex converts a hex-encoded raw TOTP key (as Authentik stores it)
// into the base32 form used by Latch.
func SecretFromHex(hexKey string) (string, error) {
	b, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return "", fmt.Errorf("totp: decode hex key: %w", err)
	}
	return b32.EncodeToString(b), nil
}

// ProvisioningURI builds the otpauth:// URI authenticator apps scan.
func ProvisioningURI(secret, issuer, account string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + account,
		RawQuery: q.Encode(),
	}
	return u.String()
}

// QRPNG renders uri as a size x size QR code PNG.
func QRPNG(uri string, size int) ([]byte, error) {
	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		return nil, fmt.Errorf("totp: parse uri: %w", err)
	}
	img, err := key.Image(size, size)
	if err != nil {
		return nil, fmt.Errorf("totp: render qr: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("totp: encode png: %w", err)
	}
	return buf.Bytes(), nil
}

// MatchStep reports whether code is a TOTP code for secret at time at,
// allowing one 30 second step of clock skew either way, and returns the
// time step (Unix time / 30) whose code it is. Spaces in code are ignored.
//
// A code must be accepted only once (RFC 6238 §5.2): callers record the
// step, and refuse a code whose step is not later than the last one used.
func MatchStep(secret, code string, at time.Time) (step int64, ok bool) {
	code = strings.Join(strings.Fields(code), "")
	if len(code) != 6 {
		return 0, false
	}
	now := at.Unix() / period
	for s := now - 1; s <= now+1; s++ {
		want, err := pqtotp.GenerateCodeCustom(secret, time.Unix(s*period, 0), pqtotp.ValidateOpts{
			Period:    period,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(want)) == 1 {
			return s, true
		}
	}
	return 0, false
}

// GenerateRecoveryCodes returns n distinct codes formatted "xxxxx-xxxxx".
func GenerateRecoveryCodes(n int) ([]string, error) {
	seen := make(map[string]bool, n)
	codes := make([]string, 0, n)
	for len(codes) < n {
		raw, err := randomRecoveryChars(2 * recoveryHalfLen)
		if err != nil {
			return nil, err
		}
		c := raw[:recoveryHalfLen] + "-" + raw[recoveryHalfLen:]
		if seen[c] {
			continue
		}
		seen[c] = true
		codes = append(codes, c)
	}
	return codes, nil
}

// randomRecoveryChars draws n characters uniformly from the recovery
// alphabet using rejection sampling to avoid modulo bias.
func randomRecoveryChars(n int) (string, error) {
	const limit = 256 - 256%len(recoveryAlphabet)
	out := make([]byte, 0, n)
	buf := make([]byte, 32)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("totp: generate recovery code: %w", err)
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out = append(out, recoveryAlphabet[int(b)%len(recoveryAlphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

// NormalizeRecoveryCode lower-cases s, strips spaces and dashes and
// re-inserts the dash after the fifth character so user-typed codes compare
// equal to stored ones.
func NormalizeRecoveryCode(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(s)
	if len(s) > recoveryHalfLen {
		return s[:recoveryHalfLen] + "-" + s[recoveryHalfLen:]
	}
	return s
}

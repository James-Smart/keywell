// Package password hashes and verifies member passwords and checks new
// passwords against the policy.
//
// New hashes are argon2id PHC strings. Verify also accepts the Django formats
// carried by users imported from Authentik (legacy.go); callers re-hash those
// after a successful sign-in, using IsLegacy to tell them apart.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// common.txt holds the entries of SecLists'
// Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt that are at
// least 10 runes long (shorter ones already fail the minimum length),
// lower-cased, trimmed and de-duplicated in original order. Regenerate with:
//
//	curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/1a7bb9127eca9e6ff2fc0301c597fe6e16a0cb56/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt | LC_ALL=C.UTF-8 gawk '{ $0 = tolower($0); gsub(/^[[:space:]]+|[[:space:]]+$/, "") } length($0) >= 10 && !seen[$0]++' > common.txt
//
//go:embed common.txt
var commonTxt string

// Cost of new hashes. Verify reads the cost from each stored hash, so these
// can be raised without invalidating existing ones.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	saltLen      = 16
	keyLen       = 32
)

const nativePrefix = "$argon2id$"

var (
	// ErrUnusable means the account has no password set ("" or "!...").
	ErrUnusable = errors.New("password: unusable hash")
	// ErrUnsupported means the stored hash is in a format Verify cannot check.
	ErrUnsupported = errors.New("password: unsupported hash format")
	// ErrCommon means the password is on the common-passwords list.
	ErrCommon = errors.New("password: too common")
)

// ErrTooShort reports a password with fewer than Min characters.
type ErrTooShort struct{ Min int }

func (e ErrTooShort) Error() string {
	return fmt.Sprintf("password: shorter than %d characters", e.Min)
}

var b64 = base64.RawStdEncoding

// Hash returns an argon2id PHC string for password with a fresh random salt.
func Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify reports whether password matches encoded, which may be a native
// hash or any supported Django format. It returns ErrUnusable for an empty
// or "!"-prefixed hash (no password set) and ErrUnsupported for an unknown
// format; other errors mean the stored hash is malformed.
func Verify(password, encoded string) (bool, error) {
	switch {
	case encoded == "" || strings.HasPrefix(encoded, "!"):
		return false, ErrUnusable
	case strings.HasPrefix(encoded, nativePrefix):
		return verifyArgon2(password, strings.Split(encoded[1:], "$"), "argon2id")
	default:
		return verifyLegacy(password, encoded)
	}
}

// IsLegacy reports whether encoded is not a native hash and so should be
// replaced with Hash after the next successful Verify.
func IsLegacy(encoded string) bool {
	return !strings.HasPrefix(encoded, nativePrefix)
}

// CheckPolicy returns ErrTooShort if password has fewer than minLen
// characters (runes) and ErrCommon if it is on the common-passwords list,
// ignoring case.
func CheckPolicy(password string, minLen int) error {
	if utf8.RuneCountInString(password) < minLen {
		return ErrTooShort{Min: minLen}
	}
	if _, ok := commonSet()[strings.ToLower(password)]; ok {
		return ErrCommon
	}
	return nil
}

var commonSet = sync.OnceValue(func() map[string]struct{} {
	set := make(map[string]struct{}, strings.Count(commonTxt, "\n"))
	for line := range strings.Lines(commonTxt) {
		if w := strings.ToLower(strings.TrimSpace(line)); w != "" {
			set[w] = struct{}{}
		}
	}
	return set
})

// verifyArgon2 checks password against the fields of an argon2 PHC string
// after its leading "$" or Django "argon2$" prefix:
// variant, "v=19", "m=M,t=T,p=P", salt, hash (unpadded base64).
func verifyArgon2(password string, f []string, variants ...string) (bool, error) {
	if len(f) != 5 {
		return false, malformed("argon2")
	}
	variant := f[0]
	if !slices.Contains(variants, variant) {
		return false, fmt.Errorf("%w: %s", ErrUnsupported, variant)
	}
	key := argon2.IDKey
	if variant == "argon2i" {
		key = argon2.Key
	}
	if f[1] != fmt.Sprintf("v=%d", argon2.Version) {
		return false, fmt.Errorf("%w: %s version", ErrUnsupported, variant)
	}
	params := strings.Split(f[2], ",")
	if len(params) != 3 {
		return false, malformed(variant)
	}
	m, okM := param(params[0], "m=", 32)
	t, okT := param(params[1], "t=", 32)
	p, okP := param(params[2], "p=", 8)
	salt, errS := b64.DecodeString(f[3])
	want, errH := b64.DecodeString(f[4])
	if !okM || !okT || !okP || t == 0 || p == 0 || errS != nil || errH != nil || len(want) == 0 {
		return false, malformed(variant)
	}
	got := key([]byte(password), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// param parses "<prefix><unsigned int>" that fits in bits.
func param(s, prefix string, bits int) (uint64, bool) {
	v, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 10, bits)
	return n, err == nil
}

// malformed deliberately omits the hash itself so it never reaches logs.
func malformed(scheme string) error {
	return fmt.Errorf("password: malformed %s hash", scheme)
}

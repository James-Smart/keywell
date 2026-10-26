// Package password hashes and verifies member passwords and checks new
// passwords against the policy.
//
// New hashes are argon2id PHC strings. Verify also accepts the Django formats
// carried by users imported from Authentik (legacy.go); callers re-hash those
// after a successful sign-in, using IsLegacy to tell them apart.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
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

// Ceilings on the cost a stored hash may ask for. A hash above them is
// refused as malformed, never checked: one sign-in against it could take
// hundreds of megabytes of memory, or many seconds of CPU. Argon2 and
// scrypt both stop at 256 MiB, so the hashing slots hold at most 1 GiB
// between them. Native hashes cost 64 MiB and 3 passes, Django's argon2
// default 100 MiB, and the other legacy formats' defaults are far below.
// For scrypt, N·r·p bounds the CPU work and 128·r·(N+p+2) the memory
// (scrypt.Key holds v = 128·N·r, B = 128·r·p and xy = 256·r bytes at once).
const (
	maxArgonMemory = 1 << 18 // KiB: 256 MiB
	maxArgonTime   = 16
	maxPBKDF2Iter  = 10_000_000
	maxPBKDF2Len   = 64      // bytes of decoded hash
	maxScryptWork  = 1 << 22 // N·r·p: CPU work
	maxScryptMem   = 1 << 28 // bytes, 128·r·(N+p+2): 256 MiB held at once
	maxBcryptCost  = 14
)

var (
	// ErrUnusable means the account has no password set ("" or "!...").
	ErrUnusable = errors.New("password: unusable hash")
	// ErrUnsupported means the stored hash is in a format Verify cannot check.
	ErrUnsupported = errors.New("password: unsupported hash format")
	// ErrCommon means the password is on the common-passwords list.
	ErrCommon = errors.New("password: too common")
	// ErrBusy means VerifyCtx or HashCtx gave up waiting for a hashing
	// slot because its context ended.
	ErrBusy = errors.New("password: too busy to hash")
)

// slots bounds how many hashes VerifyCtx and HashCtx run at once, and so
// the memory they take (64 MiB each at the native cost): a burst of
// requests waits its turn instead of growing the process by gigabytes.
var slots = make(chan struct{}, max(2, min(4, runtime.NumCPU())))

// testHookInSlot, when set, runs at the start of each hash while its slot
// is held, so tests can watch how many run at once.
var testHookInSlot func()

// withSlot runs fn holding a slot, waiting for one until ctx ends; then
// it returns ErrBusy without running fn.
func withSlot(ctx context.Context, fn func()) error {
	if ctx.Err() != nil {
		return ErrBusy
	}
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return ErrBusy
	}
	defer func() { <-slots }()
	if testHookInSlot != nil {
		testHookInSlot()
	}
	fn()
	return nil
}

// VerifyCtx is Verify for request handlers: the check waits for one of a
// few process-wide hashing slots, and fails with ErrBusy if ctx ends first.
func VerifyCtx(ctx context.Context, password, encoded string) (ok bool, err error) {
	if encoded == "" || strings.HasPrefix(encoded, "!") {
		return false, ErrUnusable // nothing to hash
	}
	if busy := withSlot(ctx, func() { ok, err = Verify(password, encoded) }); busy != nil {
		return false, busy
	}
	return ok, err
}

// HashCtx is Hash for request handlers: hashing waits for one of a few
// process-wide hashing slots, and fails with ErrBusy if ctx ends first.
func HashCtx(ctx context.Context, password string) (hash string, err error) {
	if busy := withSlot(ctx, func() { hash, err = Hash(password) }); busy != nil {
		return "", busy
	}
	return hash, err
}

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
	check, err := prepare(encoded)
	if err != nil {
		return false, err
	}
	return check(password)
}

// CheckStored reports whether Verify could check a password against
// encoded: nil if so, otherwise the error Verify would return for it
// (ErrUnusable, ErrUnsupported, or a malformed-hash error, including a hash
// asking for more cost than the ceilings allow). It computes no hash.
func CheckStored(encoded string) error {
	_, err := prepare(encoded)
	return err
}

// prepare parses encoded and checks it against the ceilings without
// hashing anything.
func prepare(encoded string) (checker, error) {
	switch {
	case encoded == "" || strings.HasPrefix(encoded, "!"):
		return nil, ErrUnusable
	case strings.HasPrefix(encoded, nativePrefix):
		return prepareArgon2(strings.Split(encoded[1:], "$"), "argon2id")
	default:
		return prepareLegacy(encoded)
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

// prepareArgon2 parses the fields of an argon2 PHC string
// after its leading "$" or Django "argon2$" prefix:
// variant, "v=19", "m=M,t=T,p=P", salt, hash (unpadded base64).
func prepareArgon2(f []string, variants ...string) (checker, error) {
	if len(f) != 5 {
		return nil, malformed("argon2")
	}
	variant := f[0]
	if !slices.Contains(variants, variant) {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, variant)
	}
	key := argon2.IDKey
	if variant == "argon2i" {
		key = argon2.Key
	}
	if f[1] != fmt.Sprintf("v=%d", argon2.Version) {
		return nil, fmt.Errorf("%w: %s version", ErrUnsupported, variant)
	}
	params := strings.Split(f[2], ",")
	if len(params) != 3 {
		return nil, malformed(variant)
	}
	m, okM := param(params[0], "m=", 32)
	t, okT := param(params[1], "t=", 32)
	p, okP := param(params[2], "p=", 8)
	salt, errS := b64.DecodeString(f[3])
	want, errH := b64.DecodeString(f[4])
	if !okM || !okT || !okP || t == 0 || p == 0 || errS != nil || errH != nil || len(want) == 0 ||
		m > maxArgonMemory || t > maxArgonTime {
		return nil, malformed(variant)
	}
	return func(password string) (bool, error) {
		got := key([]byte(password), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
		return subtle.ConstantTimeCompare(got, want) == 1, nil
	}, nil
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

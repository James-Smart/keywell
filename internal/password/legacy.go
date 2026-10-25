package password

import (
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// checker computes whether a password matches a stored hash whose format and
// cost have already been checked. Building one hashes nothing.
type checker func(password string) (bool, error)

// prepareLegacy parses a Django "<algorithm>$<fields>" hash, as carried by
// users imported from Authentik, and checks its cost against the ceilings.
// It returns ErrUnsupported for an unknown format and a malformed error for
// a hash it cannot or will not check.
func prepareLegacy(encoded string) (checker, error) {
	algorithm, fields, _ := strings.Cut(encoded, "$")
	switch algorithm {
	case "argon2":
		return prepareArgon2(strings.Split(fields, "$"), "argon2id", "argon2i")
	case "pbkdf2_sha256":
		return preparePBKDF2(fields, sha256.New)
	case "pbkdf2_sha1":
		return preparePBKDF2(fields, sha1.New)
	case "scrypt":
		return prepareScrypt(fields)
	case "bcrypt_sha256":
		return prepareBcryptSHA256(fields)
	}
	return nil, ErrUnsupported
}

// preparePBKDF2 parses "ITER$SALT$HASH". The salt is used as its literal
// bytes; the hash is padded standard base64.
func preparePBKDF2(fields string, h func() hash.Hash) (checker, error) {
	f := strings.Split(fields, "$")
	if len(f) != 3 {
		return nil, malformed("pbkdf2")
	}
	iter, errI := strconv.Atoi(f[0])
	want, errH := base64.StdEncoding.DecodeString(f[2])
	if errI != nil || errH != nil || iter < 1 || iter > maxPBKDF2Iter || len(want) == 0 || len(want) > maxPBKDF2Len {
		return nil, malformed("pbkdf2")
	}
	salt := []byte(f[1])
	return func(password string) (bool, error) {
		got, err := pbkdf2.Key(h, password, salt, iter, len(want))
		if err != nil {
			return false, fmt.Errorf("password: pbkdf2: %w", err)
		}
		return subtle.ConstantTimeCompare(got, want) == 1, nil
	}, nil
}

// prepareScrypt parses "N$SALT$R$P$HASH". The salt is used as its literal
// bytes; the hash is padded standard base64.
func prepareScrypt(fields string) (checker, error) {
	f := strings.Split(fields, "$")
	if len(f) != 5 {
		return nil, malformed("scrypt")
	}
	n, errN := strconv.Atoi(f[0])
	r, errR := strconv.Atoi(f[2])
	p, errP := strconv.Atoi(f[3])
	want, errH := base64.StdEncoding.DecodeString(f[4])
	if errors.Join(errN, errR, errP, errH) != nil || len(want) == 0 {
		return nil, malformed("scrypt")
	}
	// N·r·p against the ceiling, compared by division so it cannot
	// overflow. scrypt.Key itself refuses an N that is not a power of two.
	if n < 1 || r < 1 || p < 1 || n > maxScryptWork/r/p {
		return nil, malformed("scrypt")
	}
	salt := []byte(f[1])
	return func(password string) (bool, error) {
		got, err := scrypt.Key([]byte(password), salt, n, r, p, len(want))
		if err != nil {
			return false, fmt.Errorf("password: scrypt: %w", err)
		}
		return subtle.ConstantTimeCompare(got, want) == 1, nil
	}, nil
}

// prepareBcryptSHA256 parses a complete bcrypt string ("$2b$..."). Django
// feeds bcrypt the lower-case hex SHA-256 of the password, which keeps
// passwords longer than bcrypt's 72-byte limit significant.
func prepareBcryptSHA256(bcryptHash string) (checker, error) {
	cost, err := bcrypt.Cost([]byte(bcryptHash))
	if err != nil || cost > maxBcryptCost {
		return nil, malformed("bcrypt_sha256")
	}
	return func(password string) (bool, error) {
		sum := sha256.Sum256([]byte(password))
		err := bcrypt.CompareHashAndPassword([]byte(bcryptHash), []byte(hex.EncodeToString(sum[:])))
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, malformed("bcrypt_sha256")
		}
	}, nil
}

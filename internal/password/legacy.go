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

// verifyLegacy checks password against a Django "<algorithm>$<fields>" hash,
// as carried by users imported from Authentik.
func verifyLegacy(password, encoded string) (bool, error) {
	algorithm, fields, _ := strings.Cut(encoded, "$")
	switch algorithm {
	case "argon2":
		return verifyArgon2(password, strings.Split(fields, "$"), "argon2id", "argon2i")
	case "pbkdf2_sha256":
		return verifyPBKDF2(password, fields, sha256.New)
	case "pbkdf2_sha1":
		return verifyPBKDF2(password, fields, sha1.New)
	case "scrypt":
		return verifyScrypt(password, fields)
	case "bcrypt_sha256":
		return verifyBcryptSHA256(password, fields)
	}
	return false, ErrUnsupported
}

// verifyPBKDF2 checks "ITER$SALT$HASH". The salt is used as its literal
// bytes; the hash is padded standard base64.
func verifyPBKDF2(password, fields string, h func() hash.Hash) (bool, error) {
	f := strings.Split(fields, "$")
	if len(f) != 3 {
		return false, malformed("pbkdf2")
	}
	iter, errI := strconv.Atoi(f[0])
	want, errH := base64.StdEncoding.DecodeString(f[2])
	if errI != nil || errH != nil || iter < 1 || len(want) == 0 {
		return false, malformed("pbkdf2")
	}
	got, err := pbkdf2.Key(h, password, []byte(f[1]), iter, len(want))
	if err != nil {
		return false, fmt.Errorf("password: pbkdf2: %w", err)
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// verifyScrypt checks "N$SALT$R$P$HASH". The salt is used as its literal
// bytes; the hash is padded standard base64.
func verifyScrypt(password, fields string) (bool, error) {
	f := strings.Split(fields, "$")
	if len(f) != 5 {
		return false, malformed("scrypt")
	}
	n, errN := strconv.Atoi(f[0])
	r, errR := strconv.Atoi(f[2])
	p, errP := strconv.Atoi(f[3])
	want, errH := base64.StdEncoding.DecodeString(f[4])
	if errors.Join(errN, errR, errP, errH) != nil || len(want) == 0 {
		return false, malformed("scrypt")
	}
	got, err := scrypt.Key([]byte(password), []byte(f[1]), n, r, p, len(want))
	if err != nil {
		return false, fmt.Errorf("password: scrypt: %w", err)
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// verifyBcryptSHA256 checks a complete bcrypt string ("$2b$..."). Django
// feeds bcrypt the lower-case hex SHA-256 of the password, which keeps
// passwords longer than bcrypt's 72-byte limit significant.
func verifyBcryptSHA256(password, bcryptHash string) (bool, error) {
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
}

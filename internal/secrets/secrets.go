// Package secrets provides random tokens, token hashing, UUIDs and
// AES-GCM encryption for secrets stored at rest.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("secrets: crypto/rand failed: " + err.Error())
	}
	return b
}

// RandomToken returns nbytes of randomness as unpadded URL-safe base64.
func RandomToken(nbytes int) string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(nbytes))
}

// HashToken returns the hex SHA-256 of token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewID returns a random RFC 4122 version-4 UUID in lower-case form.
func NewID() string {
	b := randomBytes(16)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// GenerateKey returns 32 random bytes as standard base64.
func GenerateKey() string {
	return base64.StdEncoding.EncodeToString(randomBytes(32))
}

// Encryptor seals and opens data with AES-256-GCM.
type Encryptor struct{ aead cipher.AEAD }

// NewEncryptor builds an Encryptor from a standard base64 32-byte key.
func NewEncryptor(base64Key string) (*Encryptor, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Encryptor{aead: aead}, nil
}

// Seal returns nonce || ciphertext+tag.
func (e *Encryptor) Seal(plain []byte) ([]byte, error) {
	nonce := randomBytes(e.aead.NonceSize())
	return e.aead.Seal(nonce, nonce, plain, nil), nil
}

// Open reverses Seal, failing if the data is short or has been altered.
func (e *Encryptor) Open(sealed []byte) ([]byte, error) {
	ns := e.aead.NonceSize()
	if len(sealed) < ns+e.aead.Overhead() {
		return nil, errors.New("sealed data too short")
	}
	return e.aead.Open(nil, sealed[:ns], sealed[ns:], nil)
}

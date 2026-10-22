// Package oidc implements Latch's OpenID Connect endpoints.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"latch/internal/audit"
	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/store"
)

const (
	signingAlg  = "RS256"
	signingBits = 2048
)

// RetiredKeyGrace is how long a retired key still verifies tokens in
// process. Retiring a key is also how an operator revokes a compromised
// one, so after the grace it verifies nothing. The grace exists so that
// tokens signed just before a routine rotation keep working until they
// expire; it is longer than any default token lifetime (access-token
// lifetimes above 24 hours are not supported).
const RetiredKeyGrace = 24 * time.Hour

// KeyManager holds the RSA keys Latch signs tokens with. The newest
// non-retired key is active and signs; every non-retired key is published
// in the JWKS. Private keys are stored as PKCS#8 DER sealed by the
// Encryptor, public keys as PKIX PEM.
type KeyManager struct {
	store *store.Store
	enc   *secrets.Encryptor

	mu        sync.RWMutex
	now       func() time.Time
	audit     *audit.Recorder
	active    *rsa.PrivateKey
	activeKID string
	public    []jose.JSONWebKey    // non-retired keys, newest first
	verify    map[string]verifyKey // every key by kid, retired ones too
}

// verifyKey is a public key and when it was retired (nil if it is not).
type verifyKey struct {
	pub       *rsa.PublicKey
	retiredAt *time.Time
}

// NewKeyManager loads the stored keys and, if none can sign, generates one.
// It fails if the active key cannot be unsealed with enc.
func NewKeyManager(ctx context.Context, s *store.Store, enc *secrets.Encryptor) (*KeyManager, error) {
	k := &KeyManager{store: s, enc: enc, now: time.Now}
	if err := k.load(ctx); err != nil {
		return nil, err
	}
	if err := k.EnsureKey(ctx); err != nil {
		return nil, err
	}
	return k, nil
}

// WithAudit makes Rotate record its rotations with a. It returns k.
func (k *KeyManager) WithAudit(a *audit.Recorder) *KeyManager {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.audit = a
	return k
}

// SetClock replaces the time source. It exists for tests only.
func (k *KeyManager) SetClock(now func() time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.now = now
}

// load replaces the cache with the stored keys.
func (k *KeyManager) load(ctx context.Context) error {
	rows, err := k.store.ListSigningKeys(ctx)
	if err != nil {
		return fmt.Errorf("oidc: load signing keys: %w", err)
	}
	var (
		active    *rsa.PrivateKey
		activeKID string
		public    []jose.JSONWebKey
		verify    = make(map[string]verifyKey, len(rows))
	)
	for _, row := range rows { // newest first
		pub, err := parsePublicKey(row.PublicKeyPEM)
		if err != nil {
			return fmt.Errorf("oidc: signing key %s: %w", row.KID, err)
		}
		verify[row.KID] = verifyKey{pub: pub, retiredAt: row.RetiredAt}
		if row.RetiredAt != nil {
			continue
		}
		public = append(public, publicJWK(row.KID, pub))
		if active == nil {
			if active, err = k.unseal(row.PrivateKeyEnc); err != nil {
				return fmt.Errorf("oidc: signing key %s: %w", row.KID, err)
			}
			activeKID = row.KID
		}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.active, k.activeKID, k.public, k.verify = active, activeKID, public, verify
	return nil
}

// EnsureKey generates and stores a key if there is no active one.
func (k *KeyManager) EnsureKey(ctx context.Context) error {
	if k.ActiveKID() != "" {
		return nil
	}
	nk, err := k.generate()
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.active != nil {
		return nil
	}
	return k.add(ctx, nk)
}

// Rotate generates a new key and makes it active. Earlier keys stay
// published until RetireOlderThan retires them.
func (k *KeyManager) Rotate(ctx context.Context) (newKID string, err error) {
	nk, err := k.generate()
	if err != nil {
		return "", err
	}
	k.mu.Lock()
	err = k.add(ctx, nk)
	rec := k.audit
	k.mu.Unlock()
	if err != nil {
		return "", err
	}
	if rec != nil {
		rec.Record(ctx, model.AuditEvent{ActorType: audit.ActorSystem, Action: audit.KeyRotated,
			TargetType: "signing_key", TargetID: nk.kid, Summary: "Signing key rotated"})
	}
	return nk.kid, nil
}

// RetireOlderThan retires every key other than the active one created more
// than d ago, removing it from the JWKS, and returns how many it retired.
// A retired key still verifies tokens for RetiredKeyGrace.
func (k *KeyManager) RetireOlderThan(ctx context.Context, d time.Duration) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now().UTC()
	cutoff := now.Add(-d)
	rows, err := k.store.ListSigningKeys(ctx)
	if err != nil {
		return 0, fmt.Errorf("oidc: retire signing keys: %w", err)
	}
	retired := map[string]bool{}
	for _, row := range rows {
		if row.KID == k.activeKID || row.RetiredAt != nil || !row.CreatedAt.Before(cutoff) {
			continue
		}
		if err = k.store.RetireSigningKey(ctx, row.KID, now); err != nil {
			err = fmt.Errorf("oidc: retire signing key %s: %w", row.KID, err)
			break
		}
		retired[row.KID] = true
		if v, ok := k.verify[row.KID]; ok {
			v.retiredAt = &now
			k.verify[row.KID] = v
		}
	}
	k.public = slices.DeleteFunc(k.public, func(j jose.JSONWebKey) bool { return retired[j.KeyID] })
	return len(retired), err
}

// JWKS returns the public keys of every non-retired key.
func (k *KeyManager) JWKS() jose.JSONWebKeySet {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return jose.JSONWebKeySet{Keys: slices.Clone(k.public)}
}

// PublicKey returns the public key with kid for verifying a token. A
// retired key is returned only within RetiredKeyGrace of its retirement.
func (k *KeyManager) PublicKey(kid string) (*rsa.PublicKey, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	v, ok := k.verify[kid]
	if !ok || v.retiredAt != nil && !k.now().Before(v.retiredAt.Add(RetiredKeyGrace)) {
		return nil, false
	}
	return v.pub, true
}

// ActiveKID returns the kid of the key that signs new tokens.
func (k *KeyManager) ActiveKID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.activeKID
}

// Sign returns claims as an RS256 compact JWS with typ "JWT".
func (k *KeyManager) Sign(claims map[string]any) (string, error) {
	return k.SignTyped(claims, "JWT")
}

// SignTyped returns claims as an RS256 compact JWS signed by the active key,
// with its kid and the given typ in the header.
func (k *KeyManager) SignTyped(claims map[string]any, typ string) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("oidc: encode claims: %w", err)
	}
	k.mu.RLock()
	priv, kid := k.active, k.activeKID
	k.mu.RUnlock()
	if priv == nil {
		return "", errors.New("oidc: no active signing key")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", kid))
	if err != nil {
		return "", fmt.Errorf("oidc: signer: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("oidc: sign: %w", err)
	}
	return jws.CompactSerialize()
}

// newKey is a generated key and its storage form.
type newKey struct {
	kid  string
	priv *rsa.PrivateKey
	row  model.SigningKey
}

func (k *KeyManager) generate() (*newKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, signingBits)
	if err != nil {
		return nil, fmt.Errorf("oidc: generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("oidc: encode private key: %w", err)
	}
	sealed, err := k.enc.Seal(der)
	if err != nil {
		return nil, fmt.Errorf("oidc: seal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("oidc: encode public key: %w", err)
	}
	sum := sha256.Sum256(pubDER)
	kid := hex.EncodeToString(sum[:])[:16]
	return &newKey{kid: kid, priv: priv, row: model.SigningKey{
		KID:           kid,
		Alg:           signingAlg,
		PrivateKeyEnc: sealed,
		PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
	}}, nil
}

// add stores nk and makes it the active key. The caller holds mu.
func (k *KeyManager) add(ctx context.Context, nk *newKey) error {
	nk.row.CreatedAt = k.now().UTC()
	if err := k.store.InsertSigningKey(ctx, &nk.row); err != nil {
		return fmt.Errorf("oidc: store signing key: %w", err)
	}
	pub := &nk.priv.PublicKey
	k.active, k.activeKID = nk.priv, nk.kid
	k.public = append([]jose.JSONWebKey{publicJWK(nk.kid, pub)}, k.public...)
	k.verify[nk.kid] = verifyKey{pub: pub}
	return nil
}

func (k *KeyManager) unseal(sealed []byte) (*rsa.PrivateKey, error) {
	der, err := k.enc.Open(sealed)
	if err != nil {
		return nil, fmt.Errorf("open private key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, want RSA", key)
	}
	return priv, nil
}

func parsePublicKey(s string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("public key is not a PUBLIC KEY PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want RSA", key)
	}
	return pub, nil
}

func publicJWK(kid string, pub *rsa.PublicKey) jose.JSONWebKey {
	return jose.JSONWebKey{Key: pub, KeyID: kid, Algorithm: signingAlg, Use: "sig"}
}

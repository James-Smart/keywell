package oidc_test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"latch/internal/audit"
	"latch/internal/oidc"
	"latch/internal/secrets"
	"latch/internal/store"
)

func newEncryptor(t *testing.T) *secrets.Encryptor {
	t.Helper()
	enc, err := secrets.NewEncryptor(secrets.GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func newKeyManager(t *testing.T, s *store.Store, enc *secrets.Encryptor) *oidc.KeyManager {
	t.Helper()
	k, err := oidc.NewKeyManager(context.Background(), s, enc)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	return k
}

// verifyJWT parses token as RS256, checks its kid and typ headers, verifies
// it with key and returns its claims.
func verifyJWT(t *testing.T, token, wantKID, wantTyp string, key any) map[string]any {
	t.Helper()
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	h := jws.Signatures[0].Header
	if h.KeyID != wantKID {
		t.Fatalf("kid header %q, want %q", h.KeyID, wantKID)
	}
	if typ := h.ExtraHeaders[jose.HeaderType]; typ != wantTyp {
		t.Fatalf("typ header %v, want %q", typ, wantTyp)
	}
	payload, err := jws.Verify(key)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("token payload: %v", err)
	}
	return claims
}

// published reports whether k's JWKS lists kid.
func published(k *oidc.KeyManager, kid string) bool {
	set := k.JWKS()
	return len(set.Key(kid)) != 0
}

// jwksKey returns the one key with kid in the published set.
func jwksKey(t *testing.T, k *oidc.KeyManager, kid string) jose.JSONWebKey {
	t.Helper()
	set := k.JWKS()
	keys := set.Key(kid)
	if len(keys) != 1 {
		t.Fatalf("JWKS has %d keys with kid %q, want 1", len(keys), kid)
	}
	return keys[0]
}

func TestEnsureKeyCreatesOnce(t *testing.T) {
	ctx := context.Background()
	s := store.OpenTest(t)
	enc := newEncryptor(t)

	k1 := newKeyManager(t, s, enc)
	k2 := newKeyManager(t, s, enc)
	if err := k2.EnsureKey(ctx); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ListSigningKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d signing keys, want 1", len(rows))
	}
	row := rows[0]
	if k1.ActiveKID() != row.KID || k2.ActiveKID() != row.KID {
		t.Fatalf("active kids %q, %q; stored %q", k1.ActiveKID(), k2.ActiveKID(), row.KID)
	}
	if row.Alg != "RS256" || row.RetiredAt != nil {
		t.Fatalf("stored key alg %q retired %v", row.Alg, row.RetiredAt)
	}

	// The public key is a PKIX PEM block, an RSA 2048 key, and the kid is
	// the first 16 hex characters of the SHA-256 of its DER.
	block, rest := pem.Decode([]byte(row.PublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("public key PEM: %q", row.PublicKeyPEM)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok || rsaPub.N.BitLen() != 2048 {
		t.Fatalf("public key %T, want RSA 2048", pub)
	}
	sum := sha256.Sum256(block.Bytes)
	if want := hex.EncodeToString(sum[:])[:16]; row.KID != want {
		t.Fatalf("kid %q, want %q", row.KID, want)
	}

	// With every key retired there is no key to sign with, so a new one is made.
	if err := s.RetireSigningKey(ctx, row.KID, time.Now()); err != nil {
		t.Fatal(err)
	}
	k3 := newKeyManager(t, s, enc)
	if k3.ActiveKID() == row.KID {
		t.Fatal("manager kept the retired key active")
	}
	if rows, _ = s.ListSigningKeys(ctx); len(rows) != 2 {
		t.Fatalf("%d signing keys after all were retired, want 2", len(rows))
	}
}

func TestSignVerifiesAgainstJWKS(t *testing.T) {
	k := newKeyManager(t, store.OpenTest(t), newEncryptor(t))
	kid := k.ActiveKID()

	claims := map[string]any{"sub": "u1", "aud": "app", "n": float64(3), "groups": []any{"a", "b"}}
	token, err := k.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	jwk := jwksKey(t, k, kid)
	if jwk.Use != "sig" || jwk.Algorithm != "RS256" || !jwk.IsPublic() {
		t.Fatalf("JWKS key use %q alg %q public %v", jwk.Use, jwk.Algorithm, jwk.IsPublic())
	}
	if got := verifyJWT(t, token, kid, "JWT", jwk.Key); !reflect.DeepEqual(got, claims) {
		t.Fatalf("claims %v, want %v", got, claims)
	}

	// The published set holds no private key material.
	raw, err := json.Marshal(k.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	var set struct{ Keys []map[string]any }
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, ok := set.Keys[0][private]; ok {
			t.Fatalf("JWKS publishes private parameter %q", private)
		}
	}

	// SignTyped sets the typ header; PublicKey verifies in process.
	at, err := k.SignTyped(map[string]any{"sub": "u1"}, "at+jwt")
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := k.PublicKey(kid)
	if !ok {
		t.Fatalf("PublicKey(%q) not found", kid)
	}
	if got := verifyJWT(t, at, kid, "at+jwt", pub); got["sub"] != "u1" {
		t.Fatalf("access token claims %v", got)
	}
	if _, ok := k.PublicKey("unknown"); ok {
		t.Fatal("PublicKey found an unknown kid")
	}
}

func TestRotateKeepsOldPublished(t *testing.T) {
	ctx := context.Background()
	s, db := store.OpenTestDB(t)
	enc := newEncryptor(t)
	k := newKeyManager(t, s, enc).WithAudit(audit.New(s, slog.New(slog.NewTextHandler(io.Discard, nil))))
	oldKID := k.ActiveKID()
	oldToken, err := k.Sign(map[string]any{"sub": "before"})
	if err != nil {
		t.Fatal(err)
	}

	newKID, err := k.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if newKID == oldKID || k.ActiveKID() != newKID {
		t.Fatalf("rotate: new %q old %q active %q", newKID, oldKID, k.ActiveKID())
	}
	if n := len(k.JWKS().Keys); n != 2 {
		t.Fatalf("JWKS has %d keys after rotate, want 2", n)
	}
	if got := verifyJWT(t, oldToken, oldKID, "JWT", jwksKey(t, k, oldKID).Key); got["sub"] != "before" {
		t.Fatalf("old token claims %v", got)
	}
	newToken, err := k.Sign(map[string]any{"sub": "after"})
	if err != nil {
		t.Fatal(err)
	}
	if got := verifyJWT(t, newToken, newKID, "JWT", jwksKey(t, k, newKID).Key); got["sub"] != "after" {
		t.Fatalf("new token claims %v", got)
	}

	// The rotation is stored: a fresh manager signs with the new key.
	if fresh := newKeyManager(t, s, enc); fresh.ActiveKID() != newKID || len(fresh.JWKS().Keys) != 2 {
		t.Fatalf("fresh manager active %q with %d keys", fresh.ActiveKID(), len(fresh.JWKS().Keys))
	}

	var actorType, targetType, targetID string
	err = db.QueryRowContext(ctx, `SELECT actor_type, target_type, target_id FROM audit_events WHERE action=?`,
		audit.KeyRotated).Scan(&actorType, &targetType, &targetID)
	if err != nil {
		t.Fatalf("rotation audit event: %v", err)
	}
	if actorType != "system" || targetType != "signing_key" || targetID != newKID {
		t.Fatalf("audit event %q %q %q", actorType, targetType, targetID)
	}
}

func TestRetireOlderThan(t *testing.T) {
	ctx := context.Background()
	s := store.OpenTest(t)
	enc := newEncryptor(t)
	k := newKeyManager(t, s, enc)
	oldKID := k.ActiveKID()
	oldToken, err := k.Sign(map[string]any{"sub": "before"})
	if err != nil {
		t.Fatal(err)
	}
	newKID, err := k.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Both keys are younger than an hour.
	if n, err := k.RetireOlderThan(ctx, time.Hour); err != nil || n != 0 {
		t.Fatalf("RetireOlderThan(1h) = %d, %v; want 0", n, err)
	}
	if n := len(k.JWKS().Keys); n != 2 {
		t.Fatalf("JWKS has %d keys, want 2", n)
	}

	// Every key is older than zero, but the active key is never retired.
	if n, err := k.RetireOlderThan(ctx, 0); err != nil || n != 1 {
		t.Fatalf("RetireOlderThan(0) = %d, %v; want 1", n, err)
	}
	set := k.JWKS()
	if len(set.Keys) != 1 || set.Keys[0].KeyID != newKID || k.ActiveKID() != newKID {
		t.Fatalf("after retiring: JWKS has %d keys, active %q; want only %q", len(set.Keys), k.ActiveKID(), newKID)
	}
	if n, err := k.RetireOlderThan(ctx, 0); err != nil || n != 0 {
		t.Fatalf("second RetireOlderThan(0) = %d, %v; want 0", n, err)
	}

	rows, err := s.ListSigningKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if retired := row.RetiredAt != nil; retired != (row.KID == oldKID) {
			t.Fatalf("key %q retired=%v", row.KID, retired)
		}
	}
	if fresh := newKeyManager(t, s, enc); len(fresh.JWKS().Keys) != 1 || fresh.ActiveKID() != newKID {
		t.Fatalf("fresh manager: %d keys, active %q", len(fresh.JWKS().Keys), fresh.ActiveKID())
	}

	// A retired key still verifies in process, so its tokens last until they expire.
	pub, ok := k.PublicKey(oldKID)
	if !ok {
		t.Fatal("PublicKey lost the retired key")
	}
	verifyJWT(t, oldToken, oldKID, "JWT", pub)
}

func TestPrivateKeyEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	s, db := store.OpenTestDB(t)
	enc := newEncryptor(t)
	k := newKeyManager(t, s, enc)
	kid := k.ActiveKID()

	var stored []byte
	if err := db.QueryRowContext(ctx, `SELECT private_key_enc FROM signing_keys WHERE kid=?`, kid).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(stored); err == nil {
		t.Fatal("stored private key parses as plain PKCS#8")
	}
	der, err := enc.Open(stored)
	if err != nil {
		t.Fatalf("open stored private key: %v", err)
	}
	if bytes.Contains(stored, der) || bytes.Contains(stored, der[:26]) {
		t.Fatal("stored column contains the PKCS#8 DER")
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("unsealed private key is not PKCS#8: %v", err)
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("private key %T, want RSA", key)
	}
	if pub, _ := k.PublicKey(kid); !priv.PublicKey.Equal(pub) {
		t.Fatal("stored private key does not match the published public key")
	}

	// Without the right encryption key the manager refuses to start rather
	// than replacing the stored key.
	if _, err := oidc.NewKeyManager(ctx, s, newEncryptor(t)); err == nil {
		t.Fatal("NewKeyManager succeeded with the wrong encryption key")
	}
	if rows, _ := s.ListSigningKeys(ctx); len(rows) != 1 {
		t.Fatalf("%d signing keys after a failed start, want 1", len(rows))
	}
}

func TestRetiredKeyStopsVerifyingAfterGrace(t *testing.T) {
	ctx := context.Background()
	s := store.OpenTest(t)
	enc := newEncryptor(t)
	var offset time.Duration
	clock := func() time.Time { return time.Now().Add(offset) }

	k := newKeyManager(t, s, enc)
	k.SetClock(clock)
	kidA := k.ActiveKID()
	tokenA, err := k.Sign(map[string]any{"sub": "a"})
	if err != nil {
		t.Fatal(err)
	}
	kidB, err := k.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := k.RetireOlderThan(ctx, 0); err != nil || n != 1 {
		t.Fatalf("RetireOlderThan(0) = %d, %v; want 1", n, err)
	}
	// A fresh manager reads the retirement time from the store.
	fresh := newKeyManager(t, s, enc)
	fresh.SetClock(clock)
	managers := map[string]*oidc.KeyManager{"rotating": k, "fresh": fresh}

	check := func(when string, wantA bool) {
		t.Helper()
		for name, m := range managers {
			set := m.JWKS()
			if len(set.Key(kidA)) != 0 {
				t.Fatalf("%s, %s manager: JWKS lists the retired key", when, name)
			}
			if _, ok := m.PublicKey(kidB); !ok {
				t.Fatalf("%s, %s manager: active key does not verify", when, name)
			}
			pub, ok := m.PublicKey(kidA)
			if ok != wantA {
				t.Fatalf("%s, %s manager: retired key found=%v, want %v", when, name, ok, wantA)
			}
			if ok {
				verifyJWT(t, tokenA, kidA, "JWT", pub)
			} else if pub != nil {
				t.Fatalf("%s, %s manager: PublicKey returned a key with ok=false", when, name)
			}
		}
	}
	check("just retired", true)
	offset = 23 * time.Hour
	check("23h after retiring", true)
	offset = 25 * time.Hour
	check("25h after retiring", false)
}

func TestRetireOlderThanMeasuresFromSupersession(t *testing.T) {
	ctx := context.Background()
	const day = 24 * time.Hour
	k := newKeyManager(t, store.OpenTest(t), newEncryptor(t))
	var offset time.Duration
	k.SetClock(func() time.Time { return time.Now().Add(offset) })
	kidA := k.ActiveKID()

	// A is 100 days old but was superseded just now, so it stays published
	// for the tokens it signed.
	offset = 100 * day
	kidB, err := k.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := k.RetireOlderThan(ctx, 90*day); err != nil || n != 0 {
		t.Fatalf("RetireOlderThan(90d) just after rotating = %d, %v; want 0", n, err)
	}
	if !published(k, kidA) {
		t.Fatal("superseded key left the JWKS as soon as it was superseded")
	}

	// B is superseded by C at day 150, so at day 191 A has been superseded
	// for 91 days and B for only 41.
	offset = 150 * day
	kidC, err := k.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	offset = 191 * day
	if n, err := k.RetireOlderThan(ctx, 90*day); err != nil || n != 1 {
		t.Fatalf("RetireOlderThan(90d) 91 days after A was superseded = %d, %v; want 1", n, err)
	}
	if published(k, kidA) || !published(k, kidB) || !published(k, kidC) || len(k.JWKS().Keys) != 2 {
		t.Fatalf("JWKS after retiring: A %v, B %v, C %v, %d keys; want only B and C",
			published(k, kidA), published(k, kidB), published(k, kidC), len(k.JWKS().Keys))
	}
}

func TestReloadPicksUpAnotherManagersChanges(t *testing.T) {
	ctx := context.Background()
	s := store.OpenTest(t)
	enc := newEncryptor(t)
	a := newKeyManager(t, s, enc) // e.g. latch rotate-keys
	b := newKeyManager(t, s, enc) // e.g. the running server
	oldKID := a.ActiveKID()

	newKID, err := a.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b.ActiveKID() != oldKID || published(b, newKID) {
		t.Fatal("b saw the rotation before reloading")
	}
	if err := b.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if b.ActiveKID() != newKID || !published(b, oldKID) || !published(b, newKID) {
		t.Fatalf("after reload: active %q, old published %v, new published %v",
			b.ActiveKID(), published(b, oldKID), published(b, newKID))
	}
	token, err := b.Sign(map[string]any{"sub": "u1"})
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := a.PublicKey(newKID)
	verifyJWT(t, token, newKID, "JWT", pub)

	// A retirement elsewhere reaches b too; the second reload changes nothing.
	if n, err := a.RetireOlderThan(ctx, 0); err != nil || n != 1 {
		t.Fatalf("RetireOlderThan(0) = %d, %v; want 1", n, err)
	}
	for i := range 2 {
		if err := b.Reload(ctx); err != nil {
			t.Fatalf("reload %d: %v", i, err)
		}
		if b.ActiveKID() != newKID || published(b, oldKID) || len(b.JWKS().Keys) != 1 {
			t.Fatalf("reload %d after retiring: active %q, old published %v, %d keys",
				i, b.ActiveKID(), published(b, oldKID), len(b.JWKS().Keys))
		}
		if _, ok := b.PublicKey(oldKID); !ok {
			t.Fatalf("reload %d: key retired just now no longer verifies", i)
		}
	}
	if rows, _ := s.ListSigningKeys(ctx); len(rows) != 2 {
		t.Fatalf("%d signing keys after reloads, want 2", len(rows))
	}
}

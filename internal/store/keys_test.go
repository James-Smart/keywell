package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/James-Smart/keywell/internal/model"
)

func TestSigningKeysOrderAndRetire(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	older := &model.SigningKey{KID: "old", Alg: "RS256", PrivateKeyEnc: []byte{1, 2}, PublicKeyPEM: "pem1", CreatedAt: base}
	newer := &model.SigningKey{KID: "new", Alg: "RS256", PrivateKeyEnc: []byte{3}, PublicKeyPEM: "pem2", CreatedAt: base.Add(time.Hour)}
	for _, k := range []*model.SigningKey{older, newer} {
		if err := s.InsertSigningKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.InsertSigningKey(ctx, &model.SigningKey{KID: "old", Alg: "RS256", PrivateKeyEnc: []byte{1}, PublicKeyPEM: "x", CreatedAt: base}); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	keys, err := s.ListSigningKeys(ctx)
	if err != nil || len(keys) != 2 || keys[0].KID != "new" || keys[1].KID != "old" {
		t.Fatalf("order: %+v %v", keys, err)
	}
	if keys[1].PublicKeyPEM != "pem1" || len(keys[1].PrivateKeyEnc) != 2 || keys[0].RetiredAt != nil {
		t.Fatalf("fields: %+v", keys)
	}
	at := base.Add(2 * time.Hour)
	if err := s.RetireSigningKey(ctx, "old", at); err != nil {
		t.Fatal(err)
	}
	keys, _ = s.ListSigningKeys(ctx)
	if keys[1].RetiredAt == nil || !keys[1].RetiredAt.Equal(at) || keys[0].RetiredAt != nil {
		t.Fatalf("retire: %+v", keys)
	}
	if err := s.RetireSigningKey(ctx, "nope", at); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

package importer_test

import (
	"context"
	"testing"

	"github.com/James-Smart/keywell/internal/importer"
	"github.com/James-Smart/keywell/internal/testenv"
)

// An imported member signs in with their Authentik password, and the
// first sign in swaps the legacy hash for a native one.
func TestImportedMemberSignsIn(t *testing.T) {
	env := testenv.New(t)
	s := importer.NewSnap()
	s.User("alex", "alex@example.org", importer.WithName("Alex Smith")) // UsableHash: the Django vector

	_, err := importer.Run(context.Background(),
		importer.Deps{Store: env.Store, Enc: env.Enc, Cfg: env.Cfg}, s.Snapshot,
		importer.Options{Source: "db.internal:5432/authentik"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := env.Store.GetUserByEmail(context.Background(), "alex@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash != "" || u.LegacyPasswordHash != importer.UsableHash {
		t.Fatalf("before sign in: native %q, legacy %q", u.PasswordHash, u.LegacyPasswordHash)
	}

	env.Login(t, env.Client(t), "alex@example.org", "correct horse battery staple")

	u, err = env.Store.GetUserByEmail(context.Background(), "alex@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash == "" || u.LegacyPasswordHash != "" {
		t.Errorf("after sign in: native %q, legacy %q; want native and no legacy", u.PasswordHash, u.LegacyPasswordHash)
	}
}

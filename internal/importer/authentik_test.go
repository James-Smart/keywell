package importer_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"

	pqtotp "github.com/pquerna/otp/totp"

	"latch/internal/audit"
	"latch/internal/authentik"
	"latch/internal/importer"
	"latch/internal/store"
	"latch/internal/testenv"
)

// TestImportAuthentikEndToEnd imports the dev stack (make authentik-up) into
// a real installation. Members then sign in with what they used in
// Authentik, and an app gets the same sub it got there.
func TestImportAuthentikEndToEnd(t *testing.T) {
	dsn := os.Getenv("LATCH_TEST_AUTHENTIK_DSN")
	if dsn == "" {
		t.Skip("set LATCH_TEST_AUTHENTIK_DSN (make authentik-up) to run")
	}
	ctx := context.Background()
	snap, err := authentik.Read(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	env := testenv.New(t)
	deps := importer.Deps{Store: env.Store, Enc: env.Enc, Cfg: env.Cfg, Audit: audit.New(env.Store, nil), Now: env.Clock.Now}
	opts := importer.Options{Source: authentik.Source(dsn)}

	rep, err := importer.Run(ctx, deps, snap, opts)
	if err != nil {
		t.Fatalf("Run: %v (blocking: %q)", err, rep.Blocking)
	}
	if rep.Members != (importer.Counts{Added: 6, Skipped: 1}) || rep.LeftOut != 3 ||
		rep.Groups != (importer.Counts{Added: 4, Skipped: 2}) || rep.Apps != (importer.Counts{Added: 3, Skipped: 3}) {
		t.Errorf("members %+v, left out %d, groups %+v, apps %+v", rep.Members, rep.LeftOut, rep.Groups, rep.Apps)
	}
	if rep.NoPassword != 1 || rep.TOTP != 1 || rep.RecoveryCodes != 3 {
		t.Errorf("no password %d, TOTP %d, recovery codes %d; want 1, 1 and 3", rep.NoPassword, rep.TOTP, rep.RecoveryCodes)
	}
	if strings.Contains(strings.Join(rep.CountLines(), "\n")+rep.Summary(), dsn) {
		t.Error("the report has the connection string")
	}
	events, err := env.Store.ListAuditEvents(ctx, store.AuditFilter{Actions: []string{audit.ImportRun}})
	if err != nil || len(events.Rows) != 1 {
		t.Fatalf("import.run events: %d, %v", len(events.Rows), err)
	}

	var alexPK int64
	for _, u := range snap.Users {
		if u.Username == "alex" {
			alexPK = u.PK
		}
	}

	// alex signs in with his Authentik password and authenticator app, then
	// signs in to Wiki and gets the sub Authentik gave it.
	const alexEmail = "Alex.Smith@Example.org"
	alexSecret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := pqtotp.GenerateCode(alexSecret, env.Clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := env.Client(t)
	env.Login(t, c, alexEmail, "alex correct horse 1")
	resp, body := env.Submit(t, c, "/login/totp", url.Values{"code": {code}})
	if resp.StatusCode != 303 {
		t.Fatalf("TOTP step: status %d: %s", resp.StatusCode, body)
	}
	wiki, err := env.Store.GetApplicationByClientID(ctx, "wiki-client-id")
	if err != nil {
		t.Fatal(err)
	}
	authCode, verifier, _ := env.Authorize(t, c, wiki, false)
	tok, tokResp := env.Exchange(t, wiki, "wiki-client-secret-0123456789", authCode, verifier, wiki.RedirectURIs[0])
	if tokResp.StatusCode != 200 {
		t.Fatalf("token exchange: status %d: %v", tokResp.StatusCode, tok)
	}
	idToken, _ := tok["id_token"].(string)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token %q", idToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct{ Sub string }
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if want := authentik.HashedUserID(alexPK, snap.InstallID); claims.Sub != want {
		t.Errorf("sub = %q, want %q", claims.Sub, want)
	}
	alex, err := env.Store.GetUserByEmail(ctx, alexEmail)
	if err != nil {
		t.Fatal(err)
	}
	if alex.PasswordHash == "" || alex.LegacyPasswordHash != "" {
		t.Errorf("after sign in: native %q, legacy %q; want a native hash and no legacy one", alex.PasswordHash, alex.LegacyPasswordHash)
	}

	// Other members' hashers, and a recovery code at the same TOTP step.
	env.Login(t, env.Client(t), "sam@example.org", "sam correct horse 2")
	env.Login(t, env.Client(t), "kim@example.org", "kim correct horse 4")
	c = env.Client(t)
	env.Login(t, c, alexEmail, "alex correct horse 1")
	resp, body = env.Submit(t, c, "/login/totp", url.Values{"code": {"RecoveryBBB2"}})
	if resp.StatusCode != 303 {
		t.Errorf("recovery code: status %d: %s", resp.StatusCode, body)
	}

	// A second run adds nothing.
	again, err := importer.Run(ctx, deps, snap, opts)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if again.Members.Added+again.Groups.Added+again.Apps.Added != 0 {
		t.Errorf("second run added members %+v, groups %+v, apps %+v", again.Members, again.Groups, again.Apps)
	}
}

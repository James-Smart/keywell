package importer_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	pqtotp "github.com/pquerna/otp/totp"

	"latch/internal/audit"
	"latch/internal/authentik"
	"latch/internal/importer"
	"latch/internal/store"
	"latch/internal/testenv"
)

// importEventCount is how many import.run audit events there are.
func importEventCount(t *testing.T, st *store.Store) int {
	t.Helper()
	page, err := st.ListAuditEvents(context.Background(), store.AuditFilter{Actions: []string{audit.ImportRun}})
	if err != nil {
		t.Fatal(err)
	}
	return len(page.Rows)
}

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
	if n := importEventCount(t, env.Store); n != 1 {
		t.Fatalf("%d import.run events, want 1", n)
	}

	// The report text and the stored report hold no secrets and none of the
	// words the admin pages avoid.
	var text bytes.Buffer
	if err := rep.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	run, err := env.Store.LastImportRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	banned := regexp.MustCompile(`(?i)\b(provider|flow|stage|binding)s?\b`)
	var dsnPassword string
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		dsnPassword, _ = u.User.Password()
	}
	for name, s := range map[string]string{"report text": text.String(), "stored report": run.Report} {
		if m := banned.FindString(s); m != "" {
			t.Errorf("%s has the word %q", name, m)
		}
		if dsnPassword != "" && strings.Contains(s, dsnPassword) {
			t.Errorf("%s has the database password", name)
		}
		if strings.Contains(s, dsn) {
			t.Errorf("%s has the connection string", name)
		}
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
	const alexSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	totpCode := func() string {
		code, err := pqtotp.GenerateCode(alexSecret, env.Clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	// loginStep reports where GET / sends c: "" when it is signed in.
	signedInRedirect := func(c *http.Client) string {
		resp, _ := env.Page(t, c, "/")
		return resp.Header.Get("Location")
	}
	// passwordSignIn signs alex in with his password only.
	passwordSignIn := func() *http.Client {
		c := env.Client(t)
		env.Login(t, c, alexEmail, "alex correct horse 1")
		return c
	}

	before, err := env.Store.GetUserByEmail(ctx, alexEmail)
	if err != nil {
		t.Fatal(err)
	}
	if before.LegacyPasswordHash == "" || before.PasswordHash != "" {
		t.Fatalf("before sign in: native %q, legacy %q; want a legacy hash only", before.PasswordHash, before.LegacyPasswordHash)
	}

	c := passwordSignIn()
	if loc := signedInRedirect(c); !strings.HasPrefix(loc, "/login/totp") {
		t.Fatalf("after the password alone, / redirects to %q, want the TOTP step", loc)
	}
	wrong := "000000"
	if wrong == totpCode() {
		wrong = "111111"
	}
	if resp, _ := env.Submit(t, c, "/login/totp", url.Values{"code": {wrong}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("wrong code: status %d, want the form again", resp.StatusCode)
	}
	if loc := signedInRedirect(c); !strings.HasPrefix(loc, "/login/totp") {
		t.Fatalf("after a wrong code, / redirects to %q, want the TOTP step", loc)
	}
	resp, body := env.Submit(t, c, "/login/totp", url.Values{"code": {totpCode()}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("right code: status %d, Location %q: %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	if loc := signedInRedirect(c); loc != "" {
		t.Fatalf("after the right code, / redirects to %q, want the home page", loc)
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

	// Other members' hashers.
	env.Login(t, env.Client(t), "sam@example.org", "sam correct horse 2")
	env.Login(t, env.Client(t), "kim@example.org", "kim correct horse 4")

	// A recovery code works once.
	recoverySignIn := func() *http.Client {
		c := passwordSignIn()
		env.Submit(t, c, "/login/totp", url.Values{"code": {"RecoveryBBB2"}})
		return c
	}
	if loc := signedInRedirect(recoverySignIn()); loc != "" {
		t.Fatalf("recovery code: / redirects to %q, want signed in", loc)
	}
	if loc := signedInRedirect(recoverySignIn()); !strings.HasPrefix(loc, "/login/totp") {
		t.Fatalf("recovery code used twice: / redirects to %q, want the TOTP step", loc)
	}

	// A second run adds nothing, and leaves alex's Latch credentials alone
	// (Ruling 3): his native hash, his used recovery code and his TOTP.
	again, err := importer.Run(ctx, deps, snap, opts)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if again.Members.Added+again.Groups.Added+again.Apps.Added != 0 {
		t.Errorf("second run added members %+v, groups %+v, apps %+v", again.Members, again.Groups, again.Apps)
	}
	if n := importEventCount(t, env.Store); n != 2 {
		t.Errorf("%d import.run events after two runs, want 2", n)
	}
	after, err := env.Store.GetUserByEmail(ctx, alexEmail)
	if err != nil {
		t.Fatal(err)
	}
	if after.PasswordHash != alex.PasswordHash || after.LegacyPasswordHash != "" {
		t.Errorf("second run changed alex's password: native %q (was %q), legacy %q", after.PasswordHash, alex.PasswordHash, after.LegacyPasswordHash)
	}
	env.Clock.Advance(2 * time.Minute) // a later TOTP step than the first sign in
	c = passwordSignIn()
	if resp, _ := env.Submit(t, c, "/login/totp", url.Values{"code": {totpCode()}}); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("TOTP after the second run: status %d", resp.StatusCode)
	}
	if loc := signedInRedirect(c); loc != "" {
		t.Errorf("TOTP after the second run: / redirects to %q, want signed in", loc)
	}
	if loc := signedInRedirect(recoverySignIn()); !strings.HasPrefix(loc, "/login/totp") {
		t.Errorf("RecoveryBBB2 works again after the second run: / redirects to %q", loc)
	}
}

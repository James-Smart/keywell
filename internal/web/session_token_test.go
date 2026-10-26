package web_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"keywell/internal/secrets"
	"keywell/internal/session"
	"keywell/internal/testenv"
)

// cookieValue returns the session cookie c holds, or "".
func cookieValue(t *testing.T, env *testenv.Env, c *http.Client) string {
	t.Helper()
	u, err := url.Parse(env.TS.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == session.CookieName {
			return ck.Value
		}
	}
	return ""
}

// The database keeps only a hash of the session cookie, so a copy of it
// (a leaked backup, say) cannot be used to take over a session: what is
// stored does not work as a cookie.
func TestSessionTableHoldsOnlyTokenHash(t *testing.T) {
	env := testenv.New(t)
	env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	raw := cookieValue(t, env, c)

	var n int
	if err := env.DB.QueryRow(`SELECT COUNT(*) FROM sessions
		WHERE instr(id || user_id || COALESCE(ip, '') || COALESCE(user_agent, ''), ?) > 0`, raw).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("the cookie's value is stored in the sessions table")
	}
	var stored string
	if err := env.DB.QueryRow(`SELECT id FROM sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != secrets.HashToken(raw) {
		t.Fatalf("stored session id %q, want the hash of the cookie", stored)
	}

	thief := env.Client(t)
	u, err := url.Parse(env.TS.URL)
	if err != nil {
		t.Fatal(err)
	}
	thief.Jar.SetCookies(u, []*http.Cookie{{Name: session.CookieName, Value: stored}})
	resp, _ := get(t, thief, env.TS.URL+"/")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("stored id as a cookie: status %d location %q, want 303 to sign-in", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = get(t, c, env.TS.URL+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the real cookie: status %d, want 200", resp.StatusCode)
	}
}

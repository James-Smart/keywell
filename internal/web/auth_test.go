package web_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"latch/internal/audit"
	"latch/internal/model"
	"latch/internal/password"
	"latch/internal/secrets"
	"latch/internal/session"
	"latch/internal/store"
	"latch/internal/testenv"
)

const testPW = "correct horse battery staple"

// pbkdf2Hash is a Django pbkdf2_sha256 hash of testPW, as Authentik stores it.
const pbkdf2Hash = "pbkdf2_sha256$870000$vK9mZ2pQxL3n$k/YNzDxY8WuRK/+6PjMgYNCGxD4pyHdDwQFRbvUuXCo="

var (
	noMatch   = html.EscapeString("That email and password didn't match.")
	throttled = html.EscapeString("Too many attempts. Try again in a few minutes.")
)

func postLogin(t *testing.T, env *testenv.Env, c *http.Client, form url.Values) (*http.Response, string) {
	t.Helper()
	resp, err := c.PostForm(env.TS.URL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func creds(email, pw string) url.Values {
	return url.Values{"email": {email}, "password": {pw}}
}

// jarSession returns the session cookie value c holds, or "".
func jarSession(t *testing.T, env *testenv.Env, c *http.Client) string {
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

func assertRedirect(t *testing.T, resp *http.Response, location string) {
	t.Helper()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != location {
		t.Fatalf("status %d location %q, want 303 %q", resp.StatusCode, resp.Header.Get("Location"), location)
	}
}

// assertFailed checks a rejected sign-in: 200, the message, no session.
func assertFailed(t *testing.T, env *testenv.Env, c *http.Client, resp *http.Response, body, message string) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, message) {
		t.Fatalf("body missing %q", message)
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == session.CookieName && ck.MaxAge >= 0 {
			t.Fatalf("failed sign-in set a session cookie")
		}
	}
	if jarSession(t, env, c) != "" {
		t.Fatal("client holds a session cookie after a failed sign-in")
	}
}

// auditEvents returns the events recorded with action, oldest first.
func auditEvents(t *testing.T, env *testenv.Env, action string) []model.AuditEvent {
	t.Helper()
	rows, err := env.DB.Query(`SELECT actor_type, actor_id, target_type, target_id, detail
		FROM audit_events WHERE action=? ORDER BY at, rowid`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []model.AuditEvent
	for rows.Next() {
		var e model.AuditEvent
		var actorType, detail string
		if err := rows.Scan(&actorType, &e.ActorID, &e.TargetType, &e.TargetID, &detail); err != nil {
			t.Fatal(err)
		}
		e.ActorType = model.ActorType(actorType)
		if err := json.Unmarshal([]byte(detail), &e.Detail); err != nil {
			t.Fatalf("detail %q: %v", detail, err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

func TestLoginSuccessSetsCookieAndRedirects(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)

	resp, _ := postLogin(t, env, c, creds("alex@example.org", testPW))
	assertRedirect(t, resp, "/")
	sid := jarSession(t, env, c)
	if sid == "" {
		t.Fatal("no session cookie after sign-in")
	}
	sess, err := env.Store.GetSession(context.Background(), sid)
	if err != nil {
		t.Fatal(err)
	}
	if sess.UserID != u.ID || !sess.TOTPPassed {
		t.Fatalf("session %+v", sess)
	}
	got, err := env.Store.GetUser(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastLoginAt == nil {
		t.Fatal("LastLoginAt not set")
	}
	if resp, _ := get(t, c, env.TS.URL+"/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / after sign-in: status %d", resp.StatusCode)
	}

	events := auditEvents(t, env, audit.LoginSuccess)
	if len(events) != 1 || events[0].ActorType != model.ActorUser || events[0].ActorID != u.ID {
		t.Fatalf("login.success events %+v", events)
	}
}

func TestLoginEmailNormalised(t *testing.T) {
	env := testenv.New(t)
	env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)
	resp, _ := postLogin(t, env, c, creds(" Alex@Example.ORG ", testPW))
	assertRedirect(t, resp, "/")
	if jarSession(t, env, c) == "" {
		t.Fatal("no session cookie")
	}
}

func TestLoginLegacyHashUpgraded(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := &model.User{Name: "Imported", Email: "imported@example.org", IsActive: true, LegacyPasswordHash: pbkdf2Hash}
	if err := env.Store.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	resp, _ := postLogin(t, env, env.Client(t), creds("imported@example.org", testPW))
	assertRedirect(t, resp, "/")
	got, err := env.Store.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.PasswordHash, "$argon2id$") || got.LegacyPasswordHash != "" {
		t.Fatalf("hashes after sign-in: native %q legacy %q", got.PasswordHash, got.LegacyPasswordHash)
	}
	if ok, err := password.Verify(testPW, got.PasswordHash); !ok || err != nil {
		t.Fatalf("upgraded hash does not verify: %v %v", ok, err)
	}

	resp, _ = postLogin(t, env, env.Client(t), creds("imported@example.org", testPW))
	assertRedirect(t, resp, "/")
}

// sameFailure strips the echoed email so failure pages can be compared.
func sameFailure(body, email string) string {
	return strings.ReplaceAll(body, email, "EMAIL")
}

func TestLoginWrongPasswordGenericMessage(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)

	resp, wrong := postLogin(t, env, c, creds("alex@example.org", "not the password"))
	assertFailed(t, env, c, resp, wrong, noMatch)
	resp, unknown := postLogin(t, env, c, creds("Nobody@Example.ORG", "not the password"))
	assertFailed(t, env, c, resp, unknown, noMatch)
	if sameFailure(wrong, "alex@example.org") != sameFailure(unknown, "Nobody@Example.ORG") {
		t.Fatalf("unknown email page differs from wrong password page:\n%s\n---\n%s", wrong, unknown)
	}

	events := auditEvents(t, env, audit.LoginFailure)
	if len(events) != 2 {
		t.Fatalf("login.failure events %+v", events)
	}
	if e := events[0]; e.ActorType != model.ActorUser || e.ActorID != u.ID {
		t.Errorf("known email failure %+v", e)
	}
	if e := events[1]; e.ActorType != model.ActorUser || e.ActorID != "" ||
		e.Detail["email_hash"] != secrets.HashToken("nobody@example.org") {
		t.Errorf("unknown email failure %+v", e)
	}
	for _, e := range events {
		raw, _ := json.Marshal(e)
		for _, secret := range []string{"not the password", "obody@", "alex@"} {
			if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(secret)) {
				t.Errorf("audit event contains %q: %s", secret, raw)
			}
		}
	}
}

func TestLoginInactiveRejected(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	env.CreateUser(t, "alex@example.org", testPW)
	inactive := env.CreateUser(t, "gone@example.org", testPW)
	inactive.IsActive = false
	if err := env.Store.UpdateUser(ctx, inactive); err != nil {
		t.Fatal(err)
	}
	env.CreateUser(t, "nopass@example.org", "")
	c := env.Client(t)

	_, reference := postLogin(t, env, c, creds("alex@example.org", "not the password"))
	for _, email := range []string{"gone@example.org", "nopass@example.org"} {
		resp, body := postLogin(t, env, c, creds(email, testPW))
		assertFailed(t, env, c, resp, body, noMatch)
		if sameFailure(body, email) != sameFailure(reference, "alex@example.org") {
			t.Errorf("%s: page differs from the wrong password page", email)
		}
	}
}

func TestLoginThrottledAfter10(t *testing.T) {
	env := testenv.New(t)
	env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)

	for i := range 10 {
		resp, body := postLogin(t, env, c, creds("alex@example.org", "wrong"))
		assertFailed(t, env, c, resp, body, noMatch)
		if strings.Contains(body, throttled) {
			t.Fatalf("attempt %d already throttled", i+1)
		}
	}
	resp, body := postLogin(t, env, c, creds("ALEX@example.org", testPW))
	assertFailed(t, env, c, resp, body, throttled)

	env.Clock.Advance(15*time.Minute + time.Second)
	resp, _ = postLogin(t, env, c, creds("alex@example.org", testPW))
	assertRedirect(t, resp, "/")
}

func TestLoginThrottledPerIP(t *testing.T) {
	env := testenv.New(t)
	env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)

	for i := range 50 {
		resp, body := postLogin(t, env, c, creds(fmt.Sprintf("guess%d@example.org", i), "wrong"))
		assertFailed(t, env, c, resp, body, noMatch)
	}
	resp, body := postLogin(t, env, c, creds("alex@example.org", testPW))
	assertFailed(t, env, c, resp, body, throttled)
}

// Only failed attempts count: members behind one NAT address must be able
// to sign in more often than the per-IP limit.
func TestLoginSuccessesNotThrottled(t *testing.T) {
	env := testenv.New(t)
	env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)
	for i := range 60 {
		resp, _ := postLogin(t, env, c, creds("alex@example.org", testPW))
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-in %d: status %d, want 303", i+1, resp.StatusCode)
		}
	}
}

func TestLoginRedirectsToNext(t *testing.T) {
	env := testenv.New(t)
	env.CreateUser(t, "alex@example.org", testPW)
	for next, want := range map[string]string{
		"https://evil.example": "/",
		"//evil.example":       "/",
		"/account?tab=2":       "/account?tab=2",
	} {
		form := creds("alex@example.org", testPW)
		form.Set("next", next)
		resp, _ := postLogin(t, env, env.Client(t), form)
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != want {
			t.Errorf("next=%q: status %d location %q, want %q", next, resp.StatusCode, resp.Header.Get("Location"), want)
		}
	}
}

func TestLoginShowsAppName(t *testing.T) {
	env := testenv.New(t)
	env.CreateApp(t, model.Application{Name: "Members Wiki", Slug: "wiki", ClientID: "wiki-client"}, "s3cret")
	c := env.Client(t)
	const shown = "to continue to <strong>Members Wiki</strong>"

	_, body := get(t, c, env.TS.URL+"/login?app=wiki&next=%2Faccount")
	for _, want := range []string{shown, `name="app" value="wiki"`, `name="next" value="/account"`} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %q", want)
		}
	}

	_, body = get(t, c, env.TS.URL+"/login?app=nope")
	if strings.Contains(body, "to continue to") {
		t.Error("unknown app slug shown")
	}

	form := creds("alex@example.org", "wrong")
	form.Set("app", "wiki")
	form.Set("next", "/account")
	_, body = postLogin(t, env, c, form)
	for _, want := range []string{noMatch, shown, `name="app" value="wiki"`, `name="next" value="/account"`, `value="alex@example.org"`} {
		if !strings.Contains(body, want) {
			t.Errorf("failed sign-in page missing %q", want)
		}
	}
}

func TestLoginWithTOTPGoesToTOTPStep(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	confirmed := time.Now().UTC()
	if err := env.Store.SetTOTP(ctx, u.ID, []byte("sealed secret"), &confirmed); err != nil {
		t.Fatal(err)
	}
	c := env.Client(t)

	form := creds("alex@example.org", testPW)
	form.Set("next", "/account")
	resp, _ := postLogin(t, env, c, form)
	assertRedirect(t, resp, "/login/totp?next=%2Faccount")
	sess, err := env.Store.GetSession(ctx, jarSession(t, env, c))
	if err != nil {
		t.Fatal(err)
	}
	if sess.TOTPPassed {
		t.Fatal("session marked complete before the second factor")
	}

	resp, _ = get(t, c, env.TS.URL+"/")
	assertRedirect(t, resp, "/login/totp?next=%2F")

	// Pages rendered for an incomplete session do not treat it as signed in.
	resp, body := get(t, c, env.TS.URL+"/logout")
	if resp.StatusCode != http.StatusOK || strings.Contains(body, "alex@example.org") {
		t.Fatalf("logout page for incomplete session: status %d, shows user: %v", resp.StatusCode, strings.Contains(body, "alex@example.org"))
	}
}

func TestLoginRequiredTOTPGoesToEnrolment(t *testing.T) {
	env := testenv.New(t)
	env.CreateGroup(t, "Admin", true, true)
	env.CreateUser(t, "admin@example.org", testPW, "Admin")
	c := env.Client(t)

	form := creds("admin@example.org", testPW)
	form.Set("next", "/account")
	resp, _ := postLogin(t, env, c, form)
	assertRedirect(t, resp, "/account/totp?required=1&next=%2Faccount")
	sess, err := env.Store.GetSession(context.Background(), jarSession(t, env, c))
	if err != nil {
		t.Fatal(err)
	}
	if sess.TOTPPassed {
		t.Fatal("session marked complete before enrolment")
	}
	if resp, _ := get(t, c, env.TS.URL+"/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("GET / with enrolment pending: status %d, want 303", resp.StatusCode)
	}
}

func TestLogoutPostEndsSession(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	sid := jarSession(t, env, c)

	resp, body := get(t, c, env.TS.URL+"/logout")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /logout: status %d", resp.StatusCode)
	}
	for _, want := range []string{`method="post"`, `action="/logout"`, "alex@example.org"} {
		if !strings.Contains(body, want) {
			t.Errorf("logout page missing %q", want)
		}
	}

	resp, err := c.PostForm(env.TS.URL+"/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	assertRedirect(t, resp, "/logout/done")
	if jarSession(t, env, c) != "" {
		t.Fatal("session cookie not cleared")
	}
	if _, err := env.Store.GetSession(context.Background(), sid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session still stored: %v", err)
	}
	if events := auditEvents(t, env, audit.Logout); len(events) != 1 || events[0].ActorID != u.ID {
		t.Fatalf("logout events %+v", events)
	}

	resp, body = get(t, c, env.TS.URL+"/logout/done")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "You're signed out") || !strings.Contains(body, `href="/login"`) {
		t.Fatalf("signed out page: status %d body %s", resp.StatusCode, body)
	}
	resp, _ = get(t, c, env.TS.URL+"/")
	assertRedirect(t, resp, "/login?next=%2F")
}

func TestLogoutWithoutSession(t *testing.T) {
	env := testenv.New(t)
	c := env.Client(t)
	resp, body := get(t, c, env.TS.URL+"/logout")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `action="/logout"`) {
		t.Fatalf("GET /logout: status %d", resp.StatusCode)
	}
	resp, err := c.PostForm(env.TS.URL+"/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	assertRedirect(t, resp, "/logout/done")
	if events := auditEvents(t, env, audit.Logout); len(events) != 0 {
		t.Fatalf("logout without a session audited: %+v", events)
	}
}

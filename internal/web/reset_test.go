package web_test

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"latch/internal/audit"
	"latch/internal/config"
	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/store"
	"latch/internal/testenv"
	"latch/internal/web"
)

const newPW = "a brand new passphrase"

var (
	resetSent       = "If that address has an account, we've emailed a link. It lasts one hour."
	tooCommon       = "That password is too common. Pick something less guessable."
	pwMismatch      = html.EscapeString("Those passwords don't match.")
	currentMismatch = html.EscapeString("Your current password didn't match.")
	passwordChanged = "Password changed."
	// resetLinkRE matches the path of a reset link, capturing the token.
	resetLinkRE = regexp.MustCompile(`/reset/([A-Za-z0-9_-]{43})\b`)
)

// mailedLink returns the path of the reset link in the last email sent,
// checking the full link starts with the public URL.
func mailedLink(t *testing.T, env *testenv.Env) string {
	t.Helper()
	msg, ok := env.Mailer.Last()
	if !ok {
		t.Fatal("no email sent")
	}
	m := resetLinkRE.FindString(msg.Text)
	if m == "" || !strings.Contains(msg.Text, env.Cfg.PublicURL+m) {
		t.Fatalf("no reset link under %s in:\n%s", env.Cfg.PublicURL, msg.Text)
	}
	return m
}

// issueLink makes a link with web.IssueResetLink and returns its path.
func issueLink(t *testing.T, env *testenv.Env, u *model.User, purpose model.ResetPurpose) string {
	t.Helper()
	link, err := web.IssueResetLink(context.Background(), env.Store, env.Cfg.PublicURL, u.ID, purpose)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^` + regexp.QuoteMeta(env.Cfg.PublicURL) + `/reset/[A-Za-z0-9_-]{43}$`).MatchString(link) {
		t.Fatalf("link %q", link)
	}
	return strings.TrimPrefix(link, env.Cfg.PublicURL)
}

// tokenHash is the stored hash of the token in a reset link path.
func tokenHash(path string) string {
	return secrets.HashToken(strings.TrimPrefix(path, "/reset/"))
}

func setPassword(pw, confirm string) url.Values {
	return url.Values{"password": {pw}, "confirm": {confirm}}
}

// addRefreshToken stores a live refresh token for u and returns its hash.
func addRefreshToken(t *testing.T, env *testenv.Env, u *model.User) string {
	t.Helper()
	app := env.CreateApp(t, model.Application{Name: "Wiki", Slug: "wiki", ClientID: "wiki",
		RedirectURIs: []string{"https://wiki.example.org/cb"}}, "wiki secret")
	now := time.Now().UTC()
	rt := &model.RefreshToken{TokenHash: "refresh-" + u.ID, FamilyID: "family", ApplicationID: app.ID, UserID: u.ID,
		Scope: "openid", AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour)}
	if err := env.Store.CreateRefreshToken(context.Background(), rt); err != nil {
		t.Fatal(err)
	}
	return rt.TokenHash
}

func assertRevoked(t *testing.T, env *testenv.Env, hash string) {
	t.Helper()
	rt, err := env.Store.GetRefreshToken(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if rt.RevokedAt == nil {
		t.Fatal("refresh token not revoked")
	}
}

// assertLoginRefused signs in with a fresh client and checks it is refused
// with message.
func assertLoginRefused(t *testing.T, env *testenv.Env, email, pw, message string) {
	t.Helper()
	c := env.Client(t)
	resp, body := postLogin(t, env, c, creds(email, pw))
	assertFailed(t, env, c, resp, body, message)
}

func assertSessionGone(t *testing.T, env *testenv.Env, sid string) {
	t.Helper()
	if _, err := env.Store.GetSession(context.Background(), sid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session %s still stored: %v", sid, err)
	}
}

// assertExpiredPage checks the branded expired-link page.
func assertExpiredPage(t *testing.T, resp *http.Response, body string) {
	t.Helper()
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "expired") || !strings.Contains(body, `href="/reset"`) {
		t.Fatalf("expired page: status %d\n%s", resp.StatusCode, body)
	}
}

func TestResetRequestSendsMailOnlyForActiveUsers(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	off := env.CreateUser(t, "sam@example.org", testPW)
	off.IsActive = false
	if err := env.Store.UpdateUser(ctx, off); err != nil {
		t.Fatal(err)
	}
	c := env.Client(t)

	resp, body := get(t, c, env.TS.URL+"/reset")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `action="/reset"`) {
		t.Fatalf("request page: status %d\n%s", resp.StatusCode, body)
	}

	resp, unknown := post(t, env, c, "/reset", url.Values{"email": {"nobody@example.org"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(unknown, resetSent) {
		t.Fatalf("unknown email: status %d\n%s", resp.StatusCode, unknown)
	}
	resp, body = post(t, env, c, "/reset", url.Values{"email": {"sam@example.org"}})
	if resp.StatusCode != http.StatusOK || body != unknown {
		t.Fatalf("inactive user: status %d, page differs from unknown email:\n%s", resp.StatusCode, body)
	}
	if n := len(env.Mailer.Sent); n != 0 {
		t.Fatalf("sent %d emails for unknown and inactive users", n)
	}

	resp, body = post(t, env, c, "/reset", url.Values{"email": {"  Alex@Example.org "}})
	if resp.StatusCode != http.StatusOK || body != unknown {
		t.Fatalf("active user: status %d, page differs from unknown email:\n%s", resp.StatusCode, body)
	}
	if n := len(env.Mailer.Sent); n != 1 {
		t.Fatalf("sent %d emails, want 1", n)
	}
	msg, _ := env.Mailer.Last()
	if msg.To != "alex@example.org" || msg.Subject != "Reset your Latch password" || !strings.Contains(msg.Text, "1 hour") {
		t.Fatalf("email %+v", msg)
	}
	path := mailedLink(t, env)
	tok, err := env.Store.PeekResetToken(ctx, tokenHash(path))
	if err != nil {
		t.Fatal(err)
	}
	if tok.UserID != u.ID || tok.Purpose != model.ResetPurposeReset {
		t.Fatalf("token %+v", tok)
	}
	if d := time.Until(tok.ExpiresAt); d < 59*time.Minute || d > time.Hour {
		t.Fatalf("token lasts %v, want one hour", d)
	}

	events := auditEvents(t, env, audit.PasswordResetRequested)
	if len(events) != 1 || events[0].ActorID != u.ID || events[0].TargetID != u.ID ||
		fmt.Sprint(events[0].Detail) != "map[purpose:reset]" {
		t.Fatalf("reset requested events %+v", events)
	}
}

func TestResetLinkSetsPasswordAndLogsIn(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	other := env.Client(t)
	env.Login(t, other, "alex@example.org", testPW)
	otherSID := jarSession(t, env, other)
	refresh := addRefreshToken(t, env, u)

	c := env.Client(t)
	post(t, env, c, "/reset", url.Values{"email": {"alex@example.org"}})
	path := mailedLink(t, env)

	resp, body := get(t, c, env.TS.URL+path)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Choose a new password") ||
		!strings.Contains(body, `name="password"`) || !strings.Contains(body, `name="confirm"`) {
		t.Fatalf("set password page: status %d\n%s", resp.StatusCode, body)
	}
	if strings.Contains(body, "Welcome to") {
		t.Error("reset page shows the invite copy")
	}

	resp, _ = post(t, env, c, path, setPassword(newPW, newPW))
	assertRedirect(t, resp, "/")
	sid := jarSession(t, env, c)
	if sid == "" {
		t.Fatal("no session cookie after reset")
	}
	sess, err := env.Store.GetSession(ctx, sid)
	if err != nil || sess.UserID != u.ID || !sess.TOTPPassed {
		t.Fatalf("session %+v, %v", sess, err)
	}
	if resp, _ := get(t, c, env.TS.URL+"/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / after reset: status %d", resp.StatusCode)
	}

	assertSessionGone(t, env, otherSID)
	assertRevoked(t, env, refresh)
	assertLoginRefused(t, env, "alex@example.org", testPW, noMatch)
	env.Login(t, env.Client(t), "alex@example.org", newPW)

	events := auditEvents(t, env, audit.PasswordResetCompleted)
	if len(events) != 1 || events[0].ActorID != u.ID || fmt.Sprint(events[0].Detail) != "map[purpose:reset]" {
		t.Fatalf("reset completed events %+v", events)
	}
}

// A member enrolled in TOTP still enters a code after resetting.
func TestResetLinkWithTOTPGoesToTOTPStep(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	secret := env.EnrolTOTP(t, u)
	path := issueLink(t, env, u, model.ResetPurposeReset)
	c := env.Client(t)

	resp, _ := post(t, env, c, path, setPassword(newPW, newPW))
	assertRedirect(t, resp, "/login/totp?next=%2F")
	sess, err := env.Store.GetSession(ctx, jarSession(t, env, c))
	if err != nil || sess.TOTPPassed {
		t.Fatalf("session %+v, %v", sess, err)
	}
	resp, _ = get(t, c, env.TS.URL+"/")
	assertRedirect(t, resp, "/login/totp?next=%2F")
	resp, _ = post(t, env, c, "/login/totp", url.Values{"code": {validCode(t, secret)}})
	assertRedirect(t, resp, "/")
}

func TestResetLinkReuseAndExpiryShowExpiredPage(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)

	used := issueLink(t, env, u, model.ResetPurposeReset)
	resp, _ := post(t, env, c, used, setPassword(newPW, newPW))
	assertRedirect(t, resp, "/")
	resp, body := get(t, c, env.TS.URL+used)
	assertExpiredPage(t, resp, body)
	resp, body = post(t, env, c, used, setPassword("yet another passphrase", "yet another passphrase"))
	assertExpiredPage(t, resp, body)
	env.Login(t, env.Client(t), "alex@example.org", newPW)

	expired := "expired-token-expired-token-expired-token00"
	if err := env.Store.CreateResetToken(ctx, &model.ResetToken{TokenHash: secrets.HashToken(expired), UserID: u.ID,
		Purpose: model.ResetPurposeReset, CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	resp, body = get(t, c, env.TS.URL+"/reset/"+expired)
	assertExpiredPage(t, resp, body)
	resp, body = post(t, env, c, "/reset/"+expired, setPassword("yet another passphrase", "yet another passphrase"))
	assertExpiredPage(t, resp, body)

	resp, body = get(t, c, env.TS.URL+"/reset/not-a-real-token")
	assertExpiredPage(t, resp, body)
	resp, body = post(t, env, c, "/reset/not-a-real-token", setPassword("yet another passphrase", "yet another passphrase"))
	assertExpiredPage(t, resp, body)

	env.Login(t, env.Client(t), "alex@example.org", newPW)
	if n := len(auditEvents(t, env, audit.PasswordResetCompleted)); n != 1 {
		t.Fatalf("reset completed events: %d, want 1", n)
	}
}

func TestResetPolicyErrorsInline(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	path := issueLink(t, env, u, model.ResetPurposeReset)
	c := env.Client(t)

	for _, tc := range []struct{ pw, confirm, want string }{
		{"short", "short", "Use at least 10 characters."},
		{"password1234", "password1234", tooCommon},
		{newPW, "a different passphrase", pwMismatch},
	} {
		resp, body := post(t, env, c, path, setPassword(tc.pw, tc.confirm))
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, tc.want) || !strings.Contains(body, `name="password"`) {
			t.Fatalf("%q/%q: status %d, want %q\n%s", tc.pw, tc.confirm, resp.StatusCode, tc.want, body)
		}
		if jarSession(t, env, c) != "" {
			t.Fatalf("%q: signed in after a refused password", tc.pw)
		}
	}
	if _, err := env.Store.PeekResetToken(ctx, tokenHash(path)); err != nil {
		t.Fatalf("token used up by refused passwords: %v", err)
	}
	if got := getUser(t, env, u.ID); got.PasswordHash != u.PasswordHash {
		t.Fatal("password changed by a refused attempt")
	}

	resp, _ := post(t, env, c, path, setPassword(newPW, newPW))
	assertRedirect(t, resp, "/")
}

func TestInviteCopy(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "new@example.org", "")
	path := issueLink(t, env, u, model.ResetPurposeInvite)
	tok, err := env.Store.PeekResetToken(ctx, tokenHash(path))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(tok.ExpiresAt); tok.Purpose != model.ResetPurposeInvite || d < 7*24*time.Hour-time.Minute || d > 7*24*time.Hour {
		t.Fatalf("invite token %+v lasts %v", tok, d)
	}
	c := env.Client(t)

	resp, body := get(t, c, env.TS.URL+path)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Welcome to Latch. Choose your password.") {
		t.Fatalf("invite page: status %d\n%s", resp.StatusCode, body)
	}
	if strings.Contains(body, "Choose a new password") {
		t.Error("invite page shows the reset copy")
	}
	resp, body = post(t, env, c, path, setPassword("short", "short"))
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Welcome to Latch.") {
		t.Fatalf("invite page after a refused password: status %d\n%s", resp.StatusCode, body)
	}

	resp, _ = post(t, env, c, path, setPassword(newPW, newPW))
	assertRedirect(t, resp, "/")
	if !getUser(t, env, u.ID).HasPassword() {
		t.Fatal("no password after accepting the invite")
	}
	events := auditEvents(t, env, audit.PasswordResetCompleted)
	if len(events) != 1 || fmt.Sprint(events[0].Detail) != "map[purpose:invite]" {
		t.Fatalf("reset completed events %+v", events)
	}
}

// Requests are limited to 3 per account and 20 per IP an hour. Throttled
// requests show the same page and send nothing.
func TestResetThrottled(t *testing.T) {
	env := testenv.New(t)
	env.CreateUser(t, "alex@example.org", testPW)
	env.CreateUser(t, "sam@example.org", testPW)
	c := env.Client(t)
	request := func(email string) {
		t.Helper()
		resp, body := post(t, env, c, "/reset", url.Values{"email": {email}})
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, resetSent) {
			t.Fatalf("request for %s: status %d\n%s", email, resp.StatusCode, body)
		}
	}
	sent := func(want int) {
		t.Helper()
		if n := len(env.Mailer.Sent); n != want {
			t.Fatalf("sent %d emails, want %d", n, want)
		}
	}

	for range 4 {
		request("alex@example.org")
	}
	sent(3)
	request("ALEX@example.org")
	sent(3)

	env.Clock.Advance(61 * time.Minute)
	request("alex@example.org")
	sent(4)
	for i := range 19 {
		request(fmt.Sprintf("nobody%d@example.org", i))
	}
	request("sam@example.org") // the IP's 21st request this hour
	sent(4)
}

func TestChangePassword(t *testing.T) {
	env := testenv.New(t, testenv.WithConfig(func(c *config.Config) { c.Password.MinLength = 12 }))
	ctx := context.Background()
	u := env.CreateUser(t, "alex@example.org", testPW)
	other := env.Client(t)
	env.Login(t, other, "alex@example.org", testPW)
	otherSID := jarSession(t, env, other)
	refresh := addRefreshToken(t, env, u)
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	sid := jarSession(t, env, c)

	resp, body := get(t, c, env.TS.URL+"/account/password")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `action="/account/password"`) ||
		!strings.Contains(body, `name="current"`) {
		t.Fatalf("change password page: status %d\n%s", resp.StatusCode, body)
	}

	change := func(current, pw, confirm string) (*http.Response, string) {
		return post(t, env, c, "/account/password", url.Values{"current": {current}, "password": {pw}, "confirm": {confirm}})
	}
	for _, tc := range []struct{ current, pw, confirm, want string }{
		{"not the password", newPW, newPW, currentMismatch},
		{testPW, "elevenchars", "elevenchars", "Use at least 12 characters."},
		{testPW, "password1234", "password1234", tooCommon},
		{testPW, newPW, "a different passphrase", pwMismatch},
	} {
		resp, body := change(tc.current, tc.pw, tc.confirm)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, tc.want) {
			t.Fatalf("%+v: status %d\n%s", tc, resp.StatusCode, body)
		}
		if strings.Contains(body, passwordChanged) {
			t.Fatalf("%+v: shows the success notice", tc)
		}
	}
	if getUser(t, env, u.ID).PasswordHash != u.PasswordHash {
		t.Fatal("password changed by a refused attempt")
	}
	if _, err := env.Store.GetSession(ctx, otherSID); err != nil {
		t.Fatalf("other session ended by a refused attempt: %v", err)
	}

	resp, body = change(testPW, newPW, newPW)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, passwordChanged) {
		t.Fatalf("change: status %d\n%s", resp.StatusCode, body)
	}
	if _, err := env.Store.GetSession(ctx, sid); err != nil {
		t.Fatalf("current session ended: %v", err)
	}
	if jarSession(t, env, c) != sid {
		t.Fatal("current session cookie changed")
	}
	assertSessionGone(t, env, otherSID)
	assertRevoked(t, env, refresh)
	if resp, _ := get(t, c, env.TS.URL+"/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / after change: status %d", resp.StatusCode)
	}
	assertLoginRefused(t, env, "alex@example.org", testPW, noMatch)
	env.Login(t, env.Client(t), "alex@example.org", newPW)

	events := auditEvents(t, env, audit.PasswordChanged)
	if len(events) != 1 || events[0].ActorID != u.ID || events[0].TargetID != u.ID {
		t.Fatalf("password changed events %+v", events)
	}
}

// Wrong current passwords use up the account's sign-in budget, and a
// throttled form checks nothing.
func TestChangePasswordThrottled(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	change := func(current string) (*http.Response, string) {
		return post(t, env, c, "/account/password", url.Values{"current": {current}, "password": {newPW}, "confirm": {newPW}})
	}

	for i := range 10 {
		resp, body := change("not the password")
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, currentMismatch) {
			t.Fatalf("wrong password %d: status %d\n%s", i+1, resp.StatusCode, body)
		}
	}
	resp, body := change(testPW)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, throttled) {
		t.Fatalf("throttled change: status %d\n%s", resp.StatusCode, body)
	}
	if getUser(t, env, u.ID).PasswordHash != u.PasswordHash {
		t.Fatal("password changed while throttled")
	}
	// The budget is the sign-in form's.
	assertLoginRefused(t, env, "alex@example.org", testPW, throttled)
}

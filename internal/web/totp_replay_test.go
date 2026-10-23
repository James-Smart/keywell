package web_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"latch/internal/model"
	"latch/internal/testenv"
)

// A TOTP code works once (RFC 6238 §5.2): signing in with it again, from
// another session, or turning TOTP off with it counts as a wrong code.
func TestTOTPCodeAcceptedOnce(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW)
	secret := env.EnrolTOTP(t, u)
	code := codeAt(t, secret, env.Clock.Now())

	first := env.Client(t)
	env.Login(t, first, "alex@example.org", testPW)
	resp, _ := post(t, env, first, "/login/totp", url.Values{"code": {code}})
	assertRedirect(t, resp, "/")

	second := env.Client(t)
	env.Login(t, second, "alex@example.org", testPW)
	resp, body := post(t, env, second, "/login/totp", url.Values{"code": {code}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, codeMismatch) {
		t.Fatalf("same code in a second session: status %d location %q, want the form with %q",
			resp.StatusCode, resp.Header.Get("Location"), codeMismatch)
	}
	if sessionOfClient(t, env, second).TOTPPassed {
		t.Fatal("second session passed its TOTP step with a used code")
	}

	resp, body = post(t, env, first, "/account/totp/disable", url.Values{"password": {testPW}, "code": {code}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, disableMismatch) {
		t.Fatalf("disable with a used code: status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !getUser(t, env, u.ID).TOTPEnrolled() {
		t.Fatal("TOTP turned off with a used code")
	}
}

// The code that confirms an enrolment is used up by it.
func TestConfirmingCodeCannotSignIn(t *testing.T) {
	env := testenv.New(t)
	env.CreateUser(t, "alex@example.org", testPW)
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	key := beginEnrolment(t, env, c, nil)
	code := codeAt(t, key, env.Clock.Now())
	resp, _ := post(t, env, c, "/account/totp/confirm", url.Values{"code": {code}})
	assertRedirect(t, resp, "/account/totp/codes")

	other := env.Client(t)
	env.Login(t, other, "alex@example.org", testPW)
	resp, body := post(t, env, other, "/login/totp", url.Values{"code": {code}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, codeMismatch) {
		t.Fatalf("confirming code at sign-in: status %d location %q, want the form with %q",
			resp.StatusCode, resp.Header.Get("Location"), codeMismatch)
	}
}

// sessionOfClient returns the stored session c's cookie names.
func sessionOfClient(t *testing.T, env *testenv.Env, c *http.Client) *model.Session {
	t.Helper()
	sess, err := env.Store.GetSession(context.Background(), jarSession(t, env, c))
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	return sess
}

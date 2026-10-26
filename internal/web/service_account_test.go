package web_test

import (
	"context"
	"net/url"
	"testing"

	"keywell/internal/model"
	"keywell/internal/password"
	"keywell/internal/testenv"
)

// createServiceAccount stores an active service account with email and,
// against the rules, a password, as if one had been set by mistake.
func createServiceAccount(t *testing.T, env *testenv.Env, email string) *model.User {
	t.Helper()
	hash, err := password.Hash(testPW)
	if err != nil {
		t.Fatal(err)
	}
	u := &model.User{Name: "Door controller", Type: model.UserTypeService, Username: "door", Email: email,
		PasswordHash: hash, IsActive: true}
	if err := env.Store.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

// A service account cannot use the sign-in page (spec §4), even with the
// right password; it fails like a wrong password.
func TestServiceAccountCannotSignIn(t *testing.T) {
	env := testenv.New(t)
	createServiceAccount(t, env, "door@example.org")
	c := env.Client(t)
	resp, body := postLogin(t, env, c, creds("door@example.org", testPW))
	assertFailed(t, env, c, resp, body, noMatch)
}

// Password reset is for members: a request for a service account's address
// sends nothing, and a link made for one does not work.
func TestServiceAccountCannotReset(t *testing.T) {
	env := testenv.New(t)
	svc := createServiceAccount(t, env, "door@example.org")
	c := env.Client(t)

	resp, body := post(t, env, c, "/reset", url.Values{"email": {"door@example.org"}})
	if resp.StatusCode != 200 {
		t.Fatalf("reset request: status %d\n%s", resp.StatusCode, body)
	}
	env.WaitMail(t)
	if n := len(env.Mailer.Sent); n != 0 {
		t.Fatalf("sent %d emails for a service account", n)
	}

	link := issueLink(t, env, svc, model.ResetPurposeReset)
	resp, body = get(t, c, env.TS.URL+link)
	assertExpiredPage(t, resp, body)
	resp, body = post(t, env, c, link, setPassword(newPW, newPW))
	assertExpiredPage(t, resp, body)
	if jarSession(t, env, c) != "" {
		t.Fatal("a reset link signed a service account in")
	}
}
